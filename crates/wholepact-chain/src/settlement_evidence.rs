//! Source-bound observation retention and crash-recoverable conservative fanout.
//!
//! A lightwalletd response does not prove current canonical inclusion, absence,
//! input conflict or expiry resolution. This module deliberately cannot mint a
//! positive exposure-resolution permit. It does carry live provider provenance
//! into durable, replayable invalidation of previously displayed confidence.
use crate::{
    ChainAdapter, ChainError, ConfirmationPolicy, EncryptedSubmissionJournal, ReconciliationReport,
    SettlementReconciler, SourceObservation, SubmissionDescriptor,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_EVIDENCE: i64 = 8192;
const MAX_BYTES: i64 = 32 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedPayload {
    journal_identity: String,
    descriptor: SubmissionDescriptor,
    report: ReconciliationReport,
    // Normalized adapter outputs only, never raw transaction bytes or arbitrary headers.
    observations: Vec<serde_json::Value>,
}

/// Created only by actual adapter reads. Not constructible/deserializable by an
/// API client. Observation consent must be held by the runtime across this call.
pub struct SourceBoundSettlementObservation {
    descriptor: SubmissionDescriptor,
    report: ReconciliationReport,
    observations: Vec<serde_json::Value>,
}
impl SourceBoundSettlementObservation {
    pub async fn observe(
        descriptor: SubmissionDescriptor,
        policy: ConfirmationPolicy,
        sources: &[ChainAdapter],
        previous: Option<ReconciliationReport>,
    ) -> Result<Self, ChainError> {
        let ids: BTreeSet<_> = sources
            .iter()
            .map(|s| s.identity().source_id.as_str())
            .collect();
        if sources.is_empty()
            || sources.len() > 8
            || ids.len() != sources.len()
            || ids != policy.sources().iter().map(String::as_str).collect()
        {
            return Err(ChainError::InvalidConfiguration);
        }
        let mut reconciler = match previous {
            Some(report) => {
                if report.transaction_id != descriptor.transaction_id
                    || report.expiry_height != descriptor.expiry_height
                    || report.policy != policy
                {
                    return Err(ChainError::MalformedEvidence);
                }
                SettlementReconciler::restore(report)?
            }
            None => SettlementReconciler::new(
                &descriptor.transaction_id,
                descriptor.expiry_height,
                policy,
            )?,
        };
        let mut evidence = Vec::with_capacity(sources.len());
        let mut observations = Vec::with_capacity(sources.len());
        for source in sources {
            let observation = source.observe_transaction(&descriptor.transaction_id).await;
            observations.push(serde_json::json!({
                "source": source.identity(),
                "observation": &observation,
            }));
            evidence.push(SourceObservation {
                source_id: source.identity().source_id.clone(),
                observation,
            });
        }
        let report = reconciler.reconcile(&evidence, crate::now()?)?;
        Ok(Self {
            descriptor,
            report,
            observations,
        })
    }
    pub fn report(&self) -> &ReconciliationReport {
        &self.report
    }
    pub(crate) fn from_local_node(
        descriptor: SubmissionDescriptor,
        report: ReconciliationReport,
        canonical: serde_json::Value,
    ) -> Self {
        Self {
            descriptor,
            report,
            observations: vec![canonical],
        }
    }
}

/// Retention authenticates provenance, not chain finality. Recovery returns this
/// same type but cannot revive a live permit: positive resolution is unsupported.
#[derive(Clone)]
pub struct RetainedSettlementObservation {
    evidence_id: String,
    payload: RetainedPayload,
}
impl RetainedSettlementObservation {
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }
    pub fn journal_identity(&self) -> &str {
        &self.payload.journal_identity
    }
    pub fn descriptor(&self) -> &SubmissionDescriptor {
        &self.payload.descriptor
    }
    pub fn report(&self) -> &ReconciliationReport {
        &self.payload.report
    }
    /// Exact provider endpoint/trust identities, not source labels alone. Local
    /// validating-node evidence has its own source contract and does not match
    /// a lightwallet adapter enrollment through this method.
    /// Historical local-node provenance match for conservative replay only.
    /// It never revives a positive permit after restart or deadline expiry.
    pub fn matches_source_descriptor(
        &self,
        enrolled: &crate::local_node::LocalNodeSourceDescriptor,
    ) -> bool {
        if self.payload.report.policy != enrolled.confirmation_policy
            || self.payload.observations.len() != 1
        {
            return false;
        }
        let Ok(source) = serde_json::to_value(enrolled) else {
            return false;
        };
        self.payload.observations[0].get("source") == Some(&source)
    }
    pub fn matches_sources(
        &self,
        sources: &[crate::BackendIdentity],
        policy: &ConfirmationPolicy,
    ) -> bool {
        if &self.payload.report.policy != policy
            || sources.len() != self.payload.observations.len()
            || sources.is_empty()
            || sources.len() > 8
            || sources
                .iter()
                .map(|s| &s.source_id)
                .collect::<BTreeSet<_>>()
                .len()
                != sources.len()
        {
            return false;
        }
        sources.iter().all(|source| {
            let Ok(expected) = serde_json::to_value(source) else {
                return false;
            };
            self.payload
                .observations
                .iter()
                .filter(|o| o.get("source") == Some(&expected))
                .count()
                == 1
        })
    }

    /// Reopening is conservative even when replayed after restart. Every local
    /// alternative of the obligation must be considered, not only this revision.
    pub fn requires_conservative_reopen(&self) -> bool {
        self.payload.report.confidence_lost || self.payload.report.reorganization_observed
    }
    /// Current adapters cannot prove a provider refreshed canonical membership or
    /// establish private-input conflict/absence. Cached inclusion, expiry heights,
    /// rejection and missing observations NEVER mint exposure-resolution authority.
    pub fn resolution_at(&self, _now: u64) -> Result<(), ChainError> {
        Err(ChainError::UnsupportedCapability)
    }
}

impl EncryptedSubmissionJournal {
    /// Atomically retains normalized evidence and all selected delivery intents.
    /// Sinks apply idempotently by evidence_id before acknowledging; a crash between
    /// application and acknowledgement replays the same immutable evidence.
    pub fn retain_settlement_observation(
        &mut self,
        observation: SourceBoundSettlementObservation,
        destinations: &[String],
    ) -> Result<RetainedSettlementObservation, ChainError> {
        self.verify_identity()?;
        if destinations.is_empty()
            || destinations.len() > 32
            || destinations
                .iter()
                .any(|d| !crate::reconciliation::valid_source_id(d))
            || destinations.iter().collect::<BTreeSet<_>>().len() != destinations.len()
        {
            return Err(ChainError::InvalidConfiguration);
        }
        if self
            .retained_submission_descriptor(&observation.descriptor.operation_id)?
            .as_ref()
            != Some(&observation.descriptor)
        {
            return Err(ChainError::IdempotencyConflict);
        }
        observation.report.validate()?;
        let payload = RetainedPayload {
            journal_identity: self.identity().into(),
            descriptor: observation.descriptor,
            report: observation.report,
            observations: observation.observations,
        };
        let encoded = serde_json::to_string(&payload).map_err(|_| ChainError::JournalFailure)?;
        if encoded.len() > 262144 {
            return Err(ChainError::ResourceLimit);
        }
        let evidence_id = hex::encode(Sha256::digest(encoded.as_bytes()));
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ChainError::JournalFailure)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT payload FROM settlement_evidence WHERE evidence_id=?1",
                [&evidence_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| ChainError::JournalFailure)?;
        if let Some(old) = existing {
            if old != encoded {
                return Err(ChainError::IdempotencyConflict);
            }
            let mut statement = tx
                .prepare("SELECT destination FROM settlement_deliveries WHERE evidence_id=?1")
                .map_err(|_| ChainError::JournalFailure)?;
            let existing: BTreeSet<String> = statement
                .query_map([&evidence_id], |row| row.get(0))
                .map_err(|_| ChainError::JournalFailure)?
                .collect::<Result<_, _>>()
                .map_err(|_| ChainError::JournalFailure)?;
            if existing != destinations.iter().cloned().collect() {
                return Err(ChainError::IdempotencyConflict);
            }
        } else {
            let (count, bytes): (i64, i64) = tx
                .query_row(
                    "SELECT count(*),coalesce(sum(length(payload)),0) FROM settlement_evidence",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| ChainError::JournalFailure)?;
            if count >= MAX_EVIDENCE || bytes + encoded.len() as i64 > MAX_BYTES {
                return Err(ChainError::ResourceLimit);
            }
            tx.execute(
                "INSERT INTO settlement_evidence(evidence_id,operation,payload) VALUES(?1,?2,?3)",
                params![evidence_id, payload.descriptor.operation_id, encoded],
            )
            .map_err(|_| ChainError::JournalFailure)?;
        }
        for destination in destinations {
            tx.execute("INSERT OR IGNORE INTO settlement_deliveries(evidence_id,destination) VALUES(?1,?2)", params![evidence_id,destination])
                .map_err(|_| ChainError::JournalFailure)?;
        }
        // The display report and durable delivery intents must never diverge after a crash.
        let report =
            serde_json::to_string(&payload.report).map_err(|_| ChainError::JournalFailure)?;
        if report.len() > 16384 {
            return Err(ChainError::ResourceLimit);
        }
        tx.execute("INSERT INTO submission_observations(operation,report) VALUES(?1,?2) ON CONFLICT(operation) DO UPDATE SET report=excluded.report",params![payload.descriptor.operation_id,report])
            .map_err(|_| ChainError::JournalFailure)?;
        tx.commit().map_err(|_| ChainError::JournalFailure)?;
        Ok(RetainedSettlementObservation {
            evidence_id,
            payload,
        })
    }
    /// Bounded ordered replay. Acknowledged entries remain retained for audit and
    /// backup; full journals fail closed instead of evicting unresolved work.
    pub fn pending_settlement_deliveries(
        &self,
        destination: &str,
    ) -> Result<Vec<RetainedSettlementObservation>, ChainError> {
        self.verify_identity()?;
        if !crate::reconciliation::valid_source_id(destination) {
            return Err(ChainError::InvalidConfiguration);
        }
        let mut statement = self.connection.prepare("SELECT e.evidence_id,e.payload FROM settlement_evidence e JOIN settlement_deliveries d USING(evidence_id) WHERE d.destination=?1 AND d.acknowledged=0 ORDER BY e.sequence LIMIT 32")
            .map_err(|_| ChainError::JournalFailure)?;
        let mut rows = statement
            .query([destination])
            .map_err(|_| ChainError::JournalFailure)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|_| ChainError::JournalFailure)? {
            let id: String = row.get(0).map_err(|_| ChainError::JournalFailure)?;
            let encoded = row
                .get_ref(1)
                .and_then(|v| v.as_str().map_err(Into::into))
                .map_err(|_| ChainError::JournalFailure)?;
            if encoded.len() > 262144 || id != hex::encode(Sha256::digest(encoded.as_bytes())) {
                return Err(ChainError::JournalFailure);
            }
            let payload: RetainedPayload =
                serde_json::from_str(encoded).map_err(|_| ChainError::JournalFailure)?;
            payload.report.validate()?;
            if payload.journal_identity != self.identity()
                || self
                    .retained_submission_descriptor(&payload.descriptor.operation_id)?
                    .as_ref()
                    != Some(&payload.descriptor)
                || payload.report.transaction_id != payload.descriptor.transaction_id
                || payload.report.expiry_height != payload.descriptor.expiry_height
            {
                return Err(ChainError::JournalFailure);
            }
            result.push(RetainedSettlementObservation {
                evidence_id: id,
                payload,
            });
        }
        Ok(result)
    }
    /// Only the trusted native sink calls this after durable idempotent application.
    /// This checkpoint never grants permission to sign, replace or clear exposure.
    pub fn acknowledge_settlement_delivery(
        &mut self,
        evidence_id: &str,
        destination: &str,
    ) -> Result<(), ChainError> {
        self.verify_identity()?;
        let changed = self.connection.execute("UPDATE settlement_deliveries SET acknowledged=1 WHERE evidence_id=?1 AND destination=?2",params![evidence_id,destination])
            .map_err(|_| ChainError::JournalFailure)?;
        if changed != 1 {
            return Err(ChainError::JournalFailure);
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{SettlementObservationState, SubmissionPlan};
    use std::{fs, os::unix::fs::PermissionsExt};
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
    use zcash_primitives::transaction::{Authorized, TransactionData};
    use zcash_protocol::consensus::BranchId;

    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        DatabaseKey,
        EncryptedSubmissionJournal,
        SubmissionDescriptor,
    ) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("settlement.sqlite");
        let key = DatabaseKey::from_bytes([93; 32]);
        let mut journal = EncryptedSubmissionJournal::from_encrypted_connection(
            create_encrypted(&path, &key).unwrap(),
        )
        .unwrap();
        // Never-funded wire fixture; not a valid payment or chain observation.
        let tx = TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu7,
            0,
            4_498_200.into(),
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        let mut bytes = vec![];
        tx.write(&mut bytes).unwrap();
        let plan = SubmissionPlan::new(
            "synthetic-obligation-1",
            "synthetic-proposal-1",
            "synthetic-operation-1",
            &bytes,
        )
        .unwrap();
        journal.bind_submission_plan(&plan).unwrap();
        (dir, path, key, journal, plan.descriptor().clone())
    }
    fn observation(
        descriptor: &SubmissionDescriptor,
        lost: bool,
    ) -> SourceBoundSettlementObservation {
        let policy = ConfirmationPolicy::new(10, 10, vec!["synthetic".into()]).unwrap();
        let mut reconciler =
            SettlementReconciler::new(&descriptor.transaction_id, descriptor.expiry_height, policy)
                .unwrap();
        let mut report = reconciler.reconcile(&[], 100).unwrap();
        report.confidence_lost = lost;
        SourceBoundSettlementObservation {
            descriptor: descriptor.clone(),
            report,
            observations: vec![],
        }
    }
    #[test]
    fn crash_replay_ack_and_no_positive_resolution() {
        let (_dir, path, key, mut journal, descriptor) = fixture();
        let retained = journal
            .retain_settlement_observation(
                observation(&descriptor, true),
                &["records".into(), "exposure".into()],
            )
            .unwrap();
        assert!(retained.requires_conservative_reopen());
        assert_eq!(
            retained.resolution_at(100),
            Err(ChainError::UnsupportedCapability)
        );
        let id = retained.evidence_id().to_owned();
        journal
            .acknowledge_settlement_delivery(&id, "records")
            .unwrap();
        drop(journal);
        let mut journal = EncryptedSubmissionJournal::from_encrypted_connection(
            open_encrypted(&path, &key).unwrap(),
        )
        .unwrap();
        assert!(
            journal
                .pending_settlement_deliveries("records")
                .unwrap()
                .is_empty()
        );
        let pending = journal.pending_settlement_deliveries("exposure").unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].evidence_id(), id);
        assert!(pending[0].requires_conservative_reopen());
        assert_eq!(
            pending[0].resolution_at(100),
            Err(ChainError::UnsupportedCapability)
        );
        journal
            .acknowledge_settlement_delivery(&id, "exposure")
            .unwrap();
        journal
            .acknowledge_settlement_delivery(&id, "exposure")
            .unwrap();
        assert!(
            journal
                .pending_settlement_deliveries("exposure")
                .unwrap()
                .is_empty()
        );
        assert!(
            journal
                .acknowledge_settlement_delivery(&id, "unknown")
                .is_err()
        );
    }
    #[test]
    fn expiry_missing_and_changed_binding_cannot_resolve() {
        let (_dir, _path, _key, mut journal, descriptor) = fixture();
        for state in [
            SettlementObservationState::PastExpiryObserved,
            SettlementObservationState::NotObserved,
            SettlementObservationState::InclusionUncertain,
        ] {
            let mut evidence = observation(&descriptor, false);
            evidence.report.state = state;
            let retained = journal
                .retain_settlement_observation(evidence, &["exposure".into()])
                .unwrap();
            assert!(!retained.requires_conservative_reopen());
            assert_eq!(
                retained.resolution_at(100),
                Err(ChainError::UnsupportedCapability)
            );
        }
        let mut evidence = observation(&descriptor, true);
        evidence.descriptor.proposal_id = "different-proposal-1".into();
        assert!(matches!(
            journal.retain_settlement_observation(evidence, &["exposure".into()]),
            Err(ChainError::IdempotencyConflict)
        ));
    }
}
