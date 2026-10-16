//! Exact live node evidence projection into a protected participant archive.
use super::*;
use wholepact_chain::{
    local_node::{LocalNodeSourceDescriptor, LocalResolutionPermit},
    settlement_evidence::RetainedSettlementObservation,
};
use wholepact_core::records::{ExactTransactionReference, SourcedChainObservation};
use wholepact_signer::authority_bridge::protocol::OriginalAuthorizationView;

struct QualifiedObservation(SourcedChainObservation);
impl SettlementObservationSource for QualifiedObservation {
    fn observe_exact_transaction(
        &mut self,
        _: &ExactTransactionReference,
    ) -> wholepact_core::Result<SourcedChainObservation> {
        Ok(self.0.clone())
    }
}
impl StoredParticipantRecord {
    pub(crate) fn resolve_exact_settlement(
        &mut self,
        original: &OriginalAuthorizationView,
        evidence: &RetainedSettlementObservation,
        permit: &LocalResolutionPermit,
        source: &LocalNodeSourceDescriptor,
    ) -> Result<Option<bool>> {
        let denied = || {
            ApiError::new(
                "SETTLEMENT_RECORD_MISMATCH",
                "Exact participant record settlement provenance differs",
            )
        };
        let terms = original.consent.terms();
        if self.record.own_authorization.authorization_record_ref != terms.authorization_id {
            return Ok(None);
        }
        permit
            .check_source(evidence, source)
            .map_err(|_| denied())?;
        let own = &self.record.own_authorization;
        let exact = &self.record.transaction;
        if self.settlement_invalidated
            || self.owner_principal_id != terms.principal_id
            || own.account_id != terms.account_id
            || own.consent_record_ref != original.consent.reference()
            || own.release_operation_id.as_deref() != Some(terms.authorization_id.as_str())
            || own.manifest_digest != terms.manifest_digest
            || own.effects_commitment != terms.effects_digest
            || exact.transaction_id != evidence.descriptor().transaction_id
            || exact.transaction_bytes_digest != evidence.descriptor().bytes_sha256
            || exact.effects_commitment != permit.target_shielded_sighash()
        {
            return Err(denied());
        }
        let report = evidence.report();
        // For a conflict this is the alternative's canonical inclusion, never a
        // claim that the original payment settled.
        let inclusion = permit.inclusion();
        let conflict = matches!(
            permit.kind(),
            wholepact_chain::local_node::LocalResolutionKind::IronwoodInputConflict { .. }
        );
        let tip = report
            .source_tips
            .iter()
            .find(|t| t.source_id == source.source_id)
            .ok_or_else(denied)?;
        let observed = time::OffsetDateTime::from_unix_timestamp(
            i64::try_from(report.observed_at_unix_seconds).map_err(|_| denied())?,
        )
        .map_err(|_| denied())?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| denied())?;
        let confirmations = u32::try_from(
            tip.tip
                .height
                .checked_sub(inclusion.height)
                .and_then(|v| v.checked_add(1))
                .ok_or_else(denied)?,
        )
        .map_err(|_| denied())?;
        let trust = wholepact_core::proposal::canonical_digest(
            "wholepact:local-resolution-record-source:v1",
            source,
        )?;
        let policy = ObservationPolicy {
            source_id: source.source_id.clone(),
            trust_profile_id: trust.clone(),
            adapter_id: "qualified-local-node".into(),
        };
        let mut projection = QualifiedObservation(SourcedChainObservation {
            transaction: exact.clone(),
            adapter_id: policy.adapter_id.clone(),
            observation: wholepact_core::ChainObservation {
                observation_id: evidence.evidence_id().into(),
                source_id: source.source_id.clone(),
                trust_profile_id: trust,
                observed_at: observed.clone(),
                tip_height: u32::try_from(tip.tip.height).map_err(|_| denied())?,
                tip_hash: tip.tip.hash.clone(),
                synchronized: true,
                status: if conflict {
                    wholepact_core::ChainStatus::ConflictedObserved
                } else {
                    wholepact_core::ChainStatus::ConfirmationPolicyMet
                },
                inclusion_height: Some(u32::try_from(inclusion.height).map_err(|_| denied())?),
                inclusion_hash: Some(inclusion.hash.clone()),
                confirmations,
                evidence_ref: evidence.evidence_id().into(),
            },
        });
        let current = SettlementRecord::load_retained_archive(self.record.clone())?;
        let (next, event) = current.observe(
            &mut projection,
            &policy,
            &ObservationWindow {
                now: observed.clone(),
                oldest_acceptable: observed,
            },
        )?;
        let exposure = if conflict {
            wholepact_core::AuthorizationExposure::OutstandingUncertain
        } else {
            wholepact_core::AuthorizationExposure::Consumed
        };
        if event == RecordEvent::ExactReplay && self.record.own_authorization.exposure == exposure {
            return Ok(Some(false));
        }
        self.record = next.archive();
        self.record.own_authorization.exposure = exposure;
        // Preserve any earlier restore/reorganization reconciliation warning.
        SettlementRecord::load_retained_archive(self.record.clone())?;
        advance_record_revision(self)?;
        Ok(Some(true))
    }
}
