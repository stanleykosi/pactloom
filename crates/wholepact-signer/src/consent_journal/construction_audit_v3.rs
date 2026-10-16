//! Durable inert provenance for the actual V3 native read and Reserve/Consume.
//! Append occurs after genuine admission and before disclosing success. Every
//! phase retains its predecessors; no restart/recovery creates live authority.
use super::*;
use rusqlite::{Connection, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wholepact_authority::{
    ConstructionApprovalHistoryV2, ConstructionHistoryV2,
    manual_roster_construction_v3::{
        ManualRosterConstructionConsumedRecordV3, ManualRosterConstructionReservationRecordV3,
    },
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    manual_roster_witness_v2::ManualRosterSessionContinuationV2,
};
use wholepact_signer_origin::{
    manual_roster_construction_v2::ManualRosterContributionRetentionEvidenceV2,
    manual_roster_construction_v3::ManualRosterConstructionContributionEvidenceV3,
    roster_common_context_read_v1::RosterCommonContextReadEvidenceV1,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommonContextSignerAuditV1 {
    ReadAdmitted {
        version: u16,
        original: Box<ManualRosterContributionRetentionEvidenceV2>,
        evidence: Box<RosterCommonContextReadEvidenceV1>,
        witness_history: Box<ConstructionHistoryV2>,
    },
    Reserved {
        version: u16,
        read_admission_digest: String,
        extension: Box<ManualRosterEnrollmentExtensionV2>,
        continuation: Box<ManualRosterSessionContinuationV2>,
        record: Box<ManualRosterConstructionReservationRecordV3>,
    },
    Consumed {
        version: u16,
        extension: Box<ManualRosterEnrollmentExtensionV2>,
        continuation: Box<ManualRosterSessionContinuationV2>,
        reservation: Box<ManualRosterConstructionReservationRecordV3>,
        consumed: Box<ManualRosterConstructionConsumedRecordV3>,
        evidence: Box<ManualRosterConstructionContributionEvidenceV3>,
    },
}
impl CommonContextSignerAuditV1 {
    pub fn plan(
        &self,
    ) -> &wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3 {
        match self {
            Self::ReadAdmitted { evidence, .. } => &evidence.request.plan,
            Self::Reserved { record, .. } => &record.request.construction.plan,
            Self::Consumed { evidence, .. } => &evidence.request.plan,
        }
    }
    pub fn phase(&self) -> &'static str {
        match self {
            Self::ReadAdmitted { .. } => "read_admitted",
            Self::Reserved { .. } => "reserved",
            Self::Consumed { .. } => "consumed",
        }
    }
    pub fn invocation_digest(&self) -> Result<String> {
        self.plan()
            .invocation_digest()
            .map_err(|_| JournalError::InvalidBinding)
    }
    pub fn account_id(&self) -> &str {
        &self.plan().enrollment().identity.account_id
    }
    pub fn validate(&self) -> Result<()> {
        self.plan()
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        match self {
            Self::ReadAdmitted {
                version,
                original,
                evidence,
                witness_history,
            } => {
                if *version != 1 {
                    return Err(JournalError::InvalidBinding);
                }
                original
                    .validate()
                    .map_err(|_| JournalError::InvalidBinding)?;
                evidence
                    .validate()
                    .map_err(|_| JournalError::InvalidBinding)?;
                witness_history
                    .validate()
                    .map_err(|_| JournalError::InvalidBinding)?;
                if original.request != evidence.request.plan.retained
                    || original
                        .digest()
                        .map_err(|_| JournalError::InvalidBinding)?
                        != evidence.request.plan.retained_evidence_digest
                    || original.retained_signer_intent_digest
                        != evidence.retained_signer_intent_digest
                    || witness_history.observed_snapshot().account_id != self.account_id()
                {
                    return Err(JournalError::InvalidBinding);
                }
                let matching = witness_history
                    .approvals()
                    .iter()
                    .filter(|a| match a {
                        ConstructionApprovalHistoryV2::CommonContextV3 { extension, record } => {
                            record.approval.plan == evidence.request.plan
                                && record.approval.digest_for(extension).ok().as_deref()
                                    == Some(&evidence.request.witness_plan_approval_digest)
                        }
                        ConstructionApprovalHistoryV2::RosterV2 { .. } => false,
                    })
                    .count();
                if matching != 1 {
                    return Err(JournalError::InvalidBinding);
                }
            }
            Self::Reserved {
                version,
                read_admission_digest,
                extension,
                continuation,
                record,
            } => {
                if *version != 1 {
                    return Err(JournalError::InvalidBinding);
                }
                hash(read_admission_digest)?;
                record
                    .validate_for(extension, continuation)
                    .map_err(|_| JournalError::InvalidBinding)?;
            }
            Self::Consumed {
                version,
                extension,
                continuation,
                reservation,
                consumed,
                evidence,
            } => {
                if *version != 1 {
                    return Err(JournalError::InvalidBinding);
                }
                consumed
                    .validate_for(reservation, extension, continuation)
                    .map_err(|_| JournalError::InvalidBinding)?;
                evidence
                    .validate()
                    .map_err(|_| JournalError::InvalidBinding)?;
                if evidence.request != reservation.request.construction
                    || evidence.witness_reservation_digest
                        != reservation
                            .digest_for(extension, continuation)
                            .map_err(|_| JournalError::InvalidBinding)?
                    || evidence.witness_consumed_digest
                        != consumed
                            .digest_for(reservation, extension, continuation)
                            .map_err(|_| JournalError::InvalidBinding)?
                    || evidence.retained_signer_intent_digest
                        != reservation.request.signer_intent_digest
                    || evidence.current_attempt_digest != reservation.request.attempt_digest
                    || evidence.current_attempt_sequence != reservation.request.attempt_sequence
                    || evidence.native_review_digest != reservation.request.native_review_digest
                    || evidence.reviewed_at_ms != reservation.request.reviewed_at_ms
                    || evidence.reserved_at_ms != reservation.admitted_at_ms
                    || evidence.consumed_at_ms != consumed.consumed_at_ms
                    || evidence.reserved_debit_zatoshis != reservation.reserved_debit_zatoshis
                    || evidence.reserved_input_value_zatoshis
                        != reservation.reserved_input_value_zatoshis
                    || evidence.writer_session_expires_at_ms != reservation.session.expires_at_ms
                {
                    return Err(JournalError::InvalidBinding);
                }
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest("wholepact:signer-common-context-audit:v1", self)
            .map_err(|_| JournalError::InvalidBinding)
    }
}
/// Full exact inventory. Empty means no local V3 receipts, never no witness
/// exposure; recovery must still join complete authenticated authority history.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonContextSignerAuditInventoryV1 {
    pub version: u16,
    pub rows: Vec<CommonContextSignerAuditV1>,
}
impl CommonContextSignerAuditInventoryV1 {
    pub fn validate(&self, account: &str) -> Result<()> {
        if self.version != 1 || self.rows.len() > 48 {
            return Err(JournalError::Limit);
        }
        let mut by_key = BTreeMap::new();
        let mut previous = None;
        for row in &self.rows {
            row.validate()?;
            let key = (row.invocation_digest()?, row.phase());
            if row.account_id() != account
                || previous.as_ref().is_some_and(|p| p >= &key)
                || by_key.insert(key.clone(), row).is_some()
            {
                return Err(JournalError::Conflict);
            }
            previous = Some(key);
        }
        for row in &self.rows {
            let key = row.invocation_digest()?;
            match row {
                CommonContextSignerAuditV1::ReadAdmitted { .. } => {}
                CommonContextSignerAuditV1::Reserved {
                    read_admission_digest,
                    record,
                    ..
                } => {
                    let Some(CommonContextSignerAuditV1::ReadAdmitted { evidence, .. }) =
                        by_key.get(&(key.clone(), "read_admitted")).copied()
                    else {
                        return Err(JournalError::InvalidBinding);
                    };
                    if evidence
                        .digest()
                        .map_err(|_| JournalError::InvalidBinding)?
                        != *read_admission_digest
                    {
                        return Err(JournalError::Conflict);
                    }
                    require_read_reservation_link(evidence, record)?;
                }
                CommonContextSignerAuditV1::Consumed {
                    reservation,
                    evidence,
                    ..
                } => {
                    let Some(CommonContextSignerAuditV1::Reserved {
                        record,
                        read_admission_digest,
                        ..
                    }) = by_key.get(&(key, "reserved")).copied()
                    else {
                        return Err(JournalError::InvalidBinding);
                    };
                    if record != reservation
                        || *read_admission_digest != evidence.common_context_read_admission_digest
                    {
                        return Err(JournalError::Conflict);
                    }
                    let Some(CommonContextSignerAuditV1::ReadAdmitted { evidence: read, .. }) =
                        by_key
                            .get(&(row.invocation_digest()?, "read_admitted"))
                            .copied()
                    else {
                        return Err(JournalError::InvalidBinding);
                    };
                    if evidence.witness_plan_approval_digest
                        != read.request.witness_plan_approval_digest
                        || evidence.retained_signer_intent_digest
                            != read.retained_signer_intent_digest
                        || evidence.current_attempt_digest != read.current_attempt_digest
                        || evidence.current_attempt_sequence != read.current_attempt_sequence
                    {
                        return Err(JournalError::Conflict);
                    }
                }
            }
        }
        Ok(())
    }
}
pub(super) fn read_all(
    c: &Connection,
    account: &str,
) -> Result<CommonContextSignerAuditInventoryV1> {
    let mut q = c.prepare("SELECT invocation_digest,phase,account_id,receipt_digest,payload FROM signer_common_context_audit_v3 ORDER BY invocation_digest,phase")?;
    let mut rows = Vec::new();
    let result = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    for row in result {
        let (invocation, phase, owner, digest, payload) = row?;
        let row: CommonContextSignerAuditV1 = decode(payload)?;
        if invocation != row.invocation_digest()?
            || phase != row.phase()
            || owner != row.account_id()
            || digest != row.digest()?
        {
            return Err(JournalError::InvalidBinding);
        }
        rows.push(row);
    }
    let value = CommonContextSignerAuditInventoryV1 { version: 1, rows };
    value.validate(account)?;
    Ok(value)
}
impl SignerConsentJournal {
    /// Private producer-only append. Admission/Reserve/Consume have already
    /// occurred; failure is uncertainty, never cancellation or refunded charge.
    pub(crate) fn retain_common_context_audit_v3(
        &self,
        record: &CommonContextSignerAuditV1,
    ) -> Result<()> {
        record.validate()?;
        let _fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account = storage::read_account(&tx)?;
        if account.recovery_required || record.account_id() != account.account_id {
            return Err(JournalError::RecoveryRequired);
        }
        let prior = read_all(&tx, &account.account_id)?;
        if prior.rows.iter().any(|r| {
            r.invocation_digest().ok() == record.invocation_digest().ok()
                && r.phase() == record.phase()
        }) {
            return Err(JournalError::Conflict);
        }
        tx.execute(
            "INSERT INTO signer_common_context_audit_v3 VALUES(?1,?2,?3,?4,?5)",
            params![
                record.invocation_digest()?,
                record.phase(),
                record.account_id(),
                record.digest()?,
                encode(record)?.as_str()
            ],
        )?;
        // The schema15 inventory also checks the mutually exclusive
        // same-caller and reentered construction branches. A legacy append
        // must not leave a mixed history that only fails on the next reopen.
        common_context_reentry_audit_v1::read_complete(&tx, &account.account_id)?;
        storage::bounded(&tx, self.capacity_limits())?;
        tx.commit()?;
        Ok(())
    }
}

impl CommonContextSignerAuditInventoryV1 {
    /// Complete historical join. Missing local success after an authority
    /// Reserve/Consume is uncertainty, never a second attempt or an empty ledger.
    pub fn validate_against(&self, history: &ConstructionHistoryV2) -> Result<()> {
        self.validate(&history.observed_snapshot().account_id)?;
        history
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        for row in &self.rows {
            match row {
                CommonContextSignerAuditV1::ReadAdmitted {
                    witness_history, evidence, ..
                } => {
                    if witness_history.witness() != history.witness()
                        || witness_history.original_birth() != history.original_birth()
                        || witness_history
                            .approvals()
                            .iter()
                            .any(|a| !history.approvals().contains(a))
                    {
                        return Err(JournalError::Conflict);
                    }
                    let key=&evidence.request.plan.retained.selection.scope.selection.invocation.idempotency_key_digest;
                    for origin in history.origins().iter().filter(|o| o.original_key_digest()==key) {
                        let wholepact_authority::ConstructionOriginHistoryV2::CommonContextV3 {origin}=origin else {return Err(JournalError::Conflict);};
                        require_read_reservation_link(evidence,origin.reservation())?;
                    }
                }
                CommonContextSignerAuditV1::Reserved { record, extension, continuation, .. } => {
                    if !history.origins().iter().any(|o| {
                        matches!(o,
                        wholepact_authority::ConstructionOriginHistoryV2::CommonContextV3 { origin }
                        if origin.reservation() == record.as_ref() && origin.extension() == extension.as_ref() && origin.continuation() == continuation.as_ref())
                    }) {
                        return Err(JournalError::Conflict);
                    }
                }
                CommonContextSignerAuditV1::Consumed { consumed, reservation, extension, continuation, .. } => {
                    if !history.origins().iter().any(|o| {
                        matches!(o,
                        wholepact_authority::ConstructionOriginHistoryV2::CommonContextV3 { origin }
                        if origin.consumed() == Some(consumed.as_ref()) && origin.reservation() == reservation.as_ref() && origin.extension() == extension.as_ref() && origin.continuation() == continuation.as_ref())
                    }) {
                        return Err(JournalError::Conflict);
                    }
                }
            }
        }
        // Authority effects can durably precede the local success append. Missing
        // local rows are explicit charged uncertainty, never fabricated receipts.
        Ok(())
    }
}

/// Derived audit facts only. Missing local success never refunds authoritative
/// exposure or supplies a native read/construction owner.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingCommonContextNativeAuditV1 {
    pub invocation_digest: String,
    pub authority_reservation_digest: String,
    pub authority_consumed_digest: Option<String>,
    pub missing_read_admission: bool,
    pub missing_reserved: bool,
    pub missing_consumed: bool,
}
impl CommonContextSignerAuditInventoryV1 {
    pub fn missing_local_phases(
        &self,
        history: &ConstructionHistoryV2,
    ) -> Result<Vec<MissingCommonContextNativeAuditV1>> {
        self.validate_against(history)?;
        let mut missing = Vec::new();
        for origin in history.origins() {
            let wholepact_authority::ConstructionOriginHistoryV2::CommonContextV3 { origin } =
                origin
            else {
                continue;
            };
            let invocation_digest = origin
                .reservation()
                .request
                .construction
                .plan
                .invocation_digest()
                .map_err(|_| JournalError::InvalidBinding)?;
            let has = |phase| {
                self.rows.iter().any(|r| {
                    r.phase() == phase
                        && r.invocation_digest().ok().as_deref() == Some(invocation_digest.as_str())
                })
            };
            let value = MissingCommonContextNativeAuditV1 {
                authority_reservation_digest: origin
                    .reservation()
                    .digest_for(origin.extension(), origin.continuation())
                    .map_err(|_| JournalError::InvalidBinding)?,
                authority_consumed_digest: origin
                    .consumed()
                    .map(|c| {
                        c.digest_for(
                            origin.reservation(),
                            origin.extension(),
                            origin.continuation(),
                        )
                        .map_err(|_| JournalError::InvalidBinding)
                    })
                    .transpose()?,
                missing_read_admission: !has("read_admitted"),
                missing_reserved: !has("reserved"),
                missing_consumed: origin.consumed().is_some() && !has("consumed"),
                invocation_digest,
            };
            if value.missing_read_admission || value.missing_reserved || value.missing_consumed {
                missing.push(value);
            }
        }
        Ok(missing)
    }
}

/// The same exact join applies whether Reserve success was appended locally or
/// only the authenticated authority archive survived the crash boundary.
fn require_read_reservation_link(
    read: &RosterCommonContextReadEvidenceV1,
    reservation: &ManualRosterConstructionReservationRecordV3,
) -> Result<()> {
    if read.request.plan != reservation.request.construction.plan
        || read.request.current_caller_binding_digest
            != reservation
                .request
                .construction
                .current_caller_binding_digest
        || read.retained_signer_intent_digest != reservation.request.signer_intent_digest
        || read.current_attempt_digest != reservation.request.attempt_digest
        || read.current_attempt_sequence != reservation.request.attempt_sequence
        || read.writer_session_expires_at_ms != reservation.session.expires_at_ms
        || read.admitted_at_ms > reservation.request.reviewed_at_ms
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
