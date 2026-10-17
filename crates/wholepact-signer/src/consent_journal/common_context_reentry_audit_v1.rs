//! Immutable, non-authoritative local closure for the explicit construction
//! transport handoff. No serialized row can reconstruct a process-local owner.
use super::*;
use rusqlite::{Connection, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wholepact_authority::construction_transport_handoff_v1::*;
use wholepact_authority::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use wholepact_authority::manual_roster_witness_v2::ManualRosterSessionContinuationV2;
use wholepact_authority::{ConstructionHistoryV2, WriterStatus};
use wholepact_core::common_context_reentry_v1::RosterCommonContextReentryLineageV1;
use wholepact_signer_origin::common_context_reentry_v1::RosterReenteredConstructionEvidenceV1;
use wholepact_signer_origin::roster_common_context_read_v1::RosterCommonContextReadEvidenceV1;

/// New forms retain the existing signer record and complete-history limits.
/// Larger full-plan lineages fail closed; these DTOs do not widen availability.
pub const MAX_REENTRY_AUDIT_RECORD_BYTES: usize = MAX_RECORD_BYTES;
pub const MAX_REENTRY_AUDIT_INVENTORY_BYTES: usize =
    crate::authority_bridge::host_recovery_ipc::v4::MAX_COMPLETE_HISTORY_V4_BYTES;
pub const MAX_REENTRY_AUDIT_ROWS: usize = 48;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonContextReentrySignerAuditV1 {
    pub version: u16,
    pub account_id: String,
    pub invocation_digest: String,
    pub original_read_admission_digest: String,
    pub record: CommonContextReentryAuditPhaseV1,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommonContextReentryAuditPhaseV1 {
    Authorized {
        authorization: Box<SignedConstructionTransportPreauthorizationV1>,
    },
    Granted {
        grant: Box<PendingConstructionTransportGrantV1>,
    },
    Claimed {
        credential: Box<ConstructionTransportCredentialV1>,
    },
    Reentered {
        lineage: Box<RosterCommonContextReentryLineageV1>,
        witness_history: Box<ConstructionHistoryWithTransportV1>,
    },
    Reserved {
        reentry_lineage_digest: String,
        extension: Box<ManualRosterEnrollmentExtensionV2>,
        continuation: Box<ManualRosterSessionContinuationV2>,
        record: Box<ConstructionTransportReservationRecordV1>,
    },
    Consumed {
        reentry_lineage_digest: String,
        record: Box<ConstructionTransportConsumedRecordV1>,
        evidence: Box<RosterReenteredConstructionEvidenceV1>,
    },
}
impl CommonContextReentrySignerAuditV1 {
    pub fn phase(&self) -> &'static str {
        match &self.record {
            CommonContextReentryAuditPhaseV1::Authorized { .. } => "authorized",
            CommonContextReentryAuditPhaseV1::Granted { .. } => "granted",
            CommonContextReentryAuditPhaseV1::Claimed { .. } => "claimed",
            CommonContextReentryAuditPhaseV1::Reentered { .. } => "reentered",
            CommonContextReentryAuditPhaseV1::Reserved { .. } => "reserved",
            CommonContextReentryAuditPhaseV1::Consumed { .. } => "consumed",
        }
    }
    /// Shape only. Complete semantic/authenticated-origin joins are mandatory in
    /// CommonContextSignerAuditInventoryV2::validate[_against].
    pub fn validate_shape(&self) -> Result<()> {
        if self.version != 1 {
            return Err(JournalError::InvalidBinding);
        }
        hash(&self.account_id)?;
        hash(&self.invocation_digest)?;
        hash(&self.original_read_admission_digest)?;
        bounded(self, MAX_REENTRY_AUDIT_RECORD_BYTES)?;
        match &self.record {
            CommonContextReentryAuditPhaseV1::Authorized { authorization } => {
                authorization.digest().map_err(invalid)?;
            }
            CommonContextReentryAuditPhaseV1::Granted { grant } => {
                grant.validate().map_err(invalid)?;
            }
            CommonContextReentryAuditPhaseV1::Claimed { credential } => {
                credential.validate().map_err(invalid)?;
            }
            CommonContextReentryAuditPhaseV1::Reentered {
                lineage,
                witness_history,
            } => {
                lineage.validate().map_err(invalid)?;
                witness_history.validate().map_err(invalid)?;
            }
            CommonContextReentryAuditPhaseV1::Reserved {
                reentry_lineage_digest,
                extension,
                continuation,
                record,
            } => {
                hash(reentry_lineage_digest)?;
                hash(&record.credential_id)?;
                record
                    .original
                    .validate_for(extension, continuation)
                    .map_err(invalid)?;
            }
            CommonContextReentryAuditPhaseV1::Consumed {
                reentry_lineage_digest,
                record,
                evidence,
            } => {
                hash(reentry_lineage_digest)?;
                hash(&record.credential_id)?;
                evidence.validate().map_err(invalid)?;
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate_shape()?;
        self.encoded_digest()
    }
    // Only for an exact immutable row already validated in this same call.
    fn encoded_digest(&self) -> Result<String> {
        digest("wholepact:signer-common-context-reentry-audit:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonContextReentryAuditInventoryV1 {
    pub version: u16,
    pub rows: Vec<CommonContextReentrySignerAuditV1>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonContextSignerAuditInventoryV2 {
    pub version: u16,
    pub original: CommonContextSignerAuditInventoryV1,
    pub reentry: CommonContextReentryAuditInventoryV1,
}
fn invalid<E>(_: E) -> JournalError {
    JournalError::InvalidBinding
}
fn bounded<T: Serialize>(v: &T, max: usize) -> Result<()> {
    if serde_json::to_vec(v).map_err(invalid)?.len() > max {
        Err(JournalError::Limit)
    } else {
        Ok(())
    }
}
fn active(history: &ConstructionHistoryV2) -> Result<&wholepact_authority::WriterSessionReceipt> {
    let s = history.observed_snapshot();
    if s.writer_status != WriterStatus::Active {
        return Err(JournalError::Conflict);
    }
    let session = s
        .active_writer_session
        .as_ref()
        .ok_or(JournalError::InvalidBinding)?;
    if session.writer_epoch != s.writer_epoch
        || session.writer_certificate_digest != s.writer_certificate_digest
    {
        return Err(JournalError::Conflict);
    }
    Ok(session)
}
fn read_row<'a>(
    old: &'a CommonContextSignerAuditInventoryV1,
    row: &CommonContextReentrySignerAuditV1,
) -> Result<(
    &'a RosterCommonContextReadEvidenceV1,
    &'a ConstructionHistoryV2,
)> {
    let mut found = None;
    for r in &old.rows {
        if r.invocation_digest()? != row.invocation_digest {
            continue;
        }
        match r {
            CommonContextSignerAuditV1::ReadAdmitted {
                evidence,
                witness_history,
                ..
            } if found.is_none() => {
                found = Some((evidence.as_ref(), witness_history.as_ref()));
            }
            // A reentry may not coexist with the legacy same-caller construction
            // branch for the same invocation, even if its monetary fields match.
            _ => return Err(JournalError::Conflict),
        }
    }
    let (read, history) = found.ok_or(JournalError::InvalidBinding)?;
    if read.digest().map_err(invalid)? != row.original_read_admission_digest {
        return Err(JournalError::Conflict);
    }
    Ok((read, history))
}
fn require_authorization(
    a: &SignedConstructionTransportPreauthorizationV1,
    read: &RosterCommonContextReadEvidenceV1,
    history: &ConstructionHistoryV2,
) -> Result<()> {
    let birth = history
        .original_birth()
        .ok_or(JournalError::InvalidBinding)?;
    a.verify(&birth.request.policy.owner_certificate_digest)
        .map_err(invalid)?;
    let auth = &a.authorization;
    let genesis = birth
        .request
        .policy
        .account_use_genesis
        .as_ref()
        .ok_or(JournalError::InvalidBinding)?;
    if auth.account_id != read.request.plan.enrollment().identity.account_id
        || auth.network_profile_id != read.request.plan.enrollment().identity.network_profile_id
        || auth.genesis_digest != genesis.digest().map_err(invalid)?
        || auth.policy_digest != history.observed_snapshot().policy_digest
        || &auth.original_session != active(history)?
        || auth.original_session.expires_at_ms != read.writer_session_expires_at_ms
        || auth.attempt_digest != read.current_attempt_digest
        || auth.attempt_sequence != read.current_attempt_sequence
        || auth.read_request_digest != read.request.digest().map_err(invalid)?
        || auth.read_evidence_digest != read.digest().map_err(invalid)?
        || auth.plan_approval_digest != read.request.witness_plan_approval_digest
        || auth.invocation_digest != read.request.plan.invocation_digest().map_err(invalid)?
        || auth.original_caller_binding_digest != read.request.current_caller_binding_digest
        || auth.native_review_digest == read.native_review_digest
        || auth.authorized_at_ms < read.admitted_at_ms
        || auth.expires_at_ms > read.request.completion_expires_at_ms
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
// Sole caller has completed validate_shape for every immutable borrowed row.
// This helper retains the complete cross-row and authenticated-origin joins.
fn require_lineage_after_shapes(
    lineage: &RosterCommonContextReentryLineageV1,
    credential: &ConstructionTransportCredentialV1,
    read: &RosterCommonContextReadEvidenceV1,
    old_history: &ConstructionHistoryV2,
    current: &ConstructionHistoryWithTransportV1,
) -> Result<()> {
    let a = credential.authorization();
    let claim = &credential.signed_claim.claim;
    let birth = old_history
        .original_birth()
        .ok_or(JournalError::InvalidBinding)?;
    credential
        .signed_claim
        .verify(&birth.request.policy.owner_certificate_digest)
        .map_err(invalid)?;
    let s = current.original.observed_snapshot();
    if lineage.request.original_read != read.request
        || lineage.request.pending_grant_digest
            != credential.pending_grant.digest().map_err(invalid)?
        || lineage.request.requested_at_ms < credential.pending_grant.grant.granted_at_ms
        || lineage.request.admission_expires_at_ms > a.expires_at_ms
        || lineage.request.original_read_admission_digest != read.digest().map_err(invalid)?
        || lineage.request.original_attempt_digest != read.current_attempt_digest
        || lineage.request.original_attempt_sequence != read.current_attempt_sequence
        || lineage.retained_signer_intent_digest != read.retained_signer_intent_digest
        || lineage.original_native_binding_digest != a.original_native_binding_digest
        || lineage.original_host_process_digest != a.original_host_process_commitment
        || lineage.original_record_digest
            != read
                .request
                .plan
                .retained
                .selection
                .scope
                .provenance
                .signer_roster_record_digest
        || lineage.original_genesis_digest != a.genesis_digest
        || lineage.original_birth_digest != birth.request.native_birth_digest
        || lineage.current_native_binding_digest != claim.new_native_binding_digest
        || lineage.request.current_caller_binding_digest != claim.new_caller_binding_digest
        || lineage.native_review_digest != claim.native_review_digest
        || claim.native_review_digest == read.native_review_digest
        || claim.native_review_digest == a.native_review_digest
        || claim.native_review_digest == credential.pending_grant.grant.native_review_digest
        || lineage.construction_transport_credential_digest
            != credential.digest().map_err(invalid)?
        || lineage.construction_transport_credential_id != credential.credential_id()
        || lineage.original_transport_fence_digest != credential.old_key_fence_digest
        || lineage.current_writer_session_digest
            != digest(
                "wholepact:common-context-reentry-writer-session:v1",
                &a.original_session,
            )?
        || lineage.current_writer_session_expires_at_ms != a.original_session.expires_at_ms
        || active(&current.original)? != &a.original_session
        || lineage.current_witness_history_digest != current.original.complete_replay_digest()
        || current.original.witness() != old_history.witness()
        || current.original.original_birth() != old_history.original_birth()
        || old_history.observed_snapshot().head.sequence > s.head.sequence
        || (old_history.observed_snapshot().head.sequence == s.head.sequence
            && old_history != &current.original)
        || old_history.observed_snapshot().last_witness_time_ms > s.last_witness_time_ms
        || old_history
            .approvals()
            .iter()
            .any(|a| !current.original.approvals().contains(a))
        || old_history
            .origins()
            .iter()
            .any(|o| !current.original.origins().contains(o))
        || !current.transport.credentials.contains(credential)
        || !current.transport.grants.contains(&credential.pending_grant)
        || current
            .transport
            .reservations
            .iter()
            .any(|r| r.credential_id == credential.credential_id())
        || lineage.admitted_at_ms < claim.claimed_at_ms
        || lineage.completion_expires_at_ms > a.expires_at_ms
        || lineage.admitted_at_ms >= a.expires_at_ms
        || s.head.sequence < credential.claimed_head.sequence
        || (s.head.sequence == credential.claimed_head.sequence
            && s.head != credential.claimed_head)
        || s.transport_fences.as_ref().is_none_or(|f| {
            f.version != 1
                || !f
                    .fenced_session_ids
                    .contains(&a.original_session.session_id)
        })
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
impl CommonContextSignerAuditInventoryV2 {
    pub fn validate(&self, account: &str) -> Result<()> {
        self.validate_header()?;
        self.original.validate(account)?;
        self.validate_reentry_after_original(account)
    }
    fn validate_header(&self) -> Result<()> {
        if self.version != 2
            || self.reentry.version != 1
            || self.reentry.rows.len() > MAX_REENTRY_AUDIT_ROWS
        {
            return Err(JournalError::Limit);
        }
        bounded(self, MAX_REENTRY_AUDIT_INVENTORY_BYTES)
    }
    // Only the public full validator and the private actual-reader factory
    // below reach this body, after exact original validation for this account.
    fn validate_reentry_after_original(&self, account: &str) -> Result<()> {
        let mut rows = BTreeMap::new();
        let mut previous = None;
        for row in &self.reentry.rows {
            row.validate_shape()?;
            let key = (row.invocation_digest.clone(), row.phase());
            if row.account_id != account
                || previous.as_ref().is_some_and(|p| p >= &key)
                || rows.insert(key.clone(), row).is_some()
            {
                return Err(JournalError::Conflict);
            }
            previous = Some(key);
        }
        // No cache survives this validation call. References bind the exact
        // immutable original and Authorized row, not just an invocation name.
        struct ValidatedInvocation<'a> {
            read: &'a RosterCommonContextReadEvidenceV1,
            history: &'a ConstructionHistoryV2,
            authorization: &'a SignedConstructionTransportPreauthorizationV1,
            read_digest: &'a str,
        }
        let mut invocations = BTreeMap::<&str, ValidatedInvocation<'_>>::new();
        for row in &self.reentry.rows {
            let get = |phase| {
                rows.get(&(row.invocation_digest.clone(), phase))
                    .copied()
                    .ok_or(JournalError::InvalidBinding)
            };
            let binding = match invocations.entry(row.invocation_digest.as_str()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let (read, history) = read_row(&self.original, row)?;
                    let auth = match &get("authorized")?.record {
                        CommonContextReentryAuditPhaseV1::Authorized { authorization } => {
                            authorization.as_ref()
                        }
                        _ => return Err(JournalError::InvalidBinding),
                    };
                    require_authorization(auth, read, history)?;
                    entry.insert(ValidatedInvocation {
                        read,
                        history,
                        authorization: auth,
                        read_digest: &row.original_read_admission_digest,
                    })
                }
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            };
            if binding.read_digest != row.original_read_admission_digest.as_str() {
                return Err(JournalError::Conflict);
            }
            let read = binding.read;
            let history = binding.history;
            let auth = binding.authorization;
            let credential = || -> Result<&ConstructionTransportCredentialV1> {
                match &get("claimed")?.record {
                    CommonContextReentryAuditPhaseV1::Claimed { credential } => Ok(credential),
                    _ => Err(JournalError::InvalidBinding),
                }
            };
            let lineage = || -> Result<&RosterCommonContextReentryLineageV1> {
                match &get("reentered")?.record {
                    CommonContextReentryAuditPhaseV1::Reentered { lineage, .. } => Ok(lineage),
                    _ => Err(JournalError::InvalidBinding),
                }
            };
            match &row.record {
                CommonContextReentryAuditPhaseV1::Authorized { .. } => {}
                CommonContextReentryAuditPhaseV1::Granted { grant } => {
                    if &grant.grant.authorization != auth
                        || grant.grant.native_review_digest
                            == auth.authorization.native_review_digest
                        || grant.grant.native_review_digest == read.native_review_digest
                    {
                        return Err(JournalError::Conflict);
                    }
                }
                CommonContextReentryAuditPhaseV1::Claimed { credential } => {
                    let CommonContextReentryAuditPhaseV1::Granted { grant } =
                        &get("granted")?.record
                    else {
                        return Err(JournalError::InvalidBinding);
                    };
                    if &credential.pending_grant != grant.as_ref() {
                        return Err(JournalError::Conflict);
                    }
                    credential
                        .signed_claim
                        .verify(
                            &history
                                .original_birth()
                                .ok_or(JournalError::InvalidBinding)?
                                .request
                                .policy
                                .owner_certificate_digest,
                        )
                        .map_err(invalid)?;
                }
                CommonContextReentryAuditPhaseV1::Reentered {
                    lineage,
                    witness_history,
                } => require_lineage_after_shapes(
                    lineage,
                    credential()?,
                    read,
                    history,
                    witness_history,
                )?,
                CommonContextReentryAuditPhaseV1::Reserved {
                    reentry_lineage_digest,
                    extension,
                    continuation,
                    record,
                } => {
                    let lineage = lineage()?;
                    if *reentry_lineage_digest != lineage.digest().map_err(invalid)?
                        || record.credential_id != credential()?.credential_id()
                        || extension.as_ref() != &record.extension
                        || continuation.as_ref() != &record.continuation
                    {
                        return Err(JournalError::Conflict);
                    }
                    require_reservation_after_shapes(
                        lineage,
                        &record.original,
                        extension,
                        continuation,
                    )?;
                }
                CommonContextReentryAuditPhaseV1::Consumed {
                    reentry_lineage_digest,
                    record,
                    evidence,
                } => {
                    let CommonContextReentryAuditPhaseV1::Reserved {
                        extension,
                        continuation,
                        record: reserved,
                        ..
                    } = &get("reserved")?.record
                    else {
                        return Err(JournalError::InvalidBinding);
                    };
                    let lineage = lineage()?;
                    if *reentry_lineage_digest != lineage.digest().map_err(invalid)?
                        || &evidence.reentry_lineage != lineage
                        || record.credential_id != reserved.credential_id
                        || record.credential_id != credential()?.credential_id()
                    {
                        return Err(JournalError::Conflict);
                    }
                    CommonContextSignerAuditV1::Consumed {
                        version: 1,
                        extension: extension.clone(),
                        continuation: continuation.clone(),
                        reservation: Box::new(reserved.original.clone()),
                        consumed: Box::new(record.original.clone()),
                        evidence: Box::new(evidence.construction.clone()),
                    }
                    .validate()?;
                }
            }
        }
        Ok(())
    }
    fn from_validated_original(
        account: &str,
        original: construction_audit_v3::ValidatedOriginalAudit,
        rows: Vec<CommonContextReentrySignerAuditV1>,
    ) -> Result<Self> {
        let value = Self {
            version: 2,
            original: original.into_inventory_for(account)?,
            reentry: CommonContextReentryAuditInventoryV1 { version: 1, rows },
        };
        value.validate_header()?;
        value.validate_reentry_after_original(account)?;
        Ok(value)
    }
}
// Sole caller has validated this exact record against these same extension
// and continuation values in the preceding complete shape pass.
fn require_reservation_after_shapes(
    l: &RosterCommonContextReentryLineageV1,
    r: &wholepact_authority::manual_roster_construction_v3::ManualRosterConstructionReservationRecordV3,
    e: &ManualRosterEnrollmentExtensionV2,
    c: &ManualRosterSessionContinuationV2,
) -> Result<()> {
    let request = &r.request;
    if request.construction.plan != l.request.original_read.plan
        || request.construction.current_caller_binding_digest
            != l.request.current_caller_binding_digest
        || request.construction.requested_at_ms < l.admitted_at_ms
        || request.construction.admission_expires_at_ms > l.completion_expires_at_ms
        || request.construction.operation_id == l.request.operation_id
        || request.construction.operation_id == l.request.original_read.operation_id
        || request.signer_intent_digest != l.retained_signer_intent_digest
        || request.attempt_digest != l.request.current_attempt_digest
        || request.attempt_sequence != l.request.current_attempt_sequence
        || c.digest_for(e).map_err(invalid)? != l.current_witness_continuation_digest
        || c.sequence() != l.request.current_attempt_sequence
        || request.native_review_digest == l.native_review_digest
        || request.reviewed_at_ms < l.admitted_at_ms
        || r.admitted_at_ms >= l.completion_expires_at_ms
        || r.session.expires_at_ms != l.current_writer_session_expires_at_ms
        || digest(
            "wholepact:common-context-reentry-writer-session:v1",
            &r.session,
        )? != l.current_writer_session_digest
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
impl CommonContextSignerAuditInventoryV2 {
    pub fn validate_against(&self, history: &ConstructionHistoryWithTransportV1) -> Result<()> {
        history.validate().map_err(invalid)?;
        self.validate(&history.original.observed_snapshot().account_id)?;
        // The explicit new envelope contains the unchanged legacy branch and
        // ALL new transport origins. No legacy API receives a filtered union.
        validate_original_after_complete(&self.original, history)?;
        for grant in &history.transport.grants {
            let a = &grant.grant.authorization.authorization;
            if self.original.rows.iter().any(|r| {
                r.invocation_digest().ok().as_deref() == Some(a.invocation_digest.as_str())
            }) {
                let synthetic_key = CommonContextReentrySignerAuditV1 {
                    version: 1,
                    account_id: a.account_id.clone(),
                    invocation_digest: a.invocation_digest.clone(),
                    original_read_admission_digest: a.read_evidence_digest.clone(),
                    record: CommonContextReentryAuditPhaseV1::Granted {
                        grant: Box::new(grant.clone()),
                    },
                };
                let (read, old_history) = read_row(&self.original, &synthetic_key)?;
                require_authorization(&grant.grant.authorization, read, old_history)?;
            }
        }
        for row in &self.reentry.rows {
            match &row.record {
                CommonContextReentryAuditPhaseV1::Authorized { authorization } => {
                    if history.transport.grants.iter().any(|g| {
                        g.grant.authorization.authorization.invocation_digest
                            == row.invocation_digest
                            && &g.grant.authorization != authorization.as_ref()
                    }) {
                        return Err(JournalError::Conflict);
                    }
                }
                CommonContextReentryAuditPhaseV1::Granted { grant }
                    if !history.transport.grants.contains(grant) =>
                {
                    return Err(JournalError::Conflict);
                }
                CommonContextReentryAuditPhaseV1::Claimed { credential }
                    if !history.transport.credentials.contains(credential) =>
                {
                    return Err(JournalError::Conflict);
                }
                CommonContextReentryAuditPhaseV1::Reserved { record, .. }
                    if !history.transport.reservations.contains(record) =>
                {
                    return Err(JournalError::Conflict);
                }
                CommonContextReentryAuditPhaseV1::Consumed { record, .. }
                    if !history.transport.consumptions.contains(record) =>
                {
                    return Err(JournalError::Conflict);
                }
                CommonContextReentryAuditPhaseV1::Reentered {
                    witness_history: prior,
                    ..
                } => {
                    let p = prior.original.observed_snapshot();
                    let now = history.original.observed_snapshot();
                    if prior.original.witness() != history.original.witness()
                        || prior.original.original_birth() != history.original.original_birth()
                        || p.head.sequence > now.head.sequence
                        || (p.head.sequence == now.head.sequence && prior.as_ref() != history)
                        || p.last_witness_time_ms > now.last_witness_time_ms
                        || prior
                            .original
                            .approvals()
                            .iter()
                            .any(|a| !history.original.approvals().contains(a))
                        || prior
                            .original
                            .origins()
                            .iter()
                            .any(|o| !history.original.origins().contains(o))
                        || prior
                            .transport
                            .grants
                            .iter()
                            .any(|g| !history.transport.grants.contains(g))
                        || prior
                            .transport
                            .credentials
                            .iter()
                            .any(|c| !history.transport.credentials.contains(c))
                        || prior
                            .transport
                            .reservations
                            .iter()
                            .any(|r| !history.transport.reservations.contains(r))
                        || prior
                            .transport
                            .consumptions
                            .iter()
                            .any(|c| !history.transport.consumptions.contains(c))
                    {
                        return Err(JournalError::Conflict);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
    /// Missing local receipts are explicit uncertainty. Remote reservation and
    /// consumption amounts remain fully charged in the authoritative history.
    pub fn missing_local_phases(
        &self,
        history: &ConstructionHistoryWithTransportV1,
    ) -> Result<MissingCommonContextNativeAuditV2> {
        self.validate_against(history)?;
        let legacy = missing_original_after_complete(&self.original, history)?;
        let mut transport = Vec::new();
        for grant in &history.transport.grants {
            let auth = &grant.grant.authorization.authorization;
            let credential = history
                .transport
                .credentials
                .iter()
                .find(|c| c.pending_grant == *grant);
            let reserved = credential.and_then(|c| {
                history
                    .transport
                    .reservations
                    .iter()
                    .find(|r| r.credential_id == c.credential_id())
            });
            let consumed = credential.and_then(|c| {
                history
                    .transport
                    .consumptions
                    .iter()
                    .find(|r| r.credential_id == c.credential_id())
            });
            let has = |phase| {
                self.reentry
                    .rows
                    .iter()
                    .any(|r| r.invocation_digest == auth.invocation_digest && r.phase() == phase)
            };
            let value = MissingConstructionTransportNativeAuditV1 {
                invocation_digest:auth.invocation_digest.clone(),
                original_read_admission_digest:auth.read_evidence_digest.clone(),
                authority_grant_digest:grant.digest().map_err(invalid)?,
                authority_credential_digest:credential.map(|c| c.digest().map_err(invalid)).transpose()?,
                authority_reservation_digest:reserved.map(|r| r.original.digest_for(&r.extension,&r.continuation).map_err(invalid)).transpose()?,
                authority_consumed_digest:consumed.map(|c| {
                    let r = reserved.ok_or(JournalError::InvalidBinding)?;
                    c.original.digest_for(&r.original,&r.extension,&r.continuation).map_err(invalid)
                }).transpose()?,
                missing_read_admission:!self.original.rows.iter().any(|r| matches!(r,CommonContextSignerAuditV1::ReadAdmitted{evidence,..} if evidence.digest().ok().as_deref()==Some(auth.read_evidence_digest.as_str()))),
                missing_authorized:!has("authorized"), missing_granted:!has("granted"),
                missing_claimed:credential.is_some() && !has("claimed"),
                missing_reentered:credential.is_some() && !has("reentered"),
                missing_reserved:reserved.is_some() && !has("reserved"),
                missing_consumed:consumed.is_some() && !has("consumed"),
            };
            if value.missing_read_admission
                || value.missing_authorized
                || value.missing_granted
                || value.missing_claimed
                || value.missing_reentered
                || value.missing_reserved
                || value.missing_consumed
            {
                transport.push(value);
            }
        }
        Ok(MissingCommonContextNativeAuditV2 {
            version: 2,
            legacy,
            transport,
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingConstructionTransportNativeAuditV1 {
    pub invocation_digest: String,
    pub original_read_admission_digest: String,
    pub authority_grant_digest: String,
    pub authority_credential_digest: Option<String>,
    pub authority_reservation_digest: Option<String>,
    pub authority_consumed_digest: Option<String>,
    pub missing_read_admission: bool,
    pub missing_authorized: bool,
    pub missing_granted: bool,
    pub missing_claimed: bool,
    pub missing_reentered: bool,
    pub missing_reserved: bool,
    pub missing_consumed: bool,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingCommonContextNativeAuditV2 {
    pub version: u16,
    pub legacy: Vec<MissingCommonContextNativeAuditV1>,
    pub transport: Vec<MissingConstructionTransportNativeAuditV1>,
}

pub(super) fn read_complete(
    c: &Connection,
    account: &str,
) -> Result<CommonContextSignerAuditInventoryV2> {
    let original = construction_audit_v3::read_all_validated(c, account)?;
    let mut q = c.prepare("SELECT invocation_digest,phase,account_id,receipt_digest,payload FROM signer_common_context_reentry_v1 ORDER BY invocation_digest,phase")?;
    let mut rows = Vec::new();
    let mut saved_digests = Vec::new();
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
        let (invocation, phase, owner, saved_digest, payload) = row?;
        let payload = Zeroizing::new(payload);
        if payload.len() > MAX_REENTRY_AUDIT_RECORD_BYTES {
            return Err(JournalError::Limit);
        }
        let row: CommonContextReentrySignerAuditV1 =
            serde_json::from_str(&payload).map_err(invalid)?;
        if row.invocation_digest != invocation
            || row.phase() != phase
            || row.account_id != owner
        {
            return Err(JournalError::InvalidBinding);
        }
        // Equality to a canonical digest already required this exact shape.
        // Bound the retained comparison value before storing it for validation.
        hash(&saved_digest)?;
        saved_digests.push(saved_digest);
        rows.push(row);
        if rows.len() > MAX_REENTRY_AUDIT_ROWS {
            return Err(JournalError::Limit);
        }
    }
    let inventory = CommonContextSignerAuditInventoryV2::from_validated_original(
        account, original, rows,
    )?;
    for (row, saved_digest) in inventory.reentry.rows.iter().zip(saved_digests) {
        if row.encoded_digest()? != saved_digest {
            return Err(JournalError::InvalidBinding);
        }
    }
    Ok(inventory)
}
impl SignerConsentJournal {
    /// Producer-only immutable append. External grant/claim/Reserve/Consume may
    /// already be durable: failure never refunds, resets, or restores an owner.
    pub(crate) fn retain_common_context_reentry_audit_v1(
        &self,
        row: &CommonContextReentrySignerAuditV1,
    ) -> Result<()> {
        row.validate_shape()?;
        let _fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account = storage::read_account(&tx)?;
        if account.recovery_required || row.account_id != account.account_id {
            return Err(JournalError::RecoveryRequired);
        }
        let before = read_complete(&tx, &account.account_id)?;
        if before
            .reentry
            .rows
            .iter()
            .any(|r| r.invocation_digest == row.invocation_digest && r.phase() == row.phase())
        {
            return Err(JournalError::Conflict);
        }
        let payload = Zeroizing::new(serde_json::to_string(row).map_err(invalid)?);
        if payload.len() > MAX_REENTRY_AUDIT_RECORD_BYTES {
            return Err(JournalError::Limit);
        }
        tx.execute(
            "INSERT INTO signer_common_context_reentry_v1 VALUES(?1,?2,?3,?4,?5)",
            params![
                row.invocation_digest,
                row.phase(),
                row.account_id,
                row.encoded_digest()?,
                payload.as_str()
            ],
        )?;
        read_complete(&tx, &account.account_id)?;
        storage::bounded(&tx, self.capacity_limits())?;
        tx.commit()?;
        Ok(())
    }
}

// Only called after the complete new authority wrapper has been validated.
// This reproduces the unchanged legacy row joins; it never exports or accepts
// the old branch as a complete history when transport origins exist.
fn validate_original_after_complete(
    old: &CommonContextSignerAuditInventoryV1,
    complete: &ConstructionHistoryWithTransportV1,
) -> Result<()> {
    let history = &complete.original;

    old.validate(&history.observed_snapshot().account_id)?;
    for row in &old.rows {
        match row {
                CommonContextSignerAuditV1::ReadAdmitted {
                    witness_history, evidence, ..
                } => {
                    if witness_history.witness() != history.witness()
                        || witness_history.original_birth() != history.original_birth()
                        || witness_history.observed_snapshot().head.sequence
                            > history.observed_snapshot().head.sequence
                        || (witness_history.observed_snapshot().head.sequence
                            == history.observed_snapshot().head.sequence
                            && witness_history.as_ref() != history)
                        || witness_history.observed_snapshot().last_witness_time_ms
                            > history.observed_snapshot().last_witness_time_ms
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
                        require_legacy_read_reservation_link(evidence,origin.reservation())?;
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

fn missing_original_after_complete(
    old: &CommonContextSignerAuditInventoryV1,
    complete: &ConstructionHistoryWithTransportV1,
) -> Result<Vec<MissingCommonContextNativeAuditV1>> {
    let history = &complete.original;

    let mut missing = Vec::new();
    for origin in history.origins() {
        let wholepact_authority::ConstructionOriginHistoryV2::CommonContextV3 { origin } = origin
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
            old.rows.iter().any(|r| {
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

fn require_legacy_read_reservation_link(
    read: &RosterCommonContextReadEvidenceV1,
    reservation: &wholepact_authority::manual_roster_construction_v3::ManualRosterConstructionReservationRecordV3,
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

#[cfg(test)]
mod encoded_bound_tests {
    use super::*;
    #[test]
    fn reentry_encoded_row_and_inventory_limits_reject_one_extra_byte() {
        for limit in [
            MAX_REENTRY_AUDIT_RECORD_BYTES,
            MAX_REENTRY_AUDIT_INVENTORY_BYTES,
        ] {
            let exact = "a".repeat(limit - 2);
            assert_eq!(serde_json::to_vec(&exact).unwrap().len(), limit);
            bounded(&exact, limit).unwrap();
            let over = format!("{exact}a");
            assert_eq!(serde_json::to_vec(&over).unwrap().len(), limit + 1);
            assert!(matches!(bounded(&over, limit), Err(JournalError::Limit)));
        }
    }
}
