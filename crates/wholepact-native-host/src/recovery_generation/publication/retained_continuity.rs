//! Read-only consumers of EXISTING V4/V5 retained continuity evidence.
//! This is not a generation manifest, publication record, native admission or
//! live-recovery capability. Authentication and disclosure approval belong to
//! the containing archive owner; these functions establish historical joins only.
//! No V4 bytes are upgraded, filtered, or relabeled as complete V5 history.
use super::*;
use std::collections::BTreeMap;
use wholepact_authority::{ConstructionApprovalHistoryV2, ConstructionOriginHistoryV2};
use wholepact_core::common_context_reentry_v1::RosterCommonContextReentryLineageV1;
use wholepact_signer::{
    authority_bridge::host_recovery_ipc::{
        v2::{HostRecoveryHistoryV2, HostRecoveryReservationOriginV2},
        v4::{HostRecoveryContinuityEvidenceV4, MAX_COMPLETE_HISTORY_V4_BYTES},
        v5::HostRecoveryContinuityEvidenceV5,
    },
    consent_journal::{CommonContextReentryAuditPhaseV1, CommonContextSignerAuditV1},
};
use wholepact_store::{
    manual_enrollment::{
        ManualRosterConsumedConstructionAuditV2, ManualRosterConsumedConstructionAuditV3,
    },
    recovery::StoreRecoveryInventory,
};

/// The expected version and digest must come from the containing authenticated
/// inventory, never an untrusted filename or a caller's claimed approval flag.
/// No serialized container/commit format is introduced here.
pub(super) struct RetainedContinuityInput<'a> {
    pub(super) version: u16,
    pub(super) evidence_digest: &'a str,
    pub(super) bytes: &'a [u8],
}

/// Private complete variants prevent returning V5's legacy subrecord as an old
/// complete-history envelope. Decoding does not authenticate a native decision.
enum RetainedContinuity {
    V4(Box<HostRecoveryContinuityEvidenceV4>),
    V5(Box<HostRecoveryContinuityEvidenceV5>),
}
impl RetainedContinuity {
    fn read(input: &RetainedContinuityInput<'_>) -> Result<Self> {
        canonical_hash(input.evidence_digest)?;
        if input.bytes.len() > MAX_COMPLETE_HISTORY_V4_BYTES + 4096 {
            return Err(Error::Authentication);
        }
        // Typed Deserialize rejects missing/unknown fields and duplicate struct
        // fields. Each complete validator checks BOTH explicit version markers.
        let value = match input.version {
            4 => Self::V4(Box::new(serde_json::from_slice(input.bytes)?)),
            5 => Self::V5(Box::new(serde_json::from_slice(input.bytes)?)),
            _ => return Err(Error::Unsupported),
        };
        let digest = match &value {
            Self::V4(e) => e.digest(),
            Self::V5(e) => e.digest(),
        }
        .map_err(|_| Error::Authentication)?;
        if digest != input.evidence_digest {
            return Err(Error::Authentication);
        }
        Ok(value)
    }
    fn account(&self) -> &str {
        match self {
            Self::V4(e) => &e.request.account_id,
            Self::V5(e) => &e.request.account_id,
        }
    }
    fn binding(&self) -> (&str, &str) {
        match self {
            Self::V4(e) => (&e.request.generation_id, &e.request.inventory_digest),
            Self::V5(e) => (&e.request.generation_id, &e.request.inventory_digest),
        }
    }
    fn financial(&self) -> &HostRecoveryHistoryV2 {
        match self {
            Self::V4(e) => &e.complete_history.financial_origins_v2,
            Self::V5(e) => &e.complete_history.financial_origins_v2,
        }
    }
    // Only private views AFTER the full complete-envelope validator above.
    fn construction(&self) -> &wholepact_authority::ConstructionHistoryV2 {
        match self {
            Self::V4(e) => &e.complete_history.construction,
            Self::V5(e) => &e.complete_history.construction.original,
        }
    }
    fn original_audit(
        &self,
    ) -> &wholepact_signer::consent_journal::CommonContextSignerAuditInventoryV1 {
        match self {
            Self::V4(e) => &e.complete_history.signer_common_context_audit,
            Self::V5(e) => &e.complete_history.signer_common_context_audit.original,
        }
    }
}

/// Historical uncertainty is versioned with its complete source. Missing native
/// success never reduces authority charges or proves a builder did not run.
pub(super) enum MissingLocalPhases {
    V4(Vec<wholepact_signer::consent_journal::MissingCommonContextNativeAuditV1>),
    V5(wholepact_signer::consent_journal::MissingCommonContextNativeAuditV2),
}

/// Inert inspection result. No Serialize/Deserialize, native admission,
/// publication method, Store handle, session or financial-runtime conversion.
pub(super) struct RetainedHistoryInspection {
    pub(super) conservative_debit_by_account: BTreeMap<String, u64>,
    pub(super) obligation_fences: BTreeSet<String>,
    pub(super) transport_fences_by_account: BTreeMap<String, wholepact_authority::construction_transport_handoff_v1::ConstructionTransportFenceSnapshotV1>,
    pub(super) unresolved_offline_authorizations: BTreeSet<String>,
    pub(super) unmatched_host_authorizations: BTreeSet<String>,
    pub(super) missing_local_phases: BTreeMap<String, MissingLocalPhases>,
    histories: BTreeMap<String, RetainedContinuity>,
}

/// Inspect the exact complete account set of an already authenticated source.
/// The containing archive owner must separately bind its exact input inventory,
/// schema/digest pairs and account set. This function does not accept a commit
/// or admission. A publication owner may use this inert validator only alongside
/// its independent complete inventory and genuine native admission checks.
pub(super) fn inspect_retained_continuity(
    inputs: &[RetainedContinuityInput<'_>],
    generation: &str,
    inventory_digest: &str,
    affected_accounts: &BTreeSet<String>,
    store: &StoreRecoveryInventory,
) -> Result<RetainedHistoryInspection> {
    canonical_hash(generation)?;
    canonical_hash(inventory_digest)?;
    if !store.accounts().is_subset(affected_accounts) {
        return Err(Error::Authentication);
    }
    let mut inspection =
        inspect_account_rows(inputs, generation, inventory_digest, affected_accounts)?;
    for (_, claim) in store.construction_claims() {
        claim.validate().map_err(|_| Error::Authentication)?;
        for native in &claim.consumed {
            let account = &native.request.plan.enrollment().identity.account_id;
            require_roster_consume(
                inspection
                    .histories
                    .get(account)
                    .ok_or(Error::Authentication)?,
                native,
            )?;
        }
    }
    for (_, claim) in store.construction_claims_v3() {
        claim.validate().map_err(|_| Error::Authentication)?;
        for (index, native) in claim.consumed.iter().enumerate() {
            let account = &native.request.plan.enrollment().identity.account_id;
            let history = inspection
                .histories
                .get(account)
                .ok_or(Error::Authentication)?;
            match (claim.version, &claim.reentry_lineages) {
                (3, None) => require_original_common_context_consume(history, native)?,
                (4, Some(lineages)) => {
                    let RetainedContinuity::V5(e) = history else {
                        return Err(Error::RecoveryFinancialUnsupported);
                    };
                    require_reentered_consume(e, native, &lineages[index])?;
                }
                (5, Some(lineages)) => {
                    // Version 5 adds genuine Host scanner provenance, not a
                    // new signer attestation. Require its COMPLETE exact read
                    // lineage validation before the unchanged consumed join.
                    claim
                        .require_historical_provenance_v5()
                        .map_err(|_| Error::Authentication)?;
                    let RetainedContinuity::V5(e) = history else {
                        return Err(Error::RecoveryFinancialUnsupported);
                    };
                    require_reentered_consume(
                        e,
                        native,
                        lineages.get(index).ok_or(Error::Authentication)?,
                    )?;
                }
                _ => return Err(Error::Authentication),
            }
        }
    }
    // StoreRecoveryInventory already authenticates every checkpoint-to-claim
    // join, immutable row digest, fence and absent-byte uncertainty. Do not
    // reopen a writable Store or synthesize checkpoint success here.
    inspection.unmatched_host_authorizations =
        match_releases(store.releases(), &inspection.histories)?;
    // Preserve Store-only obligations as well as the complete signer union.
    inspection
        .obligation_fences
        .extend(store.obligations().iter().cloned());
    Ok(inspection)
}

fn inspect_account_rows(
    inputs: &[RetainedContinuityInput<'_>],
    generation: &str,
    inventory: &str,
    affected: &BTreeSet<String>,
) -> Result<RetainedHistoryInspection> {
    if inputs.len() != affected.len() {
        return Err(Error::Authentication);
    }
    // Retain the existing Host document ceiling across the complete account
    // inventory; per-account V5 envelopes do not multiply the archive budget.
    let total = inputs.iter().try_fold(0usize, |total, input| {
        total
            .checked_add(input.bytes.len())
            .ok_or(Error::Authentication)
    })?;
    if total > MAX_DOCUMENT {
        return Err(Error::Authentication);
    }
    let mut value = RetainedHistoryInspection {
        conservative_debit_by_account: BTreeMap::new(),
        obligation_fences: BTreeSet::new(),
        transport_fences_by_account: BTreeMap::new(),
        unresolved_offline_authorizations: BTreeSet::new(),
        unmatched_host_authorizations: BTreeSet::new(),
        missing_local_phases: BTreeMap::new(),
        histories: BTreeMap::new(),
    };
    let mut previous: Option<String> = None;
    for input in inputs {
        let history = RetainedContinuity::read(input)?;
        let account = history.account().to_owned();
        if history.binding() != (generation, inventory)
            || previous.as_ref().is_some_and(|p| p >= &account)
        {
            return Err(Error::Authentication);
        }
        previous = Some(account.clone());
        if let Some(fences) = &history.construction().observed_snapshot().transport_fences {
            value
                .transport_fences_by_account
                .insert(account.clone(), fences.clone());
        }
        let (debit, obligations, unresolved, missing) = match &history {
            RetainedContinuity::V4(e) => (
                e.complete_history.conservative_debit_zatoshis(),
                e.complete_history.conservative_obligations(),
                e.complete_history.unresolved_offline_authorizations(),
                e.complete_history
                    .missing_local_native_phases()
                    .map(MissingLocalPhases::V4),
            ),
            RetainedContinuity::V5(e) => (
                e.complete_history.conservative_debit_zatoshis(),
                e.complete_history.conservative_obligations(),
                e.complete_history.unresolved_offline_authorizations(),
                e.complete_history
                    .missing_local_native_phases()
                    .map(MissingLocalPhases::V5),
            ),
        };
        value
            .conservative_debit_by_account
            .insert(account.clone(), debit.map_err(|_| Error::Authentication)?);
        value
            .obligation_fences
            .extend(obligations.map_err(|_| Error::Authentication)?);
        value
            .unresolved_offline_authorizations
            .extend(unresolved.map_err(|_| Error::Authentication)?);
        value
            .missing_local_phases
            .insert(account.clone(), missing.map_err(|_| Error::Authentication)?);
        if value.histories.insert(account, history).is_some() {
            return Err(Error::Authentication);
        }
    }
    if value.histories.keys().cloned().collect::<BTreeSet<_>>() != *affected {
        return Err(Error::Authentication);
    }
    Ok(value)
}

fn require_roster_consume(
    history: &RetainedContinuity,
    native: &ManualRosterConsumedConstructionAuditV2,
) -> Result<()> {
    native.validate().map_err(|_| Error::Authentication)?;
    let matching = history
        .construction()
        .origins()
        .iter()
        .filter(|origin| {
            let ConstructionOriginHistoryV2::RosterV2 { origin } = origin else {
                return false;
            };
            let r = origin.reservation();
            let Some(c) = origin.consumed() else {
                return false;
            };
            r.request.construction == native.request
                && r.digest_for(origin.extension(), origin.continuation())
                    .ok()
                    .as_deref()
                    == Some(native.witness_reservation_digest.as_str())
                && c.digest_for(r, origin.extension(), origin.continuation())
                    .ok()
                    .as_deref()
                    == Some(native.witness_consumed_digest.as_str())
                && r.request.signer_intent_digest == native.retained_signer_intent_digest
                && r.request.attempt_digest == native.current_attempt_digest
                && r.request.attempt_sequence == native.current_attempt_sequence
                && r.request.native_review_digest == native.native_review_digest
                && r.request.reviewed_at_ms == native.reviewed_at_ms
                && r.admitted_at_ms == native.reserved_at_ms
                && c.consumed_at_ms == native.consumed_at_ms
                && r.reserved_debit_zatoshis == native.reserved_debit_zatoshis
                && r.reserved_input_value_zatoshis == native.reserved_input_value_zatoshis
                && r.session.expires_at_ms == native.writer_session_expires_at_ms
        })
        .count();
    if matching != 1 {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn require_plan_approval(
    history: &wholepact_authority::ConstructionHistoryV2,
    native: &ManualRosterConsumedConstructionAuditV3,
) -> Result<()> {
    if history.approvals().iter().filter(|a| {
        matches!(a, ConstructionApprovalHistoryV2::CommonContextV3 { extension, record }
            if record.approval.plan == native.request.plan
            && record.approval.digest_for(extension).ok().as_deref() == Some(native.witness_plan_approval_digest.as_str()))
    }).count() != 1 { return Err(Error::Authentication); }
    Ok(())
}

fn exact_consume(
    r: &wholepact_authority::manual_roster_construction_v3::ManualRosterConstructionReservationRecordV3,
    c: &wholepact_authority::manual_roster_construction_v3::ManualRosterConstructionConsumedRecordV3,
    extension: &wholepact_authority::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    continuation: &wholepact_authority::manual_roster_witness_v2::ManualRosterSessionContinuationV2,
    native: &ManualRosterConsumedConstructionAuditV3,
) -> bool {
    r.request.construction == native.request
        && r.digest_for(extension, continuation).ok().as_deref()
            == Some(native.witness_reservation_digest.as_str())
        && c.digest_for(r, extension, continuation).ok().as_deref()
            == Some(native.witness_consumed_digest.as_str())
        && r.request.signer_intent_digest == native.retained_signer_intent_digest
        && r.request.attempt_digest == native.current_attempt_digest
        && r.request.attempt_sequence == native.current_attempt_sequence
        && r.request.native_review_digest == native.native_review_digest
        && r.request.reviewed_at_ms == native.reviewed_at_ms
        && r.admitted_at_ms == native.reserved_at_ms
        && c.consumed_at_ms == native.consumed_at_ms
        && r.reserved_debit_zatoshis == native.reserved_debit_zatoshis
        && r.reserved_input_value_zatoshis == native.reserved_input_value_zatoshis
        && r.session.expires_at_ms == native.writer_session_expires_at_ms
}

fn require_original_common_context_consume(
    history: &RetainedContinuity,
    native: &ManualRosterConsumedConstructionAuditV3,
) -> Result<()> {
    native.validate().map_err(|_| Error::Authentication)?;
    require_plan_approval(history.construction(), native)?;
    let matching = history
        .construction()
        .origins()
        .iter()
        .filter(|origin| {
            let ConstructionOriginHistoryV2::CommonContextV3 { origin } = origin else {
                return false;
            };
            origin.consumed().is_some_and(|c| {
                exact_consume(
                    origin.reservation(),
                    c,
                    origin.extension(),
                    origin.continuation(),
                    native,
                )
            })
        })
        .count();
    if matching != 1 {
        return Err(Error::Authentication);
    }
    let invocation = native
        .request
        .plan
        .invocation_digest()
        .map_err(|_| Error::Authentication)?;
    let expected = native.digest().map_err(|_| Error::Authentication)?;
    for row in &history.original_audit().rows {
        if row.invocation_digest().map_err(|_| Error::Authentication)? != invocation {
            continue;
        }
        match row {
            CommonContextSignerAuditV1::Consumed { evidence, .. }
                if evidence.digest().ok().as_deref() != Some(expected.as_str()) =>
            {
                return Err(Error::Authentication);
            }
            CommonContextSignerAuditV1::ReadAdmitted { evidence, .. }
                if evidence.digest().ok().as_deref()
                    != Some(native.common_context_read_admission_digest.as_str()) =>
            {
                return Err(Error::Authentication);
            }
            _ => {}
        }
    }
    Ok(())
}

fn require_reentered_consume(
    evidence: &HostRecoveryContinuityEvidenceV5,
    native: &ManualRosterConsumedConstructionAuditV3,
    lineage: &RosterCommonContextReentryLineageV1,
) -> Result<()> {
    // Called after full V5 validation; retain this check for direct fixture use.
    evidence.validate().map_err(|_| Error::Authentication)?;
    native.validate().map_err(|_| Error::Authentication)?;
    lineage.validate().map_err(|_| Error::Authentication)?;
    let history = &evidence.complete_history;
    let transport = &history.construction.transport;
    require_plan_approval(&history.construction.original, native)?;
    let mut credentials = transport
        .credentials
        .iter()
        .filter(|c| c.credential_id() == lineage.construction_transport_credential_id);
    let credential = credentials.next().ok_or(Error::Authentication)?;
    if credentials.next().is_some() {
        return Err(Error::Authentication);
    }
    let authorization = credential.authorization();
    let claim = &credential.signed_claim.claim;
    let original = &lineage.request.original_read;
    let birth = history
        .construction
        .original
        .original_birth()
        .ok_or(Error::Authentication)?;
    if credential.digest().map_err(|_| Error::Authentication)?
        != lineage.construction_transport_credential_digest
        || credential.old_key_fence_digest != lineage.original_transport_fence_digest
        || credential
            .pending_grant
            .digest()
            .map_err(|_| Error::Authentication)?
            != lineage.request.pending_grant_digest
        || authorization.read_request_digest
            != original.digest().map_err(|_| Error::Authentication)?
        || authorization.read_evidence_digest != lineage.request.original_read_admission_digest
        || authorization.plan_approval_digest != native.witness_plan_approval_digest
        || authorization.invocation_digest
            != native
                .request
                .plan
                .invocation_digest()
                .map_err(|_| Error::Authentication)?
        || authorization.attempt_digest != lineage.request.current_attempt_digest
        || authorization.attempt_sequence != lineage.request.current_attempt_sequence
        || authorization.original_caller_binding_digest != original.current_caller_binding_digest
        || authorization.original_native_binding_digest != lineage.original_native_binding_digest
        || authorization.original_host_process_commitment != lineage.original_host_process_digest
        || authorization.genesis_digest != lineage.original_genesis_digest
        || birth.request.native_birth_digest != lineage.original_birth_digest
        || original
            .plan
            .retained
            .selection
            .scope
            .provenance
            .signer_roster_record_digest
            != lineage.original_record_digest
        || claim.new_native_binding_digest != lineage.current_native_binding_digest
        || claim.new_caller_binding_digest != lineage.request.current_caller_binding_digest
        || claim.native_review_digest != lineage.native_review_digest
        || authorization.original_session.expires_at_ms
            != lineage.current_writer_session_expires_at_ms
        || wholepact_core::proposal::canonical_digest(
            "wholepact:common-context-reentry-writer-session:v1",
            &authorization.original_session,
        )
        .map_err(|_| Error::Authentication)?
            != lineage.current_writer_session_digest
        || lineage.request.requested_at_ms < credential.pending_grant.grant.granted_at_ms
        || lineage.request.admission_expires_at_ms > authorization.expires_at_ms
        || lineage.admitted_at_ms < claim.claimed_at_ms
        || lineage.completion_expires_at_ms > authorization.expires_at_ms
        || native.request.plan != original.plan
        || native.request.current_caller_binding_digest
            != lineage.request.current_caller_binding_digest
        || native.request.operation_id == lineage.request.operation_id
        || native.request.operation_id == original.operation_id
        || native.request.requested_at_ms < lineage.admitted_at_ms
        || native.request.admission_expires_at_ms > lineage.completion_expires_at_ms
        || native.retained_signer_intent_digest != lineage.retained_signer_intent_digest
        || native.current_attempt_digest != lineage.request.current_attempt_digest
        || native.current_attempt_sequence != lineage.request.current_attempt_sequence
        || native.common_context_read_admission_digest
            != lineage.request.original_read_admission_digest
        || native.witness_plan_approval_digest != original.witness_plan_approval_digest
        || native.native_review_digest == lineage.native_review_digest
        || native.writer_session_expires_at_ms != lineage.current_writer_session_expires_at_ms
        || native.consumed_at_ms >= lineage.completion_expires_at_ms
    {
        return Err(Error::Authentication);
    }
    let mut reserves = transport
        .reservations
        .iter()
        .filter(|r| r.credential_id == credential.credential_id());
    let reserved = reserves.next().ok_or(Error::Authentication)?;
    let mut consumes = transport
        .consumptions
        .iter()
        .filter(|c| c.credential_id == credential.credential_id());
    let consumed = consumes.next().ok_or(Error::Authentication)?;
    if reserves.next().is_some()
        || consumes.next().is_some()
        || !exact_consume(
            &reserved.original,
            &consumed.original,
            &reserved.extension,
            &reserved.continuation,
            native,
        )
    {
        return Err(Error::Authentication);
    }
    let invocation = native
        .request
        .plan
        .invocation_digest()
        .map_err(|_| Error::Authentication)?;
    let native_digest = native.digest().map_err(|_| Error::Authentication)?;
    for row in &history.signer_common_context_audit.reentry.rows {
        if row.invocation_digest != invocation {
            continue;
        }
        match &row.record {
            CommonContextReentryAuditPhaseV1::Reentered {
                lineage: retained, ..
            } if retained.as_ref() != lineage => return Err(Error::Authentication),
            CommonContextReentryAuditPhaseV1::Consumed {
                evidence: retained, ..
            } if retained.reentry_lineage != *lineage
                || retained.construction.digest().ok().as_deref()
                    != Some(native_digest.as_str()) =>
            {
                return Err(Error::Authentication);
            }
            _ => {}
        }
    }
    // Missing local phases are retained in the inspection result. Never fabricate
    // an audit row or reinterpret absence as no construction/no debit.
    Ok(())
}

fn match_releases(
    releases: &[wholepact_store::authority::ReleaseIntent],
    histories: &BTreeMap<String, RetainedContinuity>,
) -> Result<BTreeSet<String>> {
    let mut unmatched = BTreeSet::new();
    for original in releases {
        let history = histories
            .get(&original.account_id)
            .ok_or(Error::Authentication)?;
        let mut matched = None;
        for candidate in &history.financial().origins {
            if candidate
                .authorization_id()
                .map_err(|_| Error::Authentication)?
                == original.authorization_id
                && matched.replace(candidate).is_some()
            {
                return Err(Error::Authentication);
            }
        }
        let Some(origin) = matched else {
            unmatched.insert(original.authorization_id.clone());
            continue;
        };
        let HostRecoveryReservationOriginV2::Online { permit } = origin else {
            return Err(Error::Authentication);
        };
        let request = &permit.request;
        let mut expected_inputs = original.input_ids.clone();
        expected_inputs.sort();
        let mut inputs = request
            .inputs
            .iter()
            .map(|i| i.input_id.clone())
            .collect::<Vec<_>>();
        inputs.sort();
        if request.writer_epoch != original.writer_epoch
            || request.account_id != original.account_id
            || request.obligation_id != original.obligation_id
            || request.proposal_id != original.proposal_id
            || request.manifest_digest != original.manifest_digest
            || request.effects_digest != original.effects_digest
            || request.artifact_digest != original.artifact_digest
            || request.maximum_debit_zatoshis.to_string() != original.maximum_debit
            || inputs != expected_inputs
        {
            return Err(Error::Authentication);
        }
    }
    Ok(unmatched)
}

#[cfg(all(test, feature = "manual-admission", target_os = "linux"))]
#[path = "retained_continuity_tests.rs"]
mod tests;
