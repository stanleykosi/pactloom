//! Exact born ancestry from the actual client's complete authenticated replay.
//! Returned values are immutable evidence, never permits or signing authority.
use super::super::super::named_recipient_records::{
    BornNamedManualParentV1, BornNamedRecipientOriginV1,
};
use super::*;
use wholepact_authority::{
    AuthorityClient, OwnerControl, ReconciledAuthorityHistory, WriterStatus,
    born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1,
};

/// First native original review must bind the current complete parent head and
/// its digest. Later original recovery never substitutes a newer parent digest.
pub(super) fn authenticate_parent_draft(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    history: &ReconciledAuthorityHistory,
    client: &AuthorityClient,
) -> ImportResult<BornNamedRecipientOriginV1> {
    let origin = authenticate_parents(profile, original, history, client)?;
    if &origin.parent_head != &history.snapshot().head
        || origin.parent_history_digest != history.history_digest().map_err(unavailable)?
    {
        return Err(TransportError::WrongContext);
    }
    Ok(origin)
}

/// This function accepts only the opaque actual reconciled history, not a
/// parsed history DTO. The retained original separately comes from the genuine
/// native owner's journal; its actual signer genesis is checked by its caller.
pub(super) fn authenticate_parents(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    history: &ReconciledAuthorityHistory,
    client: &AuthorityClient,
) -> ImportResult<BornNamedRecipientOriginV1> {
    let origin = original
        .born_origin
        .as_ref()
        .ok_or(TransportError::AuthorityUnavailable)?;
    origin
        .validate_structure(&profile.record, original)
        .map_err(unavailable)?;
    let witness = client.disclosure_descriptor();
    let e = &origin.enrollment.enrollment;
    if history.disclosure() != &witness
        || witness.pinned_server_certificate_digest != profile.record.witness_certificate_digest
        || witness.account_id != profile.record.account_id
        || witness.network_profile_id != original.terms.network_profile_id
        || history.snapshot().writer_status == WriterStatus::Quarantined
        || history.account_use_history().exclusion().is_some()
        || history.account_use_history().genesis() != Some(&origin.signer_genesis)
        || history.pending_birth_commit() != Some(&origin.birth)
        || history.account_policy() != &origin.birth.request.policy
        || history.born_offline_enrollment_v1().map_err(unavailable)? != Some(&origin.enrollment)
        || history.born_offline_artifacts_v1().map_err(unavailable)? != Some(&origin.artifacts)
        || history
            .born_offline_manual_extension_v1()
            .map_err(unavailable)?
            != origin.manual_extension()
        || !history.contains_head(&origin.parent_head)
        || !history.contains_head(&e.expected_head)
        || !history.contains_head(&origin.artifacts.binding.expected_head)
        || !history.contains_head(&e.original_writer_session.acquired_head)
        || !history.contains_head(&e.original_writer_session.reconciled_head)
    {
        return Err(TransportError::Authentication);
    }
    let construction = history
        .born_offline_construction_origin_v1(&origin.request.construction_link)
        .map_err(unavailable)?;
    origin
        .request
        .construction_link
        .validate_for(&construction, &origin.request.reservation)
        .map_err(unavailable)?;
    origin
        .checkpoint_origin
        .validate_for_origin(&construction)
        .map_err(unavailable)?;
    if let Some(owner) = &origin.enrollment.enrollment.owner_continuation {
        owner
            .validate_origin(&origin.enrollment.enrollment, &construction)
            .map_err(unavailable)?;
    }
    if construction.reservation.session != origin.enrollment.enrollment.original_writer_session {
        return Err(TransportError::Authentication);
    }
    // Preserve exact original parent family and signature/review evidence,
    // rather than projecting a roster parent into its inner V1 extension.
    let parent_digest = origin.manual_parent.digest().map_err(unavailable)?;
    let operation = match &origin.manual_parent {
        BornNamedManualParentV1::Single { .. } => format!("manual-extend-{parent_digest}"),
        BornNamedManualParentV1::RosterV2 { .. } => {
            format!("manual-roster-extend-v2-{parent_digest}")
        }
    };
    let parent = history
        .owner_control_request(&operation)
        .ok_or(TransportError::Authentication)?;
    let exact = match (&origin.manual_parent, &parent.control) {
        (
            BornNamedManualParentV1::Single { record: expected },
            OwnerControl::ExtendManualEnrollment { record },
        ) => expected == record.as_ref(),
        (
            BornNamedManualParentV1::RosterV2 { record: expected },
            OwnerControl::ExtendManualRosterEnrollmentV2 { record },
        ) => expected == record.as_ref(),
        _ => false,
    };
    if !exact || !history.contains_head(&parent.expected_head) {
        return Err(TransportError::Authentication);
    }
    Ok(origin.clone())
}

/// Exact original admission from the same complete native-born history. This
/// is data-only and is never converted into a legacy offline admission wrapper.
pub(super) fn authenticate_admission(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    history: &ReconciledAuthorityHistory,
    client: &AuthorityClient,
) -> ImportResult<BornOfflineAuthorizationAdmissionV1> {
    let origin = authenticate_parents(profile, original, history, client)?;
    let admission = history
        .born_offline_admission_v1(&origin.request.reservation.operation_id)
        .ok_or(TransportError::Authentication)?;
    admission
        .matches_request(&origin.request)
        .map_err(unavailable)?;
    admission
        .validate_reserved_policy_bounds(
            history.account_policy(),
            &origin.enrollment.enrollment,
            &origin.artifacts,
            origin.manual_extension(),
        )
        .map_err(unavailable)?;
    let witness = history.disclosure();
    if admission.reserved.witness_id != witness.witness_id
        || admission.reserved.witness_policy_digest != witness.policy_digest
        || !history.contains_head(&admission.reserved.committed_head)
        || admission.reserved.request_digest != original.reservation_request_digest
    {
        return Err(TransportError::WrongContext);
    }
    Ok(admission.clone())
}
