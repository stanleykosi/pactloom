//! Purpose-specific history admission for a fresh original-roster continuation.
//! Approved V3 plans remain historical data, not construction/financial grants.
//! Generic legacy history readers continue to refuse those approvals.
use super::diagnostics::{self as diag, Phase as P};
use super::*;
use wholepact_authority::{ConstructionApprovalHistoryV2, ConstructionHistoryV2};
use wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3;

pub(super) fn require_original(
    retained: &RetainedBornManualRosterEnrollmentV2,
    history: &ReconciledAuthorityHistory,
) -> Result<()> {
    let extension = retained.record.extension()?;
    let archive = require_history(history, &extension)?;
    for approval in archive.approvals() {
        if let ConstructionApprovalHistoryV2::CommonContextV3 { record, .. } = approval {
            // The authenticated witness approval is not a substitute for this
            // account's exact encrypted, native-admitted local retention file.
            // This reads/checks the actual retained owner, not an imported DTO.
            diag::signer(
                P::ContinuationRetainedReceipt,
                retention::read_exact(
                    retained,
                    &record.approval.plan.retained,
                    &record.approval.plan.retained_evidence_digest,
                ),
            )?;
        }
    }
    Ok(())
}

fn require_history(
    history: &ReconciledAuthorityHistory,
    extension: &ManualRosterEnrollmentExtensionV2,
) -> Result<ConstructionHistoryV2> {
    // No financial origin, reserved/consumed construction, exposure, recovery
    // fence or transport history is admitted. Complete replay validates every
    // approval's full plan, birth and actual pinned owner signature.
    diag::authority(
        P::ContinuationHistoryGate,
        history.require_original_roster_preconstruction_history(),
    )
    .map_err(|_| Error::Unavailable)?;
    let archive = diag::authority(
        P::ContinuationHistoryArchive,
        history.construction_history_v2(),
    )
    .map_err(|_| Error::Authentication)?;
    for approval in archive.approvals() {
        if let ConstructionApprovalHistoryV2::CommonContextV3 {
            extension: approved_extension,
            record,
        } = approval
        {
            if approved_extension.as_ref() != extension {
                return Err(Error::Authentication);
            }
            let attempt = &record
                .approval
                .plan
                .retained
                .selection
                .scope
                .selection
                .inventory
                .attempt;
            let original = history
                .manual_roster_session_continuation_v2(&attempt.continuation_digest)
                .map_err(|_| Error::Authentication)?;
            require_original_attempt(&record.approval.plan, extension, original)?;
        }
    }
    Ok(archive)
}

fn require_original_attempt(
    plan: &ManualRosterConstructionPlanV3,
    extension: &ManualRosterEnrollmentExtensionV2,
    original: Option<&ManualRosterSessionContinuationV2>,
) -> Result<()> {
    let original = original.ok_or(Error::Authentication)?;
    original
        .validate_for(extension)
        .map_err(|_| Error::Authentication)?;
    let attempt = &plan.retained.selection.scope.selection.inventory.attempt;
    if original.sequence() != attempt.attempt_sequence
        || original
            .digest_for(extension)
            .map_err(|_| Error::Authentication)?
            != attempt.continuation_digest
    {
        return Err(Error::Authentication);
    }
    // Deliberately historical: this need not be the latest attempt. The caller
    // separately binds the fresh proposal to the actual latest predecessor,
    // snapshot and admission, preserving every original deadline/drain check.
    Ok(())
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;
    use wholepact_authority::pending_birth::PendingBirthCommitRecord;

    fn fixture() -> serde_json::Value {
        let raw: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../consent_journal/fixtures/common-context-authority-audit.synthetic.json"
        ))
        .unwrap();
        assert_eq!(raw["native_actors_exercised"], false);
        raw
    }

    fn replay(raw: &serde_json::Value, count: usize) -> ReconciledAuthorityHistory {
        let birth: PendingBirthCommitRecord =
            serde_json::from_value(raw["original_birth"].clone()).unwrap();
        let events = &raw["authority_events"].as_array().unwrap()[..count];
        wholepact_authority::transport::synthetic::recorded_fixture_history(
            &birth,
            &serde_json::to_vec(events).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn approval_history_keeps_original_attempt_and_legacy_refusal() {
        let raw = fixture();
        let extension: ManualRosterEnrollmentExtensionV2 =
            serde_json::from_value(raw["extension"].clone()).unwrap();
        // Actual signed owner approval, then its separately replayed newer
        // continuation and admission. No native/session owner is manufactured.
        for count in [9, 13] {
            let history = replay(&raw, count);
            let archive = require_history(&history, &extension).unwrap();
            assert_eq!(archive.approvals().len(), 1);
            assert!(archive.origins().is_empty());
            assert!(history.require_legacy_online_only().is_err());
            let ConstructionApprovalHistoryV2::CommonContextV3 { record, .. } =
                &archive.approvals()[0]
            else {
                panic!("exact V3 approval");
            };
            let original = &record
                .approval
                .plan
                .retained
                .selection
                .scope
                .selection
                .inventory
                .attempt;
            let latest = history
                .latest_manual_roster_attempt_v2(&extension.account_extension.enrollment_ref)
                .unwrap();
            assert_eq!(original.attempt_sequence, 2);
            assert_eq!(latest.sequence, if count == 9 { 2 } else { 3 });
        }
    }

    #[test]
    fn exposure_and_tampered_approval_history_remain_refused() {
        let raw = fixture();
        let extension: ManualRosterEnrollmentExtensionV2 =
            serde_json::from_value(raw["extension"].clone()).unwrap();
        for count in [14, 15] {
            let history = replay(&raw, count);
            assert!(require_history(&history, &extension).is_err());
            assert!(history.require_legacy_online_only().is_err());
        }
        let birth: PendingBirthCommitRecord =
            serde_json::from_value(raw["original_birth"].clone()).unwrap();
        let mut events = raw["authority_events"].as_array().unwrap()[..9].to_vec();
        let signature = events[8]["mutation"]["body"]["control"]["record"]
            ["owner_signature"]["signature"]
            .as_array_mut()
            .unwrap();
        signature[0] = serde_json::json!(signature[0].as_u64().unwrap() ^ 1);
        assert!(
            wholepact_authority::transport::synthetic::recorded_fixture_history(
                &birth,
                &serde_json::to_vec(&events).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn approval_cannot_cross_enrollment_or_original_attempt() {
        let raw = fixture();
        let extension: ManualRosterEnrollmentExtensionV2 =
            serde_json::from_value(raw["extension"].clone()).unwrap();
        let history = replay(&raw, 13);
        let archive = require_history(&history, &extension).unwrap();
        let mut foreign = extension.clone();
        foreign.signer_roster_record_digest = "ab".repeat(32);
        foreign.validate().unwrap();
        assert!(require_history(&history, &foreign).is_err());
        let ConstructionApprovalHistoryV2::CommonContextV3 { record, .. } =
            &archive.approvals()[0]
        else {
            panic!("exact V3 approval");
        };
        let plan = &record.approval.plan;
        let attempt = &plan.retained.selection.scope.selection.inventory.attempt;
        let original = history
            .manual_roster_session_continuation_v2(&attempt.continuation_digest)
            .unwrap()
            .unwrap();
        require_original_attempt(plan, &extension, Some(original)).unwrap();
        assert!(require_original_attempt(plan, &extension, None).is_err());
        let later = history
            .latest_manual_roster_attempt_v2(&extension.account_extension.enrollment_ref)
            .unwrap()
            .continuation
            .unwrap();
        assert!(require_original_attempt(plan, &extension, Some(&later)).is_err());
        let mut changed_plan = plan.clone();
        changed_plan
            .retained
            .selection
            .scope
            .selection
            .inventory
            .attempt
            .attempt_sequence += 1;
        assert!(require_original_attempt(&changed_plan, &extension, Some(original)).is_err());
        changed_plan = plan.clone();
        changed_plan
            .retained
            .selection
            .scope
            .selection
            .inventory
            .attempt
            .continuation_digest = "cd".repeat(32);
        assert!(require_original_attempt(&changed_plan, &extension, Some(original)).is_err());
    }
}
