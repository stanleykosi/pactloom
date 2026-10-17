//! Shared inert V3 request-field checks, mechanically extracted from the five
//! existing outer-fenced AppRequest arms. This validates data only: it does not
//! admit a peer, mint native consent, create an owner or enable production V3.
use super::{AppRequest, Error, PairScope, Result};

pub(super) fn validate_fields(request: &AppRequest, scope: &PairScope) -> Result<()> {
    match request {
        AppRequest::RequestBornRosterCommonContextReadV1 { request } => {
            request.validate().map_err(|_| Error::InvalidData)?;
            let t = request.plan.enrollment();
            if request.plan.digest().map_err(|_| Error::InvalidData)? != scope.manifest_digest
                || t.identity.account_id != scope.account_id
                || t.scope.agreement_id != scope.agreement_id
                || t.scope.participant_id != scope.participant_id
                || scope.history_read
                || scope.authorization_export
                || scope.preconstruction_export
            {
                return Err(Error::Authentication);
            }
        }
        AppRequest::RequestBornRosterCommonContextReentryV1 {
            request,
            pending_grant_json,
        } => {
            request.validate().map_err(|_| Error::InvalidData)?;
            if pending_grant_json.len() > 16 * 1024
                || request
                    .original_read
                    .plan
                    .digest()
                    .map_err(|_| Error::InvalidData)?
                    != scope.manifest_digest
                || request.original_read.plan.enrollment().identity.account_id != scope.account_id
                || request.original_read.plan.enrollment().scope.agreement_id != scope.agreement_id
                || request.original_read.plan.enrollment().scope.participant_id
                    != scope.participant_id
                || scope.history_read
                || scope.authorization_export
                || scope.preconstruction_export
            {
                return Err(Error::Authentication);
            }
        }
        AppRequest::RequestBornRosterReenteredConstructionV1 {
            request,
            reentry_lineage_digest,
        } => {
            request.validate().map_err(|_| Error::InvalidData)?;
            wholepact_core::proposal::validate_sha256(reentry_lineage_digest)
                .map_err(|_| Error::InvalidData)?;
            if request.plan.digest().map_err(|_| Error::InvalidData)? != scope.manifest_digest
                || request.plan.enrollment().identity.account_id != scope.account_id
                || request.plan.enrollment().scope.agreement_id != scope.agreement_id
                || request.plan.enrollment().scope.participant_id != scope.participant_id
                || scope.history_read
                || scope.authorization_export
                || scope.preconstruction_export
            {
                return Err(Error::Authentication);
            }
        }
        AppRequest::RequestBornRosterCommonContextHandoffAuthorizationV1 { request } => {
            request.validate().map_err(|_| Error::InvalidData)?;
            if scope.history_read || scope.authorization_export || scope.preconstruction_export {
                return Err(Error::Authentication);
            }
        }
        AppRequest::RequestBornRosterConstructionV3 { request } => {
            request.validate().map_err(|_| Error::InvalidData)?;
            let t = request.plan.enrollment();
            if request.plan.digest().map_err(|_| Error::InvalidData)? != scope.manifest_digest
                || t.identity.account_id != scope.account_id
                || t.scope.agreement_id != scope.agreement_id
                || t.scope.participant_id != scope.participant_id
                || scope.history_read
                || scope.authorization_export
                || scope.preconstruction_export
            {
                return Err(Error::Authentication);
            }
        }
        _ => return Err(Error::Authentication),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_core::common_context_reentry_v1::{
        CommonContextReentryPurposeV1, RosterCommonContextReentryRequestV1,
    };
    use wholepact_core::manual_roster_construction_v3::{
        CommonContextReadProfileV1, CommonContextReadPurposeV1, ManualRosterConstructionPlanV3,
        ManualRosterConstructionRequestV3, RosterCommonContextReadRequestV1,
    };
    use wholepact_signer_origin::common_context_handoff_v1::RosterCommonContextHandoffAuthorizationRequestV1;

    // Existing never-funded inert JSON only. No peer, native authority, retained
    // owner, receipt, socket, wallet or transport credential is fabricated.
    fn requests() -> (PairScope, Vec<AppRequest>) {
        let plan: ManualRosterConstructionPlanV3 = serde_json::from_str(include_str!(
            "../account/birth/enrollment/roster_v2/inventory/fixtures/common-context-plan-v3.synthetic.json"
        )).unwrap();
        plan.validate().unwrap();
        let terms = plan.enrollment();
        let scope = PairScope {
            account_id: terms.identity.account_id.clone(),
            agreement_id: terms.scope.agreement_id.clone(),
            participant_id: terms.scope.participant_id.clone(),
            manifest_digest: plan.digest().unwrap(),
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        scope.validate().unwrap();
        let requested = plan.completion_expires_at_ms() - 60_000;
        let read = RosterCommonContextReadRequestV1 {
            version: 1,
            operation_id: "synthetic-v3-scope-common-read".into(),
            profile: CommonContextReadProfileV1::for_plan(&plan).unwrap(),
            plan: plan.clone(),
            original_durable_receipt_digest: "ab".repeat(32),
            witness_plan_approval_digest: "cd".repeat(32),
            purpose: CommonContextReadPurposeV1::RevalidateExactRetainedNotesAndCommonContext,
            current_caller_binding_digest: "bc".repeat(32),
            requested_at_ms: requested,
            admission_expires_at_ms: requested + 30_000,
            completion_expires_at_ms: plan.completion_expires_at_ms(),
        };
        let construction = ManualRosterConstructionRequestV3 {
            version: 3,
            operation_id: "synthetic-v3-scope-construction".into(),
            plan,
            current_caller_binding_digest: "ef".repeat(32),
            requested_at_ms: requested + 1,
            admission_expires_at_ms: requested + 30_000,
        };
        let original_sequence = read
            .plan
            .retained
            .selection
            .scope
            .selection
            .inventory
            .attempt
            .attempt_sequence
            + 1;
        let reentry = RosterCommonContextReentryRequestV1 {
            version: 1,
            operation_id: "synthetic-v3-scope-reentry".into(),
            original_read: read.clone(),
            original_read_admission_digest: "ce".repeat(32),
            pending_grant_digest: "cf".repeat(32),
            original_attempt_digest: "de".repeat(32),
            original_attempt_sequence: original_sequence,
            current_caller_binding_digest: "ef".repeat(32),
            current_attempt_digest: "de".repeat(32),
            current_attempt_sequence: original_sequence,
            purpose: CommonContextReentryPurposeV1::ResumeAlreadyAdmittedConstructionOnly,
            requested_at_ms: requested + 35_000,
            admission_expires_at_ms: requested + 50_000,
        };
        let handoff = RosterCommonContextHandoffAuthorizationRequestV1 {
            version: 1,
            operation_id: "synthetic-v3-scope-handoff".into(),
            original_read_admission_digest: "ce".repeat(32),
            current_caller_binding_digest: "bc".repeat(32),
        };
        read.validate().unwrap();
        construction.validate().unwrap();
        reentry.validate().unwrap();
        handoff.validate().unwrap();
        (
            scope,
            vec![
                AppRequest::RequestBornRosterCommonContextReadV1 {
                    request: Box::new(read),
                },
                AppRequest::RequestBornRosterCommonContextHandoffAuthorizationV1 {
                    request: Box::new(handoff),
                },
                AppRequest::RequestBornRosterCommonContextReentryV1 {
                    request: Box::new(reentry),
                    pending_grant_json: "{}".into(),
                },
                AppRequest::RequestBornRosterReenteredConstructionV1 {
                    request: Box::new(construction.clone()),
                    reentry_lineage_digest: "df".repeat(32),
                },
                AppRequest::RequestBornRosterConstructionV3 {
                    request: Box::new(construction),
                },
            ],
        )
    }

    #[test]
    fn every_valid_v3_dto_remains_unconditionally_denied_by_generic_dispatch() {
        let (scope, requests) = requests();
        assert!(!crate::ipc::COMMON_CONTEXT_V3_COMPOSITION_QUALIFIED);
        for request in requests {
            validate_fields(&request, &scope).unwrap();
            assert!(matches!(request.validate(&scope), Err(Error::Unavailable)));
            assert!(matches!(
                crate::ipc::IpcMode::Ordinary.validate_authenticated_request(&request, &scope),
                Err(Error::Unavailable)
            ));
            let mut wrong = scope.clone();
            wrong.account_id = "other-account".into();
            assert!(matches!(request.validate(&wrong), Err(Error::Unavailable)));
        }
    }

    #[test]
    fn shared_field_checks_reject_export_flags_without_admitting_other_operations() {
        let (scope, requests) = requests();
        for request in &requests {
            for flag in 0..3 {
                let mut wrong = scope.clone();
                match flag {
                    0 => wrong.history_read = true,
                    1 => wrong.authorization_export = true,
                    _ => wrong.preconstruction_export = true,
                }
                assert!(matches!(
                    validate_fields(request, &wrong),
                    Err(Error::Authentication)
                ));
            }
        }
        // Status is allowed only by the holder's separate exact-owner check.
        assert!(matches!(
            validate_fields(&AppRequest::Status {}, &scope),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn shared_fields_keep_reentry_size_and_lineage_checks_beneath_closed_gate() {
        let (scope, mut requests) = requests();
        if let AppRequest::RequestBornRosterCommonContextReentryV1 {
            pending_grant_json, ..
        } = &mut requests[2]
        {
            *pending_grant_json = "x".repeat(16 * 1024 + 1);
        } else {
            panic!("reentry DTO");
        }
        assert!(matches!(
            validate_fields(&requests[2], &scope),
            Err(Error::Authentication)
        ));
        if let AppRequest::RequestBornRosterReenteredConstructionV1 {
            reentry_lineage_digest,
            ..
        } = &mut requests[3]
        {
            *reentry_lineage_digest = "invalid".into();
        } else {
            panic!("reentered construction DTO");
        }
        assert!(matches!(
            validate_fields(&requests[3], &scope),
            Err(Error::InvalidData)
        ));
        for index in [2, 3] {
            assert!(matches!(
                requests[index].validate(&scope),
                Err(Error::Unavailable)
            ));
        }
    }
}
