//! Prospective delivery admission data, not a financial capability. The entire
//! reviewed scope is immutable. No v2 session, permit or execution adapter exists.
use crate::{durable_delivery_scope_v2::DurableDeliveryScopeV2, *};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryAdmissionRecordV2 {
    pub scope: DurableDeliveryScopeV2,
    pub witness_native_review_digest: String,
}
fn request_scope(r: &OwnerControlRequest) -> Result<&DurableDeliveryScopeV2> {
    match &r.control {
        OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } => Ok(&record.scope),
        _ => Err(AuthorityError::Permission),
    }
}
fn owner_operation_id(r: &OwnerControlRequest) -> Result<String> {
    Ok(format!(
        "durable-delivery-admit-v2-{}",
        digest(
            "wholepact:durable-delivery-owner-operation:v2",
            &(
                request_scope(r)?,
                &r.account_id,
                &r.network_profile_id,
                r.writer_epoch,
                &r.expected_head
            ),
        )?
    ))
}
pub(crate) fn request_native_review_digest_v2(
    r: &OwnerControlRequest,
    disclosure: &WitnessDisclosureDescriptor,
) -> Result<String> {
    disclosure.validate()?;
    digest(
        "wholepact:durable-delivery-witness-native-review:v2",
        &(
            request_scope(r)?,
            &r.account_id,
            &r.network_profile_id,
            r.writer_epoch,
            &r.expected_head,
            disclosure,
        ),
    )
}
impl DurableDeliveryAdmissionRecordV2 {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        hash(&self.witness_native_review_digest)
    }
    pub(crate) fn validate_request_shape(&self, r: &OwnerControlRequest) -> Result<()> {
        self.validate()?;
        hash(&r.expected_head.digest)?;
        if !matches!(&r.control, OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } if record.as_ref() == self)
            || r.operation_id != owner_operation_id(r)?
            || r.account_id != self.scope.authorization.identity.account_id
            || r.network_profile_id != self.scope.authorization.identity.network_profile_id
            || r.writer_epoch != self.scope.original_writer_epoch
            || r.expected_head.sequence != 4
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    /// Inert correlation only, never native approval or an original source.
    pub fn validate_request(
        &self,
        r: &OwnerControlRequest,
        disclosure: &WitnessDisclosureDescriptor,
    ) -> Result<()> {
        self.validate_request_shape(r)?;
        if self.scope.witness != *disclosure
            || self.witness_native_review_digest != request_native_review_digest_v2(r, disclosure)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn validate_original(
        &self,
        policy: &AccountPolicy,
        extension: &crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    ) -> Result<()> {
        self.validate()?;
        self.scope
            .authorization
            .validate_original(policy, extension)?;
        let original = &extension.account_extension.terms;
        let scope = &self.scope;
        let own = scope
            .delivery
            .owners
            .iter()
            .find(|owner| owner.account_id == policy.account_id)
            .ok_or(AuthorityError::InvalidBinding)?;
        if scope.original_writer_epoch != policy.initial_writer_epoch
            || scope.original_writer_epoch != original.signer.writer_epoch
            || scope.witness.witness_id != policy.witness_id
            || crate::account_use_link::account_use_witness_origin_digest(&scope.witness)?
                != original.original_witness_origin_digest
            || own.participant_id != original.scope.participant_id
            || scope.delivery.original_host_generation_binding_digest
                != digest(
                    "wholepact:durable-delivery-original-host:v2",
                    &original.host,
                )?
            || scope.delivery.original_host_profile_id != original.host.profile_id
            || scope.original_ceilings.enrollment_expires_at_ms != original.scope.expires_at_ms
            || scope.original_ceilings.policy_expires_at_ms != policy.policy_expires_at_ms
            || scope.delivery.valid_from_ms < original.issued_at_ms
            || scope.delivery.dispatcher.public_identity_commitment
                == policy.owner_certificate_digest
            || scope.delivery.dispatcher.public_identity_commitment
                == policy.initial_writer_certificate_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        // The witness authenticates only its own original namespace. The remote
        // PCZT/material, accepted manifest and Host file lineage require the
        // genuine independent Signer and Host issuers, not a witness claim.
        Ok(())
    }
    pub(crate) fn require_live(&self, now: u64) -> Result<()> {
        self.scope.authorization.require_live(now)?;
        if now < self.scope.delivery.valid_from_ms || now >= self.scope.delivery.valid_until_ms {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
}
/// Build inert exact request data from authenticated complete pristine history.
/// The original owner mTLS AND a separate genuine witness-native decision remain
/// mandatory. A v1 admission can never be upgraded through this builder.
pub fn prepare_durable_delivery_admission_request_v2(
    scope: DurableDeliveryScopeV2,
    history: &ReconciledAuthorityHistory,
) -> Result<OwnerControlRequest> {
    history.require_original_roster_preconstruction_history()?;
    if !history.durable_payment_history_supported_v1
        || history.snapshot.head.sequence != 4
        || history.committed_operation_ids.len() != 4
        || history.snapshot.writer_status != WriterStatus::Active
    {
        return Err(AuthorityError::PolicyDenied);
    }
    let extension = history
        .manual_roster_enrollment_extension(&scope.authorization.original_enrollment_ref)?
        .ok_or(AuthorityError::Permission)?;
    let birth = history
        .pending_birth_commit
        .as_ref()
        .ok_or(AuthorityError::CorruptHistory)?;
    extension.validate_original_birth(birth)?;
    let mut request = OwnerControlRequest {
        operation_id: String::new(),
        account_id: history.snapshot.account_id.clone(),
        network_profile_id: history.snapshot.network_profile_id.clone(),
        writer_epoch: history.snapshot.writer_epoch,
        expected_head: history.snapshot.head.clone(),
        control: OwnerControl::AdmitDurablePaymentWithDeliveryV2 {
            record: Box::new(DurableDeliveryAdmissionRecordV2 {
                scope,
                witness_native_review_digest: "0".repeat(64),
            }),
        },
    };
    request.operation_id = owner_operation_id(&request)?;
    let review = request_native_review_digest_v2(&request, &birth.request.disclosure)?;
    if let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &mut request.control {
        record.witness_native_review_digest = review;
        record.validate_original(&history.account_policy, extension)?;
        if history.snapshot.writer_epoch != record.scope.original_writer_epoch
            || history.snapshot.writer_certificate_digest
                != record.scope.authorization.writer_certificate_digest
        {
            return Err(AuthorityError::RecoveryRequired);
        }
    }
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
        unreachable!()
    };
    record.validate_request(&request, &birth.request.disclosure)?;
    Ok(request)
}
impl ReconciledAuthorityHistory {
    /// Exact immutable historical evidence, including after original expiry.
    /// This does not verify present Host material availability or issue permission.
    pub fn durable_delivery_admission_v2(
        &self,
        operation_id: &str,
    ) -> Result<Option<&OwnerControlRequest>> {
        id(operation_id)?;
        let Some(request) = self.owner_controls.get(operation_id) else {
            return Ok(None);
        };
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
            return Err(AuthorityError::InvalidBinding);
        };
        let birth = self
            .pending_birth_commit
            .as_ref()
            .ok_or(AuthorityError::CorruptHistory)?;
        let extension = self
            .manual_roster_enrollment_extension(
                &record.scope.authorization.original_enrollment_ref,
            )?
            .ok_or(AuthorityError::CorruptHistory)?;
        extension.validate_original_birth(birth)?;
        record.validate_original(&self.account_policy, extension)?;
        record.validate_request(request, &birth.request.disclosure)?;
        if !self.contains_operation(operation_id) || !self.contains_head(&request.expected_head) {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(Some(request))
    }
}

/// Data-only canonical commitment, not authenticated Host-source evidence.
pub fn original_host_generation_binding_digest_v2(
    binding: &wholepact_core::manual_enrollment::ManualHostGenerationBinding,
) -> Result<String> {
    digest("wholepact:durable-delivery-original-host:v2", binding)
}
/// Reuse the maintained authorization namespace for a fixed identity and an
/// independently sourced original account. This private, deliberately invalid
/// terms projection is used ONLY by the pure canonical-ID method. It is never
/// validated, serialized, returned, admitted or presented as original evidence.
/// The genuine Signer must derive and verify its complete authorization again.
pub fn canonical_durable_authorization_id_v2(
    fixed: &crate::durable_payment_v1::DurableFixedCandidateBindingV1,
    identity: &wholepact_core::manual_enrollment::ManualAccountIdentity,
) -> Result<String> {
    fixed.validate()?;
    hash(&identity.account_id)?;
    if fixed.network_profile_id != identity.network_profile_id {
        return Err(AuthorityError::InvalidBinding);
    }
    let projection = crate::durable_payment_v1::DurablePaymentAdmissionTermsV1 {
        version: 1,
        identity: identity.clone(),
        fixed: fixed.clone(),
        original_policy_digest: String::new(),
        original_genesis_digest: String::new(),
        original_birth_commit_digest: String::new(),
        original_roster_extension_digest: String::new(),
        original_enrollment_ref: String::new(),
        writer_certificate_digest: String::new(),
        authorization_id: String::new(),
        recipient_policy_scope_digest: String::new(),
        concrete_recipient_scope_digest: String::new(),
        inputs: Vec::new(),
        maximum_debit_zatoshis: 0,
        fee_share_zatoshis: 0,
        transaction_fee_zatoshis: 0,
        valid_from_ms: 0,
        valid_until_ms: 0,
    };
    Ok(projection.canonical_authorization_id())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::durable_delivery_scope_v2::*;
    use crate::durable_payment_v1::tests::{fixture, h, history, owner_event};
    use crate::policy::{Event, Ledger};

    /// Never-funded inert replay data. No native authority, live source or socket.
    pub(crate) fn request_fixture() -> (
        crate::pending_birth::PendingBirthCommitRecord,
        Ledger,
        Vec<Event>,
        OwnerControlRequest,
    ) {
        let (birth, ledger, events, authorization) = fixture();
        let extension = &ledger.manual_roster_extension().unwrap().unwrap().extension;
        let original = &extension.account_extension.terms;
        let other_account = if authorization.identity.account_id != h('a') {
            h('a')
        } else {
            h('b')
        };
        let mut other_identity = authorization.identity.clone();
        other_identity.account_id = other_account.clone();
        let mut owners = vec![
            DurableDeliveryOwnerLineageV2 {
                account_id: authorization.identity.account_id.clone(),
                participant_id: original.scope.participant_id.clone(),
                original_authorization_id: authorization.authorization_id.clone(),
            },
            DurableDeliveryOwnerLineageV2 {
                account_id: other_account,
                participant_id: "other-fixture-owner".into(),
                original_authorization_id: canonical_durable_authorization_id_v2(
                    &authorization.fixed,
                    &other_identity,
                )
                .unwrap(),
            },
        ];
        owners.sort_by(|a, b| a.account_id.cmp(&b.account_id));
        let material_scopes = owners
            .iter()
            .map(|owner| DurableDeliveryMaterialScopeRefV2 {
                account_id: owner.account_id.clone(),
                original_scope_digest: h('d'),
                valid_from_unix_seconds: 128,
                valid_until_unix_seconds: 800,
            })
            .collect();
        let scope = DurableDeliveryScopeV2 {
            version: 2, accepted_manifest_ref: h('9'), original_writer_epoch: ledger.policy.initial_writer_epoch,
            delivery: DurableDeliveryPlanV2 {
                dispatcher: DurableDeliveryDispatcherV2 {
                    principal_id: "isolated-prospective-fixture".into(),
                    public_identity_commitment: "0123456789abcdef".repeat(4),
                    authentication_profile: DurableDeliveryAuthenticationProfileV2::OriginalProtectedHostDispatcherV2,
                    custody_policy_commitment: h('e'),
                },
                original_host_generation_binding_digest: original_host_generation_binding_digest_v2(&original.host).unwrap(),
                original_host_profile_id: original.host.profile_id.clone(), submission_journal_identity: h('f'),
                submission_operation_id: "synthetic-submission-original-v2".into(),
                provider: wholepact_core::manual_construction::PreconstructionProvider {
                    source_id: "never-funded-provider".into(), endpoint: "https://provider.invalid".into(),
                    trust_profile: "single_tls_provider_report_not_consensus".into(),
                },
                route: DurableDeliveryRouteV2::Direct {}, owners, valid_from_ms: 128_000, valid_until_ms: 800_000,
                minimum_expiry_margin_blocks: 10, maximum_fresh_admission_lifetime_ms: 30_000,
                maximum_explicitly_approved_attempts: 1,
                extraction_rule: DurableDeliveryExtractionRuleV2::FirstDurablyRetainedVerifiedExtraction,
                retry_rule: DurableDeliveryRetryRuleV2::SameRetainedBytesWithFreshAdmission,
                attempt_rule: DurableDeliveryAttemptRuleV2::ExplicitImmediateHostDecision,
            },
            witness: birth.request.disclosure.clone(),
            original_ceilings: DurableDeliveryOriginalCeilingsV2 {
                payment_valid_from_ms: authorization.valid_from_ms, payment_valid_until_ms: authorization.valid_until_ms,
                enrollment_expires_at_ms: original.scope.expires_at_ms, policy_expires_at_ms: ledger.policy.policy_expires_at_ms,
                material_scopes,
            },
            authorization,
            disclosure_rule: DurableDeliveryDisclosureRuleV2::WholeTransactionAndConnectionMetadataToProviderCommitmentsAndLinkageToWitness,
        };
        let request =
            prepare_durable_delivery_admission_request_v2(scope, &history(&birth, &events))
                .unwrap();
        (birth, ledger, events, request)
    }
    pub(crate) fn recorded_fixture() -> (
        crate::pending_birth::PendingBirthCommitRecord,
        Ledger,
        Vec<Event>,
        OwnerControlRequest,
    ) {
        let (birth, mut ledger, mut events, request) = request_fixture();
        let event = owner_event(&ledger, request.clone(), 128_000);
        ledger.apply(&event).unwrap();
        events.push(event);
        (birth, ledger, events, request)
    }
    #[test]
    fn v2_full_scope_request_is_strict_and_every_original_context_is_bound() {
        let (birth, ledger, _, request) = request_fixture();
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: OwnerControlRequest = crate::decode(&bytes).unwrap();
        assert!(decoded == request);
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
            panic!()
        };
        record.validate_request(&request, &birth.request.disclosure).unwrap();
        ledger.validate_new_durable_delivery_admission_v2(&request, 128_000).unwrap();
        for change in 0..10 {
            let mut changed = request.clone();
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &mut changed.control
            else {
                panic!()
            };
            match change {
                0 => record.scope.accepted_manifest_ref = h('8'),
                1 => record.scope.delivery.submission_journal_identity = h('8'),
                2 => record.scope.delivery.dispatcher.custody_policy_commitment = h('8'),
                3 => record.scope.delivery.maximum_explicitly_approved_attempts += 1,
                4 => record.scope.delivery.provider.endpoint = "https://changed.invalid".into(),
                5 => record.scope.original_writer_epoch += 1,
                6 => record.scope.authorization.original_birth_commit_digest = h('8'),
                7 => record.scope.delivery.original_host_profile_id = "changed-host".into(),
                8 => {
                    record.scope.original_ceilings.material_scopes[0].original_scope_digest = h('8')
                }
                _ => record.witness_native_review_digest = h('8'),
            }
            if change < 9 {
                assert!(
                    ledger
                        .validate_new_durable_delivery_admission_v2(&changed, 128_000)
                        .is_err()
                );
            }
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &changed.control else {
                panic!()
            };
            // Same original-disclosure join used by the native locked source,
            // followed by the unchanged ledger validator. This is inert data,
            // not a native approval fixture.
            assert!(record
                .validate_request(&changed, &birth.request.disclosure)
                .and_then(|()| ledger.validate_new_durable_delivery_admission_v2(&changed, 128_000))
                .is_err());
        }
        // A syntactically valid but altered native review digest can be replayed
        // as inert ledger data, but must fail the COMPLETE original birth join.
        let (tampered_birth, mut tampered_ledger, mut tampered_events, mut tampered_request) =
            request_fixture();
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &mut tampered_request.control else {
            panic!()
        };
        record.witness_native_review_digest = h('8');
        let event = owner_event(&tampered_ledger, tampered_request, 128_000);
        tampered_ledger.apply(&event).unwrap();
        tampered_events.push(event);
        assert!(tampered_ledger
            .validate_durable_delivery_birth_v2(Some(&tampered_birth))
            .is_err());
        assert!(crate::transport::synthetic::recorded_fixture_history(
            &tampered_birth,
            &serde_json::to_vec(&tampered_events).unwrap(),
        ).is_err());
        let duplicate = String::from_utf8(bytes).unwrap().replacen(
            "\"operation_id\":",
            "\"operation_id\":\"duplicate\",\"operation_id\":",
            1,
        );
        assert!(crate::decode::<OwnerControlRequest>(duplicate.as_bytes()).is_err());
        let mut wrong_birth = birth.clone();
        wrong_birth.request.disclosure.endpoint = "127.0.0.1:9".into();
        let (_, recorded, _, _) = recorded_fixture();
        recorded.validate_durable_delivery_birth_v2(Some(&birth)).unwrap();
        assert!(
            recorded
                .validate_durable_delivery_birth_v2(Some(&wrong_birth))
                .is_err()
        );
        assert!(recorded.validate_durable_delivery_birth_v2(None).is_err());
    }
    #[test]
    fn v2_history_preserves_bootstrap_and_original_scope_after_expiry() {
        let (birth, ledger, events, request) = recorded_fixture();
        let original = history(&birth, &events[..4]);
        assert_eq!(ledger.sessions.len(), 1);
        assert_eq!(ledger.activated_sessions.len(), 1);
        assert!(ledger.snapshot.active_writer_session.is_none());
        assert!(ledger.policy == *original.account_policy());
        let history = history(&birth, &events);
        assert!(
            history
                .durable_delivery_admission_v2(&request.operation_id)
                .unwrap()
                == Some(&request)
        );
        assert!(history.permits().is_err());
        assert!(
            history
                .require_original_roster_preconstruction_history()
                .is_err()
        );
        assert!(history.construction_history_v1().is_err());
        assert!(history.construction_history_v2().is_err());
        assert!(history.construction_history_with_transport_v1().is_err());
        assert!(
            history
                .durable_payment_online_permits_v1(&request.operation_id)
                .is_err()
        );
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
            panic!()
        };
        assert!(matches!(
            record.require_live(800_000),
            Err(AuthorityError::Expired)
        ));
        assert_eq!(record.scope.accepted_manifest_ref, h('9'));
        ledger
            .validate_durable_delivery_birth_v2(Some(&birth))
            .unwrap();
    }
    #[test]
    fn v2_live_gate_denies_exact_bootstrap_replay_and_all_nonrestriction_controls() {
        let (_, mut ledger, events, request) = recorded_fixture();
        let before = ledger.snapshot.clone();
        for event in &events[..4] {
            // Historical replay remains valid in a fresh chronological ledger,
            // but never remints bootstrap permission on the completed v2 ledger.
            assert!(ledger.replay(event).unwrap().is_some());
            assert!(matches!(
                ledger.require_delivery_admission_only_v2(&event.mutation),
                Err(AuthorityError::PolicyDenied)
            ));
            assert!(ledger.apply(event).is_err());
        }
        for control in [
            OwnerControl::RequireRecovery,
            OwnerControl::ReplaceWriter {
                writer_certificate_digest: h('f'),
            },
            OwnerControl::RecoverWriter {
                writer_certificate_digest: h('f'),
                inventory_digest: h('e'),
            },
        ] {
            let mut r = request.clone();
            r.control = control;
            assert!(
                ledger
                    .require_delivery_admission_only_v2(&AuthorityMutation::OwnerControl(r))
                    .is_err()
            );
        }
        let (old_birth, mut old_ledger, mut old_events, old_admission) =
            crate::durable_payment_v1::tests::admitted_fixture();
        crate::durable_payment_v1::tests::activate(
            &old_birth,
            &mut old_ledger,
            &mut old_events,
            &old_admission,
        );
        let reserve = crate::durable_payment_v1::tests::reservation(&old_ledger, &old_admission);
        assert!(
            ledger
                .require_delivery_admission_only_v2(&AuthorityMutation::ReserveAuthorization(
                    Box::new(reserve)
                ))
                .is_err()
        );
        assert!(
            ledger
                .require_delivery_admission_only_v2(&AuthorityMutation::OwnerControl(old_admission))
                .is_err()
        );
        assert!(ledger.snapshot == before);
    }
    #[test]
    fn v2_original_witness_joins_reject_self_consistent_foreign_claims() {
        let (birth, _, events, request) = request_fixture();
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = request.control else {
            panic!()
        };
        for change in 0..7 {
            let mut scope = record.scope.clone();
            match change {
                0 => scope.delivery.original_host_generation_binding_digest = h('8'),
                1 => scope.delivery.original_host_profile_id = "foreign-original-host".into(),
                2 => scope.original_ceilings.enrollment_expires_at_ms -= 1,
                3 => scope.original_ceilings.policy_expires_at_ms += 1,
                4 => {
                    scope
                        .delivery
                        .owners
                        .iter_mut()
                        .find(|owner| owner.account_id == scope.authorization.identity.account_id)
                        .unwrap()
                        .participant_id = "foreign-participant".into()
                }
                5 => scope.witness.endpoint = "127.0.0.1:9".into(),
                _ => scope.original_writer_epoch += 1,
            }
            assert!(
                prepare_durable_delivery_admission_request_v2(scope, &history(&birth, &events))
                    .is_err()
            );
        }
    }
    #[test]
    fn v2_restrictions_keep_original_admission_and_bootstrap_immutable() {
        let (birth, mut ledger, mut events, request) = recorded_fixture();
        let sessions = ledger.sessions.clone();
        for (index, control) in [OwnerControl::Pause, OwnerControl::Revoke]
            .into_iter()
            .enumerate()
        {
            let restriction = OwnerControlRequest {
                operation_id: format!("v2-restriction-{index}"),
                account_id: request.account_id.clone(),
                network_profile_id: request.network_profile_id.clone(),
                writer_epoch: request.writer_epoch,
                expected_head: ledger.snapshot.head.clone(),
                control,
            };
            let event = owner_event(&ledger, restriction, 128_001 + index as u64);
            ledger.apply(&event).unwrap();
            events.push(event);
        }
        assert!(ledger.snapshot.writer_status == WriterStatus::Revoked);
        assert!(ledger.sessions == sessions);
        ledger
            .validate_durable_delivery_birth_v2(Some(&birth))
            .unwrap();
        let history = history(&birth, &events);
        assert!(
            history
                .durable_delivery_admission_v2(&request.operation_id)
                .unwrap()
                == Some(&request)
        );
        assert!(history.permits().is_err());
    }
    #[test]
    fn v2_does_not_upgrade_v1_or_renew_original_deadlines() {
        let (birth, mut ledger, mut events, request) = request_fixture();
        assert!(
            ledger
                .validate_new_durable_delivery_admission_v2(&request, 127_999)
                .is_err()
        );
        assert!(
            ledger
                .validate_new_durable_delivery_admission_v2(&request, 800_000)
                .is_err()
        );
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
            panic!()
        };
        let v1 = crate::durable_payment_v1::prepare_durable_payment_request_v1(
            record.scope.authorization.clone(),
            &history(&birth, &events),
        )
        .unwrap();
        let e = owner_event(&ledger, v1, 128_000);
        ledger.apply(&e).unwrap();
        events.push(e);
        assert!(
            prepare_durable_delivery_admission_request_v2(
                record.scope.clone(),
                &history(&birth, &events)
            )
            .is_err()
        );
        assert!(
            ledger
                .validate_new_durable_delivery_admission_v2(&request, 128_000)
                .is_err()
        );
    }
}
