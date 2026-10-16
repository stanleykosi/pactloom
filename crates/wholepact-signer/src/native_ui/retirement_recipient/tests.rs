//! In-memory lifecycle fixtures only. No AuthenticatedPeer is fabricated and no
//! socket, provider, proof, real key, runtime UI or network operation is invoked.
use super::*;
use crate::{
    account::{AccountVault, PendingAccount},
    native_ui::{
        authority::{recovery_test_authority, recovery_test_decision},
        retirement_destination::{ApprovedRecoveryDestination, PreparedRecoveryDestination},
        retirement_source::{PreparedRetirementSource, RetirementSourceRead},
    },
};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

struct Fixture {
    _dir: tempfile::TempDir,
    source: AccountVault,
    destination: AccountVault,
    source_native: NativeAuthority,
    destination_native: NativeAuthority,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = |name, index| {
            let pending = PendingAccount::fixed_never_funded_qualification(index).unwrap();
            let words = pending.recovery_words().unwrap();
            AccountVault::create(
                &dir.path().join(name),
                pending.verify_backup(&words).unwrap(),
                b"public-synthetic-retirement-peer",
            )
            .unwrap()
        };
        Self {
            source: vault("source", 0),
            destination: vault("destination", 1),
            source_native: recovery_test_authority(),
            destination_native: recovery_test_authority(),
            _dir: dir,
        }
    }
    fn recipient(&self) -> RetirementEvidenceRecipient {
        let binding = RecipientBinding {
            grant_id: "12".repeat(32),
            channel_digest: "23".repeat(32),
            key_digest: "34".repeat(32),
            generation: 7,
            process_instance: "45".repeat(32),
            uid: 1000,
            pid: 1234,
            application_label: "synthetic-evidence-reader".into(),
            scope: PairScope {
                account_id: self.source.account_id().unwrap(),
                agreement_id: "synthetic-retirement".into(),
                participant_id: "synthetic-owner".into(),
                manifest_digest: "56".repeat(32),
                history_read: false,
                authorization_export: false,
                preconstruction_export: false,
            },
            native_entry: self.source_native.binding().entry_digest().into(),
        };
        RetirementEvidenceRecipient {
            digest: binding_digest(&binding).unwrap(),
            binding,
            owner: RecipientOwner::Synthetic {
                native: self.source_native.binding(),
                current: Arc::new(AtomicBool::new(true)),
                expires: Instant::now() + Duration::from_secs(900),
            },
        }
    }
    fn request(&self, recipient: &RetirementEvidenceRecipient) -> RecoveryDestinationRequest {
        RecoveryDestinationRequest {
            operation_id: "synthetic-peer-evidence".into(),
            destination_account_id: self.destination.account_id().unwrap(),
            address: wholepact_protocol::review::encode_testnet_receiver(
                &self
                    .destination
                    .account()
                    .fvk()
                    .unwrap()
                    .address_at(0u32, orchard::keys::Scope::External),
            ),
            network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
            source_account_id: self.source.account_id().unwrap(),
            source_fvk_digest: hex::encode(Sha256::digest(
                self.source.account().fvk().unwrap().to_bytes(),
            )),
            local_recipient: recipient.binding.grant_id.clone(),
        }
    }
    fn source(
        &self,
        recipient: &RetirementEvidenceRecipient,
        request: &RecoveryDestinationRequest,
    ) -> RetirementSourceRead {
        let p = PreparedRetirementSource::prepare_with_recipient(
            &self.source,
            &self.source_native,
            request,
            Some(recipient.clone()),
        )
        .unwrap();
        assert!(p.display().contains("synthetic-evidence-reader"));
        assert!(p.display().contains(recipient.digest()));
        let d = recovery_test_decision(&self.source_native, p.digest());
        p.approve(&self.source, &self.source_native, d).unwrap()
    }
    fn approved(
        &self,
        recipient: &RetirementEvidenceRecipient,
    ) -> (RetirementSourceRead, ApprovedRecoveryDestination<'_>) {
        let request = self.request(recipient);
        let source = self.source(recipient, &request);
        let p = PreparedRecoveryDestination::prepare_for_retirement_recipient(
            &self.destination,
            &self.destination_native,
            request,
            &source,
            &self.source,
        )
        .unwrap();
        assert!(p.display().contains(recipient.digest()));
        assert!(p.display().contains("cannot be recalled"));
        let d = recovery_test_decision(&self.destination_native, p.digest());
        (source, p.approve(d, &self.destination_native).unwrap())
    }
}
fn revoke(recipient: &RetirementEvidenceRecipient) {
    match &recipient.owner {
        RecipientOwner::Synthetic { current, .. } => current.store(false, Ordering::Release),
        _ => unreachable!("only in-memory lifecycle fixture"),
    }
}

#[test]
fn recipient_bound_two_native_decisions_release_only_informational_destination() {
    let f = Fixture::new();
    let recipient = f.recipient();
    let request = f.request(&recipient);
    let (source, destination) = f.approved(&recipient);
    // No peer-bound approval can escape via the pre-existing local adapter.
    assert!(
        destination
            .evidence_for_retirement_source(&source, &f.source)
            .is_err()
    );
    let result = destination
        .release_for_recipient(source, &f.source, &recipient)
        .unwrap();
    assert_eq!(result.address, request.address);
    assert_eq!(
        result.user_controlled_account_ref,
        request.destination_account_id
    );
    assert_eq!(result.ownership_source_ref, request.operation_id);
    assert_eq!(result.network_profile_id, request.network_profile_id);
    assert_eq!(
        result.pool,
        wholepact_core::retirement::ShieldedReceiverPool::Ironwood
    );
    assert!(!crate::automation_supported());
    assert!(crate::provision_live_account().is_err());
}

#[test]
fn recipient_binding_rejects_claims_wrong_source_and_native_origin() {
    let f = Fixture::new();
    let recipient = f.recipient();
    let request = f.request(&recipient);
    for field in 0..4 {
        let mut wrong = request.clone();
        match field {
            0 => wrong.local_recipient = "unverified-app-label".into(),
            1 => wrong.source_account_id = f.destination.account_id().unwrap(),
            2 => wrong.source_fvk_digest = "ab".repeat(32),
            _ => wrong.network_profile_id = "wrong-network".into(),
        }
        assert!(
            PreparedRetirementSource::prepare_with_recipient(
                &f.source,
                &f.source_native,
                &wrong,
                Some(recipient.clone())
            )
            .is_err()
        );
    }
    assert!(
        PreparedRetirementSource::prepare_with_recipient(
            &f.source,
            &f.destination_native,
            &request,
            Some(recipient.clone())
        )
        .is_err()
    );
    for field in [
        "verified",
        "ownership_evidence_digest",
        "authenticated_peer",
        "native_decision",
        "recipient_binding_digest",
    ] {
        let mut wire = serde_json::to_value(&request).unwrap();
        wire[field] = true.into();
        assert!(serde_json::from_value::<RecoveryDestinationRequest>(wire).is_err());
    }
}

#[test]
fn recipient_substitution_rejects_every_grant_channel_process_and_scope_binding() {
    let f = Fixture::new();
    let recipient = f.recipient();
    for field in 0..11 {
        let (source, destination) = f.approved(&recipient);
        let mut other = recipient.clone();
        match field {
            0 => other.binding.grant_id = "67".repeat(32),
            1 => other.binding.channel_digest = "78".repeat(32),
            2 => other.binding.key_digest = "89".repeat(32),
            3 => other.binding.generation += 1,
            4 => other.binding.process_instance = "9a".repeat(32),
            5 => other.binding.pid += 1,
            6 => other.binding.uid += 1,
            7 => other.binding.scope.account_id = "other-account".into(),
            8 => other.binding.scope.manifest_digest = "ab".repeat(32),
            9 => other.binding.scope.history_read = true,
            _ => other.binding.application_label = "other-app".into(),
        }
        other.digest = binding_digest(&other.binding).unwrap();
        assert!(
            destination
                .release_for_recipient(source, &f.source, &other)
                .is_err()
        );
    }
    // Identical serialized fields and same native instance cannot replace the
    // concrete grant lifetime. A newly minted lookalike has a different owner.
    let other = f.recipient();
    assert_eq!(recipient.digest(), other.digest());
    let (source, destination) = f.approved(&recipient);
    assert!(
        destination
            .release_for_recipient(source, &f.source, &other)
            .is_err()
    );
}

#[test]
fn recipient_renewal_changes_both_review_digests_and_rejects_old_decisions() {
    let f = Fixture::new();
    let a = f.recipient();
    let mut b = a.clone();
    b.binding.generation += 1;
    b.binding.channel_digest = "bc".repeat(32);
    b.digest = binding_digest(&b.binding).unwrap();
    let request = f.request(&a); // Same grant-ID string cannot hide channel renewal.
    let pa = PreparedRetirementSource::prepare_with_recipient(
        &f.source,
        &f.source_native,
        &request,
        Some(a.clone()),
    )
    .unwrap();
    let pb = PreparedRetirementSource::prepare_with_recipient(
        &f.source,
        &f.source_native,
        &request,
        Some(b.clone()),
    )
    .unwrap();
    assert_ne!(pa.digest(), pb.digest());
    let stale = recovery_test_decision(&f.source_native, pa.digest());
    assert!(pb.approve(&f.source, &f.source_native, stale).is_err());
    let sa = f.source(&a, &request);
    let sb = f.source(&b, &request);
    let pa = PreparedRecoveryDestination::prepare_for_retirement_recipient(
        &f.destination,
        &f.destination_native,
        request.clone(),
        &sa,
        &f.source,
    )
    .unwrap();
    let pb = PreparedRecoveryDestination::prepare_for_retirement_recipient(
        &f.destination,
        &f.destination_native,
        request,
        &sb,
        &f.source,
    )
    .unwrap();
    assert_ne!(pa.digest(), pb.digest());
    let stale = recovery_test_decision(&f.destination_native, pa.digest());
    assert!(pb.approve(stale, &f.destination_native).is_err());
}

#[test]
fn recipient_revocation_rejects_preparation_approval_and_release() {
    let f = Fixture::new();
    let recipient = f.recipient();
    let request = f.request(&recipient);
    let p = PreparedRetirementSource::prepare_with_recipient(
        &f.source,
        &f.source_native,
        &request,
        Some(recipient.clone()),
    )
    .unwrap();
    let decision = recovery_test_decision(&f.source_native, p.digest());
    revoke(&recipient);
    assert!(p.approve(&f.source, &f.source_native, decision).is_err());
    assert!(
        PreparedRetirementSource::prepare_with_recipient(
            &f.source,
            &f.source_native,
            &request,
            Some(recipient)
        )
        .is_err()
    );
    let recipient = f.recipient();
    let source = f.source(&recipient, &request);
    let p = PreparedRecoveryDestination::prepare_for_retirement_recipient(
        &f.destination,
        &f.destination_native,
        request,
        &source,
        &f.source,
    )
    .unwrap();
    let decision = recovery_test_decision(&f.destination_native, p.digest());
    revoke(&recipient);
    assert!(source.check_liveness().is_err());
    assert!(p.approve(decision, &f.destination_native).is_err());
    let recipient = f.recipient();
    let (source, destination) = f.approved(&recipient);
    revoke(&recipient);
    assert!(
        destination
            .release_for_recipient(source, &f.source, &recipient)
            .is_err()
    );
}

#[test]
fn recipient_expiry_and_native_cancellation_block_release() {
    let f = Fixture::new();
    let mut recipient = f.recipient();
    match &mut recipient.owner {
        RecipientOwner::Synthetic { expires, .. } => {
            *expires = Instant::now() + Duration::from_millis(200)
        }
        _ => unreachable!(),
    }
    let (source, destination) = f.approved(&recipient);
    std::thread::sleep(Duration::from_millis(210));
    assert!(source.check_liveness().is_err());
    assert!(
        destination
            .release_for_recipient(source, &f.source, &recipient)
            .is_err()
    );
    let recipient = f.recipient();
    let (source, destination) = f.approved(&recipient);
    f.source_native.invalidate();
    assert!(
        destination
            .release_for_recipient(source, &f.source, &recipient)
            .is_err()
    );
    let f = Fixture::new();
    let recipient = f.recipient();
    let (source, destination) = f.approved(&recipient);
    f.destination_native.invalidate();
    assert!(
        destination
            .release_for_recipient(source, &f.source, &recipient)
            .is_err()
    );
}

#[test]
fn recipient_owner_rejects_local_promotion_destination_substitution_and_wrong_vault() {
    let f = Fixture::new();
    let recipient = f.recipient();
    let request = f.request(&recipient);
    let local = PreparedRetirementSource::prepare(&f.source, &f.source_native, &request).unwrap();
    let decision = recovery_test_decision(&f.source_native, local.digest());
    let local = local
        .approve(&f.source, &f.source_native, decision)
        .unwrap();
    assert!(
        PreparedRecoveryDestination::prepare_for_retirement_recipient(
            &f.destination,
            &f.destination_native,
            request.clone(),
            &local,
            &f.source
        )
        .is_err()
    );
    let source = f.source(&recipient, &request);
    for field in 0..4 {
        let mut wrong = request.clone();
        match field {
            0 => wrong.destination_account_id = "other-destination".into(),
            1 => {
                wrong.address = wholepact_protocol::review::encode_testnet_receiver(
                    &f.source
                        .account()
                        .fvk()
                        .unwrap()
                        .address_at(0u32, orchard::keys::Scope::External),
                )
            }
            2 => wrong.operation_id.push('x'),
            _ => wrong.local_recipient = "cd".repeat(32),
        }
        assert!(
            PreparedRecoveryDestination::prepare_for_retirement_recipient(
                &f.destination,
                &f.destination_native,
                wrong,
                &source,
                &f.source
            )
            .is_err()
        );
    }
    assert!(
        PreparedRecoveryDestination::prepare_for_retirement_recipient(
            &f.source,
            &f.destination_native,
            request.clone(),
            &source,
            &f.source
        )
        .is_err()
    );
    let local_destination =
        PreparedRecoveryDestination::prepare(&f.destination, &f.destination_native, request)
            .unwrap();
    let decision = recovery_test_decision(&f.destination_native, local_destination.digest());
    let local_destination = local_destination
        .approve(decision, &f.destination_native)
        .unwrap();
    assert!(
        local_destination
            .release_for_recipient(source, &f.source, &recipient)
            .is_err()
    );
    let (source, destination) = f.approved(&recipient);
    assert!(
        destination
            .release_for_recipient(source, &f.destination, &recipient)
            .is_err()
    );
}

#[test]
fn retirement_peer_adapter_does_not_add_ipc_operations() {
    for operation in [
        "request_retirement_destination",
        "release_retirement_evidence",
        "request_retirement_source",
        "retirement_evidence",
    ] {
        assert!(
            serde_json::from_value::<crate::ipc::AppRequest>(
                serde_json::json!({"operation": operation})
            )
            .is_err()
        );
    }
}

#[test]
fn recipient_destination_rejects_replacement_source_owner_and_old_source_decision() {
    let f = Fixture::new();
    let recipient = f.recipient();
    let request = f.request(&recipient);
    let (original_source, destination) = f.approved(&recipient);
    let replacement_source = f.source(&recipient, &request);
    assert!(
        destination
            .release_for_recipient(replacement_source, &f.source, &recipient)
            .is_err()
    );
    // An equivalent new preparation cannot consume a decision held from the old
    // exact preparation. A replayed native event must not reset its 120 seconds.
    let a = PreparedRetirementSource::prepare_with_recipient(
        &f.source,
        &f.source_native,
        &request,
        Some(recipient.clone()),
    )
    .unwrap();
    let b = PreparedRetirementSource::prepare_with_recipient(
        &f.source,
        &f.source_native,
        &request,
        Some(recipient),
    )
    .unwrap();
    assert_ne!(a.digest(), b.digest());
    let old = recovery_test_decision(&f.source_native, a.digest());
    assert!(b.approve(&f.source, &f.source_native, old).is_err());
    assert!(original_source.check_liveness().is_ok());
    let a = PreparedRecoveryDestination::prepare_for_retirement_recipient(
        &f.destination,
        &f.destination_native,
        request.clone(),
        &original_source,
        &f.source,
    )
    .unwrap();
    let b = PreparedRecoveryDestination::prepare_for_retirement_recipient(
        &f.destination,
        &f.destination_native,
        request,
        &original_source,
        &f.source,
    )
    .unwrap();
    assert_ne!(a.digest(), b.digest());
    let old = recovery_test_decision(&f.destination_native, a.digest());
    assert!(b.approve(old, &f.destination_native).is_err());
}

fn transport_wire(
    f: &Fixture,
) -> wholepact_signer_origin::retirement_evidence::RetirementDestinationEvidenceRequestV1 {
    wholepact_signer_origin::retirement_evidence::RetirementDestinationEvidenceRequestV1 {
        schema_version: 1,
        purpose: "retirement_destination_observation".into(),
        operation_id: "synthetic-peer-evidence".into(),
        request_nonce: "ab".repeat(32),
        source_account_id: f.source.account_id().unwrap(),
        network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
        address: f.request(&f.recipient()).address,
    }
}
fn transport_recipient(
    f: &Fixture,
    wire: &wholepact_signer_origin::retirement_evidence::RetirementDestinationEvidenceRequestV1,
) -> RetirementEvidenceRecipient {
    let mut recipient = f.recipient();
    recipient.binding.scope = wire.pair_scope().unwrap();
    recipient.digest = binding_digest(&recipient.binding).unwrap();
    recipient
}

#[test]
fn retirement_delivery_retains_exact_source_destination_and_historical_response_only() {
    use wholepact_signer_origin::retirement_evidence::RetirementDestinationEvidenceResponseV1;
    let f = Fixture::new();
    let wire = transport_wire(&f);
    let recipient = transport_recipient(&f, &wire);
    let request = f.request(&recipient);
    let (source, destination) = f.approved(&recipient);
    let source_ref = source.review_digest().to_owned();
    let original_deadline = source.deadline().min(destination.deadline());
    let delivery = transport_delivery(
        source,
        &f.source,
        destination,
        request,
        &wire,
        Instant::now() + Duration::from_secs(900),
    )
    .unwrap();
    assert_eq!(delivery.deadline(), original_deadline);
    let response = delivery.response_for_recipient(&recipient, &wire).unwrap();
    response
        .require_request_binding(&wire, recipient.grant_id())
        .unwrap();
    match &response {
        RetirementDestinationEvidenceResponseV1::Observed {
            source_review_ref,
            destination_account_id,
            source_account_id,
            ..
        } => {
            assert_eq!(source_review_ref, &source_ref);
            assert_eq!(destination_account_id, &f.destination.account_id().unwrap());
            assert_eq!(source_account_id, &f.source.account_id().unwrap());
        }
        _ => panic!("expected historical observation only"),
    }
    let value = serde_json::to_value(response).unwrap();
    for forbidden in [
        "source_fvk_digest",
        "destination_fvk_digest",
        "local_recipient",
        "token_hex",
        "verified",
        "approved",
        "ready",
        "vault_path",
        "private_key",
        "amount",
        "fee",
        "plan",
    ] {
        assert!(value.get(forbidden).is_none());
    }
    // The exact native owners are still held after encoding data; revocation
    // must make subsequent sender checks fail, rather than leaving a free lease.
    revoke(&recipient);
    assert!(delivery.check_recipient(&recipient, &wire).is_err());
    assert!(delivery.response_for_recipient(&recipient, &wire).is_err());
}

#[test]
fn retirement_delivery_rejects_every_wire_change_and_grant_channel_substitution() {
    let f = Fixture::new();
    let wire = transport_wire(&f);
    let recipient = transport_recipient(&f, &wire);
    let (source, destination) = f.approved(&recipient);
    let delivery = transport_delivery(
        source,
        &f.source,
        destination,
        f.request(&recipient),
        &wire,
        Instant::now() + Duration::from_secs(120),
    )
    .unwrap();
    for field in 0..7 {
        let mut wrong = wire.clone();
        match field {
            0 => wrong.operation_id.push('x'),
            1 => wrong.request_nonce = "cd".repeat(32),
            2 => wrong.source_account_id = f.destination.account_id().unwrap(),
            3 => wrong.address.push('x'),
            4 => wrong.network_profile_id = "unsupported".into(),
            5 => wrong.purpose = "authorize".into(),
            _ => wrong.schema_version = 2,
        }
        assert!(delivery.check_recipient(&recipient, &wrong).is_err());
    }
    for field in 0..6 {
        let mut other = recipient.clone();
        match field {
            0 => other.binding.grant_id = "67".repeat(32),
            1 => other.binding.channel_digest = "78".repeat(32),
            2 => other.binding.process_instance = "89".repeat(32),
            3 => other.binding.generation += 1,
            4 => other.binding.scope.authorization_export = true,
            _ => other.binding.scope.manifest_digest = "9a".repeat(32),
        }
        other.digest = binding_digest(&other.binding).unwrap();
        assert!(delivery.check_recipient(&other, &wire).is_err());
    }
    // Same visible fields cannot replace the actual shared revocation owner.
    let lookalike = transport_recipient(&f, &wire);
    assert_eq!(lookalike.digest(), recipient.digest());
    assert!(delivery.check_recipient(&lookalike, &wire).is_err());
}

#[test]
fn retirement_delivery_rejects_wrong_actual_vault_and_original_source_substitution() {
    let f = Fixture::new();
    let wire = transport_wire(&f);
    let recipient = transport_recipient(&f, &wire);
    let request = f.request(&recipient);
    let (source, destination) = f.approved(&recipient);
    assert!(
        transport_delivery(
            source,
            &f.destination,
            destination,
            request.clone(),
            &wire,
            Instant::now() + Duration::from_secs(120)
        )
        .is_err()
    );
    let (original, destination) = f.approved(&recipient);
    let replacement = f.source(&recipient, &request);
    assert_ne!(original.review_digest(), replacement.review_digest());
    assert!(
        transport_delivery(
            replacement,
            &f.source,
            destination,
            request.clone(),
            &wire,
            Instant::now() + Duration::from_secs(120)
        )
        .is_err()
    );
    let (source, destination) = f.approved(&recipient);
    let mut substituted = request;
    substituted.destination_account_id = f.source.account_id().unwrap();
    assert!(
        transport_delivery(
            source,
            &f.source,
            destination,
            substituted,
            &wire,
            Instant::now() + Duration::from_secs(120)
        )
        .is_err()
    );
}

#[test]
fn retirement_delivery_original_deadline_and_destination_cancellation_remain_restrictive() {
    let f = Fixture::new();
    let wire = transport_wire(&f);
    let recipient = transport_recipient(&f, &wire);
    let (source, destination) = f.approved(&recipient);
    assert!(
        transport_delivery(
            source,
            &f.source,
            destination,
            f.request(&recipient),
            &wire,
            Instant::now()
        )
        .is_err()
    );
    let (source, destination) = f.approved(&recipient);
    let deadline = Instant::now() + Duration::from_secs(10);
    let delivery = transport_delivery(
        source,
        &f.source,
        destination,
        f.request(&recipient),
        &wire,
        deadline,
    )
    .unwrap();
    assert_eq!(delivery.deadline(), deadline);
    assert!(delivery.check_recipient(&recipient, &wire).is_ok());
    f.destination_native.invalidate();
    assert!(delivery.check_recipient(&recipient, &wire).is_err());
    assert!(delivery.response_for_recipient(&recipient, &wire).is_err());
}

#[test]
fn retirement_destination_display_names_original_source_review_and_nonce_stays_exact() {
    let f = Fixture::new();
    let wire = transport_wire(&f);
    let recipient = transport_recipient(&f, &wire);
    let request = f.request(&recipient);
    let source = f.source(&recipient, &request);
    let first = PreparedRecoveryDestination::prepare_for_retirement_recipient(
        &f.destination,
        &f.destination_native,
        request.clone(),
        &source,
        &f.source,
    )
    .unwrap();
    assert!(first.display().contains(&format!(
        "Original exact source review: {}",
        source.review_digest()
    )));
    let decision = recovery_test_decision(&f.destination_native, first.digest());
    let replacement = PreparedRecoveryDestination::prepare_for_retirement_recipient(
        &f.destination,
        &f.destination_native,
        request,
        &source,
        &f.source,
    )
    .unwrap();
    assert_ne!(first.digest(), replacement.digest());
    assert!(
        replacement
            .approve(decision, &f.destination_native)
            .is_err()
    );
}

fn transport_delivery<'a>(
    source: RetirementSourceRead,
    source_vault: &'a AccountVault,
    destination: ApprovedRecoveryDestination<'a>,
    request: RecoveryDestinationRequest,
    wire: &wholepact_signer_origin::retirement_evidence::RetirementDestinationEvidenceRequestV1,
    deadline: Instant,
) -> crate::Result<crate::native_ui::retirement_delivery::RetirementEvidenceDelivery<'a>> {
    // Correlation/restriction fixture only: cannot create an AuthenticatedPeer
    // or authenticated reply owner and cannot invoke actual transport.
    let binding =
        crate::ipc::retirement_evidence::RetirementEvidenceReplyBinding::synthetic_for_test(
            deadline,
            wire.digest().unwrap(),
        );
    crate::native_ui::retirement_delivery::RetirementEvidenceDelivery::new(
        source,
        source_vault,
        destination,
        request,
        wire,
        binding,
    )
}

#[test]
fn retirement_delivery_request_cancel_blocks_release_while_recipient_remains_live() {
    use crate::ipc::retirement_evidence::RetirementEvidenceReplyBinding;
    use crate::native_ui::retirement_delivery::RetirementEvidenceDelivery;
    let f = Fixture::new();
    let wire = transport_wire(&f);
    let recipient = transport_recipient(&f, &wire);
    let (source, destination) = f.approved(&recipient);
    let binding = RetirementEvidenceReplyBinding::synthetic_for_test(
        Instant::now() + Duration::from_secs(120),
        wire.digest().unwrap(),
    );
    let cancellation = binding.clone();
    let delivery = RetirementEvidenceDelivery::new(
        source,
        &f.source,
        destination,
        f.request(&recipient),
        &wire,
        binding,
    )
    .unwrap();
    assert!(delivery.check_recipient(&recipient, &wire).is_ok());
    cancellation.cancel_for_test();
    assert!(recipient.check_current().is_ok());
    assert!(delivery.check_recipient(&recipient, &wire).is_err());
    assert!(delivery.response_for_recipient(&recipient, &wire).is_err());

    let (source, destination) = f.approved(&recipient);
    let wrong_request = RetirementEvidenceReplyBinding::synthetic_for_test(
        Instant::now() + Duration::from_secs(120),
        "cd".repeat(32),
    );
    assert!(
        RetirementEvidenceDelivery::new(
            source,
            &f.source,
            destination,
            f.request(&recipient),
            &wire,
            wrong_request
        )
        .is_err()
    );
}
