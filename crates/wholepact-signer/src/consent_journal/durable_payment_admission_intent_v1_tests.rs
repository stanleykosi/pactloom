//! Isolated synthetic journal/Pending predicates. These fixtures are inert and
//! never invoke a native window, wallet, witness server, or admission transport.
use super::*;
use crate::consent_journal::authority::fixture;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use wholepact_authority::{
    account_use::{AccountUseGenesis, AccountUseIdentity},
    AuthorityHead, DurableFixedCandidateBindingV1, DurablePaymentAdmissionTermsV1,
    InputReservation,
};

fn authority_digest<T: Serialize>(domain: &str, value: &T) -> String {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0]);
    h.update(serde_json::to_vec(value).unwrap());
    hex::encode(h.finalize())
}
fn fixed_binding(f: &DurableFixedCandidateBindingV1) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
    h.update(f.schema_version.to_le_bytes());
    h.update(f.revision.to_le_bytes());
    h.update(f.expiry_height.to_le_bytes());
    for v in [
        &f.network_profile_id,
        &f.agreement_id,
        &f.obligation_id,
        &f.proposal_id,
        &f.proposal_digest,
        &f.manifest_digest,
        &f.unsigned_artifact_digest,
        &f.proved_artifact_digest,
        &f.effects_commitment,
        &f.policy_digest,
        &f.review_binding,
        &f.action_mapping_digest,
        &f.anchor,
    ] {
        h.update((v.len() as u64).to_le_bytes());
        h.update(v.as_bytes());
    }
    hex::encode(h.finalize())
}
struct Fixture {
    journal: SignerConsentJournal,
    session: SignerConsentSession,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
    request: OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
    owner: String,
    _dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let account = "11".repeat(32);
        let journal = SignerConsentJournal::create_encrypted(
            &dir.path().join("intent.sqlite"),
            &wholepact_storage_security::DatabaseKey::from_bytes([131; 32]),
            &account,
            1,
            false,
        )
        .unwrap();
        let session = fixture::session(&journal, "synthetic-owner");
        let mut input =
            crate::consent_journal::tests::proposal("agreement-a", "obligation-a", "proposal-a")
                .input()
                .clone();
        for p in &mut input.manifest.participants {
            if p.account_id == "account-alice" {
                p.account_id = account.clone();
            }
        }
        for p in &mut input.manifest.inputs {
            if p.account_id == "account-alice" {
                p.account_id = account.clone();
            }
        }
        for p in &mut input.manifest.outputs {
            if let wholepact_core::OutputAllocation::Return { account_id, .. } = &mut p.allocation {
                if *account_id == "account-alice" {
                    *account_id = account.clone();
                }
            }
        }
        let proposal = wholepact_core::Proposal::validate(input).unwrap();
        let disclosure = WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:443".into(),
            server_name: "synthetic-witness.example".into(),
            witness_id: "synthetic-witness".into(),
            account_id: account.clone(),
            network_profile_id: proposal.manifest().agreement.network_profile_id.clone(),
            policy_digest: "22".repeat(32),
            pinned_server_certificate_digest: "33".repeat(32),
        };
        let owner = "44".repeat(32);
        let genesis = AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: account.clone(),
                full_viewing_key_digest: "fa".repeat(32),
                network_profile_id: disclosure.network_profile_id.clone(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: disclosure.witness_id.clone(),
            witness_origin_digest: account_use_witness_origin_digest(&disclosure).unwrap(),
            owner_certificate_digest: owner.clone(),
            native_birth_digest: "55".repeat(32),
        };
        journal
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
                params![
                    account,
                    genesis.identity.full_viewing_key_digest,
                    genesis.digest().unwrap(),
                    encode(&genesis).unwrap().as_str()
                ],
            )
            .unwrap();
        let (enrollment, manifest) = Self::enroll(&journal, &session, &proposal, &genesis);
        let mut fixed = DurableFixedCandidateBindingV1 {
            schema_version: 1,
            network_profile_id: disclosure.network_profile_id.clone(),
            agreement_id: "agreement-a".into(),
            obligation_id: "obligation-a".into(),
            proposal_id: "proposal-a".into(),
            revision: proposal.manifest().agreement.revision,
            expiry_height: 100,
            proposal_digest: proposal.proposal_digest().into(),
            manifest_digest: proposal.manifest_digest().into(),
            unsigned_artifact_digest: "66".repeat(32),
            proved_artifact_digest: "77".repeat(32),
            effects_commitment: "88".repeat(32),
            policy_digest: "99".repeat(32),
            review_binding: "aa".repeat(32),
            action_mapping_digest: "bb".repeat(32),
            anchor: "cc".repeat(32),
            proposal_binding: String::new(),
        };
        fixed.proposal_binding = fixed_binding(&fixed);
        let identity: wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1 =
            serde_json::from_value(serde_json::to_value(&fixed).unwrap()).unwrap();
        let now = now_ms().unwrap();
        let terms = DurablePaymentAdmissionTermsV1 {
            version: 1,
            identity: wholepact_core::manual_enrollment::ManualAccountIdentity {
                account_id: account.clone(),
                full_viewing_key_digest: genesis.identity.full_viewing_key_digest.clone(),
                network_profile_id: genesis.identity.network_profile_id.clone(),
                derivation_domain: genesis.identity.derivation_domain.clone(),
            },
            original_policy_digest: disclosure.policy_digest.clone(),
            original_genesis_digest: genesis.digest().unwrap(),
            original_birth_commit_digest: "dd".repeat(32),
            original_roster_extension_digest: "ee".repeat(32),
            original_enrollment_ref: "ff".repeat(32),
            writer_certificate_digest: "12".repeat(32),
            authorization_id:
                crate::authority_bridge::durable_proposal_v1::manual_authorization_id(
                    &identity, &account,
                )
                .unwrap(),
            fixed,
            recipient_policy_scope_digest: "23".repeat(32),
            concrete_recipient_scope_digest: "34".repeat(32),
            inputs: vec![InputReservation {
                input_id: "synthetic-input".into(),
                nullifier: "45".repeat(32),
                action_index: 0,
                value_zatoshis: 1000,
            }],
            maximum_debit_zatoshis: 100,
            fee_share_zatoshis: 10,
            transaction_fee_zatoshis: 20,
            valid_from_ms: now - 1,
            valid_until_ms: now + 60_000,
        };
        let mut request = OwnerControlRequest {
            operation_id: String::new(),
            account_id: account,
            network_profile_id: disclosure.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: AuthorityHead {
                sequence: 5,
                digest: "56".repeat(32),
            },
            control: OwnerControl::AdmitDurablePaymentV1 {
                record: Box::new(DurablePaymentAdmissionRecordV1 {
                    terms,
                    witness_native_review_digest: String::new(),
                }),
            },
        };
        finish_request(&mut request, &disclosure);
        Self {
            journal,
            session,
            enrollment,
            manifest,
            request,
            disclosure,
            owner,
            _dir: dir,
        }
    }
    fn enroll(
        j: &SignerConsentJournal,
        s: &SignerConsentSession,
        p: &wholepact_core::Proposal,
        g: &AccountUseGenesis,
    ) -> (AccountEnrollmentRecord, AcceptedManifestRecord) {
        let e = j
            .record_enrollment(fixture::approve_enrollment(
                s,
                EnrollmentTerms {
                    account_id: g.identity.account_id.clone(),
                    agreement_id: p.manifest().agreement.agreement_id.clone(),
                    participant_id: "alice".into(),
                    principal_id: "synthetic-owner".into(),
                    network_profile_id: g.identity.network_profile_id.clone(),
                    privacy_domain: "synthetic-domain".into(),
                    account_fvk_digest: g.identity.full_viewing_key_digest.clone(),
                    transport: TransportIdentityBinding::RemoteAuthenticatedKeys {
                        transport_identity_id: "synthetic-transport".into(),
                        sender_key_digest: "a1".repeat(32),
                        recipient_key_digest: "b2".repeat(32),
                        channel_binding_digest: "c3".repeat(32),
                    },
                    aggregate_budget_limit_zatoshis: 1_000_000_000,
                    receipt: fixture::receipt(s),
                },
            ))
            .unwrap();
        let p = s.prepare_manifest(&e, p).unwrap();
        let d = fixture::decision(s, p.review_digest());
        let m = j
            .record_accepted_manifest(s.approve_manifest(p, d).unwrap())
            .unwrap();
        (e, m)
    }
    fn prepared(&self) -> PreparedDurablePaymentAdmissionIntentV1 {
        self.session
            .prepare_durable_payment_admission_intent_v1(
                &self.journal,
                self.request.clone(),
                self.disclosure.clone(),
                &self.owner,
                self.enrollment.reference(),
                self.manifest.reference(),
            )
            .unwrap()
    }
    fn approved(&self) -> ApprovedDurablePaymentAdmissionIntentV1 {
        let p = self.prepared();
        let d = fixture::decision(&self.session, p.digest());
        self.session
            .approve_durable_payment_admission_intent_v1(p, d)
            .unwrap()
    }
    fn retain(&self) -> RetainedDurablePaymentAdmissionIntentV1 {
        self.journal
            .retain_durable_payment_admission_intent_v1(self.approved(), || Ok(()))
            .unwrap()
    }
    fn count(&self) -> u64 {
        self.journal
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM signer_durable_payment_admission_intents",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }
}
fn finish_request(r: &mut OwnerControlRequest, d: &WitnessDisclosureDescriptor) {
    let terms = record(r).unwrap().terms.clone();
    r.operation_id = format!(
        "durable-payment-admit-v1-{}",
        authority_digest(
            "wholepact:durable-payment-owner-operation:v1",
            &(
                &terms,
                &r.account_id,
                &r.network_profile_id,
                r.writer_epoch,
                &r.expected_head
            )
        )
    );
    let review = authority_digest(
        "wholepact:durable-payment-witness-native-review:v1",
        &(
            &terms,
            &r.account_id,
            &r.network_profile_id,
            r.writer_epoch,
            &r.expected_head,
            d,
        ),
    );
    if let OwnerControl::AdmitDurablePaymentV1 { record } = &mut r.control {
        record.witness_native_review_digest = review;
    }
    record(r).unwrap().validate_request(r, d).unwrap();
}
#[test]
fn exact_native_pending_approval_is_required_and_retain_is_atomic_before_dispatch() {
    let f = Fixture::new();
    let p = f.prepared();
    let wrong = fixture::decision(&f.session, &"ab".repeat(32));
    assert!(f
        .session
        .approve_durable_payment_admission_intent_v1(p, wrong)
        .is_err());
    assert_eq!(f.count(), 0);
    let mut calls = 0;
    let outcome = f
        .journal
        .retain_durable_payment_admission_intent_v1(f.approved(), || {
            calls += 1;
            if calls == 2 {
                Err(JournalError::Permission)
            } else {
                Ok(())
            }
        });
    assert!(outcome.is_err());
    assert_eq!(calls, 2);
    assert_eq!(f.count(), 0);
    let retained = f.retain();
    assert_eq!(f.count(), 1);
    assert!(retained.request() == &f.request);
    // No transport is invoked anywhere in this fixture. A crash/return here
    // leaves the full exact intent, without any original release or reservation.
    let c = f.journal.connection.lock().unwrap();
    for t in [
        "signer_original_consents",
        "signer_release_intents",
        "signer_input_reservations",
    ] {
        assert_eq!(
            c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
}
#[test]
fn same_body_retry_keeps_first_receipt_and_changed_head_is_conflict() {
    let mut f = Fixture::new();
    let first = f.retain();
    let retry = f.retain();
    assert!(first == retry);
    assert_eq!(f.count(), 1);
    f.request.expected_head.sequence += 1;
    f.request.expected_head.digest = "67".repeat(32);
    finish_request(&mut f.request, &f.disclosure);
    assert!(matches!(
        f.session.prepare_durable_payment_admission_intent_v1(
            &f.journal,
            f.request.clone(),
            f.disclosure.clone(),
            &f.owner,
            f.enrollment.reference(),
            f.manifest.reference()
        ),
        Err(JournalError::Conflict)
    ));
    assert_eq!(f.count(), 1);
}
#[test]
fn fresh_native_retry_requires_new_current_refs_but_never_rewrites_first_history() {
    let mut f = Fixture::new();
    let first = f.retain();
    f.session.invalidate().unwrap();
    f.session = fixture::session(&f.journal, "synthetic-owner");
    assert!(f
        .session
        .prepare_durable_payment_admission_intent_v1(
            &f.journal,
            f.request.clone(),
            f.disclosure.clone(),
            &f.owner,
            f.enrollment.reference(),
            f.manifest.reference()
        )
        .is_err());
    let proposal = f.manifest.proposal().unwrap();
    let g =
        account_use_storage::inspect(&f.journal.connection.lock().unwrap(), &f.request.account_id)
            .unwrap()
            .genesis()
            .unwrap()
            .clone();
    (f.enrollment, f.manifest) = Fixture::enroll(&f.journal, &f.session, &proposal, &g);
    assert_ne!(first.enrollment_ref(), f.enrollment.reference());
    let retried = f.retain();
    assert!(first == retried);
    assert_eq!(f.count(), 1);
}
#[test]
fn historical_row_survives_native_expiry_revocation_and_does_not_create_approval() {
    let f = Fixture::new();
    let first = f.retain();
    fixture::expire_receipt_monotonically(&f.session, first.native_receipt().nonce());
    f.session.invalidate().unwrap();
    let current = fixture::session(&f.journal, "synthetic-owner");
    let read = f
        .journal
        .durable_payment_admission_intent_v1(
            &record(&f.request).unwrap().terms.authorization_id,
            &current,
        )
        .unwrap()
        .unwrap();
    assert!(read == first);
    assert!(f
        .session
        .prepare_durable_payment_admission_intent_v1(
            &f.journal,
            f.request.clone(),
            f.disclosure.clone(),
            &f.owner,
            f.enrollment.reference(),
            f.manifest.reference()
        )
        .is_err());
}
#[test]
fn strict_payload_rejects_unknown_duplicate_fields_and_historical_link_substitution() {
    let f = Fixture::new();
    let first = f.retain();
    let raw = encode(&first.0).unwrap();
    let unknown = raw.replacen('{', "{\"unexpected\":1,", 1);
    assert!(decode::<DurablePaymentAdmissionIntentV1>(unknown).is_err());
    let duplicate = raw.replacen('{', "{\"version\":1,", 1);
    assert!(decode::<DurablePaymentAdmissionIntentV1>(duplicate).is_err());
    let c = f.journal.connection.lock().unwrap();
    for field in 0..4 {
        let mut changed = first.0.clone();
        match field {
            0 => changed.owner_certificate_digest = "78".repeat(32),
            1 => changed.enrollment_ref = "89".repeat(32),
            2 => changed.manifest_ref = "9a".repeat(32),
            _ => changed.native_receipt.writer_epoch += 1,
        };
        changed.native_review_digest = changed.review_digest().unwrap();
        assert!(validate_original_rows(&c, &changed).is_err());
    }
}
