//! Explicit, serialized, expensive positive integration fixture. A fresh encrypted
//! never-funded vault supplies the actual FVK; native/session decisions are the
//! existing cfg(test) issuer fixtures and are not genuine human approval. Real
//! Halo2 proof, maintained assertion verification and authenticated HPKE are used.
//! No chain, provider, persistent wallet or external credential. The separate
//! final-tests feature adds ephemeral selected-own spending signatures.
use super::*;
use crate::{
    account::{PendingAccount, ProvisioningConsent},
    consent_journal::{authority::fixture, named_recipient_records::*},
    native_ui::{recovery_test_authority, recovery_test_decision},
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use wholepact_authority::{AuthorityHead, OfflineAdmissionExportPlan, offline::*};
use wholepact_offline_bridge::{NamedVerifierPackageV1, synthetic_joined_named_package};
use wholepact_protocol::{
    own_effects::*,
    proving::{ProvingLimits, prove_reviewed},
    review::ReviewPolicy,
};
use wholepact_transport::*;
mod builder;
mod context;
fn random32() -> [u8; 32] {
    let mut b = [0; 32];
    getrandom::fill(&mut b).unwrap();
    b
}
fn hash_bytes(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn transport() -> TransportSecret {
    TransportSecret::from_bytes(random32()).unwrap()
}
struct Fixture {
    journal: SignerConsentJournal,
    session: SignerConsentSession,
    vault: AccountVault,
    native: Option<NativeAuthority>,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
    profile: LiveNamedRecipientProfile,
    proposal: wholepact_core::Proposal,
    policy: ReviewPolicy,
    unproved: Vec<u8>,
    pair: Ed25519KeyPair,
    sender: TransportSecret,
    witness: TransportSecret,
    witness_secret: Zeroizing<[u8; 32]>,
    return_key: TransportSecret,
    return_secret: Zeroizing<[u8; 32]>,
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        Self::new_with_certificate(None)
    }
    fn new_with_certificate(certificate: Option<String>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let pending = PendingAccount::generate(ProvisioningConsent {
            privacy_domain: "ephemeral-joined-fixture".into(),
            account_index: 0,
        })
        .unwrap();
        let words = pending.recovery_words().unwrap();
        let verified = pending.verify_backup(&words).unwrap();
        drop(words);
        let password = Zeroizing::new(random32());
        let mut vault =
            AccountVault::create(&dir.path().join("vault"), verified, password.as_ref()).unwrap();
        drop(password);
        let (unproved, mut policy) =
            builder::build(vault.account().fvk().unwrap(), &vault.account_id().unwrap());
        let proposal = context::proposal(&mut policy);
        let journal = vault.create_authority_journal().unwrap();
        let native = recovery_test_authority();
        let session = fixture::native_session(
            &journal,
            native.binding(),
            native.principal_id(),
            native.measurement(),
        );
        let (enrollment, manifest) = enroll(&journal, &session, &vault, &native, &proposal);
        let seed = Zeroizing::new(random32());
        let pair = Ed25519KeyPair::from_seed_unchecked(seed.as_ref()).unwrap();
        drop(seed);
        let sender = transport();
        let witness_secret = Zeroizing::new(random32());
        let witness = TransportSecret::from_bytes(*witness_secret).unwrap();
        let return_secret = Zeroizing::new(random32());
        let return_key = TransportSecret::from_bytes(*return_secret).unwrap();
        let prepared = PreparedNamedRecipientSetup::prepare(
            &journal,
            &session,
            &vault,
            &native,
            enrollment.reference(),
            manifest.reference(),
            NamedRecipientPins {
                verifier_signing: pair.public_key().as_ref().try_into().unwrap(),
                verifier_transport: *sender.public_key().unwrap().as_bytes(),
                witness_transport: *witness.public_key().unwrap().as_bytes(),
                witness_certificate_digest: certificate
                    .unwrap_or_else(|| hash_bytes(b"ephemeral witness certificate fixture")),
                return_transport: *return_key.public_key().unwrap().as_bytes(),
            },
        )
        .unwrap();
        let decision = recovery_test_decision(&native, prepared.digest());
        let profile = prepared
            .approve(decision, &journal, &session, &vault)
            .unwrap();
        Self {
            journal,
            session,
            vault,
            native: Some(native),
            enrollment,
            manifest,
            profile,
            proposal,
            policy,
            unproved,
            pair,
            sender,
            witness,
            witness_secret,
            return_key,
            return_secret,
            dir,
        }
    }
    fn native(&self) -> &NativeAuthority {
        self.native.as_ref().unwrap()
    }
    fn counts(&self) -> [usize; 3] {
        let c = self.journal.connection.lock().unwrap();
        [
            "signer_named_recipient_originals",
            "signer_named_recipient_receipts",
            "signer_named_intent_outbox",
        ]
        .map(|t| {
            c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap()
        })
    }
    fn exact_retained(&self) -> (String, String, String) {
        let c = self.journal.connection.lock().unwrap();
        (
            c.query_row(
                "SELECT payload FROM signer_named_recipient_originals",
                [],
                |r| r.get(0),
            )
            .unwrap(),
            c.query_row(
                "SELECT envelope_digest FROM signer_named_recipient_receipts",
                [],
                |r| r.get(0),
            )
            .unwrap(),
            c.query_row(
                "SELECT envelope_hex FROM signer_named_intent_outbox",
                [],
                |r| r.get(0),
            )
            .unwrap(),
        )
    }
}
fn enroll(
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    vault: &AccountVault,
    native: &NativeAuthority,
    proposal: &wholepact_core::Proposal,
) -> (AccountEnrollmentRecord, AcceptedManifestRecord) {
    let account_id = vault.account_id().unwrap();
    let enrollment = journal
        .record_enrollment(fixture::approve_enrollment(
            session,
            EnrollmentTerms {
                account_id,
                agreement_id: proposal.manifest().agreement.agreement_id.clone(),
                participant_id: "fixture-participant-0".into(),
                principal_id: native.principal_id().into(),
                network_profile_id: proposal.manifest().agreement.network_profile_id.clone(),
                privacy_domain: vault.account().privacy_domain().into(),
                account_fvk_digest: hex::encode(Sha256::digest(
                    vault.account().fvk().unwrap().to_bytes(),
                )),
                transport: TransportIdentityBinding::RemoteAuthenticatedKeys {
                    transport_identity_id: "synthetic-enrollment-transport".into(),
                    sender_key_digest: hex::encode(random32()),
                    recipient_key_digest: hex::encode(random32()),
                    channel_binding_digest: hex::encode(random32()),
                },
                aggregate_budget_limit_zatoshis: 1_000_000_000,
                receipt: fixture::receipt(session),
            },
        ))
        .unwrap();
    let prepared = session.prepare_manifest(&enrollment, proposal).unwrap();
    let decision = fixture::decision(session, prepared.review_digest());
    let manifest = journal
        .record_accepted_manifest(session.approve_manifest(prepared, decision).unwrap())
        .unwrap();
    (enrollment, manifest)
}
struct Incoming {
    original: NamedRecipientOriginalRecordV1,
    policy: OfflineEnrollmentPolicy,
    envelope: Vec<u8>,
    now: Timestamp,
    end: Timestamp,
}
impl Incoming {
    fn prepare(
        &self,
        f: &Fixture,
    ) -> std::result::Result<PreparedNamedRecipientOriginalImport, TransportError> {
        f.profile.prepare_original_import(
            &f.journal,
            &f.session,
            &f.vault,
            NamedRecipientOriginalInputs {
                proposed: self.original.clone(),
                own_policy: context::own_policy(&f.policy, 0),
                proposed_policy: self.policy.clone(),
                assertion_envelope: EncryptedEnvelope::from_bytes(self.envelope.clone()).unwrap(),
                outgoing: NamedIntentExportTemplate {
                    order: MessageOrder {
                        message_id: "64".repeat(16),
                        sequence: 0,
                        issued_at: self.now.clone(),
                        expires_at: self.end.clone(),
                    },
                    purpose: "Ephemeral original intent qualification".into(),
                    persistence_warning: "Never-funded fixture only".into(),
                },
                now: self.now.clone(),
            },
        )
    }
}
fn incoming(f: &Fixture) -> Incoming {
    let (mut terms, inputs, outputs) = context::terms(&f.unproved, &f.policy, &f.proposal);
    let proved = prove_reviewed(
        &f.unproved,
        &f.policy,
        &terms.review_binding,
        ProvingLimits { maximum_actions: 8 },
    )
    .unwrap();
    assert!(proved.proof_verified && proved.proof_bytes > 0);
    assert!(
        !proved.chain_validated && !proved.authorization_allowed && !proved.distribution_allowed
    );
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let now = Timestamp::from_unix_seconds(seconds).unwrap();
    let end = Timestamp::from_unix_seconds(seconds + 600).unwrap();
    let start_ms = seconds as u64 * 1000;
    let end_ms = (seconds as u64 + 600) * 1000;
    let profile = &f.profile.record;
    let policy = OfflineEnrollmentPolicy {
        schema_version: 1,
        account_id: profile.account_id.clone(),
        network_profile_id: terms.network_profile_id.clone(),
        witness_id: "ephemeral-witness".into(),
        witness_transport_key_digest: f.witness.public_key().unwrap().fingerprint(),
        witness_certificate_digest: profile.witness_certificate_digest.clone(),
        enrollment_ref: f.enrollment.reference().into(),
        offline_signer_key_digest: transport_fingerprint(&profile.transport_public_key),
        return_recipient_key_digest: f.return_key.public_key().unwrap().fingerprint(),
        source_identity_digest: terms.snapshot.source_identity_digest.clone(),
        source_policy_digest: terms.snapshot.source_policy_digest.clone(),
        maximum_admission_lifetime_ms: 600_000,
        valid_from_ms: start_ms,
        expires_at_ms: end_ms,
        semantics: OfflineAuthoritySemantics::ExactEffectsPreReservedMayDrainAfterRevocation,
    };
    terms.artifact_digest = hash_bytes(&proved.pczt_bytes);
    terms.enrollment_ref = f.enrollment.reference().into();
    terms.accepted_manifest_ref = f.manifest.reference().into();
    terms.offline_policy_digest = policy.policy_digest().unwrap();
    terms.offline_signer_key_digest = policy.offline_signer_key_digest.clone();
    terms.return_recipient_key_digest = policy.return_recipient_key_digest.clone();
    let request_digest = hash_bytes(b"ephemeral joined original request");
    // Unproved data must not pass the same maintained producer used below.
    let mut unproved_terms = terms.clone();
    unproved_terms.artifact_digest = hash_bytes(&f.unproved);
    assert!(
        synthetic_joined_named_package(
            &f.unproved,
            unproved_terms,
            f.proposal.clone(),
            f.policy.clone(),
            inputs.clone(),
            outputs.clone(),
            request_digest.clone(),
            start_ms,
            end_ms,
            &f.pair
        )
        .is_err()
    );
    let package_bytes = synthetic_joined_named_package(
        &proved.pczt_bytes,
        terms.clone(),
        f.proposal.clone(),
        f.policy.clone(),
        inputs,
        outputs,
        request_digest.clone(),
        start_ms,
        end_ms,
        &f.pair,
    )
    .unwrap();
    let package = NamedVerifierPackageV1::parse(&package_bytes).unwrap();
    let own = context::own_policy(&f.policy, 0);
    assert!(own.own_fvk.to_bytes() == f.vault.account().fvk().unwrap().to_bytes());
    let inspected = wholepact_offline_bridge::inspect_selected_offline_effects(
        &package.recipient_artifact,
        &own,
    )
    .unwrap();
    let header =
        NamedReviewBindingV1 {
            schema_version: 1,
            disclosure_profile: NAMED_REVIEW_DISCLOSURE_PROFILE_V1.into(),
            owner_setup_digest: profile.original_setup_digest.clone(),
            assertion_package_digest: hash_bytes(&package_bytes),
            original_context_digest:
                wholepact_offline_bridge::named_verifier_original_context_digest(&terms).unwrap(),
        };
    terms.review_package_digest = header.review_package_digest().unwrap();
    let reservation = ReserveOfflineAuthorization {
        schema_version: 1,
        operation_id: "ephemeral-original-operation".into(),
        writer_epoch: 1,
        expected_head: AuthorityHead {
            sequence: 0,
            digest: hash_bytes(b"ephemeral witness head; never authority"),
        },
        intent: OfflineReservationIntent {
            schema_version: 1,
            intent_id: "ephemeral-original-intent".into(),
            terms: terms.clone(),
            native_reservation_review_digest: hash_bytes(b"normalized by actual native producer"),
        },
        requested_at_ms: start_ms,
        admission_expires_at_ms: end_ms,
    };
    let own_expectations = NamedRecipientOwnExpectationsV1 {
        schema_version: 1,
        full_viewing_key_digest: profile.full_viewing_key_digest.clone(),
        manifest_digest: terms.manifest_digest.clone(),
        anchor: hex::encode(own.anchor),
        expiry_height: own.expiry_height,
        maximum_selected_net_debit_zatoshis: own.maximum_selected_net_debit_zatoshis,
        exact_selected_net_debit_zatoshis: own.exact_selected_net_debit_zatoshis,
        declared_fee_share_zatoshis: own.declared_fee_share_zatoshis,
        exact_transaction_fee_zatoshis: own.exact_transaction_fee_zatoshis,
        own_inputs: own
            .own_inputs
            .iter()
            .map(|i| NamedRecipientOwnInputV1 {
                action_index: i.action_index as u32,
                nullifier: hex::encode(i.nullifier),
                value_zatoshis: i.value_zatoshis,
            })
            .collect(),
        outputs: own
            .outputs
            .iter()
            .map(|o| NamedRecipientOwnOutputV1 {
                action_index: o.action_index as u32,
                receiver_hex: hex::encode(o.receiver.to_raw_address_bytes()),
                value_zatoshis: o.value_zatoshis,
                memo_hex: hex::encode(o.memo),
                purpose: match o.purpose {
                    OwnOutputPurpose::OwnReturn => NamedRecipientOutputPurposeV1::OwnReturn,
                    OwnOutputPurpose::Recipient => NamedRecipientOutputPurposeV1::Recipient,
                    OwnOutputPurpose::PeerReturnUnverified => {
                        NamedRecipientOutputPurposeV1::PeerReturnUnverified
                    }
                },
            })
            .collect(),
    };
    let mut original = NamedRecipientOriginalRecordV1 {
        born_origin: None,
        schema_version: 1,
        reference: String::new(),
        profile_ref: profile.reference.clone(),
        original_artifact_digest: terms.artifact_digest.clone(),
        canonical_artifact_digest: package.statement.recipient_artifact_digest.clone(),
        transformation_digest: package.statement.transformation_commitment.clone(),
        named_assertion_digest: hash_bytes(&package.statement.signing_message().unwrap()),
        assertion_package_digest: hash_bytes(&package_bytes),
        validity_not_before_ms: start_ms,
        validity_expires_ms: end_ms,
        original_request_digest: request_digest,
        reservation_request_digest: reservation.request_digest().unwrap(),
        reservation_request: reservation,
        admission_export_template: OfflineAdmissionExportPlan {
            message_id: "65".repeat(16),
            sequence: 0,
            issued_at_unix_seconds: seconds,
            expires_at_unix_seconds: seconds + 600,
            purpose: "Ephemeral admission reply".into(),
            persistence_warning: "Fixture only".into(),
            sender_id: format!("offline-admission:{}", terms.offline_policy_digest),
            recipient_id: format!("offline-admission:{}", terms.offline_signer_key_digest),
            sender_key_fingerprint: policy.witness_transport_key_digest.clone(),
            recipient_key_fingerprint: policy.offline_signer_key_digest.clone(),
        },
        own_policy_digest: inspected.inspection().policy_digest().into(),
        own_expectations,
        terms,
    };
    original.reference = original.reference_digest().unwrap();
    original.validate(profile).unwrap();
    let export = prepare_export(
        ExportRequest {
            context: MessageContext {
                network_profile_id: original.terms.network_profile_id.clone(),
                agreement_id: original.terms.agreement_id.clone(),
                proposal_id: original.terms.proposal_id.clone(),
                proposal_revision: original.terms.proposal_revision,
                sender_id: hash_bytes(f.pair.public_key().as_ref()),
                recipient_id: profile.account_id.clone(),
                artifact_kind: ArtifactKind::NamedVerifierAssertion,
            },
            order: MessageOrder {
                message_id: "66".repeat(16),
                sequence: 1,
                issued_at: now.clone(),
                expires_at: end.clone(),
            },
            purpose: "Ephemeral genuine proof assertion".into(),
            persistence_warning: "Fixture only".into(),
        },
        vec![DisclosureField::new("named-verifier-assertion-v1", package_bytes).unwrap()],
        &f.sender.public_key().unwrap(),
        &TransportPublicKey::from_bytes(profile.transport_public_key).unwrap(),
        &now,
    )
    .unwrap();
    let digest = export.preview().digest().unwrap();
    let envelope = export
        .seal(&f.sender, &digest, &now)
        .unwrap()
        .as_bytes()
        .to_vec();
    Incoming {
        original,
        policy,
        envelope,
        now,
        end,
    }
}

#[test]
#[ignore = "expensive real Halo2 proof; explicit serialized ephemeral qualification"]
fn genuine_joined_original_atomic_commit_exact_recovery_and_file_export() {
    let mut f = Fixture::new();
    let incoming = incoming(&f);
    assert_eq!(f.counts(), [0, 0, 0]);
    // Capacity is checked inside the real transaction after successful genuine
    // assertion authentication; failure must leave all three tables unchanged.
    let limits = f.journal.capacity_limits;
    f.journal.capacity_limits =
        storage::capacity_estimate(&f.journal.connection.lock().unwrap()).unwrap();
    let prepared = incoming.prepare(&f).unwrap();
    let decision = recovery_test_decision(f.native(), prepared.digest());
    assert!(
        prepared
            .approve(decision, &f.journal, &f.session, &f.vault, &incoming.now)
            .is_err()
    );
    assert_eq!(f.counts(), [0, 0, 0]);
    f.journal.capacity_limits = limits;
    // A source from a different actual native instance is not interchangeable.
    let prepared = incoming.prepare(&f).unwrap();
    let other = recovery_test_authority();
    let wrong = recovery_test_decision(&other, prepared.digest());
    assert!(
        prepared
            .approve(wrong, &f.journal, &f.session, &f.vault, &incoming.now)
            .is_err()
    );
    assert_eq!(f.counts(), [0, 0, 0]);
    drop(other);
    let prepared = incoming.prepare(&f).unwrap();
    let authorization_id = prepared.authorization_id().to_owned();
    let decision = recovery_test_decision(f.native(), prepared.digest());
    let retained = prepared
        .approve(decision, &f.journal, &f.session, &f.vault, &incoming.now)
        .unwrap();
    assert_eq!(f.counts(), [1, 1, 1]);
    assert_eq!(retained.authorization_id(), authorization_id);
    let original_ref = retained.original_ref().to_owned();
    let exact = f.exact_retained();
    // Simulate successful commit whose returned wrapper is lost: no delivered
    // original reference or ciphertext is used to locate durable recovery.
    drop(retained);
    assert!(incoming.prepare(&f).is_err());
    assert_eq!(f.counts(), [1, 1, 1]);
    assert!(
        f.profile
            .recover_original_intent_export(&f.journal, &f.session, &f.vault, "unknown-exact-id")
            .unwrap()
            .is_none()
    );
    let profile_ref = f.profile.reference().to_owned();
    f.session.invalidate().unwrap();
    f.native = None;
    f.journal = f.vault.open_authority_journal().unwrap();
    let native = recovery_test_authority();
    f.session = fixture::native_session(
        &f.journal,
        native.binding(),
        native.principal_id(),
        native.measurement(),
    );
    f.native = Some(native);
    let prepared = PreparedNamedRecipientSetup::reopen(
        &f.journal,
        &f.session,
        &f.vault,
        f.native(),
        &profile_ref,
    )
    .unwrap();
    let decision = recovery_test_decision(f.native(), prepared.digest());
    f.profile = prepared
        .approve(decision, &f.journal, &f.session, &f.vault)
        .unwrap();
    let recovered = f
        .profile
        .recover_original_intent_export(&f.journal, &f.session, &f.vault, &authorization_id)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.original_ref(), original_ref);
    assert!(f.exact_retained() == exact);
    assert_eq!(f.counts(), [1, 1, 1]);
    let destination = f.dir.path().join("exact-intent.handoff");
    let export = recovered
        .prepare_file_export(&f.journal, &f.session, &f.vault, &destination)
        .unwrap();
    let decision = recovery_test_decision(f.native(), export.digest());
    export
        .write_new_file(decision, &f.journal, &f.session, &f.vault)
        .unwrap();
    let handoff = OfflineIntentHandoffV1::parse(&std::fs::read(&destination).unwrap()).unwrap();
    assert_eq!(
        handoff.request().intent.terms.authorization_id,
        authorization_id
    );
    assert!(handoff.encrypted_intent().unwrap() == hex::decode(&exact.2).unwrap());
    let retained_original: NamedRecipientOriginalRecordV1 = serde_json::from_str(&exact.0).unwrap();
    assert!(handoff.request() == &retained_original.reservation_request);
    assert!(handoff.admission_export_template() == &retained_original.admission_export_template);
    assert!(f.exact_retained() == exact);
    assert_eq!(f.counts(), [1, 1, 1]);
    let c = f.journal.connection.lock().unwrap();
    for table in [
        "signer_named_recipient_started",
        "signer_named_recipient_results",
        "signer_bridge_keyuse",
        "signer_input_reservations",
        "signer_offline_local_admissions",
    ] {
        let n: usize = c
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "unexpected financial authority mutation");
    }
    drop(c);
    let encrypted = std::fs::read(f.dir.path().join("vault/authority.sqlite")).unwrap();
    assert!(!encrypted.starts_with(b"SQLite format 3\0"));
    for needle in [
        b"transport_secret".as_slice(),
        b"ephemeral-joined-fixture".as_slice(),
    ] {
        assert!(
            !encrypted
                .windows(needle.len())
                .any(|window| window == needle)
        );
    }
    let root = f.dir.path().to_owned();
    drop(f);
    assert!(!root.exists());
}

#[cfg(feature = "synthetic-recipient-signing-tests")]
mod final_tests;
