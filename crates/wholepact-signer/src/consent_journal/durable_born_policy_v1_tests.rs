//! Fabricated data-only history tests. No native owner, network, witness session,
//! wallet ticket or key-use authority is created by these fixtures.
use super::*;
use wholepact_authority::{
    account_use::AccountUseIdentity, manual_enrollment::ManualEnrollmentExtension,
};
use wholepact_core::{manual_enrollment::*, manual_roster_v2::*, OutputAllocation, Proposal};

fn h(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

pub(super) struct Fixture {
    pub(super) binding: DurableBornPolicyBindingV1,
    pub(super) terms: SpendConsentTerms,
    pub(super) enrollment: AccountEnrollmentRecord,
    pub(super) manifest: AcceptedManifestRecord,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let mut input =
            crate::consent_journal::tests::proposal("agreement-a", "obligation-a", "proposal-a")
                .input()
                .clone();
        input.artifact_digest = None;
        input.effects_commitment = None;
        for p in &mut input.manifest.participants {
            if p.account_id == "account-alice" {
                p.account_id = h('1');
            }
        }
        for i in &mut input.manifest.inputs {
            if i.account_id == "account-alice" {
                i.account_id = h('1');
            }
        }
        for o in &mut input.manifest.outputs {
            if let OutputAllocation::Return { account_id, .. } = &mut o.allocation {
                if account_id == "account-alice" {
                    *account_id = h('1');
                }
            }
        }
        let proposal = Proposal::validate(input).unwrap();
        let receipt = NativeConsentReceipt {
            native_session_id: h('a'),
            trusted_launch_measurement: h('b'),
            permission_generation: 3,
            writer_epoch: 7,
            nonce: h('c'),
            reviewed_at_ms: 100_000,
            expires_at_ms: 160_000,
        };
        let transport = TransportIdentityBinding::LocalProcess {
            transport_identity_id: "fresh-process".into(),
            channel_key_digest: h('4'),
            channel_binding_digest: h('5'),
            uid: 42,
            pid: 99,
            process_instance: h('6'),
            signer_generation: 9,
            account_id: h('1'),
            agreement_id: "agreement-a".into(),
            participant_id: "alice".into(),
            manifest_digest: proposal.manifest_digest().into(),
        };
        let enrollment = AccountEnrollmentRecord::new(EnrollmentTerms {
            account_id: h('1'),
            agreement_id: "agreement-a".into(),
            participant_id: "alice".into(),
            principal_id: "fresh-native-owner".into(),
            network_profile_id: proposal.manifest().agreement.network_profile_id.clone(),
            privacy_domain: "synthetic-domain".into(),
            account_fvk_digest: h('2'),
            transport,
            aggregate_budget_limit_zatoshis: 1_000_000_000,
            receipt: receipt.clone(),
        })
        .unwrap();
        let manifest = AcceptedManifestRecord::new(ManifestTerms {
            enrollment_ref: enrollment.reference().into(),
            account_id: h('1'),
            principal_id: enrollment.principal_id().into(),
            proposal: proposal.input().clone(),
            proposal_digest: proposal.proposal_digest().into(),
            manifest_digest: proposal.manifest_digest().into(),
            receipt: receipt.clone(),
        })
        .unwrap();
        let genesis = AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: h('1'),
                full_viewing_key_digest: h('2'),
                network_profile_id: enrollment.terms.network_profile_id.clone(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: "synthetic-witness".into(),
            witness_origin_digest: h('8'),
            owner_certificate_digest: h('4'),
            native_birth_digest: h('5'),
        };
        let mut first = enrollment.transport().clone();
        if let TransportIdentityBinding::LocalProcess {
            transport_identity_id,
            pid,
            signer_generation,
            ..
        } = &mut first
        {
            *transport_identity_id = "original-closed-process".into();
            *pid = 1;
            *signer_generation = 1;
        }
        let terms = BornManualEnrollmentTerms {
            version: 1,
            operation_id: "original-enrollment".into(),
            identity: ManualAccountIdentity {
                account_id: h('1'),
                full_viewing_key_digest: h('2'),
                network_profile_id: genesis.identity.network_profile_id.clone(),
                derivation_domain: genesis.identity.derivation_domain.clone(),
            },
            birth_request_digest: h('3'),
            birth_commit_digest: h('4'),
            native_birth_digest: h('5'),
            original_policy_digest: h('6'),
            account_use_genesis_digest: genesis.digest().unwrap(),
            original_witness_origin_digest: h('8'),
            host: ManualHostGenerationBinding {
                generation_id: h('9'),
                inventory_digest: h('a'),
                generation_plan_digest: h('b'),
                financial_journal_origin_digest: h('c'),
                store_destination_identity: "original-store".into(),
                profile_id: "original-profile".into(),
                canonical_root: "/synthetic/profile".into(),
                destination_identity_digest: h('e'),
                inherited_identity_digest: h('f'),
                scope_predecessor_digest: None,
            },
            signer: BornManualSignerBinding {
                enrollment_generation_id: h('1'),
                signer_target_digest: h('2'),
                original_envelope_digest: h('3'),
                owner_certificate_digest: h('4'),
                writer_certificate_digest: h('5'),
                writer_epoch: 1,
                native_signer_measurement: h('6'),
            },
            scope: BornManualScope {
                agreement_id: "agreement-a".into(),
                obligation_id: "obligation-a".into(),
                participant_id: "alice".into(),
                principal_id: "original-host-principal".into(),
                privacy_domain: "synthetic-domain".into(),
                recipient_scope_digests: vec![
                    wholepact_core::manual_construction::construction_recipient_scope_digest(
                        &proposal,
                    )
                    .unwrap(),
                ],
                aggregate_budget_zatoshis: 1_000_000_000,
                per_operation_limit_zatoshis: 500_000_000,
                maximum_fee_share_zatoshis: 12_000,
                maximum_transaction_fee_zatoshis: 30_000,
                maximum_permit_lifetime_ms: 120_000,
                expires_at_ms: 200_000,
            },
            transport_binding_digest: digest("wholepact:born-manual-transport:v1", &first).unwrap(),
            issued_at_ms: 10,
        };
        let principal = "original-native-principal".to_string();
        let original = OriginalManualRecordV1 {
            terms_digest: terms.terms_digest().unwrap(),
            signer_native_review_digest: digest(
                "wholepact:native-born-manual-enrollment-review:v1",
                &(&terms, &genesis, &first, &principal),
            )
            .unwrap(),
            terms,
            genesis,
            first_process_binding: first,
            first_native_principal: principal,
        };
        let roster = HostRosterAppendBindingV2 {
            version: 2,
            generation_id: original.terms.host.generation_id.clone(),
            store_destination_identity: original.terms.host.store_destination_identity.clone(),
            roster_sequence: 2,
            predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: h('7'),
            },
        };
        let extension = ManualEnrollmentExtension {
            version: 1,
            terms: original.terms.clone(),
            enrollment_ref: original.reference().unwrap(),
            enrollment_record_digest: original.reference().unwrap(),
            sequence: 1,
            predecessor_digest: None,
        };
        let mut fixed = FixedCandidateV1 {
            schema_version: 1,
            network_profile_id: enrollment.terms.network_profile_id.clone(),
            agreement_id: "agreement-a".into(),
            obligation_id: "obligation-a".into(),
            proposal_id: "proposal-a".into(),
            revision: proposal.manifest().agreement.revision,
            expiry_height: proposal.manifest().expiry_height,
            proposal_digest: proposal.proposal_digest().into(),
            manifest_digest: proposal.manifest_digest().into(),
            unsigned_artifact_digest: h('d'),
            proved_artifact_digest: hex::encode(Sha256::digest(b"synthetic-fixed-artifact")),
            effects_commitment: h('e'),
            policy_digest: h('a'),
            review_binding: h('b'),
            action_mapping_digest: h('c'),
            anchor: h('f'),
            proposal_binding: String::new(),
        };
        fixed.proposal_binding = fixed.binding();
        let mut binding = DurableBornPolicyBindingV1 {
            version: 1,
            original_genesis_digest: original.genesis.digest().unwrap(),
            original_enrollment_ref: original.reference().unwrap(),
            original_extension_digest: extension.digest().unwrap(),
            original_roster_extension_digest: String::new(),
            recipient_scope_digest: original.terms.scope.recipient_scope_digests[0].clone(),
            local_enrollment_ref: enrollment.reference().into(),
            local_accepted_manifest_ref: manifest.reference().into(),
            original,
            recipient_policy_profile: DurableBornRecipientPolicyProfileV1::FixedExactV1,
            original_roster_extension: ManualRosterEnrollmentExtensionV2 {
                version: 2,
                account_extension: extension,
                roster,
                signer_roster_record_digest: h('1'),
            },
            fixed,
        };
        rehash_original(&mut binding);
        let terms = SpendConsentTerms {
            durable_born_policy_v1: None,
            automation: None,
            sponsor_policy: None,
            sponsor_owner_attestation_digest: None,
            authorization_id: "authorization-a".into(),
            enrollment_ref: enrollment.reference().into(),
            accepted_manifest_ref: manifest.reference().into(),
            account_id: h('1'),
            principal_id: enrollment.principal_id().into(),
            agreement_id: "agreement-a".into(),
            obligation_id: "obligation-a".into(),
            proposal_id: "proposal-a".into(),
            proposal_digest: proposal.proposal_digest().into(),
            manifest_digest: proposal.manifest_digest().into(),
            effects_digest: binding.fixed.effects_commitment.clone(),
            artifact_digest: binding.fixed.proved_artifact_digest.clone(),
            review_binding: binding.fixed.review_binding.clone(),
            transport: enrollment.transport().clone(),
            input_bindings: vec![ConsentInputBinding {
                input_id: "input-alice".into(),
                action_index: 0,
                nullifier: h('a'),
                value_zatoshis: 500_000_000,
            }],
            maximum_debit_zatoshis: 400_012_000,
            fee_share_zatoshis: 12_000,
            transaction_fee_zatoshis: 30_000,
            aggregate_budget_limit_zatoshis: 1_000_000_000,
            transaction_expiry_height: proposal.manifest().expiry_height,
            wallet_key_use_policy: None,
            wallet_snapshot: WalletSnapshotBinding {
                tip_height: 2_999_900,
                tip_hash: h('d'),
                anchor_height: 2_999_900,
                anchor_hash: h('d'),
                anchor_root: h('f'),
            },
            receipt,
        };
        binding
            .validate_consent(&terms, &enrollment, &manifest)
            .unwrap();
        Self {
            binding,
            terms,
            enrollment,
            manifest,
        }
    }
    pub(super) fn evidence(&self, mapped: bool) -> OriginalAuthorizationEvidence {
        let mut terms = self.terms.clone();
        terms.durable_born_policy_v1 = mapped.then(|| self.binding.clone());
        let consent = OriginalSpendConsent::new(terms).unwrap();
        OriginalAuthorizationEvidence {
            enrollment: self.enrollment.clone(),
            manifest: self.manifest.clone(),
            release: ConsentLinkedReleaseIntent::from_consent(&consent),
            consent,
        }
    }
}

pub(super) fn rehash_original(b: &mut DurableBornPolicyBindingV1) {
    let o = &mut b.original;
    o.terms_digest = o.terms.terms_digest().unwrap();
    o.signer_native_review_digest = digest(
        "wholepact:native-born-manual-enrollment-review:v1",
        &(
            &o.terms,
            &o.genesis,
            &o.first_process_binding,
            &o.first_native_principal,
        ),
    )
    .unwrap();
    b.original_genesis_digest = o.genesis.digest().unwrap();
    b.original_enrollment_ref = o.reference().unwrap();
    let e = &mut b.original_roster_extension.account_extension;
    e.terms = o.terms.clone();
    e.enrollment_ref = b.original_enrollment_ref.clone();
    e.enrollment_record_digest = e.enrollment_ref.clone();
    b.original_extension_digest = e.digest().unwrap();
    let native = digest(
        "wholepact:native-born-manual-roster-enrollment-review:v2",
        &(&b.original, &b.original_roster_extension.roster),
    )
    .unwrap();
    let record = serde_json::json!({ "version": 2, "account_record": b.original, "roster": b.original_roster_extension.roster, "signer_roster_native_review_digest": native });
    b.original_roster_extension.signer_roster_record_digest =
        digest("wholepact:born-manual-roster-enrollment-record:v2", &record).unwrap();
    b.original_roster_extension_digest = b.original_roster_extension.digest().unwrap();
}

#[test]
fn exact_mapping_keeps_fresh_local_origin_and_advances_epoch_without_renewing_history() {
    let f = Fixture::new();
    assert_ne!(
        f.binding.original.terms.signer.writer_epoch,
        f.terms.receipt.writer_epoch()
    );
    assert_ne!(f.binding.original_enrollment_ref, f.enrollment.reference());
    assert!(f.binding.original.first_process_binding != *f.enrollment.transport());
    let original = f.evidence(true);
    let scope = witness_policy_scope(&original).unwrap();
    assert_eq!(scope.0, f.binding.original_enrollment_ref);
    assert_eq!(scope.1, f.binding.recipient_scope_digest);
    assert_eq!(
        original.original_consent().terms().enrollment_ref,
        f.enrollment.reference()
    );
    assert!(f.binding.require_current_time(200_000).is_err());
    // Historical validation never consults today's time or revives old receipts.
    f.binding
        .validate_consent(&f.terms, &f.enrollment, &f.manifest)
        .unwrap();
}

#[test]
fn mapping_substitution_and_unbounded_original_policy_are_rejected() {
    let f = Fixture::new();
    let mutations: Vec<Box<dyn Fn(&mut DurableBornPolicyBindingV1)>> = vec![
        Box::new(|b| b.original_genesis_digest = h('0')),
        Box::new(|b| b.original_enrollment_ref = h('0')),
        Box::new(|b| b.original_extension_digest = h('0')),
        Box::new(|b| b.original_roster_extension.signer_roster_record_digest = h('0')),
        Box::new(|b| b.original.first_native_principal = "substituted".into()),
        Box::new(|b| b.recipient_scope_digest = h('0')),
        Box::new(|b| b.local_enrollment_ref = h('0')),
        Box::new(|b| b.local_accepted_manifest_ref = h('0')),
        Box::new(|b| b.fixed.proposal_binding = h('0')),
        Box::new(|b| b.fixed.proved_artifact_digest = h('0')),
    ];
    for mutate in mutations {
        let mut b = f.binding.clone();
        mutate(&mut b);
        assert!(b
            .validate_consent(&f.terms, &f.enrollment, &f.manifest)
            .is_err());
    }
    let caps: Vec<Box<dyn Fn(&mut BornManualScope)>> = vec![
        Box::new(|s| s.aggregate_budget_zatoshis = 500_000_000),
        Box::new(|s| s.per_operation_limit_zatoshis = 400_011_999),
        Box::new(|s| s.maximum_fee_share_zatoshis = 11_999),
        Box::new(|s| s.maximum_transaction_fee_zatoshis = 29_999),
        Box::new(|s| s.maximum_permit_lifetime_ms = 59_999),
        Box::new(|s| s.expires_at_ms = 159_999),
        Box::new(|s| s.obligation_id = "other-obligation".into()),
        Box::new(|s| s.recipient_scope_digests = vec![h('0')]),
    ];
    for mutate in caps {
        let mut b = f.binding.clone();
        mutate(&mut b.original.terms.scope);
        rehash_original(&mut b);
        b.validate().unwrap();
        assert!(b
            .validate_consent(&f.terms, &f.enrollment, &f.manifest)
            .is_err());
    }
    let mut b = f.binding.clone();
    b.original.terms.issued_at_ms = 100_001;
    // Keep the original policy internally valid so this isolates a review
    // that predates it, rather than failing the source policy codec first.
    b.original.terms.scope.maximum_permit_lifetime_ms = 60_000;
    rehash_original(&mut b);
    assert!(b
        .validate_consent(&f.terms, &f.enrollment, &f.manifest)
        .is_err());
}

#[test]
fn substituted_current_account_participant_and_transport_or_old_native_origin_fail() {
    let f = Fixture::new();
    for field in ["account", "participant", "transport", "origin"] {
        let mut e = f.enrollment.clone();
        match field {
            "account" => e.terms.account_id = h('0'),
            "participant" => e.terms.participant_id = "bob".into(),
            "transport" => {
                if let TransportIdentityBinding::LocalProcess { pid, .. } = &mut e.terms.transport {
                    *pid += 1;
                }
            }
            _ => e.terms.receipt.native_session_id = h('0'),
        }
        e.reference = digest("wholepact:signer-account-enrollment:v1", &e.terms).unwrap();
        assert!(f
            .binding
            .validate_consent(&f.terms, &e, &f.manifest)
            .is_err());
    }
    let mut t = f.terms.clone();
    t.receipt.native_session_id = h('0');
    assert!(f
        .binding
        .validate_consent(&t, &f.enrollment, &f.manifest)
        .is_err());
}

#[test]
fn exact_payment_scope_includes_return_outputs_and_all_charges() {
    let f = Fixture::new();
    let mut p = f.manifest.proposal().unwrap().input().clone();
    p.manifest.outputs[1].address = "usubstitutedreturn".into();
    let altered = Proposal::validate(p).unwrap();
    assert_ne!(
        wholepact_core::manual_construction::construction_recipient_scope_digest(&altered).unwrap(),
        f.binding.recipient_scope_digest
    );
}

#[test]
fn none_is_omitted_with_unchanged_legacy_hash_and_mapping_is_hash_committed() {
    let f = Fixture::new();
    let old = f.evidence(false);
    let raw = serde_json::to_value(&f.terms).unwrap();
    assert!(raw.get("durable_born_policy_v1").is_none());
    let historical: SpendConsentTerms = serde_json::from_value(raw.clone()).unwrap();
    assert!(historical.durable_born_policy_v1.is_none());
    assert_eq!(serde_json::to_value(&historical).unwrap(), raw);
    assert_eq!(
        old.consent.reference(),
        digest("wholepact:signer-original-spend-consent:v1", &raw).unwrap()
    );
    let mapped = f.evidence(true);
    assert_ne!(old.consent.reference(), mapped.consent.reference());
    let mut added_after_approval = old.consent.clone();
    added_after_approval.terms.durable_born_policy_v1 = Some(f.binding.clone());
    assert!(added_after_approval.validate().is_err());
    let mut removed_after_approval = mapped.consent;
    removed_after_approval.terms.durable_born_policy_v1 = None;
    assert!(removed_after_approval.validate().is_err());
    let mut unknown = serde_json::to_value(&f.binding).unwrap();
    unknown["allow_current_owner"] = true.into();
    assert!(serde_json::from_value::<DurableBornPolicyBindingV1>(unknown).is_err());
}

#[test]
fn one_request_mapping_is_used_by_retained_validation_and_history() {
    use crate::authority_bridge::protocol::{
        AuthorizationDeliveryScope, RetainedAuthorizationRequest,
    };
    let f = Fixture::new();
    let original = f.evidence(true);
    let request = RetainedAuthorizationRequest::from_original(
        &original,
        b"synthetic-fixed-artifact",
        wholepact_authority::AuthorityHead {
            sequence: 1,
            digest: h('a'),
        },
        AuthorizationDeliveryScope {
            candidate_id: "proposal-a".into(),
        },
    )
    .unwrap();
    request.validate_original(&original).unwrap();
    assert_eq!(
        request.reservation.enrollment_ref,
        f.binding.original_enrollment_ref
    );
    assert_eq!(
        request.reservation.recipient_scope_digest,
        f.binding.recipient_scope_digest
    );
    let mut changed = request.clone();
    changed.reservation.enrollment_ref = f.enrollment.reference().into();
    assert!(changed.validate_original(&original).is_err());
    let mut changed = request.clone();
    changed.reservation.recipient_scope_digest =
        witness_policy_scope(&f.evidence(false)).unwrap().1;
    assert!(changed.validate_original(&original).is_err());
    let mut changed = request.clone();
    changed.reservation.permit_expires_at_ms += 1;
    assert!(changed.validate_original(&original).is_err());
}

#[test]
fn retained_mapping_requires_actual_journal_genesis() {
    let f = Fixture::new();
    let dir = private_dir();
    let key = wholepact_storage_security::DatabaseKey::from_bytes([0x43; 32]);
    let private_directory = crate::files::PrivateDirectory::open(dir.path()).unwrap();
    let journal = SignerConsentJournal::create_encrypted(
        &dir.path().join("source.sqlite"),
        &key,
        &h('1'),
        7,
        false,
        &private_directory
            .signer_journal_source_owner_for_test(&dir.path().join("source.sqlite"))
            .unwrap(),
    )
    .unwrap();
    let c = journal.connection.lock().unwrap();
    let original = f.evidence(true);
    assert!(validate_retained_original(&c, &original).is_err());
    let g = &f.binding.original.genesis;
    c.execute(
        "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
        rusqlite::params![
            g.identity.account_id,
            g.identity.full_viewing_key_digest,
            g.digest().unwrap(),
            serde_json::to_string(g).unwrap()
        ],
    )
    .unwrap();
    validate_retained_original(&c, &original).unwrap();
    let mut changed = g.clone();
    changed.witness_id = "substituted-witness".into();
    // The maintained immutable-origin trigger must remain enforced.
    assert!(c
        .execute(
            "UPDATE signer_account_use_genesis SET genesis_digest=?1,payload=?2",
            rusqlite::params![
                changed.digest().unwrap(),
                serde_json::to_string(&changed).unwrap()
            ],
        )
        .is_err());
    validate_retained_original(&c, &original).unwrap();

    // A separately created valid original journal is not this retained source,
    // even when it deliberately shares the synthetic account label and FVK.
    let other_dir = private_dir();
    let other_key = wholepact_storage_security::DatabaseKey::from_bytes([0x45; 32]);
    let other_private_directory = crate::files::PrivateDirectory::open(other_dir.path()).unwrap();
    let other = SignerConsentJournal::create_encrypted(
        &other_dir.path().join("other-source.sqlite"),
        &other_key,
        &h('1'),
        7,
        false,
        &other_private_directory
            .signer_journal_source_owner_for_test(&other_dir.path().join("other-source.sqlite"))
            .unwrap(),
    )
    .unwrap();
    let other_c = other.connection.lock().unwrap();
    other_c
        .execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            rusqlite::params![
                changed.identity.account_id,
                changed.identity.full_viewing_key_digest,
                changed.digest().unwrap(),
                serde_json::to_string(&changed).unwrap()
            ],
        )
        .unwrap();
    assert!(validate_retained_original(&other_c, &original).is_err());
}

#[test]
fn generic_release_refuses_bound_consent_without_creating_exposure() {
    let f = Fixture::new();
    let dir = private_dir();
    let key = wholepact_storage_security::DatabaseKey::from_bytes([0x44; 32]);
    let private_directory = crate::files::PrivateDirectory::open(dir.path()).unwrap();
    let journal = SignerConsentJournal::create_encrypted(
        &dir.path().join("source.sqlite"),
        &key,
        &h('1'),
        7,
        false,
        &private_directory
            .signer_journal_source_owner_for_test(&dir.path().join("source.sqlite"))
            .unwrap(),
    )
    .unwrap();
    let session = authority::fixture::session(&journal, "fresh-native-owner");
    let original = f.evidence(true);
    let approved = authority::fixture::exact_spend(&session, original.consent);
    assert!(journal.record_original_consent_release(approved).is_err());
    let c = journal.connection.lock().unwrap();
    let counts: (u64,u64,u64) = c.query_row("SELECT (SELECT count(*) FROM signer_original_consents),(SELECT count(*) FROM signer_release_intents),(SELECT count(*) FROM signer_input_reservations)", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(counts, (0, 0, 0));
}

#[cfg(all(
    feature = "durable-proposal",
    feature = "native-ui",
    target_os = "linux"
))]
#[test]
fn pure_actual_source_comparison_rejects_self_consistent_forged_source_and_fixed_identity() {
    use crate::account::birth::enrollment::roster_v2::BornManualRosterEnrollmentRecordV2;
    let f = Fixture::new();
    let native = digest(
        "wholepact:native-born-manual-roster-enrollment-review:v2",
        &(
            &f.binding.original,
            &f.binding.original_roster_extension.roster,
        ),
    )
    .unwrap();
    let source: BornManualRosterEnrollmentRecordV2 = serde_json::from_value(serde_json::json!({"version":2,"account_record":f.binding.original,"roster":f.binding.original_roster_extension.roster,"signer_roster_native_review_digest":native})).unwrap();
    f.binding
        .validate_original_source(&source, &source.account_record.genesis)
        .unwrap();
    let fixed = serde_json::from_value(serde_json::to_value(&f.binding.fixed).unwrap()).unwrap();
    f.binding.require_fixed_identity(&fixed).unwrap();
    let mut forged = f.binding.clone();
    forged.original.first_native_principal = "forged-original-principal".into();
    rehash_original(&mut forged);
    forged.validate().unwrap();
    assert!(forged
        .validate_original_source(&source, &source.account_record.genesis)
        .is_err());
    let mut fixed = fixed;
    fixed.action_mapping_digest = h('0');
    assert!(f.binding.require_fixed_identity(&fixed).is_err());
    let derived = DurableBornPolicyBindingV1::from_original_source(
        &source,
        &f.enrollment,
        &f.manifest,
        &serde_json::from_value(serde_json::to_value(&f.binding.fixed).unwrap()).unwrap(),
    )
    .unwrap();
    assert!(derived == f.binding);
}
