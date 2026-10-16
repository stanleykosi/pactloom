//! Every issuer, account label and key here is isolated fabricated test data.
//! These tests exercise durable provenance, not production human authentication.
use super::{authority::fixture::*, *};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_core::*;
use wholepact_storage_security::{bundle::*, DatabaseKey, StorageSecurityError};

fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
pub(super) fn proposal(agreement: &str, obligation: &str, proposal_id: &str) -> Proposal {
    let mut agreement_data: AgreementDraft = parse_typed_json(include_bytes!(
        "../../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    agreement_data.agreement_id = agreement.into();
    agreement_data.obligation_id = obligation.into();
    Proposal::validate(ProposalInput {
        proposal_id: proposal_id.into(),
        previous_proposal_id: None,
        artifact_digest: Some("ac".repeat(32)),
        effects_commitment: Some("ef".repeat(32)),
        created_at: "2026-10-14T00:00:00Z".into(),
        manifest: ProposalManifest {
            agreement: agreement_data.clone(),
            participants: vec![
                ParticipantAllocation {
                    participant_id: "alice".into(),
                    account_id: "account-alice".into(),
                    contribution: amount(400_000_000),
                    fee_share: amount(12_000),
                    fee_cap: amount(12_000),
                    maximum_net_debit: amount(400_012_000),
                    charges: vec![],
                },
                ParticipantAllocation {
                    participant_id: "bob".into(),
                    account_id: "account-bob".into(),
                    contribution: amount(600_000_000),
                    fee_share: amount(18_000),
                    fee_cap: amount(18_000),
                    maximum_net_debit: amount(600_018_000),
                    charges: vec![],
                },
            ],
            inputs: vec![
                ClaimedInput {
                    input_id: "input-alice".into(),
                    participant_id: "alice".into(),
                    account_id: "account-alice".into(),
                    amount: amount(500_000_000),
                    ownership_evidence_ref: None,
                },
                ClaimedInput {
                    input_id: "input-bob".into(),
                    participant_id: "bob".into(),
                    account_id: "account-bob".into(),
                    amount: amount(700_000_000),
                    ownership_evidence_ref: None,
                },
            ],
            outputs: vec![
                ClaimedOutput {
                    output_id: "recipient".into(),
                    address: agreement_data.recipients[0].address.clone(),
                    amount: amount(1_000_000_000),
                    allocation: OutputAllocation::Recipient {
                        recipient_id: agreement_data.recipients[0].recipient_id.clone(),
                    },
                },
                ClaimedOutput {
                    output_id: "alice-return".into(),
                    address: "usyntheticreturnalice".into(),
                    amount: amount(99_988_000),
                    allocation: OutputAllocation::Return {
                        participant_id: "alice".into(),
                        account_id: "account-alice".into(),
                        ownership_evidence_ref: None,
                    },
                },
                ClaimedOutput {
                    output_id: "bob-return".into(),
                    address: "usyntheticreturnbob".into(),
                    amount: amount(99_982_000),
                    allocation: OutputAllocation::Return {
                        participant_id: "bob".into(),
                        account_id: "account-bob".into(),
                        ownership_evidence_ref: None,
                    },
                },
            ],
            transaction_fee: amount(30_000),
            expiry_height: 3_000_000,
        },
    })
    .unwrap()
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
struct Fixture {
    dir: tempfile::TempDir,
    key: DatabaseKey,
    journal: SignerConsentJournal,
    session: SignerConsentSession,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
}
impl Fixture {
    fn new() -> Self {
        let dir = private_dir();
        let key = DatabaseKey::from_bytes([71; 32]);
        let journal = SignerConsentJournal::create_encrypted(
            &dir.path().join("signer"),
            &key,
            "account-alice",
            1,
            false,
        )
        .unwrap();
        let session = session(&journal, "synthetic-owner");
        let (enrollment, manifest) = enroll(
            &journal,
            &session,
            &proposal("agreement-a", "obligation-a", "proposal-a"),
            1_000_000_000,
        );
        Self {
            dir,
            key,
            journal,
            session,
            enrollment,
            manifest,
        }
    }
    pub(super) fn terms(&self) -> SpendConsentTerms {
        terms(
            &self.session,
            &self.enrollment,
            &self.manifest,
            "authorization-a",
        )
    }
    fn counts(&self) -> (u64, u64, u64) {
        self.journal.connection.lock().unwrap().query_row("SELECT (SELECT count(*) FROM signer_original_consents),(SELECT count(*) FROM signer_release_intents),(SELECT count(*) FROM signer_input_reservations)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
    }
}
pub(super) fn enroll(
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    p: &Proposal,
    budget: u64,
) -> (AccountEnrollmentRecord, AcceptedManifestRecord) {
    let enrollment = journal
        .record_enrollment(approve_enrollment(
            session,
            EnrollmentTerms {
                account_id: "account-alice".into(),
                agreement_id: p.manifest().agreement.agreement_id.clone(),
                participant_id: "alice".into(),
                principal_id: "synthetic-owner".into(),
                network_profile_id: p.manifest().agreement.network_profile_id.clone(),
                privacy_domain: "synthetic-domain".into(),
                account_fvk_digest: "fa".repeat(32),
                transport: TransportIdentityBinding::RemoteAuthenticatedKeys {
                    transport_identity_id: "synthetic-transport".into(),
                    sender_key_digest: "a1".repeat(32),
                    recipient_key_digest: "b2".repeat(32),
                    channel_binding_digest: "c3".repeat(32),
                },
                aggregate_budget_limit_zatoshis: budget,
                receipt: receipt(session),
            },
        ))
        .unwrap();
    let prepared = session.prepare_manifest(&enrollment, p).unwrap();
    let approval = decision(session, prepared.review_digest());
    let manifest = journal
        .record_accepted_manifest(session.approve_manifest(prepared, approval).unwrap())
        .unwrap();
    (enrollment, manifest)
}
pub(super) fn terms(
    session: &SignerConsentSession,
    e: &AccountEnrollmentRecord,
    m: &AcceptedManifestRecord,
    authorization: &str,
) -> SpendConsentTerms {
    SpendConsentTerms {
        automation: None,
        sponsor_policy: None,
        sponsor_owner_attestation_digest: None,
        authorization_id: authorization.into(),
        enrollment_ref: e.reference.clone(),
        accepted_manifest_ref: m.reference.clone(),
        account_id: e.terms.account_id.clone(),
        principal_id: e.terms.principal_id.clone(),
        agreement_id: e.terms.agreement_id.clone(),
        obligation_id: m.terms.proposal.manifest.agreement.obligation_id.clone(),
        proposal_id: m.terms.proposal.proposal_id.clone(),
        proposal_digest: m.terms.proposal_digest.clone(),
        manifest_digest: m.terms.manifest_digest.clone(),
        effects_digest: "ef".repeat(32),
        artifact_digest: "ac".repeat(32),
        review_binding: "b1".repeat(32),
        transport: e.terms.transport.clone(),
        input_bindings: vec![ConsentInputBinding {
            input_id: "input-alice".into(),
            action_index: 0,
            nullifier: "a0".repeat(32),
            value_zatoshis: 500_000_000,
        }],
        maximum_debit_zatoshis: 400_012_000,
        fee_share_zatoshis: 12_000,
        transaction_fee_zatoshis: 30_000,
        aggregate_budget_limit_zatoshis: e.budget_limit_zatoshis(),
        transaction_expiry_height: 3_000_000,
        wallet_key_use_policy: None,
        wallet_snapshot: WalletSnapshotBinding {
            tip_height: 2_999_900,
            tip_hash: "d0".repeat(32),
            anchor_height: 2_999_900,
            anchor_hash: "d0".repeat(32),
            anchor_root: "e0".repeat(32),
        },
        receipt: receipt(session),
    }
}
#[test]
fn immutable_original_reference_and_exact_release_survive_encrypted_reopen() {
    let f = Fixture::new();
    let approved = approve_spend(&f.session, f.terms());
    let exact = approved.0.record.clone();
    let evidence = f.journal.record_original_consent_release(approved).unwrap();
    assert_eq!(evidence.original_consent().reference(), exact.reference());
    assert_eq!(
        evidence.release_intent().original_consent_ref(),
        exact.reference()
    );
    assert_eq!(
        evidence.release_intent().intent().input_ids,
        vec!["a0".repeat(32)]
    );
    assert!(evidence.exposure_is_uncertain());
    let replay = f
        .journal
        .record_original_consent_release(exact_spend(&f.session, exact))
        .unwrap();
    assert!(replay == evidence);
    assert_eq!(f.counts(), (1, 1, 1));
    assert!(f
        .journal
        .record_original_consent_release(approve_spend(&f.session, f.terms()))
        .is_err());
    drop(f.session);
    drop(f.journal);
    let raw = std::fs::read(f.dir.path().join("signer")).unwrap();
    assert!(!raw.starts_with(b"SQLite format 3"));
    for canary in [
        "account-alice",
        "synthetic-owner",
        "obligation-a",
        evidence.original_consent().reference(),
    ] {
        assert!(!raw.windows(canary.len()).any(|w| w == canary.as_bytes()));
    }
    assert!(SignerConsentJournal::open_encrypted(
        &f.dir.path().join("signer"),
        &DatabaseKey::from_bytes([72; 32]),
        "account-alice"
    )
    .is_err());
    let reopened =
        SignerConsentJournal::open_encrypted(&f.dir.path().join("signer"), &f.key, "account-alice")
            .unwrap();
    let session = session(&reopened, "synthetic-owner");
    assert!(
        reopened
            .original_authorization("authorization-a", &session)
            .unwrap()
            .unwrap()
            == evidence
    );
}
#[test]
fn consent_release_and_reservations_are_one_abortable_transaction() {
    let f = Fixture::new();
    f.journal.connection.lock().unwrap().execute_batch("CREATE TRIGGER test_abort BEFORE INSERT ON signer_release_intents BEGIN SELECT RAISE(ABORT,'synthetic commit fault'); END;").unwrap();
    assert!(f
        .journal
        .record_original_consent_release(approve_spend(&f.session, f.terms()))
        .is_err());
    assert_eq!(f.counts(), (0, 0, 0));
    f.journal
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER test_abort;")
        .unwrap();
    f.journal
        .record_original_consent_release(approve_spend(&f.session, f.terms()))
        .unwrap();
    assert_eq!(f.counts(), (1, 1, 1));
}
#[test]
fn native_revocation_source_replacement_expiry_and_owner_reads_fail_closed() {
    let f = Fixture::new();
    let base = f.terms();
    let approved = approve_spend(&f.session, base.clone());
    f.session.invalidate().unwrap();
    assert!(matches!(
        f.journal.record_original_consent_release(approved),
        Err(JournalError::Permission)
    ));
    let s = session(&f.journal, "synthetic-owner");
    let approved = approve_spend(&s, base.clone());
    drop(s);
    assert!(matches!(
        f.journal.record_original_consent_release(approved),
        Err(JournalError::Permission)
    ));
    let other = Fixture::new();
    assert!(matches!(
        f.journal
            .record_original_consent_release(approve_spend(&other.session, other.terms())),
        Err(JournalError::Permission)
    ));
    let s = session(&f.journal, "synthetic-owner");
    let mut t = base;
    t.receipt = receipt(&s);
    t.receipt.reviewed_at_ms -= 180_000;
    t.receipt.expires_at_ms -= 180_000;
    let stale = OriginalSpendConsent::new(t).unwrap();
    assert!(matches!(
        f.journal
            .record_original_consent_release(exact_spend(&s, stale)),
        Err(JournalError::Expired)
    ));
    let stranger = session(&f.journal, "other-owner");
    assert!(matches!(
        f.journal.enrollment(f.enrollment.reference(), &stranger),
        Err(JournalError::Permission)
    ));
    assert_eq!(f.counts(), (0, 0, 0));
}
#[test]
fn every_original_scope_and_value_substitution_is_rejected_without_writes() {
    let f = Fixture::new();
    type Mutation = Box<dyn Fn(&mut SpendConsentTerms)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|t| t.account_id = "other-account".into()),
        Box::new(|t| t.principal_id = "other-owner".into()),
        Box::new(|t| t.agreement_id = "other-agreement".into()),
        Box::new(|t| t.obligation_id = "other-obligation".into()),
        Box::new(|t| t.proposal_id = "other-proposal".into()),
        Box::new(|t| t.proposal_digest = "01".repeat(32)),
        Box::new(|t| t.manifest_digest = "02".repeat(32)),
        Box::new(|t| t.effects_digest = "03".repeat(32)),
        Box::new(|t| t.artifact_digest = "04".repeat(32)),
        Box::new(|t| {
            if let TransportIdentityBinding::RemoteAuthenticatedKeys {
                sender_key_digest, ..
            } = &mut t.transport
            {
                *sender_key_digest = "05".repeat(32);
            }
        }),
        Box::new(|t| {
            if let TransportIdentityBinding::RemoteAuthenticatedKeys {
                recipient_key_digest,
                ..
            } = &mut t.transport
            {
                *recipient_key_digest = "06".repeat(32);
            }
        }),
        Box::new(|t| {
            if let TransportIdentityBinding::RemoteAuthenticatedKeys {
                channel_binding_digest,
                ..
            } = &mut t.transport
            {
                *channel_binding_digest = "07".repeat(32);
            }
        }),
        Box::new(|t| t.input_bindings[0].input_id = "other-input".into()),
        Box::new(|t| t.input_bindings[0].value_zatoshis += 1),
        Box::new(|t| t.maximum_debit_zatoshis -= 1),
        Box::new(|t| t.fee_share_zatoshis += 1),
        Box::new(|t| t.transaction_fee_zatoshis += 1),
        Box::new(|t| t.aggregate_budget_limit_zatoshis += 1),
        Box::new(|t| t.transaction_expiry_height += 1),
    ];
    for mutate in mutations {
        let mut t = f.terms();
        mutate(&mut t);
        assert!(f
            .journal
            .record_original_consent_release(approve_spend(&f.session, t))
            .is_err());
        assert_eq!(f.counts(), (0, 0, 0));
    }
}
#[test]
fn retained_native_decision_binds_nonce_epoch_review_and_cannot_be_replaced() {
    let f = Fixture::new();
    let approved = approve_spend(&f.session, f.terms());
    let original = approved.0.record.clone();
    f.journal.record_original_consent_release(approved).unwrap();
    for field in 0..5 {
        let mut t = original.terms.clone();
        match field {
            0 => t.review_binding = "11".repeat(32),
            1 => t.input_bindings[0].nullifier = "22".repeat(32),
            2 => t.receipt.nonce = "33".repeat(32),
            3 => t.receipt.writer_epoch += 1,
            _ => t.wallet_snapshot.tip_hash = "44".repeat(32),
        };
        let changed = OriginalSpendConsent::new(t).unwrap();
        assert!(f
            .journal
            .record_original_consent_release(exact_spend(&f.session, changed))
            .is_err());
    }
    assert_eq!(f.counts(), (1, 1, 1));
    let c = f.journal.connection.lock().unwrap();
    for table in [
        "signer_enrollments",
        "signer_accepted_manifests",
        "signer_original_consents",
        "signer_release_intents",
    ] {
        assert!(c.execute(&format!("DELETE FROM {table}"), []).is_err());
    }
    assert!(c
        .execute("UPDATE signer_original_consents SET payload='{}'", [])
        .is_err());
}
#[test]
fn outstanding_obligations_inputs_and_aggregate_budget_remain_reserved() {
    let f = Fixture::new();
    f.journal
        .record_original_consent_release(approve_spend(&f.session, f.terms()))
        .unwrap();
    let mut t = f.terms();
    t.authorization_id = "second-authorization".into();
    assert!(matches!(
        f.journal
            .record_original_consent_release(approve_spend(&f.session, t)),
        Err(JournalError::LiveAuthorization)
    ));
    let (e, m) = enroll(
        &f.journal,
        &f.session,
        &proposal("agreement-b", "obligation-b", "proposal-b"),
        1_000_000_000,
    );
    let mut t = terms(&f.session, &e, &m, "authorization-b");
    assert!(matches!(
        f.journal
            .record_original_consent_release(approve_spend(&f.session, t.clone())),
        Err(JournalError::InputReserved)
    ));
    t.input_bindings[0].nullifier = "a1".repeat(32);
    f.journal
        .record_original_consent_release(approve_spend(&f.session, t))
        .unwrap();
    let (e, m) = enroll(
        &f.journal,
        &f.session,
        &proposal("agreement-c", "obligation-c", "proposal-c"),
        1_000_000_000,
    );
    let mut t = terms(&f.session, &e, &m, "authorization-c");
    t.input_bindings[0].nullifier = "a2".repeat(32);
    assert!(matches!(
        f.journal
            .record_original_consent_release(approve_spend(&f.session, t)),
        Err(JournalError::BudgetExceeded)
    ));
    assert_eq!(f.counts(), (2, 2, 2));
}
#[test]
fn wrong_schema_interrupted_initialization_and_restored_account_never_reinitialize() {
    let dir = private_dir();
    let key = DatabaseKey::from_bytes([73; 32]);
    let path = dir.path().join("legacy");
    let legacy = wholepact_store::Store::create_encrypted(&path, &key).unwrap();
    drop(legacy);
    assert!(matches!(
        SignerConsentJournal::open_encrypted(&path, &key, "account-alice"),
        Err(JournalError::UnsupportedSchema)
    ));
    let incomplete = dir.path().join("interrupted");
    drop(wholepact_storage_security::create_encrypted(&incomplete, &key).unwrap());
    assert!(matches!(
        SignerConsentJournal::open_encrypted(&incomplete, &key, "account-alice"),
        Err(JournalError::Storage(
            StorageSecurityError::UninitializedDatabase
        ))
    ));
    let f = Fixture::new();
    let approved = approve_spend(&f.session, f.terms());
    f.journal.require_recovery().unwrap();
    assert!(matches!(
        f.journal.record_original_consent_release(approved),
        Err(JournalError::RecoveryRequired)
    ));
    assert!(f.journal.account_state().unwrap().recovery_required);
    drop(f.session);
    drop(f.journal);
    assert!(
        SignerConsentJournal::open_encrypted(&f.dir.path().join("signer"), &f.key, "account-alice")
            .unwrap()
            .account_state()
            .unwrap()
            .recovery_required
    );
}
pub(super) struct BackupGate;
struct BackupLease;
impl BundleLease for BackupLease {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "synthetic-signer-checkpoint"
    }
}
impl BundleAuthority for BackupGate {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.principal_id != "synthetic-owner"
            || scope.profile_id != "synthetic-signer-profile"
            || scope.wallet_spending_secrets_included
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(BackupLease))
    }
}
#[test]
fn typed_signer_bundle_inventory_roundtrip_always_restores_to_quarantine() {
    let mut f = Fixture::new();
    f.journal
        .record_original_consent_release(approve_spend(&f.session, f.terms()))
        .unwrap();
    let original = f
        .journal
        .original_authorization("authorization-a", &f.session)
        .unwrap()
        .unwrap();
    let before = storage::capacity_estimate(&f.journal.connection.lock().unwrap()).unwrap();
    {
        let c = f.journal.connection.lock().unwrap();
        // Isolated storage fixture: every v3 bridge table and escaped TEXT cell
        // participates in the actual encrypted backup and quarantine roundtrip.
        c.execute(
            "INSERT INTO signer_bridge_requests VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                "authorization-a",
                original.original_consent().reference(),
                "synthetic\n\t\"metadata",
                "ac".repeat(1024)
            ],
        )
        .unwrap();
        c.execute(
            "INSERT INTO signer_bridge_permits VALUES(?1,?2)",
            rusqlite::params!["authorization-a", "synthetic-permit"],
        )
        .unwrap();
        c.execute(
            "INSERT INTO signer_bridge_keyuse VALUES(?1)",
            ["authorization-a"],
        )
        .unwrap();
        c.execute(
            "INSERT INTO signer_bridge_results VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                "authorization-a",
                "d1".repeat(32),
                "ab".repeat(1024),
                "synthetic original outbox\n"
            ],
        )
        .unwrap();
    }
    let admitted = storage::capacity_estimate(&f.journal.connection.lock().unwrap()).unwrap();
    assert_eq!(admitted.0, before.0 + 4);
    assert!(admitted.1 > before.1 + 4 * 1024);
    f.journal.capacity_limits = admitted; // exact reduced admission boundary
    let adapter = f.journal.backup_adapter();
    let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
    let coverage = Coverage {
        present: BTreeMap::from([(
            JournalKind::SignerConsentAuthority,
            vec!["signer-authority".into()],
        )]),
        absent: BTreeSet::from([
            JournalKind::CoordinationAuthority,
            JournalKind::WalletScan,
            JournalKind::ProofWitness,
            JournalKind::SignedResults,
            JournalKind::ExactTransactions,
            JournalKind::Submission,
            JournalKind::TransportInbox,
            JournalKind::TransportOutbox,
        ]),
    };
    let archive = f.dir.path().join("archive");
    let backup_key = DatabaseKey::from_bytes([74; 32]);
    let restored_key = DatabaseKey::from_bytes([75; 32]);
    let restored = f.dir.path().join("restored");
    let manifest = snapshot(SnapshotRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        coverage,
        sources: &sources,
        destination: &archive,
        key: &backup_key,
        authority: &BackupGate,
    })
    .unwrap();
    assert_eq!(manifest.components.len(), 1);
    assert_eq!(manifest.components[0].rows as u64, admitted.0);
    assert!(manifest.components[0].logical_bytes as u64 + BACKUP_METADATA_RESERVE <= admitted.1);
    assert!(admitted.1 <= MAX_BACKUP_ENCODED_BYTES);
    let report = test_restore(RestoreRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        archive: &archive,
        key: &backup_key,
        targets: &[RestoreTarget {
            component_id: "signer-authority",
            template: SignerConsentBundleAdapter::template(),
            destination: &restored,
            key: &restored_key,
        }],
        authority: &BackupGate,
    })
    .unwrap();
    assert!(!report.authorization_allowed);
    assert!(matches!(
        SignerConsentJournal::open_encrypted(&restored, &restored_key, "account-alice"),
        Err(JournalError::Storage(
            StorageSecurityError::QuarantinedDatabase
        ))
    ));
}

#[cfg(feature = "synthetic-qualification")]
#[test]
fn maintained_pczt_review_prepares_exact_consent_and_rejects_artifact_substitution() {
    use sha2::{Digest, Sha256};
    let (accepted, inputs, bytes) = crate::manifest::tests::consent_fixture();
    let account_id = inputs.policy.participants[0].account_id.clone();
    let fvk_digest = hex::encode(Sha256::digest(inputs.policy.participants[0].fvk.to_bytes()));
    let dir = private_dir();
    let key = DatabaseKey::from_bytes([79; 32]);
    let journal = SignerConsentJournal::create_encrypted(
        &dir.path().join("signer"),
        &key,
        &account_id,
        1,
        false,
    )
    .unwrap();
    let s = session(&journal, "synthetic-owner");
    let e = journal
        .record_enrollment(approve_enrollment(
            &s,
            EnrollmentTerms {
                account_id,
                agreement_id: accepted.proposal.manifest().agreement.agreement_id.clone(),
                participant_id: "participant-0".into(),
                principal_id: "synthetic-owner".into(),
                network_profile_id: accepted
                    .proposal
                    .manifest()
                    .agreement
                    .network_profile_id
                    .clone(),
                privacy_domain: "synthetic-only".into(),
                account_fvk_digest: fvk_digest,
                transport: TransportIdentityBinding::RemoteAuthenticatedKeys {
                    transport_identity_id: "synthetic-transport".into(),
                    sender_key_digest: "a1".repeat(32),
                    recipient_key_digest: "b2".repeat(32),
                    channel_binding_digest: "c3".repeat(32),
                },
                aggregate_budget_limit_zatoshis: 1_000_000,
                receipt: receipt(&s),
            },
        ))
        .unwrap();
    let prepared = s.prepare_manifest(&e, &accepted.proposal).unwrap();
    let native = decision(&s, prepared.review_digest());
    let m = journal
        .record_accepted_manifest(s.approve_manifest(prepared, native).unwrap())
        .unwrap();
    let expected_roster: Vec<_> = inputs.policy.participants.iter().map(|p| (p.account_id.clone(),hex::encode(Sha256::digest(p.fvk.to_bytes())))).collect();
    let prepared = prepare_synthetic_spend(&s, &e, &m, &bytes, inputs).unwrap();
    assert_eq!(prepared.reviewed_owner_fvks().unwrap(),expected_roster.as_slice());
    assert_eq!(
        prepared.record().terms().artifact_digest,
        hex::encode(Sha256::digest(&bytes))
    );
    assert_eq!(prepared.record().terms().maximum_debit_zatoshis, 105_000);
    assert_eq!(prepared.record().terms().fee_share_zatoshis, 5_000);
    assert_eq!(prepared.record().terms().transaction_fee_zatoshis, 15_000);
    let native = decision(&s, prepared.review_digest());
    let original = journal
        .record_original_consent_release(s.approve_spend(prepared, native).unwrap())
        .unwrap();
    assert_eq!(original.original_consent().terms().review_binding.len(), 64);
    let (_, inputs, mut bytes) = crate::manifest::tests::consent_fixture();
    bytes.truncate(bytes.len() - 1);
    assert!(prepare_synthetic_spend(&s, &e, &m, &bytes, inputs).is_err());
}

#[test]
fn full_backup_row_and_variable_byte_admission_rolls_back_the_entire_append() {
    let mut f = Fixture::new();
    let before = storage::capacity_estimate(&f.journal.connection.lock().unwrap()).unwrap();
    assert_eq!(before.0, 3); // account + enrollment + accepted manifest
                             // This append requires consent + release + reservation, not just consent.
    f.journal.capacity_limits = (before.0 + 2, MAX_BACKUP_ENCODED_BYTES);
    assert!(matches!(
        f.journal
            .record_original_consent_release(approve_spend(&f.session, f.terms())),
        Err(JournalError::Limit)
    ));
    assert_eq!(f.counts(), (0, 0, 0));
    assert_eq!(
        storage::capacity_estimate(&f.journal.connection.lock().unwrap()).unwrap(),
        before
    );
    // Variable-size payloads independently consume the encoded-byte envelope.
    f.journal.capacity_limits = (MAX_BACKUP_ROWS, before.1 + 1);
    assert!(matches!(
        f.journal
            .record_original_consent_release(approve_spend(&f.session, f.terms())),
        Err(JournalError::Limit)
    ));
    assert_eq!(f.counts(), (0, 0, 0));
    assert_eq!(
        storage::capacity_estimate(&f.journal.connection.lock().unwrap()).unwrap(),
        before
    );
    f.journal.capacity_limits = (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES);
    let approved = approve_spend(&f.session, f.terms());
    let exact = approved.0.record.clone();
    f.journal.record_original_consent_release(approved).unwrap();
    let after = storage::capacity_estimate(&f.journal.connection.lock().unwrap()).unwrap();
    assert_eq!(after.0, before.0 + 3);
    assert!(after.1 > before.1);
    f.journal.capacity_limits = after;
    assert!(f
        .journal
        .record_original_consent_release(exact_spend(&f.session, exact))
        .is_ok());
    assert_eq!(f.counts(), (1, 1, 1));
}

#[test]
fn held_permission_lease_serializes_concurrent_revocation_through_handoff() {
    let f = Fixture::new();
    let approved = approve_spend(&f.session, f.terms());
    exercise_held_lease_revocation(&f.journal, &f.session, &approved);
    assert!(matches!(
        f.journal.record_original_consent_release(approved),
        Err(JournalError::Permission)
    ));
    assert_eq!(f.counts(), (0, 0, 0));
}

#[test]
fn explicit_repairing_appends_immutable_enrollment_and_never_reauthorizes_old_session() {
    let f = Fixture::new();
    let original = f
        .journal
        .record_original_consent_release(approve_spend(&f.session, f.terms()))
        .unwrap();
    let next = session(&f.journal, "synthetic-owner");
    let p = proposal("agreement-a", "obligation-a", "proposal-a");
    assert!(matches!(
        next.prepare_manifest(&f.enrollment, &p),
        Err(JournalError::Permission)
    ));
    let mut rotated = f.enrollment.terms.clone();
    if let TransportIdentityBinding::RemoteAuthenticatedKeys {
        sender_key_digest, ..
    } = &mut rotated.transport
    {
        *sender_key_digest = "d4".repeat(32);
    }
    let e = f
        .journal
        .record_enrollment(approve_enrollment(&next, rotated))
        .unwrap();
    assert_ne!(e.reference(), f.enrollment.reference());
    assert!(
        f.journal
            .enrollment(f.enrollment.reference(), &next)
            .unwrap()
            .unwrap()
            == f.enrollment
    );
    assert!(matches!(
        f.session.prepare_manifest(&e, &p),
        Err(JournalError::Permission)
    ));
    let prepared = next.prepare_manifest(&e, &p).unwrap();
    let native = decision(&next, prepared.review_digest());
    let m = f
        .journal
        .record_accepted_manifest(next.approve_manifest(prepared, native).unwrap())
        .unwrap();
    assert_ne!(m.reference(), f.manifest.reference());
    let t = terms(&next, &e, &m, "new-session-authorization");
    assert!(matches!(
        f.journal
            .record_original_consent_release(approve_spend(&next, t)),
        Err(JournalError::LiveAuthorization)
    ));
    let retained = f
        .journal
        .original_authorization("authorization-a", &next)
        .unwrap()
        .unwrap();
    assert!(retained == original);
    assert_eq!(retained.enrollment().reference(), f.enrollment.reference());
}

#[test]
fn local_ipc_identity_is_typed_and_pinned_to_exact_manifest_without_remote_key_claims() {
    let f = Fixture::new();
    let p = proposal("agreement-a", "obligation-a", "proposal-a");
    let local = TransportIdentityBinding::LocalProcess {
        transport_identity_id: "synthetic-local-ipc".into(),
        channel_key_digest: "11".repeat(32),
        channel_binding_digest: "22".repeat(32),
        uid: 1000,
        pid: 12345,
        process_instance: "33".repeat(32),
        signer_generation: 1,
        account_id: "account-alice".into(),
        agreement_id: "agreement-a".into(),
        participant_id: "alice".into(),
        manifest_digest: p.manifest_digest().into(),
    };
    let raw = serde_json::to_string(&local).unwrap();
    assert!(raw.contains("local_process"));
    assert!(!raw.contains("sender_key_digest"));
    assert!(!raw.contains("recipient_key_digest"));
    let mut extra = serde_json::to_value(&local).unwrap();
    extra["sender_key_digest"] = serde_json::json!("44".repeat(32));
    assert!(serde_json::from_value::<TransportIdentityBinding>(extra).is_err());
    let mut e = f.enrollment.terms.clone();
    e.transport = local;
    let e = f
        .journal
        .record_enrollment(approve_enrollment(&f.session, e))
        .unwrap();
    let prepared = f.session.prepare_manifest(&e, &p).unwrap();
    let native = decision(&f.session, prepared.review_digest());
    f.journal
        .record_accepted_manifest(f.session.approve_manifest(prepared, native).unwrap())
        .unwrap();
    let mut changed = p.input().clone();
    changed.proposal_id = "revised-proposal".into();
    changed.manifest.agreement.purpose =
        "New material terms require new local pairing scope".into();
    let changed = Proposal::validate(changed).unwrap();
    assert!(matches!(
        f.session.prepare_manifest(&e, &changed),
        Err(JournalError::InvalidBinding)
    ));
    assert!(e
        .transport()
        .validate_scope(
            "other-account",
            "agreement-a",
            "alice",
            Some(p.manifest_digest())
        )
        .is_err());
}

#[test]
fn earlier_incompatible_signer_schema_draft_is_refused_without_migration() {
    let f = Fixture::new();
    f.journal
        .connection
        .lock()
        .unwrap()
        .pragma_update(None, "user_version", 1)
        .unwrap();
    drop(f.session);
    drop(f.journal);
    assert!(matches!(
        SignerConsentJournal::open_encrypted(&f.dir.path().join("signer"), &f.key, "account-alice"),
        Err(JournalError::UnsupportedSchema)
    ));
}

#[test]
fn held_original_permission_fences_quarantine_and_new_session_cannot_revive_key_use() {
    let f = Fixture::new();
    f.journal
        .record_original_consent_release(approve_spend(&f.session, f.terms()))
        .unwrap();
    let held = f
        .journal
        .acquire_original_authorization("authorization-a", &f.session)
        .unwrap();
    held.require_current_spending_decision().unwrap();
    let next = session(&f.journal, "synthetic-owner");
    let history = f
        .journal
        .acquire_original_authorization("authorization-a", &next)
        .unwrap();
    history.check_current().unwrap();
    assert!(matches!(
        history.require_current_spending_decision(),
        Err(JournalError::Permission)
    ));
    drop(history);
    assert!(f.journal.quarantine_write_is_blocked());
    std::thread::scope(|scope| {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let journal = &f.journal;
        scope.spawn(move || {
            entered_tx.send(()).unwrap();
            let result = journal.require_recovery();
            done_tx.send(result).unwrap();
        });
        entered_rx.recv().unwrap();
        assert!(done_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        held.require_current_spending_decision().unwrap();
        drop(held);
        done_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
    });
    let history = f
        .journal
        .acquire_original_authorization("authorization-a", &f.session)
        .unwrap();
    history.check_current().unwrap();
    assert!(matches!(
        history.require_current_spending_decision(),
        Err(JournalError::RecoveryRequired)
    ));
}

#[test]
fn every_wallet_key_use_policy_field_is_part_of_immutable_original_consent() {
    use wholepact_wallet::{WalletKeyUseConfidence, WalletKeyUsePolicy};
    let f = Fixture::new();
    let mut terms = f.terms();
    terms.wallet_key_use_policy = Some(WalletKeyUsePolicy {
        confidence: WalletKeyUseConfidence::SyntheticNeverChainEvidence,
        source_id: "synthetic-provider".into(),
        endpoint: "synthetic://local".into(),
        maximum_observation_age_seconds: 120,
        minimum_confirmations: 3,
        minimum_expiry_margin_blocks: 10,
    });
    let original = f
        .journal
        .record_original_consent_release(approve_spend(&f.session, terms))
        .unwrap();
    let original = original.original_consent();
    type Change = Box<dyn Fn(&mut WalletKeyUsePolicy)>;
    let changes: Vec<Change> = vec![
        Box::new(|p| p.confidence = WalletKeyUseConfidence::TrustedSingleProviderSnapshot),
        Box::new(|p| p.source_id.push_str("-other")),
        Box::new(|p| p.endpoint.push_str("/other")),
        Box::new(|p| p.maximum_observation_age_seconds += 1),
        Box::new(|p| p.minimum_confirmations += 1),
        Box::new(|p| p.minimum_expiry_margin_blocks += 1),
    ];
    for change in changes {
        let mut changed = original.clone();
        change(changed.terms.wallet_key_use_policy.as_mut().unwrap());
        assert!(changed.validate().is_err());
        let changed = OriginalSpendConsent::new(changed.terms).unwrap();
        assert_ne!(changed.reference(), original.reference());
        assert!(matches!(
            f.journal
                .record_original_consent_release(exact_spend(&f.session, changed)),
            Err(JournalError::Conflict)
        ));
    }
    let mut absent = original.clone();
    absent.terms.wallet_key_use_policy = None;
    assert!(absent.validate().is_err());
    let legacy = OriginalSpendConsent::new(absent.terms).unwrap();
    let raw = serde_json::to_string(&legacy).unwrap();
    assert!(!raw.contains("wallet_key_use_policy"));
    let decoded: OriginalSpendConsent = serde_json::from_str(&raw).unwrap();
    decoded.validate().unwrap();
    assert!(
        f.journal
            .original_authorization("authorization-a", &f.session)
            .unwrap()
            .unwrap()
            .original_consent()
            == original
    );
}

#[test]
fn every_bridge_cell_fits_backup_cell_boundary_or_whole_append_rolls_back() {
    let f = Fixture::new();
    let original = f
        .journal
        .record_original_consent_release(approve_spend(&f.session, f.terms()))
        .unwrap();
    let mut c = f.journal.connection.lock().unwrap();
    let baseline = storage::capacity_estimate(&c).unwrap();
    for bytes in [4 * 1024 * 1024, 4 * 1024 * 1024 + 1] {
        let tx = c.transaction().unwrap();
        tx.execute(
            "INSERT INTO signer_bridge_requests VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                "authorization-a",
                original.original_consent().reference(),
                "synthetic metadata",
                "a".repeat(bytes)
            ],
        )
        .unwrap();
        let admitted = storage::bounded(&tx, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES));
        if bytes == 4 * 1024 * 1024 {
            admitted.unwrap();
        } else {
            assert!(matches!(admitted, Err(JournalError::Limit)));
        }
        // Deliberately roll back the isolated boundary probe; no history pruning.
        drop(tx);
        assert_eq!(storage::capacity_estimate(&c).unwrap(), baseline);
    }
}

#[test]
fn unexpired_wall_clock_cannot_revive_monotonically_expired_native_decision() {
    let f = Fixture::new();
    let original = f
        .journal
        .record_original_consent_release(approve_spend(&f.session, f.terms()))
        .unwrap();
    let held = f
        .journal
        .acquire_original_authorization("authorization-a", &f.session)
        .unwrap();
    held.require_current_spending_decision().unwrap();
    expire_receipt_monotonically(
        &f.session,
        original.original_consent().terms().receipt.nonce(),
    );
    assert!(now_ms().unwrap() < original.original_consent().terms().receipt.expires_at_ms());
    assert!(matches!(
        held.require_current_spending_decision(),
        Err(JournalError::Expired)
    ));
    held.check_current().unwrap(); // Read-only history remains available.
}

#[cfg(feature = "authority-signing")]
fn synthetic_settlement_source() -> wholepact_chain::local_node::LocalNodeSourceDescriptor {
    use wholepact_chain::local_node::*;
    LocalNodeSourceDescriptor {
        source_id: "synthetic-signer-node".into(), endpoint: "127.0.0.1:12345".into(),
        server_name: "localhost".into(), pinned_certificate_sha256: "11".repeat(32),
        client_certificate_sha256: "22".repeat(32), trusted_root_sha256: vec!["33".repeat(32)],
        node_release: ZEBRA_RELEASE.into(), node_source_commit: ZEBRA_SOURCE_COMMIT.into(),
        network: "testnet".into(), consensus_branch_id: wholepact_chain::NU7_BRANCH_ID,
        activation_height: wholepact_chain::NU7_ACTIVATION_HEIGHT,
        confirmation_policy: wholepact_chain::ConfirmationPolicy::new(10,10,vec!["synthetic-signer-node".into()]).unwrap(),
    }
}

/// Isolated source-enrollment semantics; no credentials, sockets or node reads.
#[cfg(feature = "authority-signing")]
#[test]
fn settlement_source_requires_exact_native_decision_and_rejects_replacement() {
    let f = Fixture::new();
    let prepare = || f.session.prepare_settlement_source(&f.journal,synthetic_settlement_source(),"44".repeat(32)).unwrap();
    let prepared = prepare();
    assert!(f.session.approve_settlement_source(prepared,decision(&f.session,&"00".repeat(32))).is_err());
    let prepared = prepare();
    let reviewed = decision(&f.session,prepared.review_digest());
    let source = f.journal.record_settlement_source(f.session.approve_settlement_source(prepared,reviewed).unwrap()).unwrap();
    assert!(f.journal.settlement_source(source.reference(),&f.session).unwrap() == source);
    let mut changed = synthetic_settlement_source(); changed.endpoint = "127.0.0.1:12346".into();
    let prepared = f.session.prepare_settlement_source(&f.journal,changed,"44".repeat(32)).unwrap();
    let reviewed = decision(&f.session,prepared.review_digest());
    assert!(matches!(f.journal.record_settlement_source(f.session.approve_settlement_source(prepared,reviewed).unwrap()),Err(JournalError::Conflict)));
    let mut invalid = synthetic_settlement_source(); invalid.endpoint = "192.0.2.1:12345".into();
    assert!(f.session.prepare_settlement_source(&f.journal,invalid,"44".repeat(32)).is_err());
}

/// A held lease is historical permission, never a way around a later recovery fence.
#[cfg(feature = "authority-signing")]
#[test]
fn settlement_dispatch_fence_rechecks_durable_recovery_for_held_lease() {
    let f = Fixture::new();
    f.journal.record_original_consent_release(approve_spend(&f.session,f.terms())).unwrap();
    let lease = f.journal.acquire_original_authorization("authorization-a",&f.session).unwrap();
    f.journal.revalidate_settlement_authority(&lease).unwrap();
    f.journal.connection.lock().unwrap().execute("UPDATE signer_account SET recovery_required=1 WHERE singleton=1",[]).unwrap();
    assert!(matches!(f.journal.revalidate_settlement_authority(&lease),Err(crate::authority_bridge::BridgeError::RecoveryRequired)));
}

/// Fabricated ledger history only: this deliberately bypasses the live issuer
/// inside the private test module to exercise restart/missing-source recovery.
#[cfg(feature = "authority-signing")]
#[test]
fn settlement_missing_runtime_source_appends_reopen_and_never_mutates_original() {
    let f = Fixture::new();
    let original = f.journal.record_original_consent_release(approve_spend(&f.session,f.terms())).unwrap();
    let prepared = f.session.prepare_settlement_source(&f.journal,synthetic_settlement_source(),"44".repeat(32)).unwrap();
    let reviewed = decision(&f.session,prepared.review_digest());
    let source = f.journal.record_settlement_source(f.session.approve_settlement_source(prepared,reviewed).unwrap()).unwrap();
    let payload = serde_json::json!({
        "original_consent_ref":original.original_consent().reference(), "request_digest":"55".repeat(32),
        "source":source,
        "transaction":{"operation_id":"synthetic-dispatch","obligation_id":"obligation-a","proposal_id":"proposal-a",
            "transaction_id":"66".repeat(32),"bytes_sha256":"77".repeat(32),"expiry_height":3000000,
            "network":"testnet","consensus_branch_id":wholepact_chain::NU7_BRANCH_ID},
        "report":null,"archive":null,
        "witness":{"record":{"operation_id":"synthetic-resolution","account_id":"account-alice","network_profile_id":"synthetic-testnet",
            "expected_head":{"sequence":1,"digest":"88".repeat(32)},"reservation_operation_id":"authorization-a",
            "reservation_request_digest":"55".repeat(32),"final_transaction_id":"66".repeat(32),"final_transaction_digest":"77".repeat(32),
            "source_descriptor_digest":"44".repeat(32),"evidence_digest":"99".repeat(32),
            "consumed_nullifiers":["aa".repeat(32)],"inclusion_block_hash":"bb".repeat(32),"inclusion_block_height":4500000},
            "committed_head":{"sequence":2,"digest":"cc".repeat(32)}},
        "consumed_nullifiers":["aa".repeat(32)]
    }).to_string();
    {
        let c=f.journal.connection.lock().unwrap();
        c.execute("INSERT INTO signer_settlement_events(evidence_id,authorization_id,source_ref,kind,payload) VALUES(?1,'authorization-a',?2,'canonical_consumed',?3)",rusqlite::params!["dd".repeat(32),source.reference(),payload]).unwrap();
    }
    let lease=f.journal.acquire_original_authorization("authorization-a",&f.session).unwrap();
    assert!(matches!(f.journal.revalidate_settlement_authority(&lease),Err(crate::authority_bridge::BridgeError::RecoveryRequired)));
    assert!(matches!(f.journal.revalidate_settlement_authority(&lease),Err(crate::authority_bridge::BridgeError::RecoveryRequired)));
    let c=f.journal.connection.lock().unwrap();
    assert_eq!(c.query_row("SELECT count(*) FROM signer_settlement_events",[],|r|r.get::<_,u64>(0)).unwrap(),2);
    assert_eq!(c.query_row("SELECT kind FROM signer_settlement_events ORDER BY sequence DESC LIMIT 1",[],|r|r.get::<_,String>(0)).unwrap(),"reopened");
    assert!(storage::read_original(&c,"authorization-a").unwrap().unwrap()==original);
    assert!(c.execute("DELETE FROM signer_settlement_events",[]).is_err());
}

/// Synthetic missing-source conflict history; no live node or funds.
#[cfg(feature = "authority-signing")]
#[test]
fn canonical_conflict_missing_runtime_source_reopens_and_preserves_original() {
    let f = Fixture::new();
    let original = f.journal.record_original_consent_release(approve_spend(&f.session,f.terms())).unwrap();
    let prepared = f.session.prepare_settlement_source(&f.journal,synthetic_settlement_source(),"44".repeat(32)).unwrap();
    let reviewed = decision(&f.session,prepared.review_digest());
    let source = f.journal.record_settlement_source(f.session.approve_settlement_source(prepared,reviewed).unwrap()).unwrap();
    let payload = serde_json::json!({
        "original_consent_ref":original.original_consent().reference(), "request_digest":"55".repeat(32),
        "source":source,
        "transaction":{"operation_id":"synthetic-dispatch","obligation_id":"obligation-a","proposal_id":"proposal-a",
            "transaction_id":"66".repeat(32),"bytes_sha256":"77".repeat(32),"expiry_height":3000000,
            "network":"testnet","consensus_branch_id":wholepact_chain::NU7_BRANCH_ID},
        "report":null,"archive":null,
        "witness":{"record":{"operation_id":"synthetic-resolution","account_id":"account-alice","network_profile_id":"synthetic-testnet",
            "expected_head":{"sequence":1,"digest":"88".repeat(32)},"reservation_operation_id":"authorization-a",
            "reservation_request_digest":"55".repeat(32),"final_transaction_id":"66".repeat(32),"final_transaction_digest":"77".repeat(32),
            "source_descriptor_digest":"44".repeat(32),"evidence_digest":"99".repeat(32),
            "consumed_nullifiers":["aa".repeat(32)],"inclusion_block_hash":"bb".repeat(32),"inclusion_block_height":4500000},
            "committed_head":{"sequence":2,"digest":"cc".repeat(32)}},
        "consumed_nullifiers":["aa".repeat(32)]
    }).to_string();
    {
        let c=f.journal.connection.lock().unwrap();
        c.execute("INSERT INTO signer_settlement_events(evidence_id,authorization_id,source_ref,kind,payload) VALUES(?1,'authorization-a',?2,'canonical_conflict',?3)",rusqlite::params!["dd".repeat(32),source.reference(),payload]).unwrap();
    }
    let lease=f.journal.acquire_original_authorization("authorization-a",&f.session).unwrap();
    assert!(matches!(f.journal.revalidate_settlement_authority(&lease),Err(crate::authority_bridge::BridgeError::RecoveryRequired)));
    assert!(matches!(f.journal.revalidate_settlement_authority(&lease),Err(crate::authority_bridge::BridgeError::RecoveryRequired)));
    let c=f.journal.connection.lock().unwrap();
    assert_eq!(c.query_row("SELECT count(*) FROM signer_settlement_events",[],|r|r.get::<_,u64>(0)).unwrap(),2);
    assert_eq!(c.query_row("SELECT kind FROM signer_settlement_events ORDER BY sequence DESC LIMIT 1",[],|r|r.get::<_,String>(0)).unwrap(),"reopened");
    assert!(storage::read_original(&c,"authorization-a").unwrap().unwrap()==original);
    assert!(c.execute("DELETE FROM signer_settlement_events",[]).is_err());
}
