//! Synthetic encrypted historical fixtures, not native birth, witness replay or
//! spending qualification. These tests never fabricate a production owner.
use super::*;
use crate::authority_bridge::{
    disclosure::RetainedWitnessDisclosure,
    protocol::{AuthorizationDeliveryScope, RetainedAuthorizationRequest, RetainedWitnessPermit},
};
use crate::consent_journal::authority::fixture;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
use wholepact_authority::{
    AuthorityHead, ReservationPermit,
    account_use::{AccountUseIdentity, ExclusionReason, PermanentAccountExclusion},
};

struct Fixture {
    journal: SignerConsentJournal,
    _dir: tempfile::TempDir,
    path: PathBuf,
    key: DatabaseKey,
    genesis: AccountUseGenesis,
    disclosure: WitnessDisclosureDescriptor,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("original.sqlite");
        let key = DatabaseKey::from_bytes([0x96; 32]);
        let account = "11".repeat(32);
        let network = crate::consent_journal::tests::proposal("a", "b", "c")
            .manifest()
            .agreement
            .network_profile_id
            .clone();
        let disclosure = WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:443".into(),
            server_name: "synthetic-witness.example".into(),
            witness_id: "synthetic-original-witness".into(),
            account_id: account.clone(),
            network_profile_id: network.clone(),
            policy_digest: "22".repeat(32),
            pinned_server_certificate_digest: "33".repeat(32),
        };
        let genesis = AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: account.clone(),
                full_viewing_key_digest: "fa".repeat(32),
                network_profile_id: network,
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: disclosure.witness_id.clone(),
            witness_origin_digest: account_use_witness_origin_digest(&disclosure).unwrap(),
            owner_certificate_digest: "44".repeat(32),
            native_birth_digest: "55".repeat(32),
        };
        let journal =
            SignerConsentJournal::create_encrypted(&path, &key, &account, 7, false).unwrap();
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
        Self {
            journal,
            _dir: dir,
            path,
            key,
            genesis,
            disclosure,
        }
    }
    fn encrypted_files(&self) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fs::read_dir(self.path.parent().unwrap())
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect()
    }
    fn commitment(&self) -> String {
        writer_history::complete_journal_commitment(&self.journal.connection.lock().unwrap())
            .unwrap()
    }
    fn check(&self) -> Result<()> {
        self.journal.check_durable_born_entry_v1(&self.genesis)
    }
    fn original(&self) -> OriginalAuthorizationEvidence {
        let session = fixture::session(&self.journal, "synthetic-owner");
        let mut input =
            crate::consent_journal::tests::proposal("agreement-a", "obligation-a", "proposal-a")
                .input()
                .clone();
        // Replace only the synthetic owner account; no live wallet/chain input.
        for participant in &mut input.manifest.participants {
            if participant.account_id == "account-alice" {
                participant.account_id = self.genesis.identity.account_id.clone();
            }
        }
        for input in &mut input.manifest.inputs {
            if input.account_id == "account-alice" {
                input.account_id = self.genesis.identity.account_id.clone();
            }
        }
        for output in &mut input.manifest.outputs {
            if let wholepact_core::OutputAllocation::Return { account_id, .. } =
                &mut output.allocation
            {
                if account_id == "account-alice" {
                    *account_id = self.genesis.identity.account_id.clone();
                }
            }
        }
        input.artifact_digest = Some(hex::encode(Sha256::digest(
            b"inert synthetic original artifact",
        )));
        let proposal = wholepact_core::Proposal::validate(input).unwrap();
        let enrollment = self
            .journal
            .record_enrollment(fixture::approve_enrollment(
                &session,
                EnrollmentTerms {
                    account_id: self.genesis.identity.account_id.clone(),
                    agreement_id: "agreement-a".into(),
                    participant_id: "alice".into(),
                    principal_id: "synthetic-owner".into(),
                    network_profile_id: self.genesis.identity.network_profile_id.clone(),
                    privacy_domain: "synthetic-domain".into(),
                    account_fvk_digest: self.genesis.identity.full_viewing_key_digest.clone(),
                    transport: TransportIdentityBinding::RemoteAuthenticatedKeys {
                        transport_identity_id: "synthetic-transport".into(),
                        sender_key_digest: "a1".repeat(32),
                        recipient_key_digest: "b2".repeat(32),
                        channel_binding_digest: "c3".repeat(32),
                    },
                    aggregate_budget_limit_zatoshis: 1_000_000_000,
                    receipt: fixture::receipt(&session),
                },
            ))
            .unwrap();
        let prepared = session.prepare_manifest(&enrollment, &proposal).unwrap();
        let decision = fixture::decision(&session, prepared.review_digest());
        let manifest = self
            .journal
            .record_accepted_manifest(session.approve_manifest(prepared, decision).unwrap())
            .unwrap();
        let mut terms = crate::consent_journal::tests::terms(
            &session,
            &enrollment,
            &manifest,
            "authorization-a",
        );
        terms.artifact_digest = proposal.input().artifact_digest.clone().unwrap();
        self.journal
            .record_original_consent_release(fixture::approve_spend(&session, terms))
            .unwrap()
    }
    fn request(&self, original: &OriginalAuthorizationEvidence) -> RetainedAuthorizationRequest {
        let mut request = RetainedAuthorizationRequest::from_original(
            original,
            b"inert synthetic original artifact",
            AuthorityHead {
                sequence: 4,
                digest: "66".repeat(32),
            },
            AuthorizationDeliveryScope {
                candidate_id: "proposal-a".into(),
            },
        )
        .unwrap();
        let nonce = "77".repeat(32);
        let native_review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:exact-native-witness-disclosure:v1",
            &(
                &self.disclosure,
                &request.reservation.expected_head,
                &nonce,
                original.original_consent(),
            ),
        )
        .unwrap();
        request.disclosure = Some(RetainedWitnessDisclosure {
            descriptor: self.disclosure.clone(),
            original_consent_ref: original.original_consent().reference().into(),
            native_review_digest,
            expected_head: request.reservation.expected_head.clone(),
            nonce,
            native_origin_measurement: original
                .original_consent()
                .terms()
                .receipt
                .trusted_launch_measurement()
                .into(),
            native_principal_id: "synthetic-owner".into(),
        });
        request.validate_original(original).unwrap();
        request
    }
    fn insert_request(&self, request: &RetainedAuthorizationRequest) {
        self.journal
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO signer_bridge_requests VALUES(?1,?2,?3,?4)",
                params![
                    request.reservation.authorization_id,
                    request.reservation.original_consent_ref,
                    encode(&(&request.reservation, &request.delivery, &request.disclosure))
                        .unwrap()
                        .as_str(),
                    request.artifact_hex
                ],
            )
            .unwrap();
    }
    fn insert_permit(&self, request: &RetainedAuthorizationRequest) {
        let permit = RetainedWitnessPermit {
            descriptor: ReservationPermit {
                protocol_version: wholepact_authority::PROTOCOL_VERSION,
                witness_id: self.disclosure.witness_id.clone(),
                policy_digest: self.disclosure.policy_digest.clone(),
                request_digest: request.reservation.request_digest().unwrap(),
                request: request.reservation.clone(),
                committed_head: AuthorityHead {
                    sequence: 5,
                    digest: "88".repeat(32),
                },
                reserved_at_ms: request.reservation.reviewed_at_ms,
                account_outstanding_debit_zatoshis: request.reservation.maximum_debit_zatoshis,
                account_reserved_input_value_zatoshis: 500_000_000,
                writer_session_id: "99".repeat(32),
            },
            witness_certificate_digest: self.disclosure.pinned_server_certificate_digest.clone(),
        };
        self.journal
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO signer_bridge_permits VALUES(?1,?2)",
                params![
                    request.reservation.authorization_id,
                    encode(&permit).unwrap().as_str()
                ],
            )
            .unwrap();
    }
}

#[test]
fn original_current_schema_reopens_with_new_binding_without_mutation() {
    let f = Fixture::new();
    let before = f.commitment();
    f.check().unwrap();
    let reopened =
        SignerConsentJournal::open_durable_born_entry_v1(&f.path, &f.key, &f.genesis).unwrap();
    assert!(reopened.binding() != f.journal.binding());
    reopened.check_durable_born_entry_v1(&f.genesis).unwrap();
    assert_eq!(before, f.commitment());
    assert_eq!(reopened.account_state().unwrap().writer_epoch, 7);
}

#[test]
fn online_release_request_permit_and_uncertain_keyuse_survive_as_exact_history() {
    let f = Fixture::new();
    let original = f.original();
    let request = f.request(&original);
    for stage in 0..4 {
        match stage {
            0 => {}
            1 => f.insert_request(&request),
            2 => f.insert_permit(&request),
            3 => {
                f.journal
                    .connection
                    .lock()
                    .unwrap()
                    .execute(
                        "INSERT INTO signer_bridge_keyuse VALUES('authorization-a')",
                        [],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = f.commitment();
        f.check().unwrap();
        let reopened =
            SignerConsentJournal::open_durable_born_entry_v1(&f.path, &f.key, &f.genesis).unwrap();
        reopened.check_durable_born_entry_v1(&f.genesis).unwrap();
        assert_eq!(f.commitment(), before, "stage {stage}");
        let c = reopened.connection.lock().unwrap();
        assert_eq!(c.query_row("SELECT count(*) FROM signer_release_intents WHERE exposure_state='outstanding_uncertain'", [], |r| r.get::<_,u64>(0)).unwrap(),1);
        assert_eq!(
            c.query_row("SELECT count(*) FROM signer_input_reservations", [], |r| {
                r.get::<_, u64>(0)
            })
            .unwrap(),
            1
        );
        assert_eq!(
            c.query_row("SELECT count(*) FROM signer_bridge_results", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    // Historical enrollment epoch 7 is not a claim that the current epoch is 7.
    f.journal
        .connection
        .lock()
        .unwrap()
        .execute("UPDATE signer_account SET writer_epoch=8", [])
        .unwrap();
    let before = f.commitment();
    f.check().unwrap();
    assert_eq!(before, f.commitment());
}

#[test]
fn wrong_genesis_key_recovery_and_exclusion_reject_without_row_changes() {
    let f = Fixture::new();
    let before = f.commitment();
    let mut wrong = f.genesis.clone();
    wrong.native_birth_digest = "ba".repeat(32);
    assert!(f.journal.check_durable_born_entry_v1(&wrong).is_err());
    let encrypted_before = f.encrypted_files();
    assert!(SignerConsentJournal::open_durable_born_entry_v1(&f.path, &f.key, &wrong).is_err());
    assert_eq!(encrypted_before, f.encrypted_files());
    assert!(
        SignerConsentJournal::open_durable_born_entry_v1(
            &f.path,
            &DatabaseKey::from_bytes([0x97; 32]),
            &f.genesis
        )
        .is_err()
    );
    assert_eq!(encrypted_before, f.encrypted_files());
    assert_eq!(before, f.commitment());
    for recovery in [false, true] {
        let f = Fixture::new();
        if recovery {
            f.journal
                .connection
                .lock()
                .unwrap()
                .execute("UPDATE signer_account SET recovery_required=1", [])
                .unwrap();
        } else {
            let event = PermanentAccountExclusion {
                version: 1,
                identity: f.genesis.identity.clone(),
                genesis_digest: f.genesis.digest().unwrap(),
                operation_id: "retire".into(),
                native_review_digest: "cd".repeat(32),
                reason: ExclusionReason::RetirementRequested,
            };
            f.journal
                .connection
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO signer_account_use_exclusion VALUES(1,?1,?2,?3)",
                    params![
                        event.genesis_digest,
                        event.digest().unwrap(),
                        encode(&event).unwrap().as_str()
                    ],
                )
                .unwrap();
        }
        let before = f.commitment();
        assert!(f.check().is_err());
        let encrypted_before = f.encrypted_files();
        assert!(
            SignerConsentJournal::open_durable_born_entry_v1(&f.path, &f.key, &f.genesis).is_err()
        );
        assert_eq!(encrypted_before, f.encrypted_files());
        assert_eq!(before, f.commitment());
    }
}

#[test]
fn every_unqualified_nonempty_table_is_rejected_by_explicit_policy() {
    let c = Connection::open_in_memory().unwrap();
    // Policy-only schema: this cannot pass the real opener's exact schema gate.
    for (table, _) in CAPACITY_TABLES {
        c.execute_batch(&format!("CREATE TABLE {table}(value TEXT)"))
            .unwrap();
    }
    for (table, _) in CAPACITY_TABLES {
        c.execute(
            &format!("INSERT INTO {table} VALUES('retained-history')"),
            [],
        )
        .unwrap();
        let allowed = matches!(
            *table,
            "signer_account"
                | "signer_account_use_genesis"
                | "signer_enrollments"
                | "signer_accepted_manifests"
                | "signer_durable_construction_outbox"
                | "signer_original_consents"
                | "signer_release_intents"
                | "signer_input_reservations"
                | "signer_remote_exposures"
                | "signer_remote_inputs"
                | "signer_writer_reconciliations"
                | "signer_bridge_requests"
                | "signer_bridge_permits"
                | "signer_bridge_keyuse"
                | "signer_bridge_results"
                | "signer_result_redeliveries"
                | "signer_dispatch_requests"
        );
        assert_eq!(require_supported_tables(&c).is_ok(), allowed, "{table}");
        assert_eq!(
            c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
        c.execute(&format!("DELETE FROM {table}"), []).unwrap();
    }
}

#[test]
fn copied_replacement_does_not_satisfy_retained_live_identity() {
    let f = Fixture::new();
    f.journal
        .connection
        .lock()
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let copy = f.path.with_file_name("copied.sqlite");
    fs::copy(&f.path, &copy).unwrap();
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o600)).unwrap();
    let copy_connection = wholepact_storage_security::open_encrypted(&copy, &f.key).unwrap();
    assert!(
        f.journal
            .database_identity
            .check_current(copy_connection.connection())
            .is_err()
    );
    drop(copy_connection);
    fs::rename(&copy, &f.path).unwrap();
    assert!(f.check().is_err());
    // A new process needs the genuine original vault/publication target owner;
    // an opaque file identity is not a historical rollback oracle.
}

#[test]
fn missing_path_and_old_schema_are_not_created_or_migrated() {
    let f = Fixture::new();
    let missing = f.path.with_file_name("missing.sqlite");
    assert!(
        SignerConsentJournal::open_durable_born_entry_v1(&missing, &f.key, &f.genesis).is_err()
    );
    assert!(!missing.exists());
    let old = f.path.with_file_name("old.sqlite");
    let mut c = wholepact_storage_security::create_encrypted(&old, &f.key)
        .unwrap()
        .into_connection();
    c.execute_batch(recovery_migration::V17_SCHEMA).unwrap();
    c.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    c.pragma_update(None, "user_version", 17).unwrap();
    c.execute(
        "INSERT INTO signer_account VALUES(1,?1,7,0)",
        [&f.genesis.identity.account_id],
    )
    .unwrap();
    let before = fs::read(&old).unwrap();
    assert!(matches!(
        SignerConsentJournal::open_durable_born_entry_v1(&old, &f.key, &f.genesis),
        Err(JournalError::UnsupportedSchema)
    ));
    assert_eq!(
        c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        17
    );
    assert_eq!(before, fs::read(&old).unwrap());
    // Keep the mutable connection until the source immutability assertion.
    let tx = c.transaction().unwrap();
    tx.rollback().unwrap();
}

#[test]
fn validated_old_v3_read_reserved_and_consumed_rows_stay_unsupported_and_intact() {
    let (inventory, evidence) =
        crate::consent_journal::common_context_audit_tests::fixture::fixture();
    let genesis = evidence
        .complete_history
        .financial_origins_v2
        .account_use
        .genesis
        .as_ref()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("old-v3.sqlite");
    let key = DatabaseKey::from_bytes([0x98; 32]);
    let journal = SignerConsentJournal::create_encrypted(
        &path,
        &key,
        &genesis.identity.account_id,
        evidence.request.expected_writer_epoch,
        false,
    )
    .unwrap();
    journal
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            params![
                genesis.identity.account_id,
                genesis.identity.full_viewing_key_digest,
                genesis.digest().unwrap(),
                encode(genesis).unwrap().as_str()
            ],
        )
        .unwrap();
    for phase in ["read_admitted", "reserved", "consumed"] {
        journal
            .retain_common_context_audit_v3(
                inventory.rows.iter().find(|r| r.phase() == phase).unwrap(),
            )
            .unwrap();
        let before =
            writer_history::complete_journal_commitment(&journal.connection.lock().unwrap())
                .unwrap();
        assert!(
            matches!(
                journal.check_durable_born_entry_v1(genesis),
                Err(JournalError::ConstructionHistoryUnsupported)
            ),
            "{phase}"
        );
        assert!(
            matches!(
                SignerConsentJournal::open_durable_born_entry_v1(&path, &key, genesis),
                Err(JournalError::ConstructionHistoryUnsupported)
            ),
            "{phase}"
        );
        assert_eq!(
            before,
            writer_history::complete_journal_commitment(&journal.connection.lock().unwrap())
                .unwrap()
        );
    }
}

#[test]
fn foreign_fvk_witness_and_orphan_keyuse_cannot_enter_new_profile() {
    let f = Fixture::new();
    let original = f.original();
    let mut foreign = original.enrollment().clone();
    foreign.terms.account_fvk_digest = "ac".repeat(32);
    foreign.reference = digest("wholepact:signer-account-enrollment:v1", &foreign.terms).unwrap();
    foreign.validate().unwrap();
    f.journal
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO signer_enrollments VALUES(?1,?2,?3,?4,?5)",
            params![
                foreign.reference(),
                foreign.account_id(),
                foreign.agreement_id(),
                foreign.participant_id(),
                encode(&foreign).unwrap().as_str()
            ],
        )
        .unwrap();
    let before = f.commitment();
    assert!(f.check().is_err());
    assert_eq!(before, f.commitment());

    let mut f = Fixture::new();
    let original = f.original();
    f.disclosure.endpoint = "127.0.0.1:444".into();
    let request = f.request(&original);
    f.insert_request(&request);
    let before = f.commitment();
    assert!(f.check().is_err());
    assert_eq!(before, f.commitment());

    let f = Fixture::new();
    {
        let c = f.journal.connection.lock().unwrap();
        c.pragma_update(None, "foreign_keys", false).unwrap();
        c.execute(
            "INSERT INTO signer_bridge_keyuse VALUES('orphan-uncertain-keyuse')",
            [],
        )
        .unwrap();
    }
    let before = f.commitment();
    assert!(f.check().is_err());
    assert_eq!(before, f.commitment());
}

#[test]
fn imported_online_exposure_and_inputs_are_neither_renewed_nor_removed() {
    let f = Fixture::new();
    let original = f.original();
    let request = f.request(&original);
    f.insert_request(&request);
    f.insert_permit(&request);
    {
        let c = f.journal.connection.lock().unwrap();
        let retained = bridge_storage::read_permit(&c, &request.reservation.authorization_id)
            .unwrap()
            .unwrap();
        let permit = retained.descriptor();
        c.execute(
            "INSERT INTO signer_remote_exposures VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                permit.request.authorization_id,
                permit.request.original_consent_ref,
                permit.request.account_id,
                permit.request.obligation_id,
                permit.request.maximum_debit_zatoshis.to_string(),
                encode(permit).unwrap().as_str()
            ],
        )
        .unwrap();
        for input in &permit.request.inputs {
            c.execute(
                "INSERT INTO signer_remote_inputs VALUES(?1,?2,?3)",
                params![
                    permit.request.authorization_id,
                    permit.request.account_id,
                    input.nullifier
                ],
            )
            .unwrap();
        }
    }
    let before = f.commitment();
    f.check().unwrap();
    let reopened =
        SignerConsentJournal::open_durable_born_entry_v1(&f.path, &f.key, &f.genesis).unwrap();
    reopened.check_durable_born_entry_v1(&f.genesis).unwrap();
    assert_eq!(before, f.commitment());
}

#[test]
fn held_original_lease_reuses_exact_fence_with_queued_revoker() {
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };
    let f = Arc::new(Fixture::new());
    f.original();
    let foreign = Fixture::new();
    let (checked_tx, checked_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let session = fixture::session(&f.journal, "synthetic-owner");
        let lease = f
            .journal
            .acquire_original_authorization("authorization-a", &session)
            .unwrap();
        assert!(
            foreign
                .journal
                .check_durable_born_entry_v1_under_lease(&foreign.genesis, &lease)
                .is_err()
        );
        let revoker = Arc::clone(&f);
        let (started_tx, started_rx) = mpsc::channel();
        let revoke = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            revoker.journal.require_recovery().unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // Linux's writer-preferring RwLock refuses a new nonblocking reader
        // once the revoker is queued, while the actual original guard remains.
        let deadline = Instant::now() + Duration::from_secs(2);
        while f.journal.authority_fence.try_read().is_ok() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(f.journal.authority_fence.try_read().is_err());
        f.journal
            .check_durable_born_entry_v1_under_lease(&f.genesis, &lease)
            .unwrap();
        checked_tx.send(()).unwrap();
        drop(lease);
        revoke.join().unwrap();
        assert!(matches!(f.check(), Err(JournalError::RecoveryRequired)));
    });
    // A regression to recursive read fails by timeout rather than hanging the
    // whole test runner on a writer waiting for the same held lease.
    checked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    worker.join().unwrap();
}
