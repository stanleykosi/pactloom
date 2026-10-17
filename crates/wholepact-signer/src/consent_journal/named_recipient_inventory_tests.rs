//! Synthetic inert retention only. No native setup decision, authenticated
//! named-verifier package, real wallet, witness admission or signing occurs.
use super::*;
use rusqlite::{params, types::Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use wholepact_storage_security::{DatabaseKey, bundle::*};

const ACCOUNT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn random32() -> [u8; 32] {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}
fn h(n: u8) -> String {
    format!("{n:064x}")
}
struct Fixture {
    dir: tempfile::TempDir,
    key: DatabaseKey,
    journal: SignerConsentJournal,
    session: SignerConsentSession,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = DatabaseKey::from_bytes(random32());
        let journal = SignerConsentJournal::create_encrypted(
            &dir.path().join("synthetic-original.sqlite"),
            &key,
            ACCOUNT,
            1,
            false,
        )
        .unwrap();
        let session = authority::fixture::session(&journal, "synthetic-owner");
        let (enrollment, manifest) = enroll_fixture(&journal, &session);
        let secret = random32();
        #[cfg(feature = "offline-review-foundation")]
        let public = *wholepact_transport::TransportSecret::from_bytes(secret)
            .unwrap()
            .public_key()
            .unwrap()
            .as_bytes();
        // This build cannot claim key-pair semantics: raw retention only.
        #[cfg(not(feature = "offline-review-foundation"))]
        let public = random32();
        let mut profile = NamedRecipientProfileRecordV1 {
            born_profile: None,
            schema_version: 1,
            reference: h(1),
            account_id: ACCOUNT.into(),
            full_viewing_key_digest: enrollment.account_fvk_digest().into(),
            enrollment_ref: enrollment.reference().into(),
            manifest_ref: manifest.reference().into(),
            native_review_digest: h(2),
            native_origin_digest: h(3),
            original_setup_digest: h(4),
            verifier_signing_public_key: random32(),
            verifier_transport_public_key: random32(),
            witness_transport_public_key: random32(),
            witness_certificate_digest: h(5),
            return_transport_public_key: random32(),
            transport_public_key: public,
            transport_secret: secret,
        };
        profile.original_setup_digest = profile.setup_digest().unwrap();
        profile.reference = profile.reference_digest().unwrap();
        let mut terms = offline_history::tests::full_admission()
            .0
            .request
            .intent
            .terms;
        terms.account_id = ACCOUNT.into();
        terms.enrollment_ref = profile.enrollment_ref.clone();
        terms.accepted_manifest_ref = profile.manifest_ref.clone();
        terms.agreement_id = "agreement-a".into();
        terms.obligation_id = "obligation-a".into();
        terms.proposal_id = "proposal-a".into();
        terms.manifest_digest = manifest.manifest_digest().into();
        terms.proposal_digest = manifest.proposal_digest().into();
        let retained = manifest.proposal_input();
        terms.network_profile_id = retained.manifest.agreement.network_profile_id.clone();
        terms.proposal_revision = u64::from(retained.manifest.agreement.revision);
        terms.artifact_digest = retained.artifact_digest.clone().unwrap();
        terms.effects_digest = retained.effects_commitment.clone().unwrap();
        terms.transaction_expiry_height = retained.manifest.expiry_height;
        terms.inputs[0].input_id = "input-alice".into();
        terms.offline_signer_key_digest = transport_fingerprint(&profile.transport_public_key);
        terms.return_recipient_key_digest =
            transport_fingerprint(&profile.return_transport_public_key);
        terms.inputs[0].value_zatoshis = 500_000_000;
        terms.maximum_debit_zatoshis = 400_012_000;
        terms.fee_share_zatoshis = 12_000;
        terms.transaction_fee_zatoshis = 30_000;
        #[cfg(feature = "offline-review-foundation")]
        {
            let header = wholepact_transport::NamedReviewBindingV1 {
                schema_version: 1,
                disclosure_profile: wholepact_transport::NAMED_REVIEW_DISCLOSURE_PROFILE_V1.into(),
                owner_setup_digest: profile.original_setup_digest.clone(),
                assertion_package_digest: h(20),
                original_context_digest:
                    wholepact_offline_bridge::named_verifier_original_context_digest(&terms)
                        .unwrap(),
            };
            terms.review_package_digest = header.review_package_digest().unwrap();
        }
        let mut reservation_request = offline_history::tests::full_admission().0.request;
        reservation_request.intent.terms = terms.clone();
        let reservation_request_digest = reservation_request.request_digest().unwrap();
        let admission_export_template = wholepact_authority::OfflineAdmissionExportPlan {
            message_id: "21".repeat(16),
            sequence: 0,
            issued_at_unix_seconds: 2,
            expires_at_unix_seconds: 30,
            purpose: "Synthetic exact original admission template".into(),
            persistence_warning: "Synthetic recipient may retain original evidence".into(),
            sender_id: format!("offline-admission:{}", terms.offline_policy_digest),
            recipient_id: format!("offline-admission:{}", terms.offline_signer_key_digest),
            sender_key_fingerprint: transport_fingerprint(&profile.witness_transport_public_key),
            recipient_key_fingerprint: transport_fingerprint(&profile.transport_public_key),
        };
        let own = NamedRecipientOwnExpectationsV1 {
            schema_version: 1,
            full_viewing_key_digest: profile.full_viewing_key_digest.clone(),
            manifest_digest: terms.manifest_digest.clone(),
            anchor: terms.snapshot.anchor_root.clone(),
            expiry_height: terms.transaction_expiry_height,
            maximum_selected_net_debit_zatoshis: terms.maximum_debit_zatoshis,
            exact_selected_net_debit_zatoshis: terms.maximum_debit_zatoshis,
            declared_fee_share_zatoshis: terms.fee_share_zatoshis,
            exact_transaction_fee_zatoshis: terms.transaction_fee_zatoshis,
            own_inputs: vec![NamedRecipientOwnInputV1 {
                action_index: terms.inputs[0].action_index.try_into().unwrap(),
                nullifier: terms.inputs[0].nullifier.clone(),
                value_zatoshis: 500_000_000,
            }],
            outputs: vec![NamedRecipientOwnOutputV1 {
                action_index: 1,
                receiver_hex: "09".repeat(43),
                value_zatoshis: 99_988_000,
                memo_hex: "00".repeat(512),
                purpose: NamedRecipientOutputPurposeV1::OwnReturn,
            }],
        };
        let mut original = NamedRecipientOriginalRecordV1 {
            born_origin: None,
            schema_version: 1,
            reference: h(6),
            profile_ref: profile.reference.clone(),
            original_artifact_digest: terms.artifact_digest.clone(),
            canonical_artifact_digest: h(7),
            transformation_digest: h(8),
            named_assertion_digest: h(9),
            assertion_package_digest: h(20),
            validity_not_before_ms: 1_000,
            validity_expires_ms: 30_000,
            original_request_digest: h(10),
            reservation_request,
            reservation_request_digest,
            admission_export_template,
            own_policy_digest: h(11),
            own_expectations: own,
            terms,
        };
        original.reference = original.reference_digest().unwrap();
        validate_original_fixture(&original, &profile).unwrap();
        let outbox = inert_intent_outbox(&original, &profile, 1, "22".repeat(16));
        let started = NamedRecipientStartedRecordV1 {
            born_final_review: None,
            final_review: None,
            schema_version: 1,
            authorization_id: original.terms.authorization_id.clone(),
            original_ref: original.reference.clone(),
            native_review_digest: h(12),
            native_origin_digest: h(13),
            admission_request_digest: original.reservation_request_digest.clone(),
            authenticated_package_digest: original.terms.review_package_digest.clone(),
            original_deadline_ms: 30_000,
        };
        let result_bytes = b"synthetic inert signature result; no key invocation";
        let result = NamedRecipientResultRecordV1 {
            encrypted_return: None,
            schema_version: 1,
            authorization_id: started.authorization_id.clone(),
            original_ref: started.original_ref.clone(),
            started_digest: started.marker_digest().unwrap(),
            result_digest: hex::encode(Sha256::digest(result_bytes)),
            result_hex: hex::encode(result_bytes),
        };
        let mut c = journal.connection.lock().unwrap();
        let tx = c.transaction().unwrap();
        tx.execute(
            "INSERT INTO signer_named_recipient_profiles VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                profile.reference,
                profile.original_setup_digest,
                profile.account_id,
                profile.enrollment_ref,
                profile.manifest_ref,
                encode(&profile).unwrap().as_str()
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO signer_named_recipient_originals VALUES(?1,?2,?3,?4)",
            params![
                original.reference,
                original.profile_ref,
                original.terms.authorization_id,
                encode(&original).unwrap().as_str()
            ],
        )
        .unwrap();
        insert_outbox(&tx, &outbox);
        let ciphertext = b"synthetic inert envelope bytes; not an authenticated package";
        let envelope_digest = domain_digest(b"wholepact.encrypted-envelope.v1\0", ciphertext);
        tx.execute(
            "INSERT INTO signer_named_recipient_receipts VALUES(?1,?2,1,?3,?4,?5,?6,?7,?8)",
            params![
                profile.reference,
                h(15),
                h(16),
                h(17),
                h(18),
                envelope_digest,
                h(19),
                hex::encode(ciphertext)
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO signer_named_recipient_started VALUES(?1,?2,?3,?4)",
            params![
                started.authorization_id,
                started.original_ref,
                started.marker_digest().unwrap(),
                encode(&started).unwrap().as_str()
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO signer_named_recipient_results VALUES(?1,?2,?3)",
            params![
                result.authorization_id,
                result.result_digest,
                encode(&result).unwrap().as_str()
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        drop(c);
        Self {
            dir,
            key,
            journal,
            session,
        }
    }
}
fn named_rows(c: &Connection) -> BTreeMap<String, Vec<Vec<Value>>> {
    [
        "signer_named_recipient_profiles",
        "signer_named_recipient_originals",
        "signer_named_recipient_receipts",
        "signer_named_recipient_started",
        "signer_named_recipient_results",
        "signer_named_intent_outbox",
    ]
    .into_iter()
    .map(|name| {
        let table = name.to_owned();
        let mut q = c
            .prepare(&format!("SELECT rowid,* FROM {table} ORDER BY rowid"))
            .unwrap();
        let n = q.column_count();
        let rows = q
            .query_map([], |r| (0..n).map(|i| r.get(i)).collect())
            .unwrap()
            .collect::<std::result::Result<Vec<Vec<Value>>, _>>()
            .unwrap();
        (table, rows)
    })
    .collect()
}
fn coverage() -> Coverage {
    Coverage {
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
    }
}
#[test]
fn named_records_are_immutable_and_accounted_without_writer_activation() {
    let f = Fixture::new();
    let c = f.journal.connection.lock().unwrap();
    storage::verify_schema(&c).unwrap();
    let before = named_rows(&c);
    let bound = storage::capacity_estimate(&c).unwrap();
    assert!(storage::bounded(&c, (bound.0 - 1, bound.1)).is_err());
    assert!(storage::bounded(&c, (bound.0, bound.1 - 1)).is_err());
    for suffix in ["profiles", "originals", "receipts", "started", "results"] {
        let table = format!("signer_named_recipient_{suffix}");
        assert!(c.execute(&format!("DELETE FROM {table}"), []).is_err());
        let column = if suffix == "receipts" {
            "envelope_hex"
        } else {
            "payload"
        };
        assert!(
            c.execute(&format!("UPDATE {table} SET {column}='replacement'"), [])
                .is_err()
        );
        assert!(
            c.execute(
                &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
                []
            )
            .is_err()
        );
    }
    assert!(
        c.execute("DELETE FROM signer_named_intent_outbox", [])
            .is_err()
    );
    assert!(
        c.execute(
            "UPDATE signer_named_intent_outbox SET preview_json='{}'",
            []
        )
        .is_err()
    );
    assert!(c.execute("INSERT OR REPLACE INTO signer_named_intent_outbox SELECT * FROM signer_named_intent_outbox", []).is_err());
    assert_eq!(before, named_rows(&c));
    assert!(matches!(
        require_absent(&c),
        Err(JournalError::NamedRecipientHistoryUnsupported)
    ));
    assert!(matches!(
        offline_history::require_accountwide_online_admission(&c),
        Err(JournalError::NamedRecipientHistoryUnsupported)
    ));
    assert!(matches!(
        offline_history::require_legacy_journal(&c),
        Err(JournalError::NamedRecipientHistoryUnsupported)
    ));
}
#[cfg(feature = "offline-review-foundation")]
#[test]
fn named_typed_inventory_has_only_fingerprints_and_exact_original_refs() {
    let f = Fixture::new();
    let inventory = f
        .journal
        .named_recipient_history_inventory(&f.session)
        .unwrap();
    assert_eq!(
        (
            inventory.profiles.len(),
            inventory.originals.len(),
            inventory.receipts.len(),
            inventory.started.len(),
            inventory.results.len(),
            inventory.intent_outbox.len()
        ),
        (1, 1, 1, 1, 1, 1)
    );
    let json = serde_json::to_string(&inventory).unwrap();
    for forbidden in [
        "transport_secret",
        "transport_public_key",
        "reservation_request",
        "admission_export_template",
        "preview_json",
        "payload",
        "envelope_hex",
        "memo_hex",
        "receiver_hex",
        "result_hex",
        "own_inputs",
    ] {
        assert!(!json.contains(&format!("\"{forbidden}\"")));
    }
    assert_eq!(
        inventory.results[0].original_ref,
        inventory.originals[0].reference
    );
    let c = f.journal.connection.lock().unwrap();
    let raw: String = c
        .query_row(
            "SELECT payload FROM signer_named_recipient_profiles",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut profile: NamedRecipientProfileRecordV1 = decode(raw).unwrap();
    profile.transport_secret = random32();
    assert!(matches!(
        profile.validate(),
        Err(JournalError::InvalidBinding)
    ));
}
#[cfg(not(feature = "offline-review-foundation"))]
#[test]
fn named_featureless_typed_reader_refuses_without_losing_raw_archive_rows() {
    let f = Fixture::new();
    assert!(matches!(
        f.journal.named_recipient_history_inventory(&f.session),
        Err(JournalError::NamedRecipientHistoryUnsupported)
    ));
    let c = f.journal.connection.lock().unwrap();
    validate_archive_rows(&c, ACCOUNT).unwrap();
    assert_eq!(named_rows(&c).len(), 6);
}
#[test]
fn named_nonempty_encrypted_archive_preserves_exact_rows_and_restored_denial() {
    let f = Fixture::new();
    let before = named_rows(&f.journal.connection.lock().unwrap());
    let archive = f.dir.path().join("synthetic-archive.sqlite");
    let restored = f.dir.path().join("synthetic-restored.sqlite");
    let archive_key = DatabaseKey::from_bytes(random32());
    let restored_key = DatabaseKey::from_bytes(random32());
    let adapter = f.journal.backup_adapter();
    let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
    snapshot(SnapshotRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        coverage: coverage(),
        sources: &sources,
        destination: &archive,
        key: &archive_key,
        authority: &super::super::tests::BackupGate,
    })
    .unwrap();
    let report = restore(RestoreRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        archive: &archive,
        key: &archive_key,
        targets: &[RestoreTarget {
            component_id: "signer-authority",
            template: SignerConsentBundleAdapter::template(),
            destination: &restored,
            key: &restored_key,
        }],
        authority: &super::super::tests::BackupGate,
    })
    .unwrap();
    assert!(!report.authorization_allowed);
    assert!(SignerConsentJournal::open_encrypted(&restored, &restored_key, ACCOUNT).is_err());
    let source = recovery::VerifiedSignerRecoverySource::open(
        history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &archive_key,
            component_id: "signer-authority",
            restored_component: &restored,
            restored_key: &restored_key,
        },
        SignerConsentBundleAdapter::template(),
    )
    .unwrap();
    assert_eq!(source.provenance().schema_version, SCHEMA_VERSION);
    for (table, expected) in &before {
        let retained = source.tables().iter().find(|t| t.name() == table).unwrap();
        let actual = retained
            .rows()
            .iter()
            .map(|row| {
                let mut cells = vec![Value::Integer(row.rowid().unwrap())];
                cells.extend(row.cells().iter().map(|cell| match cell {
                    recovery::RecoveryCell::Null => Value::Null,
                    recovery::RecoveryCell::Integer(v) => Value::Integer(*v),
                    recovery::RecoveryCell::Text(v) => Value::Text(v.clone()),
                    _ => panic!("unexpected cell"),
                }));
                cells
            })
            .collect::<Vec<_>>();
        assert_eq!(&actual, expected);
    }
    assert_eq!(before, named_rows(&f.journal.connection.lock().unwrap()));
    #[cfg(all(
        feature = "native-ui",
        feature = "authority-signing",
        target_os = "linux"
    ))]
    {
        assert!(matches!(
            offline_history::require_legacy_recovery_source(&source),
            Err(JournalError::NamedRecipientHistoryUnsupported)
        ));
        let inert = QuarantinedJournalRead::from_verified(source, ACCOUNT).unwrap();
        #[cfg(feature = "offline-review-foundation")]
        assert_eq!(
            inert
                .named_recipient_history_inventory()
                .unwrap()
                .profiles
                .len(),
            1
        );
        #[cfg(not(feature = "offline-review-foundation"))]
        assert!(matches!(
            inert.named_recipient_history_inventory(),
            Err(JournalError::NamedRecipientHistoryUnsupported)
        ));
    }
    assert_ciphertext_only(&archive);
    assert_ciphertext_only(&restored);
    // Original encrypted journal can reopen; this is historical continuity,
    // not a restored writer or named financial activation.
    let reopened = SignerConsentJournal::open_encrypted(
        &f.dir.path().join("synthetic-original.sqlite"),
        &f.key,
        ACCOUNT,
    )
    .unwrap();
    // Reopening returns exactly the original preview/ciphertext bytes; this
    // fixture never calls any seal method or mints a replacement message ID.
    assert_eq!(before, named_rows(&reopened.connection.lock().unwrap()));
}
fn assert_ciphertext_only(path: &Path) {
    let bytes = std::fs::read(path).unwrap();
    for needle in [
        b"synthetic inert signature result".as_slice(),
        b"transport_secret".as_slice(),
        b"synthetic inert envelope bytes".as_slice(),
        b"synthetic inert intent envelope".as_slice(),
    ] {
        assert!(!bytes.windows(needle.len()).any(|part| part == needle));
    }
}

fn enroll_fixture(
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
) -> (AccountEnrollmentRecord, AcceptedManifestRecord) {
    use authority::fixture::{approve_enrollment, decision, receipt};
    let mut proposal = super::super::tests::proposal("agreement-a", "obligation-a", "proposal-a")
        .input()
        .clone();
    for owner in &mut proposal.manifest.participants {
        if owner.account_id == "account-alice" {
            owner.account_id = ACCOUNT.into();
        }
    }
    for input in &mut proposal.manifest.inputs {
        if input.account_id == "account-alice" {
            input.account_id = ACCOUNT.into();
        }
    }
    for output in &mut proposal.manifest.outputs {
        if let wholepact_core::OutputAllocation::Return { account_id, .. } = &mut output.allocation
        {
            if account_id == "account-alice" {
                *account_id = ACCOUNT.into();
            }
        }
    }
    let proposal = wholepact_core::Proposal::validate(proposal).unwrap();
    let enrollment = journal
        .record_enrollment(approve_enrollment(
            session,
            EnrollmentTerms {
                account_id: ACCOUNT.into(),
                agreement_id: "agreement-a".into(),
                participant_id: "alice".into(),
                principal_id: "synthetic-owner".into(),
                network_profile_id: proposal.manifest().agreement.network_profile_id.clone(),
                privacy_domain: "synthetic-domain".into(),
                account_fvk_digest: "fa".repeat(32),
                transport: TransportIdentityBinding::RemoteAuthenticatedKeys {
                    transport_identity_id: "synthetic-transport".into(),
                    sender_key_digest: h(51),
                    recipient_key_digest: h(52),
                    channel_binding_digest: h(53),
                },
                aggregate_budget_limit_zatoshis: 1_000_000_000,
                receipt: receipt(session),
            },
        ))
        .unwrap();
    let prepared = session.prepare_manifest(&enrollment, &proposal).unwrap();
    let approved = decision(session, prepared.review_digest());
    let manifest = journal
        .record_accepted_manifest(session.approve_manifest(prepared, approved).unwrap())
        .unwrap();
    (enrollment, manifest)
}

#[cfg(all(
    feature = "pending-birth-owner-signing",
    feature = "offline-review-foundation",
    target_os = "linux"
))]
#[test]
fn named_bearing_restriction_review_preserves_originals_and_monotonic_exclusion() {
    use wholepact_authority::account_use::{
        AccountUseGenesis, AccountUseIdentity, ExclusionReason, PermanentAccountExclusion,
    };
    let f = Fixture::new();
    let genesis = AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: ACCOUNT.into(),
            full_viewing_key_digest: "fa".repeat(32),
            network_profile_id: "synthetic-testnet".into(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        witness_id: "synthetic-witness".into(),
        witness_origin_digest: h(54),
        owner_certificate_digest: h(55),
        native_birth_digest: h(56),
    };
    {
        let c = f.journal.connection.lock().unwrap();
        // Inert historical genesis fixture, never a born publication owner.
        c.execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            params![
                ACCOUNT,
                genesis.identity.full_viewing_key_digest,
                genesis.digest().unwrap(),
                encode(&genesis).unwrap().as_str()
            ],
        )
        .unwrap();
    }
    let before_rows = named_rows(&f.journal.connection.lock().unwrap());
    let (before, display) = f.journal.permanent_stop_local_review(&genesis).unwrap();
    assert_eq!(
        display["named_recipient_history"]["originals"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        display["named_recipient_history"]["started"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        display["named_recipient_history"]["results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        display["named_recipient_exposure"]
            .as_str()
            .unwrap()
            .contains("UNKNOWN")
    );
    assert_eq!(before.retained_rows["signer_named_recipient_profiles"], 1);
    assert_eq!(before.retained_rows["signer_named_intent_outbox"], 1);
    assert_eq!(
        display["named_recipient_history"]["intent_outbox"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let exclusion = PermanentAccountExclusion {
        version: 1,
        identity: genesis.identity.clone(),
        genesis_digest: genesis.digest().unwrap(),
        operation_id: "synthetic-local-stop".into(),
        native_review_digest: h(57),
        reason: ExclusionReason::RetirementRequested,
    };
    {
        let mut c = f.journal.connection.lock().unwrap();
        let tx = c.transaction().unwrap();
        account_use_storage::append_exclusion(&tx, ACCOUNT, &exclusion).unwrap();
        tx.commit().unwrap();
    }
    let (after, _) = f.journal.permanent_stop_local_review(&genesis).unwrap();
    assert!(after.exclusion.is_some());
    assert_eq!(after.writer_epoch, before.writer_epoch);
    assert_eq!(after.recovery_required, before.recovery_required);
    assert_eq!(
        before_rows,
        named_rows(&f.journal.connection.lock().unwrap())
    );
    let mut c = f.journal.connection.lock().unwrap();
    let tx = c.transaction().unwrap();
    let account = storage::read_account(&tx).unwrap();
    assert!(matches!(
        writer_history::WriterLocalInventory::read(&tx, &account, f.journal.capacity_limits()),
        Err(JournalError::NamedRecipientHistoryUnsupported)
    ));
    tx.rollback().unwrap();
}

#[test]
fn named_setup_retry_identity_is_stable_and_indexed_before_new_key_generation() {
    let f = Fixture::new();
    let c = f.journal.connection.lock().unwrap();
    let raw: String = c
        .query_row(
            "SELECT payload FROM signer_named_recipient_profiles",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut profile: NamedRecipientProfileRecordV1 = decode(raw).unwrap();
    let original_reference = profile.reference.clone();
    let stable_setup = profile.original_setup_digest.clone();
    profile.native_review_digest = h(61);
    profile.native_origin_digest = h(62);
    assert_eq!(profile.setup_digest().unwrap(), stable_setup);
    profile.reference = profile.reference_digest().unwrap();
    assert_ne!(profile.reference, original_reference);
    let saved: String = c
        .query_row(
            "SELECT reference FROM signer_named_recipient_profiles WHERE original_setup_digest=?1",
            [&stable_setup],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(saved, original_reference);
    assert!(
        c.execute(
            "INSERT OR REPLACE INTO signer_named_recipient_profiles VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                profile.reference,
                profile.original_setup_digest,
                profile.account_id,
                profile.enrollment_ref,
                profile.manifest_ref,
                encode(&profile).unwrap().as_str()
            ]
        )
        .is_err()
    );
    assert_eq!(
        c.query_row(
            "SELECT reference FROM signer_named_recipient_profiles",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        original_reference
    );
}

#[test]
fn named_receipt_gaps_and_slot_reuse_do_not_erase_retained_sequence() {
    let f = Fixture::new();
    let mut c = f.journal.connection.lock().unwrap();
    let before = named_rows(&c);
    {
        let tx = c.transaction().unwrap();
        tx.execute("INSERT INTO signer_named_recipient_receipts SELECT profile_ref,stream,3,?1,content_hash,payload_digest,envelope_digest,NULL,envelope_hex FROM signer_named_recipient_receipts",[h(63)]).unwrap();
        assert!(matches!(
            validate_archive_rows(&tx, ACCOUNT),
            Err(JournalError::InvalidBinding)
        ));
        tx.rollback().unwrap();
    }
    assert!(c.execute("INSERT INTO signer_named_recipient_receipts SELECT profile_ref,?1,1,?2,content_hash,payload_digest,envelope_digest,immutable_slot,envelope_hex FROM signer_named_recipient_receipts",params![h(64),h(65)]).is_err());
    assert!(c.execute("INSERT INTO signer_named_recipient_receipts SELECT profile_ref,stream,2,message_id,content_hash,payload_digest,envelope_digest,NULL,envelope_hex FROM signer_named_recipient_receipts",[]).is_err());
    assert_eq!(before, named_rows(&c));
}

fn validate_original_fixture(
    original: &NamedRecipientOriginalRecordV1,
    profile: &NamedRecipientProfileRecordV1,
) -> Result<()> {
    #[cfg(feature = "offline-review-foundation")]
    {
        original.validate(profile)
    }
    #[cfg(not(feature = "offline-review-foundation"))]
    {
        original.validate_structure(profile)
    }
}
fn inert_intent_outbox(
    original: &NamedRecipientOriginalRecordV1,
    profile: &NamedRecipientProfileRecordV1,
    sequence: u64,
    raw_message_id: String,
) -> NamedIntentOutboxRecordV1 {
    let ciphertext = b"synthetic inert intent envelope; never sealed, authenticated or emitted";
    #[cfg(feature = "offline-review-foundation")]
    let (stream, message_id, content_hash, payload_digest, preview_json) = {
        use wholepact_transport::*;
        let t = &original.terms;
        let prepared = prepare_export(
            ExportRequest {
                context: MessageContext {
                    network_profile_id: t.network_profile_id.clone(),
                    agreement_id: t.agreement_id.clone(),
                    proposal_id: t.proposal_id.clone(),
                    proposal_revision: t.proposal_revision,
                    sender_id: format!("offline-intent:{}", t.offline_signer_key_digest),
                    recipient_id: format!("offline-intent:{}", t.offline_policy_digest),
                    artifact_kind: ArtifactKind::OfflineReservationIntent,
                },
                order: MessageOrder {
                    message_id: raw_message_id,
                    sequence,
                    issued_at: Timestamp::from_unix_seconds(2).unwrap(),
                    expires_at: Timestamp::from_unix_seconds(30).unwrap(),
                },
                purpose: "Synthetic inert original intent".into(),
                persistence_warning: "Recipient may retain this synthetic fixture".into(),
            },
            vec![
                DisclosureField::new(
                    "offline-reservation-intent-v1",
                    serde_json::to_vec(&original.reservation_request.intent).unwrap(),
                )
                .unwrap(),
                DisclosureField::new(
                    NAMED_REVIEW_BINDING_FIELD_V1,
                    original
                        .named_header(profile)
                        .unwrap()
                        .canonical_bytes()
                        .unwrap(),
                )
                .unwrap(),
            ],
            &TransportPublicKey::from_bytes(profile.transport_public_key).unwrap(),
            &TransportPublicKey::from_bytes(profile.witness_transport_public_key).unwrap(),
            &Timestamp::from_unix_seconds(2).unwrap(),
        )
        .unwrap();
        let metadata = prepared.retained_metadata().unwrap();
        (
            metadata.stream_digest,
            metadata.message_id_digest,
            metadata.content_digest,
            metadata.payload_digest,
            serde_json::to_string(prepared.preview()).unwrap(),
        )
    };
    #[cfg(not(feature = "offline-review-foundation"))]
    let (stream, message_id, content_hash, payload_digest, preview_json) = {
        (
            h(70),
            domain_digest(
                b"wholepact.transport-message.v1\0",
                raw_message_id.as_bytes(),
            ),
            h(72),
            h(73),
            "{}".to_owned(),
        )
    };
    let outbox = NamedIntentOutboxRecordV1 {
        authorization_id: original.terms.authorization_id.clone(),
        original_ref: original.reference.clone(),
        profile_ref: profile.reference.clone(),
        stream,
        sequence,
        message_id,
        content_hash,
        payload_digest,
        envelope_digest: domain_digest(b"wholepact.encrypted-envelope.v1\0", ciphertext),
        preview_json,
        envelope_hex: hex::encode(ciphertext),
    };
    #[cfg(feature = "offline-review-foundation")]
    outbox.validate(original, profile).unwrap();
    #[cfg(not(feature = "offline-review-foundation"))]
    outbox.validate_structure(original, profile).unwrap();
    outbox
}
fn insert_outbox(c: &Connection, outbox: &NamedIntentOutboxRecordV1) {
    try_insert_outbox(c, outbox).unwrap();
}
fn try_insert_outbox(
    c: &Connection,
    outbox: &NamedIntentOutboxRecordV1,
) -> rusqlite::Result<usize> {
    c.execute(
        "INSERT INTO signer_named_intent_outbox VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            outbox.authorization_id,
            outbox.original_ref,
            outbox.profile_ref,
            outbox.stream,
            outbox.sequence,
            outbox.message_id,
            outbox.content_hash,
            outbox.payload_digest,
            outbox.envelope_digest,
            outbox.preview_json,
            outbox.envelope_hex
        ],
    )
}

fn retained_original_fixture(
    c: &Connection,
) -> (
    NamedRecipientProfileRecordV1,
    NamedRecipientOriginalRecordV1,
    NamedIntentOutboxRecordV1,
) {
    let profile = decode(
        c.query_row(
            "SELECT payload FROM signer_named_recipient_profiles",
            [],
            |r| r.get(0),
        )
        .unwrap(),
    )
    .unwrap();
    let original = decode(
        c.query_row(
            "SELECT payload FROM signer_named_recipient_originals",
            [],
            |r| r.get(0),
        )
        .unwrap(),
    )
    .unwrap();
    let outbox = c.query_row("SELECT authorization_id,original_ref,profile_ref,stream,sequence,message_id,content_hash,payload_digest,envelope_digest,preview_json,envelope_hex FROM signer_named_intent_outbox", [], |r| Ok(NamedIntentOutboxRecordV1 {
        authorization_id: r.get(0)?, original_ref: r.get(1)?, profile_ref: r.get(2)?, stream: r.get(3)?, sequence: r.get(4)?,
        message_id: r.get(5)?, content_hash: r.get(6)?, payload_digest: r.get(7)?, envelope_digest: r.get(8)?, preview_json: r.get(9)?, envelope_hex: r.get(10)?,
    })).unwrap();
    (profile, original, outbox)
}
fn rebind_original_fixture(
    original: &mut NamedRecipientOriginalRecordV1,
    profile: &NamedRecipientProfileRecordV1,
) {
    #[cfg(feature = "offline-review-foundation")]
    {
        let header = wholepact_transport::NamedReviewBindingV1 {
            schema_version: 1,
            disclosure_profile: wholepact_transport::NAMED_REVIEW_DISCLOSURE_PROFILE_V1.into(),
            owner_setup_digest: profile.original_setup_digest.clone(),
            assertion_package_digest: original.assertion_package_digest.clone(),
            original_context_digest:
                wholepact_offline_bridge::named_verifier_original_context_digest(&original.terms)
                    .unwrap(),
        };
        original.terms.review_package_digest = header.review_package_digest().unwrap();
    }
    #[cfg(not(feature = "offline-review-foundation"))]
    let _ = profile;
    original.reservation_request.intent.terms = original.terms.clone();
    original.reservation_request_digest = original.reservation_request.request_digest().unwrap();
    original.reference = original.reference_digest().unwrap();
}

#[test]
fn named_intent_retains_complete_request_and_unallocated_template_without_hash_aliasing() {
    let f = Fixture::new();
    let c = f.journal.connection.lock().unwrap();
    let (profile, original, outbox) = retained_original_fixture(&c);
    assert_eq!(
        original.reservation_request_digest,
        original.reservation_request.request_digest().unwrap()
    );
    assert!(original.reservation_request.intent.terms == original.terms);
    assert_ne!(
        original.original_request_digest,
        original.reservation_request_digest
    );
    assert_eq!(original.admission_export_template.sequence, 0);
    let modifications: [fn(&mut NamedRecipientOriginalRecordV1); 6] = [
        |r| r.reservation_request.expected_head.digest = h(81),
        |r| r.reservation_request.expected_head.sequence += 1,
        |r| r.reservation_request.requested_at_ms += 1,
        |r| {
            r.reservation_request
                .intent
                .native_reservation_review_digest = h(82)
        },
        |r| r.admission_export_template.message_id = "83".repeat(16),
        |r| r.admission_export_template.purpose.push('.'),
    ];
    for modify in modifications {
        let mut changed = original.clone();
        modify(&mut changed);
        assert_ne!(changed.reference_digest().unwrap(), original.reference);
        assert!(validate_original_fixture(&changed, &profile).is_err());
        // Rehashing changed data is a different original, never permission to
        // reuse this original's authorization/ciphertext/reference association.
        changed.reservation_request_digest = changed.reservation_request.request_digest().unwrap();
        changed.reference = changed.reference_digest().unwrap();
        assert_ne!(changed.reference, original.reference);
        assert!(outbox.validate_structure(&changed, &profile).is_err());
    }
    for mutate in [
        (|r: &mut NamedRecipientOriginalRecordV1| r.admission_export_template.sequence = 1)
            as fn(&mut NamedRecipientOriginalRecordV1),
        |r| r.reservation_request.intent.terms.review_binding = h(84),
        |r| r.reservation_request.requested_at_ms = 999,
        |r| r.reservation_request.admission_expires_at_ms = 30_001,
        |r| r.admission_export_template.sender_key_fingerprint = h(85),
        |r| r.admission_export_template.recipient_key_fingerprint = h(86),
        |r| r.admission_export_template.issued_at_unix_seconds = 1,
        |r| r.admission_export_template.expires_at_unix_seconds = 31,
    ] {
        let mut changed = original.clone();
        mutate(&mut changed);
        if let Ok(digest) = changed.reservation_request.request_digest() {
            changed.reservation_request_digest = digest;
        }
        changed.reference = changed.reference_digest().unwrap();
        assert!(validate_original_fixture(&changed, &profile).is_err());
    }
}

#[cfg(feature = "offline-review-foundation")]
#[test]
fn named_intent_exact_preview_commits_fields_pins_order_and_private_wire_metadata() {
    let f = Fixture::new();
    let c = f.journal.connection.lock().unwrap();
    let (profile, original, outbox) = retained_original_fixture(&c);
    outbox.validate(&original, &profile).unwrap();
    let changes: [fn(&mut wholepact_transport::DisclosurePreview); 9] = [
        |p| p.order.message_id = "aa".repeat(16),
        |p| p.order.sequence += 1,
        |p| p.order.issued_at = wholepact_transport::Timestamp::from_unix_seconds(1).unwrap(),
        |p| p.order.expires_at = wholepact_transport::Timestamp::from_unix_seconds(31).unwrap(),
        |p| p.context.sender_id = "wrong-sender".into(),
        |p| p.context.proposal_revision += 1,
        |p| p.fields[0].sha256 = h(87),
        |p| p.purpose.push('.'),
        |p| p.recipient_key_fingerprint = h(88),
    ];
    for change in changes {
        let mut changed = outbox.clone();
        let mut preview: wholepact_transport::DisclosurePreview =
            serde_json::from_str(&changed.preview_json).unwrap();
        change(&mut preview);
        changed.preview_json = serde_json::to_string(&preview).unwrap();
        assert!(changed.validate(&original, &profile).is_err());
    }
    let mut changed = outbox.clone();
    changed.preview_json.insert(0, ' ');
    assert!(changed.validate(&original, &profile).is_err());
    let mut changed = outbox.clone();
    changed.envelope_hex.push_str("00");
    assert!(changed.validate(&original, &profile).is_err());
    let mut changed = original.clone();
    changed.assertion_package_digest = h(89);
    changed.reference = changed.reference_digest().unwrap();
    assert!(changed.validate(&profile).is_err());
}

#[test]
fn named_intent_original_outbox_bijection_and_committed_order_fail_closed() {
    let f = Fixture::new();
    let mut c = f.journal.connection.lock().unwrap();
    let before = named_rows(&c);
    let (profile, original, first) = retained_original_fixture(&c);
    // Model corruption of retained rows, never an authorized deletion path.
    {
        let tx = c.transaction().unwrap();
        tx.execute_batch("DROP TRIGGER signer_named_intent_outbox_no_delete; DELETE FROM signer_named_intent_outbox;").unwrap();
        assert!(matches!(
            validate_archive_rows(&tx, ACCOUNT),
            Err(JournalError::InvalidBinding)
        ));
        tx.rollback().unwrap();
    }
    let mut second = original.clone();
    second.terms.authorization_id = "synthetic-distinct-named-authorization".into();
    second.reservation_request.operation_id = "synthetic-distinct-named-operation".into();
    rebind_original_fixture(&mut second, &profile);
    validate_original_fixture(&second, &profile).unwrap();
    for sequence in [2, 3] {
        let tx = c.transaction().unwrap();
        tx.execute(
            "INSERT INTO signer_named_recipient_originals VALUES(?1,?2,?3,?4)",
            params![
                second.reference,
                second.profile_ref,
                second.terms.authorization_id,
                encode(&second).unwrap().as_str()
            ],
        )
        .unwrap();
        // Insertion of an original without its exact outbox is never complete.
        assert!(matches!(
            validate_archive_rows(&tx, ACCOUNT),
            Err(JournalError::InvalidBinding)
        ));
        let next = inert_intent_outbox(&second, &profile, sequence, "24".repeat(16));
        // Distinct authorization/reference must not evade stream collisions.
        let mut same_message = next.clone();
        same_message.message_id = first.message_id.clone();
        assert!(try_insert_outbox(&tx, &same_message).is_err());
        let mut same_sequence = next.clone();
        same_sequence.sequence = first.sequence;
        assert!(try_insert_outbox(&tx, &same_sequence).is_err());
        insert_outbox(&tx, &next);
        if sequence == 2 {
            validate_archive_rows(&tx, ACCOUNT).unwrap();
        } else {
            assert!(matches!(
                validate_archive_rows(&tx, ACCOUNT),
                Err(JournalError::InvalidBinding)
            ));
        }
        tx.rollback().unwrap();
    }
    // SQL rejects collisions before a partial original/outbox can be committed.
    assert!(c.execute("INSERT INTO signer_named_intent_outbox SELECT authorization_id,original_ref,profile_ref,stream,sequence+1,message_id,content_hash,payload_digest,envelope_digest,preview_json,envelope_hex FROM signer_named_intent_outbox", []).is_err());
    let mut mixed = first.clone();
    mixed.original_ref = second.reference.clone();
    assert!(mixed.validate_structure(&original, &profile).is_err());
    mixed = first;
    mixed.profile_ref = h(90);
    assert!(mixed.validate_structure(&original, &profile).is_err());
    assert_eq!(before, named_rows(&c));
}

#[test]
fn named_intent_outbox_only_corruption_still_blocks_unsupported_financial_projection() {
    // Intentionally malformed inert database with FK checks off. An outbox-only
    // trace must never disappear merely because the legacy prefix differs.
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(SCHEMA).unwrap();
    c.pragma_update(None, "foreign_keys", false).unwrap();
    c.execute("INSERT INTO signer_named_intent_outbox VALUES('synthetic-auth',?1,?2,?3,1,?4,?5,?6,?7,'{}','00')", params![h(1),h(2),h(3),h(4),h(5),h(6),h(7)]).unwrap();
    assert!(matches!(
        require_absent(&c),
        Err(JournalError::NamedRecipientHistoryUnsupported)
    ));
    assert!(matches!(
        offline_history::require_accountwide_online_admission(&c),
        Err(JournalError::NamedRecipientHistoryUnsupported)
    ));
    assert!(matches!(
        offline_history::require_legacy_journal(&c),
        Err(JournalError::NamedRecipientHistoryUnsupported)
    ));
}

#[test]
fn named_original_exact_retention_fields_are_required_and_windows_never_refresh() {
    let f = Fixture::new();
    let c = f.journal.connection.lock().unwrap();
    let (profile, original, _) = retained_original_fixture(&c);
    let value = serde_json::to_value(&original).unwrap();
    for field in [
        "assertion_package_digest",
        "validity_not_before_ms",
        "validity_expires_ms",
        "original_request_digest",
        "reservation_request",
        "reservation_request_digest",
        "admission_export_template",
    ] {
        let mut missing = value.clone();
        assert!(missing.as_object_mut().unwrap().remove(field).is_some());
        assert!(serde_json::from_value::<NamedRecipientOriginalRecordV1>(missing).is_err());
    }
    let mut changed = original.clone();
    changed.reservation_request_digest = h(91);
    changed.reference = changed.reference_digest().unwrap();
    assert!(validate_original_fixture(&changed, &profile).is_err());
    let mut changed = original.clone();
    changed.assertion_package_digest = "AA".repeat(32);
    changed.reference = changed.reference_digest().unwrap();
    assert!(validate_original_fixture(&changed, &profile).is_err());
    for (start, end) in [
        (30_000, 30_000),
        (30_001, 30_000),
        (1_999, 2_000),
        (2_001, 30_000),
        (1_000, 29_999),
        (0, 604_801_000),
        (0, u64::MAX),
    ] {
        let mut changed = original.clone();
        changed.validity_not_before_ms = start;
        changed.validity_expires_ms = end;
        changed.reference = changed.reference_digest().unwrap();
        assert!(validate_original_fixture(&changed, &profile).is_err());
    }
}

// Legacy inert Started/results remain losslessly retainable, but cannot be
// upgraded to the new final evidence/return shape by adding one field.
#[test]
fn named_final_evidence_cannot_upgrade_or_downgrade_inert_history() {
    use super::named_recipient_records::{
        NamedRecipientEncryptedReturnV1, NamedRecipientFinalReviewV1,
    };
    let f = Fixture::new();
    let c = f.journal.connection.lock().unwrap();
    let payload = |table: &str| -> String {
        c.query_row(&format!("SELECT payload FROM {table}"), [], |r| r.get(0))
            .unwrap()
    };
    let original: NamedRecipientOriginalRecordV1 =
        decode(payload("signer_named_recipient_originals")).unwrap();
    let mut started: NamedRecipientStartedRecordV1 =
        decode(payload("signer_named_recipient_started")).unwrap();
    let mut result: NamedRecipientResultRecordV1 =
        decode(payload("signer_named_recipient_results")).unwrap();
    assert!(started.final_review.is_none());
    assert!(result.encrypted_return.is_none());
    assert!(started.validate(&original).is_ok());
    assert!(result.validate(&started, &original).is_ok());
    assert!(!encode(&started).unwrap().contains("final_review"));
    assert!(!encode(&result).unwrap().contains("encrypted_return"));
    let old_marker = started.marker_digest().unwrap();
    let (admission, enrollment, provenance) = offline_history::tests::full_admission();
    started.final_review = Some(NamedRecipientFinalReviewV1 {
        schema_version: 1,
        admission,
        enrollment,
        account_policy: provenance.account_policy,
        witness: provenance.witness,
        history_digest: provenance.history_digest,
        assertion_envelope_digest: h(92),
        native_review_digest: started.native_review_digest.clone(),
        consent_reference: h(93),
        reviewed_at_ms: 4_000,
        return_message_id: "94".repeat(16),
        return_sequence: 1,
        return_issued_at: 3,
        return_expires_at: 30,
    });
    assert_ne!(started.marker_digest().unwrap(), old_marker);
    // A different original's otherwise well-formed witness descriptor is not
    // this original's final native decision. Rehashing cannot fix that mismatch.
    let review = started.final_review.as_mut().unwrap();
    review.consent_reference = review.reference_digest().unwrap();
    assert!(started.validate(&original).is_err());
    result.started_digest = started.marker_digest().unwrap();
    assert!(result.validate(&started, &original).is_err());
    started.final_review = None;
    result.started_digest = old_marker;
    let bytes = b"synthetic ciphertext only";
    result.encrypted_return = Some(NamedRecipientEncryptedReturnV1 {
        schema_version: 1,
        signed_artifact_digest: result.result_digest.clone(),
        projection_digest: h(95),
        envelope_digest: domain_digest(b"wholepact.encrypted-envelope.v1\0", bytes),
        envelope_hex: hex::encode(bytes),
    });
    assert!(result.validate(&started, &original).is_err());
}

#[test]
fn absent_born_origin_preserves_exact_legacy_encoding_and_reference() {
    let fixture = Fixture::new();
    let c = fixture.journal.connection.lock().unwrap();
    let raw: String = c
        .query_row(
            "SELECT payload FROM signer_named_recipient_originals",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let original: NamedRecipientOriginalRecordV1 = decode(raw.clone()).unwrap();
    assert!(original.born_origin.is_none());
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(parsed.get("born_origin").is_none());
    assert_eq!(encode(&original).unwrap().as_str(), raw);
    let legacy = digest(
        "wholepact:named-recipient-original:v1",
        &(
            original.schema_version,
            &original.profile_ref,
            &original.terms,
            &original.original_artifact_digest,
            &original.canonical_artifact_digest,
            &original.transformation_digest,
            &original.named_assertion_digest,
            &original.assertion_package_digest,
            original.validity_not_before_ms,
            original.validity_expires_ms,
            &original.original_request_digest,
            &original.reservation_request,
            &original.reservation_request_digest,
            &original.admission_export_template,
            &original.own_policy_digest,
            &original.own_expectations,
        ),
    )
    .unwrap();
    assert_eq!(original.reference_digest().unwrap(), legacy);
    assert_eq!(original.reference, legacy);
    original.require_legacy_origin().unwrap();
}

#[test]
fn absent_born_final_preserves_legacy_started_bytes_and_marker_domain() {
    let f = Fixture::new();
    let c = f.journal.connection.lock().unwrap();
    let raw: String = c
        .query_row(
            "SELECT payload FROM signer_named_recipient_started",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let started: NamedRecipientStartedRecordV1 = decode(raw.clone()).unwrap();
    assert!(started.born_final_review.is_none());
    assert!(
        serde_json::from_str::<serde_json::Value>(&raw)
            .unwrap()
            .get("born_final_review")
            .is_none()
    );
    assert_eq!(encode(&started).unwrap().as_str(), raw);
    assert_eq!(
        started.marker_digest().unwrap(),
        digest("wholepact:named-recipient-started:v1", &started).unwrap()
    );
    assert!(started.return_metadata().is_err());
}

#[test]
fn inert_born_final_fields_cannot_be_attached_to_a_legacy_original() {
    // Intentionally untrusted serialized evidence, not a positive born lineage
    // fixture or a native/session/clock capability. Reject before key code exists.
    let f = Fixture::new();
    let c = f.journal.connection.lock().unwrap();
    let (profile, original, _) = retained_original_fixture(&c);
    let raw: String = c
        .query_row(
            "SELECT payload FROM signer_named_recipient_started",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut started: NamedRecipientStartedRecordV1 = decode(raw).unwrap();
    let (admission, enrollment, account) = offline_history::tests::full_admission();
    let _ = account;
    let request = wholepact_authority::born_offline_admission_v1::BornOfflineReservationRequestV1 {
        version: 1,
        enrollment_digest: h(71),
        artifact_binding_digest: h(72),
        construction_link:
            wholepact_authority::born_offline_construction_v1::BornOfflineConstructionLinkV1 {
                version: 1,
                reservation_operation_id: "inert-construction".into(),
                consume_operation_id: "inert-consume".into(),
                reservation_digest: h(73),
                consume_digest: h(74),
                plan_digest: h(75),
                common_context_digest: h(76),
                invocation_digest: h(77),
                checkpoint_origin_digest: h(78),
            },
        reservation: original.reservation_request.clone(),
    };
    let mut plan = original.admission_export_template.clone();
    plan.sequence = 1;
    let review = named_recipient_records::BornNamedRecipientFinalReviewV1 {
        schema_version: 1,
        admission:
            wholepact_authority::born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1 {
                version: 1,
                request,
                reserved: admission.clone(),
            },
        origin_digest: h(79),
        witness: wholepact_authority::WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:1".into(),
            server_name: "localhost".into(),
            witness_id: admission.witness_id.clone(),
            account_id: original.terms.account_id.clone(),
            network_profile_id: original.terms.network_profile_id.clone(),
            policy_digest: admission.witness_policy_digest.clone(),
            pinned_server_certificate_digest: enrollment.witness_certificate_digest.clone(),
        },
        history_digest: h(80),
        assertion_envelope_digest: h(81),
        admission_receipt: named_recipient_records::BornNamedAdmissionReceiptV1 {
            version: 1,
            profile_ref: profile.reference.clone(),
            original_ref: original.reference.clone(),
            original_admission_digest: h(82),
            export_plan: plan,
            stream_digest: h(83),
            sequence: 1,
            message_id_digest: h(84),
            content_digest: h(85),
            payload_digest: h(86),
            envelope_digest: h(87),
            immutable_slot_digest: h(88),
        },
        native_review_digest: started.native_review_digest.clone(),
        consent_reference: h(89),
        reviewed_at_ms: 2000,
        return_message_id: "90".repeat(16),
        return_sequence: 1,
        return_issued_at: 2,
        return_expires_at: 30,
    };
    started.born_final_review = Some(review);
    assert!(started.validate(&original).is_err());
    assert_ne!(
        started.marker_digest().unwrap(),
        digest("wholepact:named-recipient-started:v1", &started).unwrap()
    );
    // A hash that is valid syntax but the wrong origin cannot revive historical
    // inert rows or turn the inner legacy request into a born final approval.
    started.admission_request_digest = started
        .born_final_review
        .as_ref()
        .unwrap()
        .admission
        .request
        .request_digest()
        .unwrap();
    assert!(started.validate(&original).is_err());
}

#[test]
fn named_legacy_profile_keeps_exact_encoding_and_commitments_without_born_binding() {
    let f = Fixture::new();
    let c = f.journal.connection.lock().unwrap();
    let raw: String = c
        .query_row(
            "SELECT payload FROM signer_named_recipient_profiles",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let profile: NamedRecipientProfileRecordV1 = decode(raw).unwrap();
    assert!(profile.born_profile.is_none());
    let json = serde_json::to_value(&profile).unwrap();
    assert!(json.get("born_profile").is_none());
    assert_eq!(profile.witness_enrollment_ref(), profile.enrollment_ref);
    let old_setup = digest(
        "wholepact:named-recipient-setup:v1",
        &(
            profile.schema_version,
            &profile.account_id,
            &profile.full_viewing_key_digest,
            &profile.enrollment_ref,
            &profile.manifest_ref,
            &profile.verifier_signing_public_key,
            &profile.verifier_transport_public_key,
            &profile.witness_transport_public_key,
            &profile.witness_certificate_digest,
            &profile.return_transport_public_key,
        ),
    )
    .unwrap();
    let old_reference = digest(
        "wholepact:named-recipient-profile:v1",
        &(
            &old_setup,
            &profile.native_review_digest,
            &profile.native_origin_digest,
            &profile.transport_public_key,
        ),
    )
    .unwrap();
    assert_eq!(profile.original_setup_digest, old_setup);
    assert_eq!(profile.reference, old_reference);
    let decoded: NamedRecipientProfileRecordV1 = serde_json::from_value(json.clone()).unwrap();
    assert!(decoded == profile);
    assert!(serde_json::to_value(decoded).unwrap() == json);
    let mut unsupported = json;
    unsupported["born_profile"] = serde_json::json!({"version":1});
    assert!(serde_json::from_value::<NamedRecipientProfileRecordV1>(unsupported).is_err());
}
