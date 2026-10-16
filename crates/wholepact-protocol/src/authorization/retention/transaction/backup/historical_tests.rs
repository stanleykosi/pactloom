//! Encrypted synthetic historical-artifact routing only. The signed-result bytes
//! are deliberately not a PCZT and the serialized empty transaction is not a
//! payable consensus transaction. No proof, signing, socket or network is used.
use super::*;
use crate::authorization::retention::backup::{
    archived_historical_signed_result, archived_historical_transaction,
    archived_historical_transaction_export, historical_signed_result, historical_transaction,
    historical_transaction_export,
};
use wholepact_storage_security::bundle::recovery::evidence::{RecoveredEvidence, history::*};
type Result<T> = std::result::Result<T, BundleError>;
use crate::authorization::retention::{
    self as retention, SignedCandidateContext, SignedResultJournal, SignedRetentionScope,
    transaction::{TransactionCheckpointJournal, TransactionRetentionScope},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use wholepact_storage_security::{
    DatabaseKey,
    bundle::{
        self,
        recovery::{VerifiedRecoveryComponent, generation::GenerationBinding},
        *,
    },
    create_encrypted,
};

static COORDINATION: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: 0,
    schema_version: 1,
    create_sql: "CREATE TABLE fixture(id TEXT PRIMARY KEY);",
};
struct Coordination(Mutex<wholepact_storage_security::EncryptedConnection>);
impl JournalAdapter for Coordination {
    fn template(&self) -> &'static JournalTemplate {
        &COORDINATION
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&rusqlite::Connection) -> Result<()>,
    ) -> Result<()> {
        permit.check(self)?;
        visitor(
            self.0
                .lock()
                .map_err(|_| BundleError::Storage)?
                .connection(),
        )
    }
}
struct BackupGate;
impl BundleLease for BackupGate {
    fn check_current(&self) -> Result<()> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "synthetic-retained-history"
    }
}
impl BundleAuthority for BackupGate {
    fn acquire<'a>(&'a self, scope: &BundleScope<'_>) -> Result<Box<dyn BundleLease + 'a>> {
        if scope.principal_id != "synthetic-admin" || scope.profile_id != "synthetic-profile" {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(BackupGate))
    }
}
struct Gate {
    binding: HistoricalSourceBinding,
    origin: HistoricalOrigin,
    one_shot: bool,
    effect_taken: AtomicBool,
    action: HistoricalAction,
    destination: HistoricalDestination,
    revoked: AtomicBool,
    fence: Mutex<()>,
}
struct Lease<'a> {
    scope: HistoricalDisclosureScope,
    gate: &'a Gate,
}
impl HistoricalDisclosureLease for Lease<'_> {
    fn scope(&self) -> &HistoricalDisclosureScope {
        &self.scope
    }
    fn check_current(&self) -> Result<()> {
        if self.gate.revoked.load(Ordering::SeqCst) {
            Err(BundleError::Permission)
        } else {
            Ok(())
        }
    }
    fn run_effect(&self, effect: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let _held = self
            .gate
            .fence
            .lock()
            .map_err(|_| BundleError::Permission)?;
        self.check_current()?;
        if self.gate.one_shot && self.gate.effect_taken.swap(true, Ordering::SeqCst) {
            return Err(BundleError::Permission);
        }
        effect()
    }
}
impl HistoricalDisclosureAuthority for Gate {
    fn acquire<'a>(
        &'a self,
        scope: &HistoricalDisclosureScope,
    ) -> Result<Box<dyn HistoricalDisclosureLease + 'a>> {
        if scope.source != self.binding
            || scope.origin != self.origin
            || (self.one_shot && self.effect_taken.load(Ordering::SeqCst))
            || scope.action != self.action
            || scope.destination != self.destination
            || scope.principal_id != "synthetic-native-reader"
            || scope.references.account_ids != ["synthetic-account"]
            || scope.references.proof_job_id.as_deref() != Some("synthetic-proof")
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(Lease {
            scope: scope.clone(),
            gate: self,
        }))
    }
}
fn gate(
    source: &RecoveredEvidence,
    action: HistoricalAction,
    destination: HistoricalDestination,
) -> Gate {
    Gate {
        binding: source.historical_binding(),
        origin: HistoricalOrigin::from_evidence(source),
        one_shot: false,
        effect_taken: AtomicBool::new(false),
        action,
        destination,
        revoked: AtomicBool::new(false),
        fence: Mutex::new(()),
    }
}
fn key() -> DatabaseKey {
    DatabaseKey::from_bytes([191; 32])
}
fn context() -> SignedCandidateContext {
    SignedCandidateContext {
        principal_id: "synthetic-owner".into(),
        candidate_id: "synthetic-candidate".into(),
        proof_job_id: "synthetic-proof".into(),
        checkpoint_scope_digest: "11".repeat(32),
        proved_artifact_digest: "22".repeat(32),
        manifest_digest: "33".repeat(32),
        review_binding: "44".repeat(32),
        delivery_provenance_digest: "55".repeat(32),
        account_ids: vec!["synthetic-account".into()],
        local_operator: "synthetic-operator".into(),
        purpose: "synthetic structural history test".into(),
        retention_policy: "private test fixture only".into(),
    }
}
fn evidence(
    dir: &Path,
) -> (
    RecoveredEvidence,
    RecoveredEvidence,
    String,
    String,
    Vec<u8>,
) {
    let c = create_encrypted(dir.join("coordination"), &key()).unwrap();
    c.connection()
        .execute_batch(COORDINATION.create_sql)
        .unwrap();
    c.connection()
        .pragma_update(None, "user_version", 1)
        .unwrap();
    let coordination = Coordination(Mutex::new(c));
    let signed = SignedResultJournal::from_encrypted_connection(
        create_encrypted(dir.join("signed"), &key()).unwrap(),
    )
    .unwrap();
    let transactions = TransactionCheckpointJournal::from_encrypted_connection(
        create_encrypted(dir.join("transactions"), &key()).unwrap(),
    )
    .unwrap();
    let signatures = b"synthetic-signature-set-not-signatures";
    let signed_bytes = b"synthetic-retained-result-not-a-PCZT";
    let signed_scope = SignedRetentionScope {
        context: context(),
        signature_set_digest: retention::hash(signatures),
    };
    let encoded = serde_json::to_vec(&signed_scope).unwrap();
    let idem = "synthetic-historical-result-key";
    let signed_id = format!(
        "signed-{}",
        retention::framed(&[b"synthetic-owner", idem.as_bytes()])
    );
    let signed_request = retention::framed(&[&encoded, signatures, &1u64.to_le_bytes()]);
    signed
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO signed_intents VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                signed_id,
                "synthetic-owner",
                idem,
                signed_request,
                encoded,
                signatures.as_slice()
            ],
        )
        .unwrap();
    signed
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO signed_results VALUES(?1,?2,?3)",
            rusqlite::params![
                signed_id,
                signed_bytes.as_slice(),
                retention::hash(signed_bytes)
            ],
        )
        .unwrap();
    let tx_scope = TransactionRetentionScope {
        signed_scope,
        signed_result_id: signed_id.clone(),
        signed_request_digest: signed_request,
        signed_candidate_digest: retention::hash(signed_bytes),
    };
    let encoded = serde_json::to_vec(&tx_scope).unwrap();
    let tx_request = retention::framed(&[b"transaction-checkpoint-v1", &encoded]);
    let checkpoint = format!(
        "transaction-{}",
        retention::framed(&[b"transaction-id-v1", signed_id.as_bytes()])
    );
    // Structurally readable, zero-input/zero-output bytes only. No spend signature
    // or consensus/payability claim follows from this synthetic fixture.
    let tx = zcash_primitives::transaction::TransactionData::<
        zcash_primitives::transaction::Authorized,
    >::from_parts(
        zcash_primitives::transaction::TxVersion::V5,
        zcash_protocol::consensus::BranchId::Nu7,
        0,
        zcash_protocol::consensus::BlockHeight::from_u32(1),
        None,
        None,
        None,
        None,
    )
    .freeze()
    .unwrap();
    let mut bytes = vec![];
    tx.write(&mut bytes).unwrap();
    transactions
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO transaction_intents VALUES(?1,?2,?3,?4)",
            rusqlite::params![checkpoint, signed_id, tx_request, encoded],
        )
        .unwrap();
    transactions
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO transaction_results VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                checkpoint,
                bytes,
                retention::hash(&bytes),
                tx.txid().to_string()
            ],
        )
        .unwrap();
    let signed_adapter = retention::backup::SignedResultsBackupAdapter::new(&signed);
    let tx_adapter =
        retention::transaction::backup::ExactTransactionsBackupAdapter::new(&transactions);
    let sources = [
        RegisteredJournal::new("coordination", &coordination).unwrap(),
        RegisteredJournal::new("signed", &signed_adapter).unwrap(),
        RegisteredJournal::new("transactions", &tx_adapter).unwrap(),
    ];
    let archive = dir.join("archive");
    snapshot(SnapshotRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        sources: &sources,
        destination: &archive,
        key: &key(),
        authority: &BackupGate,
        coverage: Coverage {
            present: BTreeMap::from([
                (
                    JournalKind::CoordinationAuthority,
                    vec!["coordination".into()],
                ),
                (JournalKind::SignedResults, vec!["signed".into()]),
                (JournalKind::ExactTransactions, vec!["transactions".into()]),
            ]),
            absent: BTreeSet::from([
                JournalKind::SignerConsentAuthority,
                JournalKind::WalletScan,
                JournalKind::ProofWitness,
                JournalKind::Submission,
                JournalKind::TransportInbox,
                JournalKind::TransportOutbox,
            ]),
        },
    })
    .unwrap();
    let restored_c = dir.join("restored-c");
    let restored_s = dir.join("restored-s");
    let restored_t = dir.join("restored-t");
    test_restore(RestoreRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        archive: &archive,
        key: &key(),
        authority: &BackupGate,
        targets: &[
            RestoreTarget {
                component_id: "coordination",
                template: &COORDINATION,
                destination: &restored_c,
                key: &key(),
            },
            RestoreTarget {
                component_id: "signed",
                template: &retention::backup::TEMPLATE,
                destination: &restored_s,
                key: &key(),
            },
            RestoreTarget {
                component_id: "transactions",
                template: &retention::transaction::backup::TEMPLATE,
                destination: &restored_t,
                key: &key(),
            },
        ],
    })
    .unwrap();
    let open = |component, path: &Path, template| {
        VerifiedRecoveryComponent::open(
            bundle::history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &key(),
                component_id: component,
                restored_component: path,
                restored_key: &key(),
            },
            template,
        )
        .unwrap()
    };
    let s = open("signed", &restored_s, &retention::backup::TEMPLATE);
    let t = open(
        "transactions",
        &restored_t,
        &retention::transaction::backup::TEMPLATE,
    );
    let binding = GenerationBinding::new(&"66".repeat(32), &"77".repeat(32)).unwrap();
    let history_s = dir.join("history-s");
    let history_t = dir.join("history-t");
    retention::backup::reconstruct_signed_results_successor_evidence(
        &s,
        &history_s,
        &key(),
        &binding,
    )
    .unwrap();
    retention::transaction::backup::reconstruct_transactions_successor_evidence(
        &t,
        &history_t,
        &key(),
        &binding,
    )
    .unwrap();
    let s = retention::backup::open_signed_results_successor_evidence(
        &history_s,
        &key(),
        &binding,
        s.provenance(),
    )
    .unwrap();
    let t = retention::transaction::backup::open_transactions_successor_evidence(
        &history_t,
        &key(),
        &binding,
        t.provenance(),
    )
    .unwrap();
    (s, t, signed_id, checkpoint, bytes)
}
#[test]
fn typed_metadata_and_exact_export_preserve_historical_scope_without_replay() {
    let dir = std::env::temp_dir().join(format!(
        "wholepact-historical-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (signed, tx, signed_id, checkpoint, bytes) = evidence(&dir);
    let sgate = gate(
        &signed,
        HistoricalAction::SignedResultMetadata,
        HistoricalDestination::NativeTerminal,
    );
    historical_signed_result(&signed, "synthetic-native-reader", &signed_id, &sgate)
        .unwrap()
        .deliver(|metadata| {
            assert_eq!(
                metadata.references.signed_result_id.as_deref(),
                Some(signed_id.as_str())
            );
            assert!(
                !metadata.restrictions.current_authority && !metadata.restrictions.replay_allowed
            );
            Ok(())
        })
        .unwrap();
    let tgate = gate(
        &tx,
        HistoricalAction::TransactionMetadata,
        HistoricalDestination::NativeTerminal,
    );
    historical_transaction(&tx, "synthetic-native-reader", &checkpoint, &tgate)
        .unwrap()
        .deliver(|metadata| {
            assert_eq!(metadata.retained_transaction_bytes, Some(bytes.len()));
            assert_eq!(
                metadata.references.signed_result_id.as_deref(),
                Some(signed_id.as_str())
            );
            assert_eq!(
                metadata.references.proof_job_id.as_deref(),
                Some("synthetic-proof")
            );
            assert!(
                !metadata.restrictions.replay_allowed && !metadata.restrictions.replacement_allowed
            );
            Ok(())
        })
        .unwrap();
    let destination = dir.join("selected-exact.tx");
    let export_gate = gate(
        &tx,
        HistoricalAction::ExportExactTransaction,
        HistoricalDestination::NewPrivateLocalFile(destination.clone()),
    );
    historical_transaction_export(
        &tx,
        "synthetic-native-reader",
        &checkpoint,
        &destination,
        &export_gate,
    )
    .unwrap()
    .export()
    .unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&destination)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        historical_transaction_export(
            &tx,
            "synthetic-native-reader",
            &checkpoint,
            &destination,
            &export_gate
        )
        .unwrap()
        .export()
        .is_err()
    );
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    let denied = dir.join("denied.tx");
    assert!(
        historical_transaction_export(
            &tx,
            "synthetic-native-reader",
            &checkpoint,
            &denied,
            &export_gate
        )
        .is_err()
    );
    let revoked = dir.join("revoked.tx");
    let revoked_gate = gate(
        &tx,
        HistoricalAction::ExportExactTransaction,
        HistoricalDestination::NewPrivateLocalFile(revoked.clone()),
    );
    let pending = historical_transaction_export(
        &tx,
        "synthetic-native-reader",
        &checkpoint,
        &revoked,
        &revoked_gate,
    )
    .unwrap();
    revoked_gate.revoked.store(true, Ordering::SeqCst);
    assert!(pending.export().is_err());
    assert!(!revoked.exists());
    assert!(!denied.exists());
    drop(signed);
    drop(tx);
    std::fs::remove_dir_all(&dir).unwrap();
}

// These archives contain only the synthetic journals created above. All source
// journal owners have been dropped before capture; no worker can mutate them.
use wholepact_storage_security::generation_archive as capsule;
struct CapsuleGate(capsule::ArchiveScope);
impl capsule::ArchiveAuthority for CapsuleGate {
    fn acquire<'a>(
        &'a self,
        scope: &capsule::ArchiveScope,
    ) -> capsule::Result<Box<dyn capsule::ArchiveLease + 'a>> {
        if *scope != self.0 {
            return Err(capsule::ArchiveError::Permission);
        }
        Ok(Box::new(CapsuleLease))
    }
}
struct CapsuleLease;
impl capsule::ArchiveLease for CapsuleLease {
    fn check_current(&self) -> capsule::Result<()> {
        Ok(())
    }
}
fn capsule(
    dir: &Path,
    output: &Path,
    name: &str,
    index: u8,
    parents: &[&capsule::VerifiedArchive],
) -> capsule::VerifiedArchive {
    let destination = output.join(name);
    let signed = dir.join("signed");
    let transaction = dir.join("transactions");
    let sources = [
        capsule::RegisteredSource::new(
            "signed",
            "current-signed-results",
            capsule::Source::Journal(&signed),
        )
        .unwrap(),
        capsule::RegisteredSource::new(
            "transactions",
            "current-transactions",
            capsule::Source::Journal(&transaction),
        )
        .unwrap(),
    ];
    let node = capsule::NodeSpec {
        generation_id: format!("{index:02x}").repeat(32),
        profile_id: "synthetic-capsule-profile".into(),
        original_root: dir.into(),
    };
    let capsule_id = format!("{:02x}", index + 1).repeat(32);
    let scope = capsule::ArchiveScope::for_snapshot(
        &destination,
        &key(),
        &capsule_id,
        &node,
        &sources,
        parents,
    )
    .unwrap();
    capsule::snapshot(capsule::SnapshotRequest {
        destination: &destination,
        key: &key(),
        capsule_id: &capsule_id,
        node: &node,
        sources: &sources,
        parents,
        authority: &CapsuleGate(scope),
    })
    .unwrap();
    capsule::inspect(&destination, &key()).unwrap()
}
fn archived_gate(
    source: &capsule::ArchivedOrdinarySource,
    action: HistoricalAction,
    destination: HistoricalDestination,
) -> Gate {
    Gate {
        binding: source.disclosure_identity().binding(),
        origin: source.disclosure_identity().origin(),
        action,
        destination,
        one_shot: true,
        effect_taken: AtomicBool::new(false),
        revoked: AtomicBool::new(false),
        fence: Mutex::new(()),
    }
}
#[test]
fn archived_metadata_and_export_bind_exact_root_node_entry_and_one_shot_effect() {
    let dir = std::env::temp_dir().join(format!(
        "wholepact-archived-artifacts-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Keep archive writes outside every original source root and journal parent.
    let sources = dir.join("source-journals");
    let output = dir.join("capsules");
    for private in [&sources, &output] {
        std::fs::create_dir(private).unwrap();
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let (legacy_signed, legacy_tx, signed_id, checkpoint, bytes) = evidence(&sources);
    let parent = capsule(&sources, &output, "parent-capsule", 201, &[]);
    let child = capsule(&sources, &output, "child-capsule", 203, &[&parent]);
    let archived_signed = parent
        .journal(parent.manifest_digest(), "signed")
        .unwrap()
        .inspect_ordinary(&key(), &retention::backup::TEMPLATE)
        .unwrap();
    let open_tx = |archive: &capsule::VerifiedArchive, selected: &str| {
        archive
            .journal(selected, "transactions")
            .unwrap()
            .inspect_ordinary(&key(), &retention::transaction::backup::TEMPLATE)
            .unwrap()
    };
    let archived_tx = open_tx(&parent, parent.manifest_digest());
    let same_node_new_root = open_tx(&child, parent.manifest_digest());
    let other_node = open_tx(&child, child.manifest_digest());
    let same_reopened = open_tx(&parent, parent.manifest_digest());
    assert_eq!(
        archived_tx.provenance().component_digest,
        same_node_new_root.provenance().component_digest
    );
    assert_eq!(
        archived_tx.provenance().component_digest,
        other_node.provenance().component_digest
    );
    assert_eq!(
        archived_tx.provenance().component_digest,
        same_reopened.provenance().component_digest
    );
    let sgate = archived_gate(
        &archived_signed,
        HistoricalAction::SignedResultMetadata,
        HistoricalDestination::NativeTerminal,
    );
    archived_historical_signed_result(
        &archived_signed,
        "synthetic-native-reader",
        &signed_id,
        &sgate,
    )
    .unwrap()
    .deliver(|metadata| {
        assert!(sgate.fence.try_lock().is_err());
        assert!(metadata.origin.archive.is_some());
        assert_eq!(
            metadata.retained_result_digest.as_deref(),
            Some(retention::hash(b"synthetic-retained-result-not-a-PCZT").as_str())
        );
        assert_eq!(metadata.restrictions.authorization_exposure, "unknown");
        assert_eq!(
            metadata.restrictions.external_signatures,
            "unknown_possible"
        );
        assert!(!metadata.restrictions.current_authority);
        Ok(())
    })
    .unwrap();
    let tgate = archived_gate(
        &archived_tx,
        HistoricalAction::TransactionMetadata,
        HistoricalDestination::NativeTerminal,
    );
    for substituted in [&same_node_new_root, &other_node, &same_reopened] {
        assert!(
            archived_historical_transaction(
                substituted,
                "synthetic-native-reader",
                &checkpoint,
                &tgate
            )
            .is_err()
        );
    }
    assert!(
        historical_transaction(&legacy_tx, "synthetic-native-reader", &checkpoint, &tgate).is_err()
    );
    assert!(
        archived_historical_transaction(
            &archived_signed,
            "synthetic-native-reader",
            &checkpoint,
            &tgate
        )
        .is_err()
    );
    let first = archived_historical_transaction(
        &archived_tx,
        "synthetic-native-reader",
        &checkpoint,
        &tgate,
    )
    .unwrap();
    let second = archived_historical_transaction(
        &archived_tx,
        "synthetic-native-reader",
        &checkpoint,
        &tgate,
    )
    .unwrap();
    first
        .deliver(|metadata| {
            assert!(tgate.fence.try_lock().is_err());
            let archive = metadata.origin.archive.as_ref().unwrap();
            assert_eq!(archive.root_manifest_digest(), parent.manifest_digest());
            assert_eq!(archive.selected_manifest_digest(), parent.manifest_digest());
            assert_eq!(
                archive.selected_node_digest(),
                parent.manifest().node_digest
            );
            assert_eq!(metadata.retained_transaction_bytes, Some(bytes.len()));
            assert_eq!(metadata.restrictions.authorization_exposure, "unknown");
            assert_eq!(
                metadata.restrictions.chain_observation,
                "unknown_historical_observations_only"
            );
            assert!(
                !metadata.restrictions.replay_allowed && !metadata.restrictions.replacement_allowed
            );
            Ok(())
        })
        .unwrap();
    let mut leaked = false;
    assert!(
        second
            .deliver(|_| {
                leaked = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!leaked);
    let destination = dir.join("archived-exact.tx");
    let export = archived_gate(
        &archived_tx,
        HistoricalAction::ExportExactTransaction,
        HistoricalDestination::NewPrivateLocalFile(destination.clone()),
    );
    let pending = archived_historical_transaction_export(
        &archived_tx,
        "synthetic-native-reader",
        &checkpoint,
        &destination,
        &export,
    )
    .unwrap();
    for substituted in [&same_node_new_root, &other_node, &same_reopened] {
        assert!(
            archived_historical_transaction_export(
                substituted,
                "synthetic-native-reader",
                &checkpoint,
                &destination,
                &export
            )
            .is_err()
        );
    }
    let blocked = dir.join("wrong-destination.tx");
    assert!(
        archived_historical_transaction_export(
            &archived_tx,
            "synthetic-native-reader",
            &checkpoint,
            &blocked,
            &export
        )
        .is_err()
    );
    pending.export().unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&destination)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        archived_historical_transaction_export(
            &archived_tx,
            "synthetic-native-reader",
            &checkpoint,
            &destination,
            &export
        )
        .is_err()
    );
    let revoked_destination = dir.join("revoked-archived.tx");
    let revoked_gate = archived_gate(
        &archived_tx,
        HistoricalAction::ExportExactTransaction,
        HistoricalDestination::NewPrivateLocalFile(revoked_destination.clone()),
    );
    let revoked = archived_historical_transaction_export(
        &archived_tx,
        "synthetic-native-reader",
        &checkpoint,
        &revoked_destination,
        &revoked_gate,
    )
    .unwrap();
    revoked_gate.revoked.store(true, Ordering::SeqCst);
    assert!(revoked.export().is_err());
    assert!(!revoked_destination.exists() && !blocked.exists());
    drop((
        legacy_signed,
        legacy_tx,
        archived_signed,
        archived_tx,
        same_node_new_root,
        other_node,
        same_reopened,
        parent,
        child,
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}
