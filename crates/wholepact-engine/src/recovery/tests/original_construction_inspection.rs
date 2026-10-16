//! Actual encrypted historical metadata readers only. Fixture rows are inert,
//! expired synthetic history, not native owners, construction tokens or proofs.
use super::*;
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use wholepact_core::manual_enrollment::ManualHostGenerationBinding;
use wholepact_proof_jobs::{
    CheckpointScope, JobState, LocalAction, LocalProofConsent, ProofJobStore, ProofStatusSnapshot,
};
use wholepact_storage_security::{
    EncryptedConnection, bundle::recovery::generation::RecoveredGenerationConnection,
};
use wholepact_store::manual_enrollment::{
    ManualRosterConstructionCheckpointV2, ManualRosterConstructionClaimV2,
};

#[path = "original_construction_inspection/fixtures.rs"]
mod fixtures;

const CLAIM: &str = "generation_manual_construction_claim_v2";
const RECEIPT: &str = "generation_manual_construction_checkpoint_v2";

struct Fixture {
    _engine: Engine,
    _jobs: ProofJobStore,
    rows: RecoveredGenerationConnection,
    job_rows: EncryptedConnection,
    claim: ManualRosterConstructionClaimV2,
    receipt: ManualRosterConstructionCheckpointV2,
    host: ManualHostGenerationBinding,
    selected: Access,
    // Hold all original handles until after assertions; closing a writer can
    // checkpoint or remove sidecars and must not be confused with an inspection.
    _source_engine: Engine,
    _source: VerifiedRecoveryComponent,
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new(with_receipt: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source_engine = Engine::from_store(
            Store::create_encrypted(dir.path().join("source.sqlite"), &key(171)).unwrap(),
        );
        let owner = Access {
            principal_id: "synthetic-principal".into(),
            include_owned_agreements: true,
            ..Access::default()
        };
        source_engine
            .create(
                &owner,
                "synthetic-history-key",
                draft("unrelated-inherited-history"),
            )
            .unwrap();
        let source = source(&source_engine, dir.path());
        let inventory = inspect_coordination_recovery(&source).unwrap();
        let binding = bundle::recovery::generation::GenerationBinding::new(
            &"e".repeat(64),
            inventory.digest(),
        )
        .unwrap();
        let path = dir.path().join("successor.sqlite");
        Store::reconstruct_recovered_generation(&source, &path, &key(174), &binding).unwrap();
        let engine = Engine::from_store(
            Store::open_recovered_generation(&path, &key(174), &binding, source.provenance())
                .unwrap(),
        );
        let agreement = fixtures::economics().agreement;
        engine
            .create(&owner, "synthetic-current-agreement-key", agreement.clone())
            .unwrap();
        let selected = Access {
            principal_id: owner.principal_id.clone(),
            agreement_ids: BTreeSet::from([agreement.agreement_id.clone()]),
            all_agreements: false,
            include_owned_agreements: false,
        };
        let target = engine
            .manual_enrollment_intent_target(&selected, &agreement.agreement_id)
            .unwrap();
        let host = ManualHostGenerationBinding {
            generation_id: target.generation_id().into(),
            inventory_digest: target.inventory_digest().into(),
            store_destination_identity: target.store_destination_identity().into(),
            generation_plan_digest: "1".repeat(64),
            financial_journal_origin_digest: "2".repeat(64),
            profile_id: "synthetic-profile".into(),
            canonical_root: "/synthetic/host".into(),
            destination_identity_digest: "3".repeat(64),
            inherited_identity_digest: "4".repeat(64),
            scope_predecessor_digest: None,
        };
        drop(target);
        drop(engine);
        let rows = bundle::recovery::generation::open_recovered_generation(
            &path,
            &key(174),
            &binding,
            source.provenance(),
            wholepact_store::recovery::coordination_successor_template(),
        )
        .unwrap();
        let (claim, _, history) = fixtures::historical_rows(&host, with_receipt);
        for (kind, id, payload) in history {
            rows.connection()
                .execute(
                    "INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
                    [kind, id, payload],
                )
                .unwrap();
        }
        let receipt = fixtures::checkpoint(&claim);
        let engine = Engine::from_store(
            Store::open_recovered_generation(&path, &key(174), &binding, source.provenance())
                .unwrap(),
        );
        // Initialize the real encrypted proof journal, then retain independent
        // fixture-only SQL access for deliberate history changes between reads.
        let job_path = dir.path().join("proof.sqlite");
        let jobs = ProofJobStore::from_encrypted_connection(
            wholepact_storage_security::create_encrypted(&job_path, &key(175)).unwrap(),
        )
        .unwrap();
        let job_rows = wholepact_storage_security::open_encrypted(&job_path, &key(175)).unwrap();
        fs::create_dir(dir.path().join("nested-preserved")).unwrap();
        fs::write(
            dir.path().join("nested-preserved/untouched"),
            b"synthetic tree sentinel",
        )
        .unwrap();
        Self {
            _engine: engine,
            _jobs: jobs,
            rows,
            job_rows,
            claim,
            receipt,
            host,
            selected,
            _source_engine: source_engine,
            _source: source,
            dir,
        }
    }
    fn agreement(&self) -> &str {
        &self.claim.proposal().manifest.agreement.agreement_id
    }
    fn snapshot(
        &self,
    ) -> wholepact_store::Result<wholepact_store::recovery::RecoveredStoreSnapshot> {
        let binding = bundle::recovery::generation::GenerationBinding::new(
            &self.host.generation_id,
            &self.host.inventory_digest,
        )
        .unwrap();
        wholepact_store::recovery::RecoveredStoreSnapshot::open(
            &self.dir.path().join("successor.sqlite"),
            &key(174),
            &binding,
            self._source.provenance(),
        )
    }
    fn proof_snapshot(&self) -> ProofStatusSnapshot {
        ProofStatusSnapshot::open(&self.dir.path().join("proof.sqlite"), &key(175)).unwrap()
    }
    fn prepare(
        &self,
    ) -> crate::Result<crate::manual_enrollment::PreparedManualRosterConstructionInspectionV2> {
        self.prepare_for(
            &self.selected,
            self.agreement(),
            &self.claim.construction_key,
        )
    }
    fn prepare_for(
        &self,
        access: &Access,
        agreement: &str,
        construction_key: &str,
    ) -> crate::Result<crate::manual_enrollment::PreparedManualRosterConstructionInspectionV2> {
        Engine::prepare_manual_roster_construction_inspection_v2(
            self.snapshot().map_err(crate::store_error)?,
            access,
            agreement,
            construction_key,
        )
    }
    fn replace_receipt(&self, receipt: Option<&ManualRosterConstructionCheckpointV2>) {
        self.rows
            .connection()
            .execute("DELETE FROM records WHERE aggregate_type=?1", [RECEIPT])
            .unwrap();
        if let Some(receipt) = receipt {
            receipt.validate_for(&self.claim).unwrap();
            self.rows
                .connection()
                .execute(
                    "INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
                    [
                        RECEIPT.to_owned(),
                        receipt.claim_digest.clone(),
                        serde_json::to_string(receipt).unwrap(),
                    ],
                )
                .unwrap();
        }
    }
    fn replace_history(&self, host: &ManualHostGenerationBinding) {
        let (_, _, history) = fixtures::historical_rows(host, true);
        self.rows
            .connection()
            .execute(
                "DELETE FROM records WHERE aggregate_type GLOB 'generation_manual_*'",
                [],
            )
            .unwrap();
        for (kind, id, payload) in history {
            self.rows
                .connection()
                .execute(
                    "INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
                    [kind, id, payload],
                )
                .unwrap();
        }
    }
    fn retain_job_metadata(&self, state: &str, attempt: u32) {
        let scope = serde_json::to_vec(&self.receipt.scope).unwrap();
        // The deliberately non-PCZT blobs must never be read or parsed by a
        // metadata-only status call. No constructor, enqueue or proof runs.
        self.job_rows.connection().execute(
            "INSERT INTO proof_jobs(job_id,principal_id,idem_key,request_digest,scope,input_digest,input,policy,maximum_actions,state,attempt) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,8,?9,?10)",
            (&self.receipt.job_id, &self.claim.principal_id, &self.claim.construction_key, "a".repeat(64), scope,
             &self.receipt.scope.artifact_digest, b"synthetic inert bytes, never PCZT".as_slice(), b"not a private policy".as_slice(), state, attempt),
        ).unwrap();
    }
}

// Trusted embedding test double for this metadata reader only. It never stands
// in for Host native consent and refuses every private/mutating proof action.
struct InspectOnly {
    expected: CheckpointScope,
    calls: AtomicUsize,
    allow: bool,
}
impl InspectOnly {
    fn new(receipt: &ManualRosterConstructionCheckpointV2, allow: bool) -> Self {
        Self {
            expected: serde_json::from_value(serde_json::to_value(&receipt.scope).unwrap())
                .unwrap(),
            calls: AtomicUsize::new(0),
            allow,
        }
    }
}
impl LocalProofConsent for InspectOnly {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            action,
            LocalAction::InspectStatus,
            "metadata inspection requested a private or mutating action"
        );
        self.allow && scope == &self.expected
    }
}

#[test]
fn actual_encrypted_selected_claim_preserves_original_uncertainty_and_every_file() {
    for with_receipt in [false, true] {
        let f = Fixture::new(with_receipt);
        let prepared = unchanged(f.dir.path(), || f.prepare().unwrap());
        let metadata = prepared.metadata();
        assert_eq!(
            metadata.purpose,
            "inspect_original_construction_metadata_only"
        );
        assert_eq!(metadata.principal_id, f.selected.principal_id);
        assert_eq!(metadata.claim_digest, f.claim.digest().unwrap());
        assert_eq!(
            metadata.construction_key_digest,
            f.claim.request_identity().unwrap()
        );
        assert_eq!(metadata.candidate_id, f.claim.candidate_id());
        assert_eq!(metadata.original_agreement_revision, 1);
        assert_eq!(metadata.current_agreement_revision, 1);
        assert_eq!(metadata.constructor_receipt_digest.is_some(), with_receipt);
        assert_eq!(metadata.saved_checkpoint_scope.is_some(), with_receipt);
        assert_eq!(metadata.original_host.generation_id, f.host.generation_id);
        let gate = InspectOnly::new(&f.receipt, false);
        let view = unchanged(f.dir.path(), || {
            prepared
                .inspect(&f.selected, &f.proof_snapshot(), &gate)
                .unwrap()
        });
        assert_eq!(
            view.checkpoint_evidence,
            if with_receipt {
                "constructor_receipt_private_checkpoint_unconfirmed"
            } else {
                "construction_started_outcome_unknown"
            }
        );
        assert_eq!(view.claim_digest, metadata.claim_digest);
        assert_eq!(view.candidate_id, metadata.candidate_id);
        assert!(view.checkpoint.is_none());
        assert!(!view.retry_construction_allowed);
        assert_eq!(gate.calls.load(Ordering::SeqCst), 0);
        unchanged(f.dir.path(), || {
            prepared.check_current(&f.selected).unwrap()
        });
    }
}

#[test]
fn actual_encrypted_status_keeps_exact_original_running_and_uncertain_attempts_read_only() {
    let f = Fixture::new(true);
    f.retain_job_metadata("running", 7);
    let prepared = unchanged(f.dir.path(), || f.prepare().unwrap());
    let gate = InspectOnly::new(&f.receipt, true);
    let original_proof = unchanged(f.dir.path(), || f.proof_snapshot());
    for (state, expected) in [
        ("running", JobState::Running),
        ("uncertain", JobState::Uncertain),
    ] {
        if state == "uncertain" {
            f.job_rows
                .connection()
                .execute(
                    "UPDATE proof_jobs SET state='uncertain' WHERE job_id=?1",
                    [&f.receipt.job_id],
                )
                .unwrap();
            unchanged(f.dir.path(), || {
                assert!(original_proof.check_source_unchanged().is_err())
            });
            unchanged(f.dir.path(), || {
                assert!(
                    prepared
                        .inspect(&f.selected, &original_proof, &gate)
                        .is_err()
                )
            });
        }
        let view = unchanged(f.dir.path(), || {
            prepared
                .inspect(&f.selected, &f.proof_snapshot(), &gate)
                .unwrap()
        });
        assert_eq!(
            view.checkpoint_evidence,
            "exact_original_private_checkpoint_observed"
        );
        assert!(!view.retry_construction_allowed);
        let job = view.checkpoint.unwrap();
        assert_eq!(job.job_id, f.receipt.job_id);
        assert_eq!(job.state, expected);
        assert_eq!(job.attempt, 7);
        assert_eq!(job.scope_digest, f.receipt.scope_digest().unwrap());
        assert!(job.encrypted_checkpoint_created);
        assert!(
            !job.proof_verified
                && !job.chain_validated
                && !job.authorization_allowed
                && !job.distribution_allowed
        );
    }
    assert_eq!(gate.calls.load(Ordering::SeqCst), 2);
    let denied = InspectOnly::new(&f.receipt, false);
    let error = unchanged(f.dir.path(), || {
        prepared
            .inspect(&f.selected, &f.proof_snapshot(), &denied)
            .unwrap_err()
    });
    assert_eq!(error.code, "RECOVERY_REQUIRED");
    assert_eq!(denied.calls.load(Ordering::SeqCst), 1);
    // Missing receipt with an existing private job is a hard ambiguity, not an
    // empty or rebuildable result. The old prepared owner is stale as well.
    f.replace_receipt(None);
    unchanged(f.dir.path(), || {
        assert!(prepared.check_current(&f.selected).is_err())
    });
    let unconfirmed = unchanged(f.dir.path(), || f.prepare().unwrap());
    let error = unchanged(f.dir.path(), || {
        unconfirmed
            .inspect(&f.selected, &f.proof_snapshot(), &gate)
            .unwrap_err()
    });
    assert_eq!(error.code, "RECOVERY_REQUIRED");
}

#[test]
fn actual_prepared_reader_rechecks_exact_scope_key_principal_and_generation() {
    let f = Fixture::new(true);
    let prepared = f.prepare().unwrap();
    let gate = InspectOnly::new(&f.receipt, true);
    let no_selection = Access {
        agreement_ids: BTreeSet::new(),
        ..f.selected.clone()
    };
    let other_principal = Access {
        principal_id: "different-principal".into(),
        ..f.selected.clone()
    };
    for access in [&no_selection, &other_principal] {
        unchanged(f.dir.path(), || {
            assert!(prepared.check_current(access).is_err())
        });
        unchanged(f.dir.path(), || {
            assert!(
                prepared
                    .inspect(access, &f.proof_snapshot(), &gate)
                    .is_err()
            )
        });
        unchanged(f.dir.path(), || {
            assert!(
                f.prepare_for(access, f.agreement(), &f.claim.construction_key)
                    .is_err()
            )
        });
    }
    for key in [
        "wrong-construction-key",
        "short",
        " synthetic-construction-key",
    ] {
        unchanged(f.dir.path(), || {
            assert!(f.prepare_for(&f.selected, f.agreement(), key).is_err())
        });
    }
    assert_eq!(gate.calls.load(Ordering::SeqCst), 0);
    for field in 0..3 {
        let mut changed = f.host.clone();
        match field {
            0 => changed.generation_id = "9".repeat(64),
            1 => changed.inventory_digest = "9".repeat(64),
            _ => changed.store_destination_identity = "9".repeat(64),
        }
        f.replace_history(&changed);
        // Internally valid inert construction data still cannot authenticate
        // as the actual generation or destination of this protected snapshot.
        let (changed_claim, _, _) = fixtures::historical_rows(&changed, true);
        changed_claim.validate().unwrap();
        unchanged(f.dir.path(), || assert!(f.snapshot().is_err()));
        unchanged(f.dir.path(), || assert!(f.prepare().is_err()));
        unchanged(f.dir.path(), || {
            assert!(prepared.check_current(&f.selected).is_err())
        });
    }
}

#[test]
fn actual_prepared_reader_rejects_appearing_disappearing_and_changed_valid_receipt() {
    let f = Fixture::new(false);
    let without = f.prepare().unwrap();
    f.replace_receipt(Some(&f.receipt));
    unchanged(f.dir.path(), || {
        assert!(without.check_current(&f.selected).is_err())
    });
    let with = unchanged(f.dir.path(), || f.prepare().unwrap());
    let mut changed = f.receipt.clone();
    changed.scope.artifact_digest = "9".repeat(64);
    changed.validate_for(&f.claim).unwrap();
    f.replace_receipt(Some(&changed));
    unchanged(f.dir.path(), || {
        assert!(with.check_current(&f.selected).is_err())
    });
    let revised = unchanged(f.dir.path(), || f.prepare().unwrap());
    assert_ne!(
        revised.metadata().constructor_receipt_digest,
        with.metadata().constructor_receipt_digest
    );
    f.replace_receipt(None);
    unchanged(f.dir.path(), || {
        assert!(revised.check_current(&f.selected).is_err())
    });
    let fresh = unchanged(f.dir.path(), || f.prepare().unwrap());
    assert!(fresh.metadata().constructor_receipt_digest.is_none());
    assert!(fresh.metadata().saved_checkpoint_scope.is_none());
}

#[test]
fn actual_prepared_reader_rejects_current_snapshot_and_corruption_without_repair() {
    let f = Fixture::new(true);
    let prepared = f.prepare().unwrap();
    let mut record = unchanged(f.dir.path(), || {
        f.snapshot()
            .unwrap()
            .current_agreement_record(f.agreement())
            .unwrap()
    });
    record.payload["view"]["progress"] = "synthetic_changed_snapshot".into();
    // Same identity and revision still do not make changed content equivalent.
    f.rows
        .connection()
        .execute(
            "UPDATE records SET payload=?1 WHERE aggregate_type='agreement' AND id=?2",
            [
                serde_json::to_string(&record.payload).unwrap(),
                record.id.clone(),
            ],
        )
        .unwrap();
    unchanged(f.dir.path(), || {
        assert!(prepared.check_current(&f.selected).is_err())
    });
    let refreshed = unchanged(f.dir.path(), || f.prepare().unwrap());
    assert_ne!(
        refreshed.metadata().current_agreement_record_digest,
        prepared.metadata().current_agreement_record_digest
    );
    record.payload["view"]["revision"] = 2.into();
    f.rows
        .connection()
        .execute(
            "UPDATE records SET payload=?1,revision=2 WHERE aggregate_type='agreement' AND id=?2",
            [
                serde_json::to_string(&record.payload).unwrap(),
                record.id.clone(),
            ],
        )
        .unwrap();
    unchanged(f.dir.path(), || {
        assert!(refreshed.check_current(&f.selected).is_err())
    });
    let current = unchanged(f.dir.path(), || f.prepare().unwrap());
    assert_eq!(current.metadata().original_agreement_revision, 1);
    assert_eq!(current.metadata().current_agreement_revision, 2);
    record.payload["view"]["progress"] = "synthetic_changed_after_historical_prepare".into();
    f.rows
        .connection()
        .execute(
            "UPDATE records SET payload=?1 WHERE aggregate_type='agreement' AND id=?2",
            [
                serde_json::to_string(&record.payload).unwrap(),
                record.id.clone(),
            ],
        )
        .unwrap();
    unchanged(f.dir.path(), || {
        assert!(current.check_current(&f.selected).is_err())
    });
    let latest = unchanged(f.dir.path(), || f.prepare().unwrap());
    assert_eq!(latest.metadata().original_agreement_revision, 1);
    assert_eq!(latest.metadata().current_agreement_revision, 2);
    f.rows
        .connection()
        .execute(
            "UPDATE records SET payload='{}' WHERE aggregate_type=?1",
            [CLAIM],
        )
        .unwrap();
    unchanged(f.dir.path(), || {
        assert!(latest.check_current(&f.selected).is_err())
    });
    unchanged(f.dir.path(), || assert!(f.prepare().is_err()));
    unchanged(f.dir.path(), || {
        assert!(
            f.prepare_for(&f.selected, f.agreement(), "unrelated-missing-key")
                .is_err()
        )
    });
}

#[test]
fn actual_private_checkpoint_metadata_substitution_and_corruption_deny_without_mutation() {
    let f = Fixture::new(true);
    f.retain_job_metadata("running", 7);
    let prepared = f.prepare().unwrap();
    let gate = InspectOnly::new(&f.receipt, true);
    f.job_rows
        .connection()
        .execute(
            "UPDATE proof_jobs SET input_digest=?1 WHERE job_id=?2",
            ["9".repeat(64), f.receipt.job_id.clone()],
        )
        .unwrap();
    unchanged(f.dir.path(), || {
        assert!(
            prepared
                .inspect(&f.selected, &f.proof_snapshot(), &gate)
                .is_err()
        )
    });
    f.job_rows
        .connection()
        .execute(
            "UPDATE proof_jobs SET input_digest=?1 WHERE job_id=?2",
            [&f.receipt.scope.artifact_digest, &f.receipt.job_id],
        )
        .unwrap();
    let mut changed = f.receipt.scope.clone();
    changed.candidate_id = "different-original-candidate".into();
    f.job_rows
        .connection()
        .execute(
            "UPDATE proof_jobs SET scope=?1 WHERE job_id=?2",
            (serde_json::to_vec(&changed).unwrap(), &f.receipt.job_id),
        )
        .unwrap();
    unchanged(f.dir.path(), || {
        assert!(
            prepared
                .inspect(&f.selected, &f.proof_snapshot(), &gate)
                .is_err()
        )
    });
    f.job_rows
        .connection()
        .execute(
            "UPDATE proof_jobs SET scope=?1 WHERE job_id=?2",
            (b"{".as_slice(), &f.receipt.job_id),
        )
        .unwrap();
    unchanged(f.dir.path(), || {
        assert!(
            prepared
                .inspect(&f.selected, &f.proof_snapshot(), &gate)
                .is_err()
        )
    });
    // Claim/receipt inspection stays metadata-only even when the independent
    // private checkpoint is corrupt. It never repairs or rebuilds either side.
    unchanged(f.dir.path(), || {
        prepared.check_current(&f.selected).unwrap()
    });
}

fn unchanged<T>(root: &Path, read: impl FnOnce() -> T) -> T {
    let before = tree(root);
    let result = read();
    assert_eq!(
        tree(root),
        before,
        "metadata read changed a file, SQLite sidecar, directory or file identity"
    );
    result
}

// Read atime is excluded. Every other relevant identity/ownership/time and every
// byte (including WAL/SHM and nested inventory) is compared before/after capture.
#[derive(PartialEq, Eq)]
struct FileState {
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    device: u64,
    inode: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    bytes: Option<Vec<u8>>,
}
impl std::fmt::Debug for FileState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use sha2::Digest;
        // Equality still compares every raw byte. Diagnostic formatting never
        // dumps encrypted fixture pages, private contents, or megabytes of SHM.
        let bytes_len_sha256 = self
            .bytes
            .as_ref()
            .map(|bytes| (bytes.len(), hex::encode(sha2::Sha256::digest(bytes))));
        f.debug_struct("FileState")
            .field("mode", &self.mode)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("links", &self.links)
            .field("device", &self.device)
            .field("inode", &self.inode)
            .field("len", &self.len)
            .field("modified", &self.modified)
            .field("changed", &self.changed)
            .field("bytes_len_sha256", &bytes_len_sha256)
            .finish()
    }
}

fn tree(root: &Path) -> BTreeMap<PathBuf, FileState> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, FileState>) {
        let m = fs::symlink_metadata(path).unwrap();
        assert!(m.is_file() || m.is_dir());
        out.insert(
            path.strip_prefix(root).unwrap().into(),
            FileState {
                mode: m.mode(),
                uid: m.uid(),
                gid: m.gid(),
                links: m.nlink(),
                device: m.dev(),
                inode: m.ino(),
                len: m.len(),
                modified: (m.mtime(), m.mtime_nsec()),
                changed: (m.ctime(), m.ctime_nsec()),
                bytes: m.is_file().then(|| fs::read(path).unwrap()),
            },
        );
        if m.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), out);
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}
