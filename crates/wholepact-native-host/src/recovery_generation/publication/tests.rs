//! Denied publication effects on synthetic encrypted successors only. No TTY,
//! signer, witness, socket, proof, financial operation or successful approval.
use super::*;
use crate::{
    generation_backup::tests::synthetic_capsule_quarantine,
    generation_restore::RestoredGenerationCapsule,
    recovery_generation::layered::PendingLayeredGeneration,
    recovery_inventory::tests::{PASSWORD, published_empty_fixture},
    terminal::PublicationApproval,
};
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

type Fingerprint = BTreeMap<PathBuf, (Vec<u8>, u32, u64, u64, i64, i64)>;

fn fingerprint(root: &Path) -> Fingerprint {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        let bytes = if metadata.is_dir() {
            pending.extend(
                std::fs::read_dir(&path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path()),
            );
            Vec::new()
        } else {
            std::fs::read(&path).unwrap()
        };
        result.insert(
            path.strip_prefix(root).unwrap().into(),
            (
                bytes,
                metadata.mode(),
                metadata.dev(),
                metadata.ino(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            ),
        );
    }
    result
}

fn assert_denied(result: Result<()>, expired: bool) {
    if expired {
        assert!(matches!(result, Err(Error::Permission)));
    } else {
        assert!(matches!(result, Err(Error::Terminal)));
    }
}

#[test]
fn denied_v1_publication_never_opens_writable_preflight_or_changes_any_tree() {
    let (temp, backup, restored, _) = published_empty_fixture();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    for (index, expired) in [false, true].into_iter().enumerate() {
        let target = root.join(format!("denied-v1-{index}"));
        let source = crate::recovery_inventory::prepare(
            &restored,
            &backup,
            &target,
            format!("{:02x}", 172 + index).repeat(32),
            PASSWORD,
            PASSWORD,
            Instant::now() + Duration::from_secs(300),
        )
        .unwrap();
        let prepared = PendingGeneration::create(source, PASSWORD)
            .unwrap()
            .construct()
            .unwrap()
            .prepare_publication(vec![])
            .unwrap();
        let approval = PublicationApproval::denied_for_test(prepared.manifest_digest(), expired);
        let before = fingerprint(&root);
        assert_denied(prepared.publish(vec![], approval), expired);
        assert!(!target.join(COMMIT).exists());
        // This includes the exact successor base files and sidecar inventory,
        // both original source trees, and all directory identities/stamps.
        assert_eq!(before, fingerprint(&root));
    }
}

#[test]
fn denied_v2_publication_never_opens_writable_preflight_or_changes_any_tree() {
    let (temp, _, _, g1) = published_empty_fixture();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let quarantine = root.join("denied-publication-quarantine");
    drop(synthetic_capsule_quarantine(
        &g1,
        &root.join("denied-publication-capsule"),
        &quarantine,
        174,
    ));
    for (index, expired) in [false, true].into_iter().enumerate() {
        let target = root.join(format!("denied-v2-{index}"));
        let source = RestoredGenerationCapsule::open(&quarantine, PASSWORD).unwrap();
        let prepared = PendingLayeredGeneration::create(source, &target, PASSWORD)
            .unwrap()
            .construct_synthetic_storage()
            .unwrap()
            .prepare_publication(vec![])
            .unwrap();
        let approval = PublicationApproval::denied_for_test(prepared.manifest_digest(), expired);
        let before = fingerprint(&root);
        assert_denied(prepared.publish(vec![], approval), expired);
        assert!(!target.join(COMMIT).exists());
        assert_eq!(before, fingerprint(&root));
    }
}
