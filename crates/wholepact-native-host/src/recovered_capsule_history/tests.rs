//! Synthetic selection and enrollment checks; no controlling TTY or delivery.
use super::*;
use crate::{
    generation_backup::tests::synthetic_capsule_quarantine,
    recovery_generation::layered::PendingLayeredGeneration,
    recovery_inventory::tests::{PASSWORD, published_empty_fixture},
};
use std::{collections::BTreeMap, os::unix::fs::MetadataExt};
fn fingerprint(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, u32, u64, i64, i64)> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let bytes = if metadata.is_dir() {
                pending.push(path.clone());
                Vec::new()
            } else {
                std::fs::read(&path).unwrap()
            };
            result.insert(
                path.strip_prefix(root).unwrap().into(),
                (
                    bytes,
                    metadata.mode(),
                    metadata.ino(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                ),
            );
        }
    }
    result
}
fn publish(source: RestoredGenerationCapsule, target: &Path) {
    PendingLayeredGeneration::create(source, target, PASSWORD)
        .unwrap()
        .construct_synthetic_storage()
        .unwrap()
        .prepare_publication(vec![])
        .unwrap()
        .publish_synthetic_empty_accounts()
        .unwrap();
}
fn scope(source: Selected<'_>) -> HistoricalDisclosureScope {
    HistoricalDisclosureScope::from_source(
        source.identity(),
        PRINCIPAL,
        HistoricalAction::ParticipantRecord,
        HistoricalReferences {
            artifact_id: "synthetic-selection-only".into(),
            ..Default::default()
        },
        HistoricalDestination::NativeTerminal,
        b"{\"synthetic_scope_only\":true}",
    )
    .unwrap()
}
#[test]
fn archived_native_selection_binds_exact_lineage_and_reopening_without_source_mutation() {
    let (temp, _, _, g1) = published_empty_fixture();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let g2 = root.join("g2-reader");
    publish(
        synthetic_capsule_quarantine(&g1, &root.join("b1-reader"), &root.join("q1-reader"), 151),
        &g2,
    );
    let g3 = root.join("g3-reader");
    publish(
        synthetic_capsule_quarantine(&g2, &root.join("b2-reader"), &root.join("q2-reader"), 152),
        &g3,
    );
    let directory = Directory::open(&g3).unwrap();
    let secrets = Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
    let before = fingerprint(&root);
    {
        let first = Session::open_layered(&directory, &secrets).unwrap();
        let reopened = Session::open_layered(&directory, &secrets).unwrap();
        assert_eq!(first.capsule().histories().len(), 2);
        let current = first.capsule().manifest_digest();
        // Capsule node commitment and native publication commitment are
        // distinct authenticated domains; valid selection must not equate them.
        assert_ne!(
            first.capsule().histories()[current].manifest_digest(),
            current
        );
        let ancestor = first
            .capsule()
            .histories()
            .keys()
            .find(|id| id.as_str() != current)
            .unwrap();
        let selected = select(&first, current, "current", "root-coordination").unwrap();
        let same = select(&reopened, current, "current", "root-coordination").unwrap();
        let old = select(&first, ancestor, "current", "root-coordination").unwrap();
        let exact = scope(selected);
        assert!(
            validate_scope(
                &first,
                selected,
                current,
                HistoricalAction::ParticipantRecord,
                "synthetic-selection-only",
                &exact
            )
            .is_ok()
        );
        assert!(
            validate_scope(
                &first,
                selected,
                ancestor,
                HistoricalAction::ParticipantRecord,
                "synthetic-selection-only",
                &exact
            )
            .is_err()
        );
        assert!(
            validate_scope(
                &first,
                selected,
                current,
                HistoricalAction::ParticipantRecord,
                "synthetic-selection-only",
                &scope(same)
            )
            .is_err()
        );
        assert!(
            validate_scope(
                &first,
                selected,
                current,
                HistoricalAction::ParticipantRecord,
                "synthetic-selection-only",
                &scope(old)
            )
            .is_err()
        );
        assert!(exact.origin == scope(same).origin);
        assert!(exact.source != scope(same).source);
        assert!(exact.origin != scope(old).origin);
        let mut rebound = exact.clone();
        rebound
            .references
            .account_ids
            .push("unenrolled-account".into());
        assert!(
            validate_scope(
                &first,
                selected,
                current,
                HistoricalAction::ParticipantRecord,
                "synthetic-selection-only",
                &rebound
            )
            .is_err()
        );
        assert!(select(&first, &"0".repeat(64), "current", "root-coordination").is_err());
        assert!(select(&first, current, "inherited", "root-coordination").is_err());
        assert!(select(&first, current, "current", "coordination").is_err());
        for protected in [&g1, &g2, &g3] {
            assert!(
                first
                    .external_destination(&protected.join("must-not-export"))
                    .is_err()
            );
        }
        assert!(
            first
                .external_destination(&root.join("new-private-export"))
                .is_ok()
        );
        // Public typed reopen is separate from the disclosure and retains the vault anchor.
        assert!(secrets.generation_plan_digest().is_some());
    }
    assert_eq!(before, fingerprint(&root));
}
