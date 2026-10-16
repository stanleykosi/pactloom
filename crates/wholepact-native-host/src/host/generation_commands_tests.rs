//! Parser and denied native composition only; no attended TTY, signer or socket.
use super::*;
use crate::{
    generation_backup::tests::synthetic_capsule_quarantine,
    generation_restore::RestoredGenerationCapsule,
    recovery_generation::layered::PendingLayeredGeneration,
    recovery_inventory::tests::{PASSWORD, published_empty_fixture},
};
use std::{collections::BTreeMap, os::unix::fs::MetadataExt};
type Fingerprint = BTreeMap<PathBuf, (Vec<u8>, u32, u64, i64, i64)>;
fn fingerprint(root: &Path) -> Fingerprint {
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
#[test]
fn generation_commands_parse_explicit_formats_and_reject_ordinary_restore_options() {
    for args in [
        vec![
            "host",
            "generation-backup",
            "--profile",
            "/profile",
            "--destination",
            "/archive",
        ],
        vec![
            "host",
            "generation-restore",
            "--backup",
            "/archive",
            "--destination",
            "/quarantine",
        ],
        vec!["host", "generation-history", "--profile", "/quarantine"],
        vec![
            "host",
            "generation-activate",
            "--profile",
            "/quarantine",
            "--successor",
            "/successor",
            "--resume",
        ],
    ] {
        assert!(Args::try_parse_from(args).is_ok());
    }
    for args in [
        vec![
            "host",
            "generation-restore",
            "--backup",
            "/archive",
            "--destination",
            "/quarantine",
            "--test-only",
        ],
        vec![
            "host",
            "generation-activate",
            "--profile",
            "/quarantine",
            "--successor",
            "/successor",
            "--backup",
            "/ordinary",
        ],
        vec!["host", "generation-backup", "--profile", "/profile"],
        vec![
            "host",
            "generation-history",
            "--profile",
            "/quarantine",
            "--activate",
        ],
        vec![
            "host",
            "restore",
            "--backup",
            "/archive",
            "--destination",
            "/quarantine",
            "--generation",
        ],
    ] {
        assert!(Args::try_parse_from(args).is_err());
    }
}
#[test]
fn generation_command_dispatch_without_fresh_native_approval_never_creates_outputs() {
    let (temp, backup, restored, g1) = published_empty_fixture();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let target = root.join("must-not-be-created");
    let before = fingerprint(&root);
    let commands = [
        Command::GenerationBackup {
            profile: g1.clone(),
            destination: target.clone(),
        },
        Command::GenerationRestore {
            backup: backup.clone(),
            destination: target.clone(),
        },
        Command::GenerationHistory {
            profile: restored.clone(),
        },
        Command::GenerationActivate {
            profile: restored.clone(),
            successor: target.clone(),
            resume: false,
        },
        Command::GenerationActivate {
            profile: restored,
            successor: target.clone(),
            resume: true,
        },
    ];
    for command in commands {
        assert!(matches!(
            dispatch(Terminal::disconnected_for_test(), command),
            Err(Error::Terminal)
        ));
        assert!(!target.exists());
        assert_eq!(before, fingerprint(&root));
    }
    // Explicit formats do not silently reinterpret a legacy backup/live root.
    assert!(RestoredGenerationCapsule::open(&g1, PASSWORD).is_err());
    let legacy = Directory::open(&backup).unwrap();
    assert!(crate::generation_restore::open_archive(&legacy, PASSWORD).is_err());
    drop(legacy);
    assert_eq!(before, fingerprint(&root));
}
#[test]
fn generation_public_v2_open_keeps_financial_denial_and_rejects_marker_downgrade() {
    let (temp, _, _, g1) = published_empty_fixture();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let source = synthetic_capsule_quarantine(
        &g1,
        &root.join("command-capsule"),
        &root.join("command-quarantine"),
        171,
    );
    let g2 = root.join("command-g2");
    PendingLayeredGeneration::create(source, &g2, PASSWORD)
        .unwrap()
        .construct_synthetic_storage()
        .unwrap()
        .prepare_publication(vec![])
        .unwrap()
        .publish_synthetic_empty_accounts()
        .unwrap();
    {
        let directory = Directory::open(&g2).unwrap();
        let secrets =
            Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
        let host = Host::open(directory, secrets, Terminal::disconnected_for_test()).unwrap();
        assert!(matches!(
            host.require_financial_generation_admission(),
            Err(Error::RecoveryFinancialUnsupported)
        ));
        assert!(host.access.is_none() && host.config.is_none() && host.financial.is_none());
        assert!(host.observation.is_none() && host.signer_review_clients.is_empty());
    }
    for marker in ["generation.commit", "generation.keys", "recovery.plan"] {
        let saved = root.join(format!("held-{marker}"));
        std::fs::rename(g2.join(marker), &saved).unwrap();
        let before = fingerprint(&g2);
        let directory = Directory::open(&g2).unwrap();
        let secrets =
            Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
        assert!(secrets.generation_plan_digest().is_some());
        assert!(Host::open(directory, secrets, Terminal::disconnected_for_test()).is_err());
        assert_eq!(before, fingerprint(&g2));
        std::fs::rename(saved, g2.join(marker)).unwrap();
    }
}
