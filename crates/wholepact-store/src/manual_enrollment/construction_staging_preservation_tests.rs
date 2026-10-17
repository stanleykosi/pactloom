//! Actual sealed archive-to-generation staging, using synthetic integrity gates.
//! This qualifies storage/Store composition only, never native or financial consent.
use super::*;
use wholepact_storage_security::generation_archive::{self as archive, *};

struct SyntheticArchiveAuthority(ArchiveScope);
struct SyntheticArchiveLease;
impl ArchiveAuthority for SyntheticArchiveAuthority {
    fn acquire<'a>(
        &'a self,
        scope: &ArchiveScope,
    ) -> std::result::Result<Box<dyn ArchiveLease + 'a>, ArchiveError> {
        if scope != &self.0 {
            return Err(ArchiveError::Permission);
        }
        Ok(Box::new(SyntheticArchiveLease))
    }
}
impl ArchiveLease for SyntheticArchiveLease {
    fn check_current(&self) -> std::result::Result<(), ArchiveError> {
        Ok(())
    }
}

#[test]
fn encrypted_common_context_v3_supported_layer_staging_installs_exact_marker_after_validation() {
    let f = Fixture::new(true);
    let root_lock = fs::File::open(f.directory.path()).unwrap();
    root_lock.try_lock().unwrap();
    let _writer_exclusion = f.store.connection.lock().unwrap();
    let output = tempfile::tempdir().unwrap();
    fs::set_permissions(output.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let capsule_path = output.path().join("parent-capsule.sqlite");
    let capsule_key = key(0x68);
    let capsule_id = "68".repeat(32);
    let source_path = f.path();
    let sources = [RegisteredSource::new(
        "coordination",
        "current-coordination",
        Source::Journal(&source_path),
    )
    .unwrap()];
    let node = NodeSpec {
        generation_id: f.binding.generation_id().into(),
        profile_id: "synthetic-staging-profile".into(),
        original_root: f.directory.path().into(),
    };
    let authority = SyntheticArchiveAuthority(
        ArchiveScope::for_snapshot(
            &capsule_path,
            &capsule_key,
            &capsule_id,
            &node,
            &sources,
            &[],
        )
        .unwrap(),
    );
    let before = tree(f.directory.path());
    archive::snapshot(archive::SnapshotRequest {
        destination: &capsule_path,
        key: &capsule_key,
        capsule_id: &capsule_id,
        node: &node,
        sources: &sources,
        parents: &[],
        authority: &authority,
    })
    .unwrap();
    let capsule = archive::inspect(&capsule_path, &capsule_key).unwrap();
    let archived = capsule
        .journal(capsule.manifest_digest(), "coordination")
        .unwrap();
    // The fixture is produced by the current compiled ordinary/single templates.
    // Exact historical templates must reject it before any successor is staged.
    for version in [2, 4, 6] {
        assert!(
            archived
                .open_generation(
                    &key(0x61),
                    &f.binding,
                    &f.provenance,
                    crate::recovery::coordination_successor_template_for_schema(version).unwrap(),
                )
                .is_err(),
            "legacy single template {version} must reject the current source marker"
        );
    }
    let sealed = archived
        .open_generation(
            &key(0x61),
            &f.binding,
            &f.provenance,
            crate::recovery::coordination_successor_template(),
        )
        .unwrap();
    let binding =
        bundle::recovery::generation::GenerationBinding::new(&"69".repeat(32), &"6a".repeat(32))
            .unwrap();
    let destination = output.path().join("successor.sqlite");
    let destination_key = key(0x6b);
    // This is the supported public staging API. Its real storage callback runs
    // before the final user_version/storage marker is installed. A runtime
    // marker check inside that callback would fail even on this valid history.
    crate::recovery::stage_layered_coordination_successor(
        &sealed,
        &binding,
        &destination,
        &destination_key,
    )
    .unwrap();
    let staged = tree(output.path());
    crate::recovery::stage_layered_coordination_successor(
        &sealed,
        &binding,
        &destination,
        &destination_key,
    )
    .unwrap();
    assert_eq!(
        tree(output.path()),
        staged,
        "exact retry must not rewrite the destination"
    );
    let recovered_snapshot = RecoveredStoreSnapshot::open(
        &destination,
        &destination_key,
        &binding,
        sealed.source_provenance(),
    )
    .unwrap();
    assert_eq!(recovered_snapshot.layer_depth().unwrap(), 2);
    assert!(
        recovered_snapshot
            .manual_roster_construction_evidence_v2(
                &f.claim.principal_id,
                &f.claim.construction_key,
            )
            .unwrap()
            .unwrap()
            == (f.claim.clone(), f.receipt.clone())
    );
    for version in [3, 5, 7] {
        assert!(wholepact_storage_security::bundle::recovery::generation::open_recovered_generation_snapshot(
            &destination,
            &destination_key,
            &binding,
            sealed.source_provenance(),
            crate::recovery::coordination_layered_successor_template_for_schema(version).unwrap(),
        ).is_err(), "legacy layered template {version} must never accept the new generation");
    }
    recovered_snapshot.check_source_unchanged().unwrap();
    assert_eq!(
        tree(f.directory.path()),
        before,
        "complete source tree stays immutable"
    );
}
