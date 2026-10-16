//! Synthetic original binding/provenance and archive lineage qualification.
use super::*;
use crate::generation_archive as archive;
struct ArchiveGate(archive::ArchiveScope);
struct ArchiveLease;
impl archive::ArchiveAuthority for ArchiveGate {
    fn acquire<'a>(
        &'a self,
        scope: &archive::ArchiveScope,
    ) -> archive::Result<Box<dyn archive::ArchiveLease + 'a>> {
        if scope != &self.0 {
            return Err(archive::ArchiveError::Permission);
        }
        Ok(Box::new(ArchiveLease))
    }
}
impl archive::ArchiveLease for ArchiveLease {
    fn check_current(&self) -> archive::Result<()> {
        Ok(())
    }
}
#[test]
fn archived_evidence_and_generation_keep_original_identity_and_new_archive_context() {
    let inherited = fixture();
    let coordination = fixture_for(&COORDINATION);
    let originals = target();
    let archives = target();
    let old_binding = binding();
    let current_binding = GenerationBinding::new(&"c5".repeat(32), &"d6".repeat(32)).unwrap();
    let evidence_key = DatabaseKey::from_bytes([153; 32]);
    let current_key = DatabaseKey::from_bytes([154; 32]);
    let archive_key = DatabaseKey::from_bytes([155; 32]);
    let evidence_path = originals.path().join("inherited-wallet.sqlite");
    let current_path = originals.path().join("current-coordination.sqlite");
    evidence::reconstruct_wallet_scan_evidence(
        &inherited.source,
        &WALLET,
        &evidence_path,
        &evidence_key,
        &old_binding,
    )
    .unwrap();
    initialize_coordination_generation(
        &coordination.source,
        &COORDINATION,
        &SUCCESSOR,
        &current_binding,
        &current_path,
        &current_key,
        overlay,
    )
    .unwrap();
    let ordinary_read = evidence::open_wallet_scan_evidence(
        &evidence_path,
        &evidence_key,
        &old_binding,
        inherited.source.provenance(),
        &WALLET,
    )
    .unwrap();
    assert!(ordinary_read.disclosure_identity().archive().is_none());
    let sources = [
        archive::RegisteredSource::new(
            "old-wallet",
            "inherited-wallet",
            archive::Source::Journal(&evidence_path),
        )
        .unwrap(),
        archive::RegisteredSource::new(
            "current-coordination",
            "current-coordination",
            archive::Source::Journal(&current_path),
        )
        .unwrap(),
    ];
    let node = archive::NodeSpec {
        generation_id: current_binding.generation_id().into(),
        profile_id: "synthetic-current-profile".into(),
        original_root: originals.path().into(),
    };
    let path = archives.path().join("history.sqlite");
    let capsule = "e7".repeat(32);
    let gate = ArchiveGate(
        archive::ArchiveScope::for_snapshot(&path, &archive_key, &capsule, &node, &sources, &[])
            .unwrap(),
    );
    archive::snapshot(archive::SnapshotRequest {
        destination: &path,
        key: &archive_key,
        capsule_id: &capsule,
        node: &node,
        sources: &sources,
        parents: &[],
        authority: &gate,
    })
    .unwrap();
    let before_originals = crate::tests::tree_fingerprint(originals.path());
    let before_archives = crate::tests::tree_fingerprint(archives.path());
    let archive = archive::inspect(&path, &archive_key).unwrap();
    let inherited_journal = archive
        .journal(archive.manifest_digest(), "old-wallet")
        .unwrap();
    let reopened = inherited_journal
        .open_evidence(
            &evidence_key,
            &old_binding,
            inherited.source.provenance(),
            &WALLET,
        )
        .unwrap();
    let reopened_again = inherited_journal
        .open_evidence(
            &evidence_key,
            &old_binding,
            inherited.source.provenance(),
            &WALLET,
        )
        .unwrap();
    let identity = reopened.disclosure_identity();
    assert_eq!(identity.generation(), Some(&old_binding));
    assert_eq!(identity.provenance(), inherited.source.provenance());
    assert_eq!(identity.origin().generation_id, old_binding.generation_id());
    assert_eq!(
        identity.origin().inventory_digest,
        old_binding.inventory_digest()
    );
    assert!(identity.binding() != reopened_again.disclosure_identity().binding());
    assert!(identity.binding() != ordinary_read.disclosure_identity().binding());
    assert!(identity.origin() == reopened_again.disclosure_identity().origin());
    assert_eq!(
        identity.archive().unwrap().selected_generation_id(),
        current_binding.generation_id()
    );
    assert_eq!(identity.archive().unwrap().entry_id(), "old-wallet");
    assert_eq!(identity.archive().unwrap().role(), "inherited-wallet");
    assert_eq!(
        identity
            .archive()
            .unwrap()
            .source_provenance()
            .component_digest,
        inherited.source.provenance().component_digest
    );
    assert_eq!(
        identity.archive().unwrap().source_provenance().component_id,
        "old-wallet"
    );
    assert!(
        inherited_journal
            .open_evidence(
                &evidence_key,
                &current_binding,
                inherited.source.provenance(),
                &WALLET
            )
            .is_err()
    );
    let current_journal = archive
        .journal(archive.manifest_digest(), "current-coordination")
        .unwrap();
    let current = current_journal
        .open_generation(
            &current_key,
            &current_binding,
            coordination.source.provenance(),
            &SUCCESSOR,
        )
        .unwrap();
    let again = current_journal
        .open_generation(
            &current_key,
            &current_binding,
            coordination.source.provenance(),
            &SUCCESSOR,
        )
        .unwrap();
    let identity = current.disclosure_identity();
    assert_eq!(identity.generation(), Some(&current_binding));
    assert_eq!(identity.provenance(), coordination.source.provenance());
    assert_eq!(
        identity.origin().inventory_digest,
        current_binding.inventory_digest()
    );
    assert_eq!(
        identity.archive().unwrap().source_provenance(),
        current.source_provenance()
    );
    assert_ne!(identity.provenance(), current.source_provenance());
    assert!(identity.binding() != again.disclosure_identity().binding());
    assert!(identity.origin() == again.disclosure_identity().origin());
    assert_eq!(
        before_originals,
        crate::tests::tree_fingerprint(originals.path())
    );
    assert_eq!(
        before_archives,
        crate::tests::tree_fingerprint(archives.path())
    );
}
