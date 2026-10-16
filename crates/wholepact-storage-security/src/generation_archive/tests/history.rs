//! Synthetic archive identity and held disclosure boundaries only. No live keys,
//! native terminal, financial effect, proofs, transport, or network operation.
use super::*;
use crate::bundle::{
    BundleError,
    recovery::evidence::history::{
        HistoricalAction, HistoricalDestination, HistoricalDisclosure,
        HistoricalDisclosureAuthority, HistoricalDisclosureLease, HistoricalDisclosureScope,
        HistoricalReferences, acquire_checked,
    },
};
use std::cell::Cell;

type DisclosureResult<T> = std::result::Result<T, BundleError>;
struct Gate {
    expected: HistoricalDisclosureScope,
    revoked: Cell<bool>,
    repeat: Cell<bool>,
}
struct DisclosureLease<'a> {
    scope: HistoricalDisclosureScope,
    gate: &'a Gate,
}
impl HistoricalDisclosureAuthority for Gate {
    fn acquire<'a>(
        &'a self,
        scope: &HistoricalDisclosureScope,
    ) -> DisclosureResult<Box<dyn HistoricalDisclosureLease + 'a>> {
        if scope != &self.expected {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(DisclosureLease {
            scope: scope.clone(),
            gate: self,
        }))
    }
}
impl HistoricalDisclosureLease for DisclosureLease<'_> {
    fn scope(&self) -> &HistoricalDisclosureScope {
        &self.scope
    }
    fn check_current(&self) -> DisclosureResult<()> {
        if self.gate.revoked.get() {
            Err(BundleError::Permission)
        } else {
            Ok(())
        }
    }
    fn run_effect(&self, effect: &mut dyn FnMut() -> DisclosureResult<()>) -> DisclosureResult<()> {
        self.check_current()?;
        effect()?;
        if self.gate.repeat.get() {
            effect()?;
        }
        Ok(())
    }
}
fn refs() -> HistoricalReferences {
    HistoricalReferences {
        artifact_id: "synthetic-record".into(),
        ..HistoricalReferences::default()
    }
}
fn scope(source: &ArchivedOrdinarySource) -> HistoricalDisclosureScope {
    HistoricalDisclosureScope::from_source(
        source.disclosure_identity(),
        "synthetic-reader",
        HistoricalAction::TransactionMetadata,
        refs(),
        HistoricalDestination::NativeTerminal,
        &serde_json::to_vec("synthetic-metadata").unwrap(),
    )
    .unwrap()
}
fn authorize<'a>(
    source: &ArchivedOrdinarySource,
    gate: &'a Gate,
) -> DisclosureResult<HistoricalDisclosure<'a, &'static str>> {
    HistoricalDisclosure::authorize_from_source(
        source.disclosure_identity(),
        "synthetic-reader",
        HistoricalAction::TransactionMetadata,
        refs(),
        "synthetic-metadata",
        gate,
    )
}

#[test]
fn ordinary_identity_binds_root_selected_node_exact_entry_role_and_reopened_instance() {
    let source = directory();
    let output = directory();
    let journal = source.path().join("journal.sqlite");
    let journal_key = DatabaseKey::from_bytes([151; 32]);
    let archive_key = DatabaseKey::from_bytes([152; 32]);
    let writer = crate::create_encrypted(&journal, &journal_key).unwrap();
    writer.connection().execute_batch("PRAGMA user_version=1; CREATE TABLE synthetic_history(value TEXT NOT NULL); INSERT INTO synthetic_history VALUES('synthetic-metadata');").unwrap();
    crate::checkpoint_and_sync(writer.connection(), &journal).unwrap();
    drop(writer);
    let other_journal = source.path().join("other-journal.sqlite");
    fs::copy(&journal, &other_journal).unwrap();
    let node = NodeSpec {
        generation_id: "81".repeat(32),
        profile_id: "synthetic-parent".into(),
        original_root: source.path().into(),
    };
    let sources = [
        RegisteredSource::new("journal", "current-submission", Source::Journal(&journal)).unwrap(),
        RegisteredSource::new(
            "other-journal",
            "different-role",
            Source::Journal(&other_journal),
        )
        .unwrap(),
    ];
    let parent_path = output.path().join("parent.sqlite");
    let parent_report = make(
        &parent_path,
        &archive_key,
        &node,
        &sources,
        &[],
        &"82".repeat(32),
    )
    .unwrap();
    let parent = inspect(&parent_path, &archive_key).unwrap();
    let current_node = NodeSpec {
        generation_id: "83".repeat(32),
        profile_id: "synthetic-child".into(),
        ..node.clone()
    };
    let child_path = output.path().join("child.sqlite");
    let child_report = make(
        &child_path,
        &archive_key,
        &current_node,
        &sources,
        &[&parent],
        &"84".repeat(32),
    )
    .unwrap();
    let source_before = tree_fingerprint(source.path());
    let archives_before = tree_fingerprint(output.path());
    let child = inspect(&child_path, &archive_key).unwrap();
    let selected = child
        .journal(&parent_report.manifest_digest, "journal")
        .unwrap();
    let first = selected.inspect_ordinary(&journal_key, &TEMPLATE).unwrap();
    let reopened = selected.inspect_ordinary(&journal_key, &TEMPLATE).unwrap();
    let same_parent = parent
        .journal(&parent_report.manifest_digest, "journal")
        .unwrap()
        .inspect_ordinary(&journal_key, &TEMPLATE)
        .unwrap();
    let wrong_node = child
        .journal(&child_report.manifest_digest, "journal")
        .unwrap()
        .inspect_ordinary(&journal_key, &TEMPLATE)
        .unwrap();
    let wrong_entry = child
        .journal(&parent_report.manifest_digest, "other-journal")
        .unwrap()
        .inspect_ordinary(&journal_key, &TEMPLATE)
        .unwrap();
    let identity = first.disclosure_identity();
    assert!(identity.generation().is_none());
    assert!(identity.binding() == first.historical_binding());
    assert!(identity.binding() != reopened.historical_binding());
    assert!(identity.origin() == reopened.disclosure_identity().origin());
    assert_eq!(identity.origin().generation_id, node.generation_id);
    assert_eq!(
        identity.origin().inventory_digest,
        parent_report.manifest_digest
    );
    let lineage = identity.archive().unwrap();
    assert_eq!(lineage.root_manifest_digest(), child_report.manifest_digest);
    assert_eq!(lineage.root_capsule_id(), child.manifest().capsule_id);
    assert_eq!(
        lineage.selected_manifest_digest(),
        parent_report.manifest_digest
    );
    assert_eq!(
        lineage.selected_node_digest(),
        parent.manifest().node_digest
    );
    assert_eq!(lineage.selected_capsule_id(), parent.manifest().capsule_id);
    assert_eq!(lineage.selected_generation_id(), node.generation_id);
    assert_eq!(lineage.selected_profile_id(), node.profile_id);
    assert_eq!(
        lineage.selected_original_root(),
        node.original_root.to_str().unwrap()
    );
    assert_eq!(lineage.entry_id(), "journal");
    assert_eq!(lineage.role(), "current-submission");
    assert_eq!(lineage.original_path(), journal.to_str().unwrap());
    assert_eq!(lineage.source_provenance(), first.provenance());
    let gate = Gate {
        expected: scope(&first),
        revoked: Cell::new(false),
        repeat: Cell::new(false),
    };
    for substitute in [&reopened, &same_parent, &wrong_node, &wrong_entry] {
        assert!(authorize(substitute, &gate).is_err());
        // Even copying the enrolled process binding cannot launder another
        // authenticated root/node/entry's labels into an enrolled exact scope.
        if substitute.disclosure_identity().origin() != identity.origin() {
            let mut changed = scope(substitute);
            changed.source = identity.binding();
            assert!(acquire_checked(&gate, &changed).is_err());
        }
    }
    let mut called = 0;
    authorize(&first, &gate)
        .unwrap()
        .deliver(|value| {
            assert_eq!(*value, "synthetic-metadata");
            called += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(called, 1);
    let pending = authorize(&first, &gate).unwrap();
    gate.revoked.set(true);
    assert!(
        pending
            .deliver(|_| {
                called += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(called, 1);
    gate.revoked.set(false);
    gate.repeat.set(true);
    assert!(
        authorize(&first, &gate)
            .unwrap()
            .deliver(|_| {
                called += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(
        called, 2,
        "attempted duplicate final effect must not repeat output"
    );
    assert_eq!(source_before, tree_fingerprint(source.path()));
    assert_eq!(archives_before, tree_fingerprint(output.path()));
}
