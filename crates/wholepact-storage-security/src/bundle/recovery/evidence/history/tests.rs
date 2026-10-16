//! Synthetic disclosure/final-effect boundaries only. No native TTY approval,
//! proof, signature, network operation, restored authority, or settlement claim.
use super::*;
use crate::bundle::{JournalKind, recovery::generation::GenerationBinding};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

fn source() -> RecoveredEvidence {
    RecoveredEvidence {
        historical_binding: HistoricalSourceBinding::fresh(),
        archive_origin: None,
        provenance: RecoveryProvenance {
            profile_id: "old-profile".into(),
            checkpoint_id: "old-checkpoint".into(),
            bundle_digest: "a".repeat(64),
            component_id: "financial-0-proof".into(),
            kind: JournalKind::ProofWitness,
            component_digest: "b".repeat(64),
            application_id: 1,
            schema_version: 1,
            rows: 0,
        },
        generation: GenerationBinding::new(&"c".repeat(64), &"d".repeat(64)).unwrap(),
        tables: vec![],
    }
}
fn references() -> HistoricalReferences {
    HistoricalReferences {
        artifact_id: "old-proof".into(),
        historical_principal_id: "old-owner".into(),
        account_ids: vec!["old-account".into()],
        ..HistoricalReferences::default()
    }
}
#[derive(Serialize)]
struct Projection {
    historical: &'static str,
}
struct Gate {
    expected: HistoricalDisclosureScope,
    revoked: AtomicBool,
    fence: Mutex<()>,
    revoke_in_effect: bool,
    refuse: bool,
    substitute_scope: bool,
    repeat_effect: bool,
    skip_effect: bool,
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
        let _fence = self
            .gate
            .fence
            .lock()
            .map_err(|_| BundleError::Permission)?;
        if self.gate.revoke_in_effect {
            self.gate.revoked.store(true, Ordering::SeqCst);
        }
        self.check_current()?;
        if self.gate.skip_effect {
            return Ok(());
        }
        effect()?;
        if self.gate.repeat_effect {
            effect()?;
        }
        Ok(())
    }
}
impl HistoricalDisclosureAuthority for Gate {
    fn acquire<'a>(
        &'a self,
        scope: &HistoricalDisclosureScope,
    ) -> Result<Box<dyn HistoricalDisclosureLease + 'a>> {
        if self.refuse || scope != &self.expected {
            return Err(BundleError::Permission);
        }
        let mut actual = scope.clone();
        if self.substitute_scope {
            actual.principal_id = "substituted-reader".into();
        }
        Ok(Box::new(Lease {
            scope: actual,
            gate: self,
        }))
    }
}
fn gate(source: &RecoveredEvidence) -> Gate {
    Gate {
        expected: HistoricalDisclosureScope::new(
            source,
            "native-reader",
            HistoricalAction::ProofMetadata,
            references(),
            HistoricalDestination::NativeTerminal,
            &serde_json::to_vec(&Projection {
                historical: "saved-only",
            })
            .unwrap(),
        )
        .unwrap(),
        revoked: AtomicBool::new(false),
        fence: Mutex::new(()),
        revoke_in_effect: false,
        refuse: false,
        substitute_scope: false,
        repeat_effect: false,
        skip_effect: false,
    }
}
fn disclosure<'a>(
    source: &RecoveredEvidence,
    gate: &'a Gate,
) -> Result<HistoricalDisclosure<'a, Projection>> {
    HistoricalDisclosure::authorize(
        source,
        "native-reader",
        HistoricalAction::ProofMetadata,
        references(),
        Projection {
            historical: "saved-only",
        },
        gate,
    )
}
#[test]
fn exact_snapshot_scope_and_held_final_effect_are_required() {
    let source = source();
    let gate = gate(&source);
    let mut delivered = false;
    disclosure(&source, &gate)
        .unwrap()
        .deliver(|projection| {
            assert!(gate.fence.try_lock().is_err());
            assert_eq!(projection.historical, "saved-only");
            delivered = true;
            Ok(())
        })
        .unwrap();
    assert!(delivered);
    // Identical saved generation/provenance does not enroll a reopened handle.
    assert!(disclosure(&super::tests::source(), &gate).is_err());
    let mut changed = references();
    changed.account_ids.push("unapproved-account".into());
    assert!(
        HistoricalDisclosure::authorize(
            &source,
            "native-reader",
            HistoricalAction::ProofMetadata,
            changed,
            Projection {
                historical: "saved-only"
            },
            &gate
        )
        .is_err()
    );
    assert!(
        HistoricalDisclosure::authorize(
            &source,
            "another-reader",
            HistoricalAction::ProofMetadata,
            references(),
            Projection {
                historical: "saved-only"
            },
            &gate
        )
        .is_err()
    );
    assert!(
        HistoricalDisclosure::authorize(
            &source,
            "native-reader",
            HistoricalAction::SignedResultMetadata,
            references(),
            Projection {
                historical: "saved-only"
            },
            &gate
        )
        .is_err()
    );
}
#[test]
fn revocation_before_handoff_and_at_effect_admission_disclose_nothing() {
    let source = source();
    let gate = gate(&source);
    let pending = disclosure(&source, &gate).unwrap();
    gate.revoked.store(true, Ordering::SeqCst);
    let mut called = false;
    assert!(
        pending
            .deliver(|_| {
                called = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!called);
    let mut gate = super::tests::gate(&source);
    gate.revoke_in_effect = true;
    assert!(
        disclosure(&source, &gate)
            .unwrap()
            .deliver(|_| {
                called = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!called);
}
#[test]
fn output_kind_and_data_bounds_cannot_be_widened() {
    let source = source();
    assert!(
        HistoricalDisclosureScope::new(
            &source,
            "reader",
            HistoricalAction::ProofMetadata,
            references(),
            HistoricalDestination::NewPrivateLocalFile("/tmp/not-authorized".into()),
            b"metadata"
        )
        .is_err()
    );
    assert!(
        HistoricalDisclosureScope::new(
            &source,
            "reader",
            HistoricalAction::ExportExactTransaction,
            references(),
            HistoricalDestination::NativeTerminal,
            b"transaction"
        )
        .is_err()
    );
    assert!(
        HistoricalDisclosureScope::new(
            &source,
            "reader",
            HistoricalAction::ProofMetadata,
            references(),
            HistoricalDestination::NativeTerminal,
            &vec![0; MAX_HISTORICAL_METADATA_BYTES + 1]
        )
        .is_err()
    );
    let mut duplicate = references();
    duplicate.account_ids.push("old-account".into());
    assert!(
        HistoricalDisclosureScope::new(
            &source,
            "reader",
            HistoricalAction::ProofMetadata,
            duplicate,
            HistoricalDestination::NativeTerminal,
            b"metadata"
        )
        .is_err()
    );
}
#[cfg(target_os = "linux")]
#[test]
fn private_file_is_new_exact_exclusive_and_aliases_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("historical.bin");
    write_new_private_file(&output, b"synthetic-not-a-transaction").unwrap();
    assert_eq!(
        std::fs::read(&output).unwrap(),
        b"synthetic-not-a-transaction"
    );
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(write_new_private_file(&output, b"replacement").is_err());
    assert_eq!(
        std::fs::read(&output).unwrap(),
        b"synthetic-not-a-transaction"
    );
    let alias = directory.path().join("alias");
    symlink(&output, &alias).unwrap();
    assert!(write_new_private_file(&alias, b"replacement").is_err());
    let parent_alias = directory.path().join("parent-alias");
    symlink(directory.path(), &parent_alias).unwrap();
    assert!(write_new_private_file(&parent_alias.join("new.bin"), b"private").is_err());
    assert!(!directory.path().join("new.bin").exists());
}

#[test]
fn refused_or_substituted_lease_never_returns_disclosure() {
    let source = source();
    let mut gate = gate(&source);
    gate.refuse = true;
    assert!(disclosure(&source, &gate).is_err());
    gate.refuse = false;
    gate.substitute_scope = true;
    assert!(disclosure(&source, &gate).is_err());
}
#[test]
fn provider_cannot_skip_or_duplicate_one_shot_handoff() {
    let source = source();
    let mut gate = gate(&source);
    gate.skip_effect = true;
    let mut count = 0;
    assert!(
        disclosure(&source, &gate)
            .unwrap()
            .deliver(|_| {
                count += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(count, 0);
    gate.skip_effect = false;
    gate.repeat_effect = true;
    assert!(
        disclosure(&source, &gate)
            .unwrap()
            .deliver(|_| {
                count += 1;
                Ok(())
            })
            .is_err()
    );
    // An invalid provider's attempted repeat is rejected, but the first admitted
    // disclosure cannot be revoked and is never reported as undone.
    assert_eq!(count, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn exact_export_helper_requires_bound_payload_action_component_and_lease() {
    let mut source = source();
    source.provenance.kind = JournalKind::ExactTransactions;
    source.provenance.component_id = "financial-0-transactions".into();
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("exact.tx");
    let bytes = b"synthetic-bound-bytes-not-a-payable-transaction";
    let mut refs = references();
    refs.artifact_id = "old-checkpoint".into();
    refs.transaction_checkpoint_id = Some("old-checkpoint".into());
    refs.proof_job_id = Some("old-proof".into());
    refs.signed_result_id = Some("old-signed-result".into());
    refs.transaction_id = Some("1".repeat(64));
    refs.transaction_bytes_digest = Some(hex_digest(bytes));
    let scope = HistoricalDisclosureScope::new(
        &source,
        "native-reader",
        HistoricalAction::ExportExactTransaction,
        refs,
        HistoricalDestination::NewPrivateLocalFile(destination.clone()),
        bytes,
    )
    .unwrap();
    let mut gate = gate(&source);
    gate.expected = scope.clone();
    let lease = acquire_checked(&gate, &scope).unwrap();
    assert!(export_exact_transaction_bytes(&scope, &*lease, b"substituted-bytes").is_err());
    let mut changed = scope.clone();
    changed.action = HistoricalAction::ProofMetadata;
    assert!(export_exact_transaction_bytes(&changed, &*lease, bytes).is_err());
    changed = scope.clone();
    changed.origin.provenance.kind = JournalKind::SignedResults;
    assert!(export_exact_transaction_bytes(&changed, &*lease, bytes).is_err());
    changed = scope.clone();
    changed.destination =
        HistoricalDestination::NewPrivateLocalFile(directory.path().join("another.tx"));
    assert!(export_exact_transaction_bytes(&changed, &*lease, bytes).is_err());
    assert!(!destination.exists());
    export_exact_transaction_bytes(&scope, &*lease, bytes).unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    assert!(export_exact_transaction_bytes(&scope, &*lease, bytes).is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
}

#[test]
fn v1_identity_wrappers_keep_scope_and_serialized_origin_unchanged() {
    let source = source();
    let identity = source.disclosure_identity();
    assert!(identity.generation() == Some(source.generation()));
    assert!(identity.provenance() == source.provenance());
    assert!(identity.archive().is_none());
    assert!(identity.binding() == source.historical_binding());
    let old = gate(&source).expected;
    let generic = HistoricalDisclosureScope::from_source(
        identity,
        "native-reader",
        HistoricalAction::ProofMetadata,
        references(),
        HistoricalDestination::NativeTerminal,
        &serde_json::to_vec(&Projection {
            historical: "saved-only",
        })
        .unwrap(),
    )
    .unwrap();
    assert!(old == generic);
    let encoded = serde_json::to_value(identity.origin()).unwrap();
    assert_eq!(encoded.as_object().unwrap().len(), 3);
    assert!(encoded.get("archive").is_none());
    let gate = gate(&source);
    HistoricalDisclosure::authorize_from_source(
        identity,
        "native-reader",
        HistoricalAction::ProofMetadata,
        references(),
        Projection {
            historical: "saved-only",
        },
        &gate,
    )
    .unwrap()
    .deliver(|projection| {
        assert_eq!(projection.historical, "saved-only");
        Ok(())
    })
    .unwrap();
}
