//! Synthetic encrypted retained-record history. No native approval, account
//! continuity, proof, signature, financial eligibility or live settlement claim.
use super::*;
use std::{collections::BTreeMap, sync::Mutex};
use wholepact_engine::recovery::{
    HistoricalParticipantSelection, archived_historical_participant_record,
    historical_participant_record,
};
use wholepact_storage_security::bundle::{
    self,
    recovery::{
        RecoveryProvenance, VerifiedRecoveryComponent,
        evidence::{RecoveredEvidence, history::*},
        generation::GenerationBinding,
    },
    *,
};

struct BackupGate;
impl BundleLease for BackupGate {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "synthetic-private-record-history"
    }
}
impl BundleAuthority for BackupGate {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.principal_id != "synthetic-admin" || scope.profile_id != "synthetic-profile" {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(BackupGate))
    }
}
struct HistoryGate {
    source: HistoricalSourceBinding,
    origin: HistoricalOrigin,
    revoked: AtomicBool,
    fence: Mutex<()>,
}
struct HistoryLease<'a> {
    scope: HistoricalDisclosureScope,
    authority: &'a HistoryGate,
}
impl HistoricalDisclosureLease for HistoryLease<'_> {
    fn scope(&self) -> &HistoricalDisclosureScope {
        &self.scope
    }
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        if self.authority.revoked.load(Ordering::SeqCst) {
            Err(BundleError::Permission)
        } else {
            Ok(())
        }
    }
    fn run_effect(
        &self,
        effect: &mut dyn FnMut() -> std::result::Result<(), BundleError>,
    ) -> std::result::Result<(), BundleError> {
        let _held = self
            .authority
            .fence
            .lock()
            .map_err(|_| BundleError::Permission)?;
        self.check_current()?;
        effect()
    }
}
impl HistoricalDisclosureAuthority for HistoryGate {
    fn acquire<'a>(
        &'a self,
        scope: &HistoricalDisclosureScope,
    ) -> std::result::Result<Box<dyn HistoricalDisclosureLease + 'a>, BundleError> {
        if scope.source != self.source
            || scope.origin != self.origin
            || scope.principal_id != "native-history-reader"
            || scope.action != HistoricalAction::ParticipantRecord
            || scope.destination != HistoricalDestination::NativeTerminal
            || scope.references.artifact_id != "private-record-alice"
            || scope.references.participant_id.as_deref() != Some("alice")
            || scope.references.account_ids != ["account-alice", "account-bob"]
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(HistoryLease {
            scope: scope.clone(),
            authority: self,
        }))
    }
}
fn evidence(
    store: &Store,
    dir: &std::path::Path,
) -> (
    RecoveredEvidence,
    std::path::PathBuf,
    GenerationBinding,
    RecoveryProvenance,
) {
    let adapter = wholepact_store::bundle::CoordinationBundleAdapter::new(store).unwrap();
    let sources = [RegisteredJournal::new("coordination", &adapter).unwrap()];
    let archive = dir.join("private-record-archive.sqlite");
    let restored = dir.join("private-record-quarantine.sqlite");
    let key = DatabaseKey::from_bytes([181; 32]);
    snapshot(SnapshotRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        sources: &sources,
        destination: &archive,
        key: &key,
        authority: &BackupGate,
        coverage: Coverage {
            present: BTreeMap::from([(
                JournalKind::CoordinationAuthority,
                vec!["coordination".into()],
            )]),
            absent: [
                JournalKind::SignerConsentAuthority,
                JournalKind::WalletScan,
                JournalKind::ProofWitness,
                JournalKind::SignedResults,
                JournalKind::ExactTransactions,
                JournalKind::Submission,
                JournalKind::TransportInbox,
                JournalKind::TransportOutbox,
            ]
            .into_iter()
            .collect(),
        },
    })
    .unwrap();
    test_restore(RestoreRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        archive: &archive,
        key: &key,
        targets: &[RestoreTarget {
            component_id: "coordination",
            template: wholepact_store::bundle::coordination_template(),
            destination: &restored,
            key: &key,
        }],
        authority: &BackupGate,
    })
    .unwrap();
    let source = VerifiedRecoveryComponent::open(
        bundle::history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &key,
            component_id: "coordination",
            restored_component: &restored,
            restored_key: &key,
        },
        wholepact_store::bundle::coordination_template(),
    )
    .unwrap();
    let binding = GenerationBinding::new(&hash(182), &hash(183)).unwrap();
    let destination = dir.join("history-coordination.sqlite");
    wholepact_store::bundle::reconstruct_coordination_successor_evidence(
        &source,
        &destination,
        &key,
        &binding,
    )
    .unwrap();
    let provenance = source.provenance().clone();
    let evidence = wholepact_store::bundle::open_coordination_successor_evidence(
        &destination,
        &key,
        &binding,
        &provenance,
    )
    .unwrap();
    (evidence, destination, binding, provenance)
}
#[test]
fn exact_private_history_keeps_observations_historical_and_originals_immutable() {
    let dir = private_directory();
    let path = dir.path().join("source.sqlite");
    let key = DatabaseKey::from_bytes([180; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
    let (agreement, candidate, revision) = setup_candidate(&engine);
    let authority = SyntheticAuthority::for_engine(&engine);
    let retained = retain(&engine, &authority, &agreement, &candidate, revision);
    engine
        .observe_participant_record(
            &owner(),
            "historical-positive-observation",
            &agreement,
            retained.agreement_revision,
            observe_request(1),
            authority.runtime(&window()),
            &mut SyntheticChain {
                status: ChainStatus::ConfirmationPolicyMet,
                second: 1,
            },
        )
        .unwrap();
    drop(authority);
    drop(engine);
    let store = Store::open_encrypted(&path, &key).unwrap();
    let (evidence, evidence_path, binding, provenance) = evidence(&store, dir.path());
    let before = std::fs::read(&evidence_path).unwrap();
    let gate = HistoryGate {
        source: evidence.historical_binding(),
        origin: HistoricalOrigin::from_evidence(&evidence),
        revoked: AtomicBool::new(false),
        fence: Mutex::new(()),
    };
    let selection = HistoricalParticipantSelection {
        agreement_id: agreement.clone(),
        record_id: "private-record-alice".into(),
        historical_owner_principal_id: "synthetic-owner".into(),
        historical_profile_id: "synthetic-local-profile".into(),
        participant_id: "alice".into(),
        account_id: "account-alice".into(),
    };
    historical_participant_record(&evidence, "native-history-reader", &selection, &gate)
        .unwrap()
        .deliver(|record| {
            assert!(gate.fence.try_lock().is_err());
            assert_eq!(
                record.recorded_own_authorization.consent_record_ref,
                "PRIVATE-SYNTHETIC-OWN-CONSENT-SENTINEL"
            );
            assert_eq!(record.historical_observation_count, 1);
            assert_eq!(record.restrictions.authorization_exposure, "unknown");
            assert!(
                !record.restrictions.current_authority
                    && !record.restrictions.replay_allowed
                    && !record.restrictions.replacement_allowed
            );
            assert!(record.restrictions.recovery_required);
            assert_eq!(
                record.references.account_ids,
                ["account-alice", "account-bob"]
            );
            Ok(())
        })
        .unwrap();
    let mut wrong = selection.clone();
    wrong.account_id = "account-bob".into();
    assert!(
        historical_participant_record(&evidence, "native-history-reader", &wrong, &gate).is_err()
    );
    wrong = selection.clone();
    wrong.historical_owner_principal_id = "another-owner".into();
    assert!(
        historical_participant_record(&evidence, "native-history-reader", &wrong, &gate).is_err()
    );
    let pending =
        historical_participant_record(&evidence, "native-history-reader", &selection, &gate)
            .unwrap();
    gate.revoked.store(true, Ordering::SeqCst);
    let mut handed_off = false;
    assert!(
        pending
            .deliver(|_| {
                handed_off = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!handed_off);
    gate.revoked.store(false, Ordering::SeqCst);
    let reopened = wholepact_store::bundle::open_coordination_successor_evidence(
        &evidence_path,
        &DatabaseKey::from_bytes([181; 32]),
        &binding,
        &provenance,
    )
    .unwrap();
    assert!(
        historical_participant_record(&reopened, "native-history-reader", &selection, &gate)
            .is_err()
    );
    assert!(Store::open_encrypted(&evidence_path, &DatabaseKey::from_bytes([181; 32])).is_err());
    assert_eq!(std::fs::read(&evidence_path).unwrap(), before);
}

use wholepact_storage_security::generation_archive as capsule;
struct CapsuleGate(capsule::ArchiveScope);
struct CapsuleLease;
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
impl capsule::ArchiveLease for CapsuleLease {
    fn check_current(&self) -> capsule::Result<()> {
        Ok(())
    }
}
fn record_capsule(
    dir: &std::path::Path,
    output: &std::path::Path,
    name: &str,
    generation: &str,
    capsule_id: &str,
    parents: &[&capsule::VerifiedArchive],
) -> capsule::VerifiedArchive {
    let destination = output.join(name);
    let source = dir.join("staged-generation.sqlite");
    let sources = [capsule::RegisteredSource::new(
        "coordination",
        "current-coordination",
        capsule::Source::Journal(&source),
    )
    .unwrap()];
    let node = capsule::NodeSpec {
        generation_id: generation.into(),
        profile_id: "synthetic-current-profile".into(),
        original_root: dir.into(),
    };
    let key = DatabaseKey::from_bytes([185; 32]);
    let scope = capsule::ArchiveScope::for_snapshot(
        &destination,
        &key,
        capsule_id,
        &node,
        &sources,
        parents,
    )
    .unwrap();
    capsule::snapshot(capsule::SnapshotRequest {
        destination: &destination,
        key: &key,
        capsule_id,
        node: &node,
        sources: &sources,
        parents,
        authority: &CapsuleGate(scope),
    })
    .unwrap();
    capsule::inspect(&destination, &key).unwrap()
}
#[test]
fn archived_generation_records_keep_exact_provenance_and_observations_unknown() {
    let dir = private_directory();
    let path = dir.path().join("source.sqlite");
    let key = DatabaseKey::from_bytes([180; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
    let (agreement, candidate, revision) = setup_candidate(&engine);
    let authority = SyntheticAuthority::for_engine(&engine);
    let retained = retain(&engine, &authority, &agreement, &candidate, revision);
    engine
        .observe_participant_record(
            &owner(),
            "archived-positive-observation",
            &agreement,
            retained.agreement_revision,
            observe_request(1),
            authority.runtime(&window()),
            &mut SyntheticChain {
                status: ChainStatus::ConfirmationPolicyMet,
                second: 1,
            },
        )
        .unwrap();
    drop(authority);
    drop(engine);
    let store = Store::open_encrypted(&path, &key).unwrap();
    let (legacy, _, binding, provenance) = evidence(&store, dir.path());
    drop(store);
    let source = VerifiedRecoveryComponent::open(
        bundle::history::HistoryOpenRequest {
            archive: &dir.path().join("private-record-archive.sqlite"),
            archive_key: &DatabaseKey::from_bytes([181; 32]),
            component_id: "coordination",
            restored_component: &dir.path().join("private-record-quarantine.sqlite"),
            restored_key: &DatabaseKey::from_bytes([181; 32]),
        },
        wholepact_store::bundle::coordination_template(),
    )
    .unwrap();
    wholepact_store::recovery::stage_coordination_successor(
        &source,
        &binding,
        &dir.path().join("staged-generation.sqlite"),
        &DatabaseKey::from_bytes([184; 32]),
    )
    .unwrap();
    drop(source);
    // All mutable fixture owners are closed before protected capture. Output is
    // disjoint from the source root and journal parent, as capture requires.
    let output = private_directory();
    let archive = record_capsule(
        dir.path(),
        output.path(),
        "record-capsule.sqlite",
        binding.generation_id(),
        &hash(186),
        &[],
    );
    let next = record_capsule(
        dir.path(),
        output.path(),
        "next-record-capsule.sqlite",
        &hash(187),
        &hash(188),
        &[&archive],
    );
    let archived = archive
        .journal(archive.manifest_digest(), "coordination")
        .unwrap()
        .open_generation(
            &DatabaseKey::from_bytes([184; 32]),
            &binding,
            &provenance,
            wholepact_store::recovery::coordination_successor_template(),
        )
        .unwrap();
    let same_node_other_root = next
        .journal(archive.manifest_digest(), "coordination")
        .unwrap()
        .open_generation(
            &DatabaseKey::from_bytes([184; 32]),
            &binding,
            &provenance,
            wholepact_store::recovery::coordination_successor_template(),
        )
        .unwrap();
    let gate = HistoryGate {
        source: archived.disclosure_identity().binding(),
        origin: archived.disclosure_identity().origin(),
        revoked: AtomicBool::new(false),
        fence: Mutex::new(()),
    };
    let selection = HistoricalParticipantSelection {
        agreement_id: agreement,
        record_id: "private-record-alice".into(),
        historical_owner_principal_id: "synthetic-owner".into(),
        historical_profile_id: "synthetic-local-profile".into(),
        participant_id: "alice".into(),
        account_id: "account-alice".into(),
    };
    archived_historical_participant_record(&archived, "native-history-reader", &selection, &gate)
        .unwrap()
        .deliver(|record| {
            assert!(gate.fence.try_lock().is_err());
            assert_eq!(record.origin.generation_id, binding.generation_id());
            assert_eq!(record.origin.inventory_digest, binding.inventory_digest());
            assert!(record.origin.provenance == provenance);
            let origin = record.origin.archive.as_ref().unwrap();
            assert_eq!(origin.root_manifest_digest(), archive.manifest_digest());
            assert_eq!(origin.selected_manifest_digest(), archive.manifest_digest());
            assert_eq!(
                origin.selected_node_digest(),
                archive.manifest().node_digest
            );
            assert_eq!(record.historical_observation_count, 1);
            assert_eq!(record.restrictions.authorization_exposure, "unknown");
            assert_eq!(
                record.restrictions.chain_observation,
                "unknown_historical_observations_only"
            );
            assert_eq!(record.restrictions.external_signatures, "unknown_possible");
            assert!(
                !record.restrictions.current_authority
                    && !record.restrictions.replay_allowed
                    && !record.restrictions.replacement_allowed
            );
            assert!(record.restrictions.recovery_required);
            Ok(())
        })
        .unwrap();
    assert!(
        historical_participant_record(&legacy, "native-history-reader", &selection, &gate).is_err()
    );
    assert!(
        archived_historical_participant_record(
            &same_node_other_root,
            "native-history-reader",
            &selection,
            &gate
        )
        .is_err()
    );
    let mut wrong = selection.clone();
    wrong.account_id = "account-bob".into();
    assert!(
        archived_historical_participant_record(&archived, "native-history-reader", &wrong, &gate)
            .is_err()
    );
    wrong = selection.clone();
    wrong.historical_profile_id = "unrelated-profile".into();
    assert!(
        archived_historical_participant_record(&archived, "native-history-reader", &wrong, &gate)
            .is_err()
    );
    let pending = archived_historical_participant_record(
        &archived,
        "native-history-reader",
        &selection,
        &gate,
    )
    .unwrap();
    gate.revoked.store(true, Ordering::SeqCst);
    let mut leaked = false;
    assert!(
        pending
            .deliver(|_| {
                leaked = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!leaked);
}
