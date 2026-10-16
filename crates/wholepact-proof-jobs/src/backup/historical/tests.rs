//! Never-funded synthetic PCZT input only. No prover, signer, network or worker
//! is run; a queued checkpoint is archived and disclosed only as metadata.
use super::*;
use crate::{CheckpointScope, LocalAction, LocalProofConsent, ProofJobStore};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use wholepact_storage_security::{DatabaseKey, create_encrypted, generation_archive as capsule};
type R<T> = std::result::Result<T, BundleError>;
struct InputConsent;
impl LocalProofConsent for InputConsent {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        scope.principal_id == "synthetic-proof-owner"
            && action == LocalAction::RetainPrivateWitnesses
    }
}
struct Capture(capsule::ArchiveScope);
struct Captured;
impl capsule::ArchiveAuthority for Capture {
    fn acquire<'a>(
        &'a self,
        scope: &capsule::ArchiveScope,
    ) -> capsule::Result<Box<dyn capsule::ArchiveLease + 'a>> {
        if *scope != self.0 {
            return Err(capsule::ArchiveError::Permission);
        }
        Ok(Box::new(Captured))
    }
}
impl capsule::ArchiveLease for Captured {
    fn check_current(&self) -> capsule::Result<()> {
        Ok(())
    }
}
struct Gate {
    source: HistoricalSourceBinding,
    origin: HistoricalOrigin,
    job: String,
    accounts: Vec<String>,
    used: AtomicBool,
    revoked: AtomicBool,
    fence: Mutex<()>,
}
struct Lease<'a> {
    gate: &'a Gate,
    scope: HistoricalDisclosureScope,
}
impl HistoricalDisclosureAuthority for Gate {
    fn acquire<'a>(
        &'a self,
        scope: &HistoricalDisclosureScope,
    ) -> R<Box<dyn HistoricalDisclosureLease + 'a>> {
        if scope.source != self.source
            || scope.origin != self.origin
            || scope.action != HistoricalAction::ProofMetadata
            || scope.principal_id != "synthetic-native-reader"
            || scope.references.artifact_id != self.job
            || scope.references.account_ids != self.accounts
            || scope.destination != HistoricalDestination::NativeTerminal
            || self.used.load(Ordering::SeqCst)
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(Lease {
            gate: self,
            scope: scope.clone(),
        }))
    }
}
impl HistoricalDisclosureLease for Lease<'_> {
    fn scope(&self) -> &HistoricalDisclosureScope {
        &self.scope
    }
    fn check_current(&self) -> R<()> {
        if self.gate.revoked.load(Ordering::SeqCst) {
            Err(BundleError::Permission)
        } else {
            Ok(())
        }
    }
    fn run_effect(&self, effect: &mut dyn FnMut() -> R<()>) -> R<()> {
        let _held = self
            .gate
            .fence
            .lock()
            .map_err(|_| BundleError::Permission)?;
        self.check_current()?;
        if self.gate.used.swap(true, Ordering::SeqCst) {
            return Err(BundleError::Permission);
        }
        effect()
    }
}
#[test]
fn archived_proof_metadata_is_exactly_bound_and_never_restarts_work() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = DatabaseKey::from_bytes([211; 32]);
    let path = dir.path().join("proof.sqlite");
    let jobs =
        ProofJobStore::from_encrypted_connection(create_encrypted(&path, &key).unwrap()).unwrap();
    let fixture = wholepact_protocol::synthetic::review_fixture().unwrap();
    let verified =
        wholepact_protocol::review::verify_review(&fixture.pczt_bytes, &fixture.policy).unwrap();
    let scope = CheckpointScope {
        principal_id: "synthetic-proof-owner".into(),
        candidate_id: "synthetic-candidate".into(),
        manifest_digest: hex::encode(fixture.policy.manifest_digest),
        artifact_digest: crate::digest(&fixture.pczt_bytes),
        effects_commitment: verified.shielded_sighash().into(),
        coordination_request_digest: "21".repeat(32),
        review_binding: verified.review_binding().into(),
        account_ids: fixture
            .policy
            .participants
            .iter()
            .map(|p| p.account_id.clone())
            .collect(),
        local_operator: "synthetic-local-operator".into(),
        purpose: "Synthetic archive reader qualification only".into(),
        retention_policy: "Private fixture removed after test".into(),
    };
    let status = jobs
        .enqueue(
            &scope,
            "synthetic-archived-proof-key",
            &fixture.pczt_bytes,
            &fixture.policy,
            wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
            &InputConsent,
        )
        .unwrap();
    drop(jobs);
    let before = std::fs::read(&path).unwrap();
    // Capture never writes inside the source root or a source journal directory.
    let output = tempfile::tempdir().unwrap();
    std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let destination = output.path().join("capsule.sqlite");
    let sources =
        [
            capsule::RegisteredSource::new(
                "proof",
                "current-proof",
                capsule::Source::Journal(&path),
            )
            .unwrap(),
        ];
    let node = capsule::NodeSpec {
        generation_id: "22".repeat(32),
        profile_id: "synthetic-profile".into(),
        original_root: dir.path().into(),
    };
    let capsule_id = "23".repeat(32);
    let capture = Capture(
        capsule::ArchiveScope::for_snapshot(&destination, &key, &capsule_id, &node, &sources, &[])
            .unwrap(),
    );
    capsule::snapshot(capsule::SnapshotRequest {
        destination: &destination,
        key: &key,
        capsule_id: &capsule_id,
        node: &node,
        sources: &sources,
        parents: &[],
        authority: &capture,
    })
    .unwrap();
    let archive = capsule::inspect(&destination, &key).unwrap();
    let open = || {
        archive
            .journal(archive.manifest_digest(), "proof")
            .unwrap()
            .inspect_ordinary(&key, &super::super::TEMPLATE)
            .unwrap()
    };
    let source = open();
    let reopened = open();
    let gate = Gate {
        source: source.disclosure_identity().binding(),
        origin: source.disclosure_identity().origin(),
        job: status.job_id.clone(),
        accounts: scope.account_ids.clone(),
        used: AtomicBool::new(false),
        revoked: AtomicBool::new(false),
        fence: Mutex::new(()),
    };
    assert!(
        archived_historical_proof(&reopened, "synthetic-native-reader", &status.job_id, &gate)
            .is_err()
    );
    let first =
        archived_historical_proof(&source, "synthetic-native-reader", &status.job_id, &gate)
            .unwrap();
    let second =
        archived_historical_proof(&source, "synthetic-native-reader", &status.job_id, &gate)
            .unwrap();
    first
        .deliver(|metadata| {
            assert!(gate.fence.try_lock().is_err());
            assert_eq!(metadata.historical_state, crate::JobState::Queued);
            assert!(metadata.retained_result_digest.is_none());
            assert_eq!(
                metadata
                    .origin
                    .archive
                    .as_ref()
                    .unwrap()
                    .root_manifest_digest(),
                archive.manifest_digest()
            );
            assert_eq!(metadata.restrictions.authorization_exposure, "unknown");
            assert_eq!(
                metadata.restrictions.external_signatures,
                "unknown_possible"
            );
            assert!(
                !metadata.restrictions.current_authority && !metadata.restrictions.replay_allowed
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
    assert!(
        archived_historical_proof(&source, "synthetic-native-reader", &status.job_id, &gate)
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
