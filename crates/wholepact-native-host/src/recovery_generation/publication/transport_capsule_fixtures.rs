//! Synthetic encrypted storage materialization. No NativeDecision, signer lease,
//! publication admission, signing capability or production issuer is created.
use super::*;
// Existing never-funded signed authority fixture. Its local audit phases are
// explicitly modeled inert records; this does not exercise the native actor.
use super::super::retained_continuity_fixture as modeled_audit;
pub(crate) fn evidence() -> HostRecoveryContinuityEvidenceV5 {
    modeled_audit::fixture()
}
/// Keep the exact signed Claim, Reserve, Consume and transport fence, while
/// preserving uncertainty from a missing local Consume audit append.
pub(crate) fn evidence_without_local_success() -> HostRecoveryContinuityEvidenceV5 {
    let mut evidence = evidence();
    evidence
        .complete_history
        .signer_common_context_audit
        .reentry
        .rows
        .retain(|row| row.phase() != "consumed");
    evidence.validate().unwrap();
    evidence
}
fn audit_commit(manifest: &ManifestV5, digest: &str, target: &std::path::Path) -> Result<CommitV5> {
    let original = evidence();
    if manifest.continuity.len() != 1
        || (manifest.continuity[0].complete_history != original.complete_history
            && manifest.continuity[0].complete_history
                != evidence_without_local_success().complete_history)
    {
        return Err(Error::Permission);
    }
    let admissions = requests(manifest, target, digest)?
        .into_iter()
        .map(|request| HostRecoveryPublicationRecordV5 {
            request,
            // Inert saved historical audit record, never a native approval.
            native_review_digest: "51".repeat(32),
            admission_id: "52".repeat(32),
        })
        .collect();
    Ok(CommitV5 {
        version: 5,
        plan_digest: manifest.plan_digest.clone(),
        manifest_digest: digest.into(),
        admissions,
    })
}
impl PreparedPublicationV5 {
    pub(crate) fn materialize_synthetic_archive_fixture(self) -> Result<()> {
        let p = &self.generation.pending;
        p.source.check()?;
        p.directory.check()?;
        p.check_inventory()?;
        let commit = audit_commit(&self.manifest, &self.manifest_digest, &p.plan.target)?;
        drop(open_checked_v5(&p.directory, &p.secrets, &commit, true)?);
        let bytes = seal(&p.secrets, b"commit", &encode(&commit)?)?;
        p.directory.write_new(COMMIT, &bytes)
    }
}
impl PreparedLayeredPublicationV5 {
    pub(crate) fn materialize_synthetic_archive_fixture(self) -> Result<()> {
        let p = &self.generation.pending;
        p.check()?;
        let commit = audit_commit(&self.manifest, &self.manifest_digest, &p.plan.target)?;
        let bytes = seal(&p.secrets, b"commit", &encode(&commit)?)?;
        drop(super::super::layered_publication::open_layered_checked(
            &p.directory,
            &p.secrets,
            &bytes,
            true,
        )?);
        p.directory.write_new(COMMIT, &bytes)
    }
}

pub(crate) fn retained_archive_evidence(
    capsule: &super::super::archive_history::VerifiedGenerationCapsule,
) -> Result<Vec<(String, Vec<HostRecoveryContinuityEvidenceV5>)>> {
    let mut result = Vec::new();
    for (digest, history) in capsule.histories() {
        let source = capsule
            .archive()
            .read_private_entry(digest, "host-source-material", 1024)
            .map_err(|_| Error::Authentication)?;
        let secrets = crate::vault::generation_archive::source_from_material(
            source,
            &history.descriptor().profile_id,
            &history.descriptor().plan_digest,
        )?;
        let bytes = capsule
            .archive()
            .read_private_entry(digest, "host-manifest", MAX_DOCUMENT)
            .map_err(|_| Error::Authentication)?;
        let manifest: ManifestV5 = serde_json::from_slice(&unseal(&secrets, b"manifest", &bytes)?)?;
        if manifest.version != 5 {
            return Err(Error::Authentication);
        }
        let saved_commit = capsule
            .archive()
            .read_private_entry(digest, "host-commit", MAX_DOCUMENT)
            .map_err(|_| Error::Authentication)?;
        let commit: CommitV5 =
            serde_json::from_slice(&unseal(&secrets, b"commit", &saved_commit)?)?;
        let expected = audit_commit(
            &manifest,
            &hash(&bytes),
            std::path::Path::new(
                &capsule
                    .archive()
                    .node(digest)
                    .map_err(|_| Error::Authentication)?
                    .original_root,
            ),
        )?;
        if encode(&commit)? != encode(&expected)? {
            return Err(Error::Authentication);
        }
        for e in &manifest.continuity {
            e.validate().map_err(|_| Error::Authentication)?;
        }
        result.push((history.generation_id().into(), manifest.continuity));
    }
    Ok(result)
}
