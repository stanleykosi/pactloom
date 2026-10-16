//! Synthetic encrypted storage materialization. No NativeDecision, signer lease,
//! publication admission, signing capability or production issuer is created.
use super::*;
use wholepact_signer as signer;
mod modeled_audit {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../wholepact-signer/src/consent_journal/common_context_audit_fixture.rs"
    ));
}
pub(crate) fn evidence() -> HostRecoveryContinuityEvidenceV4 {
    modeled_audit::fixture().1
}
/// Exact signed authority Consume remains charged although the modeled local
/// journal stops after read admission, as a crash before local append can do.
pub(crate) fn evidence_without_local_success() -> HostRecoveryContinuityEvidenceV4 {
    let mut evidence = evidence();
    evidence
        .complete_history
        .signer_common_context_audit
        .rows
        .retain(|row| {
            matches!(
                row,
                signer::consent_journal::CommonContextSignerAuditV1::ReadAdmitted { .. }
            )
        });
    evidence.validate().unwrap();
    evidence
}
fn audit_commit(manifest: &ManifestV4, digest: &str, target: &std::path::Path) -> Result<CommitV4> {
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
        .map(|request| HostRecoveryPublicationRecordV4 {
            request,
            native_review_digest: "51".repeat(32),
            admission_id: "52".repeat(32),
        })
        .collect();
    Ok(CommitV4 {
        version: 4,
        plan_digest: manifest.plan_digest.clone(),
        manifest_digest: digest.into(),
        admissions,
    })
}
impl PreparedPublicationV4 {
    pub(crate) fn materialize_synthetic_archive_fixture(self) -> Result<()> {
        let p = &self.generation.pending;
        p.source.check()?;
        p.directory.check()?;
        p.check_inventory()?;
        let commit = audit_commit(&self.manifest, &self.manifest_digest, &p.plan.target)?;
        drop(open_checked_v4(&p.directory, &p.secrets, &commit, true)?);
        let bytes = seal(&p.secrets, b"commit", &encode(&commit)?)?;
        p.directory.write_new(COMMIT, &bytes)
    }
}
impl PreparedLayeredPublicationV4 {
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
) -> Result<Vec<(String, Vec<HostRecoveryContinuityEvidenceV4>)>> {
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
        let manifest: ManifestV4 = serde_json::from_slice(&unseal(&secrets, b"manifest", &bytes)?)?;
        if manifest.version != 4 {
            return Err(Error::Authentication);
        }
        for e in &manifest.continuity {
            e.validate().map_err(|_| Error::Authentication)?;
        }
        result.push((history.generation_id().into(), manifest.continuity));
    }
    Ok(result)
}
