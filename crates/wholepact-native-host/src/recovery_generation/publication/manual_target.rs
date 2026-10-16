//! Private integrity conjunction of the actual layered committed generation and
//! its complete authenticated parent capsule. It grants no financial authority.
use super::archive_history::{VerifiedGenerationCapsule, open_layered_parent, source_plan_version};
use super::inherited_manual_identity::InheritedManualIdentityCoverage;
use super::*;

pub(crate) struct ManualCommittedTarget<'directory> {
    directory: &'directory Directory,
    secrets: &'directory Secrets,
    generation_id: String,
    inventory_digest: String,
    plan_digest: String,
    profile_id: String,
    canonical_root: String,
    destination_identity_digest: String,
    checked_files: Vec<(&'static str, String)>,
    // Retain the real immutable capsule owner until every comparison is done.
    _capsule: VerifiedGenerationCapsule,
    coverage: InheritedManualIdentityCoverage,
}
impl<'directory> ManualCommittedTarget<'directory> {
    pub(crate) fn open(
        directory: &'directory Directory,
        secrets: &'directory Secrets,
    ) -> Result<Self> {
        directory.check()?;
        if source_plan_version(directory, secrets)? != 2 {
            // A standalone/v1 source cannot pretend it supplied the complete
            // sealed capsule owner required by this first bounded composition.
            return Err(Error::RecoveryFinancialUnsupported);
        }
        let current_commit = unseal(secrets, b"commit", &directory.read(COMMIT, MAX_DOCUMENT)?)?;
        require_current_financial_family(complete_origins::metadata_version(&current_commit)?)?;
        let (metadata, capsule) = open_layered_parent(directory, secrets)?;
        let coverage = capsule.inherited_manual_identity_coverage()?;
        coverage.require_financial_history_supported()?;
        let actual_root = directory.path("profile.vault")?;
        let actual_root = actual_root.parent().ok_or(Error::Invalid)?;
        if metadata.plan.target != actual_root
            || metadata.plan.successor_profile != secrets.profile()
        {
            return Err(Error::Authentication);
        }
        let checked_files = [PLAN, MANIFEST, COMMIT, "generation.keys"]
            .into_iter()
            .map(|name| Ok((name, hash(&directory.read(name, MAX_DOCUMENT)?))))
            .collect::<Result<Vec<_>>>()?;
        let result = Self {
            directory,
            secrets,
            generation_id: metadata.plan.generation_id,
            inventory_digest: metadata.plan.inventory_digest,
            plan_digest: hex::encode(secrets.generation_plan_digest().ok_or(Error::Quarantined)?),
            profile_id: secrets.profile(),
            canonical_root: actual_root.to_str().ok_or(Error::Invalid)?.into(),
            destination_identity_digest: directory.manual_target_identity_digest()?,
            checked_files,
            _capsule: capsule,
            coverage,
        };
        result.check_current()?;
        Ok(result)
    }
    pub(crate) fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub(crate) fn inventory_digest(&self) -> &str {
        &self.inventory_digest
    }
    pub(crate) fn plan_digest(&self) -> &str {
        &self.plan_digest
    }
    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }
    pub(crate) fn canonical_root(&self) -> &str {
        &self.canonical_root
    }
    pub(crate) fn destination_identity_digest(&self) -> &str {
        &self.destination_identity_digest
    }
    pub(crate) fn coverage(&self) -> &InheritedManualIdentityCoverage {
        &self.coverage
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.directory.check()?;
        if self.secrets.profile() != self.profile_id
            || hex::encode(
                self.secrets
                    .generation_plan_digest()
                    .ok_or(Error::Quarantined)?,
            ) != self.plan_digest
            || self.directory.manual_target_identity_digest()? != self.destination_identity_digest
        {
            return Err(Error::Authentication);
        }
        for (name, digest) in &self.checked_files {
            if hash(&self.directory.read(name, MAX_DOCUMENT)?) != *digest {
                return Err(Error::Authentication);
            }
        }
        Ok(())
    }
}

// Current V5 transport history cannot enter manual enrollment merely because
// its parent happened to carry an older financial-history family.
fn require_current_financial_family(version: u16) -> Result<()> {
    match version {
        1 | 2 | 4 => Ok(()),
        _ => Err(Error::RecoveryFinancialUnsupported),
    }
}

#[cfg(test)]
mod current_family_tests {
    use super::*;
    #[test]
    fn current_v5_is_denied_independently_of_older_parent_coverage() {
        for version in [1, 2, 4] {
            require_current_financial_family(version).unwrap();
        }
        for version in [0, 3, 5, 6] {
            assert!(matches!(
                require_current_financial_family(version),
                Err(Error::RecoveryFinancialUnsupported)
            ));
        }
    }
}
