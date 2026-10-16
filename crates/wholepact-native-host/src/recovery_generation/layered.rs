//! Pending version-two construction only. The restored capsule stays quarantined;
//! durable plan/key intent precedes copies and all native publication is separate.
use super::*;
use super::{
    archive_history::VerifiedGenerationCapsule,
    layered_metadata::{LayeredPlan, parent_key_commitment},
};
use crate::{
    generation_restore::RestoredGenerationCapsule, terminal::historical::HistoricalApproval,
};
use wholepact_storage_security::{
    DatabaseKey,
    bundle::recovery::generation::{GenerationBinding, PlannedEmptyInitialization},
    generation_archive::{
        self as archive, ArchiveError, ArchiveLease, CopyAuthority, CopyRequest, CopyScope,
    },
};

pub(super) const PARENT_CAPSULE: &str = "history.capsule.sqlite";

/// No public constructor or deserialization. Source and destination locks survive
/// all reads and journal owners. This is still pending, never published authority.
pub(crate) struct PendingLayeredGeneration {
    pub(super) source: RestoredGenerationCapsule,
    pub(super) secrets: Secrets,
    pub(super) plan: LayeredPlan,
    pub(super) plan_digest: String,
    pub(super) parent_key: Zeroizing<Vec<u8>>,
    // This must remain last so destination handles/keys drop before its lock.
    pub(super) directory: Directory,
}
impl PendingLayeredGeneration {
    /// The native caller must hold its reviewed local-effect admission while
    /// creating the target. This writes only the immutable plan/key intent; the
    /// separate construct approval covers copying complete private parent data.
    pub(crate) fn create(
        source: RestoredGenerationCapsule,
        target: &std::path::Path,
        password: &[u8],
    ) -> Result<Self> {
        source.check()?;
        source.external_destination(target)?;
        if source.capsule().histories().len() >= 16 {
            return Err(Error::Unsupported);
        }
        match std::fs::symlink_metadata(target) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Ok(_) => return Err(Error::Invalid),
            Err(error) => return Err(error.into()),
        }
        let secrets = Secrets::fresh()?;
        let generation_id = hex::encode(crate::random::<32>()?);
        if source.capsule().histories().values().any(|history| {
            history.generation_id() == generation_id || history.profile_id() == secrets.profile()
        }) {
            return Err(Error::Authentication);
        }
        let parent_key = Zeroizing::new(crate::random::<32>()?.to_vec());
        let parent = source.capsule().root();
        let plan = LayeredPlan {
            version: 2,
            generation_id,
            inventory_digest: source.capsule().manifest_digest().into(),
            target: target.into(),
            source_profile: parent.profile_id().into(),
            successor_profile: secrets.profile(),
            parent_manifest_digest: source.capsule().manifest_digest().into(),
            parent_capsule_id: source.capsule().capsule_id().into(),
            parent_node_generation: parent.generation_id().into(),
            parent_key_commitment: parent_key_commitment(&parent_key)?,
            components: parent.current_provenance(),
            affected_accounts: parent.current_semantics().accounts().clone(),
            semantic_inventory_digest: parent.current_semantics().digest().into(),
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
        };
        plan.verify_parent(source.capsule())?;
        let plain = encode(&plan)?;
        let digest: [u8; 32] = Sha256::digest(&plain).into();
        let plan_digest = hex::encode(digest);
        let secrets = secrets.bind_successor_plan(digest)?;
        let vault = secrets.seal(password)?;
        let sealed_plan = seal(&secrets, b"plan", &plain)?;
        let sealed_key = seal(
            &secrets,
            &[b"keys:".as_slice(), plan_digest.as_bytes()].concat(),
            &parent_key,
        )?;
        source.check()?;
        let directory = Directory::create(target)?;
        directory.write_new("profile.vault", &vault)?;
        directory.write_new(PLAN, &sealed_plan)?;
        directory.write_new("generation.keys", &sealed_key)?;
        let pending = Self {
            source,
            secrets,
            plan,
            plan_digest,
            parent_key,
            directory,
        };
        pending.check_inventory()?;
        Ok(pending)
    }

    /// Reopen only an anchored pending version-two plan and its exact source,
    /// target and independently wrapped key. Missing/partial intent is preserved;
    /// no new keys, identities, target or parent are inferred from file existence.
    pub(crate) fn resume(
        source: RestoredGenerationCapsule,
        target: &std::path::Path,
        password: &[u8],
    ) -> Result<Self> {
        source.check()?;
        source.external_destination(target)?;
        let directory = Directory::open(target)?;
        check_inventory(&directory)?;
        if directory.path(COMMIT)?.try_exists()? {
            return Err(Error::Authentication);
        }
        let secrets = Secrets::open(&directory.read("profile.vault", 1024)?, password)?;
        let plain = unseal(&secrets, b"plan", &directory.read(PLAN, MAX_DOCUMENT)?)?;
        let plan: LayeredPlan = serde_json::from_slice(&plain)?;
        let plan_digest = hash(&plain);
        plan.verify_parent(source.capsule())?;
        if source.capsule().histories().len() >= 16
            || secrets.generation_plan_digest() != Some(Sha256::digest(&plain).as_slice())
            || plan.target != target
            || plan.successor_profile != secrets.profile()
            || serde_json::to_vec(&plan)? != *plain
        {
            return Err(Error::Authentication);
        }
        let parent_key = unseal(
            &secrets,
            &[b"keys:".as_slice(), plan_digest.as_bytes()].concat(),
            &directory.read("generation.keys", MAX_DOCUMENT)?,
        )?;
        if parent_key_commitment(&parent_key)? != plan.parent_key_commitment {
            return Err(Error::Authentication);
        }
        let pending = Self {
            source,
            secrets,
            plan,
            plan_digest,
            parent_key,
            directory,
        };
        pending.check()?;
        Ok(pending)
    }
    pub(crate) fn generation_id(&self) -> &str {
        &self.plan.generation_id
    }
    pub(crate) fn inventory_digest(&self) -> &str {
        &self.plan.inventory_digest
    }
    pub(crate) fn binding(&self) -> Result<GenerationBinding> {
        Ok(GenerationBinding::new(
            self.generation_id(),
            self.inventory_digest(),
        )?)
    }
    pub(super) fn parent_key(&self) -> Result<DatabaseKey> {
        if parent_key_commitment(&self.parent_key)? != self.plan.parent_key_commitment {
            return Err(Error::Authentication);
        }
        Ok(DatabaseKey::from_bytes(
            self.parent_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid)?,
        ))
    }
    pub(super) fn check_inventory(&self) -> Result<()> {
        check_inventory(&self.directory)
    }
    pub(super) fn check(&self) -> Result<()> {
        self.source.check()?;
        self.directory.check()?;
        self.check_inventory()?;
        self.plan.verify_parent(self.source.capsule())?;
        if self.secrets.profile() != self.plan.successor_profile
            || self.secrets.generation_plan_digest()
                != Some(Sha256::digest(encode(&self.plan)?).as_slice())
            || hash(&encode(&self.plan)?) != self.plan_digest
        {
            return Err(Error::Authentication);
        }
        self.parent_key()?;
        Ok(())
    }
    /// Reauthenticate the complete exact copied graph. The returned capability
    /// is immutable history only and cannot be used as a current journal.
    pub(super) fn verify_parent_copy(&self) -> Result<VerifiedGenerationCapsule> {
        self.check()?;
        let copied = VerifiedGenerationCapsule::open(archive::inspect(
            &self.directory.path(PARENT_CAPSULE)?,
            &self.parent_key()?,
        )?)?;
        self.plan.verify_parent(&copied)?;
        if copied.archive().report() != self.source.capsule().archive().report() {
            return Err(Error::Authentication);
        }
        self.source.check()?;
        self.directory.check()?;
        Ok(copied)
    }
    /// The terminal's one-use effect fence encloses every construction write.
    /// CopyAuthority additionally binds exact source instance, key and target.
    pub(crate) fn construct(
        self,
        approval: &HistoricalApproval,
    ) -> Result<ConstructedLayeredGeneration> {
        let scope = CopyScope::for_copy(
            self.source.capsule().archive(),
            &self.directory.path(PARENT_CAPSULE)?,
            &self.parent_key()?,
        )?;
        let authority = ConstructionAuthority {
            scope,
            pending: &self,
            approval,
        };
        approval.effect(&mut || self.construct_inner(&authority, &|| approval.check()))?;
        Ok(ConstructedLayeredGeneration { pending: self })
    }
    fn construct_inner(
        &self,
        authority: &dyn CopyAuthority,
        check_live: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        check_live()?;
        self.check()?;
        if self.directory.path(COMMIT)?.try_exists()? {
            return Err(Error::Authentication);
        }
        let parent_path = self.directory.path(PARENT_CAPSULE)?;
        let key = self.parent_key()?;
        if !parent_path.try_exists()? {
            let report = archive::copy(CopyRequest {
                source: self.source.capsule().archive(),
                destination: &parent_path,
                key: &key,
                authority,
            })?;
            if report.manifest_digest != self.plan.parent_manifest_digest {
                return Err(Error::Authentication);
            }
        }
        // An incomplete/corrupt copy is never deleted, adopted or overwritten.
        self.verify_parent_copy()?;
        check_live()?;
        let binding = self.binding()?;
        wholepact_store::recovery::stage_layered_coordination_successor(
            self.source.capsule().root().current_coordination(),
            &binding,
            &self.directory.path(crate::vault::JOURNALS[0])?,
            &self.secrets.key(0)?,
        )?;
        for index in 1..4 {
            check_live()?;
            self.check()?;
            let path = self.directory.path(crate::vault::JOURNALS[index])?;
            let key = self.secrets.key(index)?;
            let connection = if path.try_exists()? {
                match wholepact_storage_security::open_encrypted_quiescent(&path, &key) {
                    Ok(connection) => connection,
                    Err(
                        wholepact_storage_security::StorageSecurityError::UninitializedDatabase,
                    ) => PlannedEmptyInitialization::new(&binding, &path, &key)?
                        .resume(&path, &key, &binding)?,
                    Err(error) => return Err(error.into()),
                }
            } else {
                wholepact_storage_security::create_encrypted(&path, &key)?
            };
            match index {
                1 => drop(
                    wholepact_transport::SqliteReplayLedger::from_encrypted_connection(connection)?,
                ),
                2 => {
                    drop(wholepact_transport::SqliteOutbox::from_encrypted_connection(connection)?)
                }
                3 => drop(
                    wholepact_chain::EncryptedSubmissionJournal::from_encrypted_connection(
                        connection,
                    )?,
                ),
                _ => return Err(Error::Invalid),
            }
        }
        verify_auxiliaries(&self.directory, &self.secrets, true)?;
        self.verify_parent_copy()?;
        check_live()?;
        self.check()
    }
    #[cfg(test)]
    pub(crate) fn construct_synthetic_storage(self) -> Result<ConstructedLayeredGeneration> {
        // Only synthetic zero-account qualification may omit attended native UI.
        // This cannot publish and this authority does not exist in release code.
        if !self.plan.affected_accounts.is_empty() {
            return Err(Error::Permission);
        }
        let authority = SyntheticConstructionAuthority {
            scope: CopyScope::for_copy(
                self.source.capsule().archive(),
                &self.directory.path(PARENT_CAPSULE)?,
                &self.parent_key()?,
            )?,
            pending: &self,
        };
        self.construct_inner(&authority, &|| Ok(()))?;
        Ok(ConstructedLayeredGeneration { pending: self })
    }
    #[cfg(test)]
    pub(crate) fn construct_synthetic_construction_archive(
        self,
    ) -> Result<ConstructedLayeredGeneration> {
        let evidence = super::construction_capsule_fixtures::evidence();
        if self.plan.affected_accounts
            != std::collections::BTreeSet::from([evidence.request.account_id])
        {
            return Err(Error::Permission);
        }
        // Only archive-copy authority is modeled. This does not mint native or
        // financial authority and is absent from production builds.
        let authority = SyntheticConstructionAuthority {
            scope: CopyScope::for_copy(
                self.source.capsule().archive(),
                &self.directory.path(PARENT_CAPSULE)?,
                &self.parent_key()?,
            )?,
            pending: &self,
        };
        self.construct_inner(&authority, &|| Ok(()))?;
        Ok(ConstructedLayeredGeneration { pending: self })
    }
    #[cfg(all(test, feature = "manual-admission"))]
    pub(crate) fn construct_synthetic_common_context_archive(
        self,
    ) -> Result<ConstructedLayeredGeneration> {
        let evidence = super::common_context_capsule_fixtures::evidence();
        if self.plan.affected_accounts
            != std::collections::BTreeSet::from([evidence.request.account_id])
        {
            return Err(Error::Permission);
        }
        // Only archive-copy authority is modeled. This does not mint native or
        // financial authority and is absent from production builds.
        let authority = SyntheticConstructionAuthority {
            scope: CopyScope::for_copy(
                self.source.capsule().archive(),
                &self.directory.path(PARENT_CAPSULE)?,
                &self.parent_key()?,
            )?,
            pending: &self,
        };
        self.construct_inner(&authority, &|| Ok(()))?;
        Ok(ConstructedLayeredGeneration { pending: self })
    }
    #[cfg(all(test, feature = "manual-admission", target_os = "linux"))]
    pub(crate) fn construct_synthetic_transport_archive(
        self,
    ) -> Result<ConstructedLayeredGeneration> {
        let evidence = super::transport_capsule_fixtures::evidence();
        if self.plan.affected_accounts
            != std::collections::BTreeSet::from([evidence.request.account_id])
        {
            return Err(Error::Permission);
        }
        // Only archive-copy authority is modeled. This does not mint native or
        // financial authority and is absent from production builds.
        let authority = SyntheticConstructionAuthority {
            scope: CopyScope::for_copy(
                self.source.capsule().archive(),
                &self.directory.path(PARENT_CAPSULE)?,
                &self.parent_key()?,
            )?,
            pending: &self,
        };
        self.construct_inner(&authority, &|| Ok(()))?;
        Ok(ConstructedLayeredGeneration { pending: self })
    }
}
fn check_inventory(directory: &Directory) -> Result<()> {
    directory.inventory_of(
        &[
            "coordination.sqlite",
            "inbox.sqlite",
            "outbox.sqlite",
            "submission.sqlite",
            PARENT_CAPSULE,
        ],
        &[
            "profile.lock",
            "profile.vault",
            PLAN,
            MANIFEST,
            "generation.keys",
        ],
    )
}
pub(crate) struct ConstructedLayeredGeneration {
    pub(super) pending: PendingLayeredGeneration,
}
struct ConstructionAuthority<'a> {
    scope: CopyScope,
    pending: &'a PendingLayeredGeneration,
    approval: &'a HistoricalApproval,
}
struct ConstructionLease<'a>(&'a ConstructionAuthority<'a>);
impl ArchiveLease for ConstructionLease<'_> {
    fn check_current(&self) -> std::result::Result<(), ArchiveError> {
        self.0
            .approval
            .check()
            .map_err(|_| ArchiveError::Permission)?;
        self.0.pending.check().map_err(|_| ArchiveError::Permission)
    }
}
impl CopyAuthority for ConstructionAuthority<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &CopyScope,
    ) -> std::result::Result<Box<dyn ArchiveLease + 'a>, ArchiveError> {
        if *scope != self.scope {
            return Err(ArchiveError::Permission);
        }
        let lease = ConstructionLease(self);
        lease.check_current()?;
        Ok(Box::new(lease))
    }
}
#[cfg(test)]
struct SyntheticConstructionAuthority<'a> {
    scope: CopyScope,
    pending: &'a PendingLayeredGeneration,
}
#[cfg(test)]
struct SyntheticConstructionLease<'a>(&'a PendingLayeredGeneration);
#[cfg(test)]
impl ArchiveLease for SyntheticConstructionLease<'_> {
    fn check_current(&self) -> std::result::Result<(), ArchiveError> {
        self.0.check().map_err(|_| ArchiveError::Permission)
    }
}
#[cfg(test)]
impl CopyAuthority for SyntheticConstructionAuthority<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &CopyScope,
    ) -> std::result::Result<Box<dyn ArchiveLease + 'a>, ArchiveError> {
        if *scope != self.scope {
            return Err(ArchiveError::Permission);
        }
        let lease = SyntheticConstructionLease(self.pending);
        lease.check_current()?;
        Ok(Box::new(lease))
    }
}

#[cfg(test)]
mod tests;
