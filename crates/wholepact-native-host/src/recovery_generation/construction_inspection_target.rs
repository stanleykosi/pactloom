//! Current committed-lineage identity for ORIGINAL metadata inspection only.
//! Unlike ManualCommittedTarget, this never opens ancestor financial journals
//! or interprets inherited accounts, retirement, private artifacts or eligibility.
use super::*;
use wholepact_storage_security::generation_archive::VerifiedArchive;

pub(crate) struct CurrentConstructionInspectionTargetV2<'directory> {
    directory: &'directory Directory,
    secrets: &'directory Secrets,
    generation_id: String,
    inventory_digest: String,
    plan_digest: String,
    profile_id: String,
    canonical_root: String,
    destination_identity_digest: String,
    coordination: RecoveryProvenance,
    checked_files: Vec<(&'static str, String)>,
    capsule: VerifiedArchive,
}
impl<'directory> CurrentConstructionInspectionTargetV2<'directory> {
    pub(crate) fn open(
        directory: &'directory Directory,
        secrets: &'directory Secrets,
    ) -> Result<Self> {
        check_directory(directory)?;
        if archive_history::source_plan_version(directory, secrets)? != 2 {
            return Err(Error::RecoveryFinancialUnsupported);
        }
        let vault = directory.path("profile.vault")?;
        let actual_root = vault.parent().ok_or(Error::Invalid)?;
        let profile_vault = directory.read("profile.vault", MAX_DOCUMENT)?;
        let plan = directory.read(PLAN, MAX_DOCUMENT)?;
        let manifest = directory.read(MANIFEST, MAX_DOCUMENT)?;
        let commit = directory.read(COMMIT, MAX_DOCUMENT)?;
        let keys = directory.read("generation.keys", MAX_DOCUMENT)?;
        // Existing strict reader authenticates vault plan anchor, native sealed
        // plan/manifest/commit equality and exact stored parent-key commitment.
        let metadata = layered_metadata::checked_layered_metadata_bytes(
            actual_root,
            secrets,
            &plan,
            &manifest,
            &commit,
            &keys,
        )?;
        let parent_key = wholepact_storage_security::DatabaseKey::from_bytes(
            metadata
                .parent_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Authentication)?,
        );
        // Structural encrypted archive integrity only. Never call journal(),
        // read_private_entry(), VerifiedGenerationCapsule::open or role/key
        // semantic recovery. Ancestor financial ciphertext is hashed, not opened.
        let capsule = wholepact_storage_security::generation_archive::inspect(
            &directory.path("history.capsule.sqlite")?,
            &parent_key,
        )
        .map_err(|_| Error::Authentication)?;
        let parent = capsule
            .node(capsule.manifest_digest())
            .map_err(|_| Error::Authentication)?;
        require_parent_identity(
            [
                &metadata.plan.parent_manifest_digest,
                &metadata.plan.parent_capsule_id,
                &metadata.plan.parent_node_generation,
                &metadata.plan.source_profile,
            ],
            [
                capsule.manifest_digest(),
                &capsule.manifest().capsule_id,
                &parent.generation_id,
                &parent.profile_id,
            ],
        )?;
        let coordination = metadata
            .plan
            .components
            .iter()
            .find(|component| component.component_id == "root-coordination")
            .filter(|component| {
                component.kind
                    == wholepact_storage_security::bundle::JournalKind::CoordinationAuthority
            })
            .ok_or(Error::Authentication)?
            .clone();
        let result = Self {
            directory,
            secrets,
            generation_id: metadata.plan.generation_id,
            inventory_digest: metadata.plan.inventory_digest,
            plan_digest: hex::encode(secrets.generation_plan_digest().ok_or(Error::Quarantined)?),
            profile_id: secrets.profile(),
            canonical_root: actual_root.to_str().ok_or(Error::Invalid)?.into(),
            destination_identity_digest: directory.manual_target_identity_digest()?,
            coordination,
            checked_files: vec![
                ("profile.vault", hash(&profile_vault)),
                (PLAN, hash(&plan)),
                (MANIFEST, hash(&manifest)),
                (COMMIT, hash(&commit)),
                ("generation.keys", hash(&keys)),
            ],
            capsule,
        };
        result.check_current()?;
        Ok(result)
    }
    /// Current coordination integrity only, from a source-preserving encrypted
    /// copy. The original Directory lock remains owned throughout inspection.
    pub(crate) fn coordination_snapshot(
        &self,
    ) -> Result<wholepact_store::recovery::RecoveredStoreSnapshot> {
        self.check_current()?;
        let binding =
            wholepact_storage_security::bundle::recovery::generation::GenerationBinding::new(
                &self.generation_id,
                &self.inventory_digest,
            )?;
        let snapshot = wholepact_store::recovery::RecoveredStoreSnapshot::open(
            &self.directory.path("coordination.sqlite")?,
            &self.secrets.key(0)?,
            &binding,
            &self.coordination,
        )?;
        self.check_current()?;
        snapshot.check_source_unchanged()?;
        Ok(snapshot)
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
    pub(crate) fn check_current(&self) -> Result<()> {
        check_directory(self.directory)?;
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
        self.capsule
            .check_source_unchanged(&self.directory.path("history.capsule.sqlite")?)
            .map_err(|_| Error::Authentication)
    }
}
fn check_directory(directory: &Directory) -> Result<()> {
    directory.check()?;
    directory.inventory_of(
        &[
            "coordination.sqlite",
            "inbox.sqlite",
            "outbox.sqlite",
            "submission.sqlite",
            "history.capsule.sqlite",
        ],
        &[
            "profile.lock",
            "profile.vault",
            PLAN,
            MANIFEST,
            COMMIT,
            "generation.keys",
            "financial.attached",
            "financial.inventory",
        ],
    )
}
fn require_parent_identity(expected: [&str; 4], actual: [&str; 4]) -> Result<()> {
    if expected != actual {
        return Err(Error::Authentication);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspection_lineage_never_accepts_changed_parent_identity() {
        let expected = ["manifest", "capsule", "generation", "profile"];
        assert!(require_parent_identity(expected, expected).is_ok());
        for field in 0..4 {
            let mut actual = expected;
            actual[field] = "different";
            assert!(require_parent_identity(expected, actual).is_err());
        }
    }
}

#[cfg(test)]
mod encrypted_lineage_tests {
    use super::*;
    use std::{fs, io::Write, os::unix::fs::PermissionsExt};
    use wholepact_storage_security::generation_archive::{
        self as archive, ArchiveAuthority, ArchiveLease, ArchiveScope, NodeSpec, RegisteredSource,
        SnapshotRequest, Source,
    };
    struct FixtureAuthority(ArchiveScope);
    struct FixtureLease;
    impl ArchiveLease for FixtureLease {
        fn check_current(&self) -> archive::Result<()> {
            Ok(())
        }
    }
    impl ArchiveAuthority for FixtureAuthority {
        fn acquire<'a>(
            &'a self,
            scope: &ArchiveScope,
        ) -> archive::Result<Box<dyn ArchiveLease + 'a>> {
            if scope != &self.0 {
                return Err(archive::ArchiveError::Permission);
            }
            Ok(Box::new(FixtureLease))
        }
    }
    fn tree(path: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                assert!(entry.file_type().unwrap().is_file());
                (
                    entry.file_name().into_string().unwrap(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }
    #[test]
    fn current_metadata_lineage_does_not_open_ancestor_artifacts_and_detects_tampering() {
        // Storage-only synthetic fixture. No native user approval, financial
        // owner, current Engine target, signer, wallet, witness or key use exists.
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = temp.path().join("current");
        let directory = Directory::create(&root).unwrap();
        // The protected source root and archive output are independent siblings.
        // Archive capture correctly rejects writing beneath any source root.
        let ancestor = temp.path().join("ancestor");
        fs::create_dir(&ancestor).unwrap();
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
        let source = ancestor.join("inert-ancestor-ciphertext");
        crate::files::write_new(
            &source,
            b"UNINTERPRETED SYNTHETIC BYTES, NOT A VALID FINANCIAL JOURNAL",
        )
        .unwrap();
        let key = wholepact_storage_security::DatabaseKey::from_bytes([29; 32]);
        let capsule_id = "a".repeat(64);
        let source_generation = "b".repeat(64);
        let node = NodeSpec {
            generation_id: source_generation.clone(),
            profile_id: "synthetic-ancestor".into(),
            original_root: ancestor,
        };
        let sources = [RegisteredSource::new(
            "inert-private-journal",
            "uninterpreted-ciphertext",
            Source::File(&source),
        )
        .unwrap()];
        let destination = directory.path("history.capsule.sqlite").unwrap();
        let authority = FixtureAuthority(
            ArchiveScope::for_snapshot(&destination, &key, &capsule_id, &node, &sources, &[])
                .unwrap(),
        );
        let report = archive::snapshot(SnapshotRequest {
            destination: &destination,
            key: &key,
            capsule_id: &capsule_id,
            node: &node,
            sources: &sources,
            parents: &[],
            authority: &authority,
        })
        .unwrap();
        let fresh = Secrets::fresh().unwrap();
        let components = [
            (
                "root-coordination",
                wholepact_storage_security::bundle::JournalKind::CoordinationAuthority,
            ),
            (
                "root-inbox",
                wholepact_storage_security::bundle::JournalKind::TransportInbox,
            ),
            (
                "root-outbox",
                wholepact_storage_security::bundle::JournalKind::TransportOutbox,
            ),
            (
                "root-submission",
                wholepact_storage_security::bundle::JournalKind::Submission,
            ),
        ]
        .into_iter()
        .map(|(id, kind)| {
            use wholepact_storage_security::bundle::JournalKind;
            let template = match kind {
                JournalKind::CoordinationAuthority => {
                    wholepact_store::recovery::coordination_successor_template()
                }
                JournalKind::TransportInbox => &wholepact_transport::bundle::INBOX_BACKUP_TEMPLATE,
                JournalKind::TransportOutbox => {
                    &wholepact_transport::bundle::OUTBOX_BACKUP_TEMPLATE
                }
                JournalKind::Submission => &wholepact_chain::backup::TEMPLATE,
                _ => unreachable!("only the four explicit synthetic component kinds above"),
            };
            RecoveryProvenance {
                profile_id: node.profile_id.clone(),
                checkpoint_id: capsule_id.clone(),
                bundle_digest: report.manifest_digest.clone(),
                component_id: id.into(),
                kind,
                component_digest: "c".repeat(64),
                application_id: template.application_id,
                schema_version: template.schema_version,
                rows: 0,
            }
        })
        .collect();
        let plan = layered_metadata::LayeredPlan {
            version: 2,
            generation_id: "d".repeat(64),
            inventory_digest: report.manifest_digest.clone(),
            target: root.clone(),
            source_profile: node.profile_id.clone(),
            successor_profile: fresh.profile(),
            parent_manifest_digest: report.manifest_digest,
            parent_capsule_id: capsule_id,
            parent_node_generation: source_generation,
            parent_key_commitment: layered_metadata::parent_key_commitment(&[29; 32]).unwrap(),
            components,
            affected_accounts: BTreeSet::new(),
            semantic_inventory_digest: "e".repeat(64),
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
        };
        let encoded = encode(&plan).unwrap();
        let digest = hash(&encoded);
        let secrets = fresh
            .bind_successor_plan(Sha256::digest(&encoded).into())
            .unwrap();
        let sealed_plan = seal(&secrets, b"plan", &encoded).unwrap();
        let manifest = serde_json::json!({"version":1,"plan_digest":digest,"continuity":[],"unmatched_host_authorizations":[],"unknown_external_signatures":true,"recovered_obligations_fenced":true,"financial_freshness_established":false});
        let sealed_manifest = seal(&secrets, b"manifest", &encode(&manifest).unwrap()).unwrap();
        let commit = serde_json::json!({"version":1,"plan_digest":digest,"manifest_digest":hash(&sealed_manifest),"admissions":[]});
        let sealed_commit = seal(&secrets, b"commit", &encode(&commit).unwrap()).unwrap();
        let sealed_keys = seal(
            &secrets,
            &[b"keys:".as_slice(), digest.as_bytes()].concat(),
            &[29; 32],
        )
        .unwrap();
        for (name, bytes) in [
            (PLAN, sealed_plan),
            (MANIFEST, sealed_manifest),
            (COMMIT, sealed_commit),
            ("generation.keys", sealed_keys),
        ] {
            crate::files::write_new(&directory.path(name).unwrap(), &bytes).unwrap();
        }
        crate::files::write_new(
            &directory.path("profile.vault").unwrap(),
            b"SYNTHETIC ALREADY-OPEN VAULT INSTANCE",
        )
        .unwrap();
        let before = tree(&root);
        let owner = CurrentConstructionInspectionTargetV2::open(&directory, &secrets).unwrap();
        owner.check_current().unwrap();
        assert_eq!(before, tree(&root));
        // The intentionally invalid ancestor journal was never semantically
        // opened. The owner authenticates only the sealed structural lineage.
        for name in ["profile.vault", PLAN, MANIFEST, COMMIT, "generation.keys"] {
            let path = directory.path(name).unwrap();
            let original = fs::read(&path).unwrap();
            fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"altered")
                .unwrap();
            let changed = tree(&root);
            assert!(owner.check_current().is_err());
            assert_eq!(changed, tree(&root));
            fs::write(&path, original).unwrap();
            owner.check_current().unwrap();
        }
        fs::OpenOptions::new()
            .append(true)
            .open(&destination)
            .unwrap()
            .write_all(b"changed-capsule")
            .unwrap();
        let changed = tree(&root);
        assert!(owner.check_current().is_err());
        assert_eq!(changed, tree(&root));
    }
}
