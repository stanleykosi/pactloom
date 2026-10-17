//! Strict version-2 native publication metadata. This never upgrades an audit
//! record into current signer permission or opens a live generation.
use super::*;
use wholepact_storage_security::bundle::{JournalKind, recovery::generation::GenerationBinding};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayeredPlan {
    pub(crate) version: u16,
    pub(crate) generation_id: String,
    pub(crate) inventory_digest: String,
    pub(crate) target: PathBuf,
    pub(crate) source_profile: String,
    pub(crate) successor_profile: String,
    pub(crate) parent_manifest_digest: String,
    pub(crate) parent_capsule_id: String,
    pub(crate) parent_node_generation: String,
    pub(crate) parent_key_commitment: String,
    pub(crate) components: Vec<RecoveryProvenance>,
    pub(crate) affected_accounts: BTreeSet<String>,
    pub(crate) semantic_inventory_digest: String,
    pub(crate) unknown_external_signatures: bool,
    pub(crate) recovered_obligations_fenced: bool,
}
impl LayeredPlan {
    /// Bind a publication or source-directory plan to the complete, separately
    /// authenticated parent capsule. The capability conveys integrity only.
    pub(crate) fn verify_parent(
        &self,
        parent: &super::archive_history::VerifiedGenerationCapsule,
    ) -> Result<()> {
        self.validate()?;
        if parent.manifest_digest() != self.parent_manifest_digest {
            return Err(Error::Authentication);
        }
        self.verify_parent_history(parent.archive().manifest(), parent.root())
    }

    pub(super) fn verify_parent_history(
        &self,
        parent_manifest: &wholepact_storage_security::generation_archive::SnapshotManifest,
        parent: &super::archive_history::ArchivedCommittedHistory,
    ) -> Result<()> {
        if parent_manifest.capsule_id != self.parent_capsule_id
            || parent.generation_id() != self.parent_node_generation
            || parent.profile_id() != self.source_profile
            || parent.current_provenance() != self.components
            || parent.current_semantics().digest() != self.semantic_inventory_digest
            || parent.current_semantics().accounts() != &self.affected_accounts
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.generation_id,
            &self.inventory_digest,
            &self.parent_manifest_digest,
            &self.parent_capsule_id,
            &self.parent_node_generation,
            &self.parent_key_commitment,
            &self.semantic_inventory_digest,
        ] {
            canonical_hash(digest)?;
        }
        crate::files::validate_absolute(&self.target)?;
        crate::id(&self.source_profile)?;
        crate::id(&self.successor_profile)?;
        for account in &self.affected_accounts {
            crate::id(account)?;
        }
        if self.version != 2
            || !self.unknown_external_signatures
            || !self.recovered_obligations_fenced
            || self.inventory_digest != self.parent_manifest_digest
            || self.generation_id == self.parent_node_generation
            || self.source_profile == self.successor_profile
            || self.components.len() > 52
        {
            return Err(Error::Authentication);
        }
        let count = self
            .components
            .iter()
            .filter(|component| component.kind == JournalKind::WalletScan)
            .count();
        if count > 12 || self.components.len() != 4 + count * 4 {
            return Err(Error::Authentication);
        }
        let mut expected = BTreeMap::from([
            (
                "root-coordination".to_owned(),
                JournalKind::CoordinationAuthority,
            ),
            ("root-inbox".to_owned(), JournalKind::TransportInbox),
            ("root-outbox".to_owned(), JournalKind::TransportOutbox),
            ("root-submission".to_owned(), JournalKind::Submission),
        ]);
        for index in 0..count {
            for (suffix, kind) in [
                ("wallet", JournalKind::WalletScan),
                ("proof", JournalKind::ProofWitness),
                ("signed", JournalKind::SignedResults),
                ("transactions", JournalKind::ExactTransactions),
            ] {
                expected.insert(format!("financial-{index}-{suffix}"), kind);
            }
        }
        let mut previous: Option<&str> = None;
        for component in &self.components {
            if previous.is_some_and(|id| id >= component.component_id.as_str())
                || expected.remove(&component.component_id) != Some(component.kind)
                || component.profile_id != self.source_profile
                || component.bundle_digest != self.parent_manifest_digest
                || component.checkpoint_id != self.parent_capsule_id
            {
                return Err(Error::Authentication);
            }
            canonical_hash(&component.component_digest)?;
            previous = Some(&component.component_id);
            if component.kind == JournalKind::CoordinationAuthority {
                // Exact immutable recovered families only. Versions8/9 carry
                // historical claim5 provenance; this metadata check grants no
                // authority. The sealed parent reader authenticates full schema
                // and verify_parent_history still requires exact provenance.
                if component.application_id != wholepact_storage_security::bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID
                    || ![2, 3, 4, 5, 6, 7, 8, 9].contains(&component.schema_version) { return Err(Error::Authentication); }
            } else {
                // Metadata-label compatibility only. Both wallet layouts share
                // these labels; the sealed parent reader authenticates full schema.
                let template = if component.kind == JournalKind::WalletScan {
                    wholepact_wallet::bundle::trusted_template()?
                } else {
                    super::archive_history::template(component.kind)?
                };
                if component.application_id != template.application_id
                    || component.schema_version != template.schema_version
                {
                    return Err(Error::Authentication);
                }
            }
        }
        if !expected.is_empty() {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
use std::collections::BTreeMap;

pub(crate) struct CheckedLayeredMetadata {
    pub(crate) plan: LayeredPlan,
    pub(crate) binding: GenerationBinding,
    pub(crate) manifest_digest: String,
    pub(crate) restrictions: BTreeSet<String>,
    pub(crate) parent_key: Zeroizing<Vec<u8>>,
}

pub(crate) fn parent_key_commitment(bytes: &[u8]) -> Result<String> {
    if bytes.len() != 32 {
        return Err(Error::Invalid);
    }
    let mut digest = Sha256::new();
    digest.update(b"wholepact:generation-capsule-random-key-intent:v1\0");
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

pub(crate) fn checked_layered_metadata_bytes(
    original_target: &std::path::Path,
    secrets: &Secrets,
    sealed_plan: &[u8],
    manifest_bytes: &[u8],
    commit_bytes: &[u8],
    sealed_keys: &[u8],
) -> Result<CheckedLayeredMetadata> {
    let plain = unseal(secrets, b"commit", commit_bytes)?;
    match complete_origins::metadata_version(&plain)? {
        1 => checked_layered_metadata_bytes_v1(
            original_target,
            secrets,
            sealed_plan,
            manifest_bytes,
            commit_bytes,
            sealed_keys,
        ),
        2 => checked_layered_metadata_bytes_v2(
            original_target,
            secrets,
            sealed_plan,
            manifest_bytes,
            commit_bytes,
            sealed_keys,
        ),
        3 => checked_layered_metadata_bytes_v3(
            original_target,
            secrets,
            sealed_plan,
            manifest_bytes,
            commit_bytes,
            sealed_keys,
        ),
        4 => checked_layered_metadata_bytes_v4(
            original_target,
            secrets,
            sealed_plan,
            manifest_bytes,
            commit_bytes,
            sealed_keys,
        ),
        5 => super::transport_origins::checked_layered_metadata_bytes_v5(
            original_target,
            secrets,
            sealed_plan,
            manifest_bytes,
            commit_bytes,
            sealed_keys,
        ),
        _ => Err(Error::Unsupported),
    }
}
pub(crate) fn checked_layered_metadata_bytes_v1(
    original_target: &std::path::Path,
    secrets: &Secrets,
    sealed_plan: &[u8],
    manifest_bytes: &[u8],
    commit_bytes: &[u8],
    sealed_keys: &[u8],
) -> Result<CheckedLayeredMetadata> {
    let plain = unseal(secrets, b"plan", sealed_plan)?;
    let plan: LayeredPlan = serde_json::from_slice(&plain)?;
    plan.validate()?;
    let plan_digest = hash(&plain);
    if secrets.generation_plan_digest() != Some(Sha256::digest(&plain).as_slice())
        || original_target != plan.target
        || secrets.profile() != plan.successor_profile
    {
        return Err(Error::Authentication);
    }
    let manifest: Manifest =
        serde_json::from_slice(&unseal(secrets, b"manifest", manifest_bytes)?)?;
    let commit: Commit = serde_json::from_slice(&unseal(secrets, b"commit", commit_bytes)?)?;
    if manifest.version != 1
        || manifest.plan_digest != plan_digest
        || !manifest.unknown_external_signatures
        || !manifest.recovered_obligations_fenced
        || manifest.financial_freshness_established
        || commit.version != 1
        || commit.plan_digest != plan_digest
        || commit.manifest_digest != hash(manifest_bytes)
        || commit.admissions.len() != manifest.continuity.len()
    {
        return Err(Error::Authentication);
    }
    let mut accounts = BTreeSet::new();
    for evidence in &manifest.continuity {
        evidence.digest().map_err(|_| Error::Authentication)?;
        if evidence.request.generation_id != plan.generation_id
            || evidence.request.inventory_digest != plan.inventory_digest
            || !accounts.insert(evidence.request.account_id.clone())
        {
            return Err(Error::Authentication);
        }
    }
    if accounts != plan.affected_accounts {
        return Err(Error::Authentication);
    }
    let mut admitted = BTreeSet::new();
    for record in &commit.admissions {
        record.validate().map_err(|_| Error::Authentication)?;
        let request = &record.request;
        let evidence = manifest
            .continuity
            .iter()
            .find(|evidence| evidence.request == request.continuity)
            .ok_or(Error::Authentication)?;
        if !admitted.insert(request.continuity.account_id.clone())
            || request.target_profile != plan.target
            || request.generation_manifest_digest != commit.manifest_digest
            || request.continuity_evidence_digest
                != evidence.digest().map_err(|_| Error::Authentication)?
        {
            return Err(Error::Authentication);
        }
    }
    if admitted != accounts {
        return Err(Error::Authentication);
    }
    let parent_key = unseal(
        secrets,
        &[b"keys:".as_slice(), plan_digest.as_bytes()].concat(),
        sealed_keys,
    )?;
    if parent_key_commitment(&parent_key)? != plan.parent_key_commitment {
        return Err(Error::Authentication);
    }
    let binding = GenerationBinding::new(&plan.generation_id, &plan.inventory_digest)?;
    let restrictions = manifest
        .continuity
        .iter()
        .flat_map(|evidence| {
            evidence
                .conservative_permits
                .iter()
                .map(|permit| permit.request.obligation_id.clone())
        })
        .collect();
    Ok(CheckedLayeredMetadata {
        plan,
        binding,
        manifest_digest: commit.manifest_digest,
        restrictions,
        parent_key,
    })
}
pub(crate) fn checked_layered_metadata_bytes_v2(
    original_target: &std::path::Path,
    secrets: &Secrets,
    sealed_plan: &[u8],
    manifest_bytes: &[u8],
    commit_bytes: &[u8],
    sealed_keys: &[u8],
) -> Result<CheckedLayeredMetadata> {
    let plain = unseal(secrets, b"plan", sealed_plan)?;
    let plan: LayeredPlan = serde_json::from_slice(&plain)?;
    plan.validate()?;
    let plan_digest = hash(&plain);
    if secrets.generation_plan_digest() != Some(Sha256::digest(&plain).as_slice())
        || original_target != plan.target
        || secrets.profile() != plan.successor_profile
    {
        return Err(Error::Authentication);
    }
    let manifest_plain = unseal(secrets, b"manifest", manifest_bytes)?;
    let commit_plain = unseal(secrets, b"commit", commit_bytes)?;
    let restrictions = complete_origins::validate_metadata_v2(
        &manifest_plain,
        &commit_plain,
        &hash(manifest_bytes),
        &plan_digest,
        &plan.generation_id,
        &plan.inventory_digest,
        &plan.target,
        &plan.affected_accounts,
    )?;
    let parent_key = unseal(
        secrets,
        &[b"keys:".as_slice(), plan_digest.as_bytes()].concat(),
        sealed_keys,
    )?;
    if parent_key_commitment(&parent_key)? != plan.parent_key_commitment {
        return Err(Error::Authentication);
    }
    let binding = GenerationBinding::new(&plan.generation_id, &plan.inventory_digest)?;
    Ok(CheckedLayeredMetadata {
        plan,
        binding,
        manifest_digest: hash(manifest_bytes),
        restrictions,
        parent_key,
    })
}
pub(crate) fn checked_layered_metadata_bytes_v3(
    original_target: &std::path::Path,
    secrets: &Secrets,
    sealed_plan: &[u8],
    manifest_bytes: &[u8],
    commit_bytes: &[u8],
    sealed_keys: &[u8],
) -> Result<CheckedLayeredMetadata> {
    let plain = unseal(secrets, b"plan", sealed_plan)?;
    let plan: LayeredPlan = serde_json::from_slice(&plain)?;
    plan.validate()?;
    let plan_digest = hash(&plain);
    if secrets.generation_plan_digest() != Some(Sha256::digest(&plain).as_slice())
        || original_target != plan.target
        || secrets.profile() != plan.successor_profile
    {
        return Err(Error::Authentication);
    }
    let manifest_plain = unseal(secrets, b"manifest", manifest_bytes)?;
    let commit_plain = unseal(secrets, b"commit", commit_bytes)?;
    let restrictions = super::construction_origins::validate_metadata_v3(
        &manifest_plain,
        &commit_plain,
        &hash(manifest_bytes),
        &plan_digest,
        &plan.generation_id,
        &plan.inventory_digest,
        &plan.target,
        &plan.affected_accounts,
    )?;
    let parent_key = unseal(
        secrets,
        &[b"keys:".as_slice(), plan_digest.as_bytes()].concat(),
        sealed_keys,
    )?;
    if parent_key_commitment(&parent_key)? != plan.parent_key_commitment {
        return Err(Error::Authentication);
    }
    let binding = GenerationBinding::new(&plan.generation_id, &plan.inventory_digest)?;
    Ok(CheckedLayeredMetadata {
        plan,
        binding,
        manifest_digest: hash(manifest_bytes),
        restrictions,
        parent_key,
    })
}
pub(crate) fn checked_layered_metadata_bytes_v4(
    original_target: &std::path::Path,
    secrets: &Secrets,
    sealed_plan: &[u8],
    manifest_bytes: &[u8],
    commit_bytes: &[u8],
    sealed_keys: &[u8],
) -> Result<CheckedLayeredMetadata> {
    let plain = unseal(secrets, b"plan", sealed_plan)?;
    let plan: LayeredPlan = serde_json::from_slice(&plain)?;
    plan.validate()?;
    let plan_digest = hash(&plain);
    if secrets.generation_plan_digest() != Some(Sha256::digest(&plain).as_slice())
        || original_target != plan.target
        || secrets.profile() != plan.successor_profile
    {
        return Err(Error::Authentication);
    }
    let manifest_plain = unseal(secrets, b"manifest", manifest_bytes)?;
    let commit_plain = unseal(secrets, b"commit", commit_bytes)?;
    let restrictions = super::common_context_origins::validate_metadata_v4(
        &manifest_plain,
        &commit_plain,
        &hash(manifest_bytes),
        &plan_digest,
        &plan.generation_id,
        &plan.inventory_digest,
        &plan.target,
        &plan.affected_accounts,
    )?;
    let parent_key = unseal(
        secrets,
        &[b"keys:".as_slice(), plan_digest.as_bytes()].concat(),
        sealed_keys,
    )?;
    if parent_key_commitment(&parent_key)? != plan.parent_key_commitment {
        return Err(Error::Authentication);
    }
    let binding = GenerationBinding::new(&plan.generation_id, &plan.inventory_digest)?;
    Ok(CheckedLayeredMetadata {
        plan,
        binding,
        manifest_digest: hash(manifest_bytes),
        restrictions,
        parent_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan(successor: &str) -> LayeredPlan {
        let mut components = Vec::new();
        for (id, kind) in [
            ("root-coordination", JournalKind::CoordinationAuthority),
            ("root-inbox", JournalKind::TransportInbox),
            ("root-outbox", JournalKind::TransportOutbox),
            ("root-submission", JournalKind::Submission),
        ] {
            let template = if kind == JournalKind::CoordinationAuthority {
                wholepact_store::recovery::coordination_successor_template()
            } else if kind == JournalKind::WalletScan {
                wholepact_wallet::bundle::trusted_template().unwrap()
            } else {
                super::super::archive_history::template(kind).unwrap()
            };
            components.push(RecoveryProvenance {
                profile_id: "synthetic-source".into(),
                checkpoint_id: "3".repeat(64),
                bundle_digest: "2".repeat(64),
                component_id: id.into(),
                kind,
                component_digest: "7".repeat(64),
                application_id: template.application_id,
                schema_version: template.schema_version,
                rows: 0,
            });
        }
        LayeredPlan {
            version: 2,
            generation_id: "1".repeat(64),
            inventory_digest: "2".repeat(64),
            target: "/synthetic-absent-successor/profile".into(),
            source_profile: "synthetic-source".into(),
            successor_profile: successor.into(),
            parent_manifest_digest: "2".repeat(64),
            parent_capsule_id: "3".repeat(64),
            parent_node_generation: "4".repeat(64),
            parent_key_commitment: parent_key_commitment(&[23; 32]).unwrap(),
            components,
            affected_accounts: BTreeSet::new(),
            semantic_inventory_digest: "6".repeat(64),
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
        }
    }

    #[test]
    fn layered_plan_rejects_omission_aliases_cross_capsule_components_and_unknown_fields() {
        let original = plan("synthetic-successor");
        original.validate().unwrap();
        let mut changed = plan("synthetic-successor");
        changed.components.pop();
        assert!(changed.validate().is_err());
        let mut changed = plan("synthetic-successor");
        changed.components[0].component_id = "coordination".into();
        assert!(changed.validate().is_err());
        let mut changed = plan("synthetic-successor");
        changed.components[0].bundle_digest = "9".repeat(64);
        assert!(changed.validate().is_err());
        let mut changed = plan("synthetic-successor");
        changed.parent_manifest_digest = "9".repeat(64);
        assert!(changed.validate().is_err());
        let mut changed = serde_json::to_value(&original).unwrap();
        changed["unexpected_permission"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<LayeredPlan>(changed).is_err());
        assert!(parent_key_commitment(&[23; 31]).is_err());
        assert_ne!(
            parent_key_commitment(&[23; 32]).unwrap(),
            parent_key_commitment(&[24; 32]).unwrap()
        );
    }

    #[test]
    fn layered_saved_audit_metadata_binds_original_target_anchor_and_parent_key_only() {
        // Synthetic empty-account storage metadata. No signer lease, admission
        // capability, native approval, source generation or runtime is created.
        let source = Secrets::fresh().unwrap();
        let plan = plan(&source.profile());
        let plain = encode(&plan).unwrap();
        let plan_digest = hash(&plain);
        let secrets = source
            .bind_successor_plan(Sha256::digest(&plain).into())
            .unwrap();
        let encrypted_plan = seal(&secrets, b"plan", &plain).unwrap();
        let manifest = Manifest {
            version: 1,
            plan_digest: plan_digest.clone(),
            continuity: vec![],
            unmatched_host_authorizations: BTreeSet::new(),
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        let encrypted_manifest = seal(&secrets, b"manifest", &encode(&manifest).unwrap()).unwrap();
        let commit = Commit {
            version: 1,
            plan_digest: plan_digest.clone(),
            manifest_digest: hash(&encrypted_manifest),
            admissions: vec![],
        };
        let encrypted_commit = seal(&secrets, b"commit", &encode(&commit).unwrap()).unwrap();
        let purpose = [b"keys:".as_slice(), plan_digest.as_bytes()].concat();
        let keys = seal(&secrets, &purpose, &[23; 32]).unwrap();
        let checked = checked_layered_metadata_bytes(
            &plan.target,
            &secrets,
            &encrypted_plan,
            &encrypted_manifest,
            &encrypted_commit,
            &keys,
        )
        .unwrap();
        assert!(checked.plan == plan);
        assert_eq!(checked.parent_key.as_slice(), &[23; 32]);
        assert!(
            checked_layered_metadata_bytes(
                std::path::Path::new("/changed/profile"),
                &secrets,
                &encrypted_plan,
                &encrypted_manifest,
                &encrypted_commit,
                &keys
            )
            .is_err()
        );
        let wrong_keys = seal(&secrets, &purpose, &[24; 32]).unwrap();
        assert!(
            checked_layered_metadata_bytes(
                &plan.target,
                &secrets,
                &encrypted_plan,
                &encrypted_manifest,
                &encrypted_commit,
                &wrong_keys
            )
            .is_err()
        );
    }
}
