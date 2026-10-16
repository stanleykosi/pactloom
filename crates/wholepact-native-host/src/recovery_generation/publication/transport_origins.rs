//! Explicit manifest-v5 consumers for complete origins. These are source-only
//! until the distinct native v5 endpoint and every archive reader are qualified.
//! The complete V5 envelope and WIP55 retained joins preserve original transport
//! grants, old-key fences, reentry lineage, charges and absent-native uncertainty.
//! Existing manifest-v1/commit-v1 encodings and digest domains are unchanged.
use super::*;
use wholepact_signer::authority_bridge::{
    host_publication_ipc::v5::{
        HostRecoveryPublicationAdmissionV5, HostRecoveryPublicationRecordV5,
        HostRecoveryPublicationRequestV5,
    },
    host_recovery_ipc::v5::HostRecoveryContinuityEvidenceV5,
};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestV5 {
    version: u16,
    plan_digest: String,
    continuity: Vec<HostRecoveryContinuityEvidenceV5>,
    unmatched_host_authorizations: BTreeSet<String>,
    unresolved_offline_authorizations: BTreeSet<String>,
    unknown_external_signatures: bool,
    recovered_obligations_fenced: bool,
    financial_freshness_established: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommitV5 {
    version: u16,
    plan_digest: String,
    manifest_digest: String,
    admissions: Vec<HostRecoveryPublicationRecordV5>,
}
use super::complete_origins::metadata_version;
fn validate_continuity(
    continuity: &[HostRecoveryContinuityEvidenceV5],
    generation: &str,
    inventory: &str,
    affected: &BTreeSet<String>,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    canonical_hash(generation)?;
    canonical_hash(inventory)?;
    if continuity.len() != affected.len() {
        return Err(Error::Authentication);
    }
    // Preserve the shared Host document ceiling across the full account set.
    // Individual complete-history envelopes cannot multiply that budget.
    let _bounded = encode(&continuity)?;
    let mut accounts = BTreeSet::new();
    let mut restrictions = BTreeSet::new();
    let mut unresolved = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for e in continuity {
        e.validate().map_err(|_| Error::Authentication)?;
        if e.request.generation_id != generation
            || e.request.inventory_digest != inventory
            || previous.is_some_and(|old| old >= e.request.account_id.as_str())
            || !accounts.insert(e.request.account_id.clone())
        {
            return Err(Error::Authentication);
        }
        previous = Some(&e.request.account_id);
        restrictions.extend(
            e.complete_history
                .conservative_obligations()
                .map_err(|_| Error::Authentication)?,
        );
        unresolved.extend(
            e.complete_history
                .unresolved_offline_authorizations()
                .map_err(|_| Error::Authentication)?,
        );
    }
    if &accounts != affected {
        return Err(Error::Authentication);
    }
    Ok((restrictions, unresolved))
}
/// Shared strict historical reader for both ordinary and layered generation
/// metadata. Saved admissions remain audit records and cannot enter publish().
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_metadata_v5(
    manifest_plain: &[u8],
    commit_plain: &[u8],
    manifest_digest: &str,
    plan_digest: &str,
    generation: &str,
    inventory: &str,
    target: &std::path::Path,
    affected: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    if manifest_plain.len() > MAX_DOCUMENT || commit_plain.len() > MAX_DOCUMENT {
        return Err(Error::Authentication);
    }
    for digest in [manifest_digest, plan_digest, generation, inventory] {
        canonical_hash(digest)?;
    }
    crate::files::validate_absolute(target)?;
    if metadata_version(manifest_plain)? != 5 || metadata_version(commit_plain)? != 5 {
        return Err(Error::Authentication);
    }
    let manifest: ManifestV5 = serde_json::from_slice(manifest_plain)?;
    let commit: CommitV5 = serde_json::from_slice(commit_plain)?;
    if manifest.version != 5
        || commit.version != 5
        || manifest.plan_digest != plan_digest
        || commit.plan_digest != plan_digest
        || commit.manifest_digest != manifest_digest
        || !manifest.unknown_external_signatures
        || !manifest.recovered_obligations_fenced
        || manifest.financial_freshness_established
        || commit.admissions.len() != manifest.continuity.len()
    {
        return Err(Error::Authentication);
    }
    let (restrictions, unresolved) =
        validate_continuity(&manifest.continuity, generation, inventory, affected)?;
    if unresolved != manifest.unresolved_offline_authorizations {
        return Err(Error::Authentication);
    }
    let mut admitted = BTreeSet::new();
    let mut previous: Option<&str> = None;
    let mut admission_ids = BTreeSet::new();
    for record in &commit.admissions {
        record.validate().map_err(|_| Error::Authentication)?;
        let r = &record.request;
        let e = manifest
            .continuity
            .iter()
            .find(|e| e.request == r.continuity)
            .ok_or(Error::Authentication)?;
        r.matches_evidence(e).map_err(|_| Error::Authentication)?;
        if r.target_profile != target
            || r.generation_manifest_digest != manifest_digest
            || previous.is_some_and(|old| old >= r.continuity.account_id.as_str())
            || !admitted.insert(r.continuity.account_id.clone())
            || !admission_ids.insert(&record.admission_id)
        {
            return Err(Error::Authentication);
        }
        previous = Some(&r.continuity.account_id);
    }
    if &admitted != affected {
        return Err(Error::Authentication);
    }
    for id in &manifest.unmatched_host_authorizations {
        crate::id(id)?;
    }
    Ok(restrictions)
}

pub(crate) struct PreparedPublicationV5 {
    generation: ConstructedGeneration,
    manifest: ManifestV5,
    manifest_digest: String,
}
impl ConstructedGeneration {
    pub(crate) fn prepare_publication_v5(
        self,
        mut continuity: Vec<HostRecoveryContinuityEvidenceV5>,
    ) -> Result<PreparedPublicationV5> {
        let p = &self.pending;
        p.source.check()?;
        continuity.sort_by(|a, b| a.request.account_id.cmp(&b.request.account_id));
        let (restrictions, unresolved) = validate_continuity(
            &continuity,
            &p.plan.generation_id,
            &p.plan.inventory_digest,
            &p.plan.affected_accounts,
        )?;
        let coordination = p
            .source
            .components()
            .iter()
            .find(|c| c.provenance().component_id == "coordination")
            .ok_or(Error::Invalid)?;
        let cross = crate::recovery_semantics::inspect(&p.source)?;
        if cross.digest() != p.plan.semantic_inventory_digest
            || cross.accounts() != &p.plan.affected_accounts
        {
            return Err(Error::Authentication);
        }
        let semantic = wholepact_engine::recovery::inspect_coordination_recovery(coordination)?;
        let inspected = inspect_continuity(
            &continuity,
            &p.plan.generation_id,
            &p.plan.inventory_digest,
            &p.plan.affected_accounts,
            semantic.store_inventory(),
        )?;
        let all_restrictions = inspected.obligation_fences;
        let unmatched = inspected.unmatched_host_authorizations;
        if unresolved != inspected.unresolved_offline_authorizations {
            return Err(Error::Authentication);
        }
        let binding = p.binding()?;
        let store = wholepact_store::Store::open_recovered_generation(
            &p.directory.path(crate::vault::JOURNALS[0])?,
            &p.secrets.key(0)?,
            &binding,
            coordination.provenance(),
        )?;
        // The sealed manifest's canonical continuity batch is the signer set.
        // Retain a separate monotone union batch for Store-only obligations;
        // never substitute that union for the exact batch readers authenticate.
        store.add_recovery_obligation_fences(&binding, &all_restrictions)?;
        if all_restrictions != restrictions {
            store.add_recovery_obligation_fences(&binding, &restrictions)?;
        }
        drop(store);
        let manifest = ManifestV5 {
            version: 5,
            plan_digest: p.plan_digest.clone(),
            continuity,
            unmatched_host_authorizations: unmatched,
            unresolved_offline_authorizations: unresolved,
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        let manifest_digest = persist_manifest(&p.directory, &p.secrets, &manifest)?;
        Ok(PreparedPublicationV5 {
            generation: self,
            manifest,
            manifest_digest,
        })
    }
}
fn persist_manifest(
    directory: &Directory,
    secrets: &Secrets,
    manifest: &ManifestV5,
) -> Result<String> {
    let plain = encode(manifest)?;
    let bytes = if directory.path(MANIFEST)?.try_exists()? {
        let bytes = directory.read(MANIFEST, MAX_DOCUMENT)?;
        if unseal(secrets, b"manifest", &bytes)?.as_slice() != plain.as_slice() {
            return Err(Error::RecoverySemantic("The complete transport-origin pending snapshot changed. Preserve this partial target and obtain fresh native reviews at a fresh target; no prior-format downgrade or saved-admission replay is permitted".into()));
        }
        bytes
    } else {
        let bytes = seal(secrets, b"manifest", &plain)?;
        directory.write_new(MANIFEST, &bytes)?;
        bytes
    };
    Ok(hash(&bytes))
}
fn requests(
    manifest: &ManifestV5,
    target: &std::path::Path,
    digest: &str,
) -> Result<Vec<HostRecoveryPublicationRequestV5>> {
    manifest
        .continuity
        .iter()
        .map(|e| {
            HostRecoveryPublicationRequestV5::new(e, target.into(), digest.into())
                .map_err(|_| Error::Authentication)
        })
        .collect()
}
/// Consumes only genuinely issued non-Clone, non-Deserialize live admissions.
fn consume_admissions(
    manifest: &ManifestV5,
    target: &std::path::Path,
    digest: &str,
    admissions: Vec<HostRecoveryPublicationAdmissionV5>,
) -> Result<CommitV5> {
    let requests = requests(manifest, target, digest)?;
    if admissions.len() != requests.len() {
        return Err(Error::Permission);
    }
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for admission in admissions {
        let r = admission.binding();
        if !seen.insert(r.continuity.account_id.clone()) || !requests.contains(r) {
            return Err(Error::Permission);
        }
        // Match against the immutable prepared manifest, not a caller-supplied
        // audit record or a reduced V4 view of the complete transport history.
        let evidence = manifest
            .continuity
            .iter()
            .find(|e| e.request == r.continuity)
            .ok_or(Error::Permission)?;
        records.push(
            admission
                .consume(evidence, target, digest)
                .map_err(|_| Error::Permission)?,
        );
    }
    records.sort_by(|a, b| {
        a.request
            .continuity
            .account_id
            .cmp(&b.request.continuity.account_id)
    });
    Ok(CommitV5 {
        version: 5,
        plan_digest: manifest.plan_digest.clone(),
        manifest_digest: digest.into(),
        admissions: records,
    })
}
impl PreparedPublicationV5 {
    /// Restriction-only retained source/target check during narrow endpoint
    /// reentry. It never creates or extends either terminal or signer authority.
    pub(crate) fn check_source(&self) -> Result<()> {
        let p = &self.generation.pending;
        p.source.check()?;
        p.directory.check()?;
        p.check_inventory()?;
        if hash(&p.directory.read(MANIFEST, MAX_DOCUMENT)?) != self.manifest_digest {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn requests(&self) -> Result<Vec<HostRecoveryPublicationRequestV5>> {
        requests(
            &self.manifest,
            &self.generation.pending.plan.target,
            &self.manifest_digest,
        )
    }
    pub(crate) fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    fn prepare_commit(
        &self,
        admissions: Vec<HostRecoveryPublicationAdmissionV5>,
    ) -> Result<Vec<u8>> {
        let p = &self.generation.pending;
        let commit = consume_admissions(
            &self.manifest,
            &p.plan.target,
            &self.manifest_digest,
            admissions,
        )?;
        p.source.check()?;
        p.directory.check()?;
        p.check_inventory()?;
        if hash(&p.directory.read(MANIFEST, MAX_DOCUMENT)?) != self.manifest_digest {
            return Err(Error::Authentication);
        }
        let bytes = seal(&p.secrets, b"commit", &encode(&commit)?)?;
        drop(open_checked_v5(&p.directory, &p.secrets, &commit, true)?);
        Ok(bytes)
    }
    pub(crate) fn publish(
        self,
        admissions: Vec<HostRecoveryPublicationAdmissionV5>,
        approval: crate::terminal::PublicationApproval,
    ) -> Result<()> {
        approval.commit(
            &self.manifest_digest,
            || self.prepare_commit(admissions),
            |bytes| self.generation.pending.directory.write_new(COMMIT, &bytes),
        )
    }
}

pub(super) fn checked_metadata_bytes_v5(
    original_target: &std::path::Path,
    secrets: &Secrets,
    commit: &CommitV5,
    sealed_plan: &[u8],
    manifest_bytes: &[u8],
    sealed_keys: &[u8],
) -> Result<CheckedMetadata> {
    let plan_bytes = unseal(secrets, b"plan", sealed_plan)?;
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    let plan_digest = hash(&plan_bytes);
    let anchored = secrets.generation_plan_digest().ok_or(Error::Quarantined)?;
    if anchored != Sha256::digest(&plan_bytes).as_slice()
        || plan.version != 1
        || !plan.unknown_external_signatures
        || !plan.recovered_obligations_fenced
        || plan.successor_profile != secrets.profile()
        || original_target != plan.target
        || plan.components.is_empty()
        || plan.components.len() > 52
    {
        return Err(Error::Authentication);
    }
    canonical_hash(&plan.generation_id)?;
    canonical_hash(&plan.inventory_digest)?;
    canonical_hash(&plan.semantic_inventory_digest)?;
    crate::files::validate_absolute(&plan.target)?;
    crate::id(&plan.source_profile)?;
    crate::id(&plan.successor_profile)?;
    if plan.source_profile == plan.successor_profile {
        return Err(Error::Authentication);
    }
    for account in &plan.affected_accounts {
        crate::id(account)?;
    }
    let manifest_plain = unseal(secrets, b"manifest", manifest_bytes)?;
    let restrictions = validate_metadata_v5(
        &manifest_plain,
        &encode(commit)?,
        &hash(manifest_bytes),
        &plan_digest,
        &plan.generation_id,
        &plan.inventory_digest,
        &plan.target,
        &plan.affected_accounts,
    )?;
    check_component_inventory(&plan)?;
    let keys = unseal(
        secrets,
        &[b"keys:".as_slice(), plan_digest.as_bytes()].concat(),
        sealed_keys,
    )?;
    if keys.len() != plan.components.len() * 32 {
        return Err(Error::Authentication);
    }
    let binding = wholepact_storage_security::bundle::recovery::generation::GenerationBinding::new(
        &plan.generation_id,
        &plan.inventory_digest,
    )?;
    Ok(CheckedMetadata {
        plan,
        binding,
        evidence_keys: keys,
        manifest_digest: commit.manifest_digest.clone(),
        restrictions,
    })
}

pub(super) fn open_checked_v5(
    directory: &Directory,
    secrets: &Secrets,
    commit: &CommitV5,
    unpublished: bool,
) -> Result<wholepact_store::Store> {
    if !unpublished {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    let metadata = checked_metadata_bytes_v5(
        directory
            .path("profile.vault")?
            .parent()
            .ok_or(Error::Invalid)?,
        secrets,
        commit,
        &directory.read(PLAN, MAX_DOCUMENT)?,
        &directory.read(MANIFEST, MAX_DOCUMENT)?,
        &directory.read("generation.keys", MAX_DOCUMENT)?,
    )?;
    let components = read_evidence(directory, &metadata)?;
    let cross = crate::recovery_semantics::inspect_successor(
        &components,
        &metadata.plan.affected_accounts,
    )?;
    if cross.digest() != metadata.plan.semantic_inventory_digest
        || cross.accounts() != &metadata.plan.affected_accounts
    {
        return Err(Error::Authentication);
    }
    let coordination_evidence = components
        .iter()
        .find(|c| c.provenance().component_id == "coordination")
        .ok_or(Error::Authentication)?;
    let semantic =
        wholepact_engine::recovery::inspect_successor_coordination_recovery(coordination_evidence)?;
    validate_store_manifest(
        &unseal(
            secrets,
            b"manifest",
            &directory.read(MANIFEST, MAX_DOCUMENT)?,
        )?,
        semantic.store_inventory(),
    )?;
    drop(components);
    check_directory_inventory(directory, &metadata.plan)?;
    // Keep all writable runtime and unpublished-empty checks unchanged.
    // An immutable history capability is never accepted here as admission.
    verify_auxiliaries(directory, secrets, unpublished)?;
    let coordination = metadata
        .plan
        .components
        .iter()
        .find(|c| c.component_id == "coordination")
        .ok_or(Error::Authentication)?;
    let store = wholepact_store::Store::open_recovered_generation(
        &directory.path(crate::vault::JOURNALS[0])?,
        &secrets.key(0)?,
        &metadata.binding,
        coordination,
    )?;
    store.verify_recovery_obligation_fences(&metadata.binding, &metadata.restrictions)?;
    Ok(store)
}

pub(crate) struct PreparedLayeredPublicationV5 {
    generation: super::super::layered::ConstructedLayeredGeneration,
    manifest: ManifestV5,
    manifest_digest: String,
}
impl super::super::layered::ConstructedLayeredGeneration {
    pub(crate) fn prepare_publication_v5(
        self,
        mut continuity: Vec<HostRecoveryContinuityEvidenceV5>,
    ) -> Result<PreparedLayeredPublicationV5> {
        let p = &self.pending;
        p.source.check()?;
        continuity.sort_by(|a, b| a.request.account_id.cmp(&b.request.account_id));
        let (restrictions, unresolved) = validate_continuity(
            &continuity,
            &p.plan.generation_id,
            &p.plan.inventory_digest,
            &p.plan.affected_accounts,
        )?;
        p.plan.verify_parent(p.source.capsule())?;
        let coordination = p.source.capsule().root().current_coordination();
        let semantic =
            wholepact_engine::recovery::inspect_archived_coordination_recovery(coordination)?;
        let inspected = inspect_continuity(
            &continuity,
            &p.plan.generation_id,
            &p.plan.inventory_digest,
            &p.plan.affected_accounts,
            semantic.store_inventory(),
        )?;
        let all_restrictions = inspected.obligation_fences;
        let unmatched = inspected.unmatched_host_authorizations;
        if unresolved != inspected.unresolved_offline_authorizations {
            return Err(Error::Authentication);
        }
        let binding = p.binding()?;
        let store = wholepact_store::Store::open_recovered_generation(
            &p.directory.path(crate::vault::JOURNALS[0])?,
            &p.secrets.key(0)?,
            &binding,
            coordination.source_provenance(),
        )?;
        // The sealed manifest's canonical continuity batch is the signer set.
        // Retain a separate monotone union batch for Store-only obligations;
        // never substitute that union for the exact batch readers authenticate.
        store.add_recovery_obligation_fences(&binding, &all_restrictions)?;
        if all_restrictions != restrictions {
            store.add_recovery_obligation_fences(&binding, &restrictions)?;
        }
        drop(store);
        let manifest = ManifestV5 {
            version: 5,
            plan_digest: p.plan_digest.clone(),
            continuity,
            unmatched_host_authorizations: unmatched,
            unresolved_offline_authorizations: unresolved,
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        let manifest_digest = persist_manifest(&p.directory, &p.secrets, &manifest)?;
        Ok(PreparedLayeredPublicationV5 {
            generation: self,
            manifest,
            manifest_digest,
        })
    }
}

impl PreparedLayeredPublicationV5 {
    /// Restriction-only retained source/target check during narrow endpoint
    /// reentry. It never creates or extends either terminal or signer authority.
    pub(crate) fn check_source(&self) -> Result<()> {
        let p = &self.generation.pending;
        p.source.check()?;
        p.directory.check()?;
        p.check_inventory()?;
        if hash(&p.directory.read(MANIFEST, MAX_DOCUMENT)?) != self.manifest_digest {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn requests(&self) -> Result<Vec<HostRecoveryPublicationRequestV5>> {
        requests(
            &self.manifest,
            &self.generation.pending.plan.target,
            &self.manifest_digest,
        )
    }
    pub(crate) fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    fn prepare_commit(
        &self,
        admissions: Vec<HostRecoveryPublicationAdmissionV5>,
    ) -> Result<Vec<u8>> {
        let p = &self.generation.pending;
        let commit = consume_admissions(
            &self.manifest,
            &p.plan.target,
            &self.manifest_digest,
            admissions,
        )?;
        p.source.check()?;
        p.directory.check()?;
        p.check_inventory()?;
        if hash(&p.directory.read(MANIFEST, MAX_DOCUMENT)?) != self.manifest_digest {
            return Err(Error::Authentication);
        }
        let bytes = seal(&p.secrets, b"commit", &encode(&commit)?)?;
        drop(super::layered_publication::open_layered_checked(
            &p.directory,
            &p.secrets,
            &bytes,
            true,
        )?);
        Ok(bytes)
    }
    pub(crate) fn publish(
        self,
        admissions: Vec<HostRecoveryPublicationAdmissionV5>,
        approval: crate::terminal::PublicationApproval,
    ) -> Result<()> {
        approval.commit(
            &self.manifest_digest,
            || self.prepare_commit(admissions),
            |bytes| self.generation.pending.directory.write_new(COMMIT, &bytes),
        )
    }
}

/// Read only after the containing owner authenticates the exact encrypted
/// manifest. The returned complete evidence is inert and cannot mint admissions.
pub(super) fn checked_continuity_rows(
    manifest_plain: &[u8],
) -> Result<Vec<HostRecoveryContinuityEvidenceV5>> {
    let manifest = read_manifest(manifest_plain)?;
    if let Some(first) = manifest.continuity.first() {
        let affected = manifest
            .continuity
            .iter()
            .map(|e| e.request.account_id.clone())
            .collect();
        let (_, unresolved) = validate_continuity(
            &manifest.continuity,
            &first.request.generation_id,
            &first.request.inventory_digest,
            &affected,
        )?;
        if unresolved != manifest.unresolved_offline_authorizations {
            return Err(Error::Authentication);
        }
    } else if !manifest.unresolved_offline_authorizations.is_empty()
        || !manifest.unmatched_host_authorizations.is_empty()
    {
        return Err(Error::Authentication);
    }
    Ok(manifest.continuity)
}

fn read_manifest(bytes: &[u8]) -> Result<ManifestV5> {
    if bytes.len() > MAX_DOCUMENT || metadata_version(bytes)? != 5 {
        return Err(Error::Authentication);
    }
    let manifest: ManifestV5 = serde_json::from_slice(bytes)?;
    canonical_hash(&manifest.plan_digest)?;
    if manifest.version != 5
        || !manifest.unknown_external_signatures
        || !manifest.recovered_obligations_fenced
        || manifest.financial_freshness_established
    {
        return Err(Error::Authentication);
    }
    for id in &manifest.unmatched_host_authorizations {
        crate::id(id)?;
    }
    Ok(manifest)
}

/// WIP55's complete historical join validator remains an inert read-only check.
/// This composition separately owns source authentication, exact inventory,
/// native live-admission consumption, and publication approval. Nothing in the
/// retained result enables restored financial access or replays old grants.
fn inspect_continuity(
    continuity: &[HostRecoveryContinuityEvidenceV5],
    generation: &str,
    inventory: &str,
    affected: &BTreeSet<String>,
    store: &wholepact_store::recovery::StoreRecoveryInventory,
) -> Result<super::retained_continuity::RetainedHistoryInspection> {
    let _bounded = encode(&continuity)?;
    let rows = continuity
        .iter()
        .map(|e| Ok((e.digest().map_err(|_| Error::Authentication)?, encode(e)?)))
        .collect::<Result<Vec<_>>>()?;
    let inputs = rows
        .iter()
        .map(
            |(digest, bytes)| super::retained_continuity::RetainedContinuityInput {
                version: 5,
                evidence_digest: digest,
                bytes,
            },
        )
        .collect::<Vec<_>>();
    super::retained_continuity::inspect_retained_continuity(
        &inputs, generation, inventory, affected, store,
    )
}

/// Strict V5 dispatch only. Older manifests must use their original readers;
/// never project or relabel transport/reentry origins into a V4 envelope.
pub(super) fn validate_store_manifest(
    manifest_plain: &[u8],
    store: &wholepact_store::recovery::StoreRecoveryInventory,
) -> Result<()> {
    let manifest = read_manifest(manifest_plain)?;
    let Some(first) = manifest.continuity.first() else {
        if !store.accounts().is_empty()
            || !store.obligations().is_empty()
            || !store.releases().is_empty()
            || !store.construction_claims().is_empty()
            || !store.construction_checkpoints().is_empty()
            || !store.construction_claims_v3().is_empty()
            || !store.construction_checkpoints_v3().is_empty()
            || !manifest.unmatched_host_authorizations.is_empty()
            || !manifest.unresolved_offline_authorizations.is_empty()
        {
            return Err(Error::Authentication);
        }
        return Ok(());
    };
    let accounts = manifest
        .continuity
        .iter()
        .map(|e| e.request.account_id.clone())
        .collect();
    let inspected = inspect_continuity(
        &manifest.continuity,
        &first.request.generation_id,
        &first.request.inventory_digest,
        &accounts,
        store,
    )?;
    if inspected.unmatched_host_authorizations != manifest.unmatched_host_authorizations
        || inspected.unresolved_offline_authorizations != manifest.unresolved_offline_authorizations
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

/// Layered plan remains V2: the new manifest/commit envelope is independently V5.
/// Parent capsule identity, random parent key and all exact plan bindings remain
/// mandatory. This metadata reader opens no live journals or native capabilities.
pub(super) fn checked_layered_metadata_bytes_v5(
    original_target: &std::path::Path,
    secrets: &Secrets,
    sealed_plan: &[u8],
    manifest_bytes: &[u8],
    commit_bytes: &[u8],
    sealed_keys: &[u8],
) -> Result<super::layered_metadata::CheckedLayeredMetadata> {
    use super::layered_metadata::{CheckedLayeredMetadata, LayeredPlan, parent_key_commitment};
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
    let restrictions = validate_metadata_v5(
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
    let binding = wholepact_storage_security::bundle::recovery::generation::GenerationBinding::new(
        &plan.generation_id,
        &plan.inventory_digest,
    )?;
    Ok(CheckedLayeredMetadata {
        plan,
        binding,
        manifest_digest: hash(manifest_bytes),
        restrictions,
        parent_key,
    })
}

#[cfg(all(test, feature = "manual-admission", target_os = "linux"))]
#[path = "transport_origins_tests.rs"]
mod tests;

#[cfg(all(test, feature = "manual-admission", target_os = "linux"))]
#[path = "transport_capsule_fixtures.rs"]
pub(crate) mod capsule_fixtures;
