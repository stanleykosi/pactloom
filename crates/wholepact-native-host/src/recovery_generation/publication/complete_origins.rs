//! Explicit manifest-v2 consumers for complete origins. These are source-only
//! until the distinct native v2 endpoint and every archive reader are qualified.
//! Existing manifest-v1/commit-v1 encodings and digest domains are unchanged.
#![allow(dead_code)]
use super::*;
use wholepact_signer::authority_bridge::{
    host_publication_ipc::v2::{
        HostRecoveryPublicationAdmissionV2, HostRecoveryPublicationRecordV2,
        HostRecoveryPublicationRequestV2,
    },
    host_recovery_ipc::v2::{HostRecoveryContinuityEvidenceV2, HostRecoveryReservationOriginV2},
};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestV2 {
    version: u16,
    plan_digest: String,
    continuity: Vec<HostRecoveryContinuityEvidenceV2>,
    unmatched_host_authorizations: BTreeSet<String>,
    unresolved_offline_authorizations: BTreeSet<String>,
    unknown_external_signatures: bool,
    recovered_obligations_fenced: bool,
    financial_freshness_established: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommitV2 {
    version: u16,
    plan_digest: String,
    manifest_digest: String,
    admissions: Vec<HostRecoveryPublicationRecordV2>,
}
/// Version selection never retries a failed v2 document with a v1 parser.
/// Final parsing still denies unknown fields and validates the complete body.
pub(super) fn metadata_version(bytes: &[u8]) -> Result<u16> {
    if bytes.len() > MAX_DOCUMENT {
        return Err(Error::Invalid);
    }
    let v: serde_json::Value = serde_json::from_slice(bytes)?;
    match v.get("version").and_then(serde_json::Value::as_u64) {
        Some(1) => Ok(1),
        Some(2) => Ok(2),
        Some(3) => Ok(3),
        Some(4) => Ok(4),
        Some(5) => Ok(5),
        _ => Err(Error::Unsupported),
    }
}
fn validate_continuity(
    continuity: &[HostRecoveryContinuityEvidenceV2],
    generation: &str,
    inventory: &str,
    affected: &BTreeSet<String>,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
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
/// Legacy Store releases have an original ONLINE writer epoch. An authorization
/// ID collision with an offline origin is a mismatch, never permission to invent
/// a writer epoch or a native original for minimal local evidence.
fn match_host_releases(
    releases: &[wholepact_store::authority::ReleaseIntent],
    continuity: &[HostRecoveryContinuityEvidenceV2],
) -> Result<BTreeSet<String>> {
    let mut unmatched = BTreeSet::new();
    for original in releases {
        let e = continuity
            .iter()
            .find(|e| e.request.account_id == original.account_id)
            .ok_or(Error::Authentication)?;
        let mut origin = None;
        for candidate in &e.complete_history.origins {
            if candidate
                .authorization_id()
                .map_err(|_| Error::Authentication)?
                == original.authorization_id
            {
                if origin.is_some() {
                    return Err(Error::Authentication);
                }
                origin = Some(candidate);
            }
        }
        let Some(origin) = origin else {
            unmatched.insert(original.authorization_id.clone());
            continue;
        };
        match origin {
            HostRecoveryReservationOriginV2::Online { permit } => {
                let r = &permit.request;
                let mut inputs = r
                    .inputs
                    .iter()
                    .map(|i| i.input_id.clone())
                    .collect::<Vec<_>>();
                inputs.sort();
                let mut original_inputs = original.input_ids.clone();
                original_inputs.sort();
                if r.writer_epoch != original.writer_epoch
                    || r.account_id != original.account_id
                    || r.obligation_id != original.obligation_id
                    || r.proposal_id != original.proposal_id
                    || r.manifest_digest != original.manifest_digest
                    || r.effects_digest != original.effects_digest
                    || r.artifact_digest != original.artifact_digest
                    || r.maximum_debit_zatoshis.to_string() != original.maximum_debit
                    || inputs != original_inputs
                {
                    return Err(Error::Authentication);
                }
            }
            HostRecoveryReservationOriginV2::Offline { .. } => return Err(Error::Authentication),
        }
    }
    Ok(unmatched)
}
/// Shared strict historical reader for both ordinary and layered generation
/// metadata. Saved admissions remain audit records and cannot enter publish().
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_metadata_v2(
    manifest_plain: &[u8],
    commit_plain: &[u8],
    manifest_digest: &str,
    plan_digest: &str,
    generation: &str,
    inventory: &str,
    target: &std::path::Path,
    affected: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    if metadata_version(manifest_plain)? != 2 || metadata_version(commit_plain)? != 2 {
        return Err(Error::Authentication);
    }
    let manifest: ManifestV2 = serde_json::from_slice(manifest_plain)?;
    let commit: CommitV2 = serde_json::from_slice(commit_plain)?;
    if manifest.version != 2
        || commit.version != 2
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
            || !admitted.insert(r.continuity.account_id.clone())
        {
            return Err(Error::Authentication);
        }
    }
    if &admitted != affected {
        return Err(Error::Authentication);
    }
    for id in &manifest.unmatched_host_authorizations {
        crate::id(id)?;
    }
    Ok(restrictions)
}

pub(crate) struct PreparedPublicationV2 {
    generation: ConstructedGeneration,
    manifest: ManifestV2,
    manifest_digest: String,
}
impl ConstructedGeneration {
    pub(crate) fn prepare_publication_v2(
        self,
        mut continuity: Vec<HostRecoveryContinuityEvidenceV2>,
    ) -> Result<PreparedPublicationV2> {
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
        if cross.digest() != p.plan.semantic_inventory_digest {
            return Err(Error::Authentication);
        }
        let semantic = wholepact_engine::recovery::inspect_coordination_recovery(coordination)?;
        let unmatched = match_host_releases(semantic.store_inventory().releases(), &continuity)?;
        let binding = p.binding()?;
        let store = wholepact_store::Store::open_recovered_generation(
            &p.directory.path(crate::vault::JOURNALS[0])?,
            &p.secrets.key(0)?,
            &binding,
            coordination.provenance(),
        )?;
        store.add_recovery_obligation_fences(&binding, &restrictions)?;
        drop(store);
        let manifest = ManifestV2 {
            version: 2,
            plan_digest: p.plan_digest.clone(),
            continuity,
            unmatched_host_authorizations: unmatched,
            unresolved_offline_authorizations: unresolved,
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        let manifest_digest = persist_manifest(&p.directory, &p.secrets, &manifest)?;
        Ok(PreparedPublicationV2 {
            generation: self,
            manifest,
            manifest_digest,
        })
    }
}
fn persist_manifest(
    directory: &Directory,
    secrets: &Secrets,
    manifest: &ManifestV2,
) -> Result<String> {
    let plain = encode(manifest)?;
    let bytes = if directory.path(MANIFEST)?.try_exists()? {
        let bytes = directory.read(MANIFEST, MAX_DOCUMENT)?;
        if unseal(secrets, b"manifest", &bytes)?.as_slice() != plain.as_slice() {
            return Err(Error::RecoverySemantic("The complete-origin pending snapshot changed. Preserve this partial target and obtain fresh native reviews at a fresh target; no v1 downgrade or saved-admission replay is permitted".into()));
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
    manifest: &ManifestV2,
    target: &std::path::Path,
    digest: &str,
) -> Result<Vec<HostRecoveryPublicationRequestV2>> {
    manifest
        .continuity
        .iter()
        .map(|e| {
            Ok(HostRecoveryPublicationRequestV2 {
                schema_version: 2,
                continuity: e.request.clone(),
                target_profile: target.into(),
                generation_manifest_digest: digest.into(),
                continuity_evidence_digest: e.digest().map_err(|_| Error::Authentication)?,
            })
        })
        .collect()
}
/// Consumes only genuinely issued non-Clone, non-Deserialize live admissions.
fn consume_admissions(
    manifest: &ManifestV2,
    target: &std::path::Path,
    digest: &str,
    admissions: Vec<HostRecoveryPublicationAdmissionV2>,
) -> Result<CommitV2> {
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
        r.matches_evidence(admission.evidence())
            .map_err(|_| Error::Permission)?;
        records.push(admission.into_audit_record());
    }
    records.sort_by(|a, b| {
        a.request
            .continuity
            .account_id
            .cmp(&b.request.continuity.account_id)
    });
    Ok(CommitV2 {
        version: 2,
        plan_digest: manifest.plan_digest.clone(),
        manifest_digest: digest.into(),
        admissions: records,
    })
}
impl PreparedPublicationV2 {
    pub(crate) fn requests(&self) -> Result<Vec<HostRecoveryPublicationRequestV2>> {
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
        admissions: Vec<HostRecoveryPublicationAdmissionV2>,
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
        drop(open_checked_v2(&p.directory, &p.secrets, &commit, true)?);
        Ok(bytes)
    }
    pub(crate) fn publish(
        self,
        admissions: Vec<HostRecoveryPublicationAdmissionV2>,
        approval: crate::terminal::PublicationApproval,
    ) -> Result<()> {
        approval.commit(
            &self.manifest_digest,
            || self.prepare_commit(admissions),
            |bytes| self.generation.pending.directory.write_new(COMMIT, &bytes),
        )
    }
}

pub(super) fn checked_metadata_bytes_v2(
    original_target: &std::path::Path,
    secrets: &Secrets,
    commit: &CommitV2,
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
    let manifest_plain = unseal(secrets, b"manifest", manifest_bytes)?;
    let restrictions = validate_metadata_v2(
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

pub(super) fn open_checked_v2(
    directory: &Directory,
    secrets: &Secrets,
    commit: &CommitV2,
    unpublished: bool,
) -> Result<wholepact_store::Store> {
    let metadata = checked_metadata_bytes_v2(
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
    drop(read_evidence(directory, &metadata)?);
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

pub(super) fn checked_metadata_dispatch(
    directory: &Directory,
    secrets: &Secrets,
    commit_plain: &[u8],
) -> Result<CheckedMetadata> {
    checked_metadata_bytes_dispatch(
        directory
            .path("profile.vault")?
            .parent()
            .ok_or(Error::Invalid)?,
        secrets,
        commit_plain,
        &directory.read(PLAN, MAX_DOCUMENT)?,
        &directory.read(MANIFEST, MAX_DOCUMENT)?,
        &directory.read("generation.keys", MAX_DOCUMENT)?,
    )
}
pub(super) fn checked_metadata_bytes_dispatch(
    target: &std::path::Path,
    secrets: &Secrets,
    commit_plain: &[u8],
    plan: &[u8],
    manifest: &[u8],
    keys: &[u8],
) -> Result<CheckedMetadata> {
    match metadata_version(commit_plain)? {
        1 => super::checked_metadata_bytes(
            target,
            secrets,
            &serde_json::from_slice::<Commit>(commit_plain)?,
            plan,
            manifest,
            keys,
        ),
        2 => checked_metadata_bytes_v2(
            target,
            secrets,
            &serde_json::from_slice::<CommitV2>(commit_plain)?,
            plan,
            manifest,
            keys,
        ),
        3 => super::construction_origins::checked_metadata_bytes_v3(
            target,
            secrets,
            &serde_json::from_slice::<super::construction_origins::CommitV3>(commit_plain)?,
            plan,
            manifest,
            keys,
        ),
        4 => super::common_context_origins::checked_metadata_bytes_v4(
            target,
            secrets,
            &serde_json::from_slice::<super::common_context_origins::CommitV4>(commit_plain)?,
            plan,
            manifest,
            keys,
        ),
        5 => super::transport_origins::checked_metadata_bytes_v5(
            target,
            secrets,
            &serde_json::from_slice::<super::transport_origins::CommitV5>(commit_plain)?,
            plan,
            manifest,
            keys,
        ),
        _ => Err(Error::Unsupported),
    }
}

/// Select the exact complete Store-claim family before reading retained history.
/// In particular, a V5 body never passes through a V4 financial projection.
pub(super) fn validate_store_manifest_dispatch(
    manifest_plain: &[u8],
    inventory: &wholepact_store::recovery::StoreRecoveryInventory,
) -> Result<()> {
    match metadata_version(manifest_plain)? {
        1..=4 => super::common_context_origins::validate_store_manifest(manifest_plain, inventory),
        5 => super::transport_origins::validate_store_manifest(manifest_plain, inventory),
        _ => Err(Error::Unsupported),
    }
}

pub(crate) struct PreparedLayeredPublicationV2 {
    generation: super::super::layered::ConstructedLayeredGeneration,
    manifest: ManifestV2,
    manifest_digest: String,
}
impl super::super::layered::ConstructedLayeredGeneration {
    pub(crate) fn prepare_publication_v2(
        self,
        mut continuity: Vec<HostRecoveryContinuityEvidenceV2>,
    ) -> Result<PreparedLayeredPublicationV2> {
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
        let unmatched = match_host_releases(semantic.store_inventory().releases(), &continuity)?;
        let binding = p.binding()?;
        let store = wholepact_store::Store::open_recovered_generation(
            &p.directory.path(crate::vault::JOURNALS[0])?,
            &p.secrets.key(0)?,
            &binding,
            coordination.source_provenance(),
        )?;
        store.add_recovery_obligation_fences(&binding, &restrictions)?;
        drop(store);
        let manifest = ManifestV2 {
            version: 2,
            plan_digest: p.plan_digest.clone(),
            continuity,
            unmatched_host_authorizations: unmatched,
            unresolved_offline_authorizations: unresolved,
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        let manifest_digest = persist_manifest(&p.directory, &p.secrets, &manifest)?;
        Ok(PreparedLayeredPublicationV2 {
            generation: self,
            manifest,
            manifest_digest,
        })
    }
}

impl PreparedLayeredPublicationV2 {
    pub(crate) fn requests(&self) -> Result<Vec<HostRecoveryPublicationRequestV2>> {
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
        admissions: Vec<HostRecoveryPublicationAdmissionV2>,
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
        admissions: Vec<HostRecoveryPublicationAdmissionV2>,
        approval: crate::terminal::PublicationApproval,
    ) -> Result<()> {
        approval.commit(
            &self.manifest_digest,
            || self.prepare_commit(admissions),
            |bytes| self.generation.pending.directory.write_new(COMMIT, &bytes),
        )
    }
}

/// Called only by the complete archive owner after exact metadata validation.
/// A v1 document has no complete identity/exclusion provenance projection.
pub(super) fn checked_manual_identity_rows(
    manifest_plain: &[u8],
) -> Result<Option<CheckedContinuityRows>> {
    match metadata_version(manifest_plain)? {
        1 => {
            let _: super::Manifest = serde_json::from_slice(manifest_plain)?;
            Ok(None)
        }
        2 => {
            let manifest: ManifestV2 = serde_json::from_slice(manifest_plain)?;
            Ok(Some(CheckedContinuityRows::V2(manifest.continuity)))
        }
        3 => Ok(Some(CheckedContinuityRows::V3(
            super::construction_origins::checked_continuity_rows(manifest_plain)?,
        ))),
        4 => Ok(Some(CheckedContinuityRows::V4(
            super::common_context_origins::checked_continuity_rows(manifest_plain)?,
        ))),
        5 => Ok(Some(CheckedContinuityRows::V5(
            super::transport_origins::checked_continuity_rows(manifest_plain)?,
        ))),
        _ => Err(Error::Authentication),
    }
}

pub(super) enum CheckedContinuityRows {
    V2(Vec<HostRecoveryContinuityEvidenceV2>),
    V3(Vec<wholepact_signer::authority_bridge::host_recovery_ipc::v3::HostRecoveryContinuityEvidenceV3>),
    V4(Vec<wholepact_signer::authority_bridge::host_recovery_ipc::v4::HostRecoveryContinuityEvidenceV4>),
    V5(Vec<wholepact_signer::authority_bridge::host_recovery_ipc::v5::HostRecoveryContinuityEvidenceV5>),
}

impl CheckedContinuityRows {
    // A deliberately identity-only projection AFTER validating the entire typed
    // envelope. This cannot be used as financial/exposure history.
    pub(super) fn checked_identity_rows(
        &self,
    ) -> Result<
        Vec<(
            &str,
            &wholepact_signer::authority_bridge::host_recovery_ipc::v2::AccountUseHistoryV2,
        )>,
    > {
        match self {
            Self::V2(rows) => rows
                .iter()
                .map(|e| {
                    e.validate().map_err(|_| Error::Authentication)?;
                    Ok((
                        e.request.account_id.as_str(),
                        &e.complete_history.account_use,
                    ))
                })
                .collect(),
            Self::V3(rows) => rows
                .iter()
                .map(|e| {
                    e.validate().map_err(|_| Error::Authentication)?;
                    Ok((
                        e.request.account_id.as_str(),
                        &e.complete_history.financial_origins_v2.account_use,
                    ))
                })
                .collect(),
            Self::V4(rows) => rows
                .iter()
                .map(|e| {
                    e.validate().map_err(|_| Error::Authentication)?;
                    Ok((
                        e.request.account_id.as_str(),
                        &e.complete_history.financial_origins_v2.account_use,
                    ))
                })
                .collect(),
            Self::V5(rows) => rows
                .iter()
                .map(|e| {
                    e.validate().map_err(|_| Error::Authentication)?;
                    Ok((
                        e.request.account_id.as_str(),
                        &e.complete_history.financial_origins_v2.account_use,
                    ))
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence() -> HostRecoveryContinuityEvidenceV2 {
        serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../wholepact-signer/src/authority_bridge/host_recovery_ipc/v2/fixtures/minimal_evidence.json"))).unwrap()
    }
    fn metadata() -> (ManifestV2, CommitV2, HostRecoveryContinuityEvidenceV2) {
        let e = evidence();
        let manifest = ManifestV2 {
            version: 2,
            plan_digest: "11".repeat(32),
            continuity: vec![e.clone()],
            unmatched_host_authorizations: BTreeSet::new(),
            unresolved_offline_authorizations: e
                .complete_history
                .unresolved_offline_authorizations()
                .unwrap(),
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        // Plain historical audit fixture, deliberately not a native admission.
        let record = HostRecoveryPublicationRecordV2 {
            request: HostRecoveryPublicationRequestV2 {
                schema_version: 2,
                continuity: e.request.clone(),
                target_profile: "/synthetic/successor".into(),
                generation_manifest_digest: "22".repeat(32),
                continuity_evidence_digest: e.digest().unwrap(),
            },
            native_review_digest: "33".repeat(32),
            admission_id: "44".repeat(32),
        };
        let commit = CommitV2 {
            version: 2,
            plan_digest: manifest.plan_digest.clone(),
            manifest_digest: "22".repeat(32),
            admissions: vec![record],
        };
        (manifest, commit, e)
    }
    fn check(
        m: &ManifestV2,
        c: &CommitV2,
        e: &HostRecoveryContinuityEvidenceV2,
    ) -> Result<BTreeSet<String>> {
        validate_metadata_v2(
            &encode(m)?,
            &encode(c)?,
            &"22".repeat(32),
            &"11".repeat(32),
            &e.request.generation_id,
            &e.request.inventory_digest,
            std::path::Path::new("/synthetic/successor"),
            &BTreeSet::from([e.request.account_id.clone()]),
        )
    }
    #[test]
    fn both_generation_shapes_consume_all_origin_obligation_fences() {
        let (m, c, e) = metadata();
        assert_eq!(
            check(&m, &c, &e).unwrap(),
            BTreeSet::from(["synthetic-offline-obligation".into()])
        );
        assert!(
            consume_admissions(
                &m,
                std::path::Path::new("/synthetic/successor"),
                &"22".repeat(32),
                vec![]
            )
            .is_err()
        );
    }
    #[test]
    fn unknown_coverage_cannot_be_erased_or_relabelled_financially_current() {
        let (mut m, c, e) = metadata();
        m.unresolved_offline_authorizations.clear();
        assert!(check(&m, &c, &e).is_err());
        let (mut m, c, e) = metadata();
        m.unknown_external_signatures = false;
        assert!(check(&m, &c, &e).is_err());
        let (mut m, c, e) = metadata();
        m.financial_freshness_established = true;
        assert!(check(&m, &c, &e).is_err());
        let (mut m, c, e) = metadata();
        m.continuity[0].complete_history.complete_journal_digest = "ee".repeat(32);
        assert!(check(&m, &c, &e).is_err());
    }
    #[test]
    fn mixed_versions_do_not_fall_back_to_legacy_or_accept_saved_authority() {
        let (mut m, c, e) = metadata();
        m.version = 1;
        assert!(check(&m, &c, &e).is_err());
        let (m, mut c, e) = metadata();
        c.version = 1;
        assert!(check(&m, &c, &e).is_err());
        assert_eq!(metadata_version(br#"{"version":5}"#).unwrap(), 5);
        assert!(metadata_version(br#"{"version":6}"#).is_err());
        let (m, mut c, e) = metadata();
        c.admissions[0].request.target_profile = "/synthetic/other".into();
        assert!(check(&m, &c, &e).is_err());
    }
    #[test]
    fn legacy_host_release_never_invents_an_offline_writer_or_original() {
        let e = evidence();
        let HostRecoveryReservationOriginV2::Offline { origin } = &e.complete_history.origins[0]
        else {
            panic!("wrong origin")
        };
        let t = origin.terms().unwrap();
        let release = wholepact_store::authority::ReleaseIntent {
            authorization_id: t.authorization_id.clone(),
            account_id: t.account_id.clone(),
            writer_epoch: 1,
            obligation_id: t.obligation_id.clone(),
            proposal_id: t.proposal_id.clone(),
            manifest_digest: t.manifest_digest.clone(),
            effects_digest: t.effects_digest.clone(),
            artifact_digest: t.artifact_digest.clone(),
            maximum_debit: t.maximum_debit_zatoshis.to_string(),
            input_ids: t.inputs.iter().map(|i| i.input_id.clone()).collect(),
            aggregate_budget_limit: "100".into(),
        };
        assert!(match_host_releases(&[release], &[e]).is_err());
    }
}
