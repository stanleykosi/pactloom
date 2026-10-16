//! Explicit manifest-v4 consumers for complete origins. These are source-only
//! until the distinct native v4 endpoint and every archive reader are qualified.
//! Existing manifest-v1/commit-v1 encodings and digest domains are unchanged.
#![allow(dead_code)]
use super::*;
use std::collections::BTreeMap;
use wholepact_signer::authority_bridge::{
    host_publication_ipc::v4::{
        HostRecoveryPublicationAdmissionV4, HostRecoveryPublicationRecordV4,
        HostRecoveryPublicationRequestV4,
    },
    host_recovery_ipc::{
        v2::HostRecoveryReservationOriginV2, v4::HostRecoveryContinuityEvidenceV4,
    },
};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestV4 {
    version: u16,
    plan_digest: String,
    continuity: Vec<HostRecoveryContinuityEvidenceV4>,
    unmatched_host_authorizations: BTreeSet<String>,
    unresolved_offline_authorizations: BTreeSet<String>,
    unknown_external_signatures: bool,
    recovered_obligations_fenced: bool,
    financial_freshness_established: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommitV4 {
    version: u16,
    plan_digest: String,
    manifest_digest: String,
    admissions: Vec<HostRecoveryPublicationRecordV4>,
}
use super::complete_origins::metadata_version;
fn validate_continuity(
    continuity: &[HostRecoveryContinuityEvidenceV4],
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
    continuity: &[HostRecoveryContinuityEvidenceV4],
) -> Result<BTreeSet<String>> {
    let mut unmatched = BTreeSet::new();
    for original in releases {
        let e = continuity
            .iter()
            .find(|e| e.request.account_id == original.account_id)
            .ok_or(Error::Authentication)?;
        let mut origin = None;
        for candidate in &e.complete_history.financial_origins_v2.origins {
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
pub(super) fn validate_metadata_v4(
    manifest_plain: &[u8],
    commit_plain: &[u8],
    manifest_digest: &str,
    plan_digest: &str,
    generation: &str,
    inventory: &str,
    target: &std::path::Path,
    affected: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    if metadata_version(manifest_plain)? != 4 || metadata_version(commit_plain)? != 4 {
        return Err(Error::Authentication);
    }
    let manifest: ManifestV4 = serde_json::from_slice(manifest_plain)?;
    let commit: CommitV4 = serde_json::from_slice(commit_plain)?;
    if manifest.version != 4
        || commit.version != 4
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

pub(crate) struct PreparedPublicationV4 {
    generation: ConstructedGeneration,
    manifest: ManifestV4,
    manifest_digest: String,
}
impl ConstructedGeneration {
    pub(crate) fn prepare_publication_v4(
        self,
        mut continuity: Vec<HostRecoveryContinuityEvidenceV4>,
    ) -> Result<PreparedPublicationV4> {
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
        validate_store_claims(semantic.store_inventory(), &continuity)?;
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
        let manifest = ManifestV4 {
            version: 4,
            plan_digest: p.plan_digest.clone(),
            continuity,
            unmatched_host_authorizations: unmatched,
            unresolved_offline_authorizations: unresolved,
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        let manifest_digest = persist_manifest(&p.directory, &p.secrets, &manifest)?;
        Ok(PreparedPublicationV4 {
            generation: self,
            manifest,
            manifest_digest,
        })
    }
}
fn persist_manifest(
    directory: &Directory,
    secrets: &Secrets,
    manifest: &ManifestV4,
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
    manifest: &ManifestV4,
    target: &std::path::Path,
    digest: &str,
) -> Result<Vec<HostRecoveryPublicationRequestV4>> {
    manifest
        .continuity
        .iter()
        .map(|e| {
            Ok(HostRecoveryPublicationRequestV4 {
                schema_version: 4,
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
    manifest: &ManifestV4,
    target: &std::path::Path,
    digest: &str,
    admissions: Vec<HostRecoveryPublicationAdmissionV4>,
) -> Result<CommitV4> {
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
    Ok(CommitV4 {
        version: 4,
        plan_digest: manifest.plan_digest.clone(),
        manifest_digest: digest.into(),
        admissions: records,
    })
}
impl PreparedPublicationV4 {
    pub(crate) fn requests(&self) -> Result<Vec<HostRecoveryPublicationRequestV4>> {
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
        admissions: Vec<HostRecoveryPublicationAdmissionV4>,
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
        drop(open_checked_v4(&p.directory, &p.secrets, &commit, true)?);
        Ok(bytes)
    }
    pub(crate) fn publish(
        self,
        admissions: Vec<HostRecoveryPublicationAdmissionV4>,
        approval: crate::terminal::PublicationApproval,
    ) -> Result<()> {
        approval.commit(
            &self.manifest_digest,
            || self.prepare_commit(admissions),
            |bytes| self.generation.pending.directory.write_new(COMMIT, &bytes),
        )
    }
}

pub(super) fn checked_metadata_bytes_v4(
    original_target: &std::path::Path,
    secrets: &Secrets,
    commit: &CommitV4,
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
    let restrictions = validate_metadata_v4(
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

pub(super) fn open_checked_v4(
    directory: &Directory,
    secrets: &Secrets,
    commit: &CommitV4,
    unpublished: bool,
) -> Result<wholepact_store::Store> {
    if !unpublished {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    let metadata = checked_metadata_bytes_v4(
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

pub(crate) struct PreparedLayeredPublicationV4 {
    generation: super::super::layered::ConstructedLayeredGeneration,
    manifest: ManifestV4,
    manifest_digest: String,
}
impl super::super::layered::ConstructedLayeredGeneration {
    pub(crate) fn prepare_publication_v4(
        self,
        mut continuity: Vec<HostRecoveryContinuityEvidenceV4>,
    ) -> Result<PreparedLayeredPublicationV4> {
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
        validate_store_claims(semantic.store_inventory(), &continuity)?;
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
        let manifest = ManifestV4 {
            version: 4,
            plan_digest: p.plan_digest.clone(),
            continuity,
            unmatched_host_authorizations: unmatched,
            unresolved_offline_authorizations: unresolved,
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        let manifest_digest = persist_manifest(&p.directory, &p.secrets, &manifest)?;
        Ok(PreparedLayeredPublicationV4 {
            generation: self,
            manifest,
            manifest_digest,
        })
    }
}

impl PreparedLayeredPublicationV4 {
    pub(crate) fn requests(&self) -> Result<Vec<HostRecoveryPublicationRequestV4>> {
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
        admissions: Vec<HostRecoveryPublicationAdmissionV4>,
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
        admissions: Vec<HostRecoveryPublicationAdmissionV4>,
        approval: crate::terminal::PublicationApproval,
    ) -> Result<()> {
        approval.commit(
            &self.manifest_digest,
            || self.prepare_commit(admissions),
            |bytes| self.generation.pending.directory.write_new(COMMIT, &bytes),
        )
    }
}

pub(super) fn checked_continuity_rows(
    manifest_plain: &[u8],
) -> Result<Vec<HostRecoveryContinuityEvidenceV4>> {
    if metadata_version(manifest_plain)? != 4 {
        return Err(Error::Authentication);
    }
    let manifest: ManifestV4 = serde_json::from_slice(manifest_plain)?;
    for e in &manifest.continuity {
        e.validate().map_err(|_| Error::Authentication)?;
    }
    Ok(manifest.continuity)
}

/// Check every known Store claim against the exact signer/authority origin.
/// Authority Reserve/Consume without a Store claim remains charged uncertainty;
/// absence of a claim is never interpreted as absence of a builder attempt.
fn require_manifest_v4_claim_encoding(version: u16, has_reentry_lineage: bool) -> Result<()> {
    if version != 3 || has_reentry_lineage {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    Ok(())
}

pub(super) fn validate_store_claims(
    inventory: &wholepact_store::recovery::StoreRecoveryInventory,
    continuity: &[HostRecoveryContinuityEvidenceV4],
) -> Result<()> {
    use wholepact_authority::ConstructionOriginHistoryV2;
    let mut accounts = BTreeMap::new();
    for evidence in continuity {
        evidence.validate().map_err(|_| Error::Authentication)?;
        if accounts
            .insert(evidence.request.account_id.as_str(), evidence)
            .is_some()
        {
            return Err(Error::Authentication);
        }
    }
    for (_, claim) in inventory.construction_claims() {
        claim.validate().map_err(|_| Error::Authentication)?;
        for native in &claim.consumed {
            let account = native
                .request
                .plan
                .enrollment()
                .identity
                .account_id
                .as_str();
            let history = &accounts
                .get(account)
                .ok_or(Error::Authentication)?
                .complete_history;
            let matching = history
                .construction
                .origins()
                .iter()
                .filter(|origin| {
                    let ConstructionOriginHistoryV2::RosterV2 { origin } = origin else {
                        return false;
                    };
                    let r = origin.reservation();
                    let Some(c) = origin.consumed() else {
                        return false;
                    };
                    r.request.construction == native.request
                        && r.digest_for(origin.extension(), origin.continuation())
                            .ok()
                            .as_deref()
                            == Some(native.witness_reservation_digest.as_str())
                        && c.digest_for(r, origin.extension(), origin.continuation())
                            .ok()
                            .as_deref()
                            == Some(native.witness_consumed_digest.as_str())
                        && r.request.signer_intent_digest == native.retained_signer_intent_digest
                        && r.request.attempt_digest == native.current_attempt_digest
                        && r.request.attempt_sequence == native.current_attempt_sequence
                        && r.request.native_review_digest == native.native_review_digest
                        && r.request.reviewed_at_ms == native.reviewed_at_ms
                        && r.admitted_at_ms == native.reserved_at_ms
                        && c.consumed_at_ms == native.consumed_at_ms
                        && r.reserved_debit_zatoshis == native.reserved_debit_zatoshis
                        && r.reserved_input_value_zatoshis == native.reserved_input_value_zatoshis
                        && r.session.expires_at_ms == native.writer_session_expires_at_ms
                })
                .count();
            if matching != 1 {
                return Err(Error::Authentication);
            }
        }
    }
    for (_, claim) in inventory.construction_claims_v3() {
        claim.validate().map_err(|_| Error::Authentication)?;
        // Manifest-v4 cannot discard the explicit new transport credential,
        // original-key fence and native reentry lineage. A distinct complete
        // publication format/issuer is required before recovering these claims.
        require_manifest_v4_claim_encoding(claim.version, claim.reentry_lineages.is_some())?;
        for native in &claim.consumed {
            let account = native
                .request
                .plan
                .enrollment()
                .identity
                .account_id
                .as_str();
            let history = &accounts
                .get(account)
                .ok_or(Error::Authentication)?
                .complete_history;
            require_exact_common_context_consume(history, native)?;
        }
    }
    Ok(())
}
/// Exhaustive archive dispatch: an older manifest cannot erase current V3 rows.
pub(super) fn validate_store_manifest(
    manifest_plain: &[u8],
    inventory: &wholepact_store::recovery::StoreRecoveryInventory,
) -> Result<()> {
    match metadata_version(manifest_plain)? {
        4 => validate_store_claims(inventory, &checked_continuity_rows(manifest_plain)?),
        1..=3
            if inventory.construction_claims_v3().is_empty()
                && inventory.construction_checkpoints_v3().is_empty() =>
        {
            Ok(())
        }
        _ => Err(Error::RecoveryFinancialUnsupported),
    }
}

#[cfg(test)]
#[path = "common_context_origins_tests.rs"]
mod tests;

fn require_exact_common_context_consume(
    history: &wholepact_signer::authority_bridge::host_recovery_ipc::v4::HostRecoveryHistoryV4,
    native: &wholepact_store::manual_enrollment::ManualRosterConsumedConstructionAuditV3,
) -> Result<()> {
    use wholepact_authority::{ConstructionApprovalHistoryV2, ConstructionOriginHistoryV2};
    use wholepact_signer::consent_journal::CommonContextSignerAuditV1;
    native.validate().map_err(|_| Error::Authentication)?;
    history
        .signer_common_context_audit
        .validate_against(&history.construction)
        .map_err(|_| Error::Authentication)?;
    let matching = history
        .construction
        .origins()
        .iter()
        .filter(|o| {
            let ConstructionOriginHistoryV2::CommonContextV3 { origin } = o else {
                return false;
            };
            let r = origin.reservation();
            let Some(c) = origin.consumed() else {
                return false;
            };
            r.request.construction == native.request
                && r.digest_for(origin.extension(), origin.continuation())
                    .ok()
                    .as_deref()
                    == Some(native.witness_reservation_digest.as_str())
                && c.digest_for(r, origin.extension(), origin.continuation())
                    .ok()
                    .as_deref()
                    == Some(native.witness_consumed_digest.as_str())
                && r.request.signer_intent_digest == native.retained_signer_intent_digest
                && r.request.attempt_digest == native.current_attempt_digest
                && r.request.attempt_sequence == native.current_attempt_sequence
                && r.request.native_review_digest == native.native_review_digest
                && r.request.reviewed_at_ms == native.reviewed_at_ms
                && r.admitted_at_ms == native.reserved_at_ms
                && c.consumed_at_ms == native.consumed_at_ms
                && r.reserved_debit_zatoshis == native.reserved_debit_zatoshis
                && r.reserved_input_value_zatoshis == native.reserved_input_value_zatoshis
                && r.session.expires_at_ms == native.writer_session_expires_at_ms
        })
        .count();
    if matching!=1 || history.construction.approvals().iter().filter(|a| {
        matches!(a,ConstructionApprovalHistoryV2::CommonContextV3 {extension,record}
            if record.approval.plan==native.request.plan && record.approval.digest_for(extension).ok().as_deref()==Some(native.witness_plan_approval_digest.as_str()))
    }).count()!=1 {return Err(Error::Authentication);}
    let expected = native.digest().map_err(|_| Error::Authentication)?;
    let invocation = native
        .request
        .plan
        .invocation_digest()
        .map_err(|_| Error::Authentication)?;
    // Every PRESENT local record joins exactly. Absent local success is derived
    // by missing_local_native_phases; it never erases authority charges, creates
    // a receipt, or claims that the provider read/builder did not run.
    for row in &history.signer_common_context_audit.rows {
        if row.invocation_digest().map_err(|_| Error::Authentication)? != invocation {
            continue;
        }
        match row {
            CommonContextSignerAuditV1::Consumed { evidence, .. }
                if evidence.digest().ok().as_deref() != Some(expected.as_str()) =>
            {
                return Err(Error::Authentication);
            }
            CommonContextSignerAuditV1::ReadAdmitted { evidence, .. }
                if evidence.digest().ok().as_deref()
                    != Some(native.common_context_read_admission_digest.as_str()) =>
            {
                return Err(Error::Authentication);
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "manual-admission"))]
#[path = "common_context_capsule_fixtures.rs"]
pub(crate) mod capsule_fixtures;
