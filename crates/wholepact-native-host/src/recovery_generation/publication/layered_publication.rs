//! Typed publication for layered successors. Prior admissions remain audit only.
use super::super::layered::ConstructedLayeredGeneration;
use super::archive_history::VerifiedGenerationCapsule;
use super::*;
use wholepact_storage_security::{DatabaseKey, generation_archive};

pub(crate) struct PreparedLayeredPublication {
    generation: ConstructedLayeredGeneration,
    manifest: Manifest,
    manifest_digest: String,
}
impl ConstructedLayeredGeneration {
    #[cfg(test)]
    pub(crate) fn missing_publication_admission_fixture_for_test(
        self,
        evidence: HostRecoveryContinuityEvidence,
    ) -> bool {
        // Deliberately fabricate plain audit requests inside this private test
        // module. They must never replace the opaque live admission type. No
        // source account, manifest, fence or final marker is written here.
        let manifest = Manifest {
            version: 1,
            plan_digest: self.pending.plan_digest.clone(),
            continuity: vec![evidence],
            unmatched_host_authorizations: BTreeSet::new(),
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        let prepared = PreparedLayeredPublication {
            generation: self,
            manifest,
            manifest_digest: "ab".repeat(32),
        };
        matches!(prepared.prepare_commit(vec![]), Err(Error::Permission))
    }
    /// All leases must be released before the distinct signer publication
    /// reviews. Persist only their audit evidence, never a saved permission.
    pub(crate) fn prepare_publication(
        self,
        mut continuity: Vec<HostRecoveryContinuityEvidence>,
    ) -> Result<PreparedLayeredPublication> {
        let p = &self.pending;
        p.source.check()?;
        continuity.sort_by(|a, b| a.request.account_id.cmp(&b.request.account_id));
        let mut accounts = BTreeSet::new();
        for evidence in &continuity {
            evidence.digest().map_err(|_| Error::Authentication)?;
            if evidence.request.generation_id != p.plan.generation_id
                || evidence.request.inventory_digest != p.plan.inventory_digest
                || !accounts.insert(evidence.request.account_id.clone())
            {
                return Err(Error::Authentication);
            }
        }
        if accounts != p.plan.affected_accounts {
            return Err(Error::Authentication);
        }
        p.plan.verify_parent(p.source.capsule())?;
        let coordination = p.source.capsule().root().current_coordination();
        let semantic =
            wholepact_engine::recovery::inspect_archived_coordination_recovery(coordination)?;
        let mut unmatched = BTreeSet::new();
        for original in semantic.store_inventory().releases() {
            let evidence = continuity
                .iter()
                .find(|e| e.request.account_id == original.account_id)
                .ok_or(Error::Authentication)?;
            let Some(permit) = evidence
                .conservative_permits
                .iter()
                .find(|p| p.request.authorization_id == original.authorization_id)
            else {
                // A release outside the current witness protocol is unknown,
                // never absent, discounted, or made replaceable by publication.
                unmatched.insert(original.authorization_id.clone());
                continue;
            };
            let request = &permit.request;
            let mut inputs = request
                .inputs
                .iter()
                .map(|i| i.input_id.clone())
                .collect::<Vec<_>>();
            inputs.sort();
            let mut original_inputs = original.input_ids.clone();
            original_inputs.sort();
            if request.writer_epoch != original.writer_epoch
                || request.account_id != original.account_id
                || request.obligation_id != original.obligation_id
                || request.proposal_id != original.proposal_id
                || request.manifest_digest != original.manifest_digest
                || request.effects_digest != original.effects_digest
                || request.artifact_digest != original.artifact_digest
                || request.maximum_debit_zatoshis.to_string() != original.maximum_debit
                || inputs != original_inputs
            {
                return Err(Error::Authentication);
            }
        }
        let binding = p.binding()?;
        let store = wholepact_store::Store::open_recovered_generation(
            &p.directory.path(crate::vault::JOURNALS[0])?,
            &p.secrets.key(0)?,
            &binding,
            coordination.source_provenance(),
        )?;
        let restrictions = continuity
            .iter()
            .flat_map(|e| {
                e.conservative_permits
                    .iter()
                    .map(|permit| permit.request.obligation_id.clone())
            })
            .collect::<BTreeSet<_>>();
        store.add_recovery_obligation_fences(&binding, &restrictions)?;
        drop(store);
        let manifest = Manifest {
            version: 1,
            plan_digest: p.plan_digest.clone(),
            continuity,
            unmatched_host_authorizations: unmatched,
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        let plain = encode(&manifest)?;
        let bytes = if p.directory.path(MANIFEST)?.try_exists()? {
            let bytes = p.directory.read(MANIFEST, MAX_DOCUMENT)?;
            if unseal(&p.secrets, b"manifest", &bytes)?.as_slice() != plain.as_slice() {
                return Err(Error::RecoverySemantic("The exact pending publication snapshot changed. Preserve this partial target and create a fresh target with new native reviews; saved admissions cannot be reused".into()));
            }
            bytes
        } else {
            let bytes = seal(&p.secrets, b"manifest", &plain)?;
            p.directory.write_new(MANIFEST, &bytes)?;
            bytes
        };
        Ok(PreparedLayeredPublication {
            generation: self,
            manifest,
            manifest_digest: hash(&bytes),
        })
    }
}
impl PreparedLayeredPublication {
    pub(crate) fn requests(&self) -> Result<Vec<HostRecoveryPublicationRequest>> {
        self.manifest
            .continuity
            .iter()
            .map(|e| {
                Ok(HostRecoveryPublicationRequest {
                    schema_version: 1,
                    continuity: e.request.clone(),
                    target_profile: self.generation.pending.plan.target.clone(),
                    generation_manifest_digest: self.manifest_digest.clone(),
                    continuity_evidence_digest: e.digest().map_err(|_| Error::Authentication)?,
                })
            })
            .collect()
    }
    pub(crate) fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Admission consumes live, non-deserializable signer decisions. Each is
    /// only an informational cutoff for its account; remote activity remains
    /// possible. The host's local native effect lease spans the exact marker
    /// write and fsync. A saved audit record can never call this entrypoint.
    fn prepare_commit(&self, admissions: Vec<HostRecoveryPublicationAdmission>) -> Result<Vec<u8>> {
        let requests = self.requests()?;
        if admissions.len() != requests.len() {
            return Err(Error::Permission);
        }
        let mut seen = BTreeSet::new();
        let mut records = Vec::new();
        for admission in admissions {
            let request = admission.binding();
            if !seen.insert(request.continuity.account_id.clone())
                || !requests.contains(request)
                || admission
                    .evidence()
                    .digest()
                    .map_err(|_| Error::Authentication)?
                    != request.continuity_evidence_digest
            {
                return Err(Error::Permission);
            }
            records.push(admission.into_audit_record());
        }
        records.sort_by(|a, b| {
            a.request
                .continuity
                .account_id
                .cmp(&b.request.continuity.account_id)
        });
        let p = &self.generation.pending;
        let commit = Commit {
            version: 1,
            plan_digest: p.plan_digest.clone(),
            manifest_digest: self.manifest_digest.clone(),
            admissions: records,
        };
        let bytes = seal(&p.secrets, b"commit", &encode(&commit)?)?;
        p.source.check()?;
        p.directory.check()?;
        p.check_inventory()?;
        if p.directory.read(MANIFEST, MAX_DOCUMENT).map(|b| hash(&b))? != commit.manifest_digest {
            return Err(Error::Authentication);
        }
        drop(open_layered_checked(
            &p.directory,
            &p.secrets,
            &bytes,
            true,
        )?);
        Ok(bytes)
    }
}

impl PreparedLayeredPublication {
    pub(crate) fn publish(
        self,
        admissions: Vec<HostRecoveryPublicationAdmission>,
        approval: crate::terminal::PublicationApproval,
    ) -> Result<()> {
        approval.commit(
            &self.manifest_digest,
            || self.prepare_commit(admissions),
            |bytes| self.generation.pending.directory.write_new(COMMIT, &bytes),
        )
    }
    #[cfg(test)]
    pub(crate) fn publish_synthetic_empty_accounts(self) -> Result<()> {
        // Synthetic storage-only qualification, never native approval evidence.
        if !self.manifest.continuity.is_empty() {
            return Err(Error::Permission);
        }
        let bytes = self.prepare_commit(vec![])?;
        self.generation.pending.directory.write_new(COMMIT, &bytes)
    }
}

pub(super) fn open_layered_checked(
    directory: &Directory,
    secrets: &Secrets,
    commit_bytes: &[u8],
    unpublished: bool,
) -> Result<wholepact_store::Store> {
    secrets.require_portable_legacy()?;
    directory.refuse_private_workspace_files()?;
    open_layered_checked_inner(
        directory,
        secrets,
        commit_bytes,
        unpublished,
        WorkspaceInventory::Legacy,
    )
}
// Only nominal authenticated own-file proofs can select the private originals.
enum WorkspaceInventory<'a> {
    Legacy,
    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    Original(&'a crate::host::durable_private_workspace_v1::OriginalWorkspaceFilesV1),
    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    Publication(&'a crate::host::durable_private_workspace_v1::OriginalWorkspacePublicationV1),
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    CombinedOriginal(&'a crate::host::durable_dispatcher_v2::OriginalWorkspaceDispatcherFilesV4),
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
    CombinedPublication(&'a crate::host::durable_dispatcher_v2::OriginalWorkspaceDispatcherPublicationV4),
    // Retain the lifetime in unsupported configurations without a usable variant.
    #[cfg(not(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    )))]
    _Unavailable(std::marker::PhantomData<&'a ()>),
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) fn open_private_workspace_original_store_v1(
    directory: &Directory,
    secrets: &Secrets,
    files: &crate::host::durable_private_workspace_v1::OriginalWorkspaceFilesV1,
) -> Result<wholepact_store::Store> {
    open_layered_checked_inner(
        directory,
        secrets,
        &directory.read(COMMIT, MAX_DOCUMENT)?,
        false,
        WorkspaceInventory::Original(files),
    )
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) fn open_workspace_publication_source_store_v1(
    directory: &Directory,
    secrets: &Secrets,
    files: &crate::host::durable_private_workspace_v1::OriginalWorkspacePublicationV1,
) -> Result<wholepact_store::Store> {
    open_layered_checked_inner(
        directory,
        secrets,
        &directory.read(COMMIT, MAX_DOCUMENT)?,
        false,
        WorkspaceInventory::Publication(files),
    )
}
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
pub(crate) fn open_workspace_dispatcher_original_store_v4(directory: &Directory, secrets: &Secrets, files: &crate::host::durable_dispatcher_v2::OriginalWorkspaceDispatcherFilesV4) -> Result<wholepact_store::Store> {
    // Preflight is before verify_auxiliaries or any maintained mutable constructor.
    let submission = files.submission_preflight(directory, secrets)?;
    let result = open_layered_checked_inner(directory, secrets, &directory.read(COMMIT, MAX_DOCUMENT)?, false, WorkspaceInventory::CombinedOriginal(files))?;
    submission.check_identity_only()?;
    Ok(result)
}
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
pub(crate) fn open_dispatcher_publication_source_store_v4(directory: &Directory, secrets: &Secrets, files: &crate::host::durable_dispatcher_v2::OriginalWorkspaceDispatcherPublicationV4) -> Result<wholepact_store::Store> {
    // Preflight is before verify_auxiliaries or any maintained mutable constructor.
    let submission = files.submission_preflight(directory, secrets)?;
    let result = open_layered_checked_inner(directory, secrets, &directory.read(COMMIT, MAX_DOCUMENT)?, false, WorkspaceInventory::CombinedPublication(files))?;
    submission.check_identity_only()?;
    Ok(result)
}
fn open_layered_checked_inner(
    directory: &Directory,
    secrets: &Secrets,
    commit_bytes: &[u8],
    unpublished: bool,
    inventory: WorkspaceInventory<'_>,
) -> Result<wholepact_store::Store> {
    let commit_plain = unseal(secrets, b"commit", commit_bytes)?;
    let version = complete_origins::metadata_version(&commit_plain)?;
    match &inventory {
        WorkspaceInventory::Legacy => {
            if !unpublished && matches!(version, 3..=5) {
                return Err(Error::RecoveryFinancialUnsupported);
            }
        }
        #[cfg(all(
            feature = "durable-proposal",
            feature = "manual-admission",
            target_os = "linux"
        ))]
        WorkspaceInventory::Original(files) => {
            if !matches!(version, 1 | 2 | 4) {
                return Err(Error::RecoveryFinancialUnsupported);
            }
            files.check_inventory(directory, secrets)?;
        }
        #[cfg(all(
            feature = "durable-proposal",
            feature = "manual-admission",
            target_os = "linux"
        ))]
        WorkspaceInventory::Publication(files) => {
            if !matches!(version, 1 | 2 | 4) {
                return Err(Error::RecoveryFinancialUnsupported);
            }
            files.check_inventory(directory, secrets)?;
        }
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
        WorkspaceInventory::CombinedOriginal(files) => {
            if !matches!(version, 1 | 2 | 4) { return Err(Error::RecoveryFinancialUnsupported); }
            files.check_inventory(directory, secrets)?;
        }
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
        WorkspaceInventory::CombinedPublication(files) => {
            if !matches!(version, 1 | 2 | 4) { return Err(Error::RecoveryFinancialUnsupported); }
            files.check_inventory(directory, secrets)?;
        }
        #[cfg(not(all(
            feature = "durable-proposal",
            feature = "manual-admission",
            target_os = "linux"
        )))]
        WorkspaceInventory::_Unavailable(_) => return Err(Error::Unsupported),
    }
    let path = directory.path("profile.vault")?;
    let metadata = layered_metadata::checked_layered_metadata_bytes(
        path.parent().ok_or(Error::Invalid)?,
        secrets,
        &directory.read(PLAN, MAX_DOCUMENT)?,
        &directory.read(MANIFEST, MAX_DOCUMENT)?,
        commit_bytes,
        &directory.read("generation.keys", MAX_DOCUMENT)?,
    )?;
    if matches!(inventory, WorkspaceInventory::Legacy) {
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
    )?;
    }
    let parent_key = DatabaseKey::from_bytes(
        metadata
            .parent_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Authentication)?,
    );
    let parent = VerifiedGenerationCapsule::open(generation_archive::inspect(
        &directory.path("history.capsule.sqlite")?,
        &parent_key,
    )?)?;
    metadata.plan.verify_parent(&parent)?;
    let historical_coordination =
        wholepact_engine::recovery::inspect_archived_coordination_recovery(
            parent.root().current_coordination(),
        )?;
    super::complete_origins::validate_store_manifest_dispatch(
        &unseal(
            secrets,
            b"manifest",
            &directory.read(MANIFEST, MAX_DOCUMENT)?,
        )?,
        historical_coordination.store_inventory(),
    )?;
    let provenance = parent.root().current_coordination().source_provenance();
    // Authenticate the complete owner overlay and immutable lineage before any
    // live SQLite handle is allocated under the exclusive directory lock.
    let snapshot = wholepact_store::recovery::RecoveredStoreSnapshot::open(
        &directory.path("coordination.sqlite")?,
        &secrets.key(0)?,
        &metadata.binding,
        provenance,
    )?;
    snapshot.verify_recovery_obligation_fences(&metadata.restrictions)?;
    drop(snapshot);
    verify_auxiliaries(directory, secrets, unpublished)?;
    let store = wholepact_store::Store::open_recovered_generation(
        &directory.path("coordination.sqlite")?,
        &secrets.key(0)?,
        &metadata.binding,
        provenance,
    )?;
    store.verify_recovery_obligation_fences(&metadata.binding, &metadata.restrictions)?;
    directory.check()?;
    Ok(store)
}
