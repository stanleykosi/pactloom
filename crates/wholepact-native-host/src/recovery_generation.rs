//! Host-owned encrypted generation protocol. Storage generation proofs establish
//! integrity, not native authority. Only this private composition may publish a
//! host generation after exact, separately reviewed signer admissions.
use crate::{Error, Result, files::Directory, recovery_inventory::Inventory, vault::Secrets};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::PathBuf};
use wholepact_storage_security::bundle::recovery::RecoveryProvenance;
use zeroize::Zeroizing;

const MAX_DOCUMENT: usize = 16 * 1024 * 1024;
const PLAN: &str = "recovery.plan";
const MANIFEST: &str = "generation.manifest";
const COMMIT: &str = "generation.commit";

/// Persisted metadata is audit data. No Deserialize implementation on the owning
/// PendingGeneration/CommittedGeneration capabilities is provided.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u16,
    generation_id: String,
    inventory_digest: String,
    target: PathBuf,
    source_profile: String,
    successor_profile: String,
    components: Vec<RecoveryProvenance>,
    affected_accounts: BTreeSet<String>,
    semantic_inventory_digest: String,
    unknown_external_signatures: bool,
    recovered_obligations_fenced: bool,
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn canonical_hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(serde_json::to_vec(value)?);
    if bytes.len() > MAX_DOCUMENT {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}
fn seal(secrets: &Secrets, purpose: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
    let mut domain = b"wholepact:restricted-host-generation:v1\0".to_vec();
    domain.extend(secrets.profile().as_bytes());
    domain.extend(purpose);
    let cipher = XChaCha20Poly1305::new_from_slice(&*secrets.generation_seal_key()?)
        .map_err(|_| Error::Storage)?;
    let nonce = crate::random::<24>()?;
    let mut output = nonce.to_vec();
    output.extend(
        cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: bytes,
                    aad: &domain,
                },
            )
            .map_err(|_| Error::Storage)?,
    );
    if output.len() > MAX_DOCUMENT {
        return Err(Error::Invalid);
    }
    Ok(output)
}
fn unseal(secrets: &Secrets, purpose: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() < 40 || bytes.len() > MAX_DOCUMENT {
        return Err(Error::Invalid);
    }
    let mut domain = b"wholepact:restricted-host-generation:v1\0".to_vec();
    domain.extend(secrets.profile().as_bytes());
    domain.extend(purpose);
    let cipher = XChaCha20Poly1305::new_from_slice(&*secrets.generation_seal_key()?)
        .map_err(|_| Error::Storage)?;
    cipher
        .decrypt(
            &XNonce::try_from(&bytes[..24]).map_err(|_| Error::Invalid)?,
            Payload {
                msg: &bytes[24..],
                aad: &domain,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

/// Fixed-purpose wrappers only. No caller-selected crypto domain is exposed.
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) fn seal_private_workspace_dependency_v1(
    secrets: &Secrets,
    pending: bool,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    if bytes.len() > 131_072 {
        return Err(Error::Invalid);
    }
    seal(
        secrets,
        if pending {
            b"durable-private:pending:v1"
        } else {
            b"durable-private:commit:v1"
        },
        bytes,
    )
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) fn unseal_private_workspace_dependency_v1(
    secrets: &Secrets,
    pending: bool,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() > 131_112 {
        return Err(Error::Invalid);
    }
    let plain = unseal(
        secrets,
        if pending {
            b"durable-private:pending:v1"
        } else {
            b"durable-private:commit:v1"
        },
        bytes,
    )?;
    if plain.len() > 131_072 {
        return Err(Error::Invalid);
    }
    Ok(plain)
}

pub(crate) struct PendingGeneration {
    source: Inventory,
    directory: Directory,
    secrets: Secrets,
    plan: Plan,
    plan_digest: String,
    evidence_keys: Zeroizing<Vec<u8>>,
}

impl PendingGeneration {
    /// Called only after the complete typed semantic inventory and native review.
    /// The encrypted plan is durable before constructing any successor journal or
    /// contacting a signer for publication. An interrupted target is never adopted
    /// merely because its path exists.
    pub(crate) fn create(inventory: Inventory, password: &[u8]) -> Result<Self> {
        inventory.check()?;
        let semantic = crate::recovery_semantics::inspect(&inventory)?;
        let semantic_inventory_digest = semantic.digest().to_owned();
        canonical_hash(&semantic_inventory_digest)?;
        let affected_accounts = semantic
            .accounts()
            .union(inventory.known_account_ids())
            .cloned()
            .collect::<BTreeSet<_>>();
        for account in &affected_accounts {
            crate::id(account)?;
        }
        let secrets = Secrets::fresh()?;
        let plan = Plan {
            version: 1,
            generation_id: inventory.generation_id().into(),
            inventory_digest: inventory.digest()?,
            target: inventory.successor().into(),
            source_profile: inventory.profile_id().into(),
            successor_profile: secrets.profile(),
            components: inventory
                .components()
                .iter()
                .map(|c| c.provenance().clone())
                .collect(),
            affected_accounts,
            semantic_inventory_digest,
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
        };
        let plain = encode(&plan)?;
        let digest: [u8; 32] = Sha256::digest(&plain).into();
        let secrets = secrets.bind_successor_plan(digest)?;
        // Prepare ciphertext before the first target write; no plaintext journal
        // key or private historical record is written outside encrypted storage.
        let vault = secrets.seal(password)?;
        let encrypted = seal(&secrets, b"plan", &plain)?;
        let mut evidence_keys = Zeroizing::new(vec![0u8; plan.components.len() * 32]);
        getrandom::fill(&mut evidence_keys).map_err(|_| Error::Storage)?;
        let key_purpose = [b"keys:".as_slice(), hex::encode(digest).as_bytes()].concat();
        let wrapped_keys = seal(&secrets, &key_purpose, &evidence_keys)?;
        inventory.check()?;
        let directory = Directory::create(inventory.successor())?;
        directory.write_new("profile.vault", &vault)?;
        directory.write_new(PLAN, &encrypted)?;
        directory.write_new("generation.keys", &wrapped_keys)?;
        Ok(Self {
            source: inventory,
            directory,
            secrets,
            plan,
            plan_digest: hex::encode(digest),
            evidence_keys,
        })
    }

    /// Authenticate the pending generation identifier before reopening original
    /// history for an exact retry. This creates no authority and retains no key.
    pub(crate) fn pending_identifier(target: &std::path::Path, password: &[u8]) -> Result<String> {
        let directory = Directory::open(target)?;
        let secrets = Secrets::open(&directory.read("profile.vault", 1024)?, password)?;
        let bytes = unseal(&secrets, b"plan", &directory.read(PLAN, MAX_DOCUMENT)?)?;
        let plan: Plan = serde_json::from_slice(&bytes)?;
        if secrets.generation_plan_digest() != Some(Sha256::digest(&bytes).as_slice())
            || plan.target != target
            || plan.successor_profile != secrets.profile()
            || directory.path(COMMIT)?.try_exists()?
        {
            return Err(Error::Authentication);
        }
        canonical_hash(&plan.generation_id)?;
        Ok(plan.generation_id)
    }

    /// Resume only the same authenticated plan with the original immutable
    /// inventory held. Missing/partial plan, changed target, or different keys is
    /// a hard error, not a reason to regenerate the plan or erase partial output.
    pub(crate) fn resume(inventory: Inventory, password: &[u8]) -> Result<Self> {
        inventory.check()?;
        let directory = Directory::open(inventory.successor())?;
        let secrets = Secrets::open(&directory.read("profile.vault", 1024)?, password)?;
        let plain = unseal(&secrets, b"plan", &directory.read(PLAN, MAX_DOCUMENT)?)?;
        let plan: Plan = serde_json::from_slice(&plain)?;
        let plan_digest = hash(&plain);
        if secrets.generation_plan_digest() != Some(Sha256::digest(&plain).as_slice())
            || plan.version != 1
            || !plan.unknown_external_signatures
            || !plan.recovered_obligations_fenced
            || plan.generation_id != inventory.generation_id()
            || plan.inventory_digest != inventory.digest()?
            || plan.target != inventory.successor()
            || plan.source_profile != inventory.profile_id()
            || plan.successor_profile != secrets.profile()
            || plan.components
                != inventory
                    .components()
                    .iter()
                    .map(|c| c.provenance().clone())
                    .collect::<Vec<_>>()
            || !inventory
                .known_account_ids()
                .is_subset(&plan.affected_accounts)
            || directory.path(COMMIT)?.try_exists()?
        {
            return Err(Error::Authentication);
        }
        canonical_hash(&plan.semantic_inventory_digest)?;
        let semantic = crate::recovery_semantics::inspect(&inventory)?;
        if semantic.digest() != plan.semantic_inventory_digest
            || semantic.accounts() != &plan.affected_accounts
        {
            return Err(Error::Authentication);
        }
        for account in &plan.affected_accounts {
            crate::id(account)?;
        }
        let key_purpose = [b"keys:".as_slice(), plan_digest.as_bytes()].concat();
        let evidence_keys = unseal(
            &secrets,
            &key_purpose,
            &directory.read("generation.keys", MAX_DOCUMENT)?,
        )?;
        if evidence_keys.len() != plan.components.len() * 32 {
            return Err(Error::Authentication);
        }
        Ok(Self {
            source: inventory,
            directory,
            secrets,
            plan,
            plan_digest,
            evidence_keys,
        })
    }

    pub(crate) fn evidence_key(
        &self,
        index: usize,
    ) -> Result<wholepact_storage_security::DatabaseKey> {
        let start = index.checked_mul(32).ok_or(Error::Invalid)?;
        let bytes = self
            .evidence_keys
            .get(start..start + 32)
            .ok_or(Error::Invalid)?;
        Ok(wholepact_storage_security::DatabaseKey::from_bytes(
            bytes.try_into().map_err(|_| Error::Invalid)?,
        ))
    }
    pub(crate) fn generation_id(&self) -> &str {
        &self.plan.generation_id
    }
    pub(crate) fn inventory_digest(&self) -> &str {
        &self.plan.inventory_digest
    }

    fn check_inventory(&self) -> Result<()> {
        let mut journals = crate::vault::JOURNALS
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>();
        journals.extend(
            self.plan
                .components
                .iter()
                .map(|c| format!("history-{}.sqlite", c.component_id)),
        );
        self.directory.inventory_of(
            &journals.iter().map(String::as_str).collect::<Vec<_>>(),
            &[
                "profile.lock",
                "profile.vault",
                PLAN,
                MANIFEST,
                "generation.keys",
            ],
        )
    }

    fn binding(
        &self,
    ) -> Result<wholepact_storage_security::bundle::recovery::generation::GenerationBinding> {
        Ok(
            wholepact_storage_security::bundle::recovery::generation::GenerationBinding::new(
                self.generation_id(),
                self.inventory_digest(),
            )?,
        )
    }

    /// Construct immutable history separately from live queues. No old proof job,
    /// dispatch intent, transport retry, or observer report enters a runnable
    /// auxiliary journal. The coordination transition retains explicit fences.
    pub(crate) fn construct(self) -> Result<ConstructedGeneration> {
        use wholepact_storage_security::bundle::JournalKind;
        self.source.check()?;
        self.check_inventory()?;
        let binding = self.binding()?;
        for (index, source) in self.source.components().iter().enumerate() {
            let path = self.directory.path(&format!(
                "history-{}.sqlite",
                source.provenance().component_id
            ))?;
            let key = self.evidence_key(index)?;
            match source.provenance().kind {
                JournalKind::CoordinationAuthority => {
                    wholepact_store::bundle::reconstruct_coordination_successor_evidence(source, &path, &key, &binding)?;
                    wholepact_store::Store::reconstruct_recovered_generation(source,
                        &self.directory.path(crate::vault::JOURNALS[0])?, &self.secrets.key(0)?, &binding)?;
                }
                JournalKind::TransportInbox => wholepact_transport::bundle::reconstruct_inbox_successor_evidence(source, &path, &key, &binding)?,
                JournalKind::TransportOutbox => wholepact_transport::bundle::reconstruct_outbox_successor_evidence(source, &path, &key, &binding)?,
                JournalKind::Submission => wholepact_chain::backup::reconstruct_submission_successor_evidence(source, &path, &key, &binding)?,
                #[cfg(feature = "financial-runtime")]
                JournalKind::WalletScan => wholepact_wallet::bundle::recovery::reconstruct_wallet_scan_successor_evidence(source, &path, &key, &binding)?,
                #[cfg(feature = "financial-runtime")]
                JournalKind::ProofWitness => wholepact_proof_jobs::backup::reconstruct_proof_successor_evidence(source, &path, &key, &binding)?,
                #[cfg(feature = "financial-runtime")]
                JournalKind::SignedResults => wholepact_protocol::authorization::retention::backup::reconstruct_signed_results_successor_evidence(source, &path, &key, &binding)?,
                #[cfg(feature = "financial-runtime")]
                JournalKind::ExactTransactions => wholepact_protocol::authorization::retention::transaction::backup::reconstruct_transactions_successor_evidence(source, &path, &key, &binding)?,
                _ => return Err(Error::Unsupported),
            }
        }
        // Existing retries must still be empty and use the exact persisted keys.
        // A response-loss retry never adopts an unrelated runtime or discards work.
        for index in 1..4 {
            let path = self.directory.path(crate::vault::JOURNALS[index])?;
            let key = self.secrets.key(index)?;
            let connection = if path.try_exists()? {
                match wholepact_storage_security::open_encrypted_quiescent(&path, &key) {
                    Ok(connection) => connection,
                    Err(wholepact_storage_security::StorageSecurityError::UninitializedDatabase) => {
                        wholepact_storage_security::bundle::recovery::generation::PlannedEmptyInitialization::new(&binding, &path, &key)?.resume(&path, &key, &binding)?
                    }
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
            let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(&path, &key)?;
            let c = snapshot.connection();
            let tables: &[&str] = match index {
                1 => &["receipts", "domain_imports"],
                2 => &["outbox"],
                3 => &[
                    "submission_intents",
                    "submission_bindings",
                    "submission_attempts",
                    "submission_observations",
                    "settlement_evidence",
                    "settlement_deliveries",
                ],
                _ => return Err(Error::Invalid),
            };
            for table in tables {
                let count: i64 = c
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                    .map_err(|_| Error::Storage)?;
                if count != 0 {
                    return Err(Error::Authentication);
                }
            }
        }
        self.source.check()?;
        self.directory.check()?;
        Ok(ConstructedGeneration { pending: self })
    }
}

fn verify_auxiliaries(directory: &Directory, secrets: &Secrets, require_empty: bool) -> Result<()> {
    for index in 1..4 {
        let path = directory.path(crate::vault::JOURNALS[index])?;
        let key = secrets.key(index)?;
        let connection = wholepact_storage_security::open_encrypted_quiescent(&path, &key)?;
        match index {
            1 => drop(
                wholepact_transport::SqliteReplayLedger::from_encrypted_connection(connection)?,
            ),
            2 => drop(wholepact_transport::SqliteOutbox::from_encrypted_connection(connection)?),
            3 => drop(
                wholepact_chain::EncryptedSubmissionJournal::from_encrypted_connection(connection)?,
            ),
            _ => return Err(Error::Invalid),
        }
        if require_empty {
            let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(&path, &key)?;
            let tables: &[&str] = match index {
                1 => &["receipts", "domain_imports"],
                2 => &["outbox"],
                3 => &[
                    "submission_intents",
                    "submission_bindings",
                    "submission_attempts",
                    "submission_observations",
                    "settlement_evidence",
                    "settlement_deliveries",
                ],
                _ => return Err(Error::Invalid),
            };
            for table in tables {
                let count: i64 = snapshot
                    .connection()
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                    .map_err(|_| Error::Storage)?;
                if count != 0 {
                    return Err(Error::Authentication);
                }
            }
        }
    }
    Ok(())
}

pub(crate) struct ConstructedGeneration {
    pending: PendingGeneration,
}

#[cfg(feature = "financial-runtime")]
#[allow(dead_code)]
mod retired_information;

#[cfg(feature = "financial-runtime")]
mod publication {
    use super::*;
    use wholepact_signer::authority_bridge::{
        host_publication_ipc::{
            HostRecoveryPublicationAdmission, HostRecoveryPublicationRecord,
            HostRecoveryPublicationRequest,
        },
        host_recovery_ipc::HostRecoveryContinuityEvidence,
    };

    #[derive(Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        version: u16,
        plan_digest: String,
        continuity: Vec<HostRecoveryContinuityEvidence>,
        unmatched_host_authorizations: BTreeSet<String>,
        // These are mandatory facts, not configurable policy switches.
        unknown_external_signatures: bool,
        recovered_obligations_fenced: bool,
        financial_freshness_established: bool,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Commit {
        version: u16,
        plan_digest: String,
        manifest_digest: String,
        admissions: Vec<HostRecoveryPublicationRecord>,
    }

    pub(crate) struct PreparedPublication {
        generation: ConstructedGeneration,
        manifest: Manifest,
        manifest_digest: String,
    }
    impl ConstructedGeneration {
        /// All leases must be released before the distinct signer publication
        /// reviews. Persist only their audit evidence, never a saved permission.
        pub(crate) fn prepare_publication(
            self,
            mut continuity: Vec<HostRecoveryContinuityEvidence>,
        ) -> Result<PreparedPublication> {
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
            let coordination = p
                .source
                .components()
                .iter()
                .find(|c| c.provenance().component_id == "coordination")
                .ok_or(Error::Invalid)?;
            let cross_journal = crate::recovery_semantics::inspect(&p.source)?;
            let semantic = wholepact_engine::recovery::inspect_coordination_recovery(coordination)?;
            if cross_journal.digest() != p.plan.semantic_inventory_digest {
                return Err(Error::Authentication);
            }
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
                coordination.provenance(),
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
            Ok(PreparedPublication {
                generation: self,
                manifest,
                manifest_digest: hash(&bytes),
            })
        }
    }
    impl PreparedPublication {
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
                        continuity_evidence_digest: e
                            .digest()
                            .map_err(|_| Error::Authentication)?,
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
        fn prepare_commit(
            &self,
            admissions: Vec<HostRecoveryPublicationAdmission>,
        ) -> Result<Vec<u8>> {
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
            if p.directory.read(MANIFEST, MAX_DOCUMENT).map(|b| hash(&b))? != commit.manifest_digest
            {
                return Err(Error::Authentication);
            }
            drop(open_checked(&p.directory, &p.secrets, &commit, true)?);
            Ok(bytes)
        }
    }

    impl PreparedPublication {
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

    /// Authenticates the vault's permanent plan anchor, exact final admission
    /// records, every immutable evidence component and the Store-owned runtime
    /// overlay. This never upgrades recorded signer observations to current ones.
    pub(crate) fn open_committed(
        directory: &Directory,
        secrets: &Secrets,
    ) -> Result<wholepact_store::Store> {
        secrets.require_portable_legacy()?;
        directory.refuse_private_workspace_files()?;
        // Authenticated format dispatch never falls back to ordinary Store
        // initialization. Missing/tampered markers remain a hard error.
        if archive_history::source_plan_version(directory, secrets)? == 2 {
            return open_layered_committed(directory, secrets);
        }
        let plain = unseal(secrets, b"commit", &directory.read(COMMIT, MAX_DOCUMENT)?)?;
        match complete_origins::metadata_version(&plain)? {
            1 => open_checked(
                directory,
                secrets,
                &serde_json::from_slice::<Commit>(&plain)?,
                false,
            ),
            2 => complete_origins::open_checked_v2(
                directory,
                secrets,
                &serde_json::from_slice::<complete_origins::CommitV2>(&plain)?,
                false,
            ),
            3 => construction_origins::open_checked_v3(
                directory,
                secrets,
                &serde_json::from_slice::<construction_origins::CommitV3>(&plain)?,
                false,
            ),
            4 => common_context_origins::open_checked_v4(
                directory,
                secrets,
                &serde_json::from_slice::<common_context_origins::CommitV4>(&plain)?,
                false,
            ),
            5 => Err(Error::Unsupported), // V5 informational recovery never activates financial Store access.
            _ => Err(Error::Unsupported),
        }
    }
    // Dedicated typed layered opener after strict anchored format dispatch.
    pub(crate) fn open_layered_committed(
        directory: &Directory,
        secrets: &Secrets,
    ) -> Result<wholepact_store::Store> {
        layered_publication::open_layered_checked(
            directory,
            secrets,
            &directory.read(COMMIT, MAX_DOCUMENT)?,
            false,
        )
    }
    struct CheckedMetadata {
        plan: Plan,
        binding: wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
        evidence_keys: Zeroizing<Vec<u8>>,
        manifest_digest: String,
        restrictions: BTreeSet<String>,
    }

    fn checked_metadata(
        directory: &Directory,
        secrets: &Secrets,
        commit: &Commit,
    ) -> Result<CheckedMetadata> {
        checked_metadata_bytes(
            directory
                .path("profile.vault")?
                .parent()
                .ok_or(Error::Invalid)?,
            secrets,
            commit,
            &directory.read(PLAN, MAX_DOCUMENT)?,
            &directory.read(MANIFEST, MAX_DOCUMENT)?,
            &directory.read("generation.keys", MAX_DOCUMENT)?,
        )
    }

    // Both directory and archive readers authenticate exactly the original
    // target. Relocation never rewrites a saved plan or signer admission.
    fn checked_metadata_bytes(
        original_target: &std::path::Path,
        secrets: &Secrets,
        commit: &Commit,
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
        let manifest: Manifest =
            serde_json::from_slice(&unseal(secrets, b"manifest", manifest_bytes)?)?;
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
        let mut admitted = BTreeSet::new();
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
        for record in &commit.admissions {
            record.validate().map_err(|_| Error::Authentication)?;
            let request = &record.request;
            let evidence = manifest
                .continuity
                .iter()
                .find(|e| e.request == request.continuity)
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
        check_component_inventory(&plan)?;
        let keys = unseal(
            secrets,
            &[b"keys:".as_slice(), plan_digest.as_bytes()].concat(),
            sealed_keys,
        )?;
        if keys.len() != plan.components.len() * 32 {
            return Err(Error::Authentication);
        }
        let binding =
            wholepact_storage_security::bundle::recovery::generation::GenerationBinding::new(
                &plan.generation_id,
                &plan.inventory_digest,
            )?;
        let restrictions = manifest
            .continuity
            .iter()
            .flat_map(|e| {
                e.conservative_permits
                    .iter()
                    .map(|p| p.request.obligation_id.clone())
            })
            .collect();
        Ok(CheckedMetadata {
            plan,
            binding,
            evidence_keys: keys,
            manifest_digest: commit.manifest_digest.clone(),
            restrictions,
        })
    }

    fn check_component_inventory(plan: &Plan) -> Result<()> {
        use wholepact_storage_security::bundle::JournalKind;
        crate::id(&plan.source_profile)?;
        crate::id(&plan.successor_profile)?;
        for account in &plan.affected_accounts {
            crate::id(account)?;
        }
        let count = plan
            .components
            .iter()
            .filter(|c| c.kind == JournalKind::WalletScan)
            .count();
        if count > 12 || plan.components.len() != 4 + 4 * count {
            return Err(Error::Authentication);
        }
        let coverage = crate::financial_backup::coverage(count);
        let expected: BTreeSet<_> = coverage
            .present
            .into_iter()
            .flat_map(|(kind, ids)| ids.into_iter().map(move |id| (id, kind)))
            .collect();
        let actual: BTreeSet<_> = plan
            .components
            .iter()
            .map(|c| (c.component_id.clone(), c.kind))
            .collect();
        if actual != expected
            || actual.len() != plan.components.len()
            || plan
                .components
                .iter()
                .any(|c| c.profile_id != plan.source_profile)
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    fn read_evidence(
        directory: &Directory,
        metadata: &CheckedMetadata,
    ) -> Result<Vec<wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence>>
    {
        let mut result = Vec::with_capacity(metadata.plan.components.len());
        let binding = &metadata.binding;
        for (index, expected) in metadata.plan.components.iter().enumerate() {
            let name = format!("history-{}.sqlite", expected.component_id);
            let path = directory.path(&name)?;
            let key = wholepact_storage_security::DatabaseKey::from_bytes(
                metadata.evidence_keys[index * 32..(index + 1) * 32]
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            );
            use wholepact_storage_security::bundle::JournalKind;
            let evidence = match expected.kind {
                JournalKind::CoordinationAuthority if expected.component_id == "coordination" => {
                    wholepact_store::bundle::open_coordination_successor_evidence(&path, &key, binding, expected)?
                }
                JournalKind::TransportInbox => wholepact_transport::bundle::open_inbox_successor_evidence(&path, &key, binding, expected)?,
                JournalKind::TransportOutbox => wholepact_transport::bundle::open_outbox_successor_evidence(&path, &key, binding, expected)?,
                JournalKind::Submission => wholepact_chain::backup::open_submission_successor_evidence(&path, &key, binding, expected)?,
                JournalKind::WalletScan => wholepact_wallet::bundle::recovery::open_wallet_scan_successor_evidence(&path, &key, binding, expected)?,
                JournalKind::ProofWitness => wholepact_proof_jobs::backup::open_proof_successor_evidence(&path, &key, binding, expected)?,
                JournalKind::SignedResults => wholepact_protocol::authorization::retention::backup::open_signed_results_successor_evidence(&path, &key, binding, expected)?,
                JournalKind::ExactTransactions => wholepact_protocol::authorization::retention::transaction::backup::open_transactions_successor_evidence(&path, &key, binding, expected)?,
                _ => return Err(Error::Unsupported),
            };
            result.push(evidence);
        }
        Ok(result)
    }

    fn check_directory_inventory(directory: &Directory, plan: &Plan) -> Result<()> {
        let mut journal_names = crate::vault::JOURNALS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        journal_names.extend(
            plan.components
                .iter()
                .map(|c| format!("history-{}.sqlite", c.component_id)),
        );
        directory.inventory_of(
            &journal_names.iter().map(String::as_str).collect::<Vec<_>>(),
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

    fn open_checked(
        directory: &Directory,
        secrets: &Secrets,
        commit: &Commit,
        unpublished: bool,
    ) -> Result<wholepact_store::Store> {
        let metadata = checked_metadata(directory, secrets, commit)?;
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

    pub(crate) mod archive_history;
    mod common_context_origins;
    mod complete_origins;
    mod construction_origins;
    mod retained_continuity;
    #[cfg(all(test, feature = "manual-admission", target_os = "linux"))]
    pub(super) mod retained_continuity_fixture;
    mod transport_origins;
    #[cfg(all(test, feature = "manual-admission"))]
    pub(crate) use common_context_origins::capsule_fixtures as common_context_capsule_fixtures;
    #[cfg(test)]
    pub(crate) use construction_origins::capsule_fixtures as construction_capsule_fixtures;
    #[cfg(all(test, feature = "manual-admission", target_os = "linux"))]
    pub(crate) use transport_origins::capsule_fixtures as transport_capsule_fixtures;
    mod history;
    pub(crate) mod inherited_manual_identity;
    pub(crate) mod layered_metadata;
    mod layered_publication;
    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    pub(crate) use layered_publication::{
        open_private_workspace_original_store_v1, open_workspace_publication_source_store_v1,
    };
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    pub(crate) mod manual_target;
    #[cfg(all(test, target_os = "linux"))]
    mod tests;
    pub(crate) use history::{CommittedHistory, open_committed_history};
}

#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) use publication::{
    open_private_workspace_original_store_v1, open_workspace_publication_source_store_v1,
};

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) use publication::manual_target;

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) mod construction_inspection_target;
#[cfg(feature = "financial-runtime")]
pub(crate) use publication::{CommittedHistory, open_committed, open_committed_history};
#[cfg(feature = "financial-runtime")]
pub(crate) use publication::{archive_history, layered_metadata};
#[cfg(feature = "financial-runtime")]
pub(crate) mod layered;
#[cfg(feature = "financial-runtime")]
pub(crate) mod layered_activate;

/// Foreground-only composition. Each peer pairing and account-wide disclosure
/// still requires the independently installed signer's native approval.
#[cfg(feature = "financial-runtime")]
pub(crate) fn activate(
    terminal: crate::terminal::Terminal,
    profile: &std::path::Path,
    backup: &std::path::Path,
    successor: &std::path::Path,
    resume: bool,
) -> Result<()> {
    use std::time::{Duration, Instant};
    use wholepact_signer::authority_bridge::provider::InstalledSignerProvider;
    use wholepact_signer::{
        authority_bridge::{
            host_recovery_ipc::HostRecoveryContinuityRequest, ipc::OriginalHistoryClient,
        },
        ipc::PairScope,
    };
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Signer {
        socket: PathBuf,
        account_id: String,
        network_profile_id: String,
        writer_epoch: u64,
        witness: wholepact_authority::WitnessDisclosureDescriptor,
    }
    terminal.confirm(&format!("READ HISTORICAL PRIVATE DATA and prepare a separately encrypted restricted successor. Read every original wallet, proof, signature, transaction, transport and observation row. Originals stay immutable. Restored profile: {}. Original backup: {}. Target: {}. This does not approve signer disclosure, signing, submission, old permits, or renewed financial confidence.", profile.display(), backup.display(), successor.display()))?;
    let expires = Instant::now() + Duration::from_secs(300);
    let restored_password = terminal.secret("Restored profile passphrase: ")?;
    let backup_password = terminal.secret("Original backup passphrase: ")?;
    let target_password = terminal.secret(if resume {
        "Pending successor passphrase: "
    } else {
        "New successor storage passphrase: "
    })?;
    if !resume && *target_password != *terminal.secret("Repeat successor passphrase: ")? {
        return Err(Error::Authentication);
    }
    let generation = if resume {
        PendingGeneration::pending_identifier(successor, target_password.as_bytes())?
    } else {
        hex::encode(crate::random::<32>()?)
    };
    let inventory = if resume {
        crate::recovery_inventory::prepare_for_resume(
            profile,
            backup,
            successor,
            generation,
            restored_password.as_bytes(),
            backup_password.as_bytes(),
            expires,
        )?
    } else {
        crate::recovery_inventory::prepare(
            profile,
            backup,
            successor,
            generation,
            restored_password.as_bytes(),
            backup_password.as_bytes(),
            expires,
        )?
    };
    drop(restored_password);
    drop(backup_password);
    terminal.confirm(&format!("Construct exact restricted generation {} for inventory {} at {}. All recovered obligations and grants remain fenced; old proof, dispatch and observation queues are historical only. Fresh host storage/transport keys and fresh enrollment are required. Unknown external signatures remain possible. Current complete successor backup and old-artifact replay are unavailable; preserve this entire target and the originals. No financial operation is authorized.", inventory.generation_id(), inventory.digest()?, successor.display()))?;
    if Instant::now() >= expires {
        return Err(Error::Permission);
    }
    let pending = if resume {
        PendingGeneration::resume(inventory, target_password.as_bytes())?
    } else {
        PendingGeneration::create(inventory, target_password.as_bytes())?
    };
    drop(target_password);
    let constructed = pending.construct()?;
    let p = &constructed.pending;
    terminal.json(&p.plan.affected_accounts)?;
    let signers: Vec<Signer> = serde_json::from_str(&terminal.ask(
        "Exact signer socket/account/network/writer_epoch/witness JSON array for these accounts: ",
    )?)?;
    if signers.len() != p.plan.affected_accounts.len() {
        return Err(Error::Invalid);
    }
    let mut paired = Vec::new();
    let mut accounts = BTreeSet::new();
    for signer in signers {
        if !accounts.insert(signer.account_id.clone())
            || !p.plan.affected_accounts.contains(&signer.account_id)
        {
            return Err(Error::Invalid);
        }
        crate::files::validate_absolute(&signer.socket)?;
        let request = HostRecoveryContinuityRequest {
            schema_version: 1,
            inventory_digest: p.plan.inventory_digest.clone(),
            generation_id: p.plan.generation_id.clone(),
            account_id: signer.account_id.clone(),
            network_profile_id: signer.network_profile_id,
            expected_writer_epoch: signer.writer_epoch,
            expected_witness: signer.witness,
        };
        request.validate().map_err(|_| Error::Invalid)?;
        terminal.json(&request)?;
        terminal.confirm(&format!("Request separate installed-signer native approval to disclose complete account-wide historical exposure for {} via {} into this exact restricted generation? No signing, witness writer recovery or financial permission is requested.", signer.account_id, signer.socket.display()))?;
        let client = OriginalHistoryClient::pair(
            InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
            &signer.socket,
            "wholepact-native-host-recovery",
            PairScope {
                account_id: signer.account_id,
                agreement_id: "host-recovery".into(),
                participant_id: "host-recovery".into(),
                manifest_digest: p.plan.inventory_digest.clone(),
                history_read: true,
                authorization_export: true,
                preconstruction_export: false,
            },
        )
        .map_err(|_| Error::Permission)?;
        paired.push((client, request));
    }
    let mut evidence = Vec::new();
    for (client, request) in &paired {
        let lease = client
            .acquire_host_recovery_continuity(request)
            .map_err(|_| Error::Permission)?;
        lease.check_current().map_err(|_| Error::Permission)?;
        evidence.push(lease.evidence().clone());
        drop(lease);
    }
    let prepared = constructed.prepare_publication(evidence)?;
    let requests = prepared.requests()?;
    let approval = terminal.approve_publication(prepared.manifest_digest(), &format!("Publish exact restricted host generation manifest {} at {} after the separate signer-native publication reviews. These per-account admissions are informational snapshots, not a simultaneous witness cutoff. Recovered obligations remain fenced; every later financial action requires fresh actual signer/witness authority. Old credentials and confidence remain unusable.", prepared.manifest_digest(), successor.display()))?;
    let mut admissions = Vec::new();
    for request in requests {
        approval.check()?;
        let client = paired
            .iter()
            .find(|(_, r)| r == &request.continuity)
            .map(|(c, _)| c)
            .ok_or(Error::Authentication)?;
        let lease = client
            .acquire_host_recovery_publication(&request)
            .map_err(|_| Error::Permission)?;
        admissions.push(lease.admit().map_err(|_| Error::Permission)?);
    }
    prepared.publish(admissions, approval)?;
    terminal.message("Restricted successor published and locked. Unlock explicitly with fresh native enrollment. Original history and unknown exposure remain retained; recovered obligations cannot be replaced or automatically released. No financial freshness, signature, proof or submission was produced.\n")
}

#[cfg(feature = "financial-runtime")]
pub(crate) mod layered_activate_v2;
#[cfg(feature = "financial-runtime")]
pub(crate) mod layered_activate_v3;
#[cfg(feature = "financial-runtime")]
pub(crate) mod v2_routing;
#[cfg(feature = "financial-runtime")]
pub(crate) mod v3_routing;

#[cfg(all(test, feature = "financial-runtime"))]
pub(crate) use publication::construction_capsule_fixtures;

#[cfg(all(test, feature = "financial-runtime", feature = "manual-admission"))]
pub(crate) use publication::common_context_capsule_fixtures;

#[cfg(all(
    test,
    feature = "financial-runtime",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) use publication::transport_capsule_fixtures;

// Explicit transport-complete informational routes; availability stays denied.
#[cfg(feature = "financial-runtime")]
pub(crate) mod layered_activate_v5;
#[cfg(feature = "financial-runtime")]
pub(crate) mod v5_routing;
