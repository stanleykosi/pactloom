//! Fixed original workspace + dispatcher attachment. No transport or spending API.
//! Publication evidence is never a runtime source. Both original anchors and all
//! original-file identities remain mandatory after the one-way vault transition.
use super::{Host, durable_private_workspace_v1 as workspace};
use crate::{Error, Result, files::{Directory, DispatcherFileV2}, vault::Secrets,
    terminal::{Terminal, historical::HistoricalApproval}, recovery_generation::manual_target::ManualCommittedTarget};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use wholepact_storage_security::{DatabaseFileIdentity, EncryptedReadSnapshot, DatabaseKey};
use wholepact_core::manual_enrollment::{ManualHostGenerationBinding, BornManualEnrollmentTerms};
use wholepact_authority::{WitnessDisclosureDescriptor, transport::ClientTls,
    durable_delivery_scope_v2::{DurableDeliveryDispatcherV2, DurableDeliveryAuthenticationProfileV2}};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zeroize::{Zeroize, Zeroizing};
const PENDING: &str = crate::files::DISPATCHER_PENDING;
const COMMIT: &str = crate::files::DISPATCHER_COMMIT;
const MAX_PENDING: usize = 262_184;
const MAX_COMMIT: usize = 16_424;
const PURPOSE: &str = "original-workspace-dispatcher-mtls-v2";
const AUTHENTICATION: &str = "original_protected_host_dispatcher_v2";
const CUSTODY: &str = "original_generation_encrypted_attachment_mtls_v2";

fn hash(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err(Error::Authentication); }
    Ok(())
}
fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::Authentication)
}
fn decode_hex(value: &str, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    if value.is_empty() || value.len() % 2 != 0 || value.len() > max * 2 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err(Error::Authentication); }
    Ok(Zeroizing::new(hex::decode(value).map_err(|_| Error::Authentication)?))
}
fn custody_commitment() -> Result<String> {
    digest("wholepact:durable-dispatcher-custody:v2", &(2u16, AUTHENTICATION, CUSTODY, false, false, false, true, true))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Destination {
    witness: WitnessDisclosureDescriptor,
    original_terms: BornManualEnrollmentTerms,
    original_audit: wholepact_store::manual_enrollment::OriginalManualEnrollmentAuditLink,
    original_signer_roster_record_digest: String,
    enrollment_ref: String,
    witness_extension_digest: String,
    roots_der_hex: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u16,
    purpose: String,
    workspace_anchor: String,
    workspace_association_digest: String,
    original_metadata_origin: String,
    original_proof_origin: String,
    original_host: ManualHostGenerationBinding,
    principal_id: String,
    submission_journal_identity: String,
    submission_original_origin: String,
    authentication_profile: String,
    custody_profile: String,
    client_chain_der_hex: Vec<String>,
    private_key_pkcs8_hex: String,
    leaf_certificate_sha256: String,
    destinations: Vec<Destination>,
    custody_policy_commitment: String,
}
impl Drop for Pending { fn drop(&mut self) { self.private_key_pkcs8_hex.zeroize(); } }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Commit {
    version: u16,
    semantic_digest: String,
    pending_ciphertext_sha256: String,
    pending_original_file_origin: String,
}
impl Pending {
    fn semantic_digest(&self) -> Result<String> {
        digest("wholepact:durable-dispatcher-semantic-source:v2", &(
            (self.version, &self.purpose, &self.workspace_anchor, &self.workspace_association_digest,
             &self.original_metadata_origin, &self.original_proof_origin, &self.original_host, &self.principal_id),
            (&self.submission_journal_identity, &self.submission_original_origin, &self.authentication_profile,
             &self.custody_profile, &self.client_chain_der_hex, &self.leaf_certificate_sha256,
             &self.destinations, &self.custody_policy_commitment)))
    }
    fn validate(&self) -> Result<[ClientTls; 2]> {
        if self.version != 2 || self.purpose != PURPOSE || self.authentication_profile != AUTHENTICATION
            || self.custody_profile != CUSTODY || self.custody_policy_commitment != custody_commitment()?
            || self.destinations.len() != 2 || !(1..=8).contains(&self.client_chain_der_hex.len())
            || self.destinations[0].witness.account_id >= self.destinations[1].witness.account_id {
            return Err(Error::Authentication);
        }
        crate::id(&self.principal_id)?;
        for value in [&self.workspace_anchor, &self.workspace_association_digest, &self.original_metadata_origin,
            &self.original_proof_origin, &self.submission_journal_identity, &self.submission_original_origin,
            &self.leaf_certificate_sha256, &self.custody_policy_commitment] { hash(value)?; }
        if self.submission_journal_identity.bytes().all(|b| b == b'0') { return Err(Error::Authentication); }
        let chain = self.client_chain_der_hex.iter().map(|v| decode_hex(v, 16_384).map(|b| CertificateDer::from(b.to_vec()))).collect::<Result<Vec<_>>>()?;
        let key = decode_hex(&self.private_key_pkcs8_hex, 16_384)?;
        let mut total = chain.iter().map(|c| c.len()).sum::<usize>() + key.len();
        if hex::encode(Sha256::digest(chain[0].as_ref())) != self.leaf_certificate_sha256 { return Err(Error::Authentication); }
        let mut tls = Vec::new();
        for destination in &self.destinations {
            let t = &destination.original_terms;
            let w = &destination.witness;
            t.validate().map_err(|_| Error::Authentication)?;
            w.validate().map_err(|_| Error::Authentication)?;
            hash(destination.original_audit.audit_digest())?;
            hash(&destination.original_signer_roster_record_digest)?;
            hash(&destination.enrollment_ref)?;
            hash(&destination.witness_extension_digest)?;
            if w.endpoint.len() > 2048 || w.server_name.len() > 2048 || !(1..=8).contains(&destination.roots_der_hex.len())
                || w.account_id != t.identity.account_id || w.network_profile_id != t.identity.network_profile_id
                || w.policy_digest != t.original_policy_digest || t.host != self.original_host
                || t.scope.principal_id != self.principal_id
                || wholepact_authority::account_use_link::account_use_witness_origin_digest(w).map_err(|_| Error::Authentication)? != t.original_witness_origin_digest
                || [&t.signer.owner_certificate_digest, &t.signer.writer_certificate_digest].contains(&&self.leaf_certificate_sha256) {
                return Err(Error::Authentication);
            }
            let roots = destination.roots_der_hex.iter().map(|v| decode_hex(v, 16_384).map(|b| CertificateDer::from(b.to_vec()))).collect::<Result<Vec<_>>>()?;
            total += roots.iter().map(|c| c.len()).sum::<usize>();
            if total > 98_304 { return Err(Error::Authentication); }
            tls.push(ClientTls::new(w.server_name.clone(), w.pinned_server_certificate_digest.clone(), roots, chain.clone(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()))).map_err(|_| Error::Authentication)?);
        }
        tls.try_into().map_err(|_| Error::Authentication)
    }
    fn descriptor(&self) -> Result<DurableDeliveryDispatcherV2> {
        let leaf = decode_hex(self.client_chain_der_hex.first().ok_or(Error::Authentication)?, 16_384)?;
        let identity = hex::encode(Sha256::digest(&*leaf));
        if identity != self.leaf_certificate_sha256 || custody_commitment()? != self.custody_policy_commitment { return Err(Error::Authentication); }
        Ok(DurableDeliveryDispatcherV2 { principal_id: self.principal_id.clone(), public_identity_commitment: identity,
            authentication_profile: DurableDeliveryAuthenticationProfileV2::OriginalProtectedHostDispatcherV2,
            custody_policy_commitment: custody_commitment()? })
    }
}

/// Authenticated read-only original file evidence. No initialize/migrate path.
pub(crate) struct OriginalSubmissionPreflightV2 {
    snapshot: EncryptedReadSnapshot,
    identity: DatabaseFileIdentity,
    journal_identity: String,
}
impl OriginalSubmissionPreflightV2 {
    fn open(directory: &Directory, secrets: &Secrets, expected_origin: &str, expected_identity: &str) -> Result<Self> {
        directory.check()?;
        hash(expected_origin)?; hash(expected_identity)?;
        let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(directory.path("submission.sqlite")?, &secrets.key(3)?)?;
        let identity = snapshot.source_database_identity()?;
        if hex::encode(identity.origin_commitment()) != expected_origin { return Err(Error::Authentication); }
        let result = Self { snapshot, identity, journal_identity: expected_identity.into() };
        result.check()?;
        Ok(result)
    }
    fn validate_schema(&self) -> Result<()> {
        let c = self.snapshot.connection();
        let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0)).map_err(|_| Error::Authentication)?;
        let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0)).map_err(|_| Error::Authentication)?;
        let mut statement = c.prepare("SELECT type,name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name").map_err(|_| Error::Authentication)?;
        let objects = statement.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?))).map_err(|_| Error::Authentication)?.collect::<std::result::Result<Vec<_>,_>>().map_err(|_| Error::Authentication)?;
        // Fixed initialized schema, not a second record/history implementation.
        // No journal constructor is allowed to repair or initialize this source.
        let expected = [
            ("settlement_deliveries", "CREATE TABLE settlement_deliveries(evidence_id TEXT NOT NULL REFERENCES settlement_evidence(evidence_id), destination TEXT NOT NULL CHECK(length(destination) BETWEEN 1 AND 128), acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1)), PRIMARY KEY(evidence_id,destination)) STRICT"),
            ("settlement_evidence", "CREATE TABLE settlement_evidence(sequence INTEGER PRIMARY KEY, evidence_id TEXT NOT NULL UNIQUE CHECK(length(evidence_id)=64), operation TEXT NOT NULL REFERENCES submission_intents(operation), payload TEXT NOT NULL CHECK(length(payload)<=262144)) STRICT"),
            ("submission_attempts", "CREATE TABLE submission_attempts(operation TEXT NOT NULL REFERENCES submission_intents(operation), number INTEGER NOT NULL CHECK(number BETWEEN 1 AND 128), source TEXT NOT NULL, started INTEGER NOT NULL CHECK(started>=0), outcome TEXT NOT NULL CHECK(length(outcome)<=1024), PRIMARY KEY(operation,number)) STRICT"),
            ("submission_bindings", "CREATE TABLE submission_bindings(operation TEXT PRIMARY KEY NOT NULL REFERENCES submission_intents(operation), obligation TEXT NOT NULL UNIQUE, descriptor TEXT NOT NULL CHECK(length(descriptor)<=4096)) STRICT"),
            ("submission_intents", "CREATE TABLE submission_intents(operation TEXT PRIMARY KEY NOT NULL CHECK(length(operation) BETWEEN 16 AND 128), bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 2097152), digest TEXT NOT NULL CHECK(length(digest)=64), state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 2)) STRICT"),
            ("submission_journal_identity", "CREATE TABLE submission_journal_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL CHECK(length(identity)=64)) STRICT"),
            ("submission_observations", "CREATE TABLE submission_observations(operation TEXT PRIMARY KEY NOT NULL REFERENCES submission_intents(operation), report TEXT NOT NULL CHECK(length(report)<=16384)) STRICT"),
        ];
        if app != 0x5750534a || version != 3 || objects.len() != 7 || objects.iter().zip(expected).any(|((kind,name,sql), (expected_name,expected_sql))| kind != "table" || name != expected_name || sql != expected_sql) { return Err(Error::Authentication); }
        let (count, singleton, identity): (i64, i64, String) = c.query_row("SELECT count(*),min(singleton),min(identity) FROM submission_journal_identity", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_| Error::Authentication)?;
        hash(&identity)?;
        if count != 1 || singleton != 1 || identity.bytes().all(|b| b == b'0') || identity != self.journal_identity { return Err(Error::Authentication); }
        Ok(())
    }
    pub(crate) fn check(&self) -> Result<()> { self.snapshot.check_source_unchanged()?; self.validate_schema()?; self.snapshot.check_source_unchanged()?; Ok(()) }
    /// Maintained constructors may checkpoint an unchanged schema. This is only
    /// the retained original under-lock path identity check, not a live SQLite check.
    pub(crate) fn check_identity_only(&self) -> Result<()> { self.identity.check_retained_owner_path()?; Ok(()) }
}

pub(crate) struct OriginalWorkspaceDispatcherPublicationV4 {
    workspace: workspace::OriginalWorkspaceFilesV1,
    pending_file: DispatcherFileV2,
    commit_file: DispatcherFileV2,
    pending: Pending,
    commit: Commit,
}
pub(crate) struct OriginalWorkspaceDispatcherFilesV4 { original: OriginalWorkspaceDispatcherPublicationV4 }
impl OriginalWorkspaceDispatcherPublicationV4 {
    pub(crate) fn workspace(&self) -> &workspace::OriginalWorkspaceFilesV1 { &self.workspace }
    fn inspect(directory: &Directory, secrets: &Secrets) -> Result<Self> {
        if secrets.workspace_dispatcher_anchor_v4().is_none() { return Err(Error::Authentication); }
        let workspace = workspace::OriginalWorkspaceFilesV1::inspect_combined_v4(directory, secrets)?;
        let candidates = directory.private_workspace_candidates()?;
        if candidates.len() != 4 { return Err(Error::Authentication); }
        let select = |final_name: &str, prefix: &str| -> Result<String> {
            let names = candidates.iter().filter(|n| n.as_str() == final_name || n.starts_with(prefix)).collect::<Vec<_>>();
            if names.len() != 1 { return Err(Error::Authentication); } Ok(names[0].clone())
        };
        let pending_file = DispatcherFileV2::open(directory, &select(PENDING,"staging-durable-dispatcher-pending-v2-")?, PENDING, MAX_PENDING)?;
        let commit_file = DispatcherFileV2::open(directory, &select(COMMIT,"staging-durable-dispatcher-commit-v2-")?, COMMIT, MAX_COMMIT)?;
        let pending = wholepact_core::parse_typed_json(&crate::recovery_generation::unseal_durable_dispatcher_v2(secrets,true,&pending_file.bytes(directory,MAX_PENDING)?)?).map_err(|_| Error::Authentication)?;
        let commit = wholepact_core::parse_typed_json(&crate::recovery_generation::unseal_durable_dispatcher_v2(secrets,false,&commit_file.bytes(directory,MAX_COMMIT)?)?).map_err(|_| Error::Authentication)?;
        let result = Self { workspace, pending_file, commit_file, pending, commit };
        result.check_inventory(directory,secrets)?;
        Ok(result)
    }
    fn anchor(&self, directory: &Directory) -> Result<[u8;32]> {
        attachment_anchor(directory, &self.pending.workspace_anchor, &self.commit.semantic_digest, &self.pending_file, &self.commit_file)
    }
    pub(crate) fn check_inventory(&self, directory: &Directory, secrets: &Secrets) -> Result<()> {
        self.workspace.check_combined_v4(directory,secrets)?;
        self.pending_file.check(directory,MAX_PENDING)?; self.commit_file.check(directory,MAX_COMMIT)?;
        require_publication_order(self.pending_file.is_final(),self.commit_file.is_final())?;
        let p=&self.workspace.original.pending; let c=&self.workspace.original.committed;
        // Configure and immediately destroy validation-only TLS owners here. No
        // source/runtime authority survives this files-only interpretation.
        drop(self.pending.validate()?);
        if self.commit.version != 2 || self.commit.semantic_digest != self.pending.semantic_digest()?
            || self.commit.pending_ciphertext_sha256 != self.pending_file.ciphertext_digest()
            || self.commit.pending_original_file_origin != self.pending_file.origin()?
            || self.pending.workspace_anchor != hex::encode(secrets.combined_workspace_anchor_v4().ok_or(Error::Authentication)?)
            || self.pending.workspace_association_digest != c.association_digest
            || self.pending.original_metadata_origin != hex::encode(c.original_database_origin)
            || self.pending.original_proof_origin != hex::encode(p.proof.original_proof_origin)
            || self.pending.principal_id != p.association.principal_id
            || secrets.workspace_dispatcher_anchor_v4() != Some(self.anchor(directory)?.as_slice()) {
            return Err(Error::Authentication);
        }
        directory.inventory_of(&["coordination.sqlite","inbox.sqlite","outbox.sqlite","submission.sqlite","history.capsule.sqlite"],
            &["profile.lock","profile.vault","recovery.plan","generation.manifest","generation.commit","generation.keys","financial.attached","financial.inventory",crate::files::PRIVATE_PENDING,crate::files::PRIVATE_COMMIT,self.pending_file.name(),self.commit_file.name()])
    }
    pub(crate) fn submission_preflight(&self, directory: &Directory, secrets: &Secrets) -> Result<OriginalSubmissionPreflightV2> {
        OriginalSubmissionPreflightV2::open(directory,secrets,&self.pending.submission_original_origin,&self.pending.submission_journal_identity)
    }
    fn publish(mut self, directory: &Directory, secrets: &Secrets, exclusions: &workspace::PrivateWorkspacePublicationExclusionsV1, submission: &OriginalSubmissionPreflightV2, approval: &HistoricalApproval) -> Result<()> {
        for pending in [true,false] {
            approval.check()?; self.check_inventory(directory,secrets)?; submission.check()?;
            exclusions.check(directory,secrets,&self.workspace.original)?;
            if pending { self.pending_file.publish(directory,MAX_PENDING)?; } else { self.commit_file.publish(directory,MAX_COMMIT)?; }
            approval.check()?; self.check_inventory(directory,secrets)?; submission.check()?;
            exclusions.check(directory,secrets,&self.workspace.original)?;
        }
        Ok(())
    }
}
impl OriginalWorkspaceDispatcherPublicationV4 {
    /// Rejoin sealed metadata to the complete ACTUAL original source before any
    /// Host runtime exists. These borrowed inputs are nominal owners, not DTOs.
    pub(in crate::host) fn check_publication_source_v4(
        &self,directory:&Directory,secrets:&Secrets,engine:&wholepact_engine::Engine,access:&wholepact_engine::Access,
        target:&ManualCommittedTarget<'_>,financial:&crate::financial_profile::FinancialReadProfile,
    )->Result<()> {
        self.check_inventory(directory,secrets)?;target.check_current()?;target.coverage().require_complete()?;
        let source=engine.original_private_workspace_source_v1(access,&self.workspace.original.pending.association.agreement_id)?;
        source.check_current(access)?;
        let binding=ManualHostGenerationBinding {
            generation_id:target.generation_id().into(),inventory_digest:target.inventory_digest().into(),generation_plan_digest:target.plan_digest().into(),
            financial_journal_origin_digest:financial.manual_original_primary_origin_digest(directory,secrets)?,
            store_destination_identity:source.source_destination_identity().into(),profile_id:target.profile_id().into(),canonical_root:target.canonical_root().into(),
            destination_identity_digest:target.destination_identity_digest().into(),inherited_identity_digest:target.coverage().digest()?,scope_predecessor_digest:None,
        };
        if binding!=self.pending.original_host || access.principal_id!=self.pending.principal_id { return Err(Error::Authentication); }
        check_destination_audits(engine,access,&self.workspace,&self.pending)?;
        source.check_current(access)?;target.check_current()?;self.check_inventory(directory,secrets)
    }
}
fn require_publication_order(pending_final: bool, commit_final: bool) -> Result<()> {
    if !pending_final && commit_final { Err(Error::Authentication) } else { Ok(()) }
}
fn attachment_anchor(directory: &Directory, workspace_anchor: &str, semantic: &str, pending: &DispatcherFileV2, commit: &DispatcherFileV2) -> Result<[u8;32]> {
    pending.check(directory,MAX_PENDING)?; commit.check(directory,MAX_COMMIT)?;
    let result=digest("wholepact:durable-dispatcher-attachment:v2", &(2u16,workspace_anchor,semantic,directory.manual_target_identity_digest()?,pending.origin()?,pending.ciphertext_digest(),commit.origin()?,commit.ciphertext_digest()))?;
    hex::decode(result).map_err(|_| Error::Authentication)?.try_into().map_err(|_| Error::Authentication)
}
impl OriginalWorkspaceDispatcherFilesV4 {
    fn open_final(directory:&Directory,secrets:&Secrets)->Result<Self> {
        let original=OriginalWorkspaceDispatcherPublicationV4::inspect(directory,secrets)?;
        if !original.pending_file.is_final() || !original.commit_file.is_final() { return Err(Error::Authentication); }
        Ok(Self { original })
    }
    pub(crate) fn check_inventory(&self,directory:&Directory,secrets:&Secrets)->Result<()> {
        if !self.original.pending_file.is_final() || !self.original.commit_file.is_final() { return Err(Error::Authentication); }
        self.original.check_inventory(directory,secrets)
    }
    pub(crate) fn submission_preflight(&self,directory:&Directory,secrets:&Secrets)->Result<OriginalSubmissionPreflightV2> { self.original.submission_preflight(directory,secrets) }
}
/// Private maintained TLS owners. No key/TLS accessor, Clone, serializer, Debug,
/// credential rotation or network operation is implemented.
pub(crate) struct StoredDurableDispatcherV2 { _destinations: [ClientTls;2] }
impl StoredDurableDispatcherV2 {
    fn open(files:&OriginalWorkspaceDispatcherFilesV4)->Result<Self> { Ok(Self { _destinations: files.original.pending.validate()? }) }
}

#[cfg(test)]
#[path = "durable_dispatcher_v2_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "durable_dispatcher_v2_process_tests.rs"]
mod process_tests;

/// Explicitly selected trust/credential bytes, not source authority. There is no
/// default key generation, import fallback, certificate enrollment or network use.
pub(in crate::host) struct DispatcherRootsV2 { pub account_id: String, pub roots_der: Vec<Vec<u8>> }
pub(in crate::host) struct DispatcherCredentialsV2 {
    pub client_chain_der: Vec<Vec<u8>>,
    pub private_key_pkcs8: Zeroizing<Vec<u8>>,
    pub server_roots: Vec<DispatcherRootsV2>,
}
fn check_original_material_ceilings(scopes:&[wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionScopeV1])->Result<()> {
    if scopes.len()!=2 { return Err(Error::Authentication); }
    let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_|Error::Permission)?.as_secs();
    for scope in scopes {scope.check_valid_at(now).map_err(|_|Error::Permission)?;}
    Ok(())
}
fn original_host_binding(host: &Host, target: &ManualCommittedTarget<'_>, files: &workspace::OriginalWorkspaceFilesV1) -> Result<ManualHostGenerationBinding> {
    target.check_current()?; target.coverage().require_complete()?;
    let p=&files.original.pending;
    let source=host.engine.original_private_workspace_source_v1(host.access()?, &p.association.agreement_id)?;
    source.check_current(host.access()?)?;
    let result=ManualHostGenerationBinding {
        generation_id:target.generation_id().into(), inventory_digest:target.inventory_digest().into(),
        generation_plan_digest:target.plan_digest().into(),
        financial_journal_origin_digest:host.financial.as_ref().ok_or(Error::Locked)?.manual_original_primary_origin_digest(&host.directory,&host.secrets)?,
        store_destination_identity:source.source_destination_identity().into(), profile_id:target.profile_id().into(),
        canonical_root:target.canonical_root().into(), destination_identity_digest:target.destination_identity_digest().into(),
        inherited_identity_digest:target.coverage().digest()?, scope_predecessor_digest:None,
    };
    if result.financial_journal_origin_digest != p.association.original_financial_origin_digest { return Err(Error::Authentication); }
    source.check_current(host.access()?)?; target.check_current()?;
    Ok(result)
}
fn check_destinations(host:&Host, files:&workspace::OriginalWorkspaceFilesV1, pending:&Pending) -> Result<()> {
    check_destination_audits(&host.engine,host.access()?,files,pending)
}
fn check_destination_audits(engine:&wholepact_engine::Engine,access:&wholepact_engine::Access,files:&workspace::OriginalWorkspaceFilesV1,pending:&Pending)->Result<()> {
    let roster=engine.manual_roster_intent_target(access, &files.original.pending.association.agreement_id)?;
    let members=roster.members(access)?;
    if pending.destinations.iter().map(|d| d.witness.account_id.clone()).collect::<Vec<_>>() != files.original.pending.association.reviewer_account_ids { return Err(Error::Authentication); }
    for d in &pending.destinations {
        let member=members.iter().find(|m| m.identity.account_id == d.witness.account_id).ok_or(Error::Authentication)?;
        if member.identity != d.original_terms.identity || member.scope != d.original_terms.scope || member.original_audit != d.original_audit { return Err(Error::Authentication); }
        let target=engine.manual_enrollment_target(access, &d.original_terms)?;
        let original=engine.manual_enrollment_original_audit_link(access,&target,&d.enrollment_ref,&d.witness_extension_digest)?;
        if original.as_ref() != Some(&d.original_audit) { return Err(Error::Authentication); }
        target.check_current(access)?;
    }
    roster.check_current(access)?;
    Ok(())
}
impl Host {
    /// Irrevocably consumes the actual v3 Host, credentials and paired clients.
    /// No branch can return a pre-transition Host, including uncertain writes.
    pub(in crate::host) fn register_workspace_dispatcher_v4(
        self, root:&Path, credentials:DispatcherCredentialsV2,
        clients:Vec<wholepact_signer::authority_bridge::ipc::OriginalHistoryClient>, password:&[u8],
    )->Result<()> {
        self.require_private_workspace_read_session_v1()?;
        let actual_vault=Secrets::open_private_workspace_v3(&self.directory.read("profile.vault",1024)?,password)?;
        if !actual_vault.same_recovery_material(&self.secrets) { return Err(Error::Authentication); }
        drop(actual_vault);
        if self.observation.is_some() || self.dispatcher_files.is_some() || self.dispatcher.is_some() || clients.len()!=2 { return Err(Error::Authentication); }
        let files=self.workspace_files.as_ref().ok_or(Error::Authentication)?;
        files.check_inventory(&self.directory,&self.secrets)?;
        if files.original.pending.association.workspace_root != root { return Err(Error::Authentication); }
        // Complete original eight-event/proof/material audit while BOTH old
        // original material ceilings remain current, not a summary constructor.
        let (workspace_directory,original_material_ceilings)={
            let owner=self.reopen_private_workspace_registered_v1(root)?;
            let coordinator=owner.stage_coordinator_v3();
            let inspection=owner.inspect_fixed_stage_v3()?;
            let review=coordinator.inspect_saved_read_stage_v3(self.access()?,&inspection)?;
            let ceilings=review.materials().iter().map(|m|m.scope().clone()).collect::<Vec<_>>();
            let read=owner.approve_fixed_stage_v3(inspection,review,None,||Ok(()))?;
            coordinator.read_only_original_fixed_v2(self.access()?,&read,&read,&read)?;
            read.check()?;drop(read);
            (owner.into_dispatcher_registration_exclusion_v4()?,ceilings)
        };
        check_original_material_ceilings(&original_material_ceilings)?;
        let metadata=wholepact_storage_security::open_encrypted_read_snapshot(&files.original.pending.association.database_path,&DatabaseKey::from_bytes(files.original.pending.database_key))?;
        if metadata.source_database_identity()?.origin_commitment()!=files.original.committed.original_database_origin { return Err(Error::Authentication); }
        let target=ManualCommittedTarget::open_private_workspace_original(&self.directory,&self.secrets,files)?;
        let original_host=original_host_binding(&self,&target,files)?;
        self.submission_identity.check_retained_owner_path()?;
        let submission_journal_identity=self.submission.lock().map_err(|_| Error::Locked)?.identity().to_owned();
        let submission_origin=hex::encode(self.submission_identity.origin_commitment());
        let submission_preflight=OriginalSubmissionPreflightV2::open(&self.directory,&self.secrets,&submission_origin,&submission_journal_identity)?;
        let mut destinations=Vec::new();
        let mut selected=credentials.server_roots;
        selected.sort_by(|a,b| a.account_id.cmp(&b.account_id));
        if selected.len()!=2 || selected[0].account_id>=selected[1].account_id { return Err(Error::Authentication); }
        for client in &clients {
            let evidence=client.original_witness_evidence_v2().map_err(|_| Error::Authentication)?;
            evidence.check_current().map_err(|_| Error::Authentication)?;
            let terms=evidence.original_terms();
            let witness=evidence.witness();
            if terms.host!=original_host || terms.identity.account_id!=witness.account_id { return Err(Error::Authentication); }
            let roster=self.engine.manual_roster_intent_target(self.access()?, &terms.scope.agreement_id)?;
            let members=roster.members(self.access()?)?;
            let member=members.iter().find(|m| m.identity.account_id==witness.account_id).ok_or(Error::Authentication)?;
            let roots=selected.iter().find(|r| r.account_id==witness.account_id).ok_or(Error::Authentication)?;
            destinations.push(Destination { witness:witness.clone(),original_terms:terms.clone(),original_audit:member.original_audit.clone(),
                original_signer_roster_record_digest:evidence.original_signer_roster_record_digest().into(),
                enrollment_ref:evidence.enrollment_ref().into(),witness_extension_digest:evidence.witness_extension_digest().into(),
                roots_der_hex:roots.roots_der.iter().map(hex::encode).collect() });
            roster.check_current(self.access()?)?; evidence.check_current().map_err(|_| Error::Authentication)?;
        }
        destinations.sort_by(|a,b| a.witness.account_id.cmp(&b.witness.account_id));
        let pending=Pending {
            version:2,purpose:PURPOSE.into(),workspace_anchor:hex::encode(self.secrets.private_workspace_anchor().ok_or(Error::Authentication)?),
            workspace_association_digest:files.original.committed.association_digest.clone(),original_metadata_origin:hex::encode(files.original.committed.original_database_origin),
            original_proof_origin:hex::encode(files.original.pending.proof.original_proof_origin),original_host,
            principal_id:self.access()?.principal_id.clone(),submission_journal_identity,submission_original_origin:submission_origin,
            authentication_profile:AUTHENTICATION.into(),custody_profile:CUSTODY.into(),
            leaf_certificate_sha256:hex::encode(Sha256::digest(credentials.client_chain_der.first().ok_or(Error::Authentication)?)),
            client_chain_der_hex:credentials.client_chain_der.iter().map(hex::encode).collect(),private_key_pkcs8_hex:hex::encode(&*credentials.private_key_pkcs8),
            destinations,custody_policy_commitment:custody_commitment()?,
        };
        drop(credentials.private_key_pkcs8);
        drop(pending.validate()?); check_destinations(&self,files,&pending)?;
        let approval=self.terminal.approve_historical(&format!(
            "Store this exact new dispatcher credential only in the encrypted original attachment. Leaf: {}. Original accounts/destinations: {} at {}, {} at {}. Custody: no key export, rotation or portable recovery; original files and later fresh admission required. Selected roots are trust inputs, not proof of enrollment. This irrevocably closes the current Host before vault v4 publication. No network authentication, disclosure, payment admission, signature or dispatch is authorized.",
            pending.leaf_certificate_sha256,pending.destinations[0].witness.account_id,pending.destinations[0].witness.endpoint,
            pending.destinations[1].witness.account_id,pending.destinations[1].witness.endpoint))?;
        approval.check()?;
        workspace_directory.inventory_of(&["private-coordination.sqlite"],&["profile.lock"])?;
        if workspace_directory.manual_target_identity_digest()?!=files.original.committed.workspace_directory_identity { return Err(Error::Authentication); }
        metadata.check_source_unchanged()?;
        check_original_material_ceilings(&original_material_ceilings)?;
        let financial_origins=self.financial.as_ref().ok_or(Error::Locked)?.exact_input_excluded_origins()?;
        let pending_file=DispatcherFileV2::stage(&self.directory,PENDING,&crate::recovery_generation::seal_durable_dispatcher_v2(&self.secrets,true,&Zeroizing::new(serde_json::to_vec(&pending)?))?,MAX_PENDING)?;
        let commit=Commit { version:2,semantic_digest:pending.semantic_digest()?,pending_ciphertext_sha256:pending_file.ciphertext_digest().into(),pending_original_file_origin:pending_file.origin()? };
        let commit_file=DispatcherFileV2::stage(&self.directory,COMMIT,&crate::recovery_generation::seal_durable_dispatcher_v2(&self.secrets,false,&serde_json::to_vec(&commit)?)?,MAX_COMMIT)?;
        let anchor=attachment_anchor(&self.directory,&pending.workspace_anchor,&commit.semantic_digest,&pending_file,&commit_file)?;
        // The known staged pair is checked separately; the old v3 inventory
        // continues refusing it, and is never weakened for a general opener.
        files.check_retained_registration_v3(&self.directory,&self.secrets)?;
        self.directory.inventory_of(&["coordination.sqlite","inbox.sqlite","outbox.sqlite","submission.sqlite","history.capsule.sqlite"],
            &["profile.lock","profile.vault","recovery.plan","generation.manifest","generation.commit","generation.keys","financial.attached","financial.inventory",crate::files::PRIVATE_PENDING,crate::files::PRIVATE_COMMIT,pending_file.name(),commit_file.name()])?;
        check_destinations(&self,files,&pending)?; target.check_current()?; metadata.check_source_unchanged()?; submission_preflight.check()?; approval.check()?;
        check_original_material_ceilings(&original_material_ceilings)?;
        let submission_claims=(pending.submission_original_origin.clone(),pending.submission_journal_identity.clone());
        drop((target,clients,submission_preflight,selected,approval,pending));
        self.authority.fence.revoke()?;
        let Host {secrets,terminal,engine,authority,transport,submission,submission_identity,access,config,observation,financial,signer_review_clients,resolution_source,workspace_files,dispatcher_files,dispatcher,directory}=self;
        drop((engine,transport,submission,access,config,observation,signer_review_clients,resolution_source,dispatcher_files,dispatcher,authority));
        let financial=financial.ok_or(Error::Locked)?;
        // Move the ACTUAL lock before destroying all mutable financial owners.
        let financial_directory=financial.directory;
        let financial_secrets=financial.secrets;
        drop((financial.wallet,financial.proof,financial.signed,financial.transactions));
        let financial_snapshots=(0..4).map(|i| {
            let snapshot=if i==0 { wholepact_wallet::bundle::open_wallet_scan_read_snapshot(&financial_directory.path(crate::financial_profile::JOURNALS[i])?,&financial_secrets.key(i)?).map_err(Error::from)? }
                else { wholepact_storage_security::open_encrypted_read_snapshot(financial_directory.path(crate::financial_profile::JOURNALS[i])?,&financial_secrets.key(i)?)? };
            if snapshot.source_database_identity()?.origin_commitment()!=financial_origins[i] { return Err(Error::Authentication); }
            Ok(snapshot)
        }).collect::<Result<Vec<_>>>()?;
        drop(financial_secrets);
        let submission=OriginalSubmissionPreflightV2::open(&directory,&secrets,&submission_claims.0,&submission_claims.1)?;
        if submission.identity!=submission_identity { return Err(Error::Authentication); }
        // Only retained file proofs, read snapshots, secrets and exclusion locks
        // remain. No old Engine/Host/coordinator/IPC/TLS/native source is returned.
        metadata.check_source_unchanged()?; submission.check()?; for s in &financial_snapshots { s.check_source_unchanged()?; }
        check_original_material_ceilings(&original_material_ceilings)?;
        let secrets=secrets.bind_workspace_dispatcher_v4(anchor)?;
        let envelope=Zeroizing::new(secrets.seal(password)?);
        check_original_material_ceilings(&original_material_ceilings)?;
        metadata.check_source_unchanged()?;submission.check()?;
        for snapshot in &financial_snapshots {snapshot.check_source_unchanged()?;}
        directory.replace_private("profile.vault",&envelope)?;
        let verified=Secrets::open_workspace_dispatcher_v4(&directory.read("profile.vault",1024)?,password)?;
        if !verified.same_recovery_material(&secrets) { return Err(Error::Authentication); }
        pending_file.check(&directory,MAX_PENDING)?; commit_file.check(&directory,MAX_COMMIT)?;
        metadata.check_source_unchanged()?; submission.check()?; for s in &financial_snapshots { s.check_source_unchanged()?; }
        drop((workspace_files,pending_file,commit_file,commit,verified,secrets,metadata,submission,financial_snapshots,financial_directory,workspace_directory,directory));
        terminal.message("Dispatcher anchor retained. The former Host is closed; explicit attended publication completion and a fresh final-v4 original reopen are required. No dispatcher handshake or financial admission occurred.\n")
    }
}

/// Resume accepts only the anchored exact pairs, never reseals, repairs, adopts
/// replacement inodes or returns a runtime built from intermediate evidence.
pub(in crate::host) fn finish_workspace_dispatcher_publication_v4(
    terminal:&Terminal, profile:&Path, root:&Path, password:&[u8], financial_password:&[u8],
)->Result<()> {
    let directory=Directory::open(profile)?;
    let secrets=Secrets::open_workspace_dispatcher_v4(&directory.read("profile.vault",1024)?,password)?;
    let files=OriginalWorkspaceDispatcherPublicationV4::inspect(&directory,&secrets)?;
    if files.workspace.original.pending.association.workspace_root != root { return Err(Error::Authentication); }
    let approval=terminal.approve_historical(&format!("Inspect all original source/workspace/proof/financial/submission identities, then finish ONLY exact pending-before-commit no-replace dispatcher publication. Workspace: {}. No key generation, replacement, resealing, source reconstruction or runtime authority is permitted.",root.display()))?;
    // MUST be before source Store or verify_auxiliaries can call a constructor.
    let before=files.submission_preflight(&directory,&secrets)?;
    let exclusions={
        let source=workspace::PrivateWorkspacePublicationSourceV1::open_combined_v4(&directory,&secrets,&files,financial_password,&approval)?;
        source.into_exclusions()?
    };
    before.check_identity_only()?;
    drop(before);
    // Constructors may checkpoint SQLite without changing original identity;
    // hold a newly authenticated exact schema3 snapshot across all renames.
    let submission=files.submission_preflight(&directory,&secrets)?;
    files.publish(&directory,&secrets,&exclusions,&submission,&approval)?;
    drop((exclusions,submission,secrets,directory));
    Ok(())
}
impl Host {
    pub(in crate::host) fn open_workspace_dispatcher_registered_v4(terminal:Terminal,profile:&Path,root:&Path,finish:bool)->Result<Self> {
        let password=terminal.secret("Storage passphrase: ")?;
        let financial_password=terminal.secret("Original primary financial passphrase: ")?;
        if finish { finish_workspace_dispatcher_publication_v4(&terminal,profile,root,password.as_bytes(),financial_password.as_bytes())?; }
        Self::open_workspace_dispatcher_with_passwords_v4(terminal,profile,root,password.as_bytes(),financial_password.as_bytes())
    }
    pub(in crate::host) fn open_workspace_dispatcher_with_passwords_v4(terminal:Terminal,profile:&Path,root:&Path,password:&[u8],financial_password:&[u8])->Result<Self> {
        // This SECOND decode/open never accepts a publication owner as runtime.
        let directory=Directory::open(profile)?;
        let secrets=Secrets::open_workspace_dispatcher_v4(&directory.read("profile.vault",1024)?,password)?;
        let files=OriginalWorkspaceDispatcherFilesV4::open_final(&directory,&secrets)?;
        if files.original.workspace.original.pending.association.workspace_root!=root { return Err(Error::Authentication); }
        let approval=terminal.approve_historical(&format!("Authenticate the same final-v4 original workspace, both original file pairs, complete parent history and original financial/proof/submission owners. Workspace: {}. Historical inspection only; no admission, export, signing, handshake or dispatch.",root.display()))?;
        let preflight=files.submission_preflight(&directory,&secrets)?;
        {
            let source=workspace::PrivateWorkspacePublicationSourceV1::open_combined_v4(&directory,&secrets,&files.original,financial_password,&approval)?;
            source.require_exact_association()?;
        }
        preflight.check_identity_only()?; approval.check()?;
        let p=&files.original.workspace.original.pending;
        let financial=crate::financial_profile::FinancialProfile::open_private_workspace_original_v1(&p.proof.financial_root,&directory,&secrets,financial_password,
            &p.association.original_financial_origin_digest,&p.proof.financial_directory_identity,p.proof.original_proof_origin)?;
        let store=crate::recovery_generation::open_workspace_dispatcher_original_store_v4(&directory,&secrets,&files)?;
        let dispatcher=StoredDurableDispatcherV2::open(&files)?;
        let original_submission=preflight.identity.clone();
        let expected_journal=preflight.journal_identity.clone();
        drop(preflight);
        let mut host=Self::open_runtime_from_store_checked(directory,secrets,terminal,store,Some(&original_submission))?;
        if host.submission.lock().map_err(|_| Error::Locked)?.identity()!=expected_journal { return Err(Error::Authentication); }
        host.financial=Some(financial); host.dispatcher_files=Some(files);host.dispatcher=Some(dispatcher);
        host.enroll()?;
        let saved=&host.dispatcher_files.as_ref().ok_or(Error::Authentication)?.original.pending;
        if host.access()?.principal_id!=saved.principal_id { return Err(Error::Permission); }
        host.require_private_workspace_read_session_v1()?;
        // Actual source conjunction is checked again by the dedicated nominal
        // admission owner; old v3 generic APIs still see no workspace source.
        Ok(host)
    }
}

struct InitialAdmissionInspection<'a> {
    host:&'a Host,
    files:&'a OriginalWorkspaceDispatcherFilesV4,
    target:&'a ManualCommittedTarget<'a>,
    approval:&'a HistoricalApproval,
}
fn scope_matches(scope:&wholepact_engine::PrivateWorkspaceScopeV1,files:&OriginalWorkspaceDispatcherFilesV4)->bool {
    let a=&files.original.workspace.original.pending.association;
    scope.source_digest()==a.source_digest && scope.principal_id()==a.principal_id
        && scope.agreement_id()==a.agreement_id && scope.obligation_id()==a.obligation_id
        && scope.reviewer_account_ids()==a.reviewer_account_ids && scope.protected_destination()==a.database_path
        && scope.retention_policy()==a.retention_policy
}
fn check_admission_originals(host:&Host,files:&OriginalWorkspaceDispatcherFilesV4,target:&ManualCommittedTarget<'_>)->Result<()> {
    host.require_private_workspace_read_session_v1()?; files.check_inventory(&host.directory,&host.secrets)?;
    target.check_current()?; target.coverage().require_complete()?;
    let p=&files.original.workspace.original.pending;
    let source=host.engine.original_private_workspace_source_v1(host.access()?,&p.association.agreement_id)?;
    source.check_initialization_plan_v1(host.access()?,&p.initialization_plan)?;
    if source.source_digest()!=p.association.source_digest || source.source_destination_identity()!=p.association.source_store_destination_identity
        || original_host_binding(host,target,&files.original.workspace)?!=files.original.pending.original_host
        || host.submission.lock().map_err(|_| Error::Locked)?.identity()!=files.original.pending.submission_journal_identity
        || hex::encode(host.submission_identity.origin_commitment())!=files.original.pending.submission_original_origin
        || host.dispatcher.is_none() || host.workspace_files.is_some() { return Err(Error::Authentication); }
    host.submission_identity.check_retained_owner_path()?;
    check_destinations(host,&files.original.workspace,&files.original.pending)?;
    source.check_current(host.access()?)?; target.check_current()?;
    Ok(())
}
impl wholepact_engine::LocalPrivateDurableAdmissionConsentV2 for InitialAdmissionInspection<'_> {
    fn permits_source(&self,scope:&wholepact_engine::PrivateWorkspaceScopeV1)->bool {
        scope_matches(scope,self.files) && self.approval.check().is_ok()
            && check_admission_originals(self.host,self.files,self.target).is_ok() && self.approval.check().is_ok()
    }
}
/// Nominal exclusive original admission source. Initial inspection permission
/// is separate from source liveness; a later export action obtains its own gate.
pub(in crate::host) struct OriginalDeliveryAdmissionOwnerV2<'host> {
    coordinator:wholepact_engine::PrivateDurableAdmissionCoordinatorV2<'host>,
    target:ManualCommittedTarget<'host>,
    host:&'host Host,
    files:&'host OriginalWorkspaceDispatcherFilesV4,
    inspection:HistoricalApproval,
    directory:Directory,
}
impl Host {
    pub(in crate::host) fn original_delivery_admission_owner_v2<'host>(&'host self,root:&Path)->Result<OriginalDeliveryAdmissionOwnerV2<'host>> {
        let files=self.dispatcher_files.as_ref().ok_or(Error::Authentication)?;
        files.check_inventory(&self.directory,&self.secrets)?;
        let p=&files.original.workspace.original.pending; let c=&files.original.workspace.original.committed;
        if root!=p.association.workspace_root { return Err(Error::Authentication); }
        let inspection=self.terminal.approve_historical(&format!("Inspect original fixed-prefix and bounded admission-export history metadata for agreement {}, original source {}, original workspace {}. Inspect bounded original encrypted envelope and both original material scopes for consistency, and read/verify the exact saved original proof to derive review metadata only. No construction, proving, new artifact, export or financial admission.",p.association.agreement_id,p.association.source_digest,root.display()))?;
        let target=ManualCommittedTarget::open_workspace_dispatcher_original_v4(&self.directory,&self.secrets,files)?;
        check_admission_originals(self,files,&target)?;
        let directory=Directory::open(root)?;
        directory.inventory_of(&["private-coordination.sqlite"],&["profile.lock"])?;
        if directory.manual_target_identity_digest()?!=c.workspace_directory_identity { return Err(Error::Authentication); }
        let source=self.engine.original_private_workspace_source_v1(self.access()?,&p.association.agreement_id)?;
        let proof=self.financial.as_ref().ok_or(Error::Locked)?.original_workspace_proof_v1()?;
        let privacy=InitialAdmissionInspection {host:self,files,target:&target,approval:&inspection};
        let coordinator=wholepact_engine::PrivateDurableAdmissionCoordinatorV2::open_original(source,self.access()?,&p.association.database_path,
            &DatabaseKey::from_bytes(p.database_key),c.original_database_origin,&p.association.retention_policy,&c.association_digest,
            proof,p.proof.original_proof_origin,&p.initialization_plan,&c.seed,&privacy)?;
        if coordinator.origin_marker_digest()?!=c.seed.marker_digest { return Err(Error::Authentication); }
        inspection.check()?;
        Ok(OriginalDeliveryAdmissionOwnerV2 {coordinator,target,host:self,files,inspection,directory})
    }
}
impl<'host> OriginalDeliveryAdmissionOwnerV2<'host> {
    pub(in crate::host) fn coordinator(&self)->&wholepact_engine::PrivateDurableAdmissionCoordinatorV2<'host> { &self.coordinator }
    pub(in crate::host) fn workspace_scope(&self)->&wholepact_engine::PrivateWorkspaceScopeV1 { self.coordinator.workspace_scope() }
    pub(in crate::host) fn check_current_without_proof_lock_v2(&self)->Result<()> {
        check_admission_originals(self.host,self.files,&self.target)?;
        self.directory.inventory_of(&["private-coordination.sqlite"],&["profile.lock"])?;
        if self.directory.manual_target_identity_digest()?!=self.files.original.workspace.original.committed.workspace_directory_identity { return Err(Error::Authentication); }
        Ok(())
    }
    /// Actual held original file/principal checks after closed preparation.
    /// The Engine owns same-connection metadata/proof revision observations.
    /// No initial inspection approval, TLS reconstruction or source/history
    /// interpretation is repeated in an immediate export frame callback.
    pub(in crate::host) fn check_closed_source_v3(&self)->Result<()> {
        self.host.require_private_workspace_read_session_v1()?;
        self.host.require_manual_session()?;
        self.target.check_current()?;
        self.files.original.workspace.check_combined_v4(&self.host.directory,&self.host.secrets)?;
        self.files.original.pending_file.check(&self.host.directory,MAX_PENDING)?;
        self.files.original.commit_file.check(&self.host.directory,MAX_COMMIT)?;
        if !self.files.original.pending_file.is_final() || !self.files.original.commit_file.is_final()
            || self.host.access()?.principal_id != self.files.original.pending.principal_id
            || self.host.dispatcher.is_none() || self.host.workspace_files.is_some()
            || self.host.submission.lock().map_err(|_|Error::Locked)?.identity()!=self.files.original.pending.submission_journal_identity
            || self.host.financial.as_ref().ok_or(Error::Locked)?.manual_original_primary_origin_digest(&self.host.directory,&self.host.secrets)?!=self.files.original.pending.original_host.financial_journal_origin_digest
        { return Err(Error::Authentication); }
        self.host.submission_identity.check_retained_owner_path()?;
        self.directory.inventory_of(&["private-coordination.sqlite"],&["profile.lock"])?;
        if self.directory.manual_target_identity_digest()?!=self.files.original.workspace.original.committed.workspace_directory_identity { return Err(Error::Authentication); }
        self.host.directory.inventory_of(&["coordination.sqlite","inbox.sqlite","outbox.sqlite","submission.sqlite","history.capsule.sqlite"],
            &["profile.lock","profile.vault","recovery.plan","generation.manifest","generation.commit","generation.keys","financial.attached","financial.inventory",crate::files::PRIVATE_PENDING,crate::files::PRIVATE_COMMIT,self.files.original.pending_file.name(),self.files.original.commit_file.name()])?;
        self.target.check_current()
    }
    pub(in crate::host) fn dispatcher_descriptor(&self)->Result<DurableDeliveryDispatcherV2> {
        self.check_current_without_proof_lock_v2()?; self.files.original.pending.descriptor()
    }
    pub(in crate::host) fn original_host_generation_binding(&self)->Result<ManualHostGenerationBinding> {
        self.check_current_without_proof_lock_v2()?; original_host_binding(self.host,&self.target,&self.files.original.workspace)
    }
    pub(in crate::host) fn submission_journal_identity(&self)->Result<String> {
        self.check_current_without_proof_lock_v2()?; Ok(self.host.submission.lock().map_err(|_| Error::Locked)?.identity().into())
    }
    pub(in crate::host) fn source(&self)->Result<OriginalDurableDispatcherSourceV2<'_, 'host>> {
        self.check_current_without_proof_lock_v2()?; Ok(OriginalDurableDispatcherSourceV2 {owner:self})
    }
}
impl wholepact_engine::LocalPrivateDurableAdmissionConsentV2 for OriginalDeliveryAdmissionOwnerV2<'_> {
    fn permits_source(&self,scope:&wholepact_engine::PrivateWorkspaceScopeV1)->bool {
        scope_matches(scope,self.files) && self.inspection.check().is_ok() && self.check_current_without_proof_lock_v2().is_ok() && self.inspection.check().is_ok()
    }
}
pub(in crate::host) struct OriginalDispatcherDestinationV2 {
    pub witness: WitnessDisclosureDescriptor,
    pub original_terms: BornManualEnrollmentTerms,
    pub original_audit: wholepact_store::manual_enrollment::OriginalManualEnrollmentAuditLink,
    pub original_signer_roster_record_digest: String,
}
impl OriginalDeliveryAdmissionOwnerV2<'_> {
    pub(in crate::host) fn inspection_approval(&self)->&HistoricalApproval { &self.inspection }
    pub(in crate::host) fn original_destinations(&self)->Result<Vec<OriginalDispatcherDestinationV2>> {
        self.check_current_without_proof_lock_v2()?;
        let result=self.files.original.pending.destinations.iter().map(|d| OriginalDispatcherDestinationV2 {
            witness:d.witness.clone(), original_terms:d.original_terms.clone(), original_audit:d.original_audit.clone(),
            original_signer_roster_record_digest:d.original_signer_roster_record_digest.clone(),
        }).collect();
        self.check_current_without_proof_lock_v2()?;
        Ok(result)
    }
}
/// Lexically borrowed source; exposes rederived inert prospective fields only.
pub(in crate::host) struct OriginalDurableDispatcherSourceV2<'owner,'host> { owner:&'owner OriginalDeliveryAdmissionOwnerV2<'host> }
impl OriginalDurableDispatcherSourceV2<'_, '_> {
    pub(in crate::host) fn descriptor(&self)->Result<DurableDeliveryDispatcherV2> {self.owner.dispatcher_descriptor()}
    pub(in crate::host) fn original_host_generation_binding(&self)->Result<ManualHostGenerationBinding> {self.owner.original_host_generation_binding()}
    pub(in crate::host) fn submission_journal_identity(&self)->Result<String> {self.owner.submission_journal_identity()}
}

pub(super) fn finish_command_v4(terminal:Terminal,profile:&Path,workspace:&Path)->Result<()> {
    let host=Host::open_workspace_dispatcher_registered_v4(terminal.clone(),profile,workspace,true)?;
    let owner=host.original_delivery_admission_owner_v2(workspace)?;
    owner.check_current_without_proof_lock_v2()?;
    terminal.message("Exact dispatcher publication is complete and the final original source reopened. No dispatcher handshake, financial admission, signing or dispatch is enabled.\n")
}
pub(super) fn status_command_v4(terminal:Terminal,profile:&Path,workspace:&Path)->Result<()> {
    let host=Host::open_workspace_dispatcher_registered_v4(terminal.clone(),profile,workspace,false)?;
    let owner=host.original_delivery_admission_owner_v2(workspace)?;
    let descriptor=owner.dispatcher_descriptor()?;
    terminal.message(&format!("Original dispatcher attachment: {}. Original submission identity: {}. Credential storage and original-file custody only; no handshake, enrollment or financial authority is established.\n",descriptor.public_identity_commitment,owner.submission_journal_identity()?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationReviewerSelectionV4 {
    account_id:String,
    signer_socket:std::path::PathBuf,
    selected_root_der_files:Vec<std::path::PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationSelectionV4 {
    client_certificate_der_files:Vec<std::path::PathBuf>,
    private_key_pkcs8_file:std::path::PathBuf,
    reviewers:Vec<RegistrationReviewerSelectionV4>,
}
pub(super) fn register_command_v4(terminal:Terminal,profile:&Path,root:&Path)->Result<()> {
    let host=Host::open_private_workspace_registered_v1(terminal.clone(),profile,root,false)?;
    let selection:RegistrationSelectionV4=host.read_manual_private("Exact selected dispatcher credential paths, roots and two original signer sockets JSON: ","explicit fixed-purpose encrypted dispatcher storage selection")?;
    if !(1..=8).contains(&selection.client_certificate_der_files.len()) || selection.reviewers.len()!=2 { return Err(Error::Invalid); }
    let files=host.workspace_files.as_ref().ok_or(Error::Authentication)?;
    let agreement=&files.original.pending.association.agreement_id;
    let fixed=host.private_durable_read_fixed_v2(root)?;
    let roster=host.engine.manual_roster_intent_target(host.access()?,agreement)?;
    let members=roster.members(host.access()?)?;
    let mut reviewers=selection.reviewers;
    reviewers.sort_by(|a,b|a.account_id.cmp(&b.account_id));
    if reviewers.iter().map(|r|r.account_id.clone()).collect::<Vec<_>>()!=files.original.pending.association.reviewer_account_ids { return Err(Error::Authentication); }
    let read=terminal.approve_historical("Read ONLY the explicitly selected new dispatcher certificate chain/PKCS#8 file and each selected witness root DER into temporary memory for exact key/leaf validation and encrypted storage. These must be a dedicated identity, never original owner/writer credentials. No key generation, output, network handshake or remote enrollment is authorized.")?;
    read.check()?;
    let chain=selection.client_certificate_der_files.iter().map(|p|crate::files::read_private(p,16_384)).collect::<Result<Vec<_>>>()?;
    let key=Zeroizing::new(crate::files::read_private(&selection.private_key_pkcs8_file,16_384)?);
    let mut roots=Vec::new();let mut clients=Vec::new();
    for reviewer in &reviewers {
        if !(1..=8).contains(&reviewer.selected_root_der_files.len()) { return Err(Error::Invalid); }
        crate::files::validate_absolute(&reviewer.signer_socket)?;
        let member=members.iter().find(|m|m.identity.account_id==reviewer.account_id).ok_or(Error::Authentication)?;
        roots.push(DispatcherRootsV2 {account_id:reviewer.account_id.clone(),roots_der:reviewer.selected_root_der_files.iter().map(|p|crate::files::read_private(p,16_384)).collect::<Result<Vec<_>>>()?});
        read.check()?;
        terminal.confirm(&format!("Pair installed original account {} at {} to authenticate its original public witness descriptor only. No material export, payment admission or dispatcher handshake.",reviewer.account_id,reviewer.signer_socket.display()))?;
        clients.push(wholepact_signer::authority_bridge::ipc::OriginalHistoryClient::pair(
            wholepact_signer::authority_bridge::provider::InstalledSignerProvider::load().map_err(|_|Error::Permission)?,&reviewer.signer_socket,"wholepact-dispatcher-registration-v4",
            wholepact_signer::ipc::PairScope {account_id:reviewer.account_id.clone(),agreement_id:agreement.clone(),participant_id:member.scope.participant_id.clone(),manifest_digest:fixed.manifest_digest.clone(),history_read:true,authorization_export:false,preconstruction_export:false},
        ).map_err(|_|Error::Permission)?);
    }
    roster.check_current(host.access()?)?;read.check()?;drop((read,roster));
    let password=terminal.secret("Storage passphrase for exact mandatory v4 replacement: ")?;
    // Authenticate this password against the actual original vault BEFORE staging.
    let original=Secrets::open_private_workspace_v3(&host.directory.read("profile.vault",1024)?,password.as_bytes())?;
    if !original.same_recovery_material(&host.secrets) { return Err(Error::Authentication); }
    drop(original);
    host.register_workspace_dispatcher_v4(root,DispatcherCredentialsV2 {client_chain_der:chain,private_key_pkcs8:key,server_roots:roots},clients,password.as_bytes())
}
