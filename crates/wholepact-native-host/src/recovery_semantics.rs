//! Cross-journal historical dependencies for a restricted recovery generation.
//! This authenticates known local associations, never a complete signing universe.
use crate::{Error, Result, recovery_inventory::Inventory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_engine::recovery::CoordinationRecoveryInventory;
use wholepact_storage_security::bundle::{
    JournalKind,
    recovery::{
        RecoveryCell, RecoveryProvenance, RecoveryTable, VerifiedRecoveryComponent,
        evidence::RecoveredEvidence,
    },
};

pub(crate) struct SemanticInventory {
    accounts: BTreeSet<String>,
    digest: String,
}
impl SemanticInventory {
    pub(crate) fn accounts(&self) -> &BTreeSet<String> {
        &self.accounts
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
}
fn blocked(reason: &str) -> Error {
    Error::RecoverySemantic(reason.into())
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
#[derive(Serialize)]
struct ExactTransaction {
    prefix: String,
    checkpoint_id: String,
    candidate_id: String,
    manifest_digest: String,
    transaction_id: String,
    bytes_digest: String,
}
#[derive(Default)]
struct Artifacts {
    accounts: BTreeSet<String>,
    bindings: Vec<serde_json::Value>,
    transactions: Vec<ExactTransaction>,
}

/// Private borrowed views over already authenticated source capabilities. There
/// is no constructor from imported rows, provenance labels, or saved JSON.
#[derive(Clone, Copy)]
enum Source<'a> {
    Restored(&'a VerifiedRecoveryComponent),
    Successor(&'a RecoveredEvidence),
    Archived(&'a wholepact_storage_security::generation_archive::ArchivedOrdinarySource),
}
impl<'a> Source<'a> {
    fn provenance(self) -> &'a RecoveryProvenance {
        match self {
            Self::Restored(s) => s.provenance(),
            Self::Successor(s) => s.provenance(),
            Self::Archived(s) => s.provenance(),
        }
    }
    fn tables(self) -> &'a [RecoveryTable] {
        match self {
            Self::Restored(s) => s.tables(),
            Self::Successor(s) => s.tables(),
            Self::Archived(s) => s.tables(),
        }
    }
}

pub(crate) fn inspect(inventory: &Inventory) -> Result<SemanticInventory> {
    inventory.check()?;
    let result = inspect_sources(
        inventory.known_account_ids(),
        inventory.components().iter().map(Source::Restored),
    )?;
    inventory.check()?;
    Ok(result)
}

pub(crate) fn inspect_successor(
    components: &[RecoveredEvidence],
    known_account_ids: &BTreeSet<String>,
) -> Result<SemanticInventory> {
    inspect_sources(known_account_ids, components.iter().map(Source::Successor))
}

/// Validate the complete current archived node against both its new financial
/// journals and retained older artifact groups. Old groups retain their original
/// provenance; only private lookup keys distinguish their namespaces.
#[cfg(feature = "financial-runtime")]
pub(crate) fn inspect_archived_current(
    coordination: &wholepact_storage_security::generation_archive::ArchivedGenerationSource,
    current: &[wholepact_storage_security::generation_archive::ArchivedOrdinarySource],
    inherited: &[&RecoveredEvidence],
    previous: &[&wholepact_storage_security::generation_archive::ArchivedOrdinarySource],
    known_accounts: &BTreeSet<String>,
) -> Result<SemanticInventory> {
    let semantic = wholepact_engine::recovery::inspect_archived_coordination_recovery(coordination)
        .map_err(|_| {
            blocked("archived coordination has inconsistent current or inherited envelopes")
        })?;
    let mut owned = BTreeMap::new();
    let mut prefixes = BTreeSet::new();
    for source in current
        .iter()
        .map(Source::Archived)
        .chain(inherited.iter().map(|source| Source::Successor(source)))
        .chain(previous.iter().map(|source| Source::Archived(source)))
    {
        let p = source.provenance();
        if !matches!(
            p.kind,
            JournalKind::WalletScan
                | JournalKind::ProofWitness
                | JournalKind::SignedResults
                | JournalKind::ExactTransactions
        ) {
            continue;
        }
        let (directory, suffix) = p
            .component_id
            .rsplit_once('-')
            .ok_or_else(|| blocked("archived financial role is malformed"))?;
        let prefix = format!("{}-{directory}", p.bundle_digest);
        let key = format!("{prefix}-{suffix}");
        if let Some(old) = owned.insert(key, source) {
            if old.provenance() != p {
                return Err(blocked("contradictory retained financial source identity"));
            }
        }
        prefixes.insert(prefix);
    }
    let components = owned
        .iter()
        .map(|(id, source)| (id.as_str(), *source))
        .collect();
    let artifacts = inspect_artifacts(&components, &prefixes, &semantic)?;
    let submission = current
        .iter()
        .find(|source| source.provenance().component_id == "root-submission")
        .ok_or_else(|| blocked("archived current submission journal is missing"))?;
    let submissions = inspect_submissions(
        Source::Archived(submission),
        &semantic,
        &artifacts.transactions,
    )?;
    let mut accounts = known_accounts.clone();
    accounts.extend(semantic.accounts().iter().cloned());
    accounts.extend(artifacts.accounts);
    for account in &accounts {
        crate::id(account)?;
    }
    let mut current_provenance: Vec<_> = current.iter().map(|source| source.provenance()).collect();
    current_provenance.sort_by(|a, b| a.component_id.cmp(&b.component_id));
    let artifacts_provenance: Vec<_> = owned.values().map(|source| source.provenance()).collect();
    let digest = wholepact_core::proposal::canonical_digest(
        "wholepact:archived-current-host-semantic-inventory:v1",
        &(
            coordination.source_provenance(),
            semantic.digest(),
            current_provenance,
            artifacts_provenance,
            &accounts,
            &artifacts.bindings,
            &artifacts.transactions,
            submissions,
            "all-ancestors-retained",
            "external-signatures-unknown",
            "all-original-obligations-remain-fenced",
            "observations-historical-only",
        ),
    )
    .map_err(|_| blocked("archived semantic digest could not be encoded"))?;
    Ok(SemanticInventory { accounts, digest })
}

fn inspect_sources<'a>(
    known_account_ids: &BTreeSet<String>,
    sources: impl Iterator<Item = Source<'a>>,
) -> Result<SemanticInventory> {
    let mut components = BTreeMap::new();
    for component in sources {
        if components
            .insert(component.provenance().component_id.as_str(), component)
            .is_some()
        {
            return Err(blocked("duplicate source component identity"));
        }
    }
    let coordination = *components
        .get("coordination")
        .ok_or_else(|| blocked("missing coordination component"))?;
    let semantic = match coordination {
        Source::Restored(source) => wholepact_engine::recovery::inspect_coordination_recovery(source),
        Source::Successor(source) => wholepact_engine::recovery::inspect_successor_coordination_recovery(source),
        Source::Archived(_) => return Err(blocked("ordinary archive is not a coordination generation")),
    }
        .map_err(|_| blocked("coordination history has unknown schema or inconsistent account/obligation/proposal bindings"))?;
    let mut prefixes = BTreeSet::new();
    for (id, source) in &components {
        let expected = match *id {
            "coordination" => Some(JournalKind::CoordinationAuthority),
            "inbox" => Some(JournalKind::TransportInbox),
            "outbox" => Some(JournalKind::TransportOutbox),
            "submission" => Some(JournalKind::Submission),
            _ => None,
        };
        if let Some(kind) = expected {
            if source.provenance().kind != kind {
                return Err(blocked(
                    "source component kind conflicts with its exact identity",
                ));
            }
            continue;
        }
        let (prefix, suffix) = id
            .rsplit_once('-')
            .ok_or_else(|| blocked("unrecognized component identity"))?;
        let index = prefix
            .strip_prefix("financial-")
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n < 12 && prefix == format!("financial-{n}"))
            .ok_or_else(|| blocked("unrecognized financial component prefix"))?;
        let kind = match suffix {
            "wallet" => JournalKind::WalletScan,
            "proof" => JournalKind::ProofWitness,
            "signed" => JournalKind::SignedResults,
            "transactions" => JournalKind::ExactTransactions,
            _ => return Err(blocked("unknown financial component role")),
        };
        if source.provenance().kind != kind {
            return Err(blocked(
                "financial component role does not match its compiled schema",
            ));
        }
        prefixes.insert(format!("financial-{index}"));
    }
    for required in ["coordination", "inbox", "outbox", "submission"] {
        if !components.contains_key(required) {
            return Err(blocked("missing required host journal"));
        }
    }
    let artifacts = inspect_artifacts(&components, &prefixes, &semantic)?;
    let submissions =
        inspect_submissions(components["submission"], &semantic, &artifacts.transactions)?;
    let mut accounts = known_account_ids.clone();
    accounts.extend(semantic.accounts().iter().cloned());
    accounts.extend(artifacts.accounts);
    for account in &accounts {
        crate::id(account)?;
    }
    // Component provenance commits every authenticated row, including opaque
    // transport ciphertext and complete maintained-wallet viewing history. Those
    // rows cannot establish an exhaustive account roster or current observations.
    let provenance: Vec<_> = components.values().map(|c| c.provenance()).collect();
    let digest = wholepact_core::proposal::canonical_digest(
        "wholepact:host-cross-journal-semantic-inventory:v1",
        &(
            semantic.digest(),
            provenance,
            &accounts,
            &artifacts.bindings,
            &artifacts.transactions,
            submissions,
            "transport-account-universe-unknown",
            "external-signatures-unknown",
            "all-original-obligations-remain-fenced",
            "observations-historical-only",
        ),
    )
    .map_err(|_| blocked("cross-journal semantic digest could not be encoded"))?;
    Ok(SemanticInventory { accounts, digest })
}

#[cfg(not(feature = "financial-runtime"))]
fn inspect_artifacts(
    _: &BTreeMap<&str, Source<'_>>,
    prefixes: &BTreeSet<String>,
    semantic: &CoordinationRecoveryInventory,
) -> Result<Artifacts> {
    if !prefixes.is_empty()
        || semantic
            .attempts()
            .iter()
            .any(|a| a.job_id.is_some() || a.transaction_id.is_some())
    {
        return Err(blocked(
            "financial artifact inspection requires the financial-runtime build",
        ));
    }
    Ok(Artifacts::default())
}
#[cfg(feature = "financial-runtime")]
fn observe_retained_identity(
    seen: &mut BTreeMap<String, (serde_json::Value, Option<String>)>,
    id: &str,
    immutable: serde_json::Value,
    retained: Option<String>,
) -> Result<()> {
    if let Some((old, old_retained)) = seen.get_mut(id) {
        if old != &immutable || matches!((&*old_retained, &retained), (Some(a), Some(b)) if a != b)
        {
            return Err(blocked(
                "retained artifact identity conflicts across archived generations",
            ));
        }
        if old_retained.is_none() {
            *old_retained = retained;
        }
    } else {
        seen.insert(id.into(), (immutable, retained));
    }
    Ok(())
}

#[cfg(feature = "financial-runtime")]
fn inspect_artifacts(
    components: &BTreeMap<&str, Source<'_>>,
    prefixes: &BTreeSet<String>,
    semantic: &CoordinationRecoveryInventory,
) -> Result<Artifacts> {
    let engine_bindings = coordination_checkpoint_bindings(semantic)?;
    let mut result = Artifacts::default();
    let mut observed_jobs = BTreeSet::new();
    let mut proof_identities = BTreeMap::new();
    let mut signed_identities = BTreeMap::new();
    let mut transaction_identities = BTreeMap::new();
    for prefix in prefixes {
        let component = |suffix: &str| -> Result<Source<'_>> {
            components.get(format!("{prefix}-{suffix}").as_str()).copied()
                .ok_or_else(|| blocked("financial dependency is missing its wallet/proof/signed/transaction companion"))
        };
        let wallet = component("wallet")?;
        // Compatibility labels only: legacy and recorded-import share these.
        // Each Source above is already sealed by its whole-layout reader; this
        // comparison never authenticates a layout or promotes receipt rows.
        let template = wholepact_wallet::bundle::trusted_template()?;
        if wallet.provenance().application_id != template.application_id
            || wallet.provenance().schema_version != template.schema_version
        {
            return Err(blocked(
                "wallet viewing history uses an unsupported maintained schema",
            ));
        }
        let proofs = match component("proof")? {
            Source::Restored(source) => wholepact_proof_jobs::backup::recovery_references(source),
            Source::Successor(source) => {
                wholepact_proof_jobs::backup::successor_recovery_references(source)
            }
            Source::Archived(source) => {
                wholepact_proof_jobs::backup::archived_recovery_references(source)
            }
        }
        .map_err(|_| {
            blocked("proof journal contains an unsupported or inconsistent retained checkpoint")
        })?;
        let signed = match component("signed")? {
            Source::Restored(source) => wholepact_protocol::authorization::retention::backup::recovery_references(source),
            Source::Successor(source) => wholepact_protocol::authorization::retention::backup::successor_recovery_references(source),
            Source::Archived(source) => wholepact_protocol::authorization::retention::backup::archived_recovery_references(source),
        }
            .map_err(|_| blocked("signed-result journal contains an unknown, orphaned or inconsistent retained artifact"))?;
        let transactions = match component("transactions")? {
            Source::Restored(source) => wholepact_protocol::authorization::retention::transaction::backup::recovery_references(source),
            Source::Successor(source) => wholepact_protocol::authorization::retention::transaction::backup::successor_recovery_references(source),
            Source::Archived(source) => wholepact_protocol::authorization::retention::transaction::backup::archived_recovery_references(source),
        }
                .map_err(|_| {
                    blocked(
                "transaction journal contains an unknown, orphaned or inconsistent exact artifact",
            )
                })?;
        for proof in &proofs {
            observe_retained_identity(
                &mut proof_identities,
                &proof.job_id,
                serde_json::json!({"request":proof.request_digest,"scope_digest":proof.scope_digest,"scope":proof.scope}),
                proof.retained_result_digest.clone(),
            )?;
            let binding = engine_bindings.get(&proof.job_id).ok_or_else(|| {
                blocked("proof job lacks its original engine constructor receipt")
            })?;
            if !binding.matches(proof) {
                return Err(blocked(
                    "proof checkpoint scope, principal, effects or accounts differ from the original engine constructor",
                ));
            }
            let matching: Vec<_> = semantic
                .attempts()
                .iter()
                .filter(|a| a.job_id.as_deref() == Some(proof.job_id.as_str()))
                .collect();
            if matching.is_empty()
                || matching.iter().any(|a| {
                    a.candidate_id != proof.scope.candidate_id
                        || a.manifest_digest != proof.scope.manifest_digest
                        || a.artifact_digest.as_deref().is_none_or(|d| {
                            d != proof.scope.artifact_digest
                                && Some(d) != proof.retained_result_digest.as_deref()
                        })
                })
            {
                return Err(blocked(
                    "proof job has no exact coordination checkpoint dependency or disagrees with its retained input/result",
                ));
            }
            observed_jobs.insert(proof.job_id.clone());
            result
                .accounts
                .extend(proof.scope.account_ids.iter().cloned());
            result.bindings.push(serde_json::json!({"component":format!("{prefix}-proof"), "job":proof.job_id,
                "request":proof.request_digest, "scope_digest":proof.scope_digest, "scope":proof.scope,
                "historical_state":proof.historical_state, "result":proof.retained_result_digest}));
        }
        for item in &signed {
            observe_retained_identity(
                &mut signed_identities,
                &item.result_id,
                serde_json::json!({"request":item.request_digest,"scope_digest":item.scope_digest,
                    "context":item.context,"signature_set":item.signature_set_digest,"maximum_actions":item.maximum_actions}),
                item.retained_result_digest.clone(),
            )?;
            let proof = proofs
                .iter()
                .find(|p| p.job_id == item.context.proof_job_id)
                .ok_or_else(|| {
                    blocked(
                        "signed result references a missing proof job in its financial directory",
                    )
                })?;
            if !signed_matches_proof(item, proof) {
                return Err(blocked(
                    "signed result conflicts with its exact proved checkpoint, account roster or manifest",
                ));
            }
            result
                .accounts
                .extend(item.context.account_ids.iter().cloned());
            result.bindings.push(serde_json::json!({"component":format!("{prefix}-signed"), "result_id":item.result_id,
                "request":item.request_digest, "scope_digest":item.scope_digest, "context":item.context,
                "signature_set":item.signature_set_digest,"maximum_actions":item.maximum_actions,"result":item.retained_result_digest}));
        }
        for item in &transactions {
            observe_retained_identity(
                &mut transaction_identities,
                &item.checkpoint_id,
                serde_json::json!({"request":item.request_digest,"signed_result":item.signed_result_id,
                    "signed_request":item.signed_request_digest,"signed_candidate":item.signed_candidate_digest,
                    "signature_set":item.signature_set_digest,"context":item.context}),
                match (
                    &item.retained_transaction_digest,
                    &item.retained_transaction_id,
                ) {
                    (Some(digest), Some(id)) => Some(format!("{digest}:{id}")),
                    (None, None) => None,
                    _ => return Err(blocked("partial retained transaction identity")),
                },
            )?;
            let signed = signed.iter().find(|s| s.result_id == item.signed_result_id)
                .ok_or_else(|| blocked("transaction intent references a missing signed result in its financial directory"))?;
            if item.signed_request_digest != signed.request_digest
                || Some(&item.signed_candidate_digest) != signed.retained_result_digest.as_ref()
                || item.signature_set_digest != signed.signature_set_digest
                || serde_json::to_value(&item.context)? != serde_json::to_value(&signed.context)?
            {
                return Err(blocked(
                    "transaction intent contradicts its exact retained signed result",
                ));
            }
            result
                .accounts
                .extend(item.context.account_ids.iter().cloned());
            result.bindings.push(serde_json::json!({"component":format!("{prefix}-transactions"),"checkpoint":item.checkpoint_id,
                "request":item.request_digest,"signed_result":item.signed_result_id,"signed_request":item.signed_request_digest,
                "signed_candidate":item.signed_candidate_digest,"context":item.context,"signature_set":item.signature_set_digest,
                "transaction_digest":item.retained_transaction_digest,"transaction_id":item.retained_transaction_id}));
            match (
                &item.retained_transaction_id,
                &item.retained_transaction_digest,
            ) {
                (Some(id), Some(digest)) => result.transactions.push(ExactTransaction {
                    prefix: prefix.clone(),
                    checkpoint_id: item.checkpoint_id.clone(),
                    candidate_id: item.context.candidate_id.clone(),
                    manifest_digest: item.context.manifest_digest.clone(),
                    transaction_id: id.clone(),
                    bytes_digest: digest.clone(),
                }),
                (None, None) => {}
                _ => {
                    return Err(blocked(
                        "partial transaction identity cannot be treated as an absent transaction",
                    ));
                }
            }
        }
    }
    for attempt in semantic.attempts() {
        if attempt
            .job_id
            .as_ref()
            .is_some_and(|id| !observed_jobs.contains(id))
        {
            return Err(blocked(
                "coordination retains a proof/checkpoint reference whose original financial artifact is missing",
            ));
        }
        if let (Some(id), Some(digest)) =
            (&attempt.transaction_id, &attempt.transaction_bytes_digest)
        {
            if !result.transactions.iter().any(|t| {
                &t.transaction_id == id
                    && &t.bytes_digest == digest
                    && t.candidate_id == attempt.candidate_id
                    && t.manifest_digest == attempt.manifest_digest
            }) {
                return Err(blocked(
                    "participant record references an exact transaction missing from its retained artifacts",
                ));
            }
        } else if attempt.transaction_id.is_some() || attempt.transaction_bytes_digest.is_some() {
            return Err(blocked("partial coordination transaction reference"));
        }
    }
    Ok(result)
}
#[cfg(feature = "financial-runtime")]
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConstructorReceipt {
    job_id: String,
    scope_digest: String,
    principal_id: String,
    candidate_id: String,
    manifest_digest: String,
    coordination_request_digest: String,
    artifact_digest: String,
    review_binding: String,
    effects_commitment: String,
    prepared_revision: u64,
}
#[cfg(feature = "financial-runtime")]
#[derive(PartialEq, Eq)]
struct ConstructorBinding {
    receipt: ConstructorReceipt,
    accounts: Vec<String>,
    local_operator: Option<String>,
}
#[cfg(feature = "financial-runtime")]
impl ConstructorBinding {
    fn matches(&self, proof: &wholepact_proof_jobs::backup::ProofRecoveryReference) -> bool {
        let r = &self.receipt;
        let s = &proof.scope;
        r.job_id == proof.job_id
            && r.scope_digest == proof.scope_digest
            && r.principal_id == s.principal_id
            && r.candidate_id == s.candidate_id
            && r.manifest_digest == s.manifest_digest
            && r.coordination_request_digest == s.coordination_request_digest
            && r.artifact_digest == s.artifact_digest
            && r.review_binding == s.review_binding
            && r.effects_commitment == s.effects_commitment
            && self.accounts == s.account_ids
            && self.local_operator.as_ref() == Some(&s.local_operator)
    }
}
#[cfg(feature = "financial-runtime")]
fn coordination_checkpoint_bindings(
    semantic: &CoordinationRecoveryInventory,
) -> Result<BTreeMap<String, ConstructorBinding>> {
    let mut output = BTreeMap::new();
    let store = semantic.store_inventory();
    // The owning engine already strictly decoded every complete envelope. Decode
    // only its known immutable receipt/view types to retain exact cross-journal
    // provenance, rather than trusting a caller-supplied manifest digest.
    for record in store
        .agreements()
        .iter()
        .chain(store.historical_agreements())
    {
        let view: wholepact_engine::AgreementView = serde_json::from_value(
            record
                .payload
                .get("view")
                .cloned()
                .ok_or_else(|| blocked("validated coordination envelope lacks its view"))?,
        )?;
        let receipts: BTreeMap<String, ConstructorReceipt> = serde_json::from_value(
            record
                .payload
                .get("checkpoint_receipts")
                .cloned()
                .ok_or_else(|| {
                    blocked("validated coordination envelope lacks constructor receipt inventory")
                })?,
        )?;
        for (receipt_key, receipt) in receipts {
            let candidate = view
                .candidates
                .iter()
                .find(|c| c.candidate_id == receipt.candidate_id)
                .ok_or_else(|| blocked("constructor receipt references an absent proposal"))?;
            let job_id = constructor_job_index(&receipt_key, &receipt)?;
            if receipt.manifest_digest != candidate.manifest_digest
                || receipt.prepared_revision > record.revision
            {
                return Err(blocked(
                    "constructor receipt has a conflicting proposal or revision",
                ));
            }
            // Temporary lookup only: persisted receipt keys remain untouched.
            // Downstream private journal references use the distinct job ID.
            let binding = ConstructorBinding {
                receipt,
                accounts: candidate
                    .proposal
                    .manifest
                    .participants
                    .iter()
                    .map(|p| p.account_id.clone())
                    .collect(),
                local_operator: candidate
                    .proposal
                    .manifest
                    .agreement
                    .privacy_profile
                    .proving_operator
                    .clone(),
            };
            if let Some(old) = output.get(&job_id) {
                if old != &binding {
                    return Err(blocked(
                        "one proof job has contradictory retained constructor receipts",
                    ));
                }
            } else {
                output.insert(job_id, binding);
            }
        }
    }
    Ok(output)
}
#[cfg(feature = "financial-runtime")]
fn constructor_job_index(receipt_key: &str, receipt: &ConstructorReceipt) -> Result<String> {
    if !wholepact_engine::candidates::valid_checkpoint_receipt_index(receipt_key, &receipt.job_id) {
        return Err(blocked(
            "constructor receipt storage key or proof job ID uses an invalid identity domain",
        ));
    }
    Ok(receipt.job_id.clone())
}
#[cfg(feature = "financial-runtime")]
fn signed_matches_proof(
    signed: &wholepact_protocol::authorization::retention::backup::SignedRecoveryReference,
    proof: &wholepact_proof_jobs::backup::ProofRecoveryReference,
) -> bool {
    let c = &signed.context;
    c.proof_job_id == proof.job_id
        && c.checkpoint_scope_digest == proof.scope_digest
        && Some(&c.proved_artifact_digest) == proof.retained_result_digest.as_ref()
        && c.principal_id == proof.scope.principal_id
        && c.candidate_id == proof.scope.candidate_id
        && c.manifest_digest == proof.scope.manifest_digest
        && c.review_binding == proof.scope.review_binding
        && c.account_ids == proof.scope.account_ids
}

fn table<'a>(source: Source<'a>, name: &str, columns: &[&str]) -> Result<&'a RecoveryTable> {
    let table = source
        .tables()
        .iter()
        .find(|t| t.name() == name)
        .ok_or_else(|| blocked("submission component lacks an expected table"))?;
    if table
        .columns()
        .iter()
        .map(String::as_str)
        .ne(columns.iter().copied())
    {
        return Err(blocked("submission table has an unsupported column schema"));
    }
    Ok(table)
}
fn text(cell: Option<&RecoveryCell>) -> Result<&str> {
    match cell {
        Some(RecoveryCell::Text(s)) => Ok(s),
        _ => Err(blocked("submission row has a malformed text field")),
    }
}
fn integer(cell: Option<&RecoveryCell>) -> Result<i64> {
    match cell {
        Some(RecoveryCell::Integer(n)) => Ok(*n),
        _ => Err(blocked("submission row has a malformed integer field")),
    }
}
fn report(raw: &str, descriptor: &wholepact_chain::SubmissionDescriptor) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let report: wholepact_chain::ReconciliationReport = serde_json::from_value(value.clone())?;
    if serde_json::to_value(&report)? != value
        || report.transaction_id != descriptor.transaction_id
        || report.expiry_height != descriptor.expiry_height
    {
        return Err(blocked(
            "historical observation contradicts its exact submission descriptor",
        ));
    }
    wholepact_chain::SettlementReconciler::restore(report).map_err(|_| {
        blocked("unsupported historical observation cannot establish current settlement")
    })?;
    Ok(())
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SettlementPayload {
    journal_identity: String,
    descriptor: wholepact_chain::SubmissionDescriptor,
    report: wholepact_chain::ReconciliationReport,
    observations: Vec<serde_json::Value>,
}
fn submission_has_exact_dependency(
    descriptor: &wholepact_chain::SubmissionDescriptor,
    obligations: &BTreeSet<String>,
    attempts: &[wholepact_engine::recovery::RecoveryAttempt],
    transactions: &[ExactTransaction],
) -> bool {
    obligations.contains(&descriptor.obligation_id)
        && transactions.iter().any(|t| {
            t.transaction_id == descriptor.transaction_id
                && t.bytes_digest == descriptor.bytes_sha256
                && t.candidate_id == descriptor.proposal_id
                && attempts.iter().any(|a| {
                    a.candidate_id == descriptor.proposal_id
                        && a.obligation_id == descriptor.obligation_id
                        && a.manifest_digest == t.manifest_digest
                })
        })
}
fn inspect_submissions(
    source: Source<'_>,
    semantic: &CoordinationRecoveryInventory,
    transactions: &[ExactTransaction],
) -> Result<Vec<wholepact_chain::SubmissionDescriptor>> {
    let p = source.provenance();
    if p.application_id != wholepact_chain::backup::TEMPLATE.application_id
        || p.schema_version != wholepact_chain::backup::TEMPLATE.schema_version
    {
        return Err(blocked("submission journal uses an unsupported schema"));
    }
    let intents = table(
        source,
        "submission_intents",
        &["operation", "bytes", "digest", "state"],
    )?;
    let bindings = table(
        source,
        "submission_bindings",
        &["operation", "obligation", "descriptor"],
    )?;
    if intents.rows().len() > 1024 || intents.rows().len() != bindings.rows().len() {
        return Err(blocked(
            "unbound or orphaned legacy submission intent has no verified obligation/transaction dependency",
        ));
    }
    let mut exact = BTreeMap::new();
    for row in intents.rows() {
        let cells = row.cells();
        let operation = text(cells.first())?;
        let Some(RecoveryCell::Blob(bytes)) = cells.get(1) else {
            return Err(blocked("submission bytes are missing"));
        };
        let intent = wholepact_chain::ExactSubmissionIntent::new(operation, bytes)
            .map_err(|_| blocked("submission intent is malformed or exceeds supported bounds"))?;
        if intent.bytes_sha256() != text(cells.get(2))?
            || !(0..=2).contains(&integer(cells.get(3))?)
            || exact.insert(operation, intent).is_some()
        {
            return Err(blocked("submission intent digest/state is inconsistent"));
        }
    }
    let mut descriptors = BTreeMap::new();
    for row in bindings.rows() {
        let cells = row.cells();
        let operation = text(cells.first())?;
        let descriptor: wholepact_chain::SubmissionDescriptor =
            serde_json::from_str(text(cells.get(2))?)?;
        let intent = exact
            .get(operation)
            .ok_or_else(|| blocked("orphaned submission descriptor"))?;
        let plan = wholepact_chain::SubmissionPlan::new(
            &descriptor.obligation_id,
            &descriptor.proposal_id,
            operation,
            intent.exact_bytes(),
        )
        .map_err(|_| {
            blocked("exact submission bytes use unsupported or malformed transaction encoding")
        })?;
        if plan.descriptor() != &descriptor
            || text(cells.get(1))? != descriptor.obligation_id
            || !submission_has_exact_dependency(
                &descriptor,
                semantic.obligations(),
                semantic.attempts(),
                transactions,
            )
            || descriptors
                .insert(operation.to_owned(), descriptor)
                .is_some()
        {
            return Err(blocked(
                "submission descriptor has no exact retained transaction/proposal/obligation match",
            ));
        }
    }
    for row in table(
        source,
        "submission_attempts",
        &["operation", "number", "source", "started", "outcome"],
    )?
    .rows()
    {
        let c = row.cells();
        if !descriptors.contains_key(text(c.first())?)
            || !(1..=128).contains(&integer(c.get(1))?)
            || integer(c.get(3))? < 0
        {
            return Err(blocked(
                "orphaned or malformed historical submission attempt",
            ));
        }
        crate::id(text(c.get(2))?)?;
        let _: wholepact_chain::SubmissionAttemptOutcome = serde_json::from_str(text(c.get(4))?)?;
    }
    for row in table(source, "submission_observations", &["operation", "report"])?.rows() {
        let c = row.cells();
        let descriptor = descriptors
            .get(text(c.first())?)
            .ok_or_else(|| blocked("orphaned submission observation"))?;
        report(text(c.get(1))?, descriptor)?;
    }
    let identities = table(
        source,
        "submission_journal_identity",
        &["singleton", "identity"],
    )?;
    if identities.rows().len() != 1 || integer(identities.rows()[0].cells().first())? != 1 {
        return Err(blocked(
            "submission journal identity is missing or ambiguous",
        ));
    }
    let identity = text(identities.rows()[0].cells().get(1))?;
    if identity.len() != 64
        || !identity
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(blocked("submission journal identity is malformed"));
    }
    let mut evidence_ids = BTreeSet::new();
    for row in table(
        source,
        "settlement_evidence",
        &["sequence", "evidence_id", "operation", "payload"],
    )?
    .rows()
    {
        let c = row.cells();
        let raw = text(c.get(3))?;
        let payload: SettlementPayload = serde_json::from_str(raw)?;
        let descriptor = descriptors
            .get(text(c.get(2))?)
            .ok_or_else(|| blocked("orphaned historical settlement evidence"))?;
        let id = text(c.get(1))?;
        if serde_json::to_value(&payload)? != serde_json::from_str::<serde_json::Value>(raw)?
            || integer(c.first())? <= 0
            || hash(raw.as_bytes()) != id
            || !evidence_ids.insert(id)
            || payload.journal_identity != identity
            || &payload.descriptor != descriptor
            || payload.observations.len() > 8
        {
            return Err(blocked(
                "historical settlement evidence conflicts with its source identity or exact transaction",
            ));
        }
        report(&serde_json::to_string(&payload.report)?, descriptor)?;
    }
    for row in table(
        source,
        "settlement_deliveries",
        &["evidence_id", "destination", "acknowledged"],
    )?
    .rows()
    {
        let c = row.cells();
        if !evidence_ids.contains(text(c.first())?) || !(0..=1).contains(&integer(c.get(2))?) {
            return Err(blocked("orphaned historical settlement delivery"));
        }
        crate::id(text(c.get(1))?)?;
    }
    Ok(descriptors.into_values().collect())
}

#[cfg(all(test, feature = "financial-runtime"))]
mod tests {
    use super::*;
    use wholepact_proof_jobs::{CheckpointScope, JobState, backup::ProofRecoveryReference};
    use wholepact_protocol::authorization::retention::{
        SignedCandidateContext, backup::SignedRecoveryReference,
    };

    #[test]
    fn archived_artifact_repetition_preserves_identity_and_unknown_progress() {
        let mut seen = BTreeMap::new();
        let identity = serde_json::json!({"scope":"synthetic-scope","request":"synthetic-request"});
        observe_retained_identity(&mut seen, "synthetic-job", identity.clone(), None).unwrap();
        observe_retained_identity(
            &mut seen,
            "synthetic-job",
            identity.clone(),
            Some("synthetic-result".into()),
        )
        .unwrap();
        observe_retained_identity(&mut seen, "synthetic-job", identity.clone(), None).unwrap();
        assert!(
            observe_retained_identity(
                &mut seen,
                "synthetic-job",
                identity,
                Some("conflicting-result".into())
            )
            .is_err()
        );
        assert!(
            observe_retained_identity(
                &mut seen,
                "synthetic-job",
                serde_json::json!({"scope":"changed-scope","request":"synthetic-request"}),
                None
            )
            .is_err()
        );
    }

    // Metadata-only synthetic fixtures: these exercise the exact join predicate,
    // not parser/proof validation, native approval, network or settlement.
    fn references() -> (ProofRecoveryReference, SignedRecoveryReference) {
        let scope = CheckpointScope {
            principal_id: "synthetic-owner".into(),
            candidate_id: "synthetic-candidate".into(),
            manifest_digest: "11".repeat(32),
            artifact_digest: "22".repeat(32),
            effects_commitment: "33".repeat(32),
            coordination_request_digest: "44".repeat(32),
            review_binding: "55".repeat(32),
            account_ids: vec!["synthetic-account".into()],
            local_operator: "synthetic-operator".into(),
            purpose: "proof".into(),
            retention_policy: "private".into(),
        };
        let proof = ProofRecoveryReference {
            job_id: "synthetic-job".into(),
            scope_digest: "66".repeat(32),
            request_digest: "77".repeat(32),
            scope,
            historical_state: JobState::Succeeded,
            retained_result_digest: Some("88".repeat(32)),
        };
        let signed = SignedRecoveryReference {
            result_id: "synthetic-result".into(),
            request_digest: "99".repeat(32),
            scope_digest: "aa".repeat(32),
            context: SignedCandidateContext {
                principal_id: proof.scope.principal_id.clone(),
                candidate_id: proof.scope.candidate_id.clone(),
                proof_job_id: proof.job_id.clone(),
                checkpoint_scope_digest: proof.scope_digest.clone(),
                proved_artifact_digest: proof.retained_result_digest.clone().unwrap(),
                manifest_digest: proof.scope.manifest_digest.clone(),
                review_binding: proof.scope.review_binding.clone(),
                delivery_provenance_digest: "bb".repeat(32),
                account_ids: proof.scope.account_ids.clone(),
                local_operator: "synthetic-operator".into(),
                purpose: "signed retention".into(),
                retention_policy: "private".into(),
            },
            signature_set_digest: "cc".repeat(32),
            maximum_actions: 8,
            retained_result_digest: Some("dd".repeat(32)),
        };
        (proof, signed)
    }
    #[test]
    fn signed_recovery_join_rejects_missing_proof_output_and_scope_rebinding() {
        let (mut proof, mut signed) = references();
        assert!(signed_matches_proof(&signed, &proof));
        proof.retained_result_digest = None;
        assert!(!signed_matches_proof(&signed, &proof));
        let (proof, _) = references();
        signed.context.account_ids.push("unreviewed-account".into());
        assert!(!signed_matches_proof(&signed, &proof));
        let (_, mut signed) = references();
        signed.context.manifest_digest = "ee".repeat(32);
        assert!(!signed_matches_proof(&signed, &proof));
        let (_, mut signed) = references();
        signed.context.checkpoint_scope_digest = "ff".repeat(32);
        assert!(!signed_matches_proof(&signed, &proof));
        let (_, mut signed) = references();
        signed.context.proof_job_id = "other-job".into();
        assert!(!signed_matches_proof(&signed, &proof));
    }
    #[test]
    fn constructor_receipt_lookup_uses_job_identity_without_rekeying_storage() {
        let (proof, _) = references();
        let scope = &proof.scope;
        let job_id = wholepact_proof_jobs::job_id_for_key(
            "synthetic-controller",
            "synthetic-original-construction",
        )
        .unwrap();
        let receipt = ConstructorReceipt {
            job_id: job_id.clone(),
            scope_digest: proof.scope_digest,
            principal_id: scope.principal_id.clone(),
            candidate_id: scope.candidate_id.clone(),
            manifest_digest: scope.manifest_digest.clone(),
            coordination_request_digest: scope.coordination_request_digest.clone(),
            artifact_digest: scope.artifact_digest.clone(),
            review_binding: scope.review_binding.clone(),
            effects_commitment: scope.effects_commitment.clone(),
            prepared_revision: 2,
        };
        let storage_key = "a1".repeat(32);
        assert_ne!(storage_key, job_id);
        assert_eq!(
            constructor_job_index(&storage_key, &receipt).unwrap(),
            job_id
        );
        assert!(constructor_job_index(&job_id, &receipt).is_err());
        assert!(constructor_job_index("short", &receipt).is_err());
        let malformed = ConstructorReceipt {
            job_id: storage_key.clone(),
            ..receipt
        };
        assert!(constructor_job_index(&storage_key, &malformed).is_err());
    }
    #[test]
    fn constructor_scope_and_submission_dependencies_cannot_be_rebound() {
        let (mut proof, _) = references();
        let scope = &proof.scope;
        let binding = ConstructorBinding {
            receipt: ConstructorReceipt {
                job_id: proof.job_id.clone(),
                scope_digest: proof.scope_digest.clone(),
                principal_id: scope.principal_id.clone(),
                candidate_id: scope.candidate_id.clone(),
                manifest_digest: scope.manifest_digest.clone(),
                coordination_request_digest: scope.coordination_request_digest.clone(),
                artifact_digest: scope.artifact_digest.clone(),
                review_binding: scope.review_binding.clone(),
                effects_commitment: scope.effects_commitment.clone(),
                prepared_revision: 2,
            },
            accounts: scope.account_ids.clone(),
            local_operator: Some(scope.local_operator.clone()),
        };
        assert!(binding.matches(&proof));
        proof.scope.principal_id = "other-principal".into();
        assert!(!binding.matches(&proof));
        let (mut proof, _) = references();
        proof.scope.coordination_request_digest = "ff".repeat(32);
        assert!(!binding.matches(&proof));
        let (mut proof, _) = references();
        proof.scope.account_ids.push("other-account".into());
        assert!(!binding.matches(&proof));

        let descriptor = wholepact_chain::SubmissionDescriptor {
            operation_id: "synthetic-operation".into(),
            obligation_id: "synthetic-obligation".into(),
            proposal_id: "synthetic-candidate".into(),
            transaction_id: "11".repeat(32),
            bytes_sha256: "22".repeat(32),
            expiry_height: 100,
            network: "testnet".into(),
            consensus_branch_id: 0,
        };
        let obligations = [descriptor.obligation_id.clone()].into_iter().collect();
        let attempts = vec![wholepact_engine::recovery::RecoveryAttempt {
            agreement_id: "synthetic-agreement".into(),
            obligation_id: descriptor.obligation_id.clone(),
            candidate_id: descriptor.proposal_id.clone(),
            manifest_digest: "33".repeat(32),
            job_id: None,
            artifact_digest: None,
            transaction_id: None,
            transaction_bytes_digest: None,
            account_id: None,
            authorization_id: None,
            release_operation_id: None,
        }];
        let mut transactions = vec![ExactTransaction {
            prefix: "financial-0".into(),
            checkpoint_id: "synthetic-checkpoint".into(),
            candidate_id: descriptor.proposal_id.clone(),
            manifest_digest: attempts[0].manifest_digest.clone(),
            transaction_id: descriptor.transaction_id.clone(),
            bytes_digest: descriptor.bytes_sha256.clone(),
        }];
        assert!(submission_has_exact_dependency(
            &descriptor,
            &obligations,
            &attempts,
            &transactions
        ));
        assert!(!submission_has_exact_dependency(
            &descriptor,
            &obligations,
            &attempts,
            &[]
        ));
        transactions[0].bytes_digest = "44".repeat(32);
        assert!(!submission_has_exact_dependency(
            &descriptor,
            &obligations,
            &attempts,
            &transactions
        ));
        transactions[0].bytes_digest = descriptor.bytes_sha256.clone();
        transactions[0].manifest_digest = "55".repeat(32);
        assert!(!submission_has_exact_dependency(
            &descriptor,
            &obligations,
            &attempts,
            &transactions
        ));
    }
}
