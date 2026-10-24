//! Explicit same-original financial journal profile. Schema19 admission data is
//! never rewritten. Ordinary current19 readers continue to refuse this profile.
//! Custody and retained intent are not live signing or dispatch authority.
use super::*;
use wholepact_authority::{account_use::AccountUseGenesis, durable_financial_continuation_v1::FinancialContinuationTermsV1, ReconciledAuthorityHistory};
use crate::native_ui::financial_authority_v1::FinancialContinuationReviewV1;

pub(super) const VERSION: i64 = 20;
const EXTENSION: &str = include_str!("financial_profile_v1.sql");
const TABLE: &str = "signer_financial_continuation_intents";
const COLUMNS: &[&str] = &["operation_id", "authorization_id", "original_admission_operation_id", "request_digest", "enrollment_ref", "manifest_ref", "payload"];
#[path = "financial_continuation_v1.rs"]
mod intent;
#[path = "financial_original_delivery_v1.rs"]
pub(in crate::consent_journal) mod original_delivery;
#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "financial_coordinated_v3_audit_v1.rs"]
mod coordinated_v3_audit;
#[path = "financial_coordinated_continue_v1.rs"]
mod coordinated_continue;
#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "financial_coordinated_public_pin_v2.rs"]
mod coordinated_public_pin;
pub(crate) use coordinated_continue::{CoordinatedContinueReviewDataV1, CoordinatedContinueSignerRoleV1, PreparedCoordinatedFinancialContinuationV1};
#[cfg(feature = "coordinated-signer-continue")]
pub(crate) use coordinated_continue::{PresentedCoordinatedFinancialContinuationV1, CoordinatedContinuationCommitFailureV1};
#[path = "financial_bridge_storage_v1.rs"]
mod bridge;
#[path = "financial_return_pin_v1.rs"]
mod return_pin;
pub(crate) use return_pin::FinancialReturnJournalPinV1;
#[path = "financial_admission_pin_v1.rs"]
mod admission_pin;
pub(crate) use admission_pin::FinancialAdmissionJournalPinV1;
#[path = "financial_operation_pin_v1.rs"]
mod operation_pin;
pub(crate) use operation_pin::FinancialOperationJournalPinV1;
#[path = "financial_session_v1.rs"]
mod session;
pub(crate) use session::{ApprovedFinancialSpendConsentV1, PreparedFinancialSpendV1};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(crate) use session::{PreparedCoordinatedFinancialSpendV1, PresentedCoordinatedFinancialSpendV1, ApprovedCoordinatedFinancialSpendConsentV1};
pub(crate) use intent::{PreparedFinancialContinuationIntentV1, RetainedFinancialContinuationIntentV1};

/// No Clone/serde/path constructor. Issued only from an actual validated
/// original journal and consumed by its explicit transition.
pub(crate) struct FinancialSourceBindingV1 {
    journal: SignerJournalBinding,
    identity: wholepact_storage_security::DatabaseFileIdentity,
    genesis: AccountUseGenesis,
    source_digest: String,
    original_rows_digest: String,
    continuation_digest: Option<String>,
    revision: FinancialJournalRevisionV1,
}
/// Stable inert originals only: no connection binding, source registration,
/// revision tuple, random source identity, continuation or authority owner.
#[cfg(feature = "coordinated-signer-continue")]
pub(crate) struct OriginalFinancialJournalSelectionV1 {
    identity: wholepact_storage_security::DatabaseFileIdentity,
    genesis: AccountUseGenesis,
    original_rows_digest: String,
}
#[cfg(feature = "coordinated-signer-continue")]
impl OriginalFinancialJournalSelectionV1 {
    pub(crate) fn digest(&self) -> Result<String> {
        digest("wholepact:original-financial-reentry-journal:v1", &(
            hex::encode(self.identity.origin_commitment()), &self.genesis, &self.original_rows_digest,
        ))
    }
    /// New source authentication/currentness is the caller's prerequisite.
    /// Do not compare connection-local revisions or random source identities.
    pub(crate) fn require_reopened(&self, reopened: &FinancialSourceBindingV1) -> Result<()> {
        if reopened.continuation_digest.is_some()
            || self.identity != reopened.identity || self.genesis != reopened.genesis
            || self.original_rows_digest != reopened.original_rows_digest
        { return Err(JournalError::Conflict); }
        Ok(())
    }
}
#[derive(PartialEq, Eq)]
struct FinancialJournalRevisionV1 { data_version: i64, total_changes: i64, schema_version: i64, user_version: i64 }
fn revision(c: &Connection) -> Result<FinancialJournalRevisionV1> {
    Ok(FinancialJournalRevisionV1 {
        data_version: c.pragma_query_value(None,"data_version",|r|r.get(0))?,
        total_changes: c.query_row("SELECT total_changes()",[],|r|r.get(0))?,
        schema_version: c.pragma_query_value(None,"schema_version",|r|r.get(0))?,
        user_version: c.pragma_query_value(None,"user_version",|r|r.get(0))?,
    })
}
impl FinancialSourceBindingV1 {
    pub(crate) fn identity_digest(&self) -> &str { &self.source_digest }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis { &self.genesis }
    /// Stable selection evidence only. A fresh source still requires its own
    /// full original-file audit and genuine source-entry permission.
    #[cfg(feature = "coordinated-signer-continue")]
    pub(crate) fn original_reentry_selection_v1(&self) -> Result<OriginalFinancialJournalSelectionV1> {
        if self.continuation_digest.is_some() { return Err(JournalError::RecoveryRequired); }
        Ok(OriginalFinancialJournalSelectionV1 {
            identity: self.identity.clone(), genesis: self.genesis.clone(),
            original_rows_digest: self.original_rows_digest.clone(),
        })
    }
    fn require_pin(&self, c: &Connection) -> Result<()> {
        if self.revision != revision(c)? { return Err(JournalError::Conflict); }
        if let Some(expected) = &self.continuation_digest {
            if intent::read(c)?.history_digest()? != *expected { return Err(JournalError::Conflict); }
        }
        Ok(())
    }
    fn require(&self, journal: &SignerConsentJournal, c: &Connection) -> Result<()> {
        if self.journal != journal.binding() || self.identity != journal.database_identity { return Err(JournalError::Permission); }
        journal.source_registration.owner.directory.check_current().map_err(|_| JournalError::Permission)?;
        self.identity.check_current(c)?;
        Ok(())
    }
}

/// Exclusive purpose-specific wrapper. It deliberately exposes neither Deref,
/// a generic journal getter, a raw connection nor a storage key.
pub(crate) struct FinancialConsentJournalV1 {
    journal: SignerConsentJournal,
    genesis: AccountUseGenesis,
}

/// Exact locally committed intent and source pin, never an action owner.
/// The ContinueExact owner ends at local commit. Admission requires a separate
/// fresh AdmitExact decision after the independent Witness review.
pub(crate) struct PendingFinancialContinuationAdmissionV1 {
    source: FinancialSourceBindingV1,
    retained: RetainedFinancialContinuationIntentV1,
}
impl PendingFinancialContinuationAdmissionV1 {
    pub(crate) fn request(&self) -> &wholepact_authority::OwnerControlRequest { self.retained.request() }
    pub(crate) fn admission_terms_digest(&self, source_identity: &str) -> Result<String> {
        hash(source_identity)?;
        digest("wholepact:financial-admit-retained-continuation:v1", &(source_identity, self.request(), self.retained.history_digest()?))
    }
    pub(crate) fn check_current(&self, journal: &FinancialConsentJournalV1) -> Result<()> {
        let _fence = journal.journal.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = journal.journal.connection.lock().map_err(|_| JournalError::Database)?;
        self.source.require(&journal.journal, &c)?;
        self.source.require_pin(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate(&tx, &journal.genesis)?;
        if intent::read(&tx)? != self.retained { return Err(JournalError::Conflict); }
        self.retained.terms()?.require_live(now_ms()?).map_err(|_| JournalError::Expired)?;
        self.source.require_pin(&tx)?;
        tx.commit()?;
        self.source.require_pin(&c)?;
        Ok(())
    }
}

impl SignerConsentJournal {
    pub(crate) fn prepare_financial_source_binding_v1(&self, genesis: &AccountUseGenesis) -> Result<FinancialSourceBindingV1> {
        let _fence = self.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        self.database_identity.check_current(&c)?;
        let before = revision(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        durable_born_entry_v1::validate_delivery_v3(&tx, genesis, self.capacity_limits())?;
        if financial_admission_intents::read_all(&tx)?.len() != 1 { return Err(JournalError::RecoveryRequired); }
        let original_rows_digest = original_rows_digest(&tx)?;
        self.database_identity.check_current(&tx)?;
        tx.commit()?;
        if revision(&c)? != before { return Err(JournalError::Conflict); }
        Ok(FinancialSourceBindingV1 { journal: self.binding(), identity: self.database_identity.clone(), genesis: genesis.clone(),
            source_digest: digest("wholepact:original-financial-source:v1", &(genesis, &original_rows_digest, random_id()?))?, original_rows_digest, continuation_digest: None, revision: before })
    }
    pub(crate) fn check_financial_source_binding_v1(&self, source: &FinancialSourceBindingV1) -> Result<()> {
        let _fence = self.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        source.require(self, &c)?;
        source.require_pin(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        durable_born_entry_v1::validate_delivery_v3(&tx, &source.genesis, self.capacity_limits())?;
        if original_rows_digest(&tx)? != source.original_rows_digest { return Err(JournalError::Conflict); }
        source.require(self, &tx)?;
        source.require_pin(&tx)?;
        tx.commit()?;
        source.require_pin(&c)?;
        Ok(())
    }
    pub(crate) fn prepare_financial_continuation_intent_v1(&self, source: &FinancialSourceBindingV1,
        terms: FinancialContinuationTermsV1, review: FinancialContinuationReviewV1, history: &ReconciledAuthorityHistory,
    ) -> Result<PreparedFinancialContinuationIntentV1> {
        let _fence = self.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        source.require(self, &c)?;
        source.require_pin(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        durable_born_entry_v1::validate_delivery_v3(&tx, &source.genesis, self.capacity_limits())?;
        if original_rows_digest(&tx)? != source.original_rows_digest { return Err(JournalError::Conflict); }
        let prepared = intent::prepare(&tx, self.binding(), source, terms, review, history)?;
        source.require(self, &tx)?;
        source.require_pin(&tx)?;
        tx.commit()?;
        source.require_pin(&c)?;
        Ok(prepared)
    }
}

impl FinancialConsentJournalV1 {
    pub(crate) fn prepare_financial_source_binding_v1(&self) -> Result<FinancialSourceBindingV1> {
        let _fence = self.journal.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.journal.connection.lock().map_err(|_| JournalError::Database)?;
        self.journal.database_identity.check_current(&c)?;
        let before = revision(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate(&tx, &self.genesis)?;
        let original_rows_digest = original_rows_digest(&tx)?;
        let continuation_digest = intent::read(&tx)?.history_digest()?;
        self.journal.database_identity.check_current(&tx)?;
        tx.commit()?;
        if revision(&c)? != before { return Err(JournalError::Conflict); }
        Ok(FinancialSourceBindingV1 { journal: self.journal.binding(), identity: self.journal.database_identity.clone(), genesis: self.genesis.clone(),
            source_digest: digest("wholepact:original-financial-source:v1", &(&self.genesis, &original_rows_digest, &continuation_digest, random_id()?))?, original_rows_digest, continuation_digest: Some(continuation_digest), revision: before })
    }
    pub(crate) fn check_financial_source_binding_v1(&self, source: &FinancialSourceBindingV1) -> Result<()> {
        let _fence = self.journal.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.journal.connection.lock().map_err(|_| JournalError::Database)?;
        source.require(&self.journal, &c)?;
        source.require_pin(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate(&tx, &source.genesis)?;
        if original_rows_digest(&tx)? != source.original_rows_digest { return Err(JournalError::Conflict); }
        source.require(&self.journal, &tx)?;
        source.require_pin(&tx)?;
        tx.commit()?;
        source.require_pin(&c)?;
        Ok(())
    }
    pub(crate) fn transition_original(journal: SignerConsentJournal, mut source: FinancialSourceBindingV1,
        prepared: PreparedFinancialContinuationIntentV1,
    ) -> Result<(Self, PendingFinancialContinuationAdmissionV1)> {
        // No outstanding old-source revision token or second registered handle
        // may survive an explicit profile transition.
        if Arc::strong_count(&journal.source_registration) != 1 { return Err(JournalError::Conflict); }
        let retained;
        {
            let _fence = journal.authority_fence.write().map_err(|_| JournalError::Permission)?;
            let mut c = journal.connection.lock().map_err(|_| JournalError::Database)?;
            source.require(&journal, &c)?;
            source.require_pin(&c)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            durable_born_entry_v1::validate_delivery_v3(&tx, &source.genesis, journal.capacity_limits())?;
            if original_rows_digest(&tx)? != source.original_rows_digest { return Err(JournalError::Conflict); }
            prepared.check(&journal, &source, &tx)?;
            tx.execute_batch(EXTENSION)?;
            intent::insert(&tx, &prepared)?;
            tx.pragma_update(None, "user_version", VERSION)?;
            validate(&tx, &source.genesis)?;
            if original_rows_digest(&tx)? != source.original_rows_digest { return Err(JournalError::Conflict); }
            prepared.check(&journal, &source, &tx)?;
            retained = intent::read(&tx)?;
            source.continuation_digest = Some(retained.history_digest()?);
            source.revision = revision(&tx)?;
            tx.commit()?;
            source.require_pin(&c)?;
        }
        prepared.invalidate();
        drop(prepared);
        let genesis = source.genesis.clone();
        Ok((Self { journal, genesis }, PendingFinancialContinuationAdmissionV1 { source, retained }))
    }
    /// Exact20 only, with immutable-copy preflight before touching the original.
    /// No create, upgrade, repair, fallback or empty-journal substitute.
    pub(crate) fn open_original(path: &Path, key: &DatabaseKey, genesis: &AccountUseGenesis,
        source: &Arc<SignerJournalSourceOwner>,
    ) -> Result<Self> {
        let mut owner = source.begin(path)?;
        owner.require_exclusive()?;
        let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(path, key)?;
        let original = snapshot.source_database_identity()?;
        {
            let tx = rusqlite::Transaction::new_unchecked(snapshot.connection(), TransactionBehavior::Deferred)?;
            validate(&tx, genesis)?;
            tx.commit()?;
        }
        snapshot.check_source_unchanged()?;
        owner.owner.directory.check_current().map_err(|_| JournalError::Permission)?;
        let encrypted = wholepact_storage_security::open_encrypted_quiescent(path, key)?;
        let identity = encrypted.database_identity()?;
        if identity != original { return Err(JournalError::InvalidBinding); }
        let mut c = encrypted.into_connection();
        {
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            validate(&tx, genesis)?;
            identity.check_current(&tx)?;
            tx.commit()?;
        }
        drop(snapshot);
        configure(&c)?;
        let registration = owner.register_exact_profile(&c, &identity, &genesis.identity.account_id, OriginalJournalProfile::Financial20)?;
        Ok(Self { journal: SignerConsentJournal::from_owned_source(OpenedSignerSource { connection: c, identity, registration }), genesis: genesis.clone() })
    }
    pub(crate) fn record_financial_consent_release_v1(&self, source: &mut FinancialSourceBindingV1, approved: &ApprovedFinancialSpendConsentV1) -> Result<OriginalAuthorizationEvidence> {
        approved.check_current()?;
        let record = approved.record();
        record.validate_financial_v1()?;
        let account = self.journal.account_state()?;
        let lease = approved.lease_for_journal(&self.journal.binding(), &account)?;
        let _fence = self.journal.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.journal.connection.lock().map_err(|_| JournalError::Database)?;
        source.require(&self.journal, &c)?; source.require_pin(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate(&tx, &self.genesis)?;
        check_account(&tx, &account)?;
        lease.check_current()?;
        let binding = record.financial_continuation_v1.as_ref().ok_or(JournalError::Permission)?;
        if binding.source_identity_digest != source.source_digest { return Err(JournalError::Permission); }
        let terms = record.terms();
        let enrollment = read_enrollment(&tx, &terms.enrollment_ref)?.ok_or(JournalError::NotFound)?;
        let manifest = read_manifest(&tx, &terms.accepted_manifest_ref)?.ok_or(JournalError::NotFound)?;
        let result = OriginalAuthorizationEvidence { enrollment, manifest, consent: record.clone(), release: ConsentLinkedReleaseIntent::from_consent(record) };
        validate_financial_linkage(&tx, &result)?;
        let result = append_release_rows(&tx, &result, ReleaseRowProfile::FinancialV1, self.journal.capacity_limits())?;
        validate(&tx, &self.genesis)?;
        bounded_financial(&tx)?;
        lease.check_current()?;
        source.require(&self.journal, &tx)?;
        let rows = original_rows_digest(&tx)?; let next = revision(&tx)?;
        tx.commit()?;
        source.original_rows_digest = rows; source.revision = next;
        source.require_pin(&c)?;
        Ok(result)
    }
    pub(crate) fn check_original(&self) -> Result<()> {
        let _fence = self.journal.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.journal.connection.lock().map_err(|_| JournalError::Database)?;
        self.journal.source_registration.owner.directory.check_current().map_err(|_| JournalError::Permission)?;
        self.journal.database_identity.check_current(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate(&tx, &self.genesis)?;
        self.journal.database_identity.check_current(&tx)?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn retained_continuation(&self) -> Result<RetainedFinancialContinuationIntentV1> {
        let _fence = self.journal.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.journal.connection.lock().map_err(|_| JournalError::Database)?;
        self.journal.database_identity.check_current(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate(&tx, &self.genesis)?;
        let retained = intent::read(&tx)?;
        self.journal.database_identity.check_current(&tx)?;
        tx.commit()?;
        Ok(retained)
    }
}

fn expected_schema20_objects_v1()->Result<&'static Vec<SchemaObjectV1>> {
    static EXPECTED:std::sync::OnceLock<Vec<SchemaObjectV1>>=std::sync::OnceLock::new();
    if let Some(expected)=EXPECTED.get(){return Ok(expected);}
    let built=build_expected_schema_objects_v1(EXTENSION)?;
    let _=EXPECTED.set(built);
    EXPECTED.get().ok_or(JournalError::Database)
}
pub(super) fn verify_schema(c: &Connection) -> Result<()> {
    if c.pragma_query_value::<i64, _>(None, "application_id", |r| r.get(0))? != APPLICATION_ID
        || c.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))? != VERSION { return Err(JournalError::UnsupportedSchema); }
    verify_schema_objects_v1(c,expected_schema20_objects_v1()?)?;
    bounded_financial(c)?;
    verify_retained_schema19_cells(c)?;
    construction_audit_v3::read_all(c, &read_account(c)?.account_id)?;
    common_context_reentry_audit_v1::read_complete(c, &read_account(c)?.account_id)?;
    intent::read(c)?;
    Ok(())
}
fn validate(c: &Connection, genesis: &AccountUseGenesis) -> Result<()> {
    if c.is_autocommit() { return Err(JournalError::InvalidBinding); }
    genesis.validate().map_err(|_| JournalError::InvalidBinding)?;
    verify_schema(c)?;
    let state = read_account(c)?;
    let origin = account_use_storage::inspect(c, &state.account_id)?;
    if state.account_id != genesis.identity.account_id || origin.genesis() != Some(genesis) { return Err(JournalError::InvalidBinding); }
    if state.recovery_required { return Err(JournalError::RecoveryRequired); }
    if origin.exclusion().is_some() || origin.witness_ack().is_some() { return Err(JournalError::Permission); }
    validate_financial_table_policy(c)?;
    original_delivery::validate_cells(c, genesis, &state)?;
    validate_financial_original_rows(c)?;
    bridge::validate_rows(c)?;
    let retained = intent::read(c)?;
    retained.require_original(genesis)?;
    Ok(())
}
fn bounded_financial(c: &Connection) -> Result<()> {
    let (rows, bytes) = capacity_estimate(c)?;
    let lengths = COLUMNS.iter().map(|v| format!("coalesce(length(CAST({v} AS BLOB)),0)")).collect::<Vec<_>>().join("+");
    let maxima = COLUMNS.iter().map(|v| format!("coalesce(length(CAST({v} AS BLOB)),0)")).collect::<Vec<_>>().join(",");
    let (extra_rows, extra_bytes, max_cell): (u64,u64,u64) = c.query_row(&format!("SELECT count(*),coalesce(sum({lengths}),0),coalesce(max(max({maxima},0)),0) FROM {TABLE}"), [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    if max_cell > MAX_RECORD_BYTES as u64 || rows.checked_add(extra_rows).ok_or(JournalError::Limit)? > MAX_BACKUP_ROWS
        || bytes.checked_add(extra_bytes.checked_mul(6).ok_or(JournalError::Limit)?).and_then(|v| extra_rows.checked_mul(2048).and_then(|r|v.checked_add(r))).ok_or(JournalError::Limit)? > MAX_BACKUP_ENCODED_BYTES { return Err(JournalError::Limit); }
    Ok(())
}
fn original_rows_digest(c: &Connection) -> Result<String> {
    use rusqlite::types::ValueRef;
    use sha2::{Digest, Sha256};
    fn field(h: &mut Sha256, bytes: &[u8]) { h.update((bytes.len() as u64).to_be_bytes()); h.update(bytes); }
    let mut h = Sha256::new(); h.update(b"wholepact:financial-original19-rows:v1\0");
    for (table, _) in CAPACITY_TABLES {
        field(&mut h, table.as_bytes());
        let q = c.prepare(&format!("SELECT * FROM {table}"))?;
        let columns = q.column_count(); drop(q);
        let order = (1..=columns).map(|i|i.to_string()).collect::<Vec<_>>().join(",");
        let mut q = c.prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))?;
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? { h.update([1]); for i in 0..columns { match row.get_ref(i)? {
            ValueRef::Null => h.update([0]), ValueRef::Integer(v) => { h.update([1]); h.update(v.to_be_bytes()); },
            ValueRef::Text(v) => { h.update([2]); field(&mut h,v); }, _ => return Err(JournalError::InvalidBinding),
        } } } h.update([0]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Explicit profile20 reader; the ordinary read_original path still refuses
/// these new receipts instead of treating them as the old native session.
pub(super) fn read_financial_original_v1(c: &Connection, authorization_id: &str) -> Result<Option<OriginalAuthorizationEvidence>> {
    let Some(value) = read_original_unvalidated(c, authorization_id)? else { return Ok(None); };
    validate_financial_linkage(c, &value)?;
    Ok(Some(value))
}
pub(super) fn validate_financial_linkage(c: &Connection, evidence: &OriginalAuthorizationEvidence) -> Result<()> {
    evidence.consent.validate_financial_v1()?;
    validate_economic_linkage(evidence)?;
    let retained = intent::read(c)?;
    let request = retained.request();
    let terms = retained.terms()?;
    let scope = &terms.scope;
    let fixed = &scope.authorization.fixed;
    let consent = evidence.consent.terms();
    let binding = evidence.consent.financial_continuation_v1.as_ref().ok_or(JournalError::RecoveryRequired)?;
    let wholepact_authority::OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else { return Err(JournalError::InvalidBinding); };
    let mut inert = serde_json::to_value(consent).map_err(|_| JournalError::InvalidBinding)?;
    inert.as_object_mut().ok_or(JournalError::InvalidBinding)?.remove("receipt");
    let signing_digest = digest("wholepact:financial-sign-exact-and-dispatch:v1", &(&binding.source_identity_digest, retained.history_digest()?, inert, &binding.reviewed_head, &binding.disclosure, &scope.delivery))?;
    let inputs = consent.input_bindings.iter().map(|i| wholepact_authority::InputReservation { input_id:i.input_id.clone(), nullifier:i.nullifier.clone(), action_index:i.action_index, value_zatoshis:i.value_zatoshis }).collect::<Vec<_>>();
    if binding.continuation_operation_id != request.operation_id
        || binding.continuation_request_digest != record.request_digest(request).map_err(|_| JournalError::InvalidBinding)?
        || binding.continuation_history_digest != retained.history_digest()?
        || binding.terms_digest != terms.intent_terms_digest().map_err(|_| JournalError::InvalidBinding)?
        || binding.signing_terms_digest != signing_digest || binding.disclosure != scope.witness
        || consent.authorization_id != scope.authorization.authorization_id
        || consent.enrollment_ref != terms.original_recipient_enrollment_ref || consent.accepted_manifest_ref != terms.original_recipient_manifest_ref
        || consent.account_id != scope.authorization.identity.account_id || consent.receipt.writer_epoch != scope.original_writer_epoch
        || consent.agreement_id != fixed.agreement_id || consent.obligation_id != fixed.obligation_id || consent.proposal_id != fixed.proposal_id
        || consent.proposal_digest != fixed.proposal_digest || consent.manifest_digest != fixed.manifest_digest
        || consent.effects_digest != fixed.effects_commitment || consent.artifact_digest != fixed.proved_artifact_digest
        || consent.review_binding != fixed.review_binding || consent.transaction_expiry_height != fixed.expiry_height
        || consent.wallet_snapshot.anchor_root != fixed.anchor || inputs != scope.authorization.inputs
        || consent.maximum_debit_zatoshis != scope.authorization.maximum_debit_zatoshis
        || consent.fee_share_zatoshis != scope.authorization.fee_share_zatoshis || consent.transaction_fee_zatoshis != scope.authorization.transaction_fee_zatoshis
        || consent.receipt.reviewed_at_ms < terms.valid_from_ms || consent.receipt.expires_at_ms > terms.valid_until_ms
    { return Err(JournalError::InvalidBinding); }
    Ok(())
}

fn validate_financial_table_policy(c: &Connection) -> Result<()> {
    for (table, _) in CAPACITY_TABLES {
        if matches!(*table, "signer_account" | "signer_account_use_genesis" | "signer_enrollments" | "signer_accepted_manifests"
            | "signer_durable_construction_outbox" | "signer_durable_payment_admission_intents"
            | "signer_original_consents" | "signer_release_intents" | "signer_input_reservations"
            | "signer_bridge_requests" | "signer_bridge_permits" | "signer_bridge_keyuse" | "signer_bridge_results") { continue; }
        if c.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |r|r.get::<_,bool>(0))? { return Err(JournalError::RecoveryRequired); }
    }
    Ok(())
}
fn validate_financial_original_rows(c: &Connection) -> Result<()> {
    let retained = intent::read(c)?;
    let authorization = &retained.terms()?.scope.authorization.authorization_id;
    let mut q = c.prepare("SELECT authorization_id,reference,nonce,enrollment_ref,manifest_ref FROM signer_original_consents LIMIT 2")?;
    let rows = q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;
    if rows.len()>1 { return Err(JournalError::Conflict); }
    let release_count:u64=c.query_row("SELECT count(*) FROM signer_release_intents",[],|r|r.get(0))?;
    if release_count != rows.len() as u64 { return Err(JournalError::InvalidBinding); }
    let mut expected=std::collections::BTreeSet::new();
    for (auth, reference, nonce, enrollment, manifest) in rows {
        if &auth != authorization { return Err(JournalError::InvalidBinding); }
        let e=read_financial_original_v1(c,&auth)?.ok_or(JournalError::NotFound)?;
        let t=e.consent.terms();
        if e.consent.reference()!=reference || t.receipt.nonce!=nonce || t.enrollment_ref!=enrollment || t.accepted_manifest_ref!=manifest { return Err(JournalError::InvalidBinding); }
        let row:(String,String,String,String,String)=c.query_row("SELECT original_consent_ref,account_id,obligation_id,maximum_debit,exposure_state FROM signer_release_intents WHERE authorization_id=?1",[&auth],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        if row!=(reference,t.account_id.clone(),t.obligation_id.clone(),t.maximum_debit_zatoshis.to_string(),"outstanding_uncertain".into()) { return Err(JournalError::InvalidBinding); }
        for i in &t.input_bindings { expected.insert((t.account_id.clone(),i.nullifier.clone(),auth.clone())); }
    }
    let mut q=c.prepare("SELECT account_id,input_id,authorization_id FROM signer_input_reservations")?;
    let actual=q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)))?.collect::<std::result::Result<std::collections::BTreeSet<_>,_>>()?;
    if actual!=expected { return Err(JournalError::InvalidBinding); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Real encrypted storage/schema integration, not native consent or payment
    /// qualification. The intentionally inert payloads cannot pass validation.
    #[test]
    fn encrypted_profile20_extension_preserves_original_and_refuses_legacy_readers() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("original.sqlite");
        let key = DatabaseKey::from_bytes([97;32]);
        let mut c = wholepact_storage_security::create_encrypted(&path, &key).unwrap().into_connection();
        c.execute_batch(SCHEMA).unwrap();
        c.pragma_update(None,"application_id",APPLICATION_ID).unwrap();
        c.pragma_update(None,"user_version",SCHEMA_VERSION).unwrap();
        c.execute("INSERT INTO signer_account VALUES(1,'fixture',1,0)",[]).unwrap();
        c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        c.execute("INSERT INTO signer_durable_payment_admission_intents VALUES('original-op','original-auth','original-request','e','m','original-inert-bytes')",[]).unwrap();
        let before=original_rows_digest(&c).unwrap();
        {
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
            tx.execute_batch(EXTENSION).unwrap();
            tx.execute("INSERT INTO signer_financial_continuation_intents VALUES('next-op','original-auth','original-op','next-request','e','m','inert-not-an-approval')",[]).unwrap();
            tx.pragma_update(None,"user_version",VERSION).unwrap();
            assert_eq!(before,original_rows_digest(&tx).unwrap());
            tx.commit().unwrap();
        }
        for sql in [
            "UPDATE signer_financial_continuation_intents SET payload='changed'",
            "DELETE FROM signer_financial_continuation_intents",
            "INSERT OR REPLACE INTO signer_financial_continuation_intents VALUES('next-op','other-auth','other-op','other-request','e','m','changed')",
            "INSERT OR REPLACE INTO signer_financial_continuation_intents VALUES('other-op','original-auth','other-admission','other-request','e','m','changed')",
            "INSERT OR REPLACE INTO signer_financial_continuation_intents VALUES('other-op','other-auth','original-op','other-request','e','m','changed')",
            "INSERT OR REPLACE INTO signer_financial_continuation_intents VALUES('other-op','other-auth','other-admission','next-request','e','m','changed')",
        ] { assert!(c.execute_batch(sql).is_err()); }
        assert_eq!(before,original_rows_digest(&c).unwrap());
        let changes=c.total_changes();
        assert!(super::super::verify_schema(&c).is_err());
        assert!(verify_schema(&c).is_err(),"inert rows must never become a valid financial source");
        assert_eq!(changes,c.total_changes());
        drop(c);
        let reopened=wholepact_storage_security::open_encrypted(&path,&key).unwrap().into_connection();
        assert_eq!(before,original_rows_digest(&reopened).unwrap());
        assert_eq!(reopened.pragma_query_value::<i64,_>(None,"user_version",|r|r.get(0)).unwrap(),VERSION);
        assert_eq!(reopened.query_row("SELECT payload FROM signer_durable_payment_admission_intents",[],|r|r.get::<_,String>(0)).unwrap(),"original-inert-bytes");
    }
}

#[cfg(test)]
mod expected_schema_cache_tests_v1 {
    use super::*;
    #[test]
    fn cached_expected_schema_20_matches_fresh_and_rejects_target_drift() {
        let cached=expected_schema20_objects_v1().unwrap();
        assert_eq!(*cached,build_expected_schema_objects_v1(EXTENSION).unwrap());
        assert!(std::ptr::eq(cached,expected_schema20_objects_v1().unwrap()));
        let target=Connection::open_in_memory().unwrap();target.execute_batch(SCHEMA).unwrap();
        if !EXTENSION.is_empty(){target.execute_batch(EXTENSION).unwrap();}
        verify_schema_objects_v1(&target,cached).unwrap();
        target.execute_batch("CREATE TABLE unexpected_cache_probe(value TEXT)").unwrap();
        assert!(matches!(verify_schema_objects_v1(&target,cached),Err(JournalError::UnsupportedSchema)));
        target.execute_batch("DROP TABLE unexpected_cache_probe").unwrap();
        verify_schema_objects_v1(&target,cached).unwrap();
        target.execute_batch("CREATE INDEX unexpected_cache_index ON signer_account(writer_epoch)").unwrap();
        assert!(matches!(verify_schema_objects_v1(&target,cached),Err(JournalError::UnsupportedSchema)));
    }
    #[test]
    fn expected_schema_20_reference_component_benchmark() {
        // Bounded reference-only measurement, not native/full-profile evidence.
        // No timing threshold: overloaded CI must not turn this into a flaky test.
        let cached=expected_schema20_objects_v1().unwrap();let start=std::time::Instant::now();
        for _ in 0..16 {assert_eq!(*cached,build_expected_schema_objects_v1(EXTENSION).unwrap());}
        let uncached=start.elapsed().as_micros();let start=std::time::Instant::now();
        for _ in 0..16 {assert!(std::ptr::eq(cached,expected_schema20_objects_v1().unwrap()));}
        let cached_us=start.elapsed().as_micros();
        println!("SCHEMA_REFERENCE_COMPONENT profile=20 iterations=16 uncached_us={} cached_us={} full_profile_proven=false",uncached,cached_us);
    }
}

// Test-only access to pure data projections; no authority constructors.
#[cfg(all(test, feature = "coordinated-financial-workflow-v1", feature = "durable-proposal", feature = "pending-birth-owner-signing", feature = "native-ui", target_os = "linux"))]
pub(crate) use session::{project_spend_display, project_sign_exact_facts};
