//! Recovery-only native boundary. Ordinary consent sessions cannot enter it.
//! Restored source files remain immutable; only a fresh reviewed successor is written.
use super::*;
#[path = "recovery_inventory.rs"]
mod recovery_inventory;
use crate::native_ui::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use recovery_inventory::PreparedRecoveryHistory;
use rusqlite::{Connection, TransactionBehavior, params, params_from_iter, types::Value};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use wholepact_authority::{
    AuthenticatedRecoveryFence, RecoveryFenceReceipt, ReservationEvidenceRef, ReservationPermit,
    WitnessDisclosureDescriptor,
};
use wholepact_storage_security::{
    DatabaseKey,
    bundle::{
        JournalKind, JournalTemplate,
        recovery::{RecoveryCell, RecoveryProvenance, RecoveryTable, VerifiedSignerRecoverySource},
    },
};

static V8_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: 8,
    create_sql: recovery_migration::V8_SCHEMA,
};
static V9_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: 9,
    create_sql: recovery_migration::V9_SCHEMA,
};
static V10_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: 10,
    create_sql: recovery_migration::V10_SCHEMA,
};
static V11_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: 11,
    create_sql: recovery_migration::V11_SCHEMA,
};
static V12_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: 12,
    create_sql: recovery_migration::V12_SCHEMA,
};
static V13_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: 13,
    create_sql: recovery_migration::V13_SCHEMA,
};
static V14_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: 14,
    create_sql: recovery_migration::V14_SCHEMA,
};
static V15_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: 15,
    create_sql: recovery_migration::V15_SCHEMA,
};
static V16_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: 16,
    create_sql: recovery_migration::V16_SCHEMA,
};
static V17_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: 17,
    create_sql: recovery_migration::V17_SCHEMA,
};
pub(crate) fn recovery_template(version: i64) -> Result<&'static JournalTemplate> {
    match version {
        8 => Ok(&V8_TEMPLATE),
        9 => Ok(&V9_TEMPLATE),
        10 => Ok(&V10_TEMPLATE),
        11 => Ok(&V11_TEMPLATE),
        12 => Ok(&V12_TEMPLATE),
        13 => Ok(&V13_TEMPLATE),
        14 => Ok(&V14_TEMPLATE),
        15 => Ok(&V15_TEMPLATE),
        16 => Ok(&V16_TEMPLATE),
        17 => Ok(&V17_TEMPLATE),
        18 => Ok(SignerConsentBundleAdapter::template()),
        _ => Err(JournalError::UnsupportedSchema),
    }
}

fn validate_component_coverage(source: &VerifiedSignerRecoverySource) -> Result<()> {
    let wallet = source.wallet();
    let manifest = source.manifest();
    if manifest.coverage != crate::account::backup::coverage(wallet.is_some())
        || manifest.components.len() != if wallet.is_some() { 2 } else { 1 }
        || source.provenance().component_id != "signer-authority"
        || wallet.is_some_and(|w| w.provenance().component_id != "signer-wallet")
    {
        return Err(JournalError::RecoveryRequired);
    }
    Ok(())
}

/// Review data only. It cannot grant authority through deserialization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryActivationInventory {
    operation_id: String,
    generation_id: String,
    target_profile: PathBuf,
    provenance: RecoveryProvenance,
    witness: WitnessDisclosureDescriptor,
    successor_writer_certificate_digest: String,
    local_writer_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wallet_provenance: Option<RecoveryProvenance>,
}
impl RecoveryActivationInventory {
    pub(crate) fn prepare(
        source: &VerifiedSignerRecoverySource,
        operation_id: String,
        generation_id: String,
        target_profile: PathBuf,
        witness: WitnessDisclosureDescriptor,
        successor_writer_certificate_digest: String,
    ) -> Result<Self> {
        id(&operation_id)?;
        hash(&generation_id)?;
        hash(&successor_writer_certificate_digest)?;
        witness
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        let (account, epoch) = source_account(source)?;
        validate_component_coverage(source)?;
        offline_history::require_legacy_recovery_source(source)?;
        if account != witness.account_id
            || !target_profile.is_absolute()
            || target_profile.exists()
            || target_profile.parent().is_none()
            || std::fs::canonicalize(target_profile.parent().unwrap())
                .map_err(|_| JournalError::InvalidBinding)?
                != target_profile.parent().unwrap()
            || source.provenance().application_id != APPLICATION_ID
            || !matches!(source.provenance().schema_version, 8..=18)
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(Self {
            operation_id,
            generation_id,
            target_profile,
            provenance: source.provenance().clone(),
            witness,
            successor_writer_certificate_digest,
            local_writer_epoch: epoch,
            wallet_provenance: source.wallet().map(|wallet| wallet.provenance().clone()),
        })
    }
    pub(crate) fn resume(
        source: &VerifiedSignerRecoverySource,
        proof: &crate::account::VerifiedRecoveryPlan,
    ) -> Result<Self> {
        let inventory = proof.inventory().clone();
        let (account, epoch) = source_account(source)?;
        id(&inventory.operation_id)?;
        hash(&inventory.generation_id)?;
        hash(&inventory.successor_writer_certificate_digest)?;
        inventory
            .witness
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        validate_component_coverage(source)?;
        offline_history::require_legacy_recovery_source(source)?;
        if source.wallet().map(|w| w.provenance()) != inventory.wallet_provenance.as_ref()
            || source.provenance() != &inventory.provenance
            || account != inventory.witness.account_id
            || epoch != inventory.local_writer_epoch
            || std::fs::canonicalize(&inventory.target_profile)
                .map_err(|_| JournalError::InvalidBinding)?
                != inventory.target_profile
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(inventory)
    }
    pub(crate) fn successor_writer_certificate_digest(&self) -> &str {
        &self.successor_writer_certificate_digest
    }
    pub(crate) fn digest(&self) -> Result<String> {
        digest("wholepact:recovery-activation-inventory:v1", self)
    }
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub(crate) fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub(crate) fn target_profile(&self) -> &Path {
        &self.target_profile
    }
    pub(crate) fn witness(&self) -> &WitnessDisclosureDescriptor {
        &self.witness
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryActivationRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_use_retention_digest: Option<String>,
    pub operation_id: String,
    pub generation_id: String,
    pub inventory_digest: String,
    pub fence_digest: String,
    pub history_digest: String,
    pub account_id: String,
    pub writer_epoch: u64,
    pub source_bundle_digest: String,
    pub source_component_digest: String,
    pub target_profile: PathBuf,
    pub review_digest: String,
}
/// Cannot be constructed from a saved receipt or arbitrary serialized record.
pub(crate) struct RecoveryActivationReceipt {
    record: RecoveryActivationRecord,
    fence: AuthenticatedRecoveryFence,
    native: NativeAuthorityBinding,
    approved_at: Instant,
    #[cfg(test)]
    test_deadline_elapsed: Arc<std::sync::atomic::AtomicBool>,
}
impl RecoveryActivationReceipt {
    /// Linearization boundary for this exact profile's final durable marker.
    /// A freshly admitted write drains under the native lease; clock expiry
    /// afterward cannot retroactively undo its filesystem effects.
    pub(crate) fn admit_publication(
        &self,
    ) -> crate::Result<crate::native_ui::NativePublicationLease<'_>> {
        let lease = self.native.publication_lease()?;
        self.check_current()?;
        Ok(lease)
    }
    #[cfg(test)]
    pub(crate) fn synthetic_deadline_trigger(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.test_deadline_elapsed.clone()
    }
    pub(crate) fn record(&self) -> &RecoveryActivationRecord {
        &self.record
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        #[cfg(test)]
        if self
            .test_deadline_elapsed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(JournalError::Expired);
        }
        self.fence
            .check_current()
            .map_err(|_| JournalError::Expired)?;
        self.native
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        if self.approved_at.elapsed() >= Duration::from_secs(120) {
            return Err(JournalError::Expired);
        }
        Ok(())
    }
}
pub(crate) struct PreparedRecoveryActivation {
    account_use_retention: account_use_recovery::RecoveryAccountUseRetention,
    source: VerifiedSignerRecoverySource,
    inventory: RecoveryActivationInventory,
    fence_receipt: RecoveryFenceReceipt,
    history_digest: String,
    history: PreparedRecoveryHistory,
    native: NativeAuthorityBinding,
    review_digest: String,
    created: Instant,
}
pub(crate) struct ApprovedRecoveryActivation(PreparedRecoveryActivation);
impl PreparedRecoveryActivation {
    pub(crate) fn prepare(
        source: VerifiedSignerRecoverySource,
        inventory: RecoveryActivationInventory,
        fence: AuthenticatedRecoveryFence,
        native: &NativeAuthority,
    ) -> Result<Self> {
        native
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        validate_fence(&source, &inventory, &fence)?;
        let history = validate_union(&source, fence.history())?;
        // Complete typed source inspection precedes this explicit availability
        // gate; no native preparation can admit unsupported offline history.
        history.require_enabled()?;
        let account_use_retention = if history.has_offline() {
            account_use_recovery::reconcile_complete(&source, fence.history())?
        } else {
            account_use_recovery::reconcile(&source, fence.history())?
        };
        let history_digest = fence
            .history()
            .history_digest()
            .map_err(|_| JournalError::InvalidBinding)?;
        let review_digest = if history.uses_v2_review() {
            digest(
                "wholepact:native-recovery-activation:v2",
                &(
                    &inventory,
                    account_use_retention.digest()?,
                    fence.receipt(),
                    &history_digest,
                    fence.active_session().receipt(),
                    &history,
                    native.principal_id(),
                    native.measurement(),
                ),
            )?
        } else {
            // Exact legacy tuple/domain/vector order: never hash the v2 wrapper
            // under v1 or rewrite a previous recovery record/template.
            digest(
                "wholepact:native-recovery-activation:v1",
                &(
                    &inventory,
                    account_use_retention.digest()?,
                    fence.receipt(),
                    &history_digest,
                    fence.active_session().receipt(),
                    history.legacy_online_permits()?,
                    native.principal_id(),
                    native.measurement(),
                ),
            )?
        };
        Ok(Self {
            account_use_retention,
            source,
            inventory,
            fence_receipt: fence.receipt().clone(),
            history_digest,
            history,
            native: native.binding(),
            review_digest,
            created: Instant::now(),
        })
    }
    pub(crate) fn digest(&self) -> &str {
        &self.review_digest
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_native()?;
        let detail = if self.history.uses_v2_review() {
            serde_json::to_string_pretty(&(
                "wholepact:native-recovery-activation:v2",
                &self.inventory,
                self.account_use_retention.display()?,
                &self.fence_receipt,
                &self.history_digest,
                &self.history,
            ))
        } else {
            serde_json::to_string_pretty(&(
                &self.inventory,
                self.account_use_retention.display()?,
                &self.fence_receipt,
                &self.history_digest,
                self.history.legacy_online_permits()?,
            ))
        }
        .map_err(|_| JournalError::InvalidBinding)?;
        if detail.len() > MAX_RECORD_BYTES {
            return Err(JournalError::Limit);
        }
        Ok(format!(
            "Activate restored signer into a new generation\n\nAll restored files remain quarantined and unchanged. The surviving independent witness has fenced the previous writer and separately activated this successor session. Every original local consent must have exact witness continuity. Witness-only records are exposure, never new local consent. All historical positive settlement discounts are conservatively reopened until fresh qualified observations are performed. Old signed transactions may still be broadcast; writer replacement does not revoke signatures. Wallet scan, peer grants, disclosure permissions, enrollment and spending approval must be renewed separately.\n\nExact authenticated inventory, recovery fence, history and reservations:\n{detail}"
        ))
    }
    fn check_native(&self) -> Result<()> {
        self.native
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        if self.created.elapsed() >= Duration::from_secs(120) {
            return Err(JournalError::Expired);
        }
        Ok(())
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        native: &NativeAuthority,
    ) -> Result<ApprovedRecoveryActivation> {
        self.check_native()?;
        native
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        if decision.binding() != &self.native
            || native.binding() != self.native
            || decision.reviewed_digest() != self.review_digest
        {
            return Err(JournalError::Permission);
        }
        Ok(ApprovedRecoveryActivation(self))
    }
}
impl ApprovedRecoveryActivation {
    pub(crate) fn inventory(&self) -> &RecoveryActivationInventory {
        &self.0.inventory
    }
    pub(crate) fn source_manifest(&self) -> &wholepact_storage_security::bundle::BundleManifest {
        self.0.source.manifest()
    }
    pub(crate) fn source_wallet(
        &self,
    ) -> Option<&wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent> {
        self.0.source.wallet()
    }
    pub(crate) fn source_provenance(&self) -> &RecoveryProvenance {
        self.0.source.provenance()
    }
    pub(crate) fn account_id(&self) -> &str {
        &self.0.inventory.witness.account_id
    }
    pub(crate) fn target_profile(&self) -> &Path {
        &self.0.inventory.target_profile
    }
    pub(crate) fn operation_id(&self) -> &str {
        &self.0.inventory.operation_id
    }
    pub(crate) fn inventory_digest(&self) -> Result<String> {
        self.0.inventory.digest()
    }
    /// Caller holds the exclusive NEW target profile. No existing target may be
    /// overwritten. Final profile publication still gates ordinary journal open.
    pub(crate) fn commit(
        self,
        fresh: AuthenticatedRecoveryFence,
        target_journal: &Path,
        key: &DatabaseKey,
    ) -> Result<RecoveryActivationReceipt> {
        let p = self.0;
        p.check_native()?;
        validate_fence(&p.source, &p.inventory, &fresh)?;
        if fresh.receipt() != &p.fence_receipt
            || fresh
                .history()
                .history_digest()
                .map_err(|_| JournalError::InvalidBinding)?
                != p.history_digest
            || target_journal != p.inventory.target_profile.join("authority.sqlite")
        {
            return Err(JournalError::Conflict);
        }
        let current_history = validate_union(&p.source, fresh.history())?;
        p.history.require_enabled()?;
        current_history.require_enabled()?;
        p.history.require_identical(&current_history)?;
        let current_retention = if current_history.has_offline() {
            account_use_recovery::reconcile_complete(&p.source, fresh.history())?
        } else {
            account_use_recovery::reconcile(&p.source, fresh.history())?
        };
        if current_retention.digest()? != p.account_use_retention.digest()? {
            return Err(JournalError::Conflict);
        }
        let mut record = RecoveryActivationRecord {
            account_use_retention_digest: p.account_use_retention.digest()?,
            operation_id: p.inventory.operation_id.clone(),
            generation_id: p.inventory.generation_id.clone(),
            inventory_digest: p.inventory.digest()?,
            fence_digest: digest("wholepact:recovery-fence-receipt:v1", &p.fence_receipt)?,
            history_digest: p.history_digest.clone(),
            account_id: p.inventory.witness.account_id.clone(),
            writer_epoch: p.fence_receipt.writer_epoch,
            source_bundle_digest: p.inventory.provenance.bundle_digest.clone(),
            source_component_digest: p.inventory.provenance.component_digest.clone(),
            target_profile: p.inventory.target_profile.clone(),
            review_digest: p.review_digest.clone(),
        };
        // Hold the real native publication lease across the short durable
        // successor transaction/fsync. No historical DTO can create this lease.
        let native_publication = p
            .native
            .publication_lease()
            .map_err(|_| JournalError::Permission)?;
        fresh.check_current().map_err(|_| JournalError::Expired)?;
        p.check_native()?;
        let existed = target_journal.exists();
        let mut c = if existed {
            wholepact_storage_security::open_encrypted(target_journal, key)?.into_connection()
        } else {
            wholepact_storage_security::create_encrypted(target_journal, key)?.into_connection()
        };
        c.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;",
        )?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let objects: i64 = tx.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if existed && objects != 0 {
            storage::verify_schema(&tx)?;
            let saved:String=tx.query_row("SELECT payload FROM signer_recovery_generations WHERE generation_id=?1 AND phase='committed'",[&record.generation_id],|r|r.get(0))?;
            let saved: RecoveryActivationRecord = decode(saved)?;
            // New native review/session receipts may differ after restart. All
            // fixed operation, target, provenance and fenced epoch fields may not.
            let mut comparable = saved.clone();
            comparable.review_digest = record.review_digest.clone();
            comparable.history_digest = record.history_digest.clone();
            if comparable != record {
                return Err(JournalError::Conflict);
            }
            record = saved;
            let mut expected = Connection::open_in_memory()?;
            let expected_tx = expected.transaction_with_behavior(TransactionBehavior::Immediate)?;
            populate_successor(
                &expected_tx,
                &p.source,
                &p.history,
                &record,
                &p.account_use_retention,
            )?;
            verify_identical_rows(&tx, &expected_tx)?;
        } else {
            let application: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
            let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
            if application != 0 || version != 0 {
                return Err(JournalError::Conflict);
            }
            populate_successor(
                &tx,
                &p.source,
                &p.history,
                &record,
                &p.account_use_retention,
            )?;
        }
        fresh.check_current().map_err(|_| JournalError::Expired)?;
        p.check_native()?;
        tx.commit()?;
        c.close().map_err(|_| JournalError::Database)?;
        std::fs::File::open(target_journal)
            .and_then(|f| f.sync_all())
            .map_err(|_| JournalError::Database)?;
        fresh.check_current().map_err(|_| JournalError::Expired)?;
        drop(native_publication);
        Ok(RecoveryActivationReceipt {
            record,
            fence: fresh,
            native: p.native,
            approved_at: p.created,
            #[cfg(test)]
            test_deadline_elapsed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }
}
fn validate_fence(
    source: &VerifiedSignerRecoverySource,
    inventory: &RecoveryActivationInventory,
    fence: &AuthenticatedRecoveryFence,
) -> Result<()> {
    fence.check_current().map_err(|_| JournalError::Expired)?;
    validate_component_coverage(source)?;
    if source.wallet().map(|w| w.provenance()) != inventory.wallet_provenance.as_ref() {
        return Err(JournalError::InvalidBinding);
    }
    let (account, epoch) = source_account(source)?;
    let r = fence.receipt();
    if source.provenance() != &inventory.provenance
        || epoch != inventory.local_writer_epoch
        || account != inventory.witness.account_id
        || r.account_id != account
        || r.operation_id != inventory.operation_id
        || r.inventory_digest != inventory.digest()?
        || r.writer_certificate_digest != inventory.successor_writer_certificate_digest
        || r.previous_writer_epoch < epoch
        || r.writer_epoch <= epoch
        || fence.history().disclosure() != &inventory.witness
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}
fn source_account(source: &VerifiedSignerRecoverySource) -> Result<(String, u64)> {
    let table = source.account().map_err(|_| JournalError::InvalidBinding)?;
    if table.rows().len() != 1 {
        return Err(JournalError::InvalidBinding);
    }
    let row = &table.rows()[0];
    let account = text(table, row, "account_id")?.to_string();
    id(&account)?;
    let epoch = integer(table, row, "writer_epoch")?;
    if epoch <= 0 {
        return Err(JournalError::InvalidBinding);
    }
    Ok((account, epoch as u64))
}
fn cell<'a>(
    table: &RecoveryTable,
    row: &'a wholepact_storage_security::bundle::recovery::RecoveryRow,
    column: &str,
) -> Result<&'a RecoveryCell> {
    let i = table
        .columns()
        .iter()
        .position(|c| c == column)
        .ok_or(JournalError::InvalidBinding)?;
    row.cells().get(i).ok_or(JournalError::InvalidBinding)
}
fn text<'a>(
    table: &RecoveryTable,
    row: &'a wholepact_storage_security::bundle::recovery::RecoveryRow,
    column: &str,
) -> Result<&'a str> {
    match cell(table, row, column)? {
        RecoveryCell::Text(v) => Ok(v),
        _ => Err(JournalError::InvalidBinding),
    }
}
fn integer(
    table: &RecoveryTable,
    row: &wholepact_storage_security::bundle::recovery::RecoveryRow,
    column: &str,
) -> Result<i64> {
    match cell(table, row, column)? {
        RecoveryCell::Integer(v) => Ok(*v),
        _ => Err(JournalError::InvalidBinding),
    }
}
fn validate_union(
    source: &VerifiedSignerRecoverySource,
    history: &wholepact_authority::ReconciledAuthorityHistory,
) -> Result<PreparedRecoveryHistory> {
    validate_witness_continuity(source, history)?;
    PreparedRecoveryHistory::read(source, history)
}
pub(super) fn validate_original_permit(
    original: &OriginalSpendConsent,
    permit: &ReservationPermit,
) -> Result<()> {
    let t = original.terms();
    let r = &permit.request;
    if original.reference() != r.original_consent_ref
        || t.automation.as_ref().map(|a| &a.grant) != r.automation.as_ref()
        || t.authorization_id != r.authorization_id
        || t.account_id != r.account_id
        || t.obligation_id != r.obligation_id
        || t.maximum_debit_zatoshis != r.maximum_debit_zatoshis
        || t.receipt.writer_epoch != r.writer_epoch
        || t.enrollment_ref != r.enrollment_ref
        || t.accepted_manifest_ref != r.accepted_manifest_ref
        || t.agreement_id != r.agreement_id
        || t.proposal_id != r.proposal_id
        || t.proposal_digest != r.proposal_digest
        || t.manifest_digest != r.manifest_digest
        || t.effects_digest != r.effects_digest
        || t.artifact_digest != r.artifact_digest
        || t.review_binding != r.review_binding
        || t.fee_share_zatoshis != r.fee_share_zatoshis
        || t.transaction_fee_zatoshis != r.transaction_fee_zatoshis
        || t.transaction_expiry_height != r.transaction_expiry_height
        || t.receipt.reviewed_at_ms != r.reviewed_at_ms
        || t.input_bindings.len() != r.inputs.len()
        || t.input_bindings.iter().zip(&r.inputs).any(|(a, b)| {
            a.input_id != b.input_id
                || a.nullifier != b.nullifier
                || a.action_index != b.action_index
                || a.value_zatoshis != b.value_zatoshis
        })
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
fn import_all(c: &Connection, source: &VerifiedSignerRecoverySource) -> Result<()> {
    // Names and columns come only from a sealed source verified against the
    // executable-owned exact schema. Values always use bound parameters.
    for table in source.tables() {
        let names = table
            .columns()
            .iter()
            .map(|v| format!("\"{}\"", v.replace('"', "\"\"")))
            .collect::<Vec<_>>();
        let mut columns = names;
        if table.has_rowid() {
            columns.insert(0, "rowid".into());
        }
        let sql = format!(
            "INSERT INTO \"{}\" ({}) VALUES ({})",
            table.name().replace('"', "\"\""),
            columns.join(","),
            (0..columns.len())
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(",")
        );
        for row in table.rows() {
            let mut values = Vec::new();
            if table.has_rowid() {
                values.push(Value::Integer(
                    row.rowid().ok_or(JournalError::InvalidBinding)?,
                ));
            }
            for cell in row.cells() {
                values.push(match cell {
                    RecoveryCell::Null => Value::Null,
                    RecoveryCell::Integer(v) => Value::Integer(*v),
                    RecoveryCell::Text(v) => Value::Text(v.clone()),
                    _ => return Err(JournalError::InvalidBinding),
                });
            }
            c.execute(&sql, params_from_iter(values))?;
        }
    }
    Ok(())
}
fn reopen_positive_history(c: &Connection, record: &RecoveryActivationRecord) -> Result<()> {
    let mut q=c.prepare("SELECT e.evidence_id,e.authorization_id,e.source_ref FROM signer_settlement_events e WHERE e.sequence=(SELECT max(x.sequence) FROM signer_settlement_events x WHERE x.authorization_id=e.authorization_id) AND e.kind IN ('canonical_consumed','canonical_conflict')")?;
    let rows = q
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(q);
    for (prior, authorization, source) in rows {
        let evidence = digest(
            "wholepact:recovery-conservative-reopen:v1",
            &(&record.generation_id, &prior, &authorization, &source),
        )?;
        c.execute("INSERT INTO signer_settlement_events(evidence_id,authorization_id,source_ref,kind,payload) VALUES(?1,?2,?3,'reopened',?4)",params![evidence,authorization,source,"{\"reason\":\"restored_positive_evidence_requires_fresh_requalification\"}"])?;
    }
    Ok(())
}

fn populate_successor(
    c: &rusqlite::Transaction<'_>,
    source: &VerifiedSignerRecoverySource,
    history: &PreparedRecoveryHistory,
    record: &RecoveryActivationRecord,
    account_use_retention: &account_use_recovery::RecoveryAccountUseRetention,
) -> Result<()> {
    // Before even creating schema: unsupported history cannot leave partial
    // active-generation rows through an internal mistaken caller.
    history.require_enabled()?;
    // Retained disclosure bytes are historical data, never portable native
    // decisions. Recheck before any successor schema or authority mutation.
    offline_history::require_legacy_recovery_source(source)?;
    c.execute_batch(SCHEMA)?;
    c.execute_batch("PRAGMA defer_foreign_keys=ON;")?;
    import_all(c, source)?;
    history.import_on(c, &record.account_id)?;
    account_use_retention.retain_on(c, &record.account_id)?;
    reopen_positive_history(c, record)?;
    let payload = encode(record)?;
    for phase in ["prepared", "committed"] {
        c.execute(
            "INSERT INTO signer_recovery_generations VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                record.generation_id,
                phase,
                record.operation_id,
                record.inventory_digest,
                record.fence_digest,
                record.writer_epoch,
                payload.as_str()
            ],
        )?;
    }
    c.execute(
        "UPDATE signer_account SET writer_epoch=?1,recovery_required=0 WHERE singleton=1",
        [record.writer_epoch],
    )?;
    c.pragma_update(None, "application_id", APPLICATION_ID)?;
    c.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    storage::verify_schema(c)?;
    storage::bounded(c, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES))?;
    let violations: i64 =
        c.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })?;
    if violations != 0 {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}

fn verify_identical_rows(actual: &Connection, expected: &Connection) -> Result<()> {
    let mut q =
        expected.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")?;
    let tables = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for table in tables {
        let sql = format!(
            "SELECT rowid,* FROM \"{}\" ORDER BY rowid",
            table.replace('"', "\"\"")
        );
        fn values(c: &Connection, sql: &str) -> Result<Vec<Vec<Value>>> {
            let mut q = c.prepare(sql)?;
            let n = q.column_count();
            let rows = q.query_map([], |r| (0..n).map(|i| r.get(i)).collect())?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        }
        if values(actual, &sql)? != values(expected, &sql)? {
            return Err(JournalError::Conflict);
        }
    }
    Ok(())
}

fn validate_witness_continuity(
    source: &VerifiedSignerRecoverySource,
    history: &wholepact_authority::ReconciledAuthorityHistory,
) -> Result<()> {
    use crate::authority_bridge::{
        disclosure::RetainedWitnessDisclosure,
        protocol::{AuthorizationDeliveryScope, RetainedWitnessPermit},
    };
    use wholepact_authority::{AuthorityHead, ReserveAuthorization, WriterSessionReceipt};
    let descriptor = history.disclosure();
    let table = |name: &str| {
        source
            .tables()
            .iter()
            .find(|t| t.name() == name)
            .ok_or(JournalError::InvalidBinding)
    };
    let mut pinned = false;
    let reconciliations = table("signer_writer_reconciliations")?;
    for row in reconciliations.rows() {
        let retained: WitnessDisclosureDescriptor =
            decode(text(reconciliations, row, "disclosure")?.to_owned())?;
        let sequence = integer(reconciliations, row, "head_sequence")?;
        let head = AuthorityHead {
            sequence: u64::try_from(sequence).map_err(|_| JournalError::InvalidBinding)?,
            digest: text(reconciliations, row, "head_digest")?.into(),
        };
        let (receipt, _native, _digest): (WriterSessionReceipt, NativeConsentReceipt, String) =
            decode(text(reconciliations, row, "payload")?.to_owned())?;
        if &retained != descriptor
            || receipt.disclosure != retained
            || !history.contains_head(&head)
            || !history.contains_head(&receipt.reconciled_head)
            || !history.contains_head(&receipt.acquired_head)
            || receipt.writer_epoch
                != u64::try_from(integer(reconciliations, row, "writer_epoch")?)
                    .map_err(|_| JournalError::InvalidBinding)?
        {
            return Err(JournalError::Conflict);
        }
        pinned = true;
    }
    let requests = table("signer_bridge_requests")?;
    for row in requests.rows() {
        let (request, _delivery, disclosure): (
            ReserveAuthorization,
            AuthorizationDeliveryScope,
            Option<RetainedWitnessDisclosure>,
        ) = decode(text(requests, row, "request_payload")?.to_owned())?;
        let permit = online_permit(history, &request.authorization_id)
            .ok_or(JournalError::RecoveryRequired)?;
        if permit.request != request
            || !history.contains_head(&request.expected_head)
            || request.authorization_id != text(requests, row, "authorization_id")?
        {
            return Err(JournalError::Conflict);
        }
        if let Some(disclosure) = disclosure {
            if &disclosure.descriptor != descriptor
                || disclosure.expected_head != request.expected_head
                || disclosure.original_consent_ref != request.original_consent_ref
            {
                return Err(JournalError::Conflict);
            }
            pinned = true;
        }
    }
    let retained = table("signer_bridge_permits")?;
    for row in retained.rows() {
        let saved: RetainedWitnessPermit = decode(text(retained, row, "payload")?.to_owned())?;
        if saved.witness_certificate_digest() != descriptor.pinned_server_certificate_digest
            || saved.descriptor().request.authorization_id
                != text(retained, row, "authorization_id")?
            || online_permit(history, &saved.descriptor().request.authorization_id)
                != Some(saved.descriptor())
        {
            return Err(JournalError::Conflict);
        }
    }
    let policies = table("signer_sponsor_policy_events")?;
    for row in policies.rows() {
        let policy: NativeSponsorPolicyRecord = decode(text(policies, row, "payload")?.to_owned())?;
        if policy.witness.witness_id != descriptor.witness_id
            || policy.witness.policy_digest != descriptor.policy_digest
            || policy.witness.aggregate_budget_zatoshis
                != history.snapshot().aggregate_budget_zatoshis
        {
            return Err(JournalError::Conflict);
        }
    }
    if source.provenance().schema_version >= 10 {
        let admissions = table("signer_automation_keyuse")?;
        for row in admissions.rows() {
            let admission: wholepact_authority::AutomaticKeyUseAdmission =
                decode(text(admissions, row, "payload")?.to_owned())?;
            admission
                .matches_request(&admission.request)
                .map_err(|_| JournalError::InvalidBinding)?;
            if admission.reservation.request.authorization_id
                != text(admissions, row, "authorization_id")?
                || admission.witness_id != descriptor.witness_id
                || admission.policy_digest != descriptor.policy_digest
                || !history.automatic_key_use_admissions().contains(&admission)
                || !history.contains_operation(&admission.request.operation_id)
                || !history.contains_head(&admission.committed_head)
                || online_permit(history, &admission.reservation.request.authorization_id)
                    != Some(&admission.reservation)
            {
                return Err(JournalError::Conflict);
            }
        }
        let grants = table("signer_automation_grant_events")?;
        for row in grants.rows() {
            let grant: NativeAutomationGrantRecord =
                decode(text(grants, row, "payload")?.to_owned())?;
            grant.validate()?;
            if grant.binding.grant_id != text(grants, row, "grant_id")?
                || grant.binding.revision != integer(grants, row, "revision")? as u64
                || grant.enrollment_ref != text(grants, row, "enrollment_ref")?
                || grant.witness.witness_id != descriptor.witness_id
                || grant.witness.policy_digest != descriptor.policy_digest
                || grant.witness.aggregate_budget_zatoshis
                    != history.snapshot().aggregate_budget_zatoshis
            {
                return Err(JournalError::Conflict);
            }
            // A local native control may be retained before witness synchronization.
            // Missing witness grant history cannot become active after recovery:
            // epoch and enrollment are preserved, never rewritten to the successor.
        }
    }
    if !pinned {
        return Err(JournalError::RecoveryRequired);
    }
    Ok(())
}

/// Recovery preflight before any owner mutation. Uses complete live history and
/// authenticated immutable source rows; never accepts a caller's summary flag.
pub(crate) fn verify_recovery_continuity(
    source: &VerifiedSignerRecoverySource,
    history: &wholepact_authority::ReconciledAuthorityHistory,
) -> Result<()> {
    // This is activation preflight, not the historical inventory reader.
    // Never let the financial-only online lookup silently omit retained inputs.
    if history
        .manual_roster_construction_records_v2()
        .next()
        .is_some()
        || offline_reconciliation::common_context_history(history)?.is_some()
    {
        return Err(JournalError::ConstructionHistoryUnsupported);
    }
    validate_union(source, history)?.require_enabled()
}

/// A narrowly scoped online bridge lookup, never a complete-history projection.
/// The complete typed inventory independently retains offline and construction
/// origins, and financial activation explicitly refuses construction history.
fn online_permit<'a>(
    history: &'a wholepact_authority::ReconciledAuthorityHistory,
    authorization: &str,
) -> Option<&'a ReservationPermit> {
    history
        .reservation_evidence()
        .find_map(|entry| match entry {
            ReservationEvidenceRef::OnlineV2(permit)
                if permit.request.authorization_id == authorization =>
            {
                Some(permit)
            }
            _ => None,
        })
}

#[path = "informational_read.rs"]
mod informational_read;
pub(crate) use informational_read::QuarantinedJournalRead;
