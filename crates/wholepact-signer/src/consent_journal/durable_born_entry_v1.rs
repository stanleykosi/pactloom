//! Purpose-distinct restart admission for an original born account journal.
//! The genuine vault owner supplies its fixed original path and private key
//! after fresh native unlock. This reader creates no native consent, active
//! writer, financial admission, old V3 owner, or reusable signing capability.
use super::*;
use wholepact_authority::{
    WitnessDisclosureDescriptor, account_use::AccountUseGenesis,
    account_use_link::account_use_witness_origin_digest,
};

impl SignerConsentJournal {
    /// Existing current-schema encrypted storage only. Unlike the generic
    /// opener, this boundary never migrates, initializes, repairs or clears a
    /// journal. The caller must hold the original private directory owner and
    /// bind the path to its authenticated original publication, not a DTO.
    pub(crate) fn open_durable_born_entry_v1(
        path: &Path,
        key: &DatabaseKey,
        genesis: &AccountUseGenesis,
    ) -> Result<Self> {
        // Reject invalid or unsupported retained history on a private encrypted
        // snapshot before a writable SQLite handle can touch source sidecars.
        // The genuine caller's exclusive directory ownership is required for
        // this quiescent preflight and the subsequent live-handle allocation.
        let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(path, key)?;
        let original_identity = snapshot.source_database_identity()?;
        {
            let tx = rusqlite::Transaction::new_unchecked(
                snapshot.connection(),
                TransactionBehavior::Deferred,
            )?;
            validate(&tx, genesis, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES))?;
            tx.commit()?;
        }
        snapshot.check_source_unchanged()?;
        let encrypted = wholepact_storage_security::open_encrypted_quiescent(path, key)?;
        let database_identity = encrypted.database_identity()?;
        if database_identity != original_identity {
            return Err(JournalError::InvalidBinding);
        }
        drop(snapshot);
        let mut connection = encrypted.into_connection();
        {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            database_identity.check_current(&tx)?;
            validate(&tx, genesis, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES))?;
            database_identity.check_current(&tx)?;
            tx.commit()?;
        }
        configure(&connection)?;
        database_identity.check_current(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            database_identity,
            // A NEW local binding. Never resurrect the drained V3 binding or
            // reconstruct a session from serialized historical receipts.
            binding: SignerJournalBinding(Arc::new(())),
            authority_fence: RwLock::new(()),
            #[cfg(feature = "authority-signing")]
            settlement_nodes: Mutex::new(std::collections::BTreeMap::new()),
            #[cfg(test)]
            capacity_limits: (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
        })
    }

    /// One fresh read transaction, under the retained live file identity. All
    /// financial uncertainties remain intact. A successful read is not current
    /// writer reconciliation, and historical receipts are never renewed.
    pub(crate) fn check_durable_born_entry_v1(&self, genesis: &AccountUseGenesis) -> Result<()> {
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        self.check_durable_born_entry_snapshot_v1(genesis)
    }

    /// The exact opaque original lease already holds this journal's shared
    /// authority fence. Reacquiring it can deadlock behind a queued revoker;
    /// retain the original guard and verify its binding instead. This remains
    /// only a historical read, not renewal of an old spending decision.
    pub(crate) fn check_durable_born_entry_v1_under_lease(
        &self,
        genesis: &AccountUseGenesis,
        lease: &OriginalAuthorizationLease<'_>,
    ) -> Result<()> {
        if lease.binding() != &self.binding()
            || lease.evidence().enrollment().account_id() != genesis.identity.account_id
        {
            return Err(JournalError::Permission);
        }
        lease.check_current()?;
        self.check_durable_born_entry_snapshot_v1(genesis)?;
        lease.check_current()
    }

    // Only the two guarded routes above call this helper. It never escapes as
    // an unfenced checker or accepts a caller-asserted held-lock boolean.
    fn check_durable_born_entry_snapshot_v1(&self, genesis: &AccountUseGenesis) -> Result<()> {
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        if !c.is_autocommit() {
            return Err(JournalError::Database);
        }
        self.database_identity.check_current(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate(&tx, genesis, self.capacity_limits())?;
        self.database_identity.check_current(&tx)?;
        tx.commit()?;
        Ok(())
    }
}

fn validate(c: &Connection, genesis: &AccountUseGenesis, limits: (u64, u64)) -> Result<()> {
    if c.is_autocommit() {
        return Err(JournalError::InvalidBinding);
    }
    genesis
        .validate()
        .map_err(|_| JournalError::InvalidBinding)?;
    let application: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != SCHEMA_VERSION {
        return Err(JournalError::UnsupportedSchema);
    }
    verify_schema(c)?;
    bounded(c, limits)?;
    let account = read_account(c)?;
    let stored = account_use_storage::inspect(c, &account.account_id)?;
    if account.account_id != genesis.identity.account_id || stored.genesis() != Some(genesis) {
        return Err(JournalError::InvalidBinding);
    }
    if account.recovery_required {
        return Err(JournalError::RecoveryRequired);
    }
    if stored.exclusion().is_some() || stored.witness_ack().is_some() {
        return Err(JournalError::Permission);
    }
    require_supported_tables(c)?;
    // Typed original/release/exposure/input validation retains every local and
    // imported online uncertainty. It does not import anything or clear rows.
    let _inventory = writer_history::WriterLocalInventory::read(c, &account, limits)?;
    // Existing complete local typed readers cover enrollment/manifest links,
    // bridge requests, permits, key-use fences, results, deliveries and writer
    // receipts. They validate history only, never manufacture live authority.
    permanent_stop::validate_retained_local_cells(c, &account, limits)?;
    bind_original_namespace(c, genesis)?;
    Ok(())
}

fn require_supported_tables(c: &Connection) -> Result<()> {
    // Exact schema was verified first. A future table is refused when nonempty
    // until its semantics are explicitly qualified, rather than ignored.
    for (table, _) in CAPACITY_TABLES {
        if matches!(
            *table,
            "signer_account"
                | "signer_account_use_genesis"
                | "signer_enrollments"
                | "signer_accepted_manifests"
                | "signer_durable_construction_outbox"
                | "signer_original_consents"
                | "signer_release_intents"
                | "signer_input_reservations"
                | "signer_remote_exposures"
                | "signer_remote_inputs"
                | "signer_writer_reconciliations"
                | "signer_bridge_requests"
                | "signer_bridge_permits"
                | "signer_bridge_keyuse"
                | "signer_bridge_results"
                | "signer_result_redeliveries"
                | "signer_dispatch_requests"
        ) {
            continue;
        }
        let present: bool = c.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM \"{table}\")"),
            [],
            |r| r.get(0),
        )?;
        if present {
            return Err(if table.starts_with("signer_common_context_") {
                JournalError::ConstructionHistoryUnsupported
            } else {
                JournalError::RecoveryRequired
            });
        }
    }
    Ok(())
}

fn require_witness(
    disclosure: &WitnessDisclosureDescriptor,
    genesis: &AccountUseGenesis,
) -> Result<()> {
    if disclosure.account_id != genesis.identity.account_id
        || disclosure.network_profile_id != genesis.identity.network_profile_id
        || disclosure.witness_id != genesis.witness_id
        || account_use_witness_origin_digest(disclosure)
            .map_err(|_| JournalError::InvalidBinding)?
            != genesis.witness_origin_digest
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}

fn bind_original_namespace(c: &Connection, genesis: &AccountUseGenesis) -> Result<()> {
    let mut q = c.prepare("SELECT reference FROM signer_enrollments ORDER BY reference")?;
    for row in q.query_map([], |r| r.get::<_, String>(0))? {
        let enrollment = read_enrollment(c, &row?)?.ok_or(JournalError::NotFound)?;
        if enrollment.account_id() != genesis.identity.account_id
            || enrollment.account_fvk_digest() != genesis.identity.full_viewing_key_digest
            || enrollment.terms.network_profile_id != genesis.identity.network_profile_id
        {
            return Err(JournalError::InvalidBinding);
        }
    }
    drop(q);
    let mut q =
        c.prepare("SELECT authorization_id FROM signer_bridge_requests ORDER BY authorization_id")?;
    for row in q.query_map([], |r| r.get::<_, String>(0))? {
        let request = bridge_storage::read_request(c, &row?)
            .map_err(|_| JournalError::InvalidBinding)?
            .ok_or(JournalError::NotFound)?;
        // A legacy unspecified witness is not upgraded to the born namespace.
        let disclosure = request
            .disclosure
            .as_ref()
            .ok_or(JournalError::InvalidBinding)?;
        require_witness(&disclosure.descriptor, genesis)?;
    }
    drop(q);
    let mut q = c.prepare(
        "SELECT disclosure FROM signer_writer_reconciliations ORDER BY head_sequence,review_digest",
    )?;
    for row in q.query_map([], |r| r.get::<_, String>(0))? {
        require_witness(&decode(row?)?, genesis)?;
    }
    drop(q);
    let mut q =
        c.prepare("SELECT payload FROM signer_remote_exposures ORDER BY authorization_id")?;
    for row in q.query_map([], |r| r.get::<_, String>(0))? {
        let permit: wholepact_authority::ReservationPermit = decode(row?)?;
        if permit.witness_id != genesis.witness_id
            || permit.request.account_id != genesis.identity.account_id
            || permit.request.network_profile_id != genesis.identity.network_profile_id
        {
            return Err(JournalError::InvalidBinding);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "durable_born_entry_v1_tests.rs"]
mod tests;
