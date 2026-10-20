//! Purpose-distinct restart admission for an original born account journal.
//! The genuine vault owner supplies its fixed original path and private key
//! after fresh native unlock. This reader creates no native consent, active
//! writer, financial admission, old V3 owner, or reusable signing capability.
use super::*;
use wholepact_authority::{
    account_use::AccountUseGenesis, account_use_link::account_use_witness_origin_digest,
    WitnessDisclosureDescriptor,
};

#[cfg(test)]
thread_local! {
    // Test-local accounting only, never a cached validation or runtime authority.
    static DURABLE_BORN_SNAPSHOT_VALIDATIONS_V1: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

impl SignerConsentJournal {
    /// Existing current-schema encrypted storage only. Unlike the generic
    /// opener, this boundary never migrates, initializes, repairs or clears a
    /// journal. The caller must hold the original private directory owner and
    /// bind the path to its authenticated original publication, not a DTO.
    pub(crate) fn open_durable_born_entry_v1(
        path: &Path,
        key: &DatabaseKey,
        genesis: &AccountUseGenesis,
        source: &Arc<SignerJournalSourceOwner>,
    ) -> Result<Self> {
        let mut owner = source.begin(path)?;
        let opened = open_preflighted_encrypted(
            &mut owner,
            path,
            key,
            &genesis.identity.account_id,
            Some(genesis),
            &|c| validate(c, genesis, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES)),
        )?;
        Ok(Self::from_owned_source(opened))
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

    /// Reuse the exact preconstruction record lease's existing authority fence.
    /// The full snapshot must follow acquisition: an exclusion can otherwise
    /// commit between an earlier scan and that lease without changing recovery.
    /// This checks retained history only; callers must separately require both
    /// current disclosure receipts and the actual native/source/data bindings.
    pub(crate) fn check_durable_born_entry_v1_under_preconstruction_lease(
        &self,
        genesis: &AccountUseGenesis,
        lease: &PreconstructionRecordLease<'_>,
    ) -> Result<()> {
        lease.require_journal(&self.binding())?;
        if lease.enrollment().account_id() != genesis.identity.account_id {
            return Err(JournalError::Permission);
        }
        lease.check_current()?;
        self.check_durable_born_entry_snapshot_v1(genesis)?;
        lease.check_current()
    }

    // Only the three guarded routes above call this helper. It never escapes as
    // an unfenced checker or accepts a caller-asserted held-lock boolean.
    fn check_durable_born_entry_snapshot_v1(&self, genesis: &AccountUseGenesis) -> Result<()> {
        #[cfg(test)]
        let _cost_snapshot = validation_cost_v1::enter(validation_cost_v1::Phase::SnapshotTotal);
        #[cfg(test)]
        let cost_lock = validation_cost_v1::enter(validation_cost_v1::Phase::ConnectionLock);
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        #[cfg(test)]
        drop(cost_lock);
        if !c.is_autocommit() {
            return Err(JournalError::Database);
        }
        #[cfg(test)]
        let cost_identity = validation_cost_v1::enter(validation_cost_v1::Phase::IdentityBefore);
        self.database_identity.check_current(&c)?;
        #[cfg(test)]
        drop(cost_identity);
        #[cfg(test)]
        let cost_begin = validation_cost_v1::enter(validation_cost_v1::Phase::TransactionBegin);
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        #[cfg(test)]
        drop(cost_begin);
        #[cfg(test)]
        DURABLE_BORN_SNAPSHOT_VALIDATIONS_V1.with(|count| count.set(count.get() + 1));
        writer_history::validate_durable_born_snapshot_v1(&tx, genesis, self.capacity_limits())?;
        #[cfg(test)]
        let cost_identity = validation_cost_v1::enter(validation_cost_v1::Phase::IdentityAfter);
        self.database_identity.check_current(&tx)?;
        #[cfg(test)]
        drop(cost_identity);
        #[cfg(test)]
        let cost_commit = validation_cost_v1::enter(validation_cost_v1::Phase::TransactionCommit);
        tx.commit()?;
        #[cfg(test)]
        drop(cost_commit);
        Ok(())
    }
}

fn validate(c: &Connection, genesis: &AccountUseGenesis, limits: (u64, u64)) -> Result<()> {
    #[cfg(test)]
    let _cost_validation = validation_cost_v1::enter(validation_cost_v1::Phase::ValidationTotal);
    let account = validate_durable_born_prefix_v1(c, genesis, limits)?;
    // The ordinary opener retains the complete generic inventory path.
    #[cfg(test)]
    let cost_inventory = validation_cost_v1::enter(validation_cost_v1::Phase::Inventory);
    let _inventory = writer_history::WriterLocalInventory::read(c, &account, limits)?;
    #[cfg(test)]
    drop(cost_inventory);
    validate_durable_born_suffix_v1(c, genesis, &account, limits)
}

/// Ordered full-schema and account-policy validation. The returned account is
/// inert historical data, not proof or a capability to bypass other readers.
pub(in crate::consent_journal) fn validate_durable_born_prefix_v1(
    c: &Connection,
    genesis: &AccountUseGenesis,
    limits: (u64, u64),
) -> Result<SignerAccountState> {
    if c.is_autocommit() {
        return Err(JournalError::InvalidBinding);
    }
    #[cfg(test)]
    let cost_genesis = validation_cost_v1::enter(validation_cost_v1::Phase::GenesisValidation);
    genesis
        .validate()
        .map_err(|_| JournalError::InvalidBinding)?;
    #[cfg(test)]
    drop(cost_genesis);
    let application: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != SCHEMA_VERSION {
        return Err(JournalError::UnsupportedSchema);
    }
    verify_schema(c)?;
    bounded(c, limits)?;
    #[cfg(test)]
    let cost_account = validation_cost_v1::enter(validation_cost_v1::Phase::AccountState);
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
    #[cfg(test)]
    drop(cost_account);
    require_supported_tables(c)?;
    Ok(account)
}

/// Complete retained local-cell validation and original namespace joins, in
/// their original order after the caller's complete typed inventory read.
pub(in crate::consent_journal) fn validate_durable_born_suffix_v1(
    c: &Connection,
    genesis: &AccountUseGenesis,
    account: &SignerAccountState,
    limits: (u64, u64),
) -> Result<()> {
    // Existing complete local typed readers cover enrollment/manifest links,
    // bridge requests, permits, key-use fences, results, deliveries and writer
    // receipts. They validate history only, never manufacture live authority.
    #[cfg(test)]
    let cost_local_cells = validation_cost_v1::enter(validation_cost_v1::Phase::LocalCells);
    permanent_stop::validate_retained_local_cells(c, account, limits)?;
    #[cfg(test)]
    drop(cost_local_cells);
    bind_original_namespace(c, genesis)?;
    Ok(())
}

/// Same-snapshot complete supported local DATA ancestry for the purpose-
/// distinct writer reconciliation. No WriterLocalInventory recursion, current
/// receipt expiry, native decision, source ownership, or financial permission.
pub(crate) fn validate_durable_payment_local_history_v1(
    c: &Connection,
    genesis: &AccountUseGenesis,
    limits: (u64, u64),
) -> Result<()> {
    if c.is_autocommit() {
        return Err(JournalError::InvalidBinding);
    }
    genesis
        .validate()
        .map_err(|_| JournalError::InvalidBinding)?;
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
    permanent_stop::validate_retained_local_cells(c, &account, limits)?;
    bind_original_namespace(c, genesis)?;
    Ok(())
}

fn require_supported_tables(c: &Connection) -> Result<()> {
    #[cfg(test)]
    let _cost_policy = validation_cost_v1::enter(validation_cost_v1::Phase::SupportedTablePolicy);
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
                | "signer_durable_payment_admission_intents"
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
    #[cfg(test)]
    let _cost_namespace = validation_cost_v1::enter(validation_cost_v1::Phase::NamespaceBinding);
    for intent in read_durable_payment_admission_intents_v1(c)? {
        require_witness(intent.disclosure(), genesis)?;
        if intent.owner_certificate_digest() != genesis.owner_certificate_digest {
            return Err(JournalError::InvalidBinding);
        }
    }
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

/// Distinct admission-only profile. Full schema/account/FK validation and every
/// allowed cell are checked; all financial/automatic/recovery tables stay empty.
fn validate_delivery_v2(
    c: &Connection,
    genesis: &AccountUseGenesis,
    limits: (u64, u64),
) -> Result<()> {
    let account = validate_durable_born_prefix_v1(c, genesis, limits)?;
    for (table, _) in CAPACITY_TABLES {
        if matches!(
            *table,
            "signer_account"
                | "signer_account_use_genesis"
                | "signer_enrollments"
                | "signer_accepted_manifests"
                | "signer_durable_construction_outbox"
                | "signer_durable_payment_admission_intents"
        ) {
            continue;
        }
        if c.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM \"{table}\")"),
            [],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(JournalError::RecoveryRequired);
        }
    }
    let mut foreign_keys = c.prepare("PRAGMA foreign_key_check")?;
    if foreign_keys.query([])?.next()?.is_some() {
        return Err(JournalError::InvalidBinding);
    }
    let mut enrollments = c.prepare("SELECT reference,account_id,agreement_id,participant_id FROM signer_enrollments ORDER BY reference")?;
    for row in enrollments.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (reference, id, agreement, participant) = row?;
        let e = read_enrollment(c, &reference)?.ok_or(JournalError::NotFound)?;
        if e.account_id() != account.account_id
            || e.account_id() != id
            || e.agreement_id() != agreement
            || e.participant_id() != participant
            || e.receipt().writer_epoch() > account.writer_epoch
            || e.account_fvk_digest() != genesis.identity.full_viewing_key_digest
            || e.terms.network_profile_id != genesis.identity.network_profile_id
        {
            return Err(JournalError::InvalidBinding);
        }
    }
    let mut manifests = c.prepare("SELECT reference,enrollment_ref,proposal_id,proposal_digest FROM signer_accepted_manifests ORDER BY reference")?;
    for row in manifests.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (reference, enrollment, proposal_id, proposal_digest) = row?;
        let m = read_manifest(c, &reference)?.ok_or(JournalError::NotFound)?;
        let e = read_enrollment(c, &enrollment)?.ok_or(JournalError::NotFound)?;
        let p = m.proposal()?;
        if m.enrollment_ref() != enrollment
            || m.terms.account_id != account.account_id
            || m.terms.account_id != e.account_id()
            || m.terms.principal_id != e.principal_id()
            || p.input().proposal_id != proposal_id
            || p.proposal_digest() != proposal_digest
            || p.manifest().agreement.agreement_id != e.agreement_id()
            || p.manifest().agreement.network_profile_id != e.terms.network_profile_id
            || !same_native_origin(m.receipt(), e.receipt())
        {
            return Err(JournalError::InvalidBinding);
        }
        e.transport().validate_scope(
            e.account_id(),
            e.agreement_id(),
            e.participant_id(),
            Some(p.manifest_digest()),
        )?;
        if !p.manifest().participants.iter().any(|owner| {
            owner.account_id == e.account_id() && owner.participant_id == e.participant_id()
        }) {
            return Err(JournalError::InvalidBinding);
        }
    }
    // Historical data kernel validates every typed outbox cell, exact local
    // enrollment/manifest foreign key and original native origin. It does not
    // issue authority or call the v1-only financial intent reader.
    durable_construction_v1::validate_rows(c)?;
    let intents = financial_admission_intents::read_all(c)?;
    if intents.len() > 1 {
        return Err(JournalError::Conflict);
    }
    for intent in intents {
        let financial_admission_intents::HistoricalFinancialAdmissionIntent::V2(intent) = intent
        else {
            return Err(JournalError::RecoveryRequired);
        };
        require_witness(intent.disclosure(), genesis)?;
        if intent.owner_certificate_digest() != genesis.owner_certificate_digest {
            return Err(JournalError::InvalidBinding);
        }
    }
    Ok(())
}
impl SignerConsentJournal {
    pub(crate) fn open_durable_delivery_entry_v2(
        path: &Path,
        key: &DatabaseKey,
        genesis: &AccountUseGenesis,
        source: &Arc<SignerJournalSourceOwner>,
    ) -> Result<Self> {
        let mut owner = source.begin(path)?;
        let opened = open_preflighted_encrypted(
            &mut owner,
            path,
            key,
            &genesis.identity.account_id,
            Some(genesis),
            &|c| validate_delivery_v2(c, genesis, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES)),
        )?;
        Ok(Self::from_owned_source(opened))
    }
    pub(crate) fn check_durable_delivery_entry_v2(
        &self,
        genesis: &AccountUseGenesis,
    ) -> Result<()> {
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        self.check_durable_delivery_snapshot_v2(genesis)
    }
    pub(crate) fn check_durable_delivery_entry_v2_under_preconstruction_lease(
        &self,
        genesis: &AccountUseGenesis,
        lease: &PreconstructionRecordLease<'_>,
    ) -> Result<()> {
        lease.require_journal(&self.binding())?;
        lease.check_current()?;
        self.check_durable_delivery_snapshot_v2(genesis)?;
        lease.check_current()
    }
    fn check_durable_delivery_snapshot_v2(&self, genesis: &AccountUseGenesis) -> Result<()> {
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        self.database_identity.check_current(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_delivery_v2(&tx, genesis, self.capacity_limits())?;
        self.database_identity.check_current(&tx)?;
        tx.commit()?;
        Ok(())
    }
}

// Purpose-distinct original V3 reopening. This deliberately does not call or
// loosen the V2 suffix reader. Empty original prefixes are accepted; any retained
// admission must be V3-only, with the same original genesis and complete lineage.
#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
fn validate_delivery_v3(
    c: &Connection,
    genesis: &AccountUseGenesis,
    limits: (u64, u64),
) -> Result<()> {
    let account = validate_durable_born_prefix_v1(c, genesis, limits)?;
    for (table, _) in CAPACITY_TABLES {
        if matches!(
            *table,
            "signer_account"
                | "signer_account_use_genesis"
                | "signer_enrollments"
                | "signer_accepted_manifests"
                | "signer_durable_construction_outbox"
                | "signer_durable_payment_admission_intents"
        ) {
            continue;
        }
        if c.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM \"{table}\")"),
            [],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(JournalError::RecoveryRequired);
        }
    }
    let mut foreign_keys = c.prepare("PRAGMA foreign_key_check")?;
    if foreign_keys.query([])?.next()?.is_some() {
        return Err(JournalError::InvalidBinding);
    }
    let mut enrollments = c.prepare("SELECT reference,account_id,agreement_id,participant_id FROM signer_enrollments ORDER BY reference")?;
    for row in enrollments.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (reference, id, agreement, participant) = row?;
        let e = read_enrollment(c, &reference)?.ok_or(JournalError::NotFound)?;
        if e.account_id() != account.account_id
            || e.account_id() != id
            || e.agreement_id() != agreement
            || e.participant_id() != participant
            || e.receipt().writer_epoch() > account.writer_epoch
            || e.account_fvk_digest() != genesis.identity.full_viewing_key_digest
            || e.terms.network_profile_id != genesis.identity.network_profile_id
        {
            return Err(JournalError::InvalidBinding);
        }
    }
    let mut manifests = c.prepare("SELECT reference,enrollment_ref,proposal_id,proposal_digest FROM signer_accepted_manifests ORDER BY reference")?;
    for row in manifests.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (reference, enrollment, proposal_id, proposal_digest) = row?;
        let m = read_manifest(c, &reference)?.ok_or(JournalError::NotFound)?;
        let e = read_enrollment(c, &enrollment)?.ok_or(JournalError::NotFound)?;
        let p = m.proposal()?;
        if m.enrollment_ref() != enrollment
            || m.terms.account_id != account.account_id
            || m.terms.account_id != e.account_id()
            || m.terms.principal_id != e.principal_id()
            || p.input().proposal_id != proposal_id
            || p.proposal_digest() != proposal_digest
            || p.manifest().agreement.agreement_id != e.agreement_id()
            || p.manifest().agreement.network_profile_id != e.terms.network_profile_id
            || !same_native_origin(m.receipt(), e.receipt())
        {
            return Err(JournalError::InvalidBinding);
        }
        e.transport().validate_scope(
            e.account_id(),
            e.agreement_id(),
            e.participant_id(),
            Some(p.manifest_digest()),
        )?;
        if !p.manifest().participants.iter().any(|owner| {
            owner.account_id == e.account_id() && owner.participant_id == e.participant_id()
        }) {
            return Err(JournalError::InvalidBinding);
        }
    }
    // Historical data kernel validates every typed outbox cell, exact local
    // enrollment/manifest foreign key and original native origin. It does not
    // issue authority or call the v1-only financial intent reader.
    durable_construction_v1::validate_rows(c)?;
    let intents = financial_admission_intents::read_all(c)?;
    if intents.len() > 1 {
        return Err(JournalError::Conflict);
    }
    for intent in intents {
        let financial_admission_intents::HistoricalFinancialAdmissionIntent::V3(intent) = intent
        else {
            return Err(JournalError::RecoveryRequired);
        };
        require_witness(intent.disclosure(), genesis)?;
        if intent.owner_certificate_digest() != genesis.owner_certificate_digest {
            return Err(JournalError::InvalidBinding);
        }
    }
    Ok(())
}

#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
impl SignerConsentJournal {
    pub(crate) fn open_durable_delivery_entry_v3(
        path: &Path,
        key: &DatabaseKey,
        genesis: &AccountUseGenesis,
        source: &Arc<SignerJournalSourceOwner>,
    ) -> Result<Self> {
        let mut owner = source.begin(path)?;
        let opened = open_preflighted_encrypted(
            &mut owner, path, key, &genesis.identity.account_id, Some(genesis),
            &|c| validate_delivery_v3(c, genesis, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES)),
        )?;
        Ok(Self::from_owned_source(opened))
    }
    pub(crate) fn check_durable_delivery_entry_v3(&self, genesis: &AccountUseGenesis) -> Result<()> {
        let _fence = self.authority_fence.read().map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        if !c.is_autocommit() { return Err(JournalError::Database); }
        self.database_identity.check_current(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_delivery_v3(&tx, genesis, self.capacity_limits())?;
        self.database_identity.check_current(&tx)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "durable_born_entry_v1_tests.rs"]
mod tests;
