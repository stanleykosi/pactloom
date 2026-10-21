//! Concrete Entry-only exact19 opener. The maintained legacy storage bodies are
//! unchanged. Original selection/root/account/key custody is checked by the
//! private source opener; this leaf keeps its genuine Final live across every
//! blocking database acquisition and before every private audit.
use super::*;
use wholepact_authority::account_use::AccountUseGenesis;
use wholepact_financial_coordinator_origin::{
    SignerSourceEntryFinalV1, SignerV3SourceEntryFinalV1,
};

// Closed genuine-purpose choice, private to the maintained original19 opener.
// Neither variant accepts a boolean, caller callback, or reconstructed grant.
enum EntryPermit<'a> {
    Financial(&'a SignerSourceEntryFinalV1),
    V3(&'a SignerV3SourceEntryFinalV1),
}

fn current(entry: &EntryPermit<'_>) -> Result<()> {
    match entry {
        EntryPermit::Financial(entry) => entry.check_current(),
        EntryPermit::V3(entry) => entry.check_current(),
    }
    .map_err(|_| JournalError::Permission)
}

impl SignerConsentJournal {
    pub(crate) fn open_coordinated_delivery_entry_v2(
        path: &Path,
        key: &DatabaseKey,
        genesis: &AccountUseGenesis,
        source: &Arc<SignerJournalSourceOwner>,
        entry: &SignerSourceEntryFinalV1,
    ) -> Result<Self> {
        let permit = EntryPermit::Financial(entry);
        Self::open_original19_with_entry(path, key, genesis, source, &permit)
    }

    pub(crate) fn open_coordinated_v3_source_entry_v1(
        path: &Path,
        key: &DatabaseKey,
        genesis: &AccountUseGenesis,
        source: &Arc<SignerJournalSourceOwner>,
        entry: &SignerV3SourceEntryFinalV1,
    ) -> Result<Self> {
        let permit = EntryPermit::V3(entry);
        Self::open_original19_with_entry(path, key, genesis, source, &permit)
    }

    fn open_original19_with_entry(
        path: &Path,
        key: &DatabaseKey,
        genesis: &AccountUseGenesis,
        source: &Arc<SignerJournalSourceOwner>,
        entry: &EntryPermit<'_>,
    ) -> Result<Self> {
        current(entry)?;
        let mut owner = source.begin(path)?;
        current(entry)?;
        let opened = open_original19(&mut owner, path, key, genesis, entry)?;
        current(entry)?;
        Ok(Self::from_owned_source(opened))
    }
}

fn validate_original19(
    c: &Connection,
    genesis: &AccountUseGenesis,
    entry: &EntryPermit<'_>,
) -> Result<()> {
    current(entry)?;
    if preflight_original(c, &genesis.identity.account_id, Some(genesis))? != SCHEMA_VERSION {
        return Err(JournalError::UnsupportedSchema);
    }
    current(entry)?;
    match entry {
        // Financial Entry must reopen one genuinely completed original. Its
        // strict discriminator selects historical data, never authority.
        EntryPermit::Financial(_) => financial_profile_v1::original_delivery::validate(
            c, genesis, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
        )?,
        // Initial V3 Entry still accepts only its unchanged original profile;
        // it cannot replay a completed coordinated admission as a fresh source.
        EntryPermit::V3(_) => durable_born_entry_v1::validate_delivery_v3(
            c, genesis, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
        )?,
    }
    current(entry)
}

fn open_original19(
    owner: &mut OriginalSourceOpen<'_>,
    path: &Path,
    key: &DatabaseKey,
    genesis: &AccountUseGenesis,
    entry: &EntryPermit<'_>,
) -> Result<OpenedSignerSource> {
    let account_id = &genesis.identity.account_id;
    id(account_id)?;
    current(entry)?;
    let held = owner.state.upgrade();
    if let Some(live) = held.as_ref() {
        if live.account_id != *account_id || !Arc::ptr_eq(&live.owner, owner.owner) {
            return Err(JournalError::InvalidBinding);
        }
        owner
            .owner
            .directory
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        current(entry)?;
        live.identity.check_retained_owner_path()?;
        current(entry)?;
        let encrypted = wholepact_storage_security::open_encrypted(path, key)?;
        current(entry)?;
        let identity = encrypted.database_identity()?;
        current(entry)?;
        if identity != live.identity {
            return Err(JournalError::InvalidBinding);
        }
        let mut connection = encrypted.into_connection();
        {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            current(entry)?;
            validate_original19(&tx, genesis, entry)?;
            identity.check_current(&tx)?;
            current(entry)?;
            tx.commit()?;
            current(entry)?;
        }
        configure(&connection)?;
        current(entry)?;
        let registration =
            owner.register_coordinated_entry_v2(&connection, &identity, account_id, entry)?;
        current(entry)?;
        return Ok(OpenedSignerSource {
            connection,
            identity,
            registration,
        });
    }
    owner.require_exclusive()?;
    current(entry)?;
    let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(path, key)?;
    current(entry)?;
    let original_identity = snapshot.source_database_identity()?;
    current(entry)?;
    {
        let tx = rusqlite::Transaction::new_unchecked(
            snapshot.connection(),
            TransactionBehavior::Deferred,
        )?;
        current(entry)?;
        validate_original19(&tx, genesis, entry)?;
        tx.commit()?;
        current(entry)?;
    }
    snapshot.check_source_unchanged()?;
    current(entry)?;
    owner
        .owner
        .directory
        .check_current()
        .map_err(|_| JournalError::Permission)?;
    current(entry)?;
    let encrypted = wholepact_storage_security::open_encrypted_quiescent(path, key)?;
    current(entry)?;
    let identity = encrypted.database_identity()?;
    current(entry)?;
    if identity != original_identity {
        return Err(JournalError::InvalidBinding);
    }
    let mut connection = encrypted.into_connection();
    identity.check_current(&connection)?;
    current(entry)?;
    if preflight_original(&connection, account_id, Some(genesis))? != SCHEMA_VERSION {
        return Err(JournalError::Conflict);
    }
    current(entry)?;
    drop(snapshot);
    // Known original genesis preflight above permits only current19, exactly as
    // the legacy born opener. No migration, initialization or repair branch.
    {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        current(entry)?;
        validate_original19(&tx, genesis, entry)?;
        identity.check_current(&tx)?;
        current(entry)?;
        tx.commit()?;
        current(entry)?;
    }
    configure(&connection)?;
    current(entry)?;
    let registration =
        owner.register_coordinated_entry_v2(&connection, &identity, account_id, entry)?;
    current(entry)?;
    Ok(OpenedSignerSource {
        connection,
        identity,
        registration,
    })
}

impl OriginalSourceOpen<'_> {
    /// The maintained current19 registration checks and field/drop order, with
    /// genuine Entry observation between metadata acquisition and private rows.
    fn register_coordinated_entry_v2(
        &mut self,
        connection: &Connection,
        identity: &wholepact_storage_security::DatabaseFileIdentity,
        account_id: &str,
        entry: &EntryPermit<'_>,
    ) -> Result<Arc<LiveCurrent19Source>> {
        current(entry)?;
        self.owner
            .directory
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        current(entry)?;
        identity.check_current(connection)?;
        current(entry)?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        current(entry)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        current(entry)?;
        if application != APPLICATION_ID
            || version != SCHEMA_VERSION
            || read_account(connection)?.account_id != account_id
        {
            return Err(JournalError::InvalidBinding);
        }
        current(entry)?;
        verify_schema(connection)?;
        current(entry)?;
        identity.check_current(connection)?;
        current(entry)?;
        self.owner
            .directory
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        current(entry)?;
        if let Some(live) = self.state.upgrade() {
            if live.identity != *identity
                || live.account_id != account_id
                || !Arc::ptr_eq(&live.owner, self.owner)
            {
                return Err(JournalError::InvalidBinding);
            }
            return Ok(live);
        }
        let live = Arc::new(LiveCurrent19Source {
            identity: identity.clone(),
            account_id: account_id.into(),
            owner: Arc::clone(self.owner),
        });
        *self.state = Arc::downgrade(&live);
        Ok(live)
    }
}
