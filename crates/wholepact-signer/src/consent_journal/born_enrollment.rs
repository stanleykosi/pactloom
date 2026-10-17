//! One exact born-journal initialization. Only the private native publication
//! owner supplies the target/key/genesis. Retrying never adopts another journal.
use super::*;
use crate::account::birth::enrollment::BornEnrollmentPublication;
use wholepact_authority::account_use::AccountUseGenesis;
use wholepact_storage_security::{
    PlannedWitnessBirthInitialization, PlannedWitnessBirthInspection,
};

impl SignerConsentJournal {
    pub(crate) fn check_initial_born_owner(
        &self,
        genesis: &AccountUseGenesis,
        epoch: u64,
    ) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        verify_born_initial(&connection, genesis, epoch)
    }

    pub(crate) fn verify_initial_born_history(
        path: &Path,
        key: &DatabaseKey,
        genesis: &AccountUseGenesis,
        epoch: u64,
    ) -> Result<()> {
        if let Ok(snapshot) =
            wholepact_storage_security::bundle::open_journal_read_snapshot(path, key, &TEMPLATE)
        {
            return verify_born_with_common_audit(snapshot.connection(), genesis, epoch, None);
        }
        // Old encrypted artifacts keep their own exact schema and bytes. This
        // is read-only; backup inspection must never migrate the source tree.
        for (version, schema) in [
            (17, recovery_migration::V17_SCHEMA),
            (16, recovery_migration::V16_SCHEMA),
            (15, recovery_migration::V15_SCHEMA),
            (14, recovery_migration::V14_SCHEMA),
        ] {
            let old = recovery_activation::recovery_template(version)?;
            if let Ok(snapshot) =
                wholepact_storage_security::bundle::open_journal_read_snapshot(path, key, old)
            {
                recovery_migration::verify_exact_schema(snapshot.connection(), schema)?;
                verify_born_identity_cells(snapshot.connection(), genesis, epoch)?;
                if version >= 15 {
                    common_context_reentry_audit_v1::read_complete(
                        snapshot.connection(),
                        &genesis.identity.account_id,
                    )?;
                }
                return verify_common_audit_tables(snapshot.connection(), genesis, epoch, None);
            }
        }
        let old = recovery_activation::recovery_template(13)?;
        let snapshot =
            wholepact_storage_security::bundle::open_journal_read_snapshot(path, key, old)
                .map_err(|_| JournalError::InvalidBinding)?;
        verify_born_initial_schema13(snapshot.connection(), genesis, epoch)
    }
    pub(crate) fn publish_born_enrollment(
        publication: &BornEnrollmentPublication<'_>,
    ) -> Result<Self> {
        publication
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        let path = publication.journal_path();
        let key = publication.journal_key();
        let genesis = publication.genesis();
        let epoch = publication.writer_epoch();
        let namespace = genesis.digest().map_err(|_| JournalError::InvalidBinding)?;
        let intent = publication.intent_digest();
        let plan = PlannedWitnessBirthInitialization::new(&namespace, intent, &path, &key)?;
        let mut connection = match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                wholepact_storage_security::create_encrypted(&path, &key)?.into_connection()
            }
            Err(_) => return Err(JournalError::Database),
            Ok(_) => match plan.inspect(&path, &key, &namespace, intent)? {
                PlannedWitnessBirthInspection::AuthenticatedEmpty => plan
                    .resume(&path, &key, &namespace, intent)?
                    .into_connection(),
                PlannedWitnessBirthInspection::Initialized(read) => {
                    verify_born_initial(read.connection(), genesis, epoch)?;
                    drop(read);
                    publication
                        .check_current()
                        .map_err(|_| JournalError::Permission)?;
                    let existing = Self::open_encrypted(&path, &key, &genesis.identity.account_id)?;
                    verify_born_initial(
                        &*existing
                            .connection
                            .lock()
                            .map_err(|_| JournalError::Database)?,
                        genesis,
                        epoch,
                    )?;
                    return Ok(existing);
                }
            },
        };
        // Creation and immutable account-use genesis share one SQLite commit.
        // A crash before this commit leaves only the authenticated empty page
        // that the exact durable intent above is allowed to retry.
        configure(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        verify_capacity_schema(&tx)?;
        let epoch = i64::try_from(epoch).map_err(|_| JournalError::InvalidBinding)?;
        if epoch <= 0 {
            return Err(JournalError::InvalidBinding);
        }
        tx.execute(
            "INSERT INTO signer_account VALUES(1,?1,?2,0)",
            params![genesis.identity.account_id, epoch],
        )?;
        tx.execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            params![
                genesis.identity.account_id,
                genesis.identity.full_viewing_key_digest,
                namespace,
                encode(genesis)?.as_str()
            ],
        )?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        verify_born_initial(&tx, genesis, epoch as u64)?;
        publication
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        tx.commit()?;
        drop(connection);
        let result = Self::open_encrypted(&path, &key, &genesis.identity.account_id)?;
        verify_born_initial(
            &*result
                .connection
                .lock()
                .map_err(|_| JournalError::Database)?,
            genesis,
            epoch as u64,
        )?;
        Ok(result)
    }
}
fn verify_born_identity(c: &Connection, genesis: &AccountUseGenesis, epoch: u64) -> Result<()> {
    verify_schema(c)?;
    verify_born_identity_cells(c, genesis, epoch)
}
fn verify_born_identity_cells(
    c: &Connection,
    genesis: &AccountUseGenesis,
    epoch: u64,
) -> Result<()> {
    let account = read_account(c)?;
    let stored = account_use_storage::inspect(c, &genesis.identity.account_id)?;
    if account.account_id != genesis.identity.account_id
        || account.writer_epoch != epoch
        || stored.genesis() != Some(genesis)
    {
        return Err(JournalError::InvalidBinding);
    }
    // Retained exclusions remain readable. Financial callers must use their own
    // fresh action-specific gates, never infer eligibility from this opener.
    Ok(())
}
fn verify_born_initial(c: &Connection, genesis: &AccountUseGenesis, epoch: u64) -> Result<()> {
    verify_born_identity(c, genesis, epoch)?;
    if read_account(c)?.recovery_required {
        return Err(JournalError::RecoveryRequired);
    }
    let mut statement = c.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for name in names {
        // Identifiers originate only from the executable-verified exact schema.
        let expected = usize::from(matches!(
            name.as_str(),
            "signer_account" | "signer_account_use_genesis"
        ));
        let actual: usize = c.query_row(
            &format!("SELECT count(*) FROM \"{}\"", name.replace('"', "\"\"")),
            [],
            |r| r.get(0),
        )?;
        if actual != expected {
            return Err(JournalError::RecoveryRequired);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "born_enrollment/schema_tests.rs"]
mod schema_tests;

#[path = "born_enrollment/roster_v2.rs"]
mod roster_v2;

impl SignerConsentJournal {
    pub(crate) fn check_common_context_original_owner(
        &self,
        genesis: &AccountUseGenesis,
        epoch: u64,
        plan: &wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3,
    ) -> Result<()> {
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        verify_born_with_common_audit(&c, genesis, epoch, Some(plan))
    }
}
fn verify_born_with_common_audit(
    c: &Connection,
    genesis: &AccountUseGenesis,
    epoch: u64,
    plan: Option<&wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3>,
) -> Result<()> {
    verify_born_identity(c, genesis, epoch)?;
    verify_common_audit_tables(c, genesis, epoch, plan)
}
fn verify_common_audit_tables(
    c: &Connection,
    genesis: &AccountUseGenesis,
    _epoch: u64,
    plan: Option<&wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3>,
) -> Result<()> {
    if read_account(c)?.recovery_required {
        return Err(JournalError::RecoveryRequired);
    }
    let audit = construction_audit_v3::read_all(c, &genesis.identity.account_id)?;
    if let Some(plan) = plan {
        plan.validate().map_err(|_| JournalError::InvalidBinding)?;
        if audit.rows.iter().any(|r| r.plan() != plan) {
            return Err(JournalError::Conflict);
        }
    }
    verify_common_audit_table_counts(c, plan.is_none())
}

/// Table/capacity policy only; callers must first fully validate the audit in
/// the same current view (or the same read transaction for completion reentry).
fn verify_common_audit_table_counts(c: &Connection, allow_reentry: bool) -> Result<()> {
    let mut q = c.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )?;
    let names = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for name in names {
        if name == "signer_common_context_audit_v3"
            || (allow_reentry && name == "signer_common_context_reentry_v1")
        {
            continue;
        }
        let expected = usize::from(matches!(
            name.as_str(),
            "signer_account" | "signer_account_use_genesis"
        ));
        let actual: usize = c.query_row(
            &format!("SELECT count(*) FROM \"{}\"", name.replace('"', "\"\"")),
            [],
            |r| r.get(0),
        )?;
        if actual != expected {
            return Err(JournalError::RecoveryRequired);
        }
    }
    Ok(())
}

fn verify_born_initial_schema13(
    c: &Connection,
    genesis: &AccountUseGenesis,
    epoch: u64,
) -> Result<()> {
    recovery_migration::verify_exact_schema(c, recovery_migration::V13_SCHEMA)?;
    let account = read_account(c)?;
    let stored = account_use_storage::inspect(c, &genesis.identity.account_id)?;
    if account.account_id != genesis.identity.account_id
        || account.writer_epoch != epoch
        || account.recovery_required
        || stored.genesis() != Some(genesis)
    {
        return Err(JournalError::InvalidBinding);
    }
    let mut q = c.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )?;
    let names = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for name in names {
        let expected = usize::from(matches!(
            name.as_str(),
            "signer_account" | "signer_account_use_genesis"
        ));
        let actual: usize = c.query_row(
            &format!("SELECT count(*) FROM \"{}\"", name.replace('"', "\"\"")),
            [],
            |r| r.get(0),
        )?;
        if actual != expected {
            return Err(JournalError::RecoveryRequired);
        }
    }
    Ok(())
}

impl SignerConsentJournal {
    /// Read-only exact authenticated lineage check for the actual native owner.
    /// `require_unclaimed` is only a stricter inventory assertion; neither value
    /// grants any native, witness, transport or construction capability.
    pub(crate) fn check_common_context_authorized_reentry_owner(
        &self,
        input: &CommonContextAuthorizedReentryOwnerInput<'_>,
        require_unclaimed: bool,
    ) -> Result<CommonContextSignerAuditV1> {
        let &CommonContextAuthorizedReentryOwnerInput {
            genesis,
            epoch,
            read_digest,
            attempt_digest,
            attempt_sequence,
            plan,
            authorization_digest,
        } = input;
        hash(read_digest)?;
        hash(attempt_digest)?;
        hash(authorization_digest)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        // This private check owns a fresh read-only transaction, never an outer
        // caller's transaction. Failure drops/rolls back only this transaction.
        if !c.is_autocommit() {
            return Err(JournalError::Database);
        }
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let validated = verify_schema_with_common_audit(&tx)?;
        verify_born_identity_cells(&tx, genesis, epoch)?;
        if read_account(&tx)?.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        verify_common_audit_table_counts(&tx, true)?;
        let audit = validated.inventory_for(&genesis.identity.account_id)?;
        let [row @ CommonContextSignerAuditV1::ReadAdmitted { evidence, .. }] =
            audit.original.rows.as_slice()
        else {
            return Err(JournalError::Conflict);
        };
        if &evidence.request.plan != plan
            || evidence
                .digest()
                .map_err(|_| JournalError::InvalidBinding)?
                != read_digest
            || evidence.current_attempt_digest != attempt_digest
            || evidence.current_attempt_sequence != attempt_sequence
            || audit.reentry.rows.is_empty()
            || (require_unclaimed && audit.reentry.rows.len() != 1)
            || audit.reentry.rows.iter().any(|r| {
                r.original_read_admission_digest != read_digest
                    || r.invocation_digest != plan.invocation_digest().unwrap_or_default()
            })
        {
            return Err(JournalError::Conflict);
        }
        let authorized = audit
            .reentry
            .rows
            .iter()
            .find_map(|r| match &r.record {
                CommonContextReentryAuditPhaseV1::Authorized { authorization } => {
                    Some(authorization)
                }
                _ => None,
            })
            .ok_or(JournalError::InvalidBinding)?;
        if authorized
            .digest()
            .map_err(|_| JournalError::InvalidBinding)?
            != authorization_digest
        {
            return Err(JournalError::Conflict);
        }
        // Only the already-existing inert receipt leaves this read. The
        // validated inventory is not retained as permission for a later call.
        let receipt = row.clone();
        drop(validated);
        tx.commit()?;
        Ok(receipt)
    }
}
