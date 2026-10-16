//! Source foundation: crate-private journal birth publication. Only a genuinely
//! native-approved, durably reserved namespace intent can reach this factory.
use super::*;
use crate::pending_birth::PendingBirthCommitRecord;
use crate::witness_locator::{BirthDisposition, ReservedWitnessBirth};
use wholepact_storage_security::{
    DatabaseFileIdentity, PlannedWitnessBirthInitialization, PlannedWitnessBirthInspection,
};

pub(crate) enum PendingBirthTargetInspection {
    Absent,
    AuthenticatedEmpty,
    Committed {
        record: Box<PendingBirthCommitRecord>,
        identity: DatabaseFileIdentity,
    },
}
impl AuthorityJournal {
    /// Caller holds canonical namespace/target writer and replacement exclusion.
    /// Read-only authentication precedes any writable handle, including rejects.
    pub(crate) fn inspect_pending_birth_for_locator(
        path: &Path,
        key: &DatabaseKey,
        expected_policy: &AccountPolicy,
        namespace_digest: &str,
        intent_digest: &str,
    ) -> Result<PendingBirthTargetInspection> {
        expected_policy.validate()?;
        if expected_policy.account_use_genesis.is_none() {
            return Err(AuthorityError::InvalidBinding);
        }
        let planned =
            PlannedWitnessBirthInitialization::new(namespace_digest, intent_digest, path, key)?;
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                for suffix in ["-wal", "-shm", "-journal"] {
                    let mut sidecar = path.as_os_str().to_os_string();
                    sidecar.push(suffix);
                    match std::fs::symlink_metadata(std::path::PathBuf::from(sidecar)) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        _ => return Err(AuthorityError::CorruptHistory),
                    }
                }
                return Ok(PendingBirthTargetInspection::Absent);
            }
            Err(_) => return Err(AuthorityError::Storage),
            Ok(_) => {}
        }
        let snapshot = match planned.inspect(path, key, namespace_digest, intent_digest)? {
            PlannedWitnessBirthInspection::AuthenticatedEmpty => {
                return Ok(PendingBirthTargetInspection::AuthenticatedEmpty);
            }
            PlannedWitnessBirthInspection::Initialized(snapshot) => snapshot,
        };
        let c = snapshot.connection();
        let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if app != APPLICATION_ID || !matches!(version, 5 | SCHEMA_VERSION) {
            return Err(AuthorityError::UnsupportedVersion);
        }
        verify_schema(c)?;
        let record = matching_record(c, expected_policy)?;
        if is_quarantined(c)? {
            return Err(AuthorityError::Inactive);
        }
        drop(snapshot);
        let actual = wholepact_storage_security::open_encrypted_quiescent(path, key)?;
        verify_schema(actual.connection())?;
        if matching_record(actual.connection(), expected_policy)? != record
            || is_quarantined(actual.connection())?
        {
            return Err(AuthorityError::CorruptHistory);
        }
        let identity = actual.database_identity()?;
        Ok(PendingBirthTargetInspection::Committed {
            record: Box::new(record),
            identity,
        })
    }

    pub(crate) fn open_born_history_only(
        owner: std::sync::Arc<crate::witness_locator::BornJournalOwner>,
        path: &Path,
        key: &DatabaseKey,
        policy: &AccountPolicy,
        expected: &PendingBirthCommitRecord,
    ) -> Result<Self> {
        owner.check_current()?;
        // Exact namespace owner already holds writer/replacement exclusion.
        let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(path, key)?;
        verify_schema(snapshot.connection())?;
        if matching_record(snapshot.connection(), policy)? != *expected
            || is_quarantined(snapshot.connection())?
        {
            return Err(AuthorityError::CorruptHistory);
        }
        drop(snapshot);
        let connection = wholepact_storage_security::open_encrypted_quiescent(path, key)?;
        verify_schema(connection.connection())?;
        if matching_record(connection.connection(), policy)? != *expected
            || is_quarantined(connection.connection())?
        {
            return Err(AuthorityError::CorruptHistory);
        }
        owner.check_current()?;
        Ok(Self {
            connection: Mutex::new(connection),
            resolution_node: Mutex::new(None),
            born_owner: Some(owner),
            born_manual_scope: None,
        })
    }

    pub(crate) fn create_pending_birth(reserved: &mut ReservedWitnessBirth) -> Result<Self> {
        reserved.check_current()?;
        let request = reserved.request().clone();
        let path = reserved.path().to_path_buf();
        let namespace_digest = reserved.namespace_digest().to_owned();
        let intent_digest = reserved.intent_digest().to_owned();
        let first_allowed = matches!(reserved.disposition(), BirthDisposition::FirstCommitAllowed);
        let inspection = Self::inspect_pending_birth_for_locator(
            &path,
            reserved.database_key(),
            &request.policy,
            &namespace_digest,
            &intent_digest,
        )?;
        let (connection, existing) = match inspection {
            PendingBirthTargetInspection::Committed { record, identity } => {
                reserved.validate_authenticated_record(&record)?;
                reserved.check_current()?;
                let connection = wholepact_storage_security::open_encrypted_quiescent(
                    &path,
                    reserved.database_key(),
                )?;
                identity.check_current(connection.connection())?;
                (connection, Some(*record))
            }
            PendingBirthTargetInspection::AuthenticatedEmpty => {
                if !first_allowed {
                    return Err(AuthorityError::Permission);
                }
                request.require_initial_commit_time(crate::now_ms()?)?;
                reserved.check_current()?;
                let empty = PlannedWitnessBirthInitialization::new(
                    &namespace_digest,
                    &intent_digest,
                    &path,
                    reserved.database_key(),
                )?;
                (
                    empty.resume(
                        &path,
                        reserved.database_key(),
                        &namespace_digest,
                        &intent_digest,
                    )?,
                    None,
                )
            }
            PendingBirthTargetInspection::Absent => {
                if !first_allowed {
                    return Err(AuthorityError::Permission);
                }
                request.require_initial_commit_time(crate::now_ms()?)?;
                reserved.check_current()?;
                (
                    wholepact_storage_security::create_encrypted(&path, reserved.database_key())?,
                    None,
                )
            }
        };
        configure(connection.connection())?;
        let record = if let Some(record) = existing {
            record
        } else {
            reserved.check_current()?;
            request.require_initial_commit_time(crate::now_ms()?)?;
            let tx = Transaction::new_unchecked(
                connection.connection(),
                TransactionBehavior::Immediate,
            )?;
            let app: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
            let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
            let objects: u64 =
                tx.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
            if app != 0 || version != 0 || objects != 0 {
                return Err(AuthorityError::CorruptHistory);
            }
            tx.execute_batch(SCHEMA)?;
            tx.execute(
                "INSERT INTO authority_genesis VALUES(1,?1)",
                [&*encode(&request.policy)?],
            )?;
            tx.execute("INSERT INTO authority_quarantine VALUES(1,0)", [])?;
            for peer in [
                &request.policy.owner_certificate_digest,
                &request.policy.initial_writer_certificate_digest,
            ] {
                tx.execute("INSERT INTO authority_principals VALUES(?1)", [peer])?;
            }
            // Capture the actual first-record timestamp at this boundary, never
            // reuse native admission time as a fictional durable commit time.
            let record = reserved.initial_commit_record(crate::now_ms()?)?;
            record.validate()?;
            tx.execute(
                "INSERT INTO authority_pending_birth_commit VALUES(1,?1,?2,?3)",
                params![
                    record.request.operation_id,
                    record.request_digest,
                    serde_json::to_string(&record).map_err(|_| AuthorityError::InvalidBinding)?,
                ],
            )?;
            tx.pragma_update(None, "application_id", APPLICATION_ID)?;
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            verify_schema(&tx)?;
            if matching_record(&tx, &request.policy)? != record {
                return Err(AuthorityError::CorruptHistory);
            }
            reserved.check_current()?;
            request.require_initial_commit_time(crate::now_ms()?)?;
            tx.commit()?;
            record
        };
        verify_schema(connection.connection())?;
        if matching_record(connection.connection(), &request.policy)? != record
            || is_quarantined(connection.connection())?
        {
            return Err(AuthorityError::CorruptHistory);
        }
        std::fs::File::open(path.parent().ok_or(AuthorityError::Storage)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| AuthorityError::Storage)?;
        connection
            .database_identity()?
            .check_current(connection.connection())?;
        reserved.check_current()?;
        reserved.complete_authenticated(&request.policy, &record, &connection)?;
        let born_owner = reserved.owner();
        born_owner.check_current()?;
        Ok(Self {
            connection: Mutex::new(connection),
            resolution_node: Mutex::new(None),
            born_owner: Some(born_owner),
            born_manual_scope: None,
        })
    }
}
fn matching_record(c: &Connection, expected: &AccountPolicy) -> Result<PendingBirthCommitRecord> {
    let ledger = load(c)?;
    let record = crate::pending_birth_storage::read(c, &ledger.policy)?
        .ok_or(AuthorityError::CorruptHistory)?;
    if &ledger.policy != expected || &record.request.policy != expected {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(record)
}
