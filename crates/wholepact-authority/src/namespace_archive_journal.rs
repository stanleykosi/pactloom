//! Read-only typed witness history for encrypted namespace capsules. These data
//! projections never become an AuthorityJournal, writer, admission or live owner.
use super::*;
use crate::account_use::{AccountUseCheckpoint, PermanentAccountExclusion};
use crate::pending_birth::PendingBirthCommitRecord;
use serde::{Deserialize, Serialize};
use wholepact_storage_security::bundle::{JournalKind, JournalTemplate};

pub(crate) static NAMESPACE_ACCOUNT_TEMPLATE_V5: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: APPLICATION_ID,
    schema_version: 5,
    create_sql: SCHEMA_V5,
};
pub(crate) static NAMESPACE_ACCOUNT_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: APPLICATION_ID,
    schema_version: SCHEMA_VERSION,
    create_sql: SCHEMA,
};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceJournalStamp {
    pub(crate) policy_digest: String,
    pub(crate) birth_record_digest: String,
    pub(crate) head: AuthorityHead,
    pub(crate) account_use_checkpoint: AccountUseCheckpoint,
    pub(crate) snapshot_digest: String,
    pub(crate) quarantined: bool,
}
#[derive(Serialize)]
pub(crate) struct HistoricalNamespaceAccount {
    pub(crate) policy: AccountPolicy,
    pub(crate) birth: PendingBirthCommitRecord,
    pub(crate) snapshot: AccountSnapshot,
    pub(crate) permanent_exclusion: Option<PermanentAccountExclusion>,
    pub(crate) historical_only: bool,
}
#[derive(Serialize)]
pub(crate) struct HistoricalNamespaceEvent {
    pub(crate) sequence: u64,
    pub(crate) operation_id: String,
    pub(crate) previous_head: String,
    pub(crate) head: String,
    // Raw original event JSON remains inert text, with no conversion to a permit.
    pub(crate) payload: String,
}
#[derive(Serialize)]
pub(crate) struct HistoricalNamespaceHistoryPage {
    pub(crate) source_head: AuthorityHead,
    pub(crate) first_sequence: u64,
    pub(crate) next_sequence: Option<u64>,
    pub(crate) events: Vec<HistoricalNamespaceEvent>,
    pub(crate) historical_only: bool,
}

pub(crate) fn namespace_account_stamp(
    c: &Connection,
    expected: &AccountPolicy,
) -> Result<(NamespaceJournalStamp, PendingBirthCommitRecord)> {
    let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if app != APPLICATION_ID || !matches!(version, 5 | SCHEMA_VERSION) {
        return Err(AuthorityError::UnsupportedVersion);
    }
    verify_schema(c)?;
    // Literal sqlite_ prefix; LIKE's underscore wildcard would hide sqliteX...
    // user tables. Bound schema work before the compiled-template comparison.
    let count: u64 = c.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
        [],
        |r| r.get(0),
    )?;
    let schema_template = Connection::open_in_memory()?;
    schema_template.execute_batch(if version == 5 { SCHEMA_V5 } else { SCHEMA })?;
    let wanted: u64 = schema_template.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
        [],
        |r| r.get(0),
    )?;
    if count != wanted {
        return Err(AuthorityError::CorruptHistory);
    }
    let ledger = load(c)?;
    let birth = crate::pending_birth_storage::read(c, &ledger.policy)?
        .ok_or(AuthorityError::CorruptHistory)?;
    if &ledger.policy != expected
        || &birth.request.policy != expected
        || ledger.policy.account_use_genesis.is_none()
    {
        return Err(AuthorityError::InvalidBinding);
    }
    birth.validate()?;
    let checkpoint = ledger
        .account_use_history
        .checkpoint()?
        .ok_or(AuthorityError::RecoveryRequired)?;
    Ok((
        NamespaceJournalStamp {
            policy_digest: expected.policy_digest()?,
            birth_record_digest: digest("wholepact:namespace-archive-birth-record:v1", &birth)?,
            head: ledger.snapshot.head.clone(),
            account_use_checkpoint: checkpoint,
            snapshot_digest: digest(
                "wholepact:namespace-archive-account-snapshot:v1",
                &ledger.snapshot,
            )?,
            quarantined: is_quarantined(c)?,
        },
        birth,
    ))
}
pub(crate) fn namespace_account_summary(
    c: &Connection,
    expected: &AccountPolicy,
) -> Result<HistoricalNamespaceAccount> {
    namespace_account_stamp(c, expected)?;
    let ledger = load(c)?;
    let birth = crate::pending_birth_storage::read(c, &ledger.policy)?
        .ok_or(AuthorityError::CorruptHistory)?;
    Ok(HistoricalNamespaceAccount {
        policy: ledger.policy.clone(),
        birth,
        snapshot: ledger.snapshot.clone(),
        permanent_exclusion: ledger.account_use_history.exclusion().cloned(),
        historical_only: true,
    })
}
pub(crate) fn namespace_account_history_page(
    c: &Connection,
    expected: &AccountPolicy,
    first_sequence: u64,
    limit: u32,
) -> Result<HistoricalNamespaceHistoryPage> {
    if first_sequence == 0 || limit == 0 || limit > 32 {
        return Err(AuthorityError::InvalidBinding);
    }
    let (stamp, _) = namespace_account_stamp(c, expected)?;
    if first_sequence > stamp.head.sequence.saturating_add(1) {
        return Err(AuthorityError::InvalidBinding);
    }
    let mut statement = c.prepare("SELECT sequence,operation_id,previous_head,head,payload FROM authority_events WHERE sequence>=?1 ORDER BY sequence LIMIT ?2")?;
    let mut rows = statement.query(params![first_sequence, limit])?;
    let mut events = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = rows.next()? {
        let payload: Vec<u8> = row.get(4)?;
        if payload.len() > MAX_FRAME_BYTES {
            return Err(AuthorityError::Limit);
        }
        let sequence: u64 = row.get(0)?;
        if sequence != first_sequence + events.len() as u64 {
            return Err(AuthorityError::CorruptHistory);
        }
        let item = HistoricalNamespaceEvent {
            sequence,
            operation_id: row.get(1)?,
            previous_head: row.get(2)?,
            head: row.get(3)?,
            payload: String::from_utf8(payload).map_err(|_| AuthorityError::CorruptHistory)?,
        };
        let encoded = serde_json::to_vec(&item).map_err(|_| AuthorityError::CorruptHistory)?;
        if encoded.len() > 1024 * 1024 - 1024 {
            return Err(AuthorityError::Limit);
        }
        if bytes + encoded.len() > 1024 * 1024 - 1024 {
            break;
        }
        bytes += encoded.len();
        events.push(item);
    }
    let next = first_sequence + events.len() as u64;
    let page = HistoricalNamespaceHistoryPage {
        source_head: stamp.head.clone(),
        first_sequence,
        next_sequence: (next <= stamp.head.sequence).then_some(next),
        events,
        historical_only: true,
    };
    if serde_json::to_vec(&page)
        .map_err(|_| AuthorityError::CorruptHistory)?
        .len()
        > 1024 * 1024
    {
        return Err(AuthorityError::Limit);
    }
    Ok(page)
}

pub(crate) fn open_namespace_archive_account(
    source: &wholepact_storage_security::generation_archive::ArchivedJournal<'_>,
    key: &DatabaseKey,
) -> wholepact_storage_security::generation_archive::Result<
    wholepact_storage_security::EncryptedReadSnapshot,
> {
    match source.open_ordinary(key, &NAMESPACE_ACCOUNT_TEMPLATE) {
        Err(wholepact_storage_security::generation_archive::ArchiveError::Unsupported) => {
            source.open_ordinary(key, &NAMESPACE_ACCOUNT_TEMPLATE_V5)
        }
        result => result,
    }
}
