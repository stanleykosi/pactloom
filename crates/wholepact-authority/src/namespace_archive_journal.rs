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
pub(crate) static NAMESPACE_ACCOUNT_TEMPLATE_V7: std::sync::LazyLock<JournalTemplate> =
    std::sync::LazyLock::new(|| JournalTemplate {
        kind: JournalKind::CoordinationAuthority,
        application_id: APPLICATION_ID,
        schema_version: BORN_ARTIFACT_SCHEMA_VERSION,
        create_sql: schema_v7(),
    });
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceJournalStamp {
    pub(crate) policy_digest: String,
    pub(crate) birth_record_digest: String,
    pub(crate) head: AuthorityHead,
    pub(crate) account_use_checkpoint: AccountUseCheckpoint,
    pub(crate) snapshot_digest: String,
    pub(crate) quarantined: bool,
    pub(crate) retained_state_digest: String,
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
    namespace_account_stamp_profile(c, expected, OriginalHistoryProfileV1::Legacy)
}
pub(crate) fn namespace_financial_account_stamp_v1(c: &Connection, expected: &AccountPolicy) -> Result<(NamespaceJournalStamp, PendingBirthCommitRecord)> {
    namespace_account_stamp_profile(c, expected, OriginalHistoryProfileV1::FinancialContinuation)
}
fn namespace_account_stamp_profile(c: &Connection, expected: &AccountPolicy, profile: OriginalHistoryProfileV1) -> Result<(NamespaceJournalStamp, PendingBirthCommitRecord)> {
    let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if app != APPLICATION_ID || !matches!(version, 5..=7) {
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
    schema_template.execute_batch(schema_for_version(version)?)?;
    let wanted: u64 = schema_template.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
        [],
        |r| r.get(0),
    )?;
    if count != wanted {
        return Err(AuthorityError::CorruptHistory);
    }
    let ledger = load_profile(c, profile)?;
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
            retained_state_digest: retained_state_digest(c)?,
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
    match source.open_ordinary(key, &NAMESPACE_ACCOUNT_TEMPLATE_V7) {
        Err(wholepact_storage_security::generation_archive::ArchiveError::Unsupported) => {
            match source.open_ordinary(key, &NAMESPACE_ACCOUNT_TEMPLATE) {
                Err(wholepact_storage_security::generation_archive::ArchiveError::Unsupported) => {
                    source.open_ordinary(key, &NAMESPACE_ACCOUNT_TEMPLATE_V5)
                }
                result => result,
            }
        }
        result => result,
    }
}

/// Covers every retained value, including keys, retry/original records, mailbox
/// receipt/outbox state and acknowledgments which do not advance AuthorityHead.
/// The exact schema is verified before identifiers enter this fixed-schema walk.
/// Only a domain-separated digest leaves this function; private cells are never
/// serialized, logged or returned as historical presentation data.
fn retained_state_digest(c: &Connection) -> Result<String> {
    use rusqlite::types::ValueRef;
    let mut h = Sha256::new();
    h.update(b"wholepact:namespace-retained-state:v1\0");
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    h.update(version.to_be_bytes());
    let mut tables = c.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name")?;
    let names = tables
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut total = 0u64;
    let mut row_count = 0u64;
    for name in names {
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(AuthorityError::CorruptHistory);
        }
        h.update([0]);
        h.update((name.len() as u64).to_be_bytes());
        h.update(name.as_bytes());
        let count = c
            .prepare(&format!("SELECT * FROM {name} LIMIT 0"))?
            .column_count();
        let order = (1..=count)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut q = c.prepare(&format!("SELECT * FROM {name} ORDER BY {order}"))?;
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? {
            row_count += 1;
            if row_count > 262_144 {
                return Err(AuthorityError::Limit);
            }
            h.update([1]);
            h.update((count as u64).to_be_bytes());
            for i in 0..count {
                match row.get_ref(i)? {
                    ValueRef::Null => h.update([0]),
                    ValueRef::Integer(n) => {
                        h.update([1]);
                        h.update(n.to_be_bytes());
                    }
                    ValueRef::Real(_) => return Err(AuthorityError::CorruptHistory),
                    ValueRef::Text(v) | ValueRef::Blob(v) => {
                        total = total
                            .checked_add(v.len() as u64)
                            .ok_or(AuthorityError::Limit)?;
                        if total > 512 * 1024 * 1024 {
                            return Err(AuthorityError::Limit);
                        }
                        h.update([if matches!(row.get_ref(i)?, ValueRef::Text(_)) {
                            2
                        } else {
                            3
                        }]);
                        h.update((v.len() as u64).to_be_bytes());
                        h.update(v);
                    }
                }
            }
        }
        h.update([2]);
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod retained_stamp_tests {
    use super::*;
    #[test]
    fn full_stamp_tracks_secret_original_mailbox_and_delivery_without_head_change() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(schema_v7()).unwrap();
        c.pragma_update(None, "user_version", 7).unwrap();
        let empty = retained_state_digest(&c).unwrap();
        c.execute(
            "INSERT INTO authority_session_keys VALUES(?1,?2)",
            params!["1".repeat(64), [9u8; 32].as_slice()],
        )
        .unwrap();
        let session = retained_state_digest(&c).unwrap();
        assert_ne!(empty, session);
        c.execute(
            "INSERT INTO authority_born_offline_artifacts VALUES(1,?1,?2)",
            params![b"synthetic-inert".as_slice(), [7u8; 32].as_slice()],
        )
        .unwrap();
        let key = retained_state_digest(&c).unwrap();
        assert_ne!(session, key);
        c.execute(
            "INSERT INTO receipts VALUES(?1,1,?1,?1,NULL,?1,?2)",
            params!["2".repeat(64), b"synthetic-ciphertext".as_slice()],
        )
        .unwrap();
        let inbox = retained_state_digest(&c).unwrap();
        assert_ne!(key, inbox);
        c.execute(
            "INSERT INTO outbox VALUES(?1,1,?1,?1,?1,?1,?1,?1,NULL,?1,1,2,?2,0)",
            params!["3".repeat(64), b"synthetic-outbox".as_slice()],
        )
        .unwrap();
        let outbox = retained_state_digest(&c).unwrap();
        assert_ne!(inbox, outbox);
        c.execute("UPDATE outbox SET acknowledged=1", []).unwrap();
        assert_ne!(outbox, retained_state_digest(&c).unwrap());
        let events: u64 = c
            .query_row("SELECT count(*) FROM authority_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(events, 0);
    }
}
