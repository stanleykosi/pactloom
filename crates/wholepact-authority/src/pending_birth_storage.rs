//! Source foundation: authority-local immutable birth metadata reader. There is no
//! insertion API until genuine local owner approval/creation is connected.
use crate::pending_birth::PendingBirthCommitRecord;
use crate::{AccountPolicy, AuthorityError, Result, decode};
use rusqlite::{Connection, OptionalExtension};

/// Must run inside the same transaction as the genesis/history read. Absence
/// from a migrated legacy policy is unknown. Positive genesis requires a record;
/// a record for a legacy policy is corruption, never retrospective enrollment.
pub(crate) fn read(
    tx: &Connection,
    policy: &AccountPolicy,
) -> Result<Option<PendingBirthCommitRecord>> {
    let row: Option<(String, String, String)> = tx.query_row(
        "SELECT operation_id,request_digest,CASE WHEN length(CAST(payload AS BLOB)) <= 262144 THEN payload ELSE NULL END FROM authority_pending_birth_commit WHERE singleton=1",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).optional()?;
    let Some((operation_id, request_digest, payload)) = row else {
        return if policy.account_use_genesis.is_none() {
            Ok(None)
        } else {
            Err(AuthorityError::CorruptHistory)
        };
    };
    let payload = zeroize::Zeroizing::new(payload);
    let record: PendingBirthCommitRecord = decode(payload.as_bytes())?;
    record.validate()?;
    if policy.account_use_genesis.is_none()
        || &record.request.policy != policy
        || record.request.operation_id != operation_id
        || record.request_digest != request_digest
    {
        return Err(AuthorityError::CorruptHistory);
    }
    let count: u64 = tx.query_row(
        "SELECT count(*) FROM authority_pending_birth_commit",
        [],
        |r| r.get(0),
    )?;
    if count != 1 {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(Some(record))
}
