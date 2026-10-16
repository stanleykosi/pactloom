//! Private SQL machinery. Only the concrete native-approved namespace owner
//! invokes mutations in supported source. Data-only helpers never mint authority.
use super::*;
use crate::decode;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub(super) const SCHEMA: &str = include_str!("witness_locator_schema.sql");
// Dedicated candidate locator identity, not an allocation in the live graph.
pub(super) const LOCATOR_APPLICATION_ID: i64 = 0x57504c43;
pub(super) const LOCATOR_SCHEMA_VERSION: i64 = 1;

/// Data-level transactional fold, private and not an authentication boundary.
/// Tests invoke this against synthetic memory databases, never an owner lease.
pub(super) fn prepare_in_transaction(
    tx: &Transaction<'_>,
    history: &LocatorHistory,
    intent: &CreationIntent,
    now_ms: u64,
) -> Result<CandidateAudit> {
    let result = history.classify(intent)?;
    match result {
        CandidateAudit::CompletedOriginalAudit { .. } => return Ok(result),
        CandidateAudit::ReservedExactIncomplete => {
            // Retain original prepared time and deadline. An uncertain existing
            // target must be handled by a future exact authenticated retry path.
            intent.request.require_initial_commit_time(now_ms)?;
            return Ok(result);
        }
        CandidateAudit::UnusedInRecordedNamespace => {}
    }
    intent.request.require_initial_commit_time(now_ms)?;
    let prepared = PreparedIntent {
        intent: intent.clone(),
        prepared_at_ms: now_ms,
    };
    prepared.validate(&history.namespace)?;
    let digest = intent.digest(&history.namespace)?;
    let identity = intent.identity();
    tx.execute("INSERT INTO witness_locator_intents \
        (intent_digest,namespace_digest,account_id,full_viewing_key_digest,network_profile_id,derivation_domain,\
         generation_instance_id,operation_id,request_digest,derived_child,local_target_digest,payload) \
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)", params![digest, intent.namespace_digest,
        identity.account_id, identity.full_viewing_key_digest, identity.network_profile_id, identity.derivation_domain,
        intent.request.generation_instance_id, intent.request.operation_id, intent.request_digest,
        intent.derived_child, intent.local_target_digest, &*encode(&prepared)?])?;
    // The returned classification is not a committed permit. The enclosing
    // function still has to commit, then a separate owner must recheck continuity.
    Ok(CandidateAudit::ReservedExactIncomplete)
}
pub(super) fn complete_in_transaction(
    tx: &Transaction<'_>,
    history: &LocatorHistory,
    intent: &CreationIntent,
    evidence: &CompletionEvidence,
    observed_at_ms: u64,
) -> Result<CompletionRecord> {
    intent.validate(&history.namespace)?;
    let key = intent.digest(&history.namespace)?;
    let prepared = history
        .prepared
        .get(&key)
        .ok_or(AuthorityError::RecoveryRequired)?;
    if &prepared.intent != intent {
        return Err(AuthorityError::Conflict);
    }
    evidence.validate(&history.namespace, prepared)?;
    if evidence.intent_digest != key {
        return Err(AuthorityError::InvalidBinding);
    }
    if let Some(original) = history.completed.get(&key) {
        return if &original.evidence == evidence {
            Ok(original.clone())
        } else {
            Err(AuthorityError::Conflict)
        };
    }
    let completed = CompletionRecord {
        evidence: evidence.clone(),
        completed_at_ms: observed_at_ms,
    };
    completed.validate(&history.namespace, prepared)?;
    tx.execute("INSERT INTO witness_locator_completions(intent_digest,genesis_commitment,payload) VALUES(?1,?2,?3)",
        params![key, evidence.journal_genesis_commitment, &*encode(&completed)?])?;
    // No exclusion, authority event, budget, reservation or account key is changed.
    Ok(completed)
}
#[allow(dead_code)] // Monotone inherited-exclusion importer remains unconnected.
pub(super) fn exclude_in_transaction(
    tx: &Transaction<'_>,
    history: &LocatorHistory,
    exclusion: &RetainedExclusion,
) -> Result<()> {
    let digest = exclusion.digest(&history.namespace)?;
    if history.exclusions.iter().any(|old| old == exclusion) {
        return Ok(());
    }
    let identity = &exclusion.exclusion.identity;
    tx.execute("INSERT INTO witness_locator_exclusions(exclusion_digest,account_id,full_viewing_key_digest,payload) VALUES(?1,?2,?3,?4)",
        params![digest, identity.account_id, identity.full_viewing_key_digest, &*encode(exclusion)?])?;
    Ok(())
}

/// Called only inside the owning read/write transaction. Loading no namespace,
/// unknown version/schema, missing quarantine or malformed/mismatched indexes
/// fails. Never synthesize legacy bindings or accept an empty file as fresh.
pub(super) fn load_exact(
    tx: &Connection,
    expected: &WitnessNamespaceBinding,
) -> Result<LocatorHistory> {
    expected.validate()?;
    verify_schema(tx)?;
    require_bounds(tx)?;
    let quarantine: Option<i64> = tx
        .query_row(
            "SELECT quarantined FROM witness_locator_quarantine WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if quarantine != Some(0) {
        return Err(AuthorityError::RecoveryRequired);
    }
    let namespace: Option<(String, Vec<u8>)> = tx
        .query_row(
            "SELECT binding_digest,payload FROM witness_locator_namespace WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (namespace_digest, payload) = namespace.ok_or(AuthorityError::RecoveryRequired)?;
    let namespace: WitnessNamespaceBinding = decode(&payload)?;
    if &namespace != expected || namespace.digest()? != namespace_digest {
        return Err(AuthorityError::InvalidBinding);
    }
    let mut prepared = Vec::new();
    let mut q = tx.prepare("SELECT intent_digest,namespace_digest,account_id,full_viewing_key_digest,network_profile_id,derivation_domain,generation_instance_id,operation_id,request_digest,derived_child,local_target_digest,payload FROM witness_locator_intents ORDER BY intent_digest")?;
    let mut rows = q.query([])?;
    while let Some(row) = rows.next()? {
        if prepared.len() >= MAX_INTENTS {
            return Err(AuthorityError::Limit);
        }
        let payload: Vec<u8> = row.get(11)?;
        let p: PreparedIntent = decode(&payload)?;
        p.validate(&namespace)?;
        let i = &p.intent;
        let expected = [
            i.digest(&namespace)?,
            i.namespace_digest.clone(),
            i.identity().account_id.clone(),
            i.identity().full_viewing_key_digest.clone(),
            i.identity().network_profile_id.clone(),
            i.identity().derivation_domain.clone(),
            i.request.generation_instance_id.clone(),
            i.request.operation_id.clone(),
            i.request_digest.clone(),
            i.derived_child.clone(),
            i.local_target_digest.clone(),
        ];
        for (column, value) in expected.iter().enumerate() {
            if row.get::<_, String>(column)? != *value {
                return Err(AuthorityError::CorruptHistory);
            }
        }
        prepared.push(p);
    }
    let mut completed = Vec::new();
    let mut q = tx.prepare("SELECT intent_digest,genesis_commitment,payload FROM witness_locator_completions ORDER BY intent_digest")?;
    let mut rows = q.query([])?;
    while let Some(row) = rows.next()? {
        if completed.len() >= MAX_INTENTS {
            return Err(AuthorityError::Limit);
        }
        let c: CompletionRecord = decode(&row.get::<_, Vec<u8>>(2)?)?;
        if row.get::<_, String>(0)? != c.evidence.intent_digest
            || row.get::<_, String>(1)? != c.evidence.journal_genesis_commitment
        {
            return Err(AuthorityError::CorruptHistory);
        }
        completed.push(c);
    }
    let mut exclusions = Vec::new();
    let mut q = tx.prepare("SELECT exclusion_digest,account_id,full_viewing_key_digest,payload FROM witness_locator_exclusions ORDER BY exclusion_digest")?;
    let mut rows = q.query([])?;
    while let Some(row) = rows.next()? {
        if exclusions.len() >= MAX_EXCLUSIONS {
            return Err(AuthorityError::Limit);
        }
        let e: RetainedExclusion = decode(&row.get::<_, Vec<u8>>(3)?)?;
        if row.get::<_, String>(0)? != e.digest(&namespace)?
            || row.get::<_, String>(1)? != e.exclusion.identity.account_id
            || row.get::<_, String>(2)? != e.exclusion.identity.full_viewing_key_digest
        {
            return Err(AuthorityError::CorruptHistory);
        }
        exclusions.push(e);
    }
    LocatorHistory::from_records(namespace, prepared, completed, exclusions)
}
fn require_bounds(c: &Connection) -> Result<()> {
    let (namespaces, intents, completions, exclusions, bytes): (u64, u64, u64, u64, u64) = c.query_row(
        "SELECT (SELECT count(*) FROM witness_locator_namespace),\
        (SELECT count(*) FROM witness_locator_intents),(SELECT count(*) FROM witness_locator_completions),\
        (SELECT count(*) FROM witness_locator_exclusions),\
        (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_namespace)+\
        (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_intents)+\
        (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_completions)+\
        (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_exclusions)", [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
    if namespaces != 1 {
        return Err(AuthorityError::RecoveryRequired);
    }
    if intents > MAX_INTENTS as u64
        || completions > MAX_INTENTS as u64
        || exclusions > MAX_EXCLUSIONS as u64
        || bytes > MAX_TOTAL_PAYLOAD_BYTES as u64
    {
        return Err(AuthorityError::Limit);
    }
    Ok(())
}
pub(super) fn verify_schema(c: &Connection) -> Result<()> {
    let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if app != LOCATOR_APPLICATION_ID || version != LOCATOR_SCHEMA_VERSION {
        return Err(AuthorityError::UnsupportedVersion);
    }
    // Only public, constant schema strings enter this memory database. Private
    // witness data is never copied out of the encrypted connection for SQL use.
    let template = Connection::open_in_memory()?;
    template.execute_batch(SCHEMA)?;
    if schema_objects(c)? != schema_objects(&template)? {
        return Err(AuthorityError::CorruptHistory);
    }
    let fk_error: Option<String> = c
        .query_row("PRAGMA foreign_key_check", [], |r| r.get(0))
        .optional()?;
    if fk_error.is_some() {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(())
}
fn schema_objects(c: &Connection) -> Result<Vec<(String, String, String, String)>> {
    let (count, bytes): (u64, u64) = c.query_row("SELECT count(*),coalesce(sum(length(sql)),0) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if count > 128 || bytes > 131_072 {
        return Err(AuthorityError::Limit);
    }
    let mut q = c.prepare("SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name")?;
    let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

#[cfg(test)]
#[path = "witness_locator_tests.rs"]
mod tests;
