//! Private local transaction predicates. Only the concrete lease consumer may
//! reach these in production. Tests can supply modeled identity projections;
//! production derives inherited identity coverage from actual retained rows.
use super::*;
use rusqlite::{OptionalExtension, Transaction, params};

/// Expected data is a CAS comparison, never authority. The owning Engine must
/// obtain and authorize this exact full envelope before entering this mutation.
/// The IMMEDIATE transaction keeps every cell stable through final append.
pub(super) fn require_agreement_snapshot(
    c: &rusqlite::Connection,
    expected: &StoredRecord,
    terms: &BornManualEnrollmentTerms,
) -> Result<()> {
    let actual = crate::read_record(c, "agreement", &terms.scope.agreement_id)?
        .ok_or(StoreError::NotFound)?;
    if expected.id != terms.scope.agreement_id || actual != *expected {
        return Err(StoreError::RevisionConflict);
    }
    if actual.revision == 0
        || actual
            .payload
            .pointer("/view/agreement/agreement_id")
            .and_then(serde_json::Value::as_str)
            != Some(terms.scope.agreement_id.as_str())
        || actual
            .payload
            .pointer("/view/agreement/obligation_id")
            .and_then(serde_json::Value::as_str)
            != Some(terms.scope.obligation_id.as_str())
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}

fn require_generation(
    store: &Store,
    c: &rusqlite::Connection,
    a: &ManualEnrollmentAudit,
) -> Result<()> {
    require_generation_terms(
        store,
        c,
        &a.terms,
        &a.request_identity_digest,
        ENROLLMENT,
        &a.digest()?,
    )
}
fn require_generation_terms(
    store: &Store,
    c: &rusqlite::Connection,
    terms: &BornManualEnrollmentTerms,
    request_identity: &str,
    record_kind: &str,
    record_digest: &str,
) -> Result<()> {
    require_original_terms_generation(store, c, terms)?;
    if store.generation_fenced(c, "idempotency", request_identity)?
        || store.generation_fenced(c, "record", &format!("{record_kind}:{record_digest}"))?
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}
fn require_original_terms_generation(
    store: &Store,
    c: &rusqlite::Connection,
    terms: &BornManualEnrollmentTerms,
) -> Result<()> {
    terms.validate().map_err(|_| StoreError::RecoveryRequired)?;
    let actual = store
        .recovered_binding
        .as_ref()
        .ok_or(StoreError::RecoveryRequired)?;
    let h = &terms.host;
    if !store.recovered_generation
        || store.protection != StorageProtection::Encrypted
        || !crate::backup::read_recovery_state(c)?.recovery_required
        || actual.generation_id() != h.generation_id
        || actual.inventory_digest() != h.inventory_digest
        || store.current_recovered_settlement_identity(c)? != h.store_destination_identity
    {
        return Err(StoreError::RecoveryRequired);
    }
    for (kind, id) in [
        ("operation", terms.operation_id.as_str()),
        ("effect", terms.operation_id.as_str()),
        ("agreement", terms.scope.agreement_id.as_str()),
        ("obligation", terms.scope.obligation_id.as_str()),
    ] {
        if store.generation_fenced(c, kind, id)? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    if store.generation_fenced(c,"record",&format!("agreement:{}",terms.scope.agreement_id))?
        || c.query_row("SELECT EXISTS(SELECT 1 FROM records WHERE aggregate_type='settlement_applied' AND payload=?1)",[crate::encode(&serde_json::json!(&terms.scope.obligation_id))?],|r|r.get::<_,bool>(0))?
    { return Err(StoreError::RecoveryRequired); }
    Ok(())
}
fn append_immutable<T: Serialize>(
    tx: &Transaction<'_>,
    kind: &str,
    id: &str,
    value: &T,
) -> Result<bool> {
    let payload = crate::encode(&serde_json::to_value(value)?)?;
    let existing: Option<String> = tx
        .query_row(
            "SELECT payload FROM records WHERE aggregate_type=?1 AND id=?2",
            params![kind, id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(old) = existing {
        return if old == payload {
            Ok(false)
        } else {
            Err(StoreError::IdempotencyConflict)
        };
    }
    let (count, bytes): (u64, u64) = tx.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM records WHERE aggregate_type IN(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![ENROLLMENT, SCOPE, EXCLUSION, CONTINUATION, INITIAL_PUBLICATION_V2, CONTINUATION_V3, ADDITIONAL_PUBLICATION_V3, CONTINUATION_V4, PERMANENT_STOP_V1], |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count >= MAX_AUDITS as u64
        || bytes
            .checked_add(payload.len() as u64)
            .is_none_or(|n| n > MAX_AUDIT_BYTES)
    {
        return Err(StoreError::ResourceExhausted);
    }
    tx.execute(
        "INSERT INTO records VALUES(?1,?2,0,?3,?4,?4)",
        params![kind, id, payload, crate::now_ms()],
    )?;
    Ok(true)
}
fn no_operation_reuse(
    c: &rusqlite::Connection,
    operation: &str,
    kind: &str,
    digest: &str,
) -> Result<()> {
    for (k, rows) in [
        (
            ENROLLMENT,
            read_audits::<ManualEnrollmentAudit>(c, ENROLLMENT)?
                .into_iter()
                .map(|(id, a)| (id, a.terms.operation_id))
                .collect::<Vec<_>>(),
        ),
        (
            SCOPE,
            read_audits::<ManualActionAudit>(c, SCOPE)?
                .into_iter()
                .map(|(id, a)| (id, a.intent.operation_id))
                .collect(),
        ),
        (
            CONTINUATION,
            read_audits::<ManualEnrollmentContinuationAudit>(c, CONTINUATION)?
                .into_iter()
                .map(|(id, a)| (id, a.operation_id))
                .collect(),
        ),
        (
            INITIAL_PUBLICATION_V2,
            read_audits::<ManualEnrollmentInitialPublicationV2>(c, INITIAL_PUBLICATION_V2)?
                .into_iter()
                .flat_map(|(id, a)| {
                    vec![
                        (id.clone(), a.terms().operation_id.clone()),
                        (id, a.operation_id),
                    ]
                })
                .collect(),
        ),
        (
            CONTINUATION_V3,
            read_audits::<ManualEnrollmentContinuationAuditV3>(c, CONTINUATION_V3)?
                .into_iter()
                .map(|(id, a)| (id, a.operation_id))
                .collect(),
        ),
        (
            EXCLUSION,
            read_audits::<ManualExclusionAudit>(c, EXCLUSION)?
                .into_iter()
                .map(|(id, a)| (id, a.operation_id))
                .collect(),
        ),
    ] {
        if rows
            .iter()
            .any(|(id, op)| op == operation && (k != kind || id != digest))
        {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    if c.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE operation_id=?1) OR EXISTS(SELECT 1 FROM effect_intents WHERE operation_id=?1)",[operation],|r|r.get::<_,bool>(0))? { return Err(StoreError::IdempotencyConflict); }
    for (id, a) in
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(c, ADDITIONAL_PUBLICATION_V3)?
    {
        if (a.operation_id == operation || a.terms().operation_id == operation)
            && (kind != ADDITIONAL_PUBLICATION_V3 || id != digest)
        {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (id, a) in read_audits::<ManualEnrollmentContinuationAuditV4>(c, CONTINUATION_V4)? {
        if (a.operation_id == operation) && (kind != CONTINUATION_V4 || id != digest) {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    Ok(())
}
fn no_request_reuse(
    c: &rusqlite::Connection,
    identity: &str,
    kind: &str,
    digest: &str,
) -> Result<()> {
    for (k, rows) in [
        (
            ENROLLMENT,
            read_audits::<ManualEnrollmentAudit>(c, ENROLLMENT)?
                .into_iter()
                .map(|(id, a)| (id, a.request_identity_digest))
                .collect::<Vec<_>>(),
        ),
        (
            SCOPE,
            read_audits::<ManualActionAudit>(c, SCOPE)?
                .into_iter()
                .map(|(id, a)| (id, a.intent.idempotency_key_digest))
                .collect(),
        ),
        (
            CONTINUATION,
            read_audits::<ManualEnrollmentContinuationAudit>(c, CONTINUATION)?
                .into_iter()
                .map(|(id, a)| (id, a.request_identity_digest))
                .collect(),
        ),
        (
            INITIAL_PUBLICATION_V2,
            read_audits::<ManualEnrollmentInitialPublicationV2>(c, INITIAL_PUBLICATION_V2)?
                .into_iter()
                .map(|(id, a)| (id, a.request_identity_digest))
                .collect(),
        ),
        (
            CONTINUATION_V3,
            read_audits::<ManualEnrollmentContinuationAuditV3>(c, CONTINUATION_V3)?
                .into_iter()
                .map(|(id, a)| (id, a.request_identity_digest))
                .collect(),
        ),
    ] {
        if rows
            .iter()
            .any(|(id, prior)| prior == identity && (k != kind || id != digest))
        {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (id, a) in
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(c, ADDITIONAL_PUBLICATION_V3)?
    {
        if (a.request_identity_digest == identity)
            && (kind != ADDITIONAL_PUBLICATION_V3 || id != digest)
        {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (id, a) in read_audits::<ManualEnrollmentContinuationAuditV4>(c, CONTINUATION_V4)? {
        if (a.request_identity_digest == identity) && (kind != CONTINUATION_V4 || id != digest) {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    Ok(())
}
pub(super) fn append_enrollment(
    store: &Store,
    tx: &Transaction<'_>,
    a: &ManualEnrollmentAudit,
    declared_inherited: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<bool> {
    a.validate()?;
    require_generation(store, tx, a)?;
    let digest = a.digest()?;
    no_operation_reuse(tx, &a.terms.operation_id, ENROLLMENT, &digest)?;
    no_request_reuse(tx, &a.request_identity_digest, ENROLLMENT, &digest)?;
    let inherited_ids = {
        let mut q = tx.prepare(
            "SELECT identity FROM store_generation_fences WHERE kind='account' ORDER BY identity",
        )?;
        let rows = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<BTreeSet<_>>>()?;
        rows
    };
    if declared_inherited.len() > MAX_AUDITS {
        return Err(StoreError::ResourceExhausted);
    }
    let mut covered = BTreeSet::new();
    for (old, aliases) in declared_inherited {
        identity(old, aliases)?;
        if overlaps(old, aliases, &a.terms.identity, &a.aliases) {
            return Err(StoreError::RecoveryRequired);
        }
        for alias in aliases {
            if inherited_ids.contains(alias) && !covered.insert(alias.clone()) {
                return Err(StoreError::RecoveryRequired);
            }
        }
    }
    if covered != inherited_ids {
        return Err(StoreError::RecoveryRequired);
    }
    for alias in &a.aliases {
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_accounts WHERE account_id=?1)",
            [alias],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (_, old) in read_audits::<ManualExclusionAudit>(tx, EXCLUSION)? {
        if overlaps(&old.identity, &old.aliases, &a.terms.identity, &a.aliases) {
            return Err(StoreError::RecoveryRequired);
        }
    }
    let old = read_audits::<ManualEnrollmentAudit>(tx, ENROLLMENT)?;
    for (id, prior) in &old {
        if id != &digest
            && overlaps(
                &prior.terms.identity,
                &prior.aliases,
                &a.terms.identity,
                &a.aliases,
            )
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    // Full chain validation precedes exact replay; missing rows cannot look empty.
    crate::recovery::project_manual_snapshot(
        tx,
        store
            .recovered_binding
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?,
    )?;
    let initial = read_audits::<ManualEnrollmentInitialPublicationV2>(tx, INITIAL_PUBLICATION_V2)?;
    for (_, prior) in &initial {
        if overlaps(
            &prior.terms().identity,
            &prior.aliases,
            &a.terms.identity,
            &a.aliases,
        ) {
            return Err(StoreError::RecoveryRequired);
        }
    }
    if old.iter().any(|(id, _)| id == &digest) {
        return Ok(false);
    }
    let mut generation: Vec<_> = old
        .iter()
        .filter(|(_, x)| x.terms.host.generation_id == a.terms.host.generation_id)
        .map(|(id, x)| (id, x.store_sequence))
        .chain(
            initial
                .iter()
                .filter(|(_, x)| x.terms().host.generation_id == a.terms.host.generation_id)
                .map(|(id, x)| (id, x.store_sequence)),
        )
        .collect();
    generation.sort_by_key(|(_, sequence)| *sequence);
    if a.store_sequence != generation.len() as u64 + 1
        || a.terms.host.scope_predecessor_digest.as_deref()
            != generation.last().map(|(id, _)| id.as_str())
    {
        return Err(StoreError::RecoveryRequired);
    }
    let mut complete = old;
    complete.push((digest.clone(), a.clone()));
    validate_audit_set(
        &complete,
        &read_audits::<ManualActionAudit>(tx, SCOPE)?,
        &read_audits::<ManualExclusionAudit>(tx, EXCLUSION)?,
        &read_audits::<ManualEnrollmentContinuationAudit>(tx, CONTINUATION)?,
        &initial,
        &read_audits::<ManualEnrollmentContinuationAuditV3>(tx, CONTINUATION_V3)?,
        crate::manual_enrollment::RosterAuditRows {
            additions: &read_audits::<ManualEnrollmentAdditionalPublicationV3>(
                tx,
                ADDITIONAL_PUBLICATION_V3,
            )?,
            continuations: &read_audits::<ManualEnrollmentContinuationAuditV4>(
                tx,
                CONTINUATION_V4,
            )?,
        },
    )?;
    append_immutable(tx, ENROLLMENT, &digest, a)
}
pub(super) fn append_action(
    store: &Store,
    tx: &Transaction<'_>,
    action: &ManualActionAudit,
) -> Result<bool> {
    let all = read_audits::<ManualEnrollmentAudit>(tx, ENROLLMENT)?;
    let (_, a) = all
        .iter()
        .find(|(id, _)| id == &action.enrollment_audit_digest)
        .ok_or(StoreError::RecoveryRequired)?;
    action.validate_for(a)?;
    require_generation(store, tx, a)?;
    for (_, old) in read_audits::<ManualExclusionAudit>(tx, EXCLUSION)? {
        if overlaps(&old.identity, &old.aliases, &a.terms.identity, &a.aliases) {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (kind, id) in [
        ("operation", action.intent.operation_id.as_str()),
        ("effect", action.intent.operation_id.as_str()),
        ("idempotency", action.intent.idempotency_key_digest.as_str()),
    ] {
        if store.generation_fenced(tx, kind, id)? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    let digest = action.digest()?;
    no_operation_reuse(tx, &action.intent.operation_id, SCOPE, &digest)?;
    no_request_reuse(tx, &action.intent.idempotency_key_digest, SCOPE, &digest)?;
    append_immutable(tx, SCOPE, &digest, action)
}
pub(super) fn append_exclusion(tx: &Transaction<'_>, a: &ManualExclusionAudit) -> Result<bool> {
    a.validate()?;
    let digest = a.digest()?;
    no_operation_reuse(tx, &a.operation_id, EXCLUSION, &digest)?;
    append_immutable(tx, EXCLUSION, &digest, a)
}

/// Actual retained original only. This predicate cannot create an enrollment or
/// import a caller's history. Caller supplies comparison data from a real target.
pub(super) fn require_continuation_original(
    store: &Store,
    c: &rusqlite::Connection,
    terms: &BornManualEnrollmentTerms,
    enrollment_ref: &str,
    extension_digest: &str,
) -> Result<ManualEnrollmentAudit> {
    terms.validate().map_err(|_| StoreError::RecoveryRequired)?;
    hash(enrollment_ref)?;
    hash(extension_digest)?;
    crate::recovery::project_manual_snapshot(
        c,
        store
            .recovered_binding
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?,
    )?;
    let original = read_audits::<ManualEnrollmentAudit>(c, ENROLLMENT)?
        .into_iter()
        .find(|(_, a)| a.enrollment_ref == enrollment_ref)
        .map(|(_, a)| a)
        .ok_or(StoreError::RecoveryRequired)?;
    if original.terms != *terms
        || original.witness_extension_digest != extension_digest
        || original.witness_extension_sequence != 1
        || original.witness_extension_predecessor_digest.is_some()
        || original.terms.host.scope_predecessor_digest.is_some()
    {
        return Err(StoreError::RecoveryRequired);
    }
    require_generation(store, c, &original)?;
    for alias in &original.aliases {
        if store.generation_fenced(c, "account", alias)?
            || c.query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_accounts WHERE account_id=?1)",
                [alias],
                |r| r.get::<_, bool>(0),
            )?
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (_, excluded) in read_audits::<ManualExclusionAudit>(c, EXCLUSION)? {
        if overlaps(
            &excluded.identity,
            &excluded.aliases,
            &original.terms.identity,
            &original.aliases,
        ) {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(original)
}

pub(super) fn append_continuation(
    store: &Store,
    tx: &Transaction<'_>,
    audit: &ManualEnrollmentContinuationAudit,
) -> Result<bool> {
    let original = require_continuation_original(
        store,
        tx,
        &audit.evidence.request.enrollment.terms,
        &audit.evidence.enrollment_ref,
        &audit.evidence.witness_extension_digest,
    )?;
    audit.validate_for(&original)?;
    let digest = audit.digest()?;
    for (kind, id) in [
        ("operation", audit.operation_id.as_str()),
        ("effect", audit.operation_id.as_str()),
        ("idempotency", audit.request_identity_digest.as_str()),
    ] {
        if store.generation_fenced(tx, kind, id)? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    if store.generation_fenced(tx, "record", &format!("{CONTINUATION}:{digest}"))? {
        return Err(StoreError::RecoveryRequired);
    }
    no_operation_reuse(tx, &audit.operation_id, CONTINUATION, &digest)?;
    no_request_reuse(tx, &audit.request_identity_digest, CONTINUATION, &digest)?;
    let mut all = read_audits::<ManualEnrollmentContinuationAudit>(tx, CONTINUATION)?;
    if all.iter().any(|(id, _)| id == &digest) {
        return Ok(false);
    }
    all.push((digest.clone(), audit.clone()));
    validate_audit_set(
        &read_audits::<ManualEnrollmentAudit>(tx, ENROLLMENT)?,
        &read_audits::<ManualActionAudit>(tx, SCOPE)?,
        &read_audits::<ManualExclusionAudit>(tx, EXCLUSION)?,
        &all,
        &read_audits::<ManualEnrollmentInitialPublicationV2>(tx, INITIAL_PUBLICATION_V2)?,
        &read_audits::<ManualEnrollmentContinuationAuditV3>(tx, CONTINUATION_V3)?,
        crate::manual_enrollment::RosterAuditRows {
            additions: &read_audits::<ManualEnrollmentAdditionalPublicationV3>(
                tx,
                ADDITIONAL_PUBLICATION_V3,
            )?,
            continuations: &read_audits::<ManualEnrollmentContinuationAuditV4>(
                tx,
                CONTINUATION_V4,
            )?,
        },
    )?;
    append_immutable(tx, CONTINUATION, &digest, audit)
}

/// Full common identity/exclusion check. The complete inherited fence set must
/// be known even on replay; no empty-ledger interpretation is available.
fn require_initial_identity(
    store: &Store,
    c: &rusqlite::Connection,
    terms: &BornManualEnrollmentTerms,
    aliases: &BTreeSet<String>,
    declared_inherited: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<()> {
    identity(&terms.identity, aliases)?;
    let inherited_ids = {
        let mut q = c.prepare(
            "SELECT identity FROM store_generation_fences WHERE kind='account' ORDER BY identity",
        )?;
        let keys = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<BTreeSet<_>>>()?;
        keys
    };
    if declared_inherited.len() > MAX_AUDITS {
        return Err(StoreError::ResourceExhausted);
    }
    let mut covered = BTreeSet::new();
    for (old, old_aliases) in declared_inherited {
        identity(old, old_aliases)?;
        if overlaps(old, old_aliases, &terms.identity, aliases) {
            return Err(StoreError::RecoveryRequired);
        }
        for alias in old_aliases {
            if inherited_ids.contains(alias) && !covered.insert(alias.clone()) {
                return Err(StoreError::RecoveryRequired);
            }
        }
    }
    if covered != inherited_ids {
        return Err(StoreError::RecoveryRequired);
    }
    for alias in aliases {
        if store.generation_fenced(c, "account", alias)?
            || c.query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_accounts WHERE account_id=?1)",
                [alias],
                |r| r.get::<_, bool>(0),
            )?
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (_, old) in read_audits::<ManualExclusionAudit>(c, EXCLUSION)? {
        if overlaps(&old.identity, &old.aliases, &terms.identity, aliases) {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(())
}

/// Read-only first-publication preflight. Existing V1 original, changed scope
/// chain, unknown inherited identity, or different original terms all deny.
pub(super) fn require_initial_publication_target(
    store: &Store,
    c: &rusqlite::Connection,
    terms: &BornManualEnrollmentTerms,
    enrollment_ref: &str,
    extension_digest: &str,
    known: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<Option<ManualEnrollmentInitialPublicationV2>> {
    require_original_terms_generation(store, c, terms)?;
    hash(enrollment_ref)?;
    hash(extension_digest)?;
    if terms.host.scope_predecessor_digest.is_some() {
        return Err(StoreError::RecoveryRequired);
    }
    let projection = crate::recovery::project_manual_snapshot(
        c,
        store
            .recovered_binding
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?,
    )?;
    let aliases = BTreeSet::from([terms.identity.account_id.clone()]);
    require_initial_identity(store, c, terms, &aliases, known)?;
    let mut retained = None;
    for original in projection.enrollments() {
        match original {
            ManualEnrollmentProjection::EnrollmentV1(a) => {
                if a.terms.host.generation_id == terms.host.generation_id
                    || overlaps(&a.terms.identity, &a.aliases, &terms.identity, &aliases)
                    || a.enrollment_ref == enrollment_ref
                    || a.terms.operation_id == terms.operation_id
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            ManualEnrollmentProjection::AdditionalPublicationV3(a) => {
                if a.terms().host.generation_id == terms.host.generation_id
                    || overlaps(&a.terms().identity, &a.aliases, &terms.identity, &aliases)
                    || a.evidence.enrollment_ref == enrollment_ref
                    || a.terms().operation_id == terms.operation_id
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            ManualEnrollmentProjection::InitialPublicationV2(a) => {
                if a.terms().host.generation_id == terms.host.generation_id {
                    if a.terms() != terms
                        || a.evidence.enrollment_ref != enrollment_ref
                        || a.evidence.witness_extension_digest != extension_digest
                        || a.aliases != aliases
                        || retained.is_some()
                    {
                        return Err(StoreError::RecoveryRequired);
                    }
                    retained = Some(a.clone());
                } else if overlaps(&a.terms().identity, &a.aliases, &terms.identity, &aliases)
                    || a.evidence.enrollment_ref == enrollment_ref
                    || a.terms().operation_id == terms.operation_id
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
        }
    }
    Ok(retained)
}

pub(super) fn append_initial_publication_v2(
    store: &Store,
    tx: &Transaction<'_>,
    audit: &ManualEnrollmentInitialPublicationV2,
    known: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<bool> {
    audit.validate()?;
    let digest = audit.digest()?;
    require_generation_terms(
        store,
        tx,
        audit.terms(),
        &audit.request_identity_digest,
        INITIAL_PUBLICATION_V2,
        &digest,
    )?;
    for kind in ["operation", "effect"] {
        if store.generation_fenced(tx, kind, &audit.operation_id)? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    no_operation_reuse(tx, &audit.operation_id, INITIAL_PUBLICATION_V2, &digest)?;
    no_operation_reuse(
        tx,
        &audit.terms().operation_id,
        INITIAL_PUBLICATION_V2,
        &digest,
    )?;
    no_request_reuse(
        tx,
        &audit.request_identity_digest,
        INITIAL_PUBLICATION_V2,
        &digest,
    )?;
    let retained = require_initial_publication_target(
        store,
        tx,
        audit.terms(),
        &audit.evidence.enrollment_ref,
        &audit.evidence.witness_extension_digest,
        known,
    )?;
    if let Some(old) = retained {
        return if old == *audit {
            Ok(false)
        } else {
            Err(StoreError::IdempotencyConflict)
        };
    }
    let mut initials =
        read_audits::<ManualEnrollmentInitialPublicationV2>(tx, INITIAL_PUBLICATION_V2)?;
    initials.push((digest.clone(), audit.clone()));
    validate_audit_set(
        &read_audits::<ManualEnrollmentAudit>(tx, ENROLLMENT)?,
        &read_audits::<ManualActionAudit>(tx, SCOPE)?,
        &read_audits::<ManualExclusionAudit>(tx, EXCLUSION)?,
        &read_audits::<ManualEnrollmentContinuationAudit>(tx, CONTINUATION)?,
        &initials,
        &read_audits::<ManualEnrollmentContinuationAuditV3>(tx, CONTINUATION_V3)?,
        crate::manual_enrollment::RosterAuditRows {
            additions: &read_audits::<ManualEnrollmentAdditionalPublicationV3>(
                tx,
                ADDITIONAL_PUBLICATION_V3,
            )?,
            continuations: &read_audits::<ManualEnrollmentContinuationAuditV4>(
                tx,
                CONTINUATION_V4,
            )?,
        },
    )?;
    append_immutable(tx, INITIAL_PUBLICATION_V2, &digest, audit)
}

pub(super) fn require_continuation_original_v2(
    store: &Store,
    c: &rusqlite::Connection,
    terms: &BornManualEnrollmentTerms,
    enrollment_ref: &str,
    extension_digest: &str,
    known: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<ManualEnrollmentInitialPublicationV2> {
    require_original_terms_generation(store, c, terms)?;
    hash(enrollment_ref)?;
    hash(extension_digest)?;
    crate::recovery::project_manual_snapshot(
        c,
        store
            .recovered_binding
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?,
    )?;
    let original = read_audits::<ManualEnrollmentInitialPublicationV2>(c, INITIAL_PUBLICATION_V2)?
        .into_iter()
        .find(|(_, a)| a.evidence.enrollment_ref == enrollment_ref)
        .map(|(_, a)| a)
        .ok_or(StoreError::RecoveryRequired)?;
    if original.terms() != terms || original.evidence.witness_extension_digest != extension_digest {
        return Err(StoreError::RecoveryRequired);
    }
    require_initial_identity(store, c, terms, &original.aliases, known)?;
    require_generation_terms(
        store,
        c,
        terms,
        &original.request_identity_digest,
        INITIAL_PUBLICATION_V2,
        &original.digest()?,
    )?;
    for kind in ["operation", "effect"] {
        if store.generation_fenced(c, kind, &original.operation_id)? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(original)
}

pub(super) fn append_continuation_v3(
    store: &Store,
    tx: &Transaction<'_>,
    audit: &ManualEnrollmentContinuationAuditV3,
    known: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<bool> {
    let original = require_continuation_original_v2(
        store,
        tx,
        &audit.evidence.request.enrollment.terms,
        &audit.evidence.enrollment_ref,
        &audit.evidence.witness_extension_digest,
        known,
    )?;
    audit.validate_for(&original)?;
    let digest = audit.digest()?;
    for (kind, id) in [
        ("operation", audit.operation_id.as_str()),
        ("effect", audit.operation_id.as_str()),
        ("idempotency", audit.request_identity_digest.as_str()),
    ] {
        if store.generation_fenced(tx, kind, id)? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    if store.generation_fenced(tx, "record", &format!("{CONTINUATION_V3}:{digest}"))? {
        return Err(StoreError::RecoveryRequired);
    }
    no_operation_reuse(tx, &audit.operation_id, CONTINUATION_V3, &digest)?;
    no_request_reuse(tx, &audit.request_identity_digest, CONTINUATION_V3, &digest)?;
    let mut all = read_audits::<ManualEnrollmentContinuationAuditV3>(tx, CONTINUATION_V3)?;
    if all.iter().any(|(id, _)| id == &digest) {
        return Ok(false);
    }
    all.push((digest.clone(), audit.clone()));
    validate_audit_set(
        &read_audits::<ManualEnrollmentAudit>(tx, ENROLLMENT)?,
        &read_audits::<ManualActionAudit>(tx, SCOPE)?,
        &read_audits::<ManualExclusionAudit>(tx, EXCLUSION)?,
        &read_audits::<ManualEnrollmentContinuationAudit>(tx, CONTINUATION)?,
        &read_audits::<ManualEnrollmentInitialPublicationV2>(tx, INITIAL_PUBLICATION_V2)?,
        &all,
        crate::manual_enrollment::RosterAuditRows {
            additions: &read_audits::<ManualEnrollmentAdditionalPublicationV3>(
                tx,
                ADDITIONAL_PUBLICATION_V3,
            )?,
            continuations: &read_audits::<ManualEnrollmentContinuationAuditV4>(
                tx,
                CONTINUATION_V4,
            )?,
        },
    )?;
    append_immutable(tx, CONTINUATION_V3, &digest, audit)
}

/// Exact V3 original lookup, independent of the current roster tip. An original
/// stays identifiable after another account is appended; live exclusions still deny.
pub(super) fn require_continuation_original_v3(
    store: &Store,
    c: &rusqlite::Connection,
    terms: &BornManualEnrollmentTerms,
    enrollment_ref: &str,
    extension_digest: &str,
    known: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<ManualEnrollmentAdditionalPublicationV3> {
    require_original_terms_generation(store, c, terms)?;
    hash(enrollment_ref)?;
    hash(extension_digest)?;
    crate::recovery::project_manual_snapshot(
        c,
        store
            .recovered_binding
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?,
    )?;
    let original =
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(c, ADDITIONAL_PUBLICATION_V3)?
            .into_iter()
            .find(|(_, a)| a.evidence.enrollment_ref == enrollment_ref)
            .map(|(_, a)| a)
            .ok_or(StoreError::RecoveryRequired)?;
    if original.terms() != terms || original.evidence.witness_extension_digest != extension_digest {
        return Err(StoreError::RecoveryRequired);
    }
    require_initial_identity(store, c, terms, &original.aliases, known)?;
    require_generation_terms(
        store,
        c,
        terms,
        &original.request_identity_digest,
        ADDITIONAL_PUBLICATION_V3,
        &original.digest()?,
    )?;
    for kind in ["operation", "effect"] {
        if store.generation_fenced(c, kind, &original.operation_id)? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(original)
}

/// Private kernel reached by the concrete new roster-bound lease consumer.
/// Never expose this function as an inert-DTO production API.
pub(super) fn append_additional_publication_v3(
    store: &Store,
    tx: &Transaction<'_>,
    audit: &ManualEnrollmentAdditionalPublicationV3,
    known: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<bool> {
    audit.validate()?;
    let digest = audit.digest()?;
    require_generation_terms(
        store,
        tx,
        audit.terms(),
        &audit.request_identity_digest,
        ADDITIONAL_PUBLICATION_V3,
        &digest,
    )?;
    require_initial_identity(store, tx, audit.terms(), &audit.aliases, known)?;
    for kind in ["operation", "effect"] {
        if store.generation_fenced(tx, kind, &audit.operation_id)? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    no_operation_reuse(tx, &audit.operation_id, ADDITIONAL_PUBLICATION_V3, &digest)?;
    no_operation_reuse(
        tx,
        &audit.terms().operation_id,
        ADDITIONAL_PUBLICATION_V3,
        &digest,
    )?;
    no_request_reuse(
        tx,
        &audit.request_identity_digest,
        ADDITIONAL_PUBLICATION_V3,
        &digest,
    )?;
    let projection = crate::recovery::project_manual_snapshot(
        tx,
        store
            .recovered_binding
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?,
    )?;
    let mut additions =
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(tx, ADDITIONAL_PUBLICATION_V3)?;
    // Full chain and current denial predicates precede exact historical replay.
    // Replay does not compare against today's tip or overwrite old observations.
    if let Some((_, old)) = additions.iter().find(|(id, _)| id == &digest) {
        return if old == audit {
            Ok(false)
        } else {
            Err(StoreError::IdempotencyConflict)
        };
    }
    let mut generation: Vec<_> = projection
        .enrollments()
        .into_iter()
        .filter(|a| a.terms().host.generation_id == audit.terms().host.generation_id)
        .collect();
    generation.sort_by_key(|a| a.store_sequence());
    let last = generation.last().ok_or(StoreError::RecoveryRequired)?;
    if generation.len() >= 32
        || audit.store_sequence != generation.len() as u64 + 1
        || audit.evidence.request.roster.predecessor != last.roster_link()?
    {
        return Err(StoreError::RevisionConflict);
    }
    additions.push((digest.clone(), audit.clone()));
    validate_audit_set(
        &read_audits::<ManualEnrollmentAudit>(tx, ENROLLMENT)?,
        &read_audits::<ManualActionAudit>(tx, SCOPE)?,
        &read_audits::<ManualExclusionAudit>(tx, EXCLUSION)?,
        &read_audits::<ManualEnrollmentContinuationAudit>(tx, CONTINUATION)?,
        &read_audits::<ManualEnrollmentInitialPublicationV2>(tx, INITIAL_PUBLICATION_V2)?,
        &read_audits::<ManualEnrollmentContinuationAuditV3>(tx, CONTINUATION_V3)?,
        crate::manual_enrollment::RosterAuditRows {
            additions: &additions,
            continuations: &read_audits::<ManualEnrollmentContinuationAuditV4>(
                tx,
                CONTINUATION_V4,
            )?,
        },
    )?;
    append_immutable(tx, ADDITIONAL_PUBLICATION_V3, &digest, audit)
}

pub(super) fn append_continuation_v4(
    store: &Store,
    tx: &Transaction<'_>,
    audit: &ManualEnrollmentContinuationAuditV4,
    known: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<bool> {
    let original = require_continuation_original_v3(
        store,
        tx,
        &audit.evidence.request.enrollment.terms,
        &audit.evidence.enrollment_ref,
        &audit.evidence.witness_extension_digest,
        known,
    )?;
    audit.validate_for(&original)?;
    let digest = audit.digest()?;
    for (kind, id) in [
        ("operation", audit.operation_id.as_str()),
        ("effect", audit.operation_id.as_str()),
        ("idempotency", audit.request_identity_digest.as_str()),
    ] {
        if store.generation_fenced(tx, kind, id)? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    if store.generation_fenced(tx, "record", &format!("{CONTINUATION_V4}:{digest}"))? {
        return Err(StoreError::RecoveryRequired);
    }
    no_operation_reuse(tx, &audit.operation_id, CONTINUATION_V4, &digest)?;
    no_request_reuse(tx, &audit.request_identity_digest, CONTINUATION_V4, &digest)?;
    let mut rows = read_audits::<ManualEnrollmentContinuationAuditV4>(tx, CONTINUATION_V4)?;
    if rows.iter().any(|(id, _)| id == &digest) {
        return Ok(false);
    }
    rows.push((digest.clone(), audit.clone()));
    validate_audit_set(
        &read_audits::<ManualEnrollmentAudit>(tx, ENROLLMENT)?,
        &read_audits::<ManualActionAudit>(tx, SCOPE)?,
        &read_audits::<ManualExclusionAudit>(tx, EXCLUSION)?,
        &read_audits::<ManualEnrollmentContinuationAudit>(tx, CONTINUATION)?,
        &read_audits::<ManualEnrollmentInitialPublicationV2>(tx, INITIAL_PUBLICATION_V2)?,
        &read_audits::<ManualEnrollmentContinuationAuditV3>(tx, CONTINUATION_V3)?,
        crate::manual_enrollment::RosterAuditRows {
            additions: &read_audits::<ManualEnrollmentAdditionalPublicationV3>(
                tx,
                ADDITIONAL_PUBLICATION_V3,
            )?,
            continuations: &rows,
        },
    )?;
    append_immutable(tx, CONTINUATION_V4, &digest, audit)
}

pub(super) fn require_additional_publication_target(
    store: &Store,
    c: &rusqlite::Connection,
    terms: &BornManualEnrollmentTerms,
    roster: &wholepact_core::manual_roster_v2::HostRosterAppendBindingV2,
    enrollment_ref: &str,
    extension_digest: &str,
    known: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<Option<ManualEnrollmentAdditionalPublicationV3>> {
    require_original_terms_generation(store, c, terms)?;
    roster
        .validate_for_host(&terms.host)
        .map_err(|_| StoreError::RecoveryRequired)?;
    hash(enrollment_ref)?;
    hash(extension_digest)?;
    let aliases = BTreeSet::from([terms.identity.account_id.clone()]);
    require_initial_identity(store, c, terms, &aliases, known)?;
    let projection = crate::recovery::project_manual_snapshot(
        c,
        store
            .recovered_binding
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?,
    )?;
    let mut retained = None;
    for a in projection.enrollments() {
        if overlaps(&a.terms().identity, a.aliases(), &terms.identity, &aliases)
            || a.enrollment_ref() == enrollment_ref
            || a.terms().operation_id == terms.operation_id
        {
            match a {
                ManualEnrollmentProjection::AdditionalPublicationV3(original)
                    if original.terms() == terms
                        && original.evidence.request.roster == *roster
                        && original.evidence.enrollment_ref == enrollment_ref
                        && original.evidence.witness_extension_digest == extension_digest
                        && original.aliases == aliases
                        && retained.is_none() =>
                {
                    retained = Some(original.clone());
                }
                _ => return Err(StoreError::RecoveryRequired),
            }
        }
    }
    // An exact retained original keeps its original predecessor even after
    // later members append. Neither lookup nor retry rewrites the chain.
    if let Some(original) = &retained {
        require_generation_terms(
            store,
            c,
            terms,
            &original.request_identity_digest,
            ADDITIONAL_PUBLICATION_V3,
            &original.digest()?,
        )?;
        for kind in ["operation", "effect"] {
            if store.generation_fenced(c, kind, &original.operation_id)? {
                return Err(StoreError::RecoveryRequired);
            }
        }
        return Ok(retained);
    }
    let mut rows: Vec<_> = projection
        .enrollments()
        .into_iter()
        .filter(|a| a.terms().host.generation_id == terms.host.generation_id)
        .collect();
    rows.sort_by_key(|a| a.store_sequence());
    let last = rows.last().ok_or(StoreError::RecoveryRequired)?;
    if rows.len() >= 32
        || roster.roster_sequence != rows.len() as u64 + 1
        || roster.predecessor != last.roster_link()?
    {
        return Err(StoreError::RevisionConflict);
    }
    Ok(None)
}
