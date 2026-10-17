//! Complete original local inventory for the purpose-specific born named path.
//! Existing initial/read/reentry openers remain unchanged and continue to deny
//! these later rows. Expired/uncertain Started, result and dispatch never vanish.
use super::*;
use rusqlite::Connection;
use wholepact_authority::{
    account_use::AccountUseGenesis, born_offline_construction_v1::BornOfflineConstructionOriginV1,
};
use wholepact_signer_origin::common_context_reentry_v1::RosterReenteredConstructionEvidenceV1;

impl SignerConsentJournal {
    pub(crate) fn born_named_construction_origin_v1(
        &self,
        genesis: &AccountUseGenesis,
        epoch: u64,
        evidence: &RosterReenteredConstructionEvidenceV1,
    ) -> Result<BornOfflineConstructionOriginV1> {
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        storage::verify_schema(&c)?;
        storage::bounded(&c, self.capacity_limits())?;
        let account = storage::read_account(&c)?;
        let actual = account_use_storage::inspect(&c, &account.account_id)?;
        if account.recovery_required
            || account.writer_epoch != epoch
            || account.account_id != genesis.identity.account_id
            || actual.genesis() != Some(genesis)
            || actual.exclusion().is_some()
        {
            return Err(JournalError::InvalidBinding);
        }
        let origin = read_origin(&c, &account.account_id, evidence)?;
        verify_local_records(&c, genesis, &origin)?;
        Ok(origin)
    }
}
pub(super) fn read_origin(
    c: &Connection,
    account: &str,
    evidence: &RosterReenteredConstructionEvidenceV1,
) -> Result<BornOfflineConstructionOriginV1> {
    evidence
        .validate()
        .map_err(|_| JournalError::InvalidBinding)?;
    let audit = common_context_reentry_audit_v1::read_complete(c, account)?;
    let [CommonContextSignerAuditV1::ReadAdmitted { evidence: read, .. }] =
        audit.original.rows.as_slice()
    else {
        return Err(JournalError::Conflict);
    };
    if read.request != evidence.reentry_lineage.request.original_read
        || audit.reentry.rows.len() != 6
    {
        return Err(JournalError::Conflict);
    }
    let mut reserved = None;
    let mut consumed = None;
    for row in &audit.reentry.rows {
        match &row.record {
            CommonContextReentryAuditPhaseV1::Reserved {
                extension,
                continuation,
                record,
                ..
            } => {
                reserved = Some((extension.as_ref(), continuation.as_ref(), record.as_ref()));
            }
            CommonContextReentryAuditPhaseV1::Consumed {
                record,
                evidence: retained,
                ..
            } => {
                if retained.as_ref() != evidence {
                    return Err(JournalError::Conflict);
                }
                consumed = Some(record.as_ref());
            }
            _ => {}
        }
    }
    let (extension, continuation, reservation) = reserved.ok_or(JournalError::InvalidBinding)?;
    let consumed = consumed.ok_or(JournalError::InvalidBinding)?;
    if reservation.credential_id != consumed.credential_id {
        return Err(JournalError::Conflict);
    }
    let result = BornOfflineConstructionOriginV1 {
        extension: extension.clone(),
        continuation: continuation.clone(),
        reservation: reservation.original.clone(),
        consumed: consumed.original.clone(),
        transport_credential_id: Some(reservation.credential_id.clone()),
    };
    result
        .validate()
        .map_err(|_| JournalError::InvalidBinding)?;
    Ok(result)
}
pub(super) fn verify_local_records(
    c: &Connection,
    genesis: &AccountUseGenesis,
    origin: &BornOfflineConstructionOriginV1,
) -> Result<()> {
    let plan = &origin.reservation.request.construction.plan;
    let proposal = plan.validate().map_err(|_| JournalError::InvalidBinding)?;
    let scope = &origin.extension.account_extension.terms.scope;
    let mut enrollments =
        c.prepare("SELECT reference FROM signer_enrollments ORDER BY reference")?;
    let refs = enrollments
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if refs.len() > 1 {
        return Err(JournalError::Conflict);
    }
    for reference in refs {
        let e = storage::read_enrollment(c, &reference)?.ok_or(JournalError::InvalidBinding)?;
        if e.account_id() != genesis.identity.account_id
            || e.account_fvk_digest() != genesis.identity.full_viewing_key_digest
            || e.agreement_id() != scope.agreement_id
            || e.participant_id() != scope.participant_id
            || e.budget_limit_zatoshis() != scope.aggregate_budget_zatoshis
        {
            return Err(JournalError::InvalidBinding);
        }
        e.transport().validate_scope(
            e.account_id(),
            e.agreement_id(),
            e.participant_id(),
            Some(proposal.manifest_digest()),
        )?;
    }
    let mut manifests =
        c.prepare("SELECT reference FROM signer_accepted_manifests ORDER BY reference")?;
    let refs = manifests
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if refs.len() > 1 {
        return Err(JournalError::Conflict);
    }
    for reference in refs {
        let m = storage::read_manifest(c, &reference)?.ok_or(JournalError::InvalidBinding)?;
        let e =
            storage::read_enrollment(c, m.enrollment_ref())?.ok_or(JournalError::InvalidBinding)?;
        if m.proposal_input() != proposal.input()
            || m.terms.account_id != e.account_id()
            || m.terms.principal_id != e.principal_id()
            || !storage::same_native_origin(e.receipt(), m.receipt())
        {
            return Err(JournalError::InvalidBinding);
        }
    }
    // Parse every retained named row, including unresolved Started and original
    // dispatch requests. No arbitrary table can silently appear as zero exposure.
    named_recipient_inventory::read_all(c, &genesis.identity.account_id)?;
    let mut q = c.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )?;
    let names = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for name in names {
        if matches!(
            name.as_str(),
            "signer_account"
                | "signer_account_use_genesis"
                | "signer_common_context_audit_v3"
                | "signer_common_context_reentry_v1"
                | "signer_enrollments"
                | "signer_accepted_manifests"
                | "signer_named_recipient_profiles"
                | "signer_named_recipient_originals"
                | "signer_named_recipient_receipts"
                | "signer_named_recipient_started"
                | "signer_named_recipient_results"
                | "signer_named_intent_outbox"
                | "signer_named_recipient_dispatch_requests"
        ) {
            continue;
        }
        let n: u64 = c.query_row(
            &format!("SELECT count(*) FROM \"{}\"", name.replace('"', "\"\"")),
            [],
            |r| r.get(0),
        )?;
        if n != 0 {
            return Err(JournalError::RecoveryRequired);
        }
    }
    let mut fks = c.prepare("PRAGMA foreign_key_check")?;
    if fks.query([])?.next()?.is_some() {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}
