//! Immutable native consent plus exact non-spending disclosure outbox. This
//! journal commits BEFORE export, including a failed or ambiguous response.
//! Loading a row is historical evidence only and never reconstructs authority.
use super::*;
use crate::authority_bridge::durable_construction_v1::{
    DurableConstructionHistoryRequestV1, DurableConstructionOutboxV1,
};
use crate::native_ui::durable_construction_v1::ApprovedDurableConstructionV1;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

impl SignerConsentJournal {
    pub(crate) fn record_durable_construction_v1(
        &self,
        approved: &ApprovedDurableConstructionV1,
        lease: &PreconstructionRecordLease<'_>,
    ) -> Result<DurableConstructionOutboxV1> {
        approved
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        lease.require_journal(&self.binding())?;
        lease.require_native_origin(approved.source())?;
        lease.check_current()?;
        let request = approved.request();
        if lease.enrollment().reference() != request.enrollment_ref
            || lease.manifest().reference() != request.accepted_manifest_ref
        {
            return Err(JournalError::InvalidBinding);
        }
        let candidate = approved
            .historical_outbox()
            .map_err(|_| JournalError::InvalidBinding)?;
        let mut connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        self.database_identity.check_current(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account = storage::read_account(&tx)?;
        if account.recovery_required || account.account_id != request.scope.account_id {
            return Err(JournalError::RecoveryRequired);
        }
        if let Some(existing) = read(&tx, &request.operation_id)? {
            // Exactly repeated intent returns the immutable original. Randomized
            // native review digests do not replace its historical provenance.
            if existing.request() != request
                || existing.request_digest() != candidate.request_digest()
                || existing.recipient_transport() != candidate.recipient_transport()
                || existing.redisclosure() != candidate.redisclosure()
            {
                return Err(JournalError::Conflict);
            }
            approved
                .check_current()
                .map_err(|_| JournalError::Permission)?;
            lease.check_current()?;
            return Ok(existing);
        }
        validate_original_rows(&tx, &candidate)?;
        let raw = encode(&candidate)?;
        tx.execute("INSERT INTO signer_durable_construction_outbox(operation_id,request_digest,enrollment_ref,manifest_ref,payload) VALUES(?1,?2,?3,?4,?5)",
            params![request.operation_id, candidate.request_digest(), request.enrollment_ref, request.accepted_manifest_ref, raw.as_str()])?;
        storage::bounded(&tx, self.capacity_limits())?;
        approved
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        lease.check_current()?;
        tx.commit()?;
        self.database_identity.check_current(&connection)?;
        Ok(candidate)
    }
    pub(crate) fn durable_construction_history_v1(
        &self,
        request: &DurableConstructionHistoryRequestV1,
        session: &SignerConsentSession,
    ) -> Result<DurableConstructionOutboxV1> {
        request
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        let account = self.account_state()?;
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let permission = session.read_lease(&self.binding(), &account)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        self.database_identity.check_current(&c)?;
        storage::check_account(&c, &account)?;
        let outbox = read(&c, &request.operation_id)?.ok_or(JournalError::NotFound)?;
        let enrollment = storage::read_enrollment(&c, &outbox.request().enrollment_ref)?
            .ok_or(JournalError::NotFound)?;
        if outbox.request_digest() != request.expected_request_digest
            || enrollment.principal_id() != permission.principal
        {
            return Err(JournalError::InvalidBinding);
        }
        permission.check_current()?;
        Ok(outbox)
    }
}
fn validate_original_rows(c: &Connection, outbox: &DurableConstructionOutboxV1) -> Result<()> {
    outbox
        .validate()
        .map_err(|_| JournalError::InvalidBinding)?;
    if let Some(link) = outbox.redisclosure() {
        // Bounded one-link join: refuse a chain before recursive validation, so
        // malicious restored data cannot cause cycles or unbounded recursion.
        let original = read_raw(c, &link.original_operation_id)?.ok_or(JournalError::NotFound)?;
        outbox
            .validate_redisclosure_of(&original)
            .map_err(|_| JournalError::InvalidBinding)?;
        validate_original_rows(c, &original)?;
    }
    let request = outbox.request();
    let enrollment =
        storage::read_enrollment(c, &request.enrollment_ref)?.ok_or(JournalError::NotFound)?;
    let manifest =
        storage::read_manifest(c, &request.accepted_manifest_ref)?.ok_or(JournalError::NotFound)?;
    let p = request
        .validate()
        .map_err(|_| JournalError::InvalidBinding)?;
    if enrollment.account_id() != request.scope.account_id
        || enrollment.account_fvk_digest() != request.material.fvk_digest()
        || enrollment.participant_id() != request.scope.participant_id
        || enrollment.agreement_id() != p.manifest().agreement.agreement_id
        || manifest.enrollment_ref() != request.enrollment_ref
        || manifest.proposal_input() != &request.scope.proposal
        || storage::read_account(c)?.account_id != request.scope.account_id
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}
fn read(c: &Connection, operation_id: &str) -> Result<Option<DurableConstructionOutboxV1>> {
    read_raw(c, operation_id)?
        .map(|outbox| {
            validate_original_rows(c, &outbox)?;
            Ok(outbox)
        })
        .transpose()
}
fn read_raw(c: &Connection, operation_id: &str) -> Result<Option<DurableConstructionOutboxV1>> {
    let raw: Option<(String, String, String, String)> = c.query_row(
        "SELECT request_digest,enrollment_ref,manifest_ref,payload FROM signer_durable_construction_outbox WHERE operation_id=?1", [operation_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).optional()?;
    raw.map(|(digest, enrollment, manifest, payload)| {
        let outbox: DurableConstructionOutboxV1 = decode(payload)?;
        if outbox.request().operation_id != operation_id
            || outbox.request_digest() != digest
            || outbox.request().enrollment_ref != enrollment
            || outbox.request().accepted_manifest_ref != manifest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(outbox)
    })
    .transpose()
}
/// Validates immutable historical rows without demanding current consent clocks,
/// a live native owner, or an active writer. This creates no capability.
pub(super) fn validate_rows(c: &Connection) -> Result<()> {
    let mut q = c.prepare(
        "SELECT operation_id FROM signer_durable_construction_outbox ORDER BY operation_id",
    )?;
    let ids = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if ids.len() > 100_000 {
        return Err(JournalError::Limit);
    }
    for id in ids {
        read(c, &id)?.ok_or(JournalError::NotFound)?;
    }
    Ok(())
}
