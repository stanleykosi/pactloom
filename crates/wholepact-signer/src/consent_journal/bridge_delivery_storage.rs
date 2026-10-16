//! Typed immutable redelivery append/read. An authorization result must already
//! exist; this module never signs, changes original consent or reduces exposure.
use super::*;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

impl SignerConsentJournal {
    pub fn record_result_redelivery(
        &self,
        approved: ApprovedResultRedelivery,
    ) -> Result<ResultRedeliveryRecord> {
        let a = approved.0;
        a.record.validate()?;
        let t = a.record.terms();
        let account = self.account_state()?;
        let lease = a.lease(&self.binding(), &account, &t.receipt)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let mut connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        storage::check_account(&tx, &account)?;
        if lease.principal != t.principal_id || account.account_id != t.account_id {
            return Err(JournalError::Permission);
        }
        let original = storage::read_original(&tx, &t.request.authorization_id)?
            .ok_or(JournalError::NotFound)?;
        let result =
            bridge_storage::read_validated_result(&tx, &t.request.authorization_id, &original)
                .map_err(bridge_error)?;
        a.record.validate_original(&original, &result)?;
        if let Some(old) = read_redelivery(&tx, &t.request.operation_id)? {
            if old != a.record {
                return Err(JournalError::Conflict);
            }
            lease.check_current()?;
            return Ok(old);
        }
        let payload = encode(&a.record)?;
        tx.execute("INSERT INTO signer_result_redeliveries(operation_id,reference,authorization_id,payload) VALUES(?1,?2,?3,?4)",params![t.request.operation_id,a.record.reference(),t.request.authorization_id,payload.as_str()])?;
        storage::bounded(&tx, self.capacity_limits())?;
        lease.check_current()?;
        tx.commit()?;
        Ok(a.record.clone())
    }
    /// Read one exact immutable operation under an already-held original lease.
    /// The native IPC separately requires its newly approved recipient to match
    /// the actual current peer; possession of this record alone grants nothing.
    pub(crate) fn result_redelivery(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
        operation_id: &str,
    ) -> Result<Option<ResultRedeliveryRecord>> {
        id(operation_id)?;
        lease.check_current()?;
        if lease.binding() != &self.binding() {
            return Err(JournalError::Permission);
        }
        let account = self.account_state()?;
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        storage::check_account(&c, &account)?;
        let Some(record) = read_redelivery(&c, operation_id)? else {
            return Ok(None);
        };
        let original = lease.evidence();
        let result = bridge_storage::read_validated_result(
            &c,
            &original.original_consent().terms().authorization_id,
            original,
        )
        .map_err(bridge_error)?;
        record.validate_original(original, &result)?;
        lease.check_current()?;
        Ok(Some(record))
    }
}
fn read_redelivery(c: &Connection, operation_id: &str) -> Result<Option<ResultRedeliveryRecord>> {
    let raw:Option<(String,String,String)>=c.query_row("SELECT reference,authorization_id,payload FROM signer_result_redeliveries WHERE operation_id=?1",[operation_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    raw.map(|(reference, authorization_id, payload)| {
        let record: ResultRedeliveryRecord = decode(payload)?;
        record.validate()?;
        if record.reference() != reference
            || record.terms().request.operation_id != operation_id
            || record.terms().request.authorization_id != authorization_id
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(record)
    })
    .transpose()
}
fn bridge_error(error: crate::authority_bridge::BridgeError) -> JournalError {
    match error {
        crate::authority_bridge::BridgeError::Journal(e) => e,
        crate::authority_bridge::BridgeError::Missing => JournalError::NotFound,
        crate::authority_bridge::BridgeError::Permission => JournalError::Permission,
        crate::authority_bridge::BridgeError::RecoveryRequired => JournalError::RecoveryRequired,
        _ => JournalError::InvalidBinding,
    }
}
