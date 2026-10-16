//! Exact immutable dispatch retry payload, retained in the encrypted signer
//! journal before contacting the witness. Retained JSON never confers approval.
use super::*;
use crate::authority_bridge::{dispatch_ipc::DispatchRequest, BridgeError, Result as BridgeResult};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use wholepact_authority::{AuthorizeDispatch, WitnessDisclosureDescriptor};

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedDispatch {
    pub request: DispatchRequest,
    pub exact: AuthorizeDispatch,
    pub witness: WitnessDisclosureDescriptor,
}
impl RetainedDispatch {
    pub(super) fn validate(&self, original: &OriginalAuthorizationEvidence) -> BridgeResult<()> {
        self.request.validate()?;
        self.exact.validate()?;
        self.witness.validate()?;
        self.request.history.matches(
            &crate::authority_bridge::protocol::OriginalAuthorizationView::from_original(original),
        )?;
        let t = original.original_consent().terms();
        let b = &self.request.backend;
        if self.request.operation_id != self.exact.operation_id
            || self.exact.account_id != t.account_id
            || self.witness.account_id != t.account_id
            || self.exact.network_profile_id != self.witness.network_profile_id
            || self.exact.reservation_operation_id != t.authorization_id
            || self.exact.backend_disclosure_digest != b.digest()?
            || self.exact.final_transaction_digest != b.descriptor.bytes_sha256
            || self.exact.final_transaction_id != b.descriptor.transaction_id
            || self.exact.transaction_expiry_height != b.descriptor.expiry_height
            || self.exact.transaction_expiry_height != t.transaction_expiry_height
            || b.agreement_id != t.agreement_id
            || b.descriptor.obligation_id != t.obligation_id
            || b.descriptor.proposal_id != t.proposal_id
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
impl SignerConsentJournal {
    pub(crate) fn retained_dispatch(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
        operation: &str,
    ) -> BridgeResult<Option<RetainedDispatch>> {
        // Existing exact result also verifies this lease belongs to this journal.
        self.bridge_result(lease)?;
        id(operation)?;
        let reserved = self.bridge_request(lease)?;
        let connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        let raw: Option<String> = connection
            .query_row(
                "SELECT payload FROM signer_dispatch_requests WHERE operation_id=?1",
                [operation],
                |r| r.get(0),
            )
            .optional()
            .map_err(JournalError::from)?;
        let record: Option<RetainedDispatch> = raw.map(decode).transpose()?;
        if let Some(record) = &record {
            record.validate(lease.evidence())?;
            if record.exact.reservation_request_digest != reserved.reservation().request_digest()?
                || reserved
                    .disclosure
                    .as_ref()
                    .is_none_or(|d| d.descriptor != record.witness)
                || record.exact.operation_id != operation
            {
                return Err(BridgeError::Binding);
            }
        }
        lease.check_current()?;
        Ok(record)
    }
    pub(crate) fn retain_dispatch(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
        record: &RetainedDispatch,
    ) -> BridgeResult<()> {
        self.bridge_result(lease)?;
        record.validate(lease.evidence())?;
        let reserved = self.bridge_request(lease)?;
        if record.exact.reservation_request_digest != reserved.reservation().request_digest()?
            || reserved
                .disclosure
                .as_ref()
                .is_none_or(|d| d.descriptor != record.witness)
        {
            return Err(BridgeError::Binding);
        }
        let mut connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        #[cfg(feature = "authority-signing")]
        if !self.revalidate_settlements_in_transaction(&tx)? {
            tx.commit().map_err(JournalError::from)?;
            return Err(BridgeError::RecoveryRequired);
        }
        let old: Option<String> = tx
            .query_row(
                "SELECT payload FROM signer_dispatch_requests WHERE operation_id=?1",
                [&record.exact.operation_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(JournalError::from)?;
        if let Some(old) = old {
            if decode::<RetainedDispatch>(old)? != *record {
                return Err(BridgeError::Conflict);
            }
            lease.check_current()?;
            return Ok(());
        }
        let payload = encode(record)?;
        tx.execute("INSERT INTO signer_dispatch_requests(operation_id,authorization_id,payload) VALUES(?1,?2,?3)", params![record.exact.operation_id, record.request.history.authorization_id, payload.as_str()]).map_err(JournalError::from)?;
        storage::bounded(&tx, self.capacity_limits())?;
        lease.check_current()?;
        tx.commit().map_err(JournalError::from)?;
        Ok(())
    }
}
