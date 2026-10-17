//! Immutable born dispatch retry intent. Retention is not native approval or a
//! live dispatch admission; the exact reviewed owner must contact the witness.
use super::named_recipient_records::{
    NamedRecipientOriginalRecordV1, NamedRecipientStartedRecordV1,
};
use super::*;
use crate::authority_bridge::{
    BridgeError, Result as BridgeResult, born_dispatch_ipc::BornDispatchRequestV1,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use wholepact_authority::{
    WitnessDisclosureDescriptor, born_offline_dispatch_v1::BornOfflineDispatchRequestV1,
};
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedBornDispatchV1 {
    pub(crate) request: BornDispatchRequestV1,
    pub(crate) exact: BornOfflineDispatchRequestV1,
    pub(crate) witness: WitnessDisclosureDescriptor,
}
impl RetainedBornDispatchV1 {
    pub(crate) fn validate(
        &self,
        original: &NamedRecipientOriginalRecordV1,
        started: &NamedRecipientStartedRecordV1,
    ) -> Result<()> {
        started.validate(original)?;
        let origin = original
            .born_origin
            .as_ref()
            .ok_or(JournalError::InvalidBinding)?;
        let review = started
            .born_final_review
            .as_ref()
            .ok_or(JournalError::InvalidBinding)?;
        self.request
            .matches_exact(&self.exact, &review.admission)
            .map_err(|_| JournalError::InvalidBinding)?;
        self.witness
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        if self.request.authorization_id != original.terms.authorization_id
            || self.request.expected_original_ref != original.reference
            || self.request.expected_born_origin_digest != origin.digest()?
            || self.witness != review.witness
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        digest("wholepact:retained-born-dispatch:v1", self)
    }
}
impl SignerConsentJournal {
    pub(crate) fn retained_born_dispatch(
        &self,
        original: &NamedRecipientOriginalRecordV1,
        operation: &str,
    ) -> BridgeResult<Option<RetainedBornDispatchV1>> {
        id(operation)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let old:Option<(String,String,String,String)>=c.query_row("SELECT authorization_id,original_ref,request_digest,payload FROM signer_named_recipient_dispatch_requests WHERE operation_id=?1",[operation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(JournalError::from)?;
        let Some((authorization, reference, commitment, raw)) = old else {
            return Ok(None);
        };
        let record: RetainedBornDispatchV1 = decode(raw)?;
        let raw: String = c
            .query_row(
                "SELECT payload FROM signer_named_recipient_started WHERE authorization_id=?1",
                [&original.terms.authorization_id],
                |r| r.get(0),
            )
            .map_err(JournalError::from)?;
        let started = decode(raw)?;
        record.validate(original, &started)?;
        if record.exact.dispatch.operation_id != operation
            || authorization != original.terms.authorization_id
            || reference != original.reference
            || commitment != record.digest()?
        {
            return Err(BridgeError::Binding);
        }
        Ok(Some(record))
    }
    #[cfg(all(
        feature = "native-ui",
        feature = "authority-signing",
        feature = "offline-review-foundation",
        target_os = "linux"
    ))]
    pub(crate) fn retain_born_dispatch(
        &self,
        held: &HeldBornHostHistoryV1<'_>,
        record: &RetainedBornDispatchV1,
    ) -> BridgeResult<()> {
        held.check_journal(self)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        let original = &held.original;
        let raw: String = tx
            .query_row(
                "SELECT payload FROM signer_named_recipient_started WHERE authorization_id=?1",
                [&original.terms.authorization_id],
                |r| r.get(0),
            )
            .map_err(JournalError::from)?;
        record.validate(original, &decode(raw)?)?;
        let old:Option<String>=tx.query_row("SELECT payload FROM signer_named_recipient_dispatch_requests WHERE operation_id=?1",[&record.exact.dispatch.operation_id],|r|r.get(0)).optional().map_err(JournalError::from)?;
        if let Some(raw) = old {
            if decode::<RetainedBornDispatchV1>(raw)? != *record {
                return Err(BridgeError::Conflict);
            }
        } else {
            let raw = encode(record)?;
            tx.execute("INSERT INTO signer_named_recipient_dispatch_requests(operation_id,authorization_id,original_ref,request_digest,payload) VALUES(?1,?2,?3,?4,?5)",params![record.exact.dispatch.operation_id,original.terms.authorization_id,original.reference,record.digest()?,raw.as_str()]).map_err(JournalError::from)?;
        }
        named_recipient_inventory::read_all(&tx, &original.terms.account_id)?;
        storage::bounded(&tx, self.capacity_limits())?;
        held.check_current()?;
        tx.commit().map_err(JournalError::from)?;
        held.check_current()
    }
}
