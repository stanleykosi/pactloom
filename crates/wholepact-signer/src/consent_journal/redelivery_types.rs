//! Immutable disclosure of one already retained authorization to a newly paired
//! local process. This is never a new spending decision or reconstructed permit.
use super::*;
use crate::authority_bridge::protocol::RetainedAuthorizationResult;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultRedeliveryRequest {
    pub operation_id: String,
    pub authorization_id: String,
    pub expected_original_consent_ref: String,
    pub expected_enrollment_ref: String,
    pub expected_manifest_ref: String,
}
impl ResultRedeliveryRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        id(&self.operation_id)?;
        id(&self.authorization_id)?;
        for value in [
            &self.expected_original_consent_ref,
            &self.expected_enrollment_ref,
            &self.expected_manifest_ref,
        ] {
            hash(value)?;
        }
        Ok(())
    }
    pub(crate) fn matches(&self, original: &OriginalAuthorizationEvidence) -> Result<()> {
        self.validate()?;
        if self.authorization_id != original.original_consent().terms().authorization_id
            || self.expected_original_consent_ref != original.original_consent().reference()
            || self.expected_enrollment_ref != original.enrollment().reference()
            || self.expected_manifest_ref != original.accepted_manifest().reference()
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultRedeliveryReference {
    pub operation_id: String,
    pub reference: String,
}
impl ResultRedeliveryReference {
    pub(crate) fn validate(&self) -> Result<()> {
        id(&self.operation_id)?;
        hash(&self.reference)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultRedeliveryTerms {
    pub request: ResultRedeliveryRequest,
    pub account_id: String,
    pub principal_id: String,
    pub agreement_id: String,
    pub participant_id: String,
    pub manifest_digest: String,
    pub effects_digest: String,
    pub maximum_debit_zatoshis: u64,
    pub transaction_expiry_height: u32,
    pub result_digest: String,
    pub outbox_digest: String,
    pub recipient: TransportIdentityBinding,
    pub receipt: NativeConsentReceipt,
}
/// Serializable evidence only. The approved wrapper has no public constructor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultRedeliveryRecord {
    pub(super) reference: String,
    pub(super) terms: ResultRedeliveryTerms,
}
impl ResultRedeliveryRecord {
    pub(super) fn new(terms: ResultRedeliveryTerms) -> Result<Self> {
        let record = Self {
            reference: digest("wholepact:exact-result-redelivery:v1", &terms)?,
            terms,
        };
        record.validate()?;
        Ok(record)
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn terms(&self) -> &ResultRedeliveryTerms {
        &self.terms
    }
    pub fn reference_request(&self) -> ResultRedeliveryReference {
        ResultRedeliveryReference {
            operation_id: self.terms.request.operation_id.clone(),
            reference: self.reference.clone(),
        }
    }
    /// Pure evidence validation; success does not grant export or spending.
    pub fn validate(&self) -> Result<()> {
        let t = &self.terms;
        t.request.validate()?;
        for value in [
            &t.account_id,
            &t.principal_id,
            &t.agreement_id,
            &t.participant_id,
        ] {
            id(value)?;
        }
        for value in [
            &t.manifest_digest,
            &t.effects_digest,
            &t.result_digest,
            &t.outbox_digest,
        ] {
            hash(value)?;
        }
        t.receipt.validate()?;
        t.recipient.validate_scope(
            &t.account_id,
            &t.agreement_id,
            &t.participant_id,
            Some(&t.manifest_digest),
        )?;
        if !matches!(t.recipient, TransportIdentityBinding::LocalProcess { .. })
            || t.maximum_debit_zatoshis > MAX_MONEY
            || t.transaction_expiry_height == 0
            || self.reference != digest("wholepact:exact-result-redelivery:v1", t)?
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(super) fn validate_original(
        &self,
        original: &OriginalAuthorizationEvidence,
        result: &RetainedAuthorizationResult,
    ) -> Result<()> {
        self.validate()?;
        self.terms.request.matches(original)?;
        let t = original.original_consent().terms();
        let r = &self.terms;
        if r.account_id != t.account_id
            || r.principal_id != t.principal_id
            || r.agreement_id != t.agreement_id
            || r.participant_id != original.enrollment().participant_id()
            || r.manifest_digest != t.manifest_digest
            || r.effects_digest != t.effects_digest
            || r.maximum_debit_zatoshis != t.maximum_debit_zatoshis
            || r.transaction_expiry_height != t.transaction_expiry_height
            || r.result_digest != result.result_digest()
            || r.outbox_digest != result.outbox_digest()
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}
