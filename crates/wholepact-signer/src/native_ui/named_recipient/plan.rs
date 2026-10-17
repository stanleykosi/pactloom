//! Strict bounded local request proposal. It contains no own viewing key and no
//! authority; the native original producer independently reconciles every pin.
use crate::consent_journal::named_recipient_records::{
    NamedRecipientOriginalRecordV1, NamedRecipientOutputPurposeV1, NamedRecipientOwnExpectationsV1,
    NamedRecipientOwnInputV1, NamedRecipientOwnOutputV1,
};
use crate::{Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use wholepact_authority::offline::OfflineEnrollmentPolicy;
use wholepact_authority::{OfflineAdmissionExportPlan, offline::ReserveOfflineAuthorization};
use wholepact_protocol::own_effects::{OwnEffectsPolicy, OwnOutputPurpose};
use wholepact_transport::MessageOrder;

pub(super) const MAX_PLAN_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_OWN_CONTEXT_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalRequestPlan {
    pub schema_version: u16,
    pub original: OriginalDraft,
    /// Proposed enrollment, never authenticated by this parser. The actual
    /// witness must authenticate its retained policy before reserving exposure.
    pub proposed_offline_policy: OfflineEnrollmentPolicy,
    /// Sequence zero is a preallocation template; the genuine native owner
    /// predicts and binds the exact next sequence before requesting consent.
    pub intent_order: MessageOrder,
    pub intent_purpose: String,
    pub intent_persistence_warning: String,
}
/// Public immutable claims only. Private FVK-derived expectations and the
/// native review/reference/request commitments are produced locally, not asked
/// of the online author of this file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalDraft {
    profile_ref: String,
    original_artifact_digest: String,
    canonical_artifact_digest: String,
    transformation_digest: String,
    named_assertion_digest: String,
    assertion_package_digest: String,
    validity_not_before_ms: u64,
    validity_expires_ms: u64,
    original_request_digest: String,
    reservation_request: ReserveOfflineAuthorization,
    admission_export_template: OfflineAdmissionExportPlan,
}
impl OriginalDraft {
    pub(super) fn with_local_expectations(
        self,
        policy: &OwnEffectsPolicy,
    ) -> Result<NamedRecipientOriginalRecordV1> {
        if policy.own_inputs.len() > 64 || policy.outputs.len() > 64 {
            return Err(Error::InvalidData);
        }
        let own_inputs = policy
            .own_inputs
            .iter()
            .map(|i| {
                Ok(NamedRecipientOwnInputV1 {
                    action_index: u32::try_from(i.action_index).map_err(|_| Error::InvalidData)?,
                    nullifier: hex::encode(i.nullifier),
                    value_zatoshis: i.value_zatoshis,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let outputs = policy
            .outputs
            .iter()
            .map(|o| {
                Ok(NamedRecipientOwnOutputV1 {
                    action_index: u32::try_from(o.action_index).map_err(|_| Error::InvalidData)?,
                    receiver_hex: hex::encode(o.receiver.to_raw_address_bytes()),
                    value_zatoshis: o.value_zatoshis,
                    memo_hex: hex::encode(o.memo),
                    purpose: match o.purpose {
                        OwnOutputPurpose::OwnReturn => NamedRecipientOutputPurposeV1::OwnReturn,
                        OwnOutputPurpose::Recipient => NamedRecipientOutputPurposeV1::Recipient,
                        OwnOutputPurpose::PeerReturnUnverified => {
                            NamedRecipientOutputPurposeV1::PeerReturnUnverified
                        }
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let own_expectations = NamedRecipientOwnExpectationsV1 {
            schema_version: 1,
            full_viewing_key_digest: hex::encode(Sha256::digest(policy.own_fvk.to_bytes())),
            manifest_digest: hex::encode(policy.manifest_digest),
            anchor: hex::encode(policy.anchor),
            expiry_height: policy.expiry_height,
            maximum_selected_net_debit_zatoshis: policy.maximum_selected_net_debit_zatoshis,
            exact_selected_net_debit_zatoshis: policy.exact_selected_net_debit_zatoshis,
            declared_fee_share_zatoshis: policy.declared_fee_share_zatoshis,
            exact_transaction_fee_zatoshis: policy.exact_transaction_fee_zatoshis,
            own_inputs,
            outputs,
        };
        Ok(NamedRecipientOriginalRecordV1 {
            born_origin: None,
            schema_version: 1,
            reference: String::new(),
            profile_ref: self.profile_ref,
            terms: self.reservation_request.intent.terms.clone(),
            original_artifact_digest: self.original_artifact_digest,
            canonical_artifact_digest: self.canonical_artifact_digest,
            transformation_digest: self.transformation_digest,
            named_assertion_digest: self.named_assertion_digest,
            assertion_package_digest: self.assertion_package_digest,
            validity_not_before_ms: self.validity_not_before_ms,
            validity_expires_ms: self.validity_expires_ms,
            original_request_digest: self.original_request_digest,
            reservation_request: self.reservation_request,
            reservation_request_digest: String::new(),
            admission_export_template: self.admission_export_template,
            own_policy_digest: policy.policy_commitment(),
            own_expectations,
        })
    }
}
impl OriginalRequestPlan {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PLAN_BYTES {
            return Err(Error::InvalidData);
        }
        let plan: Self = wholepact_core::parse_typed_json(bytes).map_err(|_| Error::InvalidData)?;
        if plan.schema_version != 1
            || plan.intent_order.sequence != 0
            || plan.intent_purpose.is_empty()
            || plan.intent_purpose.len() > 1024
            || plan.intent_persistence_warning.is_empty()
            || plan.intent_persistence_warning.len() > 4096
        {
            return Err(Error::InvalidData);
        }
        plan.proposed_offline_policy
            .validate()
            .map_err(|_| Error::InvalidData)?;
        // Original reference/request fields are still claims. Only the native
        // producer can normalize its own derived review commitment and then
        // validate/retain the exact request under a genuine NativeDecision.
        Ok(plan)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_plan_parser_rejects_missing_fields_and_oversized_input() {
        assert!(OriginalRequestPlan::decode(b"{}").is_err());
        assert!(OriginalRequestPlan::decode(b"{\"schema_version\":1,\"trusted\":true}").is_err());
        assert!(OriginalRequestPlan::decode(&vec![b' '; MAX_PLAN_BYTES + 1]).is_err());
    }
}
