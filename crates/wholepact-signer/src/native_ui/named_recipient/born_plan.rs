//! Strict inert born draft. Actual complete witness parents, retained signer
//! genesis and native own selection are authenticated by the private importer.
use super::plan::{MAX_PLAN_BYTES, OriginalDraft};
use crate::consent_journal::named_recipient_records::BornNamedRecipientOriginV1;
use crate::consent_journal::{
    BornNamedRecipientOriginalInputs, NamedIntentExportTemplate, NamedRecipientOriginalInputs,
};
use crate::{Error, Result};
use serde::Deserialize;
use wholepact_protocol::own_effects::OwnEffectsPolicy;
use wholepact_transport::{EncryptedEnvelope, MessageOrder, Timestamp};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BornOriginalRequestPlan {
    schema_version: u16,
    original: OriginalDraft,
    born_origin: BornNamedRecipientOriginV1,
    intent_order: MessageOrder,
    intent_purpose: String,
    intent_persistence_warning: String,
}
impl BornOriginalRequestPlan {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PLAN_BYTES {
            return Err(Error::InvalidData);
        }
        let result: Self =
            wholepact_core::parse_typed_json(bytes).map_err(|_| Error::InvalidData)?;
        if result.schema_version != 1
            || result.intent_order.sequence != 0
            || result.intent_purpose.is_empty()
            || result.intent_purpose.len() > 1024
            || result.intent_persistence_warning.is_empty()
            || result.intent_persistence_warning.len() > 4096
        {
            return Err(Error::InvalidData);
        }
        result
            .born_origin
            .request
            .validate()
            .map_err(|_| Error::InvalidData)?;
        Ok(result)
    }
    pub(super) fn with_local_expectations(
        self,
        own_policy: OwnEffectsPolicy,
        assertion_envelope: EncryptedEnvelope,
        checkpoint_envelope: EncryptedEnvelope,
        now: Timestamp,
    ) -> Result<BornNamedRecipientOriginalInputs> {
        let mut proposed = self.original.with_local_expectations(&own_policy)?;
        if proposed.reservation_request != self.born_origin.request.reservation {
            return Err(Error::InvalidData);
        }
        let proposed_policy = self.born_origin.enrollment.enrollment.policy.clone();
        proposed.born_origin = Some(self.born_origin);
        Ok(BornNamedRecipientOriginalInputs {
            checkpoint_envelope,
            original: NamedRecipientOriginalInputs {
                proposed,
                own_policy,
                proposed_policy,
                assertion_envelope,
                outgoing: NamedIntentExportTemplate {
                    order: self.intent_order,
                    purpose: self.intent_purpose,
                    persistence_warning: self.intent_persistence_warning,
                },
                now,
            },
        })
    }
}
