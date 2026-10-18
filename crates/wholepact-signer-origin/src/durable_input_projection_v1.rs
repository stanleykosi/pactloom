//! Purpose-separated, NON-SPENDING discovery wire data. None of these public
//! values authenticates a peer, approves a scan/export, reserves a note, or can
//! be converted into ordinary manifest enrollment or spending authority.
//! This leaf is intentionally unregistered pending the complete native route.
use crate::{Error, Result, digest, hash, label};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wholepact_core::durable_input_projection_v1::{
    DurableInputProjectionIntentV1, DurableInputProjectionPurposeV1, DurableInputProjectionV1,
};
use zeroize::Zeroize;

pub mod redisclosure;

pub const MAX_INPUT_PROJECTION_FRAME_BYTES_V1: usize = 128 * 1024;
pub const INPUT_PROJECTION_PAIR_REASON_V1: &str = "DURABLE_INPUT_PROJECTION_REQUEST_SCOPE_V1";

/// The exact future scan/disclosure request, not its eventual financial
/// manifest. Native pairing must display this intent and independently join
/// its original policy/account before approving this purpose-specific grant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableInputProjectionRequestV1 {
    pub version: u16,
    pub operation_id: String,
    pub intent: DurableInputProjectionIntentV1,
}
impl DurableInputProjectionRequestV1 {
    pub fn validate(&self) -> Result<()> {
        label(&self.operation_id)?;
        self.intent.validate().map_err(|_| Error::Binding)?;
        if self.version != 1 {
            return Err(Error::Binding);
        }
        bounded(self, 120 * 1024)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:durable-input-projection-request:v1", self)
    }
    pub fn pair_scope(&self) -> Result<ProjectionPairScopeV1> {
        self.validate()?;
        let scope = ProjectionPairScopeV1 {
            schema_version: 1,
            purpose: self.intent.purpose,
            operation_id: self.operation_id.clone(),
            account_id: self.intent.account_id.clone(),
            agreement_id: self.intent.agreement.agreement_id.clone(),
            obligation_id: self.intent.agreement.obligation_id.clone(),
            participant_id: self.intent.participant_id.clone(),
            intent_digest: self.intent.digest().map_err(|_| Error::Binding)?,
        };
        scope.validate()?;
        Ok(scope)
    }
    pub fn require_scope(&self, scope: &ProjectionPairScopeV1) -> Result<()> {
        scope.validate()?;
        if self.pair_scope()? != *scope {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn require_valid_at(&self, now_unix_seconds: u64) -> Result<()> {
        self.validate()?;
        if now_unix_seconds < self.intent.valid_from_unix_seconds
            || now_unix_seconds >= self.intent.valid_until_unix_seconds
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
}

/// A separate wire type, NOT PairScope. In particular there is no manifest
/// digest, history flag, preconstruction flag or authorization-export flag.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionPairScopeV1 {
    pub schema_version: u16,
    pub purpose: DurableInputProjectionPurposeV1,
    pub operation_id: String,
    pub account_id: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub participant_id: String,
    pub intent_digest: String,
}
impl ProjectionPairScopeV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.purpose != DurableInputProjectionPurposeV1::DurablePlainFixedInputProjectionV1
        {
            return Err(Error::Binding);
        }
        hash(&self.account_id)?;
        hash(&self.intent_digest)?;
        for value in [
            &self.operation_id,
            &self.agreement_id,
            &self.obligation_id,
            &self.participant_id,
        ] {
            label(value)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:durable-input-projection-pair-scope:v1", self)
    }
}

/// Historical local process/channel metadata, never an ordinary
/// TransportIdentityBinding. A grant digest hashes a random ephemeral token;
/// it is NOT a public key or portable evidence of account ownership.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionChannelBindingV1 {
    pub version: u16,
    pub scope: ProjectionPairScopeV1,
    pub grant_id: String,
    pub authenticated_local_grant_digest: String,
    pub channel_binding_digest: String,
    pub uid: u32,
    pub pid: u32,
    pub process_instance: String,
    pub signer_generation: u64,
}
impl ProjectionChannelBindingV1 {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        for value in [
            &self.grant_id,
            &self.authenticated_local_grant_digest,
            &self.channel_binding_digest,
            &self.process_instance,
        ] {
            hash(value)?;
        }
        if self.version != 1
            || self.pid == 0
            || self.signer_generation == 0
            || self.channel_binding_digest
                != projection_pairing_review_digest_v1(
                    &self.scope,
                    &self.process_instance,
                    self.signer_generation,
                )?
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:durable-input-projection-local-channel:v1", self)
    }
}

/// Inert commitment helper. Only the real native pending peer supplies the
/// process instance/generation; callers cannot establish them by hashing DTOs.
/// Ordinary pairing's existing domain and serialization remain unchanged.
pub fn projection_pairing_review_digest_v1(
    scope: &ProjectionPairScopeV1,
    process_instance: &str,
    signer_generation: u64,
) -> Result<String> {
    scope.validate()?;
    hash(process_instance)?;
    if signer_generation == 0 {
        return Err(Error::Binding);
    }
    let bytes = serde_json::to_vec(scope).map_err(|_| Error::InvalidData)?;
    let mut h = Sha256::new();
    h.update(b"wholepact:local-process-input-projection-pairing:v1\0");
    h.update(process_instance.as_bytes());
    h.update(signer_generation.to_le_bytes());
    h.update(bytes);
    Ok(hex::encode(h.finalize()))
}

/// Immutable signer outbox representation. All fields are publicly
/// constructible DATA; authenticity comes only from actual native journal and
/// installed transport joins, not deserialize/validate/digest succeeding.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableInputProjectionOutboxV1 {
    pub version: u16,
    pub request: DurableInputProjectionRequestV1,
    pub request_digest: String,
    pub projection: DurableInputProjectionV1,
    pub projection_digest: String,
    pub native_review_digest: String,
    pub native_entry_digest: String,
    pub recipient: ProjectionChannelBindingV1,
    pub reference: String,
}
impl DurableInputProjectionOutboxV1 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.projection.validate().map_err(|_| Error::Binding)?;
        self.recipient.validate()?;
        self.request.require_scope(&self.recipient.scope)?;
        for value in [
            &self.request_digest,
            &self.projection_digest,
            &self.native_review_digest,
            &self.native_entry_digest,
            &self.reference,
        ] {
            hash(value)?;
        }
        if self.version != 1
            || self.projection.intent != self.request.intent
            || self.request_digest != self.request.digest()?
            || self.projection_digest != self.projection.digest().map_err(|_| Error::Binding)?
            || self.reference != self.compute_reference()?
        {
            return Err(Error::Binding);
        }
        // Retained response overhead fits within the unchanged 128 KiB frame.
        // The native producer must preflight this BEFORE approval/commit.
        bounded(self, MAX_INPUT_PROJECTION_FRAME_BYTES_V1 - 64)
    }
    pub fn compute_reference(&self) -> Result<String> {
        digest(
            "wholepact:durable-input-projection-native-outbox:v1",
            &(
                self.version,
                &self.request_digest,
                &self.projection_digest,
                &self.native_review_digest,
                &self.native_entry_digest,
                &self.recipient,
            ),
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionPairResponseV1 {
    pub schema_version: u16,
    pub accepted: bool,
    pub reason_code: String,
    pub grant_id: String,
    pub token_hex: String,
    pub expires_in_seconds: u64,
    pub binding: ProjectionChannelBindingV1,
}
impl Drop for ProjectionPairResponseV1 {
    fn drop(&mut self) {
        self.token_hex.zeroize();
    }
}

/// Only these two purpose-specific operations exist. This is not AppRequest.
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProjectionRequestV1 {
    Status,
    Project {
        request: Box<DurableInputProjectionRequestV1>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProjectionResponseV1 {
    Current {
        binding: ProjectionChannelBindingV1,
    },
    Retained {
        outbox: Box<DurableInputProjectionOutboxV1>,
    },
    Denied,
}
pub fn decode_projection_response_v1(bytes: &[u8]) -> Result<ProjectionResponseV1> {
    if bytes.is_empty() || bytes.len() > MAX_INPUT_PROJECTION_FRAME_BYTES_V1 {
        return Err(Error::Limit);
    }
    wholepact_core::parse_typed_json(bytes).map_err(|_| Error::InvalidData)
}
fn bounded(value: &impl Serialize, maximum: usize) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::InvalidData)?);
    if bytes.len() > maximum {
        return Err(Error::Limit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> ProjectionPairScopeV1 {
        ProjectionPairScopeV1 {
            schema_version: 1,
            purpose: DurableInputProjectionPurposeV1::DurablePlainFixedInputProjectionV1,
            operation_id: "synthetic-projection".into(),
            account_id: "a".repeat(64),
            agreement_id: "synthetic-agreement".into(),
            obligation_id: "synthetic-obligation".into(),
            participant_id: "synthetic-participant".into(),
            intent_digest: "b".repeat(64),
        }
    }

    #[test]
    fn projection_and_ordinary_pair_scopes_do_not_decode_as_each_other() {
        let projection = serde_json::to_vec(&scope()).unwrap();
        assert!(serde_json::from_slice::<crate::PairScope>(&projection).is_err());
        let ordinary = crate::PairScope {
            account_id: "a".repeat(64),
            agreement_id: "synthetic-agreement".into(),
            participant_id: "synthetic-participant".into(),
            manifest_digest: "b".repeat(64),
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        assert!(
            serde_json::from_slice::<ProjectionPairScopeV1>(
                &serde_json::to_vec(&ordinary).unwrap()
            )
            .is_err()
        );
        let mut raw = serde_json::to_value(scope()).unwrap();
        raw["authorization_export"] = true.into();
        assert!(serde_json::from_value::<ProjectionPairScopeV1>(raw).is_err());
    }

    #[test]
    fn projection_channel_domain_and_exact_scope_are_not_interchangeable() {
        let scope = scope();
        let instance = "c".repeat(64);
        let channel = projection_pairing_review_digest_v1(&scope, &instance, 7).unwrap();
        let mut old = Sha256::new();
        old.update(b"wholepact:local-process-pairing:v1\0");
        old.update(instance.as_bytes());
        old.update(7u64.to_le_bytes());
        old.update(serde_json::to_vec(&scope).unwrap());
        assert_ne!(channel, hex::encode(old.finalize()));
        let binding = ProjectionChannelBindingV1 {
            version: 1,
            scope,
            grant_id: "d".repeat(64),
            authenticated_local_grant_digest: "e".repeat(64),
            channel_binding_digest: channel,
            uid: 1000,
            pid: 17,
            process_instance: instance,
            signer_generation: 7,
        };
        binding.validate().unwrap();
        let mut changed = binding.clone();
        changed.scope.operation_id.push_str("-other");
        assert!(changed.validate().is_err());
        changed = binding.clone();
        changed.scope.intent_digest = "f".repeat(64);
        assert!(changed.validate().is_err());
        changed = binding;
        changed.signer_generation += 1;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn purpose_old_operations_duplicates_and_extra_fields_are_refused() {
        let mut raw = serde_json::to_value(scope()).unwrap();
        raw["purpose"] = "ordinary_manifest_review".into();
        assert!(serde_json::from_value::<ProjectionPairScopeV1>(raw).is_err());
        assert!(
            serde_json::from_str::<ProjectionRequestV1>(
                r#"{"operation":"request_preconstruction","request":{}}"#
            )
            .is_err()
        );
        assert!(
            decode_projection_response_v1(br#"{"status":"denied","status":"denied"}"#).is_err()
        );
        assert!(
            decode_projection_response_v1(br#"{"status":"denied","authorization_export":true}"#)
                .is_err()
        );
        assert!(
            decode_projection_response_v1(&vec![b' '; MAX_INPUT_PROJECTION_FRAME_BYTES_V1 + 1])
                .is_err()
        );
    }
}
