//! Exact one-hop redelivery of an ORIGINAL projection. These strict values are
//! historical data, not permission to read the journal or export its contents.
//! Deliberately unregistered until the genuine native issuer is integrated.
use super::*;

pub const REDISCLOSURE_PAIR_REASON_V1: &str = "DURABLE_INPUT_PROJECTION_REDISCLOSURE_SCOPE_V1";

/// The Engine retained this full original request before the first pairing.
/// Recovery never accepts an optional digest, a replacement intent, or a new
/// scan under the original operation. A new operation is delivery-only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableInputProjectionRedisclosureRequestV1 {
    pub version: u16,
    pub operation_id: String,
    pub original_request: DurableInputProjectionRequestV1,
}
impl DurableInputProjectionRedisclosureRequestV1 {
    pub fn validate(&self) -> Result<()> {
        label(&self.operation_id)?;
        self.original_request.validate()?;
        if self.version != 1 || self.operation_id == self.original_request.operation_id {
            return Err(Error::Binding);
        }
        bounded(self, 120 * 1024)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(
            "wholepact:durable-input-projection-redisclosure-request:v1",
            self,
        )
    }
    pub fn require_valid_at(&self, now_unix_seconds: u64) -> Result<()> {
        self.validate()?;
        self.original_request.require_valid_at(now_unix_seconds)
    }
    pub fn pair_scope(&self) -> Result<ProjectionRedisclosurePairScopeV1> {
        self.validate()?;
        let scope = ProjectionRedisclosurePairScopeV1 {
            schema_version: 1,
            operation_id: self.operation_id.clone(),
            original_scope: self.original_request.pair_scope()?,
            original_request_digest: self.original_request.digest()?,
        };
        scope.validate()?;
        Ok(scope)
    }
    pub fn require_scope(&self, scope: &ProjectionRedisclosurePairScopeV1) -> Result<()> {
        scope.validate()?;
        if &self.pair_scope()? != scope {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

/// A different nominal scope, tag and review domain from initial selection.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRedisclosurePairScopeV1 {
    pub schema_version: u16,
    pub operation_id: String,
    pub original_scope: ProjectionPairScopeV1,
    pub original_request_digest: String,
}
impl ProjectionRedisclosurePairScopeV1 {
    pub fn validate(&self) -> Result<()> {
        label(&self.operation_id)?;
        self.original_scope.validate()?;
        hash(&self.original_request_digest)?;
        if self.schema_version != 1 || self.operation_id == self.original_scope.operation_id {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRedisclosureChannelBindingV1 {
    pub version: u16,
    pub scope: ProjectionRedisclosurePairScopeV1,
    pub grant_id: String,
    /// SHA256 of the actual ephemeral local grant token, NOT a public key.
    pub authenticated_local_grant_digest: String,
    pub channel_binding_digest: String,
    pub uid: u32,
    pub pid: u32,
    pub process_instance: String,
    pub signer_generation: u64,
}
impl ProjectionRedisclosureChannelBindingV1 {
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
                != redisclosure_pairing_review_digest_v1(
                    &self.scope,
                    &self.process_instance,
                    self.signer_generation,
                )?
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

pub fn redisclosure_pairing_review_digest_v1(
    scope: &ProjectionRedisclosurePairScopeV1,
    process_instance: &str,
    signer_generation: u64,
) -> Result<String> {
    scope.validate()?;
    hash(process_instance)?;
    if signer_generation == 0 {
        return Err(Error::Binding);
    }
    let mut h = Sha256::new();
    h.update(b"wholepact:local-process-input-projection-redisclosure-pairing:v1\0");
    h.update(process_instance.as_bytes());
    h.update(signer_generation.to_le_bytes());
    h.update(serde_json::to_vec(scope).map_err(|_| Error::InvalidData)?);
    Ok(hex::encode(h.finalize()))
}

/// Immutable new disclosure record. It always links DIRECTLY to an initial
/// outbox, never another delivery. The original projection/recipient is kept
/// verbatim, not relabelled as freshly selected or previously approved by peers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableInputProjectionDeliveryV1 {
    pub version: u16,
    pub request: DurableInputProjectionRedisclosureRequestV1,
    pub request_digest: String,
    pub original_outbox_reference: String,
    pub original_projection_digest: String,
    pub native_review_digest: String,
    pub native_entry_digest: String,
    pub recipient: ProjectionRedisclosureChannelBindingV1,
    pub reference: String,
}
impl DurableInputProjectionDeliveryV1 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.recipient.validate()?;
        self.request.require_scope(&self.recipient.scope)?;
        for value in [
            &self.request_digest,
            &self.original_outbox_reference,
            &self.original_projection_digest,
            &self.native_review_digest,
            &self.native_entry_digest,
            &self.reference,
        ] {
            hash(value)?;
        }
        if self.version != 1
            || self.request_digest != self.request.digest()?
            || self.reference != self.compute_reference()?
        {
            return Err(Error::Binding);
        }
        bounded(self, MAX_INPUT_PROJECTION_FRAME_BYTES_V1 - 64)
    }
    pub fn require_original(&self, original: &DurableInputProjectionOutboxV1) -> Result<()> {
        self.validate()?;
        original.validate()?;
        if self.request.original_request != original.request
            || self.original_outbox_reference != original.reference
            || self.original_projection_digest != original.projection_digest
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn compute_reference(&self) -> Result<String> {
        digest(
            "wholepact:durable-input-projection-delivery:v1",
            &(
                self.version,
                &self.request_digest,
                &self.original_outbox_reference,
                &self.original_projection_digest,
                &self.native_review_digest,
                &self.native_entry_digest,
                &self.recipient,
            ),
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRedisclosurePairResponseV1 {
    pub schema_version: u16,
    pub accepted: bool,
    pub reason_code: String,
    pub grant_id: String,
    pub token_hex: String,
    pub expires_in_seconds: u64,
    pub binding: ProjectionRedisclosureChannelBindingV1,
}
impl Drop for ProjectionRedisclosurePairResponseV1 {
    fn drop(&mut self) {
        self.token_hex.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[serde(from = "StrictProjectionRedisclosureRequestV1")]
pub enum ProjectionRedisclosureRequestV1 {
    Status,
    Redisclose {
        request: Box<DurableInputProjectionRedisclosureRequestV1>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[serde(from = "StrictProjectionRedisclosureResponseV1")]
pub enum ProjectionRedisclosureResponseV1 {
    Current {
        binding: ProjectionRedisclosureChannelBindingV1,
    },
    Retained {
        original: Box<DurableInputProjectionOutboxV1>,
        delivery: Box<DurableInputProjectionDeliveryV1>,
    },
    Denied,
}
// Empty struct variants are necessary: internally tagged unit variants ignore
// extra fields. The private parse shape retains the public wire/API unchanged.
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum StrictProjectionRedisclosureRequestV1 {
    Status {},
    Redisclose {
        request: Box<DurableInputProjectionRedisclosureRequestV1>,
    },
}
impl From<StrictProjectionRedisclosureRequestV1> for ProjectionRedisclosureRequestV1 {
    fn from(value: StrictProjectionRedisclosureRequestV1) -> Self {
        match value {
            StrictProjectionRedisclosureRequestV1::Status {} => Self::Status,
            StrictProjectionRedisclosureRequestV1::Redisclose { request } => {
                Self::Redisclose { request }
            }
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum StrictProjectionRedisclosureResponseV1 {
    Current {
        binding: ProjectionRedisclosureChannelBindingV1,
    },
    Retained {
        original: Box<DurableInputProjectionOutboxV1>,
        delivery: Box<DurableInputProjectionDeliveryV1>,
    },
    Denied {},
}
impl From<StrictProjectionRedisclosureResponseV1> for ProjectionRedisclosureResponseV1 {
    fn from(value: StrictProjectionRedisclosureResponseV1) -> Self {
        match value {
            StrictProjectionRedisclosureResponseV1::Current { binding } => {
                Self::Current { binding }
            }
            StrictProjectionRedisclosureResponseV1::Retained { original, delivery } => {
                Self::Retained { original, delivery }
            }
            StrictProjectionRedisclosureResponseV1::Denied {} => Self::Denied,
        }
    }
}
/// The complete response must fit the UNCHANGED frame cap before native
/// approval and before commit. No higher limit or partial JSON fallback.
pub fn encode_redisclosure_response_v1(
    original: &DurableInputProjectionOutboxV1,
    delivery: &DurableInputProjectionDeliveryV1,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    delivery.require_original(original)?;
    let response = ProjectionRedisclosureResponseV1::Retained {
        original: Box::new(original.clone()),
        delivery: Box::new(delivery.clone()),
    };
    let bytes =
        zeroize::Zeroizing::new(serde_json::to_vec(&response).map_err(|_| Error::InvalidData)?);
    if bytes.len() >= MAX_INPUT_PROJECTION_FRAME_BYTES_V1 {
        return Err(Error::Limit);
    }
    Ok(bytes)
}
pub fn decode_redisclosure_response_v1(bytes: &[u8]) -> Result<ProjectionRedisclosureResponseV1> {
    if bytes.is_empty() || bytes.len() >= MAX_INPUT_PROJECTION_FRAME_BYTES_V1 {
        return Err(Error::Limit);
    }
    wholepact_core::parse_typed_json(bytes).map_err(|_| Error::InvalidData)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn original_scope() -> ProjectionPairScopeV1 {
        ProjectionPairScopeV1 {
            schema_version: 1,
            purpose: DurableInputProjectionPurposeV1::DurablePlainFixedInputProjectionV1,
            operation_id: "original-projection".into(),
            account_id: "a".repeat(64),
            agreement_id: "agreement".into(),
            obligation_id: "obligation".into(),
            participant_id: "participant".into(),
            intent_digest: "b".repeat(64),
        }
    }
    fn scope() -> ProjectionRedisclosurePairScopeV1 {
        ProjectionRedisclosurePairScopeV1 {
            schema_version: 1,
            operation_id: "new-delivery".into(),
            original_scope: original_scope(),
            original_request_digest: "c".repeat(64),
        }
    }
    #[test]
    fn redisclosure_scope_is_not_initial_scope_and_binds_both_operations() {
        let s = scope();
        let instance = "d".repeat(64);
        assert!(
            wholepact_core::parse_typed_json::<ProjectionPairScopeV1>(
                &serde_json::to_vec(&s).unwrap()
            )
            .is_err()
        );
        let digest = redisclosure_pairing_review_digest_v1(&s, &instance, 1).unwrap();
        assert_ne!(
            digest,
            projection_pairing_review_digest_v1(&s.original_scope, &instance, 1).unwrap()
        );
        for mutation in 0..3 {
            let mut changed = s.clone();
            match mutation {
                0 => changed.operation_id.push_str("-other"),
                1 => changed.original_scope.operation_id.push_str("-other"),
                _ => changed.original_request_digest = "e".repeat(64),
            }
            assert_ne!(
                digest,
                redisclosure_pairing_review_digest_v1(&changed, &instance, 1).unwrap()
            );
        }
        let mut same = s;
        same.operation_id = same.original_scope.operation_id.clone();
        assert!(same.validate().is_err());
    }
    #[test]
    fn initial_project_is_never_redisclosure_and_extra_fields_are_refused() {
        assert!(
            wholepact_core::parse_typed_json::<ProjectionRedisclosureRequestV1>(
                br#"{"operation":"project","request":{}}"#
            )
            .is_err()
        );
        assert!(
            wholepact_core::parse_typed_json::<ProjectionRedisclosureRequestV1>(
                br#"{"operation":"status","rescan":true}"#
            )
            .is_err()
        );
        assert!(
            decode_redisclosure_response_v1(&vec![b' '; MAX_INPUT_PROJECTION_FRAME_BYTES_V1])
                .is_err()
        );
    }

    #[test]
    fn empty_redisclosure_variants_preserve_wire_and_refuse_extra_fields() {
        let status = br#"{"operation":"status"}"#;
        let denied = br#"{"status":"denied"}"#;
        assert_eq!(
            serde_json::to_vec(&ProjectionRedisclosureRequestV1::Status).unwrap(),
            status
        );
        assert_eq!(
            serde_json::to_vec(&ProjectionRedisclosureResponseV1::Denied).unwrap(),
            denied
        );
        assert!(matches!(
            wholepact_core::parse_typed_json::<ProjectionRedisclosureRequestV1>(status),
            Ok(ProjectionRedisclosureRequestV1::Status)
        ));
        assert!(matches!(
            decode_redisclosure_response_v1(denied),
            Ok(ProjectionRedisclosureResponseV1::Denied)
        ));
        for field in ["request", "authorization_export", "rescan", "binding"] {
            let mut request = serde_json::json!({"operation":"status"});
            request[field] = true.into();
            assert!(
                wholepact_core::parse_typed_json::<ProjectionRedisclosureRequestV1>(
                    &serde_json::to_vec(&request).unwrap()
                )
                .is_err()
            );
            let mut response = serde_json::json!({"status":"denied"});
            response[field] = true.into();
            assert!(
                decode_redisclosure_response_v1(&serde_json::to_vec(&response).unwrap()).is_err()
            );
        }
    }
}
