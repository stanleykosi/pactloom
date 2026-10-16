//! Inert, exact-purpose retirement disclosure wire. Parsing is not ownership,
//! recovery completeness, permission to transfer, or proof of current authority.
use crate::{Error, PairScope, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::io::Write;
use zeroize::Zeroizing;

/// Complete JSON frame cap, including its single terminal newline.
pub const FRAME_LIMIT: usize = 8192;
pub const PURPOSE: &str = "retirement_destination_observation";
pub const NETWORK_PROFILE_ID: &str = "ironwood-testnet-nu7-candidate";
pub const PAIR_AGREEMENT_ID: &str = "retirement-destination-evidence-v1";
pub const PAIR_PARTICIPANT_ID: &str = "retirement-evidence-recipient-v1";
const REQUEST_DOMAIN: &str = "wholepact:retirement-destination-evidence-request:v1";
const ADDRESS_LIMIT: usize = 1024;

/// Shared source activation boundary for the installed client and native entry.
/// Connected source branches are not attended-native or kernel qualification.
/// No feature, environment value, DTO or caller approval bypasses this gate.
pub fn require_native_transport_activation_v1() -> Result<()> {
    Err(Error::RetirementEvidenceUnavailable)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementDestinationEvidenceRequestV1 {
    #[serde(deserialize_with = "version_v1")]
    pub schema_version: u16,
    #[serde(deserialize_with = "purpose_v1")]
    pub purpose: String,
    #[serde(deserialize_with = "identifier")]
    pub operation_id: String,
    #[serde(deserialize_with = "hash_string")]
    pub request_nonce: String,
    #[serde(deserialize_with = "identifier")]
    pub source_account_id: String,
    #[serde(deserialize_with = "network_v1")]
    pub network_profile_id: String,
    #[serde(deserialize_with = "address_string")]
    pub address: String,
}
impl RetirementDestinationEvidenceRequestV1 {
    pub fn validate(&self) -> Result<()> {
        validate_header(
            self.schema_version,
            &self.purpose,
            &self.operation_id,
            &self.request_nonce,
        )?;
        validate_identifier(&self.source_account_id)?;
        validate_network(&self.network_profile_id)?;
        validate_address(&self.address)
    }
    /// All request fields, including version, purpose and nonce, are committed.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        crate::digest(REQUEST_DOMAIN, self)
    }
    /// The reserved labels identify an informational request. They do not name
    /// an actual agreement or confer any of the other pairing capabilities.
    pub fn pair_scope(&self) -> Result<PairScope> {
        Ok(PairScope {
            account_id: self.source_account_id.clone(),
            agreement_id: PAIR_AGREEMENT_ID.into(),
            participant_id: PAIR_PARTICIPANT_ID.into(),
            manifest_digest: self.digest()?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        })
    }
    pub fn require_pair_scope(&self, scope: &PairScope) -> Result<()> {
        scope.validate()?;
        if *scope != self.pair_scope()? {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementEvidencePoolV1 {
    Ironwood,
}
impl<'de> Deserialize<'de> for RetirementEvidencePoolV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        // Unit enums otherwise accept an alternate object/null representation.
        // V1 has only the exact string; no empty object can hide extra fields.
        let value = String::deserialize(deserializer)?;
        if value != "ironwood" {
            return Err(serde::de::Error::custom("unsupported retirement pool"));
        }
        Ok(Self::Ironwood)
    }
}

/// Publicly constructible informational wire data. Native-derived fields must
/// be populated by the signer while both original native owners remain held.
/// No DTO or response can reconstruct either of those live owners.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetirementDestinationEvidenceResponseV1 {
    Observed {
        #[serde(deserialize_with = "version_v1")]
        schema_version: u16,
        #[serde(deserialize_with = "purpose_v1")]
        purpose: String,
        #[serde(deserialize_with = "identifier")]
        operation_id: String,
        #[serde(deserialize_with = "hash_string")]
        request_nonce: String,
        #[serde(deserialize_with = "hash_string")]
        request_digest: String,
        #[serde(deserialize_with = "identifier")]
        source_account_id: String,
        #[serde(deserialize_with = "identifier")]
        destination_account_id: String,
        #[serde(deserialize_with = "address_string")]
        address: String,
        #[serde(deserialize_with = "network_v1")]
        network_profile_id: String,
        pool: RetirementEvidencePoolV1,
        #[serde(deserialize_with = "hash_string")]
        source_review_ref: String,
        #[serde(deserialize_with = "hash_string")]
        destination_review_ref: String,
        #[serde(deserialize_with = "hash_string")]
        recipient_grant_id: String,
    },
    Denied {
        #[serde(deserialize_with = "version_v1")]
        schema_version: u16,
        #[serde(deserialize_with = "purpose_v1")]
        purpose: String,
        #[serde(deserialize_with = "identifier")]
        operation_id: String,
        #[serde(deserialize_with = "hash_string")]
        request_nonce: String,
        #[serde(deserialize_with = "hash_string")]
        request_digest: String,
    },
}
impl RetirementDestinationEvidenceResponseV1 {
    pub fn validate(&self) -> Result<()> {
        let (version, purpose, operation, nonce, digest) = self.header();
        validate_header(version, purpose, operation, nonce)?;
        crate::hash(digest)?;
        if let Self::Observed {
            source_account_id,
            destination_account_id,
            address,
            network_profile_id,
            source_review_ref,
            destination_review_ref,
            recipient_grant_id,
            ..
        } = self
        {
            validate_identifier(source_account_id)?;
            validate_identifier(destination_account_id)?;
            if source_account_id == destination_account_id {
                return Err(Error::Binding);
            }
            validate_address(address)?;
            validate_network(network_profile_id)?;
            for value in [
                source_review_ref,
                destination_review_ref,
                recipient_grant_id,
            ] {
                crate::hash(value)?;
            }
        }
        Ok(())
    }
    /// Correlation only. Success does not assert current native ownership,
    /// sender post-write completion, recipient receipt, or recovery readiness.
    pub fn require_request_binding(
        &self,
        request: &RetirementDestinationEvidenceRequestV1,
        grant_id: &str,
    ) -> Result<()> {
        self.validate()?;
        request.validate()?;
        crate::hash(grant_id)?;
        let (_, _, operation, nonce, digest) = self.header();
        if operation != request.operation_id
            || nonce != request.request_nonce
            || digest != request.digest()?
        {
            return Err(Error::Binding);
        }
        match self {
            Self::Observed {
                source_account_id,
                address,
                network_profile_id,
                recipient_grant_id,
                pool: RetirementEvidencePoolV1::Ironwood,
                ..
            } if source_account_id == &request.source_account_id
                && address == &request.address
                && network_profile_id == &request.network_profile_id
                && recipient_grant_id == grant_id =>
            {
                Ok(())
            }
            Self::Denied { .. } => Err(Error::Permission),
            _ => Err(Error::Binding),
        }
    }
    fn header(&self) -> (u16, &str, &str, &str, &str) {
        match self {
            Self::Observed {
                schema_version,
                purpose,
                operation_id,
                request_nonce,
                request_digest,
                ..
            }
            | Self::Denied {
                schema_version,
                purpose,
                operation_id,
                request_nonce,
                request_digest,
            } => (
                *schema_version,
                purpose,
                operation_id,
                request_nonce,
                request_digest,
            ),
        }
    }
}

pub fn encode_request_frame(
    request: &RetirementDestinationEvidenceRequestV1,
) -> Result<Zeroizing<Vec<u8>>> {
    request.validate()?;
    encode_bounded_frame(request)
}
pub fn encode_response_frame(
    response: &RetirementDestinationEvidenceResponseV1,
) -> Result<Zeroizing<Vec<u8>>> {
    response.validate()?;
    encode_bounded_frame(response)
}
/// Accept exactly the delimiter-free body returned by the capped frame reader.
/// The omitted newline still counts against FRAME_LIMIT. No extension/fallback.
pub fn decode_request(body: &[u8]) -> Result<RetirementDestinationEvidenceRequestV1> {
    check_body(body)?;
    let request: RetirementDestinationEvidenceRequestV1 =
        serde_json::from_slice(body).map_err(|_| Error::InvalidData)?;
    request.validate()?;
    Ok(request)
}
pub fn decode_response(body: &[u8]) -> Result<RetirementDestinationEvidenceResponseV1> {
    check_body(body)?;
    let response: RetirementDestinationEvidenceResponseV1 =
        serde_json::from_slice(body).map_err(|_| Error::InvalidData)?;
    response.validate()?;
    Ok(response)
}
fn check_body(body: &[u8]) -> Result<()> {
    if body.is_empty() || body.len() >= FRAME_LIMIT {
        return Err(Error::Limit);
    }
    if body.contains(&b'\n') || body.contains(&b'\r') {
        return Err(Error::InvalidData);
    }
    Ok(())
}
/// Fixed-allocation serialization, also used by the private credential envelope.
/// Rejects growth before writing, and erases the backing allocation on drop.
pub(crate) fn encode_bounded_frame<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    struct Writer(Zeroizing<Vec<u8>>);
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .0
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n >= FRAME_LIMIT)
            {
                return Err(std::io::Error::other("retirement frame exceeds bound"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(FRAME_LIMIT)
        .map_err(|_| Error::Limit)?;
    let mut writer = Writer(bytes);
    serde_json::to_writer(&mut writer, value).map_err(|_| Error::Limit)?;
    writer.0.push(b'\n');
    Ok(writer.0)
}
fn validate_header(version: u16, purpose: &str, operation: &str, nonce: &str) -> Result<()> {
    if version != 1 || purpose != PURPOSE {
        return Err(Error::InvalidData);
    }
    validate_identifier(operation)?;
    crate::hash(nonce)
}
fn validate_identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(Error::Binding);
    }
    Ok(())
}
fn validate_network(value: &str) -> Result<()> {
    if value != NETWORK_PROFILE_ID {
        return Err(Error::Binding);
    }
    Ok(())
}
fn validate_address(value: &str) -> Result<()> {
    // Syntax/bounds only. Actual decoding and vault membership belong solely to
    // the maintained native adapter; this prefix is not an ownership check.
    if value.len() <= "utest1".len()
        || value.len() > ADDRESS_LIMIT
        || !value.starts_with("utest1")
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(Error::Binding);
    }
    Ok(())
}
fn version_v1<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<u16, D::Error> {
    let value = u16::deserialize(deserializer)?;
    if value != 1 {
        return Err(serde::de::Error::custom("unsupported retirement version"));
    }
    Ok(value)
}
fn read_checked<'de, D: Deserializer<'de>>(
    deserializer: D,
    check: fn(&str) -> Result<()>,
) -> std::result::Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    check(&value).map_err(|_| serde::de::Error::custom("invalid retirement field"))?;
    Ok(value)
}
fn purpose_v1<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<String, D::Error> {
    read_checked(deserializer, |value| {
        if value == PURPOSE {
            Ok(())
        } else {
            Err(Error::Binding)
        }
    })
}
fn identifier<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<String, D::Error> {
    read_checked(deserializer, validate_identifier)
}
fn hash_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    read_checked(deserializer, crate::hash)
}
fn network_v1<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<String, D::Error> {
    read_checked(deserializer, validate_network)
}
fn address_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    read_checked(deserializer, validate_address)
}

#[cfg(test)]
pub(crate) mod tests {
    #[test]
    fn retirement_native_and_client_share_unavailable_activation_boundary() {
        assert!(matches!(
            super::require_native_transport_activation_v1(),
            Err(crate::Error::RetirementEvidenceUnavailable)
        ));
    }
    use super::*;
    pub(crate) fn request() -> RetirementDestinationEvidenceRequestV1 {
        RetirementDestinationEvidenceRequestV1 {
            schema_version: 1,
            purpose: PURPOSE.into(),
            operation_id: "synthetic-retirement-observation".into(),
            request_nonce: "a".repeat(64),
            source_account_id: "synthetic-source".into(),
            network_profile_id: NETWORK_PROFILE_ID.into(),
            address: "utest1syntheticaddressonly".into(),
        }
    }
    pub(crate) fn response(
        request: &RetirementDestinationEvidenceRequestV1,
    ) -> RetirementDestinationEvidenceResponseV1 {
        RetirementDestinationEvidenceResponseV1::Observed {
            schema_version: 1,
            purpose: PURPOSE.into(),
            operation_id: request.operation_id.clone(),
            request_nonce: request.request_nonce.clone(),
            request_digest: request.digest().unwrap(),
            source_account_id: request.source_account_id.clone(),
            destination_account_id: "synthetic-destination".into(),
            address: request.address.clone(),
            network_profile_id: request.network_profile_id.clone(),
            pool: RetirementEvidencePoolV1::Ironwood,
            source_review_ref: "b".repeat(64),
            destination_review_ref: "c".repeat(64),
            recipient_grant_id: "d".repeat(64),
        }
    }
    #[test]
    fn retirement_wire_rejects_unknown_and_authority_fields() {
        let original = serde_json::to_value(request()).unwrap();
        for field in [
            "destination_account_id",
            "ownership_source_ref",
            "local_recipient",
            "source_fvk_digest",
            "approved",
            "vault_path",
            "deadline",
            "amount",
        ] {
            let mut wire = original.clone();
            wire[field] = serde_json::json!(true);
            assert!(decode_request(&serde_json::to_vec(&wire).unwrap()).is_err());
        }
        for (field, value) in [
            ("schema_version", serde_json::json!(2)),
            ("purpose", serde_json::json!("status")),
            ("network_profile_id", serde_json::json!("mainnet")),
            ("request_nonce", serde_json::json!("A".repeat(64))),
            ("operation_id", serde_json::json!("a".repeat(129))),
            (
                "address",
                serde_json::json!("utest1".to_owned() + &"a".repeat(1024)),
            ),
        ] {
            let mut wire = original.clone();
            wire[field] = value;
            assert!(decode_request(&serde_json::to_vec(&wire).unwrap()).is_err());
        }
    }
    #[test]
    fn retirement_scope_commits_every_request_field_and_no_capability_flags() {
        let request = request();
        let scope = request.pair_scope().unwrap();
        assert!(request.require_pair_scope(&scope).is_ok());
        assert_eq!(scope.agreement_id, PAIR_AGREEMENT_ID);
        assert_eq!(scope.participant_id, PAIR_PARTICIPANT_ID);
        for field in 0..7 {
            let mut changed = scope.clone();
            match field {
                0 => changed.account_id.push('x'),
                1 => changed.agreement_id.push('x'),
                2 => changed.participant_id.push('x'),
                3 => changed.manifest_digest = "e".repeat(64),
                4 => changed.history_read = true,
                5 => changed.authorization_export = true,
                _ => changed.preconstruction_export = true,
            }
            assert!(request.require_pair_scope(&changed).is_err());
        }
        for field in 0..4 {
            let mut changed = request.clone();
            match field {
                0 => changed.operation_id.push('x'),
                1 => changed.request_nonce = "f".repeat(64),
                2 => changed.source_account_id.push('x'),
                _ => changed.address.push('x'),
            }
            assert_ne!(changed.digest().unwrap(), request.digest().unwrap());
        }
        assert_ne!(
            crate::digest("wholepact:other:v1", &request).unwrap(),
            request.digest().unwrap()
        );
    }
    #[test]
    fn retirement_response_requires_exact_binding_and_informational_pool() {
        let request = request();
        let response = response(&request);
        assert!(
            response
                .require_request_binding(&request, &"d".repeat(64))
                .is_ok()
        );
        let original = serde_json::to_value(&response).unwrap();
        for (field, value) in [
            ("operation_id", "other".into()),
            ("request_nonce", "e".repeat(64)),
            ("request_digest", "f".repeat(64)),
            ("source_account_id", "other".into()),
            ("address", "utest1other".into()),
            ("recipient_grant_id", "e".repeat(64)),
            ("destination_account_id", request.source_account_id.clone()),
        ] {
            let mut wire = original.clone();
            wire[field] = serde_json::Value::String(value);
            let decoded = decode_response(&serde_json::to_vec(&wire).unwrap());
            assert!(
                decoded.is_err()
                    || decoded
                        .unwrap()
                        .require_request_binding(&request, &"d".repeat(64))
                        .is_err()
            );
        }
        for (field, value) in [
            ("pool", serde_json::json!({"ironwood": null})),
            ("pool", serde_json::json!({"ironwood": {"approved": true}})),
            ("pool", serde_json::json!("orchard")),
            ("network_profile_id", serde_json::json!("mainnet")),
            ("verified", serde_json::json!(true)),
        ] {
            let mut wire = original.clone();
            wire[field] = value;
            assert!(decode_response(&serde_json::to_vec(&wire).unwrap()).is_err());
        }
    }
    #[test]
    fn retirement_denied_variant_rejects_unknown_fields_and_cannot_observe() {
        let request = request();
        let denied = RetirementDestinationEvidenceResponseV1::Denied {
            schema_version: 1,
            purpose: PURPOSE.into(),
            operation_id: request.operation_id.clone(),
            request_nonce: request.request_nonce.clone(),
            request_digest: request.digest().unwrap(),
        };
        let mut wire = serde_json::to_value(&denied).unwrap();
        assert!(matches!(
            denied.require_request_binding(&request, &"d".repeat(64)),
            Err(Error::Permission)
        ));
        wire["approved"] = serde_json::json!(true);
        assert!(decode_response(&serde_json::to_vec(&wire).unwrap()).is_err());
        for naked in [
            br#"{"status":"denied"}"#.as_slice(),
            br#"{"status":"denied","approved":true}"#.as_slice(),
            br#"{"status":"observed"}"#.as_slice(),
            br#"{"status":"observed","approved":true}"#.as_slice(),
        ] {
            assert!(decode_response(naked).is_err());
        }
    }
    #[test]
    fn retirement_frame_bound_counts_newline_and_rejects_extra_frames() {
        let request = request();
        let encoded = encode_request_frame(&request).unwrap();
        assert_eq!(encoded.last(), Some(&b'\n'));
        assert!(encoded.len() <= FRAME_LIMIT);
        assert!(decode_request(&encoded[..encoded.len() - 1]).is_ok());
        assert!(decode_request(&encoded).is_err());
        assert!(decode_request(&vec![b' '; FRAME_LIMIT]).is_err());
        let exact = encode_bounded_frame(&"x".repeat(FRAME_LIMIT - 3)).unwrap();
        assert_eq!(exact.len(), FRAME_LIMIT);
        assert!(encode_bounded_frame(&"x".repeat(FRAME_LIMIT - 2)).is_err());
        let response = encode_response_frame(&response(&request)).unwrap();
        assert!(decode_response(&response[..response.len() - 1]).is_ok());
        for end in [0, 1, response.len() / 2, response.len() - 2] {
            assert!(decode_response(&response[..end]).is_err());
        }
        let mut duplicated = response.to_vec();
        duplicated.extend_from_slice(&response);
        assert!(decode_response(&duplicated).is_err());
    }
}
