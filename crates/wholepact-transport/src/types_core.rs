use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const SCHEMA_VERSION: u16 = 1;
pub const MAX_FILE_BYTES: usize = 1_048_576;
pub const MAX_PAYLOAD_BYTES: usize = 262_144;
pub const MAX_FIELDS: usize = 32;
pub const MAX_CIPHERTEXT_BYTES: usize = 400_000;
pub const MAX_MESSAGE_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
pub(crate) const SUITE: &str = "HPKE-Auth-X25519-HKDF-SHA256-ChaCha20Poly1305";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TransportError {
    #[error("unsupported encrypted file format, schema or algorithm")]
    UnsupportedVersion,
    #[error("malformed or noncanonical encrypted file")]
    Malformed,
    #[error("encrypted file resource limit exceeded")]
    ResourceLimit,
    #[error("authentication failed or the decryption key is incorrect")]
    Authentication,
    #[error("message recipient does not match the expected recipient")]
    WrongRecipient,
    #[error("message network profile does not match the expected profile")]
    WrongNetwork,
    #[error("message agreement, proposal, sender or artifact kind does not match")]
    WrongContext,
    #[error("message has expired or its validity period has not begun")]
    InvalidTime,
    #[error("export does not match the approved disclosure preview")]
    DisclosureDenied,
    #[error("authenticated message was already received")]
    Replay,
    #[error("authenticated message conflicts with a previously received message")]
    Equivocation,
    #[error("message sequence is out of order")]
    OutOfOrder,
    #[error("encrypted file or replay ledger I/O failed")]
    Storage,
    #[error(
        "the original encrypted import committed but its owner became unavailable; recover that original receipt"
    )]
    ImportCommittedButUnavailable,
    #[error("secure system randomness is unavailable")]
    Randomness,
    #[error("password must be 12 to 1024 bytes; use a strong unique passphrase")]
    WeakPassword,
    #[error("operation requires an independently verified authority or release adapter")]
    AuthorityUnavailable,
    #[error("domain import conflicts with an already recorded terminal outcome")]
    DomainConflict,
}
pub type Result<T> = std::result::Result<T, TransportError>;

/// Derived only from the mailbox constructor, never an external protection claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxProtection {
    CiphertextOnlyMetadataUnencrypted,
    Encrypted,
}

/// Canonical UTC timestamp, with whole-second precision, serialized as RFC 3339.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Timestamp(String);
impl Timestamp {
    pub fn from_unix_seconds(seconds: i64) -> Result<Self> {
        let value =
            DateTime::<Utc>::from_timestamp(seconds, 0).ok_or(TransportError::InvalidTime)?;
        Self::try_from(value.to_rfc3339_opts(SecondsFormat::Secs, true))
    }
    pub fn unix_seconds(&self) -> i64 {
        // Construction and deserialization both validate this invariant.
        DateTime::parse_from_rfc3339(&self.0)
            .map(|t| t.timestamp())
            .unwrap_or(0)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for Timestamp {
    type Error = TransportError;
    fn try_from(value: String) -> Result<Self> {
        if value.len() != 20 || !value.ends_with('Z') || value.as_bytes().get(17..19) == Some(b"60")
        {
            return Err(TransportError::Malformed);
        }
        let parsed = DateTime::parse_from_rfc3339(&value).map_err(|_| TransportError::Malformed)?;
        if parsed.timestamp() < 0 || parsed.to_rfc3339_opts(SecondsFormat::Secs, true) != value {
            return Err(TransportError::Malformed);
        }
        Ok(Self(value))
    }
}
impl From<Timestamp> for String {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Invitation,
    Proposal,
    Contribution,
    Authorization,
    ProvedProposal,
    FinalTransaction,
    SettlementEvidence,
    DeliveryAcknowledgment,
    ParticipationIntent,
    IntentWithdrawal,
    /// Dedicated native reservation-intent evidence; not final spending consent.
    OfflineReservationIntent,
    /// Dedicated witness admission evidence; never a generic authorization DTO.
    OfflineAuthorityAdmission,
    /// Non-authorizing terminal outcome for a never-emitted allocated sequence.
    OfflineAdmissionControl,
    /// Narrow witness projection; incompatible with the original broad descriptor.
    OfflineMinimalAuthorityAdmission,
    /// Dedicated native born witness origin; never a legacy OfflineV1 permit.
    BornOfflineMinimalAdmissionV1,
    /// Complete born request including native-authenticated constructor lineage.
    BornOfflineIntentV1,
    /// Actual retained Host constructor origin, not imported completion claims.
    BornOfflineCheckpointOriginV1,
    /// Exact offline-origin result; never an ordinary Authorization or permit.
    OfflineAuthorizationReturn,
    /// Exact native-born return, never interpreted as legacy offline authority.
    BornOfflineAuthorizationReturnV1,
    /// Signed named-verifier assertion only; never reservation or spending authority.
    NamedVerifierAssertion,
}
impl ArtifactKind {
    /// Wire-kind classification only; this never grants an export capability.
    pub fn requires_qualified_export(self) -> bool {
        matches!(
            self,
            Self::Authorization
                | Self::OfflineReservationIntent
                | Self::OfflineAuthorityAdmission
                | Self::OfflineAdmissionControl
                | Self::OfflineMinimalAuthorityAdmission
                | Self::BornOfflineMinimalAdmissionV1
                | Self::BornOfflineIntentV1
                | Self::BornOfflineCheckpointOriginV1
                | Self::OfflineAuthorizationReturn
                | Self::BornOfflineAuthorizationReturnV1
        )
    }
    /// Immutable-slot classification only, shared by typed outbox adapters.
    pub fn immutable_slot(self) -> bool {
        !matches!(
            self,
            Self::Invitation
                | Self::SettlementEvidence
                | Self::DeliveryAcknowledgment
                | Self::ParticipationIntent
                | Self::IntentWithdrawal
        )
    }
}

/// Identity labels are agreement-scoped identifiers, not verified human identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageContext {
    pub network_profile_id: String,
    pub agreement_id: String,
    pub proposal_id: String,
    pub proposal_revision: u64,
    pub sender_id: String,
    pub recipient_id: String,
    pub artifact_kind: ArtifactKind,
}
impl MessageContext {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.proposal_revision == 0 || self.proposal_revision > i64::MAX as u64 {
            return Err(TransportError::Malformed);
        }
        for value in [
            &self.network_profile_id,
            &self.agreement_id,
            &self.proposal_id,
            &self.sender_id,
            &self.recipient_id,
        ] {
            validate_id(value)?;
        }
        Ok(())
    }
    pub(crate) fn check_expected(&self, expected: &Self) -> Result<()> {
        expected.validate()?;
        if self.recipient_id != expected.recipient_id {
            return Err(TransportError::WrongRecipient);
        }
        if self.network_profile_id != expected.network_profile_id {
            return Err(TransportError::WrongNetwork);
        }
        if self != expected {
            return Err(TransportError::WrongContext);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageOrder {
    /// Exactly 32 lowercase hexadecimal characters, normally an unpredictable 128-bit ID.
    pub message_id: String,
    /// Starts at one and is strictly contiguous per profile/agreement/sender/recipient stream.
    pub sequence: u64,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
}
impl MessageOrder {
    pub(crate) fn validate(&self, now: &Timestamp) -> Result<()> {
        validate_hex(&self.message_id, 16)?;
        if self.sequence == 0 || self.sequence > i64::MAX as u64 {
            return Err(TransportError::Malformed);
        }
        let start = self.issued_at.unix_seconds();
        let end = self.expires_at.unix_seconds();
        if end <= start
            || end - start > MAX_MESSAGE_LIFETIME_SECONDS
            || now.unix_seconds() < start
            || now.unix_seconds() >= end
        {
            return Err(TransportError::InvalidTime);
        }
        Ok(())
    }
}

/// Ephemeral protocol identifier; this does not generate a credential or signer key.
pub fn random_message_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| TransportError::Randomness)?;
    Ok(hex::encode(bytes))
}

/// Exact selected bytes. This type deliberately has no Debug or Serialize implementation.
/// A trusted adapter must classify/redact complex payloads before constructing a field.
pub struct DisclosureField {
    pub(crate) name: String,
    pub(crate) bytes: Zeroizing<Vec<u8>>,
}
impl DisclosureField {
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        let name = name.into();
        validate_id(&name)?;
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(TransportError::ResourceLimit);
        }
        Ok(Self { name, bytes })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldPreview {
    pub name: String,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePreview {
    pub schema_version: u16,
    pub context: MessageContext,
    pub order: MessageOrder,
    pub sender_key_fingerprint: String,
    pub recipient_key_fingerprint: String,
    pub purpose: String,
    pub persistence_warning: String,
    pub fields: Vec<FieldPreview>,
    pub payload_digest: String,
}
impl DisclosurePreview {
    /// Exact approval token. The application must authenticate the user's decision;
    /// possessing or computing this digest alone is not evidence of consent.
    pub fn digest(&self) -> Result<String> {
        Ok(digest(b"wholepact.disclosure-preview.v1\0", &encode(self)?))
    }
}

pub(crate) fn validate_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
    {
        return Err(TransportError::Malformed);
    }
    Ok(())
}
pub(crate) fn validate_text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(TransportError::Malformed);
    }
    Ok(())
}
pub(crate) fn validate_hex(value: &str, bytes: usize) -> Result<()> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(TransportError::Malformed);
    }
    Ok(())
}
pub(crate) fn digest(domain: &[u8], value: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(value);
    hex::encode(hash.finalize())
}
pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| TransportError::Malformed)
}
pub(crate) fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(TransportError::ResourceLimit);
    }
    wholepact_core::parse_typed_json(bytes).map_err(|error| match error.code {
        wholepact_core::ErrorCode::ResourceLimit => TransportError::ResourceLimit,
        _ => TransportError::Malformed,
    })
}
pub(crate) fn b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}
pub(crate) fn unb64(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.len() > maximum.div_ceil(3) * 4 {
        return Err(TransportError::ResourceLimit);
    }
    // Decode into owned zeroizing storage so partially decoded bytes are also
    // wiped when invalid base64 or an over-limit result causes an early return.
    let mut bytes = Zeroizing::new(vec![0u8; value.len().div_ceil(4) * 3]);
    let length = STANDARD_NO_PAD
        .decode_slice(value, &mut bytes)
        .map_err(|_| TransportError::Malformed)?;
    if length > maximum {
        return Err(TransportError::ResourceLimit);
    }
    bytes.truncate(length);
    let canonical = Zeroizing::new(b64(&bytes));
    if canonical.as_str() != value {
        return Err(TransportError::Malformed);
    }
    Ok(std::mem::take(&mut *bytes))
}
