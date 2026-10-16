use crate::{AuthenticatedReceipt, ReplayLedger, RetainedEnvelope, types::*};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

type Kem = X25519HkdfSha256;
const INFO: &[u8] = b"wholepact.recipient-artifact.hpke-auth.v1";

/// Supplied by an external, protected identity store. No key generation, persistence,
/// Debug, Clone, or serialization API is provided for long-lived credentials.
pub struct TransportSecret(Zeroizing<[u8; 32]>);
impl TransportSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            return Err(TransportError::Malformed);
        }
        <Kem as KemTrait>::PrivateKey::from_bytes(&bytes).map_err(|_| TransportError::Malformed)?;
        Ok(Self(Zeroizing::new(bytes)))
    }
    fn private_key(&self) -> Result<<Kem as KemTrait>::PrivateKey> {
        <Kem as KemTrait>::PrivateKey::from_bytes(self.0.as_ref())
            .map_err(|_| TransportError::Malformed)
    }
    pub fn public_key(&self) -> Result<TransportPublicKey> {
        let key = Kem::sk_to_pk(&self.private_key()?);
        let bytes: [u8; 32] = key
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| TransportError::Malformed)?;
        TransportPublicKey::from_bytes(bytes)
    }
}

/// A key must be pinned to the named agreement-scoped identity over an independently
/// authenticated channel. A key received inside an artifact cannot establish trust.
#[derive(Clone, PartialEq, Eq)]
pub struct TransportPublicKey([u8; 32]);
impl TransportPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            return Err(TransportError::Malformed);
        }
        <Kem as KemTrait>::PublicKey::from_bytes(&bytes).map_err(|_| TransportError::Malformed)?;
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn fingerprint(&self) -> String {
        digest(b"wholepact.transport-key.v1\0", &self.0)
    }
    fn key(&self) -> Result<<Kem as KemTrait>::PublicKey> {
        <Kem as KemTrait>::PublicKey::from_bytes(&self.0).map_err(|_| TransportError::Malformed)
    }
}

/// Plaintext review metadata. The caller must present the actual selected fields,
/// destination key, purpose and persistence warning in its trusted consent UI.
pub struct ExportRequest {
    pub context: MessageContext,
    pub order: MessageOrder,
    pub purpose: String,
    pub persistence_warning: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireField {
    name: String,
    data: String,
}
impl Drop for WireField {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedMessage {
    preview: DisclosurePreview,
    approved_preview_digest: String,
    fields: Vec<WireField>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope {
    schema_version: u16,
    suite: String,
    encapsulated_key: String,
    ciphertext: String,
}
#[derive(Serialize)]
struct EnvelopeAad<'a> {
    schema_version: u16,
    suite: &'a str,
    encapsulated_key: &'a str,
}
impl WireEnvelope {
    fn aad(&self) -> Result<Vec<u8>> {
        encode(&EnvelopeAad {
            schema_version: self.schema_version,
            suite: &self.suite,
            encapsulated_key: &self.encapsulated_key,
        })
    }
    fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION || self.suite != SUITE {
            return Err(TransportError::UnsupportedVersion);
        }
        validate_hex(&self.encapsulated_key, 32)?;
        if self.ciphertext.len() > MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4 {
            return Err(TransportError::ResourceLimit);
        }
        Ok(())
    }
}

/// Immutable local preparation, not an exported file. Does not implement Debug.
pub struct PreparedExport {
    preview: DisclosurePreview,
    fields: Vec<DisclosureField>,
    recipient: TransportPublicKey,
}
impl PreparedExport {
    pub fn preview(&self) -> &DisclosurePreview {
        &self.preview
    }
    pub fn fields(&self) -> &[DisclosureField] {
        &self.fields
    }
    /// The approved digest must come from the application's authenticated consent
    /// boundary. This checks binding, not whether a human genuinely approved it.
    pub fn seal(
        self,
        sender: &TransportSecret,
        approved_preview_digest: &str,
        now: &Timestamp,
    ) -> Result<EncryptedEnvelope> {
        reject_unqualified_offline_seal(self.preview.context.artifact_kind)?;
        self.seal_qualified(sender, approved_preview_digest, now)
    }

    // Only in-crate guarded outbox adapters may seal an offline artifact. Public
    // raw PreparedExport values and computed preview digests cannot mint authority.
    // Existing unrelated Authorization semantics are deliberately unchanged.
    pub(crate) fn seal_qualified(
        self,
        sender: &TransportSecret,
        approved_preview_digest: &str,
        now: &Timestamp,
    ) -> Result<EncryptedEnvelope> {
        self.preview.order.validate(now)?;
        if self.preview.digest()? != approved_preview_digest
            || sender.public_key()?.fingerprint() != self.preview.sender_key_fingerprint
        {
            return Err(TransportError::DisclosureDenied);
        }
        let wire = ProtectedMessage {
            preview: self.preview,
            approved_preview_digest: approved_preview_digest.into(),
            fields: encode_fields(&self.fields),
        };
        let plaintext = Zeroizing::new(encode(&wire)?);
        if plaintext.len() + 16 > MAX_CIPHERTEXT_BYTES {
            return Err(TransportError::ResourceLimit);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| TransportError::Randomness)?;
        let mut rng = rand::rngs::StdRng::from_seed(*seed);
        let secret = sender.private_key()?;
        let mode = OpModeS::Auth((secret.clone(), Kem::sk_to_pk(&secret)));
        let (encapped, mut context) = hpke::setup_sender_with_rng::<
            ChaCha20Poly1305,
            HkdfSha256,
            Kem,
        >(&mode, &self.recipient.key()?, INFO, &mut rng)
        .map_err(|_| TransportError::Authentication)?;
        let mut envelope = WireEnvelope {
            schema_version: SCHEMA_VERSION,
            suite: SUITE.into(),
            encapsulated_key: hex::encode(encapped.to_bytes()),
            ciphertext: String::new(),
        };
        envelope.ciphertext = b64(&context
            .seal(&plaintext, &envelope.aad()?)
            .map_err(|_| TransportError::Authentication)?);
        Ok(EncryptedEnvelope(encode(&envelope)?))
    }
}

fn reject_unqualified_offline_seal(kind: ArtifactKind) -> Result<()> {
    if matches!(
        kind,
        ArtifactKind::OfflineReservationIntent
            | ArtifactKind::OfflineAuthorityAdmission
            | ArtifactKind::OfflineAdmissionControl
            | ArtifactKind::OfflineMinimalAuthorityAdmission
            | ArtifactKind::OfflineAuthorizationReturn
    ) {
        return Err(TransportError::AuthorityUnavailable);
    }
    Ok(())
}

/// Prepares an exact, recipient-specific field selection. Opaque PCZT fields are
/// whole blobs: this function does not inspect, label or redact their internals.
pub fn prepare_export(
    request: ExportRequest,
    mut fields: Vec<DisclosureField>,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedExport> {
    request.context.validate()?;
    request.order.validate(now)?;
    validate_text(&request.purpose)?;
    validate_text(&request.persistence_warning)?;
    fields.sort_by(|a, b| a.name.cmp(&b.name));
    validate_fields(&fields)?;
    let preview = DisclosurePreview {
        schema_version: SCHEMA_VERSION,
        context: request.context,
        order: request.order,
        sender_key_fingerprint: sender.fingerprint(),
        recipient_key_fingerprint: recipient.fingerprint(),
        purpose: request.purpose,
        persistence_warning: request.persistence_warning,
        fields: field_previews(&fields),
        payload_digest: payload_digest(&fields)?,
    };
    Ok(PreparedExport {
        preview,
        fields,
        recipient: recipient.clone(),
    })
}

/// Untrusted encrypted bytes until open_envelope authenticates them. No ordinary
/// logging implementation is supplied, even though these bytes are encrypted.
pub struct EncryptedEnvelope(Vec<u8>);
impl EncryptedEnvelope {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let parsed: WireEnvelope = parse(&bytes)?;
        parsed.validate()?;
        Ok(Self(bytes))
    }
    pub fn read_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_bytes(read_bounded(path.as_ref())?)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Never overwrites a file; uses private mode on Unix and fsyncs file contents.
    /// The caller owns secure directory selection and durable directory syncing.
    pub fn write_new_file(&self, path: impl AsRef<Path>) -> Result<()> {
        write_new(path.as_ref(), &self.0)
    }
}

/// Authenticated transport content, never trusted transaction effects or approval.
/// Plaintext is deliberately not Debug/Serialize. Owned byte buffers are wiped on
/// normal drop; parser/allocator/OS copies and abnormal termination are not covered.
pub struct ReceivedArtifact {
    preview: DisclosurePreview,
    fields: Vec<DisclosureField>,
    stream_digest: String,
    content_digest: String,
    envelope_digest: String,
}
impl ReceivedArtifact {
    /// Authenticated semantic identity, safe for an adapter’s durable idempotency key.
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
    pub fn stream_digest(&self) -> &str {
        &self.stream_digest
    }
    pub fn preview(&self) -> &DisclosurePreview {
        &self.preview
    }
    pub fn fields(&self) -> &[DisclosureField] {
        &self.fields
    }
}

/// Checks cryptographic sender authentication, recipient, exact expected context,
/// time, full preview binding, payload digest and durable replay state, in that order.
/// The replay ledger is committed before plaintext is returned. Invalid messages
/// never consume sequence state. Importing this crate starts no network activity.
pub fn open_envelope(
    envelope: &EncryptedEnvelope,
    recipient: &TransportSecret,
    expected_sender: &TransportPublicKey,
    expected: &MessageContext,
    now: &Timestamp,
    ledger: &mut impl ReplayLedger,
) -> Result<ReceivedArtifact> {
    reject_generic_control(expected)?;
    let (artifact, receipt) =
        authenticate(envelope, recipient, expected_sender, expected, Some(now))?;
    ledger.accept_authenticated(&receipt, &envelope.0)?;
    Ok(artifact)
}

/// Domain validation runs after authentication and before durable inbox mutation.
#[allow(clippy::too_many_arguments)]
pub fn open_envelope_checked(
    envelope: &EncryptedEnvelope,
    recipient: &TransportSecret,
    expected_sender: &TransportPublicKey,
    expected: &MessageContext,
    now: &Timestamp,
    ledger: &mut impl ReplayLedger,
    validate: impl FnOnce(&ReceivedArtifact) -> Result<()>,
) -> Result<ReceivedArtifact> {
    reject_generic_control(expected)?;
    let (artifact, receipt) =
        authenticate(envelope, recipient, expected_sender, expected, Some(now))?;
    validate(&artifact)?;
    ledger.accept_authenticated(&receipt, &envelope.0)?;
    Ok(artifact)
}

// Control replay may only advance together with its typed terminal outcome.
// Runs before decryption, caller validation callbacks and any ledger access.
fn reject_generic_control(expected: &MessageContext) -> Result<()> {
    if matches!(
        expected.artifact_kind,
        ArtifactKind::OfflineAdmissionControl
            | ArtifactKind::OfflineMinimalAuthorityAdmission
            | ArtifactKind::OfflineAuthorizationReturn
    ) {
        return Err(TransportError::AuthorityUnavailable);
    }
    Ok(())
}

/// Explicit historical recovery. Does not create a delivery or replay opportunity,
/// and cannot establish current validity, consent freshness or writer authority.
pub struct RecoveredArtifact {
    artifact: ReceivedArtifact,
}
impl RecoveredArtifact {
    pub fn into_artifact(self) -> ReceivedArtifact {
        self.artifact
    }
    pub fn artifact(&self) -> &ReceivedArtifact {
        &self.artifact
    }
    pub fn is_new_delivery(&self) -> bool {
        false
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
    pub fn is_currently_valid(&self, now: &Timestamp) -> bool {
        self.artifact.preview.order.validate(now).is_ok()
    }
}

/// Opens only ciphertext backed by an existing inbox receipt. Expired messages may
/// be recovered for history/reconciliation, explicitly without current authority.
/// Applications must separately make domain processing idempotent.
pub fn recover_received(
    record: &RetainedEnvelope,
    recipient: &TransportSecret,
    expected_sender: &TransportPublicKey,
    expected: &MessageContext,
) -> Result<RecoveredArtifact> {
    if expected.artifact_kind == ArtifactKind::OfflineAuthorizationReturn {
        return Err(TransportError::AuthorityUnavailable);
    }
    let (artifact, receipt) =
        authenticate(&record.envelope, recipient, expected_sender, expected, None)?;
    if !record.matches(&receipt) {
        return Err(TransportError::Authentication);
    }
    Ok(RecoveredArtifact { artifact })
}

pub(crate) fn authenticate(
    envelope: &EncryptedEnvelope,
    recipient: &TransportSecret,
    expected_sender: &TransportPublicKey,
    expected: &MessageContext,
    now: Option<&Timestamp>,
) -> Result<(ReceivedArtifact, AuthenticatedReceipt)> {
    expected.validate()?;
    let wire: WireEnvelope = parse(&envelope.0)?;
    wire.validate()?;
    let encapsulated = <Kem as KemTrait>::EncappedKey::from_bytes(
        &hex::decode(&wire.encapsulated_key).map_err(|_| TransportError::Malformed)?,
    )
    .map_err(|_| TransportError::Malformed)?;
    let ciphertext = unb64(&wire.ciphertext, MAX_CIPHERTEXT_BYTES)?;
    let mut context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Auth(expected_sender.key()?),
        &recipient.private_key()?,
        &encapsulated,
        INFO,
    )
    .map_err(|_| TransportError::Authentication)?;
    let plaintext = Zeroizing::new(
        context
            .open(&ciphertext, &wire.aad()?)
            .map_err(|_| TransportError::Authentication)?,
    );
    let protected: ProtectedMessage = parse(&plaintext)?;
    // Replay identity covers the complete authenticated semantic message, so
    // harmless JSON whitespace/key-order changes do not become equivocation.
    let canonical_plaintext = Zeroizing::new(encode(&protected)?);
    let preview = protected.preview;
    if preview.schema_version != SCHEMA_VERSION {
        return Err(TransportError::UnsupportedVersion);
    }
    preview.context.validate()?;
    preview.context.check_expected(expected)?;
    preview
        .order
        .validate(now.unwrap_or(&preview.order.issued_at))?;
    validate_text(&preview.purpose)?;
    validate_text(&preview.persistence_warning)?;
    if preview.sender_key_fingerprint != expected_sender.fingerprint() {
        return Err(TransportError::WrongContext);
    }
    if preview.recipient_key_fingerprint != recipient.public_key()?.fingerprint() {
        return Err(TransportError::WrongRecipient);
    }
    if protected.fields.len() > MAX_FIELDS {
        return Err(TransportError::ResourceLimit);
    }
    let fields = protected
        .fields
        .into_iter()
        .map(|field| {
            DisclosureField::new(field.name.clone(), unb64(&field.data, MAX_PAYLOAD_BYTES)?)
        })
        .collect::<Result<Vec<_>>>()?;
    validate_fields(&fields)?;
    if field_previews(&fields) != preview.fields
        || payload_digest(&fields)? != preview.payload_digest
        || preview.digest()? != protected.approved_preview_digest
    {
        return Err(TransportError::DisclosureDenied);
    }
    let receipt = AuthenticatedReceipt::new(&preview, &canonical_plaintext, &envelope.0)?;
    let stream_digest = receipt.stream_digest().to_owned();
    Ok((
        ReceivedArtifact {
            preview,
            fields,
            stream_digest,
            content_digest: receipt.content_digest().to_owned(),
            envelope_digest: receipt.envelope_digest().to_owned(),
        },
        receipt,
    ))
}

pub(crate) fn validate_fields(fields: &[DisclosureField]) -> Result<()> {
    if fields.is_empty() || fields.len() > MAX_FIELDS {
        return Err(TransportError::ResourceLimit);
    }
    let mut total = 0usize;
    let mut previous: Option<&str> = None;
    for field in fields {
        validate_id(&field.name)?;
        if previous.is_some_and(|previous| previous >= field.name.as_str()) {
            return Err(TransportError::Malformed);
        }
        total = total
            .checked_add(field.bytes.len())
            .ok_or(TransportError::ResourceLimit)?;
        if total > MAX_PAYLOAD_BYTES {
            return Err(TransportError::ResourceLimit);
        }
        previous = Some(&field.name);
    }
    Ok(())
}
fn encode_fields(fields: &[DisclosureField]) -> Vec<WireField> {
    fields
        .iter()
        .map(|field| WireField {
            name: field.name.clone(),
            data: b64(&field.bytes),
        })
        .collect()
}
fn field_previews(fields: &[DisclosureField]) -> Vec<FieldPreview> {
    fields
        .iter()
        .map(|field| FieldPreview {
            name: field.name.clone(),
            byte_length: field.bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&field.bytes)),
        })
        .collect()
}
/// Canonical exact-field commitment for retained-message recovery. This validates
/// sorted distinct fields but creates no consent, export or decryption authority.
pub fn disclosure_payload_digest(fields: &[DisclosureField]) -> Result<String> {
    validate_fields(fields)?;
    if fields.windows(2).any(|pair| pair[0].name >= pair[1].name) {
        return Err(TransportError::Malformed);
    }
    payload_digest(fields)
}
fn payload_digest(fields: &[DisclosureField]) -> Result<String> {
    let encoded = Zeroizing::new(encode(&encode_fields(fields))?);
    Ok(digest(b"wholepact.disclosed-payload.v1\0", &encoded))
}
pub(crate) fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).map_err(|_| TransportError::Storage)?;
    let mut bytes = Vec::new();
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| TransportError::Storage)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(TransportError::ResourceLimit);
    }
    Ok(bytes)
}
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| TransportError::Storage)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| TransportError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteReplayLedger;

    // Deliberately bypasses the export consent checks only inside this synthetic
    // adversarial fixture, to verify independent receiver-side digest validation.
    fn malicious_authenticated_file(
        wire: &ProtectedMessage,
        sender: &TransportSecret,
        recipient: &TransportPublicKey,
        pretty: bool,
    ) -> EncryptedEnvelope {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        let secret = sender.private_key().unwrap();
        let (encapped, mut context) =
            hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
                &OpModeS::Auth((secret.clone(), Kem::sk_to_pk(&secret))),
                &recipient.key().unwrap(),
                INFO,
                &mut rng,
            )
            .unwrap();
        let mut envelope = WireEnvelope {
            schema_version: 1,
            suite: SUITE.into(),
            encapsulated_key: hex::encode(encapped.to_bytes()),
            ciphertext: String::new(),
        };
        let bytes = if pretty {
            serde_json::to_vec_pretty(wire).unwrap()
        } else {
            encode(wire).unwrap()
        };
        envelope.ciphertext = b64(&context
            .seal(&Zeroizing::new(bytes), &envelope.aad().unwrap())
            .unwrap());
        EncryptedEnvelope(encode(&envelope).unwrap())
    }
    #[test]
    fn authenticated_sender_cannot_skip_receiver_payload_and_preview_consistency() {
        let sender = TransportSecret::from_bytes([71; 32]).unwrap();
        let recipient = TransportSecret::from_bytes([72; 32]).unwrap();
        let now = Timestamp::from_unix_seconds(1_000).unwrap();
        let expected = MessageContext {
            network_profile_id: "testnet-synthetic".into(),
            agreement_id: "agreement".into(),
            proposal_id: "proposal".into(),
            proposal_revision: 1,
            sender_id: "sender".into(),
            recipient_id: "recipient".into(),
            artifact_kind: ArtifactKind::Contribution,
        };
        let dir = std::env::temp_dir().join(format!(
            "wholepact-synthetic-authenticated-mutation-{}",
            random_message_id().unwrap()
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut ledger = SqliteReplayLedger::open(dir.join("ledger.sqlite")).unwrap();
        for variant in 0..6 {
            let prepared = prepare_export(
                ExportRequest {
                    context: expected.clone(),
                    order: MessageOrder {
                        message_id: "00000000000000000000000000000001".into(),
                        sequence: 1,
                        issued_at: now.clone(),
                        expires_at: Timestamp::from_unix_seconds(1_100).unwrap(),
                    },
                    purpose: "synthetic adversarial fixture".into(),
                    persistence_warning: "recipient retains bytes".into(),
                },
                vec![DisclosureField::new("field", b"selected-only".to_vec()).unwrap()],
                &sender.public_key().unwrap(),
                &recipient.public_key().unwrap(),
                &now,
            )
            .unwrap();
            let mut wire = ProtectedMessage {
                approved_preview_digest: prepared.preview.digest().unwrap(),
                preview: prepared.preview,
                fields: encode_fields(&prepared.fields),
            };
            match variant {
                0 => wire.fields[0].data = b64(b"unreviewed additional private data"),
                1 => wire.preview.payload_digest = "00".repeat(32),
                2 => wire.preview.fields[0].sha256 = "00".repeat(32),
                3 => wire.approved_preview_digest = "00".repeat(32),
                _ => {}
            }
            let file = malicious_authenticated_file(
                &wire,
                &sender,
                &recipient.public_key().unwrap(),
                variant == 5,
            );
            let result = open_envelope(
                &file,
                &recipient,
                &sender.public_key().unwrap(),
                &expected,
                &now,
                &mut ledger,
            );
            match variant {
                0..=3 => assert_eq!(result.err(), Some(TransportError::DisclosureDenied)),
                4 => assert!(result.is_ok()),
                _ => assert_eq!(result.err(), Some(TransportError::Replay)),
            }
            assert_eq!(
                ledger.record_count().unwrap(),
                if variant < 4 { 0 } else { 1 }
            );
        }
        drop(ledger);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod control_route_tests {
    use super::*;
    struct NeverLedger;
    impl ReplayLedger for NeverLedger {
        fn accept_authenticated(&mut self, _: &AuthenticatedReceipt, _: &[u8]) -> Result<()> {
            panic!("generic control must fail before ledger access")
        }
    }
    #[test]
    fn generic_control_rejects_before_authentication_callback_or_ledger() {
        // Deliberately malformed bytes and synthetic non-live key objects. No
        // HPKE roundtrip is needed to establish the public preledger guard.
        let envelope = EncryptedEnvelope(Vec::new());
        let recipient = TransportSecret::from_bytes([7; 32]).unwrap();
        let sender = TransportPublicKey::from_bytes([8; 32]).unwrap();
        let expected = MessageContext {
            network_profile_id: "synthetic".into(),
            agreement_id: "agreement".into(),
            proposal_id: "proposal".into(),
            proposal_revision: 1,
            sender_id: "witness".into(),
            recipient_id: "signer".into(),
            artifact_kind: ArtifactKind::OfflineAdmissionControl,
        };
        let now = Timestamp::from_unix_seconds(1).unwrap();
        assert_eq!(
            open_envelope(
                &envelope,
                &recipient,
                &sender,
                &expected,
                &now,
                &mut NeverLedger
            )
            .err(),
            Some(TransportError::AuthorityUnavailable)
        );
        assert_eq!(
            open_envelope_checked(
                &envelope,
                &recipient,
                &sender,
                &expected,
                &now,
                &mut NeverLedger,
                |_| panic!("generic control must fail before callback")
            )
            .err(),
            Some(TransportError::AuthorityUnavailable)
        );
        // The crate-private authenticator used by the concrete atomic importer
        // is not disabled by this generic guard: it reaches payload validation.
        // A successful complete atomic import still requires HPKE qualification.
        assert_eq!(
            authenticate(&envelope, &recipient, &sender, &expected, Some(&now)).err(),
            Some(TransportError::Malformed)
        );
    }
}

#[cfg(test)]
mod offline_raw_seal_tests {
    use super::*;
    #[test]
    fn raw_offline_seal_refuses_before_time_consent_key_or_hpke_processing() {
        let public = TransportPublicKey::from_bytes([0x61; 32]).unwrap();
        let secret = TransportSecret::from_bytes([0x62; 32]).unwrap();
        for kind in [
            ArtifactKind::OfflineReservationIntent,
            ArtifactKind::OfflineAuthorityAdmission,
            ArtifactKind::OfflineAdmissionControl,
            ArtifactKind::Authorization,
        ] {
            let prepared = prepare_export(
                ExportRequest {
                    context: MessageContext {
                        network_profile_id: "synthetic".into(),
                        agreement_id: "agreement".into(),
                        proposal_id: "proposal".into(),
                        proposal_revision: 1,
                        sender_id: "sender".into(),
                        recipient_id: "recipient".into(),
                        artifact_kind: kind,
                    },
                    order: MessageOrder {
                        message_id: "11".repeat(16),
                        sequence: 1,
                        issued_at: Timestamp::from_unix_seconds(1).unwrap(),
                        expires_at: Timestamp::from_unix_seconds(2).unwrap(),
                    },
                    purpose: "Synthetic guard test".into(),
                    persistence_warning: "Synthetic retained evidence".into(),
                },
                vec![DisclosureField::new("synthetic", b"{}".to_vec()).unwrap()],
                &public,
                &public,
                &Timestamp::from_unix_seconds(1).unwrap(),
            )
            .unwrap();
            // Wrong key, missing approval and expired time must not reach HPKE.
            let error = prepared
                .seal(
                    &secret,
                    "not-approved",
                    &Timestamp::from_unix_seconds(3).unwrap(),
                )
                .err();
            assert_eq!(
                error,
                Some(if kind == ArtifactKind::Authorization {
                    TransportError::InvalidTime // Existing unrelated semantics remain unchanged.
                } else {
                    TransportError::AuthorityUnavailable
                })
            );
        }
    }
}

#[cfg(test)]
mod minimal_admission_generic_guards {
    use super::*;
    #[test]
    fn minimal_kind_has_no_generic_seal_enqueue_or_open_route_in_any_feature_profile() {
        let kind = ArtifactKind::OfflineMinimalAuthorityAdmission;
        assert!(kind.requires_qualified_export());
        assert_eq!(
            reject_unqualified_offline_seal(kind),
            Err(TransportError::AuthorityUnavailable)
        );
        let expected = MessageContext {
            network_profile_id: "synthetic".into(),
            agreement_id: "synthetic".into(),
            proposal_id: "synthetic".into(),
            proposal_revision: 1,
            sender_id: "synthetic".into(),
            recipient_id: "synthetic".into(),
            artifact_kind: kind,
        };
        assert_eq!(
            reject_generic_control(&expected),
            Err(TransportError::AuthorityUnavailable)
        );
    }
}

#[cfg(test)]
mod offline_return_generic_guard_tests {
    use super::*;
    #[test]
    fn offline_return_cannot_use_generic_seal_or_open() {
        let kind = ArtifactKind::OfflineAuthorizationReturn;
        let context = MessageContext {
            network_profile_id: "ironwood-testnet-nu7-candidate".into(),
            agreement_id: "synthetic-agreement".into(),
            proposal_id: "synthetic-proposal".into(),
            proposal_revision: 1,
            sender_id: "offline-return:synthetic-sender".into(),
            recipient_id: "offline-return:synthetic-recipient".into(),
            artifact_kind: kind,
        };
        assert_eq!(
            reject_unqualified_offline_seal(kind),
            Err(TransportError::AuthorityUnavailable)
        );
        assert_eq!(
            reject_generic_control(&context),
            Err(TransportError::AuthorityUnavailable)
        );
        assert!(kind.immutable_slot());
        assert!(kind.requires_qualified_export());
        assert_ne!(
            serde_json::to_string(&kind).unwrap(),
            serde_json::to_string(&ArtifactKind::Authorization).unwrap()
        );
    }
}
