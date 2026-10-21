//! Private, not activated, fixed source-entry password framing. This is NOT an
//! origin, SourceEntry grant, Read grant, or an authenticated channel receiver.
//! A later genuine actor adapter must check its own immutable binding and all
//! original lifetimes/R/deadlines around these one-use operations and source KDF.
#![allow(dead_code)] // Deliberately typechecked without a role/runtime callsite.

use crate::{rejected, Result};
use hpke::{aead::{AeadTag, ChaCha20Poly1305}, kdf::HkdfSha256,
    kem::X25519HkdfSha256, Deserializable, Kem, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type SuiteKem = X25519HkdfSha256;
type PrivateKey = <SuiteKem as Kem>::PrivateKey;
type PublicKey = <SuiteKem as Kem>::PublicKey;
const INFO: &[u8] = b"wholepact:original-signer-source-entry-unlock:hpke-auth:v1\0";
const KEY_DOMAIN: &[u8] = b"wholepact:original-signer-source-entry-unlock:public-key:v1\0";
const REQUEST_DOMAIN: &[u8] = b"wholepact:original-signer-source-entry-unlock:request:v1\0";
const PURPOSE: &str = "original-signer-source-entry-unlock";
const SUITE: &str = "HPKE-Auth-X25519-HKDF-SHA256-ChaCha20Poly1305";
const PROFILE: &str = "coordinated-financial-workflow-v1";
const FULL_SUPERVISION_MS: u64 = 1_800_000;
pub(super) const FRAME_LIMIT: usize = 8192;
const PASSWORD_MIN: usize = 12;
const PASSWORD_MAX: usize = 1024;
const PLAINTEXT_LEN: usize = PASSWORD_MAX + 2;
const TAG_LEN: usize = 16;
const CIPHERTEXT_LEN: usize = PLAINTEXT_LEN + TAG_LEN;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum SourceEntryRole { Signer1, Signer2 }

/// Ordinary public facts only. This private descriptor cannot mint an offer,
/// input, Final, source lifetime or an authenticated original actor. Source
/// selection is not an authenticated opened-source identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub(super) version: u16,
    pub(super) purpose: String,
    pub(super) suite: String,
    pub(super) supervision_profile: String,
    pub(super) coordinator_process_instance: String,
    pub(super) coordinator_focus_epoch: u64,
    pub(super) signer_role: SourceEntryRole,
    pub(super) signer_process_instance: String,
    pub(super) original_host_process_instance: String,
    pub(super) common_image_measurement: String,
    pub(super) session_challenge: String,
    pub(super) selection_digest: String,
    pub(super) presentation_digest: String,
    pub(super) account_id: String,
    pub(super) owner_certificate_digest: String,
    pub(super) disclosure_digest: String,
    pub(super) terms_digest: String,
    pub(super) request_challenge: String,
    pub(super) offer_challenge: String,
    pub(super) sender_public_key: String,
    pub(super) sender_key_fingerprint: String,
    pub(super) recipient_public_key: String,
    pub(super) recipient_key_fingerprint: String,
    pub(super) reviewed_at_ms: u64,
    pub(super) expires_at_ms: u64,
    pub(super) source_expires_at_ms: u64,
    // Floor-rounded offsets from the retained pre-fork monotonic epoch, not
    // durations restarted at receive. Original source Instants stay at S.
    pub(super) native_ceiling_ms: u64,
    pub(super) entry_ceiling_ms: u64,
    pub(super) source_ceiling_ms: u64,
    pub(super) session_ceiling_ms: u64,
}
impl Binding {
    pub(super) fn validate(&self) -> Result<()> {
        if self.version != 1 || self.purpose != PURPOSE || self.suite != SUITE
            || self.supervision_profile != PROFILE || self.coordinator_focus_epoch != 1
            || self.session_ceiling_ms != FULL_SUPERVISION_MS
        { return Err(rejected("invalid source-entry envelope profile")); }
        for value in [&self.coordinator_process_instance, &self.signer_process_instance,
            &self.original_host_process_instance, &self.common_image_measurement,
            &self.session_challenge, &self.selection_digest, &self.presentation_digest,
            &self.account_id, &self.owner_certificate_digest, &self.disclosure_digest,
            &self.terms_digest, &self.request_challenge, &self.offer_challenge,
            &self.sender_key_fingerprint, &self.recipient_key_fingerprint] {
            if !lower_hex(value, 32) { return Err(rejected("invalid source-entry binding digest")); }
        }
        let sender = decode_key(&self.sender_public_key)?;
        let recipient = decode_key(&self.recipient_public_key)?;
        if sender == recipient || fingerprint(&sender) != self.sender_key_fingerprint
            || fingerprint(&recipient) != self.recipient_key_fingerprint
        { return Err(rejected("source-entry public key binding mismatch")); }
        if self.reviewed_at_ms == 0 || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120_000
            || self.expires_at_ms > self.source_expires_at_ms
            || [self.native_ceiling_ms, self.entry_ceiling_ms, self.source_ceiling_ms]
                .iter().any(|offset| *offset == 0 || *offset > self.session_ceiling_ms)
        { return Err(rejected("invalid source-entry original bounds")); }
        Ok(())
    }
    fn aad(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| rejected("source-entry metadata encoding"))?;
        // Reserve space for exactly 1042 encrypted bytes, encapsulated key and
        // fixed JSON structure. No secret ever enters this serializer.
        if bytes.len() > FRAME_LIMIT - 2300 { return Err(rejected("source-entry metadata oversized")); }
        Ok(bytes)
    }
    pub(super) fn request_digest(&self) -> Result<String> {
        let mut digest = Sha256::new();
        digest.update(REQUEST_DOMAIN);
        digest.update(self.aad()?);
        Ok(hex::encode(digest.finalize()))
    }
}

/// Secret wrappers intentionally have no Debug, Clone, serde or key importer.
/// Generation is only for a later owned post-barrier worker, never native A.
/// They grant no process/source authority, even inside this crate.
pub(super) struct SenderKey { private: PrivateKey, public: PublicKey }
pub(super) struct RecipientKey { private: PrivateKey, public: PublicKey }
fn fresh_pair() -> Result<(PrivateKey, PublicKey)> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|_| rejected("source-entry entropy unavailable"))?;
    Ok(SuiteKem::derive_keypair(&seed[..]))
}
fn public_bytes(public: &PublicKey) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&public.to_bytes());
    bytes
}
impl SenderKey {
    pub(super) fn generate() -> Result<Self> {
        let (private, public) = fresh_pair()?;
        Ok(Self { private, public })
    }
    pub(super) fn public_key(&self) -> [u8; 32] { public_bytes(&self.public) }
    /// Consumes key and secret input before any fallible work. HPKE SysRng can
    /// panic: the future owned worker must be joined and the attempt terminated,
    /// never retried or detached. The plaintext remains zeroizing on every path.
    pub(super) fn seal(self, binding: Binding, password: Zeroizing<Vec<u8>>) -> Result<Envelope> {
        let aad = binding.aad()?;
        if decode_key(&binding.sender_public_key)? != self.public_key() {
            return Err(rejected("source-entry sender key mismatch"));
        }
        let recipient = PublicKey::from_bytes(&decode_key(&binding.recipient_public_key)?)
            .map_err(|_| rejected("source-entry recipient key rejected"))?;
        let mut buffer = pack_password(&password)?;
        drop(password);
        let mode = OpModeS::<SuiteKem>::Auth((self.private, self.public));
        let (encapped, tag) = hpke::single_shot_seal_inout_detached::<ChaCha20Poly1305, HkdfSha256, SuiteKem>(
            &mode, &recipient, INFO, (&mut buffer[..]).into(), &aad)
            .map_err(|_| rejected("source-entry encryption rejected"))?;
        drop(mode);
        let mut encapsulated_key = [0u8; 32];
        encapsulated_key.copy_from_slice(&encapped.to_bytes());
        let mut ciphertext = [0u8; CIPHERTEXT_LEN];
        ciphertext[..PLAINTEXT_LEN].copy_from_slice(&buffer[..]);
        ciphertext[PLAINTEXT_LEN..].copy_from_slice(&tag.to_bytes());
        let envelope = Envelope { binding, encapsulated_key, ciphertext };
        envelope.encode()?; // Exact whole-frame cap, not only a field cap.
        Ok(envelope)
    }
}
impl RecipientKey {
    pub(super) fn generate() -> Result<Self> {
        let (private, public) = fresh_pair()?;
        Ok(Self { private, public })
    }
    pub(super) fn public_key(&self) -> [u8; 32] { public_bytes(&self.public) }
    /// Private crypto only: the future genuine received Input must additionally
    /// prove shared identity with its Final and check R/lifetimes both sides of
    /// this call. A byte-decoded Envelope by itself is never that Input.
    pub(super) fn open(self, expected: &Binding, envelope: Envelope) -> Result<Zeroizing<Vec<u8>>> {
        let aad = expected.aad()?;
        if envelope.binding != *expected || decode_key(&expected.recipient_public_key)? != self.public_key() {
            return Err(rejected("source-entry receiver binding mismatch"));
        }
        let sender = PublicKey::from_bytes(&decode_key(&expected.sender_public_key)?)
            .map_err(|_| rejected("source-entry sender key rejected"))?;
        let encapped = <SuiteKem as Kem>::EncappedKey::from_bytes(&envelope.encapsulated_key)
            .map_err(|_| rejected("source-entry encapsulation rejected"))?;
        let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(&envelope.ciphertext[PLAINTEXT_LEN..])
            .map_err(|_| rejected("source-entry tag rejected"))?;
        let mut buffer = Zeroizing::new([0u8; PLAINTEXT_LEN]);
        buffer.copy_from_slice(&envelope.ciphertext[..PLAINTEXT_LEN]);
        hpke::single_shot_open_inout_detached::<ChaCha20Poly1305, HkdfSha256, SuiteKem>(
            &OpModeR::Auth(sender), &self.private, &encapped, INFO,
            (&mut buffer[..]).into(), &aad, &tag)
            .map_err(|_| rejected("source-entry authentication rejected"))?;
        // Even the documented undefined-on-error in-place buffer is owned by
        // Zeroizing, unlike wrapping only a successful allocating open result.
        unpack_password(&buffer)
    }
}

/// Public-key/ciphertext data only, private to this crate. Decode does not prove
/// a sender, original process, native gesture, current offer, or any permission.
pub(super) struct Envelope {
    binding: Binding,
    encapsulated_key: [u8; 32],
    ciphertext: [u8; CIPHERTEXT_LEN],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope { binding: Binding, encapsulated_key: String, ciphertext: String }
impl Envelope {
    pub(super) fn binding(&self) -> &Binding { &self.binding }
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        self.binding.validate()?;
        let bytes = serde_json::to_vec(&WireEnvelope { binding: self.binding.clone(),
            encapsulated_key: hex::encode(self.encapsulated_key), ciphertext: hex::encode(self.ciphertext) })
            .map_err(|_| rejected("source-entry ciphertext encoding"))?;
        if bytes.len() > FRAME_LIMIT { return Err(rejected("source-entry frame oversized")); }
        Ok(bytes)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > FRAME_LIMIT { return Err(rejected("source-entry frame oversized")); }
        let wire: WireEnvelope = serde_json::from_slice(bytes).map_err(|_| rejected("source-entry frame rejected"))?;
        wire.binding.validate()?;
        let encapsulated_key = decode_key(&wire.encapsulated_key)?;
        if !lower_hex(&wire.ciphertext, CIPHERTEXT_LEN) { return Err(rejected("source-entry ciphertext length rejected")); }
        let mut ciphertext = [0u8; CIPHERTEXT_LEN];
        hex::decode_to_slice(wire.ciphertext, &mut ciphertext).map_err(|_| rejected("source-entry ciphertext rejected"))?;
        Ok(Self { binding: wire.binding, encapsulated_key, ciphertext })
    }
}
fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode_key(value: &str) -> Result<[u8; 32]> {
    if !lower_hex(value, 32) { return Err(rejected("source-entry public key length rejected")); }
    let mut key = [0u8; 32];
    hex::decode_to_slice(value, &mut key).map_err(|_| rejected("source-entry public key rejected"))?;
    if key == [0u8; 32] { return Err(rejected("source-entry zero public key rejected")); }
    Ok(key)
}
pub(super) fn fingerprint(key: &[u8; 32]) -> String {
    let mut digest = Sha256::new(); digest.update(KEY_DOMAIN); digest.update(key);
    hex::encode(digest.finalize())
}
fn pack_password(password: &[u8]) -> Result<Zeroizing<[u8; PLAINTEXT_LEN]>> {
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&password.len()) { return Err(rejected("source-entry password length rejected")); }
    let mut buffer = Zeroizing::new([0u8; PLAINTEXT_LEN]);
    buffer[..2].copy_from_slice(&(password.len() as u16).to_be_bytes());
    buffer[2..2 + password.len()].copy_from_slice(password);
    Ok(buffer)
}
fn unpack_password(buffer: &[u8; PLAINTEXT_LEN]) -> Result<Zeroizing<Vec<u8>>> {
    let len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&len)
        || buffer[2 + len..].iter().any(|byte| *byte != 0)
    { return Err(rejected("source-entry password frame rejected")); }
    let mut password = Zeroizing::new(vec![0u8; len]);
    password.copy_from_slice(&buffer[2..2 + len]);
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Inert fixtures only. No secret key, entropy, HPKE, process, socket, source,
    // origin, permit or genuine role constructor is invoked by these selectors.
    fn binding() -> Binding {
        let digest = "a".repeat(64);
        Binding { version: 1, purpose: PURPOSE.into(), suite: SUITE.into(), supervision_profile: PROFILE.into(),
            coordinator_process_instance: digest.clone(), coordinator_focus_epoch: 1,
            signer_role: SourceEntryRole::Signer1, signer_process_instance: digest.clone(),
            original_host_process_instance: digest.clone(), common_image_measurement: digest.clone(),
            session_challenge: digest.clone(), selection_digest: digest.clone(), presentation_digest: digest.clone(),
            account_id: digest.clone(), owner_certificate_digest: digest.clone(), disclosure_digest: digest.clone(),
            terms_digest: digest.clone(), request_challenge: digest.clone(), offer_challenge: digest,
            sender_public_key: hex::encode([1u8; 32]), sender_key_fingerprint: fingerprint(&[1u8; 32]),
            recipient_public_key: hex::encode([2u8; 32]), recipient_key_fingerprint: fingerprint(&[2u8; 32]),
            reviewed_at_ms: 1000, expires_at_ms: 121000, source_expires_at_ms: 200000,
            native_ceiling_ms: 120000, entry_ceiling_ms: 121000, source_ceiling_ms: 200000,
            session_ceiling_ms: FULL_SUPERVISION_MS }
    }
    fn encoded() -> Vec<u8> {
        Envelope { binding: binding(), encapsulated_key: [3u8; 32], ciphertext: [4u8; CIPHERTEXT_LEN] }.encode().unwrap()
    }
    #[test]
    fn fixed_password_frame_preserves_bytes_and_size() {
        for len in [12, 13, 1024] {
            let bytes = vec![0xa5; len]; let packed = pack_password(&bytes).unwrap();
            assert_eq!(packed.len(), 1026); assert_eq!(CIPHERTEXT_LEN, 1042);
            assert_eq!(&*unpack_password(&packed).unwrap(), &bytes);
            assert!(packed[2 + len..].iter().all(|b| *b == 0));
        }
        assert!(pack_password(&[0; 11]).is_err()); assert!(pack_password(&[0; 1025]).is_err());
    }
    #[test]
    fn password_frame_rejects_bad_length_and_padding() {
        let mut packed = pack_password(&[7; 12]).unwrap(); packed[1025] = 1;
        assert!(unpack_password(&packed).is_err());
        packed[1025] = 0; packed[..2].copy_from_slice(&1025u16.to_be_bytes());
        assert!(unpack_password(&packed).is_err());
        packed[..2].copy_from_slice(&11u16.to_be_bytes()); assert!(unpack_password(&packed).is_err());
    }
    #[test]
    fn envelope_schema_is_closed_bounded_and_exact_length() {
        let bytes = encoded(); assert!(bytes.len() <= FRAME_LIMIT);
        assert_eq!(Envelope::decode(&bytes).unwrap().encode().unwrap(), bytes);
        assert!(Envelope::decode(&vec![b' '; FRAME_LIMIT + 1]).is_err());
        let text = String::from_utf8(bytes).unwrap();
        assert!(Envelope::decode(text.replacen("{", "{\"unknown\":0,", 1).as_bytes()).is_err());
        assert!(Envelope::decode(text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1).as_bytes()).is_err());
        assert!(Envelope::decode(text.replacen("\"version\":1", "\"unknown\":0,\"version\":1", 1).as_bytes()).is_err());
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["ciphertext"] = "04".repeat(CIPHERTEXT_LEN - 1).into();
        assert!(Envelope::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn binding_rejects_profile_keys_and_original_bound_changes() {
        let valid = binding(); assert!(valid.validate().is_ok());
        let mut changed = valid.clone(); changed.supervision_profile = "coordinated-signer-continue".into(); assert!(changed.validate().is_err());
        let mut changed = valid.clone(); changed.session_ceiling_ms += 1; assert!(changed.validate().is_err());
        let mut changed = valid.clone(); changed.native_ceiling_ms = 0; assert!(changed.validate().is_err());
        let mut changed = valid.clone(); changed.entry_ceiling_ms = FULL_SUPERVISION_MS + 1; assert!(changed.validate().is_err());
        let mut changed = valid.clone(); changed.expires_at_ms += 1; assert!(changed.validate().is_err());
        let mut changed = valid.clone(); changed.recipient_public_key = valid.sender_public_key.clone(); assert!(changed.validate().is_err());
        let mut changed = valid.clone(); changed.sender_key_fingerprint = "b".repeat(64); assert!(changed.validate().is_err());
        let mut changed = valid; changed.coordinator_focus_epoch = 2; assert!(changed.validate().is_err());
    }
    #[test]
    fn request_commitment_covers_role_selection_challenge_and_bounds() {
        let valid = binding(); let original = valid.request_digest().unwrap();
        let mut changed = valid.clone(); changed.signer_role = SourceEntryRole::Signer2; assert_ne!(original, changed.request_digest().unwrap());
        let mut changed = valid.clone(); changed.selection_digest = "b".repeat(64); assert_ne!(original, changed.request_digest().unwrap());
        let mut changed = valid.clone(); changed.offer_challenge = "b".repeat(64); assert_ne!(original, changed.request_digest().unwrap());
        let mut changed = valid; changed.native_ceiling_ms -= 1; assert_ne!(original, changed.request_digest().unwrap());
    }
}
