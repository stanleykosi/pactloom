//! Storage-only vault. No wallet seed, signer payload or synthetic owner field.
//! Maintained pinned RustCrypto primitives match signer KDF policy, with distinct
//! domain-separated formats and independently random journal/transport keys; fresh client credentials are session-only.
#[cfg(feature = "financial-runtime")]
pub(crate) mod generation_archive;
use crate::{random, Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use wholepact_storage_security::DatabaseKey;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"WPNST001";
const RECOVERY: &[u8; 8] = b"WPNBR001";
const LENGTH: usize = 1 + 16 + 5 * 32;
pub(crate) const JOURNALS: [&str; 4] = [
    "coordination.sqlite",
    "inbox.sqlite",
    "outbox.sqlite",
    "submission.sqlite",
];
pub(crate) struct Secrets {
    bytes: Zeroizing<Vec<u8>>,
}
impl Secrets {
    pub(crate) fn fresh() -> Result<Self> {
        let mut bytes = Zeroizing::new(vec![0; LENGTH]);
        bytes[0] = 1;
        getrandom::fill(&mut bytes[1..]).map_err(|_| Error::Storage)?;
        Ok(Self { bytes })
    }
    /// A successor vault permanently binds its generation plan inside the encrypted
    /// payload. Removing external plan/commit files cannot turn it into an ordinary
    /// profile. This allocates storage keys only, never signing authority.
    #[cfg(any(feature = "financial-runtime", test))]
    pub(crate) fn bind_successor_plan(mut self, plan_digest: [u8; 32]) -> Result<Self> {
        if self.generation_plan_digest().is_some() {
            return Err(Error::Invalid);
        }
        self.bytes[0] = 2;
        self.bytes.extend_from_slice(&plan_digest);
        let seal_key_start = self.bytes.len();
        self.bytes.resize(seal_key_start + 32, 0);
        getrandom::fill(&mut self.bytes[seal_key_start..]).map_err(|_| Error::Storage)?;
        Ok(self)
    }
    pub(crate) fn generation_plan_digest(&self) -> Option<&[u8]> {
        matches!(self.bytes[0], 2 | 3 | 4).then(|| &self.bytes[LENGTH..LENGTH + 32])
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn generation_seal_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        if !matches!(self.bytes[0], 2 | 3 | 4) {
            return Err(Error::Invalid);
        }
        Ok(Zeroizing::new(
            self.bytes[LENGTH + 32..LENGTH + 64]
                .try_into()
                .map_err(|_| Error::Invalid)?,
        ))
    }
    fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        if !(bytes.first() == Some(&1) && bytes.len() == LENGTH)
            && !(bytes.first() == Some(&2) && bytes.len() == LENGTH + 64)
        {
            return Err(Error::Invalid);
        }
        Ok(Self { bytes })
    }
    /// Workspace-only v3 is a mandatory, immutable dependency anchor. This
    /// consuming transition preserves every original v2 byte except version.
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn bind_private_workspace_v3(mut self, anchor: [u8; 32]) -> Result<Self> {
        if self.bytes[0] != 2 || self.bytes.len() != LENGTH + 64 {
            return Err(Error::Invalid);
        }
        self.bytes[0] = 3;
        self.bytes.extend_from_slice(&anchor);
        Ok(self)
    }
    pub(crate) fn private_workspace_anchor(&self) -> Option<&[u8]> {
        (self.bytes[0] == 3).then(|| &self.bytes[LENGTH + 64..LENGTH + 96])
    }
    pub(crate) fn require_portable_legacy(&self) -> Result<()> {
        if (self.bytes.first() == Some(&1) && self.bytes.len() == LENGTH)
            || (self.bytes.first() == Some(&2) && self.bytes.len() == LENGTH + 64)
        { Ok(()) } else { Err(Error::Invalid) }
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn open_private_workspace_v3(bytes: &[u8], password: &[u8]) -> Result<Self> {
        let bytes = open(MAGIC, password, bytes)?;
        if bytes.first() != Some(&3) || bytes.len() != LENGTH + 96 {
            return Err(Error::Invalid);
        }
        Ok(Self { bytes })
    }
    /// The only next layout: append one dispatcher anchor to an exact v3.
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn bind_workspace_dispatcher_v4(mut self, anchor: [u8; 32]) -> Result<Self> {
        if self.bytes.first() != Some(&3) || self.bytes.len() != LENGTH + 96 {
            return Err(Error::Invalid);
        }
        self.bytes[0] = 4;
        self.bytes.extend_from_slice(&anchor);
        Ok(self)
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn open_workspace_dispatcher_v4(bytes: &[u8], password: &[u8]) -> Result<Self> {
        let bytes = open(MAGIC, password, bytes)?;
        if bytes.first() != Some(&4) || bytes.len() != LENGTH + 128 {
            return Err(Error::Invalid);
        }
        Ok(Self { bytes })
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn combined_workspace_anchor_v4(&self) -> Option<&[u8]> {
        (self.bytes.first() == Some(&4) && self.bytes.len() == LENGTH + 128)
            .then(|| &self.bytes[LENGTH + 64..LENGTH + 96])
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn workspace_dispatcher_anchor_v4(&self) -> Option<&[u8]> {
        (self.bytes.first() == Some(&4) && self.bytes.len() == LENGTH + 128)
            .then(|| &self.bytes[LENGTH + 96..LENGTH + 128])
    }
    #[cfg(test)]
    pub(crate) fn dispatcher_test_payload(&self) -> &[u8] { &self.bytes }
    pub(crate) fn same_recovery_material(&self, other: &Self) -> bool {
        self.bytes.as_slice() == other.bytes.as_slice()
    }
    pub(crate) fn profile(&self) -> String {
        format!("native-{}", hex::encode(&self.bytes[1..17]))
    }
    pub(crate) fn key(&self, n: usize) -> Result<DatabaseKey> {
        if n >= 4 {
            return Err(Error::Invalid);
        }
        Ok(DatabaseKey::from_bytes(self.array(n)?))
    }
    fn array(&self, n: usize) -> Result<[u8; 32]> {
        self.bytes[17 + n * 32..17 + (n + 1) * 32]
            .try_into()
            .map_err(|_| Error::Invalid)
    }
    pub(crate) fn transport(&self) -> Result<wholepact_transport::TransportSecret> {
        Ok(wholepact_transport::TransportSecret::from_bytes(
            self.array(4)?,
        )?)
    }
    pub(crate) fn transport_material(&self) -> Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(self.array(4)?))
    }
    pub(crate) fn seal(&self, password: &[u8]) -> Result<Vec<u8>> {
        envelope(MAGIC, password, &self.bytes)
    }
    pub(crate) fn open(bytes: &[u8], password: &[u8]) -> Result<Self> {
        Self::from_bytes(open(MAGIC, password, bytes)?)
    }
    pub(crate) fn recovery(&self, password: &[u8], archive_key: &[u8; 32]) -> Result<Vec<u8>> {
        self.require_portable_legacy()?;
        let mut payload = Zeroizing::new(Vec::with_capacity(LENGTH + 32));
        payload.extend_from_slice(archive_key);
        payload.extend_from_slice(&self.bytes);
        envelope(RECOVERY, password, &payload)
    }
    pub(crate) fn open_recovery(bytes: &[u8], password: &[u8]) -> Result<(Self, DatabaseKey)> {
        let plain = open(RECOVERY, password, bytes)?;
        if plain.len() != LENGTH + 32 && plain.len() != LENGTH + 96 {
            return Err(Error::Invalid);
        }
        let key = DatabaseKey::from_bytes(plain[..32].try_into().map_err(|_| Error::Invalid)?);
        Ok((Self::from_bytes(Zeroizing::new(plain[32..].to_vec()))?, key))
    }
}
fn derive(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if password.len() < 12 || password.len() > 1024 {
        return Err(Error::Authentication);
    }
    let params = Params::new(65_536, 3, 1, Some(32)).map_err(|_| Error::Storage)?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); 65_536]);
    kdf.hash_password_into_with_memory(password, salt, key.as_mut(), &mut *memory)
        .map_err(|_| Error::Storage)?;
    Ok(key)
}
fn envelope(magic: &[u8; 8], password: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let salt = random::<16>()?;
    let nonce = random::<24>()?;
    let key = derive(password, &salt)?;
    let mut header = magic.to_vec();
    header.extend(salt);
    header.extend(nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| Error::Storage)?;
    let encrypted = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plain,
                aad: &header,
            },
        )
        .map_err(|_| Error::Storage)?;
    header.extend(encrypted);
    Ok(header)
}
fn open(magic: &[u8; 8], password: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() < 64 || bytes.len() > 1024 || &bytes[..8] != magic {
        return Err(Error::Invalid);
    }
    let key = derive(password, &bytes[8..24])?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| Error::Storage)?;
    cipher
        .decrypt(
            &XNonce::try_from(&bytes[24..48]).map_err(|_| Error::Invalid)?,
            Payload {
                msg: &bytes[48..],
                aad: &bytes[..48],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

/// Separately consented financial storage keys, never signer spending material.
/// The authenticated payload commits to the owning coordinator profile. The
/// format cannot be opened as a legacy storage or backup recovery envelope.
#[cfg(feature = "financial-runtime")]
pub(crate) struct FinancialSecrets {
    bytes: Zeroizing<Vec<u8>>,
}
#[cfg(feature = "financial-runtime")]
impl FinancialSecrets {
    pub(crate) fn same_recovery_material(&self, other: &Self) -> bool {
        self.bytes.as_slice() == other.bytes.as_slice()
    }
    const MAGIC: &'static [u8; 8] = b"WPNFN001";
    const LENGTH: usize = 1 + 32 + 4 * 32;
    pub(crate) fn fresh(owner: &str) -> Result<Self> {
        use sha2::{Digest, Sha256};
        crate::id(owner)?;
        let mut bytes = Zeroizing::new(vec![0; Self::LENGTH]);
        bytes[0] = 1;
        bytes[1..33].copy_from_slice(&Sha256::digest(owner.as_bytes()));
        getrandom::fill(&mut bytes[33..]).map_err(|_| Error::Storage)?;
        Ok(Self { bytes })
    }
    pub(crate) fn key(&self, index: usize) -> Result<DatabaseKey> {
        if index >= 4 {
            return Err(Error::Invalid);
        }
        Ok(DatabaseKey::from_bytes(
            self.bytes[33 + index * 32..65 + index * 32]
                .try_into()
                .map_err(|_| Error::Invalid)?,
        ))
    }
    pub(crate) fn seal(&self, password: &[u8]) -> Result<Vec<u8>> {
        envelope(Self::MAGIC, password, &self.bytes)
    }
    pub(crate) fn open(bytes: &[u8], owner: &str, password: &[u8]) -> Result<Self> {
        use sha2::{Digest, Sha256};
        crate::id(owner)?;
        let bytes = open(Self::MAGIC, password, bytes)?;
        if bytes.len() != Self::LENGTH
            || bytes[0] != 1
            || bytes[1..33] != Sha256::digest(owner.as_bytes())[..]
        {
            return Err(Error::Authentication);
        }
        Ok(Self { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "financial-runtime")]
    #[test]
    fn private_workspace_v3_preserves_exact_legacy_slots_and_refuses_portable_decoders() {
        let mut v1 = vec![0u8; 177];
        v1[0] = 1;
        for (index, byte) in v1.iter_mut().enumerate().skip(1) {
            *byte = index as u8;
        }
        let legacy = Secrets::from_bytes(Zeroizing::new(v1.clone())).unwrap();
        assert_eq!(legacy.bytes.as_slice(), v1);
        let mut v2 = v1;
        v2[0] = 2;
        v2.extend_from_slice(&[11; 32]);
        v2.extend_from_slice(&[12; 32]);
        assert_eq!(v2.len(), 241);
        let old = Secrets::from_bytes(Zeroizing::new(v2.clone())).unwrap();
        let upgraded = old.bind_private_workspace_v3([13; 32]).unwrap();
        assert_eq!(upgraded.bytes.len(), 273);
        assert_eq!(upgraded.bytes[0], 3);
        assert_eq!(&upgraded.bytes[1..241], &v2[1..]);
        assert_eq!(upgraded.generation_plan_digest(), Some([11; 32].as_slice()));
        assert_eq!(*upgraded.generation_seal_key().unwrap(), [12; 32]);
        assert_eq!(
            upgraded.private_workspace_anchor(),
            Some([13; 32].as_slice())
        );
        assert!(Secrets::from_bytes(Zeroizing::new(upgraded.bytes.to_vec())).is_err());
        assert!(
            upgraded
                .recovery(b"component-test-password", &[14; 32])
                .is_err()
        );
        assert!(generation_archive::source_material(&upgraded).is_err());
        let password = b"component-test-password";
        let ciphertext = upgraded.seal(password).unwrap();
        assert!(Secrets::open(&ciphertext, password).is_err());
        let reopened = Secrets::open_private_workspace_v3(&ciphertext, password).unwrap();
        assert!(reopened.same_recovery_material(&upgraded));
        assert!(reopened.bind_private_workspace_v3([15; 32]).is_err());
        let old = Secrets::from_bytes(Zeroizing::new(v2)).unwrap();
        assert!(
            Secrets::open_private_workspace_v3(&old.seal(password).unwrap(), password).is_err()
        );
        assert!(
            Secrets::fresh()
                .unwrap()
                .bind_private_workspace_v3([13; 32])
                .is_err()
        );
    }
    #[test]
    fn successor_vault_keeps_generation_anchor_in_authenticated_payload() {
        let original = Secrets::fresh().unwrap();
        let profile = original.profile();
        let successor = original.bind_successor_plan([7; 32]).unwrap();
        assert_eq!(successor.profile(), profile);
        assert_eq!(successor.generation_plan_digest(), Some([7; 32].as_slice()));
        let restored = Secrets::from_bytes(Zeroizing::new(successor.bytes.to_vec())).unwrap();
        assert_eq!(
            restored.generation_plan_digest(),
            successor.generation_plan_digest()
        );
        assert!(restored.bind_successor_plan([8; 32]).is_err());
        let mut truncated = successor.bytes.to_vec();
        truncated.truncate(LENGTH);
        assert!(Secrets::from_bytes(Zeroizing::new(truncated)).is_err());
        let mut wrong_version = successor.bytes.to_vec();
        wrong_version[0] = 1;
        assert!(Secrets::from_bytes(Zeroizing::new(wrong_version)).is_err());
    }
    #[test]
    fn storage_vault_is_distinct_authenticated_and_bounded() {
        let password = Zeroizing::new(hex::encode(random::<24>().unwrap()));
        let secrets = Secrets::fresh().unwrap();
        let bytes = secrets.seal(password.as_bytes()).unwrap();
        assert_eq!(&bytes[..8], MAGIC);
        assert!(!bytes.windows(32).any(|s| s == &secrets.bytes[17..49]));
        assert_eq!(
            Secrets::open(&bytes, password.as_bytes())
                .unwrap()
                .profile(),
            secrets.profile()
        );
        assert!(Secrets::open(&bytes, b"wrong-long-password").is_err());
        let mut corrupt = bytes;
        corrupt[50] ^= 1;
        assert!(Secrets::open(&corrupt, password.as_bytes()).is_err());
        assert!(Secrets::open(&vec![0; 1025], password.as_bytes()).is_err());
        assert!(Secrets::open(
            &secrets.recovery(password.as_bytes(), &[9; 32]).unwrap(),
            password.as_bytes()
        )
        .is_err());
    }
}
