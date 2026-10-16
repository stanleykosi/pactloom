//! Versioned, authenticated vault and recovery backup. Only synthetic provisioning
//! is reachable in this milestone. Cryptography is entirely RustCrypto.
use crate::{files::PrivateDirectory, Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const VAULT_MAGIC: &[u8; 8] = b"WPVLT001";
const BACKUP_MAGIC: &[u8; 8] = b"WPBKP001";
const MAX_VAULT: usize = 4096;
const MAX_BACKUP: usize = 16 * 1024 * 1024;
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut value = [0; N];
    getrandom::fill(&mut value).map_err(|_| Error::Crypto)?;
    Ok(value)
}
pub(crate) fn derive(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    if password.len() < 12 || password.len() > 1024 {
        return Err(Error::Authentication);
    }
    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(32)).map_err(|_| Error::Crypto)?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); MEMORY_KIB as usize]);
    kdf.hash_password_into_with_memory(password, salt, key.as_mut(), &mut *memory)
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}
pub(crate) fn encrypt(key: &[u8; 32], domain: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = random::<24>()?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: domain,
            },
        )
        .map_err(|_| Error::Crypto)?;
    let mut out = nonce.to_vec();
    out.extend(ciphertext);
    Ok(out)
}
pub(crate) fn decrypt(key: &[u8; 32], domain: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() < 40 {
        return Err(Error::Authentication);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Crypto)?;
    cipher
        .decrypt(
            &XNonce::try_from(&bytes[..24]).map_err(|_| Error::Authentication)?,
            Payload {
                msg: &bytes[24..],
                aad: domain,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}
pub(crate) fn password_envelope(
    magic: &[u8; 8],
    password: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let salt = random::<16>()?;
    let key = derive(password, &salt)?;
    let mut header = magic.to_vec();
    header.extend(salt);
    let ciphertext = encrypt(&key, &header, payload)?;
    header.extend(ciphertext);
    Ok(header)
}
pub(crate) type OpenedEnvelope = (Zeroizing<Vec<u8>>, Zeroizing<[u8; 32]>, [u8; 16]);
pub(crate) fn open_password_envelope(
    magic: &[u8; 8],
    password: &[u8],
    bytes: &[u8],
    maximum: usize,
) -> Result<OpenedEnvelope> {
    if bytes.len() < 64 || bytes.len() > maximum || &bytes[..8] != magic {
        return Err(Error::InvalidData);
    }
    let salt = bytes[8..24].try_into().map_err(|_| Error::InvalidData)?;
    let key = derive(password, &salt)?;
    let plain = decrypt(&key, &bytes[..24], &bytes[24..])?;
    Ok((plain, key, salt))
}

/// Contains no Debug, Clone or Serialize implementation. Unlock material is
/// zeroized on lock/drop. Upstream account keys separately enable zeroize.
pub struct UnlockedVault {
    directory: PrivateDirectory,
    spending_key: Zeroizing<[u8; 32]>,
    encryption_key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    synthetic_owner: u8,
    backup_verified: bool,
    restored: bool,
}
impl UnlockedVault {
    #[cfg(any(test, feature = "synthetic-qualification"))]
    pub(crate) fn create_synthetic(
        root: &Path,
        password: &[u8],
        owner: u8,
        spending_key: [u8; 32],
    ) -> Result<Self> {
        if owner > 1 {
            return Err(Error::InvalidData);
        }
        let directory = PrivateDirectory::create(root)?;
        let secret = Zeroizing::new(spending_key);
        let salt = random::<16>()?;
        let encryption_key = derive(password, &salt)?;
        let vault = Self {
            directory,
            spending_key: secret,
            encryption_key,
            salt,
            synthetic_owner: owner,
            backup_verified: false,
            restored: false,
        };
        vault.persist()?;
        Ok(vault)
    }
    pub fn unlock(root: &Path, password: &[u8]) -> Result<Self> {
        let directory = PrivateDirectory::open(root)?;
        let bytes = directory.read("vault.wp", MAX_VAULT)?;
        let (plain, encryption_key, salt) =
            open_password_envelope(VAULT_MAGIC, password, &bytes, MAX_VAULT)?;
        if plain.len() != 36 || plain[32] > 1 || plain[33] > 1 || plain[34] > 1 || plain[35] != 1 {
            return Err(Error::InvalidData);
        }
        let spending_key = Zeroizing::new(plain[..32].try_into().map_err(|_| Error::InvalidData)?);
        Ok(Self {
            directory,
            spending_key,
            encryption_key,
            salt,
            synthetic_owner: plain[32],
            backup_verified: plain[33] == 1,
            restored: plain[34] == 1,
        })
    }
    fn plain(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(36));
        out.extend(self.spending_key.iter());
        out.extend([
            self.synthetic_owner,
            self.backup_verified as u8,
            self.restored as u8,
            1,
        ]);
        out
    }
    fn persist(&self) -> Result<()> {
        let mut header = VAULT_MAGIC.to_vec();
        header.extend(self.salt);
        let ciphertext = encrypt(&self.encryption_key, &header, &self.plain())?;
        header.extend(ciphertext);
        self.directory.write("vault.wp", &header)
    }
    pub fn directory(&self) -> &PrivateDirectory {
        &self.directory
    }
    pub fn account_id(&self) -> String {
        format!("synthetic-owner-{}", self.synthetic_owner)
    }
    pub fn owner_index(&self) -> usize {
        self.synthetic_owner as usize
    }
    pub fn backup_verified(&self) -> bool {
        self.backup_verified
    }
    pub fn recovery_required(&self) -> bool {
        self.restored
    }
    #[cfg(feature = "synthetic-qualification")]
    pub(crate) fn spending_key_bytes(&self) -> &[u8; 32] {
        &self.spending_key
    }
    pub fn require_signing_ready(&self) -> Result<()> {
        if self.restored {
            return Err(Error::RecoveryRequired);
        }
        if !self.backup_verified {
            return Err(Error::BackupRequired);
        }
        Ok(())
    }
    /// A backup includes both wallet authority and the supplied journal snapshot.
    /// Creation never establishes freshness or completes verification.
    pub fn create_backup(&self, journal: &[u8], backup_password: &[u8]) -> Result<()> {
        if journal.len() > MAX_BACKUP - 1024 {
            return Err(Error::InvalidData);
        }
        let mut plain = self.plain();
        plain.extend(journal);
        let encrypted = password_envelope(BACKUP_MAGIC, backup_password, &plain)?;
        self.directory.write("backup.wp", &encrypted)
    }
    /// Decrypt independently and compare recovery authority before unlocking the
    /// backup gate. The returned journal is sensitive and zeroized on drop.
    pub fn verify_backup(&mut self, backup_password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = self.directory.read("backup.wp", MAX_BACKUP)?;
        let (plain, _, _) =
            open_password_envelope(BACKUP_MAGIC, backup_password, &bytes, MAX_BACKUP)?;
        if plain.len() < 36
            || !bool::from(plain[..32].ct_eq(self.spending_key.as_slice()))
            || plain[32] != self.synthetic_owner
            || plain[35] != 1
        {
            return Err(Error::Authentication);
        }
        self.backup_verified = true;
        self.persist()?;
        Ok(Zeroizing::new(plain[36..].to_vec()))
    }
    /// Every import is recovery-required, even an intact full backup. No API can
    /// clear this flag. A seed-only restore is not yet exposed.
    pub fn restore(
        root: &Path,
        encrypted_backup: &[u8],
        backup_password: &[u8],
        new_password: &[u8],
    ) -> Result<Self> {
        let (plain, _, _) =
            open_password_envelope(BACKUP_MAGIC, backup_password, encrypted_backup, MAX_BACKUP)?;
        if plain.len() < 36 || plain[32] > 1 || plain[35] != 1 {
            return Err(Error::InvalidData);
        }
        let directory = PrivateDirectory::create(root)?;
        let salt = random::<16>()?;
        let encryption_key = derive(new_password, &salt)?;
        let vault = Self {
            directory,
            spending_key: Zeroizing::new(plain[..32].try_into().map_err(|_| Error::InvalidData)?),
            encryption_key,
            salt,
            synthetic_owner: plain[32],
            backup_verified: true,
            restored: true,
        };
        vault.persist()?;
        vault.write_protected(
            "restored-journal.wp",
            b"wholepact:restored-journal:v1",
            &plain[36..],
        )?;
        Ok(vault)
    }
    pub fn write_protected(&self, name: &str, purpose: &[u8], bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_BACKUP {
            return Err(Error::InvalidData);
        }
        let encrypted = encrypt(&self.encryption_key, purpose, bytes)?;
        self.directory.write(name, &encrypted)
    }
    pub fn read_protected(&self, name: &str, purpose: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decrypt(
            &self.encryption_key,
            purpose,
            &self.directory.read(name, MAX_BACKUP + 40)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASSWORD: &[u8] = b"synthetic-test-passphrase-only";
    #[test]
    pub(crate) fn encryption_unlock_backup_restore_and_tamper() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault");
        let mut vault = UnlockedVault::create_synthetic(&path, PASSWORD, 0, [1; 32]).unwrap();
        assert!(matches!(
            vault.require_signing_ready(),
            Err(Error::BackupRequired)
        ));
        let raw = vault.directory.read("vault.wp", MAX_VAULT).unwrap();
        assert!(!raw.windows(32).any(|w| w == [1; 32]));
        assert!(UnlockedVault::unlock(&path, PASSWORD).is_err()); // local writer lock
        vault
            .create_backup(b"synthetic-journal-canary", PASSWORD)
            .unwrap();
        assert!(vault.verify_backup(b"incorrect-test-password").is_err());
        assert_eq!(
            &*vault.verify_backup(PASSWORD).unwrap(),
            b"synthetic-journal-canary"
        );
        vault.require_signing_ready().unwrap();
        let backup = vault.directory.read("backup.wp", MAX_BACKUP).unwrap();
        assert!(!backup
            .windows(b"synthetic-journal-canary".len())
            .any(|w| w == b"synthetic-journal-canary"));
        let restored =
            UnlockedVault::restore(&temp.path().join("restored"), &backup, PASSWORD, PASSWORD)
                .unwrap();
        assert!(matches!(
            restored.require_signing_ready(),
            Err(Error::RecoveryRequired)
        ));
        drop(vault);
        assert!(UnlockedVault::unlock(&path, b"incorrect-test-password").is_err());
        let vault = UnlockedVault::unlock(&path, PASSWORD).unwrap();
        assert!(vault.backup_verified());
        vault
            .write_protected("result.wp", b"purpose-a", b"private-result")
            .unwrap();
        assert!(vault.read_protected("result.wp", b"purpose-b").is_err());
        assert_eq!(
            &*vault.read_protected("result.wp", b"purpose-a").unwrap(),
            b"private-result"
        );
        let mut bad = backup.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(
            UnlockedVault::restore(&temp.path().join("bad"), &bad, PASSWORD, PASSWORD).is_err()
        );
        assert!(UnlockedVault::restore(
            &temp.path().join("truncated"),
            &backup[..60],
            PASSWORD,
            PASSWORD
        )
        .is_err());
    }
    #[test]
    fn path_and_permission_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault");
        let vault = UnlockedVault::create_synthetic(&path, PASSWORD, 0, [1; 32]).unwrap();
        assert!(vault.directory.write("../escape", b"no").is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/dev/null", path.join("link")).unwrap();
            assert!(vault.directory.read("link", 1024).is_err());
        }
    }
}
