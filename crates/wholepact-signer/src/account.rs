//! Dedicated participation account source model. No CLI provisioning route is
//! enabled. Only the trusted controlling-terminal flow can create a new account
//! for persistence; tests exercise temporary synthetic entropy.
use crate::{files::PrivateDirectory, vault, Error, Result};
use bip39::{Language, Mnemonic};
use orchard::keys::{FullViewingKey, SpendingKey};
use sha2::{Digest, Sha256};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"WPACC002";
const MAX_ACCOUNT: usize = 32 * 1024;

#[cfg(test)]
std::thread_local! {
    static SPENDING_KEY_DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Produced only by the controlling-terminal confirmation flow. Not a DTO.
pub struct ProvisioningConsent {
    pub(crate) privacy_domain: String,
    pub(crate) account_index: u32,
}
#[cfg(all(
    feature = "authority-signing",
    feature = "native-ui",
    target_os = "linux"
))]
struct GeneratedAccountInstance {
    marker: std::sync::Arc<()>,
    instance_id: String,
}
pub struct PendingAccount {
    account: DedicatedAccount,
}
/// Full recovery phrase has been re-entered correctly on the trusted surface.
pub struct BackupVerifiedAccount {
    account: DedicatedAccount,
}
/// The mnemonic is explicitly BIP39 English/256-bit, empty BIP39 passphrase,
/// legacy ZIP32 testnet m/32'/1'/account'. No other recovery mode is implied.
pub struct DedicatedAccount {
    entropy: Zeroizing<[u8; 32]>,
    account_index: u32,
    // Inert commitments to immutable entropy/index, never serialized or key-use
    // permission. No seed, spending key, or viewing key is retained here.
    account_id: String,
    #[cfg_attr(
        not(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        )),
        allow(dead_code)
    )]
    full_viewing_key_digest: String,
    privacy_domain: String,
    restored: bool,
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    born_authority_pending: bool,
    // Process-instance correlation, never a native approval or persisted fact.
    // Only PendingAccount::generate sets this; decode/import/fixtures do not.
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    generated_instance: Option<GeneratedAccountInstance>,
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    activation: Option<VerifiedProfileActivation>,
}
impl PendingAccount {
    /// Fixed public, never-funded whole-flow qualification accounts only. This
    /// uses genuine BIP39/ZIP32 derivation and still requires backup verification.
    /// No caller-selected entropy, spending key, or restored-state override exists.
    #[cfg(all(
        feature = "synthetic-qualification",
        feature = "native-ui",
        feature = "authority-signing"
    ))]
    pub(crate) fn fixed_never_funded_qualification(index: u8) -> Result<Self> {
        if index > 1 {
            return Err(Error::InvalidData);
        }
        Ok(Self {
            account: DedicatedAccount::from_entropy(
                Zeroizing::new([0x71 + index; 32]),
                0,
                "connected-native-synthetic".into(),
                false,
            )?,
        })
    }
    pub fn generate(consent: ProvisioningConsent) -> Result<Self> {
        let entropy = Zeroizing::new(vault::random::<32>()?);
        let account = DedicatedAccount::from_entropy(
            entropy,
            consent.account_index,
            consent.privacy_domain,
            false,
        )?;
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        let account = {
            let mut account = account;
            account.generated_instance = Some(GeneratedAccountInstance {
                marker: std::sync::Arc::new(()),
                instance_id: hex::encode(vault::random::<32>()?),
            });
            account
        };
        Ok(Self { account })
    }
    pub(crate) fn recovery_words(&self) -> Result<Zeroizing<String>> {
        self.account.recovery_words()
    }
    pub(crate) fn verify_backup(self, words: &str) -> Result<BackupVerifiedAccount> {
        let mnemonic = parse_recovery(words)?;
        let (recovered, len) = mnemonic.to_entropy_array();
        let recovered = Zeroizing::new(recovered);
        if len != 32 || !bool::from(recovered[..32].ct_eq(self.account.entropy.as_slice())) {
            return Err(Error::Authentication);
        }
        Ok(BackupVerifiedAccount {
            account: self.account,
        })
    }
}
impl DedicatedAccount {
    fn from_entropy(
        entropy: Zeroizing<[u8; 32]>,
        account_index: u32,
        privacy_domain: String,
        restored: bool,
    ) -> Result<Self> {
        if account_index >= 1 << 31
            || privacy_domain.is_empty()
            || privacy_domain.len() > 128
            || !privacy_domain
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_:.".contains(&c))
        {
            return Err(Error::InvalidData);
        }
        // Reuse the constructor's mandatory successful derivation before this
        // account can escape. Temporary key material is not part of the account.
        let (account_id, full_viewing_key_digest) = {
            let key = Self::derive_spending_key_from_entropy(&entropy, account_index)?;
            let fvk = Zeroizing::new(FullViewingKey::from(&key).to_bytes());
            (
                Self::account_id_from_fvk(fvk.as_slice()),
                hex::encode(Sha256::digest(fvk.as_slice())),
            )
        };
        Ok(Self {
            entropy,
            account_index,
            account_id,
            full_viewing_key_digest,
            privacy_domain,
            restored,
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            born_authority_pending: false,
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            generated_instance: None,
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            activation: None,
        })
    }
    pub fn recover(words: &str, account_index: u32, privacy_domain: String) -> Result<Self> {
        let mnemonic = parse_recovery(words)?;
        let (entropy, length) = mnemonic.to_entropy_array();
        let entropy = Zeroizing::new(entropy);
        if length != 32 {
            return Err(Error::InvalidData);
        }
        Self::from_entropy(
            Zeroizing::new(entropy[..32].try_into().map_err(|_| Error::InvalidData)?),
            account_index,
            privacy_domain,
            true,
        )
    }
    fn mnemonic(&self) -> Result<Mnemonic> {
        Mnemonic::from_entropy_in(Language::English, self.entropy.as_slice())
            .map_err(|_| Error::Crypto)
    }
    pub(crate) fn recovery_words(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(self.mnemonic()?.to_string()))
    }
    /// Non-key-bearing preflight so the generic path never charges a release
    /// that is deterministically blocked by the existing born-account gate.
    pub(crate) fn require_generic_spending_source(&self) -> Result<()> {
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        if self.born_authority_pending {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    pub(crate) fn spending_key(&self) -> Result<SpendingKey> {
        self.require_generic_spending_source()?;
        self.derive_spending_key()
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "pending-birth-owner-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn derive_durable_born_spending_key_v1(
        &self,
        fence: &crate::authority_bridge::DurableBornKeyUseFenceV1<'_>,
    ) -> Result<SpendingKey> {
        if !self.born_authority_pending || self.recovery_required() {
            return Err(Error::Unavailable);
        }
        fence.require_account(self)?;
        let key = self.derive_spending_key()?;
        fence.require_account(self)?;
        Ok(key)
    }
    #[cfg(all(feature="durable-proposal",feature="pending-birth-owner-signing",feature="native-ui",target_os="linux"))]
    pub(crate) fn derive_financial_spending_key_v1(&self,fence:&crate::authority_bridge::financial_continuation_v1::FinancialKeyUseFenceV1<'_>)->Result<SpendingKey>{
        if !self.born_authority_pending||self.recovery_required(){return Err(Error::Unavailable);}
        fence.require_account(self)?;
        let key=self.derive_spending_key()?;
        fence.require_account(self)?;Ok(key)
    }
    fn derive_spending_key(&self) -> Result<SpendingKey> {
        Self::derive_spending_key_from_entropy(&self.entropy, self.account_index)
    }
    fn derive_spending_key_from_entropy(
        entropy: &[u8; 32],
        account_index: u32,
    ) -> Result<SpendingKey> {
        #[cfg(test)]
        SPENDING_KEY_DERIVATIONS.with(|count| count.set(count.get() + 1));
        let mnemonic =
            Mnemonic::from_entropy_in(Language::English, entropy).map_err(|_| Error::Crypto)?;
        let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
        SpendingKey::from_zip32_seed(
            seed.as_slice(),
            1,
            account_index.try_into().map_err(|_| Error::InvalidData)?,
        )
        .map_err(|_| Error::Crypto)
    }
    pub(crate) fn fvk(&self) -> Result<FullViewingKey> {
        Ok(FullViewingKey::from(&self.derive_spending_key()?))
    }
    pub fn account_id(&self) -> Result<String> {
        Ok(self.account_id.clone())
    }
    fn account_id_from_fvk(fvk: &[u8]) -> String {
        let mut hash = Sha256::new();
        hash.update(b"wholepact:dedicated-testnet-account:legacy-zip32:v1\0");
        hash.update(fvk);
        hex::encode(hash.finalize())
    }
    // Pure commitments from the constructor's actual derivation, never a
    // caller-supplied key or retained key-use authority.
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    fn birth_identity_commitments(&self) -> Result<(String, String)> {
        Ok((
            self.account_id.clone(),
            self.full_viewing_key_digest.clone(),
        ))
    }
    pub fn privacy_domain(&self) -> &str {
        &self.privacy_domain
    }
    pub fn recovery_required(&self) -> bool {
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        if self.activation.is_some() {
            return false;
        }
        self.restored
    }
    pub fn derivation(&self) -> String {
        format!(
            "BIP39-English-256-empty-passphrase / ZIP32 m/32'/1'/{}'",
            self.account_index
        )
    }
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(vec![1, 1, self.restored as u8]); // testnet, legacy mode, restore quarantine
        bytes.extend(self.account_index.to_le_bytes());
        bytes.extend(self.entropy.iter());
        bytes.extend((self.privacy_domain.len() as u16).to_le_bytes());
        bytes.extend(self.privacy_domain.as_bytes());
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 41 || bytes[0] != 1 || bytes[1] != 1 || bytes[2] > 1 {
            return Err(Error::InvalidData);
        }
        let domain_len =
            u16::from_le_bytes(bytes[39..41].try_into().map_err(|_| Error::InvalidData)?) as usize;
        if domain_len + 41 != bytes.len() {
            return Err(Error::InvalidData);
        }
        Self::from_entropy(
            Zeroizing::new(bytes[7..39].try_into().map_err(|_| Error::InvalidData)?),
            u32::from_le_bytes(bytes[3..7].try_into().map_err(|_| Error::InvalidData)?),
            std::str::from_utf8(&bytes[41..])
                .map_err(|_| Error::InvalidData)?
                .into(),
            bytes[2] == 1,
        )
    }
}
fn parse_recovery(words: &str) -> Result<Mnemonic> {
    if words.len() > 1024 || !words.is_ascii() {
        return Err(Error::InvalidData);
    }
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, words)
        .map_err(|_| Error::Authentication)?;
    if mnemonic.word_count() != 24 {
        return Err(Error::InvalidData);
    }
    Ok(mnemonic)
}

/// Version-distinct production-format vault. Creation needs a sealed verified
/// account. Unlock returns account authority, not permission to release signatures.
pub struct AccountVault {
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    born_origin: Option<birth::acknowledgement::RetainedBornAccountOrigin>,
    directory: PrivateDirectory,
    account: DedicatedAccount,
    encryption_key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    authority_key: Zeroizing<[u8; 32]>,
    authority_initialized: bool,
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    generation: Option<activation::VaultGeneration>,
}
impl AccountVault {
    pub fn create(root: &Path, verified: BackupVerifiedAccount, password: &[u8]) -> Result<Self> {
        let account = verified.account;
        // The existing route has no birth review or immutable origin. Even the
        // same in-process object must remain legacy/unknown after this boundary.
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        let account = {
            let mut account = account;
            account.generated_instance = None;
            account
        };
        Self::persist_new(root, account, password)
    }
    pub fn persist_recovered(
        root: &Path,
        recovered: DedicatedAccount,
        password: &[u8],
    ) -> Result<Self> {
        if !recovered.restored {
            return Err(Error::RecoveryRequired);
        }
        Self::persist_new(root, recovered, password)
    }
    fn persist_new(root: &Path, account: DedicatedAccount, password: &[u8]) -> Result<Self> {
        let salt = vault::random::<16>()?;
        let encryption_key = vault::derive(password, &salt)?;
        let directory = PrivateDirectory::create(root)?;
        let vault = Self {
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            born_origin: None,
            directory,
            account,
            encryption_key,
            salt,
            authority_key: Zeroizing::new(vault::random::<32>()?),
            authority_initialized: false,
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            generation: None,
        };
        vault.persist()?;
        Ok(vault)
    }
    pub fn unlock(root: &Path, password: &[u8]) -> Result<Self> {
        Self::unlock_internal(root, password, false)
    }
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn unlock_pending_recovery(root: &Path, password: &[u8]) -> Result<Self> {
        let vault = Self::unlock_internal(root, password, true)?;
        vault.verify_recovery_plan()?;
        Ok(vault)
    }
    fn unlock_internal(root: &Path, password: &[u8], pending_recovery: bool) -> Result<Self> {
        if pending_recovery
            && !cfg!(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))
        {
            return Err(Error::RecoveryRequired);
        }
        let directory = PrivateDirectory::open(root)?;
        Self::decode_locked(directory, password, pending_recovery)
    }
    /// Shared pure envelope decoding after the caller has acquired its exact
    /// directory ownership. This function never creates a lock or persists data.
    fn decode_locked(
        directory: PrivateDirectory,
        password: &[u8],
        pending_recovery: bool,
    ) -> Result<Self> {
        let read_bound = if cfg!(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        )) {
            512 * 1024
        } else {
            MAX_ACCOUNT
        };
        let bytes = directory.read("account.wp", read_bound)?;
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        if bytes.starts_with(birth::active::MAGIC) {
            return birth::active::open(directory, password, &bytes, pending_recovery);
        }
        let (plain, encryption_key, salt) =
            vault::open_password_envelope(MAGIC, password, &bytes, MAX_ACCOUNT)?;
        if plain.len() < 33 || plain[0] > 2 {
            return Err(Error::InvalidData);
        }
        let authority_initialized = plain[0] != 0;
        let authority_key =
            Zeroizing::new(plain[1..33].try_into().map_err(|_| Error::InvalidData)?);
        let account_bytes = &plain[33..];
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        let (generation, account_bytes) = if plain[0] == 2 {
            if account_bytes.len() < 4 {
                return Err(Error::InvalidData);
            }
            let length = u32::from_le_bytes(
                account_bytes[..4]
                    .try_into()
                    .map_err(|_| Error::InvalidData)?,
            ) as usize;
            if length > 16 * 1024 || account_bytes.len() < 4 + length {
                return Err(Error::InvalidData);
            }
            let binding = serde_json::from_slice(&account_bytes[4..4 + length])
                .map_err(|_| Error::InvalidData)?;
            (Some(binding), &account_bytes[4 + length..])
        } else {
            (None, account_bytes)
        };
        #[cfg(not(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        )))]
        if plain[0] == 2 {
            return Err(Error::RecoveryRequired);
        }
        let account = DedicatedAccount::decode(account_bytes)?;
        let opened = Self {
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            born_origin: None,
            directory,
            account,
            encryption_key,
            salt,
            authority_key,
            authority_initialized,
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            generation,
        };
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        if opened.generation.is_some() && !pending_recovery {
            opened.verify_profile_activation()?;
        }
        Ok(opened)
    }
    fn persist(&self) -> Result<()> {
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        if self.born_origin.is_some() {
            return birth::active::persist(self);
        }
        let mut header = MAGIC.to_vec();
        header.extend(self.salt);
        let mut plain = Zeroizing::new(vec![self.authority_initialized as u8]);
        plain.extend(self.authority_key.iter());
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        if let Some(generation) = &self.generation {
            plain[0] = 2;
            let encoded = serde_json::to_vec(generation).map_err(|_| Error::InvalidData)?;
            plain.extend((encoded.len() as u32).to_le_bytes());
            plain.extend(encoded);
        }
        plain.extend(self.account.encode().iter());
        let encrypted = vault::encrypt(&self.encryption_key, &header, &plain)?;
        header.extend(encrypted);
        self.directory.write("account.wp", &header)
    }
    /// Only for a newly provisioned vault. Never silently recreates a missing journal.
    pub fn create_authority_journal(
        &mut self,
    ) -> Result<crate::consent_journal::SignerConsentJournal> {
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        if self.born_origin.is_some() {
            return Err(Error::Unavailable);
        }
        if self.authority_initialized || self.directory.exists("authority.sqlite")? {
            return Err(Error::RecoveryRequired);
        }
        let key = wholepact_storage_security::DatabaseKey::from_bytes(*self.authority_key);
        let store = crate::consent_journal::SignerConsentJournal::create_encrypted(
            &self.directory.root().join("authority.sqlite"),
            &key,
            &self.account_id()?,
            1,
            self.account.restored,
            &self.directory.signer_journal_source_owner()?,
        )?;
        self.authority_initialized = true;
        self.persist()?;
        Ok(store)
    }
    pub fn open_authority_journal(
        &mut self,
    ) -> Result<crate::consent_journal::SignerConsentJournal> {
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        if self.born_origin.is_some() {
            return Err(Error::Unavailable);
        }
        if !self.directory.exists("authority.sqlite")? {
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            {
                self.account.activation = None;
            }
            self.account.restored = true;
            self.persist()?;
            return Err(Error::RecoveryRequired);
        }
        let key = wholepact_storage_security::DatabaseKey::from_bytes(*self.authority_key);
        #[cfg(all(
            feature = "authority-signing",
            feature = "native-ui",
            target_os = "linux"
        ))]
        if self.generation.is_some() {
            let verified = self.verify_profile_activation()?;
            let journal = crate::consent_journal::SignerConsentJournal::open_activated_encrypted(
                &self.directory.root().join("authority.sqlite"),
                &key,
                &self.account_id()?,
                &verified,
                &self.directory.signer_journal_source_owner()?,
            )?;
            self.account.activation = Some(verified);
            return Ok(journal);
        }
        let store = crate::consent_journal::SignerConsentJournal::open_encrypted(
            &self.directory.root().join("authority.sqlite"),
            &key,
            &self.account_id()?,
            &self.directory.signer_journal_source_owner()?,
        )?;
        if !self.authority_initialized || self.account.restored {
            store.require_recovery()?;
        }
        Ok(store)
    }
    pub fn account_id(&self) -> Result<String> {
        self.account.account_id()
    }
    /// Private native setup only. A distinct random viewing-database key is
    /// wrapped by this already unlocked vault; it is never derived from a seed.
    /// Persisting the key first makes an interrupted create fail closed on retry.
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn create_viewing_wallet_storage(
        &self,
    ) -> Result<wholepact_storage_security::EncryptedConnection> {
        if self.born_origin.is_some() {
            return Err(Error::Unavailable);
        }
        if self.account.recovery_required()
            || self.directory.exists("viewing-wallet-key.wp")?
            || self.directory.exists("viewing-wallet.sqlite")?
        {
            return Err(Error::RecoveryRequired);
        }
        let key = Zeroizing::new(vault::random::<32>()?);
        let mut domain = b"wholepact:dedicated-viewing-wallet-key:v1\0".to_vec();
        domain.extend(self.account_id()?.as_bytes());
        let wrapped = vault::encrypt(&self.encryption_key, &domain, key.as_slice())?;
        self.directory.write("viewing-wallet-key.wp", &wrapped)?;
        wholepact_storage_security::create_encrypted(
            self.directory.root().join("viewing-wallet.sqlite"),
            &wholepact_storage_security::DatabaseKey::from_bytes(*key),
        )
        .map_err(|_| Error::RecoveryRequired)
    }
    /// A missing key, missing database, authentication failure or restored state
    /// never silently creates a new wallet. This returns no raw database key.
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn open_viewing_wallet_storage(
        &self,
    ) -> Result<wholepact_storage_security::EncryptedConnection> {
        if self.born_origin.is_some() {
            return Err(Error::Unavailable);
        }
        if self.account.recovery_required()
            || !self.directory.exists("viewing-wallet-key.wp")?
            || !self.directory.exists("viewing-wallet.sqlite")?
        {
            return Err(Error::RecoveryRequired);
        }
        let wrapped = self.directory.read("viewing-wallet-key.wp", 1024)?;
        let mut domain = b"wholepact:dedicated-viewing-wallet-key:v1\0".to_vec();
        domain.extend(self.account_id()?.as_bytes());
        let key = vault::decrypt(&self.encryption_key, &domain, &wrapped)?;
        let key = wholepact_storage_security::DatabaseKey::from_bytes(
            key.as_slice()
                .try_into()
                .map_err(|_| Error::Authentication)?,
        );
        wholepact_storage_security::open_encrypted(
            self.directory.root().join("viewing-wallet.sqlite"),
            &key,
        )
        .map_err(|_| Error::RecoveryRequired)
    }
    pub fn account(&self) -> &DedicatedAccount {
        &self.account
    }
    pub fn live_signing_allowed(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derivation_count() -> usize {
        SPENDING_KEY_DERIVATIONS.with(std::cell::Cell::get)
    }

    // Independent oracle: do not call DedicatedAccount's derivation or identity
    // helpers. All inputs in these tests are fixed public, never-funded entropy.
    fn canonical_identity_oracle(entropy: [u8; 32], account_index: u32) -> (String, String) {
        let entropy = Zeroizing::new(entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_slice()).unwrap();
        let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
        let key =
            SpendingKey::from_zip32_seed(seed.as_slice(), 1, account_index.try_into().unwrap())
                .unwrap();
        let fvk = Zeroizing::new(FullViewingKey::from(&key).to_bytes());
        let mut account_hash = Sha256::new();
        account_hash.update(b"wholepact:dedicated-testnet-account:legacy-zip32:v1\0");
        account_hash.update(fvk.as_slice());
        (
            hex::encode(account_hash.finalize()),
            hex::encode(Sha256::digest(fvk.as_slice())),
        )
    }

    #[test]
    fn identity_commitments_match_independent_bip39_zip32_oracle() {
        let mut identities = Vec::new();
        for (entropy, index) in [
            ([0x61; 32], 0),
            ([0x62; 32], 0),
            ([0x61; 32], 1),
            ([0x61; 32], (1 << 31) - 1),
        ] {
            let before = derivation_count();
            let account = DedicatedAccount::from_entropy(
                Zeroizing::new(entropy),
                index,
                "synthetic-identity".into(),
                false,
            )
            .unwrap();
            let expected = canonical_identity_oracle(entropy, index);
            assert_eq!(account.account_id().unwrap(), expected.0);
            assert_eq!(account.full_viewing_key_digest, expected.1);
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            assert_eq!(account.birth_identity_commitments().unwrap(), expected);
            assert_eq!(derivation_count(), before + 1);
            identities.push(expected);
        }
        for first in 0..identities.len() {
            for second in first + 1..identities.len() {
                assert_ne!(identities[first].0, identities[second].0);
                assert_ne!(identities[first].1, identities[second].1);
            }
        }
    }

    #[test]
    fn identity_commitments_ignore_privacy_domain() {
        let first = DedicatedAccount::from_entropy(
            Zeroizing::new([0x61; 32]),
            7,
            "synthetic-domain-a".into(),
            false,
        )
        .unwrap();
        let second = DedicatedAccount::from_entropy(
            Zeroizing::new([0x61; 32]),
            7,
            "synthetic-domain-b".into(),
            false,
        )
        .unwrap();
        assert_ne!(first.privacy_domain(), second.privacy_domain());
        assert_eq!(first.account_id().unwrap(), second.account_id().unwrap());
        assert_eq!(
            first.full_viewing_key_digest,
            second.full_viewing_key_digest
        );
    }

    #[test]
    fn identity_commitments_decode_and_recover_recompute_and_preserve_quarantine() {
        let expected = canonical_identity_oracle([0x62; 32], 11);
        let before = derivation_count();
        let account = DedicatedAccount::from_entropy(
            Zeroizing::new([0x62; 32]),
            11,
            "synthetic-roundtrip".into(),
            false,
        )
        .unwrap();
        assert_eq!(derivation_count(), before + 1);
        let decoded = DedicatedAccount::decode(&account.encode()).unwrap();
        assert_eq!(derivation_count(), before + 2);
        let words = account.recovery_words().unwrap();
        let recovered =
            DedicatedAccount::recover(&words, 11, "synthetic-recovered".into()).unwrap();
        assert_eq!(derivation_count(), before + 3);
        let decoded_recovered = DedicatedAccount::decode(&recovered.encode()).unwrap();
        assert_eq!(derivation_count(), before + 4);
        for candidate in [&account, &decoded, &recovered, &decoded_recovered] {
            assert_eq!(candidate.account_id().unwrap(), expected.0);
            assert_eq!(candidate.full_viewing_key_digest, expected.1);
        }
        assert_eq!(derivation_count(), before + 4);
        assert!(!account.restored && !account.recovery_required());
        assert!(!decoded.restored && !decoded.recovery_required());
        assert!(recovered.restored && recovered.recovery_required());
        assert!(decoded_recovered.restored && decoded_recovered.recovery_required());
        assert_eq!(decoded.privacy_domain(), account.privacy_domain());
        assert_eq!(
            decoded_recovered.privacy_domain(),
            recovered.privacy_domain()
        );
    }

    #[test]
    fn identity_commitments_preserve_exact_legacy_encoding() {
        let expected = canonical_identity_oracle([0x63; 32], (1 << 31) - 1);
        for restored in [false, true] {
            let account = DedicatedAccount::from_entropy(
                Zeroizing::new([0x63; 32]),
                (1 << 31) - 1,
                "synthetic-legacy".into(),
                restored,
            )
            .unwrap();
            // Legacy bytes are laid out manually, without either new commitment.
            let mut legacy = Zeroizing::new(vec![1, 1, restored as u8, 0xff, 0xff, 0xff, 0x7f]);
            legacy.extend_from_slice(&[0x63; 32]);
            legacy.extend_from_slice(&[16, 0]);
            legacy.extend_from_slice(b"synthetic-legacy");
            // Boolean comparisons intentionally cannot print entropy on failure.
            assert!(account.encode().as_slice() == legacy.as_slice());
            let decoded = DedicatedAccount::decode(&legacy).unwrap();
            assert!(decoded.encode().as_slice() == legacy.as_slice());
            assert_eq!(decoded.account_id().unwrap(), expected.0);
            assert_eq!(decoded.full_viewing_key_digest, expected.1);
            assert_eq!(decoded.restored, restored);
            assert_eq!(decoded.recovery_required(), restored);
        }
    }

    #[test]
    fn identity_commitments_reject_malformed_and_high_index_inputs() {
        let before = derivation_count();
        let mut legacy = Zeroizing::new(vec![1, 1, 0, 0, 0, 0, 0]);
        legacy.extend_from_slice(&[0x64; 32]);
        legacy.extend_from_slice(&[16, 0]);
        legacy.extend_from_slice(b"synthetic-legacy");
        let mut malformed = vec![Zeroizing::new(Vec::new()), Zeroizing::new(vec![0; 40])];
        for (offset, value) in [(0, 2), (1, 2), (2, 2), (39, 15), (41, b' '), (41, 0xff)] {
            let mut bytes = legacy.clone();
            bytes[offset] = value;
            malformed.push(bytes);
        }
        let mut truncated = legacy.clone();
        truncated.pop();
        malformed.push(truncated);
        let mut trailing = legacy.clone();
        trailing.push(0);
        malformed.push(trailing);
        let mut empty_domain = legacy.clone();
        empty_domain.truncate(41);
        empty_domain[39..41].copy_from_slice(&[0, 0]);
        malformed.push(empty_domain);
        let mut long_domain = legacy.clone();
        long_domain.resize(41 + 129, b'a');
        long_domain[39..41].copy_from_slice(&[129, 0]);
        malformed.push(long_domain);
        for bytes in malformed {
            assert!(matches!(
                DedicatedAccount::decode(&bytes),
                Err(Error::InvalidData)
            ));
        }
        for domain in [String::new(), "invalid domain".into(), "a".repeat(129)] {
            assert!(matches!(
                DedicatedAccount::from_entropy(Zeroizing::new([0x64; 32]), 0, domain, false),
                Err(Error::InvalidData)
            ));
        }
        let words = Zeroizing::new(
            Mnemonic::from_entropy_in(Language::English, &[0x64; 32])
                .unwrap()
                .to_string(),
        );
        for index in [1 << 31, u32::MAX] {
            assert!(matches!(
                DedicatedAccount::from_entropy(
                    Zeroizing::new([0x64; 32]),
                    index,
                    "synthetic-legacy".into(),
                    false,
                ),
                Err(Error::InvalidData)
            ));
            let mut bytes = legacy.clone();
            bytes[3..7].copy_from_slice(&index.to_le_bytes());
            assert!(matches!(
                DedicatedAccount::decode(&bytes),
                Err(Error::InvalidData)
            ));
            assert!(matches!(
                DedicatedAccount::recover(&words, index, "synthetic-legacy".into()),
                Err(Error::InvalidData)
            ));
        }
        assert_eq!(derivation_count(), before);
    }

    #[test]
    fn identity_commitments_repeat_without_deriving_keys() {
        let expected = canonical_identity_oracle([0x65; 32], 3);
        let before = derivation_count();
        let account = DedicatedAccount::from_entropy(
            Zeroizing::new([0x65; 32]),
            3,
            "synthetic-repeat".into(),
            false,
        )
        .unwrap();
        assert_eq!(derivation_count(), before + 1);
        for _ in 0..16 {
            assert_eq!(account.account_id().unwrap(), expected.0);
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            assert_eq!(account.birth_identity_commitments().unwrap(), expected);
        }
        assert_eq!(derivation_count(), before + 1);
        let fvk = Zeroizing::new(account.fvk().unwrap().to_bytes());
        assert_eq!(hex::encode(Sha256::digest(fvk.as_slice())), expected.1);
        assert_eq!(derivation_count(), before + 2);
        let key = account.spending_key().unwrap();
        let fvk = Zeroizing::new(FullViewingKey::from(&key).to_bytes());
        assert_eq!(hex::encode(Sha256::digest(fvk.as_slice())), expected.1);
        assert_eq!(derivation_count(), before + 3);
    }

    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    #[test]
    fn identity_commitments_do_not_bypass_born_key_gate() {
        let before = derivation_count();
        let mut account = DedicatedAccount::from_entropy(
            Zeroizing::new([0x66; 32]),
            4,
            "synthetic-born-gate".into(),
            false,
        )
        .unwrap();
        account.born_authority_pending = true;
        let expected = canonical_identity_oracle([0x66; 32], 4);
        for _ in 0..16 {
            assert_eq!(account.account_id().unwrap(), expected.0);
            assert_eq!(account.birth_identity_commitments().unwrap(), expected);
        }
        assert!(matches!(
            account.require_generic_spending_source(),
            Err(Error::Unavailable)
        ));
        assert!(matches!(account.spending_key(), Err(Error::Unavailable)));
        assert_eq!(derivation_count(), before + 1);
        // Viewing-key access still performs its original real derivation and
        // does not authorize the generic spending-key path for a born account.
        let fvk = Zeroizing::new(account.fvk().unwrap().to_bytes());
        assert_eq!(hex::encode(Sha256::digest(fvk.as_slice())), expected.1);
        assert_eq!(derivation_count(), before + 2);
        assert!(matches!(account.spending_key(), Err(Error::Unavailable)));
        assert_eq!(derivation_count(), before + 2);
    }

    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    #[test]
    fn viewing_wallet_key_is_separate_wrapped_and_missing_half_state_refuses_recreation() {
        // Fixed public never-funded account and password, never a user vault.
        let account = DedicatedAccount::from_entropy(
            Zeroizing::new([0x59; 32]),
            0,
            "synthetic-viewing-wallet".into(),
            false,
        )
        .unwrap();
        let words = account.recovery_words().unwrap();
        let verified = PendingAccount { account }.verify_backup(&words).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("synthetic-signer");
        let password = b"public-synthetic-wallet-password";
        let signer = AccountVault::create(&root, verified, password).unwrap();
        let connection = signer.create_viewing_wallet_storage().unwrap();
        let wallet =
            wholepact_wallet::wallet::DedicatedTestnetWallet::from_encrypted_connection(connection)
                .unwrap();
        drop(wallet);
        assert!(signer.create_viewing_wallet_storage().is_err());
        let encrypted = std::fs::read(root.join("viewing-wallet-key.wp")).unwrap();
        assert!(
            !encrypted
                .windows(32)
                .any(|w| w == signer.authority_key.as_slice())
        );
        let mut domain = b"wholepact:dedicated-viewing-wallet-key:v1\0".to_vec();
        domain.extend(signer.account_id().unwrap().as_bytes());
        let plain_key = vault::decrypt(&signer.encryption_key, &domain, &encrypted).unwrap();
        assert_eq!(plain_key.len(), 32);
        assert!(plain_key.as_slice() != signer.authority_key.as_slice());
        assert!(plain_key.as_slice() != signer.encryption_key.as_slice());
        assert!(plain_key.as_slice() != signer.account.spending_key().unwrap().to_bytes());
        assert!(
            !encrypted
                .windows(32)
                .any(|w| w == signer.account.spending_key().unwrap().to_bytes())
        );
        drop(signer);
        let reopened = AccountVault::unlock(&root, password).unwrap();
        drop(reopened.open_viewing_wallet_storage().unwrap());
        std::fs::remove_file(root.join("viewing-wallet-key.wp")).unwrap();
        assert!(matches!(
            reopened.open_viewing_wallet_storage(),
            Err(Error::RecoveryRequired)
        ));
        assert!(matches!(
            reopened.create_viewing_wallet_storage(),
            Err(Error::RecoveryRequired)
        ));
    }
    #[test]
    fn dedicated_bip39_zip32_roundtrip_backup_gate_and_recovery_quarantine() {
        let account = DedicatedAccount::from_entropy(
            Zeroizing::new([0x5a; 32]),
            0,
            "synthetic-agreement".into(),
            false,
        )
        .unwrap();
        let words = account.recovery_words().unwrap();
        assert_eq!(words.split_whitespace().count(), 24);
        let original_id = account.account_id().unwrap();
        let pending = PendingAccount { account };
        let verified = pending.verify_backup(&words).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("new");
        let password = b"synthetic-account-password-only";
        let created = AccountVault::create(&path, verified, password).unwrap();
        assert!(!created.account().recovery_required());
        assert!(!created.live_signing_allowed());
        assert_eq!(created.account_id().unwrap(), original_id);
        let encrypted = std::fs::read(path.join("account.wp")).unwrap();
        assert!(!encrypted.windows(32).any(|w| w == [0x5a; 32]));
        assert!(
            !encrypted
                .windows(words.len())
                .any(|w| w == words.as_bytes())
        );
        drop(created);
        assert!(AccountVault::unlock(&path, b"wrong-synthetic-password").is_err());
        let reopened = AccountVault::unlock(&path, password).unwrap();
        assert_eq!(reopened.account_id().unwrap(), original_id);
        drop(reopened);
        let recovered = DedicatedAccount::recover(&words, 0, "synthetic-agreement".into()).unwrap();
        assert!(recovered.recovery_required());
        assert_eq!(recovered.account_id().unwrap(), original_id);
        let restored =
            AccountVault::persist_recovered(&temp.path().join("restored"), recovered, password)
                .unwrap();
        assert!(restored.account().recovery_required());
        assert!(DedicatedAccount::recover(&words, 1 << 31, "synthetic-agreement".into()).is_err());
        let another = DedicatedAccount::recover(&words, 1, "synthetic-agreement".into()).unwrap();
        assert_ne!(another.account_id().unwrap(), original_id);
        let wrong = Mnemonic::from_entropy(&[0x11; 32]).unwrap().to_string();
        let pending = PendingAccount {
            account: DedicatedAccount::from_entropy(
                Zeroizing::new([0x5a; 32]),
                0,
                "synthetic-agreement".into(),
                false,
            )
            .unwrap(),
        };
        assert!(pending.verify_backup(&wrong).is_err());
    }

    #[test]
    fn encrypted_authority_key_is_independent_persisted_and_missing_journal_quarantines() {
        let account = DedicatedAccount::from_entropy(
            Zeroizing::new([0x6b; 32]),
            0,
            "synthetic-encrypted-authority".into(),
            false,
        )
        .unwrap();
        let words = account.recovery_words().unwrap();
        let verified = PendingAccount { account }.verify_backup(&words).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("account");
        let password = b"synthetic-authority-password-only";
        let mut vault = AccountVault::create(&root, verified, password).unwrap();
        assert_ne!(
            vault.authority_key.as_slice(),
            vault.account.spending_key().unwrap().to_bytes()
        );
        let id = vault.account_id().unwrap();
        let store = vault.create_authority_journal().unwrap();
        assert!(!store.account_state().unwrap().recovery_required);
        drop(store);
        drop(vault);
        let raw = std::fs::read(root.join("authority.sqlite")).unwrap();
        assert!(!raw.starts_with(b"SQLite format 3"));
        assert!(!raw.windows(id.len()).any(|w| w == id.as_bytes()));
        let mut reopened = AccountVault::unlock(&root, password).unwrap();
        let store = reopened.open_authority_journal().unwrap();
        assert_eq!(store.account_state().unwrap().account_id, id);
        drop(store);
        for suffix in [
            "authority.sqlite",
            "authority.sqlite-wal",
            "authority.sqlite-shm",
        ] {
            let _ = std::fs::remove_file(root.join(suffix));
        }
        assert!(matches!(
            reopened.open_authority_journal(),
            Err(Error::RecoveryRequired)
        ));
        assert!(reopened.account().recovery_required());
        assert!(reopened.create_authority_journal().is_err());
        drop(reopened);
        assert!(
            AccountVault::unlock(&root, password)
                .unwrap()
                .account()
                .recovery_required()
        );
    }
}

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
mod recipient_store;

#[cfg(all(
    feature = "authority-signing",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) mod backup;

#[cfg(all(
    feature = "authority-signing",
    feature = "native-ui",
    target_os = "linux"
))]
mod activation;
#[cfg(all(
    feature = "authority-signing",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) use activation::{VerifiedProfileActivation, VerifiedRecoveryPlan};

#[cfg(all(
    test,
    feature = "synthetic-qualification",
    feature = "authority-signing",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) use activation::recovery_profile_fixture_with;

// The native ceremony can publish only a blocked pending envelope. Witness-ack
// activation and remaining historical/backup consumers are still unconnected.
#[cfg(all(
    feature = "authority-signing",
    feature = "native-ui",
    target_os = "linux"
))]
#[allow(dead_code)]
pub(crate) mod birth;

#[cfg(all(
    feature = "authority-signing",
    feature = "native-ui",
    target_os = "linux"
))]
#[path = "account/informational.rs"]
pub(crate) mod informational;
