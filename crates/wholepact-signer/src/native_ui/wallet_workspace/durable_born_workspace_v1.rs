//! Fresh native, ephemeral viewing workspace for an original born account.
//! This never adds a wallet to the immutable vault inventory, opens an old
//! cache, restores consent, exports material, or alters durable exposure.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1;
use crate::files::PrivateDirectory;
use std::{os::unix::fs::PermissionsExt, path::Path};
use wholepact_storage_security::{DatabaseKey, create_encrypted};

const PURPOSE: &str = "fresh_born_ephemeral_viewing_wallet_v1";
const RETENTION: &str = "current_native_owner_only";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableBornWalletConfigV1 {
    schema_version: u32,
    purpose: String,
    policy: WalletKeyUsePolicy,
    birthday: BirthdayCheckpoint,
    maximum_blocks: u32,
    retention: String,
}
impl DurableBornWalletConfigV1 {
    fn decode(json: &str) -> Result<Self> {
        if json.is_empty() || json.len() > MAX_SETUP {
            return Err(Error::InvalidData);
        }
        let value: Self =
            wholepact_core::parse_typed_json(json.as_bytes()).map_err(|_| Error::InvalidData)?;
        if value.schema_version != 1
            || value.purpose != PURPOSE
            || value.retention != RETENTION
            || !(1..=1000).contains(&value.maximum_blocks)
            || value.policy.confidence != WalletKeyUseConfidence::TrustedSingleProviderSnapshot
            || !(1..=300).contains(&value.policy.maximum_observation_age_seconds)
            || !(1..=100).contains(&value.policy.minimum_confirmations)
            || value.policy.minimum_expiry_margin_blocks == 0
            || value.policy.source_id.is_empty()
            || value.policy.source_id.len() > 128
            || value.policy.endpoint.is_empty()
            || value.policy.endpoint.len() > 2048
            || value.policy.endpoint.ends_with('/')
        {
            return Err(Error::InvalidData);
        }
        Ok(value)
    }
    fn birthday(&self) -> Result<AccountBirthday> {
        account_birthday_from_tree(TreeState {
            network: "test".into(),
            height: u64::from(self.birthday.prior_height),
            hash: self.birthday.prior_block_hash.clone(),
            sapling_tree: self.birthday.sapling_tree.clone(),
            orchard_tree: self.birthday.orchard_tree.clone(),
            ironwood_tree: self.birthday.ironwood_tree.clone(),
            ..Default::default()
        })
        .map_err(|_| Error::InvalidData)
    }
}

/// Retained actual source, not a record-based permission or a closure supplied
/// by the host. Access checks deliberately take no journal authority lock.
pub(super) struct DurableBornWalletSourceV1 {
    source: Arc<FreshDurableBornEntryV1>,
    account_id: String,
    fvk_digest: String,
}
impl DurableBornWalletSourceV1 {
    pub(super) fn check(&self, origin: &NativeAuthorityBinding) -> Result<()> {
        self.source.check_original_source_current()?;
        if &self.source.native_binding() != origin
            || self.source.account().recovery_required()
            || self.source.account().account_id()? != self.account_id
            || hex::encode(Sha256::digest(self.source.account().fvk()?.to_bytes()))
                != self.fvk_digest
        {
            return Err(Error::ReviewMismatch);
        }
        origin.check_current()
    }
}

/// Must be the LAST field of NativeWalletWorkspace. Rust drops fields in their
/// declaration order: maintained controller/connection first, then this lock,
/// then the owned temporary directory. Moving a workspace to a scan/sign worker
/// moves this non-cloneable guard with it; cancellation cannot delete its DB
/// while that worker still owns the controller. Cleanup is best effort, not a
/// secure-erasure promise, and never targets an original vault or journal.
pub(super) struct DurableBornWalletDirectoryV1 {
    _lock: PrivateDirectory,
    temporary: tempfile::TempDir,
}
impl DurableBornWalletDirectoryV1 {
    fn create(source: &FreshDurableBornEntryV1) -> Result<Self> {
        source.check_original_source_current()?;
        let original = std::fs::canonicalize(source.original_root())?;
        let parent = std::fs::canonicalize(std::env::temp_dir())?;
        if parent.starts_with(&original) {
            return Err(Error::InvalidData);
        }
        let temporary = tempfile::Builder::new()
            .prefix("wholepact-durable-viewing-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)?;
        if std::fs::canonicalize(temporary.path())?.starts_with(&original) {
            return Err(Error::InvalidData);
        }
        let lock = PrivateDirectory::open(temporary.path())?;
        source.check_original_source_current()?;
        Ok(Self {
            _lock: lock,
            temporary,
        })
    }
    fn path(&self) -> &Path {
        self.temporary.path()
    }
}

pub(in crate::native_ui) struct PreparedDurableBornWalletSetupV1 {
    config: DurableBornWalletConfigV1,
    chain: ChainAdapter,
    birthday: AccountBirthday,
    source: DurableBornWalletSourceV1,
    native_origin: NativeAuthorityBinding,
    digest: String,
}
impl PreparedDurableBornWalletSetupV1 {
    pub(in crate::native_ui) fn prepare(
        json: &str,
        source: Arc<FreshDurableBornEntryV1>,
        authority: &NativeAuthority,
    ) -> Result<Self> {
        authority.check_current()?;
        source.check_current()?;
        let native_origin = authority.binding();
        let source = DurableBornWalletSourceV1 {
            account_id: source.account().account_id()?,
            fvk_digest: hex::encode(Sha256::digest(source.account().fvk()?.to_bytes())),
            source,
        };
        source.check(&native_origin)?;
        let config = DurableBornWalletConfigV1::decode(json)?;
        let birthday = config.birthday()?;
        // Captures the supported existing proxy/TLS configuration without any
        // provider contact. No synthetic or direct-route fallback is accepted.
        let chain = ChainAdapter::testnet(
            &config.policy.source_id,
            &config.policy.endpoint,
            NetworkPolicy {
                observation_ttl: Duration::from_secs(u64::from(
                    config.policy.maximum_observation_age_seconds,
                )),
                ..Default::default()
            },
        )
        .map_err(|_| Error::InvalidData)?;
        let mut digest = Sha256::new();
        digest.update(b"wholepact:native-born-ephemeral-viewing-setup:v1\0");
        digest.update(crate::vault::random::<32>()?);
        digest.update(native_origin.entry_digest().as_bytes());
        digest.update(source.account_id.as_bytes());
        digest.update(source.fvk_digest.as_bytes());
        digest.update(serde_json::to_vec(&config).map_err(|_| Error::InvalidData)?);
        source.check(&native_origin)?;
        Ok(Self {
            config,
            chain,
            birthday,
            source,
            native_origin,
            digest: hex::encode(digest.finalize()),
        })
    }
    pub(in crate::native_ui) fn digest(&self) -> &str {
        &self.digest
    }
    pub(in crate::native_ui) fn display(&self) -> Result<String> {
        self.source.check(&self.native_origin)?;
        let remaining_seconds = self
            .native_origin
            .bounded_deadline()?
            .saturating_duration_since(Instant::now())
            .as_secs();
        Ok(format!(
            "CREATE FRESH EPHEMERAL SIGNER-LOCAL VIEWING WALLET\nAccount: {}\nFVK digest: {}\nExact configuration:\n{}\n\nThis new decision permits importing this actual born account's dedicated FVK and the complete displayed birthday checkpoint into a new private encrypted temporary database OUTSIDE the original vault. It permits only bounded public-block synchronization and local input selection only while this exact native owner remains live. At display, that owner has about {} seconds remaining from its ORIGINAL deadline, which started before unlock. Approval, scan progress and retry never refresh that deadline. It does NOT approve metadata/material export, witness disclosure, or spending.\nThe chosen provider and captured existing proxy can observe IP, timing, public block heights and history ranges. No FVK, private note or nullifier is sent to that provider. Trust is one explicitly chosen TLS provider, not independent consensus or global unspentness. Reorganizations, absent mempool conflicts and other-wallet spends remain possible. A wrong or too-late birthday can omit history.\nThis initial profile is limited to short-history dedicated accounts whose setup, bounded scans and review can finish within the remaining native lifetime. Committed partial scan batches may be retried only with the same still-live controller; they do not transfer to a fresh owner.\nThe independent database key remains only in memory. There is no open, resume or silent recreation route. After lock, expiry or restart, another explicit setup and bounded rescan is required. Workers retain the temporary database until their actual controller closes; cleanup is best effort and does not guarantee secure erasure after a crash. Loss or deletion of this cache never clears, refunds or replaces original signer journal or witness exposure. Long-lived disclosure validity does not extend this wallet permission.",
            self.source.account_id,
            self.source.fvk_digest,
            serde_json::to_string_pretty(&self.config).map_err(|_| Error::InvalidData)?,
            remaining_seconds,
        ))
    }
    pub(in crate::native_ui) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<NativeWalletWorkspace> {
        authority.check_current()?;
        self.source.source.check_current()?;
        self.source.check(&self.native_origin)?;
        if decision.binding() != &self.native_origin
            || authority.binding() != self.native_origin
            || decision.reviewed_digest() != self.digest
            || decision.consumed_at().elapsed() >= ACCESS_LIFETIME
        {
            return Err(Error::ReviewMismatch);
        }
        // Declare the owned directory before all database handles so constructor
        // failure also drops handles first and cleans only this newly owned cache.
        let directory = DurableBornWalletDirectoryV1::create(&self.source.source)?;
        self.source.check(&self.native_origin)?;
        let key = DatabaseKey::from_bytes(crate::vault::random::<32>()?);
        let connection = create_encrypted(directory.path().join("viewing.sqlite"), &key)
            .map_err(|_| Error::Unavailable)?;
        // The factory has keyed the actual connection; this zeroizing Rust key
        // is no longer needed and is never persisted or returned to a caller.
        drop(key);
        let identity = connection
            .database_identity()
            .map_err(|_| Error::Verification)?;
        identity
            .check_current(connection.connection())
            .map_err(|_| Error::Verification)?;
        self.source.check(&self.native_origin)?;
        let mut wallet = DedicatedTestnetWallet::from_encrypted_connection(connection)
            .map_err(|_| Error::RecoveryRequired)?;
        // Migrations may be slow. Recheck BEFORE the first private FVK write,
        // not just before opening/migrating an otherwise empty cache.
        self.source.check(&self.native_origin)?;
        identity
            .check_retained_owner_path()
            .map_err(|_| Error::Verification)?;
        let fvk = self.source.source.account().fvk()?;
        {
            let _lease = self.native_origin.publication_lease()?;
            self.source.check(&self.native_origin)?;
            identity
                .check_retained_owner_path()
                .map_err(|_| Error::Verification)?;
            wallet
                .import_dedicated_fvk(&fvk, self.birthday)
                .map_err(|_| Error::RecoveryRequired)?;
            self.source.check(&self.native_origin)?;
            identity
                .check_retained_owner_path()
                .map_err(|_| Error::Verification)?;
        }
        let minimum =
            NonZeroU32::new(self.config.policy.minimum_confirmations).ok_or(Error::InvalidData)?;
        let controller = ProtectedWalletSync::from_initialized_wallet(wallet, self.chain, minimum)
            .map_err(|_| Error::RecoveryRequired)?;
        controller
            .verify_account_fvk(&fvk)
            .map_err(|_| Error::Verification)?;
        self.source.source.check_current()?;
        self.source.check(&self.native_origin)?;
        identity
            .check_retained_owner_path()
            .map_err(|_| Error::Verification)?;
        let account_id = self.source.account_id.clone();
        let access = NativeWalletAccess {
            account: controller.account_uuid(),
            source: controller.status().map_err(|_| Error::Verification)?.source,
            origin: self.native_origin,
            revocation: NativeWalletRevocation {
                active: Arc::new(AtomicBool::new(true)),
            },
            approved: decision.consumed_at(),
            durable_source: Some(self.source),
        };
        let workspace = NativeWalletWorkspace {
            controller,
            access,
            fvk,
            account_id,
            policy: self.config.policy,
            maximum_blocks: self.config.maximum_blocks,
            ticket: None,
            ephemeral_directory: Some(directory),
        };
        workspace.check_current()?;
        Ok(workspace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1, "purpose": PURPOSE, "retention": RETENTION,
            "maximum_blocks": 100,
            "policy": {"confidence":"trusted_single_provider_snapshot", "source_id":"test-source",
                "endpoint":"https://example.invalid", "maximum_observation_age_seconds":30,
                "minimum_confirmations":1, "minimum_expiry_margin_blocks":5},
            "birthday": {"prior_height":4465039, "prior_block_hash":"11".repeat(32),
                "sapling_tree":"000000", "orchard_tree":"000000", "ironwood_tree":"000000"}
        })
    }
    #[test]
    fn new_purpose_requires_full_birthday_and_refuses_resume_or_destination() {
        assert!(DurableBornWalletConfigV1::decode(&config().to_string()).is_ok());
        for field in ["action", "path", "destination", "open", "resume"] {
            let mut value = config();
            value[field] = "open".into();
            assert!(DurableBornWalletConfigV1::decode(&value.to_string()).is_err());
        }
        for field in ["birthday", "retention", "purpose"] {
            let mut value = config();
            value.as_object_mut().unwrap().remove(field);
            assert!(DurableBornWalletConfigV1::decode(&value.to_string()).is_err());
        }
        for field in [
            "sapling_tree",
            "orchard_tree",
            "ironwood_tree",
            "prior_block_hash",
        ] {
            let mut value = config();
            value["birthday"].as_object_mut().unwrap().remove(field);
            assert!(DurableBornWalletConfigV1::decode(&value.to_string()).is_err());
        }
    }
    #[test]
    fn ephemeral_policy_refuses_purpose_reuse_synthetic_confidence_and_widened_bounds() {
        for field in ["purpose", "retention"] {
            let mut value = config();
            value[field] = "ordinary_wallet_setup".into();
            assert!(DurableBornWalletConfigV1::decode(&value.to_string()).is_err());
        }
        for blocks in [0, 1001] {
            let mut value = config();
            value["maximum_blocks"] = blocks.into();
            assert!(DurableBornWalletConfigV1::decode(&value.to_string()).is_err());
        }
        let mut value = config();
        value["policy"]["confidence"] = "synthetic_never_chain_evidence".into();
        assert!(DurableBornWalletConfigV1::decode(&value.to_string()).is_err());
        let mut value = config();
        value["birthday"]["ironwood_tree"] = "malformed".into();
        assert!(
            DurableBornWalletConfigV1::decode(&value.to_string())
                .unwrap()
                .birthday()
                .is_err()
        );
    }
}
