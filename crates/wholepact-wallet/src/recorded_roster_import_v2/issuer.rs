//! Connected issuer: actual maintained import and its returned account UUID are
//! committed with completion in the SAME SQLite transaction. No constructor can
//! turn an account lookup, request DTO, matching height, or decoded rows into
//! RecordedRosterInventoryImportV2. There is intentionally no reopen/retry method.
use super::super::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryRequestV2;
use wholepact_storage_security::DatabaseFileIdentity;
use zcash_client_backend::data_api::AccountSource;
use zcash_client_sqlite::ExtensionTransaction;
use zeroize::Zeroizing;

#[path = "post_return_history_v1.rs"]
mod post_return_history_v1;
pub(crate) use post_return_history_v1::verify_post_return_history_v1;

const MAX_RECORD: usize = 262_144;
const IMPORTER: &str = "wholepact:dedicated-testnet-orchard-roster-ufvk-import:v2";
const DERIVATION: &str = "dedicated-testnet-legacy-zip32-v1";
const KEY_SOURCE: &str = "explicit local signer viewing export";

#[derive(Debug, thiserror::Error)]
pub enum RecordedRosterImportErrorV2 {
    #[error("recorded import requires the original newly created encrypted wallet")]
    FreshOwnerRequired,
    #[error("recorded import request, source identity or immutable rows disagree")]
    Binding,
    #[error("wallet import provenance is absent, pending or not supported")]
    Incomplete,
    #[error("recorded wallet import failed; durable intent or completion may remain")]
    Storage,
}
type Result<T> = std::result::Result<T, RecordedRosterImportErrorV2>;
impl From<rusqlite::Error> for RecordedRosterImportErrorV2 {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u16,
    importer: String,
    /// Full originally admitted request, including all birthday frontiers, hash,
    /// network/account/FVK identity, attachment, profile and generation binding.
    /// This is archival input, not proof that native permission is current.
    request: ManualRosterInventoryRequestV2,
    request_digest: String,
    /// Exact canonical file destination captured by the original fresh factory.
    actual_wallet_destination: String,
    native_disclosure_evidence_digest: String,
    /// Captured inside the issuer from the encrypted factory's original handle.
    /// Never a caller-provided path or a temporary read-snapshot inode.
    wallet_database_origin_digest: String,
    actual_network: String,
    actual_key_type: String,
    actual_account_purpose: String,
    /// The fixed importer uses AccountBirthday::from_parts(prior, None).
    recover_until: Option<u32>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    version: u16,
    intent_digest: String,
    request_digest: String,
    wallet_database_origin_digest: String,
    /// Obtained from the actual maintained import return inside the transaction.
    /// Never inferred from a subsequently found account with the same FVK.
    returned_account_uuid: [u8; 16],
    actual_fvk_digest: String,
    /// Commits the FULL canonical R0 Orchard-only UFVK encoding. It prevents
    /// treating an Orchard match inside a broad everyday UFVK as this import.
    actual_ufvk_encoding_digest: String,
    first_scan_height: u32,
}

/// Process-local proof that THIS concrete import returned and both records were
/// reread after commit. It is not permission. It is not Clone, Debug, Serialize,
/// Deserialize, or constructible from a file, DTO, receipt bytes, or account UUID.
/// Dropping it does not delete or invalidate the historical database records.
pub struct RecordedRosterInventoryImportV2 {
    account: AccountUuid,
    origin: DatabaseFileIdentity,
    intent_digest: String,
    scope_digest: String,
    request_digest: String,
}
impl RecordedRosterInventoryImportV2 {
    pub fn account_uuid(&self) -> AccountUuid {
        self.account
    }
    /// A fresh-owner correlation check only. A native Host must independently
    /// retain its real attachment/Directory and current signer/admission owners.
    pub fn check_request_scope_and_account(
        &self,
        request_digest: &str,
        scope_digest: &str,
        account: AccountUuid,
    ) -> Result<()> {
        self.origin
            .check_retained_owner_path()
            .map_err(|_| RecordedRosterImportErrorV2::Binding)?;
        if self.request_digest != request_digest
            || self.scope_digest != scope_digest
            || self.account != account
        {
            return Err(RecordedRosterImportErrorV2::Binding);
        }
        Ok(())
    }
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
    pub fn intent_digest(&self) -> &str {
        &self.intent_digest
    }
}

fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    Ok(())
}
fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(value).map_err(|_| RecordedRosterImportErrorV2::Binding)?,
    );
    if bytes.is_empty() || bytes.len() > MAX_RECORD {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    Ok(bytes)
}
fn decode<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    let value =
        serde_json::from_slice::<T>(bytes).map_err(|_| RecordedRosterImportErrorV2::Binding)?;
    if encode(&value)?.as_slice() != bytes {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    Ok(value)
}
fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value)
        .map_err(|_| RecordedRosterImportErrorV2::Binding)
}
impl Intent {
    fn validate(&self) -> Result<()> {
        self.request
            .validate()
            .map_err(|_| RecordedRosterImportErrorV2::Binding)?;
        hash(&self.request_digest)?;
        if self.request_digest
            != self
                .request
                .digest()
                .map_err(|_| RecordedRosterImportErrorV2::Binding)?
            || self.actual_wallet_destination != self.request.scope.inventory.wallet_destination
        {
            return Err(RecordedRosterImportErrorV2::Binding);
        }
        hash(&self.native_disclosure_evidence_digest)?;
        hash(&self.wallet_database_origin_digest)?;
        let identity = &self.request.scope.inventory.enrollment.identity;
        if self.version != 2
            || self.importer != IMPORTER
            || self.actual_network != "zcash_testnet"
            || self.actual_key_type != "ufvk_r0_orchard_only"
            || self.actual_account_purpose != "imported_spending_derivation_none"
            || self.recover_until.is_some()
            || identity.network_profile_id != wholepact_protocol::construction::PROFILE_ID
            || identity.derivation_domain != DERIVATION
        {
            return Err(RecordedRosterImportErrorV2::Binding);
        }
        // The same bounded maintained parser supplies the actual importer.
        self.birthday()?;
        encode(self)?;
        Ok(())
    }
    fn birthday(&self) -> Result<AccountBirthday> {
        let b = &self.request.scope.inventory.birthday;
        protected_sync::account_birthday_from_tree(protected_sync::TreeState {
            network: "test".into(),
            height: u64::from(b.prior_height),
            hash: b.prior_block_hash.clone(),
            sapling_tree: b.sapling_tree.clone(),
            orchard_tree: b.orchard_tree.clone(),
            ironwood_tree: b.ironwood_tree.clone(),
            ..Default::default()
        })
        .map_err(|_| RecordedRosterImportErrorV2::Binding)
    }
    fn digest(&self) -> Result<String> {
        digest("wholepact:recorded-roster-wallet-import-intent:v2", self)
    }
}
impl Completion {
    fn require_intent(&self, intent: &Intent) -> Result<()> {
        intent.validate()?;
        hash(&self.intent_digest)?;
        hash(&self.request_digest)?;
        hash(&self.wallet_database_origin_digest)?;
        hash(&self.actual_fvk_digest)?;
        hash(&self.actual_ufvk_encoding_digest)?;
        if self.version != 2
            || self.intent_digest != intent.digest()?
            || self.request_digest != intent.request_digest
            || self.wallet_database_origin_digest != intent.wallet_database_origin_digest
            || self.actual_fvk_digest
                != intent
                    .request
                    .scope
                    .inventory
                    .enrollment
                    .identity
                    .full_viewing_key_digest
            || Some(self.first_scan_height)
                != intent
                    .request
                    .scope
                    .inventory
                    .birthday
                    .prior_height
                    .checked_add(1)
            || self.returned_account_uuid == [0; 16]
        {
            return Err(RecordedRosterImportErrorV2::Binding);
        }
        Ok(())
    }
}
fn count(ext: &ExtensionTransaction<'_>) -> Result<i64> {
    Ok(ext.query_row(
        "SELECT count(*) FROM ext_wholepact_roster_import_records_v2",
        [],
        |r| r.get(0),
    )?)
}
fn load<T: Serialize + DeserializeOwned>(
    ext: &ExtensionTransaction<'_>,
    sequence: i64,
) -> Result<T> {
    let (version, bytes): (i64, Vec<u8>) = ext.query_row(
        "SELECT format_version,record FROM ext_wholepact_roster_import_records_v2 WHERE sequence=?1",
        [sequence],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let bytes = Zeroizing::new(bytes);
    if version != 2 {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    decode(&bytes)
}
fn insert<T: Serialize>(ext: &ExtensionTransaction<'_>, sequence: i64, value: &T) -> Result<()> {
    let bytes = encode(value)?;
    if ext.execute(
        "INSERT INTO ext_wholepact_roster_import_records_v2(sequence,format_version,record) VALUES(?1,2,?2)",
        rusqlite::params![sequence, bytes.as_slice()],
    )? != 1
    {
        return Err(RecordedRosterImportErrorV2::Storage);
    }
    Ok(())
}
fn require_pending(ext: &ExtensionTransaction<'_>, expected: &Intent) -> Result<()> {
    if count(ext)? != 1 || &load::<Intent>(ext, 0)? != expected {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    Ok(())
}
fn require_completed(
    ext: &ExtensionTransaction<'_>,
    intent: &Intent,
    completed: &Completion,
) -> Result<()> {
    if count(ext)? != 2
        || &load::<Intent>(ext, 0)? != intent
        || &load::<Completion>(ext, 1)? != completed
    {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    completed.require_intent(intent)
}

impl DedicatedTestnetWallet {
    /// Inert input is accepted only by the actual importer. The native Host must
    /// verify its concrete fresh profile, actual attachment/generation, live
    /// V2 roster inventory admission and signer lease first.
    /// No caller callback, bool, success flag, UUID or AccountBirthday is accepted.
    ///
    /// The original fresh origin is consumed even on error. There is no automatic
    /// retry or adoption of an existing account. Pending intent survives failure.
    pub fn import_recorded_roster_inventory_fvk_v2(
        &mut self,
        authenticated_fvk: &FullViewingKey,
        request: &ManualRosterInventoryRequestV2,
        native_disclosure_evidence_digest: &str,
    ) -> Result<RecordedRosterInventoryImportV2> {
        let (origin, actual_wallet_destination) = self
            .recorded_roster_import_origin_v2
            .take()
            .ok_or(RecordedRosterImportErrorV2::FreshOwnerRequired)?;
        origin
            .check_retained_owner_path()
            .map_err(|_| RecordedRosterImportErrorV2::Binding)?;
        let intent = Intent {
            version: 2,
            importer: IMPORTER.into(),
            request: request.clone(),
            request_digest: request
                .digest()
                .map_err(|_| RecordedRosterImportErrorV2::Binding)?,
            actual_wallet_destination,
            native_disclosure_evidence_digest: native_disclosure_evidence_digest.into(),
            wallet_database_origin_digest: hex::encode(origin.origin_commitment()),
            actual_network: "zcash_testnet".into(),
            actual_key_type: "ufvk_r0_orchard_only".into(),
            actual_account_purpose: "imported_spending_derivation_none".into(),
            recover_until: None,
        };
        intent.validate()?;
        let fvk_bytes = Zeroizing::new(authenticated_fvk.to_bytes());
        let fvk_digest = hex::encode(Sha256::digest(fvk_bytes.as_slice()));
        if fvk_digest
            != intent
                .request
                .scope
                .inventory
                .enrollment
                .identity
                .full_viewing_key_digest
        {
            return Err(RecordedRosterImportErrorV2::Binding);
        }
        let unified = unified::Ufvk::try_from_items(
            zcash_protocol::address::Revision::R0,
            vec![unified::Uitem::Data(unified::Fvk::Orchard(*fvk_bytes))],
        )
        .map_err(|_| RecordedRosterImportErrorV2::Binding)?;
        let encoded = Zeroizing::new(unified.encode(&NetworkType::Test));
        let ufvk = UnifiedFullViewingKey::decode(&TEST_NETWORK, &encoded)
            .map_err(|_| RecordedRosterImportErrorV2::Binding)?;
        let ufvk_digest = hex::encode(Sha256::digest(encoded.as_bytes()));
        let birthday = intent.birthday()?;
        let first_scan_height = intent
            .request
            .scope
            .inventory
            .birthday
            .prior_height
            .checked_add(1)
            .ok_or(RecordedRosterImportErrorV2::Binding)?;

        // Durable intent precedes every maintained import effect. Existing intent,
        // completion, account, or malformed partial history cannot be overwritten.
        self.db
            .transactionally_with_extension(|db, ext| -> Result<()> {
                if count(ext)? != 0
                    || !db
                        .get_account_ids()
                        .map_err(|_| RecordedRosterImportErrorV2::Storage)?
                        .is_empty()
                {
                    return Err(RecordedRosterImportErrorV2::Binding);
                }
                insert(ext, 0, &intent)
            })?;
        origin
            .check_retained_owner_path()
            .map_err(|_| RecordedRosterImportErrorV2::Binding)?;

        // SQLite owns the crash boundary: account import and completion either
        // both commit, or intent alone remains. No receipt is minted retrospectively.
        let (account, completion) = self.db.transactionally_with_extension(|db, ext| -> Result<_> {
            require_pending(ext, &intent)?;
            if !db.get_account_ids().map_err(|_| RecordedRosterImportErrorV2::Storage)?.is_empty() {
                return Err(RecordedRosterImportErrorV2::Binding);
            }
            let returned = db.import_account_ufvk(
                "Wholepact dedicated participation", &ufvk, &birthday,
                AccountPurpose::Spending { derivation: None }, Some(KEY_SOURCE),
            ).map_err(|_| RecordedRosterImportErrorV2::Storage)?;
            let account = returned.id();
            if db.get_account_ids().map_err(|_| RecordedRosterImportErrorV2::Storage)? != vec![account] {
                return Err(RecordedRosterImportErrorV2::Binding);
            }
            let actual = db.get_account(account).map_err(|_| RecordedRosterImportErrorV2::Storage)?.ok_or(RecordedRosterImportErrorV2::Binding)?;
            let actual_encoding = Zeroizing::new(actual.ufvk().ok_or(RecordedRosterImportErrorV2::Binding)?
                .encode_revision(&TEST_NETWORK, zcash_protocol::address::Revision::R0).map_err(|_| RecordedRosterImportErrorV2::Binding)?);
            if actual_encoding.as_str() != encoded.as_str()
                || u32::from(db.get_account_birthday(account).map_err(|_| RecordedRosterImportErrorV2::Storage)?) != first_scan_height
                || !matches!(actual.source(), AccountSource::Imported { purpose: AccountPurpose::Spending { derivation: None }, key_source } if key_source.as_deref() == Some(KEY_SOURCE))
            { return Err(RecordedRosterImportErrorV2::Binding); }
            let completion = Completion {
                version: 2, intent_digest: intent.digest()?, request_digest: intent.request_digest.clone(),
                wallet_database_origin_digest: intent.wallet_database_origin_digest.clone(),
                returned_account_uuid: *account.expose_uuid().as_bytes(),
                actual_fvk_digest: fvk_digest.clone(), actual_ufvk_encoding_digest: ufvk_digest.clone(), first_scan_height,
            };
            completion.require_intent(&intent)?;
            insert(ext, 1, &completion)?;
            origin.check_retained_owner_path().map_err(|_| RecordedRosterImportErrorV2::Binding)?;
            Ok((account, completion))
        })?;
        origin
            .check_retained_owner_path()
            .map_err(|_| RecordedRosterImportErrorV2::Binding)?;
        self.db
            .transactionally_with_extension(|db, ext| -> Result<()> {
                require_completed(ext, &intent, &completion)?;
                if db
                    .get_account_ids()
                    .map_err(|_| RecordedRosterImportErrorV2::Storage)?
                    != vec![account]
                {
                    return Err(RecordedRosterImportErrorV2::Binding);
                }
                Ok(())
            })?;
        Ok(RecordedRosterInventoryImportV2 {
            account,
            origin,
            intent_digest: intent.digest()?,
            request_digest: intent.request_digest.clone(),
            scope_digest: intent
                .request
                .scope
                .pairing_digest()
                .map_err(|_| RecordedRosterImportErrorV2::Binding)?,
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
