//! Pending-only provisioning foundation. A birth anchor records exact historical
//! native intent, never witness acknowledgement or current signing authority.
//! The private native pending ceremony may publish this blocked envelope. Witness
//! genesis acknowledgement and protected backup/restore composition are missing.
use super::{AccountVault, BackupVerifiedAccount, DedicatedAccount};
use crate::{
    Error, Result,
    files::PrivateDirectory,
    native_ui::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority},
    vault,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use wholepact_authority::{AccountPolicy, WitnessDisclosureDescriptor};
use zeroize::Zeroizing;

// A distinct envelope, deliberately rejected by AccountVault::unlock. There is
// no conversion into AccountVault, no authority key/journal and no ack method.
const PENDING_MAGIC: &[u8; 8] = b"WPACB001";
const MAX_PENDING_BYTES: usize = 128 * 1024;
const MAX_ANCHOR_BYTES: usize = 96 * 1024;
const NETWORK: &str = "ironwood-testnet-nu7-candidate";
const DERIVATION_DOMAIN: &str = "dedicated-testnet-legacy-zip32-v1";
const REVIEW_LIFETIME: Duration = Duration::from_secs(120);

/// Audit data only. Account ID and raw FVK digest are independently retained;
/// later exclusion matching must reject either collision regardless of labels.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BirthIdentity {
    account_id: String,
    full_viewing_key_digest: String,
    network_profile_id: String,
    derivation_domain: String,
    exact_derivation: String,
}
impl BirthIdentity {
    fn derive(account: &DedicatedAccount) -> Result<Self> {
        let (account_id, full_viewing_key_digest) = account.birth_identity_commitments()?;
        Ok(Self {
            account_id,
            full_viewing_key_digest,
            network_profile_id: NETWORK.into(),
            derivation_domain: DERIVATION_DOMAIN.into(),
            exact_derivation: account.derivation(),
        })
    }
    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }
    pub(crate) fn full_viewing_key_digest(&self) -> &str {
        &self.full_viewing_key_digest
    }
    pub(crate) fn network_profile_id(&self) -> &str {
        &self.network_profile_id
    }
    pub(crate) fn derivation_domain(&self) -> &str {
        &self.derivation_domain
    }
    pub(crate) fn exact_derivation(&self) -> &str {
        &self.exact_derivation
    }
}

/// Original selected origin, not an authenticated witness response. It omits
/// policy_digest: the final policy may include a genesis referencing this birth.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BirthWitnessOrigin {
    endpoint: String,
    server_name: String,
    witness_id: String,
    pinned_server_certificate_digest: String,
}
impl BirthWitnessOrigin {
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub(crate) fn server_name(&self) -> &str {
        &self.server_name
    }
    pub(crate) fn witness_id(&self) -> &str {
        &self.witness_id
    }
    pub(crate) fn pinned_server_certificate_digest(&self) -> &str {
        &self.pinned_server_certificate_digest
    }
    /// Exact four-string tuple shared with the witness genesis contract. No
    /// enrolled policy digest is included, so genesis/birth commitments are acyclic.
    pub(crate) fn digest(&self) -> Result<String> {
        canonical(
            "wholepact:account-use-witness-origin:v1",
            &(
                self.endpoint.as_str(),
                self.server_name.as_str(),
                self.witness_id.as_str(),
                self.pinned_server_certificate_digest.as_str(),
            ),
        )
    }
}

/// Explicit v1 genesis-free policy terms, with significant list order. Neither
/// AccountPolicy.policy_digest nor a future account-use genesis is part of this
/// commitment, avoiding policy -> genesis -> birth -> policy digest recursion.
/// New policy fields fail closed at projection until this version is reviewed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalPolicyTerms {
    witness_id: String,
    account_id: String,
    network_profile_id: String,
    owner_certificate_digest: String,
    initial_writer_certificate_digest: String,
    initial_writer_epoch: u64,
    enrollment_refs: Vec<String>,
    agreement_ids: Vec<String>,
    recipient_scope_digests: Vec<String>,
    aggregate_budget_zatoshis: u64,
    per_operation_limit_zatoshis: u64,
    maximum_fee_share_zatoshis: u64,
    maximum_transaction_fee_zatoshis: u64,
    maximum_permit_lifetime_ms: u64,
    policy_expires_at_ms: u64,
}
impl OriginalPolicyTerms {
    fn from_policy(policy: &AccountPolicy) -> Result<Self> {
        policy.validate().map_err(|_| Error::InvalidData)?;
        // Do not silently drop newly introduced authority semantics. An absent,
        // skipped optional genesis is compatible; positive genesis is rejected.
        serde_json::from_value(serde_json::to_value(policy).map_err(|_| Error::InvalidData)?)
            .map_err(|_| Error::InvalidData)
    }
    fn validate(&self) -> Result<()> {
        let policy: AccountPolicy =
            serde_json::from_value(serde_json::to_value(self).map_err(|_| Error::InvalidData)?)
                .map_err(|_| Error::InvalidData)?;
        policy.validate().map_err(|_| Error::InvalidData)
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical("wholepact:account-birth-original-policy-terms:v1", self)
    }
    pub(crate) fn owner_certificate_digest(&self) -> &str {
        &self.owner_certificate_digest
    }
    pub(crate) fn initial_writer_certificate_digest(&self) -> &str {
        &self.initial_writer_certificate_digest
    }
    /// Public metadata only. This is deliberately not an enrollment or policy
    /// constructor: consumers must compare the complete exact serialized terms.
    pub(crate) fn audit_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|_| Error::InvalidData)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BirthIntent {
    version: u16,
    operation_id: String,
    generation_instance_id: String,
    identity: BirthIdentity,
    witness_origin: BirthWitnessOrigin,
    original_policy_terms: OriginalPolicyTerms,
    original_policy_terms_digest: String,
    native_principal_id: String,
    native_measurement: String,
    original_target: String,
}
impl BirthIntent {
    fn validate(&self, account: &DedicatedAccount) -> Result<()> {
        if account.restored {
            return Err(Error::InvalidData);
        }
        self.validate_identity(&BirthIdentity::derive(account)?)
    }
    // Historical identity validation never changes a recovered/imported flag.
    fn validate_identity(&self, actual: &BirthIdentity) -> Result<()> {
        if !matches!(self.version, 1 | 2)
            || self.operation_id.len() != 38
            || !self.operation_id.starts_with("birth-")
            || !self.operation_id[6..].bytes().all(is_hex)
            || !is_hash(&self.generation_instance_id)
            || &self.identity != actual
            || self.original_policy_terms.account_id != self.identity.account_id
            || self.original_policy_terms.network_profile_id != NETWORK
            || self.original_policy_terms.witness_id != self.witness_origin.witness_id
            || self.original_policy_terms_digest != self.original_policy_terms.digest()?
            || self.native_principal_id.is_empty()
            || self.native_principal_id.len() > 128
            || !self
                .native_principal_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
            || !is_hash(&self.native_measurement)
            || self.original_target.len() > 4096
            || !Path::new(&self.original_target).is_absolute()
        {
            return Err(Error::InvalidData);
        }
        // Reuse the real public origin validator without asserting that this
        // pre-genesis commitment is the eventual enrolled policy digest.
        WitnessDisclosureDescriptor {
            endpoint: self.witness_origin.endpoint.clone(),
            server_name: self.witness_origin.server_name.clone(),
            witness_id: self.witness_origin.witness_id.clone(),
            account_id: self.identity.account_id.clone(),
            network_profile_id: self.identity.network_profile_id.clone(),
            policy_digest: self.original_policy_terms_digest.clone(),
            pinned_server_certificate_digest: self
                .witness_origin
                .pinned_server_certificate_digest
                .clone(),
        }
        .validate()
        .map_err(|_| Error::InvalidData)
    }
    fn digest(&self) -> Result<String> {
        if self.version != 1 {
            return Err(Error::InvalidData);
        }
        canonical("wholepact:native-account-birth-intent:v1", self)
    }
}

/// Immutable authenticated-at-rest historical intent. Deserializing this data
/// does not authenticate a native surface or create any capability.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BirthAnchor {
    intent: BirthIntent,
    recipient_policy_v2:
        Option<wholepact_core::born_recipient_policy_v2::BornConstructionRecipientPolicyV2>,
    birth_digest: String,
}
impl BirthAnchor {
    fn validate(&self, account: &DedicatedAccount) -> Result<()> {
        self.intent.validate(account)?;
        if self.birth_digest != self.versioned_digest()? {
            return Err(Error::InvalidData);
        }
        Ok(())
    }
    /// Historical linkage only. Actual recovered key identity must still match
    /// the immutable original anchor; this never qualifies a new account birth.
    pub(crate) fn validate_historical_account(&self, account: &DedicatedAccount) -> Result<()> {
        self.intent
            .validate_identity(&BirthIdentity::derive(account)?)?;
        if self.birth_digest != self.versioned_digest()? {
            return Err(Error::InvalidData);
        }
        Ok(())
    }
    pub(crate) fn birth_digest(&self) -> &str {
        &self.birth_digest
    }
    pub(crate) fn operation_id(&self) -> &str {
        &self.intent.operation_id
    }
    pub(crate) fn generation_instance_id(&self) -> &str {
        &self.intent.generation_instance_id
    }
    pub(crate) fn identity(&self) -> &BirthIdentity {
        &self.intent.identity
    }
    pub(crate) fn witness_origin(&self) -> &BirthWitnessOrigin {
        &self.intent.witness_origin
    }
    pub(crate) fn original_policy_terms(&self) -> &OriginalPolicyTerms {
        &self.intent.original_policy_terms
    }
    pub(crate) fn original_policy_terms_digest(&self) -> &str {
        &self.intent.original_policy_terms_digest
    }
    pub(crate) fn native_principal_id(&self) -> &str {
        &self.intent.native_principal_id
    }
    pub(crate) fn native_measurement(&self) -> &str {
        &self.intent.native_measurement
    }
}

/// Non-cloneable/non-deserializable preparation, tied to the actual generated
/// instance after backup re-entry and the actual native UI authority lifetime.
pub(crate) struct PreparedAccountBirth {
    generated_instance: Arc<()>,
    source: NativeAuthorityBinding,
    anchor: BirthAnchor,
    created: Instant,
}
impl PreparedAccountBirth {
    pub(crate) fn prepare(
        verified: &BackupVerifiedAccount,
        root: &Path,
        disclosure: &WitnessDisclosureDescriptor,
        original_policy: &AccountPolicy,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        let source = owner.native();
        source.check_current()?;
        let generated_instance = genuine_instance(verified)?.marker.clone();
        let original_target = creation_target(root)?;
        let terms = OriginalPolicyTerms::from_policy(original_policy)?;
        disclosure.validate().map_err(|_| Error::InvalidData)?;
        // This descriptor describes the proposed pre-genesis policy only. The
        // final enrolled policy digest is intentionally absent from the anchor.
        if disclosure.account_id != terms.account_id
            || disclosure.network_profile_id != terms.network_profile_id
            || disclosure.witness_id != terms.witness_id
            || disclosure.policy_digest
                != original_policy
                    .policy_digest()
                    .map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        let intent = BirthIntent {
            version: 1,
            operation_id: format!("birth-{}", hex::encode(vault::random::<16>()?)),
            generation_instance_id: genuine_instance(verified)?.instance_id.clone(),
            identity: BirthIdentity::derive(&verified.account)?,
            witness_origin: BirthWitnessOrigin {
                endpoint: disclosure.endpoint.clone(),
                server_name: disclosure.server_name.clone(),
                witness_id: disclosure.witness_id.clone(),
                pinned_server_certificate_digest: disclosure
                    .pinned_server_certificate_digest
                    .clone(),
            },
            original_policy_terms_digest: terms.digest()?,
            original_policy_terms: terms,
            native_principal_id: source.principal_id().into(),
            native_measurement: source.measurement().into(),
            original_target: original_target.to_str().ok_or(Error::InvalidData)?.into(),
        };
        intent.validate(&verified.account)?;
        let anchor = BirthAnchor {
            recipient_policy_v2: None,
            birth_digest: intent.digest()?,
            intent,
        };
        Ok(Self {
            generated_instance,
            source: source.binding(),
            anchor,
            created: Instant::now(),
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        self.anchor.birth_digest()
    }
    /// Exact content to render on the trusted surface. Public audit facts only;
    /// the native renderer remains responsible for inert text and full scrolling.
    pub(crate) fn review_json(&self) -> Result<String> {
        if self.anchor.recipient_policy_v2.is_some() {
            let policy = self
                .anchor
                .recipient_policy_v2
                .as_ref()
                .ok_or(Error::InvalidData)?;
            Ok(format!(
                "{}\n\n{}",
                policy
                    .native_review_text()
                    .map_err(|_| Error::InvalidData)?,
                serde_json::to_string_pretty(&self.anchor).map_err(|_| Error::InvalidData)?
            ))
        } else {
            serde_json::to_string_pretty(&self.anchor.intent).map_err(|_| Error::InvalidData)
        }
    }
    pub(crate) fn approve(
        self,
        verified: &BackupVerifiedAccount,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ApprovedAccountBirth> {
        self.check(verified, owner)?;
        if decision.binding() != &self.source
            || decision.reviewed_digest() != self.anchor.birth_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedAccountBirth { prepared: self })
    }
    fn check(
        &self,
        verified: &BackupVerifiedAccount,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        owner.check_current()?;
        let source = owner.native();
        self.source.check_current()?;
        source.check_current()?;
        if self.created.elapsed() >= REVIEW_LIFETIME
            || self.source != source.binding()
            || self.anchor.native_principal_id() != source.principal_id()
            || self.anchor.native_measurement() != source.measurement()
        {
            return Err(Error::ReviewMismatch);
        }
        require_generation_instance(
            verified,
            &self.generated_instance,
            self.anchor.generation_instance_id(),
        )?;
        self.anchor.validate(&verified.account)
    }
}

/// Only consuming the real NativeDecision above constructs this owner token.
/// It has no public constructor, deserializer, clone or test approval shortcut.
pub(crate) struct ApprovedAccountBirth {
    prepared: PreparedAccountBirth,
}

/// Owns a directory lock and immutable audit anchor, never usable account
/// authority. No transition to AccountVault or independent witness acknowledgement
/// is implemented. Exact reopen preserves the original operation/origin/terms.
pub(crate) struct PendingBirthVault {
    account: DedicatedAccount,
    salt: [u8; 16],
    pending_envelope_digest: String,
    request_publication: std::sync::Mutex<()>,
    encryption_key: Zeroizing<[u8; 32]>,
    _directory: PrivateDirectory,
    anchor: BirthAnchor,
}
/// Borrowed proof that this anchor came from a held, authenticated born envelope.
/// It is audit provenance only and has no public or raw-JSON constructor.
/// The active/recovered AccountVault owner cannot issue this until its immutable
/// birth envelope lifecycle is implemented and qualified separately.
pub(crate) struct BirthAnchorRead<'a> {
    anchor: &'a BirthAnchor,
}
impl BirthAnchorRead<'_> {
    pub(crate) fn anchor(&self) -> &BirthAnchor {
        self.anchor
    }
}
impl PendingBirthVault {
    pub(crate) fn historical_anchor(&self) -> BirthAnchorRead<'_> {
        BirthAnchorRead {
            anchor: &self.anchor,
        }
    }
    pub(crate) fn anchor(&self) -> &BirthAnchor {
        &self.anchor
    }
    pub(crate) fn reopen(root: &Path, password: &[u8]) -> Result<Self> {
        require_canonical_existing_root(root)?;
        let directory = PrivateDirectory::open_existing(root)?;
        require_pending_inventory(&directory)?;
        let encrypted = directory.read("account.wp", MAX_PENDING_BYTES)?;
        let (plain, encryption_key, salt) =
            vault::open_password_envelope(PENDING_MAGIC, password, &encrypted, MAX_PENDING_BYTES)?;
        let (anchor, account) = decode_pending_account(&plain)?;
        let pending = Self {
            account,
            salt,
            pending_envelope_digest: hex::encode(Sha256::digest(&encrypted)),
            request_publication: std::sync::Mutex::new(()),
            encryption_key,
            _directory: directory,
            anchor,
        };
        pending.validate_request_recovery_inventory()?;
        Ok(pending)
    }
}
impl AccountVault {
    /// Pending-only native publication consumes the original
    /// generated+backup-verified instance and its exact native owner decision.
    /// Success returns a permanently pending type, with no signing/journal path.
    pub(crate) fn create_with_birth(
        root: &Path,
        verified: BackupVerifiedAccount,
        approved: ApprovedAccountBirth,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PendingBirthVault> {
        approved.prepared.check(&verified, owner)?;
        if creation_target(root)?.to_str()
            != Some(approved.prepared.anchor.intent.original_target.as_str())
        {
            return Err(Error::ReviewMismatch);
        }
        let plain = encode_pending(&verified.account, &approved.prepared.anchor)?;
        let salt = vault::random::<16>()?;
        // Password KDF/encryption do not hold the native publication lease.
        let key = vault::derive(password, &salt)?;
        let mut encrypted = Vec::from(PENDING_MAGIC.as_slice());
        encrypted.extend(salt);
        encrypted.extend(vault::encrypt(&key, &encrypted, &plain)?);
        if encrypted.len() > MAX_PENDING_BYTES {
            return Err(Error::InvalidData);
        }
        approved.prepared.check(&verified, owner)?;
        // This is the existing genuine authority's lock-linearized lease, never
        // a detached always-live fence. No blocking network work under the lease.
        let _publication = approved.prepared.source.publication_lease()?;
        approved.prepared.check(&verified, owner)?;
        if creation_target(root)?.to_str()
            != Some(approved.prepared.anchor.intent.original_target.as_str())
        {
            return Err(Error::ReviewMismatch);
        }
        let directory = PrivateDirectory::create(root)?;
        approved.prepared.check(&verified, owner)?;
        directory.write("account.wp", &encrypted)?;
        require_pending_inventory(&directory)?;
        directory.sync_all_files()?;
        let anchor = approved.prepared.anchor.clone();
        // Partial I/O failures leave an unactivated directory. They never return
        // an account or switch origin/policy. Recovery can only reopen exact data.
        Ok(PendingBirthVault {
            account: verified.account,
            salt,
            pending_envelope_digest: hex::encode(Sha256::digest(&encrypted)),
            request_publication: std::sync::Mutex::new(()),
            encryption_key: key,
            _directory: directory,
            anchor,
        })
    }
}

fn genuine_instance(verified: &BackupVerifiedAccount) -> Result<&super::GeneratedAccountInstance> {
    if verified.account.restored {
        return Err(Error::RecoveryRequired);
    }
    verified
        .account
        .generated_instance
        .as_ref()
        .ok_or(Error::Unavailable)
}
fn require_generation_instance(
    verified: &BackupVerifiedAccount,
    expected_marker: &Arc<()>,
    expected_id: &str,
) -> Result<()> {
    let generated = genuine_instance(verified)?;
    if !Arc::ptr_eq(expected_marker, &generated.marker) || generated.instance_id != expected_id {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
fn canonical<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::InvalidData)
}
fn is_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}
fn is_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(is_hex)
}
pub(crate) fn creation_target(root: &Path) -> Result<PathBuf> {
    if !root.is_absolute() || root.to_str().is_none_or(|v| v.len() > 4096) {
        return Err(Error::InvalidData);
    }
    let name = root.file_name().ok_or(Error::InvalidData)?;
    let parent = root.parent().ok_or(Error::InvalidData)?;
    if std::fs::canonicalize(parent)? != parent {
        return Err(Error::InvalidData);
    }
    match std::fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(_) => return Err(Error::InvalidData),
    }
    if parent.join(name) != root {
        return Err(Error::InvalidData);
    }
    Ok(root.to_path_buf())
}
fn require_canonical_existing_root(root: &Path) -> Result<()> {
    if !root.is_absolute() || std::fs::canonicalize(root)? != root {
        return Err(Error::InvalidData);
    }
    Ok(())
}
fn require_pending_inventory(directory: &PrivateDirectory) -> Result<()> {
    request_recovery::scan_pending_inventory(directory).map(|_| ())
}

fn encode_pending(account: &DedicatedAccount, anchor: &BirthAnchor) -> Result<Zeroizing<Vec<u8>>> {
    anchor.validate(account)?;
    let metadata = serde_json::to_vec(anchor).map_err(|_| Error::InvalidData)?;
    if metadata.len() > MAX_ANCHOR_BYTES {
        return Err(Error::InvalidData);
    }
    let mut plain = Zeroizing::new(vec![anchor.envelope_version()]);
    plain.extend((metadata.len() as u32).to_le_bytes());
    plain.extend(metadata);
    plain.extend(account.encode().iter());
    Ok(plain)
}
#[cfg(test)]
fn decode_pending(plain: &[u8]) -> Result<BirthAnchor> {
    decode_pending_account(plain).map(|(anchor, _)| anchor)
}
fn decode_pending_account(plain: &[u8]) -> Result<(BirthAnchor, DedicatedAccount)> {
    if plain.len() < 5 || plain.len() > MAX_PENDING_BYTES || !matches!(plain[0], 1 | 2) {
        return Err(Error::InvalidData);
    }
    let length =
        u32::from_le_bytes(plain[1..5].try_into().map_err(|_| Error::InvalidData)?) as usize;
    if length > MAX_ANCHOR_BYTES || length > plain.len() - 5 {
        return Err(Error::InvalidData);
    }
    let anchor: BirthAnchor =
        serde_json::from_slice(&plain[5..5 + length]).map_err(|_| Error::InvalidData)?;
    if plain[0] != anchor.envelope_version() {
        return Err(Error::InvalidData);
    }
    let account = DedicatedAccount::decode(&plain[5 + length..])?;
    // Decoding an authenticated historical record does not recreate the in-memory
    // generation instance or any NativeDecision. The return type remains pending.
    anchor.validate(&account)?;
    Ok((anchor, account))
}

#[cfg(test)]
mod tests;

// Requires the separately staged witness-owner genesis/checkpoint patch.
pub(crate) mod acknowledgement;
pub(crate) use acknowledgement::PreparedPendingBirthAcknowledgement;
pub(super) mod active;
mod history;
pub(crate) mod request;
pub(crate) mod request_recovery;

impl super::PendingAccount {
    /// Public identity data for the same pending native ceremony, before backup
    /// verification. This returns no spend/view key and no authority capability.
    pub(crate) fn birth_identity_for_native_review(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<BirthIdentity> {
        owner.check_current()?;
        if self.account.restored || self.account.generated_instance.is_none() {
            return Err(Error::Unavailable);
        }
        BirthIdentity::derive(&self.account)
    }
}

#[cfg(test)]
mod retired_historical_tests {
    use super::*;
    #[test]
    fn birth_identity_one_derivation_preserves_both_original_commitments() {
        let account = super::tests::data_account();
        let identity = BirthIdentity::derive(&account).unwrap();
        let fvk = account.fvk().unwrap().to_bytes();
        let mut account_hash = Sha256::new();
        account_hash.update(b"wholepact:dedicated-testnet-account:legacy-zip32:v1\0");
        account_hash.update(fvk);
        assert_eq!(identity.account_id, hex::encode(account_hash.finalize()));
        assert_eq!(identity.account_id, account.account_id().unwrap());
        assert_eq!(identity.full_viewing_key_digest, hex::encode(Sha256::digest(fvk)));
        assert_eq!(identity.exact_derivation, account.derivation());
        assert_eq!(identity.network_profile_id, NETWORK);
        assert_eq!(identity.derivation_domain, DERIVATION_DOMAIN);
    }
    #[test]
    fn data_only_historical_anchor_matches_actual_key_and_rejects_substitution() {
        let account = super::tests::data_account();
        let anchor = super::tests::data_anchor(&account);
        assert!(anchor.validate_historical_account(&account).is_ok());
        let other = DedicatedAccount::from_entropy(
            Zeroizing::new([0x40; 32]),
            0,
            "other-data-only".into(),
            false,
        )
        .unwrap();
        assert!(anchor.validate_historical_account(&other).is_err());
    }
    #[test]
    fn data_only_import_flag_does_not_enable_a_second_birth() {
        let account = super::tests::data_account();
        let anchor = super::tests::data_anchor(&account);
        let imported = DedicatedAccount::from_entropy(
            Zeroizing::new([0x39; 32]),
            0,
            "data-only-fixture".into(),
            true,
        )
        .unwrap();
        assert!(anchor.validate_historical_account(&imported).is_ok());
        assert!(anchor.validate(&imported).is_err());
        assert!(imported.restored);
        // Ordinary synthetic import metadata only; no protected recovery,
        // authenticated born envelope or NativeDecision is manufactured.
    }
}

impl PendingBirthVault {
    pub(super) fn check_pending_envelope(&self) -> Result<()> {
        let current = self._directory.read("account.wp", MAX_PENDING_BYTES)?;
        if hex::encode(Sha256::digest(&current)) != self.pending_envelope_digest {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}

impl AccountVault {
    pub(crate) fn born_origin_audit_json(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<String> {
        owner.check_current()?;
        let origin = self.born_origin.as_ref().ok_or(Error::Unavailable)?;
        origin.validate_at_rest(&self.account)?;
        let result = serde_json::to_string_pretty(origin).map_err(|_| Error::InvalidData)?;
        owner.check_current()?;
        Ok(result)
    }
    pub(crate) fn historical_birth_anchor(&self) -> Result<BirthAnchorRead<'_>> {
        let origin = self.born_origin.as_ref().ok_or(Error::RecoveryRequired)?;
        origin.validate_at_rest(&self.account)?;
        Ok(BirthAnchorRead {
            anchor: origin.anchor(),
        })
    }
}
pub(crate) mod backup;
pub(crate) use backup::{
    PreparedBornVaultBackup, PreparedBornVaultRecoveryDisclosure, PreparedBornVaultRestore,
    VerifiedBornBackup,
};

impl AccountVault {
    /// Explicit source-preserving entry used by the acknowledged-origin UI only.
    /// Generic legacy unlock is never a fallback for a failed born-envelope read.
    pub(crate) fn unlock_born_for_audit(
        root: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        require_canonical_existing_root(root)?;
        let directory = PrivateDirectory::open_existing(root)?;
        let encrypted = directory.read("account.wp", 512 * 1024)?;
        let opened = active::open(directory, password, &encrypted, false)?;
        owner.check_current()?;
        Ok(opened)
    }
}

#[cfg(feature = "pending-birth-owner-signing")]
pub(crate) mod enrollment;

#[cfg(feature = "pending-birth-owner-signing")]
pub(crate) mod enrollment_backup;

// Explicit v2 codec; v1 JSON/hash and policy wire bytes remain unchanged.
pub(crate) mod recipient_policy_v2;
