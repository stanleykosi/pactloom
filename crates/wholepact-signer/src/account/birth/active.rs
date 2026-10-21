//! Acknowledged born-envelope preservation. Unlocking this format never grants financial authority.
use super::acknowledgement::RetainedBornAccountOrigin;
use super::*;
use subtle::ConstantTimeEq;
pub(in crate::account) const MAGIC: &[u8; 8] = b"WPACB002";
const MAX_ACTIVE: usize = 512 * 1024;
const MAX_ORIGIN: usize = 384 * 1024;

fn encode(
    account: &DedicatedAccount,
    origin: &RetainedBornAccountOrigin,
    authority_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    origin.validate_at_rest(account)?;
    let encoded = Zeroizing::new(serde_json::to_vec(origin).map_err(|_| Error::InvalidData)?);
    if encoded.len() > MAX_ORIGIN {
        return Err(Error::InvalidData);
    }
    // Version1 is acknowledged provenance only. No caller-selectable active/journal flag.
    let mut plain = Zeroizing::new(vec![origin.anchor().envelope_version()]);
    plain.extend(authority_key);
    plain.extend((encoded.len() as u32).to_le_bytes());
    plain.extend(encoded.iter());
    plain.extend(account.encode().iter());
    if plain.len() > MAX_ACTIVE {
        return Err(Error::InvalidData);
    }
    Ok(plain)
}
// The same strict plaintext parser is used by ordinary decoding and the
// borrowed original checker. It does not issue an account or authority.
struct ParsedBornPlaintext<'a> {
    account_bytes: &'a [u8],
    origin: RetainedBornAccountOrigin,
    authority_key: Zeroizing<[u8; 32]>,
}
fn parse_plaintext(plain: &[u8]) -> Result<ParsedBornPlaintext<'_>> {
    if plain.len() < 37 || plain.len() > MAX_ACTIVE || !matches!(plain[0], 1 | 2) {
        return Err(Error::InvalidData);
    }
    let key = Zeroizing::new(plain[1..33].try_into().map_err(|_| Error::InvalidData)?);
    let n = u32::from_le_bytes(plain[33..37].try_into().map_err(|_| Error::InvalidData)?) as usize;
    if n > MAX_ORIGIN || n > plain.len() - 37 {
        return Err(Error::InvalidData);
    }
    let origin: RetainedBornAccountOrigin =
        serde_json::from_slice(&plain[37..37 + n]).map_err(|_| Error::InvalidData)?;
    if plain[0] != origin.anchor().envelope_version() {
        return Err(Error::InvalidData);
    }
    Ok(ParsedBornPlaintext {
        account_bytes: &plain[37 + n..],
        origin,
        authority_key: key,
    })
}
fn decode(
    plain: &[u8],
) -> Result<(
    DedicatedAccount,
    RetainedBornAccountOrigin,
    Zeroizing<[u8; 32]>,
)> {
    let parsed = parse_plaintext(plain)?;
    let mut account = DedicatedAccount::decode(parsed.account_bytes)?;
    parsed.origin.validate_at_rest(&account)?;
    // An authenticated origin is historical provenance, never an enrollment capability.
    account.born_authority_pending = true;
    account.generated_instance = None;
    account.activation = None;
    Ok((account, parsed.origin, parsed.authority_key))
}

/// A call-local proof of pure historical validation for these exact immutable
/// objects. No native permission, file freshness, journal state or clock is
/// cached. It cannot be cloned, deserialized or manufactured from public data.
pub(super) struct ValidatedOriginalAccount<'a> {
    account: &'a AccountVault,
    origin: &'a RetainedBornAccountOrigin,
}
impl<'a> ValidatedOriginalAccount<'a> {
    pub(super) fn for_account(account: &'a AccountVault) -> Result<Self> {
        let origin = account.born_origin.as_ref().ok_or(Error::Unavailable)?;
        origin.validate_at_rest(&account.account)?;
        Ok(Self { account, origin })
    }
    pub(super) fn origin(&self) -> &'a RetainedBornAccountOrigin {
        self.origin
    }
    fn require_exact_plaintext(&self, plain: &[u8]) -> Result<()> {
        let parsed = parse_plaintext(plain)?;
        // DedicatedAccount's complete persisted encoding is canonical. Exact
        // equality to this already-validated held account excludes every
        // malformed/changed account, without reconstructing the same ZIP32 key.
        // Origin parsing remains typed and rejects unknown/duplicate fields.
        if parsed.account_bytes != self.account.account.encode().as_slice()
            || !bool::from(
                parsed
                    .authority_key
                    .as_slice()
                    .ct_eq(self.account.authority_key.as_slice()),
            )
            || serde_json::to_vec(&parsed.origin).map_err(|_| Error::InvalidData)?
                != serde_json::to_vec(self.origin).map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn check_envelope(&self, account: &AccountVault) -> Result<()> {
        // Equal public fields cannot transfer this proof to another actual vault.
        if !std::ptr::eq(self.account, account) {
            return Err(Error::ReviewMismatch);
        }
        let current = account.directory.read("account.wp", MAX_ACTIVE)?;
        if current.len() < 24 || &current[..8] != MAGIC || current[8..24] != account.salt {
            return Err(Error::InvalidData);
        }
        let plain = vault::decrypt(&account.encryption_key, &current[..24], &current[24..])?;
        self.require_exact_plaintext(&plain)?;
        // The original owner-request ciphertext is still freshly authenticated
        // and completely compared on every call, not memoized by the proof.
        request_matches(&account.directory, &account.encryption_key, self.origin)
    }
}

fn request_matches(
    directory: &PrivateDirectory,
    encryption_key: &[u8; 32],
    origin: &RetainedBornAccountOrigin,
) -> Result<()> {
    let encrypted = directory.read(super::request::REQUEST_FILE, super::request::MAX_REQUEST)?;
    let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
    domain.extend_from_slice(origin.anchor().birth_digest().as_bytes());
    let plain = vault::decrypt(encryption_key, &domain, &encrypted)?;
    let request: wholepact_authority::pending_birth::PendingBirthRequest =
        serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
    if &request != origin.original_request() {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
pub(in crate::account) fn open(
    directory: PrivateDirectory,
    password: &[u8],
    encrypted: &[u8],
    pending_recovery: bool,
) -> Result<AccountVault> {
    if pending_recovery {
        return Err(Error::Unavailable);
    }
    inventory(&directory, false)?;
    open_exact(directory, password, encrypted)
}
#[cfg(feature = "pending-birth-owner-signing")]
pub(super) fn open_for_manual_enrollment(
    directory: PrivateDirectory,
    password: &[u8],
    encrypted: &[u8],
) -> Result<AccountVault> {
    super::enrollment::inventory(&directory)?;
    open_exact(directory, password, encrypted)
}
#[cfg(feature = "pending-birth-owner-signing")]
pub(super) fn open_for_manual_roster_enrollment_v2(
    directory: PrivateDirectory,
    password: &[u8],
    encrypted: &[u8],
) -> Result<AccountVault> {
    super::enrollment::roster_v2::roster_inventory(&directory)?;
    open_exact(directory, password, encrypted)
}
/// Original coordinated Entry only; the legacy native opener is unchanged.
/// In particular a restriction received during the password KDF must prevent
/// the subsequent private original-request read, not merely reject its result.
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(super) fn open_for_coordinated_v3_source_entry_v1(
    directory: PrivateDirectory,
    password: &[u8],
    encrypted: &[u8],
    entry: &wholepact_financial_coordinator_origin::SignerV3SourceEntryFinalV1,
) -> Result<AccountVault> {
    open_for_coordinated_entry_v1(directory,password,encrypted,CoordinatedEntryV1::Initial(entry))
}
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(super) fn open_for_coordinated_financial_source_entry_v1(
    directory: PrivateDirectory,password:&[u8],encrypted:&[u8],
    entry:&wholepact_financial_coordinator_origin::SignerSourceEntryFinalV1,
)->Result<AccountVault>{
    open_for_coordinated_entry_v1(directory,password,encrypted,CoordinatedEntryV1::Financial(entry))
}
#[cfg(feature = "coordinated-financial-workflow-v1")]
enum CoordinatedEntryV1<'a>{
    Initial(&'a wholepact_financial_coordinator_origin::SignerV3SourceEntryFinalV1),
    Financial(&'a wholepact_financial_coordinator_origin::SignerSourceEntryFinalV1),
}
#[cfg(feature = "coordinated-financial-workflow-v1")]
impl CoordinatedEntryV1<'_>{fn check_current(&self)->Result<()>{
    match self{Self::Initial(v)=>v.check_current()?,Self::Financial(v)=>v.check_current()?} Ok(())
}}
#[cfg(feature = "coordinated-financial-workflow-v1")]
fn open_for_coordinated_entry_v1(directory:PrivateDirectory,password:&[u8],encrypted:&[u8],entry:CoordinatedEntryV1<'_>)->Result<AccountVault>{
    entry.check_current()?;
    super::enrollment::roster_v2::roster_inventory(&directory)?;
    entry.check_current()?;
    let (plain, encryption_key, salt) =
        vault::open_password_envelope(MAGIC, password, encrypted, MAX_ACTIVE)?;
    entry.check_current()?;
    let (account, origin, authority_key) = decode(&plain)?;
    entry.check_current()?;
    let encrypted_request =
        directory.read(super::request::REQUEST_FILE, super::request::MAX_REQUEST)?;
    entry.check_current()?;
    let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
    domain.extend_from_slice(origin.anchor().birth_digest().as_bytes());
    let request_plain = vault::decrypt(&encryption_key, &domain, &encrypted_request)?;
    entry.check_current()?;
    let request: wholepact_authority::pending_birth::PendingBirthRequest =
        serde_json::from_slice(&request_plain).map_err(|_| Error::InvalidData)?;
    if &request != origin.original_request() {
        return Err(Error::ReviewMismatch);
    }
    entry.check_current()?;
    Ok(AccountVault {
        directory,
        account,
        encryption_key,
        salt,
        authority_key,
        authority_initialized: false,
        generation: None,
        born_origin: Some(origin),
    })
}

fn open_exact(
    directory: PrivateDirectory,
    password: &[u8],
    encrypted: &[u8],
) -> Result<AccountVault> {
    let (plain, encryption_key, salt) =
        vault::open_password_envelope(MAGIC, password, encrypted, MAX_ACTIVE)?;
    let (account, origin, authority_key) = decode(&plain)?;
    request_matches(&directory, &encryption_key, &origin)?;
    Ok(AccountVault {
        directory,
        account,
        encryption_key,
        salt,
        authority_key,
        authority_initialized: false,
        generation: None,
        born_origin: Some(origin),
    })
}
pub(in crate::account) fn persist(account: &AccountVault) -> Result<()> {
    let origin = account.born_origin.as_ref().ok_or(Error::InvalidData)?;
    if account.authority_initialized
        || account.generation.is_some()
        || !account.account.born_authority_pending
    {
        return Err(Error::Unavailable);
    }
    request_matches(&account.directory, &account.encryption_key, origin)?;
    let plain = encode(&account.account, origin, &account.authority_key)?;
    let mut encrypted = MAGIC.to_vec();
    encrypted.extend(account.salt);
    encrypted.extend(vault::encrypt(&account.encryption_key, &encrypted, &plain)?);
    account.directory.write("account.wp", &encrypted)
}

pub(super) struct StagedBornEnvelope {
    name: String,
    encrypted: Vec<u8>,
    origin: RetainedBornAccountOrigin,
}
fn stage_name(name: &str) -> bool {
    name.len() == 36
        && name.starts_with("tmp-")
        && name[4..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn inventory(directory: &PrivateDirectory, allow_stage: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut stages = 0usize;
    let mut names = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(directory.root())? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        let meta = std::fs::symlink_metadata(entry.path())?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.mode() & 0o077 != 0
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.len() > MAX_ACTIVE as u64
        {
            return Err(Error::InvalidData);
        }
        match name.as_str() {
            "account.wp" | "signer.lock" | super::request::REQUEST_FILE => {}
            _ if allow_stage && stage_name(&name) => {
                stages += 1;
            }
            _ => return Err(Error::InvalidData),
        }
        names.insert(name);
    }
    if stages > 1
        || !names.contains("account.wp")
        || !names.contains("signer.lock")
        || !names.contains(super::request::REQUEST_FILE)
    {
        return Err(Error::InvalidData);
    }
    Ok(())
}
/// Only an authenticated exact active-envelope stage can coexist with a retained request.
pub(super) fn authenticate_staged_envelope(
    pending: &PendingBirthVault,
) -> Result<Option<StagedBornEnvelope>> {
    pending.check_pending_envelope()?;
    inventory(&pending._directory, true)?;
    let mut found = None;
    for entry in std::fs::read_dir(pending._directory.root())? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        if !name.starts_with("tmp-") {
            continue;
        }
        if !stage_name(&name) || found.is_some() {
            return Err(Error::InvalidData);
        }
        let encrypted = pending._directory.read(&name, MAX_ACTIVE)?;
        if encrypted.len() < 24 || &encrypted[..8] != MAGIC || encrypted[8..24] != pending.salt {
            return Err(Error::InvalidData);
        }
        let plain = vault::decrypt(&pending.encryption_key, &encrypted[..24], &encrypted[24..])?;
        let (account, origin, _) = decode(&plain)?;
        if account.encode().as_slice() != pending.account.encode().as_slice()
            || origin.anchor().birth_digest() != pending.anchor.birth_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        request_matches(&pending._directory, &pending.encryption_key, &origin)?;
        found = Some(StagedBornEnvelope {
            name,
            encrypted,
            origin,
        });
    }
    Ok(found)
}
/// Called only after a fresh exact native acknowledgement decision under its held lease.
pub(super) fn publish(
    pending: &PendingBirthVault,
    origin: &RetainedBornAccountOrigin,
) -> Result<()> {
    pending.check_pending_envelope()?;
    origin.validate_at_rest(&pending.account)?;
    request_matches(&pending._directory, &pending.encryption_key, origin)?;
    if let Some(stage) = authenticate_staged_envelope(pending)? {
        // Native retry cannot rewrite the original acknowledgement snapshot or key.
        if serde_json::to_vec(&stage.origin).map_err(|_| Error::InvalidData)?
            != serde_json::to_vec(origin).map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        if pending._directory.read(&stage.name, MAX_ACTIVE)? != stage.encrypted {
            return Err(Error::ReviewMismatch);
        }
        let path = pending._directory.root().join(&stage.name);
        std::fs::File::open(&path)?.sync_all()?;
        std::fs::File::open(pending._directory.root())?.sync_all()?;
        pending.check_pending_envelope()?;
        std::fs::rename(path, pending._directory.root().join("account.wp"))?;
        std::fs::File::open(pending._directory.root())?.sync_all()?;
    } else {
        let authority_key = Zeroizing::new(vault::random::<32>()?);
        let plain = encode(&pending.account, origin, &authority_key)?;
        let mut encrypted = MAGIC.to_vec();
        encrypted.extend(pending.salt);
        encrypted.extend(vault::encrypt(&pending.encryption_key, &encrypted, &plain)?);
        pending.check_pending_envelope()?;
        pending._directory.write("account.wp", &encrypted)?;
    }
    // Check durable final bytes before reporting a completed acknowledgement.
    inventory(&pending._directory, false)?;
    let encrypted = pending._directory.read("account.wp", MAX_ACTIVE)?;
    if encrypted.len() < 24 || &encrypted[..8] != MAGIC || encrypted[8..24] != pending.salt {
        return Err(Error::InvalidData);
    }
    let plain = vault::decrypt(&pending.encryption_key, &encrypted[..24], &encrypted[24..])?;
    let (account, stored, _) = decode(&plain)?;
    if account.encode().as_slice() != pending.account.encode().as_slice()
        || serde_json::to_vec(&stored).map_err(|_| Error::InvalidData)?
            != serde_json::to_vec(origin).map_err(|_| Error::InvalidData)?
    {
        return Err(Error::ReviewMismatch);
    }
    request_matches(&pending._directory, &pending.encryption_key, &stored)?;
    Ok(())
}

pub(super) fn validate_backup_source(account: &AccountVault) -> Result<()> {
    inventory(&account.directory, false)?;
    validate_enrollment_source(account)
}
// Envelope authentication only; the typed manual owner checks its exact expanded inventory.
pub(super) fn validate_enrollment_source(account: &AccountVault) -> Result<()> {
    ValidatedOriginalAccount::for_account(account)?.check_envelope(account)
}
pub(super) fn validate_backup_payload(
    key: &[u8; 32],
    account: &[u8],
    request: &[u8],
) -> Result<()> {
    if account.len() < 24
        || account.len() > MAX_ACTIVE
        || &account[..8] != MAGIC
        || request.len() > super::request::MAX_REQUEST
    {
        return Err(Error::InvalidData);
    }
    let plain = vault::decrypt(key, &account[..24], &account[24..])?;
    let (_, origin, _) = decode(&plain)?;
    let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
    domain.extend(origin.anchor().birth_digest().as_bytes());
    let plain = vault::decrypt(key, &domain, request)?;
    let retained: wholepact_authority::pending_birth::PendingBirthRequest =
        serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
    if &retained != origin.original_request() {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

pub(super) fn backup_audit_json(key: &[u8; 32], account: &[u8], request: &[u8]) -> Result<String> {
    validate_backup_payload(key, account, request)?;
    let plain = vault::decrypt(key, &account[..24], &account[24..])?;
    let (_, origin, _) = decode(&plain)?;
    serde_json::to_string_pretty(&origin).map_err(|_| Error::InvalidData)
}
pub(super) fn recovered_envelopes(
    key: &[u8; 32],
    account: &[u8],
    request: &[u8],
    password: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    validate_backup_payload(key, account, request)?;
    let plain = vault::decrypt(key, &account[..24], &account[24..])?;
    let (mut account, origin, authority_key) = decode(&plain)?;
    account.restored = true;
    let salt = vault::random::<16>()?;
    let key = vault::derive(password, &salt)?;
    let plain = encode(&account, &origin, &authority_key)?;
    let mut envelope = MAGIC.to_vec();
    envelope.extend(salt);
    envelope.extend(vault::encrypt(&key, &envelope, &plain)?);
    let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
    domain.extend(origin.anchor().birth_digest().as_bytes());
    let request = Zeroizing::new(
        serde_json::to_vec(origin.original_request()).map_err(|_| Error::InvalidData)?,
    );
    let request = vault::encrypt(&key, &domain, &request)?;
    validate_backup_payload(&key, &envelope, &request)?;
    Ok((envelope, request))
}

#[cfg(feature = "pending-birth-owner-signing")]
pub(super) fn backup_origin(
    key: &[u8; 32],
    account: &[u8],
    request: &[u8],
) -> Result<RetainedBornAccountOrigin> {
    validate_backup_payload(key, account, request)?;
    let plain = vault::decrypt(key, &account[..24], &account[24..])?;
    let (_, origin, _) = decode(&plain)?;
    Ok(origin)
}

#[cfg(feature = "pending-birth-owner-signing")]
pub(super) fn require_restored_backup_payload(
    key: &[u8; 32],
    account: &[u8],
    request: &[u8],
) -> Result<()> {
    validate_backup_payload(key, account, request)?;
    let plain = vault::decrypt(key, &account[..24], &account[24..])?;
    let (decoded, _, _) = decode(&plain)?;
    if !decoded.restored || !decoded.born_authority_pending {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}

#[cfg(feature = "pending-birth-owner-signing")]
pub(super) fn require_backup_privacy_domain(
    key: &[u8; 32],
    account: &[u8],
    request: &[u8],
    expected: &str,
) -> Result<()> {
    validate_backup_payload(key, account, request)?;
    let plain = vault::decrypt(key, &account[..24], &account[24..])?;
    let (decoded, _, _) = decode(&plain)?;
    if decoded.privacy_domain() != expected {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn modeled_backup_fixture() -> ([u8; 32], Vec<u8>, Vec<u8>) {
    // Synthetic data format only; no native decision or witnessed admission.
    let account = super::tests::data_account();
    let origin = tests::data_origin(&account);
    let key = [0x78; 32];
    let plain = encode(&account, &origin, &[0x79; 32]).unwrap();
    let mut encrypted = MAGIC.to_vec();
    encrypted.extend([0x7a; 16]);
    encrypted.extend(vault::encrypt(&key, &encrypted, &plain).unwrap());
    let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
    domain.extend(origin.anchor().birth_digest().as_bytes());
    let request = vault::encrypt(
        &key,
        &domain,
        &serde_json::to_vec(origin.original_request()).unwrap(),
    )
    .unwrap();
    (key, encrypted, request)
}

#[cfg(test)]
mod tests {
    //! Data-format tests only: no genuine native owner, witnessed history or publication token.
    use super::*;
    use crate::account::birth::tests::{data_account, data_anchor};
    pub(super) fn data_origin(account: &DedicatedAccount) -> RetainedBornAccountOrigin {
        data_origin_with_anchor(account, data_anchor(account))
    }
    fn data_origin_with_anchor(
        account: &DedicatedAccount,
        anchor: BirthAnchor,
    ) -> RetainedBornAccountOrigin {
        anchor.validate_historical_account(account).unwrap();
        let mut policy: AccountPolicy = serde_json::from_value(
            serde_json::to_value(&anchor.intent.original_policy_terms).unwrap(),
        )
        .unwrap();
        policy.account_use_genesis = Some(anchor.expected_account_use_genesis().unwrap());
        let genesis = policy.account_use_genesis.as_ref().unwrap().clone();
        let (_, disclosure) = anchor.audit_policy_match(&policy).unwrap();
        let request = wholepact_authority::pending_birth::PendingBirthRequest {
            version: 1,
            operation_id: anchor.operation_id().into(),
            generation_instance_id: anchor.generation_instance_id().into(),
            native_birth_digest: anchor.birth_digest().into(),
            original_terms_digest: anchor.original_policy_terms_digest().into(),
            original_target_digest: canonical(
                "wholepact:pending-birth-target:v1",
                &anchor.intent.original_target,
            )
            .unwrap(),
            disclosure: disclosure.clone(),
            policy: policy.clone(),
            issued_at_ms: 1000,
            initial_commit_deadline_ms: 2000,
        };
        let request_digest = request.digest().unwrap();
        let checkpoint = serde_json::json!({"genesis_digest":genesis.digest().unwrap(),"history_digest":"ab".repeat(32),"permanent_exclusion_digest":null});
        serde_json::from_value(serde_json::json!({
            "anchor":anchor,
            "witness_commit":{"version":1,"request":request,"request_digest":request_digest,
                "authenticated_owner_certificate_digest":policy.owner_certificate_digest,
                "owner_approval_evidence_digest":"ac".repeat(32),"local_target_digest":"ad".repeat(32),
                "local_owner_review_digest":"ae".repeat(32),"committed_at_ms":1500},
            "observed_checkpoint":checkpoint,"permanent_exclusion":null,
            "observed_snapshot":{"account_use_checkpoint":checkpoint,"witness_id":policy.witness_id,
                "account_id":policy.account_id,"network_profile_id":policy.network_profile_id,"policy_digest":disclosure.policy_digest,
                "head":{"sequence":0,"digest":"af".repeat(32)},"writer_epoch":1,
                "writer_certificate_digest":policy.initial_writer_certificate_digest,"writer_status":"active",
                "outstanding_reservations":1,"outstanding_debit_zatoshis":40,"settled_debit_zatoshis":60,
                "aggregate_budget_zatoshis":100,"reserved_input_value_zatoshis":45,"last_witness_time_ms":1500,
                "pending_writer_session":null,"active_writer_session":null}
        })).unwrap()
    }
    fn data_vault(root: &Path, entropy: u8) -> AccountVault {
        // Data-only synthetic fixture; no native owner, current journal or
        // witnessed authority is constructed by these tests.
        let mut account = DedicatedAccount::from_entropy(
            Zeroizing::new([entropy; 32]),
            0,
            "data-only-fixture".into(),
            false,
        )
        .unwrap();
        let origin = data_origin(&account);
        account.born_authority_pending = true;
        let vault = AccountVault {
            directory: PrivateDirectory::create(root).unwrap(),
            account,
            encryption_key: Zeroizing::new([0x78; 32]),
            salt: [0x79; 16],
            authority_key: Zeroizing::new([0x7a; 32]),
            authority_initialized: false,
            generation: None,
            born_origin: Some(origin),
        };
        let origin = vault.born_origin.as_ref().unwrap();
        let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
        domain.extend_from_slice(origin.anchor().birth_digest().as_bytes());
        let request = crate::vault::encrypt(
            &vault.encryption_key,
            &domain,
            &serde_json::to_vec(origin.original_request()).unwrap(),
        )
        .unwrap();
        vault
            .directory
            .write(super::super::request::REQUEST_FILE, &request)
            .unwrap();
        persist(&vault).unwrap();
        vault
    }
    fn old_exact_plaintext(vault: &AccountVault, plain: &[u8]) -> Result<()> {
        let (decoded, origin, key) = decode(plain)?;
        if decoded.encode().as_slice() != vault.account.encode().as_slice()
            || !bool::from(key.as_slice().ct_eq(vault.authority_key.as_slice()))
            || serde_json::to_vec(&origin).map_err(|_| Error::InvalidData)?
                != serde_json::to_vec(vault.born_origin.as_ref().unwrap())
                    .map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn with_origin_json(plain: &[u8], json: &[u8]) -> Vec<u8> {
        let n = u32::from_le_bytes(plain[33..37].try_into().unwrap()) as usize;
        let mut result = plain[..33].to_vec();
        result.extend((json.len() as u32).to_le_bytes());
        result.extend_from_slice(json);
        result.extend_from_slice(&plain[37 + n..]);
        result
    }
    #[test]
    fn borrowed_original_plaintext_matches_complete_decoder_and_refuses_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let vault = data_vault(&temp.path().join("original"), 0x39);
        let other = data_vault(&temp.path().join("other"), 0x40);
        let proof = ValidatedOriginalAccount::for_account(&vault).unwrap();
        let plain = encode(&vault.account, proof.origin(), &vault.authority_key).unwrap();
        let n = u32::from_le_bytes(plain[33..37].try_into().unwrap()) as usize;
        let pretty = serde_json::to_vec_pretty(proof.origin()).unwrap();
        let equivalent = with_origin_json(&plain, &pretty);
        for candidate in [plain.as_slice(), equivalent.as_slice()] {
            assert!(old_exact_plaintext(&vault, candidate).is_ok());
            assert!(proof.require_exact_plaintext(candidate).is_ok());
        }

        let mut cases = Vec::new();
        let mut changed = plain.to_vec();
        changed[0] = if changed[0] == 1 { 2 } else { 1 };
        cases.push(changed);
        let mut changed = plain.to_vec();
        changed[1] ^= 1; // Different authority key, valid envelope shape.
        cases.push(changed);
        let mut changed = plain.to_vec();
        changed[37 + n + 2] = 1; // Restored bit is part of the full account.
        cases.push(changed);
        let mut changed = plain.to_vec();
        changed[37 + n + 7] ^= 1; // Different actual entropy/account identity.
        cases.push(changed);
        let mut changed = plain.to_vec();
        changed.push(0); // Trailing account bytes are not ignored.
        cases.push(changed);
        cases.push(plain[..plain.len() - 1].to_vec());
        cases.push(plain[..36].to_vec());
        let mut changed = plain.to_vec();
        changed[33..37].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(changed);
        cases.push(vec![0; MAX_ACTIVE + 1]);
        let json = std::str::from_utf8(&plain[37..37 + n]).unwrap();
        cases.push(with_origin_json(
            &plain,
            format!("{{\"unknown\":true,{}", &json[1..]).as_bytes(),
        ));
        let anchor = serde_json::to_string(&proof.origin().anchor()).unwrap();
        cases.push(with_origin_json(
            &plain,
            format!("{{\"anchor\":{anchor},{}", &json[1..]).as_bytes(),
        ));
        cases.push(with_origin_json(&plain, format!("{json}{{}}").as_bytes()));
        let other_origin = other.born_origin.as_ref().unwrap();
        cases.push(with_origin_json(
            &plain,
            &serde_json::to_vec(other_origin).unwrap(),
        ));
        let other_plain = encode(&other.account, other_origin, &other.authority_key).unwrap();
        assert!(decode(&other_plain).is_ok());
        cases.push(other_plain.to_vec());
        for candidate in cases {
            assert!(old_exact_plaintext(&vault, &candidate).is_err());
            assert!(proof.require_exact_plaintext(&candidate).is_err());
        }
    }
    #[test]
    fn borrowed_original_is_exact_vault_scoped_and_checks_fresh_ciphertexts() {
        let temp = tempfile::tempdir().unwrap();
        let vault = data_vault(&temp.path().join("original"), 0x39);
        let equal_fields = data_vault(&temp.path().join("equal-fields"), 0x39);
        let proof = ValidatedOriginalAccount::for_account(&vault).unwrap();
        proof.check_envelope(&vault).unwrap();
        assert!(proof.check_envelope(&equal_fields).is_err());
        let original = vault.directory.read("account.wp", MAX_ACTIVE).unwrap();
        let mut damaged = original.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        vault.directory.write("account.wp", &damaged).unwrap();
        assert!(proof.check_envelope(&vault).is_err());
        vault.directory.write("account.wp", &original).unwrap();
        proof.check_envelope(&vault).unwrap();
        let file = super::super::request::REQUEST_FILE;
        let original_request = vault
            .directory
            .read(file, super::super::request::MAX_REQUEST)
            .unwrap();
        let mut changed = proof.origin().original_request().clone();
        changed.operation_id = "changed-original-operation".into();
        let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
        domain.extend_from_slice(proof.origin().anchor().birth_digest().as_bytes());
        let encrypted = crate::vault::encrypt(
            &vault.encryption_key,
            &domain,
            &serde_json::to_vec(&changed).unwrap(),
        )
        .unwrap();
        vault.directory.write(file, &encrypted).unwrap();
        assert!(proof.check_envelope(&vault).is_err());
        vault.directory.write(file, &original_request).unwrap();
        proof.check_envelope(&vault).unwrap();
    }
    #[test]
    fn borrowed_original_cannot_be_issued_for_mismatched_held_origin() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = data_vault(&temp.path().join("original"), 0x39);
        let other = data_vault(&temp.path().join("other"), 0x40);
        vault.born_origin = other.born_origin.clone();
        assert!(ValidatedOriginalAccount::for_account(&vault).is_err());
    }
    #[test]
    fn v2_complete_encrypted_backup_restore_preserves_original_descriptor_and_key_denial() {
        let account = data_account();
        let anchor = super::super::recipient_policy_v2::modeled_v2_anchor(&account);
        let origin = data_origin_with_anchor(&account, anchor);
        let plain = encode(&account, &origin, &[0x77; 32]).unwrap();
        assert_eq!(plain[0], 2);
        let mut downgraded = plain.to_vec();
        downgraded[0] = 1;
        assert!(decode(&downgraded).is_err());
        let key = [0x78; 32];
        let mut encrypted = MAGIC.to_vec();
        encrypted.extend([0x79; 16]);
        encrypted.extend(vault::encrypt(&key, &encrypted, &plain).unwrap());
        let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
        domain.extend(origin.anchor().birth_digest().as_bytes());
        let request = vault::encrypt(
            &key,
            &domain,
            &serde_json::to_vec(origin.original_request()).unwrap(),
        )
        .unwrap();
        let before = (encrypted.clone(), request.clone());
        validate_backup_payload(&key, &encrypted, &request).unwrap();
        let restored =
            recovered_envelopes(&key, &encrypted, &request, b"synthetic-new-password-only")
                .unwrap();
        let (decoded_plain, _, _) = vault::open_password_envelope(
            MAGIC,
            b"synthetic-new-password-only",
            &restored.0,
            MAX_ACTIVE,
        )
        .unwrap();
        let (restored_account, restored_origin, _) = decode(&decoded_plain).unwrap();
        assert!(restored_account.restored && restored_account.born_authority_pending);
        assert!(restored_account.spending_key().is_err());
        assert_eq!(
            serde_json::to_vec(&origin).unwrap(),
            serde_json::to_vec(&restored_origin).unwrap()
        );
        assert_eq!(
            origin
                .anchor()
                .recipient_policy_v2()
                .unwrap()
                .digest()
                .unwrap(),
            restored_origin
                .anchor()
                .recipient_policy_v2()
                .unwrap()
                .digest()
                .unwrap()
        );
        let mut damaged = encrypted.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(validate_backup_payload(&key, &damaged, &request).is_err());
        assert_eq!((encrypted, request), before);
    }
    #[test]
    fn modeled_born_plaintext_preserves_origin_and_denies_spending_key() {
        let account = data_account();
        let origin = data_origin(&account);
        let encoded = encode(&account, &origin, &[0x77; 32]).unwrap();
        let (decoded, retained, key) = decode(&encoded).unwrap();
        assert_eq!(decoded.account_id().unwrap(), account.account_id().unwrap());
        assert_eq!(
            decoded.fvk().unwrap().to_bytes(),
            account.fvk().unwrap().to_bytes()
        );
        assert!(matches!(decoded.spending_key(), Err(Error::Unavailable)));
        assert!(decoded.generated_instance.is_none());
        assert!(decoded.activation.is_none());
        assert_eq!(key.as_slice(), &[0x77; 32]);
        assert_eq!(
            serde_json::to_vec(&retained).unwrap(),
            serde_json::to_vec(&origin).unwrap()
        );
    }
    #[test]
    fn modeled_active_encoding_rejects_substituted_identity_and_unknown_fields() {
        let account = data_account();
        let origin = data_origin(&account);
        let mut json = serde_json::to_value(&origin).unwrap();
        json["allow_financial_actions"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RetainedBornAccountOrigin>(json).is_err());
        let mut json = serde_json::to_value(&origin).unwrap();
        json["observed_snapshot"]["account_id"] = serde_json::json!("ff".repeat(32));
        let changed: RetainedBornAccountOrigin = serde_json::from_value(json).unwrap();
        assert!(encode(&account, &changed, &[0x77; 32]).is_err());
        let mut plain = encode(&account, &origin, &[0x77; 32]).unwrap();
        plain[0] = 2;
        assert!(decode(&plain).is_err());
    }
    #[test]
    fn modeled_snapshot_does_not_refund_lifetime_charges_or_drop_exclusion() {
        let account = data_account();
        let origin = data_origin(&account);
        let mut json = serde_json::to_value(&origin).unwrap();
        let genesis = origin
            .original_request()
            .policy
            .account_use_genesis
            .as_ref()
            .unwrap();
        let exclusion = wholepact_authority::account_use::PermanentAccountExclusion {
            // Data fixture only; no append or native owner is constructed.
            version: 1,
            identity: genesis.identity.clone(),
            genesis_digest: genesis.digest().unwrap(),
            reason: wholepact_authority::account_use::ExclusionReason::RetirementRequested,
            operation_id: "modeled-retirement".into(),
            native_review_digest: "bb".repeat(32),
        };
        json["permanent_exclusion"] = serde_json::to_value(&exclusion).unwrap();
        let digest = serde_json::json!(exclusion.digest().unwrap());
        json["observed_checkpoint"]["permanent_exclusion_digest"] = digest.clone();
        json["observed_snapshot"]["account_use_checkpoint"]["permanent_exclusion_digest"] = digest;
        let retired: RetainedBornAccountOrigin = serde_json::from_value(json).unwrap();
        let (decoded, retained, _) =
            decode(&encode(&account, &retired, &[0x77; 32]).unwrap()).unwrap();
        assert!(decoded.spending_key().is_err());
        let value = serde_json::to_value(retained).unwrap();
        assert_eq!(value["observed_snapshot"]["settled_debit_zatoshis"], 60);
        assert_eq!(value["observed_snapshot"]["outstanding_debit_zatoshis"], 40);
        assert!(value["permanent_exclusion"].is_object());
    }
    #[test]
    fn restored_born_vault_cannot_create_or_open_financial_stores() {
        let (key, account, request) = modeled_backup_fixture();
        let password = b"synthetic-denied-born-vault";
        let (account, request) = recovered_envelopes(&key, &account, &request, password).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("restored");
        let directory = PrivateDirectory::create(&root).unwrap();
        directory.write("account.wp", &account).unwrap();
        directory
            .write(super::super::request::REQUEST_FILE, &request)
            .unwrap();
        drop(directory);
        let mut vault = AccountVault::unlock(&root, password).unwrap();
        let before: std::collections::BTreeMap<_, _> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), std::fs::read(e.path()).unwrap())
            })
            .collect();
        assert!(!vault.live_signing_allowed());
        assert!(vault.account().spending_key().is_err());
        assert!(vault.create_authority_journal().is_err());
        assert!(vault.open_authority_journal().is_err());
        assert!(vault.create_viewing_wallet_storage().is_err());
        assert!(vault.open_viewing_wallet_storage().is_err());
        let after: std::collections::BTreeMap<_, _> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), std::fs::read(e.path()).unwrap())
            })
            .collect();
        assert_eq!(before, after);
    }
    #[test]
    fn modeled_password_recovery_preserves_original_origin_and_never_releases_key() {
        let account = data_account();
        let origin = data_origin(&account);
        let key = [0x78; 32];
        let plain = encode(&account, &origin, &[0x79; 32]).unwrap();
        let mut encrypted = MAGIC.to_vec();
        encrypted.extend([0x7a; 16]);
        encrypted.extend(vault::encrypt(&key, &encrypted, &plain).unwrap());
        let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
        domain.extend(origin.anchor().birth_digest().as_bytes());
        let request = vault::encrypt(
            &key,
            &domain,
            &serde_json::to_vec(origin.original_request()).unwrap(),
        )
        .unwrap();
        let (restored, retained_request) = recovered_envelopes(
            &key,
            &encrypted,
            &request,
            b"synthetic-born-recovery-password",
        )
        .unwrap();
        let (plain, restored_key, _) = vault::open_password_envelope(
            MAGIC,
            b"synthetic-born-recovery-password",
            &restored,
            MAX_ACTIVE,
        )
        .unwrap();
        let (decoded, retained, _) = decode(&plain).unwrap();
        assert!(decoded.restored);
        assert!(decoded.spending_key().is_err());
        assert_eq!(
            serde_json::to_vec(&retained).unwrap(),
            serde_json::to_vec(&origin).unwrap()
        );
        validate_backup_payload(&restored_key, &restored, &retained_request).unwrap();
        assert!(validate_backup_payload(&key, &restored, &retained_request).is_err());
    }
}
