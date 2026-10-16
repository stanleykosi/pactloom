//! Authenticated dependency inventory. V2 retains its immutable original v1
//! primary and every pending/committed native attachment. Neither version is
//! clone detection, freshness evidence, or permission to use financial storage.
use crate::{Error, Result, files::Directory, vault::Secrets};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use wholepact_core::manual_construction::ManualParticipantAttachment;
use zeroize::Zeroizing;

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[path = "financial_attachments.rs"]
pub(crate) mod manual;

const MAGIC: &[u8] = b"wholepact-financial-inventory-v1";
const V2_HEADER: &[u8; 8] = b"WPFI0002";
const V2_FAMILY: &[u8; 4] = b"WPFI";
const V2_DOMAIN: &[u8] = b"wholepact-financial-inventory-v2";
const MAX: usize = 65536;
const MAX_DEPENDENCIES: usize = 12;
pub(crate) const FILE: &str = "financial.inventory";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AttachmentRole {
    PrimaryFinancial,
    ParticipantWallet,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Attachment {
    pub(crate) directory: PathBuf,
    pub(crate) role: AttachmentRole,
    pub(crate) account: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    version: u32,
    owner: String,
    entries: Vec<Attachment>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AttachmentOpenMode {
    Create,
    Open,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalPrimary {
    /// Byte-for-byte equivalent serialized v1 primary inventory, never extended.
    registry: Inventory,
    journal_origin_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingAttachment {
    operation_digest: String,
    account_id: String,
    directory: PathBuf,
    mode: AttachmentOpenMode,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Extension {
    Pending {
        request: PendingAttachment,
    },
    Committed {
        pending_extension_digest: String,
        actual: ManualParticipantAttachment,
    },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtensionRecord {
    predecessor_registry_digest: String,
    native_review_digest: String,
    extension: Extension,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryV2 {
    version: u32,
    owner: String,
    original_primary: OriginalPrimary,
    extensions: Vec<ExtensionRecord>,
}
enum Registry {
    V1(Inventory),
    V2(InventoryV2),
}

fn validate(inventory: &Inventory, secrets: &Secrets) -> Result<()> {
    if inventory.version != 1
        || inventory.owner != secrets.profile()
        || inventory.entries.is_empty()
        || inventory.entries.len() > MAX_DEPENDENCIES
    {
        return Err(Error::Invalid);
    }
    validate_entries(&inventory.entries)
}
fn validate_entries(entries: &[Attachment]) -> Result<()> {
    let mut paths = BTreeSet::new();
    let mut accounts = BTreeSet::new();
    let mut primaries = 0;
    for entry in entries {
        crate::files::validate_absolute(&entry.directory)?;
        if !paths.insert(&entry.directory) {
            return Err(Error::Invalid);
        }
        match (&entry.role, &entry.account) {
            (AttachmentRole::PrimaryFinancial, None) => primaries += 1,
            (AttachmentRole::ParticipantWallet, Some(account)) => {
                crate::id(account)?;
                if !accounts.insert((account, &entry.directory)) {
                    return Err(Error::Invalid);
                }
            }
            _ => return Err(Error::Invalid),
        }
    }
    if primaries != 1 {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::Authentication)
}
impl PendingAttachment {
    fn validate(&self) -> Result<()> {
        hash(&self.operation_digest)?;
        hash(&self.account_id)?;
        crate::files::validate_absolute(&self.directory)?;
        let path = self.directory.to_str().ok_or(Error::Invalid)?;
        if path.len() > 2048
            || path.chars().any(char::is_control)
            || path.ends_with('/')
            || path
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn dependency(&self) -> Attachment {
        Attachment {
            directory: self.directory.clone(),
            role: AttachmentRole::ParticipantWallet,
            account: Some(self.account_id.clone()),
        }
    }
}
impl ExtensionRecord {
    fn digest(&self) -> Result<String> {
        digest("wholepact:native-financial-attachment-extension:v2", self)
    }
}
impl InventoryV2 {
    fn anchor_digest(&self) -> Result<String> {
        digest(
            "wholepact:native-financial-original-primary-anchor:v2",
            &(self.version, &self.owner, &self.original_primary),
        )
    }
    fn prefix_digest(&self, length: usize) -> Result<String> {
        if length > self.extensions.len() {
            return Err(Error::Invalid);
        }
        let records = self.extensions[..length]
            .iter()
            .map(ExtensionRecord::digest)
            .collect::<Result<Vec<_>>>()?;
        digest(
            "wholepact:native-financial-registry:v2",
            &(self.anchor_digest()?, records),
        )
    }
    fn current_digest(&self) -> Result<String> {
        self.prefix_digest(self.extensions.len())
    }
    fn latest_digest(&self) -> Result<String> {
        self.extensions.last().ok_or(Error::Invalid)?.digest()
    }
    fn predecessor_digest(&self) -> Result<&str> {
        Ok(&self
            .extensions
            .last()
            .ok_or(Error::Invalid)?
            .predecessor_registry_digest)
    }
    fn dependencies(&self) -> Vec<Attachment> {
        let mut entries = self.original_primary.registry.entries.clone();
        for record in &self.extensions {
            if let Extension::Pending { request } = &record.extension {
                entries.push(request.dependency());
            }
        }
        entries.sort_by(|a, b| a.directory.cmp(&b.directory));
        entries
    }
    fn pending(&self, request: &PendingAttachment) -> Result<Option<(usize, String)>> {
        for (index, record) in self.extensions.iter().enumerate() {
            if let Extension::Pending { request: old } = &record.extension {
                if old.directory == request.directory
                    || (old.operation_digest == request.operation_digest
                        && old.account_id == request.account_id)
                {
                    if old != request {
                        return Err(Error::Invalid);
                    }
                    return Ok(Some((index, record.digest()?)));
                }
            }
        }
        Ok(None)
    }
    fn committed(&self, pending_digest: &str) -> Option<&ManualParticipantAttachment> {
        self.extensions
            .iter()
            .find_map(|record| match &record.extension {
                Extension::Committed {
                    pending_extension_digest,
                    actual,
                } if pending_extension_digest == pending_digest => Some(actual),
                _ => None,
            })
    }
    fn validate(&self, secrets: &Secrets) -> Result<()> {
        validate(&self.original_primary.registry, secrets)?;
        if self.version != 2
            || self.owner != secrets.profile()
            || self.original_primary.registry.owner != self.owner
            || self.original_primary.registry.entries.len() != 1
            || self.extensions.is_empty()
            || self.extensions.len() > 2 * (MAX_DEPENDENCIES - 1)
        {
            return Err(Error::Invalid);
        }
        hash(&self.original_primary.journal_origin_digest)?;
        let mut pending: Vec<(String, &PendingAttachment)> = Vec::new();
        let mut committed = BTreeSet::new();
        let mut operations = BTreeSet::new();
        for (index, record) in self.extensions.iter().enumerate() {
            hash(&record.native_review_digest)?;
            if record.predecessor_registry_digest != self.prefix_digest(index)? {
                return Err(Error::Authentication);
            }
            match &record.extension {
                Extension::Pending { request } => {
                    request.validate()?;
                    if !operations.insert((&request.operation_digest, &request.account_id)) {
                        return Err(Error::Invalid);
                    }
                    pending.push((record.digest()?, request));
                }
                Extension::Committed {
                    pending_extension_digest,
                    actual,
                } => {
                    hash(pending_extension_digest)?;
                    hash(&actual.account_id)?;
                    hash(&actual.directory_identity_digest)?;
                    hash(&actual.journal_origin_digest)?;
                    crate::files::validate_absolute(Path::new(&actual.canonical_directory))?;
                    if actual.canonical_directory.len() > 2048
                        || actual.canonical_directory.chars().any(char::is_control)
                        || actual.canonical_directory.ends_with('/')
                        || actual
                            .canonical_directory
                            .split('/')
                            .skip(1)
                            .any(|part| part.is_empty() || part == "." || part == "..")
                    {
                        return Err(Error::Invalid);
                    }
                    let (_, request) = pending
                        .iter()
                        .find(|(id, _)| id == pending_extension_digest)
                        .ok_or(Error::Invalid)?;
                    if !committed.insert(pending_extension_digest)
                        || actual.account_id != request.account_id
                        || Some(actual.canonical_directory.as_str()) != request.directory.to_str()
                    {
                        return Err(Error::Authentication);
                    }
                }
            }
        }
        let entries = self.dependencies();
        if entries.len() > MAX_DEPENDENCIES {
            return Err(Error::Invalid);
        }
        for (index, entry) in entries.iter().enumerate() {
            if entries[index + 1..].iter().any(|other| {
                entry.directory.starts_with(&other.directory)
                    || other.directory.starts_with(&entry.directory)
            }) {
                return Err(Error::Invalid);
            }
        }
        validate_entries(&entries)
    }
    /// Reserve byte capacity for all still-pending exact commits as well as the
    /// record being appended. Completing an admitted dependency cannot run out
    /// of registry space solely because its actual-owner hashes became known.
    fn complete_size_bound(&self) -> Result<usize> {
        let mut completed = self.clone();
        for record in &self.extensions {
            if let Extension::Pending { request } = &record.extension {
                let pending = record.digest()?;
                if self.committed(&pending).is_none() {
                    completed.extensions.push(ExtensionRecord {
                        predecessor_registry_digest: "0".repeat(64),
                        native_review_digest: "0".repeat(64),
                        extension: Extension::Committed {
                            pending_extension_digest: pending,
                            actual: ManualParticipantAttachment {
                                account_id: request.account_id.clone(),
                                canonical_directory: request
                                    .directory
                                    .to_str()
                                    .ok_or(Error::Invalid)?
                                    .to_owned(),
                                directory_identity_digest: "0".repeat(64),
                                journal_origin_digest: "0".repeat(64),
                            },
                        },
                    });
                }
            }
        }
        Ok(serde_json::to_vec(&completed)?.len() + V2_HEADER.len() + 24 + 16)
    }
    fn append(
        &mut self,
        extension: Extension,
        native_review_digest: &str,
        secrets: &Secrets,
    ) -> Result<()> {
        let mut next = self.clone();
        next.extensions.push(ExtensionRecord {
            predecessor_registry_digest: self.current_digest()?,
            native_review_digest: native_review_digest.to_owned(),
            extension,
        });
        next.validate(secrets)?;
        // Capacity applies to complete ciphertext, not just the number of rows.
        if next.complete_size_bound()? > MAX {
            return Err(Error::Invalid);
        }
        *self = next;
        Ok(())
    }
}
fn cipher(secrets: &Secrets) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(&*secrets.transport_material()?).map_err(|_| Error::Storage)
}
fn open_payload(bytes: &[u8], domain: &[u8], secrets: &Secrets) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() < 40 {
        return Err(Error::Invalid);
    }
    Ok(Zeroizing::new(
        cipher(secrets)?
            .decrypt(
                &XNonce::try_from(&bytes[..24]).map_err(|_| Error::Invalid)?,
                Payload {
                    msg: &bytes[24..],
                    aad: domain,
                },
            )
            .map_err(|_| Error::Authentication)?,
    ))
}
fn decode(bytes: &[u8], secrets: &Secrets) -> Result<Registry> {
    if bytes.len() < 40 || bytes.len() > MAX {
        return Err(Error::Invalid);
    }
    // Explicit discriminator: a malformed/rejected v2-family envelope NEVER
    // falls back to legacy decryption or legacy construction.
    if bytes.starts_with(V2_FAMILY) {
        if !bytes.starts_with(V2_HEADER) {
            return Err(Error::Invalid);
        }
        let plain = open_payload(&bytes[V2_HEADER.len()..], V2_DOMAIN, secrets)?;
        let inventory: InventoryV2 = serde_json::from_slice(&plain)?;
        inventory.validate(secrets)?;
        if serde_json::to_vec(&inventory)?.as_slice() != plain.as_slice() {
            return Err(Error::Invalid);
        }
        Ok(Registry::V2(inventory))
    } else {
        let plain = open_payload(bytes, MAGIC, secrets)?;
        let inventory: Inventory = serde_json::from_slice(&plain)?;
        validate(&inventory, secrets)?;
        Ok(Registry::V1(inventory))
    }
}
fn load(directory: &Directory, secrets: &Secrets) -> Result<Registry> {
    directory.check()?;
    if directory.read("financial.attached", 1024)? != b"wholepact-financial-profile-attached-v1\n" {
        return Err(Error::Authentication);
    }
    decode(&directory.read(FILE, MAX)?, secrets)
}
/// Live source form also requires the immutable attached marker before any
/// dependency is opened. Archive-only read/read_bytes intentionally omit it.
pub(crate) fn read_current(directory: &Directory, secrets: &Secrets) -> Result<Vec<Attachment>> {
    Ok(match load(directory, secrets)? {
        Registry::V1(inventory) => inventory.entries,
        Registry::V2(inventory) => inventory.dependencies(),
    })
}
pub(crate) fn read(directory: &Directory, secrets: &Secrets) -> Result<Vec<Attachment>> {
    // Preserve legacy archive/restore semantics: archive directories have no
    // live marker. Native mutation/current-owner paths use load() instead.
    read_bytes(&directory.read(FILE, MAX)?, secrets)
}
/// Authenticate a complete registry from a bounded private archive. Every
/// pending dependency is returned even if its create/open/commit failed.
pub(crate) fn read_bytes(bytes: &[u8], secrets: &Secrets) -> Result<Vec<Attachment>> {
    Ok(match decode(bytes, secrets)? {
        Registry::V1(inventory) => inventory.entries,
        Registry::V2(inventory) => inventory.dependencies(),
    })
}
fn seal<T: Serialize>(
    value: &T,
    header: &[u8],
    domain: &[u8],
    secrets: &Secrets,
) -> Result<Vec<u8>> {
    let plain = Zeroizing::new(serde_json::to_vec(value)?);
    if header.len() + 24 + plain.len() + 16 > MAX {
        return Err(Error::Invalid);
    }
    let nonce = crate::random::<24>()?;
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(&nonce);
    bytes.extend(
        cipher(secrets)?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: domain,
                },
            )
            .map_err(|_| Error::Storage)?,
    );
    Ok(bytes)
}
fn write_v2(directory: &Directory, secrets: &Secrets, inventory: &InventoryV2) -> Result<()> {
    inventory.validate(secrets)?;
    directory.replace_private(FILE, &seal(inventory, V2_HEADER, V2_DOMAIN, secrets)?)
}
/// Legacy registration only. V2 requires an actual held owner and native reviewed
/// extension. Even an exact path-only v2 request is refused here.
pub(crate) fn register(
    directory: &Directory,
    secrets: &Secrets,
    path: &Path,
    role: AttachmentRole,
    account: Option<&str>,
) -> Result<()> {
    directory.external_destination(path)?;
    let exists = directory.path(FILE)?.try_exists()?;
    if !exists && directory.path("financial.attached")?.try_exists()? {
        return Err(Error::Unsupported);
    }
    let mut entries = if exists {
        match decode(&directory.read(FILE, MAX)?, secrets)? {
            Registry::V1(inventory) => inventory.entries,
            Registry::V2(_) => return Err(Error::RecoveryFinancialUnsupported),
        }
    } else {
        Vec::new()
    };
    let entry = Attachment {
        directory: path.to_owned(),
        role,
        account: account.map(str::to_owned),
    };
    if let Some(old) = entries.iter().find(|old| old.directory == entry.directory) {
        if old != &entry {
            return Err(Error::Invalid);
        }
        return Ok(());
    }
    entries.push(entry);
    entries.sort_by(|a, b| a.directory.cmp(&b.directory));
    let inventory = Inventory {
        version: 1,
        owner: secrets.profile(),
        entries,
    };
    validate(&inventory, secrets)?;
    directory.replace_private(FILE, &seal(&inventory, &[], MAGIC, secrets)?)?;
    if !directory.path("financial.attached")?.try_exists()? {
        directory.write_new(
            "financial.attached",
            b"wholepact-financial-profile-attached-v1\n",
        )?;
    }
    Ok(())
}
/// Read-only original anchor for the separate v2-aware actual-owner check. This
/// does not widen FinancialProfile::manual_journal_origin_digest's v1 contract.
pub(crate) fn original_primary_anchor(
    directory: &Directory,
    secrets: &Secrets,
) -> Result<(Vec<Attachment>, Option<String>)> {
    let (entries, origin) = match load(directory, secrets)? {
        Registry::V1(inventory) => (inventory.entries, None),
        Registry::V2(inventory) => (
            inventory.original_primary.registry.entries,
            Some(inventory.original_primary.journal_origin_digest),
        ),
    };
    if entries.len() != 1
        || entries[0].role != AttachmentRole::PrimaryFinancial
        || entries[0].account.is_some()
    {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    Ok((entries, origin))
}
/// Exact primary-only reopen plan. V2 never re-enters generic registration;
/// a missing legacy registry still follows the existing marker fail-closed rule.
/// The caller must check the actual opened owner with reopen_registered.
pub(crate) fn prepare_primary_open(
    directory: &Directory,
    secrets: &Secrets,
    path: &Path,
    create: bool,
) -> Result<bool> {
    let known_v2 = !create
        && directory.path(FILE)?.try_exists()?
        && known_entry_before_open(
            directory,
            secrets,
            path,
            AttachmentRole::PrimaryFinancial,
            None,
        )?;
    if !known_v2 {
        register(
            directory,
            secrets,
            path,
            AttachmentRole::PrimaryFinancial,
            None,
        )?;
    }
    Ok(known_v2)
}
/// Before an ordinary caller opens a V2 dependency, require an exact already
/// committed registration. This creates no profile and grants no owner authority.
/// Returns false only for a valid V1 inventory, preserving its legacy flow.
pub(crate) fn known_entry_before_open(
    directory: &Directory,
    secrets: &Secrets,
    path: &Path,
    role: AttachmentRole,
    account: Option<&str>,
) -> Result<bool> {
    directory.external_destination(path)?;
    match load(directory, secrets)? {
        Registry::V1(_) => Ok(false),
        Registry::V2(inventory) => {
            let entry = Attachment {
                directory: path.to_owned(),
                role,
                account: account.map(str::to_owned),
            };
            if entry == inventory.original_primary.registry.entries[0] {
                return Ok(true);
            }
            for record in &inventory.extensions {
                if let Extension::Pending { request } = &record.extension {
                    if request.dependency() == entry
                        && inventory.committed(&record.digest()?).is_some()
                    {
                        return Ok(true);
                    }
                }
            }
            Err(Error::RecoveryFinancialUnsupported)
        }
    }
}
/// Complete actual-owner checks after the fixed existing-profile open. An exact
/// label/path without its authenticated held files is never sufficient.
pub(crate) fn reopen_registered(
    directory: &Directory,
    secrets: &Secrets,
    profile: &crate::financial_profile::FinancialProfile,
    role: AttachmentRole,
    account: Option<&str>,
) -> Result<()> {
    let path = profile.current_directory()?;
    if !known_entry_before_open(directory, secrets, &path, role.clone(), account)? {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    check_backup_owner(
        directory,
        secrets,
        &Attachment {
            directory: path,
            role,
            account: account.map(str::to_owned),
        },
        profile,
    )
}
/// Backup covers all pending as well as committed dependencies. Pending storage
/// must really exist and authenticate; missing/partial files cannot become empty
/// history. Committed and original-primary storage must additionally retain their
/// exact original actual owner identities.
pub(crate) fn check_backup_owner(
    directory: &Directory,
    secrets: &Secrets,
    entry: &Attachment,
    profile: &crate::financial_profile::FinancialProfile,
) -> Result<()> {
    check_backup_owner_inner(directory, secrets, entry, BackupOwner::Profile(profile))
}
pub(crate) fn check_read_backup_owner(
    directory: &Directory,
    secrets: &Secrets,
    entry: &Attachment,
    profile: &crate::financial_profile::FinancialReadProfile,
) -> Result<()> {
    check_backup_owner_inner(directory, secrets, entry, BackupOwner::ReadOnly(profile))
}
// Private closed sum of actual owners. No external trait, bool, path, serialized
// descriptor or callback can stand in for either authenticated concrete owner.
enum BackupOwner<'a> {
    Profile(&'a crate::financial_profile::FinancialProfile),
    ReadOnly(&'a crate::financial_profile::FinancialReadProfile),
}
impl BackupOwner<'_> {
    fn current_directory(&self) -> Result<PathBuf> {
        match self {
            Self::Profile(p) => p.current_directory(),
            Self::ReadOnly(p) => p.current_directory(),
        }
    }
    fn check_retained_owner(&self, owner: &str) -> Result<()> {
        match self {
            Self::Profile(p) => p.check_retained_owner(owner),
            Self::ReadOnly(p) => p.check_retained_owner(owner),
        }
    }
    fn manual_original_primary_origin_digest(
        &self,
        directory: &Directory,
        secrets: &Secrets,
    ) -> Result<String> {
        match self {
            Self::Profile(p) => p.manual_original_primary_origin_digest(directory, secrets),
            Self::ReadOnly(p) => p.manual_original_primary_origin_digest(directory, secrets),
        }
    }
    fn manual_attachment_descriptor(
        &self,
        owner: &str,
        account: &str,
    ) -> Result<ManualParticipantAttachment> {
        match self {
            Self::Profile(p) => p.manual_attachment_descriptor(owner, account),
            Self::ReadOnly(p) => p.manual_attachment_descriptor(owner, account),
        }
    }
}
fn check_backup_owner_inner(
    directory: &Directory,
    secrets: &Secrets,
    entry: &Attachment,
    profile: BackupOwner<'_>,
) -> Result<()> {
    if profile.current_directory()? != entry.directory {
        return Err(Error::Authentication);
    }
    profile.check_retained_owner(&secrets.profile())?;
    match load(directory, secrets)? {
        Registry::V1(inventory) => {
            if !inventory.entries.contains(entry) {
                return Err(Error::Authentication);
            }
        }
        Registry::V2(inventory) => {
            if entry == &inventory.original_primary.registry.entries[0] {
                if profile.manual_original_primary_origin_digest(directory, secrets)?
                    != inventory.original_primary.journal_origin_digest
                {
                    return Err(Error::Authentication);
                }
            } else {
                let (record, request) = inventory
                    .extensions
                    .iter()
                    .find_map(|record| match &record.extension {
                        Extension::Pending { request } if request.dependency() == *entry => {
                            Some((record, request))
                        }
                        _ => None,
                    })
                    .ok_or(Error::Authentication)?;
                if let Some(expected) = inventory.committed(&record.digest()?) {
                    if &profile
                        .manual_attachment_descriptor(&secrets.profile(), &request.account_id)?
                        != expected
                    {
                        return Err(Error::Authentication);
                    }
                }
            }
        }
    }
    Ok(())
}
/// Recipient record storage is optional only as a pair.
#[cfg(test)]
pub(crate) fn recipient_pair(root: &Path) -> Result<bool> {
    let key = root.join("recipient-record-key.wp").try_exists()?;
    let records = root.join("recipient-records.wp").try_exists()?;
    if key != records {
        return Err(Error::Invalid);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_authentication_legacy_gap_and_exact_role_binding() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = Directory::create(&temporary.path().join("primary")).unwrap();
        let secrets = Secrets::fresh().unwrap();
        let main = temporary.path().join("financial");
        register(
            &directory,
            &secrets,
            &main,
            AttachmentRole::PrimaryFinancial,
            None,
        )
        .unwrap();
        register(
            &directory,
            &secrets,
            &main,
            AttachmentRole::PrimaryFinancial,
            None,
        )
        .unwrap();
        assert_eq!(read(&directory, &secrets).unwrap().len(), 1);
        assert!(read(&directory, &Secrets::fresh().unwrap()).is_err());
        assert!(
            register(
                &directory,
                &secrets,
                &main,
                AttachmentRole::ParticipantWallet,
                Some("account-one")
            )
            .is_err()
        );
        let participant = temporary.path().join("participant");
        register(
            &directory,
            &secrets,
            &participant,
            AttachmentRole::ParticipantWallet,
            Some("account-one"),
        )
        .unwrap();
        assert_eq!(read(&directory, &secrets).unwrap().len(), 2);
        directory.inventory().unwrap();
        let legacy = Directory::create(&temporary.path().join("legacy")).unwrap();
        legacy.write_new("financial.attached", b"legacy").unwrap();
        assert!(
            register(
                &legacy,
                &secrets,
                &main,
                AttachmentRole::PrimaryFinancial,
                None
            )
            .is_err()
        );
    }
    #[test]
    fn recipient_pair_never_accepts_one_missing_half() {
        let temporary = tempfile::tempdir().unwrap();
        assert!(!recipient_pair(temporary.path()).unwrap());
        crate::files::write_new(
            &temporary.path().join("recipient-record-key.wp"),
            b"synthetic encrypted fixture",
        )
        .unwrap();
        assert!(recipient_pair(temporary.path()).is_err());
        crate::files::write_new(
            &temporary.path().join("recipient-records.wp"),
            b"synthetic encrypted fixture",
        )
        .unwrap();
        assert!(recipient_pair(temporary.path()).unwrap());
    }
}

#[cfg(test)]
#[path = "financial_inventory/tests.rs"]
mod v2_tests;

#[cfg(test)]
#[path = "financial_inventory/backup_tests.rs"]
mod backup_tests;
