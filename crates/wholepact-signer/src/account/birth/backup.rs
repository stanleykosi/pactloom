//! Complete backup for acknowledged, financially denied born envelopes.
//! No journal is omitted: this format requires the exact pre-enrollment inventory.
use super::*;
use std::path::Component;
use wholepact_storage_security::receipt_file::PrivateReceiptTarget;
const MAGIC: &[u8; 8] = b"WPABB001";
const MAX_BACKUP: usize = 768 * 1024;
pub(super) fn destination(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || path.exists()
    {
        return Err(Error::InvalidData);
    }
    let parent = path.parent().ok_or(Error::InvalidData)?;
    if std::fs::canonicalize(parent)? != parent || path.file_name().is_none() {
        return Err(Error::InvalidData);
    }
    // Supported exports never create children inside another protected profile.
    for ancestor in parent.ancestors() {
        if ancestor
            .file_name()
            .is_some_and(|n| n == ".wholepact-witness")
        {
            return Err(Error::InvalidData);
        }
        for marker in [
            "account.wp",
            "profile.vault",
            "financial.vault",
            "born-backup.wp",
            "born-enrolled-backup.wp",
            "capsule.wp",
        ] {
            match std::fs::symlink_metadata(ancestor.join(marker)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::InvalidData),
                Ok(_) => return Err(Error::InvalidData),
            }
        }
    }
    Ok(path.to_path_buf())
}
pub(super) fn hold_destination(path: &Path) -> Result<(PrivateReceiptTarget, std::fs::File)> {
    let guard = PrivateReceiptTarget::open(path).map_err(|_| Error::InvalidData)?;
    let lock = std::fs::File::open(path.parent().ok_or(Error::InvalidData)?)?;
    lock.try_lock().map_err(|_| Error::AlreadyOpen)?;
    guard.check_current().map_err(|_| Error::ReviewMismatch)?;
    Ok((guard, lock))
}
fn blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if bytes.len() > 512 * 1024 {
        return Err(Error::InvalidData);
    }
    out.extend((bytes.len() as u32).to_le_bytes());
    out.extend(bytes);
    Ok(())
}
fn take<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    if bytes.len() < 4 {
        return Err(Error::InvalidData);
    }
    let n = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Error::InvalidData)?) as usize;
    if n > 512 * 1024 || n > bytes.len() - 4 {
        return Err(Error::InvalidData);
    }
    let value = &bytes[4..4 + n];
    *bytes = &bytes[4 + n..];
    Ok(value)
}
struct ExactSource {
    account: Vec<u8>,
    request: Vec<u8>,
    digest: String,
}
fn exact_source(account: &AccountVault) -> Result<ExactSource> {
    let origin = account.born_origin.as_ref().ok_or(Error::Unavailable)?;
    origin.validate_at_rest(&account.account)?;
    if account.authority_initialized
        || account.generation.is_some()
        || !account.account.born_authority_pending
    {
        return Err(Error::Unavailable);
    }
    // The active verifier authenticates its exact three-file inventory and both envelopes.
    super::active::validate_backup_source(account)?;
    let encrypted_account = account.directory.read("account.wp", 512 * 1024)?;
    let request = account
        .directory
        .read(super::request::REQUEST_FILE, super::request::MAX_REQUEST)?;
    let digest = canonical(
        "wholepact:born-vault-backup-source:v1",
        &(
            account.directory.root(),
            hex::encode(Sha256::digest(&encrypted_account)),
            hex::encode(Sha256::digest(&request)),
        ),
    )?;
    Ok(ExactSource {
        account: encrypted_account,
        request,
        digest,
    })
}
pub(crate) struct PreparedBornVaultBackup {
    target_guard: PrivateReceiptTarget,
    _target_parent_lock: std::fs::File,
    account: Arc<AccountVault>,
    target: PathBuf,
    source: NativeAuthorityBinding,
    source_digest: String,
    encrypted: Zeroizing<Vec<u8>>,
    digest: String,
    display: Zeroizing<String>,
    created: Instant,
}
impl PreparedBornVaultBackup {
    pub(crate) fn prepare(
        account: Arc<AccountVault>,
        target: &Path,
        recovery_password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        let target = destination(target)?;
        let (target_guard, target_parent_lock) = hold_destination(&target)?;
        if target.starts_with(account.directory.root())
            || account.directory.root().starts_with(&target)
        {
            return Err(Error::InvalidData);
        }
        let exact = exact_source(&account)?;
        let mut plain = Zeroizing::new(vec![1]);
        plain.extend(account.encryption_key.iter());
        blob(&mut plain, &exact.account)?;
        blob(&mut plain, &exact.request)?;
        let encrypted = Zeroizing::new(vault::password_envelope(MAGIC, recovery_password, &plain)?);
        if encrypted.len() > MAX_BACKUP {
            return Err(Error::InvalidData);
        }
        owner.check_current()?;
        let source = owner.native().binding();
        let digest = canonical(
            "wholepact:native-born-vault-backup:v1",
            &(
                &target,
                &exact.digest,
                hex::encode(Sha256::digest(&*encrypted)),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        let display = Zeroizing::new(format!(
            "Create a password-encrypted recovery package at {}. It includes the account recovery secret, exact original birth/witness acknowledgement, retained request and observed exclusions/lifetime charges. No account journal exists in this pre-enrollment format. Possession of the package and recovery password reveals private account material. This does not enroll, activate or authorize spending.\n\nSource account: {}\nSource inventory: {}\nExact review: {}",
            target.display(),
            account.account_id()?,
            exact.digest,
            digest
        ));
        Ok(Self {
            account,
            target_guard,
            _target_parent_lock: target_parent_lock,
            target,
            source,
            source_digest: exact.digest,
            encrypted,
            digest,
            display,
            created: Instant::now(),
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.source.check_current()?;
        if self.created.elapsed() >= REVIEW_LIFETIME {
            return Err(Error::ReviewMismatch);
        }
        Ok(self.display.to_string())
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        self.source.check_current()?;
        if self.created.elapsed() >= REVIEW_LIFETIME
            || self.source != owner.native().binding()
            || exact_source(&self.account)?.digest != self.source_digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.target_guard
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        destination(&self.target)?;
        Ok(())
    }
    pub(crate) fn approve_and_write(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let _lease = self.source.publication_lease()?;
        self.check(owner)?;
        let output = PrivateDirectory::create(&self.target)?;
        self.target_guard
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        output.write("born-backup.wp", &self.encrypted)?;
        output.sync_all_files()?;
        let actual = output.read("born-backup.wp", MAX_BACKUP)?;
        if actual.as_slice() != self.encrypted.as_slice() {
            return Err(Error::Authentication);
        }
        output.write("COMPLETE", hex::encode(Sha256::digest(&actual)).as_bytes())?;
        output.sync_all_files()
    }
}
/// Private authenticated payload reader. Caller must hold genuine native disclosure;
/// no public raw archive-to-account authority constructor is exposed.
type DecodedBackupPayload = (Zeroizing<[u8; 32]>, Vec<u8>, Vec<u8>);
fn decode_payload(plain: &[u8]) -> Result<DecodedBackupPayload> {
    if plain.len() < 33 || plain.len() > MAX_BACKUP || plain[0] != 1 {
        return Err(Error::InvalidData);
    }
    let key = Zeroizing::new(plain[1..33].try_into().map_err(|_| Error::InvalidData)?);
    let mut rest = &plain[33..];
    let account = take(&mut rest)?.to_vec();
    let request = take(&mut rest)?.to_vec();
    if !rest.is_empty() {
        return Err(Error::InvalidData);
    }
    super::active::validate_backup_payload(&key, &account, &request)?;
    Ok((key, account, request))
}

fn read_package(directory: &PrivateDirectory) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let mut names = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(directory.root())? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        let meta = std::fs::symlink_metadata(entry.path())?;
        if !matches!(name.as_str(), "signer.lock" | "born-backup.wp" | "COMPLETE")
            || !meta.is_file()
            || meta.nlink() != 1
            || meta.mode() & 0o077 != 0
            || meta.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::InvalidData);
        }
        names.insert(name);
    }
    if names.len() != 3 {
        return Err(Error::InvalidData);
    }
    let bytes = directory.read("born-backup.wp", MAX_BACKUP)?;
    if directory.read("COMPLETE", 64)? != hex::encode(Sha256::digest(&bytes)).as_bytes() {
        return Err(Error::Authentication);
    }
    Ok(bytes)
}
pub(crate) struct PreparedBornVaultRecoveryDisclosure {
    directory: PrivateDirectory,
    encrypted: Vec<u8>,
    password: Zeroizing<Vec<u8>>,
    source: NativeAuthorityBinding,
    digest: String,
    created: Instant,
}
impl PreparedBornVaultRecoveryDisclosure {
    pub(crate) fn prepare(
        path: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        if !path.is_absolute() || std::fs::canonicalize(path)? != path {
            return Err(Error::InvalidData);
        }
        let directory = PrivateDirectory::open_existing(path)?;
        let encrypted = read_package(&directory)?;
        let source = owner.native().binding();
        let digest = canonical(
            "wholepact:native-born-backup-disclosure:v1",
            &(
                path,
                hex::encode(Sha256::digest(&encrypted)),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        Ok(Self {
            directory,
            encrypted,
            password: Zeroizing::new(password.to_vec()),
            source,
            digest,
            created: Instant::now(),
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.source.check_current()?;
        if self.created.elapsed() >= REVIEW_LIFETIME {
            return Err(Error::ReviewMismatch);
        }
        Ok(format!(
            "Decrypt private account recovery material and original birth/witness history from {} for local review. This does not authorize restoration, signing or financial enrollment.",
            self.directory.root().display()
        ))
    }
    pub(crate) fn approve_read(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<VerifiedBornBackup> {
        owner.check_current()?;
        self.source.check_current()?;
        if decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.source != owner.native().binding()
            || self.created.elapsed() >= REVIEW_LIFETIME
            || read_package(&self.directory)? != self.encrypted
        {
            return Err(Error::ReviewMismatch);
        }
        let (plain, _, _) =
            vault::open_password_envelope(MAGIC, &self.password, &self.encrypted, MAX_BACKUP)?;
        let (inner_key, account, request) = decode_payload(&plain)?;
        owner.check_current()?;
        self.source.check_current()?;
        if self.created.elapsed() >= REVIEW_LIFETIME {
            return Err(Error::ReviewMismatch);
        }
        Ok(VerifiedBornBackup {
            directory: self.directory,
            encrypted: self.encrypted,
            inner_key,
            account,
            request,
            source: self.source,
            created: self.created,
        })
    }
}
pub(crate) struct VerifiedBornBackup {
    directory: PrivateDirectory,
    encrypted: Vec<u8>,
    inner_key: Zeroizing<[u8; 32]>,
    account: Vec<u8>,
    request: Vec<u8>,
    source: NativeAuthorityBinding,
    created: Instant,
}
impl VerifiedBornBackup {
    /// Exact original disclosure deadline. A GUI may only shorten this lifetime;
    /// worker completion or a fresh target review cannot restart it.
    pub(crate) fn disclosure_deadline(&self) -> Instant {
        self.created + REVIEW_LIFETIME
    }
    /// Worker-side current check; filesystem verification must not run on redraw.
    pub(crate) fn check_disclosure(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.check(owner)
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        self.source.check_current()?;
        if self.source != owner.native().binding()
            || self.created.elapsed() >= REVIEW_LIFETIME
            || read_package(&self.directory)? != self.encrypted
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn audit_json(&self, owner: &PendingAccountNativeAuthority) -> Result<String> {
        self.check(owner)?;
        let result =
            super::active::backup_audit_json(&self.inner_key, &self.account, &self.request)?;
        self.check(owner)?;
        Ok(result)
    }
    pub(crate) fn prepare_restore(
        self,
        target: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedBornVaultRestore> {
        self.check(owner)?;
        let target = destination(target)?;
        let (target_guard, target_parent_lock) = hold_destination(&target)?;
        if target.starts_with(self.directory.root()) || self.directory.root().starts_with(&target) {
            return Err(Error::InvalidData);
        }
        let (account, request) = super::active::recovered_envelopes(
            &self.inner_key,
            &self.account,
            &self.request,
            password,
        )?;
        self.check(owner)?;
        let digest = canonical(
            "wholepact:native-born-vault-restore:v1",
            &(
                &target,
                hex::encode(Sha256::digest(&account)),
                hex::encode(Sha256::digest(&request)),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        let display = Zeroizing::new(format!(
            "Restore the exact acknowledged origin as a financially denied, recovered vault at {}. Original birth/witness/operation identities and all recorded lifetime charges/exclusions remain unchanged. This does not recreate a witness, clear uncertainty, initialize a journal or authorize signing.\n\n{}",
            target.display(),
            self.audit_json(owner)?
        ));
        Ok(PreparedBornVaultRestore {
            verified: self,
            target_guard,
            _target_parent_lock: target_parent_lock,
            target,
            account: Zeroizing::new(account),
            request: Zeroizing::new(request),
            digest,
            display,
            created: Instant::now(),
        })
    }
}
pub(crate) struct PreparedBornVaultRestore {
    target_guard: PrivateReceiptTarget,
    _target_parent_lock: std::fs::File,
    verified: VerifiedBornBackup,
    target: PathBuf,
    account: Zeroizing<Vec<u8>>,
    request: Zeroizing<Vec<u8>>,
    digest: String,
    display: Zeroizing<String>,
    created: Instant,
}
impl PreparedBornVaultRestore {
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.verified.source.check_current()?;
        if self.created.elapsed() >= REVIEW_LIFETIME
            || self.verified.created.elapsed() >= REVIEW_LIFETIME
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(self.display.to_string())
    }
    pub(crate) fn approve_and_restore(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.verified.check(owner)?;
        if decision.binding() != &self.verified.source
            || decision.reviewed_digest() != self.digest
            || self.created.elapsed() >= REVIEW_LIFETIME
        {
            return Err(Error::ReviewMismatch);
        }
        self.target_guard
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        destination(&self.target)?;
        let _lease = self.verified.source.publication_lease()?;
        self.verified.check(owner)?;
        self.target_guard
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        destination(&self.target)?;
        let target = PrivateDirectory::create(&self.target)?;
        self.target_guard
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        target.write("account.wp", &self.account)?;
        target.write(super::request::REQUEST_FILE, &self.request)?;
        target.sync_all_files()?;
        if target.read("account.wp", 512 * 1024)?.as_slice() != self.account.as_slice()
            || target
                .read(super::request::REQUEST_FILE, super::request::MAX_REQUEST)?
                .as_slice()
                != self.request.as_slice()
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn protected_profile_and_existing_target_are_rejected_before_writes() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for marker in [
            "account.wp",
            "profile.vault",
            "financial.vault",
            "born-backup.wp",
            "born-enrolled-backup.wp",
            "capsule.wp",
        ] {
            let profile = temp.path().join(marker.replace('.', "-"));
            std::fs::create_dir(&profile).unwrap();
            std::fs::write(profile.join(marker), b"synthetic protected marker").unwrap();
            assert!(destination(&profile.join("output")).is_err());
            assert_eq!(std::fs::read_dir(&profile).unwrap().count(), 1);
        }
        assert!(destination(temp.path()).is_err());
    }
    #[test]
    fn held_destination_rejects_parent_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("selected");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = parent.join("new-package");
        let (guard, _lock) = hold_destination(&target).unwrap();
        std::fs::rename(&parent, temp.path().join("original")).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(guard.check_current().is_err());
        assert!(!target.exists());
    }
    #[test]
    fn incomplete_package_cannot_open_as_verified_backup_and_source_is_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let source = PrivateDirectory::create(&temp.path().join("partial")).unwrap();
        source
            .write("born-backup.wp", b"synthetic incomplete ciphertext")
            .unwrap();
        let before = source.read("born-backup.wp", MAX_BACKUP).unwrap();
        assert!(read_package(&source).is_err());
        assert!(!source.root().join("COMPLETE").exists());
        assert_eq!(source.read("born-backup.wp", MAX_BACKUP).unwrap(), before);
    }
    #[test]
    fn synthetic_encrypted_package_roundtrip_preserves_exact_origin_and_source_tree() {
        let (key, account, request) = super::super::active::modeled_backup_fixture();
        let mut plain = Zeroizing::new(vec![1]);
        plain.extend(key);
        blob(&mut plain, &account).unwrap();
        blob(&mut plain, &request).unwrap();
        let password = b"synthetic-package-password";
        let encrypted = vault::password_envelope(MAGIC, password, &plain).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("package");
        let package = PrivateDirectory::create(&root).unwrap();
        package.write("born-backup.wp", &encrypted).unwrap();
        package
            .write(
                "COMPLETE",
                hex::encode(Sha256::digest(&encrypted)).as_bytes(),
            )
            .unwrap();
        package.sync_all_files().unwrap();
        drop(package);
        fn tree(path: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
            std::fs::read_dir(path)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (
                        entry.file_name().to_str().unwrap().into(),
                        std::fs::read(entry.path()).unwrap(),
                    )
                })
                .collect()
        }
        let before = tree(&root);
        let package = PrivateDirectory::open_existing(&root).unwrap();
        let bytes = read_package(&package).unwrap();
        assert!(vault::open_password_envelope(MAGIC, b"wrong", &bytes, MAX_BACKUP).is_err());
        let (decoded, _, _) =
            vault::open_password_envelope(MAGIC, password, &bytes, MAX_BACKUP).unwrap();
        let (inner, retained, retained_request) = decode_payload(&decoded).unwrap();
        assert_eq!(&*inner, &key);
        assert_eq!(retained, account);
        assert_eq!(retained_request, request);
        let mut trailing = decoded.clone();
        trailing.push(0);
        assert!(decode_payload(&trailing).is_err());
        assert_eq!(tree(&root), before);
        package
            .write("unexpected", b"synthetic extra role")
            .unwrap();
        let with_extra = tree(&root);
        assert!(read_package(&package).is_err());
        assert_eq!(tree(&root), with_extra);
    }
}
