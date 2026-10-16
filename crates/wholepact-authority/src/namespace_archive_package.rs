//! Exclusive private archive package IO. Neither creation nor open touches the
//! fixed live namespace. Capsule and publication remain historical file types.
use super::*;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use wholepact_storage_security::receipt_file::PrivateReceiptTarget;

const PUBLICATION_APP: i64 = 0x57504e41;
const PUBLICATION_SCHEMA: &str = "CREATE TABLE namespace_archive_publication(singleton INTEGER PRIMARY KEY CHECK(singleton=1),payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=32768)) STRICT; CREATE TRIGGER namespace_archive_publication_no_replace BEFORE INSERT ON namespace_archive_publication WHEN EXISTS(SELECT 1 FROM namespace_archive_publication) BEGIN SELECT RAISE(ABORT,'immutable namespace archive publication'); END; CREATE TRIGGER namespace_archive_publication_no_update BEFORE UPDATE ON namespace_archive_publication BEGIN SELECT RAISE(ABORT,'immutable namespace archive publication'); END; CREATE TRIGGER namespace_archive_publication_no_delete BEFORE DELETE ON namespace_archive_publication BEGIN SELECT RAISE(ABORT,'retained namespace archive publication'); END;";
const CAPSULE: &str = "capsule.wp";
const PUBLICATION: &str = "publication.wp";

// An export must not mutate the inventory of an unrelated protected profile or
// existing archive. Presence includes dangling symlinks and non-file markers.
fn require_standalone_destination(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or(AuthorityError::InvalidBinding)?;
    for ancestor in parent.ancestors() {
        if ancestor
            .file_name()
            .is_some_and(|name| name == ".wholepact-witness")
        {
            return Err(AuthorityError::InvalidBinding);
        }
        for marker in [
            "account.wp",
            "profile.vault",
            "financial.vault",
            "born-backup.wp",
            "capsule.wp",
        ] {
            match fs::symlink_metadata(ancestor.join(marker)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(AuthorityError::Storage),
                Ok(_) => return Err(AuthorityError::InvalidBinding),
            }
        }
    }
    Ok(())
}

pub(super) struct NewPackage {
    root: PathBuf,
    parent: PrivateReceiptTarget,
}
impl NewPackage {
    pub(super) fn prepare(path: &Path, excluded_root: &Path) -> Result<Self> {
        if !path.is_absolute()
            || path.to_str().is_none()
            || path.as_os_str().len() > 4096
            || path.starts_with(excluded_root)
            || excluded_root.starts_with(path)
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let parent = PrivateReceiptTarget::open(path).map_err(|_| AuthorityError::Storage)?;
        let this = Self {
            root: path.into(),
            parent,
        };
        this.check_current()?;
        Ok(this)
    }
    pub(super) fn binding_digest(&self) -> Result<String> {
        digest(
            "wholepact:namespace-archive-target:v1",
            self.parent.identity(),
        )
    }
    pub(super) fn check_current(&self) -> Result<()> {
        require_standalone_destination(&self.root)?;
        self.parent
            .check_current()
            .map_err(|_| AuthorityError::Storage)?;
        match fs::symlink_metadata(&self.root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(AuthorityError::Conflict),
        }
    }
    pub(super) fn create(self) -> Result<PackageFiles> {
        self.check_current()?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&self.root)
            .map_err(|_| AuthorityError::Storage)?;
        // A failure after mkdir leaves uncertain output. Never remove/reuse it.
        require_standalone_destination(&self.root)?;
        self.parent
            .check_current()
            .map_err(|_| AuthorityError::Storage)?;
        fs::File::open(self.root.parent().ok_or(AuthorityError::Storage)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| AuthorityError::Storage)?;
        PackageFiles::hold(&self.root, false)
    }
}
pub(super) struct PackageFiles {
    root: PathBuf,
    _lock: fs::File,
    target: PrivateReceiptTarget,
    root_device: u64,
    root_inode: u64,
    owner_uid: u32,
}
impl PackageFiles {
    fn hold(root: &Path, require_complete: bool) -> Result<Self> {
        let target =
            PrivateReceiptTarget::open(root.join(CAPSULE)).map_err(|_| AuthorityError::Storage)?;
        let lock = fs::File::open(root).map_err(|_| AuthorityError::Storage)?;
        lock.try_lock().map_err(|_| AuthorityError::Storage)?;
        let m = lock.metadata().map_err(|_| AuthorityError::Storage)?;
        let this = Self {
            root: root.into(),
            _lock: lock,
            target,
            root_device: m.dev(),
            root_inode: m.ino(),
            owner_uid: m.uid(),
        };
        this.check(require_complete)?;
        Ok(this)
    }
    pub(super) fn open(root: &Path) -> Result<Self> {
        Self::hold(root, true)
    }
    pub(super) fn capsule(&self) -> PathBuf {
        self.root.join(CAPSULE)
    }
    pub(super) fn publication(&self) -> PathBuf {
        self.root.join(PUBLICATION)
    }
    pub(super) fn root(&self) -> &Path {
        &self.root
    }
    pub(super) fn check(&self, complete: bool) -> Result<()> {
        self.target
            .check_current()
            .map_err(|_| AuthorityError::Storage)?;
        let m = fs::symlink_metadata(&self.root).map_err(|_| AuthorityError::Storage)?;
        if !m.is_dir()
            || m.dev() != self.root_device
            || m.ino() != self.root_inode
            || m.uid() != self.owner_uid
            || m.mode() & 0o7777 != 0o700
        {
            return Err(AuthorityError::Storage);
        }
        let mut present = BTreeSet::new();
        let mut bytes = 0u64;
        let mut publication_bytes = 0u64;
        for entry in fs::read_dir(&self.root).map_err(|_| AuthorityError::Storage)? {
            let entry = entry.map_err(|_| AuthorityError::Storage)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| AuthorityError::CorruptHistory)?;
            if ![
                CAPSULE,
                "capsule.wp-wal",
                "capsule.wp-shm",
                "capsule.wp-journal",
                PUBLICATION,
                "publication.wp-wal",
                "publication.wp-shm",
                "publication.wp-journal",
            ]
            .contains(&name.as_str())
            {
                return Err(AuthorityError::CorruptHistory);
            }
            let m = fs::symlink_metadata(entry.path()).map_err(|_| AuthorityError::Storage)?;
            if !m.is_file()
                || m.nlink() != 1
                || m.uid() != self.owner_uid
                || m.mode() & 0o7777 != 0o600
            {
                return Err(AuthorityError::Storage);
            }
            bytes = bytes.checked_add(m.len()).ok_or(AuthorityError::Limit)?;
            if name == PUBLICATION || name.starts_with("publication.wp-") {
                publication_bytes = publication_bytes
                    .checked_add(m.len())
                    .ok_or(AuthorityError::Limit)?;
                if publication_bytes > 2 * 1024 * 1024 {
                    return Err(AuthorityError::Limit);
                }
            }
            if bytes > 642 * 1024 * 1024 {
                return Err(AuthorityError::Limit);
            }
            present.insert(name);
        }
        if complete && (!present.contains(CAPSULE) || !present.contains(PUBLICATION)) {
            return Err(AuthorityError::RecoveryRequired);
        }
        Ok(())
    }
    pub(super) fn binding_digest(&self) -> Result<String> {
        self.check(true)?;
        let mut stamps = BTreeMap::new();
        for entry in fs::read_dir(&self.root).map_err(|_| AuthorityError::Storage)? {
            let entry = entry.map_err(|_| AuthorityError::Storage)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| AuthorityError::Storage)?;
            let m = fs::symlink_metadata(entry.path()).map_err(|_| AuthorityError::Storage)?;
            stamps.insert(
                name,
                (
                    m.dev(),
                    m.ino(),
                    m.uid(),
                    m.mode(),
                    m.len(),
                    m.mtime(),
                    m.mtime_nsec(),
                    m.ctime(),
                    m.ctime_nsec(),
                ),
            );
        }
        digest(
            "wholepact:namespace-archive-package-identity:v1",
            &(
                self.target.identity(),
                self.root_device,
                self.root_inode,
                self.owner_uid,
                stamps,
            ),
        )
    }
    pub(super) fn sync(&self) -> Result<()> {
        self._lock.sync_all().map_err(|_| AuthorityError::Storage)?;
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Publication {
    pub(super) version: u16,
    pub(super) capsule_id: String,
    pub(super) manifest_digest: String,
    pub(super) namespace_digest: String,
    pub(super) source_plan_digest: String,
    pub(super) native_review_digest: String,
    pub(super) published_at_ms: u64,
    pub(super) permanently_historical: bool,
}
impl Publication {
    fn validate(&self) -> Result<()> {
        for h in [
            &self.capsule_id,
            &self.manifest_digest,
            &self.namespace_digest,
            &self.source_plan_digest,
            &self.native_review_digest,
        ] {
            hash(h)?;
        }
        if self.version != 1 || !self.permanently_historical || self.published_at_ms == 0 {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
pub(super) fn publish(
    files: &PackageFiles,
    key: &DatabaseKey,
    record: &Publication,
    native: &NativePublicationLease,
) -> Result<()> {
    record.validate()?;
    if record.native_review_digest != native.reviewed_digest()
        || native.admitted_at_ms() > record.published_at_ms
    {
        return Err(AuthorityError::InvalidBinding);
    }
    files.check(false)?;
    native.check_current()?;
    let c = wholepact_storage_security::create_encrypted(files.publication(), key)?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
    stage_publication_rows(&tx, record)?;
    native.check_current()?;
    files.check(false)?;
    tx.commit()?;
    drop(c);
    fs::File::open(files.publication())
        .and_then(|f| f.sync_all())
        .map_err(|_| AuthorityError::Storage)?;
    files.sync()?;
    if read_publication(files, key)? != *record {
        return Err(AuthorityError::CorruptHistory);
    }
    native.check_current()?;
    files.check(true)
}
// Private data/SQL layer shared by publication and synthetic package fixtures.
// It cannot construct a native decision, namespace owner or approved reader.
fn stage_publication_rows(tx: &Transaction<'_>, record: &Publication) -> Result<()> {
    record.validate()?;
    tx.execute_batch(PUBLICATION_SCHEMA)?;
    tx.execute(
        "INSERT INTO namespace_archive_publication VALUES(1,?1)",
        [&*encode(record)?],
    )?;
    tx.pragma_update(None, "application_id", PUBLICATION_APP)?;
    tx.pragma_update(None, "user_version", 1)?;
    Ok(())
}

#[cfg(test)]
pub(super) fn write_synthetic_publication_fixture(
    files: &PackageFiles,
    key: &DatabaseKey,
    record: &Publication,
) -> Result<()> {
    // SYNTHETIC TEMPDIR ONLY. No native lease is manufactured and this function
    // does not exist in production. It exercises the same SQL and read verifier.
    files.check(false)?;
    let c = wholepact_storage_security::create_encrypted(files.publication(), key)?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
    stage_publication_rows(&tx, record)?;
    tx.commit()?;
    drop(c);
    fs::File::open(files.publication())
        .and_then(|f| f.sync_all())
        .map_err(|_| AuthorityError::Storage)?;
    files.sync()?;
    if read_publication(files, key)? != *record {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(())
}

pub(super) fn read_publication(files: &PackageFiles, key: &DatabaseKey) -> Result<Publication> {
    files.check(true)?;
    let snapshot =
        wholepact_storage_security::open_encrypted_read_snapshot(files.publication(), key)?;
    let c = snapshot.connection();
    let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if app != PUBLICATION_APP || version != 1 {
        return Err(AuthorityError::UnsupportedVersion);
    }
    let template = rusqlite::Connection::open_in_memory()?;
    template.execute_batch(PUBLICATION_SCHEMA)?;
    let schema = |c: &rusqlite::Connection| -> Result<Vec<(String, String, String)>> {
        let count: u64 = c.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
            [],
            |r| r.get(0),
        )?;
        if count > 4 {
            return Err(AuthorityError::CorruptHistory);
        }
        let mut q = c.prepare("SELECT type,name,coalesce(sql,'') FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name")?;
        let rows = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    };
    if schema(c)? != schema(&template)? {
        return Err(AuthorityError::CorruptHistory);
    }
    let payload: Vec<u8> = c.query_row(
        "SELECT payload FROM namespace_archive_publication WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    if payload.len() > 32_768 {
        return Err(AuthorityError::Limit);
    }
    let record: Publication = crate::decode(&payload)?;
    record.validate()?;
    files.check(true)?;
    Ok(record)
}
