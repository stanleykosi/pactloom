//! Exact, bounded retained ciphertext-source checks for this one original
//! restored-account layout. No SQLite connection or key material is retained.
//!
//! The owning account holds both existing cooperative directory locks throughout
//! capture, authentication, native review and use. These checks detect changes;
//! they do not defeat hostile same-user replacement between checks, establish
//! live writer freshness, or establish a cross-database atomic snapshot.
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::Instant,
};
use zeroize::Zeroizing;

// Shared across BOTH complete source trees, not an allowance per file or DB.
const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
const PROFILE_NAMES: &[&str] = &[
    "signer.lock",
    "account.wp",
    "authority.sqlite",
    "authority.sqlite-wal",
    "authority.sqlite-shm",
    "viewing-wallet-key.wp",
    "viewing-wallet.sqlite",
    "viewing-wallet.sqlite-wal",
    "viewing-wallet.sqlite-shm",
    "recipient-record-key.wp",
    "recipient-records.wp",
];
const ARCHIVE_NAMES: &[&str] = &[
    "signer.lock",
    "recovery.wp",
    "COMPLETE",
    "bundle.sqlite",
    "bundle.sqlite-wal",
    "bundle.sqlite-shm",
];

pub(super) fn before_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::ReviewMismatch)
    } else {
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
}
impl Stamp {
    fn read(metadata: &fs::Metadata, directory: bool) -> Result<Self> {
        // SAFETY: geteuid reads process identity and takes no arguments.
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || (directory && !metadata.is_dir())
            || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        {
            return Err(Error::InvalidData);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            mode: metadata.mode(),
            owner: metadata.uid(),
            group: metadata.gid(),
            links: metadata.nlink(),
        })
    }
    fn commit(&self, digest: &mut Sha256) {
        for value in [self.device, self.inode, self.length, self.links] {
            digest.update(value.to_be_bytes());
        }
        for value in [
            self.modified.0,
            self.modified.1,
            self.changed.0,
            self.changed.1,
        ] {
            digest.update(value.to_be_bytes());
        }
        for value in [self.mode, self.owner, self.group] {
            digest.update(value.to_be_bytes());
        }
    }
}

fn maximum(name: &str) -> u64 {
    match name {
        "signer.lock" | "COMPLETE" => 512,
        "account.wp" => (super::MAX_ACCOUNT + 1024) as u64,
        "recovery.wp" => 5 * 1024 * 1024,
        "viewing-wallet-key.wp" | "recipient-record-key.wp" => 1024,
        "recipient-records.wp" => 4 * 1024 * 1024 + 1024,
        _ => MAX_SOURCE_BYTES,
    }
}

/// Preflight happens before even opening existing lock files. Only this finite
/// allowlist is traversed; unsupported names, orphan halves and sidecars fail.
pub(super) fn inventory(root: &Path, archive: bool, deadline: Instant) -> Result<()> {
    read_inventory(root, archive, deadline).map(|_| ())
}
fn read_inventory(
    root: &Path,
    archive: bool,
    deadline: Instant,
) -> Result<BTreeMap<String, Stamp>> {
    before_deadline(deadline)?;
    Stamp::read(&fs::symlink_metadata(root)?, true)?;
    let allowed = if archive {
        ARCHIVE_NAMES
    } else {
        PROFILE_NAMES
    };
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for entry in fs::read_dir(root)? {
        before_deadline(deadline)?;
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        if files.len() >= allowed.len() || !allowed.contains(&name.as_str()) {
            return Err(Error::InvalidData);
        }
        let stamp = Stamp::read(&fs::symlink_metadata(entry.path())?, false)?;
        total = total
            .checked_add(stamp.length)
            .filter(|total| *total <= MAX_SOURCE_BYTES)
            .ok_or(Error::InvalidData)?;
        if stamp.length > maximum(&name) || files.insert(name, stamp).is_some() {
            return Err(Error::InvalidData);
        }
    }
    let required: &[&str] = if archive {
        &["signer.lock", "recovery.wp", "COMPLETE", "bundle.sqlite"]
    } else {
        &["signer.lock", "account.wp", "authority.sqlite"]
    };
    if required.iter().any(|name| !files.contains_key(*name)) {
        return Err(Error::RecoveryRequired);
    }
    if !archive {
        let wallet = files.contains_key("viewing-wallet.sqlite");
        if wallet != files.contains_key("viewing-wallet-key.wp")
            || (!wallet
                && ["viewing-wallet.sqlite-wal", "viewing-wallet.sqlite-shm"]
                    .iter()
                    .any(|name| files.contains_key(*name)))
            || files.contains_key("recipient-record-key.wp")
                != files.contains_key("recipient-records.wp")
        {
            return Err(Error::InvalidData);
        }
    }
    before_deadline(deadline)?;
    Ok(files)
}

struct SourceFile {
    descriptor: File,
    stamp: Stamp,
    content: [u8; 32],
}
struct SourceTree {
    root: PathBuf,
    directory: File,
    stamp: Stamp,
    archive: bool,
    files: BTreeMap<String, SourceFile>,
}
impl SourceTree {
    fn capture(root: &Path, archive: bool, remaining: &mut u64, deadline: Instant) -> Result<Self> {
        before_deadline(deadline)?;
        if !root.is_absolute() || fs::canonicalize(root)? != root {
            return Err(Error::InvalidData);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(root)?;
        let stamp = Stamp::read(&directory.metadata()?, true)?;
        let inventory = read_inventory(root, archive, deadline)?;
        let mut files = BTreeMap::new();
        for (name, expected) in inventory {
            before_deadline(deadline)?;
            let descriptor = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(root.join(&name))?;
            let stamp = Stamp::read(&descriptor.metadata()?, false)?;
            if stamp != expected {
                return Err(Error::RecoveryRequired);
            }
            *remaining = remaining
                .checked_sub(stamp.length)
                .ok_or(Error::InvalidData)?;
            let content = hash_file_until(&descriptor, stamp.length, deadline)?;
            files.insert(
                name,
                SourceFile {
                    descriptor,
                    stamp,
                    content,
                },
            );
        }
        let tree = Self {
            root: root.into(),
            directory,
            stamp,
            archive,
            files,
        };
        tree.check_metadata(deadline)?;
        Ok(tree)
    }
    fn check_metadata(&self, deadline: Instant) -> Result<()> {
        before_deadline(deadline)?;
        if fs::canonicalize(&self.root)? != self.root
            || Stamp::read(&fs::symlink_metadata(&self.root)?, true)? != self.stamp
            || Stamp::read(&self.directory.metadata()?, true)? != self.stamp
        {
            return Err(Error::RecoveryRequired);
        }
        let actual = read_inventory(&self.root, self.archive, deadline)?;
        if actual.len() != self.files.len() {
            return Err(Error::RecoveryRequired);
        }
        for (name, source) in &self.files {
            before_deadline(deadline)?;
            if actual.get(name) != Some(&source.stamp)
                || Stamp::read(&source.descriptor.metadata()?, false)? != source.stamp
            {
                return Err(Error::RecoveryRequired);
            }
        }
        before_deadline(deadline)
    }
    fn check_content(&self, deadline: Instant) -> Result<()> {
        self.check_metadata(deadline)?;
        for source in self.files.values() {
            if hash_file_until(&source.descriptor, source.stamp.length, deadline)? != source.content
            {
                return Err(Error::RecoveryRequired);
            }
        }
        self.check_metadata(deadline)
    }
    fn commit(&self, digest: &mut Sha256) {
        digest.update([u8::from(self.archive)]);
        commit_bytes(digest, self.root.as_os_str().as_bytes());
        self.stamp.commit(digest);
        digest.update((self.files.len() as u64).to_be_bytes());
        for (name, source) in &self.files {
            commit_bytes(digest, name.as_bytes());
            source.stamp.commit(digest);
            digest.update(source.content);
        }
    }
}
fn commit_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn hash_file_until(file: &File, length: u64, deadline: Instant) -> Result<[u8; 32]> {
    hash_until(length, deadline, Instant::now, |buffer, offset| {
        file.read_at(buffer, offset)
    })
}
fn hash_until(
    length: u64,
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut read: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> Result<[u8; 32]> {
    if length > MAX_SOURCE_BYTES {
        return Err(Error::InvalidData);
    }
    let mut check = || {
        if now() >= deadline {
            Err(Error::ReviewMismatch)
        } else {
            Ok(())
        }
    };
    let mut digest = Sha256::new();
    let mut buffer = Zeroizing::new([0u8; CHUNK_BYTES]);
    let mut offset = 0u64;
    while offset < length {
        check()?;
        let count = (length - offset).min(CHUNK_BYTES as u64) as usize;
        let result = read(&mut buffer[..count], offset);
        check()?;
        match result {
            Ok(0) => return Err(Error::RecoveryRequired),
            Ok(read) if read <= count => {
                digest.update(&buffer[..read]);
                offset += read as u64;
            }
            Ok(_) => return Err(Error::RecoveryRequired),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    // Check the exact EOF too; never read an unbounded growing source.
    loop {
        check()?;
        let result = read(&mut buffer[..1], length);
        check()?;
        match result {
            Ok(0) => break,
            Ok(_) => return Err(Error::RecoveryRequired),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(digest.finalize().into())
}

/// No Clone, Debug, serialization, path accessor, mutable handle or key field.
pub(super) struct RetainedSources {
    profile: SourceTree,
    archive: SourceTree,
    digest: String,
    deadline: Instant,
}
impl RetainedSources {
    pub(super) fn capture(profile: &Path, archive: &Path, deadline: Instant) -> Result<Self> {
        if profile == archive {
            return Err(Error::InvalidData);
        }
        let mut remaining = MAX_SOURCE_BYTES;
        let profile = SourceTree::capture(profile, false, &mut remaining, deadline)?;
        let archive = SourceTree::capture(archive, true, &mut remaining, deadline)?;
        profile.check_metadata(deadline)?;
        archive.check_metadata(deadline)?;
        let mut digest = Sha256::new();
        digest.update(b"wholepact.quarantined-original-source-inventory.v1\0");
        profile.commit(&mut digest);
        archive.commit(&mut digest);
        before_deadline(deadline)?;
        Ok(Self {
            profile,
            archive,
            digest: hex::encode(digest.finalize()),
            deadline,
        })
    }
    pub(super) fn check_until(&self, deadline: Instant) -> Result<()> {
        let deadline = deadline.min(self.deadline);
        self.profile.check_content(deadline)?;
        self.archive.check_content(deadline)?;
        // The first tree is checked again after reading the complete second one.
        self.profile.check_metadata(deadline)?;
        self.archive.check_metadata(deadline)?;
        before_deadline(deadline)
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }
}

#[cfg(test)]
#[path = "source_guard/tests.rs"]
mod tests;
