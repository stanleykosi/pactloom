//! SOURCE-ONLY Linux filesystem primitives for the fixed witness installation.
//! This is storage machinery, not native authorization. Authority owns the sole
//! supported setup caller. Never use HOME/XDG/caller-root overrides here.
use crate::{Result, StorageSecurityError as E};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString},
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[cfg(feature = "synthetic-qualification")]
mod ephemeral_qualification;
#[cfg(feature = "synthetic-qualification")]
pub use ephemeral_qualification::EphemeralWitnessInstallation;

const ROOT_NAME: &str = ".wholepact-witness";
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryStamp {
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
}
pub struct InstallationProbe {
    home_path: PathBuf,
    home: File,
    #[cfg(feature = "synthetic-qualification")]
    _ephemeral_qualification: Option<std::sync::Arc<EphemeralWitnessInstallation>>,
}
pub struct InstallationFiles {
    probe: InstallationProbe,
    root: File,
    journals: File,
    marker: File,
    root_path: PathBuf,
    instance_id: String,
    root_stamp: DirectoryStamp,
    journals_stamp: DirectoryStamp,
    // Last so all held descriptors close before the test directory can vanish.
    #[cfg(feature = "synthetic-qualification")]
    _ephemeral_qualification: Option<std::sync::Arc<EphemeralWitnessInstallation>>,
}
impl InstallationProbe {
    /// Resolves the OS password database, ignoring mutable process environment.
    /// Holds the canonical home lock so all supported namespace routes serialize.
    pub fn fixed_user_installation() -> Result<Self> {
        let home_path = os_home()?;
        let home = open_directory_walk(&home_path)?;
        home_metadata(&home)?;
        home.try_lock().map_err(|_| E::UnsafePath)?;
        let this = Self {
            home_path,
            home,
            #[cfg(feature = "synthetic-qualification")]
            _ephemeral_qualification: None,
        };
        this.check_current()?;
        Ok(this)
    }
    pub fn root_path(&self) -> PathBuf {
        self.home_path.join(ROOT_NAME)
    }
    pub fn require_absent(&self) -> Result<()> {
        self.check_current()?;
        match fs::symlink_metadata(self.root_path()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(E::AlreadyExists),
        }
    }
    fn check_current(&self) -> Result<()> {
        let held = home_metadata(&self.home)?;
        let now = open_directory_walk(&self.home_path)?;
        let now = home_metadata(&now)?;
        same(&held, &now)
    }
    /// Exclusive first setup only. No adoption, cleanup, replacement or retry of
    /// a partial directory. Interrupted install stays unknown and blocked.
    pub fn create_once(self, instance_id: &str) -> Result<InstallationFiles> {
        check_id(instance_id)?;
        self.require_absent()?;
        mkdir_at(&self.home, ROOT_NAME)?;
        self.home.sync_all().map_err(|_| E::Io)?;
        let root = open_at(&self.home, ROOT_NAME, libc::O_RDONLY | libc::O_DIRECTORY)?;
        private_directory(&root)?;
        root.try_lock().map_err(|_| E::UnsafePath)?;
        mkdir_at(&root, "journals")?;
        let journals = open_at(&root, "journals", libc::O_RDONLY | libc::O_DIRECTORY)?;
        private_directory(&journals)?;
        journals.try_lock().map_err(|_| E::UnsafePath)?;
        let mut marker = open_at(
            &root,
            "installation.id",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        private_file(&marker)?;
        marker
            .write_all(instance_id.as_bytes())
            .map_err(|_| E::Io)?;
        marker.sync_all().map_err(|_| E::Io)?;
        journals.sync_all().map_err(|_| E::Io)?;
        root.sync_all().map_err(|_| E::Io)?;
        let marker = open_at(&root, "installation.id", libc::O_RDONLY)?;
        assemble(self, root, journals, marker, instance_id.into())
    }
    pub fn open_existing(self) -> Result<InstallationFiles> {
        self.check_current()?;
        let root = open_at(&self.home, ROOT_NAME, libc::O_RDONLY | libc::O_DIRECTORY)?;
        private_directory(&root)?;
        root.try_lock().map_err(|_| E::UnsafePath)?;
        let journals = open_at(&root, "journals", libc::O_RDONLY | libc::O_DIRECTORY)?;
        private_directory(&journals)?;
        journals.try_lock().map_err(|_| E::UnsafePath)?;
        let mut marker = open_at(&root, "installation.id", libc::O_RDONLY)?;
        let metadata = private_file(&marker)?;
        if metadata.len() != 64 {
            return Err(E::AuthenticationFailed);
        }
        let mut value = String::new();
        (&mut marker)
            .take(65)
            .read_to_string(&mut value)
            .map_err(|_| E::Io)?;
        check_id(&value)?;
        assemble(self, root, journals, marker, value)
    }
}
fn assemble(
    probe: InstallationProbe,
    root: File,
    journals: File,
    marker: File,
    instance_id: String,
) -> Result<InstallationFiles> {
    let root_path = probe.root_path();
    let root_stamp = stamp(&private_directory(&root)?);
    let journals_stamp = stamp(&private_directory(&journals)?);
    #[cfg(feature = "synthetic-qualification")]
    let ephemeral_qualification = probe._ephemeral_qualification.clone();
    let out = InstallationFiles {
        probe,
        root,
        journals,
        marker,
        root_path,
        instance_id,
        root_stamp,
        journals_stamp,
        #[cfg(feature = "synthetic-qualification")]
        _ephemeral_qualification: ephemeral_qualification,
    };
    out.check_current()?;
    Ok(out)
}
impl InstallationFiles {
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }
    pub fn registry_path(&self) -> PathBuf {
        self.root_path.join("registry.wp")
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    pub fn root_stamp(&self) -> &DirectoryStamp {
        &self.root_stamp
    }
    pub fn journals_stamp(&self) -> &DirectoryStamp {
        &self.journals_stamp
    }
    pub fn check_current(&self) -> Result<()> {
        self.probe.check_current()?;
        let root = open_at(
            &self.probe.home,
            ROOT_NAME,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let journals = open_at(&root, "journals", libc::O_RDONLY | libc::O_DIRECTORY)?;
        if stamp(&private_directory(&root)?) != self.root_stamp
            || stamp(&private_directory(&journals)?) != self.journals_stamp
            || stamp(&private_directory(&self.root)?) != self.root_stamp
            || stamp(&private_directory(&self.journals)?) != self.journals_stamp
        {
            return Err(E::SourceChanged);
        }
        let mut marker = open_at(&root, "installation.id", libc::O_RDONLY)?;
        same(&private_file(&self.marker)?, &private_file(&marker)?)?;
        let mut value = String::new();
        (&mut marker)
            .take(65)
            .read_to_string(&mut value)
            .map_err(|_| E::Io)?;
        if value != self.instance_id {
            return Err(E::SourceChanged);
        }
        Ok(())
    }
    pub fn sync_directories(&self) -> Result<()> {
        self.check_current()?;
        self.journals.sync_all().map_err(|_| E::Io)?;
        self.root.sync_all().map_err(|_| E::Io)?;
        self.probe.home.sync_all().map_err(|_| E::Io)?;
        Ok(())
    }
}
/// Existing independent storage secret only. Never generated here, never a
/// wallet/spending key. Bounded regular private single-link file, no symlinks.
pub fn read_existing_storage_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = read_existing_private_file(path, 32)?;
    if bytes.len() != 32 {
        return Err(E::AuthenticationFailed);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    if *key == [0u8; 32] {
        return Err(E::AuthenticationFailed);
    }
    Ok(key)
}

/// Bounded existing private input only. No create, chmod, symlink following,
/// credential generation or installation. Every path component is opened via
/// no-follow directory handles; the file and parent are rechecked after reading.
/// Intended for operator-selected protected config and TLS inputs as well as
/// the original fixed-width namespace key. Plain bytes are wiped on normal drop.
pub fn read_existing_private_file(path: &Path, maximum_bytes: usize) -> Result<Zeroizing<Vec<u8>>> {
    if maximum_bytes == 0 || maximum_bytes > 1_048_576 {
        return Err(E::UnsafePath);
    }
    let parent = path.parent().ok_or(E::UnsafePath)?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or(E::UnsafePath)?;
    let directory = open_directory_walk(parent)?;
    let parent_before = private_directory(&directory)?;
    let mut file = open_at(&directory, name, libc::O_RDONLY)?;
    let before = private_file(&file)?;
    if before.len() == 0 || before.len() > maximum_bytes as u64 {
        return Err(E::AuthenticationFailed);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(before.len() as usize));
    (&mut file)
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| E::Io)?;
    let after = private_file(&file)?;
    let reopened_parent = open_directory_walk(parent)?;
    same(&parent_before, &private_directory(&reopened_parent)?)?;
    let reopened = open_at(&reopened_parent, name, libc::O_RDONLY)?;
    let reopened_metadata = private_file(&reopened)?;
    same(&before, &after)?;
    same(&before, &reopened_metadata)?;
    for current in [&after, &reopened_metadata] {
        if current.len() != before.len()
            || current.len() != bytes.len() as u64
            || current.mtime() != before.mtime()
            || current.mtime_nsec() != before.mtime_nsec()
            || current.ctime() != before.ctime()
            || current.ctime_nsec() != before.ctime_nsec()
        {
            return Err(E::SourceChanged);
        }
    }
    if bytes.len() > maximum_bytes {
        return Err(E::AuthenticationFailed);
    }
    Ok(bytes)
}

fn os_home() -> Result<PathBuf> {
    // SAFETY: geteuid has no pointer inputs or side effects.
    let uid = unsafe { libc::geteuid() };
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 65_536];
    // SAFETY: entry, result and writable buffer remain live for the call. libc
    // owns no returned storage; pw_dir is used only while this buffer is live.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || entry.pw_dir.is_null() || entry.pw_uid != uid {
        return Err(E::UnsafePath);
    }
    let bytes = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes();
    let text = std::str::from_utf8(bytes).map_err(|_| E::UnsafePath)?;
    let path = PathBuf::from(text);
    validate_path(&path)?;
    if path == Path::new("/") {
        return Err(E::UnsafePath);
    }
    if fs::canonicalize(&path).map_err(|_| E::UnsafePath)? != path {
        return Err(E::UnsafePath);
    }
    Ok(path)
}
fn validate_path(path: &Path) -> Result<()> {
    let text = path.to_str().ok_or(E::UnsafePath)?;
    if !text.starts_with('/')
        || text.len() > 4096
        || text.ends_with('/')
        || text.contains('\0')
        || text[1..]
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(E::UnsafePath);
    }
    Ok(())
}
fn open_directory_walk(path: &Path) -> Result<File> {
    validate_path(path)?;
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| E::UnsafePath)?;
    for part in path.as_os_str().as_bytes().split(|c| *c == b'/').skip(1) {
        let part = std::str::from_utf8(part).map_err(|_| E::UnsafePath)?;
        current = open_at(&current, part, libc::O_RDONLY | libc::O_DIRECTORY)?;
    }
    Ok(current)
}
fn open_at(parent: &File, name: &str, flags: i32) -> Result<File> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(E::UnsafePath);
    }
    let name = CString::new(name).map_err(|_| E::UnsafePath)?;
    // SAFETY: parent is live, name is NUL-terminated, new descriptor transfers once.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(E::UnsafePath);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn mkdir_at(parent: &File, name: &str) -> Result<()> {
    let name = CString::new(name).map_err(|_| E::UnsafePath)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(E::AlreadyExists);
    }
    Ok(())
}
fn home_metadata(file: &File) -> Result<Metadata> {
    let m = file.metadata().map_err(|_| E::Io)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
        return Err(E::UnsafePath);
    }
    Ok(m)
}
fn private_directory(file: &File) -> Result<Metadata> {
    let m = home_metadata(file)?;
    if m.mode() & 0o7777 != 0o700 {
        return Err(E::UnsafePath);
    }
    Ok(m)
}
fn private_file(file: &File) -> Result<Metadata> {
    let m = file.metadata().map_err(|_| E::Io)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != 0o600
    {
        return Err(E::UnsafePath);
    }
    Ok(m)
}
fn stamp(m: &Metadata) -> DirectoryStamp {
    DirectoryStamp {
        device: m.dev(),
        inode: m.ino(),
        owner_uid: m.uid(),
    }
}
fn same(a: &Metadata, b: &Metadata) -> Result<()> {
    if a.dev() != b.dev() || a.ino() != b.ino() {
        Err(E::SourceChanged)
    } else {
        Ok(())
    }
}
fn check_id(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Err(E::AuthenticationFailed)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_installation_path_components_have_no_root_override() {
        assert_eq!(ROOT_NAME, ".wholepact-witness");
        for value in [
            "relative",
            "/tmp/../other",
            "/tmp//other",
            "/tmp/other/",
            "/tmp/./other",
        ] {
            assert!(validate_path(Path::new(value)).is_err());
        }
        validate_path(Path::new("/synthetic/private-home")).unwrap();
    }
    #[test]
    fn public_installation_id_is_exact_lowercase_digest_data() {
        check_id(&"a".repeat(64)).unwrap();
        for value in [
            "A".repeat(64),
            "a".repeat(63),
            "../".repeat(22),
            "0".repeat(65),
        ] {
            assert!(check_id(&value).is_err());
        }
    }
    // Never call fixed_user_installation/create_once from these synthetic tests:
    // they must not touch the real OS user's canonical installation directory.
}

#[cfg(test)]
mod private_input_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("public-synthetic-input");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"explicit public synthetic data").unwrap();
        file.sync_all().unwrap();
        (root, path)
    }
    #[test]
    fn bounded_private_input_reads_only_exact_existing_file_and_preserves_bytes() {
        let (_root, path) = fixture();
        let before = fs::read(&path).unwrap();
        let bytes = read_existing_private_file(&path, 64).unwrap();
        assert_eq!(&*bytes, &before);
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(read_existing_private_file(&path, before.len() - 1).is_err());
        assert!(read_existing_private_file(&path, 0).is_err());
        assert!(read_existing_private_file(&path, 1_048_577).is_err());
    }
    #[test]
    fn private_input_rejects_symlink_hardlink_public_file_and_public_parent() {
        let (root, path) = fixture();
        let alias = root.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(read_existing_private_file(&alias, 64).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&path, &alias).unwrap();
        assert!(read_existing_private_file(&path, 64).is_err());
        fs::remove_file(alias).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_existing_private_file(&path, 64).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(read_existing_private_file(&path, 64).is_err());
    }
    #[test]
    fn original_fixed_width_key_reader_keeps_exact_width_and_nonzero_contract() {
        let (_root, path) = fixture();
        fs::write(&path, [0u8; 32]).unwrap();
        assert!(read_existing_storage_key(&path).is_err());
        // Public repeated bytes are inert parser fixtures, not installed keys.
        fs::write(&path, [0x51u8; 32]).unwrap();
        assert_eq!(*read_existing_storage_key(&path).unwrap(), [0x51u8; 32]);
        fs::write(&path, [0x51u8; 33]).unwrap();
        assert!(read_existing_storage_key(&path).is_err());
        fs::write(&path, [0x51u8; 31]).unwrap();
        assert!(read_existing_storage_key(&path).is_err());
    }
}
