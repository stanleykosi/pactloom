//! Bounded local inputs selected in the genuine recipient window. These bytes
//! remain untrusted; reading them never establishes enrollment or approval.
use crate::native_ui::NativeAuthority;
use crate::{Error, Result};
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Component, Path},
};
use zeroize::Zeroizing;

pub(super) fn read_selected_input(
    source: &NativeAuthority,
    path: &Path,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    source.check_current()?;
    if maximum == 0
        || maximum > 16 * 1024 * 1024
        || !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(Error::InvalidData);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        // NONBLOCK prevents an attacker-controlled FIFO from blocking before the
        // regular-file check. NOFOLLOW refuses final-component symlinks.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let before = file.metadata()?;
        let uid = unsafe { libc::geteuid() };
        if !before.is_file()
            || before.uid() != uid
            || before.mode() & 0o077 != 0
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > maximum as u64
        {
            return Err(Error::InvalidData);
        }
        source.check_current()?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&file).take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        source.check_current()?;
        if bytes.is_empty()
            || bytes.len() > maximum
            || bytes.len() as u64 != before.len()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(Error::InvalidData);
        }
        // The later exact review binds these captured bytes, not a future reread.
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, maximum);
        Err(Error::Unavailable)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn selected_input_reads_exact_private_bytes_and_rejects_untrusted_file_shapes() {
        let root = tempfile::tempdir().unwrap();
        let source = crate::native_ui::recovery_test_authority();
        let path = root.path().join("input.json");
        std::fs::write(&path, b"{\"untrusted\":true}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            &**read_selected_input(&source, &path, 100).unwrap(),
            b"{\"untrusted\":true}"
        );
        assert!(read_selected_input(&source, &path, 2).is_err());
        assert!(read_selected_input(&source, Path::new("input.json"), 100).is_err());
        let alias = root.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(read_selected_input(&source, &alias, 100).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_selected_input(&source, &path, 100).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let linked = root.path().join("linked");
        std::fs::hard_link(&path, &linked).unwrap();
        assert!(read_selected_input(&source, &path, 100).is_err());
    }
}
