//! A distinct fixed common-image pin, never the legacy signer provider. This
//! selects installed bytes under the trusted OS/installer assumption only.
use crate::{rejected, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::CStr,
    fs::File,
    io::Read,
    os::{fd::{AsRawFd, FromRawFd, OwnedFd}, unix::fs::MetadataExt},
};

const MAX_IMAGE: u64 = 512 * 1024 * 1024;
const MAX_PIN: u64 = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommonImagePinV1 {
    schema_version: u16,
    profile: String,
    executable_device: u64,
    executable_inode: u64,
    executable_size: u64,
    executable_sha256: String,
}

/// Opened executing image kept only by C. Not an issuer, permission or proof of
/// a pristine process. Children inherit the verified image by actual fork.
pub(super) struct PinnedCommonImageV1 {
    _image: File,
}

impl PinnedCommonImageV1 {
    #[cfg(wholepact_bootstrap_ci)]
    pub(super) fn ci_fd(&self) -> libc::c_int { self._image.as_raw_fd() }
    pub(super) fn load_running_image() -> Result<Self> {
        // Descriptor-relative traversal avoids checking one directory and then
        // opening an attacker-replaced different pathname component.
        let root = open_at(libc::AT_FDCWD, c"/", true)?;
        let etc = open_at(root.as_raw_fd(), c"etc", true)?;
        let wholepact = open_at(etc.as_raw_fd(), c"wholepact", true)?;
        let pin_fd = open_at(
            wholepact.as_raw_fd(),
            c"financial-coordinator-common-image-v1.json",
            false,
        )?;
        let mut file = File::from(pin_fd);
        let before = file.metadata()?;
        if before.len() == 0 || before.len() > MAX_PIN {
            return Err(rejected("common image pin size"));
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        file.by_ref().take(MAX_PIN + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != before.len() || !same_file(&before, &file.metadata()?) {
            return Err(rejected("common image pin changed"));
        }
        let pin = parse_pin_data(&bytes)?;
        // /proc/self/exe is intentionally the kernel's executing-image link,
        // not a caller pathname and not an observation of some other process.
        let raw = unsafe { libc::open(c"/proc/self/exe".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if raw < 0 { return Err(std::io::Error::last_os_error()); }
        let mut image = unsafe { File::from_raw_fd(raw) };
        let before = image.metadata()?;
        if !before.is_file() || before.uid() != 0 || before.mode() & 0o022 != 0
            || before.mode() & 0o111 == 0 || before.dev() != pin.executable_device
            || before.ino() != pin.executable_inode || before.len() != pin.executable_size
        {
            return Err(rejected("executing common image does not match pin"));
        }
        let mut digest = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut seen = 0u64;
        loop {
            let n = image.read(&mut buf)?;
            if n == 0 { break; }
            seen = seen.checked_add(n as u64).ok_or_else(|| rejected("image overflow"))?;
            if seen > MAX_IMAGE { return Err(rejected("image too large")); }
            digest.update(&buf[..n]);
        }
        if seen != before.len() || !same_file(&before, &image.metadata()?)
            || hex::encode(digest.finalize()) != pin.executable_sha256
        {
            return Err(rejected("executing common image changed or mismatched"));
        }
        Ok(Self { _image: image })
    }
}

// Parsing produces data only, never installed trust or a fork origin.
fn parse_pin_data(bytes: &[u8]) -> Result<CommonImagePinV1> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_PIN {
        return Err(rejected("common image pin size"));
    }
    let pin: CommonImagePinV1 = serde_json::from_slice(bytes)
        .map_err(|_| rejected("common image pin format"))?;
    if pin.schema_version != 1
        || pin.profile != "financial-coordinator-common-image-linux-v1"
        || pin.executable_inode == 0
        || pin.executable_size == 0
        || pin.executable_size > MAX_IMAGE
        || pin.executable_sha256.len() != 64
        || !pin.executable_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(rejected("common image pin unsupported"));
    }
    Ok(pin)
}

fn open_at(parent: libc::c_int, name: &CStr, directory: bool) -> Result<OwnedFd> {
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if directory { flags |= libc::O_DIRECTORY; }
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if raw < 0 { return Err(std::io::Error::last_os_error()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut meta: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut meta) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let required = if directory { libc::S_IFDIR } else { libc::S_IFREG };
    if meta.st_uid != 0 || meta.st_mode & 0o022 != 0 || meta.st_mode & libc::S_IFMT != required {
        return Err(rejected("common image pin path is not root controlled"));
    }
    Ok(fd)
}

fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino() && a.len() == b.len()
        && a.uid() == b.uid() && a.mode() == b.mode()
        && a.mtime() == b.mtime() && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime() && a.ctime_nsec() == b.ctime_nsec()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid_data() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "profile": "financial-coordinator-common-image-linux-v1",
            "executable_device": 1,
            "executable_inode": 2,
            "executable_size": 3,
            "executable_sha256": "ab".repeat(32)
        })).unwrap()
    }
    #[test]
    fn pin_data_rejects_unknown_duplicate_missing_and_oversized_input() {
        let bytes = valid_data();
        assert!(parse_pin_data(&bytes).is_ok());
        let text = String::from_utf8(bytes).unwrap();
        assert!(parse_pin_data(text.replacen('{', "{\"unknown\":1,", 1).as_bytes()).is_err());
        assert!(parse_pin_data(text.replacen('{', "{\"schema_version\":1,", 1).as_bytes()).is_err());
        assert!(parse_pin_data(b"{}").is_err());
        assert!(parse_pin_data(&vec![b' '; MAX_PIN as usize + 1]).is_err());
        assert!(parse_pin_data(b"").is_err());
    }
    #[test]
    fn pin_data_rejects_wrong_profile_version_hash_inode_and_size() {
        let baseline: serde_json::Value = serde_json::from_slice(&valid_data()).unwrap();
        for (field, value) in [
            ("schema_version", serde_json::json!(2)),
            ("profile", serde_json::json!("legacy-signer")),
            ("executable_sha256", serde_json::json!("AB".repeat(32))),
            ("executable_sha256", serde_json::json!("ab")),
            ("executable_inode", serde_json::json!(0)),
            ("executable_size", serde_json::json!(0)),
            ("executable_size", serde_json::json!(MAX_IMAGE + 1)),
        ] {
            let mut data = baseline.clone();
            data[field] = value;
            assert!(parse_pin_data(&serde_json::to_vec(&data).unwrap()).is_err());
        }
    }
}
