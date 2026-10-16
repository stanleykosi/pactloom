//! Native preparation of an installation trust-anchor document. This writes only
//! a private staging file. A privileged owner/package installer must separately
//! install it at the fixed /etc location; ordinary JSON is never client authority.
use super::authority::{NativeAuthority, NativeDecision};
use crate::{files::PrivateDirectory, Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
#[derive(Serialize)]
struct ProviderDocument {
    schema_version: u32,
    executable_path: String,
    executable_sha256: String,
    executable_device: u64,
    executable_inode: u64,
    native_enrollment_reference: String,
}
pub(super) struct PreparedProviderExport {
    image: File,
    document: ProviderDocument,
    digest: String,
}
impl PreparedProviderExport {
    pub(super) fn prepare(path: &str, authority: &NativeAuthority) -> Result<Self> {
        authority.check_current()?;
        let path = Path::new(path);
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(Error::InvalidData);
        }
        let mut image = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = image.metadata()?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || meta.mode() & 0o111 == 0
        {
            return Err(Error::Authentication);
        }
        let image_hash = hash_image(&mut image)?;
        let mut document = ProviderDocument {
            schema_version: 1,
            executable_path: path.to_str().ok_or(Error::InvalidData)?.into(),
            executable_sha256: image_hash,
            executable_device: meta.dev(),
            executable_inode: meta.ino(),
            native_enrollment_reference: String::new(),
        };
        let mut h = Sha256::new();
        h.update(b"wholepact:native-installed-provider-enrollment:v1\0");
        h.update(crate::vault::random::<32>()?);
        h.update(authority.measurement().as_bytes());
        h.update(serde_json::to_vec(&document).map_err(|_| Error::InvalidData)?);
        let digest = hex::encode(h.finalize());
        document.native_enrollment_reference = digest.clone();
        Ok(Self {
            image,
            document,
            digest,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        Ok(format!("ENROLL INSTALLED SIGNER PROVIDER\n{}\n\nTrust root: owner/package installer and operating system. This pin identifies an installed executable, not a publisher or human.\nThis action writes a private installation-request file only. The administrator must separately install it at /etc/wholepact/signer-provider.json with protected root ownership and protected ancestors.\nAn ordinary copy of this JSON cannot grant client authority. Updating the executable requires new enrollment. No app unlock, spending permission or account keys are granted.", serde_json::to_string_pretty(&self.document).map_err(|_| Error::InvalidData)?))
    }
    pub(super) fn export(
        mut self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        directory: &str,
    ) -> Result<()> {
        authority.check_current()?;
        if decision.binding() != &authority.binding() || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let meta = self.image.metadata()?;
        if meta.dev() != self.document.executable_device
            || meta.ino() != self.document.executable_inode
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || hash_image(&mut self.image)? != self.document.executable_sha256
        {
            return Err(Error::Authentication);
        }
        let destination = PrivateDirectory::create(Path::new(directory))?;
        destination.write(
            "signer-provider.json",
            &serde_json::to_vec_pretty(&self.document).map_err(|_| Error::InvalidData)?,
        )
    }
}
fn hash_image(image: &mut File) -> Result<String> {
    image.rewind()?;
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    loop {
        let n = image.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
