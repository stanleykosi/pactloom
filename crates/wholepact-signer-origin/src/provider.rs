//! Linux installed-provider trust anchor. The only production constructor reads
//! the fixed owner-installed, root-controlled configuration; arbitrary JSON,
//! caller paths, image digests or success flags cannot mint this capability.
//! No installation or /etc mutation is performed by this module.
use crate::native_peer::PeerProcess;
use crate::{Error as BridgeError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        net::UnixStream,
    },
    path::{Component, Path},
};

#[cfg(all(
    feature = "synthetic-qualification",
    feature = "native-ui",
    feature = "authority-signing"
))]
mod qualification_endpoint;
#[cfg(all(
    feature = "synthetic-qualification",
    feature = "native-ui",
    feature = "authority-signing"
))]
pub use qualification_endpoint::QualificationEndpointReporterV1;

const INSTALLED_PIN: &str = "/etc/wholepact/signer-provider.json";
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

/// Evidence format produced by native enrollment for a separately authorized
/// installer. Deserializing this does not establish installed trust.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerProviderInstallRequest {
    pub schema_version: u16,
    pub executable_path: String,
    pub executable_sha256: String,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub native_enrollment_reference: String,
}

/// Owner-installed OS trust root. This is provenance under the trusted OS and
/// installer assumption, not publisher attestation or a proof of human action.
pub struct InstalledSignerProvider {
    pin: SignerProviderInstallRequest,
    launched: std::sync::Mutex<Option<crate::native_launch::LaunchedSigner>>,
    #[cfg(all(
        feature = "synthetic-qualification",
        feature = "native-ui",
        feature = "authority-signing"
    ))]
    qualification_process: Option<(u32, u32)>,
    #[cfg(all(
        feature = "synthetic-qualification",
        feature = "native-ui",
        feature = "authority-signing"
    ))]
    qualification_endpoint: Option<qualification_endpoint::QualificationEndpointReceiverV1>,
}
impl InstalledSignerProvider {
    pub fn load() -> Result<Self> {
        let mut file = open_root_controlled(Path::new(INSTALLED_PIN), false)?;
        if file
            .metadata()
            .map_err(|_| BridgeError::SignerOriginUnavailable)?
            .len()
            > 4096
        {
            return Err(BridgeError::SignerOriginUnavailable);
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| BridgeError::SignerOriginUnavailable)?;
        if bytes.len() > 4096 {
            return Err(BridgeError::SignerOriginUnavailable);
        }
        let pin: SignerProviderInstallRequest =
            serde_json::from_slice(&bytes).map_err(|_| BridgeError::SignerOriginUnavailable)?;
        validate_pin(&pin)?;
        let mut executable = open_root_controlled(Path::new(&pin.executable_path), true)?;
        verify_image(&mut executable, &pin)?;
        Ok(Self {
            pin,
            launched: std::sync::Mutex::new(None),
            #[cfg(all(
                feature = "synthetic-qualification",
                feature = "native-ui",
                feature = "authority-signing"
            ))]
            qualification_process: None,
            #[cfg(all(
                feature = "synthetic-qualification",
                feature = "native-ui",
                feature = "authority-signing"
            ))]
            qualification_endpoint: None,
        })
    }
    /// Narrow synthetic harness issuer: no caller path, identity, credential or
    /// verification flag is accepted. This trusts only this running test image
    /// and cannot qualify installed provenance or native human attendance.
    #[cfg(all(
        feature = "synthetic-qualification",
        feature = "native-ui",
        feature = "authority-signing"
    ))]
    pub fn qualification_current_process() -> Result<Self> {
        let mut image =
            File::open("/proc/self/exe").map_err(|_| BridgeError::SignerOriginUnavailable)?;
        let metadata = image
            .metadata()
            .map_err(|_| BridgeError::SignerOriginUnavailable)?;
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o022 != 0 || metadata.mode() & 0o111 == 0 {
            return Err(BridgeError::SignerOriginUnavailable);
        }
        let executable_sha256 = image_sha256(&mut image)?;
        let reference = hex::encode(Sha256::digest(format!(
            "wholepact/synthetic-current-process-provider/v1:{}:{}:{}:{}",
            std::process::id(),
            metadata.dev(),
            metadata.ino(),
            executable_sha256
        )));
        let pin = SignerProviderInstallRequest {
            schema_version: 1,
            executable_path: "/proc/self/exe".into(),
            executable_sha256,
            executable_device: metadata.dev(),
            executable_inode: metadata.ino(),
            native_enrollment_reference: reference,
        };
        validate_pin(&pin)?;
        let mut image =
            File::open("/proc/self/exe").map_err(|_| BridgeError::SignerOriginUnavailable)?;
        verify_image_owner(&mut image, &pin, uid)?;
        Ok(Self {
            pin,
            launched: std::sync::Mutex::new(None),
            qualification_process: Some((std::process::id(), uid)),
            #[cfg(all(
                feature = "synthetic-qualification",
                feature = "native-ui",
                feature = "authority-signing"
            ))]
            qualification_endpoint: None,
        })
    }
    /// Synthetic-only paired availability channel. The original provider is
    /// moved into the actual read client; its sole reporter stays with that same
    /// native controller until successful fresh completion reopen. No path or
    /// caller identity is accepted here, and no production launch is changed.
    #[cfg(all(
        feature = "synthetic-qualification",
        feature = "native-ui",
        feature = "authority-signing"
    ))]
    pub fn qualification_current_process_endpoint_pair()
        -> Result<(Self, QualificationEndpointReporterV1)>
    {
        let mut provider = Self::qualification_current_process()?;
        let (receiver, reporter) = qualification_endpoint::pair();
        provider.qualification_endpoint = Some(receiver);
        Ok((provider, reporter))
    }
    /// Launch exactly the opened owner-installed image. The child still requires
    /// native unlock/pairing; the inherited channel conveys only its endpoint.
    pub fn launch_native(&self) -> Result<()> {
        #[cfg(all(
            feature = "synthetic-qualification",
            feature = "native-ui",
            feature = "authority-signing"
        ))]
        if self.qualification_process.is_some() {
            return Err(BridgeError::SignerOriginUnavailable);
        }
        let mut launched = self
            .launched
            .lock()
            .map_err(|_| BridgeError::SignerOriginUnavailable)?;
        if launched.is_some() {
            return Err(BridgeError::Conflict);
        }
        let mut image = open_root_controlled(Path::new(&self.pin.executable_path), true)?;
        verify_image(&mut image, &self.pin)?;
        *launched = Some(
            crate::native_launch::LaunchedSigner::spawn(image)
                .map_err(|_| BridgeError::SignerOriginUnavailable)?,
        );
        Ok(())
    }
    pub fn wait_native_endpoint(&self, timeout: std::time::Duration) -> Result<std::path::PathBuf> {
        #[cfg(all(
            feature = "synthetic-qualification",
            feature = "native-ui",
            feature = "authority-signing"
        ))]
        if let Some(receiver) = &self.qualification_endpoint {
            return receiver.wait(timeout);
        }
        self.launched
            .lock()
            .map_err(|_| BridgeError::SignerOriginUnavailable)?
            .as_ref()
            .ok_or(BridgeError::SignerOriginUnavailable)?
            .wait_endpoint(timeout)
            .map_err(|_| BridgeError::SignerOriginUnavailable)
    }
    pub fn verify_server(&self, stream: &UnixStream) -> Result<PeerProcess> {
        if let Some(child) = self
            .launched
            .lock()
            .map_err(|_| BridgeError::SignerOriginUnavailable)?
            .as_ref()
        {
            return child
                .verify_server(stream)
                .map_err(|_| BridgeError::SignerOriginUnavailable);
        }
        let peer =
            PeerProcess::observe(stream).map_err(|_| BridgeError::SignerOriginUnavailable)?;
        // Intentionally fail closed on procfs/ptrace permission denial. Never
        // weaken PR_SET_DUMPABLE=0 or fall back to a peer-reported image hash.
        let mut image = File::open(format!("/proc/{}/exe", peer.pid()))
            .map_err(|_| BridgeError::SignerOriginUnavailable)?;
        #[cfg(all(
            feature = "synthetic-qualification",
            feature = "native-ui",
            feature = "authority-signing"
        ))]
        let expected_owner = if let Some((pid, uid)) = self.qualification_process {
            if peer.pid() != pid || peer.uid() != uid || pid != std::process::id() {
                return Err(BridgeError::SignerOriginUnavailable);
            }
            uid
        } else {
            0
        };
        #[cfg(not(all(
            feature = "synthetic-qualification",
            feature = "native-ui",
            feature = "authority-signing"
        )))]
        let expected_owner = 0;
        verify_image_owner(&mut image, &self.pin, expected_owner)?;
        peer.check_alive()
            .map_err(|_| BridgeError::SignerOriginUnavailable)?;
        Ok(peer)
    }
    pub fn native_enrollment_reference(&self) -> &str {
        &self.pin.native_enrollment_reference
    }
}
fn validate_pin(pin: &SignerProviderInstallRequest) -> Result<()> {
    let hash = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if pin.schema_version != 1
        || !hash(&pin.executable_sha256)
        || !hash(&pin.native_enrollment_reference)
        || pin.executable_device == 0
        || pin.executable_inode == 0
        || pin.executable_path.len() > 4096
    {
        return Err(BridgeError::SignerOriginUnavailable);
    }
    Ok(())
}
fn open_root_controlled(path: &Path, executable: bool) -> Result<File> {
    if !path.is_absolute() {
        return Err(BridgeError::SignerOriginUnavailable);
    }
    let mut prefix = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => prefix.push("/"),
            Component::Normal(part) => prefix.push(part),
            _ => return Err(BridgeError::SignerOriginUnavailable),
        }
        let metadata =
            std::fs::symlink_metadata(&prefix).map_err(|_| BridgeError::SignerOriginUnavailable)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (prefix != path && !metadata.is_dir())
        {
            return Err(BridgeError::SignerOriginUnavailable);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| BridgeError::SignerOriginUnavailable)?;
    let meta = file
        .metadata()
        .map_err(|_| BridgeError::SignerOriginUnavailable)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || (executable && meta.mode() & 0o111 == 0)
    {
        return Err(BridgeError::SignerOriginUnavailable);
    }
    Ok(file)
}
fn verify_image(file: &mut File, pin: &SignerProviderInstallRequest) -> Result<()> {
    verify_image_owner(file, pin, 0)
}
fn verify_image_owner(
    file: &mut File,
    pin: &SignerProviderInstallRequest,
    owner: u32,
) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|_| BridgeError::SignerOriginUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o022 != 0
        || metadata.dev() != pin.executable_device
        || metadata.ino() != pin.executable_inode
        || metadata.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(BridgeError::SignerOriginUnavailable);
    }
    if image_sha256(file)? != pin.executable_sha256 {
        return Err(BridgeError::SignerOriginUnavailable);
    }
    Ok(())
}
fn image_sha256(file: &mut File) -> Result<String> {
    let metadata = file
        .metadata()
        .map_err(|_| BridgeError::SignerOriginUnavailable)?;
    if !metadata.is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(BridgeError::SignerOriginUnavailable);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut seen = 0u64;
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| BridgeError::SignerOriginUnavailable)?;
        if n == 0 {
            break;
        }
        seen = seen
            .checked_add(n as u64)
            .ok_or(BridgeError::SignerOriginUnavailable)?;
        if seen > MAX_EXECUTABLE_BYTES {
            return Err(BridgeError::SignerOriginUnavailable);
        }
        hash.update(&buffer[..n]);
    }
    if seen != metadata.len() {
        return Err(BridgeError::SignerOriginUnavailable);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caller_path_and_symlink_cannot_establish_installed_provider() {
        assert!(open_root_controlled(Path::new("relative/provider"), false).is_err());
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("provider")).unwrap();
        assert!(open_root_controlled(&dir.path().join("provider"), false).is_err());
    }
    #[test]
    fn provider_descriptor_is_only_evidence_and_requires_exact_bounded_identity() {
        let mut pin = SignerProviderInstallRequest {
            schema_version: 1,
            executable_path: "/usr/lib/wholepact/signer".into(),
            executable_sha256: "11".repeat(32),
            executable_device: 1,
            executable_inode: 1,
            native_enrollment_reference: "22".repeat(32),
        };
        validate_pin(&pin).unwrap();
        pin.executable_sha256 = "unverified".into();
        assert!(validate_pin(&pin).is_err());
    }
}
