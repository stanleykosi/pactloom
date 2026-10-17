//! Test-process-only TLS material. The parent owns the entire temporary subtree
//! through child kill/reap; no system trust, adapter or production gate changes.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

const DIRECTORY: &str = "synthetic-provider-tls-v1";

pub(super) struct ChildTlsMaterialV1 {
    directory: PathBuf,
}
impl ChildTlsMaterialV1 {
    /// Caller is the same parent that has just created its fresh private
    /// TempDir. It retains that TempDir through kill/reap even on failure.
    pub(super) fn prepare(parent: &Path) -> io::Result<Self> {
        require_private_directory(parent)?;
        let directory = parent.join(DIRECTORY);
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let material = Self { directory };
        material.run(&[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=wholepact-synthetic-public-block-root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
        ])?;
        material.run(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-sha256",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
            "server.key",
            "-out",
            "server.csr",
        ])?;
        fs::write(material.directory.join("server.ext"), b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")?;
        material.run(&[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-sha256",
            "-extfile",
            "server.ext",
            "-outform",
            "DER",
            "-out",
            "server.der",
        ])?;
        material.run(&[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            "server.key",
            "-outform",
            "DER",
            "-out",
            "server.pk8",
        ])?;
        for entry in fs::read_dir(&material.directory)? {
            let path = entry?.path();
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err(io::Error::other("unexpected synthetic TLS entry"));
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(material)
    }

    /// This changes only the not-yet-spawned test Command. The caller's process
    /// environment, system root store and application validation stay unchanged.
    pub(super) fn configure_child(&self, command: &mut Command) {
        command.env("SSL_CERT_FILE", self.directory.join("ca.pem"));
        command.env_remove("SSL_CERT_DIR");
        // This finite loopback fixture qualifies the actual Direct route only.
        // Never inherit an external proxy into this isolated child process.
        for name in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ] {
            command.env_remove(name);
        }
    }

    fn run(&self, arguments: &[&str]) -> io::Result<()> {
        let mut child = Command::new("openssl")
            .current_dir(&self.directory)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
            if let Some(status) = status {
                return if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other("synthetic TLS material generation failed"))
                };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "synthetic TLS generation deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Reads only the fixed test subtree selected by the owning parent. This cannot
/// be linked into ordinary runtime because its ancestors are all cfg(test).
pub(super) fn child_server_config() -> io::Result<rustls::ServerConfig> {
    let root = PathBuf::from(
        std::env::var_os("TMPDIR")
            .ok_or_else(|| io::Error::other("missing synthetic parent root"))?,
    );
    require_private_directory(&root)?;
    let directory = root.join(DIRECTORY);
    require_private_directory(&directory)?;
    if std::env::var_os("SSL_CERT_FILE").as_deref() != Some(directory.join("ca.pem").as_os_str())
        || std::env::var_os("SSL_CERT_DIR").is_some()
    {
        return Err(io::Error::other("isolated synthetic TLS root mismatch"));
    }
    let certificate = CertificateDer::from(read_private(&directory.join("server.der"))?);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(read_private(
        &directory.join("server.pk8"),
    )?));
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| io::Error::other("synthetic TLS protocol configuration failed"))?
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .map_err(|_| io::Error::other("synthetic TLS identity validation failed"))
}
fn require_private_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::other("synthetic TLS owner directory mismatch"));
    }
    Ok(())
}
fn read_private(path: &Path) -> io::Result<Vec<u8>> {
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > 16 * 1024
    {
        return Err(io::Error::other("synthetic TLS private file mismatch"));
    }
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(io::Error::other("synthetic TLS private file changed"));
    }
    Ok(bytes)
}
