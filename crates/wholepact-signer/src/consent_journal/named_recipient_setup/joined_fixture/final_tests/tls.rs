//! Fresh temporary TLS identities, removed with their private TempDir. No fixture
//! key is committed and no credential is installed or contacted off-device.
use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
fn openssl(root: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(out.status.success(), "ephemeral synthetic TLS setup failed");
}
fn credential(root: &Path, name: &str, key: bool) -> PathBuf {
    root.join(if key {
        format!("{name}.key.der")
    } else {
        format!("{name}.der")
    })
}

pub(super) struct Tls {
    dir: tempfile::TempDir,
}
impl Tls {
    pub(super) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tls");
        let root = root.as_path();
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        openssl(
            root,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "1",
                "-subj",
                "/CN=Wholepact fixed never-funded fixture CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        for (name, eku) in [
            ("server", "serverAuth"),
            ("writer", "clientAuth"),
            ("owner", "clientAuth"),
        ] {
            openssl(
                root,
                &[
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    &format!("{name}.key"),
                    "-out",
                    &format!("{name}.csr"),
                    "-subj",
                    &format!("/CN=synthetic-{name}"),
                ],
            );
            fs::write(root.join(format!("{name}.ext")),format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={eku}\nsubjectAltName=DNS:localhost\n")).unwrap();
            openssl(
                root,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &format!("{name}.csr"),
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-out",
                    &format!("{name}.pem"),
                    "-days",
                    "1",
                    "-extfile",
                    &format!("{name}.ext"),
                ],
            );
            openssl(
                root,
                &[
                    "x509",
                    "-in",
                    &format!("{name}.pem"),
                    "-outform",
                    "DER",
                    "-out",
                    &format!("{name}.der"),
                ],
            );
            openssl(
                root,
                &[
                    "pkcs8",
                    "-topk8",
                    "-nocrypt",
                    "-in",
                    &format!("{name}.key"),
                    "-outform",
                    "DER",
                    "-out",
                    &format!("{name}.key.der"),
                ],
            );
        }
        openssl(
            root,
            &["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"],
        );
        for entry in fs::read_dir(root).unwrap() {
            fs::set_permissions(entry.unwrap().path(), fs::Permissions::from_mode(0o600)).unwrap();
        }

        Self { dir }
    }
    fn root(&self) -> PathBuf {
        self.dir.path().join("tls")
    }
    pub(super) fn cert(&self, name: &str) -> CertificateDer<'static> {
        CertificateDer::from(fs::read(credential(&self.root(), name, false)).unwrap())
    }
    pub(super) fn key(&self, name: &str) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fs::read(credential(&self.root(), name, true)).unwrap(),
        ))
    }
    pub(super) fn pin(&self, name: &str) -> String {
        wholepact_authority::transport::certificate_digest(&self.cert(name))
    }
}
