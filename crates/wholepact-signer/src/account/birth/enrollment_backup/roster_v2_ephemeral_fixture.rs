//! Fresh, never-installed test signing identity. No static private bytes are retained.
use rustls::{pki_types::PrivatePkcs8KeyDer, sign::SigningKey};
use std::{
    process::{Command, Stdio},
    sync::Arc,
};

pub(super) struct Owner {
    pub(super) certificate_der: Vec<u8>,
    key: Arc<dyn SigningKey>,
}
impl Owner {
    pub(super) fn new() -> Self {
        let temporary = tempfile::tempdir().expect("private synthetic owner directory");
        let run = |args: &[&str]| {
            assert!(
                Command::new("openssl")
                    .current_dir(temporary.path())
                    .args(args)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("installed OpenSSL is required for ephemeral roster tests")
                    .success(),
                "ephemeral roster fixture generation failed"
            );
        };
        run(&[
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
            "/CN=wholepact-roster-archive-synthetic.invalid",
            "-keyout",
            "private.pem",
            "-out",
            "certificate.der",
            "-outform",
            "DER",
        ]);
        run(&[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            "private.pem",
            "-outform",
            "DER",
            "-out",
            "private.pk8",
        ]);
        let certificate_der = std::fs::read(temporary.path().join("certificate.der")).unwrap();
        let key =
            PrivatePkcs8KeyDer::from(std::fs::read(temporary.path().join("private.pk8")).unwrap());
        let key = rustls::crypto::ring::sign::any_supported_type(&key.into()).unwrap();
        temporary
            .close()
            .expect("remove ephemeral roster fixture files");
        Self {
            certificate_der,
            key,
        }
    }
    pub(super) fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key
            .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap()
            .sign(message)
            .unwrap()
    }
}
