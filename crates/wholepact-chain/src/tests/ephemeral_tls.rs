//! Fresh test-only TLS identity. No committed key, installation, or system trust change.
use std::process::{Command, Stdio};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

pub(super) fn identity() -> (
    Vec<u8>,
    CertificateDer<'static>,
    PrivatePkcs8KeyDer<'static>,
) {
    let temporary = tempfile::tempdir().expect("private test fixture directory");
    let run = |args: &[&str]| {
        assert!(
            Command::new("openssl")
                .current_dir(temporary.path())
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("installed OpenSSL is required for ephemeral TLS tests")
                .success(),
            "ephemeral TLS fixture generation failed"
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
        "/CN=wholepact-proxy-test.invalid",
        "-addext",
        "subjectAltName=DNS:wholepact-proxy-test.invalid",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "keyUsage=critical,digitalSignature",
        "-addext",
        "extendedKeyUsage=serverAuth",
        "-keyout",
        "private.pem",
        "-out",
        "certificate.pem",
    ]);
    run(&[
        "x509",
        "-in",
        "certificate.pem",
        "-outform",
        "DER",
        "-out",
        "certificate.der",
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
    let certificate_pem = std::fs::read(temporary.path().join("certificate.pem")).unwrap();
    let certificate =
        CertificateDer::from(std::fs::read(temporary.path().join("certificate.der")).unwrap());
    let key =
        PrivatePkcs8KeyDer::from(std::fs::read(temporary.path().join("private.pk8")).unwrap());
    // Only the server's in-memory key remains. Never retain generated private files.
    temporary
        .close()
        .expect("remove ephemeral TLS fixture files");
    (certificate_pem, certificate, key)
}
