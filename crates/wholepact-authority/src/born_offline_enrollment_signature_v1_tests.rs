//! Fresh temporary P-256 possession evidence only; no persistent credential,
//! native decision, namespace enrollment or financial authority is established.
use super::*;
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Command,
};
fn openssl(root: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "installed OpenSSL synthetic fixture generation failed"
    );
}
fn fixture() -> (
    tempfile::TempDir,
    BornOfflineEnrollmentOwnerSignatureV1,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for p in [
        "key.pem",
        "certificate.pem",
        "certificate.der",
        "message.bin",
        "signature.bin",
    ] {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join(p))
            .unwrap();
    }
    openssl(
        dir.path(),
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "key.pem",
            "-out",
            "certificate.pem",
            "-subj",
            "/CN=wholepact-born-offline-synthetic.invalid",
            "-days",
            "1",
        ],
    );
    openssl(
        dir.path(),
        &[
            "x509",
            "-in",
            "certificate.pem",
            "-outform",
            "DER",
            "-out",
            "certificate.der",
        ],
    );
    let cert = fs::read(dir.path().join("certificate.der")).unwrap();
    let pin = crate::transport::certificate_digest(&CertificateDer::from(cert.as_slice()));
    let (birth, _, _, ledger) = crate::manual_enrollment::tests::bootstrap_events();
    let mut enrollment =
        crate::born_offline_enrollment_v1::tests::record(&ledger, &birth).enrollment;
    // This test authenticates this exact independent key pin only; it deliberately
    // does not claim the modified descriptor matches the real original birth.
    enrollment.owner_certificate_digest = pin.clone();
    fs::write(
        dir.path().join("message.bin"),
        born_offline_enrollment_v1_owner_signing_bytes(&enrollment).unwrap(),
    )
    .unwrap();
    openssl(
        dir.path(),
        &[
            "dgst",
            "-sha256",
            "-sign",
            "key.pem",
            "-out",
            "signature.bin",
            "message.bin",
        ],
    );
    let signature = fs::read(dir.path().join("signature.bin")).unwrap();
    (
        dir,
        BornOfflineEnrollmentOwnerSignatureV1 {
            version: 1,
            enrollment,
            scheme: "ecdsa-p256-sha256-asn1-v1".into(),
            owner_certificate_der: cert,
            signature,
        },
        pin,
    )
}
#[test]
fn exact_owner_signature_is_domain_bound_but_never_native_authority() {
    let (dir, envelope, pin) = fixture();
    let verified = verify_born_offline_enrollment_v1_owner_signature(&envelope, &pin).unwrap();
    assert_eq!(verified.certificate_digest(), pin);
    assert!(verified.enrollment() == &envelope.enrollment);
    assert!(verify_born_offline_enrollment_v1_owner_signature(&envelope, &"0".repeat(64)).is_err());
    let mut changed = envelope.clone();
    changed.enrollment.assurance =
        crate::born_offline_enrollment_v1::BornOfflineAssuranceV1::Independent;
    assert!(verify_born_offline_enrollment_v1_owner_signature(&changed, &pin).is_err());
    fs::write(
        dir.path().join("message.bin"),
        b"wholepact:manual-enrollment-extension-owner-approval:v1\0unrelated",
    )
    .unwrap();
    openssl(
        dir.path(),
        &[
            "dgst",
            "-sha256",
            "-sign",
            "key.pem",
            "-out",
            "signature.bin",
            "message.bin",
        ],
    );
    let mut wrong_domain = envelope;
    wrong_domain.signature = fs::read(dir.path().join("signature.bin")).unwrap();
    assert!(verify_born_offline_enrollment_v1_owner_signature(&wrong_domain, &pin).is_err());
}
