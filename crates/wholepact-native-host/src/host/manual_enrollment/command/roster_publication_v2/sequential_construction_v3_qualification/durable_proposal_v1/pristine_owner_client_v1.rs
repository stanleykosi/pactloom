//! One owner-mTLS attempt for the preserved synthetic W-only fixture. The CI
//! supervisor starts this ignored selector only after genuine native Arm. This
//! client cannot create Arm/FinalAdmit or claim a Signer-retained intent. It never
//! opens the protected namespace; the independent history audit runs after all
//! product custody/processes have drained. No retry, new fixture or new cutoff.
use std::{fs::File, io::Read, os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf}, time::{Duration, Instant}};
use serde::Deserialize;
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use wholepact_authority::{AuthorityError, AuthorityHead, OwnerControl, OwnerControlRequest,
    transport::{AuthorityClient, ClientTls}};

const ROOT: &str = "/ci-fixture";
const MAX_HANDOFF: usize = 2 * 1024 * 1024;
fn refused() -> std::io::Error { std::io::Error::other("bounded synthetic owner client refused") }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerHandoff {
    version: u16, root_path: PathBuf, root_device: u64, root_inode: u64,
    original_monotonic_cutoff_ns: u64, fixture: Handoff,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    version: u16, installation: Vec<u8>, home_path: PathBuf,
    form: Form, owner_client: OwnerClient, accounts: Vec<AccountBaseline>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Form {
    endpoint: String, server_name: String, witness_id: String,
    pinned_server_certificate_digest: String, network_profile_id: String,
    expected_account_id: String, owner_certificate_der_hex: String,
    storage_key_file: String, server_certificate_der: String,
    server_private_key_pkcs8_der: String, trusted_client_root_der: String, request_json: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerClient { certificate_der: String, private_key_pkcs8_der: String, trusted_server_root_der: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountBaseline { account_id: String, head: AuthorityHead, original_signed_birth: String, original_source_commitment: String }

type FileStamp = (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64);
fn file_stamp(m: &std::fs::Metadata) -> FileStamp {
    (m.dev(), m.ino(), m.uid(), m.mode(), m.nlink(), m.len(),
        m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec())
}
struct HeldPath { file: File, path: PathBuf, directory: bool, original: FileStamp }
impl HeldPath {
    fn open(path: &Path, directory: bool, maximum: u64) -> std::io::Result<Self> {
        if !path.is_absolute() || std::fs::canonicalize(path)? != path { return Err(refused()); }
        let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
            | if directory { libc::O_DIRECTORY } else { 0 };
        let file = std::fs::OpenOptions::new().read(true).custom_flags(flags).open(path)?;
        let m = file.metadata()?;
        if m.uid() != 10001 || (directory && (!m.is_dir() || m.mode() & 0o7777 != 0o700))
            || (!directory && (!m.is_file() || m.mode() & 0o7777 != 0o600 || m.nlink() != 1 || m.len() > maximum)) {
            return Err(refused());
        }
        let original = file_stamp(&m);
        let held = Self { file, path: path.to_owned(), directory, original };
        held.check()?;
        Ok(held)
    }
    fn check(&self) -> std::io::Result<()> {
        let held = self.file.metadata()?;
        let path = std::fs::symlink_metadata(&self.path)?;
        if std::fs::canonicalize(&self.path)? != self.path
            || (held.dev(), held.ino(), held.uid(), held.mode()) != (path.dev(), path.ino(), path.uid(), path.mode())
            || held.uid() != 10001 || held.mode() & 0o7777 != if self.directory { 0o700 } else { 0o600 }
            || (self.directory && !path.is_dir())
            || (!self.directory && (!path.is_file() || path.nlink() != 1
                || file_stamp(&held) != self.original || file_stamp(&path) != self.original)) {
            return Err(refused());
        }
        Ok(())
    }
    fn read(&mut self, maximum: usize) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
        self.check()?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        self.file.by_ref().take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        self.check()?;
        if bytes.is_empty() || bytes.len() > maximum { return Err(refused()); }
        Ok(bytes)
    }
}

fn same_cutoff(raw: &str, original: u64) -> bool {
    raw.parse::<u64>().is_ok_and(|value| value == original && value.to_string() == raw)
}
fn validate_shape(h: &RunnerHandoff) -> std::io::Result<OwnerControlRequest> {
    let f = &h.fixture;
    if h.version != 1 || f.version != 1 || f.installation.is_empty() || f.installation.len() > 16384
        || h.root_path.parent() != Some(Path::new(ROOT)) || f.home_path.parent() != Some(h.root_path.as_path())
        || f.accounts.len() != 3 || f.form.server_name != "localhost" { return Err(refused()); }
    for (actual, name) in [(&f.form.storage_key_file, "synthetic-namespace.key"),
        (&f.form.server_certificate_der, "server.der"), (&f.form.server_private_key_pkcs8_der, "server.pk8"),
        (&f.form.trusted_client_root_der, "ca.der"), (&f.owner_client.certificate_der, "owner.der"),
        (&f.owner_client.private_key_pkcs8_der, "owner.pk8"), (&f.owner_client.trusted_server_root_der, "ca.der")] {
        if actual.len() > 4096 || Path::new(actual) != f.home_path.join(name) { return Err(refused()); }
    }
    let request: OwnerControlRequest = serde_json::from_str(&f.form.request_json).map_err(|_| refused())?;
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else { return Err(refused()); };
    let d = &record.scope.witness;
    record.validate_request(&request, d).map_err(|_| refused())?;
    let endpoint: std::net::SocketAddr = f.form.endpoint.parse().map_err(|_| refused())?;
    let mut accounts = std::collections::BTreeSet::new();
    if !endpoint.ip().is_loopback() || endpoint.port() == 0 || endpoint.to_string() != f.form.endpoint
        || d.endpoint != f.form.endpoint || d.server_name != f.form.server_name
        || d.witness_id != f.form.witness_id || d.account_id != f.form.expected_account_id
        || d.network_profile_id != f.form.network_profile_id
        || d.pinned_server_certificate_digest != f.form.pinned_server_certificate_digest
        || request.expected_head.sequence != 4 || request.account_id != f.form.expected_account_id
        || !f.accounts.iter().all(|a| accounts.insert(&a.account_id) && a.original_signed_birth.len() == 64 && a.original_source_commitment.len() == 64)
        || !f.accounts.iter().any(|a| a.account_id == request.account_id && a.head == request.expected_head) {
        return Err(refused());
    }
    Ok(request)
}

fn one_original_attempt() -> std::io::Result<()> {
    // Fixed container UID, fixed handoff, no raw socket/path/approval argument.
    if unsafe { libc::geteuid() } != 10001 { return Err(refused()); }
    let base = HeldPath::open(Path::new(ROOT), true, 0)?;
    let mut input = HeldPath::open(&Path::new(ROOT).join("handoff.json"), false, MAX_HANDOFF as u64)?;
    let bytes = input.read(MAX_HANDOFF)?;
    let h: RunnerHandoff = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let request = validate_shape(&h)?;
    let raw = std::env::var("WHOLEPACT_TEST_ONLY_PRIVATE_WORKFLOW_CUTOFF_NS").map_err(|_| refused())?;
    if !same_cutoff(&raw, h.original_monotonic_cutoff_ns) { return Err(refused()); }
    let deadline = super::private_fixed_v2::child_original_cutoff().map_err(|_| refused())?;
    if deadline.checked_duration_since(Instant::now()).is_none_or(|d| d > Duration::from_secs(900)) { return Err(refused()); }
    let root = HeldPath::open(&h.root_path, true, 0)?;
    let meta = root.file.metadata()?;
    if (meta.dev(), meta.ino()) != (h.root_device, h.root_inode) { return Err(refused()); }
    let home = HeldPath::open(&h.fixture.home_path, true, 0)?;
    let mut certificate = HeldPath::open(Path::new(&h.fixture.owner_client.certificate_der), false, 16384)?;
    let mut private_key = HeldPath::open(Path::new(&h.fixture.owner_client.private_key_pkcs8_der), false, 16384)?;
    let mut ca = HeldPath::open(Path::new(&h.fixture.owner_client.trusted_server_root_der), false, 16384)?;
    let certificate_bytes = certificate.read(16384)?;
    if hex::encode(&certificate_bytes[..]) != h.fixture.form.owner_certificate_der_hex { return Err(refused()); }
    let key_bytes = private_key.read(16384)?;
    let ca_bytes = ca.read(16384)?;
    let form = &h.fixture.form;
    let tls = ClientTls::new(form.server_name.clone(), form.pinned_server_certificate_digest.clone(),
        vec![CertificateDer::from(ca_bytes.to_vec())], vec![CertificateDer::from(certificate_bytes.to_vec())],
        PrivatePkcs8KeyDer::from(key_bytes.to_vec()).into()).map_err(|_| refused())?;
    drop(key_bytes);
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else { return Err(refused()); };
    let client = AuthorityClient::new(form.endpoint.parse().map_err(|_| refused())?, tls,
        form.witness_id.clone(), form.expected_account_id.clone(), form.network_profile_id.clone(),
        record.scope.witness.policy_digest.clone()).map_err(|_| refused())?;
    let mut current = || -> wholepact_authority::Result<()> {
        if Instant::now() >= deadline { return Err(AuthorityError::Expired); }
        for held in [&base, &input, &root, &home, &certificate, &private_key, &ca] {
            held.check().map_err(|_| AuthorityError::Permission)?;
        }
        if Instant::now() >= deadline { return Err(AuthorityError::Expired); }
        Ok(())
    };
    // Exactly one attempt. Even NotListening is terminal, never discovery/retry.
    let ready = match client.prepare_durable_delivery_admission_v3(&request, deadline, &mut current) {
        Ok(ready) => ready,
        Err(error) => {
            eprintln!("CI_UI_OWNER_CLIENT_FAILURE stage=Prepare cause={error:?}");
            return Err(refused());
        }
    };
    let (result, observation) = ready.send_pristine_fixture_exact_for_qualification_v1(&request, deadline, &mut current);
    let result = match result {
        Ok(result) => result,
        Err(_) => {
            if let Some(observation) = observation {
                // Both Debug values are closed enums; no paths, errors or keys.
                eprintln!("CI_UI_OWNER_CLIENT_FAILURE stage={:?} cause={:?}", observation.stage, observation.cause);
            }
            return Err(refused());
        }
    };
    current().map_err(|_| refused())?;
    let output = serde_json::json!({"version": 1, "scope": "synthetic-witness-one-append-only",
        "outcome": "Committed", "preparation_nonce": result.preparation_nonce,
        "request_commitment": result.request_commitment, "operation_id": result.operation_id,
        "account_id": request.account_id, "expected_head": result.expected_head,
        "committed_head": result.controlled.head,
        "original_monotonic_cutoff_ns": h.original_monotonic_cutoff_ns});
    let encoded = serde_json::to_string(&output).map_err(|_| refused())?;
    if encoded.len() > 4096 { return Err(refused()); }
    println!("CI_UI_OWNER_CLIENT {encoded}");
    Ok(())
}

#[test]
#[ignore = "Approved disposable CI only, after genuine native Arm; one owner-mTLS attempt; W-only synthetic proof"]
fn coordinator_pristine_owner_same_stream_one_append() {
    assert!(one_original_attempt().is_ok(), "bounded synthetic same-stream attempt failed; never retry");
}

#[test]
fn pristine_owner_cutoff_never_replaces_original() {
    assert!(same_cutoff("123", 123));
    for raw in ["", "0123", "+123", "123 ", "122", "124", "18446744073709551616"] {
        assert!(!same_cutoff(raw, 123));
    }
}
#[test]
fn pristine_owner_input_is_closed() {
    assert!(serde_json::from_str::<OwnerClient>(r#"{"certificate_der":"a","private_key_pkcs8_der":"b","trusted_server_root_der":"c","approve":true}"#).is_err());
    assert!(serde_json::from_str::<OwnerClient>(r#"{"certificate_der":"a","certificate_der":"b","private_key_pkcs8_der":"b","trusted_server_root_der":"c"}"#).is_err());
}
