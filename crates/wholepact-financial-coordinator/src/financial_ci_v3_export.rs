//! Private ordinary-data handoff for the explicitly separate external pre-V3
//! Witness qualification profile. This is not an observer record or approval.
use std::{fs::{self, File, OpenOptions}, io::Write, os::{fd::AsRawFd, unix::fs::{MetadataExt, OpenOptionsExt}}};
use wholepact_financial_coordinator_origin::{SignerContinueRoleV1, SignerV3AdmitPresentationV1};

pub(crate) fn export_v3_admission(p: &SignerV3AdmitPresentationV1) -> std::io::Result<()> {
    p.validate()?;
    let (owner, name, temporary) = match p.actor.signer_role {
        SignerContinueRoleV1::Signer1 => ("Signer1", "v3-admission-owner1.json", ".v3-admission-owner1.pending"),
        SignerContinueRoleV1::Signer2 => ("Signer2", "v3-admission-owner2.json", ".v3-admission-owner2.pending"),
    };
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version":1,"profile":"external-pre-v3-witness-v1","owner":owner,
        "source_identity_digest":p.facts.read.source_identity_digest,
        "owner_service_digest":p.facts.read.owner_service_digest,
        "admission_request_digest":p.facts.read.admission_request_digest,
        "request_json":p.facts.request_json,
    })).map_err(|_| error())?;
    if bytes.len() > 65536 || p.facts.request_json.len() > 16384 { return Err(error()); }
    let path = "/ci-financial-control";
    let before = fs::symlink_metadata(path)?;
    // /proc/self's kernel-owned process-directory UID is the running process
    // owner. No environment, supplied UID, password or artifact value is read.
    let uid = fs::metadata("/proc/self")?.uid();
    if !before.is_dir() || before.mode() & 0o777 != 0o700 || before.uid() != uid { return Err(error()); }
    let directory = File::open(path)?;
    let pinned = directory.metadata()?;
    if pinned.dev() != before.dev() || pinned.ino() != before.ino() || !pinned.is_dir()
        || pinned.uid() != uid || pinned.mode() & 0o777 != 0o700 { return Err(error()); }
    // Resolve all names through the retained directory descriptor, not a
    // replaceable mount path. create_new atomically rejects files and symlinks.
    let base = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let pending = format!("{base}/{temporary}");
    let destination = format!("{base}/{name}");
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&pending)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1 { return Err(error()); }
    file.write_all(&bytes)?;
    file.sync_all()?;
    // A hard-link publication is atomic and refuses an existing destination;
    // the reader never sees a partially written JSON selector. No overwrite.
    fs::hard_link(&pending, &destination)?;
    directory.sync_all()?;
    fs::remove_file(&pending)?;
    directory.sync_all()?;
    Ok(())
}
fn error() -> std::io::Error { std::io::Error::new(std::io::ErrorKind::PermissionDenied,"private V3 selector export rejected") }
