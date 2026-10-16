//! Immutable nonfinancial disclosure receipts. Opening these files authenticates
//! history only; there is deliberately no receipt -> live owner constructor.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use wholepact_signer_origin::manual_roster_construction_v2::ManualRosterContributionRetentionEvidenceV2;
pub(crate) const MAX_RECEIPTS: usize = 16;
const PREFIX: &str = "born-roster-contribution-retained-v2-";
const MAX_RECEIPT_BYTES: usize = 512 * 1024;
pub(crate) fn parse_name(name: &str) -> Option<&str> {
    let digest = name.strip_prefix(PREFIX)?.strip_suffix(".wp")?;
    is_hash(digest).then_some(digest)
}
pub(crate) fn check_names(names: &BTreeSet<String>) -> Result<()> {
    let count = names.iter().filter(|n| parse_name(n).is_some()).count();
    if count > MAX_RECEIPTS
        || count > 0
            && [INTENT, ROSTER_ACQUIRE, ROSTER_COMMIT, JOURNAL]
                .iter()
                .any(|n| !names.contains(*n))
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
fn domain(record: &BornManualRosterEnrollmentRecordV2, name: &str) -> Result<Vec<u8>> {
    let mut d = b"wholepact:born-roster-contribution-retention-file:v2\0".to_vec();
    d.extend(record.reference()?.as_bytes());
    d.push(0);
    d.extend(name.as_bytes());
    Ok(d)
}
fn require_record(
    record: &BornManualRosterEnrollmentRecordV2,
    intent: &str,
    evidence: &ManualRosterContributionRetentionEvidenceV2,
) -> Result<()> {
    evidence.validate().map_err(|_| Error::InvalidData)?;
    let selection = &evidence.request.selection;
    let inventory = &selection.scope.selection.inventory;
    if inventory.enrollment != record.account_record.terms
        || inventory.enrollment_ref != record.account_record.reference()?
        || selection.scope.provenance.signer_roster_record_digest != record.reference()?
        || selection.scope.provenance.roster != record.roster
        || selection.scope.provenance.witness_roster_extension_digest
            != record
                .extension()?
                .digest()
                .map_err(|_| Error::InvalidData)?
        || evidence.retained_signer_intent_digest != intent
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
pub(crate) fn validate_files(
    record: &BornManualRosterEnrollmentRecordV2,
    intent: &str,
    key: &[u8; 32],
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    check_names(&files.keys().cloned().collect())?;
    for (name, bytes) in files.iter().filter(|(n, _)| parse_name(n).is_some()) {
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(Error::Unavailable);
        }
        let plaintext = vault::decrypt(key, &domain(record, name)?, bytes)?;
        let evidence: ManualRosterContributionRetentionEvidenceV2 =
            serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidData)?;
        require_record(record, intent, &evidence)?;
        if parse_name(name)
            != Some(
                evidence
                    .request
                    .digest()
                    .map_err(|_| Error::InvalidData)?
                    .as_str(),
            )
        {
            return Err(Error::Authentication);
        }
    }
    Ok(())
}
/// Called only AFTER the actual native publication admission. Existing exact
/// receipts deny reissuance, including after uncertain delivery or restart.
/// The signer holds its exclusive original directory lock throughout this call.
pub(crate) fn retain_once(
    retained: &RetainedBornManualRosterEnrollmentV2,
    evidence: &ManualRosterContributionRetentionEvidenceV2,
) -> Result<String> {
    require_record(&retained.record, &retained.intent_digest, evidence)?;
    let directory = &retained.account.directory;
    let name = format!(
        "{PREFIX}{}.wp",
        evidence.request.digest().map_err(|_| Error::InvalidData)?
    );
    roster_inventory(directory)?;
    if directory.exists(&name)? {
        return Err(Error::RecoveryRequired);
    }
    let mut count = 0;
    for entry in std::fs::read_dir(directory.root())? {
        let filename = entry?
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        count += usize::from(parse_name(&filename).is_some());
    }
    if count >= MAX_RECEIPTS {
        return Err(Error::Unavailable);
    }
    let plain = Zeroizing::new(serde_json::to_vec(evidence).map_err(|_| Error::InvalidData)?);
    if plain.len() > MAX_RECEIPT_BYTES - 1024 {
        return Err(Error::Unavailable);
    }
    let encrypted = vault::encrypt(
        &retained.account.encryption_key,
        &domain(&retained.record, &name)?,
        &plain,
    )?;
    write_receipt_create_once(directory, &name, &encrypted)?;
    let actual = directory.read(&name, MAX_RECEIPT_BYTES)?;
    if actual != encrypted {
        return Err(Error::RecoveryRequired);
    }
    Ok(hex::encode(Sha256::digest(&actual)))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_names_are_exact_and_need_complete_source_inventory() {
        let n = format!("{PREFIX}{}.wp", "ab".repeat(32));
        assert_eq!(parse_name(&n), Some("ab".repeat(32).as_str()));
        assert!(parse_name(&format!("{PREFIX}{}.wp", "AB".repeat(32))).is_none());
        assert!(parse_name(&format!("{n}.tmp")).is_none());
        let mut names = BTreeSet::from([n]);
        assert!(check_names(&names).is_err());
        names.extend([INTENT, ROSTER_ACQUIRE, ROSTER_COMMIT, JOURNAL].map(str::to_owned));
        check_names(&names).unwrap();
    }
}

/// Authentication of immutable historical evidence only. Full-proposal native
/// review separately requires an actual newly continued original source.
pub(crate) fn read_exact(
    retained: &RetainedBornManualRosterEnrollmentV2,
    request:&wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
    evidence_digest: &str,
) -> Result<ManualRosterContributionRetentionEvidenceV2> {
    retained.check()?;
    let name = format!(
        "{PREFIX}{}.wp",
        request.digest().map_err(|_| Error::InvalidData)?
    );
    let bytes = retained.account.directory.read(&name, MAX_RECEIPT_BYTES)?;
    let plain = vault::decrypt(
        &retained.account.encryption_key,
        &domain(&retained.record, &name)?,
        &bytes,
    )?;
    let evidence: ManualRosterContributionRetentionEvidenceV2 =
        serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
    require_record(&retained.record, &retained.intent_digest, &evidence)?;
    if &evidence.request != request
        || evidence.digest().map_err(|_| Error::InvalidData)? != evidence_digest
    {
        return Err(Error::Authentication);
    }
    Ok(evidence)
}

fn write_receipt_create_once(directory: &PrivateDirectory, name: &str, bytes: &[u8]) -> Result<()> {
    use std::{
        ffi::CString,
        fs::{File, OpenOptions},
        io::Write,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::OpenOptionsExt,
        },
    };
    if parse_name(name).is_none() || bytes.len() > MAX_RECEIPT_BYTES {
        return Err(Error::InvalidData);
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.root())?;
    let name = CString::new(name).map_err(|_| Error::InvalidData)?;
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    // No cleanup on error: a partial durable name remains a consumed/unknown
    // attempt, and reopening cannot mint a replacement owner from it.
    file.write_all(bytes)?;
    file.sync_all()?;
    root.sync_all()?;
    Ok(())
}
#[cfg(test)]
mod durable_replay_tests {
    use super::*;
    #[test]
    fn exact_receipt_replay_and_uncertain_partial_name_never_overwrite_or_reissue() {
        let temp = tempfile::tempdir().unwrap();
        let directory =
            PrivateDirectory::create(&temp.path().join("synthetic-private-receipts")).unwrap();
        let name = format!("{PREFIX}{}.wp", "ab".repeat(32));
        write_receipt_create_once(&directory, &name, b"synthetic retained ciphertext").unwrap();
        assert!(write_receipt_create_once(&directory, &name, b"same or changed retry").is_err());
        assert_eq!(
            directory.read(&name, 256).unwrap(),
            b"synthetic retained ciphertext"
        );
        let partial = format!("{PREFIX}{}.wp", "cd".repeat(32));
        write_receipt_create_once(&directory, &partial, b"").unwrap();
        assert!(write_receipt_create_once(&directory, &partial, b"replacement").is_err());
        assert!(directory.read(&partial, 256).unwrap().is_empty());
    }
}

/// Authenticate the exact encrypted original receipt, including its ciphertext
/// digest, under the actual retained account. This remains history, not consent.
pub(crate) fn read_exact_with_ciphertext_digest(
    retained: &RetainedBornManualRosterEnrollmentV2,
    request: &wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
    evidence_digest: &str,
    ciphertext_digest: &str,
) -> Result<ManualRosterContributionRetentionEvidenceV2> {
    let evidence = read_exact(retained, request, evidence_digest)?;
    let name = format!("{PREFIX}{}.wp", request.digest().map_err(|_| Error::InvalidData)?);
    let bytes = retained.account.directory.read(&name, MAX_RECEIPT_BYTES)?;
    if hex::encode(Sha256::digest(&bytes)) != ciphertext_digest {
        return Err(Error::Authentication);
    }
    // Verify the same read again rather than trusting a pathname-only digest.
    let plain = vault::decrypt(&retained.account.encryption_key, &domain(&retained.record, &name)?, &bytes)?;
    let actual: ManualRosterContributionRetentionEvidenceV2 = serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
    require_record(&retained.record, &retained.intent_digest, &actual)?;
    if actual != evidence { return Err(Error::Authentication); }
    retained.check()?;
    Ok(evidence)
}
