//! Bounded public evidence only for the single synthetic full-payment fixture.
//! Never serializes the upstream report, private artifacts, paths or transcript.
//! Reading this record cannot reconstruct any authority-bearing owner.
use super::full_payment_joined_v1::FullSyntheticPaymentReceiptV1;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::Path,
};
use wholepact_chain::{SubmissionAttemptOutcome, SubmissionState};

const FILE_NAME: &[u8] = b"synthetic-public-outcome-v1.json\0";
const MAX_BYTES: u64 = 4096;
pub(super) const PUBLIC_MARKER: &str = "WHOLEPACT_SYNTHETIC_PUBLIC_OUTCOME_V1=";

#[derive(Clone, Copy, Serialize, Deserialize)]
enum EvidenceKind {
    #[serde(rename = "synthetic_full_payment_v1")]
    SyntheticFullPayment,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
enum Network {
    #[serde(rename = "testnet")]
    Testnet,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
enum DispatchOutcome {
    #[serde(rename = "synthetic_acknowledged")]
    SyntheticAcknowledged,
}

/// Explicit allowlist. No optional extension map or arbitrary upstream strings.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicOutcomeV1 {
    schema: u16,
    evidence_kind: EvidenceKind,
    transaction_id: String,
    transaction_bytes_sha256: String,
    network: Network,
    consensus_branch_id: u32,
    expiry_height: u32,
    submission_attempt: u32,
    submission_outcome: DispatchOutcome,
    recipient_decrypted_zatoshis: u64,
    recipient_owned_note_count: u32,
    fabricated_inclusion_height: u32,
    fabricated_tip_height: u32,
    required_confirmations: u32,
    public_network_settlement_verified: bool,
    public_network_inclusion_verified: bool,
    independent_consensus_verified: bool,
    attended_native_acceptance_verified: bool,
    clears_authorization_exposure: bool,
    permits_replacement: bool,
}
fn invalid() -> io::Error {
    io::Error::other("synthetic public outcome invalid; private details withheld")
}
fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
impl PublicOutcomeV1 {
    pub(super) fn from_actual(actual: &FullSyntheticPaymentReceiptV1) -> io::Result<Self> {
        let report = &actual.exact_submission;
        let receipt = &actual.recipient;
        if report.descriptor.network != "testnet"
            || report.descriptor.transaction_id != receipt.transaction_id
            || !matches!(
                report.attempt.outcome,
                SubmissionAttemptOutcome::Acknowledged
            )
            || !matches!(
                report.historical_provider_state,
                SubmissionState::BackendAcknowledged
            )
            || receipt.evidence_kind
                != "maintained_recipient_decryption_on_fabricated_joined_fixture_blocks"
        {
            return Err(invalid());
        }
        let result = Self {
            schema: 1,
            evidence_kind: EvidenceKind::SyntheticFullPayment,
            transaction_id: report.descriptor.transaction_id.clone(),
            transaction_bytes_sha256: report.descriptor.bytes_sha256.clone(),
            network: Network::Testnet,
            consensus_branch_id: report.descriptor.consensus_branch_id,
            expiry_height: report.descriptor.expiry_height,
            submission_attempt: report.attempt.number,
            submission_outcome: DispatchOutcome::SyntheticAcknowledged,
            recipient_decrypted_zatoshis: receipt.decrypted_zatoshis,
            recipient_owned_note_count: receipt
                .owned_note_count
                .try_into()
                .map_err(|_| invalid())?,
            fabricated_inclusion_height: receipt.fabricated_inclusion_height,
            fabricated_tip_height: receipt.fabricated_tip_height,
            required_confirmations: receipt.required_confirmations,
            public_network_settlement_verified: actual.public_network_settlement_verified,
            public_network_inclusion_verified: receipt.public_network_inclusion_verified,
            independent_consensus_verified: receipt.independent_consensus_verified,
            attended_native_acceptance_verified: actual.attended_native_acceptance_verified,
            clears_authorization_exposure: report.clears_authorization_exposure,
            permits_replacement: report.permits_replacement,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> io::Result<()> {
        if self.schema != 1
            || !canonical_hash(&self.transaction_id)
            || !canonical_hash(&self.transaction_bytes_sha256)
            || self.consensus_branch_id == 0
            || self.expiry_height == 0
            || self.submission_attempt != 1
            || self.recipient_decrypted_zatoshis == 0
            || self.recipient_owned_note_count != 1
            || !(1..=32).contains(&self.required_confirmations)
            || self.fabricated_inclusion_height == 0
            || self
                .fabricated_tip_height
                .checked_sub(self.fabricated_inclusion_height)
                .and_then(|v| v.checked_add(1))
                .is_none_or(|v| v < self.required_confirmations)
            || self.public_network_settlement_verified
            || self.public_network_inclusion_verified
            || self.independent_consensus_verified
            || self.attended_native_acceptance_verified
            || self.clears_authorization_exposure
            || self.permits_replacement
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn public_json(&self) -> io::Result<String> {
        self.validate()?;
        let text = serde_json::to_string(self).map_err(|_| invalid())?;
        if text.len() as u64 > MAX_BYTES {
            return Err(invalid());
        }
        Ok(text)
    }
    /// Called only after the actual full receipt and same scenario teardown.
    /// TMPDIR is set by the owning PTY parent, not a caller output-file selector.
    pub(super) fn write_child_once(&self) -> io::Result<()> {
        let root = std::env::var_os("TMPDIR").ok_or_else(invalid)?;
        self.write_once(Path::new(&root))
    }
    fn write_once(&self, root: &Path) -> io::Result<()> {
        let text = self.public_json()?;
        let directory = private_directory(root)?;
        let mut file = relative_file(&directory, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        require_private_file(&file)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        directory.sync_all()?;
        Ok(())
    }
}
fn private_directory(root: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(invalid());
    }
    Ok(directory)
}
fn relative_file(directory: &File, flags: libc::c_int) -> io::Result<File> {
    // One fixed basename only, resolved beneath the held actual directory FD.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            FILE_NAME.as_ptr().cast(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn require_private_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_BYTES
    {
        return Err(invalid());
    }
    Ok(())
}
/// Parent calls only after exact child reap and original group absence. Failed
/// or timed-out computation never promotes even a well-formed sidecar to success.
pub(super) fn read_after_reap(root: &Path) -> io::Result<PublicOutcomeV1> {
    let directory = private_directory(root)?;
    let file = relative_file(&directory, libc::O_RDONLY)?;
    require_private_file(&file)?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid());
    }
    let result: PublicOutcomeV1 = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    result.validate()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use wholepact_chain::{SubmissionAttempt, SubmissionDescriptor, SubmissionDispatchReport};
    use wholepact_wallet::wallet::synthetic_born_payment_recipient_v1::SyntheticBornRecipientReceiptV1;
    fn actual_data() -> FullSyntheticPaymentReceiptV1 {
        // Inert public metadata only; no real receipt/authority owner is issued.
        FullSyntheticPaymentReceiptV1 {
            exact_submission: SubmissionDispatchReport {
                descriptor: SubmissionDescriptor {
                    operation_id: "never-export-operation".into(),
                    obligation_id: "never-export-obligation".into(),
                    proposal_id: "never-export-proposal".into(),
                    transaction_id: "11".repeat(32),
                    bytes_sha256: "22".repeat(32),
                    expiry_height: 4_500_100,
                    network: "testnet".into(),
                    consensus_branch_id: 0x77190ad9,
                },
                attempt: SubmissionAttempt {
                    number: 1,
                    source_id: "never-export-route".into(),
                    started_at_unix_seconds: 1,
                    outcome: SubmissionAttemptOutcome::Acknowledged,
                },
                historical_provider_state: SubmissionState::BackendAcknowledged,
                clears_authorization_exposure: false,
                permits_replacement: false,
            },
            recipient: SyntheticBornRecipientReceiptV1 {
                transaction_id: "11".repeat(32),
                recipient_address: "never-export-recipient".into(),
                decrypted_zatoshis: 100_000,
                owned_note_count: 1,
                fabricated_inclusion_height: 100,
                fabricated_tip_height: 102,
                required_confirmations: 3,
                public_network_inclusion_verified: false,
                independent_consensus_verified: false,
                evidence_kind: "maintained_recipient_decryption_on_fabricated_joined_fixture_blocks",
            },
            public_network_settlement_verified: false,
            attended_native_acceptance_verified: false,
        }
    }
    fn root() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    fn basename() -> &'static str {
        "synthetic-public-outcome-v1.json"
    }
    #[test]
    fn public_outcome_allowlist_maps_exact_values_without_upstream_identifiers() {
        let value = PublicOutcomeV1::from_actual(&actual_data()).unwrap();
        let text = value.public_json().unwrap();
        assert!(!text.contains("never-export"));
        let decoded: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(decoded["transaction_id"], "11".repeat(32));
        assert_eq!(decoded["transaction_bytes_sha256"], "22".repeat(32));
        assert_eq!(decoded["recipient_decrypted_zatoshis"], 100_000);
        assert_eq!(decoded.as_object().unwrap().len(), 20);
    }
    #[test]
    fn public_outcome_refuses_mismatched_or_claimed_real_success() {
        let mut data = actual_data();
        data.recipient.transaction_id = "33".repeat(32);
        assert!(PublicOutcomeV1::from_actual(&data).is_err());
        let mut data = actual_data();
        data.exact_submission.attempt.number = 2;
        assert!(PublicOutcomeV1::from_actual(&data).is_err());
        let mut data = actual_data();
        data.public_network_settlement_verified = true;
        assert!(PublicOutcomeV1::from_actual(&data).is_err());
        let mut data = actual_data();
        data.recipient.fabricated_tip_height = 100;
        assert!(PublicOutcomeV1::from_actual(&data).is_err());
    }
    #[test]
    fn public_outcome_parser_denies_unknown_truncated_and_noncanonical_records() {
        let value = PublicOutcomeV1::from_actual(&actual_data()).unwrap();
        let text = value.public_json().unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["private_extra"] = true.into();
        assert!(serde_json::from_value::<PublicOutcomeV1>(json).is_err());
        assert!(serde_json::from_str::<PublicOutcomeV1>(&text[..text.len() - 1]).is_err());
        let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["transaction_id"] = "AA".repeat(32).into();
        assert!(
            serde_json::from_value::<PublicOutcomeV1>(json)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["submission_outcome"] = "mined".into();
        assert!(serde_json::from_value::<PublicOutcomeV1>(json).is_err());
    }
    #[test]
    fn public_outcome_sidecar_is_single_create_exact_bounded_and_private() {
        let root = root();
        let value = PublicOutcomeV1::from_actual(&actual_data()).unwrap();
        value.write_once(root.path()).unwrap();
        assert!(value.write_once(root.path()).is_err());
        assert_eq!(
            read_after_reap(root.path()).unwrap().public_json().unwrap(),
            value.public_json().unwrap()
        );
        std::fs::set_permissions(
            root.path().join(basename()),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(read_after_reap(root.path()).is_err());
    }
    #[test]
    fn public_outcome_sidecar_denies_symlink_multilink_partial_and_oversize() {
        let value = PublicOutcomeV1::from_actual(&actual_data()).unwrap();
        let root = root();
        let path = root.path().join(basename());
        value.write_once(root.path()).unwrap();
        std::fs::hard_link(&path, root.path().join("other")).unwrap();
        assert!(read_after_reap(root.path()).is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(root.path().join("other"), &path).unwrap();
        assert!(read_after_reap(root.path()).is_err());
        std::fs::remove_file(&path).unwrap();
        value.write_once(root.path()).unwrap();
        std::fs::write(&path, b"{\"schema\":1").unwrap();
        assert!(read_after_reap(root.path()).is_err());
        std::fs::write(&path, vec![b'x'; MAX_BYTES as usize + 1]).unwrap();
        assert!(read_after_reap(root.path()).is_err());
    }
}
