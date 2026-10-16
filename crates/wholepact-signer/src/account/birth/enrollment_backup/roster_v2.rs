//! Exact historical archive adapter for the original V2 roster enrollment.
//! The archive never yields a current enrollment, witness or signer owner. Every
//! encrypted local role stays at its original filename and authenticated domain.
use super::*;
use crate::account::birth::enrollment::roster_v2::{
    self as roster, BornManualRosterEnrollmentRecordV2, acquisition, continuation, retention, permanent_stop::artifacts,
};
use wholepact_authority::{
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    manual_roster_witness_v2::{
        BornManualRosterAdmissionRecordV2, ManualRosterSessionContinuationV2,
    },
};

pub(super) const ACQUIRE: &str = "born-manual-roster-first-acquire-v2.wp";
const COMMIT: &str = "born-manual-roster-commit-v2.wp";
const INTENT: &str = "born-manual-intent.wp";
const JOURNAL: &str = "authority.sqlite";
const MAX_INTENT: usize = 128 * 1024;
const NAMES: [&str; 11] = [
    "account.wp",
    "birth-owner-request.wp",
    INTENT,
    ACQUIRE,
    COMMIT,
    JOURNAL,
    "authority.sqlite-wal",
    "authority.sqlite-shm",
    "authority.sqlite-journal",
    artifacts::SIGNATURE,
    artifacts::HOST_ACK,
];

pub(super) fn allowed_name(name: &str) -> bool {
    NAMES.contains(&name)
        || continuation::parse_name(name).is_some()
        || retention::parse_name(name).is_some()
}
pub(super) fn check_names(files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    if !(4..=NAMES.len() + 4 * continuation::MAX_LOCAL_PROPOSALS + retention::MAX_RECEIPTS)
        .contains(&files.len())
        || files.keys().any(|n| !allowed_name(n))
        || NAMES[..4].iter().any(|n| !files.contains_key(*n))
        || files.contains_key(COMMIT) && !files.contains_key(JOURNAL)
        || (files.contains_key(artifacts::SIGNATURE) || files.contains_key(artifacts::HOST_ACK)) && !files.contains_key(COMMIT)
        || files
            .keys()
            .any(|n| n.starts_with("authority.sqlite-") && !files.contains_key(JOURNAL))
    {
        return Err(Error::RecoveryRequired);
    }
    continuation::check_names(&files.keys().cloned().collect())?;
    retention::check_names(&files.keys().cloned().collect())
}
pub(super) fn state_label(state: AttemptedInventoryState) -> &'static str {
    match state {
        AttemptedInventoryState::Unpublished => {
            "V2 roster acquisition attempted; no signer journal retained"
        }
        AttemptedInventoryState::AuthenticatedEmpty => {
            "V2 roster attempt; authenticated empty journal, completion absent"
        }
        AttemptedInventoryState::InitializedUncompleted => {
            "V2 roster original journal authenticated; completion absent"
        }
        AttemptedInventoryState::CompletedOriginal => {
            "V2 roster original admission completed; all local attempt history retained"
        }
        AttemptedInventoryState::CompletedContinued => {
            "V2 roster first completion used a continuation; all original history retained"
        }
    }
}

/// Exact original commit DTO. It is deliberately not a publication-owner type.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalCommit {
    version: u16,
    signer_roster_record_digest: String,
    intent_digest: String,
    extension: ManualRosterEnrollmentExtensionV2,
    original_continuation: Option<ManualRosterSessionContinuationV2>,
    original_admission: BornManualRosterAdmissionRecordV2,
}
impl HistoricalCommit {
    fn validate(
        &self,
        record: &BornManualRosterEnrollmentRecordV2,
        intent: &str,
        attempts: &[continuation::LocalContinuation],
    ) -> Result<()> {
        self.original_admission
            .validate_for(&self.extension, self.original_continuation.as_ref())
            .map_err(|_| Error::Authentication)?;
        if self.version != 2
            || self.signer_roster_record_digest != record.reference()?
            || self.intent_digest != intent
            || self.extension != record.extension()?
        {
            return Err(Error::Authentication);
        }
        if let Some(c) = &self.original_continuation {
            let matching = attempts
                .iter()
                .find(|a| &a.proposal.continuation == c)
                .ok_or(Error::RecoveryRequired)?;
            if matching.admission.as_ref() != Some(&self.original_admission) {
                return Err(Error::Authentication);
            }
        }
        Ok(())
    }
}

pub(super) fn verify(
    history: &ExactHistory,
) -> Result<(BornManualRosterEnrollmentRecordV2, AttemptedInventoryState)> {
    check_names(&history.files)?;
    let origin = active::backup_origin(
        &history.key,
        history.file("account.wp")?,
        history.file("birth-owner-request.wp")?,
    )?;
    let mut domain = b"wholepact:born-manual-roster-enrollment-intent:v2\0".to_vec();
    domain.extend(origin.anchor().birth_digest().as_bytes());
    let ciphertext = history.file(INTENT)?;
    let plain = vault::decrypt(&history.key, &domain, ciphertext)?;
    if plain.len() < 33 || plain.len() > MAX_INTENT || plain[0] != 2 {
        return Err(Error::InvalidData);
    }
    let key = Zeroizing::new(<[u8; 32]>::try_from(&plain[1..33]).map_err(|_| Error::InvalidData)?);
    let record: BornManualRosterEnrollmentRecordV2 =
        serde_json::from_slice(&plain[33..]).map_err(|_| Error::InvalidData)?;
    record.validate()?;
    history.verify_original_record(&record.account_record)?;
    let intent = hex::encode(Sha256::digest(ciphertext));
    acquisition::validate_acquire_attempt_bytes(
        &record,
        &intent,
        &history.key,
        history.file(ACQUIRE)?,
    )?;
    let attempts = continuation::validate_files(
        &record,
        &intent,
        &history.key,
        history.file(ACQUIRE)?,
        &history.files,
    )?;
    retention::validate_files(&record, &intent, &history.key, &history.files)?;
    let commit = history
        .files
        .get(COMMIT)
        .map(|bytes| -> Result<HistoricalCommit> {
            let mut domain = b"wholepact:born-manual-roster-enrollment-commit:v2\0".to_vec();
            domain.extend(record.reference()?.as_bytes());
            let plain = vault::decrypt(&history.key, &domain, bytes)?;
            if plain.len() > MAX_INTENT {
                return Err(Error::InvalidData);
            }
            let commit: HistoricalCommit =
                serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
            commit.validate(&record, &intent, &attempts)?;
            Ok(commit)
        })
        .transpose()?;
    let state = inspect_journal(history, &key, &record, &intent, commit.as_ref())?;
    Ok((record, state))
}

fn inspect_journal(
    history: &ExactHistory,
    key: &[u8; 32],
    record: &BornManualRosterEnrollmentRecordV2,
    intent: &str,
    commit: Option<&HistoricalCommit>,
) -> Result<AttemptedInventoryState> {
    if !history.files.contains_key(JOURNAL) {
        return Ok(AttemptedInventoryState::Unpublished);
    }
    // Only original ciphertext enters this private throwaway snapshot. Neither
    // the source nor restored target is ever opened as a writable journal.
    let temp = tempfile::tempdir()?;
    let directory = private_journal_snapshot_directory(temp.path())?;
    for name in &NAMES[5..9] {
        if let Some(bytes) = history.files.get(*name) {
            directory.write(name, bytes)?;
        }
    }
    let path = directory.root().join(JOURNAL);
    let key = DatabaseKey::from_bytes(*key);
    let account = &record.account_record;
    let namespace = account.genesis.digest().map_err(|_| Error::InvalidData)?;
    let plan = wholepact_storage_security::PlannedWitnessBirthInitialization::new(
        &namespace, intent, &path, &key,
    )
    .map_err(|_| Error::RecoveryRequired)?;
    match plan
        .inspect(&path, &key, &namespace, intent)
        .map_err(|_| Error::RecoveryRequired)?
    {
        wholepact_storage_security::PlannedWitnessBirthInspection::AuthenticatedEmpty => {
            if commit.is_some() {
                return Err(Error::RecoveryRequired);
            }
            Ok(AttemptedInventoryState::AuthenticatedEmpty)
        }
        wholepact_storage_security::PlannedWitnessBirthInspection::Initialized(read) => {
            drop(read);
            let stopped = crate::consent_journal::SignerConsentJournal::verify_permanent_stop_archive(&path,&key,&account.genesis).ok();
            if let Some(state) = &stopped {
                if commit.is_none() { return Err(Error::RecoveryRequired); }
                let exclusion=state.exclusion.as_ref().ok_or(Error::RecoveryRequired)?;
                if let Some(bytes)=history.files.get(artifacts::SIGNATURE) {
                    let signature=artifacts::decode_signature(&history.key,&account.genesis,bytes)?;
                    if &signature.exclusion!=exclusion { return Err(Error::Authentication); }
                }
                if let Some(bytes)=history.files.get(artifacts::HOST_ACK) {
                    let ack=artifacts::decode_host_ack(&history.key,&account.genesis,bytes)?;
                    if ack.evidence.request.original!=record.request()? || ack.evidence.exclusion_digest!=exclusion.digest().map_err(|_|Error::InvalidData)? || ack.evidence.original_witness_receipt_digest!=state.witness_ack.as_ref().ok_or(Error::RecoveryRequired)?.digest().map_err(|_|Error::InvalidData)? {return Err(Error::Authentication);}
                }
            } else {
                if history.files.contains_key(artifacts::SIGNATURE) || history.files.contains_key(artifacts::HOST_ACK) {return Err(Error::RecoveryRequired);}
                crate::consent_journal::SignerConsentJournal::verify_initial_born_history(&path,&key,&account.genesis,account.terms.signer.writer_epoch)?;
            }
            // Archive recognition preserves all original cells and typed local
            // provenance. It grants no current witness or recovery capability;
            // fresh stop entry validates complete authenticated witness replay.
            Ok(match commit {
                None => AttemptedInventoryState::InitializedUncompleted,
                Some(c) if c.original_continuation.is_none() => {
                    AttemptedInventoryState::CompletedOriginal
                }
                Some(_) => AttemptedInventoryState::CompletedContinued,
            })
        }
    }
}

fn read_inventory(directory: &PrivateDirectory) -> Result<BTreeMap<String, Vec<u8>>> {
    roster::roster_inventory(directory)?;
    let mut files = BTreeMap::new();
    let mut size = 36usize;
    for entry in std::fs::read_dir(directory.root())? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        if name == "signer.lock" {
            continue;
        }
        if !allowed_name(&name) {
            return Err(Error::RecoveryRequired);
        }
        let bytes = directory.read(&name, MAX)?;
        size = size
            .checked_add(5 + name.len())
            .and_then(|n| n.checked_add(bytes.len()))
            .filter(|n| *n <= MAX)
            .ok_or(Error::Unavailable)?;
        files.insert(name, bytes);
    }
    check_names(&files)?;
    Ok(files)
}

pub(super) fn capture(account: &Arc<AccountVault>) -> Result<ExactHistory> {
    // Original-source admission rejects restored/relabelled/wrong-root accounts.
    // This is not a retained record -> live capability conversion.
    super::super::enrollment::original(account)?;
    let files = read_inventory(&account.directory)?;
    let format = HistoryFormat::RosterV3(AttemptedInventoryState::Unpublished);
    let digest = history_digest(format, &files)?;
    let mut result = ExactHistory {
        format,
        key: Zeroizing::new(*account.encryption_key),
        files,
        digest,
    };
    let (_, state) = verify(&result)?;
    result.format = HistoryFormat::RosterV3(state);
    // Full set and all original bytes must still match after immutable reads.
    // The held actual account lock excludes supported cooperating writers.
    super::super::enrollment::original(account)?;
    if read_inventory(&account.directory)? != result.files {
        return Err(Error::ReviewMismatch);
    }
    Ok(result)
}

#[cfg(test)]
#[path = "roster_v2_tests.rs"]
mod tests;
