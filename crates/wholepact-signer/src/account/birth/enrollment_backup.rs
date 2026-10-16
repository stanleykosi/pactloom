//! Complete, bounded backup of original V1 or roster-V2 born enrollment history.
//! Every source file is retained except the OS lock. Restores publish an inert
//! full-history capsule and a restored born account, never a writable journal.
use super::enrollment::{BornManualEnrollmentRecord, read_commit, read_retained};
use super::*;
use std::collections::BTreeMap;
use wholepact_storage_security::{DatabaseKey, receipt_file::PrivateReceiptTarget};
#[path = "enrollment_backup/roster_v2.rs"]
mod roster_v2;

const MAGIC: &[u8; 8] = b"WPABB002";
const PACKAGE: &str = "born-enrolled-backup.wp";
const RECOVERED: &str = "born-manual-recovered-history.wp";
const MAX: usize = 32 * 1024 * 1024;
const NAMES: [&str; 9] = [
    "account.wp",
    "birth-owner-request.wp",
    "born-manual-intent.wp",
    "born-manual-commit.wp",
    "authority.sqlite",
    "born-manual-first-acquire.wp",
    "authority.sqlite-wal",
    "authority.sqlite-shm",
    "authority.sqlite-journal",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttemptedInventoryState {
    Unpublished,
    AuthenticatedEmpty,
    InitializedUncompleted,
    CompletedOriginal,
    CompletedContinued,
}
impl AttemptedInventoryState {
    fn byte(self) -> u8 {
        match self {
            Self::Unpublished => 1,
            Self::AuthenticatedEmpty => 2,
            Self::InitializedUncompleted => 3,
            Self::CompletedOriginal => 4,
            Self::CompletedContinued => 5,
        }
    }
    fn parse(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Unpublished),
            2 => Ok(Self::AuthenticatedEmpty),
            3 => Ok(Self::InitializedUncompleted),
            4 => Ok(Self::CompletedOriginal),
            5 => Ok(Self::CompletedContinued),
            _ => Err(Error::InvalidData),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Unpublished => "Attempted; no signer journal created",
            Self::AuthenticatedEmpty => {
                "Attempted; authenticated empty initialization, outcome incomplete"
            }
            Self::InitializedUncompleted => {
                "Initial journal authenticated; completion not retained"
            }
            Self::CompletedOriginal => {
                "Original V1 completion authenticated; additive attempt history preserved"
            }
            Self::CompletedContinued => {
                "V2 initial completion authenticated; all original attempt history preserved"
            }
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum HistoryFormat {
    CompletedV1,
    AttemptedV2(AttemptedInventoryState),
    /// Archive discriminator 3 contains the exact original V2 roster protocol.
    /// This is not a conversion to V1 or a new/current enrollment.
    RosterV3(AttemptedInventoryState),
}
#[derive(Clone, Copy)]
enum SourceKind {
    OriginalV1,
    RosterV2,
}
impl SourceKind {
    fn capture(self, account: &Arc<AccountVault>) -> Result<ExactHistory> {
        match self {
            Self::OriginalV1 => capture(account),
            Self::RosterV2 => roster_v2::capture(account),
        }
    }
}
struct ExactHistory {
    format: HistoryFormat,
    key: Zeroizing<[u8; 32]>,
    files: BTreeMap<String, Vec<u8>>,
    digest: String,
}
impl ExactHistory {
    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(vec![match self.format {
            HistoryFormat::CompletedV1 => 1,
            HistoryFormat::AttemptedV2(_) => 2,
            HistoryFormat::RosterV3(_) => 3,
        }]);
        out.extend(self.key.iter());
        out.extend(
            u16::try_from(self.files.len())
                .map_err(|_| Error::InvalidData)?
                .to_le_bytes(),
        );
        if let HistoryFormat::AttemptedV2(state) | HistoryFormat::RosterV3(state) = self.format {
            out.push(state.byte());
        }
        for (name, bytes) in &self.files {
            out.push(u8::try_from(name.len()).map_err(|_| Error::InvalidData)?);
            out.extend(name.as_bytes());
            out.extend(
                u32::try_from(bytes.len())
                    .map_err(|_| Error::InvalidData)?
                    .to_le_bytes(),
            );
            out.extend(bytes);
        }
        if out.len() > MAX {
            return Err(Error::Unavailable);
        }
        Ok(out)
    }
    fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < 35 || input.len() > MAX || !matches!(input[0], 1..=3) {
            return Err(Error::InvalidData);
        }
        let key = Zeroizing::new(input[1..33].try_into().map_err(|_| Error::InvalidData)?);
        let count =
            u16::from_le_bytes(input[33..35].try_into().map_err(|_| Error::InvalidData)?) as usize;
        let maximum = if input[0] == 3 {
            9 + 4 * super::enrollment::roster_v2::continuation::MAX_LOCAL_PROPOSALS
                + super::enrollment::roster_v2::retention::MAX_RECEIPTS
        } else {
            9 + 4 * super::enrollment::attempts::MAX_LOCAL_PROPOSALS
        };
        if !(4..=maximum).contains(&count) {
            return Err(Error::InvalidData);
        }
        let (format, mut rest) = if input[0] == 1 {
            (HistoryFormat::CompletedV1, &input[35..])
        } else {
            let state = AttemptedInventoryState::parse(*input.get(35).ok_or(Error::InvalidData)?)?;
            (
                if input[0] == 2 {
                    HistoryFormat::AttemptedV2(state)
                } else {
                    HistoryFormat::RosterV3(state)
                },
                &input[36..],
            )
        };
        if matches!(format, HistoryFormat::CompletedV1) && !(6..=9).contains(&count) {
            return Err(Error::InvalidData);
        }
        let mut files = BTreeMap::new();
        for _ in 0..count {
            let len = *rest.first().ok_or(Error::InvalidData)? as usize;
            rest = &rest[1..];
            if rest.len() < len + 4 {
                return Err(Error::InvalidData);
            }
            let name = std::str::from_utf8(&rest[..len])
                .map_err(|_| Error::InvalidData)?
                .to_owned();
            rest = &rest[len..];
            let len =
                u32::from_le_bytes(rest[..4].try_into().map_err(|_| Error::InvalidData)?) as usize;
            rest = &rest[4..];
            let allowed = match format {
                HistoryFormat::CompletedV1 => NAMES.contains(&name.as_str()),
                HistoryFormat::AttemptedV2(_) => {
                    NAMES.contains(&name.as_str())
                        || super::enrollment::attempts::parse_name(&name).is_some()
                }
                HistoryFormat::RosterV3(_) => roster_v2::allowed_name(&name),
            };
            if !allowed || len > rest.len() || files.contains_key(&name) {
                return Err(Error::InvalidData);
            }
            files.insert(name, rest[..len].to_vec());
            rest = &rest[len..];
        }
        if !rest.is_empty() {
            return Err(Error::InvalidData);
        }
        for name in [
            "account.wp",
            "birth-owner-request.wp",
            "born-manual-intent.wp",
            if matches!(format, HistoryFormat::RosterV3(_)) {
                roster_v2::ACQUIRE
            } else {
                "born-manual-first-acquire.wp"
            },
        ] {
            if !files.contains_key(name) {
                return Err(Error::InvalidData);
            }
        }
        if matches!(format, HistoryFormat::CompletedV1)
            && NAMES[..6].iter().any(|n| !files.contains_key(*n))
        {
            return Err(Error::InvalidData);
        }
        if files.contains_key("born-manual-commit.wp") && !files.contains_key("authority.sqlite")
            || files.keys().any(|n| {
                n.starts_with("authority.sqlite-") && !files.contains_key("authority.sqlite")
            })
        {
            return Err(Error::RecoveryRequired);
        }
        if matches!(format, HistoryFormat::RosterV3(_)) {
            roster_v2::check_names(&files)?;
        }
        let digest = history_digest(format, &files)?;
        let result = Self {
            format,
            key,
            files,
            digest,
        };
        result.verify()?;
        Ok(result)
    }
    fn file(&self, name: &str) -> Result<&[u8]> {
        self.files
            .get(name)
            .map(Vec::as_slice)
            .ok_or(Error::InvalidData)
    }
    fn verify(&self) -> Result<BornManualEnrollmentRecord> {
        let (record, state) = self.verify_contents()?;
        match self.format {
            HistoryFormat::CompletedV1
                if state == AttemptedInventoryState::CompletedOriginal
                    && self.files.keys().all(|n| NAMES.contains(&n.as_str())) => {}
            HistoryFormat::AttemptedV2(expected) | HistoryFormat::RosterV3(expected)
                if expected == state => {}
            _ => return Err(Error::Authentication),
        }
        Ok(record)
    }
    fn state_label(&self) -> &'static str {
        match self.format {
            HistoryFormat::CompletedV1 => "Complete original V1 manual enrollment",
            HistoryFormat::AttemptedV2(s) => s.label(),
            HistoryFormat::RosterV3(s) => roster_v2::state_label(s),
        }
    }
    fn audit_json(&self) -> Result<String> {
        match self.format {
            HistoryFormat::RosterV3(expected) => {
                let (record, actual) = roster_v2::verify(self)?;
                if expected != actual {
                    return Err(Error::Authentication);
                }
                serde_json::to_string_pretty(&record).map_err(|_| Error::InvalidData)
            }
            _ => serde_json::to_string_pretty(&self.verify()?).map_err(|_| Error::InvalidData),
        }
    }
    fn verify_contents(&self) -> Result<(BornManualEnrollmentRecord, AttemptedInventoryState)> {
        if matches!(self.format, HistoryFormat::RosterV3(_)) {
            let (record, state) = roster_v2::verify(self)?;
            return Ok((record.account_record, state));
        }
        let account = self.file("account.wp")?;
        let request = self.file("birth-owner-request.wp")?;
        let origin = active::backup_origin(&self.key, account, request)?;
        let mut domain = b"wholepact:born-manual-enrollment-intent:v1\0".to_vec();
        domain.extend(origin.anchor().birth_digest().as_bytes());
        let intent = self.file("born-manual-intent.wp")?;
        let plain = vault::decrypt(&self.key, &domain, intent)?;
        if plain.len() < 33 || plain[0] != 1 {
            return Err(Error::InvalidData);
        }
        let key =
            Zeroizing::new(<[u8; 32]>::try_from(&plain[1..33]).map_err(|_| Error::InvalidData)?);
        let record: BornManualEnrollmentRecord =
            serde_json::from_slice(&plain[33..]).map_err(|_| Error::InvalidData)?;
        record.validate()?;
        self.verify_original_record(&record)?;
        let terms = &record.terms;
        let mut domain = b"wholepact:born-manual-enrollment-commit:v1\0".to_vec();
        domain.extend(record.reference()?.as_bytes());
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Commit {
            version: u16,
            enrollment_ref: String,
            intent_digest: String,
            extension: wholepact_authority::manual_enrollment::ManualEnrollmentExtension,
            admission: super::enrollment::publication::AdmissionAudit,
            original_writer_epoch: u64,
        }
        let commit = self
            .files
            .get("born-manual-commit.wp")
            .map(|bytes| -> Result<Commit> {
                let plain = vault::decrypt(&self.key, &domain, bytes)?;
                let commit: Commit =
                    serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
                if commit.version != commit.admission.version()
                    || commit.enrollment_ref != record.reference()?
                    || commit.intent_digest != hex::encode(Sha256::digest(intent))
                    || commit.extension != record.extension()?
                    || commit.original_writer_epoch != terms.signer.writer_epoch
                {
                    return Err(Error::Authentication);
                }
                commit.admission.validate(&commit.extension)?;
                Ok(commit)
            })
            .transpose()?;
        super::enrollment::validate_acquire_attempt_bytes(
            &record,
            &hex::encode(Sha256::digest(intent)),
            &self.key,
            self.file("born-manual-first-acquire.wp")?,
        )?;
        let attempts = super::enrollment::attempts::validate_files(
            &record,
            &hex::encode(Sha256::digest(intent)),
            &self.key,
            self.file("born-manual-first-acquire.wp")?,
            &self.files,
        )?;
        if let Some(commit) = &commit {
            commit.admission.require_attempt_history(&attempts)?;
        }
        // Only encrypted files enter this private temporary directory. It is a
        // supported read-only snapshot, never a live signer or restored writer.
        let temp = tempfile::tempdir()?;
        let directory = private_journal_snapshot_directory(temp.path())?;
        for (name, bytes) in &self.files {
            if name.starts_with("authority.sqlite") {
                directory.write(name, bytes)?;
            }
        }
        let mut state = AttemptedInventoryState::Unpublished;
        if self.files.contains_key("authority.sqlite") {
            let path = directory.root().join("authority.sqlite");
            let key = DatabaseKey::from_bytes(*key);
            let namespace = record.genesis.digest().map_err(|_| Error::InvalidData)?;
            let intent_digest = hex::encode(Sha256::digest(intent));
            let plan = wholepact_storage_security::PlannedWitnessBirthInitialization::new(
                &namespace,
                &intent_digest,
                &path,
                &key,
            )
            .map_err(|_| Error::RecoveryRequired)?;
            match plan
                .inspect(&path, &key, &namespace, &intent_digest)
                .map_err(|_| Error::RecoveryRequired)?
            {
                wholepact_storage_security::PlannedWitnessBirthInspection::AuthenticatedEmpty => {
                    state = AttemptedInventoryState::AuthenticatedEmpty;
                    if commit.is_some() {
                        return Err(Error::RecoveryRequired);
                    }
                }
                wholepact_storage_security::PlannedWitnessBirthInspection::Initialized(read) => {
                    state = match &commit {
                        Some(c) if c.version == 1 => AttemptedInventoryState::CompletedOriginal,
                        Some(_) => AttemptedInventoryState::CompletedContinued,
                        None => AttemptedInventoryState::InitializedUncompleted,
                    };
                    drop(read);
                    crate::consent_journal::SignerConsentJournal::verify_initial_born_history(
                        &path,
                        &key,
                        &record.genesis,
                        terms.signer.writer_epoch,
                    )?;
                }
            }
        }
        Ok((record, state))
    }
    /// Bind historical enrollment to the original authenticated birth, policy,
    /// signer destination and account-wide genesis; no fresh authority is issued.
    fn verify_original_record(&self, record: &BornManualEnrollmentRecord) -> Result<()> {
        record.validate()?;
        let account = self.file("account.wp")?;
        let request = self.file("birth-owner-request.wp")?;
        let origin = active::backup_origin(&self.key, account, request)?;
        let terms = &record.terms;
        active::require_backup_privacy_domain(
            &self.key,
            account,
            request,
            &terms.scope.privacy_domain,
        )?;
        if record.genesis != origin.anchor().expected_account_use_genesis()?
            || terms.birth_request_digest
                != origin
                    .original_request()
                    .digest()
                    .map_err(|_| Error::InvalidData)?
            || terms.birth_commit_digest
                != wholepact_authority::manual_enrollment::original_birth_commit_digest(
                    origin.witness_commit(),
                )
                .map_err(|_| Error::InvalidData)?
            || terms.signer.original_envelope_digest != hex::encode(Sha256::digest(account))
            || terms.original_policy_digest != origin.original_request().disclosure.policy_digest
            || terms.native_birth_digest != origin.anchor().birth_digest()
            || terms.signer.owner_certificate_digest
                != origin.original_request().policy.owner_certificate_digest
            || terms.signer.writer_certificate_digest
                != origin
                    .original_request()
                    .policy
                    .initial_writer_certificate_digest
            || terms.signer.writer_epoch != origin.original_request().policy.initial_writer_epoch
            || terms.signer.signer_target_digest
                != canonical(
                    "wholepact:born-manual-signer-target:v1",
                    &Path::new(&origin.anchor().intent.original_target),
                )?
            || !origin
                .original_request()
                .policy
                .agreement_ids
                .contains(&terms.scope.agreement_id)
            || terms.scope.recipient_scope_digests.iter().any(|d| {
                !origin
                    .original_request()
                    .policy
                    .recipient_scope_digests
                    .contains(d)
            })
            || terms.scope.aggregate_budget_zatoshis
                > origin.original_request().policy.aggregate_budget_zatoshis
            || terms.scope.per_operation_limit_zatoshis
                > origin
                    .original_request()
                    .policy
                    .per_operation_limit_zatoshis
            || terms.scope.maximum_fee_share_zatoshis
                > origin.original_request().policy.maximum_fee_share_zatoshis
            || terms.scope.maximum_transaction_fee_zatoshis
                > origin
                    .original_request()
                    .policy
                    .maximum_transaction_fee_zatoshis
            || terms.scope.maximum_permit_lifetime_ms
                > origin.original_request().policy.maximum_permit_lifetime_ms
            || terms.scope.expires_at_ms > origin.original_request().policy.policy_expires_at_ms
            || origin.permanent_exclusion().is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}
// TempDir follows the process umask. Both historical readers create a private
// child before staging ciphertext; they never chmod or otherwise repair source
// directories, nor rely on the temporary parent's default permissions.
fn private_journal_snapshot_directory(temporary_parent: &Path) -> Result<PrivateDirectory> {
    PrivateDirectory::create(&temporary_parent.join("encrypted-journal"))
}

fn history_digest(format: HistoryFormat, files: &BTreeMap<String, Vec<u8>>) -> Result<String> {
    match format {
        HistoryFormat::RosterV3(_) => {
            // The canonical JSON helper is bounded to 1 MiB. Commit the bounded
            // exact name/length/ciphertext digest set, rather than expanding up
            // to 32 MiB of binary ciphertext into an unbounded JSON array.
            let inventory: Vec<_> = files
                .iter()
                .map(|(name, bytes)| (name, bytes.len() as u64, hex::encode(Sha256::digest(bytes))))
                .collect();
            canonical(
                "wholepact:born-roster-enrolled-history-ciphertexts:v2",
                &inventory,
            )
        }
        _ => canonical("wholepact:born-enrolled-history-ciphertexts:v1", files),
    }
}

fn capture(account: &Arc<AccountVault>) -> Result<ExactHistory> {
    super::enrollment::inventory(&account.directory)?;
    let retained = read_retained(account.clone())?;
    if account.directory.exists("born-manual-commit.wp")? {
        read_commit(&retained)?;
    }
    super::enrollment::attempts::require_attempted_journal(&retained)?;
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for name in NAMES {
        if account.directory.exists(name)? {
            let bytes = account.directory.read(name, MAX)?;
            total = total
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX - 1024)
                .ok_or(Error::Unavailable)?;
            files.insert(name.into(), bytes);
        }
    }
    for (name, bytes) in super::enrollment::attempts::read_files(&account.directory)? {
        total = total
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX - 1024)
            .ok_or(Error::Unavailable)?;
        files.insert(name, bytes);
    }
    let digest = canonical("wholepact:born-enrolled-history-ciphertexts:v1", &files)?;
    let mut result = ExactHistory {
        format: HistoryFormat::AttemptedV2(AttemptedInventoryState::Unpublished),
        key: Zeroizing::new(*account.encryption_key),
        files,
        digest,
    };
    let (_, state) = result.verify_contents()?;
    result.format = if state == AttemptedInventoryState::CompletedOriginal
        && result.files.keys().all(|n| NAMES.contains(&n.as_str()))
    {
        HistoryFormat::CompletedV1
    } else {
        HistoryFormat::AttemptedV2(state)
    };
    result.verify()?;
    // Owning account lock excludes supported writers; compare all source bytes
    // again after immutable SQLite capture, including every existing sidecar.
    super::enrollment::inventory(&account.directory)?;
    for name in NAMES {
        match result.files.get(name) {
            Some(bytes) if account.directory.read(name, MAX)? == *bytes => {}
            None if !account.directory.exists(name)? => {}
            _ => return Err(Error::ReviewMismatch),
        }
    }
    let actual_attempts = super::enrollment::attempts::read_files(&account.directory)?;
    let retained_attempts: BTreeMap<_, _> = result
        .files
        .iter()
        .filter(|(n, _)| super::enrollment::attempts::parse_name(n).is_some())
        .map(|(n, b)| (n.clone(), b.clone()))
        .collect();
    if actual_attempts != retained_attempts {
        return Err(Error::ReviewMismatch);
    }
    Ok(result)
}
/// Explicit roster history audit; data can never be used as a current owner.
pub(crate) fn audit_born_roster_enrollment_history_v2(
    account: &Arc<AccountVault>,
    owner: &PendingAccountNativeAuthority,
) -> Result<String> {
    owner.check_current()?;
    owner.native().binding().bounded_deadline()?;
    let history = roster_v2::capture(account)?;
    let text = format!(
        "Authenticated inventory state: {}\n{}",
        history.state_label(),
        history.audit_json()?
    );
    owner.check_current()?;
    owner.native().binding().bounded_deadline()?;
    Ok(text)
}
pub(crate) struct PreparedBornEnrolledBackup {
    account: Arc<AccountVault>,
    kind: SourceKind,
    target: PathBuf,
    target_guard: PrivateReceiptTarget,
    _parent: std::fs::File,
    source: NativeAuthorityBinding,
    source_digest: String,
    encrypted: Zeroizing<Vec<u8>>,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedBornEnrolledBackup {
    pub(crate) fn prepare(
        account: Arc<AccountVault>,
        target: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        Self::prepare_exact(account, target, password, owner, SourceKind::OriginalV1)
    }
    pub(crate) fn prepare_roster_v2(
        account: Arc<AccountVault>,
        target: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        Self::prepare_exact(account, target, password, owner, SourceKind::RosterV2)
    }
    fn prepare_exact(
        account: Arc<AccountVault>,
        target: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
        kind: SourceKind,
    ) -> Result<Self> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        let target = backup::destination(target)?;
        let (target_guard, parent) = backup::hold_destination(&target)?;
        if target.starts_with(account.directory.root())
            || account.directory.root().starts_with(&target)
        {
            return Err(Error::InvalidData);
        }
        let source = kind.capture(&account)?;
        let encrypted =
            Zeroizing::new(vault::password_envelope(MAGIC, password, &source.bytes()?)?);
        let digest = canonical(
            "wholepact:native-born-enrolled-backup:v1",
            &(
                &target,
                &source.digest,
                hex::encode(Sha256::digest(&*encrypted)),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        let mut display = Zeroizing::new(format!(
            "BACK UP COMPLETE ORIGINAL MANUAL ATTEMPT HISTORY\nTarget: {}\n\nIncludes the exact original V1 or V2 roster protocol without conversion: original account recovery ciphertext and its wrapped key, immutable birth/request/owner record, native manual intent, the original first-Acquire attempt marker, every immutable continuation proposal/signature/acquire/admission and independent extension commit, every encrypted signer journal component (including existing WAL/sidecars), and all immutable genesis identity. This includes exact uncompleted or authenticated-empty initialization states; completion is never inferred. This bounded format rejects any later journal activity rather than omit it. Possession of package and password reveals private recovery material and history. Restore produces an inert complete history capsule plus a restored, financially denied born account; it never recreates a current writer.\n\nSource inventory digest: {}\nExact review: {}",
            target.display(),
            source.digest,
            digest
        ));
        display.push_str(&format!(
            "\nAuthenticated inventory state: {}",
            source.state_label()
        ));
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        Ok(Self {
            account,
            kind,
            target,
            target_guard,
            _parent: parent,
            source: owner.native().binding(),
            source_digest: source.digest,
            encrypted,
            digest,
            display,
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(self.display.to_string())
    }
    pub(crate) fn approve_and_write(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.source.check_current()?;
        if owner.native().binding() != self.source
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.kind.capture(&self.account)?.digest != self.source_digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.target_guard
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        backup::destination(&self.target)?;
        let _lease = self.source.publication_lease()?;
        let output = PrivateDirectory::create(&self.target)?;
        self.target_guard
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        output.write(PACKAGE, &self.encrypted)?;
        output.sync_all_files()?;
        if output.read(PACKAGE, MAX + 128)?.as_slice() != self.encrypted.as_slice() {
            return Err(Error::Authentication);
        }
        output.write(
            "COMPLETE",
            hex::encode(Sha256::digest(&*self.encrypted)).as_bytes(),
        )?;
        output.sync_all_files()
    }
}
fn package(directory: &PrivateDirectory) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let mut names = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(directory.root())? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        let m = std::fs::symlink_metadata(entry.path())?;
        if !matches!(name.as_str(), "signer.lock" | PACKAGE | "COMPLETE")
            || !m.is_file()
            || m.nlink() != 1
            || m.mode() & 0o077 != 0
            || m.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::InvalidData);
        }
        names.insert(name);
    }
    if names.len() != 3 {
        return Err(Error::InvalidData);
    }
    let bytes = directory.read(PACKAGE, MAX + 128)?;
    if directory.read("COMPLETE", 64)? != hex::encode(Sha256::digest(&bytes)).as_bytes() {
        return Err(Error::Authentication);
    }
    Ok(bytes)
}
pub(crate) struct PreparedBornEnrolledRecoveryDisclosure {
    directory: PrivateDirectory,
    encrypted: Vec<u8>,
    password: Zeroizing<Vec<u8>>,
    source: NativeAuthorityBinding,
    digest: String,
}
impl PreparedBornEnrolledRecoveryDisclosure {
    pub(crate) fn prepare(
        path: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        require_canonical_existing_root(path)?;
        let directory = PrivateDirectory::open_existing(path)?;
        let encrypted = package(&directory)?;
        let digest = canonical(
            "wholepact:native-born-enrolled-recovery-read:v1",
            &(
                path,
                hex::encode(Sha256::digest(&encrypted)),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        Ok(Self {
            directory,
            encrypted,
            password: Zeroizing::new(password.to_vec()),
            source: owner.native().binding(),
            digest,
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(format!(
            "DECRYPT ORIGINAL MANUAL ATTEMPT OR ENROLLED RECOVERY\nRead recovery secrets, original born/manual/witness history, exact attempted/completion state and any retained initial signer journal from {} for private local review. This does not authorize restoration or financial use.\nExact review: {}",
            self.directory.root().display(),
            self.digest
        ))
    }
    pub(crate) fn approve_read(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<VerifiedBornEnrolledBackup> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.source.check_current()?;
        if owner.native().binding() != self.source
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || package(&self.directory)? != self.encrypted
        {
            return Err(Error::ReviewMismatch);
        }
        let (plain, _, _) =
            vault::open_password_envelope(MAGIC, &self.password, &self.encrypted, MAX + 128)?;
        let history = ExactHistory::parse(&plain)?;
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        Ok(VerifiedBornEnrolledBackup {
            directory: self.directory,
            encrypted: self.encrypted,
            history,
            source: self.source,
        })
    }
}
pub(crate) struct VerifiedBornEnrolledBackup {
    directory: PrivateDirectory,
    encrypted: Vec<u8>,
    history: ExactHistory,
    source: NativeAuthorityBinding,
}
impl VerifiedBornEnrolledBackup {
    pub(crate) fn disclosure_deadline(&self) -> Result<Instant> {
        self.source.bounded_deadline()
    }
    pub(crate) fn check_disclosure(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.check(owner)
    }

    pub(crate) fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.source.check_current()?;
        if self.source != owner.native().binding() || package(&self.directory)? != self.encrypted {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn audit_json(&self, owner: &PendingAccountNativeAuthority) -> Result<String> {
        self.check(owner)?;
        let display = format!(
            "Authenticated inventory state: {}\n{}",
            self.history.state_label(),
            self.history.audit_json()?
        );
        self.check(owner)?;
        Ok(display)
    }
    pub(crate) fn prepare_restore(
        self,
        target: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedBornEnrolledRestore> {
        self.check(owner)?;
        let target = backup::destination(target)?;
        let (target_guard, parent) = backup::hold_destination(&target)?;
        if target.starts_with(self.directory.root()) || self.directory.root().starts_with(&target) {
            return Err(Error::InvalidData);
        }
        let (account, request) = active::recovered_envelopes(
            &self.history.key,
            self.history.file("account.wp")?,
            self.history.file("birth-owner-request.wp")?,
            password,
        )?;
        // Original account/request/intent/commit and EVERY journal byte remain
        // inside this re-encrypted complete capsule. No live authority.sqlite is
        // restored, and source labels/anchor/generation are never rewritten.
        let capsule = Zeroizing::new(vault::password_envelope(
            MAGIC,
            password,
            &self.history.bytes()?,
        )?);
        self.check(owner)?;
        let digest = canonical(
            "wholepact:native-born-enrolled-restore:v1",
            &(
                &target,
                hex::encode(Sha256::digest(&account)),
                hex::encode(Sha256::digest(&request)),
                hex::encode(Sha256::digest(&*capsule)),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        Ok(PreparedBornEnrolledRestore {
            verified: self,
            target,
            target_guard,
            _parent: parent,
            account: Zeroizing::new(account),
            request: Zeroizing::new(request),
            capsule,
            digest,
        })
    }
}
pub(crate) struct PreparedBornEnrolledRestore {
    verified: VerifiedBornEnrolledBackup,
    target: PathBuf,
    target_guard: PrivateReceiptTarget,
    _parent: std::fs::File,
    account: Zeroizing<Vec<u8>>,
    request: Zeroizing<Vec<u8>>,
    capsule: Zeroizing<Vec<u8>>,
    digest: String,
}
impl PreparedBornEnrolledRestore {
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.verified.source.check_current()?;
        Ok(format!(
            "RESTORE COMPLETE INERT MANUAL HISTORY\nAuthenticated inventory state: {}\nNew target: {}\nThe original anchor, exact attempted or completed enrollment, witness extension, every local attempt and any encrypted journal stay in a new-password-encrypted history capsule. The re-encrypted account is marked restored and remains denied for all financial/key-release/journal activation. This does not instantiate a writable signer journal or claim current witness state.\nExact review: {}",
            self.verified.history.state_label(),
            self.target.display(),
            self.digest
        ))
    }
    pub(crate) fn approve_and_restore(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.verified.check(owner)?;
        if decision.binding() != &self.verified.source || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.target_guard
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        backup::destination(&self.target)?;
        let _lease = self.verified.source.publication_lease()?;
        let out = PrivateDirectory::create(&self.target)?;
        self.target_guard
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        out.write("account.wp", &self.account)?;
        out.write("birth-owner-request.wp", &self.request)?;
        out.write(RECOVERED, &self.capsule)?;
        out.write(
            "born-manual-recovery-complete.wp",
            hex::encode(Sha256::digest(&*self.capsule)).as_bytes(),
        )?;
        out.sync_all_files()?;
        if out.read("account.wp", 512 * 1024)?.as_slice() != self.account.as_slice()
            || out.read("birth-owner-request.wp", 128 * 1024)?.as_slice() != self.request.as_slice()
            || out.read(RECOVERED, MAX + 128)?.as_slice() != self.capsule.as_slice()
            || out.read("born-manual-recovery-complete.wp", 128)?
                != hex::encode(Sha256::digest(&*self.capsule)).as_bytes()
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

/// Focused audit of a restored inert enrolled-history capsule. Exact inventory
/// and original account origin are checked; no live journal is extracted.
pub(crate) fn audit_restored_enrolled_history(
    root: &Path,
    password: &[u8],
    owner: &PendingAccountNativeAuthority,
) -> Result<String> {
    owner.check_current()?;
    owner.native().binding().bounded_deadline()?;
    require_canonical_existing_root(root)?;
    let directory = PrivateDirectory::open_existing(root)?;
    let text = read_restored_history(&directory, password)?;
    owner.check_current()?;
    owner.native().binding().bounded_deadline()?;
    Ok(text)
}
/// Data-only immutable reader; no native, witness, writer or financial owner.
fn read_restored_history(directory: &PrivateDirectory, password: &[u8]) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    let mut names = std::collections::BTreeSet::new();
    for e in std::fs::read_dir(directory.root())? {
        let e = e?;
        let name = e
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        let m = std::fs::symlink_metadata(e.path())?;
        if !matches!(
            name.as_str(),
            "signer.lock"
                | "account.wp"
                | "birth-owner-request.wp"
                | RECOVERED
                | "born-manual-recovery-complete.wp"
        ) || !m.is_file()
            || m.nlink() != 1
            || m.mode() & 0o077 != 0
            || m.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::InvalidData);
        }
        names.insert(name);
    }
    if names.len() != 5 {
        return Err(Error::InvalidData);
    }
    let capsule = directory.read(RECOVERED, MAX + 128)?;
    if directory.read("born-manual-recovery-complete.wp", 64)?
        != hex::encode(Sha256::digest(&capsule)).as_bytes()
    {
        return Err(Error::Authentication);
    }
    let (plain, _, _) = vault::open_password_envelope(MAGIC, password, &capsule, MAX + 128)?;
    let history = ExactHistory::parse(&plain)?;
    let account = directory.read("account.wp", 512 * 1024)?;
    let request = directory.read("birth-owner-request.wp", 128 * 1024)?;
    let (_, key, _) = vault::open_password_envelope(b"WPACB002", password, &account, 512 * 1024)?;
    active::require_restored_backup_payload(&key, &account, &request)?;
    let current = active::backup_origin(&key, &account, &request)?;
    let original = active::backup_origin(
        &history.key,
        history.file("account.wp")?,
        history.file("birth-owner-request.wp")?,
    )?;
    if serde_json::to_vec(&current).map_err(|_| Error::InvalidData)?
        != serde_json::to_vec(&original).map_err(|_| Error::InvalidData)?
    {
        return Err(Error::ReviewMismatch);
    }
    let text = format!(
        "Authenticated inventory state: {}\n{}",
        history.state_label(),
        history.audit_json()?
    );
    Ok(text)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn historical_journal_copy_is_private_under_nonprivate_temporary_parent() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let temporary = tempfile::tempdir().unwrap();
        // Synthetic throwaway parent only; no production/source permissions
        // are changed. Explicitly reproduce the normal umask-0022 case.
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(PrivateDirectory::open(temporary.path()).is_err());
        let directory = private_journal_snapshot_directory(temporary.path()).unwrap();
        assert_eq!(
            std::fs::metadata(directory.root()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(temporary.path()).unwrap().mode() & 0o777,
            0o755
        );
        directory
            .write("authority.sqlite", b"synthetic ciphertext only")
            .unwrap();
        assert_eq!(
            std::fs::metadata(directory.root().join("authority.sqlite"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            directory.read("authority.sqlite", 64).unwrap(),
            b"synthetic ciphertext only"
        );
    }

    #[test]
    fn attempted_backup_has_distinct_version_and_explicit_noncompleted_state() {
        let files = [
            "account.wp",
            "birth-owner-request.wp",
            "born-manual-intent.wp",
            "born-manual-first-acquire.wp",
        ]
        .into_iter()
        .map(|name| (name.into(), b"synthetic ciphertext".to_vec()))
        .collect();
        let attempted = ExactHistory {
            format: HistoryFormat::AttemptedV2(AttemptedInventoryState::Unpublished),
            key: Zeroizing::new([0x52; 32]),
            files,
            digest: "a".repeat(64),
        };
        let bytes = attempted.bytes().unwrap();
        assert_eq!(bytes[0], 2);
        assert_eq!(bytes[35], 1);
        assert!(attempted.state_label().contains("no signer journal"));
        let mut old = bytes.to_vec();
        old[0] = 1;
        old.remove(35);
        assert!(matches!(ExactHistory::parse(&old), Err(Error::InvalidData)));
        let mut unknown = bytes.to_vec();
        unknown[35] = 0;
        assert!(matches!(
            ExactHistory::parse(&unknown),
            Err(Error::InvalidData)
        ));
    }
    #[test]
    fn complete_backup_encoder_retains_required_first_attempt_ciphertext_exactly() {
        let marker = b"synthetic distinct authenticated-marker ciphertext bytes".to_vec();
        let files = NAMES[..6]
            .iter()
            .map(|name| {
                (
                    (*name).to_owned(),
                    if *name == "born-manual-first-acquire.wp" {
                        marker.clone()
                    } else {
                        b"synthetic original ciphertext".to_vec()
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(files.contains_key("born-manual-first-acquire.wp"));
        let history = ExactHistory {
            format: HistoryFormat::CompletedV1,
            key: Zeroizing::new([0x51; 32]),
            digest: "a".repeat(64),
            files,
        };
        let bytes = history.bytes().unwrap();
        let mut rest = &bytes[35..];
        let mut retained = None;
        for _ in 0..6 {
            let n = rest[0] as usize;
            rest = &rest[1..];
            let name = std::str::from_utf8(&rest[..n]).unwrap();
            rest = &rest[n..];
            let len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
            rest = &rest[4..];
            if name == "born-manual-first-acquire.wp" {
                retained = Some(rest[..len].to_vec());
            }
            rest = &rest[len..];
        }
        assert!(rest.is_empty());
        assert_eq!(retained, Some(marker));
        let mut missing = history;
        missing.files.remove("born-manual-first-acquire.wp");
        let incomplete = missing.bytes().unwrap();
        assert_eq!(
            u16::from_le_bytes(incomplete[33..35].try_into().unwrap()),
            5
        );
        assert!(ExactHistory::parse(&incomplete).is_err());
    }
    #[test]
    fn truncated_or_unknown_complete_history_never_verifies() {
        for bytes in [vec![], vec![1; 34], vec![1; 64], vec![2; 128]] {
            assert!(ExactHistory::parse(&bytes).is_err());
        }
    }
    #[test]
    fn unknown_inventory_and_missing_complete_marker_are_not_repaired() {
        let temp = tempfile::tempdir().unwrap();
        let dir = PrivateDirectory::create(&temp.path().join("source")).unwrap();
        dir.write(PACKAGE, b"synthetic incomplete ciphertext")
            .unwrap();
        assert!(package(&dir).is_err());
        assert!(!dir.root().join("COMPLETE").exists());
        dir.write("unknown", b"preserve").unwrap();
        assert!(package(&dir).is_err());
        assert_eq!(dir.read("unknown", 32).unwrap(), b"preserve");
    }
}
