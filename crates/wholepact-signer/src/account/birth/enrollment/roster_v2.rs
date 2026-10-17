//! STAGED, UNCOMPILED. Intended child account::birth::enrollment::roster_v2.
//! Real source composition, not a DTO -> capability adapter. Preparation owns
//! the actual born vault, native owner binding and kernel-authenticated peer.
//! No runnable route or feature/export is enabled by this external source.
use super::*;
use crate::native_ui::AuthenticatedPairing;
use wholepact_authority::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use wholepact_core::manual_roster_v2::HostRosterAppendBindingV2;
use wholepact_signer_origin::manual_roster_v2::{
    HostManualRosterEnrollmentIntentV2, HostManualRosterEnrollmentRequestV2,
};

pub(crate) mod acquisition;
pub(crate) mod continuation;
#[cfg(feature = "durable-proposal")]
pub(crate) mod durable_entry_v1;
pub(crate) mod inventory;
pub(crate) mod permanent_stop;
pub(crate) mod publication;
pub(crate) mod retention;
pub(super) const ROSTER_ACQUIRE: &str = "born-manual-roster-first-acquire-v2.wp";
pub(super) const ROSTER_COMMIT: &str = "born-manual-roster-commit-v2.wp";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornManualRosterEnrollmentRecordV2 {
    pub(crate) version: u16,
    /// EXACT existing inner record and digest; not a rewritten V1 record.
    pub(crate) account_record: BornManualEnrollmentRecord,
    pub(crate) roster: HostRosterAppendBindingV2,
    pub(crate) signer_roster_native_review_digest: String,
}
impl BornManualRosterEnrollmentRecordV2 {
    pub(crate) fn validate(&self) -> Result<()> {
        self.account_record.validate()?;
        self.roster
            .validate_for_host(&self.account_record.terms.host)
            .map_err(|_| Error::InvalidData)?;
        if self.version != 2
            || self.signer_roster_native_review_digest
                != roster_review_digest(&self.account_record, &self.roster)?
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn reference(&self) -> Result<String> {
        self.validate()?;
        canonical("wholepact:born-manual-roster-enrollment-record:v2", self)
    }
    pub(crate) fn extension(&self) -> Result<ManualRosterEnrollmentExtensionV2> {
        self.validate()?;
        let extension = ManualRosterEnrollmentExtensionV2 {
            version: 2,
            account_extension: self.account_record.extension()?,
            roster: self.roster.clone(),
            signer_roster_record_digest: self.reference()?,
        };
        extension.validate().map_err(|_| Error::InvalidData)?;
        Ok(extension)
    }
    pub(crate) fn request(&self) -> Result<HostManualRosterEnrollmentRequestV2> {
        self.validate()?;
        Ok(HostManualRosterEnrollmentRequestV2 {
            version: 2,
            enrollment: wholepact_signer_origin::manual::HostManualEnrollmentRequest {
                terms: self.account_record.terms.clone(),
            },
            roster: self.roster.clone(),
        })
    }
    pub(crate) fn intent(&self) -> Result<HostManualRosterEnrollmentIntentV2> {
        self.validate()?;
        let t = &self.account_record.terms;
        Ok(HostManualRosterEnrollmentIntentV2 {
            version: 2,
            account_intent: wholepact_signer_origin::manual::HostManualEnrollmentIntent {
                version: 1,
                operation_id: t.operation_id.clone(),
                host: t.host.clone(),
                scope: t.scope.clone(),
            },
            roster: self.roster.clone(),
        })
    }
}
fn roster_review_digest(
    account: &BornManualEnrollmentRecord,
    roster: &HostRosterAppendBindingV2,
) -> Result<String> {
    account.validate()?;
    roster
        .validate_for_host(&account.terms.host)
        .map_err(|_| Error::InvalidData)?;
    canonical(
        "wholepact:native-born-manual-roster-enrollment-review:v2",
        &(account, roster),
    )
}

pub(crate) struct PreparedBornManualRosterEnrollmentV2 {
    prepared_account: PreparedBornManualEnrollment,
    record: BornManualRosterEnrollmentRecordV2,
    display: Zeroizing<String>,
}
impl PreparedBornManualRosterEnrollmentV2 {
    pub(crate) fn prepare(
        account: Arc<AccountVault>,
        intent: &HostManualRosterEnrollmentIntentV2,
        pairing: &AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        intent.validate().map_err(|_| Error::InvalidData)?;
        owner.check_current()?;
        pairing.check_current()?;
        let peer = pairing.current_peer();
        if pairing.native_origin() != &owner.native().binding()
            || peer.scope.manifest_digest != intent.digest().map_err(|_| Error::InvalidData)?
            || peer.scope.history_read
            || peer.scope.authorization_export
            || peer.scope.preconstruction_export
        {
            return Err(Error::Authentication);
        }
        // Existing preparation reads actual original birth/policy/account/FVK,
        // original envelope and actual process, and derives its own journal key.
        // Caller JSON never supplies those values or a native decision.
        let prepared_account = PreparedBornManualEnrollment::prepare(
            account,
            intent.account_intent.host.clone(),
            intent.account_intent.scope.clone(),
            intent.account_intent.operation_id.clone(),
            pairing,
            owner,
        )?;
        intent
            .matches_terms(&prepared_account.record.terms, &intent.roster)
            .map_err(|_| Error::ReviewMismatch)?;
        let record = BornManualRosterEnrollmentRecordV2 {
            version: 2,
            account_record: prepared_account.record.clone(),
            roster: intent.roster.clone(),
            signer_roster_native_review_digest: roster_review_digest(
                &prepared_account.record,
                &intent.roster,
            )?,
        };
        record.validate()?;
        let display = Zeroizing::new(format!(
            "ADD THIS DISTINCT ORIGINAL BORN ACCOUNT TO THE EXACT HOST ROSTER\n\n{}\n\nThe Host roster sequence/predecessor is a reviewed claim from the paired Host. The Host must independently authenticate its locked generation, complete inherited identities/exclusions and current roster head at commit. This account's witness extension remains its first extension. The original birth, policy, account-use genesis and account-wide lifetime ledger are unchanged. This does not expand another account's scope or authorize spending.\n\nExact native review: {}",
            serde_json::to_string_pretty(&record).map_err(|_| Error::InvalidData)?,
            record.signer_roster_native_review_digest
        ));
        Ok(Self {
            prepared_account,
            record,
            display,
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.record.signer_roster_native_review_digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.prepared_account.source.check_current()?;
        self.prepared_account.peer.check_current()?;
        Ok(self.display.to_string())
    }
    pub(crate) fn approve_and_retain(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<RetainedBornManualRosterEnrollmentV2> {
        let p = &self.prepared_account;
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        p.source.check_current()?;
        p.peer.check_current()?;
        if owner.native().binding() != p.source
            || decision.binding() != &p.source
            || decision.reviewed_digest() != self.reviewed_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        let _native = p.source.publication_lease()?;
        check_record_source(&p.account, &self.record.account_record)?;
        if p.account.directory.exists(INTENT)?
            || p.account.directory.exists(JOURNAL)?
            || p.account.directory.exists(COMMIT)?
            || p.account.directory.exists(ACQUIRE_ATTEMPT)?
            || p.account.directory.exists(ROSTER_ACQUIRE)?
            || p.account.directory.exists(ROSTER_COMMIT)?
        {
            return Err(Error::RecoveryRequired);
        }
        let mut plain = Zeroizing::new(vec![2]);
        plain.extend(p.journal_key.iter());
        plain.extend(serde_json::to_vec(&self.record).map_err(|_| Error::InvalidData)?);
        let encrypted = vault::encrypt(
            &p.account.encryption_key,
            &roster_intent_domain(&p.account)?,
            &plain,
        )?;
        if encrypted.len() > MAX_INTENT {
            return Err(Error::InvalidData);
        }
        // Exclusive actual AccountVault directory ownership + absence above is
        // required. Do not turn this into an overwrite/migration of old intent.
        p.account.directory.write(INTENT, &encrypted)?;
        p.account.directory.sync_all_files()?;
        read_roster_retained(p.account.clone())
    }
}

pub(crate) struct RetainedBornManualRosterEnrollmentV2 {
    pub(super) account: Arc<AccountVault>,
    pub(super) record: BornManualRosterEnrollmentRecordV2,
    pub(super) journal_key: Zeroizing<[u8; 32]>,
    pub(super) intent_digest: String,
}
fn roster_intent_domain(account: &AccountVault) -> Result<Vec<u8>> {
    let mut bytes = b"wholepact:born-manual-roster-enrollment-intent:v2\0".to_vec();
    bytes.extend_from_slice(original(account)?.anchor().birth_digest().as_bytes());
    Ok(bytes)
}
fn read_roster_retained(
    account: Arc<AccountVault>,
) -> Result<RetainedBornManualRosterEnrollmentV2> {
    roster_inventory(&account.directory)?;
    let encrypted = account.directory.read(INTENT, MAX_INTENT)?;
    let plain = vault::decrypt(
        &account.encryption_key,
        &roster_intent_domain(&account)?,
        &encrypted,
    )?;
    let (record, journal_key) = decode_roster_intent_plain(&plain)?;
    let retained = RetainedBornManualRosterEnrollmentV2 {
        account,
        record,
        journal_key,
        intent_digest: hex::encode(Sha256::digest(&encrypted)),
    };
    retained.check()?;
    Ok(retained)
}
impl RetainedBornManualRosterEnrollmentV2 {
    pub(crate) fn record(&self) -> &BornManualRosterEnrollmentRecordV2 {
        &self.record
    }
    pub(crate) fn check_current_source(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.check()?;
        owner.check_current()
    }
    pub(crate) fn reopen_exact(&self, owner: &PendingAccountNativeAuthority) -> Result<Self> {
        self.check_current_source(owner)?;
        let next = read_roster_retained(self.account.clone())?;
        if next.record != self.record || next.intent_digest != self.intent_digest {
            return Err(Error::ReviewMismatch);
        }
        Ok(next)
    }
    pub(crate) fn disclosure(&self) -> Result<wholepact_authority::WitnessDisclosureDescriptor> {
        self.check()?;
        Ok(original(&self.account)?
            .original_request()
            .disclosure
            .clone())
    }
    pub(super) fn check(&self) -> Result<()> {
        roster_inventory(&self.account.directory)?;
        self.record.validate()?;
        check_roster_original_source(&self.account, &self.record.account_record)?;
        if hex::encode(Sha256::digest(
            self.account.directory.read(INTENT, MAX_INTENT)?,
        )) != self.intent_digest
        {
            return Err(Error::ReviewMismatch);
        }
        acquisition::validate_retained_marker(self)?;
        continuation::validate_retained_attempts(self)?;
        Ok(())
    }
}

/// Same original-source checks as V1, without feeding V2 files to a V1 decoder.
fn check_roster_original_source(
    account: &AccountVault,
    record: &BornManualEnrollmentRecord,
) -> Result<()> {
    record.validate()?;
    let origin = original(account)?;
    let request = origin.original_request();
    let terms = &record.terms;
    if terms.signer.signer_target_digest != target_digest(account)?
        || terms.signer.original_envelope_digest != envelope_digest(account)?
        || terms.identity.account_id != account.account_id()?
        || record.genesis != origin.anchor().expected_account_use_genesis()?
        || terms.birth_request_digest != request.digest().map_err(|_| Error::InvalidData)?
        || terms.birth_commit_digest
            != wholepact_authority::manual_enrollment::original_birth_commit_digest(
                origin.witness_commit(),
            )
            .map_err(|_| Error::InvalidData)?
        || terms.native_birth_digest != origin.anchor().birth_digest()
        || terms.original_policy_digest != request.disclosure.policy_digest
        || terms.signer.owner_certificate_digest != request.policy.owner_certificate_digest
        || terms.signer.writer_certificate_digest
            != request.policy.initial_writer_certificate_digest
        || terms.signer.writer_epoch != request.policy.initial_writer_epoch
    {
        return Err(Error::ReviewMismatch);
    }
    require_scope(&terms.scope, &request.policy, account, terms.issued_at_ms)
}

pub(in crate::account::birth) fn roster_inventory(directory: &PrivateDirectory) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut names = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(directory.root())? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        let m = std::fs::symlink_metadata(entry.path())?;
        if (!matches!(
            name.as_str(),
            "signer.lock"
                | "account.wp"
                | "birth-owner-request.wp"
                | INTENT
                | ROSTER_ACQUIRE
                | ROSTER_COMMIT
                | permanent_stop::artifacts::SIGNATURE
                | permanent_stop::artifacts::HOST_ACK
                | JOURNAL
                | "authority.sqlite-wal"
                | "authority.sqlite-shm"
                | "authority.sqlite-journal"
        ) && continuation::parse_name(&name).is_none()
            && retention::parse_name(&name).is_none())
            || !m.is_file()
            || m.nlink() != 1
            || m.mode() & 0o077 != 0
            || m.uid() != unsafe { libc::geteuid() }
            || m.len() > 128 * 1024 * 1024
        {
            return Err(Error::InvalidData);
        }
        names.insert(name);
    }
    continuation::check_names(&names)?;
    retention::check_names(&names)?;
    for name in ["signer.lock", "account.wp", "birth-owner-request.wp"] {
        if !names.contains(name) {
            return Err(Error::RecoveryRequired);
        }
    }
    if (names.contains(JOURNAL) || names.contains(ROSTER_COMMIT) || names.contains(ROSTER_ACQUIRE))
        && !names.contains(INTENT)
        || (names.contains(JOURNAL) || names.contains(ROSTER_COMMIT))
            && !names.contains(ROSTER_ACQUIRE)
        || names.contains(ROSTER_COMMIT) && !names.contains(JOURNAL)
        || (names.contains(permanent_stop::artifacts::SIGNATURE)
            || names.contains(permanent_stop::artifacts::HOST_ACK))
            && !names.contains(ROSTER_COMMIT)
        || names
            .iter()
            .any(|n| n.starts_with("authority.sqlite-") && !names.contains(JOURNAL))
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}

impl AccountVault {
    pub(crate) fn unlock_born_for_manual_roster_enrollment_v2(
        root: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        require_canonical_existing_root(root)?;
        let directory = PrivateDirectory::open_existing(root)?;
        let encrypted = directory.read("account.wp", 512 * 1024)?;
        let account =
            active::open_for_manual_roster_enrollment_v2(directory, password, &encrypted)?;
        original(&account)?;
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        Ok(account)
    }
    pub(crate) fn retained_born_manual_roster_enrollment_v2(
        self: &Arc<Self>,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Option<RetainedBornManualRosterEnrollmentV2>> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        original(self)?;
        roster_inventory(&self.directory)?;
        if !self.directory.exists(INTENT)? {
            return Ok(None);
        }
        // Only the V2 authenticated domain and discriminator can open here.
        // A V1 intent, mixed history, or unknown file is preserved and denied.
        let retained = read_roster_retained(self.clone())?;
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        Ok(Some(retained))
    }
}
impl RetainedBornManualRosterEnrollmentV2 {
    pub(crate) fn first_acquire_attempted(&self) -> Result<bool> {
        self.check()?;
        self.account.directory.exists(ROSTER_ACQUIRE)
    }
    pub(crate) fn require_preacquire_reentry(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check_current_source(owner)?;
        acquisition::require_unattempted_inventory(&self.account.directory)
    }
    pub(crate) fn original_recipient_policy_export_v2(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<crate::account::birth::recipient_policy_v2::OriginalRecipientPolicyExportV2> {
        self.check_current_source(owner)?;
        let data = crate::account::birth::recipient_policy_v2::OriginalRecipientPolicyExportV2::from_retained(
            original(&self.account)?)?;
        self.check_current_source(owner)?;
        Ok(data)
    }
}

fn decode_roster_intent_plain(
    plain: &[u8],
) -> Result<(BornManualRosterEnrollmentRecordV2, Zeroizing<[u8; 32]>)> {
    if plain.len() < 33 || plain.len() > MAX_INTENT || plain[0] != 2 {
        return Err(Error::InvalidData);
    }
    let record: BornManualRosterEnrollmentRecordV2 =
        serde_json::from_slice(&plain[33..]).map_err(|_| Error::InvalidData)?;
    record.validate()?;
    Ok((
        record,
        Zeroizing::new(plain[1..33].try_into().map_err(|_| Error::InvalidData)?),
    ))
}
#[cfg(test)]
mod tests;
