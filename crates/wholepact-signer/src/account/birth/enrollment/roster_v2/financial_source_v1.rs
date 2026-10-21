//! Actual original custody for explicit financial continuation. No B1 active
//! owner or historical receipt can be converted into this source.
use super::*;
use crate::consent_journal::{
    FinancialAdmissionJournalPinV1, FinancialConsentJournalV1, FinancialReturnJournalPinV1,
    FinancialSourceBindingV1, PendingFinancialContinuationAdmissionV1,
    PreparedFinancialContinuationIntentV1,
};
use crate::native_ui::{
    DormantNativeLifetime,
    financial_authority_v1::{
        FinancialContinuationReviewV1, FinancialReadLeaseV1, FinancialSignActionV1,
    },
};
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_authority::durable_financial_continuation_v1::FinancialContinuationTermsV1;

#[derive(PartialEq, Eq)]
struct FileRevision {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn immutable(
    retained: &RetainedBornManualRosterEnrollmentV2,
) -> Result<BTreeMap<String, FileRevision>> {
    let directory = &retained.account.directory;
    let _held = directory.signer_journal_source_owner()?;
    super::roster_inventory(directory)?;
    let mut result = BTreeMap::new();
    for entry in std::fs::read_dir(directory.root())? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        if matches!(
            name.as_str(),
            "signer.lock"
                | "authority.sqlite"
                | "authority.sqlite-wal"
                | "authority.sqlite-shm"
                | "authority.sqlite-journal"
        ) {
            continue;
        }
        let m = std::fs::symlink_metadata(entry.path())?;
        if !m.is_file() || m.file_type().is_symlink() || m.nlink() != 1 || m.mode() & 0o077 != 0 {
            return Err(Error::InvalidData);
        }
        result.insert(
            name,
            FileRevision {
                device: m.dev(),
                inode: m.ino(),
                length: m.len(),
                uid: m.uid(),
                gid: m.gid(),
                mode: m.mode(),
                modified: (m.mtime(), m.mtime_nsec()),
                changed: (m.ctime(), m.ctime_nsec()),
            },
        );
    }
    Ok(result)
}
enum OriginalJournalV1 {
    Before(SignerConsentJournal),
    Financial(FinancialConsentJournalV1),
}
/// Non-cloneable original vault/directory/journal custody. It has no generic
/// wallet, private-key, raw journal or source-authority getter.
pub(crate) struct PreparedOriginalFinancialSourceV1 {
    retained: RetainedBornManualRosterEnrollmentV2,
    original_commit: publication::BornManualRosterCommitV2,
    original_disclosure: wholepact_authority::WitnessDisclosureDescriptor,
    journal: OriginalJournalV1,
    binding: std::sync::Mutex<FinancialSourceBindingV1>,
    identity: String,
    recipient: std::sync::Mutex<Option<crate::native_peer::PeerProcess>>,
    immutable: BTreeMap<String, FileRevision>,
    lifetime: DormantNativeLifetime,
    original_ceiling_ms: u64,
    original_deadline: Instant,
}
impl PreparedOriginalFinancialSourceV1 {
    /// Fresh actual native unlock, followed by consuming/draining its authority.
    /// This does not consume an active V3 view or inherit its grants/sessions.
    pub(crate) fn open_original19(
        root: &Path,
        password: &[u8],
        owner: Arc<PendingAccountNativeAuthority>,
        terms: &FinancialContinuationTermsV1,
    ) -> Result<Self> {
        owner.check_current()?;
        terms.validate().map_err(|_| Error::InvalidData)?;
        let account = Arc::new(AccountVault::unlock_born_for_manual_roster_enrollment_v2(
            root, password, &owner,
        )?);
        let retained = account
            .retained_born_manual_roster_enrollment_v2(&owner)?
            .ok_or(Error::RecoveryRequired)?;
        retained.check_current_source(&owner)?;
        let original_commit = publication::read_commit(&retained)?;
        let original_disclosure = retained.disclosure()?;
        let genesis = &retained.record.account_record.genesis;
        if genesis.identity.account_id != terms.scope.authorization.identity.account_id {
            return Err(Error::ReviewMismatch);
        }
        let journal = SignerConsentJournal::open_durable_delivery_entry_v3(
            &account.directory.root().join(JOURNAL),
            &DatabaseKey::from_bytes(*retained.journal_key),
            genesis,
            &account.directory.signer_journal_source_owner()?,
        )?;
        let binding = journal.prepare_financial_source_binding_v1(genesis)?;
        let snapshot = immutable(&retained)?;
        let lifetime = owner.dormant_lifetime()?;
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Locked)?
                .as_millis(),
        )
        .map_err(|_| Error::Locked)?;
        terms.require_live(now).map_err(|_| Error::Locked)?;
        let original_ceiling_ms = terms.valid_until_ms;
        let original_deadline = Instant::now()
            .checked_add(Duration::from_millis(
                original_ceiling_ms.checked_sub(now).ok_or(Error::Locked)?,
            ))
            .ok_or(Error::InvalidData)?;
        retained.check_current_source(&owner)?;
        if immutable(&retained)? != snapshot
            || publication::read_commit(&retained)? != original_commit
        {
            return Err(Error::ReviewMismatch);
        }
        // No workers or peer owners have been created by this opener. Revoke
        // the setup instance before returning non-authorizing custody.
        owner.revoke_prepared_delivery_transition();
        drop(owner);
        Ok(Self {
            retained,
            original_commit,
            original_disclosure,
            journal: OriginalJournalV1::Before(journal),
            identity: binding.identity_digest().into(),
            binding: std::sync::Mutex::new(binding),
            recipient: std::sync::Mutex::new(None),
            immutable: snapshot,
            lifetime,
            original_ceiling_ms,
            original_deadline,
        })
    }
    /// Exact financial20 originals only. Historical native decisions stay inert.
    pub(crate) fn open_original20(
        root: &Path,
        password: &[u8],
        owner: Arc<PendingAccountNativeAuthority>,
    ) -> Result<Self> {
        owner.check_current()?;
        let account = Arc::new(AccountVault::unlock_born_for_manual_roster_enrollment_v2(
            root, password, &owner,
        )?);
        let retained = account
            .retained_born_manual_roster_enrollment_v2(&owner)?
            .ok_or(Error::RecoveryRequired)?;
        retained.check_current_source(&owner)?;
        let original_commit = publication::read_commit(&retained)?;
        let original_disclosure = retained.disclosure()?;
        let genesis = &retained.record.account_record.genesis;
        let journal = FinancialConsentJournalV1::open_original(
            &account.directory.root().join(JOURNAL),
            &DatabaseKey::from_bytes(*retained.journal_key),
            genesis,
            &account.directory.signer_journal_source_owner()?,
        )?;
        let historical = journal.retained_continuation()?;
        let terms = historical.terms()?;
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Locked)?
                .as_millis(),
        )
        .map_err(|_| Error::Locked)?;
        // Expired data may still be inspected by a separate history-only path,
        // but this explicit financial source cannot manufacture a new lifetime.
        terms.require_live(now).map_err(|_| Error::Locked)?;
        let original_ceiling_ms = terms.valid_until_ms;
        let original_deadline = Instant::now()
            .checked_add(Duration::from_millis(
                original_ceiling_ms.checked_sub(now).ok_or(Error::Locked)?,
            ))
            .ok_or(Error::InvalidData)?;
        let binding = journal.prepare_financial_source_binding_v1()?;
        let snapshot = immutable(&retained)?;
        let lifetime = owner.dormant_lifetime()?;
        retained.check_current_source(&owner)?;
        if immutable(&retained)? != snapshot
            || publication::read_commit(&retained)? != original_commit
        {
            return Err(Error::ReviewMismatch);
        }
        owner.revoke_prepared_delivery_transition();
        drop(owner);
        Ok(Self {
            retained,
            original_commit,
            original_disclosure,
            journal: OriginalJournalV1::Financial(journal),
            identity: binding.identity_digest().into(),
            binding: std::sync::Mutex::new(binding),
            recipient: std::sync::Mutex::new(None),
            immutable: snapshot,
            lifetime,
            original_ceiling_ms,
            original_deadline,
        })
    }
    pub(crate) fn require_original_owner_witness(
        &self,
        disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        certificate: &str,
    ) -> Result<()> {
        self.check_custody()?;
        if self.retained.disclosure()? != *disclosure
            || self
                .retained
                .record
                .account_record
                .terms
                .signer
                .owner_certificate_digest
                != certificate
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn original_root(&self) -> &Path {
        self.retained.account.directory.root()
    }
    pub(crate) fn identity_digest(&self) -> &str {
        &self.identity
    }
    pub(crate) fn original_deadline(&self) -> Instant {
        self.original_deadline
    }
    pub(crate) fn original_ceiling_ms(&self) -> u64 {
        self.original_ceiling_ms
    }
    pub(crate) fn check_custody(&self) -> Result<()> {
        self.lifetime.check_connected()?;
        self.retained.check()?;
        if immutable(&self.retained)? != self.immutable
            || publication::read_commit(&self.retained)? != self.original_commit
        {
            return Err(Error::ReviewMismatch);
        }
        match &self.journal {
            OriginalJournalV1::Before(journal) => journal.check_financial_source_binding_v1(
                &*self.binding.lock().map_err(|_| Error::Locked)?,
            )?,
            OriginalJournalV1::Financial(journal) => journal.check_financial_source_binding_v1(
                &*self.binding.lock().map_err(|_| Error::Locked)?,
            )?,
        }
        self.lifetime.check_connected()
    }
    pub(crate) fn prepare_continuation(
        &self,
        terms: FinancialContinuationTermsV1,
        review: FinancialContinuationReviewV1,
        history: &wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<PreparedFinancialContinuationIntentV1> {
        self.check_custody()?;
        review.check_source(self.identity_digest())?;
        if terms.valid_until_ms != self.original_ceiling_ms
            || Instant::now() >= self.original_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        match &self.journal {
            OriginalJournalV1::Before(journal) => Ok(journal
                .prepare_financial_continuation_intent_v1(
                    &*self.binding.lock().map_err(|_| Error::Locked)?,
                    terms,
                    review,
                    history,
                )?),
            OriginalJournalV1::Financial(_) => Err(Error::RecoveryRequired),
        }
    }
    /// Inert preparation only, with no native or coordinated effect owner. The
    /// original source and actual Host peer are checked, but proposed review
    /// facts do not prove an Arm or permission. No guard escapes this method.
    /// A distinct genuine final-token join and V2 history reader are required
    /// before this ticket could ever be used by a future transition.
    pub(crate) fn prepare_coordinated_continuation_v1(
        &self,
        terms: FinancialContinuationTermsV1,
        history: wholepact_authority::ReconciledAuthorityHistory,
        original_host: crate::native_peer::PeerProcess,
        review: crate::consent_journal::CoordinatedContinueReviewDataV1,
        retained_review_deadline: Instant,
    ) -> Result<crate::consent_journal::PreparedCoordinatedFinancialContinuationV1> {
        self.check_custody()?;
        original_host.check_alive()?;
        if terms.valid_until_ms != self.original_ceiling_ms
            || Instant::now() >= self.original_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        let prepared = {
            let binding = self.binding.lock().map_err(|_| Error::Locked)?;
            match &self.journal {
                OriginalJournalV1::Before(journal) => journal
                    .prepare_coordinated_financial_continuation_v1(
                        &binding,
                        terms,
                        history,
                        original_host,
                        review,
                        self.original_ceiling_ms,
                        self.original_deadline,
                        retained_review_deadline,
                    )?,
                OriginalJournalV1::Financial(_) => return Err(Error::RecoveryRequired),
            }
        };
        self.check_custody()?;
        prepared.check_retained_preparation()?;
        Ok(prepared)
    }
    pub(crate) fn commit_continuation(
        self,
        prepared: PreparedFinancialContinuationIntentV1,
    ) -> Result<(Self, PendingFinancialContinuationAdmissionV1)> {
        self.check_custody()?;
        let Self {
            retained,
            original_commit,
            original_disclosure,
            journal,
            binding,
            identity: _,
            recipient,
            immutable,
            lifetime,
            original_ceiling_ms,
            original_deadline,
        } = self;
        let OriginalJournalV1::Before(journal) = journal else {
            return Err(Error::RecoveryRequired);
        };
        let (journal, pending) = FinancialConsentJournalV1::transition_original(
            journal,
            binding.into_inner().map_err(|_| Error::Locked)?,
            prepared,
        )?;
        let binding = journal.prepare_financial_source_binding_v1()?;
        let result = Self {
            retained,
            original_commit,
            original_disclosure,
            journal: OriginalJournalV1::Financial(journal),
            identity: binding.identity_digest().into(),
            binding: std::sync::Mutex::new(binding),
            recipient,
            immutable,
            lifetime,
            original_ceiling_ms,
            original_deadline,
        };
        result.check_custody()?;
        Ok((result, pending))
    }
    pub(crate) fn check_pending(
        &self,
        pending: &PendingFinancialContinuationAdmissionV1,
    ) -> Result<()> {
        self.check_custody()?;
        match &self.journal {
            OriginalJournalV1::Financial(journal) => Ok(pending.check_current(journal)?),
            _ => Err(Error::RecoveryRequired),
        }
    }
    pub(crate) fn check_read(&self, read: &FinancialReadLeaseV1) -> Result<()> {
        read.check_source(self.identity_digest())?;
        self.check_custody()?;
        read.check_source(self.identity_digest())
    }
    pub(crate) fn check_sign(&self, sign: &FinancialSignActionV1) -> Result<()> {
        sign.check_source(self.identity_digest())?;
        self.check_custody()?;
        if Instant::now() >= self.original_deadline {
            return Err(Error::Locked);
        }
        sign.check_source(self.identity_digest())
    }
}
impl PreparedOriginalFinancialSourceV1 {
    pub(crate) fn require_original_writer_witness(
        &self,
        disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        certificate: &str,
    ) -> Result<()> {
        self.check_custody()?;
        let retained = self.financial_journal()?.retained_continuation()?;
        let terms = retained.terms()?;
        if terms.scope.witness != *disclosure
            || terms.scope.authorization.writer_certificate_digest != certificate
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn continuation_request(&self) -> Result<wholepact_authority::OwnerControlRequest> {
        self.check_custody()?;
        Ok(self
            .financial_journal()?
            .retained_continuation()?
            .request()
            .clone())
    }
    pub(crate) fn prepare_spend(
        &self,
        read: &FinancialReadLeaseV1,
        fixed: Arc<wholepact_protocol::durable_proposal_v1::VerifiedFixedProposal>,
        inputs: crate::manifest::ReviewInputs,
        history:&wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<crate::consent_journal::PreparedFinancialSpendV1> {
        self.check_read(read)?;
        let result = self.financial_journal()?.prepare_financial_spend_v1(
            &*self.binding.lock().map_err(|_| Error::Locked)?,
            read,
            self.retained.account.account(),
            fixed,
            inputs,
            history,
        )?;
        self.check_read(read)?;
        Ok(result)
    }
    // Scoped original-only internals used by the new financial bridge. The
    // wrapper exposes no raw SignerConsentJournal or generic session issuer.
    pub(crate) fn financial_journal(&self) -> Result<&FinancialConsentJournalV1> {
        match &self.journal {
            OriginalJournalV1::Financial(j) => Ok(j),
            _ => Err(Error::RecoveryRequired),
        }
    }
    pub(crate) fn financial_binding(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, FinancialSourceBindingV1>> {
        self.binding.lock().map_err(|_| Error::Locked)
    }
    pub(crate) fn financial_account(&self) -> Result<&crate::account::DedicatedAccount> {
        self.check_custody()?;
        Ok(self.retained.account.account())
    }
}
impl PreparedOriginalFinancialSourceV1 {
    pub(crate) fn require_original_financial_host_v1(
        &self,
        peer: &crate::native_peer::PeerProcess,
    ) -> Result<()> {
        self.check_custody()?;
        peer.check_alive()?;
        let expected = self
            .financial_journal()?
            .original_financial_host_instance_v1(
                &*self.binding.lock().map_err(|_| Error::Locked)?,
            )?;
        let held = self.recipient.lock().map_err(|_| Error::Locked)?;
        let retained = held.as_ref().ok_or(Error::Authentication)?;
        if expected != retained.instance() {
            return Err(Error::Authentication);
        }
        retained.same_live_process(peer)?;
        peer.check_alive()?;
        self.check_custody()
    }
}

impl PreparedOriginalFinancialSourceV1 {
    /// Accept only the original retained pidfd identity, never a newly observed
    /// peer or a deserialized instance label. This grants no effect permission.
    pub(crate) fn bind_original_financial_recipient_v1(
        &self,
        peer: crate::native_peer::PeerProcess,
    ) -> Result<()> {
        self.check_custody()?;
        peer.check_alive()?;
        let expected = self
            .financial_journal()?
            .original_financial_host_instance_v1(
                &*self.binding.lock().map_err(|_| Error::Locked)?,
            )?;
        if expected != peer.instance() {
            return Err(Error::Authentication);
        }
        let mut held = self.recipient.lock().map_err(|_| Error::Locked)?;
        if let Some(existing) = held.as_ref() {
            if existing.instance() != peer.instance() {
                return Err(Error::Authentication);
            }
            existing.same_live_process(&peer)?;
        } else {
            *held = Some(peer);
        }
        Ok(())
    }
}

/// Inert, original-only continuity proof for one already audited result read.
/// It cannot authorize a read, signature, return or mutation and is never
/// refreshed. Only the private prepared Return owner retains this pin.
pub(crate) struct FinancialReturnSourcePinV1 {
    source_identity: String,
    journal: FinancialReturnJournalPinV1,
}
impl PreparedOriginalFinancialSourceV1 {
    pub(crate) fn prepare_financial_return_source_pin_v1(
        &self,
        journal: FinancialReturnJournalPinV1,
        peer: &crate::native_peer::PeerProcess,
    ) -> Result<FinancialReturnSourcePinV1> {
        // The journal pin was issued with the full result/recipient audit in
        // one snapshot. Bind it to the actual retained original pidfd, not a
        // second semantic read or a process reopened from an instance string.
        self.check_retained_financial_peer_v1(peer)?;
        let pin = FinancialReturnSourcePinV1 {
            source_identity: self.identity.clone(),
            journal,
        };
        self.check_financial_return_source_pin_v1(&pin, peer)?;
        self.check_immutable_original_v1()?;
        Ok(pin)
    }
    pub(crate) fn check_financial_return_source_pin_v1(
        &self,
        pin: &FinancialReturnSourcePinV1,
        peer: &crate::native_peer::PeerProcess,
    ) -> Result<()> {
        self.lifetime.check_connected()?;
        if self.identity != pin.source_identity || Instant::now() >= self.original_deadline {
            return Err(Error::Locked);
        }
        if immutable(&self.retained)? != self.immutable {
            return Err(Error::ReviewMismatch);
        }
        self.financial_journal()?
            .check_financial_return_pin_v1(&*self.financial_binding()?, &pin.journal)?;
        {
            let held = self.recipient.lock().map_err(|_| Error::Locked)?;
            let original = held.as_ref().ok_or(Error::Authentication)?;
            if original.instance() != pin.journal.original_host_instance() {
                return Err(Error::Authentication);
            }
            original.same_live_process(peer)?;
        }
        // No journal/peer/binding lock survives this bounded check or crosses
        // a socket wait. Metadata work cannot extend original source lifetime.
        if immutable(&self.retained)? != self.immutable {
            return Err(Error::ReviewMismatch);
        }
        self.lifetime.check_connected()?;
        if Instant::now() >= self.original_deadline {
            return Err(Error::Locked);
        }
        peer.check_alive()?;
        Ok(())
    }
}

/// Inert, nonrefreshing continuity pin for one exact original admission. It is
/// deliberately distinct from the completed-result Return pin: no result need
/// exist yet, and both pending transition and current source identities matter.
/// The fresh Admit owner remains required independently at every callback.
pub(crate) struct FinancialAdmissionSourcePinV1 {
    source_identity: String,
    journal: FinancialAdmissionJournalPinV1,
    disclosure: wholepact_authority::WitnessDisclosureDescriptor,
    certificate_digest: String,
    admission_terms_digest: String,
}
impl FinancialAdmissionSourcePinV1 {
    pub(crate) fn admission_terms_digest(&self) -> &str {
        &self.admission_terms_digest
    }
}
impl PreparedOriginalFinancialSourceV1 {
    pub(crate) fn prepare_financial_admission_source_pin_v1(
        &self,
        pending: &PendingFinancialContinuationAdmissionV1,
        disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        certificate_digest: &str,
    ) -> Result<FinancialAdmissionSourcePinV1> {
        // Full original custody, exact owner certificate/disclosure, and pending
        // intent checks stay at issuance. No ordinary custody checker is relaxed.
        self.check_immutable_original_v1()?;
        if disclosure != &self.original_disclosure
            || certificate_digest
                != self
                    .retained
                    .record
                    .account_record
                    .terms
                    .signer
                    .owner_certificate_digest
        {
            return Err(Error::Authentication);
        }
        let admission_terms_digest = pending.admission_terms_digest(self.identity_digest())?;
        // This issuer audits the actual current and transition bindings together
        // with the immutable pending request in one original read snapshot. The
        // two source digests are intentionally distinct, not interchangeable.
        let journal = self
            .financial_journal()?
            .prepare_financial_admission_pin_v1(&*self.financial_binding()?, pending)?;
        let pin = FinancialAdmissionSourcePinV1 {
            source_identity: self.identity.clone(),
            journal,
            disclosure: disclosure.clone(),
            certificate_digest: certificate_digest.to_owned(),
            admission_terms_digest,
        };
        // Recheck after the read-only transaction commits. A mutation during
        // preflight fails closed; this function never re-pins or retries.
        self.check_financial_admission_source_pin_v1(
            &pin,
            pending,
            disclosure,
            certificate_digest,
        )?;
        self.check_immutable_original_v1()?;
        Ok(pin)
    }
    pub(crate) fn check_financial_admission_source_pin_v1(
        &self,
        pin: &FinancialAdmissionSourcePinV1,
        pending: &PendingFinancialContinuationAdmissionV1,
        disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        certificate_digest: &str,
    ) -> Result<()> {
        self.lifetime.check_connected()?;
        if self.identity != pin.source_identity || Instant::now() >= self.original_deadline {
            return Err(Error::Locked);
        }
        if disclosure != &pin.disclosure || certificate_digest != pin.certificate_digest {
            return Err(Error::Authentication);
        }
        // These are the already fully audited original files, including the
        // original publication/roster records, under retained directory custody.
        if immutable(&self.retained)? != self.immutable {
            return Err(Error::ReviewMismatch);
        }
        self.financial_journal()?.check_financial_admission_pin_v1(
            &*self.financial_binding()?,
            pending,
            &pin.journal,
        )?;
        // No lock is returned or retained over network I/O. Recheck after the
        // bounded metadata/SQLite work so its time cannot extend source life.
        if immutable(&self.retained)? != self.immutable {
            return Err(Error::ReviewMismatch);
        }
        self.lifetime.check_connected()?;
        if Instant::now() >= self.original_deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
}

/// Closed read-only intervals. These tags are not permission and cannot survive
/// an original journal mutation or replace the actual native action owner.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinancialOperationV1 {
    HistoryRead,
    Acquire,
    Activate,
    VerifyActive,
    WalletObserve,
    Reserve,
}
pub(crate) struct FinancialOperationSourcePinV1 {
    source_identity: String,
    operation: FinancialOperationV1,
    journal: crate::consent_journal::FinancialOperationJournalPinV1,
}
impl FinancialOperationSourcePinV1 {
    pub(crate) fn continuation_request(&self) -> &wholepact_authority::OwnerControlRequest {
        self.journal.continuation_request()
    }
    pub(crate) fn terms(&self) -> &FinancialContinuationTermsV1 {
        self.journal.terms()
    }
}
impl PreparedOriginalFinancialSourceV1 {
    pub(crate) fn prepare_financial_operation_source_pin_v1(
        &self,
        operation: FinancialOperationV1,
        witness: Option<(
            bool,
            &wholepact_authority::WitnessDisclosureDescriptor,
            &str,
        )>,
    ) -> Result<FinancialOperationSourcePinV1> {
        if !operation.accepts_witness_role(witness.as_ref().map(|(owner, _, _)| *owner)) {
            return Err(Error::Authentication);
        }
        // The actual opener fully audited the immutable original account and
        // publication. Sample that exact baseline, then audit current journal
        // semantics once in the factory, never reuse across a revision change.
        self.check_immutable_original_v1()?;
        let journal = self
            .financial_journal()?
            .prepare_financial_operation_pin_v1(&*self.financial_binding()?)?;
        if let Some((owner, disclosure, certificate)) = witness {
            let expected_certificate = if owner {
                &self
                    .retained
                    .record
                    .account_record
                    .terms
                    .signer
                    .owner_certificate_digest
            } else {
                &journal
                    .terms()
                    .scope
                    .authorization
                    .writer_certificate_digest
            };
            if journal.terms().scope.witness != *disclosure
                || self.original_disclosure != *disclosure
                || expected_certificate != certificate
            {
                return Err(Error::Authentication);
            }
        }
        let pin = FinancialOperationSourcePinV1 {
            source_identity: self.identity.clone(),
            operation,
            journal,
        };
        self.check_financial_operation_source_pin_v1(&pin, operation)?;
        self.check_immutable_original_v1()?;
        Ok(pin)
    }
    pub(crate) fn check_financial_operation_source_pin_v1(
        &self,
        pin: &FinancialOperationSourcePinV1,
        operation: FinancialOperationV1,
    ) -> Result<()> {
        self.lifetime.check_connected()?;
        if self.identity != pin.source_identity
            || operation != pin.operation
            || Instant::now() >= self.original_deadline
        {
            return Err(Error::Locked);
        }
        if immutable(&self.retained)? != self.immutable {
            return Err(Error::ReviewMismatch);
        }
        self.financial_journal()?
            .check_financial_operation_pin_v1(&*self.financial_binding()?, &pin.journal)?;
        if immutable(&self.retained)? != self.immutable {
            return Err(Error::ReviewMismatch);
        }
        self.lifetime.check_connected()?;
        if Instant::now() >= self.original_deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
    /// Source-owned account borrow after the exact operation pin check. No raw
    /// getter, detached account, or authority is created by this observation.
    pub(crate) fn financial_account_for_operation_v1(
        &self,
        pin: &FinancialOperationSourcePinV1,
        operation: FinancialOperationV1,
    ) -> Result<&crate::account::DedicatedAccount> {
        self.check_financial_operation_source_pin_v1(pin, operation)?;
        Ok(self.retained.account.account())
    }
}

impl FinancialOperationV1 {
    fn accepts_witness_role(self, owner: Option<bool>) -> bool {
        use FinancialOperationV1::*;
        matches!(
            (self, owner),
            (HistoryRead | Activate, Some(true))
                | (Acquire | VerifyActive | Reserve, Some(false))
                | (WalletObserve, None)
        )
    }
}
#[cfg(test)]
mod operation_role_tests {
    use super::FinancialOperationV1::*;
    #[test]
    fn financial_operation_witness_roles_are_closed() {
        for (operation, expected) in [
            (HistoryRead, Some(true)),
            (Acquire, Some(false)),
            (Activate, Some(true)),
            (VerifyActive, Some(false)),
            (WalletObserve, None),
            (Reserve, Some(false)),
        ] {
            for actual in [None, Some(true), Some(false)] {
                assert_eq!(operation.accepts_witness_role(actual), actual == expected);
            }
        }
    }
}

impl PreparedOriginalFinancialSourceV1 {
    /// Only for constructor consolidation around a full current journal audit.
    /// The immutable baseline and disclosure originate in the actual opener.
    pub(crate) fn check_immutable_original_v1(&self) -> Result<()> {
        self.lifetime.check_connected()?;
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Locked)?
                .as_millis(),
        )
        .map_err(|_| Error::Locked)?;
        if now >= self.original_ceiling_ms || Instant::now() >= self.original_deadline {
            return Err(Error::Locked);
        }
        if immutable(&self.retained)? != self.immutable {
            return Err(Error::ReviewMismatch);
        }
        self.lifetime.check_connected()?;
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Locked)?
                .as_millis(),
        )
        .map_err(|_| Error::Locked)?;
        if now >= self.original_ceiling_ms || Instant::now() >= self.original_deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(crate) fn check_retained_financial_peer_v1(
        &self,
        peer: &crate::native_peer::PeerProcess,
    ) -> Result<()> {
        self.check_immutable_original_v1()?;
        peer.check_alive()?;
        {
            let held = self.recipient.lock().map_err(|_| Error::Locked)?;
            held.as_ref()
                .ok_or(Error::Authentication)?
                .same_live_process(peer)?;
        }
        peer.check_alive()?;
        self.check_immutable_original_v1()
    }
}
