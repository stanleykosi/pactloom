//! Fresh native access to an ORIGINAL born/manual account and its complete
//! existing journal. Historical enrollment is an account association, never a
//! restored process, writer session, native approval or signing capability.
//!
//! In particular this entry does not consume a V3 dormant token, require the
//! former Host process to remain alive, or call the empty-journal initial-owner
//! gate. Old reservations and uncertain results remain in the same journal.
use super::*;
use crate::consent_journal::OriginalAuthorizationLease;
use crate::native_ui::PendingAccountNativeAuthority;
use wholepact_authority::account_use::AccountUseGenesis;

/// Finite failure locations only: no paths, private data or OS error strings.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableEntryFailureStageV1 {
    NativeOwnerCheck,
    VaultOpen,
    RetainedEnrollment,
    OriginalCommit,
    JournalOpen,
    SourceCheck,
    RuntimeActivation,
    WorkerResult,
    EndpointCreate,
    EndpointBind,
    EndpointPublish,
    PostEndpointSourceCheck,
}
pub(crate) type DurableEntryOpenResultV1<T> =
    std::result::Result<T, (DurableEntryFailureStageV1, Error)>;

/// An actual locked original vault with a fresh genuine native owner. There is
/// deliberately no Clone, Deserialize, from-record factory, key accessor,
/// activation flag, writer-session conversion or authorization conversion.
pub(crate) struct FreshDurableBornEntryV1 {
    retained: RetainedBornManualRosterEnrollmentV2,
    original_commit: publication::BornManualRosterCommitV2,
    journal: Arc<SignerConsentJournal>,
    owner: Arc<PendingAccountNativeAuthority>,
}

impl FreshDurableBornEntryV1 {
    /// Opens existing authenticated originals only. Missing enrollment, commit
    /// or journal is recovery-required, never permission to initialize a new
    /// account, choose another journal key, or replace historical evidence.
    pub(crate) fn open(
        root: &Path,
        password: &[u8],
        owner: Arc<PendingAccountNativeAuthority>,
    ) -> Result<Self> {
        Self::open_diagnosed(root, password, owner).map_err(|(_, error)| error)
    }

    /// The same opener, with its actual error and finite location preserved.
    /// This never retries, repairs, skips or converts an original refusal.
    pub(crate) fn open_diagnosed(
        root: &Path,
        password: &[u8],
        owner: Arc<PendingAccountNativeAuthority>,
    ) -> DurableEntryOpenResultV1<Self> {
        let mut stage = DurableEntryFailureStageV1::NativeOwnerCheck;
        let result = (|| -> Result<Self> {
            owner.check_current()?;
            owner.native().binding().bounded_deadline()?;

            // Existing purpose-specific opener: actual directory lock,
            // authenticated original envelope/account and complete inventory.
            // No activation or spending-key access is created.
            stage = DurableEntryFailureStageV1::VaultOpen;
            let account = Arc::new(AccountVault::unlock_born_for_manual_roster_enrollment_v2(
                root, password, &owner,
            )?);
            stage = DurableEntryFailureStageV1::RetainedEnrollment;
            let retained = account
                .retained_born_manual_roster_enrollment_v2(&owner)?
                .ok_or(Error::RecoveryRequired)?;
            retained.check_current_source(&owner)?;
            if !account.directory.exists(ROSTER_COMMIT)? || !account.directory.exists(JOURNAL)? {
                return Err(Error::RecoveryRequired);
            }

            // Historical evidence is never a current native/process owner.
            stage = DurableEntryFailureStageV1::OriginalCommit;
            let original_commit = publication::read_commit(&retained)?;
            let genesis = &retained.record.account_record.genesis;
            let key = DatabaseKey::from_bytes(*retained.journal_key);
            stage = DurableEntryFailureStageV1::JournalOpen;
            let journal = Arc::new(SignerConsentJournal::open_durable_born_entry_v1(
                &account.directory.root().join(JOURNAL),
                &key,
                genesis,
            )?);
            let result = Self {
                retained,
                original_commit,
                journal,
                owner,
            };
            stage = DurableEntryFailureStageV1::SourceCheck;
            result.check_current()?;
            Ok(result)
        })();
        result.map_err(|error| (stage, error))
    }

    /// Rechecks real native/parent lifetime, the held ORIGINAL source and the
    /// exact existing journal. No callback flag or historic receipt substitutes
    /// for these checks. Callers must separately hold their current native and
    /// journal publication fences across any immediate consequential action.
    pub(crate) fn check_current(&self) -> Result<()> {
        self.check_original_source_current()?;
        self.journal.check_durable_born_entry_v1(self.genesis())?;
        self.owner.check_current()?;
        Ok(())
    }

    /// Rechecks only the actual native/vault/immutable-original source. It takes
    /// no journal authority lock, so an immutable data callback can use it while
    /// the specialized adapter separately checks the held authorization lease.
    /// This is deliberately not sufficient journal or spending authority.
    pub(crate) fn check_original_source_current(&self) -> Result<()> {
        self.owner.check_current()?;
        self.owner.native().binding().bounded_deadline()?;
        self.retained.check_current_source(&self.owner)?;
        if publication::read_commit(&self.retained)? != self.original_commit {
            return Err(Error::ReviewMismatch);
        }
        self.owner.check_current()?;
        Ok(())
    }

    /// Reuses the existing authorization read fence. Taking another normal
    /// journal read lock here can deadlock behind a queued revocation writer.
    pub(crate) fn check_current_under_lease(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
    ) -> Result<()> {
        self.check_original_source_current()?;
        lease.require_native_origin(&self.native_binding())?;
        self.journal
            .check_durable_born_entry_v1_under_lease(self.genesis(), lease)?;
        self.owner.check_current()?;
        Ok(())
    }

    /// Same actual vault/journal identities, while preserving the held fence.
    pub(crate) fn require_authorization_identity(
        &self,
        account: &crate::account::DedicatedAccount,
        journal: &SignerConsentJournal,
        lease: &OriginalAuthorizationLease<'_>,
    ) -> Result<()> {
        if !std::ptr::eq(self.account(), account) || !std::ptr::eq(self.journal.as_ref(), journal) {
            return Err(Error::Authentication);
        }
        self.check_current_under_lease(lease)
    }

    /// Account access remains private to the concrete native composition. The
    /// existing born flag and ordinary spending-key refusal are unchanged.
    pub(crate) fn vault(&self) -> &Arc<AccountVault> {
        &self.retained.account
    }

    pub(crate) fn account(&self) -> &crate::account::DedicatedAccount {
        self.retained.account.account()
    }

    /// Equal public account identifiers do not transfer this actual source to
    /// another account instance, copied vault, or deserialized account record.
    pub(crate) fn require_account_identity(
        &self,
        account: &crate::account::DedicatedAccount,
    ) -> Result<()> {
        if !std::ptr::eq(self.account(), account) {
            return Err(Error::Authentication);
        }
        self.check_current()
    }

    pub(crate) fn journal(&self) -> &Arc<SignerConsentJournal> {
        &self.journal
    }

    /// A matching genesis or pathname is not enough: the immediate action must
    /// use this exact freshly opened journal and its held database identity.
    pub(crate) fn require_journal_identity(&self, journal: &SignerConsentJournal) -> Result<()> {
        if !std::ptr::eq(self.journal.as_ref(), journal) {
            return Err(Error::Authentication);
        }
        self.check_current()
    }

    pub(crate) fn native_owner(&self) -> &Arc<PendingAccountNativeAuthority> {
        &self.owner
    }

    pub(crate) fn native_binding(&self) -> NativeAuthorityBinding {
        self.owner.native().binding()
    }

    pub(crate) fn record(&self) -> &BornManualRosterEnrollmentRecordV2 {
        &self.retained.record
    }

    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        &self.retained.record.account_record.genesis
    }

    /// Complete ORIGINAL V2 policy evidence, not a current approval or a
    /// spending capability. Legacy births have no such preimage and remain
    /// refused; a caller cannot supply or attach a replacement descriptor.
    ///
    /// This accessor deliberately takes no journal authority lock, so the
    /// specialized adapter can use it while separately holding and checking
    /// the exact original authorization lease. Native/vault/source checks are
    /// still fresh on both sides of this historical projection.
    pub(crate) fn original_recipient_policy_export_v2(
        &self,
    ) -> Result<crate::account::birth::recipient_policy_v2::OriginalRecipientPolicyExportV2> {
        self.check_original_source_current()?;
        let original = super::original(&self.retained.account)?;
        original.validate_at_rest(self.account())?;
        let origin = original.anchor().complete_policy_origin_v2()?;
        let genesis = self.genesis();
        if original.anchor().expected_account_use_genesis()? != *genesis
            || origin.birth_digest != genesis.native_birth_digest
            || origin.intent.identity.account_id != genesis.identity.account_id
            || origin.intent.identity.full_viewing_key_digest
                != genesis.identity.full_viewing_key_digest
            || origin.intent.identity.network_profile_id != genesis.identity.network_profile_id
            || origin.intent.identity.derivation_domain != genesis.identity.derivation_domain
        {
            return Err(Error::ReviewMismatch);
        }
        self.record()
            .extension()?
            .validate_original_birth(original.witness_commit())
            .map_err(|_| Error::ReviewMismatch)?;
        // Reuse the maintained complete export validator, including exact
        // birth operation, generation, policy-terms digest and witness commit.
        let export = self
            .retained
            .original_recipient_policy_export_v2(&self.owner)?;
        export.validate()?;
        self.check_original_source_current()?;
        Ok(export)
    }

    /// The original independently selected witness endpoint/policy remains
    /// fixed. This descriptor is data, not a live TLS owner or writer session.
    pub(crate) fn original_witness_disclosure(
        &self,
    ) -> Result<wholepact_authority::WitnessDisclosureDescriptor> {
        self.check_current()?;
        let disclosure = self.retained.disclosure()?;
        self.check_current()?;
        Ok(disclosure)
    }
}
