//! One-way restrictive owner. Actual born vault and original encrypted journal
//! remain owned throughout review, persistence and retry. No old peer grant or
//! active enrollment/writer capability survives conversion into this type.
pub(crate) mod artifacts;
use super::*;
use crate::consent_journal::PermanentStopSnapshot;
use wholepact_authority::account_use::{ExclusionReason, PermanentAccountExclusion};
use wholepact_authority::account_use_link::{
    reconcile_account_exclusion_complete, AccountExclusionReceipt,
};

pub(crate) struct BornPermanentStopSourceV1 {
    retained: RetainedBornManualRosterEnrollmentV2,
    journal: Arc<SignerConsentJournal>,
    source: NativeAuthorityBinding,
    history: Option<ReconciledAuthorityHistory>,
    epoch: u64,
}
impl BornPermanentStopSourceV1 {
    /// Called only after the UI closes ordinary request admission and drains its
    /// one worker. Shared live enrollment owners are not accepted.
    pub(crate) fn from_enrolled(
        enrolled: Arc<publication::BornManualRosterEnrolledSignerV2>,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        if enrolled.source != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        // The old grant must already be revoked, never revived after transition.
        if enrolled.peer.check_current().is_ok() {
            return Err(Error::Authentication);
        }
        let enrolled = Arc::try_unwrap(enrolled).map_err(|_| Error::Locked)?;
        let epoch = enrolled.journal.account_state()?.writer_epoch;
        let result = Self {
            retained: enrolled.retained,
            journal: enrolled.journal,
            source: owner.native().binding(),
            history: None,
            epoch,
        };
        result.check(owner)?;
        Ok(result)
    }
    /// Existing born-owner unlock is used unchanged. This opens only a completed
    /// V2 enrollment's historical journal; it never installs an ordinary signer.
    pub(crate) fn reopen(
        account: Arc<AccountVault>,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        let retained = account
            .retained_born_manual_roster_enrollment_v2(owner)?
            .ok_or(Error::RecoveryRequired)?;
        publication::read_commit(&retained)?;
        let path = retained.account.directory.root().join(JOURNAL);
        let key = DatabaseKey::from_bytes(*retained.journal_key);
        // The retained original vault is actual born-origin evidence. Every
        // older format must fail before a writable handle, even if the file
        // claims to be pre-genesis; no ordinary migration is permitted here.
        let journal = Arc::new(SignerConsentJournal::open_known_born_encrypted(
            &path,
            &key,
            &retained.record.account_record.genesis,
            &retained.account.directory.signer_journal_source_owner()?,
        )?);
        let epoch = journal.account_state()?.writer_epoch;
        let result = Self {
            retained,
            journal,
            source: owner.native().binding(),
            history: None,
            epoch,
        };
        result.check(owner)?;
        Ok(result)
    }
    pub(crate) fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        self.source.check_current()?;
        self.source.bounded_deadline()?;
        if self.source != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        self.retained.check()?;
        publication::read_commit(&self.retained)?;
        let state = self.snapshot()?;
        if state.writer_epoch != self.epoch {
            return Err(Error::RecoveryRequired);
        }
        self.retained_signature()?;
        self.retained_host_ack()?;
        Ok(())
    }
    pub(crate) fn observe_history(
        &mut self,
        history: ReconciledAuthorityHistory,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        if history.disclosure() != &self.disclosure()? {
            return Err(Error::Authentication);
        }
        original(&self.retained.account)?
            .anchor()
            .audit_historical_witness_link(&history)?;
        self.journal
            .permanent_stop_complete_history(&PermanentStopHistoryPin {
                source: self,
                history: &history,
            })?;
        self.history = Some(history);
        Ok(())
    }
    pub(crate) fn complete_display(&self) -> Result<(PermanentStopSnapshot, serde_json::Value)> {
        self.journal
            .permanent_stop_complete_history(&PermanentStopHistoryPin {
                source: self,
                history: self.history.as_ref().ok_or(Error::RecoveryRequired)?,
            })
            .map_err(Into::into)
    }
    pub(crate) fn host_evidence(
        &self,
        request: &wholepact_signer_origin::permanent_stop_v1::HostPermanentStopRequestV1,
        reviewed_digest: &str,
    ) -> Result<wholepact_signer_origin::permanent_stop_v1::PermanentStopEvidenceV1> {
        request.validate().map_err(|_| Error::InvalidData)?;
        if request.original != self.record().request()? {
            return Err(Error::ReviewMismatch);
        }
        let (state, _) = self.complete_display()?;
        let exclusion = state.exclusion.ok_or(Error::RecoveryRequired)?;
        let receipt = state.witness_ack.ok_or(Error::RecoveryRequired)?;
        let history = self.history.as_ref().ok_or(Error::RecoveryRequired)?;
        let value = wholepact_signer_origin::permanent_stop_v1::PermanentStopEvidenceV1 {
            version: 1,
            request: request.clone(),
            exclusion_operation_id: exclusion.operation_id.clone(),
            exclusion_digest: exclusion.digest().map_err(|_| Error::InvalidData)?,
            original_witness_receipt_digest: receipt.digest().map_err(|_| Error::InvalidData)?,
            original_witness_head_sequence: receipt.committed_head.sequence,
            original_witness_head_digest: receipt.committed_head.digest,
            complete_witness_history_digest: history
                .history_digest()
                .map_err(|_| Error::InvalidData)?,
            native_review_digest: reviewed_digest.into(),
        };
        value.validate().map_err(|_| Error::InvalidData)?;
        Ok(value)
    }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        &self.retained.record.account_record.genesis
    }
    pub(crate) fn record(&self) -> &BornManualRosterEnrollmentRecordV2 {
        &self.retained.record
    }
    pub(crate) fn snapshot(&self) -> Result<PermanentStopSnapshot> {
        self.journal
            .permanent_stop_snapshot(self.genesis())
            .map_err(Into::into)
    }
    pub(crate) fn exclusion(&self) -> Result<PermanentAccountExclusion> {
        self.snapshot()?.exclusion.ok_or(Error::RecoveryRequired)
    }
    pub(crate) fn native_binding(&self) -> &NativeAuthorityBinding {
        &self.source
    }
    pub(crate) fn disclosure(&self) -> Result<wholepact_authority::WitnessDisclosureDescriptor> {
        self.retained.disclosure()
    }
    pub(crate) fn accept_witness_history(
        &self,
        history: &ReconciledAuthorityHistory,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<AccountExclusionReceipt> {
        self.check(owner)?;
        let exclusion = self.exclusion()?;
        let origin = original(&self.retained.account)?;
        let audit = origin.anchor().audit_historical_witness_link(history)?;
        if audit.permanent_exclusion() != Some(&exclusion) {
            return Err(Error::ReviewMismatch);
        }
        let receipt = reconcile_account_exclusion_complete(
            history,
            self.genesis(),
            &self.disclosure()?,
            &exclusion,
        )
        .map_err(|_| Error::Authentication)?;
        let (before, _) =
            self.journal
                .permanent_stop_complete_history(&PermanentStopHistoryPin {
                    source: self,
                    history,
                })?;
        let _native = self.source.publication_lease()?;
        self.check(owner)?;
        let publication = PermanentStopWitnessAcknowledgment {
            source: self,
            before,
            receipt: &receipt,
        };
        self.journal
            .retain_permanent_stop_witness_ack(&publication)?;
        Ok(receipt.evidence().clone())
    }
}

/// Borrow of the exact retained born vault and independently replayed history.
/// Only this actual source module can construct it. It is neither serializable
/// nor an active writer/recovery/financial capability.
pub(crate) struct PermanentStopHistoryPin<'a> {
    source: &'a BornPermanentStopSourceV1,
    history: &'a ReconciledAuthorityHistory,
}
impl PermanentStopHistoryPin<'_> {
    pub(crate) fn check_current(&self, journal: &SignerConsentJournal) -> Result<()> {
        if !std::ptr::eq(journal, Arc::as_ptr(&self.source.journal)) {
            return Err(Error::ReviewMismatch);
        }
        self.source.source.check_current()?;
        self.source.source.bounded_deadline()?;
        self.source.retained.check()?;
        publication::read_commit(&self.source.retained)?;
        if self.history.disclosure() != &self.source.disclosure()? {
            return Err(Error::Authentication);
        }
        original(&self.source.retained.account)?
            .anchor()
            .audit_historical_witness_link(self.history)?;
        Ok(())
    }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        self.source.genesis()
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.source.epoch
    }
    pub(crate) fn history(&self) -> &ReconciledAuthorityHistory {
        self.history
    }
}

pub(crate) struct PreparedBornPermanentStopV1 {
    source: BornPermanentStopSourceV1,
    before: PermanentStopSnapshot,
    exclusion: PermanentAccountExclusion,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedBornPermanentStopV1 {
    pub(crate) fn prepare(
        source: BornPermanentStopSourceV1,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.check(owner)?;
        let (before, complete_history) = match source.history.as_ref() {
            Some(_) => source.complete_display()?,
            None => source
                .journal
                .permanent_stop_local_review(source.genesis())?,
        };
        let operation_id = format!(
            "permanent-stop-{}",
            source.genesis().digest().map_err(|_| Error::InvalidData)?
        );
        let digest = canonical(
            "wholepact:native-born-permanent-stop-review:v1",
            &(
                source.record(),
                &before,
                &operation_id,
                owner.native().principal_id(),
                owner.native().measurement(),
                hex::encode(vault::random::<32>()?),
            ),
        )?;
        // Retry keeps the first operation AND native review, even when this new
        // native review has a fresh focus-bound nonce.
        let exclusion = before
            .exclusion
            .clone()
            .unwrap_or(PermanentAccountExclusion {
                version: 1,
                identity: source.genesis().identity.clone(),
                genesis_digest: source.genesis().digest().map_err(|_| Error::InvalidData)?,
                operation_id,
                native_review_digest: digest.clone(),
                reason: ExclusionReason::RetirementRequested,
            });
        exclusion.validate().map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "PERMANENTLY STOP ROUTINE REUSE OF THIS EXACT BORN ACCOUNT\n\n{}\n\nOriginal retained local state:\n{}\n\nComplete retained local exposure (remote exposure is UNKNOWN unless an independent full witness read is included):\n{}\n\nThis writes the local permanent restriction FIRST and can proceed without witness connectivity. It precedes witness or Host publication. A disconnect or later failure cannot undo it. Pending authorizations and reservations, construction holds, consumed capacity and all observation/recovery records remain. Counts are retained record counts, not an empty-account or complete-exposure claim. Remote witness and named Host propagation remain pending until their exact original acknowledgments are retained. No funds are moved, no future sweep is authorized, and a disclosed viewing key cannot be revoked.\n\nExact native review: {}",
            serde_json::to_string_pretty(&exclusion).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&before).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&complete_history).map_err(|_| Error::InvalidData)?, digest,
        ));
        Ok(Self {
            source,
            before,
            exclusion,
            digest,
            display,
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.source.source.check_current()?;
        Ok(self.display.to_string())
    }
    pub(crate) fn approve_and_retain(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<BornPermanentStopSourceV1> {
        self.source.check(owner)?;
        if decision.binding() != &self.source.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let publication = LocalPermanentStopPublication {
            prepared: &self,
            _native: self.source.source.publication_lease()?,
        };
        self.source.journal.retain_permanent_stop(&publication)?;
        drop(publication);
        Ok(self.source)
    }
}
pub(crate) struct LocalPermanentStopPublication<'a> {
    prepared: &'a PreparedBornPermanentStopV1,
    _native: crate::native_ui::NativePublicationLease<'a>,
}
impl LocalPermanentStopPublication<'_> {
    pub(crate) fn check_current(&self, journal: &SignerConsentJournal) -> Result<()> {
        if !std::ptr::eq(journal, Arc::as_ptr(&self.prepared.source.journal)) {
            return Err(Error::ReviewMismatch);
        }
        self.prepared.source.source.check_current()?;
        self.prepared.source.retained.check()
    }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        self.prepared.source.genesis()
    }
    pub(crate) fn exclusion(&self) -> &PermanentAccountExclusion {
        &self.prepared.exclusion
    }
    pub(crate) fn expected_snapshot(&self) -> &PermanentStopSnapshot {
        &self.prepared.before
    }
}

/// The actual original source plus independently reconciled exact receipt.
/// No deserialized acknowledgment can construct this publication owner.
pub(crate) struct PermanentStopWitnessAcknowledgment<'a> {
    source: &'a BornPermanentStopSourceV1,
    before: PermanentStopSnapshot,
    receipt: &'a wholepact_authority::account_use_link::ReconciledAccountExclusion,
}
impl PermanentStopWitnessAcknowledgment<'_> {
    pub(crate) fn check_current(&self, journal: &SignerConsentJournal) -> Result<()> {
        if !std::ptr::eq(journal, Arc::as_ptr(&self.source.journal)) {
            return Err(Error::ReviewMismatch);
        }
        self.source.source.check_current()?;
        self.source.retained.check()
    }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        self.source.genesis()
    }
    pub(crate) fn expected_snapshot(&self) -> &PermanentStopSnapshot {
        &self.before
    }
    pub(crate) fn receipt(
        &self,
    ) -> &wholepact_authority::account_use_link::ReconciledAccountExclusion {
        self.receipt
    }
}
