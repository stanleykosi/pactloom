//! Purpose-bound continuation of the genuinely consumed original construction.
//! This is not an ordinary account opener, DTO conversion, or financial permit.
mod dormant;
use super::*;
use crate::consent_journal::{SignerConsentSession, TrustedSignerLaunch};
use crate::native_ui::AuthenticatedPairing;
pub(crate) use dormant::{DormantConsumedBornNamedSourceV1, FreshConsumedBornNamedJournalReopenV1};
use wholepact_authority::born_offline_construction_v1::BornOfflineConstructionOriginV1;
use wholepact_signer_origin::common_context_reentry_v1::RosterReenteredConstructionEvidenceV1;

pub(crate) struct ConsumedBornNamedSourceV1 {
    retained: RetainedBornManualRosterEnrollmentV2,
    journal: Arc<SignerConsentJournal>,
    files: OriginalSourceIdentity,
    native: NativeAuthorityBinding,
    host: crate::native_peer::PeerProcess,
    lifetime: crate::native_ui::DormantNativeLifetime,
    construction: BornOfflineConstructionOriginV1,
    evidence: RosterReenteredConstructionEvidenceV1,
}
impl FreshCommonContextReentrySource {
    /// The actual consumed producer calls this only AFTER its immutable consumed
    /// audit commit. A caller's evidence is compared with those complete rows;
    /// the actual source itself is consumed and cannot perform another read.
    pub(crate) fn into_named_recipient_after_consumed(
        self,
        evidence: RosterReenteredConstructionEvidenceV1,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ConsumedBornNamedSourceV1> {
        self.check(owner)?;
        let construction = self.journal.born_named_construction_origin_v1(
            &self.retained.record.account_record.genesis,
            self.retained
                .record
                .account_record
                .terms
                .signer
                .writer_epoch,
            &evidence,
        )?;
        if construction.extension != self.retained.record.extension()?
            || evidence.reentry_lineage.request.original_read != self.original_read().request
        {
            return Err(Error::ReviewMismatch);
        }
        let result = ConsumedBornNamedSourceV1 {
            retained: self.retained,
            journal: self.journal,
            files: self.dormant.origin.source,
            native: self.native,
            host: self.dormant.origin.host,
            lifetime: self.dormant.origin.lifetime,
            construction,
            evidence,
        };
        result.check(owner)?;
        Ok(result)
    }
}
impl ConsumedBornNamedSourceV1 {
    pub(crate) fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        self.native.check_current()?;
        self.host.check_alive().map_err(|_| Error::Authentication)?;
        self.lifetime.check_connected()?;
        if owner.native().binding() != self.native {
            return Err(Error::ReviewMismatch);
        }
        self.retained.check_current_source(owner)?;
        self.files.check_opened(&self.retained)?;
        check_original_retention(&self.retained, &self.evidence)?;
        let actual = self.journal.born_named_construction_origin_v1(
            &self.retained.record.account_record.genesis,
            self.retained
                .record
                .account_record
                .terms
                .signer
                .writer_epoch,
            &self.evidence,
        )?;
        if actual != self.construction {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    /// Restriction-only liveness while the actual checked local-record lease is
    /// held for a separately approved named-verifier disclosure. This does not
    /// reacquire the journal or session locks and cannot replace `check` before
    /// acquiring, or after releasing, that lease. No authority is returned.
    pub(crate) fn check_disclosure_liveness(
        &self,
        owner: &PendingAccountNativeAuthority,
        lease: &crate::consent_journal::PreconstructionRecordLease<'_>,
    ) -> Result<()> {
        lease.require_journal(&self.journal.binding())?;
        lease.require_native_origin(&self.native)?;
        lease.check_current()?;
        owner.check_current()?;
        self.native.check_current()?;
        self.host.check_alive().map_err(|_| Error::Authentication)?;
        self.lifetime.check_connected()?;
        if owner.native().binding() != self.native {
            return Err(Error::ReviewMismatch);
        }
        let terms = &self.retained.record.account_record.terms;
        let genesis = self.genesis();
        let proposal = self
            .construction
            .reservation
            .request
            .construction
            .plan
            .validate()
            .map_err(|_| Error::InvalidData)?;
        let enrollment = lease.enrollment();
        let manifest = lease.manifest();
        if enrollment.account_id() != genesis.identity.account_id
            || enrollment.account_fvk_digest() != genesis.identity.full_viewing_key_digest
            || enrollment.agreement_id() != terms.scope.agreement_id
            || enrollment.participant_id() != terms.scope.participant_id
            || enrollment.budget_limit_zatoshis() != terms.scope.aggregate_budget_zatoshis
            || enrollment.receipt().writer_epoch != terms.signer.writer_epoch
            || manifest.enrollment_ref() != enrollment.reference()
            || manifest.proposal_input() != proposal.input()
            || manifest.receipt().writer_epoch != terms.signer.writer_epoch
        {
            return Err(Error::ReviewMismatch);
        }
        self.retained.check_current_source(owner)?;
        self.files.check_opened(&self.retained)?;
        check_original_retention(&self.retained, &self.evidence)?;
        self.host.check_alive().map_err(|_| Error::Authentication)?;
        self.lifetime.check_connected()?;
        self.native.check_current()?;
        owner.check_current()?;
        lease.check_current()?;
        Ok(())
    }
    pub(crate) fn check_pairing(
        &self,
        pairing: &AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        pairing.check_current()?;
        let peer = pairing.current_peer();
        self.host
            .same_live_process(&peer.peer)
            .map_err(|_| Error::Authentication)?;
        let t = &self.retained.record.account_record.terms;
        let proposal = self
            .construction
            .reservation
            .request
            .construction
            .plan
            .validate()
            .map_err(|_| Error::InvalidData)?;
        if pairing.native_origin() != &self.native
            || peer.scope.account_id != t.identity.account_id
            || peer.scope.agreement_id != t.scope.agreement_id
            || peer.scope.participant_id != t.scope.participant_id
            || peer.scope.manifest_digest != proposal.manifest_digest()
            || !peer.scope.history_read
            || peer.scope.authorization_export
            || peer.scope.preconstruction_export
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    /// A separately and genuinely paired exact proposal is required. The old
    /// construction-plan pairing cannot be reinterpreted as this local scope.
    pub(crate) fn local_consent_session(
        &self,
        pairing: &AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Arc<SignerConsentSession>> {
        self.check_pairing(pairing, owner)?;
        let launch = TrustedSignerLaunch::from_native(
            owner.native(),
            &self.journal,
            self.retained.account.account(),
            pairing,
        )?;
        let session = Arc::new(SignerConsentSession::from_trusted_launch(launch)?);
        self.check_pairing(pairing, owner)?;
        Ok(session)
    }
    /// Reuses only the exact already-retained pair after fresh actual pairing.
    /// A partial enrollment is not converted to a new-native manifest scope.
    pub(crate) fn local_records(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<(
        Option<crate::consent_journal::AccountEnrollmentRecord>,
        Option<crate::consent_journal::AcceptedManifestRecord>,
    )> {
        self.check(owner)?;
        let records = self.journal.consumed_born_named_local_records_v1(
            self.genesis(),
            self.retained
                .record
                .account_record
                .terms
                .signer
                .writer_epoch,
            &self.evidence,
            &self.construction,
        )?;
        self.check(owner)?;
        Ok(records)
    }
    pub(crate) fn original_witness_disclosure(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<wholepact_authority::WitnessDisclosureDescriptor> {
        self.check(owner)?;
        let disclosure = self.retained.disclosure()?;
        self.check(owner)?;
        Ok(disclosure)
    }
    pub(crate) fn construction(&self) -> &BornOfflineConstructionOriginV1 {
        &self.construction
    }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        &self.retained.record.account_record.genesis
    }
    pub(crate) fn journal(&self) -> &Arc<SignerConsentJournal> {
        &self.journal
    }
    pub(crate) fn vault(&self) -> &Arc<AccountVault> {
        &self.retained.account
    }
    pub(crate) fn native_binding(&self) -> &NativeAuthorityBinding {
        &self.native
    }
}

impl ConsumedBornNamedSourceV1 {
    pub(crate) fn check_pending_pairing(
        &self,
        pair: &crate::ipc::PendingPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        pair.same_live_process(&self.host)?;
        let t = &self.construction.extension.account_extension.terms;
        let proposal = self
            .construction
            .reservation
            .request
            .construction
            .plan
            .validate()
            .map_err(|_| Error::InvalidData)?;
        if pair.scope.account_id != t.identity.account_id
            || pair.scope.agreement_id != t.scope.agreement_id
            || pair.scope.participant_id != t.scope.participant_id
            || pair.scope.manifest_digest != proposal.manifest_digest()
            || !pair.scope.history_read
            || pair.scope.authorization_export
            || pair.scope.preconstruction_export
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}

/// Retained ciphertext must still be the actual original read's evidence, not
/// merely a newly captured file with a syntactically valid retention filename.
fn check_original_retention(
    retained: &RetainedBornManualRosterEnrollmentV2,
    evidence: &RosterReenteredConstructionEvidenceV1,
) -> Result<()> {
    let read = &evidence.reentry_lineage.request.original_read;
    crate::account::birth::enrollment::roster_v2::retention::read_exact_with_ciphertext_digest(
        retained,
        &read.plan.retained,
        &read.plan.retained_evidence_digest,
        &read.original_durable_receipt_digest,
    )?;
    Ok(())
}

impl ConsumedBornNamedSourceV1 {
    /// Exact original read and admission, borrowed only from the genuine
    /// consumed lineage after complete source/journal validation. No owner.
    pub(crate) fn original_common_context_read(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<(
        &wholepact_core::manual_roster_construction_v3::RosterCommonContextReadRequestV1,
        &str,
    )> {
        self.check(owner)?;
        let original = &self.evidence.reentry_lineage.request;
        Ok((
            &original.original_read,
            &original.original_read_admission_digest,
        ))
    }
}
