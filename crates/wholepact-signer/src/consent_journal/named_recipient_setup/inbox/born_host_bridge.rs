//! Read-only held original born records for the explicitly reviewed Host bridge.
//! No public DTO can construct this owner or become a signer/witness permit.
use super::super::super::named_recipient_records::{
    NamedRecipientResultRecordV1, NamedRecipientStartedRecordV1,
};
use super::*;
use crate::authority_bridge::{
    BridgeError,
    born_history_ipc::{BornOriginalHistoryEvidenceV1, BornOriginalHistoryRequestV1},
};
use wholepact_authority::AuthorityClient;
pub(crate) struct HeldBornHostHistoryV1<'a> {
    records: PreconstructionRecordLease<'a>,
    pub(crate) evidence: BornOriginalHistoryEvidenceV1,
    pub(crate) original: NamedRecipientOriginalRecordV1,
    source: NativeAuthorityBinding,
    journal: SignerJournalBinding,
}
impl HeldBornHostHistoryV1<'_> {
    pub(crate) fn check_journal(
        &self,
        journal: &SignerConsentJournal,
    ) -> crate::authority_bridge::Result<()> {
        self.records.require_journal(&journal.binding())?;
        if self.journal != journal.binding() {
            return Err(BridgeError::Binding);
        }
        self.check_current()
    }
    pub(crate) fn check_current(&self) -> crate::authority_bridge::Result<()> {
        self.source
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        self.records.check_current()?;
        Ok(())
    }
}
impl LiveNamedRecipientProfile {
    pub(crate) fn acquire_born_host_history<'a>(
        &self,
        journal: &'a SignerConsentJournal,
        session: &'a SignerConsentSession,
        client: &AuthorityClient,
        request: &BornOriginalHistoryRequestV1,
        deadline: Instant,
        mut current: impl FnMut() -> crate::authority_bridge::Result<()>,
    ) -> crate::authority_bridge::Result<HeldBornHostHistoryV1<'a>> {
        let fail = |_| BridgeError::Binding;
        request.validate()?;
        current()?;
        require_profile_owner(self, journal).map_err(fail)?;
        let (profile, retained) =
            load_profile_and_original(journal, self, &request.expected_original_ref)
                .map_err(fail)?;
        let original = retained.record;
        let origin = original.born_origin.as_ref().ok_or(BridgeError::Binding)?;
        if original.terms.authorization_id != request.authorization_id
            || origin.digest()? != request.expected_born_origin_digest
        {
            return Err(BridgeError::Binding);
        }
        let records = journal.acquire_preconstruction_records(
            &profile.enrollment_ref,
            &profile.manifest_ref,
            session,
        )?;
        records.require_native_origin(&self.source)?;
        if records.sponsor_required() || records.sponsor_policy().is_some() {
            return Err(BridgeError::Permission);
        }
        let started = {
            let c = journal
                .connection
                .lock()
                .map_err(|_| BridgeError::Journal(JournalError::Database))?;
            origin.require_actual_signer(&c, &profile, records.enrollment())?;
            origin.checkpoint_receipt.require_retained(&c)?;
            let raw: String = c
                .query_row(
                    "SELECT payload FROM signer_named_recipient_started WHERE authorization_id=?1",
                    [&request.authorization_id],
                    |r| r.get(0),
                )
                .map_err(JournalError::from)?;
            let started: NamedRecipientStartedRecordV1 = decode(raw)?;
            started.validate(&original)?;
            let review = started
                .born_final_review
                .as_ref()
                .ok_or(BridgeError::Binding)?;
            review.validate_profile(&profile, &original)?;
            review.admission_receipt.require_retained(&c)?;
            let raw: String = c
                .query_row(
                    "SELECT payload FROM signer_named_recipient_results WHERE authorization_id=?1",
                    [&request.authorization_id],
                    |r| r.get(0),
                )
                .map_err(JournalError::from)?;
            let result: NamedRecipientResultRecordV1 = decode(raw)?;
            result.validate(&started, &original)?;
            if result.encrypted_return.is_none() {
                return Err(BridgeError::Missing);
            }
            started
        };
        let history = client.reconcile_history_checked_until(deadline, || {
            current().map_err(|_| wholepact_authority::AuthorityError::Permission)
        })?;
        let admission =
            super::born_original_history::authenticate_admission(self, &original, &history, client)
                .map_err(fail)?;
        let evidence = BornOriginalHistoryEvidenceV1 {
            account_policy: history.account_policy().clone(),
            witness: history.disclosure().clone(),
            head: history.snapshot().head.clone(),
            history_digest: history.history_digest()?,
            construction: history
                .born_offline_construction_origin_v1(&admission.request.construction_link)?,
            admission,
            enrollment: origin.enrollment.clone(),
            artifacts: origin.artifacts.clone(),
            manual_extension: origin.manual_extension().clone(),
            original_ref: original.reference.clone(),
            born_origin_digest: origin.digest()?,
            retained_final_native_review_digest: started.native_review_digest,
        };
        evidence.matches(request)?;
        current()?;
        let held = HeldBornHostHistoryV1 {
            records,
            evidence,
            original,
            source: self.source.clone(),
            journal: journal.binding(),
        };
        held.check_current()?;
        Ok(held)
    }
}
