//! New nominal coordinated issuer, joined only to actual original SignRead and
//! SignExact Finals. Native spend owners are neither accepted nor manufactured.
use super::*;
use std::time::Instant;
use wholepact_financial_coordinator_origin::{
    SignerSignReadFinalV1, SignerSignReadPresentationV1, SignerSignExactFactsV1,
    SignerSignExactPresentationV1, SignerSignExactFinalV1,
};

pub(crate) struct PreparedCoordinatedFinancialSpendV1 {
    prepared: PreparedFinancialSpendV1,
    read: SignerSignReadPresentationV1,
    source_revision: FinancialJournalRevisionV1,
    history_digest: String,
    snapshot_json: String,
    active_receipt_json: String,
    authenticated_fvk: orchard::keys::FullViewingKey,
    original_source: Instant,
    original_service: Instant,
    original_writer: Instant,
}
pub(crate) struct PresentedCoordinatedFinancialSpendV1 {
    prepared: PreparedCoordinatedFinancialSpendV1,
    presentation: SignerSignExactPresentationV1,
    original_sign: Instant,
}
pub(crate) struct ApprovedCoordinatedFinancialSpendConsentV1 {
    prepared: PreparedCoordinatedFinancialSpendV1,
    record: OriginalSpendConsent,
    presentation: SignerSignExactPresentationV1,
    action: SignerSignExactFinalV1,
    original_sign: Instant,
}
impl FinancialConsentJournalV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_coordinated_financial_spend_v1(
        &self, source: &FinancialSourceBindingV1, read: &SignerSignReadFinalV1,
        account: &DedicatedAccount, fixed: Arc<VerifiedFixedProposal>, inputs: ReviewInputs,
        observed_fvk: &orchard::keys::FullViewingKey,
        history: &wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        active: &wholepact_authority::AuthenticatedWriterSession,
    ) -> Result<PreparedCoordinatedFinancialSpendV1> {
        read.check_current().map_err(|_| JournalError::Permission)?;
        let p = read.presentation();
        p.validate().map_err(|_| JournalError::InvalidBinding)?;
        let original = &p.facts.original.activation.facts.original;
        if original.source_identity_digest != source.identity_digest()
            || p.facts.original.activated.session_id != active.receipt().session_id
            || history.snapshot().active_writer_session.as_ref() != Some(active.receipt())
            || history.snapshot().pending_writer_session.is_some()
            || history.snapshot().head.digest != p.facts.original.activated.head_digest
            || history.snapshot().head.sequence != p.facts.original.activated.head_sequence
        { return Err(JournalError::InvalidBinding); }
        history.require_financial_continuation_session_v1(&history.continuation_request().operation_id, active)
            .map_err(|_| JournalError::InvalidBinding)?;
        let source_revision = FinancialJournalRevisionV1 {
            data_version: source.revision.data_version,
            total_changes: source.revision.total_changes,
            schema_version: source.revision.schema_version,
            user_version: source.revision.user_version,
        };
        let prepared = self.prepare_financial_spend_data_v1(
            source, account, fixed, inputs, history,
            &FinancialSpendPreparationGuardV1::Coordinated(read, observed_fvk),
        )?;
        read.check_current().map_err(|_| JournalError::Permission)?;
        if source.revision != source_revision { return Err(JournalError::Conflict); }
        let observed = &p.facts.observed;
        let snapshot = &prepared.terms.wallet_snapshot;
        if observed.tip_height != snapshot.tip_height || observed.tip_hash != snapshot.tip_hash
            || observed.anchor_height != snapshot.anchor_height || observed.anchor_hash != snapshot.anchor_hash
            || observed.anchor_root != snapshot.anchor_root
            || usize::try_from(observed.input_count).map_err(|_| JournalError::InvalidBinding)? != prepared.terms.input_bindings.len()
        { return Err(JournalError::InvalidBinding); }
        Ok(PreparedCoordinatedFinancialSpendV1 {
            prepared, read: p.clone(), source_revision,
            authenticated_fvk: observed_fvk.clone(),
            history_digest: history.history_digest().to_owned(),
            snapshot_json: serde_json::to_string(history.snapshot()).map_err(|_| JournalError::InvalidBinding)?,
            active_receipt_json: serde_json::to_string(active.receipt()).map_err(|_| JournalError::InvalidBinding)?,
            original_source: read.original_source_deadline(),
            original_service: read.original_service_deadline(),
            original_writer: read.original_writer_session_deadline(),
        })
    }
}
impl PreparedCoordinatedFinancialSpendV1 {
    pub(crate) fn facts(&self, reviewed_at_ms: u64, expires_at_ms: u64) -> Result<SignerSignExactFactsV1> {
        project_sign_exact_facts(
            &self.read, &self.prepared.terms, &self.prepared.digest,
            &self.history_digest, &self.snapshot_json, &self.active_receipt_json,
            || self.prepared.display(), reviewed_at_ms, expires_at_ms,
        )
    }
    pub(crate) fn freeze_presentation(self, presentation: SignerSignExactPresentationV1, original_sign: Instant) -> Result<PresentedCoordinatedFinancialSpendV1> {
        presentation.validate().map_err(|_| JournalError::InvalidBinding)?;
        if presentation.actor != self.read.actor
            || presentation.facts != self.facts(presentation.facts.reviewed_at_ms, presentation.facts.expires_at_ms)?
            || original_sign > self.original_source.min(self.original_service).min(self.original_writer)
            || Instant::now() >= original_sign
        { return Err(JournalError::InvalidBinding); }
        Ok(PresentedCoordinatedFinancialSpendV1 { prepared: self, presentation, original_sign })
    }
}
impl PresentedCoordinatedFinancialSpendV1 {
    pub(crate) fn approve(self, action: SignerSignExactFinalV1) -> Result<ApprovedCoordinatedFinancialSpendConsentV1> {
        action.check_current().map_err(|_| JournalError::Permission)?;
        if action.presentation() != &self.presentation
            || action.original_sign_deadline() != self.original_sign
            || action.original_source_deadline() != self.prepared.original_source
            || action.original_service_deadline() != self.prepared.original_service
            || action.original_writer_session_deadline() != self.prepared.original_writer
        { return Err(JournalError::Permission); }
        let p = &self.presentation;
        let inner = &self.prepared.prepared;
        let mut terms = inner.terms.clone();
        // This tuple is historical data. The explicitly tagged coordinated
        // provenance and distinct record domain prevent a native-owner claim.
        terms.receipt = NativeConsentReceipt {
            native_session_id: p.actor.session_challenge.clone(),
            trusted_launch_measurement: p.actor.common_image_measurement.clone(),
            permission_generation: 1, writer_epoch: inner.account.writer_epoch,
            nonce: p.challenge.clone(), reviewed_at_ms: p.facts.reviewed_at_ms,
            expires_at_ms: p.facts.expires_at_ms,
        };
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &inner.retained.request().control else { return Err(JournalError::InvalidBinding); };
        let binding = FinancialSpendBindingV1 {
            continuation_operation_id: inner.retained.request().operation_id.clone(),
            continuation_request_digest: record.request_digest(inner.retained.request()).map_err(|_| JournalError::InvalidBinding)?,
            continuation_history_digest: inner.retained.history_digest()?,
            source_identity_digest: inner.source_identity.clone(),
            terms_digest: inner.retained.terms()?.intent_terms_digest().map_err(|_| JournalError::InvalidBinding)?,
            signing_terms_digest: inner.digest.clone(), reviewed_head: inner.head.clone(),
            disclosure: inner.disclosure.clone(), action_review_digest: p.presentation_digest.clone(),
            native_session_digest: p.actor.session_challenge.clone(), principal_id: terms.principal_id.clone(),
            measurement: p.actor.common_image_measurement.clone(), permission_generation: 1, nonce: p.challenge.clone(),
            coordinated_origin_v1: Some(CoordinatedFinancialSpendProvenanceV1 {
                version: 1, presentation_json: serde_json::to_string(p).map_err(|_| JournalError::InvalidBinding)?,
            }),
        };
        let record = OriginalSpendConsent::new_coordinated_financial_v1(terms, binding)?;
        action.check_current().map_err(|_| JournalError::Permission)?;
        Ok(ApprovedCoordinatedFinancialSpendConsentV1 { prepared: self.prepared, record, presentation: self.presentation, action, original_sign: self.original_sign })
    }
}
impl ApprovedCoordinatedFinancialSpendConsentV1 {
    pub(crate) fn check_current(&self) -> Result<()> { self.action.check_current().map_err(|_| JournalError::Permission) }
    pub(crate) fn record(&self) -> &OriginalSpendConsent { &self.record }
    pub(crate) fn fixed(&self) -> &VerifiedFixedProposal { &self.prepared.prepared.fixed }
    pub(crate) fn authenticated_fvk(&self) -> &orchard::keys::FullViewingKey { &self.prepared.authenticated_fvk }
    pub(crate) fn inputs(&self) -> &ReviewInputs { &self.prepared.prepared.inputs }
    pub(crate) fn presentation(&self) -> &SignerSignExactPresentationV1 { &self.presentation }
    pub(crate) fn original_sign_deadline(&self) -> Instant { self.original_sign }
    pub(crate) fn original_deadlines(&self) -> (Instant, Instant, Instant) { (self.prepared.original_source,self.prepared.original_service,self.prepared.original_writer) }
    pub(in crate::consent_journal) fn require_journal(&self, journal: &SignerJournalBinding, account: &SignerAccountState) -> Result<()> {
        self.check_current()?;
        let p = &self.prepared.prepared;
        if journal != &p.binding || account.account_id != p.account.account_id
            || account.writer_epoch != p.account.writer_epoch || account.recovery_required {
            return Err(JournalError::Permission);
        }
        Ok(())
    }
    pub(in crate::consent_journal) fn require_initial_revision(&self, source: &FinancialSourceBindingV1) -> Result<()> {
        self.check_current()?;
        if source.source_digest != self.prepared.prepared.source_identity || source.revision != self.prepared.source_revision {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    pub(in crate::consent_journal) fn release(&self, commit: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> { self.action.execute_sign_release_publication(commit) }
    pub(in crate::consent_journal) fn request(&self, commit: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> { self.action.execute_sign_request_publication(commit) }
    pub(in crate::consent_journal) fn permit(&self, commit: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> { self.action.execute_sign_permit_publication(commit) }
    pub(in crate::consent_journal) fn started(&self, commit: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> { self.action.execute_sign_started_publication(commit) }
    pub(in crate::consent_journal) fn result(&self, commit: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> { self.action.execute_sign_result_publication(commit) }
    pub(crate) fn execute_key_use(&self, sign: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> { self.action.execute_sign_key_use(sign) }
    pub(crate) fn finish(self) -> Result<()> { self.action.finish_sign().map_err(|_| JournalError::Permission) }
}

// Pure Sign facts projection. The callback supplies only the existing display.
#[allow(clippy::too_many_arguments)]
pub(crate) fn project_sign_exact_facts(
    read: &SignerSignReadPresentationV1, terms: &SpendConsentTerms,
    signing_digest: &str, history_digest: &str, snapshot_json: &str, receipt_json: &str,
    display: impl FnOnce() -> Result<String>, reviewed_at_ms: u64, expires_at_ms: u64,
) -> Result<SignerSignExactFactsV1> {
    let facts = SignerSignExactFactsV1 {
        original: read.facts.original.clone(), observed: read.facts.observed.clone(),
        original_read_presentation_digest: read.presentation_digest.clone(),
        signing_terms_digest: signing_digest.to_owned(),
        signer_principal_id: terms.principal_id.clone(),
        spend_terms_json: serde_json::to_string(&inert_terms(&terms)?).map_err(|_| JournalError::InvalidBinding)?,
        authenticated_history_digest: history_digest.to_owned(),
        authenticated_snapshot_json: snapshot_json.to_owned(),
        active_receipt_json: receipt_json.to_owned(),
        active_receipt_digest: SignerSignExactFactsV1::calculate_active_receipt_digest(&receipt_json).map_err(|_| JournalError::InvalidBinding)?,
        display: display()?, reviewed_at_ms, expires_at_ms,
    };
    facts.validate().map_err(|_| JournalError::InvalidBinding)?;
    Ok(facts)
}
