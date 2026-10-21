//! Exact source-backed financial review. Data validators never grant authority.
use super::super::financial_continuation_preparation_v1::{self, PreparedNativeV1};
use super::*;
use wholepact_financial_coordinator_origin::WitnessFinancialContinuationSetupV1;

pub(crate) const ADMISSION_NOTICE: &str = "Arm only this exact original financial continuation. A later focused native admission may allow its one frozen local append to finish even if focus is lost afterward. Cancellation before that admission prevents the append. A lost response can leave a committed operation uncertain. Original owner mTLS, source, expiry and request bounds remain mandatory. No signature, extraction or transaction dispatch occurs here.";
const TRUST_NOTICE: &str = "The pinned common image, original role processes, OS and compositor form the trusted review surface. Keys stay in this Witness process. Public selectors, certificate possession and historical records do not replace independent explicit review.";

pub fn validate_financial_witness_inputs(data: &FinancialWitnessInputsV1) -> Result<()> {
    data.validate()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    if serde_json::to_vec(data)
        .map_err(|_| AuthorityError::InvalidBinding)?
        .len()
        > 60 * 1024
    {
        return Err(AuthorityError::Limit);
    }
    Ok(())
}
pub fn validate_financial_witness_presentation(
    data: &FinancialWitnessPresentationV1,
) -> Result<()> {
    data.validate()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    if !data.display.contains(ADMISSION_NOTICE)
        || !data.display.contains(TRUST_NOTICE)
        || serde_json::to_vec(data)
            .map_err(|_| AuthorityError::InvalidBinding)?
            .len()
            > 60 * 1024
    {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}
fn inert_text(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '\n' || c == ' ' || c.is_ascii_graphic() {
            safe.push(c);
        } else {
            safe.extend(c.escape_default());
        }
    }
    safe
}
pub(super) struct PreparedReviewV1 {
    pub(super) prepared: PreparedNativeV1,
    pub(super) presentation: FinancialWitnessPresentationV1,
    pub(super) clock: ReviewClock,
}
pub(super) fn prepare(
    setup: WitnessFinancialContinuationSetupV1,
    first: &mut observation::FirstFailureV1,
) -> Result<PreparedReviewV1> {
    let mut stage = observation::Stage::InputValidation;
    let result = (|| {
        setup
            .check_current()
            .map_err(|_| AuthorityError::Permission)?;
        validate_financial_witness_inputs(setup.inputs())?;
        stage = observation::Stage::ProtectedNamespaceOpen;
        let prepared = financial_continuation_preparation_v1::prepare_coordinated(&setup, first)?;
        setup
            .check_current()
            .map_err(|_| AuthorityError::Permission)?;
        stage = observation::Stage::ReviewClock;
        let ceiling = prepared
            .proposal
            .first_commit_deadline_ms()
            .ok_or(AuthorityError::Permission)?
            .min(setup.continuation().source_expires_at_ms);
        let clock = ReviewClock::start(Some(ceiling))?;
        let (prepared_at_ms, expires_at_ms) = clock.display_bounds()?;
        stage = observation::Stage::ReviewFacts;
        let backend_review_digest = prepared
            .proposal
            .coordinated_setup_review_digest_v1(&setup)?;
        let display = inert_text(&format!(
            "{}\n\nOriginal backend review digest: {}\n\n{}",
            prepared.proposal.coordinated_display_v1(&setup)?,
            backend_review_digest,
            TRUST_NOTICE
        ));
        let request = prepared.proposal.coordinated_expected_v1();
        let journal = prepared.proposal.coordinated_journal_v1();
        let owner = journal
            .born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        owner.check_setup_current(
            super::super::financial_setup_guard_v1::FinancialSetupGuardV1::Coordinated(&setup),
            true,
        )?;
        setup
            .check_current()
            .map_err(|_| AuthorityError::Permission)?;
        let (source_commitment, owner_certificate_digest) = {
            let c = journal
                .connection
                .try_lock()
                .map_err(|_| AuthorityError::Permission)?;
            setup
                .check_current()
                .map_err(|_| AuthorityError::Permission)?;
            let file = c.database_identity()?;
            file.check_current(c.connection())?;
            setup
                .check_current()
                .map_err(|_| AuthorityError::Permission)?;
            let ledger = crate::journal::load(c.connection())?;
            prepared
                .proposal
                .validate_locked(&ledger, crate::now_ms()?)?;
            setup
                .check_current()
                .map_err(|_| AuthorityError::Permission)?;
            let (stamp, birth) =
                crate::journal::namespace_account_stamp(c.connection(), &ledger.policy)?;
            owner.require_original_account_connection(&c, &birth)?;
            file.check_current(c.connection())?;
            setup
                .check_current()
                .map_err(|_| AuthorityError::Permission)?;
            (
                source_commitment(&file, &stamp, &ledger.policy)?,
                ledger.policy.owner_certificate_digest,
            )
        };
        let mut presentation = FinancialWitnessPresentationV1 {
            version: 1,
            purpose: "original-financial-continuation-append".into(),
            mode: "one-exact-append".into(),
            display,
            backend_review_digest,
            presentation_digest: String::new(),
            prepared_at_ms,
            expires_at_ms,
            account_id: request.account_id.clone(),
            operation_id: request.operation_id.clone(),
            request_commitment: setup.continuation().request_digest.clone(),
            source_commitment,
            owner_certificate_digest,
            expected_head_sequence: request.expected_head.sequence,
            expected_head_digest: request.expected_head.digest.clone(),
            continuation: setup.continuation().clone(),
        };
        presentation.presentation_digest = presentation
            .calculate_presentation_digest()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        validate_financial_witness_presentation(&presentation)?;
        stage = observation::Stage::PreparedSourceCurrentness;
        prepared.proposal.coordinated_setup_current_v1(&setup)?;
        setup
            .check_current()
            .map_err(|_| AuthorityError::Permission)?;
        clock.check()?;
        Ok(PreparedReviewV1 {
            prepared,
            presentation,
            clock,
        })
    })();
    if let Err(error) = result.as_ref() {
        first.note(stage, *error);
    }
    result
}
pub(crate) fn source_commitment(
    file: &wholepact_storage_security::DatabaseFileIdentity,
    stamp: &crate::journal::NamespaceJournalStamp,
    policy: &crate::AccountPolicy,
) -> Result<String> {
    crate::digest(
        "wholepact:coordinated-financial-continuation-original-source:v1",
        &(file.origin_commitment(), stamp, policy),
    )
}
