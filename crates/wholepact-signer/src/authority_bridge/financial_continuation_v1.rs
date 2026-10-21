//! Separate original financial source route. Historical records remain data;
//! effect authority is supplied only by a current source-bound native decision.
use super::protocol::{AuthorizationDeliveryScope, RetainedAuthorizationRequest};
use super::{BridgeError, Result};
use crate::consent_journal::OriginalAuthorizationEvidence;
use sha2::{Digest, Sha256};
pub use wholepact_authority::durable_financial_continuation_v1::{
    AuthenticatedFinancialContinuationHistoryV1, FinancialContinuationRecordV1,
};
pub use wholepact_authority::{OwnerControl, OwnerControlRequest};

/// Pure exact-request encoding, not permission or a session constructor. The
/// caller has already retained the fresh financial consent and conservative
/// exposure, and must retain this request before sending any bytes.
pub(crate) fn request_from_financial_original_v1(
    original: &OriginalAuthorizationEvidence,
    record: &FinancialContinuationRecordV1,
    bytes: &[u8],
) -> Result<RetainedAuthorizationRequest> {
    let c = original.original_consent();
    c.validate_financial_v1()?;
    let t = c.terms();
    let b = c.financial_binding_v1().ok_or(BridgeError::Binding)?;
    let a = &record.terms.scope.authorization;
    if bytes.is_empty()
        || bytes.len() > super::protocol::MAX_ARTIFACT_BYTES
        || hex::encode(Sha256::digest(bytes)) != t.artifact_digest
        || t.account_id != a.identity.account_id
        || t.authorization_id != a.authorization_id
        || b.disclosure != record.terms.scope.witness
        || t.receipt.expires_at_ms() > record.terms.valid_until_ms
    {
        return Err(BridgeError::Binding);
    }
    let reservation = wholepact_authority::ReserveAuthorization {
        automation: None,
        operation_id: t.authorization_id.clone(),
        account_id: t.account_id.clone(),
        network_profile_id: a.identity.network_profile_id.clone(),
        writer_epoch: t.receipt.writer_epoch(),
        expected_head: b.reviewed_head.clone(),
        authorization_id: t.authorization_id.clone(),
        original_consent_ref: c.reference().into(),
        enrollment_ref: a.original_enrollment_ref.clone(),
        accepted_manifest_ref: original.accepted_manifest().reference().into(),
        agreement_id: t.agreement_id.clone(),
        obligation_id: t.obligation_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_digest: t.proposal_digest.clone(),
        manifest_digest: t.manifest_digest.clone(),
        effects_digest: t.effects_digest.clone(),
        artifact_digest: t.artifact_digest.clone(),
        review_binding: t.review_binding.clone(),
        recipient_scope_digest: a.recipient_policy_scope_digest.clone(),
        inputs: t
            .input_bindings
            .iter()
            .map(|i| wholepact_authority::InputReservation {
                input_id: i.input_id.clone(),
                nullifier: i.nullifier.clone(),
                action_index: i.action_index,
                value_zatoshis: i.value_zatoshis,
            })
            .collect(),
        maximum_debit_zatoshis: t.maximum_debit_zatoshis,
        fee_share_zatoshis: t.fee_share_zatoshis,
        transaction_fee_zatoshis: t.transaction_fee_zatoshis,
        transaction_expiry_height: t.transaction_expiry_height,
        reviewed_at_ms: t.receipt.reviewed_at_ms(),
        permit_expires_at_ms: t.receipt.expires_at_ms(),
    };
    reservation.validate()?;
    // SignExact explicitly includes this disclosure. It is not a forged old
    // ApprovedWitnessDisclosure, and has a distinct historical validator.
    let disclosure = super::disclosure::RetainedWitnessDisclosure {
        descriptor: b.disclosure.clone(),
        original_consent_ref: c.reference().into(),
        native_review_digest: b.action_review_digest.clone(),
        expected_head: b.reviewed_head.clone(),
        nonce: b.nonce.clone(),
        native_origin_measurement: b.measurement.clone(),
        native_principal_id: b.principal_id.clone(),
    };
    Ok(RetainedAuthorizationRequest {
        reservation,
        delivery: AuthorizationDeliveryScope {
            candidate_id: t.proposal_id.clone(),
        },
        artifact_hex: hex::encode(bytes),
        disclosure: Some(disclosure),
    })
}

use crate::account::birth::enrollment::roster_v2::financial_source_v1::PreparedOriginalFinancialSourceV1;
use crate::consent_journal::ApprovedFinancialSpendConsentV1;
use std::time::Instant;
use wholepact_authority::{AuthenticatedPermit, AuthenticatedWriterSession, AuthorityClient};

/// Fresh one-use financial operation. The exact approved action is moved here,
/// retained through reservation, then consumed by the maintained signing kernel.
pub(crate) struct ReservedFinancialAuthorizationV1<'a> {
    source: &'a PreparedOriginalFinancialSourceV1,
    approved: ApprovedFinancialSpendConsentV1,
    request: RetainedAuthorizationRequest,
    permit: AuthenticatedPermit,
}
pub(crate) fn reserve_financial_authorization_v1<'a>(
    source: &'a PreparedOriginalFinancialSourceV1,
    approved: ApprovedFinancialSpendConsentV1,
    client: &AuthorityClient,
    history: &AuthenticatedFinancialContinuationHistoryV1,
    active: &AuthenticatedWriterSession,
    deadline: Instant,
) -> Result<ReservedFinancialAuthorizationV1<'a>> {
    source
        .check_custody()
        .map_err(|_| BridgeError::Permission)?;
    approved.check_current()?;
    if history.continuation_request()
        != &source
            .continuation_request()
            .map_err(|_| BridgeError::Binding)?
        || approved.reviewed_head() != &history.snapshot().head
        || approved.disclosure() != history.disclosure()
    {
        return Err(BridgeError::Binding);
    }
    history.require_financial_continuation_session_v1(
        &history.continuation_request().operation_id,
        active,
    )?;
    let journal = source
        .financial_journal()
        .map_err(|_| BridgeError::Permission)?;
    let original = journal.record_financial_consent_release_v1(
        &mut *source
            .financial_binding()
            .map_err(|_| BridgeError::Permission)?,
        &approved,
    )?;
    let request = request_from_financial_original_v1(
        &original,
        history.continuation_record(),
        approved.fixed().private_proved_pczt_bytes(),
    )?;
    journal.retain_financial_request_v1(
        &mut *source
            .financial_binding()
            .map_err(|_| BridgeError::Permission)?,
        &approved,
        &request,
    )?;
    // This interval begins only after the exact release and request commits.
    // It ends before the permit mutation; no pin is carried into key use.
    use crate::account::birth::enrollment::roster_v2::financial_source_v1::FinancialOperationV1;
    approved.check_current()?;
    let reserve_pin = source
        .prepare_financial_operation_source_pin_v1(
            FinancialOperationV1::Reserve,
            Some((
                false,
                &client.disclosure_descriptor(),
                &history
                    .continuation_record()
                    .terms
                    .scope
                    .authorization
                    .writer_certificate_digest,
            )),
        )
        .map_err(|_| BridgeError::Permission)?;
    if reserve_pin.continuation_request() != history.continuation_request() {
        return Err(BridgeError::Binding);
    }
    let exact_request_digest = request.reservation.request_digest()?;
    let check_reservation = || -> Result<()> {
        approved.check_current()?;
        source
            .check_financial_operation_source_pin_v1(&reserve_pin, FinancialOperationV1::Reserve)
            .map_err(|_| BridgeError::Permission)?;
        if request.reservation.request_digest()? != exact_request_digest
            || reserve_pin.continuation_request() != history.continuation_request()
        {
            return Err(BridgeError::Binding);
        }
        approved.check_current()?;
        Ok(())
    };
    check_reservation()?;
    let permit = client.reserve_financial_continuation_v1_checked_until(
        history,
        active,
        request.reservation.clone(),
        deadline,
        || check_reservation().map_err(|_| wholepact_authority::AuthorityError::Permission),
    )?;
    check_reservation()?;
    drop(check_reservation);
    drop(reserve_pin);
    journal.retain_financial_permit_v1(
        &mut *source
            .financial_binding()
            .map_err(|_| BridgeError::Permission)?,
        &approved,
        &permit,
    )?;
    Ok(ReservedFinancialAuthorizationV1 {
        source,
        approved,
        request,
        permit,
    })
}

/// No constructor outside this module. It is created only after the newly
/// committed Started row, never from reopening that row after an interruption.
pub(crate) struct FinancialKeyUseFenceV1<'a> {
    source: &'a PreparedOriginalFinancialSourceV1,
    account: &'a crate::account::DedicatedAccount,
    check: &'a dyn Fn() -> Result<()>,
}
impl FinancialKeyUseFenceV1<'_> {
    pub(crate) fn require_account(
        &self,
        account: &crate::account::DedicatedAccount,
    ) -> crate::Result<()> {
        if !std::ptr::eq(account, self.account)
            || !std::ptr::eq(account, self.source.financial_account()?)
        {
            return Err(crate::Error::Authentication);
        }
        (self.check)().map_err(|_| crate::Error::ReviewMismatch)
    }
}
#[path = "financial_result_ipc_v1.rs"]
mod result_ipc;
#[path = "financial_signing_v1.rs"]
mod signing;
pub(crate) use result_ipc::{ApprovedFinancialReturnV1, PreparedFinancialReturnV1};
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use result_ipc::PreparedCoordinatedFinancialResultReceiverV1;
pub use result_ipc::{
    AuthenticatedFinancialResultLeaseV1, AuthenticatedFinancialResultPreviewV1,
    FinancialResultRequestV1, PreparedFinancialResultReceiverV1, FinancialResultRestrictionV1,
};
pub use wholepact_authority::completed_dispatch_v1::{
    AuthenticatedCompletedDispatchAdmissionV1, AuthorizeCompletedDispatchV1,
    CompletedDispatchAdmissionV1, CompletedDispatchContextV1, CompletedDispatchOwnerV1,
};

#[cfg(feature = "synthetic-born-joined-qualification")]
pub use result_ipc::{
    FinancialResultCurrentTimingV1, FinancialResultDiagnosticV1, FinancialResultErrorClassV1,
    FinancialResultObservedErrorV1, FinancialResultStageV1,
};
