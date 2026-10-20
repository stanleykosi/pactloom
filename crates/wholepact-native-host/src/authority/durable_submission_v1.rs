//! Fresh exact final Host decision for already-completed immutable bytes.
//! This never revives a signing session, performs extraction, or authenticates
//! a Witness. The separate concrete issuer must join both real admissions.
use super::*;
use wholepact_authority::completed_dispatch_v1::CompletedDispatchContextV1;
use wholepact_chain::{BackendIdentity, ChainError, SubmissionReview};
use wholepact_engine::durable_proposals_v1::submission_verification_v1::VerifiedDurableSubmissionV1;

pub(crate) struct NativeDurableSubmissionConsentV1 {
    context: CompletedDispatchContextV1,
    backend: BackendIdentity,
    reviewed_at_ms: u64,
    held: Held,
}
/// Authority uses millisecond exclusive ceilings; RPC tokens use inclusive
/// whole seconds. Conservatively lose at most one second, never extend expiry.
pub(crate) fn strict_ms_to_inclusive_seconds(deadline_ms: u64) -> Result<u64> {
    deadline_ms
        .checked_div(1000)
        .and_then(|v| v.checked_sub(1))
        .ok_or(Error::Permission)
}
pub(crate) fn durable_backend_disclosure_digest_v1(
    descriptor: &wholepact_chain::SubmissionDescriptor,
    journal: &str,
    backend: &BackendIdentity,
    delivery: &wholepact_authority::durable_delivery_scope_v2::DurableDeliveryPlanV2,
) -> Result<String> {
    wholepact_core::proposal::canonical_digest("wholepact:completed-dispatch-backend-disclosure:v1",
        &(descriptor, journal, backend, &delivery.route, &delivery.dispatcher,
            "whole_transaction_and_connection_metadata_to_provider_commitments_and_linkage_to_witness"))
        .map_err(|_| Error::Invalid)
}
impl Authority {
    pub(crate) fn approve_exact_durable_submission_v1(
        &self,
        verified: &VerifiedDurableSubmissionV1,
        context: CompletedDispatchContextV1,
        journal: &str,
        backend: &BackendIdentity,
    ) -> Result<NativeDurableSubmissionConsentV1> {
        self.principal(&verified.context().principal_id)?;
        context.validate().map_err(|_| Error::Authentication)?;
        let descriptor = verified.descriptor();
        if context.final_transaction_digest != descriptor.bytes_sha256
            || context.final_transaction_id != descriptor.transaction_id
            || context.transaction_expiry_height != descriptor.expiry_height
            || context.network != descriptor.network
            || context.consensus_branch_id != descriptor.consensus_branch_id
            || context.delivery.submission_operation_id != descriptor.operation_id
            || context.delivery.submission_journal_identity != journal
            || context.signed_result_request_digest != verified.signed_request_digest()
            || context.signed_artifact_digest != verified.signed_candidate_digest()
            || context.transaction_checkpoint_id != verified.checkpoint_id()
            || serde_json::to_value(&context.fixed)?
                != serde_json::to_value(verified.fixed_identity())?
            || context.delivery.dispatcher.principal_id != verified.context().principal_id
            || context.delivery.provider.source_id != backend.source_id
            || context.delivery.provider.endpoint != backend.endpoint
            || context.delivery.provider.trust_profile != backend.trust_profile
            || context.backend_disclosure_digest
                != durable_backend_disclosure_digest_v1(
                    descriptor,
                    journal,
                    backend,
                    &context.delivery,
                )?
            || backend.trust_profile != "single_tls_provider_report_not_consensus"
        {
            return Err(Error::Authentication);
        }
        let now_ms = now()?.checked_mul(1000).ok_or(Error::Invalid)?;
        if now_ms < context.delivery.valid_from_ms || now_ms >= context.delivery.valid_until_ms {
            return Err(Error::Permission);
        }
        let digest = context.digest().map_err(|_| Error::Authentication)?;
        self.terminal.confirm(&format!(
            "DISPATCH EXACT SAVED TRANSACTION, attempt {} of {}.\n{}\nContext commitment: {}\nBoth owners previously approved this exact payment and bounded future dispatch. This fresh Host decision permits only the already saved bytes through the named dedicated dispatcher, even if an original signer has restarted. It cannot sign again, extract a replacement, change inputs, extend original expiry or reset attempts. The provider receives complete final transaction bytes and connection metadata and may relay/retain them. Later revocation cannot recall disclosed bytes. The original absolute expiry is {} ms; this immediate decision expires sooner, after at most two minutes. Any uncertain outcome preserves the original operation and exact bytes. No further human prompt may occur before this attempt.",
            context.attempt, context.delivery.maximum_explicitly_approved_attempts, serde_json::to_string_pretty(&context)?, digest, context.delivery.valid_until_ms,
        ))?;
        let reviewed_at_ms = now()?.checked_mul(1000).ok_or(Error::Invalid)?;
        if reviewed_at_ms < context.delivery.valid_from_ms
            || reviewed_at_ms >= context.delivery.valid_until_ms
        {
            return Err(Error::Permission);
        }
        let deadline = reviewed_at_ms
            .checked_add(120_000)
            .ok_or(Error::Invalid)?
            .min(context.delivery.valid_until_ms);
        let held = self
            .fence
            .acquire(deadline.checked_div(1000).ok_or(Error::Permission)?)?;
        Ok(NativeDurableSubmissionConsentV1 {
            context,
            backend: backend.clone(),
            reviewed_at_ms,
            held,
        })
    }
}
impl NativeDurableSubmissionConsentV1 {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.held.check()
    }
    pub(crate) fn deadline(&self) -> Result<std::time::Instant> {
        self.held.check()?;
        let remaining = self
            .valid_until_unix_seconds()
            .checked_sub(now()?)
            .ok_or(Error::Permission)?;
        std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(remaining))
            .ok_or(Error::Permission)
    }
    pub(crate) fn context(&self) -> &CompletedDispatchContextV1 {
        &self.context
    }
    pub(crate) fn reviewed_at_ms(&self) -> u64 {
        self.reviewed_at_ms
    }
    pub(crate) fn valid_until_unix_seconds(&self) -> u64 {
        self.held.expires.saturating_sub(1)
    }
    pub(crate) fn check(
        &self,
        review: &SubmissionReview<'_>,
    ) -> std::result::Result<(), ChainError> {
        self.held
            .check()
            .map_err(|_| ChainError::SubmissionNotAuthorized)?;
        let c = &self.context;
        let d = review.descriptor;
        if d.bytes_sha256 != c.final_transaction_digest
            || d.transaction_id != c.final_transaction_id
            || d.expiry_height != c.transaction_expiry_height
            || d.operation_id != c.delivery.submission_operation_id
            || d.network != c.network
            || d.consensus_branch_id != c.consensus_branch_id
            || review.journal_identity != c.delivery.submission_journal_identity
            || review.backend != &self.backend
            || review.context.source() != &self.backend
            || review.now_unix_seconds > self.valid_until_unix_seconds()
        {
            return Err(ChainError::SubmissionNotAuthorized);
        }
        review.context.check_fresh_at(review.now_unix_seconds)?;
        if review.context.tip().height < wholepact_chain::NU7_ACTIVATION_HEIGHT
            || review
                .context
                .tip()
                .height
                .checked_add(u64::from(c.delivery.minimum_expiry_margin_blocks))
                .is_none_or(|height| height > u64::from(c.transaction_expiry_height))
        {
            return Err(ChainError::SubmissionExpiryMargin);
        }
        Ok(())
    }
}
