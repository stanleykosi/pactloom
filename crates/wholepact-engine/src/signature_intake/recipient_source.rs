//! Native recipient-owned viewing-key observation of the original retained exact
//! transaction. Ordinary agreement-read access never grants recipient key access.
//! The independent privacy issuer and qualified chain source remain injected local
//! runtime boundaries; no HTTP key/verified flag or coordinator payment assertion.
use super::*;
use wholepact_core::recipient::{
    AcceptedRecipientSource, CheckedRecipientPayment, RecipientCheckPolicy,
    RecipientEvidenceProvenance, RecipientObservationSource, RecipientObservedOutput,
    RecipientPaymentRequest, RecipientSourceObservation,
};
use wholepact_core::records::{
    ExactTransactionReference, ObservationPolicy, ObservationWindow, SettlementObservationSource,
};
use wholepact_core::{Amount, CoreError, ErrorCode, Proposal};
use wholepact_protocol::authorization::retention::transaction::{
    recipient::{
        LocalRecipientObservation, RecipientObservationError, RecipientPaymentTarget,
        RecipientViewingKeySource, VerifiedRecipientOutputs, RECIPIENT_FORMAT_ID,
        RECIPIENT_VERIFIER_ID,
    },
    LocalTransactionCheckpoint, TransactionRecoveryConsent,
};

/// Native selected payment and recipient wallet account; neither field asserts
/// payment or account ownership. Actual viewing authority is a separate lease.
pub struct RecipientObservationRequest {
    pub recipient_id: String,
    pub recipient_account_ref: String,
    pub exact_transaction: ExactTransactionReference,
}
pub struct LocalRecipientPaymentCheck<'a> {
    pub profile_id: &'a str,
    pub privacy_purpose: &'a str,
    pub proof: LocalProofJob<'a>,
    pub signatures: LocalSignedRetention<'a>,
    pub transactions: LocalTransactionCheckpoint<'a>,
    pub transaction_read_consent: &'a dyn TransactionRecoveryConsent,
    pub recipient_viewing: &'a dyn RecipientViewingKeySource,
    pub deliveries: &'a [AuthenticatedSignatureDelivery<'a>],
    pub signature_idempotency_key: &'a str,
    pub now: &'a Timestamp,
    pub window: &'a ObservationWindow,
    /// Exact configured source/adapter/trust profile, never an HTTP assertion.
    pub chain_policy: &'a ObservationPolicy,
}
impl Engine {
    /// Checks actual recipient output decryption, selected destination, exact
    /// amount/memo and independently sourced current chain confidence. Private
    /// checked facts are returned only natively; no record or authorization is
    /// silently created and no real spending key is requested.
    pub fn check_retained_recipient_payment(
        &self,
        access: &Access,
        candidate_id: &str,
        request: RecipientObservationRequest,
        local: LocalRecipientPaymentCheck<'_>,
        chain: &mut impl SettlementObservationSource,
    ) -> Result<CheckedRecipientPayment> {
        local.window.validate()?;
        if local.window.now != local.now.as_str() || local.now.unix_seconds() < 0 {
            return Err(ApiError::new(
                "RECIPIENT_OBSERVATION_REJECTED",
                "Recipient and chain assessment must use the same trusted current runtime clock",
            ));
        }
        if local
            .deliveries
            .iter()
            .any(|delivery| delivery.association.is_none())
        {
            return Err(association_missing());
        }
        request.exact_transaction.validate()?;
        let (_, candidate) = self.candidate(access, candidate_id)?;
        let candidate = candidate.verified_snapshot()?;
        if request.exact_transaction.network_profile_id
            != candidate.manifest().agreement.network_profile_id
        {
            return Err(recipient_source_rejected());
        }
        let recipient = candidate
            .manifest()
            .agreement
            .recipients
            .iter()
            .find(|recipient| recipient.recipient_id == request.recipient_id)
            .ok_or_else(recipient_source_rejected)?;
        let checkpoint = self.load_candidate_proof_for_local_review(
            access,
            candidate_id,
            LocalProofJob {
                job_id: local.proof.job_id,
                jobs: local.proof.jobs,
                consent: local.proof.consent,
            },
        )?;
        let (context, signatures) = retention_inputs(
            &checkpoint,
            &candidate.manifest().agreement.agreement_id,
            &candidate.input().proposal_id,
            candidate.manifest().agreement.revision.into(),
            local.deliveries,
            local.now,
            true,
        )?;
        let retention = Gate {
            original: checkpoint.scope(),
            read: local.proof.consent,
            retain: local.signatures.consent,
        };
        let verified = local
            .signatures
            .journal
            .observe_retained_recipient_outputs(
                context,
                local.signature_idempotency_key,
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                &signatures,
                wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
                &retention,
                LocalRecipientObservation {
                    transactions: local.transactions,
                    transaction_read_consent: local.transaction_read_consent,
                    recipient_viewing: local.recipient_viewing,
                    target: RecipientPaymentTarget {
                        principal_id: &access.principal_id,
                        profile_id: local.profile_id,
                        recipient_id: &request.recipient_id,
                        recipient_account_ref: &request.recipient_account_ref,
                        network_profile_id: &request.exact_transaction.network_profile_id,
                        destination: &recipient.address,
                        expected_amount_zatoshis: recipient.amount.as_zatoshis(),
                        expected_memo: recipient.memo.as_deref(),
                        transaction_id: &request.exact_transaction.transaction_id,
                        transaction_digest: &request.exact_transaction.transaction_bytes_digest,
                        effects_commitment: &request.exact_transaction.effects_commitment,
                        privacy_purpose: local.privacy_purpose,
                    },
                    now_unix_seconds: local.now.unix_seconds() as u64,
                },
            )
            .map_err(recipient_protocol_error)?;
        let mut approved = candidate.input().clone();
        approved.effects_commitment = Some(verified.scope().effects_commitment.clone());
        approved.artifact_digest = Some(verified.signed_candidate_digest().into());
        let approved = Proposal::validate(approved)?;
        let payment = RecipientPaymentRequest::for_proposal(
            &approved,
            request.exact_transaction,
            &request.recipient_id,
        )?;
        let policy = RecipientCheckPolicy {
            chain: local.chain_policy.clone(),
            recipient_source: AcceptedRecipientSource::IndependentOutputVerifier {
                verifier_id: RECIPIENT_VERIFIER_ID.into(),
                format_id: RECIPIENT_FORMAT_ID.into(),
                recipient_binding_ref: request.recipient_account_ref,
            },
            required_confirmations: approved
                .manifest()
                .agreement
                .confirmation_policy
                .required_confirmations,
        };
        let mut source = DecryptedRecipientSource {
            verified: &verified,
            chain,
            now: local.now,
        };
        let checked = wholepact_core::recipient::check_recipient_payment(
            &mut source,
            &payment,
            &policy,
            local.window,
        )?;
        verified
            .check_current(local.now.unix_seconds() as u64)
            .map_err(recipient_protocol_error)?;
        Ok(checked)
    }
}
struct DecryptedRecipientSource<'a, 'key, S> {
    verified: &'a VerifiedRecipientOutputs<'key>,
    chain: &'a mut S,
    now: &'a Timestamp,
}
impl<S: SettlementObservationSource> RecipientObservationSource
    for DecryptedRecipientSource<'_, '_, S>
{
    fn observe_recipient_outputs(
        &mut self,
        request: &RecipientPaymentRequest,
    ) -> wholepact_core::Result<RecipientSourceObservation> {
        let guard_error = |_| {
            CoreError::new(
                ErrorCode::MissingEvidence,
                "Recipient viewing permission expired or was revoked during observation",
            )
        };
        self.verified
            .check_current(self.now.unix_seconds() as u64)
            .map_err(guard_error)?;
        let scope = self.verified.scope();
        if request.recipient_id() != scope.recipient_id
            || request.destination() != scope.destination
            || request.expected_amount().as_zatoshis() != scope.expected_amount_zatoshis
            || request.transaction().transaction_id != scope.transaction_id
            || request.transaction().transaction_bytes_digest != scope.transaction_digest
            || request.transaction().effects_commitment != scope.effects_commitment
            || request.transaction().network_profile_id != scope.network_profile_id
        {
            return Err(CoreError::new(
                ErrorCode::RevisionConflict,
                "Recipient observation must match the exact independently decrypted payment",
            ));
        }
        let chain = self
            .chain
            .observe_exact_transaction(request.transaction())?;
        self.verified
            .check_current(self.now.unix_seconds() as u64)
            .map_err(guard_error)?;
        Ok(RecipientSourceObservation {
            recipient_id: scope.recipient_id.clone(),
            observed_at: self.now.as_str().into(),
            evidence: RecipientEvidenceProvenance::IndependentOutputVerifier {
                verifier_id: RECIPIENT_VERIFIER_ID.into(),
                format_id: RECIPIENT_FORMAT_ID.into(),
                recipient_binding_ref: scope.recipient_account_ref.clone(),
                evidence_digest: self.verified.evidence_digest().into(),
            },
            outputs: self
                .verified
                .outputs()
                .iter()
                .map(|output| {
                    Ok(RecipientObservedOutput {
                        output_ref: output.output_ref().into(),
                        destination: output.destination().into(),
                        amount: Amount::from_zatoshis(output.amount_zatoshis())?,
                    })
                })
                .collect::<wholepact_core::Result<_>>()?,
            chain,
        })
    }
}
fn recipient_source_rejected() -> ApiError {
    ApiError::new(
        "RECIPIENT_OBSERVATION_REJECTED",
        "Exact retained transaction or approved recipient instruction did not match the independent observation request",
    )
}
fn recipient_protocol_error(error: RecipientObservationError) -> ApiError {
    let code = match error {
        RecipientObservationError::ConsentDenied
        | RecipientObservationError::Retention(RetentionError::ConsentDenied) => {
            "RECIPIENT_VIEWING_CONSENT_DENIED"
        }
        RecipientObservationError::RecipientKeyMismatch => "RECIPIENT_VIEWING_ACCOUNT_MISMATCH",
        RecipientObservationError::RecipientAmountMismatch => "RECIPIENT_AMOUNT_MISMATCH",
        RecipientObservationError::RecipientMemoMismatch => "RECIPIENT_MEMO_MISMATCH",
        RecipientObservationError::Retention(
            RetentionError::IntentNotFound | RetentionError::RecoveryRequired,
        ) => "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED",
        _ => "RECIPIENT_OBSERVATION_REJECTED",
    };
    ApiError::new(
        code,
        "Independent recipient decryption failed closed; no raw viewing material, transaction bytes, memo, payment or consent was inferred",
    )
}
