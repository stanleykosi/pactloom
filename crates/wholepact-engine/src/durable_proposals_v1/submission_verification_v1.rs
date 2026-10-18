//! Purpose-distinct sealed predecessor for a durable union. Historical original
//! signatures are data; a separate actual native/witness dispatch issuer must
//! still authorize the exact final bytes, backend and submission journal.
//! This leaf is unregistered until that complete Host composition is wired.
use super::*;
use wholepact_protocol::authorization::retention::transaction::submission_handoff::VerifiedRetainedSubmission;

/// Constructible only after the Engine-owned intake/source-set join and exact
/// original signed-result/transaction verification. There is no Deserialize,
/// Clone, raw byte getter, public constructor, or ordinary profile conversion.
pub struct VerifiedDurableSubmissionV1 {
    retained: VerifiedRetainedSubmission,
    fixed: FixedProposalIdentityV1,
    signature_retention_key: String,
}
impl VerifiedDurableSubmissionV1 {
    pub fn fixed_identity(&self) -> &FixedProposalIdentityV1 {
        &self.fixed
    }
    pub fn signed_result_id(&self) -> &str {
        self.retained.signed_result_id()
    }
    pub fn signed_request_digest(&self) -> &str {
        self.retained.signed_request_digest()
    }
    pub fn signed_candidate_digest(&self) -> &str {
        self.retained.signed_candidate_digest()
    }
    pub fn checkpoint_id(&self) -> String {
        self.retained.checkpoint_id()
    }
    pub fn signature_retention_key(&self) -> &str {
        &self.signature_retention_key
    }
    pub fn descriptor(&self) -> &wholepact_chain::SubmissionDescriptor {
        self.retained.descriptor()
    }
    pub fn context(&self) -> &SignedCandidateContext {
        self.retained.context()
    }
}

impl Engine {
    /// Reads existing immutable artifacts only. No `retain`, extraction,
    /// submission-intent write, network access or new signer association occurs.
    /// Cancellation remains a block on deriving a new dispatch predecessor;
    /// historical uncertain outcomes remain inspectable through their journals.
    pub fn verify_durable_submission_v1(
        &self,
        access: &Access,
        candidate_id: &str,
        operation_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        transactions: LocalTransactionCheckpoint<'_>,
    ) -> Result<VerifiedDurableSubmissionV1> {
        let read = local.consent;
        let (envelope, stored, checkpoint, fixed) =
            self.load_durable(access, candidate_id, local)?;
        if envelope.view.cancellation_requested {
            return Err(ApiError::new(
                "CANCELLATION_REQUESTED",
                "New dispatch preparation is blocked; preserve and reconcile the original exposure and transaction journals",
            ));
        }
        let original = stored.union.as_ref().ok_or_else(incomplete)?;
        let gate = Gate {
            scope: checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        let union = retention
            .journal
            .load_verified_union(
                union_context(&stored, &checkpoint)?,
                &sources(&stored),
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                limits(),
                &gate,
            )
            .map_err(retention_error)?;
        if !union.inspection().signatures_complete {
            return Err(incomplete());
        }
        let retained = union
            .verify_retained_submission(
                &original.retention_key,
                &stored.identity.obligation_id,
                candidate_id,
                operation_id,
                &transactions,
            )
            .map_err(|_| submission_error(operation_id))?;
        if retained.signed_result_id() != original.result_id
            || retained.signed_request_digest() != original.request_digest
            || retained.signed_candidate_digest() != original.signed_candidate_digest
            || retained.context().delivery_provenance_digest != original.source_set_digest
            || fixed.identity() != &stored.identity
        {
            return Err(damaged());
        }
        let signature_retention_key = original.retention_key.clone();
        Ok(VerifiedDurableSubmissionV1 {
            retained,
            fixed: stored.identity,
            signature_retention_key,
        })
    }
}
