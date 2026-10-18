//! Read-only exact predecessor verification for a previously retained union.
//! This leaf is unregistered until the durable Host submission issuer is wired.
use super::*;
use crate::authorization::retention::transaction::{
    submission_handoff::{SubmissionHandoffError, VerifiedRetainedSubmission},
    LocalTransactionCheckpoint,
};

impl VerifiedRetainedUnionV1<'_> {
    /// Read and reverify the exact existing union and completed extraction. This
    /// cannot retain a missing result, extract new randomized transaction bytes,
    /// refresh a signature, disclose bytes, or authorize a backend submission.
    /// Every original subset's current read/retention consent remains required.
    pub fn verify_retained_submission(
        &self,
        signature_key: &str,
        obligation_id: &str,
        proposal_id: &str,
        submission_operation_id: &str,
        transactions: &LocalTransactionCheckpoint<'_>,
    ) -> std::result::Result<VerifiedRetainedSubmission, SubmissionHandoffError> {
        self.journal.verify_retained_submission(
            self.context.clone(),
            signature_key,
            self.base,
            self.policy,
            &self.signatures.0,
            self.limits,
            &self.consent(),
            obligation_id,
            proposal_id,
            submission_operation_id,
            transactions,
        )
    }
}
