//! Foreground selected-signer composition over this engine's existing Store.
//! No public DTO can call the authorizer: the opaque installed-signer channel
//! owns the one-shot continuation, and Store commits Unknown before execution.
use crate::{Access, ApiError, Engine, Result, proof_jobs::LocalProofJob};
use sha2::{Digest, Sha256};
use wholepact_core::automation::AutomationRequest;
use wholepact_signer::authority_bridge::automation_ipc::SignerAutomaticAuthorization;
use wholepact_store::automation::AutomaticAuthorizationReceipt;

impl Engine {
    /// Re-read the original encrypted proof under its independent local privacy
    /// permission, match the selected signer to the exact candidate and effects,
    /// then invoke the existing Store's durable-before-callback path. No bytes
    /// are exported and this method never dispatches a transaction.
    pub fn authorize_candidate_automatically(
        &self,
        access: &Access,
        candidate_id: &str,
        participant_id: &str,
        local: LocalProofJob<'_>,
        authorization: SignerAutomaticAuthorization<'_>,
    ) -> Result<AutomaticAuthorizationReceipt> {
        let (_, candidate) = self.candidate(access, candidate_id)?;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        let review =
            wholepact_protocol::review::verify_review(checkpoint.pczt_bytes(), checkpoint.policy())
                .map_err(|_| binding_error())?;
        let digest = hex::encode(Sha256::digest(checkpoint.pczt_bytes()));
        if checkpoint.summary().result_digest.as_deref() != Some(&digest)
            || review.review_binding() != checkpoint.scope().review_binding
            || authorization.descriptor().participant_id != participant_id
        {
            return Err(binding_error());
        }
        let (owner, participant) = candidate
            .proposal
            .manifest
            .participants
            .iter()
            .enumerate()
            .find(|(_, p)| p.participant_id == participant_id)
            .ok_or_else(binding_error)?;
        let expected = CandidateBinding {
            candidate_id: &candidate.candidate_id,
            agreement_id: &candidate.proposal.manifest.agreement.agreement_id,
            obligation_id: &candidate.proposal.manifest.agreement.obligation_id,
            network: &candidate.proposal.manifest.agreement.network_profile_id,
            manifest_digest: &candidate.manifest_digest,
            account_id: &participant.account_id,
            artifact_digest: &digest,
            effects_digest: review.shielded_sighash(),
            maximum_debit: *review
                .net_debits_zatoshis()
                .get(owner)
                .ok_or_else(binding_error)?,
            fee: participant.fee_share.as_zatoshis(),
            expiry_height: candidate.proposal.manifest.expiry_height,
        };
        expected.check(&authorization.descriptor().request)?;
        authorization.authorize_in_store(&self.store).map_err(|_| {
            ApiError::new("AUTOMATIC_AUTHORIZATION_UNCERTAIN", "The exact foreground automatic attempt did not complete cleanly. Preserve original journals and authorization IDs; durable intent or a retained signer result may exist. No replacement, export, or dispatch is authorized")
        })
    }
}

struct CandidateBinding<'a> {
    candidate_id: &'a str,
    agreement_id: &'a str,
    obligation_id: &'a str,
    network: &'a str,
    manifest_digest: &'a str,
    account_id: &'a str,
    artifact_digest: &'a str,
    effects_digest: &'a str,
    maximum_debit: u64,
    fee: u64,
    expiry_height: u32,
}
impl CandidateBinding<'_> {
    fn check(&self, request: &AutomationRequest) -> Result<()> {
        if request.proposal_id != self.candidate_id
            || request.agreement_id != self.agreement_id
            || request.obligation_id != self.obligation_id
            || request.network_profile != self.network
            || request.manifest_digest != self.manifest_digest
            || request.account_id != self.account_id
            || request.artifact_digest != self.artifact_digest
            || request.effects_digest != self.effects_digest
            || request.maximum_debit.as_zatoshis() != self.maximum_debit
            || request.fee.as_zatoshis() != self.fee
            || request.transaction_expiry_height != self.expiry_height
        {
            return Err(binding_error());
        }
        Ok(())
    }
}
fn binding_error() -> ApiError {
    ApiError::new(
        "SIGNER_BINDING_MISMATCH",
        "The selected signer request does not match the original candidate, participant and independently verified encrypted proof",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_core::Amount;
    fn request() -> AutomationRequest {
        AutomationRequest {
            authorization_id: "original".into(),
            application_id: "app".into(),
            account_id: "account".into(),
            writer_epoch: 1,
            agreement_id: "agreement".into(),
            obligation_id: "obligation".into(),
            proposal_id: "candidate".into(),
            network_profile: "network".into(),
            manifest_digest: "manifest".into(),
            effects_digest: "effects".into(),
            artifact_digest: "artifact".into(),
            input_ids: vec!["input".into()],
            recipient_fingerprints: vec!["recipient".into()],
            maximum_debit: Amount::from_zatoshis(20).unwrap(),
            fee: Amount::from_zatoshis(2).unwrap(),
            current_height: 8,
            transaction_expiry_height: 12,
            authorization_expires_at_ms: 100,
            evidence: vec![],
        }
    }
    fn binding() -> CandidateBinding<'static> {
        CandidateBinding {
            candidate_id: "candidate",
            agreement_id: "agreement",
            obligation_id: "obligation",
            network: "network",
            manifest_digest: "manifest",
            account_id: "account",
            artifact_digest: "artifact",
            effects_digest: "effects",
            maximum_debit: 20,
            fee: 2,
            expiry_height: 12,
        }
    }
    #[test]
    fn automatic_candidate_binding_accepts_exact_scope_only() {
        assert!(binding().check(&request()).is_ok());
        for field in 0..11 {
            let mut request = request();
            match field {
                0 => request.proposal_id.push('x'),
                1 => request.agreement_id.push('x'),
                2 => request.obligation_id.push('x'),
                3 => request.network_profile.push('x'),
                4 => request.manifest_digest.push('x'),
                5 => request.account_id.push('x'),
                6 => request.artifact_digest.push('x'),
                7 => request.effects_digest.push('x'),
                8 => request.maximum_debit = Amount::from_zatoshis(21).unwrap(),
                9 => request.fee = Amount::from_zatoshis(3).unwrap(),
                _ => request.transaction_expiry_height += 1,
            }
            assert!(binding().check(&request).is_err(), "substitution {field}");
        }
    }
}
