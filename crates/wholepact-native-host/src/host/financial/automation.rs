//! Explicit foreground request to the selected independently installed signer.
//! Private PCZT delivery remains the separate all-owner proof disclosure flow.
use super::*;
use sha2::{Digest, Sha256};
use wholepact_engine::proof_jobs::LocalProofJob;
use wholepact_signer::authority_bridge::automation_ipc::{
    AutomaticAuthorizationAttempt, AutomaticRequest,
};
use wholepact_store::automation::AutomaticAuthorizationOutcome;

impl Host {
    pub(in crate::host) fn financial_automatic_authorization(&self) -> Result<()> {
        self.financial_permission(Permission::AuthorizeRequest)?;
        let access = self.access()?;
        let profile = self.financial.as_ref().ok_or(Error::Locked)?;
        profile.inventory()?;
        let candidate_id = self.terminal.ask("Exact original candidate ID: ")?;
        let (_, candidate) = self.engine.candidate(access, &candidate_id)?;
        let participant_id = self.terminal.ask("Exact selected participant ID: ")?;
        let participant = candidate
            .proposal
            .manifest
            .participants
            .iter()
            .find(|participant| participant.participant_id == *participant_id)
            .ok_or(Error::Invalid)?;
        let job_id = self
            .terminal
            .ask("Original succeeded proof checkpoint job ID: ")?;
        let grant_id = self
            .terminal
            .ask("Exact existing native automation grant ID: ")?;
        id(&grant_id)?;
        let client = self
            .signer_review_clients
            .get(&(candidate_id.to_string(), participant.account_id.clone()))
            .ok_or(Error::Permission)?;
        let read = self.authority.proof_consent(
            &access.principal_id,
            &candidate_id,
            &candidate.manifest_digest,
            vec![
                wholepact_proof_jobs::LocalAction::InspectStatus,
                wholepact_proof_jobs::LocalAction::ReadPrivateArtifact,
            ],
        )?;
        let checkpoint = self.engine.load_candidate_proof_for_local_review(
            access,
            &candidate_id,
            LocalProofJob {
                job_id: &job_id,
                jobs: &profile.proof,
                consent: &read,
            },
        )?;
        let artifact_digest = hex::encode(Sha256::digest(checkpoint.pczt_bytes()));
        if checkpoint.summary().result_digest.as_deref() != Some(&artifact_digest) {
            return Err(Error::Invalid);
        }
        // Drop private bytes before the independent foreground native review.
        drop(checkpoint);
        self.terminal.confirm(&format!("Request one foreground automatic authorization under existing native grant {} from the EXACT installed signer session retained by proof-send-for-review for account {}, participant {}, candidate {}, artifact {}? This request transmits references only and cannot create or activate a native grant. The signer must independently verify its local wallet and exact artifact, then separately approve witness disclosure. This existing coordinator journal will retain Unknown and conservative exposure BEFORE the one-shot signing callback. Interrupted attempts retain their original IDs; no replacement, signature export, or transaction dispatch is authorized.", grant_id.as_str(), participant.account_id, participant_id.as_str(), candidate_id.as_str(), artifact_digest))?;
        let authorization = client
            .request_automatic_attempt(&AutomaticRequest {
                grant_id: grant_id.to_string(),
                candidate_id: candidate_id.to_string(),
                artifact_digest,
                accepted_manifest_digest: candidate.manifest_digest.clone(),
            })
            .map_err(|_| Error::Permission)?;
        let authorization = match authorization {
            AutomaticAuthorizationAttempt::Prepared(authorization) => authorization,
            AutomaticAuthorizationAttempt::Historical(history) => {
                self.financial_permission(Permission::AuthorizeRequest)?;
                let outcome = if history.retained.is_some() {
                    "Original signer result retained locally"
                } else {
                    "Original signer attempt remains unknown"
                };
                return self.terminal.message(&format!("{}. Authorization ID: {}. Original signing consent reference: {}. This is authenticated historical metadata only; no continuation was created, no signing callback ran and no coordinator exposure was cleared. Use the existing separately approved original-result recovery and redelivery routes.\n", outcome, history.authorization_id, history.original_consent_ref));
            }
        };
        // Host session authority and private-read consent are checked again after
        // the signer-native wait; no coordinator transaction spans that wait.
        self.financial_permission(Permission::AuthorizeRequest)?;
        let receipt = self.engine.authorize_candidate_automatically(
            access,
            &candidate_id,
            &participant_id,
            LocalProofJob {
                job_id: &job_id,
                jobs: &profile.proof,
                consent: &read,
            },
            authorization,
        )?;
        let outcome = match receipt.record.outcome {
            AutomaticAuthorizationOutcome::RetainedLocally => {
                "Original signer result retained locally"
            }
            AutomaticAuthorizationOutcome::Unknown => {
                "Original attempt outcome unknown; preserve conservative exposure and reconcile original history"
            }
            AutomaticAuthorizationOutcome::Declined => {
                "Original attempt declined; its precommitted exposure remains"
            }
        };
        self.terminal.message(&format!("{}. Authorization ID: {}. Original signing consent reference: {}. Historical replay: {}. No signature bytes were exported and no transaction was dispatched. Use the existing separately approved original-result recovery and redelivery routes.\n", outcome, receipt.record.request.authorization_id, receipt.record.authorization_verification_reference, receipt.replayed))
    }
}
