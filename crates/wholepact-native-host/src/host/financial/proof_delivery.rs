//! Exact saved proof to independently installed native reviewers. Every original
//! owner approves this distinct disclosure; construction consent is never reused.
use super::*;
use wholepact_engine::proof_jobs::LocalProofJob;
use wholepact_signer::{
    authority_bridge::{
        ipc::OriginalHistoryClient, proved_disclosure_ipc::ProvedDisclosureRequest,
        provider::InstalledSignerProvider,
    },
    ipc::PairScope,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofReviewer {
    account_id: String,
    participant_id: String,
    signer_socket: PathBuf,
    enrollment_ref: String,
    accepted_manifest_ref: String,
}
impl Host {
    pub(in crate::host) fn financial_proof_delivery(&mut self) -> Result<()> {
        self.financial_permission(Permission::Disclose)?;
        self.financial.as_ref().ok_or(Error::Locked)?.inventory()?;
        let candidate_id = self
            .terminal
            .ask("Exact candidate ID for original proof review: ")?;
        let job_id = self
            .terminal
            .ask("Original succeeded proof checkpoint job ID: ")?;
        let request_id = self
            .terminal
            .ask("Stable native review request ID (request only, not approval): ")?;
        self.financial_proof_delivery_exact(&candidate_id, &job_id, &request_id, None)
    }
    pub(super) fn financial_proof_delivery_exact(
        &mut self,
        candidate_id: &str,
        job_id: &str,
        request_id: &str,
        expected_artifact: Option<&str>,
    ) -> Result<()> {
        self.financial_permission(Permission::Disclose)?;
        let access = self.access()?;
        let profile = self.financial.as_ref().ok_or(Error::Locked)?;
        profile.inventory()?;
        let (_, candidate) = self.engine.candidate(access, candidate_id)?;
        id(request_id)?;
        let reviewers: Vec<ProofReviewer> = self.read_json(
            "Exact original account enrollments and installed reviewer signer endpoints JSON: ",
        )?;
        if reviewers.is_empty()
            || reviewers.len() > 8
            || reviewers.len() != candidate.proposal.manifest.participants.len()
            || self
                .signer_review_clients
                .len()
                .saturating_add(reviewers.len())
                > 64
        {
            return Err(Error::Invalid);
        }
        if reviewers.iter().any(|reviewer| {
            self.signer_review_clients
                .contains_key(&(candidate_id.to_string(), reviewer.account_id.clone()))
        }) {
            // A fresh pair has a different application identity and cannot inherit
            // the selected peer's native grant. Keep that exact session instead.
            return Err(Error::Permission);
        }
        let mut seen = BTreeSet::new();
        for reviewer in &reviewers {
            if !reviewer.signer_socket.is_absolute()
                || !seen.insert(&reviewer.account_id)
                || !candidate.proposal.manifest.participants.iter().any(|p| {
                    p.account_id == reviewer.account_id
                        && p.participant_id == reviewer.participant_id
                })
            {
                return Err(Error::Invalid);
            }
        }
        let read = self.authority.proof_consent(
            &access.principal_id,
            candidate_id,
            &candidate.manifest_digest,
            vec![
                wholepact_proof_jobs::LocalAction::InspectStatus,
                wholepact_proof_jobs::LocalAction::ReadPrivateArtifact,
            ],
        )?;
        let checkpoint = self.engine.load_candidate_proof_for_local_review(
            access,
            candidate_id,
            LocalProofJob {
                job_id,
                jobs: &profile.proof,
                consent: &read,
            },
        )?;
        let review =
            wholepact_protocol::review::verify_review(checkpoint.pczt_bytes(), checkpoint.policy())
                .map_err(|_| Error::Invalid)?;
        use sha2::Digest;
        let artifact_digest = hex::encode(sha2::Sha256::digest(checkpoint.pczt_bytes()));
        if expected_artifact.is_some_and(|expected| expected != artifact_digest)
            || checkpoint.summary().result_digest.as_deref() != Some(&artifact_digest)
            || review.review_binding() != checkpoint.scope().review_binding
        {
            return Err(Error::Invalid);
        }
        let mut clients = Vec::new();
        for reviewer in &reviewers {
            self.terminal.confirm(&format!("Pair installed reviewer signer {} for account {}. A separate native disclosure decision from EVERY original owner must approve exact proved artifact {} and the complete actual recipient roster before any PCZT bytes are sent. The proof contains private viewing keys, notes, witnesses and outputs; disclosure persists. No approval or signature is implied by a review request.", reviewer.signer_socket.display(), reviewer.account_id, artifact_digest))?;
            clients.push(
                OriginalHistoryClient::pair(
                    InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
                    &reviewer.signer_socket,
                    "wholepact-native-proof-review",
                    PairScope {
                        account_id: reviewer.account_id.clone(),
                        agreement_id: candidate.proposal.manifest.agreement.agreement_id.clone(),
                        participant_id: reviewer.participant_id.clone(),
                        manifest_digest: candidate.manifest_digest.clone(),
                        history_read: false,
                        authorization_export: false,
                        preconstruction_export: false,
                    },
                )
                .map_err(|_| Error::Permission)?,
            );
        }
        let recipients = clients
            .iter()
            .map(|client| {
                client
                    .proved_disclosure_recipient()
                    .map_err(|_| Error::Permission)
            })
            .collect::<Result<Vec<_>>>()?;
        let requests = reviewers
            .iter()
            .map(|reviewer| ProvedDisclosureRequest {
                schema_version: 1,
                proposal: candidate.proposal.clone(),
                account_id: reviewer.account_id.clone(),
                participant_id: reviewer.participant_id.clone(),
                enrollment_ref: reviewer.enrollment_ref.clone(),
                accepted_manifest_ref: reviewer.accepted_manifest_ref.clone(),
                proved_artifact_sha256: artifact_digest.clone(),
                review_binding: review.review_binding().into(),
                recipients: recipients.clone(),
                purpose: "private_proved_pczt_export_and_exact_review".into(),
            })
            .collect::<Vec<_>>();
        let leases = clients
            .iter()
            .zip(&requests)
            .map(|(client, request)| {
                client
                    .request_proved_disclosure(request)
                    .map_err(|_| Error::Permission)
            })
            .collect::<Result<Vec<_>>>()?;
        for (index, client) in clients.iter().enumerate() {
            for (lease, request) in leases.iter().zip(&requests) {
                if lease.request() != request {
                    return Err(Error::Permission);
                }
                lease.check_current().map_err(|_| Error::Permission)?;
            }
            if client
                .proved_disclosure_recipient()
                .map_err(|_| Error::Permission)?
                != recipients[index]
            {
                return Err(Error::Permission);
            }
            // Revalidate the original exact read gate before each sensitive send.
            use wholepact_proof_jobs::LocalProofConsent;
            if !read.permits(
                checkpoint.scope(),
                wholepact_proof_jobs::LocalAction::ReadPrivateArtifact,
            ) {
                return Err(Error::Permission);
            }
            client
                .request_review(
                    request_id,
                    &candidate.manifest_digest,
                    checkpoint.pczt_bytes(),
                )
                .map_err(|_| Error::Permission)?;
            for lease in &leases {
                lease.check_current().map_err(|_| Error::Permission)?;
            }
            self.terminal.message(&format!("Exact proof review request acknowledged by installed signer for account {}. Review completion and signature release are not established.\n", reviewers[index].account_id))?;
        }
        drop(leases);
        for (reviewer, client) in reviewers.into_iter().zip(clients) {
            self.signer_review_clients
                .insert((candidate_id.to_string(), reviewer.account_id), client);
        }
        self.terminal.message("All selected installed signers acknowledged the exact private proof review request under every original owner's disclosure lease. The exact selected peer sessions are retained until financial-close, revoke, lock or expiry. Complete each signer's separate local wallet/witness/exact spend review; signatures are never approved by this host command.\n")
    }
}
