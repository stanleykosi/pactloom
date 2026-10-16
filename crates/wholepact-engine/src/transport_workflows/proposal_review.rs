//! Native-only authenticated proposal intake into the ordinary review journal.
//! Independently supplied private policy and action mappings are never decoded
//! from the transport artifact or accepted over HTTP. This grants no release.
use super::*;
use crate::{candidates::CandidateReview, participant_records::RecordStoreBinding};
use std::collections::BTreeMap;
use wholepact_protocol::{
    construction::{InputActionMapping, OutputActionMapping},
    review::{verify_review, ReviewPolicy},
    review_manifest::{policy_fingerprint, verify_manifest_policy},
};
use wholepact_transport::{DisclosurePreview, MailboxProtection, MessageContext};

const PROCESSOR: &str = "engine-proposal-economic-review-v1";
const REQUEST_FIELD: &str = "proposal_review_request_v1";
const PCZT_FIELD: &str = "proposal_pczt_v2";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportProposalReview {
    pub schema_version: u16,
    pub expected_agreement_revision: u64,
    pub manifest_digest: String,
}
#[derive(Clone, PartialEq, Eq)]
pub struct ProposalTransportReviewScope {
    pub store: RecordStoreBinding,
    pub principal_id: String,
    pub context: MessageContext,
    pub sender_key_fingerprint: String,
    pub recipient_key_fingerprint: String,
    pub preview_digest: String,
    pub artifact_digest: String,
    pub manifest_digest: String,
    pub policy_fingerprint: String,
    pub mapping_fingerprint: String,
    pub expected_agreement_revision: u64,
}
/// Native guard fences current source permission, privacy policy and revocation
/// through engine commit and inbox completion. Expiry checking alone is not a
/// revocation fence. No implementation or issuer is enabled by default.
pub trait ProposalTransportReviewLease {
    fn scope(&self) -> &ProposalTransportReviewScope;
    fn expires_at(&self) -> &Timestamp;
    fn check_current(&self) -> Result<()>;
}
pub trait ProposalTransportReviewAuthority {
    fn acquire<'a>(
        &'a self,
        requested: &ProposalTransportReviewScope,
        preview: &DisclosurePreview,
    ) -> Result<Box<dyn ProposalTransportReviewLease + 'a>>;
}
pub struct LocalProposalTransportReview<'a> {
    pub policy: &'a ReviewPolicy,
    pub input_actions: &'a [InputActionMapping],
    pub output_actions: &'a [OutputActionMapping],
    pub authority: &'a dyn ProposalTransportReviewAuthority,
}

/// Pure native preparation. Caller separately obtains exact disclosure consent
/// and seals into the recipient-scoped outbox. No private fields are logged.
pub fn prepare_proposal_review_message(
    request: ExportRequest,
    message: TransportProposalReview,
    pczt_bytes: Vec<u8>,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedExport> {
    validate_message(&message)?;
    if request.context.artifact_kind != ArtifactKind::Proposal {
        return Err(invalid_source());
    }
    wholepact_protocol::inspect_candidate(&pczt_bytes).map_err(|_| invalid_source())?;
    prepare_export(
        request,
        vec![
            DisclosureField::new(
                REQUEST_FIELD,
                serde_json::to_vec(&message).map_err(|_| internal())?,
            )
            .map_err(transport_error)?,
            DisclosureField::new(PCZT_FIELD, pczt_bytes).map_err(transport_error)?,
        ],
        sender,
        recipient,
        now,
    )
    .map_err(transport_error)
}

impl Engine {
    /// Authenticate current owner/source authority even for a completed replay.
    /// Commit a non-authorizing economic review, then complete the inbox ticket.
    /// A crash between these journals is reconciled under the same stable command.
    pub fn import_proposal_review_transport(
        &self,
        access: &Access,
        inbox: &mut SqliteReplayLedger,
        received: &ReceivedArtifact,
        local: LocalProposalTransportReview<'_>,
    ) -> Result<Mutation> {
        self.require_protected_transport_store()?;
        let store = self.protected_record_store_binding()?;
        if inbox.protection() != MailboxProtection::Encrypted {
            return Err(ApiError::new(
                "ENCRYPTED_STORAGE_REQUIRED",
                "Private proposal intake requires a fully encrypted inbox",
            ));
        }
        let preview = received.preview();
        let id = &preview.context.agreement_id;
        self.require_current_agreement(id)?;
        let mut envelope = self.load(access, id)?;
        owner(&envelope, access)?;
        let fields = received.fields();
        if preview.context.artifact_kind != ArtifactKind::Proposal || fields.len() != 2 {
            return Err(invalid_source());
        }
        let request_bytes = fields
            .iter()
            .find(|f| f.name() == REQUEST_FIELD)
            .ok_or_else(invalid_source)?
            .bytes();
        let bytes = fields
            .iter()
            .find(|f| f.name() == PCZT_FIELD)
            .ok_or_else(invalid_source)?
            .bytes();
        let request: TransportProposalReview =
            serde_json::from_slice(request_bytes).map_err(|_| invalid_source())?;
        validate_message(&request)?;
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|c| c.candidate_id == preview.context.proposal_id)
            .ok_or_else(not_found)?
            .clone();
        let proposal = candidate.verified_snapshot()?;
        if preview.context.network_profile_id != envelope.view.agreement.network_profile_id
            || preview.context.proposal_revision != proposal.manifest().agreement.revision as u64
            || request.manifest_digest != proposal.manifest_digest()
        {
            return Err(invalid_source());
        }
        verify_manifest_policy(
            &proposal,
            local.policy,
            local.input_actions,
            local.output_actions,
        )
        .map_err(|_| invalid_source())?;
        let scope = ProposalTransportReviewScope {
            store,
            principal_id: access.principal_id.clone(),
            context: preview.context.clone(),
            sender_key_fingerprint: preview.sender_key_fingerprint.clone(),
            recipient_key_fingerprint: preview.recipient_key_fingerprint.clone(),
            preview_digest: preview.digest().map_err(transport_error)?,
            artifact_digest: hex::encode(Sha256::digest(bytes)),
            manifest_digest: candidate.manifest_digest.clone(),
            policy_fingerprint: policy_fingerprint(local.policy),
            mapping_fingerprint: hash_domain(
                b"wholepact:local-review-action-mapping:v1\0",
                &json!({
                    "inputs":local.input_actions.iter().map(|i| json!([i.input_id,i.account_id,i.action_index])).collect::<Vec<_>>(),
                    "outputs":local.output_actions.iter().map(|o| json!([o.output_id,o.action_index])).collect::<Vec<_>>(),
                }),
            )?,
            expected_agreement_revision: request.expected_agreement_revision,
        };
        let lease = local.authority.acquire(&scope, preview)?;
        if lease.scope() != &scope {
            return Err(authority_denied());
        }
        check_lease(lease.as_ref())?;
        self.require_protected_transport_store()?;
        self.require_current_agreement(id)?;
        owner(&self.load(access, id)?, access)?;
        let ticket = inbox
            .domain_import_ticket(received, PROCESSOR)
            .map_err(transport_error)?;
        let command = context(
            access,
            ticket.idempotency_key(),
            "import_proposal_economic_review",
            id,
            Some(request.expected_agreement_revision),
            &json!({ "candidate_id":candidate.candidate_id,"manifest_digest":scope.manifest_digest,"artifact_digest":scope.artifact_digest,"preview_digest":scope.preview_digest,"policy_fingerprint":scope.policy_fingerprint,"mapping_fingerprint":scope.mapping_fingerprint }),
        )?;
        if let Some(replay) = self.replay(access, &command)? {
            check_lease(lease.as_ref())?;
            let result = finish_import(inbox, &ticket, replay)?;
            check_lease(lease.as_ref())?;
            return Ok(result);
        }
        if ticket.completed().is_some() {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Proposal inbox completion has no matching engine operation",
            ));
        }
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if now < preview.order.issued_at.unix_seconds()
            || now >= preview.order.expires_at.unix_seconds()
        {
            return Err(ApiError::new(
                "INVALID_TIME",
                "Historical proposal intake cannot create a new review operation",
            ));
        }
        candidates::check_revision(&envelope, request.expected_agreement_revision)?;
        candidates::check_current_terms(&envelope.view, proposal.manifest())?;
        if envelope
            .view
            .candidates
            .iter()
            .map(|c| c.reviews.len())
            .sum::<usize>()
            >= MAX_REVIEWS
        {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Candidate review history is full",
            ));
        }
        let verified = verify_review(bytes, local.policy).map_err(|_| {
            ApiError::new(
                "CANDIDATE_VERIFICATION_FAILED",
                "Imported proposal failed exact maintained economic verification",
            )
        })?;
        if verified.fee_zatoshis() != proposal.manifest().transaction_fee.as_zatoshis()
            || verified.net_debits_zatoshis().len() != proposal.manifest().participants.len()
        {
            return Err(internal());
        }
        let mut debits = BTreeMap::new();
        for (participant, actual) in proposal
            .manifest()
            .participants
            .iter()
            .zip(verified.net_debits_zatoshis())
        {
            if proposal
                .accounting()
                .participant_net_debits
                .get(&participant.participant_id)
                .map(|a| a.as_zatoshis())
                != Some(*actual)
            {
                return Err(invalid_source());
            }
            debits.insert(participant.participant_id.clone(), actual.to_string());
        }
        let report = CandidateReview {
            report_id: Uuid::new_v4().to_string(), candidate_id: candidate.candidate_id.clone(), manifest_digest: candidate.manifest_digest.clone(), checked_at: crate::now(), status: "economic_terms_verified_only".into(), scope: "authenticated_transport_local_policy_economic_review".into(), artifact_digest: Some(scope.artifact_digest.clone()), effects_commitment: Some(verified.shielded_sighash().into()), review_binding: Some(verified.review_binding().into()), exact_fee_zatoshis: verified.fee_zatoshis().to_string(), participant_net_debits_zatoshis: debits,
            economic_terms_verified: true, account_associations_authenticated: false, disclosure_consents_authenticated: false, human_approval: "not_requested".into(), chain_validated: false, authorization_allowed: false, distribution_allowed: false, artifact_persistence: "authenticated_encrypted_inbox_only".into(), blocking_reasons: vec!["Transport source permission is separate from account identity, input-label provenance and all-participant disclosure consent".into(), "No human approval, signing authority, release, independent chain evidence or submission is established".into()],
        };
        envelope
            .view
            .candidates
            .iter_mut()
            .find(|c| c.candidate_id == candidate.candidate_id)
            .ok_or_else(not_found)?
            .reviews
            .push(report);
        check_lease(lease.as_ref())?;
        self.require_protected_transport_store()?;
        self.require_current_agreement(id)?;
        owner(&self.load(access, id)?, access)?;
        let mutation = self.commit(
            &command,
            id,
            request.expected_agreement_revision,
            envelope,
            "imported_candidate_economics_reviewed",
        )?;
        check_lease(lease.as_ref())?;
        let result = finish_import(inbox, &ticket, mutation)?;
        check_lease(lease.as_ref())?;
        Ok(result)
    }
}
fn validate_message(message: &TransportProposalReview) -> Result<()> {
    if message.schema_version != 1
        || message.expected_agreement_revision == 0
        || message.manifest_digest.len() != 64
        || !message
            .manifest_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid_source());
    }
    Ok(())
}
fn check_lease(lease: &dyn ProposalTransportReviewLease) -> Result<()> {
    if lease.expires_at().unix_seconds() <= OffsetDateTime::now_utc().unix_timestamp() {
        return Err(authority_denied());
    }
    lease.check_current()
}
fn authority_denied() -> ApiError {
    ApiError::new(
        "PERMISSION_DENIED",
        "Current exact proposal intake authority is unavailable",
    )
}
fn invalid_source() -> ApiError {
    ApiError::new("INVALID_TERMS", "Imported proposal, complete local action mapping or independent policy differs from accepted terms")
}
