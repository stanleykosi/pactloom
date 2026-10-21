//! Closed, original-source export history. Descriptors are inert review data;
//! only the coordinated sealed recipient can open its original channel.
//! This schema never represents an installed native provider or permission.
use super::*;
use super::review_export_v1::{DurableReviewSourceV1, ExportExposure};
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
use wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_recipient_v1::CoordinatedRecipientIntentV1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatedDurableReviewExportScopeV1 {
    pub schema_version: u16,
    pub principal_id: String,
    pub proposal: FixedProposalIdentityV1,
    pub recipient: CoordinatedRecipientIntentV1,
    pub sources: Vec<DurableReviewSourceV1>,
    pub payload_digest: String,
    pub payload_length: u64,
}
/// A trusted embedding's fresh, exact ExportExact decision. This does not
/// authenticate a source/recipient and is never a serialized authority token.
pub trait LocalCoordinatedDurableReviewExportConsentV1 {
    fn permits(&self, scope: &CoordinatedDurableReviewExportScopeV1) -> bool;
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoordinatedExportIntentV1 {
    pub(crate) scope: CoordinatedDurableReviewExportScopeV1,
    pub(crate) exposure: ExportExposure,
}
use super::review_export_v3::{material_scopes, validate_capacity};
pub(crate) fn validate_recipient(roster: &Roster, candidate: &crate::CandidateView, scope: &CoordinatedDurableReviewExportScopeV1) -> Result<()> {
    let recipient = &scope.recipient;
    recipient.validate().map_err(|_| damaged())?;
    if scope.schema_version != 1 || scope.principal_id.is_empty() || scope.principal_id.len() > 128
        || scope.proposal.proposal_id != candidate.candidate_id
        || scope.proposal.proposal_digest != candidate.proposal_digest
        || scope.proposal.manifest_digest != candidate.manifest_digest
        || recipient.fixed != scope.proposal
        || recipient.request.proposal_binding != scope.proposal.proposal_binding
        || recipient.manifest_digest != candidate.manifest_digest
        || recipient.agreement_id != candidate.proposal.manifest.agreement.agreement_id
        || scope.payload_digest != recipient.payload_digest
        || scope.payload_length != recipient.payload_bytes
        || scope.sources != review_export_v1::sources(roster)?
        || scope.sources.len() != 2
        || recipient.material_scopes != material_scopes(roster)?
        || !candidate.proposal.manifest.participants.iter().any(|p| p.account_id == recipient.account_id && p.participant_id == recipient.participant_id)
    { return Err(denied()); }
    let own = roster.owners.get(&recipient.account_id).ok_or_else(damaged)?;
    // The original material is bound by its exact operation and complete request
    // digest, which already commits to its ORIGINAL capture receipt references.
    // CoordinatedRecipientIntentV1::original_* names the retained RECIPIENT admission rows,
    // joined by its validator to the current request, not those older capture
    // rows. The sealed recipient issuer independently validates the approved
    // original-to-current redisclosure; do not equate these distinct lineages.
    if own.outbox.request().operation_id != recipient.request.own_disclosure.operation_id
        || own.outbox.request_digest() != recipient.request.own_disclosure.expected_request_digest
        || recipient.request.current_disclosure.is_none()
    { return Err(denied()); }
    for intake in roster.owners.values() {
        if !intake.outbox.request().scope.permits_local_reviewer_account(&recipient.account_id)? {
            return Err(denied());
        }
    }
    Ok(())
}
pub(crate) fn validate_exports(roster: &Roster, candidate: &crate::CandidateView, frozen: Option<&serde_json::Value>) -> Result<()> {
    validate_capacity(roster)?;
    if roster.coordinated_review_exports_v1.is_empty() { return Ok(()); }
    let identity: FixedProposalIdentityV1 = serde_json::from_value(
        frozen.and_then(|v| v.get("identity")).cloned().ok_or_else(damaged)?
    ).map_err(|_| damaged())?;
    for (operation, intent) in &roster.coordinated_review_exports_v1 {
        if operation != &intent.scope.recipient.request.operation_id || intent.scope.proposal != identity {
            return Err(damaged());
        }
        validate_recipient(roster, candidate, &intent.scope)?;
    }
    Ok(())
}
