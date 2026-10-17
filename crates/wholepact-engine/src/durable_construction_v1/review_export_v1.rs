//! Exact native reviewer export. A data-only audience is not a recipient: the
//! public entry accepts only the installed signer's sealed, metadata-only
//! handshake. It loads all private bytes from original authenticated intake and
//! commits a disclosed-or-unknown intent BEFORE the first private send.
use super::*;
use crate::proof_jobs::LocalProofJob;
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
use wholepact_signer::authority_bridge::{
    durable_review_ipc_v1::{
        DurableReviewOutputActionV1, DurableReviewPayloadV1, DurableReviewRecipientV1,
        PreparedDurableReviewDeliveryV1, MAX_DURABLE_REVIEW_PAYLOAD_BYTES_V1,
    },
    BridgeError,
};

const MAX_EXPORT_INTENTS: usize = 8;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableReviewSourceV1 {
    pub account_id: String,
    pub outbox_reference: String,
    pub request_digest: String,
    pub material_digest: String,
    pub scope_digest: String,
}

/// Display/consent scope only. Neither this descriptor nor a saved true result
/// authenticates a recipient, authorizes signing, or revives former permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableReviewExportScopeV1 {
    pub schema_version: u16,
    pub principal_id: String,
    pub proposal: FixedProposalIdentityV1,
    pub recipient: DurableReviewRecipientV1,
    pub sources: Vec<DurableReviewSourceV1>,
    pub payload_digest: String,
    pub payload_length: u64,
}

/// Fresh explicit local permission to irreversibly share full viewing authority,
/// note/witness data and exact candidate with this actual installed reviewer.
/// No default-allow implementation is provided.
pub trait LocalDurableReviewExportConsentV1 {
    fn permits(&self, scope: &DurableReviewExportScopeV1) -> bool;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExportIntent {
    scope: DurableReviewExportScopeV1,
    // Deliberately never changed to "not shared" on timeout, cancellation or
    // process exit. A successful immediate reply is not spend approval either.
    exposure: ExportExposure,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExportExposure {
    DisclosedOrUnknown,
}

fn sources(roster: &Roster) -> Result<Vec<DurableReviewSourceV1>> {
    roster
        .owners
        .iter()
        .map(|(account, intake)| {
            Ok(DurableReviewSourceV1 {
                account_id: account.clone(),
                outbox_reference: intake.outbox.reference().into(),
                request_digest: intake.outbox.request_digest().into(),
                material_digest: intake.outbox.material_digest().into(),
                scope_digest: intake.outbox.request().scope.digest()?,
            })
        })
        .collect()
}

pub(super) fn validate_exports(roster: &Roster, candidate: &crate::CandidateView) -> Result<()> {
    if roster.review_exports.len() > MAX_EXPORT_INTENTS {
        return Err(damaged());
    }
    for (operation, intent) in &roster.review_exports {
        let s = &intent.scope;
        if s.schema_version != 1
            || operation != &s.recipient.request.operation_id
            || s.principal_id.is_empty()
            || s.principal_id.len() > 128
            || s.proposal.proposal_id != candidate.candidate_id
            || s.proposal.proposal_digest != candidate.proposal_digest
            || s.proposal.manifest_digest != candidate.manifest_digest
            || s.recipient.request.proposal_binding != s.proposal.proposal_binding
            || s.recipient.manifest_digest != candidate.manifest_digest
            || s.recipient.agreement_id != candidate.proposal.manifest.agreement.agreement_id
            || !valid_digest(&s.payload_digest)
            || s.payload_length == 0
            || s.payload_length > MAX_DURABLE_REVIEW_PAYLOAD_BYTES_V1 as u64
            || s.sources != sources(roster)?
            || s.sources.len() != 2
        {
            return Err(damaged());
        }
        validate_recipient(roster, candidate, s)?;
    }
    Ok(())
}

pub(super) fn validate_export_identity(
    roster: &Roster,
    frozen: Option<&serde_json::Value>,
) -> Result<()> {
    if roster.review_exports.is_empty() {
        return Ok(());
    }
    let identity: FixedProposalIdentityV1 = serde_json::from_value(
        frozen
            .and_then(|v| v.get("identity"))
            .cloned()
            .ok_or_else(damaged)?,
    )
    .map_err(|_| damaged())?;
    if roster
        .review_exports
        .values()
        .any(|i| i.scope.proposal != identity)
    {
        return Err(damaged());
    }
    Ok(())
}

fn validate_recipient(
    roster: &Roster,
    candidate: &crate::CandidateView,
    scope: &DurableReviewExportScopeV1,
) -> Result<()> {
    let recipient = &scope.recipient;
    recipient.request.validate().map_err(|_| damaged())?;
    if recipient.version != 1
        || !valid_digest(&recipient.account_id)
        || !valid_digest(&recipient.provider_enrollment_reference)
        || !valid_digest(&recipient.signer_process_instance)
        || !valid_digest(&recipient.local_grant_id)
        || !valid_digest(&recipient.local_channel_digest)
    {
        return Err(damaged());
    }
    if !candidate.proposal.manifest.participants.iter().any(|p| {
        p.account_id == recipient.account_id && p.participant_id == recipient.participant_id
    }) || recipient.manifest_digest != candidate.manifest_digest
        || recipient.agreement_id != candidate.proposal.manifest.agreement.agreement_id
        || recipient.request.proposal_binding != scope.proposal.proposal_binding
    {
        return Err(denied());
    }
    for intake in roster.owners.values() {
        if !intake
            .outbox
            .request()
            .scope
            .permits_local_reviewer_account(&recipient.account_id)?
        {
            return Err(denied());
        }
    }
    let own = roster
        .owners
        .get(&recipient.account_id)
        .ok_or_else(damaged)?;
    if own.outbox.request().operation_id != recipient.request.own_disclosure.operation_id
        || own.outbox.request_digest() != recipient.request.own_disclosure.expected_request_digest
    {
        return Err(denied());
    }
    Ok(())
}

impl Engine {
    /// Export only the exact fixed proposal and both originally admitted owner
    /// materials to a sealed authenticated installed native reviewer. This
    /// method is intentionally NOT a raw bytes/recipient DTO transport API.
    ///
    /// The immutable intent is committed before any private byte. On send or
    /// verification failure preserve that operation as disclosed-or-unknown.
    /// Retry can only redeliver identical bytes to the exact same live recipient;
    /// a genuinely new recipient session requires a new explicit export intent.
    #[allow(clippy::too_many_arguments)]
    pub fn deliver_durable_proposal_for_native_review_v1(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalProofJob<'_>,
        recipient: PreparedDurableReviewDeliveryV1<'_>,
        material_consent: &dyn LocalDurableMaterialConsentV1,
        export_consent: &dyn LocalDurableReviewExportConsentV1,
    ) -> Result<Mutation> {
        recipient.check_current().map_err(|_| denied())?;
        let proof_consent = local.consent;
        let (mut envelope, checkpoint, fixed, mappings) =
            self.load_durable_review_export_inputs_v1(access, candidate_id, local)?;
        crate::planning::check_proposer(&envelope, access)?;
        if envelope.view.cancellation_requested {
            return Err(denied());
        }
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|c| c.candidate_id == candidate_id)
            .cloned()
            .ok_or_else(damaged)?;
        let mut roster = self.durable_roster(&envelope, candidate_id)?;
        if roster.owners.len() != 2 {
            return Err(damaged());
        }
        for intake in roster.owners.values() {
            self.check_durable_material(
                access,
                intake,
                material_consent,
                DurableMaterialActionV1::ExportForLocalNativeReview,
            )?;
        }
        let payload = DurableReviewPayloadV1 {
            version: 1,
            unsigned_pczt_hex: hex::encode(checkpoint.private_unsigned_pczt_bytes()),
            proved_pczt_hex: hex::encode(checkpoint.pczt_bytes()),
            contributions: roster.owners.values().map(|i| i.outbox.clone()).collect(),
            output_actions: mappings
                .iter()
                .map(|m| DurableReviewOutputActionV1 {
                    output_id: m.output_id.clone(),
                    action_index: m.action_index,
                })
                .collect(),
        };
        let encoded = payload.encode().map_err(|_| damaged())?;
        let scope = DurableReviewExportScopeV1 {
            schema_version: 1,
            principal_id: access.principal_id.clone(),
            proposal: fixed.identity().clone(),
            recipient: recipient.descriptor().clone(),
            sources: sources(&roster)?,
            payload_digest: payload.digest().map_err(|_| damaged())?,
            payload_length: encoded.len().try_into().map_err(|_| damaged())?,
        };
        drop(encoded);
        validate_recipient(&roster, &candidate, &scope)?;
        let gate = ExportGate {
            engine: self,
            access,
            candidate_id,
            scope: &scope,
            material: material_consent,
            export: export_consent,
            proof: proof_consent,
            checkpoint_scope: checkpoint.scope(),
        };
        gate.check(false)?;
        recipient.check_current().map_err(|_| denied())?;
        let command = crate::context(
            access,
            key,
            "export_durable_native_review_v1",
            candidate_id,
            Some(revision),
            &scope,
        )?;
        let mutation = if let Some(replay) = self.replay(access, &command)? {
            replay
        } else {
            crate::candidates::check_revision(&envelope, revision)?;
            if roster
                .review_exports
                .contains_key(&scope.recipient.request.operation_id)
                || roster.review_exports.len() >= MAX_EXPORT_INTENTS
            {
                return Err(ApiError::new(
                    "CONFLICT",
                    "An exact native-review disclosure operation already exists or its bounded capacity is exhausted",
                ));
            }
            roster.review_exports.insert(
                scope.recipient.request.operation_id.clone(),
                ExportIntent {
                    scope: scope.clone(),
                    exposure: ExportExposure::DisclosedOrUnknown,
                },
            );
            validate_exports(&roster, &candidate)?;
            envelope.durable_construction_v1.insert(
                candidate_id.into(),
                serde_json::to_value(&roster).map_err(|_| damaged())?,
            );
            gate.check(false)?;
            recipient.check_current().map_err(|_| denied())?;
            self.commit(
                &command,
                &candidate.proposal.manifest.agreement.agreement_id,
                revision,
                envelope,
                "durable_native_review_disclosure_intent",
            )?
        };
        // Reload the committed ORIGINAL operation on both fresh and idempotent
        // paths. A returned/replayed mutation alone is not export permission.
        gate.check(true)?;
        let check = || gate.check(true).map_err(|_| BridgeError::Permission);
        recipient.deliver(&payload, &check).map_err(|_| {
            let mut error = ApiError::new(
                "DISCLOSURE_UNKNOWN",
                "The exact native-review disclosure is retained; some or all private bytes may have been shared. Preserve the original operation and do not claim cancellation recalled them",
            );
            error.details = Box::new(serde_json::json!({
                "operation_id": scope.recipient.request.operation_id,
                "payload_digest": scope.payload_digest,
                "disclosure_state": "disclosed_or_unknown"
            }));
            error
        })?;
        // An acknowledged mathematical import is neither native spending
        // approval nor a reduction of the permanent privacy exposure record.
        Ok(mutation)
    }
}

struct ExportGate<'a> {
    engine: &'a Engine,
    access: &'a Access,
    candidate_id: &'a str,
    scope: &'a DurableReviewExportScopeV1,
    material: &'a dyn LocalDurableMaterialConsentV1,
    export: &'a dyn LocalDurableReviewExportConsentV1,
    proof: &'a dyn LocalProofConsent,
    checkpoint_scope: &'a CheckpointScope,
}
impl ExportGate<'_> {
    fn source_current(&self, require_committed: bool) -> Result<()> {
        let (view, candidate) = self.engine.candidate(self.access, self.candidate_id)?;
        self.engine
            .require_current_agreement(&view.agreement.agreement_id)?;
        let envelope = self
            .engine
            .load(self.access, &view.agreement.agreement_id)?;
        if envelope.view.cancellation_requested
            || self.scope.principal_id != self.access.principal_id
        {
            return Err(denied());
        }
        let current_identity: FixedProposalIdentityV1 = serde_json::from_value(
            envelope
                .durable_proposals_v1
                .get(self.candidate_id)
                .and_then(|v| v.get("identity"))
                .cloned()
                .ok_or_else(damaged)?,
        )
        .map_err(|_| damaged())?;
        if current_identity != self.scope.proposal {
            return Err(damaged());
        }
        let roster = self.engine.durable_roster(&envelope, self.candidate_id)?;
        if sources(&roster)? != self.scope.sources || roster.owners.len() != 2 {
            return Err(damaged());
        }
        validate_recipient(&roster, &candidate, self.scope)?;
        if require_committed {
            let saved = roster
                .review_exports
                .get(&self.scope.recipient.request.operation_id)
                .ok_or_else(damaged)?;
            if saved.scope != *self.scope {
                return Err(damaged());
            }
        }
        for intake in roster.owners.values() {
            self.engine.check_durable_material(
                self.access,
                intake,
                self.material,
                DurableMaterialActionV1::ExportForLocalNativeReview,
            )?;
        }
        Ok(())
    }
    fn check(&self, require_committed: bool) -> Result<()> {
        self.source_current(require_committed)?;
        if !self
            .proof
            .permits(self.checkpoint_scope, LocalAction::ReadPrivateArtifact)
            || !self.export.permits(self.scope)
        {
            return Err(denied());
        }
        self.source_current(require_committed)
    }
}
