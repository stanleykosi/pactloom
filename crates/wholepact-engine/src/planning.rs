//! Nonbinding roster selection and immutable terms comparison.
//!
//! Selection expresses an organizer's proposed roster. It never locks funds,
//! verifies identity or account ownership, grants consent, or permits signing.
use super::*;
use wholepact_core::{Amount, FundingPolicy};

pub const MAX_COMPARISON_BYTES: usize = 1_048_576;
pub const MAX_COMPARISON_CHANGES: usize = 20;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterSelectionRequest {
    pub selected_intent_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalChange {
    pub field: String,
    pub older: Value,
    pub newer: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalComparison {
    pub schema_version: u32,
    pub agreement_id: String,
    pub older_proposal_id: String,
    pub newer_proposal_id: String,
    pub older_manifest_digest: String,
    pub newer_manifest_digest: String,
    pub material_change: bool,
    pub renewed_review_required: bool,
    pub changes: Vec<ProposalChange>,
    pub scope: String,
    pub signable: bool,
    pub message: String,
}

impl Engine {
    /// Select complete, unchanged intent amounts for one exact funding target.
    /// A failed selection leaves all statuses and historical snapshots intact.
    pub fn select_roster(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: RosterSelectionRequest,
    ) -> Result<Mutation> {
        validate_selection_request(&request)?;
        let command = context(
            access,
            key,
            "select_roster",
            agreement_id,
            Some(revision),
            &request,
        )?;
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        let mut envelope = self.load(access, agreement_id)?;
        check_proposer(&envelope, access)?;
        candidates::check_revision(&envelope, revision)?;
        check_planning_window(&envelope.view, OffsetDateTime::now_utc())?;
        let selected: BTreeSet<_> = request
            .selected_intent_ids
            .iter()
            .map(String::as_str)
            .collect();
        let intents: Vec<_> = selected
            .iter()
            .map(|id| {
                envelope
                    .view
                    .intents
                    .iter()
                    .find(|i| &i.intent_id.as_str() == id)
                    .ok_or_else(|| {
                        ApiError::new(
                            "INVALID_TERMS",
                            "Selected intent was not found in this agreement",
                        )
                    })
            })
            .collect::<Result<_>>()?;
        check_selected_intents(
            &envelope.view.agreement,
            &intents,
            OffsetDateTime::now_utc(),
        )?;
        for intent in &mut envelope.view.intents {
            if eligible_status(intent.status) {
                intent.status = if selected.contains(intent.intent_id.as_str()) {
                    IntentStatus::Selected
                } else {
                    IntentStatus::Waitlisted
                };
            }
        }
        envelope.view.roster_selected = true;
        self.commit(
            &command,
            agreement_id,
            revision,
            envelope,
            "nonbinding_roster_selected",
        )
    }

    /// Compare immutable terms snapshots within the caller's local access
    /// scope. This read does not refresh a review, amend a proposal, or create
    /// signing permission. A local digest is not remote provenance evidence.
    pub fn compare_proposals(
        &self,
        access: &Access,
        older_id: &str,
        newer_id: &str,
    ) -> Result<ProposalComparison> {
        let (older_view, older) = self.proposal(access, older_id)?;
        let (newer_view, newer) = self.proposal(access, newer_id)?;
        if older_view.agreement.agreement_id != newer_view.agreement.agreement_id {
            return Err(ApiError::new(
                "INVALID_TERMS",
                "Compare proposals from the same agreement",
            ));
        }
        if older.revision > newer.revision {
            return Err(ApiError::new(
                "INVALID_REQUEST",
                "The older proposal must precede the newer proposal",
            ));
        }
        let older_terms = checked_snapshot(&older_view, &older)?;
        let newer_terms = checked_snapshot(&newer_view, &newer)?;
        let old = serde_json::to_value(older_terms).map_err(|_| internal())?;
        let new = serde_json::to_value(newer_terms).map_err(|_| internal())?;
        let mut changes = Vec::new();
        // Fixed schema paths bound work and make all material fields visible.
        // Whole arrays remain intact, so additions/removals cannot hide behind
        // a positional diff, truncation, or a misleading partial summary.
        for field in [
            "schema_version",
            "agreement.schema_version",
            "agreement.agreement_id",
            "agreement.obligation_id",
            "agreement.revision",
            "agreement.purpose",
            "agreement.organizer_identity",
            "agreement.network_profile_id",
            "agreement.recipients",
            "agreement.funding_policy",
            "agreement.fee_policy",
            "agreement.privacy_profile",
            "agreement.coordination_deadline",
            "agreement.confirmation_policy",
            "agreement.extensions",
            "intents",
            "roster_selected",
            "scope",
        ] {
            let pointer = format!("/{}", field.replace('.', "/"));
            let before = old.pointer(&pointer).ok_or_else(snapshot_corrupt)?;
            let after = new.pointer(&pointer).ok_or_else(snapshot_corrupt)?;
            if before != after {
                changes.push(ProposalChange {
                    field: field.into(),
                    older: before.clone(),
                    newer: after.clone(),
                });
            }
        }
        let renewed_review_required = older_id != newer_id;
        let comparison = ProposalComparison {
            schema_version: 1,
            agreement_id: older_view.agreement.agreement_id,
            older_proposal_id: older.proposal_id,
            newer_proposal_id: newer.proposal_id,
            older_manifest_digest: older.manifest_digest,
            newer_manifest_digest: newer.manifest_digest,
            material_change: !changes.is_empty(),
            renewed_review_required,
            changes,
            scope: "nonbinding_terms_only".into(),
            signable: false,
            message: if renewed_review_required {
                "This proposal requires fresh review. Earlier reviews and approvals do not transfer. These are nonbinding terms; funds, receiving instructions, identity and transaction effects are not verified."
            } else {
                "This is the same nonbinding terms snapshot. Comparison grants no approval and cannot establish funds, receiving instructions, identity or transaction effects."
            }.into(),
        };
        bounded_comparison(comparison)
    }

    /// Compare immutable candidate claims, including account allocations,
    /// fees, inputs, outputs, and transaction expiry. Reviews and authorizations
    /// remain bound to their original candidate and are never copied forward.
    pub fn compare_candidates(
        &self,
        access: &Access,
        older_id: &str,
        newer_id: &str,
    ) -> Result<ProposalComparison> {
        let (older_view, older) = self.candidate(access, older_id)?;
        let (newer_view, newer) = self.candidate(access, newer_id)?;
        if older_view.agreement.agreement_id != newer_view.agreement.agreement_id {
            return Err(ApiError::new(
                "INVALID_TERMS",
                "Compare candidates from the same agreement",
            ));
        }
        let older_index = checked_candidate_lineage(&older_view, &older)?;
        let newer_index = checked_candidate_lineage(&newer_view, &newer)?;
        if older_index > newer_index {
            return Err(ApiError::new(
                "INVALID_REQUEST",
                "The older candidate must precede the newer candidate",
            ));
        }
        let old = serde_json::to_value(&older.proposal.manifest).map_err(|_| internal())?;
        let new = serde_json::to_value(&newer.proposal.manifest).map_err(|_| internal())?;
        let mut changes = Vec::new();
        for field in [
            "agreement.schema_version",
            "agreement.agreement_id",
            "agreement.obligation_id",
            "agreement.revision",
            "agreement.purpose",
            "agreement.organizer_identity",
            "agreement.network_profile_id",
            "agreement.recipients",
            "agreement.funding_policy",
            "agreement.fee_policy",
            "agreement.privacy_profile",
            "agreement.coordination_deadline",
            "agreement.confirmation_policy",
            "agreement.extensions",
            "participants",
            "inputs",
            "outputs",
            "transaction_fee",
            "expiry_height",
        ] {
            let pointer = format!("/{}", field.replace('.', "/"));
            let before = old.pointer(&pointer).ok_or_else(snapshot_corrupt)?;
            let after = new.pointer(&pointer).ok_or_else(snapshot_corrupt)?;
            if before != after {
                changes.push(ProposalChange {
                    field: field.into(),
                    older: before.clone(),
                    newer: after.clone(),
                });
            }
        }
        bounded_comparison(ProposalComparison {
            schema_version: 1,
            agreement_id: older_view.agreement.agreement_id,
            older_proposal_id: older.candidate_id,
            newer_proposal_id: newer.candidate_id,
            older_manifest_digest: older.manifest_digest,
            newer_manifest_digest: newer.manifest_digest,
            material_change: !changes.is_empty(),
            renewed_review_required: older_id != newer_id,
            changes,
            scope: "unsigned_candidate_claims".into(),
            signable: false,
            message: if older_id != newer_id {
                "This candidate requires fresh review. Earlier reviews and approvals do not transfer. Comparison of claimed terms does not authorize funds or establish ownership, disclosure consent, or live chain validity."
            } else {
                "This is the same candidate snapshot. Comparison of claimed terms grants no approval and does not authorize funds or establish ownership, disclosure consent, or live chain validity."
            }.into(),
        })
    }
}

fn bounded_comparison(comparison: ProposalComparison) -> Result<ProposalComparison> {
    if comparison.changes.len() > MAX_COMPARISON_CHANGES
        || serde_json::to_vec(&comparison)
            .map_err(|_| internal())?
            .len()
            > MAX_COMPARISON_BYTES
    {
        return Err(ApiError::new("RESOURCE_EXHAUSTED", "Comparison exceeds the bounded response limit; inspect the complete snapshots separately"));
    }
    Ok(comparison)
}

fn checked_candidate_lineage(view: &AgreementView, candidate: &CandidateView) -> Result<usize> {
    candidate.verified_snapshot()?;
    let index = view
        .candidates
        .iter()
        .position(|c| c.candidate_id == candidate.candidate_id)
        .ok_or_else(snapshot_corrupt)?;
    let agreement = &candidate.proposal.manifest.agreement;
    if agreement.agreement_id != view.agreement.agreement_id
        || agreement.obligation_id != view.agreement.obligation_id
        || candidate.proposal.previous_proposal_id.as_ref()
            != index
                .checked_sub(1)
                .and_then(|i| view.candidates.get(i))
                .map(|c| &c.candidate_id)
    {
        return Err(snapshot_corrupt());
    }
    Ok(index)
}

pub(crate) fn eligible_status(status: IntentStatus) -> bool {
    matches!(
        status,
        IntentStatus::Active | IntentStatus::Selected | IntentStatus::Waitlisted
    )
}

pub(crate) fn check_proposer(envelope: &Envelope, access: &Access) -> Result<()> {
    if envelope.owner_client_id != access.principal_id {
        return Err(ApiError::new(
            "PERMISSION_DENIED",
            "Only the creating application can select the roster or propose terms",
        ));
    }
    Ok(())
}

fn validate_selection_request(request: &RosterSelectionRequest) -> Result<()> {
    if request.selected_intent_ids.is_empty() || request.selected_intent_ids.len() > MAX_INTENTS {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "Select between 1 and 32 unique intent IDs",
        ));
    }
    let mut unique = BTreeSet::new();
    for id in &request.selected_intent_ids {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
            || !unique.insert(id)
        {
            return Err(ApiError::new(
                "INVALID_REQUEST",
                "Selected intent IDs must be unique bounded identifiers",
            ));
        }
    }
    Ok(())
}

fn check_planning_window(view: &AgreementView, now: OffsetDateTime) -> Result<()> {
    if view.cancellation_requested {
        return Err(ApiError::new(
            "INVALID_TRANSITION",
            "This agreement has a cancellation request",
        ));
    }
    if view
        .agreement
        .coordination_deadline
        .as_deref()
        .is_some_and(|t| expired(t, now))
    {
        return Err(ApiError::new(
            "INVALID_TRANSITION",
            "Agreement coordination deadline has passed",
        ));
    }
    Ok(())
}

fn expired(timestamp: &str, now: OffsetDateTime) -> bool {
    OffsetDateTime::parse(timestamp, &Rfc3339).map_or(true, |deadline| deadline <= now)
}

fn check_selected_intents(
    agreement: &AgreementDraft,
    intents: &[&ParticipationIntent],
    now: OffsetDateTime,
) -> Result<()> {
    if intents.is_empty() || intents.len() > MAX_INTENTS {
        return Err(ApiError::new(
            "INVALID_TRANSITION",
            "The selected roster is incomplete; select a complete roster before proposing",
        ));
    }
    let mut participants = BTreeSet::new();
    for intent in intents {
        intent.validate()?;
        if intent.agreement_id != agreement.agreement_id
            || !participants.insert(&intent.participant_id)
        {
            return Err(ApiError::new(
                "INVALID_TERMS",
                "The selected roster contains a duplicate participant or mismatched agreement",
            ));
        }
        if !eligible_status(intent.status)
            || intent
                .valid_until
                .as_deref()
                .is_some_and(|t| expired(t, now))
        {
            return Err(ApiError::new("INVALID_TRANSITION", "A selected intent was withdrawn, declined, or expired; select a currently valid roster"));
        }
    }
    let total = Amount::checked_sum(intents.iter().map(|i| i.desired_contribution))
        .map_err(CoreError::from)?;
    let FundingPolicy::Exact { target } = agreement.funding_policy;
    if total != target {
        return Err(ApiError::new("CONSERVATION_FAILURE", "Selected intent amounts must equal the exact funding target; contributions are never silently reduced or increased"));
    }
    Ok(())
}

pub(crate) fn preview_intents(view: &AgreementView) -> Result<Vec<&ParticipationIntent>> {
    let status = if view.roster_selected {
        IntentStatus::Selected
    } else {
        IntentStatus::Active
    };
    let intents: Vec<_> = view.intents.iter().filter(|i| i.status == status).collect();
    if view.roster_selected {
        let now = OffsetDateTime::now_utc();
        check_planning_window(view, now)?;
        check_selected_intents(&view.agreement, &intents, now)?;
    }
    Ok(intents)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TermsSnapshot {
    schema_version: u32,
    agreement: AgreementDraft,
    intents: Vec<ParticipationIntent>,
    #[serde(default)]
    roster_selected: bool,
    scope: String,
}

fn checked_snapshot(view: &AgreementView, proposal: &ProposalPreview) -> Result<TermsSnapshot> {
    let index = proposal
        .revision
        .checked_sub(1)
        .ok_or_else(snapshot_corrupt)? as usize;
    if view.proposals.get(index).map(|p| &p.proposal_id) != Some(&proposal.proposal_id)
        || proposal.previous_proposal_id.as_ref()
            != index
                .checked_sub(1)
                .and_then(|i| view.proposals.get(i))
                .map(|p| &p.proposal_id)
    {
        return Err(snapshot_corrupt());
    }
    if serde_json::to_vec(&proposal.manifest)
        .map_err(|_| internal())?
        .len()
        > MAX_COMPARISON_BYTES
    {
        return Err(ApiError::new(
            "RESOURCE_EXHAUSTED",
            "Terms snapshot exceeds the comparison size limit",
        ));
    }
    let terms: TermsSnapshot =
        serde_json::from_value(proposal.manifest.clone()).map_err(|_| snapshot_corrupt())?;
    if terms.schema_version != 1
        || terms.scope != "unverified_nonbinding_terms"
        || terms.agreement.agreement_id != view.agreement.agreement_id
        || proposal.agreement_id != terms.agreement.agreement_id
        || proposal.obligation_id != terms.agreement.obligation_id
        || proposal.obligation_id != view.agreement.obligation_id
        || proposal.revision == 0
        || proposal.status != "terms_only_not_signable"
        || proposal.artifact_digest.is_some()
        || proposal.effects_commitment.is_some()
        || terms.intents.len() > MAX_INTENTS
    {
        return Err(snapshot_corrupt());
    }
    terms.agreement.validate().map_err(|_| snapshot_corrupt())?;
    let mut ids = BTreeSet::new();
    let mut participants = BTreeSet::new();
    let expected_status = if terms.roster_selected {
        IntentStatus::Selected
    } else {
        IntentStatus::Active
    };
    for intent in &terms.intents {
        intent.validate().map_err(|_| snapshot_corrupt())?;
        if intent.agreement_id != terms.agreement.agreement_id
            || intent.status != expected_status
            || !ids.insert(&intent.intent_id)
            || !participants.insert(&intent.participant_id)
        {
            return Err(snapshot_corrupt());
        }
    }
    // Historical intent expiry is not current validity. Comparison preserves
    // exact historic claims without falsely renewing them against today's clock.
    if terms.roster_selected {
        let total = Amount::checked_sum(terms.intents.iter().map(|i| i.desired_contribution))
            .map_err(|_| snapshot_corrupt())?;
        let FundingPolicy::Exact { target } = terms.agreement.funding_policy;
        if terms.intents.is_empty() || total != target {
            return Err(snapshot_corrupt());
        }
    }
    Ok(terms)
}

fn snapshot_corrupt() -> ApiError {
    ApiError::new("RECOVERY_REQUIRED", "Terms snapshot schema or agreement binding is damaged; preserve the journal and do not authorize")
}

pub(crate) fn validate_recovery_snapshots(view: &AgreementView) -> Result<()> {
    for proposal in &view.proposals {
        checked_snapshot(view, proposal)?;
        if hash_domain(b"wholepact:terms-preview:v1\0", &proposal.manifest)? != proposal.manifest_digest {
            return Err(snapshot_corrupt());
        }
    }
    Ok(())
}
