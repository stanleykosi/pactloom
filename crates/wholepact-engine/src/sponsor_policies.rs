//! Private owner-scoped sponsor preparation. Durable policies are reusable
//! constraints, never standing signing grants. Preview uses immutable candidate
//! allocations and retains the core's explicit unverifiable-match boundary.
use super::*;
use std::collections::BTreeMap;
use wholepact_core::sponsor::{evaluate_sponsor_policy, SponsorFormulaPreview};
pub use wholepact_core::sponsor::{
    SponsorAccountRestriction, SponsorBeneficiaryRestriction, SponsorPolicyTerms,
};
use wholepact_core::Amount;

pub const MAX_SPONSOR_POLICIES: usize = 16;
pub const MAX_SPONSOR_POLICY_VERSIONS: usize = 32;
pub const MAX_SPONSOR_POLICY_BYTES: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicyState {
    /// Available for nonbinding previews. Never an activated spending policy.
    Draft,
    Paused,
    Retired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorPolicyVersion {
    pub version: u32,
    pub terms: SponsorPolicyTerms,
    pub terms_digest: String,
    pub previous_terms_digest: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredSponsorPolicy {
    owner_principal_id: String,
    policy_id: String,
    state: SponsorPolicyState,
    versions: Vec<SponsorPolicyVersion>,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SponsorPolicyView {
    pub agreement_id: String,
    pub policy_id: String,
    pub state: SponsorPolicyState,
    pub current_version: u32,
    pub versions: Vec<SponsorPolicyVersion>,
    pub created_at: String,
    pub updated_at: String,
    pub authorization_allowed: bool,
    pub scope: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSponsorPolicyRequest {
    pub policy_id: String,
    pub terms: SponsorPolicyTerms,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSponsorPolicyRequest {
    pub policy_id: String,
    pub expected_policy_version: u32,
    pub terms: SponsorPolicyTerms,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorPolicyStateRequest {
    pub policy_id: String,
    pub expected_policy_version: u32,
    pub state: SponsorPolicyState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorPolicyPreviewRequest {
    pub candidate_id: String,
    pub expected_policy_version: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct SponsorPolicyMutation {
    pub policy: SponsorPolicyView,
    pub agreement_revision: u64,
    pub operation_id: String,
    pub event_sequence: u64,
    pub replayed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SponsorBudgetPreview {
    pub aggregate_budget: Amount,
    pub pending_authorization_exposure: Option<Amount>,
    pub settled_debit: Option<Amount>,
    pub remaining_budget: Option<Amount>,
    pub status: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SponsorPolicyPreview {
    pub schema_version: u32,
    pub policy_agreement_id: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_terms_digest: String,
    pub candidate_agreement_id: String,
    pub candidate_agreement_revision: u64,
    pub candidate_id: String,
    pub candidate_manifest_digest: String,
    pub formula: SponsorFormulaPreview,
    pub budget: SponsorBudgetPreview,
    pub status: String,
    pub authorization_allowed: bool,
    pub blocking_reasons: Vec<String>,
}

impl Engine {
    pub fn list_sponsor_policies(
        &self,
        access: &Access,
        agreement_id: &str,
    ) -> Result<Vec<SponsorPolicyView>> {
        let envelope = self.load(access, agreement_id)?;
        Ok(envelope
            .sponsor_policies
            .values()
            .filter(|policy| policy.owner_principal_id == access.principal_id)
            .map(|policy| policy.view(agreement_id))
            .collect())
    }

    pub fn sponsor_policy(
        &self,
        access: &Access,
        agreement_id: &str,
        policy_id: &str,
    ) -> Result<SponsorPolicyView> {
        let envelope = self.load(access, agreement_id)?;
        Ok(owned_policy(&envelope, access, policy_id)?.view(agreement_id))
    }

    pub fn create_sponsor_policy(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: CreateSponsorPolicyRequest,
    ) -> Result<SponsorPolicyMutation> {
        let command = context(
            access,
            key,
            "create_sponsor_policy",
            agreement_id,
            Some(revision),
            &request,
        )?;
        if let Some(replay) = self.replay_sponsor_policy(access, &command, &request.policy_id)? {
            return Ok(replay);
        }
        let mut envelope = self.load(access, agreement_id)?;
        candidates::check_revision(&envelope, revision)?;
        validate_identifier(&request.policy_id)?;
        validate_new_terms(&request.terms)?;
        if envelope.sponsor_policies.contains_key(&request.policy_id) {
            return Err(ApiError::new(
                "REVISION_CONFLICT",
                "Sponsor policy ID is already in use; choose a new ID",
            ));
        }
        if envelope.sponsor_policies.len() >= MAX_SPONSOR_POLICIES {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Agreement sponsor policy limit reached",
            ));
        }
        let created_at = now();
        let version = new_version(&request.policy_id, 1, request.terms, None, &created_at)?;
        envelope.sponsor_policies.insert(
            request.policy_id.clone(),
            StoredSponsorPolicy {
                owner_principal_id: access.principal_id.clone(),
                policy_id: request.policy_id.clone(),
                state: SponsorPolicyState::Draft,
                versions: vec![version],
                created_at: created_at.clone(),
                updated_at: created_at,
            },
        );
        self.commit_sponsor_policy(
            access,
            &command,
            revision,
            envelope,
            &request.policy_id,
            "sponsor_policy_created",
        )
    }

    pub fn update_sponsor_policy(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: UpdateSponsorPolicyRequest,
    ) -> Result<SponsorPolicyMutation> {
        let command = context(
            access,
            key,
            "update_sponsor_policy",
            agreement_id,
            Some(revision),
            &request,
        )?;
        if let Some(replay) = self.replay_sponsor_policy(access, &command, &request.policy_id)? {
            return Ok(replay);
        }
        let mut envelope = self.load(access, agreement_id)?;
        candidates::check_revision(&envelope, revision)?;
        let old = owned_policy(&envelope, access, &request.policy_id)?;
        check_policy_version(old, request.expected_policy_version)?;
        check_not_retired(old)?;
        validate_new_terms(&request.terms)?;
        if old.versions.len() >= MAX_SPONSOR_POLICY_VERSIONS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Sponsor policy version limit reached; preserve its history",
            ));
        }
        let last = old.versions.last().ok_or_else(corrupt_policy)?;
        if last.terms == request.terms {
            return Err(ApiError::new(
                "INVALID_REQUEST",
                "Policy terms are unchanged; no new version is needed",
            ));
        }
        let version = new_version(
            &request.policy_id,
            last.version + 1,
            request.terms,
            Some(last.terms_digest.clone()),
            &now(),
        )?;
        let policy = envelope
            .sponsor_policies
            .get_mut(&request.policy_id)
            .ok_or_else(not_found)?;
        policy.updated_at = version.created_at.clone();
        policy.versions.push(version);
        // Pausing is retained across edits. A future policy cannot alter or
        // downgrade an earlier version or erase earlier authorization exposure.
        self.commit_sponsor_policy(
            access,
            &command,
            revision,
            envelope,
            &request.policy_id,
            "sponsor_policy_version_created",
        )
    }

    pub fn set_sponsor_policy_state(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: SponsorPolicyStateRequest,
    ) -> Result<SponsorPolicyMutation> {
        let command = context(
            access,
            key,
            "set_sponsor_policy_state",
            agreement_id,
            Some(revision),
            &request,
        )?;
        if let Some(replay) = self.replay_sponsor_policy(access, &command, &request.policy_id)? {
            return Ok(replay);
        }
        let mut envelope = self.load(access, agreement_id)?;
        candidates::check_revision(&envelope, revision)?;
        let old = owned_policy(&envelope, access, &request.policy_id)?;
        check_policy_version(old, request.expected_policy_version)?;
        check_not_retired(old)?;
        if old.state == request.state {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Sponsor policy is already in the requested state",
            ));
        }
        let policy = envelope
            .sponsor_policies
            .get_mut(&request.policy_id)
            .ok_or_else(not_found)?;
        policy.state = request.state;
        policy.updated_at = now();
        let event = match request.state {
            SponsorPolicyState::Draft => "sponsor_policy_draft_resumed",
            SponsorPolicyState::Paused => "sponsor_policy_paused",
            SponsorPolicyState::Retired => "sponsor_policy_retired",
        };
        self.commit_sponsor_policy(
            access,
            &command,
            revision,
            envelope,
            &request.policy_id,
            event,
        )
    }

    /// Side-effect-free concrete preview. The policy owner must separately have
    /// access to the candidate's agreement. A policy ID or account label never
    /// grants read access to the account ledger or somebody else's policy.
    pub fn preview_sponsor_policy(
        &self,
        access: &Access,
        agreement_id: &str,
        policy_id: &str,
        request: SponsorPolicyPreviewRequest,
    ) -> Result<SponsorPolicyPreview> {
        let envelope = self.load(access, agreement_id)?;
        let policy = owned_policy(&envelope, access, policy_id)?;
        check_policy_version(policy, request.expected_policy_version)?;
        if policy.state != SponsorPolicyState::Draft {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Sponsor policy is paused or retired; its historical terms remain available",
            ));
        }
        let version = policy.versions.last().ok_or_else(corrupt_policy)?;
        if version.terms.expires_at.as_deref().is_some_and(expired) {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Sponsor policy has expired; revise it deliberately before a new preview",
            ));
        }
        let (view, candidate) = self.candidate(access, &request.candidate_id)?;
        if !view.roster_selected {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Select an exact nonbinding roster before previewing the sponsor formula",
            ));
        }
        if view.candidates.last().map(|c| c.candidate_id.as_str())
            != Some(request.candidate_id.as_str())
        {
            return Err(ApiError::new("REVISION_CONFLICT", "Preview requires the current candidate; historical candidates remain inspectable separately"));
        }
        let proposal = candidate.verified_snapshot()?;
        candidates::check_current_terms(&view, proposal.manifest())?;
        let formula = evaluate_sponsor_policy(&version.terms, proposal.manifest())?;
        Ok(SponsorPolicyPreview {
            schema_version: 1,
            policy_agreement_id: agreement_id.into(),
            policy_id: policy_id.into(),
            policy_version: version.version,
            policy_terms_digest: version.terms_digest.clone(),
            candidate_agreement_id: view.agreement.agreement_id,
            candidate_agreement_revision: view.revision,
            candidate_id: candidate.candidate_id,
            candidate_manifest_digest: candidate.manifest_digest,
            formula,
            budget: SponsorBudgetPreview {
                aggregate_budget: version.terms.aggregate_budget,
                pending_authorization_exposure: None,
                settled_debit: None,
                remaining_budget: None,
                status: "unknown_requires_account_authority".into(),
                reason: "The sponsor account has no authenticated account-wide budget connection here. Pending exposure and settled spending cannot be assumed zero. Saving, pausing or retiring this policy changes neither ledger nor released authorizations.".into(),
            },
            status: "match_unverifiable".into(),
            authorization_allowed: false,
            blocking_reasons: vec![
                "Candidate input/return allocations and sponsor identity are unverified claims; no qualified ownership or attestation verifier is connected".into(),
                "Authoritative account-wide pending and settled exposure is unavailable; no remaining spend budget is established".into(),
                "Policy preparation does not issue disclosure consent, human approval, a spending grant or a signature".into(),
            ],
        })
    }

    fn replay_sponsor_policy(
        &self,
        access: &Access,
        command: &CommandContext,
        policy_id: &str,
    ) -> Result<Option<SponsorPolicyMutation>> {
        self.store
            .find_replay(command)
            .map_err(store_error)?
            .map(|result| policy_mutation(access, policy_id, result))
            .transpose()
    }

    fn commit_sponsor_policy(
        &self,
        access: &Access,
        command: &CommandContext,
        revision: u64,
        mut envelope: Envelope,
        policy_id: &str,
        event: &str,
    ) -> Result<SponsorPolicyMutation> {
        validate_stored_policies(&envelope.sponsor_policies)?;
        envelope.view.revision = revision.checked_add(1).ok_or_else(|| {
            ApiError::new("RESOURCE_EXHAUSTED", "Agreement revision limit reached")
        })?;
        envelope.view.updated_at = now();
        let id = envelope.view.agreement.agreement_id.clone();
        let result = self
            .store
            .update_agreement(command, &id, revision, encode(&envelope)?, event)
            .map_err(store_error)?;
        policy_mutation(access, policy_id, result)
    }
}

impl StoredSponsorPolicy {
    fn view(&self, agreement_id: &str) -> SponsorPolicyView {
        SponsorPolicyView {
            agreement_id: agreement_id.into(),
            policy_id: self.policy_id.clone(),
            state: self.state,
            current_version: self.versions.last().map_or(0, |v| v.version),
            versions: self.versions.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            authorization_allowed: false,
            scope: "private_reusable_constraints_only".into(),
        }
    }
}

fn policy_mutation(
    access: &Access,
    policy_id: &str,
    result: MutationResult,
) -> Result<SponsorPolicyMutation> {
    let envelope = decode(&result.record)?;
    if !access.sees(&result.record.id, &envelope.owner_client_id) {
        return Err(not_found());
    }
    let policy = owned_policy(&envelope, access, policy_id)?.view(&result.record.id);
    Ok(SponsorPolicyMutation {
        policy,
        agreement_revision: result.record.revision,
        operation_id: result.operation_id,
        event_sequence: result.event_sequence,
        replayed: result.replayed,
    })
}

fn owned_policy<'a>(
    envelope: &'a Envelope,
    access: &Access,
    policy_id: &str,
) -> Result<&'a StoredSponsorPolicy> {
    envelope
        .sponsor_policies
        .get(policy_id)
        .filter(|policy| policy.owner_principal_id == access.principal_id)
        .ok_or_else(not_found)
}

fn check_policy_version(policy: &StoredSponsorPolicy, expected: u32) -> Result<()> {
    if policy.versions.last().map(|v| v.version) != Some(expected) {
        return Err(ApiError::new(
            "REVISION_CONFLICT",
            "Sponsor policy terms changed; refresh and review the exact version",
        ));
    }
    Ok(())
}
fn check_not_retired(policy: &StoredSponsorPolicy) -> Result<()> {
    if policy.state == SponsorPolicyState::Retired {
        return Err(ApiError::new(
            "INVALID_TRANSITION",
            "Retired sponsor policies cannot be resumed or amended; their history remains retained",
        ));
    }
    Ok(())
}
fn expired(timestamp: &str) -> bool {
    OffsetDateTime::parse(timestamp, &Rfc3339)
        .map_or(true, |deadline| deadline <= OffsetDateTime::now_utc())
}
fn validate_new_terms(terms: &SponsorPolicyTerms) -> Result<()> {
    terms.validate()?;
    if !matches!(
        terms.network_profile_id.as_str(),
        "zcash-testnet-unqualified" | candidates::PROFILE_ID
    ) {
        return Err(ApiError::new(
            "UNSUPPORTED_CAPABILITY",
            "Sponsor preparation supports only the available non-signing testnet profiles",
        ));
    }
    if terms.expires_at.as_deref().is_some_and(expired) {
        return Err(ApiError::new(
            "INVALID_TERMS",
            "A new sponsor policy version must not already be expired",
        ));
    }
    Ok(())
}
fn validate_identifier(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "Sponsor policy identifiers must be 1..=128 ASCII letters, digits or -_.:",
        ));
    }
    Ok(())
}
fn new_version(
    policy_id: &str,
    version: u32,
    terms: SponsorPolicyTerms,
    previous_terms_digest: Option<String>,
    created_at: &str,
) -> Result<SponsorPolicyVersion> {
    let mut value = SponsorPolicyVersion {
        version,
        terms,
        terms_digest: String::new(),
        previous_terms_digest,
        created_at: created_at.into(),
    };
    value.terms_digest = policy_digest(policy_id, &value)?;
    Ok(value)
}
fn policy_digest(policy_id: &str, version: &SponsorPolicyVersion) -> Result<String> {
    hash_domain(
        b"wholepact:sponsor-policy-version:v1\0",
        &json!({
            "policy_id": policy_id, "version": version.version,
            "terms": version.terms, "previous_terms_digest": version.previous_terms_digest,
            "created_at": version.created_at,
        }),
    )
}

/// Revalidate durable history rather than trusting serialized evidence flags.
/// Digests detect inconsistent snapshots; they are not signatures or identity.
pub(crate) fn validate_stored_policies(
    policies: &BTreeMap<String, StoredSponsorPolicy>,
) -> Result<()> {
    if policies.len() > MAX_SPONSOR_POLICIES
        || serde_json::to_vec(policies).map_err(|_| internal())?.len() > MAX_SPONSOR_POLICY_BYTES
    {
        return Err(ApiError::new(
            "RESOURCE_EXHAUSTED",
            "Sponsor policy history exceeds its bounded storage limit",
        ));
    }
    for (id, policy) in policies {
        validate_identifier(id).map_err(|_| corrupt_policy())?;
        validate_identifier(&policy.owner_principal_id).map_err(|_| corrupt_policy())?;
        if policy.policy_id != *id
            || policy.versions.is_empty()
            || policy.versions.len() > MAX_SPONSOR_POLICY_VERSIONS
        {
            return Err(corrupt_policy());
        }
        let created =
            OffsetDateTime::parse(&policy.created_at, &Rfc3339).map_err(|_| corrupt_policy())?;
        let updated =
            OffsetDateTime::parse(&policy.updated_at, &Rfc3339).map_err(|_| corrupt_policy())?;
        if updated < created || policy.versions[0].created_at != policy.created_at {
            return Err(corrupt_policy());
        }
        let mut previous = None;
        let mut previous_time = created;
        for (index, version) in policy.versions.iter().enumerate() {
            version.terms.validate().map_err(|_| corrupt_policy())?;
            let time = OffsetDateTime::parse(&version.created_at, &Rfc3339)
                .map_err(|_| corrupt_policy())?;
            if version.version as usize != index + 1
                || version.previous_terms_digest.as_ref() != previous
                || version.terms_digest != policy_digest(id, version)?
                || time < previous_time
                || time > updated
            {
                return Err(corrupt_policy());
            }
            previous = Some(&version.terms_digest);
            previous_time = time;
        }
    }
    Ok(())
}
fn corrupt_policy() -> ApiError {
    ApiError::new("RECOVERY_REQUIRED", "Sponsor policy history is damaged or incompatible; preserve the journal and do not authorize")
}

#[cfg(feature = "signer-authority-bridge")]
mod owner_source;
#[cfg(feature = "signer-authority-bridge")]
pub use owner_source::SponsorOwnerReview;
