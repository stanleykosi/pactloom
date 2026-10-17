//! Immutable exact candidate terms and local-only economic computation.
//! Wire DTOs are claims. Only the typed embedded method can run the protocol
//! verifier; no HTTP field can assert that an artifact or account was verified.
use super::*;
use wholepact_core::{Proposal, ProposalInput, ProposalManifest};

pub const PROFILE_ID: &str = "ironwood-testnet-nu7-candidate";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRequest {
    pub manifest: ProposalManifest,
    pub previous_candidate_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateReview {
    pub report_id: String,
    pub candidate_id: String,
    pub manifest_digest: String,
    pub checked_at: String,
    pub status: String,
    pub scope: String,
    pub artifact_digest: Option<String>,
    pub effects_commitment: Option<String>,
    pub review_binding: Option<String>,
    pub exact_fee_zatoshis: String,
    pub participant_net_debits_zatoshis: std::collections::BTreeMap<String, String>,
    pub economic_terms_verified: bool,
    pub account_associations_authenticated: bool,
    pub disclosure_consents_authenticated: bool,
    pub human_approval: String,
    pub chain_validated: bool,
    pub authorization_allowed: bool,
    pub distribution_allowed: bool,
    pub artifact_persistence: String,
    pub blocking_reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateView {
    pub candidate_id: String,
    pub proposal: ProposalInput,
    pub manifest_digest: String,
    pub proposal_digest: String,
    pub accounting: Value,
    pub reviews: Vec<CandidateReview>,
    #[serde(default)]
    pub proof_jobs: Vec<CandidateProofJob>,
}

/// A cached non-private observation of the independent encrypted proof journal.
/// This is neither a release grant nor an assertion of cross-database atomicity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProofJob {
    pub job_id: String,
    pub scope_digest: String,
    pub candidate_id: String,
    pub manifest_digest: String,
    pub coordination_request_digest: String,
    pub state: String,
    pub attempt: u32,
    pub input_digest: String,
    pub result_digest: Option<String>,
    pub effects_commitment: String,
    pub review_binding: String,
    pub encrypted_checkpoint_created: bool,
    pub proof_verified: bool,
    pub chain_validated: bool,
    pub authorization_allowed: bool,
    pub distribution_allowed: bool,
    pub observed_at: String,
    pub observation_source: String,
}

/// Internal constructor provenance, never accepted from a wire DTO.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointReceipt {
    /// Exact constructor-produced action mapping; absent on historical receipts.
    /// A missing mapping cannot be invented to upgrade an old artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_mappings_v1: Option<Value>,
    pub job_id: String,
    pub scope_digest: String,
    pub principal_id: String,
    pub candidate_id: String,
    pub manifest_digest: String,
    pub coordination_request_digest: String,
    pub artifact_digest: String,
    pub review_binding: String,
    pub effects_commitment: String,
    pub prepared_revision: u64,
}

/// Structural validation of two deliberately distinct retained identities.
/// The receipt-map key hashes the original principal/construction key in its
/// own domain; the proof job ID uses the private journal's framed domain.
/// This does not authenticate either identity or replace exact journal scope
/// matching, and never rewrites historical storage keys.
pub fn valid_checkpoint_receipt_index(receipt_key: &str, job_id: &str) -> bool {
    fn digest(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    digest(receipt_key) && job_id.strip_prefix("proof-").is_some_and(digest)
}

/// Private local inputs: deliberately no Debug or serialization implementation.
#[cfg(feature = "candidate-construction")]
pub struct LocalConstruction<'a> {
    pub context: wholepact_protocol::construction::ConstructionContext,
    pub contributions: Vec<wholepact_protocol::construction::OwnedContribution>,
    pub declarations: &'a [wholepact_protocol::construction::DisclosureAcknowledgement],
}

/// Controller-issued local selections only; no caller-supplied chain context or
/// successful-sync boolean. It does not authenticate disclosure declarations.
#[cfg(feature = "wallet-sync")]
pub struct ScannedWalletConstruction<'a> {
    pub contributions: Vec<wholepact_wallet::wallet::protected_sync::ProtectedContribution>,
    pub declarations: &'a [wholepact_protocol::construction::DisclosureAcknowledgement],
}

impl CandidateView {
    pub(crate) fn verified_snapshot(&self) -> Result<Proposal> {
        let proposal = Proposal::validate(self.proposal.clone()).map_err(|_| corrupted())?;
        if self.candidate_id != proposal.input().proposal_id
            || self.manifest_digest != proposal.manifest_digest()
            || self.proposal_digest != proposal.proposal_digest()
            || self.accounting
                != serde_json::to_value(proposal.accounting()).map_err(|_| internal())?
        {
            return Err(corrupted());
        }
        if self.reviews.iter().any(|r| {
            r.candidate_id != self.candidate_id
                || r.manifest_digest != self.manifest_digest
                || r.authorization_allowed
                || r.distribution_allowed
                || r.chain_validated
                || r.account_associations_authenticated
                || r.disclosure_consents_authenticated
                || r.human_approval != "not_requested"
        }) {
            return Err(corrupted());
        }
        if self.proof_jobs.iter().any(|job| {
            job.candidate_id != self.candidate_id
                || job.manifest_digest != self.manifest_digest
                || job.chain_validated
                || job.authorization_allowed
                || job.distribution_allowed
                || !job.encrypted_checkpoint_created
        }) {
            return Err(corrupted());
        }
        Ok(proposal)
    }
}

impl Engine {
    pub fn create_candidate(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: CandidateRequest,
    ) -> Result<Mutation> {
        let command = context(
            access,
            key,
            "create_candidate",
            agreement_id,
            Some(revision),
            &request,
        )?;
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        let mut envelope = self.load(access, agreement_id)?;
        planning::check_proposer(&envelope, access)?;
        check_revision(&envelope, revision)?;
        check_current_terms(&envelope.view, &request.manifest)?;
        if envelope.view.candidates.len() >= MAX_PROPOSALS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Candidate history limit reached",
            ));
        }
        let previous = envelope
            .view
            .candidates
            .last()
            .map(|c| c.candidate_id.as_str());
        if request.previous_candidate_id.as_deref() != previous {
            return Err(ApiError::new(
                "REVISION_CONFLICT",
                "Candidate must name the latest prior candidate, or null for the first candidate",
            ));
        }
        let proposal = Proposal::validate(ProposalInput {
            proposal_id: Uuid::new_v4().to_string(),
            previous_proposal_id: request.previous_candidate_id,
            manifest: request.manifest,
            artifact_digest: None,
            effects_commitment: None,
            // Core portable timestamps intentionally use whole seconds.
            created_at: OffsetDateTime::now_utc()
                .replace_nanosecond(0)
                .map_err(|_| internal())?
                .format(&Rfc3339)
                .map_err(|_| internal())?,
        })?;
        envelope.view.candidates.push(CandidateView {
            candidate_id: proposal.input().proposal_id.clone(),
            proposal: proposal.input().clone(),
            manifest_digest: proposal.manifest_digest().into(),
            proposal_digest: proposal.proposal_digest().into(),
            accounting: serde_json::to_value(proposal.accounting()).map_err(|_| internal())?,
            reviews: vec![],
            proof_jobs: vec![],
        });
        envelope.view.progress = "preparing_proposal".into();
        self.commit(
            &command,
            agreement_id,
            revision,
            envelope,
            "candidate_terms_frozen",
        )
    }

    pub fn candidate(
        &self,
        access: &Access,
        candidate_id: &str,
    ) -> Result<(AgreementView, CandidateView)> {
        for agreement in self.list(access)? {
            if let Some(candidate) = agreement
                .candidates
                .iter()
                .find(|c| c.candidate_id == candidate_id)
                .cloned()
            {
                candidate.verified_snapshot()?;
                return Ok((agreement, candidate));
            }
        }
        Err(not_found())
    }

    /// Durable claimed-accounting report. Never takes a caller's verified flag.
    pub fn review_candidate(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
    ) -> Result<Mutation> {
        let command = context(
            access,
            key,
            "review_candidate_claims",
            candidate_id,
            Some(revision),
            &json!({}),
        )?;
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let proposal = candidate.verified_snapshot()?;
        let id = &view.agreement.agreement_id;
        let mut envelope = self.load(access, id)?;
        check_revision(&envelope, revision)?;
        check_review_limit(&envelope.view)?;
        let report = claims_report(&proposal)?;
        envelope
            .view
            .candidates
            .iter_mut()
            .find(|c| c.candidate_id == candidate_id)
            .ok_or_else(not_found)?
            .reviews
            .push(report);
        self.commit(
            &command,
            id,
            revision,
            envelope,
            "candidate_claims_reviewed",
        )
    }

    /// Runs real construction and economic verification in the caller's local
    /// trust domain. It neither authenticates declarations nor distributes data.
    /// Only summaries are journaled; witness-bearing PCZT bytes are discarded.
    /// This API is deliberately absent from HTTP and cannot be enabled by JSON.
    #[cfg(feature = "candidate-construction")]
    pub fn construct_candidate_locally(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalConstruction<'_>,
    ) -> Result<Mutation> {
        self.construct_candidate_locally_checked(access, key, candidate_id, revision, local, || {
            Ok(())
        })
    }

    /// Connect current protected-wallet selections to the same exact economic verifier.
    /// Every selection must have one common tip, anchor and profile. Single-provider
    /// observations remain unqualified for signing; all report release gates stay closed.
    #[cfg(feature = "wallet-sync")]
    pub fn construct_candidate_from_wallets(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: ScannedWalletConstruction<'_>,
    ) -> Result<Mutation> {
        if self.store.protection() != wholepact_store::StorageProtection::Encrypted {
            return Err(ApiError::new(
                "STORAGE_PROTECTION_REQUIRED",
                "Protected wallet construction requires verified encrypted coordination storage",
            ));
        }
        // Check caller scope before extracting any private constructor material.
        let (current_view, _) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&current_view.agreement.agreement_id)?;
        let (construction, guards) = checked_wallet_construction(local)?;
        self.construct_candidate_locally_checked(
            access,
            key,
            candidate_id,
            revision,
            construction,
            || check_wallet_guards(&guards),
        )
    }

    #[cfg(feature = "candidate-construction")]
    #[allow(clippy::too_many_arguments)]
    fn construct_candidate_locally_checked(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalConstruction<'_>,
        check_current: impl Fn() -> Result<()>,
    ) -> Result<Mutation> {
        check_current()?;
        let LocalConstruction {
            context: chain,
            contributions,
            declarations,
        } = local;
        let input_digest = private_request_digest(chain, &contributions, declarations)?;
        let command = context(
            access,
            key,
            "compute_candidate_locally",
            candidate_id,
            Some(revision),
            &json!({"local_input_digest":input_digest}),
        )?;
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let id = &view.agreement.agreement_id;
        let mut envelope = self.load(access, id)?;
        check_revision(&envelope, revision)?;
        check_current_terms(&envelope.view, &candidate.proposal.manifest)?;
        check_review_limit(&envelope.view)?;
        let proposal = candidate.verified_snapshot()?;
        let constructed = wholepact_protocol::construction::construct_proposal(&proposal, chain, contributions, declarations)
            .map_err(|_| ApiError::new("CANDIDATE_VERIFICATION_FAILED", "Local candidate construction rejected the selected inputs, exact outputs, fee, caps, profile, context or disclosure declaration; no artifact was retained or released"))?;
        check_current()?;
        let mut report = claims_report(&proposal)?;
        report.status = "economic_terms_verified_only".into();
        report.scope = "local_cryptographic_economic_computation".into();
        report.artifact_digest = Some(hex::encode(Sha256::digest(&constructed.pczt_bytes)));
        report.effects_commitment = Some(constructed.economic_review.shielded_sighash().into());
        report.review_binding = Some(constructed.economic_review.review_binding().into());
        report.economic_terms_verified = true;
        report.artifact_persistence = "not_retained_reconstruction_requires_new_operation".into();
        report.blocking_reasons = vec!["Human approval is not recorded".into(), "Account associations and broad-review disclosure declarations are not authenticated".into(), "Chain context has not been independently validated".into(), "Witness-bearing artifact is not retained; no durable proof, export, signing or submission operation exists".into()];
        // Verify the adapter's result remains consistent with the immutable accounting.
        if constructed.economic_review.fee_zatoshis()
            != proposal.manifest().transaction_fee.as_zatoshis()
            || constructed.economic_review.net_debits_zatoshis().len()
                != proposal.manifest().participants.len()
        {
            return Err(internal());
        }
        for (participant, actual) in proposal
            .manifest()
            .participants
            .iter()
            .zip(constructed.economic_review.net_debits_zatoshis())
        {
            let expected = proposal
                .accounting()
                .participant_net_debits
                .get(&participant.participant_id)
                .ok_or_else(internal)?;
            if expected.as_zatoshis() != *actual {
                return Err(internal());
            }
        }
        envelope
            .view
            .candidates
            .iter_mut()
            .find(|c| c.candidate_id == candidate_id)
            .ok_or_else(not_found)?
            .reviews
            .push(report);
        // A failed commit returns no report; local computation has no external effect.
        check_current()?;
        self.commit(
            &command,
            id,
            revision,
            envelope,
            "candidate_local_economics_verified",
        )
    }
}

/// Shared extraction for transient review and durable checkpointing. This does not
/// authenticate account identity or consent, or reserve any selected input.
#[cfg(feature = "wallet-sync")]
pub(crate) fn checked_wallet_construction(
    local: ScannedWalletConstruction<'_>,
) -> Result<(
    LocalConstruction<'_>,
    Vec<wholepact_wallet::wallet::protected_sync::WalletObservationGuard>,
)> {
    if !(1..=32).contains(&local.contributions.len()) {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "A bounded set of protected wallet selections is required",
        ));
    }
    let mut guards = Vec::new();
    let mut packages = Vec::new();
    let mut common = None;
    let mut common_tip = None;
    for selected in local.contributions {
        selected
            .check_current()
            .map_err(|_| wallet_observation_unavailable())?;
        let tip = selected.observation().tip().clone();
        if common_tip.as_ref().is_some_and(|t| t != &tip) {
            return Err(wallet_observation_unavailable());
        }
        common_tip = Some(tip);
        guards.push(selected.observation_guard());
        let (contribution, context) = selected
            .into_current_contribution()
            .map_err(|_| wallet_observation_unavailable())?;
        if common.as_ref().is_some_and(
            |c: &wholepact_protocol::construction::ConstructionContext| {
                c.anchor != context.anchor
                    || c.anchor_height != context.anchor_height
                    || c.anchor_block_hash != context.anchor_block_hash
                    || c.target_height != context.target_height
            },
        ) {
            return Err(wallet_observation_unavailable());
        }
        common = Some(context);
        packages.push(contribution);
    }
    Ok((
        LocalConstruction {
            context: common.ok_or_else(wallet_observation_unavailable)?,
            contributions: packages,
            declarations: local.declarations,
        },
        guards,
    ))
}

#[cfg(feature = "wallet-sync")]
pub(crate) fn check_wallet_guards(
    guards: &[wholepact_wallet::wallet::protected_sync::WalletObservationGuard],
) -> Result<()> {
    for guard in guards {
        guard
            .check_current()
            .map_err(|_| wallet_observation_unavailable())?;
    }
    Ok(())
}

#[cfg(feature = "wallet-sync")]
fn wallet_observation_unavailable() -> ApiError {
    ApiError::new(
        "WALLET_OBSERVATION_UNAVAILABLE",
        "Protected wallet selections are expired, invalidated, or do not share one exact tip and anchor; resynchronize and select again",
    )
}

pub(crate) fn check_revision(envelope: &Envelope, revision: u64) -> Result<()> {
    if envelope.view.revision != revision {
        return Err(ApiError::new(
            "REVISION_CONFLICT",
            "The aggregate revision changed; refresh and review before retrying",
        ));
    }
    Ok(())
}

pub(crate) fn check_current_terms(view: &AgreementView, manifest: &ProposalManifest) -> Result<()> {
    if view.cancellation_requested {
        return Err(ApiError::new(
            "INVALID_TRANSITION",
            "This agreement has a cancellation request",
        ));
    }
    if manifest.agreement != view.agreement {
        return Err(ApiError::new(
            "INVALID_TERMS",
            "Candidate agreement must exactly match the locally stored agreement",
        ));
    }
    if manifest.agreement.network_profile_id != PROFILE_ID {
        return Err(ApiError::new(
            "UNSUPPORTED_CAPABILITY",
            "Exact candidates require the unsigned Ironwood testnet candidate profile",
        ));
    }
    if !manifest.agreement.extensions.is_empty()
        || manifest.participants.iter().any(|p| !p.charges.is_empty())
    {
        return Err(ApiError::new(
            "UNSUPPORTED_CAPABILITY",
            "Candidate construction does not qualify extensions, matching conditions or separate service charges",
        ));
    }
    let now = OffsetDateTime::now_utc();
    if manifest
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
    let roster = planning::preview_intents(view)?;
    if view.roster_selected {
        let selected: BTreeSet<_> = roster.iter().map(|i| i.participant_id.as_str()).collect();
        let proposed: BTreeSet<_> = manifest
            .participants
            .iter()
            .map(|p| p.participant_id.as_str())
            .collect();
        if selected != proposed {
            return Err(ApiError::new(
                "INVALID_TERMS",
                "Candidate participants must exactly match the explicitly selected roster",
            ));
        }
    }
    for participant in &manifest.participants {
        let intent = roster
            .iter()
            .find(|i| i.participant_id == participant.participant_id)
            .ok_or_else(|| {
                ApiError::new(
                    "MISSING_EVIDENCE",
                    "Every proposed participant needs a current eligible local intent in the selected roster",
                )
            })?;
        if !intent.conditions.is_empty() {
            return Err(ApiError::new(
                "UNSUPPORTED_CAPABILITY",
                "Conditional intents require a qualified policy verifier",
            ));
        }
        if intent
            .valid_until
            .as_deref()
            .is_some_and(|t| expired(t, now))
        {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "A selected participant intent has expired",
            ));
        }
        if participant.contribution > intent.desired_contribution
            || participant.maximum_net_debit > intent.maximum_net_debit
            || participant.fee_cap > intent.fee_cap
        {
            return Err(ApiError::new(
                "DEBIT_CAP_EXCEEDED",
                "Candidate contribution, maximum debit or fee cap exceeds the selected local intent",
            ));
        }
        if view.roster_selected && participant.contribution != intent.desired_contribution {
            return Err(ApiError::new(
                "INVALID_TERMS",
                "Candidate contribution must equal the explicitly selected intent amount; revised amounts require new intent and roster review",
            ));
        }
    }
    Ok(())
}

fn expired(timestamp: &str, now: OffsetDateTime) -> bool {
    OffsetDateTime::parse(timestamp, &Rfc3339).map_or(true, |deadline| deadline <= now)
}
fn check_review_limit(view: &AgreementView) -> Result<()> {
    if view
        .candidates
        .iter()
        .map(|c| c.reviews.len())
        .sum::<usize>()
        >= MAX_REVIEWS
    {
        return Err(ApiError::new(
            "RESOURCE_EXHAUSTED",
            "Candidate review history limit reached",
        ));
    }
    Ok(())
}
fn claims_report(proposal: &Proposal) -> Result<CandidateReview> {
    Ok(CandidateReview {
        report_id: Uuid::new_v4().to_string(), candidate_id: proposal.input().proposal_id.clone(),
        manifest_digest: proposal.manifest_digest().into(), checked_at: now(), status: "claims_checked_only".into(),
        scope: "syntax_and_claimed_accounting".into(), artifact_digest: None, effects_commitment: None, review_binding: None,
        exact_fee_zatoshis: proposal.manifest().transaction_fee.as_zatoshis().to_string(),
        participant_net_debits_zatoshis: proposal.accounting().participant_net_debits.iter().map(|(id, amount)| (id.clone(), amount.as_zatoshis().to_string())).collect(),
        economic_terms_verified: false, account_associations_authenticated: false, disclosure_consents_authenticated: false,
        human_approval: "not_requested".into(), chain_validated: false, authorization_allowed: false, distribution_allowed: false,
        artifact_persistence: "no_artifact".into(), blocking_reasons: vec!["Input ownership, recipient receivers, return ownership and transaction effects are unverified claims".into(), "No human approval, authenticated disclosure consent or chain evidence is established".into()],
    })
}
fn corrupted() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Immutable candidate snapshot or accounting digest mismatch; preserve the journal and do not authorize",
    )
}

#[cfg(feature = "candidate-construction")]
pub(crate) fn private_request_digest(
    chain: wholepact_protocol::construction::ConstructionContext,
    contributions: &[wholepact_protocol::construction::OwnedContribution],
    declarations: &[wholepact_protocol::construction::DisclosureAcknowledgement],
) -> Result<String> {
    fn field(hash: &mut Sha256, bytes: &[u8]) {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    if contributions.len() > 32
        || declarations.len() > 32
        || contributions.iter().any(|c| c.notes.len() > 64)
    {
        return Err(ApiError::new(
            "RESOURCE_EXHAUSTED",
            "Local contribution limits exceeded",
        ));
    }
    let mut hash = Sha256::new();
    hash.update(b"wholepact:private-local-construction:v1\0");
    hash.update(chain.anchor);
    hash.update(chain.anchor_height.to_le_bytes());
    hash.update(chain.anchor_block_hash);
    hash.update(chain.target_height.to_le_bytes());
    hash.update((contributions.len() as u64).to_le_bytes());
    for c in contributions {
        field(&mut hash, c.account_id.as_bytes());
        hash.update(c.fvk.to_bytes());
        hash.update(c.change_address.to_raw_address_bytes());
        hash.update((c.notes.len() as u64).to_le_bytes());
        for n in &c.notes {
            field(&mut hash, n.input_id.as_bytes());
            hash.update(n.note.recipient().to_raw_address_bytes());
            hash.update(n.note.value().inner().to_le_bytes());
            hash.update(n.note.nullifier(&c.fvk).to_bytes());
            hash.update(n.witness.root(n.note.commitment().into()).to_bytes());
        }
    }
    hash.update((declarations.len() as u64).to_le_bytes());
    for d in declarations {
        field(&mut hash, d.account_id.as_bytes());
        hash.update(d.manifest_digest);
        field(&mut hash, d.operator.as_bytes());
        field(&mut hash, d.purpose.as_bytes());
        field(&mut hash, d.retention_policy.as_bytes());
        hash.update((d.reviewer_account_ids.len() as u64).to_le_bytes());
        for reviewer in &d.reviewer_account_ids {
            field(&mut hash, reviewer.as_bytes());
        }
        match d.scope { wholepact_protocol::construction::DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs => hash.update([1]) }
    }
    Ok(hex::encode(hash.finalize()))
}
