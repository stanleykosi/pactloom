//! Manual authorization of one retained, fully proved two-owner proposal.
//!
//! Durability belongs to the immutable proposal, not to permission. A reopened
//! proposal must obtain a new current native review, current protected-wallet
//! ticket and the existing independent witness reservation. No retained DTO can
//! reconstruct the native continuation. Once an original release is committed,
//! this adapter never creates a second attempt: only the exact already-retained
//! result may be delivered through the existing recipient-authenticated IPC.
use super::{
    disclosure::ApprovedWitnessDisclosure, protocol::AuthorizationDeliveryScope,
    AuthorizationCommit, BridgeError, Result,
};
use crate::{
    account::DedicatedAccount,
    consent_journal::{
        AcceptedManifestRecord, AccountEnrollmentRecord, ApprovedSpendConsent, NativeConsentDecision,
        OriginalSpendConsent, PreparedSpendConsent, SignerConsentJournal, SignerConsentSession,
        SpendConsentTerms,
    },
    manifest::ReviewInputs,
};
use sha2::{Digest, Sha256};
use wholepact_authority::{AuthorityClient, AuthorityHead};
use wholepact_protocol::{
    durable_proposal_v1::{FixedProposalIdentityV1, VerifiedFixedProposal},
    review_manifest::{policy_fingerprint, verify_manifest_policy},
};
use wholepact_wallet::wallet::protected_sync::{key_use::WalletKeyUseTicket, ProtectedWalletSync};

/// Reloads the exact protected proposal record and its independently retained
/// full policy. A caller must not hold a database lock across this callback or
/// across key use. Returning a digest, parsed descriptor or verification flag is
/// deliberately insufficient: every reload must construct the opaque verified
/// proposal through the maintained protocol verifier.
pub type FixedProposalSource<'a> = dyn Fn() -> Result<VerifiedFixedProposal> + 'a;

/// A displayable fresh review, not permission. Neither this type nor its approved
/// successor is serializable, cloneable, or constructible from saved evidence.
pub struct PreparedDurableProposalReview<'a> {
    source: &'a FixedProposalSource<'a>,
    proposal: VerifiedFixedProposal,
    inputs: ReviewInputs,
    prepared: PreparedSpendConsent,
}

/// One immediate genuine native decision for the exact fixed proposal. Dropping
/// it abandons permission, not durable proposal data or previously held exposure.
///
/// Saved data cannot restore this continuation:
/// ```compile_fail
/// use wholepact_signer::authority_bridge::durable_proposal_v1::ApprovedDurableProposalAction;
/// let action: ApprovedDurableProposalAction<'static> = serde_json::from_str("{}").unwrap();
/// ```
pub struct ApprovedDurableProposalAction<'a> {
    source: &'a FixedProposalSource<'a>,
    proposal: VerifiedFixedProposal,
    inputs: ReviewInputs,
    approval: ApprovedSpendConsent,
    original: OriginalSpendConsent,
}

/// A stable correlation identifier only, never an authorization capability.
/// It intentionally excludes wall-clock time, wallet tip and attempt counters.
pub fn manual_authorization_id(
    identity: &FixedProposalIdentityV1,
    account_id: &str,
) -> Result<String> {
    crate::review::validate_label(account_id).map_err(|_| BridgeError::Binding)?;
    if identity.schema_version != 1
        || identity.proposal_binding.len() != 64
        || !identity
            .proposal_binding
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Binding);
    }
    let mut hash = Sha256::new();
    hash.update(b"wholepact:durable-manual-proposal-authorization:v1\0");
    for value in [identity.proposal_binding.as_str(), account_id] {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    Ok(format!("durable-v1-{}", hex::encode(hash.finalize())))
}

/// Prepare only from a freshly reloaded verified proposal and genuine current
/// signer-owned wallet selection. The accepted enrollment/manifest must belong
/// to the current native session; old native receipts are never renewed here.
/// Human waiting happens before this call, or discards and repeats this review.
#[allow(clippy::too_many_arguments)]
pub fn prepare_manual_review<'a>(
    source: &'a FixedProposalSource<'a>,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    enrollment: &AccountEnrollmentRecord,
    manifest: &AcceptedManifestRecord,
    account: &DedicatedAccount,
    inputs: ReviewInputs,
) -> Result<PreparedDurableProposalReview<'a>> {
    let proposal = source()?;
    validate_review_inputs(&proposal, manifest, &inputs)?;
    let account_id = account.account_id().map_err(|_| BridgeError::Binding)?;
    let authorization_id = manual_authorization_id(proposal.identity(), &account_id)?;
    require_unreleased(
        journal,
        session,
        proposal.identity(),
        &authorization_id,
        &account_id,
    )?;
    // This is the existing genuine review constructor. It independently binds
    // the actual signer FVK, accepted manifest, current local selection, exact
    // economics and the current native session. It grants no key-use permission.
    let prepared = session.prepare_spend(
        enrollment,
        manifest,
        account,
        proposal.private_proved_pczt_bytes(),
        &inputs,
        &authorization_id,
    )?;
    validate_original_binding(&proposal, prepared.record(), &account_id)?;
    Ok(PreparedDurableProposalReview {
        source,
        proposal,
        inputs,
        prepared,
    })
}

impl PreparedDurableProposalReview<'_> {
    /// Borrowed for the existing native spending display and separate exact
    /// witness-disclosure review. No extraction of approval is provided.
    pub fn prepared_spend(&self) -> &PreparedSpendConsent {
        &self.prepared
    }

    pub fn identity(&self) -> &FixedProposalIdentityV1 {
        self.proposal.identity()
    }
}

impl<'a> PreparedDurableProposalReview<'a> {
    /// Only the existing native decision issuer can provide this opaque input.
    /// A JSON success flag, terminal acknowledgement or durable data is not one.
    pub fn approve(
        self,
        session: &SignerConsentSession,
        decision: NativeConsentDecision,
    ) -> Result<ApprovedDurableProposalAction<'a>> {
        check_reload(self.source, &self.proposal)?;
        let original = self.prepared.record().clone();
        let approval = session.approve_spend(self.prepared, decision)?;
        Ok(ApprovedDurableProposalAction {
            source: self.source,
            proposal: self.proposal,
            inputs: self.inputs,
            approval,
            original,
        })
    }
}

impl ApprovedDurableProposalAction<'_> {
    /// Commit exact release intent and conservative exposure before contacting
    /// the independently authenticated witness, then use the existing held
    /// wallet/native key-use fence. An error after release requires recovery,
    /// never a new authorization ID, new candidate, or reservation refund.
    ///
    /// Only a non-sensitive receipt is returned. The established native IPC
    /// exports the already-retained detached assigned signatures to the exact
    /// approved recipient; a different recipient needs its separate decision.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        account: &DedicatedAccount,
        expected_head: AuthorityHead,
        disclosure: ApprovedWitnessDisclosure,
        client: &AuthorityClient,
        wallet: &mut ProtectedWalletSync,
        ticket: &WalletKeyUseTicket,
    ) -> Result<AuthorizationCommit> {
        let account_id = account.account_id().map_err(|_| BridgeError::Binding)?;
        validate_original_binding(&self.proposal, &self.original, &account_id)?;
        require_unreleased(
            journal,
            session,
            self.proposal.identity(),
            &self.original.terms().authorization_id,
            &account_id,
        )?;
        check_ticket(&self.original, ticket)?;
        if ticket.evidence().fvk().to_bytes()
            != account.fvk().map_err(|_| BridgeError::Binding)?.to_bytes()
        {
            return Err(BridgeError::Binding);
        }
        disclosure.check(&self.original, Some(client))?;
        if disclosure.record().expected_head != expected_head {
            return Err(BridgeError::Binding);
        }
        let check = || check_reload(self.source, &self.proposal);
        check()?;
        // record_original_consent_release atomically rejects another live
        // authorization for the obligation or any reserved input, including a
        // different ID. The preflight above does not replace that safety fence.
        let pending = super::prepare_authorization(
            journal,
            session,
            account,
            self.approval,
            self.proposal.private_proved_pczt_bytes(),
            expected_head,
            AuthorizationDeliveryScope {
                candidate_id: self.proposal.identity().proposal_id.clone(),
            },
            disclosure,
        )?;
        check()?;
        let reserved = pending.reserve(client)?;
        reserved.authorize_with_wallet_checked(wallet, ticket, &self.inputs, &check)
    }
}

/// Read only the receipt for an already persisted exact result. This does not
/// restore a signing continuation or export signatures. A committed original
/// without its exact retained result is recovery-required, even before key use.
pub fn retained_manual_commit(
    source: &FixedProposalSource<'_>,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    account: &DedicatedAccount,
) -> Result<Option<AuthorizationCommit>> {
    let proposal = source()?;
    let account_id = account.account_id().map_err(|_| BridgeError::Binding)?;
    let authorization_id = manual_authorization_id(proposal.identity(), &account_id)?;
    let Some(original) = journal.original_authorization(&authorization_id, session)? else {
        return Ok(None);
    };
    validate_original_binding(&proposal, original.original_consent(), &account_id)?;
    let lease = journal.acquire_original_authorization(&authorization_id, session)?;
    let result = journal.bridge_result(&lease).map_err(recovery_if_incomplete)?;
    check_reload(source, &proposal)?;
    Ok(Some(AuthorizationCommit::from(&result)))
}

fn recovery_if_incomplete(error: BridgeError) -> BridgeError {
    match error {
        BridgeError::Missing | BridgeError::Uncertain => BridgeError::RecoveryRequired,
        other => other,
    }
}

fn require_unreleased(
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    identity: &FixedProposalIdentityV1,
    authorization_id: &str,
    account_id: &str,
) -> Result<()> {
    if let Some(original) = journal.original_authorization(authorization_id, session)? {
        let t = original.original_consent().terms();
        if t.account_id != account_id
            || t.proposal_id != identity.proposal_id
            || t.proposal_digest != identity.proposal_digest
            || t.artifact_digest != identity.proved_artifact_digest
            || t.manifest_digest != identity.manifest_digest
        {
            return Err(BridgeError::Conflict);
        }
        return Err(BridgeError::RecoveryRequired);
    }
    Ok(())
}

fn check_reload(source: &FixedProposalSource<'_>, original: &VerifiedFixedProposal) -> Result<()> {
    let current = source()?;
    if current.identity() != original.identity()
        || current.private_proved_pczt_bytes() != original.private_proved_pczt_bytes()
        || policy_fingerprint(current.private_review_policy())
            != policy_fingerprint(original.private_review_policy())
    {
        return Err(BridgeError::Conflict);
    }
    Ok(())
}

fn validate_review_inputs(
    fixed: &VerifiedFixedProposal,
    manifest: &AcceptedManifestRecord,
    inputs: &ReviewInputs,
) -> Result<()> {
    let identity = fixed.identity();
    let proposal = wholepact_core::Proposal::validate(manifest.proposal_input().clone())
        .map_err(|_| BridgeError::Binding)?;
    if proposal.input().proposal_id != identity.proposal_id
        || proposal.proposal_digest() != identity.proposal_digest
        || proposal.manifest_digest() != identity.manifest_digest
        || inputs.policy.participants.len() != 2
        || policy_fingerprint(&inputs.policy) != identity.policy_digest
        || hex::encode(inputs.policy.anchor) != identity.anchor
        || inputs.own_selection.key_use_policy.is_none()
    {
        return Err(BridgeError::Binding);
    }
    verify_manifest_policy(
        &proposal,
        &inputs.policy,
        &inputs.input_actions,
        &inputs.output_actions,
    )
    .map_err(|_| BridgeError::Verification)?;
    fixed
        .verify_action_mappings(&inputs.input_actions, &inputs.output_actions)
        .map_err(|_| BridgeError::Binding)?;
    Ok(())
}

fn validate_original_binding(
    fixed: &VerifiedFixedProposal,
    original: &OriginalSpendConsent,
    account_id: &str,
) -> Result<()> {
    let identity = fixed.identity();
    let t = original.terms();
    validate_terms_binding(identity, t, account_id)?;
    let policy = fixed.private_review_policy();
    let owner = policy
        .participants
        .iter()
        .position(|p| p.account_id == account_id)
        .ok_or(BridgeError::Binding)?;
    let own_inputs: Vec<_> = policy
        .inputs
        .iter()
        .filter(|input| input.participant_index == owner)
        .collect();
    if fixed.economic_review().net_debits_zatoshis().get(owner)
        != Some(&t.maximum_debit_zatoshis)
        || t.transaction_fee_zatoshis != policy.exact_fee_zatoshis
        || t.fee_share_zatoshis != policy.participants[owner].fee_share_zatoshis
        || own_inputs.len() != t.input_bindings.len()
        || own_inputs.iter().any(|input| {
            !t.input_bindings.iter().any(|bound| {
                bound.action_index == input.action_index as u64
                    && bound.nullifier == hex::encode(input.nullifier)
                    && bound.value_zatoshis == input.value_zatoshis
            })
        })
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

fn validate_terms_binding(
    identity: &FixedProposalIdentityV1,
    t: &SpendConsentTerms,
    account_id: &str,
) -> Result<()> {
    if t.automation.is_some()
        || t.account_id != account_id
        || t.authorization_id != manual_authorization_id(identity, account_id)?
        || t.agreement_id != identity.agreement_id
        || t.obligation_id != identity.obligation_id
        || t.proposal_id != identity.proposal_id
        || t.proposal_digest != identity.proposal_digest
        || t.manifest_digest != identity.manifest_digest
        || t.artifact_digest != identity.proved_artifact_digest
        || t.effects_digest != identity.effects_commitment
        || t.review_binding != identity.review_binding
        || t.wallet_snapshot.anchor_root != identity.anchor
        || t.transaction_expiry_height != identity.expiry_height
        || t.wallet_key_use_policy.is_none()
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

fn check_ticket(original: &OriginalSpendConsent, ticket: &WalletKeyUseTicket) -> Result<()> {
    let t = original.terms();
    let policy = t
        .wallet_key_use_policy
        .as_ref()
        .ok_or(BridgeError::Permission)?;
    ticket.validate_policy(policy)?;
    let evidence = ticket.evidence();
    let context = evidence.context();
    if evidence.account_id() != t.account_id
        || context.tip_height != t.wallet_snapshot.tip_height
        || hex::encode(context.tip_hash_protocol) != t.wallet_snapshot.tip_hash
        || context.anchor_height != t.wallet_snapshot.anchor_height
        || hex::encode(context.anchor_hash_protocol) != t.wallet_snapshot.anchor_hash
        || hex::encode(context.anchor_root) != t.wallet_snapshot.anchor_root
        || evidence.inputs().len() != t.input_bindings.len()
        || t.input_bindings.iter().any(|input| {
            !evidence.inputs().iter().any(|selected| {
                selected.input_id() == input.input_id
                    && hex::encode(selected.nullifier()) == input.nullifier
                    && selected.value_zatoshis() == input.value_zatoshis
            })
        })
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

#[cfg(test)]
#[path = "durable_proposal_v1_tests.rs"]
mod tests;
