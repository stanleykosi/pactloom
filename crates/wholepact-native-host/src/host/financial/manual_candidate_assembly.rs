//! Actual-input, unreviewed multi-owner claims. This module cannot construct a
//! transaction, reserve an input, disclose witnesses, sign or persist authority.
//! The only owner constructor consumes genuine selection owners and native
//! leases. Review access stays current; no detached Proposal getter is provided.
use super::{Host, candidate_selection::SelectedCandidateInputs};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_core::{
    Amount, ClaimedInput, ClaimedOutput, OutputAllocation, Proposal, ProposalInput,
    ProposalManifest,
    manual_candidate_selection::{ManualCandidateEconomicIntent, ManualCandidateInvocation},
    manual_construction::{ManualConstructionInput, ManualSelectionContext},
};
use wholepact_signer::authority_bridge::manual_candidate_selection::SignerCandidateSelectionLease;

/// No Clone, Debug, serialization, restore factory or raw builder conversion.
/// ProtectedContribution retains a weak source-generation reference: the actual
/// fresh wallet controllers MUST remain alive outside this owner. Their drop,
/// rescan, expiry or restart makes this object unreadable, never renewable.
pub(in crate::host) struct UnreviewedManualCandidate<'client> {
    proposal: Proposal,
    owners: Vec<SelectedCandidateOwner<'client>>,
}
struct SelectedCandidateOwner<'client> {
    selected: SelectedCandidateInputs,
    lease: SignerCandidateSelectionLease<'client>,
}
impl<'client> UnreviewedManualCandidate<'client> {
    /// An exact complete set is mandatory. There is no partial candidate and no
    /// placeholder input, fallback return or implicit revision of the economics.
    pub(in crate::host) fn assemble(
        host: &Host,
        selections: Vec<(
            SelectedCandidateInputs,
            SignerCandidateSelectionLease<'client>,
        )>,
    ) -> Result<Self> {
        if !(2..=32).contains(&selections.len()) {
            return Err(Error::Invalid);
        }
        let owners: Vec<_> = selections
            .into_iter()
            .map(|(selected, lease)| SelectedCandidateOwner { selected, lease })
            .collect();
        for owner in &owners {
            owner.check_current(host)?;
        }
        let proposal = assemble_current_claims(&owners)?;
        let candidate = Self { proposal, owners };
        candidate.check_current(host)?;
        Ok(candidate)
    }

    /// This is a live selection/display gate, not a durable completion permit.
    /// In particular, a later exact native construction review cannot be inferred
    /// from retaining this object or copying its displayed inert proposal claims.
    pub(in crate::host) fn check_current(&self, host: &Host) -> Result<()> {
        for owner in &self.owners {
            owner.check_current(host)?;
        }
        Ok(())
    }

    /// Display through the admitted Host's terminal under its retained principal
    /// permission. This does not assert Host foreground focus while the signer
    /// owns native focus. Recheck every native owner and source before and after
    /// each display operation. No arbitrary callback or ungated proposal borrow
    /// lets a caller defer this access past focus, revocation or original expiry.
    pub(in crate::host) fn display_current(&self, host: &Host) -> Result<()> {
        self.check_current(host)?;
        host.terminal.message("UNREVIEWED actual-input candidate. No construction, input reservation, proof, signature or transaction authorization exists. Displayed input and same-account return claims still require the separate full exact native construction review.\n")?;
        self.check_current(host)?;
        host.terminal.json(self.proposal.input())?;
        self.check_current(host)
    }
}
impl SelectedCandidateOwner<'_> {
    fn check_current(&self, host: &Host) -> Result<()> {
        self.lease.check_current().map_err(|_| Error::Permission)?;
        let request = self.lease.request().map_err(|_| Error::Permission)?;
        let enrollment = &request.scope.inventory.enrollment;
        let access = host.access()?;
        if enrollment.scope.principal_id != access.principal_id
            || enrollment.host.profile_id != host.secrets.profile()
        {
            return Err(Error::Permission);
        }
        host.authority
            .check_financial_principal(&access.principal_id)?;
        let target = host.engine.manual_enrollment_target(access, enrollment)?;
        if target.agreement_revision() != request.scope.economic_intent.candidate_revision {
            return Err(Error::Permission);
        }
        self.selected.current_evidence(&self.lease)?;
        target.require_current_agreement(access, &request.scope.economic_intent.agreement)?;
        self.lease.check_current().map_err(|_| Error::Permission)
    }
}

fn assemble_current_claims(owners: &[SelectedCandidateOwner<'_>]) -> Result<Proposal> {
    let first = owners.first().ok_or(Error::Invalid)?;
    let first_request = first.lease.request().map_err(|_| Error::Permission)?;
    let intent = &first_request.scope.economic_intent;
    let invocation = &first_request.scope.invocation;
    let mut facts = Vec::with_capacity(owners.len());
    let mut viewing_authorities = BTreeSet::new();
    for owner in owners {
        let request = owner.lease.request().map_err(|_| Error::Permission)?;
        request.validate().map_err(|_| Error::Invalid)?;
        require_common_intent(
            intent,
            invocation,
            &request.scope.economic_intent,
            &request.scope.invocation,
        )?;
        let actual = owner.selected.current_evidence(&owner.lease)?;
        let enrollment = &request.scope.inventory.enrollment;
        // Source is this actual held native lease, whose FVK bytes the bridge
        // authenticated against this exact digest. Renaming an account or its
        // derivation domain cannot turn one viewing authority into two owners.
        require_unique_viewing_authority(&mut viewing_authorities, &enrollment.identity)?;
        if actual.account_id != enrollment.identity.account_id
            || actual.context.anchor_height != request.scope.inventory.anchor_height
            || actual.requested_debit_zatoshis
                != request
                    .scope
                    .requested_debit_zatoshis()
                    .map_err(|_| Error::Invalid)?
        {
            return Err(Error::Permission);
        }
        // This is the maintained receiver captured by the restricted collector;
        // decoding checks supported encoding only, never establishes ownership.
        wholepact_protocol::review::decode_testnet_receiver(actual.change_address)
            .map_err(|_| Error::Invalid)?;
        facts.push(CandidateInputFacts {
            participant_id: &enrollment.scope.participant_id,
            account_id: actual.account_id,
            requested_debit_zatoshis: actual.requested_debit_zatoshis,
            selected_zatoshis: actual.selected_zatoshis,
            inputs: actual.inputs,
            context: actual.context,
            change_address: actual.change_address,
        });
    }
    let proposal = reconcile_actual_facts(intent, &facts)?;
    // Policy is checked AFTER complete actual-input arithmetic, for EVERY owner.
    // It comes from each held native request, not from a caller-supplied policy.
    for (owner, actual) in owners.iter().zip(&facts) {
        let request = owner.lease.request().map_err(|_| Error::Permission)?;
        let (checked, returns) = request
            .scope
            .original_policy_origin
            .recipient_policy
            .validate_candidate_for_enrollment(
                &request.scope.inventory.enrollment,
                proposal.input(),
            )
            .map_err(|_| Error::Permission)?;
        let change = actual
            .selected_zatoshis
            .checked_sub(actual.requested_debit_zatoshis)
            .ok_or(Error::Invalid)?;
        if checked != proposal
            || returns.len() != usize::from(change > 0)
            || returns
                .iter()
                .any(|r| r.address != actual.change_address || r.amount_zatoshis != change)
        {
            return Err(Error::Permission);
        }
        // Never serialize/retain selected notes, Merkle paths or viewing keys.
        owner.selected.current_evidence(&owner.lease)?;
    }
    Ok(proposal)
}

/// Pure uniqueness guard. Authentication comes exclusively from the production
/// caller's concrete held native lease; accepting inert identity data here does
/// not create a lease, a maintained selection or a candidate owner.
fn require_unique_viewing_authority<'a>(
    seen: &mut BTreeSet<&'a str>,
    identity: &'a wholepact_core::manual_enrollment::ManualAccountIdentity,
) -> Result<()> {
    if !canonical_hash(&identity.full_viewing_key_digest)
        || !seen.insert(identity.full_viewing_key_digest.as_str())
    {
        return Err(Error::Permission);
    }
    Ok(())
}

fn require_common_intent(
    intent: &ManualCandidateEconomicIntent,
    invocation: &ManualCandidateInvocation,
    actual_intent: &ManualCandidateEconomicIntent,
    actual_invocation: &ManualCandidateInvocation,
) -> Result<()> {
    if intent != actual_intent || invocation != actual_invocation {
        return Err(Error::Permission);
    }
    Ok(())
}

/// Inert borrowed facts used only inside the private projection. Tests may model
/// these facts; neither they nor a Proposal can create SelectedCandidateInputs,
/// a native lease or UnreviewedManualCandidate.
struct CandidateInputFacts<'a> {
    participant_id: &'a str,
    account_id: &'a str,
    requested_debit_zatoshis: u64,
    selected_zatoshis: u64,
    inputs: &'a [ManualConstructionInput],
    context: &'a ManualSelectionContext,
    change_address: &'a str,
}

fn reconcile_actual_facts(
    intent: &ManualCandidateEconomicIntent,
    facts: &[CandidateInputFacts<'_>],
) -> Result<Proposal> {
    let debits = intent.validate().map_err(|_| Error::Invalid)?;
    if intent.agreement.network_profile_id != wholepact_protocol::construction::PROFILE_ID
        || facts.len() != intent.participants.len()
    {
        return Err(Error::Invalid);
    }
    let common = facts.first().ok_or(Error::Invalid)?.context;
    validate_context(common, intent.expiry_height)?;
    let mut participants = BTreeMap::new();
    let mut accounts = BTreeSet::new();
    let mut all_inputs = BTreeSet::new();
    let mut all_nullifiers = BTreeSet::new();
    for actual in facts {
        if actual.context != common
            || !accounts.insert(actual.account_id)
            || participants.insert(actual.participant_id, actual).is_some()
            || actual.inputs.is_empty()
            || actual.inputs.len() > 256
        {
            return Err(Error::Invalid);
        }
        let mut total = 0u64;
        let mut previous = None;
        for input in actual.inputs {
            if input.input_id.is_empty()
                || previous.is_some_and(|id: &str| id >= input.input_id.as_str())
                || !all_inputs.insert(input.input_id.as_str())
                || !canonical_hash(&input.nullifier)
                || !all_nullifiers.insert(input.nullifier.as_str())
                || input.value_zatoshis == 0
            {
                return Err(Error::Invalid);
            }
            total = total
                .checked_add(input.value_zatoshis)
                .filter(|sum| *sum <= wholepact_core::MAX_MONEY)
                .ok_or(Error::Invalid)?;
            previous = Some(input.input_id.as_str());
        }
        if total != actual.selected_zatoshis {
            return Err(Error::Invalid);
        }
    }
    let mut inputs = Vec::new();
    let mut outputs: Vec<_> = intent
        .agreement
        .recipients
        .iter()
        .enumerate()
        .map(|(n, r)| ClaimedOutput {
            output_id: format!("candidate-recipient-{n}"),
            address: r.address.clone(),
            amount: r.amount,
            allocation: OutputAllocation::Recipient {
                recipient_id: r.recipient_id.clone(),
            },
        })
        .collect();
    for (n, participant) in intent.participants.iter().enumerate() {
        let actual = participants
            .get(participant.participant_id.as_str())
            .ok_or(Error::Invalid)?;
        let debit = debits
            .get(&participant.participant_id)
            .ok_or(Error::Invalid)?
            .as_zatoshis();
        if actual.account_id != participant.account_id || actual.requested_debit_zatoshis != debit {
            return Err(Error::Invalid);
        }
        for input in actual.inputs {
            inputs.push(ClaimedInput {
                input_id: input.input_id.clone(),
                participant_id: participant.participant_id.clone(),
                account_id: participant.account_id.clone(),
                amount: Amount::from_zatoshis(input.value_zatoshis).map_err(|_| Error::Invalid)?,
                // Native/local source authority is held privately, not represented
                // by a portable caller-invented ownership evidence identifier.
                ownership_evidence_ref: None,
            });
        }
        for (charge_index, charge) in participant.charges.iter().enumerate() {
            outputs.push(ClaimedOutput {
                output_id: format!("candidate-charge-{n}-{charge_index}"),
                address: charge.address.clone(),
                amount: charge.amount,
                allocation: OutputAllocation::Charge {
                    participant_id: participant.participant_id.clone(),
                    charge_id: charge.charge_id.clone(),
                },
            });
        }
        let change = actual
            .selected_zatoshis
            .checked_sub(debit)
            .ok_or(Error::Invalid)?;
        if change > 0 {
            outputs.push(ClaimedOutput {
                output_id: format!("candidate-return-{n}"),
                address: actual.change_address.to_owned(),
                amount: Amount::from_zatoshis(change).map_err(|_| Error::Invalid)?,
                allocation: OutputAllocation::Return {
                    participant_id: participant.participant_id.clone(),
                    account_id: participant.account_id.clone(),
                    ownership_evidence_ref: None,
                },
            });
        }
    }
    if inputs.len() > 256 || outputs.len() > 256 {
        return Err(Error::Invalid);
    }
    let proposal = ProposalInput {
        proposal_id: intent.proposal_id.clone(),
        previous_proposal_id: intent.previous_proposal_id.clone(),
        created_at: intent.created_at.clone(),
        manifest: ProposalManifest {
            agreement: intent.agreement.clone(),
            participants: intent.participants.clone(),
            inputs,
            outputs,
            transaction_fee: intent.transaction_fee,
            expiry_height: intent.expiry_height,
        },
        artifact_digest: None,
        effects_commitment: None,
    };
    // require_proposal runs Proposal::validate and exact economic equality. It
    // grants no native review, transaction-effects verification or key authority.
    intent
        .require_proposal(&proposal)
        .map_err(|_| Error::Invalid)
}
fn canonical_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_context(context: &ManualSelectionContext, expiry_height: u32) -> Result<()> {
    if context.anchor_height == 0
        || context.tip_height < context.anchor_height
        || context
            .tip_height
            .checked_add(1)
            .is_none_or(|target| target > expiry_height)
        || !canonical_hash(&context.tip_hash_protocol)
        || !canonical_hash(&context.anchor_hash_protocol)
        || !canonical_hash(&context.anchor_root)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

#[cfg(test)]
#[path = "manual_candidate_assembly_tests.rs"]
mod tests;
