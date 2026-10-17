//! Full mathematical review of the narrow two-account durable profile. Incoming
//! material remains untrusted data. This module does not authenticate an owner,
//! authorize disclosure, accept a manifest, issue native consent, or grant key use.
//! The concrete intake must independently retain the exact authorized audience;
//! the native action must separately use fresh current-session consent records.
use crate::authority_bridge::durable_construction_v1::{
    DurableConstructionOutboxV1, DurableConstructionRequestV1, DurableConstructionScopeV1,
};
use crate::{Error, Result};
use std::{collections::BTreeSet, sync::Arc};
use wholepact_core::{FeePolicy, OutputAllocation, Proposal};
use wholepact_protocol::{
    construction::{ConstructionContext, InputActionMapping, OutputActionMapping},
    durable_proposal_v1::VerifiedFixedProposal,
    proving::ProvingLimits,
    review::{
        InputPolicy, OutputPolicy, OutputPurpose, ParticipantPolicy, ReviewPolicy,
        decode_testnet_receiver,
    },
};
use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
    HistoricalConstructionMaterialV1, HistoricalConstructionReviewEvidenceV1,
};
use zcash_protocol::memo::MemoBytes;

/// Owned immutable mathematics only, deliberately not a saved review approval.
/// Static proof verification is performed once, before the short immediate
/// native/wallet/key-use interval. Real source and permission checks are separate.
pub(super) struct VerifiedDurableEconomicsV1 {
    proposal: Proposal,
    verified: Arc<VerifiedFixedProposal>,
    context: ConstructionContext,
    input_actions: Vec<InputActionMapping>,
    output_actions: Vec<OutputActionMapping>,
    original_contributions: Vec<DurableConstructionRequestV1>,
}
impl VerifiedDurableEconomicsV1 {
    /// The caller supplies the exact independently native-accepted proposal, not
    /// a constructor's substitute. Material can be hostile: its full note math,
    /// canonical FVK account identities and nullifier mappings are reconstructed.
    /// This function must only be called after the actual privacy intake permits
    /// these bytes to this reviewer. Successful math never retroactively permits
    /// their transmission or claims that either owner already approved spending.
    pub(super) fn verify(
        proposal: &Proposal,
        unsigned: &[u8],
        proved: &[u8],
        contributions: &[DurableConstructionOutboxV1],
        reviewer_account_id: &str,
        output_actions: Vec<OutputActionMapping>,
        limits: ProvingLimits,
    ) -> Result<Self> {
        plain_profile(proposal)?;
        if contributions.len() != 2 {
            return Err(Error::Verification);
        }
        for contribution in contributions {
            contribution.validate().map_err(|_| Error::Verification)?;
            let request = contribution.request();
            if request.scope.proposal != *proposal.input()
                || !request
                    .scope
                    .permits_local_reviewer_account(reviewer_account_id)
                    .map_err(|_| Error::Verification)?
            {
                return Err(Error::Verification);
            }
        }
        // A bounded canonical structural parse precedes reading raw nullifiers.
        // The final verifier below additionally proves every real allocation,
        // all-account economics and the exact proof-only predecessor relation.
        let structure =
            wholepact_protocol::inspect_candidate(unsigned).map_err(|_| Error::Verification)?;
        if limits.maximum_actions == 0
            || limits.maximum_actions > wholepact_protocol::proving::MAX_PROVING_ACTIONS
            || structure.actions > limits.maximum_actions
        {
            return Err(Error::Verification);
        }
        let parsed = pczt::Pczt::parse(unsigned).map_err(|_| Error::Verification)?;
        let evidence = contributions
            .iter()
            .map(|m| {
                m.request()
                    .material
                    .historical_review_evidence()
                    .map_err(|_| Error::Verification)
            })
            .collect::<Result<Vec<_>>>()?;
        let (policy, context, input_actions) =
            derive_policy(proposal, &evidence, &parsed, &output_actions)?;
        let verified = Arc::new(
            VerifiedFixedProposal::verify(
                unsigned,
                proved,
                proposal,
                &policy,
                &input_actions,
                &output_actions,
                limits,
            )
            .map_err(|_| Error::Verification)?,
        );
        Ok(Self {
            proposal: proposal.clone(),
            verified,
            context,
            input_actions,
            output_actions,
            original_contributions: contributions.iter().map(|c| c.request().clone()).collect(),
        })
    }

    pub(super) fn proposal(&self) -> &Proposal {
        &self.proposal
    }
    pub(super) fn verified(&self) -> &Arc<VerifiedFixedProposal> {
        &self.verified
    }
    pub(super) fn fixed_context(&self) -> ConstructionContext {
        self.context
    }
    pub(super) fn input_actions(&self) -> &[InputActionMapping] {
        &self.input_actions
    }
    pub(super) fn output_actions(&self) -> &[OutputActionMapping] {
        &self.output_actions
    }

    pub(super) fn original_for_account(
        &self,
        account_id: &str,
    ) -> Result<(
        &HistoricalConstructionMaterialV1,
        &DurableConstructionScopeV1,
    )> {
        let original = self
            .original_contributions
            .iter()
            .find(|c| c.scope.account_id == account_id)
            .ok_or(Error::Verification)?;
        Ok((&original.material, &original.scope))
    }
}

fn plain_profile(proposal: &Proposal) -> Result<()> {
    let m = proposal.manifest();
    if m.agreement.network_profile_id != "ironwood-testnet-nu7-candidate"
        || m.participants.len() != 2
        || m.agreement.recipients.len() != 1
        || !matches!(m.agreement.fee_policy, FeePolicy::ProRata)
        || !m.agreement.extensions.is_empty()
        || m.participants.iter().any(|p| !p.charges.is_empty())
        || m.inputs.iter().any(|i| i.ownership_evidence_ref.is_some())
        || m.outputs.iter().any(|o| match &o.allocation {
            OutputAllocation::Charge { .. } => true,
            OutputAllocation::Return {
                ownership_evidence_ref,
                ..
            } => ownership_evidence_ref.is_some(),
            OutputAllocation::Recipient { .. } => false,
        })
    {
        return Err(Error::Verification);
    }
    Ok(())
}

fn derive_policy(
    proposal: &Proposal,
    evidence: &[HistoricalConstructionReviewEvidenceV1],
    parsed: &pczt::Pczt,
    output_actions: &[OutputActionMapping],
) -> Result<(ReviewPolicy, ConstructionContext, Vec<InputActionMapping>)> {
    let m = proposal.manifest();
    let first = evidence.first().ok_or(Error::Verification)?;
    if evidence.len() != 2 || evidence[0].account_id == evidence[1].account_id {
        return Err(Error::Verification);
    }
    let anchor = &first.context;
    if evidence.iter().any(|e| {
        e.context.anchor_root != anchor.anchor_root
            || e.context.anchor_height != anchor.anchor_height
            || e.context.anchor_hash_protocol != anchor.anchor_hash_protocol
    }) {
        return Err(Error::Verification);
    }
    let mut participants = Vec::new();
    let mut inputs = Vec::new();
    let mut input_actions = Vec::new();
    let mut ids = BTreeSet::new();
    let mut nullifiers = BTreeSet::new();
    let mut action_indices = BTreeSet::new();
    for (participant_index, participant) in m.participants.iter().enumerate() {
        let own = evidence
            .iter()
            .find(|e| e.account_id == participant.account_id)
            .ok_or(Error::Verification)?;
        if own.inputs.is_empty() {
            return Err(Error::Verification);
        }
        participants.push(ParticipantPolicy {
            account_id: own.account_id.clone(),
            fvk: own.fvk.clone(),
            contribution_zatoshis: participant.contribution.as_zatoshis(),
            fee_share_zatoshis: participant.fee_share.as_zatoshis(),
            maximum_net_debit_zatoshis: participant.maximum_net_debit.as_zatoshis(),
        });
        for note in &own.inputs {
            let claimed = m
                .inputs
                .iter()
                .find(|i| i.input_id == note.input_id)
                .ok_or(Error::Verification)?;
            if claimed.account_id != own.account_id
                || claimed.participant_id != participant.participant_id
                || claimed.amount.as_zatoshis() != note.value_zatoshis
                || !ids.insert(note.input_id.as_str())
                || !nullifiers.insert(note.nullifier)
            {
                return Err(Error::Verification);
            }
            let matching = parsed
                .ironwood()
                .actions()
                .iter()
                .enumerate()
                .filter(|(_, action)| action.spend().nullifier() == &note.nullifier)
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if matching.len() != 1 || !action_indices.insert(matching[0]) {
                return Err(Error::Verification);
            }
            let action_index = matching[0];
            inputs.push(InputPolicy {
                action_index,
                participant_index,
                nullifier: note.nullifier,
                value_zatoshis: note.value_zatoshis,
            });
            input_actions.push(InputActionMapping {
                input_id: note.input_id.clone(),
                account_id: own.account_id.clone(),
                action_index,
            });
        }
    }
    if inputs.len() != m.inputs.len() {
        return Err(Error::Verification);
    }
    let mut outputs = Vec::new();
    let mut output_ids = BTreeSet::new();
    let mut output_indices = BTreeSet::new();
    for map in output_actions {
        if !output_ids.insert(map.output_id.as_str()) || !output_indices.insert(map.action_index) {
            return Err(Error::Verification);
        }
        let declared = m
            .outputs
            .iter()
            .find(|o| o.output_id == map.output_id)
            .ok_or(Error::Verification)?;
        let (purpose, memo) = match &declared.allocation {
            OutputAllocation::Recipient { recipient_id } => {
                let recipient = m
                    .agreement
                    .recipients
                    .iter()
                    .find(|r| r.recipient_id == *recipient_id)
                    .ok_or(Error::Verification)?;
                let memo = recipient
                    .memo
                    .as_ref()
                    .map(|v| MemoBytes::from_bytes(v.as_bytes()))
                    .transpose()
                    .map_err(|_| Error::Verification)?
                    .unwrap_or_else(MemoBytes::empty);
                (OutputPurpose::Recipient, memo.into_bytes())
            }
            OutputAllocation::Return { account_id, .. } => {
                let participant_index = participants
                    .iter()
                    .position(|p| p.account_id == *account_id)
                    .ok_or(Error::Verification)?;
                (
                    OutputPurpose::Return { participant_index },
                    MemoBytes::empty().into_bytes(),
                )
            }
            OutputAllocation::Charge { .. } => return Err(Error::Verification),
        };
        outputs.push(OutputPolicy {
            action_index: map.action_index,
            receiver: decode_testnet_receiver(&declared.address)
                .map_err(|_| Error::Verification)?,
            value_zatoshis: declared.amount.as_zatoshis(),
            memo,
            purpose,
        });
    }
    if outputs.len() != m.outputs.len() {
        return Err(Error::Verification);
    }
    // The maintained constructor's policy digest is order-sensitive: retain
    // accepted manifest input/output order, never incoming package/map order.
    // Otherwise the two independent reviewers could derive different durable
    // identifiers for the very same valid fixed transaction.
    input_actions.sort_by_key(|map| {
        m.inputs
            .iter()
            .position(|i| i.input_id == map.input_id)
            .unwrap_or(usize::MAX)
    });
    inputs.sort_by_key(|input| {
        input_actions
            .iter()
            .position(|map| map.action_index == input.action_index)
            .unwrap_or(usize::MAX)
    });
    outputs.sort_by_key(|output| {
        output_actions
            .iter()
            .find(|map| map.action_index == output.action_index)
            .and_then(|map| m.outputs.iter().position(|o| o.output_id == map.output_id))
            .unwrap_or(usize::MAX)
    });
    let manifest_digest = hex::decode(proposal.manifest_digest())
        .map_err(|_| Error::Verification)?
        .try_into()
        .map_err(|_| Error::Verification)?;
    let context = ConstructionContext {
        anchor: anchor.anchor_root,
        anchor_height: anchor.anchor_height,
        anchor_block_hash: anchor.anchor_hash_protocol,
        // Historical context is data only. The fresh wallet method replaces this
        // single field with its current observed tip+1, never the fixed anchor.
        target_height: anchor
            .tip_height
            .checked_add(1)
            .ok_or(Error::Verification)?,
    };
    Ok((
        ReviewPolicy {
            manifest_digest,
            participants,
            inputs,
            outputs,
            exact_fee_zatoshis: m.transaction_fee.as_zatoshis(),
            expiry_height: m.expiry_height,
            anchor: anchor.anchor_root,
        },
        context,
        input_actions,
    ))
}
