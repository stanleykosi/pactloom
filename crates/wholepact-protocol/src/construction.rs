//! Generic construction from independently selected, explicitly disclosed notes.
//!
//! This is an in-memory constructor, not an authenticated intake, consent service,
//! wallet scanner, signer or network client. Caller-owned local state must establish
//! approval, account associations, disclosure permission and chain freshness before
//! passing private data here. No witness-bearing type implements Debug or Serialize.

use crate::review::{
    CryptographicReview, InputPolicy, OutputPolicy, OutputPurpose, ParticipantPolicy, ReviewPolicy,
    decode_testnet_receiver, verify_review,
};
use orchard::{
    Address, Anchor, Note,
    keys::{FullViewingKey, Scope},
    note::NoteVersion,
    tree::MerklePath,
};
use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_core::{OutputAllocation, PrivacyMode, Proposal};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    memo::MemoBytes,
    value::Zatoshis,
};

pub const PROFILE_ID: &str = "ironwood-testnet-nu7-candidate";

/// A locally selected note. The opaque input ID binds to the accepted manifest.
pub struct SpendableNote {
    pub input_id: String,
    pub note: Note,
    pub witness: MerklePath,
}

/// Ownership is checked cryptographically; account identity remains caller context.
pub struct OwnedContribution {
    pub account_id: String,
    pub fvk: FullViewingKey,
    pub notes: Vec<SpendableNote>,
    pub change_address: Address,
}

/// Caller-observed context, not independently verified chain evidence.
#[derive(Clone, Copy)]
pub struct ConstructionContext {
    pub anchor: [u8; 32],
    pub anchor_height: u32,
    /// Consensus protocol byte order, not a displayed reversed block-hash string.
    pub anchor_block_hash: [u8; 32],
    pub target_height: u32,
}

/// Exact privacy declaration required by this broad-witness construction profile.
/// This is NOT authenticated consent: a transport/controller must verify the
/// participant's approval before exporting these fields to this process.
pub struct DisclosureAcknowledgement {
    pub account_id: String,
    pub manifest_digest: [u8; 32],
    pub operator: String,
    /// Exact complete participant account roster receiving broad review evidence.
    /// This does not authenticate those accounts or authorize actual transmission.
    pub reviewer_account_ids: Vec<String>,
    pub purpose: String,
    pub retention_policy: String,
    pub scope: DisclosureScope,
}

pub enum DisclosureScope {
    /// Includes full dedicated-account viewing authority, selected note contents,
    /// witness, values and outputs. FVK exposure is persistent and not revocable.
    DedicatedAccountFvkAndSelectedNotesAndOutputs,
}

#[derive(Clone)]
pub struct InputActionMapping {
    pub input_id: String,
    pub account_id: String,
    pub action_index: usize,
}
#[derive(Clone)]
pub struct OutputActionMapping {
    pub output_id: String,
    pub action_index: usize,
}

/// Sensitive output, deliberately not Debug/Serialize. The PCZT contains broad
/// private witness material. A caller must authorize and encrypt each disclosure.
pub struct ConstructedProposal {
    pub pczt_bytes: Vec<u8>,
    pub review_policy: ReviewPolicy,
    pub economic_review: CryptographicReview,
    pub input_actions: Vec<InputActionMapping>,
    pub output_actions: Vec<OutputActionMapping>,
    pub context: ConstructionContext,
    /// False even after a successful construction; no chain query happened.
    pub chain_validated: bool,
    /// False; declarations were checked for consistency, not authenticated.
    pub disclosure_consents_authenticated: bool,
    /// Always false: this constructor never grants export or release authority.
    pub distribution_allowed: bool,
    pub authorization_allowed: bool,
}

fn check(ok: bool, reason: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn bounded_text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

/// Construct only the exact accepted fixed-contribution manifest. This validates
/// terms again, but a `Proposal` is not itself a human approval or authorization.
///
/// The selected profile requires a declared common constructor/prover, dedicated
/// accounts and explicit manifest-bound broad-witness declarations naming the operator
/// and complete participant reviewer roster. LocalOnly,
/// unknown extensions and service charges fail closed. No credentials are loaded,
/// signatures released, proof generated or external state changed.
pub fn construct_proposal(
    proposal: &Proposal,
    context: ConstructionContext,
    contributions: Vec<OwnedContribution>,
    disclosures: &[DisclosureAcknowledgement],
) -> Result<ConstructedProposal, String> {
    wholepact_core::validate_claimed_accounting(proposal.manifest())
        .map_err(|_| "Accepted manifest accounting is invalid")?;
    construct_validated_manifest(
        proposal.manifest(),
        proposal.manifest_digest(),
        ConstructionPurpose::Ordinary,
        context,
        contributions,
        disclosures,
    )
}

/// Local cryptographic construction only. The destination FVK is caller-owned
/// material: matching its receiver does not authenticate the destination signer
/// or prove user control. The result cannot enter ordinary candidate workflows.
pub fn construct_residual_transfer_unverified(
    proposal: &wholepact_core::retirement::transfer::ResidualTransferProposal,
    destination_fvk: &FullViewingKey,
    context: ConstructionContext,
    contributions: Vec<OwnedContribution>,
    disclosures: &[DisclosureAcknowledgement],
) -> Result<UnverifiedResidualConstruction, String> {
    proposal
        .revalidate()
        .map_err(|_| "Residual plan binding is invalid")?;
    check(
        proposal.reviewed_plan().plan().destination().pool
            == wholepact_core::retirement::ShieldedReceiverPool::Ironwood,
        "Residual constructor only qualifies Ironwood receiver decoding",
    )?;
    let destination =
        decode_testnet_receiver(&proposal.reviewed_plan().plan().destination().address)?;
    check(
        destination_fvk.scope_for_address(&destination).is_some(),
        "Residual receiver does not belong to supplied destination viewing material",
    )?;
    check(
        contributions.len() == 1 && contributions[0].fvk.to_bytes() != destination_fvk.to_bytes(),
        "Residual destination must differ from the source viewing authority, including aliases",
    )?;
    let construction = construct_validated_manifest(
        proposal.manifest(),
        proposal.manifest_digest(),
        ConstructionPurpose::Residual(proposal),
        context,
        contributions,
        disclosures,
    )?;
    Ok(UnverifiedResidualConstruction {
        construction,
        plan_digest: proposal.reviewed_plan().plan().digest().into(),
    })
}

/// Private fields and no serialization/conversion to ConstructedProposal prevent
/// this unauthenticated planning result from masquerading as a normal candidate.
/// Its PCZT is private witness material and requires separate export consent.
pub struct UnverifiedResidualConstruction {
    construction: ConstructedProposal,
    plan_digest: String,
}
impl UnverifiedResidualConstruction {
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }
    pub fn private_unverified_pczt_bytes(&self) -> &[u8] {
        &self.construction.pczt_bytes
    }
    /// Private local review inputs, not a signer identity or authorization token.
    /// Ordinary review/proving paths reject its single-owner policy.
    pub fn private_unverified_review_policy(&self) -> &ReviewPolicy {
        &self.construction.review_policy
    }
    pub fn local_review(&self) -> &CryptographicReview {
        &self.construction.economic_review
    }
    pub fn destination_identity_authenticated(&self) -> bool {
        false
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
}

enum ConstructionPurpose<'a> {
    Ordinary,
    Residual(&'a wholepact_core::retirement::transfer::ResidualTransferProposal),
}

fn construct_validated_manifest(
    m: &wholepact_core::ProposalManifest,
    accepted_manifest_digest: &str,
    purpose: ConstructionPurpose<'_>,
    context: ConstructionContext,
    contributions: Vec<OwnedContribution>,
    disclosures: &[DisclosureAcknowledgement],
) -> Result<ConstructedProposal, String> {
    check(
        m.agreement.network_profile_id == PROFILE_ID,
        "Unsupported construction network profile",
    )?;
    check(
        m.agreement.extensions.is_empty(),
        "Construction does not qualify manifest extensions or conditional matching",
    )?;
    check(
        m.participants.iter().all(|p| p.charges.is_empty()),
        "Construction does not qualify service charges",
    )?;
    check(
        m.inputs.len() <= 64 && m.outputs.len() <= 64,
        "Construction supports at most 64 real inputs/outputs",
    )?;
    check(
        contributions.len() == m.participants.len(),
        "Exactly one contribution package is required per participant",
    )?;
    check(
        matches!(
            m.agreement.privacy_profile.mode,
            PrivacyMode::DeclaredOperator
        ) && m.agreement.privacy_profile.dedicated_accounts_required,
        "Broad-witness construction requires declared operator and dedicated accounts",
    )?;
    let operator = m
        .agreement
        .privacy_profile
        .proving_operator
        .as_deref()
        .ok_or("Declared construction/proving operator missing")?;
    let manifest_digest: [u8; 32] = hex::decode(accepted_manifest_digest)
        .map_err(|_| "Manifest digest encoding")?
        .try_into()
        .map_err(|_| "Manifest digest length")?;
    check(
        disclosures.len() == contributions.len(),
        "Every account must have a disclosure declaration",
    )?;
    let expected_reviewers: BTreeSet<_> = m
        .participants
        .iter()
        .map(|p| p.account_id.as_str())
        .collect();
    let mut disclosed = BTreeSet::new();
    for consent in disclosures {
        let reviewers: BTreeSet<_> = consent
            .reviewer_account_ids
            .iter()
            .map(String::as_str)
            .collect();
        check(
            reviewers == expected_reviewers
                && reviewers.len() == consent.reviewer_account_ids.len(),
            "Broad-review disclosure requires the exact complete participant reviewer roster",
        )?;
        check(
            consent.manifest_digest == manifest_digest
                && consent.operator == operator
                && bounded_text(&consent.purpose, 512)
                && bounded_text(&consent.retention_policy, 1024)
                && disclosed.insert(consent.account_id.as_str()),
            "Disclosure declaration is missing, duplicated or differs from accepted scope",
        )?;
        match consent.scope {
            DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs => {}
        }
    }
    check(
        context.anchor_height < context.target_height && context.anchor_block_hash != [0; 32],
        "Invalid anchor context",
    )?;
    check(
        m.expiry_height >= context.target_height && m.expiry_height < 500_000_000,
        "Expiry must cover target height and be a block-height expiry",
    )?;
    for height in [context.target_height, m.expiry_height] {
        check(
            BranchId::for_height(&Network::TestNetwork, BlockHeight::from_u32(height))
                == BranchId::Nu7,
            "Target and expiry must remain within the qualified testnet NU7 branch",
        )?;
    }
    let anchor = Option::<Anchor>::from(Anchor::from_bytes(context.anchor))
        .ok_or("Invalid Ironwood anchor")?;
    check(
        contributions.iter().map(|c| c.notes.len()).sum::<usize>() <= 64,
        "Total selected note count exceeds 64",
    )?;
    let mut by_account = BTreeMap::new();
    let mut all_notes = BTreeMap::new();
    let mut fvk_set = BTreeSet::new();
    let mut nullifiers = BTreeSet::new();
    let mut participant_policies = Vec::new();
    for contribution in contributions {
        check(
            disclosed.contains(contribution.account_id.as_str()),
            "Contribution lacks an exact disclosure declaration",
        )?;
        check(
            !contribution.notes.is_empty() && contribution.notes.len() <= 64,
            "Contribution note count outside 1..=64",
        )?;
        check(
            contribution
                .fvk
                .scope_for_address(&contribution.change_address)
                == Some(Scope::Internal),
            "Change address is not internal-scope account property",
        )?;
        check(
            fvk_set.insert(contribution.fvk.to_bytes()),
            "Same FVK cannot occupy multiple participant accounts",
        )?;
        let account = contribution.account_id.clone();
        for spend in &contribution.notes {
            check(
                spend.note.version() == NoteVersion::V3 && spend.note.value().inner() > 0,
                "Every selected note must be value-bearing Ironwood V3",
            )?;
            check(
                contribution
                    .fvk
                    .scope_for_address(&spend.note.recipient())
                    .is_some(),
                "Selected note is not owned by declared FVK",
            )?;
            check(
                spend
                    .witness
                    .root(spend.note.commitment().into())
                    .to_bytes()
                    == context.anchor,
                "Selected note witness differs from common anchor",
            )?;
            check(
                nullifiers.insert(spend.note.nullifier(&contribution.fvk).to_bytes()),
                "Duplicate real note/nullifier",
            )?;
            check(
                all_notes
                    .insert(spend.input_id.clone(), account.clone())
                    .is_none(),
                "Duplicate selected input ID",
            )?;
        }
        check(
            by_account.insert(account, contribution).is_none(),
            "Duplicate account contribution",
        )?;
    }
    check(
        all_notes.len() == m.inputs.len(),
        "Selected notes do not exactly cover accepted inputs",
    )?;
    for p in &m.participants {
        let source = by_account
            .get(&p.account_id)
            .ok_or("Accepted participant contribution missing")?;
        participant_policies.push(ParticipantPolicy {
            account_id: p.account_id.clone(),
            fvk: source.fvk.clone(),
            contribution_zatoshis: p.contribution.as_zatoshis(),
            fee_share_zatoshis: p.fee_share.as_zatoshis(),
            maximum_net_debit_zatoshis: p.maximum_net_debit.as_zatoshis(),
        });
    }
    let mut builder = Builder::new(
        Network::TestNetwork,
        context.target_height.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    )
    .with_expiry_height(m.expiry_height.into());
    let mut input_specs = Vec::new();
    for input in &m.inputs {
        let contribution = by_account
            .get(&input.account_id)
            .ok_or("Input account package missing")?;
        let spend = contribution
            .notes
            .iter()
            .find(|s| s.input_id == input.input_id)
            .ok_or("Accepted input does not identify a selected note")?;
        check(
            spend.note.value().inner() == input.amount.as_zatoshis(),
            "Actual selected input amount differs from accepted manifest",
        )?;
        let participant_index = m
            .participants
            .iter()
            .position(|p| p.account_id == input.account_id)
            .ok_or("Input participant missing")?;
        input_specs.push((
            participant_index,
            spend.note.nullifier(&contribution.fvk).to_bytes(),
            spend.note.value().inner(),
        ));
        builder
            .add_ironwood_spend::<zip317::FeeRule>(
                contribution.fvk.clone(),
                spend.note,
                spend.witness.clone(),
            )
            .map_err(|_| "Upstream rejected a selected Ironwood input")?;
    }
    let mut output_specs = Vec::new();
    for output in &m.outputs {
        let receiver = decode_testnet_receiver(&output.address)?;
        let (purpose, memo, ovk) = match &output.allocation {
            OutputAllocation::Recipient { recipient_id } => {
                let recipient = m
                    .agreement
                    .recipients
                    .iter()
                    .find(|r| &r.recipient_id == recipient_id)
                    .ok_or("Accepted recipient missing")?;
                let memo = match &recipient.memo {
                    Some(m) => {
                        MemoBytes::from_bytes(m.as_bytes()).map_err(|_| "Invalid recipient memo")?
                    }
                    None => MemoBytes::empty(),
                };
                // No participant outgoing key is arbitrarily assigned ownership of
                // a shared payment. Recipient receivability is independently checked.
                (OutputPurpose::Recipient, memo, None)
            }
            OutputAllocation::Return { account_id, .. } => {
                let source = by_account.get(account_id).ok_or("Return account missing")?;
                check(
                    receiver == source.change_address
                        && source.fvk.scope_for_address(&receiver) == Some(Scope::Internal),
                    "Accepted return receiver differs from account internal change",
                )?;
                let participant_index = m
                    .participants
                    .iter()
                    .position(|p| &p.account_id == account_id)
                    .ok_or("Return participant missing")?;
                (
                    OutputPurpose::Return { participant_index },
                    MemoBytes::empty(),
                    Some(source.fvk.to_ovk(Scope::Internal)),
                )
            }
            OutputAllocation::Charge { .. } => return Err("Unqualified service charge".into()),
        };
        output_specs.push((
            receiver,
            output.amount.as_zatoshis(),
            memo.clone().into_bytes(),
            purpose,
        ));
        builder
            .add_ironwood_output::<zip317::FeeRule>(
                ovk,
                receiver,
                Zatoshis::from_u64(output.amount.as_zatoshis())
                    .map_err(|_| "Output amount range")?,
                memo,
            )
            .map_err(|_| "Upstream rejected an Ironwood output")?;
    }
    let fee_rule = zip317::FeeRule::standard();
    check(
        u64::from(
            builder
                .get_fee(&fee_rule)
                .map_err(|_| "Unable to calculate exact ZIP317 fee")?,
        ) == m.transaction_fee.as_zatoshis(),
        "Accepted fee differs from ZIP317 fee for actual padded transaction shape; revise terms explicitly",
    )?;
    let PcztResult {
        pczt_parts,
        ironwood_meta,
        ..
    } = builder
        .build_for_pczt(UnwrapErr(SysRng), &fee_rule)
        .map_err(|_| "Upstream PCZT construction failed")?;
    let pczt =
        IoFinalizer::new(Creator::build_from_parts(pczt_parts).ok_or("Unsupported PCZT parts")?)
            .finalize_io(UnwrapErr(SysRng))
            .map_err(|_| "Upstream IO finalization failed")?;
    let pczt_bytes = pczt::v2::Pczt::try_from(pczt)
        .map_err(|_| "PCZT v2 serialization unsupported")?
        .serialize();
    let mut input_actions = Vec::new();
    let mut inputs = Vec::new();
    for (index, (participant_index, nullifier, value_zatoshis)) in
        input_specs.into_iter().enumerate()
    {
        let action_index = ironwood_meta
            .spend_action_index(index)
            .ok_or("Missing randomized input action mapping")?;
        inputs.push(InputPolicy {
            action_index,
            participant_index,
            nullifier,
            value_zatoshis,
        });
        input_actions.push(InputActionMapping {
            input_id: m.inputs[index].input_id.clone(),
            account_id: m.inputs[index].account_id.clone(),
            action_index,
        });
    }
    let mut output_actions = Vec::new();
    let mut outputs = Vec::new();
    for (index, (receiver, value_zatoshis, memo, purpose)) in output_specs.into_iter().enumerate() {
        let action_index = ironwood_meta
            .output_action_index(index)
            .ok_or("Missing randomized output action mapping")?;
        outputs.push(OutputPolicy {
            action_index,
            receiver,
            value_zatoshis,
            memo,
            purpose,
        });
        output_actions.push(OutputActionMapping {
            output_id: m.outputs[index].output_id.clone(),
            action_index,
        });
    }
    let review_policy = ReviewPolicy {
        manifest_digest,
        participants: participant_policies,
        inputs,
        outputs,
        exact_fee_zatoshis: m.transaction_fee.as_zatoshis(),
        expiry_height: m.expiry_height,
        anchor: context.anchor,
    };
    let economic_review = match purpose {
        ConstructionPurpose::Ordinary => verify_review(&pczt_bytes, &review_policy)?,
        ConstructionPurpose::Residual(proposal) => {
            crate::review::verify_residual_review(&pczt_bytes, &review_policy, proposal)?
        }
    };
    Ok(ConstructedProposal {
        pczt_bytes,
        review_policy,
        economic_review,
        input_actions,
        output_actions,
        context,
        chain_validated: false,
        disclosure_consents_authenticated: false,
        distribution_allowed: false,
        authorization_allowed: false,
    })
}
