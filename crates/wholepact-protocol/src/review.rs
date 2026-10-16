//! Read-only verification of exact Ironwood economic terms.
//!
//! FVK/account associations and accepted instructions must come from trusted local
//! state, not an imported proposal. This verifies their relationship to transaction
//! commitments; it cannot authenticate people, chain state, or disclosure consent.
//! No function in this module signs or authorizes a payment.

use orchard::{
    Address, Note,
    keys::FullViewingKey,
    note::{NoteVersion, Rho},
    note_encryption::IronwoodDomain,
};
use pczt::{
    Pczt,
    roles::{
        signer::Signer,
        verifier::{OrchardError, Verifier},
    },
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use zcash_note_encryption::{Domain, try_output_recovery_with_pkd_esk};

const MAX_MONEY: u64 = 2_100_000_000_000_000;

#[derive(Clone)]
pub struct ParticipantPolicy {
    pub account_id: String,
    /// Trusted, explicitly consented account viewing authority; never log this.
    pub fvk: FullViewingKey,
    pub contribution_zatoshis: u64,
    pub fee_share_zatoshis: u64,
    pub maximum_net_debit_zatoshis: u64,
}

#[derive(Clone)]
pub struct InputPolicy {
    pub action_index: usize,
    pub participant_index: usize,
    pub nullifier: [u8; 32],
    pub value_zatoshis: u64,
}

#[derive(Clone, Copy)]
pub enum OutputPurpose {
    Recipient,
    Return { participant_index: usize },
}

#[derive(Clone)]
pub struct OutputPolicy {
    pub action_index: usize,
    pub receiver: Address,
    pub value_zatoshis: u64,
    pub memo: [u8; 512],
    pub purpose: OutputPurpose,
}

#[derive(Clone)]
pub struct ReviewPolicy {
    /// Digest of a separately validated, accepted Wholepact manifest.
    pub manifest_digest: [u8; 32],
    pub participants: Vec<ParticipantPolicy>,
    pub inputs: Vec<InputPolicy>,
    pub outputs: Vec<OutputPolicy>,
    pub exact_fee_zatoshis: u64,
    pub expiry_height: u32,
    /// Explicitly reviewed anchor. This function does not prove it is on-chain.
    pub anchor: [u8; 32],
}

/// A successful economic review, constructible only by actual verification.
/// Serialized reports are evidence summaries, never reusable authorization tokens.
#[derive(Debug, Clone, Serialize)]
pub struct CryptographicReview {
    profile: &'static str,
    manifest_digest: String,
    shielded_sighash: String,
    review_binding: String,
    reviewed_anchor: String,
    actual_fee_zatoshis: u64,
    participant_net_debits_zatoshis: Vec<u64>,
    economic_terms_verified: bool,
    account_associations_authenticated: bool,
    chain_validated: bool,
    authorization_allowed: bool,
}
impl CryptographicReview {
    pub fn review_binding(&self) -> &str {
        &self.review_binding
    }
    pub fn shielded_sighash(&self) -> &str {
        &self.shielded_sighash
    }
    pub fn fee_zatoshis(&self) -> u64 {
        self.actual_fee_zatoshis
    }
    pub fn net_debits_zatoshis(&self) -> &[u64] {
        &self.participant_net_debits_zatoshis
    }
}

/// Decode a user-supplied testnet unified address and select its Orchard-protocol
/// receiver for Ironwood. Reject unsupported revisions/receiver metadata rather
/// than silently ignore conditions. The receiver's wallet compatibility is separate.
pub fn decode_testnet_receiver(encoded: &str) -> Result<Address, String> {
    use zcash_address::unified::{self, Container, Encoding, Receiver};
    if encoded.len() > 1024 {
        return Err("Receiving instruction exceeds address bound".into());
    }
    let (network, revision, address) =
        unified::Address::decode(encoded).map_err(|_| "Invalid unified address")?;
    if network != zcash_protocol::consensus::NetworkType::Test {
        return Err("Mainnet is disabled: testnet address required".into());
    }
    // Revision 2 metadata has new wallet semantics that this adapter does not qualify.
    if revision != zcash_protocol::address::Revision::R0 {
        return Err("Unified-address revision is not qualified".into());
    }
    if !address.metadata_items().is_empty() {
        return Err("Address metadata is not qualified".into());
    }
    let mut found = None;
    for item in address.items() {
        match item {
            Receiver::Orchard(bytes) => {
                if found.is_some() {
                    return Err("Duplicate Orchard-protocol receiver".into());
                }
                found = Option::from(Address::from_raw_address_bytes(&bytes));
            }
            Receiver::Unknown { .. } => return Err("Unknown receiver type is not qualified".into()),
            _ => {} // Presence does not grant use; only the Orchard-protocol receiver is selected.
        }
    }
    found.ok_or("No valid Orchard-protocol receiver for Ironwood".into())
}

/// Encode a qualified revision-0 testnet receiver for display or manifest input.
/// Encoding does not establish recipient identity or wallet scanning compatibility.
pub fn encode_testnet_receiver(receiver: &Address) -> String {
    use zcash_address::unified::{self, Encoding, Receiver, Uitem};
    unified::Address::try_from_items(
        zcash_protocol::address::Revision::R0,
        vec![Uitem::Data(Receiver::Orchard(
            receiver.to_raw_address_bytes(),
        ))],
    )
    .expect("One valid Orchard receiver is a valid unified address")
    .encode(&zcash_protocol::consensus::NetworkType::Test)
}

fn check(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn amount(n: u64) -> Result<u64, String> {
    check(n <= MAX_MONEY, "Monetary value exceeds MAX_MONEY")?;
    Ok(n)
}
fn plus(a: u64, b: u64) -> Result<u64, String> {
    amount(a.checked_add(b).ok_or("Amount overflow")?)
}
fn field(hash: &mut Sha256, data: &[u8]) {
    hash.update((data.len() as u64).to_le_bytes());
    hash.update(data);
}

pub(crate) fn policy_digest(policy: &ReviewPolicy) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"wholepact:review-policy:ironwood-testnet-nu7:v1\0");
    h.update(policy.manifest_digest);
    h.update((policy.participants.len() as u64).to_le_bytes());
    for p in &policy.participants {
        field(&mut h, p.account_id.as_bytes());
        h.update(p.fvk.to_bytes());
        for n in [
            p.contribution_zatoshis,
            p.fee_share_zatoshis,
            p.maximum_net_debit_zatoshis,
        ] {
            h.update(n.to_le_bytes());
        }
    }
    h.update((policy.inputs.len() as u64).to_le_bytes());
    for i in &policy.inputs {
        h.update((i.action_index as u64).to_le_bytes());
        h.update((i.participant_index as u64).to_le_bytes());
        h.update(i.nullifier);
        h.update(i.value_zatoshis.to_le_bytes());
    }
    h.update((policy.outputs.len() as u64).to_le_bytes());
    for o in &policy.outputs {
        h.update((o.action_index as u64).to_le_bytes());
        h.update(o.receiver.to_raw_address_bytes());
        h.update(o.value_zatoshis.to_le_bytes());
        h.update(o.memo);
        match o.purpose {
            OutputPurpose::Recipient => h.update([0]),
            OutputPurpose::Return { participant_index } => {
                h.update([1]);
                h.update((participant_index as u64).to_le_bytes());
            }
        }
    }
    h.update(policy.exact_fee_zatoshis.to_le_bytes());
    h.update(policy.expiry_height.to_le_bytes());
    h.update(policy.anchor);
    h.finalize().into()
}

/// Fully check the accepted economic terms against the actual PCZT commitments.
/// Requires unredacted witnesses/values/keys needed by this strict disclosure profile.
/// Supports fixed contributions; sponsor identity/matching, service-charge and other
/// conditional assurance must be separately verified, never inferred from success.
pub fn verify_review(bytes: &[u8], policy: &ReviewPolicy) -> Result<CryptographicReview, String> {
    verify_review_for_participants(bytes, policy, 2..=32)
}

/// Only the typed residual construction path can request single-owner review.
/// This does not authenticate destination identity, authorize or prove a spend.
#[cfg(feature = "construction")]
pub(crate) fn verify_residual_review(
    bytes: &[u8],
    policy: &ReviewPolicy,
    proposal: &wholepact_core::retirement::transfer::ResidualTransferProposal,
) -> Result<CryptographicReview, String> {
    proposal
        .revalidate()
        .map_err(|_| "Invalid residual plan binding")?;
    check(
        hex::encode(policy.manifest_digest) == proposal.manifest_digest(),
        "Residual review requires the exact typed purpose commitment",
    )?;
    verify_review_for_participants(bytes, policy, 1..=1)
}

fn verify_review_for_participants(
    bytes: &[u8],
    policy: &ReviewPolicy,
    participant_count: std::ops::RangeInclusive<usize>,
) -> Result<CryptographicReview, String> {
    crate::inspect_candidate(bytes)?;
    check(
        participant_count.contains(&policy.participants.len()),
        "Participant count differs from the typed review purpose",
    )?;
    check(
        !policy.inputs.is_empty()
            && policy.inputs.len() <= 64
            && !policy.outputs.is_empty()
            && policy.outputs.len() <= 64,
        "Policy allocation limits exceeded",
    )?;
    amount(policy.exact_fee_zatoshis)?;
    let mut accounts = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut fees = 0;
    let mut contributions = 0;
    for p in &policy.participants {
        check(
            !p.account_id.is_empty() && p.account_id.len() <= 128 && accounts.insert(&p.account_id),
            "Duplicate or invalid account identity",
        )?;
        check(
            keys.insert(p.fvk.to_bytes()),
            "An account cannot occupy multiple contribution allocations",
        )?;
        amount(p.maximum_net_debit_zatoshis)?;
        fees = plus(fees, p.fee_share_zatoshis)?;
        contributions = plus(contributions, p.contribution_zatoshis)?;
        check(
            plus(p.contribution_zatoshis, p.fee_share_zatoshis)? <= p.maximum_net_debit_zatoshis,
            "Approved debit exceeds cap",
        )?;
    }
    check(
        fees == policy.exact_fee_zatoshis,
        "Approved fee shares do not sum to fee",
    )?;
    let p = Pczt::parse(bytes).map_err(|e| format!("PCZT parse: {e}"))?;
    check(
        *p.global().version_group_id() == 0xd884b698,
        "Wrong transaction version-group ID",
    )?;
    check(
        *p.global().tx_modifiable() == 0,
        "Transaction effects are not frozen",
    )?;
    check(
        p.global().fallback_lock_time().unwrap_or(0) == 0,
        "Nonzero lock time is not qualified",
    )?;
    check(
        *p.global().expiry_height() == policy.expiry_height && policy.expiry_height < 500_000_000,
        "Expiry differs from accepted policy",
    )?;
    check(
        *p.ironwood().anchor() == Some(policy.anchor),
        "Anchor differs from the explicit review context",
    )?;
    check(*p.ironwood().flags() == 7, "Unexpected Ironwood flags")?;
    let mut spent = vec![0_u64; policy.participants.len()];
    let mut returned = vec![0_u64; policy.participants.len()];
    let mut input_total = 0;
    let mut output_total = 0;
    let mut recipients_total = 0;
    let mut input_indices = BTreeSet::new();
    let mut output_indices = BTreeSet::new();
    let mut nullifiers = BTreeSet::new();
    for input in &policy.inputs {
        check(
            input.action_index < p.ironwood().actions().len()
                && input.participant_index < spent.len()
                && input.value_zatoshis > 0
                && input_indices.insert(input.action_index),
            "Invalid or duplicate real input allocation",
        )?;
    }
    for output in &policy.outputs {
        check(
            output.action_index < p.ironwood().actions().len()
                && output.value_zatoshis > 0
                && output_indices.insert(output.action_index),
            "Invalid or duplicate real output allocation",
        )?;
    }
    Verifier::new(p.clone())
        .with_ironwood::<String, _>(|bundle| {
            let custom = OrchardError::Custom;
            bundle.verify_cross_address_restriction()?;
            for (index, action) in bundle.actions().iter().enumerate() {
                action.verify_cv_net()?;
                action.output().verify_note_commitment(action.spend())?;
                let in_value = action
                    .spend()
                    .value()
                    .ok_or_else(|| custom("Input value redacted".into()))?
                    .inner();
                let out_value = action
                    .output()
                    .value()
                    .ok_or_else(|| custom("Output value redacted".into()))?
                    .inner();
                input_total = plus(input_total, in_value).map_err(custom)?;
                output_total = plus(output_total, out_value).map_err(custom)?;
                check(
                    nullifiers.insert(action.spend().nullifier().to_bytes()),
                    "Duplicate nullifier",
                )
                .map_err(custom)?;
                if let Some(input) = policy.inputs.iter().find(|i| i.action_index == index) {
                    check(
                        input.value_zatoshis == in_value
                            && input.nullifier == action.spend().nullifier().to_bytes(),
                        "Input differs from approved wallet selection",
                    )
                    .map_err(custom)?;
                    let owner = &policy.participants[input.participant_index];
                    action.spend().verify_nullifier(Some(&owner.fvk))?;
                    action.spend().verify_rk(Some(&owner.fvk))?;
                    spent[input.participant_index] =
                        plus(spent[input.participant_index], in_value).map_err(custom)?;
                    let recipient = action
                        .spend()
                        .recipient()
                        .ok_or_else(|| custom("Spent recipient missing".into()))?;
                    let note = Option::<Note>::from(Note::from_parts(
                        recipient,
                        action.spend().value().unwrap(),
                        action
                            .spend()
                            .rho()
                            .ok_or_else(|| custom("Input rho missing".into()))?,
                        action
                            .spend()
                            .rseed()
                            .ok_or_else(|| custom("Input rseed missing".into()))?,
                        NoteVersion::V3,
                    ))
                    .ok_or_else(|| custom("Invalid input note".into()))?;
                    let witness = action
                        .spend()
                        .witness()
                        .as_ref()
                        .ok_or_else(|| custom("Spend witness missing".into()))?;
                    check(
                        witness.root(note.commitment().into()).to_bytes() == policy.anchor,
                        "Input witness does not root to reviewed anchor",
                    )
                    .map_err(custom)?;
                } else {
                    check(in_value == 0, "Unassigned value-bearing input").map_err(custom)?;
                    action.spend().verify_nullifier(None)?;
                    action.spend().verify_rk(None)?;
                }
                if let Some(output) = policy.outputs.iter().find(|o| o.action_index == index) {
                    check(
                        out_value == output.value_zatoshis
                            && *action.output().recipient() == Some(output.receiver),
                        "Recipient or amount differs from approval",
                    )
                    .map_err(custom)?;
                    let note = Option::<Note>::from(Note::from_parts(
                        output.receiver,
                        action.output().value().unwrap(),
                        Option::<Rho>::from(Rho::from_bytes(
                            &action.spend().nullifier().to_bytes(),
                        ))
                        .ok_or_else(|| custom("Invalid output rho".into()))?,
                        action
                            .output()
                            .rseed()
                            .ok_or_else(|| custom("Output randomness missing".into()))?,
                        NoteVersion::V3,
                    ))
                    .ok_or_else(|| custom("Invalid output note".into()))?;
                    let domain = IronwoodDomain::for_pczt_action(action);
                    let esk = IronwoodDomain::derive_esk(&note)
                        .ok_or_else(|| custom("Output encryption seed unavailable".into()))?;
                    let recovered = try_output_recovery_with_pkd_esk(
                        &domain,
                        IronwoodDomain::get_pk_d(&note),
                        esk,
                        action,
                    )
                    .ok_or_else(|| {
                        custom("Output ciphertext is not receivable as committed".into())
                    })?;
                    check(
                        recovered.0.value().inner() == output.value_zatoshis
                            && recovered.1 == output.receiver
                            && recovered.2 == output.memo,
                        "Actual encrypted payment or memo differs from approval",
                    )
                    .map_err(custom)?;
                    match output.purpose {
                        OutputPurpose::Recipient => {
                            recipients_total = plus(recipients_total, out_value).map_err(custom)?
                        }
                        OutputPurpose::Return { participant_index } => {
                            let owner = policy
                                .participants
                                .get(participant_index)
                                .ok_or_else(|| custom("Unknown return owner".into()))?;
                            check(
                                owner.fvk.scope_for_address(&output.receiver).is_some(),
                                "Return output is not owned by designated account",
                            )
                            .map_err(custom)?;
                            returned[participant_index] =
                                plus(returned[participant_index], out_value).map_err(custom)?;
                        }
                    }
                } else {
                    check(out_value == 0, "Unassigned value-bearing output").map_err(custom)?;
                }
            }
            Ok(())
        })
        .map_err(|e| format!("Economic verification failed: {e:?}"))?;
    let fee = input_total
        .checked_sub(output_total)
        .ok_or("Negative transaction fee")?;
    check(
        fee == policy.exact_fee_zatoshis,
        "Actual transaction fee differs from approval",
    )?;
    check(
        *p.ironwood().value_sum() == (fee, false),
        "Bundle value balance differs from actual fee",
    )?;
    check(
        recipients_total == contributions,
        "Contributions do not equal actual recipient funding",
    )?;
    let mut net = Vec::new();
    for (i, owner) in policy.participants.iter().enumerate() {
        let debit = spent[i]
            .checked_sub(returned[i])
            .ok_or("Return exceeds participant inputs")?;
        check(
            debit == plus(owner.contribution_zatoshis, owner.fee_share_zatoshis)?
                && debit <= owner.maximum_net_debit_zatoshis,
            "Actual participant debit differs from approved debit",
        )?;
        net.push(debit);
    }
    let sighash = Signer::new(p)
        .map_err(|e| format!("Effects digest: {e:?}"))?
        .shielded_sighash();
    let mut h = Sha256::new();
    h.update(b"wholepact:verified-review:ironwood-testnet-nu7:v1\0");
    h.update(policy_digest(policy));
    h.update(sighash);
    h.update(policy.anchor);
    let binding = h.finalize();
    Ok(CryptographicReview {
        profile: "ironwood-testnet-nu7-economic-review-v1",
        manifest_digest: hex::encode(policy.manifest_digest),
        shielded_sighash: hex::encode(sighash),
        review_binding: hex::encode(binding),
        reviewed_anchor: hex::encode(policy.anchor),
        actual_fee_zatoshis: fee,
        participant_net_debits_zatoshis: net,
        economic_terms_verified: true,
        account_associations_authenticated: false,
        chain_validated: false,
        authorization_allowed: false,
    })
}
