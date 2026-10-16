//! Private storage encoding only; never expose this as a wire policy or approval.
use super::{JobError, Result, MAX_POLICY_BYTES, MAX_PROVING_ACTIONS};
use orchard::{keys::FullViewingKey, Address};
use serde::{Deserialize, Serialize};
use wholepact_protocol::review::{
    InputPolicy, OutputPolicy, OutputPurpose, ParticipantPolicy, ReviewPolicy,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct StoredPolicy {
    version: u32,
    manifest: [u8; 32],
    participants: Vec<Participant>,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    fee: u64,
    expiry: u32,
    anchor: [u8; 32],
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Participant {
    account: String,
    fvk: Vec<u8>,
    contribution: u64,
    fee: u64,
    cap: u64,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Input {
    action: usize,
    participant: usize,
    nullifier: [u8; 32],
    value: u64,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Output {
    action: usize,
    receiver: Vec<u8>,
    value: u64,
    memo: Vec<u8>,
    return_to: Option<usize>,
}

pub(super) fn encode(p: &ReviewPolicy) -> Result<Zeroizing<Vec<u8>>> {
    if p.participants.is_empty()
        || p.participants.len() > MAX_PROVING_ACTIONS
        || p.inputs.len() > MAX_PROVING_ACTIONS
        || p.outputs.len() > MAX_PROVING_ACTIONS
    {
        return Err(JobError::InvalidRequest);
    }
    if p.participants
        .iter()
        .any(|p| !super::bounded(&p.account_id, 128))
    {
        return Err(JobError::InvalidRequest);
    }
    let s = StoredPolicy {
        version: 1,
        manifest: p.manifest_digest,
        fee: p.exact_fee_zatoshis,
        expiry: p.expiry_height,
        anchor: p.anchor,
        participants: p
            .participants
            .iter()
            .map(|p| Participant {
                account: p.account_id.clone(),
                fvk: p.fvk.to_bytes().to_vec(),
                contribution: p.contribution_zatoshis,
                fee: p.fee_share_zatoshis,
                cap: p.maximum_net_debit_zatoshis,
            })
            .collect(),
        inputs: p
            .inputs
            .iter()
            .map(|i| Input {
                action: i.action_index,
                participant: i.participant_index,
                nullifier: i.nullifier,
                value: i.value_zatoshis,
            })
            .collect(),
        outputs: p
            .outputs
            .iter()
            .map(|o| Output {
                action: o.action_index,
                receiver: o.receiver.to_raw_address_bytes().to_vec(),
                value: o.value_zatoshis,
                memo: o.memo.to_vec(),
                return_to: match o.purpose {
                    OutputPurpose::Recipient => None,
                    OutputPurpose::Return { participant_index } => Some(participant_index),
                },
            })
            .collect(),
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&s).map_err(|_| JobError::InvalidRequest)?);
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(JobError::InvalidRequest);
    }
    Ok(bytes)
}
pub(super) fn decode(bytes: &[u8]) -> Result<ReviewPolicy> {
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(JobError::VerificationFailed);
    }
    let p: StoredPolicy =
        serde_json::from_slice(bytes).map_err(|_| JobError::VerificationFailed)?;
    if p.version != 1
        || p.participants.is_empty()
        || p.participants.len() > MAX_PROVING_ACTIONS
        || p.inputs.len() > MAX_PROVING_ACTIONS
        || p.outputs.len() > MAX_PROVING_ACTIONS
    {
        return Err(JobError::VerificationFailed);
    }
    Ok(ReviewPolicy {
        manifest_digest: p.manifest,
        exact_fee_zatoshis: p.fee,
        expiry_height: p.expiry,
        anchor: p.anchor,
        participants: p
            .participants
            .iter()
            .map(|p| {
                Ok(ParticipantPolicy {
                    account_id: p.account.clone(),
                    fvk: FullViewingKey::from_bytes(
                        p.fvk
                            .as_slice()
                            .try_into()
                            .map_err(|_| JobError::VerificationFailed)?,
                    )
                    .ok_or(JobError::VerificationFailed)?,
                    contribution_zatoshis: p.contribution,
                    fee_share_zatoshis: p.fee,
                    maximum_net_debit_zatoshis: p.cap,
                })
            })
            .collect::<Result<_>>()?,
        inputs: p
            .inputs
            .iter()
            .map(|i| InputPolicy {
                action_index: i.action,
                participant_index: i.participant,
                nullifier: i.nullifier,
                value_zatoshis: i.value,
            })
            .collect(),
        outputs: p
            .outputs
            .iter()
            .map(|o| {
                Ok(OutputPolicy {
                    action_index: o.action,
                    receiver: Option::from(Address::from_raw_address_bytes(
                        o.receiver
                            .as_slice()
                            .try_into()
                            .map_err(|_| JobError::VerificationFailed)?,
                    ))
                    .ok_or(JobError::VerificationFailed)?,
                    value_zatoshis: o.value,
                    memo: o
                        .memo
                        .as_slice()
                        .try_into()
                        .map_err(|_| JobError::VerificationFailed)?,
                    purpose: match o.return_to {
                        None => OutputPurpose::Recipient,
                        Some(participant_index) => OutputPurpose::Return { participant_index },
                    },
                })
            })
            .collect::<Result<_>>()?,
    })
}
