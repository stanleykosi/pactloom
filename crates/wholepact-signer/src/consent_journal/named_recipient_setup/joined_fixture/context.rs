use super::*;
use wholepact_authority::InputReservation;
use wholepact_core::*;
use wholepact_protocol::{
    construction::{InputActionMapping, OutputActionMapping, PROFILE_ID},
    review::{OutputPurpose, ReviewPolicy, encode_testnet_receiver, verify_review},
};
fn amount(v: u64) -> Amount {
    Amount::from_zatoshis(v).unwrap()
}
pub(super) fn proposal(policy: &mut ReviewPolicy) -> Proposal {
    let participant_id = |index: usize| format!("fixture-participant-{index}");
    let participants = policy
        .participants
        .iter()
        .enumerate()
        .map(|(index, p)| ParticipantAllocation {
            participant_id: participant_id(index),
            account_id: p.account_id.clone(),
            contribution: amount(p.contribution_zatoshis),
            fee_share: amount(p.fee_share_zatoshis),
            fee_cap: amount(p.fee_share_zatoshis),
            maximum_net_debit: amount(p.maximum_net_debit_zatoshis),
            charges: vec![],
        })
        .collect();
    let inputs = policy
        .inputs
        .iter()
        .enumerate()
        .map(|(index, i)| ClaimedInput {
            input_id: format!("fixture-input-{index}"),
            participant_id: participant_id(i.participant_index),
            account_id: policy.participants[i.participant_index].account_id.clone(),
            amount: amount(i.value_zatoshis),
            ownership_evidence_ref: None,
        })
        .collect();
    let outputs = policy
        .outputs
        .iter()
        .enumerate()
        .map(|(index, o)| ClaimedOutput {
            output_id: format!("fixture-output-{index}"),
            address: encode_testnet_receiver(&o.receiver),
            amount: amount(o.value_zatoshis),
            allocation: match o.purpose {
                OutputPurpose::Recipient => OutputAllocation::Recipient {
                    recipient_id: "fixture-recipient".into(),
                },
                OutputPurpose::Return { participant_index } => OutputAllocation::Return {
                    participant_id: participant_id(participant_index),
                    account_id: policy.participants[participant_index].account_id.clone(),
                    ownership_evidence_ref: None,
                },
            },
        })
        .collect();
    let recipient = policy
        .outputs
        .iter()
        .find(|o| matches!(o.purpose, OutputPurpose::Recipient))
        .unwrap();
    let agreement = AgreementDraft {
        schema_version: 1,
        agreement_id: "fixture-agreement".into(),
        obligation_id: "fixture-obligation".into(),
        revision: 1,
        purpose: "Private proved named-verifier kernel test".into(),
        organizer_identity: "fixture-organizer".into(),
        network_profile_id: PROFILE_ID.into(),
        recipients: vec![Recipient {
            recipient_id: "fixture-recipient".into(),
            address: encode_testnet_receiver(&recipient.receiver),
            amount: amount(recipient.value_zatoshis),
            memo: None,
            instruction_provenance: "closed synthetic fixture".into(),
        }],
        funding_policy: FundingPolicy::Exact {
            target: amount(300_000),
        },
        fee_policy: FeePolicy::ProRata,
        privacy_profile: PrivacyProfile {
            mode: PrivacyMode::DeclaredOperator,
            proving_operator: Some("fixture-operator".into()),
            dedicated_accounts_required: true,
        },
        coordination_deadline: None,
        confirmation_policy: ConfirmationPolicy::default(),
        extensions: vec![],
    };
    let proposal = Proposal::validate(ProposalInput {
        proposal_id: "fixture-proposal".into(),
        previous_proposal_id: None,
        manifest: ProposalManifest {
            agreement,
            participants,
            inputs,
            outputs,
            transaction_fee: amount(policy.exact_fee_zatoshis),
            expiry_height: policy.expiry_height,
        },
        artifact_digest: None,
        effects_commitment: None,
        created_at: "2026-10-16T00:00:00Z".into(),
    })
    .unwrap();
    policy.manifest_digest = hex::decode(proposal.manifest_digest())
        .unwrap()
        .try_into()
        .unwrap();
    proposal
}
pub(super) fn terms(
    bytes: &[u8],
    policy: &ReviewPolicy,
    proposal: &Proposal,
) -> (
    OfflineAuthorizationTerms,
    Vec<InputActionMapping>,
    Vec<OutputActionMapping>,
) {
    let input_actions: Vec<_> = policy
        .inputs
        .iter()
        .enumerate()
        .map(|(index, i)| InputActionMapping {
            input_id: format!("fixture-input-{index}"),
            account_id: policy.participants[i.participant_index].account_id.clone(),
            action_index: i.action_index,
        })
        .collect();
    let output_actions = policy
        .outputs
        .iter()
        .enumerate()
        .map(|(index, o)| OutputActionMapping {
            output_id: format!("fixture-output-{index}"),
            action_index: o.action_index,
        })
        .collect();
    let review = verify_review(bytes, policy).unwrap();
    let mut own_inputs: Vec<_> = policy
        .inputs
        .iter()
        .filter(|i| i.participant_index == 0)
        .map(|i| InputReservation {
            input_id: input_actions
                .iter()
                .find(|m| m.action_index == i.action_index)
                .unwrap()
                .input_id
                .clone(),
            nullifier: hex::encode(i.nullifier),
            value_zatoshis: i.value_zatoshis,
            action_index: i.action_index as u64,
        })
        .collect();
    own_inputs.sort_by_key(|i| i.action_index);
    // Shape-valid, deliberately synthetic context hashes: never asserted to be
    // authenticated enrollment, admission, snapshot provenance or transport keys.
    let synthetic_context_hash = hash_bytes(b"private fixture context only; no authority");
    let terms = OfflineAuthorizationTerms {
        account_id: policy.participants[0].account_id.clone(),
        network_profile_id: PROFILE_ID.into(),
        consensus_branch_id: 0x77190ad9,
        authorization_id: "fixture-authorization".into(),
        enrollment_ref: synthetic_context_hash.clone(),
        accepted_manifest_ref: synthetic_context_hash.clone(),
        agreement_id: proposal.manifest().agreement.agreement_id.clone(),
        obligation_id: proposal.manifest().agreement.obligation_id.clone(),
        proposal_id: proposal.input().proposal_id.clone(),
        proposal_revision: 1,
        proposal_digest: proposal.proposal_digest().into(),
        manifest_digest: proposal.manifest_digest().into(),
        effects_digest: review.shielded_sighash().into(),
        artifact_digest: hash_bytes(bytes),
        review_binding: review.review_binding().into(),
        review_package_digest: synthetic_context_hash.clone(),
        recipient_scope_digest: synthetic_context_hash.clone(),
        offline_signer_key_digest: synthetic_context_hash.clone(),
        return_recipient_key_digest: synthetic_context_hash.clone(),
        offline_policy_digest: synthetic_context_hash.clone(),
        snapshot: OfflineSnapshotCommitment {
            source_id: "fixture-fabricated-tree".into(),
            source_identity_digest: synthetic_context_hash.clone(),
            source_policy_digest: synthetic_context_hash.clone(),
            snapshot_digest: synthetic_context_hash.clone(),
            observed_at_ms: 1,
            tip_height: 11,
            tip_hash: synthetic_context_hash.clone(),
            anchor_height: 10,
            anchor_hash: synthetic_context_hash,
            anchor_root: hex::encode(policy.anchor),
        },
        inputs: own_inputs,
        maximum_debit_zatoshis: policy.participants[0].maximum_net_debit_zatoshis,
        fee_share_zatoshis: policy.participants[0].fee_share_zatoshis,
        transaction_fee_zatoshis: policy.exact_fee_zatoshis,
        transaction_expiry_height: policy.expiry_height,
        unknown_facts: OfflineUnknownFact::ALL.to_vec(),
        semantics: OfflineAuthoritySemantics::ExactEffectsPreReservedMayDrainAfterRevocation,
    };
    terms.validate().unwrap();
    (terms, input_actions, output_actions)
}
pub(super) fn own_policy(policy: &ReviewPolicy, owner: usize) -> OwnEffectsPolicy {
    let p = &policy.participants[owner];
    OwnEffectsPolicy {
        account_id: p.account_id.clone(),
        own_fvk: p.fvk.clone(),
        manifest_digest: policy.manifest_digest,
        anchor: policy.anchor,
        expiry_height: policy.expiry_height,
        maximum_selected_net_debit_zatoshis: p.maximum_net_debit_zatoshis,
        exact_selected_net_debit_zatoshis: p.contribution_zatoshis + p.fee_share_zatoshis,
        declared_fee_share_zatoshis: p.fee_share_zatoshis,
        exact_transaction_fee_zatoshis: policy.exact_fee_zatoshis,
        own_inputs: policy
            .inputs
            .iter()
            .filter(|i| i.participant_index == owner)
            .map(|i| OwnInputExpectation {
                action_index: i.action_index,
                nullifier: i.nullifier,
                value_zatoshis: i.value_zatoshis,
            })
            .collect(),
        outputs: policy
            .outputs
            .iter()
            .map(|o| OwnOutputExpectation {
                action_index: o.action_index,
                receiver: o.receiver,
                value_zatoshis: o.value_zatoshis,
                memo: o.memo,
                purpose: match o.purpose {
                    OutputPurpose::Recipient => OwnOutputPurpose::Recipient,
                    OutputPurpose::Return { participant_index } if participant_index == owner => {
                        OwnOutputPurpose::OwnReturn
                    }
                    OutputPurpose::Return { .. } => OwnOutputPurpose::PeerReturnUnverified,
                },
            })
            .collect(),
    }
}
