//! Exact core-manifest/protocol/local-wallet reconciliation. Source construction
//! cannot authenticate another participant's real-world identity or chain inputs.
use crate::{Error, Result};
use orchard::keys::FullViewingKey;
use std::collections::BTreeSet;
use wholepact_core::{OutputAllocation, Proposal};
use wholepact_protocol::{
    construction::{ConstructionContext, InputActionMapping, OutputActionMapping},
    review::{decode_testnet_receiver, OutputPurpose, ReviewPolicy},
};
use zcash_protocol::memo::MemoBytes;

/// A validated manifest acknowledged on the signer's controlling terminal. Not JSON.
/// This does not authenticate a human: application-owned PTYs remain a launch blocker.
pub struct AcceptedManifest {
    pub(crate) proposal: Proposal,
}
impl AcceptedManifest {
    pub fn user_origin_authenticated(&self) -> bool {
        false
    }
    pub fn digest(&self) -> &str {
        self.proposal.manifest_digest()
    }
}
/// Created from a maintained local wallet's private-construction selection type,
/// never accepted from app-supplied FVK labels or a deserializable success flag.
pub struct LocalSelection {
    account_id: String,
    fvk: FullViewingKey,
    inputs: Vec<SelectedInput>,
    pub(crate) context: SelectionContext,
    pub(crate) key_use_policy: Option<wholepact_wallet::WalletKeyUsePolicy>,
}
pub(crate) struct SelectionContext {
    pub(crate) tip_height: u32,
    pub(crate) tip_hash: [u8; 32],
    pub(crate) anchor_height: u32,
    pub(crate) anchor_hash: [u8; 32],
    pub(crate) anchor_root: [u8; 32],
}
struct SelectedInput {
    input_id: String,
    nullifier: [u8; 32],
    value: u64,
}
impl LocalSelection {
    /// Bind a reviewed policy only to an opaque live protected-wallet ticket.
    /// Ordinary wallet snapshots cannot manufacture this key-use provenance.
    #[cfg(feature = "authority-signing")]
    pub fn from_key_use_ticket(
        ticket: &wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseTicket,
        policy: &wholepact_wallet::WalletKeyUsePolicy,
    ) -> Result<Self> {
        ticket
            .validate_policy(policy)
            .map_err(|_| Error::Verification)?;
        let mut selected = Self::from_wallet(ticket.evidence());
        selected.key_use_policy = Some(policy.clone());
        Ok(selected)
    }

    #[cfg(feature = "wallet-review")]
    pub fn from_wallet(evidence: &wholepact_wallet::wallet::LocallySelectedInputs) -> Self {
        Self {
            account_id: evidence.account_id().into(),
            key_use_policy: None,
            context: SelectionContext {
                tip_height: evidence.context().tip_height,
                tip_hash: evidence.context().tip_hash_protocol,
                anchor_height: evidence.context().anchor_height,
                anchor_hash: evidence.context().anchor_hash_protocol,
                anchor_root: evidence.context().anchor_root,
            },
            fvk: evidence.fvk().clone(),
            inputs: evidence
                .inputs()
                .iter()
                .map(|i| SelectedInput {
                    input_id: i.input_id().into(),
                    nullifier: *i.nullifier(),
                    value: i.value_zatoshis(),
                })
                .collect(),
        }
    }
}
/// Maps are untrusted constructor output. Every entry is reconciled below and
/// the signer's own inputs additionally bind to trusted local wallet selection.
pub struct ReviewInputs {
    pub construction_context: ConstructionContext,
    pub policy: ReviewPolicy,
    pub input_actions: Vec<InputActionMapping>,
    pub output_actions: Vec<OutputActionMapping>,
    pub own_selection: LocalSelection,
}

pub(crate) fn reconcile(
    accepted: &AcceptedManifest,
    inputs: &ReviewInputs,
    account_id: &str,
    fvk: &FullViewingKey,
) -> Result<()> {
    let policy = &inputs.policy;
    let manifest = accepted.proposal.manifest();
    let selected = &inputs.own_selection;
    let check = |ok| if ok { Ok(()) } else { Err(Error::Verification) };
    check(accepted.digest() == hex::encode(policy.manifest_digest))?;
    check(
        policy.anchor == selected.context.anchor_root
            && inputs.construction_context.anchor == selected.context.anchor_root
            && inputs.construction_context.anchor_height == selected.context.anchor_height
            && inputs.construction_context.anchor_block_hash == selected.context.anchor_hash
            && inputs.construction_context.target_height
                == selected
                    .context
                    .tip_height
                    .checked_add(1)
                    .ok_or(Error::Verification)?,
    )?;
    check(
        manifest.agreement.network_profile_id == "ironwood-testnet-nu7-candidate"
            && manifest.agreement.extensions.is_empty()
            && manifest.participants.iter().all(|p| p.charges.is_empty()),
    )?;
    check(
        manifest.transaction_fee.as_zatoshis() == policy.exact_fee_zatoshis
            && manifest.expiry_height == policy.expiry_height
            && manifest.participants.len() == policy.participants.len(),
    )?;
    for participant in &manifest.participants {
        let actual = policy
            .participants
            .iter()
            .find(|p| p.account_id == participant.account_id)
            .ok_or(Error::Verification)?;
        check(
            actual.contribution_zatoshis == participant.contribution.as_zatoshis()
                && actual.fee_share_zatoshis == participant.fee_share.as_zatoshis()
                && actual.maximum_net_debit_zatoshis == participant.maximum_net_debit.as_zatoshis()
                && actual.fee_share_zatoshis <= participant.fee_cap.as_zatoshis(),
        )?;
    }
    check(selected.account_id == account_id && selected.fvk.to_bytes() == fvk.to_bytes())?;
    let owner = policy
        .participants
        .iter()
        .position(|p| p.account_id == account_id && p.fvk.to_bytes() == fvk.to_bytes())
        .ok_or(Error::Verification)?;
    check(
        manifest.inputs.len() == policy.inputs.len()
            && inputs.input_actions.len() == policy.inputs.len(),
    )?;
    let mut seen_ids = BTreeSet::new();
    let mut seen_actions = BTreeSet::new();
    let mut seen_selected = BTreeSet::new();
    for mapping in &inputs.input_actions {
        check(seen_ids.insert(&mapping.input_id) && seen_actions.insert(mapping.action_index))?;
        let claimed = manifest
            .inputs
            .iter()
            .find(|i| i.input_id == mapping.input_id)
            .ok_or(Error::Verification)?;
        let actual = policy
            .inputs
            .iter()
            .find(|i| i.action_index == mapping.action_index)
            .ok_or(Error::Verification)?;
        let participant = policy
            .participants
            .get(actual.participant_index)
            .ok_or(Error::Verification)?;
        let manifest_participant = manifest
            .participants
            .iter()
            .find(|p| p.participant_id == claimed.participant_id)
            .ok_or(Error::Verification)?;
        check(
            mapping.account_id == participant.account_id
                && claimed.account_id == participant.account_id
                && manifest_participant.account_id == participant.account_id
                && claimed.amount.as_zatoshis() == actual.value_zatoshis,
        )?;
        if actual.participant_index == owner {
            let expected = selected
                .inputs
                .iter()
                .find(|i| i.input_id == mapping.input_id)
                .ok_or(Error::Verification)?;
            check(
                seen_selected.insert(&expected.input_id)
                    && expected.nullifier == actual.nullifier
                    && expected.value == actual.value_zatoshis,
            )?;
        }
    }
    check(seen_selected.len() == selected.inputs.len() && !seen_selected.is_empty())?;
    check(
        manifest.outputs.len() == policy.outputs.len()
            && inputs.output_actions.len() == policy.outputs.len(),
    )?;
    let mut seen_ids = BTreeSet::new();
    let mut seen_actions = BTreeSet::new();
    for mapping in &inputs.output_actions {
        check(seen_ids.insert(&mapping.output_id) && seen_actions.insert(mapping.action_index))?;
        let claimed = manifest
            .outputs
            .iter()
            .find(|o| o.output_id == mapping.output_id)
            .ok_or(Error::Verification)?;
        let actual = policy
            .outputs
            .iter()
            .find(|o| o.action_index == mapping.action_index)
            .ok_or(Error::Verification)?;
        check(
            decode_testnet_receiver(&claimed.address).map_err(|_| Error::Verification)?
                == actual.receiver
                && claimed.amount.as_zatoshis() == actual.value_zatoshis,
        )?;
        match (&claimed.allocation, actual.purpose) {
            (OutputAllocation::Recipient { recipient_id }, OutputPurpose::Recipient) => {
                let recipient = manifest
                    .agreement
                    .recipients
                    .iter()
                    .find(|r| r.recipient_id == *recipient_id)
                    .ok_or(Error::Verification)?;
                let memo = recipient
                    .memo
                    .as_ref()
                    .map(|m| MemoBytes::from_bytes(m.as_bytes()))
                    .transpose()
                    .map_err(|_| Error::Verification)?
                    .unwrap_or_else(MemoBytes::empty);
                check(
                    actual.memo == memo.into_bytes()
                        && decode_testnet_receiver(&recipient.address)
                            .map_err(|_| Error::Verification)?
                            == actual.receiver
                        && recipient.amount.as_zatoshis() == actual.value_zatoshis,
                )?;
            }
            (
                OutputAllocation::Return {
                    participant_id,
                    account_id,
                    ..
                },
                OutputPurpose::Return { participant_index },
            ) => {
                let participant = manifest
                    .participants
                    .iter()
                    .find(|p| p.participant_id == *participant_id)
                    .ok_or(Error::Verification)?;
                check(
                    participant.account_id == *account_id
                        && policy
                            .participants
                            .get(participant_index)
                            .is_some_and(|p| p.account_id == *account_id)
                        && actual.memo == MemoBytes::empty().into_bytes(),
                )?;
            }
            _ => return Err(Error::Verification),
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "synthetic-qualification"))]
pub(crate) mod tests {
    use super::*;
    use wholepact_core::*;
    use wholepact_protocol::{review::encode_testnet_receiver, synthetic::review_fixture};
    fn amount(n: u64) -> Amount {
        Amount::from_zatoshis(n).unwrap()
    }
    fn fixture() -> (AcceptedManifest, ReviewInputs) {
        let (manifest, inputs, _) = consent_fixture();
        (manifest, inputs)
    }
    pub(crate) fn consent_fixture() -> (AcceptedManifest, ReviewInputs, Vec<u8>) {
        let fixture = review_fixture().unwrap();
        let mut policy = fixture.policy;
        let recipient = policy
            .outputs
            .iter()
            .find(|o| matches!(o.purpose, OutputPurpose::Recipient))
            .unwrap();
        let agreement = AgreementDraft {
            schema_version: 1,
            agreement_id: "synthetic-agreement".into(),
            obligation_id: "synthetic-obligation".into(),
            revision: 1,
            purpose: "Synthetic manifest bridge; never funded".into(),
            organizer_identity: "synthetic-organizer".into(),
            network_profile_id: "ironwood-testnet-nu7-candidate".into(),
            recipients: vec![Recipient {
                recipient_id: "recipient".into(),
                address: encode_testnet_receiver(&recipient.receiver),
                amount: amount(recipient.value_zatoshis),
                memo: None,
                instruction_provenance: "synthetic fixture".into(),
            }],
            funding_policy: FundingPolicy::Exact {
                target: amount(recipient.value_zatoshis),
            },
            fee_policy: FeePolicy::ProRata,
            privacy_profile: PrivacyProfile {
                mode: PrivacyMode::DeclaredOperator,
                proving_operator: Some("synthetic-prover".into()),
                dedicated_accounts_required: true,
            },
            coordination_deadline: None,
            confirmation_policy: ConfirmationPolicy::default(),
            extensions: vec![],
        };
        let participants = policy
            .participants
            .iter()
            .enumerate()
            .map(|(i, p)| ParticipantAllocation {
                participant_id: format!("participant-{i}"),
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
            .map(|(i, p)| ClaimedInput {
                input_id: format!("wallet-note-{i}"),
                participant_id: format!("participant-{}", p.participant_index),
                account_id: policy.participants[p.participant_index].account_id.clone(),
                amount: amount(p.value_zatoshis),
                ownership_evidence_ref: None,
            })
            .collect();
        let outputs = policy
            .outputs
            .iter()
            .enumerate()
            .map(|(i, o)| ClaimedOutput {
                output_id: format!("output-{i}"),
                address: encode_testnet_receiver(&o.receiver),
                amount: amount(o.value_zatoshis),
                allocation: match o.purpose {
                    OutputPurpose::Recipient => OutputAllocation::Recipient {
                        recipient_id: "recipient".into(),
                    },
                    OutputPurpose::Return { participant_index } => OutputAllocation::Return {
                        participant_id: format!("participant-{participant_index}"),
                        account_id: policy.participants[participant_index].account_id.clone(),
                        ownership_evidence_ref: None,
                    },
                },
            })
            .collect();
        let proposal = Proposal::validate(ProposalInput {
            proposal_id: "synthetic-proposal".into(),
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
            created_at: "2026-10-13T00:00:00Z".into(),
        })
        .unwrap();
        policy.manifest_digest = hex::decode(proposal.manifest_digest())
            .unwrap()
            .try_into()
            .unwrap();
        wholepact_protocol::review::verify_review(&fixture.pczt_bytes, &policy).unwrap();
        let input_actions = policy
            .inputs
            .iter()
            .enumerate()
            .map(|(i, p)| InputActionMapping {
                input_id: format!("wallet-note-{i}"),
                account_id: policy.participants[p.participant_index].account_id.clone(),
                action_index: p.action_index,
            })
            .collect();
        let output_actions = policy
            .outputs
            .iter()
            .enumerate()
            .map(|(i, o)| OutputActionMapping {
                output_id: format!("output-{i}"),
                action_index: o.action_index,
            })
            .collect();
        let context = ConstructionContext {
            anchor: policy.anchor,
            anchor_height: 99,
            anchor_block_hash: [8; 32],
            target_height: 100,
        };
        let own_selection = LocalSelection {
            key_use_policy: None,
            context: SelectionContext {
                tip_height: 99,
                tip_hash: [8; 32],
                anchor_height: 99,
                anchor_hash: [8; 32],
                anchor_root: policy.anchor,
            },
            account_id: policy.participants[0].account_id.clone(),
            fvk: policy.participants[0].fvk.clone(),
            inputs: policy
                .inputs
                .iter()
                .enumerate()
                .filter(|(_, p)| p.participant_index == 0)
                .map(|(i, p)| SelectedInput {
                    input_id: format!("wallet-note-{i}"),
                    nullifier: p.nullifier,
                    value: p.value_zatoshis,
                })
                .collect(),
        };
        (
            AcceptedManifest { proposal },
            ReviewInputs {
                construction_context: context,
                policy,
                input_actions,
                output_actions,
                own_selection,
            },
            fixture.pczt_bytes,
        )
    }
    #[test]
    fn exact_manifest_mapping_rejects_wallet_note_and_artifact_substitution() {
        let (accepted, mut input) = fixture();
        let id = input.own_selection.account_id.clone();
        let fvk = input.own_selection.fvk.clone();
        reconcile(&accepted, &input, &id, &fvk).unwrap();
        input.policy.anchor[0] ^= 1;
        assert!(reconcile(&accepted, &input, &id, &fvk).is_err());
        input.policy.anchor[0] ^= 1;
        input.own_selection.inputs[0].nullifier[0] ^= 1;
        assert!(reconcile(&accepted, &input, &id, &fvk).is_err());
        input.own_selection.inputs[0].nullifier[0] ^= 1;
        input.policy.manifest_digest[0] ^= 1;
        assert!(reconcile(&accepted, &input, &id, &fvk).is_err());
        input.policy.manifest_digest[0] ^= 1;
        input.input_actions[0].input_id = "unselected-wallet-note".into();
        assert!(reconcile(&accepted, &input, &id, &fvk).is_err());
        let (accepted, mut input) = fixture();
        input.output_actions.swap(0, 1); // order itself is irrelevant; identifiers remain bound
        reconcile(&accepted, &input, &id, &fvk).unwrap();
        input.output_actions[0].action_index = input.output_actions[1].action_index;
        assert!(reconcile(&accepted, &input, &id, &fvk).is_err());
    }
}
