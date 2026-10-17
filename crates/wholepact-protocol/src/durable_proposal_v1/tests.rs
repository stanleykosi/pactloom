use super::*;

fn identity() -> FixedProposalIdentityV1 {
    FixedProposalIdentityV1 {
        schema_version: 1,
        network_profile_id: "ironwood-testnet-nu7-candidate".into(),
        agreement_id: "agreement".into(),
        obligation_id: "obligation".into(),
        proposal_id: "proposal".into(),
        revision: 1,
        expiry_height: 140,
        proposal_digest: "01".repeat(32),
        manifest_digest: "02".repeat(32),
        unsigned_artifact_digest: "03".repeat(32),
        proved_artifact_digest: "04".repeat(32),
        effects_commitment: "05".repeat(32),
        policy_digest: "06".repeat(32),
        review_binding: "07".repeat(32),
        action_mapping_digest: "08".repeat(32),
        anchor: "09".repeat(32),
        proposal_binding: String::new(),
    }
}

#[test]
fn fixed_binding_covers_every_identity_field_except_its_own_result() {
    let original = identity();
    let expected = proposal_binding(&original);
    let encoded = serde_json::to_value(&original).unwrap();
    for key in encoded.as_object().unwrap().keys() {
        if key == "proposal_binding" {
            continue;
        }
        let mut changed = encoded.clone();
        changed[key] = if let Some(value) = changed[key].as_u64() {
            serde_json::json!(value + 1)
        } else {
            serde_json::json!(format!("{}-different", changed[key].as_str().unwrap()))
        };
        let changed: FixedProposalIdentityV1 = serde_json::from_value(changed).unwrap();
        assert_ne!(expected, proposal_binding(&changed), "unbound field {key}");
    }
    let mut changed = original;
    changed.proposal_binding = expected.clone();
    assert_eq!(expected, proposal_binding(&changed));
    // Metadata can be stored, but is never itself a verified wrapper.
    let mut unknown = encoded;
    unknown["proof_verified"] = serde_json::json!(true);
    assert!(serde_json::from_value::<FixedProposalIdentityV1>(unknown).is_err());
}

#[test]
fn mapping_digest_is_order_independent_but_fixes_each_attribution() {
    let mut inputs = vec![
        InputActionMapping {
            input_id: "a".into(),
            account_id: "owner-a".into(),
            action_index: 2,
        },
        InputActionMapping {
            input_id: "b".into(),
            account_id: "owner-b".into(),
            action_index: 0,
        },
    ];
    let mut outputs = vec![
        OutputActionMapping {
            output_id: "recipient".into(),
            action_index: 1,
        },
        OutputActionMapping {
            output_id: "return".into(),
            action_index: 2,
        },
    ];
    let baseline = mapping_digest(&inputs, &outputs);
    inputs.reverse();
    outputs.reverse();
    assert_eq!(baseline, mapping_digest(&inputs, &outputs));
    for changed in [
        InputActionMapping {
            input_id: "different".into(),
            ..inputs[0].clone()
        },
        InputActionMapping {
            account_id: "different".into(),
            ..inputs[0].clone()
        },
        InputActionMapping {
            action_index: 1,
            ..inputs[0].clone()
        },
    ] {
        let mut altered = inputs.clone();
        altered[0] = changed;
        assert_ne!(baseline, mapping_digest(&altered, &outputs));
    }
    for changed in [
        OutputActionMapping {
            output_id: "different".into(),
            ..outputs[0].clone()
        },
        OutputActionMapping {
            action_index: 0,
            ..outputs[0].clone()
        },
    ] {
        let mut altered = outputs.clone();
        altered[0] = changed;
        assert_ne!(baseline, mapping_digest(&inputs, &altered));
    }
}

#[test]
fn detached_set_digest_binds_attribution_signature_and_fixed_artifact_identity() {
    fn signature() -> DetachedSpendSignatureV1 {
        DetachedSpendSignatureV1 {
            proposal_binding: "01".repeat(32),
            participant_id: "participant".into(),
            account_id: "account".into(),
            action_index: 1,
            signature: [2; 64],
        }
    }
    let original = signature();
    let baseline = signature_set_digest(&original.proposal_binding, &[&original]);
    for field in 0..5 {
        let mut changed = signature();
        match field {
            0 => changed.proposal_binding = "09".repeat(32),
            1 => changed.participant_id.push('x'),
            2 => changed.account_id.push('x'),
            3 => changed.action_index += 1,
            _ => changed.signature[0] ^= 1,
        }
        assert_ne!(
            baseline,
            signature_set_digest(&changed.proposal_binding, &[&changed])
        );
    }
    assert_ne!(
        baseline,
        signature_set_digest(&original.proposal_binding, &[])
    );
}

#[cfg(feature = "synthetic-qualification")]
mod synthetic {
    use super::*;
    use crate::review::encode_testnet_receiver;
    use orchard::{
        keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
        note::ExtractedNoteCommitment,
        note_encryption::IronwoodDomain,
        tree::MerkleHashOrchard,
    };
    use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer, prover::Prover};
    use rand::{SeedableRng, rngs::StdRng};
    use serde_json::{Value, json};
    use shardtree::{ShardTree, store::memory::MemoryShardStore};
    use wholepact_core::*;
    use zcash_note_encryption::try_note_decryption;
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder, BundlePadding, PcztResult},
        fees::zip317,
    };
    use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis};

    struct Fixture {
        unsigned: Vec<u8>,
        policy: ReviewPolicy,
        proposal: Proposal,
        inputs: Vec<InputActionMapping>,
        outputs: Vec<OutputActionMapping>,
    }

    fn amount(value: u64) -> Amount {
        Amount::from_zatoshis(value).unwrap()
    }

    // Every byte is generated from fixed public TEST keys and deterministic test
    // randomness. No wallet, network, filesystem, new private key or funded note
    // is read. These constants are the existing protocol qualification test keys.
    fn fixture() -> Fixture {
        let mut rng = StdRng::from_seed([0xd1; 32]);
        let keys = [1_u8, 2, 3].map(|byte| SpendingKey::from_bytes([byte; 32]).unwrap());
        let fvks = keys.each_ref().map(FullViewingKey::from);
        let version = orchard::bundle::BundleVersion::ironwood_v3();
        let mut incoming = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            version,
            version.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        for (fvk, value) in fvks.iter().take(2).zip([200_000, 300_000]) {
            incoming
                .add_output(
                    None,
                    fvk.address_at(0_u32, Scope::External),
                    orchard::value::NoteValue::from_raw(value),
                    MemoBytes::empty().into_bytes(),
                )
                .unwrap();
        }
        let (bundle, meta) = incoming.build::<i64>(&mut rng).unwrap().unwrap();
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        let mut notes = Vec::new();
        for (owner, fvk) in fvks.iter().take(2).enumerate() {
            let action = &bundle.actions()[meta.output_action_index(owner).unwrap()];
            let (note, _, _) = try_note_decryption(
                &IronwoodDomain::for_action(action),
                &fvk.to_ivk(Scope::External).prepare(),
                action,
            )
            .unwrap();
            let cmx: ExtractedNoteCommitment = note.commitment().into();
            tree.append(
                MerkleHashOrchard::from_cmx(&cmx),
                incrementalmerkletree::Retention::Marked,
            )
            .unwrap();
            notes.push(note);
        }
        tree.checkpoint(99).unwrap();
        let paths: Vec<orchard::tree::MerklePath> = (0_u64..2)
            .map(|index| {
                tree.witness_at_checkpoint_depth(index.into(), 0)
                    .unwrap()
                    .unwrap()
                    .into()
            })
            .collect();
        let anchor = paths[0].root(notes[0].commitment().into());
        let network = zcash_protocol::local_consensus::LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(2)),
            blossom: Some(BlockHeight::from_u32(3)),
            heartwood: Some(BlockHeight::from_u32(4)),
            canopy: Some(BlockHeight::from_u32(5)),
            nu5: Some(BlockHeight::from_u32(6)),
            nu6: Some(BlockHeight::from_u32(7)),
            nu6_1: Some(BlockHeight::from_u32(8)),
            nu6_2: Some(BlockHeight::from_u32(9)),
            nu6_3: Some(BlockHeight::from_u32(10)),
            nu7: Some(BlockHeight::from_u32(11)),
        };
        let mut builder = Builder::new(
            network,
            100_u32.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        )
        .with_expiry_height(140_u32.into());
        for ((fvk, note), path) in fvks.iter().take(2).zip(notes).zip(paths) {
            builder
                .add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, path)
                .unwrap();
        }
        for (owner, scope, value) in [
            (2, Scope::External, 300_000),
            (0, Scope::Internal, 95_000),
            (1, Scope::Internal, 90_000),
        ] {
            builder
                .add_ironwood_output::<zip317::FeeRule>(
                    Some(fvks[owner].to_ovk(scope)),
                    fvks[owner].address_at(0_u32, scope),
                    Zatoshis::from_u64(value).unwrap(),
                    MemoBytes::empty(),
                )
                .unwrap();
        }
        let PcztResult { pczt_parts, .. } = builder
            .build_for_pczt(&mut rng, &zip317::FeeRule::standard())
            .unwrap();
        let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
            .finalize_io(&mut rng)
            .unwrap();
        let unsigned = encode(pczt).unwrap();
        let mut policy = crate::synthetic::policy_for_fixture_pczt(&unsigned).unwrap();
        let agreement = AgreementDraft {
            schema_version: 1,
            agreement_id: "durable-test-agreement".into(),
            obligation_id: "durable-test-obligation".into(),
            revision: 1,
            purpose: "Deterministic never-funded fixed-proposal qualification".into(),
            organizer_identity: "synthetic-organizer".into(),
            network_profile_id: crate::construction::PROFILE_ID.into(),
            recipients: vec![Recipient {
                recipient_id: "recipient".into(),
                address: encode_testnet_receiver(&policy.outputs[0].receiver),
                amount: amount(300_000),
                memo: None,
                instruction_provenance: "fixed synthetic instruction".into(),
            }],
            funding_policy: FundingPolicy::Exact {
                target: amount(300_000),
            },
            fee_policy: FeePolicy::ProRata,
            privacy_profile: PrivacyProfile {
                mode: PrivacyMode::DeclaredOperator,
                proving_operator: Some("synthetic-operator".into()),
                dedicated_accounts_required: true,
            },
            coordination_deadline: None,
            confirmation_policy: ConfirmationPolicy::default(),
            extensions: vec![],
        };
        let participants: Vec<_> = policy
            .participants
            .iter()
            .enumerate()
            .map(|(owner, participant)| ParticipantAllocation {
                participant_id: format!("participant-{owner}"),
                account_id: participant.account_id.clone(),
                contribution: amount(participant.contribution_zatoshis),
                fee_share: amount(participant.fee_share_zatoshis),
                fee_cap: amount(participant.fee_share_zatoshis),
                maximum_net_debit: amount(participant.maximum_net_debit_zatoshis),
                charges: vec![],
            })
            .collect();
        let inputs: Vec<_> = policy
            .inputs
            .iter()
            .enumerate()
            .map(|(slot, input)| InputActionMapping {
                input_id: format!("input-{slot}"),
                account_id: participants[input.participant_index].account_id.clone(),
                action_index: input.action_index,
            })
            .collect();
        let claimed_inputs = policy
            .inputs
            .iter()
            .zip(&inputs)
            .map(|(input, mapping)| ClaimedInput {
                input_id: mapping.input_id.clone(),
                participant_id: participants[input.participant_index].participant_id.clone(),
                account_id: mapping.account_id.clone(),
                amount: amount(input.value_zatoshis),
                ownership_evidence_ref: None,
            })
            .collect();
        let outputs: Vec<_> = policy
            .outputs
            .iter()
            .enumerate()
            .map(|(slot, output)| OutputActionMapping {
                output_id: format!("output-{slot}"),
                action_index: output.action_index,
            })
            .collect();
        let claimed_outputs = policy
            .outputs
            .iter()
            .zip(&outputs)
            .map(|(output, mapping)| ClaimedOutput {
                output_id: mapping.output_id.clone(),
                address: encode_testnet_receiver(&output.receiver),
                amount: amount(output.value_zatoshis),
                allocation: match output.purpose {
                    crate::review::OutputPurpose::Recipient => OutputAllocation::Recipient {
                        recipient_id: "recipient".into(),
                    },
                    crate::review::OutputPurpose::Return { participant_index } => {
                        OutputAllocation::Return {
                            participant_id: participants[participant_index].participant_id.clone(),
                            account_id: participants[participant_index].account_id.clone(),
                            ownership_evidence_ref: None,
                        }
                    }
                },
            })
            .collect();
        let proposal = Proposal::validate(ProposalInput {
            proposal_id: "durable-test-proposal".into(),
            previous_proposal_id: None,
            manifest: ProposalManifest {
                agreement,
                participants,
                inputs: claimed_inputs,
                outputs: claimed_outputs,
                transaction_fee: amount(15_000),
                expiry_height: 140,
            },
            artifact_digest: None,
            effects_commitment: None,
            created_at: "2026-10-17T00:00:00Z".into(),
        })
        .unwrap();
        policy.manifest_digest = hex::decode(proposal.manifest_digest())
            .unwrap()
            .try_into()
            .unwrap();
        Fixture {
            unsigned,
            policy,
            proposal,
            inputs,
            outputs,
        }
    }

    fn wire(bytes: &[u8]) -> Value {
        serde_json::to_value(pczt::v2::Pczt::try_from(Pczt::parse(bytes).unwrap()).unwrap())
            .unwrap()
    }

    fn bytes(value: Value) -> Vec<u8> {
        serde_json::from_value::<pczt::v2::Pczt>(value)
            .unwrap()
            .serialize()
    }

    fn fabricated_proof(fixture: &Fixture) -> Vec<u8> {
        let mut value = wire(&fixture.unsigned);
        value["ironwood"]["zkproof"] = json!([1, 2, 3]);
        bytes(value)
    }

    fn verify(
        fixture: &Fixture,
        proved: &[u8],
    ) -> std::result::Result<VerifiedFixedProposal, String> {
        VerifiedFixedProposal::verify(
            &fixture.unsigned,
            proved,
            &fixture.proposal,
            &fixture.policy,
            &fixture.inputs,
            &fixture.outputs,
            ProvingLimits { maximum_actions: 8 },
        )
    }

    #[test]
    fn deterministic_fixture_reconciles_complete_manifest_and_preserves_padding() {
        let first = fixture();
        let second = fixture();
        assert_eq!(first.unsigned, second.unsigned);
        verify_manifest_policy(
            &first.proposal,
            &first.policy,
            &first.inputs,
            &first.outputs,
        )
        .unwrap();
        verify_review(&first.unsigned, &first.policy).unwrap();
        let parsed = parse_candidate(&first.unsigned).unwrap();
        verify_retained_padding_signatures(&parsed, &first.policy).unwrap();
        assert!(
            parsed
                .ironwood()
                .actions()
                .iter()
                .any(|action| action.spend().spend_auth_sig().is_some())
        );
        let fake = fabricated_proof(&first);
        // Structural success is deliberately not a verified proposal constructor.
        require_exact_proof_addition(
            &first.unsigned,
            &parsed,
            &parse_candidate(&fake).unwrap(),
            &first.policy,
        )
        .unwrap();
        assert!(verify(&first, &fake).is_err());
        assert!(verify(&first, &first.unsigned).is_err());
    }

    #[test]
    fn proof_transition_rejects_every_other_field_change_and_preexisting_real_signature() {
        let fixture = fixture();
        let unsigned = parse_candidate(&fixture.unsigned).unwrap();
        let real = fixture.policy.inputs[0].action_index;
        let dummy = unsigned
            .ironwood()
            .actions()
            .iter()
            .position(|action| action.spend().spend_auth_sig().is_some())
            .unwrap();
        let baseline = wire(&fabricated_proof(&fixture));
        let mut variants = Vec::new();
        let mut value = baseline.clone();
        value["global"]["expiry_height"] = json!(141);
        variants.push(value);
        let mut value = baseline.clone();
        value["ironwood"]["anchor"] = json!(vec![0_u8; 32]);
        variants.push(value);
        let mut value = baseline.clone();
        value["ironwood"]["bsk"] = Value::Null;
        variants.push(value);
        let mut value = baseline.clone();
        value["ironwood"]["actions"][real]["spend"]["witness"] = Value::Null;
        variants.push(value);
        let mut value = baseline.clone();
        value["ironwood"]["actions"][real]["spend"]["alpha"] = Value::Null;
        variants.push(value);
        let mut value = baseline.clone();
        value["ironwood"]["actions"][real]["output"]["user_address"] = json!("substitution");
        variants.push(value);
        let mut value = baseline.clone();
        value["ironwood"]["actions"][real]["spend"]["spend_auth_sig"] = json!(vec![0_u8; 64]);
        variants.push(value);
        let mut value = baseline.clone();
        value["ironwood"]["actions"][dummy]["spend"]["spend_auth_sig"] = Value::Null;
        variants.push(value);
        let mut value = baseline;
        value["ironwood"]["actions"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        variants.push(value);
        for changed in variants {
            let changed = bytes(changed);
            assert!(
                require_exact_proof_addition(
                    &fixture.unsigned,
                    &unsigned,
                    &parse_candidate(&changed).unwrap(),
                    &fixture.policy
                )
                .is_err()
            );
            assert!(verify(&fixture, &changed).is_err());
        }
        let mut trailing = fabricated_proof(&fixture);
        trailing.push(0);
        assert!(verify(&fixture, &trailing).is_err());
        assert!(
            VerifiedFixedProposal::verify(
                &fabricated_proof(&fixture),
                &fabricated_proof(&fixture),
                &fixture.proposal,
                &fixture.policy,
                &fixture.inputs,
                &fixture.outputs,
                ProvingLimits { maximum_actions: 8 }
            )
            .is_err()
        );
    }

    #[test]
    fn changed_manifest_policy_mappings_and_padding_signatures_fail_closed() {
        let mut fixture = fixture();
        let fake = fabricated_proof(&fixture);
        fixture.policy.manifest_digest[0] ^= 1;
        assert!(verify(&fixture, &fake).is_err());
        fixture.policy.manifest_digest[0] ^= 1;
        fixture.inputs[0].account_id = fixture.inputs[1].account_id.clone();
        assert!(verify(&fixture, &fake).is_err());
        let fixture = self::fixture();
        let mut altered = fixture.outputs.clone();
        altered[0].action_index = altered[1].action_index;
        assert!(
            VerifiedFixedProposal::verify(
                &fixture.unsigned,
                &fake,
                &fixture.proposal,
                &fixture.policy,
                &fixture.inputs,
                &altered,
                ProvingLimits { maximum_actions: 8 }
            )
            .is_err()
        );
        let parsed = parse_candidate(&fixture.unsigned).unwrap();
        let dummy = parsed
            .ironwood()
            .actions()
            .iter()
            .position(|action| action.spend().spend_auth_sig().is_some())
            .unwrap();
        for signature in [Value::Null, json!(vec![0_u8; 64])] {
            let mut value = wire(&fixture.unsigned);
            value["ironwood"]["actions"][dummy]["spend"]["spend_auth_sig"] = signature;
            assert!(
                verify_retained_padding_signatures(
                    &parse_candidate(&bytes(value)).unwrap(),
                    &fixture.policy
                )
                .is_err()
            );
        }
    }

    #[test]
    fn narrow_profile_rejects_multiple_recipients_and_non_two_owner_policy() {
        let mut fixture = fixture();
        let fake = fabricated_proof(&fixture);
        fixture
            .policy
            .participants
            .push(fixture.policy.participants[0].clone());
        assert_eq!(
            verify(&fixture, &fake).err().unwrap(),
            "Durable fixed proposal requires exactly two owners"
        );
        fixture.policy.participants.pop();
        let mut input = fixture.proposal.input().clone();
        input.manifest.agreement.recipients[0].amount = amount(100_000);
        let mut second = input.manifest.agreement.recipients[0].clone();
        second.recipient_id = "second-recipient".into();
        second.amount = amount(200_000);
        input.manifest.agreement.recipients.push(second);
        input.manifest.outputs[0].amount = amount(100_000);
        let mut second = input.manifest.outputs[0].clone();
        second.output_id = "second-recipient-output".into();
        second.amount = amount(200_000);
        second.allocation = OutputAllocation::Recipient {
            recipient_id: "second-recipient".into(),
        };
        input.manifest.outputs.push(second);
        fixture.proposal = Proposal::validate(input).unwrap();
        assert_eq!(
            verify(&fixture, &fake).err().unwrap(),
            "Durable fixed proposal requires exactly one recipient"
        );
    }

    #[test]
    #[ignore = "CPU-intensive real synthetic proof qualification; run explicitly"]
    fn real_proof_and_independent_detached_owners_preserve_exact_fixed_artifact() {
        let fixture = fixture();
        let key =
            orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
        let proved = Prover::new(parse_candidate(&fixture.unsigned).unwrap())
            .create_ironwood_proof(StdRng::from_seed([0xd2; 32]), &key)
            .unwrap()
            .finish();
        let proved = encode(proved).unwrap();
        let fixed = verify(&fixture, &proved).unwrap();
        assert_ne!(
            fixed.identity().unsigned_artifact_digest,
            fixed.identity().proved_artifact_digest
        );
        assert_eq!(
            fixed.identity().effects_commitment,
            verify_review(&fixture.unsigned, &fixture.policy)
                .unwrap()
                .shielded_sighash()
        );
        let reopened = verify(&fixture, &proved).unwrap();
        assert_eq!(fixed.identity(), reopened.identity());
        fixed
            .verify_action_mappings(&fixture.inputs, &fixture.outputs)
            .unwrap();
        let mut reversed_inputs = fixture.inputs.clone();
        reversed_inputs.reverse();
        fixed
            .verify_action_mappings(&reversed_inputs, &fixture.outputs)
            .unwrap();
        let empty = fixed.verify_detached_signatures(&[]).unwrap();
        assert!(!empty.inspection().signatures_complete);
        assert_eq!(
            empty.identity().signed_artifact_digest,
            fixed.identity().proved_artifact_digest
        );

        let mut signatures = Vec::new();
        for owner in 0..2 {
            let input = &fixture.policy.inputs[owner];
            let key =
                SpendingKey::from_bytes(crate::synthetic::TEST_OWNER_SPENDING_KEY_BYTES[owner])
                    .unwrap();
            let mut signer = Signer::new(parse_candidate(&proved).unwrap()).unwrap();
            signer
                .sign_ironwood(
                    StdRng::from_seed([0xe0 + owner as u8; 32]),
                    input.action_index,
                    &SpendAuthorizingKey::from(&key),
                )
                .unwrap();
            let signed = signer.finish();
            signatures.push(DetachedSpendSignatureV1 {
                proposal_binding: fixed.identity().proposal_binding.clone(),
                participant_id: fixture.proposal.manifest().participants[owner]
                    .participant_id
                    .clone(),
                account_id: fixture.policy.participants[owner].account_id.clone(),
                action_index: input.action_index,
                signature: signed.ironwood().actions()[input.action_index]
                    .spend()
                    .spend_auth_sig()
                    .unwrap(),
            });
        }
        let partial = fixed.verify_detached_signatures(&signatures[..1]).unwrap();
        assert_eq!(partial.inspection().verified_real_inputs, 1);
        assert!(!partial.inspection().signatures_complete);
        let complete = fixed.verify_detached_signatures(&signatures).unwrap();
        assert!(complete.inspection().signatures_complete && complete.inspection().proof_verified);
        assert!(
            !complete.inspection().authorization_allowed
                && !complete.inspection().distribution_allowed
                && !complete.inspection().chain_validated
        );
        signatures.reverse();
        assert_eq!(
            complete.identity(),
            fixed
                .verify_detached_signatures(&signatures)
                .unwrap()
                .identity()
        );
        signatures[0].proposal_binding = "00".repeat(32);
        assert!(fixed.verify_detached_signatures(&signatures).is_err());
        signatures[0].proposal_binding = fixed.identity().proposal_binding.clone();
        signatures[0].signature[0] ^= 1;
        assert!(fixed.verify_detached_signatures(&signatures).is_err());
        signatures[0].signature[0] ^= 1;
        signatures[0].account_id = signatures[1].account_id.clone();
        assert!(fixed.verify_detached_signatures(&signatures).is_err());
        signatures[0].account_id = fixture.policy.participants[1].account_id.clone();
        signatures[0].participant_id = "unknown-participant".into();
        assert!(fixed.verify_detached_signatures(&signatures).is_err());
        signatures[0].participant_id = fixture.proposal.manifest().participants[1]
            .participant_id
            .clone();
        signatures[0].action_index = parse_candidate(&proved)
            .unwrap()
            .ironwood()
            .actions()
            .iter()
            .position(|action| action.spend().spend_auth_sig().is_some())
            .unwrap();
        assert!(fixed.verify_detached_signatures(&signatures).is_err());
        signatures[0].action_index = signatures[1].action_index;
        assert!(fixed.verify_detached_signatures(&signatures).is_err());

        let mut changed = wire(&proved);
        changed["ironwood"]["actions"][0]["output"]["user_address"] =
            json!("same-effects-new-artifact");
        assert_eq!(
            Signer::new(parse_candidate(&bytes(changed.clone())).unwrap())
                .unwrap()
                .shielded_sighash(),
            Signer::new(parse_candidate(&proved).unwrap())
                .unwrap()
                .shielded_sighash()
        );
        assert!(verify(&fixture, &bytes(changed)).is_err());
    }
}
