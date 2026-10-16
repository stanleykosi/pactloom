#![cfg(feature = "synthetic-qualification")]
//! Generated never-funded notes from three independently derived temporary test
//! accounts. All witnesses refer to a fabricated tree; no backend is contacted.
use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::IronwoodDomain,
    tree::MerkleHashOrchard,
};
use rand::{Rng, rand_core::UnwrapErr, rngs::SysRng};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use wholepact_core::*;
use wholepact_protocol::{
    construction::*,
    review::{encode_testnet_receiver, verify_review},
};
use zcash_note_encryption::try_note_decryption;
use zcash_protocol::memo::MemoBytes;

struct Fixture {
    proposal: Proposal,
    context: ConstructionContext,
    contributions: Vec<OwnedContribution>,
    disclosures: Vec<DisclosureAcknowledgement>,
    keys: Vec<SpendingKey>,
}
fn amount(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}
fn fixture() -> Fixture {
    let keys: Vec<_> = (0..4)
        .map(|_| {
            let mut seed = [0; 32];
            UnwrapErr(SysRng).fill_bytes(&mut seed);
            SpendingKey::from_zip32_seed(&seed, 1, 0u32.try_into().unwrap()).unwrap()
        })
        .collect();
    let fvks: Vec<_> = keys.iter().map(FullViewingKey::from).collect();
    let specs = [
        (0, 40_000),
        (0, 65_000),
        (1, 120_000),
        (2, 70_000),
        (2, 130_000),
    ];
    let version = orchard::bundle::BundleVersion::ironwood_v3();
    let mut incoming = orchard::builder::Builder::new(
        orchard::builder::BundleType::DEFAULT,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    for (owner, value) in specs {
        incoming
            .add_output(
                None,
                fvks[owner].address_at(0u32, Scope::External),
                orchard::value::NoteValue::from_raw(value),
                MemoBytes::empty().into_bytes(),
            )
            .unwrap();
    }
    let (bundle, meta) = incoming.build::<i64>(UnwrapErr(SysRng)).unwrap().unwrap();
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    let mut notes = Vec::new();
    for (index, (owner, _)) in specs.iter().enumerate() {
        let action = &bundle.actions()[meta.output_action_index(index).unwrap()];
        let (note, _, _) = try_note_decryption(
            &IronwoodDomain::for_action(action),
            &fvks[*owner].to_ivk(Scope::External).prepare(),
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
    tree.checkpoint(4_498_000).unwrap();
    let witnesses: Vec<orchard::tree::MerklePath> = (0u64..5)
        .map(|i| {
            tree.witness_at_checkpoint_depth(i.into(), 0)
                .unwrap()
                .unwrap()
                .into()
        })
        .collect();
    let anchor = witnesses[0].root(notes[0].commitment().into()).to_bytes();
    let context = ConstructionContext {
        anchor,
        anchor_height: 4_498_000,
        anchor_block_hash: [99; 32],
        target_height: 4_498_001,
    };
    let mut contributions: Vec<_> = (0..3)
        .map(|owner| OwnedContribution {
            account_id: format!("temporary-account-{owner}"),
            fvk: fvks[owner].clone(),
            notes: vec![],
            change_address: fvks[owner].address_at(0u32, Scope::Internal),
        })
        .collect();
    for (i, ((note, witness), (owner, _))) in
        notes.into_iter().zip(witnesses).zip(specs).enumerate()
    {
        contributions[owner].notes.push(SpendableNote {
            input_id: format!("selected-note-{i}"),
            note,
            witness,
        });
    }
    let agreement = AgreementDraft {
        schema_version: 1,
        agreement_id: "generic-build".into(),
        obligation_id: "generic-obligation".into(),
        revision: 1,
        purpose: "Generated synthetic construction test".into(),
        organizer_identity: "local-test-organizer".into(),
        network_profile_id: PROFILE_ID.into(),
        recipients: vec![Recipient {
            recipient_id: "recipient".into(),
            address: encode_testnet_receiver(&fvks[3].address_at(7u32, Scope::External)),
            amount: amount(300_000),
            memo: Some("exact UTF-8 memo".into()),
            instruction_provenance: "synthetic instruction".into(),
        }],
        funding_policy: FundingPolicy::Exact {
            target: amount(300_000),
        },
        fee_policy: FeePolicy::ProRata,
        privacy_profile: PrivacyProfile {
            mode: PrivacyMode::DeclaredOperator,
            proving_operator: Some("local-test-constructor".into()),
            dedicated_accounts_required: true,
        },
        coordination_deadline: None,
        confirmation_policy: ConfirmationPolicy::default(),
        extensions: vec![],
    };
    let contributions_due = [90_000, 100_000, 110_000];
    let weights: Vec<_> = (0..3)
        .map(|i| FeeWeight {
            participant_id: format!("participant-{i}"),
            contribution: amount(contributions_due[i]),
        })
        .collect();
    let shares = allocate_fees(amount(25_000), &weights, &FeePolicy::ProRata).unwrap();
    let participants: Vec<_> = (0..3)
        .map(|i| ParticipantAllocation {
            participant_id: format!("participant-{i}"),
            account_id: format!("temporary-account-{i}"),
            contribution: amount(contributions_due[i]),
            fee_share: shares[&format!("participant-{i}")],
            fee_cap: amount(25_000),
            maximum_net_debit: amount(contributions_due[i])
                .checked_add(shares[&format!("participant-{i}")])
                .unwrap(),
            charges: vec![],
        })
        .collect();
    let inputs = specs
        .iter()
        .enumerate()
        .map(|(i, (owner, value))| ClaimedInput {
            input_id: format!("selected-note-{i}"),
            participant_id: format!("participant-{owner}"),
            account_id: format!("temporary-account-{owner}"),
            amount: amount(*value),
            ownership_evidence_ref: None,
        })
        .collect();
    let mut outputs = vec![ClaimedOutput {
        output_id: "payment".into(),
        address: agreement.recipients[0].address.clone(),
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: "recipient".into(),
        },
    }];
    for (i, total) in [105_000, 120_000, 200_000].into_iter().enumerate() {
        outputs.push(ClaimedOutput {
            output_id: format!("return-{i}"),
            address: encode_testnet_receiver(&contributions[i].change_address),
            amount: amount(total)
                .checked_sub(participants[i].maximum_net_debit)
                .unwrap(),
            allocation: OutputAllocation::Return {
                participant_id: format!("participant-{i}"),
                account_id: format!("temporary-account-{i}"),
                ownership_evidence_ref: None,
            },
        });
    }
    let manifest = ProposalManifest {
        agreement,
        participants,
        inputs,
        outputs,
        transaction_fee: amount(25_000),
        expiry_height: 4_498_041,
    };
    let proposal = Proposal::validate(ProposalInput {
        proposal_id: "generic-proposal".into(),
        previous_proposal_id: None,
        manifest,
        artifact_digest: None,
        effects_commitment: None,
        created_at: "2026-10-13T14:00:00Z".into(),
    })
    .unwrap();
    let digest: [u8; 32] = hex::decode(proposal.manifest_digest())
        .unwrap()
        .try_into()
        .unwrap();
    let disclosures = (0..3)
        .map(|i| DisclosureAcknowledgement {
            account_id: format!("temporary-account-{i}"),
            manifest_digest: digest,
            operator: "local-test-constructor".into(),
            reviewer_account_ids: (0..3).map(|i| format!("temporary-account-{i}")).collect(),
            purpose: "Synthetic construction and proving".into(),
            retention_policy: "Memory only for this test".into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    Fixture {
        proposal,
        context,
        contributions,
        disclosures,
        keys,
    }
}

#[test]
fn generic_three_owner_five_note_construction_matches_exact_manifest() {
    let f = fixture();
    let built =
        construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).unwrap();
    assert_eq!(built.input_actions.len(), 5);
    assert_eq!(built.output_actions.len(), 4);
    assert_eq!(built.review_policy.participants.len(), 3);
    assert_eq!(built.economic_review.fee_zatoshis(), 25_000);
    assert!(!built.chain_validated && !built.disclosure_consents_authenticated);
    assert!(!built.distribution_allowed && !built.authorization_allowed);
    assert_eq!(
        verify_review(&built.pczt_bytes, &built.review_policy)
            .unwrap()
            .review_binding(),
        built.economic_review.review_binding()
    );
    for mapping in built.input_actions {
        assert!(
            f.proposal
                .manifest()
                .inputs
                .iter()
                .any(|i| i.input_id == mapping.input_id)
        );
    }
}

#[test]
fn generic_constructor_rejects_substitution_and_undeclared_disclosure() {
    let mut f = fixture();
    f.disclosures.pop();
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    f.disclosures[0].reviewer_account_ids.pop();
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    f.disclosures[0]
        .reviewer_account_ids
        .push("unexpected-reviewer".into());
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    f.disclosures[0]
        .reviewer_account_ids
        .push("temporary-account-0".into());
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    f.disclosures[0].operator = "different operator".into();
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    f.disclosures[0].manifest_digest[0] ^= 1;
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    f.contributions[0].change_address = f.contributions[1].change_address;
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    f.contributions[0].notes[0].input_id = "substituted-selection".into();
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    f.contributions[0].fvk = f.contributions[1].fvk.clone();
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    f.context.anchor = orchard::Anchor::empty_tree().to_bytes();
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    f.context.target_height = f.proposal.manifest().expiry_height + 1;
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
    let mut f = fixture();
    let mut input = f.proposal.input().clone();
    input.manifest.agreement.privacy_profile.mode = PrivacyMode::LocalOnly;
    input.manifest.agreement.privacy_profile.proving_operator = None;
    f.proposal = Proposal::validate(input).unwrap();
    assert!(construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).is_err());
}

#[test]
fn generic_constructor_requires_actual_standard_fee_and_selected_note_amounts() {
    let mut f = fixture();
    let mut revised = f.proposal.input().clone();
    revised.manifest.transaction_fee = amount(25_001);
    let weights: Vec<_> = revised
        .manifest
        .participants
        .iter()
        .map(|p| FeeWeight {
            participant_id: p.participant_id.clone(),
            contribution: p.contribution,
        })
        .collect();
    let shares = allocate_fees(amount(25_001), &weights, &FeePolicy::ProRata).unwrap();
    for participant in &mut revised.manifest.participants {
        let delta = shares[&participant.participant_id]
            .checked_sub(participant.fee_share)
            .unwrap();
        participant.fee_share = shares[&participant.participant_id];
        participant.maximum_net_debit = participant
            .contribution
            .checked_add(participant.fee_share)
            .unwrap();
        let change=revised.manifest.outputs.iter_mut().find(|o|matches!(&o.allocation,
            OutputAllocation::Return{participant_id,..} if participant_id==&participant.participant_id)).unwrap();
        change.amount = change.amount.checked_sub(delta).unwrap();
    }
    f.proposal = Proposal::validate(revised).unwrap();
    let digest: [u8; 32] = hex::decode(f.proposal.manifest_digest())
        .unwrap()
        .try_into()
        .unwrap();
    for disclosure in &mut f.disclosures {
        disclosure.manifest_digest = digest;
    }
    let error = construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures)
        .err()
        .unwrap();
    assert!(error.contains("ZIP317"));
    let mut f = fixture();
    let mut revised = f.proposal.input().clone();
    revised.manifest.inputs[0].amount = revised.manifest.inputs[0]
        .amount
        .checked_add(amount(1))
        .unwrap();
    revised.manifest.outputs[1].amount = revised.manifest.outputs[1]
        .amount
        .checked_add(amount(1))
        .unwrap();
    f.proposal = Proposal::validate(revised).unwrap();
    let digest: [u8; 32] = hex::decode(f.proposal.manifest_digest())
        .unwrap()
        .try_into()
        .unwrap();
    for disclosure in &mut f.disclosures {
        disclosure.manifest_digest = digest;
    }
    let error = construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures)
        .err()
        .unwrap();
    assert!(error.contains("input amount"));
}

#[test]
fn proving_rejects_wrong_binding_and_resource_budget_before_work() {
    use wholepact_protocol::proving::{ProvingLimits, prove_reviewed, verify_proved_candidate};
    let f = fixture();
    let built =
        construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).unwrap();
    for maximum_actions in [0, 4, 9, usize::MAX] {
        assert!(
            prove_reviewed(
                &built.pczt_bytes,
                &built.review_policy,
                built.economic_review.review_binding(),
                ProvingLimits { maximum_actions }
            )
            .is_err()
        );
    }
    assert!(
        prove_reviewed(
            &built.pczt_bytes,
            &built.review_policy,
            &"00".repeat(32),
            ProvingLimits { maximum_actions: 5 }
        )
        .is_err()
    );
    assert!(
        verify_proved_candidate(
            &built.pczt_bytes,
            &built.review_policy,
            built.economic_review.review_binding(),
            ProvingLimits { maximum_actions: 5 }
        )
        .is_err()
    );
}

#[test]
#[ignore = "Explicit expensive generic-construction Halo2 qualification"]
fn generic_constructed_three_owner_transaction_proves_signs_and_extracts() {
    use pczt::{
        Pczt,
        roles::{combiner::Combiner, signer::Signer, tx_extractor::TransactionExtractor},
    };
    let f = fixture();
    let built =
        construct_proposal(&f.proposal, f.context, f.contributions, &f.disclosures).unwrap();
    let p = Pczt::parse(&built.pczt_bytes).unwrap();
    let mut copies = Vec::new();
    for (owner, key) in f.keys.iter().take(3).enumerate() {
        let mut signer = Signer::new(p.clone()).unwrap();
        for input in built
            .review_policy
            .inputs
            .iter()
            .filter(|i| i.participant_index == owner)
        {
            signer
                .sign_ironwood(
                    UnwrapErr(SysRng),
                    input.action_index,
                    &orchard::keys::SpendAuthorizingKey::from(key),
                )
                .unwrap();
        }
        copies.push(signer.finish());
    }
    use wholepact_protocol::proving::{ProvingLimits, prove_reviewed, verify_proved_candidate};
    let limits = ProvingLimits { maximum_actions: 5 };
    let proved = prove_reviewed(
        &built.pczt_bytes,
        &built.review_policy,
        built.economic_review.review_binding(),
        limits,
    )
    .unwrap();
    assert!(proved.proof_verified);
    assert!(
        !proved.chain_validated
            && !proved.distribution_allowed
            && !proved.authorization_allowed
            && !proved.encrypted_checkpoint_created
    );
    verify_proved_candidate(
        &proved.pczt_bytes,
        &built.review_policy,
        built.economic_review.review_binding(),
        limits,
    )
    .unwrap();
    assert!(
        prove_reviewed(
            &proved.pczt_bytes,
            &built.review_policy,
            built.economic_review.review_binding(),
            limits
        )
        .is_err()
    );
    let proved_pczt = Pczt::parse(&proved.pczt_bytes).unwrap();
    let proof = proved_pczt.ironwood().zkproof().as_ref().unwrap();
    let offset = proved
        .pczt_bytes
        .windows(proof.len())
        .position(|w| w == proof)
        .unwrap();
    let mut tampered = proved.pczt_bytes.clone();
    tampered[offset + 100] ^= 1;
    // Proof authorizing bytes are not economic effects. Economic review remains
    // identical, but actual independent proof verification must reject the flip.
    assert_eq!(
        verify_review(&tampered, &built.review_policy)
            .unwrap()
            .review_binding(),
        built.economic_review.review_binding()
    );
    assert!(
        verify_proved_candidate(
            &tampered,
            &built.review_policy,
            built.economic_review.review_binding(),
            limits
        )
        .is_err()
    );
    copies.push(proved_pczt);
    let combined = Combiner::new(copies).combine().unwrap();
    let bytes = pczt::v2::Pczt::try_from(combined.clone())
        .unwrap()
        .serialize();
    assert_eq!(
        verify_review(&bytes, &built.review_policy)
            .unwrap()
            .review_binding(),
        built.economic_review.review_binding()
    );
    let tx = TransactionExtractor::new(combined)
        .extract(UnwrapErr(SysRng))
        .unwrap();
    let mut bytes = Vec::new();
    tx.write(&mut bytes).unwrap();
    assert!(!bytes.is_empty());
}

// Proof-free retirement construction. Synthetic source/ownership adapters below
// are deliberately not production signer identity or complete scan evidence.
type ResidualFixture = (
    wholepact_core::retirement::transfer::ResidualTransferProposal,
    FullViewingKey,
    ConstructionContext,
    Vec<OwnedContribution>,
    Vec<DisclosureAcknowledgement>,
);

fn residual_fixture(
    pool: wholepact_core::retirement::ShieldedReceiverPool,
    alias_destination: bool,
) -> ResidualFixture {
    use wholepact_core::records::ObservationWindow;
    use wholepact_core::retirement::*;
    let mut f = fixture();
    let source = f.contributions.remove(0);
    let destination_fvk = FullViewingKey::from(&f.keys[if alias_destination { 0 } else { 3 }]);
    let destination = UserControlledShieldedDestination {
        address: encode_testnet_receiver(&destination_fvk.address_at(8u32, Scope::External)),
        user_controlled_account_ref: "synthetic-destination-account".into(),
        network_profile_id: PROFILE_ID.into(),
        pool,
        ownership_source_ref: "synthetic-not-authenticated".into(),
        ownership_evidence_digest: "22".repeat(32),
    };
    struct SyntheticSource {
        view: AccountRecoveryView,
        destination: UserControlledShieldedDestination,
    }
    impl AccountRecoverySource for SyntheticSource {
        fn read_recovery_view(&mut self, _: &str) -> wholepact_core::Result<AccountRecoveryView> {
            Ok(self.view.clone())
        }
        fn verify_destination(
            &mut self,
            _: &ReclaimDestinationRequest,
            _: &str,
        ) -> wholepact_core::Result<UserControlledShieldedDestination> {
            Ok(self.destination.clone())
        }
        fn quote_residual_transfer(
            &mut self,
            view: &AccountRecoveryView,
            destination: &UserControlledShieldedDestination,
        ) -> wholepact_core::Result<ReclaimFeeQuote> {
            Ok(ReclaimFeeQuote {
                quote_ref: "synthetic-quote".into(),
                fee: amount(10_000),
                input_set_digest: reclaim_input_digest(&view.residual_inputs)?,
                destination_digest: reclaim_destination_digest(destination)?,
                expires_at: "2026-10-14T13:00:00Z".into(),
            })
        }
    }
    struct SyntheticReview;
    impl ReclaimReviewSource for SyntheticReview {
        fn review_reclaim(
            &mut self,
            p: &AccountRetirementPlan,
        ) -> wholepact_core::Result<ReclaimReviewDecision> {
            Ok(ReclaimReviewDecision::Accepted {
                plan_digest: p.digest().into(),
                review_record_ref: "synthetic-native-review".into(),
            })
        }
    }
    let inputs: Vec<_> = f
        .proposal
        .manifest()
        .inputs
        .iter()
        .filter(|i| i.account_id == source.account_id)
        .cloned()
        .collect();
    let mut adapter = SyntheticSource {
        view: AccountRecoveryView {
            account_id: source.account_id.clone(),
            network_profile_id: PROFILE_ID.into(),
            observed_at: "2026-10-14T12:00:00Z".into(),
            history: ExposureHistoryState::Reconciled {
                writer_authority_ref: "synthetic-writer".into(),
                journal_checkpoint_digest: "11".repeat(32),
                reconciliation_evidence_ref: "synthetic-history".into(),
            },
            revisions: vec![],
            local_reservation_input_ids: vec![],
            residual_inputs: inputs
                .iter()
                .map(|i| ResidualInput {
                    input_id: i.input_id.clone(),
                    amount: i.amount,
                    origin: ResidualFundOrigin::UnselectedFunds,
                })
                .collect(),
            viewing_key_disclosure_refs: vec![],
        },
        destination: destination.clone(),
    };
    let window = ObservationWindow {
        now: "2026-10-14T12:00:00Z".into(),
        oldest_acceptable: "2026-10-14T11:59:00Z".into(),
    };
    let plan = AccountRetirementPlan::prepare(
        &mut adapter,
        ReclaimRequest {
            plan_id: "synthetic-residual".into(),
            account_id: source.account_id.clone(),
            network_profile_id: PROFILE_ID.into(),
            destination: ReclaimDestinationRequest {
                address: destination.address.clone(),
                user_controlled_account_ref: destination.user_controlled_account_ref.clone(),
            },
            maximum_fee: amount(10_000),
            maximum_net_debit: amount(105_000),
        },
        &window,
    )
    .unwrap();
    let reviewed = plan
        .review_for_separate_authorization(&mut adapter, &mut SyntheticReview, &window)
        .unwrap();
    let mut input = f.proposal.input().clone();
    input.proposal_id = "synthetic-residual-candidate".into();
    input.manifest.participants.truncate(1);
    let owner = &mut input.manifest.participants[0];
    owner.contribution = amount(95_000);
    owner.fee_share = amount(10_000);
    owner.fee_cap = amount(10_000);
    owner.maximum_net_debit = amount(105_000);
    input.manifest.inputs = inputs;
    input.manifest.outputs.truncate(1);
    input.manifest.outputs[0].address = destination.address.clone();
    input.manifest.outputs[0].amount = amount(95_000);
    input.manifest.agreement.recipients[0].address = destination.address;
    input.manifest.agreement.recipients[0].amount = amount(95_000);
    input.manifest.agreement.recipients[0].memo = None;
    input.manifest.agreement.funding_policy = FundingPolicy::Exact {
        target: amount(95_000),
    };
    input.manifest.transaction_fee = amount(10_000);
    assert!(Proposal::validate(input.clone()).is_err());
    let proposal = transfer::ResidualTransferProposal::bind(&reviewed, input).unwrap();
    f.disclosures.truncate(1);
    f.disclosures[0].manifest_digest = hex::decode(proposal.manifest_digest())
        .unwrap()
        .try_into()
        .unwrap();
    f.disclosures[0].reviewer_account_ids = vec![source.account_id.clone()];
    (
        proposal,
        destination_fvk,
        f.context,
        vec![source],
        f.disclosures,
    )
}

#[test]
fn residual_unverified_constructor_is_exact_single_owner_and_never_authority() {
    let (proposal, fvk, context, sources, disclosures) = residual_fixture(
        wholepact_core::retirement::ShieldedReceiverPool::Ironwood,
        false,
    );
    let result =
        construct_residual_transfer_unverified(&proposal, &fvk, context, sources, &disclosures)
            .unwrap();
    assert_eq!(
        result.plan_digest(),
        proposal.reviewed_plan().plan().digest()
    );
    assert_eq!(result.local_review().fee_zatoshis(), 10_000);
    assert!(!result.private_unverified_pczt_bytes().is_empty());
    assert!(
        verify_review(
            result.private_unverified_pczt_bytes(),
            result.private_unverified_review_policy()
        )
        .is_err()
    );
    assert!(!result.destination_identity_authenticated());
    assert!(!result.authorization_allowed());
}

#[test]
fn residual_unverified_constructor_rejects_wrong_pool_owner_alias_and_disclosure() {
    use wholepact_core::retirement::ShieldedReceiverPool;
    let (proposal, fvk, context, sources, disclosures) =
        residual_fixture(ShieldedReceiverPool::Orchard, false);
    assert!(
        construct_residual_transfer_unverified(&proposal, &fvk, context, sources, &disclosures)
            .is_err()
    );
    let (proposal, _, context, sources, disclosures) =
        residual_fixture(ShieldedReceiverPool::Ironwood, false);
    let wrong_fvk = sources[0].fvk.clone();
    assert!(
        construct_residual_transfer_unverified(
            &proposal,
            &wrong_fvk,
            context,
            sources,
            &disclosures
        )
        .is_err()
    );
    let (proposal, fvk, context, sources, disclosures) =
        residual_fixture(ShieldedReceiverPool::Ironwood, true);
    assert!(
        construct_residual_transfer_unverified(&proposal, &fvk, context, sources, &disclosures)
            .is_err()
    );
    let (proposal, fvk, context, sources, mut disclosures) =
        residual_fixture(ShieldedReceiverPool::Ironwood, false);
    disclosures[0].manifest_digest = [0; 32];
    assert!(
        construct_residual_transfer_unverified(&proposal, &fvk, context, sources, &disclosures)
            .is_err()
    );
}
