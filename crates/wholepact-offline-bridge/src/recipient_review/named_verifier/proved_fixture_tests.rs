//! Private pre-lease kernel qualification only. Fixed public never-funded test
//! builder keys and fabricated notes/tree, in memory. The assertion key is freshly
//! generated in RAM for this test only and is never exported or persisted. Labels below identify fixture slots;
//! they establish neither real identities nor native disclosure consent. No lease,
//! owner setup, durable authorization, reservation, wallet, or network is created.
use super::*;
use crate::{NamedVerifierPackageV1, inspect_named_verifier_package};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use wholepact_authority::offline::{OfflineAuthoritySemantics, OfflineUnknownFact};
use wholepact_core::*;
use wholepact_protocol::{
    canonical_role_layout::{validate_canonical_layout, verify_layout_transformation},
    construction::PROFILE_ID,
    proving::prove_reviewed,
    review::{encode_testnet_receiver, verify_review},
    synthetic::review_fixture,
};
use zeroize::Zeroizing;

fn amount(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}
fn hash_bytes(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

// A complete accepted fixture manifest, retained before proof or assertion.
// All FVK associations originate in the closed maintained synthetic builder.
fn retained_fixture() -> (Vec<u8>, RetainedOfflineReviewInputs) {
    let f = review_fixture().unwrap();
    let mut policy = f.policy;
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
    let review = verify_review(&f.pczt_bytes, &policy).unwrap();
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
        artifact_digest: hash_bytes(&f.pczt_bytes),
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
    let retained = RetainedOfflineReviewInputs {
        terms,
        proposal,
        policy,
        input_actions,
        output_actions,
        maximum_actions: 8,
    };
    verify_manifest_policy(
        &retained.proposal,
        &retained.policy,
        &retained.input_actions,
        &retained.output_actions,
    )
    .unwrap();
    (f.pczt_bytes, retained)
}

fn request(retained: &RetainedOfflineReviewInputs) -> OriginalNamedVerifierRequest {
    OriginalNamedVerifierRequest {
        request_digest: hash_bytes(b"private fixture original request"),
        original_context_digest: named_verifier_original_context_digest(&retained.terms).unwrap(),
        validity_not_before_ms: 100_000,
        validity_expires_ms: 200_000,
    }
}

fn own_policy(policy: &ReviewPolicy, owner: usize) -> OwnEffectsPolicy {
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

// This counter observes the adapter's before-commit ordering only. Durable replay
// and crash recovery are exercised separately by the real SqliteOutbox tests.
#[derive(Default)]
struct AdmissionCounter(usize);
impl wholepact_transport::ReplayLedger for AdmissionCounter {
    fn accept_authenticated(
        &mut self,
        _receipt: &wholepact_transport::AuthenticatedReceipt,
        _envelope: &[u8],
    ) -> wholepact_transport::Result<()> {
        self.0 += 1;
        Ok(())
    }
}
fn encrypted_assertion_roundtrip(
    bytes: &[u8],
    original_terms: &OfflineAuthorizationTerms,
    recipient: &wholepact_transport::TransportSecret,
    policy: &OwnEffectsPolicy,
    key: &[u8; 32],
    expected: &NamedVerifierExpectedContext<'_>,
) {
    use wholepact_transport::*;
    let secret = || {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        SystemRandom::new().fill(bytes.as_mut()).unwrap();
        TransportSecret::from_bytes(*bytes).unwrap()
    };
    let sender = secret();
    let now = Timestamp::from_unix_seconds(150).unwrap();
    let context = MessageContext {
        network_profile_id: PROFILE_ID.into(),
        agreement_id: "fixture-agreement".into(),
        proposal_id: "fixture-proposal".into(),
        proposal_revision: 1,
        sender_id: hash_bytes(key),
        recipient_id: policy.account_id.clone(),
        artifact_kind: ArtifactKind::NamedVerifierAssertion,
    };
    let prepared = prepare_export(
        ExportRequest {
            context: context.clone(),
            order: MessageOrder {
                message_id: "12".repeat(16),
                sequence: 1,
                issued_at: Timestamp::from_unix_seconds(100).unwrap(),
                expires_at: Timestamp::from_unix_seconds(200).unwrap(),
            },
            purpose: "Synthetic evidence-only assertion".into(),
            persistence_warning: "Ephemeral fixture; no authority".into(),
        },
        vec![DisclosureField::new("named-verifier-assertion-v1", bytes.to_vec()).unwrap()],
        &sender.public_key().unwrap(),
        &recipient.public_key().unwrap(),
        &now,
    )
    .unwrap();
    let approved_digest = prepared.preview().digest().unwrap();
    let envelope = prepared.seal(&sender, &approved_digest, &now).unwrap();
    let expectation = crate::NamedVerifierEnvelopeExpectation {
        context: &context,
        original_terms,
        own_policy: policy,
        selected_verifier: key,
        assertion: expected,
    };
    let mut ledger = AdmissionCounter::default();
    let mut wrong_context = context.clone();
    wrong_context.proposal_revision += 1;
    let wrong_terms = crate::NamedVerifierEnvelopeExpectation {
        context: &wrong_context,
        original_terms,
        own_policy: policy,
        selected_verifier: key,
        assertion: expected,
    };
    assert!(
        crate::open_named_verifier_assertion(
            &envelope,
            recipient,
            &sender.public_key().unwrap(),
            &wrong_terms,
            &now,
            &mut ledger,
            || Ok(())
        )
        .is_err()
    );
    assert_eq!(ledger.0, 0);
    // Native cancellation and wrong verifier selection consume no inbox entry.
    assert!(
        crate::open_named_verifier_assertion(
            &envelope,
            recipient,
            &sender.public_key().unwrap(),
            &expectation,
            &now,
            &mut ledger,
            || Err(TransportError::DisclosureDenied)
        )
        .is_err()
    );
    assert_eq!(ledger.0, 0);
    let mut wrong_key = *key;
    wrong_key[0] ^= 1;
    let wrong = crate::NamedVerifierEnvelopeExpectation {
        selected_verifier: &wrong_key,
        ..expectation
    };
    assert!(
        crate::open_named_verifier_assertion(
            &envelope,
            recipient,
            &sender.public_key().unwrap(),
            &wrong,
            &now,
            &mut ledger,
            || Ok(())
        )
        .is_err()
    );
    assert_eq!(ledger.0, 0);
    let expectation = crate::NamedVerifierEnvelopeExpectation {
        selected_verifier: key,
        ..wrong
    };
    let result = crate::open_named_verifier_assertion(
        &envelope,
        recipient,
        &sender.public_key().unwrap(),
        &expectation,
        &now,
        &mut ledger,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(ledger.0, 1);
    assert_eq!(result.inspection().package_digest(), hash_bytes(bytes));
    assert_eq!(result.artifact().fields()[0].bytes(), bytes);
    let mut checks = 0;
    let mut cancelled_ledger = AdmissionCounter::default();
    assert!(
        crate::open_named_verifier_assertion(
            &envelope,
            recipient,
            &sender.public_key().unwrap(),
            &expectation,
            &now,
            &mut cancelled_ledger,
            || {
                checks += 1;
                if checks == 4 {
                    Err(TransportError::DisclosureDenied)
                } else {
                    Ok(())
                }
            }
        )
        .is_err()
    );
    // Cancellation after commit leaves exactly one accepted original; no success
    // report or rollback claim escapes, and no second effect is attempted here.
    assert_eq!(cancelled_ledger.0, 1);
    // The real receipt journal supports the exact committed-but-unavailable
    // recovery route. Its temporary fixture holds ciphertext, not a wallet.
    struct PrivateInbox(std::path::PathBuf);
    impl Drop for PrivateInbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let mut suffix = [0_u8; 16];
    SystemRandom::new().fill(&mut suffix).unwrap();
    let root = PrivateInbox(
        std::env::temp_dir().join(format!("wholepact-named-inbox-{}", hex::encode(suffix))),
    );
    std::fs::create_dir(&root.0).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = root.0.join("inbox.sqlite");
    let mut ledger = SqliteReplayLedger::open(&path).unwrap();
    let mut checks = 0;
    let result = crate::open_named_verifier_assertion(
        &envelope,
        recipient,
        &sender.public_key().unwrap(),
        &expectation,
        &now,
        &mut ledger,
        || {
            checks += 1;
            if checks == 4 {
                Err(TransportError::DisclosureDenied)
            } else {
                Ok(())
            }
        },
    );
    assert!(matches!(
        result,
        Err(TransportError::ImportCommittedButUnavailable)
    ));
    assert_eq!(ledger.record_count().unwrap(), 1);
    drop(ledger);
    let ledger = SqliteReplayLedger::open(&path).unwrap();
    let record = ledger.retained_for_context(&context, 1).unwrap().unwrap();
    let recovered = crate::recover_named_verifier_assertion(
        &record,
        recipient,
        &sender.public_key().unwrap(),
        &expectation,
        || Ok(()),
    )
    .unwrap();
    assert!(!recovered.is_new_delivery() && !recovered.authorization_allowed());
    assert_eq!(recovered.inspection().package_digest(), hash_bytes(bytes));
    assert_eq!(ledger.record_count().unwrap(), 1);
    drop(ledger);
    let removed = root.0.clone();
    drop(root);
    assert!(
        !removed.exists(),
        "temporary ciphertext fixture was not removed"
    );
}

#[test]
#[ignore = "expensive genuine Halo2 proof; explicit serialized execution only"]
fn proved_two_owner_named_verifier_private_kernel() {
    let (unproved, mut retained) = retained_fixture();
    let mut recipient_seed = Zeroizing::new([0_u8; 32]);
    SystemRandom::new().fill(recipient_seed.as_mut()).unwrap();
    let recipient = wholepact_transport::TransportSecret::from_bytes(*recipient_seed).unwrap();
    drop(recipient_seed);
    retained.terms.offline_signer_key_digest = recipient.public_key().unwrap().fingerprint();
    let mut seed = Zeroizing::new([0_u8; 32]);
    SystemRandom::new().fill(seed.as_mut()).unwrap();
    let pair = Ed25519KeyPair::from_seed_unchecked(seed.as_slice()).unwrap();
    drop(seed);
    let key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
    // Positive proof is mandatory, not a claimed proof flag or a signed DTO.
    assert!(
        prepare_named_verifier_assertion(&unproved, &retained, &request(&retained), &key).is_err()
    );
    let proved = prove_reviewed(
        &unproved,
        &retained.policy,
        &retained.terms.review_binding,
        ProvingLimits { maximum_actions: 8 },
    )
    .unwrap();
    assert!(proved.proof_verified && proved.proof_bytes > 0);
    assert!(
        !proved.chain_validated
            && !proved.authorization_allowed
            && !proved.distribution_allowed
            && !proved.encrypted_checkpoint_created
    );
    retained.terms.artifact_digest = hash_bytes(&proved.pczt_bytes);
    let original_request = request(&retained);
    let prepared =
        prepare_named_verifier_assertion(&proved.pczt_bytes, &retained, &original_request, &key)
            .unwrap();
    // The full review policy is already bound by the original review identity.
    // It is not permissible to reorder that immutable original on retry.
    retained.policy.inputs.reverse();
    retained.policy.outputs.reverse();
    assert!(
        prepare_named_verifier_assertion(&proved.pczt_bytes, &retained, &original_request, &key)
            .is_err()
    );
    retained.policy.inputs.reverse();
    retained.policy.outputs.reverse();
    // Untrusted action-map enumeration must not change manifest-ordered own
    // expectations. Repeat the real producer and maintained proof validation.
    retained.input_actions.reverse();
    retained.output_actions.reverse();
    let permuted =
        prepare_named_verifier_assertion(&proved.pczt_bytes, &retained, &original_request, &key)
            .unwrap();
    assert_eq!(
        permuted.signing_message().unwrap(),
        prepared.signing_message().unwrap()
    );
    assert_eq!(
        permuted.recipient_artifact().bytes(),
        prepared.recipient_artifact().bytes()
    );
    retained.input_actions.reverse();
    retained.output_actions.reverse();
    let statement = prepared.statement();
    let redacted = prepared.recipient_artifact().bytes();
    assert_ne!(redacted, proved.pczt_bytes.as_slice());
    validate_canonical_layout(redacted, &retained.policy).unwrap();
    let redacted_proof = verify_proved_candidate(
        redacted,
        &retained.policy,
        &retained.terms.review_binding,
        ProvingLimits { maximum_actions: 8 },
    )
    .unwrap();
    assert!(redacted_proof.proof_verified);
    assert_eq!(redacted_proof.proof_bytes, proved.proof_bytes);
    assert_eq!(
        redacted_proof.economic_review.review_binding(),
        proved.economic_review.review_binding()
    );
    assert_eq!(
        redacted_proof.economic_review.shielded_sighash(),
        proved.economic_review.shielded_sighash()
    );
    assert_eq!(
        redacted_proof.economic_review.net_debits_zatoshis(),
        proved.economic_review.net_debits_zatoshis()
    );
    let transformation =
        verify_layout_transformation(&proved.pczt_bytes, redacted, &retained.policy).unwrap();
    assert_eq!(
        statement.original_artifact_digest,
        hash_bytes(&proved.pczt_bytes)
    );
    assert_eq!(statement.recipient_artifact_digest, hash_bytes(redacted));
    assert_eq!(
        statement.transformation_commitment,
        transformation.commitment()
    );
    assert_eq!(statement.inputs.len(), retained.policy.inputs.len());
    assert_eq!(statement.outputs.len(), retained.policy.outputs.len());
    assert_eq!(statement.participants.len(), 2);
    for input in &retained.policy.inputs {
        let asserted = statement
            .inputs
            .iter()
            .find(|i| i.action_index as usize == input.action_index)
            .unwrap();
        assert_eq!(asserted.participant_index as usize, input.participant_index);
        assert_eq!(asserted.nullifier, hex::encode(input.nullifier));
        assert_eq!(asserted.value_zatoshis, input.value_zatoshis);
    }
    for output in &retained.policy.outputs {
        let asserted = statement
            .outputs
            .iter()
            .find(|o| o.action_index as usize == output.action_index)
            .unwrap();
        assert_eq!(
            asserted.return_participant_index,
            match output.purpose {
                OutputPurpose::Recipient => None,
                OutputPurpose::Return { participant_index } => Some(participant_index as u32),
            }
        );
        assert_eq!(
            asserted.receiver,
            hex::encode(output.receiver.to_raw_address_bytes())
        );
        assert_eq!(asserted.value_zatoshis, output.value_zatoshis);
        assert_eq!(asserted.memo_digest, hash_bytes(&output.memo));
    }
    for owner in 0..2 {
        let own = verify_own_effects(redacted, &own_policy(&retained.policy, owner)).unwrap();
        let allocation = &statement.participants[owner];
        assert_eq!(allocation.selected_own_policy_digest, own.policy_digest());
        assert_eq!(own.selected_net_debit_zatoshis(), [105_000, 210_000][owner]);
        assert_eq!(own.transaction_fee_zatoshis(), 15_000);
        assert_eq!(own.own_return_zatoshis(), [95_000, 90_000][owner]);
        assert_eq!(own.shielded_sighash(), retained.terms.effects_digest);
        assert_eq!(allocation.contribution_zatoshis, [100_000, 200_000][owner]);
        assert_eq!(allocation.fee_share_zatoshis, [5_000, 10_000][owner]);
        assert_eq!(allocation.maximum_debit_zatoshis, [105_000, 210_000][owner]);
    }
    let own = verify_own_effects(redacted, &own_policy(&retained.policy, 0)).unwrap();
    let expected = NamedVerifierExpectedContext {
        original_artifact_digest: &retained.terms.artifact_digest,
        transformation_commitment: transformation.commitment(),
        manifest_digest: &retained.terms.manifest_digest,
        original_context_digest: &original_request.original_context_digest,
        original_request_digest: &original_request.request_digest,
        validity_not_before_ms: original_request.validity_not_before_ms,
        validity_expires_ms: original_request.validity_expires_ms,
        transaction_expiry_height: retained.policy.expiry_height,
        own_account_id: &retained.terms.account_id,
    };
    let signature = pair.sign(&prepared.signing_message().unwrap());
    verify_named_verifier_signature_evidence(
        &statement.canonical_bytes().unwrap(),
        signature.as_ref(),
        &key,
        &expected,
        &own,
    )
    .unwrap();
    let package = NamedVerifierPackageV1 {
        schema_version: 1,
        statement: statement.clone(),
        signature: signature.as_ref().to_vec(),
        recipient_artifact: redacted.to_vec(),
    };
    let package_bytes = package.canonical_bytes().unwrap();
    assert_eq!(
        NamedVerifierPackageV1::parse(&package_bytes)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        package_bytes
    );
    let selected_policy = own_policy(&retained.policy, 0);
    encrypted_assertion_roundtrip(
        &package_bytes,
        &retained.terms,
        &recipient,
        &selected_policy,
        &key,
        &expected,
    );
    let inspected =
        inspect_named_verifier_package(&package_bytes, &selected_policy, &key, &expected).unwrap();
    assert_eq!(inspected.package_digest(), hash_bytes(&package_bytes));
    assert_eq!(
        inspected.own().inspection().policy_digest(),
        own.policy_digest()
    );
    assert!(
        inspect_named_verifier_package(&package_bytes, &selected_policy, &[78; 32], &expected)
            .is_err()
    );
    let wrong_request = hash_bytes(b"different request");
    let wrong_context = NamedVerifierExpectedContext {
        original_request_digest: &wrong_request,
        ..expected
    };
    assert!(
        inspect_named_verifier_package(&package_bytes, &selected_policy, &key, &wrong_context)
            .is_err()
    );
    let mut changed = package;
    // Even a genuine signature cannot override independently retained own effects.
    changed.statement.participants[0].contribution_zatoshis += 1;
    changed.statement.participants[0].fee_share_zatoshis -= 1;
    changed.statement.participants[1].contribution_zatoshis -= 1;
    changed.statement.participants[1].fee_share_zatoshis += 1;
    // Preserve all total and per-owner arithmetic, so this reaches independent
    // own-policy checking rather than being rejected as a malformed statement.
    changed.statement.validate().unwrap();
    changed.signature = pair
        .sign(&changed.statement.signing_message().unwrap())
        .as_ref()
        .to_vec();
    let changed_bytes = changed.canonical_bytes().unwrap();
    let exact_context = NamedVerifierExpectedContext {
        original_request_digest: &original_request.request_digest,
        ..wrong_context
    };
    assert!(
        inspect_named_verifier_package(&changed_bytes, &selected_policy, &key, &exact_context)
            .is_err()
    );
    retained.policy.participants[0].contribution_zatoshis += 1;
    assert!(
        prepare_named_verifier_assertion(&proved.pczt_bytes, &retained, &original_request, &key)
            .is_err()
    );
    retained.policy.participants[0].contribution_zatoshis -= 1;
    // Same labels with wrong cryptographic ownership must fail. This never calls
    // from_current_policy_leases and must not be described as lease qualification.
    let saved = retained.policy.participants[0].fvk.clone();
    retained.policy.participants[0].fvk = retained.policy.participants[1].fvk.clone();
    assert!(
        prepare_named_verifier_assertion(&proved.pczt_bytes, &retained, &original_request, &key)
            .is_err()
    );
    retained.policy.participants[0].fvk = saved;
    let input = retained.input_actions.pop().unwrap();
    assert!(
        prepare_named_verifier_assertion(&proved.pczt_bytes, &retained, &original_request, &key)
            .is_err()
    );
    retained.input_actions.push(input);
    retained.output_actions.pop();
    assert!(
        prepare_named_verifier_assertion(&proved.pczt_bytes, &retained, &original_request, &key)
            .is_err()
    );
}
