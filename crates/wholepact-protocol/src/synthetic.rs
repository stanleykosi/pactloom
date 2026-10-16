//! Real-cryptography qualification with synthetic notes, keys and commitment tree.
//!
//! This module cannot load wallets, accept caller notes/keys, or reach a network.
//! All owners coexist inside the test process, so process isolation is NOT tested.

use orchard::{
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::IronwoodDomain,
    tree::MerkleHashOrchard,
};
use pczt::{
    Pczt,
    roles::{
        combiner::Combiner, creator::Creator, io_finalizer::IoFinalizer, prover::Prover,
        redactor::Redactor, signer::Signer, tx_extractor::TransactionExtractor, updater::Updater,
        verifier::Verifier,
    },
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde::Serialize;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis};

#[derive(Debug, Serialize)]
pub struct QualificationReport {
    pub evidence_kind: &'static str,
    pub profile: &'static str,
    pub consensus_branch_id: &'static str,
    pub dependency_baseline: &'static str,
    pub independent_synthetic_spending_keys: usize,
    pub pczt_version: u32,
    pub transaction_version: u32,
    pub ironwood_actions: usize,
    pub recipient_zatoshis: u64,
    pub fee_zatoshis: u64,
    pub participant_net_debits_zatoshis: [u64; 2],
    pub real_halo2_proof_verified: bool,
    pub both_spend_authorizations_verified: bool,
    pub missing_signature_rejected: bool,
    pub wrong_owner_key_rejected: bool,
    pub invalid_external_signature_rejected: bool,
    pub incompatible_combination_rejected: bool,
    pub v6_anchor_excluded_from_sighash_demonstrated: bool,
    pub recipients_decrypted_exact_outputs: bool,
    pub economic_review_passed: bool,
    pub review_binding_survives_proof_and_signature_additions: bool,
    pub transaction_bytes_created: usize,
    pub network_operations: usize,
    pub settlement_verified: bool,
    pub production_policy_qualified: bool,
    pub elapsed_millis: u128,
}

fn require(value: bool, message: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.into()) }
}

fn network() -> zcash_protocol::local_consensus::LocalNetwork {
    zcash_protocol::local_consensus::LocalNetwork {
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
    }
}

struct Fixture {
    pczt: Pczt,
    spend_indices: [usize; 2],
    output_indices: [usize; 3],
    keys: [SpendAuthorizingKey; 2],
    fvks: [FullViewingKey; 3],
}

fn review_policy(f: &Fixture) -> crate::review::ReviewPolicy {
    use crate::review::{
        InputPolicy, OutputPolicy, OutputPurpose, ParticipantPolicy, ReviewPolicy,
    };
    ReviewPolicy {
        manifest_digest: [42; 32],
        participants: (0..2)
            .map(|i| ParticipantPolicy {
                account_id: format!("synthetic-owner-{i}"),
                fvk: f.fvks[i].clone(),
                contribution_zatoshis: [100_000, 200_000][i],
                fee_share_zatoshis: [5_000, 10_000][i],
                maximum_net_debit_zatoshis: [105_000, 210_000][i],
            })
            .collect(),
        inputs: (0..2)
            .map(|i| InputPolicy {
                action_index: f.spend_indices[i],
                participant_index: i,
                nullifier: *f.pczt.ironwood().actions()[f.spend_indices[i]]
                    .spend()
                    .nullifier(),
                value_zatoshis: [200_000, 300_000][i],
            })
            .collect(),
        outputs: [
            (2, Scope::External, 300_000),
            (0, Scope::Internal, 95_000),
            (1, Scope::Internal, 90_000),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, (owner, scope, value))| OutputPolicy {
            action_index: f.output_indices[i],
            receiver: f.fvks[owner].address_at(0_u32, scope),
            value_zatoshis: value,
            memo: MemoBytes::empty().into_bytes(),
            purpose: if i == 0 {
                OutputPurpose::Recipient
            } else {
                OutputPurpose::Return {
                    participant_index: owner,
                }
            },
        })
        .collect(),
        exact_fee_zatoshis: 15_000,
        expiry_height: *f.pczt.global().expiry_height(),
        anchor: f.pczt.ironwood().anchor().unwrap(),
    }
}

fn encode(p: &Pczt) -> Vec<u8> {
    pczt::v2::Pczt::try_from(p.clone()).unwrap().serialize()
}

/// Public, deterministic, never-funded TEST keys. Do not use for any wallet.
pub const TEST_OWNER_SPENDING_KEY_BYTES: [[u8; 32]; 2] = [[1; 32], [2; 32]];

/// Test-only construction material for companion process integration tests.
/// The policy is trusted only because all inputs are fabricated by this module.
pub struct SyntheticReviewFixture {
    pub pczt_bytes: Vec<u8>,
    pub policy: crate::review::ReviewPolicy,
}

pub fn review_fixture() -> Result<SyntheticReviewFixture, String> {
    let f = fixture()?;
    Ok(SyntheticReviewFixture {
        pczt_bytes: encode(&f.pczt),
        policy: review_policy(&f),
    })
}

/// Fixed never-funded high-height fixture for controlled submission-journal tests.
/// Uses the same fabricated keys/notes; no network or user material is accepted.
/// Height compatibility does not turn the synthetic tree into real chain evidence.
pub fn review_fixture_for_submission() -> Result<SyntheticReviewFixture, String> {
    let f = fixture_at_heights(4_498_145, 4_498_185)?;
    Ok(SyntheticReviewFixture {
        pczt_bytes: encode(&f.pczt),
        policy: review_policy(&f),
    })
}

/// Reconstruct only this module's fixed synthetic test policy in a child process.
/// Never use this function to infer approval or ownership for real funds.
pub fn policy_for_fixture_pczt(bytes: &[u8]) -> Result<crate::review::ReviewPolicy, String> {
    crate::inspect_candidate(bytes)?;
    let pczt = Pczt::parse(bytes).map_err(|e| format!("Synthetic PCZT: {e}"))?;
    let sks = [1_u8, 2, 3].map(|b| SpendingKey::from_bytes([b; 32]).unwrap());
    let fvks = sks.each_ref().map(FullViewingKey::from);
    let mut spend_indices = [usize::MAX; 2];
    let mut output_indices = [usize::MAX; 3];
    Verifier::new(pczt.clone())
        .with_ironwood::<String, _>(|bundle| {
            for (index, action) in bundle.actions().iter().enumerate() {
                for owner in 0..2 {
                    if action
                        .spend()
                        .value()
                        .is_some_and(|value| value.inner() > 0)
                        && action.spend().verify_nullifier(Some(&fvks[owner])).is_ok()
                        && action.spend().verify_rk(Some(&fvks[owner])).is_ok()
                    {
                        require(
                            spend_indices[owner] == usize::MAX,
                            "Duplicate synthetic owner input",
                        )
                        .map_err(pczt::roles::verifier::OrchardError::Custom)?;
                        spend_indices[owner] = index;
                    }
                }
            }
            Ok(())
        })
        .map_err(|e| format!("Synthetic ownership: {e:?}"))?;
    for (index, action) in pczt.ironwood().actions().iter().enumerate() {
        for (slot, (owner, scope)) in [
            (2, Scope::External),
            (0, Scope::Internal),
            (1, Scope::Internal),
        ]
        .into_iter()
        .enumerate()
        {
            if *action.output().recipient()
                == Some(fvks[owner].address_at(0_u32, scope).to_raw_address_bytes())
            {
                require(
                    output_indices[slot] == usize::MAX,
                    "Duplicate synthetic output",
                )?;
                output_indices[slot] = index;
            }
        }
    }
    require(
        !spend_indices.contains(&usize::MAX) && !output_indices.contains(&usize::MAX),
        "Synthetic fixture allocations missing",
    )?;
    let f = Fixture {
        pczt,
        spend_indices,
        output_indices,
        keys: [
            SpendAuthorizingKey::from(&sks[0]),
            SpendAuthorizingKey::from(&sks[1]),
        ],
        fvks,
    };
    let policy = review_policy(&f);
    crate::review::verify_review(bytes, &policy)?;
    Ok(policy)
}

/// Test-only, inexpensive validation of independently signed fixture copies.
/// Requires every real owner signature and preserves the frozen economic binding.
/// Returns the combined PCZT; it does not generate/verify a proof or claim settlement.
pub fn combine_verify_authorizations(copies: &[&[u8]]) -> Result<Vec<u8>, String> {
    require(
        !copies.is_empty() && copies.len() <= 8,
        "Expected 1..=8 synthetic copies",
    )?;
    let mut parsed = Vec::new();
    let mut binding = None;
    for bytes in copies {
        let policy = policy_for_fixture_pczt(bytes)?;
        let review = crate::review::verify_review(bytes, &policy)?;
        if let Some(expected) = &binding {
            require(
                expected == review.review_binding(),
                "Fixture copies changed review binding",
            )?;
        } else {
            binding = Some(review.review_binding().to_owned());
        }
        parsed.push(Pczt::parse(bytes).map_err(|e| format!("Fixture parse: {e}"))?);
    }
    let combined = Combiner::new(parsed)
        .combine()
        .map_err(|e| format!("Fixture combination: {e:?}"))?;
    let policy = policy_for_fixture_pczt(&encode(&combined))?;
    let mut verifier =
        Signer::new(combined.clone()).map_err(|e| format!("Fixture signer validation: {e:?}"))?;
    for input in policy.inputs {
        let signature = combined.ironwood().actions()[input.action_index]
            .spend()
            .spend_auth_sig()
            .ok_or("Missing real fixture owner signature")?;
        verifier
            .apply_ironwood_signature(input.action_index, signature.into())
            .map_err(|e| format!("Invalid fixture owner signature: {e:?}"))?;
    }
    Ok(encode(&verifier.finish()))
}

fn fixture() -> Result<Fixture, String> {
    fixture_at_heights(100, 140)
}

fn fixture_at_heights(target_height: u32, expiry_height: u32) -> Result<Fixture, String> {
    // Public deterministic test bytes; these are never funded or persisted as a vault.
    let sks = [1_u8, 2, 3].map(|b| SpendingKey::from_bytes([b; 32]).unwrap());
    let fvks = sks.each_ref().map(FullViewingKey::from);
    let keys = [
        SpendAuthorizingKey::from(&sks[0]),
        SpendAuthorizingKey::from(&sks[1]),
    ];
    let version = orchard::bundle::BundleVersion::ironwood_v3();
    let mut incoming = orchard::builder::Builder::new(
        orchard::builder::BundleType::DEFAULT,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .map_err(|e| format!("Synthetic incoming builder: {e:?}"))?;
    for (fvk, value) in fvks.iter().take(2).zip([200_000, 300_000]) {
        incoming
            .add_output(
                None,
                fvk.address_at(0_u32, Scope::External),
                orchard::value::NoteValue::from_raw(value),
                MemoBytes::empty().into_bytes(),
            )
            .map_err(|e| format!("Synthetic incoming output: {e:?}"))?;
    }
    // These notes have no chain history: this builds note objects, NOT funded inputs.
    let (bundle, incoming_meta) = incoming
        .build::<i64>(UnwrapErr(SysRng))
        .map_err(|e| format!("Synthetic incoming notes: {e:?}"))?
        .ok_or("Synthetic incoming bundle missing")?;
    let mut notes = Vec::new();
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    for (i, fvk) in fvks.iter().take(2).enumerate() {
        let action = &bundle.actions()[incoming_meta.output_action_index(i).unwrap()];
        let domain = IronwoodDomain::for_action(action);
        let (note, _, _) =
            try_note_decryption(&domain, &fvk.to_ivk(Scope::External).prepare(), action)
                .ok_or("Synthetic incoming note failed recipient decryption")?;
        require(
            note.version() == orchard::note::NoteVersion::V3,
            "Expected Ironwood note v3",
        )?;
        let cmx: ExtractedNoteCommitment = note.commitment().into();
        tree.append(
            MerkleHashOrchard::from_cmx(&cmx),
            incrementalmerkletree::Retention::Marked,
        )
        .map_err(|e| format!("Synthetic tree append: {e:?}"))?;
        notes.push(note);
    }
    tree.checkpoint(99)
        .map_err(|e| format!("Synthetic checkpoint: {e:?}"))?;
    let paths: Vec<orchard::tree::MerklePath> = (0_u64..2)
        .map(|i| {
            tree.witness_at_checkpoint_depth(i.into(), 0)
                .map_err(|e| format!("Synthetic witness: {e:?}"))?
                .map(Into::into)
                .ok_or("Missing synthetic witness".into())
        })
        .collect::<Result<_, String>>()?;
    let cmx: ExtractedNoteCommitment = notes[0].commitment().into();
    let anchor = paths[0].root(cmx);
    let mut builder = Builder::new(
        network(),
        target_height.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    )
    .with_expiry_height(expiry_height.into());
    for ((fvk, note), path) in fvks.iter().take(2).zip(notes).zip(paths) {
        builder
            .add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, path)
            .map_err(|e| format!("Independent synthetic spend: {e:?}"))?;
    }
    // Exact economic terms: A contributes 100000+5000 fee, B 200000+10000 fee.
    for (owner, scope, value) in [
        (2, Scope::External, 300_000),
        (0, Scope::Internal, 95_000),
        (1, Scope::Internal, 90_000),
    ] {
        builder
            .add_ironwood_output::<zip317::FeeRule>(
                Some(fvks[owner].to_ovk(scope)),
                fvks[owner].address_at(0_u32, scope),
                Zatoshis::from_u64(value).map_err(|e| format!("Amount: {e:?}"))?,
                MemoBytes::empty(),
            )
            .map_err(|e| format!("Synthetic output: {e:?}"))?;
    }
    let PcztResult {
        pczt_parts,
        ironwood_meta,
        ..
    } = builder
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .map_err(|e| format!("Build PCZT: {e:?}"))?;
    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).ok_or("Unsupported parts")?)
        .finalize_io(UnwrapErr(SysRng))
        .map_err(|e| format!("Finalize IO: {e:?}"))?;
    Ok(Fixture {
        pczt,
        spend_indices: [
            ironwood_meta.spend_action_index(0).unwrap(),
            ironwood_meta.spend_action_index(1).unwrap(),
        ],
        output_indices: [
            ironwood_meta.output_action_index(0).unwrap(),
            ironwood_meta.output_action_index(1).unwrap(),
            ironwood_meta.output_action_index(2).unwrap(),
        ],
        keys,
        fvks,
    })
}

fn verify_fixture(f: &Fixture) -> Result<(), String> {
    // This closed fixture knows every party's FVK. Production privacy/policy design
    // needs scoped disclosure and identity evidence, not this privileged test setup.
    Verifier::new(f.pczt.clone())
        .with_ironwood::<String, _>(|bundle| {
            let custom = pczt::roles::verifier::OrchardError::Custom;
            bundle.verify_cross_address_restriction()?;
            for (i, action) in bundle.actions().iter().enumerate() {
                action.verify_cv_net()?;
                action.output().verify_note_commitment(action.spend())?;
                let expected_fvk = f
                    .spend_indices
                    .iter()
                    .position(|index| *index == i)
                    .map(|owner| &f.fvks[owner]);
                action.spend().verify_nullifier(expected_fvk)?;
                action.spend().verify_rk(expected_fvk)?;
                if expected_fvk.is_none() {
                    require(
                        action.spend().value().is_some_and(|v| v.inner() == 0),
                        "Unassigned real input",
                    )
                    .map_err(custom)?;
                }
            }
            for (slot, (owner, scope, value)) in [
                (2, Scope::External, 300_000),
                (0, Scope::Internal, 95_000),
                (1, Scope::Internal, 90_000),
            ]
            .into_iter()
            .enumerate()
            {
                let action = &bundle.actions()[f.output_indices[slot]];
                let expected_address = f.fvks[owner].address_at(0_u32, scope);
                require(
                    *action.output().recipient() == Some(expected_address),
                    "Incorrect output recipient",
                )
                .map_err(custom)?;
                require(
                    action.output().value().is_some_and(|v| v.inner() == value),
                    "Incorrect output value",
                )
                .map_err(custom)?;
                require(
                    f.fvks[owner].scope_for_address(&expected_address) == Some(scope),
                    "Output ownership mismatch",
                )
                .map_err(custom)?;
                let domain = IronwoodDomain::for_pczt_action(action);
                let (note, address, memo) =
                    try_note_decryption(&domain, &f.fvks[owner].to_ivk(scope).prepare(), action)
                        .ok_or_else(|| custom("Output ciphertext not receivable".into()))?;
                require(
                    note.value().inner() == value
                        && address == expected_address
                        && memo == MemoBytes::empty().into_bytes(),
                    "Decrypted output differs from exact terms",
                )
                .map_err(custom)?;
            }
            Ok(())
        })
        .map_err(|e| format!("Synthetic full witness verification: {e:?}"))?;
    Ok(())
}

/// Runs one bounded in-memory qualification. No transaction is sent anywhere.
pub fn run_two_owner_fixture() -> Result<QualificationReport, String> {
    let started = std::time::Instant::now();
    let f = fixture()?;
    verify_fixture(&f)?;
    let policy = review_policy(&f);
    let review = crate::review::verify_review(&encode(&f.pczt), &policy)?;
    let encoded = pczt::v2::Pczt::try_from(f.pczt.clone())
        .map_err(|e| format!("Encode v2: {e:?}"))?
        .serialize();
    let inspected = crate::inspect_candidate(&encoded)?;
    let pczt = Pczt::parse(&encoded).map_err(|e| format!("Roundtrip: {e:?}"))?;
    require(
        !inspected.policy_verified && !inspected.chain_validated,
        "Structural inspection overclaimed assurance",
    )?;
    let mut wrong_owner = Signer::new(pczt.clone()).map_err(|e| format!("Signer: {e:?}"))?;
    require(
        wrong_owner
            .sign_ironwood(UnwrapErr(SysRng), f.spend_indices[0], &f.keys[1])
            .is_err(),
        "Wrong owner key was accepted",
    )?;
    require(
        wrong_owner
            .apply_ironwood_signature(f.spend_indices[0], [0_u8; 64].into())
            .is_err(),
        "Invalid external signature accepted",
    )?;

    let sighash = Signer::new(pczt.clone())
        .map_err(|e| format!("Sighash: {e:?}"))?
        .shielded_sighash();
    let reanchored = Updater::new(
        Redactor::new(pczt.clone())
            .redact_ironwood_with(|mut r| r.clear_anchor())
            .finish(),
    )
    .set_ironwood_anchor(orchard::Anchor::empty_tree())
    .map_err(|e| format!("Re-anchor fixture: {e:?}"))?
    .finish();
    require(
        Signer::new(reanchored)
            .map_err(|e| format!("Re-anchor sighash: {e:?}"))?
            .shielded_sighash()
            == sighash,
        "Unexpected v6 anchor signature commitment",
    )?;
    let other = fixture()?;
    require(
        Combiner::new(vec![pczt.clone(), other.pczt])
            .combine()
            .is_err(),
        "Different transactions combined",
    )?;

    let key =
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let proved = Prover::new(pczt.clone())
        .create_ironwood_proof(UnwrapErr(SysRng), &key)
        .map_err(|e| format!("Real Ironwood Halo2 proof: {e:?}"))?
        .finish();
    // Each owner signs an independent copy of the SAME frozen effects.
    let mut a = Signer::new(pczt.clone()).map_err(|e| format!("Owner A signer: {e:?}"))?;
    a.sign_ironwood(UnwrapErr(SysRng), f.spend_indices[0], &f.keys[0])
        .map_err(|e| format!("Owner A signature: {e:?}"))?;
    let a_signed = a.finish();
    let partial = Combiner::new(vec![proved.clone(), a_signed.clone()])
        .combine()
        .map_err(|e| format!("Partial combine: {e:?}"))?;
    require(
        TransactionExtractor::new(partial)
            .extract(UnwrapErr(SysRng))
            .is_err(),
        "Missing real signature allowed extraction",
    )?;
    let mut b = Signer::new(pczt).map_err(|e| format!("Owner B signer: {e:?}"))?;
    b.sign_ironwood(UnwrapErr(SysRng), f.spend_indices[1], &f.keys[1])
        .map_err(|e| format!("Owner B signature: {e:?}"))?;
    let completed = Combiner::new(vec![proved, a_signed, b.finish()])
        .combine()
        .map_err(|e| format!("Combine authorizations: {e:?}"))?;
    let completed_review = crate::review::verify_review(&encode(&completed), &policy)?;
    require(
        review.review_binding() == completed_review.review_binding(),
        "Proof/signature additions altered economic review binding",
    )?;
    let tx = TransactionExtractor::new(completed)
        .extract(UnwrapErr(SysRng))
        .map_err(|e| format!("Verify and extract: {e:?}"))?;
    require(
        tx.transparent_bundle().is_none()
            && tx.sapling_bundle().is_none()
            && tx.orchard_bundle().is_none(),
        "Unexpected transaction pool",
    )?;
    let ironwood = tx.ironwood_bundle().ok_or("Ironwood bundle missing")?;
    // Recipient and owners independently decrypt the resulting transaction.
    for (owner, scope, value) in [
        (2, Scope::External, 300_000),
        (0, Scope::Internal, 95_000),
        (1, Scope::Internal, 90_000),
    ] {
        let received: Vec<_> = ironwood
            .actions()
            .iter()
            .filter_map(|action| {
                try_note_decryption(
                    &IronwoodDomain::for_action(action),
                    &f.fvks[owner].to_ivk(scope).prepare(),
                    action,
                )
            })
            .collect();
        require(
            received.len() == 1 && received[0].0.value().inner() == value,
            "Final transaction recipient decryption failed",
        )?;
    }
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| format!("Transaction encoding: {e:?}"))?;
    #[cfg(feature = "transaction-checkpoint")]
    crate::recipient_local::qualify_existing_synthetic_transaction(
        &raw,
        &f.fvks[2],
        crate::review::encode_testnet_receiver(&f.fvks[2].address_at(0u32, Scope::External)),
        300_000,
    )?;
    Ok(QualificationReport {
        evidence_kind: "real-cryptography-over-synthetic-local-tree-no-chain",
        profile: "ironwood-testnet-nu7-candidate-local-consensus-fixture",
        consensus_branch_id: "0x77190ad9",
        dependency_baseline: "pczt=0.10.0-pre.1;orchard=0.16.0;zcash_primitives=0.31.0-pre.1;zcash_protocol=0.11.0-pre.0",
        independent_synthetic_spending_keys: 2,
        pczt_version: 2,
        transaction_version: 6,
        ironwood_actions: ironwood.actions().len(),
        recipient_zatoshis: 300_000,
        fee_zatoshis: 15_000,
        participant_net_debits_zatoshis: [105_000, 210_000],
        real_halo2_proof_verified: true,
        both_spend_authorizations_verified: true,
        missing_signature_rejected: true,
        wrong_owner_key_rejected: true,
        invalid_external_signature_rejected: true,
        incompatible_combination_rejected: true,
        v6_anchor_excluded_from_sighash_demonstrated: true,
        recipients_decrypted_exact_outputs: true,
        economic_review_passed: true,
        review_binding_survives_proof_and_signature_additions: true,
        transaction_bytes_created: raw.len(),
        network_operations: 0,
        settlement_verified: false,
        production_policy_qualified: false,
        elapsed_millis: started.elapsed().as_millis(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::verify_review;

    #[test]
    fn process_fixture_helpers_verify_all_real_authorizations() {
        let f = fixture().unwrap();
        let bytes = encode(&f.pczt);
        let rebuilt = policy_for_fixture_pczt(&bytes).unwrap();
        assert_eq!(
            verify_review(&bytes, &rebuilt).unwrap().review_binding(),
            verify_review(&bytes, &review_policy(&f))
                .unwrap()
                .review_binding()
        );
        assert!(combine_verify_authorizations(&[&bytes]).is_err());
        let mut copies = Vec::new();
        for owner in 0..2 {
            let mut signer = Signer::new(f.pczt.clone()).unwrap();
            signer
                .sign_ironwood(UnwrapErr(SysRng), f.spend_indices[owner], &f.keys[owner])
                .unwrap();
            copies.push(encode(&signer.finish()));
        }
        assert!(combine_verify_authorizations(&[&copies[0]]).is_err());
        let combined = combine_verify_authorizations(&[&copies[0], &copies[1]]).unwrap();
        assert_eq!(
            verify_review(&combined, &rebuilt).unwrap().review_binding(),
            verify_review(&bytes, &rebuilt).unwrap().review_binding()
        );
    }

    #[test]
    fn address_decoder_rejects_mainnet_and_missing_receiver() {
        use zcash_address::unified::{self, Encoding, Receiver, Uitem};
        use zcash_protocol::{address::Revision, consensus::NetworkType};
        let f = fixture().unwrap();
        let receiver = f.fvks[2].address_at(0_u32, Scope::External);
        let ua = unified::Address::try_from_items(
            Revision::R0,
            vec![Uitem::Data(Receiver::Orchard(
                receiver.to_raw_address_bytes(),
            ))],
        )
        .unwrap();
        assert_eq!(
            crate::review::decode_testnet_receiver(&ua.encode(&NetworkType::Test)).unwrap(),
            receiver
        );
        assert!(crate::review::decode_testnet_receiver(&ua.encode(&NetworkType::Main)).is_err());
        assert!(crate::review::decode_testnet_receiver("not an address").is_err());
        let ua = unified::Address::try_from_items(
            Revision::R0,
            vec![Uitem::Data(Receiver::Sapling([1; 43]))],
        )
        .unwrap();
        assert!(crate::review::decode_testnet_receiver(&ua.encode(&NetworkType::Test)).is_err());
    }

    #[test]
    fn economic_review_rejects_changed_terms_and_ownership() {
        let f = fixture().unwrap();
        let bytes = encode(&f.pczt);
        let p = review_policy(&f);
        let valid = verify_review(&bytes, &p).unwrap();
        assert_eq!(valid.net_debits_zatoshis(), &[105_000, 210_000]);
        let mut wrong = p.clone();
        wrong.outputs[0].receiver = f.fvks[0].address_at(0_u32, Scope::External);
        assert!(verify_review(&bytes, &wrong).is_err());
        let mut wrong = p.clone();
        wrong.outputs[1].purpose = crate::review::OutputPurpose::Return {
            participant_index: 1,
        };
        assert!(verify_review(&bytes, &wrong).is_err());
        let mut wrong = p.clone();
        wrong.participants[0].maximum_net_debit_zatoshis = 104_999;
        assert!(verify_review(&bytes, &wrong).is_err());
        let mut wrong = p.clone();
        wrong.exact_fee_zatoshis += 1;
        assert!(verify_review(&bytes, &wrong).is_err());
        let mut wrong = p.clone();
        wrong.inputs.pop();
        assert!(verify_review(&bytes, &wrong).is_err());
        let mut wrong = p.clone();
        wrong.outputs.pop();
        assert!(verify_review(&bytes, &wrong).is_err());
        let mut wrong = p.clone();
        wrong.anchor = orchard::Anchor::empty_tree().to_bytes();
        assert!(verify_review(&bytes, &wrong).is_err());
        let mut wrong = p.clone();
        wrong.expiry_height += 1;
        assert!(verify_review(&bytes, &wrong).is_err());
        let mut changed_manifest = p.clone();
        changed_manifest.manifest_digest[0] ^= 1;
        assert_ne!(
            verify_review(&bytes, &changed_manifest)
                .unwrap()
                .review_binding(),
            valid.review_binding()
        );
    }

    #[test]
    fn economic_review_rejects_redacted_evidence_and_bad_ciphertext() {
        let f = fixture().unwrap();
        let p = review_policy(&f);
        let redacted = Redactor::new(f.pczt.clone())
            .redact_ironwood_with(|mut r| {
                r.redact_action(f.spend_indices[0], |mut a| a.clear_spend_witness());
            })
            .finish();
        assert!(verify_review(&encode(&redacted), &p).is_err());
        let mut bytes = encode(&f.pczt);
        let pczt::orchard::EncCiphertext::Encrypted(ciphertext) = f.pczt.ironwood().actions()
            [f.output_indices[0]]
            .output()
            .enc_ciphertext()
        else {
            panic!("Actual ciphertext required")
        };
        let index = bytes
            .windows(ciphertext.len())
            .position(|w| w == ciphertext)
            .unwrap();
        bytes[index + 100] ^= 1;
        assert!(verify_review(&bytes, &p).is_err());
    }

    #[test]
    fn bounded_parser_rejects_truncations_and_trailing_data() {
        let f = fixture().unwrap();
        let bytes = encode(&f.pczt);
        crate::bounded::preflight(&bytes).unwrap();
        for n in 0..bytes.len() {
            assert!(crate::bounded::preflight(&bytes[..n]).is_err());
        }
        let mut extra = bytes;
        extra.push(0);
        assert!(crate::inspect_candidate(&extra).is_err());
    }

    #[test]
    #[ignore = "Explicit CPU-intensive real Halo2 proof qualification"]
    fn real_two_owner_ironwood_qualification() {
        let report = super::run_two_owner_fixture().unwrap();
        assert!(report.real_halo2_proof_verified);
        assert!(report.missing_signature_rejected);
        assert!(!report.settlement_verified);
        assert_eq!(report.network_operations, 0);
    }
}
