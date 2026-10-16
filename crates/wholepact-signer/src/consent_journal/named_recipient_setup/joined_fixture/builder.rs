//! Private cfg(test) never-funded builder adapted from the maintained protocol
//! synthetic builder. It accepts only a viewing key, creates fabricated notes
//! and a local tree, and never signs a spend, scans a wallet, or uses a network.
use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::IronwoodDomain,
    tree::MerkleHashOrchard,
};
use pczt::{
    Pczt,
    roles::{creator::Creator, io_finalizer::IoFinalizer},
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis};
fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn fresh_key() -> SpendingKey {
    loop {
        let mut bytes = zeroize::Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut()).unwrap();
        if let Some(key) = Option::from(SpendingKey::from_bytes(*bytes)) {
            return key;
        }
    }
}
struct Fixture {
    pczt: Pczt,
    spend_indices: [usize; 2],
    output_indices: [usize; 3],
    fvks: [FullViewingKey; 3],
}
pub(super) fn build(
    own_fvk: FullViewingKey,
    account_id: &str,
) -> (Vec<u8>, wholepact_protocol::review::ReviewPolicy) {
    let f = fixture_at_heights(own_fvk, 100, 140).unwrap();
    let mut policy = review_policy(&f);
    policy.participants[0].account_id = account_id.into();
    (
        pczt::v2::Pczt::try_from(f.pczt).unwrap().serialize(),
        policy,
    )
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

fn review_policy(f: &Fixture) -> wholepact_protocol::review::ReviewPolicy {
    use wholepact_protocol::review::{
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

fn fixture_at_heights(
    own_fvk: FullViewingKey,
    target_height: u32,
    expiry_height: u32,
) -> Result<Fixture, String> {
    // Only the actual fresh vault's viewing key crosses this private fixture
    // boundary. Fabricated notes never existed on chain; no wallet is scanned.
    let peer_keys = [fresh_key(), fresh_key()];
    let fvks = [
        own_fvk,
        FullViewingKey::from(&peer_keys[0]),
        FullViewingKey::from(&peer_keys[1]),
    ];
    drop(peer_keys);
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
        fvks,
    })
}
