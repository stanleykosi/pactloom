//! Ephemeral never-funded qualification fixtures and synthetic-only scanner tests.
use super::synthetic_fixture::SyntheticContributionFixture;
use super::*;
use zcash_client_backend::proto::compact_formats::{ChainMetadata, CompactBlock, CompactTx};
use zcash_primitives::block::BlockHash;

/// Synthetic compact blocks, never a real chain or funded account.
pub(super) struct Blocks(pub(super) Vec<CompactBlock>);
impl BlockSource for Blocks {
    type Error = std::convert::Infallible;
    fn with_blocks<F, E>(
        &self,
        from: Option<BlockHeight>,
        limit: Option<usize>,
        mut f: F,
    ) -> Result<(), chain::error::Error<E, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), chain::error::Error<E, Self::Error>>,
    {
        for b in self
            .0
            .iter()
            .filter(|b| from.is_none_or(|h| b.height >= u64::from(u32::from(h))))
            .take(limit.unwrap_or(usize::MAX))
        {
            f(b.clone())?;
        }
        Ok(())
    }
}

pub(super) fn synthetic_wallet() -> (
    DedicatedTestnetWallet,
    AccountUuid,
    FullViewingKey,
    SelectionContext,
    Blocks,
) {
    synthetic_wallet_with_fixture(&SyntheticContributionFixture::generate())
}

pub(super) fn synthetic_wallet_with_fixture(
    fixture: &SyntheticContributionFixture,
) -> (
    DedicatedTestnetWallet,
    AccountUuid,
    FullViewingKey,
    SelectionContext,
    Blocks,
) {
    let fvk = FullViewingKey::from(fixture.owner_spending_key(0));
    let mut wallet =
        DedicatedTestnetWallet::from_connection(rusqlite::Connection::open_in_memory().unwrap())
            .unwrap();
    // Real TestNetwork activation parameters, fabricated block hashes and encrypted outputs.
    let height = 4_465_040u32;
    let prior = ChainState::empty((height - 1).into(), BlockHash([50; 32]));
    let account = wallet
        .import_dedicated_fvk(&fvk, AccountBirthday::from_parts(prior.clone(), None))
        .unwrap();
    let version = orchard::bundle::BundleVersion::ironwood_v3();
    let mut builder = orchard::builder::Builder::new(
        orchard::builder::BundleType::DEFAULT,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    builder
        .add_output(
            None,
            fvk.address_at(0u32, Scope::External),
            orchard::value::NoteValue::from_raw(200_000),
            zcash_protocol::memo::MemoBytes::empty().into_bytes(),
        )
        .unwrap();
    let other = FullViewingKey::from(fixture.owner_spending_key(1));
    builder
        .add_output(
            None,
            other.address_at(0u32, Scope::External),
            orchard::value::NoteValue::from_raw(300_000),
            zcash_protocol::memo::MemoBytes::empty().into_bytes(),
        )
        .unwrap();
    let (bundle, _) = builder.build::<i64>(UnwrapErr(SysRng)).unwrap().unwrap();
    let actions: Vec<_> = bundle.actions().iter().map(Into::into).collect();
    let size = actions.len() as u32;
    let block = CompactBlock {
        height: u64::from(height),
        hash: vec![51; 32],
        prev_hash: vec![50; 32],
        vtx: vec![CompactTx {
            txid: vec![52; 32],
            ironwood_actions: actions,
            ..Default::default()
        }],
        chain_metadata: Some(ChainMetadata {
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: 0,
            ironwood_commitment_tree_size: size,
        }),
        ..Default::default()
    };
    let blocks = Blocks(vec![block]);
    wallet.scan_cached(&blocks, &prior, 1, height).unwrap();
    let anchor = wallet
        .db
        .with_ironwood_tree_mut::<_, _, WalletError>(|t| {
            Ok(orchard::Anchor::from(t.root_at_checkpoint_id(&height.into())?.unwrap()).to_bytes())
        })
        .unwrap()
        .unwrap();
    let context = SelectionContext {
        tip_height: height,
        tip_hash_protocol: [51; 32],
        anchor_height: height,
        anchor_hash_protocol: [51; 32],
        anchor_root: anchor,
    };
    (wallet, account, fvk, context, blocks)
}

#[cfg(feature = "synthetic-qualification")]
pub(super) fn scanned_contributions(
    fixture: &SyntheticContributionFixture,
) -> Result<(Vec<WalletContribution>, SelectionContext), WalletError> {
    let (mut first, first_account, first_fvk, context, blocks) =
        synthetic_wallet_with_fixture(fixture);
    let second_fvk = FullViewingKey::from(fixture.owner_spending_key(1));
    let mut second = DedicatedTestnetWallet::from_connection(
        rusqlite::Connection::open_in_memory().map_err(|_| WalletError::Storage)?,
    )?;
    let prior = ChainState::empty((context.tip_height - 1).into(), BlockHash([50; 32]));
    let second_account = second.import_dedicated_fvk(
        &second_fvk,
        AccountBirthday::from_parts(prior.clone(), None),
    )?;
    second.scan_cached(&blocks, &prior, 1, context.tip_height)?;
    let a = first.select_contribution(
        first_account,
        &first_fvk,
        "owner-a",
        105_000,
        NonZeroU32::MIN,
        &context,
        &[],
    )?;
    let b = second.select_contribution(
        second_account,
        &second_fvk,
        "owner-b",
        210_000,
        NonZeroU32::MIN,
        &context,
        &[],
    )?;
    Ok((vec![a, b], context))
}

#[cfg(feature = "encrypted-storage")]
#[test]
fn encrypted_wallet_migrates_scans_and_reopens_without_plaintext_fvk() {
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.path().join("synthetic-wallet.db");
    use rand::Rng;
    let mut key_bytes = [0; 32];
    UnwrapErr(SysRng).fill_bytes(&mut key_bytes);
    let key = DatabaseKey::from_bytes(key_bytes);
    let mut wallet =
        DedicatedTestnetWallet::from_encrypted_connection(create_encrypted(&path, &key).unwrap())
            .unwrap();
    let (_, _, fvk, context, blocks) = synthetic_wallet();
    let prior = ChainState::empty((context.tip_height - 1).into(), BlockHash([50; 32]));
    let account = wallet
        .import_dedicated_fvk(&fvk, AccountBirthday::from_parts(prior.clone(), None))
        .unwrap();
    wallet
        .scan_cached(&blocks, &prior, 1, context.tip_height)
        .unwrap();
    let before = wallet
        .select_contribution(
            account,
            &fvk,
            "owner-a",
            105_000,
            NonZeroU32::MIN,
            &context,
            &[],
        )
        .unwrap();
    assert_eq!(before.selected_zatoshis(), 200_000);
    for entry in std::fs::read_dir(directory.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(fvk.to_bytes().len())
                .any(|w| w == fvk.to_bytes())
        );
        assert!(!bytes.starts_with(b"SQLite format 3"));
    }
    drop(wallet);
    let mut reopened =
        DedicatedTestnetWallet::from_encrypted_connection(open_encrypted(&path, &key).unwrap())
            .unwrap();
    let after = reopened
        .select_contribution(
            account,
            &fvk,
            "owner-a",
            105_000,
            NonZeroU32::MIN,
            &context,
            &[],
        )
        .unwrap();
    assert_eq!(
        after.evidence().inputs()[0].nullifier(),
        before.evidence().inputs()[0].nullifier()
    );
}

#[test]
fn refuses_an_unrelated_database_without_mutation() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute("CREATE TABLE everyday_wallet(data BLOB)", [])
        .unwrap();
    assert!(matches!(
        DedicatedTestnetWallet::from_connection(connection),
        Err(WalletError::AccountScope)
    ));
}

#[test]
fn scans_selects_and_witnesses_real_library_ironwood_notes() {
    let (mut wallet, account, fvk, context, _) = synthetic_wallet();
    let selected = wallet
        .select_contribution(
            account,
            &fvk,
            "owner-a",
            105_000,
            NonZeroU32::MIN,
            &context,
            &[],
        )
        .unwrap();
    assert_eq!(selected.selected_zatoshis(), 200_000);
    assert_eq!(selected.notes().len(), 1);
    assert_eq!(
        fvk.scope_for_address(&selected.change_address()),
        Some(Scope::Internal)
    );
    assert_eq!(
        selected.notes()[0]
            .witness
            .root(selected.notes()[0].note.commitment().into())
            .to_bytes(),
        context.anchor_root
    );
    let evidence = selected.evidence();
    assert_eq!(evidence.account_id(), "owner-a");
    assert_eq!(evidence.inputs()[0].value_zatoshis(), 200_000);
    assert_eq!(
        evidence.inputs()[0].nullifier(),
        &selected.notes()[0].note.nullifier(&fvk).to_bytes()
    );
    let excluded = selected.local_note_refs().to_vec();
    let contribution = selected.into_contribution();
    assert_eq!(contribution.account_id, "owner-a");
    assert_eq!(contribution.notes.len(), 1);
    assert!(matches!(
        wallet.select_contribution(
            account,
            &fvk,
            "owner-a",
            105_000,
            NonZeroU32::MIN,
            &context,
            &excluded
        ),
        Err(WalletError::InsufficientFunds)
    ));
}

#[test]
fn separate_owner_databases_select_disjoint_notes_at_one_common_anchor() {
    let fixture = SyntheticContributionFixture::generate();
    let (mut first, first_account, first_fvk, context, blocks) =
        synthetic_wallet_with_fixture(&fixture);
    let second_fvk = FullViewingKey::from(fixture.owner_spending_key(1));
    let mut second =
        DedicatedTestnetWallet::from_connection(rusqlite::Connection::open_in_memory().unwrap())
            .unwrap();
    let prior = ChainState::empty((context.tip_height - 1).into(), BlockHash([50; 32]));
    let second_account = second
        .import_dedicated_fvk(
            &second_fvk,
            AccountBirthday::from_parts(prior.clone(), None),
        )
        .unwrap();
    second
        .scan_cached(&blocks, &prior, 1, context.tip_height)
        .unwrap();
    let a = first
        .select_contribution(
            first_account,
            &first_fvk,
            "owner-a",
            105_000,
            NonZeroU32::MIN,
            &context,
            &[],
        )
        .unwrap();
    let b = second
        .select_contribution(
            second_account,
            &second_fvk,
            "owner-b",
            210_000,
            NonZeroU32::MIN,
            &context,
            &[],
        )
        .unwrap();
    assert_eq!(
        (a.selected_zatoshis(), b.selected_zatoshis()),
        (200_000, 300_000)
    );
    assert_ne!(
        a.evidence().inputs()[0].nullifier(),
        b.evidence().inputs()[0].nullifier()
    );
    assert_ne!(a.notes()[0].input_id, b.notes()[0].input_id);
    assert_eq!(a.context().anchor_root, b.context().anchor_root);
    assert_eq!(
        a.notes()[0]
            .witness
            .root(a.notes()[0].note.commitment().into())
            .to_bytes(),
        b.context().anchor_root
    );
    assert_eq!(
        b.notes()[0]
            .witness
            .root(b.notes()[0].note.commitment().into())
            .to_bytes(),
        a.context().anchor_root
    );
    assert_eq!(a.into_contribution().notes.len(), 1);
    assert_eq!(b.into_contribution().notes.len(), 1);
}

#[test]
fn rejects_wrong_account_anchor_hash_stale_tip_and_insufficient_funds() {
    let fixture = SyntheticContributionFixture::generate();
    let (mut wallet, account, fvk, context, _) = synthetic_wallet_with_fixture(&fixture);
    let wrong_fvk = FullViewingKey::from(fixture.owner_spending_key(1));
    assert!(matches!(
        wallet.select_contribution(
            account,
            &wrong_fvk,
            "owner-a",
            1,
            NonZeroU32::MIN,
            &context,
            &[]
        ),
        Err(WalletError::AccountMismatch)
    ));
    assert!(matches!(
        wallet.select_contribution(
            account,
            &fvk,
            "owner-a",
            200_001,
            NonZeroU32::MIN,
            &context,
            &[]
        ),
        Err(WalletError::InsufficientFunds)
    ));
    let mut bad = context.clone();
    bad.anchor_root = [0; 32];
    assert!(matches!(
        wallet.select_contribution(account, &fvk, "owner-a", 1, NonZeroU32::MIN, &bad, &[]),
        Err(WalletError::ChainMismatch)
    ));
    bad = context.clone();
    bad.anchor_hash_protocol = [0; 32];
    assert!(matches!(
        wallet.select_contribution(account, &fvk, "owner-a", 1, NonZeroU32::MIN, &bad, &[]),
        Err(WalletError::ChainMismatch)
    ));
    bad = context.clone();
    bad.tip_height += 1;
    assert!(matches!(
        wallet.select_contribution(account, &fvk, "owner-a", 1, NonZeroU32::MIN, &bad, &[]),
        Err(WalletError::IncompleteSync)
    ));
    assert!(matches!(
        wallet.import_dedicated_fvk(
            &wrong_fvk,
            AccountBirthday::from_parts(
                ChainState::empty(4_465_039u32.into(), BlockHash([50; 32])),
                None
            )
        ),
        Err(WalletError::AccountScope)
    ));
}
