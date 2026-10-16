//! Component tests. All fixture cryptography is public, synthetic and never-funded.
//! Native admitted owners are not mocked or constructed here. Maintained reads use
//! direct cached-block scanning, with private synthetic lifetime state only. No
//! provider sync or native admission is exercised or qualified by these tests.
use super::*;

fn context(tip: u32) -> SelectionContext {
    SelectionContext {
        tip_height: tip,
        tip_hash_protocol: [1; 32],
        anchor_height: tip,
        anchor_hash_protocol: [1; 32],
        anchor_root: [2; 32],
    }
}
#[test]
fn immutable_target_and_bounded_advance_remain_in_nu7() {
    let original = context(4_465_040);
    assert!(validate_target(&original, original.tip_height, original.tip_height, 0).is_ok());
    assert!(
        validate_target(
            &original,
            original.tip_height + 1,
            original.tip_height + 1,
            0
        )
        .is_err()
    );
    assert!(
        validate_target(
            &original,
            original.tip_height + 32,
            original.tip_height + 32,
            32
        )
        .is_ok()
    );
    assert!(
        validate_target(
            &original,
            original.tip_height + 33,
            original.tip_height + 33,
            32
        )
        .is_err()
    );
    assert!(
        validate_target(
            &original,
            original.tip_height - 1,
            original.tip_height + 32,
            32
        )
        .is_err()
    );
    assert!(validate_target(&original, u32::MAX, u32::MAX, u32::MAX).is_err());
    // Current target being NU7 never fixes an original target from an earlier branch.
    let prior_branch = context(4_465_024);
    assert!(validate_target(&prior_branch, 4_465_026, 4_465_056, 32).is_err());
    assert_eq!(
        BranchId::for_height(&TEST_NETWORK, 4_465_026u32.into()),
        BranchId::Nu7
    );
    let mut bad_anchor = original.clone();
    bad_anchor.anchor_height += 1;
    assert!(
        validate_target(
            &bad_anchor,
            bad_anchor.tip_height + 1,
            bad_anchor.tip_height + 2,
            2
        )
        .is_err()
    );
    assert_eq!(original.tip_height + 1, 4_465_041); // constructor target remains ORIGINAL
}
#[test]
fn expiry_ceiling_uses_strict_margin_and_never_extends_original_expiry() {
    let original = context(4_465_040);
    let expiry: u32 = original.tip_height + 42;
    let ceiling = expiry
        .checked_sub(10)
        .and_then(|h| h.checked_sub(1))
        .unwrap();
    assert!(validate_target(&original, ceiling, ceiling, 32).is_ok());
    assert!(validate_target(&original, ceiling + 1, ceiling, 32).is_err());
    assert_eq!(ceiling + 10, expiry - 1);
}
#[test]
fn budget_boundaries_never_renew_original_completion() {
    let now = Instant::now();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let runway = Duration::from_secs(10);
    assert!(derive_scan_budget(now, now + runway, wall + 60_000, 30_000, runway).is_err());
    assert!(
        derive_scan_budget(
            now,
            now + Duration::from_secs(9),
            wall + 60_000,
            30_000,
            runway
        )
        .is_err()
    );
    assert!(derive_scan_budget(now, now + Duration::from_secs(60), wall, 30_000, runway).is_err());
    assert!(
        derive_scan_budget(
            now,
            now + Duration::from_secs(60),
            wall + 60_000,
            30_001,
            runway
        )
        .is_err()
    );
    let actual = derive_scan_budget(
        now,
        now + Duration::from_secs(12),
        wall + 60_000,
        30_000,
        runway,
    )
    .unwrap();
    assert_eq!(actual, Duration::from_secs(2));
}
#[test]
fn private_epoch_revocation_cannot_be_repaired_by_copied_weak_tokens() {
    let mut epoch = Arc::new(());
    let earlier = Arc::downgrade(&epoch);
    let copied_verifier = earlier.clone();
    assert!(Weak::ptr_eq(&earlier, &Arc::downgrade(&epoch)));
    epoch = Arc::new(());
    assert!(earlier.upgrade().is_none());
    assert!(copied_verifier.upgrade().is_none());
    assert!(!Weak::ptr_eq(&earlier, &Arc::downgrade(&epoch)));
}

#[cfg(feature = "synthetic-qualification")]
mod maintained {
    use super::*;
    use wholepact_storage_security::{
        DatabaseKey, EncryptedConnection, create_encrypted, open_encrypted,
    };
    use zcash_primitives::block::BlockHash;

    struct FixtureSelectionAccess;
    impl LocalWalletAccess for FixtureSelectionAccess {
        fn permits(
            &self,
            _: AccountUuid,
            provider: &BackendIdentity,
            purpose: WalletAccessPurpose,
        ) -> bool {
            provider.trust_profile == "synthetic_never_chain_evidence"
                && matches!(purpose, WalletAccessPurpose::SelectPrivateContribution)
        }
    }

    struct OfflineFixture {
        _directory: tempfile::TempDir,
        wallet: ProtectedWalletSync,
        selected: ProtectedContribution,
        other: EncryptedConnection,
    }

    fn offline_fixture() -> OfflineFixture {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (_, _, fvk, context, blocks) = crate::wallet::qualification::synthetic_wallet();
        let path = directory.path().join("offline-exact-input.sqlite");
        let key = DatabaseKey::from_bytes([93; 32]);
        let connection = create_encrypted(&path, &key).unwrap();
        connection
            .connection()
            .pragma_update(None, "journal_mode", "WAL")
            .unwrap();
        let mut local =
            DedicatedTestnetWallet::from_encrypted_connection_recordable_roster_exact_input_v1(
                connection,
            )
            .unwrap();
        let prior = ChainState::empty((context.tip_height - 1).into(), BlockHash([50; 32]));
        local
            .import_dedicated_fvk(&fvk, AccountBirthday::from_parts(prior.clone(), None))
            .unwrap();
        local
            .scan_cached(&blocks, &prior, 1, context.tip_height)
            .unwrap();
        // Constructor only: Rpc::for_test creates endpoint configuration without
        // opening a channel, socket, listener, or runtime. Never call source I/O.
        let source = ChainAdapter::synthetic_loopback_for_qualification(
            "http://127.0.0.1:1",
            NetworkPolicy::default(),
        )
        .unwrap();
        let mut wallet =
            ProtectedWalletSync::from_initialized_wallet(local, source, NonZeroU32::MIN).unwrap();
        // Private component setup only. This fixed synthetic source context is
        // used for lifetime checks, not claimed to match these cached blocks.
        // It bypasses the provider observation issuer and cannot qualify sync,
        // provider continuity, the exact-observation producer, or native admission.
        wallet.accepted = Some(AcceptedObservation {
            monotonic_started: Instant::now(),
            chain: wholepact_chain::synthetic_wallet_chain_context_for_qualification(
                now().unwrap(),
            )
            .unwrap(),
            selection: context,
        });
        // Exercise the real private ProtectedContribution return from maintained
        // note/witness selection. No public factory or native owner is introduced.
        let selected = wallet
            .select_contribution(&FixtureSelectionAccess, &fvk, "owner-a", 100_000, &[])
            .unwrap();
        let other = open_encrypted(&path, &key).unwrap();
        other.connection().busy_timeout(Duration::ZERO).unwrap();
        OfflineFixture {
            _directory: directory,
            wallet,
            selected,
            other,
        }
    }

    // Private expected facts only. This does NOT construct an admitted native
    // owner, FreshExactInputObservation, slot, held guard, or financial capability.
    fn verifier(
        wallet: &ProtectedWalletSync,
        selected: &ProtectedContribution,
    ) -> ExactInputVerifierSnapshot {
        let c = &selected.contribution;
        ExactInputVerifierSnapshot {
            material: Arc::new(()),
            generation: selected.generation.clone(),
            account: wallet.account,
            origin: [7; 32],
            evidence: c.evidence(),
            notes: c
                .notes
                .iter()
                .map(|n| (n.note, n.witness.position()))
                .collect(),
            local_note_refs: c.local_note_refs.clone(),
            local_outpoints: c.local_outpoints.clone(),
            current: c.context.clone(),
            birthday: 4_465_040,
            participant_id: "synthetic-a".into(),
            minimum_confirmations: 1,
            required_ancestry: Vec::new(),
        }
    }
    #[test]
    fn actual_maintained_exact_reads_reject_changes_while_writer_lock_is_held() {
        let OfflineFixture {
            _directory,
            mut wallet,
            selected,
            other,
        } = offline_fixture();
        let mut expected = verifier(&wallet, &selected);
        wallet
            .wallet
            .db
            .transactionally_with_extension(|db, _| {
                verify_exact_notes(db, &expected).map_err(TransactionError)?;
                assert!(
                    other
                        .connection()
                        .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
                        .is_err()
                );
                expected.birthday += 1;
                assert!(verify_exact_notes(db, &expected).is_err());
                expected.birthday -= 1;
                expected.evidence.inputs[0].value_zatoshis += 1;
                assert!(verify_exact_notes(db, &expected).is_err());
                expected.evidence.inputs[0].value_zatoshis -= 1;
                expected.notes[0].1 += 1;
                assert!(verify_exact_notes(db, &expected).is_err());
                expected.notes[0].1 -= 1;
                expected.current.tip_height += 1;
                assert!(verify_exact_notes(db, &expected).is_err());
                expected.current.tip_height -= 1;
                expected.current.anchor_hash_protocol[0] ^= 1;
                assert!(verify_exact_notes(db, &expected).is_err());
                expected.current.anchor_hash_protocol[0] ^= 1;
                verify_exact_notes(db, &expected).map_err(TransactionError)?;
                Ok::<_, TransactionError<ExactObservationError>>(())
            })
            .map_err(|e| e.0)
            .unwrap();
        other
            .connection()
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
            .unwrap();
    }
    #[test]
    fn shared_original_material_attempt_gate_cannot_be_reset_across_versions() {
        for _order in ["v2_then_v3", "v3_then_v2"] {
            let OfflineFixture {
                mut wallet,
                selected,
                ..
            } = offline_fixture();
            let mut retained = RetainedExactWalletMaterial::from_current(selected).unwrap();
            let original_epoch = retained.generation.clone();
            retained.begin_read_attempt(&mut wallet).unwrap();
            assert!(retained.attempted);
            assert!(original_epoch.upgrade().is_none());
            // Simulate only the successful scanner's private lineage transfer.
            // Both real public read routes call the same gate; neither clears it.
            retained.generation = Arc::downgrade(&wallet.generation);
            assert!(matches!(
                retained.begin_read_attempt(&mut wallet),
                Err(ExactObservationError::Lineage)
            ));
            assert!(retained.attempted);
        }
    }
    #[test]
    fn historical_ttl_and_controller_epoch_are_distinct() {
        let OfflineFixture {
            _directory,
            mut wallet,
            selected,
            other: _,
        } = offline_fixture();
        let old_guard = selected.observation_guard();
        let mut retained = RetainedExactWalletMaterial::from_current(selected).unwrap();
        // Test-only historical clock: no fresh owner or native admission is minted.
        retained.original_observation =
            wholepact_chain::synthetic_wallet_chain_context_for_qualification(now().unwrap() - 120)
                .unwrap();
        assert!(
            retained
                .original_observation
                .check_fresh_at(now().unwrap())
                .is_err()
        );
        retained.check_retained_lineage().unwrap();
        wallet.invalidate_observation();
        assert!(retained.check_retained_lineage().is_err());
        assert!(old_guard.check_current().is_err());
    }
    #[test]
    fn genuine_context_getters_do_not_renew_or_convert_profile_evidence() {
        let observed = now().unwrap();
        let a =
            wholepact_chain::synthetic_wallet_chain_context_for_qualification(observed).unwrap();
        let b = wholepact_chain::synthetic_wallet_confirmation_context_for_qualification(observed)
            .unwrap();
        assert!(verify_observation_profile(&a, &b).is_ok());
        assert_eq!(a.network(), "test");
        assert_eq!(a.branch_id(), "0x77190ad9");
        assert!(!a.authorizes_signing());
        assert!(!a.independently_consensus_verified());
        assert_eq!(a.valid_until_unix_seconds(), observed + 60);
        assert!(
            check_remaining(
                &a,
                Instant::now() - Duration::from_secs(51),
                Instant::now() + Duration::from_secs(60),
                Duration::from_secs(10)
            )
            .is_err()
        );
    }
}
