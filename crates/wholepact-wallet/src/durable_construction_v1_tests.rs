//! Mathematical/data-only and inert held-kernel component tests. Fresh random
//! never-funded owners and maintained note scanning; no native decision, intake
//! or real source authority is fabricated. The private Fresh test carrier below
//! retains opaque synthetic provenance and cannot qualify a durable TLS source.
use super::*;
use wholepact_core::*;
use wholepact_protocol::review::encode_testnet_receiver;
fn amount(v: u64) -> Amount {
    Amount::from_zatoshis(v).unwrap()
}
fn material(c: &WalletContribution) -> HistoricalConstructionMaterialV1 {
    HistoricalConstructionMaterialV1 {
        version: 1,
        account_id: c.account_id.clone(),
        fvk_hex: hex::encode(c.fvk.to_bytes()),
        fvk_digest: hex::encode(Sha256::digest(c.fvk.to_bytes())),
        selected_zatoshis: c.selected_zatoshis,
        requested_debit_zatoshis: c.requested_debit_zatoshis,
        change_address: hex::encode(c.change_address.to_raw_address_bytes()),
        birthday_height: c.context.anchor_height,
        context: HistoricalContextV1::capture(&c.context),
        source: SourceHistoryV1 {
            source_id: "data-only-component".into(),
            endpoint: "https://component.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
            network: "test".into(),
            branch_id: "0x77190ad9".into(),
            lightwalletd_version: "component".into(),
            backend_subversion: "component".into(),
            protocol_version: "component".into(),
            request_started: 1_800_000_000,
            observed_at: 1_800_000_001,
            valid_until: 1_800_000_060,
        },
        notes: c
            .notes
            .iter()
            .zip(&c.local_outpoints)
            .map(|(n, (txid, index))| HistoricalNoteV1 {
                input_id: n.input_id.clone(),
                txid_protocol: hex::encode(txid.as_ref()),
                output_index: *index,
                recipient: hex::encode(n.note.recipient().to_raw_address_bytes()),
                value_zatoshis: n.note.value().inner(),
                rho: hex::encode(n.note.rho().to_bytes()),
                rseed: hex::encode(n.note.rseed().as_bytes()),
                nullifier: hex::encode(n.note.nullifier(&c.fvk).to_bytes()),
                commitment: hex::encode(
                    orchard::note::ExtractedNoteCommitment::from(n.note.commitment()).to_bytes(),
                ),
                position: n.witness.position(),
                authentication_path: n
                    .witness
                    .auth_path()
                    .iter()
                    .map(|p| hex::encode(p.to_bytes()))
                    .collect(),
            })
            .collect(),
    }
}
fn fixture() -> (
    HistoricalConstructionMaterialV1,
    DurableConstructionScopeV1,
    Vec<WalletContribution>,
) {
    let (mut contributions, _) = crate::wallet::synthetic_scanned_contributions().unwrap();
    for contribution in &mut contributions {
        contribution.account_id = canonical_durable_account_id(&contribution.fvk);
    }
    let scope = scope_for_contributions(&contributions);
    (material(&contributions[0]), scope, contributions)
}
fn scope_for_contributions(contributions: &[WalletContribution]) -> DurableConstructionScopeV1 {
    let a = &contributions[0];
    let receiver = encode_testnet_receiver(&a.notes[0].note.recipient());
    let agreement = AgreementDraft {
        schema_version: 1,
        agreement_id: "durable-component".into(),
        obligation_id: "never-funded".into(),
        revision: 1,
        purpose: "Data-only construction decoder component".into(),
        organizer_identity: "component".into(),
        network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
        recipients: vec![Recipient {
            recipient_id: "recipient".into(),
            address: receiver.clone(),
            amount: amount(300_000),
            memo: None,
            instruction_provenance: "component".into(),
        }],
        funding_policy: FundingPolicy::Exact {
            target: amount(300_000),
        },
        fee_policy: FeePolicy::ProRata,
        privacy_profile: PrivacyProfile {
            mode: PrivacyMode::DeclaredOperator,
            proving_operator: Some("local-component".into()),
            dedicated_accounts_required: true,
        },
        coordination_deadline: None,
        confirmation_policy: ConfirmationPolicy::default(),
        extensions: vec![],
    };
    let mut participants = Vec::new();
    let mut inputs = Vec::new();
    let mut outputs = vec![ClaimedOutput {
        output_id: "recipient-output".into(),
        address: receiver,
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: "recipient".into(),
        },
    }];
    for (i, c) in contributions.iter().enumerate() {
        let participant_id = format!("participant-{i}");
        participants.push(ParticipantAllocation {
            participant_id: participant_id.clone(),
            account_id: c.account_id.clone(),
            contribution: amount(if i == 0 { 100_000 } else { 200_000 }),
            fee_share: amount(if i == 0 { 5_000 } else { 10_000 }),
            fee_cap: amount(if i == 0 { 5_000 } else { 10_000 }),
            maximum_net_debit: amount(c.requested_debit_zatoshis),
            charges: vec![],
        });
        for n in &c.notes {
            inputs.push(ClaimedInput {
                input_id: n.input_id.clone(),
                participant_id: participant_id.clone(),
                account_id: c.account_id.clone(),
                amount: amount(n.note.value().inner()),
                ownership_evidence_ref: None,
            });
        }
        outputs.push(ClaimedOutput {
            output_id: format!("change-{i}"),
            address: encode_testnet_receiver(&c.change_address),
            amount: amount(c.selected_zatoshis - c.requested_debit_zatoshis),
            allocation: OutputAllocation::Return {
                participant_id,
                account_id: c.account_id.clone(),
                ownership_evidence_ref: None,
            },
        });
    }
    let scope = DurableConstructionScopeV1 {
        version: 1,
        purpose: PURPOSE.into(),
        proposal: ProposalInput {
            proposal_id: "durable-candidate".into(),
            previous_proposal_id: None,
            manifest: ProposalManifest {
                agreement,
                participants,
                inputs,
                outputs,
                transaction_fee: amount(15_000),
                expiry_height: a.context.tip_height + 30,
            },
            artifact_digest: None,
            effects_commitment: None,
            created_at: "2026-10-17T00:00:00Z".into(),
        },
        account_id: a.account_id.clone(),
        participant_id: "participant-0".into(),
        privacy_domain: "dedicated-component".into(),
        constructor: ConstructionRecipientV1 {
            principal_id: "constructor".into(),
            authenticated_local_grant_digest: "11".repeat(32),
        },
        prover: ConstructionRecipientV1 {
            principal_id: "prover".into(),
            authenticated_local_grant_digest: "11".repeat(32),
        },
        reviewers: contributions
            .iter()
            .enumerate()
            .map(|(i, c)| {
                ConstructionReviewerV1::ExactTransport(ExactTransportConstructionReviewerV1 {
                    account_id: c.account_id.clone(),
                    transport_key_digest: format!("{:02x}", 20 + i).repeat(32),
                })
            })
            .collect(),
        protected_destination: "/component/private/intake.sqlite".into(),
        retention_policy: "Retain exact encrypted material for bounded construction only".into(),
        valid_from_unix_seconds: 1_800_000_000,
        valid_until_unix_seconds: 1_800_003_600,
        minimum_confirmations: 1,
        maximum_scan_blocks: 100,
    };
    scope
}

// Opt-in, thread-local component instrumentation. Outside a measured test run
// it is inert; neither this switch nor its counters exist in product builds.
#[derive(Clone, Copy, Default)]
struct HeldValidationCounts {
    material: usize,
    live: usize,
}
struct HeldValidationMeter {
    legacy: bool,
    counts: HeldValidationCounts,
}
thread_local! {
    static HELD_VALIDATION_METER: std::cell::RefCell<Option<HeldValidationMeter>> =
        const { std::cell::RefCell::new(None) };
}
pub(super) fn record_material_validation() {
    HELD_VALIDATION_METER.with(|meter| {
        if let Some(meter) = meter.borrow_mut().as_mut() {
            meter.counts.material += 1;
        }
    });
}
pub(super) fn record_live_verification() {
    HELD_VALIDATION_METER.with(|meter| {
        if let Some(meter) = meter.borrow_mut().as_mut() {
            meter.counts.live += 1;
        }
    });
}
pub(super) fn legacy_held_validation() -> bool {
    HELD_VALIDATION_METER.with(|meter| meter.borrow().as_ref().is_some_and(|m| m.legacy))
}
fn measure_held_validation<T>(
    legacy: bool,
    work: impl FnOnce() -> T,
) -> (T, HeldValidationCounts, Duration) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HELD_VALIDATION_METER.with(|meter| {
                meter.borrow_mut().take();
            });
        }
    }
    HELD_VALIDATION_METER.with(|meter| {
        let mut meter = meter.borrow_mut();
        assert!(meter.is_none(), "nested held component measurement");
        *meter = Some(HeldValidationMeter {
            legacy,
            counts: HeldValidationCounts::default(),
        });
    });
    let reset = Reset;
    let started = Instant::now();
    let result = work();
    let elapsed = started.elapsed();
    let counts = HELD_VALIDATION_METER.with(|meter| {
        meter
            .borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("held component measurement missing"))
            .counts
    });
    drop(reset);
    (result, counts, elapsed)
}

// Real encrypted maintained scanner databases, but NO provider observation,
// native approval, construction admission, financial effect or public issuer.
// The private Fresh carrier is only inert currentness scaffolding for this
// component. Its opaque synthetic ChainContext retains synthetic provenance;
// material()'s historical TLS strings remain inert mathematical claims. They
// are deliberately incompatible with the source preflight tested below.
struct HeldComponentFixture {
    _directory: tempfile::TempDir,
    wallets: Vec<ProtectedWalletSync>,
    fresh: Vec<FreshDurableConstructionObservationV1>,
    competitors: Vec<wholepact_storage_security::EncryptedConnection>,
    paths: Vec<std::path::PathBuf>,
}
fn held_component_fixture() -> HeldComponentFixture {
    use rand::{Rng, rand_core::UnwrapErr, rngs::SysRng};
    use std::os::unix::fs::PermissionsExt;
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
    use zcash_primitives::block::BlockHash;
    let directory = material_test_value(tempfile::tempdir());
    material_test_value(std::fs::set_permissions(
        directory.path(),
        std::fs::Permissions::from_mode(0o700),
    ));
    let owners = crate::wallet::SyntheticContributionFixture::generate();
    let (_, _, _, current, blocks) =
        crate::wallet::qualification::synthetic_wallet_with_fixture(&owners);
    let mut wallets = Vec::new();
    let mut contributions = Vec::new();
    let mut competitors = Vec::new();
    let mut paths = Vec::new();
    for index in 0..2 {
        let fvk = FullViewingKey::from(owners.owner_spending_key(index));
        let mut key_bytes = [0; 32];
        UnwrapErr(SysRng).fill_bytes(&mut key_bytes);
        let key = DatabaseKey::from_bytes(key_bytes);
        let path = directory
            .path()
            .join(format!("held-component-{index}.sqlite"));
        let connection = material_test_value(create_encrypted(&path, &key));
        material_test_value(
            connection
                .connection()
                .pragma_update(None, "journal_mode", "WAL"),
        );
        material_test_value(connection.connection().busy_timeout(Duration::ZERO));
        let mut wallet = material_test_value(DedicatedTestnetWallet::from_encrypted_connection(
            connection,
        ));
        let prior = ChainState::empty((current.tip_height - 1).into(), BlockHash([50; 32]));
        let account = material_test_value(
            wallet.import_dedicated_fvk(&fvk, AccountBirthday::from_parts(prior.clone(), None)),
        );
        material_test_value(wallet.scan_cached(&blocks, &prior, 1, current.tip_height));
        contributions.push(material_test_value(wallet.select_contribution(
            account,
            &fvk,
            &canonical_durable_account_id(&fvk),
            if index == 0 { 105_000 } else { 210_000 },
            NonZeroU32::MIN,
            &current,
            &[],
        )));
        // Constructing this synthetic adapter performs no I/O. It is never
        // contacted, changed to HTTPS or treated as a TLS-qualified source.
        let source = material_test_value(ChainAdapter::synthetic_loopback_for_qualification(
            "http://127.0.0.1:1",
            NetworkPolicy::default(),
        ));
        wallets.push(material_test_value(
            ProtectedWalletSync::from_initialized_wallet(wallet, source, NonZeroU32::MIN),
        ));
        let competitor = material_test_value(open_encrypted(&path, &key));
        material_test_value(competitor.connection().busy_timeout(Duration::ZERO));
        competitors.push(competitor);
        paths.push(path);
    }
    let clock = material_test_value(now());
    let started = Instant::now();
    let observation = material_test_value(
        wholepact_chain::synthetic_wallet_chain_context_for_qualification(clock),
    );
    assert!(observation.source().trust_profile == "synthetic_never_chain_evidence");
    assert!(!observation.authorizes_signing());
    let mut scope = scope_for_contributions(&contributions);
    scope.valid_from_unix_seconds = clock - 1;
    scope.valid_until_unix_seconds = clock + 600;
    let fresh = contributions
        .iter()
        .zip(&wallets)
        .enumerate()
        .map(|(index, (c, sync))| {
            let mut scope = scope.clone();
            scope.account_id = c.account_id.clone();
            scope.participant_id = format!("participant-{index}");
            FreshDurableConstructionObservationV1 {
                material: material(c),
                scope,
                observation: observation.clone(),
                current: current.clone(),
                started,
                generation: Arc::downgrade(&sync.generation),
                account: sync.account,
                attempted: std::cell::Cell::new(false),
            }
        })
        .collect();
    HeldComponentFixture {
        _directory: directory,
        wallets,
        fresh,
        competitors,
        paths,
    }
}
fn component_try_write(connection: &wholepact_storage_security::EncryptedConnection) -> bool {
    match connection.connection().execute_batch("BEGIN IMMEDIATE;") {
        Ok(()) => {
            material_test_value(connection.connection().execute_batch("ROLLBACK;"));
            true
        }
        Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::DatabaseBusy =>
        {
            false
        }
        Err(_) => panic!("unexpected held component writer error"),
    }
}
fn with_held_component(
    wallets: &mut [ProtectedWalletSync],
    fresh: &[FreshDurableConstructionObservationV1],
    callback: impl FnOnce(&HeldDurableConstructionRosterV1<'_>) -> MaterialResult<()>,
) -> MaterialResult<()> {
    let slots = wallets
        .iter_mut()
        .zip(fresh)
        .map(|(sync, fresh)| DurableConstructionWalletSlotV1::new(sync, fresh))
        .collect::<MaterialResult<Vec<_>>>()?;
    with_durable_construction_roster_v1(slots, |held, _, _| callback(held))
}

#[test]
fn held_component_reuses_owned_with_same_live_checks_and_actual_locks() {
    let mut observed = Vec::new();
    for legacy in [true, false] {
        // Separate fresh original instances: attempted is never cleared or reused.
        let mut fixture = held_component_fixture();
        let reached = std::cell::Cell::new(0);
        let (result, counts, elapsed) = measure_held_validation(legacy, || {
            with_held_component(&mut fixture.wallets, &fixture.fresh, |held| {
                held.check_current()?;
                assert!(fixture.competitors.iter().all(|c| !component_try_write(c)));
                reached.set(reached.get() + 1);
                Ok(())
            })
        });
        assert!(
            result.is_ok(),
            "held component must accept unchanged maintained rows"
        );
        assert!(reached.get() == 1, "held component callback count changed");
        assert!(counts.live == 13, "held live checks were removed or added");
        assert!(
            counts.material == if legacy { 17 } else { 4 },
            "held material validation count changed"
        );
        assert!(fixture.competitors.iter().all(component_try_write));
        let repeated = with_held_component(&mut fixture.wallets, &fixture.fresh, |_| {
            panic!("consumed held component reached callback")
        });
        assert!(matches!(repeated, Err(DurableConstructionError::Stale)));
        observed.push((counts, elapsed));
    }
    // Finite scalar cost evidence only; elapsed time is never a pass criterion.
    eprintln!(
        "held_material_component legacy_validations={} reuse_validations={} legacy_live={} reuse_live={} legacy_us={} reuse_us={}",
        observed[0].0.material,
        observed[1].0.material,
        observed[0].0.live,
        observed[1].0.live,
        observed[0].1.as_micros(),
        observed[1].1.as_micros()
    );
}

#[test]
fn held_component_malformed_source_database_and_currentness_fail_closed() {
    let mut category_sets = Vec::new();
    for legacy in [true, false] {
        let mut categories = Vec::new();
        for fault in 0..7 {
            let mut fixture = held_component_fixture();
            match fault {
                0 => fixture.fresh[0].material.notes[0].nullifier = "ff".repeat(32),
                1 => fixture.fresh[0].started = Instant::now() - Duration::from_secs(61),
                2 => fixture.wallets[0].invalidate_observation(),
                3 => fixture.fresh[0].current.tip_hash_protocol[0] ^= 1,
                4 => fixture.fresh[0].material.birthday_height -= 1,
                5 => fixture.wallets.swap(0, 1),
                _ => fixture.fresh[0].scope.valid_until_unix_seconds = material_test_value(now()),
            }
            let reached = std::cell::Cell::new(false);
            let (result, _, _) = measure_held_validation(legacy, || {
                with_held_component(&mut fixture.wallets, &fixture.fresh, |_| {
                    reached.set(true);
                    Ok(())
                })
            });
            assert!(
                result.is_err(),
                "held component accepted a malformed or stale input"
            );
            assert!(!reached.get(), "invalid held component reached callback");
            assert!(fixture.competitors.iter().all(component_try_write));
            if fault == 1 {
                assert!(matches!(
                    result,
                    Err(DurableConstructionError::Sync(
                        SyncError::NoCurrentObservation
                    ))
                ));
            }
            categories.push(material_result_category(&result));
        }
        let fixture = held_component_fixture();
        let f = &fixture.fresh[0];
        let owned = material_test_value(f.material.validate());
        let refused = fixture.wallets[0].validate_durable_material_source_v1(
            &f.material,
            &f.scope,
            &owned.fvk,
        );
        assert!(matches!(refused, Err(DurableConstructionError::Binding)));
        assert!(
            !f.material.source.matches(&f.observation),
            "synthetic provenance was relabelled"
        );
        assert!(
            fixture.wallets[0].accepted.is_none(),
            "component acquired source authority"
        );
        let wrong_db = verify_current_notes(&fixture.wallets[1].wallet.db, f);
        assert!(matches!(wrong_db, Err(DurableConstructionError::Stale)));
        category_sets.push(categories);
    }
    assert!(
        category_sets[0] == category_sets[1],
        "held currentness refusal category changed"
    );
}

#[test]
fn held_component_mutated_rows_and_quarantine_match_legacy_refusals() {
    // Deliberate fixture corruption only; production decisions continue to use
    // maintained APIs. No stale writer is allowed through the actual held locks.
    let mutations = [
        "UPDATE ironwood_received_notes SET value = value + 1",
        "UPDATE ironwood_received_notes SET commitment_tree_position = commitment_tree_position + 1",
        "UPDATE blocks SET hash = zeroblob(32)",
        "UPDATE scan_queue SET priority = 50",
        "INSERT INTO ironwood_received_note_spends(ironwood_received_note_id, transaction_id) SELECT id, transaction_id FROM ironwood_received_notes",
        "CREATE TABLE wholepact_bundle_quarantine(recovery_required INTEGER)",
    ];
    for sql in mutations {
        let mut categories = Vec::new();
        for legacy in [true, false] {
            let mut fixture = held_component_fixture();
            material_test_value(fixture.competitors[0].connection().execute_batch(sql));
            let reached = std::cell::Cell::new(false);
            let (result, _, _) = measure_held_validation(legacy, || {
                with_held_component(&mut fixture.wallets, &fixture.fresh, |_| {
                    reached.set(true);
                    Ok(())
                })
            });
            assert!(result.is_err(), "mutated maintained rows were accepted");
            assert!(!reached.get(), "mutated maintained rows reached callback");
            assert!(fixture.competitors.iter().all(component_try_write));
            categories.push(material_result_category(&result));
        }
        assert!(
            categories[0] == categories[1],
            "held mutation refusal category changed"
        );
    }
}

#[test]
fn held_component_rechecks_identity_inside_callback_and_after_return() {
    use std::os::unix::fs::PermissionsExt;
    for legacy in [true, false] {
        let mut fixture = held_component_fixture();
        let entered = std::cell::Cell::new(false);
        let (result, _, _) = measure_held_validation(legacy, || {
            with_held_component(&mut fixture.wallets, &fixture.fresh, |held| {
                held.check_current()?;
                assert!(fixture.competitors.iter().all(|c| !component_try_write(c)));
                entered.set(true); // Operation-local diagnostic, never a financial effect.
                material_test_value(std::fs::set_permissions(
                    &fixture.paths[0],
                    std::fs::Permissions::from_mode(0o640),
                ));
                assert!(matches!(
                    held.check_current(),
                    Err(DurableConstructionError::Storage)
                ));
                // Returning success cannot suppress the kernel's post-leaf check.
                Ok(())
            })
        });
        assert!(
            entered.get(),
            "held identity mutation never reached boundary"
        );
        assert!(matches!(result, Err(DurableConstructionError::Storage)));
        assert!(fixture.competitors.iter().all(component_try_write));
    }
}
#[test]
fn exact_private_material_roundtrip_preserves_math_not_authority() {
    let (m, scope, owners) = fixture();
    m.validate_for(&scope).unwrap();
    let encoded = m.encode().unwrap();
    let restored = HistoricalConstructionMaterialV1::decode(&encoded).unwrap();
    assert!(restored == m);
    assert_eq!(restored.digest().unwrap(), m.digest().unwrap());
    restored.verify_owner(owners[0].fvk()).unwrap();
    let evidence = restored.historical_review_evidence().unwrap();
    assert_eq!(evidence.account_id, owners[0].account_id);
    assert_eq!(evidence.fvk.to_bytes(), owners[0].fvk.to_bytes());
    assert_eq!(evidence.inputs.len(), owners[0].notes.len());
    assert_eq!(
        evidence.inputs[0].nullifier,
        owners[0].notes[0].note.nullifier(&owners[0].fvk).to_bytes()
    );
    assert_eq!(evidence.context.anchor_root, owners[0].context.anchor_root);
    assert!(restored.verify_owner(owners[1].fvk()).is_err());
    // Historical source expiry is not revived or treated as fresh permission.
    assert!(
        scope
            .check_valid_at(scope.valid_until_unix_seconds)
            .is_err()
    );
    assert!(restored.validate_for(&scope).is_ok());
}
#[test]
fn malformed_tampered_and_duplicate_note_material_is_rejected() {
    let (m, _, _) = fixture();
    let mut mutations = Vec::new();
    let mut n = m.clone();
    n.notes[0].nullifier = "ff".repeat(32);
    mutations.push(n);
    let mut n = m.clone();
    n.notes[0].value_zatoshis += 1;
    mutations.push(n);
    let mut n = m.clone();
    n.notes[0].rseed = "ff".repeat(32);
    mutations.push(n);
    let mut n = m.clone();
    n.notes[0].authentication_path.pop();
    mutations.push(n);
    let mut n = m.clone();
    n.notes[0].position ^= 1;
    mutations.push(n);
    let mut n = m.clone();
    n.context.anchor_root = "00".repeat(32);
    mutations.push(n);
    let mut n = m.clone();
    n.notes.push(n.notes[0].clone());
    mutations.push(n);
    let mut n = m.clone();
    n.fvk_digest = "00".repeat(32);
    mutations.push(n);
    for bad in mutations {
        let raw = Zeroizing::new(serde_json::to_vec(&bad).unwrap());
        assert!(HistoricalConstructionMaterialV1::decode(&raw).is_err());
    }
    let mut value = serde_json::to_value(&m).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("verified".into(), serde_json::json!(true));
    assert!(
        HistoricalConstructionMaterialV1::decode(&serde_json::to_vec(&value).unwrap()).is_err()
    );
    assert!(HistoricalConstructionMaterialV1::decode(&vec![b' '; MAX_MATERIAL_BYTES + 1]).is_err());
}
#[test]
fn old_purpose_wrong_account_and_missing_reviewer_are_not_durable_consent() {
    let (m, scope, _) = fixture();
    let mut old = scope.clone();
    old.purpose = "construct_exact_accepted_candidate".into();
    assert!(m.validate_for(&old).is_err());
    let mut wrong = scope.clone();
    wrong.account_id = "other-account".into();
    assert!(m.validate_for(&wrong).is_err());
    let mut missing = scope.clone();
    missing.reviewers.pop();
    assert!(m.validate_for(&missing).is_err());
    let mut repeated = scope.clone();
    repeated.reviewers[1] = repeated.reviewers[0].clone();
    assert!(m.validate_for(&repeated).is_err());
    let mut long = scope.clone();
    long.valid_until_unix_seconds = long.valid_from_unix_seconds + MAX_VALIDITY_SECONDS + 1;
    assert!(long.validate().is_err());
}
#[test]
fn exact_consent_digest_binds_changed_recipient_manifest_and_destination() {
    let (_, scope, _) = fixture();
    let original = scope.digest().unwrap();
    let mut values = Vec::new();
    let mut v = scope.clone();
    v.constructor.authenticated_local_grant_digest = "12".repeat(32);
    values.push(v);
    let mut v = scope.clone();
    v.prover.authenticated_local_grant_digest = "12".repeat(32);
    values.push(v);
    let mut v = scope.clone();
    let ConstructionReviewerV1::ExactTransport(reviewer) = &mut v.reviewers[0] else {
        panic!("legacy fixture");
    };
    reviewer.transport_key_digest = "12".repeat(32);
    values.push(v);
    let mut v = scope.clone();
    v.protected_destination.push_str(".other");
    values.push(v);
    let mut v = scope.clone();
    v.retention_policy.push_str(" changed");
    values.push(v);
    let mut v = scope.clone();
    v.proposal.manifest.agreement.revision += 1;
    values.push(v);
    let mut v = scope.clone();
    v.proposal
        .manifest
        .agreement
        .obligation_id
        .push_str("-other");
    values.push(v);
    for changed in values {
        assert_ne!(changed.digest().unwrap(), original);
    }
}

#[test]
fn arbitrary_or_relabelled_account_is_not_cryptographic_account_ownership() {
    let (material, mut scope, _) = fixture();
    let mut forged = material.clone();
    forged.account_id = "host-selected-owner-label".into();
    assert!(forged.encode().is_err());
    assert!(forged.historical_review_evidence().is_err());
    // Coordinated relabelling of both material and manifest cannot make a
    // different account ID belong to the same actual viewing key.
    let old = scope.account_id.clone();
    scope.account_id = forged.account_id.clone();
    for participant in &mut scope.proposal.manifest.participants {
        if participant.account_id == old {
            participant.account_id = forged.account_id.clone();
        }
    }
    for input in &mut scope.proposal.manifest.inputs {
        if input.account_id == old {
            input.account_id = forged.account_id.clone();
        }
    }
    for output in &mut scope.proposal.manifest.outputs {
        if let OutputAllocation::Return { account_id, .. } = &mut output.allocation {
            if *account_id == old {
                *account_id = forged.account_id.clone();
            }
        }
    }
    for reviewer in &mut scope.reviewers {
        if let ConstructionReviewerV1::ExactTransport(reviewer) = reviewer {
            if reviewer.account_id == old {
                reviewer.account_id = forged.account_id.clone();
            }
        }
    }
    scope.validate().unwrap();
    assert!(forged.validate_for(&scope).is_err());
}

#[test]
fn local_reviewer_audience_is_explicit_and_never_inferred_from_legacy_transport() {
    let (_, mut scope, _) = fixture();
    let account = scope.account_id.clone();
    assert!(!scope.permits_local_reviewer_account(&account).unwrap());
    let legacy = serde_json::to_value(&scope.reviewers[0]).unwrap();
    assert!(legacy.get("transport_key_digest").is_some());
    assert!(legacy.get("kind").is_none());
    scope.reviewers = scope
        .reviewers
        .iter()
        .map(|r| ConstructionReviewerV1::local_installed_signer(r.account_id().into()))
        .collect();
    assert!(scope.validate().is_err()); // Not a grant under the old scope version.
    scope.version = 2;
    assert!(scope.permits_local_reviewer_account(&account).unwrap());
    assert!(
        !scope
            .permits_local_reviewer_account(&"ff".repeat(32))
            .unwrap()
    );
    let encoded = serde_json::to_value(&scope.reviewers[0]).unwrap();
    assert_eq!(encoded["kind"], "local_installed_signer_canonical_account");
    assert!(encoded.get("transport_key_digest").is_none());
    let mut ambiguous = encoded.clone();
    ambiguous["transport_key_digest"] = serde_json::json!("11".repeat(32));
    assert!(serde_json::from_value::<ConstructionReviewerV1>(ambiguous).is_err());
    let mut unknown = encoded;
    unknown["unknown_recipient"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ConstructionReviewerV1>(unknown).is_err());
    scope.reviewers[0] = serde_json::from_value(legacy).unwrap();
    assert!(scope.validate().is_err()); // No mixed audience or fallback.
}

type MaterialResult<T> = std::result::Result<T, DurableConstructionError>;

// Frozen pre-consolidation scope/material composition. Keep this independent of
// validate_for, validate_for_proposal and validate_for_with_digest: it is the
// differential reference, not an assertion that historical data is authority.
fn frozen_material_validate_for(
    material: &HistoricalConstructionMaterialV1,
    scope: &DurableConstructionScopeV1,
) -> MaterialResult<Proposal> {
    let p = scope.validate()?;
    let c = material.validate()?;
    if material.account_id != scope.account_id
        || material.context.tip_height >= p.manifest().expiry_height
    {
        return Err(DurableConstructionError::Binding);
    }
    let allocation = p
        .manifest()
        .participants
        .iter()
        .find(|a| a.account_id == material.account_id)
        .ok_or(DurableConstructionError::Binding)?;
    let debit = p
        .accounting()
        .participant_net_debits
        .get(&scope.participant_id)
        .ok_or(DurableConstructionError::Binding)?
        .as_zatoshis();
    let inputs = p
        .manifest()
        .inputs
        .iter()
        .filter(|n| n.account_id == material.account_id)
        .collect::<Vec<_>>();
    if inputs.len() != material.notes.len()
        || debit != material.requested_debit_zatoshis
        || debit > allocation.maximum_net_debit.as_zatoshis()
        || material
            .context
            .tip_height
            .checked_sub(material.context.anchor_height)
            .and_then(|h| h.checked_add(1))
            .is_none_or(|v| v < scope.minimum_confirmations)
        || inputs.iter().any(|i| {
            i.participant_id != scope.participant_id
                || !material
                    .notes
                    .iter()
                    .any(|n| n.input_id == i.input_id && n.value_zatoshis == i.amount.as_zatoshis())
        })
        || c.fvk.scope_for_address(&c.change_address) != Some(Scope::Internal)
    {
        return Err(DurableConstructionError::Binding);
    }
    Ok(p)
}

// All new failure messages are fixed strings. In particular, never format the
// material, serialized mutation, viewing key, witness, proposal or digest.
fn material_test_value<T, E>(value: std::result::Result<T, E>) -> T {
    match value {
        Ok(value) => value,
        Err(_) => panic!("material differential fixture operation failed"),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MaterialResultCategory {
    Valid,
    Invalid,
    Binding,
    Stale,
    Storage,
    Sync,
}
fn material_result_category<T>(result: &MaterialResult<T>) -> MaterialResultCategory {
    match result {
        Ok(_) => MaterialResultCategory::Valid,
        Err(DurableConstructionError::Invalid) => MaterialResultCategory::Invalid,
        Err(DurableConstructionError::Binding) => MaterialResultCategory::Binding,
        Err(DurableConstructionError::Stale) => MaterialResultCategory::Stale,
        Err(DurableConstructionError::Storage) => MaterialResultCategory::Storage,
        Err(DurableConstructionError::Sync(_)) => MaterialResultCategory::Sync,
    }
}
fn assert_material_validation_matches_frozen(
    material: &HistoricalConstructionMaterialV1,
    scope: &DurableConstructionScopeV1,
) -> MaterialResultCategory {
    // The old composition validates scope/material, then calls the unchanged
    // separately validating public digest. It never calls a consolidated API.
    let expected = frozen_material_validate_for(material, scope)
        .and_then(|proposal| material.digest().map(|digest| (proposal, digest)));
    let actual = material.validate_for_with_digest(scope);
    let category = material_result_category(&expected);
    assert!(
        material_result_category(&actual) == category,
        "material validation error category changed"
    );
    if let (Ok((expected_proposal, expected_digest)), Ok((proposal, digest))) = (expected, actual) {
        assert!(proposal == expected_proposal, "material proposal changed");
        assert!(digest == expected_digest, "material digest changed");
        // Independent canonical oracle uses the old literal domain directly,
        // not the production helper or the returned digest as an input.
        let canonical = material_test_value(wholepact_core::proposal::canonical_digest(
            "wholepact:historical-construction-material:v1",
            material,
        ));
        assert!(digest == canonical, "material canonical domain changed");
    }
    category
}

fn assert_material_validation_category(
    material: &HistoricalConstructionMaterialV1,
    scope: &DurableConstructionScopeV1,
    expected: MaterialResultCategory,
) {
    assert!(
        assert_material_validation_matches_frozen(material, scope) == expected,
        "material fixture category changed"
    );
    assert!(
        material_result_category(&material.validate_for(scope)) == expected,
        "legacy material validation contract changed"
    );
}

// Enumerate every serialized leaf and array, including all 32 path positions
// in every note. Each replacement is applied alone to a fresh fixture clone.
// Nonempty arrays are tested both missing an element and repeating an element;
// empty arrays are tested with an unexpected member. Object members are visited
// recursively rather than selecting just a few hand-picked bindings.
fn material_json_mutations(
    value: &serde_json::Value,
    pointer: &str,
    mutations: &mut Vec<(String, serde_json::Value)>,
) {
    use serde_json::Value;
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                material_json_mutations(value, &format!("{pointer}/{escaped}"), mutations);
            }
        }
        Value::Array(array) => {
            if array.is_empty() {
                mutations.push((pointer.into(), serde_json::json!([null])));
            } else {
                let mut missing = array.clone();
                missing.pop();
                mutations.push((pointer.into(), Value::Array(missing)));
                let mut repeated = array.clone();
                repeated.push(array[0].clone());
                mutations.push((pointer.into(), Value::Array(repeated)));
                for (index, value) in array.iter().enumerate() {
                    material_json_mutations(value, &format!("{pointer}/{index}"), mutations);
                }
            }
        }
        Value::String(value) => {
            // Keep Amount strings numeric and keep byte encodings syntactically
            // valid, so their mutations reach arithmetic and binding checks.
            let changed = if let Some(number) = (value.len() <= 20)
                .then(|| value.parse::<u64>().ok())
                .flatten()
            {
                (number ^ 1).to_string()
            } else if !value.is_empty()
                && value
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            {
                let mut changed = value.clone();
                changed.replace_range(..1, if value.starts_with('0') { "1" } else { "0" });
                changed
            } else if value == "declared_operator" {
                "local_only".into()
            } else {
                format!("{value}-changed")
            };
            mutations.push((pointer.into(), Value::String(changed)));
            if !value.is_empty() {
                mutations.push((pointer.into(), Value::String(String::new())));
            }
        }
        Value::Number(value) => {
            let number = value
                .as_u64()
                .unwrap_or_else(|| panic!("non-integer material fixture"));
            mutations.push((pointer.into(), Value::from(number ^ 1)));
        }
        Value::Bool(value) => mutations.push((pointer.into(), Value::Bool(!value))),
        Value::Null => mutations.push((pointer.into(), Value::String("changed".into()))),
    }
}

#[test]
fn consolidated_material_validation_matches_every_material_field_and_witness_path() {
    let (material, scope, _) = fixture();
    assert_material_validation_category(&material, &scope, MaterialResultCategory::Valid);
    let original = material_test_value(serde_json::to_value(&material));
    let mut mutations = Vec::new();
    material_json_mutations(&original, "", &mut mutations);
    let mut valid = 0;
    let mut invalid = 0;
    let mut binding = 0;
    let mut path_positions = BTreeSet::new();
    for (pointer, replacement) in mutations {
        if pointer.contains("/authentication_path/") {
            path_positions.insert(pointer.clone());
        }
        let mut changed = original.clone();
        *changed
            .pointer_mut(&pointer)
            .unwrap_or_else(|| panic!("material mutation path missing")) = replacement;
        assert!(changed != original, "material mutation did not change data");
        // All material leaves are primitive strings/integers. Array shape
        // mutations remain deserializable, including an empty notes array.
        let changed: HistoricalConstructionMaterialV1 =
            material_test_value(serde_json::from_value(changed));
        match assert_material_validation_matches_frozen(&changed, &scope) {
            MaterialResultCategory::Valid => {
                valid += 1;
                let canonical = material_test_value(wholepact_core::proposal::canonical_digest(
                    "wholepact:historical-construction-material:v1",
                    &changed,
                ));
                let original_canonical =
                    material_test_value(wholepact_core::proposal::canonical_digest(
                        "wholepact:historical-construction-material:v1",
                        &material,
                    ));
                assert!(
                    canonical != original_canonical,
                    "material mutation not committed"
                );
            }
            MaterialResultCategory::Invalid => invalid += 1,
            MaterialResultCategory::Binding => binding += 1,
            _ => panic!("data-only material validation returned a live-state error"),
        }
    }
    assert!(
        valid > 0 && invalid > 0 && binding > 0,
        "material categories not exercised"
    );
    assert!(
        path_positions.len() == material.notes.len() * 32,
        "material witness path coverage incomplete"
    );
}

#[test]
fn consolidated_material_validation_matches_every_scope_field_and_both_audiences() {
    let (material, scope, _) = fixture();
    for local_audience in [false, true] {
        let mut scope = scope.clone();
        if local_audience {
            scope.version = 2;
            scope.reviewers = scope
                .reviewers
                .iter()
                .map(|reviewer| {
                    ConstructionReviewerV1::local_installed_signer(reviewer.account_id().into())
                })
                .collect();
        }
        assert_material_validation_category(&material, &scope, MaterialResultCategory::Valid);
        let original = material_test_value(serde_json::to_value(&scope));
        let mut mutations = Vec::new();
        material_json_mutations(&original, "", &mut mutations);
        let mut valid = 0;
        let mut invalid = 0;
        let mut binding = 0;
        let mut schema_rejected = 0;
        for (pointer, replacement) in mutations {
            let mut changed = original.clone();
            *changed
                .pointer_mut(&pointer)
                .unwrap_or_else(|| panic!("scope mutation path missing")) = replacement;
            assert!(changed != original, "scope mutation did not change data");
            // Invalid enum tags and malformed optional/array values cannot
            // become a typed scope. Keep them in the exhaustive field walk and
            // check their rejection rather than silently skipping such fields.
            let changed: DurableConstructionScopeV1 = match serde_json::from_value(changed) {
                Ok(changed) => changed,
                Err(_) => {
                    schema_rejected += 1;
                    continue;
                }
            };
            match assert_material_validation_matches_frozen(&material, &changed) {
                // The independent oracle in the comparison also ensures that
                // scope changes cannot contaminate the material-only digest.
                MaterialResultCategory::Valid => valid += 1,
                MaterialResultCategory::Invalid => invalid += 1,
                MaterialResultCategory::Binding => binding += 1,
                _ => panic!("data-only scope validation returned a live-state error"),
            }
        }
        assert!(
            valid > 0 && invalid > 0 && binding > 0 && schema_rejected > 0,
            "scope categories not exercised"
        );
    }
}

#[test]
fn consolidated_material_validation_preserves_bounds_and_error_precedence() {
    let (material, scope, _) = fixture();
    // These APIs retain their independent validating contracts and byte bounds.
    let encoded = material_test_value(material.encode());
    let decoded = material_test_value(HistoricalConstructionMaterialV1::decode(&encoded));
    assert!(decoded == material, "material roundtrip changed");
    assert_material_validation_category(&decoded, &scope, MaterialResultCategory::Valid);
    let mut padded = Zeroizing::new(encoded.to_vec());
    padded.resize(MAX_MATERIAL_BYTES, b' ');
    assert!(
        HistoricalConstructionMaterialV1::decode(&padded).is_ok(),
        "exact material byte limit changed"
    );
    padded.push(b' ');
    assert!(
        material_result_category(&HistoricalConstructionMaterialV1::decode(&padded))
            == MaterialResultCategory::Invalid,
        "oversized material bytes accepted"
    );
    assert!(
        material_result_category(&HistoricalConstructionMaterialV1::decode(&[]))
            == MaterialResultCategory::Invalid,
        "empty material bytes accepted"
    );

    let mut bad_material = material.clone();
    bad_material.source.source_id = "x".repeat(MAX_MATERIAL_BYTES + 1);
    assert_material_validation_category(&bad_material, &scope, MaterialResultCategory::Invalid);
    assert!(
        material_result_category(&bad_material.digest()) == MaterialResultCategory::Invalid
            && material_result_category(&bad_material.encode()) == MaterialResultCategory::Invalid,
        "standalone material APIs skipped validation"
    );
    bad_material = material.clone();
    bad_material.notes = vec![material.notes[0].clone(); MAX_SELECTED_NOTES + 1];
    assert_material_validation_category(&bad_material, &scope, MaterialResultCategory::Invalid);
    bad_material.notes = vec![material.notes[0].clone(); MAX_SELECTED_NOTES];
    assert_material_validation_category(&bad_material, &scope, MaterialResultCategory::Binding);
    bad_material.notes.clear();
    assert_material_validation_category(&bad_material, &scope, MaterialResultCategory::Invalid);

    // Scope validation precedes material mathematics. Mixed failures preserve
    // the same category instead of accidentally prioritizing material checks.
    bad_material = material.clone();
    bad_material.fvk_digest = "00".repeat(32);
    let mut bad_scope = scope.clone();
    bad_scope.purpose.clear();
    assert_material_validation_category(&bad_material, &bad_scope, MaterialResultCategory::Invalid);
    bad_material.version = 0;
    bad_scope = scope.clone();
    bad_scope.reviewers.pop();
    assert_material_validation_category(&bad_material, &bad_scope, MaterialResultCategory::Binding);

    // Fill otherwise-valid optional extension data up to the existing exact
    // serialized scope byte limit, then exceed it by just one byte.
    let mut bounded_scope = scope.clone();
    bounded_scope.proposal.manifest.agreement.extensions = (0..9)
        .map(|index| Extension {
            name: format!("padding-{index}"),
            required: false,
            schema_version: 1,
            value: serde_json::Value::String(String::new()),
        })
        .collect();
    let limit = 128 * 1024;
    let initial = material_test_value(serde_json::to_vec(&bounded_scope)).len();
    assert!(initial < limit, "scope size fixture exceeds limit");
    let mut remaining = limit - initial;
    for extension in &mut bounded_scope.proposal.manifest.agreement.extensions {
        let fill = remaining.min(16_382);
        extension.value = serde_json::Value::String("x".repeat(fill));
        remaining -= fill;
    }
    assert!(remaining == 0, "scope size fixture padding incomplete");
    assert!(
        material_test_value(serde_json::to_vec(&bounded_scope)).len() == limit,
        "scope size fixture is not exact"
    );
    assert_material_validation_category(&material, &bounded_scope, MaterialResultCategory::Valid);
    let last = bounded_scope
        .proposal
        .manifest
        .agreement
        .extensions
        .last_mut()
        .unwrap_or_else(|| panic!("scope size fixture missing extension"));
    last.value = serde_json::Value::String("x".into());
    assert!(
        material_test_value(serde_json::to_vec(&bounded_scope)).len() == limit + 1,
        "oversized scope fixture is not exact"
    );
    assert_material_validation_category(&material, &bounded_scope, MaterialResultCategory::Invalid);
}

#[test]
fn consolidated_material_validation_preserves_exact_scope_bindings_after_success() {
    let (material, scope, owners) = fixture();
    assert_material_validation_category(&material, &scope, MaterialResultCategory::Valid);

    let mut changed_scope = scope.clone();
    changed_scope.account_id = owners[1].account_id.clone();
    changed_scope.participant_id = "participant-1".into();
    assert_material_validation_category(&material, &changed_scope, MaterialResultCategory::Binding);

    changed_scope = scope.clone();
    changed_scope.proposal.manifest.expiry_height = material.context.tip_height;
    assert_material_validation_category(&material, &changed_scope, MaterialResultCategory::Binding);

    changed_scope = scope.clone();
    changed_scope.minimum_confirmations =
        material.context.tip_height - material.context.anchor_height + 2;
    assert_material_validation_category(&material, &changed_scope, MaterialResultCategory::Binding);

    changed_scope = scope.clone();
    let input = changed_scope
        .proposal
        .manifest
        .inputs
        .iter_mut()
        .find(|input| input.account_id == material.account_id)
        .unwrap_or_else(|| panic!("scope binding fixture missing input"));
    input.input_id.push_str("-changed");
    assert_material_validation_category(&material, &changed_scope, MaterialResultCategory::Binding);

    // Reconcile the proposal independently so a wrong claimed input amount
    // reaches the material join instead of failing proposal arithmetic first.
    changed_scope = scope.clone();
    let input = changed_scope
        .proposal
        .manifest
        .inputs
        .iter_mut()
        .find(|input| input.account_id == material.account_id)
        .unwrap_or_else(|| panic!("scope binding fixture missing input"));
    input.amount = material_test_value(Amount::from_zatoshis(input.amount.as_zatoshis() + 1));
    let returned = changed_scope
        .proposal
        .manifest
        .outputs
        .iter_mut()
        .find(|output| {
            matches!(
                &output.allocation,
                OutputAllocation::Return { account_id, .. } if *account_id == material.account_id
            )
        })
        .unwrap_or_else(|| panic!("scope binding fixture missing return"));
    returned.amount = material_test_value(Amount::from_zatoshis(returned.amount.as_zatoshis() + 1));
    assert_material_validation_category(&material, &changed_scope, MaterialResultCategory::Binding);

    let mut changed_material = material.clone();
    changed_material.requested_debit_zatoshis += 1;
    assert_material_validation_category(&changed_material, &scope, MaterialResultCategory::Binding);
    // Restoring the actual data restores the same result; no successful result
    // from an earlier invocation authorizes a later mutated object.
    changed_material.requested_debit_zatoshis -= 1;
    assert_material_validation_category(&changed_material, &scope, MaterialResultCategory::Valid);
}
