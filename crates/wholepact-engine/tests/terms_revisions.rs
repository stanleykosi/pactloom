//! Never-funded synthetic draft metadata. No signer, provider, proof or network.
use serde_json::json;
use std::sync::{Arc, Barrier};
use wholepact_core::{AgreementDraft, Amount, ParticipationIntent};
use wholepact_engine::{Access, Engine};
use wholepact_store::{CommandContext, Store, authority::ReleaseIntent};

fn owner() -> Access {
    Access {
        principal_id: "draft-owner".into(),
        include_owned_agreements: true,
        ..Default::default()
    }
}
fn draft() -> AgreementDraft {
    serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap()
}
fn changed() -> AgreementDraft {
    let mut terms = draft();
    terms.revision = 2;
    terms.purpose = "Revised synthetic procurement terms".into();
    terms
}
fn setup(e: &Engine) {
    e.create(&owner(), "draft-create-command", draft()).unwrap();
}
fn revise(
    e: &Engine,
    key: &str,
    revision: u64,
    terms: AgreementDraft,
) -> wholepact_engine::Result<wholepact_engine::Mutation> {
    e.revise_agreement(&owner(), key, &draft().agreement_id, revision, terms)
}
fn intent() -> ParticipationIntent {
    serde_json::from_value(json!({"intent_id":"synthetic-intent","agreement_id":draft().agreement_id,"participant_id":"synthetic-person","desired_contribution":"1000000000","maximum_net_debit":"1000010000","fee_cap":"10000","conditions":[],"valid_until":null,"status":"active"})).unwrap()
}

#[test]
fn revisions_keep_identity_history_and_unknown_exposure_across_reopen_and_uncertain_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-metadata.sqlite");
    let e = Engine::open(&path).unwrap();
    setup(&e);
    let saved = revise(&e, "draft-revision-command", 1, changed()).unwrap();
    assert_eq!(saved.agreement.agreement, changed());
    assert_eq!(saved.agreement.terms_history, [draft()]);
    assert!(saved.agreement.terms_editability.allowed);
    assert_eq!(saved.agreement.authorization_exposure, "unknown");
    assert_eq!(saved.agreement.chain_observation, "unknown");
    assert_eq!(saved.agreement.revision, 2);
    drop(e); // Model a lost successful response; retry exact request after reopen.
    let e = Engine::open(&path).unwrap();
    let replay = revise(&e, "draft-revision-command", 1, changed()).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, saved.operation_id);
    assert_eq!(replay.event_sequence, saved.event_sequence);
    assert_eq!(replay.agreement.terms_history, [draft()]);
    let mut third = changed();
    third.revision = 3;
    third.purpose = "Third exact terms".into();
    revise(&e, "draft-third-revision", 2, third.clone()).unwrap();
    let current = e.get(&owner(), &draft().agreement_id).unwrap();
    assert_eq!(current.terms_history, [draft(), changed()]);
    assert_eq!(current.agreement, third);
    assert_eq!(
        e.operation(&owner(), &saved.operation_id).unwrap()["result"]["agreement"]["agreement"]["revision"],
        2
    );
    let events = e.events(&owner(), 0, 100).unwrap();
    assert_eq!(events.as_array().unwrap().len(), 3);
    assert_eq!(events[1]["kind"], "agreement_terms_revised");
    assert_eq!(
        events[1]["payload"],
        json!({"id":draft().agreement_id,"revision":2})
    );
}

#[test]
fn previews_and_reviews_stay_immutable_and_journal_revision_is_not_terms_revision() {
    let e = Engine::in_memory().unwrap();
    setup(&e);
    let p = e
        .propose(&owner(), "draft-preview-command", &draft().agreement_id, 1)
        .unwrap();
    let proposal = p.agreement.proposals[0].clone();
    let reviewed = e
        .review(&owner(), "draft-review-command", &proposal.proposal_id, 2)
        .unwrap();
    let report = serde_json::to_value(&reviewed.agreement.verification_reports[0]).unwrap();
    assert_eq!(reviewed.agreement.agreement.revision, 1);
    let revised = revise(&e, "draft-revise-reviewed", 3, changed()).unwrap();
    assert_eq!(revised.agreement.revision, 4);
    assert_eq!(revised.agreement.agreement.revision, 2);
    assert_eq!(revised.agreement.proposals[0].manifest, proposal.manifest);
    assert_eq!(
        serde_json::to_value(&revised.agreement.verification_reports[0]).unwrap(),
        report
    );
    let p2 = e
        .propose(&owner(), "draft-preview-second", &draft().agreement_id, 4)
        .unwrap();
    let comparison = e
        .compare_proposals(
            &owner(),
            &proposal.proposal_id,
            &p2.agreement.proposals[1].proposal_id,
        )
        .unwrap();
    assert!(comparison.material_change && comparison.renewed_review_required);
    assert!(!comparison.signable);
    assert!(
        comparison
            .changes
            .iter()
            .any(|c| c.field == "agreement.purpose")
    );
    assert!(
        comparison
            .changes
            .iter()
            .any(|c| c.field == "agreement.revision")
    );
}

#[test]
fn exact_scope_ownership_stale_terms_cas_and_idempotency_conflicts_refuse_without_writes() {
    let e = Engine::in_memory().unwrap();
    setup(&e);
    let id = draft().agreement_id;
    let mut other = Access {
        principal_id: "other".into(),
        ..Default::default()
    };
    assert_eq!(
        e.revise_agreement(&other, "draft-hidden-request", &id, 1, changed())
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );
    other.agreement_ids.insert(id.clone());
    assert_eq!(
        e.revise_agreement(&other, "draft-other-request", &id, 1, changed())
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
    let mut stale = changed();
    stale.revision = 3;
    assert_eq!(
        revise(&e, "draft-stale-terms-key", 1, stale)
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    let saved = revise(&e, "draft-original-key", 1, changed()).unwrap();
    assert_eq!(
        revise(&e, "draft-stale-journal", 1, changed())
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    let mut different = changed();
    different.purpose.push_str(" changed payload");
    assert_eq!(
        revise(&e, "draft-original-key", 1, different)
            .unwrap_err()
            .code,
        "IDEMPOTENCY_CONFLICT"
    );
    let unscoped_owner = Access {
        principal_id: owner().principal_id,
        ..Default::default()
    };
    assert_eq!(
        e.revise_agreement(&unscoped_owner, "draft-original-key", &id, 1, changed())
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );
    assert!(e.operation(&unscoped_owner, &saved.operation_id).is_err());
    assert_eq!(e.get(&owner(), &id).unwrap().revision, 2);
}

#[test]
fn invalid_amounts_identity_profile_and_no_op_leave_original_terms_untouched() {
    let e = Engine::in_memory().unwrap();
    setup(&e);
    for field in [
        "agreement_id",
        "obligation_id",
        "organizer_identity",
        "network_profile_id",
    ] {
        let mut value = serde_json::to_value(changed()).unwrap();
        value[field] = json!("changed-identity");
        let error = revise(
            &e,
            &format!("invalid-field-{field}"),
            1,
            serde_json::from_value(value).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            error.code.as_str(),
            "INVALID_TERMS" | "UNSUPPORTED_CAPABILITY"
        ));
    }
    let mut privacy = changed();
    privacy.privacy_profile.dedicated_accounts_required = false;
    assert_eq!(
        revise(&e, "invalid-privacy-key", 1, privacy)
            .unwrap_err()
            .code,
        "INVALID_TERMS"
    );
    let mut zero = changed();
    zero.recipients[0].amount = Amount::ZERO;
    assert!(revise(&e, "invalid-zero-amount", 1, zero).is_err());
    let mut wrong_total = changed();
    wrong_total.recipients[0].amount = Amount::from_zatoshis(1).unwrap();
    assert_eq!(
        revise(&e, "invalid-total-amount", 1, wrong_total)
            .unwrap_err()
            .code,
        "CONSERVATION_FAILURE"
    );
    for amount in [
        json!(-1),
        json!(1.2),
        json!("-1"),
        json!("1.2"),
        json!("2100000000000001"),
    ] {
        let mut value = serde_json::to_value(changed()).unwrap();
        value["recipients"][0]["amount"] = amount;
        assert!(serde_json::from_value::<AgreementDraft>(value).is_err());
    }
    let mut same = draft();
    same.revision = 2;
    assert_eq!(
        revise(&e, "invalid-no-op-terms", 1, same).unwrap_err().code,
        "INVALID_TERMS"
    );
    assert_eq!(
        e.get(&owner(), &draft().agreement_id).unwrap().agreement,
        draft()
    );
    assert_eq!(
        e.events(&owner(), 0, 100)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn concurrent_revisions_have_one_winner_and_duplicate_commands_one_event() {
    let e = Arc::new(Engine::in_memory().unwrap());
    setup(&e);
    let barrier = Arc::new(Barrier::new(3));
    let jobs: Vec<_> = (0..2)
        .map(|i| {
            let e = e.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                revise(&e, &format!("racing-command-{i:04}"), 1, changed())
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results.iter().find_map(|r| r.as_ref().err()).unwrap().code,
        "REVISION_CONFLICT"
    );
    let e = Arc::new(Engine::in_memory().unwrap());
    setup(&e);
    let barrier = Arc::new(Barrier::new(3));
    let jobs: Vec<_> = (0..2)
        .map(|_| {
            let e = e.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                revise(&e, "duplicate-command-key", 1, changed())
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = jobs
        .into_iter()
        .map(|j| j.join().unwrap().unwrap())
        .collect();
    assert_eq!(results[0].operation_id, results[1].operation_id);
    assert_eq!(
        e.events(&owner(), 0, 100)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn participation_withdrawal_cancellation_and_foreign_review_never_reopen_editing() {
    let id = draft().agreement_id;
    for scenario in ["intent", "withdrawn", "cancel", "foreign-review"] {
        let e = Engine::in_memory().unwrap();
        setup(&e);
        let revision = match scenario {
            "intent" | "withdrawn" => {
                e.add_intent(&owner(), "draft-intent-command", &id, 1, intent())
                    .unwrap();
                if scenario == "withdrawn" {
                    e.withdraw(
                        &owner(),
                        "draft-withdraw-command",
                        &id,
                        &intent().intent_id,
                        2,
                    )
                    .unwrap();
                    3
                } else {
                    2
                }
            }
            "cancel" => {
                e.cancel(&owner(), "draft-cancel-command", &id, 1).unwrap();
                2
            }
            _ => {
                let p = e
                    .propose(&owner(), "draft-preview-command", &id, 1)
                    .unwrap();
                let other = Access {
                    principal_id: "other".into(),
                    agreement_ids: [id.clone()].into(),
                    ..Default::default()
                };
                let shared = e.get(&other, &id).unwrap();
                assert_eq!(shared.revision, 3);
                e.review(
                    &other,
                    "draft-other-review",
                    &p.agreement.proposals[0].proposal_id,
                    3,
                )
                .unwrap();
                4
            }
        };
        assert!(
            !e.get(&owner(), &id).unwrap().terms_editability.allowed,
            "{scenario}"
        );
        assert_eq!(
            revise(&e, "draft-closed-command", revision, changed())
                .unwrap_err()
                .code,
            "INVALID_TRANSITION"
        );
        assert_eq!(
            e.get(&owner(), &id).unwrap().authorization_exposure,
            "unknown"
        );
    }
}

#[test]
fn durable_non_draft_lineage_refuses_even_if_local_candidates_and_intents_are_missing() {
    for kind in [
        "intent_recorded",
        "transport_peer_grant_created",
        "candidate_constructed",
        "native_request_queued",
        "cancellation_requested",
        "unknown_future_lifecycle",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.sqlite");
        let e = Engine::open(&path).unwrap();
        setup(&e);
        let store = Store::open(&path).unwrap();
        let original = store.get_agreement(&draft().agreement_id).unwrap().unwrap();
        let command = CommandContext::for_request(
            owner().principal_id,
            "fixture-durable-history",
            &json!({"fixture":kind}),
        )
        .unwrap();
        // Deliberately omit lifecycle objects; retained event history must still close the window.
        store
            .update_agreement(&command, &draft().agreement_id, 1, original.payload, kind)
            .unwrap();
        assert!(
            !e.get(&owner(), &draft().agreement_id)
                .unwrap()
                .terms_editability
                .allowed,
            "{kind}"
        );
        assert_eq!(
            revise(&e, "draft-missing-candidates", 2, changed())
                .unwrap_err()
                .code,
            "INVALID_TRANSITION"
        );
    }
}

#[test]
fn independent_obligation_exposure_is_never_cleared_or_inferred_away() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.sqlite");
    let e = Engine::open(&path).unwrap();
    setup(&e);
    let store = Store::open(&path).unwrap();
    store
        .initialize_authority_account("synthetic-account", 1)
        .unwrap();
    let release = ReleaseIntent {
        authorization_id: "synthetic-authorization".into(),
        account_id: "synthetic-account".into(),
        writer_epoch: 1,
        obligation_id: draft().obligation_id,
        proposal_id: "separate-synthetic-proposal".into(),
        manifest_digest: "11".repeat(32),
        effects_digest: "22".repeat(32),
        artifact_digest: "33".repeat(32),
        maximum_debit: "100".into(),
        input_ids: vec!["synthetic-input".into()],
        aggregate_budget_limit: "1000".into(),
    };
    store.record_authorization_release_intent(&release).unwrap();
    store
        .mark_authorization_released(&release.authorization_id)
        .unwrap();
    let before = store.exposure(&release.authorization_id).unwrap();
    assert_eq!(
        revise(&e, "draft-exposure-refusal", 1, changed())
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    assert_eq!(
        store
            .exposure(&release.authorization_id)
            .unwrap()
            .unwrap()
            .state,
        before.unwrap().state
    );
    assert_eq!(store.outstanding_debit("synthetic-account").unwrap(), "100");
    assert_eq!(
        e.get(&owner(), &draft().agreement_id)
            .unwrap()
            .authorization_exposure,
        "unknown"
    );
}

#[test]
fn terms_history_is_bounded_and_damaged_history_is_not_silently_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.sqlite");
    let e = Engine::open(&path).unwrap();
    setup(&e);
    for revision in 2..=64 {
        let mut terms = changed();
        terms.revision = revision;
        terms.purpose = format!("Synthetic terms {revision}");
        revise(
            &e,
            &format!("bounded-revision-{revision:04}"),
            u64::from(revision - 1),
            terms,
        )
        .unwrap();
    }
    let view = e.get(&owner(), &draft().agreement_id).unwrap();
    assert_eq!(view.terms_history.len(), 63);
    assert!(!view.terms_editability.allowed);
    let mut too_many = changed();
    too_many.revision = 65;
    assert_eq!(
        revise(&e, "bounded-revision-over", 64, too_many)
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    let store = Store::open(&path).unwrap();
    let mut record = store.get_agreement(&draft().agreement_id).unwrap().unwrap();
    record.payload["view"]["terms_history"][0]["obligation_id"] = json!("different-obligation");
    let context =
        CommandContext::for_request("test", "synthetic-corrupt-history", &json!({"test":true}))
            .unwrap();
    store
        .update_agreement(
            &context,
            &record.id,
            record.revision,
            record.payload,
            "synthetic_corruption",
        )
        .unwrap();
    assert_eq!(
        e.get(&owner(), &draft().agreement_id).unwrap_err().code,
        "RECOVERY_REQUIRED"
    );
}

#[test]
fn encrypted_backup_keeps_history_and_restore_refuses_edits_and_old_replay() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = wholepact_storage_security::DatabaseKey::from_bytes([123; 32]); // Public synthetic fixture only.
    let source = dir.path().join("source.sqlite");
    let e = Engine::from_store(Store::create_encrypted(&source, &key).unwrap());
    setup(&e);
    revise(&e, "draft-backup-revision", 1, changed()).unwrap();
    drop(e);
    let store = Store::open_encrypted(&source, &key).unwrap();
    let archive = dir.path().join("archive.sqlite");
    store.backup_agreement_journal(&archive, &key).unwrap();
    let restored = dir.path().join("restored.sqlite");
    wholepact_store::backup::restore_agreement_journal(&archive, &key, &restored, &key).unwrap();
    let e = Engine::from_store(Store::open_encrypted(&restored, &key).unwrap());
    let view = e.get(&owner(), &draft().agreement_id).unwrap();
    assert_eq!(view.terms_history, [draft()]);
    assert!(!view.terms_editability.allowed);
    let mut terms = changed();
    terms.revision = 3;
    terms.purpose = "Forbidden recovered edit".into();
    assert_eq!(
        revise(&e, "draft-restored-refusal", 2, terms)
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
    assert_eq!(
        revise(&e, "draft-backup-revision", 1, changed())
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
}

#[test]
fn legacy_origin_is_not_assumed_unshared_and_foreign_read_closure_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.sqlite");
    let e = Engine::open(&path).unwrap();
    setup(&e);
    let source = Store::open(&path).unwrap();
    let mut legacy = source
        .get_agreement(&draft().agreement_id)
        .unwrap()
        .unwrap()
        .payload;
    legacy
        .as_object_mut()
        .unwrap()
        .remove("terms_editing_origin");
    let destination = Store::in_memory().unwrap();
    let command = CommandContext::for_request(
        owner().principal_id,
        "legacy-creation-fixture",
        &json!({"legacy":true}),
    )
    .unwrap();
    destination
        .create_agreement(&command, &draft().agreement_id, legacy)
        .unwrap();
    let historical = Engine::from_store(destination);
    assert!(
        !historical
            .get(&owner(), &draft().agreement_id)
            .unwrap()
            .terms_editability
            .allowed
    );
    assert_eq!(
        revise(&historical, "legacy-revision-refused", 1, changed())
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    let reader = Access {
        principal_id: "shared-reader".into(),
        agreement_ids: [draft().agreement_id].into(),
        ..Default::default()
    };
    let shared = e.get(&reader, &draft().agreement_id).unwrap();
    assert_eq!(shared.revision, 2);
    assert!(!shared.terms_editability.allowed);
    assert_eq!(shared.agreement.revision, 1);
    assert_eq!(e.get(&reader, &draft().agreement_id).unwrap().revision, 2);
    drop(e);
    let e = Engine::open(&path).unwrap();
    assert_eq!(
        revise(&e, "shared-revision-refused", 2, changed())
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    assert_eq!(
        e.events(&owner(), 0, 100).unwrap()[1]["kind"],
        "terms_editing_closed_before_shared_read"
    );
}

#[cfg(feature = "transport-workflows")]
mod invitation_closure {
    use super::*;
    use wholepact_engine::transport_workflows::InvitationExportRequest;
    use wholepact_transport::*;

    fn now() -> Timestamp {
        Timestamp::from_unix_seconds(1_790_000_000).unwrap()
    }
    fn request(e: &Engine) -> InvitationExportRequest {
        InvitationExportRequest {
            expected_agreement_revision: 1,
            transport: ExportRequest {
                context: MessageContext {
                    network_profile_id: draft().network_profile_id,
                    agreement_id: draft().agreement_id,
                    proposal_id: "synthetic-invitation".into(),
                    proposal_revision: 1,
                    sender_id: draft().organizer_identity,
                    recipient_id: "synthetic-recipient".into(),
                    artifact_kind: ArtifactKind::Invitation,
                },
                order: MessageOrder {
                    message_id: "12".repeat(16),
                    sequence: 1,
                    issued_at: now(),
                    expires_at: Timestamp::from_unix_seconds(now().unix_seconds() + 600).unwrap(),
                },
                purpose: "Synthetic private invitation".into(),
                persistence_warning: "Recipient can retain the invitation".into(),
            },
            invitation: PrivateInvitation {
                schema_version: 1,
                invitation_id: "34".repeat(16),
                organizer_key_fingerprint: secret(22).public_key().unwrap().fingerprint(),
                invited_participant_id: "synthetic-recipient".into(),
                agreement_manifest_digest: e
                    .invitation_agreement_digest(&owner(), &draft().agreement_id)
                    .unwrap(),
                offered_roles: vec![InvitationRole::Contributor],
                purpose: draft().purpose,
                recipient_summary: "Synthetic unverified recipient".into(),
                fee_summary: "Unverified pro-rata fees".into(),
                visibility_summary: "Read-only metadata".into(),
                coordination_deadline: Timestamp::from_unix_seconds(now().unix_seconds() + 1200)
                    .unwrap(),
            },
        }
    }
    fn secret(byte: u8) -> TransportSecret {
        TransportSecret::from_bytes([byte; 32]).unwrap()
    }
    fn prepare(
        e: &Engine,
        request: InvitationExportRequest,
    ) -> wholepact_engine::Result<PreparedExport> {
        e.prepare_private_invitation(
            &owner(),
            request,
            &secret(22).public_key().unwrap(),
            &secret(11).public_key().unwrap(),
            &now(),
        )
    }
    #[test]
    fn invitation_preparation_closes_editing_before_export_and_exact_retry_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.sqlite");
        let e = Engine::open(&path).unwrap();
        setup(&e);
        let original = request(&e);
        let prepared = prepare(&e, original).unwrap();
        let fingerprint = prepared.preview().digest().unwrap();
        assert_eq!(e.get(&owner(), &draft().agreement_id).unwrap().revision, 2);
        assert_eq!(
            revise(&e, "invitation-revision-refused", 2, changed())
                .unwrap_err()
                .code,
            "INVALID_TRANSITION"
        );
        // Disclosure approval deliberately fails. Closure is monotonic even when
        // no ciphertext escaped, and no local retry invents another agreement.
        assert!(
            prepared
                .seal(&secret(22), &"ff".repeat(32), &now())
                .is_err()
        );
        drop(e);
        let e = Engine::open(&path).unwrap();
        let retry = prepare(&e, request(&e)).unwrap();
        assert_eq!(retry.preview().digest().unwrap(), fingerprint);
        assert_eq!(e.get(&owner(), &draft().agreement_id).unwrap().revision, 2);
        assert!(
            !e.get(&owner(), &draft().agreement_id)
                .unwrap()
                .terms_editability
                .allowed
        );
        e.cancel(
            &owner(),
            "cancel-after-invitation",
            &draft().agreement_id,
            2,
        )
        .unwrap();
        assert_eq!(
            prepare(&e, request(&e)).err().unwrap().code,
            "INVALID_TERMS"
        );
    }
    #[test]
    fn concurrent_invitation_preparation_and_revision_cannot_both_succeed() {
        for _ in 0..8 {
            let e = Arc::new(Engine::in_memory().unwrap());
            setup(&e);
            let original = request(&e);
            let barrier = Arc::new(Barrier::new(3));
            let first = {
                let e = e.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    prepare(&e, original).is_ok()
                })
            };
            let second = {
                let e = e.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    revise(&e, "race-invitation-revision", 1, changed()).is_ok()
                })
            };
            barrier.wait();
            let results = [first.join().unwrap(), second.join().unwrap()];
            assert_eq!(results.into_iter().filter(|v| *v).count(), 1);
            let view = e.get(&owner(), &draft().agreement_id).unwrap();
            assert_eq!(view.revision, 2);
            assert_eq!(view.terms_editability.allowed, view.agreement.revision == 2);
        }
    }
}
