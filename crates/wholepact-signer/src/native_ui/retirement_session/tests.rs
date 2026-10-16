//! Synthetic review-machine and restriction/channel fixtures only. Even the
//! positive paths below invoke no attended UI, AuthenticatedPeer, authenticated
//! reply, socket, provider, proof, live signing key, or actual transport delivery.
use super::*;
use crate::native_ui::authority::recovery_test_authority;

const EPOCH: u64 = 7;

fn entry_controls(deadline: Instant) -> Arc<SessionControls> {
    Arc::new(SessionControls {
        cancelled: AtomicBool::new(false),
        stage: AtomicU8::new(SessionStage::Entry as u8),
        request: OnceLock::new(),
        endpoint: OnceLock::new(),
        source_account_id: OnceLock::new(),
        source_native: Arc::new(recovery_test_authority()),
        destination_native: Arc::new(recovery_test_authority()),
        parent_channel: None,
        deadline,
        focus_epoch: EPOCH,
    })
}
fn synthetic_request(deadline: Instant) -> RequestRestrictions {
    RequestRestrictions {
        channel: Cancellation::SyntheticRestrictionOnly,
        reply: RetirementEvidenceReplyBinding::synthetic_for_test(deadline, "61".repeat(32)),
    }
}
fn controls(deadline: Instant) -> Arc<SessionControls> {
    let controls = entry_controls(deadline);
    controls
        .advance_stage(SessionStage::Entry, SessionStage::Pairing)
        .unwrap();
    controls
        .register_request(synthetic_request(deadline))
        .unwrap();
    controls
        .source_account_id
        .set("synthetic-source".into())
        .unwrap();
    controls
}
fn exchange(
    controls: Arc<SessionControls>,
) -> (
    RetirementEvidenceSession,
    SyncSender<SessionReview>,
    Receiver<PhaseDecision>,
) {
    let (review_sender, reviews) = mpsc::sync_channel(1);
    let (decisions, decision_receiver) = mpsc::sync_channel(1);
    (
        RetirementEvidenceSession {
            controls,
            reviews,
            decisions,
            next_review: Some(ReviewPhase::Source),
            pending_review: None,
            worker: None,
        },
        review_sender,
        decision_receiver,
    )
}
fn click(mut review: ExactNativeReview) -> NativeDecision {
    let entered = format!("AUTHORIZE {}", &review.digest()[..12]);
    review.continue_from_native_click(true, EPOCH).unwrap();
    review.consume_native_click(true, EPOCH, &entered).unwrap()
}
fn staged_decision(native: &NativeAuthority, digest: &str) -> NativeDecision {
    click(ExactNativeReview::stage(native, digest, "synthetic review only".into(), EPOCH).unwrap())
}
fn send_review(phase: ReviewPhase, controls: &SessionControls, sender: &SyncSender<SessionReview>) {
    let digest = match phase {
        ReviewPhase::Pairing => "60".repeat(32),
        ReviewPhase::Source => "71".repeat(32),
        ReviewPhase::Destination => "82".repeat(32),
    };
    publish_review(
        phase,
        controls,
        sender,
        &digest,
        "synthetic review only".into(),
    )
    .unwrap();
}
fn drain_ready(session: &RetirementEvidenceSession) {
    let limit = Instant::now() + Duration::from_secs(5);
    while !session.is_finished() {
        assert!(Instant::now() < limit, "synthetic worker did not drain");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn synthetic_exchange_orders_two_exact_review_machine_decisions_once() {
    let controls = controls(Instant::now() + Duration::from_secs(5));
    let (mut session, sender, receiver) = exchange(Arc::clone(&controls));
    assert_eq!(session.focus_epoch(), EPOCH);
    assert_eq!(session.source_account_id(), Some("synthetic-source"));
    for phase in [ReviewPhase::Source, ReviewPhase::Destination] {
        send_review(phase, &controls, &sender);
        let review = session.try_review().unwrap().unwrap();
        assert_eq!(review.phase, phase);
        assert!(session.try_review().unwrap().is_none());
        let digest = review.exact.digest().to_owned();
        session.submit_decision(phase, click(review.exact)).unwrap();
        let accepted = wait_step(phase, &controls, &receiver, controls.deadline)
            .unwrap()
            .unwrap();
        assert_eq!(accepted.reviewed_digest(), digest);
        assert!(accepted.binding() == &controls.native(phase).binding());
    }
    assert!(session.next_review.is_none());
    let duplicate = staged_decision(&controls.destination_native, &"82".repeat(32));
    assert!(
        session
            .submit_decision(ReviewPhase::Destination, duplicate)
            .is_err()
    );
    assert!(controls.source_native.check_current().is_err());
    assert!(controls.destination_native.check_current().is_err());
}

#[test]
fn synthetic_exchange_rejects_destination_first_and_wrong_phase_submission() {
    let controls = controls(Instant::now() + Duration::from_secs(5));
    let (mut session, sender, _receiver) = exchange(Arc::clone(&controls));
    send_review(ReviewPhase::Destination, &controls, &sender);
    assert!(session.try_review().is_err());
    assert!(controls.check_current().is_err());

    let controls = self::controls(Instant::now() + Duration::from_secs(5));
    let (mut session, sender, _receiver) = exchange(Arc::clone(&controls));
    send_review(ReviewPhase::Source, &controls, &sender);
    let review = session.try_review().unwrap().unwrap();
    assert!(
        session
            .submit_decision(ReviewPhase::Destination, click(review.exact))
            .is_err()
    );
}

#[test]
fn synthetic_exchange_rejects_stale_digest_and_different_native_instance() {
    for other_native in [false, true] {
        let controls = controls(Instant::now() + Duration::from_secs(5));
        let (mut session, sender, _receiver) = exchange(Arc::clone(&controls));
        send_review(ReviewPhase::Source, &controls, &sender);
        let review = session.try_review().unwrap().unwrap();
        let replacement = recovery_test_authority();
        let decision = if other_native {
            staged_decision(&replacement, review.exact.digest())
        } else {
            staged_decision(&controls.source_native, &"93".repeat(32))
        };
        assert!(
            session
                .submit_decision(ReviewPhase::Source, decision)
                .is_err()
        );
        assert!(controls.check_current().is_err());
    }
}

#[test]
fn synthetic_worker_step_rejects_wrong_phase_even_without_gui_filter() {
    let controls = controls(Instant::now() + Duration::from_secs(5));
    let (sender, receiver) = mpsc::sync_channel(1);
    sender
        .try_send(PhaseDecision {
            phase: ReviewPhase::Source,
            decision: staged_decision(&controls.source_native, &"71".repeat(32)),
        })
        .unwrap_or_else(|_| panic!("synthetic channel unexpectedly closed"));
    assert!(
        wait_step(
            ReviewPhase::Destination,
            &controls,
            &receiver,
            controls.deadline
        )
        .is_err()
    );
}

#[test]
fn synthetic_original_request_deadline_expires_without_gui_redraw_or_refresh() {
    let original_deadline = Instant::now() + Duration::from_millis(100);
    let controls = controls(original_deadline);
    let (sender, receiver) = mpsc::sync_channel(1);
    sender
        .try_send(PhaseDecision {
            phase: ReviewPhase::Source,
            decision: staged_decision(&controls.source_native, &"71".repeat(32)),
        })
        .unwrap_or_else(|_| panic!("synthetic channel unexpectedly closed"));
    assert!(
        wait_step(ReviewPhase::Source, &controls, &receiver, original_deadline)
            .unwrap()
            .is_some()
    );
    let retained = Arc::clone(&controls);
    let worker = thread::spawn(move || {
        // A later phase's ceiling cannot renew the original request lifetime.
        let later_preparation = Instant::now() + Duration::from_secs(120);
        loop {
            match wait_step(
                ReviewPhase::Destination,
                &retained,
                &receiver,
                later_preparation,
            ) {
                Ok(None) => {}
                Ok(Some(_)) => panic!("no synthetic destination decision was sent"),
                Err(error) => {
                    retained.cancel();
                    return Err::<(), _>(error);
                }
            }
        }
    });
    assert!(worker.join().unwrap().is_err());
    assert!(Instant::now() >= original_deadline);
    assert!(controls.source_native.check_current().is_err());
    assert!(controls.destination_native.check_current().is_err());
    drop(sender);
}

#[test]
fn synthetic_ui_disappearance_rejects_review_and_decision_channels() {
    let controls = controls(Instant::now() + Duration::from_secs(5));
    let (reviews, disappeared) = mpsc::sync_channel(1);
    drop(disappeared);
    assert!(
        publish_review(
            ReviewPhase::Source,
            &controls,
            &reviews,
            &"71".repeat(32),
            "synthetic".into()
        )
        .is_err()
    );
    let (decisions, receiver) = mpsc::sync_channel(1);
    drop(decisions);
    assert!(wait_step(ReviewPhase::Source, &controls, &receiver, controls.deadline).is_err());
}

#[test]
fn synthetic_cancel_rejects_already_ready_success_and_drop_joins_worker() {
    let controls = controls(Instant::now() + Duration::from_secs(5));
    let original_source = controls.source_native.binding();
    let original_destination = controls.destination_native.binding();
    let (mut session, _sender, _receiver) = exchange(Arc::clone(&controls));
    session.worker = Some(thread::spawn(|| Ok(())));
    drain_ready(&session);
    session.cancel();
    assert!(session.finish().is_err());
    assert!(original_source.check_current().is_err());
    assert!(original_destination.check_current().is_err());

    let controls = self::controls(Instant::now() + Duration::from_secs(5));
    let (mut session, _sender, receiver) = exchange(Arc::clone(&controls));
    let drained = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&drained);
    session.worker = Some(thread::spawn(move || {
        loop {
            if wait_step(ReviewPhase::Source, &controls, &receiver, controls.deadline).is_err() {
                break;
            }
        }
        observed.store(true, Ordering::Release);
        Err(Error::Locked)
    }));
    drop(session);
    assert!(drained.load(Ordering::Acquire));
}

#[test]
fn synthetic_completion_distinguishes_terminal_reply_close_from_cancellation() {
    let pending_controls = controls(Instant::now() + Duration::from_secs(5));
    let (pending, _sender, _receiver) = exchange(Arc::clone(&pending_controls));
    assert!(pending.check_ui_poll_current().is_ok());
    pending_controls
        .request
        .get()
        .unwrap()
        .reply
        .cancel_for_test();
    // A pending review must still reject an independently closed channel.
    assert!(pending.check_ui_poll_current().is_err());
    assert!(pending.check_current().is_err());

    for invalidation in 0..3 {
        let controls = controls(Instant::now() + Duration::from_secs(5));
        let (mut session, sender, receiver) = exchange(Arc::clone(&controls));
        for phase in [ReviewPhase::Source, ReviewPhase::Destination] {
            send_review(phase, &controls, &sender);
            let review = session.try_review().unwrap().unwrap();
            session.submit_decision(phase, click(review.exact)).unwrap();
            assert!(
                wait_step(phase, &controls, &receiver, controls.deadline)
                    .unwrap()
                    .is_some()
            );
        }
        // Restriction-only model of the sender's terminal close while joining
        // is still pending. Both exact machine decisions were submitted above.
        controls.request.get().unwrap().reply.cancel_for_test();
        assert!(session.check_current().is_err());
        assert!(session.check_ui_poll_current().is_ok());
        assert!(controls.completion(Ok(())).is_ok());
        match invalidation {
            0 => session.cancel(),
            1 => controls.source_native.revoke_informational_now(),
            _ => controls.destination_native.revoke_informational_now(),
        }
        assert!(session.check_ui_poll_current().is_err());
        assert!(controls.completion(Ok(())).is_err());
    }
}

#[test]
fn synthetic_worker_unwind_guard_revokes_both_original_owners() {
    let controls = controls(Instant::now() + Duration::from_secs(5));
    let source = controls.source_native.binding();
    let destination = controls.destination_native.binding();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = WorkerFailureGuard {
            controls: &controls,
            succeeded: false,
        };
        panic!("synthetic worker failure; no transport invoked");
    }));
    assert!(source.check_current().is_err());
    assert!(destination.check_current().is_err());
}

#[test]
fn synthetic_pairing_precedes_evidence_and_cannot_serve_as_source_decision() {
    let controls = entry_controls(Instant::now() + Duration::from_secs(5));
    let (mut session, sender, receiver) = exchange(Arc::clone(&controls));
    session.next_review = Some(ReviewPhase::Pairing);
    assert_eq!(session.source_account_id(), None);
    assert!(controls.check_current().is_ok());
    assert!(controls.require_phase(ReviewPhase::Pairing).is_err());
    assert!(controls.require_phase(ReviewPhase::Source).is_err());
    controls
        .advance_stage(SessionStage::Entry, SessionStage::Pairing)
        .unwrap();
    send_review(ReviewPhase::Pairing, &controls, &sender);
    let review = session.try_review().unwrap().unwrap();
    session
        .submit_decision(ReviewPhase::Pairing, click(review.exact))
        .unwrap();
    let pairing = wait_step(
        ReviewPhase::Pairing,
        &controls,
        &receiver,
        controls.deadline,
    )
    .unwrap()
    .unwrap();
    assert_eq!(pairing.reviewed_digest(), "60".repeat(32));
    assert_eq!(session.next_review, Some(ReviewPhase::Source));
    assert!(controls.require_phase(ReviewPhase::Source).is_err());
    controls
        .register_request(synthetic_request(controls.deadline))
        .unwrap();
    assert!(controls.require_phase(ReviewPhase::Pairing).is_err());
    send_review(ReviewPhase::Source, &controls, &sender);
    let _source = session.try_review().unwrap().unwrap();
    assert!(
        session
            .submit_decision(ReviewPhase::Source, pairing)
            .is_err()
    );
    assert!(controls.check_current().is_err());
}

#[test]
fn synthetic_evidence_stage_never_accepts_missing_request_restrictions() {
    let controls = entry_controls(Instant::now() + Duration::from_secs(5));
    assert!(controls.check_current().is_ok());
    assert!(controls.completion(Ok(())).is_err());
    controls
        .advance_stage(SessionStage::Entry, SessionStage::Pairing)
        .unwrap();
    assert!(
        controls
            .advance_stage(SessionStage::Pairing, SessionStage::Entry)
            .is_err()
    );
    controls
        .advance_stage(SessionStage::Pairing, SessionStage::Evidence)
        .unwrap();
    assert!(controls.check_entry_current().is_ok());
    assert!(controls.check_current().is_err());
    assert!(controls.completion(Ok(())).is_err());
    assert!(
        controls
            .advance_stage(SessionStage::Entry, SessionStage::Pairing)
            .is_err()
    );
    let (mut session, _sender, _receiver) = exchange(controls);
    session.next_review = None; // Terminal GUI state is not a substitute reply.
    assert!(session.check_ui_poll_current().is_err());
}

#[test]
fn synthetic_request_registration_is_single_assignment_and_cancels_late_handles() {
    let controls = entry_controls(Instant::now() + Duration::from_secs(5));
    controls
        .advance_stage(SessionStage::Entry, SessionStage::Pairing)
        .unwrap();
    controls.cancel();
    let late = synthetic_request(controls.deadline);
    let binding = late.reply.clone();
    assert!(controls.register_request(late).is_err());
    assert!(binding.check_current().is_err());

    let controls = self::controls(Instant::now() + Duration::from_secs(5));
    let original = controls.request.get().unwrap().reply.clone();
    let duplicate = synthetic_request(controls.deadline);
    let rejected = duplicate.reply.clone();
    assert!(controls.register_request(duplicate).is_err());
    assert!(original.check_current().is_err());
    assert!(rejected.check_current().is_err());
    assert!(controls.source_native.check_current().is_err());
    assert!(controls.destination_native.check_current().is_err());
}

#[test]
fn synthetic_registration_cancel_race_leaves_no_live_request_restrictions() {
    for _ in 0..64 {
        let controls = entry_controls(Instant::now() + Duration::from_secs(5));
        controls
            .advance_stage(SessionStage::Entry, SessionStage::Pairing)
            .unwrap();
        let request = synthetic_request(controls.deadline);
        let binding = request.reply.clone();
        let start = Arc::new(std::sync::Barrier::new(2));
        let worker_controls = Arc::clone(&controls);
        let worker_start = Arc::clone(&start);
        let worker = thread::spawn(move || {
            worker_start.wait();
            worker_controls.register_request(request)
        });
        start.wait();
        controls.cancel();
        let _ = worker.join().unwrap();
        assert!(binding.check_current().is_err());
        assert!(controls.check_current().is_err());
        assert!(controls.source_native.check_current().is_err());
        assert!(controls.destination_native.check_current().is_err());
    }
}

#[test]
fn entry_deadline_is_a_nonrenewable_bounded_ceiling() {
    assert!(require_entry_ceiling(Instant::now() + Duration::from_secs(60)).is_ok());
    assert!(require_entry_ceiling(Instant::now()).is_err());
    assert!(require_entry_ceiling(Instant::now() + Duration::from_secs(121)).is_err());
}

#[test]
fn entry_paths_reject_missing_alias_and_overlapping_runtime_trees_without_creation() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let destination = temp.path().join("destination");
    let runtime = temp.path().join("runtime");
    for path in [&source, &destination, &runtime] {
        std::fs::create_dir(path).unwrap();
    }
    let inputs = |source_root: PathBuf, destination_root: PathBuf, runtime_directory: PathBuf| {
        RetirementSessionInputs {
            source_root,
            destination_root,
            runtime_directory,
            source_password: Zeroizing::new(Vec::new()),
            destination_password: Zeroizing::new(Vec::new()),
        }
    };
    let mut valid = inputs(source.clone(), destination.clone(), runtime.clone());
    validate_input_paths(&mut valid).unwrap();
    assert!(valid.runtime_directory.is_absolute());
    let missing = temp.path().join("missing");
    assert!(
        validate_input_paths(&mut inputs(
            source.clone(),
            destination.clone(),
            missing.clone()
        ))
        .is_err()
    );
    assert!(!missing.exists());
    assert!(
        validate_input_paths(&mut inputs(source.clone(), source.clone(), runtime.clone())).is_err()
    );
    let nested = source.join("local-apps");
    std::fs::create_dir(&nested).unwrap();
    assert!(
        validate_input_paths(&mut inputs(source.clone(), destination.clone(), nested)).is_err()
    );
    assert!(
        validate_input_paths(&mut inputs(
            source.clone(),
            destination.clone(),
            temp.path().to_path_buf()
        ))
        .is_err()
    );
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&source, &alias).unwrap();
    assert!(validate_input_paths(&mut inputs(source, alias, runtime)).is_err());
}

#[cfg(feature = "synthetic-qualification")]
mod vaults {
    use super::*;
    use crate::{
        account::PendingAccount,
        native_ui::{
            retirement_destination::{PreparedRecoveryDestination, RecoveryDestinationRequest},
            retirement_recipient::RetirementEvidenceRecipient,
            retirement_source::PreparedRetirementSource,
        },
    };
    use sha2::{Digest, Sha256};

    const PASSWORD: &[u8] = b"public-synthetic-session-fixture";
    fn vault(root: &std::path::Path, index: u8) -> AccountVault {
        let pending = PendingAccount::fixed_never_funded_qualification(index).unwrap();
        let words = pending.recovery_words().unwrap();
        AccountVault::create(root, pending.verify_backup(&words).unwrap(), PASSWORD).unwrap()
    }
    fn request(
        source: &AccountVault,
        destination: &AccountVault,
        recipient: &RetirementEvidenceRecipient,
    ) -> RecoveryDestinationRequest {
        RecoveryDestinationRequest {
            operation_id: "synthetic-session-original-preparation".into(),
            destination_account_id: destination.account_id().unwrap(),
            address: wholepact_protocol::review::encode_testnet_receiver(
                &destination
                    .account()
                    .fvk()
                    .unwrap()
                    .address_at(0u32, orchard::keys::Scope::External),
            ),
            network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
            source_account_id: source.account_id().unwrap(),
            source_fvk_digest: hex::encode(Sha256::digest(
                source.account().fvk().unwrap().to_bytes(),
            )),
            local_recipient: recipient.grant_id().into(),
        }
    }

    #[test]
    fn never_funded_prelude_preserves_source_journal_eligibility_and_lock() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        let mut source = vault(&root, 0);
        let id = source.account_id().unwrap();
        let journal = source.create_authority_journal().unwrap();
        assert!(!journal.account_state().unwrap().recovery_required);
        drop(journal);
        drop(source);
        let (source, journal) = unlock_source(
            &root,
            PASSWORD,
            &entry_controls(Instant::now() + Duration::from_secs(60)),
        )
        .unwrap();
        assert_eq!(source.account_id().unwrap(), id);
        assert!(matches!(
            AccountVault::unlock(&root, PASSWORD),
            Err(Error::AlreadyOpen)
        ));
        journal.require_recovery().unwrap();
        assert!(matches!(
            require_source_eligibility(&source, &journal),
            Err(Error::RecoveryRequired)
        ));
        drop(journal);
        drop(source);
        assert!(matches!(
            unlock_source(
                &root,
                PASSWORD,
                &entry_controls(Instant::now() + Duration::from_secs(60))
            ),
            Err(Error::RecoveryRequired)
        ));
    }

    #[test]
    fn never_funded_prelude_rejects_missing_source_journal_instead_of_activating() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        drop(vault(&root, 0));
        assert!(!root.join("authority.sqlite").exists());
        assert!(matches!(
            unlock_source(
                &root,
                PASSWORD,
                &entry_controls(Instant::now() + Duration::from_secs(60))
            ),
            Err(Error::RecoveryRequired)
        ));
        assert!(!root.join("authority.sqlite").exists());
        assert!(
            AccountVault::unlock(&root, PASSWORD)
                .unwrap()
                .account()
                .recovery_required()
        );
    }

    #[test]
    fn never_funded_expired_post_kdf_entry_refuses_source_journal_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        drop(vault(&root, 0));
        // Fixed never-funded vault unlock only; model the already-expired
        // original entry at the post-KDF boundary. No native entry or IPC runs.
        let source = AccountVault::unlock(&root, PASSWORD).unwrap();
        assert!(!source.account().recovery_required());
        let expired = entry_controls(Instant::now());
        assert!(matches!(
            retain_source_journal(source, &expired),
            Err(Error::Locked)
        ));
        assert!(!root.join("authority.sqlite").exists());
        let source = AccountVault::unlock(&root, PASSWORD).unwrap();
        assert!(!source.account().recovery_required());
    }

    #[test]
    fn never_funded_destination_eligibility_rejects_same_account_and_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let source = vault(&temp.path().join("source"), 0);
        let same = vault(&temp.path().join("same"), 0);
        let destination = vault(&temp.path().join("destination"), 1);
        assert!(require_destination_eligibility(&source, &destination).is_ok());
        assert!(matches!(
            require_destination_eligibility(&source, &same),
            Err(Error::ReviewMismatch)
        ));
        let pending = PendingAccount::fixed_never_funded_qualification(1).unwrap();
        let words = pending.recovery_words().unwrap();
        let recovered =
            crate::account::DedicatedAccount::recover(&words, 0, "synthetic-recovery".into())
                .unwrap();
        let recovered =
            AccountVault::persist_recovered(&temp.path().join("recovered"), recovered, PASSWORD)
                .unwrap();
        assert!(matches!(
            require_destination_eligibility(&source, &recovered),
            Err(Error::RecoveryRequired)
        ));
    }

    #[test]
    fn synthetic_two_review_waits_retain_original_nonce_bearing_preparations() {
        let temp = tempfile::tempdir().unwrap();
        let source = vault(&temp.path().join("source"), 0);
        let destination = vault(&temp.path().join("destination"), 1);
        let controls = controls(Instant::now() + Duration::from_secs(5));
        let recipient = RetirementEvidenceRecipient::synthetic_for_session_test(
            source.account_id().unwrap(),
            &controls.source_native,
            controls.deadline,
        )
        .unwrap();
        let request = request(&source, &destination, &recipient);
        let (mut session, sender, receiver) = exchange(Arc::clone(&controls));
        let prepared = PreparedRetirementSource::prepare_with_recipient(
            &source,
            &controls.source_native,
            &request,
            Some(recipient.clone()),
        )
        .unwrap();
        let repeated = PreparedRetirementSource::prepare_with_recipient(
            &source,
            &controls.source_native,
            &request,
            Some(recipient.clone()),
        )
        .unwrap();
        assert_ne!(prepared.digest(), repeated.digest());
        let source_digest = prepared.digest().to_owned();
        let stale_source = staged_decision(&controls.source_native, prepared.digest());
        assert!(
            repeated
                .approve(&source, &controls.source_native, stale_source)
                .is_err()
        );
        publish_review(
            ReviewPhase::Source,
            &controls,
            &sender,
            prepared.digest(),
            prepared.display(),
        )
        .unwrap();
        let review = session.try_review().unwrap().unwrap();
        session
            .submit_decision(review.phase, click(review.exact))
            .unwrap();
        prepared.check_current(&source).unwrap();
        let decision = wait_step(ReviewPhase::Source, &controls, &receiver, controls.deadline)
            .unwrap()
            .unwrap();
        prepared.check_current(&source).unwrap();
        let approved_source = prepared
            .approve(&source, &controls.source_native, decision)
            .unwrap();
        assert_eq!(approved_source.review_digest(), source_digest);
        let original_source_deadline = approved_source.deadline();

        let prepared = PreparedRecoveryDestination::prepare_for_retirement_recipient(
            &destination,
            &controls.destination_native,
            request.clone(),
            &approved_source,
            &source,
        )
        .unwrap();
        let repeated = PreparedRecoveryDestination::prepare_for_retirement_recipient(
            &destination,
            &controls.destination_native,
            request.clone(),
            &approved_source,
            &source,
        )
        .unwrap();
        assert_ne!(prepared.digest(), repeated.digest());
        let destination_digest = prepared.digest().to_owned();
        let stale_destination = staged_decision(&controls.destination_native, prepared.digest());
        assert!(
            repeated
                .approve(stale_destination, &controls.destination_native)
                .is_err()
        );
        publish_review(
            ReviewPhase::Destination,
            &controls,
            &sender,
            prepared.digest(),
            prepared.display(),
        )
        .unwrap();
        let review = session.try_review().unwrap().unwrap();
        assert!(review.exact.display().contains(&source_digest));
        session
            .submit_decision(review.phase, click(review.exact))
            .unwrap();
        prepared.check_current().unwrap();
        let decision = wait_step(
            ReviewPhase::Destination,
            &controls,
            &receiver,
            controls.deadline,
        )
        .unwrap()
        .unwrap();
        prepared.check_current().unwrap();
        let approved_destination = prepared
            .approve(decision, &controls.destination_native)
            .unwrap();
        assert_eq!(approved_source.deadline(), original_source_deadline);
        let fact = approved_destination
            .evidence_for_retirement_delivery(&approved_source, &source, &recipient)
            .unwrap();
        assert_eq!(fact.ownership_evidence_digest, destination_digest);
        assert_eq!(fact.address, request.address);
        // This is an in-memory informational fact, never an authenticated reply.
        assert!(!crate::automation_supported());
    }

    #[test]
    fn synthetic_cancel_keeps_both_actual_vaults_until_worker_drain() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let destination_path = temp.path().join("destination");
        let source = vault(&source_path, 0);
        let destination = vault(&destination_path, 1);
        let controls = controls(Instant::now() + Duration::from_secs(5));
        let source_binding = controls.source_native.binding();
        let destination_binding = controls.destination_native.binding();
        let (mut session, _sender, receiver) = exchange(Arc::clone(&controls));
        let (started, ready) = mpsc::sync_channel(1);
        let (drain, release) = mpsc::sync_channel(1);
        session.worker = Some(thread::spawn(move || {
            started.send(()).unwrap();
            loop {
                if wait_step(ReviewPhase::Source, &controls, &receiver, controls.deadline).is_err()
                {
                    break;
                }
            }
            // Model a previously admitted terminal operation still draining.
            release.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(source.account_id().is_ok());
            assert!(destination.account_id().is_ok());
            drop((source, destination));
            Err(Error::Locked)
        }));
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        session.cancel();
        assert!(source_binding.check_current().is_err());
        assert!(destination_binding.check_current().is_err());
        assert!(!session.is_finished());
        assert!(session.finish().is_err()); // Must not consume/drop/join the owner.
        assert!(matches!(
            AccountVault::unlock(&source_path, PASSWORD),
            Err(Error::AlreadyOpen)
        ));
        assert!(matches!(
            AccountVault::unlock(&destination_path, PASSWORD),
            Err(Error::AlreadyOpen)
        ));
        drain.send(()).unwrap();
        drain_ready(&session);
        assert!(session.finish().is_err());
        assert!(AccountVault::unlock(&source_path, PASSWORD).is_ok());
        assert!(AccountVault::unlock(&destination_path, PASSWORD).is_ok());
    }
}
