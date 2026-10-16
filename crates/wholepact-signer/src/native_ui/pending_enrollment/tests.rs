use super::*;

#[test]
fn cancellation_erases_drafts_without_minting_owner_or_decision() {
    let mut ui = PendingEnrollmentUi::default();
    ui.certificate.push_str("private certificate path");
    ui.key.push_str("private credential path");
    ui.destination.push_str("private export path");
    ui.history_setup.push_str("private descriptive setup");
    ui.confirmation.push_str("AUTHORIZE modeled-input-only");
    ui.clear();
    assert!(ui.owner.is_none() && ui.opened.is_none() && ui.review.is_none());
    assert!(ui.certificate.is_empty() && ui.key.is_empty() && ui.destination.is_empty());
    assert!(ui.history_setup.is_empty() && ui.confirmation.is_empty());
    assert!(!ui.is_active());
}

#[test]
fn cancellation_does_not_block_or_release_worker_slot_early() {
    let (release, wait) = mpsc::sync_channel(1);
    let (send, receive) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let _ = wait.recv();
        let _ = send.send(Err(Error::Uncertain));
    });
    let mut ui = PendingEnrollmentUi::default();
    ui.job = Some(Job { receive, thread });
    ui.clear();
    assert!(ui.is_active());
    assert!(ui.job.is_some());
    // This models a stalled worker only. No native owner, decision, key,
    // authenticated vault/history or publication capability is fabricated.
    release.send(()).unwrap();
    let job = ui.job.take().unwrap();
    job.thread.join().unwrap();
    assert!(job.receive.try_recv().unwrap().is_err());
}

#[test]
fn absent_owner_cannot_start_or_confirm_a_pending_step() {
    let mut ui = PendingEnrollmentUi::default();
    assert!(ui.current_owner(0).is_err());
    assert!(ui.consume_review(true, 0).is_err());
    assert!(ui.prepare_action(Action::History, 0).is_err());
    assert!(ui.job.is_none());
}

#[test]
fn history_json_cannot_supply_an_origin_history_or_approval() {
    for field in [
        "endpoint",
        "policy",
        "history",
        "approved",
        "decision",
        "native_owner",
    ] {
        let mut input = serde_json::json!({
            "trusted_server_root_der": "/synthetic/root.der",
            "owner_certificate_der": "/synthetic/owner.der",
            "owner_private_key_pkcs8_der": "/synthetic/owner.key",
            "operator_name": "synthetic operator",
            "retention_statement": "synthetic statement"
        });
        input[field] = serde_json::json!(true);
        assert!(
            history::parse_setup_for_test(&input.to_string()).is_err(),
            "{field}"
        );
    }
}
