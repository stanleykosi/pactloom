//! Pure byte, clock and restriction policy fixtures. These do not construct an
//! AuthenticatedPeer, native approval, account, credential or actual socket.
use super::*;
use std::collections::VecDeque;
use wholepact_signer_origin::retirement_evidence::{NETWORK_PROFILE_ID, PURPOSE};

fn request() -> RetirementDestinationEvidenceRequestV1 {
    RetirementDestinationEvidenceRequestV1 {
        schema_version: 1,
        purpose: PURPOSE.into(),
        operation_id: "synthetic-retirement-request".into(),
        request_nonce: "a".repeat(64),
        source_account_id: "synthetic-source-account".into(),
        network_profile_id: NETWORK_PROFILE_ID.into(),
        address: "utest1syntacticfixtureonly".into(),
    }
}

#[test]
fn staged_admission_requires_exact_dedicated_scope_and_rejects_other_modes() {
    let request = request();
    let scope = request.pair_scope().unwrap();
    assert!(
        validate_staged_admission(
            StagedEndpointClass::RetirementEvidenceOnly,
            &request,
            &scope,
        )
        .is_ok()
    );
    for mode in [
        StagedEndpointClass::Ordinary,
        StagedEndpointClass::QuarantinedV5,
    ] {
        assert!(validate_staged_admission(mode, &request, &scope).is_err());
    }
    for index in 0..7 {
        let mut changed = scope.clone();
        match index {
            0 => changed.account_id.push('x'),
            1 => changed.agreement_id.push('x'),
            2 => changed.participant_id.push('x'),
            3 => changed.manifest_digest = "b".repeat(64),
            4 => changed.history_read = true,
            5 => changed.authorization_export = true,
            6 => changed.preconstruction_export = true,
            _ => unreachable!(),
        }
        assert!(
            validate_staged_admission(
                StagedEndpointClass::RetirementEvidenceOnly,
                &request,
                &changed,
            )
            .is_err()
        );
    }
    let mut replayed_as_new_request = request.clone();
    replayed_as_new_request.request_nonce = "b".repeat(64);
    assert!(
        validate_staged_admission(
            StagedEndpointClass::RetirementEvidenceOnly,
            &replayed_as_new_request,
            &scope,
        )
        .is_err()
    );
}

#[test]
fn dedicated_envelope_is_strict_and_generic_requests_remain_closed() {
    let value = serde_json::json!({
        "schema_version": 1,
        "grant_id": "c".repeat(64),
        "token_hex": "d".repeat(64),
        "request": request(),
    });
    assert!(serde_json::from_value::<RetirementRequestEnvelopeV1>(value.clone()).is_ok());
    for (field, injected) in [
        ("verified", serde_json::json!(true)),
        ("peer", serde_json::json!({"pid": 42})),
        ("deadline", serde_json::json!(u64::MAX)),
        ("command", serde_json::json!("request")),
    ] {
        let mut changed = value.clone();
        changed[field] = injected;
        assert!(serde_json::from_value::<RetirementRequestEnvelopeV1>(changed).is_err());
    }
    for operation in [
        "retirement_destination_observation",
        "request_retirement_destination_evidence_v1",
        "request_retirement_evidence",
    ] {
        assert!(
            serde_json::from_value::<super::super::AppRequest>(serde_json::json!({
                "operation": operation,
                "request": request(),
            }))
            .is_err()
        );
    }
}

#[test]
fn encoded_cap_counts_newline_and_refuses_growth_before_append() {
    let exact = "x".repeat(FRAME_LIMIT - 3); // JSON quotes plus newline.
    let encoded = encode_frame(&exact).unwrap();
    assert_eq!(encoded.len(), FRAME_LIMIT);
    assert_eq!(encoded.last(), Some(&b'\n'));
    assert!(encode_frame(&(exact + "x")).is_err());

    let mut frame = BoundedFrame {
        bytes: Zeroizing::new(Vec::with_capacity(FRAME_LIMIT)),
    };
    frame.write_all(&vec![b'x'; FRAME_LIMIT - 1]).unwrap();
    let capacity = frame.bytes.capacity();
    assert!(frame.write_all(b"x").is_err());
    assert_eq!(frame.bytes.len(), FRAME_LIMIT - 1);
    assert_eq!(frame.bytes.capacity(), capacity);
}

#[test]
fn reply_binding_rejects_same_request_on_another_channel_and_cannot_renew() {
    let deadline = Instant::now() + REQUEST_BUDGET;
    let original = RetirementEvidenceReplyBinding::synthetic_for_test(deadline, "a".repeat(64));
    let same = original.clone();
    original.require_same_channel(&same).unwrap();
    original.require_request_digest(&"a".repeat(64)).unwrap();
    assert!(original.require_request_digest(&"b".repeat(64)).is_err());

    let mut another_channel =
        RetirementEvidenceReplyBinding::synthetic_for_test(deadline, "a".repeat(64));
    // Make every scalar identical. Only concrete original channel ownership
    // distinguishes this replacement, as with the same grant and request nonce.
    another_channel.admitted_at = original.admitted_at;
    assert!(original.require_same_channel(&another_channel).is_err());

    let mut renewed = original.clone();
    renewed.deadline += Duration::from_millis(1);
    assert!(original.require_same_channel(&renewed).is_err());
    let mut replaced_request = original.clone();
    replaced_request.request_digest = "b".repeat(64);
    assert!(original.require_same_channel(&replaced_request).is_err());

    original.cancelled.store(true, Ordering::Release);
    assert!(same.check_current().is_err());
    assert!(original.require_same_channel(&same).is_err());
    let expired =
        RetirementEvidenceReplyBinding::synthetic_for_test(Instant::now(), "a".repeat(64));
    assert!(expired.check_current().is_err());
}

enum WriteOutcome {
    Bytes(usize),
    Interrupted,
    Error,
}
#[derive(Clone, Copy)]
enum Restriction {
    None,
    Cancel,
    GrantRevoked,
    NativeRevoked,
    ChannelEvent(libc::c_short),
    UnexpectedInput,
}
struct Step {
    outcome: WriteOutcome,
    elapsed: Duration,
    restriction: Restriction,
}
impl Step {
    fn byte(elapsed: Duration) -> Self {
        Self {
            outcome: WriteOutcome::Bytes(1),
            elapsed,
            restriction: Restriction::None,
        }
    }
}
struct SyntheticIo {
    now: Instant,
    cancelled: Arc<AtomicBool>,
    grant_current: bool,
    native_current: bool,
    channel_event: libc::c_short,
    unexpected_input: bool,
    steps: VecDeque<Step>,
    sent: Vec<u8>,
    timeouts: Vec<Duration>,
    checks: usize,
}
impl SyntheticIo {
    fn new(now: Instant, steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            now,
            cancelled: Arc::new(AtomicBool::new(false)),
            grant_current: true,
            native_current: true,
            channel_event: 0,
            unexpected_input: false,
            steps: steps.into_iter().collect(),
            sent: Vec::new(),
            timeouts: Vec::new(),
            checks: 0,
        }
    }
    fn restrict(&mut self, restriction: Restriction) {
        match restriction {
            Restriction::None => {}
            Restriction::Cancel => self.cancelled.store(true, Ordering::Release),
            Restriction::GrantRevoked => self.grant_current = false,
            Restriction::NativeRevoked => self.native_current = false,
            Restriction::ChannelEvent(event) => self.channel_event = event,
            Restriction::UnexpectedInput => self.unexpected_input = true,
        }
    }
}
impl DeliveryIo for SyntheticIo {
    fn now(&self) -> Instant {
        self.now
    }
    fn check(&mut self) -> Result<()> {
        self.checks += 1;
        if self.cancelled.load(Ordering::Acquire)
            || !self.grant_current
            || !self.native_current
            || self.unexpected_input
        {
            return Err(Error::Authentication);
        }
        require_open_poll_state(self.channel_event)
    }
    fn write(&mut self, bytes: &[u8], timeout: Duration) -> io::Result<usize> {
        self.timeouts.push(timeout);
        let step = self.steps.pop_front().expect("no implicit retry permitted");
        self.now += step.elapsed;
        self.restrict(step.restriction);
        match step.outcome {
            WriteOutcome::Bytes(count) => {
                self.sent
                    .extend_from_slice(&bytes[..count.min(bytes.len())]);
                Ok(count)
            }
            WriteOutcome::Interrupted => Err(io::ErrorKind::Interrupted.into()),
            WriteOutcome::Error => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

#[test]
fn partial_write_checks_each_byte_including_newline_without_deadline_renewal() {
    let start = Instant::now();
    let deadline = start + Duration::from_millis(75);
    let mut io = SyntheticIo::new(start, (0..3).map(|_| Step::byte(Duration::from_millis(20))));
    write_bytes_until(b"{}\n", deadline, &mut io).unwrap();
    assert_eq!(io.sent, b"{}\n");
    assert_eq!(io.checks, 7); // Before/after all three syscalls, then final check.
    assert_eq!(io.timeouts, [75, 55, 35].map(Duration::from_millis),);
}

#[test]
fn interrupted_write_consumes_original_budget_and_late_partial_is_failure() {
    let start = Instant::now();
    let mut io = SyntheticIo::new(
        start,
        [
            Step {
                outcome: WriteOutcome::Interrupted,
                elapsed: Duration::from_millis(40),
                restriction: Restriction::None,
            },
            Step::byte(Duration::from_millis(20)),
        ],
    );
    assert!(write_bytes_until(b"{}\n", start + Duration::from_millis(50), &mut io).is_err());
    assert_eq!(io.sent, b"{"); // The late byte cannot be recalled.
    assert_eq!(io.timeouts, [50, 10].map(Duration::from_millis));
    assert_eq!(io.checks, 4);
}

#[test]
fn queued_expiry_and_preexisting_restrictions_emit_no_bytes() {
    let start = Instant::now();
    let mut expired = SyntheticIo::new(start + Duration::from_secs(120), []);
    assert!(write_bytes_until(b"{}\n", start + Duration::from_secs(120), &mut expired).is_err());
    assert!(expired.sent.is_empty());
    assert!(expired.timeouts.is_empty());

    for restriction in [
        Restriction::Cancel,
        Restriction::GrantRevoked,
        Restriction::NativeRevoked,
        Restriction::ChannelEvent(libc::POLLHUP),
        Restriction::ChannelEvent(libc::POLLRDHUP),
        Restriction::ChannelEvent(libc::POLLERR),
        Restriction::ChannelEvent(libc::POLLNVAL),
        Restriction::UnexpectedInput,
    ] {
        let mut io = SyntheticIo::new(start, []);
        io.restrict(restriction);
        assert!(write_bytes_until(b"{}\n", start + REQUEST_BUDGET, &mut io).is_err());
        assert!(io.sent.is_empty());
        assert!(io.timeouts.is_empty());
    }
}

#[test]
fn live_process_and_current_owners_do_not_override_channel_termination() {
    let start = Instant::now();
    for event in [
        libc::POLLHUP,
        libc::POLLRDHUP,
        libc::POLLERR,
        libc::POLLNVAL,
    ] {
        let mut io = SyntheticIo::new(start, []);
        // This model deliberately leaves all non-channel owners current.
        assert!(io.grant_current && io.native_current);
        io.channel_event = event | libc::POLLIN;
        assert!(write_bytes_until(b"{}\n", start + REQUEST_BUDGET, &mut io).is_err());
        assert!(io.timeouts.is_empty());
    }
}

#[test]
fn every_mid_write_restriction_is_terminal_without_second_write() {
    let start = Instant::now();
    for restriction in [
        Restriction::Cancel,
        Restriction::GrantRevoked,
        Restriction::NativeRevoked,
        Restriction::ChannelEvent(libc::POLLHUP),
        Restriction::ChannelEvent(libc::POLLRDHUP),
        Restriction::UnexpectedInput,
    ] {
        let mut step = Step::byte(Duration::ZERO);
        step.restriction = restriction;
        let mut io = SyntheticIo::new(start, [step]);
        assert!(write_bytes_until(b"{}\n", start + REQUEST_BUDGET, &mut io).is_err());
        assert_eq!(io.sent, b"{");
        assert_eq!(io.timeouts.len(), 1);
    }
}

#[test]
fn late_cancel_or_expiry_on_final_newline_never_reports_completion() {
    let start = Instant::now();
    for cancel in [false, true] {
        let mut final_step = Step::byte(Duration::from_millis(10));
        final_step.restriction = if cancel {
            Restriction::Cancel
        } else {
            Restriction::None
        };
        let mut io = SyntheticIo::new(
            start,
            [
                Step::byte(Duration::ZERO),
                Step::byte(Duration::ZERO),
                final_step,
            ],
        );
        let deadline = start
            + if cancel {
                REQUEST_BUDGET
            } else {
                Duration::from_millis(10)
            };
        assert!(write_bytes_until(b"{}\n", deadline, &mut io).is_err());
        assert_eq!(io.sent, b"{}\n"); // Complete bytes can escape a failed attempt.
        assert_eq!(io.timeouts.len(), 3);
    }
}

#[test]
fn zero_and_error_writes_are_terminal_and_never_retry_a_partial_frame() {
    let start = Instant::now();
    for outcome in [WriteOutcome::Bytes(0), WriteOutcome::Error] {
        let mut io = SyntheticIo::new(
            start,
            [
                Step::byte(Duration::ZERO),
                Step {
                    outcome,
                    elapsed: Duration::ZERO,
                    restriction: Restriction::None,
                },
            ],
        );
        assert!(write_bytes_until(b"{}\n", start + REQUEST_BUDGET, &mut io).is_err());
        assert_eq!(io.sent, b"{");
        assert_eq!(io.timeouts.len(), 2);
    }
}

#[test]
fn malformed_or_multiple_frames_never_enter_write_loop() {
    let start = Instant::now();
    for bytes in [b"".as_slice(), b"{}", b"{}\n{}\n"] {
        let mut io = SyntheticIo::new(start, []);
        assert!(write_bytes_until(bytes, start + REQUEST_BUDGET, &mut io).is_err());
        assert!(io.timeouts.is_empty());
    }
    let mut oversized = vec![b'x'; FRAME_LIMIT + 1];
    *oversized.last_mut().unwrap() = b'\n';
    let mut io = SyntheticIo::new(start, []);
    assert!(write_bytes_until(&oversized, start + REQUEST_BUDGET, &mut io).is_err());
    assert!(io.timeouts.is_empty());
}

#[test]
fn bounded_serialization_rechecks_owner_before_any_write_admission() {
    struct CancelDuringSerialize(Arc<AtomicBool>);
    impl Serialize for CancelDuringSerialize {
        fn serialize<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            self.0.store(true, Ordering::Release);
            serializer.serialize_str("synthetic historical data")
        }
    }
    let start = Instant::now();
    let mut io = SyntheticIo::new(start, []);
    let value = CancelDuringSerialize(Arc::clone(&io.cancelled));
    assert!(encode_frame_until(&value, start + REQUEST_BUDGET, &mut io).is_err());
    assert_eq!(io.checks, 2);
    assert!(io.timeouts.is_empty());
    assert!(io.sent.is_empty());
}
