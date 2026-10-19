//! One nominal fixture's committed-Acquire response loss. Nothing here can
//! manufacture a journal result, session, owner, retry, or source permission.
//! The observation retains inert data only, and has no wait/rearm interface.
use super::*;
use super::durable_payment_server_v1::DurablePaymentServingV1;
use crate::native_witness_owner::DurableAcquireReplyLossArmV1;
use crate::policy::{Event, Ledger};
use rusqlite::Connection;
use std::{collections::BTreeSet, io, sync::Mutex};

struct BaselineV1 {
    admission: OwnerControlRequest,
    acquire_operation_id: String,
    snapshot: AccountSnapshot,
    history_digest: String,
    disclosure: WitnessDisclosureDescriptor,
    row_fingerprints: Vec<[u8; 32]>,
    session_ids: BTreeSet<String>,
}
struct SelectedV1 {
    request: AcquireWriterRequest,
    receipt: WriterSessionReceipt,
    shutdown: Option<std::result::Result<(), io::ErrorKind>>,
    frame_write: Option<FrameWriteV1>,
    retry_receipt: Option<WriterSessionReceipt>,
    retry_count: u64,
}
#[derive(Clone, Copy)]
struct FrameWriteV1 {
    failed: bool,
    first_io_error: Option<io::ErrorKind>,
}
enum PhaseV1 {
    Armed,
    Consumed(SelectedV1),
}
struct StateV1 {
    baseline: BaselineV1,
    phase: PhaseV1,
}
// Each clone made by AuthorityServer shares this single committed scope. No
// journal, listener, source, installation, key, or native lease is retained.
pub(super) struct PlanV1 {
    state: Arc<Mutex<StateV1>>,
}
pub(crate) struct DurableAcquireReplyLossObservationV1 {
    state: Arc<Mutex<StateV1>>,
}
#[derive(Clone, Copy)]
enum CandidateKindV1 {
    Fresh,
    Retry,
}
pub(super) struct CandidateV1<'a> {
    plan: &'a PlanV1,
    request: AcquireWriterRequest,
    kind: CandidateKindV1,
}
pub(super) struct CommittedReplyV1<'a> {
    candidate: CandidateV1<'a>,
    receipt: WriterSessionReceipt,
}
pub(super) struct SelectedReplyV1<'a> {
    plan: &'a PlanV1,
}

impl AuthorityServer {
    /// Only the nominal fixture leaf can construct this arm. Uniqueness prevents
    /// replacing/rearming a scope that might already have accepted connections.
    pub(crate) fn attach_durable_acquire_reply_loss_v1(
        &mut self,
        arm: DurableAcquireReplyLossArmV1,
    ) -> Result<DurableAcquireReplyLossObservationV1> {
        let scope = Arc::get_mut(
            self.durable_payment
                .as_mut()
                .ok_or(AuthorityError::Permission)?,
        )
        .ok_or(AuthorityError::Permission)?;
        let DurablePaymentServingV1::Committed {
            owner,
            acquire_reply_loss,
        } = scope
        else {
            return Err(AuthorityError::Permission);
        };
        if acquire_reply_loss.is_some() {
            return Err(AuthorityError::Permission);
        }
        self.journal.require_born_read_current()?;
        let baseline = {
            let connection = self
                .journal
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let connection = connection.connection();
            let ledger = crate::journal::load(connection)?;
            if owner.require_locked(&self.journal, &ledger)? != arm.admission().operation_id {
                return Err(AuthorityError::Permission);
            }
            BaselineV1::capture(connection, &ledger, arm.admission())?
        };
        self.journal.require_born_read_current()?;
        let state = Arc::new(Mutex::new(StateV1 {
            baseline,
            phase: PhaseV1::Armed,
        }));
        *acquire_reply_loss = Some(PlanV1 {
            state: state.clone(),
        });
        Ok(DurableAcquireReplyLossObservationV1 { state })
    }

    pub(super) fn durable_acquire_reply_loss_candidate_v1(
        &self,
        peer: &str,
        exporter: &[u8; 32],
        request: &WireRequest,
    ) -> Option<CandidateV1<'_>> {
        let DurablePaymentServingV1::Committed {
            acquire_reply_loss: Some(plan),
            ..
        } = self.durable_payment.as_deref()?
        else {
            return None;
        };
        plan.candidate(peer, exporter, request)
    }
}

impl BaselineV1 {
    fn capture(
        connection: &Connection,
        ledger: &Ledger,
        admission: &OwnerControlRequest,
    ) -> Result<Self> {
        ledger.require_supported_durable_payment_history_v1()?;
        let OwnerControl::AdmitDurablePaymentV1 { record } = &admission.control else {
            return Err(AuthorityError::Permission);
        };
        let birth = crate::pending_birth_storage::read(connection, &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        let disclosure = birth.request.disclosure;
        record.validate_request(admission, &disclosure)?;
        let acquire_operation_id = record.acquire_operation_id(admission)?;
        let Some((
            AuthorityMutation::OwnerControl(actual),
            _,
            MutationResult::Controlled(committed),
        )) = ledger.operations.get(&admission.operation_id)
        else {
            return Err(AuthorityError::CorruptHistory);
        };
        if actual != admission
            || ledger.durable_payment_admission_v1(&admission.operation_id)? != Some(admission)
            || ledger.snapshot != *committed
            || admission.expected_head.sequence.checked_add(1) != Some(committed.head.sequence)
            || ledger.policy.account_id != admission.account_id
            || ledger.policy.network_profile_id != admission.network_profile_id
            || ledger.snapshot.writer_epoch != admission.writer_epoch
            || ledger.snapshot.writer_certificate_digest != record.terms.writer_certificate_digest
            || ledger.snapshot.pending_writer_session.is_some()
            || ledger.snapshot.active_writer_session.is_some()
            || ledger.operations.contains_key(&acquire_operation_id)
        {
            return Err(AuthorityError::Permission);
        }
        let row_fingerprints = row_fingerprints(connection)?;
        if row_fingerprints.len() as u64 != committed.head.sequence {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(Self {
            admission: admission.clone(),
            acquire_operation_id,
            snapshot: ledger.snapshot.clone(),
            history_digest: crate::session::history_digest(&ledger.snapshot)?,
            disclosure,
            row_fingerprints,
            session_ids: session_ids(connection)?,
        })
    }
    fn matches_request(&self, peer: &str, request: &AcquireWriterRequest) -> bool {
        peer == self.snapshot.writer_certificate_digest
            && request.operation_id == self.acquire_operation_id
            && request.account_id == self.admission.account_id
            && request.network_profile_id == self.admission.network_profile_id
            && request.writer_epoch == self.admission.writer_epoch
            && request.expected_head == self.snapshot.head
            && request.reconciled_history_digest == self.history_digest
            && request.disclosure == self.disclosure
    }
    fn matches_receipt(
        &self,
        request: &AcquireWriterRequest,
        receipt: &WriterSessionReceipt,
    ) -> bool {
        receipt.session_id == request.session_id
            && receipt.writer_certificate_digest == self.snapshot.writer_certificate_digest
            && receipt.writer_epoch == request.writer_epoch
            && receipt.reconciled_head == request.expected_head
            && receipt.reconciled_history_digest == request.reconciled_history_digest
            && receipt.disclosure == request.disclosure
            && receipt.reconciled_head.sequence.checked_add(1)
                == Some(receipt.acquired_head.sequence)
            && receipt.acquired_at_ms < receipt.expires_at_ms
    }
}
impl PlanV1 {
    fn candidate(
        &self,
        peer: &str,
        exporter: &[u8; 32],
        wire: &WireRequest,
    ) -> Option<CandidateV1<'_>> {
        let WireRequest::Mutate {
            mutation,
            session_proof,
        } = wire
        else {
            return None;
        };
        let AuthorityMutation::AcquireWriter(request) = mutation.as_ref() else {
            return None;
        };
        let state = self.state.lock().ok()?;
        if !state.baseline.matches_request(peer, request) {
            return None;
        }
        let kind = match (&state.phase, session_proof) {
            (PhaseV1::Armed, None)
                if request.session_id == crate::session::session_id(exporter) =>
            {
                CandidateKindV1::Fresh
            }
            (PhaseV1::Consumed(selected), Some(proof))
                if request == &selected.request && proof.session_id == request.session_id =>
            {
                CandidateKindV1::Retry
            }
            _ => return None,
        };
        Some(CandidateV1 {
            plan: self,
            request: request.clone(),
            kind,
        })
    }
}
impl<'a> CandidateV1<'a> {
    /// This receives the actual Result returned by the unchanged per-connection
    /// dispatch, before rejected responses are converted to wire envelopes.
    pub(super) fn after_dispatch(
        self,
        response: &Result<WireResponse>,
    ) -> Option<CommittedReplyV1<'a>> {
        let Ok(WireResponse::Mutation(MutationResult::WriterPending(receipt))) = response else {
            return None;
        };
        let matches = self
            .plan
            .state
            .lock()
            .ok()?
            .baseline
            .matches_receipt(&self.request, receipt);
        matches.then(|| CommittedReplyV1 {
            candidate: self,
            receipt: receipt.clone(),
        })
    }
}
impl<'a> CommittedReplyV1<'a> {
    /// Transport calls this only after its unchanged output-current gate. A
    /// consumed token never resets, and no shared last-result slot is used.
    pub(super) fn after_output_check(self) -> Option<SelectedReplyV1<'a>> {
        let mut state = self.candidate.plan.state.lock().ok()?;
        match (&mut state.phase, self.candidate.kind) {
            (phase @ PhaseV1::Armed, CandidateKindV1::Fresh) => {
                *phase = PhaseV1::Consumed(SelectedV1 {
                    request: self.candidate.request,
                    receipt: self.receipt,
                    shutdown: None,
                    frame_write: None,
                    retry_receipt: None,
                    retry_count: 0,
                });
                // Drop the guard before the caller touches any socket/writer.
                drop(state);
                Some(SelectedReplyV1 {
                    plan: self.candidate.plan,
                })
            }
            (PhaseV1::Consumed(selected), CandidateKindV1::Retry)
                if selected.request == self.candidate.request
                    && selected.receipt == self.receipt =>
            {
                selected.retry_count = selected.retry_count.saturating_add(1);
                if selected.retry_receipt.is_none() {
                    selected.retry_receipt = Some(self.receipt);
                }
                None
            }
            _ => None,
        }
    }
}
impl SelectedReplyV1<'_> {
    pub(super) fn observe_shutdown(&self, result: &io::Result<()>) {
        if let Ok(mut state) = self.plan.state.lock() {
            if let PhaseV1::Consumed(selected) = &mut state.phase {
                if selected.shutdown.is_none() {
                    selected.shutdown = Some(result.as_ref().map(|_| ()).map_err(|e| e.kind()));
                }
            }
        }
    }
    fn observe_frame_write(self, result: &Result<()>, first_io_error: Option<io::ErrorKind>) {
        if let Ok(mut state) = self.plan.state.lock() {
            if let PhaseV1::Consumed(selected) = &mut state.phase {
                if selected.frame_write.is_none() {
                    selected.frame_write = Some(FrameWriteV1 {
                        failed: result.is_err(),
                        first_io_error,
                    });
                }
            }
        }
    }
}
struct FrameIoV1<'a, W> {
    inner: &'a mut W,
    first_io_error: Option<io::ErrorKind>,
}
impl<W> FrameIoV1<'_, W> {
    fn observe<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if self.first_io_error.is_none() {
            self.first_io_error = result.as_ref().err().map(io::Error::kind);
        }
        result
    }
}
impl<W: Write> Write for FrameIoV1<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let result = self.inner.write(bytes);
        self.observe(result)
    }
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let result = self.inner.write_all(bytes);
        self.observe(result)
    }
    fn flush(&mut self) -> io::Result<()> {
        let result = self.inner.flush();
        self.observe(result)
    }
}
pub(super) fn write_frame<T: serde::Serialize>(
    stream: &mut impl Write,
    message: &T,
    admission_observer: Option<&admission_diagnostics_v1::AdmissionWitnessObserverV1>,
    selected: Option<SelectedReplyV1<'_>>,
) -> Result<()> {
    match selected {
        None => admission_diagnostics_v1::write_frame(stream, message, admission_observer),
        Some(selected) => {
            let mut writer = FrameIoV1 {
                inner: stream,
                first_io_error: None,
            };
            let result =
                admission_diagnostics_v1::write_frame(&mut writer, message, admission_observer);
            selected.observe_frame_write(&result, writer.first_io_error);
            // Preserve the actual writer's exact Result and original '?' path.
            result
        }
    }
}

fn row_fingerprints(connection: &Connection) -> Result<Vec<[u8; 32]>> {
    let mut query = connection.prepare(
        "SELECT sequence,operation_id,previous_head,head,payload FROM authority_events ORDER BY sequence",
    )?;
    let mut rows = query.query([])?;
    let mut result = Vec::new();
    let mut bytes = 0_u64;
    while let Some(row) = rows.next()? {
        let sequence: u64 = row.get(0)?;
        let operation: String = row.get(1)?;
        let previous: String = row.get(2)?;
        let head: String = row.get(3)?;
        let payload = Zeroizing::new(row.get::<_, Vec<u8>>(4)?);
        bytes = bytes
            .checked_add(payload.len() as u64)
            .filter(|n| *n <= MAX_JOURNAL_BYTES)
            .ok_or(AuthorityError::Limit)?;
        if result.len() as u64 >= MAX_EVENTS {
            return Err(AuthorityError::Limit);
        }
        let mut hash = Sha256::new();
        hash.update(b"wholepact:synthetic-acquire-reply-loss-row:v1\0");
        hash.update(sequence.to_be_bytes());
        for value in [
            operation.as_bytes(),
            previous.as_bytes(),
            head.as_bytes(),
            payload.as_slice(),
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        result.push(hash.finalize().into());
    }
    Ok(result)
}
fn session_ids(connection: &Connection) -> Result<BTreeSet<String>> {
    let mut query =
        connection.prepare("SELECT session_id FROM authority_session_keys ORDER BY session_id")?;
    let ids = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    Ok(ids)
}
struct ActualAcquireRowV1 {
    sequence: u64,
    operation_id: String,
    previous_head: String,
    head: String,
    event: Event,
}
fn actual_acquire_row(connection: &Connection, operation_id: &str) -> Result<ActualAcquireRowV1> {
    let (sequence, operation_id, previous_head, head, payload): (u64, String, String, String, Vec<u8>) =
        connection.query_row(
            "SELECT sequence,operation_id,previous_head,head,payload FROM authority_events WHERE operation_id=?1",
            [operation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;
    let payload = Zeroizing::new(payload);
    Ok(ActualAcquireRowV1 {
        sequence,
        operation_id,
        previous_head,
        head,
        event: crate::decode(&payload)?,
    })
}
impl DurableAcquireReplyLossObservationV1 {
    pub(crate) fn account_id(&self) -> Result<String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| AuthorityError::Storage)?
            .baseline
            .admission
            .account_id
            .clone())
    }
    /// Called only after the fixture's serving handles reach zero. Unique inert
    /// state also proves that the server plan and connection borrows have ended.
    /// This is a distinct actual persisted-journal audit, not the earlier fresh
    /// commit-return observation and not a DTO-built substitute ledger.
    pub(crate) fn audit(
        self,
        journal: &AuthorityJournal,
        retry: &WriterSessionReceipt,
    ) -> Result<()> {
        let state = Arc::try_unwrap(self.state)
            .map_err(|_| AuthorityError::Permission)?
            .into_inner()
            .map_err(|_| AuthorityError::Storage)?;
        let PhaseV1::Consumed(selected) = state.phase else {
            return Err(AuthorityError::Uncertain);
        };
        require_complete_io(&selected, retry)?;
        journal.require_born_read_current()?;
        let connection = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let connection = connection.connection();
        let ledger = crate::journal::load(connection)?;
        ledger.require_supported_durable_payment_history_v1()?;
        let rows = row_fingerprints(connection)?;
        let ids = session_ids(connection)?;
        let actual = actual_acquire_row(connection, &state.baseline.acquire_operation_id)?;
        require_exact_final_history(
            &state.baseline,
            &selected,
            &ledger,
            &rows,
            &ids,
            &actual,
            retry,
        )?;
        journal.require_born_read_current()?;
        Ok(())
    }
}
fn require_complete_io(selected: &SelectedV1, retry: &WriterSessionReceipt) -> Result<()> {
    if selected.shutdown != Some(Ok(()))
        || !matches!(
            selected.frame_write,
            Some(FrameWriteV1 {
                failed: true,
                first_io_error: Some(_)
            })
        )
        || selected.retry_count != 1
        || selected.retry_receipt.as_ref() != Some(&selected.receipt)
        || retry != &selected.receipt
    {
        return Err(AuthorityError::Uncertain);
    }
    Ok(())
}
fn require_exact_final_history(
    baseline: &BaselineV1,
    selected: &SelectedV1,
    ledger: &Ledger,
    rows: &[[u8; 32]],
    ids: &BTreeSet<String>,
    actual: &ActualAcquireRowV1,
    retry: &WriterSessionReceipt,
) -> Result<()> {
    let mut expected_ids = baseline.session_ids.clone();
    let mut expected_snapshot = baseline.snapshot.clone();
    expected_snapshot.head = selected.receipt.acquired_head.clone();
    expected_snapshot.last_witness_time_ms = selected.receipt.acquired_at_ms;
    expected_snapshot.pending_writer_session = Some(selected.receipt.clone());
    if ledger.snapshot != expected_snapshot
        || !expected_ids.insert(selected.request.session_id.clone())
        || ids != &expected_ids
        || ids.len().checked_sub(baseline.session_ids.len()) != Some(1)
        || rows.len().checked_sub(baseline.row_fingerprints.len()) != Some(1)
        || !rows.starts_with(&baseline.row_fingerprints)
        || baseline.snapshot.head.sequence.checked_add(1) != Some(actual.sequence)
        || actual.operation_id != baseline.acquire_operation_id
        || actual.previous_head != baseline.snapshot.head.digest
        || actual.head != selected.receipt.acquired_head.digest
        || actual.sequence != selected.receipt.acquired_head.sequence
        || actual.event.mutation != AuthorityMutation::AcquireWriter(selected.request.clone())
        || actual.event.authenticated_certificate_digest
            != baseline.snapshot.writer_certificate_digest
        || actual.event.witness_time_ms != selected.receipt.acquired_at_ms
        || actual.event.writer_session_id.is_some()
        || actual.event.original_request_link.is_some()
        || !baseline.matches_request(
            &actual.event.authenticated_certificate_digest,
            &selected.request,
        )
        || !baseline.matches_receipt(&selected.request, &selected.receipt)
        || ledger.snapshot.head != selected.receipt.acquired_head
        || ledger.snapshot.pending_writer_session.as_ref() != Some(&selected.receipt)
        || ledger.snapshot.active_writer_session.is_some()
        || ledger.durable_payment_admission_v1(&baseline.admission.operation_id)?
            != Some(&baseline.admission)
        || ledger.sessions.get(&selected.request.session_id) != Some(&selected.receipt)
        || ledger
            .activated_sessions
            .contains(&selected.request.session_id)
        || retry != &selected.receipt
    {
        return Err(AuthorityError::CorruptHistory);
    }
    let Some((mutation, peer, MutationResult::WriterPending(receipt))) =
        ledger.operations.get(&baseline.acquire_operation_id)
    else {
        return Err(AuthorityError::CorruptHistory);
    };
    if mutation != &actual.event.mutation
        || peer != &actual.event.authenticated_certificate_digest
        || receipt != &selected.receipt
        || receipt != retry
    {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_payment_v1::tests::{admitted_fixture, h};

    const EXPORTER: [u8; 32] = [0x43; 32];
    // Pure predicate/state data, NEVER an actual commit/qualification. No SQL,
    // owner, native entry, source, endpoint, TLS, socket or key store is created.
    fn inert_fixture() -> (
        PlanV1,
        Ledger,
        AcquireWriterRequest,
        WriterSessionReceipt,
        ActualAcquireRowV1,
    ) {
        let (birth, mut ledger, events, admission) = admitted_fixture();
        let OwnerControl::AdmitDurablePaymentV1 { record } = &admission.control else {
            panic!()
        };
        // Retain the real-shaped bootstrap Acquire/Activate prefix and key IDs.
        assert!(
            events
                .iter()
                .any(|e| matches!(&e.mutation, AuthorityMutation::AcquireWriter(_)))
        );
        assert!(events.iter().any(|e| matches!(
            &e.mutation,
            AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ActivateWriter { .. },
                ..
            })
        )));
        let request = AcquireWriterRequest {
            operation_id: record.acquire_operation_id(&admission).unwrap(),
            account_id: admission.account_id.clone(),
            network_profile_id: admission.network_profile_id.clone(),
            writer_epoch: admission.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            reconciled_history_digest: crate::session::history_digest(&ledger.snapshot).unwrap(),
            session_id: crate::session::session_id(&EXPORTER),
            disclosure: birth.request.disclosure,
        };
        let baseline = BaselineV1 {
            admission,
            acquire_operation_id: request.operation_id.clone(),
            snapshot: ledger.snapshot.clone(),
            history_digest: request.reconciled_history_digest.clone(),
            disclosure: request.disclosure.clone(),
            row_fingerprints: events
                .iter()
                .enumerate()
                .map(|(i, _)| [(i + 1) as u8; 32])
                .collect(),
            session_ids: ledger.sessions.keys().cloned().collect(),
        };
        let event = Event {
            mutation: AuthorityMutation::AcquireWriter(request.clone()),
            authenticated_certificate_digest: ledger.snapshot.writer_certificate_digest.clone(),
            witness_time_ms: 129_000,
            writer_session_id: None,
            original_request_link: None,
        };
        let MutationResult::WriterPending(receipt) = ledger.apply(&event).unwrap() else {
            panic!()
        };
        let row = ActualAcquireRowV1 {
            sequence: receipt.acquired_head.sequence,
            operation_id: request.operation_id.clone(),
            previous_head: request.expected_head.digest.clone(),
            head: receipt.acquired_head.digest.clone(),
            event,
        };
        let plan = PlanV1 {
            state: Arc::new(Mutex::new(StateV1 {
                baseline,
                phase: PhaseV1::Armed,
            })),
        };
        (plan, ledger, request, receipt, row)
    }
    fn wire(request: &AcquireWriterRequest) -> WireRequest {
        WireRequest::Mutate {
            mutation: Box::new(AuthorityMutation::AcquireWriter(request.clone())),
            session_proof: None,
        }
    }
    fn reply(receipt: &WriterSessionReceipt) -> Result<WireResponse> {
        Ok(WireResponse::Mutation(MutationResult::WriterPending(
            receipt.clone(),
        )))
    }
    fn armed(plan: &PlanV1) -> bool {
        matches!(plan.state.lock().unwrap().phase, PhaseV1::Armed)
    }
    fn select<'a>(
        plan: &'a PlanV1,
        request: &AcquireWriterRequest,
        receipt: &WriterSessionReceipt,
    ) -> SelectedReplyV1<'a> {
        plan.candidate(
            &receipt.writer_certificate_digest,
            &EXPORTER,
            &wire(request),
        )
        .unwrap()
        .after_dispatch(&reply(receipt))
        .unwrap()
        .after_output_check()
        .unwrap()
    }
    fn proof_wire(request: &AcquireWriterRequest) -> WireRequest {
        WireRequest::Mutate {
            mutation: Box::new(AuthorityMutation::AcquireWriter(request.clone())),
            session_proof: Some(crate::protocol::WriterSessionProof {
                session_id: request.session_id.clone(),
                tag: h('1'),
            }),
        }
    }

    #[test]
    fn pure_acquire_reply_loss_selector_rejects_every_mismatched_binding_without_consuming() {
        let (plan, _, request, receipt, _) = inert_fixture();
        let changes: [fn(&mut AcquireWriterRequest); 9] = [
            |r| r.operation_id.push('x'),
            |r| r.account_id.push('x'),
            |r| r.network_profile_id.push('x'),
            |r| r.writer_epoch += 1,
            |r| r.expected_head.sequence += 1,
            |r| r.expected_head.digest.push('x'),
            |r| r.reconciled_history_digest.push('x'),
            |r| r.disclosure.endpoint.push('x'),
            |r| r.session_id.push('x'),
        ];
        for change in changes {
            let mut changed = request.clone();
            change(&mut changed);
            assert!(
                plan.candidate(
                    &receipt.writer_certificate_digest,
                    &EXPORTER,
                    &wire(&changed)
                )
                .is_none()
            );
            assert!(armed(&plan));
        }
        assert!(
            plan.candidate("wrong-peer", &EXPORTER, &wire(&request))
                .is_none()
        );
        assert!(
            plan.candidate(
                &receipt.writer_certificate_digest,
                &[0x44; 32],
                &wire(&request)
            )
            .is_none()
        );
        assert!(
            plan.candidate(
                &receipt.writer_certificate_digest,
                &EXPORTER,
                &proof_wire(&request)
            )
            .is_none()
        );
        for other in [
            WireRequest::Snapshot {
                account_id: request.account_id.clone(),
                network_profile_id: request.network_profile_id.clone(),
            },
            WireRequest::ReadHistory {
                account_id: request.account_id.clone(),
                network_profile_id: request.network_profile_id.clone(),
                expected_head: request.expected_head.clone(),
                after_sequence: 0,
                maximum_entries: 1,
            },
            WireRequest::Mutate {
                mutation: Box::new(AuthorityMutation::OwnerControl(
                    plan.state.lock().unwrap().baseline.admission.clone(),
                )),
                session_proof: None,
            },
        ] {
            assert!(
                plan.candidate(&receipt.writer_certificate_digest, &EXPORTER, &other)
                    .is_none()
            );
        }
        assert!(armed(&plan));
    }

    #[test]
    fn pure_acquire_reply_loss_requires_success_and_post_output_gate_once() {
        let (plan, _, request, receipt, _) = inert_fixture();
        for response in [
            Err(AuthorityError::Uncertain),
            Ok(WireResponse::Rejected(AuthorityError::Permission)),
        ] {
            assert!(
                plan.candidate(
                    &receipt.writer_certificate_digest,
                    &EXPORTER,
                    &wire(&request)
                )
                .unwrap()
                .after_dispatch(&response)
                .is_none()
            );
            assert!(armed(&plan));
        }
        let mut changed = receipt.clone();
        changed.acquired_head.sequence += 1;
        assert!(
            plan.candidate(
                &receipt.writer_certificate_digest,
                &EXPORTER,
                &wire(&request)
            )
            .unwrap()
            .after_dispatch(&reply(&changed))
            .is_none()
        );
        // An output-check failure drops this local object. It cannot consume.
        drop(
            plan.candidate(
                &receipt.writer_certificate_digest,
                &EXPORTER,
                &wire(&request),
            )
            .unwrap()
            .after_dispatch(&reply(&receipt))
            .unwrap(),
        );
        assert!(armed(&plan));
        let earlier = plan
            .candidate(
                &receipt.writer_certificate_digest,
                &EXPORTER,
                &wire(&request),
            )
            .unwrap()
            .after_dispatch(&reply(&receipt))
            .unwrap();
        let selected = select(&plan, &request, &receipt);
        assert!(earlier.after_output_check().is_none());
        assert!(!armed(&plan));
        assert!(
            plan.candidate(
                &receipt.writer_certificate_digest,
                &EXPORTER,
                &wire(&request)
            )
            .is_none()
        );
        // Inert proof-shaped data tests only routing; real dispatch must verify
        // the genuine original key before a production retry reaches this seam.
        let retry = plan
            .candidate(
                &receipt.writer_certificate_digest,
                &[0x45; 32],
                &proof_wire(&request),
            )
            .unwrap()
            .after_dispatch(&reply(&receipt))
            .unwrap();
        assert!(retry.after_output_check().is_none());
        let state = plan.state.lock().unwrap();
        let PhaseV1::Consumed(actual) = &state.phase else {
            panic!()
        };
        assert!(actual.request == request && actual.receipt == receipt);
        assert_eq!(actual.retry_count, 1);
        assert!(actual.shutdown.is_none() && actual.frame_write.is_none());
        drop(state);
        drop(selected);
    }

    struct CountingWriter {
        bytes: Vec<u8>,
        writes: usize,
        write_alls: usize,
        flushes: usize,
        fail_at: Option<usize>,
    }
    impl CountingWriter {
        fn new(fail_at: Option<usize>) -> Self {
            Self {
                bytes: Vec::new(),
                writes: 0,
                write_alls: 0,
                flushes: 0,
                fail_at,
            }
        }
    }
    impl Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.write_alls += 1;
            if self.fail_at == Some(self.write_alls) {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.fail_at == Some(3) {
                return Err(io::Error::from(io::ErrorKind::ConnectionReset));
            }
            Ok(())
        }
    }
    #[test]
    fn pure_acquire_reply_loss_frame_forwarding_preserves_exact_calls_bytes_and_errors() {
        for fail_at in [None, Some(1), Some(2), Some(3)] {
            let mut expected = CountingWriter::new(fail_at);
            let expected_result = super::super::write_frame(&mut expected, &"inert-frame");
            let mut unobserved = CountingWriter::new(fail_at);
            let unobserved_result = write_frame(&mut unobserved, &"inert-frame", None, None);
            let (plan, _, request, receipt, _) = inert_fixture();
            let mut observed = CountingWriter::new(fail_at);
            let observed_result = write_frame(
                &mut observed,
                &"inert-frame",
                None,
                Some(select(&plan, &request, &receipt)),
            );
            for (actual, result) in [
                (&unobserved, unobserved_result),
                (&observed, observed_result),
            ] {
                assert_eq!(result, expected_result);
                assert_eq!(actual.bytes, expected.bytes);
                assert_eq!(
                    (actual.writes, actual.write_alls, actual.flushes),
                    (expected.writes, expected.write_alls, expected.flushes)
                );
            }
            let state = plan.state.lock().unwrap();
            let PhaseV1::Consumed(actual) = &state.phase else {
                panic!()
            };
            let frame = actual.frame_write.unwrap();
            assert_eq!(frame.failed, fail_at.is_some());
            assert_eq!(
                frame.first_io_error,
                match fail_at {
                    None => None,
                    Some(3) => Some(io::ErrorKind::ConnectionReset),
                    _ => Some(io::ErrorKind::BrokenPipe),
                }
            );
            assert!(actual.shutdown.is_none()); // No socket was ever used.
        }
    }
    #[test]
    fn pure_acquire_reply_loss_io_observer_returns_owned_error_unchanged() {
        let mut inner = CountingWriter::new(None);
        let mut writer = FrameIoV1 {
            inner: &mut inner,
            first_io_error: None,
        };
        let result: io::Result<()> = Err(io::Error::from_raw_os_error(32));
        let returned = writer.observe(result).unwrap_err();
        assert_eq!(returned.raw_os_error(), Some(32));
        assert_eq!(writer.first_io_error, Some(io::ErrorKind::BrokenPipe));
        writer.write(b"a").unwrap();
        writer.write_all(b"b").unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.inner.bytes, b"ab");
        assert_eq!(
            (
                writer.inner.writes,
                writer.inner.write_alls,
                writer.inner.flushes
            ),
            (1, 1, 1)
        );
        assert_eq!(writer.first_io_error, Some(io::ErrorKind::BrokenPipe));
    }

    fn inert_selected(request: AcquireWriterRequest, receipt: WriterSessionReceipt) -> SelectedV1 {
        SelectedV1 {
            request,
            retry_receipt: Some(receipt.clone()),
            receipt,
            shutdown: Some(Ok(())),
            frame_write: Some(FrameWriteV1 {
                failed: true,
                first_io_error: Some(io::ErrorKind::BrokenPipe),
            }),
            retry_count: 1,
        }
    }
    #[test]
    fn pure_acquire_reply_loss_missing_or_failed_real_io_never_qualifies() {
        let (_, _, request, receipt, _) = inert_fixture();
        let changes: [fn(&mut SelectedV1); 9] = [
            |s| s.shutdown = None,
            |s| s.shutdown = Some(Err(io::ErrorKind::NotConnected)),
            |s| s.frame_write = None,
            |s| s.frame_write.as_mut().unwrap().failed = false,
            |s| s.frame_write.as_mut().unwrap().first_io_error = None,
            |s| s.retry_count = 0,
            |s| s.retry_count = 2,
            |s| s.retry_receipt = None,
            |s| s.retry_receipt.as_mut().unwrap().expires_at_ms += 1,
        ];
        for change in changes {
            let mut selected = inert_selected(request.clone(), receipt.clone());
            change(&mut selected);
            assert!(require_complete_io(&selected, &receipt).is_err());
        }
        let selected = inert_selected(request, receipt.clone());
        assert!(require_complete_io(&selected, &receipt).is_ok());
        let mut changed = receipt;
        changed.acquired_at_ms += 1;
        assert!(require_complete_io(&selected, &changed).is_err());
    }
    #[test]
    fn pure_acquire_reply_loss_audit_requires_exact_prefix_one_append_keys_and_receipt() {
        let (plan, ledger, request, receipt, row) = inert_fixture();
        let state = plan.state.lock().unwrap();
        let baseline = &state.baseline;
        assert!(!baseline.session_ids.is_empty());
        let selected = inert_selected(request, receipt.clone());
        let mut rows = baseline.row_fingerprints.clone();
        rows.push([0xff; 32]);
        let ids = ledger.sessions.keys().cloned().collect::<BTreeSet<_>>();
        let check = |rows: &[[u8; 32]],
                     ids: &BTreeSet<String>,
                     row: &ActualAcquireRowV1,
                     retry: &WriterSessionReceipt| {
            require_exact_final_history(baseline, &selected, &ledger, rows, ids, row, retry)
        };
        assert!(check(&rows, &ids, &row, &receipt).is_ok());
        let mut altered = rows.clone();
        altered[0][0] ^= 1;
        assert!(check(&altered, &ids, &row, &receipt).is_err());
        assert!(check(&rows[1..], &ids, &row, &receipt).is_err());
        assert!(check(&rows[..rows.len() - 1], &ids, &row, &receipt).is_err());
        altered = rows.clone();
        altered.push([0xee; 32]); // Any extra Acquire/Activate/Reserve is rejected.
        assert!(check(&altered, &ids, &row, &receipt).is_err());
        let mut changed_ids = ids.clone();
        changed_ids.remove(&selected.request.session_id);
        assert!(check(&rows, &changed_ids, &row, &receipt).is_err());
        changed_ids = ids.clone();
        changed_ids.insert(h('2'));
        assert!(check(&rows, &changed_ids, &row, &receipt).is_err());
        let mut changed_receipt = receipt.clone();
        changed_receipt.expires_at_ms += 1;
        assert!(check(&rows, &ids, &row, &changed_receipt).is_err());
        changed_receipt = receipt.clone();
        changed_receipt.session_id.push('x');
        assert!(check(&rows, &ids, &row, &changed_receipt).is_err());
        let changes: [fn(&mut ActualAcquireRowV1); 8] = [
            |r| r.sequence += 1,
            |r| r.operation_id.push('x'),
            |r| r.previous_head.push('x'),
            |r| r.head.push('x'),
            |r| r.event.authenticated_certificate_digest.push('x'),
            |r| r.event.witness_time_ms += 1,
            |r| r.event.writer_session_id = Some(h('3')),
            |r| {
                let AuthorityMutation::AcquireWriter(request) = &mut r.event.mutation else {
                    panic!()
                };
                request.session_id.push('x');
            },
        ];
        for change in changes {
            let mut changed = ActualAcquireRowV1 {
                sequence: row.sequence,
                operation_id: row.operation_id.clone(),
                previous_head: row.previous_head.clone(),
                head: row.head.clone(),
                event: row.event.clone(),
            };
            change(&mut changed);
            assert!(check(&rows, &ids, &changed, &receipt).is_err());
        }
    }
    #[test]
    fn pure_acquire_reply_loss_observation_cannot_outlive_a_live_plan_as_joined() {
        let (plan, _, _, _, _) = inert_fixture();
        let observation = DurableAcquireReplyLossObservationV1 {
            state: plan.state.clone(),
        };
        // A live server plan prevents unique consumption. No operational owner
        // is opened and this predicate cannot stand in for the fixture's join.
        assert!(Arc::try_unwrap(observation.state).is_err());
        let observation = DurableAcquireReplyLossObservationV1 {
            state: plan.state.clone(),
        };
        drop(plan);
        assert!(Arc::try_unwrap(observation.state).is_ok());
        // The non-Clone observation and by-value audit prevent repeated audit.
    }
}
