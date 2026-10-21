//! Genuine fixed-W control/worker join. Control never acquires source, journal,
//! registry or filesystem locks while observing the original coordinator edge.
use super::*;
use std::{
    io,
    sync::{mpsc, Mutex},
    thread,
    time::Duration,
};
use wholepact_financial_coordinator_origin::{
    FinancialWitnessRequestV1, WitnessFinancialContinuationOriginV1,
    WitnessFinancialContinuationSetupV1,
};

pub(super) enum WorkerEventV1 {
    Display(FinancialWitnessPresentationV1, Instant),
    Armed,
    Ready(FinancialWitnessReadyV1, Instant),
}
struct WorkerResultV1 {
    outcome: Option<FinancialWitnessOutcomeV1>,
    first_failure: Option<observation::DeliveryFailureV1>,
}

/// The sole positive entry. Consumes actual fixed-fork custody, not an FD,
/// claimed role, callback, selector or approval bit. Normal completion follows
/// actual worker join/drop. Original-peer loss or the one cleanup cutoff instead
/// fails into process exit WITHOUT claiming disposal of a blocked worker.
/// Preparation can perform protected opener sidecar work and bind a listener.
pub fn run_witness_financial_continuation_once_v1(
    mut origin: WitnessFinancialContinuationOriginV1,
) -> ! {
    let result = run(&mut origin);
    origin.complete(result)
}
fn failure() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "The one financial continuation attempt was terminated",
    )
}
fn run(origin: &mut WitnessFinancialContinuationOriginV1) -> io::Result<()> {
    let restrictions = Arc::new(RestrictionsV1 {
        revoke_requested: AtomicBool::new(false),
        original_coordinator_lost: AtomicBool::new(false),
    });
    let (events_tx, events_rx) = mpsc::sync_channel(2);
    let (arm_tx, arm_rx) = mpsc::sync_channel(1);
    let (grant_tx, grant_rx) = mpsc::sync_channel(1);
    let mut arm_rx = Some(arm_rx);
    let mut grant_rx = Some(grant_rx);
    let mut events_tx = Some(events_tx);
    let mut worker: Option<thread::JoinHandle<WorkerResultV1>> = None;
    let mut consumed = false;
    let mut arm_seen = false;
    let mut grant_seen = false;
    let mut interrupted = false;
    let mut communication_failed = false;
    let mut displayed: Option<String> = None;
    let mut ready_effect: Option<String> = None;
    let mut cancel_seen = false;
    let mut disposed = false;
    let mut cleanup_deadline: Option<Instant> = None;
    let hard_cleanup = origin.session_deadline() + Duration::from_secs(5);
    loop {
        // This observer is independent of every blocking backend operation.
        if origin.check_original_coordinator_alive().is_err() {
            restrictions
                .original_coordinator_lost
                .store(true, Ordering::Release);
            restrictions.revoke_requested.store(true, Ordering::Release);
            // complete(Err) exits the actual role, terminating any blocked
            // worker. Process death is NOT a successful disposal proof.
            return Err(failure());
        }
        if Instant::now() >= origin.session_deadline() {
            restrictions.revoke_requested.store(true, Ordering::Release);
            interrupted = true;
        }
        if interrupted {
            cleanup_deadline
                .get_or_insert_with(|| (Instant::now() + Duration::from_secs(5)).min(hard_cleanup));
        }
        if Instant::now() >= hard_cleanup
            || cleanup_deadline.is_some_and(|end| Instant::now() >= end)
        {
            return Err(failure()); // never wait indefinitely for blocked storage
        }
        if !communication_failed {
            match origin.try_receive() {
                Ok(Some(FinancialWitnessRequestV1::PrepareOnce(input)))
                    if !consumed && !interrupted =>
                {
                    consumed = true; // failure consumes the slot too
                    let flags = restrictions.clone();
                    let deadline = origin.session_deadline();
                    let tx = events_tx.take().expect("one private worker sender");
                    let arms = arm_rx.take().expect("one private arm receiver");
                    let grants = grant_rx.take().expect("one private grant receiver");
                    worker = Some(
                        thread::Builder::new()
                            .name("witness-one-financial-continuation".into())
                            .spawn(move || worker_once(input, deadline, flags, tx, arms, grants))
                            .map_err(|_| failure())?,
                    );
                }
                Ok(Some(FinancialWitnessRequestV1::Arm(arm)))
                    if consumed && !arm_seen && !interrupted && !disposed =>
                {
                    arm_seen = true;
                    if arm_tx.try_send(arm).is_err() {
                        restrictions.revoke_requested.store(true, Ordering::Release);
                        interrupted = true;
                    }
                }
                Ok(Some(FinancialWitnessRequestV1::FinalAdmit(grant)))
                    if arm_seen && !grant_seen && !disposed =>
                {
                    grant_seen = true;
                    // Authenticated token is not a caller-controlled bool. The
                    // worker also matches it against its exact private ticket.
                    if grant_tx.try_send(grant).is_err() {
                        restrictions.revoke_requested.store(true, Ordering::Release);
                        interrupted = true;
                    }
                }
                Ok(Some(FinancialWitnessRequestV1::ClosePurpose)) if disposed => {
                    origin.send_purpose_closed()?;
                    return Ok(());
                }
                Ok(Some(FinancialWitnessRequestV1::Cancel)) if !cancel_seen => {
                    cancel_seen = true;
                    restrictions.revoke_requested.store(true, Ordering::Release);
                    interrupted = true;
                }
                Ok(Some(_)) | Err(_) => {
                    restrictions
                        .original_coordinator_lost
                        .store(true, Ordering::Release);
                    restrictions.revoke_requested.store(true, Ordering::Release);
                    communication_failed = true;
                    interrupted = true;
                }
                Ok(None) => (),
            }
        }
        if communication_failed {
            return Err(failure());
        }
        if interrupted {
            cleanup_deadline
                .get_or_insert_with(|| (Instant::now() + Duration::from_secs(5)).min(hard_cleanup));
        }
        // Transport only. Actual C A was already ordered in its native loop;
        // neither this monitor nor its dequeue/send manufactures approval.
        while let Ok(event) = events_rx.try_recv() {
            let sent = match event {
                WorkerEventV1::Armed => origin.acknowledge_armed(),
                WorkerEventV1::Display(data, deadline) => {
                    if interrupted {
                        Ok(())
                    } else {
                        let digest = data.presentation_digest.clone();
                        origin.send_display(data, deadline).map(|()| {
                            displayed = Some(digest);
                        })
                    }
                }
                WorkerEventV1::Ready(data, deadline) => {
                    if interrupted {
                        Ok(())
                    } else {
                        let effect = data.effect_commitment.clone();
                        origin.send_ready(data, deadline).map(|()| {
                            ready_effect = Some(effect);
                        })
                    }
                }
            };
            if sent.is_err() {
                restrictions
                    .original_coordinator_lost
                    .store(true, Ordering::Release);
                restrictions.revoke_requested.store(true, Ordering::Release);
                communication_failed = true;
                interrupted = true;
            }
        }
        if communication_failed {
            return Err(failure());
        }
        if !disposed && worker.as_ref().is_some_and(|worker| worker.is_finished()) {
            let result = worker.take().expect("finished sole worker").join();
            // Actual successful join, after all owned fields drop, is required
            // for the normal disposal acknowledgement. A panic never gets one.
            let result = match result {
                Ok(result) => result,
                Err(_) => {
                    if !communication_failed {
                        if let Some(presentation_digest) = displayed {
                            let _ = origin.send_outcome(FinancialWitnessOutcomeV1::Uncertain {
                                presentation_digest,
                                effect_commitment: ready_effect,
                            });
                        }
                    }
                    return Err(failure());
                }
            };
            if communication_failed {
                return Err(failure());
            }
            if let Some(first) = result.first_failure {
                origin.send_first_failure(first)?;
            }
            if displayed.is_some() {
                origin.send_outcome(outcome_for_original_wire(
                    result.outcome.ok_or_else(failure)?,
                    ready_effect.as_deref(),
                )?)?;
            } else if !cancel_seen {
                origin.send_preparation_failed()?;
            }
            origin.send_disposed()?;
            disposed = true;
            cleanup_deadline
                .get_or_insert_with(|| (Instant::now() + Duration::from_secs(5)).min(hard_cleanup));
        }
        if !disposed && cancel_seen && !consumed {
            if communication_failed {
                return Err(failure());
            }
            origin.send_disposed()?;
            disposed = true;
        }
        // It does not recall an admitted effect or renew any cleanup deadline.
        // Only authenticated ClosePurpose after actual Disposed closes this grammar.
        thread::sleep(Duration::from_millis(5));
    }
}
/// Omit a private un-published ticket's correlation only. Never change the
/// recorded effect classification or erase a committed outcome.
fn outcome_for_original_wire(
    mut outcome: FinancialWitnessOutcomeV1,
    sent: Option<&str>,
) -> io::Result<FinancialWitnessOutcomeV1> {
    match &mut outcome {
        FinancialWitnessOutcomeV1::Committed {
            effect_commitment, ..
        } => {
            if sent != Some(effect_commitment.as_str()) {
                return Err(failure());
            }
        }
        FinancialWitnessOutcomeV1::KnownNoEffect {
            effect_commitment, ..
        }
        | FinancialWitnessOutcomeV1::Uncertain {
            effect_commitment, ..
        } => match sent {
            Some(expected) if effect_commitment.as_deref() == Some(expected) => (),
            None => *effect_commitment = None,
            _ => return Err(failure()),
        },
    }
    Ok(outcome)
}

fn worker_once(
    input: WitnessFinancialContinuationSetupV1,
    session_deadline: Instant,
    restrictions: Arc<RestrictionsV1>,
    events: mpsc::SyncSender<WorkerEventV1>,
    arms: mpsc::Receiver<WitnessFinancialContinuationArmV1>,
    grants: mpsc::Receiver<FinancialContinuationFinalV1>,
) -> WorkerResultV1 {
    let mut first_failure = observation::FirstFailureV1::default();
    let prepared = match presentation::prepare(input, &mut first_failure) {
        Ok(value) => value,
        Err(_) => {
            return WorkerResultV1 {
                outcome: None,
                first_failure: first_failure.take(),
            };
        }
    };
    let digest = prepared.presentation.presentation_digest.clone();
    let before_arm = (|| {
        restrictions.require_unrevoked()?;
        prepared.clock.check()?;
        if Instant::now() >= session_deadline {
            return Err(AuthorityError::Expired);
        }
        events
            .try_send(WorkerEventV1::Display(
                prepared.presentation.clone(),
                prepared.clock.original_deadline(),
            ))
            .map_err(|_| AuthorityError::Permission)?;
        loop {
            prepared.clock.check()?;
            restrictions.require_unrevoked()?;
            if Instant::now() >= session_deadline {
                return Err(AuthorityError::Expired);
            }
            match arms.recv_timeout(Duration::from_millis(5)) {
                Ok(arm) => {
                    arm.check_current()
                        .map_err(|_| AuthorityError::Permission)?;
                    if arm.presentation_digest() != digest
                        || arm.original_review_deadline() != prepared.clock.original_deadline()
                    {
                        return Err(AuthorityError::Authentication);
                    }
                    prepared.proposal_current(&arm).map_err(|error| {
                        first_failure.note(observation::Stage::ArmCurrentness, error);
                        error
                    })?;
                    restrictions.require_unrevoked()?;
                    prepared.clock.check()?;
                    return Ok(arm);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AuthorityError::Permission);
                }
            }
        }
    })();
    let arm = match before_arm {
        Ok(arm) => arm,
        Err(error) => {
            first_failure.note(observation::Stage::ArmCurrentness, error);
            drop(prepared);
            return WorkerResultV1 {
                outcome: Some(FinancialWitnessOutcomeV1::KnownNoEffect {
                    presentation_digest: digest,
                    effect_commitment: None,
                }),
                first_failure: first_failure.take(),
            };
        }
    };
    let presentation::PreparedReviewV1 {
        prepared,
        presentation,
        clock,
    } = prepared;
    let super::super::financial_continuation_preparation_v1::PreparedNativeV1 {
        proposal,
        tls,
        listener,
    } = prepared;
    let review_bounds = (presentation.prepared_at_ms, presentation.expires_at_ms);
    let source = Mutex::new(CoordinatedFinancialContinuationSourceV1 {
        proposal,
        arm,
        clock,
        review_bounds,
        session_deadline,
        presentation,
        retained_effect: None,
        restrictions,
        phase: PhaseV1::Armed,
        pending_effect: None,
        outcome: OutcomeV1::Pending,
        first_failure,
    });
    // Retain this actual origin arm until the entire one attempt drains. It is
    // never converted into a legacy FinalPrimaryClick or publication lease.
    if events.try_send(WorkerEventV1::Armed).is_err() {
        let mut first = observation::FirstFailureV1::default();
        first.note(
            observation::Stage::ArmCurrentness,
            AuthorityError::Permission,
        );
        return WorkerResultV1 {
            outcome: Some(FinancialWitnessOutcomeV1::KnownNoEffect {
                presentation_digest: digest,
                effect_commitment: None,
            }),
            first_failure: first.take(),
        };
    }
    let bridge = FinancialContinuationCoordinatorBridgeV1 {
        events,
        grant: grants,
    };
    let serving = crate::transport::coordinated_financial_continuation_v1::serve_coordinated_financial_continuation_once_v1(
        listener, tls, &source, bridge,
    );
    let mut source = match source.into_inner() {
        Ok(source) => source,
        Err(poisoned) => {
            let mut source = poisoned.into_inner();
            let first_failure = source.first_failure.take();
            drop(source);
            return WorkerResultV1 {
                outcome: Some(FinancialWitnessOutcomeV1::Uncertain {
                    presentation_digest: digest,
                    effect_commitment: None,
                }),
                first_failure,
            };
        }
    };
    if matches!(source.outcome, OutcomeV1::Pending) {
        source.record_no_effect(serving.err().unwrap_or(AuthorityError::Permission));
    }
    let effect_commitment = source.retained_effect.clone();
    let outcome = match &source.outcome {
        OutcomeV1::Completed(snapshot) => match effect_commitment {
            Some(effect_commitment) => FinancialWitnessOutcomeV1::Committed {
                presentation_digest: digest,
                effect_commitment,
                head_sequence: snapshot.head.sequence,
                head_digest: snapshot.head.digest.clone(),
            },
            None => FinancialWitnessOutcomeV1::Uncertain {
                presentation_digest: digest,
                effect_commitment: None,
            },
        },
        OutcomeV1::KnownNoEffect(_) => FinancialWitnessOutcomeV1::KnownNoEffect {
            presentation_digest: digest,
            effect_commitment,
        },
        OutcomeV1::Uncertain | OutcomeV1::Pending => FinancialWitnessOutcomeV1::Uncertain {
            presentation_digest: digest,
            effect_commitment,
        },
    };
    let first_failure = source.first_failure.take();
    drop(source); // actual proposal/journal/namespace owner is gone before return
    WorkerResultV1 {
        outcome: Some(outcome),
        first_failure,
    }
}
impl presentation::PreparedReviewV1 {
    fn proposal_current(&self, arm: &WitnessFinancialContinuationArmV1) -> Result<()> {
        self.prepared.proposal.coordinated_arm_current_v1(arm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_wire_projection_never_fabricates_or_erases_a_commit() {
        let digest = "a".repeat(64);
        let effect = "b".repeat(64);
        let known = FinancialWitnessOutcomeV1::KnownNoEffect {
            presentation_digest: digest.clone(),
            effect_commitment: Some(effect.clone()),
        };
        assert!(matches!(
            outcome_for_original_wire(known, None).unwrap(),
            FinancialWitnessOutcomeV1::KnownNoEffect {
                effect_commitment: None,
                ..
            }
        ));
        let committed = FinancialWitnessOutcomeV1::Committed {
            presentation_digest: digest,
            effect_commitment: effect.clone(),
            head_sequence: 5,
            head_digest: "c".repeat(64),
        };
        assert!(outcome_for_original_wire(committed.clone(), None).is_err());
        assert!(matches!(
            outcome_for_original_wire(committed, Some(&effect)).unwrap(),
            FinancialWitnessOutcomeV1::Committed { .. }
        ));
    }
}
