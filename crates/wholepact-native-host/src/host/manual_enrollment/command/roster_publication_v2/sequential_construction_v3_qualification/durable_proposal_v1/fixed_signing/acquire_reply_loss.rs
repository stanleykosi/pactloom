//! One original pending-session recovery after a genuinely committed Acquire
//! reply loss. This deliberately ends before activation, reconciliation,
//! reservation, wallet setup or signing. It cannot mint fixture authority.
use super::*;
use wholepact_authority::durable_payment_v1::DurableFixedCandidateBindingV1;

const SELECTED_OWNER: usize = 1;

fn selected_owner_is_only_financial_owner(index: usize) -> bool {
    index == SELECTED_OWNER
}

// Inert exact identity comparison only. Genuine proof/native source validation
// and actual committed admission remain mandatory in the live path below.
fn exact_fixed_binding(
    actual: &DurableFixedCandidateBindingV1,
    expected: &FixedProposalIdentityV1,
) -> std::result::Result<bool, serde_json::Error> {
    Ok(serde_json::to_value(actual)? == serde_json::to_value(expected)?)
}

pub(super) fn exercise(input: FixedSigningInputsV1<'_>) -> Result<()> {
    let mut trace = HostTrace::new();
    trace.begin(B::MetadataCheck);
    trace.check(
        input.original_disclosures.len() == 2
            && input.export_sources.len() == 2
            && input.proposal.manifest.participants.len() == 2
            && selected_owner_is_only_financial_owner(SELECTED_OWNER)
            && input.identity.proposal_id == input.candidate_id,
    )?;
    let proposal = Proposal::validate(input.proposal.clone())
        .map_err(|_| trace.refused(Outcome::HostInvalid))?;
    let manifest = proposal.manifest();
    trace.check(
        input.identity.schema_version == 1
            && proposal.input().proposal_id == input.identity.proposal_id
            && proposal.proposal_digest() == input.identity.proposal_digest
            && proposal.manifest_digest() == input.identity.manifest_digest
            && manifest.agreement.network_profile_id == input.identity.network_profile_id
            && manifest.agreement.agreement_id == input.identity.agreement_id
            && manifest.agreement.obligation_id == input.identity.obligation_id
            && manifest.agreement.revision == input.identity.revision
            && manifest.expiry_height == input.identity.expiry_height
            && manifest
                .participants
                .iter()
                .zip(&input.original.born[1..])
                .all(|(participant, born)| {
                    participant.account_id == born.account_id
                        && participant.participant_id == born.participant_id
                })
            && input.original.born[1..]
                .iter()
                .enumerate()
                .all(|(i, born)| {
                    input.export_sources.iter().any(|source| {
                        born.account_id == source.account_id
                            && source.request_digest
                                == input.original_disclosures[i].expected_request_digest
                    })
                })
            && input.export_sources[0].account_id != input.export_sources[1].account_id,
    )?;
    // Exact original temporary custody, not a caller-selected existing directory
    // or symlink alias. The retained Engine/proof journals must remain under the
    // real parent fixture root; no new signature/transaction journal is opened.
    let expected_root = input
        .original
        .temporary
        .path()
        .join("durable-original-engine");
    trace.check(input.protected_root == expected_root)?;
    let original_root = std::fs::canonicalize(input.original.temporary.path())
        .map_err(|error| trace.storage(error))?;
    let protected_metadata =
        std::fs::symlink_metadata(input.protected_root).map_err(|error| trace.storage(error))?;
    trace.check(
        protected_metadata.file_type().is_dir()
            && protected_metadata.permissions().mode() & 0o077 == 0,
    )?;
    let protected_root =
        std::fs::canonicalize(input.protected_root).map_err(|error| trace.storage(error))?;
    trace.check(protected_root == original_root.join("durable-original-engine"))?;
    trace.begin(B::DurableHostReload);
    let local = || LocalProofJob {
        job_id: input.job_id,
        jobs: input.jobs,
        consent: input.proof_consent,
    };
    let _checkpoint = input
        .jobs
        .load_verified(
            &input.access.principal_id,
            input.job_id,
            input.proof_consent,
        )
        .map_err(|error| trace.job(error))?;
    let fixed = input
        .engine
        .load_durable_proposal_for_local_review_v1(input.access, input.candidate_id, local())
        .map_err(|error| trace.engine(error))?;
    trace.check(fixed.identity() == input.identity)?;
    let worker = &input.original.signers;
    let mut revision = input.revision;
    let index = SELECTED_OWNER;
    trace.begin(B::DurableHostWitnessSetup);
    let account_id = &input.original.born[index].account_id;
    let bootstrap = input
        .original
        .witness
        .observe_original_roster_attempt_v2(account_id)
        .map_err(|error| trace.authority(error))?;
    trace.check(
        bootstrap.attempt.sequence == 1
            && bootstrap.attempt.continuation.is_none()
            && bootstrap.attempt.snapshot.head.sequence == 4
            && bootstrap
                .extension
                .account_extension
                .terms
                .identity
                .account_id
                == *account_id,
    )?;
    let publication_deadline = bootstrap
        .attempt
        .last_publication_deadline_ms()
        .ok_or_else(|| trace.refused(Outcome::HostInvalid))?;
    trace.check(publication_deadline <= input.original.expiry_ms)?;
    wait_original_publication(publication_deadline, &mut trace)?;
    // Informational serving cannot admit this financial record. It exists
    // only while the signer derives its exact request from complete history.
    let history_server = input
        .original
        .witness
        .serve_original_history()
        .map_err(|error| trace.authority(error))?;
    trace.begin(B::DurableHostOpen);
    worker
        .send(Command::OpenDurable(index, input.proposal.clone()))
        .map_err(|error| trace.worker(error))?;
    let (peer, scope) = match worker.receive().map_err(|error| trace.worker(error))? {
        Reply::DurablePeer {
            index: actual,
            peer,
            scope,
            ..
        } if actual == index => (peer, scope),
        _ => return Err(trace.refused(Outcome::HostInvalid)),
    };
    trace.begin(B::DurableHostPairStatus);
    worker
        .send(Command::PollDurablePair(index))
        .map_err(|error| trace.worker(error))?;
    let client = OriginalHistoryClient::pair(
        peer.provider,
        &peer.endpoint,
        "Synthetic-fixed-proposal-signer",
        scope,
    )
    .map_err(|error| trace.bridge(error))?;
    trace.begin(B::DurableHostPairObserved);
    done(worker, index, &mut trace)?;
    trace.begin(B::DurableHostWitnessSetup);
    worker
        .send(Command::ConfigureDurableWitness(index))
        .map_err(|error| trace.worker(error))?;
    done(worker, index, &mut trace)?;
    let admission_records = accept_records(worker, index, &mut trace)?;
    revision = redisclose_and_import(
        &input,
        &client,
        index,
        &admission_records,
        ReviewImportPurpose::Admission,
        revision,
        &mut trace,
    )?;
    trace.begin(B::DurableHostWitnessSetup);
    let before_admission = history_server.measurement_snapshot();
    worker
        .send(Command::PrepareDurableAdmission(index))
        .map_err(|error| trace.worker(error))?;
    let admission_result = worker.receive();
    let after_admission = history_server.measurement_snapshot();
    // Both are independent handle observations, not a readiness proof.
    // Emit only for the failed receive, before the original Result can
    // unwind and drop the server. No output delays the measured dispatch,
    // and earlier successful owners cannot supply this failure's snapshots.
    if admission_result.is_err() {
        for (point, (age_us, remaining_us, stopped, finished, clamped)) in [
            (
                diagnostic::HistoryServerMeasurementPoint::BeforeAdmission,
                before_admission,
            ),
            (
                diagnostic::HistoryServerMeasurementPoint::AfterAdmission,
                after_admission,
            ),
        ] {
            diagnostic::emit_history_server_measurement(
                point,
                age_us,
                remaining_us,
                stopped,
                finished,
                clamped,
            );
        }
    }
    let admission = match admission_result.map_err(|error| trace.worker(error))? {
        Reply::DurableAdmissionRequest {
            index: actual,
            request,
        } if actual == index => request,
        _ => return Err(trace.refused(Outcome::HostInvalid)),
    };
    let wholepact_authority::OwnerControl::AdmitDurablePaymentV1 { record } = &admission.control
    else {
        return Err(trace.refused(Outcome::HostInvalid));
    };

    let extension_digest = bootstrap
        .extension
        .digest()
        .map_err(|error| trace.authority(error))?;
    let fixed_matches = exact_fixed_binding(&record.terms.fixed, input.identity)
        .map_err(|_| trace.refused(Outcome::HostInvalid))?;
    trace.check(
        admission.account_id == *account_id
            && admission.network_profile_id == input.identity.network_profile_id
            && admission.expected_head == bootstrap.attempt.snapshot.head
            && admission.writer_epoch == bootstrap.attempt.snapshot.writer_epoch
            && record.terms.original_roster_extension_digest == extension_digest
            && record.terms.original_enrollment_ref
                == bootstrap.extension.account_extension.enrollment_ref
            && fixed_matches,
    )?;
    // The SAME original endpoint must be unbound before production witness
    // preparation. Starting the focused final click does not drain yet:
    // its real admission worker waits for this signer's original-owner mTLS.
    drop(history_server);
    let admission_started = input
        .original
        .witness
        .start_exact_durable_payment_admission(account_id, &admission);
    if admission_started.is_err() {
        if let Some(observation) = input
            .original
            .witness
            .take_durable_payment_admission_diagnostic_v1()
        {
            diagnostic::emit_witness_admission(&observation);
        }
    }
    admission_started.map_err(|error| trace.authority(error))?;
    worker
        .send(Command::ApproveDurableAdmission(index))
        .map_err(|error| trace.worker(error))?;
    let admission_finished = input
        .original
        .witness
        .finish_exact_durable_payment_admission();
    // Only inert observations survive this take. Keep the same snapshot
    // through the original signer receive: remote commit can succeed even
    // when its reply or local completion was not accepted. No extra read,
    // retry or journal inspection is performed for this optional evidence.
    let admission_observation = input
        .original
        .witness
        .take_durable_payment_admission_diagnostic_v1();
    if admission_finished.is_err() {
        if let Some(observation) = admission_observation.as_ref() {
            diagnostic::emit_witness_admission(observation);
        }
    }
    admission_finished.map_err(|error| trace.authority(error))?;
    // The helper observes the real immutable local intent and committed
    // correlation. Its production approval retains intent BEFORE mTLS.
    let signer_finished = done(worker, index, &mut trace);
    if signer_finished.is_err() {
        if let Some(observation) = admission_observation.as_ref() {
            diagnostic::emit_witness_admission(observation);
        }
    }
    signer_finished?;

    // Admission is now exact committed history, not a reusable native
    // window. Drain the old owner and obtain genuine fresh permissions
    // BEFORE the first writer acquisition. No acquired client/session is
    // ever replaced by this deliberately separate fixture phase.
    drop(client);
    trace.begin(B::DurableHostClose);
    worker
        .send(Command::CloseDurable(index))
        .map_err(|error| trace.worker(error))?;
    done(worker, index, &mut trace)?;
    trace.begin(B::DurableHostOpen);
    worker
        .send(Command::OpenDurableObserved(index, input.proposal.clone()))
        .map_err(|error| trace.worker(error))?;
    let (peer, scope) = match worker.receive().map_err(|error| trace.worker(error))? {
        Reply::DurablePeer {
            index: actual,
            peer,
            scope,
            ..
        } if actual == index => (peer, scope),
        _ => return Err(trace.refused(Outcome::HostInvalid)),
    };
    trace.begin(B::DurableHostPairStatus);
    worker
        .send(Command::PollDurablePair(index))
        .map_err(|error| trace.worker(error))?;
    let client = OriginalHistoryClient::pair(
        peer.provider,
        &peer.endpoint,
        "Synthetic-fixed-proposal-signer",
        scope,
    )
    .map_err(|error| trace.bridge(error))?;
    trace.begin(B::DurableHostPairObserved);
    done(worker, index, &mut trace)?;
    trace.begin(B::DurableHostWitnessSetup);
    worker
        .send(Command::ConfigureDurableWitness(index))
        .map_err(|error| trace.worker(error))?;
    done(worker, index, &mut trace)?;
    let preacquire_records = accept_records(worker, index, &mut trace)?;
    trace.check(
        preacquire_records.enrollment_ref != admission_records.enrollment_ref
            && preacquire_records.accepted_manifest_ref != admission_records.accepted_manifest_ref,
    )?;
    let _revision_after_import = redisclose_and_import(
        &input,
        &client,
        index,
        &preacquire_records,
        ReviewImportPurpose::PreAcquire,
        revision,
        &mut trace,
    )?;
    trace.begin(B::DurableHostWitnessSetup);
    // Open the SAME committed original namespace exactly once, immediately
    // before the first history contact. Local setup/import above needs no
    // witness socket. Its original bounded serving lifetime is unchanged.
    let (financial_server, fault_observation) = input
        .original
        .witness
        .serve_committed_durable_payment_losing_acquire_reply_v1(&admission.operation_id)
        .map_err(|error| trace.authority(error))?;
    worker
        .send(Command::ObserveCommittedDurableAdmission(
            index,
            admission.clone(),
        ))
        .map_err(|error| trace.worker(error))?;
    done(worker, index, &mut trace)?;
    // The actual returned Closed/Uncertain result allows the ordinary retry.
    // No server observation, poll, readiness signal, or fault wait may precede it.
    // In particular this is not WriterReconcile, and must never announce that
    // activation/reconciliation completed merely because an Acquire completed.
    trace.begin(B::DurableHostWitnessSetup);
    worker
        .send(Command::AcquireDurableWriterExpectingReplyLoss(index))
        .map_err(|error| trace.worker(error))?;
    let expected_loss = match worker.receive().map_err(|error| trace.worker(error))? {
        Reply::DurableAcquireReplyLost {
            index: actual,
            observation,
        } if actual == index && observation.is_expected_loss() => observation,
        _ => return Err(trace.refused(Outcome::HostInvalid)),
    };
    worker
        .send(Command::RetryDurableWriterAfterReplyLoss(index))
        .map_err(|error| trace.worker(error))?;
    let retry_receipt = match worker.receive().map_err(|error| trace.worker(error))? {
        Reply::DurableAcquireRetried {
            index: actual,
            receipt,
        } if actual == index => receipt,
        _ => return Err(trace.refused(Outcome::HostInvalid)),
    };
    // The actual failure stays private and never enters ordinary terminal-error
    // emission. The same live original client and approval supplied the retry.
    drop(expected_loss);
    trace.begin(B::DurableHostClose);
    worker
        .send(Command::CloseDurable(index))
        .map_err(|error| trace.worker(error))?;
    done(worker, index, &mut trace)?;
    drop(client);
    drop(financial_server); // The original finite handler/listener joins here.
    trace.begin(B::DurableHostWitnessSetup);
    let report = input
        .original
        .witness
        .audit_committed_durable_payment_reply_loss_v1(fault_observation, &retry_receipt)
        .map_err(|error| trace.authority(error))?;
    // Only the joined audit reads actual original/retry receipts and reopened
    // persisted history. These coarse report checks cannot replace that audit.
    trace.check(
        report.original_acquire_committed
            && report.selected_response_transport_lost
            && report.retry_same_original
            && report.event_delta == 1
            && report.financial_acquire_delta == 1
            && report.session_key_delta == 1
            && report.prefix_unchanged
            && report.no_new_activation_or_reservation
            && report.stopped_and_drained
            && report.qualification
                == "original-pending-session-after-committed-acquire-reply-loss-v1",
    )?;
    drop(retry_receipt);
    trace.complete();
    // Return to the original preproof provider shutdown and fixture drain.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Inert metadata only: no native owner, proof, receipt or journal is created.
    fn identity() -> FixedProposalIdentityV1 {
        FixedProposalIdentityV1 {
            schema_version: 1,
            network_profile_id: "network".into(),
            agreement_id: "agreement".into(),
            obligation_id: "obligation".into(),
            proposal_id: "proposal".into(),
            revision: 2,
            expiry_height: 3,
            proposal_digest: "proposal-digest".into(),
            manifest_digest: "manifest-digest".into(),
            unsigned_artifact_digest: "unsigned-digest".into(),
            proved_artifact_digest: "proved-digest".into(),
            effects_commitment: "effects".into(),
            policy_digest: "policy".into(),
            review_binding: "review".into(),
            action_mapping_digest: "mapping".into(),
            anchor: "anchor".into(),
            proposal_binding: "binding".into(),
        }
    }

    #[test]
    fn pure_acquire_reply_loss_preserves_every_fixed_identity_field() {
        let expected = identity();
        let value = serde_json::to_value(&expected).unwrap();
        let actual = serde_json::from_value(value.clone()).unwrap();
        assert!(exact_fixed_binding(&actual, &expected).unwrap());
        for field in value.as_object().unwrap().keys() {
            let mut changed = value.clone();
            changed[field] = match &changed[field] {
                serde_json::Value::String(value) => {
                    serde_json::Value::String(format!("{value}-changed"))
                }
                serde_json::Value::Number(value) => (value.as_u64().unwrap() + 1).into(),
                _ => panic!("fixed identity field shape changed"),
            };
            let actual = serde_json::from_value(changed).unwrap();
            assert!(!exact_fixed_binding(&actual, &expected).unwrap());
        }
    }

    #[test]
    fn pure_acquire_reply_loss_selects_only_owner_one() {
        assert_eq!(SELECTED_OWNER, 1);
        for index in 0..=3 {
            assert_eq!(selected_owner_is_only_financial_owner(index), index == 1);
        }
        assert!(!ReviewImportPurpose::Admission.requires_reconciled_writer());
        assert!(!ReviewImportPurpose::PreAcquire.requires_reconciled_writer());
    }

    #[test]
    fn pure_acquire_reply_loss_stops_before_reconciliation_or_signing() {
        // Source-contract assertion, not evidence that a native run succeeded.
        let source = include_str!("acquire_reply_loss.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "Command::ReconcileDurableWriter",
            "Command::ConfigureDurableWallet",
            "Command::SignDurableFixed",
            "Command::ServeDurableResult",
            "ReviewImportPurpose::Signing",
            "B::DurableHostWriterReconcile",
            "WriterReconcileComplete",
            "SignedResultJournal",
            "TransactionCheckpointJournal",
        ] {
            assert!(!source.contains(forbidden));
        }
        let first = source
            .find(".send(Command::AcquireDurableWriterExpectingReplyLoss(index))")
            .unwrap();
        let retry = source
            .find(".send(Command::RetryDurableWriterAfterReplyLoss(index))")
            .unwrap();
        let close = source[retry..]
            .find(".send(Command::CloseDurable(index))")
            .unwrap()
            + retry;
        let server_drop = source[close..].find("drop(financial_server)").unwrap() + close;
        let audit = source
            .find(".audit_committed_durable_payment_reply_loss_v1(")
            .unwrap();
        assert!(first < retry && retry < close && close < server_drop && server_drop < audit);
        assert!(!source[first..retry].contains("fault_observation"));
        assert!(!source[first..retry].contains("wait_"));
    }
}
