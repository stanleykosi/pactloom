//! Purpose-specific financial client retaining the original nonbackup signing key.
use super::born_offline_witness_v1::lock_born_session_until;
use super::*;
use crate::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1;
impl AuthorityClient {
    /// Retain this same client's original request/key across every uncertain
    /// error. A callback denial after dispatch is not proof of rollback; inspect
    /// exact history and never allocate a replacement session or operation ID.
    pub fn acquire_financial_continuation_writer_v1_checked_until(
        &self,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        admission_operation_id: &str,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<WriterSessionReceipt> {
        self.acquire_financial_continuation_writer_v1_observed(
            history,
            admission_operation_id,
            deadline,
            &mut check_current,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
    #[cfg(feature = "synthetic-qualification")]
    pub fn acquire_financial_continuation_writer_v1_diagnosed_checked_until(
        &self,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        admission_operation_id: &str,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> std::result::Result<WriterSessionReceipt, history_diagnostics_v1::CheckedHistoryFailureV1>
    {
        let observer = HistoryObserverV1::with_flow_deadline(Some(deadline));
        self.acquire_financial_continuation_writer_v1_observed(
            history,
            admission_operation_id,
            deadline,
            &mut check_current,
            Some(&observer),
        )
        .map_err(|error| observer.into_failure(error))
    }
    fn acquire_financial_continuation_writer_v1_observed(
        &self,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        admission_operation_id: &str,
        deadline: Instant,
        check_current: &mut impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-qualification")] observer: Option<&HistoryObserverV1>,
    ) -> Result<WriterSessionReceipt> {
        observed_flow_current!(observer, check_current)?;
        observed_flow_result!(
            observer,
            CallerDeadline,
            require_before_caller_deadline(deadline)
        )?;
        observed_flow_result!(
            observer,
            FlowRequestValidation,
            history.financial_continuation_online_permits_v1(admission_operation_id)
        )?;
        let admission = observed_history_result!(
            observer,
            observed_history_result!(
                observer,
                history.financial_continuation_admission_v1(admission_operation_id)
            )?
            .ok_or(AuthorityError::Permission)
        )?;
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &admission.control else {
            return observed_history_result!(observer, Err(AuthorityError::CorruptHistory));
        };
        let operation_id =
            observed_history_result!(observer, record.acquire_operation_id(admission))?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::FlowBinding);
        }
        if history.history.disclosure != self.disclosure_descriptor()
            || history.history.snapshot.writer_certificate_digest != self.tls.client_certificate
            || record.terms.scope.authorization.writer_certificate_digest
                != self.tls.client_certificate
        {
            return observed_history_result!(observer, Err(AuthorityError::Permission));
        }
        if history.history.snapshot.writer_status == WriterStatus::Quarantined {
            return observed_history_result!(observer, Err(AuthorityError::RecoveryRequired));
        }
        let mut state = observed_flow_result!(
            observer,
            FlowSession,
            lock_born_session_until(&self.session, deadline, &mut || observed_flow_current!(
                observer,
                check_current
            ))
        )?;
        if let Some(session) = state.as_ref() {
            if session.request.operation_id != operation_id {
                return observed_history_result!(observer, Err(AuthorityError::Conflict));
            }
            if session.request.expected_head != history.history.snapshot.head {
                // A lost Acquire reply may advance the authenticated original
                // history. Retain the SAME request/head/key; never rebase it.
                let receipt = history
                    .history
                    .snapshot
                    .pending_writer_session
                    .as_ref()
                    .or(history.history.snapshot.active_writer_session.as_ref())
                    .ok_or(AuthorityError::RecoveryRequired)?;
                if !history.history.contains_operation(&operation_id)
                    || receipt.session_id != session.request.session_id
                    || receipt.reconciled_head != session.request.expected_head
                    || receipt.reconciled_history_digest
                        != session.request.reconciled_history_digest
                    || receipt.disclosure != session.request.disclosure
                    || !history.history.contains_head(&receipt.acquired_head)
                    || crate::session::session_id(&session.key) != receipt.session_id
                {
                    return observed_history_result!(
                        observer,
                        Err(AuthorityError::RecoveryRequired)
                    );
                }
            }
        } else if history
            .history
            .committed_operation_ids
            .contains(&operation_id)
        {
            // A used operation without this client's retained original key is
            // recovery, never a new exporter/session with the same or fresh ID.
            return observed_history_result!(observer, Err(AuthorityError::RecoveryRequired));
        }
        let response = self.call_with_inner_checked_observed(
            |exporter| {
                let retry = state.is_some();
                if state.is_none() {
                    *state = Some(ClientWriterSession {
                        request: AcquireWriterRequest {
                            operation_id: operation_id.clone(),
                            account_id: self.account.clone(),
                            network_profile_id: self.network.clone(),
                            writer_epoch: history.history.snapshot.writer_epoch,
                            expected_head: history.history.snapshot.head.clone(),
                            reconciled_history_digest: history.history_digest().to_owned(),
                            session_id: crate::session::session_id(exporter),
                            disclosure: self.disclosure_descriptor(),
                        },
                        key: Zeroizing::new(*exporter),
                        receipt: None,
                    });
                }
                let session = state.as_ref().ok_or(AuthorityError::SessionRequired)?;
                let mutation = AuthorityMutation::AcquireWriter(session.request.clone());
                let session_proof = if retry {
                    Some(crate::session::proof(
                        &session.key,
                        (
                            &session.request.session_id,
                            &session.request.disclosure,
                            session.request.writer_epoch,
                        ),
                        exporter,
                        &mutation,
                    )?)
                } else {
                    None
                };
                Ok(WireRequest::Mutate {
                    mutation: Box::new(mutation),
                    session_proof,
                })
            },
            Some(deadline),
            &mut *check_current,
            #[cfg(feature = "synthetic-qualification")]
            observer.map(|observer| (observer, HistoryPhaseV1::Acquire)),
        )?;
        observed_flow_current!(observer, check_current)?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::FlowResponse);
        }
        let WireResponse::Mutation(MutationResult::WriterPending(receipt)) = response else {
            return observed_history_result!(observer, Err(AuthorityError::InvalidBinding));
        };
        let session = observed_flow_result!(
            observer,
            FlowSession,
            state.as_mut().ok_or(AuthorityError::SessionRequired)
        )?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::FlowReceiptValidation);
        }
        if receipt.session_id != session.request.session_id
            || receipt.writer_certificate_digest != self.tls.client_certificate
            || receipt.writer_epoch != session.request.writer_epoch
            || receipt.reconciled_head != session.request.expected_head
            || receipt.reconciled_history_digest != session.request.reconciled_history_digest
            || receipt.disclosure != session.request.disclosure
            || receipt.expires_at_ms <= receipt.acquired_at_ms
            || receipt.expires_at_ms > record.terms.valid_until_ms
        {
            return observed_history_result!(observer, Err(AuthorityError::Authentication));
        }
        observed_flow_result!(
            observer,
            FlowCommittedHeadValidation,
            self.check_committed_head(
                &session.request.expected_head,
                &receipt.acquired_head,
                AuthorityMutation::AcquireWriter(session.request.clone()),
                receipt.acquired_at_ms,
                None,
            )
        )?;
        // Retain the authentic receipt even when a final restriction fails. It
        // remains inert until all checks pass; deleting it would lose retry state.
        session.receipt = Some(receipt.clone());
        observed_flow_current!(observer, check_current)?;
        observed_flow_result!(
            observer,
            CallerDeadline,
            require_before_caller_deadline(deadline)
        )?;
        Ok(receipt)
    }

    /// Exact owner-client activation. Any post-dispatch error requires retained
    /// history reconciliation with this same request; never copy a writer key
    /// into the owner client or infer cancellation rolled back the append.
    pub fn activate_financial_continuation_writer_v1_checked_until(
        &self,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        admission_operation_id: &str,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        self.activate_financial_continuation_writer_v1_observed(
            history,
            admission_operation_id,
            request,
            deadline,
            &mut check_current,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
    #[cfg(feature = "synthetic-qualification")]
    pub fn activate_financial_continuation_writer_v1_diagnosed_checked_until(
        &self,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        admission_operation_id: &str,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> std::result::Result<AccountSnapshot, history_diagnostics_v1::CheckedHistoryFailureV1> {
        let observer = HistoryObserverV1::with_flow_deadline(Some(deadline));
        self.activate_financial_continuation_writer_v1_observed(
            history,
            admission_operation_id,
            request,
            deadline,
            &mut check_current,
            Some(&observer),
        )
        .map_err(|error| observer.into_failure(error))
    }
    fn activate_financial_continuation_writer_v1_observed(
        &self,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        admission_operation_id: &str,
        request: &OwnerControlRequest,
        deadline: Instant,
        check_current: &mut impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-qualification")] observer: Option<&HistoryObserverV1>,
    ) -> Result<AccountSnapshot> {
        observed_flow_current!(observer, check_current)?;
        observed_flow_result!(
            observer,
            FlowRequestValidation,
            validate_pending_activation_v1(
                history,
                admission_operation_id,
                request,
                &self.disclosure_descriptor(),
                &self.tls.client_certificate,
                observed_history_result!(observer, now_ms())?,
            )
        )?;
        observed_flow_current!(observer, check_current)?;
        observed_flow_result!(
            observer,
            CallerDeadline,
            require_before_caller_deadline(deadline)
        )?;
        self.financial_signing_control_checked_v1(
            request,
            deadline,
            check_current,
            #[cfg(feature = "synthetic-qualification")]
            observer.map(|observer| (observer, HistoryPhaseV1::Activate)),
        )
    }

    pub fn verify_financial_continuation_session_v1_checked_until(
        &self,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        admission_operation_id: &str,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedWriterSession> {
        self.verify_financial_continuation_session_v1_observed(
            history,
            admission_operation_id,
            deadline,
            &mut check_current,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
    #[cfg(feature = "synthetic-qualification")]
    pub fn verify_financial_continuation_session_v1_diagnosed_checked_until(
        &self,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        admission_operation_id: &str,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> std::result::Result<
        AuthenticatedWriterSession,
        history_diagnostics_v1::CheckedHistoryFailureV1,
    > {
        let observer = HistoryObserverV1::with_flow_deadline(Some(deadline));
        self.verify_financial_continuation_session_v1_observed(
            history,
            admission_operation_id,
            deadline,
            &mut check_current,
            Some(&observer),
        )
        .map_err(|error| observer.into_failure(error))
    }
    fn verify_financial_continuation_session_v1_observed(
        &self,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        admission_operation_id: &str,
        deadline: Instant,
        check_current: &mut impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-qualification")] observer: Option<&HistoryObserverV1>,
    ) -> Result<AuthenticatedWriterSession> {
        observed_flow_current!(observer, check_current)?;
        observed_flow_result!(
            observer,
            FlowRequestValidation,
            observed_history_result!(
                observer,
                history.financial_continuation_admission_v1(admission_operation_id)
            )?
            .ok_or(AuthorityError::Permission)
        )?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::FlowBinding);
        }
        if history.history.disclosure != self.disclosure_descriptor() {
            return observed_history_result!(observer, Err(AuthorityError::Authentication));
        }
        let state = observed_flow_result!(
            observer,
            FlowSession,
            lock_born_session_until(&self.session, deadline, &mut || observed_flow_current!(
                observer,
                check_current
            ))
        )?;
        let session = observed_history_result!(
            observer,
            state.as_ref().ok_or(AuthorityError::RecoveryRequired)
        )?;
        let receipt = observed_history_result!(
            observer,
            session
                .receipt
                .as_ref()
                .ok_or(AuthorityError::SessionRequired)
        )?;
        if crate::session::session_id(&session.key) != receipt.session_id {
            return observed_history_result!(observer, Err(AuthorityError::Authentication));
        }
        let observed = Instant::now();
        let observed_at_ms = observed_history_result!(observer, now_ms())?;
        let response = self.call_with_inner_checked_observed(
            |_| {
                Ok(WireRequest::Snapshot {
                    account_id: self.account.clone(),
                    network_profile_id: self.network.clone(),
                })
            },
            Some(deadline),
            &mut *check_current,
            #[cfg(feature = "synthetic-qualification")]
            observer.map(|observer| (observer, HistoryPhaseV1::Verify)),
        )?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::FlowResponse);
        }
        let WireResponse::Snapshot(snapshot) = response else {
            return observed_history_result!(observer, Err(AuthorityError::InvalidBinding));
        };
        observed_flow_current!(observer, check_current)?;
        observed_flow_result!(
            observer,
            FlowSnapshotValidation,
            self.check_snapshot(&snapshot)
        )?;
        observed_history_result!(
            observer,
            snapshot.require_unfenced_transport(&receipt.session_id)
        )?;
        if snapshot != history.history.snapshot {
            return observed_history_result!(observer, Err(AuthorityError::StaleHead));
        }
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::FlowReceiptValidation);
        }
        if snapshot.writer_status != WriterStatus::Active
            || snapshot.active_writer_session.as_ref() != Some(receipt)
            || receipt.writer_certificate_digest != self.tls.client_certificate
            || receipt.writer_epoch != snapshot.writer_epoch
            || observed_history_result!(observer, now_ms())? >= receipt.expires_at_ms
        {
            return observed_history_result!(observer, Err(AuthorityError::SessionRequired));
        }
        let active = AuthenticatedWriterSession {
            observed,
            observed_at_ms,
            snapshot,
            receipt: receipt.clone(),
            disclosure: self.disclosure_descriptor(),
            history_digest: observed_history_result!(
                observer,
                Ok(history.history_digest().to_owned())
            )?,
        };
        observed_flow_result!(
            observer,
            FlowFinalValidation,
            history.require_financial_continuation_session_v1(admission_operation_id, &active)
        )?;
        observed_flow_current!(observer, check_current)?;
        observed_flow_result!(
            observer,
            CallerDeadline,
            require_before_caller_deadline(deadline)
        )?;
        Ok(active)
    }

    fn financial_signing_control_checked_v1(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        check_current: &mut impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-qualification")] observation: Option<(
            &HistoryObserverV1,
            HistoryPhaseV1,
        )>,
    ) -> Result<AccountSnapshot> {
        #[cfg(feature = "synthetic-qualification")]
        let observer = observation.map(|(observer, _)| observer);
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(
                if observation.is_some_and(|(_, phase)| phase == HistoryPhaseV1::Activate) {
                    CheckedHistoryStageV1::FlowBinding
                } else {
                    CheckedHistoryStageV1::AdmissionBinding
                },
            );
        }
        if request.account_id != self.account || request.network_profile_id != self.network {
            return observed_history_result!(observer, Err(AuthorityError::InvalidBinding));
        }
        let response = self.call_with_inner_checked_observed(
            |_| {
                Ok(WireRequest::Mutate {
                    mutation: Box::new(AuthorityMutation::OwnerControl(request.clone())),
                    session_proof: None,
                })
            },
            Some(deadline),
            &mut *check_current,
            #[cfg(feature = "synthetic-qualification")]
            observation,
        )?;
        #[cfg(feature = "synthetic-qualification")]
        let checked = history_diagnostics_v1::callback_observed(observer, || check_current());
        #[cfg(not(feature = "synthetic-qualification"))]
        let checked = check_current();
        checked?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(
                if observation.is_some_and(|(_, phase)| phase == HistoryPhaseV1::Activate) {
                    CheckedHistoryStageV1::FlowResponse
                } else {
                    CheckedHistoryStageV1::AdmissionResponse
                },
            );
        }
        let WireResponse::Mutation(MutationResult::Controlled(snapshot)) = response else {
            return observed_history_result!(observer, Err(AuthorityError::InvalidBinding));
        };
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(
                if observation.is_some_and(|(_, phase)| phase == HistoryPhaseV1::Activate) {
                    CheckedHistoryStageV1::FlowSnapshotValidation
                } else {
                    CheckedHistoryStageV1::AdmissionSnapshotValidation
                },
            );
        }
        observed_history_result!(observer, self.check_snapshot(&snapshot))?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(
                if observation.is_some_and(|(_, phase)| phase == HistoryPhaseV1::Activate) {
                    CheckedHistoryStageV1::FlowCommittedHeadValidation
                } else {
                    CheckedHistoryStageV1::AdmissionCommittedHeadValidation
                },
            );
        }
        observed_history_result!(
            observer,
            self.check_committed_head(
                &request.expected_head,
                &snapshot.head,
                AuthorityMutation::OwnerControl(request.clone()),
                snapshot.last_witness_time_ms,
                None,
            )
        )?;
        #[cfg(feature = "synthetic-qualification")]
        let checked = history_diagnostics_v1::callback_observed(observer, || check_current());
        #[cfg(not(feature = "synthetic-qualification"))]
        let checked = check_current();
        checked?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(
                if observation.is_some_and(|(_, phase)| phase == HistoryPhaseV1::Activate) {
                    CheckedHistoryStageV1::FlowFinalValidation
                } else {
                    CheckedHistoryStageV1::AdmissionFinalValidation
                },
            );
        }
        observed_history_result!(observer, require_before_caller_deadline(deadline))?;
        Ok(snapshot)
    }
}

// Inert validation only. This does not access or mint any writer/owner key.
fn validate_pending_activation_v1(
    history: &AuthenticatedFinancialContinuationHistoryV1,
    admission_operation_id: &str,
    request: &OwnerControlRequest,
    disclosure: &WitnessDisclosureDescriptor,
    owner_certificate: &str,
    now: u64,
) -> Result<()> {
    history.financial_continuation_online_permits_v1(admission_operation_id)?;
    let admission = history
        .financial_continuation_admission_v1(admission_operation_id)?
        .ok_or(AuthorityError::Permission)?;
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &admission.control else {
        return Err(AuthorityError::CorruptHistory);
    };
    let OwnerControl::ActivateWriter { session_id } = &request.control else {
        return Err(AuthorityError::Permission);
    };
    if history.history.disclosure != *disclosure
        || history.history.account_policy.owner_certificate_digest != owner_certificate
        || request.expected_head != history.history.snapshot.head
        || request.writer_epoch != history.history.snapshot.writer_epoch
    {
        return Err(AuthorityError::Authentication);
    }
    // The owner and writer are distinct real mTLS clients. The owner joins
    // the exact authenticated pending receipt without copying or installing
    // the writer's exporter key in this client.
    let receipt = history
        .history
        .snapshot
        .pending_writer_session
        .as_ref()
        .ok_or(AuthorityError::SessionRequired)?;
    let admitted_sequence = admission
        .expected_head
        .sequence
        .checked_add(1)
        .ok_or(AuthorityError::Limit)?;
    if !history
        .history
        .committed_operation_ids
        .contains(&record.acquire_operation_id(admission)?)
        || receipt.session_id != *session_id
        || receipt.writer_certificate_digest
            != record.terms.scope.authorization.writer_certificate_digest
        || receipt.reconciled_head.sequence != admitted_sequence
        || history.history.history_heads.get(&admitted_sequence)
            != Some(&receipt.reconciled_head.digest)
        || request.expected_head != receipt.acquired_head
        || now >= receipt.expires_at_ms
    {
        return Err(AuthorityError::SessionRequired);
    }
    Ok(())
}
impl AuthorityClient {
    /// Exact signing-phase reservation over the original retained writer key.
    /// All errors after request dispatch remain uncertain and must be reconciled
    /// using this exact request; the callback is denial-only, never an issuer.
    pub fn reserve_financial_continuation_v1_checked_until(
        &self,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        active: &AuthenticatedWriterSession,
        request: ReserveAuthorization,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedPermit> {
        check_current()?;
        require_before_caller_deadline(deadline)?;
        let continuation = history.continuation_request();
        let record = history.continuation_record();
        history.require_financial_continuation_session_v1(&continuation.operation_id, active)?;
        record.terms.require_live(now_ms()?)?;
        crate::durable_payment_policy_v1::require_exact_reservation_v1(
            &record.terms.scope.authorization,
            continuation.writer_epoch,
            &request,
        )?;
        if request.account_id != self.account
            || request.network_profile_id != self.network
            || request.expected_head != history.snapshot().head
            || request.permit_expires_at_ms > record.terms.valid_until_ms
            || request.permit_expires_at_ms > active.receipt().expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let state = lock_born_session_until(&self.session, deadline, &mut check_current)?;
        let session = state.as_ref().ok_or(AuthorityError::SessionRequired)?;
        if session.receipt.as_ref() != Some(active.receipt())
            || crate::session::session_id(&session.key) != active.receipt().session_id
        {
            return Err(AuthorityError::Authentication);
        }
        let mutation = AuthorityMutation::ReserveAuthorization(Box::new(request.clone()));
        let response = self.call_with_inner_checked_observed(
            |exporter| {
                Ok(WireRequest::Mutate {
                    session_proof: Some(crate::session::proof(
                        &session.key,
                        (
                            &session.request.session_id,
                            &session.request.disclosure,
                            session.request.writer_epoch,
                        ),
                        exporter,
                        &mutation,
                    )?),
                    mutation: Box::new(mutation),
                })
            },
            Some(deadline),
            &mut check_current,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )?;
        let WireResponse::Mutation(MutationResult::Reserved(permit)) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        permit.matches_request(&request)?;
        if permit.witness_id != self.witness
            || permit.policy_digest != self.policy_digest
            || permit.writer_session_id != active.receipt().session_id
        {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &request.expected_head,
            &permit.committed_head,
            AuthorityMutation::ReserveAuthorization(Box::new(request.clone())),
            permit.reserved_at_ms,
            Some(permit.writer_session_id.clone()),
        )?;
        check_current()?;
        require_before_caller_deadline(deadline)?;
        if now_ms()? >= request.permit_expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        Ok(AuthenticatedPermit {
            descriptor: *permit,
            certificate_digest: self.tls.pinned_certificate.clone(),
        })
    }
}
