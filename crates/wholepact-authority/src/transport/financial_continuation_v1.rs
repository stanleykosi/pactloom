//! Full-scope owner-mTLS admission only. No committed financial serving mode.
use super::*;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
use crate::durable_financial_continuation_owner_v1::NativeFinancialContinuationSourceV1;

impl AuthorityClient {
    /// After dispatch may have started, ANY error (including cancellation or
    /// Permission from a restriction callback) requires exact retained-history
    /// inspection. Keep the original request, ID, head and workspace; errors do
    /// not prove rollback, authorize replacement, or refund exposure.
    pub fn admit_financial_continuation_v1_checked_until(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        self.admit_financial_continuation_v1_checked_observed(
            request,
            deadline,
            &mut check_current,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }

    /// Inert synthetic evidence from this same admission and checked TLS kernel.
    /// Any error still leaves remote commit uncertain; this is not a retry route.
    #[cfg(feature = "synthetic-qualification")]
    pub fn admit_financial_continuation_v1_diagnosed_checked_until(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> std::result::Result<AccountSnapshot, history_diagnostics_v1::CheckedHistoryFailureV1> {
        let observer = HistoryObserverV1::with_admission_deadline(deadline);
        self.admit_financial_continuation_v1_checked_observed(
            request,
            deadline,
            &mut check_current,
            Some(&observer),
        )
        .map_err(|error| observer.into_failure(error))
    }

    fn admit_financial_continuation_v1_checked_observed(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        check_current: &mut impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-qualification")] observer: Option<&HistoryObserverV1>,
    ) -> Result<AccountSnapshot> {
        #[cfg(feature = "synthetic-qualification")]
        let checked = history_diagnostics_v1::callback_observed(observer, || check_current());
        #[cfg(not(feature = "synthetic-qualification"))]
        let checked = check_current();
        checked?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::AdmissionRequestValidation);
        }
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
            return observed_history_result!(observer, Err(AuthorityError::Permission));
        };
        observed_history_result!(
            observer,
            record.validate_request(request, &self.disclosure_descriptor())
        )?;
        observed_history_result!(
            observer,
            record
                .terms
                .require_live(observed_history_result!(observer, now_ms())?)
        )?;
        self.financial_continuation_control_checked_v1(
            request,
            deadline,
            check_current,
            #[cfg(feature = "synthetic-qualification")]
            observer.map(|observer| (observer, HistoryPhaseV1::Admission)),
        )
    }

    fn financial_continuation_control_checked_v1(
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

impl AuthorityServer {
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    pub(crate) fn from_financial_continuation_v1(
        source: NativeFinancialContinuationSourceV1,
        tls: ServerTls,
        actual_listen: &str,
    ) -> Result<Self> {
        source.check_open()?;
        source.require_endpoint(&tls.certificate_digest, actual_listen)?;
        #[cfg(feature = "synthetic-qualification")]
        let observer = source.admission_observer().cloned();
        let mut server = Self::new(source.journal(), tls);
        #[cfg(feature = "synthetic-qualification")]
        {
            server.admission_observer = observer;
        }
        server.financial_continuation_v1 = Some(Arc::new(std::sync::Mutex::new(source)));
        Ok(server)
    }
    pub(super) fn check_financial_continuation_wait_v1(&self) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(source) = &self.financial_continuation_v1 {
            source
                .try_lock()
                .map_err(|_| AuthorityError::Permission)?
                .check_open()?;
        }
        Ok(())
    }
    pub(super) fn require_financial_continuation_socket_v1(
        &self,
        socket: &TcpStream,
    ) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(source) = &self.financial_continuation_v1 {
            source
                .try_lock()
                .map_err(|_| AuthorityError::Permission)?
                .require_endpoint(
                    &self.tls.certificate_digest,
                    &socket
                        .local_addr()
                        .map_err(|_| AuthorityError::Authentication)?
                        .to_string(),
                )?;
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        let _ = socket;
        Ok(())
    }
    pub(super) fn is_financial_continuation_v1(&self) -> bool {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        {
            self.financial_continuation_v1.is_some()
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        {
            false
        }
    }
    pub(super) fn serve_financial_continuation_v1(
        &self,
        peer: &str,
        request: WireRequest,
    ) -> Result<WireResponse> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        {
            let source = self
                .financial_continuation_v1
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            let WireRequest::Mutate {
                mutation,
                session_proof: None,
            } = request
            else {
                return Err(AuthorityError::Permission);
            };
            let AuthorityMutation::OwnerControl(request) = *mutation else {
                return Err(AuthorityError::Permission);
            };
            let mut source = source.try_lock().map_err(|_| AuthorityError::Permission)?;
            self.journal
                .commit_native_financial_continuation_v1(&mut source, peer, request)
                .map(WireResponse::Mutation)
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        {
            let _ = (peer, request);
            Err(AuthorityError::Permission)
        }
    }
    pub(super) fn check_financial_continuation_output_v1(
        &self,
        response: &WireResponse,
    ) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        {
            let source = self
                .financial_continuation_v1
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            let source = source.try_lock().map_err(|_| AuthorityError::Permission)?;
            if let Some(committed) = source.committed() {
                if !matches!(response, WireResponse::Mutation(MutationResult::Controlled(snapshot)) if snapshot == committed)
                {
                    return Err(AuthorityError::Uncertain);
                }
            } else {
                source.check_open()?;
            }
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        let _ = response;
        Ok(())
    }
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    pub(crate) fn financial_continuation_result_v1(&self) -> Result<Option<AccountSnapshot>> {
        let source = self
            .financial_continuation_v1
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        let source = source.try_lock().map_err(|_| AuthorityError::Permission)?;
        if let Some(snapshot) = source.committed() {
            return Ok(Some(snapshot.clone()));
        }
        source.check_open()?;
        Ok(None)
    }
}

impl AuthorityClient {
    /// New strict profile, with no conversion from an ordinary historical DTO.
    pub fn financial_continuation_history_v1_checked_until(
        &self,
        continuation_operation_id: &str,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<crate::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1>
    {
        use crate::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1;
        id(continuation_operation_id)?;
        require_before_caller_deadline(deadline)?;
        let history = self.reconcile_history_profile_v1(
            &mut check_current,
            true,
            Some(deadline),
            #[cfg(feature = "synthetic-qualification")]
            None,
            crate::journal::OriginalHistoryProfileV1::FinancialContinuation,
        )?;
        let continuation = history
            .owner_controls
            .get(continuation_operation_id)
            .ok_or(AuthorityError::Permission)?
            .clone();
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &continuation.control else {
            return Err(AuthorityError::Permission);
        };
        record.validate_request(&continuation, &history.disclosure)?;
        let record = (**record).clone();
        let history_digest = crate::session::history_digest(&history.snapshot)?;
        check_current()?;
        require_before_caller_deadline(deadline)?;
        Ok(AuthenticatedFinancialContinuationHistoryV1 {
            history,
            continuation,
            record,
            history_digest,
        })
    }
}
impl AuthorityClient {
    pub fn restrict_financial_continuation_v1_checked_until(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        if !matches!(
            request.control,
            OwnerControl::Pause
                | OwnerControl::Revoke
                | OwnerControl::PermanentlyExcludeAccount { .. }
        ) {
            return Err(AuthorityError::Permission);
        }
        check_current()?;
        require_before_caller_deadline(deadline)?;
        self.financial_continuation_control_checked_v1(
            request,
            deadline,
            &mut check_current,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
}
