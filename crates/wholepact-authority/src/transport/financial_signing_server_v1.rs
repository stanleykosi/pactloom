//! Dedicated original-namespace routes. The admission route can append ONE exact
//! native-reviewed owner request; the durable route cannot issue that admission.
use super::*;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
use crate::durable_financial_continuation_owner_v1::{
    ConfiguredFinancialWitnessV1, NativeFinancialContinuationSourceV1,
};

#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(super) enum FinancialSigningServingV1 {
    Admission(std::sync::Mutex<NativeFinancialContinuationSourceV1>),
    Committed {
        owner: ConfiguredFinancialWitnessV1,
        #[cfg(feature = "synthetic-qualification")]
        acquire_reply_loss: Option<super::durable_acquire_reply_loss_v1::PlanV1>,
    },
}
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub fn open_born_financial_signing_v1_for_server(
    namespace_json: &[u8],
    admission_operation_id: &str,
    tls: ServerTls,
    actual_listen: &str,
) -> Result<AuthorityServer> {
    if namespace_json.is_empty() || namespace_json.len() > 16 * 1024 {
        return Err(AuthorityError::Limit);
    }
    let input: crate::witness_locator::NamespaceOpenInput =
        serde_json::from_slice(namespace_json).map_err(|_| AuthorityError::InvalidBinding)?;
    AuthorityServer::from_born_financial_signing_namespace_v1(
        input,
        admission_operation_id,
        tls,
        actual_listen,
    )
}
impl AuthorityServer {
    // Shared original-namespace opener, not a scope/source constructor. Ordinary
    // JSON cannot carry the serde-skipped nominal synthetic installation owner.
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    pub(crate) fn from_born_financial_signing_namespace_v1(
        input: crate::witness_locator::NamespaceOpenInput,
        admission_operation_id: &str,
        tls: ServerTls,
        actual_listen: &str,
    ) -> Result<Self> {
        let journal = crate::witness_locator::open_born_financial_history_v1(input)?;
        let owner = ConfiguredFinancialWitnessV1::from_original(journal, admission_operation_id)?;
        owner.require_endpoint(&tls.certificate_digest, actual_listen)?;
        let mut server = Self::new(owner.journal(), tls);
        server.financial_signing = Some(Arc::new(FinancialSigningServingV1::Committed {
            owner,
            #[cfg(feature = "synthetic-qualification")]
            acquire_reply_loss: None,
        }));
        Ok(server)
    }
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    pub(crate) fn from_financial_signing_admission_v1(
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
        server.financial_signing = Some(Arc::new(FinancialSigningServingV1::Admission(
            std::sync::Mutex::new(source),
        )));
        Ok(server)
    }
    pub(super) fn check_financial_signing_wait_v1(&self) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(scope) = &self.financial_signing {
            match scope.as_ref() {
                FinancialSigningServingV1::Admission(source) => source
                    .try_lock()
                    .map_err(|_| AuthorityError::Permission)?
                    .check_open()?,
                FinancialSigningServingV1::Committed { .. } => {
                    self.journal.require_born_read_current()?
                }
            }
        }
        Ok(())
    }
    /// Noncommitted output remains revocable. A committed exact receipt is
    /// historical evidence after OPEN is consumed, never a renewed source.
    pub(super) fn check_financial_signing_output_v1(&self, response: &WireResponse) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(scope) = &self.financial_signing {
            match scope.as_ref() {
                FinancialSigningServingV1::Admission(source) => {
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
                FinancialSigningServingV1::Committed { .. } => {
                    self.journal.require_born_read_current()?
                }
            }
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        let _ = response;
        Ok(())
    }
    pub(super) fn require_financial_signing_socket_v1(&self, socket: &TcpStream) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(scope) = &self.financial_signing {
            let listen = socket
                .local_addr()
                .map_err(|_| AuthorityError::Authentication)?
                .to_string();
            match scope.as_ref() {
                FinancialSigningServingV1::Admission(source) => source
                    .try_lock()
                    .map_err(|_| AuthorityError::Permission)?
                    .require_endpoint(&self.tls.certificate_digest, &listen)?,
                FinancialSigningServingV1::Committed { owner, .. } => {
                    owner.require_endpoint(&self.tls.certificate_digest, &listen)?
                }
            }
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        let _ = socket;
        Ok(())
    }
    pub(super) fn is_financial_signing_server_v1(&self) -> bool {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        {
            self.financial_signing.is_some()
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        {
            false
        }
    }
    pub(super) fn serve_financial_signing_request_v1(
        &self,
        peer: &str,
        exporter: &[u8; 32],
        request: WireRequest,
    ) -> Result<WireResponse> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        {
            let scope = self
                .financial_signing
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            match request {
                WireRequest::Snapshot {
                    account_id,
                    network_profile_id,
                } => self
                    .journal
                    .financial_snapshot_v1(peer, &account_id, &network_profile_id)
                    .map(WireResponse::Snapshot),
                WireRequest::ReadHistory {
                    account_id,
                    network_profile_id,
                    expected_head,
                    after_sequence,
                    maximum_entries,
                } => self
                    .journal
                    .financial_history_page_v1(
                        peer,
                        &account_id,
                        &network_profile_id,
                        &expected_head,
                        after_sequence,
                        maximum_entries,
                    )
                    .map(|p| WireResponse::History(Box::new(p))),
                WireRequest::Mutate {
                    mutation,
                    session_proof,
                } => match scope.as_ref() {
                    FinancialSigningServingV1::Admission(source) => {
                        if session_proof.is_some() {
                            return Err(AuthorityError::Permission);
                        }
                        let AuthorityMutation::OwnerControl(request) = *mutation else {
                            return Err(AuthorityError::Permission);
                        };
                        let mut source =
                            source.try_lock().map_err(|_| AuthorityError::Permission)?;
                        self.journal
                            .commit_native_financial_continuation_v1(&mut source, peer, request)
                            .map(WireResponse::Mutation)
                    }
                    FinancialSigningServingV1::Committed { owner, .. }
                        if matches!(
                            &*mutation,
                            AuthorityMutation::OwnerControl(OwnerControlRequest {
                                control: OwnerControl::Pause
                                    | OwnerControl::Revoke
                                    | OwnerControl::PermanentlyExcludeAccount { .. },
                                ..
                            })
                        ) =>
                    {
                        if session_proof.is_some() {
                            return Err(AuthorityError::Permission);
                        }
                        let AuthorityMutation::OwnerControl(request) = *mutation else {
                            unreachable!()
                        };
                        self.journal
                            .restrict_financial_continuation_v1(owner, peer, request)
                            .map(WireResponse::Mutation)
                    }
                    FinancialSigningServingV1::Committed { owner, .. } => self
                        .journal
                        .mutate_financial_continuation_v1(
                            owner,
                            peer,
                            *mutation,
                            session_proof,
                            exporter,
                            &self.tls.certificate_digest,
                        )
                        .map(WireResponse::Mutation),
                },
                _ => Err(AuthorityError::Permission),
            }
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        {
            let _ = (peer, exporter, request);
            Err(AuthorityError::Permission)
        }
    }
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    pub(crate) fn financial_signing_admission_result_v1(&self) -> Result<Option<AccountSnapshot>> {
        let Some(scope) = &self.financial_signing else {
            return Err(AuthorityError::Permission);
        };
        let FinancialSigningServingV1::Admission(source) = scope.as_ref() else {
            return Err(AuthorityError::Permission);
        };
        let source = source.try_lock().map_err(|_| AuthorityError::Permission)?;
        if let Some(snapshot) = source.committed() {
            return Ok(Some(snapshot.clone()));
        }
        source.check_open()?;
        Ok(None)
    }
}
