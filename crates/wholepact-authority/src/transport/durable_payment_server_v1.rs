//! Dedicated original-namespace routes. The admission route can append ONE exact
//! native-reviewed owner request; the durable route cannot issue that admission.
use super::*;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
use crate::durable_payment_owner_v1::{
    ConfiguredDurablePaymentWitnessV1, NativeDurablePaymentAdmissionSourceV1,
};

#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(super) enum DurablePaymentServingV1 {
    Admission(std::sync::Mutex<NativeDurablePaymentAdmissionSourceV1>),
    Committed(ConfiguredDurablePaymentWitnessV1),
}
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub fn open_born_durable_payment_v1_for_server(
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
    AuthorityServer::from_born_durable_payment_namespace_v1(
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
    pub(crate) fn from_born_durable_payment_namespace_v1(
        input: crate::witness_locator::NamespaceOpenInput,
        admission_operation_id: &str,
        tls: ServerTls,
        actual_listen: &str,
    ) -> Result<Self> {
        let journal = crate::born_history_server::open_born_history_from_namespace(
            input,
            &tls.certificate_digest,
            actual_listen,
        )?;
        let owner =
            ConfiguredDurablePaymentWitnessV1::from_original(journal, admission_operation_id)?;
        owner.require_endpoint(&tls.certificate_digest, actual_listen)?;
        let mut server = Self::new(owner.journal(), tls);
        server.durable_payment = Some(Arc::new(DurablePaymentServingV1::Committed(owner)));
        Ok(server)
    }
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    pub(crate) fn from_durable_payment_admission_v1(
        source: NativeDurablePaymentAdmissionSourceV1,
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
        server.durable_payment = Some(Arc::new(DurablePaymentServingV1::Admission(
            std::sync::Mutex::new(source),
        )));
        Ok(server)
    }
    pub(super) fn check_durable_payment_wait_v1(&self) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(scope) = &self.durable_payment {
            match scope.as_ref() {
                DurablePaymentServingV1::Admission(source) => source
                    .try_lock()
                    .map_err(|_| AuthorityError::Permission)?
                    .check_open()?,
                DurablePaymentServingV1::Committed(_) => {
                    self.journal.require_born_read_current()?
                }
            }
        }
        Ok(())
    }
    /// Noncommitted output remains revocable. A committed exact receipt is
    /// historical evidence after OPEN is consumed, never a renewed source.
    pub(super) fn check_durable_payment_output_v1(&self, response: &WireResponse) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(scope) = &self.durable_payment {
            match scope.as_ref() {
                DurablePaymentServingV1::Admission(source) => {
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
                DurablePaymentServingV1::Committed(_) => {
                    self.journal.require_born_read_current()?
                }
            }
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        let _ = response;
        Ok(())
    }
    pub(super) fn require_durable_payment_socket_v1(&self, socket: &TcpStream) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(scope) = &self.durable_payment {
            let listen = socket
                .local_addr()
                .map_err(|_| AuthorityError::Authentication)?
                .to_string();
            match scope.as_ref() {
                DurablePaymentServingV1::Admission(source) => source
                    .try_lock()
                    .map_err(|_| AuthorityError::Permission)?
                    .require_endpoint(&self.tls.certificate_digest, &listen)?,
                DurablePaymentServingV1::Committed(owner) => {
                    owner.require_endpoint(&self.tls.certificate_digest, &listen)?
                }
            }
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        let _ = socket;
        Ok(())
    }
    pub(super) fn is_durable_payment_server_v1(&self) -> bool {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        {
            self.durable_payment.is_some()
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        {
            false
        }
    }
    pub(super) fn serve_durable_payment_request_v1(
        &self,
        peer: &str,
        exporter: &[u8; 32],
        request: WireRequest,
    ) -> Result<WireResponse> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        {
            let scope = self
                .durable_payment
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            match request {
                WireRequest::Snapshot {
                    account_id,
                    network_profile_id,
                } => self
                    .journal
                    .snapshot(peer, &account_id, &network_profile_id)
                    .map(WireResponse::Snapshot),
                WireRequest::ReadHistory {
                    account_id,
                    network_profile_id,
                    expected_head,
                    after_sequence,
                    maximum_entries,
                } => self
                    .journal
                    .history(
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
                    DurablePaymentServingV1::Admission(source) => {
                        if session_proof.is_some() {
                            return Err(AuthorityError::Permission);
                        }
                        let AuthorityMutation::OwnerControl(request) = *mutation else {
                            return Err(AuthorityError::Permission);
                        };
                        let mut source =
                            source.try_lock().map_err(|_| AuthorityError::Permission)?;
                        self.journal
                            .commit_native_durable_payment_v1(&mut source, peer, request)
                            .map(WireResponse::Mutation)
                    }
                    DurablePaymentServingV1::Committed(owner) => self
                        .journal
                        .mutate_durable_payment_v1(
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
    pub(crate) fn durable_payment_admission_result_v1(&self) -> Result<Option<AccountSnapshot>> {
        let Some(scope) = &self.durable_payment else {
            return Err(AuthorityError::Permission);
        };
        let DurablePaymentServingV1::Admission(source) = scope.as_ref() else {
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
