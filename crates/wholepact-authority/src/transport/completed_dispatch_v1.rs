//! Purpose-separated dispatcher service. TLS possession is additionally pinned
//! to the exact certificate authorized by the strict original financial scope.
use super::*;
use crate::completed_dispatch_v1::*;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
use crate::durable_financial_continuation_owner_v1::ConfiguredFinancialWitnessV1;
impl AuthorityServer {
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    pub(crate) fn from_born_completed_dispatch_namespace_v1(
        input: crate::witness_locator::NamespaceOpenInput,
        continuation_operation_id: &str,
        tls: ServerTls,
        actual_listen: &str,
    ) -> Result<Self> {
        if input.pinned_server_certificate_digest != tls.certificate_digest
            || input.endpoint != actual_listen
        {
            return Err(AuthorityError::Authentication);
        }
        let account = input.expected_account_id.clone();
        let journal = crate::witness_locator::open_born_financial_history_v1(input)?;
        let source =
            ConfiguredFinancialWitnessV1::from_original(journal, continuation_operation_id)?;
        source.require_endpoint(&tls.certificate_digest, actual_listen)?;
        let mut server = Self::new(source.journal(), tls);
        server.completed_dispatch_v1 = Some(Arc::new(std::collections::BTreeMap::from([(
            account,
            Arc::new(source),
        )])));
        Ok(server)
    }
    /// Closed exact-original multi-account service at a shared retained endpoint.
    /// Every route is constructed through the same full source opener; routing
    /// does not enroll peers or relax the target's independent dispatcher pin.
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    pub(crate) fn from_born_completed_dispatch_namespaces_v1(
        inputs: Vec<(crate::witness_locator::NamespaceOpenInput, String)>,
        tls: ServerTls,
        actual_listen: &str,
    ) -> Result<Self> {
        if inputs.is_empty() || inputs.len() > 2 {
            return Err(AuthorityError::Limit);
        }
        // Authenticate one concrete installation owner, retaining its exclusive
        // locks while separately opening and auditing each exact account journal.
        let namespace_inputs: Vec<_> = inputs.iter().map(|(input, _)| input.clone()).collect();
        for input in &namespace_inputs {
            if input.pinned_server_certificate_digest != tls.certificate_digest
                || input.endpoint != actual_listen
            {
                return Err(AuthorityError::Authentication);
            }
        }
        let journals = crate::witness_locator::open_born_financial_histories_v1(&namespace_inputs)?;
        let mut sources = std::collections::BTreeMap::new();
        let mut base = None;
        for ((input, operation), journal) in inputs.into_iter().zip(journals) {
            let source = ConfiguredFinancialWitnessV1::from_original(journal, &operation)?;
            source.require_endpoint(&tls.certificate_digest, actual_listen)?;
            if base.is_none() {
                base = Some(Self::new(source.journal(), tls.clone()));
            }
            if sources
                .insert(input.expected_account_id, Arc::new(source))
                .is_some()
            {
                return Err(AuthorityError::Conflict);
            }
        }
        let mut server = base.ok_or(AuthorityError::Permission)?;
        server.completed_dispatch_v1 = Some(Arc::new(sources));
        server.completed_dispatch_wait_v1(None)?;
        Ok(server)
    }
    pub(super) fn completed_dispatch_wait_v1(&self, socket: Option<&TcpStream>) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(sources) = &self.completed_dispatch_v1 {
            for source in sources.values() {
                source.journal().require_born_read_current()?;
                if let Some(socket) = socket {
                    source.require_endpoint(
                        &self.tls.certificate_digest,
                        &socket
                            .local_addr()
                            .map_err(|_| AuthorityError::Authentication)?
                            .to_string(),
                    )?;
                }
            }
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        let _ = socket;
        Ok(())
    }
    pub(super) fn is_completed_dispatch_v1(&self) -> bool {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        {
            self.completed_dispatch_v1.is_some()
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        {
            false
        }
    }
    pub(super) fn serve_completed_dispatch_v1(
        &self,
        peer: &str,
        request: WireRequest,
    ) -> Result<WireResponse> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        {
            let account = match &request {
                WireRequest::Snapshot { account_id, .. }
                | WireRequest::ReadHistory { account_id, .. } => account_id,
                WireRequest::Mutate {
                    mutation,
                    session_proof: None,
                } => match mutation.as_ref() {
                    AuthorityMutation::AuthorizeCompletedDispatchV1(request) => &request.account_id,
                    _ => return Err(AuthorityError::Permission),
                },
                _ => return Err(AuthorityError::Permission),
            };
            let source = self
                .completed_dispatch_v1
                .as_ref()
                .ok_or(AuthorityError::Permission)?
                .get(account)
                .ok_or(AuthorityError::Permission)?;
            let journal = source.journal();
            match request {
                WireRequest::Snapshot {
                    account_id,
                    network_profile_id,
                } => journal
                    .completed_dispatch_snapshot_v1(source, peer, &account_id, &network_profile_id)
                    .map(WireResponse::Snapshot),
                WireRequest::ReadHistory {
                    account_id,
                    network_profile_id,
                    expected_head,
                    after_sequence,
                    maximum_entries,
                } => journal
                    .completed_dispatch_history_v1(
                        source,
                        peer,
                        &account_id,
                        &network_profile_id,
                        &expected_head,
                        after_sequence,
                        maximum_entries,
                    )
                    .map(|page| WireResponse::History(Box::new(page))),
                WireRequest::Mutate {
                    mutation,
                    session_proof: None,
                } => match *mutation {
                    AuthorityMutation::AuthorizeCompletedDispatchV1(request) => journal
                        .authorize_completed_dispatch_v1(source, peer, request)
                        .map(WireResponse::Mutation),
                    _ => Err(AuthorityError::Permission),
                },
                _ => Err(AuthorityError::Permission),
            }
        }
        #[cfg(not(all(feature = "native-witness-owner", target_os = "linux")))]
        {
            let _ = (peer, request);
            Err(AuthorityError::Permission)
        }
    }
}
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub fn open_born_completed_dispatch_v1_for_server(
    namespace_json: &[u8],
    continuation_operation_id: &str,
    tls: ServerTls,
    actual_listen: &str,
) -> Result<AuthorityServer> {
    if namespace_json.is_empty() || namespace_json.len() > 16 * 1024 {
        return Err(AuthorityError::Limit);
    }
    let input =
        serde_json::from_slice(namespace_json).map_err(|_| AuthorityError::InvalidBinding)?;
    AuthorityServer::from_born_completed_dispatch_namespace_v1(
        input,
        continuation_operation_id,
        tls,
        actual_listen,
    )
}
/// Configure at most two exact original account sources at their shared endpoint.
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub fn open_born_completed_dispatch_pair_v1_for_server(
    namespaces: [(&[u8], &str); 2],
    tls: ServerTls,
    actual_listen: &str,
) -> Result<AuthorityServer> {
    let mut inputs = Vec::new();
    for (bytes, operation) in namespaces {
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(AuthorityError::Limit);
        }
        let input = serde_json::from_slice(bytes).map_err(|_| AuthorityError::InvalidBinding)?;
        inputs.push((input, operation.to_owned()));
    }
    AuthorityServer::from_born_completed_dispatch_namespaces_v1(inputs, tls, actual_listen)
}
impl AuthorityClient {
    /// Caller must retain this exact request before bytes can leave this method.
    /// Any error after the call starts is uncertain; never allocate another
    /// request/head/operation merely to learn whether the original committed.
    pub fn authorize_completed_dispatch_v1_checked_until(
        &self,
        request: &AuthorizeCompletedDispatchV1,
        deadline: Instant,
        check_current: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedCompletedDispatchAdmissionV1> {
        self.authorize_completed_dispatch_v1_restricted_kernel(request, deadline, check_current, None)
    }
    /// Additional borrowed denial-only gate for every physical TLS I/O. The
    /// callback must be zero-wait and must not read sources or acquire DB locks.
    pub fn authorize_completed_dispatch_v1_restricted_checked_until(
        &self,
        request: &AuthorizeCompletedDispatchV1,
        deadline: Instant,
        check_current: impl FnMut() -> Result<()>,
        io_restriction: &dyn Fn() -> Result<()>,
    ) -> Result<AuthenticatedCompletedDispatchAdmissionV1> {
        self.authorize_completed_dispatch_v1_restricted_kernel(request, deadline, check_current, Some(io_restriction))
    }
    fn authorize_completed_dispatch_v1_restricted_kernel(
        &self,
        request: &AuthorizeCompletedDispatchV1,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
        io_restriction: Option<&dyn Fn() -> Result<()>>,
    ) -> Result<AuthenticatedCompletedDispatchAdmissionV1> {
        request.validate()?;
        if request.account_id != self.account
            || request.network_profile_id != self.network
            || request
                .context
                .delivery
                .dispatcher
                .public_identity_commitment
                != self.tls.client_certificate
        {
            return Err(AuthorityError::Authentication);
        }
        check_current()?;
        require_before_caller_deadline(deadline)?;
        let response = self.call_with_inner_checked_restricted_observed(
            |_| {
                Ok(WireRequest::Mutate {
                    mutation: Box::new(AuthorityMutation::AuthorizeCompletedDispatchV1(
                        request.clone(),
                    )),
                    session_proof: None,
                })
            },
            Some(deadline),
            &mut check_current,
            io_restriction,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )?;
        let WireResponse::Mutation(MutationResult::CompletedDispatchAdmittedV1(admission)) =
            response
        else {
            return Err(AuthorityError::InvalidBinding);
        };
        admission.validate()?;
        if admission.request != *request
            || admission.witness_id != self.disclosure_descriptor().witness_id
            || admission.policy_digest != self.policy_digest
        {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &request.expected_head,
            &admission.committed_head,
            AuthorityMutation::AuthorizeCompletedDispatchV1(request.clone()),
            admission.activated_at_ms,
            None,
        )?;
        let observed = Instant::now();
        let observed_at_ms = now_ms()?;
        if observed_at_ms < admission.activated_at_ms || observed_at_ms >= admission.expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        check_current()?;
        require_before_caller_deadline(deadline)?;
        let result = AuthenticatedCompletedDispatchAdmissionV1 {
            admission: *admission,
            observed,
            observed_at_ms,
        };
        result.check_current()?;
        Ok(result)
    }
}
