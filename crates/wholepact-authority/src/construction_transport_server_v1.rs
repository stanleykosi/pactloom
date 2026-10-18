//! Explicit one-grant serving selection. Existing AuthorityServer::new does not
//! gain handoff permission. Before claim, the selected server can answer the
//! existing bounded Snapshot/ReadHistory requests at that exact pending head.
//! Each read closes its connection; only Claim starts the retained four-frame
//! channel. History never supplies or reconstructs a transport owner.
use super::*;
use crate::construction_transport_handoff_v1::*;

#[derive(Clone)]
pub(super) struct ConstructionTransportServingScopeV1 {
    pending: PendingConstructionTransportGrantV1,
    pending_digest: String,
}
impl ConstructionTransportServingScopeV1 {
    fn require_pending(
        &self,
        ledger: &crate::policy::Ledger,
        peer: &str,
        server_certificate: &str,
        now: u64,
    ) -> Result<()> {
        let authorization = &self.pending.grant.authorization.authorization;
        if peer != authorization.original_session.writer_certificate_digest
            || server_certificate
                != authorization
                    .original_session
                    .disclosure
                    .pinned_server_certificate_digest
        {
            return Err(AuthorityError::Authentication);
        }
        if ledger.construction_transport_grant(&self.pending_digest)? != self.pending {
            return Err(AuthorityError::InvalidBinding);
        }
        if ledger.snapshot.head != self.pending.committed_head {
            return Err(AuthorityError::StaleHead);
        }
        // Complete-history reentry is bounded by the same entry budget as the
        // existing checked client. Page/response byte limits remain maintained
        // by the shared journal history builder and transport frame encoder.
        if ledger.snapshot.head.sequence > 65_536 {
            return Err(AuthorityError::Limit);
        }
        ledger.validate_construction_transport_authorization(authorization, now)?;
        if now < self.pending.grant.granted_at_ms {
            return Err(AuthorityError::Expired);
        }
        ledger.require_unfenced_transport(&authorization.original_session.session_id)?;
        if ledger
            .construction_transport_history_v1()
            .credentials
            .iter()
            .any(|credential| credential.pending_grant == self.pending)
        {
            return Err(AuthorityError::Conflict);
        }
        Ok(())
    }

    fn validate_read_request(
        &self,
        ledger: &crate::policy::Ledger,
        peer: &str,
        server_certificate: &str,
        request: &WireRequest,
        now: u64,
    ) -> Result<()> {
        let (account, network) = match request {
            WireRequest::Snapshot {
                account_id,
                network_profile_id,
            }
            | WireRequest::ReadHistory {
                account_id,
                network_profile_id,
                ..
            } => (account_id, network_profile_id),
            _ => return Err(AuthorityError::Permission),
        };
        self.require_pending(ledger, peer, server_certificate, now)?;
        ledger.authenticate_read(peer, account, network)?;
        if let WireRequest::ReadHistory {
            expected_head,
            after_sequence,
            maximum_entries,
            ..
        } = request
        {
            if expected_head != &self.pending.committed_head {
                return Err(AuthorityError::StaleHead);
            }
            if *maximum_entries == 0
                || *maximum_entries > 16
                || *after_sequence > expected_head.sequence
            {
                return Err(AuthorityError::Limit);
            }
        }
        Ok(())
    }

    fn read(
        &self,
        journal: &AuthorityJournal,
        peer: &str,
        server_certificate: &str,
        request: WireRequest,
        now: u64,
    ) -> Result<WireResponse> {
        journal.require_born_read_current()?;
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = rusqlite::Transaction::new_unchecked(
            c.connection(),
            rusqlite::TransactionBehavior::Deferred,
        )?;
        crate::journal::authenticate_admission(&tx, peer)?;
        let ledger = crate::journal::load(&tx)?;
        self.validate_read_request(&ledger, peer, server_certificate, &request, now)?;
        // Scope validation and output construction use this one locked
        // transaction, so a concurrent claim cannot substitute a newer head.
        let response = match request {
            WireRequest::Snapshot { .. } => WireResponse::Snapshot(ledger.snapshot),
            WireRequest::ReadHistory {
                expected_head,
                after_sequence,
                maximum_entries,
                ..
            } => WireResponse::History(Box::new(crate::journal::history_page_at(
                &tx,
                ledger,
                &expected_head,
                after_sequence,
                maximum_entries,
            )?)),
            _ => return Err(AuthorityError::Permission),
        };
        journal.require_born_read_current()?;
        // Journal replay/page encoding can take time. Check the original grant
        // expiry again; reading never extends it or obtains session-key material.
        require_pending_read_finish(
            now,
            now_ms()?,
            self.pending.grant.authorization.authorization.expires_at_ms,
        )?;
        Ok(response)
    }
}

fn require_pending_read_finish(start: u64, finish: u64, original_expiry: u64) -> Result<()> {
    if finish < start || finish >= original_expiry {
        return Err(AuthorityError::Expired);
    }
    Ok(())
}

fn pending_history_request(stage: u8, request: &WireRequest) -> bool {
    stage == 0
        && matches!(
            request,
            WireRequest::Snapshot { .. } | WireRequest::ReadHistory { .. }
        )
}

impl AuthorityServer {
    /// Select one immutable, already native-published pending grant. Opening
    /// this source cannot create a grant, follow a different attempt or recover a
    /// lost channel. A successful claim cannot be served again after restart.
    pub fn for_construction_transport_v1(
        journal: Arc<AuthorityJournal>,
        tls: ServerTls,
        selected_pending_grant_digest: &str,
    ) -> Result<Self> {
        // Selecting a public serving scope is an activation boundary, before
        // any journal access or adoption of the selected grant.
        if !crate::COMMON_CONTEXT_V3_ACTIVATION_QUALIFIED {
            return Err(AuthorityError::ConstructionHistoryUnsupported);
        }
        Self::for_retained_construction_transport_v1(journal, tls, selected_pending_grant_digest)
    }

    // Same validation for the concrete synthetic native owner. No wire caller,
    // raw DTO or public namespace selector can enter this private inner path.
    pub(crate) fn for_retained_construction_transport_v1(
        journal: Arc<AuthorityJournal>,
        tls: ServerTls,
        selected_pending_grant_digest: &str,
    ) -> Result<Self> {
        hash(selected_pending_grant_digest)?;
        let pending = {
            let c = journal
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let ledger = crate::journal::load(c.connection())?;
            let pending = ledger.construction_transport_grant(selected_pending_grant_digest)?;
            let scope = ConstructionTransportServingScopeV1 {
                pending: pending.clone(),
                pending_digest: selected_pending_grant_digest.into(),
            };
            scope.require_pending(
                &ledger,
                &pending
                    .grant
                    .authorization
                    .authorization
                    .original_session
                    .writer_certificate_digest,
                &tls.certificate_digest,
                now_ms()?,
            )?;
            pending
        };
        Ok(Self {
            journal,
            tls,
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            durable_payment: None,
            #[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
            offline_witness: None,
            #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
            born_offline_witness: None,
            handoff_scope: Some(ConstructionTransportServingScopeV1 {
                pending,
                pending_digest: selected_pending_grant_digest.into(),
            }),
        })
    }

    pub(super) fn serve_construction_handoff_stream_v1(
        &self,
        mut stream: StreamOwned<ServerConnection, DeadlineSocket>,
        peer: &str,
        exporter: &[u8; 32],
        scope: &ConstructionTransportServingScopeV1,
    ) -> Result<()> {
        let expected_credential = credential_id(exporter);
        let expected_exporter = exporter_commitment(exporter);
        let authorization = &scope.pending.grant.authorization.authorization;
        if peer != authorization.original_session.writer_certificate_digest
            || self.tls.certificate_digest
                != authorization
                    .original_session
                    .disclosure
                    .pinned_server_certificate_digest
        {
            return Err(AuthorityError::Authentication);
        }
        // Either one bounded informational read, or four finite handoff frames,
        // all under the original accept deadline. No stage refreshes it and no
        // request reaches the general mutation API.
        for stage in 0_u8..4 {
            stream
                .sock
                .remaining()
                .map_err(|_| AuthorityError::Expired)?;
            let request: WireRequest = read_frame(&mut stream)?;
            let now = now_ms()?;
            let read_only = pending_history_request(stage, &request);
            let result = if now >= authorization.expires_at_ms {
                Err(AuthorityError::Expired)
            } else if read_only {
                scope.read(
                    &self.journal,
                    peer,
                    &self.tls.certificate_digest,
                    request,
                    now,
                )
            } else {
                match (stage, request) {
                    (0, WireRequest::ClaimConstructionTransport { claim }) => {
                        if claim.claim.pending_grant_digest != scope.pending_digest
                            || claim.claim.expected_head != scope.pending.committed_head
                            || claim.claim.credential_id != expected_credential
                            || claim.claim.exporter_commitment != expected_exporter
                        {
                            Err(AuthorityError::Authentication)
                        } else {
                            self.journal
                                .claim_construction_transport_on_channel(
                                    peer,
                                    &claim,
                                    exporter,
                                    &self.tls.certificate_digest,
                                    now,
                                )
                                .map(|credential| {
                                    WireResponse::ConstructionTransportClaimed(Box::new(credential))
                                })
                        }
                    }
                    (
                        1,
                        WireRequest::ObserveConstructionTransport {
                            credential_id,
                            proof,
                        },
                    ) if credential_id == expected_credential => self
                        .journal
                        .observe_construction_transport_on_channel(
                            peer,
                            &credential_id,
                            &proof,
                            exporter,
                            &self.tls.certificate_digest,
                            now,
                        )
                        .map(|observation| {
                            WireResponse::ConstructionTransportObserved(Box::new(observation))
                        }),
                    (2, WireRequest::MutateConstructionTransport { request, proof })
                        if request.credential_id == expected_credential
                            && matches!(
                                &request.mutation,
                                ConstructionTransportMutationV1::Reserve(_)
                            ) =>
                    {
                        self.journal
                            .construction_transport_mutate_on_channel(
                                peer,
                                &request,
                                &proof,
                                exporter,
                                &self.tls.certificate_digest,
                                now,
                            )
                            .map(WireResponse::Mutation)
                    }
                    (3, WireRequest::MutateConstructionTransport { request, proof })
                        if request.credential_id == expected_credential
                            && matches!(
                                &request.mutation,
                                ConstructionTransportMutationV1::Consume(_)
                            ) =>
                    {
                        self.journal
                            .construction_transport_mutate_on_channel(
                                peer,
                                &request,
                                &proof,
                                exporter,
                                &self.tls.certificate_digest,
                                now,
                            )
                            .map(WireResponse::Mutation)
                    }
                    (_, WireRequest::ClaimConstructionTransport { .. }) => {
                        Err(AuthorityError::Uncertain)
                    }
                    _ => Err(AuthorityError::Permission),
                }
            };
            let failed = result.is_err();
            let response = result.unwrap_or_else(WireResponse::Rejected);
            write_frame(&mut stream, &response)?;
            if failed || read_only {
                break;
            }
        }
        stream.conn.send_close_notify();
        stream.flush().map_err(|_| AuthorityError::Uncertain)?;
        Ok(())
    }
}

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
#[path = "construction_transport_server_tests_v1.rs"]
mod tests;
