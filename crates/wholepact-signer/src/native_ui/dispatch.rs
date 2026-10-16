//! Exact native dispatch review. All witness credentials and live writer-session
//! access remain inside the signer; the host receives only a held IPC receipt.
use super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::authority_bridge::{
    self, BridgeError,
    dispatch_ipc::{DispatchCommand, DispatchRequest, DispatchResponse, write_frame},
    protocol::OriginalAuthorizationView,
};
use crate::{
    Error, Result,
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use std::{
    os::unix::net::UnixStream,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_authority::{AuthorizeDispatch, WitnessDisclosureDescriptor};

pub(super) struct PreparedDispatch {
    request: DispatchRequest,
    exact: AuthorizeDispatch,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    witness: WitnessDisclosureDescriptor,
    digest: String,
    display: zeroize::Zeroizing<String>,
    started: Instant,
}
pub(super) struct ApprovedDispatch(PreparedDispatch);
fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::InvalidData)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::InvalidData)
}
fn binding_error(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
fn validate_original(
    request: &DispatchRequest,
    peer: &AuthenticatedPeer,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
) -> authority_bridge::Result<()> {
    request.validate()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    if !peer.scope.history_read || !peer.scope.authorization_export {
        return Err(BridgeError::Permission);
    }
    let lease =
        journal.acquire_original_authorization(&request.history.authorization_id, session)?;
    let original = OriginalAuthorizationView::from_original(lease.evidence());
    request.history.matches(&original)?;
    let t = original.consent.terms();
    let b = &request.backend;
    if t.account_id != peer.scope.account_id
        || t.agreement_id != peer.scope.agreement_id
        || original.enrollment.participant_id() != peer.scope.participant_id
        || t.manifest_digest != peer.scope.manifest_digest
        || b.agreement_id != t.agreement_id
        || b.descriptor.obligation_id != t.obligation_id
        || b.descriptor.proposal_id != t.proposal_id
        || b.descriptor.expiry_height != t.transaction_expiry_height
    {
        return Err(BridgeError::Binding);
    }
    // An existing original result is mandatory. Admission never manufactures a
    // signature or substitutes a replacement transaction for a missing original.
    journal.bridge_result(&lease)?;
    lease.check_current()?;
    Ok(())
}
impl PreparedDispatch {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        request: DispatchRequest,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        authority: &NativeAuthorityBinding,
        workspace: &NativeWitnessWorkspace,
    ) -> Result<Self> {
        authority.check_current()?;
        workspace.check_current()?;
        if &peer.native_origin != authority {
            return Err(Error::Authentication);
        }
        validate_original(&request, &peer, journal, session).map_err(binding_error)?;
        let lease = journal
            .acquire_original_authorization(&request.history.authorization_id, session)
            .map_err(binding_error)?;
        let retained = journal.bridge_request(&lease).map_err(binding_error)?;
        let r = retained.reservation();
        let witness = workspace.disclosure();
        if retained
            .disclosure
            .as_ref()
            .is_none_or(|d| d.descriptor != witness)
        {
            return Err(Error::ReviewMismatch);
        }
        let exact = if let Some(saved) = journal
            .retained_dispatch(&lease, &request.operation_id)
            .map_err(binding_error)?
        {
            if saved.request != request || saved.witness != witness {
                return Err(Error::ReviewMismatch);
            }
            // Preserve the exact original head and deadline. An uncertain call
            // never silently creates a fresh admission payload.
            saved.exact
        } else {
            let head = workspace.snapshot_head()?;
            let snapshot = workspace
                .client()
                .snapshot()
                .map_err(|_| Error::Uncertain)?;
            if snapshot.head != head {
                return Err(Error::ReviewMismatch);
            }
            let now = now_ms()?;
            AuthorizeDispatch {
                operation_id: request.operation_id.clone(),
                account_id: r.account_id.clone(),
                network_profile_id: r.network_profile_id.clone(),
                writer_epoch: snapshot.writer_epoch,
                expected_head: head,
                reservation_operation_id: r.operation_id.clone(),
                reservation_request_digest: r.request_digest().map_err(binding_error)?,
                final_transaction_digest: request.backend.descriptor.bytes_sha256.clone(),
                final_transaction_id: request.backend.descriptor.transaction_id.clone(),
                transaction_expiry_height: r.transaction_expiry_height,
                backend_disclosure_digest: request.backend.digest().map_err(binding_error)?,
                reviewed_at_ms: now,
                admission_expires_at_ms: now.checked_add(120_000).ok_or(Error::InvalidData)?,
            }
        };
        if now_ms()? >= exact.admission_expires_at_ms {
            return Err(Error::ReviewMismatch);
        }
        exact.validate().map_err(binding_error)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-exact-dispatch-review:v1",
            &(
                &request,
                &exact,
                &witness,
                &peer.grant_id,
                &peer.channel_digest,
            ),
        )
        .map_err(binding_error)?;
        let display = zeroize::Zeroizing::new(format!(
            "Authorize exact retained transaction dispatch\n\nComplete backend and transaction disclosure:\n{}\n\nIndependent witness disclosure:\n{}\n\nExact admission request:\n{}\n\nOwn original maximum debit: {} zatoshis\nOwn fee share: {} zatoshis\nTransaction fee: {} zatoshis\n\nThe named backend receives the complete signed transaction and connection metadata and may retain/link them. Its response is a single-provider report, not consensus. The witness receives these transaction commitments, backend disclosure commitment and original account/reservation linkage; its durable admission does not prove settlement. Timeout, cancellation, pause or expiry cannot recall signatures, erase exposure, or undo an admitted packet. This grants no new signature and no replacement transaction. The host must independently reverify the original transaction bytes and enforce current chain/expiry checks. Approval applies only to the displayed exact operation and expires in two minutes.\nReview binding: {}",
            serde_json::to_string_pretty(&request.backend).map_err(binding_error)?,
            serde_json::to_string_pretty(&witness).map_err(binding_error)?,
            serde_json::to_string_pretty(&exact).map_err(binding_error)?,
            r.maximum_debit_zatoshis,
            r.fee_share_zatoshis,
            r.transaction_fee_zatoshis,
            digest
        ));
        Ok(Self {
            request,
            exact,
            peer,
            stream,
            source: authority.clone(),
            witness,
            digest,
            display,
            started: Instant::now(),
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedDispatch> {
        self.source.check_current()?;
        authority.check_current()?;
        self.peer.check_current()?;
        if self.source != authority.binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.started.elapsed() >= Duration::from_secs(120)
            || now_ms()? >= self.exact.admission_expires_at_ms
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedDispatch(self))
    }
}
impl ApprovedDispatch {
    pub(super) fn serve(
        mut self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        workspace: &NativeWitnessWorkspace,
    ) -> authority_bridge::Result<()> {
        validate_original(&self.0.request, &self.0.peer, journal, session)?;
        let lease = journal
            .acquire_original_authorization(&self.0.request.history.authorization_id, session)?;
        let check = || -> authority_bridge::Result<()> {
            self.0
                .source
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            self.0
                .peer
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            workspace
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            lease.check_current()?;
            journal.revalidate_settlement_authority(&lease)?;
            if workspace.disclosure() != self.0.witness
                || self.0.started.elapsed() >= Duration::from_secs(120)
                || now_ms().map_err(|_| BridgeError::Permission)?
                    >= self.0.exact.admission_expires_at_ms
            {
                return Err(BridgeError::Permission);
            }
            Ok(())
        };
        check()?;
        journal.retain_dispatch(
            &lease,
            &crate::consent_journal::RetainedDispatch {
                request: self.0.request.clone(),
                exact: self.0.exact.clone(),
                witness: self.0.witness.clone(),
            },
        )?;
        check()?;
        let admission = workspace
            .client()
            .authorize_dispatch(self.0.exact.clone())?;
        admission.matches_request(&self.0.exact)?;
        check()?;
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        let sent = write_frame(
            &mut self.0.stream,
            &DispatchResponse::Admitted {
                lease_id: lease_id.clone(),
                admission: Box::new(admission.descriptor().clone()),
            },
        );
        if sent.is_err() {
            retain_until_finished(&mut self.0.stream, &self.0.peer);
            return Err(BridgeError::Ipc);
        }
        loop {
            let command = crate::ipc::read_frame_with_deadline(
                &self.0.stream,
                &self.0.peer.peer,
                Duration::from_secs(120),
            )
            .ok()
            .and_then(|b| serde_json::from_slice::<DispatchCommand>(&b).ok());
            match command {
                Some(DispatchCommand::Finish) => {
                    let _ = write_frame(&mut self.0.stream, &DispatchResponse::Finished);
                    return Ok(());
                }
                Some(DispatchCommand::CheckCurrent) if check().is_ok() => {
                    if write_frame(
                        &mut self.0.stream,
                        &DispatchResponse::Current {
                            lease_id: lease_id.clone(),
                        },
                    )
                    .is_ok()
                    {
                        continue;
                    }
                }
                _ => {
                    let _ = write_frame(&mut self.0.stream, &DispatchResponse::Denied);
                }
            }
            retain_until_finished(&mut self.0.stream, &self.0.peer);
            return Err(BridgeError::Permission);
        }
    }
}
fn retain_until_finished(stream: &mut UnixStream, peer: &AuthenticatedPeer) {
    // Never release original authority while a disconnected live consumer might
    // still be completing its final dispatch/outcome commit.
    while peer.peer.check_alive().is_ok() {
        if crate::ipc::read_frame_with_deadline(stream, &peer.peer, Duration::from_secs(2))
            .ok()
            .and_then(|b| serde_json::from_slice::<DispatchCommand>(&b).ok())
            .is_some_and(|c| matches!(c, DispatchCommand::Finish))
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
