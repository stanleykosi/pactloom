//! Exact native born dispatch, using the unchanged actual original writer owner.
//! Durable immutable intent precedes the authenticated purpose-distinct call.
use super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    born_history::{check_peer, retain_until_finished},
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{
    Error, Result,
    authority_bridge::{self, BridgeError, born_dispatch_ipc::*, dispatch_ipc::write_frame},
    consent_journal::{
        LiveNamedRecipientProfile, RetainedBornDispatchV1, SignerConsentJournal,
        SignerConsentSession,
    },
    ipc::AuthenticatedPeer,
};
use std::{
    os::unix::net::UnixStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_authority::{
    AuthorizeDispatch, born_offline_dispatch_v1::BornOfflineDispatchRequestV1,
};
pub(super) struct PreparedBornDispatchV1 {
    record: RetainedBornDispatchV1,
    profile: LiveNamedRecipientProfile,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    digest: String,
    display: String,
    deadline: Instant,
    wall_floor: u64,
    cancelled: Arc<AtomicBool>,
}
pub(super) struct ApprovedBornDispatchV1(PreparedBornDispatchV1);
fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::InvalidData)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::InvalidData)
}
impl PreparedBornDispatchV1 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        request: BornDispatchRequestV1,
        profile: LiveNamedRecipientProfile,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        source: &NativeAuthorityBinding,
        workspace: &NativeWitnessWorkspace,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        request.validate().map_err(|_| Error::ReviewMismatch)?;
        let wall_floor = now_ms()?;
        if wall_floor < request.observed_at_ms || wall_floor >= request.observation_expires_at_ms {
            return Err(Error::ReviewMismatch);
        }
        let deadline =
            Instant::now() + Duration::from_millis(request.observation_expires_at_ms - wall_floor);
        let current = || {
            source
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            peer.check_current().map_err(|_| BridgeError::Permission)?;
            workspace
                .require_native_origin(source)
                .map_err(|_| BridgeError::Permission)?;
            let now = now_ms().map_err(|_| BridgeError::Permission)?;
            if cancelled.load(Ordering::Acquire)
                || Instant::now() >= deadline
                || now < wall_floor
                || now >= request.observation_expires_at_ms
            {
                return Err(BridgeError::Permission);
            }
            Ok(())
        };
        let held = profile
            .acquire_born_host_history(
                journal,
                session,
                workspace.client(),
                &request.history(),
                deadline,
                current,
            )
            .map_err(|_| Error::ReviewMismatch)?;
        let e = &held.evidence;
        check_peer(&peer, source, e).map_err(|_| Error::ReviewMismatch)?;
        if request.original_admission_digest
            != e.admission
                .admission_digest()
                .map_err(|_| Error::ReviewMismatch)?
            || request.construction_link_digest
                != e.admission
                    .request
                    .construction_link
                    .digest()
                    .map_err(|_| Error::ReviewMismatch)?
        {
            return Err(Error::ReviewMismatch);
        }
        let record = if let Some(old) = journal
            .retained_born_dispatch(&held.original, &request.operation_id)
            .map_err(|_| Error::ReviewMismatch)?
        {
            if old.request != request || old.witness != e.witness {
                return Err(Error::ReviewMismatch);
            }
            old
        } else {
            let reviewed = now_ms()?;
            let native_review = wholepact_core::proposal::canonical_digest(
                "wholepact:native-born-dispatch-observation:v1",
                &(
                    &request,
                    e,
                    &peer.grant_id,
                    &peer.channel_digest,
                    source.entry_digest(),
                ),
            )
            .map_err(|_| Error::InvalidData)?;
            let exact = BornOfflineDispatchRequestV1 {
                version: 1,
                dispatch: AuthorizeDispatch {
                    operation_id: request.operation_id.clone(),
                    account_id: e.witness.account_id.clone(),
                    network_profile_id: e.witness.network_profile_id.clone(),
                    writer_epoch: e.admission.request.reservation.writer_epoch,
                    expected_head: e.head.clone(),
                    reservation_operation_id: e.admission.request.reservation.operation_id.clone(),
                    reservation_request_digest: e
                        .admission
                        .request
                        .request_digest()
                        .map_err(|_| Error::ReviewMismatch)?,
                    final_transaction_digest: request.backend.descriptor.bytes_sha256.clone(),
                    final_transaction_id: request.backend.descriptor.transaction_id.clone(),
                    transaction_expiry_height: request.backend.descriptor.expiry_height,
                    backend_disclosure_digest: request
                        .backend_digest()
                        .map_err(|_| Error::ReviewMismatch)?,
                    reviewed_at_ms: reviewed,
                    admission_expires_at_ms: request
                        .observation_expires_at_ms
                        .min(
                            e.enrollment
                                .enrollment
                                .original_writer_session
                                .expires_at_ms,
                        )
                        .min(e.enrollment.enrollment.policy.expires_at_ms),
                },
                original_admission_digest: request.original_admission_digest.clone(),
                construction_link_digest: request.construction_link_digest.clone(),
                current_input_observation_digest: request.current_input_observation_digest.clone(),
                observed_at_ms: request.observed_at_ms,
                observation_expires_at_ms: request.observation_expires_at_ms,
                native_review_digest: native_review,
            };
            request
                .matches_exact(&exact, &e.admission)
                .map_err(|_| Error::ReviewMismatch)?;
            RetainedBornDispatchV1 {
                request: request.clone(),
                exact,
                witness: e.witness.clone(),
            }
        };
        if now_ms()? >= record.exact.dispatch.admission_expires_at_ms {
            return Err(Error::ReviewMismatch);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-born-exact-dispatch-review:v1",
            &(
                &record,
                &peer.grant_id,
                &peer.channel_digest,
                source.entry_digest(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        // Size-only wire projection, never an admission/authority constructor.
        // Every variable-length field is the actual retained original. Unknown
        // witness time/sequence use the longest u64 encoding and digest64hex.
        let response_size_projection = serde_json::json!({
            "status":"admitted","lease_id":"00".repeat(32),
            "admission":{
                "version":1,"request":&record.exact,"request_digest":"00".repeat(32),
                "original":&e.admission,
                "committed_head":{"sequence":u64::MAX,"digest":"00".repeat(32)},
                "admitted_at_ms":u64::MAX,
                "original_writer_session":&e.enrollment.enrollment.original_writer_session
            }
        });
        crate::authority_bridge::born_ipc_io::ensure_response_fits(&response_size_projection)
            .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "Authorize this exact original born transaction for dispatch\n\n{}\n\nThis sends the full signed transaction to the displayed backend. It can retain and link the transaction and your connection. The current-input observation is the named Host/provider's report, not signer consensus or a promise of settlement. The witness receives the displayed exact commitments under the ORIGINAL writer session and policy. The fresh bounded dispatch window does not renew signing, construction, expiry or earlier uncertain delivery. No new signature, replacement, new inputs or cleared exposure is authorized. An admitted packet cannot be recalled by Lock, cancellation or expiry.\nExact native review: {}",
            serde_json::to_string_pretty(&record).map_err(|_| Error::InvalidData)?,
            digest
        );
        current().map_err(|_| Error::Locked)?;
        Ok(Self {
            record,
            profile,
            peer,
            stream,
            source: source.clone(),
            digest,
            display,
            deadline,
            wall_floor,
            cancelled,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(self.display.clone())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedBornDispatchV1> {
        self.source.check_current()?;
        if authority.binding() != self.source
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.cancelled.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
            || now_ms()? < self.wall_floor
            || now_ms()? >= self.record.exact.dispatch.admission_expires_at_ms
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedBornDispatchV1(self))
    }
}
impl ApprovedBornDispatchV1 {
    pub(super) fn serve(
        self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        workspace: &NativeWitnessWorkspace,
    ) -> authority_bridge::Result<()> {
        let PreparedBornDispatchV1 {
            record,
            profile,
            peer,
            mut stream,
            source,
            deadline,
            wall_floor,
            cancelled,
            ..
        } = self.0;
        let current = || {
            source
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            peer.check_current().map_err(|_| BridgeError::Permission)?;
            workspace
                .require_native_origin(&source)
                .map_err(|_| BridgeError::Permission)?;
            let now = now_ms().map_err(|_| BridgeError::Permission)?;
            if cancelled.load(Ordering::Acquire)
                || Instant::now() >= deadline
                || now < wall_floor
                || now >= record.exact.dispatch.admission_expires_at_ms
            {
                return Err(BridgeError::Permission);
            }
            Ok(())
        };
        let held = profile.acquire_born_host_history(
            journal,
            session,
            workspace.client(),
            &record.request.history(),
            deadline,
            current,
        )?;
        check_peer(&peer, &source, &held.evidence)?;
        record
            .request
            .matches_exact(&record.exact, &held.evidence.admission)?;
        if record.witness != held.evidence.witness {
            return Err(BridgeError::Binding);
        }
        journal.retain_born_dispatch(&held, &record)?;
        current()?;
        let current_witness = || {
            current().map_err(|_| wholepact_authority::AuthorityError::Permission)?;
            held.check_current()
                .map_err(|_| wholepact_authority::AuthorityError::Permission)
        };
        let enrollment = &held.evidence.enrollment.enrollment;
        let admission = if enrollment.owner_continuation.is_some() {
            workspace
                .client()
                .authorize_born_owner_dispatch_checked_until_v1(
                    enrollment,
                    record.exact.clone(),
                    deadline,
                    current_witness,
                )?
        } else {
            workspace
                .client()
                .authorize_born_offline_dispatch_checked_until_v1(
                    record.exact.clone(),
                    deadline,
                    current_witness,
                )?
        };
        admission.check_current(&record.exact)?;
        if admission.authenticated_witness_certificate_digest()
            != record.witness.pinned_server_certificate_digest
        {
            return Err(BridgeError::Binding);
        }
        let mut receiver = crate::authority_bridge::born_ipc_io::HeldReceiver::default();
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        current()?;
        held.check_current()?;
        if crate::authority_bridge::born_ipc_io::write_response_checked(
            &mut stream,
            &BornDispatchResponseV1::Admitted {
                lease_id: lease_id.clone(),
                admission: Box::new(admission.descriptor().clone()),
            },
            deadline,
            &current,
        )
        .is_err()
        {
            retain_until_finished(&mut stream, &peer, &mut receiver);
            return Err(BridgeError::Ipc);
        }
        loop {
            let command = receiver
                .read(&stream, &peer.peer, deadline, &current)
                .ok()
                .and_then(|b| serde_json::from_slice::<BornDispatchCommandV1>(&b).ok());
            match command {
                Some(BornDispatchCommandV1::Finish) => {
                    let _ = write_frame(&mut stream, &BornDispatchResponseV1::Finished);
                    return Ok(());
                }
                Some(BornDispatchCommandV1::CheckCurrent { check_id })
                    if crate::authority_bridge::born_history_ipc::hash(&check_id).is_ok()
                        && current().is_ok()
                        && held.check_current().is_ok()
                        && admission.check_current(&record.exact).is_ok() =>
                {
                    if write_frame(
                        &mut stream,
                        &BornDispatchResponseV1::Current {
                            lease_id: lease_id.clone(),
                            check_id,
                        },
                    )
                    .is_err()
                    {
                        retain_until_finished(&mut stream, &peer, &mut receiver);
                        return Err(BridgeError::Ipc);
                    }
                }
                _ => {
                    let _ = write_frame(&mut stream, &BornDispatchResponseV1::Denied);
                    retain_until_finished(&mut stream, &peer, &mut receiver);
                    return Err(BridgeError::Permission);
                }
            }
        }
    }
}
