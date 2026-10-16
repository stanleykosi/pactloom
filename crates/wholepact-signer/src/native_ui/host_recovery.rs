//! Exact native consent before disclosing all witnessed account reservations to
//! a restored host. The surviving signer retains its existing writer and secrets.
use super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{
    Error, Result,
    authority_bridge::{
        self, BridgeError,
        dispatch_ipc::write_frame,
        host_recovery_ipc::{
            HostContinuityCommand, HostContinuityResponse, HostRecoveryContinuityEvidence,
            HostRecoveryContinuityRequest,
        },
    },
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use std::{
    os::unix::net::UnixStream,
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) struct PreparedHostContinuity {
    request: HostRecoveryContinuityRequest,
    evidence: HostRecoveryContinuityEvidence,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    witness: Arc<NativeWitnessWorkspace>,
    digest: String,
    started: Instant,
}
pub(super) struct ApprovedHostContinuity(PreparedHostContinuity);
fn error(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
pub(super) fn observe(
    request: &HostRecoveryContinuityRequest,
    witness: &NativeWitnessWorkspace,
) -> authority_bridge::Result<(
    wholepact_authority::ReconciledAuthorityHistory,
    wholepact_authority::AuthenticatedWriterSession,
    HostRecoveryContinuityEvidence,
)> {
    request.validate()?;
    witness
        .check_current()
        .map_err(|_| BridgeError::Permission)?;
    if witness.disclosure() != request.expected_witness {
        return Err(BridgeError::Binding);
    }
    let history = witness.client().reconcile_history()?;
    let active = witness.client().verify_active_session(&history)?;
    let s = history.snapshot();
    if s.account_id != request.account_id
        || s.network_profile_id != request.network_profile_id
        || s.writer_epoch != request.expected_writer_epoch
        || s.writer_certificate_digest != witness.writer_certificate_digest()
        || history.disclosure() != &request.expected_witness
    {
        return Err(BridgeError::Binding);
    }
    let evidence = HostRecoveryContinuityEvidence {
        request: request.clone(),
        writer_certificate_digest: s.writer_certificate_digest.clone(),
        writer_session_id: active.receipt().session_id.clone(),
        writer_session_expires_at_ms: active.receipt().expires_at_ms,
        head: s.head.clone(),
        history_digest: history.history_digest()?,
        conservative_permits: history.permits()?.to_vec(),
    };
    evidence.validate()?;
    witness
        .check_current()
        .map_err(|_| BridgeError::Permission)?;
    Ok((history, active, evidence))
}
impl PreparedHostContinuity {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        request: HostRecoveryContinuityRequest,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        source: NativeAuthorityBinding,
        witness: Arc<NativeWitnessWorkspace>,
    ) -> Result<Self> {
        source.check_current()?;
        peer.check_current()?;
        if peer.native_origin != source
            || !peer.scope.history_read
            || !peer.scope.authorization_export
            || peer.scope.account_id != request.account_id
        {
            return Err(Error::Authentication);
        }
        let (history, active, evidence) = observe(&request, &witness).map_err(error)?;
        let held = journal.acquire_host_recovery_continuity(session, &history, &active)?;
        held.require_native_origin(&source)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-recovery-continuity:v1",
            &(
                &request,
                &evidence,
                &peer.grant_id,
                &peer.channel_digest,
                crate::vault::random::<32>()?,
            ),
        )
        .map_err(error)?;
        Ok(Self {
            request,
            evidence,
            peer,
            stream,
            source,
            witness,
            digest,
            started: Instant::now(),
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        self.peer.check_current()?;
        let evidence = serde_json::to_string_pretty(&self.evidence).map_err(error)?;
        if evidence.len() > 1_900_000 {
            return Err(Error::Unavailable);
        }
        Ok(format!(
            "DISCLOSE COMPLETE WITNESSED EXPOSURE TO RESTORED HOST\n\nRecipient: locally paired application {} (PID {}, UID {}, grant {}).\n\nThis separately discloses account-wide authorization, agreement, obligation, input/nullifier, amount, fee and witness metadata, including activity outside the paired agreement, to this exact local process for the displayed host inventory and generation.\n\nThe surviving signer keeps its current writer identity. This does not invoke writer recovery, provide signing or wallet keys, sign a transaction, cancel an old signature, or activate the host. Every retained witness permit is conservative exposure, including historically resolved or expired records. The signer cannot establish completeness of the host's inventory or absence of signatures outside this witness protocol. The host must independently authenticate all source journals, retain unknown exposure, and require separate artifact/redelivery consent.\n\nA fresh complete witness replay and the same current session/head are required after this review. Local new authorization is blocked only while this short read-only inventory lease is current. Read checks do not admit durable publication. Publishing a restricted informational generation requires a distinct native review. It grants no financial authority; its exact durable write is separately fenced by the host.\n\nExact request, witness identity, current session, history and all conservative permits:\n{}\n\nNative review binding: {}",
            self.peer.label,
            self.peer.peer.pid(),
            self.peer.peer.uid(),
            self.peer.grant_id,
            evidence,
            self.digest
        ))
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedHostContinuity> {
        self.source.check_current()?;
        authority.check_current()?;
        self.peer.check_current()?;
        if self.source != authority.binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.started.elapsed() >= Duration::from_secs(120)
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedHostContinuity(self))
    }
}
impl ApprovedHostContinuity {
    pub(super) fn serve(
        mut self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
    ) -> authority_bridge::Result<()> {
        let p = &mut self.0;
        if p.started.elapsed() >= Duration::from_secs(120) {
            return Err(BridgeError::Permission);
        }
        let started = Instant::now();
        let (history, active, evidence) = observe(&p.request, &p.witness)?;
        if evidence != p.evidence || started.elapsed() >= Duration::from_secs(30) {
            return Err(BridgeError::Binding);
        }
        let held = journal.acquire_host_recovery_continuity(session, &history, &active)?;
        held.require_native_origin(&p.source)?;
        let check = || -> authority_bridge::Result<()> {
            p.source
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            p.peer
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            held.check_current()?;
            evidence.require_unchanged(&evidence, started.elapsed())?;
            p.witness
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            // The complete replay is fixed at an immutable head. A fresh
            // authenticated active-session check requires exactly that entire
            // snapshot again, so a changed head cannot skip its new history.
            let current = p.witness.client().verify_active_session(&history)?;
            if current.receipt() != active.receipt()
                || current.disclosure() != active.disclosure()
                || current.history_digest() != active.history_digest()
            {
                return Err(BridgeError::Binding);
            }
            evidence.require_unchanged(&evidence, started.elapsed())
        };
        check()?;
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        let evidence_digest = evidence.digest()?;
        if write_frame(
            &mut p.stream,
            &HostContinuityResponse::Held {
                lease_id: lease_id.clone(),
                evidence: Box::new(evidence.clone()),
            },
        )
        .is_err()
        {
            return Err(BridgeError::Ipc);
        }
        // This is read-only disclosure, not durable publication admission.
        // All errors release the local inventory fence. There is no indefinite
        // drain because this protocol has admitted no external durable effect.
        loop {
            let remaining = Duration::from_secs(30)
                .checked_sub(started.elapsed())
                .ok_or(BridgeError::Permission)?;
            let command = crate::ipc::read_frame_with_deadline(&p.stream, &p.peer.peer, remaining)
                .ok()
                .and_then(|frame| serde_json::from_slice::<HostContinuityCommand>(&frame).ok());
            match command {
                Some(HostContinuityCommand::Finish) => {
                    let _ = write_frame(&mut p.stream, &HostContinuityResponse::Finished);
                    return Ok(());
                }
                Some(HostContinuityCommand::CheckCurrent)
                    if check().is_ok()
                        && write_frame(
                            &mut p.stream,
                            &HostContinuityResponse::Current {
                                lease_id: lease_id.clone(),
                                evidence_digest: evidence_digest.clone(),
                            },
                        )
                        .is_ok() =>
                {
                    continue;
                }
                _ => {}
            }
            let _ = write_frame(&mut p.stream, &HostContinuityResponse::Denied);
            return Err(BridgeError::Permission);
        }
    }
}

/// Private source-only complete-origin path; no runtime event enables it.
pub(crate) mod v2;

// Construction-complete historical family; endpoint remains unavailable.
pub(crate) mod v3;

// Transport-complete V5 owner; route remains denied pending qualification.
pub(crate) mod v5;
