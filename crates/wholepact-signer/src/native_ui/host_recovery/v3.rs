#![allow(dead_code)]
//! Exact native consent before disclosing all witnessed account reservations to
//! a restored host. The surviving signer retains its existing writer and secrets.
use super::super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{
    Error, Result,
    authority_bridge::{
        self, BridgeError,
        dispatch_ipc::write_frame,
        host_recovery_ipc::v3::{
            HostContinuityCommandV3, HostContinuityResponseV3, HostRecoveryContinuityEvidenceV3,
            HostRecoveryContinuityRequestV3,
        },
    },
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use std::{
    os::unix::net::UnixStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(crate) struct PreparedHostContinuityV3 {
    request: HostRecoveryContinuityRequestV3,
    evidence: HostRecoveryContinuityEvidenceV3,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    witness: Arc<NativeWitnessWorkspace>,
    digest: String,
    started: Instant,
    cancelled: Arc<AtomicBool>,
}
pub(crate) struct ApprovedHostContinuityV3(PreparedHostContinuityV3);
fn error(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
pub(crate) fn observe_v3(
    request: &HostRecoveryContinuityRequestV3,
    witness: &NativeWitnessWorkspace,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    mut check_current: impl FnMut() -> authority_bridge::Result<()>,
) -> authority_bridge::Result<(
    wholepact_authority::ReconciledAuthorityHistory,
    wholepact_authority::AuthenticatedWriterSession,
    HostRecoveryContinuityEvidenceV3,
)> {
    check_current()?;
    request.validate()?;
    witness
        .check_current()
        .map_err(|_| BridgeError::Permission)?;
    if witness.disclosure() != request.expected_witness {
        return Err(BridgeError::Binding);
    }
    let history = witness.client().reconcile_history_checked(|| {
        check_current().map_err(|_| wholepact_authority::AuthorityError::Permission)
    })?;
    check_current()?;
    let active = witness.client().verify_active_session(&history)?;
    check_current()?;
    let s = history.snapshot();
    if s.account_id != request.account_id
        || s.network_profile_id != request.network_profile_id
        || s.writer_epoch != request.expected_writer_epoch
        || s.writer_certificate_digest != witness.writer_certificate_digest()
        || history.disclosure() != &request.expected_witness
    {
        return Err(BridgeError::Binding);
    }
    let held = journal.acquire_host_recovery_continuity_v3(session, &history, &active)?;
    let complete_history = held.history_v3().clone();
    held.check_current()?;
    drop(held);
    let evidence = HostRecoveryContinuityEvidenceV3 {
        request: request.clone(),
        writer_certificate_digest: s.writer_certificate_digest.clone(),
        writer_session_id: active.receipt().session_id.clone(),
        writer_session_expires_at_ms: active.receipt().expires_at_ms,
        head: s.head.clone(),
        history_digest: history.history_digest()?,
        complete_history,
    };
    evidence.validate()?;
    witness
        .check_current()
        .map_err(|_| BridgeError::Permission)?;
    check_current()?;
    Ok((history, active, evidence))
}
impl PreparedHostContinuityV3 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        request: HostRecoveryContinuityRequestV3,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        source: NativeAuthorityBinding,
        witness: Arc<NativeWitnessWorkspace>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        crate::authority_bridge::host_recovery_ipc::v3::require_complete_origin_endpoint()
            .map_err(error)?;
        source.check_current()?;
        peer.check_current()?;
        if peer.native_origin != source
            || !peer.scope.history_read
            || !peer.scope.authorization_export
            || peer.scope.account_id != request.account_id
            || peer.scope.manifest_digest != request.inventory_digest
        {
            return Err(Error::Authentication);
        }
        let (history, active, evidence) = observe_v3(&request, &witness, journal, session, || {
            check_observer(&source, &peer, &witness, &cancelled)
        })
        .map_err(error)?;
        let held = journal.acquire_host_recovery_continuity_v3(session, &history, &active)?;
        held.require_native_origin(&source)?;
        if held.history_v3() != &evidence.complete_history {
            return Err(Error::ReviewMismatch);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-recovery-continuity:v3",
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
            cancelled,
        })
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> Result<String> {
        check_observer(&self.source, &self.peer, &self.witness, &self.cancelled).map_err(error)?;
        self.source.check_current()?;
        self.peer.check_current()?;
        let evidence = serde_json::to_string_pretty(&self.evidence).map_err(error)?;
        if evidence.len() > 1_900_000 {
            return Err(Error::Unavailable);
        }
        Ok(format!(
            "DISCLOSE COMPLETE WITNESSED EXPOSURE TO RESTORED HOST\n\nRecipient: locally paired application {} (PID {}, UID {}, grant {}).\n\nThis separately discloses account-wide authorization, agreement, obligation, input/nullifier, amount, fee and witness metadata, including activity outside the paired agreement, to this exact local process for the displayed host inventory and generation.\n\nThe surviving signer keeps its current writer identity. This does not invoke writer recovery, provide signing or wallet keys, sign a transaction, cancel an old signature, or activate the host. Every admitted origin is conservative exposure, including historically resolved or expired records. Construction Reserve and Consume records include their exact original inputs and deadlines; consumption or expiry never releases their permanent debit/input charge. Current continuity refuses local-only admissions missing from witness replay; saved audit records retain that explicit unresolved state. Missing originals, results, or key-use fences never prove no signature exists. The signer cannot establish completeness of the host's inventory or absence of signatures outside this witness protocol. The host must independently authenticate all source journals, retain unknown exposure, and require separate artifact/redelivery consent.\n\nA fresh complete witness replay plus exact signer journal snapshot and the same current session/head are required after this review. Local new authorization is blocked only while this short read-only inventory lease is current. Read checks do not admit durable publication. Publishing a restricted informational generation requires a distinct native review. It grants no financial authority; its exact durable write is separately fenced by the host.\n\nExact request, witness identity, current session, history and every online, full-witness offline and minimal-local offline origin, retained review receipt and permanent account exclusion:\n{}\n\nNative review binding: {}",
            self.peer.label,
            self.peer.peer.pid(),
            self.peer.peer.uid(),
            self.peer.grant_id,
            evidence,
            self.digest
        ))
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedHostContinuityV3> {
        check_observer(&self.source, &self.peer, &self.witness, &self.cancelled).map_err(error)?;
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
        Ok(ApprovedHostContinuityV3(self))
    }
}
impl ApprovedHostContinuityV3 {
    pub(crate) fn serve(
        mut self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
    ) -> authority_bridge::Result<()> {
        let p = &mut self.0;
        if p.started.elapsed() >= Duration::from_secs(120) {
            return Err(BridgeError::Permission);
        }
        let started = Instant::now();
        let (history, active, evidence) =
            observe_v3(&p.request, &p.witness, journal, session, || {
                check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)
            })?;
        if evidence != p.evidence || started.elapsed() >= Duration::from_secs(30) {
            return Err(BridgeError::Binding);
        }
        let held = journal.acquire_host_recovery_continuity_v3(session, &history, &active)?;
        held.require_native_origin(&p.source)?;
        if held.history_v3() != &evidence.complete_history {
            return Err(BridgeError::Binding);
        }
        let check = || -> authority_bridge::Result<()> {
            check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)?;
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
            &HostContinuityResponseV3::Held {
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
                .and_then(|frame| serde_json::from_slice::<HostContinuityCommandV3>(&frame).ok());
            match command {
                Some(HostContinuityCommandV3::Finish) => {
                    let _ = write_frame(&mut p.stream, &HostContinuityResponseV3::Finished);
                    return Ok(());
                }
                Some(HostContinuityCommandV3::CheckCurrent)
                    if check().is_ok()
                        && write_frame(
                            &mut p.stream,
                            &HostContinuityResponseV3::Current {
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
            let _ = write_frame(&mut p.stream, &HostContinuityResponseV3::Denied);
            return Err(BridgeError::Permission);
        }
    }
}

// Cancellation observes the same native/pairing/witness owner; it creates no grant.
pub(crate) fn check_observer(
    source: &NativeAuthorityBinding,
    peer: &AuthenticatedPeer,
    witness: &NativeWitnessWorkspace,
    cancelled: &AtomicBool,
) -> authority_bridge::Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(BridgeError::Permission);
    }
    source
        .check_current()
        .map_err(|_| BridgeError::Permission)?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    witness.check_current().map_err(|_| BridgeError::Permission)
}
