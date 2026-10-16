#![allow(dead_code)]
//! Native-reviewed one-shot admission of an informational host successor.
//! Remote continuity is an observation, not a lease over the witness history.
use super::super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    host_recovery::v2::{check_observer, observe_v2},
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{
    Error, Result,
    authority_bridge::{
        self, BridgeError,
        dispatch_ipc::write_frame,
        host_publication_ipc::PublicationWindow,
        host_publication_ipc::v2::{
            HostPublicationCommandV2, HostPublicationResponseV2, HostRecoveryPublicationRecordV2,
            HostRecoveryPublicationRequestV2,
        },
        host_recovery_ipc::v2::HostRecoveryContinuityEvidenceV2,
    },
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use std::{
    os::unix::net::UnixStream,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

pub(crate) struct PreparedHostPublicationV2 {
    request: HostRecoveryPublicationRequestV2,
    evidence: HostRecoveryContinuityEvidenceV2,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    witness: Arc<NativeWitnessWorkspace>,
    digest: String,
    started: Instant,
    cancelled: Arc<AtomicBool>,
}
pub(crate) struct ApprovedHostPublicationV2(PreparedHostPublicationV2);
fn error(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
impl PreparedHostPublicationV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        request: HostRecoveryPublicationRequestV2,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        source: NativeAuthorityBinding,
        witness: Arc<NativeWitnessWorkspace>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        request.validate().map_err(error)?;
        crate::authority_bridge::host_recovery_ipc::v2::require_complete_origin_endpoint()
            .map_err(error)?;
        source.check_current()?;
        peer.check_current()?;
        if peer.native_origin != source
            || !peer.scope.history_read
            || !peer.scope.authorization_export
            || peer.scope.account_id != request.continuity.account_id
            || peer.scope.manifest_digest != request.continuity.inventory_digest
        {
            return Err(Error::Authentication);
        }
        let (history, active, evidence) =
            observe_v2(&request.continuity, &witness, journal, session, || {
                check_observer(&source, &peer, &witness, &cancelled)
            })
            .map_err(error)?;
        request.matches_evidence(&evidence).map_err(error)?;
        let held = journal.acquire_host_recovery_continuity_v2(session, &history, &active)?;
        held.require_native_origin(&source)?;
        if held.history_v2() != &evidence.complete_history {
            return Err(Error::ReviewMismatch);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-recovery-publication:v2",
            &(
                &request,
                &evidence,
                &peer.grant_id,
                &peer.channel_digest,
                crate::vault::random::<32>()?,
            ),
        )
        .map_err(error)?;
        // No journal guard is held while the owner considers the native review.
        drop(held);
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
        let request = serde_json::to_string_pretty(&self.request).map_err(error)?;
        let evidence = serde_json::to_string_pretty(&self.evidence).map_err(error)?;
        if request.len() + evidence.len() > 1_900_000 {
            return Err(Error::Unavailable);
        }
        Ok(format!(
            "PUBLISH ONE RESTRICTED INFORMATIONAL HOST GENERATION\n\nRecipient: locally paired application {} (PID {}, UID {}, grant {}).\n\nThis is separate approval for the exact target directory, inventory, generation and manifest below. The complete online, full-witness offline and minimal-local offline origin history, retained receipt metadata and permanent account-use exclusions are disclosed to this process, including agreement, obligation, input/nullifier, amount, fee and authorization metadata. Earlier read-only disclosure does not approve this publication.\n\nThe successor is an immutable informational recovery snapshot. This approval grants no spending, signing, replacement, redelivery, submission, observer enrollment or current financial status. Every admitted origin, known obligation and possible external authorization remains conservative. Local-only admissions missing from current witness replay remain explicitly unresolved; missing original consent, key-use or result is never an absence-of-signature proof. Later signer activity and signatures outside this witness protocol remain possible. Sequential account observations never establish an atomic global cutoff. The host must preserve unknown exposure and require fresh independent checks for every financial action.\n\nThe signer keeps its existing writer and all credentials. No writer recovery occurs. A fresh same-head/session observation is required before admission. A stalled or disconnected process cannot retain the preadmission fence beyond its short deadline. At admission the signer releases its local fence before responding; it does not remain frozen while the host writes. The host must protect its exact final durable write with its own current native publication lease. A saved audit record cannot grant new admission.\n\nExact publication request:\n{}\n\nExact conservative continuity evidence:\n{}\n\nNative review binding: {}",
            self.peer.label,
            self.peer.peer.pid(),
            self.peer.peer.uid(),
            self.peer.grant_id,
            request,
            evidence,
            self.digest,
        ))
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedHostPublicationV2> {
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
        Ok(ApprovedHostPublicationV2(self))
    }
}
impl ApprovedHostPublicationV2 {
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
        let mut window = PublicationWindow::default();
        // Remote work is never performed while retaining the local journal fence.
        let (history, active, evidence) =
            observe_v2(&p.request.continuity, &p.witness, journal, session, || {
                check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)
            })?;
        p.request.matches_evidence(&evidence)?;
        evidence.require_unchanged(&p.evidence, started.elapsed())?;
        let held = journal.acquire_host_recovery_continuity_v2(session, &history, &active)?;
        held.require_native_origin(&p.source)?;
        if held.history_v2() != &evidence.complete_history {
            return Err(BridgeError::Binding);
        }
        p.peer
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)?;
        window.remaining(started.elapsed())?;
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        let request_digest = p.request.digest()?;
        write_frame(
            &mut p.stream,
            &HostPublicationResponseV2::Prepared {
                lease_id: lease_id.clone(),
                request_digest: request_digest.clone(),
                native_review_digest: p.digest.clone(),
                evidence: Box::new(evidence.clone()),
            },
        )?;
        let frame = crate::ipc::read_frame_with_deadline(
            &p.stream,
            &p.peer.peer,
            window.remaining(started.elapsed())?,
        )
        .map_err(|_| BridgeError::Ipc)?;
        // Finish, malformed input, timeout and disconnect all drop this guard.
        // There is no uncertain-consumer drain for an informational snapshot.
        let command: HostPublicationCommandV2 =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        drop(held);
        match command {
            HostPublicationCommandV2::Finish => {
                let _ = write_frame(&mut p.stream, &HostPublicationResponseV2::Finished);
                return Ok(());
            }
            HostPublicationCommandV2::Admit {
                lease_id: supplied,
                request_digest: supplied_digest,
            } if supplied == lease_id && supplied_digest == request_digest => {}
            _ => return Err(BridgeError::Binding),
        }
        check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)?;
        window.remaining(started.elapsed())?;
        // This fresh observation is not a remote lease. If local activity races
        // it, reacquisition below checks every local original against this exact
        // complete history and fails if that activity is missing or changed.
        let current = p.witness.client().verify_active_session(&history)?;
        if current.receipt() != active.receipt()
            || current.disclosure() != active.disclosure()
            || current.history_digest() != active.history_digest()
        {
            return Err(BridgeError::Binding);
        }
        let held = journal.acquire_host_recovery_continuity_v2(session, &history, &current)?;
        held.require_native_origin(&p.source)?;
        if held.history_v2() != &evidence.complete_history {
            return Err(BridgeError::Binding);
        }
        check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)?;
        let native = p
            .source
            .publication_lease()
            .map_err(|_| BridgeError::Permission)?;
        p.peer
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        p.witness
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        held.check_current()?;
        window.consume_and_release(held, started.elapsed())?;
        let record = HostRecoveryPublicationRecordV2 {
            request: p.request.clone(),
            native_review_digest: p.digest.clone(),
            admission_id: lease_id,
        };
        // The native decision has now admitted only this exact snapshot. Release
        // every local/native fence BEFORE any remote response or host disk write.
        drop(native);
        write_frame(
            &mut p.stream,
            &HostPublicationResponseV2::Admitted {
                record: Box::new(record),
            },
        )
    }
}
