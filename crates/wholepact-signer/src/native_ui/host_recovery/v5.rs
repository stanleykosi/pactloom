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
        host_recovery_ipc::v5::{
            HostContinuityCommandV5, HostContinuityResponseV5, HostRecoveryContinuityEvidenceV5,
            HostRecoveryContinuityRequestV5,
            transfer::{self, V5TransferDialect},
            transfer_io,
        },
    },
    consent_journal::SignerConsentJournal,
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

pub(crate) struct PreparedHostContinuityV5 {
    request: HostRecoveryContinuityRequestV5,
    evidence: HostRecoveryContinuityEvidenceV5,
    journal_binding: crate::consent_journal::SignerJournalBinding,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    witness: Arc<NativeWitnessWorkspace>,
    digest: String,
    started: Instant,
    cancelled: Arc<AtomicBool>,
    dialect: V5TransferDialect,
}
pub(crate) struct ApprovedHostContinuityV5(PreparedHostContinuityV5);
fn error(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
/// Genuine native, caller-bound informational observation, never a writer
/// session. Fenced or inactive historical sessions cannot be used as authority.
/// No Clone, serde, public constructor or conversion to a financial owner.
pub(crate) struct NativeHostRecoveryObservationV5 {
    history: wholepact_authority::ReconciledAuthorityHistory,
    journal_binding: crate::consent_journal::SignerJournalBinding,
    source: NativeAuthorityBinding,
    peer: AuthenticatedPeer,
    witness: Arc<NativeWitnessWorkspace>,
    cancelled: Arc<AtomicBool>,
    observed: Instant,
}
impl NativeHostRecoveryObservationV5 {
    pub(crate) fn history(&self) -> &wholepact_authority::ReconciledAuthorityHistory {
        &self.history
    }
    pub(crate) fn require_journal(
        &self,
        binding: &crate::consent_journal::SignerJournalBinding,
    ) -> authority_bridge::Result<()> {
        self.check_current()?;
        if binding != &self.journal_binding {
            return Err(BridgeError::Permission);
        }
        Ok(())
    }
    pub(crate) fn check_current(&self) -> authority_bridge::Result<()> {
        if self.observed.elapsed() >= Duration::from_secs(30) {
            return Err(BridgeError::Permission);
        }
        check_observer(&self.source, &self.peer, &self.witness, &self.cancelled)?;
        self.witness
            .require_native_origin(&self.source)
            .map_err(|_| BridgeError::Permission)
    }
    pub(crate) fn require_native_origin(
        &self,
        source: &NativeAuthorityBinding,
    ) -> authority_bridge::Result<()> {
        self.check_current()?;
        if source != &self.source {
            return Err(BridgeError::Permission);
        }
        Ok(())
    }
    /// Authenticated informational read only. It never proves ownership of an
    /// active transport key or removes a retained fence. Call outside SQL locks.
    pub(crate) fn require_same_snapshot(&self) -> authority_bridge::Result<()> {
        self.check_current()?;
        let current = self.witness.client().snapshot()?;
        if &current != self.history.snapshot() {
            return Err(BridgeError::Binding);
        }
        self.check_current()
    }
    /// Uses the original owner deadline; snapshot I/O cannot create a fresh
    /// witness timeout after an informational transfer has already consumed it.
    pub(crate) fn require_same_snapshot_until(
        &self,
        deadline: Instant,
    ) -> authority_bridge::Result<()> {
        let deadline = deadline.min(self.observed + Duration::from_secs(30));
        transfer_io::require_before_deadline(deadline)?;
        self.check_current()?;
        let current = self.witness.client().snapshot_until(deadline)?;
        transfer_io::require_before_deadline(deadline)?;
        if &current != self.history.snapshot() {
            return Err(BridgeError::Binding);
        }
        self.check_current()?;
        transfer_io::require_before_deadline(deadline)
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_v5(
    request: &HostRecoveryContinuityRequestV5,
    journal: &SignerConsentJournal,
    source: &NativeAuthorityBinding,
    peer: &AuthenticatedPeer,
    witness: &Arc<NativeWitnessWorkspace>,
    cancelled: &Arc<AtomicBool>,
) -> authority_bridge::Result<(
    NativeHostRecoveryObservationV5,
    HostRecoveryContinuityEvidenceV5,
)> {
    observe_v5_inner(request, journal, source, peer, witness, cancelled, None)
}
/// Post-review replay shares the single native transfer/admission deadline.
#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_v5_until(
    request: &HostRecoveryContinuityRequestV5,
    journal: &SignerConsentJournal,
    source: &NativeAuthorityBinding,
    peer: &AuthenticatedPeer,
    witness: &Arc<NativeWitnessWorkspace>,
    cancelled: &Arc<AtomicBool>,
    deadline: Instant,
) -> authority_bridge::Result<(
    NativeHostRecoveryObservationV5,
    HostRecoveryContinuityEvidenceV5,
)> {
    observe_v5_inner(
        request,
        journal,
        source,
        peer,
        witness,
        cancelled,
        Some(deadline),
    )
}
#[allow(clippy::too_many_arguments)]
fn observe_v5_inner(
    request: &HostRecoveryContinuityRequestV5,
    journal: &SignerConsentJournal,
    source: &NativeAuthorityBinding,
    peer: &AuthenticatedPeer,
    witness: &Arc<NativeWitnessWorkspace>,
    cancelled: &Arc<AtomicBool>,
    deadline: Option<Instant>,
) -> authority_bridge::Result<(
    NativeHostRecoveryObservationV5,
    HostRecoveryContinuityEvidenceV5,
)> {
    let check = || -> authority_bridge::Result<()> {
        if let Some(deadline) = deadline {
            transfer_io::require_before_deadline(deadline)?;
        }
        check_observer(source, peer, witness, cancelled)
    };
    check()?;
    request.validate()?;
    check()?;
    witness
        .require_native_origin(source)
        .map_err(|_| BridgeError::Permission)?;
    if &peer.native_origin != source
        || !peer.scope.history_read
        || !peer.scope.authorization_export
        || peer.scope.account_id != request.account_id
        || peer.scope.manifest_digest != request.inventory_digest
        || witness.disclosure() != request.expected_witness
    {
        return Err(BridgeError::Binding);
    }
    let check_replay = || check().map_err(|_| wholepact_authority::AuthorityError::Permission);
    let history = if let Some(deadline) = deadline {
        witness
            .client()
            .reconcile_history_checked_until(deadline, check_replay)?
    } else {
        witness.client().reconcile_history_checked(check_replay)?
    };
    check()?;
    let snapshot = history.snapshot();
    if snapshot.account_id != request.account_id
        || snapshot.network_profile_id != request.network_profile_id
        || snapshot.writer_epoch != request.expected_writer_epoch
        || snapshot.writer_certificate_digest != witness.writer_certificate_digest()
        || history.disclosure() != &request.expected_witness
    {
        return Err(BridgeError::Binding);
    }
    let observation = NativeHostRecoveryObservationV5 {
        history,
        journal_binding: journal.binding(),
        source: source.clone(),
        peer: peer.clone(),
        witness: witness.clone(),
        cancelled: cancelled.clone(),
        observed: Instant::now(),
    };
    if let Some(deadline) = deadline {
        observation.require_same_snapshot_until(deadline)?;
    } else {
        observation.require_same_snapshot()?;
    }
    check()?;
    let held = journal.acquire_host_recovery_continuity_v5(&observation)?;
    held.require_native_origin(source)?;
    let complete_history = held.history_v5().clone();
    held.check_current()?;
    drop(held);
    let snapshot = observation.history().snapshot();
    let historical_session = snapshot.active_writer_session.as_ref();
    let evidence = HostRecoveryContinuityEvidenceV5 {
        request: request.clone(),
        writer_certificate_digest: snapshot.writer_certificate_digest.clone(),
        writer_session_id: historical_session.map(|s| s.session_id.clone()),
        writer_session_expires_at_ms: historical_session.map(|s| s.expires_at_ms),
        head: snapshot.head.clone(),
        history_digest: observation.history().history_digest()?,
        complete_history,
    };
    evidence.validate()?;
    observation.check_current()?;
    check()?;
    Ok((observation, evidence))
}
impl PreparedHostContinuityV5 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        request: HostRecoveryContinuityRequestV5,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        source: NativeAuthorityBinding,
        witness: Arc<NativeWitnessWorkspace>,
        cancelled: Arc<AtomicBool>,
        dialect: V5TransferDialect,
    ) -> Result<Self> {
        crate::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint()
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
        let (observation, evidence) =
            observe_v5(&request, journal, &source, &peer, &witness, &cancelled).map_err(error)?;
        let held = journal.acquire_host_recovery_continuity_v5(&observation)?;
        held.require_native_origin(&source)?;
        if held.history_v5() != &evidence.complete_history {
            return Err(Error::ReviewMismatch);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-recovery-continuity:v5",
            &(
                &request,
                &evidence,
                &peer.grant_id,
                &peer.channel_digest,
                dialect,
                transfer::MAX_TRANSFER_EVIDENCE_BYTES,
                crate::vault::random::<32>()?,
            ),
        )
        .map_err(error)?;
        if dialect == V5TransferDialect::SingleFrame {
            crate::authority_bridge::host_recovery_ipc::v5::require_wire_capacity(
                &HostContinuityResponseV5::Held {
                    lease_id: "00".repeat(32),
                    evidence: Box::new(evidence.clone()),
                },
            )
            .map_err(error)?;
        }
        Ok(Self {
            request,
            evidence,
            journal_binding: journal.binding(),
            peer,
            stream,
            source,
            witness,
            digest,
            started: Instant::now(),
            cancelled,
            dialect,
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
        let transport = match self.dialect {
            V5TransferDialect::SingleFrame => {
                "Legacy single-frame V5, subject to the unchanged 128 KiB frame ceiling."
            }
            V5TransferDialect::BoundedV1 => {
                "Bounded V5 dialect v5_bounded_transfer_v1: exact complete evidence up to 1 MiB, transferred in at most 32 chunks of 32 KiB (the last may be shorter). Fresh post-review replay, serialization, all chunk turns, complete validation and final current-owner confirmation share the same original 30-second server window. The window is never renewed for a chunk or acknowledgement."
            }
        };
        let display = format!(
            "DISCLOSE COMPLETE WITNESSED EXPOSURE TO RESTORED HOST\n\nRecipient: locally paired application {} (PID {}, UID {}, grant {}).\n\nTransfer: {}\n\nThis separately discloses account-wide authorization, agreement, obligation, input/nullifier, amount, fee and witness metadata, including activity outside the paired agreement, to this exact local process for the displayed host inventory and generation.\n\nThe surviving signer retains its identity. An observed session is historical metadata, including a fenced, paused or retired state; it is never restored writer authority. This does not invoke writer recovery, provide signing or wallet keys, sign a transaction, cancel an old signature, or activate the host. Every admitted origin is conservative exposure, including historically resolved or expired records. Construction Reserve and Consume records include their exact original inputs and deadlines; the complete transport grant, claimed credential, reentry, reservation, consumption, caller/native lineage and retained fence records are also preserved; consumption or expiry never releases their permanent debit/input charge. Current continuity refuses local-only admissions missing from witness replay; saved audit records retain that explicit unresolved state. Missing originals, results, or key-use fences never prove no signature exists. The signer cannot establish completeness of the host's inventory or absence of signatures outside this witness protocol. The host must independently authenticate all source journals, retain unknown exposure, and require separate artifact/redelivery consent.\n\nDisclosure may arrive in bounded pieces. Metadata already disclosed to this process cannot be recalled by cancellation, failed final validation or failed publication. Incomplete transfer grants no continuity or publication authority.\n\nA fresh complete witness replay plus exact signer journal snapshot and the same observed snapshot/head are required after this review. Local new authorization is blocked only while this short read-only inventory lease is current. Read checks do not admit durable publication. Publishing a restricted informational generation requires a distinct native review. It grants no financial authority; its exact durable write is separately fenced by the host.\n\nExact request, witness identity, historical session state, history and every online, full-witness offline and minimal-local offline origin, retained review receipt and permanent account exclusion:\n{}\n\nNative review binding: {}",
            self.peer.label,
            self.peer.peer.pid(),
            self.peer.peer.uid(),
            self.peer.grant_id,
            transport,
            evidence,
            self.digest
        );
        if display.len() > 1_900_000 {
            return Err(Error::Unavailable);
        }
        Ok(display)
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedHostContinuityV5> {
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
        Ok(ApprovedHostContinuityV5(self))
    }
}
impl ApprovedHostContinuityV5 {
    pub(crate) fn serve(mut self, journal: &SignerConsentJournal) -> authority_bridge::Result<()> {
        let p = &mut self.0;
        if p.journal_binding != journal.binding() || p.started.elapsed() >= Duration::from_secs(120)
        {
            return Err(BridgeError::Permission);
        }
        // This begins before the fresh replay. Serialization, transfer, final
        // snapshot and all later Current checks spend this same original budget.
        let started = Instant::now();
        let deadline = started + Duration::from_secs(30);
        let (observation, evidence) = match p.dialect {
            V5TransferDialect::SingleFrame => observe_v5(
                &p.request,
                journal,
                &p.source,
                &p.peer,
                &p.witness,
                &p.cancelled,
            )?,
            V5TransferDialect::BoundedV1 => observe_v5_until(
                &p.request,
                journal,
                &p.source,
                &p.peer,
                &p.witness,
                &p.cancelled,
                deadline,
            )?,
        };
        if evidence != p.evidence || started.elapsed() >= Duration::from_secs(30) {
            return Err(BridgeError::Binding);
        }
        let held = journal.acquire_host_recovery_continuity_v5(&observation)?;
        held.require_native_origin(&p.source)?;
        if held.history_v5() != &evidence.complete_history {
            return Err(BridgeError::Binding);
        }
        // Per-turn checks use the actual retained native, peer, witness workspace,
        // cancellation and journal owners. They never do a per-chunk network read.
        let check = || -> authority_bridge::Result<()> {
            transfer_io::require_before_deadline(deadline)?;
            check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)?;
            observation.require_native_origin(&p.source)?;
            held.require_native_origin(&p.source)?;
            held.check_current()?;
            transfer_io::require_before_deadline(deadline)
        };
        check()?;
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        let evidence_digest = evidence.digest()?;
        check()?;
        if p.dialect == V5TransferDialect::SingleFrame {
            // Legacy peers still receive exactly one complete Held response and
            // retain the legacy frame limit. There is no dialect fallback.
            let check_legacy = || -> authority_bridge::Result<()> {
                check()?;
                observation.require_same_snapshot()?;
                check()
            };
            check_legacy()?;
            write_frame(
                &mut p.stream,
                &HostContinuityResponseV5::Held {
                    lease_id: lease_id.clone(),
                    evidence: Box::new(evidence.clone()),
                },
            )?;
            loop {
                let remaining = Duration::from_secs(30)
                    .checked_sub(started.elapsed())
                    .ok_or(BridgeError::Permission)?;
                let command =
                    crate::ipc::read_frame_with_deadline(&p.stream, &p.peer.peer, remaining)
                        .ok()
                        .and_then(|frame| {
                            serde_json::from_slice::<HostContinuityCommandV5>(&frame).ok()
                        });
                match command {
                    Some(HostContinuityCommandV5::Finish {}) => {
                        let _ = write_frame(&mut p.stream, &HostContinuityResponseV5::Finished {});
                        return Ok(());
                    }
                    Some(HostContinuityCommandV5::CheckCurrent {})
                        if check_legacy().is_ok()
                            && write_frame(
                                &mut p.stream,
                                &HostContinuityResponseV5::Current {
                                    lease_id: lease_id.clone(),
                                    evidence_digest: evidence_digest.clone(),
                                },
                            )
                            .is_ok() => {}
                    _ => {
                        let _ = write_frame(&mut p.stream, &HostContinuityResponseV5::Denied {});
                        return Err(BridgeError::Permission);
                    }
                }
            }
        }

        let mut sender = transfer::TransferSender::new(
            transfer::TransferMetadata {
                purpose: transfer::TransferPurpose::Continuity,
                transfer_id: hex::encode(
                    crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?,
                ),
                lease_id: lease_id.clone(),
                request_digest: p.request.digest()?,
                native_review_digest: p.digest.clone(),
                evidence_digest: evidence_digest.clone(),
                head_digest: evidence.head.digest.clone(),
                head_sequence: evidence.head.sequence,
            },
            &evidence,
        )?;
        check()?;
        let header = sender.begin()?;
        let chunk_count = header.chunk_count;
        check()?;
        transfer_io::write_frame_until(
            &mut p.stream,
            &transfer::TransferResponseV1::Begin { header },
            deadline,
        )?;
        check()?;
        // Strict stop-and-wait: no next chunk exists until the exact next request
        // has been consumed on this retained authenticated stream.
        for _ in 0..chunk_count {
            check()?;
            let frame = transfer_io::read_frame_until(&p.stream, &p.peer.peer, deadline)?;
            check()?;
            let command: transfer::TransferCommandV1 = transfer::decode_frame(&frame)?;
            if matches!(command, transfer::TransferCommandV1::Finish {}) {
                sender.finish();
                return Ok(());
            }
            let chunk = sender.next(&command)?;
            check()?;
            transfer_io::write_frame_until(
                &mut p.stream,
                &transfer::TransferResponseV1::Chunk { chunk },
                deadline,
            )?;
            check()?;
        }
        let frame = transfer_io::read_frame_until(&p.stream, &p.peer.peer, deadline)?;
        check()?;
        let command: transfer::TransferCommandV1 = transfer::decode_frame(&frame)?;
        if matches!(command, transfer::TransferCommandV1::Finish {}) {
            sender.finish();
            return Ok(());
        }
        sender.accept_complete(&command)?;
        check()?;
        // Complete-byte acknowledgement does not grant authority. Only this
        // actual owner can confirm, after the final exact authenticated snapshot.
        observation.require_same_snapshot_until(deadline)?;
        check()?;
        let confirmation = sender.confirmation()?;
        check()?;
        transfer_io::write_frame_until(&mut p.stream, &confirmation, deadline)?;
        check()?;
        drop(sender);

        // This is read-only disclosure, not publication admission. Any error,
        // disconnect, cancellation or original expiry drops the actual journal
        // exclusion. Cleanup neither renews time nor drains acknowledgements.
        loop {
            check()?;
            let frame = transfer_io::read_frame_until(&p.stream, &p.peer.peer, deadline)?;
            check()?;
            let command: HostContinuityCommandV5 = transfer::decode_frame(&frame)?;
            match command {
                HostContinuityCommandV5::Finish {} => {
                    transfer_io::write_frame_until(
                        &mut p.stream,
                        &HostContinuityResponseV5::Finished {},
                        deadline,
                    )?;
                    check()?;
                    return Ok(());
                }
                HostContinuityCommandV5::CheckCurrent {} => {
                    observation.require_same_snapshot_until(deadline)?;
                    check()?;
                    transfer_io::write_frame_until(
                        &mut p.stream,
                        &HostContinuityResponseV5::Current {
                            lease_id: lease_id.clone(),
                            evidence_digest: evidence_digest.clone(),
                        },
                        deadline,
                    )?;
                    check()?;
                }
            }
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
