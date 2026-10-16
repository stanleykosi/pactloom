//! Native-reviewed one-shot admission of an informational host successor.
//! Remote continuity is an observation, not a lease over the witness history.
use super::super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    host_recovery::v5::{check_observer, observe_v5, observe_v5_until},
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{
    Error, Result,
    authority_bridge::{
        self, BridgeError,
        dispatch_ipc::write_frame,
        host_publication_ipc::PublicationWindow,
        host_publication_ipc::v5::{
            HostPublicationCommandV5, HostPublicationResponseV5, HostRecoveryPublicationRecordV5,
            HostRecoveryPublicationRequestV5,
        },
        host_recovery_ipc::v5::{
            HostRecoveryContinuityEvidenceV5,
            transfer::{
                TransferCommandV1, TransferMetadata, TransferPurpose, TransferResponseV1,
                TransferSender, V5TransferDialect, decode_frame,
            },
            transfer_io::{read_frame_until, require_before_deadline, write_frame_until},
        },
    },
    consent_journal::SignerConsentJournal,
    ipc::AuthenticatedPeer,
};
use std::{
    os::unix::net::UnixStream,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

pub(crate) struct PreparedHostPublicationV5 {
    request: HostRecoveryPublicationRequestV5,
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
pub(crate) struct ApprovedHostPublicationV5(PreparedHostPublicationV5);
fn error(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
impl PreparedHostPublicationV5 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        request: HostRecoveryPublicationRequestV5,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        source: NativeAuthorityBinding,
        witness: Arc<NativeWitnessWorkspace>,
        cancelled: Arc<AtomicBool>,
        dialect: V5TransferDialect,
    ) -> Result<Self> {
        request.validate().map_err(error)?;
        crate::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint()
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
        let (observation, evidence) = observe_v5(
            &request.continuity,
            journal,
            &source,
            &peer,
            &witness,
            &cancelled,
        )
        .map_err(error)?;
        request.matches_evidence(&evidence).map_err(error)?;
        let held = journal.acquire_host_recovery_continuity_v5(&observation)?;
        held.require_native_origin(&source)?;
        if held.history_v5() != &evidence.complete_history {
            return Err(Error::ReviewMismatch);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-recovery-publication:v5",
            &(
                &request,
                &dialect,
                &evidence,
                &peer.grant_id,
                &peer.channel_digest,
                crate::vault::random::<32>()?,
            ),
        )
        .map_err(error)?;
        // No journal guard is held while the owner considers the native review.
        drop(held);
        if dialect == V5TransferDialect::SingleFrame {
            crate::authority_bridge::host_recovery_ipc::v5::require_wire_capacity(
                &HostPublicationResponseV5::Prepared {
                    lease_id: "00".repeat(32),
                    request_digest: request.digest().map_err(error)?,
                    native_review_digest: digest.clone(),
                    evidence: Box::new(evidence.clone()),
                },
            )
            .map_err(error)?;
        } else {
            evidence.validate().map_err(error)?;
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
        let request = serde_json::to_string_pretty(&self.request).map_err(error)?;
        let evidence = serde_json::to_string_pretty(&self.evidence).map_err(error)?;
        let transfer_scope = match self.dialect {
            V5TransferDialect::SingleFrame => {
                "Legacy single-frame V5 disclosure; the existing frame cap applies."
            }
            V5TransferDialect::BoundedV1 => {
                "Bounded V5 disclosure: complete evidence up to 1 MiB, fixed 32 KiB raw chunks, at most 32 chunk turns, each within the existing 128 KiB wire limit. Fresh replay, transfer, verification and admission share the original 30-second window. Already disclosed metadata cannot be recalled if cancellation, expiry or failure stops completion. Reconstructed data alone never approves publication; separate exact admission remains required."
            }
        };
        let evidence = format!("{transfer_scope}\n\n{evidence}");
        if request.len() + evidence.len() > 1_900_000 {
            return Err(Error::Unavailable);
        }
        let display = format!(
            "PUBLISH ONE RESTRICTED INFORMATIONAL HOST GENERATION\n\nRecipient: locally paired application {} (PID {}, UID {}, grant {}).\n\nThis is separate approval for the exact target directory, inventory, generation and manifest below. The complete online, full-witness offline and minimal-local offline origin history, retained receipt metadata and permanent account-use exclusions are disclosed to this process, including agreement, obligation, input/nullifier, amount, fee and authorization metadata. Earlier read-only disclosure does not approve this publication.\n\nThe successor is an immutable informational recovery snapshot. This approval grants no spending, signing, replacement, redelivery, submission, observer enrollment or current financial status. Every admitted origin, known obligation and possible external authorization remains conservative. Construction Reserve and Consume records retain their original inputs, deadlines and permanent debit/input charges. Every transport grant, claimed credential, reentry, reservation, consumption, caller/native lineage and retained fence is included unchanged; consumption or expiry never refunds them. Local-only admissions missing from current witness replay remain explicitly unresolved; missing original consent, key-use or result is never an absence-of-signature proof. Later signer activity and signatures outside this witness protocol remain possible. Sequential account observations never establish an atomic global cutoff. The host must preserve unknown exposure and require fresh independent checks for every financial action.\n\nThe signer retains its credentials. The observed session is historical metadata, including fenced, paused or retired state; it never proves or restores writer authority. No writer recovery occurs. A fresh exact authenticated snapshot/head observation is required before admission. A stalled or disconnected process cannot retain the preadmission fence beyond its short deadline. At admission the signer releases its local fence before responding; it does not remain frozen while the host writes. The host must protect its exact final durable write with its own current native publication lease. A saved audit record cannot grant new admission.\n\nExact publication request:\n{}\n\nExact conservative continuity evidence:\n{}\n\nNative review binding: {}",
            self.peer.label,
            self.peer.peer.pid(),
            self.peer.peer.uid(),
            self.peer.grant_id,
            request,
            evidence,
            self.digest,
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
    ) -> Result<ApprovedHostPublicationV5> {
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
        Ok(ApprovedHostPublicationV5(self))
    }
}
impl ApprovedHostPublicationV5 {
    pub(crate) fn serve(mut self, journal: &SignerConsentJournal) -> authority_bridge::Result<()> {
        let p = &mut self.0;
        if p.journal_binding != journal.binding() || p.started.elapsed() >= Duration::from_secs(120)
        {
            return Err(BridgeError::Permission);
        }
        let started = Instant::now();
        let mut window = PublicationWindow::default();
        // Remote work is never performed while retaining the local journal fence.
        let deadline = started + Duration::from_secs(30);
        let (observation, evidence) = if p.dialect == V5TransferDialect::BoundedV1 {
            observe_v5_until(
                &p.request.continuity,
                journal,
                &p.source,
                &p.peer,
                &p.witness,
                &p.cancelled,
                deadline,
            )?
        } else {
            observe_v5(
                &p.request.continuity,
                journal,
                &p.source,
                &p.peer,
                &p.witness,
                &p.cancelled,
            )?
        };
        p.request.matches_evidence(&evidence)?;
        evidence.require_unchanged(&p.evidence, started.elapsed())?;
        let held = journal.acquire_host_recovery_continuity_v5(&observation)?;
        held.require_native_origin(&p.source)?;
        if held.history_v5() != &evidence.complete_history {
            return Err(BridgeError::Binding);
        }
        p.peer
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)?;
        window.remaining(started.elapsed())?;
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        let request_digest = p.request.digest()?;
        if p.dialect == V5TransferDialect::BoundedV1 {
            let mut transfer = TransferSender::new(
                TransferMetadata {
                    purpose: TransferPurpose::Publication,
                    transfer_id: hex::encode(
                        crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?,
                    ),
                    lease_id: lease_id.clone(),
                    request_digest: request_digest.clone(),
                    native_review_digest: p.digest.clone(),
                    evidence_digest: evidence.digest()?,
                    head_digest: evidence.head.digest.clone(),
                    head_sequence: evidence.head.sequence,
                },
                &evidence,
            )?;
            check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)?;
            held.check_current()?;
            write_frame_until(
                &mut p.stream,
                &TransferResponseV1::Begin {
                    header: transfer.begin()?,
                },
                deadline,
            )?;
            loop {
                check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)?;
                held.check_current()?;
                require_before_deadline(deadline)?;
                let frame = read_frame_until(&p.stream, &p.peer.peer, deadline)?;
                let command: TransferCommandV1 = decode_frame(&frame)?;
                check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)?;
                held.check_current()?;
                require_before_deadline(deadline)?;
                match &command {
                    TransferCommandV1::Finish {} => return Ok(()),
                    TransferCommandV1::Next { .. } => {
                        let chunk = transfer.next(&command)?;
                        check_observer(&p.source, &p.peer, &p.witness, &p.cancelled)?;
                        held.check_current()?;
                        write_frame_until(
                            &mut p.stream,
                            &TransferResponseV1::Chunk { chunk },
                            deadline,
                        )?;
                    }
                    TransferCommandV1::AcceptComplete { .. } => {
                        transfer.accept_complete(&command)?;
                        // Reconstruction acknowledges data only. Admission still requires
                        // the separate Admit and its original release/recheck sequence.
                        write_frame_until(&mut p.stream, &transfer.confirmation()?, deadline)?;
                        break;
                    }
                }
            }
        } else {
            write_frame(
                &mut p.stream,
                &HostPublicationResponseV5::Prepared {
                    lease_id: lease_id.clone(),
                    request_digest: request_digest.clone(),
                    native_review_digest: p.digest.clone(),
                    evidence: Box::new(evidence.clone()),
                },
            )?;
        }
        let frame = if p.dialect == V5TransferDialect::BoundedV1 {
            read_frame_until(&p.stream, &p.peer.peer, deadline)?
        } else {
            crate::ipc::read_frame_with_deadline(
                &p.stream,
                &p.peer.peer,
                window.remaining(started.elapsed())?,
            )
            .map_err(|_| BridgeError::Ipc)?
        };
        // Finish, malformed input, timeout and disconnect all drop this guard.
        // There is no uncertain-consumer drain for an informational snapshot.
        let command: HostPublicationCommandV5 =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        drop(held);
        match command {
            HostPublicationCommandV5::Finish {} => {
                if p.dialect == V5TransferDialect::BoundedV1 {
                    let _ = write_frame_until(
                        &mut p.stream,
                        &HostPublicationResponseV5::Finished {},
                        deadline,
                    );
                } else {
                    let _ = write_frame(&mut p.stream, &HostPublicationResponseV5::Finished {});
                }
                return Ok(());
            }
            HostPublicationCommandV5::Admit {
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
        if p.dialect == V5TransferDialect::BoundedV1 {
            observation.require_same_snapshot_until(deadline)?;
        } else {
            observation.require_same_snapshot()?;
        }
        let held = journal.acquire_host_recovery_continuity_v5(&observation)?;
        held.require_native_origin(&p.source)?;
        if held.history_v5() != &evidence.complete_history {
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
        let record = HostRecoveryPublicationRecordV5 {
            request: p.request.clone(),
            native_review_digest: p.digest.clone(),
            admission_id: lease_id,
        };
        // The native decision has now admitted only this exact snapshot. Release
        // every local/native fence BEFORE any remote response or host disk write.
        drop(native);
        let response = HostPublicationResponseV5::Admitted {
            record: Box::new(record),
        };
        if p.dialect == V5TransferDialect::BoundedV1 {
            write_frame_until(&mut p.stream, &response, deadline)
        } else {
            write_frame(&mut p.stream, &response)
        }
    }
}
