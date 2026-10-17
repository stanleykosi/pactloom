//! Genuine native disclosure of bounded original born evidence. The local Host
//! receives no writer key, private viewing data, PCZT, signature or renewal.
use super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{
    Error, Result,
    authority_bridge::{self, BridgeError, born_history_ipc::*, dispatch_ipc::write_frame},
    consent_journal::{LiveNamedRecipientProfile, SignerConsentJournal, SignerConsentSession},
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
pub(super) struct PreparedBornHistoryV1 {
    request: BornOriginalHistoryRequestV1,
    profile: LiveNamedRecipientProfile,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    evidence: BornOriginalHistoryEvidenceV1,
    digest: String,
    display: String,
    deadline: Instant,
    review_deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
pub(super) struct ApprovedBornHistoryV1(PreparedBornHistoryV1);
pub(super) fn check_peer(
    peer: &AuthenticatedPeer,
    source: &NativeAuthorityBinding,
    e: &BornOriginalHistoryEvidenceV1,
) -> authority_bridge::Result<()> {
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    source
        .check_current()
        .map_err(|_| BridgeError::Permission)?;
    let t = &e.admission.request.reservation.intent.terms;
    let m = &e.manual_extension.terms;
    if &peer.native_origin != source
        || !peer.scope.history_read
        || peer.scope.authorization_export
        || peer.scope.preconstruction_export
        || peer.scope.account_id != t.account_id
        || peer.scope.agreement_id != t.agreement_id
        || peer.scope.participant_id != m.scope.participant_id
        || peer.scope.manifest_digest != t.manifest_digest
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl PreparedBornHistoryV1 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        request: BornOriginalHistoryRequestV1,
        profile: LiveNamedRecipientProfile,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        source: &NativeAuthorityBinding,
        workspace: &NativeWitnessWorkspace,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        let start = Instant::now();
        let review_deadline = start + Duration::from_secs(120);
        let deadline = start + Duration::from_secs(900);
        let current = || {
            source
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            peer.check_current().map_err(|_| BridgeError::Permission)?;
            workspace
                .require_native_origin(source)
                .map_err(|_| BridgeError::Permission)?;
            if cancelled.load(Ordering::Acquire) || Instant::now() >= review_deadline {
                return Err(BridgeError::Permission);
            }
            Ok(())
        };
        let held = profile
            .acquire_born_host_history(
                journal,
                session,
                workspace.client(),
                &request,
                review_deadline,
                current,
            )
            .map_err(|_| Error::ReviewMismatch)?;
        check_peer(&peer, source, &held.evidence).map_err(|_| Error::ReviewMismatch)?;
        let evidence = held.evidence.clone();
        // Exact serialized response is bounded BEFORE requesting native consent.
        // The actual random lease identifier has this same fixed hex length.
        crate::authority_bridge::born_ipc_io::ensure_response_fits(&BornHistoryResponseV1::Held {
            lease_id: "00".repeat(32),
            evidence: Box::new(evidence.clone()),
        })
        .map_err(|_| Error::InvalidData)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-born-original-host-history:v1",
            &(&request, &evidence, &peer.grant_id, &peer.channel_digest),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "Disclose exact original born history to the paired local Host\n\n{}\n\nThis shares the exact account policy, birth enrollment/artifact commitments, selected construction input/economic linkage, original admission and retained final consent identifier. It contains no private viewing key, PCZT or signatures. The selected Host can retain and link this information. The witness replay was actually authenticated inside this signer; this is not a fresh chain observation, dispatch permission, new signing consent, or settlement. The separate historical-only held channel expires fifteen minutes after this request began and is revoked on Lock or blur.\nExact review: {}",
            serde_json::to_string_pretty(&evidence).map_err(|_| Error::InvalidData)?,
            digest
        );
        current().map_err(|_| Error::Locked)?;
        Ok(Self {
            request,
            profile,
            peer,
            stream,
            source: source.clone(),
            evidence,
            digest,
            display,
            deadline,
            review_deadline,
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
    ) -> Result<ApprovedBornHistoryV1> {
        self.source.check_current()?;
        if authority.binding() != self.source
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.cancelled.load(Ordering::Acquire)
            || Instant::now() >= self.review_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedBornHistoryV1(self))
    }
}
impl ApprovedBornHistoryV1 {
    pub(super) fn serve(
        self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        workspace: &NativeWitnessWorkspace,
    ) -> authority_bridge::Result<()> {
        let PreparedBornHistoryV1 {
            request,
            profile,
            peer,
            mut stream,
            source,
            evidence,
            deadline,
            cancelled,
            ..
        } = self.0;
        let current = || {
            check_peer(&peer, &source, &evidence)?;
            workspace
                .require_native_origin(&source)
                .map_err(|_| BridgeError::Permission)?;
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(BridgeError::Permission);
            }
            Ok(())
        };
        let held = profile.acquire_born_host_history(
            journal,
            session,
            workspace.client(),
            &request,
            deadline,
            current,
        )?;
        if held.evidence != evidence {
            return Err(BridgeError::Binding);
        }
        let mut receiver = crate::authority_bridge::born_ipc_io::HeldReceiver::default();
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        current()?;
        held.check_current()?;
        if crate::authority_bridge::born_ipc_io::write_response_checked(
            &mut stream,
            &BornHistoryResponseV1::Held {
                lease_id: lease_id.clone(),
                evidence: Box::new(held.evidence.clone()),
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
                .and_then(|b| serde_json::from_slice::<BornHistoryCommandV1>(&b).ok());
            match command {
                Some(BornHistoryCommandV1::Finish) => {
                    let _ = write_frame(&mut stream, &BornHistoryResponseV1::Finished);
                    return Ok(());
                }
                Some(BornHistoryCommandV1::CheckCurrent { check_id })
                    if crate::authority_bridge::born_history_ipc::hash(&check_id).is_ok()
                        && current().is_ok()
                        && held.check_current().is_ok() =>
                {
                    if write_frame(
                        &mut stream,
                        &BornHistoryResponseV1::Current {
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
                    let _ = write_frame(&mut stream, &BornHistoryResponseV1::Denied);
                    retain_until_finished(&mut stream, &peer, &mut receiver);
                    return Err(BridgeError::Permission);
                }
            }
        }
    }
}
pub(super) fn retain_until_finished(
    stream: &mut UnixStream,
    peer: &AuthenticatedPeer,
    receiver: &mut crate::authority_bridge::born_ipc_io::HeldReceiver,
) {
    // A disconnected but still-live Host may be committing its outcome. Keep
    // the original read/exclusion fence until explicit Finish or process exit.
    // After any partial-frame failure, never restart parsing at an unknown
    // offset: only process exit can close that uncertain lifetime safely.
    while peer.peer.check_alive().is_ok() {
        if !receiver.poisoned()
            && receiver
                .read(
                    stream,
                    &peer.peer,
                    Instant::now() + Duration::from_secs(2),
                    &|| Ok(()),
                )
                .ok()
                .and_then(|b| serde_json::from_slice::<BornHistoryCommandV1>(&b).ok())
                .is_some_and(|c| matches!(c, BornHistoryCommandV1::Finish))
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
