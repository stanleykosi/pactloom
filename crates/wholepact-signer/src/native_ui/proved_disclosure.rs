//! Separate native privacy decision for exact proved-artifact disclosure.
//! Construction consent and pairing cannot authorize this later distribution.
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::authority_bridge::{
    self, BridgeError,
    dispatch_ipc::write_frame,
    proved_disclosure_ipc::{
        ProvedDisclosureCommand, ProvedDisclosureRequest, ProvedDisclosureResponse,
    },
};
use crate::{
    Error, Result,
    account::AccountVault,
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use sha2::{Digest, Sha256};
use std::{
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(super) struct PreparedProvedDisclosure {
    request: ProvedDisclosureRequest,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    fvk_digest: String,
    digest: String,
    display: Zeroizing<String>,
    started: Instant,
}
pub(super) struct ApprovedProvedDisclosure {
    prepared: PreparedProvedDisclosure,
}
fn error(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
fn validate_records(
    request: &ProvedDisclosureRequest,
    peer: &AuthenticatedPeer,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    fvk_digest: &str,
) -> authority_bridge::Result<()> {
    let proposal = request.validate()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    let scope = request;
    if peer.scope.account_id != scope.account_id
        || peer.scope.participant_id != scope.participant_id
        || peer.scope.agreement_id != proposal.manifest().agreement.agreement_id
        || peer.scope.manifest_digest != proposal.manifest_digest()
    {
        return Err(BridgeError::Permission);
    }
    let enrollment = journal
        .enrollment(&request.enrollment_ref, session)?
        .ok_or(BridgeError::Missing)?;
    let accepted = journal
        .accepted_manifest(&request.accepted_manifest_ref, session)?
        .ok_or(BridgeError::Missing)?;
    if enrollment.account_id() != scope.account_id
        || enrollment.participant_id() != scope.participant_id
        || enrollment.agreement_id() != proposal.manifest().agreement.agreement_id
        || enrollment.account_fvk_digest() != fvk_digest
        || accepted.enrollment_ref() != enrollment.reference()
        || accepted.manifest_digest() != proposal.manifest_digest()
        || accepted.proposal_input() != &scope.proposal
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl PreparedProvedDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        request: ProvedDisclosureRequest,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        authority: &NativeAuthorityBinding,
        vault: &AccountVault,
    ) -> Result<Self> {
        authority.check_current()?;
        if &peer.native_origin != authority
            || vault.account().recovery_required()
            || vault.account_id()? != request.account_id
        {
            return Err(Error::ReviewMismatch);
        }
        let fvk_digest = hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes()));
        validate_records(&request, &peer, journal, session, &fvk_digest).map_err(error)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-proved-disclosure-review:v1",
            &(
                &request,
                &fvk_digest,
                &peer.grant_id,
                &peer.channel_digest,
                crate::vault::random::<32>()?,
            ),
        )
        .map_err(error)?;
        let display = Zeroizing::new(format!(
            "DISCLOSE EXACT PROVED TRANSACTION ARTIFACT\n\n{}\n\nRequesting local application: {} (PID {}, UID {}, grant {}).\n\nThis is a separate privacy decision for the exact saved PCZT SHA256 and review binding above. A proved PCZT can retain full viewing material, selected notes, witnesses, values, outputs and participant linkages. Proving does not redact it. The complete listed installed signer recipients receive this sensitive artifact for private export and exact review. Installed process identity is not a human identity or remote participant authentication.\n\nPreviously approved construction disclosure does not grant this permission. Copied material cannot be recalled. No public export, arbitrary recipient, later artifact, spending or payment is authorized. Every original account owner must separately approve before the host exports or delivers the artifact.\n\nNative review binding: {}",
            serde_json::to_string_pretty(&request).map_err(error)?,
            peer.label,
            peer.peer.pid(),
            peer.peer.uid(),
            peer.grant_id,
            digest
        ));
        Ok(Self {
            request,
            peer,
            stream,
            source: authority.clone(),
            fvk_digest,
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
        vault: &AccountVault,
    ) -> Result<ApprovedProvedDisclosure> {
        self.source.check_current()?;
        authority.check_current()?;
        self.peer.check_current()?;
        if self.source != authority.binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.started.elapsed() >= Duration::from_secs(120)
            || vault.account().recovery_required()
            || vault.account_id()? != self.request.account_id
        {
            return Err(Error::ReviewMismatch);
        }
        let fvk = Zeroizing::new(vault.account().fvk()?.to_bytes());
        if hex::encode(Sha256::digest(*fvk)) != self.fvk_digest {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedProvedDisclosure { prepared: self })
    }
}
impl ApprovedProvedDisclosure {
    pub(super) fn serve(
        mut self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
    ) -> authority_bridge::Result<()> {
        // Acquire one read fence before disclosure and hold it through the host's
        // final commit, including an ambiguous disconnect. Never nest journal reads
        // inside the check while a revocation writer might be waiting.
        let lease = journal.acquire_preconstruction_records(
            &self.prepared.request.enrollment_ref,
            &self.prepared.request.accepted_manifest_ref,
            session,
        )?;
        lease.require_native_origin(&self.prepared.source)?;
        let proposal = self.prepared.request.validate()?;
        if lease.enrollment().account_fvk_digest() != self.prepared.fvk_digest
            || lease.enrollment().account_id() != self.prepared.request.account_id
            || lease.enrollment().participant_id() != self.prepared.request.participant_id
            || lease.enrollment().agreement_id() != proposal.manifest().agreement.agreement_id
            || lease.manifest().proposal_input() != &self.prepared.request.proposal
        {
            return Err(BridgeError::Binding);
        }
        let started = Instant::now();
        let check = |p: &PreparedProvedDisclosure| -> authority_bridge::Result<()> {
            p.source
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            if started.elapsed() >= Duration::from_secs(900) {
                return Err(BridgeError::Permission);
            }
            p.peer
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            lease.check_current()?;
            Ok(())
        };
        check(&self.prepared)?;
        // The request's entire native approval is consumed before material exists
        // on the wire. A failed send is possible disclosure, never safe retraction.
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        let sent = write_frame(
            &mut self.prepared.stream,
            &ProvedDisclosureResponse::Approved {
                lease_id: lease_id.clone(),
                request_digest: self.prepared.request.digest()?,
            },
        );
        if sent.is_err() {
            retain_until_finished(&mut self.prepared.stream, &self.prepared.peer);
            return Err(BridgeError::Ipc);
        }
        loop {
            let command = crate::ipc::read_frame_with_deadline(
                &self.prepared.stream,
                &self.prepared.peer.peer,
                Duration::from_secs(120),
            )
            .ok()
            .and_then(|frame| serde_json::from_slice::<ProvedDisclosureCommand>(&frame).ok());
            match command {
                Some(ProvedDisclosureCommand::Finish) => {
                    let _ = write_frame(
                        &mut self.prepared.stream,
                        &ProvedDisclosureResponse::Finished,
                    );
                    return Ok(());
                }
                Some(ProvedDisclosureCommand::CheckCurrent) if check(&self.prepared).is_ok() => {
                    if write_frame(
                        &mut self.prepared.stream,
                        &ProvedDisclosureResponse::Current {
                            lease_id: lease_id.clone(),
                        },
                    )
                    .is_ok()
                    {
                        continue;
                    }
                }
                _ => {
                    let _ =
                        write_frame(&mut self.prepared.stream, &ProvedDisclosureResponse::Denied);
                }
            }
            retain_until_finished(&mut self.prepared.stream, &self.prepared.peer);
            return Err(BridgeError::Permission);
        }
    }
}
fn retain_until_finished(stream: &mut UnixStream, peer: &AuthenticatedPeer) {
    while peer.peer.check_alive().is_ok() {
        if crate::ipc::read_frame_with_deadline(stream, &peer.peer, Duration::from_secs(2))
            .ok()
            .and_then(|frame| serde_json::from_slice::<ProvedDisclosureCommand>(&frame).ok())
            .is_some_and(|command| matches!(command, ProvedDisclosureCommand::Finish))
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
