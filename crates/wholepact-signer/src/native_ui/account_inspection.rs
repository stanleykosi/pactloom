//! Exact local owner consent for a bounded account audit projection. No witness
//! or provider contact, viewing keys, private artifacts or grant mutation.
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::{
    Error, Result,
    account::AccountVault,
    authority_bridge::account_inspection_ipc::{
        InspectionCommand, InspectionResponse, OwnerInspectionRequest, OwnerInspectionSnapshot,
    },
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

pub(super) struct PreparedOwnerInspection {
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    snapshot: OwnerInspectionSnapshot,
    digest: String,
    started: Instant,
}
impl PreparedOwnerInspection {
    pub(super) fn prepare(
        request: OwnerInspectionRequest,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        authority: &NativeAuthorityBinding,
        vault: &AccountVault,
    ) -> Result<Self> {
        authority.check_current()?;
        peer.check_current()?;
        if !request.validate()
            || &peer.native_origin != authority
            || !peer.scope.history_read
            || peer.scope.account_id != vault.account_id()?
            || peer.scope.agreement_id != request.agreement_id
            || peer.scope.participant_id != request.participant_id
            || peer.scope.manifest_digest != request.manifest_digest
        {
            return Err(Error::Authentication);
        }
        let snapshot = journal
            .owner_inspection(&request, session, authority)
            .map_err(|_| Error::ReviewMismatch)?;
        if snapshot.account_id != vault.account_id()? {
            return Err(Error::ReviewMismatch);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-owner-inspection:v1",
            &(&snapshot, &peer.grant_id),
        )
        .map_err(|_| Error::InvalidData)?;
        Ok(Self {
            peer,
            stream,
            source: authority.clone(),
            snapshot,
            digest,
            started: Instant::now(),
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(format!(
            "DISCLOSE EXACT LOCAL ACCOUNT AUDIT METADATA\nRecipient: paired local application {} (PID {}, UID {}, grant {})\n{}\n\nApprove sharing ONLY these displayed scoped original authorization IDs, maximum debit limits, expiry heights, retained-result/settlement labels, native sponsor constraints and automation grant status/limits with this paired host. The host retains them for the requesting principal and agreement; the approved application's browser, SDK or CLI can read this saved result. No keys, signatures, witnesses, private transaction bytes or other agreements are exported. This cannot activate, pause, revoke or renew grants.\n\nThis is an historical local journal snapshot. Empty lists do not prove absence of other instances or missing history. Account-wide pending exposure, settled spending, remaining budget, balance, chain freshness and current automation eligibility remain UNKNOWN. Expiry height and recorded settlement labels do not clear exposure. No network read or financial operation occurs. A lost uncommitted result remains unknown; the same request is never re-executed.\nReview digest: {}",
            self.peer.label,
            self.peer.peer.pid(),
            self.peer.peer.uid(),
            self.peer.grant_id,
            serde_json::to_string_pretty(&self.snapshot).map_err(|_| Error::InvalidData)?,
            self.digest
        ))
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedOwnerInspection> {
        self.source.check_current()?;
        self.peer.check_current()?;
        if self.started.elapsed() >= Duration::from_secs(120)
            || decision.binding() != &self.source
            || authority.binding() != self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedOwnerInspection(self))
    }
}
pub(super) struct ApprovedOwnerInspection(PreparedOwnerInspection);
impl ApprovedOwnerInspection {
    pub(super) fn serve(mut self) -> Result<()> {
        let _fence = self.0.source.publication_lease()?;
        self.0.peer.check_current()?;
        write_current_frame(
            &mut self.0.stream,
            &InspectionResponse::Reviewed {
                snapshot: Box::new(self.0.snapshot.clone()),
            },
            self.0.started,
            &self.0.source,
            &self.0.peer,
        )
        .map_err(|_| Error::Unavailable)?;
        loop {
            self.0.source.check_current()?;
            self.0.peer.check_current()?;
            let remaining = review_remaining(self.0.started, Instant::now())?;
            let bytes =
                crate::ipc::read_frame_with_deadline(&self.0.stream, &self.0.peer.peer, remaining)?;
            let command = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidData)?;
            match command {
                InspectionCommand::CheckCurrent => {
                    self.0.source.check_current()?;
                    self.0.peer.check_current()?;
                    write_current_frame(
                        &mut self.0.stream,
                        &InspectionResponse::Current,
                        self.0.started,
                        &self.0.source,
                        &self.0.peer,
                    )?;
                }
                InspectionCommand::Finish => return Ok(()),
            }
        }
    }
}

// Both delayed worker admission and every partial write retain the original
// review deadline; a fresh approval check cannot extend its disclosure window.
fn review_remaining(started: Instant, now: Instant) -> Result<Duration> {
    Duration::from_secs(120)
        .checked_sub(now.saturating_duration_since(started))
        .filter(|remaining| !remaining.is_zero())
        .ok_or(Error::Locked)
}
fn write_current_frame(
    stream: &mut UnixStream,
    value: &InspectionResponse,
    started: Instant,
    source: &NativeAuthorityBinding,
    peer: &AuthenticatedPeer,
) -> Result<()> {
    let mut bytes =
        zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::InvalidData)?);
    if bytes.len() > 128 * 1024 {
        return Err(Error::InvalidData);
    }
    bytes.push(b'\n');
    let mut sent = 0;
    while sent < bytes.len() {
        source.check_current()?;
        peer.check_current()?;
        let remaining = review_remaining(started, Instant::now())?;
        stream.set_write_timeout(Some(remaining.min(Duration::from_secs(2))))?;
        match stream.write(&bytes[sent..]) {
            Ok(0) => return Err(Error::Unavailable),
            Ok(n) => sent += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Unavailable),
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delayed_worker_cannot_start_or_refresh_an_expired_disclosure() {
        let started = Instant::now();
        assert_eq!(
            review_remaining(started, started).unwrap(),
            Duration::from_secs(120)
        );
        assert_eq!(
            review_remaining(started, started + Duration::from_secs(119)).unwrap(),
            Duration::from_secs(1)
        );
        assert!(review_remaining(started, started + Duration::from_secs(120)).is_err());
        assert!(review_remaining(started, started + Duration::from_secs(121)).is_err());
    }
}
