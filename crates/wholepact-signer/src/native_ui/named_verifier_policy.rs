//! Fresh purpose-specific native disclosure to one exact named verifier. Existing
//! construction approval cannot enter this owner. No signing authority is issued.
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::{
    Error, Result,
    account::AccountVault,
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Write,
    os::unix::net::UnixStream,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_signer_origin::manual::{ManualAdmissionCommand, ManualAdmissionResponse};
use wholepact_signer_origin::named_verifier_policy::{
    NamedVerifierPolicyRequestV1, NamedVerifierPolicyResponseV1,
};
use zeroize::Zeroizing;
fn wall() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidData)?
            .as_millis(),
    )
    .map_err(|_| Error::InvalidData)
}
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::Locked)
}
fn map(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
fn write<T: serde::Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
    source: &NativeAuthorityBinding,
    peer: &AuthenticatedPeer,
    check_record: impl Fn() -> Result<()>,
) -> Result<()> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(value).map_err(map)?);
    if bytes.len() > 128 * 1024 {
        return Err(Error::InvalidData);
    }
    bytes.push(b'\n');
    let mut offset = 0;
    while offset < bytes.len() {
        source.check_current()?;
        peer.check_current()?;
        check_record()?;
        stream.set_write_timeout(Some(remaining(deadline)?.min(Duration::from_secs(2))))?;
        // Hold the native revocation fence only across one bounded syscall.
        // Never retain it while waiting for a caller command or journal mutation.
        let publication = source.publication_lease()?;
        peer.check_current()?;
        remaining(deadline)?;
        let n = stream.write(&bytes[offset..])?;
        drop(publication);
        source.check_current()?;
        peer.check_current()?;
        check_record()?;
        if n == 0 {
            return Err(Error::Uncertain);
        }
        offset += n;
    }
    remaining(deadline)?;
    Ok(())
}
pub(super) struct PreparedNamedVerifierPolicy {
    request: NamedVerifierPolicyRequestV1,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    digest: String,
    fvk_digest: String,
    display: Zeroizing<String>,
    observed_ms: u64,
    deadline: Instant,
}
pub(super) struct ApprovedNamedVerifierPolicy {
    prepared: PreparedNamedVerifierPolicy,
    fvk: Zeroizing<[u8; 96]>,
}
impl PreparedNamedVerifierPolicy {
    pub(super) fn prepare(
        request: NamedVerifierPolicyRequestV1,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<Self> {
        authority.check_current()?;
        peer.check_current()?;
        let p = request.validate().map_err(map)?;
        if peer.native_origin != authority.binding()
            || vault.account().recovery_required()
            || vault.account_id()? != request.scope.account_id
            || peer.scope.account_id != request.scope.account_id
            || peer.scope.participant_id != request.scope.participant_id
            || peer.scope.agreement_id != p.manifest().agreement.agreement_id
            || peer.scope.manifest_digest != request.scope.pairing_digest().map_err(map)?
            || peer.scope.history_read
            || peer.scope.authorization_export
            || peer.scope.preconstruction_export
            || request.current_caller_binding_digest
                != wholepact_signer_origin::manual_current_caller_binding_digest(
                    &peer.grant_id,
                    &peer.scope,
                )
                .map_err(map)?
        {
            return Err(Error::ReviewMismatch);
        }
        let observed_ms = wall()?;
        if observed_ms < request.scope.requested_at_ms
            || observed_ms >= request.scope.disclosure_expires_at_ms
        {
            return Err(Error::Locked);
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(
                request.scope.disclosure_expires_at_ms - observed_ms,
            ))
            .ok_or(Error::Locked)?;
        let fvk_digest = hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes()));
        let lease = journal
            .acquire_preconstruction_records(
                &request.scope.enrollment_ref,
                &request.scope.accepted_manifest_ref,
                session,
            )
            .map_err(map)?;
        lease
            .require_native_origin(&authority.binding())
            .map_err(map)?;
        if lease.enrollment().account_id() != request.scope.account_id
            || lease.enrollment().account_fvk_digest() != fvk_digest
            || lease.enrollment().participant_id() != request.scope.participant_id
            || lease.enrollment().agreement_id() != p.manifest().agreement.agreement_id
            || lease.manifest().proposal_input() != &request.scope.proposal
        {
            return Err(Error::ReviewMismatch);
        }
        drop(lease);
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-named-verifier-policy:v1",
            &(
                request.digest().map_err(map)?,
                &peer.grant_id,
                &peer.channel_digest,
                &fvk_digest,
                authority.measurement(),
            ),
        )
        .map_err(map)?;
        let display = Zeroizing::new(format!(
            "DISCLOSE VIEWING CAPABILITY TO ONE NAMED VERIFIER\nVerifier signing-key SHA-256: {}\nDestination: {}\nActual local recipient: {} PID {} UID {} grant {}\nAccount: {}\nExact original request: {}\nExact original artifact: {}\nManifest: {}\nOriginal expiry: {} ms\n\nThis sends this dedicated account's FULL VIEWING KEY to this explicit verifier process for the exact offline assertion. It reveals past/future account activity and cannot be revoked or erased by lease expiry. It does not approve forwarding that key to peer recipients. The verifier may produce ownership/return-allocation assertions; its signature authenticates a statement, not its truth. No spending key, reservation, construction, transaction signature, submission or account-wide completeness is authorized. A failed send can still disclose the key.\nExact native review: {}",
            request.scope.verifier_key_digest,
            request.scope.verifier_destination,
            peer.label,
            peer.peer.pid(),
            peer.peer.uid(),
            peer.grant_id,
            request.scope.account_id,
            request.scope.original_request_digest,
            request.scope.original_artifact_digest,
            p.manifest_digest(),
            request.scope.disclosure_expires_at_ms,
            digest
        ));
        Ok(Self {
            request,
            peer,
            stream,
            source: authority.binding(),
            digest,
            fvk_digest,
            display,
            observed_ms,
            deadline,
        })
    }
    fn check(&self) -> Result<()> {
        self.source.check_current()?;
        self.peer.check_current()?;
        remaining(self.deadline)?;
        let now = wall()?;
        if now < self.observed_ms || now >= self.request.scope.disclosure_expires_at_ms {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.check()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<ApprovedNamedVerifierPolicy> {
        self.check()?;
        authority.check_current()?;
        if decision.binding() != &self.source
            || authority.binding() != self.source
            || decision.reviewed_digest() != self.digest
            || vault.account().recovery_required()
            || vault.account_id()? != self.request.scope.account_id
        {
            return Err(Error::ReviewMismatch);
        }
        let fvk = Zeroizing::new(vault.account().fvk()?.to_bytes());
        if hex::encode(Sha256::digest(*fvk)) != self.fvk_digest {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedNamedVerifierPolicy {
            prepared: self,
            fvk,
        })
    }
}
impl ApprovedNamedVerifierPolicy {
    pub(super) fn serve(
        self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
    ) -> Result<()> {
        self.serve_with_current(journal, session, |_| Ok(()), || Ok(()))
    }
    /// The born lane adds checks against its actual original source while the
    /// maintained local-record lease is held; no callback issues authority.
    pub(super) fn serve_with_current(
        mut self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        check_held: impl Fn(&crate::consent_journal::PreconstructionRecordLease<'_>) -> Result<()>,
        check_released: impl Fn() -> Result<()>,
    ) -> Result<()> {
        let lease = journal
            .acquire_preconstruction_records(
                &self.prepared.request.scope.enrollment_ref,
                &self.prepared.request.scope.accepted_manifest_ref,
                session,
            )
            .map_err(map)?;
        lease
            .require_native_origin(&self.prepared.source)
            .map_err(map)?;
        if lease.enrollment().account_fvk_digest() != self.prepared.fvk_digest
            || lease.enrollment().account_id() != self.prepared.request.scope.account_id
            || lease.manifest().proposal_input() != &self.prepared.request.scope.proposal
        {
            return Err(Error::ReviewMismatch);
        }
        self.prepared.check()?;
        lease.check_current().map_err(map)?;
        check_held(&lease)?;
        let id = hex::encode(crate::vault::random::<32>()?);
        let digest = self.prepared.request.digest().map_err(map)?;
        write(
            &mut self.prepared.stream,
            &NamedVerifierPolicyResponseV1::Disclosed {
                lease_id: id.clone(),
                request_digest: digest.clone(),
                account_fvk_hex: hex::encode(*self.fvk),
            },
            self.prepared.deadline,
            &self.prepared.source,
            &self.prepared.peer,
            || { lease.check_current().map_err(map)?; check_held(&lease) },
        )?;
        let mut challenges = BTreeSet::new();
        for _ in 0..256 {
            self.prepared.check()?;
            lease.check_current().map_err(map)?;
        check_held(&lease)?;
            let frame = wholepact_signer_origin::framing::read_frame_capped_checked_until(
                &self.prepared.stream,
                &self.prepared.peer.peer,
                4097,
                self.prepared.deadline,
                || {
                    self.prepared
                        .check()
                        .map_err(|_| wholepact_signer_origin::Error::Permission)?;
                    lease.check_current().map_err(|_| wholepact_signer_origin::Error::Permission)?;
                    check_held(&lease).map_err(|_| wholepact_signer_origin::Error::Permission)
                },
            )
            .map_err(map)?;
            if frame.len() > 4096 {
                return Err(Error::InvalidData);
            }
            let command: ManualAdmissionCommand = serde_json::from_slice(&frame).map_err(map)?;
            self.prepared.check()?;
            lease.check_current().map_err(map)?;
        check_held(&lease)?;
            match command {
                ManualAdmissionCommand::Finish {} => {
                    check_held(&lease)?;
                    drop(lease);
                    check_released()?;
                    write(
                        &mut self.prepared.stream,
                        &ManualAdmissionResponse::Finished {},
                        self.prepared.deadline,
                        &self.prepared.source,
                        &self.prepared.peer,
                        // The original record lease is deliberately released
                        // before Finished. This acknowledges release only.
                        &check_released,
                    )?;
                    return Ok(());
                }
                ManualAdmissionCommand::CheckCurrent {
                    lease_id,
                    evidence_digest,
                    challenge_nonce,
                } => {
                    if lease_id != id
                        || evidence_digest != digest
                        || challenge_nonce.len() != 64
                        || !challenge_nonce
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        || !challenges.insert(challenge_nonce.clone())
                    {
                        return Err(Error::ReviewMismatch);
                    }
                    write(
                        &mut self.prepared.stream,
                        &ManualAdmissionResponse::Current {
                            lease_id: id.clone(),
                            evidence_digest: digest.clone(),
                            challenge_nonce,
                        },
                        self.prepared.deadline,
                        &self.prepared.source,
                        &self.prepared.peer,
                        || { lease.check_current().map_err(map)?; check_held(&lease) },
                    )?;
                }
            }
        }
        Err(Error::Unavailable)
    }
}
