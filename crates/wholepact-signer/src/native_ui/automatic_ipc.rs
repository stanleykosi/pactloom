//! Native-owned half of the two-phase automatic authorization channel. Only an
//! already-derived, separately disclosed continuation reaches this server. The
//! coordinator receives metadata; signing artifacts remain in the original
//! protected journal and its separately approved export route.
use crate::{
    authority_bridge::{
        AuthorizationCommit, BridgeError, Result,
        automation_ipc::{
            AutomaticCommand, AutomaticDescriptor, AutomaticHistory, AutomaticRequest,
            AutomaticResponse, AutomaticRetained, read_command, write_response,
        },
    },
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use std::{
    os::unix::net::UnixStream,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAXIMUM_LEASE: Duration = Duration::from_secs(120);

/// References must match the existing private intake; this cannot introduce or
/// replace bytes, a candidate, or a native accepted manifest.
pub(super) fn check_reference(
    request: &AutomaticRequest,
    candidate_id: &str,
    manifest_digest: &str,
    bytes: &[u8],
) -> Result<()> {
    use sha2::{Digest, Sha256};
    request.validate()?;
    if request.candidate_id != candidate_id
        || request.accepted_manifest_digest != manifest_digest
        || request.artifact_digest != hex::encode(Sha256::digest(bytes))
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

/// Shared by foreground, incoming IPC, and post-wallet staging so retries keep
/// the original authorization identity without accepting a caller-selected ID.
pub(super) fn authorization_id(
    grant_id: &str,
    candidate_id: &str,
    bytes: &[u8],
) -> crate::Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-automatic-request:v1",
        &(grant_id, candidate_id, bytes),
    )
    .map_err(|_| crate::Error::InvalidData)
}

/// Read-only replay is independently bound to the exact original application.
/// A historical result cannot create a new grant, ticket or signing continuation.
pub(super) fn serve_historical(
    mut stream: UnixStream,
    peer: AuthenticatedPeer,
    request: AutomaticRequest,
    authorization_id: String,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
) -> Result<()> {
    let result = (|| {
        request.validate()?;
        let pairing = super::AuthenticatedPairing::from_authenticated_request(peer.clone())
            .map_err(|_| BridgeError::Permission)?;
        let lease = journal.acquire_original_authorization(&authorization_id, session)?;
        let original = lease.evidence();
        let consent = original.original_consent();
        let terms = consent.terms();
        let automation = terms.automation.as_ref().ok_or(BridgeError::Binding)?;
        if terms.authorization_id != authorization_id
            || terms.account_id != peer.scope.account_id
            || terms.agreement_id != peer.scope.agreement_id
            || terms.proposal_id != request.candidate_id
            || terms.artifact_digest != request.artifact_digest
            || terms.manifest_digest != request.accepted_manifest_digest
            || terms.manifest_digest != peer.scope.manifest_digest
            || original.enrollment().participant_id() != peer.scope.participant_id
            || original.enrollment().transport() != pairing.binding()
            || &terms.transport != pairing.binding()
            || automation.grant.grant_id != request.grant_id
            || automation.grant.application_id != pairing.binding().identity_id()
        {
            return Err(BridgeError::Binding);
        }
        let retained = match journal.bridge_result(&lease) {
            Ok(result) => {
                if result.authorization_id != authorization_id
                    || result.original_consent_ref != consent.reference()
                {
                    return Err(BridgeError::Binding);
                }
                Some(AutomaticRetained {
                    result_digest: result.result_digest.clone(),
                    outbox_digest: result.outbox_digest.clone(),
                })
            }
            Err(BridgeError::Missing | BridgeError::Uncertain) => None,
            Err(error) => return Err(error),
        };
        lease.check_current()?;
        pairing
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        write_response(
            &mut stream,
            &AutomaticResponse::Historical {
                history: Box::new(AutomaticHistory {
                    request,
                    authorization_id,
                    original_consent_ref: consent.reference().to_owned(),
                    retained,
                }),
            },
        )
    })();
    if result.is_err() {
        let _ = write_response(&mut stream, &AutomaticResponse::Denied);
    }
    result
}

/// This gate is local, one-use state, never deserialized from the coordinator.
/// A command cannot refresh its initial deadline or change either exact ID.
struct ExecutionGate {
    lease_id: String,
    authorization_id: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    started: Instant,
    consumed: bool,
}
impl ExecutionGate {
    fn check_current(&self) -> Result<()> {
        self.check_at(now_ms()?, self.started.elapsed())
    }
    fn check_at(&self, now: u64, elapsed: Duration) -> Result<()> {
        if now < self.issued_at_ms
            || now >= self.expires_at_ms
            || elapsed >= MAXIMUM_LEASE
            || elapsed.as_millis() >= u128::from(self.expires_at_ms - self.issued_at_ms)
        {
            return Err(BridgeError::Permission);
        }
        Ok(())
    }
    fn consume(&mut self, lease_id: &str, authorization_id: &str) -> Result<()> {
        self.check_current()?;
        if self.consumed || lease_id != self.lease_id || authorization_id != self.authorization_id {
            return Err(BridgeError::Permission);
        }
        self.consumed = true;
        Ok(())
    }
    fn remaining(&self) -> Result<Duration> {
        self.check_current()?;
        let wall_remaining = self
            .expires_at_ms
            .checked_sub(now_ms()?)
            .filter(|remaining| *remaining > 0)
            .ok_or(BridgeError::Permission)?;
        let elapsed = self.started.elapsed();
        let monotonic_remaining = Duration::from_millis(self.expires_at_ms - self.issued_at_ms)
            .min(MAXIMUM_LEASE)
            .checked_sub(elapsed)
            .filter(|remaining| !remaining.is_zero())
            .ok_or(BridgeError::Permission)?;
        Ok(Duration::from_millis(wall_remaining).min(monotonic_remaining))
    }
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BridgeError::Permission)?
        .as_millis()
        .try_into()
        .map_err(|_| BridgeError::Permission)
}

/// `current` may inspect the original native grant before execution. The
/// callback's deadline check deliberately does not reacquire session/journal
/// locks: actual signing already holds the original permission and authority
/// fence. The callback is FnOnce and a failed or disconnected Execute is never
/// reconstructed here. Store commits Unknown before its client sends Execute.
pub(super) fn serve<C, F>(
    mut stream: UnixStream,
    peer: &AuthenticatedPeer,
    descriptor: AutomaticDescriptor,
    current: C,
    execute: F,
) -> Result<AuthorizationCommit>
where
    C: Fn() -> Result<()>,
    F: FnOnce(&dyn Fn() -> Result<()>) -> Result<AuthorizationCommit>,
{
    let result = (|| {
        let issued_at_ms = now_ms()?;
        let original_consent_ref = descriptor.original_consent_ref.clone();
        let mut gate = ExecutionGate {
            lease_id: hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?),
            authorization_id: descriptor.request.authorization_id.clone(),
            issued_at_ms,
            expires_at_ms: descriptor.expires_at_ms,
            started: Instant::now(),
            consumed: false,
        };
        gate.check_current()?;
        peer.check_current().map_err(|_| BridgeError::Permission)?;
        peer.native_origin
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        current()?;
        write_response(
            &mut stream,
            &AutomaticResponse::Prepared {
                lease_id: gate.lease_id.clone(),
                descriptor: Box::new(descriptor),
            },
        )?;
        loop {
            let command = read_command(&stream, peer, gate.remaining()?)?;
            gate.check_current()?;
            peer.check_current().map_err(|_| BridgeError::Permission)?;
            peer.native_origin
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            match command {
                AutomaticCommand::CheckCurrent => {
                    current()?;
                    write_response(
                        &mut stream,
                        &AutomaticResponse::Current {
                            lease_id: gate.lease_id.clone(),
                        },
                    )?;
                }
                AutomaticCommand::Execute {
                    lease_id,
                    authorization_id,
                } => {
                    gate.consume(&lease_id, &authorization_id)?;
                    current()?;
                    let point_of_use = || {
                        gate.check_current()?;
                        peer.check_current().map_err(|_| BridgeError::Permission)?;
                        peer.native_origin
                            .check_current()
                            .map_err(|_| BridgeError::Permission)
                    };
                    let commit = execute(&point_of_use)?;
                    if commit.authorization_id != gate.authorization_id
                        || commit.original_consent_ref != original_consent_ref
                    {
                        return Err(BridgeError::Binding);
                    }
                    // The original result remains durable if this response is
                    // lost. Neither this channel nor a retry exports its bytes.
                    write_response(
                        &mut stream,
                        &AutomaticResponse::Retained {
                            lease_id: gate.lease_id,
                            authorization_id: commit.authorization_id.clone(),
                            original_consent_ref: commit.original_consent_ref.clone(),
                            result_digest: commit.result_digest.clone(),
                            outbox_digest: commit.outbox_digest.clone(),
                        },
                    )?;
                    return Ok(commit);
                }
                AutomaticCommand::Finish => return Err(BridgeError::Permission),
            }
        }
    })();
    if result.is_err() {
        let _ = write_response(&mut stream, &AutomaticResponse::Denied);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> ExecutionGate {
        let now = now_ms().unwrap();
        ExecutionGate {
            lease_id: "synthetic-native-lease".into(),
            authorization_id: "synthetic-authorization".into(),
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            started: Instant::now(),
            consumed: false,
        }
    }

    #[test]
    fn automatic_reference_cannot_replace_private_intake_and_keeps_stable_identity() {
        use sha2::{Digest, Sha256};
        let bytes = b"synthetic artifact, never a real PCZT";
        let request = AutomaticRequest {
            grant_id: "synthetic-grant".into(),
            candidate_id: "synthetic-candidate".into(),
            artifact_digest: hex::encode(Sha256::digest(bytes)),
            accepted_manifest_digest: "a1".repeat(32),
        };
        check_reference(&request, "synthetic-candidate", &"a1".repeat(32), bytes).unwrap();
        assert!(check_reference(&request, "other-candidate", &"a1".repeat(32), bytes).is_err());
        assert!(check_reference(&request, "synthetic-candidate", &"b2".repeat(32), bytes).is_err());
        assert!(
            check_reference(
                &request,
                "synthetic-candidate",
                &"a1".repeat(32),
                b"changed"
            )
            .is_err()
        );
        let id = authorization_id(&request.grant_id, &request.candidate_id, bytes).unwrap();
        assert_eq!(
            id,
            authorization_id("synthetic-grant", "synthetic-candidate", bytes).unwrap()
        );
        assert_ne!(
            id,
            authorization_id("other-grant", "synthetic-candidate", bytes).unwrap()
        );
        assert_ne!(
            id,
            authorization_id("synthetic-grant", "other-candidate", bytes).unwrap()
        );
        assert_ne!(
            id,
            authorization_id("synthetic-grant", "synthetic-candidate", b"changed").unwrap()
        );
    }

    #[test]
    fn automatic_execute_requires_both_original_ids_and_is_one_shot() {
        let mut gate = gate();
        assert!(
            gate.consume("other-lease", "synthetic-authorization")
                .is_err()
        );
        assert!(
            gate.consume("synthetic-native-lease", "other-authorization")
                .is_err()
        );
        assert!(!gate.consumed);
        gate.consume("synthetic-native-lease", "synthetic-authorization")
            .unwrap();
        assert!(
            gate.consume("synthetic-native-lease", "synthetic-authorization")
                .is_err()
        );
    }

    #[test]
    fn automatic_lease_rejects_clock_rollback_and_both_expiry_clocks() {
        let gate = gate();
        assert!(
            gate.check_at(gate.issued_at_ms - 1, Duration::ZERO)
                .is_err()
        );
        assert!(gate.check_at(gate.expires_at_ms, Duration::ZERO).is_err());
        assert!(
            gate.check_at(gate.issued_at_ms, Duration::from_secs(60))
                .is_err()
        );
        assert!(
            gate.check_at(gate.issued_at_ms + 1, Duration::from_millis(1))
                .is_ok()
        );
        let mut longer = gate;
        longer.expires_at_ms = longer.issued_at_ms + 300_000;
        assert!(longer.check_at(longer.issued_at_ms, MAXIMUM_LEASE).is_err());
    }
}
