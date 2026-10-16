//! The sole lower-origin policy-lease producer: actual installed signer pairing
//! and its purpose-specific native disclosure/current-lease responses.
use super::*;
use crate::named_verifier_policy::{NamedVerifierPolicyRequestV1, NamedVerifierPolicyResponseV1};
use sha2::{Digest, Sha256};
impl NativeManualClient {
    pub fn begin_named_verifier_policy_before(
        &self,
        request: &NamedVerifierPolicyRequestV1,
        deadline: Instant,
    ) -> Result<PendingNamedVerifierPolicy<'_>> {
        self.require_named_verifier_scope(request)?;
        let observed = now_ms()?;
        let lifetime = policy_deadline_budget(
            request.scope.requested_at_ms,
            request.scope.disclosure_expires_at_ms,
            observed,
        )?;
        let deadline = deadline.min(self.grant.expires).min(
            Instant::now()
                .checked_add(lifetime)
                .ok_or(Error::Permission)?,
        );
        let slot = self.acquire_slot()?;
        let stream = self.open_request_before(
            serde_json::json!({"operation":"request_named_verifier_policy_v1","request":request}),
            deadline,
        )?;
        Ok(PendingNamedVerifierPolicy {
            client: self,
            request: request.clone(),
            pending: PendingStream(Some(stream)),
            slot,
            deadline,
        })
    }
    fn require_named_verifier_scope(&self, r: &NamedVerifierPolicyRequestV1) -> Result<()> {
        let p = r.validate()?;
        self.check_channel()?;
        if self.scope.account_id != r.scope.account_id
            || self.scope.participant_id != r.scope.participant_id
            || self.scope.agreement_id != p.manifest().agreement.agreement_id
            || self.scope.manifest_digest != r.scope.pairing_digest()?
            || self.scope.history_read
            || self.scope.authorization_export
            || self.scope.preconstruction_export
            || r.current_caller_binding_digest != self.current_caller_binding_digest()?
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
pub struct PendingNamedVerifierPolicy<'a> {
    client: &'a NativeManualClient,
    request: NamedVerifierPolicyRequestV1,
    pending: PendingStream,
    slot: LeaseSlot<'a>,
    deadline: Instant,
}
impl<'a> PendingNamedVerifierPolicy<'a> {
    pub fn finish(self) -> Result<NamedVerifierPolicyLease<'a>> {
        self.finish_checked(|| Ok(()))
    }
    /// The concrete owner may only narrow cancellation; all installed-channel,
    /// request and lease verification remains mandatory below.
    pub fn finish_checked(
        mut self,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<NamedVerifierPolicyLease<'a>> {
        check_current()?;
        let bytes = Zeroizing::new(framing::read_frame_capped_checked_until(
            self.pending.stream()?,
            &self.client.peer,
            128 * 1024 + 1,
            self.deadline,
            &mut check_current,
        )?);
        check_current()?;
        if bytes.len() > 128 * 1024 {
            return Err(Error::Limit);
        }
        let response: NamedVerifierPolicyResponseV1 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let NamedVerifierPolicyResponseV1::Disclosed {
            lease_id,
            request_digest,
            account_fvk_hex,
        } = &response
        else {
            return Err(Error::Permission);
        };
        hash(lease_id)?;
        if request_digest != &self.request.digest()? || account_fvk_hex.len() != 192 {
            return Err(Error::Binding);
        }
        let raw = Zeroizing::new(hex::decode(account_fvk_hex).map_err(|_| Error::Binding)?);
        let fvk = Zeroizing::new(<[u8; 96]>::try_from(raw.as_slice()).map_err(|_| Error::Binding)?);
        let mut h = Sha256::new();
        h.update(b"wholepact:dedicated-testnet-account:legacy-zip32:v1\0");
        h.update(*fvk);
        if hex::encode(h.finalize()) != self.request.scope.account_id {
            return Err(Error::Binding);
        }
        self.client.require_named_verifier_scope(&self.request)?;
        let observed = now_ms()?;
        let lifetime = policy_deadline_budget(
            self.request.scope.requested_at_ms,
            self.request.scope.disclosure_expires_at_ms,
            observed,
        )?
        .min(remaining_before(self.deadline)?);
        let lease = NamedVerifierPolicyLease {
            held: HeldLease {
                client: self.client,
                stream: Mutex::new(self.pending.take()?),
                lease_id: lease_id.clone(),
                evidence_digest: request_digest.clone(),
                started: Instant::now(),
                lifetime,
                original_deadline: Some((observed, self.request.scope.disclosure_expires_at_ms)),
                failed: AtomicBool::new(false),
                completion: CompletionState::Pending,
                _slot: self.slot,
            },
            request: self.request,
            fvk,
        };
        check_current()?;
        lease.check_current()?;
        check_current()?;
        Ok(lease)
    }
}
/// Not Clone/serde; cannot be manufactured from imported policies or UI flags.
pub struct NamedVerifierPolicyLease<'a> {
    held: HeldLease<'a>,
    request: NamedVerifierPolicyRequestV1,
    fvk: Zeroizing<[u8; 96]>,
}
impl NamedVerifierPolicyLease<'_> {
    pub fn request(&self) -> &NamedVerifierPolicyRequestV1 {
        &self.request
    }
    pub fn check_current(&self) -> Result<()> {
        self.held.check_current()
    }
    /// No peer request or renewal. Final local admission after a fresh remote
    /// challenge checks the original monotonic lifetime, wall bound and channel.
    pub fn check_local_current(&self) -> Result<()> {
        if self.held.failed.load(Ordering::Acquire) {
            return Err(Error::Permission);
        }
        require_policy_local_deadline(
            self.held.started,
            self.held.lifetime,
            self.held.client.grant.expires,
            Instant::now(),
        )?;
        self.held.check_original_deadline()?;
        self.held.client.check_channel()
    }

    pub fn full_viewing_key_bytes(&self) -> Result<&[u8; 96]> {
        self.check_current()?;
        Ok(&self.fvk)
    }
    pub fn finish(self) -> Result<()> {
        self.held.finish()
    }
}

fn policy_deadline_budget(admitted: u64, expires: u64, observed: u64) -> Result<Duration> {
    if admitted >= expires
        || expires - admitted > 120_000
        || observed < admitted
        || observed >= expires
    {
        return Err(Error::Permission);
    }
    Ok(Duration::from_millis(expires - observed))
}

fn require_policy_local_deadline(
    started: Instant,
    lifetime: Duration,
    grant: Instant,
    now: Instant,
) -> Result<()> {
    let expires = started.checked_add(lifetime).ok_or(Error::Permission)?;
    if now < started || now >= expires || now >= grant {
        return Err(Error::Permission);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn named_policy_budget_preserves_its_original_native_deadline() {
        assert_eq!(
            policy_deadline_budget(100, 120_100, 100).unwrap(),
            Duration::from_secs(120)
        );
        assert_eq!(
            policy_deadline_budget(100, 120_100, 119_100).unwrap(),
            Duration::from_secs(1)
        );
        assert!(policy_deadline_budget(100, 120_101, 100).is_err());
        assert!(policy_deadline_budget(100, 120_100, 99).is_err());
        assert!(policy_deadline_budget(100, 120_100, 120_100).is_err());
    }
    #[test]
    fn final_policy_deadline_rejects_slow_persistence_and_grant_expiry() {
        let start = Instant::now();
        let lifetime = Duration::from_secs(10);
        let grant = start + Duration::from_secs(20);
        assert!(require_policy_local_deadline(start, lifetime, grant, start).is_ok());
        for delay in [10, 11, 20] {
            assert!(
                require_policy_local_deadline(
                    start,
                    lifetime,
                    grant,
                    start + Duration::from_secs(delay)
                )
                .is_err()
            );
        }
        assert!(
            require_policy_local_deadline(
                start,
                lifetime,
                start + Duration::from_secs(5),
                start + Duration::from_secs(5)
            )
            .is_err()
        );
    }
}
