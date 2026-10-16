//! Fresh challenge over the existing pinned TLS 1.3/mTLS transport. No portable
//! clock token or caller-supplied successful-response factory exists.
use super::*;
use crate::offline_clock_v1::{OfflineClockRequestV1, OfflineClockResponseV1, OfflineClockScopeV1};
use ring::rand::{SecureRandom, SystemRandom};

// Monotonic exchange limit; the separately charged continuity allowance also
// bounds accepted wall/monotonic discrepancy across this exchange and later use.
const MAX_RTT: Duration = Duration::from_secs(2);
const MAX_OBSERVATION: Duration = Duration::from_secs(120);
// Local wall time supplies only a continuity guard, never witness time. This
// margin is also removed from validity, so tolerated suspend/clock drift cannot
// extend the original expiry. Larger discontinuities invalidate the observation.
const CLOCK_MARGIN: Duration = Duration::from_secs(1);

/// Same-process bounded evidence about one already committed original. It cannot
/// be serialized, cloned, renewed, converted to a permit or resumed after restart.
/// A fresh observation requires another authenticated challenge, and still uses
/// the same immutable original admission/expiry. The configured witness's clock
/// and this process's correctly operating OS clocks are explicit assumptions.
/// ```compile_fail
/// use wholepact_authority::transport::AuthenticatedOfflineClockV1;
/// let _ = serde_json::from_str::<AuthenticatedOfflineClockV1<'_>>("{}");
/// ```
pub struct AuthenticatedOfflineClockV1<'client> {
    client: &'client AuthorityClient,
    scope: OfflineClockScopeV1,
    witness_time_ms: u64,
    round_trip: Duration,
    continuity_started: Instant,
    wall_at_start: std::time::SystemTime,
    ceiling: Instant,
    failed: std::sync::atomic::AtomicBool,
}
impl AuthenticatedOfflineClockV1<'_> {
    pub fn scope(&self) -> &OfflineClockScopeV1 {
        &self.scope
    }
    pub fn witness_time_ms(&self) -> u64 {
        self.witness_time_ms
    }
    /// Conservative elapsed-time bound charged to original validity, including
    /// upward millisecond rounding and the single continuity allowance.
    pub fn round_trip_upper_bound(&self) -> Duration {
        // Construction bounds the measurement by two seconds, so this cannot
        // truncate. Never expose the raw Instant duration as a real-time bound.
        let rounded_ms = self.round_trip.as_nanos().div_ceil(1_000_000) as u64;
        Duration::from_millis(rounded_ms) + CLOCK_MARGIN
    }
    pub fn monotonic_ceiling(&self) -> Instant {
        self.ceiling
    }
    pub fn authenticated_witness_certificate_digest(&self) -> &str {
        &self.client.tls.pinned_certificate
    }
    pub fn check_current(&self, original: &OfflineClockScopeV1) -> Result<()> {
        use std::sync::atomic::Ordering;
        if self.failed.load(Ordering::Acquire) {
            return Err(AuthorityError::Expired);
        }
        let result = if original != &self.scope {
            Err(AuthorityError::InvalidBinding)
        } else {
            check_continuity(
                self.continuity_started,
                self.wall_at_start,
                self.ceiling,
                Instant::now(),
                std::time::SystemTime::now(),
            )
        };
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
}
impl AuthorityClient {
    /// The native owner supplies an already bounded absolute lifetime and keeps
    /// its current-owner check. Neither this read nor its success authorizes a
    /// financial operation. The check never renews either original deadline.
    pub fn observe_offline_admission_time_v1(
        &self,
        original: &OfflineClockScopeV1,
        owner_deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedOfflineClockV1<'_>> {
        check_current()?;
        original.validate()?;
        if original.witness_id != self.witness
            || original.account_id != self.account
            || original.network_profile_id != self.network
            || original.witness_policy_digest != self.policy_digest
        {
            return Err(AuthorityError::Authentication);
        }
        // Sample wall time BEFORE Instant to conservatively bracket the entire
        // exchange. Retain this same pair afterward: resetting it on receipt
        // could hide suspend during I/O or spend the continuity margin twice.
        let wall_at_start = std::time::SystemTime::now();
        let started = Instant::now();
        let deadline =
            owner_deadline.min(started.checked_add(MAX_RTT).ok_or(AuthorityError::Limit)?);
        require_before_caller_deadline(deadline)?;
        let mut nonce = [0; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| AuthorityError::Authentication)?;
        let challenge = hex::encode(nonce);
        let mut expected_binding = None;
        let response = self.call_with_until(deadline, |exporter| {
            check_current()?;
            let binding = channel_binding(exporter, original, &challenge)?;
            expected_binding = Some(binding.clone());
            Ok(WireRequest::ObserveOfflineAdmissionTimeV1(Box::new(
                OfflineClockRequestV1 {
                    scope: original.clone(),
                    challenge: challenge.clone(),
                    channel_binding: binding,
                },
            )))
        })?;
        let received = Instant::now();
        let wall_at_receive = std::time::SystemTime::now();
        check_continuity(started, wall_at_start, deadline, received, wall_at_receive)?;
        check_current()?;
        let WireResponse::OfflineAdmissionTimeV1(response) = response else {
            return Err(AuthorityError::Authentication);
        };
        let ceiling = validate_response(
            original,
            &challenge,
            expected_binding
                .as_deref()
                .ok_or(AuthorityError::Authentication)?,
            &response,
            started,
            received,
            owner_deadline,
        )?;
        let result = AuthenticatedOfflineClockV1 {
            client: self,
            scope: original.clone(),
            witness_time_ms: response.witness_time_ms,
            round_trip: received.duration_since(started),
            continuity_started: started,
            wall_at_start,
            ceiling,
            failed: std::sync::atomic::AtomicBool::new(false),
        };
        result.check_current(original)?;
        Ok(result)
    }
}
pub(super) fn channel_binding(
    exporter: &[u8; 32],
    scope: &OfflineClockScopeV1,
    challenge: &str,
) -> Result<String> {
    scope.validate()?;
    hash(challenge)?;
    // A purpose-separated commitment to the actual maintained TLS exporter.
    // The exporter itself never leaves this process; TLS authenticates the frame.
    let mut h = Sha256::new();
    h.update(b"wholepact:offline-clock-tls-binding:v1\0");
    h.update(exporter);
    h.update(encode(&(scope, challenge))?);
    Ok(hex::encode(h.finalize()))
}
fn validate_response(
    original: &OfflineClockScopeV1,
    challenge: &str,
    binding: &str,
    response: &OfflineClockResponseV1,
    started: Instant,
    received: Instant,
    owner_deadline: Instant,
) -> Result<Instant> {
    original.validate()?;
    if response.scope != *original
        || response.challenge != challenge
        || response.channel_binding != binding
    {
        return Err(AuthorityError::Authentication);
    }
    let rtt = received
        .checked_duration_since(started)
        .ok_or(AuthorityError::Expired)?;
    if rtt > MAX_RTT
        || received >= owner_deadline
        || response.witness_time_ms < original.original_not_before_ms
    {
        return Err(AuthorityError::Expired);
    }
    // Charge the WHOLE RTT (including handshake/ledger work) and one continuity
    // margin against the original expiry. Rounding is always conservative.
    let uncertainty_ms = u64::try_from(rtt.as_nanos().div_ceil(1_000_000))
        .map_err(|_| AuthorityError::Limit)?
        .checked_add(CLOCK_MARGIN.as_millis() as u64)
        .ok_or(AuthorityError::Limit)?;
    let latest_at_receive = response
        .witness_time_ms
        .checked_add(uncertainty_ms)
        .ok_or(AuthorityError::Expired)?;
    let remaining = original
        .original_expires_at_ms
        .checked_sub(latest_at_receive)
        .filter(|n| *n > 0)
        .ok_or(AuthorityError::Expired)?;
    received
        .checked_add(Duration::from_millis(remaining).min(MAX_OBSERVATION))
        .map(|end| end.min(owner_deadline))
        .ok_or(AuthorityError::Expired)
}
fn check_continuity(
    started: Instant,
    wall: std::time::SystemTime,
    ceiling: Instant,
    now: Instant,
    wall_now: std::time::SystemTime,
) -> Result<()> {
    if now >= ceiling {
        return Err(AuthorityError::Expired);
    }
    let elapsed = now
        .checked_duration_since(started)
        .ok_or(AuthorityError::Expired)?;
    let wall_elapsed = wall_now
        .duration_since(wall)
        .map_err(|_| AuthorityError::Expired)?;
    if elapsed.abs_diff(wall_elapsed) > CLOCK_MARGIN {
        return Err(AuthorityError::Expired);
    }
    Ok(())
}

#[cfg(test)]
#[path = "offline_clock_v1_tests.rs"]
mod tests;
