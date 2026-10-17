//! Read-only, purpose-bound time evidence for the dedicated native born witness. A current
//! clock observation is not enrollment, consent, reservation, revocation status,
//! input spendability or permission to sign. No journal mutation is performed.
use crate::{born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1, *};
use serde::{Deserialize, Serialize};

/// Lookup expectation only. Callers must obtain it from their retained original;
/// deserializing this DTO never authenticates an admission or a clock observation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineClockScopeV1 {
    pub enrollment_digest: String,
    pub artifact_binding_digest: String,
    pub witness_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub witness_policy_digest: String,
    pub operation_id: String,
    pub authorization_id: String,
    pub original_request_digest: String,
    pub original_admission_digest: String,
    pub original_not_before_ms: u64,
    pub original_expires_at_ms: u64,
}
impl BornOfflineClockScopeV1 {
    /// Uses the same digest as the existing minimal admission statement, so a
    /// recipient need not receive witness-private totals/full admission bytes.
    pub fn from_descriptor(admission: &BornOfflineAuthorizationAdmissionV1) -> Result<Self> {
        admission.matches_request(&admission.request)?;
        let a = &admission.reserved;
        let scope = Self {
            enrollment_digest: admission.request.enrollment_digest.clone(),
            artifact_binding_digest: admission.request.artifact_binding_digest.clone(),
            witness_id: a.witness_id.clone(),
            account_id: a.request.intent.terms.account_id.clone(),
            network_profile_id: a.request.intent.terms.network_profile_id.clone(),
            witness_policy_digest: a.witness_policy_digest.clone(),
            operation_id: a.request.operation_id.clone(),
            authorization_id: a.request.intent.terms.authorization_id.clone(),
            original_request_digest: admission.request.request_digest()?,
            original_admission_digest: admission.admission_digest()?,
            original_not_before_ms: a.reserved_at_ms,
            original_expires_at_ms: a.request.admission_expires_at_ms,
        };
        scope.validate()?;
        Ok(scope)
    }
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.witness_id,
            &self.account_id,
            &self.network_profile_id,
            &self.operation_id,
            &self.authorization_id,
        ] {
            id(value)?;
        }
        for value in [
            &self.enrollment_digest,
            &self.artifact_binding_digest,
            &self.witness_policy_digest,
            &self.original_request_digest,
            &self.original_admission_digest,
        ] {
            hash(value)?;
        }
        if self.original_not_before_ms == 0
            || self.original_not_before_ms >= self.original_expires_at_ms
            || self.original_expires_at_ms > i64::MAX as u64
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornOfflineClockRequestV1 {
    pub(crate) scope: BornOfflineClockScopeV1,
    pub(crate) challenge: String,
    pub(crate) channel_binding: String,
}
impl BornOfflineClockRequestV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        hash(&self.challenge)?;
        hash(&self.channel_binding)?;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornOfflineClockResponseV1 {
    pub(crate) scope: BornOfflineClockScopeV1,
    pub(crate) challenge: String,
    pub(crate) channel_binding: String,
    pub(crate) witness_time_ms: u64,
}

impl AuthorityJournal {
    fn require_born_clock_origin_v1(&self) -> Result<()> {
        #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
        {
            self.require_born_artifact_owner_read_current_v1()
        }
        #[cfg(not(all(feature = "born-offline-witness-owner", target_os = "linux")))]
        {
            Err(AuthorityError::Permission)
        }
    }
    /// Read permission is checked before operation presence is exposed. Only a
    /// committed exact offline reservation can supply the immutable scope. Later
    /// pause/revoke does not erase that original; this says nothing about status.
    pub(crate) fn observe_born_offline_clock_v1(
        &self,
        peer: &str,
        request: &BornOfflineClockRequestV1,
        channel_binding: &str,
        sample_now: impl FnOnce() -> Result<u64>,
    ) -> Result<BornOfflineClockResponseV1> {
        self.require_born_clock_origin_v1()?;
        request.validate()?;
        if request.channel_binding != channel_binding {
            return Err(AuthorityError::Authentication);
        }
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = rusqlite::Transaction::new_unchecked(
            c.connection(),
            rusqlite::TransactionBehavior::Deferred,
        )?;
        crate::journal::authenticate_admission(&tx, peer)?;
        let ledger = crate::journal::load(&tx)?;
        validate_original(&ledger, peer, &request.scope)?;
        // Sample the actual witness clock AFTER replay/authentication, never the
        // retained ledger event time, a client timestamp or a supplied wire value.
        let now = sample_now()?;
        let response = response_at(&ledger, request, now)?;
        // Recheck the genuine born-journal owner after replay, without nesting
        // the journal lock inside its separate namespace-registry lock.
        drop(tx);
        drop(c);
        self.require_born_clock_origin_v1()?;
        Ok(response)
    }
}
fn validate_original(
    ledger: &crate::policy::Ledger,
    peer: &str,
    expected: &BornOfflineClockScopeV1,
) -> Result<()> {
    expected.validate()?;
    ledger.authenticate_read(peer, &expected.account_id, &expected.network_profile_id)?;
    if ledger.snapshot.writer_status == WriterStatus::Quarantined {
        return Err(AuthorityError::RecoveryRequired);
    }
    let (mutation, _, result) = ledger
        .operations
        .get(&expected.operation_id)
        .ok_or(AuthorityError::InvalidBinding)?;
    let (
        AuthorityMutation::ReserveBornOfflineV1(record),
        MutationResult::BornOfflineReservedV1(admission),
    ) = (mutation, result)
    else {
        return Err(AuthorityError::InvalidBinding);
    };
    let enrollment = &ledger
        .born_offline_enrollment_v1()?
        .ok_or(AuthorityError::CorruptHistory)?
        .enrollment;
    let artifacts = ledger
        .born_offline_artifacts_v1()?
        .ok_or(AuthorityError::CorruptHistory)?;
    let manual = &ledger
        .manual_extension()?
        .ok_or(AuthorityError::CorruptHistory)?
        .extension;
    record
        .authentication
        .matches(&record.request.reservation, &enrollment.policy)?;
    admission.matches_request(&record.request)?;
    admission.validate_reserved_policy_bounds(&ledger.policy, enrollment, artifacts, manual)?;
    if BornOfflineClockScopeV1::from_descriptor(admission)? != *expected {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}
fn response_at(
    ledger: &crate::policy::Ledger,
    request: &BornOfflineClockRequestV1,
    now: u64,
) -> Result<BornOfflineClockResponseV1> {
    if now < ledger.snapshot.last_witness_time_ms
        || now < request.scope.original_not_before_ms
        || now >= request.scope.original_expires_at_ms
    {
        return Err(AuthorityError::Expired);
    }
    Ok(BornOfflineClockResponseV1 {
        scope: request.scope.clone(),
        challenge: request.challenge.clone(),
        channel_binding: request.channel_binding.clone(),
        witness_time_ms: now,
    })
}

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn born_clock_requires_exact_complete_original_and_current_time_not_event_time() {
        let (mut ledger, _, record) = crate::born_offline_admission_v1::tests::fixture();
        let event = crate::born_offline_admission_v1::tests::event(&ledger, &record);
        let MutationResult::BornOfflineReservedV1(admission) = ledger.apply(&event).unwrap() else {
            panic!()
        };
        let scope = BornOfflineClockScopeV1::from_descriptor(&admission).unwrap();
        let peer = ledger.policy.initial_writer_certificate_digest.clone();
        validate_original(&ledger, &peer, &scope).unwrap();
        let request = BornOfflineClockRequestV1 {
            scope: scope.clone(),
            challenge: "11".repeat(32),
            channel_binding: "22".repeat(32),
        };
        assert_eq!(
            response_at(&ledger, &request, 254500)
                .unwrap()
                .witness_time_ms,
            254500
        );
        for now in [254000, 255000, u64::MAX] {
            assert!(response_at(&ledger, &request, now).is_err());
        }
        for change in 0..4 {
            let mut changed = scope.clone();
            match change {
                0 => changed.enrollment_digest = "33".repeat(32),
                1 => changed.artifact_binding_digest = "44".repeat(32),
                2 => changed.original_admission_digest = "55".repeat(32),
                _ => changed.original_expires_at_ms += 1,
            };
            assert!(validate_original(&ledger, &peer, &changed).is_err());
        }
        assert!(validate_original(&ledger, &"66".repeat(32), &scope).is_err());
        ledger.snapshot.writer_status = WriterStatus::Paused;
        validate_original(&ledger, &peer, &scope).unwrap();
        ledger.snapshot.writer_status = WriterStatus::Quarantined;
        assert!(validate_original(&ledger, &peer, &scope).is_err());
    }
}
