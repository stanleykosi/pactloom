//! Read-only, purpose-bound time evidence from the configured witness. A current
//! clock observation is not enrollment, consent, reservation, revocation status,
//! input spendability or permission to sign. No journal mutation is performed.
use crate::{offline::OfflineAuthorizationAdmission, *};
use serde::{Deserialize, Serialize};

/// Lookup expectation only. Callers must obtain it from their retained original;
/// deserializing this DTO never authenticates an admission or a clock observation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineClockScopeV1 {
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
impl OfflineClockScopeV1 {
    /// Uses the same digest as the existing minimal admission statement, so a
    /// recipient need not receive witness-private totals/full admission bytes.
    pub fn from_descriptor(admission: &OfflineAuthorizationAdmission) -> Result<Self> {
        admission.matches_request(&admission.request)?;
        let scope = Self {
            witness_id: admission.witness_id.clone(),
            account_id: admission.request.intent.terms.account_id.clone(),
            network_profile_id: admission.request.intent.terms.network_profile_id.clone(),
            witness_policy_digest: admission.witness_policy_digest.clone(),
            operation_id: admission.request.operation_id.clone(),
            authorization_id: admission.request.intent.terms.authorization_id.clone(),
            original_request_digest: admission.request_digest.clone(),
            original_admission_digest: digest(
                "wholepact.offline-original-admission-assertion.v1",
                admission,
            )?,
            original_not_before_ms: admission.reserved_at_ms,
            original_expires_at_ms: admission.request.admission_expires_at_ms,
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
pub(crate) struct OfflineClockRequestV1 {
    pub(crate) scope: OfflineClockScopeV1,
    pub(crate) challenge: String,
    pub(crate) channel_binding: String,
}
impl OfflineClockRequestV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        hash(&self.challenge)?;
        hash(&self.channel_binding)?;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfflineClockResponseV1 {
    pub(crate) scope: OfflineClockScopeV1,
    pub(crate) challenge: String,
    pub(crate) channel_binding: String,
    pub(crate) witness_time_ms: u64,
}

impl AuthorityJournal {
    /// Read permission is checked before operation presence is exposed. Only a
    /// committed exact offline reservation can supply the immutable scope. Later
    /// pause/revoke does not erase that original; this says nothing about status.
    pub(crate) fn observe_offline_clock_v1(
        &self,
        peer: &str,
        request: &OfflineClockRequestV1,
        channel_binding: &str,
        sample_now: impl FnOnce() -> Result<u64>,
    ) -> Result<OfflineClockResponseV1> {
        self.require_born_read_current()?;
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
        self.require_born_read_current()?;
        Ok(response)
    }
}
fn validate_original(
    ledger: &crate::policy::Ledger,
    peer: &str,
    expected: &OfflineClockScopeV1,
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
        AuthorityMutation::ReserveOfflineAuthorization(record),
        MutationResult::OfflineReserved(admission),
    ) = (mutation, result)
    else {
        return Err(AuthorityError::InvalidBinding);
    };
    let policy = ledger
        .offline_policies
        .get(&record.request.intent.terms.offline_policy_digest)
        .ok_or(AuthorityError::CorruptHistory)?;
    record.authentication.matches(&record.request, policy)?;
    admission.matches_request(&record.request)?;
    admission.validate_reserved_policy_bounds(&ledger.policy, policy)?;
    if OfflineClockScopeV1::from_descriptor(admission)? != *expected {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}
fn response_at(
    ledger: &crate::policy::Ledger,
    request: &OfflineClockRequestV1,
    now: u64,
) -> Result<OfflineClockResponseV1> {
    if now < ledger.snapshot.last_witness_time_ms
        || now < request.scope.original_not_before_ms
        || now >= request.scope.original_expires_at_ms
    {
        return Err(AuthorityError::Expired);
    }
    Ok(OfflineClockResponseV1 {
        scope: request.scope.clone(),
        challenge: request.challenge.clone(),
        channel_binding: request.channel_binding.clone(),
        witness_time_ms: now,
    })
}

#[cfg(test)]
#[path = "offline_clock_v1_tests.rs"]
pub(crate) mod tests;
