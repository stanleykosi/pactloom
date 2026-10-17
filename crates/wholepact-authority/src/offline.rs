//! Strict evidence contracts for a future exact-effects offline profile.
//!
//! These DTOs are NOT authenticated capabilities. There is deliberately no
//! journal mutation, portable permit issuer, signing constructor or conversion to
//! `AuthenticatedPermit`. A valid descriptor cannot reserve budget or use keys.
//! Runtime support stays disabled until the independent witness, native signer,
//! scoped transport and current online dispatch are composed and qualified.
use crate::{
    AccountPolicy, AuthorityError, AuthorityHead, InputReservation, MAX_EVENTS, MAX_MONEY, Result,
    digest, encode, hash, id,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const OFFLINE_PROTOCOL_VERSION: u16 = 1;

/// This supported contract never promises global single invocation on cloned
/// software, or immediate remote revocation of already exported exact authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineAuthoritySemantics {
    ExactEffectsPreReservedMayDrainAfterRevocation,
}

/// Every fact in this list must be shown as unknown at offline review. Keeping a
/// fixed complete set prevents a caller from silently omitting an inconvenient
/// limitation. Snapshot provenance is checked separately from current truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineUnknownFact {
    CurrentChainTip,
    CurrentInputSpendability,
    MempoolConflicts,
    SubsequentReorganization,
    CurrentRemotePolicyAndRevocation,
    GlobalSingleKeyInvocation,
}
impl OfflineUnknownFact {
    pub const ALL: [Self; 6] = [
        Self::CurrentChainTip,
        Self::CurrentInputSpendability,
        Self::MempoolConflicts,
        Self::SubsequentReorganization,
        Self::CurrentRemotePolicyAndRevocation,
        Self::GlobalSingleKeyInvocation,
    ];
}

/// Authenticated provenance is still supplied by a separate pinned source
/// adapter. The timestamp is an observation label, not a fresh clock or oracle.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineSnapshotCommitment {
    pub source_id: String,
    pub source_identity_digest: String,
    pub source_policy_digest: String,
    pub snapshot_digest: String,
    pub observed_at_ms: u64,
    pub tip_height: u32,
    pub tip_hash: String,
    pub anchor_height: u32,
    pub anchor_hash: String,
    pub anchor_root: String,
}
impl OfflineSnapshotCommitment {
    pub fn validate(&self) -> Result<()> {
        id(&self.source_id)?;
        for h in [
            &self.source_identity_digest,
            &self.source_policy_digest,
            &self.snapshot_digest,
            &self.tip_hash,
            &self.anchor_hash,
            &self.anchor_root,
        ] {
            hash(h)?;
        }
        if self.observed_at_ms == 0
            || self.observed_at_ms > i64::MAX as u64
            || self.anchor_height > self.tip_height
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}

/// Shared immutable terms; the review-package digest covers the bounded role
/// payload bytes, including the actual proof and disclosure inventory, excluding
/// this commitment wrapper (no self-referential digest). A digest
/// does not itself establish that the package was verified or minimally redacted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineAuthorizationTerms {
    pub account_id: String,
    pub network_profile_id: String,
    pub consensus_branch_id: u32,
    pub authorization_id: String,
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub proposal_revision: u64,
    pub proposal_digest: String,
    pub manifest_digest: String,
    pub effects_digest: String,
    pub artifact_digest: String,
    pub review_binding: String,
    pub review_package_digest: String,
    pub recipient_scope_digest: String,
    /// Existing wholepact transport-key.v1 fingerprint, not raw SHA-256(key).
    pub offline_signer_key_digest: String,
    pub return_recipient_key_digest: String,
    pub offline_policy_digest: String,
    pub snapshot: OfflineSnapshotCommitment,
    pub inputs: Vec<InputReservation>,
    pub maximum_debit_zatoshis: u64,
    pub fee_share_zatoshis: u64,
    pub transaction_fee_zatoshis: u64,
    pub transaction_expiry_height: u32,
    pub unknown_facts: Vec<OfflineUnknownFact>,
    pub semantics: OfflineAuthoritySemantics,
}
impl OfflineAuthorizationTerms {
    pub fn validate(&self) -> Result<()> {
        for s in [
            &self.account_id,
            &self.network_profile_id,
            &self.authorization_id,
            &self.agreement_id,
            &self.obligation_id,
            &self.proposal_id,
        ] {
            id(s)?;
        }
        for h in [
            &self.enrollment_ref,
            &self.accepted_manifest_ref,
            &self.proposal_digest,
            &self.manifest_digest,
            &self.effects_digest,
            &self.artifact_digest,
            &self.review_binding,
            &self.review_package_digest,
            &self.recipient_scope_digest,
            &self.offline_signer_key_digest,
            &self.return_recipient_key_digest,
            &self.offline_policy_digest,
        ] {
            hash(h)?;
        }
        self.snapshot.validate()?;
        if self.proposal_revision == 0
            || self.consensus_branch_id == 0
            || self.proposal_revision > i64::MAX as u64
            || self.inputs.is_empty()
            || self.inputs.len() > 256
            || self.maximum_debit_zatoshis == 0
            || self.maximum_debit_zatoshis > MAX_MONEY
            || self.fee_share_zatoshis > self.maximum_debit_zatoshis
            || self.fee_share_zatoshis > self.transaction_fee_zatoshis
            || self.transaction_fee_zatoshis > MAX_MONEY
            || self.transaction_expiry_height <= self.snapshot.tip_height
            || self.unknown_facts.as_slice() != OfflineUnknownFact::ALL
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut ids = BTreeSet::new();
        let mut nullifiers = BTreeSet::new();
        let mut actions = BTreeSet::new();
        let mut total = 0_u64;
        // Canonical order prevents semantic-equivalence retries with distinct
        // request hashes. There is no permission to renumber actual PCZT actions.
        let mut previous_action = None;
        for input in &self.inputs {
            id(&input.input_id)?;
            hash(&input.nullifier)?;
            if input.action_index > 255
                || input.value_zatoshis == 0
                || input.value_zatoshis > MAX_MONEY
                || !ids.insert(&input.input_id)
                || !nullifiers.insert(&input.nullifier)
                || !actions.insert(input.action_index)
                || previous_action.is_some_and(|old| old >= input.action_index)
            {
                return Err(AuthorityError::InvalidBinding);
            }
            previous_action = Some(input.action_index);
            total = total
                .checked_add(input.value_zatoshis)
                .filter(|v| *v <= MAX_MONEY)
                .ok_or(AuthorityError::InvalidBinding)?;
        }
        if total < self.maximum_debit_zatoshis {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub fn terms_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:offline-authorization-terms:v1", self)
    }
}

/// Reservation intent is NOT final spending consent. The native review digest
/// needs authenticated signer-origin verification outside this shape validator.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineReservationIntent {
    pub schema_version: u16,
    pub intent_id: String,
    pub terms: OfflineAuthorizationTerms,
    pub native_reservation_review_digest: String,
}
impl OfflineReservationIntent {
    pub fn validate(&self) -> Result<()> {
        version(self.schema_version)?;
        id(&self.intent_id)?;
        hash(&self.native_reservation_review_digest)?;
        self.terms.validate()?;
        encode(self)?;
        Ok(())
    }
    pub fn intent_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:offline-reservation-intent:v1", self)
    }
}

/// Owner-enrolled offline bounds, never accepted merely because a request embeds
/// them. No budget lives here: all modes must charge the ordinary witness ledger.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineEnrollmentPolicy {
    pub schema_version: u16,
    pub account_id: String,
    pub network_profile_id: String,
    pub witness_id: String,
    pub witness_transport_key_digest: String,
    pub witness_certificate_digest: String,
    pub enrollment_ref: String,
    /// Existing wholepact transport-key.v1 fingerprint, not raw SHA-256(key).
    pub offline_signer_key_digest: String,
    pub return_recipient_key_digest: String,
    pub source_identity_digest: String,
    pub source_policy_digest: String,
    pub maximum_admission_lifetime_ms: u64,
    pub valid_from_ms: u64,
    pub expires_at_ms: u64,
    pub semantics: OfflineAuthoritySemantics,
}
impl OfflineEnrollmentPolicy {
    pub fn validate(&self) -> Result<()> {
        version(self.schema_version)?;
        for s in [&self.account_id, &self.network_profile_id, &self.witness_id] {
            id(s)?;
        }
        for h in [
            &self.witness_transport_key_digest,
            &self.witness_certificate_digest,
            &self.enrollment_ref,
            &self.offline_signer_key_digest,
            &self.return_recipient_key_digest,
            &self.source_identity_digest,
            &self.source_policy_digest,
        ] {
            hash(h)?;
        }
        if self.maximum_admission_lifetime_ms == 0
            || self.maximum_admission_lifetime_ms > 7 * 24 * 60 * 60 * 1000
            || self.valid_from_ms >= self.expires_at_ms
            || self.expires_at_ms > i64::MAX as u64
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn policy_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:offline-enrollment-policy:v1", self)
    }
}

/// Proposed request shape only: not an AuthorityMutation. Issuance must be one
/// shared-ledger transaction that reserves exposure AND pre-admits exact key use.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReserveOfflineAuthorization {
    pub schema_version: u16,
    pub operation_id: String,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub intent: OfflineReservationIntent,
    pub requested_at_ms: u64,
    pub admission_expires_at_ms: u64,
}
impl ReserveOfflineAuthorization {
    pub fn validate(&self) -> Result<()> {
        version(self.schema_version)?;
        id(&self.operation_id)?;
        hash(&self.expected_head.digest)?;
        self.intent.validate()?;
        if self.writer_epoch == 0
            || self.writer_epoch > i64::MAX as u64
            || self.expected_head.sequence >= MAX_EVENTS
            || self.requested_at_ms < self.intent.terms.snapshot.observed_at_ms
            || self.admission_expires_at_ms <= self.requested_at_ms
            || self.admission_expires_at_ms > i64::MAX as u64
        {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub fn request_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:reserve-offline-authorization:v1", self)
    }
    /// Pure static preflight, NEVER a reservation, live policy check or authority.
    /// Callers still need authenticated enrollment, current writer/head/session,
    /// revocation, input/obligation exclusion and atomic aggregate accounting.
    pub fn validate_policy_bounds(
        &self,
        account: &AccountPolicy,
        offline: &OfflineEnrollmentPolicy,
        witness_now_ms: u64,
    ) -> Result<()> {
        // Legacy origin membership is immutable. Born extension references are
        // admitted only by their separate complete origin validator.
        if !account
            .enrollment_refs
            .contains(&self.intent.terms.enrollment_ref)
        {
            return Err(AuthorityError::PolicyDenied);
        }
        self.validate_common_policy_bounds(account, offline, witness_now_ms)
    }
    pub(crate) fn validate_common_policy_bounds(
        &self,
        account: &AccountPolicy,
        offline: &OfflineEnrollmentPolicy,
        witness_now_ms: u64,
    ) -> Result<()> {
        self.validate()?;
        account.validate()?;
        offline.validate()?;
        let t = &self.intent.terms;
        if t.account_id != account.account_id
            || t.account_id != offline.account_id
            || t.network_profile_id != account.network_profile_id
            || t.network_profile_id != offline.network_profile_id
            || account.witness_id != offline.witness_id
            || t.enrollment_ref != offline.enrollment_ref
            || t.offline_policy_digest != offline.policy_digest()?
            || t.offline_signer_key_digest != offline.offline_signer_key_digest
            || t.return_recipient_key_digest != offline.return_recipient_key_digest
            || t.snapshot.source_identity_digest != offline.source_identity_digest
            || t.snapshot.source_policy_digest != offline.source_policy_digest
            || t.semantics != offline.semantics
            || !account.agreement_ids.contains(&t.agreement_id)
            || !account
                .recipient_scope_digests
                .contains(&t.recipient_scope_digest)
            || t.maximum_debit_zatoshis > account.per_operation_limit_zatoshis
            || t.fee_share_zatoshis > account.maximum_fee_share_zatoshis
            || t.transaction_fee_zatoshis > account.maximum_transaction_fee_zatoshis
            || self.admission_expires_at_ms - self.requested_at_ms
                > offline.maximum_admission_lifetime_ms
            || self.admission_expires_at_ms - self.requested_at_ms
                > account.maximum_permit_lifetime_ms
            || self.admission_expires_at_ms > offline.expires_at_ms
            || self.admission_expires_at_ms > account.policy_expires_at_ms
            || self.requested_at_ms < offline.valid_from_ms
        {
            return Err(AuthorityError::PolicyDenied);
        }
        if witness_now_ms < self.requested_at_ms || witness_now_ms >= self.admission_expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
}

/// Portable DESCRIPTOR only. Successful matching is not witness authentication,
/// a current remote-policy assertion, or proof of a durable ledger commit.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineAuthorizationAdmission {
    pub schema_version: u16,
    pub witness_id: String,
    pub witness_policy_digest: String,
    pub witness_transport_key_digest: String,
    pub request_digest: String,
    pub request: ReserveOfflineAuthorization,
    pub committed_head: AuthorityHead,
    pub reserved_at_ms: u64,
    pub account_outstanding_debit_zatoshis: u64,
    pub account_reserved_input_value_zatoshis: u64,
    pub writer_session_id: String,
}
impl OfflineAuthorizationAdmission {
    /// Match retained original owner-policy evidence at issuance time. This is
    /// NOT witness authentication or a current dispatch/revocation check.
    pub fn validate_reserved_policy_bounds(
        &self,
        account: &AccountPolicy,
        offline: &OfflineEnrollmentPolicy,
    ) -> Result<()> {
        self.matches_request(&self.request)?;
        self.request
            .validate_policy_bounds(account, offline, self.reserved_at_ms)?;
        if self.witness_id != account.witness_id
            || self.witness_policy_digest != account.policy_digest()?
            || self.witness_transport_key_digest != offline.witness_transport_key_digest
            || self.account_outstanding_debit_zatoshis > account.aggregate_budget_zatoshis
        {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(())
    }
    pub fn matches_request(&self, request: &ReserveOfflineAuthorization) -> Result<()> {
        version(self.schema_version)?;
        request.validate()?;
        id(&self.witness_id)?;
        for h in [
            &self.witness_policy_digest,
            &self.witness_transport_key_digest,
            &self.request_digest,
            &self.committed_head.digest,
            &self.writer_session_id,
        ] {
            hash(h)?;
        }
        let own_inputs = request.intent.terms.inputs.iter().try_fold(0_u64, |v, i| {
            v.checked_add(i.value_zatoshis)
                .ok_or(AuthorityError::InvalidBinding)
        })?;
        if self.request != *request
            || self.request_digest != request.request_digest()?
            || self.committed_head.sequence
                != request
                    .expected_head
                    .sequence
                    .checked_add(1)
                    .ok_or(AuthorityError::InvalidBinding)?
            || self.reserved_at_ms < request.requested_at_ms
            || self.reserved_at_ms >= request.admission_expires_at_ms
            || self.account_outstanding_debit_zatoshis < request.intent.terms.maximum_debit_zatoshis
            || self.account_outstanding_debit_zatoshis > MAX_MONEY
            || self.account_reserved_input_value_zatoshis < own_inputs
            || self.account_reserved_input_value_zatoshis > MAX_MONEY
        {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
}

fn version(value: u16) -> Result<()> {
    if value != OFFLINE_PROTOCOL_VERSION {
        return Err(AuthorityError::UnsupportedVersion);
    }
    Ok(())
}

#[cfg(test)]
#[path = "offline_tests.rs"]
pub(crate) mod tests;
