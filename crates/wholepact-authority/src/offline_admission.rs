//! Opaque offline admission evidence. No public issuer or capability factory.
//! A configured witness bridge must authenticate the offline signer independently
//! of the controller's mTLS channel. Raw mutation DTOs never supply this authority.
use crate::{offline::*, *};
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
#[path = "offline_witness_owner_v1.rs"]
pub(crate) mod configured_witness;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineEnrollmentStatus {
    Active,
    Paused,
    Revoked,
}

/// Historical accepted authentication facts, not a live authentication token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineIntentAuthenticationRecord {
    pub intent_digest: String,
    pub reservation_request_digest: String,
    pub policy_digest: String,
    pub sender_fingerprint: String,
    pub witness_fingerprint: String,
    pub envelope_digest: String,
}
impl OfflineIntentAuthenticationRecord {
    pub fn matches(
        &self,
        request: &ReserveOfflineAuthorization,
        policy: &OfflineEnrollmentPolicy,
    ) -> Result<()> {
        let intent = &request.intent;
        hash(&self.envelope_digest)?;
        if self.reservation_request_digest != request.request_digest()?
            || self.intent_digest != intent.intent_digest()?
            || self.policy_digest != policy.policy_digest()?
            || self.sender_fingerprint != policy.offline_signer_key_digest
            || self.witness_fingerprint != policy.witness_transport_key_digest
            || intent.terms.offline_policy_digest != self.policy_digest
            || intent.terms.account_id != policy.account_id
            || intent.terms.network_profile_id != policy.network_profile_id
            || intent.terms.enrollment_ref != policy.enrollment_ref
            || intent.terms.offline_signer_key_digest != policy.offline_signer_key_digest
            || intent.terms.return_recipient_key_digest != policy.return_recipient_key_digest
            || intent.terms.snapshot.source_identity_digest != policy.source_identity_digest
            || intent.terms.snapshot.source_policy_digest != policy.source_policy_digest
            || intent.terms.semantics != policy.semantics
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(())
    }
}

/// Privileged bridge handle. No Deserialize/Clone/Debug or public constructor.
/// Only the private configured witness owner constructs this after actual retained
/// enrollment and HPKE checks. It never reaches a controller/application callback.
pub struct OfflineIntentAuthenticationIssuer {
    policy: OfflineEnrollmentPolicy,
}
impl OfflineIntentAuthenticationIssuer {
    /// The holder is trusted verification code, not an untrusted caller. Invoke
    /// only AFTER pinned HPKE open and complete intent/context equality checks.
    pub fn bind_verified_intent(
        &self,
        request: &ReserveOfflineAuthorization,
        intent: &OfflineReservationIntent,
        sender_fingerprint: &str,
        witness_fingerprint: &str,
        envelope_digest: &str,
    ) -> Result<AuthenticatedOfflineIntent> {
        if &request.intent != intent {
            return Err(AuthorityError::Authentication);
        }
        let record = OfflineIntentAuthenticationRecord {
            intent_digest: intent.intent_digest()?,
            reservation_request_digest: request.request_digest()?,
            policy_digest: self.policy.policy_digest()?,
            sender_fingerprint: sender_fingerprint.into(),
            witness_fingerprint: witness_fingerprint.into(),
            envelope_digest: envelope_digest.into(),
        };
        record.matches(request, &self.policy)?;
        Ok(AuthenticatedOfflineIntent {
            record,
            policy: self.policy.clone(),
        })
    }
    /// Pure tests alone can construct the disabled foundation's privileged handle.
    #[cfg(test)]
    pub(crate) fn for_test(policy: OfflineEnrollmentPolicy) -> Result<Self> {
        policy.validate()?;
        Ok(Self { policy })
    }
}
/// Nonportable one-use authentication result, not spending consent or a permit.
pub struct AuthenticatedOfflineIntent {
    record: OfflineIntentAuthenticationRecord,
    policy: OfflineEnrollmentPolicy,
}
impl AuthenticatedOfflineIntent {
    pub fn evidence(&self) -> &OfflineIntentAuthenticationRecord {
        &self.record
    }
    pub(crate) fn matches(
        &self,
        request: &ReserveOfflineAuthorization,
        record: &OfflineIntentAuthenticationRecord,
    ) -> Result<()> {
        request.validate()?;
        if &self.record != record {
            return Err(AuthorityError::Authentication);
        }
        self.record.matches(request, &self.policy)
    }
}
/// Persisted event body. Only the sealed authentication result admits it to the
/// private journal route; deserializing this value is insufficient.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineReservationRecord {
    pub request: ReserveOfflineAuthorization,
    pub authentication: OfflineIntentAuthenticationRecord,
}
/// Only a successful durable journal commit may construct this export evidence.
/// No factory is exposed while offline consumers/bridge are incomplete.
pub struct CommittedOfflineAdmission {
    pub(crate) descriptor: OfflineAuthorizationAdmission,
}
impl CommittedOfflineAdmission {
    pub fn descriptor(&self) -> &OfflineAuthorizationAdmission {
        &self.descriptor
    }
}

impl policy::Ledger {
    pub(crate) fn set_offline_policy(
        &mut self,
        policy: &OfflineEnrollmentPolicy,
        previous: Option<&str>,
        now: u64,
    ) -> Result<()> {
        policy.validate()?;
        if policy.account_id != self.policy.account_id
            || policy.network_profile_id != self.policy.network_profile_id
            || policy.witness_id != self.policy.witness_id
            || !self.policy.enrollment_refs.contains(&policy.enrollment_ref)
            || policy.expires_at_ms > self.policy.policy_expires_at_ms
            || policy.maximum_admission_lifetime_ms > self.policy.maximum_permit_lifetime_ms
            || now < policy.valid_from_ms
            || now >= policy.expires_at_ms
        {
            return Err(AuthorityError::PolicyDenied);
        }
        let key = policy.policy_digest()?;
        if self.offline_policies.contains_key(&key) {
            return Err(AuthorityError::Conflict);
        }
        match (
            self.offline_policy_states.get(&policy.enrollment_ref),
            previous,
        ) {
            (None, None) => {}
            (Some((old, _)), Some(expected)) if old == expected => {}
            _ => return Err(AuthorityError::Conflict),
        }
        self.offline_policies.insert(key.clone(), policy.clone());
        self.offline_policy_states.insert(
            policy.enrollment_ref.clone(),
            (key, OfflineEnrollmentStatus::Active),
        );
        Ok(())
    }
    pub(crate) fn set_offline_status(
        &mut self,
        enrollment: &str,
        digest: &str,
        status: OfflineEnrollmentStatus,
    ) -> Result<()> {
        hash(enrollment)?;
        hash(digest)?;
        let (current, old) = self
            .offline_policy_states
            .get(enrollment)
            .ok_or(AuthorityError::PolicyDenied)?;
        if current != digest
            || status == OfflineEnrollmentStatus::Active
            || *old == OfflineEnrollmentStatus::Revoked
        {
            return Err(AuthorityError::PolicyDenied);
        }
        self.offline_policy_states
            .insert(enrollment.into(), (digest.into(), status));
        Ok(())
    }
    pub(crate) fn reserve_offline(
        &mut self,
        record: &OfflineReservationRecord,
        event: &policy::Event,
        head: &AuthorityHead,
    ) -> Result<MutationResult> {
        let r = &record.request;
        r.validate()?;
        let t = &r.intent.terms;
        self.fence(&r.expected_head, r.writer_epoch)?;
        if self.snapshot.writer_status != WriterStatus::Active
            || event.authenticated_certificate_digest != self.snapshot.writer_certificate_digest
        {
            return Err(AuthorityError::Inactive);
        }
        let session = self
            .snapshot
            .active_writer_session
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if event.writer_session_id.as_deref() != Some(session.session_id.as_str())
            || session.writer_epoch != r.writer_epoch
            || session.writer_certificate_digest != event.authenticated_certificate_digest
            || event.witness_time_ms >= session.expires_at_ms
        {
            return Err(AuthorityError::SessionRequired);
        }
        let policy = self
            .offline_policies
            .get(&t.offline_policy_digest)
            .ok_or(AuthorityError::PolicyDenied)?;
        if self.offline_policy_states.get(&t.enrollment_ref)
            != Some(&(
                t.offline_policy_digest.clone(),
                OfflineEnrollmentStatus::Active,
            ))
        {
            return Err(AuthorityError::Inactive);
        }
        r.validate_policy_bounds(&self.policy, policy, event.witness_time_ms)?;
        record.authentication.matches(r, policy)?;
        self.check_account_outstanding_limit(t.maximum_debit_zatoshis)?;
        if self.authorizations.contains(&t.authorization_id)
            || self.offline_intents.contains(&r.intent.intent_id)
            || self
                .offline_intent_digests
                .contains(&r.intent.intent_digest()?)
        {
            return Err(AuthorityError::Conflict);
        }
        self.check_input_obligation_exclusions(
            &t.obligation_id,
            t.inputs
                .iter()
                .map(|i| (i.input_id.as_str(), i.nullifier.as_str())),
        )?;
        let debit = self
            .snapshot
            .outstanding_debit_zatoshis
            .checked_add(t.maximum_debit_zatoshis)
            .filter(|v| {
                v.checked_add(self.snapshot.settled_debit_zatoshis)
                    .is_some_and(|total| total <= self.policy.aggregate_budget_zatoshis)
            })
            .ok_or(AuthorityError::BudgetExceeded)?;
        let selected =
            t.inputs
                .iter()
                .try_fold(self.snapshot.reserved_input_value_zatoshis, |n, i| {
                    n.checked_add(i.value_zatoshis)
                        .filter(|v| *v <= MAX_MONEY)
                        .ok_or(AuthorityError::BudgetExceeded)
                })?;
        let permit = OfflineAuthorizationAdmission {
            schema_version: OFFLINE_PROTOCOL_VERSION,
            witness_id: self.policy.witness_id.clone(),
            witness_policy_digest: self.snapshot.policy_digest.clone(),
            witness_transport_key_digest: policy.witness_transport_key_digest.clone(),
            request_digest: r.request_digest()?,
            request: r.clone(),
            committed_head: head.clone(),
            reserved_at_ms: event.witness_time_ms,
            account_outstanding_debit_zatoshis: debit,
            account_reserved_input_value_zatoshis: selected,
            writer_session_id: session.session_id.clone(),
        };
        permit.validate_reserved_policy_bounds(&self.policy, policy)?;
        self.snapshot.outstanding_debit_zatoshis = debit;
        self.snapshot.reserved_input_value_zatoshis = selected;
        self.snapshot.outstanding_reservations += 1;
        self.authorizations.insert(t.authorization_id.clone());
        self.offline_intents.insert(r.intent.intent_id.clone());
        self.offline_intent_digests
            .insert(r.intent.intent_digest()?);
        self.obligations.insert(t.obligation_id.clone());
        for input in &t.inputs {
            self.input_ids.insert(input.input_id.clone());
            self.nullifiers.insert(input.nullifier.clone());
        }
        Ok(MutationResult::OfflineReserved(Box::new(permit)))
    }
}
