//! Witness-enforced grant revisions and exact key-use admission. A reservation
//! alone never authorizes automatic key use. All controls and admissions share
//! the same immutable journal and BEGIN IMMEDIATE serialization boundary.
use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationGrantBinding {
    pub grant_id: String,
    pub revision: u64,
    pub terms_digest: String,
    pub application_id: String,
}
impl AutomationGrantBinding {
    pub fn validate(&self) -> Result<()> {
        id(&self.grant_id)?;
        id(&self.application_id)?;
        hash(&self.terms_digest)?;
        if self.revision == 0 || self.revision > MAX_EVENTS {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationGrantStatus {
    Active,
    Paused,
    Revoked,
}
/// One owner-approved account pending-debit ceiling, separate from the
/// witness lifetime ceiling. IDs are immutable; replacement requires a new ID.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAutomationAccountPolicy {
    pub policy_id: String,
    pub writer_epoch: u64,
    pub maximum_outstanding_debit_zatoshis: u64,
    pub valid_from_ms: u64,
    pub expires_at_ms: u64,
}
impl WitnessAutomationAccountPolicy {
    pub fn validate(&self) -> Result<()> {
        id(&self.policy_id)?;
        if self.writer_epoch == 0
            || self.writer_epoch > i64::MAX as u64
            || self.maximum_outstanding_debit_zatoshis == 0
            || self.maximum_outstanding_debit_zatoshis > MAX_MONEY
            || self.valid_from_ms >= self.expires_at_ms
            || self.expires_at_ms > i64::MAX as u64
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAutomationGrant {
    pub account_policy_id: String,
    pub binding: AutomationGrantBinding,
    pub writer_epoch: u64,
    pub enrollment_ref: String,
    pub agreement_ids: Vec<String>,
    pub recipient_scope_digests: Vec<String>,
    pub maximum_payment_debit_zatoshis: u64,
    pub maximum_payment_fee_zatoshis: u64,
    pub maximum_outstanding_debit_zatoshis: u64,
    pub maximum_authorization_lifetime_ms: u64,
    pub valid_from_ms: u64,
    pub expires_at_ms: u64,
    pub status: AutomationGrantStatus,
}
impl WitnessAutomationGrant {
    /// Pure preflight of owner-enrolled immutable bounds, not an authorization.
    /// Native review uses this before retaining a control that cannot synchronize.
    /// The live witness also checks current epoch, head, revision and status.
    pub fn validate_account_bounds(
        &self,
        account: &WitnessAutomationAccountPolicy,
        witness: &AccountPolicy,
    ) -> Result<()> {
        self.validate()?;
        account.validate()?;
        witness.validate()?;
        if self.account_policy_id != account.policy_id
            || self.writer_epoch != account.writer_epoch
            || self.valid_from_ms < account.valid_from_ms
            || self.expires_at_ms > account.expires_at_ms
            || self.maximum_outstanding_debit_zatoshis > account.maximum_outstanding_debit_zatoshis
            || account.maximum_outstanding_debit_zatoshis > witness.aggregate_budget_zatoshis
            || account.expires_at_ms > witness.policy_expires_at_ms
            || !witness.enrollment_refs.contains(&self.enrollment_ref)
            || !self
                .agreement_ids
                .iter()
                .all(|a| witness.agreement_ids.contains(a))
            || !self
                .recipient_scope_digests
                .iter()
                .all(|r| witness.recipient_scope_digests.contains(r))
            || self.maximum_payment_debit_zatoshis > witness.per_operation_limit_zatoshis
            || self.maximum_payment_fee_zatoshis > witness.maximum_fee_share_zatoshis
            || self.maximum_authorization_lifetime_ms > witness.maximum_permit_lifetime_ms
        {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        id(&self.account_policy_id)?;
        hash(&self.enrollment_ref)?;
        for list in [&self.agreement_ids, &self.recipient_scope_digests] {
            if list.is_empty()
                || list.len() > 128
                || list.iter().collect::<std::collections::BTreeSet<_>>().len() != list.len()
            {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        for a in &self.agreement_ids {
            id(a)?;
        }
        for r in &self.recipient_scope_digests {
            hash(r)?;
        }
        if self.writer_epoch == 0
            || self.writer_epoch > i64::MAX as u64
            || self.maximum_payment_debit_zatoshis == 0
            || self.maximum_payment_debit_zatoshis > self.maximum_outstanding_debit_zatoshis
            || self.maximum_outstanding_debit_zatoshis > MAX_MONEY
            || self.maximum_payment_fee_zatoshis > self.maximum_payment_debit_zatoshis
            || self.maximum_authorization_lifetime_ms == 0
            || self.maximum_authorization_lifetime_ms > 7 * 24 * 60 * 60 * 1000
            || self.valid_from_ms >= self.expires_at_ms
            || self.expires_at_ms > i64::MAX as u64
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeAutomaticKeyUse {
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub reservation_operation_id: String,
    pub reservation_request_digest: String,
    pub automation: AutomationGrantBinding,
    pub reviewed_at_ms: u64,
    pub admission_expires_at_ms: u64,
}
impl AuthorizeAutomaticKeyUse {
    pub fn validate(&self) -> Result<()> {
        for v in [
            &self.operation_id,
            &self.account_id,
            &self.network_profile_id,
            &self.reservation_operation_id,
        ] {
            id(v)?;
        }
        hash(&self.expected_head.digest)?;
        hash(&self.reservation_request_digest)?;
        self.automation.validate()?;
        if self.writer_epoch == 0
            || self.writer_epoch > i64::MAX as u64
            || self.reviewed_at_ms >= self.admission_expires_at_ms
            || self.admission_expires_at_ms > i64::MAX as u64
            || self.admission_expires_at_ms - self.reviewed_at_ms > 120_000
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn request_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:automatic-key-use:v1", self)
    }
}
/// Retained exact evidence. Serialization cannot create a key-use capability.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticKeyUseAdmission {
    pub request: AuthorizeAutomaticKeyUse,
    pub request_digest: String,
    pub reservation: ReservationPermit,
    pub witness_id: String,
    pub policy_digest: String,
    pub committed_head: AuthorityHead,
    pub admitted_at_ms: u64,
    pub writer_session_id: String,
}
impl AutomaticKeyUseAdmission {
    pub fn matches_request(&self, request: &AuthorizeAutomaticKeyUse) -> Result<()> {
        self.reservation
            .matches_request(&self.reservation.request)?;
        if self.request != *request
            || self.request_digest != request.request_digest()?
            || self.witness_id != self.reservation.witness_id
            || self.policy_digest != self.reservation.policy_digest
            || request.reservation_operation_id != self.reservation.request.operation_id
            || request.reservation_request_digest != self.reservation.request_digest
            || self.reservation.request.automation.as_ref() != Some(&request.automation)
            || request.account_id != self.reservation.request.account_id
            || request.network_profile_id != self.reservation.request.network_profile_id
            || request.writer_epoch != self.reservation.request.writer_epoch
            || self.admitted_at_ms < request.reviewed_at_ms
            || self.admitted_at_ms >= request.admission_expires_at_ms
            || request.admission_expires_at_ms > self.reservation.request.permit_expires_at_ms
            || self.committed_head.sequence
                != request
                    .expected_head
                    .sequence
                    .checked_add(1)
                    .ok_or(AuthorityError::InvalidBinding)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        hash(&self.writer_session_id)?;
        hash(&self.committed_head.digest)?;
        Ok(())
    }
}

impl crate::policy::Ledger {
    pub(crate) fn set_automation_grant(
        &mut self,
        grant: &WitnessAutomationGrant,
        account_policy: &WitnessAutomationAccountPolicy,
        now: u64,
    ) -> Result<()> {
        grant.validate_account_bounds(account_policy, &self.policy)?;
        if let Some(old) = self
            .automation_account_policies
            .get(&account_policy.policy_id)
        {
            if old != account_policy {
                return Err(AuthorityError::Conflict);
            }
            if grant.status == AutomationGrantStatus::Active
                && self.automation_account_policy.as_ref() != Some(account_policy)
            {
                // Historical policies cannot be reinstated by replay or by a
                // new grant; replacement is an explicit new immutable policy ID.
                return Err(AuthorityError::Conflict);
            }
        } else if grant.status != AutomationGrantStatus::Active {
            return Err(AuthorityError::PolicyDenied);
        }
        if grant.writer_epoch != self.snapshot.writer_epoch {
            return Err(AuthorityError::PolicyDenied);
        }
        if grant.status == AutomationGrantStatus::Active
            && (now < grant.valid_from_ms || now >= grant.expires_at_ms)
        {
            return Err(AuthorityError::Expired);
        }
        if let Some(old) = self.automation_grants.get(&grant.binding.grant_id) {
            if old.status == AutomationGrantStatus::Revoked
                || grant.binding.revision != old.binding.revision + 1
                || old.binding.application_id != grant.binding.application_id
                || old.enrollment_ref != grant.enrollment_ref
            {
                return Err(AuthorityError::Conflict);
            }
        } else if grant.binding.revision != 1 {
            return Err(AuthorityError::Conflict);
        }
        // All checks complete before either durable projection changes.
        self.automation_account_policies
            .insert(account_policy.policy_id.clone(), account_policy.clone());
        if grant.status == AutomationGrantStatus::Active {
            self.automation_account_policy = Some(account_policy.clone());
        }
        self.automation_grants
            .insert(grant.binding.grant_id.clone(), grant.clone());
        Ok(())
    }
    pub(crate) fn check_automation_reservation(
        &self,
        r: &ReserveAuthorization,
        now: u64,
        add: bool,
    ) -> Result<()> {
        let Some(binding) = &r.automation else {
            return Ok(());
        };
        let policy = self
            .automation_account_policy
            .as_ref()
            .ok_or(AuthorityError::PolicyDenied)?;
        if policy.writer_epoch != r.writer_epoch
            || now < policy.valid_from_ms
            || now >= policy.expires_at_ms
        {
            return Err(AuthorityError::Expired);
        }
        let grant = self
            .automation_grants
            .get(&binding.grant_id)
            .ok_or(AuthorityError::PolicyDenied)?;
        if grant.account_policy_id != policy.policy_id
            || grant.binding != *binding
            || grant.writer_epoch != r.writer_epoch
            || grant.enrollment_ref != r.enrollment_ref
        {
            return Err(AuthorityError::InvalidBinding);
        }
        if grant.status != AutomationGrantStatus::Active {
            return Err(AuthorityError::Inactive);
        }
        if now < grant.valid_from_ms
            || now >= grant.expires_at_ms
            || r.permit_expires_at_ms > grant.expires_at_ms
            || r.permit_expires_at_ms - r.reviewed_at_ms > grant.maximum_authorization_lifetime_ms
        {
            return Err(AuthorityError::Expired);
        }
        if !grant.agreement_ids.contains(&r.agreement_id)
            || !grant
                .recipient_scope_digests
                .contains(&r.recipient_scope_digest)
            || r.maximum_debit_zatoshis > grant.maximum_payment_debit_zatoshis
            || r.fee_share_zatoshis > grant.maximum_payment_fee_zatoshis
        {
            return Err(AuthorityError::PolicyDenied);
        }
        self.check_account_outstanding_limit(if add { r.maximum_debit_zatoshis } else { 0 })?;
        let mut outstanding = if add { r.maximum_debit_zatoshis } else { 0 };
        for (op, (_, _, result)) in &self.operations {
            if let MutationResult::Reserved(p) = result {
                if p.request
                    .automation
                    .as_ref()
                    .is_some_and(|b| b.grant_id == binding.grant_id)
                    && !self.resolutions.contains_key(op)
                {
                    outstanding = outstanding
                        .checked_add(p.request.maximum_debit_zatoshis)
                        .ok_or(AuthorityError::BudgetExceeded)?;
                }
            }
        }
        if outstanding > grant.maximum_outstanding_debit_zatoshis {
            return Err(AuthorityError::BudgetExceeded);
        }
        Ok(())
    }
    pub(crate) fn check_account_outstanding_limit(&self, additional: u64) -> Result<()> {
        if let Some(policy) = &self.automation_account_policy {
            if self
                .snapshot
                .outstanding_debit_zatoshis
                .checked_add(additional)
                .is_none_or(|total| total > policy.maximum_outstanding_debit_zatoshis)
            {
                return Err(AuthorityError::BudgetExceeded);
            }
        }
        Ok(())
    }
    pub(crate) fn admit_automatic_key_use(
        &mut self,
        r: &AuthorizeAutomaticKeyUse,
        event: &crate::policy::Event,
        next_head: &AuthorityHead,
    ) -> Result<MutationResult> {
        r.validate()?;
        self.fence(&r.expected_head, r.writer_epoch)?;
        if self.snapshot.writer_status != WriterStatus::Active {
            return Err(AuthorityError::Inactive);
        }
        let session = self
            .snapshot
            .active_writer_session
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if event.writer_session_id.as_deref() != Some(&session.session_id)
            || event.authenticated_certificate_digest != session.writer_certificate_digest
            || event.witness_time_ms >= session.expires_at_ms
        {
            return Err(AuthorityError::SessionRequired);
        }
        if event.witness_time_ms < r.reviewed_at_ms
            || event.witness_time_ms >= r.admission_expires_at_ms
        {
            return Err(AuthorityError::Expired);
        }
        let (_, _, MutationResult::Reserved(permit)) = self
            .operations
            .get(&r.reservation_operation_id)
            .ok_or(AuthorityError::InvalidBinding)?
        else {
            return Err(AuthorityError::InvalidBinding);
        };
        if self
            .automatic_key_uses
            .contains(&r.reservation_operation_id)
            || self.resolutions.contains_key(&r.reservation_operation_id)
        {
            return Err(AuthorityError::Conflict);
        }
        self.check_automation_reservation(&permit.request, event.witness_time_ms, false)?;
        let admission = AutomaticKeyUseAdmission {
            request: r.clone(),
            request_digest: r.request_digest()?,
            reservation: (**permit).clone(),
            witness_id: self.policy.witness_id.clone(),
            policy_digest: self.snapshot.policy_digest.clone(),
            committed_head: next_head.clone(),
            admitted_at_ms: event.witness_time_ms,
            writer_session_id: session.session_id.clone(),
        };
        admission.matches_request(r)?;
        self.automatic_key_uses
            .insert(r.reservation_operation_id.clone());
        Ok(MutationResult::AutomaticKeyUseAdmitted(Box::new(admission)))
    }
}
