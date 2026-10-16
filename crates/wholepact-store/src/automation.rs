//! Bounded automation over the authoritative encrypted exposure ledger.
//!
//! The generic source remains deny-only. Native production adapters live in the
//! signer and verify owner consent, kernel application identity, exact artifacts,
//! wallet provenance and complete authenticated witness history. Local grants are
//! mirrors: the independent witness serializes revision controls, reservations
//! and a separate one-shot key-use admission. Only an admitted exact operation
//! may drain a later revocation; snapshots alone can never authorize key use.
//! There is no independent automation exposure ledger.

use crate::{
    StorageProtection, Store, StoreError,
    authority::{ReleaseIntent, StoredExposure},
    encode, request_digest,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use wholepact_core::{
    CoreError,
    automation::{
        AutomationAccountPolicy, AutomationGrantTerms, AutomationRequest,
        evaluate_automation_request,
    },
};

const ACCOUNT: &str = "automation_account";
const POLICY: &str = "automation_policy_history";
const GRANT: &str = "automation_grant";
const AUTHORIZATION: &str = "automation_authorization";
const MAX_GRANTS_PER_ACCOUNT: u64 = 256;
const MAX_AUTHORIZATION_RECORDS: u64 = 16_384;
const CLOCK: &str = "automation_clock";

#[derive(Debug, thiserror::Error)]
pub enum AutomationError {
    #[error("automation policy rejected the request: {0}")]
    Policy(#[from] CoreError),
    #[error("automation storage failed: {0}")]
    Store(#[from] StoreError),
    #[error(
        "qualified automation identity, consent, concurrency and verifier source is unavailable"
    )]
    Unavailable,
    #[error("automation grant is not active")]
    NotActive,
    #[error("automation clock moved backwards or is out of range")]
    ClockInvalid,
    #[error("automation authority or exact scope was denied")]
    Denied,
    #[error("durable automation state may have changed; inspect it before retrying")]
    StateMayHaveChanged,
    #[error("authorization intent is durable and outcome is uncertain; exposure remains")]
    AuthorizationUncertain,
}
pub type Result<T> = std::result::Result<T, AutomationError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationGrantStatus {
    Draft,
    Active,
    Paused,
    Revoked,
    Expired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationGrantAction {
    Activate,
    Pause,
    Revoke,
    ObserveExpiry,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredAutomationAccount {
    pub revision: u64,
    pub policy: AutomationAccountPolicy,
    pub consent_reference: String,
    pub updated_at_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredAutomationGrant {
    pub revision: u64,
    pub terms: AutomationGrantTerms,
    pub status: AutomationGrantStatus,
    /// Original deliberate activation consent, retained after pause/revoke.
    pub original_activation_consent_reference: Option<String>,
    /// A resume requires new deliberate consent without changing grant terms.
    pub current_activation_consent_reference: Option<String>,
    pub updated_at_ms: u64,
}
impl StoredAutomationGrant {
    /// Time-aware display only; this never manufactures an activation permit.
    pub fn effective_status(&self, now_ms: u64) -> AutomationGrantStatus {
        if self.status != AutomationGrantStatus::Revoked && now_ms >= self.terms.expires_at_ms {
            AutomationGrantStatus::Expired
        } else {
            self.status
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticAuthorizationOutcome {
    /// A trusted authorizer retained its result locally. This is not export,
    /// broadcast, settlement or evidence that the ledger can release exposure.
    RetainedLocally,
    /// Includes timeout, crash recovery, or any ambiguous callback result.
    Unknown,
    /// Even this result does not clear the precommitted exposure reservation.
    Declined,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticAuthorizationRecord {
    pub grant_id: String,
    pub grant_revision: u64,
    pub account_policy_id: String,
    pub request_digest: String,
    pub request: AutomationRequest,
    pub original_activation_consent_reference: String,
    pub active_consent_reference: String,
    pub authorization_verification_reference: String,
    pub outcome: AutomaticAuthorizationOutcome,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomaticAuthorizationReceipt {
    pub record: AutomaticAuthorizationRecord,
    pub exposure: StoredExposure,
    /// Replay only returns historical metadata. The authorizer is never called.
    pub replayed: bool,
}

/// Full exact review passed only to a deliberately injected trusted source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomationReview {
    ConfigureAccount {
        policy: AutomationAccountPolicy,
        previous: Option<StoredAutomationAccount>,
    },
    CreateGrant {
        terms: AutomationGrantTerms,
        account: StoredAutomationAccount,
    },
    ChangeGrant {
        grant: StoredAutomationGrant,
        action: AutomationGrantAction,
    },
    Authorize {
        account: Box<StoredAutomationAccount>,
        grant: Box<StoredAutomationGrant>,
        request: Box<AutomationRequest>,
    },
}
impl AutomationReview {
    pub fn account_id(&self) -> &str {
        match self {
            Self::ConfigureAccount { policy, .. } => &policy.account_id,
            Self::CreateGrant { terms, .. } => &terms.account_id,
            Self::ChangeGrant { grant, .. } => &grant.terms.account_id,
            Self::Authorize { grant, .. } => &grant.terms.account_id,
        }
    }
}
/// Owned exact-intent lease, held until after the last callback and audit write.
/// Implementations must provide account-wide serialization, either by exclusive
/// authority or independent witness operations for control/reservation/key-use.
/// A snapshot/mutex alone does not suffice. With operational serialization the
/// authorizer must acquire a one-shot current admission before actual key use.
/// Rechecks must not retain this Store's connection lock across signer calls.
pub trait AutomationLease {
    fn check_current(&self, review: &AutomationReview, now_ms: u64) -> Result<()>;
    /// Original retained consent/verification reference from the trusted source,
    /// never synthesized from a signature ID or accepted from a client DTO.
    fn consent_reference(&self) -> &str;
}
pub trait AutomationTrustSource {
    type Lease: AutomationLease;
    /// Stable adapter identity, authenticated independently by the lease issuer.
    fn verifier_id(&self) -> &str;
    fn acquire(&self, review: &AutomationReview) -> Result<Self::Lease>;
    fn now_ms(&self) -> Result<u64>;
}
pub struct DenyAutomationTrustSource;
pub struct DeniedAutomationLease;
impl AutomationLease for DeniedAutomationLease {
    fn check_current(&self, _: &AutomationReview, _: u64) -> Result<()> {
        Err(AutomationError::Unavailable)
    }
    fn consent_reference(&self) -> &str {
        ""
    }
}
impl AutomationTrustSource for DenyAutomationTrustSource {
    type Lease = DeniedAutomationLease;
    fn verifier_id(&self) -> &str {
        "unavailable"
    }
    fn acquire(&self, _: &AutomationReview) -> Result<Self::Lease> {
        Err(AutomationError::Unavailable)
    }
    fn now_ms(&self) -> Result<u64> {
        Err(AutomationError::Unavailable)
    }
}

/// Cannot be constructed, deserialized or cloned by a client. Contains no keys,
/// signature bytes or arbitrary artifact export. The trusted authorizer must
/// independently locate and verify the exact retained artifact and signer scope.
pub struct PreparedAutomaticAuthorization<'a> {
    record: &'a AutomaticAuthorizationRecord,
    check_current: &'a dyn Fn() -> Result<()>,
}
impl PreparedAutomaticAuthorization<'_> {
    pub fn record(&self) -> &AutomaticAuthorizationRecord {
        self.record
    }
    /// Recheck the held lease, fresh clock, exact policy and current ledger
    /// immediately before each key-use operation. This does not create a new
    /// attempt or invoke the authorizer again. Never retain a token for later use.
    pub fn check_current(&self) -> Result<()> {
        (self.check_current)()
    }
}
pub trait AutomaticAuthorizer {
    /// Stable adapter identity; this label alone is never signer authority.
    fn signer_id(&self) -> &str;
    fn authorize_exact(
        &mut self,
        prepared: PreparedAutomaticAuthorization<'_>,
    ) -> Result<AutomaticAuthorizationOutcome>;
}

impl Store {
    /// Install/replace an owner-approved account ceiling. Replacements require a
    /// new immutable policy ID and deliberate consent; old grants cannot adopt
    /// it implicitly. Lowering below outstanding exposure does not erase it.
    pub fn configure_automation_account<T: AutomationTrustSource>(
        &self,
        policy: AutomationAccountPolicy,
        expected_revision: Option<u64>,
        trust: &T,
    ) -> Result<StoredAutomationAccount> {
        protected(self)?;
        policy.validate()?;
        let previous = self.automation_account(&policy.account_id)?;
        if previous.as_ref().map(|r| r.revision) != expected_revision {
            return Err(StoreError::RevisionConflict.into());
        }
        let review = AutomationReview::ConfigureAccount {
            policy: policy.clone(),
            previous: previous.clone(),
        };
        let lease = trust.acquire(&review)?;
        let now = checked_now(trust, previous.as_ref().map_or(0, |r| r.updated_at_ms))?;
        lease.check_current(&review, now)?;
        let consent = consent(&lease)?;
        if now < policy.valid_from_ms || now >= policy.expires_at_ms {
            return Err(AutomationError::NotActive);
        }
        let value = StoredAutomationAccount {
            revision: previous
                .as_ref()
                .map_or(Some(1), |r| r.revision.checked_add(1))
                .ok_or(StoreError::ResourceExhausted)?,
            policy,
            consent_reference: consent,
            updated_at_ms: now,
        };
        {
            let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(StoreError::from)?;
            current_account(&tx, &value.policy.account_id, value.policy.writer_epoch)?;
            if read::<StoredAutomationAccount>(&tx, ACCOUNT, &value.policy.account_id)? != previous
            {
                return Err(StoreError::RevisionConflict.into());
            }
            if read::<StoredAutomationAccount>(&tx, POLICY, &value.policy.policy_id)?.is_some() {
                return Err(StoreError::AlreadyExists.into());
            }
            write(&tx, POLICY, &value.policy.policy_id, 1, &value, now)?;
            write(
                &tx,
                ACCOUNT,
                &value.policy.account_id,
                value.revision,
                &value,
                now,
            )?;
            audit(
                &tx,
                ACCOUNT,
                &value.policy.account_id,
                value.revision,
                "automation.account_policy_configured",
                &value,
                now,
            )?;
            let fresh_now = checked_now(trust, now)?;
            if fresh_now >= value.policy.expires_at_ms {
                return Err(AutomationError::NotActive);
            }
            lease.check_current(&review, fresh_now)?;
            advance_clock(&tx, review.account_id(), fresh_now)?;
            tx.commit().map_err(StoreError::from)?;
        }
        post_commit(trust, &lease, &review, now)?;
        Ok(value)
    }

    /// A draft is always off. Review the pure evaluator's allowed/rejected
    /// examples and named signer/verifier before the separate Activate action.
    pub fn create_automation_grant<T: AutomationTrustSource>(
        &self,
        terms: AutomationGrantTerms,
        trust: &T,
    ) -> Result<StoredAutomationGrant> {
        protected(self)?;
        let account = self
            .automation_account(&terms.account_id)?
            .ok_or(StoreError::NotFound)?;
        terms.validate(&account.policy)?;
        if trust.verifier_id() != terms.verifier_id {
            return Err(AutomationError::Denied);
        }
        let review = AutomationReview::CreateGrant {
            terms: terms.clone(),
            account: account.clone(),
        };
        let lease = trust.acquire(&review)?;
        let now = checked_now(trust, account.updated_at_ms)?;
        lease.check_current(&review, now)?;
        consent(&lease)?;
        let value = StoredAutomationGrant {
            revision: 1,
            terms,
            status: AutomationGrantStatus::Draft,
            original_activation_consent_reference: None,
            current_activation_consent_reference: None,
            updated_at_ms: now,
        };
        {
            let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(StoreError::from)?;
            current_account(&tx, &value.terms.account_id, value.terms.writer_epoch)?;
            if read::<StoredAutomationAccount>(&tx, ACCOUNT, &value.terms.account_id)?.as_ref()
                != Some(&account)
            {
                return Err(StoreError::RevisionConflict.into());
            }
            if read::<StoredAutomationGrant>(&tx, GRANT, &value.terms.grant_id)?.is_some() {
                return Err(StoreError::AlreadyExists.into());
            }
            let count = grants(&tx, &value.terms.account_id)?.len() as u64;
            if count >= MAX_GRANTS_PER_ACCOUNT {
                return Err(StoreError::ResourceExhausted.into());
            }
            write(&tx, GRANT, &value.terms.grant_id, 1, &value, now)?;
            audit(
                &tx,
                GRANT,
                &value.terms.grant_id,
                1,
                "automation.grant_drafted",
                &value,
                now,
            )?;
            let fresh_now = checked_now(trust, now)?;
            lease.check_current(&review, fresh_now)?;
            advance_clock(&tx, review.account_id(), fresh_now)?;
            tx.commit().map_err(StoreError::from)?;
        }
        post_commit(trust, &lease, &review, now)?;
        Ok(value)
    }

    pub fn change_automation_grant<T: AutomationTrustSource>(
        &self,
        grant_id: &str,
        expected_revision: u64,
        action: AutomationGrantAction,
        trust: &T,
    ) -> Result<StoredAutomationGrant> {
        protected(self)?;
        let previous = self
            .automation_grant(grant_id)?
            .ok_or(StoreError::NotFound)?;
        if previous.revision != expected_revision {
            return Err(StoreError::RevisionConflict.into());
        }
        if trust.verifier_id() != previous.terms.verifier_id {
            return Err(AutomationError::Denied);
        }
        let review = AutomationReview::ChangeGrant {
            grant: previous.clone(),
            action,
        };
        let lease = trust.acquire(&review)?;
        let now = checked_now(trust, previous.updated_at_ms)?;
        lease.check_current(&review, now)?;
        let reference = consent(&lease)?;
        let mut value = previous.clone();
        let expired = now >= value.terms.expires_at_ms;
        value.status = match action {
            AutomationGrantAction::Activate
                if !expired
                    && now >= value.terms.valid_from_ms
                    && matches!(
                        value.status,
                        AutomationGrantStatus::Draft | AutomationGrantStatus::Paused
                    ) =>
            {
                value
                    .original_activation_consent_reference
                    .get_or_insert_with(|| reference.clone());
                value.current_activation_consent_reference = Some(reference);
                AutomationGrantStatus::Active
            }
            AutomationGrantAction::Pause if value.status == AutomationGrantStatus::Active => {
                AutomationGrantStatus::Paused
            }
            AutomationGrantAction::Revoke if value.status != AutomationGrantStatus::Revoked => {
                AutomationGrantStatus::Revoked
            }
            AutomationGrantAction::ObserveExpiry
                if expired && value.status != AutomationGrantStatus::Revoked =>
            {
                AutomationGrantStatus::Expired
            }
            _ => return Err(StoreError::InvalidTransition.into()),
        };
        value.revision = value
            .revision
            .checked_add(1)
            .ok_or(StoreError::ResourceExhausted)?;
        value.updated_at_ms = now;
        {
            let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(StoreError::from)?;
            if read::<StoredAutomationGrant>(&tx, GRANT, grant_id)?.as_ref() != Some(&previous) {
                return Err(StoreError::RevisionConflict.into());
            }
            if action == AutomationGrantAction::Activate {
                current_account(&tx, &value.terms.account_id, value.terms.writer_epoch)?;
                let account =
                    read::<StoredAutomationAccount>(&tx, ACCOUNT, &value.terms.account_id)?
                        .ok_or(StoreError::NotFound)?;
                value.terms.validate(&account.policy)?;
                if now < account.policy.valid_from_ms || now >= account.policy.expires_at_ms {
                    return Err(AutomationError::NotActive);
                }
            }
            write(&tx, GRANT, grant_id, value.revision, &value, now)?;
            audit(
                &tx,
                GRANT,
                grant_id,
                value.revision,
                match action {
                    AutomationGrantAction::Activate => "automation.grant_activated",
                    AutomationGrantAction::Pause => "automation.grant_paused",
                    AutomationGrantAction::Revoke => "automation.grant_revoked",
                    AutomationGrantAction::ObserveExpiry => "automation.grant_expired",
                },
                &value,
                now,
            )?;
            let fresh_now = checked_now(trust, now)?;
            if action == AutomationGrantAction::Activate && fresh_now >= value.terms.expires_at_ms {
                return Err(AutomationError::NotActive);
            }
            lease.check_current(&review, fresh_now)?;
            advance_clock(&tx, review.account_id(), fresh_now)?;
            tx.commit().map_err(StoreError::from)?;
        }
        post_commit(trust, &lease, &review, now)?;
        Ok(value)
    }

    /// Exactly one callback attempt per immutable authorization ID. Durable
    /// exposure and the complete audit binding precede that callback atomically.
    /// Replay never calls the authorizer, even after revoke, expiry or recovery.
    pub fn authorize_automatically<T: AutomationTrustSource, A: AutomaticAuthorizer>(
        &self,
        grant_id: &str,
        request: AutomationRequest,
        trust: &T,
        authorizer: &mut A,
    ) -> Result<AutomaticAuthorizationReceipt> {
        protected(self)?;
        let request_digest =
            request_digest(&serde_json::to_value(&request).map_err(StoreError::from)?)?;
        if let Some(record) = self.automatic_authorization(&request.authorization_id)? {
            if record.grant_id != grant_id
                || record.request_digest != request_digest
                || record.request != request
            {
                return Err(StoreError::IdempotencyConflict.into());
            }
            let exposure = self
                .exposure(&request.authorization_id)?
                .ok_or(StoreError::RecoveryRequired)?;
            return Ok(AutomaticAuthorizationReceipt {
                record,
                exposure,
                replayed: true,
            });
        }
        let grant = self
            .automation_grant(grant_id)?
            .ok_or(StoreError::NotFound)?;
        let account = self
            .automation_account(&grant.terms.account_id)?
            .ok_or(StoreError::NotFound)?;
        if trust.verifier_id() != grant.terms.verifier_id
            || authorizer.signer_id() != grant.terms.signer_id
        {
            return Err(AutomationError::Denied);
        }
        let review = AutomationReview::Authorize {
            account: Box::new(account.clone()),
            grant: Box::new(grant.clone()),
            request: Box::new(request.clone()),
        };
        let lease = trust.acquire(&review)?;
        let now = checked_now(trust, grant.updated_at_ms.max(account.updated_at_ms))?;
        lease.check_current(&review, now)?;
        if grant.status != AutomationGrantStatus::Active {
            return Err(AutomationError::NotActive);
        }
        evaluate_automation_request(&account.policy, &grant.terms, &request, now)?;
        let mut record = AutomaticAuthorizationRecord {
            grant_id: grant_id.to_owned(),
            grant_revision: grant.revision,
            account_policy_id: account.policy.policy_id.clone(),
            request_digest,
            request,
            original_activation_consent_reference: grant
                .original_activation_consent_reference
                .clone()
                .ok_or(AutomationError::Denied)?,
            active_consent_reference: grant
                .current_activation_consent_reference
                .clone()
                .ok_or(AutomationError::Denied)?,
            authorization_verification_reference: consent(&lease)?,
            outcome: AutomaticAuthorizationOutcome::Unknown,
            created_at_ms: now,
            updated_at_ms: now,
        };
        let exposure;
        {
            let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(StoreError::from)?;
            if read::<StoredAutomationGrant>(&tx, GRANT, grant_id)?.as_ref() != Some(&grant)
                || read::<StoredAutomationAccount>(&tx, ACCOUNT, &grant.terms.account_id)?.as_ref()
                    != Some(&account)
            {
                return Err(StoreError::RevisionConflict.into());
            }
            if read::<AutomaticAuthorizationRecord>(
                &tx,
                AUTHORIZATION,
                &record.request.authorization_id,
            )?
            .is_some()
            {
                return Err(StoreError::IdempotencyConflict.into());
            }
            // An authorization ID already in the manual ledger cannot be adopted
            // into an automatic callback, even if its economic fields match.
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM authority_exposures WHERE authorization_id=?1)",
                    [&record.request.authorization_id],
                    |r| r.get(0),
                )
                .map_err(StoreError::from)?;
            if exists {
                return Err(StoreError::IdempotencyConflict.into());
            }
            let outstanding = grant_outstanding(&tx, grant_id)?;
            if outstanding + record.request.maximum_debit.as_zatoshis() as u128
                > grant.terms.maximum_outstanding_debit.as_zatoshis() as u128
            {
                return Err(StoreError::BudgetExceeded.into());
            }
            let fresh_now = checked_now(trust, now)?;
            evaluate_automation_request(&account.policy, &grant.terms, &record.request, fresh_now)?;
            lease.check_current(&review, fresh_now)?;
            advance_clock(&tx, review.account_id(), fresh_now)?;
            let count: u64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM records WHERE aggregate_type=?1",
                    [AUTHORIZATION],
                    |r| r.get(0),
                )
                .map_err(StoreError::from)?;
            if count >= MAX_AUTHORIZATION_RECORDS {
                return Err(StoreError::ResourceExhausted.into());
            }
            let r = &record.request;
            let intent = ReleaseIntent {
                authorization_id: r.authorization_id.clone(),
                account_id: r.account_id.clone(),
                writer_epoch: r.writer_epoch,
                obligation_id: r.obligation_id.clone(),
                proposal_id: r.proposal_id.clone(),
                manifest_digest: r.manifest_digest.clone(),
                effects_digest: r.effects_digest.clone(),
                artifact_digest: r.artifact_digest.clone(),
                maximum_debit: r.maximum_debit.as_zatoshis().to_string(),
                input_ids: r.input_ids.clone(),
                aggregate_budget_limit: account
                    .policy
                    .maximum_outstanding_debit
                    .as_zatoshis()
                    .to_string(),
            };
            exposure = crate::authority::record_release_intent_in_transaction(
                &tx,
                &intent,
                fresh_now as i64,
            )?;
            write(
                &tx,
                AUTHORIZATION,
                &r.authorization_id,
                1,
                &record,
                fresh_now,
            )?;
            audit(
                &tx,
                AUTHORIZATION,
                &r.authorization_id,
                1,
                "automation.authorization_intent_recorded",
                &record,
                fresh_now,
            )?;
            tx.commit().map_err(StoreError::from)?;
        }
        let fresh_now =
            checked_now(trust, now).map_err(|_| AutomationError::AuthorizationUncertain)?;
        evaluate_automation_request(&account.policy, &grant.terms, &record.request, fresh_now)
            .map_err(|_| AutomationError::AuthorizationUncertain)?;
        lease
            .check_current(&review, fresh_now)
            .map_err(|_| AutomationError::AuthorizationUncertain)?;
        if trust.verifier_id() != grant.terms.verifier_id
            || authorizer.signer_id() != grant.terms.signer_id
        {
            return Err(AutomationError::AuthorizationUncertain);
        }
        let point_of_use = || {
            let now = checked_now(trust, fresh_now)?;
            evaluate_automation_request(&account.policy, &grant.terms, &record.request, now)?;
            lease.check_current(&review, now)?;
            if trust.verifier_id() != grant.terms.verifier_id {
                return Err(AutomationError::Denied);
            }
            let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
            current_account(&c, &grant.terms.account_id, grant.terms.writer_epoch)?;
            if read::<StoredAutomationGrant>(&c, GRANT, grant_id)?.as_ref() != Some(&grant)
                || read::<StoredAutomationAccount>(&c, ACCOUNT, &grant.terms.account_id)?.as_ref()
                    != Some(&account)
            {
                return Err(AutomationError::Denied);
            }
            if read::<u64>(&c, CLOCK, &grant.terms.account_id)?.is_some_and(|old| now < old) {
                return Err(AutomationError::ClockInvalid);
            }
            Ok(())
        };
        point_of_use().map_err(|_| AutomationError::AuthorizationUncertain)?;
        record.outcome = authorizer
            .authorize_exact(PreparedAutomaticAuthorization {
                record: &record,
                check_current: &point_of_use,
            })
            .unwrap_or(AutomaticAuthorizationOutcome::Unknown);
        let completed_at =
            checked_now(trust, fresh_now).map_err(|_| AutomationError::AuthorizationUncertain)?;
        record.updated_at_ms = completed_at;
        {
            let mut c = self
                .connection
                .lock()
                .map_err(|_| AutomationError::AuthorizationUncertain)?;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| AutomationError::AuthorizationUncertain)?;
            advance_clock(&tx, review.account_id(), completed_at)
                .map_err(|_| AutomationError::AuthorizationUncertain)?;
            write(
                &tx,
                AUTHORIZATION,
                &record.request.authorization_id,
                2,
                &record,
                completed_at,
            )
            .map_err(|_| AutomationError::AuthorizationUncertain)?;
            audit(
                &tx,
                AUTHORIZATION,
                &record.request.authorization_id,
                2,
                "automation.authorization_callback_observed",
                &record,
                completed_at,
            )
            .map_err(|_| AutomationError::AuthorizationUncertain)?;
            tx.commit()
                .map_err(|_| AutomationError::AuthorizationUncertain)?;
        }
        // Outcome persistence never clears or downgrades exposure. Even a
        // callback error/decline can be ambiguous at an external signer.
        Ok(AutomaticAuthorizationReceipt {
            record,
            exposure,
            replayed: false,
        })
    }

    pub fn automation_account(&self, account_id: &str) -> Result<Option<StoredAutomationAccount>> {
        protected(self)?;
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(read(&c, ACCOUNT, account_id)?)
    }
    pub fn automation_grant(&self, grant_id: &str) -> Result<Option<StoredAutomationGrant>> {
        protected(self)?;
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(read(&c, GRANT, grant_id)?)
    }
    pub fn automation_grants(&self, account_id: &str) -> Result<Vec<StoredAutomationGrant>> {
        protected(self)?;
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(grants(&c, account_id)?)
    }
    pub fn automatic_authorization(
        &self,
        authorization_id: &str,
    ) -> Result<Option<AutomaticAuthorizationRecord>> {
        protected(self)?;
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(read(&c, AUTHORIZATION, authorization_id)?)
    }
}

fn advance_clock(c: &Connection, account_id: &str, now: u64) -> Result<()> {
    if read::<u64>(c, CLOCK, account_id)?.is_some_and(|old| now < old) {
        return Err(AutomationError::ClockInvalid);
    }
    write(c, CLOCK, account_id, 1, &now, now)?;
    Ok(())
}
fn protected(store: &Store) -> Result<()> {
    // Restored grants and authorization snapshots remain historical. A successor
    // needs a separately wired, fresh automation enrollment protocol before this
    // runtime may expose any saved active grant as operational.
    if store.protection() != StorageProtection::Encrypted || store.recovered_generation {
        return Err(AutomationError::Unavailable);
    }
    Ok(())
}
fn checked_now<T: AutomationTrustSource>(trust: &T, minimum: u64) -> Result<u64> {
    let now = trust.now_ms()?;
    if now < minimum || now > i64::MAX as u64 {
        return Err(AutomationError::ClockInvalid);
    }
    Ok(now)
}
fn consent<L: AutomationLease>(lease: &L) -> Result<String> {
    crate::validate_id(lease.consent_reference())?;
    Ok(lease.consent_reference().to_owned())
}
fn post_commit<T: AutomationTrustSource>(
    trust: &T,
    lease: &T::Lease,
    review: &AutomationReview,
    now: u64,
) -> Result<()> {
    let now = checked_now(trust, now).map_err(|_| AutomationError::StateMayHaveChanged)?;
    lease
        .check_current(review, now)
        .map_err(|_| AutomationError::StateMayHaveChanged)
}
fn read<T: DeserializeOwned>(c: &Connection, kind: &str, id: &str) -> crate::Result<Option<T>> {
    let payload: Option<String> = c
        .query_row(
            "SELECT payload FROM records WHERE aggregate_type=?1 AND id=?2",
            params![kind, id],
            |r| r.get(0),
        )
        .optional()?;
    payload
        .map(|p| serde_json::from_str(&p).map_err(StoreError::from))
        .transpose()
}
fn write<T: Serialize>(
    c: &Connection,
    kind: &str,
    id: &str,
    revision: u64,
    value: &T,
    now: u64,
) -> crate::Result<()> {
    let payload = encode(&serde_json::to_value(value)?)?;
    let revision = i64::try_from(revision).map_err(|_| StoreError::ResourceExhausted)?;
    c.execute("INSERT INTO records(aggregate_type,id,revision,payload,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?5) ON CONFLICT(aggregate_type,id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload,updated_at_ms=excluded.updated_at_ms", params![kind,id,revision,payload,now as i64])?;
    Ok(())
}
fn audit<T: Serialize>(
    c: &Connection,
    kind: &str,
    id: &str,
    revision: u64,
    event: &str,
    value: &T,
    now: u64,
) -> crate::Result<()> {
    let payload = encode(&serde_json::to_value(value)?)?;
    c.execute("INSERT INTO events(aggregate_type,aggregate_id,aggregate_revision,kind,payload,operation_id,occurred_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![kind,id,revision as i64,event,payload,format!("{kind}:{id}:{revision}"),now as i64])?;
    Ok(())
}
fn current_account(c: &Connection, account_id: &str, epoch: u64) -> crate::Result<()> {
    if crate::backup::read_recovery_state(c)?.recovery_required {
        return Err(StoreError::RecoveryRequired);
    }
    let value: Option<(u64, bool)> = c
        .query_row(
            "SELECT writer_epoch,recovery_required FROM authority_accounts WHERE account_id=?1",
            [account_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (stored_epoch, recovery) = value.ok_or(StoreError::NotFound)?;
    if recovery {
        return Err(StoreError::RecoveryRequired);
    }
    if stored_epoch != epoch {
        return Err(StoreError::WriterEpochMismatch);
    }
    Ok(())
}
fn grants(c: &Connection, account_id: &str) -> crate::Result<Vec<StoredAutomationGrant>> {
    let mut q = c.prepare("SELECT payload FROM records WHERE aggregate_type=?1 ORDER BY id")?;
    let mut result = Vec::new();
    for row in q.query_map([GRANT], |r| r.get::<_, String>(0))? {
        let grant: StoredAutomationGrant = serde_json::from_str(&row?)?;
        if grant.terms.account_id == account_id {
            result.push(grant);
        }
    }
    Ok(result)
}
fn grant_outstanding(c: &Connection, grant_id: &str) -> crate::Result<u128> {
    let mut q = c.prepare("SELECT r.payload,e.maximum_debit FROM records r JOIN authority_exposures e ON e.authorization_id=r.id WHERE r.aggregate_type=?1 AND e.state IN('authorized_locally','released','outstanding_uncertain','expired_observed','conflicted_observed')")?;
    let mut total = 0u128;
    for row in q.query_map([AUTHORIZATION], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })? {
        let (payload, debit) = row?;
        let record: AutomaticAuthorizationRecord = serde_json::from_str(&payload)?;
        if record.grant_id == grant_id {
            let debit = debit
                .parse::<u64>()
                .map_err(|_| StoreError::RecoveryRequired)?;
            total = total
                .checked_add(debit as u128)
                .ok_or(StoreError::BudgetExceeded)?;
        }
    }
    Ok(total)
}
/// Also enforced by the existing manually reviewed ledger path. No request may
/// silently select a larger account-wide ceiling than the retained policy.
pub(crate) fn account_budget_ceiling(
    c: &Connection,
    account_id: &str,
) -> crate::Result<Option<u64>> {
    read::<StoredAutomationAccount>(c, ACCOUNT, account_id)?
        .map(|r| {
            r.policy
                .validate()
                .map_err(|_| StoreError::RecoveryRequired)?;
            if r.policy.account_id != account_id {
                return Err(StoreError::RecoveryRequired);
            }
            Ok(r.policy.maximum_outstanding_debit.as_zatoshis())
        })
        .transpose()
}

#[cfg(all(test, target_os = "linux"))]
#[path = "automation_tests.rs"]
mod tests;
