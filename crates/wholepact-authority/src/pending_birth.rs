//! Source foundation: pending-birth enrollment bindings. These are audit/request data,
//! never native approval, key freshness proof, or witness creation capability.
use crate::account_use_link::account_use_witness_origin_digest;
use crate::{AccountPolicy, AuthorityError, Result, WitnessDisclosureDescriptor, digest, hash, id};
use serde::{Deserialize, Serialize};

/// Public request exported only after genuine pending-vault review. The receiving
/// witness separately authenticates the exact owner and confirms local enrollment.
/// Deserialization cannot authenticate any of these statements.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingBirthRequest {
    pub version: u16,
    pub operation_id: String,
    pub generation_instance_id: String,
    pub native_birth_digest: String,
    pub original_terms_digest: String,
    pub original_target_digest: String,
    pub disclosure: WitnessDisclosureDescriptor,
    pub policy: AccountPolicy,
    pub issued_at_ms: u64,
    pub initial_commit_deadline_ms: u64,
}
impl PendingBirthRequest {
    pub fn validate(&self) -> Result<()> {
        id(&self.operation_id)?;
        for value in [
            &self.generation_instance_id,
            &self.native_birth_digest,
            &self.original_terms_digest,
            &self.original_target_digest,
        ] {
            hash(value)?;
        }
        self.disclosure.validate()?;
        self.policy.validate()?;
        let genesis = self
            .policy
            .account_use_genesis
            .as_ref()
            .ok_or(AuthorityError::InvalidBinding)?;
        genesis.validate()?;
        if self.version != 1
            || self.issued_at_ms == 0
            || self.initial_commit_deadline_ms <= self.issued_at_ms
            || self.initial_commit_deadline_ms - self.issued_at_ms > 300_000
            || self.initial_commit_deadline_ms > self.policy.policy_expires_at_ms
            || self.disclosure.policy_digest != self.policy.policy_digest()?
            || self.disclosure.account_id != self.policy.account_id
            || self.disclosure.network_profile_id != self.policy.network_profile_id
            || self.disclosure.witness_id != self.policy.witness_id
            || genesis.identity.account_id != self.policy.account_id
            || genesis.identity.network_profile_id != self.policy.network_profile_id
            || genesis.witness_id != self.policy.witness_id
            || genesis.owner_certificate_digest != self.policy.owner_certificate_digest
            || genesis.native_birth_digest != self.native_birth_digest
            || genesis.witness_origin_digest != account_use_witness_origin_digest(&self.disclosure)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut original = self.policy.clone();
        original.account_use_genesis = None;
        if self.original_terms_digest
            != wholepact_core::proposal::canonical_digest(
                "wholepact:account-birth-original-policy-terms:v1",
                &original,
            )
            .map_err(|_| AuthorityError::InvalidBinding)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:pending-account-birth-request:v1", self)
    }
    /// Time check for first creation only. A matching existing immutable record
    /// can be inspected after expiry, but that historical read grants no authority.
    pub fn require_initial_commit_time(&self, now_ms: u64) -> Result<()> {
        self.validate()?;
        if now_ms < self.issued_at_ms || now_ms >= self.initial_commit_deadline_ms {
            return Err(AuthorityError::Permission);
        }
        Ok(())
    }
}

/// Retained in the witness's genesis transaction. All fields describe historical
/// authentication; this serializable record is deliberately not a creation token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingBirthCommitRecord {
    pub version: u16,
    pub request: PendingBirthRequest,
    pub request_digest: String,
    pub authenticated_owner_certificate_digest: String,
    pub owner_approval_evidence_digest: String,
    pub local_target_digest: String,
    pub local_owner_review_digest: String,
    pub committed_at_ms: u64,
}
impl PendingBirthCommitRecord {
    pub fn validate(&self) -> Result<()> {
        self.request
            .require_initial_commit_time(self.committed_at_ms)?;
        hash(&self.owner_approval_evidence_digest)?;
        hash(&self.local_target_digest)?;
        hash(&self.local_owner_review_digest)?;
        if self.version != 1
            || self.request_digest != self.request.digest()?
            || self.authenticated_owner_certificate_digest
                != self.request.policy.owner_certificate_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    /// Exact idempotency comparison only, never reauthentication. A changed
    /// deadline is also a changed request. A re-review requires an explicit later
    /// protocol, not rewriting this immutable original.
    pub fn require_exact_retry(&self, request: &PendingBirthRequest) -> Result<()> {
        self.validate()?;
        request.validate()?;
        if &self.request != request || self.request_digest != request.digest()? {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_use::{AccountUseGenesis, AccountUseIdentity};
    fn h(c: char) -> String {
        c.to_string().repeat(64)
    }
    fn request() -> PendingBirthRequest {
        let mut policy = AccountPolicy {
            account_use_genesis: None,
            witness_id: "test-witness".into(),
            account_id: h('1'),
            network_profile_id: "test-network".into(),
            owner_certificate_digest: h('2'),
            initial_writer_certificate_digest: h('3'),
            initial_writer_epoch: 1,
            enrollment_refs: vec![h('c')],
            agreement_ids: vec!["manual-only".into()],
            recipient_scope_digests: vec![h('4')],
            aggregate_budget_zatoshis: 100,
            per_operation_limit_zatoshis: 100,
            maximum_fee_share_zatoshis: 5,
            maximum_transaction_fee_zatoshis: 5,
            maximum_permit_lifetime_ms: 1000,
            policy_expires_at_ms: 100_000,
        };
        let terms = wholepact_core::proposal::canonical_digest(
            "wholepact:account-birth-original-policy-terms:v1",
            &policy,
        )
        .unwrap();
        let mut disclosure = WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:1911".into(),
            server_name: "localhost".into(),
            witness_id: policy.witness_id.clone(),
            account_id: policy.account_id.clone(),
            network_profile_id: policy.network_profile_id.clone(),
            policy_digest: h('0'),
            pinned_server_certificate_digest: h('5'),
        };
        policy.account_use_genesis = Some(AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: policy.account_id.clone(),
                full_viewing_key_digest: h('6'),
                network_profile_id: policy.network_profile_id.clone(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: policy.witness_id.clone(),
            witness_origin_digest: account_use_witness_origin_digest(&disclosure).unwrap(),
            owner_certificate_digest: policy.owner_certificate_digest.clone(),
            native_birth_digest: h('7'),
        });
        disclosure.policy_digest = policy.policy_digest().unwrap();
        PendingBirthRequest {
            version: 1,
            operation_id: "birth-test-operation".into(),
            generation_instance_id: h('8'),
            native_birth_digest: h('7'),
            original_terms_digest: terms,
            original_target_digest: h('9'),
            disclosure,
            policy,
            issued_at_ms: 1000,
            initial_commit_deadline_ms: 2000,
        }
    }
    #[test]
    fn request_binds_full_original_terms_and_origin() {
        let r = request();
        r.validate().unwrap();
        let mut changed = r.clone();
        changed.policy.aggregate_budget_zatoshis += 1;
        changed.disclosure.policy_digest = changed.policy.policy_digest().unwrap();
        assert!(changed.validate().is_err());
        let mut changed = r.clone();
        changed.disclosure.endpoint = "127.0.0.1:1912".into();
        assert!(changed.validate().is_err());
        let mut changed = r;
        changed.policy.account_use_genesis = None;
        assert!(changed.validate().is_err());
    }
    #[test]
    fn request_freshness_is_initial_commit_only_and_exact_retry_never_remints() {
        let r = request();
        assert!(r.require_initial_commit_time(999).is_err());
        r.require_initial_commit_time(1000).unwrap();
        assert!(r.require_initial_commit_time(2000).is_err());
        let record = PendingBirthCommitRecord {
            version: 1,
            request_digest: r.digest().unwrap(),
            authenticated_owner_certificate_digest: r.policy.owner_certificate_digest.clone(),
            owner_approval_evidence_digest: h('a'),
            local_target_digest: h('d'),
            local_owner_review_digest: h('e'),
            committed_at_ms: 1500,
            request: r.clone(),
        };
        record.require_exact_retry(&r).unwrap();
        let mut changed = r;
        changed.initial_commit_deadline_ms += 1;
        assert!(record.require_exact_retry(&changed).is_err());
        let mut changed = record;
        changed.authenticated_owner_certificate_digest = h('b');
        assert!(changed.validate().is_err());
    }
    #[test]
    fn parsed_record_is_only_audit_and_unknown_fields_are_rejected() {
        let r = request();
        let mut value = serde_json::to_value(&r).unwrap();
        value["approved"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PendingBirthRequest>(value).is_err());
        // There is intentionally no conversion from this DTO to creation,
        // signing, dispatch, native owner, or active-vault authority.
    }
}
