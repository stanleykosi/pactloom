//! Inert exact intent for born-account manual enrollment. These data formats
//! neither authenticate their sender nor create native, signer or Store authority.
use crate::{CoreError, ErrorCode, Result, proposal::canonical_digest};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualAccountIdentity {
    pub account_id: String,
    pub full_viewing_key_digest: String,
    pub network_profile_id: String,
    pub derivation_domain: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualHostGenerationBinding {
    pub generation_id: String,
    pub inventory_digest: String,
    pub generation_plan_digest: String,
    pub financial_journal_origin_digest: String,
    pub store_destination_identity: String,
    pub profile_id: String,
    pub canonical_root: String,
    pub destination_identity_digest: String,
    pub inherited_identity_digest: String,
    pub scope_predecessor_digest: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Original first-enrollment audit values. Every action independently checks
/// the current certificate, writer epoch/session and witness state.
pub struct BornManualSignerBinding {
    pub enrollment_generation_id: String,
    pub signer_target_digest: String,
    pub original_envelope_digest: String,
    pub owner_certificate_digest: String,
    pub writer_certificate_digest: String,
    pub writer_epoch: u64,
    pub native_signer_measurement: String,
}
/// One exact new obligation in one explicitly shared privacy domain. This cap
/// is checked against the SAME account-wide lifetime ledger; never a new budget.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornManualScope {
    pub agreement_id: String,
    pub obligation_id: String,
    pub participant_id: String,
    pub principal_id: String,
    pub privacy_domain: String,
    pub recipient_scope_digests: Vec<String>,
    pub aggregate_budget_zatoshis: u64,
    pub per_operation_limit_zatoshis: u64,
    pub maximum_fee_share_zatoshis: u64,
    pub maximum_transaction_fee_zatoshis: u64,
    pub maximum_permit_lifetime_ms: u64,
    pub expires_at_ms: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornManualEnrollmentTerms {
    pub version: u16,
    pub operation_id: String,
    pub identity: ManualAccountIdentity,
    pub birth_request_digest: String,
    pub birth_commit_digest: String,
    pub native_birth_digest: String,
    pub original_policy_digest: String,
    pub account_use_genesis_digest: String,
    pub original_witness_origin_digest: String,
    pub host: ManualHostGenerationBinding,
    pub signer: BornManualSignerBinding,
    pub scope: BornManualScope,
    /// Observed actual paired process/channel commitment, not a caller success flag.
    pub transport_binding_digest: String,
    pub issued_at_ms: u64,
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid exact manual enrollment intent",
    )
}
fn text(value: &str, limit: usize) -> Result<()> {
    if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}
impl BornManualEnrollmentTerms {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.issued_at_ms == 0 || self.signer.writer_epoch == 0 {
            return Err(invalid());
        }
        for value in [
            &self.operation_id,
            &self.identity.network_profile_id,
            &self.identity.derivation_domain,
            &self.host.profile_id,
            &self.scope.agreement_id,
            &self.scope.obligation_id,
            &self.scope.participant_id,
            &self.scope.principal_id,
            &self.scope.privacy_domain,
        ] {
            text(value, 256)?;
        }
        text(&self.host.canonical_root, 4096)?;
        text(&self.host.store_destination_identity, 4096)?;
        if !self.host.canonical_root.starts_with('/')
            || self.host.canonical_root == "/"
            || self.host.canonical_root.ends_with('/')
            || self
                .host
                .canonical_root
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err(invalid());
        }
        for value in [
            &self.identity.account_id,
            &self.identity.full_viewing_key_digest,
            &self.birth_request_digest,
            &self.birth_commit_digest,
            &self.native_birth_digest,
            &self.original_policy_digest,
            &self.account_use_genesis_digest,
            &self.original_witness_origin_digest,
            &self.host.generation_plan_digest,
            &self.host.financial_journal_origin_digest,
            &self.host.generation_id,
            &self.host.inventory_digest,
            &self.host.destination_identity_digest,
            &self.host.inherited_identity_digest,
            &self.signer.enrollment_generation_id,
            &self.signer.signer_target_digest,
            &self.signer.original_envelope_digest,
            &self.signer.owner_certificate_digest,
            &self.signer.writer_certificate_digest,
            &self.signer.native_signer_measurement,
            &self.transport_binding_digest,
        ] {
            hash(value)?;
        }
        if let Some(previous) = &self.host.scope_predecessor_digest {
            hash(previous)?;
        }
        let scope = &self.scope;
        if scope.recipient_scope_digests.is_empty()
            || scope.recipient_scope_digests.len() > 32
            || scope.aggregate_budget_zatoshis == 0
            || scope.per_operation_limit_zatoshis == 0
            || scope.per_operation_limit_zatoshis > scope.aggregate_budget_zatoshis
            || scope.aggregate_budget_zatoshis > crate::MAX_MONEY
            || scope.maximum_fee_share_zatoshis > scope.maximum_transaction_fee_zatoshis
            || scope.maximum_fee_share_zatoshis > scope.per_operation_limit_zatoshis
            || scope.maximum_transaction_fee_zatoshis > crate::MAX_MONEY
            || scope.maximum_permit_lifetime_ms == 0
            || scope.expires_at_ms <= self.issued_at_ms
            || scope.maximum_permit_lifetime_ms > scope.expires_at_ms - self.issued_at_ms
        {
            return Err(invalid());
        }
        let mut last: Option<&str> = None;
        for recipient in &scope.recipient_scope_digests {
            hash(recipient)?;
            if last.is_some_and(|p| p >= recipient.as_str()) {
                return Err(invalid());
            }
            last = Some(recipient);
        }
        if serde_json::to_vec(self).map_err(|_| invalid())?.len() > 32 * 1024 {
            return Err(invalid());
        }
        Ok(())
    }
    /// A stable commitment to inert data, never an enrollment capability.
    pub fn terms_digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:born-manual-enrollment-terms:v1", self)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BornManualAction {
    Construct,
    Prove,
    Authorize,
    RetainSignedResult,
    Dispatch,
    Observe,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornManualActionIntent {
    pub version: u16,
    pub enrollment_ref: String,
    pub candidate_id: String,
    pub proposal_id: String,
    pub manifest_digest: String,
    pub obligation_id: String,
    pub operation_id: String,
    pub idempotency_key_digest: String,
    pub input_set_digest: String,
    /// Canonical digest of the COMPLETE owning action request, including effects,
    /// selected destinations and provider policy where that action uses them.
    pub exact_request_digest: String,
    pub action: BornManualAction,
    pub invocation_nonce: String,
}
impl BornManualActionIntent {
    pub fn validate_for(
        &self,
        enrollment: &BornManualEnrollmentTerms,
        enrollment_ref: &str,
    ) -> Result<()> {
        hash(enrollment_ref)?;
        enrollment.validate()?;
        if self.version != 1
            || self.enrollment_ref != enrollment_ref
            || self.obligation_id != enrollment.scope.obligation_id
        {
            return Err(invalid());
        }
        for value in [
            &self.candidate_id,
            &self.proposal_id,
            &self.obligation_id,
            &self.operation_id,
        ] {
            text(value, 256)?;
        }
        for value in [
            &self.enrollment_ref,
            &self.manifest_digest,
            &self.idempotency_key_digest,
            &self.input_set_digest,
            &self.exact_request_digest,
            &self.invocation_nonce,
        ] {
            hash(value)?;
        }
        Ok(())
    }
    pub fn digest(
        &self,
        enrollment: &BornManualEnrollmentTerms,
        enrollment_ref: &str,
    ) -> Result<String> {
        self.validate_for(enrollment, enrollment_ref)?;
        canonical_digest("wholepact:born-manual-action-intent:v1", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(c: char) -> String {
        c.to_string().repeat(64)
    }
    fn terms() -> BornManualEnrollmentTerms {
        BornManualEnrollmentTerms {
            version: 1,
            operation_id: "synthetic-enrollment".into(),
            identity: ManualAccountIdentity {
                account_id: h('a'),
                full_viewing_key_digest: h('b'),
                network_profile_id: "synthetic-testnet".into(),
                derivation_domain: "dedicated-synthetic".into(),
            },
            birth_request_digest: h('c'),
            birth_commit_digest: h('d'),
            native_birth_digest: h('e'),
            original_policy_digest: h('f'),
            account_use_genesis_digest: h('1'),
            original_witness_origin_digest: h('2'),
            host: ManualHostGenerationBinding {
                generation_id: h('3'),
                inventory_digest: h('4'),
                generation_plan_digest: h('5'),
                financial_journal_origin_digest: h('6'),
                store_destination_identity: "/synthetic/host/coordination.sqlite".into(),
                profile_id: "synthetic-profile".into(),
                canonical_root: "/synthetic/host".into(),
                destination_identity_digest: h('7'),
                inherited_identity_digest: h('8'),
                scope_predecessor_digest: None,
            },
            signer: BornManualSignerBinding {
                enrollment_generation_id: h('9'),
                signer_target_digest: h('a'),
                original_envelope_digest: h('b'),
                owner_certificate_digest: h('c'),
                writer_certificate_digest: h('d'),
                writer_epoch: 1,
                native_signer_measurement: h('e'),
            },
            scope: BornManualScope {
                agreement_id: "synthetic-agreement".into(),
                obligation_id: "synthetic-obligation".into(),
                participant_id: "synthetic-participant".into(),
                principal_id: "synthetic-principal".into(),
                privacy_domain: "synthetic-domain".into(),
                recipient_scope_digests: vec![h('f')],
                aggregate_budget_zatoshis: 100,
                per_operation_limit_zatoshis: 50,
                maximum_fee_share_zatoshis: 2,
                maximum_transaction_fee_zatoshis: 200,
                maximum_permit_lifetime_ms: 500,
                expires_at_ms: 2000,
            },
            transport_binding_digest: h('1'),
            issued_at_ms: 1000,
        }
    }
    #[test]
    fn stable_terms_are_inert_and_bind_all_original_and_target_fields() {
        let original = terms();
        original.validate().unwrap();
        let digest = original.terms_digest().unwrap();
        let mut changed = original.clone();
        changed.host.generation_id = h('a');
        assert_ne!(digest, changed.terms_digest().unwrap());
        changed = original.clone();
        changed.identity.full_viewing_key_digest = h('f');
        assert_ne!(digest, changed.terms_digest().unwrap());
        changed = original.clone();
        changed.scope.principal_id = "other-native-recipient".into();
        assert_ne!(digest, changed.terms_digest().unwrap());
        changed = original;
        changed.host.scope_predecessor_digest = Some(h('a'));
        assert_ne!(digest, changed.terms_digest().unwrap());
    }
    #[test]
    fn unknown_approval_automation_and_version_fields_do_not_upgrade_terms() {
        let mut value = serde_json::to_value(terms()).unwrap();
        value["approved"] = serde_json::json!(true);
        assert!(serde_json::from_value::<BornManualEnrollmentTerms>(value).is_err());
        let mut value = serde_json::to_value(terms()).unwrap();
        value["scope"]["automation"] = serde_json::json!(true);
        assert!(serde_json::from_value::<BornManualEnrollmentTerms>(value).is_err());
        let mut bad = terms();
        bad.version = 2;
        assert!(bad.validate().is_err());
    }
    #[test]
    fn financial_scope_uses_integer_limits_and_does_not_duplicate_recipients() {
        let mut bad = terms();
        bad.scope.per_operation_limit_zatoshis = 101;
        assert!(bad.validate().is_err());
        bad = terms();
        bad.scope.aggregate_budget_zatoshis = crate::MAX_MONEY + 1;
        assert!(bad.validate().is_err());
        bad = terms();
        bad.scope.recipient_scope_digests.push(h('f'));
        assert!(bad.validate().is_err());
        bad = terms();
        bad.scope.maximum_fee_share_zatoshis = 51;
        assert!(bad.validate().is_err());
        // Total transaction fee may exceed this participant's own debit limit;
        // only the participant's allocated fee share is charged to its account.
        terms().validate().unwrap();
    }
    #[test]
    fn exact_target_rejects_traversal_aliases_and_missing_provenance() {
        for root in [
            "relative",
            "/",
            "/synthetic/../host",
            "/synthetic/./host",
            "/synthetic//host",
        ] {
            let mut bad = terms();
            bad.host.canonical_root = root.into();
            assert!(bad.validate().is_err());
        }
        let mut bad = terms();
        bad.original_witness_origin_digest.clear();
        assert!(bad.validate().is_err());
        bad = terms();
        bad.account_use_genesis_digest = "unknown".into();
        assert!(bad.validate().is_err());
    }
    #[test]
    fn original_time_is_committed_and_elapsed_scope_is_not_extended_by_parsing() {
        let mut bad = terms();
        bad.scope.expires_at_ms = bad.issued_at_ms;
        assert!(bad.validate().is_err());
        bad = terms();
        bad.scope.maximum_permit_lifetime_ms = 1001;
        assert!(bad.validate().is_err());
        let original = terms();
        let digest = original.terms_digest().unwrap();
        let parsed: BornManualEnrollmentTerms =
            serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
        assert_eq!(digest, parsed.terms_digest().unwrap());
        assert_eq!(parsed.issued_at_ms, 1000);
    }
    #[test]
    fn action_intent_requires_exact_enrollment_obligation_request_and_no_automation_variant() {
        let terms = terms();
        let reference = h('a');
        let mut action = BornManualActionIntent {
            version: 1,
            enrollment_ref: reference.clone(),
            candidate_id: "candidate".into(),
            proposal_id: "proposal".into(),
            manifest_digest: h('b'),
            obligation_id: terms.scope.obligation_id.clone(),
            operation_id: "operation".into(),
            idempotency_key_digest: h('c'),
            input_set_digest: h('d'),
            exact_request_digest: h('e'),
            action: BornManualAction::Construct,
            invocation_nonce: h('f'),
        };
        action.validate_for(&terms, &reference).unwrap();
        let digest = action.digest(&terms, &reference).unwrap();
        action.exact_request_digest = h('1');
        assert_ne!(digest, action.digest(&terms, &reference).unwrap());
        action.obligation_id = "inherited-other-obligation".into();
        assert!(action.validate_for(&terms, &reference).is_err());
        assert!(serde_json::from_str::<BornManualAction>("\"automation\"").is_err());
    }
}
