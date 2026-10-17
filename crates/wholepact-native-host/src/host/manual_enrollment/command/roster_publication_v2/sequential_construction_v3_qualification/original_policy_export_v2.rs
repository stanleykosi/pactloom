//! Strict DATA adapter for the actual retained signer's original policy export.
//! This fixture-only envelope mirrors OriginalRecipientPolicyExportV2, not a
//! native owner. Its complete anchor/commit checks precede any projection;
//! current account/owner matching remains at the caller after this historical read.
use crate::{Error, Result};
use wholepact_authority::pending_birth::PendingBirthCommitRecord;
use wholepact_core::born_policy_origin_v2::BornRecipientPolicyOriginV2;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalPolicyExportV2 {
    version: u16,
    anchor: BornRecipientPolicyOriginV2,
    original_birth_commit: PendingBirthCommitRecord,
}
impl OriginalPolicyExportV2 {
    fn validate(&self) -> Result<()> {
        // Same complete validation contract as the maintained signer export:
        // account/birth/recipient_policy_v2.rs::OriginalRecipientPolicyExportV2.
        if self.version != 2 {
            return Err(Error::Invalid);
        }
        self.anchor.validate().map_err(|_| Error::Invalid)?;
        let request = &self.original_birth_commit.request;
        if self.anchor.birth_digest != request.native_birth_digest
            || self.anchor.intent.operation_id != request.operation_id
            || self.anchor.intent.generation_instance_id != request.generation_instance_id
            || self.anchor.intent.original_policy_terms_digest != request.original_terms_digest
        {
            return Err(Error::Authentication);
        }
        // Checks the original commit time, NOT present wall time. Historical
        // parsing cannot renew the original publication or create authority.
        self.original_birth_commit
            .validate()
            .map_err(|_| Error::Invalid)
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<BornRecipientPolicyOriginV2> {
    let envelope: OriginalPolicyExportV2 = serde_json::from_slice(bytes)?;
    envelope.validate()?;
    Ok(envelope.anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_authority::{
        AccountPolicy, WitnessDisclosureDescriptor,
        account_use::{AccountUseGenesis, AccountUseIdentity},
        account_use_link::account_use_witness_origin_digest,
        pending_birth::PendingBirthRequest,
    };
    use wholepact_core::{
        born_policy_origin_v2::{
            BornPolicyIdentityV2, BornPolicyOriginalTermsV2, BornPolicyWitnessOriginV2,
            BornRecipientPolicyBirthIntentV2,
        },
        born_recipient_policy_v2::{
            BornConstructionRecipientPolicyV2, BornOriginalLimitsV2, BornOwnReturnRuleV2,
            BornRecipientLimitV2,
        },
        proposal::canonical_digest,
    };

    fn h(c: char) -> String {
        c.to_string().repeat(64)
    }
    // Inert, producer-shaped historical data only. No native decision, key,
    // real signer, socket, witness installation or completed owner is created.
    fn fixture(generation: char) -> serde_json::Value {
        let limits = BornOriginalLimitsV2 {
            aggregate_budget_zatoshis: 100,
            per_operation_limit_zatoshis: 100,
            maximum_fee_share_zatoshis: 5,
            maximum_transaction_fee_zatoshis: 5,
            maximum_permit_lifetime_ms: 1000,
            policy_expires_at_ms: 100_000,
        };
        let recipient_policy = BornConstructionRecipientPolicyV2 {
            version: 2,
            account_id: h('1'),
            network_profile_id: "test-network".into(),
            agreement_id: "synthetic-agreement".into(),
            obligation_id: "synthetic-obligation".into(),
            participant_id: "synthetic-participant".into(),
            recipients: vec![BornRecipientLimitV2 {
                recipient_id: "synthetic-recipient".into(),
                address: "syntheticreceiver0001".into(),
                memo: None,
                instruction_provenance: "Inert historical test claim".into(),
                maximum_amount_zatoshis: 100,
            }],
            charges: vec![],
            original_limits: limits,
            own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
        };
        let mut policy = AccountPolicy {
            account_use_genesis: None,
            witness_id: "synthetic-witness".into(),
            account_id: recipient_policy.account_id.clone(),
            network_profile_id: recipient_policy.network_profile_id.clone(),
            owner_certificate_digest: h('2'),
            initial_writer_certificate_digest: h('3'),
            initial_writer_epoch: 1,
            enrollment_refs: vec![h('c')],
            agreement_ids: vec![recipient_policy.agreement_id.clone()],
            recipient_scope_digests: vec![recipient_policy.digest().unwrap()],
            aggregate_budget_zatoshis: 100,
            per_operation_limit_zatoshis: 100,
            maximum_fee_share_zatoshis: 5,
            maximum_transaction_fee_zatoshis: 5,
            maximum_permit_lifetime_ms: 1000,
            policy_expires_at_ms: 100_000,
        };
        let original_policy_terms: BornPolicyOriginalTermsV2 =
            serde_json::from_value(serde_json::to_value(&policy).unwrap()).unwrap();
        let mut disclosure = WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:1911".into(),
            server_name: "localhost".into(),
            witness_id: policy.witness_id.clone(),
            account_id: policy.account_id.clone(),
            network_profile_id: policy.network_profile_id.clone(),
            policy_digest: h('0'),
            pinned_server_certificate_digest: h('5'),
        };
        let intent = BornRecipientPolicyBirthIntentV2 {
            version: 2,
            operation_id: format!("birth-{}", "a".repeat(32)),
            generation_instance_id: h(generation),
            identity: BornPolicyIdentityV2 {
                account_id: policy.account_id.clone(),
                full_viewing_key_digest: h('6'),
                network_profile_id: policy.network_profile_id.clone(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
                exact_derivation: "synthetic-exact-derivation".into(),
            },
            witness_origin: BornPolicyWitnessOriginV2 {
                endpoint: disclosure.endpoint.clone(),
                server_name: disclosure.server_name.clone(),
                witness_id: disclosure.witness_id.clone(),
                pinned_server_certificate_digest: disclosure
                    .pinned_server_certificate_digest
                    .clone(),
            },
            original_policy_terms_digest: original_policy_terms.digest().unwrap(),
            original_policy_terms,
            native_principal_id: "synthetic-principal".into(),
            native_measurement: h('7'),
            original_target: "/synthetic/original-target".into(),
        };
        let anchor = BornRecipientPolicyOriginV2 {
            version: 2,
            birth_digest: canonical_digest(
                "wholepact:native-account-birth-intent:v2",
                &(&intent, &recipient_policy),
            )
            .unwrap(),
            intent,
            recipient_policy,
        };
        anchor.validate().unwrap();
        policy.account_use_genesis = Some(AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: policy.account_id.clone(),
                full_viewing_key_digest: anchor.intent.identity.full_viewing_key_digest.clone(),
                network_profile_id: policy.network_profile_id.clone(),
                derivation_domain: anchor.intent.identity.derivation_domain.clone(),
            },
            witness_id: policy.witness_id.clone(),
            witness_origin_digest: account_use_witness_origin_digest(&disclosure).unwrap(),
            owner_certificate_digest: policy.owner_certificate_digest.clone(),
            native_birth_digest: anchor.birth_digest.clone(),
        });
        disclosure.policy_digest = policy.policy_digest().unwrap();
        let request = PendingBirthRequest {
            version: 1,
            operation_id: anchor.intent.operation_id.clone(),
            generation_instance_id: anchor.intent.generation_instance_id.clone(),
            native_birth_digest: anchor.birth_digest.clone(),
            original_terms_digest: anchor.intent.original_policy_terms_digest.clone(),
            original_target_digest: h('9'),
            disclosure,
            policy,
            issued_at_ms: 1000,
            initial_commit_deadline_ms: 2000,
        };
        let commit = PendingBirthCommitRecord {
            version: 1,
            request_digest: request.digest().unwrap(),
            authenticated_owner_certificate_digest: request.policy.owner_certificate_digest.clone(),
            request,
            owner_approval_evidence_digest: h('a'),
            local_target_digest: h('d'),
            local_owner_review_digest: h('e'),
            committed_at_ms: 1500,
        };
        commit.validate().unwrap();
        serde_json::json!({"version":2,"anchor":anchor,"original_birth_commit":commit})
    }

    #[test]
    fn producer_shaped_policy_envelope_projects_only_validated_original() {
        let envelope = fixture('8');
        let bytes = serde_json::to_vec_pretty(&envelope).unwrap();
        // This is the original consumer bug: the complete producer envelope is
        // deliberately not the bare anchor encoding.
        assert!(serde_json::from_slice::<BornRecipientPolicyOriginV2>(&bytes).is_err());
        let original = parse(&bytes).unwrap();
        let expected: BornRecipientPolicyOriginV2 =
            serde_json::from_value(envelope["anchor"].clone()).unwrap();
        assert!(original == expected);
        // Historical times remain exactly retained despite being long expired.
        assert_eq!(envelope["original_birth_commit"]["committed_at_ms"], 1500);
    }

    #[test]
    fn policy_envelope_rejects_individually_valid_substituted_originals() {
        let original = fixture('8');
        let other = fixture('9');
        assert!(parse(&serde_json::to_vec(&other).unwrap()).is_ok());
        for field in ["anchor", "original_birth_commit"] {
            let mut changed = original.clone();
            changed[field] = other[field].clone();
            assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut damaged = original;
        damaged["original_birth_commit"]["request_digest"] = serde_json::json!(h('f'));
        assert!(parse(&serde_json::to_vec(&damaged).unwrap()).is_err());
    }

    #[test]
    fn policy_envelope_refuses_bare_legacy_unknown_and_duplicate_fields() {
        let original = fixture('8');
        assert!(parse(&serde_json::to_vec(&original["anchor"]).unwrap()).is_err());
        for field in ["version", "unexpected"] {
            let mut changed = original.clone();
            changed[field] = serde_json::json!(1);
            assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut missing = original.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("original_birth_commit");
        assert!(parse(&serde_json::to_vec(&missing).unwrap()).is_err());
        let bytes = serde_json::to_string(&original).unwrap();
        let duplicate = bytes.replacen('{', "{\"version\":2,", 1);
        assert!(parse(duplicate.as_bytes()).is_err());
    }
}
