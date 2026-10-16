//! Explicit original V2 policy retention. V1 decoding does not learn optional
//! fields; each wire shape denies unknown fields independently. No historical
//! anchor, reopened vault or backup can be upgraded by attaching a descriptor.
use super::*;
use serde::{Deserializer, Serializer, de::Error as _};
use wholepact_core::born_recipient_policy_v2::{
    BornConstructionRecipientPolicyV2, BornOriginalLimitsV2,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAnchor {
    intent: BirthIntent,
    birth_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StableAnchor {
    version: u16,
    intent: BirthIntent,
    recipient_policy: BornConstructionRecipientPolicyV2,
    birth_digest: String,
}
impl Serialize for BirthAnchor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match &self.recipient_policy_v2 {
            None => LegacyAnchor {
                intent: self.intent.clone(),
                birth_digest: self.birth_digest.clone(),
            }
            .serialize(serializer),
            Some(policy) => StableAnchor {
                version: 2,
                intent: self.intent.clone(),
                recipient_policy: policy.clone(),
                birth_digest: self.birth_digest.clone(),
            }
            .serialize(serializer),
        }
    }
}
#[derive(Deserialize)]
#[serde(untagged)]
enum WireAnchor {
    Legacy(Box<LegacyAnchor>),
    Stable(Box<StableAnchor>),
}
impl<'de> Deserialize<'de> for BirthAnchor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        // Serde's struct decoders retain duplicate-field rejection. Do NOT
        // parse through serde_json::Value: it collapses repeated map keys.
        let anchor = match WireAnchor::deserialize(deserializer)? {
            WireAnchor::Legacy(old) => {
                let old = *old;
                if old.intent.version != 1 {
                    return Err(D::Error::custom("invalid legacy birth version"));
                }
                Self {
                    intent: old.intent,
                    birth_digest: old.birth_digest,
                    recipient_policy_v2: None,
                }
            }
            WireAnchor::Stable(new) => {
                let new = *new;
                if new.version != 2 || new.intent.version != 2 {
                    return Err(D::Error::custom("invalid stable birth version"));
                }
                Self {
                    intent: new.intent,
                    birth_digest: new.birth_digest,
                    recipient_policy_v2: Some(new.recipient_policy),
                }
            }
        };
        if anchor.recipient_policy_v2.is_some()
            && anchor.versioned_digest().map_err(D::Error::custom)? != anchor.birth_digest
        {
            return Err(D::Error::custom("birth digest mismatch"));
        }
        Ok(anchor)
    }
}
impl BirthAnchor {
    pub(super) fn envelope_version(&self) -> u8 {
        if self.recipient_policy_v2.is_some() {
            2
        } else {
            1
        }
    }
    pub(crate) fn recipient_policy_v2(&self) -> Result<&BornConstructionRecipientPolicyV2> {
        if self.versioned_digest()? != self.birth_digest {
            return Err(Error::Authentication);
        }
        self.recipient_policy_v2.as_ref().ok_or(Error::Unavailable)
    }
    pub(crate) fn complete_policy_origin_v2(
        &self,
    ) -> Result<wholepact_core::born_policy_origin_v2::BornRecipientPolicyOriginV2> {
        self.recipient_policy_v2()?;
        let origin: wholepact_core::born_policy_origin_v2::BornRecipientPolicyOriginV2 =
            serde_json::from_value(serde_json::to_value(self).map_err(|_| Error::InvalidData)?)
                .map_err(|_| Error::InvalidData)?;
        origin.validate().map_err(|_| Error::InvalidData)?;
        Ok(origin)
    }
    pub(super) fn versioned_digest(&self) -> Result<String> {
        match &self.recipient_policy_v2 {
            None => self.intent.digest(),
            Some(policy) => {
                if self.intent.version != 2 {
                    return Err(Error::InvalidData);
                }
                require_original_descriptor(
                    policy,
                    &self.intent.original_policy_terms,
                    &self.intent.identity,
                )?;
                canonical(
                    "wholepact:native-account-birth-intent:v2",
                    &(&self.intent, policy),
                )
            }
        }
    }
}
fn require_original_descriptor(
    policy: &BornConstructionRecipientPolicyV2,
    terms: &OriginalPolicyTerms,
    identity: &BirthIdentity,
) -> Result<()> {
    policy.validate().map_err(|_| Error::InvalidData)?;
    terms.validate()?;
    let limits = BornOriginalLimitsV2 {
        aggregate_budget_zatoshis: terms.aggregate_budget_zatoshis,
        per_operation_limit_zatoshis: terms.per_operation_limit_zatoshis,
        maximum_fee_share_zatoshis: terms.maximum_fee_share_zatoshis,
        maximum_transaction_fee_zatoshis: terms.maximum_transaction_fee_zatoshis,
        maximum_permit_lifetime_ms: terms.maximum_permit_lifetime_ms,
        policy_expires_at_ms: terms.policy_expires_at_ms,
    };
    if policy.account_id != identity.account_id
        || policy.network_profile_id != identity.network_profile_id
        || policy.account_id != terms.account_id
        || policy.network_profile_id != terms.network_profile_id
        || !terms.agreement_ids.contains(&policy.agreement_id)
        || !terms
            .recipient_scope_digests
            .contains(&policy.digest().map_err(|_| Error::InvalidData)?)
        || policy.original_limits != limits
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
impl PreparedAccountBirth {
    /// Only the already generated, backup-verified in-memory instance can enter
    /// this original V2 format. It still needs the ordinary exact native click.
    pub(crate) fn prepare_v2(
        verified: &BackupVerifiedAccount,
        root: &Path,
        disclosure: &WitnessDisclosureDescriptor,
        original_policy: &AccountPolicy,
        policy: BornConstructionRecipientPolicyV2,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        let mut prepared = Self::prepare(verified, root, disclosure, original_policy, owner)?;
        require_original_descriptor(
            &policy,
            &prepared.anchor.intent.original_policy_terms,
            &prepared.anchor.intent.identity,
        )?;
        prepared.anchor.intent.version = 2;
        prepared.anchor.recipient_policy_v2 = Some(policy);
        prepared.anchor.birth_digest = prepared.anchor.versioned_digest()?;
        prepared.anchor.validate(&verified.account)?;
        prepared.check(verified, owner)?;
        Ok(prepared)
    }
}
/// A complete audit export projection of the exact authenticated original
/// descriptor. Data serialization never establishes native or witness authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalRecipientPolicyExportV2 {
    version: u16,
    anchor: wholepact_core::born_policy_origin_v2::BornRecipientPolicyOriginV2,
    original_birth_commit: wholepact_authority::pending_birth::PendingBirthCommitRecord,
}
impl OriginalRecipientPolicyExportV2 {
    pub(crate) fn from_retained(
        origin: &acknowledgement::RetainedBornAccountOrigin,
    ) -> Result<Self> {
        origin.anchor().recipient_policy_v2()?;
        let result = Self {
            version: 2,
            anchor: origin.anchor().complete_policy_origin_v2()?,
            original_birth_commit: origin.witness_commit().clone(),
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != 2 {
            return Err(Error::InvalidData);
        }
        self.anchor.validate().map_err(|_| Error::InvalidData)?;
        if self.anchor.birth_digest != self.original_birth_commit.request.native_birth_digest
            || self.anchor.intent.operation_id != self.original_birth_commit.request.operation_id
            || self.anchor.intent.generation_instance_id
                != self.original_birth_commit.request.generation_instance_id
            || self.anchor.intent.original_policy_terms_digest
                != self.original_birth_commit.request.original_terms_digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.original_birth_commit
            .validate()
            .map_err(|_| Error::InvalidData)
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical("wholepact:original-born-recipient-policy-export:v2", self)
    }
}
#[cfg(test)]
pub(super) fn modeled_v2_anchor(account: &DedicatedAccount) -> BirthAnchor {
    tests::v2(account)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(anchor: &BirthAnchor) -> BornConstructionRecipientPolicyV2 {
        use wholepact_core::born_recipient_policy_v2::{BornOwnReturnRuleV2, BornRecipientLimitV2};
        let t = &anchor.intent.original_policy_terms;
        BornConstructionRecipientPolicyV2 {
            version: 2,
            account_id: anchor.identity().account_id().into(),
            network_profile_id: anchor.identity().network_profile_id().into(),
            agreement_id: t.agreement_ids[0].clone(),
            obligation_id: "synthetic-obligation".into(),
            participant_id: "synthetic-participant".into(),
            recipients: vec![BornRecipientLimitV2 {
                recipient_id: "synthetic-recipient".into(),
                address: "uSyntheticRecipient".into(),
                memo: None,
                instruction_provenance: "synthetic fixture".into(),
                maximum_amount_zatoshis: 1,
            }],
            charges: vec![],
            original_limits: BornOriginalLimitsV2 {
                aggregate_budget_zatoshis: t.aggregate_budget_zatoshis,
                per_operation_limit_zatoshis: t.per_operation_limit_zatoshis,
                maximum_fee_share_zatoshis: t.maximum_fee_share_zatoshis,
                maximum_transaction_fee_zatoshis: t.maximum_transaction_fee_zatoshis,
                maximum_permit_lifetime_ms: t.maximum_permit_lifetime_ms,
                policy_expires_at_ms: t.policy_expires_at_ms,
            },
            own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
        }
    }
    pub(super) fn v2(account: &DedicatedAccount) -> BirthAnchor {
        let mut a = super::super::tests::data_anchor(account);
        let p = policy(&a);
        a.intent
            .original_policy_terms
            .recipient_scope_digests
            .push(p.digest().unwrap());
        a.intent.original_policy_terms_digest = a.intent.original_policy_terms.digest().unwrap();
        a.intent.version = 2;
        a.recipient_policy_v2 = Some(p);
        a.birth_digest = a.versioned_digest().unwrap();
        a
    }
    #[test]
    fn legacy_bytes_and_unknown_field_denial_are_unchanged() {
        let account = super::super::tests::data_account();
        let a = super::super::tests::data_anchor(&account);
        let before = serde_json::to_vec(&LegacyAnchor {
            intent: a.intent.clone(),
            birth_digest: a.birth_digest.clone(),
        })
        .unwrap();
        assert_eq!(before, serde_json::to_vec(&a).unwrap());
        let bytes = String::from_utf8(before.clone()).unwrap();
        let duplicate = bytes.replacen(
            "\"birth_digest\":",
            &format!("\"birth_digest\":\"{}\",\"birth_digest\":", a.birth_digest),
            1,
        );
        assert!(serde_json::from_str::<BirthAnchor>(&duplicate).is_err());
        let mut value = serde_json::to_value(&a).unwrap();
        value["recipient_policy"] = serde_json::to_value(policy(&a)).unwrap();
        assert!(serde_json::from_value::<BirthAnchor>(value).is_err());
        assert!(a.recipient_policy_v2().is_err());
    }
    #[test]
    fn explicit_v2_envelope_retains_descriptor_and_rejects_downgrade() {
        let account = super::super::tests::data_account();
        let a = v2(&account);
        assert_eq!(
            a.complete_policy_origin_v2().unwrap().digest().unwrap(),
            a.birth_digest
        );
        let plain = encode_pending(&account, &a).unwrap();
        assert_eq!(plain[0], 2);
        let reopened = decode_pending_account(&plain).unwrap().0;
        assert!(reopened == a);
        assert_eq!(
            reopened.recipient_policy_v2().unwrap().digest().unwrap(),
            a.recipient_policy_v2().unwrap().digest().unwrap()
        );
        let mut down = plain.to_vec();
        down[0] = 1;
        assert!(decode_pending_account(&down).is_err());
        let mut value = serde_json::to_value(&a).unwrap();
        value["recipient_policy"]["recipients"][0]["address"] = "uDifferent".into();
        assert!(serde_json::from_value::<BirthAnchor>(value).is_err());
    }
    #[test]
    fn v2_policy_cannot_loosen_original_limits_or_move_to_another_account() {
        let account = super::super::tests::data_account();
        let mut a = v2(&account);
        a.recipient_policy_v2
            .as_mut()
            .unwrap()
            .original_limits
            .aggregate_budget_zatoshis += 1;
        assert!(a.versioned_digest().is_err());
        let mut a = v2(&account);
        a.recipient_policy_v2.as_mut().unwrap().account_id = "ff".repeat(32);
        assert!(a.versioned_digest().is_err());
    }
}
