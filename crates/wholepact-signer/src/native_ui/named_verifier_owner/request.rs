//! Bounded untrusted import. No viewing key, approval or transport credential is
//! accepted here. Keys enter the review policy only from actual retained leases.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use wholepact_protocol::review::{
    InputPolicy, OutputPolicy, OutputPurpose, ParticipantPolicy, ReviewPolicy,
};
use wholepact_signer_origin::{
    named_verifier_policy::NamedVerifierPolicyScopeV1, NamedVerifierPolicyLease,
};

const MAX: usize = 2 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ParticipantClaim {
    account_id: String,
    contribution_zatoshis: u64,
    fee_share_zatoshis: u64,
    maximum_net_debit_zatoshis: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputClaim {
    input_id: String,
    action_index: usize,
    participant_index: usize,
    nullifier: String,
    value_zatoshis: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputClaim {
    output_id: String,
    action_index: usize,
    receiver: String,
    value_zatoshis: u64,
    memo: Vec<u8>,
    return_participant_index: Option<usize>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyClaims {
    manifest_digest: String,
    participants: Vec<ParticipantClaim>,
    inputs: Vec<InputClaim>,
    outputs: Vec<OutputClaim>,
    exact_fee_zatoshis: u64,
    expiry_height: u32,
    anchor: String,
}
fn bytes<const N: usize>(s: &str) -> Result<[u8; N]> {
    let b = hex::decode(s).map_err(|_| Error::InvalidData)?;
    if hex::encode(&b) != s {
        return Err(Error::InvalidData);
    }
    b.try_into().map_err(|_| Error::InvalidData)
}
impl PolicyClaims {
    fn validate(&self) -> Result<()> {
        bytes::<32>(&self.manifest_digest)?;
        bytes::<32>(&self.anchor)?;
        if !(2..=32).contains(&self.participants.len())
            || self.inputs.is_empty()
            || self.inputs.len() > 64
            || self.outputs.is_empty()
            || self.outputs.len() > 64
        {
            return Err(Error::InvalidData);
        }
        let mut accounts = BTreeSet::new();
        let mut input_indices = BTreeSet::new();
        let mut output_indices = BTreeSet::new();
        for p in &self.participants {
            crate::review::validate_label(&p.account_id)?;
            if !accounts.insert(&p.account_id) {
                return Err(Error::InvalidData);
            }
        }
        for i in &self.inputs {
            crate::review::validate_label(&i.input_id)?;
            bytes::<32>(&i.nullifier)?;
            if i.participant_index >= self.participants.len()
                || i.action_index >= 64
                || !input_indices.insert(i.action_index)
            {
                return Err(Error::InvalidData);
            }
        }
        for o in &self.outputs {
            crate::review::validate_label(&o.output_id)?;
            bytes::<43>(&o.receiver)?;
            if o.memo.len() != 512
                || o.action_index >= 64
                || o.return_participant_index
                    .is_some_and(|p| p >= self.participants.len())
                || !output_indices.insert(o.action_index)
            {
                return Err(Error::InvalidData);
            }
        }
        Ok(())
    }
    pub(super) fn bind_current_leases(
        &self,
        leases: &[NamedVerifierPolicyLease<'_>],
    ) -> Result<ReviewPolicy> {
        self.validate()?;
        if leases.len() != self.participants.len() {
            return Err(Error::ReviewMismatch);
        }
        let mut participants = Vec::with_capacity(leases.len());
        for p in &self.participants {
            let mut matches = leases
                .iter()
                .filter(|l| l.request().scope.account_id == p.account_id);
            let lease = matches.next().ok_or(Error::ReviewMismatch)?;
            if matches.next().is_some() {
                return Err(Error::ReviewMismatch);
            }
            lease.check_current().map_err(|_| Error::Locked)?;
            let fvk = orchard::keys::FullViewingKey::from_bytes(
                lease.full_viewing_key_bytes().map_err(|_| Error::Locked)?,
            )
            .ok_or(Error::Verification)?;
            participants.push(ParticipantPolicy {
                account_id: p.account_id.clone(),
                fvk,
                contribution_zatoshis: p.contribution_zatoshis,
                fee_share_zatoshis: p.fee_share_zatoshis,
                maximum_net_debit_zatoshis: p.maximum_net_debit_zatoshis,
            });
        }
        Ok(ReviewPolicy {
            manifest_digest: bytes(&self.manifest_digest)?,
            participants,
            inputs: self
                .inputs
                .iter()
                .map(|i| {
                    Ok(InputPolicy {
                        action_index: i.action_index,
                        participant_index: i.participant_index,
                        nullifier: bytes(&i.nullifier)?,
                        value_zatoshis: i.value_zatoshis,
                    })
                })
                .collect::<Result<_>>()?,
            outputs: self
                .outputs
                .iter()
                .map(|o| {
                    Ok(OutputPolicy {
                        action_index: o.action_index,
                        receiver: Option::from(orchard::Address::from_raw_address_bytes(&bytes(
                            &o.receiver,
                        )?))
                        .ok_or(Error::Verification)?,
                        value_zatoshis: o.value_zatoshis,
                        memo: o
                            .memo
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error::InvalidData)?,
                        purpose: o
                            .return_participant_index
                            .map_or(OutputPurpose::Recipient, |participant_index| {
                                OutputPurpose::Return { participant_index }
                            }),
                    })
                })
                .collect::<Result<_>>()?,
            exact_fee_zatoshis: self.exact_fee_zatoshis,
            expiry_height: self.expiry_height,
            anchor: bytes(&self.anchor)?,
        })
    }
}
#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(transparent)]
struct PrivateArtifact(Vec<u8>);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestFile {
    version: u16,
    pub scopes: Vec<NamedVerifierPolicyScopeV1>,
    pub endpoints: Vec<String>,
    original_artifact: PrivateArtifact,
    terms: wholepact_authority::offline::OfflineAuthorizationTerms,
    policy: PolicyClaims,
}
impl RequestFile {
    pub(super) fn parse(raw: &[u8], selected_key: &[u8; 32]) -> Result<Self> {
        if raw.is_empty() || raw.len() > MAX {
            return Err(Error::InvalidData);
        }
        let r: Self = serde_json::from_slice(raw).map_err(|_| Error::InvalidData)?;
        if r.version != 1
            || r.original_artifact.0.is_empty()
            || r.original_artifact.0.len() > 1024 * 1024
            || !(2..=32).contains(&r.scopes.len())
            || r.endpoints.len() != r.scopes.len()
        {
            return Err(Error::InvalidData);
        }
        r.policy.validate()?;
        r.terms.validate().map_err(|_| Error::InvalidData)?;
        if r.terms.artifact_digest != hex::encode(Sha256::digest(&r.original_artifact.0)) {
            return Err(Error::ReviewMismatch);
        }
        let first = &r.scopes[0];
        let mut accounts = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for (scope, endpoint) in r.scopes.iter().zip(&r.endpoints) {
            scope.validate().map_err(|_| Error::InvalidData)?;
            if scope.verifier_public_key != *selected_key
                || scope.original_artifact_digest != r.terms.artifact_digest
                || scope.original_request_digest != first.original_request_digest
                || scope.proposal != first.proposal
                || scope.original_validity_not_before_ms != first.original_validity_not_before_ms
                || scope.original_validity_expires_ms != first.original_validity_expires_ms
                || !accounts.insert(&scope.account_id)
                || !endpoints.insert(endpoint)
                || endpoint.len() > 4096
                || !std::path::Path::new(endpoint).is_absolute()
                || endpoint.chars().any(char::is_control)
            {
                return Err(Error::ReviewMismatch);
            }
        }
        if accounts.len() != r.policy.participants.len()
            || r.policy
                .participants
                .iter()
                .any(|p| !accounts.contains(&p.account_id))
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(r)
    }
    pub(super) fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| Error::InvalidData)?,
        )))
    }
    pub(super) fn into_input(mut self) -> Result<(Vec<String>, super::worker::AssertionInput)> {
        let proposal = self.scopes[0].validate().map_err(|_| Error::InvalidData)?;
        let input_actions = self
            .policy
            .inputs
            .iter()
            .map(|i| wholepact_protocol::construction::InputActionMapping {
                input_id: i.input_id.clone(),
                account_id: self.policy.participants[i.participant_index]
                    .account_id
                    .clone(),
                action_index: i.action_index,
            })
            .collect();
        let output_actions = self
            .policy
            .outputs
            .iter()
            .map(|o| wholepact_protocol::construction::OutputActionMapping {
                output_id: o.output_id.clone(),
                action_index: o.action_index,
            })
            .collect();
        Ok((
            self.endpoints,
            super::worker::AssertionInput {
                scopes: self.scopes,
                original: zeroize::Zeroizing::new(std::mem::take(&mut self.original_artifact.0)),
                terms: self.terms,
                proposal,
                policy: self.policy,
                input_actions,
                output_actions,
                maximum_actions: 64,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claims() -> PolicyClaims {
        PolicyClaims {
            manifest_digest: "11".repeat(32),
            anchor: "22".repeat(32),
            expiry_height: 100,
            exact_fee_zatoshis: 10,
            participants: (0..2)
                .map(|i| ParticipantClaim {
                    account_id: format!("account-{i}"),
                    contribution_zatoshis: 50,
                    fee_share_zatoshis: 5,
                    maximum_net_debit_zatoshis: 55,
                })
                .collect(),
            inputs: (0..2)
                .map(|i| InputClaim {
                    input_id: format!("input-{i}"),
                    action_index: i,
                    participant_index: i,
                    nullifier: format!("{i:02x}").repeat(32),
                    value_zatoshis: 60,
                })
                .collect(),
            outputs: vec![OutputClaim {
                output_id: "recipient".into(),
                action_index: 0,
                receiver: "00".repeat(43),
                value_zatoshis: 100,
                memo: vec![0; 512],
                return_participant_index: None,
            }],
        }
    }
    #[test]
    fn imported_policy_has_no_viewing_key_or_authority_field() {
        let value = serde_json::to_value(claims()).unwrap();
        assert!(serde_json::from_value::<PolicyClaims>(value.clone()).is_ok());
        for field in ["fvk", "approved", "verified", "lease"] {
            let mut changed = value.clone();
            changed
                .as_object_mut()
                .unwrap()
                .insert(field.into(), serde_json::json!(true));
            assert!(serde_json::from_value::<PolicyClaims>(changed).is_err());
            let mut changed = value.clone();
            changed["participants"][0][field] = serde_json::json!(true);
            assert!(serde_json::from_value::<PolicyClaims>(changed).is_err());
        }
    }
    #[test]
    fn imported_policy_without_real_leases_cannot_bind_keys() {
        let claims = claims();
        claims.validate().unwrap();
        assert!(matches!(
            claims.bind_current_leases(&[]),
            Err(Error::ReviewMismatch)
        ));
    }
    #[test]
    fn imported_policy_rejects_duplicate_and_out_of_range_indices() {
        for case in 0..5 {
            let mut p = claims();
            match case {
                0 => p.inputs[1].action_index = 0,
                1 => p.inputs[1].participant_index = 2,
                2 => p.participants[1].account_id = "account-0".into(),
                3 => p.outputs[0].return_participant_index = Some(2),
                _ => p.outputs[0].memo.pop().map(|_| ()).unwrap(),
            }
            assert!(p.validate().is_err());
        }
    }
    #[test]
    fn imported_request_rejects_oversize_and_unknown_authority() {
        assert!(RequestFile::parse(&[], &[0; 32]).is_err());
        assert!(RequestFile::parse(&vec![b' '; MAX + 1], &[0; 32]).is_err());
        assert!(RequestFile::parse(br#"{"approved":true,"version":1}"#, &[0; 32]).is_err());
    }
    #[test]
    fn imported_binary_commitments_are_exact_lowercase_and_length() {
        assert_eq!(bytes::<32>(&"11".repeat(32)).unwrap(), [0x11; 32]);
        for s in [
            "AA".repeat(32),
            "11".repeat(31),
            "11".repeat(33),
            "zz".repeat(32),
        ] {
            assert!(bytes::<32>(&s).is_err());
        }
    }
}
