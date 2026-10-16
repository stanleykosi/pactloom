//! Optional named-verifier assertion evidence. A signature authenticates an
//! assertion, never its truth, native trust selection, or financial authority.
use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wholepact_protocol::own_effects::OwnEffectsInspection;
use wholepact_transport::TransportError;

const DOMAIN: &[u8] = b"wholepact:named-verifier:pczt-0.10.0-pre.1:ironwood-testnet-nu7:v1\0";
const MAX_BYTES: usize = 131_072;
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamedInputAllocationV1 {
    pub action_index: u32,
    pub participant_index: u32,
    pub nullifier: String,
    pub value_zatoshis: u64,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamedOutputAllocationV1 {
    pub action_index: u32,
    /// None is the common recipient; Some identifies a retained participant return.
    pub return_participant_index: Option<u32>,
    pub receiver: String,
    pub value_zatoshis: u64,
    pub memo_digest: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamedParticipantAllocationV1 {
    pub account_id: String,
    pub contribution_zatoshis: u64,
    pub fee_share_zatoshis: u64,
    pub maximum_debit_zatoshis: u64,
    pub selected_own_policy_digest: String,
}
/// Untrusted wire statement. No field is an approval or authority token.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamedVerifierStatementV1 {
    pub schema_version: u16,
    pub verifier_key_digest: String,
    pub recipient_account_id: String,
    pub original_artifact_digest: String,
    pub recipient_artifact_digest: String,
    pub transformation_commitment: String,
    pub effects_digest: String,
    pub manifest_digest: String,
    pub original_context_digest: String,
    pub original_request_digest: String,
    pub validity_not_before_ms: u64,
    pub validity_expires_ms: u64,
    pub transaction_expiry_height: u32,
    pub transaction_fee_zatoshis: u64,
    pub participants: Vec<NamedParticipantAllocationV1>,
    pub inputs: Vec<NamedInputAllocationV1>,
    pub outputs: Vec<NamedOutputAllocationV1>,
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn hash_ok(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(TransportError::WrongContext)
    }
}
impl NamedVerifierStatementV1 {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == 1
                && (2..=32).contains(&self.participants.len())
                && !self.inputs.is_empty()
                && self.inputs.len() <= 64
                && !self.outputs.is_empty()
                && self.outputs.len() <= 64
                && self.validity_not_before_ms < self.validity_expires_ms
                && self.transaction_expiry_height < 500_000_000,
        )?;
        for h in [
            &self.verifier_key_digest,
            &self.original_artifact_digest,
            &self.recipient_artifact_digest,
            &self.transformation_commitment,
            &self.effects_digest,
            &self.manifest_digest,
            &self.original_context_digest,
            &self.original_request_digest,
        ] {
            require(hash_ok(h))?;
        }
        require(
            self.participants
                .iter()
                .any(|p| p.account_id == self.recipient_account_id),
        )?;
        let mut accounts = std::collections::BTreeSet::new();
        for p in &self.participants {
            require(
                !p.account_id.is_empty()
                    && p.account_id.len() <= 128
                    && accounts.insert(&p.account_id)
                    && hash_ok(&p.selected_own_policy_digest)
                    && p.contribution_zatoshis
                        .checked_add(p.fee_share_zatoshis)
                        .is_some_and(|d| d <= p.maximum_debit_zatoshis)
                    && p.maximum_debit_zatoshis <= 2_100_000_000_000_000,
            )?;
        }
        let mut previous = None;
        let mut nullifiers = std::collections::BTreeSet::new();
        for i in &self.inputs {
            require(
                i.action_index < 64
                    && previous.is_none_or(|p| p < i.action_index)
                    && (i.participant_index as usize) < self.participants.len()
                    && hash_ok(&i.nullifier)
                    && nullifiers.insert(&i.nullifier)
                    && i.value_zatoshis > 0
                    && i.value_zatoshis <= 2_100_000_000_000_000,
            )?;
            previous = Some(i.action_index);
        }
        previous = None;
        for o in &self.outputs {
            require(
                o.action_index < 64
                    && previous.is_none_or(|p| p < o.action_index)
                    && o.return_participant_index
                        .is_none_or(|p| (p as usize) < self.participants.len())
                    && o.receiver.len() == 86
                    && o.receiver
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && hash_ok(&o.memo_digest)
                    && o.value_zatoshis > 0
                    && o.value_zatoshis <= 2_100_000_000_000_000,
            )?;
            previous = Some(o.action_index);
        }
        let sum = |values: Vec<u64>| -> Result<u64> {
            values.into_iter().try_fold(0u64, |a, b| {
                a.checked_add(b)
                    .filter(|v| *v <= 2_100_000_000_000_000)
                    .ok_or(TransportError::WrongContext)
            })
        };
        require(
            sum(self.inputs.iter().map(|i| i.value_zatoshis).collect())?.checked_sub(sum(self
                .outputs
                .iter()
                .map(|o| o.value_zatoshis)
                .collect())?)
                == Some(self.transaction_fee_zatoshis),
        )?;
        require(
            sum(self
                .participants
                .iter()
                .map(|p| p.fee_share_zatoshis)
                .collect())?
                == self.transaction_fee_zatoshis,
        )?;
        for (index, p) in self.participants.iter().enumerate() {
            let inputs: Vec<_> = self
                .inputs
                .iter()
                .filter(|i| i.participant_index as usize == index)
                .map(|i| i.value_zatoshis)
                .collect();
            require(!inputs.is_empty())?;
            let returns = sum(self
                .outputs
                .iter()
                .filter(|o| o.return_participant_index == Some(index as u32))
                .map(|o| o.value_zatoshis)
                .collect())?;
            require(
                sum(inputs)?.checked_sub(returns)
                    == p.contribution_zatoshis.checked_add(p.fee_share_zatoshis),
            )?;
        }
        require(self.transaction_fee_zatoshis <= 2_100_000_000_000_000)
    }
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let bytes = self.canonical_bytes()?;
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&bytes);
        Ok(message)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let b = serde_json::to_vec(self).map_err(|_| TransportError::Malformed)?;
        require(b.len() <= MAX_BYTES)?;
        Ok(b)
    }
}
/// Exact retained expectations, supplied by the local owner adapter, never
/// inferred from an incoming statement. This value itself grants no native trust.
pub struct NamedVerifierExpectedContext<'a> {
    pub original_artifact_digest: &'a str,
    pub transformation_commitment: &'a str,
    pub manifest_digest: &'a str,
    pub original_context_digest: &'a str,
    pub original_request_digest: &'a str,
    pub validity_not_before_ms: u64,
    pub validity_expires_ms: u64,
    pub transaction_expiry_height: u32,
    pub own_account_id: &'a str,
}
/// Maintained signature + exact binding evidence; no trust or permission factory.
pub struct NamedVerifierSignatureEvidence {
    statement: NamedVerifierStatementV1,
    statement_digest: String,
    verifier_key: [u8; 32],
}
impl NamedVerifierSignatureEvidence {
    pub fn statement(&self) -> &NamedVerifierStatementV1 {
        &self.statement
    }
    pub fn statement_digest(&self) -> &str {
        &self.statement_digest
    }
    pub fn verifier_key_digest(&self) -> String {
        digest(&self.verifier_key)
    }
}
/// The key is an explicit input, not imported from the assertion. The caller must
/// separately obtain real native selection before treating these as trusted claims.
/// No wall-clock assertion or current-admission decision is inferred here.
pub fn verify_named_verifier_signature_evidence(
    statement_bytes: &[u8],
    signature: &[u8],
    selected_key: &[u8; 32],
    expected: &NamedVerifierExpectedContext<'_>,
    own: &OwnEffectsInspection,
) -> Result<NamedVerifierSignatureEvidence> {
    require(statement_bytes.len() <= MAX_BYTES && signature.len() == 64)?;
    let s: NamedVerifierStatementV1 =
        serde_json::from_slice(statement_bytes).map_err(|_| TransportError::Malformed)?;
    require(s.canonical_bytes()? == statement_bytes)?;
    require(
        s.verifier_key_digest == digest(selected_key)
            && s.recipient_account_id == expected.own_account_id
            && s.original_artifact_digest == expected.original_artifact_digest
            && s.recipient_artifact_digest == own.artifact_digest()
            && s.transformation_commitment == expected.transformation_commitment
            && s.effects_digest == own.shielded_sighash()
            && s.manifest_digest == expected.manifest_digest
            && s.original_context_digest == expected.original_context_digest
            && s.original_request_digest == expected.original_request_digest
            && s.validity_not_before_ms == expected.validity_not_before_ms
            && s.validity_expires_ms == expected.validity_expires_ms
            && s.transaction_expiry_height == expected.transaction_expiry_height
            && s.transaction_fee_zatoshis == own.transaction_fee_zatoshis(),
    )?;
    let p = s
        .participants
        .iter()
        .find(|p| p.account_id == expected.own_account_id)
        .ok_or(TransportError::WrongContext)?;
    require(
        p.selected_own_policy_digest == own.policy_digest()
            && p.contribution_zatoshis.checked_add(p.fee_share_zatoshis)
                == Some(own.selected_net_debit_zatoshis())
            && p.fee_share_zatoshis == own.declared_fee_share_zatoshis(),
    )?;
    let participant = s
        .participants
        .iter()
        .position(|p| p.account_id == expected.own_account_id)
        .ok_or(TransportError::WrongContext)?;
    let indices = s
        .inputs
        .iter()
        .filter(|i| i.participant_index as usize == participant)
        .map(|i| i.action_index as usize)
        .collect::<Vec<_>>();
    require(indices == own.own_action_indices())?;
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(statement_bytes);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, selected_key)
        .verify(&message, signature)
        .map_err(|_| TransportError::Authentication)?;
    Ok(NamedVerifierSignatureEvidence {
        statement: s,
        statement_digest: digest(&message),
        verifier_key: *selected_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn statement() -> NamedVerifierStatementV1 {
        NamedVerifierStatementV1 {
            schema_version: 1,
            verifier_key_digest: "01".repeat(32),
            recipient_account_id: "owner-0".into(),
            original_artifact_digest: "02".repeat(32),
            recipient_artifact_digest: "03".repeat(32),
            transformation_commitment: "04".repeat(32),
            effects_digest: "05".repeat(32),
            manifest_digest: "06".repeat(32),
            original_context_digest: "07".repeat(32),
            original_request_digest: "08".repeat(32),
            validity_not_before_ms: 100,
            validity_expires_ms: 200,
            transaction_expiry_height: 140,
            transaction_fee_zatoshis: 10,
            participants: (0..2)
                .map(|i| NamedParticipantAllocationV1 {
                    account_id: format!("owner-{i}"),
                    contribution_zatoshis: 55,
                    fee_share_zatoshis: 5,
                    maximum_debit_zatoshis: 60,
                    selected_own_policy_digest: format!("{i:02x}").repeat(32),
                })
                .collect(),
            inputs: (0..2)
                .map(|i| NamedInputAllocationV1 {
                    action_index: i,
                    participant_index: i,
                    nullifier: format!("{i:02x}").repeat(32),
                    value_zatoshis: 100,
                })
                .collect(),
            outputs: vec![
                NamedOutputAllocationV1 {
                    action_index: 0,
                    return_participant_index: Some(0),
                    receiver: "10".repeat(43),
                    value_zatoshis: 40,
                    memo_digest: "12".repeat(32),
                },
                NamedOutputAllocationV1 {
                    action_index: 1,
                    return_participant_index: Some(1),
                    receiver: "11".repeat(43),
                    value_zatoshis: 40,
                    memo_digest: "12".repeat(32),
                },
                NamedOutputAllocationV1 {
                    action_index: 2,
                    return_participant_index: None,
                    receiver: "13".repeat(43),
                    value_zatoshis: 110,
                    memo_digest: "12".repeat(32),
                },
            ],
        }
    }
    #[test]
    fn named_statement_canonical_domain_and_complete_accounting() {
        let s = statement();
        s.validate().unwrap();
        let bytes = s.canonical_bytes().unwrap();
        let parsed: NamedVerifierStatementV1 = serde_json::from_slice(&bytes).unwrap();
        assert!(s == parsed);
        assert_eq!(parsed.canonical_bytes().unwrap(), bytes);
        assert!(s.signing_message().unwrap().starts_with(DOMAIN));
        assert_ne!(digest(&s.signing_message().unwrap()), digest(&bytes));
    }
    #[test]
    fn named_statement_rejects_omitted_duplicate_and_reallocated_rows() {
        let base = statement();
        let mut variants = vec![];
        let mut s = base.clone();
        s.inputs.pop();
        variants.push(s);
        let mut s = base.clone();
        s.outputs.pop();
        variants.push(s);
        let mut s = base.clone();
        s.inputs[1].action_index = 0;
        variants.push(s);
        let mut s = base.clone();
        s.outputs[1].action_index = 0;
        variants.push(s);
        let mut s = base.clone();
        s.inputs[1].participant_index = 0;
        variants.push(s);
        let mut s = base.clone();
        s.outputs[1].return_participant_index = Some(0);
        variants.push(s);
        let mut s = base.clone();
        s.participants[1].account_id = s.participants[0].account_id.clone();
        variants.push(s);
        for s in variants {
            assert!(s.validate().is_err());
        }
    }
    #[test]
    fn named_statement_rejects_value_overflow_wrong_fee_and_validity() {
        let base = statement();
        let mut variants = vec![];
        let mut s = base.clone();
        s.inputs[0].value_zatoshis = u64::MAX;
        variants.push(s);
        let mut s = base.clone();
        s.participants[0].contribution_zatoshis = u64::MAX;
        variants.push(s);
        let mut s = base.clone();
        s.transaction_fee_zatoshis = 11;
        variants.push(s);
        let mut s = base.clone();
        s.participants[0].maximum_debit_zatoshis = 59;
        variants.push(s);
        let mut s = base.clone();
        s.validity_expires_ms = 100;
        variants.push(s);
        let mut s = base.clone();
        s.schema_version = 2;
        variants.push(s);
        let mut s = base.clone();
        s.original_request_digest = "AB".repeat(32);
        variants.push(s);
        for s in variants {
            assert!(s.validate().is_err());
        }
    }
    #[test]
    fn named_statement_rejects_unknown_wire_fields() {
        let mut value = serde_json::to_value(statement()).unwrap();
        value["trusted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<NamedVerifierStatementV1>(value).is_err());
    }
    #[test]
    fn named_statement_binds_original_request_key_validity_and_allocations() {
        let base = statement();
        let message = base.signing_message().unwrap();
        let mut variants = vec![];
        let mut s = base.clone();
        s.original_request_digest = "18".repeat(32);
        variants.push(s);
        let mut s = base.clone();
        s.verifier_key_digest = "19".repeat(32);
        variants.push(s);
        let mut s = base.clone();
        s.validity_expires_ms = 201;
        variants.push(s);
        let mut s = base.clone();
        s.outputs[2].receiver = "14".repeat(43);
        variants.push(s);
        let mut s = base.clone();
        s.original_artifact_digest = "20".repeat(32);
        variants.push(s);
        let mut s = base.clone();
        s.recipient_artifact_digest = "21".repeat(32);
        variants.push(s);
        for s in variants {
            assert_ne!(message, s.signing_message().unwrap());
        }
    }
}
