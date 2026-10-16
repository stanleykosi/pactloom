//! Pure immutable request/outcome state. Serialization is encrypted by its owner.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use wholepact_offline_bridge::NamedVerifierStatementV1;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub version: u16,
    pub public_key: [u8; 32],
    pub restored_informational: bool,
    pub families: BTreeMap<String, String>,
    pub rows: BTreeMap<String, Entry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_identity: Option<super::export_identity::ExportIdentity>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub statement: NamedVerifierStatementV1,
    pub recipient_artifact: Vec<u8>,
    pub state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_terms: Option<wholepact_authority::offline::OfflineAuthorizationTerms>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum State {
    Prepared,
    Started {
        native_review_digest: String,
    },
    Signed {
        native_review_digest: String,
        signature: Vec<u8>,
    },
}
pub(super) fn row_key(s: &NamedVerifierStatementV1) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:named-verifier-outcome-key:v1",
        &(&s.original_request_digest, &s.recipient_account_id),
    )
    .map_err(|_| Error::InvalidData)
}
fn family(s: &NamedVerifierStatementV1) -> Result<String> {
    let mut value = serde_json::to_value(s).map_err(|_| Error::InvalidData)?;
    let object = value.as_object_mut().ok_or(Error::InvalidData)?;
    object
        .remove("recipient_account_id")
        .ok_or(Error::InvalidData)?;
    object
        .remove("original_context_digest")
        .ok_or(Error::InvalidData)?;
    wholepact_core::proposal::canonical_digest("wholepact:named-verifier-request-family:v1", &value)
        .map_err(|_| Error::InvalidData)
}
fn hash_ok(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Journal {
    /// Private retained-result source for separate native encrypted disclosure.
    /// Historical expiry does not erase bytes and does not renew validity.
    pub fn retained_package(
        &self,
        key: &str,
    ) -> Result<wholepact_offline_bridge::NamedVerifierPackageV1> {
        self.validate()?;
        let entry = self.rows.get(key).ok_or(Error::InvalidData)?;
        let State::Signed { signature, .. } = &entry.state else {
            return Err(Error::Uncertain);
        };
        let package = wholepact_offline_bridge::NamedVerifierPackageV1 {
            schema_version: 1,
            statement: entry.statement.clone(),
            signature: signature.clone(),
            recipient_artifact: entry.recipient_artifact.clone(),
        };
        package.canonical_bytes().map_err(|_| Error::InvalidData)?;
        Ok(package)
    }
    pub fn validate(&self) -> Result<()> {
        if let Some(identity) = &self.export_identity {
            identity.validate()?;
            if identity.setup_intent.verifier_digest != hex::encode(Sha256::digest(self.public_key))
            {
                return Err(Error::ReviewMismatch);
            }
        }
        if self.version != 1 || self.rows.len() > 128 || self.families.len() > 128 {
            return Err(Error::InvalidData);
        }
        let key_digest = hex::encode(Sha256::digest(self.public_key));
        let mut families = BTreeMap::new();
        for (key, e) in &self.rows {
            if let Some(terms) = &e.original_terms {
                if wholepact_offline_bridge::named_verifier_original_context_digest(terms)
                    .map_err(|_| Error::InvalidData)?
                    != e.statement.original_context_digest
                {
                    return Err(Error::ReviewMismatch);
                }
            }
            e.statement.validate().map_err(|_| Error::InvalidData)?;
            if row_key(&e.statement)? != *key
                || e.statement.verifier_key_digest != key_digest
                || e.recipient_artifact.len() > 1_048_576
                || hex::encode(Sha256::digest(&e.recipient_artifact))
                    != e.statement.recipient_artifact_digest
            {
                return Err(Error::InvalidData);
            }
            let f = family(&e.statement)?;
            if families
                .insert(e.statement.original_request_digest.clone(), f.clone())
                .is_some_and(|prior| prior != f)
            {
                return Err(Error::InvalidData);
            }
            match &e.state {
                State::Prepared => {}
                State::Started {
                    native_review_digest,
                } => {
                    if !hash_ok(native_review_digest) {
                        return Err(Error::InvalidData);
                    }
                }
                State::Signed {
                    native_review_digest,
                    signature,
                } => {
                    if !hash_ok(native_review_digest) || signature.len() != 64 {
                        return Err(Error::InvalidData);
                    }
                    ring::signature::UnparsedPublicKey::new(
                        &ring::signature::ED25519,
                        &self.public_key,
                    )
                    .verify(
                        &e.statement
                            .signing_message()
                            .map_err(|_| Error::InvalidData)?,
                        signature,
                    )
                    .map_err(|_| Error::Verification)?;
                }
            }
        }
        if families != self.families {
            return Err(Error::InvalidData);
        }
        Ok(())
    }
    pub fn prepare(
        &mut self,
        statement: NamedVerifierStatementV1,
        artifact: Vec<u8>,
    ) -> Result<String> {
        if self.restored_informational {
            return Err(Error::RecoveryRequired);
        }
        statement.validate().map_err(|_| Error::InvalidData)?;
        if statement.verifier_key_digest != hex::encode(Sha256::digest(self.public_key))
            || artifact.len() > 1_048_576
            || hex::encode(Sha256::digest(&artifact)) != statement.recipient_artifact_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let key = row_key(&statement)?;
        if let Some(e) = self.rows.get(&key) {
            if e.statement != statement || e.recipient_artifact != artifact {
                return Err(Error::ReviewMismatch);
            }
            return Ok(key);
        }
        if self.rows.len() >= 128 {
            return Err(Error::Unavailable);
        }
        let f = family(&statement)?;
        if self
            .families
            .get(&statement.original_request_digest)
            .is_some_and(|prior| prior != &f)
        {
            return Err(Error::ReviewMismatch);
        }
        self.families
            .insert(statement.original_request_digest.clone(), f);
        self.rows.insert(
            key.clone(),
            Entry {
                statement,
                recipient_artifact: artifact,
                state: State::Prepared,
                original_terms: None,
            },
        );
        Ok(key)
    }
    pub fn begin(&mut self, key: &str, review: &str) -> Result<()> {
        if self.restored_informational || !hash_ok(review) {
            return Err(Error::ReviewMismatch);
        }
        let entry = self.rows.get_mut(key).ok_or(Error::InvalidData)?;
        if !matches!(entry.state, State::Prepared) {
            return Err(Error::Uncertain);
        }
        entry.state = State::Started {
            native_review_digest: review.into(),
        };
        Ok(())
    }
    pub fn finish(&mut self, key: &str, review: &str, signature: Vec<u8>) -> Result<()> {
        let entry = self.rows.get_mut(key).ok_or(Error::InvalidData)?;
        if !matches!(&entry.state,State::Started{native_review_digest} if native_review_digest==review)
        {
            return Err(Error::Uncertain);
        }
        if signature.len() != 64 {
            return Err(Error::Verification);
        }
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &self.public_key)
            .verify(
                &entry
                    .statement
                    .signing_message()
                    .map_err(|_| Error::InvalidData)?,
                &signature,
            )
            .map_err(|_| Error::Verification)?;
        entry.state = State::Signed {
            native_review_digest: review.into(),
            signature,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_offline_bridge::{
        NamedInputAllocationV1, NamedOutputAllocationV1, NamedParticipantAllocationV1,
    };
    // Pure state fixture: a public-key byte string with no corresponding private
    // credential, no builder, no signature generation and no filesystem access.
    fn fixture() -> (Journal, NamedVerifierStatementV1, Vec<u8>) {
        let public_key = [0; 32];
        let artifact = b"synthetic journal payload".to_vec();
        let statement = NamedVerifierStatementV1 {
            schema_version: 1,
            verifier_key_digest: hex::encode(Sha256::digest(public_key)),
            recipient_account_id: "owner-0".into(),
            original_artifact_digest: "01".repeat(32),
            recipient_artifact_digest: hex::encode(Sha256::digest(&artifact)),
            transformation_commitment: "02".repeat(32),
            effects_digest: "03".repeat(32),
            manifest_digest: "04".repeat(32),
            original_context_digest: "05".repeat(32),
            original_request_digest: "06".repeat(32),
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
        };
        (
            Journal {
                version: 1,
                public_key,
                restored_informational: false,
                families: Default::default(),
                rows: Default::default(),
                export_identity: None,
            },
            statement,
            artifact,
        )
    }
    #[test]
    fn verifier_journal_exact_retry_never_rewrites_original() {
        let (mut j, s, a) = fixture();
        let key = j.prepare(s.clone(), a.clone()).unwrap();
        let before = serde_json::to_vec(&j).unwrap();
        assert_eq!(j.prepare(s.clone(), a.clone()).unwrap(), key);
        assert_eq!(serde_json::to_vec(&j).unwrap(), before);
        let mut changed = s;
        changed.validity_expires_ms += 1;
        assert!(j.prepare(changed, a).is_err());
        assert_eq!(serde_json::to_vec(&j).unwrap(), before);
        j.validate().unwrap();
    }
    #[test]
    fn verifier_journal_started_state_survives_restart_without_reset() {
        let (mut j, s, a) = fixture();
        let key = j.prepare(s, a).unwrap();
        assert!(matches!(j.retained_package(&key), Err(Error::Uncertain)));
        j.begin(&key, &"11".repeat(32)).unwrap();
        assert!(matches!(j.retained_package(&key), Err(Error::Uncertain)));
        let encoded = serde_json::to_vec(&j).unwrap();
        let mut reopened: Journal = serde_json::from_slice(&encoded).unwrap();
        reopened.validate().unwrap();
        assert!(matches!(
            reopened.begin(&key, &"22".repeat(32)),
            Err(Error::Uncertain)
        ));
        assert_eq!(serde_json::to_vec(&reopened).unwrap(), encoded);
    }
    #[test]
    fn verifier_journal_family_keeps_economics_across_recipient_contexts() {
        let (mut j, s, a) = fixture();
        j.prepare(s.clone(), a.clone()).unwrap();
        let mut second = s.clone();
        second.recipient_account_id = "owner-1".into();
        second.original_context_digest = "55".repeat(32);
        j.prepare(second, a.clone()).unwrap();
        assert_eq!(j.rows.len(), 2);
        assert_eq!(j.families.len(), 1);
        let before = serde_json::to_vec(&j).unwrap();
        let mut changed = s;
        changed.effects_digest = "66".repeat(32);
        assert!(j.prepare(changed, a).is_err());
        assert_eq!(serde_json::to_vec(&j).unwrap(), before);
        j.validate().unwrap();
    }
    #[test]
    fn verifier_journal_rejects_fabricated_result_without_losing_started_fence() {
        let (mut j, s, a) = fixture();
        let key = j.prepare(s, a).unwrap();
        j.begin(&key, &"11".repeat(32)).unwrap();
        let before = serde_json::to_vec(&j).unwrap();
        assert!(j.finish(&key, &"11".repeat(32), vec![0; 64]).is_err());
        assert_eq!(serde_json::to_vec(&j).unwrap(), before);
    }
    #[test]
    fn verifier_journal_restore_is_informational_and_family_omission_rejects() {
        let (mut j, s, a) = fixture();
        let key = j.prepare(s.clone(), a.clone()).unwrap();
        j.restored_informational = true;
        assert!(j.prepare(s, a).is_err());
        assert!(j.begin(&key, &"11".repeat(32)).is_err());
        j.validate().unwrap();
        j.families.clear();
        assert!(j.validate().is_err());
    }
}
