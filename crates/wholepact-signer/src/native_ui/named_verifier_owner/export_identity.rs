//! Private encrypted-profile state for a separate assertion transport identity.
//! These bytes never establish native approval, recipient trust, or spending authority.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Component, PathBuf},
};
use wholepact_storage_security::{DatabaseKey, PlannedNamedVerifierOutboxInitialization};
use wholepact_transport::{TransportPublicKey, TransportSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(super) struct ExportSecrets {
    pub transport: [u8; 32],
    pub database: [u8; 32],
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum SetupState {
    Prepared,
    Ready,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExportIdentity {
    pub version: u16,
    pub secrets: ExportSecrets,
    pub setup_intent: SetupIntent,
    pub state: SetupState,
    pub pins: BTreeMap<String, RecipientPin>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetupIntent {
    pub verifier_digest: String,
    pub original_review_digest: String,
    pub outbox_path: PathBuf,
    pub database_key_commitment: [u8; 32],
}
impl SetupIntent {
    pub fn validate(&self, database: &[u8; 32]) -> Result<()> {
        for hash in [&self.verifier_digest, &self.original_review_digest] {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Error::InvalidData);
            }
        }
        if !self.outbox_path.is_absolute()
            || self.outbox_path.as_os_str().len() > 4096
            || self.outbox_path.file_name().and_then(|s| s.to_str())
                != Some(super::export_setup::OUTBOX)
            || self
                .outbox_path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            || self.database_key_commitment
                != PlannedNamedVerifierOutboxInitialization::database_key_commitment(
                    &DatabaseKey::from_bytes(*database),
                )
        {
            return Err(Error::InvalidData);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecipientPin {
    pub network_profile_id: String,
    pub agreement_id: String,
    pub recipient_account_id: String,
    pub recipient_transport_key: [u8; 32],
    pub native_review_digest: String,
}
impl RecipientPin {
    pub fn key(&self) -> Result<String> {
        wholepact_core::proposal::canonical_digest(
            "wholepact:named-verifier-recipient-pin:v1",
            &(
                &self.network_profile_id,
                &self.agreement_id,
                &self.recipient_account_id,
            ),
        )
        .map_err(|_| Error::InvalidData)
    }
    pub fn validate(&self) -> Result<()> {
        for id in [
            &self.network_profile_id,
            &self.agreement_id,
            &self.recipient_account_id,
        ] {
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
            {
                return Err(Error::InvalidData);
            }
        }
        if self.native_review_digest.len() != 64
            || !self
                .native_review_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidData);
        }
        TransportPublicKey::from_bytes(self.recipient_transport_key)
            .map_err(|_| Error::InvalidData)?;
        Ok(())
    }
}
impl ExportIdentity {
    pub fn validate(&self) -> Result<()> {
        self.validate_metadata()?;
        TransportSecret::from_bytes(self.secrets.transport)
            .map_err(|_| Error::InvalidData)?
            .public_key()
            .map_err(|_| Error::InvalidData)?;
        Ok(())
    }
    pub fn validate_metadata(&self) -> Result<()> {
        self.setup_intent.validate(&self.secrets.database)?;
        if self.version != 1
            || self.secrets.database == [0; 32]
            || self.secrets.database == self.secrets.transport
            || self.pins.len() > 128
        {
            return Err(Error::InvalidData);
        }
        for (key, pin) in &self.pins {
            pin.validate()?;
            if &pin.key()? != key {
                return Err(Error::InvalidData);
            }
        }
        if self.state == SetupState::Prepared && !self.pins.is_empty() {
            return Err(Error::InvalidData);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::{SecureRandom, SystemRandom};

    fn identity() -> ExportIdentity {
        let mut transport = [0; 32];
        let mut database = [0; 32];
        SystemRandom::new().fill(&mut transport).unwrap();
        SystemRandom::new().fill(&mut database).unwrap();
        ExportIdentity {
            version: 1,
            secrets: ExportSecrets {
                transport,
                database,
            },
            setup_intent: SetupIntent {
                verifier_digest: "ab".repeat(32),
                original_review_digest: "cd".repeat(32),
                outbox_path: PathBuf::from("/tmp/wholepact-fixture/named-verifier-outbox.sqlite"),
                database_key_commitment:
                    PlannedNamedVerifierOutboxInitialization::database_key_commitment(
                        &DatabaseKey::from_bytes(database),
                    ),
            },
            state: SetupState::Prepared,
            pins: BTreeMap::new(),
        }
    }
    fn pin(identity: &ExportIdentity) -> RecipientPin {
        RecipientPin {
            network_profile_id: "test-network".into(),
            agreement_id: "agreement-a".into(),
            recipient_account_id: "account-a".into(),
            recipient_transport_key: TransportSecret::from_bytes(identity.secrets.transport)
                .unwrap()
                .public_key()
                .unwrap()
                .as_bytes()
                .to_owned(),
            native_review_digest: "ab".repeat(32),
        }
    }
    #[test]
    fn prepared_setup_cannot_contain_recipient_pins() {
        let mut identity = identity();
        identity.validate().unwrap();
        let pin = pin(&identity);
        identity.pins.insert(pin.key().unwrap(), pin);
        assert!(identity.validate().is_err());
        identity.state = SetupState::Ready;
        identity.validate().unwrap();
    }
    #[test]
    fn pin_storage_key_binds_network_agreement_and_account() {
        let mut identity = identity();
        identity.state = SetupState::Ready;
        let mut pin = pin(&identity);
        let original = pin.key().unwrap();
        pin.network_profile_id.push_str("-changed");
        assert_ne!(original, pin.key().unwrap());
        pin.network_profile_id = "test-network".into();
        pin.agreement_id.push_str("-changed");
        assert_ne!(original, pin.key().unwrap());
        pin.agreement_id = "agreement-a".into();
        pin.recipient_account_id.push_str("-changed");
        assert_ne!(original, pin.key().unwrap());
        identity.pins.insert(original, pin);
        assert!(identity.validate().is_err());
    }
    #[test]
    fn malformed_or_aliased_transport_identity_is_rejected() {
        let mut identity = identity();
        identity.secrets.database = identity.secrets.transport;
        assert!(identity.validate().is_err());
        identity.secrets.database = [0; 32];
        assert!(identity.validate().is_err());
        identity.secrets.database = [1; 32];
        identity.version = 2;
        assert!(identity.validate().is_err());
    }
}
