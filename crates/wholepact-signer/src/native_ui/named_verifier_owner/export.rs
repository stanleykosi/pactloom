//! Exact native disclosure of a retained signed assertion. No signing or witness
//! admission occurs here. Committed ciphertext is recovered before any new seal.
use super::{
    export_identity::{RecipientPin, SetupState},
    NativeAuthorityBinding, NativeDecision, VerifierOwner,
};
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use wholepact_transport::{
    ArtifactKind, DisclosureField, ExportRequest, MessageContext, MessageOrder, OutboxArtifact,
    PreparedExport, Timestamp, TransportPublicKey, TransportSecret,
};
const FIELD: &str = "named-verifier-assertion-v1";
fn now() -> Result<Timestamp> {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Locked)?
        .as_secs();
    Timestamp::from_unix_seconds(i64::try_from(n).map_err(|_| Error::Locked)?)
        .map_err(|_| Error::Locked)
}
fn digest<T: serde::Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::InvalidData)
}
pub(super) struct PreparedRecipientPin {
    row: String,
    pin: RecipientPin,
    digest: String,
    commitment: String,
    source: NativeAuthorityBinding,
    display: String,
}
pub(super) struct PreparedAssertionExport {
    row: String,
    filename: String,
    context: MessageContext,
    recipient: TransportPublicKey,
    message_id: String,
    payload_digest: String,
    prepared: Option<PreparedExport>,
    prior: Option<OutboxArtifact>,
    digest: String,
    commitment: String,
    source: NativeAuthorityBinding,
    display: String,
}
impl VerifierOwner {
    fn export_context(&self, row: &str) -> Result<MessageContext> {
        self.check_current()?;
        let entry = self.journal.rows.get(row).ok_or(Error::InvalidData)?;
        let terms = entry
            .original_terms
            .as_ref()
            .ok_or(Error::RecoveryRequired)?;
        if wholepact_offline_bridge::named_verifier_original_context_digest(terms)
            .map_err(|_| Error::Verification)?
            != entry.statement.original_context_digest
            || terms.account_id != entry.statement.recipient_account_id
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(MessageContext {
            network_profile_id: terms.network_profile_id.clone(),
            agreement_id: terms.agreement_id.clone(),
            proposal_id: terms.proposal_id.clone(),
            proposal_revision: terms.proposal_revision,
            sender_id: hex::encode(Sha256::digest(self.public_key())),
            recipient_id: terms.account_id.clone(),
            artifact_kind: ArtifactKind::NamedVerifierAssertion,
        })
    }
    pub(super) fn prepare_recipient_pin(
        &self,
        row: &str,
        recipient_key: [u8; 32],
    ) -> Result<PreparedRecipientPin> {
        self.check_current()?;
        self.journal.retained_package(row)?;
        let identity = self
            .journal
            .export_identity
            .as_ref()
            .ok_or(Error::Unavailable)?;
        if identity.state != SetupState::Ready || self.journal.restored_informational {
            return Err(Error::RecoveryRequired);
        }
        let context = self.export_context(row)?;
        let recipient =
            TransportPublicKey::from_bytes(recipient_key).map_err(|_| Error::InvalidData)?;
        let terms = self.journal.rows[row]
            .original_terms
            .as_ref()
            .ok_or(Error::InvalidData)?;
        if recipient.fingerprint() != terms.offline_signer_key_digest {
            return Err(Error::ReviewMismatch);
        }
        let commitment = self.state_commitment()?;
        let digest = digest(
            "wholepact:native-named-recipient-pin:v1",
            &(
                row,
                &context,
                recipient_key,
                &commitment,
                self.source.entry_digest(),
            ),
        )?;
        let pin = RecipientPin {
            network_profile_id: context.network_profile_id,
            agreement_id: context.agreement_id,
            recipient_account_id: context.recipient_id,
            recipient_transport_key: recipient_key,
            native_review_digest: digest.clone(),
        };
        pin.validate()?;
        if let Some(prior) = identity.pins.get(&pin.key()?) {
            if prior.recipient_transport_key != recipient_key {
                return Err(Error::ReviewMismatch);
            }
        }
        let display=format!("PIN EXACT OFFLINE ASSERTION RECIPIENT\nAccount: {}\nAgreement: {}\nNetwork: {}\nTransport key: {}\nFingerprint: {}\nOriginal retained row: {}\nVerify this key independently on the intended recipient device. A key from a package cannot authenticate itself. This pin must also match the original retained authorization terms. The assertion remains named-verifier evidence, not authority to spend.\nExact review: {}",pin.recipient_account_id,pin.agreement_id,pin.network_profile_id,hex::encode(recipient_key),recipient.fingerprint(),row,digest);
        Ok(PreparedRecipientPin {
            row: row.into(),
            pin,
            digest,
            commitment,
            source: self.source.clone(),
            display,
        })
    }
    pub(super) fn prepare_assertion_export(&self, row: &str) -> Result<PreparedAssertionExport> {
        self.check_current()?;
        let package = self.journal.retained_package(row)?;
        let bytes = package.canonical_bytes().map_err(|_| Error::Verification)?;
        let context = self.export_context(row)?;
        let identity = self
            .journal
            .export_identity
            .as_ref()
            .ok_or(Error::Unavailable)?;
        identity.validate()?;
        let pin_key = digest(
            "wholepact:named-verifier-recipient-pin:v1",
            &(
                &context.network_profile_id,
                &context.agreement_id,
                &context.recipient_id,
            ),
        )?;
        let pin = identity.pins.get(&pin_key).ok_or(Error::ReviewMismatch)?;
        pin.validate()?;
        let recipient = TransportPublicKey::from_bytes(pin.recipient_transport_key)
            .map_err(|_| Error::InvalidData)?;
        let terms = self.journal.rows[row]
            .original_terms
            .as_ref()
            .ok_or(Error::InvalidData)?;
        if recipient.fingerprint() != terms.offline_signer_key_digest {
            return Err(Error::ReviewMismatch);
        }
        let sender = TransportSecret::from_bytes(identity.secrets.transport)
            .map_err(|_| Error::Crypto)?
            .public_key()
            .map_err(|_| Error::Crypto)?;
        let fields = vec![DisclosureField::new(FIELD, bytes).map_err(|_| Error::InvalidData)?];
        let payload_digest = wholepact_transport::disclosure_payload_digest(&fields)
            .map_err(|_| Error::InvalidData)?;
        let message_id = digest(
            "wholepact:named-assertion-original-export:v1",
            &(
                row,
                &context,
                &payload_digest,
                recipient.fingerprint(),
                sender.fingerprint(),
            ),
        )?[..32]
            .to_string();
        let outbox = self.open_export_outbox()?;
        let prior = outbox
            .recover_message_for_recipient(
                &context,
                &recipient,
                &message_id,
                &payload_digest,
                &sender,
            )
            .map_err(|_| Error::Verification)?;
        let prepared = if prior.is_none() {
            let current = now()?;
            let issued_at = Timestamp::from_unix_seconds(
                i64::try_from(package.statement.validity_not_before_ms.div_ceil(1000))
                    .map_err(|_| Error::InvalidData)?,
            )
            .map_err(|_| Error::InvalidData)?;
            let expires_at = Timestamp::from_unix_seconds(
                i64::try_from(package.statement.validity_expires_ms / 1000)
                    .map_err(|_| Error::InvalidData)?,
            )
            .map_err(|_| Error::InvalidData)?;
            let request=ExportRequest{context:context.clone(),order:MessageOrder{message_id:message_id.clone(),sequence:outbox.next_sequence(&context).map_err(|_|Error::Verification)?,issued_at,expires_at},purpose:"Exact named-verifier assertion; no spending authority".into(),persistence_warning:"Recipient copies persist; disclosure cannot be recalled. Original validity is never renewed.".into()};
            Some(
                wholepact_transport::prepare_export(request, fields, &sender, &recipient, &current)
                    .map_err(|_| Error::Verification)?,
            )
        } else {
            None
        };
        let filename = format!("assertion-{row}.wpe");
        let commitment = self.state_commitment()?;
        let exact = prepared
            .as_ref()
            .map(|p| p.preview().digest())
            .transpose()
            .map_err(|_| Error::Verification)?
            .or_else(|| prior.as_ref().map(|p| p.preview_digest().to_owned()))
            .ok_or(Error::InvalidData)?;
        let digest = digest(
            "wholepact:native-named-assertion-export:v1",
            &(
                row,
                &filename,
                &context,
                &payload_digest,
                &exact,
                &commitment,
                self.source.entry_digest(),
            ),
        )?;
        let display=format!("EXPORT EXACT ENCRYPTED ASSERTION\nOriginal row: {}\nRecipient: {}\nRecipient transport fingerprint: {}\nPackage payload commitment: {}\nOriginal transport preview: {}\nPrivate filename: {}\n{}\nThe package contains the redacted artifact and named-verifier allocation assertion, never peer viewing keys. This creates no reservation, signature authorization or settlement. Delivery remains unknown until an authenticated recipient receipt. Copying historical expired ciphertext cannot renew its validity.\nExact review: {}",row,context.recipient_id,recipient.fingerprint(),payload_digest,exact,filename,if prior.is_some(){"Recovering exact previously committed ciphertext; no resealing."}else{"New ciphertext and sequence commit atomically before file disclosure."},digest);
        Ok(PreparedAssertionExport {
            row: row.into(),
            filename,
            context,
            recipient,
            message_id,
            payload_digest,
            prepared,
            prior,
            digest,
            commitment,
            source: self.source.clone(),
            display,
        })
    }
}
impl PreparedRecipientPin {
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    pub(super) fn approve(self, owner: &mut VerifierOwner, decision: NativeDecision) -> Result<()> {
        owner.check_current()?;
        if owner.source != self.source
            || owner.state_commitment()? != self.commitment
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        owner.journal.retained_package(&self.row)?;
        let _publication = self.source.publication_lease()?;
        let state = owner
            .journal
            .export_identity
            .as_mut()
            .ok_or(Error::Unavailable)?;
        let key = self.pin.key()?;
        if let Some(old) = state.pins.get(&key) {
            if old.recipient_transport_key != self.pin.recipient_transport_key {
                return Err(Error::ReviewMismatch);
            }
            return Ok(());
        }
        if state.pins.len() >= 128 {
            return Err(Error::InvalidData);
        }
        state.pins.insert(key, self.pin);
        if owner.persist().is_err() {
            owner.poisoned = true;
            return Err(Error::Uncertain);
        }
        Ok(())
    }
}
impl PreparedAssertionExport {
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    pub(super) fn approve(
        self,
        owner: &mut VerifierOwner,
        decision: NativeDecision,
    ) -> Result<String> {
        owner.check_current()?;
        if owner.source != self.source
            || owner.state_commitment()? != self.commitment
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        owner.journal.retained_package(&self.row)?;
        let _publication = self.source.publication_lease()?;
        let identity = owner
            .journal
            .export_identity
            .as_ref()
            .ok_or(Error::Unavailable)?;
        let sender =
            TransportSecret::from_bytes(identity.secrets.transport).map_err(|_| Error::Crypto)?;
        let mut outbox = owner.open_export_outbox()?;
        let current = outbox
            .recover_message_for_recipient(
                &self.context,
                &self.recipient,
                &self.message_id,
                &self.payload_digest,
                &sender.public_key().map_err(|_| Error::Crypto)?,
            )
            .map_err(|_| Error::Verification)?;
        let result = (|| -> Result<()> {
            self.source.check_current()?;
            let artifact = match (self.prior, current, self.prepared) {
                (Some(prior), Some(current), None)
                    if prior.envelope().as_bytes() == current.envelope().as_bytes() =>
                {
                    current
                }
                (None, None, Some(prepared)) => {
                    let preview = prepared
                        .preview()
                        .digest()
                        .map_err(|_| Error::Verification)?;
                    outbox
                        .enqueue(prepared, &sender, &preview, &now()?)
                        .map_err(|_| Error::Uncertain)?
                }
                _ => return Err(Error::ReviewMismatch),
            };
            self.source.check_current()?;
            if owner.directory.exists(&self.filename)? {
                let bytes = owner
                    .directory
                    .read(&self.filename, wholepact_transport::MAX_FILE_BYTES)?;
                if bytes != artifact.envelope().as_bytes() {
                    return Err(Error::ReviewMismatch);
                }
            } else {
                owner
                    .directory
                    .write(&self.filename, artifact.envelope().as_bytes())?;
            }
            Ok(())
        })();
        if result.is_err() {
            owner.poisoned = true;
            return Err(Error::Uncertain);
        }
        Ok(self.filename)
    }
}
