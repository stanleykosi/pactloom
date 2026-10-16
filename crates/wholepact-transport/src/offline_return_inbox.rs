//! Staged exact offline-result import. No retained-original producer, export
//! factory, signature assurance, signer permission or dispatch authority exists.
//! The generic Authorization and raw open/seal/outbox routes remain incompatible.
use crate::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use wholepact_authority::{
    AccountPolicy,
    offline::{OfflineAuthorizationAdmission, OfflineAuthorizationTerms, OfflineEnrollmentPolicy},
};
use zeroize::Zeroize;

const FIELD: &str = "offline-authorization-return-v1";
const MAX_RETURN_BYTES: usize = 16_384;

/// Protected original from a future authenticated journal composition. No
/// constructor, Clone, Deserialize, Debug or DTO conversion. In particular,
/// neither OfflineOriginHistory nor an incoming return can create this value.
/// The producer must authenticate the original account enrollment, committed
/// admission, native final consent, key-use fence, retained exact result and
/// approved signature-only projection, including source/redacted artifact linkage.
/// Serialized file data cannot manufacture this retained original.
/// ```compile_fail
/// use wholepact_transport::RetainedOfflineReturnOriginal;
/// let _ = serde_json::from_str::<RetainedOfflineReturnOriginal>("{}");
/// ```
pub struct RetainedOfflineReturnOriginal {
    /// Captured by the absent protected original producer from its configured
    /// authenticated inbox. Never captured from the caller's inbox at import.
    inbox_identity: InboxDatabaseIdentity,
    account: AccountPolicy,
    enrollment: OfflineEnrollmentPolicy,
    admission: OfflineAuthorizationAdmission,
    original_consent_ref: String,
    native_review_digest: String,
    signed_artifact_digest: String,
    projection_digest: String,
    online_proved_artifact_digest: String,
    account_fvk_digest: String,
    return_order: MessageOrder,
    purpose: String,
    persistence_warning: String,
}
impl RetainedOfflineReturnOriginal {
    pub fn terms(&self) -> &OfflineAuthorizationTerms {
        &self.admission.request.intent.terms
    }
    pub fn online_proved_artifact_digest(&self) -> &str {
        &self.online_proved_artifact_digest
    }
    pub fn original_consent_ref(&self) -> &str {
        &self.original_consent_ref
    }
    pub fn account_fvk_digest(&self) -> &str {
        &self.account_fvk_digest
    }
    fn validate(&self) -> Result<()> {
        self.admission
            .validate_reserved_policy_bounds(&self.account, &self.enrollment)
            .map_err(|_| TransportError::WrongContext)?;
        for h in [
            &self.original_consent_ref,
            &self.native_review_digest,
            &self.signed_artifact_digest,
            &self.projection_digest,
            &self.online_proved_artifact_digest,
            &self.account_fvk_digest,
        ] {
            crate::types::validate_hex(h, 32)?;
        }
        self.return_order.validate(&self.return_order.issued_at)?;
        crate::types::validate_text(&self.purpose)?;
        crate::types::validate_text(&self.persistence_warning)?;
        if self.original_consent_ref
            == self
                .admission
                .request
                .intent
                .intent_digest()
                .map_err(|_| TransportError::WrongContext)?
        {
            return Err(TransportError::WrongContext);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReturnPayload {
    schema_version: u16,
    account_id: String,
    authorization_id: String,
    original_consent_ref: String,
    native_review_digest: String,
    admission_request_digest: String,
    intent_digest: String,
    terms_digest: String,
    review_package_digest: String,
    reviewed_artifact_digest: String,
    online_proved_artifact_digest: String,
    manifest_digest: String,
    effects_digest: String,
    review_binding: String,
    signed_artifact_digest: String,
    signatures: Vec<ReturnedSignature>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReturnedSignature {
    action_index: u64,
    signature_hex: String,
}
impl Drop for ReturnedSignature {
    fn drop(&mut self) {
        self.signature_hex.zeroize();
    }
}

/// Authenticated original-bound wire data, not cryptographic signature assurance.
/// Constructible only after exact pinned-envelope and payload validation here.
pub struct OfflineReturnData {
    payload: ReturnPayload,
}
impl OfflineReturnData {
    pub fn account_id(&self) -> &str {
        &self.payload.account_id
    }
    pub fn effects_digest(&self) -> &str {
        &self.payload.effects_digest
    }
    pub fn signatures(&self) -> impl Iterator<Item = (u64, &str)> {
        self.payload
            .signatures
            .iter()
            .map(|s| (s.action_index, s.signature_hex.as_str()))
    }
}

/// Durable encrypted transport receipt only. No signature, current-chain,
/// native-consent, financial-intake or permission success flag is exposed.
pub struct OfflineReturnInboxReceipt {
    data: OfflineReturnData,
    envelope_digest: String,
    content_digest: String,
}
impl OfflineReturnInboxReceipt {
    pub fn data(&self) -> &OfflineReturnData {
        &self.data
    }
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}
/// Historical transport evidence deliberately has a distinct type. It cannot
/// become a fresh return or renew signing/authority/transport lifetimes.
pub struct RecoveredOfflineReturn {
    receipt: OfflineReturnInboxReceipt,
}
impl RecoveredOfflineReturn {
    pub fn receipt(&self) -> &OfflineReturnInboxReceipt {
        &self.receipt
    }
}

fn context(original: &RetainedOfflineReturnOriginal) -> MessageContext {
    let t = original.terms();
    MessageContext {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        sender_id: format!("offline-return:{}", t.offline_signer_key_digest),
        recipient_id: format!("offline-return:{}", t.return_recipient_key_digest),
        artifact_kind: ArtifactKind::OfflineAuthorizationReturn,
    }
}
fn check_keys(
    original: &RetainedOfflineReturnOriginal,
    recipient: &TransportSecret,
    sender: &TransportPublicKey,
    inbox: &SqliteReplayLedger,
) -> Result<()> {
    original.validate()?;
    if inbox.protection() != MailboxProtection::Encrypted {
        return Err(TransportError::AuthorityUnavailable);
    }
    if inbox.database_identity()? != original.inbox_identity {
        return Err(TransportError::AuthorityUnavailable);
    }
    if sender.fingerprint() != original.terms().offline_signer_key_digest
        || recipient.public_key()?.fingerprint() != original.terms().return_recipient_key_digest
    {
        return Err(TransportError::Authentication);
    }
    Ok(())
}
fn parse_payload(fields: &[DisclosureField]) -> Result<ReturnPayload> {
    if fields.len() != 1 || fields[0].name() != FIELD {
        return Err(TransportError::WrongContext);
    }
    let raw = fields[0].bytes();
    if raw.len() > MAX_RETURN_BYTES {
        return Err(TransportError::ResourceLimit);
    }
    let p: ReturnPayload = crate::types::parse(raw)?;
    let canonical = zeroize::Zeroizing::new(crate::types::encode(&p)?);
    if canonical.as_slice() != raw {
        return Err(TransportError::Malformed);
    }
    if p.schema_version != 1 || p.signatures.is_empty() || p.signatures.len() > 64 {
        return Err(TransportError::Malformed);
    }
    let mut prior = None;
    for s in &p.signatures {
        crate::types::validate_hex(&s.signature_hex, 64)?;
        if prior.is_some_and(|p| p >= s.action_index) {
            return Err(TransportError::Malformed);
        }
        prior = Some(s.action_index);
    }
    Ok(p)
}
fn validate_return(
    artifact: &ReceivedArtifact,
    original: &RetainedOfflineReturnOriginal,
) -> Result<OfflineReturnData> {
    let preview = artifact.preview();
    if preview.context != context(original)
        || preview.order != original.return_order
        || preview.purpose != original.purpose
        || preview.persistence_warning != original.persistence_warning
    {
        return Err(TransportError::WrongContext);
    }
    let p = parse_payload(artifact.fields())?;
    if hex::encode(Sha256::digest(artifact.fields()[0].bytes())) != original.projection_digest {
        return Err(TransportError::WrongContext);
    }
    let t = original.terms();
    if p.account_id != t.account_id
        || p.authorization_id != t.authorization_id
        || p.original_consent_ref != original.original_consent_ref
        || p.native_review_digest != original.native_review_digest
        || p.admission_request_digest != original.admission.request_digest
        || p.intent_digest
            != original
                .admission
                .request
                .intent
                .intent_digest()
                .map_err(|_| TransportError::WrongContext)?
        || p.terms_digest != t.terms_digest().map_err(|_| TransportError::WrongContext)?
        || p.review_package_digest != t.review_package_digest
        || p.reviewed_artifact_digest != t.artifact_digest
        || p.online_proved_artifact_digest != original.online_proved_artifact_digest
        || p.manifest_digest != t.manifest_digest
        || p.effects_digest != t.effects_digest
        || p.review_binding != t.review_binding
        || p.signed_artifact_digest != original.signed_artifact_digest
    {
        return Err(TransportError::WrongContext);
    }
    let wanted: BTreeSet<_> = t.inputs.iter().map(|i| i.action_index).collect();
    let actual: BTreeSet<_> = p.signatures.iter().map(|s| s.action_index).collect();
    if wanted != actual || actual.len() != p.signatures.len() {
        return Err(TransportError::WrongContext);
    }
    Ok(OfflineReturnData { payload: p })
}

/// Dedicated pinned import. The callback may only add validation; its result is
/// returned separately and never upgrades this transport receipt to authority.
/// The concrete engine callback performs real proof/economic/signature checks
/// before encrypted replay insertion. Invalid returns do not consume sequence.
/// There is no caller-implemented replay ledger and no financial journal mutation.
pub fn accept_offline_return_checked<V>(
    envelope: &EncryptedEnvelope,
    recipient: &TransportSecret,
    sender: &TransportPublicKey,
    original: &RetainedOfflineReturnOriginal,
    now: &Timestamp,
    inbox: &mut SqliteReplayLedger,
    verify: impl FnOnce(&OfflineReturnData) -> Result<V>,
) -> Result<(OfflineReturnInboxReceipt, V)> {
    let started = std::time::Instant::now();
    check_keys(original, recipient, sender, inbox)?;
    let remaining_seconds = original
        .return_order
        .expires_at
        .unix_seconds()
        .checked_sub(now.unix_seconds())
        .filter(|seconds| *seconds > 0)
        .ok_or(TransportError::InvalidTime)?;
    let original_remaining = std::time::Duration::from_secs(remaining_seconds as u64);
    let (artifact, receipt) =
        crate::envelope::authenticate(envelope, recipient, sender, &context(original), Some(now))?;
    let data = validate_return(&artifact, original)?;
    let verified = verify(&data)?;
    check_keys(original, recipient, sender, inbox)?;
    if started.elapsed() >= original_remaining {
        return Err(TransportError::InvalidTime);
    }
    inbox.accept_authenticated(&receipt, envelope.as_bytes())?;
    // A late failure may follow an already committed ciphertext receipt. It
    // cannot be retried as a fresh sequence or imply that nothing was retained.
    check_keys(original, recipient, sender, inbox)?;
    Ok((
        OfflineReturnInboxReceipt {
            data,
            envelope_digest: artifact.envelope_digest().into(),
            content_digest: artifact.content_digest().into(),
        },
        verified,
    ))
}

/// Reauthenticates only the exact retained ciphertext and reruns the same checks.
/// No insertion, replacement, current-time approval or fresh-return conversion.
pub fn recover_offline_return_checked<V>(
    recipient: &TransportSecret,
    sender: &TransportPublicKey,
    original: &RetainedOfflineReturnOriginal,
    inbox: &SqliteReplayLedger,
    verify: impl FnOnce(&OfflineReturnData) -> Result<V>,
) -> Result<Option<(RecoveredOfflineReturn, V)>> {
    check_keys(original, recipient, sender, inbox)?;
    let expected = context(original);
    let Some(retained) = inbox.retained_for_context(&expected, original.return_order.sequence)?
    else {
        return Ok(None);
    };
    let (artifact, authenticated) =
        crate::envelope::authenticate(&retained.envelope, recipient, sender, &expected, None)?;
    if !retained.matches(&authenticated) {
        return Err(TransportError::Authentication);
    }
    let data = validate_return(&artifact, original)?;
    let verified = verify(&data)?;
    check_keys(original, recipient, sender, inbox)?;
    Ok(Some((
        RecoveredOfflineReturn {
            receipt: OfflineReturnInboxReceipt {
                data,
                envelope_digest: artifact.envelope_digest().into(),
                content_digest: artifact.content_digest().into(),
            },
        },
        verified,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn raw_claim() -> ReturnPayload {
        ReturnPayload {
            schema_version: 1,
            account_id: "synthetic-owner".into(),
            authorization_id: "synthetic-authorization".into(),
            original_consent_ref: "1".repeat(64),
            native_review_digest: "2".repeat(64),
            admission_request_digest: "3".repeat(64),
            intent_digest: "4".repeat(64),
            terms_digest: "5".repeat(64),
            review_package_digest: "6".repeat(64),
            reviewed_artifact_digest: "7".repeat(64),
            online_proved_artifact_digest: "8".repeat(64),
            manifest_digest: "9".repeat(64),
            effects_digest: "a".repeat(64),
            review_binding: "b".repeat(64),
            signed_artifact_digest: "c".repeat(64),
            signatures: vec![ReturnedSignature {
                action_index: 1,
                signature_hex: "0".repeat(128),
            }],
        }
    }
    fn field(p: &ReturnPayload) -> Vec<DisclosureField> {
        vec![DisclosureField::new(FIELD, crate::types::encode(p).unwrap()).unwrap()]
    }
    #[test]
    fn canonical_wire_parse_is_only_a_claim_not_a_capability() {
        assert!(parse_payload(&field(&raw_claim())).is_ok());
        // This deliberately does not construct RetainedOfflineReturnOriginal,
        // a transport receipt, native consent, or cryptographic signature evidence.
    }
    #[test]
    fn empty_excess_and_duplicate_signature_lists_fail() {
        let mut p = raw_claim();
        p.signatures.clear();
        assert!(parse_payload(&field(&p)).is_err());
        p.signatures = (0..65)
            .map(|action_index| ReturnedSignature {
                action_index,
                signature_hex: "0".repeat(128),
            })
            .collect();
        assert!(parse_payload(&field(&p)).is_err());
        p.signatures = vec![
            ReturnedSignature {
                action_index: 1,
                signature_hex: "0".repeat(128),
            },
            ReturnedSignature {
                action_index: 1,
                signature_hex: "0".repeat(128),
            },
        ];
        assert!(parse_payload(&field(&p)).is_err());
    }
    #[test]
    fn alternate_signature_order_uppercase_and_wrong_width_fail() {
        let mut p = raw_claim();
        p.signatures[0].signature_hex = "A".repeat(128);
        assert!(parse_payload(&field(&p)).is_err());
        p.signatures[0].signature_hex = "0".repeat(126);
        assert!(parse_payload(&field(&p)).is_err());
        p.signatures = vec![
            ReturnedSignature {
                action_index: 2,
                signature_hex: "0".repeat(128),
            },
            ReturnedSignature {
                action_index: 1,
                signature_hex: "0".repeat(128),
            },
        ];
        assert!(parse_payload(&field(&p)).is_err());
    }
    #[test]
    fn noncanonical_json_and_unsupported_version_fail() {
        let mut p = raw_claim();
        p.schema_version = 2;
        assert!(parse_payload(&field(&p)).is_err());
        p.schema_version = 1;
        let mut bytes = crate::types::encode(&p).unwrap();
        bytes.push(b' ');
        assert!(parse_payload(&[DisclosureField::new(FIELD, bytes).unwrap()]).is_err());
    }
    #[test]
    fn return_field_does_not_alias_online_authorization_or_admission() {
        for field in [
            "external_spend_signatures_v1",
            "offline-minimal-admission-v1",
        ] {
            let input = vec![DisclosureField::new(field, b"{}".to_vec()).unwrap()];
            assert!(matches!(
                parse_payload(&input),
                Err(TransportError::WrongContext)
            ));
        }
        assert!(matches!(
            parse_payload(&[]),
            Err(TransportError::WrongContext)
        ));
    }
    #[test]
    fn extra_unknown_and_oversized_return_fields_are_rejected() {
        let input = vec![
            DisclosureField::new(FIELD, b"{}".to_vec()).unwrap(),
            DisclosureField::new("extra", b"{}".to_vec()).unwrap(),
        ];
        assert!(matches!(
            parse_payload(&input),
            Err(TransportError::WrongContext)
        ));
        let input = vec![DisclosureField::new(FIELD, vec![b' '; MAX_RETURN_BYTES + 1]).unwrap()];
        assert!(matches!(
            parse_payload(&input),
            Err(TransportError::ResourceLimit)
        ));
        let input = vec![DisclosureField::new(FIELD, b"{\"verified\":true}".to_vec()).unwrap()];
        assert!(matches!(
            parse_payload(&input),
            Err(TransportError::Malformed)
        ));
    }
}
