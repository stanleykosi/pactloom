//! Source-only offline transport foundation. No issuance, native spending consent,
//! key provisioning, or conversion into authority journal permission is exposed.
//! Authenticated payloads remain evidence until a sealed authority-owned adapter
//! checks current enrollment and writer/session state inside its transaction.
#![forbid(unsafe_code)]

mod selected_effects;
pub use selected_effects::*;
mod recipient_review;
pub use recipient_review::*;
mod witness;
mod control;
pub use control::*;

use serde::de::DeserializeOwned;
use wholepact_authority::offline::{
    OfflineAuthorizationAdmission, OfflineEnrollmentPolicy, OfflineReservationIntent,
    ReserveOfflineAuthorization,
};
use wholepact_core::parse_typed_json;
use wholepact_transport::{
    open_envelope_checked, recover_received, ArtifactKind, DisclosureField, EncryptedEnvelope,
    MailboxProtection, MessageContext, ReceivedArtifact, SqliteReplayLedger,
    Timestamp, TransportError, TransportPublicKey, TransportSecret, MAX_PAYLOAD_BYTES,
};

type Result<T> = std::result::Result<T, TransportError>;
const INTENT_FIELD: &str = "offline-reservation-intent-v1";
const ADMISSION_FIELD: &str = "offline-authority-admission-v1";

/// Transport-authenticated evidence only, not native approval, current owner
/// enrollment, account attribution, a durable reservation, or journal permission.
/// No Serialize/Deserialize/Clone/Debug or caller-controlled constructor.
pub struct OfflineIntentEnvelopeEvidence {
    intent: OfflineReservationIntent,
    envelope_digest: String,
    content_digest: String,
}
impl OfflineIntentEnvelopeEvidence {
    pub fn intent(&self) -> &OfflineReservationIntent { &self.intent }
    pub fn envelope_digest(&self) -> &str { &self.envelope_digest }
    pub fn content_digest(&self) -> &str { &self.content_digest }
}

/// Resolve dedicated wire kinds only. Legacy Authorization/Contribution kinds
/// can never stand in for these protocols. On today's transport this fails closed.
fn offline_kind(name: &str) -> Result<ArtifactKind> {
    let encoded = serde_json::to_vec(name).map_err(|_| TransportError::Malformed)?;
    serde_json::from_slice(&encoded).map_err(|_| TransportError::AuthorityUnavailable)
}

/// Expected context is built from retained exact intent and locally retained
/// enrollment. It must never be selected from imported envelope labels.
/// Dedicated direction labels isolate ordering from ordinary participant traffic.
pub fn intent_context(intent: &OfflineReservationIntent) -> Result<MessageContext> {
    intent.validate().map_err(|_| TransportError::Malformed)?;
    let t = &intent.terms;
    if t.proposal_revision == 0 { return Err(TransportError::WrongContext); }
    Ok(MessageContext {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        sender_id: format!("offline-intent:{}", t.offline_signer_key_digest),
        recipient_id: format!("offline-intent:{}", t.offline_policy_digest),
        artifact_kind: offline_kind("offline_reservation_intent")?,
    })
}

fn exact_field<T: DeserializeOwned + serde::Serialize>(fields: &[DisclosureField], name: &str) -> Result<T> {
    if fields.len() != 1 || fields[0].name() != name {
        return Err(TransportError::WrongContext);
    }
    let bytes = fields[0].bytes();
    if bytes.len() > MAX_PAYLOAD_BYTES { return Err(TransportError::ResourceLimit); }
    let parsed: T = parse_typed_json(bytes).map_err(|_| TransportError::Malformed)?;
    // One canonical payload representation; reject duplicate keys, extra fields,
    // whitespace/ordering aliases and alternate encodings before inbox acceptance.
    if serde_json::to_vec(&parsed).map_err(|_| TransportError::Malformed)? != bytes {
        return Err(TransportError::Malformed);
    }
    Ok(parsed)
}

fn validate_intent_payload(artifact: &ReceivedArtifact, expected: &OfflineReservationIntent) -> Result<()> {
    let intent: OfflineReservationIntent = exact_field(artifact.fields(), INTENT_FIELD)?;
    intent.validate().map_err(|_| TransportError::Malformed)?;
    if intent != *expected { return Err(TransportError::WrongContext); }
    Ok(())
}

/// Authenticate the enrolled signer key independently of the controller's mTLS.
/// This deliberately cannot authorize a mutation. Raw policy bytes are only a
/// comparison input here; current owner enrollment must be obtained separately by
/// the future authority-owned transaction adapter. Exact payload equality includes
/// every term and native reservation review digest, not just a caller digest.
///
/// Requires a concrete encrypted durable inbox, not a caller-implemented ledger.
/// Domain validation occurs before replay insertion. Historical recovery uses a
/// separate evidence type and cannot resume authority until exact operation linkage
/// has been integrated into the authority journal.
#[allow(clippy::too_many_arguments)]
pub fn authenticate_intent_evidence(
    envelope: &EncryptedEnvelope,
    witness_secret: &TransportSecret,
    signer_key: &TransportPublicKey,
    policy: &OfflineEnrollmentPolicy,
    expected_intent: &OfflineReservationIntent,
    now: &Timestamp,
    inbox: &mut SqliteReplayLedger,
) -> Result<OfflineIntentEnvelopeEvidence> {
    check_enrollment_binding(witness_secret, signer_key, policy, expected_intent, inbox)?;
    let context = intent_context(expected_intent)?;
    let artifact = open_envelope_checked(
        envelope, witness_secret, signer_key, &context, now, inbox,
        |artifact| validate_intent_payload(artifact, expected_intent),
    )?;
    Ok(OfflineIntentEnvelopeEvidence {
        intent: expected_intent.clone(),
        envelope_digest: artifact.envelope_digest().to_owned(),
        content_digest: artifact.content_digest().to_owned(),
    })
}

fn check_enrollment_binding(
    witness_secret: &TransportSecret, signer_key: &TransportPublicKey,
    policy: &OfflineEnrollmentPolicy, expected_intent: &OfflineReservationIntent,
    inbox: &SqliteReplayLedger,
) -> Result<()> {
    policy.validate().map_err(|_| TransportError::Malformed)?;
    let t = &expected_intent.terms;
    if inbox.protection() != MailboxProtection::Encrypted {
        return Err(TransportError::AuthorityUnavailable);
    }
    if signer_key.fingerprint() != policy.offline_signer_key_digest
        || witness_secret.public_key()?.fingerprint() != policy.witness_transport_key_digest
        || t.offline_signer_key_digest != policy.offline_signer_key_digest
        || t.offline_policy_digest != policy.policy_digest().map_err(|_| TransportError::Malformed)?
        || t.account_id != policy.account_id
        || t.network_profile_id != policy.network_profile_id
        || t.enrollment_ref != policy.enrollment_ref
        || t.return_recipient_key_digest != policy.return_recipient_key_digest
        || t.snapshot.source_identity_digest != policy.source_identity_digest
        || t.snapshot.source_policy_digest != policy.source_policy_digest
        || t.semantics != policy.semantics
    { return Err(TransportError::Authentication); }
    Ok(())
}

/// Read-only recovered source evidence. Deliberately a distinct type from fresh
/// delivery evidence, with no conversion into an authority authentication token.
pub struct RetainedOfflineIntentEvidence {
    intent: OfflineReservationIntent,
    envelope_digest: String,
    content_digest: String,
    currently_within_transport_window: bool,
}
impl RetainedOfflineIntentEvidence {
    pub fn intent(&self) -> &OfflineReservationIntent { &self.intent }
    pub fn envelope_digest(&self) -> &str { &self.envelope_digest }
    pub fn content_digest(&self) -> &str { &self.content_digest }
    /// Delivery-window observation only, never approval, current policy or authority.
    pub fn currently_within_transport_window(&self) -> bool {
        self.currently_within_transport_window
    }
}

/// Recover exact retained ciphertext using a LOCALLY RETAINED expected intent and
/// sequence. Imported stream labels/digests never select authority. The transport
/// reauthenticates sender/context and compares its retained receipt before returning.
/// Expired entries remain recoverable history; they cannot mint new authority.
#[allow(clippy::too_many_arguments)]
pub fn recover_intent_evidence(
    witness_secret: &TransportSecret,
    signer_key: &TransportPublicKey,
    policy: &OfflineEnrollmentPolicy,
    expected_intent: &OfflineReservationIntent,
    sequence: u64,
    now: &Timestamp,
    inbox: &SqliteReplayLedger,
) -> Result<Option<RetainedOfflineIntentEvidence>> {
    check_enrollment_binding(witness_secret, signer_key, policy, expected_intent, inbox)?;
    let context = intent_context(expected_intent)?;
    let Some(retained) = inbox.retained_for_context(&context, sequence)? else {
        return Ok(None);
    };
    let recovered = recover_received(&retained, witness_secret, signer_key, &context)?;
    let artifact = recovered.artifact();
    validate_intent_payload(artifact, expected_intent)?;
    Ok(Some(RetainedOfflineIntentEvidence {
        intent: expected_intent.clone(),
        envelope_digest: artifact.envelope_digest().to_owned(),
        content_digest: artifact.content_digest().to_owned(),
        currently_within_transport_window: recovered.is_currently_valid(now),
    }))
}

/// Pure descriptor matching only. This is useful inside an authenticated envelope
/// validation closure, but DOES NOT establish witness origin or durable commitment.
/// Kept separate from any future sealed post-commit export capability.
pub fn validate_admission_fields(
    fields: &[DisclosureField], expected: &ReserveOfflineAuthorization,
) -> Result<OfflineAuthorizationAdmission> {
    let admission: OfflineAuthorizationAdmission = exact_field(fields, ADMISSION_FIELD)?;
    admission.matches_request(expected).map_err(|_| TransportError::WrongContext)?;
    Ok(admission)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_existing_kind_can_substitute_for_offline_protocol() {
        for kind in [ArtifactKind::Authorization, ArtifactKind::Contribution,
            ArtifactKind::ParticipationIntent, ArtifactKind::ProvedProposal] {
            let encoded = serde_json::to_string(&kind).unwrap();
            assert_ne!(encoded, "\"offline_reservation_intent\"");
            assert_ne!(encoded, "\"offline_authority_admission\"");
        }
    }

    #[test]
    fn unexpected_extra_fields_reject_before_domain_acceptance() {
        let fields = vec![DisclosureField::new("unexpected", b"{}".to_vec()).unwrap()];
        assert!(matches!(exact_field::<OfflineReservationIntent>(&fields, INTENT_FIELD),
            Err(TransportError::WrongContext)));
        assert!(matches!(exact_field::<OfflineReservationIntent>(&[], INTENT_FIELD),
            Err(TransportError::WrongContext)));
    }

    #[test]
    fn strict_parser_rejects_unknown_or_duplicate_payload_members() {
        for bytes in [b"{\"schema_version\":1,\"schema_version\":1}".as_slice(),
            b"{\"unexpected\":true}".as_slice()] {
            let fields = vec![DisclosureField::new(INTENT_FIELD, bytes.to_vec()).unwrap()];
            assert!(matches!(exact_field::<OfflineReservationIntent>(&fields, INTENT_FIELD),
                Err(TransportError::Malformed)));
        }
    }

    #[test]
    fn canonical_single_field_round_trips_without_aliases() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        #[serde(deny_unknown_fields)]
        struct SyntheticPayload { schema_version: u16, exact: String }
        let original = SyntheticPayload { schema_version: 1, exact: "synthetic".into() };
        let fields = vec![DisclosureField::new(INTENT_FIELD, serde_json::to_vec(&original).unwrap()).unwrap()];
        assert_eq!(exact_field::<SyntheticPayload>(&fields, INTENT_FIELD).unwrap(), original);
        for bytes in [
            br#"{ "schema_version":1,"exact":"synthetic"}"#.as_slice(),
            br#"{"exact":"synthetic","schema_version":1}"#.as_slice(),
            br#"{"schema_version":1,"exact":"synthetic","extra":true}"#.as_slice(),
        ] {
            let fields = vec![DisclosureField::new(INTENT_FIELD, bytes.to_vec()).unwrap()];
            assert!(matches!(exact_field::<SyntheticPayload>(&fields, INTENT_FIELD),
                Err(TransportError::Malformed)));
        }
    }

    #[test]
    fn field_size_limit_is_not_raised_for_offline_payloads() {
        assert!(matches!(DisclosureField::new(INTENT_FIELD, vec![0; MAX_PAYLOAD_BYTES + 1]),
            Err(TransportError::ResourceLimit)));
    }
}

mod named_verifier;
pub use named_verifier::*;

mod named_verifier_package;
pub use named_verifier_package::*;
