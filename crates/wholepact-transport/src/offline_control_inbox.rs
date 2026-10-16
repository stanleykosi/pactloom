//! Concrete atomic control inbox and typed terminal-outcome journal.
//! No callback can manufacture a terminal record; pinned HPKE and full original
//! context validation happen here before the single encrypted SQLite transaction.
use crate::*;
use wholepact_authority::{AccountPolicy, OfflineAdmissionControl, OfflineAdmissionExportPlan,
    OfflineAdmissionControlOutcome};
use wholepact_authority::offline::{ReserveOfflineAuthorization, OfflineEnrollmentPolicy};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
const CONTROL_FIELD: &str = "offline-admission-control-v1";


fn exact_field<T: serde::de::DeserializeOwned + serde::Serialize>(fields: &[DisclosureField], name: &str) -> Result<T> {
    if fields.len() != 1 || fields[0].name() != name { return Err(TransportError::WrongContext); }
    let bytes = fields[0].bytes();
    if bytes.len() > MAX_PAYLOAD_BYTES { return Err(TransportError::ResourceLimit); }
    let parsed: T = crate::types::parse(bytes)?;
    if crate::types::encode(&parsed)? != bytes { return Err(TransportError::Malformed); }
    Ok(parsed)
}

/// Caller must obtain every reference from retained authenticated original state,
/// not labels/digests supplied by the incoming control. This is comparison data,
/// not a portable authority capability or an enrollment factory.
pub struct OfflineControlImportExpected<'a> {
    pub request: &'a ReserveOfflineAuthorization,
    pub account_policy: &'a AccountPolicy,
    pub offline_policy: &'a OfflineEnrollmentPolicy,
    pub original_export_plan: &'a OfflineAdmissionExportPlan,
    pub prepared_record_digest: &'a str,
    pub authenticated_receipt_digest: &'a str,
}

/// No conversion into admission, permit, final consent or dispatch authority.
/// No public constructor, Clone, Deserialize or Debug.
pub struct OfflineControlInboxReceipt {
    control: OfflineAdmissionControl,
    envelope_digest: String,
    currently_within_transport_window: bool,
}
impl OfflineControlInboxReceipt {
    pub fn control(&self) -> &OfflineAdmissionControl { &self.control }
    pub fn envelope_digest(&self) -> &str { &self.envelope_digest }
    pub fn authorization_allowed(&self) -> bool { false }
    /// True only because matching ciphertext and typed outcome share one commit.
    pub fn terminal_control_recorded(&self) -> bool { true }
    pub fn currently_within_transport_window(&self) -> bool { self.currently_within_transport_window }
}

fn control_context(expected: &OfflineControlImportExpected<'_>) -> Result<MessageContext> {
    expected.request.validate().map_err(|_| TransportError::Malformed)?;
    let t = &expected.request.intent.terms;
    Ok(MessageContext {
        network_profile_id: t.network_profile_id.clone(), agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(), proposal_revision: t.proposal_revision,
        sender_id: format!("offline-admission:{}", t.offline_policy_digest),
        recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
        artifact_kind: ArtifactKind::OfflineAdmissionControl,
    })
}

fn validate_control_fields(
    artifact: &ReceivedArtifact, expected: &OfflineControlImportExpected<'_>,
) -> Result<OfflineAdmissionControl> {
    let control: OfflineAdmissionControl = exact_field(artifact.fields(), CONTROL_FIELD)?;
    control.validate().map_err(|_| TransportError::Malformed)?;
    control.matches_request(expected.request).map_err(|_| TransportError::WrongContext)?;
    expected.account_policy.validate().map_err(|_| TransportError::Malformed)?;
    expected.original_export_plan.matches_preparation(expected.request, expected.offline_policy)
        .map_err(|_| TransportError::WrongContext)?;
    let account = expected.account_policy;
    let policy = expected.offline_policy;
    let t = &expected.request.intent.terms;
    if control.prepared_record_digest != expected.prepared_record_digest
        || control.authenticated_receipt_digest != expected.authenticated_receipt_digest
        || control.original_export_plan_digest != expected.original_export_plan.plan_digest().map_err(|_| TransportError::Malformed)?
        || control.original_sequence != expected.original_export_plan.sequence
        || control.witness_id != policy.witness_id || control.witness_id != account.witness_id
        || control.witness_policy_digest != account.policy_digest().map_err(|_| TransportError::Malformed)?
        || control.witness_transport_key_digest != policy.witness_transport_key_digest
        || account.account_id != t.account_id || account.network_profile_id != t.network_profile_id
    { return Err(TransportError::WrongContext); }
    let p = artifact.preview();
    if p.context != control_context(expected)? { return Err(TransportError::WrongContext); }
    // Validate the ACTUAL HPKE-authenticated current plan. It is independent of
    // the expired original plan but cannot choose another sequence or recipient.
    let plan = OfflineAdmissionExportPlan {
        message_id: p.order.message_id.clone(), sequence: p.order.sequence,
        issued_at_unix_seconds: p.order.issued_at.unix_seconds(),
        expires_at_unix_seconds: p.order.expires_at.unix_seconds(),
        purpose: p.purpose.clone(), persistence_warning: p.persistence_warning.clone(),
        sender_id: p.context.sender_id.clone(), recipient_id: p.context.recipient_id.clone(),
        sender_key_fingerprint: p.sender_key_fingerprint.clone(),
        recipient_key_fingerprint: p.recipient_key_fingerprint.clone(),
    };
    control.validate_export_plan(&plan).map_err(|_| TransportError::WrongContext)?;
    Ok(control)
}

fn check_control_keys(
    offline_secret: &TransportSecret, witness_key: &TransportPublicKey,
    expected: &OfflineControlImportExpected<'_>, inbox: &SqliteReplayLedger,
) -> Result<()> {
    if inbox.protection() != MailboxProtection::Encrypted { return Err(TransportError::AuthorityUnavailable); }
    expected.offline_policy.validate().map_err(|_| TransportError::Malformed)?;
    expected.original_export_plan.matches_preparation(expected.request, expected.offline_policy)
        .map_err(|_| TransportError::WrongContext)?;
    if offline_secret.public_key()?.fingerprint() != expected.offline_policy.offline_signer_key_digest
        || witness_key.fingerprint() != expected.offline_policy.witness_transport_key_digest
    { return Err(TransportError::Authentication); }
    Ok(())
}

/// This commits only a non-authorizing terminal control record, not a financial
/// operation. Replay ciphertext and exact typed outcome commit or roll back
/// together. Same-sequence retry must use historical recovery, never re-import.
pub fn accept_offline_control(
    envelope: &EncryptedEnvelope, offline_secret: &TransportSecret,
    witness_key: &TransportPublicKey, expected: &OfflineControlImportExpected<'_>,
    now: &Timestamp, inbox: &mut SqliteReplayLedger,
) -> Result<OfflineControlInboxReceipt> {
    check_control_keys(offline_secret, witness_key, expected, inbox)?;
    let context = control_context(expected)?;
    let (artifact, receipt) = crate::envelope::authenticate(envelope, offline_secret, witness_key, &context, Some(now))?;
    let control = validate_control_fields(&artifact, expected)?;
    let control_digest = control.control_digest().map_err(|_| TransportError::Malformed)?;
    let (outcome, admission_digest) = outcome_columns(&control.outcome);
    let tx = inbox.connection.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| TransportError::Storage)?;
    crate::replay::insert_authenticated_in_transaction(&tx, &receipt, envelope.as_bytes())?;
    tx.execute("INSERT INTO offline_control_outcomes(stream,sequence,content_digest,control_digest,outcome,admission_digest) VALUES(?1,?2,?3,?4,?5,?6)",
        params![artifact.stream_digest(), artifact.preview().order.sequence as i64,
            artifact.content_digest(), control_digest, outcome, admission_digest])
        .map_err(|_| TransportError::Storage)?;
    tx.commit().map_err(|_| TransportError::Storage)?;
    Ok(OfflineControlInboxReceipt { control, envelope_digest: artifact.envelope_digest().into(), currently_within_transport_window: true })
}

/// Requires BOTH authenticated retained ciphertext and its exact typed row. Does
/// not populate a missing outcome, bypass freshness, advance replay or reseal.
/// Already expired controls remain history, never a new current delivery.
pub fn recover_offline_control_receipt(
    offline_secret: &TransportSecret, witness_key: &TransportPublicKey,
    expected: &OfflineControlImportExpected<'_>, now: &Timestamp, inbox: &SqliteReplayLedger,
) -> Result<Option<OfflineControlInboxReceipt>> {
    check_control_keys(offline_secret, witness_key, expected, inbox)?;
    let context = control_context(expected)?;
    let Some(retained) = inbox.retained_for_context(&context, expected.original_export_plan.sequence)? else { return Ok(None); };
    let recovered = recover_received(&retained, offline_secret, witness_key, &context)?;
    let artifact = recovered.artifact();
    let control = validate_control_fields(artifact, expected)?;
    let stored: Option<(String,String,i64,Option<String>)> = inbox.connection.query_row(
        "SELECT substr(content_digest,1,65),substr(control_digest,1,65),outcome,substr(admission_digest,1,65) FROM offline_control_outcomes WHERE stream=?1 AND sequence=?2",
        params![artifact.stream_digest(), artifact.preview().order.sequence as i64],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))
        .optional().map_err(|_| TransportError::Storage)?;
    let (content, digest, outcome, admission) = stored.ok_or(TransportError::DomainConflict)?;
    let (expected_outcome, expected_admission) = outcome_columns(&control.outcome);
    if content != artifact.content_digest()
        || digest != control.control_digest().map_err(|_| TransportError::Malformed)?
        || outcome != expected_outcome || admission.as_deref() != expected_admission
    { return Err(TransportError::DomainConflict); }
    Ok(Some(OfflineControlInboxReceipt { control, envelope_digest: artifact.envelope_digest().into(),
        currently_within_transport_window: recovered.is_currently_valid(now) }))
}

fn outcome_columns(outcome: &OfflineAdmissionControlOutcome) -> (i64, Option<&str>) {
    match outcome {
        OfflineAdmissionControlOutcome::NoAdmission => (1, None),
        OfflineAdmissionControlOutcome::ExposureRetained { admission_digest } => (2, Some(admission_digest)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_columns_preserve_exposure_distinction() {
        assert_eq!(outcome_columns(&OfflineAdmissionControlOutcome::NoAdmission), (1,None));
        let retained = OfflineAdmissionControlOutcome::ExposureRetained { admission_digest: "a".repeat(64) };
        assert_eq!(outcome_columns(&retained), (2,Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
    }
    #[test]
    fn canonical_control_parser_rejects_wrong_kind_field_and_extras() {
        let fields = vec![DisclosureField::new("offline-authority-admission-v1", b"{}".to_vec()).unwrap()];
        assert!(matches!(exact_field::<OfflineAdmissionControl>(&fields, CONTROL_FIELD), Err(TransportError::WrongContext)));
        let fields = vec![DisclosureField::new(CONTROL_FIELD, b"{}".to_vec()).unwrap(), DisclosureField::new("extra", b"{}".to_vec()).unwrap()];
        assert!(matches!(exact_field::<OfflineAdmissionControl>(&fields, CONTROL_FIELD), Err(TransportError::WrongContext)));
    }
}

#[cfg(test)]
#[path = "offline_control_inbox_tests.rs"]
mod synthetic_crypto_tests;
