//! Narrow witness-authenticated projection. Source-only, unqualified staging.
//! The legacy raw descriptor/kind is deliberately neither accepted nor rewritten.
use crate::*;
use serde::{Deserialize, Serialize};
use wholepact_authority::offline::{
    OfflineAuthorizationAdmission, OfflineEnrollmentPolicy, OfflineReservationIntent,
};
use wholepact_authority::{
    AuthorityHead, CommittedOfflineAdmissionExport, HistoricalOfflineAdmissionExport,
    OfflineAdmissionExportPlan,
};

pub const OFFLINE_MINIMAL_ADMISSION_FIELD: &str = "offline-minimal-admission-v1";

/// Authenticated witness assertion only. No account totals, writer epoch/session,
/// complete request, private policy body, or unrelated history are serialized.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineMinimalAdmission {
    pub schema_version: u16,
    pub witness_id: String,
    pub witness_transport_key_digest: String,
    pub witness_policy_digest: String,
    pub operation_id: String,
    pub authorization_id: String,
    pub request_digest: String,
    pub intent_digest: String,
    pub terms_digest: String,
    pub review_package_digest: String,
    /// The recipient cannot recompute this from the deliberately smaller payload.
    /// It is a pinned-witness assertion about the retained original descriptor.
    pub original_admission_digest: String,
    pub original_export_plan_digest: String,
    pub committed_head: AuthorityHead,
    pub reserved_at_ms: u64,
    pub admission_expires_at_ms: u64,
}
impl OfflineMinimalAdmission {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(TransportError::UnsupportedVersion);
        }
        for id in [&self.witness_id, &self.operation_id, &self.authorization_id] {
            crate::types::validate_id(id)?;
        }
        for h in [
            &self.witness_transport_key_digest,
            &self.witness_policy_digest,
            &self.request_digest,
            &self.intent_digest,
            &self.terms_digest,
            &self.review_package_digest,
            &self.original_admission_digest,
            &self.original_export_plan_digest,
            &self.committed_head.digest,
        ] {
            crate::types::validate_hex(h, 32)?;
        }
        if self.committed_head.sequence == 0
            || self.committed_head.sequence > i64::MAX as u64
            || self.reserved_at_ms == 0
            || self.reserved_at_ms >= self.admission_expires_at_ms
            || self.admission_expires_at_ms > i64::MAX as u64
        {
            return Err(TransportError::Malformed);
        }
        Ok(())
    }
    /// Digest of the complete *minimal* statement, distinct from the assertion
    /// naming the original witness-private admission descriptor.
    pub fn statement_digest(&self) -> Result<String> {
        self.validate()?;
        Ok(crate::types::digest(
            b"wholepact.offline-minimal-admission.v1\0",
            &crate::types::encode(self)?,
        ))
    }
}

fn projection(
    admission: &OfflineAuthorizationAdmission,
    plan: &OfflineAdmissionExportPlan,
) -> Result<OfflineMinimalAdmission> {
    admission
        .matches_request(&admission.request)
        .map_err(|_| TransportError::AuthorityUnavailable)?;
    plan.matches_commit(admission)
        .map_err(|_| TransportError::WrongContext)?;
    let intent = &admission.request.intent;
    let statement = OfflineMinimalAdmission {
        schema_version: 1,
        witness_id: admission.witness_id.clone(),
        witness_transport_key_digest: admission.witness_transport_key_digest.clone(),
        witness_policy_digest: admission.witness_policy_digest.clone(),
        operation_id: admission.request.operation_id.clone(),
        authorization_id: intent.terms.authorization_id.clone(),
        request_digest: admission.request_digest.clone(),
        intent_digest: intent
            .intent_digest()
            .map_err(|_| TransportError::Malformed)?,
        terms_digest: intent
            .terms
            .terms_digest()
            .map_err(|_| TransportError::Malformed)?,
        review_package_digest: intent.terms.review_package_digest.clone(),
        original_admission_digest: crate::types::digest(
            b"wholepact.offline-original-admission-assertion.v1\0",
            &crate::types::encode(admission)?,
        ),
        original_export_plan_digest: plan.plan_digest().map_err(|_| TransportError::Malformed)?,
        committed_head: admission.committed_head.clone(),
        reserved_at_ms: admission.reserved_at_ms,
        admission_expires_at_ms: admission.request.admission_expires_at_ms,
    };
    statement.validate()?;
    Ok(statement)
}

/// No public constructor or conversion from a raw descriptor/statement.
pub struct PreparedOfflineMinimalAdmission<'a> {
    prepared: PreparedExport,
    original: &'a CommittedOfflineAdmissionExport,
}
impl PreparedOfflineMinimalAdmission<'_> {
    pub fn preview(&self) -> &DisclosurePreview {
        self.prepared.preview()
    }
    pub fn fields(&self) -> &[DisclosureField] {
        self.prepared.fields()
    }
}

fn reconstruct(
    admission: &OfflineAuthorizationAdmission,
    plan: &OfflineAdmissionExportPlan,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedExport> {
    let statement = projection(admission, plan)?;
    let terms = &admission.request.intent.terms;
    if sender.fingerprint() != statement.witness_transport_key_digest
        || sender.fingerprint() != plan.sender_key_fingerprint
        || recipient.fingerprint() != terms.offline_signer_key_digest
        || recipient.fingerprint() != plan.recipient_key_fingerprint
    {
        return Err(TransportError::Authentication);
    }
    prepare_export(
        ExportRequest {
            context: minimal_admission_context(&admission.request.intent),
            order: MessageOrder {
                message_id: plan.message_id.clone(),
                sequence: plan.sequence,
                issued_at: Timestamp::from_unix_seconds(plan.issued_at_unix_seconds)?,
                expires_at: Timestamp::from_unix_seconds(plan.expires_at_unix_seconds)?,
            },
            purpose: plan.purpose.clone(),
            persistence_warning: plan.persistence_warning.clone(),
        },
        vec![DisclosureField::new(
            OFFLINE_MINIMAL_ADMISSION_FIELD,
            crate::types::encode(&statement)?,
        )?],
        sender,
        recipient,
        now,
    )
}

pub fn prepare_offline_minimal_admission<'a>(
    original: &'a CommittedOfflineAdmissionExport,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedOfflineMinimalAdmission<'a>> {
    Ok(PreparedOfflineMinimalAdmission {
        prepared: reconstruct(
            original.descriptor(),
            original.export_plan(),
            sender,
            recipient,
            now,
        )?,
        original,
    })
}

impl SqliteOutbox {
    pub fn enqueue_offline_minimal_admission(
        &mut self,
        prepared: PreparedOfflineMinimalAdmission<'_>,
        sender: &TransportSecret,
        approved_preview_digest: &str,
        now: &Timestamp,
    ) -> Result<OutboxArtifact> {
        if self.protection() != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        let PreparedOfflineMinimalAdmission { prepared, original } = prepared;
        let _original = original;
        self.enqueue_validated(prepared, sender, approved_preview_digest, now)
    }
    /// Historical capability can recover exact existing ciphertext only. An old
    /// raw-descriptor slot conflicts; it is never converted, resealed or overwritten.
    pub fn recover_offline_minimal_admission(
        &self,
        original: &HistoricalOfflineAdmissionExport,
        sender: &TransportPublicKey,
        recipient: &TransportPublicKey,
        approved_preview_digest: &str,
    ) -> Result<Option<OutboxArtifact>> {
        if self.protection() != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        let time = Timestamp::from_unix_seconds(original.export_plan().issued_at_unix_seconds)?;
        let p = reconstruct(
            original.descriptor(),
            original.export_plan(),
            sender,
            recipient,
            &time,
        )?;
        if p.preview().digest()? != approved_preview_digest {
            return Err(TransportError::DisclosureDenied);
        }
        let found = self.recover_for_recipient(
            &p.preview().context,
            recipient,
            p.preview().order.sequence,
        )?;
        if found
            .as_ref()
            .is_some_and(|a| a.preview_digest() != approved_preview_digest)
        {
            return Err(TransportError::Equivocation);
        }
        Ok(found)
    }
}

pub fn minimal_admission_context(intent: &OfflineReservationIntent) -> MessageContext {
    let t = &intent.terms;
    MessageContext {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        sender_id: format!("offline-admission:{}", t.offline_policy_digest),
        recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
        artifact_kind: ArtifactKind::OfflineMinimalAuthorityAdmission,
    }
}

/// Low-level comparison data only. Higher-level signer code must use the bridge's
/// constructor-free owner-established setup, never populate this from imported keys.
pub struct OfflineMinimalAdmissionExpected<'a> {
    pub intent: &'a OfflineReservationIntent,
    pub offline_policy: &'a OfflineEnrollmentPolicy,
    pub witness_account_policy_digest: &'a str,
    pub original_operation_id: &'a str,
    pub original_request_digest: &'a str,
    pub original_export_plan: &'a OfflineAdmissionExportPlan,
    pub expected_committed_head: &'a AuthorityHead,
    pub admission_expires_at_ms: u64,
}

pub struct OfflineMinimalAdmissionReceipt {
    statement: OfflineMinimalAdmission,
    envelope_digest: String,
    content_digest: String,
}
impl OfflineMinimalAdmissionReceipt {
    pub fn statement(&self) -> &OfflineMinimalAdmission {
        &self.statement
    }
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

fn validate_statement(
    artifact: &ReceivedArtifact,
    expected: &OfflineMinimalAdmissionExpected<'_>,
) -> Result<OfflineMinimalAdmission> {
    let fields = artifact.fields();
    if fields.len() != 1 || fields[0].name() != OFFLINE_MINIMAL_ADMISSION_FIELD {
        return Err(TransportError::WrongContext);
    }
    let value: OfflineMinimalAdmission = crate::types::parse(fields[0].bytes())?;
    if crate::types::encode(&value)? != fields[0].bytes() {
        return Err(TransportError::Malformed);
    }
    value.validate()?;
    let i = expected.intent;
    let p = expected.offline_policy;
    let plan = expected.original_export_plan;
    i.validate().map_err(|_| TransportError::Malformed)?;
    p.validate().map_err(|_| TransportError::Malformed)?;
    plan.validate().map_err(|_| TransportError::Malformed)?;
    // Expected data is not authority by itself, but cannot silently describe a
    // different enrolled account, signer, source, policy or recipient either.
    if i.terms.account_id != p.account_id
        || i.terms.network_profile_id != p.network_profile_id
        || i.terms.enrollment_ref != p.enrollment_ref
        || i.terms.offline_policy_digest
            != p.policy_digest().map_err(|_| TransportError::Malformed)?
        || i.terms.offline_signer_key_digest != p.offline_signer_key_digest
        || i.terms.return_recipient_key_digest != p.return_recipient_key_digest
        || i.terms.snapshot.source_identity_digest != p.source_identity_digest
        || i.terms.snapshot.source_policy_digest != p.source_policy_digest
        || i.terms.semantics != p.semantics
        || plan.sender_id != format!("offline-admission:{}", i.terms.offline_policy_digest)
        || plan.recipient_id != format!("offline-admission:{}", i.terms.offline_signer_key_digest)
        || plan.sender_key_fingerprint != p.witness_transport_key_digest
        || plan.recipient_key_fingerprint != p.offline_signer_key_digest
    {
        return Err(TransportError::WrongContext);
    }
    let a = artifact.preview();
    if a.context != minimal_admission_context(i)
        || value.witness_id != p.witness_id
        || value.witness_transport_key_digest != p.witness_transport_key_digest
        || value.witness_policy_digest != expected.witness_account_policy_digest
        || value.authorization_id != i.terms.authorization_id
        || value.intent_digest != i.intent_digest().map_err(|_| TransportError::Malformed)?
        || value.terms_digest
            != i.terms
                .terms_digest()
                .map_err(|_| TransportError::Malformed)?
        || value.review_package_digest != i.terms.review_package_digest
        || value.operation_id != expected.original_operation_id
        || value.request_digest != expected.original_request_digest
        || value.original_export_plan_digest
            != plan.plan_digest().map_err(|_| TransportError::Malformed)?
        || value.committed_head != *expected.expected_committed_head
        || value.admission_expires_at_ms != expected.admission_expires_at_ms
        || value.reserved_at_ms < i.terms.snapshot.observed_at_ms
        || a.order.message_id != plan.message_id
        || a.order.sequence != plan.sequence
        || a.order.issued_at.unix_seconds() != plan.issued_at_unix_seconds
        || a.order.expires_at.unix_seconds() != plan.expires_at_unix_seconds
        || a.sender_key_fingerprint != plan.sender_key_fingerprint
        || a.recipient_key_fingerprint != plan.recipient_key_fingerprint
        || a.purpose != plan.purpose
        || a.persistence_warning != plan.persistence_warning
    {
        return Err(TransportError::WrongContext);
    }
    let start_ms = u64::try_from(plan.issued_at_unix_seconds)
        .ok()
        .and_then(|t| t.checked_mul(1000));
    let end_ms = u64::try_from(plan.expires_at_unix_seconds)
        .ok()
        .and_then(|t| t.checked_mul(1000));
    if !matches!((start_ms, end_ms), (Some(start), Some(end))
        if start <= value.reserved_at_ms && value.reserved_at_ms < end
            && end <= value.admission_expires_at_ms)
    {
        return Err(TransportError::InvalidTime);
    }
    Ok(value)
}

/// Dedicated intake prevents generic open callbacks from consuming this stream.
/// It commits authenticated original ciphertext only after complete exact checks.
pub fn open_offline_minimal_admission(
    envelope: &EncryptedEnvelope,
    recipient: &TransportSecret,
    witness: &TransportPublicKey,
    expected: &OfflineMinimalAdmissionExpected<'_>,
    now: &Timestamp,
    inbox: &mut SqliteReplayLedger,
) -> Result<OfflineMinimalAdmissionReceipt> {
    if inbox.protection() != MailboxProtection::Encrypted {
        return Err(TransportError::AuthorityUnavailable);
    }
    let p = expected.offline_policy;
    if witness.fingerprint() != p.witness_transport_key_digest
        || recipient.public_key()?.fingerprint() != p.offline_signer_key_digest
    {
        return Err(TransportError::Authentication);
    }
    let (artifact, receipt) = crate::envelope::authenticate(
        envelope,
        recipient,
        witness,
        &minimal_admission_context(expected.intent),
        Some(now),
    )?;
    let statement = validate_statement(&artifact, expected)?;
    inbox.accept_authenticated(&receipt, envelope.as_bytes())?;
    Ok(OfflineMinimalAdmissionReceipt {
        statement,
        envelope_digest: artifact.envelope_digest().into(),
        content_digest: artifact.content_digest().into(),
    })
}

/// Reauthenticated exact inbox history only. Deliberately distinct from current
/// bridge evidence, native consent and newly delivered transport receipt.
pub struct RecoveredOfflineMinimalAdmission {
    statement: OfflineMinimalAdmission,
    envelope_digest: String,
    content_digest: String,
    original_order: MessageOrder,
}
impl RecoveredOfflineMinimalAdmission {
    pub fn statement(&self) -> &OfflineMinimalAdmission {
        &self.statement
    }
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
    pub fn original_order(&self) -> &MessageOrder {
        &self.original_order
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
    pub fn is_new_delivery(&self) -> bool {
        false
    }
}

/// Read-only recovery through the original concrete encrypted inbox. This accepts
/// expired history but never an arbitrary retained-envelope DTO or fresh authority.
/// Callers must separately compare protected receipt pins and current local state.
pub fn recover_offline_minimal_admission_receipt(
    recipient: &TransportSecret,
    witness: &TransportPublicKey,
    expected: &OfflineMinimalAdmissionExpected<'_>,
    inbox: &SqliteReplayLedger,
) -> Result<Option<RecoveredOfflineMinimalAdmission>> {
    if inbox.protection() != MailboxProtection::Encrypted {
        return Err(TransportError::AuthorityUnavailable);
    }
    if witness.fingerprint() != expected.offline_policy.witness_transport_key_digest
        || recipient.public_key()?.fingerprint()
            != expected.offline_policy.offline_signer_key_digest
    {
        return Err(TransportError::Authentication);
    }
    let context = minimal_admission_context(expected.intent);
    let Some(retained) =
        inbox.retained_for_context(&context, expected.original_export_plan.sequence)?
    else {
        return Ok(None);
    };
    let historical = recover_received(&retained, recipient, witness, &context)?;
    let artifact = historical.artifact();
    let statement = validate_statement(artifact, expected)?;
    Ok(Some(RecoveredOfflineMinimalAdmission {
        statement,
        envelope_digest: artifact.envelope_digest().into(),
        content_digest: artifact.content_digest().into(),
        original_order: artifact.preview().order.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovered_minimal_history_never_claims_delivery_or_authorization() {
        let history = RecoveredOfflineMinimalAdmission {
            statement: statement_fixture(),
            envelope_digest: "a".repeat(64),
            content_digest: "b".repeat(64),
            original_order: MessageOrder {
                message_id: "c".repeat(32),
                sequence: 1,
                issued_at: Timestamp::from_unix_seconds(100).unwrap(),
                expires_at: Timestamp::from_unix_seconds(200).unwrap(),
            },
        };
        assert!(!history.authorization_allowed());
        assert!(!history.is_new_delivery());
        assert_eq!(history.original_order().expires_at.unix_seconds(), 200);
        assert!(history.statement() == &statement_fixture());
    }
    #[test]
    fn new_kind_requires_qualified_export_and_cannot_alias_raw_descriptor() {
        assert!(ArtifactKind::OfflineMinimalAuthorityAdmission.requires_qualified_export());
        assert_ne!(
            ArtifactKind::OfflineMinimalAuthorityAdmission,
            ArtifactKind::OfflineAuthorityAdmission
        );
        assert_ne!(
            OFFLINE_MINIMAL_ADMISSION_FIELD,
            crate::OFFLINE_ADMISSION_FIELD
        );
    }
    #[test]
    fn legacy_sensitive_fields_are_not_accepted_by_minimal_statement() {
        for key in [
            "account_outstanding_debit_zatoshis",
            "account_reserved_input_value_zatoshis",
            "writer_session_id",
            "request",
            "writer_epoch",
            "policy",
            "unrelated_history",
        ] {
            let mut value = serde_json::to_value(statement_fixture()).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(key.into(), serde_json::json!("private-canary"));
            assert!(
                crate::types::parse::<OfflineMinimalAdmission>(
                    &serde_json::to_vec(&value).unwrap()
                )
                .is_err()
            );
        }
    }
    fn statement_fixture() -> OfflineMinimalAdmission {
        let h = "a".repeat(64);
        OfflineMinimalAdmission {
            schema_version: 1,
            witness_id: "synthetic-witness".into(),
            witness_transport_key_digest: h.clone(),
            witness_policy_digest: h.clone(),
            operation_id: "synthetic-operation".into(),
            authorization_id: "synthetic-authorization".into(),
            request_digest: h.clone(),
            intent_digest: h.clone(),
            terms_digest: h.clone(),
            review_package_digest: h.clone(),
            original_admission_digest: h.clone(),
            original_export_plan_digest: h.clone(),
            committed_head: AuthorityHead {
                sequence: 1,
                digest: h,
            },
            reserved_at_ms: 1000,
            admission_expires_at_ms: 2000,
        }
    }
    #[test]
    fn minimal_statement_binds_all_digest_time_and_head_fields() {
        let original = statement_fixture();
        original.validate().unwrap();
        let original_digest = original.statement_digest().unwrap();
        for changed in [
            "intent",
            "terms",
            "package",
            "request",
            "admission",
            "plan",
            "head",
        ] {
            let mut s = original.clone();
            let field = match changed {
                "intent" => &mut s.intent_digest,
                "terms" => &mut s.terms_digest,
                "package" => &mut s.review_package_digest,
                "request" => &mut s.request_digest,
                "admission" => &mut s.original_admission_digest,
                "plan" => &mut s.original_export_plan_digest,
                _ => &mut s.committed_head.digest,
            };
            *field = "b".repeat(64);
            assert_ne!(s.statement_digest().unwrap(), original_digest);
        }
        let mut expired = original.clone();
        expired.reserved_at_ms = expired.admission_expires_at_ms;
        assert!(expired.validate().is_err());
        let mut version = original;
        version.schema_version = 2;
        assert_eq!(version.validate(), Err(TransportError::UnsupportedVersion));
    }
    #[test]
    fn raw_and_minimal_share_original_durable_stream_and_sequence_fence() {
        let mut old = MessageContext {
            network_profile_id: "synthetic-network".into(),
            agreement_id: "synthetic-agreement".into(),
            proposal_id: "synthetic-proposal".into(),
            proposal_revision: 1,
            sender_id: "offline-admission:synthetic-policy".into(),
            recipient_id: "offline-admission:synthetic-signer".into(),
            artifact_kind: ArtifactKind::OfflineAuthorityAdmission,
        };
        let original_stream = crate::replay::stream_digest(&old).unwrap();
        old.artifact_kind = ArtifactKind::OfflineMinimalAuthorityAdmission;
        assert_eq!(crate::replay::stream_digest(&old).unwrap(), original_stream);
        for first in [
            ArtifactKind::OfflineAuthorityAdmission,
            ArtifactKind::OfflineMinimalAuthorityAdmission,
            ArtifactKind::OfflineAdmissionControl,
        ] {
            for second in [
                ArtifactKind::OfflineAuthorityAdmission,
                ArtifactKind::OfflineMinimalAuthorityAdmission,
                ArtifactKind::OfflineAdmissionControl,
            ] {
                if first == second {
                    continue;
                }
                old.artifact_kind = first;
                let first_stream = crate::replay::stream_digest(&old).unwrap();
                old.artifact_kind = second;
                assert_eq!(crate::replay::stream_digest(&old).unwrap(), first_stream);
                assert_same_plan_excludes_other_representation(&first_stream, first, second);
            }
        }
    }
    fn assert_same_plan_excludes_other_representation(
        original_stream: &str,
        first: ArtifactKind,
        second: ArtifactKind,
    ) {
        // Actual outbox schema, no credentials, HPKE, files or proof execution.
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(crate::outbox::OUTBOX_SCHEMA).unwrap();
        let insert = "INSERT INTO outbox(stream,sequence,message_digest,preview_digest,context_digest,sender_fingerprint,recipient_fingerprint,payload_digest,slot,envelope_digest,issued_at,expires_at,envelope) VALUES(?1,1,'same-message',?2,?3,'sender','recipient','payload',NULL,'envelope',1,2,x'00')";
        let first_preview = format!("first:{first:?}");
        let second_preview = format!("second:{second:?}");
        c.execute(
            insert,
            rusqlite::params![original_stream, first_preview, "first-context"],
        )
        .unwrap();
        // The real enqueue SELECT finds this row before it reaches sealing.
        let prior: String = c.query_row("SELECT preview_digest FROM outbox WHERE stream=?1 AND (sequence=?2 OR message_digest=?3)",
            rusqlite::params![original_stream, 1, "same-message"], |r| r.get(0)).unwrap();
        assert_ne!(prior, second_preview);
        assert!(
            c.execute(
                insert,
                rusqlite::params![original_stream, second_preview, "second-context"]
            )
            .is_err()
        );
    }
}
