//! Proposed post-commit export adapter. Feature remains disabled by default.
//! Original durable metadata and opaque authority evidence are mandatory.
//! This is admission evidence, not native spending consent or settlement.
use crate::*;
use wholepact_authority::{CommittedOfflineAdmissionExport, HistoricalOfflineAdmissionExport, OfflineAdmissionExportPlan};
use wholepact_authority::offline::OfflineAuthorizationAdmission;

pub const OFFLINE_ADMISSION_FIELD: &str = "offline-authority-admission-v1";

/// No public fields, Clone, Deserialize, or conversion from a portable descriptor.
/// Holds the authority-owned evidence through preparation and encrypted commit.
pub struct PreparedOfflineAdmissionExport<'a> {
    prepared: PreparedExport,
    committed: &'a CommittedOfflineAdmissionExport,
}
impl PreparedOfflineAdmissionExport<'_> {
    pub fn preview(&self) -> &DisclosurePreview { self.prepared.preview() }
    pub fn fields(&self) -> &[DisclosureField] { self.prepared.fields() }
}

/// Original keys are supplied by protected host composition. This API does not
/// enroll, generate, rotate, store or recover credentials. Exact disclosure consent
/// is still independently required by enqueue; computing a digest is not consent.
pub fn prepare_offline_admission_export<'a>(
    committed: &'a CommittedOfflineAdmissionExport,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedOfflineAdmissionExport<'a>> {
    let prepared = reconstruct_admission_preview(committed.descriptor(), committed.export_plan(), sender, recipient, now)?;
    Ok(PreparedOfflineAdmissionExport { prepared, committed })
}

// Private reconstruction never escapes as PreparedExport on the historical API.
// Raw DTOs can compute a preview internally but cannot mint an enqueue capability.
fn reconstruct_admission_preview(
    descriptor: &OfflineAuthorizationAdmission, plan: &OfflineAdmissionExportPlan,
    sender: &TransportPublicKey, recipient: &TransportPublicKey, now: &Timestamp,
) -> Result<PreparedExport> {
    descriptor.matches_request(&descriptor.request)
        .map_err(|_| TransportError::AuthorityUnavailable)?;
    let terms = &descriptor.request.intent.terms;
    validate_window(
        plan.issued_at_unix_seconds, plan.expires_at_unix_seconds,
        descriptor.request.requested_at_ms, descriptor.reserved_at_ms,
        descriptor.request.admission_expires_at_ms,
    )?;
    if sender.fingerprint() != descriptor.witness_transport_key_digest
        || sender.fingerprint() != plan.sender_key_fingerprint
        || recipient.fingerprint() != terms.offline_signer_key_digest
        || recipient.fingerprint() != plan.recipient_key_fingerprint
    {
        return Err(TransportError::Authentication);
    }
    // These dedicated directions must be shared verbatim with admission intake.
    let (sender_id, recipient_id) = direction_labels(
        &terms.offline_policy_digest, &terms.offline_signer_key_digest,
    );
    if plan.sender_id != sender_id || plan.recipient_id != recipient_id {
        return Err(TransportError::WrongContext);
    }
    let request = ExportRequest {
        context: MessageContext {
            network_profile_id: terms.network_profile_id.clone(),
            agreement_id: terms.agreement_id.clone(),
            proposal_id: terms.proposal_id.clone(),
            proposal_revision: terms.proposal_revision,
            sender_id, recipient_id,
            artifact_kind: ArtifactKind::OfflineAuthorityAdmission,
        },
        order: MessageOrder {
            message_id: plan.message_id.clone(), sequence: plan.sequence,
            issued_at: Timestamp::from_unix_seconds(plan.issued_at_unix_seconds)?,
            expires_at: Timestamp::from_unix_seconds(plan.expires_at_unix_seconds)?,
        },
        purpose: plan.purpose.clone(),
        persistence_warning: plan.persistence_warning.clone(),
    };
    // This payload is NOT yet qualified as minimally disclosed. The descriptor
    // includes account aggregates/input metadata; production remains disabled.
    let bytes = crate::types::encode(descriptor)?;
    let prepared = prepare_export(
        request, vec![DisclosureField::new(OFFLINE_ADMISSION_FIELD, bytes)?],
        sender, recipient, now,
    )?;
    Ok(prepared)
}

impl SqliteOutbox {
    /// Only post-commit authority evidence reaches the shared journal. Failure
    /// leaves exposure reserved and does not refund, reissue or retime admission.
    pub fn enqueue_offline_admission(
        &mut self,
        prepared: PreparedOfflineAdmissionExport<'_>,
        sender: &TransportSecret,
        approved_preview_digest: &str,
        now: &Timestamp,
    ) -> Result<OutboxArtifact> {
        if self.protection() != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        let PreparedOfflineAdmissionExport { prepared, committed } = prepared;
        // Keep the opaque witness capability in scope through durable commit.
        let _original = committed;
        self.enqueue_validated(prepared, sender, approved_preview_digest, now)
    }

    /// Recover existing original ciphertext, including expired history. Never
    /// reseal, refresh a deadline or insert a missing row through this path.
    /// A missing row after expiry remains missing; reservation is not released.
    pub fn recover_offline_admission(
        &self,
        committed: &HistoricalOfflineAdmissionExport,
        sender: &TransportPublicKey,
        recipient: &TransportPublicKey,
        approved_preview_digest: &str,
    ) -> Result<Option<OutboxArtifact>> {
        if self.protection() != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        // Original issuance timestamp is solely for deterministic reconstruction
        // and structural validation. It is never used to encrypt or authorize now.
        let original_time = Timestamp::from_unix_seconds(
            committed.export_plan().issued_at_unix_seconds,
        )?;
        let prepared = reconstruct_admission_preview(
            committed.descriptor(), committed.export_plan(), sender, recipient, &original_time,
        )?;
        let preview = prepared.preview();
        if preview.digest()? != approved_preview_digest {
            return Err(TransportError::DisclosureDenied);
        }
        let artifact = self.recover_for_recipient(
            &preview.context, recipient, preview.order.sequence,
        )?;
        if artifact.as_ref().is_some_and(|a| a.preview_digest() != approved_preview_digest) {
            return Err(TransportError::Equivocation);
        }
        Ok(artifact)
    }
}

fn direction_labels(policy: &str, signer: &str) -> (String, String) {
    (format!("offline-admission:{policy}"), format!("offline-admission:{signer}"))
}

fn validate_window(
    issued: i64, expires: i64, requested_ms: u64, reserved_ms: u64, admission_end_ms: u64,
) -> Result<()> {
    let issued_ms = u64::try_from(issued).ok().and_then(|t| t.checked_mul(1000));
    let expires_ms = u64::try_from(expires).ok().and_then(|t| t.checked_mul(1000));
    match (issued_ms, expires_ms) {
        (Some(start), Some(end)) if requested_ms <= start && start <= reserved_ms
            && reserved_ms < end && end <= admission_end_ms
            && end > start && end - start <= (MAX_MESSAGE_LIFETIME_SECONDS as u64) * 1000 => Ok(()),
        _ => Err(TransportError::InvalidTime),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Pure tests only: no keys, HPKE, SQLCipher, socket, proof or Cargo execution.
    #[test]
    fn window_never_rounds_expiry_outward() {
        assert!(validate_window(2, 3, 1501, 2500, 3999).is_ok());
        assert_eq!(validate_window(1, 3, 1501, 2500, 3999), Err(TransportError::InvalidTime));
        assert_eq!(validate_window(2, 4, 1501, 2500, 3999), Err(TransportError::InvalidTime));
    }
    #[test]
    fn original_plan_may_start_before_commit_but_cannot_expire_before_commit() {
        assert!(validate_window(2, 4, 1501, 3500, 4999).is_ok());
        assert_eq!(validate_window(2, 4, 1501, 1999, 4999), Err(TransportError::InvalidTime));
        assert_eq!(validate_window(2, 4, 1501, 4000, 4999), Err(TransportError::InvalidTime));
        assert_eq!(validate_window(2, 4, 2001, 3500, 4999), Err(TransportError::InvalidTime));
    }
    #[test]
    fn empty_negative_and_overflow_windows_fail_closed() {
        for (start, end) in [(2, 2), (3, 2), (-1, 2), (i64::MAX - 1, i64::MAX)] {
            assert_eq!(validate_window(start, end, 1, 2000, u64::MAX), Err(TransportError::InvalidTime));
        }
    }
    #[test]
    fn transport_lifetime_bound_is_not_extended() {
        let end = 1 + MAX_MESSAGE_LIFETIME_SECONDS;
        assert!(validate_window(1, end, 1000, 1000, (end as u64) * 1000).is_ok());
        assert_eq!(validate_window(1, end + 1, 1000, 1000, u64::MAX), Err(TransportError::InvalidTime));
    }
    #[test]
    fn dedicated_direction_does_not_alias_intent_or_swap_recipient() {
        let (sender, recipient) = direction_labels(&"a".repeat(64), &"b".repeat(64));
        assert_eq!(sender, format!("offline-admission:{}", "a".repeat(64)));
        assert_eq!(recipient, format!("offline-admission:{}", "b".repeat(64)));
        assert!(sender.len() <= 128 && recipient.len() <= 128);
        assert!(!sender.starts_with("offline-intent:"));
    }
}
