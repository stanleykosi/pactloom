//! Qualified non-authorizing sequence outcome, disabled without authority feature.
//! No public capability factory. An allocated sequence may choose this outcome
//! only before any admission export capability escaped, under authority's durable
//! single-outcome and continuous-protected-lineage fence. Missing ciphertext or an
//! ACK never proves non-emission; this adapter does not make that determination.
use crate::*;
use wholepact_authority::{CommittedOfflineControlExport, HistoricalOfflineControlExport,
    OfflineAdmissionControl, OfflineAdmissionExportPlan};

pub const OFFLINE_CONTROL_FIELD: &str = "offline-admission-control-v1";

/// Opaque authority-selected terminal outcome, not admission or spending consent.
pub struct PreparedOfflineControlExport<'a> {
    prepared: PreparedExport,
    committed: &'a CommittedOfflineControlExport,
}
impl PreparedOfflineControlExport<'_> {
    pub fn preview(&self) -> &DisclosurePreview { self.prepared.preview() }
    pub fn fields(&self) -> &[DisclosureField] { self.prepared.fields() }
}

/// Fixed current control plan, never an extension of the original admission plan.
/// Supplied keys must be independently pinned; no credential lifecycle occurs.
pub fn prepare_offline_control_export<'a>(
    committed: &'a CommittedOfflineControlExport,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedOfflineControlExport<'a>> {
    let prepared = reconstruct_control_preview(committed.descriptor(), committed.export_plan(), sender, recipient, now)?;
    Ok(PreparedOfflineControlExport { prepared, committed })
}

// Historical entry points never expose the PreparedExport or call encryption.
fn reconstruct_control_preview(
    descriptor: &OfflineAdmissionControl, plan: &OfflineAdmissionExportPlan,
    sender: &TransportPublicKey, recipient: &TransportPublicKey, now: &Timestamp,
) -> Result<PreparedExport> {
    descriptor.validate().map_err(|_| TransportError::AuthorityUnavailable)?;
    descriptor.matches_request(&descriptor.request)
        .map_err(|_| TransportError::AuthorityUnavailable)?;
    descriptor.validate_export_plan(plan)
        .map_err(|_| TransportError::AuthorityUnavailable)?;
    let terms = &descriptor.request.intent.terms;
    if sender.fingerprint() != descriptor.witness_transport_key_digest
        || sender.fingerprint() != plan.sender_key_fingerprint
        || recipient.fingerprint() != terms.offline_signer_key_digest
        || recipient.fingerprint() != plan.recipient_key_fingerprint
        || plan.sequence != descriptor.original_sequence
    {
        return Err(TransportError::Authentication);
    }
    let sender_id = format!("offline-admission:{}", terms.offline_policy_digest);
    let recipient_id = format!("offline-admission:{}", terms.offline_signer_key_digest);
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
            artifact_kind: ArtifactKind::OfflineAdmissionControl,
        },
        order: MessageOrder {
            message_id: plan.message_id.clone(), sequence: plan.sequence,
            issued_at: Timestamp::from_unix_seconds(plan.issued_at_unix_seconds)?,
            expires_at: Timestamp::from_unix_seconds(plan.expires_at_unix_seconds)?,
        },
        purpose: plan.purpose.clone(), persistence_warning: plan.persistence_warning.clone(),
    };
    let prepared = prepare_export(
        request, vec![DisclosureField::new(OFFLINE_CONTROL_FIELD, crate::types::encode(descriptor)?)?],
        sender, recipient, now,
    )?;
    Ok(prepared)
}

impl SqliteOutbox {
    /// Ordinary contiguous replay, immutable slot and resource limits still apply.
    /// Cannot replace an existing admission or emitted control at this sequence.
    pub fn enqueue_offline_control(
        &mut self, prepared: PreparedOfflineControlExport<'_>, sender: &TransportSecret,
        approved_preview_digest: &str, now: &Timestamp,
    ) -> Result<OutboxArtifact> {
        if self.protection() != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        let PreparedOfflineControlExport { prepared, committed } = prepared;
        let _original = committed;
        self.enqueue_validated(prepared, sender, approved_preview_digest, now)
    }

    /// Historical retrieval only, never new encryption or an outcome switch.
    /// Expired existing control stays expired; missing control stays missing.
    pub fn recover_offline_control(
        &self, committed: &HistoricalOfflineControlExport,
        sender: &TransportPublicKey, recipient: &TransportPublicKey,
        approved_preview_digest: &str,
    ) -> Result<Option<OutboxArtifact>> {
        if self.protection() != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        let original_time = Timestamp::from_unix_seconds(committed.export_plan().issued_at_unix_seconds)?;
        let prepared = reconstruct_control_preview(committed.descriptor(), committed.export_plan(), sender, recipient, &original_time)?;
        let preview = prepared.preview();
        if preview.digest()? != approved_preview_digest {
            return Err(TransportError::DisclosureDenied);
        }
        let artifact = self.recover_for_recipient(&preview.context, recipient, preview.order.sequence)?;
        if artifact.as_ref().is_some_and(|a| a.preview_digest() != approved_preview_digest) {
            return Err(TransportError::Equivocation);
        }
        Ok(artifact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_uses_original_stream_but_a_distinct_immutable_kind() {
        let mut admission = MessageContext {
            network_profile_id: "synthetic".into(), agreement_id: "agreement".into(),
            proposal_id: "proposal".into(), proposal_revision: 1,
            sender_id: format!("offline-admission:{}", "a".repeat(64)),
            recipient_id: format!("offline-admission:{}", "b".repeat(64)),
            artifact_kind: ArtifactKind::OfflineAuthorityAdmission,
        };
        let stream = crate::replay::stream_digest(&admission).unwrap();
        admission.artifact_kind = ArtifactKind::OfflineAdmissionControl;
        assert_eq!(stream, crate::replay::stream_digest(&admission).unwrap());
        assert!(admission.artifact_kind.immutable_slot());
        assert!(admission.artifact_kind.requires_qualified_export());
        assert_ne!(OFFLINE_CONTROL_FIELD, OFFLINE_ADMISSION_FIELD);
    }
}
