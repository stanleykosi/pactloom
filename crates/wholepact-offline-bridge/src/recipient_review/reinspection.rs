//! Disabled, outside-graph restart composition. No public constructor or export.
//! Include as a private child of recipient_review only after journal integration.
#![allow(dead_code)]
use super::*;

/// Protected signer-journal receipt, never selected from incoming file metadata.
/// Deliberately no Deserialize, public fields, constructor or implementable trait.
struct DurableReviewPin {
    context: MessageContext,
    order: MessageOrder,
    owner_setup_digest: String,
    package_digest: String,
    envelope_digest: String,
    content_digest: String,
}

/// Unavailable factory: must hold actual account-vault/original-history and current
/// account-use/recovery leases, restore the authenticated setup, and establish an
/// acceptable restart clock. A raw Timestamp or persisted success bit cannot mint
/// this value. The clock cannot claim current remote revocation knowledge.
struct RestartPrerequisites<'a> {
    setup: &'a OwnerEstablishedOfflineSetup,
    expected: &'a RetainedOfflineReviewInputs,
    pin: &'a DurableReviewPin,
    clock: RestartClock,
}

/// No production constructor. Bounds must come from a qualified local clock
/// continuity mechanism, not incoming timestamps or a caller trust flag.
/// Platform qualification and durable anti-rollback state are still unresolved.
struct RestartClock {
    lower_unix_seconds: i64,
    upper_unix_seconds: i64,
    observed: Instant,
}
impl RestartClock {
    fn window(&self, order: &MessageOrder) -> Result<Duration> {
        let issued = order.issued_at.unix_seconds();
        let expires = order.expires_at.unix_seconds();
        if self.lower_unix_seconds > self.upper_unix_seconds
            || self.lower_unix_seconds < issued
            || self.upper_unix_seconds >= expires
        {
            return Err(TransportError::InvalidTime);
        }
        let original_remaining = u64::try_from(expires - self.upper_unix_seconds)
            .map_err(|_| TransportError::InvalidTime)?;
        Duration::from_secs(original_remaining)
            .checked_sub(self.observed.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(TransportError::InvalidTime)
    }
}

fn match_pin(
    pin: &DurableReviewPin,
    preview: &DisclosurePreview,
    envelope_digest: &str,
    content_digest: &str,
) -> Result<()> {
    if pin.context != preview.context
        || pin.order.message_id != preview.order.message_id
        || pin.order.sequence != preview.order.sequence
        || pin.order.issued_at != preview.order.issued_at
        || pin.order.expires_at != preview.order.expires_at
        || pin.envelope_digest != envelope_digest
        || pin.content_digest != content_digest
    {
        return Err(TransportError::WrongContext);
    }
    Ok(())
}

/// Read-only exact reinspection. This does not accept inbox delivery, reserve a
/// sequence, change any authority deadline, record consent or invoke a key.
/// Factory remains absent until the complete durable pin/state/clock path exists.
fn reinspect_review_package(
    prerequisites: &RestartPrerequisites<'_>,
    signer_secret: &TransportSecret,
    inbox: &SqliteReplayLedger,
) -> Result<OfflineReviewInspection> {
    let imported = Instant::now();
    let setup = prerequisites.setup;
    let expected = prerequisites.expected;
    let pin = prerequisites.pin;
    check_setup(setup, expected)?;
    if inbox.protection() != MailboxProtection::Encrypted
        || inbox.database_identity()? != setup.inbox_identity
        || signer_secret.public_key()? != setup.signer_key
        || pin.owner_setup_digest != setup.owner_setup_digest
        || pin.package_digest != expected.terms.review_package_digest
        || pin.context != review_context(setup, &expected.terms)
    {
        return Err(TransportError::Authentication);
    }
    let remaining_at_start = prerequisites.clock.window(&pin.order)?;
    let retained = inbox
        .retained_for_context(&pin.context, pin.order.sequence)?
        .ok_or(TransportError::AuthorityUnavailable)?;
    let recovered = recover_received(&retained, signer_secret, &setup.source_key, &pin.context)?;
    let artifact = recovered.artifact();
    match_pin(
        pin,
        artifact.preview(),
        artifact.envelope_digest(),
        artifact.content_digest(),
    )?;
    // Recover is historical only. This full independent verifier is mandatory,
    // including the still-unavailable minimal disclosure qualification gate.
    let display = inspect_fields(artifact.fields(), setup, expected)?;
    prerequisites.clock.window(&pin.order)?;
    let inspection = OfflineReviewInspection {
        terms: expected.terms.clone(),
        proposal: expected.proposal.clone(),
        policy: expected.policy.clone(),
        input_actions: expected.input_actions.clone(),
        output_actions: expected.output_actions.clone(),
        pczt: Zeroizing::new(artifact.fields()[1].bytes().to_vec()),
        maximum_actions: expected.maximum_actions,
        display: Zeroizing::new(display),
        source_envelope_digest: artifact.envelope_digest().into(),
        source_content_digest: artifact.content_digest().into(),
        receipt: receipt::from_artifact(artifact, setup, expected)?,
        imported,
        transport_window_remaining: remaining_at_start,
    };
    // Original monotonic budget includes decryption and proof reinspection.
    inspection.recheck()?;
    Ok(inspection)
}

/// Long round-trip while this process retains its original monotonic observation.
/// No historical/persisted DTO can supply `previous`. Renewal repeats all checks
/// and renews only the temporary review UI, never its original transport deadline.
pub(super) fn reinspect_in_process(
    previous: &OfflineReviewInspection,
    signer_secret: &TransportSecret,
    setup: &OwnerEstablishedOfflineSetup,
    expected: &RetainedOfflineReviewInputs,
    inbox: &SqliteReplayLedger,
) -> Result<OfflineReviewInspection> {
    let imported = Instant::now();
    let remaining = previous
        .transport_window_remaining
        .checked_sub(previous.imported.elapsed())
        .filter(|r| !r.is_zero())
        .ok_or(TransportError::InvalidTime)?;
    check_setup(setup, expected)?;
    if previous.terms != expected.terms
        || previous.receipt.owner_setup_digest() != setup.owner_setup_digest
        || inbox.database_identity()? != setup.inbox_identity
        || signer_secret.public_key()? != setup.signer_key
    {
        return Err(TransportError::Authentication);
    }
    let pin = DurableReviewPin {
        context: previous.receipt.preview().context.clone(),
        order: previous.receipt.preview().order.clone(),
        owner_setup_digest: setup.owner_setup_digest.clone(),
        package_digest: previous.package_digest().into(),
        envelope_digest: previous.source_envelope_digest.clone(),
        content_digest: previous.source_content_digest.clone(),
    };
    if pin.context != review_context(setup, &expected.terms) {
        return Err(TransportError::WrongContext);
    }
    let retained = inbox
        .retained_for_context(&pin.context, pin.order.sequence)?
        .ok_or(TransportError::AuthorityUnavailable)?;
    let recovered = recover_received(&retained, signer_secret, &setup.source_key, &pin.context)?;
    let artifact = recovered.artifact();
    match_pin(
        &pin,
        artifact.preview(),
        artifact.envelope_digest(),
        artifact.content_digest(),
    )?;
    let display = inspect_fields(artifact.fields(), setup, expected)?;
    if inbox.database_identity()? != setup.inbox_identity {
        return Err(TransportError::Authentication);
    }
    let inspection = OfflineReviewInspection {
        terms: expected.terms.clone(),
        proposal: expected.proposal.clone(),
        policy: expected.policy.clone(),
        input_actions: expected.input_actions.clone(),
        output_actions: expected.output_actions.clone(),
        pczt: Zeroizing::new(artifact.fields()[1].bytes().to_vec()),
        maximum_actions: expected.maximum_actions,
        display: Zeroizing::new(display),
        source_envelope_digest: artifact.envelope_digest().into(),
        source_content_digest: artifact.content_digest().into(),
        receipt: receipt::from_artifact(artifact, setup, expected)?,
        imported,
        transport_window_remaining: remaining,
    };
    inspection.recheck()?;
    Ok(inspection)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn order() -> MessageOrder {
        MessageOrder {
            message_id: "a".repeat(32),
            sequence: 1,
            issued_at: Timestamp::from_unix_seconds(100).unwrap(),
            expires_at: Timestamp::from_unix_seconds(200).unwrap(),
        }
    }
    fn clock(lower: i64, upper: i64) -> RestartClock {
        RestartClock {
            lower_unix_seconds: lower,
            upper_unix_seconds: upper,
            observed: Instant::now(),
        }
    }
    #[test]
    fn interval_straddling_original_expiry_is_refused() {
        assert!(clock(190, 200).window(&order()).is_err());
        assert!(clock(190, 201).window(&order()).is_err());
    }
    #[test]
    fn rollback_before_original_issuance_and_reversed_clock_are_refused() {
        assert!(clock(99, 150).window(&order()).is_err());
        assert!(clock(151, 150).window(&order()).is_err());
    }
    #[test]
    fn restart_does_not_refresh_original_deadline() {
        assert!(clock(190, 195).window(&order()).unwrap() <= Duration::from_secs(5));
        assert!(clock(200, 200).window(&order()).is_err());
    }
    #[test]
    fn spent_monotonic_budget_cannot_restart_review() {
        let mut c = clock(190, 195);
        c.observed = Instant::now().checked_sub(Duration::from_secs(6)).unwrap();
        assert!(c.window(&order()).is_err());
    }
    #[test]
    fn receipt_pin_rejects_changed_context_order_and_ciphertext() {
        let context = MessageContext {
            network_profile_id: "synthetic-profile".into(),
            agreement_id: "synthetic-agreement".into(),
            proposal_id: "synthetic-proposal".into(),
            proposal_revision: 1,
            sender_id: "synthetic-source".into(),
            recipient_id: "synthetic-signer".into(),
            artifact_kind: ArtifactKind::ProvedProposal,
        };
        let pin = DurableReviewPin {
            context: context.clone(),
            order: order(),
            owner_setup_digest: "a".repeat(64),
            package_digest: "b".repeat(64),
            envelope_digest: "c".repeat(64),
            content_digest: "d".repeat(64),
        };
        let mut preview = DisclosurePreview {
            schema_version: 1,
            context,
            order: order(),
            sender_key_fingerprint: "e".repeat(64),
            recipient_key_fingerprint: "f".repeat(64),
            purpose: "synthetic".into(),
            persistence_warning: "synthetic".into(),
            fields: vec![],
            payload_digest: "0".repeat(64),
        };
        assert!(match_pin(&pin, &preview, &pin.envelope_digest, &pin.content_digest).is_ok());
        assert!(match_pin(&pin, &preview, &"0".repeat(64), &pin.content_digest).is_err());
        assert!(match_pin(&pin, &preview, &pin.envelope_digest, &"0".repeat(64)).is_err());
        preview.context.artifact_kind = ArtifactKind::OfflineAuthorityAdmission;
        assert!(match_pin(&pin, &preview, &pin.envelope_digest, &pin.content_digest).is_err());
        preview.context = pin.context.clone();
        preview.order.sequence = 2;
        assert!(match_pin(&pin, &preview, &pin.envelope_digest, &pin.content_digest).is_err());
        preview.order = order();
        preview.order.expires_at = Timestamp::from_unix_seconds(201).unwrap();
        assert!(match_pin(&pin, &preview, &pin.envelope_digest, &pin.content_digest).is_err());
    }
}
