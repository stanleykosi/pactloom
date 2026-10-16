//! Private disabled witness composition. No public factory or endpoint.
//! Original request/envelope are durably fixed before concrete inbox acceptance.
use super::*;
use wholepact_authority::{
    AuthenticatedOfflineIntent, OfflineIntentAuthenticationIssuer, OfflineOriginalBridge,
    OfflineAdmissionExportPlan, OriginalTransportReceipt, RetainedOfflineOriginal,
};

#[allow(dead_code, clippy::too_many_arguments)]
fn authenticate_and_bind_intent(
    original_bridge: &OfflineOriginalBridge<'_>,
    issuer: &OfflineIntentAuthenticationIssuer,
    envelope: &EncryptedEnvelope,
    unallocated_plan: OfflineAdmissionExportPlan,
    witness_secret: &TransportSecret,
    signer_key: &TransportPublicKey,
    policy: &OfflineEnrollmentPolicy,
    expected_request: &ReserveOfflineAuthorization,
    now: &Timestamp,
    inbox: &mut SqliteReplayLedger,
) -> Result<AuthenticatedOfflineIntent> {
    expected_request.validate().map_err(|_| TransportError::Malformed)?;
    check_enrollment_binding(witness_secret, signer_key, policy, &expected_request.intent, inbox)?;
    // Authority prepare requires sequence zero, retains the exact unallocated
    // metadata, original operation/head/window and encrypted input, and allocates
    // no outbound stream slot until the authenticated callback below.
    let original = original_bridge.prepare(expected_request, envelope.as_bytes(), unallocated_plan, milliseconds(now)?)
        .map_err(|_| TransportError::AuthorityUnavailable)?;
    open_retained_and_bind(original_bridge, issuer, &original, witness_secret, signer_key, policy, now, inbox)
}

#[allow(dead_code, clippy::too_many_arguments)]
fn recover_and_bind_original_intent(
    original_bridge: &OfflineOriginalBridge<'_>, issuer: &OfflineIntentAuthenticationIssuer,
    operation_id: &str, original_request_digest: &str,
    witness_secret: &TransportSecret, signer_key: &TransportPublicKey,
    policy: &OfflineEnrollmentPolicy, now: &Timestamp, inbox: &mut SqliteReplayLedger,
) -> Result<AuthenticatedOfflineIntent> {
    // These references only select retained state. The authority bridge checks
    // current enrollment, active writer/session, request expiry and quarantine.
    let original = original_bridge.recover(operation_id, original_request_digest, milliseconds(now)?)
        .map_err(|_| TransportError::AuthorityUnavailable)?
        .ok_or(TransportError::WrongContext)?;
    check_enrollment_binding(witness_secret, signer_key, policy, &original.request().intent, inbox)?;
    let context = intent_context(&original.request().intent)?;
    if let Some(expected_receipt) = original.authenticated_receipt() {
        if let Some(retained) = inbox.retained_for_context(&context, expected_receipt.sequence)? {
            let recovered = recover_received(&retained, witness_secret, signer_key, &context)?;
            // Conservative disabled profile: expired historical transport remains
            // inspectable by public history API, but cannot resume token issuance.
            if !recovered.is_currently_valid(now) { return Err(TransportError::InvalidTime); }
            let artifact = recovered.artifact();
            validate_intent_payload(artifact, &original.request().intent)?;
            let receipt = transport_receipt(artifact)?;
            if &receipt != expected_receipt { return Err(TransportError::Authentication); }
            original_bridge.record_inbox_accepted(
                &original.prepared_record_digest().map_err(|_| TransportError::Authentication)?,
                &original.request().operation_id, receipt, milliseconds(now)?,
            ).map_err(|_| TransportError::AuthorityUnavailable)?;
            return bind_original(issuer, &original, artifact, witness_secret, signer_key);
        }
    }
    // Crash before inbox commit: re-open ONLY the retained original bytes. This
    // cannot choose a replacement operation, head, message ID or validity window.
    open_retained_and_bind(original_bridge, issuer, &original, witness_secret, signer_key, policy, now, inbox)
}

#[allow(clippy::too_many_arguments)]
fn open_retained_and_bind(
    original_bridge: &OfflineOriginalBridge<'_>, issuer: &OfflineIntentAuthenticationIssuer,
    original: &RetainedOfflineOriginal, witness_secret: &TransportSecret,
    signer_key: &TransportPublicKey, policy: &OfflineEnrollmentPolicy,
    now: &Timestamp, inbox: &mut SqliteReplayLedger,
) -> Result<AuthenticatedOfflineIntent> {
    check_enrollment_binding(witness_secret, signer_key, policy, &original.request().intent, inbox)?;
    let prepared = original.prepared_record_digest().map_err(|_| TransportError::Authentication)?;
    let envelope = EncryptedEnvelope::from_bytes(original.original_envelope_bytes().to_vec())?;
    let context = intent_context(&original.request().intent)?;
    let now_ms = milliseconds(now)?;
    let artifact = open_envelope_checked(
        &envelope, witness_secret, signer_key, &context, now, inbox,
        |artifact| {
            validate_intent_payload(artifact, &original.request().intent)?;
            original_bridge.record_authenticated_receipt(
                &prepared, &original.request().operation_id, transport_receipt(artifact)?, now_ms,
            ).map_err(|_| TransportError::AuthorityUnavailable)
        },
    )?;
    // A Replay/error is never treated as successful inbox acceptance. Recovery
    // above reauthenticates actual retained ciphertext before this journal mark.
    original_bridge.record_inbox_accepted(
        &prepared, &original.request().operation_id, transport_receipt(&artifact)?, now_ms,
    ).map_err(|_| TransportError::AuthorityUnavailable)?;
    bind_original(issuer, original, &artifact, witness_secret, signer_key)
}

fn bind_original(
    issuer: &OfflineIntentAuthenticationIssuer, original: &RetainedOfflineOriginal,
    artifact: &ReceivedArtifact, witness_secret: &TransportSecret, signer_key: &TransportPublicKey,
) -> Result<AuthenticatedOfflineIntent> {
    issuer.bind_verified_intent(
        original.request(), &original.request().intent, &signer_key.fingerprint(),
        &witness_secret.public_key()?.fingerprint(), artifact.envelope_digest(),
    ).map_err(|_| TransportError::Authentication)
}

fn transport_receipt(artifact: &ReceivedArtifact) -> Result<OriginalTransportReceipt> {
    let p = artifact.preview(); let c = &p.context; let o = &p.order;
    if c.artifact_kind != ArtifactKind::OfflineReservationIntent { return Err(TransportError::WrongContext); }
    Ok(OriginalTransportReceipt {
        network_profile_id: c.network_profile_id.clone(), agreement_id: c.agreement_id.clone(),
        proposal_id: c.proposal_id.clone(), proposal_revision: c.proposal_revision,
        sender_id: c.sender_id.clone(), recipient_id: c.recipient_id.clone(),
        artifact_kind: "offline_reservation_intent".into(), message_id: o.message_id.clone(),
        sequence: o.sequence, issued_at_unix_seconds: o.issued_at.unix_seconds(),
        expires_at_unix_seconds: o.expires_at.unix_seconds(),
        sender_key_fingerprint: p.sender_key_fingerprint.clone(), recipient_key_fingerprint: p.recipient_key_fingerprint.clone(),
        stream_digest: artifact.stream_digest().into(), preview_digest: p.digest()?,
        content_digest: artifact.content_digest().into(), payload_digest: p.payload_digest.clone(),
        envelope_digest: artifact.envelope_digest().into(),
    })
}
fn milliseconds(now: &Timestamp) -> Result<u64> {
    u64::try_from(now.unix_seconds()).ok().and_then(|v| v.checked_mul(1000))
        .ok_or(TransportError::InvalidTime)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn witness_clock_conversion_is_exact_not_a_renewal() {
        assert_eq!(milliseconds(&Timestamp::from_unix_seconds(123).unwrap()).unwrap(), 123000);
    }
}
