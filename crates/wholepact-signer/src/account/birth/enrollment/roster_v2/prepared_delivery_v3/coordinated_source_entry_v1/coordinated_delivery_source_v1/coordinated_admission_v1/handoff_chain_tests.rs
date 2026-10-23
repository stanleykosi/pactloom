//! Inert, validated public DTOs exercise the production Prepare→Received
//! comparison kernel. No source, peer, opaque binding or genuine Final is
//! fabricated. This does not qualify the native multi-actor path.
use super::*;
use wholepact_financial_coordinator_origin::{
    SignerContinueRoleV1, SignerV3AdmitReadPresentationV1,
};

fn h(byte: u8) -> String { format!("{byte:02x}").repeat(32) }

fn presentations() -> (SignerV3PrepareReadPresentationV1, SignerV3AdmitReadPresentationV1) {
    // Ordinary serde DTO construction, never an authority/Final constructor.
    let owner = serde_json::json!({
        "schema_version": 1, "endpoint": "127.0.0.1:443", "server_name": "synthetic.example",
        "witness_id": "synthetic-witness", "account_id": "synthetic-account",
        "network_profile_id": "synthetic-network", "policy_digest": h(1),
        "pinned_server_certificate_digest": h(2), "trusted_server_root_der": "/synthetic/root.der",
        "client_certificate_der": "/synthetic/client.der", "client_private_key_pkcs8_der": "/synthetic/key.der",
        "operator_name": "synthetic", "retention_statement": "inert test metadata only"
    });
    let mut read: SignerV3PrepareReadPresentationV1 = serde_json::from_value(serde_json::json!({
        "actor": {
            "profile": "coordinated-financial-workflow-v1", "coordinator_process_instance": h(3),
            "coordinator_focus_epoch": 1, "signer_role": "signer1", "signer_process_instance": h(4),
            "common_image_measurement": h(5), "session_challenge": h(6)
        },
        "facts": {
            "entry_presentation_digest": h(10), "source_identity_digest": h(11),
            "pair_grant_id": h(12), "pair_key_digest": h(13), "pair_channel_digest": h(14),
            "coordinated_session_id": h(15), "current_enrollment_ref": h(16), "current_manifest_ref": h(17),
            "current_outbox_reference": h(18), "current_request_digest": h(19), "preparation_digest": h(20),
            "owner_selection_digest": h(21), "owner_certificate_digest": h(22), "disclosure_digest": h(23),
            "payload_digest": h(24), "fixed_identity_digest": h(25), "material_scopes_digest": h(26),
            "coordinated_provider_reference": h(27), "original_host_process_instance": h(28),
            "display": "Synthetic PrepareRead data, not permission", "preparation_json": "{}",
            "owner_setup_json": owner.to_string(), "owner_selection_challenge": h(29),
            "pair_generation": 1, "payload_bytes": 123, "reviewed_at_ms": 1000, "expires_at_ms": 2000,
            "source_expires_at_ms": 600000, "service_expires_at_ms": 550000, "material_expires_at_ms": 500000
        },
        "notice": "Read exactly the selected private source and owner client key to prepare this immutable recipient delivery and retain local client custody. This does not authenticate a remote owner or authorize history, Receive, admission, export or financial effects.",
        "challenge": h(30), "source_ceiling_ms": 600000, "review_ceiling_ms": 2000,
        "service_ceiling_ms": 550000, "material_ceiling_ms": 500000, "presentation_digest": ""
    })).unwrap();
    read.presentation_digest = read.calculate_presentation_digest().unwrap();
    read.validate().unwrap();
    let f = &read.facts;
    let mut admission: SignerV3AdmitReadPresentationV1 = serde_json::from_value(serde_json::json!({
        "actor": read.actor,
        "facts": {
            "received": {
                "receive_presentation_digest": h(31), "prepare_read_presentation_digest": read.presentation_digest,
                "source_identity_digest": f.source_identity_digest, "owner_service_digest": h(32),
                "recipient_intent_digest": h(33), "payload_digest": f.payload_digest,
                "payload_bytes": f.payload_bytes, "fixed_identity_digest": f.fixed_identity_digest
            },
            "owner_selection_digest": f.owner_selection_digest, "owner_certificate_digest": f.owner_certificate_digest,
            "disclosure_digest": f.disclosure_digest, "display": "Synthetic AdmitRead data, not permission",
            "reviewed_at_ms": 3000, "expires_at_ms": 4000, "source_expires_at_ms": f.source_expires_at_ms,
            "service_expires_at_ms": f.service_expires_at_ms, "material_expires_at_ms": f.material_expires_at_ms
        },
        "notice": "Read the full authenticated history from this original selected owner and prepare one exact local immutable admission request and journal candidate for this verified payload. No local INSERT, remote READY, admission, audit or financial action is approved.",
        "challenge": h(34), "source_ceiling_ms": read.source_ceiling_ms, "review_ceiling_ms": 4000,
        "service_ceiling_ms": read.service_ceiling_ms, "material_ceiling_ms": read.material_ceiling_ms,
        "presentation_digest": ""
    })).unwrap();
    admission.presentation_digest = admission.calculate_presentation_digest().unwrap();
    admission.validate().unwrap();
    (read, admission)
}

fn caps() -> [Instant; 4] {
    let now = Instant::now();
    [600, 590, 500, 550].map(|seconds| now + Duration::from_secs(seconds))
}

#[test]
fn handoff_admit_read_chain_rejects_each_received_and_owner_binding_mismatch() {
    let (read, admission) = presentations();
    let bounds = caps();
    require_admit_read_purpose_binding(&read, &admission, bounds, bounds).unwrap();
    for field in 0..8 {
        let mut changed = admission.clone();
        match field {
            0 => changed.facts.received.source_identity_digest = h(250),
            1 => changed.facts.received.prepare_read_presentation_digest = h(250),
            2 => changed.facts.received.payload_digest = h(250),
            3 => changed.facts.received.payload_bytes += 1,
            4 => changed.facts.received.fixed_identity_digest = h(250),
            5 => changed.facts.owner_selection_digest = h(250),
            6 => changed.facts.owner_certificate_digest = h(250),
            _ => changed.facts.disclosure_digest = h(250),
        }
        changed.presentation_digest = changed.calculate_presentation_digest().unwrap();
        changed.validate().unwrap();
        assert!(matches!(require_admit_read_purpose_binding(&read, &changed, bounds, bounds),
            Err(Error::ReviewMismatch)), "accepted changed chain field {field}");
    }
}

#[test]
fn handoff_admit_read_chain_rejects_each_actor_role_and_session_mismatch() {
    let (read, admission) = presentations();
    let bounds = caps();
    require_admit_read_purpose_binding(&read, &admission, bounds, bounds).unwrap();
    for field in 0..7 {
        let mut changed = admission.clone();
        match field {
            0 => changed.actor.profile.push_str("-other"),
            1 => changed.actor.coordinator_process_instance = h(250),
            2 => changed.actor.coordinator_focus_epoch += 1,
            3 => changed.actor.signer_role = SignerContinueRoleV1::Signer2,
            4 => changed.actor.signer_process_instance = h(250),
            5 => changed.actor.common_image_measurement = h(250),
            _ => changed.actor.session_challenge = h(250),
        }
        // Test the exact-actor kernel itself, independently of schema rejection
        // for an unknown profile/focus epoch. No changed DTO becomes a Final.
        assert!(matches!(require_admit_read_purpose_binding(&read, &changed, bounds, bounds),
            Err(Error::ReviewMismatch)), "accepted changed actor field {field}");
    }
}

#[test]
fn handoff_admit_read_chain_rejects_rebound_prepare_refs_session_pair_and_material() {
    let (read, admission) = presentations();
    let bounds = caps();
    for field in 0..12 {
        let mut changed = read.clone();
        match field {
            0 => changed.facts.current_enrollment_ref = h(250),
            1 => changed.facts.current_manifest_ref = h(250),
            2 => changed.facts.coordinated_session_id = h(250),
            3 => changed.facts.pair_grant_id = h(250),
            4 => changed.facts.pair_key_digest = h(250),
            5 => changed.facts.pair_channel_digest = h(250),
            6 => changed.facts.current_outbox_reference = h(250),
            7 => changed.facts.current_request_digest = h(250),
            8 => changed.facts.preparation_digest = h(250),
            9 => changed.facts.material_scopes_digest = h(250),
            10 => changed.facts.coordinated_provider_reference = h(250),
            _ => changed.facts.original_host_process_instance = h(250),
        }
        changed.presentation_digest = changed.calculate_presentation_digest().unwrap();
        changed.validate().unwrap();
        // A rehashed but different Prepare DTO is not the exact presentation
        // retained by the Received result. Public data cannot rebind the chain.
        assert!(matches!(require_admit_read_purpose_binding(&changed, &admission, bounds, bounds),
            Err(Error::ReviewMismatch)), "accepted rebound Prepare field {field}");
    }
}

#[test]
fn handoff_admit_read_chain_rejects_changed_original_source_channel_material_service_caps() {
    let (read, admission) = presentations();
    let bounds = caps();
    require_admit_read_purpose_binding(&read, &admission, bounds, bounds).unwrap();
    for field in 0..4 {
        for later in [false, true] {
            let mut changed = bounds;
            changed[field] = if later { changed[field] + Duration::from_nanos(1) }
                else { changed[field] - Duration::from_nanos(1) };
            assert!(matches!(require_admit_read_purpose_binding(&read, &admission, bounds, changed),
                Err(Error::ReviewMismatch)), "accepted changed original cap {field}");
        }
    }
}
