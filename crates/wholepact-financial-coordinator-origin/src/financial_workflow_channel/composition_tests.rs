//! Real private encoder regression over inert public data. No Core, peer,
//! socket, Final, or permission is constructed. This is an implication-gap
//! counterexample, not evidence that the shared realistic Signer fixture fails.
use super::*;
use crate::financial_workflow_continue::{ContinueStart, ContinueWire};
use crate::{SignerContinuePresentationV1, SignerContinueReviewDataV1};

#[test]
fn continue_valid_data_can_exceed_actual_packet_and_original_peer_join_remains_exact() {
    let mut entry = sample_entry();
    entry.presentation.actor.signer_process_instance="b1".repeat(32);
    entry.presentation.facts.original_host_process_instance="b2".repeat(32);
    entry.presentation.presentation_digest=entry.presentation.calculate_presentation_digest().unwrap();
    entry.crypto.signer_process_instance=entry.presentation.actor.signer_process_instance.clone();
    entry.crypto.original_host_process_instance=entry.presentation.facts.original_host_process_instance.clone();
    entry.crypto.presentation_digest=entry.presentation.presentation_digest.clone();
    entry.validate().unwrap();
    let mut read = sample_read(&entry);
    // Independent identity domains: observed S, original H, C and source must
    // never accidentally compare equal because a fixture reused one hash.
    read.facts.original_host_process_instance = "b2".repeat(32);
    read.facts.source_identity_digest = "b3".repeat(32);
    read.facts.read_digest = read.facts.calculate_read_digest().unwrap();
    read.presentation_digest = read.calculate_presentation_digest().unwrap();
    read.validate().unwrap();
    assert!(read.matches_entry(&entry.presentation));
    let a = &read.actor; let f = &read.facts;
    let mut presentation = SignerContinuePresentationV1 {
        review: SignerContinueReviewDataV1 {
            coordinator_process_instance:a.coordinator_process_instance.clone(),
            coordinator_focus_epoch:a.coordinator_focus_epoch, signer_role:a.signer_role,
            signer_process_instance:a.signer_process_instance.clone(),
            original_host_process_instance:f.original_host_process_instance.clone(),
            signer_principal_id:"inert-original-principal".into(),
            signer_image_measurement:a.common_image_measurement.clone(),
            source_identity_digest:f.source_identity_digest.clone(), terms_digest:f.terms_digest.clone(),
            session_digest:f.session_digest.clone(), review_challenge:"b4".repeat(32),
            review_digest:"b5".repeat(32), reviewed_at_ms:f.reviewed_at_ms,
            expires_at_ms:f.expires_at_ms, session_expires_at_ms:f.source_expires_at_ms,
        },
        display:"Exact inert Continue encoder control".into(), request_json:"{}".into(),
        request_digest:SignerContinuePresentationV1::calculate_request_digest("{}"),
        prepared_digest:"b6".repeat(32), presentation_digest:String::new(),
    };
    presentation.presentation_digest = presentation.calculate_presentation_digest().unwrap();
    let mut wire = ContinueWire {
        context:ContinueStart { start:entry.start.clone(),
            entry_presentation_digest:read.source_entry_presentation_digest.clone(),
            read_presentation_digest:read.presentation_digest.clone(),
            challenge:"b7".repeat(32), native_ceiling_ms:120_000 },
        presentation, source_ceiling_ms:read.source_ceiling_ms, review_ceiling_ms:read.read_ceiling_ms,
    };
    wire.validate().unwrap();
    assert!(wire.matches_read(&entry.start,&read));
    let control = Packet::ContinueDisplay { binding:wire.clone() };
    assert!(payload(&control).unwrap().len()+8 <= MAX_PACKET);
    let mut wrong = wire.clone();
    wrong.presentation.review.original_host_process_instance = read.actor.signer_process_instance.clone();
    wrong.presentation.presentation_digest = wrong.presentation.calculate_presentation_digest().unwrap();
    wrong.validate().unwrap();
    assert!(!wrong.matches_read(&entry.start,&read), "observed Signer is not original Host");
    wire.presentation.display = "\\".repeat(32_768);
    wire.presentation.presentation_digest = wire.presentation.calculate_presentation_digest().unwrap();
    wire.validate().unwrap();
    assert!(wire.matches_read(&entry.start,&read));
    let oversized = Packet::ContinueDisplay { binding:wire };
    assert!(serde_json::to_vec(&oversized).unwrap().len() > MAX_PACKET-8);
    assert!(payload(&oversized).is_err(), "real encoder must retain fail-closed packet bound");
}
