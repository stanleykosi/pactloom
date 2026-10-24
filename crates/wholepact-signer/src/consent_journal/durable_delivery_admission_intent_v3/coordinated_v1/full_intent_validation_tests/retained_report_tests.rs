//! Complete inert report/display characterization. No Final, source owner,
//! permission, purpose binding, publication or channel is manufactured. The
//! private candidate is used ONLY for its actual immutable display/digest/data
//! getters; all journal/account fields come from the real encrypted fixture.
use super::*;
use wholepact_financial_coordinator_origin::{
    FinancialActorContextV1, SignerV3AdmitFactsV1, SignerV3AdmitPresentationV1,
    SignerV3AdmitReadRetainedV1,
};

const ADMIT_NOTICE: &str = "Prepare only this exact admission on the retained original owner client. An authenticated READY must be retained on the same live connection and separately approved before local journal publication and the exact remote send. Unknown outcomes remain retained, never permission to retry; fresh Audit is still required.";

// Exact serde envelope projection of the private Packet variant, not its
// transport/payload implementation. Source audit binds the tag and8-byte header.
#[derive(serde::Serialize)]
#[serde(tag = "kind")]
enum PacketProjection<'a> {
    V3AdmitDisplay { presentation: &'a SignerV3AdmitPresentationV1 },
}

fn facts(i: &CoordinatedAdmissionIntentV1, report: SignerV3AdmitReadRetainedV1) -> SignerV3AdmitFactsV1 {
    SignerV3AdmitFactsV1 {
        display: report.display.clone(), read: report,
        request_json: checked(serde_json::to_string(&i.request)),
        reviewed_at_ms: i.admit_read.approved_at_ms + 10_000,
        expires_at_ms: i.admit_read.expires_at_ms - 10_000,
        source_expires_at_ms: i.ceilings.original_source_expires_at_ms,
        service_expires_at_ms: i.ceilings.original_owner_service_expires_at_ms,
        material_expires_at_ms: i.ceilings.original_material_expires_at_ms,
    }
}
fn presentation(facts: SignerV3AdmitFactsV1) -> SignerV3AdmitPresentationV1 {
    let actor: FinancialActorContextV1 = checked(serde_json::from_value(serde_json::json!({
        "profile": "coordinated-financial-workflow-v1", "coordinator_process_instance": h(0xc3),
        "coordinator_focus_epoch": 1, "signer_role": "signer1", "signer_process_instance": h(0xc4),
        "common_image_measurement": h(0xc5), "session_challenge": h(0xc6)
    })));
    assert!(actor.validate().is_ok(), "report fixture inert actor shape");
    let mut p = SignerV3AdmitPresentationV1 {
        actor, facts, notice: ADMIT_NOTICE.into(), challenge: h(0xc7),
        source_ceiling_ms: 900_000, review_ceiling_ms: 360_000,
        service_ceiling_ms: 600_000, material_ceiling_ms: 900_000,
        presentation_digest: String::new(),
    };
    p.presentation_digest = checked(p.calculate_presentation_digest()); p
}
fn packet_bytes(p: &SignerV3AdmitPresentationV1) -> usize {
    checked(serde_json::to_vec(&PacketProjection::V3AdmitDisplay { presentation: p })).len() + 8
}

fn measure_case(
    f: &MaterialFixture,
    mut i: CoordinatedAdmissionIntentV1,
    material_input_id: bool,
) -> ((usize, usize, usize), impl FnOnce()) {
    assert!(i.validate().is_ok(), "report case complete retained DTO");
    let input_id_bytes = checked(record(&i.request)).scope.authorization.inputs[0].input_id.len();
    // Match the actual prepared stage: admission provenance is absent; it is
    // excluded from both review digest and the complete display projection.
    i.admission = AdmissionProvenanceV1 {
        read_session_digest: String::new(), admit_read_presentation_digest: String::new(),
        final_presentation_digest: String::new(), authenticated_ready_digest: String::new(),
        reviewed_digest: String::new(), reviewed_at_ms: 0, retained_at_ms: 0, expires_at_ms: 0,
    };
    assert!(i.validate_review().is_ok(), "report fixture full review");
    {
        let c = checked(f.journal().connection.lock()); let before = c.total_changes();
        assert!(storage::verify_schema(&c).is_ok(), "report fixture encrypted schema");
        assert!(validate_original_rows(&c, &i).is_ok(), "report fixture original rows");
        assert!(before == c.total_changes());
    }
    let prepared = PreparedCoordinatedAdmissionIntentV1 {
        journal: f.journal().binding(), account: checked(f.journal().account_state()),
        source_identity: i.read.source_identity_digest.clone(),
        review_digest: checked(i.review_digest()), intent: i.clone(),
    };
    let display = checked(prepared.display());
    // Exact prior pretty oracle versus the actual lossless compact getter.
    let tuple = (&i.request, &i.disclosure, &i.owner_certificate_digest,
        &i.enrollment_ref, &i.manifest_ref, &i.recipient_intent, &i.read,
        &i.admit_read, &i.ceilings);
    // Exact frozen P56/P57 pretty expression remains the old-behavior oracle.
    let pretty = checked(serde_json::to_string_pretty(&tuple));
    let compact = checked(serde_json::to_string(&tuple));
    assert!(display == compact, "actual display must be the complete compact tuple");
    let pretty_value: serde_json::Value = checked(serde_json::from_str(&pretty));
    let compact_value: serde_json::Value = checked(serde_json::from_str(&display));
    assert!(pretty_value == compact_value, "compact diagnostic must retain every field");
    let request = prepared.request();
    let report = SignerV3AdmitReadRetainedV1 {
        admit_read_presentation_digest: i.admit_read.presentation_digest.clone(),
        source_identity_digest: i.admit_read.source_identity_digest.clone(),
        owner_service_digest: i.admit_read.owner_service_digest.clone(),
        recipient_intent_digest: checked(i.recipient_intent.digest()),
        authenticated_history_digest: i.admit_read.authenticated_history_digest.clone(),
        admission_request_digest: checked(prepared.request_digest()),
        admission_review_digest: prepared.review_digest().into(),
        operation_id: request.operation_id.clone(), expected_head_sequence: request.expected_head.sequence,
        expected_head_digest: request.expected_head.digest.clone(), display: pretty,
    };
    assert!(report.recipient_intent_digest == i.admit_read.recipient_intent_digest);
    assert!(report.admission_request_digest == checked(i.request_digest()));
    assert!(report.admission_review_digest == checked(i.review_digest()));

    // Isolate the current rejection: all eight hashes, operation/head fields,
    // actor and clocks pass real validators when ONLY display is a short control.
    // This control is never emitted or treated as a repaired production report.
    let mut control = report.clone(); control.display = "inert size-isolation control".into();
    assert!(control.validate().is_ok(), "non-display retained fields must pass");
    let control_facts = facts(&i, control);
    assert!(control_facts.validate().is_ok(), "non-display Admit facts must pass");
    let control_presentation = presentation(control_facts);
    assert!(control_presentation.validate().is_ok(), "non-display Admit presentation must pass");
    assert!(packet_bytes(&control_presentation) <= 65_536);

    let pretty_facts = facts(&i, report.clone());
    let pretty_presentation = presentation(pretty_facts.clone());
    let mut compact_report = report.clone(); compact_report.display = display;
    let compact_facts = facts(&i, compact_report.clone());
    let compact_presentation = presentation(compact_facts.clone());
    let pretty_facts_bytes = checked(serde_json::to_vec(&pretty_facts)).len();
    let compact_facts_bytes = checked(serde_json::to_vec(&compact_facts)).len();
    let pretty_presentation_bytes = checked(serde_json::to_vec(&pretty_presentation)).len();
    let compact_presentation_bytes = checked(serde_json::to_vec(&compact_presentation)).len();
    // Only finite sizes/outcomes are logged: no display, request, keys or IDs.
    eprintln!("COORDINATED_RETAINED_REPORT_SIZE_V2 {}", serde_json::json!({
        "material_input_id": material_input_id, "input_id_bytes": input_id_bytes,
        "pretty_display_bytes": report.display.len(), "compact_display_bytes": compact_report.display.len(),
        "request_json_bytes": pretty_facts.request_json.len(),
        "pretty_facts_bytes": pretty_facts_bytes, "compact_facts_bytes": compact_facts_bytes,
        "pretty_presentation_bytes": pretty_presentation_bytes, "compact_presentation_bytes": compact_presentation_bytes,
        "pretty_packet_bytes": packet_bytes(&pretty_presentation), "compact_packet_bytes": packet_bytes(&compact_presentation),
        "pretty_report_valid": report.validate().is_ok(), "compact_report_valid": compact_report.validate().is_ok(),
        "pretty_facts_valid": pretty_facts.validate().is_ok(), "compact_facts_valid": compact_facts.validate().is_ok(),
        "pretty_presentation_valid": pretty_presentation.validate().is_ok(), "compact_presentation_valid": compact_presentation.validate().is_ok()
    }));
    let sizes = (report.display.len(), compact_report.display.len(), pretty_facts.request_json.len());
    // Both cases emit their strict finite records before any final size verdict.
    let check = move || {
        assert_eq!(packet_bytes(&pretty_presentation), pretty_presentation_bytes + 41 + 8);
        assert_eq!(packet_bytes(&compact_presentation), compact_presentation_bytes + 41 + 8);
        assert_eq!(report.validate().is_ok(), report.display.len() <= 16_384);
        assert_eq!(compact_report.validate().is_ok(), compact_report.display.len() <= 16_384);
        assert_eq!(compact_facts.validate().is_ok(), compact_report.display.len() <= 16_384
            && compact_facts.request_json.len() <= 16_384 && compact_facts_bytes <= 48 * 1024);
        assert_eq!(compact_presentation.validate().is_ok(), compact_facts.validate().is_ok()
            && compact_presentation_bytes <= 60 * 1024);
        if material_input_id {
            assert!(input_id_bytes >= 75, "real decoded input ID must retain its full canonical length");
            assert!(report.display.len() > 16_384, "real material input ID must reproduce the prior oversized display");
            assert!(report.validate().is_err(), "old full report must demonstrate size rejection");
        } else {
            assert_eq!(input_id_bytes, 11);
            assert_eq!(report.display.len(), 16_381, "preserve actual P57 short-fixture boundary");
            assert!(report.validate().is_ok(), "the historical short fixture was not oversized");
        }
        assert!(compact_report.validate().is_ok(), "actual compact full report");
        assert!(compact_facts.validate().is_ok(), "actual compact full Admit facts");
        assert!(compact_presentation.validate().is_ok(), "actual compact full presentation");
        assert!(packet_bytes(&compact_presentation) <= 65_536, "actual compact packet budget");
    };
    (sizes, check)
}

#[test]
fn complete_prepared_display_reproduces_retained_and_admit_size_boundaries() {
    let f = MaterialFixture::coordinated();
    let short = complete(&f);
    assert_eq!(checked(record(&short.request)).scope.authorization.inputs.len(), 1);
    let material_ids = f.rows()[0].request().material.input_ids().collect::<Vec<_>>();
    assert_eq!(material_ids.len(), 1);
    let actual_id = material_ids[0];
    let short_id_bytes = checked(record(&short.request)).scope.authorization.inputs[0].input_id.len();
    assert!(actual_id.starts_with("ironwood:"));
    assert!(actual_id.len() >= 75 && actual_id.len() > short_id_bytes);
    let mut realistic = short.clone();
    // Only this real decoded material field varies. No arbitrary padding,
    // extra inputs, renamed display keys, removed data, or cap increase.
    scope_mut(&mut realistic).authorization.inputs[0].input_id = actual_id.into();
    rebind_request(&mut realistic); retain(&mut realistic);
    let (before, check_before) = measure_case(&f, short, false);
    let (after, check_after) = measure_case(&f, realistic, true);
    check_before(); check_after();
    let delta = actual_id.len() - short_id_bytes;
    assert_eq!(after.0 - before.0, delta, "only input-ID length changes pretty display");
    assert_eq!(after.1 - before.1, delta, "only input-ID length changes compact display");
    assert_eq!(after.2 - before.2, delta, "only input-ID length changes actual request JSON");
}
