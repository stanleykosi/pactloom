//! Actual production admission-chain equality predicate, using inert borrowed
//! carriers only. Each numbered identity corresponds to the fixed production
//! assembly in PreparedCoordinatedAdmissionIntentV1::purpose_binding. This
//! tests rejection, not actual digest computation, source/Final construction,
//! publication, or minting an opaque admission binding.
use super::*;
use std::time::{Duration, Instant};
use wholepact_financial_coordinator_origin::{FinancialActorContextV1, SignerContinueRoleV1};

fn actor() -> FinancialActorContextV1 {
    let actor = FinancialActorContextV1 {
        profile: "coordinated-financial-workflow-v1".into(),
        coordinator_process_instance: "a1".repeat(32),
        coordinator_focus_epoch: 1,
        signer_role: SignerContinueRoleV1::Signer1,
        signer_process_instance: "a2".repeat(32),
        common_image_measurement: "a3".repeat(32),
        session_challenge: "a4".repeat(32),
    };
    actor.validate().unwrap();
    actor
}

const IDENTITIES: [&str; 21] = [
    "retained-source/source", "retained-source/prepare", "retained-source/admit",
    "enrollment/source", "manifest/source", "enrollment/prepare", "manifest/prepare",
    "session/prepare", "principal/source", "measurement/peer",
    "prepare-presentation/prepare", "read-session/prepare", "owner-selection/prepare",
    "owner-certificate/prepare", "review/admit", "request-digest/admit",
    "admit-read/admit", "authenticated-history/admit", "owner-service/admit",
    "recipient-intent/admit", "request-json/admit",
];

fn matching<'a>(actor: &'a FinancialActorContextV1) -> AdmissionPurposeChainV1<'a> {
    let start = Instant::now();
    AdmissionPurposeChainV1 {
        actors: (actor, actor),
        identities: IDENTITIES.map(|value| (value, value)),
        wall_ceilings: [(600_000, 600_000), (500_000, 500_000), (550_000, 550_000)],
        original_deadlines: [600, 590, 500, 550].map(|seconds| {
            let deadline = start + Duration::from_secs(seconds);
            (deadline, deadline)
        }),
    }
}

#[test]
fn handoff_admission_chain_rejects_each_source_ref_principal_session_digest_and_request_mismatch() {
    let actor = actor();
    require_admission_purpose_chain(&matching(&actor)).unwrap();
    for field in 0..IDENTITIES.len() {
        for change_left in [false, true] {
            let mut chain = matching(&actor);
            if change_left { chain.identities[field].0 = "foreign-identity"; }
            else { chain.identities[field].1 = "foreign-identity"; }
            assert!(matches!(require_admission_purpose_chain(&chain), Err(JournalError::Permission)),
                "accepted changed {}", IDENTITIES[field]);
        }
    }
}

#[test]
fn handoff_admission_chain_rejects_each_actor_role_and_session_mismatch() {
    let original = actor();
    require_admission_purpose_chain(&matching(&original)).unwrap();
    for field in 0..7 {
        let mut changed = original.clone();
        match field {
            0 => changed.profile.push_str("-other"),
            1 => changed.coordinator_process_instance = "fa".repeat(32),
            2 => changed.coordinator_focus_epoch += 1,
            3 => changed.signer_role = SignerContinueRoleV1::Signer2,
            4 => changed.signer_process_instance = "fb".repeat(32),
            5 => changed.common_image_measurement = "fc".repeat(32),
            _ => changed.session_challenge = "fd".repeat(32),
        }
        let mut chain = matching(&original);
        chain.actors.1 = &changed;
        assert!(matches!(require_admission_purpose_chain(&chain), Err(JournalError::Permission)),
            "accepted changed actor field {field}");
    }
}

#[test]
fn handoff_admission_chain_rejects_changed_source_material_and_service_wall_ceilings() {
    let actor = actor();
    require_admission_purpose_chain(&matching(&actor)).unwrap();
    for field in 0..3 {
        for later in [false, true] {
            let mut chain = matching(&actor);
            if later { chain.wall_ceilings[field].1 += 1; }
            else { chain.wall_ceilings[field].1 -= 1; }
            assert!(matches!(require_admission_purpose_chain(&chain), Err(JournalError::Permission)),
                "accepted changed wall ceiling {field}");
        }
    }
}

#[test]
fn handoff_admission_chain_rejects_changed_original_source_channel_material_service_deadlines() {
    let actor = actor();
    require_admission_purpose_chain(&matching(&actor)).unwrap();
    for field in 0..4 {
        for later in [false, true] {
            let mut chain = matching(&actor);
            let actual = &mut chain.original_deadlines[field].1;
            *actual = if later { *actual + Duration::from_nanos(1) }
                else { *actual - Duration::from_nanos(1) };
            assert!(matches!(require_admission_purpose_chain(&chain), Err(JournalError::Permission)),
                "accepted changed original deadline {field}");
        }
    }
}
