//! Inert routing regressions only. No listener, pairing, source or disclosure
//! approval is constructed by these tests.
use super::*;

fn exact_scope() -> PairScope {
    PairScope {
        account_id: "synthetic-born-account".into(),
        agreement_id: "synthetic-agreement".into(),
        participant_id: "synthetic-participant".into(),
        manifest_digest: "42".repeat(32),
        history_read: false,
        authorization_export: false,
        preconstruction_export: false,
    }
}

#[test]
fn born_named_verifier_mode_rejects_every_scope_widening() {
    let exact = exact_scope();
    exact.validate().unwrap();
    let mode = IpcMode::BornNamedVerifierV1 {
        exact: exact.clone(),
    };
    assert!(mode.permits_scope(&exact));
    assert!(
        mode.validate_authenticated_request(&AppRequest::Status {}, &exact)
            .is_ok()
    );
    for field in 0..7 {
        let mut other = exact.clone();
        match field {
            0 => other.account_id.push_str("-other"),
            1 => other.agreement_id.push_str("-other"),
            2 => other.participant_id.push_str("-other"),
            3 => other.manifest_digest = "43".repeat(32),
            4 => other.history_read = true,
            5 => other.authorization_export = true,
            6 => other.preconstruction_export = true,
            _ => unreachable!(),
        }
        other.validate().unwrap();
        assert!(!mode.permits_scope(&other));
        assert!(
            mode.validate_authenticated_request(&AppRequest::Status {}, &other)
                .is_err()
        );
    }
}

#[test]
fn born_named_verifier_mode_cannot_route_review_history_or_dispatch() {
    let exact = exact_scope();
    let mode = IpcMode::BornNamedVerifierV1 {
        exact: exact.clone(),
    };
    let dispatch = crate::authority_bridge::born_dispatch_ipc::born_synthetic_request();
    let history = dispatch.history();
    let requests = [
        AppRequest::RequestReview {
            request_id: "synthetic-request".into(),
            accepted_manifest_digest: exact.manifest_digest.clone(),
            pczt_hex: String::new(),
        },
        AppRequest::RequestBornOriginalHistoryV1 {
            request: Box::new(history),
        },
        AppRequest::RequestBornDispatchV1 {
            request: Box::new(dispatch),
        },
    ];
    for request in requests {
        assert!(!mode.permits_request(&request));
        assert!(
            mode.validate_authenticated_request(&request, &exact)
                .is_err()
        );
    }
}
