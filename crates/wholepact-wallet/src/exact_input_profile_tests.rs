//! Pure comparison negatives. These borrowed facts cannot issue a ChainContext,
//! native admission, FreshExactInputObservation, or other authority. No I/O.
use super::*;

fn source() -> BackendIdentity {
    BackendIdentity {
        source_id: "profile-fixture".into(),
        endpoint: "synthetic://profile-fixture".into(),
        trust_profile: "synthetic_never_chain_evidence",
    }
}
fn facts(source: &BackendIdentity) -> ObservationProfileFacts<'_> {
    ObservationProfileFacts {
        source,
        network: "test",
        branch_id: "0x77190ad9",
        lightwalletd_version: "synthetic-fixture-version",
        backend_subversion: "synthetic-fixture-backend",
        protocol_version: "synthetic-fixture-protocol",
        lifetime_seconds: Some(60),
    }
}

#[test]
fn every_pinned_profile_fact_change_is_rejected_on_either_side() {
    let original_source = source();
    let baseline = facts(&original_source);
    assert!(verify_profile_facts(baseline, baseline).is_ok());
    let mut changed_source_id = original_source.clone();
    changed_source_id.source_id.push_str("-changed");
    let mut changed_endpoint = original_source.clone();
    changed_endpoint.endpoint.push_str("/changed");
    let mut changed_trust = original_source.clone();
    changed_trust.trust_profile = "changed-trust-profile";
    let cases = [
        (
            "network",
            ObservationProfileFacts {
                network: "main",
                ..baseline
            },
        ),
        (
            "branch",
            ObservationProfileFacts {
                branch_id: "0xc8e71055",
                ..baseline
            },
        ),
        (
            "source id",
            ObservationProfileFacts {
                source: &changed_source_id,
                ..baseline
            },
        ),
        (
            "endpoint",
            ObservationProfileFacts {
                source: &changed_endpoint,
                ..baseline
            },
        ),
        (
            "trust profile",
            ObservationProfileFacts {
                source: &changed_trust,
                ..baseline
            },
        ),
        (
            "lightwalletd version",
            ObservationProfileFacts {
                lightwalletd_version: "changed",
                ..baseline
            },
        ),
        (
            "backend subversion",
            ObservationProfileFacts {
                backend_subversion: "changed",
                ..baseline
            },
        ),
        (
            "protocol version",
            ObservationProfileFacts {
                protocol_version: "changed",
                ..baseline
            },
        ),
    ];
    for (field, changed) in cases {
        assert!(
            matches!(
                verify_profile_facts(baseline, changed),
                Err(ExactObservationError::ProfileChanged)
            ),
            "changed current {field} must fail"
        );
        assert!(
            matches!(
                verify_profile_facts(changed, baseline),
                Err(ExactObservationError::ProfileChanged)
            ),
            "changed original {field} must fail"
        );
    }
    // Mutual equality does not admit a different network or branch.
    for unsupported in [
        ObservationProfileFacts {
            network: "main",
            ..baseline
        },
        ObservationProfileFacts {
            branch_id: "0xc8e71055",
            ..baseline
        },
    ] {
        assert!(matches!(
            verify_profile_facts(unsupported, unsupported),
            Err(ExactObservationError::ProfileChanged)
        ));
    }
}

#[test]
fn lease_overflow_or_underflow_is_rejected_but_conservative_shortening_is_allowed() {
    let source = source();
    let baseline = facts(&source);
    // None is checked_sub failure from original genuine context times.
    for lifetime_seconds in [None, Some(61), Some(u64::MAX)] {
        let invalid = ObservationProfileFacts {
            lifetime_seconds,
            ..baseline
        };
        assert!(matches!(
            verify_profile_facts(baseline, invalid),
            Err(ExactObservationError::ProfileChanged)
        ));
        assert!(matches!(
            verify_profile_facts(invalid, baseline),
            Err(ExactObservationError::ProfileChanged)
        ));
    }
    // Exact TTL equality is deliberately not a requirement: cache provenance
    // may shorten either observation. Actual expiry/runway checks remain separate.
    for lifetime_seconds in [Some(1), Some(59), Some(60)] {
        let shorter = ObservationProfileFacts {
            lifetime_seconds,
            ..baseline
        };
        assert!(verify_profile_facts(baseline, shorter).is_ok());
        assert!(verify_profile_facts(shorter, baseline).is_ok());
    }
}
