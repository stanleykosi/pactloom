//! Pure pairing-plan checks only. No provider, client, peer, native owner,
//! source, socket, credential or signing/proof helper is constructed.
use super::*;

fn scope() -> PairScope {
    PairScope {
        account_id: "synthetic-quarantined-account".into(),
        agreement_id: "host-recovery".into(),
        participant_id: "host-recovery".into(),
        manifest_digest: "ab".repeat(32),
        history_read: true,
        authorization_export: true,
        preconstruction_export: false,
    }
}

#[test]
fn quarantined_pairing_defers_status_only_for_explicit_restricted_mode() {
    assert_eq!(PairingMode::default(), PairingMode::Ordinary);
    assert_eq!(
        PairingMode::Ordinary.possession_probe(),
        Some(serde_json::json!({"operation": "status"}))
    );
    assert!(
        PairingMode::QuarantinedInformational
            .possession_probe()
            .is_none()
    );
    // Inspecting the restricted plan cannot mutate the ordinary handshake or
    // silently make a later ordinary pairing use deferred authentication.
    assert_eq!(
        PairingMode::default().possession_probe(),
        Some(serde_json::json!({"operation": "status"}))
    );
}

#[test]
fn quarantined_pairing_requires_exact_historical_flags_before_connection() {
    let original = scope();
    for history_read in [false, true] {
        for authorization_export in [false, true] {
            for preconstruction_export in [false, true] {
                let mut requested = original.clone();
                requested.history_read = history_read;
                requested.authorization_export = authorization_export;
                requested.preconstruction_export = preconstruction_export;
                assert_eq!(
                    PairingMode::QuarantinedInformational
                        .validate_scope(&requested)
                        .is_ok(),
                    history_read && authorization_export && !preconstruction_export
                );
            }
        }
    }
    assert!(original == scope());
}

#[test]
fn quarantined_pairing_checks_canonical_account_and_inventory_before_connection() {
    let valid = scope();
    assert!(
        PairingMode::QuarantinedInformational
            .validate_scope(&valid)
            .is_ok()
    );
    for value in ["".to_string(), "invalid account".into(), "x".repeat(129)] {
        let mut bad = valid.clone();
        bad.account_id = value;
        assert!(
            PairingMode::QuarantinedInformational
                .validate_scope(&bad)
                .is_err()
        );
    }
    for value in [
        "".to_string(),
        "ab".repeat(31),
        "AB".repeat(32),
        "gg".repeat(32),
    ] {
        let mut bad = valid.clone();
        bad.manifest_digest = value;
        assert!(
            PairingMode::QuarantinedInformational
                .validate_scope(&bad)
                .is_err()
        );
    }
    for bad in [
        PairScope {
            agreement_id: "".into(),
            ..valid.clone()
        },
        PairScope {
            participant_id: "invalid participant".into(),
            ..valid.clone()
        },
    ] {
        assert!(
            PairingMode::QuarantinedInformational
                .validate_scope(&bad)
                .is_err()
        );
    }
    assert!(valid == scope());
}

#[test]
fn quarantined_provider_release_requires_exact_restricted_mode_and_no_leases() {
    // Predicate inputs only. No installed provider, ClientGrant/token, native
    // authority, client, socket or process fixture is manufactured.
    for mode in [PairingMode::Ordinary, PairingMode::QuarantinedInformational] {
        for leases in [0, 1, 8, usize::MAX] {
            assert_eq!(
                mode.require_provider_release(leases).is_ok(),
                mode == PairingMode::QuarantinedInformational && leases == 0,
            );
        }
    }
    assert!(PairingMode::default().require_provider_release(0).is_err());
}

#[test]
fn quarantined_provider_release_does_not_mutate_pairing_mode_or_probe() {
    // Teardown eligibility cannot convert ordinary pairing or waive the fresh
    // restricted scope checks that must precede a subsequent connection.
    let mode = PairingMode::QuarantinedInformational;
    assert!(mode.require_provider_release(0).is_ok());
    assert!(mode.possession_probe().is_none());
    let mut invalid = scope();
    invalid.preconstruction_export = true;
    assert!(mode.validate_scope(&invalid).is_err());
    assert!(PairingMode::Ordinary.require_provider_release(0).is_err());
    assert_eq!(
        PairingMode::Ordinary.possession_probe(),
        Some(serde_json::json!({"operation": "status"})),
    );
}
