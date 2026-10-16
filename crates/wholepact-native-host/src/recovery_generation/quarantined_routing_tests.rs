//! Pure route checks and existing inert historical DTO validation only. No
//! activation wrapper, native terminal, source, provider, socket or key is opened.
use super::*;

#[test]
fn quarantined_availability_is_explicit_and_never_changes_default_source() {
    let ordinary = V5SignerSource::default();
    assert_eq!(ordinary, V5SignerSource::Ordinary);
    assert!(matches!(
        ordinary.require_available(),
        Err(Error::CompleteOriginRecoveryUnavailable)
    ));
    assert!(
        V5SignerSource::QuarantinedInformational
            .require_available()
            .is_ok()
    );
    assert!(matches!(
        require_available(),
        Err(Error::CompleteOriginRecoveryUnavailable)
    ));
    assert_eq!(ordinary, V5SignerSource::Ordinary);
}

// This inspected fixture only decodes the existing never-funded transcript and
// constructs inert local audit phases. No native/session issuer or proof helper.
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
use super::super::publication::retained_continuity_fixture as modeled_history;

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[test]
fn quarantined_source_selection_never_converts_complete_history_to_financial_authority() {
    let evidence = modeled_history::fixture();
    evidence.validate().unwrap();
    let original = serde_json::to_vec(&evidence).unwrap();
    let debit = evidence
        .complete_history
        .conservative_debit_zatoshis()
        .unwrap();
    let obligations = evidence
        .complete_history
        .conservative_obligations()
        .unwrap();
    assert!(debit > 0);
    assert!(!obligations.is_empty());
    assert!(
        !evidence
            .complete_history
            .construction
            .transport
            .credentials
            .is_empty()
    );
    assert!(
        evidence
            .complete_history
            .construction
            .observed_snapshot()
            .transport_fences
            .is_some()
    );
    for source in [
        V5SignerSource::Ordinary,
        V5SignerSource::QuarantinedInformational,
    ] {
        let _availability_only = source.require_available();
        assert!(
            evidence
                .complete_history
                .require_financial_activation_supported()
                .is_err()
        );
        assert_eq!(
            evidence
                .complete_history
                .conservative_debit_zatoshis()
                .unwrap(),
            debit
        );
        assert_eq!(
            evidence
                .complete_history
                .conservative_obligations()
                .unwrap(),
            obligations
        );
        assert_eq!(serde_json::to_vec(&evidence).unwrap(), original);
    }
}

#[test]
fn quarantined_pairing_route_selects_only_dedicated_client_without_contact() {
    // Compare the actual production route selector's function pointers without
    // constructing a provider or invoking either socket-bearing function.
    assert!(std::ptr::fn_addr_eq(
        V5SignerSource::Ordinary.pairing_client(),
        OriginalHistoryClient::pair as PairClient,
    ));
    assert!(std::ptr::fn_addr_eq(
        V5SignerSource::QuarantinedInformational.pairing_client(),
        OriginalHistoryClient::pair_quarantined_informational as PairClient,
    ));
    assert!(std::ptr::fn_addr_eq(
        V5SignerSource::default().pairing_client(),
        OriginalHistoryClient::pair as PairClient,
    ));
    assert!(matches!(
        V5SignerSource::Ordinary.require_available(),
        Err(Error::CompleteOriginRecoveryUnavailable)
    ));
}
