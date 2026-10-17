// Canonical production source is also compiled inside the private witness owner.
include!("types_core.rs");

#[cfg(test)]
mod offline_kind_tests {
    use super::*;

    // Pure wire/guard contracts. No keys, crypto, storage, sockets or issuance.
    #[test]
    fn exact_offline_kinds_are_immutable_and_qualified_export_only() {
        for (kind, wire) in [
            (
                ArtifactKind::OfflineReservationIntent,
                "offline_reservation_intent",
            ),
            (
                ArtifactKind::OfflineAuthorityAdmission,
                "offline_authority_admission",
            ),
            (
                ArtifactKind::OfflineAdmissionControl,
                "offline_admission_control",
            ),
            (
                ArtifactKind::OfflineMinimalAuthorityAdmission,
                "offline_minimal_authority_admission",
            ),
            (
                ArtifactKind::BornOfflineMinimalAdmissionV1,
                "born_offline_minimal_admission_v1",
            ),
            (
                ArtifactKind::BornOfflineAuthorizationReturnV1,
                "born_offline_authorization_return_v1",
            ),
            (
                ArtifactKind::OfflineAuthorizationReturn,
                "offline_authorization_return",
            ),
        ] {
            assert!(kind.immutable_slot());
            assert!(kind.requires_qualified_export());
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::Value::String(wire.into())
            );
        }
        assert!(ArtifactKind::Authorization.requires_qualified_export());
        assert!(!ArtifactKind::Contribution.requires_qualified_export());
    }

    #[test]
    fn existing_artifact_wire_names_remain_identical() {
        for (kind, wire) in [
            (ArtifactKind::Invitation, "invitation"),
            (ArtifactKind::Proposal, "proposal"),
            (ArtifactKind::Contribution, "contribution"),
            (ArtifactKind::Authorization, "authorization"),
            (ArtifactKind::ProvedProposal, "proved_proposal"),
            (ArtifactKind::FinalTransaction, "final_transaction"),
            (ArtifactKind::SettlementEvidence, "settlement_evidence"),
            (
                ArtifactKind::DeliveryAcknowledgment,
                "delivery_acknowledgment",
            ),
            (ArtifactKind::ParticipationIntent, "participation_intent"),
            (ArtifactKind::IntentWithdrawal, "intent_withdrawal"),
        ] {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::Value::String(wire.into())
            );
        }
        assert!(
            serde_json::from_str::<ArtifactKind>("\"offline_authority_admission_v2\"").is_err()
        );
    }
}
