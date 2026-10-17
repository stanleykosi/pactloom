//! Inert routing regression, not a born owner, authenticated history or permit.
use super::*;
#[test]
fn empty_native_draft_routes_only_for_preallocation_and_full_context_stays_strict() {
    let (admission, _, _) = crate::consent_journal::offline_history::tests::full_admission();
    let mut request = admission.request;
    request.intent.native_reservation_review_digest.clear();
    assert!(request.validate().is_err());
    let draft = draft_intent_context(&request.intent.terms, true).unwrap();
    assert_eq!(draft.artifact_kind, wire::ArtifactKind::BornOfflineIntentV1);
    assert_eq!(
        draft.sender_id,
        format!(
            "born-offline-intent:{}",
            request.intent.terms.offline_signer_key_digest
        )
    );
    assert!(require_same_intent_context(&draft, &draft).is_ok());
    let mut mismatch = draft.clone();
    mismatch.proposal_revision += 1;
    assert!(matches!(
        require_same_intent_context(&draft, &mismatch),
        Err(TransportError::WrongContext)
    ));
    mismatch = draft.clone();
    mismatch.artifact_kind = wire::ArtifactKind::OfflineReservationIntent;
    assert!(require_same_intent_context(&draft, &mismatch).is_err());
    request.intent.terms.offline_policy_digest.clear();
    assert!(draft_intent_context(&request.intent.terms, true).is_err());
}
