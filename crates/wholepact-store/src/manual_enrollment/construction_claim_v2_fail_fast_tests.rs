//! Private synthetic persistence tests only. Test-local claim structs are NOT
//! native admissions; these tests cannot qualify the end-to-end builder route.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn fixture() -> (
    Store,
    ManualRosterConstructionClaimV2,
    ManualRosterConstructionCheckpointV2,
) {
    let store = crate::manual_enrollment::tests::modeled_store();
    let mut root = crate::manual_enrollment::tests::initial_publication::initial_fixture();
    let target = store.manual_store_target().unwrap();
    let terms = &mut root.evidence.request.enrollment.terms;
    terms.identity.account_id = "3".repeat(64);
    terms.identity.full_viewing_key_digest = "4".repeat(64);
    terms.host.generation_id = target.generation_id().into();
    terms.host.inventory_digest = target.inventory_digest().into();
    terms.host.store_destination_identity = target.store_destination_identity().into();
    root.aliases = BTreeSet::from(["3".repeat(64)]);
    root.evidence.admission.exact_request_digest = root.evidence.request.digest().unwrap();
    root.validate().unwrap();
    drop(target);
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
            params![
                INITIAL_PUBLICATION_V2,
                root.digest().unwrap(),
                serde_json::to_string(&root).unwrap()
            ],
        )
        .unwrap();
    let (claim, receipt) =
        crate::manual_enrollment::construction_claim_v2::append_modeled_construction_rows(
            &store, &root, true,
        );
    (store, claim, receipt.unwrap())
}

fn timeout(store: &Store) -> u32 {
    store
        .connection
        .lock()
        .unwrap()
        .pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .unwrap()
}

#[test]
fn checkpoint_adapters_preserve_exact_duplicate_and_validation_refusal() {
    let (store, claim, receipt) = fixture();
    for fast in [false, true] {
        let token = ManualRosterConstructionClaimTokenV2 {
            store: &store,
            claim: claim.clone(),
        };
        let result = if fast {
            token.record_checkpoint_fail_fast(receipt.clone())
        } else {
            token.record_checkpoint(receipt.clone())
        };
        assert!(matches!(result, Err(StoreError::RecoveryRequired)));
        assert_eq!(timeout(&store), 5000);
        let mut changed = receipt.clone();
        changed.scope.coordination_request_digest = "0".repeat(64);
        let token = ManualRosterConstructionClaimTokenV2 {
            store: &store,
            claim: claim.clone(),
        };
        let result = if fast {
            token.record_checkpoint_fail_fast(changed)
        } else {
            token.record_checkpoint(changed)
        };
        assert!(result.is_err());
        assert_eq!(timeout(&store), 5000);
    }
    let retained = store
        .manual_roster_construction_evidence_v2(&claim.principal_id, &claim.construction_key)
        .unwrap()
        .unwrap();
    assert!(retained.0 == claim);
    assert!(retained.1 == Some(receipt));
}

#[test]
fn checkpoint_mutex_contention_consumes_test_token_without_receipt_change() {
    let (store, claim, receipt) = fixture();
    let held = store.connection.lock().unwrap();
    let token = ManualRosterConstructionClaimTokenV2 {
        store: &store,
        claim,
    };
    assert!(matches!(
        token.record_checkpoint_fail_fast(receipt),
        Err(StoreError::ResourceExhausted)
    ));
    drop(held);
    assert_eq!(timeout(&store), 5000);
}

#[test]
fn checkpoint_poison_cannot_be_recovered_as_new_permission() {
    let (store, claim, receipt) = fixture();
    let caught = catch_unwind(AssertUnwindSafe(|| {
        let _held = store.connection.lock().unwrap();
        panic!("synthetic checkpoint poison")
    }));
    assert!(caught.is_err());
    let token = ManualRosterConstructionClaimTokenV2 {
        store: &store,
        claim,
    };
    assert!(matches!(
        token.record_checkpoint_fail_fast(receipt),
        Err(StoreError::Poisoned)
    ));
}

#[test]
fn fail_fast_claim_keeps_real_native_owner_requirement() {
    let (store, claim, _) = fixture();
    let target = store.manual_store_target_fail_fast().unwrap();
    let expected = target
        .current_agreement_record_fail_fast(&claim.proposal().manifest.agreement.agreement_id)
        .unwrap();
    let old = store
        .claim_manual_roster_construction_v2(
            &target,
            &expected,
            &claim.principal_id,
            &claim.construction_key,
            claim.maximum_actions,
            &[],
        )
        .err()
        .unwrap();
    let fast = store
        .claim_manual_roster_construction_v2_fail_fast(
            &target,
            &expected,
            &claim.principal_id,
            &claim.construction_key,
            claim.maximum_actions,
            &[],
        )
        .err()
        .unwrap();
    assert_eq!(std::mem::discriminant(&old), std::mem::discriminant(&fast));
    assert_eq!(timeout(&store), 5000);
}
