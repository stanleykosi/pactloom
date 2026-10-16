//! Actual encrypted SQLite capture/restore of synthetic historical claims.
//! The existing modeled layer kernel never manufactures a native admission.
use super::*;
use crate::manual_enrollment::{
    append_modeled_initial_layer_audits,
    construction_claim_v2::{
        CONSTRUCTION_CHECKPOINT_V2, CONSTRUCTION_CLAIM_V2, append_modeled_construction_rows,
    },
};
fn rows(store: &Store) -> Vec<(String, String, u64, String, i64, i64)> {
    store.connection.lock().unwrap().prepare("SELECT aggregate_type,id,revision,payload,created_at_ms,updated_at_ms FROM records WHERE aggregate_type LIKE 'generation_manual_%' ORDER BY aggregate_type,id").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap()
}
#[test]
fn encrypted_construction_pending_and_checkpoint_rows_survive_two_layers_without_reissue() {
    for with_checkpoint in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let one = root_encrypted(&dir.path().join("g1"));
        // Index 2 keeps the independently modeled roster root's identity
        // distinct from both construction contributors.
        let root = append_modeled_initial_layer_audits(&one.store, 2);
        let (claim, receipt) =
            append_modeled_construction_rows(&one.store, &root.0, with_checkpoint);
        let exact = rows(&one.store);
        assert_eq!(
            exact
                .iter()
                .filter(|r| r.0 == CONSTRUCTION_CLAIM_V2 || r.0 == CONSTRUCTION_CHECKPOINT_V2)
                .count(),
            if with_checkpoint { 2 } else { 1 }
        );
        let before = tree(&one.directory);
        let two = advance_encrypted(&one, &dir.path().join("g2"), 2);
        assert_eq!(rows(&two.store), exact);
        let two_before = tree(&two.directory);
        let three = advance_encrypted(&two, &dir.path().join("g3"), 3);
        assert_eq!(rows(&three.store), exact);
        for restored in [&two, &three] {
            let observed = restored
                .store
                .manual_roster_construction_evidence_v2(
                    &claim.principal_id,
                    &claim.construction_key,
                )
                .unwrap()
                .unwrap();
            assert!(observed.0 == claim);
            assert!(observed.1 == receipt);
            assert!(restored.store.recovery_state().unwrap().recovery_required);
            assert!(
                restored
                    .store
                    .recovery_record_is_historical(CONSTRUCTION_CLAIM_V2, &claim.digest().unwrap())
                    .unwrap()
            );
            assert!(
                restored
                    .store
                    .require_ordinary_financial_lineage(
                        &claim.proposal().manifest.agreement.agreement_id,
                        &claim.proposal().manifest.agreement.obligation_id,
                        &claim.principal_id,
                        Some(&claim.construction_key),
                        &[]
                    )
                    .is_err()
            );
            let ctx = CommandContext::for_request(
                &claim.principal_id,
                &claim.construction_key,
                &serde_json::json!({}),
            )
            .unwrap();
            assert!(restored.store.find_replay(&ctx).is_err());
            // No read API returns a token; only inert rows are comparable here.
            for audit in &claim.consumed {
                assert!(
                    restored
                        .store
                        .settlement_obligation_requires_recovery(
                            &audit.request.plan.enrollment().scope.obligation_id
                        )
                        .unwrap()
                );
            }
        }
        let guard = three.store.connection.lock().unwrap();
        let snapshot = three.snapshot();
        let c = snapshot.snapshot.connection();
        validate_generation(c, &three.source, &binding(3)).unwrap();
        let inventory = inventory(c, &three.source).unwrap();
        assert_eq!(inventory.construction_claims().len(), 1);
        assert_eq!(
            inventory.construction_checkpoints().len(),
            usize::from(with_checkpoint)
        );
        drop(snapshot);
        drop(guard);
        assert_eq!(tree(&one.directory), before);
        assert_eq!(tree(&two.directory), two_before);
        assert_eq!(
            three.store.settled_debit("synthetic-account").unwrap(),
            "111"
        );
        assert_eq!(
            three.store.outstanding_debit("synthetic-account").unwrap(),
            "222"
        );
    }
}
