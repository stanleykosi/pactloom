//! Modeled test data only. No live signer/native/witness lease is constructed.
use super::*;

pub(crate) fn append_modeled_layer_audits(
    store: &Store,
    index: u8,
) -> (
    ManualEnrollmentAudit,
    ManualActionAudit,
    ManualExclusionAudit,
) {
    assert!((1..=2).contains(&index));
    assert_eq!(store.protection, StorageProtection::Encrypted);
    let binding = store.recovered_binding.as_ref().unwrap();
    let mut a = enrollment();
    a.terms.identity = if index == 1 {
        ident('1', '2')
    } else {
        ident('3', '4')
    };
    a.aliases = aliases(&a.terms.identity);
    a.aliases.insert(format!("synthetic-manual-alias-{index}"));
    a.terms.operation_id = format!("synthetic-enrollment-{index}");
    a.terms.scope.agreement_id = format!("synthetic-manual-agreement-{index}");
    a.terms.scope.obligation_id = format!("synthetic-manual-obligation-{index}");
    a.terms.host.generation_id = binding.generation_id().into();
    a.terms.host.inventory_digest = binding.inventory_digest().into();
    a.terms.host.store_destination_identity = store
        .manual_store_target()
        .unwrap()
        .store_destination_identity()
        .into();
    let hash =
        |kind: &str| request_digest(&serde_json::json!(["synthetic-layer", kind, index])).unwrap();
    a.enrollment_ref = hash("enrollment-reference");
    a.witness_extension_digest = hash("extension");
    a.request_identity_digest = hash("request-identity");
    a.terms.account_use_genesis_digest = hash("genesis");
    rebind(&mut a);
    let context = CommandContext::for_request(
        "owner",
        format!("synthetic-create-{index}"),
        &serde_json::json!(["synthetic-manual-create", index]),
    )
    .unwrap();
    store
        .create_agreement(
            &context,
            &a.terms.scope.agreement_id,
            serde_json::json!({"view":{"agreement":{
                "agreement_id":a.terms.scope.agreement_id,
                "obligation_id":a.terms.scope.obligation_id,
            }}}),
        )
        .unwrap();

    // The older synthetic-account fixture predates identity rows. Its identity
    // is explicitly modeled here, never accepted by the production appender.
    let old_identity = ident('8', '9');
    let mut old_aliases = aliases(&old_identity);
    old_aliases.insert("synthetic-account".into());
    let mut inherited = vec![(old_identity, old_aliases)];
    {
        let c = store.connection.lock().unwrap();
        inherited.extend(
            read_audits::<ManualEnrollmentAudit>(&c, ENROLLMENT)
                .unwrap()
                .into_iter()
                .map(|(_, old)| (old.terms.identity, old.aliases)),
        );
    }
    assert!(append(store, &a, &inherited).unwrap());
    let mut action = action(&a);
    action.intent.operation_id = format!("synthetic-action-{index}");
    action.intent.idempotency_key_digest = hash("action-idempotency");
    action.admission.exact_request_digest = action_request_digest(
        &a.terms,
        &a.enrollment_ref,
        &a.witness_extension_digest,
        &action.intent,
    )
    .unwrap();
    assert!(add_action(store, &action).unwrap());
    let mut continuation = super::continuation::fixture(&a);
    continuation.operation_id = format!("synthetic-continuation-{index}");
    continuation.request_identity_digest = hash("continuation-idempotency");
    continuation.evidence.request.continuation_digest = hash("continuation-attempt");
    continuation.evidence.admission.attempt_digest =
        continuation.evidence.request.continuation_digest.clone();
    continuation.evidence.admission.exact_request_digest =
        continuation.evidence.request.digest().unwrap();
    assert!(super::continuation::add(store, &continuation).unwrap());
    let exclusion = ManualExclusionAudit {
        version: 1,
        operation_id: format!("synthetic-exclusion-{index}"),
        identity: a.terms.identity.clone(),
        aliases: a.aliases.clone(),
        account_use_genesis_digest: a.terms.account_use_genesis_digest.clone(),
        exclusion_digest: hash("exclusion"),
        witness_history_digest: hash("exclusion-history"),
    };
    let mut c = store.connection.lock().unwrap();
    let tx = c
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(append_exclusion(&tx, &exclusion).unwrap());
    tx.commit().unwrap();
    (a, action, exclusion)
}
