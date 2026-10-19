//! Component checks only, NOT evidence of genuine native source qualification.
use super::*;

#[test]
fn second_principal_cannot_use_agreement_scope_as_private_audience() {
    let owner = Access {
        principal_id: "owner".into(),
        agreement_ids: ["agreement".into()].into(),
        ..Access::default()
    };
    require_principal(&owner, "owner", "agreement").unwrap();
    let other = Access {
        principal_id: "other".into(),
        agreement_ids: ["agreement".into()].into(),
        all_agreements: true,
        include_owned_agreements: true,
    };
    assert!(require_principal(&other, "owner", "agreement").is_err());
    assert!(
        require_principal(
            &Access {
                principal_id: "owner".into(),
                ..Access::default()
            },
            "owner",
            "agreement"
        )
        .is_err()
    );
}
struct Denied;
impl LocalPrivateWorkspaceConsentV1 for Denied {
    fn permits_workspace(&self, _: &PrivateWorkspaceScopeV1, _: PrivateWorkspaceActionV1) -> bool {
        false
    }
}
fn private_scope() -> PrivateWorkspaceScopeV1 {
    PrivateWorkspaceScopeV1 {
        source_digest: "a".repeat(64),
        principal_id: "owner".into(),
        agreement_id: "agreement".into(),
        obligation_id: "obligation".into(),
        reviewer_account_ids: vec!["account-a".into(), "account-b".into()],
        protected_destination: "/original/private-coordination.sqlite".into(),
        retention_policy: "retain exact original".into(),
    }
}
#[test]
fn constructors_and_every_product_action_need_current_permission() {
    for action in [
        PrivateWorkspaceActionV1::Create,
        PrivateWorkspaceActionV1::Reopen,
        PrivateWorkspaceActionV1::ReadStatus,
        PrivateWorkspaceActionV1::RetainDiscovery,
        PrivateWorkspaceActionV1::RetainProjection,
        PrivateWorkspaceActionV1::FreezeCandidate,
        PrivateWorkspaceActionV1::PrepareExactCandidate,
        PrivateWorkspaceActionV1::RetainExactMaterial,
        PrivateWorkspaceActionV1::ObserveExactMaterial,
        PrivateWorkspaceActionV1::CheckpointExactOriginal,
        PrivateWorkspaceActionV1::ProveOriginalOnce,
        PrivateWorkspaceActionV1::FreezeVerifiedFixed,
        PrivateWorkspaceActionV1::ReadVerifiedFixed,
    ] {
        assert!(require_current_privacy(&private_scope(), &Denied, action).is_err());
    }
    // Structural ordering supplements the predicate test, but is not claimed
    // as an actual committed-source/foreground integration fixture.
    let source = include_str!("durable_private_workspace_v1.rs");
    let create = source
        .split("pub fn prepare_empty_new(")
        .nth(1)
        .unwrap()
        .split("pub fn open_uninitialized_original(")
        .next()
        .unwrap();
    assert!(
        create.find("check_source_permission(").unwrap()
            < create.find("Store::create_encrypted(").unwrap()
    );
}
#[test]
fn original_and_replayed_mutations_never_export_embedded_agreement_or_operation() {
    let engine = Engine::in_memory().unwrap();
    let access = Access {
        principal_id: "owner".into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    let mut draft: AgreementDraft = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    draft.agreement_id = "private-workspace-sanitize-test".into();
    draft.obligation_id = "private-workspace-obligation".into();
    let original = engine
        .create(&access, "private-workspace-sanitize-command", draft.clone())
        .unwrap();
    let replay = engine
        .create(&access, "private-workspace-sanitize-command", draft)
        .unwrap();
    let operation = replay.operation_id.clone();
    assert!(
        serde_json::to_value(&replay)
            .unwrap()
            .get("agreement")
            .is_some()
    );
    for mutation in [original, replay] {
        // Shape-only projection check. Stage A does not execute a private
        // command or turn this generic result into a private operation owner.
        let (revision, replayed) = (mutation.agreement.revision, mutation.replayed);
        let status = PrivateWorkspaceStatusV1 {
            revision,
            replayed,
            rounds: vec![],
            authorization_allowed: false,
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(
            json.as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            ["authorization_allowed", "replayed", "revision", "rounds"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        assert!(!json.to_string().contains(&operation));
        assert!(!json.to_string().contains("private-workspace-obligation"));
        assert!(!json.to_string().contains("recipient"));
    }
}
#[test]
fn facade_has_no_generic_read_or_owner_escape_contract() {
    let source = include_str!("durable_private_workspace_v1.rs");
    let implementation = source
        .split("impl<'source> PrivateDurableCoordinatorV1<'source>")
        .nth(1)
        .unwrap();
    for forbidden in [
        "pub fn get(",
        "pub fn list(",
        "pub fn events(",
        "pub fn operation(",
        "pub fn into_inner(",
        "pub fn engine(",
        "pub fn store(",
        "pub fn raw(",
        "-> Result<Mutation>",
        "-> &Engine",
        "-> &Store",
    ] {
        assert!(
            !implementation.contains(forbidden),
            "unexpected generic escape: {forbidden}"
        );
    }
    assert!(source.contains("\"terms_editing_origin\": false"));
    assert!(!implementation.contains("source.engine.clone()"));
}

#[test]
fn nominal_read_owner_has_no_latent_generic_mutation_or_replay_method() {
    let source = include_str!("durable_private_workspace_v1/operation_v1.rs");
    let read = source
        .split("impl<'op, 'source> PrivateWorkspaceOperationV1")
        .nth(1)
        .unwrap()
        .split("fn decode(")
        .next()
        .unwrap();
    for forbidden in [
        "fn replay(",
        "fn commit(",
        ".update_agreement(",
        ".create_agreement(",
        ".find_replay(",
    ] {
        assert!(!read.contains(forbidden));
    }
    assert!(read.contains("pub(super) fn load("));
}
