use wholepact_core::AgreementDraft;
use wholepact_engine::{Access, Engine};
fn draft(id: &str) -> AgreementDraft {
    let mut d: AgreementDraft = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    d.agreement_id = id.into();
    d.obligation_id = format!("obligation-{id}");
    d
}
fn selected() -> Access {
    Access {
        principal_id: "owner".into(),
        agreement_ids: ["selected".into()].into(),
        all_agreements: false,
        include_owned_agreements: false,
    }
}
#[test]
fn ownership_never_expands_selected_reads_events_or_replay() {
    let e = Engine::in_memory().unwrap();
    let owned = Access {
        principal_id: "owner".into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    e.create(&owned, "create-selected-operation", draft("selected"))
        .unwrap();
    e.create(&owned, "create-hidden-operation", draft("hidden"))
        .unwrap();
    let s = selected();
    assert_eq!(e.list(&s).unwrap().len(), 1);
    assert!(e.get(&s, "hidden").is_err());
    assert!(
        e.create(&s, "create-hidden-operation", draft("hidden"))
            .is_err()
    );
    let replay = e
        .create(&s, "create-selected-operation", draft("selected"))
        .unwrap();
    assert!(replay.replayed);
    let events = e.events(&s, 0, 100).unwrap();
    let text = serde_json::to_string(&events).unwrap();
    assert!(text.contains("selected"));
    assert!(!text.contains("hidden"));
}
#[test]
fn selected_creation_is_explicit_and_denied_creation_has_no_effect() {
    let e = Engine::in_memory().unwrap();
    let s = selected();
    let denied = e
        .create(&s, "deny-outside-operation", draft("future-owned"))
        .unwrap_err();
    assert_eq!(denied.code, "PERMISSION_DENIED");
    let all = Access {
        all_agreements: true,
        ..Access::default()
    };
    assert!(e.list(&all).unwrap().is_empty());
    assert!(
        e.events(&all, 0, 100)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty()
    );
    e.create(&s, "create-explicit-operation", draft("selected"))
        .unwrap();
    assert!(s.permits_agreement("selected", "other-owner"));
    assert!(!s.permits_agreement("future-owned", "owner"));
}
#[test]
fn default_access_denies_even_matching_owner_and_explicit_owned_is_preserved() {
    let mut a = Access {
        principal_id: "owner".into(),
        ..Access::default()
    };
    assert!(!a.permits_agreement("future", "owner"));
    a.include_owned_agreements = true;
    assert!(a.permits_agreement("future", "owner"));
    assert!(!a.permits_agreement("foreign", "other"));
    a.all_agreements = true;
    assert!(a.permits_agreement("foreign", "other"));
}
