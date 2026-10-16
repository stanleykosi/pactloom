//! Synthetic source-only negative/data-fold tests. These never create/open the fixed
//! user namespace, generate actual keys, mint a native lease or call publication.
use super::*;
use crate::account_use::{AccountUseGenesis, ExclusionReason};
use crate::{AccountPolicy, WitnessDisclosureDescriptor};
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn request() -> PendingBirthRequest {
    let mut policy = AccountPolicy {
        account_use_genesis: None,
        witness_id: "synthetic-witness".into(),
        account_id: h('1'),
        network_profile_id: "synthetic-network".into(),
        owner_certificate_digest: h('2'),
        initial_writer_certificate_digest: h('3'),
        initial_writer_epoch: 1,
        enrollment_refs: vec![h('c')],
        agreement_ids: vec!["manual-only".into()],
        recipient_scope_digests: vec![h('4')],
        aggregate_budget_zatoshis: 100,
        per_operation_limit_zatoshis: 100,
        maximum_fee_share_zatoshis: 5,
        maximum_transaction_fee_zatoshis: 5,
        maximum_permit_lifetime_ms: 1000,
        policy_expires_at_ms: 100_000,
    };
    let original_terms_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:account-birth-original-policy-terms:v1",
        &policy,
    )
    .unwrap();
    let mut disclosure = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:1911".into(),
        server_name: "localhost".into(),
        witness_id: policy.witness_id.clone(),
        account_id: policy.account_id.clone(),
        network_profile_id: policy.network_profile_id.clone(),
        policy_digest: h('0'),
        pinned_server_certificate_digest: h('5'),
    };
    policy.account_use_genesis = Some(AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: policy.account_id.clone(),
            full_viewing_key_digest: h('6'),
            network_profile_id: policy.network_profile_id.clone(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        witness_id: policy.witness_id.clone(),
        witness_origin_digest: account_use_witness_origin_digest(&disclosure).unwrap(),
        owner_certificate_digest: policy.owner_certificate_digest.clone(),
        native_birth_digest: h('7'),
    });
    disclosure.policy_digest = policy.policy_digest().unwrap();
    PendingBirthRequest {
        version: 1,
        operation_id: "synthetic-birth".into(),
        generation_instance_id: h('8'),
        native_birth_digest: h('7'),
        original_terms_digest,
        original_target_digest: h('9'),
        disclosure,
        policy,
        issued_at_ms: 1000,
        initial_commit_deadline_ms: 2000,
    }
}
fn namespace(r: &PendingBirthRequest) -> WitnessNamespaceBinding {
    WitnessNamespaceBinding {
        version: 1,
        namespace_instance_id: h('a'),
        initial_inventory_digest: h('b'),
        witness_id: r.policy.witness_id.clone(),
        witness_origin_digest: account_use_witness_origin_digest(&r.disclosure).unwrap(),
        pinned_server_certificate_digest: r.disclosure.pinned_server_certificate_digest.clone(),
        owner_certificate_digest: r.policy.owner_certificate_digest.clone(),
        network_profile_id: r.policy.network_profile_id.clone(),
        canonical_private_root: "/synthetic/never-opened/witness".into(),
        root_identity: DirectoryIdentity {
            platform: "linux-unix-v1".into(),
            device: 1,
            inode: 2,
            owner_uid: 1000,
        },
        journals_identity: DirectoryIdentity {
            platform: "linux-unix-v1".into(),
            device: 1,
            inode: 3,
            owner_uid: 1000,
        },
    }
}
fn intent(n: &WitnessNamespaceBinding, r: PendingBirthRequest) -> CreationIntent {
    CreationIntent {
        version: 1,
        namespace_digest: n.digest().unwrap(),
        request_digest: r.digest().unwrap(),
        derived_child: derived_child(&r.policy.account_id).unwrap(),
        local_target_digest: target_digest(n, &r.policy.account_id).unwrap(),
        request: r,
        local_owner_review_digest: h('d'),
        owner_approval_evidence_digest: h('e'),
    }
}
fn fixture() -> (WitnessNamespaceBinding, CreationIntent) {
    let r = request();
    let n = namespace(&r);
    let i = intent(&n, r);
    (n, i)
}
fn rebind(
    mut r: PendingBirthRequest,
    account: char,
    fvk: char,
    operation: &str,
    generation: char,
) -> PendingBirthRequest {
    r.policy.account_id = h(account);
    r.disclosure.account_id = h(account);
    let g = r.policy.account_use_genesis.as_mut().unwrap();
    g.identity.account_id = h(account);
    g.identity.full_viewing_key_digest = h(fvk);
    r.operation_id = operation.into();
    r.generation_instance_id = h(generation);
    let mut original = r.policy.clone();
    original.account_use_genesis = None;
    r.original_terms_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:account-birth-original-policy-terms:v1",
        &original,
    )
    .unwrap();
    r.disclosure.policy_digest = r.policy.policy_digest().unwrap();
    r.validate().unwrap();
    r
}
fn history() -> LocatorHistory {
    let (namespace, intent) = fixture();
    LocatorHistory::from_records(
        namespace,
        vec![PreparedIntent {
            intent,
            prepared_at_ms: 1100,
        }],
        vec![],
        vec![],
    )
    .unwrap()
}
fn descriptor(history: &LocatorHistory) -> Descriptor {
    Descriptor {
        version: 1,
        namespace: history.namespace.clone(),
        captured_at_ms: 2100,
        locator_history_digest: history_digest(history).unwrap(),
        accounts: history
            .prepared
            .keys()
            .map(|id| (id.clone(), AccountState::Absent))
            .collect(),
    }
}
fn object() -> capsule::ObjectRef {
    capsule::ObjectRef {
        digest: h('0'),
        length: 64,
    }
}
fn node(descriptor: &Descriptor) -> capsule::Node {
    let root = Path::new(&descriptor.namespace.canonical_private_root);
    capsule::Node {
        generation_id: descriptor.namespace.namespace_instance_id.clone(),
        profile_id: descriptor.namespace.witness_id.clone(),
        original_root: root.display().to_string(),
        entries: BTreeMap::from([
            (
                DESCRIPTOR.into(),
                capsule::Entry {
                    role: DESCRIPTOR_ROLE.into(),
                    origin: None,
                    payload: capsule::EntryPayload::Secret { object: object() },
                },
            ),
            (
                MASTER.into(),
                capsule::Entry {
                    role: MASTER_ROLE.into(),
                    origin: None,
                    payload: capsule::EntryPayload::Secret { object: object() },
                },
            ),
            (
                MARKER.into(),
                capsule::Entry {
                    role: MARKER_ROLE.into(),
                    origin: Some(root.join("installation.id").display().to_string()),
                    payload: capsule::EntryPayload::File { object: object() },
                },
            ),
            (
                LOCATOR.into(),
                capsule::Entry {
                    role: LOCATOR_ROLE.into(),
                    origin: Some(root.join("registry.wp").display().to_string()),
                    payload: capsule::EntryPayload::Journal {
                        files: BTreeMap::from([("".into(), object())]),
                    },
                },
            ),
        ]),
    }
}
fn birth(intent: &CreationIntent) -> PendingBirthCommitRecord {
    PendingBirthCommitRecord {
        version: 1,
        request: intent.request.clone(),
        request_digest: intent.request_digest.clone(),
        authenticated_owner_certificate_digest: intent
            .request
            .policy
            .owner_certificate_digest
            .clone(),
        owner_approval_evidence_digest: intent.owner_approval_evidence_digest.clone(),
        local_target_digest: intent.local_target_digest.clone(),
        local_owner_review_digest: intent.local_owner_review_digest.clone(),
        committed_at_ms: 1500,
    }
}
#[test]
fn absent_prepared_intent_is_retained_without_new_genesis() {
    let history = history();
    let descriptor = descriptor(&history);
    assert!(require_inventory_matrix(&node(&descriptor), &descriptor, &history).is_ok());
    assert_eq!(descriptor.accounts.len(), 1);
    assert!(matches!(
        descriptor.accounts.values().next(),
        Some(AccountState::Absent)
    ));
}
#[test]
fn omission_of_prepared_intent_is_denied() {
    let history = history();
    let mut descriptor = descriptor(&history);
    descriptor.accounts.clear();
    assert!(require_inventory_matrix(&node(&descriptor), &descriptor, &history).is_err());
}
#[test]
fn extra_unknown_journal_is_denied() {
    let history = history();
    let descriptor = descriptor(&history);
    let mut node = node(&descriptor);
    node.entries.insert(
        "unknown-legacy-history".into(),
        node.entries[LOCATOR].clone(),
    );
    assert!(require_inventory_matrix(&node, &descriptor, &history).is_err());
}
#[test]
fn absent_state_cannot_hide_an_archived_target() {
    let history = history();
    let descriptor = descriptor(&history);
    let mut node = node(&descriptor);
    node.entries.insert(
        account_id(history.prepared.keys().next().unwrap()).unwrap(),
        node.entries[LOCATOR].clone(),
    );
    assert!(require_inventory_matrix(&node, &descriptor, &history).is_err());
}
#[test]
fn empty_state_requires_exact_account_origin_and_role() {
    let history = history();
    let mut descriptor = descriptor(&history);
    let (id, prepared) = history.prepared.iter().next().unwrap();
    descriptor
        .accounts
        .insert(id.clone(), AccountState::AuthenticatedEmpty);
    let mut node = node(&descriptor);
    assert!(require_inventory_matrix(&node, &descriptor, &history).is_err());
    let entry = capsule::Entry {
        role: ACCOUNT_ROLE.into(),
        origin: Some(format!(
            "{}/{}",
            history.namespace.canonical_private_root, prepared.intent.derived_child
        )),
        payload: capsule::EntryPayload::Journal {
            files: BTreeMap::from([("".into(), object())]),
        },
    };
    node.entries.insert(account_id(id).unwrap(), entry);
    assert!(require_inventory_matrix(&node, &descriptor, &history).is_ok());
    node.entries
        .get_mut(&account_id(id).unwrap())
        .unwrap()
        .origin = Some("/other/empty.wp".into());
    assert!(require_inventory_matrix(&node, &descriptor, &history).is_err());
}
#[test]
fn wrong_secret_role_or_payload_kind_is_denied() {
    let history = history();
    let descriptor = descriptor(&history);
    let mut node = node(&descriptor);
    node.entries.get_mut(MASTER).unwrap().role = DESCRIPTOR_ROLE.into();
    assert!(require_inventory_matrix(&node, &descriptor, &history).is_err());
    node.entries.get_mut(MASTER).unwrap().role = MASTER_ROLE.into();
    node.entries.get_mut(MASTER).unwrap().payload =
        capsule::EntryPayload::File { object: object() };
    assert!(require_inventory_matrix(&node, &descriptor, &history).is_err());
}
#[test]
fn immutable_origin_change_is_not_namespace_relocation() {
    let history = history();
    let mut descriptor = descriptor(&history);
    descriptor.namespace.canonical_private_root = "/different/private/root".into();
    assert!(require_inventory_matrix(&node(&descriptor), &descriptor, &history).is_err());
}
#[test]
fn original_native_evidence_and_commit_time_must_survive() {
    let history = history();
    let prepared = history.prepared.values().next().unwrap();
    let mut birth = birth(&prepared.intent);
    assert!(require_birth(&history, prepared, &birth).is_ok());
    birth.local_owner_review_digest = h('f');
    assert!(require_birth(&history, prepared, &birth).is_err());
    birth = self::birth(&prepared.intent);
    birth.committed_at_ms = 1050;
    assert!(require_birth(&history, prepared, &birth).is_err());
    birth = self::birth(&prepared.intent);
    birth.committed_at_ms = 2000;
    assert!(require_birth(&history, prepared, &birth).is_err());
}
#[test]
fn old_key_alias_cannot_enter_archived_locator_fold() {
    let (namespace, first) = fixture();
    let second_request = rebind(first.request.clone(), 'a', '6', "other-operation", 'd');
    let second = intent(&namespace, second_request);
    assert!(
        LocatorHistory::from_records(
            namespace,
            vec![
                PreparedIntent {
                    intent: first,
                    prepared_at_ms: 1100
                },
                PreparedIntent {
                    intent: second,
                    prepared_at_ms: 1100
                }
            ],
            vec![],
            vec![]
        )
        .is_err()
    );
}
#[test]
fn retained_budget_change_changes_archive_history_commitment() {
    let original = history();
    let before = history_digest(&original).unwrap();
    let (namespace, mut changed) = fixture();
    changed.request.policy.aggregate_budget_zatoshis += 1;
    // Even changing terms and recomputing hashes must not compare equal to original.
    assert!(changed.validate(&namespace).is_err());
    assert_eq!(history_digest(&original).unwrap(), before);
}
#[test]
fn descriptor_rejects_legacy_unknown_version_and_oversized_inventory() {
    let history = history();
    let mut descriptor = descriptor(&history);
    descriptor.version = 0;
    assert!(descriptor.bytes().is_err());
    descriptor.version = 1;
    descriptor.accounts.clear();
    for i in 0..=MAX_INTENTS {
        descriptor
            .accounts
            .insert(format!("{i:064x}"), AccountState::Absent);
    }
    assert!(descriptor.bytes().is_err());
}
#[test]
fn canonical_descriptor_refuses_unknown_fields() {
    let history = history();
    let descriptor = descriptor(&history);
    let mut json = serde_json::to_value(&descriptor).unwrap();
    json["restored_live"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<Descriptor>(json).is_err());
}
#[test]
fn explicit_history_and_timestamp_are_part_of_plan() {
    let history = history();
    let mut descriptor = descriptor(&history);
    let before = descriptor.commitment().unwrap();
    descriptor.captured_at_ms += 1;
    assert_ne!(descriptor.commitment().unwrap(), before);
    descriptor.captured_at_ms -= 1;
    descriptor.locator_history_digest = h('f');
    assert_ne!(descriptor.commitment().unwrap(), before);
}
#[test]
fn marker_schema_prefix_uses_literal_underscore() {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch("CREATE TABLE sqliteXunknown(a INTEGER)")
        .unwrap();
    let count: u64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

fn evidence(n: &WitnessNamespaceBinding, i: &CreationIntent) -> CompletionEvidence {
    let birth_commit = PendingBirthCommitRecord {
        version: 1,
        request: i.request.clone(),
        request_digest: i.request_digest.clone(),
        authenticated_owner_certificate_digest: n.owner_certificate_digest.clone(),
        owner_approval_evidence_digest: i.owner_approval_evidence_digest.clone(),
        local_target_digest: i.local_target_digest.clone(),
        local_owner_review_digest: i.local_owner_review_digest.clone(),
        committed_at_ms: 1500,
    };
    let journal_genesis_commitment = digest(
        "wholepact:witness-locator-journal-genesis:v1",
        &(&i.request.policy, &birth_commit),
    )
    .unwrap();
    CompletionEvidence {
        version: 1,
        intent_digest: i.digest(n).unwrap(),
        birth_commit,
        journal_identity: JournalIdentity {
            device: 1,
            inode: 4,
            owner_uid: 1000,
        },
        journal_genesis_commitment,
    }
}

fn exclusion(n: &WitnessNamespaceBinding, i: &CreationIntent) -> RetainedExclusion {
    RetainedExclusion {
        version: 1,
        namespace_digest: n.digest().unwrap(),
        source_history_digest: h('f'),
        exclusion: PermanentAccountExclusion {
            version: 1,
            identity: i.identity().clone(),
            genesis_digest: i
                .request
                .policy
                .account_use_genesis
                .as_ref()
                .unwrap()
                .digest()
                .unwrap(),
            operation_id: "synthetic-retirement".into(),
            native_review_digest: h('c'),
            reason: ExclusionReason::RetirementRequested,
        },
    }
}

#[test]
fn completed_intent_cannot_be_archived_as_absent_or_empty() {
    let (namespace, intent) = fixture();
    let completion = CompletionRecord {
        evidence: evidence(&namespace, &intent),
        completed_at_ms: 1600,
    };
    let history = LocatorHistory::from_records(
        namespace,
        vec![PreparedIntent {
            intent,
            prepared_at_ms: 1100,
        }],
        vec![completion],
        vec![],
    )
    .unwrap();
    let mut descriptor = descriptor(&history);
    assert!(require_inventory_matrix(&node(&descriptor), &descriptor, &history).is_err());
    descriptor
        .accounts
        .values_mut()
        .for_each(|s| *s = AccountState::AuthenticatedEmpty);
    assert!(require_inventory_matrix(&node(&descriptor), &descriptor, &history).is_err());
}
#[test]
fn exclusion_omission_changes_sealed_locator_commitment() {
    let (namespace, intent) = fixture();
    let excluded = exclusion(&namespace, &intent);
    let before = LocatorHistory::from_records(
        namespace.clone(),
        vec![PreparedIntent {
            intent: intent.clone(),
            prepared_at_ms: 1100,
        }],
        vec![],
        vec![],
    )
    .unwrap();
    let after = LocatorHistory::from_records(
        namespace,
        vec![PreparedIntent {
            intent,
            prepared_at_ms: 1100,
        }],
        vec![],
        vec![excluded],
    )
    .unwrap();
    assert_ne!(
        history_digest(&before).unwrap(),
        history_digest(&after).unwrap()
    );
    let descriptor = descriptor(&after);
    assert!(require_inventory_matrix(&node(&descriptor), &descriptor, &before).is_err());
    assert!(require_inventory_matrix(&node(&descriptor), &descriptor, &after).is_ok());
}
#[test]
fn account_and_fvk_aliases_both_remain_reserved() {
    let (namespace, first) = fixture();
    let second_request = rebind(
        first.request.clone(),
        '1',
        'f',
        "same-account-other-key",
        'd',
    );
    let second = intent(&namespace, second_request);
    assert!(
        LocatorHistory::from_records(
            namespace,
            vec![
                PreparedIntent {
                    intent: first,
                    prepared_at_ms: 1100
                },
                PreparedIntent {
                    intent: second,
                    prepared_at_ms: 1100
                }
            ],
            vec![],
            vec![]
        )
        .is_err()
    );
}

#[test]
fn archive_node_cannot_relabel_installed_identity_or_root() {
    let history = history();
    let descriptor = descriptor(&history);
    let mut node = node(&descriptor);
    node.generation_id = h('f');
    assert!(require_inventory_matrix(&node, &descriptor, &history).is_err());
    node.generation_id = descriptor.namespace.namespace_instance_id.clone();
    node.profile_id = "different-installed-witness".into();
    assert!(require_inventory_matrix(&node, &descriptor, &history).is_err());
    node.profile_id = descriptor.namespace.witness_id.clone();
    node.original_root = "/new/empty/root".into();
    assert!(require_inventory_matrix(&node, &descriptor, &history).is_err());
}

#[path = "namespace_archive_capsule_tests.rs"]
mod capsule_tests;
