//! Pure synthetic schema predicates, not original-born migration or native birth.
use super::*;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use wholepact_authority::{
    account_use::{AccountUseGenesis, AccountUseIdentity},
    account_use_link::account_use_witness_origin_digest,
    durable_payment_v1::{
        DurableFixedCandidateBindingV1, DurablePaymentAdmissionRecordV1,
        DurablePaymentAdmissionTermsV1,
    },
    AuthorityHead, InputReservation, OwnerControl, OwnerControlRequest,
    WitnessDisclosureDescriptor,
};

#[test]
fn financial19_is_exact_frozen18_plus_only_financial_intent_objects() {
    assert_eq!(SCHEMA_VERSION, 19);
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(recovery_migration::V18_SCHEMA).unwrap();
    c.execute_batch(include_str!("durable_payment_admission_schema_v19.sql"))
        .unwrap();
    recovery_migration::verify_exact_schema(&c, SCHEMA).unwrap();
    assert_eq!(
        c.query_row(
            "SELECT count(*) FROM signer_durable_payment_admission_intents",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        0
    );
    assert!(recovery_migration::verify_exact_schema(&c, recovery_migration::V18_SCHEMA).is_err());
    assert_eq!(
        c.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name LIKE '%durable_input_projection%'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn immutable_financial_intent_disallows_update_delete_replace_and_all_unique_collisions() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(SCHEMA).unwrap();
    c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    c.execute("INSERT INTO signer_durable_payment_admission_intents VALUES('op','auth','digest','e','m','payload')",[]).unwrap();
    for sql in [
        "UPDATE signer_durable_payment_admission_intents SET payload='changed'",
        "DELETE FROM signer_durable_payment_admission_intents",
        "INSERT OR REPLACE INTO signer_durable_payment_admission_intents VALUES('op','new-auth','new-digest','e','m','new')",
        "INSERT OR REPLACE INTO signer_durable_payment_admission_intents VALUES('new-op','auth','new-digest','e','m','new')",
        "INSERT OR REPLACE INTO signer_durable_payment_admission_intents VALUES('new-op','new-auth','digest','e','m','new')",
    ] { assert!(c.execute_batch(sql).is_err()); }
    let retained:(String,String,String,String)=c.query_row("SELECT operation_id,authorization_id,request_digest,payload FROM signer_durable_payment_admission_intents",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(
        retained,
        (
            "op".into(),
            "auth".into(),
            "digest".into(),
            "payload".into()
        )
    );
}

#[test]
fn malformed_financial_row_is_not_dropped_by_schema_or_backup_validation() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(SCHEMA).unwrap();
    c.execute("INSERT INTO signer_account VALUES(1,'synthetic',1,0)", [])
        .unwrap();
    c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    c.execute(
        "INSERT INTO signer_durable_payment_admission_intents VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            "op",
            "auth",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "{}"
        ],
    )
    .unwrap();
    let changes = c.total_changes();
    assert!(storage::verify_schema(&c).is_err());
    assert_eq!(changes, c.total_changes());
    assert_eq!(
        c.query_row(
            "SELECT count(*) FROM signer_durable_payment_admission_intents",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        1
    );
}

// This serialization-only mirror supplies historical bytes to the real strict
// reader. It has no Pending, Approval, native issuer, session, or live authority.
#[derive(Serialize)]
struct InertFinancialHistory {
    version: u16,
    request: OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
    owner_certificate_digest: String,
    enrollment_ref: String,
    manifest_ref: String,
    native_receipt: NativeConsentReceipt,
    native_review_digest: String,
}

fn authority_history_digest<T: Serialize>(domain: &str, value: &T) -> String {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0]);
    h.update(serde_json::to_vec(value).unwrap());
    hex::encode(h.finalize())
}

fn inert_fixed_binding(f: &DurableFixedCandidateBindingV1) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
    h.update(f.schema_version.to_le_bytes());
    h.update(f.revision.to_le_bytes());
    h.update(f.expiry_height.to_le_bytes());
    for value in [
        &f.network_profile_id,
        &f.agreement_id,
        &f.obligation_id,
        &f.proposal_id,
        &f.proposal_digest,
        &f.manifest_digest,
        &f.unsigned_artifact_digest,
        &f.proved_artifact_digest,
        &f.effects_commitment,
        &f.policy_digest,
        &f.review_binding,
        &f.action_mapping_digest,
        &f.anchor,
    ] {
        h.update((value.len() as u64).to_le_bytes());
        h.update(value.as_bytes());
    }
    hex::encode(h.finalize())
}

fn valid_inert_financial_history() -> (Connection, InertFinancialHistory) {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    c.execute_batch(SCHEMA).unwrap();
    let account = "11".repeat(32);
    c.execute("INSERT INTO signer_account VALUES(1,?1,1,0)", [&account])
        .unwrap();

    // Reuse only the pure proposal-data builder, never its native test helpers.
    let mut input = super::tests::proposal("agreement-a", "obligation-a", "proposal-a")
        .input()
        .clone();
    for participant in &mut input.manifest.participants {
        if participant.account_id == "account-alice" {
            participant.account_id = account.clone();
        }
    }
    for input in &mut input.manifest.inputs {
        if input.account_id == "account-alice" {
            input.account_id = account.clone();
        }
    }
    for output in &mut input.manifest.outputs {
        if let wholepact_core::OutputAllocation::Return { account_id, .. } = &mut output.allocation
        {
            if *account_id == "account-alice" {
                *account_id = account.clone();
            }
        }
    }
    let proposal = wholepact_core::Proposal::validate(input).unwrap();
    let disclosure = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:443".into(),
        server_name: "synthetic-witness.example".into(),
        witness_id: "synthetic-witness".into(),
        account_id: account.clone(),
        network_profile_id: proposal.manifest().agreement.network_profile_id.clone(),
        policy_digest: "22".repeat(32),
        pinned_server_certificate_digest: "33".repeat(32),
    };
    let genesis = AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: account.clone(),
            full_viewing_key_digest: "fa".repeat(32),
            network_profile_id: disclosure.network_profile_id.clone(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        witness_id: disclosure.witness_id.clone(),
        witness_origin_digest: account_use_witness_origin_digest(&disclosure).unwrap(),
        owner_certificate_digest: "44".repeat(32),
        native_birth_digest: "55".repeat(32),
    };
    c.execute(
        "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
        params![
            account,
            genesis.identity.full_viewing_key_digest,
            genesis.digest().unwrap(),
            encode(&genesis).unwrap().as_str()
        ],
    )
    .unwrap();

    // Deliberately expired, fabricated receipt data. No native runtime issues it.
    let receipt = NativeConsentReceipt {
        native_session_id: "61".repeat(32),
        trusted_launch_measurement: "62".repeat(32),
        permission_generation: 1,
        writer_epoch: 1,
        nonce: "63".repeat(32),
        reviewed_at_ms: 1_000,
        expires_at_ms: 2_000,
    };
    let enrollment = AccountEnrollmentRecord::new(EnrollmentTerms {
        account_id: account.clone(),
        agreement_id: proposal.manifest().agreement.agreement_id.clone(),
        participant_id: "alice".into(),
        principal_id: "synthetic-owner".into(),
        network_profile_id: disclosure.network_profile_id.clone(),
        privacy_domain: "synthetic-domain".into(),
        account_fvk_digest: genesis.identity.full_viewing_key_digest.clone(),
        transport: TransportIdentityBinding::RemoteAuthenticatedKeys {
            transport_identity_id: "synthetic-transport".into(),
            sender_key_digest: "a1".repeat(32),
            recipient_key_digest: "b2".repeat(32),
            channel_binding_digest: "c3".repeat(32),
        },
        aggregate_budget_limit_zatoshis: 1_000_000_000,
        receipt: receipt.clone(),
    })
    .unwrap();
    let manifest = AcceptedManifestRecord::new(ManifestTerms {
        enrollment_ref: enrollment.reference().into(),
        account_id: account.clone(),
        principal_id: enrollment.principal_id().into(),
        proposal: proposal.input().clone(),
        proposal_digest: proposal.proposal_digest().into(),
        manifest_digest: proposal.manifest_digest().into(),
        receipt: receipt.clone(),
    })
    .unwrap();
    c.execute(
        "INSERT INTO signer_enrollments VALUES(?1,?2,?3,?4,?5)",
        params![
            enrollment.reference(),
            enrollment.account_id(),
            enrollment.agreement_id(),
            enrollment.participant_id(),
            encode(&enrollment).unwrap().as_str()
        ],
    )
    .unwrap();
    c.execute(
        "INSERT INTO signer_accepted_manifests VALUES(?1,?2,?3,?4,?5)",
        params![
            manifest.reference(),
            manifest.enrollment_ref(),
            proposal.input().proposal_id,
            proposal.proposal_digest(),
            encode(&manifest).unwrap().as_str()
        ],
    )
    .unwrap();
    let mut fixed = DurableFixedCandidateBindingV1 {
        schema_version: 1,
        network_profile_id: disclosure.network_profile_id.clone(),
        agreement_id: proposal.manifest().agreement.agreement_id.clone(),
        obligation_id: proposal.manifest().agreement.obligation_id.clone(),
        proposal_id: proposal.input().proposal_id.clone(),
        revision: proposal.manifest().agreement.revision,
        expiry_height: proposal.manifest().expiry_height,
        proposal_digest: proposal.proposal_digest().into(),
        manifest_digest: proposal.manifest_digest().into(),
        unsigned_artifact_digest: "66".repeat(32),
        proved_artifact_digest: "77".repeat(32),
        effects_commitment: "88".repeat(32),
        policy_digest: "99".repeat(32),
        review_binding: "aa".repeat(32),
        action_mapping_digest: "bb".repeat(32),
        anchor: "cc".repeat(32),
        proposal_binding: String::new(),
    };
    fixed.proposal_binding = inert_fixed_binding(&fixed);
    let mut authorization = Sha256::new();
    authorization.update(b"wholepact:durable-manual-proposal-authorization:v1\0");
    for value in [&fixed.proposal_binding, &account] {
        authorization.update((value.len() as u64).to_le_bytes());
        authorization.update(value.as_bytes());
    }
    let terms = DurablePaymentAdmissionTermsV1 {
        version: 1,
        identity: wholepact_core::manual_enrollment::ManualAccountIdentity {
            account_id: account.clone(),
            full_viewing_key_digest: genesis.identity.full_viewing_key_digest.clone(),
            network_profile_id: genesis.identity.network_profile_id.clone(),
            derivation_domain: genesis.identity.derivation_domain.clone(),
        },
        original_policy_digest: disclosure.policy_digest.clone(),
        original_genesis_digest: genesis.digest().unwrap(),
        original_birth_commit_digest: "dd".repeat(32),
        original_roster_extension_digest: "ee".repeat(32),
        original_enrollment_ref: "ff".repeat(32),
        writer_certificate_digest: "12".repeat(32),
        fixed,
        authorization_id: format!("durable-v1-{}", hex::encode(authorization.finalize())),
        recipient_policy_scope_digest: "23".repeat(32),
        concrete_recipient_scope_digest: "34".repeat(32),
        inputs: vec![InputReservation {
            input_id: "synthetic-input".into(),
            nullifier: "45".repeat(32),
            action_index: 0,
            value_zatoshis: 1_000,
        }],
        maximum_debit_zatoshis: 100,
        fee_share_zatoshis: 10,
        transaction_fee_zatoshis: 20,
        valid_from_ms: 1,
        valid_until_ms: 60_001,
    };
    let head = AuthorityHead {
        sequence: 5,
        digest: "56".repeat(32),
    };
    let operation_id = format!(
        "durable-payment-admit-v1-{}",
        authority_history_digest(
            "wholepact:durable-payment-owner-operation:v1",
            &(
                &terms,
                &account,
                &disclosure.network_profile_id,
                1_u64,
                &head
            )
        )
    );
    let witness_native_review_digest = authority_history_digest(
        "wholepact:durable-payment-witness-native-review:v1",
        &(
            &terms,
            &account,
            &disclosure.network_profile_id,
            1_u64,
            &head,
            &disclosure,
        ),
    );
    let authorization_id = terms.authorization_id.clone();
    let request = OwnerControlRequest {
        operation_id,
        account_id: account,
        network_profile_id: disclosure.network_profile_id.clone(),
        writer_epoch: 1,
        expected_head: head,
        control: OwnerControl::AdmitDurablePaymentV1 {
            record: Box::new(DurablePaymentAdmissionRecordV1 {
                terms,
                witness_native_review_digest,
            }),
        },
    };
    if let OwnerControl::AdmitDurablePaymentV1 { record } = &request.control {
        record.validate_request(&request, &disclosure).unwrap();
    }
    let mut history = InertFinancialHistory {
        version: 1,
        request,
        disclosure,
        owner_certificate_digest: genesis.owner_certificate_digest,
        enrollment_ref: enrollment.reference().into(),
        manifest_ref: manifest.reference().into(),
        native_receipt: receipt,
        native_review_digest: String::new(),
    };
    history.native_review_digest = digest(
        "wholepact:signer-durable-payment-admission-review:v1",
        &(
            history.version,
            &history.request,
            &history.disclosure,
            &history.owner_certificate_digest,
            &history.enrollment_ref,
            &history.manifest_ref,
            &history.native_receipt,
        ),
    )
    .unwrap();

    // The non-financial history already passes in both feature profiles.
    storage::verify_schema(&c).unwrap();
    c.execute(
        "INSERT INTO signer_durable_payment_admission_intents VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            history.request.operation_id,
            authorization_id,
            digest(
                "wholepact:signer-durable-payment-admission-request:v1",
                &history.request
            )
            .unwrap(),
            history.enrollment_ref,
            history.manifest_ref,
            encode(&history).unwrap().as_str()
        ],
    )
    .unwrap();
    (c, history)
}

#[test]
fn valid_retained_financial_history_requires_the_enabled_profile_without_mutation() {
    let (c, history) = valid_inert_financial_history();
    let changes = c.total_changes();
    let original_payload = encode(&history).unwrap();

    // Independent full reader success prevents a malformed-data refusal from
    // satisfying the disabled-profile regression.
    let retained = read_durable_payment_admission_intents_v1(&c).unwrap();
    assert_eq!(retained.len(), 1);
    assert!(retained[0].request() == &history.request);
    assert_eq!(
        retained[0].history_digest().unwrap(),
        digest(
            "wholepact:signer-durable-payment-admission-intent-history:v1",
            &history
        )
        .unwrap()
    );

    #[cfg(not(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    )))]
    assert!(matches!(
        storage::verify_schema(&c),
        Err(JournalError::RecoveryRequired)
    ));
    // The exact same valid rows are a positive control with the typed profile.
    #[cfg(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    ))]
    storage::verify_schema(&c).unwrap();

    assert_eq!(changes, c.total_changes());
    let payloads = c
        .prepare("SELECT payload FROM signer_durable_payment_admission_intents")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(payloads, vec![original_payload.to_string()]);
}
