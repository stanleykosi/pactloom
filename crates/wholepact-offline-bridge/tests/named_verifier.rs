#![cfg(feature = "synthetic-selected-effects-tests")]
//! In-memory unproved builder only; IO-finalized dummy signatures, no prover,
//! real-owner signer, network or vault. Reports cannot become signing authority.
use wholepact_offline_bridge::inspect_selected_offline_effects;
use wholepact_protocol::{
    canonical_role_layout::produce_canonical_layout,
    own_effects::*,
    review::{OutputPurpose, verify_review},
    synthetic::review_fixture,
};
fn fixture() -> (
    Vec<u8>,
    OwnEffectsPolicy,
    String,
    wholepact_protocol::canonical_role_layout::CanonicalLayoutArtifact,
    wholepact_protocol::review::ReviewPolicy,
) {
    let f = review_fixture().unwrap();
    let broad = verify_review(&f.pczt_bytes, &f.policy).unwrap();
    let artifact = produce_canonical_layout(&f.pczt_bytes, &f.policy).unwrap();
    let bytes = artifact.bytes().to_vec();
    let p = &f.policy.participants[0];
    let policy = OwnEffectsPolicy {
        account_id: p.account_id.clone(),
        own_fvk: p.fvk.clone(),
        manifest_digest: f.policy.manifest_digest,
        anchor: f.policy.anchor,
        expiry_height: f.policy.expiry_height,
        maximum_selected_net_debit_zatoshis: p.maximum_net_debit_zatoshis,
        exact_selected_net_debit_zatoshis: broad.net_debits_zatoshis()[0],
        declared_fee_share_zatoshis: p.fee_share_zatoshis,
        exact_transaction_fee_zatoshis: f.policy.exact_fee_zatoshis,
        own_inputs: f
            .policy
            .inputs
            .iter()
            .filter(|i| i.participant_index == 0)
            .map(|i| OwnInputExpectation {
                action_index: i.action_index,
                nullifier: i.nullifier,
                value_zatoshis: i.value_zatoshis,
            })
            .collect(),
        outputs: f
            .policy
            .outputs
            .iter()
            .map(|o| OwnOutputExpectation {
                action_index: o.action_index,
                receiver: o.receiver,
                value_zatoshis: o.value_zatoshis,
                memo: o.memo,
                purpose: match o.purpose {
                    OutputPurpose::Recipient => OwnOutputPurpose::Recipient,
                    OutputPurpose::Return {
                        participant_index: 0,
                    } => OwnOutputPurpose::OwnReturn,
                    OutputPurpose::Return { .. } => OwnOutputPurpose::PeerReturnUnverified,
                },
            })
            .collect(),
    };
    (
        bytes,
        policy,
        broad.shielded_sighash().into(),
        artifact,
        f.policy.clone(),
    )
}
use sha2::{Digest, Sha256};
use wholepact_offline_bridge::{
    NamedInputAllocationV1, NamedOutputAllocationV1, NamedParticipantAllocationV1,
    NamedVerifierExpectedContext, NamedVerifierStatementV1,
    verify_named_verifier_signature_evidence,
};
fn h(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn wire_statement(
    policy: &wholepact_protocol::review::ReviewPolicy,
    artifact: &wholepact_protocol::canonical_role_layout::CanonicalLayoutArtifact,
    own: &OwnEffectsInspection,
    key: &[u8; 32],
) -> NamedVerifierStatementV1 {
    let mut s = NamedVerifierStatementV1 {
        schema_version: 1,
        verifier_key_digest: h(key),
        recipient_account_id: policy.participants[0].account_id.clone(),
        original_artifact_digest: artifact.transformation().original_digest().into(),
        recipient_artifact_digest: artifact.transformation().redacted_digest().into(),
        transformation_commitment: artifact.transformation().commitment().into(),
        effects_digest: own.shielded_sighash().into(),
        manifest_digest: hex::encode(policy.manifest_digest),
        original_context_digest: "11".repeat(32),
        original_request_digest: "12".repeat(32),
        validity_not_before_ms: 100,
        validity_expires_ms: 200,
        transaction_expiry_height: policy.expiry_height,
        transaction_fee_zatoshis: policy.exact_fee_zatoshis,
        participants: policy
            .participants
            .iter()
            .enumerate()
            .map(|(index, p)| NamedParticipantAllocationV1 {
                account_id: p.account_id.clone(),
                contribution_zatoshis: p.contribution_zatoshis,
                fee_share_zatoshis: p.fee_share_zatoshis,
                maximum_debit_zatoshis: p.maximum_net_debit_zatoshis,
                selected_own_policy_digest: if index == 0 {
                    own.policy_digest().into()
                } else {
                    "22".repeat(32)
                },
            })
            .collect(),
        inputs: policy
            .inputs
            .iter()
            .map(|i| NamedInputAllocationV1 {
                action_index: i.action_index as u32,
                participant_index: i.participant_index as u32,
                nullifier: hex::encode(i.nullifier),
                value_zatoshis: i.value_zatoshis,
            })
            .collect(),
        outputs: policy
            .outputs
            .iter()
            .map(|o| NamedOutputAllocationV1 {
                action_index: o.action_index as u32,
                return_participant_index: match o.purpose {
                    OutputPurpose::Recipient => None,
                    OutputPurpose::Return { participant_index } => Some(participant_index as u32),
                },
                receiver: hex::encode(o.receiver.to_raw_address_bytes()),
                value_zatoshis: o.value_zatoshis,
                memo_digest: h(&o.memo),
            })
            .collect(),
    };
    s.inputs.sort_by_key(|i| i.action_index);
    s.outputs.sort_by_key(|o| o.action_index);
    s
}
fn context(s: &NamedVerifierStatementV1) -> NamedVerifierExpectedContext<'_> {
    NamedVerifierExpectedContext {
        original_artifact_digest: &s.original_artifact_digest,
        transformation_commitment: &s.transformation_commitment,
        manifest_digest: &s.manifest_digest,
        original_context_digest: &s.original_context_digest,
        original_request_digest: &s.original_request_digest,
        validity_not_before_ms: s.validity_not_before_ms,
        validity_expires_ms: s.validity_expires_ms,
        transaction_expiry_height: s.transaction_expiry_height,
        own_account_id: &s.participants[0].account_id,
    }
}
#[test]
fn named_signature_rejects_fabrication_after_actual_own_review() {
    let (bytes, policy, _, artifact, broad) = fixture();
    let own = inspect_selected_offline_effects(&bytes, &policy).unwrap();
    let key = [7; 32];
    let s = wire_statement(&broad, &artifact, own.inspection(), &key);
    assert!(matches!(
        verify_named_verifier_signature_evidence(
            &s.canonical_bytes().unwrap(),
            &[0; 64],
            &key,
            &context(&s),
            own.inspection()
        ),
        Err(wholepact_transport::TransportError::Authentication)
    ));
}
#[test]
fn named_signature_rejects_cross_key_original_request_and_validity() {
    let (bytes, policy, _, artifact, broad) = fixture();
    let own = inspect_selected_offline_effects(&bytes, &policy).unwrap();
    let key = [7; 32];
    let s = wire_statement(&broad, &artifact, own.inspection(), &key);
    assert!(matches!(
        verify_named_verifier_signature_evidence(
            &s.canonical_bytes().unwrap(),
            &[0; 64],
            &[8; 32],
            &context(&s),
            own.inspection()
        ),
        Err(wholepact_transport::TransportError::WrongContext)
    ));
    for changed in 0..4 {
        let mut copy = s.clone();
        match changed {
            0 => copy.original_request_digest = "33".repeat(32),
            1 => copy.validity_expires_ms += 1,
            2 => copy.original_artifact_digest = "44".repeat(32),
            _ => copy.transformation_commitment = "55".repeat(32),
        }
        assert!(matches!(
            verify_named_verifier_signature_evidence(
                &copy.canonical_bytes().unwrap(),
                &[0; 64],
                &key,
                &context(&s),
                own.inspection()
            ),
            Err(wholepact_transport::TransportError::WrongContext)
        ));
    }
}
#[test]
fn named_signature_rejects_wrong_selected_policy_and_noncanonical_wire() {
    let (bytes, policy, _, artifact, broad) = fixture();
    let own = inspect_selected_offline_effects(&bytes, &policy).unwrap();
    let key = [7; 32];
    let s = wire_statement(&broad, &artifact, own.inspection(), &key);
    let mut copy = s.clone();
    copy.participants[0].selected_own_policy_digest = "66".repeat(32);
    assert!(matches!(
        verify_named_verifier_signature_evidence(
            &copy.canonical_bytes().unwrap(),
            &[0; 64],
            &key,
            &context(&s),
            own.inspection()
        ),
        Err(wholepact_transport::TransportError::WrongContext)
    ));
    let mut noncanonical = s.canonical_bytes().unwrap();
    noncanonical.push(b' ');
    assert!(
        verify_named_verifier_signature_evidence(
            &noncanonical,
            &[0; 64],
            &key,
            &context(&s),
            own.inspection()
        )
        .is_err()
    );
}

#[test]
fn named_package_real_own_review_cannot_accept_fabricated_assertion() {
    let (bytes, policy, _, artifact, broad) = fixture();
    let own = inspect_selected_offline_effects(&bytes, &policy).unwrap();
    let key = [7; 32];
    let statement = wire_statement(&broad, &artifact, own.inspection(), &key);
    let package = wholepact_offline_bridge::NamedVerifierPackageV1 {
        schema_version: 1,
        statement: statement.clone(),
        signature: vec![0; 64],
        recipient_artifact: bytes,
    };
    let encoded = package.canonical_bytes().unwrap();
    assert!(matches!(
        wholepact_offline_bridge::inspect_named_verifier_package(
            &encoded,
            &policy,
            &key,
            &context(&statement)
        ),
        Err(wholepact_transport::TransportError::Authentication)
    ));
}
#[test]
fn named_package_rejects_replaced_artifact_unknown_fields_and_noncanonical_wire() {
    let (bytes, policy, _, artifact, broad) = fixture();
    let own = inspect_selected_offline_effects(&bytes, &policy).unwrap();
    let key = [7; 32];
    let statement = wire_statement(&broad, &artifact, own.inspection(), &key);
    let mut package = wholepact_offline_bridge::NamedVerifierPackageV1 {
        schema_version: 1,
        statement,
        signature: vec![0; 64],
        recipient_artifact: bytes,
    };
    let encoded = package.canonical_bytes().unwrap();
    assert_eq!(
        wholepact_offline_bridge::NamedVerifierPackageV1::parse(&encoded)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        encoded
    );
    let mut spaced = encoded.clone();
    spaced.push(b' ');
    assert!(wholepact_offline_bridge::NamedVerifierPackageV1::parse(&spaced).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("approved".into(), serde_json::json!(true));
    assert!(
        wholepact_offline_bridge::NamedVerifierPackageV1::parse(
            &serde_json::to_vec(&unknown).unwrap()
        )
        .is_err()
    );
    package.recipient_artifact[0] ^= 1;
    assert!(package.canonical_bytes().is_err());
}
