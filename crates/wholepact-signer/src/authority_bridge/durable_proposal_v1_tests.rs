//! Pure binding tests over fabricated metadata. These construct no native
//! decision, wallet permission, witness permit, spending key or signature.
use super::*;
use crate::consent_journal::{
    ConsentInputBinding, NativeConsentReceipt, TransportIdentityBinding, WalletSnapshotBinding,
};

fn hash(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn identity() -> FixedProposalIdentityV1 {
    FixedProposalIdentityV1 {
        schema_version: 1,
        network_profile_id: "ironwood-testnet-nu7-candidate".into(),
        agreement_id: "never-funded-agreement".into(),
        obligation_id: "never-funded-obligation".into(),
        proposal_id: "never-funded-proposal".into(),
        revision: 1,
        expiry_height: 3_000_000,
        proposal_digest: hash('1'),
        manifest_digest: hash('2'),
        unsigned_artifact_digest: hash('3'),
        proved_artifact_digest: hash('4'),
        effects_commitment: hash('5'),
        policy_digest: hash('6'),
        review_binding: hash('7'),
        action_mapping_digest: hash('8'),
        anchor: hash('9'),
        proposal_binding: hash('a'),
    }
}

fn terms(identity: &FixedProposalIdentityV1) -> SpendConsentTerms {
    SpendConsentTerms {
        automation: None,
        sponsor_policy: None,
        sponsor_owner_attestation_digest: None,
        authorization_id: manual_authorization_id(identity, "never-funded-alice").unwrap(),
        enrollment_ref: hash('b'),
        accepted_manifest_ref: hash('c'),
        account_id: "never-funded-alice".into(),
        principal_id: "never-funded-native-principal".into(),
        agreement_id: identity.agreement_id.clone(),
        obligation_id: identity.obligation_id.clone(),
        proposal_id: identity.proposal_id.clone(),
        proposal_digest: identity.proposal_digest.clone(),
        manifest_digest: identity.manifest_digest.clone(),
        effects_digest: identity.effects_commitment.clone(),
        artifact_digest: identity.proved_artifact_digest.clone(),
        review_binding: identity.review_binding.clone(),
        transport: TransportIdentityBinding::RemoteAuthenticatedKeys {
            transport_identity_id: "never-funded-transport-descriptor".into(),
            sender_key_digest: hash('b'),
            recipient_key_digest: hash('c'),
            channel_binding_digest: hash('d'),
        },
        input_bindings: vec![ConsentInputBinding {
            input_id: "never-funded-alice-input".into(),
            action_index: 0,
            nullifier: hash('e'),
            value_zatoshis: 120_000,
        }],
        maximum_debit_zatoshis: 110_000,
        fee_share_zatoshis: 10_000,
        transaction_fee_zatoshis: 20_000,
        aggregate_budget_limit_zatoshis: 1_000_000,
        transaction_expiry_height: identity.expiry_height,
        wallet_snapshot: WalletSnapshotBinding {
            tip_height: 2_999_900,
            tip_hash: hash('d'),
            anchor_height: 2_999_899,
            anchor_hash: hash('e'),
            anchor_root: identity.anchor.clone(),
        },
        wallet_key_use_policy: Some(wholepact_wallet::WalletKeyUsePolicy {
            confidence: wholepact_wallet::WalletKeyUseConfidence::SyntheticNeverChainEvidence,
            source_id: "never-funded-source".into(),
            endpoint: "https://invalid.invalid".into(),
            maximum_observation_age_seconds: 30,
            minimum_confirmations: 1,
            minimum_expiry_margin_blocks: 10,
        }),
        receipt: NativeConsentReceipt {
            native_session_id: hash('b'),
            trusted_launch_measurement: hash('c'),
            permission_generation: 1,
            writer_epoch: 1,
            nonce: hash('d'),
            reviewed_at_ms: 1,
            expires_at_ms: 120_001,
        },
    }
}

#[test]
fn authorization_identifier_is_stable_per_fixed_candidate_and_actual_account() {
    let identity = identity();
    let alice = manual_authorization_id(&identity, "never-funded-alice").unwrap();
    let bob = manual_authorization_id(&identity, "never-funded-bob").unwrap();
    assert_ne!(alice, bob);
    assert_eq!(alice, manual_authorization_id(&identity, "never-funded-alice").unwrap());
    assert!(alice.starts_with("durable-v1-"));
    assert!(alice.len() <= 128);
    let mut replacement = identity.clone();
    replacement.proposal_binding = hash('f');
    assert_ne!(alice, manual_authorization_id(&replacement, "never-funded-alice").unwrap());
    // Changing an attempt time or current wallet tip is not an input to this
    // identifier, so a restart cannot mint another attempt for the same payment.
}

#[test]
fn authorization_identifier_rejects_unversioned_or_malformed_commitments() {
    let mut identity = identity();
    assert!(manual_authorization_id(&identity, "").is_err());
    assert!(manual_authorization_id(&identity, "alice\nother").is_err());
    identity.schema_version = 2;
    assert!(manual_authorization_id(&identity, "never-funded-alice").is_err());
    identity.schema_version = 1;
    for invalid in ["", "abc", &"A".repeat(64), &"g".repeat(64)] {
        identity.proposal_binding = invalid.into();
        assert!(manual_authorization_id(&identity, "never-funded-alice").is_err());
    }
}

#[test]
fn original_binding_rejects_replacement_artifact_anchor_terms_and_retry_id() {
    let identity = identity();
    let original = terms(&identity);
    validate_terms_binding(&identity, &original, "never-funded-alice").unwrap();
    let changes: &[fn(&mut SpendConsentTerms)] = &[
        |t| t.authorization_id = "new-attempt-id".into(),
        |t| t.account_id = "never-funded-bob".into(),
        |t| t.agreement_id.push_str("-replacement"),
        |t| t.obligation_id.push_str("-replacement"),
        |t| t.proposal_id.push_str("-replacement"),
        |t| t.proposal_digest = hash('f'),
        |t| t.manifest_digest = hash('f'),
        |t| t.artifact_digest = hash('f'),
        |t| t.effects_digest = hash('f'),
        |t| t.review_binding = hash('f'),
        |t| t.wallet_snapshot.anchor_root = hash('f'),
        |t| t.transaction_expiry_height += 1,
        |t| t.wallet_key_use_policy = None,
    ];
    for change in changes {
        let mut changed = original.clone();
        change(&mut changed);
        assert!(matches!(
            validate_terms_binding(&identity, &changed, "never-funded-alice"),
            Err(BridgeError::Binding)
        ));
    }
}

#[test]
fn fixed_data_does_not_freeze_or_renew_the_native_wallet_tip() {
    let identity = identity();
    let mut current_terms = terms(&identity);
    let authorization = current_terms.authorization_id.clone();
    // A genuinely NEW native review may use then-current wallet context without
    // changing the immutable transaction/anchor. This data check grants nothing;
    // approve_spend and the wallet guard still demand current opaque authority.
    current_terms.wallet_snapshot.tip_height += 1;
    current_terms.wallet_snapshot.tip_hash = hash('f');
    current_terms.receipt.native_session_id = hash('e');
    current_terms.receipt.nonce = hash('f');
    validate_terms_binding(&identity, &current_terms, "never-funded-alice").unwrap();
    assert_eq!(authorization, current_terms.authorization_id);
    current_terms.wallet_snapshot.anchor_root = hash('0');
    assert!(validate_terms_binding(&identity, &current_terms, "never-funded-alice").is_err());
}

#[test]
fn missing_or_uncertain_persisted_result_requires_recovery_not_resigning() {
    assert!(matches!(recovery_if_incomplete(BridgeError::Missing), BridgeError::RecoveryRequired));
    assert!(matches!(recovery_if_incomplete(BridgeError::Uncertain), BridgeError::RecoveryRequired));
    assert!(matches!(recovery_if_incomplete(BridgeError::Binding), BridgeError::Binding));
    assert!(matches!(recovery_if_incomplete(BridgeError::Permission), BridgeError::Permission));
}
