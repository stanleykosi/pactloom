//! Mathematical/data-only component tests. Fresh random never-funded owners and
//! maintained note scanning; no native decision, intake or fresh source is faked.
use super::*;
use wholepact_core::*;
use wholepact_protocol::review::encode_testnet_receiver;
fn amount(v: u64) -> Amount {
    Amount::from_zatoshis(v).unwrap()
}
fn material(c: &WalletContribution) -> HistoricalConstructionMaterialV1 {
    HistoricalConstructionMaterialV1 {
        version: 1,
        account_id: c.account_id.clone(),
        fvk_hex: hex::encode(c.fvk.to_bytes()),
        fvk_digest: hex::encode(Sha256::digest(c.fvk.to_bytes())),
        selected_zatoshis: c.selected_zatoshis,
        requested_debit_zatoshis: c.requested_debit_zatoshis,
        change_address: hex::encode(c.change_address.to_raw_address_bytes()),
        birthday_height: c.context.anchor_height,
        context: HistoricalContextV1::capture(&c.context),
        source: SourceHistoryV1 {
            source_id: "data-only-component".into(),
            endpoint: "https://component.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
            network: "test".into(),
            branch_id: "0x77190ad9".into(),
            lightwalletd_version: "component".into(),
            backend_subversion: "component".into(),
            protocol_version: "component".into(),
            request_started: 1_800_000_000,
            observed_at: 1_800_000_001,
            valid_until: 1_800_000_060,
        },
        notes: c
            .notes
            .iter()
            .zip(&c.local_outpoints)
            .map(|(n, (txid, index))| HistoricalNoteV1 {
                input_id: n.input_id.clone(),
                txid_protocol: hex::encode(txid.as_ref()),
                output_index: *index,
                recipient: hex::encode(n.note.recipient().to_raw_address_bytes()),
                value_zatoshis: n.note.value().inner(),
                rho: hex::encode(n.note.rho().to_bytes()),
                rseed: hex::encode(n.note.rseed().as_bytes()),
                nullifier: hex::encode(n.note.nullifier(&c.fvk).to_bytes()),
                commitment: hex::encode(
                    orchard::note::ExtractedNoteCommitment::from(n.note.commitment()).to_bytes(),
                ),
                position: n.witness.position(),
                authentication_path: n
                    .witness
                    .auth_path()
                    .iter()
                    .map(|p| hex::encode(p.to_bytes()))
                    .collect(),
            })
            .collect(),
    }
}
fn fixture() -> (
    HistoricalConstructionMaterialV1,
    DurableConstructionScopeV1,
    Vec<WalletContribution>,
) {
    let (contributions, _) = crate::wallet::synthetic_scanned_contributions().unwrap();
    let a = &contributions[0];
    let receiver = encode_testnet_receiver(&a.notes[0].note.recipient());
    let agreement = AgreementDraft {
        schema_version: 1,
        agreement_id: "durable-component".into(),
        obligation_id: "never-funded".into(),
        revision: 1,
        purpose: "Data-only construction decoder component".into(),
        organizer_identity: "component".into(),
        network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
        recipients: vec![Recipient {
            recipient_id: "recipient".into(),
            address: receiver.clone(),
            amount: amount(300_000),
            memo: None,
            instruction_provenance: "component".into(),
        }],
        funding_policy: FundingPolicy::Exact {
            target: amount(300_000),
        },
        fee_policy: FeePolicy::ProRata,
        privacy_profile: PrivacyProfile {
            mode: PrivacyMode::DeclaredOperator,
            proving_operator: Some("local-component".into()),
            dedicated_accounts_required: true,
        },
        coordination_deadline: None,
        confirmation_policy: ConfirmationPolicy::default(),
        extensions: vec![],
    };
    let mut participants = Vec::new();
    let mut inputs = Vec::new();
    let mut outputs = vec![ClaimedOutput {
        output_id: "recipient-output".into(),
        address: receiver,
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: "recipient".into(),
        },
    }];
    for (i, c) in contributions.iter().enumerate() {
        let participant_id = format!("participant-{i}");
        participants.push(ParticipantAllocation {
            participant_id: participant_id.clone(),
            account_id: c.account_id.clone(),
            contribution: amount(if i == 0 { 100_000 } else { 200_000 }),
            fee_share: amount(if i == 0 { 5_000 } else { 10_000 }),
            fee_cap: amount(if i == 0 { 5_000 } else { 10_000 }),
            maximum_net_debit: amount(c.requested_debit_zatoshis),
            charges: vec![],
        });
        for n in &c.notes {
            inputs.push(ClaimedInput {
                input_id: n.input_id.clone(),
                participant_id: participant_id.clone(),
                account_id: c.account_id.clone(),
                amount: amount(n.note.value().inner()),
                ownership_evidence_ref: None,
            });
        }
        outputs.push(ClaimedOutput {
            output_id: format!("change-{i}"),
            address: encode_testnet_receiver(&c.change_address),
            amount: amount(c.selected_zatoshis - c.requested_debit_zatoshis),
            allocation: OutputAllocation::Return {
                participant_id,
                account_id: c.account_id.clone(),
                ownership_evidence_ref: None,
            },
        });
    }
    let scope = DurableConstructionScopeV1 {
        version: 1,
        purpose: PURPOSE.into(),
        proposal: ProposalInput {
            proposal_id: "durable-candidate".into(),
            previous_proposal_id: None,
            manifest: ProposalManifest {
                agreement,
                participants,
                inputs,
                outputs,
                transaction_fee: amount(15_000),
                expiry_height: a.context.tip_height + 30,
            },
            artifact_digest: None,
            effects_commitment: None,
            created_at: "2026-10-17T00:00:00Z".into(),
        },
        account_id: a.account_id.clone(),
        participant_id: "participant-0".into(),
        privacy_domain: "dedicated-component".into(),
        constructor: ConstructionRecipientV1 {
            principal_id: "constructor".into(),
            authenticated_local_grant_digest: "11".repeat(32),
        },
        prover: ConstructionRecipientV1 {
            principal_id: "prover".into(),
            authenticated_local_grant_digest: "11".repeat(32),
        },
        reviewers: contributions
            .iter()
            .enumerate()
            .map(|(i, c)| ConstructionReviewerV1 {
                account_id: c.account_id.clone(),
                transport_key_digest: format!("{:02x}", 20 + i).repeat(32),
            })
            .collect(),
        protected_destination: "/component/private/intake.sqlite".into(),
        retention_policy: "Retain exact encrypted material for bounded construction only".into(),
        valid_from_unix_seconds: 1_800_000_000,
        valid_until_unix_seconds: 1_800_003_600,
        minimum_confirmations: 1,
        maximum_scan_blocks: 100,
    };
    (material(a), scope, contributions)
}
#[test]
fn exact_private_material_roundtrip_preserves_math_not_authority() {
    let (m, scope, owners) = fixture();
    m.validate_for(&scope).unwrap();
    let encoded = m.encode().unwrap();
    let restored = HistoricalConstructionMaterialV1::decode(&encoded).unwrap();
    assert!(restored == m);
    assert_eq!(restored.digest().unwrap(), m.digest().unwrap());
    restored.verify_owner(owners[0].fvk()).unwrap();
    assert!(restored.verify_owner(owners[1].fvk()).is_err());
    // Historical source expiry is not revived or treated as fresh permission.
    assert!(
        scope
            .check_valid_at(scope.valid_until_unix_seconds)
            .is_err()
    );
    assert!(restored.validate_for(&scope).is_ok());
}
#[test]
fn malformed_tampered_and_duplicate_note_material_is_rejected() {
    let (m, _, _) = fixture();
    let mut mutations = Vec::new();
    let mut n = m.clone();
    n.notes[0].nullifier = "ff".repeat(32);
    mutations.push(n);
    let mut n = m.clone();
    n.notes[0].value_zatoshis += 1;
    mutations.push(n);
    let mut n = m.clone();
    n.notes[0].rseed = "ff".repeat(32);
    mutations.push(n);
    let mut n = m.clone();
    n.notes[0].authentication_path.pop();
    mutations.push(n);
    let mut n = m.clone();
    n.notes[0].position ^= 1;
    mutations.push(n);
    let mut n = m.clone();
    n.context.anchor_root = "00".repeat(32);
    mutations.push(n);
    let mut n = m.clone();
    n.notes.push(n.notes[0].clone());
    mutations.push(n);
    let mut n = m.clone();
    n.fvk_digest = "00".repeat(32);
    mutations.push(n);
    for bad in mutations {
        let raw = Zeroizing::new(serde_json::to_vec(&bad).unwrap());
        assert!(HistoricalConstructionMaterialV1::decode(&raw).is_err());
    }
    let mut value = serde_json::to_value(&m).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("verified".into(), serde_json::json!(true));
    assert!(
        HistoricalConstructionMaterialV1::decode(&serde_json::to_vec(&value).unwrap()).is_err()
    );
    assert!(HistoricalConstructionMaterialV1::decode(&vec![b' '; MAX_MATERIAL_BYTES + 1]).is_err());
}
#[test]
fn old_purpose_wrong_account_and_missing_reviewer_are_not_durable_consent() {
    let (m, scope, _) = fixture();
    let mut old = scope.clone();
    old.purpose = "construct_exact_accepted_candidate".into();
    assert!(m.validate_for(&old).is_err());
    let mut wrong = scope.clone();
    wrong.account_id = "other-account".into();
    assert!(m.validate_for(&wrong).is_err());
    let mut missing = scope.clone();
    missing.reviewers.pop();
    assert!(m.validate_for(&missing).is_err());
    let mut repeated = scope.clone();
    repeated.reviewers[1] = repeated.reviewers[0].clone();
    assert!(m.validate_for(&repeated).is_err());
    let mut long = scope.clone();
    long.valid_until_unix_seconds = long.valid_from_unix_seconds + MAX_VALIDITY_SECONDS + 1;
    assert!(long.validate().is_err());
}
#[test]
fn exact_consent_digest_binds_changed_recipient_manifest_and_destination() {
    let (_, scope, _) = fixture();
    let original = scope.digest().unwrap();
    let mut values = Vec::new();
    let mut v = scope.clone();
    v.constructor.authenticated_local_grant_digest = "12".repeat(32);
    values.push(v);
    let mut v = scope.clone();
    v.prover.authenticated_local_grant_digest = "12".repeat(32);
    values.push(v);
    let mut v = scope.clone();
    v.reviewers[0].transport_key_digest = "12".repeat(32);
    values.push(v);
    let mut v = scope.clone();
    v.protected_destination.push_str(".other");
    values.push(v);
    let mut v = scope.clone();
    v.retention_policy.push_str(" changed");
    values.push(v);
    let mut v = scope.clone();
    v.proposal.manifest.agreement.revision += 1;
    values.push(v);
    let mut v = scope.clone();
    v.proposal
        .manifest
        .agreement
        .obligation_id
        .push_str("-other");
    values.push(v);
    for changed in values {
        assert_ne!(changed.digest().unwrap(), original);
    }
}
