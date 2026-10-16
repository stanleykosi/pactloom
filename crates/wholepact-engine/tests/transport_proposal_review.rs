#![cfg(all(feature = "transport-workflows", feature = "synthetic-qualification"))]
//! Real maintained economic verification over never-funded synthetic notes only.
use std::sync::{RwLock, RwLockReadGuard};
use wholepact_core::*;
use wholepact_engine::participant_records::RecordStoreBinding;
use wholepact_engine::transport_workflows::proposal_review::*;
use wholepact_engine::{Access, ApiError, CandidateRequest, Engine};
use wholepact_protocol::{construction::*, review::encode_testnet_receiver, review_manifest::*};
use wholepact_storage_security::{DatabaseKey, create_encrypted};
use wholepact_store::Store;
use wholepact_transport::*;
use wholepact_wallet::wallet::synthetic_scanned_contributions;
fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}

struct Fixture {
    agreement: AgreementDraft,
    request: CandidateRequest,
    chain: ConstructionContext,
    packages: Vec<OwnedContribution>,
    account_ids: Vec<String>,
}
fn fixture() -> Fixture {
    let (wallets, selection) = synthetic_scanned_contributions().unwrap();
    let receiver = encode_testnet_receiver(&wallets[0].notes()[0].note.recipient());
    let account_ids: Vec<_> = wallets.iter().map(|w| w.account_id().to_owned()).collect();
    let agreement = AgreementDraft {
        schema_version: 1,
        agreement_id: "scanner-to-engine-synthetic".into(),
        obligation_id: "never-funded-obligation".into(),
        revision: 1,
        purpose: "Synthetic scanner to candidate qualification; no network or funds".into(),
        organizer_identity: "fixture-organizer".into(),
        network_profile_id: PROFILE_ID.into(),
        recipients: vec![Recipient {
            recipient_id: "fixture-recipient".into(),
            address: receiver.clone(),
            amount: amount(300_000),
            memo: None,
            instruction_provenance: "Synthetic owner receiver, not a live payment".into(),
        }],
        funding_policy: FundingPolicy::Exact {
            target: amount(300_000),
        },
        fee_policy: FeePolicy::ProRata,
        privacy_profile: PrivacyProfile {
            mode: PrivacyMode::DeclaredOperator,
            proving_operator: Some("synthetic-local-constructor".into()),
            dedicated_accounts_required: true,
        },
        coordination_deadline: None,
        confirmation_policy: ConfirmationPolicy::default(),
        extensions: vec![],
    };
    let participants: Vec<_> = wallets
        .iter()
        .enumerate()
        .map(|(i, w)| ParticipantAllocation {
            participant_id: format!("participant-{i}"),
            account_id: w.account_id().into(),
            contribution: amount(if i == 0 { 100_000 } else { 200_000 }),
            fee_share: amount(if i == 0 { 5_000 } else { 10_000 }),
            fee_cap: amount(if i == 0 { 5_000 } else { 10_000 }),
            maximum_net_debit: amount(w.requested_debit_zatoshis()),
            charges: vec![],
        })
        .collect();
    let mut inputs = vec![];
    let mut outputs = vec![ClaimedOutput {
        output_id: "recipient-output".into(),
        address: receiver,
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: "fixture-recipient".into(),
        },
    }];
    for (i, w) in wallets.iter().enumerate() {
        for n in w.notes() {
            inputs.push(ClaimedInput {
                input_id: n.input_id.clone(),
                participant_id: participants[i].participant_id.clone(),
                account_id: w.account_id().into(),
                amount: amount(n.note.value().inner()),
                ownership_evidence_ref: None,
            });
        }
        outputs.push(ClaimedOutput {
            output_id: format!("change-{i}"),
            address: encode_testnet_receiver(&w.change_address()),
            amount: amount(w.selected_zatoshis() - w.requested_debit_zatoshis()),
            allocation: OutputAllocation::Return {
                participant_id: participants[i].participant_id.clone(),
                account_id: w.account_id().into(),
                ownership_evidence_ref: None,
            },
        });
    }
    let request = CandidateRequest {
        manifest: ProposalManifest {
            agreement: agreement.clone(),
            participants: participants.clone(),
            inputs,
            outputs,
            transaction_fee: amount(15_000),
            expiry_height: selection.tip_height + 30,
        },
        previous_candidate_id: None,
    };
    let chain = ConstructionContext {
        anchor: selection.anchor_root,
        anchor_height: selection.anchor_height,
        anchor_block_hash: selection.anchor_hash_protocol,
        target_height: selection.tip_height + 1,
    };
    let packages: Vec<_> = wallets.into_iter().map(|w| w.into_contribution()).collect();
    Fixture {
        agreement,
        request,
        chain,
        packages,
        account_ids,
    }
}

fn now() -> Timestamp {
    Timestamp::from_unix_seconds(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    )
    .unwrap()
}
fn secret(b: u8) -> TransportSecret {
    TransportSecret::from_bytes([b; 32]).unwrap()
}
struct Authority {
    store: RecordStoreBinding,
    permitted: RwLock<bool>,
    candidate: String,
    manifest: String,
}
struct Lease<'a> {
    scope: ProposalTransportReviewScope,
    expires: Timestamp,
    guard: RwLockReadGuard<'a, bool>,
}
impl ProposalTransportReviewLease for Lease<'_> {
    fn scope(&self) -> &ProposalTransportReviewScope {
        &self.scope
    }
    fn expires_at(&self) -> &Timestamp {
        &self.expires
    }
    fn check_current(&self) -> std::result::Result<(), ApiError> {
        if *self.guard {
            Ok(())
        } else {
            Err(ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic review lease revoked",
            ))
        }
    }
}
impl ProposalTransportReviewAuthority for Authority {
    fn acquire<'a>(
        &'a self,
        scope: &ProposalTransportReviewScope,
        _: &DisclosurePreview,
    ) -> std::result::Result<Box<dyn ProposalTransportReviewLease + 'a>, ApiError> {
        let guard = self.permitted.read().unwrap();
        if !*guard
            || scope.store != self.store
            || scope.principal_id != "synthetic-controller"
            || scope.context.proposal_id != self.candidate
            || scope.manifest_digest != self.manifest
            || scope.sender_key_fingerprint != secret(11).public_key().unwrap().fingerprint()
            || scope.recipient_key_fingerprint != secret(22).public_key().unwrap().fingerprint()
        {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic review source scope denied",
            ));
        }
        Ok(Box::new(Lease {
            scope: scope.clone(),
            expires: Timestamp::from_unix_seconds(now().unix_seconds() + 60).unwrap(),
            guard,
        }))
    }
}
#[test]
fn authenticated_proposal_import_uses_exact_native_policy_and_reconciles_durable_review() {
    let Fixture {
        agreement,
        request,
        chain,
        packages,
        account_ids,
    } = fixture();
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let engine = Engine::from_store(
        Store::create_encrypted(
            dir.path().join("engine.db"),
            &DatabaseKey::from_bytes([90; 32]),
        )
        .unwrap(),
    );
    let access = Access {
        include_owned_agreements: true,
        principal_id: "synthetic-controller".into(),
        ..Access::default()
    };
    engine
        .create(&access, "synthetic-create-agreement", agreement.clone())
        .unwrap();
    for (i, p) in request.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &access,
                &format!("synthetic-intent-{i:04}"),
                &agreement.agreement_id,
                i as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("intent-{i}"),
                    agreement_id: agreement.agreement_id.clone(),
                    participant_id: p.participant_id.clone(),
                    desired_contribution: p.contribution,
                    maximum_net_debit: p.maximum_net_debit,
                    fee_cap: p.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            )
            .unwrap();
    }
    let frozen = engine
        .create_candidate(
            &access,
            "synthetic-freeze-candidate",
            &agreement.agreement_id,
            3,
            request,
        )
        .unwrap();
    let candidate = &frozen.agreement.candidates[0];
    let proposal = Proposal::validate(candidate.proposal.clone()).unwrap();
    let disclosures: Vec<_> = account_ids
        .iter()
        .map(|id| DisclosureAcknowledgement {
            account_id: id.clone(),
            manifest_digest: hex::decode(&candidate.manifest_digest)
                .unwrap()
                .try_into()
                .unwrap(),
            operator: "synthetic-local-constructor".into(),
            reviewer_account_ids: account_ids.clone(),
            purpose: "Synthetic local policy only".into(),
            retention_policy: "Encrypted recipient review only".into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    let constructed = construct_proposal(&proposal, chain, packages, &disclosures).unwrap();
    verify_manifest_policy(
        &proposal,
        &constructed.review_policy,
        &constructed.input_actions,
        &constructed.output_actions,
    )
    .unwrap();
    let mut altered = constructed.review_policy.clone();
    altered.outputs[0].memo[0] ^= 1;
    assert!(
        verify_manifest_policy(
            &proposal,
            &altered,
            &constructed.input_actions,
            &constructed.output_actions
        )
        .is_err()
    );
    let mut duplicates = constructed.output_actions.clone();
    duplicates[1] = duplicates[0].clone();
    assert!(
        verify_manifest_policy(
            &proposal,
            &constructed.review_policy,
            &constructed.input_actions,
            &duplicates
        )
        .is_err()
    );
    assert!(
        verify_manifest_policy(
            &proposal,
            &constructed.review_policy,
            &constructed.input_actions,
            &constructed.output_actions[1..]
        )
        .is_err()
    );
    altered = constructed.review_policy.clone();
    altered.participants[0].account_id = "untrusted-identity".into();
    assert!(
        verify_manifest_policy(
            &proposal,
            &altered,
            &constructed.input_actions,
            &constructed.output_actions
        )
        .is_err()
    );
    let now = now();
    let context = MessageContext {
        network_profile_id: agreement.network_profile_id.clone(),
        agreement_id: agreement.agreement_id.clone(),
        proposal_id: candidate.candidate_id.clone(),
        proposal_revision: agreement.revision.into(),
        sender_id: "pinned-proposal-source".into(),
        recipient_id: "local-reviewer".into(),
        artifact_kind: ArtifactKind::Proposal,
    };
    let prepared = prepare_proposal_review_message(
        ExportRequest {
            context: context.clone(),
            order: MessageOrder {
                message_id: "ab".repeat(16),
                sequence: 1,
                issued_at: now.clone(),
                expires_at: Timestamp::from_unix_seconds(now.unix_seconds() + 600).unwrap(),
            },
            purpose: "Synthetic exact proposal review".into(),
            persistence_warning:
                "The explicitly selected recipient can retain the witness-bearing artifact.".into(),
        },
        TransportProposalReview {
            schema_version: 1,
            expected_agreement_revision: 4,
            manifest_digest: candidate.manifest_digest.clone(),
        },
        constructed.pczt_bytes.clone(),
        &secret(11).public_key().unwrap(),
        &secret(22).public_key().unwrap(),
        &now,
    )
    .unwrap();
    let digest = prepared.preview().digest().unwrap();
    let file = prepared.seal(&secret(11), &digest, &now).unwrap();
    let mut inbox = SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(
            dir.path().join("inbox.db"),
            &DatabaseKey::from_bytes([91; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let received = open_envelope(
        &file,
        &secret(22),
        &secret(11).public_key().unwrap(),
        &context,
        &now,
        &mut inbox,
    )
    .unwrap();
    let authority = Authority {
        store: engine.protected_record_store_binding().unwrap(),
        permitted: RwLock::new(true),
        candidate: candidate.candidate_id.clone(),
        manifest: candidate.manifest_digest.clone(),
    };
    let local = || LocalProposalTransportReview {
        policy: &constructed.review_policy,
        input_actions: &constructed.input_actions,
        output_actions: &constructed.output_actions,
        authority: &authority,
    };
    let imported = engine
        .import_proposal_review_transport(&access, &mut inbox, &received, local())
        .unwrap();
    assert_eq!(imported.agreement.revision, 5);
    let report = &imported.agreement.candidates[0].reviews[0];
    assert!(report.economic_terms_verified);
    assert!(
        !report.authorization_allowed
            && !report.distribution_allowed
            && !report.account_associations_authenticated
            && !report.disclosure_consents_authenticated
            && !report.chain_validated
    );
    let replay = engine
        .import_proposal_review_transport(&access, &mut inbox, &received, local())
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, imported.operation_id);
    // Engine committed first; a restored receipt without completion reconciles
    // the original operation instead of appending another review.
    let mut recovered_inbox = SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(
            dir.path().join("recovered-inbox.db"),
            &DatabaseKey::from_bytes([92; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let recovered = open_envelope(
        &file,
        &secret(22),
        &secret(11).public_key().unwrap(),
        &context,
        &now,
        &mut recovered_inbox,
    )
    .unwrap();
    let replay = engine
        .import_proposal_review_transport(&access, &mut recovered_inbox, &recovered, local())
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, imported.operation_id);
    *authority.permitted.write().unwrap() = false;
    assert_eq!(
        engine
            .import_proposal_review_transport(&access, &mut inbox, &received, local())
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    assert_eq!(
        engine
            .get(&access, &agreement.agreement_id)
            .unwrap()
            .revision,
        5
    );
}
