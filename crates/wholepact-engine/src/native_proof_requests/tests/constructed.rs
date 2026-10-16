//! Source-only synthetic constructor/retention qualification. No proof run or native approval.
use super::*;
use crate::candidates::LocalConstruction;
use crate::{Access, CandidateRequest, Engine};
use wholepact_core::*;
use wholepact_protocol::{construction::*, review::encode_testnet_receiver};
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

use crate::proof_jobs::{LocalCheckpoint, LocalProofJob};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, ProofJobStore};
use wholepact_protocol::proving::ProvingLimits;
use wholepact_storage_security::{DatabaseKey, create_encrypted};

// Test-only permission for never-funded synthetic data. This gate explicitly
// excludes ProveLocally, recovery, and ReadPrivateArtifact; no native UI is invoked.
struct SyntheticInspectGate {
    candidate: String,
    manifest: String,
    accounts: Vec<String>,
    allowed: AtomicBool,
    race: Option<(Engine, Access, String)>,
    checks: AtomicUsize,
}
impl LocalProofConsent for SyntheticInspectGate {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        let valid = self.allowed.load(Ordering::SeqCst)
            && scope.principal_id == "synthetic-controller"
            && scope.candidate_id == self.candidate
            && scope.manifest_digest == self.manifest
            && scope.account_ids == self.accounts
            && scope.local_operator == "synthetic-local-constructor"
            && scope.purpose == "Synthetic request reconciliation qualification"
            && scope.retention_policy == "Encrypted temporary directory only"
            && matches!(
                action,
                LocalAction::RetainPrivateWitnesses | LocalAction::InspectStatus
            );
        if valid
            && action == LocalAction::RetainPrivateWitnesses
            && self.checks.fetch_add(1, Ordering::SeqCst) == 1
        {
            if let Some((engine, access, id)) = &self.race {
                engine
                    .propose(
                        access,
                        "synthetic-constructor-race",
                        id,
                        engine.get(access, id).unwrap().revision,
                    )
                    .unwrap();
            }
        }
        valid
    }
}
struct Constructed {
    dir: tempfile::TempDir,
    engine: Engine,
    jobs: ProofJobStore,
    access: Access,
    gate: SyntheticInspectGate,
    agreement: String,
    candidate: String,
    job: String,
}
impl Constructed {
    fn revision(&self) -> u64 {
        self.engine
            .get(&self.access, &self.agreement)
            .unwrap()
            .revision
    }
    fn queue(&self, key: &str) -> NativeProofRequestView {
        self.engine
            .queue_native_proof_reconciliation(
                &self.access,
                key,
                &self.agreement,
                self.revision(),
                NativeProofReconcileRequest {
                    candidate_id: self.candidate.clone(),
                    job_id: self.job.clone(),
                },
            )
            .unwrap()
    }
    fn status(&self, request: &str) -> NativeProofRequestView {
        self.engine
            .native_proof_request(&self.access, &self.agreement, request)
            .unwrap()
    }
    fn mark(&self, request: &str) -> NativeProofReconciliationAttempt {
        self.engine
            .mark_native_proof_reconciliation_attempt(&self.access, &self.agreement, request)
            .unwrap()
    }
    fn reconcile(&self, attempt: &NativeProofReconciliationAttempt) -> crate::Result<Mutation> {
        self.engine.reconcile_candidate_proof_job(
            &self.access,
            attempt.reconciliation_key(),
            attempt.candidate_id(),
            attempt.revision(),
            LocalProofJob {
                job_id: attempt.job_id(),
                jobs: &self.jobs,
                consent: &self.gate,
            },
        )
    }
    fn restart(&mut self) {
        self.engine = Engine::in_memory().unwrap();
        self.engine = Engine::from_store(
            Store::open_encrypted(
                self.dir.path().join("metadata.sqlite"),
                &DatabaseKey::from_bytes([81; 32]),
            )
            .unwrap(),
        );
    }
}
fn constructed(missing_link: bool) -> Constructed {
    constructed_named(missing_link, false).0
}
fn constructed_named(missing_link: bool, native: bool) -> (Constructed, Option<String>) {
    use std::os::unix::fs::PermissionsExt;
    let Fixture {
        agreement,
        request,
        chain,
        packages,
        account_ids,
    } = fixture();
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::from_store(
        Store::create_encrypted(
            dir.path().join("metadata.sqlite"),
            &DatabaseKey::from_bytes([81; 32]),
        )
        .unwrap(),
    );
    let jobs = ProofJobStore::from_encrypted_connection(
        create_encrypted(
            dir.path().join("proof.sqlite"),
            &DatabaseKey::from_bytes([82; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let access = Access {
        principal_id: "synthetic-controller".into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    engine
        .create(
            &access,
            "synthetic-proof-request-agreement",
            agreement.clone(),
        )
        .unwrap();
    for (i, p) in request.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &access,
                &format!("synthetic-proof-request-intent-{i}"),
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
            "synthetic-proof-request-candidate",
            &agreement.agreement_id,
            3,
            request,
        )
        .unwrap();
    let candidate = &frozen.agreement.candidates[0];
    let (construction_key, construction_revision, native_request) = if native {
        let queued = engine
            .queue_native_construction(
                &access,
                "synthetic-original-native-request",
                &agreement.agreement_id,
                frozen.agreement.revision,
                crate::native_requests::NativeConstructionRequest {
                    candidate_id: candidate.candidate_id.clone(),
                },
            )
            .unwrap();
        let attempt = engine
            .mark_native_construction_attempt(&access, &agreement.agreement_id, &queued.request_id)
            .unwrap();
        (
            attempt.construction_key().to_owned(),
            attempt.revision(),
            Some(queued.request_id),
        )
    } else {
        (
            "synthetic-proof-request-original-construction".to_owned(),
            frozen.agreement.revision,
            None,
        )
    };

    let declarations: Vec<_> = account_ids
        .iter()
        .map(|account| DisclosureAcknowledgement {
            account_id: account.clone(),
            manifest_digest: hex::decode(&candidate.manifest_digest)
                .unwrap()
                .try_into()
                .unwrap(),
            operator: "synthetic-local-constructor".into(),
            reviewer_account_ids: account_ids.clone(),
            purpose: "Synthetic request reconciliation qualification".into(),
            retention_policy: "Encrypted temporary directory only".into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    let mut gate = SyntheticInspectGate {
        candidate: candidate.candidate_id.clone(),
        manifest: candidate.manifest_digest.clone(),
        accounts: account_ids,
        allowed: AtomicBool::new(true),
        checks: AtomicUsize::new(0),
        race: missing_link.then(|| {
            (
                engine.clone(),
                access.clone(),
                agreement.agreement_id.clone(),
            )
        }),
    };
    let result = engine.checkpoint_candidate_locally(
        &access,
        &construction_key,
        &candidate.candidate_id,
        construction_revision,
        LocalCheckpoint {
            construction: LocalConstruction {
                context: chain,
                contributions: packages,
                declarations: &declarations,
            },
            jobs: &jobs,
            limits: ProvingLimits { maximum_actions: 8 },
            consent: &gate,
        },
    );
    if missing_link {
        let error = result.unwrap_err();
        assert_eq!(error.code, "REVISION_CONFLICT");
        assert_eq!(error.details["encrypted_checkpoint_created"], true);
        assert!(
            engine
                .get(&access, &agreement.agreement_id)
                .unwrap()
                .candidates[0]
                .proof_jobs
                .is_empty()
        );
    } else {
        assert_eq!(result.unwrap().agreement.candidates[0].proof_jobs.len(), 1);
    }
    gate.race = None;
    let job =
        wholepact_proof_jobs::job_id_for_key(&access.principal_id, &construction_key).unwrap();
    (
        Constructed {
            dir,
            engine,
            jobs,
            access,
            gate,
            agreement: agreement.agreement_id,
            candidate: candidate.candidate_id.clone(),
            job,
        },
        native_request,
    )
}

#[test]
fn actual_constructor_missing_cache_reconciles_exactly_and_allows_next_refresh() {
    let mut f = constructed(true);
    let original_receipts = serde_json::to_value(
        &f.engine
            .load(&f.access, &f.agreement)
            .unwrap()
            .checkpoint_receipts,
    )
    .unwrap();
    let empty = f.engine.store.get_agreement(&f.agreement).unwrap().unwrap();
    assert!(empty.payload.get("native_proof_requests").is_none());
    assert!(empty.payload.get("native_requests").is_none());
    let queued = f.queue("synthetic-first-proof-request");
    assert_eq!(queued.operation, "proof_reconcile");
    assert_eq!(queued.schema_version, 1);
    assert_eq!(queued.reconciliation_status, "not_attempted");
    assert_ne!(queued.receipt_storage_key, queued.job_id);
    assert!(candidates::valid_checkpoint_receipt_index(
        &queued.receipt_storage_key,
        &queued.job_id
    ));
    let attempt = f.mark(&queued.request_id);
    assert_eq!(attempt.reconciliation_key(), queued.reconciliation_key());
    assert_eq!(attempt.receipt_digest(), queued.receipt_digest);
    assert_eq!(attempt.receipt_storage_key(), queued.receipt_storage_key);
    assert_eq!(attempt.scope_digest(), queued.scope_digest);
    assert_eq!(
        attempt.coordination_request_digest(),
        queued.coordination_request_digest
    );
    f.restart(); // Crash before exact reconciliation cannot manufacture completion.
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "unknown"
    );
    f.gate.allowed.store(false, Ordering::SeqCst);
    assert_eq!(f.reconcile(&attempt).unwrap_err().code, "DISCLOSURE_DENIED");
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "unknown"
    );
    f.gate.allowed.store(true, Ordering::SeqCst);
    let observed = f
        .engine
        .candidate_proof_status(
            &f.access,
            &f.candidate,
            LocalProofJob {
                job_id: &f.job,
                jobs: &f.jobs,
                consent: &f.gate,
            },
        )
        .unwrap();
    assert!(!observed.proof_verified);
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "unknown"
    );
    let committed = f.reconcile(&attempt).unwrap();
    f.restart(); // Crash after exact durable reconciliation needs no completion write.
    let complete = f.status(&queued.request_id);
    assert_eq!(complete.state, NativeRequestState::AttemptStarted);
    assert_eq!(
        complete.reconciliation_status,
        "cached_reconciliation_recorded"
    );
    assert_eq!(
        complete.reconciliation_operation_id.as_deref(),
        Some(committed.operation_id.as_str())
    );
    assert!(!complete.authorization_allowed);
    assert_eq!(complete.result_status, "unknown_not_financial_evidence");
    assert_eq!(
        serde_json::to_value(
            &f.engine
                .load(&f.access, &f.agreement)
                .unwrap()
                .checkpoint_receipts
        )
        .unwrap(),
        original_receipts
    );
    let replay = f
        .engine
        .queue_native_proof_reconciliation(
            &f.access,
            "synthetic-first-proof-request",
            &f.agreement,
            queued.original_revision,
            NativeProofReconcileRequest {
                candidate_id: f.candidate.clone(),
                job_id: f.job.clone(),
            },
        )
        .unwrap();
    assert_eq!(replay.request_id, queued.request_id);
    assert_eq!(
        replay.reconciliation_operation_id,
        complete.reconciliation_operation_id
    );
    f.gate.allowed.store(false, Ordering::SeqCst);
    assert_eq!(f.reconcile(&attempt).unwrap_err().code, "DISCLOSURE_DENIED");
    // Cached completion is a past fact, not a grant of current native consent.
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "cached_reconciliation_recorded"
    );
    f.gate.allowed.store(true, Ordering::SeqCst);
    let next = f.queue("synthetic-next-proof-refresh");
    assert_ne!(next.request_id, queued.request_id);
    assert_eq!(next.reconciliation_status, "not_attempted");
    assert_eq!(
        f.engine
            .native_proof_requests(&f.access, &f.agreement)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        f.engine
            .get(&f.access, &f.agreement)
            .unwrap()
            .authorization_exposure,
        "unknown"
    );
}

#[test]
fn exact_receipt_and_all_request_bindings_fail_closed_when_altered() {
    let f = constructed(false);
    let queued = f.queue("synthetic-binding-proof-request");
    let envelope = f.engine.load(&f.access, &f.agreement).unwrap();
    let original = serde_json::to_value(&envelope).unwrap();
    for field in [
        "job_id",
        "scope_digest",
        "principal_id",
        "candidate_id",
        "manifest_digest",
        "coordination_request_digest",
        "artifact_digest",
        "review_binding",
        "effects_commitment",
        "prepared_revision",
    ] {
        let mut altered = original.clone();
        altered["checkpoint_receipts"][&queued.receipt_storage_key][field] =
            if field == "prepared_revision" {
                json!(0)
            } else {
                json!("42".repeat(32))
            };
        let altered: Envelope = serde_json::from_value(altered).unwrap();
        assert!(validate_stored(&altered).is_err(), "receipt field {field}");
    }
    for field in [
        "job_id",
        "scope_digest",
        "principal_id",
        "candidate_id",
        "manifest_digest",
        "coordination_request_digest",
        "receipt_storage_key",
        "receipt_digest",
    ] {
        let mut altered = original.clone();
        altered["native_proof_requests"][&queued.request_id][field] = json!("42".repeat(32));
        let altered: Envelope = serde_json::from_value(altered).unwrap();
        assert!(validate_stored(&altered).is_err(), "request field {field}");
    }
    let mut wrong_domain = envelope.clone();
    let receipt = wrong_domain
        .checkpoint_receipts
        .remove(&queued.receipt_storage_key)
        .unwrap();
    wrong_domain
        .checkpoint_receipts
        .insert(queued.job_id.clone(), receipt);
    wrong_domain
        .native_proof_requests
        .get_mut(&queued.request_id)
        .unwrap()
        .receipt_storage_key = queued.job_id;
    assert!(validate_stored(&wrong_domain).is_err());
}

#[test]
fn only_exact_command_result_completes_and_uncertain_attempt_cannot_be_replaced() {
    let f = constructed(false);
    let queued = f.queue("synthetic-unknown-proof-request");
    let attempt = f.mark(&queued.request_id);
    let unrelated = f
        .engine
        .reconcile_candidate_proof_job(
            &f.access,
            "synthetic-unrelated-reconciliation",
            &f.candidate,
            attempt.revision(),
            LocalProofJob {
                job_id: &f.job,
                jobs: &f.jobs,
                consent: &f.gate,
            },
        )
        .unwrap();
    assert_ne!(unrelated.operation_id, "");
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "unknown"
    );
    // Even a fake optimistic status in the cache is not completion evidence.
    let mut envelope = f.engine.load(&f.access, &f.agreement).unwrap();
    envelope.view.candidates[0].proof_jobs[0].state = "succeeded".into();
    envelope.view.candidates[0].proof_jobs[0].proof_verified = true;
    let command = context(
        &f.access,
        "synthetic-fake-cached-status",
        "synthetic_cache_only",
        &f.agreement,
        Some(envelope.view.revision),
        &json!({}),
    )
    .unwrap();
    f.engine
        .commit(
            &command,
            &f.agreement,
            envelope.view.revision,
            envelope,
            "synthetic_cache_only",
        )
        .unwrap();
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "unknown"
    );
    assert!(
        f.status(&queued.request_id)
            .reconciliation_operation_id
            .is_none()
    );
    assert_eq!(
        f.engine
            .queue_native_proof_reconciliation(
                &f.access,
                "synthetic-forbidden-refresh",
                &f.agreement,
                f.revision(),
                NativeProofReconcileRequest {
                    candidate_id: f.candidate.clone(),
                    job_id: f.job.clone()
                }
            )
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    assert!(
        f.engine
            .mark_native_proof_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
            .is_err()
    );
    assert!(
        f.engine
            .withdraw_native_proof_request(
                &f.access,
                "synthetic-forbidden-withdraw",
                &f.agreement,
                f.revision(),
                &queued.request_id
            )
            .is_err()
    );
}

#[test]
fn request_ownership_scope_revision_and_withdrawal_are_enforced() {
    let f = constructed(false);
    let queued = f.queue("synthetic-scope-proof-request");
    let hidden = Access {
        principal_id: f.access.principal_id.clone(),
        ..Access::default()
    };
    assert!(
        f.engine
            .native_proof_request(&hidden, &f.agreement, &queued.request_id)
            .is_err()
    );
    assert!(
        f.engine
            .queue_native_proof_reconciliation(
                &hidden,
                "synthetic-scope-proof-request",
                &f.agreement,
                queued.original_revision,
                NativeProofReconcileRequest {
                    candidate_id: f.candidate.clone(),
                    job_id: f.job.clone()
                }
            )
            .is_err()
    );
    let other = Access {
        principal_id: "other".into(),
        all_agreements: true,
        ..Access::default()
    };
    assert!(
        f.engine
            .native_proof_request(&other, &f.agreement, &queued.request_id)
            .is_err()
    );
    assert!(
        f.engine
            .native_proof_requests(&other, &f.agreement)
            .unwrap()
            .is_empty()
    );
    assert!(
        f.engine
            .mark_native_proof_reconciliation_attempt(&other, &f.agreement, &queued.request_id)
            .is_err()
    );
    let withdrawn = f
        .engine
        .withdraw_native_proof_request(
            &f.access,
            "synthetic-proof-withdraw-key",
            &f.agreement,
            f.revision(),
            &queued.request_id,
        )
        .unwrap();
    assert_eq!(withdrawn.state, NativeRequestState::Withdrawn);
    assert_eq!(withdrawn.reconciliation_status, "not_attempted");
    assert!(
        f.engine
            .mark_native_proof_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
            .is_err()
    );
    let replay = f
        .engine
        .withdraw_native_proof_request(
            &f.access,
            "synthetic-proof-withdraw-key",
            &f.agreement,
            queued.queued_revision,
            &queued.request_id,
        )
        .unwrap();
    assert_eq!(replay.state, NativeRequestState::Withdrawn);
    let next = f.queue("synthetic-new-proof-request");
    f.engine
        .review_candidate(
            &f.access,
            "synthetic-intervening-review",
            &f.candidate,
            f.revision(),
        )
        .unwrap();
    assert_eq!(
        f.engine
            .mark_native_proof_reconciliation_attempt(&f.access, &f.agreement, &next.request_id)
            .err()
            .unwrap()
            .code,
        "REVISION_CONFLICT"
    );
    assert_eq!(f.status(&next.request_id).state, NativeRequestState::Queued);
}

#[test]
fn construction_and_proof_requests_share_one_lifetime_quota() {
    use crate::native_requests::{MAX_NATIVE_REQUESTS, NativeConstructionRequest};
    let f = constructed(false);
    for i in 0..MAX_NATIVE_REQUESTS {
        if i % 2 == 0 {
            let queued = f.queue(&format!("synthetic-proof-quota-{i:04}"));
            f.engine
                .withdraw_native_proof_request(
                    &f.access,
                    &format!("synthetic-proof-withdraw-{i:04}"),
                    &f.agreement,
                    f.revision(),
                    &queued.request_id,
                )
                .unwrap();
        } else {
            let queued = f
                .engine
                .queue_native_construction(
                    &f.access,
                    &format!("synthetic-construction-quota-{i:04}"),
                    &f.agreement,
                    f.revision(),
                    NativeConstructionRequest {
                        candidate_id: f.candidate.clone(),
                    },
                )
                .unwrap();
            f.engine
                .withdraw_native_request(
                    &f.access,
                    &format!("synthetic-construction-withdraw-{i:04}"),
                    &f.agreement,
                    f.revision(),
                    &queued.request_id,
                )
                .unwrap();
        }
    }
    assert_eq!(
        f.engine
            .native_proof_requests(&f.access, &f.agreement)
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        f.engine
            .native_requests(&f.access, &f.agreement)
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        f.engine
            .queue_native_proof_reconciliation(
                &f.access,
                "synthetic-proof-over-quota",
                &f.agreement,
                f.revision(),
                NativeProofReconcileRequest {
                    candidate_id: f.candidate.clone(),
                    job_id: f.job.clone()
                }
            )
            .unwrap_err()
            .code,
        "RESOURCE_EXHAUSTED"
    );
    assert_eq!(
        f.engine
            .queue_native_construction(
                &f.access,
                "synthetic-construction-over-quota",
                &f.agreement,
                f.revision(),
                NativeConstructionRequest {
                    candidate_id: f.candidate.clone()
                }
            )
            .unwrap_err()
            .code,
        "RESOURCE_EXHAUSTED"
    );
}

#[test]
fn concurrent_exact_native_starts_return_only_one_inert_attempt() {
    let f = constructed(false);
    let queued = f.queue("synthetic-concurrent-proof-request");
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let engine = f.engine.clone();
            let access = f.access.clone();
            let agreement = f.agreement.clone();
            let request = queued.request_id.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                engine
                    .mark_native_proof_reconciliation_attempt(&access, &agreement, &request)
                    .is_ok()
            })
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| usize::from(worker.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "unknown"
    );
}

#[test]
fn cancellation_does_not_prevent_informational_reconciliation() {
    let f = constructed(false);
    f.engine
        .cancel(
            &f.access,
            "synthetic-cancel-before-status",
            &f.agreement,
            f.revision(),
        )
        .unwrap();
    let queued = f.queue("synthetic-cancelled-status-request");
    let attempt = f.mark(&queued.request_id);
    f.reconcile(&attempt).unwrap();
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "cached_reconciliation_recorded"
    );
    assert!(
        f.engine
            .get(&f.access, &f.agreement)
            .unwrap()
            .cancellation_requested
    );
}

#[test]
fn proof_request_backup_preserves_receipt_and_historical_requests_without_activation() {
    use std::collections::BTreeMap;
    use wholepact_storage_security::bundle::*;
    struct BackupGate;
    impl BundleLease for BackupGate {
        fn check_current(&self) -> std::result::Result<(), BundleError> {
            Ok(())
        }
        fn checkpoint_id(&self) -> &str {
            "synthetic-stopped-request-writer"
        }
    }
    impl BundleAuthority for BackupGate {
        fn acquire<'a>(
            &'a self,
            scope: &BundleScope<'_>,
        ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
            if scope.principal_id != "synthetic-admin" || scope.profile_id != "synthetic-profile" {
                return Err(BundleError::Permission);
            }
            Ok(Box::new(BackupGate))
        }
    }
    let f = constructed(false);
    let queued = f.queue("synthetic-backup-proof-request");
    let attempt = f.mark(&queued.request_id);
    let committed = f.reconcile(&attempt).unwrap();
    let before = f.engine.store.get_agreement(&f.agreement).unwrap().unwrap();
    let adapter = wholepact_store::bundle::CoordinationBundleAdapter::new(&f.engine.store).unwrap();
    let sources = [RegisteredJournal::new("coordination", &adapter).unwrap()];
    let archive = f.dir.path().join("archive");
    let key = DatabaseKey::from_bytes([81; 32]);
    snapshot(SnapshotRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        sources: &sources,
        destination: &archive,
        key: &key,
        authority: &BackupGate,
        coverage: Coverage {
            present: BTreeMap::from([(
                JournalKind::CoordinationAuthority,
                vec!["coordination".into()],
            )]),
            absent: [
                JournalKind::SignerConsentAuthority,
                JournalKind::WalletScan,
                JournalKind::ProofWitness,
                JournalKind::SignedResults,
                JournalKind::ExactTransactions,
                JournalKind::Submission,
                JournalKind::TransportInbox,
                JournalKind::TransportOutbox,
            ]
            .into(),
        },
    })
    .unwrap();
    let restored = f.dir.path().join("restored");
    test_restore(RestoreRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        archive: &archive,
        key: &key,
        targets: &[RestoreTarget {
            component_id: "coordination",
            template: wholepact_store::bundle::coordination_template(),
            destination: &restored,
            key: &key,
        }],
        authority: &BackupGate,
    })
    .unwrap();
    assert!(Store::open_encrypted(&restored, &key).is_err());
    let source = wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent::open(
        wholepact_storage_security::bundle::history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &key,
            component_id: "coordination",
            restored_component: &restored,
            restored_key: &key,
        },
        wholepact_store::bundle::coordination_template(),
    )
    .unwrap();
    let inventory = crate::recovery::inspect_coordination_recovery(&source).unwrap();
    let latest = inventory
        .store_inventory()
        .agreements()
        .iter()
        .find(|record| record.id == f.agreement)
        .unwrap();
    assert_eq!(
        latest.payload["checkpoint_receipts"],
        before.payload["checkpoint_receipts"]
    );
    assert_eq!(
        latest.payload["native_proof_requests"],
        before.payload["native_proof_requests"]
    );
    assert!(
        inventory
            .store_inventory()
            .historical_agreements()
            .iter()
            .any(
                |record| record.payload["native_proof_requests"][&queued.request_id]["state"]
                    == "queued"
            )
    );
    assert_eq!(
        f.status(&queued.request_id)
            .reconciliation_operation_id
            .as_deref(),
        Some(committed.operation_id.as_str())
    );
    assert!(Store::open_encrypted(&restored, &key).is_err());
}

#[test]
fn original_metadata_retry_recovers_exact_inputs_without_resetting_fence() {
    let mut f = constructed(false);
    let queued = f.queue("synthetic-original-metadata-retry");
    assert!(
        f.engine
            .original_native_proof_reconciliation_attempt(
                &f.access,
                &f.agreement,
                &queued.request_id
            )
            .is_err()
    );
    let first = f.mark(&queued.request_id);
    f.restart();
    let before = f
        .engine
        .store
        .get_agreement(&f.agreement)
        .unwrap()
        .unwrap()
        .payload;
    let restored = f
        .engine
        .original_native_proof_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
        .unwrap();
    assert_eq!(first.reconciliation_key(), restored.reconciliation_key());
    assert_eq!(first.revision(), restored.revision());
    assert_eq!(first.receipt_digest(), restored.receipt_digest());
    assert_eq!(
        before,
        f.engine
            .store
            .get_agreement(&f.agreement)
            .unwrap()
            .unwrap()
            .payload
    );
    assert!(
        f.engine
            .mark_native_proof_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
            .is_err()
    );
    f.gate.allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        f.reconcile(&restored).unwrap_err().code,
        "DISCLOSURE_DENIED"
    );
    f.gate.allowed.store(true, Ordering::SeqCst);
    let completed = f.reconcile(&restored).unwrap();
    let same = f
        .engine
        .original_native_proof_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
        .unwrap();
    assert_eq!(
        f.reconcile(&same).unwrap().operation_id,
        completed.operation_id
    );
    f.gate.allowed.store(false, Ordering::SeqCst);
    assert_eq!(f.reconcile(&same).unwrap_err().code, "DISCLOSURE_DENIED");
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "cached_reconciliation_recorded"
    );
}

#[test]
fn unknown_original_metadata_retry_rejects_changed_revision_and_wrong_owner() {
    let f = constructed(false);
    let queued = f.queue("synthetic-original-stale-retry");
    let attempt = f.mark(&queued.request_id);
    let other = Access {
        principal_id: "other".into(),
        all_agreements: true,
        ..Access::default()
    };
    assert!(
        f.engine
            .original_native_proof_reconciliation_attempt(&other, &f.agreement, &queued.request_id)
            .is_err()
    );
    f.engine
        .reconcile_candidate_proof_job(
            &f.access,
            "synthetic-unrelated-refresh",
            &f.candidate,
            attempt.revision(),
            LocalProofJob {
                job_id: &f.job,
                jobs: &f.jobs,
                consent: &f.gate,
            },
        )
        .unwrap();
    assert_eq!(
        f.engine
            .original_native_proof_reconciliation_attempt(
                &f.access,
                &f.agreement,
                &queued.request_id
            )
            .err()
            .unwrap()
            .code,
        "REVISION_CONFLICT"
    );
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "unknown"
    );
}

#[test]
fn original_native_constructor_evidence_uses_actual_inserted_receipt_without_rekey() {
    for missing_link in [false, true] {
        let (mut f, request) = constructed_named(missing_link, true);
        let request = request.unwrap();
        f.restart();
        let before = f
            .engine
            .store
            .get_agreement(&f.agreement)
            .unwrap()
            .unwrap()
            .payload;
        let evidence = f
            .engine
            .original_native_construction_checkpoint(&f.access, &f.agreement, &request)
            .unwrap();
        assert_eq!(evidence.expected_job_id, f.job);
        assert_ne!(evidence.expected_job_id, evidence.receipt_storage_key);
        assert_eq!(evidence.private_work_before_receipt, "unknown");
        assert!(!evidence.retry_construction_allowed);
        assert!(evidence.receipt_digest.is_some());
        assert_eq!(evidence.original_operation_id.is_some(), !missing_link);
        assert_eq!(
            before,
            f.engine
                .store
                .get_agreement(&f.agreement)
                .unwrap()
                .unwrap()
                .payload
        );
        assert!(
            f.engine
                .mark_native_construction_attempt(&f.access, &f.agreement, &request)
                .is_err()
        );
    }
}

#[test]
fn original_constructor_without_receipt_cannot_infer_no_private_work() {
    let f = constructed(false);
    let queued = f
        .engine
        .queue_native_construction(
            &f.access,
            "synthetic-no-receipt-native",
            &f.agreement,
            f.revision(),
            crate::native_requests::NativeConstructionRequest {
                candidate_id: f.candidate.clone(),
            },
        )
        .unwrap();
    f.engine
        .mark_native_construction_attempt(&f.access, &f.agreement, &queued.request_id)
        .unwrap();
    let evidence = f
        .engine
        .original_native_construction_checkpoint(&f.access, &f.agreement, &queued.request_id)
        .unwrap();
    assert_eq!(
        evidence.checkpoint_evidence,
        "no_constructor_receipt_observed"
    );
    assert_eq!(evidence.private_work_before_receipt, "unknown");
    assert!(!evidence.retry_construction_allowed);
    assert!(evidence.original_operation_id.is_none());
    assert!(evidence.receipt_digest.is_none());
}

#[test]
fn concurrent_original_metadata_retries_share_one_exact_durable_operation() {
    let f = constructed(false);
    let queued = f.queue("synthetic-concurrent-original-metadata");
    f.mark(&queued.request_id);
    let before = f.revision();
    let barrier = std::sync::Barrier::new(4);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let attempt = f
                        .engine
                        .original_native_proof_reconciliation_attempt(
                            &f.access,
                            &f.agreement,
                            &queued.request_id,
                        )
                        .unwrap();
                    barrier.wait();
                    f.reconcile(&attempt).unwrap().operation_id
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(results.iter().all(|id| id == &results[0]));
    assert_eq!(f.revision(), before + 1);
    assert_eq!(
        f.status(&queued.request_id).reconciliation_status,
        "cached_reconciliation_recorded"
    );
    assert!(
        f.engine
            .mark_native_proof_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
            .is_err()
    );
}

#[test]
fn original_constructor_rejects_substituted_receipt_and_unrelated_completion() {
    let (f, request) = constructed_named(false, true);
    let request = request.unwrap();
    let evidence = f
        .engine
        .original_native_construction_checkpoint(&f.access, &f.agreement, &request)
        .unwrap();
    let mut envelope = f.engine.load(&f.access, &f.agreement).unwrap();
    envelope
        .checkpoint_receipts
        .get_mut(&evidence.receipt_storage_key)
        .unwrap()
        .scope_digest = "ab".repeat(32);
    let revision = envelope.view.revision;
    let command = context(
        &f.access,
        "synthetic-receipt-substitution",
        "synthetic_corrupt_receipt",
        &f.agreement,
        Some(revision),
        &json!({}),
    )
    .unwrap();
    f.engine
        .commit(
            &command,
            &f.agreement,
            revision,
            envelope,
            "synthetic_corrupt_receipt",
        )
        .unwrap();
    assert_eq!(
        f.engine
            .original_native_construction_checkpoint(&f.access, &f.agreement, &request)
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );

    let (f, request) = constructed_named(true, true);
    let request = request.unwrap();
    let evidence = f
        .engine
        .original_native_construction_checkpoint(&f.access, &f.agreement, &request)
        .unwrap();
    let envelope = f.engine.load(&f.access, &f.agreement).unwrap();
    let revision = envelope.view.revision;
    let unrelated = CommandContext {
        principal_id: f.access.principal_id.clone(),
        idempotency_key: evidence.construction_key,
        request_digest: evidence.coordination_request_digest.unwrap(),
    };
    f.engine
        .commit(
            &unrelated,
            &f.agreement,
            revision,
            envelope,
            "synthetic_unrelated_operation",
        )
        .unwrap();
    assert_eq!(
        f.engine
            .original_native_construction_checkpoint(&f.access, &f.agreement, &request)
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
}
