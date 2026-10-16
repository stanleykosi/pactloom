#![cfg(target_os = "linux")]
//! Synthetic evidence/authority adapters over actual SQLCipher engine storage.
//! No real signer, wallet, payment, chain proof or production enrollment is used.
use std::sync::atomic::{AtomicBool, Ordering};
use wholepact_core::disclosure::*;
use wholepact_core::records::*;
use wholepact_core::retirement::*;
use wholepact_core::*;
use wholepact_engine::participant_records::*;
use wholepact_engine::{Access, ApiError, CandidateRequest, Engine};
use wholepact_storage_security::DatabaseKey;
use wholepact_store::Store;
use wholepact_store::authority::ReleaseIntent;

fn private_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn hash(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}
fn owner() -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: "synthetic-owner".into(),
        all_agreements: true,
        ..Access::default()
    }
}
fn window() -> ObservationWindow {
    ObservationWindow {
        now: "2026-10-14T14:00:00Z".into(),
        oldest_acceptable: "2026-10-14T13:55:00Z".into(),
    }
}
fn policy() -> ObservationPolicy {
    ObservationPolicy {
        source_id: "synthetic-chain".into(),
        trust_profile_id: "synthetic-unqualified".into(),
        adapter_id: "synthetic-chain-adapter".into(),
    }
}
fn candidate_request() -> CandidateRequest {
    let mut agreement: AgreementDraft = parse_typed_json(include_bytes!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    agreement.network_profile_id = wholepact_engine::candidates::PROFILE_ID.into();
    agreement.recipients[0].amount = amount(1000);
    agreement.funding_policy = FundingPolicy::Exact {
        target: amount(1000),
    };
    let participants: Vec<_> = [("alice", 400, 4), ("bob", 600, 6)]
        .into_iter()
        .map(|(name, contribution, fee)| ParticipantAllocation {
            participant_id: name.into(),
            account_id: format!("account-{name}"),
            contribution: amount(contribution),
            fee_share: amount(fee),
            fee_cap: amount(fee),
            maximum_net_debit: amount(contribution + fee),
            charges: vec![],
        })
        .collect();
    let inputs = participants
        .iter()
        .map(|p| ClaimedInput {
            input_id: format!("input-{}", p.participant_id),
            participant_id: p.participant_id.clone(),
            account_id: p.account_id.clone(),
            amount: p.maximum_net_debit,
            ownership_evidence_ref: None,
        })
        .collect();
    CandidateRequest {
        manifest: ProposalManifest {
            outputs: vec![ClaimedOutput {
                output_id: "recipient-output".into(),
                address: agreement.recipients[0].address.clone(),
                amount: amount(1000),
                allocation: OutputAllocation::Recipient {
                    recipient_id: agreement.recipients[0].recipient_id.clone(),
                },
            }],
            agreement,
            participants,
            inputs,
            transaction_fee: amount(10),
            expiry_height: 4_465_070,
        },
        previous_candidate_id: None,
    }
}
fn setup_candidate(engine: &Engine) -> (String, String, u64) {
    setup_candidate_request(engine, candidate_request())
}
fn setup_candidate_request(engine: &Engine, request: CandidateRequest) -> (String, String, u64) {
    let id = request.manifest.agreement.agreement_id.clone();
    engine
        .create(
            &owner(),
            "record-create-agreement",
            request.manifest.agreement.clone(),
        )
        .unwrap();
    for (i, participant) in request.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &owner(),
                &format!("record-intent-{i:04}"),
                &id,
                i as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("intent-{i}"),
                    agreement_id: id.clone(),
                    participant_id: participant.participant_id.clone(),
                    desired_contribution: participant.contribution,
                    maximum_net_debit: participant.maximum_net_debit,
                    fee_cap: participant.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            )
            .unwrap();
    }
    let result = engine
        .create_candidate(&owner(), "record-candidate-create", &id, 3, request)
        .unwrap();
    (
        id,
        result.agreement.candidates[0].candidate_id.clone(),
        result.agreement.revision,
    )
}
struct SyntheticAuthority {
    binding: RecordStoreBinding,
    revoked: AtomicBool,
}
impl SyntheticAuthority {
    fn for_engine(engine: &Engine) -> Self {
        Self {
            binding: engine.protected_record_store_binding().unwrap(),
            revoked: AtomicBool::new(false),
        }
    }
    fn runtime<'a>(&'a self, window: &'a ObservationWindow) -> ParticipantRecordRuntime<'a> {
        ParticipantRecordRuntime {
            profile_id: "synthetic-local-profile",
            authority: self,
            window,
        }
    }
}
struct SyntheticLease<'a> {
    scope: ParticipantRecordScope,
    authority: &'a SyntheticAuthority,
}
impl ParticipantRecordLease for SyntheticLease<'_> {
    fn scope(&self) -> &ParticipantRecordScope {
        &self.scope
    }
    fn expires_at(&self) -> &str {
        "2026-10-15T14:00:00Z"
    }
    fn check_current(&self) -> wholepact_engine::Result<()> {
        if self.authority.revoked.load(Ordering::SeqCst) {
            Err(ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic runtime lease revoked",
            ))
        } else {
            Ok(())
        }
    }
}
impl ParticipantRecordAuthority for SyntheticAuthority {
    fn acquire<'a>(
        &'a self,
        scope: &ParticipantRecordScope,
        _: &ObservationWindow,
    ) -> wholepact_engine::Result<Box<dyn ParticipantRecordLease + 'a>> {
        if scope.store != self.binding
            || scope.profile_id != "synthetic-local-profile"
            || scope.principal_id != "synthetic-owner"
            || scope.account_id != "account-alice"
            || scope.participant_id != "alice"
        {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic authority scope mismatch",
            ));
        }
        Ok(Box::new(SyntheticLease {
            scope: scope.clone(),
            authority: self,
        }))
    }
}
#[derive(Default)]
struct SyntheticRetainedSource {
    loads: usize,
    substituted_terms: bool,
}
impl RetainedParticipantRecordSource for SyntheticRetainedSource {
    fn source_id(&self) -> &str {
        "synthetic-retained-journals"
    }
    fn load_retained_record(
        &mut self,
        request: &RetainParticipantRecordRequest,
        candidate: &Proposal,
    ) -> wholepact_engine::Result<SettlementRecord> {
        self.loads += 1;
        let mut approved = candidate.input().clone();
        approved.artifact_digest = Some(hash(1));
        approved.effects_commitment = Some(hash(2));
        if self.substituted_terms {
            approved.manifest.agreement.purpose = "Substituted terms".into();
        }
        let approved = Proposal::validate(approved)?;
        let own = OwnAuthorizationRecord {
            participant_id: request.participant_id.clone(),
            account_id: request.account_id.clone(),
            proposal_digest: approved.proposal_digest().into(),
            manifest_digest: approved.manifest_digest().into(),
            effects_commitment: hash(2),
            consent_record_ref: "PRIVATE-SYNTHETIC-OWN-CONSENT-SENTINEL".into(),
            authorization_record_ref: "PRIVATE-SYNTHETIC-OWN-AUTH-SENTINEL".into(),
            release_operation_id: Some("synthetic-private-release".into()),
            exposure: AuthorizationExposure::Released,
        };
        let transaction = ExactTransactionReference {
            network_profile_id: approved.manifest().agreement.network_profile_id.clone(),
            transaction_id: hash(3),
            transaction_bytes_digest: hash(4),
            effects_commitment: hash(2),
        };
        Ok(SettlementRecord::new(
            request.record_id.clone(),
            approved,
            own,
            transaction,
        )?)
    }
}
fn retention_request(candidate_id: &str) -> RetainParticipantRecordRequest {
    RetainParticipantRecordRequest {
        record_id: "private-record-alice".into(),
        candidate_id: candidate_id.into(),
        participant_id: "alice".into(),
        account_id: "account-alice".into(),
    }
}
fn retain(
    engine: &Engine,
    authority: &SyntheticAuthority,
    id: &str,
    candidate_id: &str,
    revision: u64,
) -> ParticipantRecordMutation {
    engine
        .retain_participant_record(
            &owner(),
            "retain-record-alice-0001",
            id,
            revision,
            retention_request(candidate_id),
            authority.runtime(&window()),
            &mut SyntheticRetainedSource::default(),
        )
        .unwrap()
}
struct SyntheticChain {
    status: ChainStatus,
    second: u8,
}
impl SettlementObservationSource for SyntheticChain {
    fn observe_exact_transaction(
        &mut self,
        transaction: &ExactTransactionReference,
    ) -> wholepact_core::Result<SourcedChainObservation> {
        let included = matches!(
            self.status,
            ChainStatus::Included | ChainStatus::ConfirmationPolicyMet
        );
        Ok(SourcedChainObservation {
            transaction: transaction.clone(),
            adapter_id: policy().adapter_id,
            observation: ChainObservation {
                observation_id: format!("source-observation-{}", self.second),
                source_id: policy().source_id,
                trust_profile_id: policy().trust_profile_id,
                observed_at: format!("2026-10-14T13:59:{:02}Z", self.second),
                tip_height: 4_465_069,
                tip_hash: hash(5),
                synchronized: true,
                status: self.status,
                inclusion_height: included.then_some(4_465_060),
                inclusion_hash: included.then(|| hash(6)),
                confirmations: if included { 10 } else { 0 },
                evidence_ref: "synthetic-inclusion-evidence".into(),
            },
        })
    }
}
fn observe_request(record_revision: u64) -> ObserveParticipantRecordRequest {
    ObserveParticipantRecordRequest {
        record_id: "private-record-alice".into(),
        expected_record_revision: record_revision,
        policy: policy(),
    }
}

#[test]
fn encrypted_record_retention_is_idempotent_scoped_and_absent_from_ordinary_responses() {
    let dir = private_directory();
    let path = dir.path().join("records.sqlite");
    let key = DatabaseKey::from_bytes([91; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
    let (id, candidate, revision) = setup_candidate(&engine);
    let authority = SyntheticAuthority::for_engine(&engine);
    let mut source = SyntheticRetainedSource::default();
    let first = engine
        .retain_participant_record(
            &owner(),
            "retain-record-alice-0001",
            &id,
            revision,
            retention_request(&candidate),
            authority.runtime(&window()),
            &mut source,
        )
        .unwrap();
    let replay = engine
        .retain_participant_record(
            &owner(),
            "retain-record-alice-0001",
            &id,
            revision,
            retention_request(&candidate),
            authority.runtime(&window()),
            &mut source,
        )
        .unwrap();
    assert_eq!(source.loads, 1);
    assert!(replay.replayed);
    assert_eq!(first.operation_id, replay.operation_id);
    assert_eq!(first.record.record_revision, 1);
    let status = engine
        .participant_record_status(&owner(), Some(authority.runtime(&window())))
        .unwrap();
    assert_eq!(status.status, "available");
    assert_eq!(status.records.as_ref().unwrap().len(), 1);
    assert_eq!(
        status.records.as_ref().unwrap()[0].confidence,
        RecordConfidence::NoObservation
    );
    let no_runtime = engine.participant_record_status(&owner(), None).unwrap();
    assert_eq!(no_runtime.status, "unavailable");
    assert!(no_runtime.records.is_none());
    let ordinary = [
        serde_json::to_string(&engine.get(&owner(), &id).unwrap()).unwrap(),
        engine
            .operation(&owner(), &first.operation_id)
            .unwrap()
            .to_string(),
        engine.events(&owner(), 0, 100).unwrap().to_string(),
        serde_json::to_string(&status).unwrap(),
    ];
    for text in ordinary {
        assert!(!text.contains("PRIVATE-SYNTHETIC"));
        assert!(!text.contains("participant_records"));
    }
    let outsider = Access {
        include_owned_agreements: true,
        principal_id: "other-app".into(),
        all_agreements: true,
        ..Access::default()
    };
    assert_eq!(
        engine
            .read_participant_record(
                &outsider,
                &id,
                "private-record-alice",
                authority.runtime(&window())
            )
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );
    assert!(
        engine
            .participant_record_status(&outsider, Some(authority.runtime(&window())))
            .unwrap()
            .records
            .unwrap()
            .is_empty()
    );
    authority.revoked.store(true, Ordering::SeqCst);
    assert_eq!(
        engine
            .retain_participant_record(
                &owner(),
                "retain-record-alice-0001",
                &id,
                revision,
                retention_request(&candidate),
                authority.runtime(&window()),
                &mut source
            )
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
    assert_eq!(source.loads, 1);
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        !bytes
            .windows(b"PRIVATE-SYNTHETIC".len())
            .any(|w| w == b"PRIVATE-SYNTHETIC")
    );
}

#[test]
fn plaintext_and_substituted_sources_are_blocked_without_creating_a_record() {
    let engine = Engine::in_memory().unwrap();
    let (id, candidate, revision) = setup_candidate(&engine);
    assert_eq!(
        engine.protected_record_store_binding().unwrap_err().code,
        "STORAGE_PROTECTION_REQUIRED"
    );
    let dir = private_directory();
    let key = DatabaseKey::from_bytes([92; 32]);
    let encrypted = Engine::from_store(
        Store::create_encrypted(dir.path().join("protected.sqlite"), &key).unwrap(),
    );
    let authority = SyntheticAuthority::for_engine(&encrypted);
    let mut source = SyntheticRetainedSource::default();
    assert_eq!(
        engine
            .retain_participant_record(
                &owner(),
                "reject-plaintext-record",
                &id,
                revision,
                retention_request(&candidate),
                authority.runtime(&window()),
                &mut source
            )
            .unwrap_err()
            .code,
        "STORAGE_PROTECTION_REQUIRED"
    );
    assert_eq!(source.loads, 0);
    let (id, candidate, revision) = setup_candidate(&encrypted);
    source.substituted_terms = true;
    assert_eq!(
        encrypted
            .retain_participant_record(
                &owner(),
                "reject-substitute-record",
                &id,
                revision,
                retention_request(&candidate),
                authority.runtime(&window()),
                &mut source
            )
            .unwrap_err()
            .code,
        "RECORD_SOURCE_REJECTED"
    );
    assert_eq!(encrypted.get(&owner(), &id).unwrap().revision, revision);
}

#[test]
fn record_observations_use_cas_and_survive_restart_without_stale_success_or_old_leases() {
    let dir = private_directory();
    let path = dir.path().join("record-restart.sqlite");
    let key = DatabaseKey::from_bytes([93; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
    let (id, candidate, revision) = setup_candidate(&engine);
    let authority = SyntheticAuthority::for_engine(&engine);
    let retained = retain(&engine, &authority, &id, &candidate, revision);
    let request = observe_request(1);
    let observed = engine
        .observe_participant_record(
            &owner(),
            "record-observe-inclusion",
            &id,
            retained.agreement_revision,
            request.clone(),
            authority.runtime(&window()),
            &mut SyntheticChain {
                status: ChainStatus::ConfirmationPolicyMet,
                second: 1,
            },
        )
        .unwrap();
    assert_eq!(
        observed.record.confidence,
        RecordConfidence::ConfirmationPolicyMet
    );
    assert_eq!(observed.record.record_revision, 2);
    assert_eq!(
        engine
            .observe_participant_record(
                &owner(),
                "record-observe-stale-cas",
                &id,
                observed.agreement_revision,
                observe_request(1),
                authority.runtime(&window()),
                &mut SyntheticChain {
                    status: ChainStatus::PendingObserved,
                    second: 2
                }
            )
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    let replay = engine
        .observe_participant_record(
            &owner(),
            "record-observe-inclusion",
            &id,
            retained.agreement_revision,
            request,
            authority.runtime(&window()),
            &mut SyntheticChain {
                status: ChainStatus::Reorganized,
                second: 2,
            },
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, observed.operation_id);
    assert_eq!(
        replay.record.confidence,
        RecordConfidence::ConfirmationPolicyMet
    );
    drop(engine);
    let restarted = Engine::from_store(Store::open_encrypted(&path, &key).unwrap());
    assert_eq!(
        restarted
            .read_participant_record(
                &owner(),
                &id,
                "private-record-alice",
                authority.runtime(&window())
            )
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
    let new_authority = SyntheticAuthority::for_engine(&restarted);
    let stale_window = ObservationWindow {
        now: "2026-10-14T15:00:00Z".into(),
        oldest_acceptable: "2026-10-14T14:55:00Z".into(),
    };
    let status = restarted
        .participant_record_status(&owner(), Some(new_authority.runtime(&stale_window)))
        .unwrap();
    assert_eq!(
        status.records.unwrap()[0].confidence,
        RecordConfidence::Stale
    );
    let reorg = restarted
        .observe_participant_record(
            &owner(),
            "record-observe-real-reorg",
            &id,
            observed.agreement_revision,
            observe_request(2),
            new_authority.runtime(&window()),
            &mut SyntheticChain {
                status: ChainStatus::Reorganized,
                second: 3,
            },
        )
        .unwrap();
    assert!(reorg.record.recovery_required);
    assert_eq!(reorg.record.confidence, RecordConfidence::Reorganized);
    let old_inclusion_replay = restarted
        .observe_participant_record(
            &owner(),
            "record-observe-inclusion",
            &id,
            retained.agreement_revision,
            observe_request(1),
            new_authority.runtime(&window()),
            &mut SyntheticChain {
                status: ChainStatus::ConfirmationPolicyMet,
                second: 4,
            },
        )
        .unwrap();
    assert!(old_inclusion_replay.replayed);
    assert_eq!(old_inclusion_replay.operation_id, observed.operation_id);
    assert_eq!(old_inclusion_replay.event_sequence, observed.event_sequence);
    assert_eq!(
        old_inclusion_replay.agreement_revision,
        reorg.agreement_revision
    );
    assert_eq!(
        old_inclusion_replay.record.record_revision,
        reorg.record.record_revision
    );
    assert_eq!(
        old_inclusion_replay.record.confidence,
        RecordConfidence::Reorganized
    );
    assert!(old_inclusion_replay.record.recovery_required);
    assert!(
        restarted
            .events(&owner(), 0, 100)
            .unwrap()
            .to_string()
            .contains("participant_record_reconciliation_required")
    );
}

fn disclosure_request() -> PreviewParticipantDisclosureRequest {
    PreviewParticipantDisclosureRequest {
        record_id: "private-record-alice".into(),
        expected_record_revision: 1,
        preview_id: "amount-only-preview".into(),
        selection: DisclosureSelection {
            fields: vec![DisclosureField::RecipientAmount],
            payment_recipient_id: Some("recipient-example".into()),
            destination: DisclosureDestination {
                recipient_id: "selected-reviewer".into(),
                destination: "reviewer-selected-file".into(),
                audience: DisclosureAudience::NamedPrivateRecipient,
            },
            purpose: "Only the approved amount".into(),
            persistence: "Recipient may retain the selected file".into(),
        },
        method: DisclosureMethod::PrivateReceipt,
    }
}
#[test]
fn exact_selected_preview_persists_without_implicit_disclosure_and_invalidates_after_observation() {
    let dir = private_directory();
    let path = dir.path().join("disclosure.sqlite");
    let key = DatabaseKey::from_bytes([94; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
    let (id, candidate, revision) = setup_candidate(&engine);
    let authority = SyntheticAuthority::for_engine(&engine);
    let retained = retain(&engine, &authority, &id, &candidate, revision);
    let request = disclosure_request();
    let prepared = engine
        .preview_participant_disclosure(
            &owner(),
            "prepare-selected-preview",
            &id,
            retained.agreement_revision,
            request.clone(),
            authority.runtime(&window()),
        )
        .unwrap();
    let preview = engine
        .read_participant_disclosure_preview(
            &owner(),
            &id,
            "private-record-alice",
            "amount-only-preview",
            authority.runtime(&window()),
        )
        .unwrap();
    let digest = preview.digest().to_string();
    let selected = serde_json::to_string(preview.receipt()).unwrap();
    for excluded in [
        "account-alice",
        "PRIVATE-SYNTHETIC",
        "agreement-example",
        "input-alice",
        "uregtest",
    ] {
        assert!(!selected.contains(excluded));
    }
    assert_eq!(
        preview.receipt().facts,
        vec![DisclosedFact::RecipientAmount(amount(1000))]
    );
    let replay = engine
        .preview_participant_disclosure(
            &owner(),
            "prepare-selected-preview",
            &id,
            retained.agreement_revision,
            request.clone(),
            authority.runtime(&window()),
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, prepared.operation_id);
    let mut changed = request;
    changed.selection.destination.destination = "different-reviewer".into();
    assert_eq!(
        engine
            .preview_participant_disclosure(
                &owner(),
                "prepare-selected-preview",
                &id,
                retained.agreement_revision,
                changed,
                authority.runtime(&window())
            )
            .unwrap_err()
            .code,
        "IDEMPOTENCY_CONFLICT"
    );
    drop(engine);
    let restarted = Engine::from_store(Store::open_encrypted(&path, &key).unwrap());
    let authority = SyntheticAuthority::for_engine(&restarted);
    assert_eq!(
        restarted
            .read_participant_disclosure_preview(
                &owner(),
                &id,
                "private-record-alice",
                "amount-only-preview",
                authority.runtime(&window())
            )
            .unwrap()
            .digest(),
        digest
    );
    restarted
        .observe_participant_record(
            &owner(),
            "invalidate-preview-observation",
            &id,
            prepared.agreement_revision,
            observe_request(1),
            authority.runtime(&window()),
            &mut SyntheticChain {
                status: ChainStatus::PendingObserved,
                second: 1,
            },
        )
        .unwrap();
    assert_eq!(
        restarted
            .read_participant_disclosure_preview(
                &owner(),
                &id,
                "private-record-alice",
                "amount-only-preview",
                authority.runtime(&window())
            )
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
}

struct SyntheticRecovery {
    candidate_id: String,
    exact_debit: Amount,
    exposure: AuthorizationExposure,
}
impl AccountRecoverySource for SyntheticRecovery {
    fn read_recovery_view(
        &mut self,
        account_id: &str,
    ) -> wholepact_core::Result<AccountRecoveryView> {
        Ok(AccountRecoveryView {
            account_id: account_id.into(),
            network_profile_id: wholepact_engine::candidates::PROFILE_ID.into(),
            observed_at: "2026-10-14T13:59:00Z".into(),
            history: ExposureHistoryState::Reconciled {
                writer_authority_ref: "synthetic-writer".into(),
                journal_checkpoint_digest: hash(10),
                reconciliation_evidence_ref: "synthetic-exposure-reconciled".into(),
            },
            revisions: vec![RevisionExposure {
                proposal_id: self.candidate_id.clone(),
                obligation_id: "obligation-example-01".into(),
                maximum_net_debit: self.exact_debit,
                exposure: self.exposure,
                input_ids: vec!["input-alice".into()],
            }],
            local_reservation_input_ids: vec![],
            residual_inputs: vec![ResidualInput {
                input_id: "synthetic-residual-input".into(),
                amount: amount(100),
                origin: ResidualFundOrigin::LeftoverChange,
            }],
            viewing_key_disclosure_refs: vec!["synthetic-prover-disclosure".into()],
        })
    }
    fn verify_destination(
        &mut self,
        request: &ReclaimDestinationRequest,
        network: &str,
    ) -> wholepact_core::Result<UserControlledShieldedDestination> {
        Ok(UserControlledShieldedDestination {
            address: request.address.clone(),
            user_controlled_account_ref: request.user_controlled_account_ref.clone(),
            network_profile_id: network.into(),
            pool: ShieldedReceiverPool::Orchard,
            ownership_source_ref: "synthetic-owned-destination".into(),
            ownership_evidence_digest: hash(11),
        })
    }
    fn quote_residual_transfer(
        &mut self,
        view: &AccountRecoveryView,
        destination: &UserControlledShieldedDestination,
    ) -> wholepact_core::Result<ReclaimFeeQuote> {
        Ok(ReclaimFeeQuote {
            quote_ref: "synthetic-fee-quote".into(),
            fee: amount(10),
            input_set_digest: reclaim_input_digest(&view.residual_inputs)?,
            destination_digest: reclaim_destination_digest(destination)?,
            expires_at: "2026-10-14T14:05:00Z".into(),
        })
    }
}
fn retirement_request(plan_id: &str) -> PlanParticipantRetirementRequest {
    PlanParticipantRetirementRequest {
        record_id: "private-record-alice".into(),
        expected_record_revision: 1,
        reclaim: ReclaimRequest {
            plan_id: plan_id.into(),
            account_id: "account-alice".into(),
            network_profile_id: wholepact_engine::candidates::PROFILE_ID.into(),
            destination: ReclaimDestinationRequest {
                address: "usyntheticexplicitdestination".into(),
                user_controlled_account_ref: "different-user-account".into(),
            },
            maximum_fee: amount(10),
            maximum_net_debit: amount(100),
        },
    }
}
#[test]
fn retirement_plan_is_durable_unsigned_and_cross_checks_local_released_exposure() {
    let dir = private_directory();
    let path = dir.path().join("retirement.sqlite");
    let key = DatabaseKey::from_bytes([95; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
    let mut request = candidate_request();
    // The authorization's actual reviewed debit is 404, below this user's cap.
    request.manifest.participants[0].maximum_net_debit = amount(500);
    let (id, candidate, revision) = setup_candidate_request(&engine, request);
    let authority = SyntheticAuthority::for_engine(&engine);
    let retained = retain(&engine, &authority, &id, &candidate, revision);
    let missing_known_release = engine
        .plan_participant_retirement(
            &owner(),
            "reject-omitted-known-release",
            &id,
            retained.agreement_revision,
            retirement_request("missing-history-plan"),
            authority.runtime(&window()),
            &mut SyntheticRecovery {
                candidate_id: "omitted-real-proposal".into(),
                exact_debit: amount(404),
                exposure: AuthorizationExposure::Consumed,
            },
        )
        .unwrap_err();
    assert_eq!(missing_known_release.code, "RECOVERY_REQUIRED");
    assert_eq!(
        engine.get(&owner(), &id).unwrap().revision,
        retained.agreement_revision
    );
    for wrong_debit in [amount(403), amount(500)] {
        assert_eq!(
            engine
                .plan_participant_retirement(
                    &owner(),
                    "reject-inexact-release-debit",
                    &id,
                    retained.agreement_revision,
                    retirement_request("inexact-release-plan"),
                    authority.runtime(&window()),
                    &mut SyntheticRecovery {
                        candidate_id: candidate.clone(),
                        exact_debit: wrong_debit,
                        exposure: AuthorizationExposure::Consumed,
                    },
                )
                .unwrap_err()
                .code,
            "RECOVERY_REQUIRED"
        );
    }
    let plan = engine
        .plan_participant_retirement(
            &owner(),
            "prepare-separate-retirement",
            &id,
            retained.agreement_revision,
            retirement_request("retirement-plan-one"),
            authority.runtime(&window()),
            &mut SyntheticRecovery {
                candidate_id: candidate.clone(),
                exact_debit: amount(404),
                exposure: AuthorizationExposure::Consumed,
            },
        )
        .unwrap();
    let view = engine
        .read_participant_retirement_plan(
            &owner(),
            &id,
            "private-record-alice",
            "retirement-plan-one",
            authority.runtime(&window()),
        )
        .unwrap();
    assert_eq!(view.transfer_amount, amount(90));
    assert_eq!(view.fee, amount(10));
    assert_eq!(view.maximum_net_debit, amount(100));
    assert_eq!(view.viewing_key_exposure, VIEWING_KEY_EXPOSURE_STATEMENT);
    assert_eq!(
        view.status,
        "unsigned_separate_review_and_authorization_required"
    );
    let store = Store::open_encrypted(&path, &key).unwrap();
    store
        .initialize_authority_account("account-alice", 1)
        .unwrap();
    store
        .record_authorization_release_intent(&ReleaseIntent {
            authorization_id: "outstanding-local-auth".into(),
            account_id: "account-alice".into(),
            writer_epoch: 1,
            obligation_id: "another-obligation".into(),
            proposal_id: "another-proposal".into(),
            manifest_digest: hash(20),
            effects_digest: hash(21),
            artifact_digest: hash(22),
            maximum_debit: "50".into(),
            input_ids: vec!["another-input".into()],
            aggregate_budget_limit: "100".into(),
        })
        .unwrap();
    assert_eq!(
        engine
            .plan_participant_retirement(
                &owner(),
                "block-hidden-local-exposure",
                &id,
                plan.agreement_revision,
                retirement_request("retirement-plan-two"),
                authority.runtime(&window()),
                &mut SyntheticRecovery {
                    candidate_id: candidate.clone(),
                    exact_debit: amount(404),
                    exposure: AuthorizationExposure::Consumed,
                }
            )
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
    assert_eq!(
        engine.get(&owner(), &id).unwrap().revision,
        plan.agreement_revision
    );
    drop(engine);
    let restarted = Engine::from_store(Store::open_encrypted(&path, &key).unwrap());
    let authority = SyntheticAuthority::for_engine(&restarted);
    assert_eq!(
        restarted
            .read_participant_retirement_plan(
                &owner(),
                &id,
                "private-record-alice",
                "retirement-plan-one",
                authority.runtime(&window())
            )
            .unwrap(),
        view
    );
}

#[test]
fn encrypted_backup_keeps_private_records_and_restore_never_reactivates_mutation() {
    let dir = private_directory();
    let path = dir.path().join("source.sqlite");
    let key = DatabaseKey::from_bytes([96; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
    let (id, candidate, revision) = setup_candidate(&engine);
    let authority = SyntheticAuthority::for_engine(&engine);
    let retained = retain(&engine, &authority, &id, &candidate, revision);
    let backup_path = dir.path().join("backup.sqlite");
    let backup_key = DatabaseKey::from_bytes([97; 32]);
    Store::open_encrypted(&path, &key)
        .unwrap()
        .backup_agreement_journal(&backup_path, &backup_key)
        .unwrap();
    let restored_path = dir.path().join("restored.sqlite");
    let restored_key = DatabaseKey::from_bytes([98; 32]);
    let (store, report) = wholepact_store::backup::restore_agreement_journal(
        &backup_path,
        &backup_key,
        &restored_path,
        &restored_key,
    )
    .unwrap();
    assert!(report.recovery_required);
    let restored = Engine::from_store(store);
    let restored_authority = SyntheticAuthority::for_engine(&restored);
    let record = restored
        .read_participant_record(
            &owner(),
            &id,
            "private-record-alice",
            restored_authority.runtime(&window()),
        )
        .unwrap();
    assert!(
        record
            .assess(&window())
            .unwrap()
            .exposure_reconciliation_required
    );
    assert_eq!(
        record.own_authorization().authorization_record_ref,
        "PRIVATE-SYNTHETIC-OWN-AUTH-SENTINEL"
    );
    assert_eq!(
        restored
            .observe_participant_record(
                &owner(),
                "block-restored-observation",
                &id,
                retained.agreement_revision,
                observe_request(1),
                restored_authority.runtime(&window()),
                &mut SyntheticChain {
                    status: ChainStatus::PendingObserved,
                    second: 1
                }
            )
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
    assert_eq!(
        restored
            .preview_participant_disclosure(
                &owner(),
                "block-restored-disclosure",
                &id,
                retained.agreement_revision,
                disclosure_request(),
                restored_authority.runtime(&window())
            )
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
    assert_eq!(
        restored
            .plan_participant_retirement(
                &owner(),
                "block-restored-retirement",
                &id,
                retained.agreement_revision,
                retirement_request("restored-plan"),
                restored_authority.runtime(&window()),
                &mut SyntheticRecovery {
                    candidate_id: candidate.clone(),
                    exact_debit: amount(404),
                    exposure: AuthorizationExposure::Consumed,
                }
            )
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
}

struct RevokingRecordSource<'a> {
    authority: &'a SyntheticAuthority,
}
impl RetainedParticipantRecordSource for RevokingRecordSource<'_> {
    fn source_id(&self) -> &str {
        "synthetic-revoking-source"
    }
    fn load_retained_record(
        &mut self,
        request: &RetainParticipantRecordRequest,
        candidate: &Proposal,
    ) -> wholepact_engine::Result<SettlementRecord> {
        let record = SyntheticRetainedSource::default().load_retained_record(request, candidate)?;
        self.authority.revoked.store(true, Ordering::SeqCst);
        Ok(record)
    }
}
#[test]
fn runtime_revocation_during_source_read_prevents_private_commit() {
    let dir = private_directory();
    let key = DatabaseKey::from_bytes([99; 32]);
    let engine = Engine::from_store(
        Store::create_encrypted(dir.path().join("revocation.sqlite"), &key).unwrap(),
    );
    let (id, candidate, revision) = setup_candidate(&engine);
    let authority = SyntheticAuthority::for_engine(&engine);
    let mut source = RevokingRecordSource {
        authority: &authority,
    };
    assert_eq!(
        engine
            .retain_participant_record(
                &owner(),
                "revoke-during-record-read",
                &id,
                revision,
                retention_request(&candidate),
                authority.runtime(&window()),
                &mut source
            )
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
    assert_eq!(engine.get(&owner(), &id).unwrap().revision, revision);
    authority.revoked.store(false, Ordering::SeqCst);
    assert!(
        engine
            .participant_record_status(&owner(), Some(authority.runtime(&window())))
            .unwrap()
            .records
            .unwrap()
            .is_empty()
    );
}

#[path = "participant_records/disclosure_exports.rs"]
mod disclosure_exports;

#[path = "participant_records/historical.rs"]
mod historical;

#[test]
fn retirement_planning_rejects_retained_conflict_expiry_and_local_hidden_holds_without_writes() {
    for exposure in [
        AuthorizationExposure::ConflictedObserved,
        AuthorizationExposure::ExpiredObserved,
    ] {
        let dir = private_directory();
        let path = dir.path().join("retained-hold.sqlite");
        let mut key_bytes = [0u8; 32];
        std::io::Read::read_exact(
            &mut std::fs::File::open("/dev/urandom").unwrap(),
            &mut key_bytes,
        )
        .unwrap();
        let key = DatabaseKey::from_bytes(key_bytes);
        let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
        let (id, candidate, revision) = setup_candidate(&engine);
        let authority = SyntheticAuthority::for_engine(&engine);
        let retained = retain(&engine, &authority, &id, &candidate, revision);
        let before = engine.get(&owner(), &id).unwrap().revision;
        let mut source = SyntheticRecovery {
            candidate_id: candidate,
            exact_debit: amount(404),
            exposure,
        };
        assert_eq!(
            engine
                .plan_participant_retirement(
                    &owner(),
                    "reject-reversible-original",
                    &id,
                    retained.agreement_revision,
                    retirement_request("unsafe-observed-plan"),
                    authority.runtime(&window()),
                    &mut source,
                )
                .unwrap_err()
                .code,
            "OUTSTANDING_EXPOSURE"
        );
        assert_eq!(engine.get(&owner(), &id).unwrap().revision, before);
        assert!(
            engine
                .read_participant_retirement_plan(
                    &owner(),
                    &id,
                    "private-record-alice",
                    "unsafe-observed-plan",
                    authority.runtime(&window()),
                )
                .is_err()
        );
        // A different local authorization must also fence the account even if
        // the selected adapter reports only the legitimately consumed original.
        let store = Store::open_encrypted(&path, &key).unwrap();
        store
            .initialize_authority_account("account-alice", 1)
            .unwrap();
        store
            .record_authorization_release_intent(&ReleaseIntent {
                authorization_id: "hidden-local-release".into(),
                account_id: "account-alice".into(),
                writer_epoch: 1,
                obligation_id: "other-obligation".into(),
                proposal_id: "other-proposal".into(),
                manifest_digest: hash(60),
                effects_digest: hash(61),
                artifact_digest: hash(62),
                maximum_debit: "10".into(),
                input_ids: vec!["other-input".into()],
                aggregate_budget_limit: "100".into(),
            })
            .unwrap();
        let local_state = match exposure {
            AuthorizationExposure::ConflictedObserved => {
                wholepact_store::authority::ExposureState::ConflictedObserved
            }
            _ => wholepact_store::authority::ExposureState::ExpiredObserved,
        };
        store
            .record_observed_resolution(
                "hidden-local-release",
                local_state,
                "synthetic-observation-only",
            )
            .unwrap();
        source.exposure = AuthorizationExposure::Consumed;
        assert_eq!(
            engine
                .plan_participant_retirement(
                    &owner(),
                    "reject-hidden-reversible-release",
                    &id,
                    retained.agreement_revision,
                    retirement_request("unsafe-hidden-plan"),
                    authority.runtime(&window()),
                    &mut source,
                )
                .unwrap_err()
                .code,
            "RECOVERY_REQUIRED"
        );
        assert_eq!(engine.get(&owner(), &id).unwrap().revision, before);
    }
}
