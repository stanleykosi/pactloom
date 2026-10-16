//! Synthetic unqualified adapters only. No wallet secrets, cryptographic proofs,
//! live transaction execution, or real financial authorization are used here.
use wholepact_core::disclosure::*;
use wholepact_core::recipient::*;
use wholepact_core::records::*;
use wholepact_core::retirement::*;
use wholepact_core::*;

fn a(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn hash(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}
fn window() -> ObservationWindow {
    ObservationWindow {
        now: "2026-10-14T12:00:00Z".into(),
        oldest_acceptable: "2026-10-14T11:55:00Z".into(),
    }
}
fn proposal() -> Proposal {
    let agreement: AgreementDraft =
        parse_typed_json(include_bytes!("fixtures/agreement.json")).unwrap();
    Proposal::validate(ProposalInput {
        proposal_id: "synthetic-proposal".into(),
        previous_proposal_id: None,
        artifact_digest: Some(hash(1)),
        effects_commitment: Some(hash(2)),
        created_at: "2026-10-14T10:00:00Z".into(),
        manifest: ProposalManifest {
            outputs: vec![ClaimedOutput {
                output_id: "recipient-output".into(),
                address: agreement.recipients[0].address.clone(),
                amount: a(1_000_000_000),
                allocation: OutputAllocation::Recipient {
                    recipient_id: "recipient-example".into(),
                },
            }],
            agreement,
            participants: vec![
                ParticipantAllocation {
                    participant_id: "alice".into(),
                    account_id: "account-alice".into(),
                    contribution: a(400_000_000),
                    fee_share: a(12_000),
                    fee_cap: a(12_000),
                    maximum_net_debit: a(400_012_000),
                    charges: vec![],
                },
                ParticipantAllocation {
                    participant_id: "bob".into(),
                    account_id: "account-bob".into(),
                    contribution: a(600_000_000),
                    fee_share: a(18_000),
                    fee_cap: a(18_000),
                    maximum_net_debit: a(600_018_000),
                    charges: vec![],
                },
            ],
            inputs: vec![
                ClaimedInput {
                    input_id: "input-alice".into(),
                    participant_id: "alice".into(),
                    account_id: "account-alice".into(),
                    amount: a(400_012_000),
                    ownership_evidence_ref: None,
                },
                ClaimedInput {
                    input_id: "input-bob".into(),
                    participant_id: "bob".into(),
                    account_id: "account-bob".into(),
                    amount: a(600_018_000),
                    ownership_evidence_ref: None,
                },
            ],
            transaction_fee: a(30_000),
            expiry_height: 1000,
        },
    })
    .unwrap()
}
fn transaction() -> ExactTransactionReference {
    ExactTransactionReference {
        network_profile_id: "zcash-testnet-unqualified".into(),
        transaction_id: hash(3),
        transaction_bytes_digest: hash(4),
        effects_commitment: hash(2),
    }
}
fn authorization(proposal: &Proposal) -> OwnAuthorizationRecord {
    OwnAuthorizationRecord {
        participant_id: "alice".into(),
        account_id: "account-alice".into(),
        proposal_digest: proposal.proposal_digest().into(),
        manifest_digest: proposal.manifest_digest().into(),
        effects_commitment: hash(2),
        consent_record_ref: "synthetic-consent".into(),
        authorization_record_ref: "synthetic-authorization".into(),
        release_operation_id: Some("synthetic-release".into()),
        exposure: AuthorizationExposure::Released,
    }
}
fn record() -> SettlementRecord {
    let proposal = proposal();
    let authorization = authorization(&proposal);
    SettlementRecord::new(
        "synthetic-record".into(),
        proposal,
        authorization,
        transaction(),
    )
    .unwrap()
}
fn policy() -> ObservationPolicy {
    ObservationPolicy {
        source_id: "synthetic-chain".into(),
        trust_profile_id: "synthetic-unqualified".into(),
        adapter_id: "synthetic-adapter".into(),
    }
}
fn chain(status: ChainStatus, seconds: u8) -> SourcedChainObservation {
    let included = matches!(
        status,
        ChainStatus::Included
            | ChainStatus::ConfirmationPolicyMet
            | ChainStatus::ConflictedObserved
    );
    SourcedChainObservation {
        transaction: transaction(),
        adapter_id: policy().adapter_id,
        observation: ChainObservation {
            observation_id: format!("observation-{seconds}"),
            source_id: policy().source_id,
            trust_profile_id: policy().trust_profile_id,
            observed_at: format!("2026-10-14T11:59:{seconds:02}Z"),
            tip_height: 999,
            tip_hash: hash(5),
            synchronized: true,
            status,
            inclusion_height: included.then_some(990),
            inclusion_hash: included.then(|| hash(6)),
            confirmations: if included { 10 } else { 0 },
            evidence_ref: "synthetic-chain-evidence".into(),
        },
    }
}
struct SyntheticChain(SourcedChainObservation);
impl SettlementObservationSource for SyntheticChain {
    fn observe_exact_transaction(
        &mut self,
        _: &ExactTransactionReference,
    ) -> Result<SourcedChainObservation> {
        Ok(self.0.clone())
    }
}
fn included_record() -> SettlementRecord {
    record()
        .observe(
            &mut SyntheticChain(chain(ChainStatus::ConfirmationPolicyMet, 1)),
            &policy(),
            &window(),
        )
        .unwrap()
        .0
}

#[test]
fn private_record_binds_owner_manifest_effects_and_durable_release() {
    let proposal = proposal();
    let mut own = authorization(&proposal);
    own.account_id = "another-account".into();
    assert_eq!(
        SettlementRecord::new("record".into(), proposal.clone(), own, transaction())
            .unwrap_err()
            .code,
        ErrorCode::RevisionConflict
    );
    let mut own = authorization(&proposal);
    own.release_operation_id = None;
    assert_eq!(
        SettlementRecord::new("record".into(), proposal.clone(), own, transaction())
            .unwrap_err()
            .code,
        ErrorCode::MissingEvidence
    );
    let mut changed = transaction();
    changed.effects_commitment = hash(9);
    assert_eq!(
        SettlementRecord::new(
            "record".into(),
            proposal.clone(),
            authorization(&proposal),
            changed
        )
        .unwrap_err()
        .code,
        ErrorCode::RevisionConflict
    );
    assert_eq!(
        record().assess(&window()).unwrap().confidence,
        RecordConfidence::NoObservation
    );
    assert!(!format!("{:?}", record()).contains("alice"));
}

#[test]
fn observation_replay_equivocation_substitution_and_freshness_are_checked() {
    let observed = included_record();
    let (same, event) = observed
        .observe(
            &mut SyntheticChain(chain(ChainStatus::ConfirmationPolicyMet, 1)),
            &policy(),
            &window(),
        )
        .unwrap();
    assert_eq!(event, RecordEvent::ExactReplay);
    assert_eq!(same.observations().len(), 1);
    let mut changed = chain(ChainStatus::ConfirmationPolicyMet, 1);
    changed.observation.evidence_ref = "different-evidence".into();
    assert_eq!(
        observed
            .observe(&mut SyntheticChain(changed), &policy(), &window())
            .unwrap_err()
            .code,
        ErrorCode::RevisionConflict
    );
    let mut wrong = chain(ChainStatus::ConfirmationPolicyMet, 2);
    wrong.transaction.transaction_bytes_digest = hash(99);
    assert_eq!(
        observed
            .observe(&mut SyntheticChain(wrong), &policy(), &window())
            .unwrap_err()
            .code,
        ErrorCode::MissingEvidence
    );
    let old = chain(ChainStatus::PendingObserved, 0);
    assert_eq!(
        observed
            .observe(&mut SyntheticChain(old), &policy(), &window())
            .unwrap_err()
            .code,
        ErrorCode::StaleChain
    );
    let mut future = chain(ChainStatus::PendingObserved, 2);
    future.observation.observed_at = "2026-10-14T12:01:00Z".into();
    assert_eq!(
        observed
            .observe(&mut SyntheticChain(future), &policy(), &window())
            .unwrap_err()
            .code,
        ErrorCode::StaleChain
    );
}

#[test]
fn reorg_staleness_and_restore_never_keep_an_unchanged_success_assurance() {
    let record = included_record();
    assert_eq!(
        record.assess(&window()).unwrap().confidence,
        RecordConfidence::ConfirmationPolicyMet
    );
    let later = ObservationWindow {
        now: "2026-10-14T13:00:00Z".into(),
        oldest_acceptable: "2026-10-14T12:55:00Z".into(),
    };
    assert_eq!(
        record.assess(&later).unwrap().confidence,
        RecordConfidence::Stale
    );
    let (reorg, event) = record
        .observe(
            &mut SyntheticChain(chain(ChainStatus::Reorganized, 2)),
            &policy(),
            &window(),
        )
        .unwrap();
    assert_eq!(event, RecordEvent::ReconcileOutstandingExposure);
    assert_eq!(
        reorg.assess(&window()).unwrap().confidence,
        RecordConfidence::Reorganized
    );
    assert!(
        reorg
            .assess(&window())
            .unwrap()
            .exposure_reconciliation_required
    );
    assert_eq!(reorg.observations().len(), 2);
    let restored = SettlementRecord::restore(record.archive()).unwrap();
    assert!(
        restored
            .assess(&window())
            .unwrap()
            .exposure_reconciliation_required
    );
    assert_eq!(
        restored.own_authorization().exposure,
        AuthorizationExposure::Released
    );
}

#[test]
fn contradictory_sources_and_premature_expiry_cannot_resolve_confidence() {
    let record = included_record();
    let mut second = chain(ChainStatus::PendingObserved, 2);
    second.observation.source_id = "second-source".into();
    let mut second_policy = policy();
    second_policy.source_id = "second-source".into();
    let (record, event) = record
        .observe(&mut SyntheticChain(second), &second_policy, &window())
        .unwrap();
    assert_eq!(event, RecordEvent::ReconcileOutstandingExposure);
    assert_eq!(
        record.assess(&window()).unwrap().confidence,
        RecordConfidence::Contradictory
    );
    let mut expiry = chain(ChainStatus::ExpiredObserved, 3);
    expiry.observation.tip_height = 1000;
    assert_eq!(
        record
            .observe(&mut SyntheticChain(expiry.clone()), &policy(), &window())
            .unwrap_err()
            .code,
        ErrorCode::StaleChain
    );
    expiry.observation.tip_height = 1010;
    assert!(
        record
            .observe(&mut SyntheticChain(expiry), &policy(), &window())
            .is_ok()
    );
}

fn selection(fields: Vec<DisclosureField>) -> DisclosureSelection {
    let payment_recipient_id = fields
        .iter()
        .any(|f| {
            matches!(
                f,
                DisclosureField::RecipientAmount | DisclosureField::RecipientDestination
            )
        })
        .then(|| "recipient-example".into());
    DisclosureSelection {
        fields,
        payment_recipient_id,
        destination: DisclosureDestination {
            recipient_id: "reviewer".into(),
            destination: "reviewer-local-file".into(),
            audience: DisclosureAudience::NamedPrivateRecipient,
        },
        purpose: "Share only the selected payment fact".into(),
        persistence: "Recipient may retain a permanent copy".into(),
    }
}
enum SyntheticConsent {
    Approve,
    Reject,
    Revoke,
    WrongPreview,
    Expired,
}
impl DisclosureConsentSource for SyntheticConsent {
    fn review_current_disclosure(
        &mut self,
        preview: &DisclosurePreview,
    ) -> Result<DisclosureDecision> {
        Ok(match self {
            Self::Reject => DisclosureDecision::Rejected,
            Self::Revoke => DisclosureDecision::Revoked,
            Self::Approve | Self::WrongPreview | Self::Expired => DisclosureDecision::Approved {
                preview_digest: if matches!(self, Self::WrongPreview) {
                    hash(99)
                } else {
                    preview.digest().into()
                },
                consent_record_ref: "synthetic-disclosure-consent".into(),
                expires_at: if matches!(self, Self::Expired) {
                    window().now
                } else {
                    "2026-10-15T12:00:00Z".into()
                },
            },
        })
    }
}
#[test]
fn disclosure_projection_exports_only_selected_fact_and_no_hidden_linkage() {
    let record = included_record();
    let preview = DisclosurePreview::build(
        &record,
        selection(vec![DisclosureField::RecipientAmount]),
        DisclosureMethod::PrivateReceipt,
        &window(),
    )
    .unwrap();
    let prepared = preview
        .prepare_export(&record, &mut SyntheticConsent::Approve, &window())
        .unwrap();
    let bytes = prepared.encode().unwrap();
    let encoded = String::from_utf8(bytes.clone()).unwrap();
    for excluded in [
        "alice",
        "bob",
        "synthetic-proposal",
        "agreement-example",
        "authorization_record_ref",
        "input-alice",
        "uregtest",
        &transaction().transaction_id,
    ] {
        assert!(
            !encoded.contains(excluded),
            "unselected information leaked: {excluded}"
        );
    }
    let inspected = inspect_private_receipt(
        &bytes,
        &selection(vec![DisclosureField::RecipientAmount]).destination,
    )
    .unwrap();
    assert_eq!(
        inspected.facts,
        vec![DisclosedFact::RecipientAmount(a(1_000_000_000))]
    );
    assert!(
        inspected
            .limitations
            .contains("not independently authenticated")
    );
    assert_eq!(inspected.method, DisclosureMethod::PrivateReceipt);
}
#[test]
fn disclosure_requires_fresh_exact_separate_consent_and_rejects_unsupported_proofs() {
    let record = included_record();
    let preview = DisclosurePreview::build(
        &record,
        selection(vec![DisclosureField::ChainConfidence]),
        DisclosureMethod::PrivateReceipt,
        &window(),
    )
    .unwrap();
    for mut denied in [SyntheticConsent::Reject, SyntheticConsent::Revoke] {
        assert_eq!(
            preview
                .prepare_export(&record, &mut denied, &window())
                .unwrap_err()
                .code,
            ErrorCode::UserRejected
        );
    }
    for mut bad in [SyntheticConsent::WrongPreview, SyntheticConsent::Expired] {
        assert_eq!(
            preview
                .prepare_export(&record, &mut bad, &window())
                .unwrap_err()
                .code,
            ErrorCode::MissingEvidence
        );
    }
    let later = ObservationWindow {
        now: "2026-10-14T13:00:00Z".into(),
        oldest_acceptable: "2026-10-14T12:55:00Z".into(),
    };
    assert_eq!(
        preview
            .prepare_export(&record, &mut SyntheticConsent::Approve, &later)
            .unwrap_err()
            .code,
        ErrorCode::StaleChain
    );
    let (changed, _) = record
        .observe(
            &mut SyntheticChain(chain(ChainStatus::Reorganized, 2)),
            &policy(),
            &window(),
        )
        .unwrap();
    assert_eq!(
        preview
            .prepare_export(&changed, &mut SyntheticConsent::Approve, &window())
            .unwrap_err()
            .code,
        ErrorCode::RevisionConflict
    );
    for method in [
        DisclosureMethod::CryptographicPaymentProof {
            format_id: "invented-format".into(),
        },
        DisclosureMethod::NamedOperatorAssertion {
            operator_id: "operator".into(),
            signature_format: "unimplemented".into(),
        },
    ] {
        assert_eq!(
            DisclosurePreview::build(
                &record,
                selection(vec![DisclosureField::TransactionId]),
                method,
                &window()
            )
            .unwrap_err()
            .code,
            ErrorCode::UnsupportedCapability
        );
    }
}
#[test]
fn disclosure_inspector_does_not_accept_destination_limits_or_schema_substitution() {
    let record = included_record();
    let selection = selection(vec![
        DisclosureField::AgreementLinkage,
        DisclosureField::OwnNetDebit,
        DisclosureField::ChainConfidence,
    ]);
    let preview = DisclosurePreview::build(
        &record,
        selection.clone(),
        DisclosureMethod::PrivateReceipt,
        &window(),
    )
    .unwrap();
    let mut receipt = preview.receipt().clone();
    receipt.limitations = "Payment guaranteed".into();
    assert_eq!(
        inspect_private_receipt(
            &serde_json::to_vec(&receipt).unwrap(),
            &selection.destination
        )
        .unwrap_err()
        .code,
        ErrorCode::PrivacyIncompatible
    );
    let mut receipt = preview.receipt().clone();
    receipt.facts.push(receipt.facts[0].clone());
    assert_eq!(
        inspect_private_receipt(
            &serde_json::to_vec(&receipt).unwrap(),
            &selection.destination
        )
        .unwrap_err()
        .code,
        ErrorCode::DuplicateIdentifier
    );
    let mut value = serde_json::to_value(preview.receipt()).unwrap();
    value["private_witness"] = serde_json::json!("forbidden");
    assert!(
        inspect_private_receipt(&serde_json::to_vec(&value).unwrap(), &selection.destination)
            .is_err()
    );
}

fn recipient_policy() -> RecipientCheckPolicy {
    RecipientCheckPolicy {
        chain: policy(),
        recipient_source: AcceptedRecipientSource::RecipientWallet {
            wallet_adapter_id: "synthetic-recipient-wallet".into(),
            recipient_account_ref: "recipient-own-account".into(),
        },
        required_confirmations: 10,
    }
}
fn recipient_observation() -> RecipientSourceObservation {
    RecipientSourceObservation {
        recipient_id: "recipient-example".into(),
        observed_at: "2026-10-14T11:59:01Z".into(),
        evidence: RecipientEvidenceProvenance::RecipientWallet {
            wallet_adapter_id: "synthetic-recipient-wallet".into(),
            recipient_account_ref: "recipient-own-account".into(),
            scan_checkpoint_ref: "synthetic-scan".into(),
            decryption_evidence_digest: hash(12),
        },
        outputs: vec![RecipientObservedOutput {
            output_ref: "orchard-output-0".into(),
            destination: proposal().manifest().agreement.recipients[0]
                .address
                .clone(),
            amount: a(1_000_000_000),
        }],
        chain: chain(ChainStatus::ConfirmationPolicyMet, 1),
    }
}
struct SyntheticRecipient(RecipientSourceObservation);
impl RecipientObservationSource for SyntheticRecipient {
    fn observe_recipient_outputs(
        &mut self,
        _: &RecipientPaymentRequest,
    ) -> Result<RecipientSourceObservation> {
        Ok(self.0.clone())
    }
}
fn recipient_request() -> RecipientPaymentRequest {
    RecipientPaymentRequest::for_proposal(&proposal(), transaction(), "recipient-example").unwrap()
}
#[test]
fn recipient_amount_destination_and_confidence_are_independently_scoped() {
    let checked = check_recipient_payment(
        &mut SyntheticRecipient(recipient_observation()),
        &recipient_request(),
        &recipient_policy(),
        &window(),
    )
    .unwrap();
    assert_eq!(checked.amount(), a(1_000_000_000));
    assert_eq!(
        checked.confidence(),
        RecordConfidence::ConfirmationPolicyMet
    );
    let later = ObservationWindow {
        now: "2026-10-14T13:00:00Z".into(),
        oldest_acceptable: "2026-10-14T12:55:00Z".into(),
    };
    assert_eq!(
        checked.confidence_at(&later).unwrap(),
        RecordConfidence::Stale
    );
    let mut pending = recipient_observation();
    pending.chain = chain(ChainStatus::PendingObserved, 1);
    assert_eq!(
        check_recipient_payment(
            &mut SyntheticRecipient(pending),
            &recipient_request(),
            &recipient_policy(),
            &window()
        )
        .unwrap()
        .confidence(),
        RecordConfidence::Pending
    );
    let mut stricter = recipient_policy();
    stricter.required_confirmations = 20;
    assert_eq!(
        check_recipient_payment(
            &mut SyntheticRecipient(recipient_observation()),
            &recipient_request(),
            &stricter,
            &window()
        )
        .unwrap()
        .confidence(),
        RecordConfidence::Included
    );
}
#[test]
fn coordinator_assertion_and_substituted_recipient_evidence_are_rejected() {
    let mut assertion = recipient_observation();
    assertion.evidence = RecipientEvidenceProvenance::CoordinatorAssertion {
        operator_id: "organizer".into(),
        assertion_ref: "success-message".into(),
    };
    assert_eq!(
        check_recipient_payment(
            &mut SyntheticRecipient(assertion),
            &recipient_request(),
            &recipient_policy(),
            &window()
        )
        .unwrap_err()
        .code,
        ErrorCode::MissingEvidence
    );
    let mut wrong = recipient_observation();
    wrong.outputs[0].destination = "uattacker".into();
    assert_eq!(
        check_recipient_payment(
            &mut SyntheticRecipient(wrong),
            &recipient_request(),
            &recipient_policy(),
            &window()
        )
        .unwrap_err()
        .code,
        ErrorCode::MissingEvidence
    );
    let mut wrong = recipient_observation();
    wrong.outputs[0].amount = a(999_999_999);
    assert_eq!(
        check_recipient_payment(
            &mut SyntheticRecipient(wrong),
            &recipient_request(),
            &recipient_policy(),
            &window()
        )
        .unwrap_err()
        .code,
        ErrorCode::ConservationFailure
    );
    let mut duplicated = recipient_observation();
    duplicated.outputs.push(duplicated.outputs[0].clone());
    assert_eq!(
        check_recipient_payment(
            &mut SyntheticRecipient(duplicated),
            &recipient_request(),
            &recipient_policy(),
            &window()
        )
        .unwrap_err()
        .code,
        ErrorCode::DuplicateIdentifier
    );
    let mut wrong = recipient_observation();
    wrong.chain.transaction.transaction_id = hash(55);
    assert_eq!(
        check_recipient_payment(
            &mut SyntheticRecipient(wrong),
            &recipient_request(),
            &recipient_policy(),
            &window()
        )
        .unwrap_err()
        .code,
        ErrorCode::MissingEvidence
    );
}

fn recovery_view() -> AccountRecoveryView {
    AccountRecoveryView {
        account_id: "account-alice".into(),
        network_profile_id: "zcash-testnet-unqualified".into(),
        observed_at: "2026-10-14T11:59:00Z".into(),
        history: ExposureHistoryState::Reconciled {
            writer_authority_ref: "synthetic-current-writer".into(),
            journal_checkpoint_digest: hash(20),
            reconciliation_evidence_ref: "synthetic-exposure-reconciliation".into(),
        },
        revisions: vec![RevisionExposure {
            proposal_id: "original-proposal".into(),
            obligation_id: "original-obligation".into(),
            maximum_net_debit: a(100),
            exposure: AuthorizationExposure::ExpiredObserved,
            input_ids: vec!["original-input".into()],
        }],
        local_reservation_input_ids: vec![],
        residual_inputs: vec![ResidualInput {
            input_id: "residual-input".into(),
            amount: a(1000),
            origin: ResidualFundOrigin::LeftoverChange,
        }],
        viewing_key_disclosure_refs: vec!["original-prover-disclosure".into()],
    }
}
fn reclaim_request() -> ReclaimRequest {
    ReclaimRequest {
        plan_id: "synthetic-reclaim-plan".into(),
        account_id: "account-alice".into(),
        network_profile_id: "zcash-testnet-unqualified".into(),
        destination: ReclaimDestinationRequest {
            address: "usyntheticusercontrolleddestination".into(),
            user_controlled_account_ref: "another-owned-account".into(),
        },
        maximum_fee: a(20),
        maximum_net_debit: a(1000),
    }
}
fn destination() -> UserControlledShieldedDestination {
    UserControlledShieldedDestination {
        address: reclaim_request().destination.address,
        user_controlled_account_ref: reclaim_request().destination.user_controlled_account_ref,
        network_profile_id: reclaim_request().network_profile_id,
        pool: ShieldedReceiverPool::Orchard,
        ownership_source_ref: "synthetic-owner-check".into(),
        ownership_evidence_digest: hash(21),
    }
}
struct SyntheticRecovery {
    view: AccountRecoveryView,
    destination: UserControlledShieldedDestination,
    fee: Amount,
    quote_expiry: String,
}
impl Default for SyntheticRecovery {
    fn default() -> Self {
        Self {
            view: recovery_view(),
            destination: destination(),
            fee: a(10),
            quote_expiry: "2026-10-14T12:05:00Z".into(),
        }
    }
}
impl AccountRecoverySource for SyntheticRecovery {
    fn read_recovery_view(&mut self, _: &str) -> Result<AccountRecoveryView> {
        Ok(self.view.clone())
    }
    fn verify_destination(
        &mut self,
        _: &ReclaimDestinationRequest,
        _: &str,
    ) -> Result<UserControlledShieldedDestination> {
        Ok(self.destination.clone())
    }
    fn quote_residual_transfer(
        &mut self,
        view: &AccountRecoveryView,
        destination: &UserControlledShieldedDestination,
    ) -> Result<ReclaimFeeQuote> {
        Ok(ReclaimFeeQuote {
            quote_ref: "synthetic-fee-quote".into(),
            fee: self.fee,
            input_set_digest: reclaim_input_digest(&view.residual_inputs)?,
            destination_digest: reclaim_destination_digest(destination)?,
            expires_at: self.quote_expiry.clone(),
        })
    }
}
struct SyntheticReclaimReview(ReclaimReviewDecision);
impl ReclaimReviewSource for SyntheticReclaimReview {
    fn review_reclaim(&mut self, _: &AccountRetirementPlan) -> Result<ReclaimReviewDecision> {
        Ok(self.0.clone())
    }
}
fn reviewed_plan() -> ReviewedReclaimPlan {
    let mut source = SyntheticRecovery::default();
    let plan = AccountRetirementPlan::prepare(&mut source, reclaim_request(), &window()).unwrap();
    let mut review = SyntheticReclaimReview(ReclaimReviewDecision::Accepted {
        plan_digest: plan.digest().into(),
        review_record_ref: "synthetic-reclaim-review".into(),
    });
    plan.review_for_separate_authorization(&mut source, &mut review, &window())
        .unwrap()
}
#[test]
fn missing_stale_and_live_history_block_reclaim_even_with_empty_exposure() {
    for history in [
        ExposureHistoryState::Missing,
        ExposureHistoryState::RestoredOrUnknown,
    ] {
        let mut source = SyntheticRecovery::default();
        source.view.history = history;
        source.view.revisions.clear();
        assert_eq!(
            AccountRetirementPlan::prepare(&mut source, reclaim_request(), &window())
                .unwrap_err()
                .code,
            ErrorCode::RecoveryRequired
        );
    }
    for exposure in [
        AuthorizationExposure::AuthorizedLocally,
        AuthorizationExposure::Released,
        AuthorizationExposure::OutstandingUncertain,
    ] {
        let mut source = SyntheticRecovery::default();
        source.view.revisions[0].exposure = exposure;
        assert_eq!(
            AccountRetirementPlan::prepare(&mut source, reclaim_request(), &window())
                .unwrap_err()
                .code,
            ErrorCode::OutstandingExposure
        );
    }
    let mut source = SyntheticRecovery::default();
    source
        .view
        .local_reservation_input_ids
        .push("unrelated-reserved-input".into());
    assert_eq!(
        AccountRetirementPlan::prepare(&mut source, reclaim_request(), &window())
            .unwrap_err()
            .code,
        ErrorCode::OutstandingExposure
    );
    let mut source = SyntheticRecovery::default();
    source.view.residual_inputs[0].origin = ResidualFundOrigin::Unknown;
    assert_eq!(
        AccountRetirementPlan::prepare(&mut source, reclaim_request(), &window())
            .unwrap_err()
            .code,
        ErrorCode::MissingEvidence
    );
}
#[test]
fn reclaim_exact_balance_fee_and_destination_require_independent_evidence() {
    let plan = AccountRetirementPlan::prepare(
        &mut SyntheticRecovery::default(),
        reclaim_request(),
        &window(),
    )
    .unwrap();
    assert_eq!(plan.transfer_amount(), a(990));
    assert_eq!(plan.fee(), a(10));
    assert_eq!(plan.maximum_net_debit(), a(1000));
    assert_eq!(plan.viewing_key_exposure(), VIEWING_KEY_EXPOSURE_STATEMENT);
    let mut source = SyntheticRecovery::default();
    source.destination.address = "uattacker".into();
    assert_eq!(
        AccountRetirementPlan::prepare(&mut source, reclaim_request(), &window())
            .unwrap_err()
            .code,
        ErrorCode::MissingEvidence
    );
    let mut source = SyntheticRecovery {
        fee: a(21),
        ..Default::default()
    };
    assert_eq!(
        AccountRetirementPlan::prepare(&mut source, reclaim_request(), &window())
            .unwrap_err()
            .code,
        ErrorCode::FeeCapExceeded
    );
    let mut request = reclaim_request();
    request.maximum_net_debit = a(999);
    assert_eq!(
        AccountRetirementPlan::prepare(&mut SyntheticRecovery::default(), request, &window())
            .unwrap_err()
            .code,
        ErrorCode::DebitCapExceeded
    );
    let mut source = SyntheticRecovery {
        quote_expiry: window().now,
        ..Default::default()
    };
    assert_eq!(
        AccountRetirementPlan::prepare(&mut source, reclaim_request(), &window())
            .unwrap_err()
            .code,
        ErrorCode::MissingEvidence
    );
}
#[test]
fn separate_reclaim_review_rejects_substitution_and_new_exposure_races() {
    let mut source = SyntheticRecovery::default();
    let plan = AccountRetirementPlan::prepare(&mut source, reclaim_request(), &window()).unwrap();
    assert_eq!(
        plan.review_for_separate_authorization(
            &mut source,
            &mut SyntheticReclaimReview(ReclaimReviewDecision::Rejected),
            &window()
        )
        .unwrap_err()
        .code,
        ErrorCode::UserRejected
    );
    let mut wrong = SyntheticReclaimReview(ReclaimReviewDecision::Accepted {
        plan_digest: hash(90),
        review_record_ref: "review".into(),
    });
    assert_eq!(
        plan.review_for_separate_authorization(&mut source, &mut wrong, &window())
            .unwrap_err()
            .code,
        ErrorCode::RevisionConflict
    );
    source.view.revisions[0].exposure = AuthorizationExposure::Released;
    let mut matching = SyntheticReclaimReview(ReclaimReviewDecision::Accepted {
        plan_digest: plan.digest().into(),
        review_record_ref: "review".into(),
    });
    assert_eq!(
        plan.review_for_separate_authorization(&mut source, &mut matching, &window())
            .unwrap_err()
            .code,
        ErrorCode::OutstandingExposure
    );
    assert!(format!("{:?}", reviewed_plan()).contains("REQUIRED"));
}
fn reclaim_settlement(reviewed: &ReviewedReclaimPlan) -> ReclaimSettlementEvidence {
    let mut chain = chain(ChainStatus::ConfirmationPolicyMet, 1);
    chain.transaction.transaction_id = hash(30);
    chain.transaction.transaction_bytes_digest = hash(31);
    chain.transaction.effects_commitment = hash(32);
    ReclaimSettlementEvidence {
        plan_digest: reviewed.plan().digest().into(),
        authorization_record_ref: "separate-reclaim-authorization".into(),
        release_operation_id: "separate-reclaim-release".into(),
        input_set_digest: reclaim_input_digest(reviewed.plan().inputs()).unwrap(),
        destination: destination(),
        amount: a(990),
        fee: a(10),
        chain,
    }
}
struct SyntheticReclaimSettlement(ReclaimSettlementEvidence);
impl ReclaimSettlementSource for SyntheticReclaimSettlement {
    fn observe_separately_authorized_reclaim(
        &mut self,
        _: &ReviewedReclaimPlan,
    ) -> Result<ReclaimSettlementEvidence> {
        Ok(self.0.clone())
    }
}
#[test]
fn retirement_needs_observed_separate_transfer_and_preserves_viewing_exposure() {
    let reviewed = reviewed_plan();
    let evidence = reclaim_settlement(&reviewed);
    let mut source = SyntheticRecovery::default();
    source.view.residual_inputs.clear();
    let retired = RetiredAccountRecord::after_reclaim(
        &mut source,
        &mut SyntheticReclaimSettlement(evidence.clone()),
        &reviewed,
        &policy(),
        10,
        &window(),
    )
    .unwrap();
    assert!(!retired.routine_reuse_allowed());
    assert_eq!(
        retired.viewing_key_exposure(),
        VIEWING_KEY_EXPOSURE_STATEMENT
    );
    assert_eq!(
        retired.reclaim_transaction().unwrap().transaction_id,
        hash(30)
    );
    let recovery = retired.reconcile_after_reorganization();
    assert!(!recovery.account.routine_reuse_allowed());
    assert!(recovery.reason.contains("no automatic replacement"));
    let mut wrong = evidence.clone();
    wrong.amount = a(989);
    assert_eq!(
        RetiredAccountRecord::after_reclaim(
            &mut source,
            &mut SyntheticReclaimSettlement(wrong),
            &reviewed,
            &policy(),
            10,
            &window()
        )
        .unwrap_err()
        .code,
        ErrorCode::RevisionConflict
    );
    let mut reorg = evidence;
    reorg.chain = chain(ChainStatus::Reorganized, 2);
    assert_eq!(
        RetiredAccountRecord::after_reclaim(
            &mut source,
            &mut SyntheticReclaimSettlement(reorg),
            &reviewed,
            &policy(),
            10,
            &window()
        )
        .unwrap_err()
        .code,
        ErrorCode::StaleChain
    );
    assert_eq!(
        RetiredAccountRecord::after_reclaim(
            &mut SyntheticRecovery::default(),
            &mut SyntheticReclaimSettlement(reclaim_settlement(&reviewed)),
            &reviewed,
            &policy(),
            10,
            &window()
        )
        .unwrap_err()
        .code,
        ErrorCode::OutstandingExposure
    );
}
#[test]
fn empty_account_retirement_still_requires_complete_history_and_preserves_records() {
    let mut source = SyntheticRecovery::default();
    source.view.residual_inputs.clear();
    source.view.history = ExposureHistoryState::Missing;
    assert_eq!(
        RetiredAccountRecord::retire_empty_account(
            &mut source,
            "account-alice",
            "zcash-testnet-unqualified",
            &window()
        )
        .unwrap_err()
        .code,
        ErrorCode::RecoveryRequired
    );
    source.view.history = recovery_view().history;
    let retired = RetiredAccountRecord::retire_empty_account(
        &mut source,
        "account-alice",
        "zcash-testnet-unqualified",
        &window(),
    )
    .unwrap();
    let persisted = serde_json::to_string(&retired).unwrap();
    assert!(persisted.contains("original-prover-disclosure"));
    assert!(persisted.contains(&hash(20)));
    assert!(!retired.routine_reuse_allowed());
    assert!(retired.reclaim_transaction().is_none());
}

#[test]
fn pending_first_provider_contradiction_stays_flagged_after_restart() {
    let (pending, _) = record()
        .observe(
            &mut SyntheticChain(chain(ChainStatus::PendingObserved, 1)),
            &policy(),
            &window(),
        )
        .unwrap();
    let mut inclusion = chain(ChainStatus::Included, 2);
    inclusion.observation.source_id = "second-source".into();
    let mut second_policy = policy();
    second_policy.source_id = "second-source".into();
    let (contradictory, event) = pending
        .observe(&mut SyntheticChain(inclusion), &second_policy, &window())
        .unwrap();
    assert_eq!(event, RecordEvent::ReconcileOutstandingExposure);
    let loaded = SettlementRecord::load_retained_archive(contradictory.archive()).unwrap();
    assert!(
        loaded
            .assess(&window())
            .unwrap()
            .exposure_reconciliation_required
    );
    assert!(
        !SettlementRecord::load_retained_archive(included_record().archive())
            .unwrap()
            .assess(&window())
            .unwrap()
            .exposure_reconciliation_required
    );
    assert!(
        SettlementRecord::load_retained_archive(
            SettlementRecord::restore(included_record().archive())
                .unwrap()
                .archive()
        )
        .unwrap()
        .assess(&window())
        .unwrap()
        .exposure_reconciliation_required
    );
}

fn residual_transfer_input(reviewed: &ReviewedReclaimPlan) -> ProposalInput {
    let plan = reviewed.plan();
    let mut agreement: AgreementDraft =
        parse_typed_json(include_bytes!("fixtures/agreement.json")).unwrap();
    agreement.network_profile_id = plan.request().network_profile_id.clone();
    agreement.recipients[0].address = plan.destination().address.clone();
    agreement.recipients[0].amount = plan.transfer_amount();
    agreement.funding_policy = FundingPolicy::Exact {
        target: plan.transfer_amount(),
    };
    ProposalInput {
        proposal_id: "synthetic-separate-reclaim-candidate".into(),
        previous_proposal_id: None,
        artifact_digest: None,
        effects_commitment: None,
        created_at: window().now,
        manifest: ProposalManifest {
            outputs: vec![ClaimedOutput {
                output_id: "recovery-destination".into(),
                address: plan.destination().address.clone(),
                amount: plan.transfer_amount(),
                allocation: OutputAllocation::Recipient {
                    recipient_id: agreement.recipients[0].recipient_id.clone(),
                },
            }],
            agreement,
            participants: vec![ParticipantAllocation {
                participant_id: "recovery-owner".into(),
                account_id: plan.request().account_id.clone(),
                contribution: plan.transfer_amount(),
                fee_share: plan.fee(),
                fee_cap: plan.request().maximum_fee,
                maximum_net_debit: plan.maximum_net_debit(),
                charges: vec![],
            }],
            inputs: plan
                .inputs()
                .iter()
                .map(|i| ClaimedInput {
                    input_id: i.input_id.clone(),
                    participant_id: "recovery-owner".into(),
                    account_id: plan.request().account_id.clone(),
                    amount: i.amount,
                    ownership_evidence_ref: None,
                })
                .collect(),
            transaction_fee: plan.fee(),
            expiry_height: 3_000_000,
        },
    }
}

#[test]
fn residual_single_owner_is_separate_typed_purpose_and_cannot_roundtrip_as_ordinary() {
    use wholepact_core::retirement::transfer::ResidualTransferProposal;
    let reviewed = reviewed_plan();
    let input = residual_transfer_input(&reviewed);
    assert!(Proposal::validate(input.clone()).is_err());
    assert!(validate_claimed_accounting(&input.manifest).is_err());
    let residual = ResidualTransferProposal::bind(&reviewed, input.clone()).unwrap();
    residual.revalidate().unwrap();
    assert!(!residual.accounting().authorization_allowed);
    assert_ne!(
        residual.manifest_digest(),
        wholepact_core::proposal::canonical_digest("wholepact:manifest:v1", &input.manifest)
            .unwrap()
    );
    let serialized_input = serde_json::to_vec(residual.input()).unwrap();
    assert!(Proposal::validate(serde_json::from_slice(&serialized_input).unwrap()).is_err());
}

#[test]
fn residual_binding_rejects_changed_effects_caps_inputs_and_ordinary_replacement() {
    use wholepact_core::retirement::transfer::ResidualTransferProposal;
    let reviewed = reviewed_plan();
    let base = residual_transfer_input(&reviewed);
    let changes: [fn(&mut ProposalInput); 16] = [
        |i| i.manifest.participants[0].account_id = "different-source".into(),
        |i| i.manifest.outputs[0].address = "udifferentsyntheticdestination".into(),
        |i| i.manifest.outputs[0].amount = a(989),
        |i| i.manifest.transaction_fee = a(11),
        |i| i.manifest.participants[0].fee_cap = a(21),
        |i| i.manifest.participants[0].maximum_net_debit = a(1001),
        |i| i.manifest.inputs[0].input_id = "different-input".into(),
        |i| i.manifest.inputs[0].amount = a(1001),
        |i| i.previous_proposal_id = Some("original-payment".into()),
        |i| i.artifact_digest = Some(hash(3)),
        |i| i.effects_commitment = Some(hash(4)),
        |i| i.manifest.agreement.network_profile_id = "different-network".into(),
        |i| i.manifest.agreement.recipients[0].memo = Some("unexpected memo".into()),
        |i| i.manifest.expiry_height = 0,
        |i| {
            i.manifest
                .participants
                .push(i.manifest.participants[0].clone())
        },
        |i| i.manifest.outputs.push(i.manifest.outputs[0].clone()),
    ];
    for change in changes {
        let mut input = base.clone();
        change(&mut input);
        assert!(ResidualTransferProposal::bind(&reviewed, input).is_err());
    }
}

#[test]
fn residual_commitment_binds_exact_review_and_destination_pool() {
    use wholepact_core::retirement::transfer::ResidualTransferProposal;
    let original = reviewed_plan();
    let before =
        ResidualTransferProposal::bind(&original, residual_transfer_input(&original)).unwrap();
    let mut source = SyntheticRecovery::default();
    source.destination.pool = ShieldedReceiverPool::Ironwood;
    let plan = AccountRetirementPlan::prepare(&mut source, reclaim_request(), &window()).unwrap();
    let reviewed = plan
        .review_for_separate_authorization(
            &mut source,
            &mut SyntheticReclaimReview(ReclaimReviewDecision::Accepted {
                plan_digest: plan.digest().into(),
                review_record_ref: "different-native-review".into(),
            }),
            &window(),
        )
        .unwrap();
    let after =
        ResidualTransferProposal::bind(&reviewed, residual_transfer_input(&reviewed)).unwrap();
    assert_ne!(before.manifest_digest(), after.manifest_digest());
    assert_ne!(before.proposal_digest(), after.proposal_digest());
}
