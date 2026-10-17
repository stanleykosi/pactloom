//! Connected, offline, never-funded acceptance fixture. One maintained Halo2 proof
//! is reused through every production-shaped bridge below. The only synthetic
//! authority issuers are private to this test module; this is not product acceptance.
use super::recipient_source::*;
use super::record_source::*;
use super::*;
use crate::Result;
use crate::{
    backups::*,
    candidates::{CandidateRequest, LocalConstruction, PROFILE_ID},
    participant_records::*,
    planning::RosterSelectionRequest,
    proof_jobs::{LocalCheckpoint, LocalProofJob},
};
use orchard::keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey};
use rand::{Rng, rand_core::UnwrapErr, rngs::SysRng};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use wholepact_chain as chain;
use wholepact_core::*;
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, ProofJobStore};
use wholepact_protocol::{
    authorization::retention::{
        SignedResultJournal, SignedRetentionConsent, SignedRetentionScope,
        transaction::{
            LocalTransactionCheckpoint, RecoveryAction, TransactionCheckpointJournal,
            TransactionRecoveryConsent, TransactionRecoveryScope, TransactionRetentionConsent,
            TransactionRetentionScope,
            recipient::{
                RecipientObservationError, RecipientViewingKeyLease, RecipientViewingKeySource,
                RecipientViewingScope,
            },
            submission_handoff::{
                LocalSubmissionHandoff, SubmissionHandoffConsent, SubmissionHandoffScope,
            },
        },
    },
    construction::*,
    proving::ProvingLimits,
    review::encode_testnet_receiver,
};
use wholepact_storage_security::{DatabaseKey, bundle, create_encrypted, open_encrypted};
use wholepact_store::Store;
use wholepact_transport as transport;

const PRINCIPAL: &str = "connected-synthetic-controller";
const OPERATOR: &str = "connected-synthetic-local-prover";
const PURPOSE: &str = "Offline never-funded connected-flow fixture";
const RETENTION: &str = "Temporary encrypted test directory only; no distribution";
const AGREEMENT: &str = "connected-synthetic-agreement";
const OBLIGATION: &str = "connected-never-funded-obligation";
const SIGNATURE_KEY: &str = "connected-retain-signatures";
const SUBMISSION_OPERATION: &str = "connected-synthetic-submit";
const NOW: u64 = 1_800_000_020;

fn amount(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}
// Numeric slots below identify journals only; every key is freshly generated.
// This single owner keeps reopen/recovery and signing tied to the same run.
struct FixtureSecrets {
    owners: wholepact_wallet::wallet::SyntheticContributionFixture,
    databases: BTreeMap<u8, DatabaseKey>,
    recipient: transport::TransportSecret,
    senders: [transport::TransportSecret; 2],
}
impl FixtureSecrets {
    fn generate() -> Self {
        Self {
            owners: wholepact_wallet::wallet::SyntheticContributionFixture::generate(),
            databases: [81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 94]
                .into_iter()
                .map(|slot| (slot, DatabaseKey::from_bytes(random_fixture_bytes())))
                .collect(),
            recipient: random_transport_secret(),
            senders: [random_transport_secret(), random_transport_secret()],
        }
    }
    fn key(&self, slot: u8) -> &DatabaseKey {
        self.databases
            .get(&slot)
            .expect("known fixture journal slot")
    }
}
fn random_fixture_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    UnwrapErr(SysRng).fill_bytes(&mut bytes);
    bytes
}
fn random_transport_secret() -> transport::TransportSecret {
    loop {
        if let Ok(secret) = transport::TransportSecret::from_bytes(random_fixture_bytes()) {
            return secret;
        }
    }
}
fn timestamp(seconds: u64) -> transport::Timestamp {
    transport::Timestamp::from_unix_seconds(seconds as i64).unwrap()
}

struct Fixture {
    secrets: FixtureSecrets,
    request: CandidateRequest,
    context: ConstructionContext,
    packages: Vec<OwnedContribution>,
}
fn fixture() -> Fixture {
    let secrets = FixtureSecrets::generate();
    let (wallets, selection) = secrets.owners.scanned_contributions().unwrap();
    let receiver = encode_testnet_receiver(&wallets[0].notes()[0].note.recipient());
    let agreement = AgreementDraft {
        schema_version: 1,
        agreement_id: AGREEMENT.into(),
        obligation_id: OBLIGATION.into(),
        revision: 1,
        purpose: PURPOSE.into(),
        organizer_identity: PRINCIPAL.into(),
        network_profile_id: PROFILE_ID.into(),
        recipients: vec![Recipient {
            recipient_id: "synthetic-recipient".into(),
            address: receiver.clone(),
            amount: amount(300_000),
            memo: None,
            instruction_provenance: "Never-funded synthetic owner receiver".into(),
        }],
        funding_policy: FundingPolicy::Exact {
            target: amount(300_000),
        },
        fee_policy: FeePolicy::ProRata,
        privacy_profile: PrivacyProfile {
            mode: PrivacyMode::DeclaredOperator,
            proving_operator: Some(OPERATOR.into()),
            dedicated_accounts_required: true,
        },
        coordination_deadline: None,
        confirmation_policy: wholepact_core::ConfirmationPolicy::default(),
        extensions: vec![],
    };
    let participants: Vec<_> = wallets
        .iter()
        .enumerate()
        .map(|(index, wallet)| ParticipantAllocation {
            participant_id: format!("synthetic-participant-{index}"),
            account_id: wallet.account_id().into(),
            contribution: amount(if index == 0 { 100_000 } else { 200_000 }),
            fee_share: amount(if index == 0 { 5_000 } else { 10_000 }),
            fee_cap: amount(if index == 0 { 5_000 } else { 10_000 }),
            maximum_net_debit: amount(wallet.requested_debit_zatoshis()),
            charges: vec![],
        })
        .collect();
    let mut inputs = vec![];
    let mut outputs = vec![ClaimedOutput {
        output_id: "synthetic-recipient-output".into(),
        address: receiver,
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: "synthetic-recipient".into(),
        },
    }];
    for (index, wallet) in wallets.iter().enumerate() {
        for note in wallet.notes() {
            inputs.push(ClaimedInput {
                input_id: note.input_id.clone(),
                participant_id: participants[index].participant_id.clone(),
                account_id: wallet.account_id().into(),
                amount: amount(note.note.value().inner()),
                ownership_evidence_ref: None,
            });
        }
        outputs.push(ClaimedOutput {
            output_id: format!("synthetic-change-{index}"),
            address: encode_testnet_receiver(&wallet.change_address()),
            amount: amount(wallet.selected_zatoshis() - wallet.requested_debit_zatoshis()),
            allocation: OutputAllocation::Return {
                participant_id: participants[index].participant_id.clone(),
                account_id: wallet.account_id().into(),
                ownership_evidence_ref: None,
            },
        });
    }
    Fixture {
        secrets,
        request: CandidateRequest {
            manifest: ProposalManifest {
                agreement,
                participants,
                inputs,
                outputs,
                transaction_fee: amount(15_000),
                expiry_height: selection.tip_height + 30,
            },
            previous_candidate_id: None,
        },
        context: ConstructionContext {
            anchor: selection.anchor_root,
            anchor_height: selection.anchor_height,
            anchor_block_hash: selection.anchor_hash_protocol,
            target_height: selection.tip_height + 1,
        },
        packages: wallets
            .into_iter()
            .map(|wallet| wallet.into_contribution())
            .collect(),
    }
}

/// Exact test-only privacy gates. No corresponding runtime authority is enrolled.
struct FixturePrivacy {
    candidate_id: String,
    manifest_digest: String,
    account_ids: Vec<String>,
    allowed: AtomicBool,
}
impl FixturePrivacy {
    fn context_matches(&self, context: &SignedCandidateContext) -> bool {
        self.allowed.load(Ordering::SeqCst)
            && context.principal_id == PRINCIPAL
            && context.candidate_id == self.candidate_id
            && context.manifest_digest == self.manifest_digest
            && context.account_ids == self.account_ids
            && context.local_operator == OPERATOR
            && context.purpose == PURPOSE
            && context.retention_policy == RETENTION
    }
}
impl LocalProofConsent for FixturePrivacy {
    fn permits(&self, scope: &CheckpointScope, _: LocalAction) -> bool {
        self.allowed.load(Ordering::SeqCst)
            && scope.principal_id == PRINCIPAL
            && scope.candidate_id == self.candidate_id
            && scope.manifest_digest == self.manifest_digest
            && scope.account_ids == self.account_ids
            && scope.local_operator == OPERATOR
            && scope.purpose == PURPOSE
            && scope.retention_policy == RETENTION
            && scope.coordination_request_digest.len() == 64
            && scope.review_binding.len() == 64
    }
}
impl SignedRetentionConsent for FixturePrivacy {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        self.context_matches(&scope.context) && scope.signature_set_digest.len() == 64
    }
}
impl TransactionRetentionConsent for FixturePrivacy {
    fn permits(&self, scope: &TransactionRetentionScope) -> bool {
        SignedRetentionConsent::permits(self, &scope.signed_scope)
            && scope.signed_candidate_digest.len() == 64
            && scope.signed_request_digest.len() == 64
    }
}
impl SubmissionHandoffConsent for FixturePrivacy {
    fn permits(&self, scope: &SubmissionHandoffScope<'_>) -> bool {
        TransactionRetentionConsent::permits(self, scope.retained)
            && scope.descriptor.obligation_id == OBLIGATION
            && scope.descriptor.operation_id == SUBMISSION_OPERATION
            && scope.backend.trust_profile == "synthetic_never_chain_evidence"
            && !scope.destination_journal_identity.is_empty()
    }
}

/// Test-only authority checks the exact cryptographically extracted transaction.
/// It cannot be imported into a library build or construed as human approval.
struct FixtureAuthority {
    expected: chain::SubmissionDescriptor,
    allowed: Arc<AtomicBool>,
}
struct FixturePermit {
    expected: chain::SubmissionDescriptor,
    allowed: Arc<AtomicBool>,
}
fn check_authority(
    expected: &chain::SubmissionDescriptor,
    allowed: &AtomicBool,
    review: &chain::SubmissionReview<'_>,
) -> std::result::Result<(), chain::ChainError> {
    if !allowed.load(Ordering::SeqCst)
        || review.descriptor != expected
        || review.backend.trust_profile != "synthetic_never_chain_evidence"
        || review.backend != review.context.source()
        || review.journal_identity.is_empty()
    {
        return Err(chain::ChainError::SubmissionNotAuthorized);
    }
    review.context.check_fresh_at(review.now_unix_seconds)
}
impl chain::SubmissionAuthority for FixtureAuthority {
    type Permit = FixturePermit;
    fn authorize(
        &mut self,
        review: &chain::SubmissionReview<'_>,
    ) -> std::result::Result<FixturePermit, chain::ChainError> {
        check_authority(&self.expected, &self.allowed, review)?;
        Ok(FixturePermit {
            expected: self.expected.clone(),
            allowed: self.allowed.clone(),
        })
    }
}
impl chain::SubmissionPermit for FixturePermit {
    fn check_current(
        &mut self,
        review: &chain::SubmissionReview<'_>,
    ) -> std::result::Result<(), chain::ChainError> {
        check_authority(&self.expected, &self.allowed, review)
    }
}
struct FixtureClock(u64);
impl chain::SubmissionClock for FixtureClock {
    fn now_unix_seconds(&self) -> std::result::Result<u64, chain::ChainError> {
        Ok(self.0)
    }
}
struct OfflineBackend {
    context: chain::ChainContext,
    calls: Vec<Vec<u8>>,
    outcomes: VecDeque<std::result::Result<chain::BackendSubmissionResult, chain::ChainError>>,
    pending: bool,
}
impl chain::SubmissionBackend for OfflineBackend {
    fn identity(&self) -> &chain::BackendIdentity {
        self.context.source()
    }
    fn fresh_context(
        &mut self,
    ) -> chain::SubmissionFuture<'_, std::result::Result<chain::ChainContext, chain::ChainError>>
    {
        Box::pin(async { Ok(self.context.clone()) })
    }
    fn submit_exact<'a>(
        &'a mut self,
        dispatch: chain::PreparedDispatch<'a>,
    ) -> chain::SubmissionFuture<
        'a,
        std::result::Result<chain::BackendSubmissionResult, chain::ChainError>,
    > {
        Box::pin(async move {
            assert_eq!(dispatch.backend(), self.context.source());
            assert!(NOW <= dispatch.valid_until_unix_seconds());
            self.calls.push(dispatch.exact_bytes().to_vec());
            if self.pending {
                std::future::pending().await
            } else {
                self.outcomes
                    .pop_front()
                    .expect("one explicit outcome per dispatch")
            }
        })
    }
}

struct BackupGate {
    source: LocalBackupSource,
    archive: PathBuf,
    destination: Option<PathBuf>,
    action: FullJournalBackupAction,
}
struct BackupLease;
impl FullJournalBackupLease for BackupLease {
    fn still_authorized(&self) -> bool {
        true
    }
}
impl FullJournalBackupConsent for BackupGate {
    fn acquire<'a>(
        &'a self,
        scope: &'a FullJournalBackupScope<'_>,
    ) -> Option<Box<dyn FullJournalBackupLease + 'a>> {
        (scope.source().matches_binding(&self.source)
            && scope.principal_id() == PRINCIPAL
            && scope.archive_path() == self.archive
            && scope.restore_destination() == self.destination.as_deref()
            && scope.action() == self.action
            && scope.retention_policy() == "local-only; retain until deliberately removed"
            && scope.includes_all_principals_and_profiles()
            && scope.backup_key_loss_is_unrecoverable())
        .then(|| Box::new(BackupLease) as Box<dyn FullJournalBackupLease>)
    }
}

fn iso(seconds: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(seconds as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
struct RecordAuthority {
    binding: RecordStoreBinding,
    participant_id: String,
    account_id: String,
    allowed: AtomicBool,
}
struct RecordLease<'a> {
    authority: &'a RecordAuthority,
    scope: ParticipantRecordScope,
    expiry: String,
}
impl ParticipantRecordAuthority for RecordAuthority {
    fn acquire<'a>(
        &'a self,
        scope: &ParticipantRecordScope,
        window: &wholepact_core::records::ObservationWindow,
    ) -> Result<Box<dyn ParticipantRecordLease + 'a>> {
        if !self.allowed.load(Ordering::SeqCst)
            || scope.store != self.binding
            || scope.profile_id != "synthetic-record-profile"
            || scope.principal_id != PRINCIPAL
            || scope.agreement_id != AGREEMENT
            || scope.record_id != "connected-private-record"
            || scope.participant_id != self.participant_id
            || scope.account_id != self.account_id
        {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic record authority scope differs",
            ));
        }
        assert!(window.now < iso(NOW + 60));
        Ok(Box::new(RecordLease {
            authority: self,
            scope: scope.clone(),
            expiry: iso(NOW + 60),
        }))
    }
}
impl ParticipantRecordLease for RecordLease<'_> {
    fn scope(&self) -> &ParticipantRecordScope {
        &self.scope
    }
    fn expires_at(&self) -> &str {
        &self.expiry
    }
    fn check_current(&self) -> Result<()> {
        if self.authority.allowed.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic record authority revoked",
            ))
        }
    }
}
/// Only this test can issue consent provenance for the public never-funded
/// fixture. The reference is an original encrypted record saved before signing.
struct OriginalConsentAuthority {
    journal: Arc<Store>,
    consent_id: String,
    authorization_id: String,
    allowed: AtomicBool,
}
struct OriginalConsentLease<'a> {
    authority: &'a OriginalConsentAuthority,
    scope: OriginalAuthorizationConsentScope,
    expiry: transport::Timestamp,
}
fn original_consent_payload(scope: &OriginalAuthorizationConsentScope) -> serde_json::Value {
    serde_json::json!({
        "synthetic_never_human_approval": true,
        "principal_id": scope.principal_id, "agreement_id": scope.agreement_id,
        "candidate_id": scope.candidate_id, "participant_id": scope.participant_id,
        "account_id": scope.account_id, "authorization_id": scope.authorization_id,
        "release_intent_digest": scope.release_intent_digest, "manifest_digest": scope.manifest_digest,
        "effects_commitment": scope.effects_commitment, "proved_artifact_digest": scope.proved_artifact_digest,
        "review_binding": scope.review_binding, "input_ids": scope.input_ids,
        "maximum_net_debit": scope.exact_net_debit.as_zatoshis().to_string(),
    })
}
impl OriginalConsentAuthority {
    fn check(&self, scope: &OriginalAuthorizationConsentScope) -> Result<()> {
        let reject = || {
            ApiError::new(
                "ORIGINAL_AUTHORIZATION_HISTORY_MISSING",
                "Synthetic original consent is absent or differs",
            )
        };
        if !self.allowed.load(Ordering::SeqCst) || scope.authorization_id != self.authorization_id {
            return Err(reject());
        }
        let original = self
            .journal
            .get_record("synthetic_original_consent", &self.consent_id)
            .map_err(|_| reject())?
            .ok_or_else(reject)?;
        let release = self
            .journal
            .exposure(&self.authorization_id)
            .map_err(|_| reject())?
            .ok_or_else(reject)?;
        if original.revision != 1
            || original.payload != original_consent_payload(scope)
            || original.created_at_ms > release.created_at_ms
        {
            return Err(reject());
        }
        Ok(())
    }
}
impl OriginalAuthorizationConsentSource for OriginalConsentAuthority {
    fn acquire<'a>(
        &'a self,
        scope: &OriginalAuthorizationConsentScope,
        release_journal: &Store,
        now: &transport::Timestamp,
    ) -> Result<Box<dyn OriginalAuthorizationConsentLease + 'a>> {
        if !std::ptr::eq(self.journal.as_ref(), release_journal)
            || now.unix_seconds() >= (NOW + 60) as i64
        {
            return Err(ApiError::new(
                "ORIGINAL_AUTHORIZATION_HISTORY_MISSING",
                "Synthetic original consent store or time differs",
            ));
        }
        self.check(scope)?;
        Ok(Box::new(OriginalConsentLease {
            authority: self,
            scope: scope.clone(),
            expiry: timestamp(NOW + 60),
        }))
    }
}
impl OriginalAuthorizationConsentLease for OriginalConsentLease<'_> {
    fn scope(&self) -> &OriginalAuthorizationConsentScope {
        &self.scope
    }
    fn original_consent_record_ref(&self) -> &str {
        &self.authority.consent_id
    }
    fn expires_at(&self) -> &transport::Timestamp {
        &self.expiry
    }
    fn check_current(&self) -> Result<()> {
        self.authority.check(&self.scope)
    }
}
impl TransactionRecoveryConsent for FixturePrivacy {
    fn permits(&self, scope: &TransactionRecoveryScope<'_>) -> bool {
        scope.action == RecoveryAction::InspectExistingIntent
            && TransactionRetentionConsent::permits(self, scope.retention)
    }
}

/// Exact recipient viewing permission for this never-funded fixture only. No
/// contributor consent, coordinator assertion or database possession grants it.
struct RecipientFixtureAuthority<'a> {
    journal: &'a TransactionCheckpointJournal,
    scope: RecipientViewingScope,
    viewing_key: FullViewingKey,
    allowed: AtomicBool,
}
struct RecipientFixtureLease<'a> {
    authority: &'a RecipientFixtureAuthority<'a>,
}
impl RecipientViewingKeySource for RecipientFixtureAuthority<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &RecipientViewingScope,
        journal: &TransactionCheckpointJournal,
        now: u64,
    ) -> std::result::Result<Box<dyn RecipientViewingKeyLease + 'a>, RecipientObservationError>
    {
        if scope != &self.scope
            || !std::ptr::eq(self.journal, journal)
            || now >= NOW + 60
            || !self.allowed.load(Ordering::SeqCst)
        {
            return Err(RecipientObservationError::ConsentDenied);
        }
        Ok(Box::new(RecipientFixtureLease { authority: self }))
    }
}
impl RecipientViewingKeyLease for RecipientFixtureLease<'_> {
    fn scope(&self) -> &RecipientViewingScope {
        &self.authority.scope
    }
    fn viewing_key(&self) -> &FullViewingKey {
        &self.authority.viewing_key
    }
    fn expires_at_unix_seconds(&self) -> u64 {
        NOW + 60
    }
    fn check_current(&self) -> std::result::Result<(), RecipientObservationError> {
        if self.authority.allowed.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(RecipientObservationError::ConsentDenied)
        }
    }
}

struct RecordObservation {
    exact: wholepact_core::records::ExactTransactionReference,
    report: chain::ReconciliationReport,
}
impl wholepact_core::records::SettlementObservationSource for RecordObservation {
    fn observe_exact_transaction(
        &mut self,
        expected: &wholepact_core::records::ExactTransactionReference,
    ) -> wholepact_core::Result<wholepact_core::records::SourcedChainObservation> {
        assert_eq!(expected, &self.exact);
        assert_eq!(self.report.transaction_id, expected.transaction_id);
        assert!(
            !self.report.independently_consensus_verified
                && !self.report.clears_authorization_exposure
                && !self.report.permits_replacement
        );
        let (status, inclusion, confirmations) = match &self.report.state {
            chain::SettlementObservationState::ConfirmationPolicyMet {
                block,
                confirmations,
            } => (
                ChainStatus::ConfirmationPolicyMet,
                Some(block),
                *confirmations as u32,
            ),
            chain::SettlementObservationState::Reorganized => (ChainStatus::Reorganized, None, 0),
            _ => {
                panic!("fixture covers only explicit confirmation and reorganization observations")
            }
        };
        let tip = &self.report.source_tips[0];
        Ok(wholepact_core::records::SourcedChainObservation {
            transaction: self.exact.clone(),
            adapter_id: "synthetic-chain-to-record".into(),
            observation: ChainObservation {
                observation_id: format!(
                    "synthetic-observation-{}",
                    self.report.observed_at_unix_seconds
                ),
                source_id: tip.source_id.clone(),
                trust_profile_id: "synthetic_never_chain_evidence".into(),
                observed_at: iso(self.report.observed_at_unix_seconds),
                tip_height: tip.tip.height as u32,
                tip_hash: tip.tip.hash.clone(),
                synchronized: true,
                status,
                inclusion_height: inclusion.map(|block| block.height as u32),
                inclusion_hash: inclusion.map(|block| block.hash.clone()),
                confirmations,
                evidence_ref: SUBMISSION_OPERATION.into(),
            },
        })
    }
}

struct AutomationFixtureTrust {
    store: Arc<Store>,
    policy: wholepact_core::automation::AutomationAccountPolicy,
    terms: wholepact_core::automation::AutomationGrantTerms,
    request: wholepact_core::automation::AutomationRequest,
    participant_id: String,
    review_binding: String,
    authorization_consent_id: &'static str,
    held: Arc<AtomicBool>,
}
struct AutomationFixtureLease {
    scope: wholepact_store::automation::AutomationReview,
    held: Arc<AtomicBool>,
    consent: &'static str,
}
impl Drop for AutomationFixtureLease {
    fn drop(&mut self) {
        self.held.store(false, Ordering::SeqCst);
    }
}
impl wholepact_store::automation::AutomationLease for AutomationFixtureLease {
    fn check_current(
        &self,
        review: &wholepact_store::automation::AutomationReview,
        now: u64,
    ) -> wholepact_store::automation::Result<()> {
        if !self.held.load(Ordering::SeqCst) || review != &self.scope || now != NOW * 1000 {
            return Err(wholepact_store::automation::AutomationError::Denied);
        }
        Ok(())
    }
    fn consent_reference(&self) -> &str {
        self.consent
    }
}
impl wholepact_store::automation::AutomationTrustSource for AutomationFixtureTrust {
    type Lease = AutomationFixtureLease;
    fn verifier_id(&self) -> &str {
        "synthetic-automation-verifier"
    }
    fn now_ms(&self) -> wholepact_store::automation::Result<u64> {
        Ok(NOW * 1000)
    }
    fn acquire(
        &self,
        review: &wholepact_store::automation::AutomationReview,
    ) -> wholepact_store::automation::Result<Self::Lease> {
        use wholepact_store::automation::{AutomationError, AutomationReview};
        let (valid, consent, kind) = match review {
            AutomationReview::ConfigureAccount { policy, previous } => (
                policy == &self.policy && previous.is_none(),
                "synthetic-account-policy-consent",
                "synthetic_automation_consent",
            ),
            AutomationReview::CreateGrant { terms, account } => (
                terms == &self.terms && account.policy == self.policy,
                "synthetic-bounded-grant-consent",
                "synthetic_automation_consent",
            ),
            AutomationReview::ChangeGrant { grant, .. } => (
                grant.terms == self.terms,
                "synthetic-bounded-grant-consent",
                "synthetic_automation_consent",
            ),
            AutomationReview::Authorize {
                account,
                grant,
                request,
            } => (
                account.policy == self.policy
                    && grant.terms == self.terms
                    && **request == self.request,
                self.authorization_consent_id,
                "synthetic_original_consent",
            ),
        };
        let expected_payload = match review {
            AutomationReview::ConfigureAccount { .. } => {
                serde_json::json!({ "synthetic_never_human_approval": true, "account_policy": self.policy })
            }
            AutomationReview::CreateGrant { .. } | AutomationReview::ChangeGrant { .. } => {
                serde_json::json!({ "synthetic_never_human_approval": true,
                "account_policy": self.policy, "grant_terms": self.terms })
            }
            AutomationReview::Authorize { .. } => {
                let request = &self.request;
                let release = wholepact_store::authority::ReleaseIntent {
                    authorization_id: request.authorization_id.clone(),
                    account_id: request.account_id.clone(),
                    writer_epoch: request.writer_epoch,
                    obligation_id: request.obligation_id.clone(),
                    proposal_id: request.proposal_id.clone(),
                    manifest_digest: request.manifest_digest.clone(),
                    effects_digest: request.effects_digest.clone(),
                    artifact_digest: request.artifact_digest.clone(),
                    maximum_debit: request.maximum_debit.as_zatoshis().to_string(),
                    input_ids: request.input_ids.clone(),
                    aggregate_budget_limit: self
                        .policy
                        .maximum_outstanding_debit
                        .as_zatoshis()
                        .to_string(),
                };
                original_consent_payload(&OriginalAuthorizationConsentScope {
                    principal_id: PRINCIPAL.into(),
                    agreement_id: request.agreement_id.clone(),
                    candidate_id: request.proposal_id.clone(),
                    participant_id: self.participant_id.clone(),
                    account_id: request.account_id.clone(),
                    authorization_id: request.authorization_id.clone(),
                    release_intent_digest: wholepact_store::request_digest(
                        &serde_json::to_value(release).unwrap(),
                    )
                    .unwrap(),
                    manifest_digest: request.manifest_digest.clone(),
                    effects_commitment: request.effects_digest.clone(),
                    proved_artifact_digest: request.artifact_digest.clone(),
                    review_binding: self.review_binding.clone(),
                    input_ids: request.input_ids.clone(),
                    exact_net_debit: request.maximum_debit,
                })
            }
        };
        let retained = self
            .store
            .get_record(kind, consent)
            .map_err(|_| AutomationError::Denied)?
            .ok_or(AutomationError::Denied)?;
        if !valid
            || retained.revision != 1
            || retained.payload != expected_payload
            || self
                .held
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return Err(AutomationError::Denied);
        }
        // Fixture has one synchronous owner and no other writers. The held
        // account lease spans actual signing and its separate encrypted commit.
        Ok(AutomationFixtureLease {
            scope: review.clone(),
            held: self.held.clone(),
            consent,
        })
    }
}
struct AutomationFixtureSigner<'a> {
    spending_key: &'a SpendingKey,
    request: &'a wholepact_core::automation::AutomationRequest,
    checkpoint: &'a wholepact_proof_jobs::VerifiedCheckpoint,
    held: Arc<AtomicBool>,
    storage: &'a Store,
    signed: Option<pczt::Pczt>,
    calls: usize,
}
impl wholepact_store::automation::AutomaticAuthorizer for AutomationFixtureSigner<'_> {
    fn signer_id(&self) -> &str {
        "synthetic-automation-signer"
    }
    fn authorize_exact(
        &mut self,
        prepared: wholepact_store::automation::PreparedAutomaticAuthorization<'_>,
    ) -> wholepact_store::automation::Result<
        wholepact_store::automation::AutomaticAuthorizationOutcome,
    > {
        use wholepact_store::automation::{AutomaticAuthorizationOutcome, AutomationError};
        assert!(self.held.load(Ordering::SeqCst));
        assert_eq!(&prepared.record().request, self.request);
        assert_eq!(
            prepared.record().original_activation_consent_reference,
            "synthetic-bounded-grant-consent"
        );
        assert_eq!(
            prepared.record().authorization_verification_reference,
            "synthetic-original-consent-0"
        );
        assert_eq!(
            hex::encode(Sha256::digest(self.checkpoint.pczt_bytes())),
            self.request.artifact_digest
        );
        let review = wholepact_protocol::review::verify_review(
            self.checkpoint.pczt_bytes(),
            self.checkpoint.policy(),
        )
        .map_err(|_| AutomationError::Denied)?;
        assert_eq!(review.shielded_sighash(), self.request.effects_digest);
        assert_eq!(
            review.net_debits_zatoshis()[0],
            self.request.maximum_debit.as_zatoshis()
        );
        let mut signer = pczt::roles::signer::Signer::new(
            pczt::Pczt::parse(self.checkpoint.pczt_bytes()).unwrap(),
        )
        .unwrap();
        prepared.check_current()?;
        for input in self
            .checkpoint
            .policy()
            .inputs
            .iter()
            .filter(|input| input.participant_index == 0)
        {
            prepared.check_current()?;
            signer
                .sign_ironwood(
                    UnwrapErr(SysRng),
                    input.action_index,
                    &SpendAuthorizingKey::from(self.spending_key),
                )
                .unwrap();
        }
        let signed = signer.finish();
        let payload = serde_json::json!({ "synthetic_never_human_approval": true, "request": self.request,
            "signed_pczt_hex": hex::encode(signed.clone().serialize().unwrap()) });
        let command = wholepact_store::CommandContext::for_request(
            "synthetic-local-signer",
            "synthetic-retain-authorized-pczt",
            &payload,
        )
        .unwrap();
        self.storage
            .commit_record(
                &command,
                "synthetic_signer_result",
                &self.request.authorization_id,
                None,
                payload,
                "synthetic_signer_result_retained",
            )
            .map_err(|_| AutomationError::Unavailable)?;
        assert!(self.held.load(Ordering::SeqCst));
        self.signed = Some(signed);
        self.calls += 1;
        Ok(AutomaticAuthorizationOutcome::RetainedLocally)
    }
}

/// Snapshot phase is synchronous and has no background writers or pending
/// dispatches. This fixture-only lease exact-binds the full enrolled profile;
/// production embeddings must supply their actual whole-profile writer fence.
struct BundleFixtureAuthority {
    action: bundle::BundleAction,
    archive: PathBuf,
    destinations: Vec<PathBuf>,
    coverage: bundle::Coverage,
    sources: Vec<(String, bundle::JournalBinding)>,
    fence: Mutex<()>,
}
struct BundleFixtureLease<'a> {
    _held: MutexGuard<'a, ()>,
}
impl bundle::BundleLease for BundleFixtureLease<'_> {
    fn check_current(&self) -> std::result::Result<(), bundle::BundleError> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "synthetic-whole-profile-quiescent-checkpoint"
    }
}
impl bundle::BundleAuthority for BundleFixtureAuthority {
    fn acquire<'a>(
        &'a self,
        scope: &bundle::BundleScope<'_>,
    ) -> std::result::Result<Box<dyn bundle::BundleLease + 'a>, bundle::BundleError> {
        if scope.principal_id != PRINCIPAL
            || scope.profile_id != "synthetic-coordinator-profile"
            || scope.action != self.action
            || scope.archive != self.archive
            || scope.destinations != self.destinations
            || scope.coverage != &self.coverage
            || scope.sources != self.sources
            || scope.retention != "local-only; retain until deliberately removed"
            || scope.wallet_spending_secrets_included
            || !scope.private_viewing_witness_and_correlation_data_may_be_included
        {
            return Err(bundle::BundleError::Permission);
        }
        Ok(Box::new(BundleFixtureLease {
            _held: self
                .fence
                .lock()
                .map_err(|_| bundle::BundleError::Permission)?,
        }))
    }
}

fn assert_encrypted(path: &Path, canaries: &[&[u8]]) {
    for file in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
    ] {
        if let Ok(bytes) = std::fs::read(file) {
            assert!(!bytes.windows(16).any(|part| part == b"SQLite format 3\0"));
            for canary in canaries {
                assert!(!canary.is_empty());
                assert!(!bytes.windows(canary.len()).any(|part| part == *canary));
            }
        }
    }
}

#[test]
fn connected_never_funded_flow_uses_one_proof_and_preserves_exact_recovery_boundaries() {
    let Fixture {
        secrets,
        request,
        context,
        packages,
    } = fixture();
    // Same-run close/reopen/recovery remains exercised below. The former opt-in
    // retained-directory mode is intentionally gone: ephemeral private owners
    // are never serialized or retained for a later process.
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().to_path_buf();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let metadata_path = directory.as_path().join("coordination.db");
    let proof_path = directory.as_path().join("proof.db");
    let signed_path = directory.as_path().join("signed.db");
    let transaction_path = directory.as_path().join("transaction.db");
    let submission_path = directory.as_path().join("submission.db");
    let engine =
        Engine::from_store(Store::create_encrypted(&metadata_path, secrets.key(81)).unwrap());
    let access = Access {
        include_owned_agreements: true,
        principal_id: PRINCIPAL.into(),
        ..Access::default()
    };
    let created = engine
        .create(
            &access,
            "connected-create-agreement",
            request.manifest.agreement.clone(),
        )
        .unwrap();
    assert_eq!(created.agreement.revision, 1);
    assert!(
        engine
            .create(
                &access,
                "connected-create-agreement",
                request.manifest.agreement.clone()
            )
            .unwrap()
            .replayed
    );
    for (index, participant) in request.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &access,
                &format!("connected-add-intent-{index}"),
                AGREEMENT,
                index as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("synthetic-intent-{index}"),
                    agreement_id: AGREEMENT.into(),
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
    let selected = engine
        .select_roster(
            &access,
            "connected-select-roster",
            AGREEMENT,
            3,
            RosterSelectionRequest {
                selected_intent_ids: vec!["synthetic-intent-0".into(), "synthetic-intent-1".into()],
            },
        )
        .unwrap();
    assert!(selected.agreement.roster_selected);
    assert!(
        selected
            .agreement
            .intents
            .iter()
            .all(|intent| intent.status == IntentStatus::Selected)
    );
    let frozen = engine
        .create_candidate(
            &access,
            "connected-create-candidate",
            AGREEMENT,
            4,
            request.clone(),
        )
        .unwrap();
    let candidate = frozen.agreement.candidates[0].clone();
    let candidate_id = candidate.candidate_id.clone();
    let privacy = FixturePrivacy {
        candidate_id: candidate_id.clone(),
        manifest_digest: candidate.manifest_digest.clone(),
        account_ids: request
            .manifest
            .participants
            .iter()
            .map(|participant| participant.account_id.clone())
            .collect(),
        allowed: AtomicBool::new(true),
    };
    let declarations: Vec<_> = privacy
        .account_ids
        .iter()
        .map(|account_id| DisclosureAcknowledgement {
            account_id: account_id.clone(),
            manifest_digest: hex::decode(&candidate.manifest_digest)
                .unwrap()
                .try_into()
                .unwrap(),
            operator: OPERATOR.into(),
            reviewer_account_ids: privacy.account_ids.clone(),
            purpose: PURPOSE.into(),
            retention_policy: RETENTION.into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    let jobs = ProofJobStore::from_encrypted_connection(
        create_encrypted(&proof_path, secrets.key(82)).unwrap(),
    )
    .unwrap();
    let checkpointed = engine
        .checkpoint_candidate_locally(
            &access,
            "connected-checkpoint",
            &candidate_id,
            5,
            LocalCheckpoint {
                construction: LocalConstruction {
                    context,
                    contributions: packages,
                    declarations: &declarations,
                },
                jobs: &jobs,
                limits: ProvingLimits { maximum_actions: 8 },
                consent: &privacy,
            },
        )
        .unwrap();
    let job_id = checkpointed.agreement.candidates[0].proof_jobs[0]
        .job_id
        .clone();
    let checkpoint_revision = checkpointed.agreement.revision;
    drop(jobs);
    drop(engine);
    // Reopen independently encrypted stores before any expensive proof execution.
    let engine =
        Engine::from_store(Store::open_encrypted(&metadata_path, secrets.key(81)).unwrap());
    let jobs = ProofJobStore::from_encrypted_connection(
        open_encrypted(&proof_path, secrets.key(82)).unwrap(),
    )
    .unwrap();
    let local = || LocalProofJob {
        job_id: &job_id,
        jobs: &jobs,
        consent: &privacy,
    };
    let proved = engine
        .run_candidate_proof_locally(
            &access,
            "connected-prove-once",
            &candidate_id,
            checkpoint_revision,
            local(),
        )
        .unwrap();
    let proof_summary = &proved.agreement.candidates[0].proof_jobs[0];
    assert!(proof_summary.proof_verified && proof_summary.encrypted_checkpoint_created);
    assert!(
        !proof_summary.authorization_allowed
            && !proof_summary.distribution_allowed
            && !proof_summary.chain_validated
    );
    let repeated = engine
        .run_candidate_proof_locally(
            &access,
            "connected-prove-once",
            &candidate_id,
            checkpoint_revision,
            local(),
        )
        .unwrap();
    assert!(repeated.replayed);
    assert_eq!(repeated.operation_id, proved.operation_id);
    assert_eq!(repeated.agreement.candidates[0].proof_jobs[0].attempt, 1);
    let checkpoint = engine
        .load_candidate_proof_for_local_review(&access, &candidate_id, local())
        .unwrap();
    assert_eq!(
        checkpoint.scope().manifest_digest,
        candidate.manifest_digest
    );
    assert_eq!(checkpoint.policy().participants.len(), 2);
    let private_fvk = checkpoint.policy().participants[0].fvk.to_bytes();
    let original_proof_digest = hex::encode(Sha256::digest(checkpoint.pczt_bytes()));
    // Synthetic attended decisions are retained before signing, and real
    // production journal APIs fence every usable authorization before delivery.
    // No fixture decision is presented as a real person's approval.
    let reviewed =
        wholepact_protocol::review::verify_review(checkpoint.pczt_bytes(), checkpoint.policy())
            .unwrap();
    let mut release_intents = Vec::new();
    for (owner, participant) in request.manifest.participants.iter().enumerate() {
        let mut input_ids: Vec<_> = checkpoint
            .policy()
            .inputs
            .iter()
            .filter(|input| input.participant_index == owner)
            .map(|input| hex::encode(input.nullifier))
            .collect();
        input_ids.sort();
        let release = wholepact_store::authority::ReleaseIntent {
            authorization_id: format!("synthetic-authorization-{owner}"),
            account_id: participant.account_id.clone(),
            writer_epoch: 1,
            obligation_id: OBLIGATION.into(),
            proposal_id: candidate_id.clone(),
            manifest_digest: candidate.manifest_digest.clone(),
            effects_digest: reviewed.shielded_sighash().into(),
            artifact_digest: checkpoint.summary().result_digest.clone().unwrap(),
            maximum_debit: reviewed.net_debits_zatoshis()[owner].to_string(),
            input_ids,
            aggregate_budget_limit: participant.maximum_net_debit.as_zatoshis().to_string(),
        };
        let original_consent_id = format!("synthetic-original-consent-{owner}");
        let release_digest =
            wholepact_store::request_digest(&serde_json::to_value(&release).unwrap()).unwrap();
        let original = serde_json::json!({
            "synthetic_never_human_approval": true,
            "principal_id": PRINCIPAL, "agreement_id": AGREEMENT, "candidate_id": candidate_id,
            "participant_id": participant.participant_id, "account_id": participant.account_id,
            "authorization_id": release.authorization_id, "release_intent_digest": release_digest,
            "manifest_digest": candidate.manifest_digest, "effects_commitment": reviewed.shielded_sighash(),
            "proved_artifact_digest": checkpoint.summary().result_digest,
            "review_binding": reviewed.review_binding(), "input_ids": release.input_ids,
            "maximum_net_debit": release.maximum_debit,
        });
        let command = wholepact_store::CommandContext::for_request(
            PRINCIPAL,
            format!("retain-{original_consent_id}"),
            &original,
        )
        .unwrap();
        engine
            .store
            .commit_record(
                &command,
                "synthetic_original_consent",
                &original_consent_id,
                None,
                original,
                "synthetic_original_consent_retained",
            )
            .unwrap();
        engine
            .store
            .initialize_authority_account(&participant.account_id, 1)
            .unwrap();
        if owner != 0 {
            let retained_release = engine
                .store
                .record_authorization_release_intent(&release)
                .unwrap();
            assert!(retained_release.release_intent_recorded);
            assert_eq!(
                retained_release.state,
                wholepact_store::authority::ExposureState::OutstandingUncertain
            );
            assert_eq!(
                engine
                    .store
                    .record_authorization_release_intent(&release)
                    .unwrap()
                    .intent,
                release
            );
        }
        release_intents.push(release);
    }
    use wholepact_core::automation as automatic;
    use wholepact_store::automation as automation_store;
    let owner = &request.manifest.participants[0];
    let receiver_fingerprint = hex::encode(Sha256::digest(
        wholepact_protocol::review::decode_testnet_receiver(
            &request.manifest.agreement.recipients[0].address,
        )
        .unwrap()
        .to_raw_address_bytes(),
    ));
    let policy = automatic::AutomationAccountPolicy {
        policy_id: "synthetic-account-wide-policy".into(),
        account_id: owner.account_id.clone(),
        writer_epoch: 1,
        maximum_outstanding_debit: owner.maximum_net_debit,
        valid_from_ms: NOW * 1000 - 1000,
        expires_at_ms: NOW * 1000 + 60_000,
    };
    let evidence_kinds = [
        automatic::AutomationEvidenceKind::AccountControl,
        automatic::AutomationEvidenceKind::RecipientInstructions,
        automatic::AutomationEvidenceKind::ExactEffects,
        automatic::AutomationEvidenceKind::CurrentChain,
        automatic::AutomationEvidenceKind::ExposureContinuity,
    ];
    let terms = automatic::AutomationGrantTerms {
        grant_id: "synthetic-bounded-grant".into(),
        application_id: PRINCIPAL.into(),
        account_id: owner.account_id.clone(),
        account_policy_id: policy.policy_id.clone(),
        writer_epoch: 1,
        network_profile: PROFILE_ID.into(),
        signer_id: "synthetic-automation-signer".into(),
        verifier_id: "synthetic-automation-verifier".into(),
        agreement_ids: vec![AGREEMENT.into()],
        recipient_fingerprints: vec![receiver_fingerprint.clone()],
        maximum_payment_debit: owner.maximum_net_debit,
        maximum_payment_fee: owner.fee_cap,
        maximum_outstanding_debit: owner.maximum_net_debit,
        evidence: evidence_kinds
            .iter()
            .map(|kind| automatic::AutomationEvidenceRequirement {
                kind: *kind,
                verifier_id: "synthetic-automation-verifier".into(),
                maximum_age_ms: 1000,
            })
            .collect(),
        maximum_authorization_lifetime_ms: 30_000,
        maximum_expiry_height_delta: 30,
        valid_from_ms: policy.valid_from_ms,
        expires_at_ms: policy.expires_at_ms,
    };
    let auto_request = automatic::AutomationRequest {
        authorization_id: release_intents[0].authorization_id.clone(),
        application_id: PRINCIPAL.into(),
        account_id: owner.account_id.clone(),
        writer_epoch: 1,
        agreement_id: AGREEMENT.into(),
        obligation_id: OBLIGATION.into(),
        proposal_id: candidate_id.clone(),
        network_profile: PROFILE_ID.into(),
        manifest_digest: candidate.manifest_digest.clone(),
        effects_digest: reviewed.shielded_sighash().into(),
        artifact_digest: checkpoint.summary().result_digest.clone().unwrap(),
        input_ids: release_intents[0].input_ids.clone(),
        recipient_fingerprints: vec![receiver_fingerprint],
        maximum_debit: amount(reviewed.net_debits_zatoshis()[0]),
        fee: owner.fee_share,
        current_height: context.anchor_height,
        transaction_expiry_height: request.manifest.expiry_height,
        authorization_expires_at_ms: NOW * 1000 + 20_000,
        evidence: evidence_kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| automatic::AutomationEvidence {
                kind: *kind,
                verifier_id: "synthetic-automation-verifier".into(),
                evidence_digest: hex::encode(Sha256::digest(format!(
                    "synthetic-fixture-evidence-{index}-{}",
                    reviewed.review_binding()
                ))),
                manifest_digest: candidate.manifest_digest.clone(),
                effects_digest: reviewed.shielded_sighash().into(),
                observed_at_ms: NOW * 1000,
                expires_at_ms: NOW * 1000 + 30_000,
            })
            .collect(),
    };
    for (id, payload) in [
        (
            "synthetic-account-policy-consent",
            serde_json::json!({"synthetic_never_human_approval": true, "account_policy": policy}),
        ),
        (
            "synthetic-bounded-grant-consent",
            serde_json::json!({"synthetic_never_human_approval": true, "account_policy": policy, "grant_terms": terms}),
        ),
    ] {
        let command = wholepact_store::CommandContext::for_request(
            PRINCIPAL,
            format!("retain-{id}"),
            &payload,
        )
        .unwrap();
        engine
            .store
            .commit_record(
                &command,
                "synthetic_automation_consent",
                id,
                None,
                payload,
                "synthetic_automation_consent_retained",
            )
            .unwrap();
    }
    let automatic_trust = AutomationFixtureTrust {
        store: engine.store.clone(),
        policy: policy.clone(),
        terms: terms.clone(),
        request: auto_request.clone(),
        participant_id: owner.participant_id.clone(),
        review_binding: reviewed.review_binding().into(),
        authorization_consent_id: "synthetic-original-consent-0",
        held: Arc::new(AtomicBool::new(false)),
    };
    engine
        .store
        .configure_automation_account(policy, None, &automatic_trust)
        .unwrap();
    engine
        .store
        .create_automation_grant(terms.clone(), &automatic_trust)
        .unwrap();
    engine
        .store
        .change_automation_grant(
            &terms.grant_id,
            1,
            automation_store::AutomationGrantAction::Activate,
            &automatic_trust,
        )
        .unwrap();
    let signer_storage = Store::create_encrypted(
        directory.as_path().join("external-synthetic-signer.db"),
        secrets.key(94),
    )
    .unwrap();
    let mut automatic_signer = AutomationFixtureSigner {
        spending_key: secrets.owners.owner_spending_key(0),
        request: &auto_request,
        checkpoint: &checkpoint,
        held: automatic_trust.held.clone(),
        storage: &signer_storage,
        signed: None,
        calls: 0,
    };
    let automated = engine
        .store
        .authorize_automatically(
            &terms.grant_id,
            auto_request.clone(),
            &automatic_trust,
            &mut automatic_signer,
        )
        .unwrap();
    assert_eq!(automated.exposure.intent, release_intents[0]);
    assert_eq!(
        automated.record.outcome,
        automation_store::AutomaticAuthorizationOutcome::RetainedLocally
    );
    assert_eq!(automatic_signer.calls, 1);
    assert!(!automatic_trust.held.load(Ordering::SeqCst));
    assert!(
        signer_storage
            .get_record("synthetic_signer_result", &auto_request.authorization_id)
            .unwrap()
            .is_some()
    );
    let automated_replay = engine
        .store
        .authorize_automatically(
            &terms.grant_id,
            auto_request.clone(),
            &automatic_trust,
            &mut automatic_signer,
        )
        .unwrap();
    assert!(automated_replay.replayed);
    assert_eq!(automatic_signer.calls, 1);
    let now = timestamp(NOW);
    let recipient = &secrets.recipient;
    let inbox_path = directory.as_path().join("transport-inbox.db");
    let mut ledger = transport::SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(&inbox_path, secrets.key(90)).unwrap(),
    )
    .unwrap();
    let mut artifacts = vec![];
    let mut associations = vec![];
    let mut signature_canaries = vec![];
    for (owner, release_intent) in release_intents.iter().enumerate() {
        let sender = &secrets.senders[owner];
        let participant = &checkpoint.policy().participants[owner];
        let owned_inputs: Vec<_> = checkpoint
            .policy()
            .inputs
            .iter()
            .filter(|input| input.participant_index == owner)
            .collect();
        assert!(!owned_inputs.is_empty());
        let signed = if owner == 0 {
            automatic_signer
                .signed
                .take()
                .expect("actual signing occurred inside the held automation lease")
        } else {
            let mut signer = pczt::roles::signer::Signer::new(
                pczt::Pczt::parse(checkpoint.pczt_bytes()).unwrap(),
            )
            .unwrap();
            let spending_key = secrets.owners.owner_spending_key(owner);
            for input in &owned_inputs {
                signer
                    .sign_ironwood(
                        UnwrapErr(SysRng),
                        input.action_index,
                        &SpendAuthorizingKey::from(spending_key),
                    )
                    .unwrap();
            }
            signer.finish()
        };
        let signatures: Vec<_> = owned_inputs.iter().map(|input| {
            let signature = signed.ironwood().actions()[input.action_index].spend().spend_auth_sig().unwrap();
            signature_canaries.push(signature);
            serde_json::json!({"action_index": input.action_index, "signature_hex": hex::encode(signature)})
        }).collect();
        let payload = serde_json::to_vec(&serde_json::json!({ "schema_version": 1,
            "candidate_id": candidate_id, "manifest_digest": candidate.manifest_digest,
            "proved_artifact_digest": checkpoint.summary().result_digest,
            "review_binding": checkpoint.scope().review_binding, "account_id": participant.account_id,
            "signatures": signatures })).unwrap();
        let context = transport::MessageContext {
            network_profile_id: PROFILE_ID.into(),
            agreement_id: AGREEMENT.into(),
            proposal_id: candidate.proposal.proposal_id.clone(),
            proposal_revision: 1,
            sender_id: format!("synthetic-signer-{owner}"),
            recipient_id: PRINCIPAL.into(),
            artifact_kind: transport::ArtifactKind::Authorization,
        };
        let prepared = transport::prepare_export(
            transport::ExportRequest {
                context: context.clone(),
                order: transport::MessageOrder {
                    message_id: transport::random_message_id().unwrap(),
                    sequence: 1,
                    issued_at: now.clone(),
                    expires_at: timestamp(NOW + 60),
                },
                purpose: PURPOSE.into(),
                persistence_warning: RETENTION.into(),
            },
            vec![transport::DisclosureField::new("external_spend_signatures_v1", payload).unwrap()],
            &sender.public_key().unwrap(),
            &recipient.public_key().unwrap(),
            &now,
        )
        .unwrap();
        let preview_digest = prepared.preview().digest().unwrap();
        let sealed = prepared.seal(sender, &preview_digest, &now).unwrap();
        let artifact = transport::open_envelope(
            &sealed,
            recipient,
            &sender.public_key().unwrap(),
            &context,
            &now,
            &mut ledger,
        )
        .unwrap();
        assert!(
            transport::open_envelope(
                &sealed,
                recipient,
                &sender.public_key().unwrap(),
                &context,
                &now,
                &mut ledger
            )
            .is_err()
        );
        artifacts.push(artifact);
        engine
            .store
            .mark_authorization_released(&release_intent.authorization_id)
            .unwrap();
        // This is the sole deliberately synthetic association issuer. Production
        // enrollment/revocation is absent and remains a hard acceptance blocker.
        associations.push(AuthenticatedAccountAssociation {
            origin: AccountAssociationOrigin::RemoteKeys,
            sender_fingerprint: sender.public_key().unwrap().fingerprint(),
            recipient_fingerprint: recipient.public_key().unwrap().fingerprint(),
            sender_id: context.sender_id,
            recipient_id: context.recipient_id,
            account_id: participant.account_id.clone(),
            fvk_digest: hex::encode(Sha256::digest(participant.fvk.to_bytes())),
            manifest_digest: candidate.manifest_digest.clone(),
            candidate_id: candidate_id.clone(),
        });
    }
    engine
        .store
        .change_automation_grant(
            &terms.grant_id,
            2,
            automation_store::AutomationGrantAction::Revoke,
            &automatic_trust,
        )
        .unwrap();
    assert_eq!(
        engine
            .store
            .automation_grant(&terms.grant_id)
            .unwrap()
            .unwrap()
            .status,
        automation_store::AutomationGrantStatus::Revoked
    );
    assert!(
        engine
            .store
            .exposure(&auto_request.authorization_id)
            .unwrap()
            .unwrap()
            .state
            .is_outstanding()
    );
    let mut after_revoke = auto_request.clone();
    after_revoke.authorization_id = "synthetic-after-revocation".into();
    // Even a separately retained exact synthetic decision cannot reactivate the
    // revoked standing grant. This isolates the actual runtime NotActive check.
    let mut next_release = release_intents[0].clone();
    next_release.authorization_id = after_revoke.authorization_id.clone();
    let mut next_consent = engine
        .store
        .get_record("synthetic_original_consent", "synthetic-original-consent-0")
        .unwrap()
        .unwrap()
        .payload;
    next_consent["authorization_id"] = serde_json::json!(after_revoke.authorization_id);
    next_consent["release_intent_digest"] = serde_json::json!(
        wholepact_store::request_digest(&serde_json::to_value(next_release).unwrap()).unwrap()
    );
    let command = wholepact_store::CommandContext::for_request(
        PRINCIPAL,
        "synthetic-review-after-revocation",
        &next_consent,
    )
    .unwrap();
    engine
        .store
        .commit_record(
            &command,
            "synthetic_original_consent",
            "synthetic-after-revocation-consent",
            None,
            next_consent,
            "synthetic_original_consent_retained",
        )
        .unwrap();
    let post_revoke_trust = AutomationFixtureTrust {
        store: engine.store.clone(),
        policy: automatic_trust.policy.clone(),
        terms: terms.clone(),
        request: after_revoke.clone(),
        participant_id: automatic_trust.participant_id.clone(),
        review_binding: reviewed.review_binding().into(),
        authorization_consent_id: "synthetic-after-revocation-consent",
        held: Arc::new(AtomicBool::new(false)),
    };
    assert!(matches!(
        engine.store.authorize_automatically(
            &terms.grant_id,
            after_revoke,
            &post_revoke_trust,
            &mut automatic_signer
        ),
        Err(automation_store::AutomationError::NotActive)
    ));
    assert_eq!(automatic_signer.calls, 1);
    assert!(
        engine
            .store
            .automatic_authorization("synthetic-after-revocation")
            .unwrap()
            .is_none()
    );
    let missing_association = [AuthenticatedSignatureDelivery {
        artifact: &artifacts[0],
        association: None,
    }];
    assert_eq!(
        engine
            .inspect_candidate_signatures(
                &access,
                &candidate_id,
                local(),
                &missing_association,
                &now
            )
            .unwrap_err()
            .code,
        "ACCOUNT_ASSOCIATION_UNAVAILABLE"
    );
    let deliveries: Vec<_> = artifacts
        .iter()
        .zip(&associations)
        .map(|(artifact, association)| AuthenticatedSignatureDelivery {
            artifact,
            association: Some(association),
        })
        .collect();
    let partial = engine
        .inspect_candidate_signatures(&access, &candidate_id, local(), &deliveries[..1], &now)
        .unwrap();
    assert!(!partial.signatures_complete);
    let complete = engine
        .inspect_candidate_signatures(&access, &candidate_id, local(), &deliveries, &now)
        .unwrap();
    assert!(
        complete.signatures_complete
            && complete.exact_candidate_preserved
            && complete.proof_verified
    );
    assert!(
        !complete.authorization_allowed
            && !complete.distribution_allowed
            && !complete.chain_validated
    );
    let signed = SignedResultJournal::from_encrypted_connection(
        create_encrypted(&signed_path, secrets.key(83)).unwrap(),
    )
    .unwrap();
    let transactions = TransactionCheckpointJournal::from_encrypted_connection(
        create_encrypted(&transaction_path, secrets.key(84)).unwrap(),
    )
    .unwrap();
    let retention = || LocalSignedRetention {
        journal: &signed,
        consent: &privacy,
    };
    let transaction = || LocalTransactionCheckpoint {
        journal: &transactions,
        consent: &privacy,
    };
    engine
        .retain_candidate_signatures(
            &access,
            "connected-partial-signatures",
            &candidate_id,
            local(),
            retention(),
            &deliveries[..1],
            &now,
        )
        .unwrap();
    assert_eq!(
        engine
            .checkpoint_retained_candidate_transaction(
                &access,
                "connected-partial-signatures",
                &candidate_id,
                local(),
                retention(),
                transaction(),
                &deliveries[..1],
                &now
            )
            .unwrap_err()
            .code,
        "TRANSACTION_SIGNATURES_INCOMPLETE"
    );
    let retained = engine
        .retain_candidate_signatures(
            &access,
            SIGNATURE_KEY,
            &candidate_id,
            local(),
            retention(),
            &deliveries,
            &now,
        )
        .unwrap();
    assert!(
        !retained.transaction_extracted
            && !retained.authorization_allowed
            && !retained.distribution_allowed
    );
    let extracted = engine
        .checkpoint_retained_candidate_transaction(
            &access,
            SIGNATURE_KEY,
            &candidate_id,
            local(),
            retention(),
            transaction(),
            &deliveries,
            &now,
        )
        .unwrap();
    assert!(extracted.cryptographic_transaction_verified && extracted.transaction_extracted);
    assert!(
        !extracted.release_allowed
            && !extracted.authorization_allowed
            && !extracted.distribution_allowed
            && !extracted.chain_validated
    );
    drop(transactions);
    drop(signed);
    let signed = SignedResultJournal::from_encrypted_connection(
        open_encrypted(&signed_path, secrets.key(83)).unwrap(),
    )
    .unwrap();
    let transactions = TransactionCheckpointJournal::from_encrypted_connection(
        open_encrypted(&transaction_path, secrets.key(84)).unwrap(),
    )
    .unwrap();
    let retention = || LocalSignedRetention {
        journal: &signed,
        consent: &privacy,
    };
    let transaction = || LocalTransactionCheckpoint {
        journal: &transactions,
        consent: &privacy,
    };
    let historical = timestamp(NOW + 600);
    assert!(
        engine
            .inspect_candidate_signatures(&access, &candidate_id, local(), &deliveries, &historical)
            .is_err()
    );
    let retained_again = engine
        .reconcile_retained_candidate_signatures(
            &access,
            SIGNATURE_KEY,
            &candidate_id,
            local(),
            retention(),
            &deliveries,
            &historical,
        )
        .unwrap();
    assert!(retained_again.exact_replay && retained_again.historical_reconciliation);
    assert_eq!(retained_again.result_id, retained.result_id);
    let replayed = engine
        .checkpoint_retained_candidate_transaction(
            &access,
            SIGNATURE_KEY,
            &candidate_id,
            local(),
            retention(),
            transaction(),
            &deliveries,
            &historical,
        )
        .unwrap();
    assert!(replayed.exact_replay);
    assert_eq!(replayed.txid, extracted.txid);
    assert_eq!(replayed.transaction_digest, extracted.transaction_digest);
    assert_eq!(
        hex::encode(Sha256::digest(
            engine
                .load_candidate_proof_for_local_review(&access, &candidate_id, local())
                .unwrap()
                .pczt_bytes()
        )),
        original_proof_digest
    );

    let chain_context = chain::synthetic_wallet_chain_context_for_qualification(NOW).unwrap();
    assert_eq!(chain_context.tip().height, u64::from(context.anchor_height));
    assert!(
        !chain_context.independently_consensus_verified() && !chain_context.authorizes_signing()
    );
    let backend_identity = chain_context.source().clone();
    let expected = chain::SubmissionDescriptor {
        operation_id: SUBMISSION_OPERATION.into(),
        obligation_id: OBLIGATION.into(),
        proposal_id: candidate.proposal.proposal_id.clone(),
        transaction_id: extracted.txid.clone(),
        bytes_sha256: extracted.transaction_digest.clone(),
        expiry_height: request.manifest.expiry_height,
        network: "testnet".into(),
        consensus_branch_id: chain::NU7_BRANCH_ID,
    };
    let mut authority = FixtureAuthority {
        expected: expected.clone(),
        allowed: Arc::new(AtomicBool::new(false)),
    };
    let mut submissions = chain::EncryptedSubmissionJournal::from_encrypted_connection(
        create_encrypted(&submission_path, secrets.key(85)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        engine
            .retain_candidate_for_submission(
                &access,
                SIGNATURE_KEY,
                &candidate_id,
                SUBMISSION_OPERATION,
                local(),
                retention(),
                LocalSubmissionHandoff {
                    transactions: transaction(),
                    submission_journal: &mut submissions,
                    authority: &mut authority,
                    backend: &backend_identity,
                    chain_context: &chain_context,
                    clock: &FixtureClock(NOW),
                    policy: chain::SubmissionPolicy::default(),
                    consent: &privacy,
                },
                &deliveries,
                &historical
            )
            .unwrap_err()
            .code,
        "SUBMISSION_NOT_AUTHORIZED"
    );
    assert!(
        submissions
            .retained_submission_descriptor(SUBMISSION_OPERATION)
            .unwrap()
            .is_none()
    );
    authority.allowed.store(true, Ordering::SeqCst);
    let descriptor = engine
        .retain_candidate_for_submission(
            &access,
            SIGNATURE_KEY,
            &candidate_id,
            SUBMISSION_OPERATION,
            local(),
            retention(),
            LocalSubmissionHandoff {
                transactions: transaction(),
                submission_journal: &mut submissions,
                authority: &mut authority,
                backend: &backend_identity,
                chain_context: &chain_context,
                clock: &FixtureClock(NOW),
                policy: chain::SubmissionPolicy::default(),
                consent: &privacy,
            },
            &deliveries,
            &historical,
        )
        .unwrap();
    assert_eq!(descriptor, expected);
    assert!(
        submissions
            .submission_attempts(SUBMISSION_OPERATION)
            .unwrap()
            .is_empty()
    );
    // Local retention alone has not contacted even this offline backend.
    let mut backend = OfflineBackend {
        context: chain_context.clone(),
        calls: vec![],
        pending: true,
        outcomes: vec![
            Err(chain::ChainError::Timeout),
            Ok(chain::BackendSubmissionResult::Acknowledged),
            Ok(chain::BackendSubmissionResult::Rejected { code: 17 }),
        ]
        .into(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let stale = chain::retry_retained_submission(
            &mut submissions,
            SUBMISSION_OPERATION,
            &mut backend,
            &mut authority,
            &FixtureClock(NOW + 3600),
            chain::SubmissionPolicy::default(),
        )
        .await;
        assert!(matches!(stale, Err(chain::ChainError::StaleChain)));
        assert!(backend.calls.is_empty());
        let interrupted = tokio::time::timeout(
            Duration::from_millis(20),
            chain::retry_retained_submission(
                &mut submissions,
                SUBMISSION_OPERATION,
                &mut backend,
                &mut authority,
                &FixtureClock(NOW),
                chain::SubmissionPolicy::default(),
            ),
        )
        .await;
        assert!(interrupted.is_err());
        assert_eq!(backend.calls.len(), 1);
        assert!(matches!(
            submissions
                .submission_attempts(SUBMISSION_OPERATION)
                .unwrap()[0]
                .outcome,
            chain::SubmissionAttemptOutcome::Unknown
        ));
    });
    drop(submissions);
    let mut submissions = chain::EncryptedSubmissionJournal::from_encrypted_connection(
        open_encrypted(&submission_path, secrets.key(85)).unwrap(),
    )
    .unwrap();
    backend.pending = false;
    runtime.block_on(async {
        let uncertain = chain::retry_retained_submission(
            &mut submissions,
            SUBMISSION_OPERATION,
            &mut backend,
            &mut authority,
            &FixtureClock(NOW + 1),
            chain::SubmissionPolicy::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            uncertain.attempt.outcome,
            chain::SubmissionAttemptOutcome::Indeterminate {
                reason: chain::SubmissionFailure::Timeout
            }
        ));
        assert_eq!(
            uncertain.historical_provider_state,
            chain::SubmissionState::SubmissionUnknown
        );
        assert!(!uncertain.clears_authorization_exposure && !uncertain.permits_replacement);
        let acknowledged = chain::retry_retained_submission(
            &mut submissions,
            SUBMISSION_OPERATION,
            &mut backend,
            &mut authority,
            &FixtureClock(NOW + 2),
            chain::SubmissionPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            acknowledged.historical_provider_state,
            chain::SubmissionState::BackendAcknowledged
        );
        let rejected_later = chain::retry_retained_submission(
            &mut submissions,
            SUBMISSION_OPERATION,
            &mut backend,
            &mut authority,
            &FixtureClock(NOW + 3),
            chain::SubmissionPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            rejected_later.historical_provider_state,
            chain::SubmissionState::BackendAcknowledged
        );
        assert!(
            !rejected_later.clears_authorization_exposure && !rejected_later.permits_replacement
        );
        assert_eq!(rejected_later.attempt.number, 4);
        assert_eq!(backend.calls.len(), 4);
        assert!(backend.calls.iter().all(|bytes| bytes == &backend.calls[0]
            && hex::encode(Sha256::digest(bytes)) == descriptor.bytes_sha256));
        let replacement = chain::SubmissionPlan::new(
            OBLIGATION,
            "synthetic-replacement-proposal",
            "synthetic-replacement-operation",
            &backend.calls[0],
        )
        .unwrap();
        let mut replacement_authority = FixtureAuthority {
            expected: replacement.descriptor().clone(),
            allowed: authority.allowed.clone(),
        };
        assert!(matches!(
            chain::submit_plan(
                &mut submissions,
                &replacement,
                &mut backend,
                &mut replacement_authority,
                &FixtureClock(NOW + 4),
                chain::SubmissionPolicy::default()
            )
            .await,
            Err(chain::ChainError::ObligationConflict)
        ));
        assert_eq!(backend.calls.len(), 4);
    });
    let policy =
        chain::ConfirmationPolicy::new(10, 10, vec![backend_identity.source_id.clone()]).unwrap();
    let mut reconciler = chain::SettlementReconciler::new(
        &descriptor.transaction_id,
        descriptor.expiry_height,
        policy,
    )
    .unwrap();
    let confirmation_context =
        chain::synthetic_wallet_confirmation_context_for_qualification(NOW).unwrap();
    assert_eq!(confirmation_context.source(), chain_context.source());
    assert_eq!(
        confirmation_context.tip().height - u64::from(context.target_height) + 1,
        10
    );
    let evidence = |status| chain::SourceObservation {
        source_id: backend_identity.source_id.clone(),
        observation: Ok(chain::TransactionObservation {
            transaction_id: descriptor.transaction_id.clone(),
            context: confirmation_context.clone(),
            status,
            confirms_raw_transaction_id: true,
            independently_consensus_verified: false,
            clears_authorization_exposure: false,
        }),
    };
    let confirmed = reconciler
        .reconcile(
            &[evidence(chain::TransactionStatus::Included {
                block: chain::BlockIdentity {
                    height: u64::from(context.target_height),
                    hash: "41".repeat(32),
                },
                confirmations: 10,
            })],
            NOW + 5,
        )
        .unwrap();
    assert!(confirmed.state.confirmation_policy_met());
    assert!(
        !confirmed.independently_consensus_verified
            && !confirmed.clears_authorization_exposure
            && !confirmed.permits_replacement
    );
    submissions
        .record_reconciliation(SUBMISSION_OPERATION, &confirmed)
        .unwrap();
    drop(submissions);
    let mut submissions = chain::EncryptedSubmissionJournal::from_encrypted_connection(
        open_encrypted(&submission_path, secrets.key(85)).unwrap(),
    )
    .unwrap();
    let mut restored_reconciler = submissions
        .recover_reconciler(SUBMISSION_OPERATION)
        .unwrap()
        .unwrap();
    assert_eq!(
        restored_reconciler.last_report().unwrap().state,
        chain::SettlementObservationState::Stale
    );
    let reorganized = restored_reconciler
        .reconcile(&[evidence(chain::TransactionStatus::Reorganized)], NOW + 6)
        .unwrap();
    assert!(reorganized.confidence_lost && reorganized.reorganization_observed);
    assert_eq!(reorganized.last_inclusion, confirmed.last_inclusion);
    assert_eq!(
        reorganized.state,
        chain::SettlementObservationState::Reorganized
    );
    submissions
        .record_reconciliation(SUBMISSION_OPERATION, &reorganized)
        .unwrap();
    assert!(!reorganized.clears_authorization_exposure && !reorganized.permits_replacement);

    let cancellation = engine
        .cancel(
            &access,
            "connected-cancel-after-release",
            AGREEMENT,
            engine.get(&access, AGREEMENT).unwrap().revision,
        )
        .unwrap();
    assert!(cancellation.agreement.cancellation_requested);
    assert_eq!(cancellation.agreement.progress, "cancellation_requested");
    assert_eq!(cancellation.agreement.authorization_exposure, "unknown");
    for release in &release_intents {
        let retained = engine
            .store
            .exposure(&release.authorization_id)
            .unwrap()
            .unwrap();
        assert!(retained.state.is_outstanding() && retained.release_intent_recorded);
        assert_eq!(
            engine.store.outstanding_debit(&release.account_id).unwrap(),
            release.maximum_debit
        );
    }
    let mut competing_release = release_intents[0].clone();
    competing_release.authorization_id = "synthetic-competing-authorization".into();
    competing_release.input_ids = vec!["f1".repeat(32)];
    assert!(matches!(
        engine
            .store
            .record_authorization_release_intent(&competing_release),
        Err(wholepact_store::StoreError::LiveAuthorizationExists)
    ));

    // Consume the concrete production protocol-to-record source. It rechecks
    // exact protected journals and original release/consent provenance. Only the
    // account identity and original human-decision issuer remain synthetic.
    use wholepact_core::{disclosure, records};
    let owner = &request.manifest.participants[0];
    let record_authority = RecordAuthority {
        binding: engine.protected_record_store_binding().unwrap(),
        participant_id: owner.participant_id.clone(),
        account_id: owner.account_id.clone(),
        allowed: AtomicBool::new(true),
    };
    let window = records::ObservationWindow {
        now: iso(NOW + 10),
        oldest_acceptable: iso(NOW - 10),
    };
    let record_runtime = || ParticipantRecordRuntime {
        profile_id: "synthetic-record-profile",
        authority: &record_authority,
        window: &window,
    };
    let record_request = RetainParticipantRecordRequest {
        record_id: "connected-private-record".into(),
        candidate_id: candidate_id.clone(),
        participant_id: owner.participant_id.clone(),
        account_id: owner.account_id.clone(),
    };
    let original_consent = OriginalConsentAuthority {
        journal: engine.store.clone(),
        consent_id: "synthetic-original-consent-0".into(),
        authorization_id: release_intents[0].authorization_id.clone(),
        allowed: AtomicBool::new(true),
    };
    let record_now = timestamp(NOW + 10);
    let protocol_source = |consent| LocalParticipantRecordSource {
        proof: local(),
        signatures: retention(),
        transaction: transaction(),
        transaction_read_consent: &privacy,
        deliveries: &deliveries,
        signature_idempotency_key: SIGNATURE_KEY,
        original_authorization: OriginalAuthorizationHistory::ProtectedJournal {
            journal: &engine.store,
            authorization_id: &release_intents[0].authorization_id,
            consent,
        },
        now: &record_now,
    };
    let revision = engine.get(&access, AGREEMENT).unwrap().revision;
    assert_eq!(
        engine
            .retain_participant_record_from_protocol(
                &access,
                "connected-no-original-consent",
                AGREEMENT,
                revision,
                record_request.clone(),
                record_runtime(),
                protocol_source(None)
            )
            .unwrap_err()
            .code,
        "ORIGINAL_AUTHORIZATION_HISTORY_MISSING"
    );
    let missing_transaction_path = directory.as_path().join("missing-transaction.db");
    let missing_transaction = TransactionCheckpointJournal::from_encrypted_connection(
        create_encrypted(&missing_transaction_path, secrets.key(89)).unwrap(),
    )
    .unwrap();
    let mut absent = protocol_source(Some(&original_consent));
    absent.transaction = LocalTransactionCheckpoint {
        journal: &missing_transaction,
        consent: &privacy,
    };
    assert_eq!(
        engine
            .retain_participant_record_from_protocol(
                &access,
                "connected-missing-transaction",
                AGREEMENT,
                revision,
                record_request.clone(),
                record_runtime(),
                absent
            )
            .unwrap_err()
            .code,
        "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED"
    );
    let audit_missing = open_encrypted(&missing_transaction_path, secrets.key(89)).unwrap();
    assert_eq!(
        audit_missing
            .connection()
            .query_row("SELECT count(*) FROM transaction_intents", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    drop(audit_missing);
    let mut wrong_owner_history = protocol_source(Some(&original_consent));
    wrong_owner_history.original_authorization = OriginalAuthorizationHistory::ProtectedJournal {
        journal: &engine.store,
        authorization_id: &release_intents[1].authorization_id,
        consent: Some(&original_consent),
    };
    assert_eq!(
        engine
            .retain_participant_record_from_protocol(
                &access,
                "connected-wrong-original-owner",
                AGREEMENT,
                revision,
                record_request.clone(),
                record_runtime(),
                wrong_owner_history
            )
            .unwrap_err()
            .code,
        "RECORD_SOURCE_REJECTED"
    );
    original_consent.allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        engine
            .retain_participant_record_from_protocol(
                &access,
                "connected-revoked-original-consent",
                AGREEMENT,
                revision,
                record_request.clone(),
                record_runtime(),
                protocol_source(Some(&original_consent))
            )
            .unwrap_err()
            .code,
        "ORIGINAL_AUTHORIZATION_HISTORY_MISSING"
    );
    original_consent.allowed.store(true, Ordering::SeqCst);
    let record_retained = engine
        .retain_participant_record_from_protocol(
            &access,
            "connected-retain-record",
            AGREEMENT,
            revision,
            record_request.clone(),
            record_runtime(),
            protocol_source(Some(&original_consent)),
        )
        .unwrap();
    assert_eq!(
        record_retained.record.confidence,
        records::RecordConfidence::NoObservation
    );
    let replay_record = engine
        .retain_participant_record_from_protocol(
            &access,
            "connected-retain-record",
            AGREEMENT,
            revision,
            record_request.clone(),
            record_runtime(),
            protocol_source(Some(&original_consent)),
        )
        .unwrap();
    assert!(replay_record.replayed);
    assert_eq!(replay_record.operation_id, record_retained.operation_id);
    assert_eq!(
        engine
            .retain_participant_record_from_protocol(
                &access,
                "connected-retain-record",
                AGREEMENT,
                revision,
                record_request.clone(),
                record_runtime(),
                protocol_source(None)
            )
            .unwrap_err()
            .code,
        "ORIGINAL_AUTHORIZATION_HISTORY_MISSING"
    );
    original_consent.allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        engine
            .retain_participant_record_from_protocol(
                &access,
                "connected-retain-record",
                AGREEMENT,
                revision,
                record_request.clone(),
                record_runtime(),
                protocol_source(Some(&original_consent))
            )
            .unwrap_err()
            .code,
        "ORIGINAL_AUTHORIZATION_HISTORY_MISSING"
    );
    original_consent.allowed.store(true, Ordering::SeqCst);
    privacy.allowed.store(false, Ordering::SeqCst);
    assert!(
        engine
            .retain_participant_record_from_protocol(
                &access,
                "connected-retain-record",
                AGREEMENT,
                revision,
                record_request.clone(),
                record_runtime(),
                protocol_source(Some(&original_consent))
            )
            .is_err()
    );
    privacy.allowed.store(true, Ordering::SeqCst);
    let mut missing_on_replay = protocol_source(Some(&original_consent));
    missing_on_replay.transaction = LocalTransactionCheckpoint {
        journal: &missing_transaction,
        consent: &privacy,
    };
    assert_eq!(
        engine
            .retain_participant_record_from_protocol(
                &access,
                "connected-retain-record",
                AGREEMENT,
                revision,
                record_request.clone(),
                record_runtime(),
                missing_on_replay
            )
            .unwrap_err()
            .code,
        "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED"
    );
    let private_record = engine
        .read_participant_record(
            &access,
            AGREEMENT,
            &record_request.record_id,
            record_runtime(),
        )
        .unwrap();
    assert_eq!(
        private_record.own_authorization().consent_record_ref,
        "synthetic-original-consent-0"
    );
    assert_eq!(
        private_record.own_authorization().authorization_record_ref,
        release_intents[0].authorization_id
    );
    assert_eq!(
        private_record.own_authorization().exposure,
        AuthorizationExposure::Released
    );
    assert_eq!(
        private_record.transaction().transaction_id,
        descriptor.transaction_id
    );
    assert_eq!(
        private_record.transaction().transaction_bytes_digest,
        descriptor.bytes_sha256
    );
    assert_eq!(private_record.proposal().manifest(), &request.manifest);
    let observation_policy = records::ObservationPolicy {
        source_id: backend_identity.source_id.clone(),
        trust_profile_id: "synthetic_never_chain_evidence".into(),
        adapter_id: "synthetic-chain-to-record".into(),
    };
    // Actual maintained incoming-key decryption of retained canonical bytes.
    // The recipient is synthetic key71 and also owns a distinct95k change output;
    // the checked incoming payment must be300k, never the wallet's combined395k.
    let recipient_instruction = &request.manifest.agreement.recipients[0];
    let recipient_memo = &checkpoint
        .policy()
        .outputs
        .iter()
        .find(|output| {
            matches!(
                output.purpose,
                wholepact_protocol::review::OutputPurpose::Recipient
            )
        })
        .unwrap()
        .memo;
    let recipient_scope = RecipientViewingScope {
        principal_id: PRINCIPAL.into(),
        retained_operator_principal_id: PRINCIPAL.into(),
        profile_id: "synthetic-recipient-profile".into(),
        recipient_id: recipient_instruction.recipient_id.clone(),
        recipient_account_ref: "synthetic-recipient-wallet-key71".into(),
        candidate_id: candidate_id.clone(),
        retained_checkpoint_id: extracted.checkpoint_id.clone(),
        transaction_id: descriptor.transaction_id.clone(),
        transaction_digest: descriptor.bytes_sha256.clone(),
        effects_commitment: private_record.transaction().effects_commitment.clone(),
        network_profile_id: PROFILE_ID.into(),
        destination: recipient_instruction.address.clone(),
        expected_amount_zatoshis: 300_000,
        expected_memo_digest: hex::encode(Sha256::digest(recipient_memo)),
        privacy_purpose: "Independently inspect the synthetic recipient payment".into(),
    };
    let recipient_viewing = RecipientFixtureAuthority {
        journal: &transactions,
        scope: recipient_scope.clone(),
        viewing_key: checkpoint.policy().participants[0].fvk.clone(),
        allowed: AtomicBool::new(true),
    };
    let wrong_recipient_viewing = RecipientFixtureAuthority {
        journal: &transactions,
        scope: recipient_scope,
        viewing_key: checkpoint.policy().participants[1].fvk.clone(),
        allowed: AtomicBool::new(true),
    };
    let recipient_request = || RecipientObservationRequest {
        recipient_id: recipient_instruction.recipient_id.clone(),
        recipient_account_ref: "synthetic-recipient-wallet-key71".into(),
        exact_transaction: private_record.transaction().clone(),
    };
    let recipient_local = |viewing| LocalRecipientPaymentCheck {
        profile_id: "synthetic-recipient-profile",
        privacy_purpose: "Independently inspect the synthetic recipient payment",
        proof: local(),
        signatures: retention(),
        transactions: transaction(),
        transaction_read_consent: &privacy,
        recipient_viewing: viewing,
        deliveries: &deliveries,
        signature_idempotency_key: SIGNATURE_KEY,
        now: &record_now,
        window: &window,
        chain_policy: &observation_policy,
    };
    let mut recipient_chain = RecordObservation {
        exact: private_record.transaction().clone(),
        report: confirmed.clone(),
    };
    let received = engine
        .check_retained_recipient_payment(
            &access,
            &candidate_id,
            recipient_request(),
            recipient_local(&recipient_viewing),
            &mut recipient_chain,
        )
        .unwrap();
    assert_eq!(received.amount(), amount(300_000));
    assert_eq!(received.observation().outputs.len(), 1);
    assert_eq!(
        received.confidence(),
        records::RecordConfidence::ConfirmationPolicyMet
    );
    assert_eq!(
        received.request().transaction(),
        private_record.transaction()
    );
    assert_eq!(
        received
            .confidence_at(&records::ObservationWindow {
                now: iso(NOW + 120),
                oldest_acceptable: iso(NOW + 60),
            })
            .unwrap(),
        records::RecordConfidence::Stale
    );
    assert_eq!(
        engine
            .check_retained_recipient_payment(
                &access,
                &candidate_id,
                recipient_request(),
                recipient_local(&wrong_recipient_viewing),
                &mut recipient_chain,
            )
            .unwrap_err()
            .code,
        "RECIPIENT_VIEWING_ACCOUNT_MISMATCH"
    );
    recipient_viewing.allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        engine
            .check_retained_recipient_payment(
                &access,
                &candidate_id,
                recipient_request(),
                recipient_local(&recipient_viewing),
                &mut recipient_chain,
            )
            .unwrap_err()
            .code,
        "RECIPIENT_VIEWING_CONSENT_DENIED"
    );
    recipient_viewing.allowed.store(true, Ordering::SeqCst);
    recipient_chain.report = reorganized.clone();
    let received_reorg = engine
        .check_retained_recipient_payment(
            &access,
            &candidate_id,
            recipient_request(),
            recipient_local(&recipient_viewing),
            &mut recipient_chain,
        )
        .unwrap();
    assert_eq!(received_reorg.amount(), amount(300_000));
    assert_eq!(
        received_reorg.confidence(),
        records::RecordConfidence::Reorganized
    );

    let mut observed = RecordObservation {
        exact: private_record.transaction().clone(),
        report: confirmed.clone(),
    };
    let record_confirmed = engine
        .observe_participant_record(
            &access,
            "connected-record-confirmed",
            AGREEMENT,
            record_retained.agreement_revision,
            ObserveParticipantRecordRequest {
                record_id: record_request.record_id.clone(),
                expected_record_revision: 1,
                policy: observation_policy.clone(),
            },
            record_runtime(),
            &mut observed,
        )
        .unwrap();
    assert_eq!(
        record_confirmed.record.confidence,
        records::RecordConfidence::ConfirmationPolicyMet
    );
    let preview_request = PreviewParticipantDisclosureRequest {
        record_id: record_request.record_id.clone(),
        expected_record_revision: 2,
        preview_id: "connected-disclosure-preview".into(),
        method: disclosure::DisclosureMethod::PrivateReceipt,
        selection: disclosure::DisclosureSelection {
            fields: vec![
                disclosure::DisclosureField::TransactionId,
                disclosure::DisclosureField::ChainConfidence,
            ],
            payment_recipient_id: None,
            destination: disclosure::DisclosureDestination {
                recipient_id: "synthetic-reviewer".into(),
                destination: "synthetic://private-local-review".into(),
                audience: disclosure::DisclosureAudience::NamedPrivateRecipient,
            },
            purpose: "Inspect exactly selected synthetic receipt statements".into(),
            persistence: "No export; private encrypted local preview".into(),
        },
    };
    let previewed = engine
        .preview_participant_disclosure(
            &access,
            "connected-preview-receipt",
            AGREEMENT,
            record_confirmed.agreement_revision,
            preview_request.clone(),
            record_runtime(),
        )
        .unwrap();
    let preview = engine
        .read_participant_disclosure_preview(
            &access,
            AGREEMENT,
            &record_request.record_id,
            &preview_request.preview_id,
            record_runtime(),
        )
        .unwrap();
    let preview_json = serde_json::to_string(preview.receipt()).unwrap();
    assert!(preview_json.contains(&descriptor.transaction_id));
    assert!(
        !preview_json.contains(&owner.account_id) && !preview_json.contains(&owner.participant_id)
    );
    assert!(!preview_json.contains(&request.manifest.agreement.recipients[0].address));
    assert!(preview_json.contains("not independently authenticated proof of payment"));
    observed.report = reorganized.clone();
    let record_reorg = engine
        .observe_participant_record(
            &access,
            "connected-record-reorganized",
            AGREEMENT,
            previewed.agreement_revision,
            ObserveParticipantRecordRequest {
                record_id: record_request.record_id.clone(),
                expected_record_revision: 2,
                policy: observation_policy,
            },
            record_runtime(),
            &mut observed,
        )
        .unwrap();
    assert_eq!(
        record_reorg.record.confidence,
        records::RecordConfidence::Reorganized
    );
    assert!(record_reorg.record.recovery_required);
    assert_eq!(
        engine
            .read_participant_disclosure_preview(
                &access,
                AGREEMENT,
                &record_request.record_id,
                &preview_request.preview_id,
                record_runtime()
            )
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    let unavailable = engine.participant_record_status(&access, None).unwrap();
    assert!(unavailable.records.is_none());
    assert_eq!(
        unavailable.account_exposure,
        "unknown_not_established_by_records"
    );
    record_authority.allowed.store(false, Ordering::SeqCst);
    assert!(
        engine
            .read_participant_record(
                &access,
                AGREEMENT,
                &record_request.record_id,
                record_runtime()
            )
            .is_err()
    );
    record_authority.allowed.store(true, Ordering::SeqCst);

    engine
        .store
        .require_account_recovery(&owner.account_id)
        .unwrap();
    assert_eq!(
        engine
            .retain_participant_record_from_protocol(
                &access,
                "connected-retain-record",
                AGREEMENT,
                revision,
                record_request.clone(),
                record_runtime(),
                protocol_source(Some(&original_consent))
            )
            .unwrap_err()
            .code,
        "ORIGINAL_AUTHORIZATION_HISTORY_MISSING"
    );
    assert_eq!(
        engine
            .read_participant_record(
                &access,
                AGREEMENT,
                &record_request.record_id,
                record_runtime()
            )
            .unwrap()
            .transaction()
            .transaction_id,
        descriptor.transaction_id
    );
    // Full coordination backup is scoped honestly: separate proof/signed/tx and
    // submission journals are not silently reconstructed or declared recovered.
    let source = engine
        .bind_local_backup_source("synthetic-profile", "synthetic-coordination")
        .unwrap();
    let archive = directory.as_path().join("coordination-backup.db");
    let backup_gate = BackupGate {
        source: source.clone(),
        archive: archive.clone(),
        destination: None,
        action: FullJournalBackupAction::CreateArchive,
    };
    let backup = engine
        .backup_local_journal(
            &access,
            LocalJournalBackup {
                source: &source,
                destination: &archive,
                backup_key: secrets.key(86),
                retention_policy: "local-only; retain until deliberately removed",
                consent: &backup_gate,
            },
        )
        .unwrap();
    assert!(
        !backup.wallet_secrets_included
            && !backup.separate_artifact_journals_included
            && !backup.freshness_established
    );
    let destination = directory.as_path().join("restored-coordination.db");
    let restore_gate = BackupGate {
        source: source.clone(),
        archive: archive.clone(),
        destination: Some(destination.clone()),
        action: FullJournalBackupAction::RestoreJournal,
    };
    let (restored, restoration) = engine
        .restore_local_journal(
            &access,
            LocalJournalRestore {
                source: &source,
                archive: &archive,
                backup_key: secrets.key(86),
                destination: &destination,
                destination_key: secrets.key(87),
                retention_policy: "local-only; retain until deliberately removed",
                consent: &restore_gate,
            },
        )
        .unwrap();
    assert!(restoration.integrity_verified && restoration.recovery_required);
    assert!(!restoration.authorization_allowed && !restoration.signer_recovered);
    let metadata = restored.journal_recovery_metadata().unwrap();
    assert!(metadata.restored_journal_quarantined && metadata.writer_reconciliation_required);
    assert!(
        !metadata.new_authorization_allowed
            && !metadata.wallet_recovered
            && !metadata.separate_private_journals_recovered
    );
    assert_eq!(
        restored
            .candidate(&access, &candidate_id)
            .unwrap()
            .1
            .manifest_digest,
        candidate.manifest_digest
    );
    assert!(
        restored
            .create(
                &access,
                "connected-create-agreement",
                request.manifest.agreement.clone()
            )
            .unwrap()
            .replayed
    );
    for release in &release_intents {
        assert!(
            restored
                .store
                .authority_account(&release.account_id)
                .unwrap()
                .unwrap()
                .recovery_required
        );
        assert!(
            restored
                .store
                .exposure(&release.authorization_id)
                .unwrap()
                .unwrap()
                .state
                .is_outstanding()
        );
        assert_eq!(
            restored
                .store
                .outstanding_debit(&release.account_id)
                .unwrap(),
            release.maximum_debit
        );
    }
    assert!(matches!(
        restored
            .store
            .record_authorization_release_intent(&competing_release),
        Err(wholepact_store::StoreError::RecoveryRequired)
    ));
    // An open-store authority cannot silently transfer to the restored clone.
    assert!(
        restored
            .read_participant_record(
                &access,
                AGREEMENT,
                &record_request.record_id,
                record_runtime()
            )
            .is_err()
    );
    let restored_authority = RecordAuthority {
        binding: restored.protected_record_store_binding().unwrap(),
        participant_id: owner.participant_id.clone(),
        account_id: owner.account_id.clone(),
        allowed: AtomicBool::new(true),
    };
    let restored_runtime = || ParticipantRecordRuntime {
        profile_id: "synthetic-record-profile",
        authority: &restored_authority,
        window: &window,
    };
    let restored_record = restored
        .read_participant_record(
            &access,
            AGREEMENT,
            &record_request.record_id,
            restored_runtime(),
        )
        .unwrap();
    assert_eq!(restored_record.transaction(), private_record.transaction());
    assert!(
        restored_record
            .assess(&window)
            .unwrap()
            .exposure_reconciliation_required
    );
    assert_eq!(
        restored
            .observe_participant_record(
                &access,
                "restored-cannot-advance-record",
                AGREEMENT,
                record_reorg.agreement_revision,
                ObserveParticipantRecordRequest {
                    record_id: record_request.record_id.clone(),
                    expected_record_revision: 3,
                    policy: records::ObservationPolicy {
                        source_id: backend_identity.source_id.clone(),
                        trust_profile_id: "synthetic_never_chain_evidence".into(),
                        adapter_id: "synthetic-chain-to-record".into()
                    }
                },
                restored_runtime(),
                &mut observed
            )
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
    let empty_jobs = ProofJobStore::from_encrypted_connection(
        create_encrypted(directory.as_path().join("empty-proof.db"), secrets.key(88)).unwrap(),
    )
    .unwrap();
    assert!(
        restored
            .load_candidate_proof_for_local_review(
                &access,
                &candidate_id,
                LocalProofJob {
                    job_id: &job_id,
                    jobs: &empty_jobs,
                    consent: &privacy
                }
            )
            .is_err()
    );
    let summaries = serde_json::to_string(&engine.get(&access, AGREEMENT).unwrap()).unwrap();
    assert!(!summaries.contains(&hex::encode(private_fvk)));
    assert!(!summaries.contains("pczt_bytes"));
    assert!(!summaries.contains("consent_record_ref"));
    assert!(!summaries.contains("synthetic-retention-"));
    assert_eq!(
        engine
            .get(&access, AGREEMENT)
            .unwrap()
            .authorization_exposure,
        "unknown"
    );
    for path in [
        &metadata_path,
        &proof_path,
        &signed_path,
        &transaction_path,
        &submission_path,
        &inbox_path,
        &archive,
        &destination,
    ] {
        assert_encrypted(
            path,
            &[
                PRINCIPAL.as_bytes(),
                &private_fvk,
                &signature_canaries[0][..32],
            ],
        );
    }
    assert_eq!(
        submissions
            .retained_submission_descriptor(SUBMISSION_OPERATION)
            .unwrap()
            .unwrap(),
        descriptor
    );
    // The complete enrolled coordinator profile has six actual populated
    // journals. Wallet scanning was an external ephemeral fixture input; this
    // coordinator never owned a wallet DB or an outgoing transport mailbox.
    // Neither missing nor lost journals are classified as absent.
    let coordination_adapter =
        wholepact_store::bundle::CoordinationBundleAdapter::new(&engine.store).unwrap();
    let proof_adapter = wholepact_proof_jobs::backup::ProofWitnessBackupAdapter::new(&jobs);
    let signed_adapter =
        wholepact_protocol::authorization::retention::backup::SignedResultsBackupAdapter::new(
            &signed,
        );
    let transaction_adapter = wholepact_protocol::authorization::retention::transaction::backup::ExactTransactionsBackupAdapter::new(&transactions);
    let submissions = Mutex::new(submissions);
    let submission_adapter = chain::backup::SubmissionBackupAdapter::new(&submissions);
    let inbox_adapter = ledger.backup_adapter().unwrap();
    let adapters: [(&str, &dyn bundle::JournalAdapter); 6] = [
        ("coordination", &coordination_adapter),
        ("proof", &proof_adapter),
        ("signatures", &signed_adapter),
        ("transaction", &transaction_adapter),
        ("submission", &submission_adapter),
        ("inbox", &inbox_adapter),
    ];
    let sources = vec![
        bundle::RegisteredJournal::new("coordination", &coordination_adapter).unwrap(),
        bundle::RegisteredJournal::new("proof", &proof_adapter).unwrap(),
        bundle::RegisteredJournal::new("signatures", &signed_adapter).unwrap(),
        bundle::RegisteredJournal::new("transaction", &transaction_adapter).unwrap(),
        bundle::RegisteredJournal::new("submission", &submission_adapter).unwrap(),
        bundle::RegisteredJournal::new("inbox", &inbox_adapter).unwrap(),
    ];
    let coverage = bundle::Coverage {
        present: BTreeMap::from([
            (
                bundle::JournalKind::CoordinationAuthority,
                vec!["coordination".into()],
            ),
            (bundle::JournalKind::ProofWitness, vec!["proof".into()]),
            (
                bundle::JournalKind::SignedResults,
                vec!["signatures".into()],
            ),
            (
                bundle::JournalKind::ExactTransactions,
                vec!["transaction".into()],
            ),
            (bundle::JournalKind::Submission, vec!["submission".into()]),
            (bundle::JournalKind::TransportInbox, vec!["inbox".into()]),
        ]),
        absent: BTreeSet::from([
            bundle::JournalKind::SignerConsentAuthority,
            bundle::JournalKind::WalletScan,
            bundle::JournalKind::TransportOutbox,
        ]),
    };
    let bundle_path = directory.as_path().join("complete-coordinator-profile.db");
    let bundle_authority = BundleFixtureAuthority {
        action: bundle::BundleAction::Snapshot,
        archive: bundle_path.clone(),
        destinations: vec![],
        coverage: coverage.clone(),
        sources: sources
            .iter()
            .map(|source| (source.id().into(), source.binding()))
            .collect(),
        fence: Mutex::new(()),
    };
    let bundle_key = secrets.key(91);
    let bundle_manifest = bundle::snapshot(bundle::SnapshotRequest {
        principal_id: PRINCIPAL,
        profile_id: "synthetic-coordinator-profile",
        coverage: coverage.clone(),
        sources: &sources,
        destination: &bundle_path,
        key: bundle_key,
        authority: &bundle_authority,
    })
    .unwrap();
    assert_eq!(bundle_manifest.components.len(), 6);
    assert!(
        bundle_manifest
            .components
            .iter()
            .all(|component| component.rows > 0 && component.logical_bytes > 0)
    );
    assert!(
        !bundle_manifest.writer_freshness_established
            && !bundle_manifest.wallet_spending_secrets_included
    );
    assert!(bundle_manifest.restore_requires_recovery);
    assert!(bundle_manifest.private_viewing_witness_and_correlation_data_may_be_included);
    let bundle_destinations: Vec<_> = adapters
        .iter()
        .map(|(id, _)| directory.as_path().join(format!("bundle-restored-{id}.db")))
        .collect();
    let restore_key = secrets.key(92);
    let targets: Vec<_> = adapters
        .iter()
        .zip(&bundle_destinations)
        .map(|((id, adapter), destination)| bundle::RestoreTarget {
            component_id: id,
            template: adapter.template(),
            destination,
            key: restore_key,
        })
        .collect();
    let bundle_restore_authority = BundleFixtureAuthority {
        action: bundle::BundleAction::TestRestore,
        archive: bundle_path.clone(),
        destinations: bundle_destinations.clone(),
        coverage,
        sources: vec![],
        fence: Mutex::new(()),
    };
    let full_restore = bundle::test_restore(bundle::RestoreRequest {
        principal_id: PRINCIPAL,
        profile_id: "synthetic-coordinator-profile",
        archive: &bundle_path,
        key: bundle_key,
        targets: &targets,
        authority: &bundle_restore_authority,
    })
    .unwrap();
    assert_eq!(full_restore.manifest, bundle_manifest);
    assert_eq!(full_restore.restored_components, 6);
    assert!(full_restore.integrity_verified && full_restore.all_components_quarantined);
    assert!(!full_restore.authorization_allowed && !full_restore.signer_recovered);
    for destination in &bundle_destinations {
        assert!(matches!(
            open_encrypted(destination, restore_key),
            Err(wholepact_storage_security::StorageSecurityError::QuarantinedDatabase)
        ));
        assert_encrypted(
            destination,
            &[
                PRINCIPAL.as_bytes(),
                &private_fvk,
                &signature_canaries[0][..32],
            ],
        );
    }
    assert_encrypted(
        &bundle_path,
        &[
            PRINCIPAL.as_bytes(),
            &private_fvk,
            &signature_canaries[0][..32],
        ],
    );
    assert_eq!(
        submissions
            .lock()
            .unwrap()
            .retained_submission_descriptor(SUBMISSION_OPERATION)
            .unwrap()
            .unwrap(),
        descriptor
    );
    privacy.allowed.store(false, Ordering::SeqCst);
    assert!(
        engine
            .load_candidate_proof_for_local_review(&access, &candidate_id, local())
            .is_err()
    );
}

#[cfg(feature = "durable-proposal")]
#[path = "durable_proposals_v1_tests.rs"]
mod durable_proposals;
