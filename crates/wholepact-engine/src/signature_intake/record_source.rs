//! Concrete proof/signature/exact-transaction journals → participant-local record.
//! This bridge only reads/reconciles existing retained artifacts. It never creates
//! an extraction intent, regenerates transaction bytes or invents original consent.
use super::*;
use crate::participant_records::{
    ParticipantRecordMutation, ParticipantRecordRuntime, RetainParticipantRecordRequest,
    RetainedParticipantRecordSource,
};
use std::collections::BTreeSet;
use std::fmt;
use wholepact_core::records::{
    ExactTransactionReference, OwnAuthorizationRecord, SettlementRecord,
};
use wholepact_core::{Amount, AuthorizationExposure, Proposal};
use wholepact_protocol::authorization::retention::transaction::{
    LocalTransactionCheckpoint, LocalTransactionRecovery, RecoveryAction, RecoveryState,
    TransactionRecoveryConsent, TransactionRecoveryScope,
};
use wholepact_store::{
    StorageProtection, Store,
    authority::{ExposureState, StoredExposure},
};

/// Approval-time facts reconstructed from actual retained protocol and release
/// journals. No serialized version of this object is an authority token.
#[derive(Clone, PartialEq, Eq)]
pub struct OriginalAuthorizationConsentScope {
    pub principal_id: String,
    pub agreement_id: String,
    pub candidate_id: String,
    pub participant_id: String,
    pub account_id: String,
    pub authorization_id: String,
    pub release_intent_digest: String,
    pub manifest_digest: String,
    pub effects_commitment: String,
    pub proved_artifact_digest: String,
    pub review_binding: String,
    /// Protocol nullifiers, never unverified app-local note labels.
    pub input_ids: Vec<String>,
    pub exact_net_debit: Amount,
}
impl fmt::Debug for OriginalAuthorizationConsentScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalAuthorizationConsentScope { private_binding: [REDACTED] }")
    }
}
/// Runtime-held original authorization-history permission and provenance. The
/// original reference must name a real retained signer consent record issued
/// before the authorization, not a new receipt or digest of collected signatures.
pub trait OriginalAuthorizationConsentLease {
    fn scope(&self) -> &OriginalAuthorizationConsentScope;
    fn original_consent_record_ref(&self) -> &str;
    fn expires_at(&self) -> &Timestamp;
    fn check_current(&self) -> Result<()>;
}
/// Trusted issuer checks the exact protected release journal, authenticated
/// original signer/account and immutable consent record, then holds that binding
/// current for the returned guard's lifetime. The signer bridge is a concrete issuer.
pub trait OriginalAuthorizationConsentSource {
    fn acquire<'a>(
        &'a self,
        scope: &OriginalAuthorizationConsentScope,
        release_journal: &Store,
        now: &Timestamp,
    ) -> Result<Box<dyn OriginalAuthorizationConsentLease + 'a>>;
}
pub enum OriginalAuthorizationHistory<'a> {
    /// Existing local signer embedding with an independently protected ledger.
    ProtectedJournal {
        journal: &'a Store,
        authorization_id: &'a str,
        consent: Option<&'a dyn OriginalAuthorizationConsentSource>,
    },
    /// Live authenticated read of the actual signer-owned originals. This is
    /// not a serialized history import or an assertion of complete account history.
    #[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
    AuthenticatedSigner {
        history: &'a wholepact_signer::authority_bridge::ipc::OriginalHistoryLease<'a>,
    },
}
impl<'history> OriginalAuthorizationHistory<'history> {
    fn exposure(&self, account_id: &str) -> Result<StoredExposure> {
        match self {
            Self::ProtectedJournal {
                journal,
                authorization_id,
                consent,
            } => {
                consent.ok_or_else(missing_original_history)?;
                if journal.protection() != StorageProtection::Encrypted {
                    return Err(ApiError::new(
                        "STORAGE_PROTECTION_REQUIRED",
                        "Original authorization history requires protected storage",
                    ));
                }
                require_reconciled_original_history(journal, account_id)?;
                journal
                    .exposure(authorization_id)
                    .map_err(crate::store_error)?
                    .ok_or_else(missing_original_history)
            }
            #[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
            Self::AuthenticatedSigner { history } => {
                history
                    .check_current()
                    .map_err(|_| missing_original_history())?;
                let original = history.evidence();
                let intent = original.release_intent.intent();
                if intent.account_id != account_id || original.retained_result.is_none() {
                    return Err(missing_original_history());
                }
                // The receipt records known released authority conservatively.
                // It does not mirror incomplete account history into a writable
                // ledger or infer resolution from a historical signer reply.
                Ok(StoredExposure {
                    intent: intent.clone(),
                    state: ExposureState::OutstandingUncertain,
                    release_intent_recorded: true,
                    created_at_ms: 0,
                    updated_at_ms: 0,
                })
            }
        }
    }
    fn acquire(
        &self,
        scope: &OriginalAuthorizationConsentScope,
        now: &Timestamp,
    ) -> Result<Box<dyn OriginalAuthorizationConsentLease + 'history>> {
        match self {
            Self::ProtectedJournal {
                journal, consent, ..
            } => consent
                .ok_or_else(missing_original_history)?
                .acquire(scope, journal, now),
            #[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
            Self::AuthenticatedSigner { history } => {
                super::authority_bridge::validate_original_scope(history.evidence(), scope)?;
                history
                    .check_current()
                    .map_err(|_| missing_original_history())?;
                let expires = Timestamp::from_unix_seconds(
                    now.unix_seconds()
                        .checked_add(60)
                        .ok_or_else(missing_original_history)?,
                )
                .map_err(|_| missing_original_history())?;
                Ok(Box::new(BorrowedSignerConsent {
                    history,
                    scope: scope.clone(),
                    expires,
                }))
            }
        }
    }
}
#[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
struct BorrowedSignerConsent<'a> {
    history: &'a wholepact_signer::authority_bridge::ipc::OriginalHistoryLease<'a>,
    scope: OriginalAuthorizationConsentScope,
    expires: Timestamp,
}
#[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
impl OriginalAuthorizationConsentLease for BorrowedSignerConsent<'_> {
    fn scope(&self) -> &OriginalAuthorizationConsentScope {
        &self.scope
    }
    fn original_consent_record_ref(&self) -> &str {
        self.history.evidence().consent.reference()
    }
    fn expires_at(&self) -> &Timestamp {
        &self.expires
    }
    fn check_current(&self) -> Result<()> {
        self.history
            .check_current()
            .map_err(|_| missing_original_history())
    }
}
/// All roles are local borrowed handles to separately protected journals/gates.
/// This is deliberately not serializable and never accepted by the HTTP service.
pub struct LocalParticipantRecordSource<'a> {
    pub proof: LocalProofJob<'a>,
    pub signatures: LocalSignedRetention<'a>,
    pub transaction: LocalTransactionCheckpoint<'a>,
    pub transaction_read_consent: &'a dyn TransactionRecoveryConsent,
    pub deliveries: &'a [AuthenticatedSignatureDelivery<'a>],
    pub signature_idempotency_key: &'a str,
    pub original_authorization: OriginalAuthorizationHistory<'a>,
    pub now: &'a Timestamp,
}

impl Engine {
    /// Retain a participant record only after actual maintained proof/signature
    /// and exact saved-byte verification, own durable release and original user
    /// consent provenance. The outer account/record lease spans the source call
    /// and encrypted CAS commit. No success label or chain observation is created.
    #[allow(clippy::too_many_arguments)]
    pub fn retain_participant_record_from_protocol(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: RetainParticipantRecordRequest,
        runtime: ParticipantRecordRuntime<'_>,
        local: LocalParticipantRecordSource<'_>,
    ) -> Result<ParticipantRecordMutation> {
        if runtime.window.now != local.now.as_str() {
            return Err(ApiError::new(
                "RECORD_SOURCE_REJECTED",
                "Record runtime and protected protocol source must use the same current clock assessment",
            ));
        }
        let mut source = RetainedProtocolRecordSource {
            engine: self,
            access,
            local,
            original_lease: None,
        };
        self.retain_participant_record(
            access,
            key,
            agreement_id,
            revision,
            request,
            runtime,
            &mut source,
        )
    }
}

struct RetainedProtocolRecordSource<'engine, 'artifacts> {
    engine: &'engine Engine,
    access: &'engine Access,
    local: LocalParticipantRecordSource<'artifacts>,
    // The issuer's guard remains held through the caller's encrypted CAS commit
    // and through replay return, not merely while private source bytes are read.
    original_lease: Option<Box<dyn OriginalAuthorizationConsentLease + 'artifacts>>,
}
struct InspectOnlyRecovery<'a>(&'a dyn TransactionRecoveryConsent);
impl TransactionRecoveryConsent for InspectOnlyRecovery<'_> {
    fn permits(&self, scope: &TransactionRecoveryScope<'_>) -> bool {
        scope.action == RecoveryAction::InspectExistingIntent && self.0.permits(scope)
    }
}
impl RetainedParticipantRecordSource for RetainedProtocolRecordSource<'_, '_> {
    fn source_id(&self) -> &str {
        "retained-protocol-and-original-consent-v1"
    }
    fn load_retained_record(
        &mut self,
        request: &RetainParticipantRecordRequest,
        candidate: &Proposal,
    ) -> Result<SettlementRecord> {
        let original = &self.local.original_authorization;
        let exposure = original.exposure(&request.account_id)?;
        if self
            .local
            .deliveries
            .iter()
            .any(|delivery| delivery.association.is_none())
        {
            return Err(association_missing());
        }
        let (_, saved_candidate) = self.engine.candidate(self.access, &request.candidate_id)?;
        let saved_candidate = saved_candidate.verified_snapshot()?;
        if saved_candidate != *candidate {
            return Err(source_rejected());
        }
        let checkpoint = self.engine.load_candidate_proof_for_local_review(
            self.access,
            &request.candidate_id,
            LocalProofJob {
                job_id: self.local.proof.job_id,
                jobs: self.local.proof.jobs,
                consent: self.local.proof.consent,
            },
        )?;
        let review =
            wholepact_protocol::review::verify_review(checkpoint.pczt_bytes(), checkpoint.policy())
                .map_err(|_| source_rejected())?;
        let (context, signatures) = retention_inputs(
            &checkpoint,
            &candidate.manifest().agreement.agreement_id,
            &candidate.input().proposal_id,
            candidate.manifest().agreement.revision.into(),
            self.local.deliveries,
            self.local.now,
            true,
        )?;
        let own_index = checkpoint
            .policy()
            .participants
            .iter()
            .position(|p| p.account_id == request.account_id)
            .ok_or_else(source_rejected)?;
        let allocation = candidate
            .manifest()
            .participants
            .iter()
            .find(|p| {
                p.participant_id == request.participant_id && p.account_id == request.account_id
            })
            .ok_or_else(source_rejected)?;
        if !self.local.deliveries.iter().any(|delivery| {
            delivery
                .association
                .is_some_and(|association| association.account_id == request.account_id)
        }) {
            return Err(source_rejected());
        }
        let actual_debit = Amount::from_zatoshis(
            *review
                .net_debits_zatoshis()
                .get(own_index)
                .ok_or_else(source_rejected)?,
        )
        .map_err(wholepact_core::CoreError::from)?;
        if candidate
            .accounting()
            .participant_net_debits
            .get(&request.participant_id)
            != Some(&actual_debit)
            || actual_debit > allocation.maximum_net_debit
        {
            return Err(source_rejected());
        }
        let mut input_ids: Vec<_> = checkpoint
            .policy()
            .inputs
            .iter()
            .filter(|input| input.participant_index == own_index)
            .map(|input| hex::encode(input.nullifier))
            .collect();
        input_ids.sort();
        if input_ids.is_empty()
            || input_ids.len() > 256
            || input_ids.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(source_rejected());
        }
        validate_original_release(
            &exposure,
            request,
            candidate,
            &context.proved_artifact_digest,
            review.shielded_sighash(),
            actual_debit,
            &input_ids,
        )?;
        let scope = OriginalAuthorizationConsentScope {
            principal_id: self.access.principal_id.clone(),
            agreement_id: candidate.manifest().agreement.agreement_id.clone(),
            candidate_id: request.candidate_id.clone(),
            participant_id: request.participant_id.clone(),
            account_id: request.account_id.clone(),
            authorization_id: exposure.intent.authorization_id.clone(),
            release_intent_digest: wholepact_store::request_digest(
                &serde_json::to_value(&exposure.intent).map_err(|_| source_rejected())?,
            )
            .map_err(crate::store_error)?,
            manifest_digest: candidate.manifest_digest().into(),
            effects_commitment: review.shielded_sighash().into(),
            proved_artifact_digest: context.proved_artifact_digest.clone(),
            review_binding: review.review_binding().into(),
            input_ids,
            exact_net_debit: actual_debit,
        };
        let original_lease = original.acquire(&scope, self.local.now)?;
        check_original_consent(&*original_lease, &scope, self.local.now)?;
        let consent = Gate {
            original: checkpoint.scope(),
            read: self.local.proof.consent,
            retain: self.local.signatures.consent,
        };
        let signed = self
            .local
            .signatures
            .journal
            .reconcile_existing(
                context.clone(),
                self.local.signature_idempotency_key,
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                &signatures,
                wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
                &consent,
            )
            .map_err(record_retention_error)?;
        if !signed.inspection.signatures_complete {
            return Err(ApiError::new(
                "TRANSACTION_SIGNATURES_INCOMPLETE",
                "A participant settlement record needs the complete retained exact authorization set",
            ));
        }
        let inspect_only = InspectOnlyRecovery(self.local.transaction_read_consent);
        let recovered = self
            .local
            .signatures
            .journal
            .recover_transaction_checkpoint(
                context,
                self.local.signature_idempotency_key,
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                &signatures,
                wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
                &consent,
                LocalTransactionRecovery {
                    destination: LocalTransactionCheckpoint {
                        journal: self.local.transaction.journal,
                        consent: self.local.transaction.consent,
                    },
                    retained_copy: None,
                    consent: &inspect_only,
                },
            )
            .map_err(record_retention_error)?;
        if recovered.state != RecoveryState::CompleteExactReplay {
            return Err(ApiError::new(
                "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED",
                "Original exact transaction bytes are missing or fenced; the record source will not regenerate them",
            ));
        }
        let transaction = recovered.checkpoint.ok_or_else(source_rejected)?;
        if transaction.signed_result_id != signed.result_id || !transaction.exact_replay {
            return Err(source_rejected());
        }
        check_original_consent(&*original_lease, &scope, self.local.now)?;
        let current = original.exposure(&request.account_id)?;
        if current.intent != exposure.intent || !current.release_intent_recorded {
            return Err(missing_original_history());
        }
        let mut approved = candidate.input().clone();
        approved.artifact_digest = Some(signed.signed_candidate_digest);
        approved.effects_commitment = Some(scope.effects_commitment.clone());
        let approved = Proposal::validate(approved)?;
        let own = OwnAuthorizationRecord {
            participant_id: request.participant_id.clone(),
            account_id: request.account_id.clone(),
            proposal_digest: approved.proposal_digest().into(),
            manifest_digest: approved.manifest_digest().into(),
            effects_commitment: scope.effects_commitment.clone(),
            consent_record_ref: original_lease.original_consent_record_ref().into(),
            authorization_record_ref: current.intent.authorization_id.clone(),
            release_operation_id: Some(current.intent.authorization_id),
            // A durable release intent may have crossed the boundary before a
            // crash even when its cached state still reads authorized_locally.
            exposure: match current.state {
                ExposureState::AuthorizedLocally | ExposureState::OutstandingUncertain => {
                    AuthorizationExposure::OutstandingUncertain
                }
                ExposureState::Released => AuthorizationExposure::Released,
                ExposureState::ExpiredObserved => AuthorizationExposure::ExpiredObserved,
                ExposureState::ConflictedObserved => AuthorizationExposure::ConflictedObserved,
                ExposureState::Consumed => AuthorizationExposure::Consumed,
            },
        };
        let record = SettlementRecord::new(
            request.record_id.clone(),
            approved,
            own,
            ExactTransactionReference {
                network_profile_id: candidate.manifest().agreement.network_profile_id.clone(),
                transaction_id: transaction.txid,
                transaction_bytes_digest: transaction.transaction_digest,
                effects_commitment: scope.effects_commitment.clone(),
            },
        )?;
        check_original_consent(&*original_lease, &scope, self.local.now)?;
        self.original_lease = Some(original_lease);
        Ok(record)
    }
    fn validate_replay(
        &mut self,
        request: &RetainParticipantRecordRequest,
        candidate: &Proposal,
        retained: &SettlementRecord,
    ) -> Result<()> {
        let current = self.load_retained_record(request, candidate)?;
        let previous = retained.own_authorization();
        let refreshed = current.own_authorization();
        if current.proposal() != retained.proposal()
            || current.transaction() != retained.transaction()
            || refreshed.participant_id != previous.participant_id
            || refreshed.account_id != previous.account_id
            || refreshed.consent_record_ref != previous.consent_record_ref
            || refreshed.authorization_record_ref != previous.authorization_record_ref
            || refreshed.release_operation_id != previous.release_operation_id
        {
            return Err(source_rejected());
        }
        // The record keeps its original exposure and observations. A current
        // ledger assessment can never silently rewrite the retained receipt.
        Ok(())
    }
}
// An account-level imported-history fence is independent of the Store-wide
// archive fence. Existing private records remain inspectable under their own
// read lease; only fresh verified reconstruction through this source is refused.
fn require_reconciled_original_history(journal: &Store, account_id: &str) -> Result<()> {
    if journal
        .recovery_state()
        .map_err(crate::store_error)?
        .recovery_required
        || journal
            .authority_account(account_id)
            .map_err(crate::store_error)?
            .is_none_or(|account| account.recovery_required)
    {
        return Err(missing_original_history());
    }
    Ok(())
}
fn check_original_consent(
    lease: &dyn OriginalAuthorizationConsentLease,
    expected: &OriginalAuthorizationConsentScope,
    now: &Timestamp,
) -> Result<()> {
    if lease.scope() != expected || lease.expires_at().unix_seconds() <= now.unix_seconds() {
        return Err(missing_original_history());
    }
    let reference = lease.original_consent_record_ref();
    if reference.is_empty()
        || reference.len() > 128
        || !reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(missing_original_history());
    }
    lease.check_current()
}
#[allow(clippy::too_many_arguments)]
fn validate_original_release(
    exposure: &StoredExposure,
    request: &RetainParticipantRecordRequest,
    candidate: &Proposal,
    proved_digest: &str,
    effects: &str,
    debit: Amount,
    input_ids: &[String],
) -> Result<()> {
    let intent = &exposure.intent;
    let stored_inputs: BTreeSet<_> = intent.input_ids.iter().map(String::as_str).collect();
    if !exposure.release_intent_recorded
        || intent.account_id != request.account_id
        || intent.proposal_id != request.candidate_id
        || intent.obligation_id != candidate.manifest().agreement.obligation_id
        || intent.manifest_digest != candidate.manifest_digest()
        || intent.effects_digest != effects
        || intent.artifact_digest != proved_digest
        || Amount::parse_zatoshis(&intent.maximum_debit).ok() != Some(debit)
        || stored_inputs.len() != intent.input_ids.len()
        || stored_inputs != input_ids.iter().map(String::as_str).collect()
    {
        return Err(source_rejected());
    }
    Ok(())
}
fn missing_original_history() -> ApiError {
    let mut error = ApiError::new(
        "ORIGINAL_AUTHORIZATION_HISTORY_MISSING",
        "The original signer consent and exact release history are missing, expired, revoked or unreconciled; no participant record success can be inferred from collected signatures",
    );
    error.safe_actions = vec![
        "Locate the original protected signer consent and release journal".into(),
        "Reconcile the same retained authorization without creating a new payment".into(),
    ];
    error
}
fn source_rejected() -> ApiError {
    ApiError::new(
        "RECORD_SOURCE_REJECTED",
        "Retained proof, signatures, transaction, account association and original authorization history do not bind the same exact participant payment",
    )
}
fn record_retention_error(error: RetentionError) -> ApiError {
    match error {
        RetentionError::ConsentDenied => ApiError::new(
            "RECORD_SOURCE_CONSENT_DENIED",
            "Current protected artifact/transaction read permission was denied",
        ),
        RetentionError::IntentNotFound | RetentionError::RecoveryRequired => ApiError::new(
            "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED",
            "Existing protected signature/transaction history is missing or fenced; no record source extraction is permitted",
        ),
        RetentionError::IncompleteSignatures => ApiError::new(
            "TRANSACTION_SIGNATURES_INCOMPLETE",
            "Retained transaction does not have every required signature",
        ),
        _ => source_rejected(),
    }
}
