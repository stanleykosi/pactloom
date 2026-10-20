//! Shared local orchestration for the service, CLI, and workspace.
//!
//! Durable nonbinding agreement and exact candidate orchestration. Local economic
//! computation never grants human approval, disclosure, signing, or submission.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, sync::Arc};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use wholepact_core::{AgreementDraft, CoreError, IntentStatus, ParticipationIntent};
use wholepact_store::{CommandContext, MutationResult, Store, StoredEvent, StoredRecord};

pub const MAX_AGREEMENTS: usize = 256;
pub const MAX_INTENTS: usize = 32;
pub const MAX_PROPOSALS: usize = 64;
pub const MAX_REVIEWS: usize = 128;
#[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
pub mod automation;
pub mod backups;
#[cfg(all(
    feature = "manual-admission",
    feature = "local-proof-jobs",
    target_os = "linux"
))]
pub mod born_offline_checkpoint_original_v1;
#[cfg(all(
    feature = "manual-admission",
    feature = "local-proof-jobs",
    target_os = "linux"
))]
pub mod born_offline_saved_proof_v1;
pub mod candidates;
#[cfg(all(feature = "durable-proposal", target_os = "linux"))]
pub mod durable_construction_v1;
// Compiler/component qualification only. These modules deliberately expose no
// shared-Engine discovery API or public private-workspace factory. Native
// discovery issuance and the Host dependency/privacy boundary remain inactive.
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) mod durable_input_projections_v1;
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) mod durable_private_workspace_v1;
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub use durable_private_workspace_v1::{
    PreparedPrivateDurableAdmissionDeliveryV3, ClosedPrivateDurableAdmissionReviewV3, PrivateDurableAdmissionDeliveryV3, PrivateDurableAdmissionStatusV3,
    LocalPrivateDurableAdmissionConsentV2, LocalPrivateFixedPermissionBoundaryV3,
    LocalPrivateWorkspaceConsentV1, OriginalCheckpointOutcomeV2, OriginalProofAttemptV2,
    PreparedPrivateDurableCoordinatorV1, PrivateDurableAdmissionCoordinatorV2,
    PrivateDurableAdmissionDeliveryV2, PrivateDurableAdmissionInspectionV2,
    PrivateDurableAdmissionStatusV2, PrivateDurableCoordinatorV1, PrivateDurableWorkspaceSourceV1,
    PrivateExactCandidateV2, PrivateFixedArtifactCallbackV3, PrivateFixedMaterialReviewV3,
    PrivateFixedObservationCallbackV3, PrivateFixedPermissionRequestV3, PrivateFixedStageReviewV3,
    PrivateFixedStageV3, PrivateFixedStatusV2, PrivateVerifiedFixedV2, PrivateWorkspaceActionV1,
    PrivateWorkspaceInitializationPlanV1, PrivateWorkspaceScopeV1, PrivateWorkspaceSeedBindingV1,
    PrivateWorkspaceStatusV1,
};
#[cfg(feature = "durable-proposal")]
pub mod durable_proposals_v1;
pub mod financial_preflight;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub mod manual_enrollment;
#[cfg(all(
    feature = "manual-admission",
    feature = "signer-authority-bridge",
    feature = "wallet-sync",
    feature = "local-proof-jobs",
    target_os = "linux"
))]
pub mod manual_roster_construct_v2;
#[cfg(all(
    feature = "manual-admission",
    feature = "signer-authority-bridge",
    feature = "wallet-sync",
    feature = "local-proof-jobs",
    target_os = "linux"
))]
pub mod manual_roster_construct_v3;
pub mod native_account_inspection_requests;
pub mod native_artifact_handoff_requests;
pub mod native_dispatch_requests;
pub mod native_proof_execution_requests;
pub mod native_proof_requests;
pub mod native_reconciliation_requests;
pub mod native_requests;
pub mod native_settlement_requests;
pub mod participant_records;
pub mod planning;
mod private_workspace_origin_v1;
#[cfg(feature = "local-proof-jobs")]
pub mod proof_jobs;
pub mod recovery;
#[cfg(feature = "signature-intake")]
pub mod signature_intake;
pub mod sponsor_policies;
pub mod terms_revisions;
#[cfg(feature = "transport-workflows")]
pub mod transport_workflows;
pub use candidates::{CandidateRequest, CandidateReview, CandidateView};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub operation_id: Option<String>,
    pub details: Box<Value>,
    pub safe_actions: Vec<String>,
}
impl ApiError {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: false,
            operation_id: None,
            details: Box::new(json!({})),
            safe_actions: vec![],
        }
    }
    pub fn unsupported() -> Self {
        let mut e = Self::new(
            "UNSUPPORTED_CAPABILITY",
            "No qualified wallet, signer, protocol verifier, prover, or chain adapter is connected. Terms remain nonbinding; no authorization or payment was created.",
        );
        e.safe_actions = vec![
            "Inspect capabilities and qualification evidence".into(),
            "Continue editing unsigned local terms".into(),
        ];
        e
    }
}
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for ApiError {}
impl From<CoreError> for ApiError {
    fn from(value: CoreError) -> Self {
        let code = serde_json::to_value(value.code)
            .ok()
            .and_then(|v| v.as_str().map(str::to_uppercase))
            .unwrap_or_else(|| "INVALID_TERMS".into());
        Self::new(
            if code == "RESOURCE_LIMIT" {
                "RESOURCE_EXHAUSTED"
            } else {
                &code
            },
            &value.message,
        )
    }
}
pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Clone, Default)]
pub struct Access {
    pub principal_id: String,
    pub agreement_ids: BTreeSet<String>,
    pub all_agreements: bool,
    /// Explicit OWNED scope. False by default, including newly created agreements.
    pub include_owned_agreements: bool,
}
impl Access {
    /// Pure scope predicate; this does not establish current native or financial authority.
    pub fn permits_agreement(&self, id: &str, owner: &str) -> bool {
        self.all_agreements
            || (self.include_owned_agreements && self.principal_id == owner)
            || self.agreement_ids.contains(id)
    }
    fn sees(&self, id: &str, owner: &str) -> bool {
        self.permits_agreement(id, owner)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalPreview {
    pub proposal_id: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub revision: u32,
    pub previous_proposal_id: Option<String>,
    pub manifest: Value,
    pub manifest_digest: String,
    pub artifact_digest: Option<String>,
    pub effects_commitment: Option<String>,
    pub status: String,
    pub created_at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReport {
    pub report_id: String,
    pub proposal_id: String,
    pub manifest_digest: String,
    pub artifact_digest: Option<String>,
    pub effects_commitment: Option<String>,
    pub status: String,
    pub checked_at: String,
    pub checks: Vec<Value>,
    pub blocking_errors: Vec<ApiError>,
    pub review_summary: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgreementView {
    pub agreement: AgreementDraft,
    /// Immutable previous terms, ordered by terms revision. Journal revisions are separate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terms_history: Vec<AgreementDraft>,
    /// Current caller/lifecycle guidance, recomputed from durable history on reads.
    #[serde(
        default,
        skip_serializing_if = "terms_revisions::TermsEditability::is_unavailable"
    )]
    pub terms_editability: terms_revisions::TermsEditability,
    pub revision: u64,
    pub progress: String,
    pub authorization_exposure: String,
    pub chain_observation: String,
    pub intents: Vec<ParticipationIntent>,
    /// An explicit nonbinding roster was selected. Withdrawal never clears this
    /// marker or implicitly substitutes other interested participants.
    #[serde(default)]
    pub roster_selected: bool,
    pub proposals: Vec<ProposalPreview>,
    pub verification_reports: Vec<ReviewReport>,
    #[serde(default)]
    pub candidates: Vec<CandidateView>,
    pub cancellation_requested: bool,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    /// Recognized in every build. Present null/malformed is never legacy.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "private_workspace_origin_v1::deserialize_present_marker"
    )]
    private_workspace_origin_v1:
        Option<wholepact_store::private_workspace_origin_v1::PrivateWorkspaceOriginV1>,
    /// Recognized even without this profile: unsupported builds must refuse
    /// nonempty private history rather than silently project its derived view.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    durable_input_projections_v1: std::collections::BTreeMap<String, Value>,
    /// Private purpose-distinct disclosure receipts. Never projected in views.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    durable_construction_v1: std::collections::BTreeMap<String, Value>,
    /// Versioned data-only durable proposal records. Kept opaque in builds that
    /// do not compile this experimental profile, so old history stays readable.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    durable_proposals_v1: std::collections::BTreeMap<String, Value>,
    /// Only new drafts created with durable pre-disclosure closure semantics qualify.
    #[serde(default, skip_serializing_if = "terms_revisions::is_false")]
    terms_editing_origin: bool,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    native_requests: std::collections::BTreeMap<String, native_requests::StoredNativeRequest>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    native_proof_requests:
        std::collections::BTreeMap<String, native_proof_requests::StoredNativeProofRequest>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    native_proof_execution_requests: std::collections::BTreeMap<
        String,
        native_proof_execution_requests::StoredNativeProofExecutionRequest,
    >,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    native_artifact_handoff_requests: std::collections::BTreeMap<
        String,
        native_artifact_handoff_requests::StoredNativeArtifactHandoffRequest,
    >,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    native_settlement_requests: std::collections::BTreeMap<
        String,
        native_settlement_requests::StoredNativeSettlementRequest,
    >,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    native_dispatch_requests:
        std::collections::BTreeMap<String, native_dispatch_requests::StoredNativeDispatchRequest>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    native_reconciliation_requests: std::collections::BTreeMap<
        String,
        native_reconciliation_requests::StoredNativeReconciliationRequest,
    >,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    native_account_inspection_requests: std::collections::BTreeMap<
        String,
        native_account_inspection_requests::StoredNativeAccountInspectionRequest,
    >,
    owner_client_id: String,
    #[serde(default)]
    sponsor_policies: std::collections::BTreeMap<String, sponsor_policies::StoredSponsorPolicy>,
    #[serde(default)]
    participant_records:
        std::collections::BTreeMap<String, participant_records::StoredParticipantRecord>,
    #[serde(default)]
    transport_peer_grants: std::collections::BTreeMap<String, Value>,
    #[serde(default)]
    checkpoint_receipts: std::collections::BTreeMap<String, candidates::CheckpointReceipt>,
    intent_owners: std::collections::BTreeMap<String, String>,
    view: AgreementView,
}
#[derive(Clone, Debug, Serialize)]
pub struct Mutation {
    pub agreement: AgreementView,
    pub operation_id: String,
    pub event_sequence: u64,
    pub replayed: bool,
}

/// Public event DTO. Database time representation is deliberately not wire API.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub event_id: String,
    pub sequence: u64,
    pub occurred_at: String,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub aggregate_revision: u64,
    pub kind: String,
    pub payload: Value,
    pub operation_id: String,
}
impl TryFrom<StoredEvent> for Event {
    type Error = ApiError;
    fn try_from(stored: StoredEvent) -> Result<Self> {
        let occurred_at = timestamp_from_ms(stored.occurred_at_ms)?;
        Ok(Self {
            event_id: stored.event_id,
            sequence: stored.sequence,
            occurred_at,
            aggregate_type: stored.aggregate_type,
            aggregate_id: stored.aggregate_id,
            aggregate_revision: stored.aggregate_revision,
            kind: stored.kind,
            payload: stored.payload,
            operation_id: stored.operation_id,
        })
    }
}

/// Public operation DTO, with no storage envelope or client ownership metadata.
#[derive(Clone, Debug, Serialize)]
pub struct Operation {
    pub operation_id: String,
    pub kind: String,
    pub resource_id: String,
    pub status: String,
    pub result: Mutation,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct Engine {
    store: Arc<Store>,
}
impl Engine {
    /// Inject an already-opened store, including one verified by the SQLCipher factory.
    /// This performs no network activity and never accepts a caller-supplied protection flag.
    pub fn from_store(store: Store) -> Self {
        Self {
            store: Arc::new(store),
        }
    }
    pub fn storage_protection(&self) -> &'static str {
        match self.store.protection() {
            wholepact_store::StorageProtection::Encrypted => "encrypted_local_metadata",
            wholepact_store::StorageProtection::InMemory => "ephemeral_in_memory",
            wholepact_store::StorageProtection::PlaintextDevelopment => {
                "local_metadata_unencrypted"
            }
        }
    }
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            store: Arc::new(Store::open(path).map_err(store_error)?),
        })
    }
    pub fn in_memory() -> Result<Self> {
        Ok(Self {
            store: Arc::new(Store::in_memory().map_err(store_error)?),
        })
    }

    pub fn capabilities(&self) -> Value {
        json!({
            "api_version": "1", "engine_version": env!("CARGO_PKG_VERSION"),
            "features": {
                "local_agreements":{"status":"supported","reason_code":null,"evidence_reference":"crates/wholepact-engine/tests","operations":["create","read","validate","revise_unsigned_terms","intent","withdraw","select_roster","terms_preview","compare_proposals","review_report","cancellation_request"]},
                "sponsor_policies":{"status":"supported","reason_code":null,"scope":"nonbinding_policy_preparation","operations":["create","read","version","pause","resume_draft","retire","preview_candidate_formula"],"verified_match_available":false,"account_control_verified":false,"aggregate_exposure_available":false,"authorization_allowed":false,"evidence_reference":"docs/sponsor-policies.md"},
                "candidate_terms":{"status":"supported","reason_code":null,"evidence_reference":"docs/candidate-workflow.md","operations":["create","read","compare_candidates","review_claimed_accounting"]},
                "local_candidate_construction":{"status":if cfg!(feature="candidate-construction") {"experimental"} else {"unavailable"},"reason_code":"NO_AUTHENTICATED_DISCLOSURE_OR_CHAIN_APPROVAL","evidence_reference":"docs/candidate-workflow.md","operations":if cfg!(feature="candidate-construction") {vec!["embedded_local_computation"]} else {vec![]}},
                "cooperative_settlement":{"status":"unavailable","reason_code":"PROTOCOL_NOT_QUALIFIED","evidence_reference":"docs/protocol-qualification.md","operations":[]},
                "local_proof_checkpoints":{"status":if cfg!(feature="local-proof-jobs") {"experimental"} else {"unavailable"},"reason_code":"TRUSTED_LOCAL_PRIVACY_GATE_REQUIRED","evidence_reference":"docs/candidate-workflow.md","operations":if cfg!(feature="local-proof-jobs") {vec!["embedded_checkpoint","embedded_local_proof","reconcile_checkpoint_link","embedded_proof_review_read"]} else {vec![]}},
                "protected_wallet_checkpoint":{"status":if cfg!(all(feature="wallet-sync",feature="local-proof-jobs")) {"experimental"} else {"unavailable"},"reason_code":"CURRENT_WALLET_PROVENANCE_AND_LOCAL_PRIVACY_GATE_REQUIRED","evidence_reference":"docs/candidate-workflow.md","operations":if cfg!(all(feature="wallet-sync",feature="local-proof-jobs")) {vec!["embedded_checkpoint_from_wallets"]} else {vec![]}},
                "encrypted_backups":{"status":if self.store.protection()==wholepact_store::StorageProtection::Encrypted {"experimental"} else {"unavailable"},"reason_code":if self.store.protection()==wholepact_store::StorageProtection::Encrypted {"TRUSTED_FULL_JOURNAL_ADMINISTRATION_REQUIRED"} else {"ENCRYPTED_STORAGE_REQUIRED"},"interface":"trusted_local_rust_embedding_only","http_available":false,"scope":"complete_coordination_and_local_authority_journal_only","separate_private_journals_included":false,"evidence_reference":"docs/engine-journal-backup.md","operations":if self.store.protection()==wholepact_store::StorageProtection::Encrypted {vec!["embedded_full_journal_backup","embedded_test_restore","embedded_quarantined_restore"]} else {vec![]}},
                "automation":{"status":"unavailable","reason_code":"SIGNER_AUTHORITY_NOT_CONNECTED","evidence_reference":null,"operations":[]}
            },
            "profiles":[{"id":"zcash-testnet-unqualified","network":"testnet","status":"unavailable","reason_code":"PROTOCOL_NOT_QUALIFIED","evidence_reference":"docs/protocol-qualification.md","operations":[]},{"id":"ironwood-testnet-nu7-candidate","network":"testnet","status":"experimental","reason_code":"UNSIGNED_CANDIDATE_ONLY","evidence_reference":"docs/candidate-workflow.md","operations":["candidate_terms","review_claimed_accounting"]}],
            "adapters":[], "limits":{"agreements":MAX_AGREEMENTS,"participants":MAX_INTENTS,"proposals_per_agreement":MAX_PROPOSALS,"request_bytes":262144,"event_batch":100,"settlement_participants":0},
            "runtime":{"storage":self.storage_protection(),"signer":"not_connected","chain":"not_connected","background_observation":false,"development_only":true}
        })
    }
    pub fn validate(&self, agreement: &AgreementDraft) -> Result<Value> {
        agreement.validate()?;
        check_profile(agreement)?;
        Ok(
            json!({"valid":true,"scope":"syntax_and_arithmetic_only","signable":false,"warnings":["Recipient address, ownership, chain context, and actual transaction effects are not verified."]}),
        )
    }
    pub fn list(&self, access: &Access) -> Result<Vec<AgreementView>> {
        self.store
            .list_agreements()
            .map_err(store_error)?
            .into_iter()
            .filter_map(|record| match decode(&record) {
                Ok(e) if access.sees(&record.id, &e.owner_client_id) => {
                    Some(self.present_terms_editability(&access.principal_id, e))
                }
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .collect()
    }
    fn load(&self, access: &Access, id: &str) -> Result<Envelope> {
        let record = self
            .store
            .get_agreement(id)
            .map_err(store_error)?
            .ok_or_else(not_found)?;
        let envelope = decode(&record)?;
        if !access.sees(id, &envelope.owner_client_id) {
            return Err(not_found());
        }
        Ok(envelope)
    }
    pub fn get(&self, access: &Access, id: &str) -> Result<AgreementView> {
        self.present_terms_editability(&access.principal_id, self.load(access, id)?)
    }

    /// New external work must reject an old generation's envelope before any
    /// separate proof, extraction, delivery or submission journal is touched.
    fn require_current_agreement(&self, id: &str) -> Result<()> {
        if self
            .store
            .runtime_recovery_required()
            .map_err(store_error)?
            || self
                .store
                .recovery_record_is_historical("agreement", id)
                .map_err(store_error)?
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Historical agreement artifacts remain inert; fresh operations require a new unfenced agreement and current permissions",
            ));
        }
        Ok(())
    }

    fn replay(&self, access: &Access, context: &CommandContext) -> Result<Option<Mutation>> {
        match self.store.find_replay(context).map_err(store_error)? {
            Some(result) => {
                let envelope = decode(&result.record)?;
                if !access.sees(&result.record.id, &envelope.owner_client_id) {
                    return Err(not_found());
                }
                Ok(Some(mutation(result)?))
            }
            None => Ok(None),
        }
    }
    pub fn create(&self, access: &Access, key: &str, draft: AgreementDraft) -> Result<Mutation> {
        // Ownership of a future agreement cannot expand an exact selected scope.
        if !access.permits_agreement(&draft.agreement_id, &access.principal_id) {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Agreement creation is outside the explicit local scope",
            ));
        }
        let context = context(
            access,
            key,
            "create_agreement",
            &draft.agreement_id,
            None,
            &draft,
        )?;
        if let Some(replay) = self.replay(access, &context)? {
            return Ok(replay);
        }
        draft.validate()?;
        check_profile(&draft)?;
        if draft.revision != 1 {
            return Err(ApiError::new(
                "INVALID_TERMS",
                "A newly created agreement must start at revision 1",
            ));
        }
        if self.store.list_agreements().map_err(store_error)?.len() >= MAX_AGREEMENTS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Local agreement limit reached",
            ));
        }
        let now = now();
        let envelope = Envelope {
            private_workspace_origin_v1: None,
            durable_input_projections_v1: Default::default(),
            durable_construction_v1: Default::default(),
            durable_proposals_v1: Default::default(),
            terms_editing_origin: true,
            native_requests: Default::default(),
            native_account_inspection_requests: Default::default(),
            native_proof_requests: Default::default(),
            native_proof_execution_requests: Default::default(),
            native_artifact_handoff_requests: Default::default(),
            native_settlement_requests: Default::default(),
            native_dispatch_requests: Default::default(),
            native_reconciliation_requests: Default::default(),
            owner_client_id: access.principal_id.clone(),
            sponsor_policies: Default::default(),
            participant_records: Default::default(),
            transport_peer_grants: Default::default(),
            checkpoint_receipts: Default::default(),
            intent_owners: Default::default(),
            view: AgreementView {
                agreement: draft.clone(),
                terms_history: vec![],
                terms_editability: Default::default(),
                revision: 1,
                progress: "gathering_intent".into(),
                authorization_exposure: "unknown".into(),
                chain_observation: "unknown".into(),
                intents: vec![],
                roster_selected: false,
                proposals: vec![],
                verification_reports: vec![],
                candidates: vec![],
                cancellation_requested: false,
                created_at: now.clone(),
                updated_at: now,
            },
        };
        self.present_mutation(
            &access.principal_id,
            self.store
                .create_agreement(&context, &draft.agreement_id, encode(&envelope)?)
                .map_err(store_error)?,
        )
    }
    pub fn add_intent(
        &self,
        access: &Access,
        key: &str,
        id: &str,
        revision: u64,
        intent: ParticipationIntent,
    ) -> Result<Mutation> {
        let context = context(access, key, "record_intent", id, Some(revision), &intent)?;
        if let Some(replay) = self.replay(access, &context)? {
            return Ok(replay);
        }
        let mut envelope = self.load(access, id)?;
        intent.validate()?;
        if intent.agreement_id != id || intent.status != IntentStatus::Active {
            return Err(ApiError::new(
                "INVALID_TERMS",
                "Intent must be active and refer to this agreement",
            ));
        }
        if envelope.view.cancellation_requested {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "This agreement has a cancellation request",
            ));
        }
        if envelope.view.intents.len() >= MAX_INTENTS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Agreement intent limit reached",
            ));
        }
        if envelope.view.intents.iter().any(|i| {
            i.intent_id == intent.intent_id
                || i.participant_id == intent.participant_id && planning::eligible_status(i.status)
        }) {
            return Err(ApiError::new(
                "INVALID_TERMS",
                "Intent ID or active, selected, or waitlisted participant intent already exists",
            ));
        }
        envelope
            .intent_owners
            .insert(intent.intent_id.clone(), access.principal_id.clone());
        envelope.view.intents.push(intent);
        self.commit(&context, id, revision, envelope, "intent_recorded")
    }
    pub fn withdraw(
        &self,
        access: &Access,
        key: &str,
        id: &str,
        intent_id: &str,
        revision: u64,
    ) -> Result<Mutation> {
        let context = context(
            access,
            key,
            "withdraw_intent",
            id,
            Some(revision),
            &json!({"intent_id":intent_id}),
        )?;
        if let Some(replay) = self.replay(access, &context)? {
            return Ok(replay);
        }
        let mut envelope = self.load(access, id)?;
        if envelope.intent_owners.get(intent_id) != Some(&access.principal_id) {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Only the application that recorded this intent can withdraw it",
            ));
        }
        let intent = envelope
            .view
            .intents
            .iter_mut()
            .find(|i| i.intent_id == intent_id)
            .ok_or_else(not_found)?;
        if !planning::eligible_status(intent.status) {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Only an active, selected, or waitlisted intent can be withdrawn",
            ));
        }
        intent.status = IntentStatus::Withdrawn;
        self.commit(&context, id, revision, envelope, "intent_withdrawn")
    }
    pub fn propose(&self, access: &Access, key: &str, id: &str, revision: u64) -> Result<Mutation> {
        let context = context(access, key, "preview_terms", id, Some(revision), &json!({}))?;
        if let Some(replay) = self.replay(access, &context)? {
            return Ok(replay);
        }
        let mut envelope = self.load(access, id)?;
        planning::check_proposer(&envelope, access)?;
        candidates::check_revision(&envelope, revision)?;
        if envelope.view.proposals.len() >= MAX_PROPOSALS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Proposal history limit reached",
            ));
        }
        if envelope.view.cancellation_requested {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "This agreement has a cancellation request",
            ));
        }
        let intents = planning::preview_intents(&envelope.view)?;
        let manifest = json!({"schema_version":1,"agreement":envelope.view.agreement,"intents":intents,"roster_selected":envelope.view.roster_selected,"scope":"unverified_nonbinding_terms"});
        let manifest_digest = hash_domain(b"wholepact:terms-preview:v1\0", &manifest)?;
        let next = u32::try_from(envelope.view.proposals.len() + 1)
            .map_err(|_| ApiError::new("RESOURCE_EXHAUSTED", "Revision limit reached"))?;
        let preview = ProposalPreview {
            proposal_id: Uuid::new_v4().to_string(),
            agreement_id: id.into(),
            obligation_id: envelope.view.agreement.obligation_id.clone(),
            revision: next,
            previous_proposal_id: envelope
                .view
                .proposals
                .last()
                .map(|p| p.proposal_id.clone()),
            manifest,
            manifest_digest,
            artifact_digest: None,
            effects_commitment: None,
            status: "terms_only_not_signable".into(),
            created_at: now(),
        };
        envelope.view.proposals.push(preview);
        envelope.view.progress = "preparing_proposal".into();
        self.commit(&context, id, revision, envelope, "terms_preview_created")
    }
    pub fn proposal(
        &self,
        access: &Access,
        proposal_id: &str,
    ) -> Result<(AgreementView, ProposalPreview)> {
        for agreement in self.list(access)? {
            if let Some(proposal) = agreement
                .proposals
                .iter()
                .find(|p| p.proposal_id == proposal_id)
                .cloned()
            {
                if hash_domain(b"wholepact:terms-preview:v1\0", &proposal.manifest)?
                    != proposal.manifest_digest
                {
                    return Err(ApiError::new(
                        "RECOVERY_REQUIRED",
                        "Terms snapshot digest mismatch; preserve the journal and do not authorize",
                    ));
                }
                return Ok((agreement, proposal));
            }
        }
        Err(not_found())
    }
    pub fn review(
        &self,
        access: &Access,
        key: &str,
        proposal_id: &str,
        revision: u64,
    ) -> Result<Mutation> {
        let context = context(
            access,
            key,
            "review_terms",
            proposal_id,
            Some(revision),
            &json!({}),
        )?;
        if let Some(replay) = self.replay(access, &context)? {
            return Ok(replay);
        }
        let (agreement, proposal) = self.proposal(access, proposal_id)?;
        let id = agreement.agreement.agreement_id;
        let mut envelope = self.load(access, &id)?;
        if envelope.view.verification_reports.len() >= MAX_REVIEWS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Review history limit reached",
            ));
        }
        let report = ReviewReport {
            report_id: Uuid::new_v4().to_string(),
            proposal_id: proposal_id.into(),
            manifest_digest: proposal.manifest_digest,
            artifact_digest: None,
            effects_commitment: None,
            status: "unsupported".into(),
            checked_at: now(),
            checks: vec![
                json!({"code":"TERMS_SNAPSHOT_INTEGRITY","result":"passed","trust_source":"local journal","evidence_provenance":"domain-separated SHA-256 of immutable terms; not a transaction fingerprint"}),
                json!({"code":"ACTUAL_TRANSACTION_EFFECTS","result":"unsupported","trust_source":null,"evidence_provenance":null}),
            ],
            blocking_errors: vec![ApiError::unsupported()],
            review_summary: json!({"signable":false,"scope":"nonbinding_terms_only","message":"No actual transaction exists. Recipient instructions and contribution amounts remain unverified claims."}),
        };
        envelope.view.verification_reports.push(report);
        self.commit(
            &context,
            &id,
            revision,
            envelope,
            "review_blocked_by_unqualified_protocol",
        )
    }
    pub fn cancel(&self, access: &Access, key: &str, id: &str, revision: u64) -> Result<Mutation> {
        let context = context(
            access,
            key,
            "request_cancellation",
            id,
            Some(revision),
            &json!({}),
        )?;
        if let Some(replay) = self.replay(access, &context)? {
            return Ok(replay);
        }
        let mut envelope = self.load(access, id)?;
        if envelope.owner_client_id != access.principal_id {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Only the creating application can request agreement-wide cancellation; withdraw your own intent separately",
            ));
        }
        if envelope.view.cancellation_requested {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Cancellation was already requested",
            ));
        }
        envelope.view.cancellation_requested = true;
        envelope.view.progress = "cancellation_requested".into();
        // Deliberately leave exposure and chain observation untouched.
        self.commit(&context, id, revision, envelope, "cancellation_requested")
    }
    fn commit(
        &self,
        context: &CommandContext,
        id: &str,
        revision: u64,
        mut envelope: Envelope,
        kind: &str,
    ) -> Result<Mutation> {
        private_workspace_origin_v1::refuse_public_payload(&encode(&envelope)?)?;
        envelope.view.revision = revision
            .checked_add(1)
            .ok_or_else(|| ApiError::new("RESOURCE_EXHAUSTED", "Revision limit reached"))?;
        envelope.view.updated_at = now();
        self.present_mutation(
            &context.principal_id,
            self.store
                .update_agreement(context, id, revision, encode(&envelope)?, kind)
                .map_err(store_error)?,
        )
    }
    pub fn events(&self, access: &Access, after: u64, limit: u32) -> Result<Value> {
        Ok(self.event_batch(access, after, limit)?.0)
    }
    pub fn event_batch(&self, access: &Access, after: u64, limit: u32) -> Result<(Value, u64)> {
        let allowed: BTreeSet<_> = self
            .list(access)?
            .into_iter()
            .map(|v| v.agreement.agreement_id)
            .collect();
        let mut cursor = after;
        let mut visible = Vec::new();
        let limit = limit.clamp(1, 100) as usize;
        loop {
            let events = self.store.events_after(cursor, 100).map_err(store_error)?;
            if events.is_empty() {
                break;
            }
            for event in events {
                cursor = cursor.max(event.sequence);
                if event.aggregate_type == "agreement" && allowed.contains(&event.aggregate_id) {
                    visible.push(
                        serde_json::to_value(Event::try_from(event)?).map_err(|_| internal())?,
                    );
                }
                if visible.len() == limit {
                    return Ok((Value::Array(visible), cursor));
                }
            }
        }
        Ok((Value::Array(visible), cursor))
    }
    pub fn operation(&self, access: &Access, id: &str) -> Result<Value> {
        let operation = self
            .store
            .get_operation(id)
            .map_err(store_error)?
            .ok_or_else(not_found)?;
        self.get(access, &operation.resource_id)?;
        let result: MutationResult = serde_json::from_value(operation.result).map_err(|_| {
            ApiError::new(
                "RECOVERY_REQUIRED",
                "Stored operation result is incompatible; preserve the journal",
            )
        })?;
        let public = Operation {
            operation_id: operation.operation_id,
            kind: operation.kind,
            resource_id: operation.resource_id,
            status: operation.status,
            result: mutation(result)?,
            created_at: timestamp_from_ms(operation.created_at_ms)?,
            updated_at: timestamp_from_ms(operation.updated_at_ms)?,
        };
        serde_json::to_value(public).map_err(|_| internal())
    }
    pub fn recovery(&self, access: &Access) -> Result<Value> {
        let count = self.list(access)?.len();
        let journal = self.journal_recovery_metadata()?;
        let quarantined = journal.restored_journal_quarantined;
        Ok(
            json!({"schema_version":1,"status":if quarantined {"restored_journal_quarantined"} else {"metadata_only"},"agreements_loaded":count,"observation_stale":true,"background_observation":false,"new_authorization_allowed":false,"authority_status":if quarantined {"recovery_required"} else {"not_connected"},"wallet_recovery":"unavailable","agreement_backup":if self.store.protection()==wholepact_store::StorageProtection::Encrypted {"trusted_local_full_journal_embedding_only"} else {"unavailable_requires_encrypted_store"},"journal_recovery":journal,"message":if quarantined {"This restored coordination journal is quarantined. Reconcile writer authority and outstanding exposure, and recover the separate wallet and private artifact journals before any spending can be considered."} else {"Local agreement records are available. A full coordination-journal backup requires separate trusted local administration. The legacy metadata-only backup refuses journals containing durable private construction disclosures; those viewing keys, selected notes and witnesses require a separately qualified private-material backup path. Other private artifact journals and signer vaults are separate. No signer authority or complete outstanding history is established."}}),
        )
    }
}

fn check_profile(agreement: &AgreementDraft) -> Result<()> {
    if !matches!(
        agreement.network_profile_id.as_str(),
        "zcash-testnet-unqualified" | candidates::PROFILE_ID
    ) {
        return Err(ApiError::new(
            "UNSUPPORTED_CAPABILITY",
            "Only the unqualified Zcash testnet draft and unsigned Ironwood testnet candidate profiles are available. Mainnet and unknown profiles are disabled.",
        ));
    }
    Ok(())
}

fn context<T: Serialize>(
    access: &Access,
    key: &str,
    command: &str,
    resource: &str,
    revision: Option<u64>,
    request: &T,
) -> Result<CommandContext> {
    if key.len() < 16 || key.len() > 128 || !key.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "Idempotency-Key requires 16 to 128 visible ASCII bytes",
        ));
    }
    let payload = json!({"command":command,"resource":resource,"expected_revision":revision,"request":request});
    Ok(CommandContext {
        principal_id: access.principal_id.clone(),
        idempotency_key: key.into(),
        request_digest: hash_domain(b"wholepact:command:v1\0", &payload)?,
    })
}
fn hash_domain(domain: &[u8], value: &Value) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_json::to_vec(value).map_err(|_| internal())?);
    Ok(hex::encode(hash.finalize()))
}
fn encode(envelope: &Envelope) -> Result<Value> {
    serde_json::to_value(envelope).map_err(|_| internal())
}
fn decode(record: &StoredRecord) -> Result<Envelope> {
    private_workspace_origin_v1::refuse_public_payload(&record.payload)?;
    decode_unprojected(record)
}
// Only the exclusive source-owned private facade may use this decoder on a
// marked record. It is not a generic projection or caller-selected bypass.
fn decode_unprojected(record: &StoredRecord) -> Result<Envelope> {
    let mut envelope: Envelope = serde_json::from_value(record.payload.clone()).map_err(|_| {
        ApiError::new(
            "RECOVERY_REQUIRED",
            "Stored agreement schema is incompatible or damaged; preserve the journal",
        )
    })?;
    if let Some(marker) = &envelope.private_workspace_origin_v1 {
        marker.validate().map_err(|_| {
            ApiError::new(
                "RECOVERY_REQUIRED",
                "Private workspace origin is incompatible; preserve the original journal",
            )
        })?;
        if marker.agreement_id != record.id
            || marker.agreement_id != envelope.view.agreement.agreement_id
            || marker.obligation_id != envelope.view.agreement.obligation_id
            || marker.principal_id != envelope.owner_client_id
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Private workspace origin does not match its record",
            ));
        }
        #[cfg(not(all(
            feature = "durable-proposal",
            feature = "manual-admission",
            target_os = "linux"
        )))]
        return Err(ApiError::new(
            "RECOVERY_REQUIRED",
            "Private workspace history requires its compatible protected owner; preserve the original journal",
        ));
    }
    if envelope.durable_proposals_v1.len() > MAX_PROPOSALS
        || envelope.durable_construction_v1.len() > 4
        || envelope.durable_input_projections_v1.len() > 4
    {
        return Err(ApiError::new(
            "RECOVERY_REQUIRED",
            "Durable proposal inventory exceeds its bound",
        ));
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    durable_input_projections_v1::validate_stored(&envelope)?;
    #[cfg(not(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    )))]
    if !envelope.durable_input_projections_v1.is_empty() {
        return Err(ApiError::new(
            "RECOVERY_REQUIRED",
            "Private discovery history requires its compatible protected workspace; preserve the original journal",
        ));
    }
    #[cfg(feature = "durable-proposal")]
    durable_proposals_v1::validate_stored(&envelope)?;
    #[cfg(all(feature = "durable-proposal", target_os = "linux"))]
    durable_construction_v1::validate_stored(&envelope)?;
    terms_revisions::validate_history(&envelope.view)?;
    native_requests::validate_stored(&envelope)?;
    native_account_inspection_requests::validate_stored(&envelope)?;
    native_proof_requests::validate_stored(&envelope)?;
    native_proof_execution_requests::validate_stored(&envelope)?;
    native_artifact_handoff_requests::validate_stored(&envelope)?;
    native_settlement_requests::validate_stored(&envelope)?;
    native_dispatch_requests::validate_stored(&envelope)?;
    native_reconciliation_requests::validate_stored(&envelope)?;
    sponsor_policies::validate_stored_policies(&envelope.sponsor_policies)?;
    participant_records::validate_stored_records(
        &envelope.participant_records,
        &envelope.view.agreement.agreement_id,
    )?;
    for candidate in &envelope.view.candidates {
        candidate.verified_snapshot()?;
    }
    // Metadata access cannot establish account-wide absence of released signatures
    // or submissions, including effects recorded in separate protected journals.
    envelope.view.authorization_exposure = "unknown".into();
    envelope.view.chain_observation = "unknown".into();
    envelope.view.revision = record.revision;
    Ok(envelope)
}
fn mutation(result: MutationResult) -> Result<Mutation> {
    Ok(Mutation {
        agreement: decode(&result.record)?.view,
        operation_id: result.operation_id,
        event_sequence: result.event_sequence,
        replayed: result.replayed,
    })
}
fn timestamp_from_ms(timestamp: i64) -> Result<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(timestamp) * 1_000_000)
        .map_err(|_| {
            ApiError::new(
                "RECOVERY_REQUIRED",
                "Stored timestamp is outside the supported range",
            )
        })?
        .format(&Rfc3339)
        .map_err(|_| internal())
}
fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}
fn internal() -> ApiError {
    ApiError::new(
        "INTERNAL_ERROR",
        "Local operation failed; no sensitive details are included",
    )
}
fn not_found() -> ApiError {
    ApiError::new(
        "NOT_FOUND",
        "Resource was not found or is outside this client's grant",
    )
}
fn store_error(error: wholepact_store::StoreError) -> ApiError {
    use wholepact_store::StoreError::*;
    match error {
        IdempotencyConflict => ApiError::new(
            "IDEMPOTENCY_CONFLICT",
            "This idempotency key was already used for a different request",
        ),
        RevisionConflict | AlreadyExists => ApiError::new(
            "REVISION_CONFLICT",
            "The aggregate revision changed; refresh and review before retrying",
        ),
        NotFound => not_found(),
        InvalidInput(_) => ApiError::new(
            "INVALID_REQUEST",
            "The journal rejected invalid or oversized input",
        ),
        RecoveryRequired | UnsupportedSchema(_) | Encoding(_) => ApiError::new(
            "RECOVERY_REQUIRED",
            "Local journal needs compatible recovery; preserve all files",
        ),
        LiveAuthorizationExists | InputReserved => ApiError::new(
            "LIVE_AUTHORIZATION_EXISTS",
            "Outstanding authorization exposure prevents this action",
        ),
        WriterEpochMismatch => ApiError::new(
            "RECOVERY_REQUIRED",
            "Account writer authority requires reconciliation",
        ),
        ResourceExhausted => ApiError::new(
            "RESOURCE_EXHAUSTED",
            "The local journal or application record quota has been reached",
        ),
        BudgetExceeded => ApiError::new(
            "RESOURCE_EXHAUSTED",
            "Aggregate outstanding exposure exceeds the authorized budget",
        ),
        InvalidTransition => ApiError::new(
            "INVALID_TRANSITION",
            "This state transition is not permitted",
        ),
        StorageSecurity(_) => ApiError::new(
            "STORAGE_PROTECTION_REQUIRED",
            "Encrypted local storage could not be verified; no protected data was retained or released",
        ),
        Database(_) | Poisoned | File(_) => {
            let mut e = ApiError::new(
                "STORAGE_UNAVAILABLE",
                "Local journal could not commit the operation; no external effect was attempted",
            );
            e.retryable = true;
            e
        }
    }
}

#[cfg(feature = "submission-handoff")]
pub mod settlement_fanout;

#[cfg(test)]
#[path = "durable_discovery_registration_tests.rs"]
mod durable_discovery_registration_tests;
