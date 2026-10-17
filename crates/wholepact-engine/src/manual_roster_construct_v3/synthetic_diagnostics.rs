//! Synthetic-only closed projections. Never format upstream errors, fields,
//! transaction bytes, identities, paths, or caller-provided strings.
#[derive(Clone, Copy)]
pub(super) enum Phase {
    Claim,
    Plan,
    Retained,
    Parts,
    Native,
    Held,
    Restriction,
    Construct,
    Inspect,
    ActionLimit,
    Consent,
    Receipt,
    Record,
    Enqueue,
    Finish,
    Context,
}
impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Claim => "EngineCheckpointClaim",
            Self::Plan => "EngineCheckpointPlan",
            Self::Retained => "EngineCheckpointRetained",
            Self::Parts => "EngineCheckpointParts",
            Self::Native => "EngineCheckpointNative",
            Self::Held => "EngineCheckpointHeld",
            Self::Restriction => "EngineCheckpointRestriction",
            Self::Construct => "EngineCheckpointConstruct",
            Self::Inspect => "EngineCheckpointInspect",
            Self::ActionLimit => "EngineCheckpointActionLimit",
            Self::Consent => "EngineCheckpointConsent",
            Self::Receipt => "EngineCheckpointReceipt",
            Self::Record => "EngineCheckpointRecord",
            Self::Enqueue => "EngineCheckpointEnqueue",
            Self::Finish => "EngineCheckpointFinish",
            Self::Context => "EngineCheckpointContext",
        }
    }
}
fn emit(phase: Phase, outcome: &'static str) {
    eprintln!("\n[JOINED_DIAGNOSTIC {} {}]", phase.label(), outcome);
}
pub(super) fn begin(phase: Phase) { emit(phase, "Begin"); }
pub(super) fn permit(phase: Phase, permitted: bool) {
    emit(phase, if permitted { "Complete" } else { "EngineManualConstructionDenied" });
}
pub(super) fn api<T>(phase: Phase, result: &crate::Result<T>) {
    emit(phase, match result {
        Ok(_) => "Complete",
        Err(error) => match error.code.as_str() {
            "MANUAL_CONSTRUCTION_DENIED" => "EngineManualConstructionDenied",
            "RETAINED_INPUT_OBSERVATION_UNAVAILABLE" => "EngineRetainedObservationUnavailable",
            "CANDIDATE_VERIFICATION_FAILED" => "EngineCandidateVerificationFailed",
            "IDEMPOTENCY_CONFLICT" => "EngineIdempotencyConflict",
            "REVISION_CONFLICT" => "EngineRevisionConflict",
            "NOT_FOUND" => "EngineNotFound",
            "INVALID_REQUEST" => "EngineInvalidRequest",
            "RECOVERY_REQUIRED" => "EngineRecoveryRequired",
            "LIVE_AUTHORIZATION_EXISTS" => "EngineLiveAuthorizationExists",
            "RESOURCE_EXHAUSTED" => "EngineResourceExhausted",
            "INVALID_TRANSITION" => "EngineInvalidTransition",
            "STORAGE_PROTECTION_REQUIRED" => "EngineStorageProtectionRequired",
            "STORAGE_UNAVAILABLE" => "EngineStorageUnavailable",
            "ACCESS_DENIED" => "EngineAccessDenied",
            _ => "EngineUnclassified",
        },
    });
}
pub(super) fn store<T>(phase: Phase, result: &wholepact_store::Result<T>) {
    use wholepact_store::StoreError as E;
    emit(phase, match result {
        Ok(_) => "Complete",
        Err(E::StorageSecurity(_)) => "StoreStorageSecurity",
        Err(E::Database(_)) => "StoreDatabase",
        Err(E::Encoding(_)) => "StoreEncoding",
        Err(E::Poisoned) => "StorePoisoned",
        Err(E::IdempotencyConflict) => "StoreIdempotencyConflict",
        Err(E::RevisionConflict) => "StoreRevisionConflict",
        Err(E::NotFound) => "StoreNotFound",
        Err(E::AlreadyExists) => "StoreAlreadyExists",
        Err(E::InvalidInput(_)) => "StoreInvalidInput",
        Err(E::UnsupportedSchema(_)) => "StoreUnsupportedSchema",
        Err(E::RecoveryRequired) => "StoreRecoveryRequired",
        Err(E::WriterEpochMismatch) => "StoreWriterEpochMismatch",
        Err(E::LiveAuthorizationExists) => "StoreLiveAuthorizationExists",
        Err(E::InputReserved) => "StoreInputReserved",
        Err(E::ResourceExhausted) => "StoreResourceExhausted",
        Err(E::BudgetExceeded) => "StoreBudgetExceeded",
        Err(E::InvalidTransition) => "StoreInvalidTransition",
        Err(E::File(_)) => "StoreFile",
    });
}
pub(super) fn bridge<T>(phase: Phase, result: &wholepact_signer::authority_bridge::Result<T>) {
    use wholepact_signer::authority_bridge::BridgeError as E;
    emit(phase, match result {
        Ok(_) => "Complete",
        Err(E::Binding) => "BridgeBinding",
        Err(E::Conflict) => "BridgeConflict",
        Err(E::Missing) => "BridgeMissing",
        Err(E::Uncertain) => "BridgeUncertain",
        Err(E::Limit) => "BridgeLimit",
        Err(E::Permission) => "BridgePermission",
        Err(E::RecoveryRequired) => "BridgeRecoveryRequired",
        Err(E::CompleteOriginRecoveryUnavailable) => "BridgeCompleteOriginRecoveryUnavailable",
        Err(E::Verification) => "BridgeVerification",
        Err(E::SignerOriginUnavailable) => "BridgeSignerOriginUnavailable",
        Err(E::Journal(_)) => "BridgeJournal",
        Err(E::Authority(_)) => "BridgeAuthority",
        Err(E::Wallet(_)) => "BridgeWallet",
        Err(E::Ipc) => "BridgeIpc",
    });
}
pub(super) fn job<T>(phase: Phase, result: &wholepact_proof_jobs::Result<T>) {
    use wholepact_proof_jobs::JobError as E;
    emit(phase, match result {
        Ok(_) => "Complete",
        Err(E::ConsentDenied) => "JobConsentDenied",
        Err(E::NotFound) => "JobNotFound",
        Err(E::InvalidRequest) => "JobInvalidRequest",
        Err(E::VerificationFailed) => "JobVerificationFailed",
        Err(E::IdempotencyConflict) => "JobIdempotencyConflict",
        Err(E::RecoveryRequired) => "JobRecoveryRequired",
        Err(E::StateConflict) => "JobStateConflict",
        Err(E::Storage) => "JobStorage",
        Err(E::UnsupportedSchema) => "JobUnsupportedSchema",
        Err(E::ResourceExhausted) => "JobResourceExhausted",
    });
}
pub(super) fn protocol<T>(phase: Phase, result: &std::result::Result<T, String>) {
    emit(phase, match result {
        Ok(_) => "Complete",
        Err(error) => match error.as_str() {
            "Accepted manifest accounting is invalid"
            | "Unsupported construction network profile"
            | "Construction does not qualify manifest extensions or conditional matching"
            | "Construction does not qualify service charges"
            | "Construction supports at most 64 real inputs/outputs"
            | "Broad-witness construction requires declared operator and dedicated accounts" => "ProtocolManifest",
            "Declared construction/proving operator missing"
            | "Manifest digest encoding"
            | "Manifest digest length"
            | "Every account must have a disclosure declaration"
            | "Broad-review disclosure requires the exact complete participant reviewer roster"
            | "Disclosure declaration is missing, duplicated or differs from accepted scope" => "ProtocolDisclosure",
            "Invalid anchor context"
            | "Expiry must cover target height and be a block-height expiry"
            | "Target and expiry must remain within the qualified testnet NU7 branch"
            | "Invalid Ironwood anchor" => "ProtocolContext",
            "Exactly one contribution package is required per participant"
            | "Total selected note count exceeds 64"
            | "Contribution lacks an exact disclosure declaration"
            | "Contribution note count outside 1..=64"
            | "Change address is not internal-scope account property"
            | "Same FVK cannot occupy multiple participant accounts"
            | "Duplicate account contribution"
            | "Accepted participant contribution missing" => "ProtocolContribution",
            "Every selected note must be value-bearing Ironwood V3"
            | "Selected note is not owned by declared FVK"
            | "Selected note witness differs from common anchor"
            | "Duplicate real note/nullifier"
            | "Duplicate selected input ID"
            | "Selected notes do not exactly cover accepted inputs"
            | "Input account package missing"
            | "Accepted input does not identify a selected note"
            | "Actual selected input amount differs from accepted manifest"
            | "Input participant missing" => "ProtocolInput",
            "Accepted recipient missing"
            | "Invalid recipient memo"
            | "Return account missing"
            | "Accepted return receiver differs from account internal change"
            | "Return participant missing"
            | "Unqualified service charge"
            | "Output amount range" => "ProtocolOutput",
            "Unable to calculate exact ZIP317 fee"
            | "Accepted fee differs from ZIP317 fee for actual padded transaction shape; revise terms explicitly" => "ProtocolFee",
            "Upstream rejected a selected Ironwood input" => "ProtocolBuilderInput",
            "Upstream rejected an Ironwood output" => "ProtocolBuilderOutput",
            "Upstream PCZT construction failed"
            | "Unsupported PCZT parts"
            | "PCZT v2 serialization unsupported" => "ProtocolPczt",
            "Upstream IO finalization failed" => "ProtocolFinalize",
            "Missing randomized input action mapping"
            | "Missing randomized output action mapping" => "ProtocolActionMapping",
            _ => "ProtocolUnclassified",
        },
    });
}
