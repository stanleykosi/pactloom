//! Semantic CI only. Match variant identity, never error payloads or formatting.
use crate::Error;
pub(crate) use wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::Stage;
use wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::{Class,latch_failure,classify_io};
pub(crate) fn native(stage:Stage,error:&Error) {latch_failure(stage,class(error));}
pub(crate) fn io(stage:Stage,error:&std::io::Error) {latch_failure(stage,classify_io(error.kind()));}
fn class(error:&Error)->Class {
 match error {
 Error::Platform=>Class::Platform,Error::Terminal=>Class::Terminal,Error::Permission=>Class::Permission,
 Error::Locked=>Class::Locked,Error::Invalid=>Class::Invalid,Error::Authentication=>Class::Authentication,
 Error::Storage=>Class::Storage,Error::Quarantined=>Class::Quarantined,Error::Unsupported=>Class::Unsupported,
 Error::Receipt(_)=>Class::Receipt,Error::RecoverySemantic(_)=>Class::RecoverySemantic,
 Error::RecoveryBackupUnsupported=>Class::RecoveryBackupUnsupported,
 Error::RecoveryFinancialUnsupported=>Class::RecoveryFinancialUnsupported,
 Error::CompleteOriginRecoveryUnavailable=>Class::CompleteOriginRecoveryUnavailable,
 Error::HistoricalExportIncomplete=>Class::HistoricalExportIncomplete,
 Error::GenerationArchiveIncomplete=>Class::GenerationArchiveIncomplete,
 }
}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn payloads_never_enter_classification(){assert_eq!(class(&Error::Receipt("synthetic-not-serialized".into())),Class::Receipt);assert_eq!(class(&Error::RecoverySemantic("synthetic-not-serialized".into())),Class::RecoverySemantic);}
 #[test] fn native_variants_are_distinct(){
  let cases=[(Error::Platform,Class::Platform),(Error::Terminal,Class::Terminal),(Error::Permission,Class::Permission),(Error::Locked,Class::Locked),(Error::Invalid,Class::Invalid),(Error::Authentication,Class::Authentication),(Error::Storage,Class::Storage),(Error::Quarantined,Class::Quarantined),(Error::Unsupported,Class::Unsupported),(Error::RecoveryBackupUnsupported,Class::RecoveryBackupUnsupported),(Error::RecoveryFinancialUnsupported,Class::RecoveryFinancialUnsupported),(Error::CompleteOriginRecoveryUnavailable,Class::CompleteOriginRecoveryUnavailable),(Error::HistoricalExportIncomplete,Class::HistoricalExportIncomplete),(Error::GenerationArchiveIncomplete,Class::GenerationArchiveIncomplete)];for (error,expected) in cases {assert_eq!(class(&error),expected);}
 }
}

/// Match only finite failure identity; the original BridgeError is not formatted.
pub(crate) fn pair(error: &wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedPairFailureV1) {
    use wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::{CoordinatedPairFailureStageV1 as S, CoordinatedPairFailureClassV1 as C};
    let stage = match error.stage() {
        S::EndpointValidate=>Stage::PairEndpointValidate,
        S::ScopeValidate=>Stage::PairScopeValidate,
        S::OriginalCustody=>Stage::PairOriginalCustody,
        S::Connect=>Stage::PairConnect,
        S::EnableCredentials=>Stage::PairEnableCredentials,
        S::VerifySigner=>Stage::PairVerifySigner,
        S::ObservePeer=>Stage::PairObservePeer,
        S::CloneObserver=>Stage::PairCloneObserver,
        S::RequestWrite=>Stage::PairRequestWrite,
        S::ResponseRead=>Stage::PairResponseRead,
        S::ResponseDecode=>Stage::PairResponseDecode,
        S::ResponseValidate=>Stage::PairResponseValidate,
        S::ResponseDigest=>Stage::PairResponseDigest,
        S::ChannelDigest=>Stage::PairChannelDigest,
        S::InitialCurrent=>Stage::PairInitialCurrent,
        S::StatusOpen=>Stage::PairStatusOpen,
        S::StatusRead=>Stage::PairStatusRead,
        S::StatusDecode=>Stage::PairStatusDecode,
        S::StatusValidate=>Stage::PairStatusValidate,
        S::FinalCurrent=>Stage::PairFinalCurrent,
    };
    let class = match error.class() {
        C::BridgeBinding=>Class::BridgeBinding,
        C::BridgeConflict=>Class::BridgeConflict,
        C::BridgeMissing=>Class::BridgeMissing,
        C::BridgeUncertain=>Class::BridgeUncertain,
        C::BridgeLimit=>Class::BridgeLimit,
        C::BridgePermission=>Class::BridgePermission,
        C::BridgeRecoveryRequired=>Class::BridgeRecoveryRequired,
        C::BridgeCompleteOriginRecoveryUnavailable=>Class::BridgeCompleteOriginRecoveryUnavailable,
        C::BridgeVerification=>Class::BridgeVerification,
        C::BridgeSignerOriginUnavailable=>Class::BridgeSignerOriginUnavailable,
        C::BridgeJournal=>Class::BridgeJournal,
        C::BridgeAuthority=>Class::BridgeAuthority,
        C::BridgeWallet=>Class::BridgeWallet,
        C::BridgeIpc=>Class::BridgeIpc,
        C::FrameUnclassified=>Class::FrameUnclassified,
        C::FrameDeadline=>Class::FrameDeadline,
        C::FrameEof=>Class::FrameEof,
        C::FrameCredentialsMissing=>Class::FrameCredentialsMissing,
        C::FrameCredentialsMismatch=>Class::FrameCredentialsMismatch,
        C::FrameAncillaryRejected=>Class::FrameAncillaryRejected,
        C::FrameTruncated=>Class::FrameTruncated,
        C::FramePeerNotLive=>Class::FramePeerNotLive,
        C::FrameCurrentCheck=>Class::FrameCurrentCheck,
        C::FrameIo=>Class::FrameIo,
        C::FrameLimit=>Class::FrameLimit,
        C::FrameInvalidFrame=>Class::FrameInvalidFrame,
        C::FrameInvalidBudget=>Class::FrameInvalidBudget,
    };
    latch_failure(stage, class);
}

/// Same finite engine categories as the existing delivery observer. Borrowed
/// classification precedes the caller's unchanged native Error conversion.
pub(crate) fn engine(stage:Stage,error:&wholepact_engine::ApiError) {
 let class=match error.code.as_str() {
  "DISCLOSURE_UNKNOWN"=>Class::EngineDisclosureUnknown,
  "DISCLOSURE_DENIED"=>Class::EngineDisclosureDenied,
  "RECOVERY_REQUIRED"|"DURABLE_PROPOSAL_RECOVERY_REQUIRED"=>Class::EngineRecoveryRequired,
  "IDEMPOTENCY_CONFLICT"=>Class::EngineIdempotencyConflict,
  "REVISION_CONFLICT"=>Class::EngineRevisionConflict,
  "DURABLE_PROPOSAL_CONFLICT"=>Class::EngineDurableProposalConflict,
  "DURABLE_CONSTRUCTION_UNAVAILABLE"=>Class::EngineDurableConstructionUnavailable,
  "DURABLE_PROFILE_UNAVAILABLE"=>Class::EngineDurableProfileUnavailable,
  "RESOURCE_EXHAUSTED"=>Class::EngineResourceExhausted,
  _=>Class::EngineUnclassified,
 };
 latch_failure(stage,class);
}
pub(crate) fn bridge(stage:Stage,error:&wholepact_signer::authority_bridge::BridgeError) {
 use wholepact_signer::authority_bridge::BridgeError as E;
 let class=match error {
  E::Binding=>Class::BridgeBinding,E::Conflict=>Class::BridgeConflict,E::Missing=>Class::BridgeMissing,
  E::Uncertain=>Class::BridgeUncertain,E::Limit=>Class::BridgeLimit,E::Permission=>Class::BridgePermission,
  E::RecoveryRequired=>Class::BridgeRecoveryRequired,E::CompleteOriginRecoveryUnavailable=>Class::BridgeCompleteOriginRecoveryUnavailable,
  E::Verification=>Class::BridgeVerification,E::SignerOriginUnavailable=>Class::BridgeSignerOriginUnavailable,
  E::Journal(_)=>Class::BridgeJournal,E::Authority(_)=>Class::BridgeAuthority,E::Wallet(_)=>Class::BridgeWallet,E::Ipc=>Class::BridgeIpc,
 };
 latch_failure(stage,class);
}

/// Details remain local until an admission method actually returns Err to Host.
/// Recoverable exchange/status failures never call this observer.
pub(crate) fn admission(error: &wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedAdmissionFailureV1) {
    use wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedAdmissionFailureStageV1 as S;
    let stage = match error.stage() {
        S::RequestDeadline=>Stage::AdmissionRequestDeadline,
        S::RequestChannel=>Stage::AdmissionRequestChannel,
        S::RequestIntent=>Stage::AdmissionRequestIntent,
        S::RequestNonce=>Stage::AdmissionRequestNonce,
        S::HistoryIntent=>Stage::AdmissionHistoryIntent,
        S::HistoryOwner=>Stage::AdmissionHistoryOwner,
        S::HistoryDeadline=>Stage::AdmissionHistoryDeadline,
        S::HistoryNonce=>Stage::AdmissionHistoryNonce,
        S::HistoryOpen=>Stage::AdmissionHistoryOpen,
        S::HistoryCurrent=>Stage::AdmissionHistoryCurrent,
        S::HistoryStatus=>Stage::AdmissionHistoryStatus,
        S::HistoryPrevious=>Stage::AdmissionHistoryPrevious,
        S::HistoryResponseMatch=>Stage::AdmissionHistoryResponseMatch,
        S::ResponseCheckBefore=>Stage::AdmissionResponseCheckBefore,
        S::ResponsePeerBefore=>Stage::AdmissionResponsePeerBefore,
        S::ResponseDeadlineBefore=>Stage::AdmissionResponseDeadlineBefore,
        S::ResponseFrame=>Stage::AdmissionResponseFrame,
        S::ResponseCheckAfter=>Stage::AdmissionResponseCheckAfter,
        S::ResponsePeerAfter=>Stage::AdmissionResponsePeerAfter,
        S::ResponseDeadlineAfter=>Stage::AdmissionResponseDeadlineAfter,
        S::ResponseDecode=>Stage::AdmissionResponseDecode,
    };
    if let Some(cause) = error.frame_cause() {
        use wholepact_signer_origin::framing::FrameReadCause as F;
        let class = match cause {
            F::Unclassified=>Class::FrameUnclassified,
            F::Deadline=>Class::FrameDeadline,
            F::Eof=>Class::FrameEof,
            F::CredentialsMissing=>Class::FrameCredentialsMissing,
            F::CredentialsMismatch=>Class::FrameCredentialsMismatch,
            F::AncillaryRejected=>Class::FrameAncillaryRejected,
            F::Truncated=>Class::FrameTruncated,
            F::PeerNotLive=>Class::FramePeerNotLive,
            F::CurrentCheck=>Class::FrameCurrentCheck,
            F::Io=>Class::FrameIo,
            F::FrameLimit=>Class::FrameLimit,
            F::InvalidFrame=>Class::FrameInvalidFrame,
            F::InvalidBudget=>Class::FrameInvalidBudget,
        };
        latch_failure(stage,class);
    } else {
        bridge(stage,error.error());
    }
}
