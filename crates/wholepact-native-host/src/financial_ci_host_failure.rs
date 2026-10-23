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
