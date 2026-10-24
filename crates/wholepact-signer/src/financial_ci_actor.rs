//! Finite semantic-only error observations, not authority or error formatting.
use wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics as diagnostic;
use diagnostic::{Class,DriverStage,ListenerStage};
pub(crate) trait ErrorClass { fn finite_class(&self)->Class; }
impl ErrorClass for std::io::Error {fn finite_class(&self)->Class {diagnostic::classify_io(self.kind())}}
impl ErrorClass for crate::Error {fn finite_class(&self)->Class {use crate::Error as E;match self {
 E::Unavailable=>Class::SignerUnavailable,E::PeerLifetimeUnavailable=>Class::SignerPeerLifetimeUnavailable,
 E::Io(e)=>e.finite_class(),E::Authentication=>Class::SignerAuthentication,E::InvalidData=>Class::SignerInvalidData,
 E::Crypto=>Class::SignerCrypto,E::Locked=>Class::SignerLocked,E::BackupRequired=>Class::SignerBackupRequired,
 E::RecoveryRequired=>Class::SignerRecoveryRequired,E::AlreadyOpen=>Class::SignerAlreadyOpen,
 E::ReviewMismatch=>Class::SignerReviewMismatch,E::Verification=>Class::SignerVerification,E::Uncertain=>Class::SignerUncertain,
 E::ConsentJournal(error)=>error.finite_class(),E::Store(_)=>Class::SignerStore,
}}}
impl ErrorClass for crate::authority_bridge::BridgeError {fn finite_class(&self)->Class {use crate::authority_bridge::BridgeError as E;match self {
 E::Binding=>Class::BridgeBinding,E::Conflict=>Class::BridgeConflict,E::Missing=>Class::BridgeMissing,E::Uncertain=>Class::BridgeUncertain,
 E::Limit=>Class::BridgeLimit,E::Permission=>Class::BridgePermission,E::RecoveryRequired=>Class::BridgeRecoveryRequired,
 E::CompleteOriginRecoveryUnavailable=>Class::BridgeCompleteOriginRecoveryUnavailable,E::Verification=>Class::BridgeVerification,
 E::SignerOriginUnavailable=>Class::BridgeSignerOriginUnavailable,E::Journal(error)=>error.finite_class(),E::Authority(_)=>Class::BridgeAuthority,
 #[cfg(feature="authority-signing")] E::Wallet(_)=>Class::BridgeWallet,E::Ipc=>Class::BridgeIpc,
}}}
pub(crate) fn driver(stage:DriverStage,error:&impl ErrorClass){diagnostic::driver(stage,error.finite_class());}
pub(crate) fn listener(stage:ListenerStage,error:&impl ErrorClass){diagnostic::listener(stage,error.finite_class());}
pub(crate) fn frame(error:&wholepact_signer_origin::framing::ObservedFrameError) {
 use wholepact_signer_origin::framing::FrameReadCause as F;
 diagnostic::listener(ListenerStage::RequestRead,match error.cause {
 F::Unclassified=>Class::FrameUnclassified,F::Deadline=>Class::FrameDeadline,F::Eof=>Class::FrameEof,
 F::CredentialsMissing=>Class::FrameCredentialsMissing,F::CredentialsMismatch=>Class::FrameCredentialsMismatch,
 F::AncillaryRejected=>Class::FrameAncillaryRejected,F::Truncated=>Class::FrameTruncated,F::PeerNotLive=>Class::FramePeerNotLive,
 F::CurrentCheck=>Class::FrameCurrentCheck,F::Io=>Class::FrameIo,F::FrameLimit=>Class::FrameLimit,
 F::InvalidFrame=>Class::FrameInvalidFrame,F::InvalidBudget=>Class::FrameInvalidBudget,
 });
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn original_error_ownership_and_one_evaluation_are_preserved(){
  #[derive(Debug)]struct PrivatePayload;
  impl std::fmt::Display for PrivatePayload {fn fmt(&self,_:&mut std::fmt::Formatter<'_>)->std::fmt::Result {panic!("diagnostic must never format private payload")}}
  impl std::error::Error for PrivatePayload {}
  let error=std::io::Error::new(std::io::ErrorKind::PermissionDenied,PrivatePayload);
  let pointer=error.get_ref().unwrap() as *const dyn std::error::Error;
  let mut evaluated=0;
  let result=actor_driver_result!(Handle,{evaluated+=1;Err::<(),_>(error)});
  let result=actor_listener_result!(StatusWrite,result);
  let error=result.unwrap_err();assert_eq!(evaluated,1);
  assert!(std::ptr::addr_eq(pointer,error.get_ref().unwrap() as *const dyn std::error::Error));
 }
 #[test]fn successful_wrappers_preserve_value_without_new_failure(){
  let mut evaluated=0;
  let result=actor_driver_result!(Handle,{evaluated+=1;Ok::<u8,crate::Error>(7)});
  let result=actor_driver_detail_result!(EnrollmentPeerCheck,result);
  let result=actor_listener_result!(StatusWrite,result);
  assert_eq!(result.unwrap(),7);assert_eq!(evaluated,1);
 }
 #[test]fn opaque_payloads_do_not_change_finite_class(){
  assert_eq!(std::io::Error::new(std::io::ErrorKind::PermissionDenied,"private canary").finite_class(),Class::IoPermissionDenied);
  assert_eq!(crate::Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut,"private canary")).finite_class(),Class::IoTimedOut);
  assert_eq!(crate::Error::Locked.finite_class(),Class::SignerLocked);
 }
}
impl ErrorClass for wholepact_signer_origin::Error {fn finite_class(&self)->Class {
 match self {wholepact_signer_origin::Error::Io(error)=>error.finite_class(),_=>Class::PredicateDenied}
}}
pub(crate) fn driver_detail(stage:DriverStage,error:&impl ErrorClass){diagnostic::driver_detail(stage,error.finite_class());}

impl ErrorClass for crate::consent_journal::JournalError {fn finite_class(&self)->Class {
 use crate::consent_journal::JournalError as E;
 match self {E::Storage(_)=>Class::JournalStorage,E::Database=>Class::JournalDatabase,E::Permission=>Class::JournalPermission,
 E::Expired=>Class::JournalExpired,E::RecoveryRequired=>Class::JournalRecoveryRequired,E::UnsupportedSchema=>Class::JournalUnsupportedSchema,
 E::OfflineHistoryUnsupported=>Class::JournalOfflineHistoryUnsupported,E::NamedRecipientHistoryUnsupported=>Class::JournalNamedRecipientHistoryUnsupported,
 E::ConstructionHistoryUnsupported=>Class::JournalConstructionHistoryUnsupported,E::InvalidBinding=>Class::JournalInvalidBinding,
 E::Conflict=>Class::JournalConflict,E::NotFound=>Class::JournalNotFound,E::LiveAuthorization=>Class::JournalLiveAuthorization,
 E::InputReserved=>Class::JournalInputReserved,E::BudgetExceeded=>Class::JournalBudgetExceeded,E::Limit=>Class::JournalLimit}
}}

// Only the owned AdmitRead/prepare lexical scopes enable these details. A
// reusable borrowed check cannot poison the global failure latch on its own.
type AdmitReadDetail = (DriverStage, Class);
std::thread_local! {
    static ADMIT_READ_DETAIL: std::cell::Cell<Option<Option<AdmitReadDetail>>> = const { std::cell::Cell::new(None) };
}
pub(crate) struct AdmitReadObservation { previous: Option<Option<AdmitReadDetail>> }
impl AdmitReadObservation {
    pub(crate) fn enter() -> Self {
        Self { previous: ADMIT_READ_DETAIL.with(|slot| slot.replace(Some(None))) }
    }
}
impl Drop for AdmitReadObservation {
    fn drop(&mut self) { ADMIT_READ_DETAIL.with(|slot| slot.set(self.previous)); }
}
pub(crate) fn admit_read_detail_value(detail: AdmitReadDetail) {
    ADMIT_READ_DETAIL.with(|slot| { if slot.get() == Some(None) { slot.set(Some(Some(detail))); } });
}
pub(crate) fn admit_read_detail(stage: DriverStage, error: &impl ErrorClass) {
    admit_read_detail_value((stage, error.finite_class()));
}
fn admit_read_selected(stage: DriverStage, class: Class) -> AdmitReadDetail {
    ADMIT_READ_DETAIL.with(|slot| slot.get().flatten().unwrap_or((stage, class)))
}
pub(crate) fn admit_read_terminal(stage: DriverStage, error: &impl ErrorClass) {
    let (stage, class) = admit_read_selected(stage, error.finite_class());
    diagnostic::driver(stage, class);
}
impl ErrorClass for wholepact_authority::AuthorityError {
    fn finite_class(&self) -> Class {
        use wholepact_authority::AuthorityError as E;
        match self {
            E::InvalidBinding=>Class::AuthorityInvalidBinding,
            E::Permission=>Class::AuthorityPermission,
            E::StaleHead=>Class::AuthorityStaleHead,
            E::Conflict=>Class::AuthorityConflict,
            E::Inactive=>Class::AuthorityInactive,
            E::RecoveryRequired=>Class::AuthorityRecoveryRequired,
            E::Expired=>Class::AuthorityExpired,
            E::PolicyDenied=>Class::AuthorityPolicyDenied,
            E::BudgetExceeded=>Class::AuthorityBudgetExceeded,
            E::InputReserved=>Class::AuthorityInputReserved,
            E::ObligationReserved=>Class::AuthorityObligationReserved,
            E::Limit=>Class::AuthorityLimit,
            E::Storage=>Class::AuthorityStorage,
            E::CorruptHistory=>Class::AuthorityCorruptHistory,
            E::PermanentStopUnavailable=>Class::AuthorityPermanentStopUnavailable,
            E::OfflineHistoryUnsupported=>Class::AuthorityOfflineHistoryUnsupported,
            E::ConstructionHistoryUnsupported=>Class::AuthorityConstructionHistoryUnsupported,
            E::UnsupportedVersion=>Class::AuthorityUnsupportedVersion,
            E::Authentication=>Class::AuthorityAuthentication,
            E::Uncertain=>Class::AuthorityUncertain,
            E::ResolutionUnavailable=>Class::AuthorityResolutionUnavailable,
            E::SessionRequired=>Class::AuthoritySessionRequired,
            E::SessionPending=>Class::AuthoritySessionPending,
        }
    }
}
#[cfg(feature = "synthetic-qualification")]
pub(crate) fn admit_read_history_detail(error: &wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1) -> AdmitReadDetail {
    use wholepact_authority::transport::history_diagnostics_v1::{CheckedHistoryStageV1 as S, CheckedHistoryIoKindV1 as I};
    let stage = match error.stage() {
        S::CallerDeadline=>DriverStage::AdmitReadHistoryCallerDeadline,
        S::ExchangeDeadline=>DriverStage::AdmitReadHistoryExchangeDeadline,
        S::SourceCallback=>DriverStage::AdmitReadHistorySourceCallback,
        S::SnapshotConnect=>DriverStage::AdmitReadHistorySnapshotConnect,
        S::SnapshotHandshake=>DriverStage::AdmitReadHistorySnapshotHandshake,
        S::SnapshotPeerBinding=>DriverStage::AdmitReadHistorySnapshotPeerBinding,
        S::SnapshotRequestBuild=>DriverStage::AdmitReadHistorySnapshotRequestBuild,
        S::SnapshotRequestWrite=>DriverStage::AdmitReadHistorySnapshotRequestWrite,
        S::SnapshotResponseRead=>DriverStage::AdmitReadHistorySnapshotResponseRead,
        S::SnapshotResponse=>DriverStage::AdmitReadHistorySnapshotResponse,
        S::SnapshotValidation=>DriverStage::AdmitReadHistorySnapshotValidation,
        S::PageConnect=>DriverStage::AdmitReadHistoryPageConnect,
        S::PageHandshake=>DriverStage::AdmitReadHistoryPageHandshake,
        S::PagePeerBinding=>DriverStage::AdmitReadHistoryPagePeerBinding,
        S::PageRequestBuild=>DriverStage::AdmitReadHistoryPageRequestBuild,
        S::PageRequestWrite=>DriverStage::AdmitReadHistoryPageRequestWrite,
        S::PageResponseRead=>DriverStage::AdmitReadHistoryPageResponseRead,
        S::PageResponse=>DriverStage::AdmitReadHistoryPageResponse,
        S::PageValidation=>DriverStage::AdmitReadHistoryPageValidation,
        S::EventReplay=>DriverStage::AdmitReadHistoryEventReplay,
        S::FinalValidation=>DriverStage::AdmitReadHistoryFinalValidation,
        S::Bounds=>DriverStage::AdmitReadHistoryBounds,
        _ => DriverStage::AdmitReadHistory,
    };
    let class = match error.io_kind() {
        Some(I::Timeout)=>Class::IoTimedOut, Some(I::Closed)=>Class::IoUnexpectedEof,
        Some(I::Refused)=>Class::IoConnectionRefused, Some(I::Other)=>Class::IoOther,
        None=>error.error().finite_class(),
    };
    (stage, class)
}

#[cfg(test)]
mod admit_read_observation_tests {
    use super::*;
    const FIRST: AdmitReadDetail = (DriverStage::AdmitReadSourceRevision, Class::JournalInvalidBinding);
    const FALLBACK: AdmitReadDetail = (DriverStage::AdmitReadSourceBefore, Class::SignerReviewMismatch);
    fn selected() -> AdmitReadDetail { admit_read_selected(FALLBACK.0, FALLBACK.1) }
    #[test]
    fn borrowed_detail_outside_owned_scope_is_unavailable() {
        admit_read_detail_value(FIRST);
        assert_eq!(selected(), FALLBACK);
    }
    #[test]
    fn owned_scope_first_detail_wins_and_success_discards_it() {
        { let _scope = AdmitReadObservation::enter();
          admit_read_detail_value(FIRST); admit_read_detail_value(FALLBACK);
          assert_eq!(selected(), FIRST); }
        assert_eq!(selected(), FALLBACK);
    }
    #[test]
    fn nested_owned_scope_restores_exact_parent_detail() {
        let _parent = AdmitReadObservation::enter();
        admit_read_detail_value(FIRST);
        { let _child = AdmitReadObservation::enter();
          assert_eq!(selected(), FALLBACK);
          admit_read_detail_value(FALLBACK); assert_eq!(selected(), FALLBACK); }
        assert_eq!(selected(), FIRST);
    }
    #[test]
    fn unwind_restores_scope_without_latching_or_closing() {
        let _parent = AdmitReadObservation::enter();
        admit_read_detail_value(FIRST);
        let result = std::panic::catch_unwind(|| {
            let _child = AdmitReadObservation::enter();
            admit_read_detail_value(FALLBACK); panic!("synthetic scope unwind");
        });
        assert!(result.is_err()); assert_eq!(selected(), FIRST);
    }
    #[test]
    fn details_do_not_cross_worker_threads() {
        let _scope = AdmitReadObservation::enter(); admit_read_detail_value(FIRST);
        assert_eq!(std::thread::spawn(selected).join().unwrap(), FALLBACK);
        assert_eq!(selected(), FIRST);
    }
    #[test]
    fn original_authority_error_variant_classification_is_exact() {
        assert_eq!(wholepact_authority::AuthorityError::InvalidBinding.finite_class(), Class::AuthorityInvalidBinding);
        assert_eq!(wholepact_authority::AuthorityError::Permission.finite_class(), Class::AuthorityPermission);
        assert_eq!(wholepact_authority::AuthorityError::StaleHead.finite_class(), Class::AuthorityStaleHead);
        assert_eq!(wholepact_authority::AuthorityError::Conflict.finite_class(), Class::AuthorityConflict);
        assert_eq!(wholepact_authority::AuthorityError::Inactive.finite_class(), Class::AuthorityInactive);
        assert_eq!(wholepact_authority::AuthorityError::RecoveryRequired.finite_class(), Class::AuthorityRecoveryRequired);
        assert_eq!(wholepact_authority::AuthorityError::Expired.finite_class(), Class::AuthorityExpired);
        assert_eq!(wholepact_authority::AuthorityError::PolicyDenied.finite_class(), Class::AuthorityPolicyDenied);
        assert_eq!(wholepact_authority::AuthorityError::BudgetExceeded.finite_class(), Class::AuthorityBudgetExceeded);
        assert_eq!(wholepact_authority::AuthorityError::InputReserved.finite_class(), Class::AuthorityInputReserved);
        assert_eq!(wholepact_authority::AuthorityError::ObligationReserved.finite_class(), Class::AuthorityObligationReserved);
        assert_eq!(wholepact_authority::AuthorityError::Limit.finite_class(), Class::AuthorityLimit);
        assert_eq!(wholepact_authority::AuthorityError::Storage.finite_class(), Class::AuthorityStorage);
        assert_eq!(wholepact_authority::AuthorityError::CorruptHistory.finite_class(), Class::AuthorityCorruptHistory);
        assert_eq!(wholepact_authority::AuthorityError::PermanentStopUnavailable.finite_class(), Class::AuthorityPermanentStopUnavailable);
        assert_eq!(wholepact_authority::AuthorityError::OfflineHistoryUnsupported.finite_class(), Class::AuthorityOfflineHistoryUnsupported);
        assert_eq!(wholepact_authority::AuthorityError::ConstructionHistoryUnsupported.finite_class(), Class::AuthorityConstructionHistoryUnsupported);
        assert_eq!(wholepact_authority::AuthorityError::UnsupportedVersion.finite_class(), Class::AuthorityUnsupportedVersion);
        assert_eq!(wholepact_authority::AuthorityError::Authentication.finite_class(), Class::AuthorityAuthentication);
        assert_eq!(wholepact_authority::AuthorityError::Uncertain.finite_class(), Class::AuthorityUncertain);
        assert_eq!(wholepact_authority::AuthorityError::ResolutionUnavailable.finite_class(), Class::AuthorityResolutionUnavailable);
        assert_eq!(wholepact_authority::AuthorityError::SessionRequired.finite_class(), Class::AuthoritySessionRequired);
        assert_eq!(wholepact_authority::AuthorityError::SessionPending.finite_class(), Class::AuthoritySessionPending);
    }
}

// Test-only finite observation; cannot set metadata or mint native authority.
#[cfg(test)]
pub(crate) fn admit_read_detail_for_test() -> Option<(DriverStage, Class)> {
    ADMIT_READ_DETAIL.with(|slot| slot.get().flatten())
}
