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
