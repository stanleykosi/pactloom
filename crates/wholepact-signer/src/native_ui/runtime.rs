//! Actual signer-owned native account, pairing, and consent workflow. No exported
//! API can inject native decisions. This is source implementation; operating a
//! real account remains an explicit user's native action, never a test fixture.
// The original expression is evaluated once. Diagnostics borrow errors and
// return the same owned Result; the None path adds no clock, check, or IO.
macro_rules! durable_flow_observe_v1 {
    ($observer:expr, $stage:expr, $original:expr) => {{
        let original = $original;
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        let original = crate::authority_bridge::durable_flow_diagnostics_v1::observe_result(
            $observer, $stage, original,
        );
        original
    }};
}
macro_rules! durable_flow_call_v1 {
    ($observer:expr, $call:expr, $stage:expr, $original:expr) => {{
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Some(observer) = $observer {
            observer.call_enter($call);
        }
        let original = $original;
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Some(observer) = $observer {
            observer.call_return($call, &original);
        }
        durable_flow_observe_v1!($observer, $stage, original)
    }};
}
#[cfg(all(
    feature = "synthetic-born-joined-qualification",
    feature = "durable-proposal"
))]
use crate::authority_bridge::durable_flow_diagnostics_v1 as flow_diag_v1;

// Observe only the existing returned error, before its original discard/return.
// Without the synthetic feature this evaluates the original expression once
// and performs no diagnostic classification, IO, state change or extra check.
macro_rules! durable_delivery_observe_v2 {
    ($stage:ident, $original:expr) => {{
        let original = $original;
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        let original = delivery_diagnostics_v2::signer_result(
            delivery_diagnostics_v2::Stage::$stage,
            original,
        );
        original
    }};
}

#[cfg(all(
    feature = "synthetic-born-joined-qualification",
    feature = "durable-proposal"
))]
pub(super) mod delivery_diagnostics_v2 {
    use crate::{Error, authority_bridge::BridgeError};
    use std::io::Write;

    macro_rules! labels {
        ($name:ident { $($variant:ident),+ $(,)? }) => {
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub(in crate::native_ui) enum $name { $($variant),+ }
            impl $name {
                fn label(self) -> &'static str {
                    match self { $(Self::$variant => stringify!($variant)),+ }
                }
            }
        };
    }
    labels! { Stage {
        DeliveryRedisclosurePrepare,
        DeliveryRedisclosureApprove,
        DeliveryRedisclosureServe,
        DeliveryArtifactImportStart,
    } }
    labels! { Outcome {
        SignerUnavailable, SignerPeerLifetimeUnavailable, SignerIo,
        SignerAuthentication, SignerInvalidData, SignerCrypto, SignerLocked,
        SignerBackupRequired, SignerRecoveryRequired, SignerAlreadyOpen,
        SignerReviewMismatch, SignerVerification, SignerUncertain,
        SignerConsentJournal, SignerStore,
        BridgeBinding, BridgeConflict, BridgeMissing, BridgeUncertain,
        BridgeLimit, BridgePermission, BridgeRecoveryRequired,
        BridgeCompleteOriginRecoveryUnavailable, BridgeVerification,
        BridgeSignerOriginUnavailable, BridgeJournal, BridgeAuthority,
        BridgeWallet, BridgeIpc, WorkerFailure,
    } }
    fn signer_error(error: &Error) -> Outcome {
        match error {
            Error::Unavailable => Outcome::SignerUnavailable,
            Error::PeerLifetimeUnavailable => Outcome::SignerPeerLifetimeUnavailable,
            Error::Io(_) => Outcome::SignerIo,
            Error::Authentication => Outcome::SignerAuthentication,
            Error::InvalidData => Outcome::SignerInvalidData,
            Error::Crypto => Outcome::SignerCrypto,
            Error::Locked => Outcome::SignerLocked,
            Error::BackupRequired => Outcome::SignerBackupRequired,
            Error::RecoveryRequired => Outcome::SignerRecoveryRequired,
            Error::AlreadyOpen => Outcome::SignerAlreadyOpen,
            Error::ReviewMismatch => Outcome::SignerReviewMismatch,
            Error::Verification => Outcome::SignerVerification,
            Error::Uncertain => Outcome::SignerUncertain,
            Error::ConsentJournal(_) => Outcome::SignerConsentJournal,
            Error::Store(_) => Outcome::SignerStore,
        }
    }
    fn bridge_error(error: &BridgeError) -> Outcome {
        match error {
            BridgeError::Binding => Outcome::BridgeBinding,
            BridgeError::Conflict => Outcome::BridgeConflict,
            BridgeError::Missing => Outcome::BridgeMissing,
            BridgeError::Uncertain => Outcome::BridgeUncertain,
            BridgeError::Limit => Outcome::BridgeLimit,
            BridgeError::Permission => Outcome::BridgePermission,
            BridgeError::RecoveryRequired => Outcome::BridgeRecoveryRequired,
            BridgeError::CompleteOriginRecoveryUnavailable => {
                Outcome::BridgeCompleteOriginRecoveryUnavailable
            }
            BridgeError::Verification => Outcome::BridgeVerification,
            BridgeError::SignerOriginUnavailable => Outcome::BridgeSignerOriginUnavailable,
            BridgeError::Journal(_) => Outcome::BridgeJournal,
            BridgeError::Authority(_) => Outcome::BridgeAuthority,
            BridgeError::Wallet(_) => Outcome::BridgeWallet,
            BridgeError::Ipc => Outcome::BridgeIpc,
        }
    }
    fn emit(stage: Stage, outcome: Outcome) {
        // Diagnostics must not turn a failed stderr write into a runtime panic.
        // Only closed enum labels reach this sink, never error/value payloads.
        let _ = writeln!(
            std::io::stderr().lock(),
            "\n[JOINED_DIAGNOSTIC {} {}]",
            stage.label(),
            outcome.label(),
        );
    }
    fn observe_result<T, E>(
        stage: Stage,
        original: std::result::Result<T, E>,
        classify: impl FnOnce(&E) -> Option<Outcome>,
        emit: impl FnOnce(Stage, Outcome),
    ) -> std::result::Result<T, E> {
        if let Err(error) = &original {
            emit(stage, classify(error).unwrap_or(Outcome::WorkerFailure));
        }
        original
    }
    pub(in crate::native_ui) fn signer_result<T>(
        stage: Stage,
        original: crate::Result<T>,
    ) -> crate::Result<T> {
        observe_result(stage, original, |error| Some(signer_error(error)), emit)
    }
    pub(in crate::native_ui) fn bridge_result<T>(
        stage: Stage,
        original: crate::authority_bridge::Result<T>,
    ) -> crate::authority_bridge::Result<T> {
        observe_result(stage, original, |error| Some(bridge_error(error)), emit)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{cell::RefCell, rc::Rc};

        #[test]
        fn delivery_signer_error_mapping_is_closed_and_payload_free() {
            let cases = [
                (Error::Unavailable, Outcome::SignerUnavailable),
                (Error::PeerLifetimeUnavailable, Outcome::SignerPeerLifetimeUnavailable),
                (Error::Io(std::io::Error::other("private payload")), Outcome::SignerIo),
                (Error::Authentication, Outcome::SignerAuthentication),
                (Error::InvalidData, Outcome::SignerInvalidData),
                (Error::Crypto, Outcome::SignerCrypto),
                (Error::Locked, Outcome::SignerLocked),
                (Error::BackupRequired, Outcome::SignerBackupRequired),
                (Error::RecoveryRequired, Outcome::SignerRecoveryRequired),
                (Error::AlreadyOpen, Outcome::SignerAlreadyOpen),
                (Error::ReviewMismatch, Outcome::SignerReviewMismatch),
                (Error::Verification, Outcome::SignerVerification),
                (Error::Uncertain, Outcome::SignerUncertain),
                (Error::ConsentJournal(crate::consent_journal::JournalError::Database), Outcome::SignerConsentJournal),
                (Error::Store(wholepact_store::StoreError::InvalidInput("private payload")), Outcome::SignerStore),
            ];
            for (error, expected) in cases {
                let original = Err::<Box<u8>, _>(error);
                let identity = std::mem::discriminant(original.as_ref().unwrap_err());
                let returned = observe_result(
                    Stage::DeliveryRedisclosurePrepare,
                    original,
                    |error| Some(signer_error(error)),
                    |stage, outcome| {
                        assert_eq!(stage, Stage::DeliveryRedisclosurePrepare);
                        assert_eq!(outcome, expected);
                        assert!(!outcome.label().contains("private"));
                    },
                );
                assert_eq!(std::mem::discriminant(returned.as_ref().unwrap_err()), identity);
            }
        }

        #[test]
        fn delivery_bridge_error_mapping_is_closed_and_payload_free() {
            let cases = [
                (BridgeError::Binding, Outcome::BridgeBinding),
                (BridgeError::Conflict, Outcome::BridgeConflict),
                (BridgeError::Missing, Outcome::BridgeMissing),
                (BridgeError::Uncertain, Outcome::BridgeUncertain),
                (BridgeError::Limit, Outcome::BridgeLimit),
                (BridgeError::Permission, Outcome::BridgePermission),
                (BridgeError::RecoveryRequired, Outcome::BridgeRecoveryRequired),
                (BridgeError::CompleteOriginRecoveryUnavailable, Outcome::BridgeCompleteOriginRecoveryUnavailable),
                (BridgeError::Verification, Outcome::BridgeVerification),
                (BridgeError::SignerOriginUnavailable, Outcome::BridgeSignerOriginUnavailable),
                (BridgeError::Journal(crate::consent_journal::JournalError::Database), Outcome::BridgeJournal),
                (BridgeError::Authority(wholepact_authority::AuthorityError::Permission), Outcome::BridgeAuthority),
                (BridgeError::Wallet(wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError::Permission), Outcome::BridgeWallet),
                (BridgeError::Ipc, Outcome::BridgeIpc),
            ];
            for (error, expected) in cases {
                let original = Err::<Box<u8>, _>(error);
                let identity = std::mem::discriminant(original.as_ref().unwrap_err());
                let returned = observe_result(
                    Stage::DeliveryRedisclosureServe,
                    original,
                    |error| Some(bridge_error(error)),
                    |stage, outcome| {
                        assert_eq!(stage, Stage::DeliveryRedisclosureServe);
                        assert_eq!(outcome, expected);
                    },
                );
                assert_eq!(std::mem::discriminant(returned.as_ref().unwrap_err()), identity);
            }
        }

        struct NonClone {
            value: Box<u8>,
            events: Rc<RefCell<Vec<&'static str>>>,
        }
        impl Drop for NonClone {
            fn drop(&mut self) {
                self.events.borrow_mut().push("drop");
            }
        }
        #[test]
        fn delivery_observation_preserves_owned_value_and_skips_success_sink() {
            let events = Rc::new(RefCell::new(Vec::new()));
            let value = NonClone { value: Box::new(7), events: events.clone() };
            let identity = &*value.value as *const u8;
            let returned = observe_result(
                Stage::DeliveryArtifactImportStart,
                Ok::<_, NonClone>(value),
                |_| panic!("successful value must not be classified"),
                |_, _| panic!("successful value must not be emitted"),
            );
            assert!(events.borrow().is_empty());
            assert_eq!(&*returned.as_ref().ok().unwrap().value as *const u8, identity);
            drop(returned);
            assert_eq!(&*events.borrow(), &["drop"]);
        }
        #[test]
        fn delivery_unknown_error_is_borrowed_emitted_before_drop_and_returned_unchanged() {
            let events = Rc::new(RefCell::new(Vec::new()));
            let error = NonClone { value: Box::new(9), events: events.clone() };
            let identity = &*error.value as *const u8;
            let returned = observe_result(
                Stage::DeliveryRedisclosureApprove,
                Err::<NonClone, _>(error),
                |borrowed| {
                    assert_eq!(&*borrowed.value as *const u8, identity);
                    events.borrow_mut().push("classify");
                    None
                },
                |stage, outcome| {
                    assert_eq!(stage, Stage::DeliveryRedisclosureApprove);
                    assert_eq!(outcome.label(), "WorkerFailure");
                    events.borrow_mut().push("emit");
                },
            );
            assert_eq!(&*events.borrow(), &["classify", "emit"]);
            assert_eq!(&*returned.as_ref().err().unwrap().value as *const u8, identity);
            drop(returned);
            assert_eq!(&*events.borrow(), &["classify", "emit", "drop"]);
        }
    }
}


#[cfg(all(test, not(feature = "synthetic-born-joined-qualification")))]
mod delivery_diagnostics_disabled_tests {
    #[test]
    fn delivery_observation_is_identity_without_synthetic_feature() {
        struct NonClone(Box<u8>);
        let calls = std::cell::Cell::new(0);
        let success = NonClone(Box::new(7));
        let success_identity = &*success.0 as *const u8;
        // This nonexistent stage is deliberately never resolved outside the
        // synthetic cfg. Only the original expression and Result remain.
        let returned: std::result::Result<_, NonClone> = durable_delivery_observe_v2!(
            NoDiagnosticStageExists,
            {
                calls.set(calls.get() + 1);
                Ok(success)
            }
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(&*returned.as_ref().ok().unwrap().0 as *const u8, success_identity);
        let error = NonClone(Box::new(9));
        let error_identity = &*error.0 as *const u8;
        let returned: std::result::Result<(), _> = durable_delivery_observe_v2!(
            NoDiagnosticStageExists,
            {
                calls.set(calls.get() + 1);
                Err(error)
            }
        );
        assert_eq!(calls.get(), 2);
        assert_eq!(&*returned.as_ref().err().unwrap().0 as *const u8, error_identity);
    }
}

#[cfg(feature = "pending-birth-owner-signing")]
#[path = "qualification/born_consumed_named_entry_v1.rs"]
mod born_consumed_named_entry_v1;
#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
mod durable_entry_v1;
#[cfg(all(
    feature = "synthetic-born-joined-qualification",
    feature = "durable-proposal"
))]
#[path = "qualification/durable_proposal_v1.rs"]
pub(in crate::native_ui) mod durable_proposal_qualification_v1;
#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
mod durable_review_v1;
#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
mod durable_delivery_admission_v2;
#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
mod durable_witness_v1;

#[cfg(feature = "pending-birth-owner-signing")]
#[path = "qualification/born_common_context_entry_v3.rs"]
mod born_common_context_entry_v3;

use super::{
    authority::{ExactNativeReview, NativeAuthority},
    state::inert_text,
};
use crate::{
    account::{AccountVault, PendingAccount, ProvisioningConsent},
    consent_journal::*,
    ipc::{AuthenticatedPeer, LocalEvent, LocalIpc, PendingPairing},
    Error, Result,
};
use eframe::egui;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use wholepact_core::{Proposal, ProposalInput};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "authority-signing")]
use super::{
    wallet_workspace::{NativeWalletRevocation, NativeWalletWorkspace, PreparedWalletSetup},
    witness_workspace::{
        ApprovedWriterActivation, ApprovedWriterSession, NativeWitnessWorkspace,
        PreparedWitnessSetup, PreparedWriterActivation, PreparedWriterSession,
    },
};
#[cfg(feature = "authority-signing")]
use crate::authority_bridge::{
    self,
    disclosure::{ApprovedWitnessDisclosure, WitnessDisclosureReview},
    protocol::AuthorizationDeliveryScope,
};
#[cfg(feature = "authority-signing")]
struct SpendFlow {
    prepared: PreparedSpendConsent,
    inputs: crate::manifest::ReviewInputs,
    bytes: Zeroizing<Vec<u8>>,
    head: wholepact_authority::AuthorityHead,
    candidate_id: String,
}
#[cfg(feature = "authority-signing")]
struct AutomaticFlow {
    approval: ApprovedAutomaticSpendConsent,
    inputs: crate::manifest::ReviewInputs,
    bytes: Zeroizing<Vec<u8>>,
    head: wholepact_authority::AuthorityHead,
    candidate_id: String,
    ticket: wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseTicket,
    verified: authority_bridge::automation::VerifiedAutomaticRequest,
    grant: NativeAutomationGrantRecord,
    delivery: Option<AutomaticIpcDelivery>,
}
#[cfg(feature = "authority-signing")]
struct AutomaticIpcDelivery {
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: authority_bridge::automation_ipc::AutomaticRequest,
}
#[cfg(feature = "authority-signing")]
type WalletReviewResult = Result<(
    crate::manifest::ReviewInputs,
    wholepact_authority::AuthorityHead,
    Option<wholepact_authority::AuthenticatedWriterSession>,
)>;
#[cfg(feature = "authority-signing")]
struct WalletJob {
    automation_grant: Option<String>,
    automatic_delivery: Option<AutomaticIpcDelivery>,
    receive: std::sync::mpsc::Receiver<(NativeWalletWorkspace, WalletReviewResult)>,
    revoke: NativeWalletRevocation,
    done: Arc<AtomicBool>,
    bytes: Zeroizing<Vec<u8>>,
    epoch: u64,
}
#[cfg(feature = "authority-signing")]
struct SigningJob {
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    flow: Option<(
        flow_diag_v1::DurableFlowJobObservationV1,
        flow_diag_v1::DurableFlowObserverV1,
    )>,
    receive: std::sync::mpsc::Receiver<(
        OpenAccount,
        std::result::Result<authority_bridge::AuthorizationCommit, authority_bridge::BridgeError>,
    )>,
    session: Arc<SignerConsentSession>,
    admission: crate::ipc::IpcRevocation,
    wallet_revoke: NativeWalletRevocation,
    peer: AuthenticatedPeer,
    lock_requested: bool,
}
#[cfg(feature = "authority-signing")]
struct WorkerCompletion(Arc<AtomicBool>);
#[cfg(feature = "authority-signing")]
impl Drop for WorkerCompletion {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
#[cfg(feature = "authority-signing")]
enum WitnessOutcome {
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    DurablePaymentV1(durable_witness_v1::DurableWitnessOutcomeV1),
    HostContinuityPrepared(Result<Box<super::host_recovery::PreparedHostContinuity>>),
    HostContinuityPreparedV2(Result<Box<super::host_recovery::v2::PreparedHostContinuityV2>>),
    HostContinuityPreparedV3(Result<Box<super::host_recovery::v3::PreparedHostContinuityV3>>),
    HostContinuityPreparedV5(Result<Box<super::host_recovery::v5::PreparedHostContinuityV5>>),
    HostPublicationPrepared(Result<Box<super::host_publication::PreparedHostPublication>>),
    HostPublicationPreparedV2(Result<Box<super::host_publication::v2::PreparedHostPublicationV2>>),
    HostPublicationPreparedV3(Result<Box<super::host_publication::v3::PreparedHostPublicationV3>>),
    HostPublicationPreparedV5(Result<Box<super::host_publication::v5::PreparedHostPublicationV5>>),
    AutomationGrantPrepared(Result<Box<PreparedAutomationGrantChange>>),
    AutomationPrepared(Result<Box<super::automation_workspace::PreparedGrantSynchronization>>),
    AutomationCompleted(Result<()>),
    SponsorPolicyCompleted(Result<()>),
    ResolutionPrepared(Result<Box<super::resolution_workspace::PreparedResolution>>),
    ResolutionCompleted(Result<Option<String>>),
    DispatchPrepared(Result<Box<super::dispatch::PreparedDispatch>>),
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    BornHistoryPrepared(Result<Box<super::born_history::PreparedBornHistoryV1>>),
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    BornDispatchPrepared(Result<Box<super::born_dispatch::PreparedBornDispatchV1>>),
    SessionPrepared(Result<Box<PreparedWriterSession>>),
    SessionAcquired {
        approved: Box<ApprovedWriterSession>,
        result: Result<Box<wholepact_authority::WriterSessionReceipt>>,
    },
    ActivationPrepared(Result<Box<PreparedWriterActivation>>),
    Activated {
        approved: Box<ApprovedWriterActivation>,
        result: Result<()>,
    },
    ReconciliationPrepared(Result<Box<PreparedWriterReconciliation>>),
    Reconciled(Result<()>),
}
#[cfg(feature = "authority-signing")]
struct WitnessJob {
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    flow: Option<(
        flow_diag_v1::DurableFlowJobObservationV1,
        flow_diag_v1::DurableFlowObserverV1,
        flow_diag_v1::DurableFlowStageV1,
    )>,
    receive: std::sync::mpsc::Receiver<WitnessOutcome>,
    done: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    epoch: u64,
}
/// Issued from a successful kernel-authenticated, token-proving request after
/// native pairing. This authenticates only the stated local process association.
pub(crate) struct AuthenticatedPairing {
    peer: AuthenticatedPeer,
    binding: TransportIdentityBinding,
}
impl AuthenticatedPairing {
    pub(crate) fn from_authenticated_request(peer: AuthenticatedPeer) -> Result<Self> {
        peer.check_current()?;
        let binding = TransportIdentityBinding::LocalProcess {
            transport_identity_id: peer.grant_id.clone(),
            channel_key_digest: peer.key_digest.clone(),
            channel_binding_digest: peer.channel_digest.clone(),
            uid: peer.peer.uid(),
            pid: peer.peer.pid(),
            process_instance: peer.peer.instance().into(),
            signer_generation: peer.generation,
            account_id: peer.scope.account_id.clone(),
            agreement_id: peer.scope.agreement_id.clone(),
            participant_id: peer.scope.participant_id.clone(),
            manifest_digest: peer.scope.manifest_digest.clone(),
        };
        Ok(Self { peer, binding })
    }
    pub(crate) fn account_id(&self) -> &str {
        &self.peer.scope.account_id
    }
    pub(crate) fn agreement_id(&self) -> &str {
        &self.peer.scope.agreement_id
    }
    pub(crate) fn participant_id(&self) -> &str {
        &self.peer.scope.participant_id
    }
    pub(crate) fn binding(&self) -> &TransportIdentityBinding {
        &self.binding
    }
    pub(crate) fn current_peer(&self) -> AuthenticatedPeer {
        self.peer.clone()
    }
    pub(crate) fn native_origin(&self) -> &super::NativeAuthorityBinding {
        &self.peer.native_origin
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.peer.native_origin.check_current()?;
        self.peer.check_current()
    }
}
enum Operation {
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    DurableWitnessV1(Box<durable_witness_v1::DurableWitnessPreparedV1>),
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    DurableDeliveryV2(Box<durable_delivery_admission_v2::PreparedAdmissionV2>),
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    DurableDeliveryRedisclosureV2(Box<durable_delivery_admission_v2::PreparedRedisclosureV2>),
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    DurableDisclosureV1 {
        flow: Box<durable_review_v1::DurableSpendFlowV1>,
        review: Box<WitnessDisclosureReview>,
    },
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    DurableSpendV1 {
        flow: Box<durable_review_v1::DurableSpendFlowV1>,
        disclosure: Box<ApprovedWitnessDisclosure>,
    },
    #[cfg(feature = "authority-signing")]
    HostContinuity(Box<super::host_recovery::PreparedHostContinuity>),
    #[cfg(feature = "authority-signing")]
    HostContinuityV2(Box<super::host_recovery::v2::PreparedHostContinuityV2>),
    #[cfg(feature = "authority-signing")]
    HostContinuityV3(Box<super::host_recovery::v3::PreparedHostContinuityV3>),
    #[cfg(feature = "authority-signing")]
    HostContinuityV5(Box<super::host_recovery::v5::PreparedHostContinuityV5>),
    #[cfg(feature = "authority-signing")]
    HostPublication(Box<super::host_publication::PreparedHostPublication>),
    #[cfg(feature = "authority-signing")]
    HostPublicationV2(Box<super::host_publication::v2::PreparedHostPublicationV2>),
    #[cfg(feature = "authority-signing")]
    HostPublicationV3(Box<super::host_publication::v3::PreparedHostPublicationV3>),
    #[cfg(feature = "authority-signing")]
    HostPublicationV5(Box<super::host_publication::v5::PreparedHostPublicationV5>),
    #[cfg(feature = "authority-signing")]
    AutomationGrant(Box<PreparedAutomationGrantChange>),
    #[cfg(feature = "authority-signing")]
    AutomationWitness(Box<super::automation_workspace::PreparedGrantSynchronization>),
    #[cfg(feature = "authority-signing")]
    AutomaticDisclosure {
        flow: Box<AutomaticFlow>,
        review: Box<WitnessDisclosureReview>,
    },
    #[cfg(feature = "authority-signing")]
    SponsorPolicy(Box<crate::consent_journal::PreparedSponsorPolicyChange>),
    #[cfg(feature = "authority-signing")]
    Resolution(Box<super::resolution_workspace::PreparedResolution>),
    #[cfg(feature = "authority-signing")]
    RecipientObservation(Box<super::recipient::observation::PreparedObservation>),
    #[cfg(feature = "authority-signing")]
    Recipient(Box<super::recipient::PreparedRecipient>),
    #[cfg(feature = "authority-signing")]
    OwnerInspection(Box<super::account_inspection::PreparedOwnerInspection>),
    #[cfg(feature = "authority-signing")]
    NamedVerifierPolicy(Box<super::named_verifier_policy::PreparedNamedVerifierPolicy>),
    #[cfg(feature = "authority-signing")]
    Preconstruction(Box<super::preconstruction::PreparedPreconstruction>),
    #[cfg(feature = "durable-proposal")]
    DurableConstructionV1(Box<super::durable_construction_v1::PreparedDurableConstructionV1>),
    #[cfg(feature = "authority-signing")]
    ProvedDisclosure(Box<super::proved_disclosure::PreparedProvedDisclosure>),
    #[cfg(feature = "authority-signing")]
    Dispatch(Box<super::dispatch::PreparedDispatch>),
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    BornHistory(Box<super::born_history::PreparedBornHistoryV1>),
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    BornDispatch(Box<super::born_dispatch::PreparedBornDispatchV1>),
    Pair(Box<PendingPairing>),
    Redelivery {
        prepared: Box<PreparedResultRedelivery>,
        peer: Box<AuthenticatedPeer>,
        stream: std::os::unix::net::UnixStream,
    },
    Enroll(Box<PreparedEnrollment>),
    Manifest(Box<PreparedManifestAcceptance>),
    #[cfg(feature = "authority-signing")]
    Wallet(Box<PreparedWalletSetup>),
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    DurableBornWalletV1(
        Box<super::wallet_workspace::durable_born_workspace_v1::PreparedDurableBornWalletSetupV1>,
    ),
    #[cfg(feature = "authority-signing")]
    Witness(Box<PreparedWitnessSetup>),
    #[cfg(feature = "authority-signing")]
    OwnerWitness(Box<PreparedWitnessSetup>),
    #[cfg(feature = "authority-signing")]
    WriterSession(Box<PreparedWriterSession>),
    #[cfg(feature = "authority-signing")]
    WriterActivation(Box<PreparedWriterActivation>),
    #[cfg(feature = "authority-signing")]
    Reconcile(Box<PreparedWriterReconciliation>),
    #[cfg(feature = "authority-signing")]
    Disclosure {
        flow: Box<SpendFlow>,
        review: Box<WitnessDisclosureReview>,
    },
    #[cfg(feature = "authority-signing")]
    Spend {
        flow: Box<SpendFlow>,
        disclosure: Box<ApprovedWitnessDisclosure>,
    },
    Provider(Box<super::provider_export::PreparedProviderExport>),
}
struct PendingDecision {
    review: ExactNativeReview,
    operation: Operation,
}
enum OpenNativeAuthority {
    Ordinary(NativeAuthority),
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    DurableBorn(Arc<super::PendingAccountNativeAuthority>),
}
impl std::ops::Deref for OpenNativeAuthority {
    type Target = NativeAuthority;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Ordinary(native) => native,
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            Self::DurableBorn(owner) => owner.native(),
        }
    }
}
struct OpenAccount {
    vault: Arc<AccountVault>,
    journal: Arc<SignerConsentJournal>,
    authority: OpenNativeAuthority,
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    durable_born_entry: Option<
        Arc<
            crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1,
        >,
    >,
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    durable_review: Option<Arc<durable_review_v1::ImportedDurableReviewV1>>,
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    durable_delivery_entry: Option<Arc<crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableDeliveryEntryV2>>,
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    durable_delivery: durable_delivery_admission_v2::DurableDeliveryRuntimeV2,
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    durable_witness: durable_witness_v1::DurableWitnessRuntimeV1,
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    durable_import_job: Option<durable_review_v1::DurableImportJobV1>,
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    durable_wallet_job: Option<durable_review_v1::DurableWalletJobV1>,
    // Every session remains registered until its through-commit write fence completes on lock,
    // navigation, app revocation/exit, expiry or replacement. Blur discards pending
    // input but preserves already-approved scope and original expiry. No detached grants.
    session: Option<Arc<SignerConsentSession>>,
    ipc: LocalIpc,
    // Fields drop in declaration order. IPC drains BEFORE its owned external
    // temporary directory is removed; the original vault inventory is untouched.
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    durable_ipc_directory: Option<tempfile::TempDir>,
    pairing: Option<AuthenticatedPairing>,
    enrollment: Option<AccountEnrollmentRecord>,
    manifest: Option<AcceptedManifestRecord>,
    revocations: Vec<Arc<AtomicBool>>,
    history_workers: Vec<std::thread::JoinHandle<()>>,
    disclosure_worker_ids: std::collections::HashSet<std::thread::ThreadId>,
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    born_bridge_active: bool,
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    born_bridge_workers: std::collections::HashSet<std::thread::ThreadId>,
    #[cfg(feature = "authority-signing")]
    host_continuity_worker: Option<std::thread::ThreadId>,
    #[cfg(feature = "authority-signing")]
    wallet: Option<NativeWalletWorkspace>,
    #[cfg(feature = "authority-signing")]
    wallet_job: Option<WalletJob>,
    #[cfg(feature = "authority-signing")]
    witness: Option<Arc<NativeWitnessWorkspace>>,
    #[cfg(feature = "authority-signing")]
    owner_witness: Option<Arc<NativeWitnessWorkspace>>,
    #[cfg(feature = "authority-signing")]
    witness_job: Option<WitnessJob>,
    #[cfg(feature = "authority-signing")]
    writer_receipt: Option<wholepact_authority::WriterSessionReceipt>,
    #[cfg(feature = "authority-signing")]
    writer_reconciled: bool,
    #[cfg(feature = "authority-signing")]
    writer_retry: Option<ApprovedWriterSession>,
    #[cfg(feature = "authority-signing")]
    activation_retry: Option<ApprovedWriterActivation>,
}
impl OpenAccount {
    fn supports_ordinary_routes(&self) -> bool {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self.durable_born_entry.is_some() || self.durable_delivery_entry.is_some() {
            return false;
        }
        true
    }
    fn invalidate_review(&mut self) {
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        let flow_observer = self.durable_witness.flow_observation.clone();
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        {
            self.durable_witness = durable_witness_v1::DurableWitnessRuntimeV1::default();
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        {
            self.clear_durable_review_v1();
            self.durable_delivery.clear();
        }
        // Close admission immediately, before waiting for any already-held
        // through-commit lease. The native event thread never waits for a client.
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        if self.born_bridge_active {
            self.authority.revoke_named_recipient_now();
            self.ipc.revocation().close_named_recipient_now();
        } else {
            self.ipc.revoke_all();
        }
        #[cfg(not(all(feature = "authority-signing", feature = "offline-review-foundation")))]
        self.ipc.revoke_all();
        self.pairing = None;
        #[cfg(feature = "authority-signing")]
        {
            if let Some(wallet) = self.wallet.take() {
                wallet.revoke_handle().revoke();
            }
            if let Some(job) = self.witness_job.take() {
                #[cfg(all(
                    feature = "synthetic-born-joined-qualification",
                    feature = "durable-proposal"
                ))]
                if let Some((flow, _, _)) = &job.flow {
                    flow.invalidated();
                }
                job.cancelled.store(true, Ordering::Release);
                self.revocations.push(job.done);
            }
            if let Some(job) = self.wallet_job.take() {
                job.revoke.revoke();
                self.revocations.push(job.done);
            }
            self.witness = None;
            self.owner_witness = None;
            self.writer_receipt = None;
            self.writer_reconciled = false;
            self.writer_retry = None;
            self.activation_retry = None;
        }
        if let Some(session) = self.session.take() {
            let done = Arc::new(AtomicBool::new(false));
            let finished = done.clone();
            std::thread::spawn(move || {
                let _ = durable_flow_observe_v1!(
                    flow_observer.as_ref(),
                    flow_diag_v1::DurableFlowStageV1::Close,
                    session.invalidate()
                );
                finished.store(true, Ordering::Release);
            });
            self.revocations.push(done);
        }
        self.enrollment = None;
        self.manifest = None;
    }
    fn refresh_session(&mut self) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if let Some(source) = &self.durable_delivery_entry {
            source.check_current()?;
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if let Some(source) = &self.durable_born_entry {
            source.check_current()?;
        }
        self.revocations
            .retain(|done| !done.load(Ordering::Acquire));
        if !self.revocations.is_empty() || self.session.is_some() {
            return Err(Error::Locked);
        }
        let launch = TrustedSignerLaunch::from_native(
            &self.authority,
            &self.journal,
            self.vault.account(),
            self.pairing.as_ref().ok_or(Error::Authentication)?,
        )?;
        self.session = Some(Arc::new(SignerConsentSession::from_trusted_launch(launch)?));
        Ok(())
    }
    fn close(mut self) {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        {
            self.clear_durable_review_v1();
            self.durable_delivery.clear();
        }
        self.ipc.revoke_all();
        #[cfg(feature = "authority-signing")]
        {
            if let Some(wallet) = self.wallet.take() {
                wallet.revoke_handle().revoke();
            }
            if let Some(job) = self.witness_job.take() {
                #[cfg(all(
                    feature = "synthetic-born-joined-qualification",
                    feature = "durable-proposal"
                ))]
                if let Some((flow, _, _)) = &job.flow {
                    flow.invalidated();
                }
                job.cancelled.store(true, Ordering::Release);
                self.revocations.push(job.done);
            }
            if let Some(job) = self.wallet_job.take() {
                job.revoke.revoke();
                self.revocations.push(job.done);
            }
        }
        if let Some(session) = self.session.take() {
            let _ = durable_flow_observe_v1!(
                self.durable_witness.flow_observation.as_ref(),
                flow_diag_v1::DurableFlowStageV1::Close,
                session.invalidate()
            );
        }
        // A disconnected client may still be completing an admitted commit.
        // Keep its source alive until the actual process ends or lease finishes.
        for done in &self.revocations {
            while !done.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        self.authority.invalidate();
        for worker in self.history_workers {
            let _ = worker.join();
        }
    }
    #[cfg(feature = "authority-signing")]
    fn bind_host_recovery_v5(&mut self, peer: &AuthenticatedPeer) -> Result<()> {
        self.authority.check_current()?;
        peer.check_current()?;
        if self
            .revocations
            .iter()
            .any(|done| !done.load(Ordering::Acquire))
            || peer.native_origin != self.authority.binding()
            || peer.scope.account_id != self.vault.account_id()?
            || !peer.scope.history_read
            || !peer.scope.authorization_export
        {
            return Err(Error::Authentication);
        }
        // This peer already owns a distinct real native IPC grant. V5 binds it
        // without creating a financial SignerConsentSession or replacing any
        // conflicting/revoked pairing. General enrollment is unchanged.
        let incoming = AuthenticatedPairing::from_authenticated_request(peer.clone())?;
        if let Some(existing) = &self.pairing {
            existing.check_current()?;
            if existing.binding() != incoming.binding() {
                return Err(Error::Authentication);
            }
        } else {
            self.pairing = Some(incoming);
        }
        self.check_pairing()?;
        Ok(())
    }
    fn check_pairing(&self) -> Result<&AuthenticatedPairing> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if let Some(source) = &self.durable_born_entry {
            source.check_current()?;
        }
        self.authority.check_current()?;
        if self
            .revocations
            .iter()
            .any(|done| !done.load(Ordering::Acquire))
        {
            return Err(Error::Locked);
        }
        let paired = self.pairing.as_ref().ok_or(Error::Authentication)?;
        paired.check_current()?;
        if paired.account_id() != self.vault.account_id()? {
            return Err(Error::Authentication);
        }
        Ok(paired)
    }
}
/// Issued only in this runtime's focused primary-click branch, before account
/// generation. No external constructor, serde form or boolean approval exists.
#[cfg(feature = "authority-signing")]
pub(super) struct PendingBirthEntry {
    focus_epoch: u64,
    parent_channel: Option<crate::native_launch::ParentChannel>,
}
#[cfg(feature = "authority-signing")]
impl PendingBirthEntry {
    pub(super) fn into_parts(self) -> (u64, Option<crate::native_launch::ParentChannel>) {
        (self.focus_epoch, self.parent_channel)
    }
}
/// Constructed only by the focused, idle dedicated retirement entry below.
/// It carries no account, peer grant, serialized consent or replacement owner.
#[cfg(feature = "authority-signing")]
pub(super) struct RetirementNativeEntry {
    focus_epoch: u64,
    parent_channel: Option<crate::native_launch::ParentChannel>,
    deadline: std::time::Instant,
}
#[cfg(feature = "authority-signing")]
impl RetirementNativeEntry {
    pub(super) fn into_parts(
        self,
    ) -> (
        u64,
        Option<crate::native_launch::ParentChannel>,
        std::time::Instant,
    ) {
        (self.focus_epoch, self.parent_channel, self.deadline)
    }
}
pub(super) struct NativeRuntime {
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    durable_entry_job: Option<durable_entry_v1::DurableEntryJobV1>,
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
    durable_delivery_entry_job: Option<durable_entry_v1::DurableDeliveryEntryJobV2>,
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    durable_entry_failure: Option<(durable_entry_v1::DurableEntryFailureStageV1, Error)>,
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    named_verifier: super::named_verifier_owner::SetupWorkspace,
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    named_recipient: super::named_recipient::NamedRecipientWorkspace,
    open: Option<OpenAccount>,
    parent_channel: Option<crate::native_launch::ParentChannel>,
    pending_account: Option<PendingAccount>,
    #[cfg(feature = "authority-signing")]
    birth: super::birth_workspace::NativeBirthCeremony,
    #[cfg(feature = "pending-birth-owner-signing")]
    pending_enrollment: super::pending_enrollment::PendingEnrollmentUi,
    #[cfg(feature = "pending-birth-owner-signing")]
    born_origin: super::born_origin_workspace::BornOriginUi,
    #[cfg(feature = "pending-birth-owner-signing")]
    born_manual: super::born_manual::BornManualUi,
    #[cfg(feature = "pending-birth-owner-signing")]
    born_manual_roster_v2: super::born_manual_roster_v2::BornManualRosterUiV2,
    #[cfg(feature = "pending-birth-owner-signing")]
    born_enrolled_backup: super::born_enrolled_backup::BornEnrolledBackupUi,
    #[cfg(feature = "authority-signing")]
    retirement_evidence: super::retirement_review::RetirementEvidenceUi,
    #[cfg(feature = "authority-signing")]
    retirement_evidence_session: super::retirement_session_ui::RetirementEvidenceSessionUi,
    #[cfg(feature = "authority-signing")]
    quarantined_history: super::quarantined_history::QuarantinedHistoryUi,
    #[cfg(feature = "authority-signing")]
    informational_archive: String,
    #[cfg(feature = "authority-signing")]
    informational_runtime_directory: String,
    #[cfg(feature = "authority-signing")]
    informational_password: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    retirement_witness: super::retirement_witness::RetirementWitnessUi,
    recovery: Zeroizing<String>,
    backup: Zeroizing<String>,
    root: String,
    privacy_domain: String,
    password: Zeroizing<String>,
    proposal: Zeroizing<String>,
    budget: String,
    #[cfg(feature = "authority-signing")]
    sponsor_policy_key: String,
    #[cfg(feature = "authority-signing")]
    automation: super::automation_workspace::AutomationUi,
    #[cfg(feature = "authority-signing")]
    sponsor_policy_terms: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    recipient_instructions: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    recipient_reference: String,
    #[cfg(feature = "authority-signing")]
    recipient_transaction_path: String,
    #[cfg(feature = "authority-signing")]
    recipient_result: Option<Zeroizing<String>>,
    #[cfg(feature = "authority-signing")]
    recipient_source: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    recipient_job: Option<
        std::sync::mpsc::Receiver<Result<super::recipient::observation::CompletedObservation>>,
    >,
    #[cfg(feature = "authority-signing")]
    recovery_directory: String,
    #[cfg(feature = "authority-signing")]
    recovery_password: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    recovery_repeat: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    recovery_confirmation: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    recovery_activation: super::recovery_workspace::RecoveryUi,
    provider_image: String,
    provider_export_directory: String,
    confirmation: Zeroizing<String>,
    pending: Option<PendingDecision>,
    message: &'static str,
    last_receipt: Option<String>,
    closing_accounts: Vec<Arc<AtomicBool>>,
    #[cfg(feature = "authority-signing")]
    wallet_setup: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    witness_setup: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    owner_witness_setup: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    resolution_setup: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    witness_resolution_setup: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    resolution_authorization: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    resolution_dispatch: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    resolution_source_reference: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    review_context: Zeroizing<String>,
    #[cfg(feature = "authority-signing")]
    incoming_pczt: Option<Zeroizing<Vec<u8>>>,
    #[cfg(feature = "authority-signing")]
    signing_job: Option<SigningJob>,
}
impl NativeRuntime {
    pub(super) fn new(parent_channel: Option<crate::native_launch::ParentChannel>) -> Self {
        Self {
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            durable_entry_job: None,
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            durable_delivery_entry_job: None,
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            ))]
            durable_entry_failure: None,
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            named_verifier: super::named_verifier_owner::SetupWorkspace::default(),
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            named_recipient: super::named_recipient::NamedRecipientWorkspace::default(),
            open: None,
            parent_channel,
            pending_account: None,
            #[cfg(feature = "authority-signing")]
            birth: super::birth_workspace::NativeBirthCeremony::default(),
            #[cfg(feature = "pending-birth-owner-signing")]
            pending_enrollment: super::pending_enrollment::PendingEnrollmentUi::default(),
            #[cfg(feature = "pending-birth-owner-signing")]
            born_origin: super::born_origin_workspace::BornOriginUi::default(),
            #[cfg(feature = "pending-birth-owner-signing")]
            born_manual: super::born_manual::BornManualUi::default(),
            #[cfg(feature = "pending-birth-owner-signing")]
            born_manual_roster_v2: super::born_manual_roster_v2::BornManualRosterUiV2::default(),
            #[cfg(feature = "pending-birth-owner-signing")]
            born_enrolled_backup: super::born_enrolled_backup::BornEnrolledBackupUi::default(),
            #[cfg(feature = "authority-signing")]
            retirement_evidence: super::retirement_review::RetirementEvidenceUi::default(),
            #[cfg(feature = "authority-signing")]
            retirement_evidence_session:
                super::retirement_session_ui::RetirementEvidenceSessionUi::default(),
            #[cfg(feature = "authority-signing")]
            quarantined_history: super::quarantined_history::QuarantinedHistoryUi::default(),
            #[cfg(feature = "authority-signing")]
            informational_archive: String::new(),
            #[cfg(feature = "authority-signing")]
            informational_runtime_directory: String::new(),
            #[cfg(feature = "authority-signing")]
            informational_password: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            retirement_witness: super::retirement_witness::RetirementWitnessUi::default(),
            recovery: Zeroizing::new(String::new()),
            backup: Zeroizing::new(String::new()),
            root: String::new(),
            privacy_domain: String::new(),
            password: Zeroizing::new(String::new()),
            proposal: Zeroizing::new(String::new()),
            budget: String::new(),
            #[cfg(feature = "authority-signing")]
            sponsor_policy_key: String::new(),
            #[cfg(feature = "authority-signing")]
            automation: super::automation_workspace::AutomationUi::default(),
            #[cfg(feature = "authority-signing")]
            sponsor_policy_terms: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            recipient_instructions: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            recipient_reference: String::new(),
            #[cfg(feature = "authority-signing")]
            recipient_transaction_path: String::new(),
            #[cfg(feature = "authority-signing")]
            recipient_result: None,
            #[cfg(feature = "authority-signing")]
            recipient_source: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            recipient_job: None,
            #[cfg(feature = "authority-signing")]
            recovery_directory: String::new(),
            #[cfg(feature = "authority-signing")]
            recovery_password: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            recovery_repeat: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            recovery_confirmation: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            recovery_activation: super::recovery_workspace::RecoveryUi::default(),
            provider_image: String::new(),
            provider_export_directory: String::new(),
            confirmation: Zeroizing::new(String::new()),
            pending: None,
            message: "No account is unlocked. Native setup is separate from synthetic tests.",
            last_receipt: None,
            closing_accounts: Vec::new(),
            #[cfg(feature = "authority-signing")]
            wallet_setup: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            witness_setup: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            owner_witness_setup: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            resolution_setup: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            witness_resolution_setup: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            resolution_authorization: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            resolution_dispatch: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            resolution_source_reference: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            review_context: Zeroizing::new(String::new()),
            #[cfg(feature = "authority-signing")]
            incoming_pczt: None,
            #[cfg(feature = "authority-signing")]
            signing_job: None,
        }
    }
    pub(super) fn lock(&mut self) {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        {
            {
                self.cancel_durable_entry_v1();
                self.cancel_durable_delivery_entry_v2();
            }
            if let Some(source) = self
                .open
                .as_ref()
                .and_then(|o| o.durable_delivery_entry.as_ref())
            {
                source.native_owner().revoke_pending_now();
            }
            if let Some(source) = self
                .open
                .as_ref()
                .and_then(|o| o.durable_born_entry.as_ref())
            {
                source.native_owner().revoke_pending_now();
            }
        }
        // Named workers retain the exact live source and may be draining I/O.
        // Close admission without a grant/publication mutex on the event thread;
        // the unchanged background close below owns all blocking cleanup.
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        let named_closing = self.named_recipient.final_active()
            || self.open.as_ref().is_some_and(|o| o.born_bridge_active);
        #[cfg(not(all(feature = "authority-signing", feature = "offline-review-foundation")))]
        let named_closing = false;
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        if named_closing {
            if let Some(open) = self.open.as_ref() {
                open.authority.revoke_named_recipient_now();
                open.ipc.revocation().close_named_recipient_now();
            }
        }
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        self.named_verifier.clear();
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        self.named_recipient.clear();
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence.clear();
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence_session.clear();
        #[cfg(feature = "authority-signing")]
        {
            self.quarantined_history.clear();
            self.informational_password.zeroize();
        }
        #[cfg(feature = "authority-signing")]
        self.retirement_witness.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_origin.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_manual.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_manual_roster_v2.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_enrolled_backup.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.pending_enrollment.clear();
        #[cfg(feature = "authority-signing")]
        self.birth.clear();
        #[cfg(feature = "authority-signing")]
        self.recovery_activation.clear();
        #[cfg(feature = "authority-signing")]
        {
            self.automation.clear();
            self.sponsor_policy_terms.zeroize();
            self.sponsor_policy_key.zeroize();
        }
        #[cfg(feature = "authority-signing")]
        {
            self.incoming_pczt = None;
            self.review_context.zeroize();
            self.wallet_setup.zeroize();
            self.witness_setup.zeroize();
            self.owner_witness_setup.zeroize();
            self.resolution_setup.zeroize();
            self.witness_resolution_setup.zeroize();
            self.resolution_authorization.zeroize();
            self.resolution_dispatch.zeroize();
            self.resolution_source_reference.zeroize();
            if let Some(job) = self.signing_job.as_mut().filter(|job| !job.lock_requested) {
                job.lock_requested = true;
                job.admission.close();
                job.wallet_revoke.revoke();
                let session = job.session.clone();
                #[cfg(all(
                    feature = "synthetic-born-joined-qualification",
                    feature = "durable-proposal"
                ))]
                let flow_observer = job.flow.as_ref().map(|(_, observer)| observer.clone());
                std::thread::spawn(move || {
                    let _ = durable_flow_observe_v1!(
                        flow_observer.as_ref(),
                        flow_diag_v1::DurableFlowStageV1::Close,
                        session.invalidate()
                    );
                });
            }
        }
        self.pending = None;
        if let Some(mut open) = self.open.take() {
            if !named_closing {
                open.ipc.revoke_all();
            }
            let done = Arc::new(AtomicBool::new(false));
            let finished = done.clone();
            std::thread::spawn(move || {
                open.close();
                finished.store(true, Ordering::Release);
            });
            self.closing_accounts.push(done);
        }
        self.pending_account = None;
        self.recovery.zeroize();
        self.backup.zeroize();
        self.password.zeroize();
        #[cfg(feature = "authority-signing")]
        {
            self.recovery_password.zeroize();
            self.recovery_repeat.zeroize();
            self.recovery_confirmation.zeroize();
        }
        self.proposal.zeroize();
        #[cfg(feature = "authority-signing")]
        {
            self.recipient_instructions.zeroize();
            self.recipient_reference.clear();
            self.recipient_transaction_path.clear();
            self.recipient_result = None;
            self.recipient_source.zeroize();
            self.recipient_job = None;
        }
        self.confirmation.zeroize();
        self.last_receipt = None;
        self.message = "New requests are blocked and pending decisions discarded. Lock completes after any already-admitted operation finishes or its process exits.";
    }
    /// Losing focus cancels unconfirmed input, not an already consumed exact
    /// disclosure decision. Explicit lock still revokes every original lease.
    pub(super) fn blur(&mut self) {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_delivery_entry.is_some())
        {
            self.lock();
            return;
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_wallet_job.is_some() || o.durable_import_job.is_some())
        {
            self.lock();
            return;
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        {
            self.cancel_durable_entry_v1();
            self.cancel_durable_delivery_entry_v2();
        }
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        self.named_verifier.blur();
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        self.named_recipient.clear();
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence.clear();
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence_session.clear();
        #[cfg(feature = "authority-signing")]
        {
            self.quarantined_history.blur();
            self.informational_password.zeroize();
        }
        #[cfg(feature = "authority-signing")]
        self.retirement_witness.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_origin.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_manual.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_manual_roster_v2.blur();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_enrolled_backup.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.pending_enrollment.clear();
        #[cfg(feature = "authority-signing")]
        self.birth.clear();
        #[cfg(feature = "authority-signing")]
        self.recovery_activation.clear();
        #[cfg(feature = "authority-signing")]
        {
            self.automation.clear();
            self.sponsor_policy_terms.zeroize();
            self.sponsor_policy_key.zeroize();
        }
        if self.open.as_ref().is_some_and(|o| {
            history_requires_blur_lock(&o.history_workers, &o.disclosure_worker_ids)
        }) {
            self.lock();
            return;
        }
        #[cfg(feature = "authority-signing")]
        if self.signing_job.is_some()
            || self.recipient_job.is_some()
            || self
                .open
                .as_ref()
                .is_some_and(|o| o.wallet_job.is_some() || o.witness_job.is_some())
        {
            self.lock();
            return;
        }
        self.pending = None;
        self.pending_account = None;
        self.confirmation.zeroize();
        self.password.zeroize();
        #[cfg(feature = "authority-signing")]
        {
            self.recovery_password.zeroize();
            self.recovery_repeat.zeroize();
            self.recovery_confirmation.zeroize();
        }
        self.backup.zeroize();
        self.recovery.zeroize();
        self.proposal.zeroize();
        self.last_receipt = None;
        #[cfg(feature = "authority-signing")]
        {
            self.incoming_pczt = None;
            self.review_context.zeroize();
            self.wallet_setup.zeroize();
            self.witness_setup.zeroize();
            self.owner_witness_setup.zeroize();
            self.resolution_setup.zeroize();
            self.witness_resolution_setup.zeroize();
            self.resolution_authorization.zeroize();
            self.resolution_dispatch.zeroize();
            self.resolution_source_reference.zeroize();
            self.recipient_instructions.zeroize();
            self.recipient_reference.clear();
            self.recipient_transaction_path.clear();
            self.recipient_result = None;
            self.recipient_source.zeroize();
        }
        // No refresh, replacement, TTL extension, new decision or key-use work.
        // The current peer/session remains bounded by its existing native grant.
        self.message = "Pending review discarded on focus loss. Already approved exact permissions retain their original scope and expiry; Lock revokes them.";
    }
    pub(super) fn navigate(&mut self) {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        {
            self.cancel_durable_entry_v1();
            self.cancel_durable_delivery_entry_v2();
        }
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        self.named_verifier.clear();
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        self.named_recipient.clear();
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence.clear();
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence_session.clear();
        #[cfg(feature = "authority-signing")]
        {
            self.quarantined_history.clear();
            self.informational_password.zeroize();
        }
        #[cfg(feature = "authority-signing")]
        self.retirement_witness.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_origin.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_manual.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_manual_roster_v2.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_enrolled_backup.clear();
        #[cfg(feature = "pending-birth-owner-signing")]
        self.pending_enrollment.clear();
        #[cfg(feature = "authority-signing")]
        self.birth.clear();
        #[cfg(feature = "authority-signing")]
        self.recovery_activation.clear();
        #[cfg(feature = "authority-signing")]
        {
            self.automation.clear();
            self.sponsor_policy_terms.zeroize();
            self.sponsor_policy_key.zeroize();
        }
        #[cfg(feature = "authority-signing")]
        if self.signing_job.is_some() {
            self.lock();
            return;
        }
        #[cfg(feature = "authority-signing")]
        {
            self.incoming_pczt = None;
            self.review_context.zeroize();
        }
        self.pending = None;
        self.confirmation.zeroize();
        self.password.zeroize();
        #[cfg(feature = "authority-signing")]
        {
            self.recovery_password.zeroize();
            self.recovery_repeat.zeroize();
            self.recovery_confirmation.zeroize();
        }
        self.backup.zeroize();
        self.pending_account = None;
        self.recovery.zeroize();
        if let Some(open) = self.open.as_mut() {
            open.invalidate_review();
        }
    }
    fn activate(&mut self, vault: AccountVault, journal: SignerConsentJournal) -> Result<()> {
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence_session
            .before_account_replacement()?;
        #[cfg(feature = "pending-birth-owner-signing")]
        if self.pending_enrollment.is_active()
            || self.born_origin.is_active()
            || self.born_manual.is_active()
            || self.born_manual_roster_v2.is_active()
            || self.born_enrolled_backup.is_active()
        {
            return Err(Error::ReviewMismatch);
        }
        #[cfg(feature = "authority-signing")]
        if self.birth.is_active() {
            return Err(Error::ReviewMismatch);
        }
        #[cfg(feature = "authority-signing")]
        self.recovery_activation.clear();
        if vault.account().recovery_required() || journal.account_state()?.recovery_required {
            return Err(Error::RecoveryRequired);
        }
        let ipc_path = Path::new(&self.root).join("local-apps");
        let directory = if ipc_path.exists() {
            crate::files::PrivateDirectory::open(&ipc_path)?
        } else {
            crate::files::PrivateDirectory::create(&ipc_path)?
        };
        let ipc = LocalIpc::bind(directory)?;
        let authority = NativeAuthority::entered_native_window()?;
        if let Some(channel) = &self.parent_channel {
            channel.publish_endpoint(ipc.socket_path())?;
        }
        self.open = Some(OpenAccount {
            vault: Arc::new(vault),
            journal: Arc::new(journal),
            authority: OpenNativeAuthority::Ordinary(authority),
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            durable_born_entry: None,
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            durable_delivery_entry: None,
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            durable_delivery: Default::default(),
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            durable_review: None,
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            durable_witness: durable_witness_v1::DurableWitnessRuntimeV1::default(),
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            durable_import_job: None,
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            durable_wallet_job: None,
            session: None,
            ipc,
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            durable_ipc_directory: None,
            pairing: None,
            enrollment: None,
            manifest: None,
            revocations: Vec::new(),
            history_workers: Vec::new(),
            disclosure_worker_ids: std::collections::HashSet::new(),
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            born_bridge_active: false,
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            born_bridge_workers: std::collections::HashSet::new(),
            #[cfg(feature = "authority-signing")]
            host_continuity_worker: None,
            #[cfg(feature = "authority-signing")]
            wallet: None,
            #[cfg(feature = "authority-signing")]
            wallet_job: None,
            #[cfg(feature = "authority-signing")]
            witness: None,
            #[cfg(feature = "authority-signing")]
            owner_witness: None,
            #[cfg(feature = "authority-signing")]
            witness_job: None,
            #[cfg(feature = "authority-signing")]
            writer_receipt: None,
            #[cfg(feature = "authority-signing")]
            writer_reconciled: false,
            #[cfg(feature = "authority-signing")]
            writer_retry: None,
            #[cfg(feature = "authority-signing")]
            activation_retry: None,
        });
        self.password.zeroize();
        #[cfg(feature = "authority-signing")]
        {
            self.recovery_password.zeroize();
            self.recovery_repeat.zeroize();
            self.recovery_confirmation.zeroize();
        }
        self.backup.zeroize();
        self.recovery.zeroize();
        self.message =
            "Account unlocked in this native window. Pair a local application before enrollment.";
        Ok(())
    }
    fn unlock(&mut self) -> Result<()> {
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence_session
            .before_account_replacement()?;
        #[cfg(feature = "authority-signing")]
        if self.birth.is_active() {
            return Err(Error::ReviewMismatch);
        }
        let mut vault = AccountVault::unlock(Path::new(&self.root), self.password.as_bytes())?;
        let journal = vault.open_authority_journal()?;
        self.activate(vault, journal)
    }
    fn create(&mut self) -> Result<()> {
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence_session
            .before_account_replacement()?;
        #[cfg(feature = "authority-signing")]
        if self.birth.is_active() {
            return Err(Error::ReviewMismatch);
        }
        if self.root.is_empty() || self.password.len() < 12 {
            return Err(Error::InvalidData);
        }
        let pending = PendingAccount::generate(ProvisioningConsent {
            privacy_domain: self.privacy_domain.clone(),
            account_index: 0,
        })?;
        self.recovery = pending.recovery_words()?;
        self.pending_account = Some(pending);
        self.message =
            "Record the dedicated account's recovery words privately, then re-enter them below.";
        Ok(())
    }
    fn finish_create(&mut self) -> Result<()> {
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence_session
            .before_account_replacement()?;
        #[cfg(feature = "authority-signing")]
        if self.birth.is_active() {
            return Err(Error::ReviewMismatch);
        }
        let pending = self.pending_account.take().ok_or(Error::ReviewMismatch)?;
        let verified = pending.verify_backup(&self.backup)?;
        let mut vault =
            AccountVault::create(Path::new(&self.root), verified, self.password.as_bytes())?;
        let journal = vault.create_authority_journal()?;
        self.activate(vault, journal)
    }
    #[cfg(feature = "authority-signing")]
    fn stage_recipient_observation(&mut self, epoch: u64) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }
        if self.recipient_job.is_some() {
            return Err(Error::Locked);
        }
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let prepared = super::recipient::observation::PreparedObservation::prepare(
            &self.recipient_source,
            &self.recipient_reference,
            &open.authority,
            &open.vault,
        )?;
        self.recipient_result = None;
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                prepared.digest(),
                prepared.display(),
                epoch,
            )?,
            operation: Operation::RecipientObservation(Box::new(prepared)),
        });
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn poll_recipient(&mut self) {
        let result = match self.recipient_job.as_ref().map(|job| job.try_recv()) {
            Some(Ok(result)) => Some(result),
            Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => Some(Err(Error::Unavailable)),
            _ => None,
        };
        if let Some(result) = result {
            self.recipient_job = None;
            let retained = result.and_then(|result| {
                let open = self.open.as_ref().ok_or(Error::Locked)?;
                result.retain(&open.authority, &open.vault)
            });
            match retained {
                Ok(summary) => {
                    self.recipient_result = Some(Zeroizing::new(summary));
                    self.message = "Recipient provider snapshot retained. Confidence is source-specific and expires.";
                }
                Err(_) => {
                    self.recipient_result = None;
                    self.message = "Recipient observation unavailable, stale or revoked. No success status or absence claim was recorded.";
                }
            }
        }
    }
    #[cfg(feature = "authority-signing")]
    fn stage_recipient(&mut self, issue: bool, epoch: u64) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let prepared = if issue {
            super::recipient::PreparedRecipient::issue(
                &self.recipient_instructions,
                &open.authority,
                &open.vault,
            )?
        } else {
            super::recipient::PreparedRecipient::check(
                &self.recipient_reference,
                &self.recipient_transaction_path,
                &open.authority,
                &open.vault,
            )?
        };
        self.recipient_result = None;
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                prepared.digest(),
                prepared.display(),
                epoch,
            )?,
            operation: Operation::Recipient(Box::new(prepared)),
        });
        Ok(())
    }
    fn stage_provider(&mut self, epoch: u64) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let prepared = super::provider_export::PreparedProviderExport::prepare(
            &self.provider_image,
            &open.authority,
        )?;
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                prepared.digest(),
                prepared.display()?,
                epoch,
            )?,
            operation: Operation::Provider(Box::new(prepared)),
        });
        Ok(())
    }
    fn poll(&mut self, epoch: u64) {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        self.poll_durable_delivery_v2(epoch);
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        self.poll_durable_material_lifetime_v1();
        if self.pending.as_ref().is_some_and(|p| p.review.expired()) {
            self.pending = None;
            self.confirmation.zeroize();
            self.message = "Native review expired. Request or prepare it again.";
        }
        self.closing_accounts
            .retain(|done| !done.load(Ordering::Acquire));
        let Some(open) = self.open.as_mut() else {
            return;
        };
        open.revocations
            .retain(|done| !done.load(Ordering::Acquire));
        open.history_workers.retain(|worker| !worker.is_finished());
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        {
            open.born_bridge_workers
                .retain(|id| open.history_workers.iter().any(|w| w.thread().id() == *id));
            open.born_bridge_active &= open.witness_job.is_some()
                || !open.born_bridge_workers.is_empty()
                || self.pending.as_ref().is_some_and(|p| {
                    matches!(
                        &p.operation,
                        Operation::BornHistory(_) | Operation::BornDispatch(_)
                    )
                });
        }
        open.disclosure_worker_ids
            .retain(|id| open.history_workers.iter().any(|w| w.thread().id() == *id));
        #[cfg(feature = "authority-signing")]
        if open
            .host_continuity_worker
            .is_some_and(|id| !open.history_workers.iter().any(|w| w.thread().id() == id))
        {
            open.host_continuity_worker = None;
        }
        if !open.revocations.is_empty() {
            self.message = "Revocation pending: waiting for an already-admitted operation. New requests and reviews are blocked.";
            return;
        }
        if open
            .pairing
            .as_ref()
            .is_some_and(|p| p.check_current().is_err())
        {
            open.invalidate_review();
            open.pairing = None;
            self.pending = None;
            self.message = "The paired process exited, expired or was revoked. Its current permission was discarded.";
        }
        #[cfg(feature = "authority-signing")]
        if open.witness_job.is_some() || open.host_continuity_worker.is_some() {
            return;
        }
        for _ in 0..8 {
            let Some(event) = open.ipc.next_event() else {
                break;
            };
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            if open.born_bridge_active
                && !matches!(
                    &event,
                    LocalEvent::BornOriginalHistoryV1 { .. } | LocalEvent::BornDispatchV1 { .. }
                )
            {
                drop(event);
                continue;
            }
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            if open.durable_delivery_entry.is_some()
                && !durable_delivery_admission_v2::allowed_event(&event)
            {
                self.message = "V2 admission-only entry denies every financial and ordinary route.";
                continue;
            }
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            if open.durable_born_entry.is_some() && !durable_review_v1::allowed_event(&event) {
                drop(event);
                self.message = "This fresh durable entry refuses legacy, V3, named, sponsor, automatic and recovery routes. No unsupported history was written.";
                continue;
            }
            match event {
                #[cfg(feature = "pending-birth-owner-signing")]
                LocalEvent::BornRosterCommonContextHandoffAuthorizationV1 { stream, .. }
                | LocalEvent::BornRosterCommonContextReentryV1 { stream, .. }
                | LocalEvent::BornRosterReenteredConstructionV1 { stream, .. } => {
                    // This is the ordinary account endpoint. The actual bounded
                    // original/completion owner services these variants through
                    // its own IPC in BornManualRosterUiV2; forwarding this
                    // wrong-channel request would substitute native provenance.
                    drop(stream);
                    self.message = "Common-context handoff requires its original read owner or freshly unlocked completion window and that window's exact paired channel.";
                }
                #[cfg(feature = "pending-birth-owner-signing")]
                LocalEvent::BornPermanentStopV1(request) => {
                    drop(request);
                    self.message = "Permanent-stop publication requires its separate actual born-source restriction window.";
                }
                #[cfg(feature = "pending-birth-owner-signing")]
                LocalEvent::BornManualRosterEnrollmentV2 { stream, .. }
                | LocalEvent::BornManualEnrollment { stream, .. }
                | LocalEvent::BornManualEnrollmentContinuationV2 { stream, .. }
                | LocalEvent::BornRosterInventoryV2 { stream, .. }
                | LocalEvent::BornRosterCandidateSelectionV2 { stream, .. }
                | LocalEvent::BornRosterExactInputObservationV1 { stream, .. }
                | LocalEvent::BornRosterConstructionV2 { stream, .. }
                | LocalEvent::BornRosterConstructionV3 { stream, .. }
                | LocalEvent::BornRosterCommonContextReadV1 { stream, .. }
                | LocalEvent::BornPreliminaryInventoryV1 { stream, .. }
                | LocalEvent::BornCandidateSelectionV1 { stream, .. } => {
                    drop(stream);
                    self.message = "Born manual enrollment admission requires its genuine original-born native window.";
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::AutomaticAuthorization {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.check_pairing().is_err()
                    {
                        continue;
                    }
                    // This request only refers to already-private artifact
                    // intake. It never installs a new pairing or replaces the
                    // artifact, wallet setup, grant or accepted manifest.
                    if self
                        .start_automatic_ipc(
                            AutomaticIpcDelivery {
                                peer,
                                stream,
                                request: *request,
                            },
                            epoch,
                        )
                        .is_err()
                    {
                        self.message = "The automatic request did not match current native scope and privately delivered artifact. No signing attempt was started.";
                    }
                    return;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::HostRecoveryPublication {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let (Some(session), Some(witness)) =
                        (open.session.clone(), open.witness.clone())
                    else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let source = open.authority.binding();
                    let _ = self.start_witness_job(epoch, move |cancelled| {
                        WitnessOutcome::HostPublicationPrepared(
                            if cancelled.load(Ordering::Acquire) {
                                Err(Error::Locked)
                            } else {
                                super::host_publication::PreparedHostPublication::prepare(
                                    *request, peer, stream, &journal, &session, source, witness,
                                )
                                .map(Box::new)
                            },
                        )
                    });
                    return;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::HostRecoveryPublicationV2 {
                    peer,
                    stream,
                    request,
                } => {
                    if crate::authority_bridge::host_recovery_ipc::v2::require_complete_origin_endpoint().is_err()
                        || self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let (Some(session), Some(witness)) =
                        (open.session.clone(), open.witness.clone())
                    else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let source = open.authority.binding();
                    let _ = self.start_witness_job(epoch, move |cancelled| {
                        WitnessOutcome::HostPublicationPreparedV2(
                            if cancelled.load(Ordering::Acquire) {
                                Err(Error::Locked)
                            } else {
                                super::host_publication::v2::PreparedHostPublicationV2::prepare(
                                    *request, peer, stream, &journal, &session, source, witness,
                                    cancelled,
                                )
                                .map(Box::new)
                            },
                        )
                    });
                    return;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::HostRecoveryPublicationV3 {
                    peer,
                    stream,
                    request,
                } => {
                    if crate::authority_bridge::host_recovery_ipc::v3::require_complete_origin_endpoint().is_err()
                        || self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let (Some(session), Some(witness)) =
                        (open.session.clone(), open.witness.clone())
                    else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let source = open.authority.binding();
                    let _ = self.start_witness_job(epoch, move |cancelled| {
                        WitnessOutcome::HostPublicationPreparedV3(
                            if cancelled.load(Ordering::Acquire) {
                                Err(Error::Locked)
                            } else {
                                super::host_publication::v3::PreparedHostPublicationV3::prepare(
                                    *request, peer, stream, &journal, &session, source, witness,
                                    cancelled,
                                )
                                .map(Box::new)
                            },
                        )
                    });
                    return;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::HostRecoveryPublicationV5 {
                    peer,
                    stream,
                    request,
                    transfer_dialect,
                } => {
                    if crate::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint().is_err()
                        || self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.history_workers.len() >= 8
                        || open.bind_host_recovery_v5(&peer).is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(witness) = open.witness.clone() else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let source = open.authority.binding();
                    let _ = self.start_witness_job(epoch, move |cancelled| {
                        WitnessOutcome::HostPublicationPreparedV5(
                            if cancelled.load(Ordering::Acquire) {
                                Err(Error::Locked)
                            } else {
                                super::host_publication::v5::PreparedHostPublicationV5::prepare(
                                    *request,
                                    peer,
                                    stream,
                                    &journal,
                                    source,
                                    witness,
                                    cancelled,
                                    transfer_dialect,
                                )
                                .map(Box::new)
                            },
                        )
                    });
                    return;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::HostRecoveryContinuity {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let (Some(session), Some(witness)) =
                        (open.session.clone(), open.witness.clone())
                    else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let source = open.authority.binding();
                    let _ = self.start_witness_job(epoch, move |cancelled| {
                        WitnessOutcome::HostContinuityPrepared(
                            if cancelled.load(Ordering::Acquire) {
                                Err(Error::Locked)
                            } else {
                                super::host_recovery::PreparedHostContinuity::prepare(
                                    *request, peer, stream, &journal, &session, source, witness,
                                )
                                .map(Box::new)
                            },
                        )
                    });
                    return;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::HostRecoveryContinuityV2 {
                    peer,
                    stream,
                    request,
                } => {
                    if crate::authority_bridge::host_recovery_ipc::v2::require_complete_origin_endpoint().is_err()
                        || self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let (Some(session), Some(witness)) =
                        (open.session.clone(), open.witness.clone())
                    else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let source = open.authority.binding();
                    let _ = self.start_witness_job(epoch, move |cancelled| {
                        WitnessOutcome::HostContinuityPreparedV2(
                            if cancelled.load(Ordering::Acquire) {
                                Err(Error::Locked)
                            } else {
                                super::host_recovery::v2::PreparedHostContinuityV2::prepare(
                                    *request, peer, stream, &journal, &session, source, witness,
                                    cancelled,
                                )
                                .map(Box::new)
                            },
                        )
                    });
                    return;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::HostRecoveryContinuityV3 {
                    peer,
                    stream,
                    request,
                } => {
                    if crate::authority_bridge::host_recovery_ipc::v3::require_complete_origin_endpoint().is_err()
                        || self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let (Some(session), Some(witness)) =
                        (open.session.clone(), open.witness.clone())
                    else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let source = open.authority.binding();
                    let _ = self.start_witness_job(epoch, move |cancelled| {
                        WitnessOutcome::HostContinuityPreparedV3(
                            if cancelled.load(Ordering::Acquire) {
                                Err(Error::Locked)
                            } else {
                                super::host_recovery::v3::PreparedHostContinuityV3::prepare(
                                    *request, peer, stream, &journal, &session, source, witness,
                                    cancelled,
                                )
                                .map(Box::new)
                            },
                        )
                    });
                    return;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::HostRecoveryContinuityV5 {
                    peer,
                    stream,
                    request,
                    transfer_dialect,
                } => {
                    if crate::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint().is_err()
                        || self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.history_workers.len() >= 8
                        || open.bind_host_recovery_v5(&peer).is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(witness) = open.witness.clone() else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let source = open.authority.binding();
                    let _ = self.start_witness_job(epoch, move |cancelled| {
                        WitnessOutcome::HostContinuityPreparedV5(
                            if cancelled.load(Ordering::Acquire) {
                                Err(Error::Locked)
                            } else {
                                super::host_recovery::v5::PreparedHostContinuityV5::prepare(
                                    *request,
                                    peer,
                                    stream,
                                    &journal,
                                    source,
                                    witness,
                                    cancelled,
                                    transfer_dialect,
                                )
                                .map(Box::new)
                            },
                        )
                    });
                    return;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::OwnerInspection {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.as_ref() else {
                        continue;
                    };
                    if let Ok(prepared) =
                        super::account_inspection::PreparedOwnerInspection::prepare(
                            *request,
                            peer,
                            stream,
                            &open.journal,
                            session,
                            &open.authority.binding(),
                            &open.vault,
                        )
                    {
                        if let Ok(display) = prepared.display() {
                            if let Ok(review) = ExactNativeReview::stage(
                                &open.authority,
                                prepared.digest(),
                                display,
                                epoch,
                            ) {
                                self.pending = Some(PendingDecision {
                                    review,
                                    operation: Operation::OwnerInspection(Box::new(prepared)),
                                });
                                self.message = "Review exact local account audit disclosure. Account-wide exposure and balances remain unknown; no financial action is enabled.";
                            }
                        }
                    }
                }
                #[cfg(not(feature = "authority-signing"))]
                LocalEvent::NamedVerifierPolicy { .. } => {
                    self.message = "Named-verifier disclosure is unavailable in this build.";
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::NamedVerifierPolicy {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.as_ref() else {
                        continue;
                    };
                    if let Ok(prepared) =
                        super::named_verifier_policy::PreparedNamedVerifierPolicy::prepare(
                            *request,
                            peer,
                            stream,
                            &open.journal,
                            session,
                            &open.authority,
                            &open.vault,
                        )
                    {
                        if let Ok(display) = prepared.display() {
                            if let Ok(review) = ExactNativeReview::stage(
                                &open.authority,
                                prepared.digest(),
                                display,
                                epoch,
                            ) {
                                self.pending = Some(PendingDecision {
                                    review,
                                    operation: Operation::NamedVerifierPolicy(Box::new(prepared)),
                                });
                                self.message = "Review exact named-verifier viewing disclosure. No construction or spending permission is requested.";
                            }
                        }
                    }
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::Preconstruction {
                    peer,
                    stream,
                    request,
                } => {
                    #[cfg(all(
                        feature = "durable-proposal",
                        feature = "pending-birth-owner-signing"
                    ))]
                    if durable_review_v1::check_plain_preconstruction(open, &request).is_err() {
                        continue;
                    }
                    if self.pending.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.as_ref() else {
                        continue;
                    };
                    if let Ok(prepared) = super::preconstruction::PreparedPreconstruction::prepare(
                        *request,
                        peer,
                        stream,
                        &open.journal,
                        session,
                        &open.authority.binding(),
                        &open.vault,
                        open.witness.clone(),
                    ) {
                        if let Ok(display) = prepared.display() {
                            if let Ok(review) = ExactNativeReview::stage(
                                &open.authority,
                                prepared.digest(),
                                display,
                                epoch,
                            ) {
                                self.pending = Some(PendingDecision {
                                    review,
                                    operation: Operation::Preconstruction(Box::new(prepared)),
                                });
                                self.message = "Review dedicated-account viewing disclosure. A viewing-key disclosure permanently reveals this account's viewing capability to the named local constructor.";
                            }
                        }
                    }
                }
                #[cfg(feature = "durable-proposal")]
                LocalEvent::DurableConstructionV1 {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.as_ref() else {
                        continue;
                    };
                    if let Ok(prepared) =
                        super::durable_construction_v1::PreparedDurableConstructionV1::prepare(
                            *request,
                            peer,
                            stream,
                            &open.journal,
                            session,
                            &open.authority.binding(),
                            &open.vault,
                        )
                    {
                        if let Ok(display) = prepared.display() {
                            if let Ok(review) = ExactNativeReview::stage(
                                &open.authority,
                                prepared.digest(),
                                display,
                                epoch,
                            ) {
                                self.pending = Some(PendingDecision {
                                    review,
                                    operation: Operation::DurableConstructionV1(Box::new(prepared)),
                                });
                                self.message = "Review exact durable construction disclosure and retention. This shares viewing material with the named constructor; it grants no spending permission.";
                            }
                        }
                    }
                }
                #[cfg(feature = "durable-proposal")]
                LocalEvent::DurableConstructionHistoryV1 {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.clone() else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let worker = std::thread::spawn(move || {
                        let _ =
                            super::durable_construction_v1::serve_durable_construction_history_v1(
                                stream, peer, *request, &journal, &session,
                            );
                    });
                    open.disclosure_worker_ids.insert(worker.thread().id());
                    open.history_workers.push(worker);
                    self.message = "Checking only the exact retained construction disclosure for its original authenticated recipient. No permission or validity window is being renewed.";
                }
                #[cfg(feature = "durable-proposal")]
                LocalEvent::DurableConstructionRedisclosureV1 {
                    peer,
                    stream,
                    request,
                } => {
                    #[cfg(feature = "pending-birth-owner-signing")]
                    if open.durable_delivery_entry.is_some() {
                        let _ = durable_delivery_observe_v2!(
                            DeliveryRedisclosurePrepare,
                            self.prepare_durable_delivery_redisclosure_v2(
                                stream, peer, *request, epoch,
                            )
                        );
                        return;
                    }

                    if self.pending.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.as_ref() else {
                        continue;
                    };
                    if let Ok(prepared) = super::durable_construction_v1::PreparedDurableConstructionV1::prepare_redisclosure(
                        *request, peer, stream, &open.journal, session,
                        &open.authority.binding(), &open.vault,
                    ) {
                        if let Ok(display) = prepared.display() {
                            if let Ok(review) = ExactNativeReview::stage(
                                &open.authority, prepared.digest(), display, epoch,
                            ) {
                                self.pending = Some(PendingDecision {
                                    review,
                                    operation: Operation::DurableConstructionV1(Box::new(prepared)),
                                });
                                self.message = "Review a NEW privacy disclosure of exactly retained construction material to this current paired process. Old permission is not restored; no spending is authorized.";
                            }
                        }
                    }
                }
                #[cfg(feature = "durable-proposal")]
                LocalEvent::DurableDeliveryV2 {
                    stream,
                    peer,
                    request,
                } => {
                    #[cfg(feature = "pending-birth-owner-signing")]
                    let _ = self.handle_durable_delivery_v2(stream, peer, *request, epoch);
                    #[cfg(feature = "pending-birth-owner-signing")]
                    return;
                }
                #[cfg(feature = "durable-proposal")]
                LocalEvent::DurableProposalReviewV1 {
                    peer,
                    stream,
                    request,
                } => {
                    #[cfg(feature = "pending-birth-owner-signing")]
                    if self
                        .open
                        .as_ref()
                        .is_some_and(|o| o.durable_delivery_entry.is_some())
                    {
                        let _ = durable_delivery_observe_v2!(
                            DeliveryArtifactImportStart,
                            self.start_durable_delivery_import_v2(stream, peer, *request, epoch)
                        );
                    } else {
                        let _ = self.start_durable_import_v1(stream, peer, *request, epoch);
                    }
                    return;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::ProvedDisclosure {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.as_ref() else {
                        continue;
                    };
                    if let Ok(prepared) =
                        super::proved_disclosure::PreparedProvedDisclosure::prepare(
                            *request,
                            peer,
                            stream,
                            &open.journal,
                            session,
                            &open.authority.binding(),
                            &open.vault,
                        )
                    {
                        if let Ok(display) = prepared.display() {
                            if let Ok(review) = ExactNativeReview::stage(
                                &open.authority,
                                prepared.digest(),
                                display,
                                epoch,
                            ) {
                                self.pending = Some(PendingDecision {
                                    review,
                                    operation: Operation::ProvedDisclosure(Box::new(prepared)),
                                });
                                self.message = "Review separate exact proved-artifact disclosure to the listed installed signer recipients. Proving does not redact sensitive material.";
                            }
                        }
                    }
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::Settlement {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let (Some(session), Some(witness)) =
                        (open.session.as_ref(), open.witness.clone())
                    else {
                        continue;
                    };
                    let result = super::resolution_workspace::PreparedResolution::observe(
                        &request.history.authorization_id,
                        &request.dispatch_operation_id,
                        &self.resolution_source_reference,
                        &open.journal,
                        session,
                        witness,
                        &open.authority,
                    )
                    .and_then(|prepared| {
                        prepared.bind_ipc(*request, peer, stream, &open.journal, session)
                    });
                    if let Ok(prepared) = result {
                        if let Ok(display) = prepared.display() {
                            if let Ok(review) = ExactNativeReview::stage(
                                &open.authority,
                                prepared.digest(),
                                display,
                                epoch,
                            ) {
                                self.pending = Some(PendingDecision {
                                    review,
                                    operation: Operation::Resolution(Box::new(prepared)),
                                });
                                self.message = "Review the exact retained authorization and independent node disclosure. The app cannot supply resolution evidence or enroll a source.";
                            }
                        }
                    }
                }
                #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
                LocalEvent::BornOriginalHistoryV1 {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let (Some(session), Some(witness), Some(profile)) = (
                        open.session.clone(),
                        open.witness.clone(),
                        self.named_recipient.live_profile(),
                    ) else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let authority = open.authority.binding();
                    let cancelled = Arc::new(AtomicBool::new(false));
                    let cancellation = cancelled.clone();
                    let done = Arc::new(AtomicBool::new(false));
                    let complete = done.clone();
                    let (send, receive) = std::sync::mpsc::sync_channel(1);
                    std::thread::spawn(move || {
                        let _finished = WorkerCompletion(complete);
                        let result = super::born_history::PreparedBornHistoryV1::prepare(
                            *request,
                            profile,
                            peer,
                            stream,
                            &journal,
                            &session,
                            &authority,
                            &witness,
                            cancellation,
                        )
                        .map(Box::new);
                        let _ = send.send(WitnessOutcome::BornHistoryPrepared(result));
                    });
                    open.born_bridge_active = true;
                    open.witness_job = Some(WitnessJob {
                        #[cfg(all(
                            feature = "synthetic-born-joined-qualification",
                            feature = "durable-proposal"
                        ))]
                        flow: None,
                        receive,
                        done,
                        cancelled,
                        epoch,
                    });
                    self.message = "Preparing purpose-distinct original born evidence for separate exact native review. Lock and blur revoke new admission immediately.";
                    break;
                }
                #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
                LocalEvent::BornDispatchV1 {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.wallet_job.is_some()
                        || open.witness_job.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let (Some(session), Some(witness), Some(profile)) = (
                        open.session.clone(),
                        open.witness.clone(),
                        self.named_recipient.live_profile(),
                    ) else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    let authority = open.authority.binding();
                    let cancelled = Arc::new(AtomicBool::new(false));
                    let cancellation = cancelled.clone();
                    let done = Arc::new(AtomicBool::new(false));
                    let complete = done.clone();
                    let (send, receive) = std::sync::mpsc::sync_channel(1);
                    std::thread::spawn(move || {
                        let _finished = WorkerCompletion(complete);
                        let result = super::born_dispatch::PreparedBornDispatchV1::prepare(
                            *request,
                            profile,
                            peer,
                            stream,
                            &journal,
                            &session,
                            &authority,
                            &witness,
                            cancellation,
                        )
                        .map(Box::new);
                        let _ = send.send(WitnessOutcome::BornDispatchPrepared(result));
                    });
                    open.born_bridge_active = true;
                    open.witness_job = Some(WitnessJob {
                        #[cfg(all(
                            feature = "synthetic-born-joined-qualification",
                            feature = "durable-proposal"
                        ))]
                        flow: None,
                        receive,
                        done,
                        cancelled,
                        epoch,
                    });
                    self.message = "Preparing purpose-distinct original born evidence for separate exact native review. Lock and blur revoke new admission immediately.";
                    break;
                }
                #[cfg(feature = "authority-signing")]
                LocalEvent::Dispatch {
                    peer,
                    stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let (Some(session), Some(witness)) =
                        (open.session.clone(), open.witness.clone())
                    else {
                        continue;
                    };
                    if open.wallet_job.is_some() || open.witness_job.is_some() {
                        continue;
                    }
                    let journal = open.journal.clone();
                    let authority = open.authority.binding();
                    let cancelled = Arc::new(AtomicBool::new(false));
                    let cancellation = cancelled.clone();
                    let done = Arc::new(AtomicBool::new(false));
                    let complete = done.clone();
                    let (send, receive) = std::sync::mpsc::sync_channel(1);
                    std::thread::spawn(move || {
                        let _finished = WorkerCompletion(complete);
                        let result = if cancellation.load(Ordering::Acquire) {
                            Err(Error::Locked)
                        } else {
                            super::dispatch::PreparedDispatch::prepare(
                                *request, peer, stream, &journal, &session, &authority, &witness,
                            )
                            .map(Box::new)
                        };
                        let _ = send.send(WitnessOutcome::DispatchPrepared(result));
                    });
                    open.witness_job = Some(WitnessJob {
                        #[cfg(all(
                            feature = "synthetic-born-joined-qualification",
                            feature = "durable-proposal"
                        ))]
                        flow: None,
                        receive,
                        done,
                        cancelled,
                        epoch,
                    });
                    self.message = "Preparing exact dispatch disclosure from signer-owned originals and authenticated witness state. Lock remains available.";
                    break;
                }
                LocalEvent::Redelivery {
                    peer,
                    mut stream,
                    request,
                } => {
                    if self.pending.is_some()
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.as_ref() else {
                        continue;
                    };
                    match crate::authority_bridge::ipc::existing_redelivery_reference(
                        &open.journal,
                        session,
                        &peer,
                        &request,
                    ) {
                        Ok(Some(reference)) => {
                            let _ = crate::authority_bridge::ipc::send_redelivery_reference(
                                &mut stream,
                                &reference,
                            );
                            continue;
                        }
                        Err(_) => continue,
                        Ok(None) => {}
                    }
                    let prepared = (|| -> Result<_> {
                        peer.check_current()?;
                        let transport =
                            AuthenticatedTransportIdentity::from_native(open.check_pairing()?)?;
                        let prepared = open
                            .session
                            .as_ref()
                            .ok_or(Error::Locked)?
                            .prepare_result_redelivery(&open.journal, transport, request)?;
                        let review = ExactNativeReview::stage(
                            &open.authority,
                            prepared.review_digest(),
                            prepared.display()?.to_string(),
                            epoch,
                        )?;
                        Ok((prepared, review))
                    })();
                    if let Ok((prepared, review)) = prepared {
                        self.pending = Some(PendingDecision {
                            review,
                            operation: Operation::Redelivery {
                                prepared: Box::new(prepared),
                                peer: Box::new(peer),
                                stream,
                            },
                        });
                        self.message = "Review the exact retained signature redelivery and its new local recipient. No signing or exposure release occurs.";
                    }
                }
                LocalEvent::Redelivered {
                    peer,
                    stream,
                    history,
                    redelivery,
                    history_only,
                } => {
                    if open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.clone() else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    open.history_workers.push(std::thread::spawn(move || {
                        if history_only {
                            let _ = crate::authority_bridge::ipc::serve_history(
                                stream,
                                peer,
                                history,
                                Some(redelivery),
                                &journal,
                                &session,
                            );
                        } else {
                            let _ = crate::authority_bridge::ipc::serve_authorization_result(
                                stream,
                                peer,
                                history,
                                Some(redelivery),
                                &journal,
                                &session,
                            );
                        }
                    }));
                }
                LocalEvent::Pairing(pair) => {
                    if self.pending.is_some()
                        || pair.scope.account_id != open.vault.account_id().unwrap_or_default()
                    {
                        continue;
                    }
                    let display = format!(
                        "PAIR LOCAL PROCESS\nUnverified application label: {}\nObserved Unix UID: {}\nObserved process PID: {}\nSigner process-instance binding: {}\nAccount: {}\nAgreement: {}\nParticipant association you are choosing: {}\nExact manifest: {}\nBase scope: status and transaction-review requests. No approval, unlock or private keys. Separately requested history and retained-signature delivery scopes are shown below.\nExpires in 15 minutes; Lock, process exit, explicit revoke and signer exit revoke it.\nThis does not authenticate a software publisher, remote HPKE key or real-world participant.",
                        pair.label,
                        pair.uid(),
                        pair.pid(),
                        pair.instance(),
                        pair.scope.account_id,
                        pair.scope.agreement_id,
                        pair.scope.participant_id,
                        pair.scope.manifest_digest
                    );
                    let display = format!(
                        "{display}\nRead original authorization history for this exact scope: {}",
                        if pair.scope.history_read {
                            "YES: original enrollment, accepted manifest, consent and release metadata; no FVK, PCZT or signatures"
                        } else {
                            "NO"
                        }
                    );
                    let display = format!(
                        "{display}\nDeliver already-retained exact signatures to this same local process: {}",
                        if pair.scope.authorization_export {
                            "YES, only this original grant, exact scope and process lifetime"
                        } else {
                            "NO"
                        }
                    );
                    let display = format!(
                        "{display}\nRequest dedicated-account viewing-key disclosure for private construction: {}",
                        if pair.scope.preconstruction_export {
                            "YES: every disclosure still requires its separate exact native review; viewing-key disclosure cannot be recalled"
                        } else {
                            "NO"
                        }
                    );
                    if let Ok(digest) = pair.review_digest(open.ipc.generation()) {
                        if let Ok(review) =
                            ExactNativeReview::stage(&open.authority, &digest, display, epoch)
                        {
                            self.pending = Some(PendingDecision {
                                review,
                                operation: Operation::Pair(Box::new(pair)),
                            });
                        }
                    }
                }
                LocalEvent::Export {
                    peer,
                    stream,
                    history,
                } => {
                    if open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || !peer.scope.authorization_export
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.clone() else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    open.history_workers.push(std::thread::spawn(move || {
                        let _ = crate::authority_bridge::ipc::serve_original_authorization_result(
                            stream, peer, history, &journal, &session,
                        );
                    }));
                }
                LocalEvent::History {
                    peer,
                    stream,
                    history,
                } => {
                    if open.history_workers.len() >= 8
                        || open.check_pairing().is_err()
                        || !peer.scope.history_read
                        || open
                            .pairing
                            .as_ref()
                            .is_none_or(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    let Some(session) = open.session.clone() else {
                        continue;
                    };
                    let journal = open.journal.clone();
                    open.history_workers.push(std::thread::spawn(move || {
                        let _ = crate::authority_bridge::ipc::serve_original_history(
                            stream, peer, history, &journal, &session,
                        );
                    }));
                }
                LocalEvent::Request { peer, request } => {
                    if peer.scope.account_id != open.vault.account_id().unwrap_or_default() {
                        continue;
                    }
                    if open
                        .pairing
                        .as_ref()
                        .is_some_and(|p| p.peer.grant_id != peer.grant_id)
                    {
                        continue;
                    }
                    if open.pairing.is_none() {
                        if let Ok(pairing) = AuthenticatedPairing::from_authenticated_request(peer)
                        {
                            open.pairing = Some(pairing);
                            if open.refresh_session().is_err() {
                                open.pairing = None;
                            }
                        }
                    }
                    #[cfg(feature = "authority-signing")]
                    if let crate::ipc::AppRequest::RequestReview { pczt_hex, .. } = &request {
                        if self.pending.is_none() && open.wallet_job.is_none() {
                            self.incoming_pczt = hex::decode(pczt_hex).ok().map(Zeroizing::new);
                        }
                    }
                    self.message = match request {
                        #[cfg(feature = "pending-birth-owner-signing")]
                        crate::ipc::AppRequest::RequestBornRosterCommonContextHandoffAuthorizationV1 { .. }
                        | crate::ipc::AppRequest::RequestBornRosterCommonContextReentryV1 { .. }
                        | crate::ipc::AppRequest::RequestBornRosterReenteredConstructionV1 { .. } => {
                            "Common-context handoff requires its original read owner or freshly unlocked completion window and that window's exact paired channel."
                        }
                        #[cfg(feature = "pending-birth-owner-signing")]
                        crate::ipc::AppRequest::RequestBornManualRosterEnrollmentIntentV2 {
                            ..
                        }
                        | crate::ipc::AppRequest::RequestBornManualRosterEnrollmentV2 { .. }
                        | crate::ipc::AppRequest::RequestBornPermanentStopV1 { .. }
                        | crate::ipc::AppRequest::RequestBornManualEnrollmentIntent { .. }
                        | crate::ipc::AppRequest::RequestBornManualEnrollment { .. }
                        | crate::ipc::AppRequest::RequestBornRosterInventoryV2 { .. }
                        | crate::ipc::AppRequest::RequestBornRosterExactInputObservationV1 {
                            ..
                        }
                        | crate::ipc::AppRequest::RequestBornRosterConstructionV2 { .. }
                        | crate::ipc::AppRequest::RequestBornRosterConstructionV3 { .. }
                        | crate::ipc::AppRequest::RequestBornRosterCommonContextReadV1 { .. }
                        | crate::ipc::AppRequest::RequestBornRosterCandidateSelectionV2 {
                            ..
                        }
                        | crate::ipc::AppRequest::RequestBornPreliminaryInventoryV1 { .. }
                        | crate::ipc::AppRequest::RequestBornCandidateSelectionV1 { .. }
                        | crate::ipc::AppRequest::RequestBornManualEnrollmentContinuationV2 {
                            ..
                        } => {
                            "Born manual enrollment requires its separate original-born native owner window."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestAutomaticAuthorization { .. } => {
                            "Automatic authorization requires its original authenticated two-phase channel and a separate exact native privacy decision."
                        }
                        crate::ipc::AppRequest::RequestResultRedelivery { .. }
                        | crate::ipc::AppRequest::RetrieveRedeliveredAuthorization { .. }
                        | crate::ipc::AppRequest::AcquireRedeliveredAuthorization { .. } => {
                            "Redelivery requires its separate exact native review and authenticated channel."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestHostRecoveryPublication { .. } => {
                            "Restricted host generation publication requires its distinct exact native review. It grants no financial authority or continuing signer fence."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestHostRecoveryPublicationV2 { .. } => {
                            "Restricted host generation publication requires its distinct exact native review. It grants no financial authority or continuing signer fence."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestHostRecoveryContinuity { .. } => {
                            "Host recovery continuity requires separate native account-wide disclosure and a surviving current signer/witness session."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestHostRecoveryContinuityV3 { .. } => {
                            "Construction-complete continuity remains unavailable pending native qualification; saved history grants no authority."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestHostRecoveryContinuityV5 { .. } => {
                            "Transport-complete V5 continuity remains unavailable pending native qualification; saved history grants no authority."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestHostRecoveryPublicationV3 { .. } => {
                            "Construction-complete informational publication remains unavailable; financial activation is unsupported."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestHostRecoveryPublicationV5 { .. } => {
                            "Transport-complete V5 informational publication remains unavailable; financial activation is unsupported."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestHostRecoveryContinuityV2 { .. } => {
                            "Host recovery continuity requires separate native account-wide disclosure and a surviving current signer/witness session."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestSettlement { .. } => {
                            "Settlement requires a separate exact native decision and independently enrolled sources."
                        }
                        #[cfg(all(feature="authority-signing",feature="offline-review-foundation"))]
                        crate::ipc::AppRequest::RequestBornOriginalHistoryV1{..}|crate::ipc::AppRequest::RequestBornDispatchV1{..}=>{"Born history and dispatch require their separate exact native decisions; the pairing grant is not authority."}
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestDispatch { .. } => {
                            "Dispatch requires a separate exact native decision."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestProvedDisclosure { .. } => {
                            "Proved artifact disclosure requires its own exact native privacy decision."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestOwnerInspection { .. } => { "Account inspection requires a separate native metadata-disclosure decision." }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestNamedVerifierPolicyV1 { .. } => {
                            "Named-verifier viewing disclosure requires its own exact native decision."
                        }
                        #[cfg(feature = "authority-signing")]
                        crate::ipc::AppRequest::RequestPreconstruction { .. } => {
                            "Viewing export requires its own exact native disclosure decision."
                        }
                        #[cfg(feature = "durable-proposal")]
                        crate::ipc::AppRequest::RequestDurableConstructionV1 { .. }
                        | crate::ipc::AppRequest::RequestDurableConstructionHistoryV1 { .. }
                        | crate::ipc::AppRequest::RequestDurableConstructionRedisclosureV1 { .. } => {
                            "Durable construction uses its separate exact native disclosure and original-recipient history channel; a request grants no spending authority."
                        }
                        #[cfg(feature = "durable-proposal")]
                        crate::ipc::AppRequest::RequestDurableProposalReviewV1 { .. }
                        | crate::ipc::AppRequest::RequestDurableDeliveryV2 { .. } => {
                            "Exact durable proposal import requires its separate authenticated metadata handshake; received data is not native spending permission."
                        }
                        crate::ipc::AppRequest::Status {} => {
                            "The native-approved local process proved current channel-key possession. You can now prepare enrollment."
                        }
                        crate::ipc::AppRequest::RetrieveAuthorization { .. } => {
                            "Signature retrieval requires its separately approved original-recipient channel."
                        }
                        crate::ipc::AppRequest::AcquireOriginalAuthorization { .. } => {
                            "History requests require their separate authenticated leased channel."
                        }
                        crate::ipc::AppRequest::RequestReview { .. } => {
                            "Transaction request received. Exact spend review additionally requires signer-local wallet selection and verification; a request alone grants no consent."
                        }
                    };
                }
            }
        }
    }
    fn stage_enrollment(&mut self, epoch: u64) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        if open.session.is_none() {
            open.refresh_session()?;
        }
        let paired = open.check_pairing()?;
        let input: ProposalInput = wholepact_core::parse_typed_json(self.proposal.as_bytes())
            .map_err(|_| Error::InvalidData)?;
        let proposal = Proposal::validate(input).map_err(|_| Error::Verification)?;
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        durable_review_v1::check_plain_proposal(open, &proposal)?;
        if proposal.manifest_digest() != paired.peer.scope.manifest_digest
            || proposal.manifest().agreement.agreement_id != paired.agreement_id()
        {
            return Err(Error::Verification);
        }
        let budget: u64 = self.budget.parse().map_err(|_| Error::InvalidData)?;
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if open.durable_born_entry.as_ref().is_some_and(|source| {
            budget
                > source
                    .record()
                    .account_record
                    .terms
                    .scope
                    .aggregate_budget_zatoshis
        }) {
            return Err(Error::ReviewMismatch);
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if open.durable_delivery_entry.as_ref().is_some_and(|source| {
            budget
                > source
                    .record()
                    .account_record
                    .terms
                    .scope
                    .aggregate_budget_zatoshis
        }) {
            return Err(Error::ReviewMismatch);
        }
        let transport = AuthenticatedTransportIdentity::from_native(paired)?;
        let prepared = open
            .session
            .as_ref()
            .ok_or(Error::Locked)?
            .prepare_enrollment(
                open.vault.account(),
                &proposal,
                transport,
                EnrollmentRequest {
                    participant_id: paired.participant_id().into(),
                    aggregate_budget_limit_zatoshis: budget,
                },
            )?;
        let display = format!(
            "ENROLL EXACT ACCOUNT AND LOCAL PROCESS\n{}\n\nCOMPLETE PROPOSAL\n{}\n\nThis grants a bounded local account association, not spending authorization or remote participant identity.",
            serde_json::to_string_pretty(prepared.record()).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(proposal.input()).map_err(|_| Error::InvalidData)?
        );
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                prepared.review_digest(),
                display,
                epoch,
            )?,
            operation: Operation::Enroll(Box::new(prepared)),
        });
        Ok(())
    }
    fn stage_manifest(&mut self, epoch: u64) -> Result<()> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        open.check_pairing()?;
        let input: ProposalInput = wholepact_core::parse_typed_json(self.proposal.as_bytes())
            .map_err(|_| Error::InvalidData)?;
        let proposal = Proposal::validate(input).map_err(|_| Error::Verification)?;
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        durable_review_v1::check_plain_proposal(open, &proposal)?;
        let prepared = open
            .session
            .as_ref()
            .ok_or(Error::Locked)?
            .prepare_manifest(
                open.enrollment.as_ref().ok_or(Error::ReviewMismatch)?,
                &proposal,
            )?;
        let display = format!(
            "ACCEPT EXACT IMMUTABLE MANIFEST\n{}\n\nThis accepts the displayed arrangement; it does not sign or submit a payment.",
            serde_json::to_string_pretty(prepared.record()).map_err(|_| Error::InvalidData)?
        );
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                prepared.review_digest(),
                display,
                epoch,
            )?,
            operation: Operation::Manifest(Box::new(prepared)),
        });
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn stage_spend(
        &mut self,
        bytes: Zeroizing<Vec<u8>>,
        inputs: crate::manifest::ReviewInputs,
        head: wholepact_authority::AuthorityHead,
        epoch: u64,
    ) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        open.check_pairing()?;
        let authorization_id = format!("native-{}", hex::encode(crate::vault::random::<24>()?));
        let manifest = open.manifest.as_ref().ok_or(Error::ReviewMismatch)?;
        let candidate_id = manifest.proposal_input().proposal_id.clone();
        let prepared = open.session.as_ref().ok_or(Error::Locked)?.prepare_spend(
            open.enrollment.as_ref().ok_or(Error::ReviewMismatch)?,
            manifest,
            open.vault.account(),
            &bytes,
            &inputs,
            &authorization_id,
        )?;
        let prepared = open
            .journal
            .bind_spend_sponsor(prepared, open.session.as_ref().ok_or(Error::Locked)?)?;
        let witness = open.witness.as_ref().ok_or(Error::Locked)?;
        witness.check_current()?;
        let disclosure = WitnessDisclosureReview::new(witness.client(), &prepared, head.clone())
            .map_err(|_| Error::Verification)?;
        let review = ExactNativeReview::stage(
            &open.authority,
            disclosure.review_digest(),
            disclosure.display().into(),
            epoch,
        )?;
        self.pending = Some(PendingDecision {
            review,
            operation: Operation::Disclosure {
                flow: Box::new(SpendFlow {
                    prepared,
                    inputs,
                    bytes,
                    head,
                    candidate_id,
                }),
                review: Box::new(disclosure),
            },
        });
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn stage_automatic_spend(
        &mut self,
        bytes: Zeroizing<Vec<u8>>,
        inputs: crate::manifest::ReviewInputs,
        active: wholepact_authority::AuthenticatedWriterSession,
        grant_id: &str,
        delivery: Option<AutomaticIpcDelivery>,
        epoch: u64,
    ) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?;
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        let grant = open
            .journal
            .automation_grant(grant_id, session)?
            .ok_or(Error::ReviewMismatch)?;
        let manifest = open.manifest.as_ref().ok_or(Error::ReviewMismatch)?;
        let candidate_id = manifest.proposal_input().proposal_id.clone();
        if let Some(delivery) = &delivery {
            Self::check_automatic_delivery(open, delivery, &bytes)?;
            if delivery.request.grant_id != grant_id {
                return Err(Error::ReviewMismatch);
            }
        }
        // Stable exact request identity: repeated delivery is never a fresh attempt.
        let authorization_id =
            super::automatic_ipc::authorization_id(grant_id, &candidate_id, &bytes)?;
        if let Some(original) = open
            .journal
            .original_authorization(&authorization_id, session)?
        {
            let retained = authority_bridge::automation::retained_automatic_commit(
                &open.journal,
                session,
                &authorization_id,
            );
            let state = match retained {
                Ok(Some(commit)) => {
                    self.last_receipt = Some(commit.original_consent_ref);
                    "Original result retained; exposure remains until independent canonical resolution."
                }
                _ => {
                    "Original attempt outcome is uncertain; reconcile existing history and preserve exposure."
                }
            };
            self.automation.status = Some(Zeroizing::new(format!(
                "{}\nOriginal authorization already retained. Authorization ID: {}\nOriginal consent: {}\nNo second signature attempt was made. The authenticated original application can use RetrieveAuthorization/AcquireOriginalAuthorization. A changed recipient must request exact native result redelivery through RequestResultRedelivery. Uncertain attempts require reconciliation; exposure remains.",
                state,
                authorization_id,
                original.original_consent().reference()
            )));
            self.message = "Original automatic attempt found. Inspect its retained status and use original-result retrieval or separately approved redelivery; no second signing attempt was started.";
            if let Some(delivery) = delivery {
                Self::queue_automatic_history(open, delivery, authorization_id)?;
            }
            return Ok(());
        }
        let prepared = session.prepare_spend(
            open.enrollment.as_ref().ok_or(Error::ReviewMismatch)?,
            manifest,
            open.vault.account(),
            &bytes,
            &inputs,
            &authorization_id,
        )?;
        let prepared = open.journal.bind_spend_sponsor(prepared, session)?;
        let ticket = open.wallet.as_mut().ok_or(Error::Locked)?.take_ticket()?;
        let verified = authority_bridge::automation::VerifiedAutomaticRequest::verify(
            &grant,
            &prepared,
            open.check_pairing()?,
            &bytes,
            &inputs,
            &ticket,
            &active,
        )
        .map_err(|_| Error::Verification)?;
        let head = verified.witness_head().clone();
        let approval =
            session.derive_automatic_spend(&open.journal, prepared, &grant, &verified)?;
        let witness = open.witness.as_ref().ok_or(Error::Locked)?;
        let disclosure =
            WitnessDisclosureReview::new_automatic(witness.client(), &approval, head.clone())
                .map_err(|_| Error::Verification)?;
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                disclosure.review_digest(),
                disclosure.display().into(),
                epoch,
            )?,
            operation: Operation::AutomaticDisclosure {
                flow: Box::new(AutomaticFlow {
                    approval,
                    inputs,
                    bytes,
                    head,
                    candidate_id,
                    ticket,
                    verified,
                    grant,
                    delivery,
                }),
                review: Box::new(disclosure),
            },
        });
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn stage_wallet_setup(&mut self, epoch: u64) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }

        let open = self.open.as_ref().ok_or(Error::Locked)?;
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if let Some(source) = &open.durable_born_entry {
            // Preserve the same owner's partial scan state. Replacement needs
            // explicit close and a fresh owner/setup, never a cache reset or an
            // ordinary born-vault storage fallback.
            if self.pending.is_some()
                || open.wallet.is_some()
                || open.wallet_job.is_some()
                || open.durable_wallet_job.is_some()
            {
                return Err(Error::Locked);
            }
            let prepared = super::wallet_workspace::durable_born_workspace_v1::PreparedDurableBornWalletSetupV1::prepare(
                &self.wallet_setup,
                source.clone(),
                &open.authority,
            )?;
            self.pending = Some(PendingDecision {
                review: ExactNativeReview::stage(
                    &open.authority,
                    prepared.digest(),
                    prepared.display()?,
                    epoch,
                )?,
                operation: Operation::DurableBornWalletV1(Box::new(prepared)),
            });
            return Ok(());
        }
        let prepared =
            PreparedWalletSetup::prepare(&self.wallet_setup, &open.vault, &open.authority)?;
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                prepared.digest(),
                prepared.display()?,
                epoch,
            )?,
            operation: Operation::Wallet(Box::new(prepared)),
        });
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn stage_resolution(&mut self, kind: u8, epoch: u64) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        open.check_pairing()?;
        if self.pending.is_some() || open.wallet_job.is_some() || open.witness_job.is_some() {
            return Err(Error::Locked);
        }
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        if kind == 1 {
            let json = self.witness_resolution_setup.to_string();
            let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
            let native = open.authority.binding();
            return self.start_witness_job(epoch, move |cancelled| {
                WitnessOutcome::ResolutionPrepared(if cancelled.load(Ordering::Acquire) {
                    Err(Error::Locked)
                } else {
                    super::resolution_workspace::PreparedResolution::owner(&json, owner, native)
                        .map(Box::new)
                })
            });
        }
        let prepared = if kind == 0 {
            super::resolution_workspace::PreparedResolution::signer(
                &self.resolution_setup,
                &open.journal,
                session,
                &open.authority,
            )?
        } else {
            super::resolution_workspace::PreparedResolution::observe(
                &self.resolution_authorization,
                &self.resolution_dispatch,
                &self.resolution_source_reference,
                &open.journal,
                session,
                open.witness.clone().ok_or(Error::Locked)?,
                &open.authority,
            )?
        };
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                prepared.digest(),
                prepared.display()?,
                epoch,
            )?,
            operation: Operation::Resolution(Box::new(prepared)),
        });
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn stage_witness_setup(&mut self, epoch: u64) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }

        let open = self.open.as_ref().ok_or(Error::Locked)?;
        if open.writer_retry.is_some() || open.writer_receipt.is_some() {
            return Err(Error::Locked);
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        durable_review_v1::check_selected_witness_setup(open, &self.witness_setup)?;
        let prepared =
            PreparedWitnessSetup::prepare(&self.witness_setup, &open.vault, &open.authority)?;
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                prepared.digest(),
                prepared.display()?,
                epoch,
            )?,
            operation: Operation::Witness(Box::new(prepared)),
        });
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn stage_owner_witness_setup(&mut self, epoch: u64) -> Result<()> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        if open.activation_retry.is_some() {
            return Err(Error::Locked);
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        durable_review_v1::check_selected_witness_setup(open, &self.owner_witness_setup)?;
        let prepared =
            PreparedWitnessSetup::prepare(&self.owner_witness_setup, &open.vault, &open.authority)?;
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                prepared.digest(),
                format!("SEPARATE OWNER-CONTROL CLIENT\n{}", prepared.display()?),
                epoch,
            )?,
            operation: Operation::OwnerWitness(Box::new(prepared)),
        });
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn start_witness_job(
        &mut self,
        epoch: u64,
        work: impl FnOnce(Arc<AtomicBool>) -> WitnessOutcome + Send + 'static,
    ) -> Result<()> {
        self.start_witness_job_inner(
            epoch,
            work,
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            ))]
            None,
        )
    }
    #[cfg(feature = "authority-signing")]
    fn start_witness_job_inner(
        &mut self,
        epoch: u64,
        work: impl FnOnce(Arc<AtomicBool>) -> WitnessOutcome + Send + 'static,
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        observation: Option<(
            flow_diag_v1::DurableFlowObserverV1,
            flow_diag_v1::DurableFlowJobPurposeV1,
            flow_diag_v1::DurableFlowStageV1,
        )>,
    ) -> Result<()> {
        if self.pending.is_some() {
            return Err(Error::Locked);
        }
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?;
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        durable_review_v1::check_configured_witnesses(open)?;
        if open.wallet_job.is_some() || open.witness_job.is_some() {
            return Err(Error::Locked);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = cancelled.clone();
        let done = Arc::new(AtomicBool::new(false));
        let complete = done.clone();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        let flow = observation.map(|(observer, purpose, stage)| {
            (observer.job_start(purpose, epoch), observer, stage)
        });
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        let worker_flow = flow.clone();
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Some((job, observer, _)) = &flow {
            let point = match job.purpose() {
                Some(flow_diag_v1::DurableFlowJobPurposeV1::AcquirePrepare) => {
                    Some(flow_diag_v1::DurableLifecyclePointV1::AcquirePrepareLaunch)
                }
                Some(flow_diag_v1::DurableFlowJobPurposeV1::Acquire) => {
                    Some(flow_diag_v1::DurableLifecyclePointV1::AcquireWorkerLaunch)
                }
                _ => None,
            };
            if let Some(point) = point {
                observer.lifecycle_point(point);
            }
        }
        std::thread::spawn(move || {
            let _finished = WorkerCompletion(complete);
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            ))]
            if let Some((job, _, _)) = &worker_flow {
                job.started();
            }
            let result = work(cancellation);
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            ))]
            if let Some((job, _, stage)) = &worker_flow {
                durable_witness_v1::observe_flow_worker_v1(job, *stage, &result);
            }
            let _ = send.send(result);
        });
        open.witness_job = Some(WitnessJob {
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            ))]
            flow,
            receive,
            done,
            cancelled,
            epoch,
        });
        self.message = "Exact witness operation is running. No replacement is attempted if the outcome is uncertain. Lock remains available.";
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn prepare_writer_session(&mut self, epoch: u64) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }

        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return self.prepare_durable_session_v1(epoch);
        }
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        if open.writer_retry.is_some() || open.writer_receipt.is_some() {
            return Err(Error::Locked);
        }
        let witness = open.witness.as_ref().ok_or(Error::Locked)?.clone();
        self.start_witness_job(epoch, move |cancelled| {
            WitnessOutcome::SessionPrepared(if cancelled.load(Ordering::Acquire) {
                Err(Error::Locked)
            } else {
                PreparedWriterSession::prepare(&witness).map(Box::new)
            })
        })
    }
    #[cfg(feature = "authority-signing")]
    fn acquire_writer_session(
        &mut self,
        approved: ApprovedWriterSession,
        epoch: u64,
    ) -> Result<()> {
        let witness = self
            .open
            .as_ref()
            .and_then(|o| o.witness.clone())
            .ok_or(Error::Locked)?;
        self.start_witness_job(epoch, move |cancelled| {
            let result = if cancelled.load(Ordering::Acquire) {
                Err(Error::Locked)
            } else {
                approved.acquire(&witness).map(Box::new)
            };
            WitnessOutcome::SessionAcquired {
                approved: Box::new(approved),
                result,
            }
        })
    }
    #[cfg(feature = "authority-signing")]
    fn prepare_writer_activation(&mut self, epoch: u64) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }

        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return self.prepare_durable_activation_v1(epoch);
        }
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        if open.activation_retry.is_some() {
            return Err(Error::Locked);
        }
        let owner = open.owner_witness.as_ref().ok_or(Error::Locked)?.clone();
        let receipt = open.writer_receipt.as_ref().ok_or(Error::Locked)?.clone();
        self.start_witness_job(epoch, move |cancelled| {
            WitnessOutcome::ActivationPrepared(if cancelled.load(Ordering::Acquire) {
                Err(Error::Locked)
            } else {
                PreparedWriterActivation::prepare(&owner, receipt).map(Box::new)
            })
        })
    }
    #[cfg(feature = "authority-signing")]
    fn activate_writer_session(
        &mut self,
        approved: ApprovedWriterActivation,
        epoch: u64,
    ) -> Result<()> {
        let owner = self
            .open
            .as_ref()
            .and_then(|o| o.owner_witness.clone())
            .ok_or(Error::Locked)?;
        self.start_witness_job(epoch, move |cancelled| {
            let result = if cancelled.load(Ordering::Acquire) {
                Err(Error::Locked)
            } else {
                approved.activate(&owner).map(|_| ())
            };
            WitnessOutcome::Activated {
                approved: Box::new(approved),
                result,
            }
        })
    }
    #[cfg(feature = "authority-signing")]
    fn prepare_writer_reconciliation(&mut self, epoch: u64) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }

        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return self.prepare_durable_reconciliation_v1(epoch);
        }
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let witness = open.witness.as_ref().ok_or(Error::Locked)?.clone();
        let session = open.session.as_ref().ok_or(Error::Locked)?.clone();
        let journal = open.journal.clone();
        self.start_witness_job(epoch, move |cancelled| {
            WitnessOutcome::ReconciliationPrepared((|| {
                if cancelled.load(Ordering::Acquire) {
                    return Err(Error::Locked);
                }
                witness.check_current()?;
                let history = witness
                    .client()
                    .reconcile_history()
                    .map_err(|_| Error::Uncertain)?;
                if cancelled.load(Ordering::Acquire) {
                    return Err(Error::Locked);
                }
                let active = witness
                    .client()
                    .verify_active_session(&history)
                    .map_err(|_| Error::Authentication)?;
                witness.check_current()?;
                Ok(Box::new(session.prepare_writer_reconciliation(
                    &journal, history, active,
                )?))
            })())
        })
    }
    #[cfg(feature = "authority-signing")]
    fn poll_witness(&mut self, epoch: u64) {
        let result = {
            let Some(open) = self.open.as_mut() else {
                return;
            };
            let Some(job) = open.witness_job.as_ref() else {
                return;
            };
            match durable_flow_try_receive_v1(
                &job.receive,
                #[cfg(all(
                    feature = "synthetic-born-joined-qualification",
                    feature = "durable-proposal"
                ))]
                job.flow.as_ref().map(|(flow, _, _)| flow),
            ) {
                Ok(value) => Some((open.witness_job.take().unwrap(), value)),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(_) => {
                    open.witness_job = None;
                    #[cfg(all(
                        feature = "synthetic-born-joined-qualification",
                        feature = "durable-proposal",
                        feature = "pending-birth-owner-signing"
                    ))]
                    open.durable_witness.observe_admission_disconnected_v1();
                    self.message = "Witness worker stopped with an uncertain outcome. Preserve exposure and reconcile; no replacement was authorized.";
                    None
                }
            }
        };
        let Some((job, result)) = result else {
            return;
        };
        let open = self.open.as_mut().unwrap();
        if !witness_completion_allowed_v1(
            &result,
            job.epoch == epoch,
            || job.cancelled.load(Ordering::Acquire),
            || open.check_pairing().map(|_| ()),
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            ))]
            job.flow.as_ref(),
        ) {
            self.message = "Witness operation was invalidated. Any already admitted mutation remains in independent witness history.";
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal",
                feature = "pending-birth-owner-signing"
            ))]
            if let WitnessOutcome::DurablePaymentV1(outcome) = result {
                open.durable_witness
                    .observe_admission_invalidated_v1(outcome);
            }
            return;
        }
        let prepared = match result {
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            WitnessOutcome::DurablePaymentV1(outcome) => {
                let (message, prepared) = durable_witness_v1::complete_inner(
                    open,
                    outcome,
                    #[cfg(all(
                        feature = "synthetic-born-joined-qualification",
                        feature = "durable-proposal"
                    ))]
                    job.flow.as_ref().map(|(_, observer, _)| observer),
                );
                self.message = message;
                prepared
            }

            WitnessOutcome::HostPublicationPrepared(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::HostPublication(value),
            )),
            WitnessOutcome::HostPublicationPreparedV2(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::HostPublicationV2(value),
            )),
            WitnessOutcome::HostPublicationPreparedV3(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::HostPublicationV3(value),
            )),
            WitnessOutcome::HostPublicationPreparedV5(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::HostPublicationV5(value),
            )),
            WitnessOutcome::HostContinuityPrepared(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::HostContinuity(value),
            )),
            WitnessOutcome::HostContinuityPreparedV2(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::HostContinuityV2(value),
            )),
            WitnessOutcome::HostContinuityPreparedV3(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::HostContinuityV3(value),
            )),
            WitnessOutcome::HostContinuityPreparedV5(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::HostContinuityV5(value),
            )),
            WitnessOutcome::AutomationGrantPrepared(Ok(value)) => Some((
                value.review_digest().to_owned(),
                value.display().map_err(Error::from),
                Operation::AutomationGrant(value),
            )),
            WitnessOutcome::AutomationGrantPrepared(Err(_)) => {
                self.message = "No new grant control was prepared or committed. The existing grant may remain active. Lock or revoke the paired application to stop local work; synchronize any retained pending revision before another control.";
                None
            }
            WitnessOutcome::AutomationPrepared(Err(_)) => {
                self.message = "The local grant decision remains retained, but witness synchronization is pending. Inspect status and review synchronization of this retained revision. Global pause/revoke is not confirmed until the witness commits.";
                None
            }
            WitnessOutcome::AutomationPrepared(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::AutomationWitness(value),
            )),
            WitnessOutcome::AutomationCompleted(result) => {
                self.message = if result.is_ok() {
                    "Exact grant revision synchronized with the independent witness. Previous exposure remains; no request was signed or exported."
                } else {
                    "Grant synchronization is uncertain. Inspect retained local and witness state; no replacement control or signature was created."
                };
                None
            }

            WitnessOutcome::ResolutionPrepared(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::Resolution(value),
            )),
            WitnessOutcome::SponsorPolicyCompleted(result) => {
                self.message = if result.is_ok() {
                    "Native sponsor policy change committed. Prior bindings are ineligible for new spending; existing exposure remains."
                } else {
                    "Native sponsor policy change failed or expired. Reinspect the durable policy before retrying."
                };
                None
            }
            WitnessOutcome::ResolutionCompleted(Ok(reference)) => {
                if let Some(reference) = reference {
                    self.resolution_source_reference = Zeroizing::new(reference);
                }
                self.message = "Exact native resolution operation committed. Enrollment alone does not establish payment; only independent canonical observation resolves original exposure.";
                None
            }

            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            WitnessOutcome::BornHistoryPrepared(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::BornHistory(value),
            )),
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            WitnessOutcome::BornDispatchPrepared(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::BornDispatch(value),
            )),
            WitnessOutcome::DispatchPrepared(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::Dispatch(value),
            )),
            WitnessOutcome::SessionPrepared(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::WriterSession(value),
            )),
            WitnessOutcome::ActivationPrepared(Ok(value)) => Some((
                value.digest().to_owned(),
                value.display(),
                Operation::WriterActivation(value),
            )),
            WitnessOutcome::ReconciliationPrepared(Ok(value)) => Some((
                value.review_digest().to_owned(),
                value.display().map_err(Error::from),
                Operation::Reconcile(value),
            )),
            WitnessOutcome::SessionAcquired { approved, result } => {
                match result {
                    Ok(receipt) => {
                        open.writer_receipt = Some(*receipt);
                        self.message = "Fresh writer session is pending. It needs separate independent owner activation before any reservation.";
                    }
                    Err(_) => {
                        open.writer_retry = Some(*approved);
                        self.message = "Writer-session outcome is uncertain. Only retry this identical approved operation within its original lifetime, or reconcile independently.";
                    }
                }
                None
            }
            WitnessOutcome::Activated { approved, result } => {
                match result {
                    Ok(_) => {
                        self.message = "The exact writer session was owner-activated. Review full independent history and reconcile the local journal before fresh enrollment.";
                    }
                    Err(_) => {
                        open.activation_retry = Some(*approved);
                        self.message = "Owner activation outcome is uncertain. Only the identical approved operation may be retried; no replacement was created.";
                    }
                }
                None
            }
            WitnessOutcome::Reconciled(Ok(())) => {
                open.writer_reconciled = true;
                if let Some(session) = open.session.take() {
                    let done = Arc::new(AtomicBool::new(false));
                    let finished = done.clone();
                    std::thread::spawn(move || {
                        let _ = session.invalidate();
                        finished.store(true, Ordering::Release);
                    });
                    open.revocations.push(done);
                }
                open.enrollment = None;
                open.manifest = None;
                self.message = "Authenticated writer history and all outstanding exposure were committed. The old session is invalidated; fresh enrollment and manifest decisions are required.";
                None
            }
            _ => {
                self.message = "Witness state/history/session was unavailable or rejected. No substitute head, session or consent was accepted.";
                None
            }
        };
        if let Some((digest, Ok(display), operation)) = prepared {
            match ExactNativeReview::stage(&open.authority, &digest, display, epoch) {
                Ok(review) => {
                    #[cfg(all(
                        feature = "synthetic-born-joined-qualification",
                        feature = "durable-proposal"
                    ))]
                    if let Some((flow, _, _)) = &job.flow {
                        flow.presentation(flow_diag_v1::DurableFlowPresentationV1::Accepted);
                    }
                    self.pending = Some(PendingDecision { review, operation });
                }
                Err(_error) => {
                    #[cfg(all(
                        feature = "synthetic-born-joined-qualification",
                        feature = "durable-proposal"
                    ))]
                    if let Some((flow, observer, stage)) = &job.flow {
                        observer.record_error(*stage, &_error);
                        flow.presentation(flow_diag_v1::DurableFlowPresentationV1::Suppressed);
                    }
                    #[cfg(all(
                        feature = "synthetic-born-joined-qualification",
                        feature = "durable-proposal"
                    ))]
                    if matches!(&operation, Operation::DurableWitnessV1(value)
                        if matches!(value.as_ref(), durable_witness_v1::DurableWitnessPreparedV1::Admission(_)))
                    {
                        open.durable_witness
                            .record_qualification_native_stage_failure_v1(_error);
                    }
                }
            }
        }
    }
    #[cfg(feature = "authority-signing")]
    fn start_wallet_review(&mut self, epoch: u64) -> Result<()> {
        self.start_wallet_review_mode(epoch, None)
    }
    #[cfg(feature = "authority-signing")]
    fn start_wallet_review_mode(
        &mut self,
        epoch: u64,
        automation_grant: Option<String>,
    ) -> Result<()> {
        self.start_wallet_review_delivery(epoch, automation_grant, None)
    }
    #[cfg(feature = "authority-signing")]
    fn check_automatic_delivery(
        open: &OpenAccount,
        delivery: &AutomaticIpcDelivery,
        bytes: &[u8],
    ) -> Result<()> {
        let pairing = open.check_pairing()?;
        let requested = AuthenticatedPairing::from_authenticated_request(delivery.peer.clone())?;
        let manifest = open.manifest.as_ref().ok_or(Error::ReviewMismatch)?;
        if requested.binding() != pairing.binding() {
            return Err(Error::ReviewMismatch);
        }
        super::automatic_ipc::check_reference(
            &delivery.request,
            &manifest.proposal_input().proposal_id,
            manifest.manifest_digest(),
            bytes,
        )
        .map_err(|_| Error::ReviewMismatch)?;
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn start_automatic_ipc(&mut self, delivery: AutomaticIpcDelivery, epoch: u64) -> Result<()> {
        // A completed intake has already been consumed and zeroized. Look up
        // original metadata before requiring those bytes again; replay never
        // triggers another synchronization, input selection or signing flow.
        let historical_id = {
            let open = self.open.as_ref().ok_or(Error::Locked)?;
            Self::find_automatic_history(open, &delivery)?
        };
        if let Some(original_id) = historical_id {
            self.inspect_original_automatic_request(&original_id)?;
            let open = self.open.as_mut().ok_or(Error::Locked)?;
            return Self::queue_automatic_history(open, delivery, original_id);
        }
        let original_id = {
            let open = self.open.as_ref().ok_or(Error::Locked)?;
            let bytes = self.incoming_pczt.as_ref().ok_or(Error::InvalidData)?;
            Self::check_automatic_delivery(open, &delivery, bytes)?;
            super::automatic_ipc::authorization_id(
                &delivery.request.grant_id,
                &delivery.request.candidate_id,
                bytes,
            )?
        };
        if self.inspect_original_automatic_request(&original_id)? {
            // Retained history never recreates the sealed continuation. The
            // response is metadata only, through the exact original app binding.
            let open = self.open.as_mut().ok_or(Error::Locked)?;
            Self::queue_automatic_history(open, delivery, original_id)?;
            return Ok(());
        }
        self.start_wallet_review_delivery(
            epoch,
            Some(delivery.request.grant_id.clone()),
            Some(delivery),
        )
    }
    #[cfg(feature = "authority-signing")]
    fn find_automatic_history(
        open: &OpenAccount,
        delivery: &AutomaticIpcDelivery,
    ) -> Result<Option<String>> {
        delivery
            .request
            .validate()
            .map_err(|_| Error::InvalidData)?;
        let pairing = open.check_pairing()?;
        let requested = AuthenticatedPairing::from_authenticated_request(delivery.peer.clone())?;
        if requested.binding() != pairing.binding()
            || delivery.request.accepted_manifest_digest != delivery.peer.scope.manifest_digest
        {
            return Err(Error::Authentication);
        }
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        let mut matching = None;
        for attempt in open
            .journal
            .automation_attempts(Some(&delivery.request.grant_id), session)?
        {
            let original = open
                .journal
                .original_authorization(&attempt.authorization_id, session)?
                .ok_or(Error::Verification)?;
            let terms = original.original_consent().terms();
            if terms.artifact_digest == delivery.request.artifact_digest
                && terms.manifest_digest == delivery.request.accepted_manifest_digest
                && terms.proposal_id == delivery.request.candidate_id
            {
                if matching.is_some()
                    || &terms.transport != pairing.binding()
                    || attempt.grant.application_id != pairing.binding().identity_id()
                    || original.enrollment().participant_id() != delivery.peer.scope.participant_id
                    || terms.account_id != delivery.peer.scope.account_id
                    || terms.agreement_id != delivery.peer.scope.agreement_id
                {
                    return Err(Error::Authentication);
                }
                matching = Some(attempt.authorization_id);
            }
        }
        Ok(matching)
    }
    #[cfg(feature = "authority-signing")]
    fn queue_automatic_history(
        open: &mut OpenAccount,
        delivery: AutomaticIpcDelivery,
        original_id: String,
    ) -> Result<()> {
        if open.history_workers.len() >= 8 {
            return Err(Error::Locked);
        }
        let session = open.session.clone().ok_or(Error::Locked)?;
        let journal = open.journal.clone();
        open.history_workers.push(std::thread::spawn(move || {
            let _ = super::automatic_ipc::serve_historical(
                delivery.stream,
                delivery.peer,
                delivery.request,
                original_id,
                &journal,
                &session,
            );
        }));
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn start_wallet_review_delivery(
        &mut self,
        epoch: u64,
        automation_grant: Option<String>,
        automatic_delivery: Option<AutomaticIpcDelivery>,
    ) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        if !open.writer_reconciled {
            return Err(Error::Locked);
        }
        open.check_pairing()?;
        if open.wallet_job.is_some() || open.witness_job.is_some() || self.pending.is_some() {
            return Err(Error::Locked);
        }
        let proposal = Proposal::validate(
            open.manifest
                .as_ref()
                .ok_or(Error::ReviewMismatch)?
                .proposal_input()
                .clone(),
        )
        .map_err(|_| Error::Verification)?;
        let bytes = self.incoming_pczt.take().ok_or(Error::InvalidData)?;
        let witness = open.witness.as_ref().ok_or(Error::Locked)?.clone();
        witness.check_current()?;
        let mut wallet = open.wallet.take().ok_or(Error::Locked)?;
        let revoke = wallet.revoke_handle();
        let context = Zeroizing::new(self.review_context.as_bytes().to_vec());
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let done = Arc::new(AtomicBool::new(false));
        let finished = done.clone();
        let automatic = automation_grant.is_some();
        std::thread::spawn(move || {
            let _completed = WorkerCompletion(finished);
            let result = (|| -> Result<_> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| Error::Unavailable)?;
                let inputs = runtime.block_on(wallet.synchronize_review(&proposal, &context))?;
                wallet.check_current()?;
                let active = if automatic {
                    let history = witness
                        .client()
                        .reconcile_history()
                        .map_err(|_| Error::Unavailable)?;
                    Some(
                        witness
                            .client()
                            .verify_active_session(&history)
                            .map_err(|_| Error::Authentication)?,
                    )
                } else {
                    None
                };
                let head = match &active {
                    Some(active) => active.snapshot().head.clone(),
                    None => witness.snapshot_head()?,
                };
                wallet.check_current()?;
                Ok((inputs, head, active))
            })();
            let _ = send.send((wallet, result));
        });
        open.wallet_job = Some(WalletJob {
            automation_grant,
            automatic_delivery,
            receive,
            revoke,
            done,
            bytes,
            epoch,
        });
        self.message = "Synchronizing the explicitly selected public source and selecting inputs locally. No spending decision has been made.";
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn poll_wallet(&mut self, epoch: u64) {
        let result = {
            let Some(open) = self.open.as_mut() else {
                return;
            };
            let Some(job) = open.wallet_job.as_ref() else {
                return;
            };
            match job.receive.try_recv() {
                Ok(result) => Some((open.wallet_job.take().unwrap(), result)),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(_) => {
                    open.wallet_job = None;
                    self.message = "Local wallet worker stopped. Review was discarded; reopen the workspace before retrying.";
                    None
                }
            }
        };
        if let Some((job, (wallet, result))) = result {
            let open = self.open.as_mut().unwrap();
            open.wallet = Some(wallet);
            if job.epoch != epoch || open.check_pairing().is_err() {
                job.revoke.revoke();
                self.message = "Wallet review was invalidated before completion.";
                return;
            }
            match result {
                Ok((inputs, head, active)) => {
                    let result = match (job.automation_grant, active) {
                        (Some(grant), Some(active)) => self.stage_automatic_spend(
                            job.bytes,
                            inputs,
                            active,
                            &grant,
                            job.automatic_delivery,
                            epoch,
                        ),
                        (None, None) => self.stage_spend(job.bytes, inputs, head, epoch),
                        _ => Err(Error::Authentication),
                    };
                    if result.is_err() {
                        self.message = "Signer-local transaction verification failed. No spend decision was prepared.";
                    }
                }
                Err(_) => {
                    self.message = "Selected wallet source, local input selection or authenticated witness state was unavailable. No substitute snapshot or consent was used."
                }
            }
        }
    }
    #[cfg(feature = "authority-signing")]
    fn begin_signing(
        &mut self,
        flow: SpendFlow,
        disclosure: ApprovedWitnessDisclosure,
        decision: super::NativeDecision,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        let peer = open.check_pairing()?.peer.clone();
        let session = open.session.as_ref().ok_or(Error::Locked)?.clone();
        let native = session.native_decision(decision)?;
        let approval = session.approve_spend(flow.prepared, native)?;
        let witness = open.witness.as_ref().ok_or(Error::Locked)?.clone();
        witness.check_current()?;
        let wallet = open.wallet.as_mut().ok_or(Error::Locked)?;
        let wallet_revoke = wallet.revoke_handle();
        let ticket = wallet.take_ticket()?;
        let admission = open.ipc.revocation();
        let mut open = self.open.take().ok_or(Error::Locked)?;
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let worker_session = session.clone();
        std::thread::spawn(move || {
            let result = (|| {
                open.check_pairing()
                    .map_err(|_| authority_bridge::BridgeError::Permission)?;
                let pending = authority_bridge::prepare_authorization(
                    &open.journal,
                    &worker_session,
                    open.vault.account(),
                    approval,
                    &flow.bytes,
                    flow.head,
                    AuthorizationDeliveryScope {
                        candidate_id: flow.candidate_id,
                    },
                    disclosure,
                )?;
                let reserved = pending.reserve(witness.client())?;
                reserved.authorize_with_wallet(
                    open.wallet
                        .as_mut()
                        .ok_or(authority_bridge::BridgeError::Permission)?
                        .wallet_mut(),
                    &ticket,
                    &flow.inputs,
                )
            })();
            if let Err(unsent) = send.send((open, result)) {
                unsent.0.0.close();
            }
        });
        self.signing_job = Some(SigningJob {
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            ))]
            flow: None,
            receive,
            session,
            admission,
            wallet_revoke,
            peer,
            lock_requested: false,
        });
        self.message = "Exact native authorization is in progress. Existing exposure is retained if an outcome is uncertain. No transaction is broadcast by this signer.";
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn begin_automatic_signing(
        &mut self,
        flow: AutomaticFlow,
        disclosure: ApprovedWitnessDisclosure,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        let peer = open.check_pairing()?.peer.clone();
        if let Some(delivery) = &flow.delivery {
            Self::check_automatic_delivery(open, delivery, &flow.bytes)?;
        }
        let coordinated = flow.delivery.is_some();
        let session = open.session.clone().ok_or(Error::Locked)?;
        let witness = open.witness.clone().ok_or(Error::Locked)?;
        witness.check_current()?;
        let wallet_revoke = open.wallet.as_ref().ok_or(Error::Locked)?.revoke_handle();
        let admission = open.ipc.revocation();
        let mut open = self.open.take().ok_or(Error::Locked)?;
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let worker_session = session.clone();
        std::thread::spawn(move || {
            let result = (|| {
                open.check_pairing()
                    .map_err(|_| authority_bridge::BridgeError::Permission)?;
                let AutomaticFlow {
                    approval,
                    inputs,
                    bytes,
                    head,
                    candidate_id,
                    ticket,
                    verified,
                    grant,
                    delivery,
                } = flow;
                let original_consent_ref = approval.record().reference().to_owned();
                let journal = open.journal.clone();
                let current = || {
                    verified.check_current()?;
                    witness
                        .check_current()
                        .map_err(|_| authority_bridge::BridgeError::Permission)?;
                    if journal
                        .automation_grant(&grant.binding.grant_id, &worker_session)?
                        .as_ref()
                        != Some(&grant)
                    {
                        return Err(authority_bridge::BridgeError::Permission);
                    }
                    Ok(())
                };
                let execute = |lease_current: &dyn Fn() -> authority_bridge::Result<()>| {
                    lease_current()?;
                    verified.check_current()?;
                    let pending = authority_bridge::prepare_automatic_authorization(
                        &journal,
                        &worker_session,
                        open.vault.account(),
                        approval,
                        &bytes,
                        head,
                        AuthorizationDeliveryScope { candidate_id },
                        disclosure,
                    )?;
                    let reserved = pending.reserve(witness.client())?;
                    // The original lease already holds the native session and
                    // authority fences. Do not recursively reacquire them here.
                    let check = || {
                        lease_current()?;
                        verified.check_current()
                    };
                    reserved.authorize_with_wallet_checked(
                        open.wallet
                            .as_mut()
                            .ok_or(authority_bridge::BridgeError::Permission)?
                            .wallet_mut(),
                        &ticket,
                        &inputs,
                        &check,
                    )
                };
                if let Some(delivery) = delivery {
                    let descriptor = authority_bridge::automation_ipc::AutomaticDescriptor {
                        original_consent_ref,
                        request: verified.request().clone(),
                        policy: grant.policy.clone(),
                        grant: grant.terms.clone(),
                        grant_reference: grant.reference()?,
                        grant_revision: grant.binding.revision,
                        participant_id: delivery.peer.scope.participant_id.clone(),
                        expires_at_ms: verified.request().authorization_expires_at_ms,
                    };
                    super::automatic_ipc::serve(
                        delivery.stream,
                        &delivery.peer,
                        descriptor,
                        current,
                        execute,
                    )
                } else {
                    current()?;
                    execute(&|| Ok(()))
                }
            })();
            if let Err(unsent) = send.send((open, result)) {
                unsent.0.0.close();
            }
        });
        self.signing_job = Some(SigningJob {
            #[cfg(all(
                feature = "synthetic-born-joined-qualification",
                feature = "durable-proposal"
            ))]
            flow: None,
            receive,
            session,
            admission,
            wallet_revoke,
            peer,
            lock_requested: false,
        });
        self.message = if coordinated {
            "Exact privacy decision accepted. The original coordinator channel must commit conservative exposure before requesting one-shot signing. Results remain protected; export and dispatch require separate approval."
        } else {
            "Foreground exact grant authorization is in progress. A separate privacy decision was accepted; no spending click was manufactured. Results and uncertain exposure are retained; export and dispatch require separate approval."
        };
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn poll_signing(&mut self) {
        if self.signing_job.as_ref().is_some_and(|job| {
            !job.lock_requested
                && durable_flow_observe_v1!(
                    job.flow.as_ref().map(|(_, observer)| observer),
                    flow_diag_v1::DurableFlowStageV1::Close,
                    job.peer.check_current()
                )
                .is_err()
        }) {
            // OpenAccount is owned by the worker during key use. Keep the exact
            // original peer alive/current check on the native side as well, and
            // serialize revocation behind any already-admitted journal lease.
            self.lock();
            self.message = "The original application exited or its grant expired. New work is blocked; an already-admitted operation must finish before revocation completes.";
        }
        let mut disconnected = false;
        let result = {
            let Some(job) = self.signing_job.as_ref() else {
                return;
            };
            match durable_flow_try_receive_v1(
                &job.receive,
                #[cfg(all(
                    feature = "synthetic-born-joined-qualification",
                    feature = "durable-proposal"
                ))]
                job.flow.as_ref().map(|(flow, _)| flow),
            ) {
                Ok(value) => Some(value),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(_) => {
                    disconnected = true;
                    self.message = "Signing worker stopped with an uncertain outcome. Reconcile original history; do not create a substitute authorization.";
                    None
                }
            }
        };
        if disconnected {
            if let Some(job) = self.signing_job.take() {
                job.admission.close();
                job.wallet_revoke.revoke();
                let done = Arc::new(AtomicBool::new(false));
                let finished = done.clone();
                std::thread::spawn(move || {
                    let _ = durable_flow_observe_v1!(
                        job.flow.as_ref().map(|(_, observer)| observer),
                        flow_diag_v1::DurableFlowStageV1::Close,
                        job.session.invalidate()
                    );
                    finished.store(true, Ordering::Release);
                });
                self.closing_accounts.push(done);
            }
            return;
        }
        if let Some((open, result)) = result {
            let job = self.signing_job.take().unwrap();
            if !signing_completion_presented_v1(
                &result,
                job.lock_requested,
                #[cfg(all(
                    feature = "synthetic-born-joined-qualification",
                    feature = "durable-proposal"
                ))]
                job.flow.as_ref().map(|(flow, _)| flow),
            ) {
                let done = Arc::new(AtomicBool::new(false));
                let finished = done.clone();
                std::thread::spawn(move || {
                    open.close();
                    finished.store(true, Ordering::Release);
                });
                self.closing_accounts.push(done);
                self.message = "Lock requested. The admitted authorization finished or remained uncertain; exposure has not been cleared.";
            } else {
                match result {
                    Ok(receipt) => {
                        self.last_receipt = Some(receipt.original_consent_ref);
                        self.message = "Exact signatures were retained durably. Only the originally approved recipient process can retrieve them; no payment was broadcast.";
                    }
                    Err(_) => {
                        self.message = "Authorization did not complete cleanly. Preserve original exposure and reconcile the exact operation; no replacement was created."
                    }
                }
                self.open = Some(open);
            }
        }
    }
    fn approve(&mut self, focused: bool, epoch: u64) -> Result<()> {
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        let observation = self
            .pending
            .as_ref()
            .and_then(|pending| match &pending.operation {
                Operation::DurableSpendV1 { flow, .. } => flow
                    .flow_observer
                    .clone()
                    .map(|observer| (observer, flow_diag_v1::DurableFlowStageV1::SpendDecision)),
                Operation::DurableDisclosureV1 { flow, .. } => {
                    flow.flow_observer.clone().map(|observer| {
                        (
                            observer,
                            flow_diag_v1::DurableFlowStageV1::DisclosureDecision,
                        )
                    })
                }
                Operation::DurableWitnessV1(value) => value
                    .flow_observer_v1()
                    .cloned()
                    .map(|observer| (observer, value.flow_native_stage_v1())),
                _ => None,
            });
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        let delivery_redisclosure = self.pending.as_ref().is_some_and(|pending| {
            matches!(&pending.operation, Operation::DurableDeliveryRedisclosureV2(_))
        });
        let result = self.approve_inner(focused, epoch);
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        let result = if delivery_redisclosure {
            durable_delivery_observe_v2!(DeliveryRedisclosureApprove, result)
        } else {
            result
        };
        durable_flow_observe_v1!(
            observation.as_ref().map(|(observer, _)| observer),
            observation
                .as_ref()
                .map(|(_, stage)| *stage)
                .unwrap_or(flow_diag_v1::DurableFlowStageV1::FixtureState),
            result
        )
    }
    fn approve_inner(&mut self, focused: bool, epoch: u64) -> Result<()> {
        let pending = self.pending.take().ok_or(Error::ReviewMismatch)?;
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if let Operation::DurableDeliveryRedisclosureV2(prepared) = &pending.operation {
            prepared.check_current()?;
        }

        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_delivery_entry.is_some())
            && !durable_delivery_admission_v2::allowed_operation(&pending.operation)
        {
            return Err(Error::Unavailable);
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some())
            && !durable_review_v1::allowed_operation(&pending.operation)
        {
            return Err(Error::Unavailable);
        }
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        let flow_observer = match &pending.operation {
            Operation::DurableSpendV1 { flow, .. }
            | Operation::DurableDisclosureV1 { flow, .. } => flow.flow_observer.as_ref(),
            Operation::DurableWitnessV1(value) => value.flow_observer_v1(),
            _ => None,
        };
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        let flow_stage = match &pending.operation {
            Operation::DurableSpendV1 { .. } => flow_diag_v1::DurableFlowStageV1::SpendDecision,
            Operation::DurableDisclosureV1 { .. } => {
                flow_diag_v1::DurableFlowStageV1::DisclosureDecision
            }
            Operation::DurableWitnessV1(value) => value.flow_native_stage_v1(),
            _ => flow_diag_v1::DurableFlowStageV1::FixtureState,
        };
        let decision = durable_flow_observe_v1!(
            flow_observer,
            flow_stage,
            pending
                .review
                .consume_native_click(focused, epoch, &self.confirmation)
        )?;
        self.confirmation.zeroize();
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if let Operation::DurableDeliveryV2(prepared) = pending.operation {
            return self.approve_durable_delivery_v2(*prepared, decision, epoch);
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if let Operation::DurableDeliveryRedisclosureV2(prepared) = pending.operation {
            return self.approve_durable_delivery_redisclosure_v2(*prepared, decision);
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if let Operation::DurableSpendV1 { flow, disclosure } = pending.operation {
            return self.begin_durable_signing_v1(*flow, *disclosure, decision);
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if let Operation::DurableDisclosureV1 { flow, review } = pending.operation {
            return self.approve_durable_disclosure_v1(*flow, *review, decision, epoch);
        }
        #[cfg(feature = "authority-signing")]
        if let Operation::Spend { flow, disclosure } = pending.operation {
            return self.begin_signing(*flow, *disclosure, decision);
        }
        #[cfg(feature = "authority-signing")]
        if let Operation::AutomaticDisclosure { flow, review } = pending.operation {
            let open = self.open.as_ref().ok_or(Error::Locked)?;
            let disclosure = review
                .approve(decision, &open.authority)
                .map_err(|_| Error::Authentication)?;
            return self.begin_automatic_signing(*flow, disclosure);
        }
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        match pending.operation {
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            Operation::DurableSpendV1 { .. }
            | Operation::DurableDisclosureV1 { .. }
            | Operation::DurableDeliveryV2(_)
            | Operation::DurableDeliveryRedisclosureV2(_) => {
                unreachable!()
            }
            #[cfg(feature = "authority-signing")]
            Operation::AutomationGrant(prepared) => {
                open.check_pairing()?;
                let session = open.session.as_ref().ok_or(Error::Locked)?;
                let native = session.native_decision(decision)?;
                let approved = session.approve_automation_grant(*prepared, native)?;
                let record = open.journal.record_automation_grant(approved)?;
                let scope = Self::automation_recipient_scope(open, &record)?;
                let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
                let source = open.authority.binding();
                self.message = "Local native grant decision retained. Separate exact witness disclosure/control approval is required before synchronization.";
                return self.start_witness_job(epoch, move |cancelled| {
                    WitnessOutcome::AutomationPrepared(if cancelled.load(Ordering::Acquire) {
                        Err(Error::Locked)
                    } else {
                        super::automation_workspace::PreparedGrantSynchronization::prepare(
                            record, scope, owner, source,
                        )
                        .map(Box::new)
                    })
                });
            }
            #[cfg(feature = "authority-signing")]
            Operation::AutomationWitness(prepared) => {
                let approved = prepared.approve(decision, &open.authority)?;
                return self.start_witness_job(epoch, move |cancelled| {
                    WitnessOutcome::AutomationCompleted(if cancelled.load(Ordering::Acquire) {
                        Err(Error::Locked)
                    } else {
                        approved.run()
                    })
                });
            }
            #[cfg(feature = "authority-signing")]
            Operation::SponsorPolicy(prepared) => {
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                return self.start_witness_job(epoch, move |cancelled| {
                    WitnessOutcome::SponsorPolicyCompleted(if cancelled.load(Ordering::Acquire) {
                        Err(Error::Locked)
                    } else {
                        journal
                            .commit_sponsor_policy_change(*prepared, decision, &session)
                            .map_err(Error::from)
                    })
                });
            }
            #[cfg(feature = "authority-signing")]
            Operation::Resolution(prepared) => {
                open.check_pairing()?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let approved = prepared.approve(decision, &open.authority, &session)?;
                let journal = open.journal.clone();
                return self.start_witness_job(epoch, move |cancelled| {
                    WitnessOutcome::ResolutionCompleted(if cancelled.load(Ordering::Acquire) {
                        Err(Error::Locked)
                    } else {
                        approved.run(&journal, &session)
                    })
                });
            }
            #[cfg(feature = "authority-signing")]
            Operation::RecipientObservation(prepared) => {
                if self.recipient_job.is_some() {
                    return Err(Error::Locked);
                }
                let job = prepared.approve(decision, &open.authority, &open.vault)?;
                let (send, receive) = std::sync::mpsc::sync_channel(1);
                std::thread::spawn(move || {
                    let _ = send.send(job.run());
                });
                self.recipient_job = Some(receive);
                self.message = "Checking the explicitly selected recipient provider. No wallet key was shared.";
            }

            #[cfg(feature = "authority-signing")]
            Operation::Recipient(prepared) => {
                self.recipient_result = Some(Zeroizing::new(prepared.approve(
                    decision,
                    &open.authority,
                    &open.vault,
                )?));
                self.message = "Recipient-local operation completed. Review the separate payment and chain status below.";
            }

            #[cfg(feature = "authority-signing")]
            Operation::HostPublication(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session);
                });
                open.host_continuity_worker = Some(worker.thread().id());
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact restricted host generation reviewed. Its bounded admission releases the signer before the host writes. All financial actions require fresh checks; external uncertainty remains.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::HostPublicationV2(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session);
                });
                open.host_continuity_worker = Some(worker.thread().id());
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact restricted host generation reviewed. Its bounded admission releases the signer before the host writes. All financial actions require fresh checks; external uncertainty remains.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::HostPublicationV3(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session);
                });
                open.host_continuity_worker = Some(worker.thread().id());
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact restricted host generation reviewed. Its bounded admission releases the signer before the host writes. All financial actions require fresh checks; external uncertainty remains.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::HostPublicationV5(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal);
                });
                open.host_continuity_worker = Some(worker.thread().id());
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact restricted host generation reviewed. Its bounded admission releases the signer before the host writes. All financial actions require fresh checks; external uncertainty remains.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::HostContinuity(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session);
                });
                open.host_continuity_worker = Some(worker.thread().id());
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact account-wide continuity disclosure approved for this restored host inventory. All witnessed exposure remains conservative; host activation and spending are separate checks.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::HostContinuityV2(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session);
                });
                open.host_continuity_worker = Some(worker.thread().id());
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact account-wide continuity disclosure approved for this restored host inventory. All witnessed exposure remains conservative; host activation and spending are separate checks.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::HostContinuityV3(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session);
                });
                open.host_continuity_worker = Some(worker.thread().id());
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact account-wide continuity disclosure approved for this restored host inventory. All witnessed exposure remains conservative; host activation and spending are separate checks.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::HostContinuityV5(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal);
                });
                open.host_continuity_worker = Some(worker.thread().id());
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact account-wide continuity disclosure approved for this restored host inventory. All witnessed exposure remains conservative; host activation and spending are separate checks.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::OwnerInspection(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve();
                });
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact historical account audit metadata approved for the paired local host. No balance, current exposure or financial authority is established.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::NamedVerifierPolicy(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority, &open.vault)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session);
                });
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact viewing disclosure approved for this named verifier only. The disclosed viewing key cannot be recalled; no spending authority was granted.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::Preconstruction(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority, &open.vault)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session);
                });
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact viewing disclosure approved for the named local constructor. Spending keys remain inside the signer; disclosed viewing capability cannot be recalled.";
            }
            #[cfg(feature = "durable-proposal")]
            Operation::DurableConstructionV1(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority, &open.vault)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session);
                });
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact durable construction disclosure approved for its named recipient and retention scope. No signature, reservation refund or payment was authorized.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::ProvedDisclosure(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority, &open.vault)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session);
                });
                open.disclosure_worker_ids.insert(worker.thread().id());
                open.history_workers.push(worker);
                self.message = "Exact proved-artifact disclosure approved for the listed installed recipients. Every original owner must separately approve.";
            }
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            Operation::BornHistory(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let witness = open.witness.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session, &witness);
                });
                open.born_bridge_workers.insert(worker.thread().id());
                open.history_workers.push(worker);
                open.born_bridge_active = true;
                self.message = "The exact born Host channel is held. Original exposure remains retained; Lock or blur stops new admission, and already-admitted outcomes remain possible.";
            }
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            Operation::BornDispatch(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let witness = open.witness.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                let worker = std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session, &witness);
                });
                open.born_bridge_workers.insert(worker.thread().id());
                open.history_workers.push(worker);
                open.born_bridge_active = true;
                self.message = "The exact born Host channel is held. Original exposure remains retained; Lock or blur stops new admission, and already-admitted outcomes remain possible.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::Dispatch(prepared) => {
                open.check_pairing()?;
                if open.history_workers.len() >= 8 {
                    return Err(Error::Unavailable);
                }
                let approved = prepared.approve(decision, &open.authority)?;
                let session = open.session.clone().ok_or(Error::Locked)?;
                let witness = open.witness.clone().ok_or(Error::Locked)?;
                let journal = open.journal.clone();
                open.history_workers.push(std::thread::spawn(move || {
                    let _ = approved.serve(&journal, &session, &witness);
                }));
                self.message = "Exact dispatch admission is being requested. Outstanding exposure remains retained; the signer does not broadcast.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::Wallet(prepared) => {
                open.wallet = Some(prepared.approve(decision, &open.authority, &open.vault)?);
                self.message = "Native wallet setup accepted. Public synchronization and local selection require a separate native action.";
            }
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            Operation::DurableBornWalletV1(prepared) => {
                let source = open.durable_born_entry.as_ref().ok_or(Error::Unavailable)?;
                source.check_current()?;
                if open.wallet.is_some()
                    || open.wallet_job.is_some()
                    || open.durable_wallet_job.is_some()
                {
                    return Err(Error::Locked);
                }
                open.wallet = Some(prepared.approve(decision, &open.authority)?);
                self.message = "Fresh encrypted ephemeral viewing wallet accepted outside the original vault. Its original native deadline is unchanged; public synchronization, export and spending still require their separate actions.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::OwnerWitness(prepared) => {
                let witness = prepared.approve(decision, &open.authority, &open.vault)?;
                #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
                durable_review_v1::check_witness_descriptor(open, &witness.disclosure())?;
                open.owner_witness = Some(Arc::new(witness));
                self.message = "Separate owner-control client selected. Activation requires its own exact review; writer identity was not replaced.";
            }
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            Operation::DurableWitnessV1(prepared) => {
                return self.approve_durable_witness_v1(*prepared, decision, epoch);
            }
            #[cfg(feature = "authority-signing")]
            Operation::WriterSession(prepared) => {
                let approved = prepared.approve(
                    decision,
                    &open.authority,
                    open.witness.as_ref().ok_or(Error::Locked)?,
                )?;
                return self.acquire_writer_session(approved, epoch);
            }
            #[cfg(feature = "authority-signing")]
            Operation::WriterActivation(prepared) => {
                let approved = prepared.approve(
                    decision,
                    &open.authority,
                    open.owner_witness.as_ref().ok_or(Error::Locked)?,
                )?;
                return self.activate_writer_session(approved, epoch);
            }
            #[cfg(feature = "authority-signing")]
            Operation::Reconcile(prepared) => {
                let session = open.session.as_ref().ok_or(Error::Locked)?;
                let native = session.native_decision(decision)?;
                let approved = session.approve_writer_reconciliation(*prepared, native)?;
                let journal = open.journal.clone();
                return self.start_witness_job(epoch, move |cancelled| {
                    WitnessOutcome::Reconciled(if cancelled.load(Ordering::Acquire) {
                        Err(Error::Locked)
                    } else {
                        journal
                            .reconcile_writer(approved)
                            .map(|_| ())
                            .map_err(Error::from)
                    })
                });
            }
            #[cfg(feature = "authority-signing")]
            Operation::Witness(prepared) => {
                let witness = prepared.approve(decision, &open.authority, &open.vault)?;
                #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
                durable_review_v1::check_witness_descriptor(open, &witness.disclosure())?;
                open.witness = Some(Arc::new(witness));
                self.message = "Pinned witness client selected natively. Every exact reservation still needs a separate disclosure and spend decision.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::Disclosure { flow, review } => {
                let disclosure = review
                    .approve(decision, &open.authority)
                    .map_err(|_| Error::Authentication)?;
                let display = format!(
                    "AUTHORIZE EXACT VERIFIED SPEND\n{}\n\nCOMPLETE ACCEPTED MANIFEST\n{}\n\nAn independent witness reservation and current wallet checks are required before key use. This does not broadcast a transaction.",
                    serde_json::to_string_pretty(flow.prepared.record())
                        .map_err(|_| Error::InvalidData)?,
                    serde_json::to_string_pretty(
                        open.manifest.as_ref().ok_or(Error::ReviewMismatch)?
                    )
                    .map_err(|_| Error::InvalidData)?
                );
                self.pending = Some(PendingDecision {
                    review: ExactNativeReview::stage(
                        &open.authority,
                        flow.prepared.review_digest(),
                        display,
                        epoch,
                    )?,
                    operation: Operation::Spend {
                        flow,
                        disclosure: Box::new(disclosure),
                    },
                });
                self.message = "Exact witness disclosure accepted. Review and approve the separate exact spending decision next.";
            }
            #[cfg(feature = "authority-signing")]
            Operation::Spend { .. } | Operation::AutomaticDisclosure { .. } => unreachable!(),
            Operation::Pair(pair) => {
                open.ipc.approve_pairing(*pair, decision, &open.authority)?;
                self.message = "Local pairing approved. Waiting for the same live process to prove possession of the delivered channel key.";
            }
            Operation::Provider(prepared) => {
                prepared.export(decision, &open.authority, &self.provider_export_directory)?;
                self.message = "Native provider enrollment request saved privately. Administrative installation was not performed; this file alone grants no app authority.";
            }
            operation => {
                open.check_pairing()?;
                let session = open.session.as_ref().ok_or(Error::Locked)?;
                let decision = session.native_decision(decision)?;
                match operation {
                    #[cfg(all(
                        feature = "durable-proposal",
                        feature = "pending-birth-owner-signing"
                    ))]
                    Operation::DurableWitnessV1(_) => {
                        // The source-bound branch above handles this operation.
                        // Never route it through legacy journal approval.
                        return Err(Error::Unavailable);
                    }
                    #[cfg(all(
                        feature = "durable-proposal",
                        feature = "pending-birth-owner-signing"
                    ))]
                    Operation::DurableSpendV1 { .. }
                    | Operation::DurableDisclosureV1 { .. }
                    | Operation::DurableDeliveryV2(_)
                    | Operation::DurableDeliveryRedisclosureV2(_) => {
                        unreachable!()
                    }
                    Operation::Redelivery {
                        prepared,
                        peer,
                        mut stream,
                    } => {
                        peer.check_current()?;
                        let record = open.journal.record_result_redelivery(
                            session.approve_result_redelivery(*prepared, decision)?,
                        )?;
                        peer.check_current()?;
                        crate::authority_bridge::ipc::send_redelivery_reference(
                            &mut stream,
                            &record.reference_request(),
                        )?;
                        self.last_receipt = Some(record.reference().into());
                        self.message = "Exact retained-result redelivery recorded for this local process. The original consent and outstanding exposure are unchanged.";
                    }
                    Operation::Enroll(prepared) => {
                        let record = open
                            .journal
                            .record_enrollment(session.approve_enrollment(*prepared, decision)?)?;
                        self.last_receipt = Some(record.reference().into());
                        open.enrollment = Some(record);
                        self.message =
                            "Exact native enrollment committed in the encrypted signer journal.";
                    }
                    Operation::Manifest(prepared) => {
                        let record = open.journal.record_accepted_manifest(
                            session.approve_manifest(*prepared, decision)?,
                        )?;
                        self.last_receipt = Some(record.reference().into());
                        open.manifest = Some(record);
                        self.message = "Exact native manifest acceptance committed in the encrypted signer journal.";
                    }
                    Operation::Pair(_) | Operation::Provider(_) => unreachable!(),
                    #[cfg(feature = "durable-proposal")]
                    Operation::DurableConstructionV1(_) => unreachable!(),
                    #[cfg(all(
                        feature = "durable-proposal",
                        feature = "pending-birth-owner-signing"
                    ))]
                    Operation::DurableBornWalletV1(_) => unreachable!(),
                    #[cfg(all(
                        feature = "authority-signing",
                        feature = "offline-review-foundation"
                    ))]
                    Operation::BornHistory(_) | Operation::BornDispatch(_) => unreachable!(),
                    #[cfg(feature = "authority-signing")]
                    Operation::AutomationGrant(_)
                    | Operation::AutomationWitness(_)
                    | Operation::AutomaticDisclosure { .. }
                    | Operation::SponsorPolicy(_)
                    | Operation::Resolution(_)
                    | Operation::RecipientObservation(_)
                    | Operation::Recipient(_)
                    | Operation::ProvedDisclosure(_)
                    | Operation::OwnerInspection(_)
                    | Operation::NamedVerifierPolicy(_)
                    | Operation::Preconstruction(_)
                    | Operation::HostContinuity(_)
                    | Operation::HostContinuityV2(_)
                    | Operation::HostContinuityV3(_)
                    | Operation::HostContinuityV5(_)
                    | Operation::HostPublication(_)
                    | Operation::HostPublicationV2(_)
                    | Operation::HostPublicationV3(_)
                    | Operation::HostPublicationV5(_)
                    | Operation::Dispatch(_)
                    | Operation::Wallet(_)
                    | Operation::Witness(_)
                    | Operation::OwnerWitness(_)
                    | Operation::WriterSession(_)
                    | Operation::WriterActivation(_)
                    | Operation::Reconcile(_)
                    | Operation::Disclosure { .. }
                    | Operation::Spend { .. } => unreachable!(),
                }
            }
        }
        Ok(())
    }
    #[cfg(feature = "authority-signing")]
    fn automation_recipient_scope(
        open: &OpenAccount,
        record: &NativeAutomationGrantRecord,
    ) -> Result<Option<String>> {
        if record.status != wholepact_authority::AutomationGrantStatus::Active {
            return Ok(None);
        }
        let enrollment = open.enrollment.as_ref().ok_or(Error::ReviewMismatch)?;
        if record.enrollment_ref != enrollment.reference() {
            return Err(Error::Authentication);
        }
        let manifest = open.manifest.as_ref().ok_or(Error::ReviewMismatch)?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:signer-exact-authorization-recipient:v1",
            &(
                enrollment.transport(),
                AuthorizationDeliveryScope {
                    candidate_id: manifest.proposal_input().proposal_id.clone(),
                },
            ),
        )
        .map(Some)
        .map_err(|_| Error::InvalidData)
    }
    #[cfg(feature = "authority-signing")]
    fn inspect_original_automatic_request(&mut self, authorization_id: &str) -> Result<bool> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        open.check_pairing()?;
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        let Some(original) = open
            .journal
            .original_authorization(authorization_id, session)?
        else {
            return Ok(false);
        };
        let retained = authority_bridge::automation::retained_automatic_commit(
            &open.journal,
            session,
            authorization_id,
        );
        let state = match retained {
            Ok(Some(commit)) => {
                self.last_receipt = Some(commit.original_consent_ref);
                "Original result retained; exposure remains until independent canonical resolution."
            }
            _ => {
                "Original attempt outcome is uncertain; reconcile existing history and preserve exposure."
            }
        };
        self.automation.status = Some(Zeroizing::new(format!(
            "{}\nAuthorization ID: {}\nOriginal consent: {}\nRepeated delivery did not select inputs, reserve again or invoke signing. The original authenticated application uses RetrieveAuthorization/AcquireOriginalAuthorization; a changed recipient requests the separate native RequestResultRedelivery flow. Uncertain attempts retain exposure.",
            state,
            authorization_id,
            original.original_consent().reference()
        )));
        self.message = "Original automatic request found before wallet synchronization. Its retained result/status remains available through the original retrieval or separately reviewed redelivery routes; no new attempt was started.";
        Ok(true)
    }
    #[cfg(feature = "authority-signing")]
    fn automation_command(
        &mut self,
        command: super::automation_workspace::AutomationCommand,
        epoch: u64,
    ) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }
        use super::automation_workspace::AutomationCommand as C;
        if command == C::Authorize {
            let grant = self.automation.grant_id.to_string();
            if grant.is_empty() {
                return Err(Error::InvalidData);
            }
            let original_id = {
                let open = self.open.as_ref().ok_or(Error::Locked)?;
                open.check_pairing()?;
                let manifest = open.manifest.as_ref().ok_or(Error::ReviewMismatch)?;
                let bytes = self.incoming_pczt.as_ref().ok_or(Error::InvalidData)?;
                super::automatic_ipc::authorization_id(
                    &grant,
                    &manifest.proposal_input().proposal_id,
                    bytes,
                )?
            };
            if self.inspect_original_automatic_request(&original_id)? {
                self.incoming_pczt = None;
                return Ok(());
            }
            return self.start_wallet_review_mode(epoch, Some(grant));
        }
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        open.check_pairing()?;
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        if command == C::Inspect {
            let records = open.journal.automation_grants(session)?;
            let selected = if self.automation.grant_id.is_empty() {
                None
            } else {
                Some(self.automation.grant_id.as_str())
            };
            let attempts = open.journal.automation_attempts(selected, session)?;
            self.automation.status = Some(Zeroizing::new(format!(
                "RETAINED GRANTS\n{}\n\nRETAINED ATTEMPTS\n{}\n\nSettlement entries are recorded observations (canonical_consumed/reopened), not proof of current chain state. Use fresh independent settlement observation before relying on finality. Pending, reserved and key-use-uncertain attempts preserve exposure; retained results use the existing original-recipient retrieval or separately reviewed redelivery routes.",
                serde_json::to_string_pretty(&records).map_err(|_| Error::InvalidData)?,
                serde_json::to_string_pretty(&attempts).map_err(|_| Error::InvalidData)?
            )));
            return Ok(());
        }
        if open.witness_job.is_some() || open.wallet_job.is_some() || self.pending.is_some() {
            return Err(Error::Locked);
        }
        if command == C::Synchronize {
            let record = open
                .journal
                .automation_grant(&self.automation.grant_id, session)?
                .ok_or(Error::ReviewMismatch)?;
            let scope = Self::automation_recipient_scope(open, &record)?;
            let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
            let source = open.authority.binding();
            return self.start_witness_job(epoch, move |cancelled| {
                WitnessOutcome::AutomationPrepared(if cancelled.load(Ordering::Acquire) {
                    Err(Error::Locked)
                } else {
                    super::automation_workspace::PreparedGrantSynchronization::prepare(
                        record, scope, owner, source,
                    )
                    .map(Box::new)
                })
            });
        }
        let owner = open.owner_witness.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        let witness = open.witness.as_ref().ok_or(Error::Locked)?;
        witness.check_current()?;
        let (policy, terms, enrollment) = if matches!(command, C::Pause | C::Revoke) {
            let record = open
                .journal
                .automation_grant(&self.automation.grant_id, session)?
                .ok_or(Error::ReviewMismatch)?;
            let enrollment = open
                .journal
                .enrollment(&record.enrollment_ref, session)?
                .ok_or(Error::ReviewMismatch)?;
            (record.policy, record.terms, enrollment)
        } else {
            let policy = serde_json::from_str(&self.automation.policy_json)
                .map_err(|_| Error::InvalidData)?;
            let terms: wholepact_core::automation::AutomationGrantTerms =
                serde_json::from_str(&self.automation.terms_json)
                    .map_err(|_| Error::InvalidData)?;
            if terms.grant_id != *self.automation.grant_id {
                return Err(Error::ReviewMismatch);
            }
            let existing = open.journal.automation_grant(&terms.grant_id, session)?;
            if (command == C::Renew && existing.is_none())
                || (command == C::Activate && existing.is_some())
            {
                return Err(Error::ReviewMismatch);
            }
            (
                policy,
                terms,
                open.enrollment
                    .as_ref()
                    .ok_or(Error::ReviewMismatch)?
                    .clone(),
            )
        };
        let status = match command {
            C::Pause => wholepact_authority::AutomationGrantStatus::Paused,
            C::Revoke => wholepact_authority::AutomationGrantStatus::Revoked,
            _ => wholepact_authority::AutomationGrantStatus::Active,
        };
        let recipient_scope = if status == wholepact_authority::AutomationGrantStatus::Active {
            let manifest = open.manifest.as_ref().ok_or(Error::ReviewMismatch)?;
            Some(
                wholepact_core::proposal::canonical_digest(
                    "wholepact:signer-exact-authorization-recipient:v1",
                    &(
                        enrollment.transport(),
                        AuthorizationDeliveryScope {
                            candidate_id: manifest.proposal_input().proposal_id.clone(),
                        },
                    ),
                )
                .map_err(|_| Error::InvalidData)?,
            )
        } else {
            None
        };
        let descriptor = witness.disclosure();
        let prior = open.journal.automation_grant(&terms.grant_id, session)?;
        let owner = owner.clone();
        let session = session.clone();
        let journal = open.journal.clone();
        let source = open.authority.binding();
        self.message = "Checking the independently retained predecessor revision before preparing a new native grant decision. Unsynchronized revisions must be synchronized first.";
        self.start_witness_job(epoch, move |cancelled| {
            let result = (|| -> Result<_> {
                if cancelled.load(Ordering::Acquire) {
                    return Err(Error::Locked);
                }
                source.check_current()?;
                owner.check_current()?;
                let history = owner
                    .client()
                    .reconcile_history()
                    .map_err(|_| Error::Unavailable)?;
                let snapshot = history.snapshot();
                if snapshot.account_id != terms.account_id
                    || snapshot.writer_epoch != terms.writer_epoch
                    || snapshot.writer_certificate_digest == owner.writer_certificate_digest()
                {
                    return Err(Error::Authentication);
                }
                let previous = history.automation_grant(&terms.grant_id);
                match (&prior, previous) {
                    (None, None) => {}
                    (Some(local), Some(remote))
                        if local.binding == remote.binding && local.status == remote.status => {}
                    _ => return Err(Error::Uncertain),
                }
                let prepared = session.prepare_automation_grant(
                    &journal,
                    &enrollment,
                    policy,
                    terms,
                    SponsorWitnessBinding {
                        witness_id: descriptor.witness_id,
                        policy_digest: descriptor.policy_digest,
                        aggregate_budget_zatoshis: snapshot.aggregate_budget_zatoshis,
                    },
                    status,
                )?;
                super::automation_workspace::validate_grant_for_witness(
                    prepared.record(),
                    &history,
                    recipient_scope.as_deref(),
                )?;
                Ok(Box::new(prepared))
            })();
            WitnessOutcome::AutomationGrantPrepared(result)
        })
    }
    #[cfg(feature = "authority-signing")]
    fn stage_sponsor_policy(
        &mut self,
        status: crate::consent_journal::NativeSponsorPolicyStatus,
        update: bool,
        epoch: u64,
    ) -> Result<()> {
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_born_entry.is_some() || o.durable_delivery_entry.is_some())
        {
            return Err(Error::Unavailable);
        }
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        let replacement = if update {
            Some(serde_json::from_str(&self.sponsor_policy_terms).map_err(|_| Error::InvalidData)?)
        } else {
            None
        };
        let prepared = open.journal.prepare_sponsor_policy_change(
            &self.sponsor_policy_key,
            status,
            replacement,
            session,
            &open.authority.binding(),
        )?;
        let review = ExactNativeReview::stage(
            &open.authority,
            prepared.digest(),
            prepared.display()?,
            epoch,
        )?;
        self.pending = Some(PendingDecision {
            review,
            operation: Operation::SponsorPolicy(Box::new(prepared)),
        });
        Ok(())
    }
    fn exact_review_ui(&mut self, ui: &mut egui::Ui, focused: bool, epoch: u64) {
        if let Some(pending) = self.pending.as_mut() {
            ui.separator();
            ui.label(egui::RichText::new(pending.review.display()).monospace());
            if !pending.review.confirming() {
                if ui
                    .button("Continue after reviewing all exact terms")
                    .clicked_by(egui::PointerButton::Primary)
                    && pending
                        .review
                        .continue_from_native_click(focused, epoch)
                        .is_err()
                {
                    self.pending = None;
                    self.message = "Review was invalidated. Prepare it again.";
                }
            } else {
                let phrase = format!("AUTHORIZE {}", &pending.review.digest()[..12]);
                ui.label(format!("Type {phrase}"));
                ui.add(egui::TextEdit::singleline(&mut *self.confirmation).char_limit(64));
                if ui
                    .add_enabled(
                        *self.confirmation == phrase,
                        egui::Button::new("Confirm this exact native decision"),
                    )
                    .clicked_by(egui::PointerButton::Primary)
                    && self.approve(focused, epoch).is_err()
                {
                    self.message = "Decision rejected, expired, revoked or unable to commit. No substitute approval was created.";
                }
            }
            if ui
                .button("Reject and discard pending decision")
                .clicked_by(egui::PointerButton::Primary)
            {
                self.pending = None;
                self.confirmation.zeroize();
            }
        }
    }
    /// Same private transition for the focused primary-click branch below and
    /// explicit synthetic controller delivery. This is not a public token API.
    #[cfg(feature = "authority-signing")]
    fn begin_pending_birth_from_native_click(&mut self, focused: bool, epoch: u64) -> Result<()> {
        if !focused
            || self.open.is_some()
            || self.pending_account.is_some()
            || self.birth.is_active()
            || !self.closing_accounts.is_empty()
            || self.signing_job.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let entry = PendingBirthEntry {
            focus_epoch: epoch,
            parent_channel: self.parent_channel.clone(),
        };
        let result = self.birth.begin(
            entry,
            Path::new(&self.root),
            &self.password,
            &self.privacy_domain,
        );
        self.password.zeroize();
        self.message = if result.is_ok() {
            "Pending native birth started. No witness or application was contacted."
        } else {
            self.birth.clear();
            "Pending birth could not start. Check the new private target, password and native parent lifetime. No signer account was activated."
        };
        result
    }

    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn entered_pending_birth_for_qualification(
        root: &Path,
        privacy_domain: &str,
    ) -> Result<super::birth_workspace::NativeBirthCeremony> {
        let mut runtime = Self::new(None);
        runtime.root = root.to_str().ok_or(Error::InvalidData)?.to_owned();
        runtime.password = Zeroizing::new(
            super::birth_workspace::born_roster_v3::SYNTHETIC_PENDING_PASSWORD.into(),
        );
        runtime.privacy_domain = privacy_domain.into();
        // Rejected delivery must not create entropy, a private entry or owner.
        if runtime
            .begin_pending_birth_from_native_click(false, 1)
            .is_ok()
            || runtime.birth.is_active()
        {
            return Err(Error::ReviewMismatch);
        }
        runtime.begin_pending_birth_from_native_click(true, 1)?;
        Ok(std::mem::take(&mut runtime.birth))
    }

    #[cfg(feature = "pending-birth-owner-signing")]
    fn reopen_pending_from_native_click(&mut self, focused: bool, epoch: u64) -> Result<()> {
        if !focused
            || self.open.is_some()
            || self.pending_account.is_some()
            || self.birth.is_active()
            || self.pending_enrollment.is_active()
            || !self.closing_accounts.is_empty()
            || self.signing_job.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let entry = PendingBirthEntry {
            focus_epoch: epoch,
            parent_channel: self.parent_channel.clone(),
        };
        let result = self
            .pending_enrollment
            .begin(entry, Path::new(&self.root), &self.password);
        self.password.zeroize();
        self.message = if result.is_ok() {
            "Authenticating the exact pending envelope in a bounded native worker."
        } else {
            self.pending_enrollment.clear();
            "Pending reopen failed. Preserve the original directory unchanged; no account authority was granted."
        };
        result
    }

    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn entered_pending_continuation_for_qualification(
        root: &Path,
    ) -> Result<super::pending_enrollment::PendingEnrollmentUi> {
        let mut runtime = Self::new(None);
        runtime.root = root.to_str().ok_or(Error::InvalidData)?.to_owned();
        runtime.password = Zeroizing::new(
            super::birth_workspace::born_roster_v3::SYNTHETIC_PENDING_PASSWORD.into(),
        );
        if runtime.reopen_pending_from_native_click(false, 1).is_ok()
            || runtime.pending_enrollment.is_active()
        {
            return Err(Error::ReviewMismatch);
        }
        runtime.reopen_pending_from_native_click(true, 1)?;
        Ok(std::mem::take(&mut runtime.pending_enrollment))
    }

    #[cfg(feature = "pending-birth-owner-signing")]
    fn reopen_born_roster_from_native_click(&mut self, focused: bool, epoch: u64) -> Result<()> {
        if !focused
            || self.open.is_some()
            || self.pending_account.is_some()
            || self.birth.is_active()
            || self.pending_enrollment.is_active()
            || self.born_origin.is_active()
            || self.born_manual_roster_v2.is_active()
            || self.born_manual.is_active()
            || self.born_enrolled_backup.is_active()
            || !self.closing_accounts.is_empty()
            || self.signing_job.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let entry = PendingBirthEntry {
            focus_epoch: epoch,
            parent_channel: self.parent_channel.clone(),
        };
        let result = self
            .born_manual_roster_v2
            .begin(entry, Path::new(&self.root), &self.password);
        self.password.zeroize();
        self.message = if result.is_ok() {
            "Authenticating exact original born V2 roster source."
        } else {
            self.born_manual_roster_v2.clear();
            "V2 roster enrollment entry failed; original state preserved."
        };
        result
    }

    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn entered_born_roster_for_qualification(
        root: &Path,
    ) -> Result<super::born_manual_roster_v2::BornManualRosterUiV2> {
        let mut runtime = Self::new(None);
        runtime.root = root.to_str().ok_or(Error::InvalidData)?.to_owned();
        runtime.password = Zeroizing::new(
            super::birth_workspace::born_roster_v3::SYNTHETIC_PENDING_PASSWORD.into(),
        );
        if runtime
            .reopen_born_roster_from_native_click(false, 1)
            .is_ok()
            || runtime.born_manual_roster_v2.is_active()
        {
            return Err(Error::ReviewMismatch);
        }
        runtime.reopen_born_roster_from_native_click(true, 1)?;
        Ok(std::mem::take(&mut runtime.born_manual_roster_v2))
    }

    #[cfg(feature = "pending-birth-owner-signing")]
    fn reopen_born_single_from_native_click(&mut self, focused: bool, epoch: u64) -> Result<()> {
        if !focused
            || self.open.is_some()
            || self.pending_account.is_some()
            || self.birth.is_active()
            || self.pending_enrollment.is_active()
            || self.born_origin.is_active()
            || self.born_manual_roster_v2.is_active()
            || self.born_manual.is_active()
            || self.born_enrolled_backup.is_active()
            || !self.closing_accounts.is_empty()
            || self.signing_job.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let entry = PendingBirthEntry {
            focus_epoch: epoch,
            parent_channel: self.parent_channel.clone(),
        };
        let result = self
            .born_manual
            .begin(entry, Path::new(&self.root), &self.password);
        self.password.zeroize();
        self.message = if result.is_ok() {
            "Authenticating exact original born enrollment source."
        } else {
            self.born_manual.clear();
            #[cfg(feature = "pending-birth-owner-signing")]
            self.born_manual_roster_v2.clear();
            "Born manual enrollment entry failed; original state preserved."
        };
        result
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn entered_born_single_for_qualification(
        root: &Path,
    ) -> Result<super::born_manual::BornManualUi> {
        let mut runtime = Self::new(None);
        runtime.root = root.to_str().ok_or(Error::InvalidData)?.to_owned();
        runtime.password = Zeroizing::new(
            super::birth_workspace::born_roster_v3::SYNTHETIC_PENDING_PASSWORD.into(),
        );
        if runtime
            .reopen_born_single_from_native_click(false, 1)
            .is_ok()
            || runtime.born_manual.is_active()
        {
            return Err(Error::ReviewMismatch);
        }
        runtime.reopen_born_single_from_native_click(true, 1)?;
        Ok(std::mem::take(&mut runtime.born_manual))
    }

    pub(super) fn ui(&mut self, ui: &mut egui::Ui, focused: bool, epoch: u64) {
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        if self.open.as_ref().is_some_and(|o| o.born_bridge_active) {
            if !focused {
                self.lock();
                return;
            }
            self.poll_witness(epoch);
            self.poll(epoch);
            ui.label("Original born Host disclosure/dispatch channel is active. Only exact born bridge requests are admitted until it finishes.");
            self.exact_review_ui(ui, focused, epoch);
            ui.label(self.message);
            if ui
                .button("Lock and close born Host admission")
                .clicked_by(egui::PointerButton::Primary)
            {
                self.lock();
            }
            return;
        }
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        self.named_recipient.reap_cancelled();
        // A final recipient worker can hold the signer journal. Route its
        // event-thread cancellation/review before sibling polls or DB-backed UI.
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        if self.named_recipient.final_active() {
            if self
                .open
                .as_ref()
                .is_some_and(|open| !open.supports_ordinary_routes())
            {
                self.named_recipient.clear();
                self.message =
                    "This fresh durable entry cannot resume a named or legacy recipient workspace.";
                return;
            }
            if !focused {
                self.named_recipient.clear();
                return;
            }
            if let Some(open) = self.open.as_ref() {
                if let Some(session) = open.session.as_ref() {
                    let owner = super::wallet_workspace::NamedRecipientOwnerContext {
                        journal: &open.journal,
                        session,
                        enrollment_ref: open.enrollment.as_ref().map_or("", |r| r.reference()),
                        manifest_ref: open.manifest.as_ref().map_or("", |r| r.reference()),
                        vault: &open.vault,
                        authority: &open.authority,
                        #[cfg(feature = "pending-birth-owner-signing")]
                        born: None,
                    };
                    self.named_recipient.final_ui(
                        ui,
                        &owner,
                        open.wallet.as_ref(),
                        open.witness.as_ref(),
                        focused,
                        epoch,
                    );
                } else {
                    self.named_recipient.clear();
                }
            } else {
                self.named_recipient.clear();
            }
            return;
        }
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        self.named_verifier.poll_lifecycle(focused);

        #[cfg(feature = "authority-signing")]
        self.retirement_evidence_session
            .poll_lifecycle(focused, epoch);
        #[cfg(feature = "authority-signing")]
        self.retirement_evidence.poll_lifecycle(focused, epoch);
        #[cfg(feature = "authority-signing")]
        self.quarantined_history.poll_lifecycle(focused, epoch);
        #[cfg(feature = "authority-signing")]
        self.retirement_witness.poll_lifecycle(focused, epoch);
        #[cfg(feature = "pending-birth-owner-signing")]
        self.pending_enrollment.poll_lifecycle(focused, epoch);
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_origin.poll_lifecycle(focused, epoch);
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_manual.poll_lifecycle(focused, epoch);
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_manual_roster_v2.poll_lifecycle(focused, epoch);
        #[cfg(feature = "pending-birth-owner-signing")]
        self.born_enrolled_backup.poll_lifecycle(focused, epoch);
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        {
            self.poll_durable_entry_v1(focused, epoch);
            self.poll_durable_delivery_entry_v2(focused, epoch);
        }
        if !focused {
            #[cfg(feature = "authority-signing")]
            self.birth.clear();
            ui.label("Private signer details hidden while unfocused. No new native requests are admitted.");
            return;
        }
        #[cfg(feature = "authority-signing")]
        {
            self.poll_recipient();
            self.poll_signing();
            self.poll_wallet(epoch);
            self.poll_witness(epoch);
        }
        #[cfg(feature = "authority-signing")]
        if self.retirement_evidence_session.has_content() {
            self.retirement_evidence_session.ui(ui, focused, epoch);
            return;
        }
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        if self.named_verifier.is_active() {
            self.named_verifier.ui(ui, focused, epoch);
            return;
        }
        self.poll(epoch);
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        {
            self.poll_durable_import_v1(epoch);
            self.poll_durable_wallet_review_v1(epoch);
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.durable_wallet_job.is_some() || o.durable_import_job.is_some())
        {
            ui.label(self.message);
            ui.label("The bounded exact durable import or wallet check is in progress. Lock remains available.");
            return;
        }
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
        if self.durable_entry_job.is_some() {
            ui.label("Authenticating the original durable born source in a bounded worker. Lock, navigation or focus loss cancels entry; no old approval is restored.");
            return;
        }
        #[cfg(feature = "authority-signing")]
        if self.signing_job.is_some() {
            ui.label(self.message);
            ui.label("The exact admitted authorization is still in progress. Lock remains available; new requests wait for completion.");
            return;
        }
        #[cfg(feature = "authority-signing")]
        if self.open.as_ref().is_some_and(|o| o.wallet_job.is_some()) {
            ui.label(self.message);
            ui.label("Local synchronization and authenticated witness observation are running. Lock and navigation cancel the pending review safely.");
            return;
        }
        #[cfg(feature = "authority-signing")]
        if self.open.as_ref().is_some_and(|o| o.witness_job.is_some()) {
            ui.label(self.message);
            ui.label("Independent witness operation is running. New reviews wait; Lock and navigation remain available.");
            return;
        }
        #[cfg(feature = "authority-signing")]
        if self
            .open
            .as_ref()
            .is_some_and(|o| o.host_continuity_worker.is_some())
        {
            ui.label(self.message);
            ui.label("A bounded host recovery inspection or publication admission is in progress. Lock remains available. Informational publication releases the signer fence before the host writes; no financial authority is granted.");
            return;
        }
        ui.label("Linux native signer session. Trust assumptions: correctly operating installed signer, OS, and Wayland compositor. Local pairing needs Linux SO_PEERPIDFD support. No remote publisher or human-origin attestation is claimed.");
        ui.separator();
        if !self.closing_accounts.is_empty() {
            ui.label("Lock is pending while an already-admitted operation completes. New account sessions are blocked; this window remains responsive.");
            return;
        }
        #[cfg(feature = "authority-signing")]
        if self.birth.is_active() {
            if let Some(message) = self.birth.ui(ui, focused, epoch) {
                self.message = message;
            }
            return;
        }
        #[cfg(feature = "pending-birth-owner-signing")]
        if self.pending_enrollment.is_active() {
            if let Some(message) = self.pending_enrollment.ui(ui, focused, epoch) {
                self.message = message;
            }
            return;
        }
        #[cfg(feature = "pending-birth-owner-signing")]
        if self.born_origin.is_active() {
            if let Some(message) = self.born_origin.ui(ui, focused, epoch) {
                self.message = message;
            }
            return;
        }
        #[cfg(feature = "pending-birth-owner-signing")]
        if self.born_manual_roster_v2.is_active() {
            if let Some(message) = self.born_manual_roster_v2.ui(ui, focused, epoch) {
                self.message = message;
            }
            return;
        }
        #[cfg(feature = "pending-birth-owner-signing")]
        if self.born_manual.is_active() {
            if let Some(message) = self.born_manual.ui(ui, focused, epoch) {
                self.message = message;
            }
            return;
        }
        #[cfg(feature = "pending-birth-owner-signing")]
        if self.born_enrolled_backup.is_active() {
            if let Some(message) = self.born_enrolled_backup.ui(ui, focused, epoch) {
                self.message = message;
            }
            return;
        }
        #[cfg(feature = "authority-signing")]
        if self.quarantined_history.is_active() {
            self.quarantined_history.ui(ui, focused, epoch);
            return;
        }
        if self.open.is_none() {
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            if self.pending_account.is_none()
                && ui
                    .button("Open optional named-verifier workspace")
                    .clicked_by(egui::PointerButton::Primary)
                && focused
            {
                self.named_verifier.begin();
                return;
            }
            ui.label("Account directory (entered only in this native window)");
            if ui
                .add(egui::TextEdit::singleline(&mut self.root).char_limit(4096))
                .changed()
            {
                #[cfg(feature = "authority-signing")]
                {
                    self.quarantined_history.clear();
                    self.retirement_evidence_session.clear();
                }
            }
            ui.label("Vault password (never transmitted to applications)");
            ui.add(
                egui::TextEdit::singleline(&mut *self.password)
                    .password(true)
                    .char_limit(1024),
            );
            #[cfg(feature = "authority-signing")]
            if self.pending_account.is_none() {
                self.recovery_controls(ui, focused, epoch);
                if self.recovery_activation.is_active() {
                    return;
                }
                self.retirement_entry_controls(ui, focused, epoch);
                if self.retirement_evidence_session.has_content() {
                    return;
                }
            }
            if self.pending_account.is_none() {
                #[cfg(feature = "pending-birth-owner-signing")]
                {
                    if self.born_manual_roster_v2.has_dormant_named() {
                        ui.label("Exact consumed named payment is key-free. A new native entry does not renew its original financial deadlines.");
                        if ui
                            .button("Unlock exact consumed account for named payment")
                            .clicked_by(egui::PointerButton::Primary)
                            && focused
                        {
                            let _ = self.reopen_consumed_named_from_native_click(focused, epoch);
                            return;
                        }
                    }
                    if self.born_manual_roster_v2.has_dormant_common_context() {
                        ui.label("One admitted read retains a key-free completion. Fresh unlock cannot renew its deadline.");
                        if ui
                            .button("Unlock exact original account for admitted completion")
                            .clicked_by(egui::PointerButton::Primary)
                            && focused
                        {
                            let _ =
                                self.reopen_born_common_context_from_native_click(focused, epoch);
                            return;
                        }
                    }
                    ui.label("Permanent stop of routine reuse preserves the original born V2 vault, all pending exposure, exact witness exclusion and named Host acknowledgment. Activation is unavailable until attended native/kernel qualification.");
                    if ui
                        .button("Reopen original born V2 account for permanent stop / exact retry")
                        .clicked_by(egui::PointerButton::Primary)
                        && focused
                    {
                        let entry = PendingBirthEntry {
                            focus_epoch: epoch,
                            parent_channel: self.parent_channel.clone(),
                        };
                        let result = self.born_manual_roster_v2.begin_permanent_stop(
                            entry,
                            Path::new(&self.root),
                            &self.password,
                        );
                        self.password.zeroize();
                        self.message = if result.is_ok() {
                            "Opening exact original born restriction source."
                        } else {
                            "Permanent-stop entry is unavailable; no original state or owner was changed."
                        };
                        return;
                    }
                    ui.label("Separate V2 Host roster enrollment preserves the original born account, policy, lifetime ledger and exact Host roster predecessor. It grants no financial, inventory or selection permission.");
                    if ui
                        .button("Reopen original born account for exact Host roster enrollment V2")
                        .clicked_by(egui::PointerButton::Primary)
                        && focused
                    {
                        let _ = self.reopen_born_roster_from_native_click(focused, epoch);
                        return;
                    }
                    ui.label("Separate original-born manual enrollment privately reads the immutable birth and policy, opens a bounded local pairing endpoint, and reviews one exact paired host generation and agreement. It never activates financial/key-release permission.");
                    if ui
                        .button("Reopen original born account for exact manual enrollment")
                        .clicked_by(egui::PointerButton::Primary)
                        && focused
                    {
                        let _ = self.reopen_born_single_from_native_click(focused, epoch);
                        return;
                    }
                    ui.label("Complete enrolled backup/restore reads private birth, enrollment and encrypted journal history. Explicit V1 and V2 roster source entries support only exact initial schema-13 enrolled history; later activity fails closed. Restored history stays inert and financially denied.");
                    for (label, mode) in [
                        ("Reopen enrolled source for complete backup", 0u8),
                        (
                            "Review enrolled backup for inert complete-history restore",
                            1,
                        ),
                        ("Audit restored enrolled history capsule", 2),
                        ("Reopen V2 roster enrolled source for complete backup", 3),
                    ] {
                        if ui.button(label).clicked_by(egui::PointerButton::Primary) && focused {
                            let entry = PendingBirthEntry {
                                focus_epoch: epoch,
                                parent_channel: self.parent_channel.clone(),
                            };
                            let result = match mode {
                                0 => self.born_enrolled_backup.begin(
                                    entry,
                                    Path::new(&self.root),
                                    &self.password,
                                ),
                                1 => self.born_enrolled_backup.begin_recovery(
                                    entry,
                                    Path::new(&self.root),
                                    &self.password,
                                ),
                                3 => self.born_enrolled_backup.begin_roster_v2(
                                    entry,
                                    Path::new(&self.root),
                                    &self.password,
                                ),
                                _ => self.born_enrolled_backup.begin_restored_audit(
                                    entry,
                                    Path::new(&self.root),
                                    &self.password,
                                ),
                            };
                            self.password.zeroize();
                            self.message = if result.is_ok() {
                                "Preparing bounded complete enrolled-history review."
                            } else {
                                self.born_enrolled_backup.clear();
                                "Enrolled history entry failed; no fallback or financial authority created."
                            };
                            return;
                        }
                    }
                    ui.label("For born-backup recovery, the directory and password above refer to the existing private backup package and its recovery password. Reading private contents and publishing a restored target require two separate exact reviews.");
                    if ui
                        .button("Review born backup for original-origin restore")
                        .clicked_by(egui::PointerButton::Primary)
                        && focused
                    {
                        let entry = PendingBirthEntry {
                            focus_epoch: epoch,
                            parent_channel: self.parent_channel.clone(),
                        };
                        let result = self.born_origin.begin_recovery(
                            entry,
                            Path::new(&self.root),
                            &self.password,
                        );
                        self.password.zeroize();
                        self.message = if result.is_ok() {
                            "Preparing the exact private backup disclosure review. No restored target exists yet."
                        } else {
                            self.born_origin.clear();
                            #[cfg(feature = "pending-birth-owner-signing")]
                            self.born_manual.clear();
                            #[cfg(feature = "pending-birth-owner-signing")]
                            self.born_manual_roster_v2.clear();
                            #[cfg(feature = "pending-birth-owner-signing")]
                            self.born_enrolled_backup.clear();
                            "Born backup inspection failed. No fallback vault or restored target was created."
                        };
                        return;
                    }
                    ui.label("Separate acknowledged-origin audit reads the private immutable birth and witness record in the selected directory. It cannot activate enrollment or financial authority.");
                    if ui
                        .button("Reopen acknowledged origin for private audit / backup")
                        .clicked_by(egui::PointerButton::Primary)
                        && focused
                    {
                        let entry = PendingBirthEntry {
                            focus_epoch: epoch,
                            parent_channel: self.parent_channel.clone(),
                        };
                        let result =
                            self.born_origin
                                .begin(entry, Path::new(&self.root), &self.password);
                        self.password.zeroize();
                        self.message = if result.is_ok() {
                            "Authenticating acknowledged origin for private audit only."
                        } else {
                            self.born_origin.clear();
                            #[cfg(feature = "pending-birth-owner-signing")]
                            self.born_manual.clear();
                            #[cfg(feature = "pending-birth-owner-signing")]
                            self.born_manual_roster_v2.clear();
                            #[cfg(feature = "pending-birth-owner-signing")]
                            self.born_enrolled_backup.clear();
                            "Acknowledged-origin audit failed. No pending/legacy fallback or financial authority was created."
                        };
                        return;
                    }
                }
                #[cfg(feature = "pending-birth-owner-signing")]
                if ui
                    .button(
                        "Reopen authenticated pending account: request / export / acknowledgement",
                    )
                    .clicked_by(egui::PointerButton::Primary)
                    && focused
                {
                    let _ = self.reopen_pending_from_native_click(focused, epoch);
                    return;
                }
                #[cfg(feature = "authority-signing")]
                ui.collapsing("Quarantined signer-only historical review", |ui| {
                    ui.label("Restricted historical read only: current original restored signer-only sources and their exact archive. Generic unlock stays denied. Wallet-bearing, born, successor and incomplete sources are unsupported. The original 120-second source lifetime includes all reviews; attended timing remains unqualified.");
                    if self.quarantined_history.has_dormant_continuity() {
                        ui.label("Completed continuity remains only as an inert restriction for one fresh publication entry with these unchanged paths and the original expiry. Switching paths, Lock, Cancel or closing the window erases it.");
                    }
                    ui.label("Exact original encrypted archive directory");
                    if ui.add(egui::TextEdit::singleline(&mut self.informational_archive).char_limit(4096)).changed() { self.quarantined_history.clear(); }
                    ui.label("Original archive passphrase");
                    ui.add(egui::TextEdit::singleline(&mut *self.informational_password).password(true).char_limit(1024));
                    ui.label("Separate private runtime directory, outside both retained source trees");
                    if ui.add(egui::TextEdit::singleline(&mut self.informational_runtime_directory).char_limit(4096)).changed() { self.quarantined_history.clear(); }
                    let informational_endpoint = Path::new(&self.informational_runtime_directory)
                        .join(crate::ipc::QUARANTINED_INFORMATIONAL_SOCKET_BASENAME);
                    ui.label(format!("Exact restricted endpoint for Host pre-entry review: {}", informational_endpoint.display()));
                    ui.label("Review this exact endpoint in the Host before entering here. No listener exists until this private runtime path and original source authenticate; an occupied endpoint is refused.");
                    if ui.button("Enter restricted historical review").clicked_by(egui::PointerButton::Primary) && focused {
                        let result = self.quarantined_history.begin(
                            Path::new(&self.root), self.password.as_bytes(),
                            Path::new(&self.informational_archive), self.informational_password.as_bytes(),
                            Path::new(&self.informational_runtime_directory), focused, epoch,
                            self.parent_channel.clone(),
                        );
                        self.password.zeroize();
                        self.informational_password.zeroize();
                        self.message = if result.is_ok() { "Opening exact historical source for separately approved reads." }
                            else { "Restricted historical entry was refused. No writer session or financial authority was created." };
                    }
                });
                #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
                if ui
                    .button("Fresh v2 prospective delivery admission / original history")
                    .clicked_by(egui::PointerButton::Primary)
                    && focused
                {
                    let _ = self.begin_durable_delivery_entry_v2(focused, epoch);
                    return;
                }
                #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
                if ui
                    .button("Fresh entry to original born account for fixed durable proposal")
                    .clicked_by(egui::PointerButton::Primary)
                    && focused
                {
                    if self.begin_durable_entry_v1(focused, epoch).is_err() {
                        self.password.zeroize();
                        self.message = "Fresh durable entry refused. Preserve the original account and journal; no native receipt, writer or key permission was restored.";
                    }
                    return;
                }
                if ui
                    .button("Unlock existing dedicated account")
                    .clicked_by(egui::PointerButton::Primary)
                    && focused
                    && self.unlock().is_err()
                {
                    self.password.zeroize();
                    #[cfg(feature = "authority-signing")]
                    {
                        self.recovery_password.zeroize();
                        self.recovery_repeat.zeroize();
                        self.recovery_confirmation.zeroize();
                    }
                    self.message =
                        "Unlock failed or the journal needs recovery. No session was granted.";
                }
                ui.separator();
                ui.label("New dedicated testnet account: exact privacy domain");
                ui.add(egui::TextEdit::singleline(&mut self.privacy_domain).char_limit(128));
                ui.label("Creation generates a new dedicated BIP39 account in this signer. Record and verify its backup; this does not fund, connect to a network or send a payment.");
                #[cfg(feature = "authority-signing")]
                {
                    ui.label("Separate pending-birth ceremony: pin the original independent witness origin and full policy terms before any usable vault exists. This saves only a blocked encrypted pending account. Independent witness enrollment and acknowledgement require the separate pending continuation flow when included; financial activation remains unavailable.");
                    if ui
                        .button("Begin pending birth: generate and verify backup")
                        .clicked_by(egui::PointerButton::Primary)
                        && focused
                    {
                        let _ = self.begin_pending_birth_from_native_click(focused, epoch);
                        return;
                    }
                }
                #[cfg(feature = "authority-signing")]
                ui.label("Ordinary creation below remains legacy/unknown for immutable birth provenance and cannot satisfy distinct-authority successor enrollment.");
                if ui
                    .button("Create new dedicated account and show backup")
                    .clicked_by(egui::PointerButton::Primary)
                    && focused
                    && self.create().is_err()
                {
                    self.message = "Account preparation failed. Check a new private directory, privacy domain and password of at least 12 characters.";
                }
            } else {
                ui.colored_label(egui::Color32::YELLOW, "PRIVATE RECOVERY WORDS. Anyone with them controls this dedicated account. Do not share them with an application.");
                ui.label(self.recovery.as_str());
                ui.label("Re-enter all 24 recovery words before saving");
                ui.add(egui::TextEdit::multiline(&mut *self.backup).char_limit(1024));
                if ui
                    .button("Verify backup and save encrypted account")
                    .clicked_by(egui::PointerButton::Primary)
                    && focused
                    && self.finish_create().is_err()
                {
                    self.recovery.zeroize();
                    self.backup.zeroize();
                    self.password.zeroize();
                    #[cfg(feature = "authority-signing")]
                    {
                        self.recovery_password.zeroize();
                        self.recovery_repeat.zeroize();
                        self.recovery_confirmation.zeroize();
                    }
                    self.message = "Backup or encrypted journal setup failed. No authorization session was granted; inspect the directory before retrying.";
                }
            }
        } else {
            #[cfg(feature = "authority-signing")]
            if ui
                .button("Lock ordinary account before dedicated retirement evidence")
                .clicked_by(egui::PointerButton::Primary)
                && focused
            {
                self.lock_for_retirement_entry();
                return;
            }
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            if self.durable_delivery_ui_v2(ui, focused, epoch)
                || self.durable_witness_ui_v1(ui, focused, epoch)
            {
                return;
            }
            let open = self.open.as_ref().unwrap();
            #[cfg(feature = "authority-signing")]
            if self.pending.is_none() && open.supports_ordinary_routes() {
                self.retirement_evidence
                    .ui(ui, &open.vault, &open.authority, focused, epoch);
                self.retirement_witness.ui(
                    ui,
                    &open.vault,
                    &open.authority,
                    open.witness.as_ref(),
                    focused,
                    epoch,
                );
            }
            ui.label(format!(
                "Unlocked account: {}",
                open.vault.account_id().unwrap_or_default()
            ));
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing"))]
            if open.durable_review.is_some()
                && self.pending.is_none()
                && ui
                    .button("Review exact imported durable proposal with fresh wallet and witness")
                    .clicked_by(egui::PointerButton::Primary)
                && focused
            {
                if self.start_durable_wallet_review_v1(epoch).is_err() {
                    self.message = "Fresh durable review unavailable. Preserve the same fixed proposal and all existing exposure; no replacement inputs or approval were created.";
                }
                return;
            }
            ui.label(format!(
                "Request-only Unix endpoint: {}",
                inert_text(&open.ipc.socket_path().display().to_string())
            ));
            if let Some(paired) = &open.pairing {
                ui.label(format!(
                    "Native-selected local process: {} (UID {}, PID {})",
                    inert_text(&paired.peer.label),
                    paired.peer.peer.uid(),
                    paired.peer.peer.pid()
                ));
            }
            #[cfg(feature = "authority-signing")]
            if let Some(witness) = &open.witness {
                let descriptor = witness.disclosure();
                ui.label(format!(
                    "Selected witness: {} at {}",
                    inert_text(&descriptor.witness_id),
                    inert_text(&descriptor.endpoint)
                ));
            }
            let selected_grant = open.pairing.as_ref().map(|p| p.peer.grant_id.clone());
            if selected_grant.is_some()
                && ui
                    .button("Revoke this paired process")
                    .clicked_by(egui::PointerButton::Primary)
                && focused
            {
                let open = self.open.as_mut().unwrap();
                open.ipc.revoke(selected_grant.as_deref().unwrap());
                open.invalidate_review();
                self.pending = None;
                self.message = "Selected process revoked. Already-admitted operations must finish before revocation completes.";
            }
            if ui
                .button("Revoke all paired applications")
                .clicked_by(egui::PointerButton::Primary)
                && focused
            {
                let open = self.open.as_mut().unwrap();
                open.invalidate_review();
                open.ipc.revoke_all();
                open.pairing = None;
                self.pending = None;
                self.message = "All local application grants revoked.";
            }
            if self.pending.is_none() {
                ui.label("Complete ProposalInput JSON for exact account enrollment and manifest acceptance (128 KiB maximum)");
                ui.add(
                    egui::TextEdit::multiline(&mut *self.proposal)
                        .char_limit(131_072)
                        .desired_rows(6),
                );
                ui.label("Aggregate account budget in integer zatoshis");
                ui.add(egui::TextEdit::singleline(&mut self.budget).char_limit(16));
                if ui
                    .button("Review exact account enrollment")
                    .clicked_by(egui::PointerButton::Primary)
                    && focused
                    && self.stage_enrollment(epoch).is_err()
                {
                    self.message = "Enrollment requires a current paired process, exact matching proposal scope and valid budget.";
                }
                if ui
                    .button("Review exact manifest acceptance")
                    .clicked_by(egui::PointerButton::Primary)
                    && focused
                    && self.stage_manifest(epoch).is_err()
                {
                    self.message = "Manifest review requires the current session's original enrollment and exact validated proposal.";
                }
            }
        }
        #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
        if self.pending.is_none()
            && self
                .open
                .as_ref()
                .is_some_and(OpenAccount::supports_ordinary_routes)
        {
            if let Some(open) = self.open.as_ref() {
                if let Some(session) = open.session.as_ref() {
                    let owner = super::wallet_workspace::NamedRecipientOwnerContext {
                        journal: &open.journal,
                        session,
                        enrollment_ref: open.enrollment.as_ref().map_or("", |r| r.reference()),
                        manifest_ref: open.manifest.as_ref().map_or("", |r| r.reference()),
                        vault: &open.vault,
                        authority: &open.authority,
                        #[cfg(feature = "pending-birth-owner-signing")]
                        born: None,
                    };
                    self.named_recipient.ui(
                        ui,
                        &owner,
                        open.wallet.as_ref(),
                        open.witness.as_ref(),
                        focused,
                        epoch,
                    );
                    if self.named_recipient.final_active() {
                        return;
                    }
                }
            }
        }
        #[cfg(feature = "authority-signing")]
        if self.open.is_some() && self.pending.is_none() {
            egui::CollapsingHeader::new("Signer-local wallet and witness configuration").show(ui,|ui|{
                ui.label("Exact native wallet configuration JSON. The selected public provider and privacy policy are reviewed before any import or network contact.");
                ui.add(egui::TextEdit::multiline(&mut *self.wallet_setup).char_limit(131_072).desired_rows(4));
                if ui.button("Review local wallet setup").clicked_by(egui::PointerButton::Primary)&&focused && self.stage_wallet_setup(epoch).is_err() {self.message="Wallet setup was invalid. No provider contact or account import was performed.";}
                ui.label("Exact witness configuration JSON. Credential file paths are selected locally; do not paste secret key contents.");
                ui.add(egui::TextEdit::multiline(&mut *self.witness_setup).char_limit(16_384).desired_rows(4));
                if ui.button("Review pinned witness setup").clicked_by(egui::PointerButton::Primary)&&focused && self.stage_witness_setup(epoch).is_err() {self.message="Witness setup or selected private credentials were invalid. No network request was made.";}
            });
            if let Some(command) = self.automation.ui(ui, focused) {
                if self.automation_command(command, epoch).is_err() {
                    self.message = "Automation action requires current enrolled application/account, exact scope, active session, wallet and independent witness. No substitute consent was created.";
                }
            }
            egui::CollapsingHeader::new("Native sponsor policy controls").show(ui, |ui| {
                ui.label("Policy key from the native accepted sponsor binding");
                ui.text_edit_singleline(&mut self.sponsor_policy_key);
                ui.label("Exact replacement policy terms (JSON), used only by Update");
                ui.add(egui::TextEdit::multiline(&mut *self.sponsor_policy_terms).char_limit(32768).desired_rows(4));
                use crate::consent_journal::NativeSponsorPolicyStatus as S;
                for (label,status,update) in [("Review pause",S::Paused,false),("Review permanent revoke",S::Revoked,false),("Review resume as new version",S::Active,false),("Review exact policy update",S::Active,true)] {
                    if ui.button(label).clicked_by(egui::PointerButton::Primary) && focused && self.stage_sponsor_policy(status,update,epoch).is_err() {
                        self.message = "Policy review failed. Use a current native session and an existing policy key; revoked policies cannot be resumed.";
                    }
                }
            });
            egui::CollapsingHeader::new("Independent settlement source and exact resolution").show(ui, |ui| {
                ui.label("Signer node JSON: source_id, loopback endpoint, server_name, pinned_certificate_sha256, trusted_root_der, client_certificate_der, client_private_key_pkcs8_der, required_confirmations, and complete witness_source descriptor. Select private local files; never paste credential contents.");
                ui.add(egui::TextEdit::multiline(&mut *self.resolution_setup).char_limit(32768).desired_rows(4));
                if ui.button("Review signer resolution source").clicked_by(egui::PointerButton::Primary) && focused && self.stage_resolution(0,epoch).is_err() { self.message="Source setup failed. Existing private credentials and an active native consent session are required; no node was contacted."; }
                ui.label("Complete independent witness LocalNodeSourceDescriptor JSON. The separately selected owner credential must approve enrollment; the witness operator attaches its own matching node.");
                ui.add(egui::TextEdit::multiline(&mut *self.witness_resolution_setup).char_limit(32768).desired_rows(4));
                if ui.button("Inspect owner state and review witness source enrollment").clicked_by(egui::PointerButton::Primary) && focused && self.stage_resolution(1,epoch).is_err() { self.message="Owner source review could not start. Select the independent owner-control client first."; }
                ui.label("Original authorization ID"); ui.text_edit_singleline(&mut *self.resolution_authorization);
                ui.label("Retained dispatch operation ID"); ui.text_edit_singleline(&mut *self.resolution_dispatch);
                ui.label("Signer-enrolled source reference"); ui.text_edit_singleline(&mut *self.resolution_source_reference);
                if ui.button("Review exact original settlement observation").clicked_by(egui::PointerButton::Primary) && focused && self.stage_resolution(2,epoch).is_err() { self.message="Exact original authorization, retained dispatch, enrolled source and current witness/session are required. No supplied settlement claim was accepted."; }
            });
            egui::CollapsingHeader::new("Fresh writer session and independent owner activation").show(ui, |ui| {
                ui.label("Separate owner-client configuration JSON. Select an existing owner credential only for independent session activation; this does not replace the writer client.");
                ui.add(egui::TextEdit::multiline(&mut *self.owner_witness_setup).char_limit(16_384).desired_rows(3));
                if ui.button("Review separate owner-control client").clicked_by(egui::PointerButton::Primary) && focused && self.stage_owner_witness_setup(epoch).is_err() {
                    self.message = "Owner client setup failed or an exact activation retry is pending.";
                }
                if ui.button("Inspect full history and review a fresh writer session").clicked_by(egui::PointerButton::Primary) && focused && self.prepare_writer_session(epoch).is_err() {
                    self.message = "Session preparation requires a current writer client and no retained session/retry. Never replace an uncertain session automatically.";
                }
                if self.open.as_ref().is_some_and(|o| o.writer_retry.is_some()) && ui.button("Retry identical approved writer-session request").clicked_by(egui::PointerButton::Primary) && focused {
                    let retry = self.open.as_mut().unwrap().writer_retry.take().unwrap();
                    if self.acquire_writer_session(retry, epoch).is_err() { self.message = "Exact retry could not start. No replacement was created."; }
                }
                if ui.button("Review independent owner activation of this exact session").clicked_by(egui::PointerButton::Primary) && focused && self.prepare_writer_activation(epoch).is_err() {
                    self.message = "Activation requires the original pending session receipt and separately selected owner client.";
                }
                if self.open.as_ref().is_some_and(|o| o.activation_retry.is_some()) && ui.button("Retry identical approved owner activation").clicked_by(egui::PointerButton::Primary) && focused {
                    let retry = self.open.as_mut().unwrap().activation_retry.take().unwrap();
                    if self.activate_writer_session(retry, epoch).is_err() { self.message = "Exact owner retry could not start. No replacement was created."; }
                }
                if ui.button("Review complete writer history and local journal reconciliation").clicked_by(egui::PointerButton::Primary) && focused && self.prepare_writer_reconciliation(epoch).is_err() {
                    self.message = "Reconciliation requires a current native session and its independently activated witness client.";
                }
            });
            ui.label("Untrusted construction context JSON for the current requested PCZT. Account keys and transaction effects are independently reconciled with the local wallet and accepted manifest.");
            ui.add(
                egui::TextEdit::multiline(&mut *self.review_context)
                    .char_limit(2_097_152)
                    .desired_rows(5),
            );
            if ui
                .button("Synchronize locally and prepare exact requested spend")
                .clicked_by(egui::PointerButton::Primary)
                && focused
                && self.start_wallet_review(epoch).is_err()
            {
                self.message = "Spend preparation requires current pairing, accepted manifest, requested PCZT, native wallet and witness setup.";
            }
        }
        if self.open.is_some() && self.pending.is_none() {
            egui::CollapsingHeader::new("Prepare installed signer trust anchor").show(ui, |ui| {
                ui.label("Root-owned installed signer executable path");
                ui.add(egui::TextEdit::singleline(&mut self.provider_image).char_limit(4096));
                ui.label("New private export directory (no system installation here)");
                ui.add(egui::TextEdit::singleline(&mut self.provider_export_directory).char_limit(4096));
                if ui.button("Review exact installed-provider enrollment").clicked_by(egui::PointerButton::Primary) && focused && self.stage_provider(epoch).is_err() { self.message = "Provider preparation failed. Select a root-owned, non-group/other-writable installed executable."; }
            });
        }
        #[cfg(feature = "authority-signing")]
        if self.open.is_some() && self.pending.is_none() {
            egui::CollapsingHeader::new("Recipient: issue instructions and verify incoming payment").show(ui, |ui| {
                ui.label("Independent recipient workflow: no coordinator or contributor records required. Uses only this unlocked account's viewing key inside the signer.");
                ui.label("Receiving instructions JSON: reference, network_profile_id, denomination (ZEC), destination, amount_zatoshis, memo (null or text), valid_until_unix_seconds. Pasted text is untrusted until the separate native owner review.");
                ui.add(egui::TextEdit::multiline(&mut *self.recipient_instructions).char_limit(16384));
                if ui.button("Review and issue own receiving instructions").clicked_by(egui::PointerButton::Primary) && focused && self.stage_recipient(true, epoch).is_err() {
                    self.message = "Instructions are invalid, expired, already recorded, or do not belong to this account.";
                }
                ui.label("Previously issued instruction reference");
                ui.add(egui::TextEdit::singleline(&mut self.recipient_reference).char_limit(128));
                ui.label("Local finalized transaction file (maximum 1 MiB; never a PCZT or private witness package)");
                ui.add(egui::TextEdit::singleline(&mut self.recipient_transaction_path).char_limit(4096));
                if ui.button("Review exact local viewing-key use").clicked_by(egui::PointerButton::Primary) && focused && self.stage_recipient(false, epoch).is_err() {
                    self.message = "Recipient check preparation failed. Select existing issued instructions and a bounded finalized transaction file.";
                }
                ui.label("Optional named provider JSON: source_id, endpoint (HTTPS), required_confirmations (1–100). A separate exact review authorizes the transaction-ID disclosure.");
                ui.add(egui::TextEdit::multiline(&mut *self.recipient_source).char_limit(4096));
                if self.recipient_job.is_some() { ui.label("Recipient provider observation is in progress."); }
                if ui.add_enabled(self.recipient_job.is_none(), egui::Button::new("Review recipient chain observation disclosure")).clicked_by(egui::PointerButton::Primary) && focused && self.stage_recipient_observation(epoch).is_err() {
                    self.message = "Select a locally verified recipient payment and valid named provider configuration first.";
                }
                if let Some(result) = &self.recipient_result { ui.label(inert_text(result)); }
                ui.label("Decryption alone leaves chain inclusion unobserved. Provider reports are source-specific snapshots, never independently verified consensus. Do not deliver solely on an organizer message or a cryptographic check. Refunds require a separately agreed destination and separately authorized payment.");
            });
        }
        self.exact_review_ui(ui, focused, epoch);
        ui.separator();
        ui.label(self.message);
        if let Some(receipt) = &self.last_receipt {
            ui.label(format!("Encrypted journal record reference: {receipt}"));
        }
    }
}

#[cfg(feature = "authority-signing")]
fn durable_flow_try_receive_v1<T>(
    receive: &std::sync::mpsc::Receiver<T>,
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    flow: Option<&flow_diag_v1::DurableFlowJobObservationV1>,
) -> std::result::Result<T, std::sync::mpsc::TryRecvError> {
    let result = receive.try_recv();
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    if let Some(flow) = flow {
        match &result {
            Err(std::sync::mpsc::TryRecvError::Empty) => flow.pending(),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => flow.disconnected(),
            Ok(_) => {}
        }
    }
    result
}
#[cfg(feature = "authority-signing")]
fn signing_completion_presented_v1<T>(
    result: &authority_bridge::Result<T>,
    lock_requested: bool,
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    flow: Option<&flow_diag_v1::DurableFlowJobObservationV1>,
) -> bool {
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    if let Some(flow) = flow {
        flow.received(flow_diag_v1::DurableFlowStageV1::Completion, result);
        if lock_requested {
            flow.presentation(flow_diag_v1::DurableFlowPresentationV1::Suppressed);
        } else if result.is_ok() {
            flow.presentation(flow_diag_v1::DurableFlowPresentationV1::Accepted);
        }
    }
    #[cfg(not(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    )))]
    let _ = result;
    !lock_requested
}
#[cfg(feature = "authority-signing")]
fn witness_completion_allowed_v1(
    result: &WitnessOutcome,
    epoch_matches: bool,
    cancelled: impl FnOnce() -> bool,
    pairing: impl FnOnce() -> Result<()>,
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    flow: Option<&(
        flow_diag_v1::DurableFlowJobObservationV1,
        flow_diag_v1::DurableFlowObserverV1,
        flow_diag_v1::DurableFlowStageV1,
    )>,
) -> bool {
    #[cfg(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    ))]
    if let Some((job, _, stage)) = flow {
        durable_witness_v1::observe_flow_receive_v1(job, *stage, result);
    }
    #[cfg(not(all(
        feature = "synthetic-born-joined-qualification",
        feature = "durable-proposal"
    )))]
    let _ = result;
    if !epoch_matches
        || cancelled()
        || durable_flow_observe_v1!(
            flow.map(|(_, observer, _)| observer),
            flow.map(|(_, _, stage)| *stage)
                .unwrap_or(flow_diag_v1::DurableFlowStageV1::Completion),
            pairing()
        )
        .is_err()
    {
        #[cfg(all(
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Some((job, _, _)) = flow {
            job.invalidated();
            job.presentation(flow_diag_v1::DurableFlowPresentationV1::Suppressed);
        }
        false
    } else {
        true
    }
}

/// Only exact disclosure workers may outlive blur; untagged history, dispatch
/// and authorization delivery workers keep the preexisting full-lock behavior.
fn history_requires_blur_lock(
    workers: &[std::thread::JoinHandle<()>],
    disclosure_ids: &std::collections::HashSet<std::thread::ThreadId>,
) -> bool {
    workers
        .iter()
        .any(|worker| !worker.is_finished() && !disclosure_ids.contains(&worker.thread().id()))
}

impl Drop for NativeRuntime {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(feature = "authority-signing")]
impl NativeRuntime {
    /// A dedicated transition closes ordinary admission before its existing
    /// close/drain path. No ordinary peer, native owner or vault is transferred.
    fn lock_for_retirement_entry(&mut self) {
        // A signing worker can own the entire OpenAccount. The actual surface
        // does not offer this transition while it runs; ordinary Lock remains
        // its existing cancellation path and fresh entry stays refused.
        if self.signing_job.is_some() {
            self.message = "The admitted signing worker must finish its existing lock/drain before dedicated evidence entry.";
            return;
        }
        let closing = self.open.take();
        if let Some(open) = closing.as_ref() {
            open.authority.revoke_informational_now();
            open.ipc.revocation().close_informational_now();
        }
        // With the ordinary owner removed from GUI state, this clears the
        // remaining native drafts without calling its blocking revoke_all.
        // The exact owner stays retained below until close() and IPC Drop drain.
        self.lock();
        if let Some(open) = closing {
            let done = Arc::new(AtomicBool::new(false));
            let finished = Arc::clone(&done);
            std::thread::spawn(move || {
                open.close();
                finished.store(true, Ordering::Release);
            });
            self.closing_accounts.push(done);
        }
        self.message = "Ordinary grants are revoked. Wait for lock/drain, then use the dedicated evidence entry with fresh native unlock and pairing.";
    }
    fn retirement_entry_idle(&self, focused: bool) -> bool {
        let idle = focused
            && self.open.is_none()
            && self.closing_accounts.is_empty()
            && self.signing_job.is_none()
            && self.recipient_job.is_none()
            && self.pending_account.is_none()
            && self.pending.is_none()
            && !self.birth.is_active()
            && !self.recovery_activation.is_active()
            && !self.quarantined_history.is_active()
            && !self.retirement_evidence_session.is_active();
        #[cfg(feature = "pending-birth-owner-signing")]
        let idle = idle
            && !self.pending_enrollment.is_active()
            && !self.born_origin.is_active()
            && !self.born_manual.is_active()
            && !self.born_manual_roster_v2.is_active()
            && !self.born_enrolled_backup.is_active();
        idle
    }
    fn begin_retirement_entry(&mut self, focused: bool, epoch: u64) -> Result<()> {
        if !self.retirement_entry_idle(focused) {
            return Err(Error::Locked);
        }
        // The shared gate is checked before native creation, KDF, copying any
        // password, opening sources or binding/publishing a restricted endpoint.
        wholepact_signer_origin::retirement_evidence::require_native_transport_activation_v1()
            .map_err(|_| Error::Unavailable)?;
        let entry = RetirementNativeEntry {
            focus_epoch: epoch,
            parent_channel: self.parent_channel.clone(),
            deadline: std::time::Instant::now() + Duration::from_secs(120),
        };
        self.retirement_evidence_session.begin_native(
            entry,
            Path::new(&self.root),
            self.password.as_bytes(),
        )
    }
    fn retirement_entry_controls(&mut self, ui: &mut egui::Ui, focused: bool, epoch: u64) {
        ui.collapsing("Dedicated application retirement evidence", |ui| {
            self.retirement_evidence_session.entry_fields(ui);
            let available = wholepact_signer_origin::retirement_evidence::require_native_transport_activation_v1().is_ok();
            let idle = self.retirement_entry_idle(focused);
            if ui.add_enabled(available && idle, egui::Button::new("Enter fresh restricted retirement evidence session"))
                .clicked_by(egui::PointerButton::Primary) && focused
            {
                let result = self.begin_retirement_entry(focused, epoch);
                self.password.zeroize();
                self.retirement_evidence_session.erase_entry_password();
                self.message = if result.is_ok() {
                    "Dedicated unlock and fresh restricted pairing are pending. No evidence has been released."
                } else {
                    self.retirement_evidence_session.clear();
                    "Dedicated retirement entry was refused. No ordinary owner or peer grant was reused."
                };
            }
        });
    }
    fn recovery_controls(&mut self, ui: &mut egui::Ui, focused: bool, epoch: u64) {
        let idle = focused
            && self.open.is_none()
            && self.closing_accounts.is_empty()
            && self.signing_job.is_none()
            && self.pending_account.is_none();
        self.recovery_activation.ui(
            ui,
            super::recovery_workspace::RecoveryInputs {
                focused,
                epoch,
                idle,
                root: &self.root,
                archive: &self.recovery_directory,
                password: self.password.as_bytes(),
                recovery_password: self.recovery_password.as_bytes(),
            },
        );
        ui.collapsing("Signer-owned encrypted backup and quarantined restore", |ui| {
            ui.label("Use only after locking this signer and all admitted jobs have drained. This separate recovery includes encrypted spending recovery, authority history, the viewing wallet when present, and recipient-local records. Coordinator history and the independent witness are separate. Never send this backup to the coordinator.");
            ui.label("Backup directory: NEW destination for backup; existing source for restore");
            ui.add(egui::TextEdit::singleline(&mut self.recovery_directory).char_limit(4096));
            ui.label("Backup recovery passphrase (at least 12 characters)");
            ui.add(egui::TextEdit::singleline(&mut *self.recovery_password).password(true).char_limit(1024));
            ui.label("Repeat backup recovery passphrase (required for a new backup)");
            ui.add(egui::TextEdit::singleline(&mut *self.recovery_repeat).password(true).char_limit(1024));
            ui.label("For backup, the account directory above must already exist and Vault password unlocks it. For restore, the account directory above must be NEW and Vault password protects the restored account.");
            ui.label(format!("Selected account directory: {}", inert_text(&self.root)));
            ui.label(format!("Selected backup directory: {}", inert_text(&self.recovery_directory)));
            ui.label("Type BACKUP SIGNER or RESTORE QUARANTINED to approve the selected local action. Restore never enables signing, imports witness authority, or proves outstanding exposure reconciled.");
            ui.add(egui::TextEdit::singleline(&mut *self.recovery_confirmation).char_limit(64));
            let idle = focused && self.open.is_none() && self.closing_accounts.is_empty() && self.signing_job.is_none() && self.pending_account.is_none();
            let backup = ui.add_enabled(idle && self.recovery_confirmation.as_str() == "BACKUP SIGNER" && self.recovery_password.len() >= 12 && *self.recovery_password == *self.recovery_repeat,egui::Button::new("Create selected signer-only encrypted backup")).clicked_by(egui::PointerButton::Primary);
            let restore = ui.add_enabled(idle && self.recovery_confirmation.as_str() == "RESTORE QUARANTINED",egui::Button::new("Restore selected signer backup into NEW quarantined account")).clicked_by(egui::PointerButton::Primary);
            ui.label("Optional restored private history: exact recipient instruction reference");
            ui.add(egui::TextEdit::singleline(&mut self.recipient_reference).char_limit(256));
            ui.label("To read only that restored record locally, type READ PRIVATE HISTORY above. No network observation or signing is performed.");
            let history = ui.add_enabled(idle && self.recovery_confirmation.as_str() == "READ PRIVATE HISTORY",egui::Button::new("Read selected restored recipient instruction history")).clicked_by(egui::PointerButton::Primary);
            if history {
                let result = AccountVault::unlock(Path::new(&self.root),self.password.as_bytes()).and_then(|vault|super::recipient::historical(&vault,&self.recipient_reference));
                self.password.zeroize(); self.recovery_password.zeroize(); self.recovery_repeat.zeroize(); self.recovery_confirmation.zeroize();
                match result {
                    Ok(text) => { self.recipient_result=Some(text); self.message="Private historical recipient instructions opened locally. Current chain state and writer authority remain unknown."; },
                    Err(_) => { self.recipient_result=None; self.message="Historical read failed closed. Check the restored account, passphrase and exact instruction reference. No authority was changed."; },
                }
            }
            if let Some(text) = &self.recipient_result { ui.label(inert_text(text)); }
            if backup || restore {
                let result = if backup {
                    crate::account::backup::snapshot(Path::new(&self.root),Path::new(&self.recovery_directory),self.password.as_bytes(),self.recovery_password.as_bytes())
                } else {
                    crate::account::backup::restore(Path::new(&self.recovery_directory),Path::new(&self.root),self.recovery_password.as_bytes(),self.password.as_bytes())
                };
                self.password.zeroize(); self.recovery_password.zeroize();
            self.recovery_repeat.zeroize(); self.recovery_confirmation.zeroize();
                self.message = match (backup,result) {
                    (true,Ok(())) => "Signer-owned encrypted backup verified. Preserve every file. Coordinator history and the independently operated witness remain separate.",
                    (false,Ok(())) => "Signer recovery restored in quarantine. Spending remains disabled; original authority history and recipient records are retained. No writer continuity was established.",
                    (_,Err(_)) => "Signer recovery action failed closed. Preserve the source and any partial destination unchanged; check exact inventory, passwords, paths and stopped writers. No signing permission was created.",
                };
            }
        });
    }
}

#[cfg(test)]
mod focus_tests {
    use super::*;
    #[cfg(feature = "authority-signing")]
    #[test]
    fn retirement_entry_gate_refuses_before_native_source_or_transport_effects() {
        let mut runtime = NativeRuntime::new(None);
        runtime.root = "/synthetic-path-that-must-not-be-opened".into();
        runtime.password.push_str("public-synthetic-native-input");
        assert!(matches!(
            runtime.begin_retirement_entry(true, 0),
            Err(Error::Unavailable)
        ));
        assert!(matches!(
            runtime.begin_retirement_entry(false, 0),
            Err(Error::Locked)
        ));
        assert!(runtime.open.is_none());
        assert!(runtime.closing_accounts.is_empty());
        assert!(runtime.signing_job.is_none());
        assert!(!runtime.retirement_evidence_session.is_active());
        runtime.password.zeroize();
    }
    #[cfg(feature = "authority-signing")]
    #[test]
    fn retirement_entry_waits_for_original_close_completion_without_ownership_transfer() {
        let mut runtime = NativeRuntime::new(None);
        assert!(runtime.retirement_entry_idle(true));
        assert!(!runtime.retirement_entry_idle(false));
        let finished = Arc::new(AtomicBool::new(false));
        runtime.closing_accounts.push(Arc::clone(&finished));
        assert!(!runtime.retirement_entry_idle(true));
        assert!(matches!(
            runtime.begin_retirement_entry(true, 1),
            Err(Error::Locked)
        ));
        finished.store(true, Ordering::Release);
        // A completed marker still must be observed by the existing drain poll.
        assert!(!runtime.retirement_entry_idle(true));
        runtime.poll(1);
        assert!(runtime.retirement_entry_idle(true));
        runtime.lock_for_retirement_entry();
        assert!(runtime.open.is_none());
        assert!(runtime.closing_accounts.is_empty());
        assert!(!runtime.retirement_evidence_session.is_active());
    }
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    #[test]
    fn named_verifier_native_lifecycle_revokes_inert_source() {
        // Genuine runtime entry points, synthetic lifetime only: no key, profile,
        // signing decision, worker, filesystem, listener or provider is created.
        for operation in 0..3 {
            let mut runtime = NativeRuntime::new(None);
            let source = runtime.named_verifier.test_arm_inert_source();
            assert!(source.check_current().is_ok());
            match operation {
                0 => runtime.blur(),
                1 => runtime.lock(),
                _ => runtime.navigate(),
            }
            assert!(!runtime.named_verifier.is_active());
            assert!(source.check_current().is_err());
        }
    }
    #[test]
    fn only_explicitly_tagged_disclosure_workers_survive_blur() {
        // Real thread lifetime test only: no signer source, grant or approval.
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = receive.recv();
        });
        let workers = vec![worker];
        let mut tags = std::collections::HashSet::new();
        assert!(history_requires_blur_lock(&workers, &tags));
        tags.insert(workers[0].thread().id());
        assert!(!history_requires_blur_lock(&workers, &tags));
        tags.clear();
        assert!(history_requires_blur_lock(&workers, &tags));
        send.send(()).unwrap();
        for worker in workers {
            worker.join().unwrap();
        }
    }
    #[cfg(feature = "authority-signing")]
    #[test]
    fn every_native_automation_route_requires_an_open_authenticated_account() {
        use super::super::automation_workspace::AutomationCommand as C;
        for command in [
            C::Activate,
            C::Pause,
            C::Revoke,
            C::Renew,
            C::Inspect,
            C::Synchronize,
            C::Authorize,
        ] {
            let mut runtime = NativeRuntime::new(None);
            runtime.automation.grant_id.push_str("synthetic-grant");
            assert!(runtime.automation_command(command, 0).is_err());
            assert!(
                runtime.pending.is_none()
                    && runtime.open.is_none()
                    && runtime.signing_job.is_none()
            );
        }
    }
    #[cfg(feature = "authority-signing")]
    #[test]
    fn lock_and_navigation_clear_automation_drafts_and_status() {
        for navigate in [false, true] {
            let mut runtime = NativeRuntime::new(None);
            runtime.automation.grant_id.push_str("synthetic-grant");
            runtime.automation.policy_json.push_str("synthetic-policy");
            runtime.automation.terms_json.push_str("synthetic-terms");
            runtime.automation.status = Some(Zeroizing::new("synthetic-status".into()));
            if navigate {
                runtime.navigate();
            } else {
                runtime.lock();
            }
            assert!(
                runtime.automation.grant_id.is_empty()
                    && runtime.automation.policy_json.is_empty()
                    && runtime.automation.terms_json.is_empty()
                    && runtime.automation.status.is_none()
            );
            assert!(runtime.pending.is_none() && runtime.open.is_none());
        }
    }
    #[test]
    fn blur_erases_pending_private_buffers_without_creating_authority() {
        let mut runtime = NativeRuntime::new(None);
        runtime.password.push_str("synthetic-password");
        runtime.backup.push_str("synthetic-backup");
        runtime.recovery.push_str("synthetic-recovery");
        runtime.proposal.push_str("synthetic-private-proposal");
        runtime.confirmation.push_str("synthetic-confirmation");
        runtime.last_receipt = Some("synthetic-reference".into());
        #[cfg(feature = "authority-signing")]
        {
            runtime.incoming_pczt = Some(Zeroizing::new(vec![1, 2, 3]));
            runtime
                .sponsor_policy_terms
                .push_str("synthetic-private-sponsor-terms");
            runtime.sponsor_policy_key.push_str("synthetic-policy-key");
            runtime.automation.grant_id.push_str("synthetic-grant");
            runtime
                .automation
                .policy_json
                .push_str("synthetic-private-policy");
            runtime
                .automation
                .terms_json
                .push_str("synthetic-private-terms");
            runtime.automation.status = Some(Zeroizing::new("synthetic-status".into()));
        }
        runtime.blur();
        assert!(
            runtime.password.is_empty() && runtime.backup.is_empty() && runtime.recovery.is_empty()
        );
        assert!(runtime.proposal.is_empty() && runtime.confirmation.is_empty());
        assert!(
            runtime.pending.is_none() && runtime.open.is_none() && runtime.last_receipt.is_none()
        );
        #[cfg(feature = "authority-signing")]
        assert!(
            runtime.incoming_pczt.is_none()
                && runtime.sponsor_policy_terms.is_empty()
                && runtime.sponsor_policy_key.is_empty()
                && runtime.automation.grant_id.is_empty()
                && runtime.automation.policy_json.is_empty()
                && runtime.automation.terms_json.is_empty()
                && runtime.automation.status.is_none()
        );
        runtime.lock();
        assert!(runtime.open.is_none());
    }
}

#[cfg(all(test, feature = "authority-signing"))]
mod pending_birth_draft_tests {
    use super::*;
    #[test]
    fn real_runtime_invalidation_paths_clear_unprivileged_birth_drafts() {
        // This deliberately exercises only draft cleanup. It creates no native
        // owner, entry token, key or decision and proves no attended lifecycle.
        for invalidation in 0..3 {
            let mut runtime = NativeRuntime::new(None);
            runtime.birth =
                super::super::birth_workspace::NativeBirthCeremony::data_only_draft_fixture();
            match invalidation {
                0 => runtime.lock(),
                1 => runtime.blur(),
                _ => runtime.navigate(),
            }
            assert!(runtime.birth.data_only_drafts_empty());
            assert!(!runtime.birth.is_active());
            assert!(runtime.open.is_none());
        }
    }
}

#[cfg(all(test, feature = "authority-signing"))]
mod quarantined_history_runtime_tests {
    use super::*;

    #[test]
    fn restricted_history_runtime_invalidation_clears_unprivileged_secret_drafts() {
        // Ordinary runtime lifecycle only; no native authority, entry, listener,
        // source decoder, witness client or decision is created.
        for operation in 0..3 {
            let mut runtime = NativeRuntime::new(None);
            runtime.informational_password.push_str("synthetic-draft");
            match operation {
                0 => runtime.lock(),
                1 => runtime.blur(),
                _ => runtime.navigate(),
            }
            assert!(runtime.informational_password.is_empty());
            assert!(!runtime.quarantined_history.is_active());
            assert!(runtime.open.is_none());
        }
    }
}

#[cfg(all(
    test,
    feature = "synthetic-born-joined-qualification",
    feature = "durable-proposal"
))]
mod durable_flow_poller_tests {
    use super::*;
    use flow_diag_v1::{
        DurableFlowCollectorV1 as Collector, DurableFlowErrorCodeV1 as Code,
        DurableFlowJobPurposeV1 as Purpose, DurableFlowOperationV1 as Operation,
        DurableFlowPresentationV1 as Presentation, DurableFlowReceiveV1 as Receive,
        DurableFlowResultV1 as Observed, DurableFlowStageV1 as Stage,
    };
    #[test]
    fn actual_signing_poller_locked_success_and_error_preserve_original_results() {
        for success in [false, true] {
            for diagnosed in [false, true] {
                let collector = Collector::default();
                let observer = collector.arm(Operation::InitialSign);
                let job = observer.job_start(Purpose::Sign, 17);
                let result: authority_bridge::Result<Box<u8>> = if success {
                    Ok(Box::new(3))
                } else {
                    Err(authority_bridge::BridgeError::Permission)
                };
                let ptr = result.as_ref().ok().map(|v| &**v as *const u8);
                assert!(!signing_completion_presented_v1(
                    &result,
                    true,
                    diagnosed.then_some(&job)
                ));
                assert_eq!(result.is_ok(), success);
                assert_eq!(result.as_ref().ok().map(|v| &**v as *const u8), ptr);
                if diagnosed {
                    let report = observer.finish(Observed::ReturnedErr).unwrap();
                    assert!(
                        report.completion().result()
                            == if success {
                                Observed::ReturnedOk
                            } else {
                                Observed::ReturnedErr
                            }
                    );
                    assert!(report.completion().presentation() == Presentation::Suppressed);
                    assert_eq!(report.first_error().is_some(), !success);
                    if !success {
                        assert!(report.first_error().unwrap().code() == Code::BridgePermission);
                    }
                }
            }
        }
    }
    #[test]
    fn actual_witness_poller_invalid_epoch_preserves_error_before_short_circuit() {
        let collector = Collector::default();
        let observer = collector.arm(Operation::WriterReconcile);
        let job = observer.job_start(Purpose::AcquirePrepare, 7);
        let flow = (job, observer.clone(), Stage::AcquirePrepare);
        let outcome = WitnessOutcome::DurablePaymentV1(
            durable_witness_v1::DurableWitnessOutcomeV1::Prepared(Err(Error::Verification)),
        );
        assert!(!witness_completion_allowed_v1(
            &outcome,
            false,
            || panic!("cancel short circuit"),
            || panic!("pairing short circuit"),
            Some(&flow)
        ));
        let report = observer.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().unwrap().code() == Code::SignerVerification);
        assert!(report.completion().result() == Observed::ReturnedErr);
        assert!(report.completion().receive() == Receive::Invalidated);
    }
    #[test]
    fn actual_witness_poller_old_job_does_not_attribute_pairing_to_new_arm() {
        let collector = Collector::default();
        let old = collector.arm(Operation::WriterReconcile);
        let flow = (
            old.job_start(Purpose::AcquirePrepare, 7),
            old.clone(),
            Stage::AcquirePrepare,
        );
        let current = collector.arm(Operation::WriterReconcile);
        let outcome = WitnessOutcome::DurablePaymentV1(
            durable_witness_v1::DurableWitnessOutcomeV1::Prepared(Err(Error::Uncertain)),
        );
        assert!(!witness_completion_allowed_v1(
            &outcome,
            true,
            || false,
            || Err(Error::Authentication),
            Some(&flow)
        ));
        let report = current.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().is_none());
        assert!(report.completion().result() == Observed::NotObserved);
        assert!(report.incomplete());
    }
}
