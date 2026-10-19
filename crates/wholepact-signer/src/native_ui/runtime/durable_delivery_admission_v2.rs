//! Genuine v2 imported-source issuer and historical-only native runtime.
//! No v1 financial owner, permit, writer session, signature or dispatch adapter.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableDeliveryEntryV2;
use crate::authority_bridge::{
    BridgeError,
    durable_delivery_admission_ipc_v2::*,
    durable_review_ipc_v1::{
        self as wire, DeliveryCommandV1, DeliveryResponseV1, DurableReviewDeliveryReceiptV1,
        DurableReviewDeliveryRequestV1, DurableReviewPayloadV1,
    },
};
use crate::consent_journal::{
    PreparedDurableDeliveryAdmissionIntentV2, RetainedDurableDeliveryAdmissionIntentV2,
};
use crate::native_ui::{NativeDecision, durable_proposal_v1::VerifiedDurableEconomicsV1};
use sha2::{Digest, Sha256};
use std::{
    os::unix::net::UnixStream,
    sync::mpsc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_authority::{
    OwnerControl, OwnerControlRequest, ReconciledAuthorityHistory,
    durable_delivery_scope_v2::*,
    durable_payment_v1::{DurableFixedCandidateBindingV1, DurablePaymentAdmissionTermsV1},
};
use wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionScopeV1;
fn bridge_error(_: impl std::fmt::Display) -> BridgeError {
    BridgeError::Permission
}
fn now() -> authority_bridge::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| BridgeError::Permission)
}
fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::ReviewMismatch)?
            .as_millis(),
    )
    .map_err(|_| Error::ReviewMismatch)
}
fn canonical<T: serde::Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::InvalidData)
}
// Every expression is evaluated once, before its original error conversion.
// The feature-disabled path performs no diagnostic classification or mutation.
macro_rules! receive_result_v2 {
    ($collector:expr, $stage:ident, $kind:ident, $original:expr) => {{
        let original = $original;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let original = receiver_diagnostics_v2::$kind(
            $collector,
            receiver_diagnostics_v2::Stage::$stage,
            original,
        );
        original
    }};
}
macro_rules! receive_denied_v2 {
    ($collector:expr, $stage:ident, $denied:expr) => {{
        let denied = $denied;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let denied = receiver_diagnostics_v2::denied(
            $collector,
            receiver_diagnostics_v2::Stage::$stage,
            denied,
        );
        denied
    }};
}

#[cfg(feature = "synthetic-born-joined-qualification")]
mod receiver_diagnostics_v2 {
    use super::{BridgeError, Error};
    use crate::consent_journal::JournalError;
    use std::{cell::Cell, io::Write};
    use wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError;

    macro_rules! labels {
        ($name:ident { $($variant:ident),+ $(,)? }) => {
            #[allow(dead_code)]
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub(super) enum $name { $($variant),+ }
            impl $name {
                fn label(self) -> &'static str {
                    match self { $(Self::$variant => stringify!($variant)),+ }
                }
            }
        };
    }
    labels! { Stage {
        DeliveryReceiveNativeDeadline,
        DeliveryReceiveRequest,
        DeliveryReceiveSource,
        DeliveryReceiveOriginalHistory,
        DeliveryReceiveOriginalBinding,
        DeliveryReceiveCurrentHistory,
        DeliveryReceiveRedisclosureBinding,
        DeliveryReceiveRecipientBinding,
        DeliveryReceiveViewingKey,
        DeliveryReceiveMaterialOwner,
        DeliveryReceiveLease,
        DeliveryReceiveNativeOrigin,
        DeliveryReceiveSourceUnderLease,
        DeliveryReceiveReceipts,
        DeliveryReceiveProposal,
        DeliveryReceiveAccount,
        DeliveryReceiveAccountBinding,
        DeliveryReceiveReviewerScope,
        DeliveryReceiveDeadline,
        DeliveryReceiveOriginalSource,
        DeliveryReceivePeer,
        DeliveryReceiveMaterialClock,
        DeliveryReceiveMaterialScope,
        DeliveryReceiveRequestDigest,
        DeliveryReceiveReadyWrite,
        DeliveryReceiveFrame,
        DeliveryReceiveCommandParse,
        DeliveryReceiveCommandBinding,
        DeliveryReceivePayloadLimit,
        DeliveryReceiveChunkDecode,
        DeliveryReceiveCurrentWrite,
        DeliveryReceiveReceivingWrite,
        DeliveryReceivePayloadBinding,
        DeliveryReceivePayloadParse,
        DeliveryReceivePayloadCanonical,
        DeliveryReceiveContributionBinding,
        DeliveryReceiveUnsignedDecode,
        DeliveryReceiveProvedDecode,
        DeliveryReceiveEconomics,
        DeliveryReceiveFinalBinding,
        DeliveryReceiveFinalSource,
        DeliveryReceiveFinalPeer,
        DeliveryReceiveFinalDeadline,
        DeliveryReceiveFinalMaterialClock,
        DeliveryReceiveFinalMaterialScope,
        DeliveryReceiveImportedWrite,
        DeliveryReceiveTerminal,
    } }
    labels! { Outcome {
        SignerUnavailable,
        SignerPeerLifetimeUnavailable,
        SignerIo,
        SignerAuthentication,
        SignerInvalidData,
        SignerCrypto,
        SignerLocked,
        SignerBackupRequired,
        SignerRecoveryRequired,
        SignerAlreadyOpen,
        SignerReviewMismatch,
        SignerVerification,
        SignerUncertain,
        SignerConsentJournal,
        SignerStore,
        BridgeBinding,
        BridgeConflict,
        BridgeMissing,
        BridgeUncertain,
        BridgeLimit,
        BridgePermission,
        BridgeRecoveryRequired,
        BridgeCompleteOriginRecoveryUnavailable,
        BridgeVerification,
        BridgeSignerOriginUnavailable,
        BridgeJournal,
        BridgeAuthority,
        BridgeWallet,
        BridgeIpc,
        WorkerFailure,
        PredicateDenied,
        OriginPermanentStopUnavailable,
        OriginRetirementEvidenceUnavailable,
        OriginSignerOriginUnavailable,
        OriginPeerLifetimeUnavailable,
        OriginAuthentication,
        OriginBinding,
        OriginConflict,
        OriginPermission,
        OriginInvalidData,
        OriginLocked,
        OriginCrypto,
        OriginIpc,
        OriginLimit,
        OriginIoTimedOut,
        OriginIoWouldBlock,
        OriginIoUnexpectedEof,
        OriginIoBrokenPipe,
        OriginIoConnectionReset,
        OriginIoConnectionAborted,
        OriginIoNotConnected,
        OriginIoInterrupted,
        OriginIoPermissionDenied,
        OriginIoOther,
        JournalExpired,
        JournalPermission,
        JournalOther,
        ConstructionInvalid,
        ConstructionBinding,
        ConstructionStale,
        ConstructionStorage,
        ConstructionSync,
    } }

    // A lower error that has no safe classifier still closes the first-cause
    // slot. Its enclosing Permission/Ipc conversion cannot replace it.
    #[derive(Clone, Copy, Default)]
    enum FirstCause {
        #[default]
        Vacant,
        SeenUnknown(Stage),
        SeenFinite(Stage, Outcome),
    }
    #[derive(Default)]
    pub(super) struct Collector(Cell<FirstCause>);
    impl Collector {
        fn record(&self, stage: Stage, outcome: Option<Outcome>) {
            if matches!(self.0.get(), FirstCause::Vacant) {
                self.0.set(match outcome {
                    Some(outcome) => FirstCause::SeenFinite(stage, outcome),
                    None => FirstCause::SeenUnknown(stage),
                });
            }
        }
        fn terminal_labels(&self, error: &BridgeError) -> (Stage, Outcome) {
            match self.0.get() {
                FirstCause::Vacant => (Stage::DeliveryReceiveTerminal, bridge_outcome(error)),
                FirstCause::SeenUnknown(stage) => (stage, Outcome::WorkerFailure),
                FirstCause::SeenFinite(stage, outcome) => (stage, outcome),
            }
        }
        pub(super) fn emit_terminal(&self, error: &BridgeError) {
            self.emit_terminal_to(error, &mut std::io::stderr().lock());
        }
        fn emit_terminal_to(&self, error: &BridgeError, writer: &mut impl Write) {
            let (stage, outcome) = self.terminal_labels(error);
            // Closed labels only. A diagnostic write failure cannot replace
            // the original failure or panic before the held stream is dropped.
            let _ = writeln!(
                writer,
                "\n[JOINED_DIAGNOSTIC {} {}]",
                stage.label(),
                outcome.label()
            );
        }
    }

    fn observe<T, E>(
        collector: Option<&Collector>,
        stage: Stage,
        original: std::result::Result<T, E>,
        classify: impl FnOnce(&E) -> Option<Outcome>,
    ) -> std::result::Result<T, E> {
        if let (Some(collector), Err(error)) = (collector, &original) {
            collector.record(stage, classify(error));
        }
        original
    }
    pub(super) fn denied(collector: Option<&Collector>, stage: Stage, denied: bool) -> bool {
        if denied {
            if let Some(collector) = collector {
                collector.record(stage, Some(Outcome::PredicateDenied));
            }
        }
        denied
    }
    pub(super) fn unknown<T, E>(
        collector: Option<&Collector>,
        stage: Stage,
        original: std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        observe(collector, stage, original, |_| None)
    }
    macro_rules! typed_result {
        ($name:ident, $error:ty, $classify:ident) => {
            pub(super) fn $name<T>(
                collector: Option<&Collector>,
                stage: Stage,
                original: std::result::Result<T, $error>,
            ) -> std::result::Result<T, $error> {
                observe(collector, stage, original, |error| Some($classify(error)))
            }
        };
    }
    typed_result!(signer, Error, signer_outcome);
    typed_result!(bridge, BridgeError, bridge_outcome);
    typed_result!(journal, JournalError, journal_outcome);
    typed_result!(construction, DurableConstructionError, construction_outcome);
    typed_result!(origin, wholepact_signer_origin::Error, origin_outcome);
    fn journal_outcome(error: &JournalError) -> Outcome {
        match error {
            JournalError::Expired => Outcome::JournalExpired,
            JournalError::Permission => Outcome::JournalPermission,
            _ => Outcome::JournalOther,
        }
    }
    fn construction_outcome(error: &DurableConstructionError) -> Outcome {
        match error {
            DurableConstructionError::Invalid => Outcome::ConstructionInvalid,
            DurableConstructionError::Binding => Outcome::ConstructionBinding,
            DurableConstructionError::Stale => Outcome::ConstructionStale,
            DurableConstructionError::Storage => Outcome::ConstructionStorage,
            DurableConstructionError::Sync(_) => Outcome::ConstructionSync,
        }
    }
    fn signer_outcome(error: &Error) -> Outcome {
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
            Error::ConsentJournal(error) => journal_outcome(error),
            Error::Store(_) => Outcome::SignerStore,
        }
    }
    fn bridge_outcome(error: &BridgeError) -> Outcome {
        use Outcome as O;
        match error {
            BridgeError::Binding => O::BridgeBinding,
            BridgeError::Conflict => O::BridgeConflict,
            BridgeError::Missing => O::BridgeMissing,
            BridgeError::Uncertain => O::BridgeUncertain,
            BridgeError::Limit => O::BridgeLimit,
            BridgeError::Permission => O::BridgePermission,
            BridgeError::RecoveryRequired => O::BridgeRecoveryRequired,
            BridgeError::CompleteOriginRecoveryUnavailable => {
                O::BridgeCompleteOriginRecoveryUnavailable
            }
            BridgeError::Verification => O::BridgeVerification,
            BridgeError::SignerOriginUnavailable => O::BridgeSignerOriginUnavailable,
            BridgeError::Journal(error) => journal_outcome(error),
            BridgeError::Authority(_) => O::BridgeAuthority,
            #[cfg(feature = "authority-signing")]
            BridgeError::Wallet(_) => O::BridgeWallet,
            BridgeError::Ipc => O::BridgeIpc,
        }
    }
    fn io_outcome(error: &std::io::Error) -> Outcome {
        use Outcome as O;
        use std::io::ErrorKind as E;
        match error.kind() {
            E::TimedOut => O::OriginIoTimedOut,
            E::WouldBlock => O::OriginIoWouldBlock,
            E::UnexpectedEof => O::OriginIoUnexpectedEof,
            E::BrokenPipe => O::OriginIoBrokenPipe,
            E::ConnectionReset => O::OriginIoConnectionReset,
            E::ConnectionAborted => O::OriginIoConnectionAborted,
            E::NotConnected => O::OriginIoNotConnected,
            E::Interrupted => O::OriginIoInterrupted,
            E::PermissionDenied => O::OriginIoPermissionDenied,
            _ => O::OriginIoOther,
        }
    }
    fn origin_outcome(error: &wholepact_signer_origin::Error) -> Outcome {
        use Outcome as O;
        use wholepact_signer_origin::Error as E;
        match error {
            E::PermanentStopUnavailable => O::OriginPermanentStopUnavailable,
            E::RetirementEvidenceUnavailable => O::OriginRetirementEvidenceUnavailable,
            E::SignerOriginUnavailable => O::OriginSignerOriginUnavailable,
            E::PeerLifetimeUnavailable => O::OriginPeerLifetimeUnavailable,
            E::Authentication => O::OriginAuthentication,
            E::Binding => O::OriginBinding,
            E::Conflict => O::OriginConflict,
            E::Permission => O::OriginPermission,
            E::InvalidData => O::OriginInvalidData,
            E::Locked => O::OriginLocked,
            E::Crypto => O::OriginCrypto,
            E::Ipc => O::OriginIpc,
            E::Limit => O::OriginLimit,
            E::Io(error) => io_outcome(error),
        }
    }
    #[cfg(test)]
    mod tests {
        use super::super::{borrowed_receive_terminal_v2, bridge_error};
        use super::*;

        #[test]
        fn callback_lower_cause_survives_permission_and_frame_conversion() {
            let collector = Collector::default();
            let check = || -> crate::authority_bridge::Result<()> {
                signer(
                    Some(&collector),
                    Stage::DeliveryReceiveOriginalSource,
                    Err::<(), _>(Error::Locked),
                )
                .map_err(bridge_error)?;
                Ok(())
            };
            // Same actual callback conversions as the receive kernel. No
            // source, native grant, process, socket or clock is fabricated.
            let result = origin(
                Some(&collector),
                Stage::DeliveryReceiveFrame,
                check().map_err(|_| wholepact_signer_origin::Error::Permission),
            )
            .map_err(|_| BridgeError::Ipc);
            assert!(matches!(result, Err(BridgeError::Ipc)));
            assert_eq!(
                collector.terminal_labels(result.as_ref().unwrap_err()),
                (Stage::DeliveryReceiveOriginalSource, Outcome::SignerLocked,)
            );
        }

        #[test]
        fn unknown_first_cause_blocks_later_finite_replacement() {
            let collector = Collector::default();
            let private = Box::new(String::from("private parse detail"));
            let identity = &*private as *const String;
            let original = unknown(
                Some(&collector),
                Stage::DeliveryReceiveCommandParse,
                Err::<(), _>(private),
            );
            assert_eq!(&**original.as_ref().unwrap_err() as *const String, identity);
            let result = bridge(
                Some(&collector),
                Stage::DeliveryReceiveFrame,
                original.map_err(|_| BridgeError::Ipc),
            );
            let labels = collector.terminal_labels(result.as_ref().unwrap_err());
            assert_eq!(
                labels,
                (Stage::DeliveryReceiveCommandParse, Outcome::WorkerFailure)
            );
            let mut output = Vec::new();
            collector.emit_terminal_to(result.as_ref().unwrap_err(), &mut output);
            assert_eq!(
                String::from_utf8(output).unwrap(),
                "\n[JOINED_DIAGNOSTIC DeliveryReceiveCommandParse WorkerFailure]\n"
            );
        }

        #[test]
        fn explicit_deadline_is_distinct_from_source_peer_receipt_and_material() {
            let deadline = Collector::default();
            assert!(!denied(
                Some(&deadline),
                Stage::DeliveryReceiveDeadline,
                false
            ));
            assert!(matches!(deadline.0.get(), FirstCause::Vacant));
            assert!(denied(
                Some(&deadline),
                Stage::DeliveryReceiveDeadline,
                true
            ));
            assert_eq!(
                deadline.terminal_labels(&BridgeError::Permission),
                (Stage::DeliveryReceiveDeadline, Outcome::PredicateDenied,)
            );
            for (stage, error, expected) in [
                (
                    Stage::DeliveryReceiveOriginalSource,
                    Error::Locked,
                    Outcome::SignerLocked,
                ),
                (
                    Stage::DeliveryReceivePeer,
                    Error::Authentication,
                    Outcome::SignerAuthentication,
                ),
            ] {
                let collector = Collector::default();
                let result =
                    signer(Some(&collector), stage, Err::<(), _>(error)).map_err(bridge_error);
                assert_eq!(
                    collector.terminal_labels(result.as_ref().unwrap_err()),
                    (stage, expected)
                );
            }
            let receipt = Collector::default();
            let result = journal(
                Some(&receipt),
                Stage::DeliveryReceiveReceipts,
                Err::<(), _>(JournalError::Expired),
            )
            .map_err(BridgeError::from);
            assert_eq!(
                receipt.terminal_labels(result.as_ref().unwrap_err()),
                (Stage::DeliveryReceiveReceipts, Outcome::JournalExpired,)
            );
            let material = Collector::default();
            let result = construction(
                Some(&material),
                Stage::DeliveryReceiveMaterialScope,
                Err::<(), _>(DurableConstructionError::Stale),
            )
            .map_err(bridge_error);
            assert_eq!(
                material.terminal_labels(result.as_ref().unwrap_err()),
                (
                    Stage::DeliveryReceiveMaterialScope,
                    Outcome::ConstructionStale,
                )
            );
        }

        #[test]
        fn bare_frame_authentication_remains_ambiguous_and_operations_are_isolated() {
            let first = Collector::default();
            let result = origin(
                Some(&first),
                Stage::DeliveryReceiveFrame,
                Err::<(), _>(wholepact_signer_origin::Error::Authentication),
            )
            .map_err(|_| BridgeError::Ipc);
            assert_eq!(
                first.terminal_labels(result.as_ref().unwrap_err()),
                (Stage::DeliveryReceiveFrame, Outcome::OriginAuthentication,)
            );
            let second = Collector::default();
            assert!(matches!(second.0.get(), FirstCause::Vacant));
            assert_eq!(
                second.terminal_labels(&BridgeError::Binding),
                (Stage::DeliveryReceiveTerminal, Outcome::BridgeBinding,)
            );
            assert_eq!(
                first.terminal_labels(&BridgeError::Binding),
                (Stage::DeliveryReceiveFrame, Outcome::OriginAuthentication,)
            );
        }

        #[test]
        fn typed_journal_and_material_categories_survive_original_wrappers() {
            for (error, expected) in [
                (JournalError::Expired, Outcome::JournalExpired),
                (JournalError::Permission, Outcome::JournalPermission),
                (JournalError::Database, Outcome::JournalOther),
            ] {
                assert_eq!(journal_outcome(&error), expected);
                assert_eq!(bridge_outcome(&BridgeError::Journal(error)), expected);
            }
            assert_eq!(
                signer_outcome(&Error::ConsentJournal(JournalError::Expired)),
                Outcome::JournalExpired
            );
            for (error, expected) in [
                (
                    DurableConstructionError::Invalid,
                    Outcome::ConstructionInvalid,
                ),
                (
                    DurableConstructionError::Binding,
                    Outcome::ConstructionBinding,
                ),
                (DurableConstructionError::Stale, Outcome::ConstructionStale),
                (
                    DurableConstructionError::Storage,
                    Outcome::ConstructionStorage,
                ),
                (
                    DurableConstructionError::Sync(
                        wholepact_wallet::wallet::protected_sync::SyncError::NoCurrentObservation,
                    ),
                    Outcome::ConstructionSync,
                ),
            ] {
                assert_eq!(construction_outcome(&error), expected);
            }
        }

        #[test]
        fn source_check_short_circuits_once_before_later_receipt_observation() {
            let collector = Collector::default();
            let calls = Cell::new(0);
            let result = (|| -> crate::authority_bridge::Result<()> {
                signer(Some(&collector), Stage::DeliveryReceiveOriginalSource, {
                    calls.set(calls.get() + 1);
                    Err::<(), _>(Error::Locked)
                })
                .map_err(bridge_error)?;
                calls.set(calls.get() + 100);
                journal(
                    Some(&collector),
                    Stage::DeliveryReceiveReceipts,
                    Err::<(), _>(JournalError::Expired),
                )?;
                Ok(())
            })();
            assert_eq!(calls.get(), 1);
            assert_eq!(
                collector.terminal_labels(result.as_ref().unwrap_err()),
                (Stage::DeliveryReceiveOriginalSource, Outcome::SignerLocked,)
            );
        }

        #[test]
        fn absent_collector_and_success_do_not_classify_or_emit() {
            let value = Box::new(71_u64);
            let identity = &*value as *const u64;
            let result = observe(
                None,
                Stage::DeliveryReceiveFrame,
                Err::<(), _>(value),
                |_| panic!("absent collector must not classify"),
            );
            assert_eq!(&**result.as_ref().unwrap_err() as *const u64, identity);
            let collector = Collector::default();
            let mut resource = ();
            let mut output = Vec::new();
            let result = borrowed_receive_terminal_v2(
                &mut resource,
                |_| {
                    observe(
                        Some(&collector),
                        Stage::DeliveryReceiveFrame,
                        Ok::<_, BridgeError>(Box::new(72_u64)),
                        |_| panic!("success must not classify"),
                    )
                },
                |error| collector.emit_terminal_to(error, &mut output),
            );
            assert_eq!(**result.as_ref().unwrap(), 72);
            assert!(output.is_empty());
            assert!(matches!(collector.0.get(), FirstCause::Vacant));
        }

        #[test]
        fn ignored_sink_write_error_does_not_replace_owned_terminal_error() {
            struct FailingWriter;
            impl std::io::Write for FailingWriter {
                fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                    Err(std::io::Error::other("private stderr failure"))
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let collector = Collector::default();
            let mut resource = ();
            let result = borrowed_receive_terminal_v2(
                &mut resource,
                |_| Err::<(), _>(BridgeError::Journal(JournalError::Expired)),
                |error| collector.emit_terminal_to(error, &mut FailingWriter),
            );
            assert!(matches!(
                result,
                Err(BridgeError::Journal(JournalError::Expired))
            ));
        }
    }
}

// The actual owned stream stays in the caller. The body may only borrow it;
// the terminal sink sees the same owned error before the caller drops it.
fn borrowed_receive_terminal_v2<R, T, E>(
    resource: &mut R,
    body: impl FnOnce(&mut R) -> std::result::Result<T, E>,
    terminal: impl FnOnce(&E),
) -> std::result::Result<T, E> {
    let original = body(resource);
    if let Err(error) = &original {
        terminal(error);
    }
    original
}

pub(super) struct ImportedDeliveryReviewV2 {
    pub(super) fixed: Arc<VerifiedDurableEconomicsV1>,
    pub(super) request: DurableReviewDeliveryRequestV1,
    source: Arc<FreshDurableDeliveryEntryV2>,
    peer: AuthenticatedPeer,
    session: Arc<SignerConsentSession>,
    scopes: Vec<DurableConstructionScopeV1>,
}
impl ImportedDeliveryReviewV2 {
    fn check_data_current(&self) -> Result<()> {
        self.check_data_current_observed_v2(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    fn check_data_current_observed_v2(
        &self,
        #[cfg(feature = "synthetic-born-joined-qualification")] collector: Option<
            &receiver_diagnostics_v2::Collector,
        >,
    ) -> Result<()> {
        receive_result_v2!(
            collector,
            DeliveryReceiveFinalSource,
            signer,
            self.source.check_original_source_current()
        )?;
        receive_result_v2!(
            collector,
            DeliveryReceiveFinalPeer,
            signer,
            self.peer.check_current()
        )?;
        if receive_denied_v2!(
            collector,
            DeliveryReceiveFinalBinding,
            self.peer.native_origin != self.source.native_binding()
                || receive_denied_v2!(
                    collector,
                    DeliveryReceiveFinalDeadline,
                    Instant::now()
                        >= receive_result_v2!(
                            collector,
                            DeliveryReceiveFinalDeadline,
                            signer,
                            self.deadline()
                        )?
                )
                || self.scopes.len() != 2
        ) {
            return Err(Error::ReviewMismatch);
        }
        for scope in &self.scopes {
            receive_result_v2!(
                collector,
                DeliveryReceiveFinalMaterialScope,
                construction,
                scope.check_valid_at(
                    receive_result_v2!(collector, DeliveryReceiveFinalMaterialClock, bridge, now())
                        .map_err(|_| Error::ReviewMismatch)?
                )
            )
            .map_err(|_| Error::ReviewMismatch)?;
            if receive_denied_v2!(
                collector,
                DeliveryReceiveFinalBinding,
                scope.proposal != *self.fixed.proposal().input()
            ) {
                return Err(Error::ReviewMismatch);
            }
        }
        Ok(())
    }
    fn check_current(&self) -> Result<()> {
        self.check_data_current()?;
        let lease = self.source.journal().acquire_preconstruction_records(
            &self.request.enrollment_ref,
            &self.request.accepted_manifest_ref,
            &self.session,
        )?;
        lease.require_native_origin(&self.source.native_binding())?;
        self.source
            .check_current_under_preconstruction_lease(&lease)?;
        lease.require_current_durable_disclosure_receipts_v1()?;
        if lease.manifest().proposal_input() != self.fixed.proposal().input()
            || lease.enrollment().participant_id() != self.peer.scope.participant_id
        {
            return Err(Error::ReviewMismatch);
        }
        self.check_data_current()?;
        drop(lease);
        Ok(())
    }
    fn deadline(&self) -> Result<Instant> {
        Ok(self
            .peer
            .deadline()
            .min(self.source.native_binding().bounded_deadline()?))
    }
}
fn receive_delivery(
    mut stream: UnixStream,
    peer: AuthenticatedPeer,
    request: DurableReviewDeliveryRequestV1,
    source: Arc<FreshDurableDeliveryEntryV2>,
    session: Arc<SignerConsentSession>,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
) -> authority_bridge::Result<ImportedDeliveryReviewV2> {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    let collector = receiver_diagnostics_v2::Collector::default();
    borrowed_receive_terminal_v2(
        &mut stream,
        |stream| {
            receive_delivery_borrowed_v2(
                stream,
                peer,
                request,
                source,
                session,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                observer,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                Some(&collector),
            )
        },
        |_error| {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            collector.emit_terminal(_error);
        },
    )
}

fn receive_delivery_borrowed_v2(
    stream: &mut UnixStream,
    peer: AuthenticatedPeer,
    request: DurableReviewDeliveryRequestV1,
    source: Arc<FreshDurableDeliveryEntryV2>,
    session: Arc<SignerConsentSession>,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
    #[cfg(feature = "synthetic-born-joined-qualification")] collector: Option<
        &receiver_diagnostics_v2::Collector,
    >,
) -> authority_bridge::Result<ImportedDeliveryReviewV2> {
    let deadline = (Instant::now() + Duration::from_secs(120))
        .min(peer.deadline())
        .min(
            receive_result_v2!(
                collector,
                DeliveryReceiveNativeDeadline,
                signer,
                source.native_binding().bounded_deadline()
            )
            .map_err(bridge_error)?,
        );
    receive_result_v2!(
        collector,
        DeliveryReceiveRequest,
        bridge,
        request.validate()
    )?;
    receive_result_v2!(
        collector,
        DeliveryReceiveSource,
        signer,
        durable_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::ImportSource,
            source.check_current()
        )
    )
    .map_err(bridge_error)?;
    let journal = source.journal();
    let original = receive_result_v2!(
        collector,
        DeliveryReceiveOriginalHistory,
        journal,
        journal.durable_construction_history_v1(&request.own_disclosure, &session)
    )?;
    if receive_denied_v2!(
        collector,
        DeliveryReceiveOriginalBinding,
        original.redisclosure().is_some()
    ) {
        return Err(BridgeError::Binding);
    }
    let current = if let Some(current) = &request.current_disclosure {
        let renewed = receive_result_v2!(
            collector,
            DeliveryReceiveCurrentHistory,
            journal,
            journal.durable_construction_history_v1(current, &session)
        )?;
        receive_result_v2!(
            collector,
            DeliveryReceiveRedisclosureBinding,
            bridge,
            renewed.validate_redisclosure_of(&original)
        )?;
        renewed
    } else {
        original.clone()
    };
    if receive_denied_v2!(
        collector,
        DeliveryReceiveRecipientBinding,
        !authority_bridge::ipc::exact_local_recipient(current.recipient_transport(), &peer)
            || !peer.scope.history_read
            || !peer.scope.preconstruction_export
            || peer.native_origin != source.native_binding()
    ) {
        return Err(BridgeError::Permission);
    }
    receive_result_v2!(
        collector,
        DeliveryReceiveMaterialOwner,
        construction,
        original.request().material.verify_owner(
            &receive_result_v2!(
                collector,
                DeliveryReceiveViewingKey,
                signer,
                source.account().fvk()
            )
            .map_err(bridge_error)?
        )
    )
    .map_err(bridge_error)?;
    let lease = receive_result_v2!(
        collector,
        DeliveryReceiveLease,
        journal,
        journal.acquire_preconstruction_records(
            &request.enrollment_ref,
            &request.accepted_manifest_ref,
            &session,
        )
    )?;
    receive_result_v2!(
        collector,
        DeliveryReceiveNativeOrigin,
        journal,
        lease.require_native_origin(&source.native_binding())
    )?;
    receive_result_v2!(
        collector,
        DeliveryReceiveSourceUnderLease,
        signer,
        source.check_current_under_preconstruction_lease(&lease)
    )
    .map_err(bridge_error)?;
    receive_result_v2!(
        collector,
        DeliveryReceiveReceipts,
        journal,
        lease.require_current_durable_disclosure_receipts_v1()
    )?;
    let proposal = receive_result_v2!(
        collector,
        DeliveryReceiveProposal,
        unknown,
        Proposal::validate(lease.manifest().proposal_input().clone())
    )
    .map_err(|_| BridgeError::Binding)?;
    let account_id = receive_result_v2!(
        collector,
        DeliveryReceiveAccount,
        signer,
        source.account().account_id()
    )
    .map_err(bridge_error)?;
    let original_scope = &original.request().scope;
    let born_scope = &source.record().account_record.terms.scope;
    if receive_denied_v2!(
        collector,
        DeliveryReceiveAccountBinding,
        lease.enrollment().account_id() != account_id
            || lease.enrollment().participant_id() != peer.scope.participant_id
            || lease.enrollment().agreement_id() != peer.scope.agreement_id
            || lease.manifest().manifest_digest() != peer.scope.manifest_digest
            || original_scope.proposal != *proposal.input()
            || original_scope.account_id != account_id
            || proposal.manifest().agreement.agreement_id != born_scope.agreement_id
            || proposal.manifest().agreement.obligation_id != born_scope.obligation_id
            || !receive_result_v2!(
                collector,
                DeliveryReceiveReviewerScope,
                construction,
                original_scope.permits_local_reviewer_account(&account_id)
            )
            .map_err(bridge_error)?
    ) {
        return Err(BridgeError::Binding);
    }
    let check = || -> authority_bridge::Result<()> {
        if receive_denied_v2!(
            collector,
            DeliveryReceiveDeadline,
            Instant::now() >= deadline
        ) {
            return Err(BridgeError::Permission);
        }
        receive_result_v2!(
            collector,
            DeliveryReceiveOriginalSource,
            signer,
            source.check_original_source_current()
        )
        .map_err(bridge_error)?;
        receive_result_v2!(
            collector,
            DeliveryReceivePeer,
            signer,
            durable_flow_observe_v1!(
                observer,
                flow_diag_v1::DurableFlowStageV1::ImportSource,
                peer.check_current()
            )
        )
        .map_err(bridge_error)?;
        receive_result_v2!(
            collector,
            DeliveryReceiveNativeOrigin,
            journal,
            lease.require_native_origin(&source.native_binding())
        )?;
        receive_result_v2!(
            collector,
            DeliveryReceiveReceipts,
            journal,
            lease.require_current_durable_disclosure_receipts_v1()
        )?;
        receive_result_v2!(
            collector,
            DeliveryReceiveMaterialScope,
            construction,
            original_scope.check_valid_at(receive_result_v2!(
                collector,
                DeliveryReceiveMaterialClock,
                bridge,
                now()
            )?)
        )
        .map_err(bridge_error)?;
        Ok(())
    };
    let request_digest = receive_result_v2!(
        collector,
        DeliveryReceiveRequestDigest,
        bridge,
        request.digest()
    )?;
    receive_result_v2!(
        collector,
        DeliveryReceiveReadyWrite,
        bridge,
        wire::bounded_write(
            stream,
            &DeliveryResponseV1::Ready {
                request_digest: request_digest.clone(),
                account_id: account_id.clone(),
                participant_id: peer.scope.participant_id.clone(),
                agreement_id: peer.scope.agreement_id.clone(),
                manifest_digest: peer.scope.manifest_digest.clone(),
                local_grant_id: peer.grant_id.clone(),
                local_channel_digest: peer.channel_digest.clone(),
            },
            deadline,
            &check,
        )
    )?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut expected: Option<(String, usize)> = None;
    loop {
        check()?;
        // Waiting for the engine's independently verified export intent is not
        // a new permission window. Preserve the original absolute deadline and
        // partial frame while polling actual revocation/scope every 100 ms.
        let frame = receive_result_v2!(
            collector,
            DeliveryReceiveFrame,
            origin,
            wholepact_signer_origin::framing::read_frame_capped_checked_until(
                stream,
                &peer.peer,
                128 * 1024,
                deadline,
                || check().map_err(|_| wholepact_signer_origin::Error::Permission),
            )
        )
        .map_err(|_| BridgeError::Ipc)?;
        check()?;
        let command: DeliveryCommandV1 = receive_result_v2!(
            collector,
            DeliveryReceiveCommandParse,
            unknown,
            wholepact_core::parse_typed_json(&frame)
        )
        .map_err(|_| BridgeError::Binding)?;
        match &command {
            DeliveryCommandV1::CheckCurrent if expected.is_none() => {
                receive_result_v2!(
                    collector,
                    DeliveryReceiveCurrentWrite,
                    bridge,
                    wire::bounded_write(
                        stream,
                        &DeliveryResponseV1::Current {
                            request_digest: request_digest.clone(),
                        },
                        deadline,
                        &check,
                    )
                )?;
            }
            DeliveryCommandV1::Begin {
                payload_digest,
                payload_bytes,
            } if expected.is_none() => {
                if receive_denied_v2!(
                    collector,
                    DeliveryReceiveCommandBinding,
                    payload_digest.len() != 64
                        || !payload_digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                ) {
                    return Err(BridgeError::Binding);
                }
                let size = receive_result_v2!(
                    collector,
                    DeliveryReceivePayloadLimit,
                    unknown,
                    usize::try_from(*payload_bytes)
                )
                .map_err(|_| BridgeError::Limit)?;
                if receive_denied_v2!(
                    collector,
                    DeliveryReceivePayloadLimit,
                    size == 0 || size > wire::MAX_PAYLOAD
                ) {
                    return Err(BridgeError::Limit);
                }
                bytes.reserve(size);
                expected = Some((payload_digest.clone(), size));
                receive_result_v2!(
                    collector,
                    DeliveryReceiveReceivingWrite,
                    bridge,
                    wire::bounded_write(
                        stream,
                        &DeliveryResponseV1::Receiving { received_bytes: 0 },
                        deadline,
                        &check,
                    )
                )?;
            }
            DeliveryCommandV1::Chunk { offset, data_hex } => {
                let (_, size) = receive_result_v2!(
                    collector,
                    DeliveryReceiveCommandBinding,
                    bridge,
                    expected.as_ref().ok_or(BridgeError::Binding)
                )?;
                if receive_denied_v2!(
                    collector,
                    DeliveryReceiveCommandBinding,
                    *offset != bytes.len() as u64
                        || data_hex.is_empty()
                        || data_hex.len() > wire::CHUNK_BYTES * 2
                        || data_hex.len() % 2 != 0
                        || !data_hex
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                ) {
                    return Err(BridgeError::Binding);
                }
                let chunk = Zeroizing::new(
                    receive_result_v2!(
                        collector,
                        DeliveryReceiveChunkDecode,
                        unknown,
                        hex::decode(data_hex)
                    )
                    .map_err(|_| BridgeError::Binding)?,
                );
                if receive_denied_v2!(
                    collector,
                    DeliveryReceivePayloadLimit,
                    bytes
                        .len()
                        .checked_add(chunk.len())
                        .is_none_or(|n| n > *size)
                ) {
                    return Err(BridgeError::Limit);
                }
                bytes.extend_from_slice(&chunk);
                receive_result_v2!(
                    collector,
                    DeliveryReceiveReceivingWrite,
                    bridge,
                    wire::bounded_write(
                        stream,
                        &DeliveryResponseV1::Receiving {
                            received_bytes: bytes.len() as u64,
                        },
                        deadline,
                        &check,
                    )
                )?;
            }
            DeliveryCommandV1::Finish => break,
            _ => {
                return receive_result_v2!(
                    collector,
                    DeliveryReceiveCommandBinding,
                    bridge,
                    Err(BridgeError::Binding)
                );
            }
        }
    }
    let (digest, size) = receive_result_v2!(
        collector,
        DeliveryReceivePayloadBinding,
        bridge,
        expected.ok_or(BridgeError::Binding)
    )?;
    if receive_denied_v2!(
        collector,
        DeliveryReceivePayloadBinding,
        bytes.len() != size || hex::encode(Sha256::digest(bytes.as_slice())) != digest
    ) {
        return Err(BridgeError::Binding);
    }
    let payload: DurableReviewPayloadV1 = receive_result_v2!(
        collector,
        DeliveryReceivePayloadParse,
        unknown,
        wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, wire::MAX_PAYLOAD)
    )
    .map_err(|_| BridgeError::Binding)?;
    if receive_denied_v2!(
        collector,
        DeliveryReceivePayloadCanonical,
        receive_result_v2!(
            collector,
            DeliveryReceivePayloadCanonical,
            bridge,
            payload.encode()
        )?
        .as_slice()
            != bytes.as_slice()
    ) {
        return Err(BridgeError::Binding);
    }
    let own = receive_result_v2!(
        collector,
        DeliveryReceiveContributionBinding,
        bridge,
        payload
            .contributions
            .iter()
            .find(|c| c.request().scope.account_id == account_id)
            .ok_or(BridgeError::Binding)
    )?;
    if receive_denied_v2!(
        collector,
        DeliveryReceiveContributionBinding,
        own != &original
    ) {
        return Err(BridgeError::Binding);
    }
    for contribution in &payload.contributions {
        receive_result_v2!(
            collector,
            DeliveryReceiveMaterialScope,
            construction,
            contribution
                .request()
                .scope
                .check_valid_at(receive_result_v2!(
                    collector,
                    DeliveryReceiveMaterialClock,
                    bridge,
                    now()
                )?)
        )
        .map_err(bridge_error)?;
    }
    let unsigned = Zeroizing::new(
        receive_result_v2!(
            collector,
            DeliveryReceiveUnsignedDecode,
            unknown,
            hex::decode(&payload.unsigned_pczt_hex)
        )
        .map_err(|_| BridgeError::Binding)?,
    );
    let proved = Zeroizing::new(
        receive_result_v2!(
            collector,
            DeliveryReceiveProvedDecode,
            unknown,
            hex::decode(&payload.proved_pczt_hex)
        )
        .map_err(|_| BridgeError::Binding)?,
    );
    check()?;
    let fixed = receive_result_v2!(
        collector,
        DeliveryReceiveEconomics,
        signer,
        VerifiedDurableEconomicsV1::verify(
            &proposal,
            &unsigned,
            &proved,
            &payload.contributions,
            &account_id,
            payload
                .output_actions
                .iter()
                .map(|m| wholepact_protocol::construction::OutputActionMapping {
                    output_id: m.output_id.clone(),
                    action_index: m.action_index,
                })
                .collect(),
            wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
        )
    )
    .map_err(|_| BridgeError::Binding)?;
    if receive_denied_v2!(
        collector,
        DeliveryReceiveFinalBinding,
        fixed.verified().identity().proposal_binding != request.proposal_binding
    ) {
        return Err(BridgeError::Binding);
    }
    check()?;
    let imported = ImportedDeliveryReviewV2 {
        fixed: Arc::new(fixed),
        request,
        source: source.clone(),
        peer: peer.clone(),
        session: session.clone(),
        scopes: payload
            .contributions
            .iter()
            .map(|c| c.request().scope.clone())
            .collect(),
    };
    imported
        .check_data_current_observed_v2(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            collector,
        )
        .map_err(bridge_error)?;
    receive_result_v2!(
        collector,
        DeliveryReceiveImportedWrite,
        bridge,
        wire::bounded_write(
            stream,
            &DeliveryResponseV1::Imported {
                receipt: DurableReviewDeliveryReceiptV1 {
                    version: 1,
                    recipient_request_digest: request_digest,
                    payload_digest: digest,
                    payload_bytes: size as u64,
                    state: "imported_for_review".into(),
                },
            },
            deadline,
            &check,
        )
    )?;
    drop(lease);
    Ok(imported)
}

fn fixed_binding(source: &ImportedDeliveryReviewV2) -> Result<DurableFixedCandidateBindingV1> {
    wholepact_core::parse_typed_json(
        &serde_json::to_vec(source.fixed.verified().identity()).map_err(|_| Error::InvalidData)?,
    )
    .map_err(|_| Error::InvalidData)
}
fn terms_from_current_policy_records(
    source: &ImportedDeliveryReviewV2,
    from: u64,
    until: u64,
) -> Result<DurablePaymentAdmissionTermsV1> {
    let entry = source.source.as_ref();
    let extension = entry.record().extension()?;
    let old = &extension.account_extension;
    let economics = source.fixed.as_ref();
    let fixed = economics.verified();
    let lease = entry.journal().acquire_preconstruction_records(
        &source.request.enrollment_ref,
        &source.request.accepted_manifest_ref,
        &source.session,
    )?;
    lease.require_native_origin(&entry.native_binding())?;
    lease.require_current_durable_disclosure_receipts_v1()?;
    let recipient_policy_scope_digest = authority_bridge::validate_durable_delivery_policy_v2(
        entry,
        lease.enrollment(),
        lease.manifest(),
        fixed,
        economics.input_actions(),
        economics.output_actions(),
    )
    .map_err(|_| Error::ReviewMismatch)?;
    let account = entry.account().account_id()?;
    let proposal = economics.proposal();
    let owner = proposal
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == account)
        .ok_or(Error::ReviewMismatch)?;
    let inputs = economics
        .input_actions()
        .iter()
        .filter(|i| i.account_id == account)
        .map(|map| {
            let input = fixed
                .private_review_policy()
                .inputs
                .iter()
                .find(|i| i.action_index == map.action_index)
                .ok_or(Error::ReviewMismatch)?;
            Ok(wholepact_authority::InputReservation {
                input_id: map.input_id.clone(),
                nullifier: hex::encode(input.nullifier),
                action_index: map.action_index as u64,
                value_zatoshis: input.value_zatoshis,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let result = DurablePaymentAdmissionTermsV1 {
        version: 1,
        identity: old.terms.identity.clone(),
        original_policy_digest: old.terms.original_policy_digest.clone(),
        original_genesis_digest: entry
            .genesis()
            .digest()
            .map_err(|_| Error::ReviewMismatch)?,
        original_birth_commit_digest: old.terms.birth_commit_digest.clone(),
        original_roster_extension_digest: extension.digest().map_err(|_| Error::ReviewMismatch)?,
        original_enrollment_ref: old.enrollment_ref.clone(),
        writer_certificate_digest: old.terms.signer.writer_certificate_digest.clone(),
        fixed: fixed_binding(source)?,
        authorization_id: authority_bridge::durable_proposal_v1::manual_authorization_id(
            fixed.identity(),
            &account,
        )
        .map_err(|_| Error::ReviewMismatch)?,
        recipient_policy_scope_digest,
        concrete_recipient_scope_digest:
            wholepact_core::manual_construction::construction_recipient_scope_digest(proposal)
                .map_err(|_| Error::ReviewMismatch)?,
        inputs,
        maximum_debit_zatoshis: proposal
            .accounting()
            .participant_net_debits
            .get(&owner.participant_id)
            .ok_or(Error::ReviewMismatch)?
            .as_zatoshis(),
        fee_share_zatoshis: owner.fee_share.as_zatoshis(),
        transaction_fee_zatoshis: proposal.manifest().transaction_fee.as_zatoshis(),
        valid_from_ms: from,
        valid_until_ms: until,
    };
    result.validate().map_err(|_| Error::ReviewMismatch)?;
    source.check_data_current()?;
    drop(lease);
    Ok(result)
}
fn scope_from_original(
    source: &ImportedDeliveryReviewV2,
    delivery: &DurableDeliveryPlanV2,
    history: &ReconciledAuthorityHistory,
) -> Result<DurableDeliveryScopeV2> {
    source.check_current()?;
    let terms =
        terms_from_current_policy_records(source, delivery.valid_from_ms, delivery.valid_until_ms)?;
    let extension = source.source.record().extension()?;
    let witness = source.source.original_witness_disclosure_data_v1()?;
    if history.disclosure() != &witness
        || history
            .account_policy()
            .policy_digest()
            .map_err(|_| Error::ReviewMismatch)?
            != source
                .source
                .record()
                .account_record
                .terms
                .original_policy_digest
    {
        return Err(Error::Authentication);
    }
    let mut materials = source
        .scopes
        .iter()
        .map(|s| {
            Ok(DurableDeliveryMaterialScopeRefV2 {
                account_id: s.account_id.clone(),
                original_scope_digest: s.digest().map_err(|_| Error::ReviewMismatch)?,
                valid_from_unix_seconds: s.valid_from_unix_seconds,
                valid_until_unix_seconds: s.valid_until_unix_seconds,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    materials.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    let independently_derived_inputs = terms.inputs.clone();
    let scope = DurableDeliveryScopeV2 {
        version:2, accepted_manifest_ref:source.request.accepted_manifest_ref.clone(), original_writer_epoch:extension.account_extension.terms.signer.writer_epoch,
        original_ceilings:DurableDeliveryOriginalCeilingsV2 { payment_valid_from_ms:terms.valid_from_ms, payment_valid_until_ms:terms.valid_until_ms, enrollment_expires_at_ms:extension.account_extension.terms.scope.expires_at_ms, policy_expires_at_ms:history.account_policy().policy_expires_at_ms, material_scopes:materials.clone() },
        authorization:terms, delivery:delivery.clone(), witness:witness.clone(), disclosure_rule:DurableDeliveryDisclosureRuleV2::WholeTransactionAndConnectionMetadataToProviderCommitmentsAndLinkageToWitness,
    };
    scope
        .matches_original_claims(
            history.account_policy(),
            &extension,
            source.fixed.proposal(),
            &fixed_binding(source)?,
            &source.request.accepted_manifest_ref,
            extension.account_extension.terms.signer.writer_epoch,
            &witness,
            &independently_derived_inputs,
            &materials,
        )
        .map_err(|_| Error::ReviewMismatch)?;
    // Inputs above were derived independently from the imported verified PCZT
    // action map, never supplied by the plan or a caller's scope projection.
    source.check_current()?;
    Ok(scope)
}
fn require_workspace(
    source: &FreshDurableDeliveryEntryV2,
    owner: &NativeWitnessWorkspace,
) -> Result<()> {
    source.check_original_source_current()?;
    owner.require_durable_credential_v1(
        &source.native_binding(),
        &source.original_witness_disclosure_data_v1()?,
        &source
            .record()
            .account_record
            .terms
            .signer
            .owner_certificate_digest,
    )
}
fn source_history(
    source: &ImportedDeliveryReviewV2,
    owner: &NativeWitnessWorkspace,
    #[cfg(feature = "synthetic-born-joined-qualification")] failure: &mut Option<
        wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1,
    >,
) -> Result<ReconciledAuthorityHistory> {
    owner.durable_delivery_history_v2(
        source.deadline()?,
        || {
            require_workspace(&source.source, owner)?;
            source.check_current()
        },
        #[cfg(feature = "synthetic-born-joined-qualification")]
        failure,
    )
}
fn require_live(scope: &DurableDeliveryScopeV2) -> Result<()> {
    let time = now_ms()?;
    if time < scope.delivery.valid_from_ms || time >= scope.delivery.valid_until_ms {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
fn retained_scope(
    intent: &RetainedDurableDeliveryAdmissionIntentV2,
) -> Result<&DurableDeliveryScopeV2> {
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &intent.request().control
    else {
        return Err(Error::ReviewMismatch);
    };
    Ok(&record.scope)
}
fn status_from_history(
    entry: &FreshDurableDeliveryEntryV2,
    intent: &RetainedDurableDeliveryAdmissionIntentV2,
    history: &ReconciledAuthorityHistory,
) -> Result<DurableDeliveryAdmissionStatusV2> {
    entry.check_current()?;
    let scope = retained_scope(intent)?;
    let remote = history
        .durable_delivery_admission_v2(&intent.request().operation_id)
        .map_err(|_| Error::RecoveryRequired)?;
    if remote.is_some_and(|request| request != intent.request())
        || history.disclosure() != intent.disclosure()
        || history.account_policy().owner_certificate_digest != intent.owner_certificate_digest()
        || scope.accepted_manifest_ref != intent.manifest_ref()
    {
        return Err(Error::ReviewMismatch);
    }
    if remote.is_none() && history.snapshot().head != intent.request().expected_head {
        return Err(Error::RecoveryRequired);
    }
    Ok(DurableDeliveryAdmissionStatusV2 {
        version: 2,
        request: intent.request().clone(),
        scope: scope.clone(),
        original_enrollment_ref: intent.enrollment_ref().into(),
        original_accepted_manifest_ref: intent.manifest_ref().into(),
        original_local_intent_digest: intent.history_digest()?,
        authenticated_witness_history_digest: history
            .history_digest()
            .map_err(|_| Error::ReviewMismatch)?,
        witness_committed: remote.is_some(),
        current_fixed_material_source: "unchecked".into(),
    })
}
/// Only the dedicated same-original redisclosure ingress creates this nominal
/// wrapper. General initial capture/construction never enters the v2 profile.
pub(super) struct PreparedRedisclosureV2 {
    source: Arc<FreshDurableDeliveryEntryV2>,
    prepared: crate::native_ui::durable_construction_v1::PreparedDurableConstructionV1,
}
impl PreparedRedisclosureV2 {
    pub(super) fn check_current(&self) -> Result<()> {
        self.source.check_current()
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn request(
        &self,
    ) -> &crate::authority_bridge::durable_construction_v1::DurableConstructionRequestV1 {
        self.prepared.qualification_request()
    }
}
pub(super) struct PreparedAdmissionV2 {
    source: Arc<ImportedDeliveryReviewV2>,
    owner: Arc<NativeWitnessWorkspace>,
    request: OwnerControlRequest,
    prepared: PreparedDurableDeliveryAdmissionIntentV2,
    stream: UnixStream,
    peer: AuthenticatedPeer,
    attempt: u64,
    deadline: Instant,
}
impl PreparedAdmissionV2 {
    pub(super) fn request(&self) -> &OwnerControlRequest {
        &self.request
    }
    fn current(&self) -> Result<()> {
        self.source.check_current()?;
        self.peer.check_current()?;
        self.peer.require_same_grant(&self.source.peer)?;
        require_workspace(&self.source.source, &self.owner)?;
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &self.request.control
        else {
            return Err(Error::ReviewMismatch);
        };
        require_live(&record.scope)?;
        if Instant::now() >= self.deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
    fn display(&self) -> Result<String> {
        self.current()?;
        Ok(format!(
            "PROSPECTIVE V2 DELIVERY ADMISSION ONLY\n\n{}\n\nReview the exact dispatcher leaf and custody commitment, original Host and submission-journal binding, fixed candidate, BOTH owner IDs, provider and route, finite attempt/expiry bounds and original material ceilings. This immutably admits only this complete prospective scope at the independent Witness. Acquire, Activate, Reserve, signing, extraction and dispatch are DISABLED. No v1 admission is upgraded. A partial/unknown remote outcome remains retained and must be audited exactly; it is not rolled back.",
            self.prepared.display()?
        ))
    }
}
/// A real owner-mTLS Controlled response is NOT complete-history evidence.
/// This private owner preserves the original connection, clock and exact local
/// commitment even if the one permitted read-only audit subsequently fails.
struct PendingAuditV2 {
    entry: Arc<FreshDurableDeliveryEntryV2>,
    session: Arc<SignerConsentSession>,
    owner: Arc<NativeWitnessWorkspace>,
    retained: RetainedDurableDeliveryAdmissionIntentV2,
    controlled: wholepact_authority::AccountSnapshot,
    stream: UnixStream,
    peer: AuthenticatedPeer,
    attempt: u64,
    deadline: Instant,
    audit_started: std::sync::atomic::AtomicBool,
}
fn start_readonly_audit_once(started: &std::sync::atomic::AtomicBool) -> Result<()> {
    if started.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return Err(Error::Unavailable);
    }
    Ok(())
}
fn require_same_committed_snapshot(
    controlled: &wholepact_authority::AccountSnapshot,
    history: &wholepact_authority::AccountSnapshot,
) -> Result<()> {
    if history != controlled {
        return Err(Error::Uncertain);
    }
    Ok(())
}
impl PendingAuditV2 {
    fn check_current(&self) -> Result<()> {
        self.entry.check_current()?;
        self.peer.check_current()?;
        require_workspace(&self.entry, &self.owner)?;
        let original = self
            .entry
            .journal()
            .durable_delivery_admission_intent_v2(
                &retained_scope(&self.retained)?
                    .authorization
                    .authorization_id,
                &self.session,
            )?
            .ok_or(Error::RecoveryRequired)?;
        if original != self.retained
            || self.peer.native_origin != self.entry.native_binding()
            || Instant::now() >= self.deadline
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableDeliveryStageV2 {
    Import,
    OriginalEvidence,
    Source,
    History,
    Scope,
    PrepareIntent,
    NativeReview,
    RetainIntent,
    OwnerSend,
    Audit,
}
pub struct DurableDeliveryFailureV2 {
    attempt: u64,
    stage: DurableDeliveryStageV2,
    error: Error,
    import_error: Option<BridgeError>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    transport:
        Option<wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1>,
}
impl DurableDeliveryFailureV2 {
    pub fn attempt(&self) -> u64 {
        self.attempt
    }
    pub fn stage(&self) -> DurableDeliveryStageV2 {
        self.stage
    }
    pub fn into_error(self) -> Error {
        self.error
    }
    pub fn into_import_error(self) -> Option<BridgeError> {
        self.import_error
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub fn into_parts(
        self,
    ) -> (
        u64,
        DurableDeliveryStageV2,
        Error,
        Option<BridgeError>,
        Option<wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1>,
    ) {
        (
            self.attempt,
            self.stage,
            self.error,
            self.import_error,
            self.transport,
        )
    }
}
enum DeliveryOutcomeV2 {
    Prepared(PreparedAdmissionV2),
    AwaitingAudit(Arc<PendingAuditV2>),
    Completed(DurableDeliveryAdmissionStatusV2),
}
struct DeliveryJobV2 {
    receive: mpsc::Receiver<std::result::Result<DeliveryOutcomeV2, DurableDeliveryFailureV2>>,
    epoch: u64,
    attempt: u64,
}
// A diagnostic read may observe a successful completion, but cannot adopt it.
// Keep that exact owned value in the original job until ordinary polling applies
// its original epoch, attempt, pairing and imported-source gates.
struct ImportJobV2<
    T = ImportedDeliveryReviewV2,
    E = BridgeError,
    R = DurableReviewDeliveryRequestV1,
> {
    receive: mpsc::Receiver<std::result::Result<T, E>>,
    pending_result: Option<std::result::Result<T, E>>,
    epoch: u64,
    attempt: u64,
    request: R,
}
impl<T, E, R> ImportJobV2<T, E, R> {
    fn try_take_result(
        &mut self,
    ) -> std::result::Result<std::result::Result<T, E>, mpsc::TryRecvError> {
        match self.pending_result.take() {
            Some(result) => Ok(result),
            None => self.receive.try_recv(),
        }
    }
}
#[cfg(any(test, feature = "synthetic-born-joined-qualification"))]
impl<T, E, R: PartialEq> ImportJobV2<T, E, R> {
    fn take_failure_for(
        &mut self,
        epoch: u64,
        attempt: u64,
        request: &R,
        current_attempt: u64,
    ) -> Option<E> {
        if self.epoch != epoch
            || self.attempt != attempt
            || &self.request != request
            || current_attempt != attempt
        {
            return None;
        }
        match self.try_take_result() {
            Ok(Err(error)) => Some(error),
            Ok(Ok(imported)) => {
                self.pending_result = Some(Ok(imported));
                None
            }
            // Neither an empty channel nor a disconnected worker supplies an
            // actual worker error. Leave ordinary polling to handle disconnect.
            Err(_) => None,
        }
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
struct ImportCorrelationV2 {
    epoch: u64,
    attempt: u64,
    request: DurableReviewDeliveryRequestV1,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl ImportCorrelationV2 {
    fn matches(&self, epoch: u64, attempt: u64, request: &DurableReviewDeliveryRequestV1) -> bool {
        self.epoch == epoch && self.attempt == attempt && &self.request == request
    }
}
#[derive(Default)]
pub(super) struct DurableDeliveryRuntimeV2 {
    pub(super) imported: Option<Arc<ImportedDeliveryReviewV2>>,
    import: Option<ImportJobV2>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    import_terminal: Option<ImportCorrelationV2>,
    job: Option<DeliveryJobV2>,
    next_attempt: u64,
    awaiting_audit: Option<Arc<PendingAuditV2>>,
    pub(super) status: Option<DurableDeliveryAdmissionStatusV2>,
    pub(super) failure: Option<DurableDeliveryFailureV2>,
}
impl DurableDeliveryRuntimeV2 {
    pub(super) fn clear(&mut self) {
        self.imported = None;
        self.import = None;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            self.import_terminal = None;
        }
        self.job = None;
        self.awaiting_audit = None;
    }
    pub(super) fn response_received(&self) -> bool {
        self.awaiting_audit.is_some()
    }
    fn attempt(&mut self) -> Result<u64> {
        self.next_attempt = self.next_attempt.checked_add(1).ok_or(Error::Unavailable)?;
        self.failure = None;
        self.status = None;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            self.import_terminal = None;
        }
        Ok(self.next_attempt)
    }
}
// Correlation observations only: none of these methods creates an import,
// adopts a successful result, or supplies current source authority.
#[cfg(feature = "synthetic-born-joined-qualification")]
impl DurableDeliveryRuntimeV2 {
    pub(super) fn qualification_import_attempt_v2(
        &self,
        epoch: u64,
        request: &DurableReviewDeliveryRequestV1,
    ) -> Result<(u64, u64, bool)> {
        if self.job.is_some()
            || self.awaiting_audit.is_some()
            || self.status.is_some()
            || self.failure.is_some()
            || self.imported.is_some()
            || self.import_terminal.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        if let Some(job) = &self.import {
            if job.epoch != epoch || &job.request != request || job.attempt != self.next_attempt {
                return Err(Error::ReviewMismatch);
            }
            return Ok((
                job.attempt.checked_sub(1).ok_or(Error::ReviewMismatch)?,
                job.attempt,
                true,
            ));
        }
        Ok((
            self.next_attempt,
            self.next_attempt.checked_add(1).ok_or(Error::Unavailable)?,
            false,
        ))
    }
    pub(super) fn qualification_import_current_v2(
        &self,
        epoch: u64,
        predecessor: u64,
        expected: u64,
        request: &DurableReviewDeliveryRequestV1,
        job_seen: &mut bool,
    ) -> Result<bool> {
        if predecessor.checked_add(1) != Some(expected)
            || self.job.is_some()
            || self.awaiting_audit.is_some()
            || self.status.is_some()
            || self.failure.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        if let Some(job) = &self.import {
            if self.next_attempt != expected
                || job.attempt != expected
                || job.epoch != epoch
                || &job.request != request
                || self.imported.is_some()
                || self.import_terminal.is_some()
            {
                return Err(Error::ReviewMismatch);
            }
            *job_seen = true;
            return Ok(false);
        }
        if let Some(imported) = &self.imported {
            if self.next_attempt != expected
                || &imported.request != request
                || !self
                    .import_terminal
                    .as_ref()
                    .is_some_and(|actual| actual.matches(epoch, expected, request))
            {
                return Err(Error::ReviewMismatch);
            }
            *job_seen = true;
            return Ok(true);
        }
        if *job_seen || self.next_attempt != predecessor || self.import_terminal.is_some() {
            return Err(Error::ReviewMismatch);
        }
        Ok(false)
    }
    pub(super) fn qualification_import_failure_attempt_v2(
        &self,
        epoch: u64,
        request: &DurableReviewDeliveryRequestV1,
    ) -> Option<u64> {
        if let Some(job) = &self.import {
            return (job.epoch == epoch
                && job.attempt == self.next_attempt
                && &job.request == request)
                .then_some(job.attempt);
        }
        self.import_terminal
            .as_ref()
            .filter(|actual| actual.matches(epoch, self.next_attempt, request))
            .map(|actual| actual.attempt)
    }
    pub(super) fn qualification_take_import_failure_v2(
        &mut self,
        epoch: u64,
        expected: u64,
        request: &DurableReviewDeliveryRequestV1,
    ) -> Option<DurableDeliveryFailureV2> {
        if self.next_attempt != expected {
            return None;
        }
        if let Some(job) = self.import.as_mut() {
            let error = job.take_failure_for(epoch, expected, request, self.next_attempt)?;
            let job = self.import.take().expect("matched import job");
            self.import_terminal = Some(ImportCorrelationV2 {
                epoch: job.epoch,
                attempt: job.attempt,
                request: job.request,
            });
            return Some(DurableDeliveryFailureV2 {
                attempt: expected,
                stage: DurableDeliveryStageV2::Import,
                error: Error::Verification,
                import_error: Some(error),
                transport: None,
            });
        }
        if !self
            .import_terminal
            .as_ref()
            .is_some_and(|actual| actual.matches(epoch, expected, request))
            || !self.failure.as_ref().is_some_and(|failure| {
                failure.attempt == expected
                    && matches!(
                        failure.stage,
                        DurableDeliveryStageV2::Import | DurableDeliveryStageV2::Source
                    )
            })
        {
            return None;
        }
        self.failure.take()
    }
}
fn send_response(
    stream: &mut UnixStream,
    peer: &AuthenticatedPeer,
    deadline: Instant,
    response: &DurableDeliveryResponseV2,
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    wire::bounded_write(stream, response, deadline, || {
        check().map_err(bridge_error)?;
        peer.check_current().map_err(bridge_error)
    })
    .map_err(|_| Error::Uncertain)
}
fn public_evidence(
    open: &OpenAccount,
    peer: &AuthenticatedPeer,
) -> Result<OriginalWitnessPublicDataV2> {
    open.check_pairing()?.peer.require_same_grant(peer)?;
    macro_rules! derive {
        ($source:expr) => {{
            let source = $source;
            source.check_current()?;
            if source.native_binding() != peer.native_origin {
                return Err(Error::Authentication);
            }
            let record = source.record();
            let extension = record.extension()?;
            let evidence = OriginalWitnessPublicDataV2 {
                version: 2,
                original_terms: record.account_record.terms.clone(),
                original_roster: record.roster.clone(),
                original_signer_roster_record_digest: record.reference()?,
                witness: source.original_witness_disclosure_data_v1()?,
                native_entry_digest: source.native_binding().entry_digest().into(),
                original_enrollment_ref: extension.account_extension.enrollment_ref.clone(),
                original_witness_extension_digest: extension
                    .account_extension
                    .digest()
                    .map_err(|_| Error::ReviewMismatch)?,
                local_grant_id: peer.grant_id.clone(),
                local_channel_digest: peer.channel_digest.clone(),
            };
            evidence.validate().map_err(|_| Error::ReviewMismatch)?;
            source.check_current()?;
            evidence
        }};
    }
    let evidence = if let Some(source) = &open.durable_delivery_entry {
        derive!(source)
    } else if let Some(source) = &open.durable_born_entry {
        derive!(source)
    } else {
        return Err(Error::Unavailable);
    };
    peer.check_current()?;
    Ok(evidence)
}
impl NativeRuntime {
    pub(super) fn prepare_durable_delivery_redisclosure_v2(
        &mut self,
        stream: UnixStream,
        peer: AuthenticatedPeer,
        request: crate::authority_bridge::durable_construction_v1::DurableConstructionRedisclosureRequestV1,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let source = open
            .durable_delivery_entry
            .clone()
            .ok_or(Error::Unavailable)?;
        source.check_current()?;
        open.check_pairing()?.peer.require_same_grant(&peer)?;
        if self.pending.is_some()
            || open.history_workers.len() >= 8
            || open.durable_delivery.import.is_some()
            || open.durable_delivery.job.is_some()
            || open.durable_delivery.imported.is_some()
            || open.durable_delivery.awaiting_audit.is_some()
            || open
                .enrollment
                .as_ref()
                .is_none_or(|e| e.reference() != request.enrollment_ref)
            || open
                .manifest
                .as_ref()
                .is_none_or(|m| m.reference() != request.accepted_manifest_ref)
            || request.original.expected_request_digest.is_none()
        {
            return Err(Error::ReviewMismatch);
        }
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        let prepared = crate::native_ui::durable_construction_v1::PreparedDurableConstructionV1::prepare_redisclosure(
            request, peer, stream, &open.journal, session, &source.native_binding(), &open.vault)?;
        source.check_current()?;
        let review = ExactNativeReview::stage(
            &open.authority,
            prepared.digest(),
            prepared.display()?,
            epoch,
        )?;
        self.pending = Some(PendingDecision {
            review,
            operation: Operation::DurableDeliveryRedisclosureV2(Box::new(PreparedRedisclosureV2 {
                source,
                prepared,
            })),
        });
        self.message = "Review a fresh privacy disclosure of exactly the same original material to this current recipient. Original bytes, audience and absolute expiry cannot change. No financial action is authorized.";
        Ok(())
    }
    pub(super) fn approve_durable_delivery_redisclosure_v2(
        &mut self,
        prepared: PreparedRedisclosureV2,
        decision: NativeDecision,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        prepared.check_current()?;
        open.check_pairing()?;
        if !open
            .durable_delivery_entry
            .as_ref()
            .is_some_and(|source| Arc::ptr_eq(source, &prepared.source))
            || open.history_workers.len() >= 8
        {
            return Err(Error::ReviewMismatch);
        }
        let approved = prepared
            .prepared
            .approve(decision, &open.authority, &open.vault)?;
        let source = prepared.source;
        let session = open.session.clone().ok_or(Error::Locked)?;
        let journal = open.journal.clone();
        let worker = std::thread::spawn(move || {
            // The checked serve observes its same terminal Result before its
            // owned stream drops. Do not emit a duplicate after this return.
            let _ = approved.serve_with_original_source_check_v2(&journal, &session, |lease| {
                source
                    .check_current_under_preconstruction_lease(lease)
                    .map_err(bridge_error)
            });
        });
        open.disclosure_worker_ids.insert(worker.thread().id());
        open.history_workers.push(worker);
        Ok(())
    }
}
impl NativeRuntime {
    pub(super) fn start_durable_delivery_import_v2(
        &mut self,
        stream: UnixStream,
        peer: AuthenticatedPeer,
        request: DurableReviewDeliveryRequestV1,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?.peer.require_same_grant(&peer)?;
        if self.pending.is_some()
            || open.durable_delivery.job.is_some()
            || open.durable_delivery.import.is_some()
            || open.durable_delivery.awaiting_audit.is_some()
            || open.history_workers.len() >= 8
            || open
                .enrollment
                .as_ref()
                .is_none_or(|e| e.reference() != request.enrollment_ref)
            || open
                .manifest
                .as_ref()
                .is_none_or(|m| m.reference() != request.accepted_manifest_ref)
        {
            return Err(Error::ReviewMismatch);
        }
        let source = open
            .durable_delivery_entry
            .clone()
            .ok_or(Error::Unavailable)?;
        source.check_current()?;
        let session = open.session.clone().ok_or(Error::Locked)?;
        let attempt = open.durable_delivery.attempt()?;
        let (send, receive) = mpsc::channel();
        let accepted_request = request.clone();
        let worker = std::thread::spawn(move || {
            let result = receive_delivery(
                stream,
                peer,
                request,
                source,
                session,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                None,
            );
            let _ = send.send(result);
        });
        open.history_workers.push(worker);
        open.durable_delivery.imported = None;
        open.durable_delivery.import = Some(ImportJobV2 {
            receive,
            pending_result: None,
            epoch,
            attempt,
            request: accepted_request,
        });
        Ok(())
    }
    pub(super) fn handle_durable_delivery_v2(
        &mut self,
        mut stream: UnixStream,
        peer: AuthenticatedPeer,
        command: DurableDeliveryCommandV2,
        epoch: u64,
    ) -> Result<()> {
        command.validate().map_err(|_| Error::InvalidData)?;
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?.peer.require_same_grant(&peer)?;
        let deadline = peer
            .deadline()
            .min(open.authority.binding().bounded_deadline()?);
        if let DurableDeliveryCommandV2::OriginalWitnessEvidence {} = command {
            let evidence = public_evidence(open, &peer)?;
            return send_response(
                &mut stream,
                &peer,
                deadline,
                &DurableDeliveryResponseV2::OriginalWitnessEvidence { evidence },
                || public_evidence(open, &peer).map(|_| ()),
            );
        }
        let entry = open
            .durable_delivery_entry
            .clone()
            .ok_or(Error::Unavailable)?;
        if self.pending.is_some()
            || open.durable_delivery.job.is_some()
            || open.durable_delivery.import.is_some()
            || open.durable_delivery.awaiting_audit.is_some()
            || open.history_workers.len() >= 8
        {
            return Err(Error::Locked);
        }
        let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
        require_workspace(&entry, &owner)?;
        let session = open.session.clone().ok_or(Error::Locked)?;
        let imported = open.durable_delivery.imported.clone();
        let attempt = open.durable_delivery.attempt()?;
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut stage = DurableDeliveryStageV2::Source;
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let mut transport = None;
            let result = (|| -> Result<DeliveryOutcomeV2> {
                entry.check_current()?;
                peer.check_current()?;
                match command {
                    DurableDeliveryCommandV2::History { request } => {
                        stage = DurableDeliveryStageV2::History;
                        let intent = entry
                            .journal()
                            .durable_delivery_admission_intent_v2(
                                &request.authorization_id,
                                &session,
                            )?
                            .ok_or(Error::RecoveryRequired)?;
                        let history = owner.durable_delivery_history_v2(
                            deadline,
                            || {
                                entry.check_current()?;
                                peer.check_current()?;
                                require_workspace(&entry, &owner)
                            },
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            &mut transport,
                        )?;
                        let status = status_from_history(&entry, &intent, &history)?;
                        send_response(
                            &mut stream,
                            &peer,
                            deadline,
                            &DurableDeliveryResponseV2::Admission {
                                admission: status.clone(),
                            },
                            || entry.check_current(),
                        )?;
                        Ok(DeliveryOutcomeV2::Completed(status))
                    }
                    DurableDeliveryCommandV2::Admit { request } => {
                        let source = imported.ok_or(Error::Unavailable)?;
                        if request.import_request != source.request
                            || !Arc::ptr_eq(&source.source, &entry)
                        {
                            return Err(Error::ReviewMismatch);
                        }
                        source.peer.require_same_grant(&peer)?;
                        source.check_current()?;
                        stage = DurableDeliveryStageV2::History;
                        let history = source_history(
                            &source,
                            &owner,
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            &mut transport,
                        )?;
                        stage = DurableDeliveryStageV2::Scope;
                        let scope = scope_from_original(&source, &request.delivery, &history)?;
                        require_live(&scope)?;
                        if let Some(intent) = entry.journal().durable_delivery_admission_intent_v2(
                            &scope.authorization.authorization_id,
                            &session,
                        )? {
                            if retained_scope(&intent)? != &scope {
                                return Err(Error::ReviewMismatch);
                            }
                            let status = status_from_history(&entry, &intent, &history)?;
                            // Retained-but-unconfirmed requests are history only; no
                            // fresh operation ID, renewed approval or hidden retry.
                            send_response(
                                &mut stream,
                                &peer,
                                deadline,
                                &DurableDeliveryResponseV2::Admission {
                                    admission: status.clone(),
                                },
                                || source.check_current(),
                            )?;
                            return Ok(DeliveryOutcomeV2::Completed(status));
                        }
                        let exact=wholepact_authority::durable_delivery_admission_v2::prepare_durable_delivery_admission_request_v2(scope,&history).map_err(|_|Error::ReviewMismatch)?;
                        stage = DurableDeliveryStageV2::PrepareIntent;
                        let prepared = session.prepare_durable_delivery_admission_intent_v2(
                            entry.journal(),
                            exact.clone(),
                            entry.original_witness_disclosure_data_v1()?,
                            &entry
                                .record()
                                .account_record
                                .terms
                                .signer
                                .owner_certificate_digest,
                            &source.request.enrollment_ref,
                            &source.request.accepted_manifest_ref,
                        )?;
                        source.check_current()?;
                        Ok(DeliveryOutcomeV2::Prepared(PreparedAdmissionV2 {
                            source,
                            owner,
                            request: exact,
                            prepared,
                            stream: stream.try_clone()?,
                            peer: peer.clone(),
                            attempt,
                            deadline,
                        }))
                    }
                    _ => Err(Error::Unavailable),
                }
            })();
            if result.is_err() {
                let _ = send_response(
                    &mut stream,
                    &peer,
                    deadline,
                    &DurableDeliveryResponseV2::Denied,
                    || entry.check_original_source_current(),
                );
            }
            let _ = send.send(result.map_err(|error| DurableDeliveryFailureV2 {
                attempt,
                stage,
                error,
                import_error: None,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                transport,
            }));
        });
        open.history_workers.push(worker);
        open.durable_delivery.job = Some(DeliveryJobV2 {
            receive,
            epoch,
            attempt,
        });
        Ok(())
    }
    pub(super) fn approve_durable_delivery_v2(
        &mut self,
        prepared: PreparedAdmissionV2,
        decision: NativeDecision,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?
            .peer
            .require_same_grant(&prepared.peer)?;
        prepared.current()?;
        if decision.binding() != &prepared.source.source.native_binding()
            || decision.reviewed_digest() != prepared.prepared.digest()
            || decision.consumed_at() >= prepared.deadline
            || open.authority.binding() != prepared.source.source.native_binding()
            || !open
                .owner_witness
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &prepared.owner))
        {
            return Err(Error::ReviewMismatch);
        }
        let local = prepared.source.session.native_decision(decision)?;
        let approved = prepared
            .source
            .session
            .approve_durable_delivery_admission_intent_v2(prepared.prepared, local)?;
        let attempt = prepared.attempt;
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut stage = DurableDeliveryStageV2::RetainIntent;
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let mut transport = None;
            let source = prepared.source;
            let owner = prepared.owner;
            let peer = prepared.peer;
            let deadline = prepared.deadline;
            let request = prepared.request;
            let mut stream = prepared.stream;
            let result = (|| -> Result<DeliveryOutcomeV2> {
                source.check_current()?;
                let retained = source
                    .source
                    .journal()
                    .retain_durable_delivery_admission_intent_v2(approved, || {
                        source
                            .check_data_current()
                            .map_err(|_| JournalError::Permission)?;
                        peer.check_current().map_err(|_| JournalError::Permission)?;
                        require_workspace(&source.source, &owner)
                            .map_err(|_| JournalError::Permission)?;
                        if Instant::now() >= deadline {
                            return Err(JournalError::Permission);
                        }
                        Ok(())
                    })?;
                if retained.request() != &request {
                    return Err(Error::RecoveryRequired);
                }
                // The complete immutable local intent exists before the first
                // owner-mTLS request byte, including every callback thereafter.
                source.check_current()?;
                stage = DurableDeliveryStageV2::OwnerSend;
                let controlled = owner.durable_delivery_admit_v2(
                    &request,
                    deadline,
                    || {
                        source.check_current()?;
                        peer.check_current()?;
                        require_workspace(&source.source, &owner)
                    },
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    &mut transport,
                )?;
                // Do not race the one-record admission listener with an
                // automatic History request. An explicit production UI action
                // continues this same connection after a read-only listener is
                // ready. No final status exists at this intermediate boundary.
                Ok(DeliveryOutcomeV2::AwaitingAudit(Arc::new(PendingAuditV2 {
                    entry: source.source.clone(),
                    session: source.session.clone(),
                    owner: owner.clone(),
                    retained,
                    controlled,
                    stream: stream.try_clone()?,
                    peer: peer.clone(),
                    attempt,
                    deadline,
                    audit_started: std::sync::atomic::AtomicBool::new(false),
                })))
            })();
            if result.is_err() {
                let _ = send_response(
                    &mut stream,
                    &peer,
                    deadline,
                    &DurableDeliveryResponseV2::Denied,
                    || source.source.check_original_source_current(),
                );
            }
            let _ = send.send(result.map_err(|error| DurableDeliveryFailureV2 {
                attempt,
                stage,
                error,
                import_error: None,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                transport,
            }));
        });
        open.history_workers.push(worker);
        open.durable_delivery.job = Some(DeliveryJobV2 {
            receive,
            epoch,
            attempt,
        });
        Ok(())
    }
    /// Read-only continuation, available in the production native UI. It
    /// consumes no approval and sends no admission request a second time.
    pub(super) fn begin_durable_delivery_history_audit_v2(&mut self, epoch: u64) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        if self.pending.is_some()
            || open.durable_delivery.job.is_some()
            || open.history_workers.len() >= 8
        {
            return Err(Error::Locked);
        }
        let pending = open
            .durable_delivery
            .awaiting_audit
            .clone()
            .ok_or(Error::Unavailable)?;
        open.check_pairing()?
            .peer
            .require_same_grant(&pending.peer)?;
        if !open
            .durable_delivery_entry
            .as_ref()
            .is_some_and(|entry| Arc::ptr_eq(entry, &pending.entry))
            || !open
                .owner_witness
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &pending.owner))
        {
            return Err(Error::ReviewMismatch);
        }
        pending.check_current()?;
        start_readonly_audit_once(&pending.audit_started)?;
        let attempt = pending.attempt;
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let mut transport = None;
            let result = (|| -> Result<DeliveryOutcomeV2> {
                pending.check_current()?;
                let history = pending.owner.durable_delivery_history_v2(
                    pending.deadline,
                    || pending.check_current(),
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    &mut transport,
                )?;
                pending.check_current()?;
                // Exact committed snapshot joins the authentic Controlled
                // response to the complete original history, not a DTO claim.
                require_same_committed_snapshot(&pending.controlled, history.snapshot())?;
                let status = status_from_history(&pending.entry, &pending.retained, &history)?;
                if !status.witness_committed {
                    return Err(Error::Uncertain);
                }
                let mut stream = pending.stream.try_clone()?;
                send_response(
                    &mut stream,
                    &pending.peer,
                    pending.deadline,
                    &DurableDeliveryResponseV2::Admission {
                        admission: status.clone(),
                    },
                    || pending.check_current(),
                )?;
                Ok(DeliveryOutcomeV2::Completed(status))
            })();
            // On audit failure the real Controlled reply, original intent and
            // stream remain owned in awaiting_audit. Never downgrade them to a
            // fabricated denial, retry admission, or claim full-history success.
            let _ = send.send(result.map_err(|error| DurableDeliveryFailureV2 {
                attempt,
                stage: DurableDeliveryStageV2::Audit,
                error,
                import_error: None,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                transport,
            }));
        });
        open.history_workers.push(worker);
        open.durable_delivery.job = Some(DeliveryJobV2 {
            receive,
            epoch,
            attempt,
        });
        self.message = "Checking complete authenticated history for the exact already-committed request. No new admission or approval is sent.";
        Ok(())
    }
    pub(super) fn poll_durable_delivery_v2(&mut self, epoch: u64) {
        let Some(open) = self.open.as_mut() else {
            return;
        };
        if let Some(job) = open.durable_delivery.import.as_mut() {
            match job.try_take_result() {
                Err(mpsc::TryRecvError::Empty) => {}
                result => {
                    let job = open.durable_delivery.import.take().expect("checked job");
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    {
                        open.durable_delivery.import_terminal = Some(ImportCorrelationV2 {
                            epoch: job.epoch,
                            attempt: job.attempt,
                            request: job.request,
                        });
                    }
                    match result {
                        Ok(Ok(imported))
                            if job.epoch == epoch
                                && open.durable_delivery.next_attempt == job.attempt =>
                        {
                            match open.check_pairing().and_then(|_| imported.check_current()) {
                                Ok(()) => {
                                    open.durable_delivery.imported = Some(Arc::new(imported));
                                    self.message = "Verified exact original fixed artifact and both original material scopes for prospective v2 admission only.";
                                }
                                Err(error) => {
                                    open.durable_delivery.failure =
                                        Some(DurableDeliveryFailureV2 {
                                            attempt: job.attempt,
                                            stage: DurableDeliveryStageV2::Source,
                                            error,
                                            import_error: None,
                                            #[cfg(feature = "synthetic-born-joined-qualification")]
                                            transport: None,
                                        });
                                }
                            }
                        }
                        Ok(Err(error)) if open.durable_delivery.next_attempt == job.attempt => {
                            open.durable_delivery.failure = Some(DurableDeliveryFailureV2 {
                                attempt: job.attempt,
                                stage: DurableDeliveryStageV2::Import,
                                error: Error::Verification,
                                import_error: Some(error),
                                #[cfg(feature = "synthetic-born-joined-qualification")]
                                transport: None,
                            });
                        }
                        _ => {
                            self.message = "V2 import failed or lost its exact native/peer source.";
                        }
                    }
                }
            }
        }
        if open
            .durable_delivery
            .imported
            .as_ref()
            .is_some_and(|source| {
                source.scopes.iter().any(|scope| {
                    now().is_err() || now().is_ok_and(|now| now >= scope.valid_until_unix_seconds)
                })
            })
        {
            open.durable_delivery.imported = None;
            if self
                .pending
                .as_ref()
                .is_some_and(|p| matches!(&p.operation, Operation::DurableDeliveryV2(_)))
            {
                self.pending = None;
                self.confirmation.zeroize();
            }
        }
        let Some(job) = open.durable_delivery.job.as_ref() else {
            return;
        };
        let result = match job.receive.try_recv() {
            Err(mpsc::TryRecvError::Empty) => return,
            Ok(result) => result,
            Err(_) => Err(DurableDeliveryFailureV2 {
                attempt: job.attempt,
                stage: DurableDeliveryStageV2::Audit,
                error: Error::Uncertain,
                import_error: None,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                transport: None,
            }),
        };
        let job = open.durable_delivery.job.take().expect("checked job");
        // Keep the exact worker error for its actual attempt even when native
        // presentation has become stale. A lost/late success creates no current
        // decision and cannot replace a later attempt's diagnostic.
        let outcome = match result {
            Err(failure) => {
                if failure.attempt == job.attempt
                    && open.durable_delivery.next_attempt == job.attempt
                {
                    open.durable_delivery.failure = Some(failure);
                }
                self.message = "V2 admission did not complete. Exact original intent and any remote commitment remain; audit the same operation before proceeding.";
                return;
            }
            Ok(outcome) => outcome,
        };
        // Preserve the actual response as historical/uncertain evidence even
        // if presentation changed after the send. This creates no status or
        // current authority: the explicit audit rechecks every source again.
        let outcome = match outcome {
            DeliveryOutcomeV2::AwaitingAudit(pending) => {
                if open.durable_delivery.next_attempt == job.attempt {
                    open.durable_delivery.awaiting_audit = Some(pending);
                    open.durable_delivery.imported = None;
                    self.message = "Owner-mTLS committed response received; full history is NOT yet verified. Start the original read-only history listener, then check exact original history. No financial action is enabled.";
                }
                return;
            }
            outcome => outcome,
        };
        if job.epoch != epoch
            || open.check_pairing().is_err()
            || open.durable_delivery.next_attempt != job.attempt
        {
            return;
        }
        match outcome {
            DeliveryOutcomeV2::AwaitingAudit(_) => unreachable!("handled inert response above"),
            DeliveryOutcomeV2::Completed(status) => {
                open.durable_delivery.awaiting_audit = None;
                open.durable_delivery.status = Some(status);
                open.durable_delivery.imported = None;
                self.message = "Exact prospective v2 admission/history retained. Financial actions remain disabled.";
            }
            DeliveryOutcomeV2::Prepared(prepared) => {
                let result = prepared.display().and_then(|display| {
                    ExactNativeReview::stage(
                        &open.authority,
                        prepared.prepared.digest(),
                        display,
                        epoch,
                    )
                });
                match result {
                    Ok(review) => {
                        self.pending = Some(PendingDecision {
                            review,
                            operation: Operation::DurableDeliveryV2(Box::new(prepared)),
                        });
                        self.message = "Review the complete prospective v2 scope. This is not signing or dispatch permission.";
                    }
                    Err(error) => {
                        open.durable_delivery.failure = Some(DurableDeliveryFailureV2 {
                            attempt: prepared.attempt,
                            stage: DurableDeliveryStageV2::NativeReview,
                            error,
                            import_error: None,
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            transport: None,
                        });
                    }
                }
            }
        }
    }
    pub(super) fn durable_delivery_ui_v2(
        &mut self,
        ui: &mut egui::Ui,
        focused: bool,
        epoch: u64,
    ) -> bool {
        if self
            .open
            .as_ref()
            .is_none_or(|open| open.durable_delivery_entry.is_none())
        {
            return false;
        }
        ui.label("V2 original-source prospective admission and exact historical audit only. No Acquire, Activate, Reserve, signing, extraction or dispatch route exists.");
        if self.pending.is_some() {
            return false;
        }
        if self
            .open
            .as_ref()
            .is_some_and(|open| open.durable_delivery.awaiting_audit.is_some())
        {
            ui.label("A checked committed response and exact local intent are retained. Complete authenticated history has NOT been verified.");
            let ready = self.open.as_ref().is_some_and(|open| {
                open.durable_delivery.job.is_none()
                    && open
                        .durable_delivery
                        .awaiting_audit
                        .as_ref()
                        .is_some_and(|p| {
                            !p.audit_started.load(std::sync::atomic::Ordering::Acquire)
                        })
            });
            if ui
                .add_enabled(ready, egui::Button::new("Check exact original history"))
                .clicked_by(egui::PointerButton::Primary)
                && focused
            {
                let _ = self.begin_durable_delivery_history_audit_v2(epoch);
            }
            return true;
        }
        ui.label("Select the original owner-mTLS witness configuration. Credentials are read only; no enrollment or replacement is performed.");
        ui.add(egui::TextEdit::multiline(&mut *self.owner_witness_setup).char_limit(16 * 1024));
        if ui
            .button("Review original owner witness configuration")
            .clicked_by(egui::PointerButton::Primary)
            && focused
        {
            let _ = self.stage_owner_witness_setup(epoch);
        }
        ui.label("For a new prospective import only, accept the exact same enrollment and manifest after pairing. Historical status requires neither a new manifest nor a private import.");
        ui.add(egui::TextEdit::multiline(&mut *self.proposal).char_limit(128 * 1024));
        ui.add(egui::TextEdit::singleline(&mut self.budget));
        if ui
            .button("Review exact enrollment for v2 import")
            .clicked_by(egui::PointerButton::Primary)
            && focused
        {
            let _ = self.stage_enrollment(epoch);
        }
        if ui
            .button("Review exact manifest for v2 import")
            .clicked_by(egui::PointerButton::Primary)
            && focused
        {
            let _ = self.stage_manifest(epoch);
        }
        true
    }
}
pub(super) fn allowed_event(event: &LocalEvent) -> bool {
    match event {
        LocalEvent::Pairing(_)
        | LocalEvent::DurableDeliveryV2 { .. }
        | LocalEvent::DurableProposalReviewV1 { .. }
        | LocalEvent::DurableConstructionRedisclosureV1 { .. } => true,
        LocalEvent::Request { request, .. } => {
            matches!(request, crate::ipc::AppRequest::Status { .. })
        }
        _ => false,
    }
}
pub(super) fn allowed_operation(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Pair(_)
            | Operation::Enroll(_)
            | Operation::Manifest(_)
            | Operation::OwnerWitness(_)
            | Operation::DurableDeliveryV2(_)
            | Operation::DurableDeliveryRedisclosureV2(_)
    )
}
pub(super) fn check_plain_proposal(open: &OpenAccount, proposal: &Proposal) -> Result<()> {
    let source = open
        .durable_delivery_entry
        .as_ref()
        .ok_or(Error::Unavailable)?;
    source.check_current()?;
    crate::native_ui::durable_proposal_v1::plain_profile(proposal)?;
    let scope = &source.record().account_record.terms.scope;
    let account = source.account().account_id()?;
    let own = proposal
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == account)
        .ok_or(Error::ReviewMismatch)?;
    if proposal.manifest().agreement.agreement_id != scope.agreement_id
        || proposal.manifest().agreement.obligation_id != scope.obligation_id
        || own.participant_id != scope.participant_id
        || own.maximum_net_debit.as_zatoshis() > scope.per_operation_limit_zatoshis
        || own.fee_share.as_zatoshis() > scope.maximum_fee_share_zatoshis
        || own.fee_cap.as_zatoshis() > scope.maximum_fee_share_zatoshis
        || proposal.manifest().transaction_fee.as_zatoshis()
            > scope.maximum_transaction_fee_zatoshis
        || now_ms()? >= scope.expires_at_ms
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod continuation_source_contract_tests {
    use super::*;
    #[test]
    fn exact_readonly_audit_is_one_shot_even_after_failure() {
        let started = std::sync::atomic::AtomicBool::new(false);
        assert!(start_readonly_audit_once(&started).is_ok());
        assert!(matches!(
            start_readonly_audit_once(&started),
            Err(Error::Unavailable)
        ));
        assert!(matches!(
            start_readonly_audit_once(&started),
            Err(Error::Unavailable)
        ));
    }
    #[test]
    fn actual_snapshot_join_refuses_changed_history_without_issuing_status() {
        // Inert snapshots exercise the actual comparison predicate only; they
        // cannot construct PendingAudit, a native owner, or a final status.
        let controlled = wholepact_authority::AccountSnapshot {
            transport_fences: None,
            account_use_checkpoint: None,
            witness_id: "synthetic-witness".into(),
            account_id: "synthetic-account".into(),
            network_profile_id: "synthetic-network".into(),
            policy_digest: "01".repeat(32),
            head: wholepact_authority::AuthorityHead {
                sequence: 5,
                digest: "02".repeat(32),
            },
            writer_epoch: 1,
            writer_certificate_digest: "03".repeat(32),
            writer_status: wholepact_authority::WriterStatus::Active,
            outstanding_reservations: 0,
            outstanding_debit_zatoshis: 0,
            settled_debit_zatoshis: 0,
            aggregate_budget_zatoshis: 100,
            reserved_input_value_zatoshis: 0,
            last_witness_time_ms: 7,
            pending_writer_session: None,
            active_writer_session: None,
        };
        assert!(require_same_committed_snapshot(&controlled, &controlled).is_ok());
        let mut changed = controlled.clone();
        changed.head.digest = "04".repeat(32);
        assert!(matches!(
            require_same_committed_snapshot(&controlled, &changed),
            Err(Error::Uncertain)
        ));
        changed = controlled.clone();
        changed.head.sequence += 1;
        assert!(require_same_committed_snapshot(&controlled, &changed).is_err());
        changed = controlled.clone();
        changed.account_id = "another-account".into();
        assert!(require_same_committed_snapshot(&controlled, &changed).is_err());
    }
    #[test]
    fn production_owner_response_is_distinct_from_full_history_status() {
        // Static contract regression, not a substitute for the actual native
        // qualification. The actual response owns the complete retained intent.
        let source = include_str!("durable_delivery_admission_v2.rs");
        let send = source
            .split("pub(super) fn approve_durable_delivery_v2(")
            .nth(1)
            .unwrap()
            .split("pub(super) fn begin_durable_delivery_history_audit_v2")
            .next()
            .unwrap();
        assert!(
            send.find("retain_durable_delivery_admission_intent_v2")
                .unwrap()
                < send.find("durable_delivery_admit_v2").unwrap()
        );
        assert!(send.contains("let controlled = owner.durable_delivery_admit_v2"));
        assert!(send.contains("DeliveryOutcomeV2::AwaitingAudit"));
        assert!(!send.contains("source_history("));
        assert!(!send.contains("DeliveryOutcomeV2::Completed"));
        let audit = source
            .split("pub(super) fn begin_durable_delivery_history_audit_v2")
            .nth(1)
            .unwrap()
            .split("pub(super) fn poll_durable_delivery_v2")
            .next()
            .unwrap();
        assert!(!audit.contains("durable_delivery_admit_v2"));
        assert!(audit.contains("start_readonly_audit_once(&pending.audit_started)"));
        assert!(audit.contains("pending.deadline"));
        assert!(
            audit.find("durable_delivery_history_v2").unwrap()
                < audit.find("send_response(").unwrap()
        );
        assert!(
            audit.contains(
                "require_same_committed_snapshot(&pending.controlled, history.snapshot())"
            )
        );
        assert!(!audit.contains("awaiting_audit.take()"));
    }
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
mod pending_import_completion_tests {
    use super::*;

    // Owned, deliberately non-Clone data exercises the exact production job
    // kernel without constructing native/source/import authority.
    #[derive(Debug)]
    struct Owned(Box<u64>);

    fn inert_job() -> (
        mpsc::Sender<std::result::Result<Owned, Owned>>,
        ImportJobV2<Owned, Owned, &'static str>,
    ) {
        let (send, receive) = mpsc::channel();
        (
            send,
            ImportJobV2 {
                receive,
                pending_result: None,
                epoch: 17,
                attempt: 8,
                request: "exact-request",
            },
        )
    }

    fn request() -> DurableReviewDeliveryRequestV1 {
        DurableReviewDeliveryRequestV1 {
            operation_id: "inert-import".into(),
            enrollment_ref: "01".repeat(32),
            accepted_manifest_ref: "02".repeat(32),
            own_disclosure:
                crate::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1 {
                    operation_id: "inert-disclosure".into(),
                    expected_request_digest: "03".repeat(32),
                },
            current_disclosure: None,
            proposal_binding: "04".repeat(32),
        }
    }

    fn runtime_job(
        request: DurableReviewDeliveryRequestV1,
    ) -> (
        mpsc::Sender<authority_bridge::Result<ImportedDeliveryReviewV2>>,
        DurableDeliveryRuntimeV2,
    ) {
        let (send, receive) = mpsc::channel();
        let mut runtime = DurableDeliveryRuntimeV2::default();
        runtime.next_attempt = 8;
        runtime.import = Some(ImportJobV2 {
            receive,
            pending_result: None,
            epoch: 17,
            attempt: 8,
            request,
        });
        (send, runtime)
    }

    #[test]
    fn queued_nonclone_error_is_exact_owned_and_consumed_once() {
        let (send, mut job) = inert_job();
        let error = Owned(Box::new(71));
        let original = &*error.0 as *const u64;
        send.send(Err(error)).unwrap();
        let observed = job.take_failure_for(17, 8, &"exact-request", 8).unwrap();
        assert_eq!(&*observed.0 as *const u64, original);
        assert_eq!(*observed.0, 71);
        assert!(job.take_failure_for(17, 8, &"exact-request", 8).is_none());
        assert!(matches!(
            job.try_take_result(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn queued_nonclone_success_stays_owned_until_ordinary_take() {
        let (send, mut job) = inert_job();
        let imported = Owned(Box::new(72));
        let original = &*imported.0 as *const u64;
        send.send(Ok(imported)).unwrap();
        for _ in 0..3 {
            assert!(job.take_failure_for(17, 8, &"exact-request", 8).is_none());
            let buffered = job.pending_result.as_ref().unwrap().as_ref().unwrap();
            assert_eq!(&*buffered.0 as *const u64, original);
        }
        assert!(job.take_failure_for(17, 8, &"other-request", 8).is_none());
        let buffered = job.pending_result.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(&*buffered.0 as *const u64, original);
        // The diagnostic has no adoption closure or source authority. Only the
        // ordinary once-only read can release its retained successful value.
        let imported = job.try_take_result().unwrap().unwrap();
        assert_eq!(&*imported.0 as *const u64, original);
        assert_eq!(*imported.0, 72);
        assert!(job.pending_result.is_none());
        assert!(matches!(
            job.try_take_result(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn wrong_epoch_attempt_request_or_current_attempt_leaves_queue_untouched() {
        let (send, mut job) = inert_job();
        let error = Owned(Box::new(73));
        let original = &*error.0 as *const u64;
        send.send(Err(error)).unwrap();
        for (epoch, attempt, request, current) in [
            (18, 8, "exact-request", 8),
            (17, 9, "exact-request", 8),
            (17, 8, "other-request", 8),
            (17, 8, "exact-request", 9),
        ] {
            assert!(
                job.take_failure_for(epoch, attempt, &request, current)
                    .is_none()
            );
            assert!(job.pending_result.is_none());
        }
        let observed = job.try_take_result().unwrap().unwrap_err();
        assert_eq!(&*observed.0 as *const u64, original);
    }

    #[test]
    fn empty_or_disconnected_worker_never_fabricates_failure() {
        let (send, mut job) = inert_job();
        assert!(job.take_failure_for(17, 8, &"exact-request", 8).is_none());
        assert!(matches!(
            job.try_take_result(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(send);
        assert!(job.take_failure_for(17, 8, &"exact-request", 8).is_none());
        assert!(matches!(
            job.try_take_result(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn predecessor_is_pending_only_before_exact_job_has_been_seen() {
        let request = request();
        let mut runtime = DurableDeliveryRuntimeV2::default();
        runtime.next_attempt = 7;
        assert_eq!(
            runtime
                .qualification_import_attempt_v2(17, &request)
                .unwrap(),
            (7, 8, false)
        );
        let mut seen = false;
        assert!(
            !runtime
                .qualification_import_current_v2(17, 7, 8, &request, &mut seen)
                .unwrap()
        );
        assert!(!seen);
        let (_send, mut runtime) = runtime_job(request.clone());
        assert_eq!(
            runtime
                .qualification_import_attempt_v2(17, &request)
                .unwrap(),
            (7, 8, true)
        );
        assert!(
            !runtime
                .qualification_import_current_v2(17, 7, 8, &request, &mut seen)
                .unwrap()
        );
        assert!(seen);
        runtime.clear();
        assert!(
            runtime
                .qualification_import_current_v2(17, 7, 8, &request, &mut seen)
                .is_err()
        );
        // Even an inert attempt rollback cannot turn a seen-then-vanished job
        // back into the initial IPC-not-yet-started state.
        runtime.next_attempt = 7;
        assert!(
            runtime
                .qualification_import_current_v2(17, 7, 8, &request, &mut seen)
                .is_err()
        );
    }

    #[test]
    fn runtime_correlation_refuses_replaced_job_before_diagnostic_read() {
        let request = request();
        let (send, mut runtime) = runtime_job(request.clone());
        send.send(Err(BridgeError::Ipc)).ok().unwrap();
        assert_eq!(
            runtime.qualification_import_failure_attempt_v2(17, &request),
            Some(8)
        );
        assert_eq!(
            DurableDeliveryRuntimeV2::default()
                .qualification_import_failure_attempt_v2(17, &request),
            None
        );
        let mut wrong_request = request.clone();
        wrong_request.operation_id = "other-import".into();
        for (epoch, expected, request) in [
            (18, 8, &request),
            (17, 9, &request),
            (17, 8, &wrong_request),
        ] {
            assert!(
                runtime
                    .qualification_take_import_failure_v2(epoch, expected, request)
                    .is_none()
            );
            let mut seen = true;
            assert!(
                runtime
                    .qualification_import_current_v2(
                        epoch,
                        expected - 1,
                        expected,
                        request,
                        &mut seen
                    )
                    .is_err()
            );
        }
        assert!(
            runtime
                .qualification_import_attempt_v2(18, &request)
                .is_err()
        );
        assert_eq!(
            runtime.qualification_import_failure_attempt_v2(18, &request),
            None
        );
        assert_eq!(
            runtime.qualification_import_failure_attempt_v2(17, &wrong_request),
            None
        );
        assert!(
            runtime
                .qualification_import_attempt_v2(17, &wrong_request)
                .is_err()
        );
        let failure = runtime
            .qualification_take_import_failure_v2(17, 8, &request)
            .unwrap();
        assert_eq!(failure.attempt(), 8);
        assert!(failure.stage() == DurableDeliveryStageV2::Import);
        assert!(matches!(
            failure.into_import_error(),
            Some(BridgeError::Ipc)
        ));
        assert!(runtime.import.is_none());
        assert!(runtime.imported.is_none());
        assert!(
            runtime
                .qualification_take_import_failure_v2(17, 8, &request)
                .is_none()
        );
    }

    #[test]
    fn ordinary_terminal_failure_remains_exact_and_correlation_is_invalidated() {
        let request = request();
        let mut runtime = DurableDeliveryRuntimeV2::default();
        runtime.next_attempt = 8;
        runtime.import_terminal = Some(ImportCorrelationV2 {
            epoch: 17,
            attempt: 8,
            request: request.clone(),
        });
        assert_eq!(
            runtime.qualification_import_failure_attempt_v2(17, &request),
            Some(8)
        );
        runtime.failure = Some(DurableDeliveryFailureV2 {
            attempt: 8,
            stage: DurableDeliveryStageV2::Source,
            error: Error::Locked,
            import_error: None,
            transport: None,
        });
        assert!(
            runtime
                .qualification_take_import_failure_v2(18, 8, &request)
                .is_none()
        );
        assert!(runtime.failure.is_some());
        let failure = runtime
            .qualification_take_import_failure_v2(17, 8, &request)
            .unwrap();
        assert!(matches!(failure.into_error(), Error::Locked));
        assert!(
            runtime
                .qualification_take_import_failure_v2(17, 8, &request)
                .is_none()
        );
        runtime.clear();
        assert!(runtime.import_terminal.is_none());
        runtime.import_terminal = Some(ImportCorrelationV2 {
            epoch: 17,
            attempt: 8,
            request,
        });
        assert_eq!(runtime.attempt().unwrap(), 9);
        assert!(runtime.import_terminal.is_none());
    }

    #[test]
    fn ordinary_import_adoption_keeps_original_current_and_epoch_attempt_gates() {
        // Static production integration evidence only. These inert job tests do
        // not construct a native source or claim native expiry/timing coverage.
        let source = include_str!("durable_delivery_admission_v2.rs");
        let poll = source
            .split("pub(super) fn poll_durable_delivery_v2(&mut self, epoch: u64)")
            .nth(1)
            .unwrap()
            .split("pub(super) fn durable_delivery_ui_v2")
            .next()
            .unwrap();
        assert!(poll.contains("match job.try_take_result()"));
        assert!(poll.contains("if job.epoch == epoch"));
        assert!(poll.contains("&& open.durable_delivery.next_attempt == job.attempt"));
        assert!(poll.contains("open.check_pairing().and_then(|_| imported.check_current())"));
        assert!(
            poll.contains("Ok(Err(error)) if open.durable_delivery.next_attempt == job.attempt")
        );
        let drain = source
            .split("pub(super) fn qualification_take_import_failure_v2(")
            .nth(1)
            .unwrap()
            .split("fn send_response(")
            .next()
            .unwrap();
        assert!(!drain.contains("check_current("));
        assert!(!drain.contains("check_pairing("));
        assert!(!drain.contains("self.imported ="));
        assert!(!drain.contains("thread::spawn"));
        assert!(!drain.contains("Instant::now"));
        assert!(!drain.contains("receive_delivery("));
    }
}

#[cfg(test)]
mod receiver_terminal_tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    struct BorrowedResource(Rc<RefCell<Vec<&'static str>>>);
    impl Drop for BorrowedResource {
        fn drop(&mut self) {
            self.0.borrow_mut().push("resource-drop");
        }
    }
    struct NonCloneError {
        value: Box<u64>,
        events: Rc<RefCell<Vec<&'static str>>>,
    }
    impl Drop for NonCloneError {
        fn drop(&mut self) {
            self.events.borrow_mut().push("error-drop");
        }
    }

    #[test]
    fn borrowed_body_observes_same_nonclone_error_before_resource_drop() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let original = NonCloneError {
            value: Box::new(73),
            events: events.clone(),
        };
        let identity = &*original.value as *const u64;
        let returned = {
            let mut resource = BorrowedResource(events.clone());
            let result = borrowed_receive_terminal_v2(
                &mut resource,
                |resource| {
                    resource.0.borrow_mut().push("body");
                    Err::<(), _>(original)
                },
                |error| {
                    assert_eq!(&*error.value as *const u64, identity);
                    events.borrow_mut().push("terminal");
                    assert_eq!(&*events.borrow(), &["body", "terminal"]);
                },
            );
            assert_eq!(&*events.borrow(), &["body", "terminal"]);
            result
        };
        assert_eq!(
            &*returned.as_ref().err().unwrap().value as *const u64,
            identity
        );
        assert_eq!(&*events.borrow(), &["body", "terminal", "resource-drop"]);
        drop(returned);
        assert_eq!(
            &*events.borrow(),
            &["body", "terminal", "resource-drop", "error-drop"]
        );
    }

    #[test]
    fn borrowed_success_never_observes_and_retains_original_allocation() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let value = Box::new(74_u64);
        let identity = &*value as *const u64;
        let returned = {
            let mut resource = BorrowedResource(events.clone());
            borrowed_receive_terminal_v2(
                &mut resource,
                |resource| {
                    resource.0.borrow_mut().push("body");
                    Ok::<_, NonCloneError>(value)
                },
                |_| panic!("success must not invoke terminal observer"),
            )
        };
        assert_eq!(&**returned.as_ref().ok().unwrap() as *const u64, identity);
        assert_eq!(&*events.borrow(), &["body", "resource-drop"]);
    }

    #[test]
    fn observation_macros_preserve_no_collector_and_feature_disabled_parity() {
        // The same macro expansion is compiled with and without synthetic
        // diagnostics. Neither path evaluates an expression more than once.
        let calls = std::cell::Cell::new(0);
        let value = Box::new(75_u64);
        let identity = &*value as *const u64;
        let result = receive_result_v2!(None, DeliveryReceiveFrame, unknown, {
            calls.set(calls.get() + 1);
            Err::<(), _>(value)
        });
        assert_eq!(calls.get(), 1);
        assert_eq!(&**result.as_ref().unwrap_err() as *const u64, identity);
        assert!(receive_denied_v2!(None, DeliveryReceiveDeadline, {
            calls.set(calls.get() + 1);
            true || {
                calls.set(100);
                false
            }
        }));
        assert_eq!(calls.get(), 2);
    }
}
