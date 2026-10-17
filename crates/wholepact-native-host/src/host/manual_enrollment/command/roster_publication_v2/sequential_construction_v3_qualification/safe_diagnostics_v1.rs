//! Finite public diagnostics for a private-transcript synthetic PTY test.
//! Only exact enum labels cross the transcript boundary. No error Display/Debug,
//! path, review text, account identifier, receipt, credential or artifact is copied.
use crate::{Error, Result};

macro_rules! labels {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy)]
        pub(super) enum $name { $($variant),+ }
        impl $name {
            fn label(self) -> &'static str { match self { $(Self::$variant => stringify!($variant)),+ } }
            fn parse(value: &str) -> Option<Self> { match value { $(stringify!($variant) => Some(Self::$variant)),+, _ => None } }
        }
    };
}
labels! { Boundary {
    Bootstrap, Session, PublicRefusal, PaymentReceiver, AgreementInput, AgreementNative, WitnessSetup, WitnessOrigin, SignerStart, BirthExport, BirthRead, BirthEnroll, BirthHistory, BirthAcknowledge, BirthDistinct, SinglePrepare, SingleOpen, SinglePair, SingleSubmit, SingleExport, SingleWitness, SinglePublicationPrepare, SingleHistory, SinglePublicationOpen, SinglePublicationPair, SingleFinish, SingleClose, RosterPrepare, RosterOpen, RosterPair, RosterSubmit, RosterExport, RosterWitness, RosterPublicationPrepare, RosterHistory, RosterPublicationOpen, RosterPublicationPair, RosterFinish, RosterClose, MetadataCheck, FinancialRefusal, EndInvariant, SignerCreate, SignerExportBirth, SignerAcknowledge, SignerOpenSingleIntent, SignerPollSingleIntent, SignerExportSingle, SignerOpenSinglePublication, SignerPollSinglePublication, SignerCloseSinglePublication, SignerOpenRosterIntent, SignerPollRosterIntent, SignerExportRoster, SignerOpenRosterPublication, SignerPollRosterPublication, SignerCloseRosterPublication, SignerOpenContinuationIntent, SignerPollContinuationIntent, SignerOpenContinuedPublication, SignerPollContinuedPublication, SignerCloseContinuedPublication, SignerExportOriginalFullPlan, SignerOpenCommonContextRead, SignerPollCommonContextRead, SignerParkCommonContextCompletion, SignerPeerMetadata, SignerNativeEntry, SignerEndpoint, SignerProvider, SignerDeadline, SignerSingleController, ObservedInputs, ObservedRetainedPredecessor, ObservedAssemble, ObservedCandidateReview, ObservedPlanExport, ObservedPlanSign, ObservedPlanRead, ObservedPlanAuthenticate, ObservedPlanWitness, ObservedContinuation, ObservedOwnerSplit, ObservedReadPrepare, ObservedReadHistory, ObservedReadOpen, ObservedReadPair, ObservedReadFinish, ObservedReadPark, ObservedBarrier, ObservedProviderDrain, ConstructedPredecessor, ConstructedDisclosure, ConstructedWitnessOriginal, ConstructedWitnessGrant, ConstructedWitnessScope, ConstructedPendingFile, ConstructedPendingReview, ConstructedSignerOpen, ConstructedConsume, ConstructedSignerPark, ConstructedServerSeal, ConstructedCheckpoint, ConstructedSavedOriginal, ConstructedInvariant, ConstructedProviderDrain, SignerOpenOriginalCompletion, SignerPollOriginalCompletion, ProvedConstructionDrain, ProvedOriginalJob, ProvedOriginalCorrelation, ProvedHostPublic, ProvedWitnessKey, ProvedNamedOpen, ProvedNamedPair, ProvedNamedStatus, ProvedNamedRecords, ProvedNamedProfile, ProvedNativePins, ProvedCarrierPrepare, ProvedCarrierExport, ProvedCarrierRecover, ProvedCarrierRetained, ProvedCarrierInvariant, SignerOpenOriginalNamed, SignerPollOriginalNamed, SignerRetainOriginalProfile, SignerNamedEnrollmentExport, SignerNamedInstalledMetadata, SignerNamedVerifierArm, SignerNamedVerifierStart, SignerNamedVerifierPoll, SignerNamedAssertionExport, SignerNamedOriginalImport, SignerNamedOriginalSubmit, SignerNamedOriginalSign, SignerNamedHostServing, FullPaymentPredecessor, FullEnrollmentExport, FullEnrollmentInstall, FullArtifactsInstall, FullInstalledMetadata, FullVerifierRequest, FullAssertion, FullOriginalImport, FullAdmission, FullSignatureReturn, FullHistory, FullReturnIntake, FullMerge, FullCurrentDispatch, FullRecipientReceipt, SingleAccountUnlock, SingleRetainedRead, SingleAcquireState, SingleAttemptedSource, SingleAttemptsRead, SingleRetainedReopen, SinglePreacquire, SingleReference, SingleAccountId, SingleAudit, SingleEndpointCreate, SingleDirectoryOpen, SingleIpcBind, SingleEndpointPublish
} }
labels! { Outcome {
    Begin, Complete, HostPlatform, HostTerminal, HostPermission, HostLocked, HostInvalid, HostAuthentication, HostStorage, HostQuarantined, HostUnsupported, HostReceipt, HostRecoverySemantic, HostRecoveryBackupUnsupported, HostRecoveryFinancialUnsupported, HostCompleteOriginRecoveryUnavailable, HostHistoricalExportIncomplete, HostGenerationArchiveIncomplete, SignerUnavailable, SignerPeerLifetimeUnavailable, SignerIo, SignerAuthentication, SignerInvalidData, SignerCrypto, SignerLocked, SignerBackupRequired, SignerRecoveryRequired, SignerAlreadyOpen, SignerReviewMismatch, SignerVerification, SignerUncertain, SignerConsentJournal, SignerStore, WorkerFailure
} }

pub(super) fn emit(boundary: Boundary, outcome: Outcome) {
    eprintln!(
        "\n[JOINED_DIAGNOSTIC {} {}]",
        boundary.label(),
        outcome.label()
    );
}
pub(super) fn host<T>(boundary: Boundary, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    emit(boundary, Outcome::Begin);
    let result = operation();
    emit(
        boundary,
        result
            .as_ref()
            .map_or_else(host_error, |_| Outcome::Complete),
    );
    result
}
fn host_error(error: &Error) -> Outcome {
    match error {
        Error::Platform => Outcome::HostPlatform,
        Error::Terminal => Outcome::HostTerminal,
        Error::Permission => Outcome::HostPermission,
        Error::Locked => Outcome::HostLocked,
        Error::Invalid => Outcome::HostInvalid,
        Error::Authentication => Outcome::HostAuthentication,
        Error::Storage => Outcome::HostStorage,
        Error::Quarantined => Outcome::HostQuarantined,
        Error::Unsupported => Outcome::HostUnsupported,
        Error::Receipt(_) => Outcome::HostReceipt,
        Error::RecoverySemantic(_) => Outcome::HostRecoverySemantic,
        Error::RecoveryBackupUnsupported => Outcome::HostRecoveryBackupUnsupported,
        Error::RecoveryFinancialUnsupported => Outcome::HostRecoveryFinancialUnsupported,
        Error::CompleteOriginRecoveryUnavailable => Outcome::HostCompleteOriginRecoveryUnavailable,
        Error::HistoricalExportIncomplete => Outcome::HostHistoricalExportIncomplete,
        Error::GenerationArchiveIncomplete => Outcome::HostGenerationArchiveIncomplete,
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn signer_error(error: &wholepact_signer::Error) -> Outcome {
    use wholepact_signer::Error as E;
    match error {
        E::Unavailable => Outcome::SignerUnavailable,
        E::PeerLifetimeUnavailable => Outcome::SignerPeerLifetimeUnavailable,
        E::Io(_) => Outcome::SignerIo,
        E::Authentication => Outcome::SignerAuthentication,
        E::InvalidData => Outcome::SignerInvalidData,
        E::Crypto => Outcome::SignerCrypto,
        E::Locked => Outcome::SignerLocked,
        E::BackupRequired => Outcome::SignerBackupRequired,
        E::RecoveryRequired => Outcome::SignerRecoveryRequired,
        E::AlreadyOpen => Outcome::SignerAlreadyOpen,
        E::ReviewMismatch => Outcome::SignerReviewMismatch,
        E::Verification => Outcome::SignerVerification,
        E::Uncertain => Outcome::SignerUncertain,
        E::ConsentJournal(_) => Outcome::SignerConsentJournal,
        E::Store(_) => Outcome::SignerStore,
    }
}
/// Called only with locally generated labels. Parse again before disclosing:
/// even a spoofed marker cannot cause arbitrary transcript content to escape.
pub(super) fn summary(transcript: &[u8]) -> String {
    let mut output = std::collections::VecDeque::new();
    for line in transcript.split(|byte| *byte == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        let line = line.trim_end_matches('\r');
        if let Some(inner) = line
            .strip_prefix("[JOINED_IO ")
            .and_then(|s| s.strip_suffix(']'))
        {
            let mut fields = inner.split(' ');
            let (Some(boundary), Some(kind), Some(errno), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let Some(boundary) = Boundary::parse(boundary) else {
                continue;
            };
            if !matches!(
                kind,
                "NotFound"
                    | "PermissionDenied"
                    | "AlreadyExists"
                    | "InvalidInput"
                    | "InvalidData"
                    | "AddrInUse"
                    | "AddrNotAvailable"
                    | "WouldBlock"
                    | "TimedOut"
                    | "Interrupted"
                    | "Unsupported"
                    | "Other"
            ) || (errno != "none" && !errno.parse::<i32>().is_ok_and(|n| n.to_string() == errno))
            {
                continue;
            }
            if output.len() == 64 {
                output.pop_front();
            }
            output.push_back(format!("{}:IoKind={kind}:errno={errno}", boundary.label()));
            continue;
        }
        let Some(inner) = line
            .strip_prefix("[JOINED_DIAGNOSTIC ")
            .and_then(|s| s.strip_suffix(']'))
        else {
            continue;
        };
        let Some((boundary, outcome)) = inner.split_once(' ') else {
            continue;
        };
        let (Some(boundary), Some(outcome)) = (Boundary::parse(boundary), Outcome::parse(outcome))
        else {
            continue;
        };
        if output.len() == 64 {
            output.pop_front();
        }
        output.push_back(format!("{}:{}", boundary.label(), outcome.label()));
    }
    if output.is_empty() {
        "none".into()
    } else {
        output.into_iter().collect::<Vec<_>>().join(",")
    }
}

#[test]
fn private_transcript_diagnostic_projection_is_closed_and_bounded() {
    let transcript = b"private-path-and-key-material\n[JOINED_DIAGNOSTIC AgreementNative HostInvalid]\r\n[JOINED_DIAGNOSTIC AgreementNative HostInvalid extra-private-data]\n[JOINED_DIAGNOSTIC unknown HostInvalid]\n";
    assert_eq!(summary(transcript), "AgreementNative:HostInvalid");
    assert_eq!(
        summary(b"\xffprivate\n[JOINED_DIAGNOSTIC Bootstrap Begin] secret"),
        "none"
    );
    let long = "[JOINED_DIAGNOSTIC Bootstrap Begin]\n".repeat(100);
    assert_eq!(summary(long.as_bytes()).split(',').count(), 64);
}

#[test]
fn io_diagnostics_accept_only_closed_kind_and_canonical_errno() {
    assert_eq!(summary(b"[JOINED_IO SingleIpcBind InvalidInput none]\n[JOINED_IO SingleDirectoryOpen PermissionDenied 1]"), "SingleIpcBind:IoKind=InvalidInput:errno=none,SingleDirectoryOpen:IoKind=PermissionDenied:errno=1");
    for line in [
        "[JOINED_IO private-path InvalidInput none]",
        "[JOINED_IO SingleIpcBind /private/path 1]",
        "[JOINED_IO SingleIpcBind InvalidInput 1/private]",
        "[JOINED_IO SingleIpcBind InvalidInput +1]",
        "[JOINED_IO SingleIpcBind InvalidInput 2147483648]",
        "[JOINED_IO SingleIpcBind InvalidInput 1 extra]",
    ] {
        assert_eq!(summary(line.as_bytes()), "none");
    }
}
