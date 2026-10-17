//! Denial-only synthetic projection. Results are evaluated by the caller once,
//! borrowed for a closed discriminant, and returned unchanged. No private data.
use crate::Result;
#[cfg(feature = "synthetic-born-joined-qualification")]
use crate::Error;

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    RosterBirthHistoryGate,
    RosterBirthExtension,
    RosterBirthOriginal,
    RosterBirthLinkage,
    ContinuationRetainedSource,
    ContinuationAttemptedSource,
    ContinuationWriterSource,
    ContinuationHistoryReplay,
    ContinuationPairing,
    ContinuationPreparedReview,
    ContinuationSource,
    ContinuationBirthLink,
    ContinuationPreconstruction,
    ContinuationHistoryGate,
    ContinuationHistoryArchive,
    ContinuationRetainedReceipt,
    ContinuationPreviousLoad,
    ContinuationProposalCapacity,
    ContinuationProposalIndex,
    ContinuationAttemptSequence,
    ContinuationProposalValidation,
}
impl Phase {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn label(self) -> &'static str {
        match self {
            Self::RosterBirthHistoryGate => "RosterBirthHistoryGate",
            Self::RosterBirthExtension => "RosterBirthExtension",
            Self::RosterBirthOriginal => "RosterBirthOriginal",
            Self::RosterBirthLinkage => "RosterBirthLinkage",
            Self::ContinuationRetainedSource => "ContinuationRetainedSource",
            Self::ContinuationAttemptedSource => "ContinuationAttemptedSource",
            Self::ContinuationWriterSource => "ContinuationWriterSource",
            Self::ContinuationHistoryReplay => "ContinuationHistoryReplay",
            Self::ContinuationPairing => "ContinuationPairing",
            Self::ContinuationPreparedReview => "ContinuationPreparedReview",
            Self::ContinuationSource => "ContinuationSource",
            Self::ContinuationBirthLink => "ContinuationBirthLink",
            Self::ContinuationPreconstruction => "ContinuationPreconstruction",
            Self::ContinuationHistoryGate => "ContinuationHistoryGate",
            Self::ContinuationHistoryArchive => "ContinuationHistoryArchive",
            Self::ContinuationRetainedReceipt => "ContinuationRetainedReceipt",
            Self::ContinuationPreviousLoad => "ContinuationPreviousLoad",
            Self::ContinuationProposalCapacity => "ContinuationProposalCapacity",
            Self::ContinuationProposalIndex => "ContinuationProposalIndex",
            Self::ContinuationAttemptSequence => "ContinuationAttemptSequence",
            Self::ContinuationProposalValidation => "ContinuationProposalValidation",
        }
    }
}

pub(crate) fn signer<T>(phase: Phase, result: Result<T>) -> Result<T> {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if let Err(error) = &result {
        let outcome = match error {
            Error::Unavailable => "SignerUnavailable",
            Error::PeerLifetimeUnavailable => "SignerPeerLifetimeUnavailable",
            Error::Io(_) => "SignerIo",
            Error::Authentication => "SignerAuthentication",
            Error::InvalidData => "SignerInvalidData",
            Error::Crypto => "SignerCrypto",
            Error::Locked => "SignerLocked",
            Error::BackupRequired => "SignerBackupRequired",
            Error::RecoveryRequired => "SignerRecoveryRequired",
            Error::AlreadyOpen => "SignerAlreadyOpen",
            Error::ReviewMismatch => "SignerReviewMismatch",
            Error::Verification => "SignerVerification",
            Error::Uncertain => "SignerUncertain",
            Error::ConsentJournal(_) => "SignerConsentJournal",
            Error::Store(_) => "SignerStore",
        };
        eprintln!("\n[JOINED_DIAGNOSTIC {} {}]", phase.label(), outcome);
    }
    #[cfg(not(feature = "synthetic-born-joined-qualification"))]
    let _ = phase;
    result
}

pub(crate) fn authority<T>(
    phase: Phase,
    result: wholepact_authority::Result<T>,
) -> wholepact_authority::Result<T> {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if let Err(error) = &result {
        use wholepact_authority::AuthorityError as E;
        let outcome = match error {
            E::InvalidBinding => "AuthorityInvalidBinding",
            E::Permission => "AuthorityPermission",
            E::StaleHead => "AuthorityStaleHead",
            E::Conflict => "AuthorityConflict",
            E::Inactive => "AuthorityInactive",
            E::RecoveryRequired => "AuthorityRecoveryRequired",
            E::Expired => "AuthorityExpired",
            E::PolicyDenied => "AuthorityPolicyDenied",
            E::BudgetExceeded => "AuthorityBudgetExceeded",
            E::InputReserved => "AuthorityInputReserved",
            E::ObligationReserved => "AuthorityObligationReserved",
            E::Limit => "AuthorityLimit",
            E::Storage => "AuthorityStorage",
            E::CorruptHistory => "AuthorityCorruptHistory",
            E::PermanentStopUnavailable => "AuthorityPermanentStopUnavailable",
            E::OfflineHistoryUnsupported => "AuthorityOfflineHistoryUnsupported",
            E::ConstructionHistoryUnsupported => "AuthorityConstructionHistoryUnsupported",
            E::UnsupportedVersion => "AuthorityUnsupportedVersion",
            E::Authentication => "AuthorityAuthentication",
            E::Uncertain => "AuthorityUncertain",
            E::ResolutionUnavailable => "AuthorityResolutionUnavailable",
            E::SessionRequired => "AuthoritySessionRequired",
            E::SessionPending => "AuthoritySessionPending",
        };
        eprintln!("\n[JOINED_DIAGNOSTIC {} {}]", phase.label(), outcome);
    }
    #[cfg(not(feature = "synthetic-born-joined-qualification"))]
    let _ = phase;
    result
}
