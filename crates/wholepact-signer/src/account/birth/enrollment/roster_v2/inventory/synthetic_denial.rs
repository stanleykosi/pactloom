//! Denial-only synthetic diagnostics. No private value or error payload is
//! formatted; original callers retain every result, owner and fixed clock.
use super::{Error, Result};

#[derive(Clone, Copy)]
pub(super) enum Boundary {
    InventorySourceOwner,
    InventorySourceNative,
    InventorySourceDeadline,
    InventorySourcePeer,
    InventorySourceOwnerBinding,
    InventorySourcePeerBinding,
    InventorySourceRetiredGrant,
    InventorySourceProcess,
    InventorySourceRetained,
    InventorySourceAdmission,
    InventorySourceHistory,
    InventorySourceWitness,
    InventoryWindowWallRollback,
    InventoryWindowWallExpired,
    InventoryWindowMonotonicExpired,
    InventoryNativeBinding,
    InventorySourceRequest,
    InventoryPeerConnection,
    InventoryObservedMissing,
    InventoryObservedLifetimeInvalid,
    InventoryObservedWallRollback,
    InventoryObservedSessionExpired,
    InventoryObservedAgeExpired,
}
impl Boundary {
    fn label(self) -> &'static str {
        match self {
            Self::InventorySourceOwner => "InventorySourceOwner",
            Self::InventorySourceNative => "InventorySourceNative",
            Self::InventorySourceDeadline => "InventorySourceDeadline",
            Self::InventorySourcePeer => "InventorySourcePeer",
            Self::InventorySourceOwnerBinding => "InventorySourceOwnerBinding",
            Self::InventorySourcePeerBinding => "InventorySourcePeerBinding",
            Self::InventorySourceRetiredGrant => "InventorySourceRetiredGrant",
            Self::InventorySourceProcess => "InventorySourceProcess",
            Self::InventorySourceRetained => "InventorySourceRetained",
            Self::InventorySourceAdmission => "InventorySourceAdmission",
            Self::InventorySourceHistory => "InventorySourceHistory",
            Self::InventorySourceWitness => "InventorySourceWitness",
            Self::InventoryWindowWallRollback => "InventoryWindowWallRollback",
            Self::InventoryWindowWallExpired => "InventoryWindowWallExpired",
            Self::InventoryWindowMonotonicExpired => "InventoryWindowMonotonicExpired",
            Self::InventoryNativeBinding => "InventoryNativeBinding",
            Self::InventorySourceRequest => "InventorySourceRequest",
            Self::InventoryPeerConnection => "InventoryPeerConnection",
            Self::InventoryObservedMissing => "InventoryObservedMissing",
            Self::InventoryObservedLifetimeInvalid => "InventoryObservedLifetimeInvalid",
            Self::InventoryObservedWallRollback => "InventoryObservedWallRollback",
            Self::InventoryObservedSessionExpired => "InventoryObservedSessionExpired",
            Self::InventoryObservedAgeExpired => "InventoryObservedAgeExpired",
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Authentication,
    ReviewMismatch,
}
pub(super) fn emit(boundary: Boundary, kind: Kind) {
    let outcome = match kind {
        Kind::Authentication => "SignerAuthentication",
        Kind::ReviewMismatch => "SignerReviewMismatch",
    };
    eprintln!("\n[JOINED_DIAGNOSTIC {} {}]", boundary.label(), outcome);
}
pub(super) fn result<T>(boundary: Boundary, result: &Result<T>) {
    let Err(error) = result else {
        return;
    };
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
    eprintln!("\n[JOINED_DIAGNOSTIC {} {}]", boundary.label(), outcome);
}
