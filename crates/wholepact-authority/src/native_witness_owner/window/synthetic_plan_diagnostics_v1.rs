//! Closed synthetic-only plan-controller diagnostics. No payload or error text.
//! This module issues no owner, decision or receipt and never changes a result.
use crate::{AuthorityError, Result};

#[derive(Clone, Copy)]
pub(super) enum Boundary {
    WitnessPlanInput,
    WitnessPlanSelect,
    WitnessPlanInputUtf8,
    WitnessPlanPublicRefusal,
    WitnessPlanQualifiedEntry,
    WitnessPlanLaunch,
    WitnessPlanDrain,
    WitnessPlanPending,
    WitnessPlanApprove,
    WitnessPlanReceipt,
    WitnessPlanReceiptDigest,
    WitnessPlanExpectedParse,
    WitnessPlanDigestMatch,
    WitnessPlanWorkerPrepare,
    WitnessPlanWorkerApprove,
}
impl Boundary {
    fn label(self) -> &'static str {
        match self {
            Self::WitnessPlanInput => "WitnessPlanInput",
            Self::WitnessPlanSelect => "WitnessPlanSelect",
            Self::WitnessPlanInputUtf8 => "WitnessPlanInputUtf8",
            Self::WitnessPlanPublicRefusal => "WitnessPlanPublicRefusal",
            Self::WitnessPlanQualifiedEntry => "WitnessPlanQualifiedEntry",
            Self::WitnessPlanLaunch => "WitnessPlanLaunch",
            Self::WitnessPlanDrain => "WitnessPlanDrain",
            Self::WitnessPlanPending => "WitnessPlanPending",
            Self::WitnessPlanApprove => "WitnessPlanApprove",
            Self::WitnessPlanReceipt => "WitnessPlanReceipt",
            Self::WitnessPlanReceiptDigest => "WitnessPlanReceiptDigest",
            Self::WitnessPlanExpectedParse => "WitnessPlanExpectedParse",
            Self::WitnessPlanDigestMatch => "WitnessPlanDigestMatch",
            Self::WitnessPlanWorkerPrepare => "WitnessPlanWorkerPrepare",
            Self::WitnessPlanWorkerApprove => "WitnessPlanWorkerApprove",
        }
    }
}

pub(super) fn begin(boundary: Boundary) {
    eprintln!("\n[JOINED_DIAGNOSTIC {} Begin]", boundary.label());
}
pub(super) fn result<T>(boundary: Boundary, result: &Result<T>) {
    let outcome = match result {
        Ok(_) => "Complete",
        Err(error) => error_kind(error),
    };
    eprintln!("\n[JOINED_DIAGNOSTIC {} {outcome}]", boundary.label());
}
pub(super) fn run<T>(boundary: Boundary, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    begin(boundary);
    let value = operation();
    result(boundary, &value);
    value
}
pub(super) fn input_size(bytes: &[u8]) {
    // Only a closed category of the already-read signed envelope. No
    // length, bytes, identity or timestamp is disclosed and no gate is changed.
    let outcome = if bytes.is_empty() {
        "AuthorityInputEmpty"
    } else if bytes.len() > crate::MAX_FRAME_BYTES {
        "AuthorityInputOverBound"
    } else {
        "AuthorityInputWithinBound"
    };
    eprintln!("\n[JOINED_DIAGNOSTIC {} {outcome}]", Boundary::WitnessPlanInput.label());
}
fn error_kind(error: &AuthorityError) -> &'static str {
    match error {
        AuthorityError::InvalidBinding => "AuthorityInvalidBinding",
        AuthorityError::Permission => "AuthorityPermission",
        AuthorityError::StaleHead => "AuthorityStaleHead",
        AuthorityError::Conflict => "AuthorityConflict",
        AuthorityError::Inactive => "AuthorityInactive",
        AuthorityError::RecoveryRequired => "AuthorityRecoveryRequired",
        AuthorityError::Expired => "AuthorityExpired",
        AuthorityError::PolicyDenied => "AuthorityPolicyDenied",
        AuthorityError::BudgetExceeded => "AuthorityBudgetExceeded",
        AuthorityError::InputReserved => "AuthorityInputReserved",
        AuthorityError::ObligationReserved => "AuthorityObligationReserved",
        AuthorityError::Limit => "AuthorityLimit",
        AuthorityError::Storage => "AuthorityStorage",
        AuthorityError::CorruptHistory => "AuthorityCorruptHistory",
        AuthorityError::PermanentStopUnavailable => "AuthorityPermanentStopUnavailable",
        AuthorityError::OfflineHistoryUnsupported => "AuthorityOfflineHistoryUnsupported",
        AuthorityError::ConstructionHistoryUnsupported => "AuthorityConstructionHistoryUnsupported",
        AuthorityError::UnsupportedVersion => "AuthorityUnsupportedVersion",
        AuthorityError::Authentication => "AuthorityAuthentication",
        AuthorityError::Uncertain => "AuthorityUncertain",
        AuthorityError::ResolutionUnavailable => "AuthorityResolutionUnavailable",
        AuthorityError::SessionRequired => "AuthoritySessionRequired",
        AuthorityError::SessionPending => "AuthoritySessionPending",
    }
}
