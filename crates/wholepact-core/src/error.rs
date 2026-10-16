use crate::amount::AmountError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable, machine-readable categories. Error text is explanatory, never a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidAmount,
    InvalidTerms,
    UnknownParticipant,
    DuplicateIdentifier,
    ConservationFailure,
    DebitCapExceeded,
    FeeCapExceeded,
    MissingEvidence,
    UnverifiableMatch,
    PrivacyIncompatible,
    UnsupportedCapability,
    UnsupportedVersion,
    ResourceLimit,
    StaleChain,
    InvalidTransition,
    RevisionConflict,
    OutstandingExposure,
    RecoveryRequired,
    UserRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreError {
    pub code: ErrorCode,
    pub message: String,
}

impl CoreError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for CoreError {}

impl From<AmountError> for CoreError {
    fn from(error: AmountError) -> Self {
        Self::new(ErrorCode::InvalidAmount, error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;

pub(crate) fn validate_id(id: &str, label: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            format!("{label} must be 1..=128 ASCII letters, digits, or -_.:"),
        ));
    }
    Ok(())
}
