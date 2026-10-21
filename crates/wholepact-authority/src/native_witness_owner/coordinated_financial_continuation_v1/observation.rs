//! Closed first actual operation failure only. This data cannot alter a return
//! value, outcome, source, admission, deadline or retry policy.
use crate::AuthorityError;
pub(crate) use wholepact_financial_coordinator_origin::{
    DeliveryFailureClassV1 as Class, DeliveryFailureStageV1 as Stage, DeliveryFailureV1,
};

#[derive(Default)]
pub(crate) struct FirstFailureV1 {
    first: Option<DeliveryFailureV1>,
}
impl FirstFailureV1 {
    pub(crate) fn note(&mut self, stage: Stage, error: AuthorityError) {
        if self.first.is_none() {
            self.first = Some(DeliveryFailureV1 {
                stage,
                class: classify(error),
            });
        }
    }
    pub(crate) fn take(&mut self) -> Option<DeliveryFailureV1> {
        self.first.take()
    }
}
fn classify(error: AuthorityError) -> Class {
    match error {
        AuthorityError::InvalidBinding => Class::InvalidBinding,
        AuthorityError::Permission => Class::Permission,
        AuthorityError::StaleHead => Class::StaleHead,
        AuthorityError::Conflict => Class::Conflict,
        AuthorityError::Inactive => Class::Inactive,
        AuthorityError::RecoveryRequired => Class::RecoveryRequired,
        AuthorityError::Expired => Class::Expired,
        AuthorityError::PolicyDenied => Class::PolicyDenied,
        AuthorityError::BudgetExceeded => Class::BudgetExceeded,
        AuthorityError::InputReserved => Class::InputReserved,
        AuthorityError::ObligationReserved => Class::ObligationReserved,
        AuthorityError::Limit => Class::Limit,
        AuthorityError::Storage => Class::Storage,
        AuthorityError::CorruptHistory => Class::CorruptHistory,
        AuthorityError::PermanentStopUnavailable => Class::PermanentStopUnavailable,
        AuthorityError::OfflineHistoryUnsupported => Class::OfflineHistoryUnsupported,
        AuthorityError::ConstructionHistoryUnsupported => Class::ConstructionHistoryUnsupported,
        AuthorityError::UnsupportedVersion => Class::UnsupportedVersion,
        AuthorityError::Authentication => Class::Authentication,
        AuthorityError::Uncertain => Class::Uncertain,
        AuthorityError::ResolutionUnavailable => Class::ResolutionUnavailable,
        AuthorityError::SessionRequired => Class::SessionRequired,
        AuthorityError::SessionPending => Class::SessionPending,
    }
}
