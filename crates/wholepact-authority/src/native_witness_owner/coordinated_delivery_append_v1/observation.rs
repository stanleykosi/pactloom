//! Closed first actual operation failure only. This data cannot alter a return
//! value, outcome, source, admission, deadline or retry policy.
use crate::AuthorityError;
pub(crate) use wholepact_financial_coordinator_origin::{DeliveryFailureV1, DeliveryFailureStageV1 as Stage, DeliveryFailureClassV1 as Class};

#[derive(Default)]
pub(super) struct FirstFailureV1 { first: Option<DeliveryFailureV1> }
impl FirstFailureV1 {
    pub(super) fn note(&mut self, stage: Stage, error: AuthorityError) {
        if self.first.is_none() { self.first = Some(DeliveryFailureV1 { stage, class: classify(error) }); }
    }
    pub(super) fn take(&mut self) -> Option<DeliveryFailureV1> { self.first.take() }
    pub(super) fn preparation(&mut self, failure: super::super::delivery_preparation_v2::PreparationFailureV1) -> AuthorityError {
        use super::super::delivery_preparation_v2::PreparationStageV1 as P;
        let stage = match failure.stage {
            P::InputValidation => Stage::InputValidation,
            P::RequestDecode => Stage::RequestDecode,
            P::EndpointValidation => Stage::EndpointValidation,
            P::ServerCertificateRead => Stage::ServerCertificateRead,
            P::ServerCertificateValidation => Stage::ServerCertificateValidation,
            P::TrustedClientRootRead => Stage::TrustedClientRootRead,
            P::ServerPrivateKeyRead => Stage::ServerPrivateKeyRead,
            P::TlsConfiguration => Stage::TlsConfiguration,
            P::ProtectedNamespaceOpen => Stage::ProtectedNamespaceOpen,
            P::ListenerBind => Stage::ListenerBind,
            P::ListenerConfiguration => Stage::ListenerConfiguration,
            P::PreparedSourceCurrentness => Stage::PreparedSourceCurrentness,
        };
        self.note(stage, failure.error);
        failure.error // the SAME original error, not a diagnostic substitution
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_actual_failure_survives_later_cleanup_error() {
        let mut observer = FirstFailureV1::default();
        observer.note(Stage::ProtectedNamespaceOpen, AuthorityError::CorruptHistory);
        observer.note(Stage::CommitRollback, AuthorityError::Uncertain);
        let first = observer.take().unwrap();
        assert_eq!(first.stage, Stage::ProtectedNamespaceOpen);
        assert_eq!(first.class, Class::CorruptHistory);
    }
    #[test]
    fn observed_preparation_preserves_original_error() {
        let mut observer = FirstFailureV1::default();
        let original = AuthorityError::Authentication;
        let returned = observer.preparation(super::super::super::delivery_preparation_v2::PreparationFailureV1 {
            stage: super::super::super::delivery_preparation_v2::PreparationStageV1::ServerCertificateValidation,
            error: original,
        });
        assert_eq!(returned, original);
        assert_eq!(observer.take().unwrap().class, Class::Authentication);
    }
}
