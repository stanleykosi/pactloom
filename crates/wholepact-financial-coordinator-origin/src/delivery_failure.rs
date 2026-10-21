//! Finite inert first-failure diagnostics. No strings, secret data or authority.
use serde::{Serialize, Deserialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryFailureStageV1 {
    InputValidation, RequestDecode, EndpointValidation, ServerCertificateRead, ServerCertificateValidation, TrustedClientRootRead, ServerPrivateKeyRead, TlsConfiguration, ProtectedNamespaceOpen, ListenerBind, ListenerConfiguration, PreparedSourceCurrentness, ReviewClock, ReviewFacts, ArmCurrentness, TlsAccept, TlsHandshake, TlsPeerIdentity, TlsPreparation, TlsReadyWrite, TlsRequest, FirstPreflight, PreflightRollback, FinalAdmitWait, SecondPreflight, FinalCurrentness, JournalAppend, JournalCommit, CommitRollback, TlsResponse,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryFailureClassV1 {
    InvalidBinding, Permission, StaleHead, Conflict, Inactive, RecoveryRequired, Expired, PolicyDenied, BudgetExceeded, InputReserved, ObligationReserved, Limit, Storage, CorruptHistory, PermanentStopUnavailable, OfflineHistoryUnsupported, ConstructionHistoryUnsupported, UnsupportedVersion, Authentication, Uncertain, ResolutionUnavailable, SessionRequired, SessionPending,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryFailureV1 { pub stage: DeliveryFailureStageV1, pub class: DeliveryFailureClassV1 }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostics_are_closed_data_not_free_form_claims() {
        let data = DeliveryFailureV1 { stage: DeliveryFailureStageV1::JournalCommit, class: DeliveryFailureClassV1::Uncertain };
        let bytes = serde_json::to_vec(&data).unwrap(); assert_eq!(serde_json::from_slice::<DeliveryFailureV1>(&bytes).unwrap(), data);
        for bad in [r#"{"stage":"Unknown","class":"Storage"}"#, r#"{"stage":"TlsAccept","class":"password"}"#,
            r#"{"stage":"TlsAccept","class":"Storage","detail":"secret"}"#, r#"{"stage":"TlsAccept","stage":"TlsRequest","class":"Storage"}"#] {
            assert!(serde_json::from_str::<DeliveryFailureV1>(bad).is_err());
        }
    }
}
