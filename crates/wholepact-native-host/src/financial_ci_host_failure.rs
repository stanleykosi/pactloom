//! Semantic CI only. Match variant identity, never error payloads or formatting.
use crate::Error;
pub(crate) use wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::Stage;
use wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::{Class,latch_failure,classify_io};
pub(crate) fn native(stage:Stage,error:&Error) {latch_failure(stage,class(error));}
pub(crate) fn io(stage:Stage,error:&std::io::Error) {latch_failure(stage,classify_io(error.kind()));}
fn class(error:&Error)->Class {
 match error {
 Error::Platform=>Class::Platform,Error::Terminal=>Class::Terminal,Error::Permission=>Class::Permission,
 Error::Locked=>Class::Locked,Error::Invalid=>Class::Invalid,Error::Authentication=>Class::Authentication,
 Error::Storage=>Class::Storage,Error::Quarantined=>Class::Quarantined,Error::Unsupported=>Class::Unsupported,
 Error::Receipt(_)=>Class::Receipt,Error::RecoverySemantic(_)=>Class::RecoverySemantic,
 Error::RecoveryBackupUnsupported=>Class::RecoveryBackupUnsupported,
 Error::RecoveryFinancialUnsupported=>Class::RecoveryFinancialUnsupported,
 Error::CompleteOriginRecoveryUnavailable=>Class::CompleteOriginRecoveryUnavailable,
 Error::HistoricalExportIncomplete=>Class::HistoricalExportIncomplete,
 Error::GenerationArchiveIncomplete=>Class::GenerationArchiveIncomplete,
 }
}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn payloads_never_enter_classification(){assert_eq!(class(&Error::Receipt("synthetic-not-serialized".into())),Class::Receipt);assert_eq!(class(&Error::RecoverySemantic("synthetic-not-serialized".into())),Class::RecoverySemantic);}
 #[test] fn native_variants_are_distinct(){
  let cases=[(Error::Platform,Class::Platform),(Error::Terminal,Class::Terminal),(Error::Permission,Class::Permission),(Error::Locked,Class::Locked),(Error::Invalid,Class::Invalid),(Error::Authentication,Class::Authentication),(Error::Storage,Class::Storage),(Error::Quarantined,Class::Quarantined),(Error::Unsupported,Class::Unsupported),(Error::RecoveryBackupUnsupported,Class::RecoveryBackupUnsupported),(Error::RecoveryFinancialUnsupported,Class::RecoveryFinancialUnsupported),(Error::CompleteOriginRecoveryUnavailable,Class::CompleteOriginRecoveryUnavailable),(Error::HistoricalExportIncomplete,Class::HistoricalExportIncomplete),(Error::GenerationArchiveIncomplete,Class::GenerationArchiveIncomplete)];for (error,expected) in cases {assert_eq!(class(&error),expected);}
 }
}
