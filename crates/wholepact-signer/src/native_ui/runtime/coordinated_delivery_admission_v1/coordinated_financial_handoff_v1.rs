//! Consumes only actual completed coordinated V3. No NativeRuntime adapter,
//! status importer, credential constructor, replacement socket or clock renewal.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::{
    CoordinatedFinancialRoleTransportV1,OriginalFinancialReentrySelectionV1,
};
use crate::native_peer::PeerProcess;
use wholepact_authority::durable_financial_continuation_v1::FinancialContinuationTermsV1;

pub(in crate::native_ui::runtime) struct DetachedCoordinatedFinancialHandoffV1 {
    pub(in crate::native_ui::runtime) selection:OriginalFinancialReentrySelectionV1,
    pub(in crate::native_ui::runtime) material:VerifiedDurableEconomicsV1,
    pub(in crate::native_ui::runtime) original_host:PeerProcess,
    pub(in crate::native_ui::runtime) original_material_deadline:Instant,
    pub(in crate::native_ui::runtime) owner_setup_json:zeroize::Zeroizing<String>,
    pub(in crate::native_ui::runtime) transport:CoordinatedFinancialRoleTransportV1,
    pub(in crate::native_ui::runtime) terms:FinancialContinuationTermsV1,
    pub(in crate::native_ui::runtime) audit:wholepact_financial_coordinator_origin::SignerV3AuditedV1,
    pub(in crate::native_ui::runtime) received:SignerV3ReceivedV1,
}
impl HistoryReturnedCoordinatedV3V1 {
    /// Actual H final status consumption/source-entry ordering is established by
    /// the original role driver before calling this on its owned bounded worker.
    pub(in crate::native_ui::runtime) fn into_financial_handoff(self)->Result<DetachedCoordinatedFinancialHandoffV1> {
        let AuditedCoordinatedV3V1{custody,selection,history,terms,report,lifetime}=self.completed.audited;
        lifetime.check_current()?;
        custody.source.check_current()?;
        custody.witness.check_custody()?;
        if selection.terms()!=&terms || report.source_identity_digest!=custody.source.source_identity()
            || report.recipient_intent_digest!=custody.intent.digest().map_err(|_|Error::ReviewMismatch)?
            || custody.retained.as_ref().ok_or(Error::RecoveryRequired)?.history_digest()?!=report.local_record_digest
            || lifetime.audit_presentation_digest()!=report.audit_presentation_digest
        {return Err(Error::ReviewMismatch);}
        let original_material_deadline=custody.source.original_material_deadline();
        if Instant::now()>=original_material_deadline{return Err(Error::Locked);}
        let owner_setup_json=zeroize::Zeroizing::new(custody.source.original_owner_setup_json().to_owned());
        let CoordinatedAdmissionAttemptV1{source,witness,intent:_,fixed,receipt:_,received,request:_,retained:_,controlled:_,admitted:_,failure:_}=custody;
        // End old private owner client/read custody before opening financial
        // originals. No read capability is derived from completion observation.
        drop(witness);
        drop(history);
        let (transport,original_host)=source.into_financial_role_transport(lifetime)?;
        selection.check_host(&original_host)?;
        transport.check_current()?;
        if Instant::now()>=original_material_deadline{return Err(Error::Locked);}
        Ok(DetachedCoordinatedFinancialHandoffV1 {
            selection,material:fixed,original_host,original_material_deadline,
            owner_setup_json,transport,terms,audit:report,received,
        })
    }
}

#[path = "coordinated_financial_entry_v1.rs"]
pub(in crate::native_ui::runtime) mod coordinated_financial_entry_v1;
