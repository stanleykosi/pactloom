//! Genuine completed custody -> fresh financial Entry -> fresh initial Read.
//! Ordinary setup bytes never open credentials or replace a completed owner.
use super::*;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::{
    PreparedOriginalFinancialSourceV1,PreparedCoordinatedSourceEntryV1,
    PresentedCoordinatedSourceEntryV1,OpenedCoordinatedOriginalFinancialSourceV2,
};
use crate::native_ui::witness_workspace::financial_continuation_v1::coordinated_initial_read_v1::{
    PreparedCoordinatedInitialReadV1,PresentedCoordinatedInitialReadV1,ReadFinancialContinueInputsV2,
};
use wholepact_financial_coordinator_origin::{
    SignerFinancialWorkflowOriginV1,SignerFinancialSetupSelectionV1,
    SignerSourceEntryPresentationV1,SignerSourceEntryInputV1,SignerSourceEntryFinalV1,
    SignerFinancialReadFinalV1,
};
use zeroize::Zeroizing;

struct Inputs {
    host:PeerProcess,material:VerifiedDurableEconomicsV1,terms:FinancialContinuationTermsV1,
    material_deadline:Instant,owner_setup:Zeroizing<String>,writer_setup:Zeroizing<String>,wallet_setup:Zeroizing<String>,
}
pub(in crate::native_ui::runtime) struct PresentedFinancialEntryRoleV1 {
    inputs:Inputs,selection:OriginalFinancialReentrySelectionV1,presented:PresentedCoordinatedSourceEntryV1,
}
pub(in crate::native_ui::runtime) struct OpenedFinancialEntryRoleV1 {
    inputs:Inputs,source:OpenedCoordinatedOriginalFinancialSourceV2,entry:SignerSourceEntryPresentationV1,
}
pub(in crate::native_ui::runtime) struct PreparedInitialFinancialReadRoleV1 {
    inputs:Inputs,source:OpenedCoordinatedOriginalFinancialSourceV2,prepared:PreparedCoordinatedInitialReadV1,
}
pub(in crate::native_ui::runtime) struct PresentedInitialFinancialReadRoleV1 {
    inputs:Inputs,source:OpenedCoordinatedOriginalFinancialSourceV2,presented:PresentedCoordinatedInitialReadV1,
}
pub(in crate::native_ui::runtime) struct ReadInitialFinancialRoleV1 {
    pub(in crate::native_ui::runtime) original_peer:PeerProcess,
    pub(in crate::native_ui::runtime) terms:FinancialContinuationTermsV1,
    pub(in crate::native_ui::runtime) material:VerifiedDurableEconomicsV1,
    pub(in crate::native_ui::runtime) writer_setup:Zeroizing<String>,
    pub(in crate::native_ui::runtime) wallet_setup:Zeroizing<String>,
    pub(in crate::native_ui::runtime) read:ReadFinancialContinueInputsV2,
}
impl DetachedCoordinatedFinancialHandoffV1 {
    pub(in crate::native_ui::runtime) fn offer_entry(
        self,setup:SignerFinancialSetupSelectionV1,origin:&mut SignerFinancialWorkflowOriginV1,
    )->Result<(PresentedFinancialEntryRoleV1,CoordinatedFinancialRoleTransportV1)> {
        setup.validate()?;
        self.transport.check_current()?;
        self.selection.check_host(&self.original_host)?;
        if setup.source_identity_digest!=self.audit.source_identity_digest
            || setup.audit_presentation_digest!=self.audit.audit_presentation_digest
            || setup.recipient_intent_digest!=self.audit.recipient_intent_digest
            || setup.fixed_identity_digest!=self.received.fixed_identity_digest
            || self.selection.terms()!=&self.terms
            || Instant::now()>=self.original_material_deadline
        {return Err(Error::ReviewMismatch);}
        let session_digest=wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-financial-actual-v3-session:v1",
            &(&self.audit,&self.received,self.selection.digest(),&setup),
        ).map_err(|_|Error::InvalidData)?;
        let prepared=PreparedCoordinatedSourceEntryV1::prepare(
            &self.selection,self.original_material_deadline,&self.original_host,session_digest,
        )?;
        let presentation=origin.offer_source_entry(prepared.facts().clone(),
            prepared.original_source_deadline(),prepared.original_entry_deadline())?;
        let presented=prepared.freeze_presentation(presentation)?;
        let inputs=Inputs{host:self.original_host,material:self.material,terms:self.terms,
            material_deadline:self.original_material_deadline,owner_setup:self.owner_setup_json,
            writer_setup:Zeroizing::new(setup.writer_setup_json),wallet_setup:Zeroizing::new(setup.wallet_setup_json)};
        Ok((PresentedFinancialEntryRoleV1{inputs,selection:self.selection,presented},self.transport))
    }
}
impl PresentedFinancialEntryRoleV1 {
    pub(in crate::native_ui::runtime) fn open(self,input:SignerSourceEntryInputV1,action:SignerSourceEntryFinalV1)->Result<OpenedFinancialEntryRoleV1> {
        let entry=self.presented.presentation().clone();
        let source=PreparedOriginalFinancialSourceV1::open_coordinated_original19(
            self.selection,self.inputs.material_deadline,&self.inputs.host,self.presented,input,action,
        )?;
        source.check_public(&self.inputs.host)?;
        Ok(OpenedFinancialEntryRoleV1{inputs:self.inputs,source,entry})
    }
}
impl OpenedFinancialEntryRoleV1 {
    pub(in crate::native_ui::runtime) fn prepare_read(self)->Result<PreparedInitialFinancialReadRoleV1> {
        let prepared=PreparedCoordinatedInitialReadV1::prepare(self.inputs.owner_setup.as_str(),
            &self.source,&self.inputs.host,self.inputs.terms.clone(),self.entry)?;
        Ok(PreparedInitialFinancialReadRoleV1{inputs:self.inputs,source:self.source,prepared})
    }
}
impl PreparedInitialFinancialReadRoleV1 {
    pub(in crate::native_ui::runtime) fn offer(self,origin:&mut SignerFinancialWorkflowOriginV1)->Result<PresentedInitialFinancialReadRoleV1> {
        let presentation=origin.offer_initial_read(self.prepared.facts().clone(),
            self.prepared.original_read_deadline(),self.prepared.original_source_deadline())?;
        let presented=self.prepared.freeze_presentation(presentation)?;
        Ok(PresentedInitialFinancialReadRoleV1{inputs:self.inputs,source:self.source,presented})
    }
}
impl PresentedInitialFinancialReadRoleV1 {
    pub(in crate::native_ui::runtime) fn read(self,action:SignerFinancialReadFinalV1)->Result<ReadInitialFinancialRoleV1> {
        let read=self.presented.read_history_for_continue_preparation_v2(self.source,&self.inputs.host,action)?;
        Ok(ReadInitialFinancialRoleV1{original_peer:self.inputs.host,terms:self.inputs.terms,
            material:self.inputs.material,writer_setup:self.inputs.writer_setup,wallet_setup:self.inputs.wallet_setup,read})
    }
}
