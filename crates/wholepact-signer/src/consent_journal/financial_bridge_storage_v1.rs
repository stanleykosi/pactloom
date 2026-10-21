//! Exact profile20 bridge rows. The legacy bridge reader never accepts these
//! receipts. A private transaction kernel retains the actual current native
//! action through each effect and advances only its own source revision.
use super::*;
#[cfg(feature="coordinated-financial-workflow-v1")]
#[path="financial_bridge_storage_v1/coordinated_return_v1.rs"]
mod coordinated_return_v1;
use crate::authority_bridge::{BridgeError, Result as BridgeResult};
use crate::authority_bridge::protocol::{RetainedAuthorizationRequest, RetainedAuthorizationResult, RetainedWitnessPermit};
use crate::authority_bridge::financial_continuation_v1::request_from_financial_original_v1;
use crate::consent_journal::bridge_storage::{read_request,read_permit,read_result};
use wholepact_authority::{AuthenticatedPermit,OwnerControl};

fn encode<T:serde::Serialize>(value:&T)->BridgeResult<zeroize::Zeroizing<String>> {
    let raw=zeroize::Zeroizing::new(serde_json::to_string(value).map_err(|_|BridgeError::Binding)?);
    if raw.len()>512*1024 { return Err(BridgeError::Limit); } Ok(raw)
}
fn validate_request(c:&Connection, request:&RetainedAuthorizationRequest)->BridgeResult<OriginalAuthorizationEvidence> {
    let original=read_financial_original_v1(c,&request.reservation.authorization_id)?.ok_or(BridgeError::Missing)?;
    let retained=intent::read(c)?;
    let OwnerControl::AdmitFinancialContinuationV1{record}=&retained.request().control else {return Err(BridgeError::Binding)};
    if request_from_financial_original_v1(&original,record,&request.artifact()?)? != *request {return Err(BridgeError::Binding);}
    Ok(original)
}
fn validate_permit(request:&RetainedAuthorizationRequest,permit:&RetainedWitnessPermit)->BridgeResult<()> {
    permit.descriptor.matches_request(&request.reservation)?;
    let witness=&request.disclosure.as_ref().ok_or(BridgeError::Binding)?.descriptor;
    if permit.witness_certificate_digest!=witness.pinned_server_certificate_digest
        || permit.descriptor.witness_id!=witness.witness_id || permit.descriptor.policy_digest!=witness.policy_digest {return Err(BridgeError::Binding);}
    Ok(())
}
fn current_permit(c:&Connection,id:&str,permit:&AuthenticatedPermit)->BridgeResult<()> {
    let request=read_request(c,id)?.ok_or(BridgeError::Missing)?;
    validate_request(c,&request)?;
    let expected=RetainedWitnessPermit::from_authenticated(permit,&request.reservation)?;
    validate_permit(&request,&expected)?;
    if read_permit(c,id)?.as_ref()!=Some(&expected) {return Err(BridgeError::Binding);}
    let now=now_ms()?;
    if now<expected.descriptor.reserved_at_ms || now>=request.reservation.permit_expires_at_ms {return Err(BridgeError::Permission);}
    Ok(())
}

impl FinancialConsentJournalV1 {
    // This closure is private to this module; no generic write or authority
    // provider is exported. Callers select one of the four exact effects below.
    fn financial_bridge_effect<T>(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedFinancialSpendConsentV1,
        effect:impl FnOnce(&Connection,&str)->BridgeResult<T>)->BridgeResult<T> {
        approved.check_current()?;
        let account=self.journal.account_state()?;
        let journal_binding=self.journal.binding();
        let lease=approved.lease_for_journal(&journal_binding,&account)?;
        let _fence=self.journal.authority_fence.read().map_err(|_|JournalError::Permission)?;
        let mut c=self.journal.connection.lock().map_err(|_|JournalError::Database)?;
        source.require(&self.journal,&c)?; source.require_pin(&c)?;
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate).map_err(JournalError::from)?;
        validate(&tx,&self.genesis)?; check_account(&tx,&account)?; lease.check_current()?;
        let record=approved.record();
        if record.financial_binding_v1().ok_or(BridgeError::Permission)?.source_identity_digest!=source.source_digest {return Err(BridgeError::Permission);}
        let id=&record.terms().authorization_id;
        let original=read_financial_original_v1(&tx,id)?.ok_or(BridgeError::Missing)?;
        if original.original_consent()!=record {return Err(BridgeError::Binding);}
        let result=effect(&tx,id)?;
        validate(&tx,&self.genesis)?; bounded_financial(&tx)?;
        lease.check_current()?; source.require(&self.journal,&tx)?;
        let rows=original_rows_digest(&tx)?; let next=revision(&tx)?;
        tx.commit().map_err(JournalError::from)?;
        source.original_rows_digest=rows; source.revision=next; source.require_pin(&c)?;
        Ok(result)
    }
    pub(crate) fn retain_financial_request_v1(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedFinancialSpendConsentV1,request:&RetainedAuthorizationRequest)->BridgeResult<()> {
        self.financial_bridge_effect(source,approved,|c,id|retain_request_rows(c,id,request))
    }
    pub(crate) fn retain_financial_permit_v1(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedFinancialSpendConsentV1,permit:&AuthenticatedPermit)->BridgeResult<RetainedWitnessPermit> {
        self.financial_bridge_effect(source,approved,|c,id|retain_permit_rows(c,id,permit))
    }
    pub(crate) fn begin_financial_key_use_v1(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedFinancialSpendConsentV1,permit:&AuthenticatedPermit)->BridgeResult<()> {
        self.financial_bridge_effect(source,approved,|c,id|begin_key_use_rows(c,id,permit))
    }
    pub(crate) fn retain_financial_result_v1(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedFinancialSpendConsentV1,permit:&AuthenticatedPermit,result:&RetainedAuthorizationResult)->BridgeResult<()> {
        self.financial_bridge_effect(source,approved,|c,id|retain_result_rows(c,id,permit,result))
    }
}

/// Full row census, canonical exact request reconstruction, actual retained
/// witness identity and strict state ordering. This validates history only.
pub(super) fn validate_rows(c:&Connection)->Result<()> {
    validate_rows_inner(c).map_err(|_|JournalError::InvalidBinding)
}
fn validate_rows_inner(c:&Connection)->BridgeResult<()> {
    let retained=intent::read(c)?;let terms=retained.terms()?;let id=&terms.scope.authorization.authorization_id;
    let mut counts=Vec::new();
    for table in ["signer_bridge_requests","signer_bridge_permits","signer_bridge_keyuse","signer_bridge_results"] {
        let count:u64=c.query_row(&format!("SELECT count(*) FROM {table}"),[],|r|r.get(0)).map_err(JournalError::from)?;
        let foreign:bool=c.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE authorization_id<>?1)"),[id],|r|r.get(0)).map_err(JournalError::from)?;
        if count>1||foreign {return Err(BridgeError::Binding);}counts.push(count);
    }
    if counts.windows(2).any(|w|w[1]>w[0]) {return Err(BridgeError::Binding);}
    let Some(request)=read_request(c,id)? else {return Ok(())};validate_request(c,&request)?;
    let raw:String=c.query_row("SELECT request_payload FROM signer_bridge_requests WHERE authorization_id=?1",[id],|r|r.get(0)).map_err(JournalError::from)?;
    if raw!=*encode(&(&request.reservation,&request.delivery,&request.disclosure))? {return Err(BridgeError::Binding);}
    if let Some(permit)=read_permit(c,id)? {
        validate_permit(&request,&permit)?;
        let raw:String=c.query_row("SELECT payload FROM signer_bridge_permits WHERE authorization_id=?1",[id],|r|r.get(0)).map_err(JournalError::from)?;
        if raw!=*encode(&permit)? {return Err(BridgeError::Binding);}
    }
    if let Some(result)=read_result(c,id)? {result.validate(&request)?;}
    Ok(())
}

impl FinancialConsentJournalV1 {
    /// A fresh read decision can retrieve historical bytes but cannot return
    /// them under an authenticated origin. ReturnExact needs its own new click.
    pub(crate) fn financial_retained_result_v1(&self,source:&FinancialSourceBindingV1,read:&crate::native_ui::financial_authority_v1::FinancialReadLeaseV1)
        ->BridgeResult<(OriginalAuthorizationEvidence,RetainedAuthorizationRequest,RetainedWitnessPermit,RetainedAuthorizationResult,FinancialReturnJournalPinV1,wholepact_authority::OwnerControlRequest)> {
        read.check_source(source.identity_digest()).map_err(|_|BridgeError::Permission)?;
        let publication=read.publication_lease().map_err(|_|BridgeError::Permission)?;
        let _fence=self.journal.authority_fence.read().map_err(|_|JournalError::Permission)?;
        let mut c=self.journal.connection.lock().map_err(|_|JournalError::Database)?;
        if !c.is_autocommit(){return Err(JournalError::Conflict.into());}
        source.require(&self.journal,&c)?;source.require_pin(&c)?;
        let tx=c.transaction_with_behavior(TransactionBehavior::Deferred).map_err(JournalError::from)?;
        validate(&tx,&self.genesis)?;
        let (original,request,permit,result,retained)=read_retained_result_rows(&tx)?;
        let terms=retained.terms()?;let id=&terms.scope.authorization.authorization_id;
        source.require(&self.journal,&tx)?;source.require_pin(&tx)?;
        let original_delivery=authority::durable_delivery_admission_intent_v3::read(&tx,id)?.ok_or(BridgeError::Missing)?;
        let pin=FinancialReturnJournalPinV1::from_audited_result(self,source,&tx,original_delivery.recipient_intent().authorized_host_process_instance.clone(),result.result_digest.clone())?;
        read.check_source(source.identity_digest()).map_err(|_|BridgeError::Permission)?;
        tx.commit().map_err(JournalError::from)?;source.require_pin(&c)?;
        if !c.is_autocommit(){return Err(JournalError::Conflict.into());}
        pin.require(self,source,&c)?;
        drop(publication);
        Ok((original,request,permit,result,pin,retained.request().clone()))
    }
}

// Exact rows only; current authority and transaction ownership stay in the
// concrete caller. No caller can obtain a grant from this private function.
fn retain_request_rows(c:&Connection,id:&str,request:&RetainedAuthorizationRequest)->BridgeResult<()>{
            if request.reservation.authorization_id!=id {return Err(BridgeError::Binding);}
            validate_request(c,request)?;
            if let Some(old)=read_request(c,id)? {return if old==*request {Ok(())} else {Err(BridgeError::Conflict)};}
            let raw=encode(&(&request.reservation,&request.delivery,&request.disclosure))?;
            c.execute("INSERT INTO signer_bridge_requests(authorization_id,original_consent_ref,request_payload,artifact_hex) VALUES(?1,?2,?3,?4)",params![id,request.reservation.original_consent_ref,raw.as_str(),request.artifact_hex]).map_err(JournalError::from)?;
            Ok(())
}

// Exact rows only; current authority and transaction ownership stay in the
// concrete caller. No caller can obtain a grant from this private function.
fn retain_permit_rows(c:&Connection,id:&str,permit:&AuthenticatedPermit)->BridgeResult<RetainedWitnessPermit>{
            let request=read_request(c,id)?.ok_or(BridgeError::Missing)?;validate_request(c,&request)?;
            let retained=RetainedWitnessPermit::from_authenticated(permit,&request.reservation)?;validate_permit(&request,&retained)?;
            if let Some(old)=read_permit(c,id)? {return if old==retained {Ok(old)} else {Err(BridgeError::Conflict)};}
            let raw=encode(&retained)?;
            c.execute("INSERT INTO signer_bridge_permits(authorization_id,payload) VALUES(?1,?2)",params![id,raw.as_str()]).map_err(JournalError::from)?;
            Ok(retained)
}

// Exact rows only; current authority and transaction ownership stay in the
// concrete caller. No caller can obtain a grant from this private function.
fn begin_key_use_rows(c:&Connection,id:&str,permit:&AuthenticatedPermit)->BridgeResult<()>{
            current_permit(c,id,permit)?;
            let started:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM signer_bridge_keyuse WHERE authorization_id=?1)",[id],|r|r.get(0)).map_err(JournalError::from)?;
            if started {return Err(BridgeError::Uncertain);}
            c.execute("INSERT INTO signer_bridge_keyuse(authorization_id) VALUES(?1)",[id]).map_err(JournalError::from)?;
            Ok(())
}

// Exact rows only; current authority and transaction ownership stay in the
// concrete caller. No caller can obtain a grant from this private function.
fn retain_result_rows(c:&Connection,id:&str,permit:&AuthenticatedPermit,result:&RetainedAuthorizationResult)->BridgeResult<()>{
            current_permit(c,id,permit)?;
            let request=read_request(c,id)?.ok_or(BridgeError::Missing)?;result.validate(&request)?;
            if let Some(old)=read_result(c,id)? {return if old==*result {Ok(())} else {Err(BridgeError::Conflict)};}
            // FK to Started establishes durable ordering. Failure leaves
            // Started and conservative exposure intact, never another key use.
            c.execute("INSERT INTO signer_bridge_results(authorization_id,result_digest,result_hex,outbox_payload) VALUES(?1,?2,?3,?4)",params![id,result.result_digest,result.signed_pczt_hex,result.outbox_payload]).map_err(JournalError::from)?;
            Ok(())
}

// Private row interpretation shared by concrete Read issuers. No permission,
// lock, transaction, or source revision is manufactured by this kernel.
fn read_retained_result_rows(c:&Connection)->BridgeResult<(
    OriginalAuthorizationEvidence, RetainedAuthorizationRequest,
    RetainedWitnessPermit, RetainedAuthorizationResult,
    intent::RetainedFinancialContinuationIntentV1,
)> {
        let retained=intent::read(c)?;let terms=retained.terms()?;let id=&terms.scope.authorization.authorization_id;
        let original=read_financial_original_v1(c,id)?.ok_or(BridgeError::Missing)?;
        let request=read_request(c,id)?.ok_or(BridgeError::Missing)?;validate_request(c,&request)?;
        let permit=read_permit(c,id)?.ok_or(BridgeError::Missing)?;validate_permit(&request,&permit)?;
        let result=read_result(c,id)?.ok_or(BridgeError::Uncertain)?;result.validate(&request)?;
    Ok((original,request,permit,result,retained))
}

#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "financial_bridge_storage_v1/coordinated_sign_v1.rs"]
mod coordinated_sign_v1;
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(crate) use coordinated_sign_v1::CoordinatedFinancialResultCommitV1;
