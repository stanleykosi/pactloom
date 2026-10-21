//! Actual nominal SignExact commits, strict immutable revision CAS and one-use
//! Origin gates. The transaction is moved into its matching gate, never merely
//! tested before an unguarded commit. No network or await spans any gate.
use super::*;
use crate::consent_journal::ApprovedCoordinatedFinancialSpendConsentV1;

enum Effect<'a> {
    Release,
    Request(&'a RetainedAuthorizationRequest),
    Permit(&'a AuthenticatedPermit),
    Started(&'a AuthenticatedPermit),
    Result(&'a AuthenticatedPermit,&'a RetainedAuthorizationResult),
}
enum Value { Release(OriginalAuthorizationEvidence), Unit }
struct Settlement { value:Value, after_commit:Option<BridgeError> }
/// An actual successful result COMMIT is retained even when later Origin/R or
/// wallet checks fail. This marker is not permission and cannot retry signing.
pub(crate) struct CoordinatedFinancialResultCommitV1 {
    pub(crate) commit: crate::authority_bridge::AuthorizationCommit,
    pub(crate) after_commit: Option<BridgeError>,
}
impl FinancialConsentJournalV1 {
    fn coordinated_sign_effect(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedCoordinatedFinancialSpendConsentV1,effect:Effect<'_>)->BridgeResult<Settlement>{
        approved.check_current()?;
        let _fence=self.journal.authority_fence.read().map_err(|_|JournalError::Permission)?;
        approved.check_current()?;
        let mut c=self.journal.connection.lock().map_err(|_|JournalError::Database)?;
        approved.check_current()?;
        if !c.is_autocommit(){return Err(BridgeError::Conflict);}
        source.require(&self.journal,&c)?;
        approved.check_current()?;
        source.require_pin(&c)?;
        approved.check_current()?;
        if matches!(&effect,Effect::Release){approved.require_initial_revision(source)?;}
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate).map_err(JournalError::from)?;
        approved.check_current()?;
        // The source binding is an exact CAS, not a newly refreshed baseline.
        source.require(&self.journal,&tx)?;
        source.require_pin(&tx)?;
        approved.check_current()?;
        validate(&tx,&self.genesis)?;
        approved.check_current()?;
        let account=read_account(&tx)?;
        approved.require_journal(&self.journal.binding(),&account)?;
        let record=approved.record();
        record.validate_financial_v1()?;
        if record.financial_binding_v1().ok_or(BridgeError::Binding)?.source_identity_digest!=source.identity_digest(){return Err(BridgeError::Binding);}
        let id=&record.terms().authorization_id;
        let old=read_financial_original_v1(&tx,id)?;
        approved.check_current()?;
        let value=match &effect {
            Effect::Release=>{
                if old.is_some(){return Err(BridgeError::Conflict);}
                let terms=record.terms();
                let enrollment=read_enrollment(&tx,&terms.enrollment_ref)?.ok_or(BridgeError::Missing)?;
                approved.check_current()?;
                let manifest=read_manifest(&tx,&terms.accepted_manifest_ref)?.ok_or(BridgeError::Missing)?;
                approved.check_current()?;
                let original=OriginalAuthorizationEvidence { enrollment,manifest,consent:record.clone(),release:ConsentLinkedReleaseIntent::from_consent(record) };
                validate_financial_linkage(&tx,&original)?;
                approved.check_current()?;
                Value::Release(append_release_rows(&tx,&original,ReleaseRowProfile::FinancialV1,self.journal.capacity_limits())?)
            }
            _=>{
                if old.as_ref().map(OriginalAuthorizationEvidence::original_consent)!=Some(record){return Err(BridgeError::Binding);}
                let table=match &effect {Effect::Request(_)=>"signer_bridge_requests",Effect::Permit(_)=>"signer_bridge_permits",Effect::Started(_)=>"signer_bridge_keyuse",Effect::Result(_,_)=>"signer_bridge_results",Effect::Release=>unreachable!()};
                let exists:bool=tx.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE authorization_id=?1)"),[id],|r|r.get(0)).map_err(JournalError::from)?;
                if exists{return Err(BridgeError::Uncertain);}
                approved.check_current()?;
                match &effect {
                    Effect::Request(request)=>retain_request_rows(&tx,id,request)?,
                    Effect::Permit(permit)=>{retain_permit_rows(&tx,id,permit)?;},
                    Effect::Started(permit)=>begin_key_use_rows(&tx,id,permit)?,
                    Effect::Result(permit,result)=>retain_result_rows(&tx,id,permit,result)?,
                    Effect::Release=>unreachable!(),
                }
                Value::Unit
            }
        };
        approved.check_current()?;
        validate(&tx,&self.genesis)?;
        bounded_financial(&tx)?;
        approved.check_current()?;
        source.require(&self.journal,&tx)?;
        let rows=original_rows_digest(&tx)?;
        let next=revision(&tx)?;
        approved.check_current()?;
        let committed=std::cell::Cell::new(false);
        let attempted=std::cell::Cell::new(false);
        // All locks and the actual SQL transaction exist before admission.
        // Moving tx prevents approval of a callback followed by a later commit.
        let committed_ref=&committed;
        let attempted_ref=&attempted;
        let commit=move ||->std::io::Result<()>{
            attempted_ref.set(true);
            tx.commit().map_err(|_|std::io::Error::other("coordinated sign commit uncertain"))?;
            committed_ref.set(true);
            Ok(())
        };
        let admitted=match effect {
            Effect::Release=>approved.release(commit),
            Effect::Request(_)=>approved.request(commit),
            Effect::Permit(_)=>approved.permit(commit),
            Effect::Started(_)=>approved.started(commit),
            Effect::Result(_,_)=>approved.result(commit),
        };
        if !committed.get(){return Err(if attempted.get(){BridgeError::Uncertain}else{BridgeError::Permission});}
        // This revision belongs to the actual settled commit, including when R
        // raced its return. Never reopen/refresh from an unknown outside writer.
        source.original_rows_digest=rows;
        source.revision=next;
        let metadata=(||->BridgeResult<()>{
            source.require(&self.journal,&c)?;
            if !c.is_autocommit()||source.revision!=revision(&c)?{return Err(BridgeError::Conflict);}
            Ok(())
        })();
        let after_commit=admitted.err().map(|_|BridgeError::Permission)
            .or_else(||metadata.err())
            .or_else(||approved.check_current().err().map(BridgeError::from));
        Ok(Settlement{value,after_commit})
    }
    pub(crate) fn record_coordinated_financial_release_v1(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedCoordinatedFinancialSpendConsentV1)->BridgeResult<OriginalAuthorizationEvidence>{
        let settled=self.coordinated_sign_effect(source,approved,Effect::Release)?;
        if let Some(error)=settled.after_commit{return Err(error);}
        match settled.value{Value::Release(value)=>Ok(value),Value::Unit=>Err(BridgeError::Binding)}
    }
    pub(crate) fn retain_coordinated_financial_request_v1(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedCoordinatedFinancialSpendConsentV1,request:&RetainedAuthorizationRequest)->BridgeResult<()>{
        let settled=self.coordinated_sign_effect(source,approved,Effect::Request(request))?;
        settled.after_commit.map_or(Ok(()),Err)
    }
    pub(crate) fn retain_coordinated_financial_permit_v1(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedCoordinatedFinancialSpendConsentV1,permit:&AuthenticatedPermit)->BridgeResult<()>{
        let settled=self.coordinated_sign_effect(source,approved,Effect::Permit(permit))?;
        settled.after_commit.map_or(Ok(()),Err)
    }
    pub(crate) fn begin_coordinated_financial_key_use_v1(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedCoordinatedFinancialSpendConsentV1,permit:&AuthenticatedPermit)->BridgeResult<()>{
        let settled=self.coordinated_sign_effect(source,approved,Effect::Started(permit))?;
        settled.after_commit.map_or(Ok(()),Err)
    }
    pub(crate) fn retain_coordinated_financial_result_v1(&self,source:&mut FinancialSourceBindingV1,approved:&ApprovedCoordinatedFinancialSpendConsentV1,permit:&AuthenticatedPermit,result:&RetainedAuthorizationResult)->BridgeResult<CoordinatedFinancialResultCommitV1>{
        let settled=self.coordinated_sign_effect(source,approved,Effect::Result(permit,result))?;
        Ok(CoordinatedFinancialResultCommitV1{commit:result.into(),after_commit:settled.after_commit})
    }
}
