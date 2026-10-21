//! Sealed worker/main-thread split. Origin never enters a blocking worker;
//! genuine Read and SignExact Finals remain consuming distinct action owners.
use super::*;
#[path="coordinated_financial_return_v1.rs"]
pub(in crate::native_ui::runtime) mod coordinated_financial_return_v1;
use crate::consent_journal::{PreparedCoordinatedFinancialSpendV1,PresentedCoordinatedFinancialSpendV1};
use crate::native_ui::wallet_workspace::financial_v1::PreparedCoordinatedSigningWalletV1;
use crate::authority_bridge::{AuthorizationCommit,financial_continuation_v1::FinancialResultRequestV1};
use wholepact_financial_coordinator_origin::{SignerSignReadFactsV1,SignerSignReadFinalV1,SignerSignReadPresentationV1,
    SignerSignExactFinalV1,SignerSignExactPresentationV1,SignerSignCommittedV1,SignerSignFailureV1,SignerSignFailureStageV1,SignerWalletObservedV1};

pub(in crate::native_ui::runtime) struct PresentedCoordinatedSignReadV1 {
    retained: AwaitingCoordinatedSignReadV1,
    presentation: SignerSignReadPresentationV1,
    deadline: Instant,
}
pub(in crate::native_ui::runtime) struct PreparedCoordinatedSignOwnerV1 {
    retained: AwaitingCoordinatedWalletPrepareV1,
    wallet: PreparedCoordinatedSigningWalletV1,
    spend: PreparedCoordinatedFinancialSpendV1,
    history: AuthenticatedFinancialContinuationHistoryV1,
    active: wholepact_authority::AuthenticatedWriterSession,
    read: SignerSignReadFinalV1,
    original: SignerWalletOriginalV1,
    observed: SignerWalletObservedV1,
}
pub(in crate::native_ui::runtime) struct PresentedCoordinatedSignExactV1 {
    retained: AwaitingCoordinatedWalletPrepareV1,
    wallet: PreparedCoordinatedSigningWalletV1,
    spend: PresentedCoordinatedFinancialSpendV1,
    history: AuthenticatedFinancialContinuationHistoryV1,
    active: wholepact_authority::AuthenticatedWriterSession,
    presentation: SignerSignExactPresentationV1,
    original: SignerWalletOriginalV1,
    observed: SignerWalletObservedV1,
}
pub(in crate::native_ui::runtime) struct FailedCoordinatedSignV1 {
    retained: AwaitingCoordinatedWalletPrepareV1,
    observed_wallet: Option<ObservedCoordinatedFinancialWalletV1>,
    error: Error,
    failure: SignerSignFailureV1,
}
/// Actual effect settlement, retained before a fallible main-thread report.
/// A failed/uncertain output has no method to retry or create another approval.
pub(in crate::native_ui::runtime) struct CoordinatedSignCommitV1 {
    retained: AwaitingCoordinatedWalletPrepareV1,
    committed: Option<AuthorizationCommit>,
    result_request: Option<FinancialResultRequestV1>,
    report: Option<SignerSignCommittedV1>,
    error: Option<Error>,
    failure: SignerSignFailureV1,
    original: SignerWalletOriginalV1,
    observed: SignerWalletObservedV1,
}
pub(in crate::native_ui::runtime) struct AwaitingCoordinatedReturnReadV1 {
    selector_reported: bool,
    retained: AwaitingCoordinatedWalletPrepareV1,
    result_request: FinancialResultRequestV1,
    committed: AuthorizationCommit,
    report: SignerSignCommittedV1,
    original: SignerWalletOriginalV1,
    observed: SignerWalletObservedV1,
}
impl AwaitingCoordinatedSignReadV1 {
    pub(in crate::native_ui::runtime) fn offer_sign_read(self,origin:&mut SignerFinancialWorkflowOriginV1)->Result<PresentedCoordinatedSignReadV1>{
        let(deadline,reviewed_at_ms,expires_at_ms)=wallet_ceiling(&self.retained)?;
        let facts=SignerSignReadFactsV1{original:self.wallet.original().clone(),observed:self.wallet.report().clone(),reviewed_at_ms,expires_at_ms,
            display:"Read one full authenticated history and active session through the SAME retained selected writer TLS client. Compare the exact original activation receipt/head, then prepare the exact fixed spend using the SAME observed wallet inputs. No release, reservation, Started, private spending key, signature or return is authorized.".into()};
        let presentation=origin.offer_sign_read(facts,deadline)?;
        check_wallet_context(&self.retained)?;
        Ok(PresentedCoordinatedSignReadV1{retained:self,presentation,deadline})
    }
}
impl PresentedCoordinatedSignReadV1 {
    /// Worker only: no Origin reference, no report emission, no key use.
    pub(in crate::native_ui::runtime) fn consume_final(self,read:SignerSignReadFinalV1)
        ->std::result::Result<PreparedCoordinatedSignOwnerV1,FailedCoordinatedSignV1>{
        let AwaitingCoordinatedSignReadV1{retained,wallet}=self.retained;
        let original=wallet.original().clone();
        let observed=wallet.report().clone();
        let mut wallet=Some(wallet);
        let result=(||->Result<(PreparedCoordinatedSigningWalletV1,PreparedCoordinatedFinancialSpendV1,AuthenticatedFinancialContinuationHistoryV1,wholepact_authority::AuthenticatedWriterSession)>{
            read.check_current()?;
            check_wallet_context(&retained)?;
            let c=&retained.context;
            if read.presentation()!=&self.presentation || read.original_read_deadline()!=self.deadline
                || read.original_source_deadline()!=c.source.original_deadline()
                || read.original_service_deadline()!=retained.original_service_deadline
                || read.original_writer_session_deadline()!=retained.original_writer_session_deadline
            {return Err(Error::ReviewMismatch);}
            let host=c.original_peer.as_ref().ok_or(Error::Authentication)?;
            let(history,active,pin)=c.writer.as_ref().ok_or(Error::Unavailable)?.read_coordinated_sign_once_v1(
                &c.source,host,&retained.activated,&retained.receipt,&read)?;
            read.check_current()?;
            let(actual,spend)=wallet.take().ok_or(Error::Unavailable)?.prepare_sign_once_v1(&c.source,host,&pin,&read,
                Arc::clone(c.material.as_ref().ok_or(Error::Unavailable)?.verified()),&history,&active)?;
            read.check_current()?;
            check_wallet_context(&retained)?;
            Ok((actual,spend,history,active))
        })();
        match result {
            Ok((wallet,spend,history,active))=>Ok(PreparedCoordinatedSignOwnerV1{retained,wallet,spend,history,active,read,original,observed}),
            Err(error)=>Err(FailedCoordinatedSignV1{retained,observed_wallet:wallet,error,failure:SignerSignFailureV1{presentation_digest:self.presentation.presentation_digest,stage:SignerSignFailureStageV1::ReadFailed}}),
        }
    }
}
impl PreparedCoordinatedSignOwnerV1 {
    /// Main/control thread only. The actual live Read is CONSUMED by Origin's
    /// immutable Exact offer, not finished early and reconstructed from data.
    pub(in crate::native_ui::runtime) fn offer_sign_exact(self,origin:&mut SignerFinancialWorkflowOriginV1)->Result<PresentedCoordinatedSignExactV1>{
        self.read.check_current()?;
        let(deadline,reviewed_at_ms,expires_at_ms)=wallet_ceiling(&self.retained)?;
        let facts=self.spend.facts(reviewed_at_ms,expires_at_ms)?;
        self.read.check_current()?;
        let presentation=origin.offer_sign_exact(self.read,facts,deadline)?;
        let spend=self.spend.freeze_presentation(presentation.clone(),deadline)?;
        Ok(PresentedCoordinatedSignExactV1{retained:self.retained,wallet:self.wallet,spend,history:self.history,active:self.active,presentation,original:self.original,observed:self.observed})
    }
}
impl FailedCoordinatedSignV1 {
    pub(in crate::native_ui::runtime) fn report_failure(&self,origin:&mut SignerFinancialWorkflowOriginV1)->Result<()>{
        origin.report_sign_failure(self.failure.clone())?;Ok(())
    }
}
impl PresentedCoordinatedSignExactV1 {
    /// Worker only. All custody/effect outputs are retained before the main
    /// thread reports; neither transport failure nor R creates a retry branch.
    pub(in crate::native_ui::runtime) fn consume_final(self,action:SignerSignExactFinalV1)->CoordinatedSignCommitV1{
        let mut committed=None;
        let mut result_request=None;
        let mut report=None;
        let failure=SignerSignFailureV1{presentation_digest:self.presentation.presentation_digest.clone(),stage:SignerSignFailureStageV1::SignUncertain};
        let result=(||->Result<()>{
            action.check_current()?;
            check_wallet_context(&self.retained)?;
            if action.presentation()!=&self.presentation{return Err(Error::ReviewMismatch);}
            let c=&self.retained.context;
            let fixed=c.material.as_ref().ok_or(Error::Unavailable)?.verified().identity().clone();
            let account_id=c.terms.scope.authorization.identity.account_id.clone();
            let approved=self.spend.approve(action)?;
            let signed=self.wallet.sign_once_v1(c.writer.as_ref().ok_or(Error::Unavailable)?,c.original_peer.as_ref().ok_or(Error::Authentication)?,approved,&self.history,&self.active);
            let commit=match signed{
                Ok(commit)=>commit,
                Err(failed)=>{committed=failed.committed;return Err(Error::Uncertain);},
            };
            // No postcommit private reread or renewed lifetime is needed to
            // describe the actual retained output. These are immutable data.
            result_request=Some(FinancialResultRequestV1{account_id,authorization_id:commit.authorization_id.clone(),original_consent_ref:commit.original_consent_ref.clone(),fixed});
            let actual=SignerSignCommittedV1{sign_presentation_digest:self.presentation.presentation_digest.clone(),authorization_id:commit.authorization_id.clone(),
                original_consent_ref:commit.original_consent_ref.clone(),result_digest:commit.result_digest.clone(),outbox_digest:commit.outbox_digest.clone(),fixed_identity_digest:self.original.fixed_identity_digest.clone()};
            committed=Some(commit);
            actual.validate()?;
            report=Some(actual);
            Ok(())
        })();
        CoordinatedSignCommitV1{retained:self.retained,committed,result_request,report,error:result.err(),failure,original:self.original,observed:self.observed}
    }
}
impl CoordinatedSignCommitV1 {
    pub(in crate::native_ui::runtime) fn succeeded(&self)->bool{self.error.is_none()&&self.committed.is_some()&&self.report.is_some()&&self.result_request.is_some()}
    pub(in crate::native_ui::runtime) fn report(&self,origin:&mut SignerFinancialWorkflowOriginV1)->Result<()>{
        if self.succeeded(){origin.report_sign_committed(self.report.as_ref().ok_or(Error::Unavailable)?.clone())?;}
        else{origin.report_sign_failure(self.failure.clone())?;}
        Ok(())
    }
    pub(in crate::native_ui::runtime) fn into_result(mut self)->std::result::Result<AwaitingCoordinatedReturnReadV1,Self>{
        if !self.succeeded(){return Err(self);}
        // Presence established above; avoid any fallible drop after taking the
        // actual committed result. The kept object has no signing entry point.
        let (Some(committed),Some(result_request),Some(report))=(self.committed.take(),self.result_request.take(),self.report.take()) else {return Err(self);};
        self.retained.context.next=Next::Return;
        Ok(AwaitingCoordinatedReturnReadV1{selector_reported:false,retained:self.retained,committed,result_request,report,original:self.original,observed:self.observed})
    }
}

impl AwaitingCoordinatedReturnReadV1 {
    /// Emit only this retained successful result request. Origin supplies the
    /// genuine original endpoint and independently matches the reported Sign.
    /// This public metadata neither reads nor returns signature bytes.
    pub(in crate::native_ui::runtime) fn report_result_selector(
        &mut self, origin:&mut SignerFinancialWorkflowOriginV1,
    )->Result<()> {
        if self.selector_reported {return Ok(());}
        self.result_request.validate().map_err(|_|Error::InvalidData)?;
        if self.result_request.authorization_id!=self.report.authorization_id
            || self.result_request.original_consent_ref!=self.report.original_consent_ref
            || self.committed.result_digest!=self.report.result_digest
            || self.committed.outbox_digest!=self.report.outbox_digest
        {return Err(Error::ReviewMismatch);}
        let encoded=serde_json::to_string(&self.result_request).map_err(|_|Error::InvalidData)?;
        self.selector_reported=true;
        origin.report_financial_result_selector(encoded)?;
        Ok(())
    }
}
