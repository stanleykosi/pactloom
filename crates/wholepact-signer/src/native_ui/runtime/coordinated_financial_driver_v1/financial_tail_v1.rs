//! One owned worker at a time; original control Origin remains on its thread.
//! All results are genuine consuming owners, never report DTO importers.
use super::*;
use super::super::coordinated_continue::*;
use super::super::coordinated_admit::*;
use super::super::coordinated_admit::coordinated_writer_read::*;
use super::super::coordinated_admit::coordinated_writer_read::coordinated_financial_activate_v1::*;
use super::super::coordinated_admit::coordinated_writer_read::coordinated_financial_activate_v1::coordinated_financial_wallet_v1::*;
use super::super::coordinated_admit::coordinated_writer_read::coordinated_financial_activate_v1::coordinated_financial_wallet_v1::coordinated_financial_sign_v1::*;
use super::super::coordinated_admit::coordinated_writer_read::coordinated_financial_activate_v1::coordinated_financial_wallet_v1::coordinated_financial_sign_v1::coordinated_financial_return_v1::*;
use delivery::{DetachedCoordinatedFinancialHandoffV1,PresentedFinancialEntryRoleV1,OpenedFinancialEntryRoleV1,PreparedInitialFinancialReadRoleV1,PresentedInitialFinancialReadRoleV1};

pub(super) enum FinancialState {
    Detached(DetachedCoordinatedFinancialHandoffV1),
    Entry(PresentedFinancialEntryRoleV1), Opened(OpenedFinancialEntryRoleV1),
    InitialPrepared(PreparedInitialFinancialReadRoleV1), InitialRead(PresentedInitialFinancialReadRoleV1),
    ContinueInspected(InspectedCoordinatedContinueReadV1), ContinuePrepared(PreparedCoordinatedContinueRoleV1),
    ContinueReview(PreparedCoordinatedContinueRoleV1), ContinueReadyReport(ContinueReadyToReportV1),
    ContinueReady(PreparedCoordinatedContinueRoleV1), ContinueCommit(CoordinatedContinueCommitV1),
    AdmitInspected(InspectedCoordinatedAdmitV1), AdmitReview(PreparedCoordinatedAdmitRoleV1),
    AdmitReadyReport(AdmitReadyToReportV1), AdmitReady(ReadyCoordinatedAdmitRoleV1), AdmitCommit(CoordinatedAdmitCommitV1),
    WriterPrepared(PreparedCoordinatedWriterReadRoleV1), WriterRead(PresentedCoordinatedWriterReadRoleV1),
    AcquirePrepared(PreparedCoordinatedAcquireUnderReadV1), AcquireReview(PresentedCoordinatedAcquireReviewV1),
    AcquireReadyReport(AcquireReadyToReportV1), AcquireReady(ReadyCoordinatedAcquireV1), AcquireCommit(CoordinatedAcquireCommitV1),
    ActivateRead(PresentedCoordinatedActivateReadV1), ActivatePrepared(PreparedCoordinatedActivateUnderReadV1),
    ActivateReview(PresentedCoordinatedActivateV1), ActivateReadyReport(ActivateReadyToReportV1),
    ActivateReady(ReadyCoordinatedActivateV1), ActivateCommit(CoordinatedActivateCommitV1),
    WalletPrepare(PresentedCoordinatedWalletPrepareV1), WalletPrepared(UnreportedCoordinatedWalletPreparedV1),
    WalletObserve(PresentedCoordinatedWalletObserveV1), WalletObserved(UnreportedCoordinatedWalletObservedV1),
    WalletFailed(FailedCoordinatedWalletV1), AwaitingSign(AwaitingCoordinatedSignReadV1),
    SignRead(PresentedCoordinatedSignReadV1), SignPrepared(PreparedCoordinatedSignOwnerV1),
    SignExact(PresentedCoordinatedSignExactV1), SignCommit(CoordinatedSignCommitV1),
    SignFailed(FailedCoordinatedSignV1), AwaitingReturn(AwaitingCoordinatedReturnReadV1),
    ReturnRead(PresentedCoordinatedReturnReadV1), ReturnPrepared(UnreportedCoordinatedReturnPreparedV1),
    ReturnExact(PresentedCoordinatedReturnExactV1), Returned(CompletedCoordinatedReturnV1), ReturnFailed(FailedCoordinatedReturnV1), ReturnOfferFailed(FailedCoordinatedReturnOfferV1), ReturnReported(CompletedCoordinatedReturnV1),
    Working(FinancialWorker), Taken,
}
pub(super) struct FinancialWorker { handle:Option<std::thread::JoinHandle<Result<FinancialState>>> }
impl FinancialWorker {
    fn join(mut self)->Result<FinancialState> {self.handle.take().ok_or(Error::Unavailable)?.join().map_err(|_|Error::Uncertain)?}
}
impl Drop for FinancialWorker {fn drop(&mut self){if let Some(h)=self.handle.take(){let _=h.join();}}}
impl Driver {
    fn spawn_financial(&mut self,work:impl FnOnce()->Result<FinancialState>+Send+'static)->Result<()> {
        let handle=std::thread::Builder::new().name("original-financial-purpose".into()).spawn(work)?;
        self.state=State::Financial(FinancialState::Working(FinancialWorker{handle:Some(handle)}));Ok(())
    }
    pub(super) fn poll_financial(&mut self)->Result<()> {
        if matches!(&self.state,State::HistoryReturned(_)) && self.financial_setup.is_some() && self.financial_entry_requested {
            let State::HistoryReturned(actual)=std::mem::replace(&mut self.state,State::Taken) else {return Err(Error::Unavailable)};
            self.spawn_financial(move ||actual.into_financial_handoff().map(FinancialState::Detached))?;
        }
        if matches!(&self.state,State::Financial(FinancialState::Working(w)) if w.handle.as_ref().is_some_and(|h|h.is_finished())) {
            let State::Financial(FinancialState::Working(w))=std::mem::replace(&mut self.state,State::Taken) else {return Err(Error::Unavailable)};
            self.state=State::Financial(w.join()?);
        }
        if !matches!(&self.state,State::Financial(_)){return Ok(())}
        if let State::Financial(FinancialState::AwaitingReturn(actual))=&mut self.state {
            // Actual owner is stored before any fallible metadata observation.
            actual.report_result_selector(&mut self.origin)?;
        }
        if matches!(&self.state,State::Financial(FinancialState::AwaitingReturn(_))) {
            let event=self.financial_transport.as_ref().ok_or(Error::Unavailable)?.next_result()?;
            if let Some(event)=event {
                let transport=self.financial_transport.take().ok_or(Error::Unavailable)?;
                let State::Financial(FinancialState::AwaitingReturn(v))=std::mem::replace(&mut self.state,State::Taken) else {return Err(Error::Unavailable)};
                self.state=State::Financial(match v.offer_return_read(transport,event,&mut self.origin){Ok(actual)=>FinancialState::ReturnRead(actual),Err(failed)=>FinancialState::ReturnOfferFailed(failed)});
            }
        }
        // Store actual effect owners BEFORE fallible main-thread reports. On
        // report loss the state survives until R and joined disposal, no retry.
        match &self.state {
            State::Financial(FinancialState::ContinuePrepared(v))=>v.report_read(&mut self.origin)?,
            State::Financial(FinancialState::ContinueCommit(v))=>{v.report(&mut self.origin)?;if !v.succeeded(){return Err(Error::Uncertain)}},
            State::Financial(FinancialState::AdmitCommit(v))=>{v.report(&mut self.origin)?;if !v.succeeded(){return Err(Error::Uncertain)}},
            State::Financial(FinancialState::AcquireCommit(v))=>{v.report(&mut self.origin)?;if !v.succeeded(){return Err(Error::Uncertain)}},
            State::Financial(FinancialState::ActivateCommit(v))=>{v.report(&mut self.origin)?;if !v.succeeded(){return Err(Error::Uncertain)}},
            State::Financial(FinancialState::SignCommit(v))=>{v.report(&mut self.origin)?;if !v.succeeded(){return Err(Error::Uncertain)}},
            State::Financial(FinancialState::ReturnOfferFailed(_))=>return Err(Error::Uncertain),
            State::Financial(FinancialState::ReturnFailed(v))=>{v.report_failure(&mut self.origin)?;return Err(Error::Uncertain)},
            State::Financial(FinancialState::SignFailed(v))=>{v.report_failure(&mut self.origin)?;return Err(Error::Uncertain)},
            State::Financial(FinancialState::WalletFailed(v))=>{v.report_failure(&mut self.origin)?;return Err(Error::Uncertain)},
            _=>(),
        }
        let State::Financial(stage)=std::mem::replace(&mut self.state,State::Taken) else {
            // Do not disturb another profile's actual owner.
            return Err(Error::Unavailable);
        };
        let next=match stage {
            FinancialState::Detached(v)=>{
                let setup=self.financial_setup.take().ok_or(Error::Unavailable)?;
                let (entry,transport)=v.offer_entry(setup,&mut self.origin)?;
                if self.financial_transport.replace(transport).is_some(){return Err(Error::ReviewMismatch)}
                FinancialState::Entry(entry)
            },
            FinancialState::Opened(v)=>{
                self.state=State::Financial(FinancialState::Opened(v));
                self.origin.source_opened()?;
                let State::Financial(FinancialState::Opened(v))=std::mem::replace(&mut self.state,State::Taken) else {return Err(Error::Unavailable)};
                self.spawn_financial(move ||v.prepare_read().map(FinancialState::InitialPrepared))?;return Ok(())
            },
            FinancialState::InitialPrepared(v)=>FinancialState::InitialRead(v.offer(&mut self.origin)?),
            FinancialState::ContinueInspected(v)=>{
                let bound=v.begin_review(&mut self.origin)?;
                self.spawn_financial(move ||bound.prepare().map(FinancialState::ContinuePrepared))?;return Ok(())
            },
            FinancialState::ContinuePrepared(v)=>FinancialState::ContinueReview(v),
            FinancialState::ContinueReadyReport(v)=>FinancialState::ContinueReady(v.send_ready(&mut self.origin)?),
            FinancialState::ContinueCommit(v)=>{
                let actual=v.into_result().map_err(|_|Error::Uncertain)?;let deadline=self.origin.session_deadline();
                self.spawn_financial(move ||PreparedCoordinatedAdmitRoleV1::inspect(actual,deadline).map(FinancialState::AdmitInspected))?;return Ok(())
            },
            FinancialState::AdmitInspected(v)=>FinancialState::AdmitReview(v.offer(&mut self.origin)?),
            FinancialState::AdmitReadyReport(v)=>FinancialState::AdmitReady(v.send_ready(&mut self.origin)?),
            FinancialState::AdmitCommit(v)=>{
                let actual=v.into_result().map_err(|_|Error::Uncertain)?;let deadline=self.origin.session_deadline();
                self.spawn_financial(move ||PreparedCoordinatedWriterReadRoleV1::prepare(actual,deadline).map(FinancialState::WriterPrepared))?;return Ok(())
            },
            FinancialState::WriterPrepared(v)=>{
                let p=self.origin.offer_writer_read(v.facts().clone(),v.original_source_deadline(),v.original_read_deadline())?;
                FinancialState::WriterRead(v.freeze_presentation(p)?)
            },
            FinancialState::AcquirePrepared(v)=>FinancialState::AcquireReview(v.freeze_and_present(&mut self.origin)?),
            FinancialState::AcquireReadyReport(v)=>FinancialState::AcquireReady(v.send_ready(&mut self.origin)?),
            FinancialState::AcquireCommit(v)=>FinancialState::ActivateRead(v.into_result().map_err(|_|Error::Uncertain)?.offer_activate_read(&mut self.origin)?),
            FinancialState::ActivatePrepared(v)=>FinancialState::ActivateReview(v.freeze_and_present(&mut self.origin)?),
            FinancialState::ActivateReadyReport(v)=>FinancialState::ActivateReady(v.send_ready(&mut self.origin)?),
            FinancialState::ActivateCommit(v)=>FinancialState::WalletPrepare(v.into_result().map_err(|_|Error::Uncertain)?.offer_wallet_prepare(&mut self.origin)?),
            FinancialState::WalletPrepared(v)=>match v.report(&mut self.origin) {Ok(actual)=>FinancialState::WalletObserve(actual.offer_wallet_observe(&mut self.origin)?),Err(failed)=>FinancialState::WalletFailed(failed)},
            FinancialState::WalletObserved(v)=>match v.report(&mut self.origin) {Ok(actual)=>FinancialState::AwaitingSign(actual),Err(failed)=>FinancialState::WalletFailed(failed)},
            FinancialState::AwaitingSign(v)=>FinancialState::SignRead(v.offer_sign_read(&mut self.origin)?),
            FinancialState::SignPrepared(v)=>FinancialState::SignExact(v.offer_sign_exact(&mut self.origin)?),
            FinancialState::SignCommit(v)=>FinancialState::AwaitingReturn(v.into_result().map_err(|_|Error::Uncertain)?),
            FinancialState::ReturnPrepared(v)=>match v.offer_return_exact(&mut self.origin){Ok(actual)=>FinancialState::ReturnExact(actual),Err(failed)=>FinancialState::ReturnFailed(failed)},
            FinancialState::Returned(v)=>match v.report(&mut self.origin){Ok(actual)=>FinancialState::ReturnReported(actual),Err(failed)=>FinancialState::ReturnFailed(failed)},
            other=>other,
        };
        self.state=State::Financial(next);Ok(())
    }
    pub(super) fn handle_financial(&mut self,request:Request)->Result<()> {
        let State::Financial(stage)=std::mem::replace(&mut self.state,State::Taken) else {return Err(Error::ReviewMismatch)};
        match (stage,request) {
            (FinancialState::Entry(v),Request::SourceEntry{input,final_action})=>self.spawn_financial(move ||v.open(input,final_action).map(FinancialState::Opened)),
            (FinancialState::InitialRead(v),Request::InitialRead(action))=>self.spawn_financial(move ||{
                let v=v.read(action)?;
                PreparedCoordinatedContinueRoleV1::inspect_from_read_v2(v.original_peer,v.terms,v.material,v.writer_setup,v.wallet_setup,v.read).map(FinancialState::ContinueInspected)
            }),
            (FinancialState::ContinueReview(v),Request::ContinueRequested)=>{self.state=State::Financial(FinancialState::ContinueReview(v.send_continue_display_v1(&mut self.origin)?));Ok(())},
            (FinancialState::ContinueReview(v),Request::ContinueArm(arm))=>self.spawn_financial(move ||v.prepare_ready(arm).map(FinancialState::ContinueReadyReport)),
            (FinancialState::ContinueReady(v),Request::ContinueFinal(action))=>self.spawn_financial(move ||Ok(FinancialState::ContinueCommit(v.commit_final(action)))),
            (FinancialState::AdmitReview(v),Request::AdmitArm(arm))=>self.spawn_financial(move ||v.prepare_ready(arm).map(FinancialState::AdmitReadyReport)),
            (FinancialState::AdmitReady(v),Request::AdmitFinal(action))=>self.spawn_financial(move ||Ok(FinancialState::AdmitCommit(v.commit_final(action)))),
            (FinancialState::WriterRead(v),Request::WriterRead(action))=>self.spawn_financial(move ||v.read_and_prepare(action).map(FinancialState::AcquirePrepared)),
            (FinancialState::AcquireReview(v),Request::AcquireArm(arm))=>self.spawn_financial(move ||v.prepare_ready(arm).map(FinancialState::AcquireReadyReport)),
            (FinancialState::AcquireReady(v),Request::AcquireFinal(action))=>self.spawn_financial(move ||Ok(FinancialState::AcquireCommit(v.commit_final(action)))),
            (FinancialState::ActivateRead(v),Request::ActivateRead(action))=>self.spawn_financial(move ||v.read_and_prepare(action).map(FinancialState::ActivatePrepared)),
            (FinancialState::ActivateReview(v),Request::ActivateArm(arm))=>self.spawn_financial(move ||v.prepare_ready(arm).map(FinancialState::ActivateReadyReport)),
            (FinancialState::ActivateReady(v),Request::ActivateFinal(action))=>self.spawn_financial(move ||Ok(FinancialState::ActivateCommit(v.commit_final(action)))),
            (FinancialState::WalletPrepare(v),Request::WalletPrepare{final_action})=>self.spawn_financial(move ||Ok(match v.consume_final(final_action){Ok(actual)=>FinancialState::WalletPrepared(actual),Err(failed)=>FinancialState::WalletFailed(failed)})),
            (FinancialState::WalletObserve(v),Request::WalletObserve{final_action})=>self.spawn_financial(move ||Ok(match v.consume_final(final_action){Ok(actual)=>FinancialState::WalletObserved(actual),Err(failed)=>FinancialState::WalletFailed(failed)})),
            (FinancialState::SignRead(v),Request::SignRead{final_action})=>self.spawn_financial(move ||Ok(match v.consume_final(final_action){Ok(actual)=>FinancialState::SignPrepared(actual),Err(failed)=>FinancialState::SignFailed(failed)})),
            (FinancialState::SignExact(v),Request::SignExact{final_action})=>self.spawn_financial(move ||Ok(FinancialState::SignCommit(v.consume_final(final_action)))),
            (FinancialState::ReturnRead(v),Request::ReturnRead{final_action})=>self.spawn_financial(move ||Ok(match v.consume_final(final_action){Ok(actual)=>FinancialState::ReturnPrepared(actual),Err(failed)=>FinancialState::ReturnFailed(failed)})),
            (FinancialState::ReturnExact(v),Request::ReturnExact{final_action})=>self.spawn_financial(move ||Ok(match v.consume_final(final_action){Ok(actual)=>FinancialState::Returned(actual),Err(failed)=>FinancialState::ReturnFailed(failed)})),
            _=>Err(Error::ReviewMismatch),
        }
    }
}
