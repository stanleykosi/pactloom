//! Bounded same-H status sends never block the original control pump.
use super::*;
pub(super) enum StatusKind { Admit, Status, History(String) }
enum NextStatus { Restore, OfferAdmit, OfferAudit }
pub(super) struct StatusWorker {
    handle:Option<std::thread::JoinHandle<(Box<State>,Result<()>,NextStatus)>>,
}
impl Drop for StatusWorker {fn drop(&mut self){if let Some(h)=self.handle.take(){let _=h.join();}}}
impl Driver {
    pub(super) fn spawn_status(&mut self,peer:CoordinatedPairPeerV1,stream:std::os::unix::net::UnixStream,intent:String,nonce:String,deadline:Instant,kind:StatusKind)->Result<()> {
        let retained=Box::new(std::mem::replace(&mut self.state,State::Taken));
        let handle=std::thread::Builder::new().name("original-v3-status".into()).spawn(move || {
            let (result,next)=match (&*retained,kind) {
                (State::AdmissionPrepared(v),StatusKind::Admit)=>(v.acknowledge(peer,stream,intent,nonce,deadline),NextStatus::OfferAdmit),
                (State::AdmissionPrepared(v)|State::AdmissionReview(v),StatusKind::Status)=>(v.acknowledge(peer,stream,intent,nonce,deadline),NextStatus::Restore),
                (State::AdmissionAttempt(v)|State::AuditReview(v),StatusKind::Status)=>(v.respond(peer,stream,intent,nonce,deadline,None),NextStatus::Restore),
                (State::AdmissionAttempt(v),StatusKind::History(id))=>(v.respond(peer,stream,intent,nonce,deadline,Some(&id)),NextStatus::OfferAudit),
                (State::AuditReview(v),StatusKind::History(id))=>(v.respond(peer,stream,intent,nonce,deadline,Some(&id)),NextStatus::Restore),
                _=>(Err(Error::ReviewMismatch),NextStatus::Restore),
            }; (retained,result,next)
        })?;
        self.state=State::StatusWorking(StatusWorker{handle:Some(handle)});Ok(())
    }
    pub(super) fn poll_status(&mut self)->Result<()> {
        if !matches!(&self.state,State::StatusWorking(v) if v.handle.as_ref().is_some_and(|h|h.is_finished())){return Ok(())}
        let State::StatusWorking(mut worker)=std::mem::replace(&mut self.state,State::Taken) else {return Err(Error::Unavailable)};
        let (retained,result,next)=worker.handle.take().ok_or(Error::Unavailable)?.join().map_err(|_|Error::Uncertain)?;
        self.state=*retained;result?;
        match next {
            NextStatus::Restore=>(),
            NextStatus::OfferAdmit=>{
                let State::AdmissionPrepared(v)=std::mem::replace(&mut self.state,State::Taken) else {return Err(Error::Unavailable)};
                self.state=State::AdmissionReview(v);
                let State::AdmissionReview(v)=&self.state else {return Err(Error::Unavailable)};
                let (facts,deadline)=v.review()?;self.origin.offer_v3_admit(facts,deadline)?;
            },
            NextStatus::OfferAudit=>{
                let State::AdmissionAttempt(v)=std::mem::replace(&mut self.state,State::Taken) else {return Err(Error::Unavailable)};
                self.state=State::AuditReview(v);
                let State::AuditReview(v)=&self.state else {return Err(Error::Unavailable)};
                let (facts,deadline)=v.audit_review()?;self.origin.offer_v3_audit(facts,deadline)?;
            },
        }
        if let Some(request)=self.pending_status_control.take(){if !self.handle(request)?{return Err(Error::Locked)}}
        Ok(())
    }
}
