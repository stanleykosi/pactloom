//! Actual native review with revocable background preflight/key use. The event
//! thread never performs remote or database I/O for this final continuation.
use super::*;
use crate::consent_journal::{
    NamedRecipientOperation, PreparedNamedRecipientReturnFile, PreparedNamedRecipientSigning,
};
use crate::native_ui::witness_workspace::NativeWitnessWorkspace;
use std::{
    sync::{Arc, mpsc},
    thread::JoinHandle,
};
enum Operation {
    Sign(Box<PreparedNamedRecipientSigning>),
    Export(Box<PreparedNamedRecipientReturnFile>),
}
struct Pending {
    operation: Operation,
    review: ExactNativeReview,
    shown: u64,
    continued: Option<u64>,
}
enum Output {
    Review(Operation),
    Completed(String),
}
struct Job {
    receive: mpsc::Receiver<Result<Output>>,
    thread: JoinHandle<()>,
    epoch: u64,
}
impl Job {
    fn start(epoch: u64, work: impl FnOnce() -> Result<Output> + Send + 'static) -> Result<Self> {
        let (send, receive) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("wholepact-named-recipient-final".into())
            .spawn(move || {
                let _ = send.send(work());
            })?;
        Ok(Self {
            receive,
            thread,
            epoch,
        })
    }
    fn finish(self) -> Result<Output> {
        if self.thread.join().is_err() {
            return Err(Error::Uncertain);
        }
        self.receive.try_recv().map_err(|_| Error::Uncertain)?
    }
}
#[derive(Default)]
pub(super) struct SigningWorkspace {
    authorization: String,
    destination: String,
    pending: Option<Pending>,
    phrase: Zeroizing<String>,
    frame: u64,
    status: String,
    operation: Option<NamedRecipientOperation>,
    job: Option<Job>,
}
impl SigningWorkspace {
    pub(super) fn is_active(&self) -> bool {
        self.job.is_some() || self.pending.is_some()
    }
    pub(super) fn clear(&mut self) {
        if self.job.is_some() {
            self.status = "Final work cancelled. A previously Started operation or retained result remains uncertain; preserve the original authorization ID and never retry signing automatically.".into();
        } else if self.pending.is_some() {
            self.status = "Final review discarded without approving that step. Any earlier Started operation or result remains unchanged.".into();
        }
        if let Some(operation) = &self.operation {
            operation.revoke();
        }
        self.pending = None;
        self.phrase.zeroize();
        self.reap_cancelled();
    }
    /// Navigation/lock still poll cancelled jobs; no replacement worker is
    /// admitted until that exact thread has completed and been joined.
    pub(super) fn reap_cancelled(&mut self) {
        if self.operation.as_ref().is_some_and(|o| o.check().is_err())
            && self.job.as_ref().is_some_and(|j| j.thread.is_finished())
        {
            let _ = self.job.take().expect("finished job").finish();
            self.operation = None;
        }
    }
    fn poll(&mut self, owner: &NamedRecipientOwnerContext<'_>, epoch: u64) -> Result<()> {
        self.reap_cancelled();
        if !self.job.as_ref().is_some_and(|j| j.thread.is_finished()) {
            return Ok(());
        }
        let job = self.job.take().expect("finished job");
        if job.epoch != epoch || self.operation.as_ref().is_none_or(|o| o.check().is_err()) {
            let _ = job.finish();
            self.clear();
            return Err(Error::Locked);
        }
        match job.finish()? {
            Output::Review(operation) => {
                let (digest, display) = match &operation {
                    Operation::Sign(p) => (p.digest(), p.display()),
                    Operation::Export(p) => (p.digest(), p.display()),
                };
                let review =
                    ExactNativeReview::stage(owner.authority, digest, display.into(), epoch)?;
                self.pending = Some(Pending {
                    operation,
                    review,
                    shown: self.frame,
                    continued: None,
                });
            }
            Output::Completed(status) => {
                self.status = status;
                self.operation = None;
            }
        }
        Ok(())
    }
    pub(super) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        profile: &LiveNamedRecipientProfile,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: Option<&Arc<NativeWitnessWorkspace>>,
        focused: bool,
        epoch: u64,
    ) {
        if !focused || owner.authority.check_current().is_err() {
            self.clear();
            return;
        }
        self.frame = self.frame.saturating_add(1);
        if self.poll(owner, epoch).is_err() {
            self.clear();
            self.status="Final work did not establish success. Preserve the original ID; any Started or retained result remains authoritative uncertainty, never permission to re-sign.".into();
        }
        if self.pending.as_ref().is_some_and(|p| p.review.expired())
            || self.operation.as_ref().is_some_and(|o| o.check().is_err())
        {
            self.clear();
        }
        ui.collapsing("Finish an exact admitted named-mode original",|ui|{
            ui.label("Explicit named-verifier trust is required. This legacy-account route checks complete original witness history and a challenge-bound clock. Born accounts and sponsor policies remain unavailable here. Current chain validity and settlement are not established.");
            ui.label(&self.status);
            if self.job.is_some(){ui.label("Exact original work is running. Cancel, blur, lock or navigation revokes further key use; already started effects can remain uncertain.");ui.ctx().request_repaint_after(std::time::Duration::from_millis(50));}
            else if self.pending.is_none(){
                ui.label("Original authorization ID, unchanged after any interruption");ui.add(egui::TextEdit::singleline(&mut self.authorization).char_limit(160));
                if ui.add_enabled(witness.is_some(),egui::Button::new("Inspect original admission for final signing")).clicked_by(egui::PointerButton::Primary){
                    let result=(||->Result<()>{
                        let witness=witness.ok_or(Error::Unavailable)?.clone();witness.require_native_origin(&owner.authority.binding())?;
                        let profile=profile.clone();let journal=owner.journal.clone();let session=owner.session.clone();let vault=owner.vault.clone();let authorization=self.authorization.clone();
                        let operation=NamedRecipientOperation::new();self.operation=Some(operation.clone());
                        self.job=Some(Job::start(epoch,move||{
                            let prepared=profile.prepare_final_signing(&journal,&session,&vault,witness.client(),&authorization,operation).map_err(|_|Error::Verification)?;
                            Ok(Output::Review(Operation::Sign(Box::new(prepared))))
                        })?);Ok(())
                    })();if result.is_err(){self.clear();self.status="Final inspection could not start. No signature was released.".into();}
                }
                ui.label("Private new output file for the exact retained encrypted return");ui.add(egui::TextEdit::singleline(&mut self.destination).char_limit(4096));
                if self.job.is_none() && ui.button("Recover and review retained return file").clicked_by(egui::PointerButton::Primary){
                    let profile=profile.clone();let journal=owner.journal.clone();let session=owner.session.clone();let vault=owner.vault.clone();let authorization=self.authorization.clone();let path=std::path::PathBuf::from(&self.destination);
                    let operation=NamedRecipientOperation::new();self.operation=Some(operation.clone());
                    match Job::start(epoch,move||{
                        let prepared=profile.prepare_retained_return_file(&journal,&session,&vault,&authorization,&path,operation).map_err(|_|Error::Verification)?;
                        Ok(Output::Review(Operation::Export(Box::new(prepared))))
                    }){Ok(job)=>self.job=Some(job),Err(_)=>{self.clear();self.status="Return recovery could not start.".into();}}
                }
            } else {
                let p=self.pending.as_mut().expect("checked pending");ui.label(p.review.display());
                if !p.review.confirming(){
                    if self.frame>p.shown && ui.button("Continue exact final review").clicked_by(egui::PointerButton::Primary){
                        if p.review.continue_from_native_click(focused,epoch).is_ok(){p.continued=Some(self.frame);}else{self.clear();}
                    }
                }else{
                    ui.label(format!("Type AUTHORIZE {}",&p.review.digest()[..12]));ui.add(egui::TextEdit::singleline(&mut *self.phrase).char_limit(128));
                    if ui.add_enabled(p.continued.is_some_and(|frame|self.frame>frame),egui::Button::new("Approve this exact final step")).clicked_by(egui::PointerButton::Primary){
                        let p=self.pending.take().expect("checked pending");
                        let result=(||->Result<()>{
                            let decision=p.review.consume_native_click(focused,epoch,&self.phrase)?;
                            let journal=owner.journal.clone();let session=owner.session.clone();let vault=owner.vault.clone();let witness=witness.cloned();
                            if matches!(&p.operation,Operation::Sign(_)){witness.as_ref().ok_or(Error::Unavailable)?.require_native_origin(&owner.authority.binding())?;}
                            self.job=Some(Job::start(epoch,move||{
                                match p.operation {
                                    Operation::Sign(prepared)=>{
                                        let out=prepared.approve_and_sign(decision,&journal,&session,&vault,witness.as_ref().ok_or(Error::Unavailable)?.client()).map_err(|_|Error::Uncertain)?;
                                        Ok(Output::Completed(format!("Exact result and encrypted return retained. Authorization: {}. Original: {}. Signed artifact: {}. Return: {}. Review file delivery separately; no payment is claimed.",out.authorization_id,out.original_ref,out.result_digest,out.return_envelope_digest)))
                                    }
                                    Operation::Export(prepared)=>{prepared.write(decision,&journal,&session,&vault).map_err(|_|Error::Uncertain)?;Ok(Output::Completed("Original encrypted return written unchanged. Delivery, current online validation and payment remain separate.".into()))}
                                }
                            })?);Ok(())
                        })();self.phrase.zeroize();if result.is_err(){self.clear();self.status="Exact final work could not start. Preserve any original Started/result.".into();}
                    }
                }
            }
            if ui.button("Cancel final review or work").clicked_by(egui::PointerButton::Primary){self.clear();}
        });
    }
}
impl Drop for SigningWorkspace {
    fn drop(&mut self) {
        if let Some(operation) = &self.operation {
            operation.revoke();
        }
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;
    #[test]
    fn cancel_does_not_wait_for_a_blocked_worker_and_keeps_it_tracked() {
        let (release, wait) = mpsc::sync_channel(1);
        let operation = NamedRecipientOperation::new();
        let worker_operation = operation.clone();
        let mut ui = SigningWorkspace::default();
        ui.operation = Some(operation);
        ui.job = Some(
            Job::start(1, move || {
                wait.recv().map_err(|_| Error::Uncertain)?;
                assert!(worker_operation.check().is_err());
                Err(Error::Locked)
            })
            .unwrap(),
        );
        let start = std::time::Instant::now();
        ui.clear();
        assert!(start.elapsed() < std::time::Duration::from_millis(250));
        assert!(ui.job.is_some());
        release.send(()).unwrap();
        while !ui.job.as_ref().unwrap().thread.is_finished() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        ui.reap_cancelled();
        assert!(ui.job.is_none());
        assert!(ui.operation.is_none());
    }
}
