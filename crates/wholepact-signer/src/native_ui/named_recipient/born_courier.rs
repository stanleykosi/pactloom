//! Separate native courier review. Remote submission is exact and may become
//! uncertain; recovery never reseals, reissues or changes an original request.
use super::input::read_selected_input;
use crate::consent_journal::{
    BornCourierActionV1, LiveNamedRecipientProfile, NamedRecipientOperation,
    PreparedBornDeliveryFileV1, PreparedBornIntentCourierV1, RetainedBornCourierDeliveryV1,
};
use crate::native_ui::{
    authority::ExactNativeReview, wallet_workspace::NamedRecipientOwnerContext,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{Error, Result};
use eframe::egui;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread::JoinHandle,
};
use zeroize::{Zeroize, Zeroizing};
enum Operation {
    Courier(Box<PreparedBornIntentCourierV1>),
    Export(Box<PreparedBornDeliveryFileV1>),
}
struct Pending {
    operation: Operation,
    review: ExactNativeReview,
    shown: u64,
    continued: Option<u64>,
}
enum Output {
    Review(Operation),
    Delivery(Box<RetainedBornCourierDeliveryV1>),
    Written,
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
            .name("wholepact-born-courier".into())
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
        self.thread.join().map_err(|_| Error::Uncertain)?;
        self.receive.try_recv().map_err(|_| Error::Uncertain)?
    }
}
#[derive(Default)]
pub(super) struct BornCourierWorkspace {
    handoff_path: String,
    destination: String,
    pending: Option<Pending>,
    delivery: Option<RetainedBornCourierDeliveryV1>,
    phrase: Zeroizing<String>,
    frame: u64,
    status: String,
    operation: Option<NamedRecipientOperation>,
    job: Option<Job>,
}
impl BornCourierWorkspace {
    pub(super) fn is_active(&self) -> bool {
        self.job.is_some() || self.pending.is_some()
    }
    pub(super) fn clear(&mut self) {
        if let Some(op) = &self.operation {
            op.revoke();
        }
        self.pending = None;
        self.delivery = None;
        self.phrase.zeroize();
        self.reap_cancelled();
    }
    pub(super) fn reap_cancelled(&mut self) {
        if self.operation.as_ref().is_some_and(|o| o.check().is_err())
            && self.job.as_ref().is_some_and(|j| j.thread.is_finished())
        {
            let _ = self.job.take().expect("finished").finish();
            self.operation = None;
        }
    }
    fn poll(&mut self, owner: &NamedRecipientOwnerContext<'_>, epoch: u64) -> Result<()> {
        self.reap_cancelled();
        if !self.job.as_ref().is_some_and(|j| j.thread.is_finished()) {
            return Ok(());
        }
        let job = self.job.take().expect("finished");
        if job.epoch != epoch || self.operation.as_ref().is_none_or(|o| o.check().is_err()) {
            let _ = job.finish();
            self.clear();
            return Err(Error::Locked);
        }
        match job.finish()? {
            Output::Review(operation) => {
                let (digest, display) = match &operation {
                    Operation::Courier(p) => (p.digest(), p.display()),
                    Operation::Export(p) => (p.digest(), p.display()),
                };
                self.pending = Some(Pending {
                    review: ExactNativeReview::stage(
                        owner.authority,
                        digest,
                        display.into(),
                        epoch,
                    )?,
                    operation,
                    shown: self.frame,
                    continued: None,
                });
            }
            Output::Delivery(delivery) => {
                self.status = delivery.display().into();
                self.delivery = Some(*delivery);
                self.operation = None;
            }
            Output::Written => {
                self.status="Exact original HPKE delivery file written. Recipient import/final approval remains separate; no signature or payment is claimed.".into();
                self.operation = None;
            }
        }
        Ok(())
    }
    fn prepare_courier(
        &mut self,
        profile: &LiveNamedRecipientProfile,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: &Arc<NativeWitnessWorkspace>,
        action: BornCourierActionV1,
        epoch: u64,
    ) -> Result<()> {
        witness.require_native_origin(&owner.authority.binding())?;
        let bytes = read_selected_input(
            owner.authority,
            Path::new(&self.handoff_path),
            2 * 1024 * 1024,
        )?;
        let profile = profile.clone();
        let journal = owner.journal.clone();
        let session = owner.session.clone();
        let witness = witness.clone();
        let op = NamedRecipientOperation::new();
        self.operation = Some(op.clone());
        self.job = Some(Job::start(epoch, move || {
            let prepared = profile
                .prepare_born_intent_courier(
                    &journal,
                    &session,
                    witness.client(),
                    &bytes,
                    action,
                    op,
                )
                .map_err(|_| Error::Verification)?;
            Ok(Output::Review(Operation::Courier(Box::new(prepared))))
        })?);
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
            self.status="Courier outcome is uncertain. Preserve the original handoff file and recover its original delivery; never submit a changed request or retry signing.".into();
        }
        if self.pending.as_ref().is_some_and(|p| p.review.expired())
            || self.operation.as_ref().is_some_and(|o| o.check().is_err())
        {
            self.clear();
        }
        ui.collapsing("Born account: courier exact original to its witness",|ui|{
   ui.label("Submit may reserve original exposure. Recovery only retrieves the already retained HPKE delivery. Neither step authorizes spending or makes a payment.");ui.label(&self.status);
   if self.job.is_some(){ui.label("Exact courier work running. Cancel may leave a committed remote request; use original recovery after an interruption.");ui.ctx().request_repaint_after(std::time::Duration::from_millis(50));}
   else if self.pending.is_none(){ui.label("Original born courier file, unchanged on every recovery");ui.add(egui::TextEdit::singleline(&mut self.handoff_path).char_limit(4096));
    for(label,action)in[("Review original born submission",BornCourierActionV1::SubmitOriginal),("Review recovery of original born delivery",BornCourierActionV1::RecoverOriginal)]{
     if ui.add_enabled(self.job.is_none()&&witness.is_some(),egui::Button::new(label)).clicked_by(egui::PointerButton::Primary)&&self.prepare_courier(profile,owner,witness.expect("enabled"),action,epoch).is_err(){self.clear();self.status="Courier review could not start. No new request was sent by this action.".into();}
    }
    ui.label("New private destination for exact encrypted admission bytes");ui.add(egui::TextEdit::singleline(&mut self.destination).char_limit(4096));
    if self.job.is_none()&&ui.add_enabled(self.delivery.is_some(),egui::Button::new("Review original encrypted delivery file")).clicked_by(egui::PointerButton::Primary){let retained=self.delivery.take().expect("enabled");let journal=owner.journal.clone();let session=owner.session.clone();let destination=PathBuf::from(&self.destination);let op=NamedRecipientOperation::new();self.operation=Some(op.clone());match Job::start(epoch,move||{let prepared=retained.prepare_file_export(&journal,&session,&destination,op).map_err(|_|Error::Verification)?;Ok(Output::Review(Operation::Export(Box::new(prepared))))}){Ok(job)=>self.job=Some(job),Err(_)=>{self.clear();self.status="Delivery export review could not start; recover the original witness ciphertext if needed.".into();}}}
   }else{let p=self.pending.as_mut().expect("pending");ui.label(p.review.display());if !p.review.confirming(){if self.frame>p.shown&&ui.button("Continue exact born courier review").clicked_by(egui::PointerButton::Primary){if p.review.continue_from_native_click(focused,epoch).is_ok(){p.continued=Some(self.frame);}else{self.clear();}}}else{
    ui.label(format!("Type AUTHORIZE {}",&p.review.digest()[..12]));ui.add(egui::TextEdit::singleline(&mut*self.phrase).char_limit(128));
    if ui.add_enabled(p.continued.is_some_and(|f|self.frame>f),egui::Button::new("Approve exact born courier step")).clicked_by(egui::PointerButton::Primary){let result=self.approve_pending(owner,witness,focused,epoch);if result.is_err(){self.clear();self.status="Courier step could not start. Preserve any prior request/delivery; no automatic retry.".into();}}
   }}
   if ui.button("Cancel born courier work").clicked_by(egui::PointerButton::Primary){self.clear();self.status="Cancelled. A sent request or partially written file can remain uncertain. Keep the original handoff and use exact recovery, never a new request.".into();}
  });
    }
}
impl Drop for BornCourierWorkspace {
    fn drop(&mut self) {
        if let Some(op) = &self.operation {
            op.revoke();
        }
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn cancel_is_immediate_and_original_worker_stays_tracked_until_finished() {
        let (release, wait) = mpsc::sync_channel(1);
        let operation = NamedRecipientOperation::new();
        let worker = operation.clone();
        let job = Job::start(1, move || {
            wait.recv().map_err(|_| Error::Uncertain)?;
            assert!(worker.check().is_err());
            Err(Error::Locked)
        })
        .unwrap();
        let mut state = BornCourierWorkspace::default();
        state.operation.replace(operation);
        state.job.replace(job);
        let start = std::time::Instant::now();
        state.clear();
        assert!(start.elapsed() < std::time::Duration::from_millis(250));
        assert!(state.job.is_some());
        release.send(()).unwrap();
        while !state.job.as_ref().unwrap().thread.is_finished() {
            std::thread::yield_now();
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
        }
        state.reap_cancelled();
        assert!(state.job.is_none());
        assert!(state.operation.is_none());
        assert!(state.pending.is_none());
    }
}

impl BornCourierWorkspace {
    fn approve_pending(
        &mut self,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: Option<&Arc<NativeWitnessWorkspace>>,
        focused: bool,
        epoch: u64,
    ) -> Result<()> {
        let p = self.pending.take().expect("pending");
        let result = (|| -> Result<()> {
            let decision = p
                .review
                .consume_native_click(focused, epoch, &self.phrase)?;
            let journal = owner.journal.clone();
            let session = owner.session.clone();
            let witness = witness.cloned();
            if matches!(&p.operation, Operation::Courier(_)) {
                witness
                    .as_ref()
                    .ok_or(Error::Unavailable)?
                    .require_native_origin(&owner.authority.binding())?;
            }
            self.job = Some(Job::start(epoch, move || match p.operation {
                Operation::Courier(p) => Ok(Output::Delivery(Box::new(
                    p.approve(
                        decision,
                        &journal,
                        &session,
                        witness.as_ref().ok_or(Error::Unavailable)?.client(),
                    )
                    .map_err(|_| Error::Uncertain)?,
                ))),
                Operation::Export(p) => {
                    p.write_new_file(decision, &journal, &session)
                        .map_err(|_| Error::Uncertain)?;
                    Ok(Output::Written)
                }
            })?);
            Ok(())
        })();
        self.phrase.zeroize();
        result
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "born_courier/synthetic_payment.rs"]
mod synthetic_payment;
