//! Purpose-distinct born intake. Authenticated remote work stays off the event
//! thread, with nonrenewing cancellation and exact historical retry lookup.
use super::{
    born_plan::BornOriginalRequestPlan,
    input::read_selected_input,
    plan::{MAX_OWN_CONTEXT_BYTES, MAX_PLAN_BYTES},
};
use crate::consent_journal::{
    LiveNamedRecipientProfile, NamedRecipientOperation, PreparedBornNamedIntentFileExport,
    PreparedBornNamedRecipientOriginalImport, RetainedBornNamedIntentExport,
};
use crate::native_ui::{
    authority::ExactNativeReview,
    wallet_workspace::{NamedRecipientOwnerContext, NativeWalletWorkspace},
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{Error, Result};
use eframe::egui;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread::JoinHandle,
    time::{SystemTime, UNIX_EPOCH},
};
use wholepact_transport::{EncryptedEnvelope, MAX_FILE_BYTES, Timestamp};
use zeroize::{Zeroize, Zeroizing};
enum Operation {
    Original(Box<PreparedBornNamedRecipientOriginalImport>),
    Export(Box<PreparedBornNamedIntentFileExport>),
}
struct Pending {
    operation: Operation,
    review: ExactNativeReview,
    shown: u64,
    continued: Option<u64>,
}
enum Output {
    Review(Operation),
    Retained(Box<RetainedBornNamedIntentExport>),
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
            .name("wholepact-born-original".into())
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
pub(super) struct BornInboxWorkspace {
    plan_path: String,
    own_context_path: String,
    assertion_path: String,
    checkpoint_path: String,
    authorization: String,
    destination: String,
    pending: Option<Pending>,
    retained: Option<RetainedBornNamedIntentExport>,
    phrase: Zeroizing<String>,
    frame: u64,
    status: String,
    operation: Option<NamedRecipientOperation>,
    job: Option<Job>,
}
fn now() -> Result<Timestamp> {
    Timestamp::from_unix_seconds(
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Locked)?
                .as_secs(),
        )
        .map_err(|_| Error::Locked)?,
    )
    .map_err(|_| Error::Locked)
}
impl BornInboxWorkspace {
    pub(super) fn is_active(&self) -> bool {
        self.job.is_some() || self.pending.is_some()
    }
    pub(super) fn clear(&mut self) {
        if let Some(op) = &self.operation {
            op.revoke();
        }
        self.pending = None;
        self.retained = None;
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
                    Operation::Original(p) => (p.digest(), p.display()),
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
            Output::Retained(retained) => {
                self.authorization = retained.authorization_id().into();
                self.status = format!(
                    "Exact born original retained: {}. This is not admission or signing. Review its courier file separately.",
                    retained.original_ref()
                );
                self.retained = Some(*retained);
                self.operation = None;
            }
            Output::Completed(text) => {
                self.status = text;
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
        wallet: Option<&NativeWalletWorkspace>,
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
            self.status="Born intake did not establish success. Preserve the original authorization ID; inspect exact retained history before any retry.".into();
        }
        if self.pending.as_ref().is_some_and(|p| p.review.expired())
            || self.operation.as_ref().is_some_and(|o| o.check().is_err())
        {
            self.clear();
        }
        ui.collapsing("Born account: retain exact original and courier file",|ui|{
   ui.label("This separate route verifies your original born lineage, named-verifier setup and authenticated completed Host checkpoint. It never converts the account to legacy authority. No witness reservation or signature is created by intake.");ui.label(&self.status);
   if self.job.is_some(){ui.label("Checking the exact original. Cancel, blur or lock revokes continuation; an already committed original remains retained.");ui.ctx().request_repaint_after(std::time::Duration::from_millis(50));}
   else if self.pending.is_none(){
    for(label,value)in[("Born original plan file",&mut self.plan_path),("Own construction context file",&mut self.own_context_path),("Encrypted named assertion file",&mut self.assertion_path),("Authenticated Host checkpoint-origin file",&mut self.checkpoint_path)]{ui.label(label);ui.add(egui::TextEdit::singleline(value).char_limit(4096));}
    if ui.add_enabled(witness.is_some()&&(wallet.is_some()||{#[cfg(feature="pending-birth-owner-signing")]{owner.born.is_some()}#[cfg(not(feature="pending-birth-owner-signing"))]{false}}),egui::Button::new("Inspect exact born original")).clicked_by(egui::PointerButton::Primary){let result=(||->Result<()>{
     let witness=witness.ok_or(Error::Unavailable)?.clone();witness.require_native_origin(&owner.authority.binding())?;
     let plan=BornOriginalRequestPlan::decode(&read_selected_input(owner.authority,Path::new(&self.plan_path),MAX_PLAN_BYTES)?)?;
     let context=read_selected_input(owner.authority,Path::new(&self.own_context_path),MAX_OWN_CONTEXT_BYTES)?;
     let exact_owner=NamedRecipientOwnerContext{journal:owner.journal,session:owner.session,vault:owner.vault,authority:owner.authority,#[cfg(feature="pending-birth-owner-signing")]born:owner.born,enrollment_ref:profile.enrollment_ref(),manifest_ref:profile.manifest_ref()};
     let policy={
         #[cfg(feature="pending-birth-owner-signing")]
         if exact_owner.born.is_some(){exact_owner.born_own_policy(&context)?}else{wallet.ok_or(Error::Unavailable)?.named_recipient_policy_from_retained_selection(&exact_owner,&context)?}
         #[cfg(not(feature="pending-birth-owner-signing"))]
         {wallet.ok_or(Error::Unavailable)?.named_recipient_policy_from_retained_selection(&exact_owner,&context)?}
     };
     let encrypted=EncryptedEnvelope::from_bytes(read_selected_input(owner.authority,Path::new(&self.assertion_path),MAX_FILE_BYTES)?.to_vec()).map_err(|_|Error::InvalidData)?;
     let checkpoint=EncryptedEnvelope::from_bytes(read_selected_input(owner.authority,Path::new(&self.checkpoint_path),MAX_FILE_BYTES)?.to_vec()).map_err(|_|Error::InvalidData)?;
     let inputs=plan.with_local_expectations(policy,encrypted,checkpoint,now()?)?;self.authorization=inputs.original.proposed.terms.authorization_id.clone();
     let profile=profile.clone();let journal=owner.journal.clone();let session=owner.session.clone();let vault=owner.vault.clone();let op=NamedRecipientOperation::new();self.operation=Some(op.clone());
     self.job=Some(Job::start(epoch,move||{let p=profile.prepare_born_original_import(&journal,&session,&vault,witness.client(),inputs,op).map_err(|_|Error::Verification)?;Ok(Output::Review(Operation::Original(Box::new(p))))})?);Ok(())
    })();if result.is_err(){self.clear();self.status="Born original inspection could not start. No original was created.".into();}}
    ui.label("Original authorization ID for exact interrupted-intake recovery");ui.add(egui::TextEdit::singleline(&mut self.authorization).char_limit(160));
    if self.job.is_none()&&ui.button("Recover retained born original").clicked_by(egui::PointerButton::Primary){let profile=profile.clone();let journal=owner.journal.clone();let session=owner.session.clone();let vault=owner.vault.clone();let id=self.authorization.clone();let op=NamedRecipientOperation::new();self.operation=Some(op.clone());match Job::start(epoch,move||{op.check().map_err(|_|Error::Locked)?;let result=profile.recover_born_original_intent_export(&journal,&session,&vault,&id).map_err(|_|Error::Verification)?.ok_or(Error::Unavailable)?;op.check().map_err(|_|Error::Locked)?;Ok(Output::Retained(Box::new(result)))}){Ok(job)=>self.job=Some(job),Err(_)=>{self.clear();self.status="Original recovery could not start. Preserve the unchanged authorization ID.".into();}}}
    ui.label("New private destination for distinct born courier file");ui.add(egui::TextEdit::singleline(&mut self.destination).char_limit(4096));
    if self.job.is_none()&&ui.add_enabled(self.retained.is_some(),egui::Button::new("Review born courier file export")).clicked_by(egui::PointerButton::Primary){let retained=self.retained.take().expect("enabled");let journal=owner.journal.clone();let session=owner.session.clone();let vault=owner.vault.clone();let destination=PathBuf::from(&self.destination);let op=NamedRecipientOperation::new();self.operation=Some(op.clone());match Job::start(epoch,move||{let p=retained.prepare_file_export(&journal,&session,&vault,&destination,op).map_err(|_|Error::Verification)?;Ok(Output::Review(Operation::Export(Box::new(p))))}){Ok(job)=>self.job=Some(job),Err(_)=>{self.clear();self.status="Courier export review could not start. Recover the exact original again when ready.".into();}}}
   }else{
    let p=self.pending.as_mut().expect("pending");ui.label(p.review.display());if !p.review.confirming(){if self.frame>p.shown&&ui.button("Continue exact born review").clicked_by(egui::PointerButton::Primary){if p.review.continue_from_native_click(focused,epoch).is_ok(){p.continued=Some(self.frame);}else{self.clear();}}}else{
     ui.label(format!("Type AUTHORIZE {}",&p.review.digest()[..12]));ui.add(egui::TextEdit::singleline(&mut*self.phrase).char_limit(128));
     if ui.add_enabled(p.continued.is_some_and(|f|self.frame>f),egui::Button::new("Approve exact born intake step")).clicked_by(egui::PointerButton::Primary){let result=self.approve_pending(owner,witness,focused,epoch);if result.is_err(){self.clear();self.status="Born intake step could not start. Preserve any original retained state.".into();}}
    }
   }
   if ui.button("Cancel born intake work").clicked_by(egui::PointerButton::Primary){self.clear();self.status="Cancelled. Any earlier original or partially written file remains uncertain; preserve the original ID and recover, never reseal automatically.".into();}
  });
    }
}
impl Drop for BornInboxWorkspace {
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
        let mut state = BornInboxWorkspace::default();
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

impl BornInboxWorkspace {
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
            let vault = owner.vault.clone();
            let witness = witness.cloned();
            if matches!(&p.operation, Operation::Original(_)) {
                witness
                    .as_ref()
                    .ok_or(Error::Unavailable)?
                    .require_native_origin(&owner.authority.binding())?;
            }
            self.job = Some(Job::start(epoch, move || match p.operation {
                Operation::Original(p) => {
                    let out = p
                        .approve(
                            decision,
                            &journal,
                            &session,
                            &vault,
                            witness.as_ref().ok_or(Error::Unavailable)?.client(),
                            &now()?,
                        )
                        .map_err(|_| Error::Uncertain)?;
                    Ok(Output::Retained(Box::new(out)))
                }
                Operation::Export(p) => {
                    p.write_new_file(decision, &journal, &session, &vault)
                        .map_err(|_| Error::Uncertain)?;
                    Ok(Output::Completed("Original born courier file written unchanged. Submission, admission and signing remain separate.".into()))
                }
            })?);
            Ok(())
        })();
        self.phrase.zeroize();
        result
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "born_inbox/synthetic_payment.rs"]
mod synthetic_payment;
