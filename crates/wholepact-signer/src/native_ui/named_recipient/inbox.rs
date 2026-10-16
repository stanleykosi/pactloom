//! Exact native intake and separate retained-file export. Network submission and
//! final signing have their own owners and cannot be invoked by this window.
use super::{
    input::read_selected_input,
    plan::{MAX_OWN_CONTEXT_BYTES, MAX_PLAN_BYTES, OriginalRequestPlan},
};
use crate::consent_journal::{
    LiveNamedRecipientProfile, NamedIntentExportTemplate, NamedRecipientOriginalInputs,
    PreparedNamedIntentFileExport, PreparedNamedRecipientOriginalImport, RetainedNamedIntentExport,
};
use crate::native_ui::{
    authority::ExactNativeReview,
    wallet_workspace::{NamedRecipientOwnerContext, NativeWalletWorkspace},
};
use crate::{Error, Result};
use eframe::egui;
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use wholepact_transport::{EncryptedEnvelope, MAX_FILE_BYTES, Timestamp};
use zeroize::{Zeroize, Zeroizing};

enum Operation {
    Original(Box<PreparedNamedRecipientOriginalImport>),
    Export(Box<PreparedNamedIntentFileExport>),
}
struct Pending {
    operation: Operation,
    review: ExactNativeReview,
    shown: u64,
    continued: Option<u64>,
}
#[derive(Default)]
pub(super) struct InboxWorkspace {
    plan_path: String,
    own_context_path: String,
    assertion_path: String,
    authorization_id: String,
    destination: String,
    pending: Option<Pending>,
    retained: Option<RetainedNamedIntentExport>,
    phrase: Zeroizing<String>,
    frame: u64,
    status: String,
}
fn now() -> Result<Timestamp> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Locked)?
        .as_secs();
    Timestamp::from_unix_seconds(i64::try_from(seconds).map_err(|_| Error::Locked)?)
        .map_err(|_| Error::Locked)
}
impl InboxWorkspace {
    pub(super) fn clear(&mut self) {
        self.pending = None;
        self.retained = None;
        self.phrase.zeroize();
    }
    fn original_owner<'a>(
        profile: &'a LiveNamedRecipientProfile,
        owner: &'a NamedRecipientOwnerContext<'a>,
    ) -> NamedRecipientOwnerContext<'a> {
        NamedRecipientOwnerContext {
            journal: owner.journal,
            session: owner.session,
            vault: owner.vault,
            authority: owner.authority,
            enrollment_ref: profile.enrollment_ref(),
            manifest_ref: profile.manifest_ref(),
        }
    }
    fn prepare_original(
        &mut self,
        profile: &LiveNamedRecipientProfile,
        owner: &NamedRecipientOwnerContext<'_>,
        wallet: Option<&NativeWalletWorkspace>,
        epoch: u64,
    ) -> Result<()> {
        self.clear();
        profile.check_current(owner.journal, owner.session)?;
        let plan_bytes =
            read_selected_input(owner.authority, Path::new(&self.plan_path), MAX_PLAN_BYTES)?;
        let plan = OriginalRequestPlan::decode(&plan_bytes)?;
        let context = read_selected_input(
            owner.authority,
            Path::new(&self.own_context_path),
            MAX_OWN_CONTEXT_BYTES,
        )?;
        let envelope_bytes = read_selected_input(
            owner.authority,
            Path::new(&self.assertion_path),
            MAX_FILE_BYTES,
        )?;
        let original_owner = Self::original_owner(profile, owner);
        let own_policy = wallet
            .ok_or(Error::Unavailable)?
            .named_recipient_policy_from_retained_selection(&original_owner, &context)?;
        let envelope = EncryptedEnvelope::from_bytes(envelope_bytes.to_vec())
            .map_err(|_| Error::InvalidData)?;
        let proposed = plan.original.with_local_expectations(&own_policy)?;
        let prepared = profile
            .prepare_original_import(
                owner.journal,
                owner.session,
                owner.vault,
                NamedRecipientOriginalInputs {
                    proposed,
                    own_policy,
                    proposed_policy: plan.proposed_offline_policy,
                    assertion_envelope: envelope,
                    outgoing: NamedIntentExportTemplate {
                        order: plan.intent_order,
                        purpose: plan.intent_purpose,
                        persistence_warning: plan.intent_persistence_warning,
                    },
                    now: now()?,
                },
            )
            .map_err(|_| Error::Verification)?;
        self.authorization_id = prepared.authorization_id().into();
        let review = ExactNativeReview::stage(
            owner.authority,
            prepared.digest(),
            prepared.display().into(),
            epoch,
        )?;
        self.pending = Some(Pending {
            operation: Operation::Original(Box::new(prepared)),
            review,
            shown: self.frame,
            continued: None,
        });
        Ok(())
    }
    fn prepare_export(&mut self, owner: &NamedRecipientOwnerContext<'_>, epoch: u64) -> Result<()> {
        let retained = self.retained.take().ok_or(Error::Unavailable)?;
        let prepared = retained
            .prepare_file_export(
                owner.journal,
                owner.session,
                owner.vault,
                Path::new(&self.destination),
            )
            .map_err(|_| Error::Verification)?;
        let review = ExactNativeReview::stage(
            owner.authority,
            prepared.digest(),
            prepared.display().into(),
            epoch,
        )?;
        self.pending = Some(Pending {
            operation: Operation::Export(Box::new(prepared)),
            review,
            shown: self.frame,
            continued: None,
        });
        Ok(())
    }
    pub(super) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        profile: &LiveNamedRecipientProfile,
        owner: &NamedRecipientOwnerContext<'_>,
        wallet: Option<&NativeWalletWorkspace>,
        focused: bool,
        epoch: u64,
    ) {
        if !focused
            || profile
                .check_display_association(owner.journal, owner.authority)
                .is_err()
        {
            self.clear();
            return;
        }
        self.frame = self.frame.saturating_add(1);
        if self.pending.as_ref().is_some_and(|p| p.review.expired()) {
            self.clear();
            self.status =
                "Review expired. Recover any committed request by its original authorization ID."
                    .into();
        }
        ui.collapsing("Import assertion and prepare original witness request", |ui| {
            ui.label("This request uses the explicitly selected verifier for peers and independently checks your own effects. The witness must separately authenticate enrollment and reserve exposure. This screen cannot sign or submit a transaction.");
            ui.label(&self.status);
            ui.label("Keep the original authorization ID before approval. Uncertain retention is recovered by this ID; never replace the request head, time or sequence.");
            ui.add(egui::TextEdit::singleline(&mut self.authorization_id).char_limit(160));
            if self.pending.is_none() {
                for (label, path) in [ ("Private request plan file", &mut self.plan_path), ("Private own action-context file", &mut self.own_context_path), ("Exact encrypted assertion file", &mut self.assertion_path) ] {
                    ui.label(label); ui.add(egui::TextEdit::singleline(path).char_limit(4096));
                }
                if ui.add_enabled(wallet.is_some(), egui::Button::new("Review first original request")).clicked_by(egui::PointerButton::Primary)
                    && self.prepare_original(profile, owner, wallet, epoch).is_err() {
                    self.status = "Request preparation rejected. Exact original records, retained local wallet selection, valid private files and matching pins are required.".into();
                }
                if ui.button("Recover exact retained original request").clicked_by(egui::PointerButton::Primary) {
                    self.retained = None;
                    match profile.recover_original_intent_export(owner.journal, owner.session, owner.vault, &self.authorization_id) {
                        Ok(Some(retained)) => { self.retained = Some(retained); self.status = "Original retained request recovered. Its original deadline and ciphertext are unchanged.".into(); },
                        Ok(None) => self.status = "No committed original was found for this ID. This does not establish that no external action occurred.".into(),
                        Err(_) => self.status = "Original recovery rejected. Preserve the journal and exact authorization ID.".into(),
                    }
                }
                if let Some(retained) = &self.retained {
                    ui.label(retained.display());
                    ui.label("New private output file, never overwritten. The courier includes your full own request and input identifiers for the online controller, plus encrypted intent bytes. It contains no assertion package or peer viewing key.");
                    ui.add(egui::TextEdit::singleline(&mut self.destination).char_limit(4096));
                    if ui.button("Review exact witness courier file").clicked_by(egui::PointerButton::Primary)
                        && self.prepare_export(owner, epoch).is_err() {
                        self.status = "Export preparation rejected. Recover the original request before retrying the exact destination review.".into();
                    }
                }
            } else {
                let pending = self.pending.as_mut().expect("pending checked");
                ui.label(pending.review.display());
                if !pending.review.confirming() {
                    if self.frame > pending.shown && ui.button("Continue exact request review").clicked_by(egui::PointerButton::Primary) {
                        if pending.review.continue_from_native_click(focused, epoch).is_ok() { pending.continued = Some(self.frame); }
                        else { self.clear(); }
                    }
                } else {
                    ui.label(format!("Type AUTHORIZE {}", &pending.review.digest()[..12]));
                    ui.add(egui::TextEdit::singleline(&mut *self.phrase).char_limit(128));
                    if ui.add_enabled(pending.continued.is_some_and(|f| self.frame > f), egui::Button::new("Approve this exact step")).clicked_by(egui::PointerButton::Primary) {
                        let pending = self.pending.take().expect("pending checked");
                        let result = (|| -> Result<()> {
                            let decision = pending.review.consume_native_click(focused, epoch, &self.phrase)?;
                            match pending.operation {
                                Operation::Original(prepared) => {
                                    self.retained = Some(prepared.approve(decision, owner.journal, owner.session, owner.vault, &now()?).map_err(|_| Error::Uncertain)?);
                                    self.status = "Exact original request retained. Review its exact courier file separately. No witness admission or signature is claimed.".into();
                                }
                                Operation::Export(prepared) => {
                                    prepared.write_new_file(decision, owner.journal, owner.session, owner.vault).map_err(|_| Error::Uncertain)?;
                                    self.status = "Exact witness courier file written. Submit only this original request through the configured witness owner.".into();
                                }
                            }
                            Ok(())
                        })();
                        self.phrase.zeroize();
                        if result.is_err() { self.retained = None; self.status = "This step did not establish success. Retention or file output may be incomplete; recover the original ID and inspect the exact destination before retrying. No automatic retry occurs.".into(); }
                    }
                }
            }
            if ui.button("Cancel request/export review").clicked_by(egui::PointerButton::Primary) { self.clear(); }
        });
    }
}
