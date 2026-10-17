//! Native-only review surface for the owning assertion worker. It accepts no
//! serialized approval and exposes neither retained viewing keys nor signatures.
use super::{
    handoff::ApprovedRequest,
    worker::{Notice, Worker},
    NativeAuthority, VerifierOwner,
};
use crate::native_ui::authority::ExactNativeReview;
use crate::{Error, Result};
use eframe::egui;
use zeroize::{Zeroize, Zeroizing};
struct Review {
    exact: ExactNativeReview,
    shown: u64,
    continued: Option<u64>,
}
pub(super) struct AssertionWorkspace {
    native: Option<NativeAuthority>,
    profile: std::path::PathBuf,
    password: Zeroizing<String>,
    need_owner: bool,
    cancelled: bool,
    worker: Worker,
    review: Option<Review>,
    phrase: Zeroizing<String>,
    frame: u64,
    status: String,
}
impl AssertionWorkspace {
    /// Retains only the exact admitted request while peers receive focus.
    /// Every key phase requires a fresh native owner and exact decision.
    pub fn start(profile: std::path::PathBuf, approved: ApprovedRequest) -> Result<Self> {
        Ok(Self{native:None,profile,password:Zeroizing::new(String::new()),need_owner:false,cancelled:false,worker:Worker::start(approved)?,review:None,phrase:Zeroizing::new(String::new()),frame:0,status:"Approve pairing in the selected signer windows. Only the exact bounded key-free request remains admitted during peer focus.".into()})
    }
    pub fn blur(&mut self) {
        self.review = None;
        self.phrase.zeroize();
        self.password.zeroize();
        self.native.take();
        if !self.worker.lifetime.permits_peer_focus() {
            self.cancel();
            self.status="Verifier key phase cancelled by focus loss. Inspect the original journal; no authority is automatically renewed.".into();
        }
    }
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.need_owner = false;
        self.review = None;
        self.phrase.zeroize();
        self.password.zeroize();
        self.worker.cancel();
        // NativeAuthority::drop closes new publication admissions. An admitted
        // short commit may drain; cancellation does not prove no signature exists.
        self.native.take();
        self.status = "Cancelled. Work already started may have an unknown durable outcome; reopen the original journal, do not repeat it.".into();
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, focused: bool, epoch: u64) {
        if !focused {
            self.blur();
        }
        self.worker.reap();
        self.frame = self.frame.saturating_add(1);
        if let Some(native) = &self.native {
            if native.check_current().is_err() {
                self.cancel();
            }
        }
        while let Ok(notice) = self.worker.notices.try_recv() {
            if self.cancelled {
                continue;
            }
            match notice {
                Notice::NeedOwner => {
                    self.review = None;
                    self.native.take();
                    self.need_owner = true;
                    self.status="Return focus here and unlock the same original verifier profile. This does not approve key use; a separate exact review follows.".into();
                }
                Notice::PeerWait => {
                    self.review = None;
                    self.native.take();
                    self.need_owner = false;
                    self.status="Verifier signing keys have been dropped. Approve the exact viewing disclosures in the selected signer windows. Lock or Cancel still cancels this bounded request.".into();
                }
                Notice::Review { digest, display } => {
                    let exact = self.native.as_ref().ok_or(Error::Locked).and_then(|n| {
                        if self.review.is_some() {
                            return Err(Error::ReviewMismatch);
                        }
                        ExactNativeReview::stage(n, &digest, display.to_string(), epoch)
                    });
                    match exact {
                        Ok(exact) => {
                            self.review = Some(Review {
                                exact,
                                shown: self.frame,
                                continued: None,
                            })
                        }
                        Err(_) => self.cancel(),
                    }
                }
                Notice::Finished(result) => {
                    self.need_owner = false;
                    self.review = None;
                    self.phrase.zeroize();
                    self.status = match result {
                        Ok(row) => format!("Exact assertion retained in row {row}. No result was exported. Separate native disclosure is required."),
                        Err(Error::Uncertain) => "The original operation has an unknown outcome. Inspect its retained journal; never reset or repeat the request.".into(),
                        Err(_) => "Operation ended without a qualified completion report. Inspect the original journal before any further action.".into(),
                    };
                    self.native.take();
                }
            }
        }
        ui.label(&self.status);
        if self.need_owner {
            ui.label(format!(
                "Original verifier profile: {}\nExact selected key: {}",
                self.profile.display(),
                hex::encode(self.worker.key())
            ));
            ui.add(
                egui::TextEdit::singleline(&mut *self.password)
                    .password(true)
                    .char_limit(1024),
            );
            if ui
                .add_enabled(
                    focused,
                    egui::Button::new("Unlock original verifier for fresh review"),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                let result = (|| {
                    let native = NativeAuthority::entered_named_verifier_window(
                        self.worker.lifetime.deadline(),
                    )?;
                    let owner =
                        VerifierOwner::open(&self.profile, self.password.as_bytes(), &native)?;
                    self.worker.submit_owner(owner)?;
                    self.native = Some(native);
                    self.need_owner = false;
                    Ok::<_, Error>(())
                })();
                self.password.zeroize();
                if result.is_err() {
                    self.cancel();
                }
            }
        }

        let mut consume = false;
        if let Some(review) = &mut self.review {
            ui.label(review.exact.display());
            if review.exact.expired() {
                self.cancel();
                return;
            }
            if review.continued.is_none() {
                if ui
                    .add_enabled(
                        focused && self.frame > review.shown,
                        egui::Button::new("Continue exact verifier review"),
                    )
                    .clicked()
                {
                    if review
                        .exact
                        .continue_from_native_click(focused, epoch)
                        .is_ok()
                    {
                        review.continued = Some(self.frame);
                    } else {
                        self.cancel();
                        return;
                    }
                }
            } else {
                ui.label(format!("Type AUTHORIZE {}", &review.exact.digest()[..12]));
                ui.text_edit_singleline(&mut *self.phrase);
                consume = ui
                    .add_enabled(
                        focused && review.continued.is_some_and(|f| self.frame > f),
                        egui::Button::new("Authorize this exact step"),
                    )
                    .clicked();
            }
        }
        if consume {
            if let Some(review) = self.review.take() {
                let decision = review
                    .exact
                    .consume_native_click(focused, epoch, &self.phrase);
                self.phrase.zeroize();
                if decision.and_then(|d| self.worker.decide(d)).is_err() {
                    self.cancel();
                }
            }
        }
        if ui.button("Cancel verifier work").clicked() {
            self.cancel();
        }
    }
}
impl Drop for AssertionWorkspace {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
mod synthetic_born_assertion;
