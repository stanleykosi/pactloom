//! Genuine native entry for a separate verifier profile. Imported claims never
//! create approval; every privileged step consumes an exact native decision.
use super::{
    request::RequestFile, ui::AssertionWorkspace, NativeAuthority, PreparedVerifierCreation,
    VerifierOwner,
};
use crate::{native_ui::authority::ExactNativeReview, Error, Result};
use eframe::egui;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};
enum Step {
    Create(PreparedVerifierCreation),
    Request(Box<RequestFile>),
}
struct Pending {
    exact: ExactNativeReview,
    step: Step,
    shown: u64,
    continued: Option<u64>,
}
pub(in crate::native_ui) struct SetupWorkspace {
    active: bool,
    path: String,
    password: Zeroizing<String>,
    filename: String,
    native: Option<NativeAuthority>,
    owner: Option<VerifierOwner>,
    pending: Option<Pending>,
    assertion: Option<AssertionWorkspace>,
    phrase: Zeroizing<String>,
    frame: u64,
    status: String,
}
impl Default for SetupWorkspace {
    fn default() -> Self {
        Self {
            active: false,
            path: String::new(),
            password: Zeroizing::new(String::new()),
            filename: String::new(),
            native: None,
            owner: None,
            pending: None,
            assertion: None,
            phrase: Zeroizing::new(String::new()),
            frame: 0,
            status: String::new(),
        }
    }
}
impl SetupWorkspace {
    #[cfg(test)]
    pub(in crate::native_ui) fn test_arm_inert_source(&mut self) -> super::NativeAuthorityBinding {
        self.begin();
        let native = crate::native_ui::authority::recovery_test_authority();
        let source = native.binding();
        self.native = Some(native);
        source
    }

    pub(in crate::native_ui) fn is_active(&self) -> bool {
        self.active
    }
    pub(in crate::native_ui) fn begin(&mut self) {
        self.clear();
        self.active = true;
        self.status="Optional named-verifier setup. Peers must explicitly approve their viewing disclosure; this identity cannot authorize payments.".into();
    }
    pub(in crate::native_ui) fn clear(&mut self) {
        self.pending = None;
        self.assertion = None;
        self.native = None;
        self.owner = None;
        self.password.zeroize();
        self.phrase.zeroize();
        self.active = false;
    }
    pub(in crate::native_ui) fn blur(&mut self) {
        if let Some(assertion) = &mut self.assertion {
            assertion.blur();
            self.pending = None;
            self.native = None;
            self.owner = None;
            self.password.zeroize();
            self.phrase.zeroize();
        } else {
            self.clear();
        }
    }
    pub(in crate::native_ui) fn poll_lifecycle(&mut self, focused: bool) {
        if !focused {
            self.blur();
        }
        if self
            .native
            .as_ref()
            .is_some_and(|n| n.check_current().is_err())
        {
            self.clear();
        }
    }
    fn stage_create(&mut self, epoch: u64) -> Result<()> {
        self.native = Some(NativeAuthority::entered_native_window()?);
        let native = self.native.as_ref().ok_or(Error::Locked)?;
        let prepared = PreparedVerifierCreation::prepare(Path::new(&self.path), native)?;
        let exact = ExactNativeReview::stage(native, prepared.digest(), prepared.display(), epoch)?;
        self.pending = Some(Pending {
            exact,
            step: Step::Create(prepared),
            shown: self.frame,
            continued: None,
        });
        Ok(())
    }
    fn open(&mut self) -> Result<()> {
        let native = NativeAuthority::entered_native_window()?;
        let owner = VerifierOwner::open(Path::new(&self.path), self.password.as_bytes(), &native)?;
        self.native = Some(native);
        self.owner = Some(owner);
        self.password.zeroize();
        Ok(())
    }
    fn stage_request(&mut self, epoch: u64) -> Result<()> {
        let owner = self.owner.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        let bytes = Zeroizing::new(owner.directory.read(&self.filename, 2 * 1024 * 1024)?);
        let request = RequestFile::parse(&bytes, &owner.public_key())?;
        let digest = request.digest()?;
        let display=format!("DISCLOSE EXACT REQUEST TO SELECTED INSTALLED SIGNERS\nVerifier key: {}\nOriginal request: {}\nOriginal artifact: {}\nOriginal validity: {} through {} (expiry exclusive)\nSelected endpoints/accounts: {}\nEach signer must independently approve its exact pairing and viewing disclosure. The imported claims confer no authority. This step may disclose the proposal, account identifiers, original artifact hash and verifier identity; no viewing keys are read from the request file. Final assertion signing requires separate exact native review.\nRequest commitment: {}",hex::encode(owner.public_key()),request.scopes[0].original_request_digest,request.scopes[0].original_artifact_digest,request.scopes[0].original_validity_not_before_ms,request.scopes[0].original_validity_expires_ms,request.scopes.iter().zip(&request.endpoints).map(|(s,e)|format!("{} -> {}",s.account_id,e)).collect::<Vec<_>>().join("; "),digest);
        let display = format!(
            "{display}\nExact proposal shared with these signers:\n{}",
            serde_json::to_string(&request.scopes[0].proposal).map_err(|_| Error::InvalidData)?
        );
        let exact = ExactNativeReview::stage(
            self.native.as_ref().ok_or(Error::Locked)?,
            &digest,
            display,
            epoch,
        )?;
        self.pending = Some(Pending {
            exact,
            step: Step::Request(Box::new(request)),
            shown: self.frame,
            continued: None,
        });
        Ok(())
    }
    fn consume(&mut self, focused: bool, epoch: u64) -> Result<()> {
        let pending = self.pending.take().ok_or(Error::Locked)?;
        let decision = pending
            .exact
            .consume_native_click(focused, epoch, &self.phrase)?;
        self.phrase.zeroize();
        match pending.step {
            Step::Create(prepared) => {
                self.owner = Some(prepared.create(
                    decision,
                    self.native.as_ref().ok_or(Error::Locked)?,
                    self.password.as_bytes(),
                )?);
                self.password.zeroize();
                self.status="Separate protected verifier identity created. No assertion has been issued or exported.".into();
            }
            Step::Request(request) => {
                let native = self.native.as_ref().ok_or(Error::Locked)?;
                let owner = self.owner.as_ref().ok_or(Error::Locked)?;
                let profile = owner.directory.root().to_path_buf();
                let approved =
                    super::handoff::ApprovedRequest::admit(*request, decision, native, owner)?;
                // Close/zeroize the actual profile owner and revoke its native key
                // authority before any peer pairing or external approval wait.
                self.owner.take();
                self.native.take();
                self.assertion = Some(AssertionWorkspace::start(profile, approved)?);
            }
        }
        Ok(())
    }
    pub(in crate::native_ui) fn ui(&mut self, ui: &mut egui::Ui, focused: bool, epoch: u64) {
        self.poll_lifecycle(focused);
        if !self.active {
            return;
        }
        self.frame = self.frame.saturating_add(1);
        if let Some(workspace) = &mut self.assertion {
            workspace.ui(ui, focused, epoch);
            if ui
                .button("Close named-verifier workspace")
                .clicked_by(egui::PointerButton::Primary)
            {
                self.clear();
            }
            return;
        }
        ui.heading("Optional named verifier");
        ui.label(&self.status);
        if self.pending.is_none() {
            if let Some(owner) = &self.owner {
                ui.label(format!(
                    "Exact verifier public key: {}",
                    hex::encode(owner.public_key())
                ));
                ui.label("Untrusted request filename inside this private verifier directory");
                ui.add(egui::TextEdit::singleline(&mut self.filename).char_limit(160));
                if ui
                    .button("Review imported exact request")
                    .clicked_by(egui::PointerButton::Primary)
                    && self.stage_request(epoch).is_err()
                {
                    self.status =
                        "Request rejected. No peer access or assertion was authorized.".into();
                }
            } else {
                ui.label("Separate private verifier directory");
                ui.add(egui::TextEdit::singleline(&mut self.path).char_limit(4096));
                ui.label("Verifier profile passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.password)
                        .password(true)
                        .char_limit(1024),
                );
                if ui
                    .button("Review creation of separate verifier identity")
                    .clicked_by(egui::PointerButton::Primary)
                    && self.stage_create(epoch).is_err()
                {
                    self.native = None;
                    self.status = "Creation review unavailable.".into();
                }
                if ui
                    .button("Unlock existing exact verifier profile")
                    .clicked_by(egui::PointerButton::Primary)
                {
                    self.status = if self.open().is_ok() {
                        "Existing profile authenticated; no assertion authorized."
                    } else {
                        "Profile could not be authenticated."
                    }
                    .into();
                    self.password.zeroize();
                }
            }
        }
        let mut consume = false;
        if let Some(pending) = &mut self.pending {
            ui.label(pending.exact.display());
            if pending.exact.expired() {
                self.clear();
                return;
            }
            if pending.continued.is_none() {
                if ui
                    .add_enabled(
                        self.frame > pending.shown,
                        egui::Button::new("Continue exact setup review"),
                    )
                    .clicked_by(egui::PointerButton::Primary)
                {
                    if pending
                        .exact
                        .continue_from_native_click(focused, epoch)
                        .is_err()
                    {
                        self.clear();
                        return;
                    }
                    pending.continued = Some(self.frame);
                }
            } else {
                ui.label(format!("Type AUTHORIZE {}", &pending.exact.digest()[..12]));
                ui.text_edit_singleline(&mut *self.phrase);
                consume = ui
                    .add_enabled(
                        pending.continued.is_some_and(|f| self.frame > f),
                        egui::Button::new("Authorize exact setup step"),
                    )
                    .clicked_by(egui::PointerButton::Primary);
            }
        }
        if consume && self.consume(focused, epoch).is_err() {
            self.clear();
            self.status="The exact step did not complete. A durable profile or assertion may exist; inspect its original journal before retrying.".into();
        }
        if ui
            .button("Close verifier setup")
            .clicked_by(egui::PointerButton::Primary)
        {
            self.clear();
        }
    }
}
impl Drop for SetupWorkspace {
    fn drop(&mut self) {
        self.clear();
    }
}
