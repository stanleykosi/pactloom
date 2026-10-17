//! Genuine native entry for a separate verifier profile. Imported claims never
//! create approval; every privileged step consumes an exact native decision.
use super::{
    NativeAuthority, PreparedVerifierCreation, VerifierOwner, request::RequestFile,
    ui::AssertionWorkspace,
};
use crate::{Error, Result, native_ui::authority::ExactNativeReview};
use eframe::egui;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};
enum Step {
    Create(PreparedVerifierCreation),
    Request(Box<RequestFile>),
    Transport(super::export_setup::PreparedTransportSetup),
    Pin(super::export::PreparedRecipientPin),
    Export(Box<super::export::PreparedAssertionExport>),
    Backup(Box<super::backup::PreparedBackup>),
    Restore(Box<super::backup::PreparedRestore>),
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
    row: String,
    recipient_key: String,
    backup_path: String,
    restore_source: String,
    restore_destination: String,
    backup_password: Zeroizing<String>,
    restore_password: Zeroizing<String>,
    native: Option<NativeAuthority>,
    owner: Option<VerifierOwner>,
    pending: Option<Pending>,
    assertion: Option<AssertionWorkspace>,
    phrase: Zeroizing<String>,
    frame: u64,
    status: String,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    synthetic_providers: Option<Vec<wholepact_signer_origin::InstalledSignerProvider>>,
}
impl Default for SetupWorkspace {
    fn default() -> Self {
        Self {
            active: false,
            path: String::new(),
            password: Zeroizing::new(String::new()),
            filename: String::new(),
            row: String::new(),
            recipient_key: String::new(),
            backup_path: String::new(),
            restore_source: String::new(),
            restore_destination: String::new(),
            backup_password: Zeroizing::new(String::new()),
            restore_password: Zeroizing::new(String::new()),
            native: None,
            owner: None,
            pending: None,
            assertion: None,
            phrase: Zeroizing::new(String::new()),
            frame: 0,
            status: String::new(),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            synthetic_providers: None,
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
        self.backup_password.zeroize();
        self.restore_password.zeroize();
        self.phrase.zeroize();
        self.active = false;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        { self.synthetic_providers = None; }
    }
    pub(in crate::native_ui) fn blur(&mut self) {
        if let Some(assertion) = &mut self.assertion {
            assertion.blur();
            self.pending = None;
            self.native = None;
            self.owner = None;
            self.password.zeroize();
            self.backup_password.zeroize();
            self.restore_password.zeroize();
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
        let display = format!(
            "DISCLOSE EXACT REQUEST TO SELECTED INSTALLED SIGNERS\nVerifier key: {}\nOriginal request: {}\nOriginal artifact: {}\nOriginal validity: {} through {} (expiry exclusive)\nSelected endpoints/accounts: {}\nEach signer must independently approve its exact pairing and viewing disclosure. The imported claims confer no authority. This step may disclose the proposal, account identifiers, original artifact hash and verifier identity; no viewing keys are read from the request file. Final assertion signing requires separate exact native review.\nRequest commitment: {}",
            hex::encode(owner.public_key()),
            request.scopes[0].original_request_digest,
            request.scopes[0].original_artifact_digest,
            request.scopes[0].original_validity_not_before_ms,
            request.scopes[0].original_validity_expires_ms,
            request
                .scopes
                .iter()
                .zip(&request.endpoints)
                .map(|(s, e)| format!("{} -> {}", s.account_id, e))
                .collect::<Vec<_>>()
                .join("; "),
            digest
        );
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
    fn stage_export_step(&mut self, operation: u8, epoch: u64) -> Result<()> {
        let owner = self.owner.as_mut().ok_or(Error::Locked)?;
        let (step, digest, display) = match operation {
            0 => {
                let p = owner.prepare_transport_setup()?;
                let d = p.digest().to_owned();
                let text = p.display().to_owned();
                (Step::Transport(p), d, text)
            }
            1 => {
                let key: [u8; 32] = hex::decode(&self.recipient_key)
                    .map_err(|_| Error::InvalidData)?
                    .try_into()
                    .map_err(|_| Error::InvalidData)?;
                let p = owner.prepare_recipient_pin(&self.row, key)?;
                let d = p.digest().to_owned();
                let text = p.display().to_owned();
                (Step::Pin(p), d, text)
            }
            2 => {
                let p = owner.prepare_assertion_export(&self.row)?;
                let d = p.digest().to_owned();
                let text = p.display().to_owned();
                (Step::Export(Box::new(p)), d, text)
            }
            _ => return Err(Error::InvalidData),
        };
        let exact = ExactNativeReview::stage(
            self.native.as_ref().ok_or(Error::Locked)?,
            &digest,
            display,
            epoch,
        )?;
        self.pending = Some(Pending {
            exact,
            step,
            shown: self.frame,
            continued: None,
        });
        Ok(())
    }
    fn stage_archive(&mut self, restore: bool, epoch: u64) -> Result<()> {
        if self.assertion.is_some() || self.pending.is_some() {
            return Err(Error::Locked);
        }
        let (step, digest, display) = if restore {
            if self.owner.is_some() {
                return Err(Error::Locked);
            }
            self.native = Some(NativeAuthority::entered_native_window()?);
            let native = self.native.as_ref().ok_or(Error::Locked)?;
            let result = super::backup::PreparedRestore::prepare(
                Path::new(&self.restore_source),
                Path::new(&self.restore_destination),
                self.backup_password.as_bytes(),
                native,
            );
            self.backup_password.zeroize();
            let prepared = result?;
            let digest = prepared.digest().to_owned();
            let display = prepared.display().to_owned();
            (Step::Restore(Box::new(prepared)), digest, display)
        } else {
            let native = self.native.as_ref().ok_or(Error::Locked)?;
            let prepared = self
                .owner
                .as_mut()
                .ok_or(Error::Locked)?
                .prepare_backup(Path::new(&self.backup_path), native)?;
            let digest = prepared.digest().to_owned();
            let display = prepared.display().to_owned();
            (Step::Backup(Box::new(prepared)), digest, display)
        };
        let exact = ExactNativeReview::stage(
            self.native.as_ref().ok_or(Error::Locked)?,
            &digest,
            display,
            epoch,
        )?;
        self.pending = Some(Pending {
            exact,
            step,
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
            Step::Transport(prepared) => {
                prepared.approve(self.owner.as_mut().ok_or(Error::Locked)?, decision)?;
                self.status =
                    "Independent transport mailbox ready. No recipient pin or export was approved."
                        .into();
            }
            Step::Pin(prepared) => {
                prepared.approve(self.owner.as_mut().ok_or(Error::Locked)?, decision)?;
                self.status="Exact recipient transport key retained. Export still requires a separate native decision.".into();
            }
            Step::Export(prepared) => {
                let filename =
                    prepared.approve(self.owner.as_mut().ok_or(Error::Locked)?, decision)?;
                self.status = format!(
                    "Exact encrypted assertion retained as {filename}. Delivery is unknown; no spending authority or settlement was created."
                );
            }
            Step::Backup(prepared) => {
                let result = (*prepared).approve(
                    self.owner.as_mut().ok_or(Error::Locked)?,
                    decision,
                    self.backup_password.as_bytes(),
                );
                self.backup_password.zeroize();
                result?;
                self.status = "Complete encrypted verifier/outbox pair saved. Keep all files together; restores are informational only.".into();
            }
            Step::Restore(prepared) => {
                let result = (*prepared).approve(decision, self.restore_password.as_bytes());
                self.restore_password.zeroize();
                self.backup_password.zeroize();
                self.native = None;
                result?;
                self.status = "Informational records restored. No live verifier, key use, assertion export or financial authority was activated.".into();
            }
            Step::Request(request) => {
                let native = self.native.as_ref().ok_or(Error::Locked)?;
                let owner = self.owner.as_ref().ok_or(Error::Locked)?;
                let profile = owner.directory.root().to_path_buf();
                let approved =
                    super::handoff::ApprovedRequest::admit(*request, decision, native, owner)?;
                #[cfg(feature = "synthetic-born-joined-qualification")]
                let approved = { let mut actual = approved; actual.synthetic_providers = self.synthetic_providers.take(); actual };
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
                if let Some(identity) = &owner.journal.export_identity {
                    if let Ok(key) =
                        wholepact_transport::TransportSecret::from_bytes(identity.secrets.transport)
                            .and_then(|s| s.public_key())
                    {
                        ui.label(format!(
                            "Independent transport public key: {} / fingerprint {}",
                            hex::encode(key.as_bytes()),
                            key.fingerprint()
                        ));
                    }
                }
                ui.label("Original retained signed row for export");
                ui.add(egui::TextEdit::singleline(&mut self.row).char_limit(64));
                ui.label("Independently verified recipient transport public key (hex)");
                ui.add(egui::TextEdit::singleline(&mut self.recipient_key).char_limit(64));
                for (operation, label) in [
                    (0, "Review independent transport setup"),
                    (1, "Review exact recipient pin"),
                    (2, "Review encrypted assertion export or exact retry"),
                ] {
                    if ui.button(label).clicked_by(egui::PointerButton::Primary)
                        && self.stage_export_step(operation, epoch).is_err()
                    {
                        self.status="Export step rejected. Preserve original records and inspect pending/uncertain state; no automatic retry or identity reset.".into();
                    }
                }
                ui.separator();
                ui.label("New private encrypted backup directory (absolute path)");
                ui.add(egui::TextEdit::singleline(&mut self.backup_path).char_limit(4096));
                ui.label("Separate backup passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.backup_password)
                        .password(true)
                        .char_limit(1024),
                );
                if ui
                    .button("Review complete encrypted verifier/outbox backup")
                    .clicked_by(egui::PointerButton::Primary)
                    && self.stage_archive(false, epoch).is_err()
                {
                    self.backup_password.zeroize();
                    self.status = "Backup review unavailable. Original Ready mailbox and exact source are required.".into();
                }
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
                ui.label("Informational restore never creates a live verifier");
                ui.label("Original complete backup directory");
                ui.add(egui::TextEdit::singleline(&mut self.restore_source).char_limit(4096));
                ui.label("New private informational destination");
                ui.add(egui::TextEdit::singleline(&mut self.restore_destination).char_limit(4096));
                ui.label("Original backup passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.backup_password)
                        .password(true)
                        .char_limit(1024),
                );
                ui.label("New informational-record passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.restore_password)
                        .password(true)
                        .char_limit(1024),
                );
                if ui
                    .button("Review exact informational restore")
                    .clicked_by(egui::PointerButton::Primary)
                    && self.stage_archive(true, epoch).is_err()
                {
                    self.native = None;
                    self.backup_password.zeroize();
                    self.restore_password.zeroize();
                    self.status = "Restore review rejected. Preserve all original backup pieces; no live profile was created.".into();
                }
                ui.separator();
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

#[cfg(test)]
mod backup_lifecycle_tests {
    use super::*;
    #[test]
    fn blur_clears_both_backup_passwords_and_revokes_setup_source() {
        let mut workspace = SetupWorkspace::default();
        let source = workspace.test_arm_inert_source();
        workspace.backup_password = Zeroizing::new("public-test-backup-input".into());
        workspace.restore_password = Zeroizing::new("public-test-restore-input".into());
        workspace.blur();
        assert!(workspace.backup_password.is_empty());
        assert!(workspace.restore_password.is_empty());
        assert!(!workspace.is_active());
        assert!(source.check_current().is_err());
    }
    #[test]
    fn cancel_clears_backup_restore_input_without_creating_an_owner() {
        let mut workspace = SetupWorkspace::default();
        let source = workspace.test_arm_inert_source();
        workspace.backup_password = Zeroizing::new("public-test-backup-input".into());
        workspace.restore_password = Zeroizing::new("public-test-restore-input".into());
        workspace.clear();
        assert!(workspace.backup_password.is_empty());
        assert!(workspace.restore_password.is_empty());
        assert!(workspace.owner.is_none() && workspace.pending.is_none());
        assert!(source.check_current().is_err());
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
pub(in crate::native_ui) mod synthetic_born_fixture;
