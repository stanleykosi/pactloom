use super::{
    pairing::PairingState,
    state::{self, Phase, ReviewState, SurfaceMode},
    transaction::TransactionReview,
};
use crate::Result;
use eframe::egui::{self, Color32, RichText, Vec2};
use zeroize::{Zeroize, Zeroizing};

const BACKGROUND: Color32 = Color32::from_rgb(15, 22, 29);
const PANEL: Color32 = Color32::from_rgb(24, 34, 43);
const MINT: Color32 = Color32::from_rgb(128, 230, 183);
const MUTED: Color32 = Color32::from_rgb(162, 178, 188);
const AMBER: Color32 = Color32::from_rgb(247, 197, 111);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Review,
    Accounts,
    Applications,
    Security,
}
pub(super) struct Window {
    mode: SurfaceMode,
    page: Page,
    review: ReviewState,
    transaction: TransactionReview,
    pairing: PairingState,
    native: super::runtime::NativeRuntime,
    focus_epoch: u64,
    imported: Zeroizing<String>,
    account: String,
    client: String,
    confirmation: Zeroizing<String>,
    understood: bool,
    error: Option<&'static str>,
    focused_last: bool,
}
impl Window {
    pub(super) fn new(
        mode: SurfaceMode,
        parent_channel: Option<crate::native_launch::ParentChannel>,
    ) -> Result<Self> {
        Ok(Self {
            mode,
            page: Page::Review,
            review: ReviewState::new(mode)?,
            transaction: TransactionReview::new()?,
            pairing: PairingState::new(),
            native: super::runtime::NativeRuntime::new(parent_channel),
            focus_epoch: 0,
            imported: Zeroizing::new(String::new()),
            account: "account-alice".into(),
            client: "locally-imported-manifest".into(),
            confirmation: Zeroizing::new(String::new()),
            understood: false,
            error: None,
            focused_last: false,
        })
    }
    fn discard(&mut self) {
        self.native.lock();
        self.focus_epoch = self.focus_epoch.saturating_add(1);
        self.review.invalidate();
        self.transaction.invalidate();
        self.pairing.lock();
        self.imported.zeroize();
        self.confirmation.zeroize();
        self.understood = false;
        self.error = None;
    }
    fn blur(&mut self) {
        self.native.blur();
        self.focus_epoch = self.focus_epoch.saturating_add(1);
        self.review.invalidate();
        self.transaction.invalidate();
        // Rehearsal grants are UI state, never production disclosure leases.
        self.pairing.lock();
        self.imported.zeroize();
        self.confirmation.zeroize();
        self.understood = false;
        self.error = None;
    }
    fn navigate(&mut self, next: Page) {
        if self.page != next {
            self.native.navigate();
            self.focus_epoch = self.focus_epoch.saturating_add(1);
            self.review.invalidate();
            self.transaction.invalidate();
            self.pairing.cancel();
            self.confirmation.zeroize();
            self.understood = false;
            self.error = None;
            self.page = next;
        }
    }
    fn load_demo(&mut self) {
        self.confirmation.zeroize();
        self.understood = false;
        self.error = None;
        self.client = "synthetic-workspace".into();
        self.account = "account-alice".into();
        if self
            .review
            .stage(&state::demo_manifest(), &self.account, &self.client)
            .is_err()
        {
            self.error = Some("The synthetic manifest did not pass local validation.");
        }
    }
    #[cfg(feature = "synthetic-qualification")]
    fn load_transaction_demo(&mut self) {
        self.review.invalidate();
        self.transaction.invalidate();
        self.confirmation.zeroize();
        self.understood = false;
        self.error = crate::review::PreparedReview::synthetic_preview()
            .and_then(|review| self.transaction.stage(review.into_inspection()))
            .err()
            .map(|_| "Synthetic transaction verification failed. No review was retained.");
    }
    fn banner(&self, ui: &mut egui::Ui) {
        egui::Frame::new().fill(Color32::from_rgb(55, 44, 25)).inner_margin(14).corner_radius(8).show(ui, |ui| {
            ui.label(RichText::new(if self.mode == SurfaceMode::SyntheticDemo {
                "SYNTHETIC DEMO  ·  No keys, accounts, IPC grants or signatures"
            } else {
                "PRE-RELEASE REVIEW  ·  Runtime security profile is not qualified"
            }).color(AMBER).strong());
            ui.label("A review acknowledgment records application terms for this window only. It does not authorize a payment or prove who launched this window.");
        });
    }
    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.label(RichText::new("wholepact").size(28.0).strong().color(MINT));
        ui.label(RichText::new("SIGNER COMPANION").size(11.0).color(MUTED));
        ui.add_space(30.0);
        for (page, label) in [
            (Page::Review, "01   Review a proposal"),
            (Page::Accounts, "02   Dedicated accounts"),
            (Page::Applications, "03   Paired applications"),
            (Page::Security, "04   Security profile"),
        ] {
            if ui
                .add_sized(
                    [210.0, 42.0],
                    egui::Button::selectable(self.page == page, label),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                self.navigate(page);
            }
            ui.add_space(5.0);
        }
        ui.add_space(28.0);
        ui.separator();
        ui.add_space(14.0);
        ui.label(
            RichText::new("Your part. Exact terms.")
                .color(MINT)
                .strong(),
        );
        ui.label(RichText::new("The coordinator cannot approve for you.\n\nEvery account stays separate. Every new proposal needs a new review.").color(MUTED).size(12.0));
        ui.add_space(28.0);
        if ui
            .add_sized(
                [210.0, 36.0],
                egui::Button::new("Lock & clear this session"),
            )
            .clicked_by(egui::PointerButton::Primary)
        {
            self.discard();
        }
        ui.label(
            RichText::new("Focus loss locks the native account and discards pending reviews and current grants.")
                .color(MUTED)
                .size(11.0),
        );
    }
    fn review_page(&mut self, ui: &mut egui::Ui) {
        heading(ui, "Review the whole arrangement", "See exact recipients, contribution caps, fees and disclosure before acknowledging terms.");
        self.banner(ui);
        ui.add_space(20.0);
        if self.transaction.phase() != Phase::Idle {
            self.transaction_page(ui);
            return;
        }
        match self.review.phase() {
            Phase::Idle | Phase::Rejected => self.import_page(ui),
            Phase::Reading => self.reading_page(ui),
            Phase::Confirming => self.confirm_page(ui),
            Phase::Accepted => self.receipt_page(ui),
        }
        if let Some(error) = self.error {
            ui.add_space(10.0);
            ui.colored_label(AMBER, error);
        }
    }
    fn import_page(&mut self, ui: &mut egui::Ui) {
        if self.review.phase() == Phase::Rejected {
            ui.colored_label(MINT, "Review declined. No acknowledgment was retained.");
        }
        card(ui, |ui| {
            ui.label(
                RichText::new("Start with a public synthetic example")
                    .size(18.0)
                    .strong(),
            );
            ui.label("Two fabricated contributors, one fabricated recipient, explicit return amounts and fee shares. No cryptographic or on-chain verification is claimed.");
            ui.add_space(12.0);
            if primary(ui, "Open synthetic proposal").clicked_by(egui::PointerButton::Primary) {
                self.load_demo();
            }
        });
        #[cfg(feature = "synthetic-qualification")]
        if self.mode == SurfaceMode::SyntheticDemo {
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.label(RichText::new("Inspect a real-library synthetic transaction").strong());
                ui.label("Independently verifies a fixed public PCZT: recipients, values, owned returns, fees and effects. No live account, network, proof, signature or payment is used.");
                if primary(ui, "Open cryptographic transaction review")
                    .clicked_by(egui::PointerButton::Primary)
                {
                    self.load_transaction_demo();
                }
            });
        }
        if self.mode != SurfaceMode::SyntheticDemo {
            ui.add_space(16.0);
            egui::CollapsingHeader::new("Inspect a local application manifest").show(ui, |ui| {
                ui.label("Paste a ProposalInput JSON object. Do not paste seeds, passwords, spending keys, viewing keys or private PCZT witnesses. Maximum 128 KiB.");
                ui.horizontal(|ui| { ui.label("Account scope"); ui.add(egui::TextEdit::singleline(&mut self.account).char_limit(128)); });
                ui.horizontal(|ui| { ui.label("Source label (unverified)"); ui.add(egui::TextEdit::singleline(&mut self.client).char_limit(128)); });
                ui.add(egui::TextEdit::multiline(&mut *self.imported).desired_rows(7).desired_width(f32::INFINITY).char_limit(131_072).code_editor());
                if ui.button("Validate and open complete terms").clicked_by(egui::PointerButton::Primary) {
                    self.confirmation.zeroize();
                    self.understood = false;
                    self.error = self.review.stage(self.imported.as_bytes(), &self.account, &self.client).err().map(|_| "Manifest rejected. Check its schema, exact accounting and account scope. No partial review was accepted.");
                    self.imported.zeroize();
                }
            });
        }
    }
    fn reading_page(&mut self, ui: &mut egui::Ui) {
        let Some(proposal) = self.review.proposal() else {
            return;
        };
        let manifest = proposal.manifest();
        ui.horizontal(|ui| {
            badge(ui, "1 / 2  READ EXACT TERMS", MINT);
            ui.label(format!("Revision {}", manifest.agreement.revision));
        });
        ui.add_space(12.0);
        card(ui, |ui| {
            ui.label(
                RichText::new(state::inert_text(&manifest.agreement.purpose))
                    .size(20.0)
                    .strong(),
            );
            field(ui, "Agreement", &manifest.agreement.agreement_id);
            field(ui, "Obligation", &manifest.agreement.obligation_id);
            field(ui, "Proposal", &proposal.input().proposal_id);
            field(
                ui,
                "Network profile",
                &manifest.agreement.network_profile_id,
            );
            field(
                ui,
                "Transaction fee",
                &format!("{} zatoshis", manifest.transaction_fee),
            );
            field(ui, "Expiry height", &manifest.expiry_height.to_string());
            ui.add_space(10.0);
            for owner in &manifest.participants {
                ui.label(
                    RichText::new(format!(
                        "{}  ·  {}",
                        state::inert_text(&owner.participant_id),
                        state::inert_text(&owner.account_id)
                    ))
                    .strong(),
                );
                ui.label(format!(
                    "Contribution {}  +  fee {}  |  maximum net debit {} zatoshis",
                    owner.contribution, owner.fee_share, owner.maximum_net_debit
                ));
            }
        });
        ui.add_space(14.0);
        ui.label(
            RichText::new("Recipients & full immutable manifest")
                .size(17.0)
                .strong(),
        );
        ui.label(RichText::new("Recipient provenance, account ownership, real identities, wallet inputs and chain freshness remain unverified. Read the whole text, including privacy, memos and returns.").color(AMBER));
        egui::ScrollArea::vertical()
            .id_salt("complete-manifest")
            .max_height(235.0)
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(self.review.exact_text().unwrap_or(""))
                            .monospace()
                            .size(12.0),
                    )
                    .wrap(),
                );
            });
        ui.add_space(8.0);
        ui.label(
            RichText::new(format!("Manifest digest: {}", proposal.manifest_digest()))
                .monospace()
                .size(11.0),
        );
        ui.horizontal(|ui| {
            if primary(ui, "Continue to acknowledgment").clicked_by(egui::PointerButton::Primary) {
                self.error = self
                    .review
                    .continue_from_local_click()
                    .err()
                    .map(|_| "This review expired or lost focus. Open it again.");
                self.confirmation.zeroize();
                self.understood = false;
            }
            if ui
                .button("Decline")
                .clicked_by(egui::PointerButton::Primary)
            {
                self.review.reject();
            }
        });
    }
    fn confirm_page(&mut self, ui: &mut egui::Ui) {
        let Some(proposal) = self.review.proposal() else {
            return;
        };
        let phrase = state::confirmation_phrase(proposal.manifest_digest());
        let proposal_id = proposal.input().proposal_id.clone();
        let manifest_digest = proposal.manifest_digest().to_string();
        badge(ui, "2 / 2  EXPLICIT ACKNOWLEDGMENT", MINT);
        ui.add_space(16.0);
        card(ui, |ui| {
            ui.label(
                RichText::new("Accept these exact application terms?")
                    .size(23.0)
                    .strong(),
            );
            field(ui, "Account scope", &self.account);
            field(ui, "Source label (unverified)", &self.client);
            field(ui, "Proposal", &proposal_id);
            field(ui, "Manifest digest", &manifest_digest);
            field(
                ui,
                "One-session exact binding",
                self.review.binding().as_deref().unwrap_or(""),
            );
            ui.add_space(16.0);
            ui.checkbox(&mut self.understood, "I understand this is a local terms acknowledgment. It does not sign, authorize disclosure, establish identity, reserve funds or promise settlement.");
            ui.add_space(16.0);
            ui.label(format!("Type {phrase} to confirm the reviewed context."));
            ui.add(
                egui::TextEdit::singleline(&mut *self.confirmation)
                    .hint_text("ACCEPT followed by the 8 characters above")
                    .desired_width(400.0)
                    .char_limit(64),
            );
            ui.label(RichText::new("The phrase is not an authentication credential. A different proposal needs a new review.").color(MUTED).size(12.0));
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(self.understood && *self.confirmation == phrase && self.review.focused(), egui::Button::new("Acknowledge exact terms").fill(MINT)).clicked_by(egui::PointerButton::Primary) {
                    self.error = self.review.confirm_from_local_click(&self.confirmation, self.understood).err().map(|_| "Acknowledgment rejected because its exact review context changed or expired.");
                    self.confirmation.zeroize();
                    self.understood = false;
                }
                if ui.button("Cancel review").clicked_by(egui::PointerButton::Primary) {
                    self.review.reject();
                    self.confirmation.zeroize();
                    self.understood = false;
                }
            });
        });
    }
    fn receipt_page(&mut self, ui: &mut egui::Ui) {
        let Some(receipt) = self.review.receipt() else {
            return;
        };
        card(ui, |ui| {
            badge(
                ui,
                if receipt.demo {
                    "SYNTHETIC ACKNOWLEDGMENT"
                } else {
                    "SESSION-LOCAL ACKNOWLEDGMENT"
                },
                MINT,
            );
            ui.add_space(12.0);
            ui.label(
                RichText::new("Exact terms acknowledged")
                    .size(24.0)
                    .strong(),
            );
            ui.label("No signature was created. Nothing was sent to an application or the network. This receipt is discarded from session state when the window loses focus, locks or closes.");
            field(ui, "Proposal", &receipt.proposal_id);
            field(ui, "Manifest digest", &receipt.manifest_digest);
            field(ui, "Exact session binding", &receipt.exact_binding);
            field(ui, "Account scope", &receipt.account_id);
            field(ui, "Source label (unverified)", &receipt.client_id);
            ui.add_space(16.0);
            ui.colored_label(AMBER, "Spending release remains blocked by the unqualified desktop/sandbox, account, wallet and release integration gates.");
        });
        ui.add_space(14.0);
        if ui
            .button("Start another review")
            .clicked_by(egui::PointerButton::Primary)
        {
            self.review.invalidate();
            self.transaction.invalidate();
        }
    }
    fn transaction_page(&mut self, ui: &mut egui::Ui) {
        badge(ui, "SIGNER-VERIFIED SYNTHETIC TRANSACTION", MINT);
        ui.label("Local cryptographic checks verify the retained bytes. Runtime identity and spending authority remain unqualified.");
        if self.transaction.phase() == Phase::Accepted {
            ui.label(
                RichText::new("Exact transaction review acknowledged")
                    .size(23.0)
                    .strong(),
            );
            field(
                ui,
                "Session binding",
                self.transaction.binding().unwrap_or(""),
            );
            ui.colored_label(AMBER, "No signature or disclosure was authorized. The retained review is discarded on expiry, focus loss, lock or close.");
        } else {
            egui::ScrollArea::vertical()
                .id_salt("verified-transaction")
                .max_height(360.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(state::inert_text(
                                self.transaction.display().unwrap_or(""),
                            ))
                            .monospace(),
                        )
                        .wrap(),
                    );
                });
            if self.transaction.phase() == Phase::Reading {
                if primary(ui, "Continue to exact transaction acknowledgment")
                    .clicked_by(egui::PointerButton::Primary)
                {
                    self.error = self
                        .transaction
                        .continue_from_local_click()
                        .err()
                        .map(|_| "Transaction review expired or changed. Open it again.");
                }
            } else if self.transaction.phase() == Phase::Confirming {
                let phrase = self.transaction.phrase().unwrap_or_default();
                field(
                    ui,
                    "Exact session binding",
                    self.transaction.binding().unwrap_or(""),
                );
                ui.checkbox(&mut self.understood, "I understand this synthetic acknowledgment cannot sign, send private data, or establish human origin.");
                ui.label(format!("Type {phrase}"));
                ui.add(egui::TextEdit::singleline(&mut *self.confirmation).char_limit(64));
                if ui
                    .add_enabled(
                        self.understood && *self.confirmation == phrase,
                        egui::Button::new("Acknowledge exact transaction"),
                    )
                    .clicked_by(egui::PointerButton::Primary)
                {
                    self.error = self
                        .transaction
                        .confirm_from_local_click(&self.confirmation, self.understood)
                        .err()
                        .map(|_| "Exact transaction acknowledgment was rejected.");
                    self.confirmation.zeroize();
                    self.understood = false;
                }
            }
        }
        if ui
            .button("Clear transaction review")
            .clicked_by(egui::PointerButton::Primary)
        {
            self.discard();
        }
        if let Some(error) = self.error {
            ui.colored_label(AMBER, error);
        }
    }
    fn accounts_page(&mut self, ui: &mut egui::Ui) {
        if self.mode != SurfaceMode::SyntheticDemo {
            heading(
                ui,
                "Native account and authority",
                "Secrets, application grants and exact decisions stay in this signer-owned window.",
            );
            self.native.ui(ui, self.focused_last, self.focus_epoch);
            return;
        }
        heading(
            ui,
            "A separate account for each agreement",
            "Account setup belongs inside the signer, away from the integrating application.",
        );
        self.banner(ui);
        ui.add_space(20.0);
        card(ui, |ui| {
            ui.label(
                RichText::new("Account setup is awaiting desktop qualification")
                    .size(20.0)
                    .strong(),
            );
            ui.label("This synthetic demo cannot generate, unlock, import, display recovery words or persist a real account. It does not accept credentials.");
            ui.add_space(12.0);
            for line in ["1. Launch from a packaged, trusted desktop installation.", "2. Verify the enforced application sandbox and private capability channel.", "3. Qualify attended review, malicious-app denial, lock and recovery tests.", "4. Review and activate the existing encrypted account adapter for that measured profile."] { ui.label(line); }
            ui.add_space(16.0);
            ui.add_enabled(false, egui::Button::new("Create dedicated testnet account"));
            ui.add_enabled(false, egui::Button::new("Unlock or recover account"));
        });
    }
    fn applications_page(&mut self, ui: &mut egui::Ui) {
        if self.mode != SurfaceMode::SyntheticDemo {
            heading(
                ui,
                "Pair a local process",
                "Only observed, current process instances can request exact scoped review.",
            );
            self.native.ui(ui, self.focused_last, self.focus_epoch);
            return;
        }
        heading(ui, "Applications request. You decide.", "A scoped connection must never grant approval, unlock, key access or spending authority.");
        self.banner(ui);
        ui.add_space(20.0);
        card(ui, |ui| {
            ui.label(RichText::new("Pairing profile").size(20.0).strong());
            ui.label("This demo rehearses narrow request-only permission. The native runtime separately pairs an actual kernel-observed process and delivers a channel key over its authenticated private socket.");
            ui.label("A caller-supplied PID, executable name, app label, website identity or pasted token cannot establish a native grant. This demo never creates one.");
            if self.mode == SurfaceMode::SyntheticDemo {
                ui.add_space(12.0);
                if !self.pairing.is_reviewing()
                    && ui
                        .button("Rehearse pairing a synthetic app")
                        .clicked_by(egui::PointerButton::Primary)
                {
                    self.error = self
                        .pairing
                        .begin_local_rehearsal()
                        .err()
                        .map(|_| "Could not prepare synthetic pairing.");
                }
                if self.pairing.is_reviewing() {
                    ui.separator();
                    ui.label(
                        RichText::new("Synthetic Workspace requests: status + request-review")
                            .strong(),
                    );
                    ui.label("Rehearsal only. No process launches and no IPC capability is created. The synthetic record expires in 15 minutes and is revoked on focus loss or lock.");
                    ui.horizontal(|ui| {
                        if primary(ui, "Confirm synthetic pairing")
                            .clicked_by(egui::PointerButton::Primary)
                        {
                            let _ = self.pairing.confirm_local_rehearsal();
                        }
                        if ui.button("Cancel").clicked_by(egui::PointerButton::Primary) {
                            self.pairing.cancel();
                        }
                    });
                }
                let grants: Vec<_> = self
                    .pairing
                    .grants()
                    .map(|g| (g.name.clone(), g.instance.clone()))
                    .collect();
                for (name, instance) in grants {
                    ui.separator();
                    ui.label(RichText::new(name).strong());
                    ui.label("Scope: status, request-review · Session-only · Synthetic");
                    field(ui, "Synthetic instance", &instance);
                    if ui
                        .button("Revoke this rehearsal grant")
                        .clicked_by(egui::PointerButton::Primary)
                    {
                        self.pairing.revoke(&instance);
                    }
                }
            } else {
                ui.add_enabled(false, egui::Button::new("Connect application"));
            }
        });
    }
    fn security_page(&self, ui: &mut egui::Ui) {
        heading(ui, "Trust is a boundary, not a badge", "First intended profile: Linux Wayland with a trusted desktop and confined integrating applications.");
        self.banner(ui);
        ui.add_space(20.0);
        card(ui, |ui| {
            for (title, detail) in [
                ("Native input only", "Private button events drive two-stage review. No stdin, HTTP, CLI approval flag, D-Bus action or caller-provided verified boolean can accept terms."),
                ("Deliberately narrow build", "Pinned eframe/egui. Wayland forced; X11 window/input backend, AccessKit activation, inspection input server, browser links and persistent UI storage are disabled. Clipboard runtime remains unqualified."),
                ("Exact immutable context", "Complete canonical proposal, account scope, source label, random surface nonce and review generation are bound together. Replacement, expiry, focus loss, lock and close discard approval state."),
                ("Explicit threat-model limits", "A hostile compositor, unsandboxed same-UID process, writable install, ptrace, input injection, remote-control and accessibility activation are outside the proposed profile. Environment variables cannot prove these conditions."),
                ("Still required", "Attended desktop and displayed-pixel qualification; owner-controlled installed provider and wallet/witness setup; remote participant key integration; live network/receiver observation. Implemented source flows remain separate from these qualification results."),
            ] {
                ui.label(RichText::new(title).size(17.0).strong().color(MINT));
                ui.label(detail);
                ui.add_space(14.0);
            }
        });
    }
}
impl Window {
    fn draw(&mut self, ui: &mut egui::Ui) {
        let (focused, focus_was_lost) = ui.ctx().input(|i| {
            (
                i.focused && i.viewport().focused == Some(true),
                i.events
                    .iter()
                    .any(|event| matches!(event, egui::Event::WindowFocused(false))),
            )
        });
        // Winit can batch lose+regain events before one redraw. The final focus
        // flag alone must not preserve consent across that lost-focus interval.
        if focus_was_lost || (self.focused_last && !focused) {
            self.review.observe_focus(false);
            self.blur();
        }
        self.review.observe_focus(focused);
        self.transaction.observe_focus(focused);
        self.focused_last = focused;
        self.review.expire();
        self.transaction.expire();
        if ui.ctx().input(|i| i.viewport().close_requested()) {
            self.discard();
        }
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_secs(1));
        // Keyboard shortcuts never accept. Enter remains text input only.
        if ui.ctx().input(|i| i.key_pressed(egui::Key::Escape)) {
            self.discard();
        }
        // Do not poll request queues, start jobs or render account details while
        // unfocused. Existing exact approved leases retain their original expiry.
        if !focused {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.heading("Wholepact signer");
                ui.label("Private details hidden. Pending decisions were discarded. Previously approved bounded operations may continue until their original expiry. Return to review a new request; Lock or Escape revokes access.");
                if ui.button("Lock signer").clicked_by(egui::PointerButton::Primary) {
                    self.discard();
                }
            });
            return;
        }
        egui::Panel::left("signer-navigation")
            .exact_size(244.0)
            .resizable(false)
            .frame(egui::Frame::new().fill(PANEL).inner_margin(16))
            .show(ui, |ui| self.sidebar(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BACKGROUND).inner_margin(24))
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| match self.page {
                    Page::Review => self.review_page(ui),
                    Page::Accounts => self.accounts_page(ui),
                    Page::Applications => self.applications_page(ui),
                    Page::Security => self.security_page(ui),
                });
            });
    }
}
impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}
pub(super) fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.global_style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = BACKGROUND;
    style.visuals.window_fill = PANEL;
    style.visuals.override_text_color = Some(Color32::from_rgb(228, 236, 239));
    style.visuals.selection.bg_fill = Color32::from_rgb(43, 91, 73);
    style.spacing.item_spacing = Vec2::new(10.0, 9.0);
    style.spacing.button_padding = Vec2::new(14.0, 10.0);
    ctx.set_global_style(style);
}
fn heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(28.0).strong());
    ui.label(RichText::new(subtitle).color(MUTED));
    ui.add_space(18.0);
}
fn card(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(PANEL)
        .inner_margin(18)
        .corner_radius(10)
        .show(ui, body);
}
fn badge(ui: &mut egui::Ui, label: &str, color: Color32) {
    ui.label(RichText::new(label).color(color).size(12.0).strong());
}
fn field(ui: &mut egui::Ui, title: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{title}:")).color(MUTED));
        ui.label(
            RichText::new(state::inert_text(value))
                .monospace()
                .size(12.0),
        );
    });
}
fn primary(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(label).color(BACKGROUND).strong()).fill(MINT))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(focused: bool) -> egui::RawInput {
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(1100.0, 780.0),
            )),
            focused,
            ..Default::default()
        };
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .unwrap()
            .focused = Some(focused);
        input
    }
    fn frame(ctx: &egui::Context, window: &mut Window, focused: bool) -> egui::FullOutput {
        {
            let mut output = ctx.run_ui(input(focused), |ui| window.draw(ui));
            output.textures_delta.clear();
            output
        }
    }
    #[cfg(feature = "synthetic-qualification")]
    #[test]
    fn cryptographic_transaction_path_renders_and_batched_focus_revokes_acknowledgment() {
        for acknowledge in [false, true] {
            let ctx = egui::Context::default();
            let mut window = Window::new(SurfaceMode::SyntheticDemo, None).unwrap();
            let _ = frame(&ctx, &mut window, true);
            window.load_transaction_demo();
            assert!(window.error.is_none());
            assert_eq!(window.review.phase(), Phase::Idle);
            assert_eq!(window.transaction.phase(), Phase::Reading);
            let output = frame(&ctx, &mut window, true);
            assert!(!output.shapes.is_empty());
            assert!(output.platform_output.commands.is_empty());
            window.transaction.continue_from_local_click().unwrap();
            let phrase = window.transaction.phrase().unwrap();
            window.confirmation = Zeroizing::new(phrase.clone());
            window.understood = true;
            let mut raw = input(true);
            raw.events.push(egui::Event::Key {
                key: egui::Key::Enter,
                physical_key: Some(egui::Key::Enter),
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            });
            let mut output = ctx.run_ui(raw, |ui| window.draw(ui));
            output.textures_delta.clear();
            assert_eq!(window.transaction.phase(), Phase::Confirming);
            if acknowledge {
                window
                    .transaction
                    .confirm_from_local_click(&phrase, true)
                    .unwrap();
                let output = frame(&ctx, &mut window, true);
                assert!(!output.shapes.is_empty());
                assert!(output.platform_output.commands.is_empty());
            }
            let mut raw = input(true);
            raw.events.extend([
                egui::Event::WindowFocused(false),
                egui::Event::WindowFocused(true),
            ]);
            let mut output = ctx.run_ui(raw, |ui| window.draw(ui));
            output.textures_delta.clear();
            assert_eq!(window.transaction.phase(), Phase::Idle);
            assert!(window.transaction.binding().is_none());
            assert!(window.confirmation.is_empty());
            assert!(window
                .transaction
                .confirm_from_local_click(&phrase, true)
                .is_err());
        }
    }
    #[test]
    fn headless_pages_render_and_focus_loss_erases_review_and_pairing() {
        let ctx = egui::Context::default();
        configure_style(&ctx);
        let mut window = Window::new(SurfaceMode::SyntheticDemo, None).unwrap();
        for page in [
            Page::Review,
            Page::Accounts,
            Page::Applications,
            Page::Security,
        ] {
            window.navigate(page);
            let output = frame(&ctx, &mut window, true);
            assert!(!output.shapes.is_empty());
            assert!(output.platform_output.commands.is_empty());
        }
        window.navigate(Page::Review);
        window.load_demo();
        let _ = frame(&ctx, &mut window, true);
        assert_eq!(window.review.phase(), Phase::Reading);
        window.review.continue_from_local_click().unwrap();
        let _ = frame(&ctx, &mut window, true);
        window.pairing.begin_local_rehearsal().unwrap();
        window.pairing.confirm_local_rehearsal().unwrap();
        let _ = frame(&ctx, &mut window, false);
        assert_eq!(window.review.phase(), Phase::Idle);
        assert_eq!(window.pairing.grants().count(), 0);
        assert!(window.confirmation.is_empty());
    }
    #[test]
    fn unfocused_frame_hides_details_and_clears_pending_input() {
        let ctx = egui::Context::default();
        let mut window = Window::new(SurfaceMode::SyntheticDemo, None).unwrap();
        let _ = frame(&ctx, &mut window, true);
        window.imported.push_str("synthetic-private-import-marker");
        window.confirmation.push_str("synthetic-private-confirmation-marker");
        let epoch = window.focus_epoch;
        let output = frame(&ctx, &mut window, false);
        assert!(window.focus_epoch > epoch);
        assert!(window.imported.is_empty() && window.confirmation.is_empty());
        assert_eq!(window.review.phase(), Phase::Idle);
        let rendered = format!("{:?}", output.shapes);
        assert!(!rendered.contains("synthetic-private-import-marker"));
        assert!(!rendered.contains("synthetic-private-confirmation-marker"));
        assert!(output.platform_output.commands.is_empty());
        // Explicit discard remains the full lock path, including after blur.
        window.discard();
        assert!(window.confirmation.is_empty());
    }
    #[test]
    fn enter_key_cannot_confirm_and_navigation_invalidates_pending_review() {
        let ctx = egui::Context::default();
        let mut window = Window::new(SurfaceMode::SyntheticDemo, None).unwrap();
        let _ = frame(&ctx, &mut window, true);
        window.load_demo();
        window.review.continue_from_local_click().unwrap();
        window.confirmation = Zeroizing::new(state::confirmation_phrase(
            window.review.proposal().unwrap().manifest_digest(),
        ));
        window.understood = true;
        let mut raw = input(true);
        raw.events.push(egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: Some(egui::Key::Enter),
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        let mut output = ctx.run_ui(raw, |ui| window.draw(ui));
        output.textures_delta.clear();
        assert_eq!(window.review.phase(), Phase::Confirming);
        assert!(window.review.receipt().is_none());
        window.navigate(Page::Accounts);
        assert_eq!(window.review.phase(), Phase::Idle);
        assert!(window.confirmation.is_empty());
    }
    #[test]
    fn batched_focus_loss_and_regain_cancels_pending_and_accepted_context() {
        for accept_first in [false, true] {
            let ctx = egui::Context::default();
            let mut window = Window::new(SurfaceMode::SyntheticDemo, None).unwrap();
            let _ = frame(&ctx, &mut window, true);
            window.load_demo();
            window.review.continue_from_local_click().unwrap();
            if accept_first {
                let phrase =
                    state::confirmation_phrase(window.review.proposal().unwrap().manifest_digest());
                window
                    .review
                    .confirm_from_local_click(&phrase, true)
                    .unwrap();
                assert!(window.review.receipt().is_some());
            }
            window.pairing.begin_local_rehearsal().unwrap();
            window.pairing.confirm_local_rehearsal().unwrap();
            let mut raw = input(true);
            raw.events.extend([
                egui::Event::WindowFocused(false),
                egui::Event::WindowFocused(true),
            ]);
            let mut output = ctx.run_ui(raw, |ui| window.draw(ui));
            output.textures_delta.clear();
            assert!(window.focused_last);
            assert_eq!(window.review.phase(), Phase::Idle);
            assert!(window.review.receipt().is_none());
            assert_eq!(window.pairing.grants().count(), 0);
        }
    }
}
