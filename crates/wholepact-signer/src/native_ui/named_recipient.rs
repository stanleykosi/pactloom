//! Explicit optional-mode setup in the already-open genuine signer window.
//! Uses that account's authority/session; no replacement native source is minted.
use super::{authority::ExactNativeReview, wallet_workspace::NamedRecipientOwnerContext};
use crate::{
    Error, Result,
    consent_journal::{LiveNamedRecipientProfile, NamedRecipientPins, PreparedNamedRecipientSetup},
};
use eframe::egui;
mod born_courier;
mod born_inbox;
mod born_plan;
mod born_signing;
mod inbox;
mod input;
mod plan;
mod signing;
use zeroize::{Zeroize, Zeroizing};
struct Pending {
    setup: PreparedNamedRecipientSetup,
    review: ExactNativeReview,
    shown: u64,
    continued: Option<u64>,
}
#[derive(Default)]
pub(super) struct NamedRecipientWorkspace {
    original_profile_ref: String,
    verifier_signing: String,
    verifier_transport: String,
    witness_transport: String,
    witness_certificate: String,
    return_transport: String,
    pending: Option<Pending>,
    live: Option<LiveNamedRecipientProfile>,
    phrase: Zeroizing<String>,
    frame: u64,
    status: String,
    inbox: inbox::InboxWorkspace,
    signing: signing::SigningWorkspace,
    born_signing: born_signing::BornSigningWorkspace,
    born_inbox: born_inbox::BornInboxWorkspace,
    born_courier: born_courier::BornCourierWorkspace,
}
fn key(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|_| Error::InvalidData)?;
    if hex::encode(&bytes) != s {
        return Err(Error::InvalidData);
    }
    bytes.try_into().map_err(|_| Error::InvalidData)
}
impl NamedRecipientWorkspace {
    pub(super) fn live_profile(&self) -> Option<LiveNamedRecipientProfile> {
        self.live.clone()
    }
    pub(super) fn final_active(&self) -> bool {
        self.signing.is_active()
            || self.born_signing.is_active()
            || self.born_inbox.is_active()
            || self.born_courier.is_active()
    }
    /// Dedicated event-thread path while final work or consent is pending. No
    /// sibling inbox/setup/IPC operation may wait on the worker's journal lock.
    pub(super) fn final_ui(
        &mut self,
        ui: &mut egui::Ui,
        owner: &NamedRecipientOwnerContext<'_>,
        wallet: Option<&super::wallet_workspace::NativeWalletWorkspace>,
        witness: Option<&std::sync::Arc<super::witness_workspace::NativeWitnessWorkspace>>,
        focused: bool,
        epoch: u64,
    ) {
        if !focused || owner.authority.check_current().is_err() {
            self.clear();
            return;
        }
        if let Some(live) = &self.live {
            if live
                .check_display_association(owner.journal, owner.authority)
                .is_err()
            {
                self.clear();
                return;
            }
            if self.signing.is_active() {
                self.signing.ui(ui, live, owner, witness, focused, epoch);
            } else if self.born_signing.is_active() {
                self.born_signing
                    .ui(ui, live, owner, witness, focused, epoch);
            } else if self.born_inbox.is_active() {
                self.born_inbox
                    .ui(ui, live, owner, wallet, witness, focused, epoch);
            } else if self.born_courier.is_active() {
                self.born_courier
                    .ui(ui, live, owner, witness, focused, epoch);
            }
        } else {
            self.reap_cancelled();
            ui.label("Cancelled final work is still finishing. No new operation is admitted; preserve any original Started/result.");
        }
    }
    pub(super) fn reap_cancelled(&mut self) {
        self.signing.reap_cancelled();
        self.born_signing.reap_cancelled();
        self.born_inbox.reap_cancelled();
        self.born_courier.reap_cancelled();
    }
    pub(super) fn clear(&mut self) {
        self.inbox.clear();
        self.born_inbox.clear();
        self.born_courier.clear();
        self.signing.clear();
        self.born_signing.clear();
        self.pending = None;
        self.live = None;
        self.phrase.zeroize();
    }
    fn prepare(
        &mut self,
        owner: &NamedRecipientOwnerContext<'_>,
        epoch: u64,
        reopen: Option<bool>,
    ) -> Result<()> {
        self.clear();
        let setup = if let Some(by_setup) = reopen {
            if by_setup {
                PreparedNamedRecipientSetup::reopen_by_setup_commitment(
                    owner.journal,
                    owner.session,
                    owner.vault,
                    owner.authority,
                    &self.original_profile_ref,
                )?
            } else {
                PreparedNamedRecipientSetup::reopen(
                    owner.journal,
                    owner.session,
                    owner.vault,
                    owner.authority,
                    &self.original_profile_ref,
                )?
            }
        } else {
            #[cfg(feature = "pending-birth-owner-signing")]
            if let Some((actual, born_owner)) = owner.born {
                PreparedNamedRecipientSetup::prepare_born(
                    actual,
                    born_owner,
                    owner.session,
                    owner.enrollment_ref,
                    owner.manifest_ref,
                    NamedRecipientPins {
                        verifier_signing: key(&self.verifier_signing)?,
                        verifier_transport: key(&self.verifier_transport)?,
                        witness_transport: key(&self.witness_transport)?,
                        witness_certificate_digest: self.witness_certificate.clone(),
                        return_transport: key(&self.return_transport)?,
                    },
                )?
            } else {
                Self::prepare_legacy(owner, self)?
            }
            #[cfg(not(feature = "pending-birth-owner-signing"))]
            {
                Self::prepare_legacy(owner, self)?
            }
        };
        let review = ExactNativeReview::stage(
            owner.authority,
            setup.digest(),
            setup.display().into(),
            epoch,
        )?;
        self.pending = Some(Pending {
            setup,
            review,
            shown: self.frame,
            continued: None,
        });
        Ok(())
    }
    fn prepare_legacy(
        owner: &NamedRecipientOwnerContext<'_>,
        this: &Self,
    ) -> Result<PreparedNamedRecipientSetup> {
        PreparedNamedRecipientSetup::prepare(
            owner.journal,
            owner.session,
            owner.vault,
            owner.authority,
            owner.enrollment_ref,
            owner.manifest_ref,
            NamedRecipientPins {
                verifier_signing: key(&this.verifier_signing)?,
                verifier_transport: key(&this.verifier_transport)?,
                witness_transport: key(&this.witness_transport)?,
                witness_certificate_digest: this.witness_certificate.clone(),
                return_transport: key(&this.return_transport)?,
            },
        )
    }
    fn retain_reviewed_profile(
        &mut self,
        owner: &NamedRecipientOwnerContext<'_>,
        focused: bool,
        epoch: u64,
    ) -> Result<()> {
        let p = self.pending.take().ok_or(Error::Locked)?;
        let result = p
            .review
            .consume_native_click(focused, epoch, &self.phrase)
            .and_then(|d| {
                p.setup
                    .approve(d, owner.journal, owner.session, owner.vault)
            });
        self.phrase.zeroize();
        match result {
            Ok(profile) => {
                self.live = Some(profile);
                self.status = "Exact profile retained or original recovered. No signing or witness reservation occurred.".into();
                Ok(())
            }
            Err(Error::Uncertain) => {
                self.live = None;
                self.status = "Commit outcome uncertain. Preserve the journal and repeat only this exact setup review; the original key must be recovered, never reset.".into();
                Err(Error::Uncertain)
            }
            Err(error) => {
                self.live = None;
                self.status = "Profile approval failed or expired. No success is claimed; retained originals remain immutable.".into();
                Err(error)
            }
        }
    }
    pub(super) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        owner: &NamedRecipientOwnerContext<'_>,
        wallet: Option<&super::wallet_workspace::NativeWalletWorkspace>,
        witness: Option<&std::sync::Arc<super::witness_workspace::NativeWitnessWorkspace>>,
        focused: bool,
        epoch: u64,
    ) {
        if !focused || owner.authority.check_current().is_err() {
            self.clear();
            return;
        }
        self.frame = self.frame.saturating_add(1);
        if self.pending.as_ref().is_some_and(|p| p.review.expired()) {
            self.clear();
            self.status = "Review expired. Retained original profiles are unchanged.".into();
        }
        if self.live.as_ref().is_some_and(|p| {
            p.check_display_association(owner.journal, owner.authority)
                .is_err()
        }) {
            self.clear();
            self.status =
                "Current source association ended. Reopen through the exact original setup review."
                    .into();
        }
        ui.collapsing("Optional named-verifier offline profile", |ui| {
            ui.label("The fully independent mode is unavailable. This optional mode trusts an explicitly selected verifier for peer ownership and allocation. Setup alone cannot authorize a payment.");
            ui.label(&self.status);
            if let Some(live) = &self.live {
                ui.label(format!("Retained profile: {}", live.reference()));
                ui.label(format!("Recipient public transport key: {}", hex::encode(live.transport_public_key())));
                self.inbox.ui(ui, live, owner, wallet, focused, epoch);
                self.signing.ui(ui, live, owner, witness, focused, epoch);
                if self.signing.is_active() { return; }
                self.born_signing.ui(ui, live, owner, witness, focused, epoch);
                if self.born_signing.is_active() { return; }
                self.born_inbox.ui(ui, live, owner, wallet, witness, focused, epoch);
                if self.born_inbox.is_active() { return; }
                self.born_courier.ui(ui, live, owner, witness, focused, epoch);
            }
            if self.final_active() { return; }
            if self.pending.is_none() {
                ui.label("Reopen an existing immutable profile using its exact original reference. No new enrollment or acceptance is required.");
                ui.add(egui::TextEdit::singleline(&mut self.original_profile_ref).char_limit(64));
                if ui.button("Review reopening original profile").clicked_by(egui::PointerButton::Primary)
                    && self.prepare(owner, epoch, Some(false)).is_err() {
                    self.status = "Original profile reopen rejected. Keep the exact original reference and journal; do not replace it with fresh setup.".into();
                }
                if ui.button("Review reopening by original setup commitment").clicked_by(egui::PointerButton::Primary)
                    && self.prepare(owner, epoch, Some(true)).is_err() {
                    self.status = "Original setup commitment was not recovered. No replacement key was created.".into();
                }
                ui.label("Use the setup commitment displayed before approval if a commit result was interrupted before its profile reference appeared.");
                ui.label("Fresh setup is a separate immutable operation. It currently blocks legacy financial/history/recovery paths; cancel cannot undo retention.");
                for (label, value) in [
                    ("Independently authenticated verifier signing key", &mut self.verifier_signing),
                    ("Independently authenticated verifier transport key", &mut self.verifier_transport),
                    ("Configured witness transport key", &mut self.witness_transport),
                    ("Configured witness certificate digest", &mut self.witness_certificate),
                    ("Original return destination transport key", &mut self.return_transport),
                ] {
                    ui.label(label);
                    ui.add(egui::TextEdit::singleline(value).char_limit(64));
                }
                if ui.add_enabled(!owner.enrollment_ref.is_empty() && !owner.manifest_ref.is_empty(), egui::Button::new("Review fresh optional profile")).clicked_by(egui::PointerButton::Primary)
                    && self.prepare(owner, epoch, None).is_err() {
                    self.status = "Setup rejected. Current account, enrollment, accepted manifest and exact pins are required.".into();
                }
            } else {
                let p = self.pending.as_mut().expect("checked pending");
                ui.label(p.review.display());
                if !p.review.confirming() {
                    if self.frame > p.shown && ui.button("Continue exact trust review").clicked_by(egui::PointerButton::Primary) {
                        if p.review.continue_from_native_click(focused, epoch).is_ok() { p.continued = Some(self.frame); }
                        else { self.clear(); }
                    }
                } else {
                    ui.label(format!("Type AUTHORIZE {}", &p.review.digest()[..12]));
                    ui.add(egui::TextEdit::singleline(&mut *self.phrase).char_limit(128));
                    let can = p.continued.is_some_and(|f| self.frame > f);
                    if ui.add_enabled(can, egui::Button::new("Retain exact optional profile")).clicked_by(egui::PointerButton::Primary) {
                        let _ = self.retain_reviewed_profile(owner, focused, epoch);
                    }
                }
            }
            if ui.button("Cancel local profile review").clicked_by(egui::PointerButton::Primary) { self.clear(); }
        });
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
mod synthetic_born_profile;

#[cfg(feature = "synthetic-born-joined-qualification")]
mod synthetic_born_payment;
