//! Actual pending-account native lifecycle. No witness client, journal creation,
//! IPC endpoint, financial activation or authority-conversion path exists here.
use super::{
    authority::{ExactNativeReview, PendingAccountNativeAuthority},
    runtime::PendingBirthEntry,
    state::inert_text,
};
use crate::{
    Error, Result,
    account::{
        AccountVault, BackupVerifiedAccount, PendingAccount, ProvisioningConsent,
        birth::{BirthIdentity, PendingBirthVault, PreparedAccountBirth, creation_target},
    },
};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
};
use wholepact_authority::{AccountPolicy, WitnessDisclosureDescriptor};
use zeroize::{Zeroize, Zeroizing};

const MAX_SETUP_BYTES: usize = 128 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicBirthSetup {
    disclosure: WitnessDisclosureDescriptor,
    original_policy: AccountPolicy,
}
struct BirthReview {
    verified: BackupVerifiedAccount,
    prepared: PreparedAccountBirth,
    review: ExactNativeReview,
    displayed_to_end: bool,
}
enum Phase {
    Backup {
        account: Box<PendingAccount>,
        words: Zeroizing<String>,
        identity: Box<BirthIdentity>,
    },
    Review(Box<BirthReview>),
    Publishing(mpsc::Receiver<Result<PendingBirthVault>>),
    Pending(Box<PendingBirthVault>),
}
#[derive(Default)]
pub(super) struct NativeBirthCeremony {
    owner: Option<Arc<PendingAccountNativeAuthority>>,
    phase: Option<Phase>,
    root: PathBuf,
    password: Zeroizing<String>,
    backup: Zeroizing<String>,
    setup: Zeroizing<String>,
    construction_proposal: Zeroizing<String>,
    stable_recipient_policy: Zeroizing<String>,
    construction_scope_preview: Zeroizing<String>,
    confirmation: Zeroizing<String>,
}
impl NativeBirthCeremony {
    pub(super) fn is_active(&self) -> bool {
        self.phase.is_some() || self.owner.is_some()
    }
    pub(super) fn begin(
        &mut self,
        entry: PendingBirthEntry,
        root: &Path,
        password: &str,
        privacy_domain: &str,
    ) -> Result<()> {
        if self.is_active() || password.len() < 12 || password.len() > 1024 {
            return Err(Error::InvalidData);
        }
        let root = creation_target(root)?;
        // The private actual-window token is consumed BEFORE generating entropy.
        // Neither an open account nor caller JSON can supply this owner value.
        let owner = Arc::new(PendingAccountNativeAuthority::enter(entry)?);
        let account = PendingAccount::generate(ProvisioningConsent {
            privacy_domain: privacy_domain.into(),
            account_index: 0,
        })?;
        owner.check_current()?;
        let identity = account.birth_identity_for_native_review(&owner)?;
        let words = account.recovery_words()?;
        self.root = root;
        self.password = Zeroizing::new(password.into());
        self.owner = Some(owner);
        self.phase = Some(Phase::Backup {
            account: Box::new(account),
            words,
            identity: Box::new(identity),
        });
        Ok(())
    }
    /// Called synchronously by real blur/navigation/lock/close and cancellation.
    /// Invalidate before dropping state: a KDF worker may still hold an Arc, but
    /// it cannot acquire a new publication lease once this returns. A short
    /// already-admitted disk publication drains; its result remains pending only.
    pub(super) fn clear(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.invalidate();
        }
        self.phase = None;
        self.password.zeroize();
        self.backup.zeroize();
        self.setup.zeroize();
        self.construction_proposal.zeroize();
        self.stable_recipient_policy.zeroize();
        self.construction_scope_preview.zeroize();
        self.confirmation.zeroize();
        self.root.clear();
    }
    fn current_owner(&self, epoch: u64) -> Result<Arc<PendingAccountNativeAuthority>> {
        let owner = self.owner.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        if owner.focus_epoch() != epoch {
            return Err(Error::ReviewMismatch);
        }
        Ok(owner.clone())
    }
    /// Draft-only helper. The existing final birth review still owns publication.
    /// Never available after a birth record or original policy is retained.
    fn derive_construction_scope(&mut self, epoch: u64) -> Result<()> {
        let owner = self.current_owner(epoch)?;
        let Some(Phase::Backup { identity, .. }) = self.phase.as_ref() else {
            return Err(Error::ReviewMismatch);
        };
        let (updated, digest) = derive_construction_draft(
            &self.setup,
            &self.construction_proposal,
            identity.account_id(),
            identity.network_profile_id(),
        )?;
        owner.check_current()?;
        self.setup = updated;
        self.construction_scope_preview = Zeroizing::new(format!(
            "Draft payment-effect scope: {digest}\nThis is for exact NON-SIGNING construction only. It is not a delivery-recipient scope, viewing consent, witness admission or financial permission. The complete updated original policy remains subject to the next exact native birth review."
        ));
        Ok(())
    }
    fn derive_stable_recipient_scope(&mut self, epoch: u64) -> Result<()> {
        let owner = self.current_owner(epoch)?;
        let Some(Phase::Backup { identity, .. }) = self.phase.as_ref() else {
            return Err(Error::ReviewMismatch);
        };
        let (updated, preview) = derive_stable_recipient_draft(
            &self.setup,
            &self.stable_recipient_policy,
            identity.account_id(),
            identity.network_profile_id(),
        )?;
        owner.check_current()?;
        self.setup = updated;
        self.construction_scope_preview = Zeroizing::new(preview);
        Ok(())
    }
    fn stage_backup_and_review(&mut self, epoch: u64) -> Result<()> {
        let owner = self.current_owner(epoch)?;
        let identity = match self.phase.as_ref() {
            Some(Phase::Backup { identity, .. }) => identity,
            _ => return Err(Error::ReviewMismatch),
        };
        let setup = parse_setup(
            &self.setup,
            identity.account_id(),
            identity.network_profile_id(),
        )?;
        let Some(Phase::Backup { account, .. }) = self.phase.take() else {
            return Err(Error::ReviewMismatch);
        };
        let verified = account.verify_backup(&self.backup)?;
        self.backup.zeroize();
        let prepared = if self.stable_recipient_policy.trim().is_empty() {
            PreparedAccountBirth::prepare(
                &verified,
                &self.root,
                &setup.disclosure,
                &setup.original_policy,
                &owner,
            )?
        } else {
            let policy = parse_stable_recipient_policy(&self.stable_recipient_policy)?;
            PreparedAccountBirth::prepare_v2(
                &verified,
                &self.root,
                &setup.disclosure,
                &setup.original_policy,
                policy,
                &owner,
            )?
        };
        let display = format!(
            "SAVE A BLOCKED PENDING ACCOUNT ONLY\nNo witness is contacted or enrolled. No account journal, signer IPC, usable vault or financial permission is created. The original origin and all terms below will be immutable. Losing this origin cannot be repaired by selecting another witness.\n\n{}",
            prepared.review_json()?,
        );
        let review =
            ExactNativeReview::stage(owner.native(), prepared.reviewed_digest(), display, epoch)?;
        self.setup.zeroize();
        self.construction_proposal.zeroize();
        self.stable_recipient_policy.zeroize();
        self.construction_scope_preview.zeroize();
        self.phase = Some(Phase::Review(Box::new(BirthReview {
            verified,
            prepared,
            review,
            displayed_to_end: false,
        })));
        Ok(())
    }
    fn continue_review(&mut self, focused: bool, epoch: u64) -> Result<()> {
        self.current_owner(epoch)?;
        let Some(Phase::Review(review)) = self.phase.as_mut() else {
            return Err(Error::ReviewMismatch);
        };
        if !review.displayed_to_end {
            return Err(Error::ReviewMismatch);
        }
        review.review.continue_from_native_click(focused, epoch)
    }
    fn publish_from_native_click(&mut self, focused: bool, epoch: u64) -> Result<()> {
        let owner = self.current_owner(epoch)?;
        let Some(Phase::Review(review)) = self.phase.take() else {
            return Err(Error::ReviewMismatch);
        };
        if !review.displayed_to_end {
            return Err(Error::ReviewMismatch);
        }
        let BirthReview {
            verified,
            prepared,
            review,
            ..
        } = *review;
        // The only decision source is the existing exact native review machine,
        // reached from the actual focused primary-click branch below.
        let decision = review.consume_native_click(focused, epoch, &self.confirmation)?;
        self.confirmation.zeroize();
        let approved = prepared.approve(&verified, decision, &owner)?;
        let root = self.root.clone();
        let password = std::mem::replace(&mut self.password, Zeroizing::new(String::new()));
        let (send, receive) = mpsc::channel();
        std::thread::Builder::new()
            .name("wholepact-pending-birth".into())
            .spawn(move || {
                // The actual UI remains responsive throughout KDF/encryption. Its
                // retained owner is explicitly invalidated on every lifecycle loss.
                let outcome = AccountVault::create_with_birth(
                    &root,
                    verified,
                    approved,
                    password.as_bytes(),
                    &owner,
                );
                // Receiver loss cannot activate the published envelope. Dropping a
                // successfully returned PendingBirthVault merely releases its lock.
                let _ = send.send(outcome);
            })?;
        self.phase = Some(Phase::Publishing(receive));
        Ok(())
    }
    fn poll(&mut self, epoch: u64) -> Result<()> {
        if !matches!(self.phase, Some(Phase::Pending(_))) {
            self.current_owner(epoch)?;
        }
        if let Some(Phase::Review(review)) = &self.phase {
            if review.review.expired() {
                return Err(Error::ReviewMismatch);
            }
        }
        let outcome = match &self.phase {
            Some(Phase::Publishing(receive)) => match receive.try_recv() {
                Ok(outcome) => Some(outcome),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => return Err(Error::Uncertain),
            },
            _ => None,
        };
        if let Some(outcome) = outcome {
            let pending = outcome?;
            self.current_owner(epoch)?;
            if let Some(owner) = self.owner.take() {
                owner.invalidate();
            }
            self.phase = Some(Phase::Pending(Box::new(pending)));
        }
        Ok(())
    }
    pub(super) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        focused: bool,
        epoch: u64,
    ) -> Option<&'static str> {
        if !focused || self.poll(epoch).is_err() {
            self.clear();
            let message = "Pending birth cancelled or interrupted. Preserve any partial directory unchanged. No signer account or witness authority was activated.";
            ui.label(message);
            return Some(message);
        }
        enum Action {
            None,
            Review,
            DeriveConstructionScope,
            DeriveStableRecipientScope,
            Continue,
            Publish,
            Cancel,
        }
        let mut action = Action::None;
        ui.heading("Pending account birth");
        ui.label("This ceremony saves a blocked pending envelope. Financial account activation remains unavailable.");
        #[cfg(feature = "pending-birth-owner-signing")]
        ui.label("After saving, close this ceremony and use the separate authenticated pending-account reopen flow to review the original request, existing-owner signature, private export and witness acknowledgement.");
        #[cfg(not(feature = "pending-birth-owner-signing"))]
        ui.label(
            "Pending request, export and witness acknowledgement UI are unavailable in this build.",
        );
        ui.label(format!(
            "Frozen target: {}",
            inert_text(&self.root.display().to_string())
        ));
        match self.phase.as_mut() {
            Some(Phase::Backup {
                words, identity, ..
            }) => {
                ui.colored_label(egui::Color32::YELLOW, "PRIVATE RECOVERY WORDS. Record them privately. Do not put them in the public policy JSON or share them with any application.");
                ui.label(words.as_str());
                ui.label("Re-enter all 24 words");
                ui.add(egui::TextEdit::multiline(&mut *self.backup).char_limit(1024));
                ui.label(format!("Derived account ID: {}", identity.account_id()));
                ui.label(format!(
                    "Raw FVK digest: {}",
                    identity.full_viewing_key_digest()
                ));
                ui.label(format!(
                    "Network: {}\nDerivation: {}",
                    identity.network_profile_id(),
                    identity.exact_derivation()
                ));
                ui.label("Public setup JSON with exactly disclosure and original_policy. Enter the displayed account ID/network in both. The disclosure policy_digest must match the original genesis-free policy. Include original witness endpoint/server name/certificate digest, owner/writer certificate digests and all scope, expiry and lifetime-cap terms. Never enter certificate private keys, passwords or credentials. No files or network endpoints are loaded by this form.");
                ui.add(egui::TextEdit::multiline(&mut *self.setup).char_limit(MAX_SETUP_BYTES));
                ui.collapsing("Optional exact construction scope in NEW policy draft", |ui| {
                    ui.label("Paste the intended full proposal with this newly derived account and network. This button explicitly adds its computed payment-effect scope to the unpublished policy draft and updates the disclosure policy digest. It cannot modify an existing birth or enrollment. No private keys or credentials belong here.");
                    ui.add(egui::TextEdit::multiline(&mut *self.construction_proposal).char_limit(MAX_SETUP_BYTES));
                    if ui.button("Derive and add exact payment-effect scope to this draft")
                        .clicked_by(egui::PointerButton::Primary) && focused {
                        action = Action::DeriveConstructionScope;
                    }
                    if !self.construction_scope_preview.is_empty() {
                        ui.label(self.construction_scope_preview.as_str());
                    }
                });
                ui.collapsing("New VERSION 2 stable recipient policy before inventory", |ui| {
                    ui.label("This distinct new-origin format records exact allowed recipient/charge addresses, purposes and caps before inputs or change are known. Every later candidate still needs exact review; own returns must be authenticated against this account. No automatic signing is granted. Paste the full typed version-2 descriptor, including the unchanged original lifetime/debit/fee/time limits. Leave empty for legacy exact-output policy. Existing born records cannot be upgraded.");
                    ui.add(egui::TextEdit::multiline(&mut *self.stable_recipient_policy).char_limit(96*1024));
                    if ui.button("Review and commit this stable policy to the unpublished draft").clicked_by(egui::PointerButton::Primary) && focused { action=Action::DeriveStableRecipientScope; }
                });
                if ui
                    .button("Verify backup and review exact pending-birth terms")
                    .clicked_by(egui::PointerButton::Primary)
                    && focused
                {
                    action = Action::Review;
                }
            }
            Some(Phase::Review(review)) => {
                let scroll = egui::ScrollArea::vertical()
                    .id_salt("exact-pending-birth-review")
                    .max_height(440.0)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(review.review.display()).monospace())
                    });
                if scroll.state.offset.y + scroll.inner_rect.height() + 1.0 >= scroll.content_size.y
                {
                    review.displayed_to_end = true;
                }
                if !review.review.confirming() {
                    if ui
                        .add_enabled(
                            review.displayed_to_end,
                            egui::Button::new("Continue after reviewing every immutable term"),
                        )
                        .clicked_by(egui::PointerButton::Primary)
                        && focused
                    {
                        action = Action::Continue;
                    }
                } else {
                    let phrase = format!("AUTHORIZE {}", &review.review.digest()[..12]);
                    ui.label(format!(
                        "Type {phrase} to save this exact blocked pending envelope"
                    ));
                    ui.add(egui::TextEdit::singleline(&mut *self.confirmation).char_limit(64));
                    if ui
                        .add_enabled(
                            *self.confirmation == phrase,
                            egui::Button::new("Save exact blocked pending account"),
                        )
                        .clicked_by(egui::PointerButton::Primary)
                        && focused
                    {
                        action = Action::Publish;
                    }
                }
            }
            Some(Phase::Publishing(_)) => {
                ui.label("Preparing encrypted pending storage. This window remains responsive. Focus loss, lock, navigation or launcher disconnect invalidates further publication. A short already-admitted disk write may finish, but its envelope remains blocked.");
            }
            Some(Phase::Pending(pending)) => {
                let anchor = pending.anchor();
                ui.label("Encrypted pending envelope retained durably. This is not an activated account, witness enrolment or financial capability.");
                ui.label(format!(
                    "Birth digest: {}\nOperation: {}\nAccount: {}\nOriginal terms digest: {}",
                    anchor.birth_digest(),
                    anchor.operation_id(),
                    anchor.identity().account_id(),
                    anchor.original_policy_terms_digest()
                ));
                ui.label(format!(
                    "Original witness: {} at {} ({})\nPinned certificate digest: {}",
                    anchor.witness_origin().witness_id(),
                    anchor.witness_origin().endpoint(),
                    anchor.witness_origin().server_name(),
                    anchor.witness_origin().pinned_server_certificate_digest()
                ));
                ui.label("Do not fund or treat this pending envelope as usable. Ordinary unlock rejects this pending format. Preserve the exact directory and original witness origin.");
                #[cfg(feature = "pending-birth-owner-signing")]
                ui.label("Close this ceremony, then select Reopen authenticated pending account for separately reviewed request/signing/export/acknowledgement. Closing does not delete the saved envelope.");
            }
            None => {
                action = Action::Cancel;
            }
        }
        if ui
            .button("Cancel / close pending ceremony")
            .clicked_by(egui::PointerButton::Primary)
        {
            action = Action::Cancel;
        }
        let outcome = match action {
            Action::None => return None,
            Action::Review => self.stage_backup_and_review(epoch),
            Action::DeriveConstructionScope => self.derive_construction_scope(epoch),
            Action::DeriveStableRecipientScope => self.derive_stable_recipient_scope(epoch),
            Action::Continue => self.continue_review(focused, epoch),
            Action::Publish => self.publish_from_native_click(focused, epoch),
            Action::Cancel => {
                self.clear();
                return Some(
                    "Pending ceremony closed. Any already-published pending envelope is retained unchanged and remains unusable.",
                );
            }
        };
        if outcome.is_err() {
            self.clear();
            let message = "Pending birth failed closed. No substitute approval or witness origin was used. Preserve any partial directory; no account was activated.";
            ui.label(message);
            Some(message)
        } else {
            None
        }
    }
}
impl Drop for NativeBirthCeremony {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Syntax and exact-data checks only. This function cannot create a native
/// source, decision, birth approval or witness authentication.
fn parse_setup(bytes: &str, account_id: &str, network: &str) -> Result<PublicBirthSetup> {
    if bytes.len() > MAX_SETUP_BYTES {
        return Err(Error::InvalidData);
    }
    let setup: PublicBirthSetup = serde_json::from_str(bytes).map_err(|_| Error::InvalidData)?;
    setup
        .disclosure
        .validate()
        .map_err(|_| Error::InvalidData)?;
    setup
        .original_policy
        .validate()
        .map_err(|_| Error::InvalidData)?;
    if setup.original_policy.account_use_genesis.is_some()
        || setup.disclosure.account_id != account_id
        || setup.original_policy.account_id != account_id
        || setup.disclosure.network_profile_id != network
        || setup.original_policy.network_profile_id != network
        || setup.disclosure.witness_id != setup.original_policy.witness_id
        || setup.disclosure.policy_digest
            != setup
                .original_policy
                .policy_digest()
                .map_err(|_| Error::InvalidData)?
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(setup)
}

/// Pure draft transformation, not an owner or approval factory. Callers cannot
/// use it to modify retained policy because publication has its own sealed owner.
fn derive_construction_draft(
    setup_json: &str,
    proposal_json: &str,
    account_id: &str,
    network: &str,
) -> Result<(Zeroizing<String>, String)> {
    if proposal_json.len() > MAX_SETUP_BYTES {
        return Err(Error::InvalidData);
    }
    let mut setup = parse_setup(setup_json, account_id, network)?;
    let input: wholepact_core::ProposalInput =
        serde_json::from_str(proposal_json).map_err(|_| Error::InvalidData)?;
    let proposal =
        wholepact_core::Proposal::validate(input.clone()).map_err(|_| Error::InvalidData)?;
    if proposal.manifest().agreement.network_profile_id != network
        || !setup
            .original_policy
            .agreement_ids
            .contains(&proposal.manifest().agreement.agreement_id)
        || !proposal
            .manifest()
            .participants
            .iter()
            .any(|p| p.account_id == account_id)
    {
        return Err(Error::ReviewMismatch);
    }
    let digest = wholepact_core::manual_construction::construction_payment_scope_digest(&input)
        .map_err(|_| Error::InvalidData)?;
    if !setup
        .original_policy
        .recipient_scope_digests
        .contains(&digest)
    {
        setup
            .original_policy
            .recipient_scope_digests
            .push(digest.clone());
        setup.original_policy.recipient_scope_digests.sort();
    }
    setup
        .original_policy
        .validate()
        .map_err(|_| Error::InvalidData)?;
    setup.disclosure.policy_digest = setup
        .original_policy
        .policy_digest()
        .map_err(|_| Error::InvalidData)?;
    let updated =
        Zeroizing::new(serde_json::to_string_pretty(&setup).map_err(|_| Error::InvalidData)?);
    parse_setup(&updated, account_id, network)?;
    Ok((updated, digest))
}

#[cfg(test)]
mod tests;

fn parse_stable_recipient_policy(
    json: &str,
) -> Result<wholepact_core::born_recipient_policy_v2::BornConstructionRecipientPolicyV2> {
    if json.len() > 96 * 1024 {
        return Err(Error::InvalidData);
    }
    let policy: wholepact_core::born_recipient_policy_v2::BornConstructionRecipientPolicyV2 =
        serde_json::from_str(json).map_err(|_| Error::InvalidData)?;
    policy.validate().map_err(|_| Error::InvalidData)?;
    Ok(policy)
}
fn derive_stable_recipient_draft(
    setup_json: &str,
    policy_json: &str,
    account_id: &str,
    network: &str,
) -> Result<(Zeroizing<String>, String)> {
    let mut setup = parse_setup(setup_json, account_id, network)?;
    let policy = parse_stable_recipient_policy(policy_json)?;
    let p = &setup.original_policy;
    let l = &policy.original_limits;
    if policy.account_id != account_id
        || policy.network_profile_id != network
        || !p.agreement_ids.contains(&policy.agreement_id)
        || p.aggregate_budget_zatoshis != l.aggregate_budget_zatoshis
        || p.per_operation_limit_zatoshis != l.per_operation_limit_zatoshis
        || p.maximum_fee_share_zatoshis != l.maximum_fee_share_zatoshis
        || p.maximum_transaction_fee_zatoshis != l.maximum_transaction_fee_zatoshis
        || p.maximum_permit_lifetime_ms != l.maximum_permit_lifetime_ms
        || p.policy_expires_at_ms != l.policy_expires_at_ms
    {
        return Err(Error::ReviewMismatch);
    }
    let digest = policy.digest().map_err(|_| Error::InvalidData)?;
    if !setup
        .original_policy
        .recipient_scope_digests
        .contains(&digest)
    {
        setup.original_policy.recipient_scope_digests.push(digest);
        setup.original_policy.recipient_scope_digests.sort();
    }
    setup
        .original_policy
        .validate()
        .map_err(|_| Error::InvalidData)?;
    setup.disclosure.policy_digest = setup
        .original_policy
        .policy_digest()
        .map_err(|_| Error::InvalidData)?;
    let updated =
        Zeroizing::new(serde_json::to_string_pretty(&setup).map_err(|_| Error::InvalidData)?);
    parse_setup(&updated, account_id, network)?;
    Ok((
        updated,
        policy
            .native_review_text()
            .map_err(|_| Error::InvalidData)?,
    ))
}
