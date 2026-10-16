//! Native local source/destination evidence collection only. No IPC endpoint,
//! wallet query, signing route, complete-evidence assertion or exclusion writer.
use super::retirement_destination::{PreparedRecoveryDestination, RecoveryDestinationRequest};
use super::retirement_source::{PreparedRetirementSource, RetirementSourceRead};
use super::{NativeAuthority, authority::ExactNativeReview};
use crate::{Error, Result, account::AccountVault};
use eframe::egui;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
pub(super) struct RetirementEvidenceUi {
    destination_path: String,
    password: Zeroizing<String>,
    address: String,
    operation: String,
    confirmation: Zeroizing<String>,
    active: Option<Inspection>,
    message: &'static str,
}
struct Inspection {
    destination: AccountVault,
    request: RecoveryDestinationRequest,
    prepared_source: Option<PreparedRetirementSource>,
    source: Option<RetirementSourceRead>,
    review: Option<ExactNativeReview>,
    result: Option<Zeroizing<String>>,
    epoch: u64,
}
impl RetirementEvidenceUi {
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }
    pub(super) fn poll_lifecycle(&mut self, focused: bool, epoch: u64) {
        if !focused
            || self.active.as_ref().is_some_and(|a| {
                a.epoch != epoch
                    || a.review.as_ref().is_some_and(|r| r.expired())
                    || a.source
                        .as_ref()
                        .is_some_and(|s| s.check_liveness().is_err())
            })
        {
            self.clear();
        }
    }
    fn begin(&mut self, source: &AccountVault, native: &NativeAuthority, epoch: u64) -> Result<()> {
        self.active = None;
        let unlocked = AccountVault::unlock(
            std::path::Path::new(&self.destination_path),
            self.password.as_bytes(),
        );
        self.password.zeroize();
        let destination = unlocked?;
        native.check_current()?;
        let request = RecoveryDestinationRequest {
            operation_id: self.operation.clone(),
            destination_account_id: destination.account_id()?,
            address: self.address.clone(),
            network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
            source_account_id: source.account_id()?,
            source_fvk_digest: hex::encode(Sha256::digest(source.account().fvk()?.to_bytes())),
            local_recipient: "native-retirement-evidence-panel".into(),
        };
        // Actual destination ownership is checked before any review, and checked
        // again after the separate destination native decision.
        PreparedRecoveryDestination::prepare(&destination, native, request.clone())?;
        let prepared = PreparedRetirementSource::prepare(source, native, &request)?;
        let review =
            ExactNativeReview::stage(native, prepared.digest(), prepared.display(), epoch)?;
        self.active = Some(Inspection {
            destination,
            request,
            prepared_source: Some(prepared),
            source: None,
            review: Some(review),
            result: None,
            epoch,
        });
        Ok(())
    }
    pub(super) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        vault: &AccountVault,
        native: &NativeAuthority,
        focused: bool,
        epoch: u64,
    ) {
        if !focused
            || native.check_current().is_err()
            || self.active.as_ref().is_some_and(|a| {
                a.epoch != epoch
                    || a.review.as_ref().is_some_and(|r| r.expired())
                    || a.source
                        .as_ref()
                        .is_some_and(|s| s.check_destination(vault, &a.request).is_err())
            })
        {
            self.clear();
            return;
        }
        ui.collapsing("Retirement: inspect local source and destination evidence", |ui| {
            ui.label("Local identity/ownership evidence only. Complete account history and balances remain unknown. No reclaim, funds movement, signing or retirement completion is available.");
            if self.active.is_none() {
                ui.label("Existing independently controlled destination account directory");
                ui.add(egui::TextEdit::singleline(&mut self.destination_path).char_limit(4096));
                ui.label("Destination account passphrase (cleared after unlock)");
                ui.add(egui::TextEdit::singleline(&mut *self.password).password(true).char_limit(1024));
                ui.label("Exact destination shielded address");
                ui.add(egui::TextEdit::singleline(&mut self.address).char_limit(1024));
                ui.label("Local evidence operation identifier");
                ui.add(egui::TextEdit::singleline(&mut self.operation).char_limit(128));
                if ui.button("Unlock destination and review source identity").clicked_by(egui::PointerButton::Primary) && self.begin(vault, native, epoch).is_err() {
                    self.active = None;
                    self.message = "Evidence preparation failed closed. No source permission or destination ownership fact was issued.";
                }
            }
            let mut consume = false;
            let mut failed = false;
            if let Some(active) = &mut self.active {
                if let Some(review) = &mut active.review {
                    ui.label(review.display());
                    if !review.confirming() {
                        if ui.button("Continue exact evidence review").clicked_by(egui::PointerButton::Primary) && review.continue_from_native_click(focused, epoch).is_err() { failed = true; }
                    } else {
                        ui.label(format!("Type AUTHORIZE {}", &review.digest()[..12]));
                        ui.add(egui::TextEdit::singleline(&mut *self.confirmation).char_limit(32));
                        consume = ui.button("Approve this exact local evidence scope").clicked_by(egui::PointerButton::Primary);
                    }
                }
                if let Some(result) = &active.result { ui.label(super::state::inert_text(result)); }
            }
            if consume {
                let result = self.advance(vault, native, focused, epoch);
                self.confirmation.zeroize();
                if result.is_err() { failed = true; }
            }
            if failed {
                self.active = None;
                self.confirmation.zeroize();
                self.message = "Evidence review expired or mismatched. Start a new exact review; no financial permission was granted.";
            }
            ui.label(self.message);
            if ui.button("Clear retirement evidence and lock destination").clicked_by(egui::PointerButton::Primary) { self.clear(); }
        });
    }
    fn advance(
        &mut self,
        vault: &AccountVault,
        native: &NativeAuthority,
        focused: bool,
        epoch: u64,
    ) -> Result<()> {
        let active = self.active.as_mut().ok_or(Error::Locked)?;
        let decision = active
            .review
            .take()
            .ok_or(Error::Locked)?
            .consume_native_click(focused, epoch, &self.confirmation)?;
        if let Some(prepared) = active.prepared_source.take() {
            let source = prepared.approve(vault, native, decision)?;
            source.check_destination(vault, &active.request)?;
            let destination = PreparedRecoveryDestination::prepare(
                &active.destination,
                native,
                active.request.clone(),
            )?;
            active.review = Some(ExactNativeReview::stage(
                native,
                destination.digest(),
                destination.display(),
                epoch,
            )?);
            active.source = Some(source);
            self.message = "Source identity inspection approved. Destination ownership requires its own exact native decision.";
        } else {
            let source = active.source.as_ref().ok_or(Error::Locked)?;
            source.check_destination(vault, &active.request)?;
            let prepared = PreparedRecoveryDestination::prepare(
                &active.destination,
                native,
                active.request.clone(),
            )?;
            let approved = prepared.approve(decision, native)?;
            let evidence = approved.evidence_for_retirement_source(source, vault)?;
            active.result = Some(Zeroizing::new(format!(
                "Local evidence collected for source {} and destination {}.\nExact destination: {}\nOwnership review: {}\nEarliest activity, all account components, complete pending/full transactions, independent canonical unspentness and all authorization/reservation history: UNKNOWN.\nRetirement completion: UNAVAILABLE. Reclaim/signing/exclusion authority: NONE.\nThis is an observation of the unlocked local vaults, not independently verified current chain state or proof of exclusive key ownership.",
                active.request.source_account_id,
                evidence.user_controlled_account_ref,
                evidence.address,
                evidence.ownership_evidence_digest
            )));
            self.message = "Local identity and destination ownership evidence collected. Complete retirement evidence remains unavailable.";
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "synthetic-qualification")]
    #[test]
    fn native_retirement_preparation_is_discarded_by_epoch_change_before_panel_display() {
        use crate::account::PendingAccount;
        let dir = tempfile::tempdir().unwrap();
        let vault = |name: &str, index: u8| {
            let pending = PendingAccount::fixed_never_funded_qualification(index).unwrap();
            let words = pending.recovery_words().unwrap();
            AccountVault::create(
                &dir.path().join(name),
                pending.verify_backup(&words).unwrap(),
                b"synthetic-retirement-ui",
            )
            .unwrap()
        };
        let source = vault("source", 0);
        let destination = vault("destination", 1);
        let native = super::super::authority::recovery_test_authority();
        let mut state = RetirementEvidenceUi {
            destination_path: dir.path().join("destination").to_str().unwrap().into(),
            ..RetirementEvidenceUi::default()
        };
        state.password.push_str("synthetic-retirement-ui");
        state.operation = "synthetic-native-preparation".into();
        state.address = wholepact_protocol::review::encode_testnet_receiver(
            &destination
                .account()
                .fvk()
                .unwrap()
                .address_at(0u32, orchard::keys::Scope::External),
        );
        drop(destination); // The real form unlocks a closed destination vault.
        state.begin(&source, &native, 7).unwrap();
        assert!(state.password.is_empty());
        assert!(state.active.as_ref().unwrap().source.is_none());
        state.poll_lifecycle(true, 8);
        assert!(state.active.is_none());
        assert!(state.address.is_empty());
    }
    #[test]
    fn clearing_retirement_review_discards_private_fields_and_no_authority_is_created() {
        let mut state = RetirementEvidenceUi {
            destination_path: "synthetic-private-path".into(),
            ..RetirementEvidenceUi::default()
        };
        state.password.push_str("synthetic-passphrase");
        state.address = "synthetic-address".into();
        state.operation = "synthetic-operation".into();
        state.confirmation.push_str("synthetic-confirmation");
        state.clear();
        assert!(state.active.is_none());
        assert!(state.password.is_empty() && state.confirmation.is_empty());
        assert!(
            state.destination_path.is_empty()
                && state.address.is_empty()
                && state.operation.is_empty()
        );
    }
}
