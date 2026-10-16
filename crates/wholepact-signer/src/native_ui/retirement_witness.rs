//! Separate exact native read of configured surviving-witness history.
//! No mutation, writer activation, wallet access or retirement readiness issuer.
use super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision, authority::ExactNativeReview,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{Error, Result, account::AccountVault};
use eframe::egui;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use wholepact_authority::{ReconciledAuthorityHistory, WitnessDisclosureDescriptor};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize)]
struct ReadRequest {
    version: u16,
    purpose: &'static str,
    local_recipient: &'static str,
    source_account_id: String,
    source_fvk_digest: String,
    witness: WitnessDisclosureDescriptor,
    review_nonce: String,
}
struct PreparedRead {
    request: ReadRequest,
    native: NativeAuthorityBinding,
    started: Instant,
    digest: String,
}
struct ApprovedRead(PreparedRead);
impl PreparedRead {
    fn prepare(
        vault: &AccountVault,
        native: &NativeAuthority,
        witness: &NativeWitnessWorkspace,
    ) -> Result<Self> {
        native.check_current()?;
        witness.check_current()?;
        if vault.account().recovery_required() {
            return Err(Error::RecoveryRequired);
        }
        let account = vault.account_id()?;
        let disclosure = witness.disclosure();
        if disclosure.account_id != account
            || disclosure.network_profile_id != wholepact_protocol::construction::PROFILE_ID
        {
            return Err(Error::ReviewMismatch);
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| Error::Crypto)?;
        Self::bind(
            native,
            ReadRequest {
                version: 1,
                purpose: "read_surviving_witness_retirement_facts_only",
                local_recipient: "native-retirement-witness-panel",
                source_account_id: account,
                source_fvk_digest: hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes())),
                witness: disclosure,
                review_nonce: hex::encode(nonce),
            },
        )
    }
    fn bind(native: &NativeAuthority, request: ReadRequest) -> Result<Self> {
        native.check_current()?;
        if request.version != 1
            || request.purpose != "read_surviving_witness_retirement_facts_only"
            || request.local_recipient != "native-retirement-witness-panel"
            || request.review_nonce.len() != 32
            || !request.review_nonce.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::InvalidData);
        }
        wholepact_core::proposal::validate_sha256(&request.source_fvk_digest)
            .map_err(|_| Error::InvalidData)?;
        request.witness.validate().map_err(|_| Error::InvalidData)?;
        if request.source_account_id != request.witness.account_id {
            return Err(Error::ReviewMismatch);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-retirement-witness-read:v1",
            &(&request, native.principal_id(), native.measurement()),
        )
        .map_err(|_| Error::InvalidData)?;
        Ok(Self {
            request,
            native: native.binding(),
            started: Instant::now(),
            digest,
        })
    }
    fn check_native(&self) -> Result<()> {
        self.native.check_current()?;
        if self.started.elapsed() >= Duration::from_secs(120) {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn display(&self) -> Result<String> {
        self.check_native()?;
        let detail = serde_json::to_string_pretty(&self.request).map_err(|_| Error::InvalidData)?;
        Ok(format!(
            "Read private surviving-witness history for retirement evidence.\nThis separately permits a network read using the exact already configured witness below. It does not reuse source-identity consent. Complete bounded namespace replay only; cancellation/expiry discards results and never returns a partial fold.\nNo writer activation, reserve, signing, transfer or exclusion operation is permitted. Historical exposure remains charged. Earliest chain activity, canonical unspentness, complete external pending transactions and absence of cloned keys remain UNKNOWN.\nFacts stay in this local native panel until clear/lock/blur/expiry. No FVK is exported.\n{detail}\nExact review: {}",
            self.digest
        ))
    }
    fn approve(self, native: &NativeAuthority, decision: NativeDecision) -> Result<ApprovedRead> {
        self.check_native()?;
        native.check_current()?;
        if native.binding() != self.native
            || decision.binding() != &self.native
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedRead(self))
    }
}
impl ApprovedRead {
    fn check_worker(&self, witness: &NativeWitnessWorkspace, cancel: &AtomicBool) -> Result<()> {
        self.0.check_native()?;
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Locked);
        }
        witness.check_current()?;
        if witness.disclosure() != self.0.request.witness {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn require_source(&self, vault: &AccountVault) -> Result<()> {
        self.0.check_native()?;
        if vault.account().recovery_required()
            || vault.account_id()? != self.0.request.source_account_id
            || hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes()))
                != self.0.request.source_fvk_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn collect(
        self,
        witness: Arc<NativeWitnessWorkspace>,
        cancel: Arc<AtomicBool>,
    ) -> Result<Observation> {
        self.check_worker(&witness, &cancel)?;
        let history = witness
            .client()
            .reconcile_history_checked(|| {
                self.check_worker(&witness, &cancel)
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        self.check_worker(&witness, &cancel)?;
        let text = project_history(&history, &self.0.request)?;
        self.check_worker(&witness, &cancel)?;
        Ok(Observation { owner: self, text })
    }
}
fn project_history(
    history: &ReconciledAuthorityHistory,
    request: &ReadRequest,
) -> Result<Zeroizing<String>> {
    if history.disclosure() != &request.witness
        || history.snapshot().account_id != request.source_account_id
        || history.snapshot().network_profile_id != request.witness.network_profile_id
        || history.account_policy().account_id != request.source_account_id
    {
        return Err(Error::Authentication);
    }
    if let Some(genesis) = history.account_use_history().genesis() {
        if genesis.identity.full_viewing_key_digest != request.source_fvk_digest {
            return Err(Error::Authentication);
        }
    }
    let facts = history
        .retirement_history_facts()
        .map_err(|_| Error::Authentication)?;
    let encoded = serde_json::to_string_pretty(&facts).map_err(|_| Error::InvalidData)?;
    if encoded.len() > 65536 {
        return Err(Error::InvalidData);
    }
    Ok(Zeroizing::new(format!(
        "Authenticated surviving-witness namespace observation at the displayed head. This is historical evidence, not a current reservation/retirement lease.\n{encoded}\nComplete external history and readiness remain UNKNOWN. No witness or signer state was changed."
    )))
}
struct Observation {
    owner: ApprovedRead,
    text: Zeroizing<String>,
}
struct Worker {
    deadline: Instant,
    cancel: Arc<AtomicBool>,
    receive: mpsc::Receiver<Result<Observation>>,
    handle: JoinHandle<()>,
}
#[derive(Default)]
pub(super) struct RetirementWitnessUi {
    prepared: Option<PreparedRead>,
    review: Option<ExactNativeReview>,
    confirmation: Zeroizing<String>,
    worker: Option<Worker>,
    draining: Vec<JoinHandle<()>>,
    result: Option<Observation>,
    epoch: Option<u64>,
    message: &'static str,
}
impl RetirementWitnessUi {
    pub(super) fn clear(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.cancel.store(true, Ordering::Release);
            self.draining.push(worker.handle);
        }
        self.prepared = None;
        self.review = None;
        self.confirmation.zeroize();
        self.result = None;
        self.epoch = None;
    }
    pub(super) fn poll_lifecycle(&mut self, focused: bool, epoch: u64) {
        if !focused
            || self.epoch.is_some_and(|e| e != epoch)
            || self
                .worker
                .as_ref()
                .is_some_and(|w| Instant::now() >= w.deadline)
            || self
                .prepared
                .as_ref()
                .is_some_and(|p| p.check_native().is_err())
            || self
                .result
                .as_ref()
                .is_some_and(|r| r.owner.0.check_native().is_err())
        {
            self.clear();
        }
        let mut pending = Vec::new();
        for handle in self.draining.drain(..) {
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                pending.push(handle);
            }
        }
        self.draining = pending;
        let outcome = self.worker.as_ref().map(|w| w.receive.try_recv());
        match outcome {
            Some(Ok(result)) => {
                let worker = self.worker.take().unwrap();
                self.draining.push(worker.handle);
                match result {
                    Ok(observed)
                        if self.epoch == Some(epoch)
                            && focused
                            && observed.owner.0.check_native().is_ok() =>
                    {
                        self.result = Some(observed);
                        self.message = "Complete configured-witness observation received. External history and retirement readiness remain unknown.";
                    }
                    _ => {
                        self.result = None;
                        self.message = "Read failed, expired or was cancelled. No partial or replacement observation is accepted.";
                    }
                }
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.clear();
                self.message = "Witness read stopped. No evidence or authority was created.";
            }
            _ => (),
        }
    }
    pub(super) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        vault: &AccountVault,
        native: &NativeAuthority,
        witness: Option<&Arc<NativeWitnessWorkspace>>,
        focused: bool,
        epoch: u64,
    ) {
        if !focused || native.check_current().is_err() {
            self.clear();
            return;
        }
        if self.result.as_ref().is_some_and(|r| {
            r.owner.require_source(vault).is_err()
                || witness.is_none_or(|w| {
                    w.disclosure() != r.owner.0.request.witness || w.check_current().is_err()
                })
        }) {
            self.clear();
        }
        ui.collapsing("Retirement: separately read surviving witness history", |ui| {
            ui.label("Private network read of the exact previously configured witness only. No scan, spending or exclusion authority. Namespace completeness does not prove global account completeness.");
            if self.worker.is_some() || !self.draining.is_empty() { ui.label("Prior witness read is running or draining. A new read cannot start yet."); }
            let idle = self.worker.is_none() && self.draining.is_empty() && self.review.is_none();
            if ui.add_enabled(idle && witness.is_some(), egui::Button::new("Review exact surviving-witness read")).clicked_by(egui::PointerButton::Primary) {
                self.result = None;
                let result = (|| {
                    let prepared = PreparedRead::prepare(vault, native, witness.ok_or(Error::Locked)?)?;
                    self.review = Some(ExactNativeReview::stage(native, &prepared.digest, prepared.display()?, epoch)?);
                    self.prepared = Some(prepared);
                    self.epoch = Some(epoch);
                    Ok::<_, Error>(())
                })();
                if result.is_err() { self.clear(); self.message = "Witness read review failed closed."; }
            }
            let mut approve = false;
            let mut failed = false;
            if let Some(review) = &mut self.review {
                ui.label(review.display());
                if !review.confirming() {
                    if ui.button("Continue exact witness-read review").clicked_by(egui::PointerButton::Primary) && review.continue_from_native_click(focused, epoch).is_err() { failed = true; }
                } else {
                    ui.label(format!("Type AUTHORIZE {}", &review.digest()[..12]));
                    ui.add(egui::TextEdit::singleline(&mut *self.confirmation).char_limit(32));
                    approve = ui.button("Approve only this bounded witness read").clicked_by(egui::PointerButton::Primary);
                }
            }
            if approve {
                let result = (|| {
                    let decision = self.review.take().ok_or(Error::Locked)?.consume_native_click(focused, epoch, &self.confirmation)?;
                    let approved = self.prepared.take().ok_or(Error::Locked)?.approve(native, decision)?;
                    approved.require_source(vault)?;
                    let witness = witness.ok_or(Error::Locked)?.clone();
                    let cancel = Arc::new(AtomicBool::new(false));
                    approved.check_worker(&witness, &cancel)?;
                    let deadline = approved.0.started + Duration::from_secs(120);
                    let worker_cancel = cancel.clone();
                    let (send, receive) = mpsc::sync_channel(1);
                    let handle = std::thread::spawn(move || { let _ = send.send(approved.collect(witness, worker_cancel)); });
                    self.worker = Some(Worker { deadline, cancel, receive, handle });
                    Ok::<_, Error>(())
                })();
                self.confirmation.zeroize();
                if result.is_err() { failed = true; }
            }
            if failed { self.clear(); self.message = "Witness read decision mismatched or expired. No read authority retained."; }
            if let Some(result) = &self.result { ui.label(super::state::inert_text(&result.text)); }
            ui.label(self.message);
            if ui.button("Cancel read and clear witness facts").clicked_by(egui::PointerButton::Primary) { self.clear(); }
        });
    }
}
impl Drop for RetirementWitnessUi {
    fn drop(&mut self) {
        self.clear();
        for handle in self.draining.drain(..) {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::authority::{recovery_test_authority, recovery_test_decision};
    use super::*;
    fn request() -> ReadRequest {
        ReadRequest {
            version: 1,
            purpose: "read_surviving_witness_retirement_facts_only",
            local_recipient: "native-retirement-witness-panel",
            source_account_id: "synthetic-source".into(),
            source_fvk_digest: "11".repeat(32),
            witness: WitnessDisclosureDescriptor {
                endpoint: "127.0.0.1:1".into(),
                server_name: "synthetic.invalid".into(),
                witness_id: "synthetic-witness".into(),
                account_id: "synthetic-source".into(),
                network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
                policy_digest: "22".repeat(32),
                pinned_server_certificate_digest: "33".repeat(32),
            },
            review_nonce: "44".repeat(16),
        }
    }
    #[test]
    fn witness_read_approval_is_exact_and_cannot_reuse_another_native_window() {
        let native = recovery_test_authority();
        let other = recovery_test_authority();
        let prepared = PreparedRead::bind(&native, request()).unwrap();
        let decision = recovery_test_decision(&other, &prepared.digest);
        assert!(prepared.approve(&native, decision).is_err());
        let prepared = PreparedRead::bind(&native, request()).unwrap();
        let decision = recovery_test_decision(&native, &"55".repeat(32));
        assert!(prepared.approve(&native, decision).is_err());
        let prepared = PreparedRead::bind(&native, request()).unwrap();
        let decision = recovery_test_decision(&native, &prepared.digest);
        let approved = prepared.approve(&native, decision).unwrap();
        native.invalidate();
        assert!(approved.0.check_native().is_err());
    }
    #[test]
    fn witness_read_original_deadline_and_exact_endpoint_remain_bound() {
        let native = recovery_test_authority();
        let mut prepared = PreparedRead::bind(&native, request()).unwrap();
        let mut other = request();
        other.witness.pinned_server_certificate_digest = "66".repeat(32);
        assert_ne!(
            prepared.digest,
            PreparedRead::bind(&native, other).unwrap().digest
        );
        prepared.started = Instant::now() - Duration::from_secs(121);
        let decision = recovery_test_decision(&native, &prepared.digest);
        assert!(prepared.approve(&native, decision).is_err());
    }
    #[test]
    fn identity_only_purpose_and_changed_epoch_cannot_authorize_witness_read() {
        let native = recovery_test_authority();
        let mut wrong = request();
        wrong.purpose = "local_identity_only";
        assert!(PreparedRead::bind(&native, wrong).is_err());
        let prepared = PreparedRead::bind(&native, request()).unwrap();
        let review =
            ExactNativeReview::stage(&native, &prepared.digest, prepared.display().unwrap(), 7)
                .unwrap();
        let mut ui = RetirementWitnessUi {
            review: Some(review),
            prepared: Some(prepared),
            epoch: Some(7),
            confirmation: Zeroizing::new(String::new()),
            worker: None,
            draining: Vec::new(),
            result: None,
            message: "",
        };
        ui.poll_lifecycle(true, 8);
        assert!(ui.review.is_none() && ui.prepared.is_none() && ui.worker.is_none());
    }
    #[test]
    fn cancelled_read_worker_is_retained_and_drained_without_network_or_authority() {
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (send, receive) = mpsc::sync_channel(1);
        let handle = std::thread::spawn(move || {
            while !worker_cancel.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            let _ = send.send(Err(Error::Locked));
        });
        let mut ui = RetirementWitnessUi {
            worker: Some(Worker {
                deadline: Instant::now() + Duration::from_secs(120),
                cancel: cancel.clone(),
                receive,
                handle,
            }),
            prepared: None,
            review: None,
            confirmation: Zeroizing::new(String::new()),
            draining: Vec::new(),
            result: None,
            epoch: None,
            message: "",
        };
        ui.clear();
        assert!(cancel.load(Ordering::Acquire));
        assert!(ui.worker.is_none());
        assert_eq!(ui.draining.len(), 1);
        drop(ui); // joins the cancelled pure worker; no authenticated owner exists.
    }
}
