//! Separate locked-account recovery surface. Never creates OpenAccount, local
//! IPC, a spending grant, or authority from a restored witness backup.
use super::{authority::ExactNativeReview, witness_workspace::*, NativeAuthority, NativeDecision};
use crate::{
    account::{backup, AccountVault},
    consent_journal::{PreparedRecoveryActivation, RecoveryActivationInventory},
    Error, Result,
};
use eframe::egui;
use std::{
    path::{Path, PathBuf},
    sync::{mpsc, Arc},
    time::Instant,
};
use wholepact_authority::{OwnerControl, OwnerControlRequest, WriterSessionReceipt};
use wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource;
use zeroize::{Zeroize, Zeroizing};

pub(super) struct RecoveryInputs<'a> {
    pub(super) focused: bool,
    pub(super) epoch: u64,
    pub(super) idle: bool,
    pub(super) root: &'a str,
    pub(super) archive: &'a str,
    pub(super) password: &'a [u8],
    pub(super) recovery_password: &'a [u8],
}
#[derive(Default)]
pub(super) struct RecoveryUi {
    destination: String,
    new_password: Zeroizing<String>,
    repeat_password: Zeroizing<String>,
    writer_json: Zeroizing<String>,
    owner_json: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    state: Option<RecoveryState>,
    pending: Option<(ExactNativeReview, Decision)>,
    job: Option<mpsc::Receiver<Result<Completed>>>,
    message: String,
}
struct RecoveryState {
    authority: Arc<NativeAuthority>,
    vault: Arc<AccountVault>,
    source: Option<Arc<VerifiedSignerRecoverySource>>,
    writer: Option<Arc<NativeWitnessWorkspace>>,
    owner: Option<Arc<NativeWitnessWorkspace>>,
    inventory: Option<RecoveryActivationInventory>,
    owner_recovered: bool,
    session: Option<WriterSessionReceipt>,
    session_active: bool,
    session_retry: Option<Arc<ApprovedWriterSession>>,
    activation_retry: Option<Arc<ApprovedWriterActivation>>,
}
// Exactly one bounded pending native review is held; its complete authenticated
// history remains owned with the decision rather than detached behind a clone.
#[allow(clippy::large_enum_variant)]
enum Decision {
    Setup(bool, PreparedWitnessSetup),
    Fence(PreparedOwnerRecovery),
    Pause(PreparedOwnerPause),
    Session(PreparedWriterSession),
    Activate(PreparedWriterActivation),
    Publish(PreparedRecoveryActivation),
}
enum Completed {
    Review(Box<Decision>),
    OwnerRecovered,
    Session(Box<WriterSessionReceipt>),
    SessionActive,
    SessionReset,
    Published(PathBuf),
}
struct PreparedOwnerRecovery {
    history: wholepact_authority::ReconciledAuthorityHistory,
    request: OwnerControlRequest,
    digest: String,
    display: String,
    source: super::NativeAuthorityBinding,
    owner: Arc<NativeWitnessWorkspace>,
    created: Instant,
}
impl PreparedOwnerRecovery {
    fn prepare(
        owner: Arc<NativeWitnessWorkspace>,
        inventory: RecoveryActivationInventory,
        authority: &NativeAuthority,
        saved: Option<OwnerControlRequest>,
        original: &VerifiedSignerRecoverySource,
    ) -> Result<Self> {
        authority.check_current()?;
        owner.check_current()?;
        let history = owner
            .client()
            .reconcile_history()
            .map_err(|_| Error::Uncertain)?;
        crate::consent_journal::verify_recovery_continuity(original, &history)?;
        let snapshot = history.snapshot();
        owner.check_current()?;
        if snapshot.account_id != inventory.witness().account_id
            || owner.disclosure() != *inventory.witness()
            || snapshot.writer_certificate_digest == owner.writer_certificate_digest()
        {
            return Err(Error::Authentication);
        }
        let mut request = saved.unwrap_or(OwnerControlRequest {
            operation_id: inventory.operation_id().to_owned(),
            account_id: snapshot.account_id.clone(),
            network_profile_id: snapshot.network_profile_id.clone(),
            expected_head: snapshot.head.clone(),
            writer_epoch: snapshot.writer_epoch,
            control: OwnerControl::RecoverWriter {
                writer_certificate_digest: inventory
                    .successor_writer_certificate_digest()
                    .to_owned(),
                inventory_digest: inventory.digest()?,
            },
        });
        if let Some(committed) = history.owner_control_request(inventory.operation_id()) {
            request = committed.clone();
        } else {
            if history.contains_operation(&request.operation_id) {
                return Err(Error::Authentication);
            }
            // Exact absent operation only: preserve ID/content/epoch and require
            // a new native decision over this authenticated current head.
            request.expected_head = snapshot.head.clone();
        }
        if request.operation_id != inventory.operation_id()
            || request.account_id != snapshot.account_id
            || request.network_profile_id != snapshot.network_profile_id
            || request.control
                != (OwnerControl::RecoverWriter {
                    writer_certificate_digest: inventory
                        .successor_writer_certificate_digest()
                        .to_owned(),
                    inventory_digest: inventory.digest()?,
                })
        {
            return Err(Error::Authentication);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-owner-profile-recovery:v1",
            &(
                &request,
                &inventory,
                &snapshot,
                owner.writer_certificate_digest(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "Independent owner: fence the old writer for exact profile recovery\nAccount: {}\nWitness: {}\nEndpoint: {}\nOld epoch: {}\nCurrent witness head: {} / {}\nRecovery operation: {}\nInventory digest: {}\nNew generation: {}\nNEW destination: {}\nSuccessor certificate: {}\n\nThis advances the independent witness writer epoch. Existing signed transactions and every historical reservation remain possible exposure. This does not cancel them, create a spending approval, activate a restored witness, or prove current wallet state. Uncertain responses must be investigated using this same operation; never silently replace it.",
            snapshot.account_id,
            snapshot.witness_id,
            owner.disclosure().endpoint,
            snapshot.writer_epoch,
            snapshot.head.sequence,
            snapshot.head.digest,
            request.operation_id,
            inventory.digest()?,
            inventory.generation_id(),
            inventory.target_profile().display(),
            inventory.successor_writer_certificate_digest()
        );
        Ok(Self {
            history,
            request,
            digest,
            display,
            source: authority.binding(),
            owner,
            created: Instant::now(),
        })
    }
    fn execute(self, decision: NativeDecision, authority: &NativeAuthority) -> Result<()> {
        authority.check_current()?;
        self.source.check_current()?;
        self.owner.check_current()?;
        if authority.binding() != self.source
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.created.elapsed().as_secs() >= 120
        {
            return Err(Error::ReviewMismatch);
        }
        self.owner
            .client()
            .control(self.request)
            .map_err(|_| Error::Uncertain)?;
        self.source.check_current()?;
        Ok(())
    }
}
struct PreparedOwnerPause {
    request: OwnerControlRequest,
    digest: String,
    display: String,
    source: super::NativeAuthorityBinding,
    owner: Arc<NativeWitnessWorkspace>,
    target: PathBuf,
    password: Zeroizing<String>,
    created: Instant,
}
impl PreparedOwnerPause {
    fn prepare(
        owner: Arc<NativeWitnessWorkspace>,
        inventory: RecoveryActivationInventory,
        authority: &NativeAuthority,
        password: Zeroizing<String>,
    ) -> Result<Self> {
        authority.check_current()?;
        owner.check_current()?;
        let history = owner
            .client()
            .reconcile_history()
            .map_err(|_| Error::Uncertain)?;
        let snapshot = history.snapshot();
        let fence = history
            .recovery_fences()
            .iter()
            .find(|r| r.operation_id == inventory.operation_id())
            .ok_or(Error::Authentication)?;
        if history.disclosure() != inventory.witness()
            || fence.inventory_digest != inventory.digest()?
            || fence.writer_certificate_digest != inventory.successor_writer_certificate_digest()
            || snapshot.writer_certificate_digest != fence.writer_certificate_digest
            || snapshot.writer_epoch != fence.writer_epoch
            || snapshot.account_id != fence.account_id
            || owner.writer_certificate_digest() == snapshot.writer_certificate_digest
        {
            return Err(Error::Authentication);
        }
        let pending =
            AccountVault::unlock_pending_recovery(inventory.target_profile(), password.as_bytes())?;
        let mut request = pending
            .saved_recovery_pause()?
            .unwrap_or(OwnerControlRequest {
                operation_id: hex::encode(crate::vault::random::<32>()?),
                account_id: snapshot.account_id.clone(),
                network_profile_id: snapshot.network_profile_id.clone(),
                expected_head: snapshot.head.clone(),
                writer_epoch: snapshot.writer_epoch,
                control: OwnerControl::Pause,
            });
        if let Some(committed) = history.owner_control_request(&request.operation_id) {
            request = committed.clone();
        } else {
            if history.contains_operation(&request.operation_id) {
                return Err(Error::Authentication);
            }
            request.expected_head = snapshot.head.clone();
        }
        if request.account_id != snapshot.account_id
            || request.network_profile_id != snapshot.network_profile_id
            || request.writer_epoch != snapshot.writer_epoch
            || request.control != OwnerControl::Pause
        {
            return Err(Error::Authentication);
        }
        pending.reconcile_recovery_pause(&request, &history)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-recovery-session-reset:v1",
            &(
                &request,
                &inventory,
                fence,
                snapshot,
                history.history_digest().map_err(|_| Error::InvalidData)?,
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!("Independent owner: pause the exact recovered writer session
Account: {}
Witness: {}
Recovery operation: {}
Inventory: {}
Writer epoch: {}
Writer certificate: {}
Pause operation: {}
Original expected head: {} / {}

This clears pending/active ephemeral writer sessions while preserving every reservation and possible signed transaction. Use after losing the original recovery process/session. It does not replace the writer, erase exposure, authorize spending, or change the generation. A fresh session and independent owner activation remain required. An uncertain request is retried with this identical saved operation.", snapshot.account_id, snapshot.witness_id, inventory.operation_id(), inventory.digest()?, snapshot.writer_epoch, snapshot.writer_certificate_digest, request.operation_id, request.expected_head.sequence, request.expected_head.digest);
        authority.check_current()?;
        Ok(Self {
            request,
            digest,
            display,
            source: authority.binding(),
            owner,
            target: inventory.target_profile().to_path_buf(),
            password,
            created: Instant::now(),
        })
    }
    fn execute(self, decision: NativeDecision, authority: &NativeAuthority) -> Result<()> {
        authority.check_current()?;
        self.source.check_current()?;
        self.owner.check_current()?;
        if authority.binding() != self.source
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.created.elapsed().as_secs() >= 120
        {
            return Err(Error::ReviewMismatch);
        }
        self.owner
            .client()
            .control(self.request.clone())
            .map_err(|_| Error::Uncertain)?;
        self.source.check_current()?;
        let pending =
            AccountVault::unlock_pending_recovery(&self.target, self.password.as_bytes())?;
        pending.acknowledge_recovery_pause(&self.request)?;
        Ok(())
    }
}
impl RecoveryUi {
    pub(super) fn is_active(&self) -> bool {
        self.state.is_some() || self.job.is_some()
    }
    pub(super) fn clear(&mut self) {
        if let Some(state) = self.state.take() {
            state.authority.invalidate();
        }
        self.pending = None;
        self.job = None;
        self.new_password.zeroize();
        self.repeat_password.zeroize();
        self.writer_json.zeroize();
        self.owner_json.zeroize();
        self.confirmation.zeroize();
    }
    fn start_job(
        &mut self,
        work: impl FnOnce() -> Result<Completed> + Send + 'static,
    ) -> Result<()> {
        if self.job.is_some() || self.pending.is_some() {
            return Err(Error::Locked);
        }
        let (send, receive) = mpsc::channel();
        self.job = Some(receive);
        std::thread::spawn(move || {
            let _ = send.send(work());
        });
        Ok(())
    }
    fn stage(&mut self, decision: Decision, epoch: u64) -> Result<()> {
        let state = self.state.as_ref().ok_or(Error::Locked)?;
        let (digest, display) = match &decision {
            Decision::Setup(_, p) => (p.digest().to_owned(), p.display()?),
            Decision::Fence(p) => (p.digest.clone(), p.display.clone()),
            Decision::Pause(p) => (p.digest.clone(), p.display.clone()),
            Decision::Session(p) => (p.digest().to_owned(), p.display()?),
            Decision::Activate(p) => (p.digest().to_owned(), p.display()?),
            Decision::Publish(p) => (p.digest().to_owned(), p.display()?),
        };
        self.pending = Some((
            ExactNativeReview::stage(&state.authority, &digest, display, epoch)?,
            decision,
        ));
        Ok(())
    }
    fn poll(&mut self, epoch: u64) -> Result<()> {
        let result = match self.job.as_ref().map(|r| r.try_recv()) {
            Some(Ok(value)) => Some(value),
            Some(Err(mpsc::TryRecvError::Disconnected)) => Some(Err(Error::Uncertain)),
            _ => None,
        };
        if let Some(result) = result {
            self.job = None;
            match result? {
                Completed::Review(decision) => self.stage(*decision, epoch)?,
                Completed::OwnerRecovered => {
                    self.state.as_mut().ok_or(Error::Locked)?.owner_recovered = true;
                    self.message = "Old writer fenced. Review a fresh successor session next; all original exposure remains retained.".into();
                }
                Completed::Session(receipt) => {
                    self.state.as_mut().ok_or(Error::Locked)?.session = Some(*receipt);
                    self.message = "Fresh session pending independent owner approval.".into();
                }
                Completed::SessionReset => {
                    let state = self.state.as_mut().ok_or(Error::Locked)?;
                    state.session = None;
                    state.writer = None; // Drop cached ephemeral possession; require fresh native client review.
                    state.session_active = false;
                    state.session_retry = None;
                    state.activation_retry = None;
                    self.message = "Exact recovered writer paused; old session possession was discarded. Re-review the successor client configuration, then a fresh session and owner activation.".into();
                }
                Completed::SessionActive => {
                    self.state.as_mut().ok_or(Error::Locked)?.session_active = true;
                    self.message = "Fresh successor session activated. Review the exact recovered profile before publication.".into();
                }
                Completed::Published(path) => {
                    self.clear();
                    self.message = format!(
                        "Successor committed at {}. Original quarantine remains unchanged. Explicitly unlock this new path, then separately pair, enroll and rescan before any signing.",
                        path.display()
                    );
                }
            }
        }
        Ok(())
    }
    fn begin(
        &mut self,
        restored: &Path,
        backup_path: &Path,
        password: &[u8],
        recovery_password: &[u8],
    ) -> Result<()> {
        if self.state.is_some()
            || self.job.is_some()
            || self.new_password.len() < 12
            || *self.new_password != *self.repeat_password
        {
            return Err(Error::InvalidData);
        }
        let vault = AccountVault::unlock(restored, password)?;
        if !vault.account().recovery_required() {
            return Err(Error::RecoveryRequired);
        }
        let source = backup::verified_recovery_source(&vault, backup_path, recovery_password)?;
        let inventory = if Path::new(&self.destination).exists() {
            let pending = AccountVault::unlock_pending_recovery(
                Path::new(&self.destination),
                self.new_password.as_bytes(),
            )?;
            let expected = pending.resume_recovery_inventory(source.manifest(), &vault)?;
            let proof = pending.verify_recovery_plan()?;
            let inventory = RecoveryActivationInventory::resume(&source, &proof)?;
            if inventory != expected {
                return Err(Error::Authentication);
            }
            Some(inventory)
        } else {
            None
        };
        let authority = NativeAuthority::entered_native_window()?;
        self.state = Some(RecoveryState {
            authority: Arc::new(authority),
            vault: Arc::new(vault),
            source: Some(Arc::new(source)),
            writer: None,
            owner: None,
            inventory,
            owner_recovered: false,
            session: None,
            session_active: false,
            session_retry: None,
            activation_retry: None,
        });
        self.message = "Original authenticated in quarantine. Select existing successor and separate owner credentials for exact native review. No app session or signing authority exists.".into();
        Ok(())
    }
    fn setup(&mut self, owner: bool, epoch: u64) -> Result<()> {
        let state = self.state.as_ref().ok_or(Error::Locked)?;
        if state.session.is_some() || (state.owner_recovered && (owner || state.writer.is_some())) {
            return Err(Error::ReviewMismatch);
        }
        let json = if owner {
            &self.owner_json
        } else {
            &self.writer_json
        };
        let prepared = PreparedWitnessSetup::prepare(json, &state.vault, &state.authority)?;
        self.stage(Decision::Setup(owner, prepared), epoch)
    }
    fn fence(&mut self) -> Result<()> {
        let state = self.state.as_mut().ok_or(Error::Locked)?;
        if state.owner_recovered {
            return Err(Error::ReviewMismatch);
        }
        let writer = state.writer.as_ref().ok_or(Error::Locked)?;
        let owner = state.owner.as_ref().ok_or(Error::Locked)?.clone();
        if owner.disclosure() != writer.disclosure()
            || owner.writer_certificate_digest() == writer.writer_certificate_digest()
        {
            return Err(Error::Authentication);
        }
        let inventory = if let Some(inventory) = &state.inventory {
            if inventory.witness() != &writer.disclosure()
                || inventory.successor_writer_certificate_digest()
                    != writer.writer_certificate_digest()
            {
                return Err(Error::Authentication);
            }
            inventory.clone()
        } else {
            let inventory = RecoveryActivationInventory::prepare(
                state.source.as_ref().ok_or(Error::Locked)?,
                hex::encode(crate::vault::random::<32>()?),
                hex::encode(crate::vault::random::<32>()?),
                PathBuf::from(&self.destination),
                writer.disclosure(),
                writer.writer_certificate_digest().to_owned(),
            )?;
            state.inventory = Some(inventory.clone());
            inventory
        };
        let password = Zeroizing::new(self.new_password.to_string());
        let authority = state.authority.clone();
        let vault = state.vault.clone();
        let source = state.source.as_ref().ok_or(Error::Locked)?.clone();
        self.start_job(move || {
            let saved = if inventory.target_profile().exists() {
                let pending = AccountVault::unlock_pending_recovery(
                    inventory.target_profile(),
                    password.as_bytes(),
                )?;
                if pending.resume_recovery_inventory(source.manifest(), &vault)? != inventory {
                    return Err(Error::Authentication);
                }
                pending.read_recovery_owner_request()?
            } else {
                None
            };
            let prepared = PreparedOwnerRecovery::prepare(
                owner,
                inventory.clone(),
                &authority,
                saved,
                &source,
            )?;
            if !inventory.target_profile().exists() {
                vault.stage_recovery_plan(&inventory, &source, password.as_bytes())?;
            }
            let pending = AccountVault::unlock_pending_recovery(
                inventory.target_profile(),
                password.as_bytes(),
            )?;
            pending.reconcile_recovery_owner_request(&prepared.request, &prepared.history)?;
            Ok(Completed::Review(Box::new(Decision::Fence(prepared))))
        })
    }
    fn pause_session(&mut self) -> Result<()> {
        let state = self.state.as_ref().ok_or(Error::Locked)?;
        if !state.owner_recovered {
            return Err(Error::ReviewMismatch);
        }
        let owner = state.owner.as_ref().ok_or(Error::Locked)?.clone();
        let inventory = state.inventory.clone().ok_or(Error::Locked)?;
        let authority = state.authority.clone();
        let password = Zeroizing::new(self.new_password.to_string());
        self.start_job(move || {
            Ok(Completed::Review(Box::new(Decision::Pause(
                PreparedOwnerPause::prepare(owner, inventory, &authority, password)?,
            ))))
        })
    }
    fn request_session(&mut self) -> Result<()> {
        let state = self.state.as_ref().ok_or(Error::Locked)?;
        if !state.owner_recovered || state.session.is_some() {
            return Err(Error::ReviewMismatch);
        }
        let writer = state.writer.as_ref().ok_or(Error::Locked)?.clone();
        if let Some(approved) = &state.session_retry {
            let approved = approved.clone();
            return self
                .start_job(move || Ok(Completed::Session(Box::new(approved.acquire(&writer)?))));
        }
        self.start_job(move || {
            Ok(Completed::Review(Box::new(Decision::Session(
                PreparedWriterSession::prepare(&writer)?,
            ))))
        })
    }
    fn activate_session(&mut self) -> Result<()> {
        let state = self.state.as_ref().ok_or(Error::Locked)?;
        if state.session_active {
            return Err(Error::ReviewMismatch);
        }
        let owner = state.owner.as_ref().ok_or(Error::Locked)?.clone();
        if let Some(approved) = &state.activation_retry {
            let approved = approved.clone();
            return self.start_job(move || {
                approved.activate(&owner)?;
                Ok(Completed::SessionActive)
            });
        }
        let receipt = state.session.clone().ok_or(Error::Locked)?;
        self.start_job(move || {
            Ok(Completed::Review(Box::new(Decision::Activate(
                PreparedWriterActivation::prepare(&owner, receipt)?,
            ))))
        })
    }
    fn prepare_publish(&mut self) -> Result<()> {
        let state = self.state.as_mut().ok_or(Error::Locked)?;
        if !state.session_active {
            return Err(Error::ReviewMismatch);
        }
        let source = Arc::try_unwrap(state.source.take().ok_or(Error::Locked)?)
            .map_err(|_| Error::Locked)?;
        let inventory = state.inventory.clone().ok_or(Error::Locked)?;
        let writer = state.writer.as_ref().ok_or(Error::Locked)?.clone();
        let authority = state.authority.clone();
        self.start_job(move || {
            let fence = writer
                .client()
                .authenticate_recovery_fence(inventory.operation_id(), &inventory.digest()?)
                .map_err(|_| Error::Uncertain)?;
            Ok(Completed::Review(Box::new(Decision::Publish(
                PreparedRecoveryActivation::prepare(source, inventory, fence, &authority)?,
            ))))
        })
    }
    fn approve(&mut self, focused: bool, epoch: u64) -> Result<()> {
        let (review, operation) = self.pending.take().ok_or(Error::ReviewMismatch)?;
        let decision = review.consume_native_click(focused, epoch, &self.confirmation)?;
        self.confirmation.zeroize();
        let state = self.state.as_mut().ok_or(Error::Locked)?;
        match operation {
            Decision::Setup(owner, prepared) => {
                let workspace =
                    Arc::new(prepared.approve(decision, &state.authority, &state.vault)?);
                if let Some(inventory) = &state.inventory {
                    if workspace.disclosure() != *inventory.witness()
                        || (!owner
                            && workspace.writer_certificate_digest()
                                != inventory.successor_writer_certificate_digest())
                    {
                        return Err(Error::Authentication);
                    }
                }
                if owner {
                    state.owner = Some(workspace);
                    self.owner_json.zeroize();
                } else {
                    state.writer = Some(workspace);
                    self.writer_json.zeroize();
                }
                Ok(())
            }
            Decision::Fence(prepared) => {
                let authority = state.authority.clone();
                self.start_job(move || {
                    prepared.execute(decision, &authority)?;
                    Ok(Completed::OwnerRecovered)
                })
            }
            Decision::Pause(prepared) => {
                let authority = state.authority.clone();
                self.start_job(move || {
                    prepared.execute(decision, &authority)?;
                    Ok(Completed::SessionReset)
                })
            }
            Decision::Session(prepared) => {
                let writer = state.writer.as_ref().ok_or(Error::Locked)?.clone();
                let approved = Arc::new(prepared.approve(decision, &state.authority, &writer)?);
                state.session_retry = Some(approved.clone());
                self.start_job(move || Ok(Completed::Session(Box::new(approved.acquire(&writer)?))))
            }
            Decision::Activate(prepared) => {
                let owner = state.owner.as_ref().ok_or(Error::Locked)?.clone();
                let approved = Arc::new(prepared.approve(decision, &state.authority, &owner)?);
                state.activation_retry = Some(approved.clone());
                self.start_job(move || {
                    approved.activate(&owner)?;
                    Ok(Completed::SessionActive)
                })
            }
            Decision::Publish(prepared) => {
                let approved = prepared.approve(decision, &state.authority)?;
                let writer = state.writer.as_ref().ok_or(Error::Locked)?.clone();
                let vault = state.vault.clone();
                let password = std::mem::take(&mut self.new_password);
                self.repeat_password.zeroize();
                self.start_job(move || {
                    let target = approved.target_profile().to_path_buf();
                    let fresh = writer
                        .client()
                        .authenticate_recovery_fence(
                            approved.operation_id(),
                            &approved.inventory_digest()?,
                        )
                        .map_err(|_| Error::Uncertain)?;
                    let successor =
                        vault.publish_recovery_successor(approved, fresh, password.as_bytes())?;
                    drop(successor);
                    Ok(Completed::Published(target))
                })
            }
        }
    }
    pub(super) fn ui(&mut self, ui: &mut egui::Ui, inputs: RecoveryInputs<'_>) {
        let RecoveryInputs {
            focused,
            epoch,
            idle,
            root,
            archive,
            password,
            recovery_password,
        } = inputs;
        if self.poll(epoch).is_err() {
            self.message = "Recovery stopped or response is uncertain. Retry the same step; after restarting, reopen the SAME encrypted destination with its passphrase. Preserve source, operation and witness history. Do not create a replacement operation. No partial profile is adopted.".into();
        }
        ui.collapsing("Independent witnessed recovery into a NEW signer profile", |ui| {
            ui.label("Supported inventory: signer authority, optional dedicated wallet history, and recipient history. All wallet rows are retained, but a fresh scan is required. Coordinator, host financial, and other included components block activation until an authenticated successor producer exists. Restored independent witness backups never qualify.");
            ui.label(&self.message);
            if self.state.is_none() {
                ui.label("NEW successor directory, or exact previously staged directory to resume"); ui.text_edit_singleline(&mut self.destination);
                ui.label("Successor passphrase (existing passphrase when resuming)"); ui.add(egui::TextEdit::singleline(&mut *self.new_password).password(true));
                ui.label("Repeat successor passphrase"); ui.add(egui::TextEdit::singleline(&mut *self.repeat_password).password(true));
                if ui.add_enabled(idle && focused, egui::Button::new("Authenticate selected restored original and backup")).clicked_by(egui::PointerButton::Primary) && self.begin(Path::new(root), Path::new(archive), password, recovery_password).is_err() {
                    self.message = "Original/backup authentication failed or this complete inventory is unsupported. No writer state changed.".into();
                }
            } else if self.job.is_some() {
                ui.label("Authenticated witness operation is in progress. Lock cancels future approval; an already transmitted owner request may have committed. Preserve its exact operation ID.");
            } else if self.pending.is_some() {
                let review = &self.pending.as_ref().unwrap().0;
                ui.label(review.display());
                ui.label(format!("Review digest: {}", review.digest()));
                if review.confirming() {
                    ui.label(format!("Type AUTHORIZE {}", &review.digest()[..12]));
                    ui.add(egui::TextEdit::singleline(&mut *self.confirmation));
                    if ui.button("Approve this exact recovery step").clicked_by(egui::PointerButton::Primary) && self.approve(focused, epoch).is_err() { self.message = "Exact recovery approval expired or failed; no replacement was authorized.".into(); }
                } else if ui.button("Continue after reading exact recovery step").clicked_by(egui::PointerButton::Primary)
                    && self.pending.as_mut().unwrap().0.continue_from_native_click(focused, epoch).is_err() { self.pending = None; }

                if ui.button("Cancel this recovery review").clicked_by(egui::PointerButton::Primary) { self.pending = None; self.confirmation.zeroize(); }
            } else {
                ui.label("Existing successor writer configuration JSON (select private credential files, never paste secrets)");
                ui.add(egui::TextEdit::multiline(&mut *self.writer_json).char_limit(16_384));
                if ui.button("Review successor witness client").clicked_by(egui::PointerButton::Primary) && self.setup(false, epoch).is_err() { self.message = "Successor setup unavailable; existing inventory cannot be changed.".into(); }
                ui.label("Separate existing independent owner configuration JSON");
                ui.add(egui::TextEdit::multiline(&mut *self.owner_json).char_limit(16_384));
                if ui.button("Review independent owner client").clicked_by(egui::PointerButton::Primary) && self.setup(true, epoch).is_err() { self.message = "Owner setup unavailable; existing inventory cannot be changed.".into(); }
                if ui.button("Inspect independent witness and review exact writer recovery").clicked_by(egui::PointerButton::Primary) && self.fence().is_err() { self.message = "Exact recovery inventory already exists or clients do not match. No replacement was generated.".into(); }
                if ui.button("Review owner pause of lost recovery session").clicked_by(egui::PointerButton::Primary) && self.pause_session().is_err() { self.message = "Session reset requires the exact completed recovery inventory and independent owner. No automatic pause was sent.".into(); }
                if ui.button("Review fresh successor session").clicked_by(egui::PointerButton::Primary) && self.request_session().is_err() { self.message = "A completed exact owner recovery and no prior pending session are required.".into(); }
                if ui.button("Review owner activation of successor session").clicked_by(egui::PointerButton::Primary) && self.activate_session().is_err() { self.message = "A retained original pending session is required.".into(); }
                if ui.button("Review complete successor profile publication").clicked_by(egui::PointerButton::Primary) && self.prepare_publish().is_err() { self.message = "Fresh active session and complete authenticated source are required. No partial profile is adopted.".into(); }
            }
            if self.state.is_some() && ui.button("Lock recovery workspace").clicked_by(egui::PointerButton::Primary) { self.clear(); }
        });
    }
}
impl Drop for RecoveryUi {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod recovery_ui_tests {
    use super::*;
    #[test]
    fn clear_wipes_recovery_secrets_without_creating_runtime_authority() {
        let mut ui = RecoveryUi::default();
        *ui.new_password = "synthetic-only-password".into();
        *ui.repeat_password = "synthetic-only-password".into();
        *ui.writer_json = "synthetic-selected-paths".into();
        *ui.owner_json = "synthetic-selected-paths".into();
        *ui.confirmation = "AUTHORIZE synthetic".into();
        ui.clear();
        assert!(!ui.is_active());
        assert!(ui.new_password.is_empty() && ui.repeat_password.is_empty());
        assert!(
            ui.writer_json.is_empty() && ui.owner_json.is_empty() && ui.confirmation.is_empty()
        );
        assert!(ui.pending.is_none() && ui.job.is_none());
    }
}
