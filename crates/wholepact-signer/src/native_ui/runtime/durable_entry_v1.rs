//! Genuine focused native reopen of an original born account. Historical
//! enrollment is association evidence only; every process/native/writer action
//! after this entry is fresh. The old V3 in-memory owner is never consulted.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1;
use std::{path::PathBuf, sync::mpsc, time::Instant};

pub(super) struct DurableEntryJobV1 {
    owner: Arc<super::super::PendingAccountNativeAuthority>,
    receive: mpsc::Receiver<Result<FreshDurableBornEntryV1>>,
    done: Arc<AtomicBool>,
    focus_epoch: u64,
    root: PathBuf,
}
impl Drop for DurableEntryJobV1 {
    fn drop(&mut self) {
        // Successful activation transfers the SAME owner to OpenAccount; it
        // clears this guard via finish below before dropping the pending job.
        if self.focus_epoch != 0 {
            self.owner.revoke_pending_now();
        }
    }
}
impl NativeRuntime {
    pub(super) fn begin_durable_entry_v1(&mut self, focused: bool, epoch: u64) -> Result<()> {
        #[cfg(feature = "offline-review-foundation")]
        if self.named_recipient.final_active() {
            return Err(Error::Locked);
        }
        if !focused
            || epoch == 0
            || self.open.is_some()
            || self.pending.is_some()
            || self.pending_account.is_some()
            || self.durable_entry_job.is_some()
            || self.birth.is_active()
            || self.pending_enrollment.is_active()
            || self.born_origin.is_active()
            || self.born_manual.is_active()
            || self.born_manual_roster_v2.is_active()
            || self.born_enrolled_backup.is_active()
            || self.signing_job.is_some()
            || !self.closing_accounts.is_empty()
        {
            return Err(Error::ReviewMismatch);
        }
        self.retirement_evidence_session
            .before_account_replacement()?;
        let deadline = Instant::now() + Duration::from_secs(120);
        let owner = Arc::new(super::super::PendingAccountNativeAuthority::enter_bounded(
            PendingBirthEntry {
                focus_epoch: epoch,
                parent_channel: self.parent_channel.clone(),
            },
            deadline,
        )?);
        let root = PathBuf::from(&self.root);
        let worker_root = root.clone();
        let password = Zeroizing::new(self.password.as_bytes().to_vec());
        self.password.zeroize();
        let (send, receive) = mpsc::channel();
        let done = Arc::new(AtomicBool::new(false));
        let worker_done = done.clone();
        let worker_owner = owner.clone();
        std::thread::spawn(move || {
            let _done = WorkerCompletion(worker_done);
            let result = FreshDurableBornEntryV1::open(&worker_root, &password, worker_owner);
            let _ = send.send(result);
        });
        self.durable_entry_job = Some(DurableEntryJobV1 {
            owner,
            receive,
            done,
            focus_epoch: epoch,
            root,
        });
        self.message = "Opening the exact original born vault and complete retained journal. No writer, old approval, reservation or signing continuation is being restored.";
        Ok(())
    }
    pub(super) fn cancel_durable_entry_v1(&mut self) {
        if let Some(job) = self.durable_entry_job.take() {
            job.owner.revoke_pending_now();
            if !job.done.load(Ordering::Acquire) {
                self.closing_accounts.push(job.done.clone());
            }
        }
    }
    pub(super) fn poll_durable_entry_v1(&mut self, focused: bool, epoch: u64) {
        let Some(job) = self.durable_entry_job.as_ref() else {
            return;
        };
        if !focused
            || job.focus_epoch != epoch
            || job.root != Path::new(&self.root)
            || job.owner.check_current().is_err()
        {
            self.cancel_durable_entry_v1();
            return;
        }
        let result = match job.receive.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => Err(Error::Unavailable),
        };
        let mut job = self.durable_entry_job.take().expect("pending job checked");
        let result = result.and_then(|source| {
            if self.open.is_some() || self.pending.is_some() || job.focus_epoch != epoch {
                return Err(Error::ReviewMismatch);
            }
            source.check_current()?;
            if !Arc::ptr_eq(source.native_owner(), &job.owner) {
                return Err(Error::Authentication);
            }
            self.activate_durable_entry_v1(Arc::new(source))?;
            // Disable only this job's cancellation guard, not a native/born
            // authority flag. The actual owner is retained in OpenAccount.
            job.focus_epoch = 0;
            Ok(())
        });
        if result.is_err() {
            job.owner.revoke_pending_now();
            self.message = "Fresh durable source authentication failed. Original history remains unchanged; preserve the original account and journal for recovery.";
        }
    }
    fn activate_durable_entry_v1(&mut self, source: Arc<FreshDurableBornEntryV1>) -> Result<()> {
        source.check_current()?;
        self.retirement_evidence_session
            .before_account_replacement()?;
        let ipc_path = Path::new(&self.root).join("local-apps");
        let directory = if ipc_path.exists() {
            crate::files::PrivateDirectory::open(&ipc_path)?
        } else {
            crate::files::PrivateDirectory::create(&ipc_path)?
        };
        let ipc = LocalIpc::bind(directory)?;
        source
            .native_owner()
            .publish_pending_endpoint(ipc.socket_path())?;
        source.check_current()?;
        self.open = Some(OpenAccount {
            vault: source.vault().clone(),
            journal: source.journal().clone(),
            authority: OpenNativeAuthority::DurableBorn(source.native_owner().clone()),
            durable_born_entry: Some(source),
            durable_review: None,
            durable_import_job: None,
            durable_wallet_job: None,
            session: None,
            ipc,
            pairing: None,
            enrollment: None,
            manifest: None,
            revocations: Vec::new(),
            history_workers: Vec::new(),
            disclosure_worker_ids: std::collections::HashSet::new(),
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            born_bridge_active: false,
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            born_bridge_workers: std::collections::HashSet::new(),
            host_continuity_worker: None,
            wallet: None,
            wallet_job: None,
            witness: None,
            owner_witness: None,
            witness_job: None,
            writer_receipt: None,
            writer_reconciled: false,
            writer_retry: None,
            activation_retry: None,
        });
        self.password.zeroize();
        self.recovery_password.zeroize();
        self.recovery_repeat.zeroize();
        self.recovery_confirmation.zeroize();
        self.backup.zeroize();
        self.recovery.zeroize();
        self.message = "Original born account reopened with a fresh bounded native owner. Pair this actual process, freshly accept the same enrollment and manifest, and reconcile the original independent witness. No old spend permission was restored.";
        Ok(())
    }
}
