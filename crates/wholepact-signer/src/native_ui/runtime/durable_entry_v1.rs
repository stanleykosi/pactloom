//! Genuine focused native reopen of an original born account. Historical
//! enrollment is association evidence only; every process/native/writer action
//! after this entry is fresh. The old V3 in-memory owner is never consulted.
use super::*;
pub(super) use crate::account::birth::enrollment::roster_v2::durable_entry_v1::DurableEntryFailureStageV1;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::DurableEntryOpenResultV1;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1;
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::mpsc, time::Instant};

/// Drop order is deliberate: the actual IPC worker/socket drains before its
/// external private container is removed, including activation-error paths.
pub(super) struct DurableEntryEndpointV1 {
    pub(super) ipc: LocalIpc,
    pub(super) temporary: tempfile::TempDir,
}
pub(super) fn create_durable_endpoint_v1(
    original_root: &Path,
) -> DurableEntryOpenResultV1<DurableEntryEndpointV1> {
    let create = DurableEntryFailureStageV1::EndpointCreate;
    let original = std::fs::canonicalize(original_root).map_err(|e| (create, Error::from(e)))?;
    let parent =
        std::fs::canonicalize(std::env::temp_dir()).map_err(|e| (create, Error::from(e)))?;
    // Refuse an environment-selected temporary parent inside the original
    // BEFORE creating anything there. Never remove/repair an unknown entry.
    if parent.starts_with(&original) {
        return Err((create, Error::InvalidData));
    }
    let temporary = tempfile::Builder::new()
        .prefix("wholepact-durable-native-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .map_err(|e| (create, Error::from(e)))?;
    let bind = DurableEntryFailureStageV1::EndpointBind;
    let directory =
        crate::files::PrivateDirectory::open(temporary.path()).map_err(|e| (bind, e))?;
    let ipc = LocalIpc::bind(directory).map_err(|e| (bind, e))?;
    Ok(DurableEntryEndpointV1 { ipc, temporary })
}

pub(super) struct DurableEntryJobV1 {
    owner: Arc<super::super::PendingAccountNativeAuthority>,
    receive: mpsc::Receiver<DurableEntryOpenResultV1<FreshDurableBornEntryV1>>,
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
            || self.durable_delivery_entry_job.is_some()
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
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            self.durable_entry_failure = None;
        }
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
            let result =
                FreshDurableBornEntryV1::open_diagnosed(&worker_root, &password, worker_owner);
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
        if !focused || job.focus_epoch != epoch || job.root != Path::new(&self.root) {
            self.cancel_durable_entry_v1();
            return;
        }
        if let Err(error) = job.owner.check_current() {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            {
                self.durable_entry_failure =
                    Some((DurableEntryFailureStageV1::NativeOwnerCheck, error));
            }
            #[cfg(not(feature = "synthetic-born-joined-qualification"))]
            let _ = error;
            self.cancel_durable_entry_v1();
            return;
        }
        let result = match job.receive.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err((DurableEntryFailureStageV1::WorkerResult, Error::Unavailable))
            }
        };
        let mut job = self.durable_entry_job.take().expect("pending job checked");
        let result = result.and_then(|source| {
            let stage = DurableEntryFailureStageV1::RuntimeActivation;
            if self.open.is_some() || self.pending.is_some() || job.focus_epoch != epoch {
                return Err((stage, Error::ReviewMismatch));
            }
            source.check_current().map_err(|error| (stage, error))?;
            if !Arc::ptr_eq(source.native_owner(), &job.owner) {
                return Err((stage, Error::Authentication));
            }
            self.activate_durable_entry_v1(Arc::new(source))?;
            // Disable only this job's cancellation guard, not a native/born
            // authority flag. The actual owner is retained in OpenAccount.
            job.focus_epoch = 0;
            Ok(())
        });
        if let Err((stage, error)) = result {
            job.owner.revoke_pending_now();
            #[cfg(feature = "synthetic-born-joined-qualification")]
            {
                self.durable_entry_failure = Some((stage, error));
            }
            #[cfg(not(feature = "synthetic-born-joined-qualification"))]
            let _ = (stage, error);
            self.message = "Fresh durable source authentication failed. Original history remains unchanged; preserve the original account and journal for recovery.";
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn take_durable_entry_failure_for_qualification(
        &mut self,
    ) -> Option<(DurableEntryFailureStageV1, Error)> {
        self.durable_entry_failure.take()
    }
    fn activate_durable_entry_v1(
        &mut self,
        source: Arc<FreshDurableBornEntryV1>,
    ) -> DurableEntryOpenResultV1<()> {
        let stage = DurableEntryFailureStageV1::RuntimeActivation;
        source.check_current().map_err(|error| (stage, error))?;
        self.retirement_evidence_session
            .before_account_replacement()
            .map_err(|error| (stage, error))?;
        // The complete original vault inventory forbids subdirectories. Reuse
        // the supported external private endpoint pattern, never widen it.
        let endpoint = create_durable_endpoint_v1(Path::new(&self.root))?;
        source
            .native_owner()
            .publish_pending_endpoint(endpoint.ipc.socket_path())
            .map_err(|error| (DurableEntryFailureStageV1::EndpointPublish, error))?;
        source
            .check_current()
            .map_err(|error| (DurableEntryFailureStageV1::PostEndpointSourceCheck, error))?;
        self.open = Some(OpenAccount {
            vault: source.vault().clone(),
            journal: source.journal().clone(),
            authority: OpenNativeAuthority::DurableBorn(source.native_owner().clone()),
            durable_born_entry: Some(source),
            durable_delivery_entry: None,
            durable_delivery: Default::default(),
            durable_review: None,
            durable_witness: durable_witness_v1::DurableWitnessRuntimeV1::default(),
            durable_import_job: None,
            durable_wallet_job: None,
            session: None,
            ipc: endpoint.ipc,
            durable_ipc_directory: Some(endpoint.temporary),
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

pub(super) struct DurableDeliveryEntryJobV2 {
    owner: Arc<super::super::PendingAccountNativeAuthority>,
    receive: mpsc::Receiver<DurableEntryOpenResultV1<crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableDeliveryEntryV2>>,
    done: Arc<AtomicBool>,
    focus_epoch: u64,
    root: PathBuf,
}
impl Drop for DurableDeliveryEntryJobV2 {
    fn drop(&mut self) {
        // Successful activation transfers the SAME owner to OpenAccount; it
        // clears this guard via finish below before dropping the pending job.
        if self.focus_epoch != 0 {
            self.owner.revoke_pending_now();
        }
    }
}
impl NativeRuntime {
    pub(super) fn begin_durable_delivery_entry_v2(
        &mut self,
        focused: bool,
        epoch: u64,
    ) -> Result<()> {
        #[cfg(feature = "offline-review-foundation")]
        if self.named_recipient.final_active() {
            return Err(Error::Locked);
        }
        if !focused
            || epoch == 0
            || self.open.is_some()
            || self.pending.is_some()
            || self.pending_account.is_some()
            || self.durable_delivery_entry_job.is_some()
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
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            self.durable_entry_failure = None;
        }
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
            let result =
                crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableDeliveryEntryV2::open_diagnosed(&worker_root, &password, worker_owner);
            let _ = send.send(result);
        });
        self.durable_delivery_entry_job = Some(DurableDeliveryEntryJobV2 {
            owner,
            receive,
            done,
            focus_epoch: epoch,
            root,
        });
        self.message = "Opening the exact original born vault and complete retained journal. No writer, old approval, reservation or signing continuation is being restored.";
        Ok(())
    }
    pub(super) fn cancel_durable_delivery_entry_v2(&mut self) {
        if let Some(job) = self.durable_delivery_entry_job.take() {
            job.owner.revoke_pending_now();
            if !job.done.load(Ordering::Acquire) {
                self.closing_accounts.push(job.done.clone());
            }
        }
    }
    pub(super) fn poll_durable_delivery_entry_v2(&mut self, focused: bool, epoch: u64) {
        let Some(job) = self.durable_delivery_entry_job.as_ref() else {
            return;
        };
        if !focused || job.focus_epoch != epoch || job.root != Path::new(&self.root) {
            self.cancel_durable_delivery_entry_v2();
            return;
        }
        if let Err(error) = job.owner.check_current() {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            {
                self.durable_entry_failure =
                    Some((DurableEntryFailureStageV1::NativeOwnerCheck, error));
            }
            #[cfg(not(feature = "synthetic-born-joined-qualification"))]
            let _ = error;
            self.cancel_durable_delivery_entry_v2();
            return;
        }
        let result = match job.receive.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err((DurableEntryFailureStageV1::WorkerResult, Error::Unavailable))
            }
        };
        let mut job = self
            .durable_delivery_entry_job
            .take()
            .expect("pending job checked");
        let result = result.and_then(|source| {
            let stage = DurableEntryFailureStageV1::RuntimeActivation;
            if self.open.is_some() || self.pending.is_some() || job.focus_epoch != epoch {
                return Err((stage, Error::ReviewMismatch));
            }
            source.check_current().map_err(|error| (stage, error))?;
            if !Arc::ptr_eq(source.native_owner(), &job.owner) {
                return Err((stage, Error::Authentication));
            }
            self.activate_durable_delivery_entry_v2(Arc::new(source))?;
            // Disable only this job's cancellation guard, not a native/born
            // authority flag. The actual owner is retained in OpenAccount.
            job.focus_epoch = 0;
            Ok(())
        });
        if let Err((stage, error)) = result {
            job.owner.revoke_pending_now();
            #[cfg(feature = "synthetic-born-joined-qualification")]
            {
                self.durable_entry_failure = Some((stage, error));
            }
            #[cfg(not(feature = "synthetic-born-joined-qualification"))]
            let _ = (stage, error);
            self.message = "Fresh durable source authentication failed. Original history remains unchanged; preserve the original account and journal for recovery.";
        }
    }
    fn activate_durable_delivery_entry_v2(
        &mut self,
        source: Arc<crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableDeliveryEntryV2>,
    ) -> DurableEntryOpenResultV1<()> {
        let stage = DurableEntryFailureStageV1::RuntimeActivation;
        source.check_current().map_err(|error| (stage, error))?;
        self.retirement_evidence_session
            .before_account_replacement()
            .map_err(|error| (stage, error))?;
        // The complete original vault inventory forbids subdirectories. Reuse
        // the supported external private endpoint pattern, never widen it.
        let endpoint = create_durable_endpoint_v1(Path::new(&self.root))?;
        source
            .native_owner()
            .publish_pending_endpoint(endpoint.ipc.socket_path())
            .map_err(|error| (DurableEntryFailureStageV1::EndpointPublish, error))?;
        source
            .check_current()
            .map_err(|error| (DurableEntryFailureStageV1::PostEndpointSourceCheck, error))?;
        self.open = Some(OpenAccount {
            vault: source.vault().clone(),
            journal: source.journal().clone(),
            authority: OpenNativeAuthority::DurableBorn(source.native_owner().clone()),
            durable_born_entry: None,
            durable_delivery_entry: Some(source),
            durable_delivery: Default::default(),
            durable_review: None,
            durable_witness: durable_witness_v1::DurableWitnessRuntimeV1::default(),
            durable_import_job: None,
            durable_wallet_job: None,
            session: None,
            ipc: endpoint.ipc,
            durable_ipc_directory: Some(endpoint.temporary),
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
        self.message = "Original source opened in the separate v2 admission/history-only profile. Pair this actual process and original witness. History needs no new manifest or private import; new admission requires both. No signing, reservation, extraction or dispatch permission exists.";
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn durable_fixture_pairing_labels_use_existing_identifier_grammar() {
        // Exercise the SAME validator called before the history client opens
        // a socket. These are unverified application labels, not authority.
        for (valid, rejected) in [
            (
                "Synthetic-durable-constructor",
                "Synthetic durable constructor",
            ),
            (
                "Synthetic-fresh-durable-reviewer",
                "Synthetic fresh durable reviewer",
            ),
            (
                "Synthetic-fixed-proposal-signer",
                "Synthetic fixed proposal signer",
            ),
        ] {
            assert!(crate::review::validate_label(valid).is_ok());
            assert!(crate::review::validate_label(rejected).is_err());
        }
    }

    fn inventory(root: &Path) -> BTreeMap<std::ffi::OsString, (bool, bool, bool)> {
        std::fs::read_dir(root)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let kind = std::fs::symlink_metadata(entry.path()).unwrap().file_type();
                (
                    entry.file_name(),
                    (kind.is_file(), kind.is_dir(), kind.is_symlink()),
                )
            })
            .collect()
    }

    #[test]
    fn durable_endpoint_is_external_preserves_inventory_and_drains_before_cleanup() {
        let original = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        // Storage-only fixture, not a native account/approval factory.
        std::fs::write(
            original.path().join("account.wp"),
            b"synthetic inert original",
        )
        .unwrap();
        std::fs::write(
            original.path().join("authority.sqlite"),
            b"synthetic inert journal",
        )
        .unwrap();
        // An unsupported preexisting entry is never silently repaired/removed.
        std::fs::create_dir(original.path().join("local-apps")).unwrap();
        let before = inventory(original.path());
        for _ in 0..2 {
            let endpoint = create_durable_endpoint_v1(original.path())
                .unwrap_or_else(|_| panic!("external endpoint setup failed"));
            let directory = endpoint.temporary.path().to_path_buf();
            let socket = endpoint.ipc.socket_path().to_path_buf();
            assert!(!directory.starts_with(original.path()));
            assert!(!socket.starts_with(original.path()));
            assert!(socket.exists());
            assert_eq!(inventory(original.path()), before);
            drop(endpoint);
            assert!(!socket.exists());
            assert!(!directory.exists());
            assert_eq!(inventory(original.path()), before);
        }
    }
}
