//! Original-connection change detection, not source authority or a writer lease.
//! Capture before the caller's full audit and recheck after it. Never hold the
//! connection mutex or a read transaction over that audit or a human/network wait.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    data_version: i64,
    total_changes: u64,
    schema_version: i64,
    user_version: i64,
    application_id: i64,
}
impl Stamp {
    fn read(connection: &Connection) -> Result<Self> {
        Ok(Self {
            data_version: connection.pragma_query_value(None, "data_version", |r| r.get(0))?,
            total_changes: connection.total_changes(),
            schema_version: connection.pragma_query_value(None, "schema_version", |r| r.get(0))?,
            user_version: connection.pragma_query_value(None, "user_version", |r| r.get(0))?,
            application_id: connection.pragma_query_value(None, "application_id", |r| r.get(0))?,
        })
    }
}

/// Opaque, non-Clone observation tied to this actual original Store and agreement.
/// It authenticates no user and grants no disclosure, proof or financial effect.
pub struct OriginalPrivateRevisionPinV3<'a> {
    store: &'a Store,
    agreement_id: String,
    revision: u64,
    stamp: Stamp,
}
impl<'a> OriginalPrivateRevisionPinV3<'a> {
    pub fn check_current_v3(&self) -> Result<()> {
        let connection = self
            .store
            .connection
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
                std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
            })?;
        if !connection.is_autocommit() {
            return Err(StoreError::RevisionConflict);
        }
        self.check_locked(&connection)
    }
    pub(super) fn require_target(
        &self,
        store: &Store,
        id: &str,
        revision: Option<u64>,
    ) -> Result<()> {
        if !std::ptr::eq(self.store, store)
            || self.agreement_id != id
            || revision != Some(self.revision)
        {
            return Err(StoreError::RevisionConflict);
        }
        Ok(())
    }
    pub(super) fn capture_locked(
        store: &'a Store,
        connection: &Connection,
        id: &str,
    ) -> Result<Self> {
        validate_id(id)?;
        original(store, connection)?;
        let stamp = Stamp::read(connection)?;
        let revision = selected_revision(connection, id)?;
        original(store, connection)?;
        if stamp != Stamp::read(connection)?
            || stamp.user_version != SCHEMA_VERSION
            || stamp.application_id != 0
        {
            return Err(StoreError::RevisionConflict);
        }
        Ok(Self {
            store,
            agreement_id: id.into(),
            revision,
            stamp,
        })
    }
    pub(super) fn check_locked(&self, connection: &Connection) -> Result<()> {
        original(self.store, connection)?;
        if Stamp::read(connection)? != self.stamp
            || selected_revision(connection, &self.agreement_id)? != self.revision
            || Stamp::read(connection)? != self.stamp
        {
            return Err(StoreError::RevisionConflict);
        }
        original(self.store, connection)
    }
}

#[derive(PartialEq, Eq)]
enum SourceProfileV3 {
    Original,
    Recovered {
        binding: wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
        destination_identity: String,
    },
}

/// Read-only observation of the actual encrypted source Store, including an
/// authenticated recovered/layered root. This is not a private destination pin:
/// it has no mutation target, successor, conversion or update operation.
///
/// The caller still performs its full source/provenance audit between capture
/// and recheck. This token detects changes; it does not authenticate a new source
/// or grant disclosure, native permission or financial authority.
pub struct OriginalSourceReadRevisionPinV3<'a> {
    store: &'a Store,
    agreement_id: String,
    revision: u64,
    stamp: Stamp,
    profile: SourceProfileV3,
}
impl OriginalSourceReadRevisionPinV3<'_> {
    pub fn check_current_v3(&self) -> Result<()> {
        let connection = self.store.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        if !connection.is_autocommit() {
            return Err(StoreError::RevisionConflict);
        }
        if read_source_profile(self.store, &connection)? != self.profile
            || Stamp::read(&connection)? != self.stamp
            || selected_revision(&connection, &self.agreement_id)? != self.revision
            || Stamp::read(&connection)? != self.stamp
            || read_source_profile(self.store, &connection)? != self.profile
        {
            return Err(StoreError::RevisionConflict);
        }
        Ok(())
    }
}

fn read_source_profile(store: &Store, connection: &Connection) -> Result<SourceProfileV3> {
    if store.protection != StorageProtection::Encrypted {
        return Err(StoreError::RecoveryRequired);
    }
    store
        .original_database
        .as_ref()
        .ok_or(StoreError::RecoveryRequired)?
        .check_current(connection)?;
    if store.recovered_generation {
        let (binding, destination_identity) =
            store.original_read_generation_identity_v3(connection)?;
        Ok(SourceProfileV3::Recovered {
            binding,
            destination_identity,
        })
    } else {
        let stamp = Stamp::read(connection)?;
        if store.recovered_binding.is_some()
            || stamp.user_version != SCHEMA_VERSION
            || stamp.application_id != 0
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(SourceProfileV3::Original)
    }
}

fn original(store: &Store, connection: &Connection) -> Result<()> {
    if store.protection != StorageProtection::Encrypted || store.recovered_generation {
        return Err(StoreError::RecoveryRequired);
    }
    store
        .original_database
        .as_ref()
        .ok_or(StoreError::RecoveryRequired)?
        .check_current(connection)?;
    Ok(())
}
fn selected_revision(connection: &Connection, id: &str) -> Result<u64> {
    let revision: Option<i64> = connection
        .query_row(
            "SELECT revision FROM records WHERE aggregate_type='agreement' AND id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    let revision = revision.ok_or(StoreError::NotFound)?;
    if revision <= 0 {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(revision as u64)
}
impl Store {
    pub fn pin_original_source_read_revision_v3(
        &self,
        agreement_id: &str,
    ) -> Result<OriginalSourceReadRevisionPinV3<'_>> {
        validate_id(agreement_id)?;
        let connection = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        if !connection.is_autocommit() {
            return Err(StoreError::RevisionConflict);
        }
        let stamp = Stamp::read(&connection)?;
        let profile = read_source_profile(self, &connection)?;
        let revision = selected_revision(&connection, agreement_id)?;
        if read_source_profile(self, &connection)? != profile
            || Stamp::read(&connection)? != stamp
        {
            return Err(StoreError::RevisionConflict);
        }
        Ok(OriginalSourceReadRevisionPinV3 {
            store: self,
            agreement_id: agreement_id.into(),
            revision,
            stamp,
            profile,
        })
    }

    pub fn pin_original_revision_v3(
        &self,
        agreement_id: &str,
    ) -> Result<OriginalPrivateRevisionPinV3<'_>> {
        let connection = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        if !connection.is_autocommit() {
            return Err(StoreError::RevisionConflict);
        }
        OriginalPrivateRevisionPinV3::capture_locked(self, &connection, agreement_id)
    }
    /// Consumes the old observation. Refusal or ambiguous commit yields no new
    /// pin; callers reconcile the original operation instead of silently retrying.
    pub fn update_original_agreement_pinned_v3<'a>(
        &'a self,
        pin: OriginalPrivateRevisionPinV3<'a>,
        context: &CommandContext,
        id: &str,
        expected_revision: u64,
        payload: Value,
        event_kind: &str,
    ) -> Result<(MutationResult, OriginalPrivateRevisionPinV3<'a>)> {
        pin.require_target(self, id, Some(expected_revision))?;
        let (result, next) = self.commit_record_kernel_v3(
            context,
            "agreement",
            id,
            Some(expected_revision),
            payload,
            event_kind,
            Some(pin),
        )?;
        Ok((result, next.ok_or(StoreError::RecoveryRequired)?))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    // Actual encrypted Store/SQLite integration. These generic synthetic rows
    // exercise change detection and atomicity, not private-source/native authority.
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wholepact_storage_security::DatabaseKey;
    fn context(key: &str) -> CommandContext {
        CommandContext::for_request(
            "synthetic-pin-owner",
            format!("synthetic-original-pin-v3:{key}"),
            &serde_json::json!({"operation":key}),
        )
        .unwrap()
    }
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Store) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("original.sqlite");
        let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([0x63; 32])).unwrap();
        store
            .create_agreement(
                &context("create"),
                "agreement",
                serde_json::json!({"synthetic":1}),
            )
            .unwrap();
        (dir, path, store)
    }
    #[test]
    fn encrypted_source_read_pin_preserves_original_destination_write_separation() {
        let (_dir, _path, store) = fixture();
        let command = context("source-read-then-original-write");
        let before = store.get_agreement("agreement").unwrap().unwrap();
        let history = serde_json::to_value(store.events_after(0, 100).unwrap()).unwrap();
        let changes = store.connection.lock().unwrap().total_changes();
        let read = store
            .pin_original_source_read_revision_v3("agreement")
            .unwrap();
        // A separate original destination admission is still necessary; the
        // read token has no conversion into the consuming mutation API.
        let write = store.pin_original_revision_v3("agreement").unwrap();
        store.verify_integrity().unwrap();
        read.check_current_v3().unwrap();
        write.check_current_v3().unwrap();
        assert_eq!(store.get_agreement("agreement").unwrap().unwrap(), before);
        assert_eq!(
            serde_json::to_value(store.events_after(0, 100).unwrap()).unwrap(),
            history
        );
        assert_eq!(store.connection.lock().unwrap().total_changes(), changes);
        assert!(store.find_replay(&command).unwrap().is_none());

        let (committed, successor) = store
            .update_original_agreement_pinned_v3(
                write,
                &command,
                "agreement",
                before.revision,
                serde_json::json!({"synthetic": 2}),
                "synthetic.update",
            )
            .unwrap();
        assert_eq!(committed.record.revision, before.revision + 1);
        assert!(!committed.replayed);
        successor.check_current_v3().unwrap();
        assert!(matches!(
            read.check_current_v3(),
            Err(StoreError::RevisionConflict)
        ));
    }
    #[test]
    fn encrypted_pin_rejects_independent_already_open_handle_write() {
        let (_dir, path, store) = fixture();
        let other = Store::open_encrypted(&path, &DatabaseKey::from_bytes([0x63; 32])).unwrap();
        let pin = store.pin_original_revision_v3("agreement").unwrap();
        // Same selected revision, but real independent authoritative state changed.
        other
            .initialize_authority_account("synthetic-account", 1)
            .unwrap();
        assert!(matches!(
            pin.check_current_v3(),
            Err(StoreError::RevisionConflict)
        ));
        assert!(store
            .update_original_agreement_pinned_v3(
                pin,
                &context("must-not-write"),
                "agreement",
                1,
                serde_json::json!({"synthetic":2}),
                "synthetic.update"
            )
            .is_err());
        assert_eq!(
            store.get_agreement("agreement").unwrap().unwrap().revision,
            1
        );
        assert!(store
            .find_replay(&context("must-not-write"))
            .unwrap()
            .is_none());
    }
    #[test]
    fn encrypted_pin_own_mutation_invalidates_even_without_data_version_change() {
        let (_dir, _path, store) = fixture();
        let pin = store.pin_original_revision_v3("agreement").unwrap();
        store
            .initialize_authority_account("synthetic-own-account", 1)
            .unwrap();
        assert!(matches!(
            pin.check_current_v3(),
            Err(StoreError::RevisionConflict)
        ));
    }
    #[test]
    fn encrypted_pinned_commit_returns_only_exact_new_revision_and_replay_refuses() {
        let (_dir, _path, store) = fixture();
        let old = store.pin_original_revision_v3("agreement").unwrap();
        let consumed = store.pin_original_revision_v3("agreement").unwrap();
        let command = context("pinned-write");
        let payload = serde_json::json!({"synthetic":2});
        let (result, next) = store
            .update_original_agreement_pinned_v3(
                consumed,
                &command,
                "agreement",
                1,
                payload.clone(),
                "synthetic.update",
            )
            .unwrap();
        assert_eq!(result.record.revision, 2);
        assert!(!result.replayed);
        next.check_current_v3().unwrap();
        assert!(old.check_current_v3().is_err());
        assert!(store
            .update_original_agreement_pinned_v3(
                next,
                &command,
                "agreement",
                2,
                payload.clone(),
                "synthetic.update"
            )
            .is_err());
        // Legacy semantic retry order is unchanged despite stale expected revision.
        assert!(
            store
                .update_agreement(&command, "agreement", 1, payload, "synthetic.update")
                .unwrap()
                .replayed
        );
        assert_eq!(
            store.get_agreement("agreement").unwrap().unwrap().revision,
            2
        );
    }
    #[test]
    fn encrypted_pin_cannot_cross_actual_store_owners_or_memory_destination() {
        let (_dir, _path, store) = fixture();
        let (_other_dir, _other_path, other) = fixture();
        let pin = store.pin_original_revision_v3("agreement").unwrap();
        assert!(other
            .update_original_agreement_pinned_v3(
                pin,
                &context("wrong-owner"),
                "agreement",
                1,
                serde_json::json!({"synthetic":2}),
                "synthetic.update"
            )
            .is_err());
        assert!(Store::in_memory()
            .unwrap()
            .pin_original_revision_v3("agreement")
            .is_err());
        assert_eq!(
            other.get_agreement("agreement").unwrap().unwrap().revision,
            1
        );
    }
    #[test]
    fn encrypted_pin_brackets_audit_and_detects_schema_change_and_file_substitution() {
        let (_dir, path, store) = fixture();
        let pin = store.pin_original_revision_v3("agreement").unwrap();
        store.verify_integrity().unwrap();
        pin.check_current_v3().unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("CREATE TABLE synthetic_pin_probe(value INTEGER)")
            .unwrap();
        assert!(pin.check_current_v3().is_err());
        let current = store.pin_original_revision_v3("agreement").unwrap();
        std::fs::rename(&path, path.with_extension("moved")).unwrap();
        std::fs::write(&path, b"synthetic replacement, not a database").unwrap();
        assert!(current.check_current_v3().is_err());
    }
    #[test]
    fn encrypted_pin_is_rechecked_under_the_actual_immediate_transaction() {
        let (_dir, path, store) = fixture();
        let other = Store::open_encrypted(&path, &DatabaseKey::from_bytes([0x63; 32])).unwrap();
        let pin = store.pin_original_revision_v3("agreement").unwrap();
        let mut connection = store.connection.lock().unwrap();
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        pin.check_locked(&tx).unwrap();
        let external = other.connection.lock().unwrap();
        external.busy_timeout(std::time::Duration::ZERO).unwrap();
        assert!(external
            .execute(
                "UPDATE records SET updated_at_ms=updated_at_ms+1 WHERE id='agreement'",
                []
            )
            .is_err());
        drop(external);
        tx.rollback().unwrap();
        drop(connection);
        pin.check_current_v3().unwrap();
    }
}
