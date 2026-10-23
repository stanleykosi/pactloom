//! Borrowed read-only proposed append head. This is not publication authority.
use super::*;
use wholepact_core::manual_roster_v2::HostRosterAppendBindingV2;

/// Only already-retained identity/scope metadata for an exact native review.
/// No current witness receipt, viewing key, input history or issuer is exposed.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ManualEnrollmentRosterMember {
    pub original_audit: OriginalManualEnrollmentAuditLink,
    pub identity: ManualAccountIdentity,
    pub scope: wholepact_core::manual_enrollment::BornManualScope,
}
/// No Clone, Deserialize or caller constructor. Successful publication makes
/// this pre-append owner stale; a distinct committed owner must replace it.
pub struct ManualEnrollmentRosterHead<'store> {
    store: &'store Store,
    target: ManualStoreTarget<'store>,
    agreement: StoredRecord,
    binding: HostRosterAppendBindingV2,
    projection_digest: String,
    members: Vec<ManualEnrollmentRosterMember>,
}
/// Invocation-local read of one fully audited, unchanged original roster.
/// This is not enrollment, publication, disclosure, or financial authority.
/// No connection lock or transaction is retained, and no mutable/raw member
/// accessor, caller constructor, Clone, or serialization is provided.
pub struct OriginalManualRosterReadV3<'head, 'store> {
    head: &'head ManualEnrollmentRosterHead<'store>,
    pin: crate::OriginalSourceReadRevisionPinV3<'store>,
}
impl OriginalManualRosterReadV3<'_, '_> {
    pub fn check_current_v3(&self) -> Result<()> {
        self.head.target.check_current()?;
        self.pin.check_current_v3()?;
        self.head.target.check_current()?;
        self.pin.check_current_v3()
    }
    pub fn members_v3(&self) -> Result<&[ManualEnrollmentRosterMember]> {
        self.check_current_v3()?;
        Ok(&self.head.members)
    }
}
impl ManualEnrollmentRosterHead<'_> {
    /// Inert exact proposal to display/sign. Always check_current before use.
    pub fn binding(&self) -> &HostRosterAppendBindingV2 {
        &self.binding
    }
    pub fn members(&self) -> Result<&[ManualEnrollmentRosterMember]> {
        self.check_current()?;
        Ok(&self.members)
    }
    pub fn check_current(&self) -> Result<()> {
        let (binding, digest, members) =
            read_roster_head(self.store, &self.target, &self.agreement)?;
        if binding != self.binding || digest != self.projection_digest || members != self.members {
            return Err(StoreError::RevisionConflict);
        }
        Ok(())
    }
}
impl<'store> ManualEnrollmentRosterHead<'store> {
    /// Capture BEFORE the full audit, then prove that the same original
    /// connection, agreement, generation, and all database state stayed fixed.
    /// Each use still checks current target/file identity and this observation.
    /// Ordinary members/check_current methods deliberately retain full audits.
    pub fn original_read_v3(&self) -> Result<OriginalManualRosterReadV3<'_, 'store>> {
        let pin = self.store.pin_original_source_read_revision_v3(&self.agreement.id)?;
        self.check_current()?;
        pin.check_current_v3()?;
        Ok(OriginalManualRosterReadV3 { head: self, pin })
    }
}
impl Store {
    pub fn manual_enrollment_roster_head<'store>(
        &'store self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
    ) -> Result<ManualEnrollmentRosterHead<'store>> {
        let (binding, projection_digest, members) =
            read_roster_head(self, target, expected_agreement)?;
        let head = ManualEnrollmentRosterHead {
            store: self,
            target: self.manual_store_target()?,
            agreement: expected_agreement.clone(),
            binding,
            projection_digest,
            members,
        };
        head.check_current()?;
        Ok(head)
    }
}
fn read_roster_head(
    store: &Store,
    target: &ManualStoreTarget<'_>,
    agreement: &StoredRecord,
) -> Result<(
    HostRosterAppendBindingV2,
    String,
    Vec<ManualEnrollmentRosterMember>,
)> {
    if !std::ptr::eq(store, target.store) {
        return Err(StoreError::RecoveryRequired);
    }
    target.check_current()?;
    let mut c = store.connection.try_lock().map_err(|error| match error {
        std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
        std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
    })?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let actual =
        crate::read_record(&tx, "agreement", &agreement.id)?.ok_or(StoreError::NotFound)?;
    if actual != *agreement {
        return Err(StoreError::RevisionConflict);
    }
    if actual.revision == 0
        || actual
            .payload
            .pointer("/view/agreement/agreement_id")
            .and_then(serde_json::Value::as_str)
            != Some(agreement.id.as_str())
    {
        return Err(StoreError::RecoveryRequired);
    }
    #[cfg(test)]
    ORIGINAL_READ_PROJECTIONS.with(|calls| calls.set(calls.get() + 1));
    let projection = crate::recovery::project_manual_snapshot(
        &tx,
        store
            .recovered_binding
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?,
    )?;
    let mut rows: Vec<_> = projection
        .enrollments()
        .into_iter()
        .filter(|a| a.terms().host.generation_id == target.generation_id)
        .collect();
    rows.sort_by_key(|a| a.store_sequence());
    let last = rows.last().ok_or(StoreError::RecoveryRequired)?;
    let binding = HostRosterAppendBindingV2 {
        version: 2,
        generation_id: target.generation_id.clone(),
        store_destination_identity: target.store_destination_identity.clone(),
        roster_sequence: rows.len() as u64 + 1,
        predecessor: last.roster_link()?,
    };
    binding
        .validate()
        .map_err(|_| StoreError::RecoveryRequired)?;
    let members = rows
        .into_iter()
        .map(|a| {
            Ok(ManualEnrollmentRosterMember {
                original_audit: a.original_audit_link()?,
                identity: a.terms().identity.clone(),
                scope: a.terms().scope.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let digest = projection.digest().to_owned();
    tx.commit()?;
    drop(c);
    target.check_current()?;
    Ok((binding, digest, members))
}

#[cfg(test)]
thread_local! {
    static ORIGINAL_READ_PROJECTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod original_read_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wholepact_storage_security::{DatabaseKey, bundle::recovery::generation::{
        GenerationBinding, RECOVERED_GENERATION_APPLICATION_ID,
    }};

    // Real owned SQLCipher connections/file identity, with the existing inert
    // recovery/audit DTO fixture. No native process, grant, signer, account
    // authority, socket, or financial effect is created by these tests.
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Store, StoredRecord) {
        let (dir, path, store, record, _other) = fixture_with_other();
        (dir, path, store, record)
    }
    fn fixture_with_other() -> (tempfile::TempDir, std::path::PathBuf, Store, StoredRecord, wholepact_storage_security::EncryptedConnection) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("lexical-read.sqlite");
        let mut store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([0x42; 32])).unwrap();
        // Open the independent real handle before installing modeled recovery
        // rows. The ordinary opener correctly refuses recovered generations.
        let other = wholepact_storage_security::open_encrypted(&path, &DatabaseKey::from_bytes([0x42; 32])).unwrap();
        store.recovered_generation = true;
        store.recovered_binding = Some(GenerationBinding::new(&"a".repeat(64), &"b".repeat(64)).unwrap());
        {
            let c = store.connection.lock().unwrap();
            c.execute_batch(include_str!("../recovery-schema.sql")).unwrap();
            c.execute("UPDATE store_recovery SET recovery_required=1,restored_at_ms=1,source_snapshot_digest=?1", ["f".repeat(64)]).unwrap();
            c.execute("INSERT INTO records VALUES('settlement_generation_identity','local',0,?1,1,1)", [serde_json::to_string(&"c".repeat(64)).unwrap()]).unwrap();
            c.pragma_update(None, "application_id", RECOVERED_GENERATION_APPLICATION_ID).unwrap();
            c.pragma_update(None, "user_version", 8).unwrap();
        }
        let root = crate::manual_enrollment::tests::initial_publication::initial_fixture();
        crate::manual_enrollment::tests::initial_publication::add_initial(&store, &root, &[]).unwrap();
        let record = store.create_agreement(
            &crate::CommandContext::for_request("owner", "lexical-source-read", &serde_json::json!({})).unwrap(),
            &root.terms().scope.agreement_id,
            serde_json::json!({"view":{"agreement":{
                "agreement_id":root.terms().scope.agreement_id,
                "obligation_id":root.terms().scope.obligation_id,
            }}}),
        ).unwrap().record;
        (dir, path, store, record, other)
    }
    fn make_head<'a>(store: &'a Store, record: &StoredRecord) -> ManualEnrollmentRosterHead<'a> {
        store.manual_enrollment_roster_head(&store.manual_store_target().unwrap(), record).unwrap()
    }
    #[test]
    fn lexical_read_audits_once_keeps_members_and_releases_all_locks() {
        let (_dir, _path, store, record) = fixture();
        let head = make_head(&store, &record);
        let expected = head.members().unwrap().to_vec();
        ORIGINAL_READ_PROJECTIONS.with(|n| n.set(0));
        let read = head.original_read_v3().unwrap();
        for _ in 0..6 { read.check_current_v3().unwrap(); }
        assert!(read.members_v3().unwrap() == expected);
        assert!(store.connection.try_lock().unwrap().is_autocommit());
        ORIGINAL_READ_PROJECTIONS.with(|n| assert_eq!(n.get(), 1));
        // Other callers keep the original complete audit, not a global cache.
        for _ in 0..7 { head.check_current().unwrap(); }
        ORIGINAL_READ_PROJECTIONS.with(|n| assert_eq!(n.get(), 8));
        assert_eq!(store.get_agreement(&record.id).unwrap().unwrap(), record);
    }
    #[test]
    fn lexical_read_rejects_same_revision_own_and_independent_connection_writes() {
        for independent in [false, true] {
            let (_dir, _path, store, record, other) = fixture_with_other();
            let head = make_head(&store, &record);
            let read = head.original_read_v3().unwrap();
            if independent {
                std::thread::spawn(move || {
                    other.connection().execute("UPDATE records SET updated_at_ms=updated_at_ms+1 WHERE aggregate_type!='agreement'", []).unwrap();
                }).join().unwrap();
            } else {
                store.connection.lock().unwrap().execute("UPDATE records SET updated_at_ms=updated_at_ms+1 WHERE aggregate_type!='agreement'", []).unwrap();
            }
            assert_eq!(store.get_agreement(&record.id).unwrap().unwrap(), record);
            assert!(matches!(read.check_current_v3(), Err(StoreError::RevisionConflict)));
            assert!(read.members_v3().is_err());
        }
    }
    #[test]
    fn lexical_read_refuses_contention_without_holding_a_connection_lock() {
        let (_dir, _path, store, record) = fixture();
        let head = make_head(&store, &record);
        let read = head.original_read_v3().unwrap();
        let held = store.connection.lock().unwrap();
        assert!(matches!(read.check_current_v3(), Err(StoreError::ResourceExhausted)));
        assert!(matches!(head.original_read_v3(), Err(StoreError::ResourceExhausted)));
        drop(held);
        read.check_current_v3().unwrap();
    }
    #[test]
    #[ignore = "isolated owned-file component timing, not a hosted performance threshold"]
    fn lexical_read_component_timing_only() {
        let (_dir, _path, store, record) = fixture();
        let head = make_head(&store, &record);
        for rounds in [1, 10, 50] {
            ORIGINAL_READ_PROJECTIONS.with(|n| n.set(0));
            let start = std::time::Instant::now();
            for _ in 0..rounds { for _ in 0..7 { head.check_current().unwrap(); } }
            let old = start.elapsed();
            ORIGINAL_READ_PROJECTIONS.with(|n| assert_eq!(n.get(), rounds * 7));
            ORIGINAL_READ_PROJECTIONS.with(|n| n.set(0));
            let start = std::time::Instant::now();
            for _ in 0..rounds {
                let read = head.original_read_v3().unwrap();
                for _ in 0..6 { read.check_current_v3().unwrap(); }
            }
            let new = start.elapsed();
            ORIGINAL_READ_PROJECTIONS.with(|n| assert_eq!(n.get(), rounds));
            eprintln!("owned_encrypted_roster rounds={rounds} old_us={} new_us={}", old.as_micros(), new.as_micros());
        }
    }
    #[test]
    fn lexical_read_rejects_open_transaction_and_rolled_back_dirty_state() {
        let (_dir, _path, store, record) = fixture();
        let head = make_head(&store, &record);
        let read = head.original_read_v3().unwrap();
        store.connection.lock().unwrap().execute_batch("BEGIN; UPDATE records SET updated_at_ms=updated_at_ms+1 WHERE aggregate_type!='agreement';").unwrap();
        assert!(read.check_current_v3().is_err());
        store.connection.lock().unwrap().execute_batch("ROLLBACK").unwrap();
        assert_eq!(store.get_agreement(&record.id).unwrap().unwrap(), record);
        assert!(matches!(read.check_current_v3(), Err(StoreError::RevisionConflict)));
    }
    #[test]
    fn lexical_read_refuses_changed_agreement_or_failed_original_audit() {
        let (_dir, _path, store, record) = fixture();
        let head = make_head(&store, &record);
        store.connection.lock().unwrap().execute("UPDATE records SET payload='{}' WHERE aggregate_type='agreement' AND id=?1", [&record.id]).unwrap();
        assert!(head.check_current().is_err());
        assert!(head.original_read_v3().is_err());
        // A new pin over already-corrupted history is not an audit proof.
        let (_dir, _path, store, record) = fixture();
        let head = make_head(&store, &record);
        store.connection.lock().unwrap().execute(
            "UPDATE records SET payload='{}' WHERE aggregate_type=?1",
            [crate::manual_enrollment::INITIAL_PUBLICATION_V2],
        ).unwrap();
        assert_eq!(store.get_agreement(&record.id).unwrap().unwrap(), record);
        assert!(store.pin_original_source_read_revision_v3(&record.id).is_ok());
        assert!(head.original_read_v3().is_err());
    }
    #[test]
    fn lexical_read_rejects_generation_schema_and_file_replacement() {
        for change in 0..3 {
            let (_dir, path, store, record) = fixture();
            let head = make_head(&store, &record);
            let read = head.original_read_v3().unwrap();
            match change {
                0 => { store.connection.lock().unwrap().execute("UPDATE records SET payload=?1 WHERE aggregate_type='settlement_generation_identity'", [serde_json::to_string(&"d".repeat(64)).unwrap()]).unwrap(); }
                1 => { store.connection.lock().unwrap().pragma_update(None, "user_version", 6).unwrap(); }
                _ => {
                    std::fs::rename(&path, path.with_extension("old")).unwrap();
                    std::fs::write(&path, b"not the retained original database").unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            assert!(read.check_current_v3().is_err());
            assert!(read.members_v3().is_err());
        }
    }
}
