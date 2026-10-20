//! Return-only interpretation of an already fully audited result snapshot.
//! No Clone, serde, factory outside this closed storage adapter, or refresh.
//! This pin is sampled change detection under the retained original directory
//! exclusion, not permission, external writer exclusion, or an OS sandbox.
use super::*;

#[derive(PartialEq, Eq)]
struct ReturnRevisionV1 {
    application_id: i64,
    data_version: i64,
    total_changes: i64,
    schema_version: i64,
    user_version: i64,
}
fn return_revision(c: &Connection) -> Result<ReturnRevisionV1> {
    Ok(ReturnRevisionV1 {
        application_id: c.pragma_query_value(None, "application_id", |r| r.get(0))?,
        data_version: c.pragma_query_value(None, "data_version", |r| r.get(0))?,
        total_changes: c.query_row("SELECT total_changes()", [], |r| r.get(0))?,
        schema_version: c.pragma_query_value(None, "schema_version", |r| r.get(0))?,
        user_version: c.pragma_query_value(None, "user_version", |r| r.get(0))?,
    })
}
pub(crate) struct FinancialReturnJournalPinV1 {
    journal: SignerJournalBinding,
    registration: Arc<LiveCurrent19Source>,
    identity: wholepact_storage_security::DatabaseFileIdentity,
    source_digest: String,
    revision: ReturnRevisionV1,
    original_host_instance: String,
    result_digest: String,
}
impl FinancialReturnJournalPinV1 {
    /// Called only after the bridge adapter has audited the complete profile,
    /// exact original/request/permit/result and recipient in this same snapshot.
    pub(super) fn from_audited_result(
        journal: &FinancialConsentJournalV1,
        source: &FinancialSourceBindingV1,
        c: &Connection,
        original_host_instance: String,
        result_digest: String,
    ) -> Result<Self> {
        if c.is_autocommit() { return Err(JournalError::InvalidBinding); }
        hash(&original_host_instance)?;
        hash(&result_digest)?;
        source.require(&journal.journal, c)?;
        source.require_pin(c)?;
        let pin=Self {
            journal:journal.journal.binding(),
            registration:Arc::clone(&journal.journal.source_registration),
            identity:journal.journal.database_identity.clone(),
            source_digest:source.identity_digest().to_owned(),
            revision:return_revision(c)?,
            original_host_instance,
            result_digest,
        };
        pin.require(journal,source,c)?;
        Ok(pin)
    }
    pub(crate) fn original_host_instance(&self) -> &str { &self.original_host_instance }
    pub(crate) fn result_digest(&self) -> &str { &self.result_digest }
    pub(super) fn require(&self, journal:&FinancialConsentJournalV1, source:&FinancialSourceBindingV1, c:&Connection) -> Result<()> {
        if self.journal!=journal.journal.binding()
            || !Arc::ptr_eq(&self.registration,&journal.journal.source_registration)
            || self.identity!=journal.journal.database_identity
            || self.source_digest!=source.identity_digest()
        { return Err(JournalError::Permission); }
        // Original registration owns the retained exclusive Directory handle.
        // This is a live path/handle check, never just a serialized fingerprint.
        self.registration.owner.directory.check_current().map_err(|_|JournalError::Permission)?;
        source.require(&journal.journal,c)?;
        self.identity.check_current(c)?;
        if return_revision(c)?!=self.revision { return Err(JournalError::Conflict); }
        Ok(())
    }
}
impl FinancialConsentJournalV1 {
    /// Read-only, same-connection sample. No caller gets a lock, transaction,
    /// refreshed pin, semantic records, or new permission out of this method.
    pub(crate) fn check_financial_return_pin_v1(&self, source:&FinancialSourceBindingV1, pin:&FinancialReturnJournalPinV1) -> Result<()> {
        let _fence=self.journal.authority_fence.read().map_err(|_|JournalError::Permission)?;
        let mut c=self.journal.connection.lock().map_err(|_|JournalError::Database)?;
        if !c.is_autocommit() { return Err(JournalError::Conflict); }
        pin.require(self,source,&c)?;
        let tx=c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        // Establish an actual SQLite read snapshot without replaying history.
        let _:i64=tx.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get(0))?;
        pin.require(self,source,&tx)?;
        tx.commit()?;
        if !c.is_autocommit() { return Err(JournalError::Conflict); }
        pin.require(self,source,&c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt,path::PathBuf};
    use wholepact_authority::account_use::AccountUseIdentity;
    // Real encrypted revision/identity kernel coverage ONLY. Private test-only
    // construction below is not a valid profile20 audit or native return owner.
    // The full native CI must establish actual audited issuance and IPC return.
    struct Fixture {
        wrapper:FinancialConsentJournalV1,
        source:FinancialSourceBindingV1,
        pin:FinancialReturnJournalPinV1,
        path:PathBuf,
        key:DatabaseKey,
        _directory:crate::files::PrivateDirectory,
        _temp:tempfile::TempDir,
    }
    impl Fixture {
        fn new() -> Self {
            let temp=tempfile::tempdir().unwrap();
            std::fs::set_permissions(temp.path(),std::fs::Permissions::from_mode(0o700)).unwrap();
            let path=temp.path().join("original.sqlite");
            let directory=crate::files::PrivateDirectory::open(temp.path()).unwrap();
            let owner=directory.signer_journal_source_owner_for_test(&path).unwrap();
            let key=DatabaseKey::from_bytes([0x83;32]);
            let account="11".repeat(32);
            let journal=SignerConsentJournal::create_encrypted(&path,&key,&account,7,false,&owner).unwrap();
            let genesis=AccountUseGenesis {version:1,identity:AccountUseIdentity {account_id:account,full_viewing_key_digest:"22".repeat(32),network_profile_id:"synthetic-only".into(),derivation_domain:"synthetic-only".into()},witness_id:"synthetic-only".into(),witness_origin_digest:"33".repeat(32),owner_certificate_digest:"44".repeat(32),native_birth_digest:"55".repeat(32)};
            let (source,pin)={
                let c=journal.connection.lock().unwrap();
                let source=FinancialSourceBindingV1 {journal:journal.binding(),identity:journal.database_identity.clone(),genesis:genesis.clone(),source_digest:"66".repeat(32),original_rows_digest:"77".repeat(32),continuation_digest:None,revision:revision(&c).unwrap()};
                let pin=FinancialReturnJournalPinV1 {journal:journal.binding(),registration:Arc::clone(&journal.source_registration),identity:journal.database_identity.clone(),source_digest:source.source_digest.clone(),revision:return_revision(&c).unwrap(),original_host_instance:"88".repeat(32),result_digest:"99".repeat(32)};
                (source,pin)
            };
            Self {wrapper:FinancialConsentJournalV1 {journal,genesis},source,pin,path,key,_directory:directory,_temp:temp}
        }
        fn check(&self) -> Result<()> {self.wrapper.check_financial_return_pin_v1(&self.source,&self.pin)}
    }
    #[test]
    fn encrypted_return_pin_same_connection_mutation_dirty_and_rollback_refuse() {
        let f=Fixture::new();f.check().unwrap();f.check().unwrap();
        let before=f.wrapper.journal.connection.lock().unwrap().total_changes();
        f.check().unwrap();
        assert_eq!(before,f.wrapper.journal.connection.lock().unwrap().total_changes());
        {
            let c=f.wrapper.journal.connection.lock().unwrap();
            c.execute_batch("BEGIN DEFERRED").unwrap();
        }
        assert!(f.check().is_err());
        f.wrapper.journal.connection.lock().unwrap().execute_batch("ROLLBACK").unwrap();
        f.check().unwrap(); // Empty dirty snapshot had no semantic mutation.
        {
            let c=f.wrapper.journal.connection.lock().unwrap();
            c.execute_batch("BEGIN IMMEDIATE; UPDATE signer_account SET writer_epoch=writer_epoch; ROLLBACK").unwrap();
        }
        assert!(matches!(f.check(),Err(JournalError::Conflict)));
        assert!(matches!(f.check(),Err(JournalError::Conflict))); // No refresh.
        let f=Fixture::new();
        f.wrapper.journal.connection.lock().unwrap().execute("UPDATE signer_account SET writer_epoch=writer_epoch",[]).unwrap();
        assert!(matches!(f.check(),Err(JournalError::Conflict)));
    }
    #[test]
    fn encrypted_return_pin_external_restore_and_header_drift_refuse() {
        let f=Fixture::new();
        let other=wholepact_storage_security::open_encrypted(&f.path,&f.key).unwrap().into_connection();
        f.check().unwrap();
        other.execute_batch("UPDATE signer_account SET writer_epoch=8; UPDATE signer_account SET writer_epoch=7").unwrap();
        assert!(matches!(f.check(),Err(JournalError::Conflict)));
        for pragma in ["application_id","schema_version","user_version"] {
            let f=Fixture::new();f.check().unwrap();
            let c=f.wrapper.journal.connection.lock().unwrap();
            let value:i64=c.pragma_query_value(None,pragma,|r|r.get(0)).unwrap();
            c.pragma_update(None,pragma,value+1).unwrap();drop(c);
            assert!(matches!(f.check(),Err(JournalError::Conflict)));
        }
    }
    #[test]
    fn encrypted_return_pin_foreign_connection_registration_and_replaced_file_refuse() {
        let mut f=Fixture::new();let other=Fixture::new();
        assert!(other.wrapper.check_financial_return_pin_v1(&other.source,&f.pin).is_err());
        assert!(other.wrapper.check_financial_return_pin_v1(&f.source,&f.pin).is_err());
        let original_registration=Arc::clone(&f.pin.registration);
        f.pin.registration=Arc::clone(&other.wrapper.journal.source_registration);
        assert!(matches!(f.check(),Err(JournalError::Permission)));
        f.pin.registration=original_registration;
        f.check().unwrap();
        let held=f.path.with_extension("held-original");
        std::fs::rename(&f.path,&held).unwrap();
        std::fs::copy(&held,&f.path).unwrap();
        assert!(f.check().is_err());
    }
}
