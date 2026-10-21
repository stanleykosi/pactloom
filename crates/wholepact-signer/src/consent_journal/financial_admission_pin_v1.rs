//! Admission-only sampled custody of a fully audited immutable pending request.
//! Not permission, an external writer lock, a refresh, or a retry signal.
use super::*;

#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "financial_admission_pin_v1/coordinated_admit_v1.rs"]
mod coordinated_admit;

#[derive(PartialEq, Eq)]
struct AdmissionRevisionV1 {
    application_id: i64,
    data_version: i64,
    total_changes: i64,
    schema_version: i64,
    user_version: i64,
}
fn admission_revision(c: &Connection) -> Result<AdmissionRevisionV1> {
    Ok(AdmissionRevisionV1 {
        application_id: c.pragma_query_value(None,"application_id",|r|r.get(0))?,
        data_version: c.pragma_query_value(None,"data_version",|r|r.get(0))?,
        total_changes: c.query_row("SELECT total_changes()",[],|r|r.get(0))?,
        schema_version: c.pragma_query_value(None,"schema_version",|r|r.get(0))?,
        user_version: c.pragma_query_value(None,"user_version",|r|r.get(0))?,
    })
}
struct AdmissionCustodyPinV1 {
    journal: SignerJournalBinding,
    registration: Arc<LiveCurrent19Source>,
    identity: wholepact_storage_security::DatabaseFileIdentity,
    current_identity: String,
    pending_identity: String,
    revision: AdmissionRevisionV1,
}
impl AdmissionCustodyPinV1 {
    fn capture(journal:&FinancialConsentJournalV1,current:&FinancialSourceBindingV1,pending:&FinancialSourceBindingV1,c:&Connection)->Result<Self> {
        if c.is_autocommit() { return Err(JournalError::InvalidBinding); }
        current.require(&journal.journal,c)?;
        pending.require(&journal.journal,c)?;
        let pin=Self {journal:journal.journal.binding(),registration:Arc::clone(&journal.journal.source_registration),identity:journal.journal.database_identity.clone(),current_identity:current.identity_digest().to_owned(),pending_identity:pending.identity_digest().to_owned(),revision:admission_revision(c)?};
        pin.require(journal,current,pending,c)?;
        Ok(pin)
    }
    fn require(&self,journal:&FinancialConsentJournalV1,current:&FinancialSourceBindingV1,pending:&FinancialSourceBindingV1,c:&Connection)->Result<()> {
        if self.journal!=journal.journal.binding()
            || !Arc::ptr_eq(&self.registration,&journal.journal.source_registration)
            || self.identity!=journal.journal.database_identity
            || self.current_identity!=current.identity_digest()
            || self.pending_identity!=pending.identity_digest()
        { return Err(JournalError::Permission); }
        self.registration.owner.directory.check_current().map_err(|_|JournalError::Permission)?;
        current.require(&journal.journal,c)?;
        pending.require(&journal.journal,c)?;
        self.identity.check_current(c)?;
        if self.revision!=admission_revision(c)? || current.revision!=revision(c)? || pending.revision!=revision(c)? {return Err(JournalError::Conflict);}
        Ok(())
    }
}
/// Issued only by the full audited admission factory below. No Clone or serde.
pub(crate) struct FinancialAdmissionJournalPinV1 {
    custody: AdmissionCustodyPinV1,
    retained: RetainedFinancialContinuationIntentV1,
    history_digest: String,
    original_rows_digest: String,
}
impl FinancialAdmissionJournalPinV1 {
    fn require(&self,journal:&FinancialConsentJournalV1,current:&FinancialSourceBindingV1,pending:&PendingFinancialContinuationAdmissionV1,c:&Connection)->Result<()> {
        self.custody.require(journal,current,&pending.source,c)?;
        if self.retained!=pending.retained || current.genesis!=journal.genesis || pending.source.genesis!=journal.genesis
            || current.original_rows_digest!=self.original_rows_digest || pending.source.original_rows_digest!=self.original_rows_digest
            || current.continuation_digest.as_deref()!=Some(self.history_digest.as_str())
            || pending.source.continuation_digest.as_deref()!=Some(self.history_digest.as_str())
        {return Err(JournalError::Conflict);}
        // Original wall-clock ceiling remains enforced in every callback.
        self.retained.terms()?.require_live(now_ms()?).map_err(|_|JournalError::Expired)
    }
}
impl FinancialConsentJournalV1 {
    pub(crate) fn prepare_financial_admission_pin_v1(&self,current:&FinancialSourceBindingV1,pending:&PendingFinancialContinuationAdmissionV1)->Result<FinancialAdmissionJournalPinV1> {
        let _fence=self.journal.authority_fence.read().map_err(|_|JournalError::Permission)?;
        let mut c=self.journal.connection.lock().map_err(|_|JournalError::Database)?;
        if !c.is_autocommit() {return Err(JournalError::Conflict);}
        current.require(&self.journal,&c)?; pending.source.require(&self.journal,&c)?;
        current.require_pin(&c)?; pending.source.require_pin(&c)?;
        let before=admission_revision(&c)?;
        let tx=c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate(&tx,&self.genesis)?;
        let retained=intent::read(&tx)?;
        if retained!=pending.retained {return Err(JournalError::Conflict);}
        let history_digest=retained.history_digest()?;
        let original_rows_digest=original_rows_digest(&tx)?;
        current.require_pin(&tx)?; pending.source.require_pin(&tx)?;
        let pin=FinancialAdmissionJournalPinV1 {custody:AdmissionCustodyPinV1::capture(self,current,&pending.source,&tx)?,retained,history_digest,original_rows_digest};
        if pin.custody.revision!=before {return Err(JournalError::Conflict);}
        pin.require(self,current,pending,&tx)?;
        tx.commit()?;
        if !c.is_autocommit() {return Err(JournalError::Conflict);}
        pin.require(self,current,pending,&c)?;
        Ok(pin)
    }
    /// Sample exact same connection before/inside/after a read-only transaction.
    /// No semantic replay, refreshed evidence, or held lock across socket I/O.
    pub(crate) fn check_financial_admission_pin_v1(&self,current:&FinancialSourceBindingV1,pending:&PendingFinancialContinuationAdmissionV1,pin:&FinancialAdmissionJournalPinV1)->Result<()> {
        let _fence=self.journal.authority_fence.read().map_err(|_|JournalError::Permission)?;
        let mut c=self.journal.connection.lock().map_err(|_|JournalError::Database)?;
        if !c.is_autocommit() {return Err(JournalError::Conflict);}
        pin.require(self,current,pending,&c)?;
        let tx=c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let _:i64=tx.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get(0))?;
        pin.require(self,current,pending,&tx)?;
        tx.commit()?;
        if !c.is_autocommit() {return Err(JournalError::Conflict);}
        pin.require(self,current,pending,&c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt,path::PathBuf};
    use wholepact_authority::account_use::AccountUseIdentity;
    // Actual encrypted custody constructor and revision mechanics ONLY. This
    // fixture cannot issue a valid audited profile20 pending request or action.
    struct Fixture {
        wrapper: FinancialConsentJournalV1,
        current: FinancialSourceBindingV1,
        pending: FinancialSourceBindingV1,
        pin: AdmissionCustodyPinV1,
        path: PathBuf,
        key: DatabaseKey,
        _directory: crate::files::PrivateDirectory,
        _temp: tempfile::TempDir,
    }
    impl Fixture {
        fn new()->Self {
            let temp=tempfile::tempdir().unwrap();
            std::fs::set_permissions(temp.path(),std::fs::Permissions::from_mode(0o700)).unwrap();
            let path=temp.path().join("original.sqlite");
            let directory=crate::files::PrivateDirectory::open(temp.path()).unwrap();
            let owner=directory.signer_journal_source_owner_for_test(&path).unwrap();
            let key=DatabaseKey::from_bytes([0x94;32]);
            let account="11".repeat(32);
            let journal=SignerConsentJournal::create_encrypted(&path,&key,&account,7,false,&owner).unwrap();
            let genesis=AccountUseGenesis {version:1,identity:AccountUseIdentity {account_id:account,full_viewing_key_digest:"22".repeat(32),network_profile_id:"synthetic-only".into(),derivation_domain:"synthetic-only".into()},witness_id:"synthetic-only".into(),witness_origin_digest:"33".repeat(32),owner_certificate_digest:"44".repeat(32),native_birth_digest:"55".repeat(32)};
            let wrapper=FinancialConsentJournalV1 {journal,genesis};
            let (current,pending,pin)={
                let mut c=wrapper.journal.connection.lock().unwrap();
                let source=|identity:String| FinancialSourceBindingV1 {journal:wrapper.journal.binding(),identity:wrapper.journal.database_identity.clone(),genesis:wrapper.genesis.clone(),source_digest:identity,original_rows_digest:"77".repeat(32),continuation_digest:None,revision:revision(&c).unwrap()};
                let current=source("66".repeat(32));
                let pending=source("88".repeat(32));
                assert!(AdmissionCustodyPinV1::capture(&wrapper,&current,&pending,&c).is_err());
                let before=admission_revision(&c).unwrap();
                let tx=c.transaction_with_behavior(TransactionBehavior::Deferred).unwrap();
                let _:i64=tx.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get(0)).unwrap();
                let pin=AdmissionCustodyPinV1::capture(&wrapper,&current,&pending,&tx).unwrap();
                pin.require(&wrapper,&current,&pending,&tx).unwrap();
                tx.commit().unwrap();
                assert!(c.is_autocommit());
                assert!(before==admission_revision(&c).unwrap());
                pin.require(&wrapper,&current,&pending,&c).unwrap();
                (current,pending,pin)
            };
            Self {wrapper,current,pending,pin,path,key,_directory:directory,_temp:temp}
        }
        fn check(&self)->Result<()> {
            let mut c=self.wrapper.journal.connection.lock().map_err(|_|JournalError::Database)?;
            if !c.is_autocommit() {return Err(JournalError::Conflict);}
            self.pin.require(&self.wrapper,&self.current,&self.pending,&c)?;
            let tx=c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let _:i64=tx.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get(0))?;
            self.pin.require(&self.wrapper,&self.current,&self.pending,&tx)?;
            tx.commit()?;
            self.pin.require(&self.wrapper,&self.current,&self.pending,&c)
        }
    }
    #[test]
    fn encrypted_admission_pin_actual_custody_constructor_and_distinct_sources() {
        let mut f=Fixture::new();
        assert_ne!(f.current.identity_digest(),f.pending.identity_digest());
        f.check().unwrap();
        let before=f.wrapper.journal.connection.lock().unwrap().total_changes();
        f.check().unwrap();
        assert_eq!(before,f.wrapper.journal.connection.lock().unwrap().total_changes());
        std::mem::swap(&mut f.current.source_digest,&mut f.pending.source_digest);
        assert!(f.check().is_err());
        std::mem::swap(&mut f.current.source_digest,&mut f.pending.source_digest);
        f.check().unwrap();
        let saved=f.pending.source_digest.clone();f.pending.source_digest="99".repeat(32);
        assert!(f.check().is_err());f.pending.source_digest=saved;f.check().unwrap();
        let saved=f.current.source_digest.clone();f.current.source_digest="99".repeat(32);
        assert!(f.check().is_err());f.current.source_digest=saved;f.check().unwrap();
    }
    #[test]
    fn encrypted_admission_pin_mutation_rollback_external_restore_and_headers_refuse() {
        let f=Fixture::new();
        f.wrapper.journal.connection.lock().unwrap().execute_batch("BEGIN DEFERRED").unwrap();
        assert!(f.check().is_err());
        f.wrapper.journal.connection.lock().unwrap().execute_batch("ROLLBACK").unwrap();f.check().unwrap();
        f.wrapper.journal.connection.lock().unwrap().execute_batch("BEGIN IMMEDIATE; UPDATE signer_account SET writer_epoch=writer_epoch; ROLLBACK").unwrap();
        assert!(f.check().is_err());assert!(f.check().is_err());
        let f=Fixture::new();
        f.wrapper.journal.connection.lock().unwrap().execute("UPDATE signer_account SET writer_epoch=writer_epoch",[]).unwrap();
        assert!(f.check().is_err());
        let f=Fixture::new();
        let other=wholepact_storage_security::open_encrypted(&f.path,&f.key).unwrap().into_connection();
        other.execute_batch("UPDATE signer_account SET writer_epoch=8; UPDATE signer_account SET writer_epoch=7").unwrap();
        assert!(f.check().is_err());
        for pragma in ["application_id","schema_version","user_version"] {
            let f=Fixture::new();let c=f.wrapper.journal.connection.lock().unwrap();
            let value:i64=c.pragma_query_value(None,pragma,|r|r.get(0)).unwrap();
            c.pragma_update(None,pragma,value+1).unwrap();drop(c);
            assert!(f.check().is_err());
        }
    }
    #[test]
    fn encrypted_admission_pin_foreign_registration_binding_and_replacement_refuse() {
        let mut f=Fixture::new();let other=Fixture::new();
        let registration=Arc::clone(&f.pin.registration);
        f.pin.registration=Arc::clone(&other.wrapper.journal.source_registration);
        assert!(f.check().is_err());f.pin.registration=registration;f.check().unwrap();
        f.pending.journal=other.wrapper.journal.binding();
        assert!(f.check().is_err());
        let mut f=Fixture::new();
        f.current.journal=other.wrapper.journal.binding();
        assert!(f.check().is_err());
        let f=Fixture::new();
        let held=f.path.with_extension("held-original");
        std::fs::rename(&f.path,&held).unwrap();std::fs::copy(&held,&f.path).unwrap();
        assert!(f.check().is_err());
    }
}
