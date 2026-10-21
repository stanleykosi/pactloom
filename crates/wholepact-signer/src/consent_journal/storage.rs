use super::*;
#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "coordinated_entry_open_v2.rs"]
mod coordinated_entry_open_v2;
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    target_os = "linux"
))]
#[path = "durable_born_entry_v1.rs"]
mod durable_born_entry_v1;
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    target_os = "linux"
))]
#[path = "prepared_delivery_v3.rs"]
mod prepared_delivery_v3;
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    target_os = "linux"
))]
pub(crate) use prepared_delivery_v3::PreparedDeliveryJournalRevisionV3;
#[cfg(test)]
#[path = "validation_cost_v1.rs"]
mod validation_cost_v1;
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    target_os = "linux"
))]
pub(crate) use durable_born_entry_v1::validate_durable_payment_local_history_v1;
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    target_os = "linux"
))]
pub(super) use durable_born_entry_v1::{
    validate_durable_born_prefix_v1, validate_durable_born_suffix_v1,
};

#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", target_os = "linux"))]
#[path = "financial_profile_v1.rs"]
pub(crate) mod financial_profile_v1;

// Keep the observer's types private while measuring the closed snapshot path
// with the same phase boundaries as the ordinary durable-born validator.
#[cfg(all(
    test,
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    target_os = "linux"
))]
pub(super) fn enter_durable_born_validation_cost_v1() -> impl Drop {
    validation_cost_v1::enter(validation_cost_v1::Phase::ValidationTotal)
}
#[cfg(all(
    test,
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    target_os = "linux"
))]
pub(super) fn enter_durable_born_inventory_cost_v1() -> impl Drop {
    validation_cost_v1::enter(validation_cost_v1::Phase::Inventory)
}

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{
    path::Path,
    sync::{Mutex, RwLock, RwLockReadGuard},
};
use wholepact_storage_security::{
    bundle::{BackupReadPermit, BundleError, JournalAdapter, JournalKind, JournalTemplate},
    DatabaseKey,
};

pub(super) static TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: SCHEMA_VERSION,
    create_sql: SCHEMA,
};

/// Concrete actual-directory custody for one original signer database. This
/// never authenticates a key or grants account/native/financial permission.
pub(crate) struct SignerJournalSourceOwner {
    directory: crate::files::RetainedDirectoryExclusion,
    path: std::path::PathBuf,
    state: Mutex<std::sync::Weak<LiveCurrent19Source>>,
}
struct LiveCurrent19Source {
    identity: wholepact_storage_security::DatabaseFileIdentity,
    account_id: String,
    owner: Arc<SignerJournalSourceOwner>,
}
/// The connection MUST drop before registration, including errors and unwind.
struct OpenedSignerSource {
    connection: Connection,
    identity: wholepact_storage_security::DatabaseFileIdentity,
    registration: Arc<LiveCurrent19Source>,
}
pub(super) struct OriginalSourceOpen<'a> {
    owner: &'a Arc<SignerJournalSourceOwner>,
    state: std::sync::MutexGuard<'a, std::sync::Weak<LiveCurrent19Source>>,
}
impl SignerJournalSourceOwner {
    pub(crate) fn new(
        directory: crate::files::RetainedDirectoryExclusion,
        child: &str,
    ) -> crate::Result<Self> {
        directory.check_current()?;
        if child.is_empty()
            || child.len() > 160
            || child == "."
            || child == ".."
            || !child
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(crate::Error::InvalidData);
        }
        let path = directory.root().join(child);
        Ok(Self {
            directory,
            path,
            state: Mutex::new(std::sync::Weak::new()),
        })
    }
    pub(super) fn begin<'a>(self: &'a Arc<Self>, path: &Path) -> Result<OriginalSourceOpen<'a>> {
        self.directory
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        let parent = path.parent().ok_or(JournalError::InvalidBinding)?;
        if std::fs::canonicalize(parent).map_err(|_| JournalError::InvalidBinding)?
            != self.directory.root()
            || path.file_name() != self.path.file_name()
        {
            return Err(JournalError::InvalidBinding);
        }
        let state = self.state.lock().map_err(|_| JournalError::Permission)?;
        self.directory
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        Ok(OriginalSourceOpen { owner: self, state })
    }
}
// Closed executable-selected original profiles. Ordinary readers never infer
// a financial transition from a user_version or caller-supplied flag.
#[derive(Clone, Copy)]
enum OriginalJournalProfile {
    Current19,
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", target_os = "linux"))]
    Financial20,
}
impl OriginalJournalProfile {
    fn version(self) -> i64 { match self {
        Self::Current19 => SCHEMA_VERSION,
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", target_os = "linux"))]
        Self::Financial20 => financial_profile_v1::VERSION,
    } }
    fn verify(self, c: &Connection) -> Result<()> { match self {
        Self::Current19 => verify_schema(c),
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", target_os = "linux"))]
        Self::Financial20 => financial_profile_v1::verify_schema(c),
    } }
}
impl OriginalSourceOpen<'_> {
    pub(super) fn require_exclusive(&self) -> Result<()> {
        if self.state.upgrade().is_some() {
            return Err(JournalError::Conflict);
        }
        self.owner
            .directory
            .check_current()
            .map_err(|_| JournalError::Permission)
    }
    fn register(
        &mut self,
        connection: &Connection,
        identity: &wholepact_storage_security::DatabaseFileIdentity,
        account_id: &str,
    ) -> Result<Arc<LiveCurrent19Source>> {
        self.register_exact_profile(connection, identity, account_id, OriginalJournalProfile::Current19)
    }
    fn register_exact_profile(
        &mut self,
        connection: &Connection,
        identity: &wholepact_storage_security::DatabaseFileIdentity,
        account_id: &str,
        profile: OriginalJournalProfile,
    ) -> Result<Arc<LiveCurrent19Source>> {
        self.owner
            .directory
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        identity.check_current(connection)?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application != APPLICATION_ID
            || version != profile.version()
            || read_account(connection)?.account_id != account_id
        {
            return Err(JournalError::InvalidBinding);
        }
        profile.verify(connection)?;
        identity.check_current(connection)?;
        self.owner
            .directory
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        if let Some(live) = self.state.upgrade() {
            if live.identity != *identity
                || live.account_id != account_id
                || !Arc::ptr_eq(&live.owner, self.owner)
            {
                return Err(JournalError::InvalidBinding);
            }
            return Ok(live);
        }
        let live = Arc::new(LiveCurrent19Source {
            identity: identity.clone(),
            account_id: account_id.into(),
            owner: Arc::clone(self.owner),
        });
        *self.state = Arc::downgrade(&live);
        Ok(live)
    }
}

/// Only AccountVault can open this private authority. It never yields a Store,
/// database key, generic SQL connection, generic record writer or release token.
pub struct SignerConsentJournal {
    pub(super) connection: Mutex<Connection>,
    /// Captured only by the authenticated SQLCipher factory, never from archive
    /// cells, a path claim or an imported receipt. Read-only correlation only.
    pub(super) database_identity: wholepact_storage_security::DatabaseFileIdentity,
    binding: SignerJournalBinding,
    pub(super) authority_fence: RwLock<()>,
    #[cfg(feature = "authority-signing")]
    pub(super) settlement_nodes: Mutex<
        std::collections::BTreeMap<String, Arc<wholepact_chain::local_node::LocalValidatingNode>>,
    >,
    #[cfg(test)]
    pub(super) capacity_limits: (u64, u64),
    // LAST: SQLite and all its final checkpoint work close before source custody.
    source_registration: Arc<LiveCurrent19Source>,
}
impl SignerConsentJournal {
    fn from_owned_source(opened: OpenedSignerSource) -> Self {
        Self {
            connection: Mutex::new(opened.connection),
            database_identity: opened.identity,
            binding: SignerJournalBinding(Arc::new(())),
            authority_fence: RwLock::new(()),
            #[cfg(feature = "authority-signing")]
            settlement_nodes: Mutex::new(std::collections::BTreeMap::new()),
            #[cfg(test)]
            capacity_limits: (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
            source_registration: opened.registration,
        }
    }
    pub(crate) fn create_encrypted(
        path: &Path,
        key: &DatabaseKey,
        account_id: &str,
        writer_epoch: u64,
        recovery_required: bool,
        source: &Arc<SignerJournalSourceOwner>,
    ) -> Result<Self> {
        id(account_id)?;
        let epoch = i64::try_from(writer_epoch).map_err(|_| JournalError::InvalidBinding)?;
        if epoch <= 0 {
            return Err(JournalError::InvalidBinding);
        }
        let mut owner = source.begin(path)?;
        owner.require_exclusive()?;
        // Declared after owner: all raw SQLite cleanup precedes owner unlock.
        let encrypted = wholepact_storage_security::create_encrypted(path, key)?;
        let identity = encrypted.database_identity()?;
        let mut connection = encrypted.into_connection();
        configure(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        verify_capacity_schema(&tx)?;
        tx.execute(
            "INSERT INTO signer_account VALUES(1,?1,?2,?3)",
            params![account_id, epoch, recovery_required],
        )?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        let registration = owner.register(&connection, &identity, account_id)?;
        Ok(Self::from_owned_source(OpenedSignerSource {
            connection,
            identity,
            registration,
        }))
    }
    pub(crate) fn open_encrypted(
        path: &Path,
        key: &DatabaseKey,
        account_id: &str,
        source: &Arc<SignerJournalSourceOwner>,
    ) -> Result<Self> {
        let mut owner = source.begin(path)?;
        let opened =
            open_preflighted_encrypted(&mut owner, path, key, account_id, None, &|_| Ok(()))?;
        let generations: u64 = opened.connection.query_row(
            "SELECT count(*) FROM signer_recovery_generations",
            [],
            |r| r.get(0),
        )?;
        if generations != 0 {
            return Err(JournalError::RecoveryRequired);
        }
        Ok(Self::from_owned_source(opened))
    }
    /// Actual born origin always chooses current-only, even if old cells claim
    /// UNKNOWN pre-genesis or were removed. There is no born schema upgrade.
    #[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
    pub(crate) fn open_known_born_encrypted(
        path: &Path,
        key: &DatabaseKey,
        genesis: &wholepact_authority::account_use::AccountUseGenesis,
        source: &Arc<SignerJournalSourceOwner>,
    ) -> Result<Self> {
        let mut owner = source.begin(path)?;
        let opened = open_preflighted_encrypted(
            &mut owner,
            path,
            key,
            &genesis.identity.account_id,
            Some(genesis),
            &|_| Ok(()),
        )?;
        let generations: u64 = opened.connection.query_row(
            "SELECT count(*) FROM signer_recovery_generations",
            [],
            |r| r.get(0),
        )?;
        if generations != 0 {
            return Err(JournalError::RecoveryRequired);
        }
        Ok(Self::from_owned_source(opened))
    }
    #[cfg(all(
        feature = "native-ui",
        feature = "authority-signing",
        target_os = "linux"
    ))]
    pub(crate) fn open_activated_encrypted(
        path: &Path,
        key: &DatabaseKey,
        account_id: &str,
        proof: &crate::account::VerifiedProfileActivation,
        source: &Arc<SignerJournalSourceOwner>,
    ) -> Result<Self> {
        let mut owner = source.begin(path)?;
        let opened =
            open_preflighted_encrypted(&mut owner, path, key, account_id, None, &|_| Ok(()))?;
        let record = proof.record();
        let payload = encode(record)?;
        let rows:i64=opened.connection.query_row("SELECT count(*) FROM signer_recovery_generations WHERE generation_id=?1 AND operation_id=?2 AND inventory_digest=?3 AND fence_digest=?4 AND writer_epoch=?5 AND payload=?6",params![record.generation_id,record.operation_id,record.inventory_digest,record.fence_digest,record.writer_epoch,payload.as_str()],|r|r.get(0))?;
        let account = read_account(&opened.connection)?;
        if rows != 2
            || account.account_id != account_id
            || account.account_id != record.account_id
            || account.writer_epoch < record.writer_epoch
            || account.recovery_required
        {
            return Err(JournalError::RecoveryRequired);
        }
        Ok(Self::from_owned_source(opened))
    }
    pub fn binding(&self) -> SignerJournalBinding {
        self.binding.clone()
    }
    pub fn account_state(&self) -> Result<SignerAccountState> {
        read_account(&*self.connection.lock().map_err(|_| JournalError::Database)?)
    }
    /// Conservative one-way quarantine. There is no clear/reset API.
    pub fn require_recovery(&self) -> Result<()> {
        let _fence = self
            .authority_fence
            .write()
            .map_err(|_| JournalError::Permission)?;
        let connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        if connection.execute(
            "UPDATE signer_account SET recovery_required=1 WHERE singleton=1",
            [],
        )? != 1
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub fn record_enrollment(
        &self,
        approved: ApprovedEnrollment,
    ) -> Result<AccountEnrollmentRecord> {
        let a = approved.0;
        a.record.validate()?;
        let account = self.account_state()?;
        let lease = a.lease(&self.binding, &account, a.record.receipt())?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let mut connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_account(&tx, &account)?;
        if lease.principal != a.record.principal_id() || account.account_id != a.record.account_id()
        {
            return Err(JournalError::Permission);
        }
        if let Some(old) = read_enrollment(&tx, a.record.reference())? {
            if old != a.record {
                return Err(JournalError::Conflict);
            }
            return Ok(old);
        }
        let raw = encode(&a.record)?;
        tx.execute(
            "INSERT INTO signer_enrollments VALUES(?1,?2,?3,?4,?5)",
            params![
                a.record.reference(),
                a.record.account_id(),
                a.record.agreement_id(),
                a.record.participant_id(),
                raw.as_str()
            ],
        )?;
        bounded(&tx, self.capacity_limits())?;
        tx.commit()?;
        Ok(a.record.clone())
    }
    pub fn record_accepted_manifest(
        &self,
        approved: ApprovedManifestAcceptance,
    ) -> Result<AcceptedManifestRecord> {
        let a = approved.0;
        let proposal = a.record.proposal()?;
        let account = self.account_state()?;
        let lease = a.lease(&self.binding, &account, a.record.receipt())?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let mut connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_account(&tx, &account)?;
        let enrollment =
            read_enrollment(&tx, a.record.enrollment_ref())?.ok_or(JournalError::NotFound)?;
        if lease.principal != enrollment.principal_id()
            || account.account_id != enrollment.account_id()
            || a.record.terms.account_id != enrollment.account_id()
            || a.record.terms.principal_id != enrollment.principal_id()
            || proposal.manifest().agreement.agreement_id != enrollment.agreement_id()
            || proposal.manifest().agreement.network_profile_id
                != enrollment.terms.network_profile_id
            || !proposal.manifest().participants.iter().any(|p| {
                p.account_id == enrollment.account_id()
                    && p.participant_id == enrollment.participant_id()
            })
        {
            return Err(JournalError::InvalidBinding);
        }
        enrollment.transport().validate_scope(
            enrollment.account_id(),
            enrollment.agreement_id(),
            enrollment.participant_id(),
            Some(proposal.manifest_digest()),
        )?;
        if !same_native_origin(enrollment.receipt(), a.record.receipt()) {
            return Err(JournalError::Permission);
        }
        if let Some(old) = read_manifest(&tx, a.record.reference())? {
            if old != a.record {
                return Err(JournalError::Conflict);
            }
            return Ok(old);
        }
        let existing: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM signer_accepted_manifests WHERE enrollment_ref=?1 AND proposal_id=?2)", params![a.record.enrollment_ref(), proposal.input().proposal_id], |r| r.get(0))?;
        if existing {
            return Err(JournalError::Conflict);
        }
        let raw = encode(&a.record)?;
        tx.execute(
            "INSERT INTO signer_accepted_manifests VALUES(?1,?2,?3,?4,?5)",
            params![
                a.record.reference(),
                a.record.enrollment_ref(),
                proposal.input().proposal_id,
                a.record.proposal_digest(),
                raw.as_str()
            ],
        )?;
        bounded(&tx, self.capacity_limits())?;
        tx.commit()?;
        Ok(a.record.clone())
    }
    /// One IMMEDIATE transaction appends the immutable original consent, exact
    /// release link and conservative reservations. A crash/failure cannot leave
    /// a consent-only record or export permission without durable exposure.
    /// Success is evidence of intent, never evidence a signature was produced.
    pub fn record_original_consent_release(
        &self,
        approved: ApprovedSpendConsent,
    ) -> Result<OriginalAuthorizationEvidence> {
        let a = approved.0;
        if a.record.terms().automation.is_some()
            || a.record.terms().durable_born_policy_v1.is_some()
        {
            return Err(JournalError::Permission);
        }
        self.record_consent_release(a)
    }
    /// Only the actual freshly opened original born source may consume this
    /// explicit profile. Saved policy mappings are historical data, not a
    /// replacement for native authority or the actual original vault/journal.
    #[cfg(all(
        feature = "durable-proposal",
        feature = "pending-birth-owner-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn record_durable_born_consent_release_v1(
        &self,
        approved: ApprovedSpendConsent,
        entry: &crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1,
    ) -> Result<OriginalAuthorizationEvidence> {
        entry
            .require_journal_identity(self)
            .map_err(|_| JournalError::Permission)?;
        let terms = approved.0.record.terms();
        let binding = terms
            .durable_born_policy_v1
            .as_ref()
            .ok_or(JournalError::Permission)?;
        if binding.uses_stable_recipient_policy_v2() {
            let original_policy = entry
                .original_recipient_policy_export_v2()
                .map_err(|_| JournalError::InvalidBinding)?;
            binding.validate_stable_original_source_v2(
                entry.record(),
                entry.genesis(),
                &original_policy,
            )?;
        } else {
            // Explicit legacy-exact mapping only. Its validator refuses a
            // stable-policy record rather than falling back by hash membership.
            binding.validate_original_source(entry.record(), entry.genesis())?;
        }
        binding.require_current_time(now_ms()?)?;
        if terms.automation.is_some()
            || terms.sponsor_policy.is_some()
            || terms.sponsor_owner_attestation_digest.is_some()
            || entry
                .account()
                .account_id()
                .map_err(|_| JournalError::InvalidBinding)?
                != terms.account_id
        {
            return Err(JournalError::InvalidBinding);
        }
        // record_consent_release rechecks the complete current local records,
        // exact mapping and persisted genesis in its own transaction, before
        // appending any irreversible release or input reservation.
        self.record_consent_release(approved.0)
    }
    pub(super) fn record_consent_release(
        &self,
        a: authority::Approval<OriginalSpendConsent>,
    ) -> Result<OriginalAuthorizationEvidence> {
        a.record.validate()?;
        let t = a.record.terms();
        let account = self.account_state()?;
        let lease = a.lease(&self.binding, &account, &t.receipt)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let mut connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_account(&tx, &account)?;
        if lease.principal != t.principal_id || account.account_id != t.account_id {
            return Err(JournalError::Permission);
        }
        #[cfg(feature = "authority-signing")]
        if !self.revalidate_settlements_in_transaction(&tx)? {
            tx.commit()?;
            return Err(JournalError::RecoveryRequired);
        }
        let enrollment = read_enrollment(&tx, &t.enrollment_ref)?.ok_or(JournalError::NotFound)?;
        let manifest =
            read_manifest(&tx, &t.accepted_manifest_ref)?.ok_or(JournalError::NotFound)?;
        let release = ConsentLinkedReleaseIntent::from_consent(&a.record);
        let result = OriginalAuthorizationEvidence {
            enrollment,
            manifest,
            consent: a.record.clone(),
            release,
        };
        validate_linkage(&result)?;
        validate_retained_durable_born_original_v1(&tx, &result)?;
        let result = append_release_rows(&tx, &result, ReleaseRowProfile::OriginalV1, self.capacity_limits())?;
        tx.commit()?;
        Ok(result)
    }
    pub fn enrollment(
        &self,
        reference: &str,
        session: &SignerConsentSession,
    ) -> Result<Option<AccountEnrollmentRecord>> {
        hash(reference)?;
        let account = self.account_state()?;
        let lease = session.read_lease(&self.binding, &account)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        check_account(&c, &account)?;
        let record = read_enrollment(&c, reference)?;
        if record
            .as_ref()
            .is_some_and(|r| r.principal_id() != lease.principal)
        {
            return Err(JournalError::Permission);
        }
        Ok(record)
    }
    pub fn accepted_manifest(
        &self,
        reference: &str,
        session: &SignerConsentSession,
    ) -> Result<Option<AcceptedManifestRecord>> {
        hash(reference)?;
        let account = self.account_state()?;
        let lease = session.read_lease(&self.binding, &account)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        check_account(&c, &account)?;
        let record = read_manifest(&c, reference)?;
        if record
            .as_ref()
            .is_some_and(|r| r.terms.principal_id != lease.principal)
        {
            return Err(JournalError::Permission);
        }
        Ok(record)
    }
    pub fn original_authorization(
        &self,
        authorization_id: &str,
        session: &SignerConsentSession,
    ) -> Result<Option<OriginalAuthorizationEvidence>> {
        match self.acquire_original_authorization(authorization_id, session) {
            Ok(lease) => Ok(Some(lease.evidence().clone())),
            Err(JournalError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }
    /// Holds current native permission and the journal's quarantine fence through
    /// every subsequent history handoff or synchronous key-use operation.
    pub fn acquire_original_authorization<'a>(
        &'a self,
        authorization_id: &str,
        session: &'a SignerConsentSession,
    ) -> Result<OriginalAuthorizationLease<'a>> {
        id(authorization_id)?;
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding, &account)?;
        let fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        check_account(&c, &account)?;
        let evidence = read_original(&c, authorization_id)?.ok_or(JournalError::NotFound)?;
        if evidence.original_consent().terms().principal_id != permission.principal {
            return Err(JournalError::Permission);
        }
        let sponsor_policy = sponsor::current_for_consent(&c, evidence.original_consent().terms());
        let lease = OriginalAuthorizationLease {
            automatic: None,
            sponsor_policy,
            permission,
            _fence: fence,
            evidence,
            binding: self.binding.clone(),
            recovery_required: account.recovery_required,
            permanent_account_exclusion: account_use_storage::inspect(&c, &account.account_id)?
                .exclusion()
                .is_some(),
        };
        lease.check_current()?;
        Ok(lease)
    }
    pub(crate) fn record_automatic_consent_release(
        &self,
        approved: ApprovedAutomaticSpendConsent,
    ) -> Result<(OriginalAuthorizationEvidence, ApprovedAutomaticContinuation)> {
        if approved.record().terms().automation.is_none() {
            return Err(JournalError::Permission);
        }
        let continuation = approved.continuation();
        continuation.check_current()?;
        let evidence = self.record_consent_release(approved.0)?;
        Ok((evidence, continuation))
    }
    pub(crate) fn original_automatic_authorization_lease<'a>(
        &'a self,
        authorization_id: &str,
        session: &'a SignerConsentSession,
        continuation: &ApprovedAutomaticContinuation,
    ) -> Result<OriginalAuthorizationLease<'a>> {
        let mut lease = self.acquire_original_authorization(authorization_id, session)?;
        continuation.matches(
            session,
            lease.evidence().original_consent(),
            &lease.permission,
        )?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        automation::current_for_consent(&c, lease.evidence().original_consent().terms())?
            .ok_or(JournalError::Permission)?;
        lease.automatic = Some(continuation.clone_for_lease());
        lease.require_current_authorization()?;
        Ok(lease)
    }
    pub(super) fn capacity_limits(&self) -> (u64, u64) {
        #[cfg(test)]
        {
            self.capacity_limits
        }
        #[cfg(not(test))]
        {
            (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES)
        }
    }
    #[cfg(test)]
    pub(super) fn quarantine_write_is_blocked(&self) -> bool {
        matches!(
            self.authority_fence.try_write(),
            Err(std::sync::TryLockError::WouldBlock)
        )
    }
    pub fn backup_adapter(&self) -> SignerConsentBundleAdapter<'_> {
        SignerConsentBundleAdapter { journal: self }
    }
}

/// A non-serializable held permission. Original evidence can be inspected under
/// a current session after reopening; fresh key use additionally requires the
/// exact original live native decision and monotonic expiry provenance.
pub struct OriginalAuthorizationLease<'a> {
    permission: authority::ReadLease<'a>,
    _fence: RwLockReadGuard<'a, ()>,
    evidence: OriginalAuthorizationEvidence,
    binding: SignerJournalBinding,
    recovery_required: bool,
    permanent_account_exclusion: bool,
    sponsor_policy: Result<Option<NativeSponsorPolicyRecord>>,
    automatic: Option<ApprovedAutomaticContinuation>,
}
impl OriginalAuthorizationLease<'_> {
    pub fn evidence(&self) -> &OriginalAuthorizationEvidence {
        &self.evidence
    }
    pub fn check_current(&self) -> Result<()> {
        self.permission.check_current()
    }
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    pub(crate) fn require_native_origin(
        &self,
        origin: &crate::native_ui::NativeAuthorityBinding,
    ) -> Result<()> {
        self.permission.require_native_origin(origin)
    }
    pub fn require_current_spending_decision(&self) -> Result<()> {
        if self
            .evidence
            .original_consent()
            .terms()
            .automation
            .is_some()
        {
            return Err(JournalError::Permission);
        }
        self.require_active_sponsor()?;
        self.permission
            .require_spending_decision(&self.evidence.original_consent().terms().receipt)
    }
    fn require_active_sponsor(&self) -> Result<()> {
        if self.permanent_account_exclusion {
            return Err(JournalError::Permission);
        }
        let policy = self
            .sponsor_policy
            .as_ref()
            .map_err(|_| JournalError::Permission)?;
        if let Some(policy) = policy {
            policy.require_active()?;
        }
        if self.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        self.permission.check_current()
    }
    /// Only an opaque automatic continuation may select the grant path. A plain
    /// historical original lease always retains the manual decision requirement.
    pub(crate) fn require_current_authorization(&self) -> Result<()> {
        match &self.automatic {
            Some(continuation) => {
                self.require_active_sponsor()?;
                continuation.check_current_held(&self.permission)
            }
            None => self.require_current_spending_decision(),
        }
    }
    pub(crate) fn binding(&self) -> &SignerJournalBinding {
        &self.binding
    }
}
pub(super) fn check_account(c: &Connection, expected: &SignerAccountState) -> Result<()> {
    let current = read_account(c)?;
    if current.recovery_required != expected.recovery_required {
        return Err(JournalError::RecoveryRequired);
    }
    if current.account_id != expected.account_id || current.writer_epoch != expected.writer_epoch {
        return Err(JournalError::Permission);
    }
    Ok(())
}

/// Exclusive FIRST opens use immutable-copy preflight. A genuine live exact19
/// registration permits maintained ordinary multi-open; its wrong-key failures
/// retain ordinary sidecar semantics and make no byte-preservation claim.
fn open_preflighted_encrypted(
    owner: &mut OriginalSourceOpen<'_>,
    path: &Path,
    key: &DatabaseKey,
    account_id: &str,
    known_born: Option<&wholepact_authority::account_use::AccountUseGenesis>,
    extra: &dyn Fn(&Connection) -> Result<()>,
) -> Result<OpenedSignerSource> {
    id(account_id)?;
    let current = owner.state.upgrade();
    if let Some(live) = current.as_ref() {
        if live.account_id != account_id || !Arc::ptr_eq(&live.owner, owner.owner) {
            return Err(JournalError::InvalidBinding);
        }
        owner
            .owner
            .directory
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        live.identity.check_retained_owner_path()?;
        let encrypted = wholepact_storage_security::open_encrypted(path, key)?;
        let identity = encrypted.database_identity()?;
        if identity != live.identity {
            return Err(JournalError::InvalidBinding);
        }
        let mut connection = encrypted.into_connection();
        {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            if preflight_original(&tx, account_id, known_born)? != SCHEMA_VERSION {
                return Err(JournalError::UnsupportedSchema);
            }
            extra(&tx)?;
            identity.check_current(&tx)?;
            tx.commit()?;
        }
        configure(&connection)?;
        let registration = owner.register(&connection, &identity, account_id)?;
        return Ok(OpenedSignerSource {
            connection,
            identity,
            registration,
        });
    }
    owner.require_exclusive()?;
    let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(path, key)?;
    let original_identity = snapshot.source_database_identity()?;
    let initial_version = {
        let tx = rusqlite::Transaction::new_unchecked(
            snapshot.connection(),
            TransactionBehavior::Deferred,
        )?;
        let version = preflight_original(&tx, account_id, known_born)?;
        // A source-owner token proves custody, not origin. No current approved
        // caller proves8..11 ordinary provenance, so UNKNOWN stays unsupported.
        if (8..=11).contains(&version) {
            return Err(JournalError::RecoveryRequired);
        }
        extra(&tx)?;
        tx.commit()?;
        version
    };
    snapshot.check_source_unchanged()?;
    owner
        .owner
        .directory
        .check_current()
        .map_err(|_| JournalError::Permission)?;
    let encrypted = wholepact_storage_security::open_encrypted_quiescent(path, key)?;
    let identity = encrypted.database_identity()?;
    if identity != original_identity {
        return Err(JournalError::InvalidBinding);
    }
    let mut connection = encrypted.into_connection();
    identity.check_current(&connection)?;
    if preflight_original(&connection, account_id, known_born)? != initial_version {
        return Err(JournalError::Conflict);
    }
    drop(snapshot);
    match initial_version {
        12 => recovery_migration::migrate_v12(&mut connection, account_id)?,
        13 => recovery_migration::migrate_v13(&mut connection, account_id)?,
        14 => recovery_migration::migrate_v14(&mut connection, account_id)?,
        15 => recovery_migration::migrate_v15(&mut connection, account_id)?,
        16 => recovery_migration::migrate_v16(&mut connection, account_id)?,
        17 => recovery_migration::migrate_v17(&mut connection, account_id)?,
        18 => recovery_migration::migrate_v18(&mut connection, account_id)?,
        SCHEMA_VERSION => {}
        _ => return Err(JournalError::UnsupportedSchema),
    }
    {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        if preflight_original(&tx, account_id, known_born)? != SCHEMA_VERSION {
            return Err(JournalError::UnsupportedSchema);
        }
        extra(&tx)?;
        identity.check_current(&tx)?;
        tx.commit()?;
    }
    configure(&connection)?;
    let registration = owner.register(&connection, &identity, account_id)?;
    Ok(OpenedSignerSource {
        connection,
        identity,
        registration,
    })
}
fn preflight_original(
    c: &Connection,
    account_id: &str,
    known_born: Option<&wholepact_authority::account_use::AccountUseGenesis>,
) -> Result<i64> {
    if let Some(genesis) = known_born {
        genesis
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        let application: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application != APPLICATION_ID || version != SCHEMA_VERSION {
            return Err(JournalError::UnsupportedSchema);
        }
        verify_schema(c)?;
        let account = read_account(c)?;
        if account.account_id != account_id
            || account_id != genesis.identity.account_id
            || account_use_storage::inspect(c, account_id)?.genesis() != Some(genesis)
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(version)
    } else {
        recovery_migration::preflight_open(c, account_id)
    }
}

fn configure(c: &Connection) -> Result<()> {
    c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA max_page_count=32768;")?;
    Ok(())
}
// Every table and every text column in the compiled schema is accounted for.
// A row has at most sixteen cells. JSON text escaping expands each UTF-8 byte by
// at most 6 (an ASCII control byte -> \u00xx). 2048 bytes per row is a proven
// conservative allowance for <=16 tagged cells, signed 64-bit integers/rowid,
// quotes, punctuation and field names (<2048 bytes at maximum widths).
// There are no BLOB or REAL cells in this schema. This dominates the bundle's
// exact Row/Cell JSON encoding without duplicating its private serialization.
const CAPACITY_TABLES: &[(&str, &[&str])] = &[
    (
        "signer_durable_payment_admission_intents",
        &[
            "operation_id",
            "authorization_id",
            "request_digest",
            "enrollment_ref",
            "manifest_ref",
            "payload",
        ],
    ),
    (
        "signer_durable_construction_outbox",
        &[
            "operation_id",
            "request_digest",
            "enrollment_ref",
            "manifest_ref",
            "payload",
        ],
    ),
    (
        "signer_named_intent_outbox",
        &[
            "authorization_id",
            "original_ref",
            "profile_ref",
            "stream",
            "message_id",
            "content_hash",
            "payload_digest",
            "envelope_digest",
            "preview_json",
            "envelope_hex",
        ],
    ),
    (
        "signer_named_recipient_profiles",
        &[
            "reference",
            "original_setup_digest",
            "account_id",
            "enrollment_ref",
            "manifest_ref",
            "payload",
        ],
    ),
    (
        "signer_named_recipient_originals",
        &["reference", "profile_ref", "authorization_id", "payload"],
    ),
    (
        "signer_named_recipient_receipts",
        &[
            "profile_ref",
            "stream",
            "message_id",
            "content_hash",
            "payload_digest",
            "envelope_digest",
            "immutable_slot",
            "envelope_hex",
        ],
    ),
    (
        "signer_named_recipient_started",
        &[
            "authorization_id",
            "original_ref",
            "marker_digest",
            "payload",
        ],
    ),
    (
        "signer_named_recipient_results",
        &["authorization_id", "result_digest", "payload"],
    ),
    (
        "signer_common_context_reentry_v1",
        &[
            "invocation_digest",
            "phase",
            "account_id",
            "receipt_digest",
            "payload",
        ],
    ),
    (
        "signer_common_context_audit_v3",
        &[
            "invocation_digest",
            "phase",
            "account_id",
            "receipt_digest",
            "payload",
        ],
    ),
    (
        "signer_offline_review_inputs",
        &[
            "authorization_id",
            "account_id",
            "terms_digest",
            "package_digest",
            "envelope_digest",
            "envelope_hex",
        ],
    ),
    (
        "signer_offline_review_authenticated",
        &["authorization_id", "receipt_digest", "payload"],
    ),
    (
        "signer_offline_review_accepted",
        &["authorization_id", "receipt_digest"],
    ),
    (
        "signer_account_use_genesis",
        &[
            "account_id",
            "full_viewing_key_digest",
            "genesis_digest",
            "payload",
        ],
    ),
    (
        "signer_account_use_exclusion",
        &["genesis_digest", "exclusion_digest", "payload"],
    ),
    (
        "signer_account_use_witness_ack",
        &[
            "exclusion_digest",
            "witness_origin_digest",
            "committed_head_digest",
            "receipt_digest",
            "payload",
        ],
    ),
    (
        "signer_offline_local_admissions",
        &[
            "authorization_id",
            "account_id",
            "obligation_id",
            "maximum_debit",
            "payload",
        ],
    ),
    (
        "signer_offline_local_inputs",
        &["authorization_id", "account_id", "nullifier"],
    ),
    (
        "signer_offline_enrollments",
        &["policy_digest", "enrollment_ref", "account_id", "payload"],
    ),
    (
        "signer_offline_intents",
        &[
            "intent_digest",
            "authorization_id",
            "policy_digest",
            "payload",
        ],
    ),
    (
        "signer_offline_admissions",
        &["authorization_id", "request_digest", "payload"],
    ),
    (
        "signer_offline_remote_exposures",
        &[
            "authorization_id",
            "account_id",
            "obligation_id",
            "maximum_debit",
            "payload",
        ],
    ),
    (
        "signer_offline_remote_inputs",
        &["authorization_id", "account_id", "nullifier"],
    ),
    (
        "signer_offline_original_consents",
        &[
            "reference",
            "authorization_id",
            "account_id",
            "nonce",
            "payload",
        ],
    ),
    (
        "signer_offline_keyuse",
        &["authorization_id", "original_consent_ref", "payload"],
    ),
    (
        "signer_offline_results",
        &["authorization_id", "result_digest", "result_hex", "payload"],
    ),
    ("signer_automation_keyuse", &["authorization_id", "payload"]),
    (
        "signer_automation_grant_events",
        &["grant_id", "enrollment_ref", "payload"],
    ),
    (
        "signer_recovery_generations",
        &[
            "generation_id",
            "phase",
            "operation_id",
            "inventory_digest",
            "fence_digest",
            "payload",
        ],
    ),
    ("signer_sponsor_policy_events", &["policy_key", "payload"]),
    (
        "signer_sponsor_manifest_bindings",
        &["manifest_ref", "policy_key", "payload"],
    ),
    (
        "signer_sponsor_owner_attestations",
        &["manifest_ref", "payload"],
    ),
    (
        "signer_settlement_sources",
        &["reference", "account_id", "payload"],
    ),
    (
        "signer_settlement_events",
        &[
            "evidence_id",
            "authorization_id",
            "source_ref",
            "kind",
            "payload",
        ],
    ),
    ("signer_account", &["account_id"]),
    (
        "signer_remote_exposures",
        &[
            "authorization_id",
            "original_consent_ref",
            "account_id",
            "obligation_id",
            "maximum_debit",
            "payload",
        ],
    ),
    (
        "signer_remote_inputs",
        &["authorization_id", "account_id", "nullifier"],
    ),
    (
        "signer_writer_reconciliations",
        &["review_digest", "disclosure", "head_digest", "payload"],
    ),
    (
        "signer_enrollments",
        &[
            "reference",
            "account_id",
            "agreement_id",
            "participant_id",
            "payload",
        ],
    ),
    (
        "signer_accepted_manifests",
        &[
            "reference",
            "enrollment_ref",
            "proposal_id",
            "proposal_digest",
            "payload",
        ],
    ),
    (
        "signer_original_consents",
        &[
            "reference",
            "enrollment_ref",
            "manifest_ref",
            "authorization_id",
            "nonce",
            "payload",
        ],
    ),
    (
        "signer_release_intents",
        &[
            "authorization_id",
            "original_consent_ref",
            "account_id",
            "obligation_id",
            "maximum_debit",
            "payload",
            "exposure_state",
        ],
    ),
    (
        "signer_input_reservations",
        &["account_id", "input_id", "authorization_id"],
    ),
    (
        "signer_bridge_requests",
        &[
            "authorization_id",
            "original_consent_ref",
            "request_payload",
            "artifact_hex",
        ],
    ),
    ("signer_bridge_permits", &["authorization_id", "payload"]),
    ("signer_bridge_keyuse", &["authorization_id"]),
    (
        "signer_named_recipient_dispatch_requests",
        &[
            "operation_id",
            "authorization_id",
            "original_ref",
            "request_digest",
            "payload",
        ],
    ),
    (
        "signer_dispatch_requests",
        &["operation_id", "authorization_id", "payload"],
    ),
    (
        "signer_result_redeliveries",
        &["operation_id", "reference", "authorization_id", "payload"],
    ),
    (
        "signer_bridge_results",
        &[
            "authorization_id",
            "result_digest",
            "result_hex",
            "outbox_payload",
        ],
    ),
];
fn verify_capacity_schema(c: &Connection) -> Result<()> {
    use std::collections::BTreeSet;
    let mut q = c.prepare("SELECT name FROM sqlite_schema WHERE type='table'")?;
    let actual = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    let expected = CAPACITY_TABLES.iter().map(|(t, _)| t.to_string()).collect();
    // Includes any future sqlite_sequence table: a schema change cannot silently
    // add unaccounted backup rows or widen the fixed per-row overhead allowance.
    if actual != expected {
        return Err(JournalError::UnsupportedSchema);
    }
    for (table, text_columns) in CAPACITY_TABLES {
        let mut q = c.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = q
            .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if columns.is_empty()
            || columns.len() > 16
            || columns.iter().any(|(_, t)| t != "TEXT" && t != "INTEGER")
        {
            return Err(JournalError::UnsupportedSchema);
        }
        let actual_text = columns
            .into_iter()
            .filter(|(_, t)| t == "TEXT")
            .map(|(name, _)| name)
            .collect::<BTreeSet<_>>();
        if actual_text != text_columns.iter().map(|s| s.to_string()).collect() {
            return Err(JournalError::UnsupportedSchema);
        }
    }
    Ok(())
}
pub(super) fn capacity_estimate(c: &Connection) -> Result<(u64, u64)> {
    let mut rows = 0_u64;
    let mut text_bytes = 0_u64;
    for (table, columns) in CAPACITY_TABLES {
        let lengths = columns
            .iter()
            .map(|column| format!("coalesce(length(CAST({column} AS BLOB)),0)"))
            .collect::<Vec<_>>()
            .join("+");
        let maximum = columns
            .iter()
            .map(|column| format!("coalesce(length(CAST({column} AS BLOB)),0)"))
            .collect::<Vec<_>>()
            .join(",");
        // The trailing zero forces scalar max even for one-column tables.
        let sql = format!(
            "SELECT count(*),coalesce(sum({lengths}),0),coalesce(max(max({maximum},0)),0) FROM {table}"
        );
        let (count, bytes, cell): (u64, u64, u64) =
            c.query_row(&sql, [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        if cell > 4 * 1024 * 1024 {
            return Err(JournalError::Limit);
        }
        rows = rows.checked_add(count).ok_or(JournalError::Limit)?;
        text_bytes = text_bytes.checked_add(bytes).ok_or(JournalError::Limit)?;
    }
    let encoded_upper_bound = text_bytes
        .checked_mul(6)
        .and_then(|bytes| {
            rows.checked_mul(2048)
                .and_then(|overhead| bytes.checked_add(overhead))
        })
        .and_then(|bytes| bytes.checked_add(BACKUP_METADATA_RESERVE))
        .ok_or(JournalError::Limit)?;
    Ok((rows, encoded_upper_bound))
}

pub(super) fn bounded(c: &Connection, limits: (u64, u64)) -> Result<()> {
    let (rows, encoded_upper_bound) = capacity_estimate(c)?;
    if rows > limits.0 || encoded_upper_bound > limits.1 {
        return Err(JournalError::Limit);
    }
    Ok(())
}

pub(super) fn read_account(c: &Connection) -> Result<SignerAccountState> {
    if c.query_row("SELECT count(*) FROM signer_account", [], |r| {
        r.get::<_, u64>(0)
    })? != 1
    {
        return Err(JournalError::InvalidBinding);
    }
    let state = c.query_row(
        "SELECT account_id,writer_epoch,recovery_required FROM signer_account WHERE singleton=1",
        [],
        |r| {
            Ok(SignerAccountState {
                account_id: r.get(0)?,
                writer_epoch: r.get(1)?,
                recovery_required: r.get(2)?,
            })
        },
    )?;
    id(&state.account_id)?;
    if state.writer_epoch == 0 {
        return Err(JournalError::InvalidBinding);
    }
    Ok(state)
}
pub(super) fn read_enrollment(
    c: &Connection,
    reference: &str,
) -> Result<Option<AccountEnrollmentRecord>> {
    let raw: Option<String> = c
        .query_row(
            "SELECT payload FROM signer_enrollments WHERE reference=?1",
            [reference],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|raw| {
        let record: AccountEnrollmentRecord = decode(raw)?;
        record.validate()?;
        if record.reference() != reference {
            return Err(JournalError::InvalidBinding);
        }
        Ok(record)
    })
    .transpose()
}
pub(super) fn read_manifest(
    c: &Connection,
    reference: &str,
) -> Result<Option<AcceptedManifestRecord>> {
    let raw: Option<String> = c
        .query_row(
            "SELECT payload FROM signer_accepted_manifests WHERE reference=?1",
            [reference],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|raw| {
        let record: AcceptedManifestRecord = decode(raw)?;
        record.proposal()?;
        if record.reference() != reference {
            return Err(JournalError::InvalidBinding);
        }
        Ok(record)
    })
    .transpose()
}
pub(super) fn read_original(
    c: &Connection,
    authorization_id: &str,
) -> Result<Option<OriginalAuthorizationEvidence>> {
    let Some(result) = read_original_unvalidated(c, authorization_id)? else { return Ok(None); };
    validate_linkage(&result)?;
    validate_retained_durable_born_original_v1(c, &result)?;
    Ok(Some(result))
}
// Raw typed decode is private. Only closed validators below may return it.
fn read_original_unvalidated(c: &Connection, authorization_id: &str) -> Result<Option<OriginalAuthorizationEvidence>> {
    let release: Option<(String,String)> = c.query_row("SELECT original_consent_ref,payload FROM signer_release_intents WHERE authorization_id=?1", [authorization_id], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((reference, raw)) = release else {
        return Ok(None);
    };
    let release: ConsentLinkedReleaseIntent = decode(raw)?;
    let raw: String = c.query_row(
        "SELECT payload FROM signer_original_consents WHERE reference=?1 AND authorization_id=?2",
        params![reference, authorization_id],
        |r| r.get(0),
    )?;
    let consent: OriginalSpendConsent = decode(raw)?;
    if consent.reference() != reference
        || release.original_consent_ref() != reference
        || consent.terms.authorization_id != authorization_id
    {
        return Err(JournalError::InvalidBinding);
    }
    let enrollment =
        read_enrollment(c, &consent.terms.enrollment_ref)?.ok_or(JournalError::NotFound)?;
    let manifest =
        read_manifest(c, &consent.terms.accepted_manifest_ref)?.ok_or(JournalError::NotFound)?;
    let result = OriginalAuthorizationEvidence {
        enrollment,
        manifest,
        consent,
        release,
    };
    Ok(Some(result))
}
// Both callers already hold an actual source/permission lease and Immediate
// transaction. This closed kernel preserves existing input/budget exclusion and
// exact replay; it never selects a profile from serialized caller data.
#[derive(Clone, Copy)]
enum ReleaseRowProfile {
    OriginalV1,
    #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", target_os = "linux"))]
    FinancialV1,
}
fn append_release_rows(c: &Connection, result: &OriginalAuthorizationEvidence, profile: ReleaseRowProfile, limits: (u64,u64)) -> Result<OriginalAuthorizationEvidence> {
    if c.is_autocommit() { return Err(JournalError::InvalidBinding); }
    let t = result.consent.terms();
    let account = read_account(c)?;
    if account.account_id != t.account_id || account.writer_epoch != t.receipt.writer_epoch || account.recovery_required { return Err(JournalError::Permission); }
    match profile {
        ReleaseRowProfile::OriginalV1 => { validate_linkage(result)?; validate_retained_durable_born_original_v1(c,result)?; },
        #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", target_os = "linux"))]
        ReleaseRowProfile::FinancialV1 => financial_profile_v1::validate_financial_linkage(c,result)?,
    }
        sponsor::current_for_consent(c, t)?;
        automation::current_for_consent(c, t)?;
        account_use_storage::require_not_excluded(c, &account.account_id)?;
        let existing = match profile {
            ReleaseRowProfile::OriginalV1 => read_original(c, &t.authorization_id)?,
            #[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", target_os = "linux"))]
            ReleaseRowProfile::FinancialV1 => financial_profile_v1::read_financial_original_v1(c, &t.authorization_id)?,
        };
        if let Some(old) = existing {
            if &old != result {
                return Err(JournalError::Conflict);
            }
            return Ok(old);
        }
        offline_history::read_all(c, &account.account_id)?;
        offline_history::require_accountwide_online_admission(c)?;
        automation::check_outstanding(c, t)?;
        let remote_id: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM signer_remote_exposures WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_offline_remote_exposures WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_offline_local_admissions WHERE authorization_id=?1)",
            [&t.authorization_id],
            |r| r.get(0),
        )?;
        if remote_id {
            return Err(JournalError::Conflict);
        }
        let live: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM signer_release_intents WHERE account_id=?1 AND obligation_id=?2 UNION ALL SELECT 1 FROM signer_remote_exposures WHERE account_id=?1 AND obligation_id=?2 UNION ALL SELECT 1 FROM signer_offline_remote_exposures WHERE account_id=?1 AND obligation_id=?2 UNION ALL SELECT 1 FROM signer_offline_local_admissions WHERE account_id=?1 AND obligation_id=?2)", params![t.account_id,t.obligation_id], |r| r.get(0))?;
        if live {
            return Err(JournalError::LiveAuthorization);
        }
        // Budget is fixed in original native account enrollment, never supplied
        // by the coordinator at release. All unresolved signer history counts.
        let mut total: u128 = 0;
        {
            let mut q =
                c.prepare("SELECT maximum_debit FROM signer_release_intents l WHERE account_id=?1 AND (?2=0 OR NOT EXISTS(SELECT 1 FROM signer_settlement_events e WHERE e.authorization_id=l.authorization_id AND e.kind='canonical_consumed' AND e.sequence=(SELECT max(x.sequence) FROM signer_settlement_events x WHERE x.authorization_id=l.authorization_id))) UNION ALL SELECT maximum_debit FROM signer_remote_exposures r WHERE account_id=?1 AND NOT EXISTS(SELECT 1 FROM signer_original_consents o WHERE o.reference=r.original_consent_ref AND o.authorization_id=r.authorization_id) UNION ALL SELECT maximum_debit FROM signer_offline_remote_exposures WHERE account_id=?1 UNION ALL SELECT maximum_debit FROM signer_offline_local_admissions l WHERE account_id=?1 AND NOT EXISTS(SELECT 1 FROM signer_offline_remote_exposures r WHERE r.authorization_id=l.authorization_id)")?;
            // Builds without a live independent source implementation must count
            // every original release, including history resolved by another build.
            for value in q.query_map(
                params![&t.account_id, cfg!(feature = "authority-signing")],
                |r| r.get::<_, String>(0),
            )? {
                let value = value?;
                let amount = value
                    .parse::<u64>()
                    .map_err(|_| JournalError::InvalidBinding)?;
                if amount.to_string() != value {
                    return Err(JournalError::InvalidBinding);
                }
                total = total
                    .checked_add(u128::from(amount))
                    .ok_or(JournalError::BudgetExceeded)?;
            }
        }
        if total + u128::from(t.maximum_debit_zatoshis)
            > u128::from(result.enrollment.budget_limit_zatoshis())
        {
            return Err(JournalError::BudgetExceeded);
        }
        for input in &t.input_bindings {
            let held: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM signer_input_reservations WHERE account_id=?1 AND input_id=?2 UNION ALL SELECT 1 FROM signer_remote_inputs WHERE account_id=?1 AND nullifier=?2 UNION ALL SELECT 1 FROM signer_offline_remote_inputs WHERE account_id=?1 AND nullifier=?2 UNION ALL SELECT 1 FROM signer_offline_local_inputs WHERE account_id=?1 AND nullifier=?2)", params![t.account_id,input.nullifier], |r| r.get(0))?;
            if held {
                return Err(JournalError::InputReserved);
            }
        }
        let consent = encode(&result.consent)?;
        let release = encode(&result.release)?;
        c.execute(
            "INSERT INTO signer_original_consents VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                result.consent.reference(),
                t.enrollment_ref,
                t.accepted_manifest_ref,
                t.authorization_id,
                t.receipt.nonce,
                consent.as_str()
            ],
        )?;
        c.execute(
            "INSERT INTO signer_release_intents VALUES(?1,?2,?3,?4,?5,?6,'outstanding_uncertain')",
            params![
                t.authorization_id,
                result.consent.reference(),
                t.account_id,
                t.obligation_id,
                t.maximum_debit_zatoshis.to_string(),
                release.as_str()
            ],
        )?;
        for input in &t.input_bindings {
            c.execute(
                "INSERT INTO signer_input_reservations VALUES(?1,?2,?3)",
                params![t.account_id, input.nullifier, t.authorization_id],
            )?;
        }
        bounded(c, limits)?;
    Ok(result.clone())
}
pub(super) fn same_native_origin(a: &NativeConsentReceipt, b: &NativeConsentReceipt) -> bool {
    a.native_session_id == b.native_session_id
        && a.permission_generation == b.permission_generation
        && a.trusted_launch_measurement == b.trusted_launch_measurement
        && a.writer_epoch == b.writer_epoch
}
fn validate_linkage(e: &OriginalAuthorizationEvidence) -> Result<()> {
    e.consent.validate()?;
    if !same_native_origin(e.manifest.receipt(), &e.consent.terms().receipt) { return Err(JournalError::Permission); }
    validate_economic_linkage(e)
}
// Shared mathematical/record linkage only. The caller must select an explicit
// validated authority profile before this kernel; it never grants permission.
fn validate_economic_linkage(e: &OriginalAuthorizationEvidence) -> Result<()> {
    e.enrollment.validate()?;
    let p = e.manifest.proposal()?;
    let t = e.consent.terms();
    e.enrollment.transport().validate_scope(e.enrollment.account_id(), e.enrollment.agreement_id(), e.enrollment.participant_id(), Some(p.manifest_digest()))?;
    if !same_native_origin(e.enrollment.receipt(), e.manifest.receipt()) { return Err(JournalError::Permission); }
    let owner = p
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == t.account_id && p.participant_id == e.enrollment.participant_id())
        .ok_or(JournalError::InvalidBinding)?;
    let mut expected: Vec<_> = p
        .manifest()
        .inputs
        .iter()
        .filter(|i| i.account_id == t.account_id)
        .map(|i| (i.input_id.as_str(), i.amount.as_zatoshis()))
        .collect();
    expected.sort();
    let mut actual: Vec<_> = t
        .input_bindings
        .iter()
        .map(|i| (i.input_id.as_str(), i.value_zatoshis))
        .collect();
    actual.sort();
    if t.enrollment_ref != e.enrollment.reference
        || t.accepted_manifest_ref != e.manifest.reference
        || e.manifest.terms.enrollment_ref != e.enrollment.reference
        || t.account_id != e.enrollment.account_id()
        || t.account_id != e.manifest.terms.account_id
        || t.principal_id != e.enrollment.principal_id()
        || t.principal_id != e.manifest.terms.principal_id
        || t.agreement_id != e.enrollment.agreement_id()
        || t.agreement_id != p.manifest().agreement.agreement_id
        || t.obligation_id != p.manifest().agreement.obligation_id
        || t.proposal_id != p.input().proposal_id
        || t.proposal_digest != p.proposal_digest()
        || t.manifest_digest != p.manifest_digest()
        || t.transport != e.enrollment.terms.transport
        || t.receipt.writer_epoch != e.enrollment.receipt().writer_epoch
        || t.receipt.writer_epoch != e.manifest.receipt().writer_epoch
        || t.aggregate_budget_limit_zatoshis != e.enrollment.budget_limit_zatoshis()
        || t.fee_share_zatoshis != owner.fee_share.as_zatoshis()
        || t.transaction_fee_zatoshis != p.manifest().transaction_fee.as_zatoshis()
        || t.transaction_expiry_height != p.manifest().expiry_height
        || t.maximum_debit_zatoshis > owner.maximum_net_debit.as_zatoshis()
        || p.accounting()
            .participant_net_debits
            .get(&owner.participant_id)
            .map(|a| a.as_zatoshis())
            != Some(t.maximum_debit_zatoshis)
        || expected != actual
        || p.input()
            .artifact_digest
            .as_ref()
            .is_some_and(|d| d != &t.artifact_digest)
        || p.input()
            .effects_commitment
            .as_ref()
            .is_some_and(|d| d != &t.effects_digest)
        || e.release != ConsentLinkedReleaseIntent::from_consent(&e.consent)
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}
/// Legacy semantic projections cannot represent the distinct schema15 phases.
/// Keep them denied rather than silently dropping authenticated lineage.
pub(super) fn require_no_unimplemented_reentry(c: &Connection) -> Result<()> {
    let present: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM signer_common_context_reentry_v1)",
        [],
        |r| r.get(0),
    )?;
    if present {
        return Err(JournalError::ConstructionHistoryUnsupported);
    }
    Ok(())
}
pub(super) fn verify_schema(c: &Connection) -> Result<()> {
    #[cfg(test)]
    let _cost_schema = validation_cost_v1::enter(validation_cost_v1::Phase::SchemaTotal);
    verify_schema_before_common_audit(c)?;
    #[cfg(test)]
    let cost_construction = validation_cost_v1::enter(validation_cost_v1::Phase::ConstructionAudit);
    construction_audit_v3::read_all(c, &read_account(c)?.account_id)?;
    #[cfg(test)]
    drop(cost_construction);
    #[cfg(test)]
    let cost_common = validation_cost_v1::enter(validation_cost_v1::Phase::CommonAudit);
    common_context_reentry_audit_v1::read_complete(c, &read_account(c)?.account_id)?;
    #[cfg(test)]
    drop(cost_common);
    Ok(())
}

/// Inert complete validation from this exact borrowed database read. Only this
/// module can construct it; no clone, deserialization or mutable accessor can
/// turn a caller's inventory into validated history. Callers keep it inside
/// their own fresh read transaction, never across a native/effect boundary.
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(super) struct ValidatedCommonAudit<'snapshot> {
    account: String,
    inventory: CommonContextSignerAuditInventoryV2,
    _snapshot: &'snapshot Connection,
}
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
impl ValidatedCommonAudit<'_> {
    pub(super) fn inventory_for(
        &self,
        account: &str,
    ) -> Result<&CommonContextSignerAuditInventoryV2> {
        if self.account != account {
            return Err(JournalError::InvalidBinding);
        }
        Ok(&self.inventory)
    }
}

/// `read_complete` itself reads and fully validates the original construction
/// audit, so no separate, discarded replay is necessary in this same snapshot.
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(super) fn verify_schema_with_common_audit(c: &Connection) -> Result<ValidatedCommonAudit<'_>> {
    #[cfg(test)]
    let _cost_schema = validation_cost_v1::enter(validation_cost_v1::Phase::SchemaTotal);
    verify_schema_before_common_audit(c)?;
    let account = read_account(c)?.account_id;
    #[cfg(test)]
    let cost_common = validation_cost_v1::enter(validation_cost_v1::Phase::CommonAudit);
    let inventory = common_context_reentry_audit_v1::read_complete(c, &account)?;
    #[cfg(test)]
    drop(cost_common);
    Ok(ValidatedCommonAudit {
        account,
        inventory,
        _snapshot: c,
    })
}

type SchemaObjectV1=(String,String,String,Option<String>);
fn schema_objects_v1(c:&Connection)->Result<Vec<SchemaObjectV1>> {
    let mut q=c.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")?;
    let rows=q.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    rows.collect::<std::result::Result<Vec<_>,_>>().map_err(Into::into)
}
// Trusted executable DDL only. No target observations or connection survive.
fn build_expected_schema_objects_v1(extension:&str)->Result<Vec<SchemaObjectV1>> {
    #[cfg(test)]
    let cost_reference_open=validation_cost_v1::enter(validation_cost_v1::Phase::SchemaReferenceOpen);
    let expected=Connection::open_in_memory()?;
    #[cfg(test)]
    drop(cost_reference_open);
    #[cfg(test)]
    let cost_reference_build=validation_cost_v1::enter(validation_cost_v1::Phase::SchemaReferenceBuild);
    expected.execute_batch(SCHEMA)?;
    if !extension.is_empty(){expected.execute_batch(extension)?;}
    #[cfg(test)]
    drop(cost_reference_build);
    schema_objects_v1(&expected)
}
fn expected_schema19_objects_v1()->Result<&'static Vec<SchemaObjectV1>> {
    static EXPECTED:std::sync::OnceLock<Vec<SchemaObjectV1>>=std::sync::OnceLock::new();
    if let Some(expected)=EXPECTED.get(){return Ok(expected);}
    // Cache successes only. Initialization failures retain their original error.
    // A racing initializer computes the same static DDL on its own connection.
    let built=build_expected_schema_objects_v1("")?;
    let _=EXPECTED.set(built);
    EXPECTED.get().ok_or(JournalError::Database)
}
fn verify_schema_objects_v1(c:&Connection,expected:&[SchemaObjectV1])->Result<()> {
    if schema_objects_v1(c)?.as_slice()!=expected {return Err(JournalError::UnsupportedSchema);}
    Ok(())
}
fn verify_schema_before_common_audit(c: &Connection) -> Result<()> {
    let expected=expected_schema19_objects_v1()?;
    #[cfg(test)]
    let cost_compare = validation_cost_v1::enter(validation_cost_v1::Phase::SchemaCompare);
    verify_schema_objects_v1(c,expected)?;
    #[cfg(test)]
    drop(cost_compare);
    #[cfg(test)]
    let cost_capacity = validation_cost_v1::enter(validation_cost_v1::Phase::SchemaCapacity);
    verify_capacity_schema(c)?;
    #[cfg(test)]
    drop(cost_capacity);
    #[cfg(test)]
    let cost_bounds = validation_cost_v1::enter(validation_cost_v1::Phase::SchemaBounds);
    bounded(c, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES))?;
    #[cfg(test)]
    drop(cost_bounds);
    verify_retained_schema19_cells(c)
}

// Private semantic kernel. Only exact executable schema validators call this.
// It never chooses a profile from caller data and does not grant authority.
fn verify_retained_schema19_cells(c: &Connection) -> Result<()> {
    #[cfg(test)]
    let cost_offline = validation_cost_v1::enter(validation_cost_v1::Phase::OfflineHistory);
    offline_history::read_all(c, &read_account(c)?.account_id)?;
    #[cfg(test)]
    drop(cost_offline);
    #[cfg(test)]
    let cost_receipts = validation_cost_v1::enter(validation_cost_v1::Phase::OfflineReceipts);
    offline_receipts::validate_all(c, &read_account(c)?.account_id)?;
    #[cfg(test)]
    drop(cost_receipts);
    #[cfg(test)]
    let cost_account_use = validation_cost_v1::enter(validation_cost_v1::Phase::SchemaAccountUse);
    account_use_storage::inspect(c, &read_account(c)?.account_id)?;
    #[cfg(test)]
    drop(cost_account_use);
    #[cfg(test)]
    let cost_named = validation_cost_v1::enter(validation_cost_v1::Phase::NamedRecipientHistory);
    named_recipient_inventory::validate_archive_rows(c, &read_account(c)?.account_id)?;
    #[cfg(test)]
    drop(cost_named);
    #[cfg(test)]
    let cost_intents = validation_cost_v1::enter(validation_cost_v1::Phase::AdmissionIntents);
    financial_admission_intents::validate_rows(c)?;
    #[cfg(test)]
    drop(cost_intents);
    #[cfg(not(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    )))]
    if c.query_row(
        "SELECT EXISTS(SELECT 1 FROM signer_durable_payment_admission_intents)",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        return Err(JournalError::RecoveryRequired);
    }

    #[cfg(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    ))]
    {
        #[cfg(test)]
        let _cost_material =
            validation_cost_v1::enter(validation_cost_v1::Phase::DurableMaterialRows);
        durable_construction_v1::validate_rows(c)?;
    }
    #[cfg(not(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    )))]
    {
        // A build without the typed reader must not silently omit retained
        // disclosure evidence or admit it as an original native capability.
        let present: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM signer_durable_construction_outbox)",
            [],
            |r| r.get(0),
        )?;
        if present {
            return Err(JournalError::ConstructionHistoryUnsupported);
        }
    }
    Ok(())
}

pub struct SignerConsentBundleAdapter<'a> {
    journal: &'a SignerConsentJournal,
}
impl SignerConsentBundleAdapter<'_> {
    pub fn template() -> &'static JournalTemplate {
        &TEMPLATE
    }
}
impl JournalAdapter for SignerConsentBundleAdapter<'_> {
    fn template(&self) -> &'static JournalTemplate {
        &TEMPLATE
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&Connection) -> std::result::Result<(), BundleError>,
    ) -> std::result::Result<(), BundleError> {
        permit.check(self)?;
        let c = self
            .journal
            .connection
            .lock()
            .map_err(|_| BundleError::Storage)?;
        verify_schema(&c).map_err(|_| BundleError::Integrity)?;
        visitor(&c)
    }
}

#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
#[path = "born_enrollment.rs"]
mod born_enrollment;

/// Borrowed exact lineage for a read-only journal check, never an owner or
/// a native, witness, transport, or construction capability.
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(crate) struct CommonContextAuthorizedReentryOwnerInput<'a> {
    pub(crate) genesis: &'a wholepact_authority::account_use::AccountUseGenesis,
    pub(crate) epoch: u64,
    pub(crate) read_digest: &'a str,
    pub(crate) attempt_digest: &'a str,
    pub(crate) attempt_sequence: u64,
    pub(crate) plan:
        &'a wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3,
    pub(crate) authorization_digest: &'a str,
}

#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
impl SignerConsentJournal {
    /// Read-completion-specific binding-preserving reopen. The borrowed proof is privately
    /// created by the consumed actual dormant owner after fresh native unlock;
    /// neither a path, receipt nor an arbitrary Arc can substitute for it.
    pub(crate) fn reopen_common_context_completion(
        proof: &crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::FreshCommonContextJournalReopen<'_>,
    ) -> Result<Self> {
        proof
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        let read = proof
            .original_read()
            .map_err(|_| JournalError::InvalidBinding)?;
        let path = proof.journal_path();
        let key = proof.journal_key();
        let mut journal = Self::open_known_born_encrypted(
            &path,
            &key,
            proof.genesis(),
            &proof
                .journal_source_owner()
                .map_err(|_| JournalError::Permission)?,
        )?;
        journal.check_common_context_authorized_reentry_owner(
            &CommonContextAuthorizedReentryOwnerInput {
                genesis: proof.genesis(),
                epoch: proof.writer_epoch(),
                read_digest: &read.digest().map_err(|_| JournalError::InvalidBinding)?,
                attempt_digest: &read.current_attempt_digest,
                attempt_sequence: read.current_attempt_sequence,
                plan: &read.request.plan,
                authorization_digest: &proof
                    .original_authorization_digest()
                    .map_err(|_| JournalError::InvalidBinding)?,
            },
            true,
        )?;
        proof
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        journal.binding = proof.original_binding().clone();
        Ok(journal)
    }
}

#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
impl SignerConsentJournal {
    /// Purpose-distinct reopen of the genuinely consumed V3 source after a new
    /// native unlock. Only its private proof can preserve the original local
    /// binding; complete current rows must exactly equal the drained snapshot.
    pub(crate) fn reopen_consumed_born_named_v1(
        proof: &crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::FreshConsumedBornNamedJournalReopenV1<'_>,
    ) -> Result<Self> {
        proof
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        let path = proof.journal_path();
        let key = proof.journal_key();
        let mut journal = Self::open_known_born_encrypted(
            &path,
            &key,
            proof.genesis(),
            &proof
                .journal_source_owner()
                .map_err(|_| JournalError::Permission)?,
        )?;
        let actual = journal.consumed_born_named_inventory_v1(
            proof.genesis(),
            proof.writer_epoch(),
            proof.evidence(),
            proof.construction(),
        )?;
        if &actual != proof.inventory() {
            return Err(JournalError::Conflict);
        }
        proof
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        journal.binding = proof.original_binding().clone();
        Ok(journal)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod source_owner_tests {
    use super::*;
    use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

    struct SyntheticSource {
        source: Arc<SignerJournalSourceOwner>,
        directory: crate::files::PrivateDirectory,
        path: PathBuf,
        key: DatabaseKey,
        _temp: tempfile::TempDir,
    }
    impl SyntheticSource {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let directory = crate::files::PrivateDirectory::open(temp.path()).unwrap();
            let path = temp.path().join("source.sqlite");
            let source = directory
                .signer_journal_source_owner_for_test(&path)
                .unwrap();
            Self {
                source,
                directory,
                path,
                key: DatabaseKey::from_bytes([177; 32]),
                _temp: temp,
            }
        }
        fn create(&self) -> SignerConsentJournal {
            SignerConsentJournal::create_encrypted(
                &self.path,
                &self.key,
                "synthetic-source",
                7,
                false,
                &self.source,
            )
            .unwrap()
        }
        fn files(&self) -> BTreeMap<PathBuf, Vec<u8>> {
            fs::read_dir(self.path.parent().unwrap())
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let bytes = fs::read(&path).unwrap();
                    (path, bytes)
                })
                .collect()
        }
        fn old(&self, version: i64, schema: &str) {
            // Dedicated synthetic raw fixture is closed before classification.
            let c = wholepact_storage_security::create_encrypted(&self.path, &self.key).unwrap();
            c.connection().execute_batch(schema).unwrap();
            c.connection()
                .execute(
                    "INSERT INTO signer_account VALUES(1,'synthetic-source',7,0)",
                    [],
                )
                .unwrap();
            c.connection()
                .pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            c.connection()
                .pragma_update(None, "user_version", version)
                .unwrap();
        }
    }

    #[test]
    fn live_journal_retains_actual_directory_lock_after_directory_owner_drops() {
        let f = SyntheticSource::new();
        let journal = f.create();
        let SyntheticSource {
            source,
            directory,
            path,
            key: _,
            _temp,
        } = f;
        drop(directory);
        drop(source);
        assert!(crate::files::PrivateDirectory::open_existing(path.parent().unwrap()).is_err());
        drop(journal);
        crate::files::PrivateDirectory::open_existing(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn concurrent_first_opens_publish_only_one_actual_current19_registration() {
        let f = SyntheticSource::new();
        drop(f.create());
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let source = Arc::clone(&f.source);
                let path = f.path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let journal = SignerConsentJournal::open_encrypted(
                        &path,
                        &DatabaseKey::from_bytes([177; 32]),
                        "synthetic-source",
                        &source,
                    )
                    .unwrap();
                    journal
                })
            })
            .collect();
        let mut journals = handles.into_iter().map(|h| h.join().unwrap());
        let first = journals.next().unwrap();
        let second = journals.next().unwrap();
        assert!(Arc::ptr_eq(
            &first.source_registration,
            &second.source_registration
        ));
        assert!(first.binding() != second.binding());
    }

    #[test]
    fn known_live_current19_reopens_during_existing_writer_without_snapshot() {
        let f = SyntheticSource::new();
        let first = f.create();
        let mut c = first.connection.lock().unwrap();
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE signer_account SET writer_epoch=writer_epoch WHERE singleton=1",
            [],
        )
        .unwrap();
        let second =
            SignerConsentJournal::open_encrypted(&f.path, &f.key, "synthetic-source", &f.source)
                .unwrap();
        assert!(Arc::ptr_eq(
            &first.source_registration,
            &second.source_registration
        ));
        tx.rollback().unwrap();
    }

    #[test]
    fn exclusive_first_open_wrong_key_account_unknown_or_objects_preserves_all_files() {
        for version in 8..=11 {
            let f = SyntheticSource::new();
            let schema = match version {
                8 => recovery_migration::V8_SCHEMA,
                9 => recovery_migration::V9_SCHEMA,
                10 => recovery_migration::V10_SCHEMA,
                _ => recovery_migration::V11_SCHEMA,
            };
            f.old(version, schema);
            let before = f.files();
            assert!(matches!(
                SignerConsentJournal::open_encrypted(
                    &f.path,
                    &f.key,
                    "synthetic-source",
                    &f.source
                ),
                Err(JournalError::RecoveryRequired)
            ));
            assert!(
                before == f.files(),
                "UNKNOWN schema {version} changed retained files"
            );
            assert!(f.source.state.lock().unwrap().upgrade().is_none());
        }
        let f = SyntheticSource::new();
        drop(f.create());
        let before = f.files();
        assert!(
            SignerConsentJournal::open_encrypted(
                &f.path,
                &DatabaseKey::from_bytes([178; 32]),
                "synthetic-source",
                &f.source
            )
            .is_err()
        );
        assert!(before == f.files(), "retained encrypted files changed");
        assert!(
            SignerConsentJournal::open_encrypted(&f.path, &f.key, "different-account", &f.source)
                .is_err()
        );
        assert!(before == f.files(), "retained encrypted files changed");
        let c = wholepact_storage_security::open_encrypted(&f.path, &f.key).unwrap();
        c.connection()
            .execute_batch("CREATE TABLE foreign_object(value TEXT)")
            .unwrap();
        drop(c);
        let before = f.files();
        assert!(
            SignerConsentJournal::open_encrypted(&f.path, &f.key, "synthetic-source", &f.source)
                .is_err()
        );
        assert!(before == f.files(), "retained encrypted files changed");
    }

    #[test]
    fn failed_or_panicked_first_open_never_publishes_registration() {
        let f = SyntheticSource::new();
        drop(f.create());
        {
            let mut owner = f.source.begin(&f.path).unwrap();
            assert!(
                open_preflighted_encrypted(
                    &mut owner,
                    &f.path,
                    &f.key,
                    "synthetic-source",
                    None,
                    &|_| Err(JournalError::Permission)
                )
                .is_err()
            );
            assert!(owner.state.upgrade().is_none());
        }
        let calls = std::cell::Cell::new(0);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut owner = f.source.begin(&f.path).unwrap();
            let _ = open_preflighted_encrypted(
                &mut owner,
                &f.path,
                &f.key,
                "synthetic-source",
                None,
                &|_| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        panic!("synthetic failure after original allocation");
                    }
                    Ok(())
                },
            );
        }));
        assert!(panic.is_err());
        assert_eq!(calls.get(), 2);
        let state = match f.source.state.lock() {
            Err(poisoned) => poisoned.into_inner(),
            Ok(_) => panic!("first-open unwind must poison source state"),
        };
        assert!(state.upgrade().is_none());
        drop(state);
        assert!(
            SignerConsentJournal::open_encrypted(&f.path, &f.key, "synthetic-source", &f.source)
                .is_err()
        );
    }

    #[test]
    fn actual_file_replacement_and_cross_child_hardlink_cannot_reuse_owner() {
        let f = SyntheticSource::new();
        let journal = f.create();
        let alias = f.path.with_file_name("alias.sqlite");
        let alias_source = f
            .directory
            .signer_journal_source_owner_for_test(&alias)
            .unwrap();
        assert!(!Arc::ptr_eq(&f.source, &alias_source));
        fs::hard_link(&f.path, &alias).unwrap();
        let before = f.files();
        assert!(
            SignerConsentJournal::open_encrypted(&alias, &f.key, "synthetic-source", &alias_source)
                .is_err()
        );
        assert!(before == f.files(), "retained encrypted files changed");
        fs::remove_file(&alias).unwrap();
        // Checkpoint before copying, then retain the original live handle while
        // replacing its pathname with a different inode carrying equal bytes.
        journal
            .connection
            .lock()
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        fs::copy(&f.path, &alias).unwrap();
        fs::set_permissions(&alias, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&alias, &f.path).unwrap();
        let before = f.files();
        assert!(
            SignerConsentJournal::open_encrypted(&f.path, &f.key, "synthetic-source", &f.source)
                .is_err()
        );
        assert!(before == f.files(), "retained encrypted files changed");
    }
}

#[cfg(test)]
mod expected_schema_cache_tests_v1 {
    use super::*;
    #[test]
    fn cached_expected_schema_19_matches_fresh_and_rejects_target_drift() {
        let cached=expected_schema19_objects_v1().unwrap();
        assert_eq!(*cached,build_expected_schema_objects_v1("").unwrap());
        assert!(std::ptr::eq(cached,expected_schema19_objects_v1().unwrap()));
        let target=Connection::open_in_memory().unwrap();target.execute_batch(SCHEMA).unwrap();
        verify_schema_objects_v1(&target,cached).unwrap();
        target.execute_batch("CREATE TABLE unexpected_cache_probe(value TEXT)").unwrap();
        assert!(matches!(verify_schema_objects_v1(&target,cached),Err(JournalError::UnsupportedSchema)));
        target.execute_batch("DROP TABLE unexpected_cache_probe").unwrap();
        verify_schema_objects_v1(&target,cached).unwrap();
        target.execute_batch("CREATE INDEX unexpected_cache_index ON signer_account(writer_epoch)").unwrap();
        assert!(matches!(verify_schema_objects_v1(&target,cached),Err(JournalError::UnsupportedSchema)));
    }
    #[test]
    fn expected_schema_19_reference_component_benchmark() {
        // Bounded reference-only measurement, not native/full-profile evidence.
        // No timing threshold: overloaded CI must not turn this into a flaky test.
        let cached=expected_schema19_objects_v1().unwrap();let start=std::time::Instant::now();
        for _ in 0..16 {assert_eq!(*cached,build_expected_schema_objects_v1("").unwrap());}
        let uncached=start.elapsed().as_micros();let start=std::time::Instant::now();
        for _ in 0..16 {assert!(std::ptr::eq(cached,expected_schema19_objects_v1().unwrap()));}
        let cached_us=start.elapsed().as_micros();
        println!("SCHEMA_REFERENCE_COMPONENT profile=19 iterations=16 uncached_us={} cached_us={} full_profile_proven=false",uncached,cached_us);
    }
}

#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(in crate::consent_journal) use prepared_delivery_v3::CoordinatedReceiptActionV1;

#[cfg(all(feature = "coordinated-financial-workflow-v1", feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(in crate::consent_journal) use prepared_delivery_v3::CoordinatedAdmissionPublicationV1;
