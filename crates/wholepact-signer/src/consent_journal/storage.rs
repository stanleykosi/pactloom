use super::*;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    path::Path,
    sync::{Mutex, RwLock, RwLockReadGuard},
};
use wholepact_storage_security::{
    DatabaseKey,
    bundle::{BackupReadPermit, BundleError, JournalAdapter, JournalKind, JournalTemplate},
};

pub(super) static TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignerConsentAuthority,
    application_id: APPLICATION_ID,
    schema_version: SCHEMA_VERSION,
    create_sql: SCHEMA,
};

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
}
impl SignerConsentJournal {
    pub(crate) fn create_encrypted(
        path: &Path,
        key: &DatabaseKey,
        account_id: &str,
        writer_epoch: u64,
        recovery_required: bool,
    ) -> Result<Self> {
        id(account_id)?;
        let epoch = i64::try_from(writer_epoch).map_err(|_| JournalError::InvalidBinding)?;
        if epoch <= 0 {
            return Err(JournalError::InvalidBinding);
        }
        let encrypted = wholepact_storage_security::create_encrypted(path, key)?;
        let database_identity = encrypted.database_identity()?;
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
        database_identity.check_current(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            database_identity,
            binding: SignerJournalBinding(Arc::new(())),
            authority_fence: RwLock::new(()),
            #[cfg(feature = "authority-signing")]
            settlement_nodes: Mutex::new(std::collections::BTreeMap::new()),
            #[cfg(test)]
            capacity_limits: (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
        })
    }
    pub(crate) fn open_encrypted(path: &Path, key: &DatabaseKey, account_id: &str) -> Result<Self> {
        let encrypted = wholepact_storage_security::open_encrypted(path, key)?;
        let database_identity = encrypted.database_identity()?;
        let mut connection = encrypted.into_connection();
        let initial_version: i64 =
            connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if matches!(initial_version, 8..=17) && read_account(&connection)?.account_id != account_id
        {
            return Err(JournalError::InvalidBinding);
        }
        if initial_version == 8 {
            recovery_migration::migrate_v8(&mut connection)?;
        }
        if initial_version == 9 {
            recovery_migration::migrate_v9(&mut connection)?;
        }
        if initial_version == 10 {
            recovery_migration::migrate_v10(&mut connection, account_id)?;
        }
        if initial_version == 11 {
            recovery_migration::migrate_v11(&mut connection, account_id)?;
        }
        if initial_version == 12 {
            recovery_migration::migrate_v12(&mut connection, account_id)?;
        }
        if initial_version == 13 {
            recovery_migration::migrate_v13(&mut connection, account_id)?;
        }
        if initial_version == 14 {
            recovery_migration::migrate_v14(&mut connection, account_id)?;
        }
        if initial_version == 15 {
            recovery_migration::migrate_v15(&mut connection, account_id)?;
        }
        if initial_version == 16 {
            recovery_migration::migrate_v16(&mut connection, account_id)?;
        }
        if initial_version == 17 {
            recovery_migration::migrate_v17(&mut connection, account_id)?;
        }
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application != APPLICATION_ID || version != SCHEMA_VERSION {
            return Err(JournalError::UnsupportedSchema);
        }
        verify_schema(&connection)?;
        let generations: i64 = connection.query_row(
            "SELECT count(*) FROM signer_recovery_generations",
            [],
            |r| r.get(0),
        )?;
        if generations != 0 {
            return Err(JournalError::RecoveryRequired);
        }
        let account = read_account(&connection)?;
        if account.account_id != account_id {
            return Err(JournalError::InvalidBinding);
        }
        configure(&connection)?;
        database_identity.check_current(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            database_identity,
            binding: SignerJournalBinding(Arc::new(())),
            authority_fence: RwLock::new(()),
            #[cfg(feature = "authority-signing")]
            settlement_nodes: Mutex::new(std::collections::BTreeMap::new()),
            #[cfg(test)]
            capacity_limits: (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
        })
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
    ) -> Result<Self> {
        let encrypted = wholepact_storage_security::open_encrypted(path, key)?;
        let database_identity = encrypted.database_identity()?;
        let mut connection = encrypted.into_connection();
        let initial_version: i64 =
            connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if matches!(initial_version, 8..=17) && read_account(&connection)?.account_id != account_id
        {
            return Err(JournalError::InvalidBinding);
        }
        if initial_version == 8 {
            recovery_migration::migrate_v8(&mut connection)?;
        }
        if initial_version == 9 {
            recovery_migration::migrate_v9(&mut connection)?;
        }
        if initial_version == 10 {
            recovery_migration::migrate_v10(&mut connection, account_id)?;
        }
        if initial_version == 11 {
            recovery_migration::migrate_v11(&mut connection, account_id)?;
        }
        if initial_version == 12 {
            recovery_migration::migrate_v12(&mut connection, account_id)?;
        }
        if initial_version == 13 {
            recovery_migration::migrate_v13(&mut connection, account_id)?;
        }
        if initial_version == 14 {
            recovery_migration::migrate_v14(&mut connection, account_id)?;
        }
        if initial_version == 15 {
            recovery_migration::migrate_v15(&mut connection, account_id)?;
        }
        if initial_version == 16 {
            recovery_migration::migrate_v16(&mut connection, account_id)?;
        }
        if initial_version == 17 {
            recovery_migration::migrate_v17(&mut connection, account_id)?;
        }
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application != APPLICATION_ID || version != SCHEMA_VERSION {
            return Err(JournalError::UnsupportedSchema);
        }
        verify_schema(&connection)?;
        let record = proof.record();
        let payload = encode(record)?;
        let rows:i64=connection.query_row("SELECT count(*) FROM signer_recovery_generations WHERE generation_id=?1 AND operation_id=?2 AND inventory_digest=?3 AND fence_digest=?4 AND writer_epoch=?5 AND payload=?6",params![record.generation_id,record.operation_id,record.inventory_digest,record.fence_digest,record.writer_epoch,payload.as_str()],|r|r.get(0))?;
        if rows != 2 {
            return Err(JournalError::RecoveryRequired);
        }
        let account = read_account(&connection)?;
        if account.account_id != account_id
            || account.account_id != record.account_id
            || account.writer_epoch < record.writer_epoch
            || account.recovery_required
        {
            return Err(JournalError::RecoveryRequired);
        }
        configure(&connection)?;
        database_identity.check_current(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            database_identity,
            binding: SignerJournalBinding(Arc::new(())),
            authority_fence: RwLock::new(()),
            #[cfg(feature = "authority-signing")]
            settlement_nodes: Mutex::new(std::collections::BTreeMap::new()),
            #[cfg(test)]
            capacity_limits: (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
        })
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
        if a.record.terms().automation.is_some() {
            return Err(JournalError::Permission);
        }
        self.record_consent_release(a)
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
        sponsor::current_for_consent(&tx, t)?;
        automation::current_for_consent(&tx, t)?;
        account_use_storage::require_not_excluded(&tx, &account.account_id)?;
        if let Some(old) = read_original(&tx, &t.authorization_id)? {
            if old != result {
                return Err(JournalError::Conflict);
            }
            return Ok(old);
        }
        offline_history::read_all(&tx, &account.account_id)?;
        offline_history::require_accountwide_online_admission(&tx)?;
        automation::check_outstanding(&tx, t)?;
        let remote_id: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM signer_remote_exposures WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_offline_remote_exposures WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_offline_local_admissions WHERE authorization_id=?1)",
            [&t.authorization_id],
            |r| r.get(0),
        )?;
        if remote_id {
            return Err(JournalError::Conflict);
        }
        let live: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM signer_release_intents WHERE account_id=?1 AND obligation_id=?2 UNION ALL SELECT 1 FROM signer_remote_exposures WHERE account_id=?1 AND obligation_id=?2 UNION ALL SELECT 1 FROM signer_offline_remote_exposures WHERE account_id=?1 AND obligation_id=?2 UNION ALL SELECT 1 FROM signer_offline_local_admissions WHERE account_id=?1 AND obligation_id=?2)", params![t.account_id,t.obligation_id], |r| r.get(0))?;
        if live {
            return Err(JournalError::LiveAuthorization);
        }
        // Budget is fixed in original native account enrollment, never supplied
        // by the coordinator at release. All unresolved signer history counts.
        let mut total: u128 = 0;
        {
            let mut q =
                tx.prepare("SELECT maximum_debit FROM signer_release_intents l WHERE account_id=?1 AND (?2=0 OR NOT EXISTS(SELECT 1 FROM signer_settlement_events e WHERE e.authorization_id=l.authorization_id AND e.kind='canonical_consumed' AND e.sequence=(SELECT max(x.sequence) FROM signer_settlement_events x WHERE x.authorization_id=l.authorization_id))) UNION ALL SELECT maximum_debit FROM signer_remote_exposures r WHERE account_id=?1 AND NOT EXISTS(SELECT 1 FROM signer_original_consents o WHERE o.reference=r.original_consent_ref AND o.authorization_id=r.authorization_id) UNION ALL SELECT maximum_debit FROM signer_offline_remote_exposures WHERE account_id=?1 UNION ALL SELECT maximum_debit FROM signer_offline_local_admissions l WHERE account_id=?1 AND NOT EXISTS(SELECT 1 FROM signer_offline_remote_exposures r WHERE r.authorization_id=l.authorization_id)")?;
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
            let held: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM signer_input_reservations WHERE account_id=?1 AND input_id=?2 UNION ALL SELECT 1 FROM signer_remote_inputs WHERE account_id=?1 AND nullifier=?2 UNION ALL SELECT 1 FROM signer_offline_remote_inputs WHERE account_id=?1 AND nullifier=?2 UNION ALL SELECT 1 FROM signer_offline_local_inputs WHERE account_id=?1 AND nullifier=?2)", params![t.account_id,input.nullifier], |r| r.get(0))?;
            if held {
                return Err(JournalError::InputReserved);
            }
        }
        let consent = encode(&a.record)?;
        let release = encode(&result.release)?;
        tx.execute(
            "INSERT INTO signer_original_consents VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                a.record.reference(),
                t.enrollment_ref,
                t.accepted_manifest_ref,
                t.authorization_id,
                t.receipt.nonce,
                consent.as_str()
            ],
        )?;
        tx.execute(
            "INSERT INTO signer_release_intents VALUES(?1,?2,?3,?4,?5,?6,'outstanding_uncertain')",
            params![
                t.authorization_id,
                a.record.reference(),
                t.account_id,
                t.obligation_id,
                t.maximum_debit_zatoshis.to_string(),
                release.as_str()
            ],
        )?;
        for input in &t.input_bindings {
            tx.execute(
                "INSERT INTO signer_input_reservations VALUES(?1,?2,?3)",
                params![t.account_id, input.nullifier, t.authorization_id],
            )?;
        }
        bounded(&tx, self.capacity_limits())?;
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
    validate_linkage(&result)?;
    Ok(Some(result))
}
pub(super) fn same_native_origin(a: &NativeConsentReceipt, b: &NativeConsentReceipt) -> bool {
    a.native_session_id == b.native_session_id
        && a.permission_generation == b.permission_generation
        && a.trusted_launch_measurement == b.trusted_launch_measurement
        && a.writer_epoch == b.writer_epoch
}
fn validate_linkage(e: &OriginalAuthorizationEvidence) -> Result<()> {
    e.enrollment.validate()?;
    let p = e.manifest.proposal()?;
    e.consent.validate()?;
    let t = e.consent.terms();
    e.enrollment.transport().validate_scope(
        e.enrollment.account_id(),
        e.enrollment.agreement_id(),
        e.enrollment.participant_id(),
        Some(p.manifest_digest()),
    )?;
    if !same_native_origin(e.enrollment.receipt(), e.manifest.receipt())
        || !same_native_origin(e.manifest.receipt(), &t.receipt)
    {
        return Err(JournalError::Permission);
    }
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
    verify_schema_before_common_audit(c)?;
    construction_audit_v3::read_all(c, &read_account(c)?.account_id)?;
    common_context_reentry_audit_v1::read_complete(c, &read_account(c)?.account_id)?;
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
    pub(super) fn inventory_for(&self, account: &str) -> Result<&CommonContextSignerAuditInventoryV2> {
        if self.account != account {
            return Err(JournalError::InvalidBinding);
        }
        Ok(&self.inventory)
    }
}

/// `read_complete` itself reads and fully validates the original construction
/// audit, so no separate, discarded replay is necessary in this same snapshot.
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(super) fn verify_schema_with_common_audit(
    c: &Connection,
) -> Result<ValidatedCommonAudit<'_>> {
    verify_schema_before_common_audit(c)?;
    let account = read_account(c)?.account_id;
    let inventory = common_context_reentry_audit_v1::read_complete(c, &account)?;
    Ok(ValidatedCommonAudit { account, inventory, _snapshot: c })
}

fn verify_schema_before_common_audit(c: &Connection) -> Result<()> {
    type SchemaObject = (String, String, String, Option<String>);
    fn objects(c: &Connection) -> Result<Vec<SchemaObject>> {
        let mut q =
            c.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")?;
        let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA)?;
    if objects(c)? != objects(&expected)? {
        return Err(JournalError::UnsupportedSchema);
    }
    verify_capacity_schema(c)?;
    bounded(c, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES))?;
    offline_history::read_all(c, &read_account(c)?.account_id)?;
    offline_receipts::validate_all(c, &read_account(c)?.account_id)?;
    account_use_storage::inspect(c, &read_account(c)?.account_id)?;
    named_recipient_inventory::validate_archive_rows(c, &read_account(c)?.account_id)?;
    #[cfg(all(feature = "durable-proposal", feature = "native-ui", target_os = "linux"))]
    durable_construction_v1::validate_rows(c)?;
    #[cfg(not(all(feature = "durable-proposal", feature = "native-ui", target_os = "linux")))]
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
        let mut journal = Self::open_encrypted(&path, &key, &proof.genesis().identity.account_id)?;
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
        let mut journal = Self::open_encrypted(&path, &key, &proof.genesis().identity.account_id)?;
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
