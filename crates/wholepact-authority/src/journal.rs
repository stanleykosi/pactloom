use crate::{
    policy::{Event, Ledger},
    *,
};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use std::{path::Path, sync::Mutex};
use wholepact_storage_security::{DatabaseKey, EncryptedConnection};

#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
#[path = "pending_birth_publication.rs"]
mod pending_birth_publication;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) use pending_birth_publication::PendingBirthTargetInspection;

#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
#[path = "namespace_archive_journal.rs"]
mod namespace_archive_journal;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) use namespace_archive_journal::*;

#[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
#[path = "offline_witness_journal_v1.rs"]
mod offline_witness_journal_v1;

#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
#[path = "born_offline_dispatch_journal_v1.rs"]
mod born_offline_dispatch_journal_v1;
#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
#[path = "born_offline_witness_journal_v1.rs"]
mod born_offline_witness_journal_v1;

#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
#[path = "durable_payment_journal_v1.rs"]
mod durable_payment_journal_v1;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
#[path = "durable_delivery_admission_journal_v2.rs"]
mod durable_delivery_admission_journal_v2;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
#[path = "durable_financial_continuation_journal_v1.rs"]
mod durable_financial_continuation_journal_v1;

const APPLICATION_ID: i64 = 0x57504157;
const SCHEMA_VERSION: i64 = 6;
const BORN_ARTIFACT_SCHEMA_VERSION: i64 = 7;
#[path = "born_offline_artifacts_storage_v1.rs"]
mod born_offline_artifacts_storage_v1;
#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
pub(crate) use born_offline_artifacts_storage_v1::install_born_artifact_rows_v1;
#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
pub(crate) use born_offline_artifacts_storage_v1::verify_born_artifact_schema_v1;
fn schema_v7() -> &'static str {
    static SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!(
            "{}\n{}\n{}\n{}\n{}",
            SCHEMA,
            include_str!("born_offline_artifacts_schema_v1.sql"),
            crate::born_offline_artifact_schema_v1::INBOX_SCHEMA,
            crate::born_offline_artifact_schema_v1::OUTBOX_SCHEMA,
            include_str!("born_offline_retry_schema_v1.sql"),
        )
    });
    SQL.as_str()
}
fn schema_for_version(version: i64) -> Result<&'static str> {
    match version {
        5 => Ok(SCHEMA_V5),
        6 => Ok(SCHEMA),
        7 => Ok(schema_v7()),
        _ => Err(AuthorityError::UnsupportedVersion),
    }
}
#[path = "construction_transport_handoff_journal_v1.rs"]
mod construction_transport_handoff_journal_v1;
const LEGACY_SCHEMA: &str = include_str!("schema.sql");
const SCHEMA_V4: &str = concat!(
    include_str!("schema.sql"),
    "\n",
    include_str!("offline_retry_schema.sql"),
    "\n",
    include_str!("offline_outcome_schema.sql")
);
const SCHEMA_V5: &str = concat!(
    include_str!("schema.sql"),
    "\n",
    include_str!("offline_retry_schema.sql"),
    "\n",
    include_str!("offline_outcome_schema.sql"),
    "\n",
    include_str!("pending_birth_schema.sql")
);

const SCHEMA: &str = concat!(
    include_str!("schema.sql"),
    "\n",
    include_str!("offline_retry_schema.sql"),
    "\n",
    include_str!("offline_outcome_schema.sql"),
    "\n",
    include_str!("pending_birth_schema.sql"),
    "\n",
    include_str!("construction_transport_handoff_schema.sql")
);

/// The complete authoritative state is an immutable encrypted append history.
/// There is no signer restore adapter, SQL handle, arbitrary balance setter or
/// exposure-clearing route. Each accepted mutation commits FULL-sync before its
/// result leaves this boundary. Separate connections serialize at BEGIN IMMEDIATE.
pub struct AuthorityJournal {
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    pub(crate) born_manual_scope:
        Option<crate::manual_session_continuation::BornManualBootstrapScope>,
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    pub(crate) born_owner: Option<std::sync::Arc<crate::witness_locator::BornJournalOwner>>,
    pub(crate) connection: Mutex<EncryptedConnection>,
    pub(crate) resolution_node:
        Mutex<Option<std::sync::Arc<wholepact_chain::local_node::LocalValidatingNode>>>,
}
impl AuthorityJournal {
    /// Owner-local enrollment is distinct from remote reservation. The supplied
    /// policy must originate in the owner's trusted setup/consent flow. This API
    /// creates exclusively and never adopts an existing database or account ID.
    pub fn create_encrypted(path: &Path, key: &DatabaseKey, policy: AccountPolicy) -> Result<Self> {
        if policy.account_use_genesis.is_some() {
            return Err(AuthorityError::Permission);
        }
        policy.validate()?;
        let connection = wholepact_storage_security::create_encrypted(path, key)?;
        configure(connection.connection())?;
        let tx =
            Transaction::new_unchecked(connection.connection(), TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO authority_genesis VALUES(1,?1)",
            [&*encode(&policy)?],
        )?;
        tx.execute("INSERT INTO authority_quarantine VALUES(1,0)", [])?;
        for peer in [
            &policy.owner_certificate_digest,
            &policy.initial_writer_certificate_digest,
        ] {
            tx.execute("INSERT INTO authority_principals VALUES(?1)", [peer])?;
        }
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(Self {
            connection: Mutex::new(connection),
            resolution_node: Mutex::new(None),
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            born_owner: None,
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            born_manual_scope: None,
        })
    }
    pub fn open_encrypted(
        path: &Path,
        key: &DatabaseKey,
        expected_account: &str,
        expected_network: &str,
    ) -> Result<Self> {
        let connection = wholepact_storage_security::open_encrypted(path, key)?;
        let c = connection.connection();
        let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if app != APPLICATION_ID || !matches!(version, 3 | 4 | 5 | SCHEMA_VERSION) {
            return Err(AuthorityError::UnsupportedVersion);
        }
        // Ordinary mutable opener keeps its established SQLite concurrency
        // contract and may touch sidecars. It does not bypass born namespace
        // ownership; native supported routes use the separate immutable preflight.
        let raw: Vec<u8> = c.query_row(
            "SELECT policy FROM authority_genesis WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if decode::<AccountPolicy>(&raw)?.account_use_genesis.is_some() {
            return Err(AuthorityError::Permission);
        }
        configure(c)?;
        if version < SCHEMA_VERSION {
            let old_schema = if version == 3 {
                LEGACY_SCHEMA
            } else if version == 4 {
                SCHEMA_V4
            } else {
                SCHEMA_V5
            };
            verify_schema_against(c, old_schema)?;
            let legacy = load(c)?;
            if legacy.policy.account_id != expected_account
                || legacy.policy.network_profile_id != expected_network
                || legacy.policy.account_use_genesis.is_some()
            {
                return Err(AuthorityError::InvalidBinding);
            }
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            let locked_version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
            if matches!(locked_version, 3..=5) {
                verify_schema_against(
                    &tx,
                    if locked_version == 3 {
                        LEGACY_SCHEMA
                    } else if locked_version == 4 {
                        SCHEMA_V4
                    } else {
                        SCHEMA_V5
                    },
                )?;
                let locked = load(&tx)?;
                if locked.policy != legacy.policy {
                    return Err(AuthorityError::InvalidBinding);
                }
                if locked_version == 3 {
                    tx.execute_batch(crate::offline_retry::OFFLINE_RETRY_SCHEMA)?;
                    tx.execute_batch(crate::offline_outcome::OFFLINE_OUTCOME_SCHEMA)?;
                }
                // Empty extension only. Never fabricate a retrospective birth.
                if locked_version < 5 {
                    tx.execute_batch(include_str!("pending_birth_schema.sql"))?;
                }
                tx.execute_batch(include_str!("construction_transport_handoff_schema.sql"))?;
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            } else if locked_version != SCHEMA_VERSION {
                return Err(AuthorityError::UnsupportedVersion);
            }
            verify_schema(&tx)?;
            load(&tx)?;
            tx.commit()?;
        }
        verify_schema(c)?;
        let ledger = load(c)?;
        if ledger.policy.account_id != expected_account
            || ledger.policy.network_profile_id != expected_network
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(Self {
            connection: Mutex::new(connection),
            resolution_node: Mutex::new(None),
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            born_owner: None,
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            born_manual_scope: None,
        })
    }
    pub(crate) fn require_born_mutation_current(&self) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(owner) = &self.born_owner {
            owner.check_mutation_current()?;
            // Scoped bootstrap has a separate narrow route. Neither historical
            // born handles nor enrollment publication grant financial authority.
            return Err(AuthorityError::Permission);
        }
        Ok(())
    }
    fn require_born_bootstrap_owner(&self) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(owner) = &self.born_owner {
            owner.check_mutation_current()?;
            if self.born_manual_scope.is_none() {
                return Err(AuthorityError::Permission);
            }
        }
        Ok(())
    }
    fn require_born_bootstrap_mutation(
        &self,
        ledger: &Ledger,
        mutation: &AuthorityMutation,
        now: u64,
    ) -> Result<()> {
        if ledger.policy.account_use_genesis.is_none() {
            if matches!(
                mutation,
                AuthorityMutation::ReserveManualRosterConstructionV3(_)
                    | AuthorityMutation::ReserveManualRosterConstructionV2(_)
                    | AuthorityMutation::ConsumeManualRosterConstructionV3(_)
                    | AuthorityMutation::ConsumeManualRosterConstructionV2(_)
                    | AuthorityMutation::AdmitBornManualEnrollment(_)
                    | AuthorityMutation::AdmitBornManualEnrollmentV2(_)
                    | AuthorityMutation::AdmitBornManualRosterEnrollmentV2(_)
            ) {
                return Err(AuthorityError::Permission);
            }
            return Ok(());
        }
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if self.born_owner.is_some() {
            let scope = self
                .born_manual_scope
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            if ledger.manual_roster_extension()?.is_some() {
                if ledger.latest_manual_roster_attempt_v2()?.attempt_digest != scope.attempt_digest
                {
                    return Err(AuthorityError::StaleHead);
                }
                return ledger.require_manual_roster_bootstrap_scope_v2(
                    &scope.extension_digest,
                    mutation,
                    now,
                );
            }
            if ledger.latest_manual_attempt()?.attempt_digest != scope.attempt_digest {
                return Err(AuthorityError::StaleHead);
            }
            return ledger.require_manual_bootstrap_scope(&scope.extension_digest, mutation, now);
        }
        let _ = (mutation, now);
        Err(AuthorityError::Permission)
    }
    pub(crate) fn require_born_read_current(&self) -> Result<()> {
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        if let Some(owner) = &self.born_owner {
            owner.check_current()?;
        }
        Ok(())
    }
    pub(crate) fn snapshot(
        &self,
        peer: &str,
        account: &str,
        network: &str,
    ) -> Result<AccountSnapshot> {
        self.require_born_read_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        authenticate_admission(&tx, peer)?;
        let ledger = load(&tx)?;
        ledger.authenticate_read(peer, account, network)?;
        Ok(ledger.snapshot)
    }
    pub(crate) fn mutate_on_channel(
        &self,
        peer: &str,
        mutation: AuthorityMutation,
        proof: Option<protocol::WriterSessionProof>,
        exporter: &[u8; 32],
        server_certificate: &str,
        now: u64,
    ) -> Result<MutationResult> {
        if matches!(
            &mutation,
            AuthorityMutation::ClaimConstructionTransportV1(_)
                | AuthorityMutation::UseConstructionTransportV1(_)
                | AuthorityMutation::QualifiedResolution(_)
                | AuthorityMutation::ReopenResolutions(_)
                | AuthorityMutation::ReserveOfflineAuthorization(_)
                | AuthorityMutation::ReserveBornOfflineV1(_)
                | AuthorityMutation::AuthorizeBornOfflineDispatchV1(_)
                | AuthorityMutation::AuthorizeCompletedDispatchV1(_)
                | AuthorityMutation::OwnerControl(OwnerControlRequest {
                    control: OwnerControl::AdmitDurablePaymentV1 { .. }
                        | OwnerControl::AdmitDurablePaymentWithDeliveryV2 { .. }
                        | OwnerControl::AdmitFinancialContinuationV1 { .. }
                        | OwnerControl::EnrollBornOfflineV1 { .. }
                        | OwnerControl::InstallBornOfflineArtifactsV1 { .. }
                        | OwnerControl::GrantConstructionTransportV1 { .. }
                        | OwnerControl::ApproveManualRosterConstructionV3 { .. }
                        | OwnerControl::ApproveManualRosterConstructionV2 { .. }
                        | OwnerControl::ExtendManualEnrollment { .. }
                        | OwnerControl::ExtendManualRosterEnrollmentV2 { .. }
                        | OwnerControl::ContinueManualRosterSessionV2 { .. }
                        | OwnerControl::ContinueManualEnrollmentSession { .. },
                    ..
                })
        ) {
            return Err(AuthorityError::Permission);
        }
        self.mutate_inner(
            peer,
            mutation,
            proof,
            exporter,
            server_certificate,
            now,
            None,
            false,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn mutate_inner(
        &self,
        peer: &str,
        mutation: AuthorityMutation,
        proof: Option<protocol::WriterSessionProof>,
        exporter: &[u8; 32],
        server_certificate: &str,
        now: u64,
        offline_authentication: Option<&AuthenticatedOfflineIntent>,
        require_original: bool,
    ) -> Result<MutationResult> {
        self.mutate_inner_timed(
            peer,
            mutation,
            proof,
            exporter,
            server_certificate,
            now,
            offline_authentication,
            require_original,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn mutate_inner_timed(
        &self,
        peer: &str,
        mutation: AuthorityMutation,
        proof: Option<protocol::WriterSessionProof>,
        exporter: &[u8; 32],
        server_certificate: &str,
        now: u64,
        offline_authentication: Option<&AuthenticatedOfflineIntent>,
        require_original: bool,
        current: Option<&crate::offline_witness_v1::CurrentOfflineWitnessWindowV1>,
    ) -> Result<MutationResult> {
        // The generic adapter, including synthetic/offline callers, cannot issue
        // a handoff or reinterpret its proof as ordinary writer authentication.
        if matches!(
            &mutation,
            AuthorityMutation::ClaimConstructionTransportV1(_)
                | AuthorityMutation::UseConstructionTransportV1(_)
                | AuthorityMutation::AuthorizeCompletedDispatchV1(_)
                | AuthorityMutation::OwnerControl(OwnerControlRequest {
                    control: OwnerControl::AdmitDurablePaymentV1 { .. }
                        | OwnerControl::AdmitDurablePaymentWithDeliveryV2 { .. }
                        | OwnerControl::AdmitFinancialContinuationV1 { .. }
                        | OwnerControl::GrantConstructionTransportV1 { .. },
                    ..
                })
        ) {
            return Err(AuthorityError::Permission);
        }
        self.require_born_bootstrap_owner()?;
        match (&mutation, offline_authentication) {
            (AuthorityMutation::ReserveOfflineAuthorization(record), Some(authentication)) => {
                authentication.matches(&record.request, &record.authentication)?
            }
            (AuthorityMutation::ReserveOfflineAuthorization(_), None) | (_, Some(_)) => {
                return Err(AuthorityError::Authentication);
            }
            (_, None) => {}
        }
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        let now = match current {
            Some(window) => window.check()?,
            None => now,
        };
        authenticate_admission(&tx, peer)?;
        let mut ledger = load(&tx)?;
        ledger.require_delivery_admission_only_v2(&mutation)?;
        self.require_born_bootstrap_mutation(&ledger, &mutation, now)?;
        let mut event = Event {
            original_request_link: None,
            mutation,
            authenticated_certificate_digest: peer.into(),
            witness_time_ms: now,
            writer_session_id: proof.as_ref().map(|p| p.session_id.clone()),
        };
        ledger.authenticate_mutation(&event)?;
        if let Some(proof) = &proof {
            ledger.require_unfenced_transport(&proof.session_id)?;
        }
        ledger.require_unconsumed_roster_construction_v2(&event.mutation)?;
        ledger.require_unconsumed_roster_construction_v3(&event.mutation)?;
        // This boundary returns opaque execution admissions even for an exact
        // retry. Historical read/replay remains available separately; retirement
        // must prevent reminting an execution wrapper from an old reservation.
        ledger.require_account_use_for_new_mutation(&event.mutation)?;
        if ledger.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        let mut new_session_key: Option<Zeroizing<[u8; 32]>> = None;
        match &event.mutation {
            AuthorityMutation::OwnerControl(_) => {
                if proof.is_some() {
                    return Err(AuthorityError::InvalidBinding);
                }
            }
            AuthorityMutation::AcquireWriter(request) if ledger.replay(&event)?.is_none() => {
                if proof.is_some()
                    || crate::session::session_id(exporter) != request.session_id
                    || request.disclosure.pinned_server_certificate_digest != server_certificate
                {
                    return Err(AuthorityError::Authentication);
                }
                event.writer_session_id = None;
                new_session_key = Some(Zeroizing::new(*exporter));
            }
            _ => {
                let proof = proof.as_ref().ok_or(AuthorityError::SessionRequired)?;
                let receipt = ledger
                    .sessions
                    .get(&proof.session_id)
                    .ok_or(AuthorityError::SessionRequired)?;
                if receipt.writer_certificate_digest != peer
                    || receipt.disclosure.pinned_server_certificate_digest != server_certificate
                {
                    return Err(AuthorityError::Permission);
                }
                if !matches!(&event.mutation, AuthorityMutation::AcquireWriter(_))
                    && !ledger.activated_sessions.contains(&proof.session_id)
                {
                    return Err(AuthorityError::SessionRequired);
                }
                let key = read_session_key(&tx, &proof.session_id)?;
                crate::session::verify(&key, receipt, exporter, &event.mutation, proof)?;
            }
        }
        if matches!(
            &event.mutation,
            AuthorityMutation::ReserveManualRosterConstructionV3(_)
                | AuthorityMutation::ReserveManualRosterConstructionV2(_)
                | AuthorityMutation::ReserveAuthorization(_)
                | AuthorityMutation::ReserveOfflineAuthorization(_)
                | AuthorityMutation::ReserveBornOfflineV1(_)
                | AuthorityMutation::AuthorizeBornOfflineDispatchV1(_)
                | AuthorityMutation::AuthorizeCompletedDispatchV1(_)
                | AuthorityMutation::AuthorizeAutomaticKeyUse(_)
                | AuthorityMutation::AuthorizeDispatch(_)
                | AuthorityMutation::OwnerControl(OwnerControlRequest {
                    control: OwnerControl::RecoverWriter { .. },
                    ..
                })
        ) && !ledger.resolutions.is_empty()
            && self.revalidate_resolutions(&ledger).is_err()
        {
            self.append_reopen(&tx, &mut ledger, now)?;
            tx.commit()?;
            return Err(AuthorityError::ResolutionUnavailable);
        }
        if let AuthorityMutation::ReserveOfflineAuthorization(record) = &event.mutation {
            crate::offline_outcome::ensure_offline_request_not_terminated(&tx, &record.request)?;
        }
        if require_original {
            let AuthorityMutation::ReserveOfflineAuthorization(record) = &event.mutation else {
                return Err(AuthorityError::InvalidBinding);
            };
            let session = event
                .writer_session_id
                .as_deref()
                .ok_or(AuthorityError::SessionRequired)?;
            event.original_request_link = Some(crate::offline_retry::original_event_link(
                &tx,
                peer,
                &record.request,
                &record.authentication,
                session,
                now,
            )?);
        }
        // Even an exact dispatch replay returns a live authenticated admission;
        // revalidate released exposure before returning that capability.
        if let Some(result) = ledger.replay(&event)? {
            if matches!(
                &event.mutation,
                AuthorityMutation::AuthorizeAutomaticKeyUse(_)
            ) {
                // The original durable admission may have escaped. Reissuing a
                // capability could repeat key use after a crash or revocation.
                return Err(AuthorityError::Uncertain);
            }
            if let Some(window) = current {
                let AuthorityMutation::ReserveOfflineAuthorization(record) = &event.mutation else {
                    return Err(AuthorityError::InvalidBinding);
                };
                let checked =
                    crate::offline_retry::gate(&tx, peer, &record.request, window.check()?)?;
                window.check_after_replay(&checked, &record.request)?;
            }
            return Ok(result);
        }
        let previous_head = ledger.snapshot.head.digest.clone();
        let result = ledger.apply(&event)?;
        if let Some(link) = &event.original_request_link {
            let AuthorityMutation::ReserveOfflineAuthorization(record) = &event.mutation else {
                return Err(AuthorityError::InvalidBinding);
            };
            let MutationResult::OfflineReserved(admission) = &result else {
                return Err(AuthorityError::CorruptHistory);
            };
            if &crate::offline_retry::original_commit_link(
                &tx,
                peer,
                &record.request,
                &record.authentication,
                admission,
                now,
            )? != link
            {
                return Err(AuthorityError::Conflict);
            }
        }
        let payload = encode(&event)?;
        let bytes: u64 = tx.query_row(
            "SELECT coalesce(sum(length(payload)),0) FROM authority_events",
            [],
            |r| r.get(0),
        )?;
        if bytes
            .checked_add(payload.len() as u64)
            .filter(|v| *v <= MAX_JOURNAL_BYTES)
            .is_none()
        {
            return Err(AuthorityError::Limit);
        }
        tx.execute(
            "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
            params![
                ledger.snapshot.head.sequence,
                event.mutation.operation_id(),
                previous_head,
                ledger.snapshot.head.digest,
                &*payload
            ],
        )?;
        if let AuthorityMutation::OwnerControl(OwnerControlRequest {
            control:
                OwnerControl::ReplaceWriter {
                    writer_certificate_digest,
                }
                | OwnerControl::RecoverWriter {
                    writer_certificate_digest,
                    ..
                },
            ..
        }) = &event.mutation
        {
            tx.execute(
                "INSERT OR IGNORE INTO authority_principals VALUES(?1)",
                [writer_certificate_digest],
            )?;
        }
        if let Some(key) = new_session_key {
            let AuthorityMutation::AcquireWriter(request) = &event.mutation else {
                return Err(AuthorityError::InvalidBinding);
            };
            tx.execute(
                "INSERT INTO authority_session_keys VALUES(?1,?2)",
                params![request.session_id, key.as_slice()],
            )?;
        }
        // Native extension scope, global alias exclusions and namespace continuity
        // are checked again at the durable boundary. No GUI lease spans network I/O.
        self.require_born_bootstrap_owner()?;
        self.require_born_bootstrap_mutation(&ledger, &event.mutation, now_ms()?)?;
        if let Some(window) = current {
            let AuthorityMutation::ReserveOfflineAuthorization(record) = &event.mutation else {
                return Err(AuthorityError::InvalidBinding);
            };
            let checked = crate::offline_retry::gate(&tx, peer, &record.request, window.check()?)?;
            window.check_after_replay(&checked, &record.request)?;
        }
        tx.commit()?;
        Ok(result)
    }
    pub(crate) fn history(
        &self,
        peer: &str,
        account: &str,
        network: &str,
        expected: &AuthorityHead,
        after: u64,
        maximum: u16,
    ) -> Result<HistoryPage> {
        self.require_born_read_current()?;
        if maximum == 0 || maximum > 16 || after > expected.sequence {
            return Err(AuthorityError::Limit);
        }
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        authenticate_admission(&tx, peer)?;
        let ledger = load(&tx)?;
        ledger.authenticate_read(peer, account, network)?;
        history_page_at(&tx, ledger, expected, after, maximum)
    }
    #[cfg(any(test, feature = "synthetic-qualification"))]
    pub(crate) fn synthetic_activate(&self, peer: &str, now: u64) -> Result<AccountSnapshot> {
        let (policy, snapshot) = {
            let c = self
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let ledger = load(c.connection())?;
            if ledger.selected_durable_delivery_admission_v2()?.is_some() {
                return Err(AuthorityError::PolicyDenied);
            }
            (ledger.policy, ledger.snapshot)
        };
        if peer != snapshot.writer_certificate_digest {
            return Err(AuthorityError::Permission);
        }
        if snapshot.active_writer_session.is_some() {
            return Ok(snapshot);
        }
        let key = Zeroizing::new(
            Sha256::digest(
                format!("SYNTHETIC-ONLY-session-{}-{peer}", snapshot.head.digest).as_bytes(),
            )
            .into(),
        );
        let disclosure = WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:1".into(),
            server_name: "localhost".into(),
            witness_id: policy.witness_id,
            account_id: policy.account_id.clone(),
            network_profile_id: policy.network_profile_id.clone(),
            policy_digest: snapshot.policy_digest.clone(),
            pinned_server_certificate_digest: "0".repeat(64),
        };
        let acquire = AcquireWriterRequest {
            operation_id: format!("synthetic-acquire-{}", snapshot.head.sequence + 1),
            account_id: policy.account_id.clone(),
            network_profile_id: policy.network_profile_id.clone(),
            writer_epoch: snapshot.writer_epoch,
            expected_head: snapshot.head.clone(),
            reconciled_history_digest: crate::session::history_digest(&snapshot)?,
            session_id: crate::session::session_id(&key),
            disclosure,
        };
        let result = self.mutate_inner(
            peer,
            AuthorityMutation::AcquireWriter(acquire),
            None,
            &key,
            &"0".repeat(64),
            now,
            None,
            false,
        )?;
        let MutationResult::WriterPending(receipt) = result else {
            return Err(AuthorityError::InvalidBinding);
        };
        let activate = OwnerControlRequest {
            operation_id: format!("synthetic-activate-{}", receipt.acquired_head.sequence + 1),
            account_id: policy.account_id,
            network_profile_id: policy.network_profile_id,
            expected_head: receipt.acquired_head,
            writer_epoch: receipt.writer_epoch,
            control: OwnerControl::ActivateWriter {
                session_id: receipt.session_id,
            },
        };
        match self.mutate_inner(
            &policy.owner_certificate_digest,
            AuthorityMutation::OwnerControl(activate),
            None,
            &[0; 32],
            &"0".repeat(64),
            now + 1,
            None,
            false,
        )? {
            MutationResult::Controlled(snapshot) => Ok(snapshot),
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
    #[cfg(any(test, feature = "synthetic-qualification"))]
    pub(crate) fn mutate(
        &self,
        peer: &str,
        mutation: AuthorityMutation,
        now: u64,
    ) -> Result<MutationResult> {
        let proof = if matches!(&mutation, AuthorityMutation::OwnerControl(_)) {
            None
        } else {
            let c = self
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            authenticate_admission(c.connection(), peer)?;
            let ledger = load(c.connection())?;
            ledger.require_delivery_admission_only_v2(&mutation)?;
            let event = Event {
                original_request_link: None,
                mutation: mutation.clone(),
                authenticated_certificate_digest: peer.into(),
                witness_time_ms: now,
                writer_session_id: None,
            };
            ledger.authenticate_mutation(&event)?;
            if ledger.snapshot.writer_status == WriterStatus::Quarantined {
                return Err(AuthorityError::RecoveryRequired);
            }
            let historical = ledger.historical_session(mutation.operation_id());
            let selected = historical
                .or_else(|| {
                    ledger
                        .snapshot
                        .active_writer_session
                        .as_ref()
                        .map(|s| s.session_id.as_str())
                })
                .ok_or(AuthorityError::SessionRequired)?;
            let receipt = ledger
                .sessions
                .get(selected)
                .ok_or(AuthorityError::SessionRequired)?;
            let key = read_session_key(c.connection(), selected)?;
            Some(crate::session::proof(
                &key,
                (
                    &receipt.session_id,
                    &receipt.disclosure,
                    receipt.writer_epoch,
                ),
                &[0xaa; 32],
                &mutation,
            )?)
        };
        self.mutate_inner(
            peer,
            mutation,
            proof,
            &[0xaa; 32],
            &"0".repeat(64),
            now,
            None,
            false,
        )
    }
    /// A separate independently keyed backup. The destination is quarantined
    /// before it is returned and cannot issue new or historical permits. A crash
    /// before quarantine completes leaves only a staging file, never a completed
    /// backup path. Never put this in the signer's bundle or restore lifecycle.
    pub fn backup_quarantined(
        &self,
        staging_path: &Path,
        completed_path: &Path,
        key: &DatabaseKey,
    ) -> Result<()> {
        // Born namespaces require their complete immutable installation/index backup.
        // A standalone account backup cannot preserve that provenance.
        self.require_born_mutation_current()?;
        if staging_path == completed_path
            || staging_path.parent() != completed_path.parent()
            || completed_path.exists()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let source = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let source_tx =
            Transaction::new_unchecked(source.connection(), TransactionBehavior::Deferred)?;
        load(&source_tx)?;
        let backup = wholepact_storage_security::create_encrypted(staging_path, key)?;
        // Schema, original history and quarantine enter the destination in ONE
        // transaction. A crash cannot leave an integrity-valid active backup.
        let destination_tx =
            Transaction::new_unchecked(backup.connection(), TransactionBehavior::Immediate)?;
        destination_tx.execute_batch(SCHEMA)?;
        let policy = Zeroizing::new(source_tx.query_row(
            "SELECT policy FROM authority_genesis WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )?);
        destination_tx.execute("INSERT INTO authority_genesis VALUES(1,?1)", [&*policy])?;
        destination_tx.execute("INSERT INTO authority_quarantine VALUES(1,1)", [])?;
        {
            let mut query = source_tx
                .prepare("SELECT evidence_digest,payload FROM authority_resolution_evidence")?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                let payload = Zeroizing::new(row.get::<_, Vec<u8>>(1)?);
                destination_tx.execute(
                    "INSERT INTO authority_resolution_evidence VALUES(?1,?2)",
                    params![row.get::<_, String>(0)?, &*payload],
                )?;
            }
        }
        {
            let mut query = source_tx.prepare(
                "SELECT session_id,secret FROM authority_session_keys ORDER BY session_id",
            )?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                let key = Zeroizing::new(row.get::<_, Vec<u8>>(1)?);
                destination_tx.execute(
                    "INSERT INTO authority_session_keys VALUES(?1,?2)",
                    params![row.get::<_, String>(0)?, &*key],
                )?;
            }
        }
        {
            let mut query = source_tx.prepare(
                "SELECT certificate_digest FROM authority_principals ORDER BY certificate_digest",
            )?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                destination_tx.execute(
                    "INSERT INTO authority_principals VALUES(?1)",
                    [row.get::<_, String>(0)?],
                )?;
            }
        }
        {
            let mut query = source_tx.prepare("SELECT sequence,operation_id,previous_head,head,payload FROM authority_events ORDER BY sequence")?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                let payload = Zeroizing::new(row.get::<_, Vec<u8>>(4)?);
                destination_tx.execute(
                    "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
                    params![
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        &*payload
                    ],
                )?;
            }
        }
        crate::offline_retry::copy_offline_state(&source_tx, &destination_tx)?;
        construction_transport_handoff_journal_v1::copy_handoff_tables(
            &source_tx,
            &destination_tx,
        )?;
        if let Some(record) =
            crate::pending_birth_storage::read(&source_tx, &load(&source_tx)?.policy)?
        {
            destination_tx.execute(
                "INSERT INTO authority_pending_birth_commit VALUES(1,?1,?2,?3)",
                params![
                    record.request.operation_id,
                    record.request_digest,
                    serde_json::to_string(&record).map_err(|_| AuthorityError::InvalidBinding)?
                ],
            )?;
        }
        destination_tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        destination_tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        load(&destination_tx)?;
        destination_tx.commit()?;
        let (busy, _, _): (i64, i64, i64) =
            backup
                .connection()
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
        if busy != 0 {
            return Err(AuthorityError::Storage);
        }
        drop(backup);
        std::fs::File::open(staging_path)
            .and_then(|f| f.sync_all())
            .map_err(|_| AuthorityError::Storage)?;
        // Hard-link is exclusive unlike rename; the completed artifact is never
        // overwritten. Remove staging immediately to restore nlink=1 validation.
        std::fs::hard_link(staging_path, completed_path).map_err(|_| AuthorityError::Storage)?;
        std::fs::remove_file(staging_path).map_err(|_| AuthorityError::Storage)?;
        std::fs::File::open(completed_path.parent().ok_or(AuthorityError::Storage)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| AuthorityError::Storage)?;
        Ok(())
    }
    /// Reports whether an exact owner-enrolled native source is attached. This is
    /// configuration availability, not evidence of settlement or node freshness.
    pub fn resolution_capability(&self) -> Result<()> {
        self.require_born_mutation_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = load(c.connection())?;
        if ledger.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        let node = self
            .resolution_node
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let node = node.as_ref().ok_or(AuthorityError::ResolutionUnavailable)?;
        if ledger.resolution_source.as_ref()
            != Some(&resolution_source_digest(&node.source_descriptor())?)
        {
            return Err(AuthorityError::Permission);
        }
        Ok(())
    }
}

/// Build the maintained bounded page from the ledger loaded in the caller's
/// transaction. The caller retains the journal lock and must authenticate scope
/// before entering this helper; it never opens another connection or loads a
/// newer head between validation and page construction.
pub(crate) fn history_page_at(
    c: &Connection,
    ledger: Ledger,
    expected: &AuthorityHead,
    after: u64,
    maximum: u16,
) -> Result<HistoryPage> {
    if maximum == 0 || maximum > 16 || after > expected.sequence {
        return Err(AuthorityError::Limit);
    }
    if &ledger.snapshot.head != expected {
        return Err(AuthorityError::StaleHead);
    }
    let pending_birth_commit = crate::pending_birth_storage::read(c, &ledger.policy)?;
    let mut page = HistoryPage {
        pending_birth_commit,
        policy: ledger.policy,
        snapshot: ledger.snapshot,
        entries: Vec::new(),
        next_after_sequence: None,
    };
    let mut q = c.prepare("SELECT sequence,previous_head,head,payload FROM authority_events WHERE sequence>?1 ORDER BY sequence LIMIT ?2")?;
    let mut rows = q.query(params![after, maximum])?;
    while let Some(row) = rows.next()? {
        let raw = Zeroizing::new(row.get::<_, Vec<u8>>(3)?);
        let event: Event = decode(&raw)?;
        page.entries.push(HistoryEntry {
            original_request_link: event.original_request_link,
            sequence: row.get(0)?,
            previous_head: row.get(1)?,
            head: row.get(2)?,
            mutation: event.mutation,
            authenticated_certificate_digest: event.authenticated_certificate_digest,
            witness_time_ms: event.witness_time_ms,
            writer_session_id: event.writer_session_id,
        });
        // Include the actual response envelope and a possible continuation
        // cursor when enforcing the transport bound. A page must be usable,
        // not merely have an individually serializable inner payload.
        page.next_after_sequence = Some(row.get(0)?);
        if encode(&protocol::WireResponse::History(Box::new(page.clone()))).is_err() {
            page.entries.pop();
            break;
        }
    }
    let last = page.entries.last().map_or(after, |e| e.sequence);
    page.next_after_sequence = None;
    if last < expected.sequence {
        if last == after {
            return Err(AuthorityError::Limit);
        }
        page.next_after_sequence = Some(last);
    }
    encode(&protocol::WireResponse::History(Box::new(page.clone())))?;
    Ok(page)
}

fn configure(c: &Connection) -> Result<()> {
    c.execute_batch(
        "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA max_page_count=32768;",
    )?;
    Ok(())
}
pub(crate) fn authenticate_admission(c: &Connection, peer: &str) -> Result<()> {
    // Admission only; current permissions and history are still checked in full.
    let known: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM authority_principals WHERE certificate_digest=?1)",
        [peer],
        |r| r.get(0),
    )?;
    if !known {
        return Err(AuthorityError::Permission);
    }
    Ok(())
}
fn is_quarantined(c: &Connection) -> Result<bool> {
    Ok(c.query_row(
        "SELECT quarantined FROM authority_quarantine WHERE singleton=1",
        [],
        |r| r.get(0),
    )?)
}
#[derive(Clone, Copy)]
pub(crate) enum OriginalHistoryProfileV1 { Legacy, FinancialContinuation }
pub(crate) fn load(c: &Connection) -> Result<Ledger> { load_profile(c, OriginalHistoryProfileV1::Legacy) }
pub(crate) fn load_financial_continuation_v1(c: &Connection) -> Result<Ledger> { load_profile(c, OriginalHistoryProfileV1::FinancialContinuation) }
fn load_profile(c: &Connection, profile: OriginalHistoryProfileV1) -> Result<Ledger> {
    let raw: Zeroizing<Vec<u8>> = Zeroizing::new(c.query_row(
        "SELECT policy FROM authority_genesis WHERE singleton=1",
        [],
        |r| r.get(0),
    )?);
    let mut ledger = Ledger::new(decode(&raw)?)?;
    let mut q = c.prepare("SELECT sequence,operation_id,previous_head,head,payload FROM authority_events ORDER BY sequence")?;
    let mut rows = q.query([])?;
    let mut total = 0_u64;
    while let Some(row) = rows.next()? {
        let sequence: u64 = row.get(0)?;
        let operation: String = row.get(1)?;
        let previous: String = row.get(2)?;
        let head: String = row.get(3)?;
        let raw = Zeroizing::new(row.get::<_, Vec<u8>>(4)?);
        total = total
            .checked_add(raw.len() as u64)
            .filter(|v| *v <= MAX_JOURNAL_BYTES)
            .ok_or(AuthorityError::Limit)?;
        let event: Event = decode(&raw)?;
        if sequence != ledger.snapshot.head.sequence + 1
            || previous != ledger.snapshot.head.digest
            || operation != event.mutation.operation_id()
            || ledger.replay(&event)?.is_some()
        {
            return Err(AuthorityError::CorruptHistory);
        }
        if let AuthorityMutation::QualifiedResolution(record) = &event.mutation {
            let payload = Zeroizing::new(c.query_row(
                "SELECT payload FROM authority_resolution_evidence WHERE evidence_digest=?1",
                [&record.evidence_digest],
                |r| r.get::<_, Vec<u8>>(0),
            )?);
            if hex::encode(Sha256::digest(&*payload)) != record.evidence_digest {
                return Err(AuthorityError::CorruptHistory);
            }
        }
        if let Some(link) = &event.original_request_link {
            let AuthorityMutation::ReserveOfflineAuthorization(record) = &event.mutation else {
                return Err(AuthorityError::CorruptHistory);
            };
            crate::offline_retry::verify_original_event_link(
                c,
                record,
                link,
                ledger
                    .offline_policies
                    .get(&record.request.intent.terms.offline_policy_digest)
                    .ok_or(AuthorityError::CorruptHistory)?,
                event
                    .writer_session_id
                    .as_deref()
                    .ok_or(AuthorityError::CorruptHistory)?,
                event.witness_time_ms,
            )?;
        }
        match profile {
            OriginalHistoryProfileV1::Legacy => ledger.apply(&event),
            OriginalHistoryProfileV1::FinancialContinuation => ledger.apply_financial_continuation_v1(&event),
        }.map_err(|_| AuthorityError::CorruptHistory)?;
        if ledger.snapshot.head.digest != head {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    if is_quarantined(c)? {
        ledger.snapshot.writer_status = WriterStatus::Quarantined;
    }
    let mut query = c.prepare(
        "SELECT certificate_digest FROM authority_principals ORDER BY certificate_digest",
    )?;
    let peers = query
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()?;
    if peers
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != ledger.admitted_certificates()
    {
        return Err(AuthorityError::CorruptHistory);
    }
    let count: usize = c.query_row("SELECT count(*) FROM authority_session_keys", [], |r| {
        r.get(0)
    })?;
    if count != ledger.sessions.len() {
        return Err(AuthorityError::CorruptHistory);
    }
    for id in ledger.sessions.keys() {
        let key = read_session_key_retained(c, id)?;
        if crate::session::session_id(&key) != *id {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if matches!(version, 4..=7) {
        crate::offline_retry::verify_offline_state(c, &ledger)?;
    }
    if matches!(version, 5..=7) {
        let birth = crate::pending_birth_storage::read(c, &ledger.policy)?;
        ledger.validate_manual_birth(birth.as_ref())?;
        ledger.validate_durable_payment_birth_v1(birth.as_ref())?;
        match profile {
            OriginalHistoryProfileV1::Legacy => ledger.validate_durable_delivery_birth_v2(birth.as_ref())?,
            OriginalHistoryProfileV1::FinancialContinuation => ledger.validate_financial_continuation_birth_v1(birth.as_ref())?,
        }
        ledger.validate_born_offline_birth_v1(birth.as_ref())?;
    } else if ledger.policy.account_use_genesis.is_some() {
        return Err(AuthorityError::CorruptHistory);
    }
    if matches!(version, 6 | 7) {
        construction_transport_handoff_journal_v1::verify_handoff_tables(c, &ledger)?;
    } else if !ledger.construction_transport_history_v1().is_empty() {
        return Err(AuthorityError::CorruptHistory);
    }
    born_offline_artifacts_storage_v1::verify_artifact_tables(c, &ledger)?;
    if version == BORN_ARTIFACT_SCHEMA_VERSION {
        crate::born_offline_retry_v1::verify_retained_born_offline_v1(c, &ledger)?;
    }
    Ok(ledger)
}
fn verify_schema(c: &Connection) -> Result<()> {
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    verify_schema_against(c, schema_for_version(version)?)
}
fn verify_schema_against(c: &Connection, expected_sql: &str) -> Result<()> {
    // Compare the exact compiled schema using a scratch in-memory schema only;
    // private account data never enters the unencrypted connection.
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(expected_sql)?;
    fn schema(c: &Connection) -> Result<Vec<(String, String, String)>> {
        let mut q = c.prepare("SELECT type,name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name")?;
        let rows = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
    if schema(c)? != schema(&expected)? {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(())
}

fn read_session_key(c: &Connection, id: &str) -> Result<Zeroizing<[u8; 32]>> {
    #[cfg(all(test, feature = "native-witness-owner", target_os = "linux"))]
    durable_delivery_admission_journal_v2::observe_operational_key_read_for_test();
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version == SCHEMA_VERSION {
        let count: u64 = c.query_row(
            "SELECT count(*) FROM authority_transport_fences WHERE session_id=?1",
            [id],
            |r| r.get(0),
        )?;
        if count != 0 {
            return Err(AuthorityError::SessionRequired);
        }
    }
    read_session_key_retained(c, id)
}
fn read_session_key_retained(c: &Connection, id: &str) -> Result<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(c.query_row(
        "SELECT secret FROM authority_session_keys WHERE session_id=?1",
        [id],
        |r| r.get::<_, Vec<u8>>(0),
    )?);
    Ok(Zeroizing::new(
        raw.as_slice()
            .try_into()
            .map_err(|_| AuthorityError::CorruptHistory)?,
    ))
}

impl AuthorityJournal {
    /// Disabled foundation: private witness composition only. No generic remote
    /// method or public token factory can call this route. The held opaque intent
    /// was authenticated by the configured witness bridge, not the mTLS client.
    #[allow(dead_code, clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn commit_offline_authenticated(
        &self,
        peer: &str,
        request: crate::offline::ReserveOfflineAuthorization,
        authentication: AuthenticatedOfflineIntent,
        proof: Option<protocol::WriterSessionProof>,
        exporter: &[u8; 32],
        server_certificate: &str,
        now: u64,
    ) -> Result<CommittedOfflineAdmission> {
        let record = OfflineReservationRecord {
            request,
            authentication: authentication.evidence().clone(),
        };
        authentication.matches(&record.request, &record.authentication)?;
        let result = self.mutate_inner(
            peer,
            AuthorityMutation::ReserveOfflineAuthorization(Box::new(record)),
            proof,
            exporter,
            server_certificate,
            now,
            Some(&authentication),
            false,
        )?;
        let MutationResult::OfflineReserved(descriptor) = result else {
            return Err(AuthorityError::CorruptHistory);
        };
        // mutate_inner committed before returning. Nothing usable escapes earlier.
        Ok(CommittedOfflineAdmission {
            descriptor: *descriptor,
        })
    }

    // Connected original-request route; private until complete configured bridge activation.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub(crate) fn commit_offline_prepared(
        &self,
        peer: &str,
        request: crate::offline::ReserveOfflineAuthorization,
        authentication: AuthenticatedOfflineIntent,
        proof: Option<protocol::WriterSessionProof>,
        exporter: &[u8; 32],
        server_certificate: &str,
        now: u64,
    ) -> Result<CommittedOfflineAdmission> {
        let record = OfflineReservationRecord {
            request,
            authentication: authentication.evidence().clone(),
        };
        authentication.matches(&record.request, &record.authentication)?;
        let result = self.mutate_inner(
            peer,
            AuthorityMutation::ReserveOfflineAuthorization(Box::new(record)),
            proof,
            exporter,
            server_certificate,
            now,
            Some(&authentication),
            true,
        )?;
        let MutationResult::OfflineReserved(descriptor) = result else {
            return Err(AuthorityError::CorruptHistory);
        };
        // mutate_inner committed before returning. Nothing usable escapes earlier.
        Ok(CommittedOfflineAdmission {
            descriptor: *descriptor,
        })
    }
}

#[cfg(test)]
impl AuthorityJournal {
    /// Test-only direct composition; never exposed by a production witness server.
    pub(crate) fn commit_offline_for_test(
        &self,
        peer: &str,
        request: crate::offline::ReserveOfflineAuthorization,
        authentication: AuthenticatedOfflineIntent,
        now: u64,
    ) -> Result<CommittedOfflineAdmission> {
        let record = OfflineReservationRecord {
            request: request.clone(),
            authentication: authentication.evidence().clone(),
        };
        let mutation = AuthorityMutation::ReserveOfflineAuthorization(Box::new(record));
        let proof = {
            let c = self
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let ledger = load(c.connection())?;
            ledger.require_delivery_admission_only_v2(&mutation)?;
            let selected = ledger
                .historical_session(&request.operation_id)
                .or_else(|| {
                    ledger
                        .snapshot
                        .active_writer_session
                        .as_ref()
                        .map(|s| s.session_id.as_str())
                })
                .ok_or(AuthorityError::SessionRequired)?;
            let receipt = ledger
                .sessions
                .get(selected)
                .ok_or(AuthorityError::SessionRequired)?;
            let key = read_session_key(c.connection(), selected)?;
            crate::session::proof(
                &key,
                (
                    &receipt.session_id,
                    &receipt.disclosure,
                    receipt.writer_epoch,
                ),
                &[0xaa; 32],
                &mutation,
            )?
        };
        self.commit_offline_authenticated(
            peer,
            request,
            authentication,
            Some(proof),
            &[0xaa; 32],
            &"0".repeat(64),
            now,
        )
    }
}

// Test-only helpers; no production constructor/API.
#[cfg(test)]
impl AuthorityJournal {
    /// Reuse the existing synthetic channel-proof setup, but exercise the real
    /// linked original-request transaction route rather than legacy issuance.
    pub(crate) fn commit_offline_prepared_for_test(
        &self,
        peer: &str,
        request: crate::offline::ReserveOfflineAuthorization,
        authentication: AuthenticatedOfflineIntent,
        now: u64,
    ) -> Result<CommittedOfflineAdmission> {
        let record = OfflineReservationRecord {
            request: request.clone(),
            authentication: authentication.evidence().clone(),
        };
        let mutation = AuthorityMutation::ReserveOfflineAuthorization(Box::new(record));
        let proof = {
            let c = self
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let ledger = load(c.connection())?;
            ledger.require_delivery_admission_only_v2(&mutation)?;
            let selected = ledger
                .historical_session(&request.operation_id)
                .or_else(|| {
                    ledger
                        .snapshot
                        .active_writer_session
                        .as_ref()
                        .map(|s| s.session_id.as_str())
                })
                .ok_or(AuthorityError::SessionRequired)?;
            let receipt = ledger
                .sessions
                .get(selected)
                .ok_or(AuthorityError::SessionRequired)?;
            let key = read_session_key(c.connection(), selected)?;
            crate::session::proof(
                &key,
                (
                    &receipt.session_id,
                    &receipt.disclosure,
                    receipt.writer_epoch,
                ),
                &[0xaa; 32],
                &mutation,
            )?
        };
        self.commit_offline_prepared(
            peer,
            request,
            authentication,
            Some(proof),
            &[0xaa; 32],
            &"0".repeat(64),
            now,
        )
    }

    /// Create an ACTUAL encrypted v3-format synthetic journal so open_encrypted
    /// exercises its real migration path. Never invoke outside test builds.
    pub(crate) fn create_encrypted_legacy_v3_for_test(
        path: &Path,
        key: &DatabaseKey,
        policy: AccountPolicy,
    ) -> Result<Self> {
        policy.validate()?;
        let connection = wholepact_storage_security::create_encrypted(path, key)?;
        configure(connection.connection())?;
        let tx =
            Transaction::new_unchecked(connection.connection(), TransactionBehavior::Immediate)?;
        tx.execute_batch(LEGACY_SCHEMA)?;
        tx.execute(
            "INSERT INTO authority_genesis VALUES(1,?1)",
            [&*encode(&policy)?],
        )?;
        tx.execute("INSERT INTO authority_quarantine VALUES(1,0)", [])?;
        for peer in [
            &policy.owner_certificate_digest,
            &policy.initial_writer_certificate_digest,
        ] {
            tx.execute("INSERT INTO authority_principals VALUES(?1)", [peer])?;
        }
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", 3)?;
        tx.commit()?;
        Ok(Self {
            connection: Mutex::new(connection),
            resolution_node: Mutex::new(None),
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            born_owner: None,
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            born_manual_scope: None,
        })
    }
}

#[cfg(test)]
impl AuthorityJournal {
    pub(crate) fn offline_controller_proof_for_test(
        &self,
        peer: &str,
        request: &crate::offline::ReserveOfflineAuthorization,
        authentication: &AuthenticatedOfflineIntent,
    ) -> Result<OfflineControllerProofInput> {
        let record = OfflineReservationRecord {
            request: request.clone(),
            authentication: authentication.evidence().clone(),
        };
        let mutation = AuthorityMutation::ReserveOfflineAuthorization(Box::new(record));
        let proof = {
            let c = self
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let ledger = load(c.connection())?;
            ledger.require_delivery_admission_only_v2(&mutation)?;
            if ledger.snapshot.writer_certificate_digest != peer {
                return Err(AuthorityError::Permission);
            }
            let selected = ledger
                .historical_session(&request.operation_id)
                .or_else(|| {
                    ledger
                        .snapshot
                        .active_writer_session
                        .as_ref()
                        .map(|s| s.session_id.as_str())
                })
                .ok_or(AuthorityError::SessionRequired)?;
            let receipt = ledger
                .sessions
                .get(selected)
                .ok_or(AuthorityError::SessionRequired)?;
            let key = read_session_key(c.connection(), selected)?;
            crate::session::proof(
                &key,
                (
                    &receipt.session_id,
                    &receipt.disclosure,
                    receipt.writer_epoch,
                ),
                &[0xaa; 32],
                &mutation,
            )?
        };
        Ok(OfflineControllerProofInput {
            schema_version: 1,
            session_id: proof.session_id,
            tag: proof.tag,
        })
    }
}

#[cfg(test)]
mod offline_schema_tests {
    use super::*;
    #[test]
    fn staged_schema_upgrade_is_atomic_and_preserves_legacy_objects() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(LEGACY_SCHEMA).unwrap();
        c.pragma_update(None, "user_version", 3).unwrap();
        verify_schema_against(&c, LEGACY_SCHEMA).unwrap();
        {
            let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
            tx.execute_batch(crate::offline_retry::OFFLINE_RETRY_SCHEMA)
                .unwrap();
            tx.execute_batch(crate::offline_outcome::OFFLINE_OUTCOME_SCHEMA)
                .unwrap();
            tx.pragma_update(None, "user_version", 4).unwrap();
            verify_schema_against(&tx, SCHEMA_V4).unwrap();
            // Deliberately roll back the whole schema change.
        }
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
        verify_schema_against(&c, LEGACY_SCHEMA).unwrap();
        let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
        tx.execute_batch(crate::offline_retry::OFFLINE_RETRY_SCHEMA)
            .unwrap();
        tx.execute_batch(crate::offline_outcome::OFFLINE_OUTCOME_SCHEMA)
            .unwrap();
        tx.pragma_update(None, "user_version", 4).unwrap();
        verify_schema_against(&tx, SCHEMA_V4).unwrap();
        tx.commit().unwrap();
        verify_schema_against(&c, SCHEMA_V4).unwrap();
    }
    #[test]
    fn staged_schema_rejects_unexpected_objects() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(SCHEMA).unwrap();
        c.pragma_update(None, "user_version", SCHEMA_VERSION)
            .unwrap();
        verify_schema(&c).unwrap();
        c.execute_batch("CREATE TABLE unrelated_state(value BLOB)")
            .unwrap();
        assert!(matches!(
            verify_schema(&c),
            Err(AuthorityError::CorruptHistory)
        ));
    }
}

#[cfg(test)]
mod schema_name_filter_tests {
    use super::*;
    #[test]
    fn sqlite_prefix_user_objects_are_not_treated_as_internal_schema() {
        for sql in [
            "CREATE TABLE sqliteXextra(value TEXT)",
            "CREATE TRIGGER sqliteXextra AFTER INSERT ON authority_events BEGIN SELECT 1; END",
        ] {
            let c = Connection::open_in_memory().unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.pragma_update(None, "user_version", SCHEMA_VERSION)
                .unwrap();
            verify_schema(&c).unwrap();
            c.execute_batch(sql).unwrap();
            assert!(matches!(
                verify_schema(&c),
                Err(AuthorityError::CorruptHistory)
            ));
        }
    }
    #[test]
    fn legitimate_sqlite_statistics_and_autoindexes_remain_supported() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(SCHEMA).unwrap();
        c.pragma_update(None, "user_version", SCHEMA_VERSION)
            .unwrap();
        c.execute_batch("ANALYZE;").unwrap();
        let stats: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='sqlite_stat1')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stats);
        verify_schema(&c).unwrap();
    }
}

#[cfg(test)]
#[path = "manual_enrollment_encrypted_tests.rs"]
mod manual_enrollment_encrypted_tests;

#[cfg(test)]
#[path = "manual_session_continuation_encrypted_tests.rs"]
mod manual_session_continuation_encrypted_tests;

#[cfg(test)]
#[path = "manual_roster_construction_encrypted_tests_v2.rs"]
mod manual_roster_construction_encrypted_tests_v2;

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
#[path = "manual_roster_construction_encrypted_tests_v3.rs"]
mod manual_roster_construction_encrypted_tests_v3;

#[cfg(test)]
#[path = "durable_payment_encrypted_tests_v1.rs"]
mod durable_payment_encrypted_tests_v1;
