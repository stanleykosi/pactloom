//! One exact coordinated financial-continuation append, with an unlocked FinalAdmit gap.
//!
//! Private leaf reachable only through the concrete genuine-origin adapter. No
//! public source/permit constructor, callback, bool adapter or legacy lease lives here.
use super::*;
use crate::native_witness_owner::coordinated_financial_continuation_v1::{
    observation::Stage, AuthenticatedOriginalOwnerPeerV1, CoordinatedFinancialContinuationSourceV1,
    FinancialContinuationFinalV1, FinancialContinuationWaitBoundsV1,
};
use std::sync::Arc;
use wholepact_storage_security::DatabaseFileIdentity;

/// A pin of this same SQLite handle, not independent rollback protection.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
struct RevisionV1 {
    application_id: i64,
    data_version: i64,
    total_changes: i64,
    schema_version: i64,
    user_version: i64,
}
impl RevisionV1 {
    fn read(c: &Connection) -> Result<Self> {
        Ok(Self {
            application_id: c.pragma_query_value(None, "application_id", |r| r.get(0))?,
            data_version: c.pragma_query_value(None, "data_version", |r| r.get(0))?,
            total_changes: c.query_row("SELECT total_changes()", [], |r| r.get(0))?,
            schema_version: c.pragma_query_value(None, "schema_version", |r| r.get(0))?,
            user_version: c.pragma_query_value(None, "user_version", |r| r.get(0))?,
        })
    }
}

/// Not Clone/Debug/serde and no public constructor. Owns no lock, transaction or
/// borrowed ledger. The actual original namespace lifetime remains retained.
pub(crate) struct PreparedFinancialContinuationAppendV1 {
    journal: Arc<AuthorityJournal>,
    owner: Arc<crate::witness_locator::BornJournalOwner>,
    file: DatabaseFileIdentity,
    revision: RevisionV1,
    stamp: NamespaceJournalStamp,
    policy: AccountPolicy,
    event: Event,
    peer: AuthenticatedOriginalOwnerPeerV1,
    effect_commitment: String,
    bounds: FinancialContinuationWaitBoundsV1,
    ready: wholepact_financial_coordinator_origin::FinancialWitnessReadyV1,
}
impl PreparedFinancialContinuationAppendV1 {
    /// Inert correlation only. Only the actual original C channel can issue a
    /// matching final-admit token; this digest cannot be passed as permission.
    pub(crate) fn effect_commitment(&self) -> &str {
        &self.effect_commitment
    }
    pub(crate) fn ready_data(
        &self,
    ) -> wholepact_financial_coordinator_origin::FinancialWitnessReadyV1 {
        self.ready.clone()
    }
    pub(crate) fn original_tls_deadline(&self) -> std::time::Instant {
        self.peer.original_deadline()
    }
    pub(crate) fn check_while_waiting(&self) -> Result<()> {
        self.bounds.check_unadmitted()?;
        self.peer.check_original_bounds()
    }
}

impl AuthorityJournal {
    /// First lexical phase. The transport must release its OUTER source guard
    /// after return, before offering Ready or waiting on the original C edge.
    pub(crate) fn prepare_coordinated_financial_continuation_v1(
        &self,
        source: &mut CoordinatedFinancialContinuationSourceV1,
        peer: AuthenticatedOriginalOwnerPeerV1,
        request: OwnerControlRequest,
    ) -> Result<PreparedFinancialContinuationAppendV1> {
        source.begin_exact_preflight()?; // consumes the sole request attempt
        let prepared = (|| {
            source.check_before_publication()?;
            peer.check_original_bounds()?;
            let journal = source.journal();
            if !std::ptr::eq(Arc::as_ptr(&journal), self) {
                return Err(AuthorityError::Authentication);
            }
            let owner = self
                .born_owner
                .as_ref()
                .ok_or(AuthorityError::Permission)?
                .clone();
            source.check_original_owner_preflight(&owner)?;
            let c = self
                .connection
                .try_lock()
                .map_err(|_| AuthorityError::Permission)?;
            source.check_before_publication()?;
            peer.check_original_bounds()?;
            require_connection_mode(c.connection())?;
            let file = c.database_identity()?;
            file.check_current(c.connection())?;
            source.check_before_publication()?;
            peer.check_original_bounds()?;
            let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
            let checked = (|| {
                source.check_before_publication()?;
                peer.check_original_bounds()?;
                authenticate_admission(&tx, peer.certificate_digest())?;
                source.check_before_publication()?;
                peer.check_original_bounds()?;
                let ledger = load(&tx)?;
                let now = now_ms()?;
                source.require_exact_locked(self, &ledger, &peer, &request, now)?;
                source.check_before_publication()?;
                peer.check_original_bounds()?;
                let (stamp, birth) = namespace_account_stamp(&tx, &ledger.policy)?;
                owner.require_original_account_connection(&c, &birth)?;
                source.require_source_commitment(&crate::native_witness_owner::coordinated_financial_continuation_v1::source_commitment(
                    &file, &stamp, &ledger.policy,
                )?)?;
                file.check_current(c.connection())?;
                let event = Event {
                    mutation: AuthorityMutation::OwnerControl(request),
                    authenticated_certificate_digest: peer.certificate_digest().into(),
                    witness_time_ms: now,
                    writer_session_id: None,
                    original_request_link: None,
                };
                ledger.authenticate_mutation(&event)?;
                if ledger.replay(&event)?.is_some() {
                    return Err(AuthorityError::Uncertain);
                }
                source.check_before_publication()?;
                peer.check_original_bounds()?;
                let revision = RevisionV1::read(&tx)?;
                let effect_commitment = digest(
                    "wholepact:coordinated-financial-continuation-exact-append:v1",
                    &(
                        source.original_presentation_digest(),
                        &event,
                        &ledger.policy,
                        &stamp,
                        &revision,
                        file.origin_commitment(),
                        peer.original_stream_commitment(),
                        source.original_review_bounds(),
                        peer.original_accept_bounds(),
                    ),
                )?;
                source.check_before_publication()?;
                peer.check_original_bounds()?;
                Ok((
                    stamp,
                    ledger.policy.clone(),
                    event,
                    revision,
                    effect_commitment,
                ))
            })();
            // Explicit rollback, even for a read-only preflight. Never rely on
            // Drop's ignored rollback result before releasing a Ready ticket.
            if let Err(error) = checked.as_ref() {
                source.observe_failure(Stage::FirstPreflight, *error);
            }
            tx.rollback().map_err(|_| {
                source.observe_failure(Stage::PreflightRollback, AuthorityError::Uncertain);
                AuthorityError::Uncertain
            })?;
            if !c.connection().is_autocommit() {
                return Err(AuthorityError::Uncertain);
            }
            let (stamp, policy, event, revision, effect_commitment) = checked?;
            source.check_before_publication()?;
            peer.check_original_bounds()?;
            if RevisionV1::read(c.connection())? != revision {
                return Err(AuthorityError::Conflict);
            }
            file.check_current(c.connection())?;
            source.check_before_publication()?;
            peer.check_original_bounds()?;
            drop(c); // all transaction/connection/registry guards end before Ready
            source.retain_preflight_commitment(&effect_commitment)?;
            let ready = source.ready_for_exact_effect(&effect_commitment, &peer)?;
            Ok(PreparedFinancialContinuationAppendV1 {
                journal,
                owner,
                file,
                revision,
                stamp,
                policy,
                event,
                peer,
                effect_commitment,
                bounds: source.retained_wait_bounds(),
                ready,
            })
        })();
        if let Err(error) = prepared.as_ref() {
            source.observe_failure(Stage::FirstPreflight, *error);
            source.record_no_effect(*error);
        }
        prepared
    }

    /// Second lexical phase. FinalAdmit has ALREADY been authenticated while no
    /// source/journal/registry guard was held. This call performs no IPC and
    /// accepts neither a generic closure nor a caller-supplied approval claim.
    pub(crate) fn commit_coordinated_financial_continuation_v1(
        &self,
        source: &mut CoordinatedFinancialContinuationSourceV1,
        ticket: PreparedFinancialContinuationAppendV1,
        grant: FinancialContinuationFinalV1,
    ) -> Result<MutationResult> {
        source.begin_exact_commit(&ticket.effect_commitment, &grant)?;
        let mut commit_attempted = false;
        let mut observed_stage = Stage::SecondPreflight;
        let committed = (|| {
            source.check_before_publication()?;
            ticket.peer.check_original_bounds()?;
            grant
                .check_original_coordinator_alive()
                .map_err(|_| AuthorityError::Permission)?; // zero-wait lifetime check, no receive
            if !std::ptr::eq(Arc::as_ptr(&ticket.journal), self)
                || !Arc::ptr_eq(
                    self.born_owner.as_ref().ok_or(AuthorityError::Permission)?,
                    &ticket.owner,
                )
            {
                return Err(AuthorityError::Authentication);
            }
            ticket.owner.check_setup_current(
                crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1::Final(
                    &grant,
                ),
                true,
            )?;
            let c = self
                .connection
                .try_lock()
                .map_err(|_| AuthorityError::Permission)?;
            grant
                .check_current()
                .map_err(|_| AuthorityError::Permission)?;
            ticket.peer.check_original_bounds()?;
            require_connection_mode(c.connection())?;
            ticket.file.check_current(c.connection())?;
            grant
                .check_current()
                .map_err(|_| AuthorityError::Permission)?;
            ticket.peer.check_original_bounds()?;
            let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
            let result_before_commit = (|| {
                grant
                    .check_current()
                    .map_err(|_| AuthorityError::Permission)?;
                ticket.peer.check_original_bounds()?;
                if RevisionV1::read(&tx)? != ticket.revision {
                    return Err(AuthorityError::Conflict);
                }
                let request = match &ticket.event.mutation {
                    AuthorityMutation::OwnerControl(request) => request,
                    _ => return Err(AuthorityError::Permission),
                };
                grant
                    .check_current()
                    .map_err(|_| AuthorityError::Permission)?;
                ticket.peer.check_original_bounds()?;
                authenticate_admission(&tx, ticket.peer.certificate_digest())?;
                grant
                    .check_current()
                    .map_err(|_| AuthorityError::Permission)?;
                ticket.peer.check_original_bounds()?;
                let mut ledger = load(&tx)?;
                let now = now_ms()?;
                if now < ticket.event.witness_time_ms || ledger.policy != ticket.policy {
                    return Err(AuthorityError::Conflict);
                }
                source.require_exact_locked(self, &ledger, &ticket.peer, request, now)?;
                grant
                    .check_current()
                    .map_err(|_| AuthorityError::Permission)?;
                ticket.peer.check_original_bounds()?;
                let (stamp, birth) = namespace_account_stamp(&tx, &ticket.policy)?;
                if stamp != ticket.stamp {
                    return Err(AuthorityError::Conflict);
                }
                ticket
                    .owner
                    .require_original_account_connection(&c, &birth)?;
                ticket.file.check_current(c.connection())?;
                ledger.authenticate_mutation(&ticket.event)?;
                if ledger.replay(&ticket.event)?.is_some() {
                    return Err(AuthorityError::Uncertain);
                }
                // Sole local P transition after the COMPLETE second preflight.
                // Consumes the real exact grant once; no old FinalPrimaryClick,
                // NativeWorkerLease or whole-request-chain Publishing authority.
                let publication = source.consume_final_admit_after_lock(
                    &ticket.effect_commitment,
                    &ticket.peer,
                    grant,
                )?;
                publication.check_original_bounds()?;
                let previous = ledger.snapshot.head.digest.clone();
                // The frozen first-preflight W timestamp is never refreshed.
                observed_stage = Stage::JournalAppend;
                let result = ledger.apply_financial_continuation_v1(&ticket.event)?;
                publication.check_original_bounds()?;
                ticket.peer.check_original_bounds()?;
                super::durable_financial_continuation_journal_v1::append_exact(&tx, &ledger, &ticket.event, &previous)?;
                observed_stage = Stage::FinalCurrentness;
                publication.check_original_owner(&ticket.owner)?;
                ticket.file.check_current(c.connection())?;
                publication.check_original_bounds()?;
                ticket.peer.check_original_bounds()?;
                let (final_stamp, final_birth) = namespace_account_stamp(&tx, &ticket.policy)?;
                ticket
                    .owner
                    .require_original_account_connection(&c, &final_birth)?;
                if final_stamp.head != ledger.snapshot.head || final_stamp.quarantined {
                    return Err(AuthorityError::CorruptHistory);
                }
                let final_now = now_ms()?;
                let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
                    return Err(AuthorityError::Permission);
                };
                if final_now < ticket.event.witness_time_ms {
                    return Err(AuthorityError::Expired);
                }
                record.terms.require_live(final_now)?;
                // Last checks AFTER all potentially blocking identity/registry/
                // replay work, immediately before E. This never waits for C.
                publication.check_original_bounds()?;
                ticket.peer.check_original_bounds()?;
                let MutationResult::Controlled(snapshot) = &result else {
                    return Err(AuthorityError::CorruptHistory);
                };
                if snapshot != &ledger.snapshot {
                    return Err(AuthorityError::CorruptHistory);
                }
                Ok((result, publication))
            })();
            let (result, publication) = match result_before_commit {
                Ok(value) => value,
                Err(error) => {
                    source.observe_failure(observed_stage, error);
                    // KnownNoEffect requires an actually successful rollback,
                    // not a destructor whose rollback error was ignored.
                    if tx.rollback().is_err() || !c.connection().is_autocommit() {
                        source.observe_failure(Stage::CommitRollback, AuthorityError::Uncertain);
                        source.record_uncertain();
                        return Err(AuthorityError::Uncertain);
                    }
                    return Err(error);
                }
            };
            // No mutex/IPC operation or new timeout budget can enter this gap.
            if let Err(error) = publication
                .check_original_bounds()
                .and_then(|_| ticket.peer.check_original_bounds())
            {
                source.observe_failure(Stage::FinalCurrentness, error);
                if tx.rollback().is_err() || !c.connection().is_autocommit() {
                    source.observe_failure(Stage::CommitRollback, AuthorityError::Uncertain);
                    source.record_uncertain();
                    return Err(AuthorityError::Uncertain);
                }
                return Err(error);
            }
            if let Err(error) = source.record_commit_attempt() {
                source.observe_failure(Stage::JournalCommit, error);
                if tx.rollback().is_err() || !c.connection().is_autocommit() {
                    source.record_uncertain();
                }
                return Err(error); // fail closed: E was never entered
            }
            commit_attempted = true;
            tx.commit().map_err(|_| {
                source.observe_failure(Stage::JournalCommit, AuthorityError::Uncertain);
                AuthorityError::Uncertain
            })?;
            let MutationResult::Controlled(snapshot) = &result else {
                return Err(AuthorityError::Uncertain);
            };
            source.record_committed(snapshot.clone())?;
            // c/namespace work is dropped by this lexical return BEFORE any
            // terminal coordinator message or response on the retained TLS stream.
            Ok(result)
        })();
        if let Err(error) = committed.as_ref() {
            source.observe_failure(observed_stage, *error);
            if commit_attempted {
                source.record_uncertain();
            } else {
                source.record_no_effect(*error);
            }
        }
        committed
    }
}

fn require_connection_mode(c: &Connection) -> Result<()> {
    if !c.is_autocommit()
        || c.pragma_query_value::<i64, _>(None, "synchronous", |r| r.get(0))? != 2
        || c.pragma_query_value::<i64, _>(None, "foreign_keys", |r| r.get(0))? != 1
    {
        return Err(AuthorityError::Storage);
    }
    Ok(())
}
