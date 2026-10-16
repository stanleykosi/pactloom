//! Concrete read-only chain observation adapter for the bounded operator.
//! It never submits a transaction or clears authorization exposure.
use crate::operator::{OperatorTask, TaskFailure, TaskFuture, TaskKind};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use wholepact_chain::{
    BackendIdentity, ChainAdapter, ConfirmationPolicy, EncryptedSubmissionJournal,
    SubmissionDescriptor,
};

use wholepact_chain::settlement_evidence::{
    RetainedSettlementObservation, SourceBoundSettlementObservation,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationScope {
    pub profile_id: String,
    pub journal_identity: String,
    pub transaction: SubmissionDescriptor,
    pub sources: Vec<BackendIdentity>,
    pub policy: ConfirmationPolicy,
}
/// Native authority explicitly approves transaction-linkage disclosure to these
/// exact providers and local observation retention. Held across network calls and
/// journal commit; no browser JSON approval is accepted.
pub trait ObservationLease: Send + Sync {
    fn scope(&self) -> &ObservationScope;
    fn check_current(&self, now_unix_seconds: u64) -> Result<(), TaskFailure>;
}
pub trait ObservationAuthority: Send + Sync {
    fn acquire(
        &self,
        scope: &ObservationScope,
        now_unix_seconds: u64,
    ) -> Result<Box<dyn ObservationLease + '_>, TaskFailure>;
}
/// Native sink implementation must enforce its own exact store/account leases.
/// Identity is persisted by the destination, never supplied by browser requests.
pub trait SettlementObservationSink: Send + Sync {
    fn destination(&self) -> &str;
    fn apply(&self, evidence: &RetainedSettlementObservation) -> Result<(), TaskFailure>;
}
pub struct EngineSettlementSink {
    engine: wholepact_engine::Engine,
    scope: wholepact_engine::settlement_fanout::SettlementSinkScope,
    authority: Arc<dyn wholepact_engine::settlement_fanout::SettlementSinkAuthority>,
}
impl EngineSettlementSink {
    pub fn new(
        engine: wholepact_engine::Engine,
        journal_identity: &str,
        transaction: &SubmissionDescriptor,
        authority: Arc<dyn wholepact_engine::settlement_fanout::SettlementSinkAuthority>,
    ) -> Result<Self, TaskFailure> {
        let scope = engine
            .settlement_sink_scope(journal_identity, transaction)
            .map_err(|_| TaskFailure::RecoveryRequired)?;
        Ok(Self {
            engine,
            scope,
            authority,
        })
    }
}
impl SettlementObservationSink for EngineSettlementSink {
    fn destination(&self) -> &str {
        &self.scope.destination
    }
    fn apply(&self, evidence: &RetainedSettlementObservation) -> Result<(), TaskFailure> {
        self.engine
            .apply_settlement_observation(&self.scope, evidence, &*self.authority)
            .map_err(|_| TaskFailure::RecoveryRequired)
    }
}
pub struct ChainObservationTask {
    scope: ObservationScope,
    sources: Vec<ChainAdapter>,
    journal: Arc<Mutex<EncryptedSubmissionJournal>>,
    authority: Arc<dyn ObservationAuthority>,
    sinks: Vec<Arc<dyn SettlementObservationSink>>,
}
impl ChainObservationTask {
    pub fn new(
        profile_id: String,
        operation_id: &str,
        policy: ConfirmationPolicy,
        sources: Vec<ChainAdapter>,
        journal: Arc<Mutex<EncryptedSubmissionJournal>>,
        authority: Arc<dyn ObservationAuthority>,
    ) -> Result<Self, TaskFailure> {
        if profile_id.is_empty()
            || profile_id.len() > 128
            || sources.is_empty()
            || sources.len() > 8
        {
            return Err(TaskFailure::RecoveryRequired);
        }
        let ids: Vec<_> = sources
            .iter()
            .map(|s| s.identity().source_id.clone())
            .collect();
        let mut actual = ids.clone();
        actual.sort();
        actual.dedup();
        let mut expected = policy.sources().to_vec();
        expected.sort();
        if actual.len() != ids.len() || actual != expected {
            return Err(TaskFailure::RecoveryRequired);
        }
        let (journal_identity, transaction) = {
            let guard = journal.lock().map_err(|_| TaskFailure::RecoveryRequired)?;
            let descriptor = guard
                .retained_submission_descriptor(operation_id)
                .map_err(|_| TaskFailure::RecoveryRequired)?
                .ok_or(TaskFailure::RecoveryRequired)?;
            (guard.identity().to_owned(), descriptor)
        };
        let scope = ObservationScope {
            profile_id,
            journal_identity,
            transaction,
            sources: sources.iter().map(|s| s.identity().clone()).collect(),
            policy,
        };
        Ok(Self {
            scope,
            sources,
            journal,
            authority,
            sinks: Vec::new(),
        })
    }
    fn verify_journal(&self, journal: &EncryptedSubmissionJournal) -> Result<(), TaskFailure> {
        if journal.identity() != self.scope.journal_identity
            || journal
                .retained_submission_descriptor(&self.scope.transaction.operation_id)
                .map_err(|_| TaskFailure::RecoveryRequired)?
                .as_ref()
                != Some(&self.scope.transaction)
        {
            return Err(TaskFailure::RecoveryRequired);
        }
        Ok(())
    }
    /// Required before execution; silently retaining display confidence without
    /// updating enrolled authority stores would leave stale replacement authority.
    pub fn with_sinks(
        mut self,
        sinks: Vec<Arc<dyn SettlementObservationSink>>,
    ) -> Result<Self, TaskFailure> {
        let ids: std::collections::BTreeSet<_> = sinks.iter().map(|s| s.destination()).collect();
        if sinks.is_empty() || sinks.len() > 32 || ids.len() != sinks.len() {
            return Err(TaskFailure::RecoveryRequired);
        }
        self.sinks = sinks;
        Ok(self)
    }
    fn replay(&self, lease: &dyn ObservationLease) -> Result<(), TaskFailure> {
        for sink in &self.sinks {
            loop {
                lease.check_current(now()?)?;
                let pending = {
                    let journal = self
                        .journal
                        .lock()
                        .map_err(|_| TaskFailure::RecoveryRequired)?;
                    self.verify_journal(&journal)?;
                    journal
                        .pending_settlement_deliveries(sink.destination())
                        .map_err(|_| TaskFailure::RecoveryRequired)?
                };
                if pending.is_empty() {
                    break;
                }
                for evidence in pending {
                    lease.check_current(now()?)?;
                    // Other operations sharing this destination need their own
                    // exact runtime binding; leave them pending for that task.
                    if evidence.descriptor() != &self.scope.transaction
                        || !evidence.matches_sources(&self.scope.sources, &self.scope.policy)
                    {
                        return Err(TaskFailure::RecoveryRequired);
                    }
                    sink.apply(&evidence)?;
                    lease.check_current(now()?)?;
                    let mut journal = self
                        .journal
                        .lock()
                        .map_err(|_| TaskFailure::RecoveryRequired)?;
                    self.verify_journal(&journal)?;
                    journal
                        .acknowledge_settlement_delivery(evidence.evidence_id(), sink.destination())
                        .map_err(|_| TaskFailure::RecoveryRequired)?;
                }
            }
        }
        Ok(())
    }
    async fn observe(&self) -> Result<(), TaskFailure> {
        if self.sinks.is_empty() {
            return Err(TaskFailure::RecoveryRequired);
        }
        let lease = self.authority.acquire(&self.scope, now()?)?;
        if lease.scope() != &self.scope {
            return Err(TaskFailure::PermissionLost);
        }
        lease.check_current(now()?)?;
        self.replay(&*lease)?;
        let previous = {
            let journal = self
                .journal
                .lock()
                .map_err(|_| TaskFailure::RecoveryRequired)?;
            self.verify_journal(&journal)?;
            journal
                .recover_reconciler(&self.scope.transaction.operation_id)
                .map_err(|_| TaskFailure::RecoveryRequired)?
                .and_then(|r| r.last_report().cloned())
        };
        let evidence = SourceBoundSettlementObservation::observe(
            self.scope.transaction.clone(),
            self.scope.policy.clone(),
            &self.sources,
            previous,
        )
        .await
        .map_err(|_| TaskFailure::RecoveryRequired)?;
        lease.check_current(now()?)?;
        {
            let mut journal = self
                .journal
                .lock()
                .map_err(|_| TaskFailure::RecoveryRequired)?;
            self.verify_journal(&journal)?;
            lease.check_current(now()?)?;
            journal
                .retain_settlement_observation(
                    evidence,
                    &self
                        .sinks
                        .iter()
                        .map(|s| s.destination().to_owned())
                        .collect::<Vec<_>>(),
                )
                .map_err(|_| TaskFailure::RecoveryRequired)?;
        }
        self.replay(&*lease)
    }
}
impl OperatorTask for ChainObservationTask {
    fn kind(&self) -> TaskKind {
        TaskKind::ChainObservation
    }
    fn tick(&self) -> TaskFuture<'_> {
        Box::pin(self.observe())
    }
}
fn now() -> Result<u64, TaskFailure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| TaskFailure::RecoveryRequired)
}
