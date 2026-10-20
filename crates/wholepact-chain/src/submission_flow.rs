//! Opt-in exact-byte dispatch orchestration. No default authority, automatic retry,
//! replacement, or service endpoint is provided. Injected adapters are trusted code.
use crate::{
    BackendIdentity, ChainAdapter, ChainContext, ChainError, EncryptedSubmissionJournal,
    ExactSubmissionIntent, SubmissionState,
};
use serde::{Deserialize, Serialize};
use std::{future::Future, io::Cursor, pin::Pin, time::Duration};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;
use zeroize::Zeroizing;

pub type SubmissionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubmissionDescriptor {
    pub operation_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub transaction_id: String,
    pub bytes_sha256: String,
    pub expiry_height: u32,
    pub network: String,
    pub consensus_branch_id: u32,
}
/// Bounded canonical wire parsing establishes identity and profile, not cryptographic
/// validity, input availability, consent, or authority. The trusted gate must check these.
pub struct SubmissionPlan {
    pub(crate) intent: ExactSubmissionIntent,
    pub(crate) descriptor: SubmissionDescriptor,
}
impl SubmissionPlan {
    pub fn new(
        obligation_id: &str,
        proposal_id: &str,
        operation_id: &str,
        bytes: &[u8],
    ) -> Result<Self, ChainError> {
        crate::submission::validate_operation_id(obligation_id)?;
        crate::submission::validate_operation_id(proposal_id)?;
        let intent = ExactSubmissionIntent::new(operation_id, bytes)?;
        let mut cursor = Cursor::new(bytes);
        let tx = Transaction::read(&mut cursor, BranchId::Nu7)
            .map_err(|_| ChainError::MalformedEvidence)?;
        if cursor.position() != bytes.len() as u64 {
            return Err(ChainError::MalformedEvidence);
        }
        if tx.version() != TxVersion::V6
            || tx.consensus_branch_id() != BranchId::Nu7
            || tx.transparent_bundle().is_some()
            || tx.sprout_bundle().is_some()
            || tx.sapling_bundle().is_some()
            || tx.orchard_bundle().is_some()
        {
            return Err(ChainError::UnsupportedCapability);
        }
        let expiry_height = u32::from(tx.expiry_height());
        if expiry_height == 0 {
            return Err(ChainError::SubmissionExpiryMargin);
        }
        // Reject alternate encodings, even if maintained parsing computes the same txid.
        let mut canonical = Zeroizing::new(Vec::new());
        tx.write(&mut *canonical)
            .map_err(|_| ChainError::MalformedEvidence)?;
        if canonical.as_slice() != bytes {
            return Err(ChainError::MalformedEvidence);
        }
        let descriptor = SubmissionDescriptor {
            operation_id: operation_id.into(),
            obligation_id: obligation_id.into(),
            proposal_id: proposal_id.into(),
            transaction_id: tx.txid().to_string(),
            bytes_sha256: intent.bytes_sha256().into(),
            expiry_height,
            network: "testnet".into(),
            consensus_branch_id: crate::NU7_BRANCH_ID,
        };
        Ok(Self { intent, descriptor })
    }
    pub fn descriptor(&self) -> &SubmissionDescriptor {
        &self.descriptor
    }
}

/// The authority must verify the exact-byte digest and transaction identity against retained, independently approved
/// effects/signatures, consent to this backend, current writer/exposure continuity and
/// current qualified chain/input policy. Caller-supplied booleans do not establish this.
/// A permit should own the embedding's lock/lease across the entire awaited dispatch.
/// No production authority implementation is supplied by this crate.
pub trait SubmissionAuthority {
    type Permit: SubmissionPermit;
    fn authorize(&mut self, review: &SubmissionReview<'_>) -> Result<Self::Permit, ChainError>;
}
pub trait SubmissionPermit {
    /// Optional exact attempt number committed by a bounded original delegation.
    /// Compared inside the submission journal write transaction, not just before it.
    fn expected_attempt_number(&self) -> Option<u32> {
        None
    }
    /// Optional immutable INCLUSIVE wall-clock send ceiling. This is a
    /// restriction, never authority: the backend must enforce it after any
    /// asynchronous connection/readiness work and before sending bytes.
    /// A strict millisecond deadline must be rounded conservatively to
    /// `deadline_ms / 1000 - 1`, never rounded up. Legacy authorities without
    /// an additional absolute deadline retain the existing context bound.
    fn valid_until_unix_seconds(&self) -> Option<u64> {
        None
    }
    fn check_current(&mut self, review: &SubmissionReview<'_>) -> Result<(), ChainError>;
}
pub struct SubmissionReview<'a> {
    pub descriptor: &'a SubmissionDescriptor,
    pub journal_identity: &'a str,
    pub backend: &'a BackendIdentity,
    pub context: &'a ChainContext,
    pub now_unix_seconds: u64,
}
pub struct DenySubmissionAuthority;
pub struct DeniedSubmissionPermit;
impl SubmissionAuthority for DenySubmissionAuthority {
    type Permit = DeniedSubmissionPermit;
    fn authorize(&mut self, _: &SubmissionReview<'_>) -> Result<Self::Permit, ChainError> {
        Err(ChainError::SubmissionNotAuthorized)
    }
}
impl SubmissionPermit for DeniedSubmissionPermit {
    fn check_current(&mut self, _: &SubmissionReview<'_>) -> Result<(), ChainError> {
        Err(ChainError::SubmissionNotAuthorized)
    }
}

pub trait SubmissionClock {
    fn now_unix_seconds(&self) -> Result<u64, ChainError>;
}
pub struct SystemSubmissionClock;
impl SubmissionClock for SystemSubmissionClock {
    fn now_unix_seconds(&self) -> Result<u64, ChainError> {
        crate::now()
    }
}

/// Opaque, non-cloneable, single-dispatch token. Only the orchestrator can create one,
/// after authority/currentness checks and the durable exact intent and attempt commit.
pub struct PreparedDispatch<'a> {
    plan: &'a SubmissionPlan,
    backend: &'a BackendIdentity,
    valid_until_unix_seconds: u64,
}
impl PreparedDispatch<'_> {
    pub fn exact_bytes(&self) -> &[u8] {
        self.plan.intent.exact_bytes()
    }
    pub fn descriptor(&self) -> &SubmissionDescriptor {
        &self.plan.descriptor
    }
    pub fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
    }
    pub fn backend(&self) -> &BackendIdentity {
        self.backend
    }
}
pub trait SubmissionBackend {
    fn identity(&self) -> &BackendIdentity;
    fn fresh_context(&mut self) -> SubmissionFuture<'_, Result<ChainContext, ChainError>>;
    /// Implementations must make at most one attempt, recheck token TTL immediately
    /// before writing bytes, and never log bytes/server messages.
    fn submit_exact<'a>(
        &'a mut self,
        dispatch: PreparedDispatch<'a>,
    ) -> SubmissionFuture<'a, Result<BackendSubmissionResult, ChainError>>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendSubmissionResult {
    Acknowledged,
    Rejected { code: i32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubmissionAttemptOutcome {
    /// Includes a process crash or a cancelled future after the intent commit.
    Unknown,
    Acknowledged,
    Rejected {
        code: i32,
    },
    Indeterminate {
        reason: SubmissionFailure,
    },
    /// No dispatch occurred in this attempt; earlier delivery remains possible.
    BlockedBeforeDispatch,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubmissionFailure {
    Timeout,
    Interrupted,
    TransportUnavailable,
    ResourceLimit,
    MalformedEvidence,
    UnsupportedCapability,
    Backend { grpc_code: i32 },
    Other,
}
impl From<&ChainError> for SubmissionFailure {
    fn from(e: &ChainError) -> Self {
        match e {
            ChainError::Timeout => Self::Timeout,
            ChainError::ObservationInterrupted => Self::Interrupted,
            ChainError::TransportUnavailable => Self::TransportUnavailable,
            ChainError::ResourceLimit => Self::ResourceLimit,
            ChainError::MalformedEvidence | ChainError::ContradictoryChain => {
                Self::MalformedEvidence
            }
            ChainError::UnsupportedCapability => Self::UnsupportedCapability,
            ChainError::BackendFailure { grpc_code } => Self::Backend {
                grpc_code: *grpc_code,
            },
            _ => Self::Other,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubmissionAttempt {
    pub number: u32,
    pub source_id: String,
    pub started_at_unix_seconds: u64,
    pub outcome: SubmissionAttemptOutcome,
}
#[derive(Debug, Clone, Serialize)]
pub struct SubmissionDispatchReport {
    pub descriptor: SubmissionDescriptor,
    pub attempt: SubmissionAttempt,
    pub historical_provider_state: SubmissionState,
    pub clears_authorization_exposure: bool,
    pub permits_replacement: bool,
}
#[derive(Debug, Clone, Copy)]
pub struct SubmissionPolicy {
    pub minimum_expiry_margin_blocks: u32,
    pub dispatch_timeout: Duration,
}
impl Default for SubmissionPolicy {
    fn default() -> Self {
        Self {
            minimum_expiry_margin_blocks: 3,
            dispatch_timeout: Duration::from_secs(15),
        }
    }
}
impl SubmissionPolicy {
    fn validate(&self) -> Result<(), ChainError> {
        if !(1..=100).contains(&self.minimum_expiry_margin_blocks)
            || self.dispatch_timeout.is_zero()
            || self.dispatch_timeout > Duration::from_secs(30)
        {
            return Err(ChainError::InvalidConfiguration);
        }
        Ok(())
    }
}
fn check_current(
    plan: &SubmissionPlan,
    backend: &BackendIdentity,
    context: &ChainContext,
    now: u64,
    policy: SubmissionPolicy,
) -> Result<(), ChainError> {
    if backend != context.source() {
        return Err(ChainError::ContradictoryChain);
    }
    context.check_fresh_at(now)?;
    if context
        .tip()
        .height
        .checked_add(u64::from(policy.minimum_expiry_margin_blocks))
        .is_none_or(|height| height > u64::from(plan.descriptor.expiry_height))
    {
        return Err(ChainError::SubmissionExpiryMargin);
    }
    Ok(())
}

/// Retain a verified private transaction from a concrete protocol handoff without exposing
/// a raw-byte getter through the engine. The consent gate runs before persistence.
/// This is local retention only. Calling submit/retry later requires fresh authority.
pub fn retain_submission_plan<A: SubmissionAuthority, C: SubmissionClock>(
    journal: &mut EncryptedSubmissionJournal,
    plan: &SubmissionPlan,
    authority: &mut A,
    backend: &BackendIdentity,
    context: &ChainContext,
    clock: &C,
    policy: SubmissionPolicy,
) -> Result<SubmissionDescriptor, ChainError> {
    policy.validate()?;
    let now = clock.now_unix_seconds()?;
    check_current(plan, backend, context, now, policy)?;
    let journal_identity = journal.identity().to_owned();
    let review = SubmissionReview {
        descriptor: &plan.descriptor,
        journal_identity: &journal_identity,
        backend,
        context,
        now_unix_seconds: now,
    };
    let mut permit = authority.authorize(&review)?;
    // Authority work can consume the context lifetime. Destination and consent are
    // checked again immediately before and after the durable retention boundary.
    let current = clock.now_unix_seconds()?;
    check_current(plan, backend, context, current, policy)?;
    permit.check_current(&SubmissionReview {
        now_unix_seconds: current,
        ..review
    })?;
    journal.bind_submission_plan(plan)?;
    let current = clock
        .now_unix_seconds()
        .map_err(|_| ChainError::SubmissionRetentionUncertain)?;
    check_current(plan, backend, context, current, policy)
        .map_err(|_| ChainError::SubmissionRetentionUncertain)?;
    permit
        .check_current(&SubmissionReview {
            now_unix_seconds: current,
            ..review
        })
        .map_err(|_| ChainError::SubmissionRetentionUncertain)?;
    Ok(plan.descriptor.clone())
}

/// One explicit attempt; never creates a revision or retries automatically. Every error
/// after the durable boundary preserves possible delivery, including cancellation/drop.
pub async fn submit_plan<B: SubmissionBackend, A: SubmissionAuthority, C: SubmissionClock>(
    journal: &mut EncryptedSubmissionJournal,
    plan: &SubmissionPlan,
    backend: &mut B,
    authority: &mut A,
    clock: &C,
    policy: SubmissionPolicy,
) -> Result<SubmissionDispatchReport, ChainError> {
    policy.validate()?;
    let context = tokio::time::timeout(policy.dispatch_timeout, backend.fresh_context())
        .await
        .map_err(|_| ChainError::Timeout)??;
    let identity = backend.identity().clone();
    let now = clock.now_unix_seconds()?;
    check_current(plan, &identity, &context, now, policy)?;
    let journal_identity = journal.identity().to_owned();
    let review = SubmissionReview {
        descriptor: &plan.descriptor,
        journal_identity: &journal_identity,
        backend: &identity,
        context: &context,
        now_unix_seconds: now,
    };
    let mut permit = authority.authorize(&review)?;
    let authority_until = permit.valid_until_unix_seconds();
    let expected_attempt = permit.expected_attempt_number();
    let before_commit = clock.now_unix_seconds()?;
    if authority_until.is_some_and(|until| before_commit > until) {
        return Err(ChainError::SubmissionNotAuthorized);
    }
    check_current(plan, &identity, &context, before_commit, policy)?;
    permit.check_current(&SubmissionReview {
        now_unix_seconds: before_commit,
        ..review
    })?;
    journal.bind_submission_plan(plan)?;
    let mut attempt =
        journal.begin_submission_attempt(plan, &identity.source_id, now, expected_attempt)?;
    // Disk commit and gate work can consume the context lifetime. Recheck after both.
    let current = clock.now_unix_seconds().and_then(|now| {
        if authority_until.is_some_and(|until| now > until) {
            return Err(ChainError::SubmissionNotAuthorized);
        }
        check_current(plan, &identity, &context, now, policy)?;
        permit.check_current(&SubmissionReview {
            now_unix_seconds: now,
            ..review
        })
    });
    if let Err(error) = current {
        attempt.outcome = SubmissionAttemptOutcome::BlockedBeforeDispatch;
        journal
            .finish_submission_attempt(&plan.descriptor.operation_id, &attempt)
            .map_err(|_| ChainError::SubmissionOutcomeUnrecorded)?;
        return Err(error);
    }
    let dispatch = PreparedDispatch {
        plan,
        backend: &identity,
        valid_until_unix_seconds: authority_until
            .map_or(context.valid_until_unix_seconds(), |authority_until| {
                context.valid_until_unix_seconds().min(authority_until)
            }),
    };
    let result = tokio::time::timeout(policy.dispatch_timeout, backend.submit_exact(dispatch))
        .await
        .unwrap_or(Err(ChainError::Timeout));
    attempt.outcome = match result {
        Ok(BackendSubmissionResult::Acknowledged) => SubmissionAttemptOutcome::Acknowledged,
        Ok(BackendSubmissionResult::Rejected { code }) => {
            SubmissionAttemptOutcome::Rejected { code }
        }
        Err(error) => SubmissionAttemptOutcome::Indeterminate {
            reason: (&error).into(),
        },
    };
    let state = journal
        .finish_submission_attempt(&plan.descriptor.operation_id, &attempt)
        .map_err(|_| ChainError::SubmissionOutcomeUnrecorded)?;
    // Keep the authority lease alive until the result is durably recorded.
    drop(permit);
    Ok(SubmissionDispatchReport {
        descriptor: plan.descriptor.clone(),
        attempt,
        historical_provider_state: state,
        clears_authorization_exposure: false,
        permits_replacement: false,
    })
}

/// Recovery takes no new bytes. It reparses and dispatches exactly the retained intent.
pub async fn retry_retained_submission<
    B: SubmissionBackend,
    A: SubmissionAuthority,
    C: SubmissionClock,
>(
    journal: &mut EncryptedSubmissionJournal,
    operation_id: &str,
    backend: &mut B,
    authority: &mut A,
    clock: &C,
    policy: SubmissionPolicy,
) -> Result<SubmissionDispatchReport, ChainError> {
    let plan = journal
        .recover_submission_plan(operation_id)?
        .ok_or(ChainError::JournalFailure)?;
    submit_plan(journal, &plan, backend, authority, clock, policy).await
}

/// Concrete pinned lightwallet-protocol sender. Construction performs no I/O. Only an
/// orchestrator-issued PreparedDispatch can invoke SendTransaction. Default capability
/// discovery remains disabled; integrating this requires a qualified authority adapter.
pub struct LightwalletSubmissionBackend {
    adapter: ChainAdapter,
}
impl LightwalletSubmissionBackend {
    pub fn new(adapter: ChainAdapter) -> Self {
        Self { adapter }
    }
}
impl SubmissionBackend for LightwalletSubmissionBackend {
    fn identity(&self) -> &BackendIdentity {
        self.adapter.identity()
    }
    fn fresh_context(&mut self) -> SubmissionFuture<'_, Result<ChainContext, ChainError>> {
        Box::pin(self.adapter.context())
    }
    fn submit_exact<'a>(
        &'a mut self,
        dispatch: PreparedDispatch<'a>,
    ) -> SubmissionFuture<'a, Result<BackendSubmissionResult, ChainError>> {
        Box::pin(async move {
            if dispatch.backend() != self.adapter.identity() {
                return Err(ChainError::ContradictoryChain);
            }
            self.adapter
                .rpc
                .submit_once(dispatch.exact_bytes(), dispatch.valid_until_unix_seconds())
                .await
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "submission_flow_tests.rs"]
mod tests;
