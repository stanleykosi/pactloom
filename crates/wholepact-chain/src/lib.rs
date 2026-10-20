//! Read-only, explicitly single-provider testnet observations. Never signing authority.
//! Default adapters are read-only. Opt-in submission requires a durable journal and
//! an explicit trusted authority adapter; no live financial capability is qualified.

pub mod backup;
#[cfg(feature = "submission-dispatch")]
pub mod local_node;
pub mod public_read_profile_v1;
mod proxy;
mod connect_driver;
#[cfg(test)]
mod connect_driver_tests;
mod reconciliation;
mod rpc;
#[cfg(feature = "submission-dispatch")]
pub mod settlement_evidence;
mod submission;
#[cfg(feature = "submission-dispatch")]
mod submission_flow;
mod sync_transport;
mod wire_guard;
mod transport_diagnostics;
#[cfg(feature = "synthetic-qualification")]
pub use transport_diagnostics::{TransportDiagnostics, TransportDiagnosticSnapshot};

pub use reconciliation::*;
#[cfg(feature = "submission-dispatch")]
pub use submission_flow::*;
pub use sync_transport::PublicSyncChannel;

pub use submission::{
    EncryptedSubmissionJournal, ExactSubmissionIntent, SubmissionIntentSummary, SubmissionJournal,
    SubmissionState,
};

use serde::{Deserialize, Serialize};
use std::{
    io::Cursor,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zcash_protocol::{TxId, consensus::BranchId};

pub const SCHEMA_COMMIT: &str = "12b892541bbf14d8e485a13e63ccfac85382fc21";
pub const NU7_BRANCH_ID: u32 = 0x77190ad9;
pub const NU7_ACTIVATION_HEIGHT: u64 = 4_465_026;

#[derive(Debug, Clone, Copy)]
pub struct NetworkPolicy {
    pub request_timeout: Duration,
    pub retries: u8,
    pub retry_delay: Duration,
    pub maximum_response_bytes: usize,
    pub observation_ttl: Duration,
    pub maximum_tip_age: Duration,
    pub maximum_clock_skew: Duration,
    pub maximum_reported_height_gap: u64,
}
impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            retries: 1,
            retry_delay: Duration::from_millis(250),
            maximum_response_bytes: 4 * 1024 * 1024,
            observation_ttl: Duration::from_secs(60),
            maximum_tip_age: Duration::from_secs(1200),
            maximum_clock_skew: Duration::from_secs(30),
            maximum_reported_height_gap: 2,
        }
    }
}
impl NetworkPolicy {
    fn validate(&self) -> Result<(), ChainError> {
        if self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(30)
            || self.retries > 2
            || self.retry_delay > Duration::from_secs(2)
            || !(1024..=8 * 1024 * 1024).contains(&self.maximum_response_bytes)
            || self.observation_ttl.is_zero()
            || self.observation_ttl > Duration::from_secs(300)
            || self.maximum_tip_age.is_zero()
            || self.maximum_tip_age > Duration::from_secs(1800)
            || self.maximum_clock_skew > Duration::from_secs(60)
            || self.maximum_reported_height_gap > 3
        {
            Err(ChainError::InvalidConfiguration)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainError {
    #[error("invalid bounded testnet backend configuration")]
    InvalidConfiguration,
    #[error("mainnet or a mismatching chain is disabled")]
    WrongNetwork,
    #[error(
        "configured proxy is unsupported or requires credentials; no direct fallback attempted"
    )]
    UnsupportedProxyConfiguration,
    #[error("backend does not report the qualified NU7 branch")]
    WrongBranch,
    #[error("backend context is stale or insufficiently synchronized")]
    StaleChain,
    #[error("backend observations contradict each other; retain exposure")]
    ContradictoryChain,
    #[error("network observation timed out; outcome remains unknown")]
    Timeout,
    #[error("backend unavailable; outcome remains unknown")]
    TransportUnavailable,
    #[error("backend cancelled or interrupted this observation; outcome remains unknown")]
    ObservationInterrupted,
    #[error("different reported tip heights require additional ancestry evidence")]
    MissingAncestryEvidence,
    #[error("backend did not observe the item; this is not absence proof")]
    NotObserved,
    #[error("backend observation exceeds a configured resource limit")]
    ResourceLimit,
    #[error("backend returned malformed or unsupported evidence")]
    MalformedEvidence,
    #[error("backend does not support the requested observation")]
    UnsupportedCapability,
    #[error("backend RPC failed with status {grpc_code}")]
    BackendFailure { grpc_code: i32 },
    #[error("local clock is unavailable")]
    ClockUnavailable,
    #[error("the same operation id names different exact transaction bytes")]
    IdempotencyConflict,
    #[error("durable submission intent could not be recorded")]
    JournalFailure,
    #[error("exact submission authority or consent is missing or revoked")]
    SubmissionNotAuthorized,
    #[error("transaction has reached the conservative submission expiry margin")]
    SubmissionExpiryMargin,
    #[error("another exact submission already occupies this logical obligation")]
    ObligationConflict,
    #[error("submission result was not durably recorded; delivery remains possible")]
    SubmissionOutcomeUnrecorded,
    #[error("submission intent may be retained; reconcile the original operation before retrying")]
    SubmissionRetentionUncertain,
}

/// Provider and trust descriptions are never consensus proofs.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BackendIdentity {
    pub source_id: String,
    pub endpoint: String,
    pub trust_profile: &'static str,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockIdentity {
    pub height: u64,
    /// Display byte order, as used by zcashd RPC (reverse of protocol bytes).
    pub hash: String,
}
/// Only selected, normalized response metadata is retained. No arbitrary headers.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheStatus {
    Hit,
    Miss,
    NotReported,
    OtherReported,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RpcCacheObservation {
    pub method: &'static str,
    pub cache_status: CacheStatus,
    pub reported_age_seconds: Option<u64>,
    pub malformed_age: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct ChainContext {
    source: BackendIdentity,
    network: &'static str,
    genesis_identity_verified: bool,
    observed_at_unix_seconds: u64,
    request_started_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    tip: BlockIdentity,
    tip_mined_at_unix_seconds: u64,
    branch_id: String,
    reported_height: u64,
    estimated_height: u64,
    synchronized_by_provider_heuristic: bool,
    independently_consensus_verified: bool,
    lightwalletd_version: String,
    backend_subversion: String,
    protocol_version: String,
    provider_refresh_time_verified: bool,
    rpc_cache_observations: Vec<RpcCacheObservation>,
}
impl ChainContext {
    pub fn source(&self) -> &BackendIdentity {
        &self.source
    }
    /// Immutable provider-reported profile facts. These do not authenticate the
    /// provider's implementation or independently establish consensus validity.
    pub fn network(&self) -> &str {
        self.network
    }
    pub fn branch_id(&self) -> &str {
        &self.branch_id
    }
    pub fn lightwalletd_version(&self) -> &str {
        &self.lightwalletd_version
    }
    pub fn backend_subversion(&self) -> &str {
        &self.backend_subversion
    }
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }
    pub fn tip(&self) -> &BlockIdentity {
        &self.tip
    }
    pub fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }
    /// Earliest local request clock, not a claim about provider refresh time.
    pub fn request_started_at_unix_seconds(&self) -> u64 {
        self.request_started_at_unix_seconds
    }
    pub fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
    }
    pub fn rpc_cache_observations(&self) -> &[RpcCacheObservation] {
        &self.rpc_cache_observations
    }
    /// Retain additional normalized response provenance without extending this context's
    /// lifetime. Reported cache age is a conservative constraint, never a freshness proof.
    pub fn with_additional_cache_observations(
        mut self,
        observations: Vec<RpcCacheObservation>,
    ) -> Result<Self, ChainError> {
        if self.rpc_cache_observations.len() + observations.len() > 128 {
            return Err(ChainError::ResourceLimit);
        }
        if observations.iter().any(|o| o.malformed_age) {
            return Err(ChainError::MalformedEvidence);
        }
        let prior_age = self
            .rpc_cache_observations
            .iter()
            .filter_map(|o| o.reported_age_seconds)
            .max()
            .unwrap_or(0);
        let added_age = observations
            .iter()
            .filter_map(|o| o.reported_age_seconds)
            .max()
            .unwrap_or(0);
        self.valid_until_unix_seconds = self
            .valid_until_unix_seconds
            .checked_sub(added_age.saturating_sub(prior_age))
            .ok_or(ChainError::StaleChain)?;
        self.rpc_cache_observations.extend(observations);
        self.check_fresh_at(self.observed_at_unix_seconds)?;
        Ok(self)
    }
    /// Recheck at point of use. This only validates bounded age, not chain consensus.
    pub fn check_fresh_at(&self, now: u64) -> Result<(), ChainError> {
        if now < self.observed_at_unix_seconds || now > self.valid_until_unix_seconds {
            Err(ChainError::StaleChain)
        } else {
            Ok(())
        }
    }
    pub fn authorizes_signing(&self) -> bool {
        false
    }
    pub fn independently_consensus_verified(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AnchorEvidence {
    pub context: ChainContext,
    pub block: BlockIdentity,
    pub pool: &'static str,
    pub root_protocol_hex: String,
    pub leaf_count: usize,
    pub tree_encoding_sha256: String,
    pub provider_reported_only: bool,
    pub proves_note_membership: bool,
    pub proves_unspentness: bool,
    pub rpc_cache_observations: Vec<RpcCacheObservation>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TransactionStatus {
    /// Source-specific absence. Never means safe to replace/clear exposure.
    NotObserved,
    PendingObserved,
    /// Backend explicitly reports a transaction indexed on a noncanonical fork.
    Reorganized,
    Included {
        block: BlockIdentity,
        confirmations: u64,
    },
}
#[derive(Debug, Clone, Serialize)]
pub struct TransactionObservation {
    pub transaction_id: String,
    pub context: ChainContext,
    pub status: TransactionStatus,
    pub confirms_raw_transaction_id: bool,
    pub independently_consensus_verified: bool,
    pub clears_authorization_exposure: bool,
}

/// Construction performs no I/O. Calling read-only methods requires a Tokio runtime.
/// A configured HTTPS source is a named trust dependency, not a trustless node.
pub struct ChainAdapter {
    identity: BackendIdentity,
    policy: NetworkPolicy,
    rpc: rpc::Rpc,
}
impl ChainAdapter {
    /// Attach bounded evidence counters; does not change errors, policy or authority.
    #[cfg(feature = "synthetic-qualification")]
    pub fn with_transport_diagnostics(mut self, diagnostics: TransportDiagnostics) -> Self {
        self.rpc.observer.diagnostics = Some(diagnostics);
        self
    }
    /// Public, never-funded controlled fixtures only. This feature must not be enabled
    /// in a production embedding. Literal loopback only; no DNS, redirects or TLS bypass
    /// for remote hosts. Every resulting context retains synthetic provenance.
    #[cfg(feature = "synthetic-qualification")]
    pub fn synthetic_loopback_for_qualification(
        endpoint: &str,
        policy: NetworkPolicy,
    ) -> Result<Self, ChainError> {
        policy.validate()?;
        let uri: tonic::codegen::http::Uri = endpoint
            .parse()
            .map_err(|_| ChainError::InvalidConfiguration)?;
        let host = uri
            .host()
            .ok_or(ChainError::InvalidConfiguration)?
            .trim_matches(['[', ']']);
        let ip: std::net::IpAddr = host.parse().map_err(|_| ChainError::InvalidConfiguration)?;
        if !ip.is_loopback()
            || uri.scheme_str() != Some("http")
            || uri.authority().is_some_and(|a| a.as_str().contains('@'))
            || uri
                .path_and_query()
                .is_some_and(|p| !matches!(p.as_str(), "" | "/"))
        {
            return Err(ChainError::InvalidConfiguration);
        }
        Ok(Self {
            identity: BackendIdentity {
                source_id: "synthetic-loopback".into(),
                endpoint: endpoint.trim_end_matches('/').into(),
                trust_profile: "synthetic_never_chain_evidence",
            },
            policy,
            rpc: rpc::Rpc::for_test(endpoint, policy),
        })
    }
    pub fn testnet(
        source_id: &str,
        endpoint: &str,
        policy: NetworkPolicy,
    ) -> Result<Self, ChainError> {
        policy.validate()?;
        if source_id.is_empty()
            || source_id.len() > 128
            || !source_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        {
            return Err(ChainError::InvalidConfiguration);
        }
        let uri: tonic::codegen::http::Uri = endpoint
            .parse()
            .map_err(|_| ChainError::InvalidConfiguration)?;
        if uri.scheme_str() != Some("https")
            || uri.host().is_none()
            || uri.authority().is_some_and(|a| a.as_str().contains('@'))
            || uri
                .path_and_query()
                .is_some_and(|p| !matches!(p.as_str(), "" | "/"))
        {
            return Err(ChainError::InvalidConfiguration);
        }
        let rpc = rpc::Rpc::new(endpoint, policy)?;
        Ok(Self {
            identity: BackendIdentity {
                source_id: source_id.into(),
                endpoint: endpoint.trim_end_matches('/').into(),
                trust_profile: "single_tls_provider_report_not_consensus",
            },
            policy,
            rpc,
        })
    }
    pub fn identity(&self) -> &BackendIdentity {
        &self.identity
    }
    /// Connect using the same HTTPS, native trust roots, existing proxy and bounded
    /// handshake as public chain observation. Only public block/tree RPCs are permitted.
    /// This does not import accounts, start scanning or authorize provider contact.
    pub async fn public_sync_channel(&self) -> Result<PublicSyncChannel, ChainError> {
        Ok(PublicSyncChannel::new(
            self.rpc.connect().await?,
            self.policy.maximum_response_bytes,
        ).with_observer(self.rpc.observer.clone()))
    }
    pub async fn context(&self) -> Result<ChainContext, ChainError> {
        let started = now()?;
        let info = self.rpc.info().await?;
        validate_info(&info)?;
        let first = self.rpc.latest().await?;
        let block = self.rpc.block(first.height).await?;
        let last = self.rpc.latest().await?;
        let mut context = validate_context(
            &self.identity,
            &self.policy,
            &info,
            &first,
            &block,
            &last,
            started,
            now()?,
        )?;
        apply_cache_observations(
            &mut context,
            vec![info.cache, first.cache, block.cache, last.cache],
        )?;
        Ok(context)
    }
    /// No account material or nullifiers are transmitted. The tree is a provider
    /// assertion at a block whose hash is checked again against that provider.
    pub async fn ironwood_anchor(
        &self,
        context: &ChainContext,
        height: u64,
    ) -> Result<AnchorEvidence, ChainError> {
        self.check_context(context)?;
        if height < NU7_ACTIVATION_HEIGHT || height > context.tip.height {
            return Err(ChainError::MalformedEvidence);
        }
        let tree = self.rpc.tree(height).await?;
        let block = self.rpc.block(height).await?;
        let identity = block_identity(block.height, &block.hash)?;
        if tree.network != "test" {
            return Err(ChainError::WrongNetwork);
        }
        if tree.height != height
            || block.height != height
            || tree.hash.to_ascii_lowercase() != identity.hash
            || tree.time != block.time
        {
            return Err(ChainError::ContradictoryChain);
        }
        let (root, count, digest) = parse_ironwood_tree(&tree.ironwood_tree)?;
        let recheck_cache = self.recheck_context_tip(context).await?;
        let observations = vec![tree.cache, block.cache, recheck_cache];
        let context = context
            .clone()
            .with_additional_cache_observations(observations.clone())?;
        context.check_fresh_at(now()?)?;
        Ok(AnchorEvidence {
            context,
            block: identity,
            pool: "ironwood",
            root_protocol_hex: hex::encode(root),
            leaf_count: count,
            tree_encoding_sha256: digest,
            provider_reported_only: true,
            proves_note_membership: false,
            proves_unspentness: false,
            rpc_cache_observations: observations,
        })
    }
    /// Queries disclose this public transaction id to the selected provider.
    /// The caller must obtain any necessary transaction-linkage disclosure consent.
    pub async fn observe_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<TransactionObservation, ChainError> {
        let txid = TxId::from_hex(transaction_id).ok_or(ChainError::MalformedEvidence)?;
        let mut context = self.context().await?;
        let mut cache_observations = Vec::new();
        let response = self.rpc.transaction(*txid.as_ref()).await;
        let (status, confirms_id) = match response {
            Err(ChainError::NotObserved) => (TransactionStatus::NotObserved, false),
            Err(e) => return Err(e),
            Ok(raw) => {
                cache_observations.push(raw.cache.clone());
                verify_transaction_id(&raw.data, txid)?;
                let status = match raw.height {
                    0 => TransactionStatus::PendingObserved,
                    u64::MAX => TransactionStatus::Reorganized,
                    height if height > context.tip.height => {
                        return Err(ChainError::ContradictoryChain);
                    }
                    height => {
                        let block = self.rpc.block(height).await?;
                        cache_observations.push(block.cache.clone());
                        let identity = block_identity(block.height, &block.hash)?;
                        if block.height != height
                            || (height == context.tip.height && identity != context.tip)
                            || block
                                .vtx
                                .iter()
                                .filter(|t| t.txid.as_slice() == txid.as_ref())
                                .count()
                                != 1
                        {
                            return Err(ChainError::ContradictoryChain);
                        }
                        TransactionStatus::Included {
                            block: identity,
                            confirmations: context.tip.height - height + 1,
                        }
                    }
                };
                (status, true)
            }
        };
        cache_observations.push(self.recheck_context_tip(&context).await?);
        context = context.with_additional_cache_observations(cache_observations)?;
        context.check_fresh_at(now()?)?;
        Ok(TransactionObservation {
            transaction_id: txid.to_string(),
            context,
            status,
            confirms_raw_transaction_id: confirms_id,
            independently_consensus_verified: false,
            clears_authorization_exposure: false,
        })
    }
    /// Re-confirm at most eight already-scanned public block identities against
    /// this exact provider, then recheck the original observed tip. The caller
    /// must independently retain the maintained contiguous scanned ancestry;
    /// these single-provider responses are not an ancestry/consensus proof or
    /// a native read capability. No account, note, nullifier or key is sent.
    /// The earliest context clock is retained and cache ages can only shorten it.
    pub async fn revalidate_scanned_block_identities(
        &self,
        context: &ChainContext,
        required: &[BlockIdentity],
    ) -> Result<ChainContext, ChainError> {
        self.check_context(context)?;
        validate_scanned_identity_targets(context.tip.height, required)?;
        let mut provenance = Vec::with_capacity(required.len() + 1);
        for expected in required {
            self.check_context(context)?;
            let block = self.rpc.block(expected.height).await?;
            if block_identity(block.height, &block.hash)? != *expected {
                return Err(ChainError::ContradictoryChain);
            }
            provenance.push(block.cache);
        }
        provenance.push(self.recheck_context_tip(context).await?);
        let observed = context
            .clone()
            .with_additional_cache_observations(provenance)?;
        self.check_context(&observed)?;
        Ok(observed)
    }
    /// No lightwalletd unary endpoint proves that private selected notes remain unspent.
    pub fn observe_inputs(&self) -> Result<(), ChainError> {
        Err(ChainError::UnsupportedCapability)
    }
    fn check_context(&self, context: &ChainContext) -> Result<(), ChainError> {
        if context.source != self.identity {
            return Err(ChainError::ContradictoryChain);
        }
        context.check_fresh_at(now()?)
    }
    async fn recheck_context_tip(
        &self,
        context: &ChainContext,
    ) -> Result<RpcCacheObservation, ChainError> {
        self.check_context(context)?;
        let canonical = self.rpc.block(context.tip.height).await?;
        if block_identity(canonical.height, &canonical.hash)? != context.tip {
            return Err(ChainError::ContradictoryChain);
        }
        self.check_context(context)?;
        Ok(canonical.cache)
    }
}

fn validate_scanned_identity_targets(
    tip: u64,
    required: &[BlockIdentity],
) -> Result<(), ChainError> {
    if required.is_empty() || required.len() > 8 {
        return Err(ChainError::ResourceLimit);
    }
    let mut previous = None;
    for expected in required {
        if expected.height < NU7_ACTIVATION_HEIGHT
            || expected.height > tip
            || previous.is_some_and(|height| height >= expected.height)
            || expected.hash.len() != 64
            || !expected
                .hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || expected.hash.bytes().all(|byte| byte == b'0')
        {
            return Err(ChainError::MalformedEvidence);
        }
        previous = Some(expected.height);
    }
    Ok(())
}

#[cfg(test)]
mod scanned_identity_target_tests {
    use super::*;
    #[test]
    fn public_revalidation_targets_are_bounded_sorted_and_never_a_future_tip() {
        let first = BlockIdentity {
            height: NU7_ACTIVATION_HEIGHT,
            hash: "12".repeat(32),
        };
        let second = BlockIdentity {
            height: first.height + 1,
            hash: "34".repeat(32),
        };
        assert!(
            validate_scanned_identity_targets(second.height, &[first.clone(), second.clone()])
                .is_ok()
        );
        assert!(
            validate_scanned_identity_targets(first.height, std::slice::from_ref(&second)).is_err()
        );
        assert!(
            validate_scanned_identity_targets(second.height, &[second, first.clone()]).is_err()
        );
        assert!(
            validate_scanned_identity_targets(first.height, &[first.clone(), first.clone()])
                .is_err()
        );
        assert!(validate_scanned_identity_targets(first.height, &[]).is_err());
        assert!(validate_scanned_identity_targets(first.height, &vec![first; 9]).is_err());
    }
}

fn apply_cache_observations(
    context: &mut ChainContext,
    observations: Vec<RpcCacheObservation>,
) -> Result<(), ChainError> {
    // Advertised cache age can only make our expiry earlier. Missing Age or a
    // cache miss cannot demonstrate when the provider refreshed its backend.
    if observations.iter().any(|m| m.malformed_age) {
        return Err(ChainError::MalformedEvidence);
    }
    let age = observations
        .iter()
        .filter_map(|m| m.reported_age_seconds)
        .max()
        .unwrap_or(0);
    context.valid_until_unix_seconds = context
        .valid_until_unix_seconds
        .checked_sub(age)
        .ok_or(ChainError::StaleChain)?;
    context.check_fresh_at(context.observed_at_unix_seconds)?;
    context.rpc_cache_observations = observations;
    Ok(())
}

fn now() -> Result<u64, ChainError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ChainError::ClockUnavailable)
}
fn validate_info(info: &rpc::LightdInfo) -> Result<(), ChainError> {
    if info.chain_name != "test" || info.sapling_activation_height != 280_000 {
        return Err(ChainError::WrongNetwork);
    }
    if info.consensus_branch_id != "77190ad9" || info.block_height < NU7_ACTIVATION_HEIGHT {
        return Err(ChainError::WrongBranch);
    }
    if [
        info.version.len(),
        info.zcashd_subversion.len(),
        info.protocol_version.len(),
        info.vendor.len(),
    ]
    .iter()
    .any(|n| *n > 256)
    {
        return Err(ChainError::MalformedEvidence);
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn validate_context(
    identity: &BackendIdentity,
    policy: &NetworkPolicy,
    info: &rpc::LightdInfo,
    first: &rpc::BlockId,
    block: &rpc::CompactBlock,
    last: &rpc::BlockId,
    started: u64,
    observed: u64,
) -> Result<ChainContext, ChainError> {
    validate_info(info)?;
    let tip = block_identity(first.height, &first.hash)?;
    if first.height < NU7_ACTIVATION_HEIGHT {
        return Err(ChainError::WrongBranch);
    }
    if first != last || tip != block_identity(block.height, &block.hash)? {
        return Err(ChainError::ContradictoryChain);
    }
    if block.prev_hash.len() != 32 {
        return Err(ChainError::MalformedEvidence);
    }
    if observed < started
        || observed - started > policy.observation_ttl.as_secs()
        || observed.saturating_sub(u64::from(block.time)) > policy.maximum_tip_age.as_secs()
        || u64::from(block.time) > observed.saturating_add(policy.maximum_clock_skew.as_secs())
        || info.block_height.abs_diff(first.height) > policy.maximum_reported_height_gap
        || info.estimated_height.abs_diff(first.height) > policy.maximum_reported_height_gap
    {
        return Err(ChainError::StaleChain);
    }
    Ok(ChainContext {
        source: identity.clone(),
        network: "test",
        genesis_identity_verified: false,
        observed_at_unix_seconds: observed,
        request_started_at_unix_seconds: started,
        valid_until_unix_seconds: started
            .checked_add(policy.observation_ttl.as_secs())
            .ok_or(ChainError::ClockUnavailable)?,
        tip,
        tip_mined_at_unix_seconds: u64::from(block.time),
        branch_id: "0x77190ad9".into(),
        reported_height: info.block_height,
        estimated_height: info.estimated_height,
        synchronized_by_provider_heuristic: true,
        independently_consensus_verified: false,
        lightwalletd_version: info.version.clone(),
        backend_subversion: info.zcashd_subversion.clone(),
        protocol_version: info.protocol_version.clone(),
        provider_refresh_time_verified: false,
        rpc_cache_observations: Vec::new(),
    })
}
fn block_identity(height: u64, hash: &[u8]) -> Result<BlockIdentity, ChainError> {
    if hash.len() != 32 || hash.iter().all(|b| *b == 0) {
        return Err(ChainError::MalformedEvidence);
    }
    let display: Vec<u8> = hash.iter().rev().copied().collect();
    Ok(BlockIdentity {
        height,
        hash: hex::encode(display),
    })
}
fn verify_transaction_id(bytes: &[u8], expected: TxId) -> Result<(), ChainError> {
    if bytes.is_empty() || bytes.len() > 2 * 1024 * 1024 {
        return Err(ChainError::ResourceLimit);
    }
    let mut cursor = Cursor::new(bytes);
    let tx = zcash_primitives::transaction::Transaction::read(&mut cursor, BranchId::Nu7)
        .map_err(|_| ChainError::MalformedEvidence)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ChainError::MalformedEvidence);
    }
    if tx.txid() != expected {
        return Err(ChainError::ContradictoryChain);
    }
    Ok(())
}
fn parse_ironwood_tree(value: &str) -> Result<([u8; 32], usize, String), ChainError> {
    use sha2::{Digest, Sha256};
    // Absent proto3 fields must not silently mean a compatible, empty Ironwood tree.
    if value.is_empty() {
        return Err(ChainError::UnsupportedCapability);
    }
    if value.len() > 2 * (3 + 34 * 33) {
        return Err(ChainError::ResourceLimit);
    }
    let bytes = hex::decode(value).map_err(|_| ChainError::MalformedEvidence)?;
    // Bound the CompactSize vector before entering upstream's generic tree decoder.
    fn node(bytes: &[u8], p: &mut usize) -> Result<(), ChainError> {
        match bytes.get(*p) {
            Some(0) => *p += 1,
            Some(1) => *p += 33,
            _ => return Err(ChainError::MalformedEvidence),
        }
        if *p > bytes.len() {
            return Err(ChainError::MalformedEvidence);
        }
        Ok(())
    }
    let mut p = 0;
    node(&bytes, &mut p)?;
    node(&bytes, &mut p)?;
    let count = *bytes.get(p).ok_or(ChainError::MalformedEvidence)?;
    if count > 31 {
        return Err(ChainError::MalformedEvidence);
    }
    p += 1;
    for _ in 0..count {
        node(&bytes, &mut p)?;
    }
    if p != bytes.len() {
        return Err(ChainError::MalformedEvidence);
    }
    let tree = zcash_primitives::merkle_tree::read_commitment_tree::<
        orchard::tree::MerkleHashOrchard,
        _,
        32,
    >(&bytes[..])
    .map_err(|_| ChainError::MalformedEvidence)?;
    // Upstream's legacy container checks depth but permits impossible leaf layouts.
    if tree.left().is_none()
        && (tree.right().is_some() || tree.parents().iter().any(Option::is_some))
    {
        return Err(ChainError::MalformedEvidence);
    }
    Ok((
        tree.root().to_bytes(),
        tree.size(),
        hex::encode(Sha256::digest(&bytes)),
    ))
}

/// Deterministic, never-funded context for offline integration qualification only.
/// The fixed source, tip, branch and synthetic trust profile cannot be selected by
/// callers. Only the observation time varies to exercise real freshness checks.
/// This feature must not be enabled in a production embedding.
#[cfg(feature = "synthetic-qualification")]
pub fn synthetic_chain_context_for_qualification(
    observed_at_unix_seconds: u64,
) -> Result<ChainContext, ChainError> {
    synthetic_fixed_context(
        observed_at_unix_seconds,
        SyntheticContextProfile::Transaction,
    )
}

/// Second fixed never-funded context for the wallet scanner integration fixture.
/// Only time is caller-supplied; height/source/trust cannot be chosen by callers.
#[cfg(feature = "synthetic-qualification")]
pub fn synthetic_wallet_chain_context_for_qualification(
    observed_at_unix_seconds: u64,
) -> Result<ChainContext, ChainError> {
    synthetic_fixed_context(observed_at_unix_seconds, SyntheticContextProfile::Wallet)
}

/// Fixed successor tip for observing ten confirmations after the wallet fixture's
/// target height. It retains that fixture's backend identity and synthetic trust.
#[cfg(feature = "synthetic-qualification")]
pub fn synthetic_wallet_confirmation_context_for_qualification(
    observed_at_unix_seconds: u64,
) -> Result<ChainContext, ChainError> {
    synthetic_fixed_context(
        observed_at_unix_seconds,
        SyntheticContextProfile::WalletConfirmed,
    )
}

#[cfg(feature = "synthetic-qualification")]
enum SyntheticContextProfile {
    Transaction,
    Wallet,
    WalletConfirmed,
}

#[cfg(feature = "synthetic-qualification")]
fn synthetic_fixed_context(
    observed_at_unix_seconds: u64,
    profile: SyntheticContextProfile,
) -> Result<ChainContext, ChainError> {
    let time = u32::try_from(observed_at_unix_seconds).map_err(|_| ChainError::ClockUnavailable)?;
    let (height, source_id, endpoint, hash) = match profile {
        SyntheticContextProfile::Wallet | SyntheticContextProfile::WalletConfirmed => (
            if matches!(profile, SyntheticContextProfile::WalletConfirmed) {
                4_465_050
            } else {
                4_465_040
            },
            "synthetic-wallet-offline-fixture",
            "synthetic://wallet-offline-never-network",
            if matches!(profile, SyntheticContextProfile::WalletConfirmed) {
                3
            } else {
                1
            },
        ),
        SyntheticContextProfile::Transaction => (
            4_498_144,
            "synthetic-offline-fixture",
            "synthetic://offline-never-network",
            1,
        ),
    };
    let identity = BackendIdentity {
        source_id: source_id.into(),
        endpoint: endpoint.into(),
        trust_profile: "synthetic_never_chain_evidence",
    };
    let info = rpc::LightdInfo {
        version: "synthetic-qualification".into(),
        chain_name: "test".into(),
        sapling_activation_height: 280_000,
        consensus_branch_id: "77190ad9".into(),
        block_height: height,
        estimated_height: height,
        ..Default::default()
    };
    let tip = rpc::BlockId {
        height,
        hash: vec![hash; 32],
    };
    let block = rpc::CompactBlock {
        height: tip.height,
        hash: tip.hash.clone(),
        prev_hash: vec![2; 32],
        time,
        vtx: vec![],
    };
    validate_context(
        &identity,
        &NetworkPolicy::default(),
        &info,
        &tip,
        &block,
        &tip,
        observed_at_unix_seconds,
        observed_at_unix_seconds,
    )
}

/// A same-height disagreement is contradictory, even when either source appears fresh.
/// Different heights need ancestry evidence; this function does not invent it.
pub fn compare_contexts(
    left: &ChainContext,
    right: &ChainContext,
    now: u64,
) -> Result<(), ChainError> {
    left.check_fresh_at(now)?;
    right.check_fresh_at(now)?;
    if left.tip.height != right.tip.height {
        return Err(ChainError::MissingAncestryEvidence);
    }
    if left.tip != right.tip || left.branch_id != right.branch_id {
        return Err(ChainError::ContradictoryChain);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Serialize)]
pub struct ChainCapability {
    pub network: &'static str,
    pub read_only_observer_implemented: bool,
    pub native_public_transport_qualified_in_this_environment: bool,
    pub independently_validates_consensus: bool,
    pub establishes_unspentness: bool,
    /// Network financial capability remains disabled regardless of compiled source.
    pub submission_implemented: bool,
    pub injected_submission_orchestration_compiled: bool,
    pub observation_reconciliation_implemented: bool,
    pub mainnet_enabled: bool,
}
pub fn capability() -> ChainCapability {
    ChainCapability {
        network: "testnet-nu7",
        read_only_observer_implemented: true,
        native_public_transport_qualified_in_this_environment: true,
        independently_validates_consensus: false,
        establishes_unspentness: false,
        submission_implemented: false,
        injected_submission_orchestration_compiled: cfg!(feature = "submission-dispatch"),
        observation_reconciliation_implemented: true,
        mainnet_enabled: false,
    }
}
