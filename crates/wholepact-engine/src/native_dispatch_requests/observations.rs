//! Bounded metadata DTOs are deliberately available without native dispatch features.
use super::*;
pub const MAX_DISPATCH_OBSERVATIONS: usize = 16;
pub const MAX_DISPATCH_ATTEMPTS: usize = 128;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchDescriptor {
    pub operation_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub transaction_id: String,
    pub bytes_sha256: String,
    pub expiry_height: u32,
    pub network: String,
    pub consensus_branch_id: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchProviderState {
    SubmissionUnknown,
    BackendAcknowledged,
    BackendRejected,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchIntentObservation {
    pub operation_id: String,
    pub bytes_sha256: String,
    pub historical_provider_state: DispatchProviderState,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DispatchAttemptOutcome {
    Unknown {},
    Acknowledged {},
    Rejected { code: i32 },
    Indeterminate { reason: DispatchFailure },
    BlockedBeforeDispatch {},
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum DispatchFailure {
    Timeout {},
    Interrupted {},
    TransportUnavailable {},
    ResourceLimit {},
    MalformedEvidence {},
    UnsupportedCapability {},
    Backend { grpc_code: i32 },
    Other {},
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchAttemptObservation {
    pub number: u32,
    pub source_id: String,
    pub started_at_unix_seconds: u64,
    pub outcome: DispatchAttemptOutcome,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchObservation {
    pub submission_journal_identity: String,
    pub descriptor: Option<DispatchDescriptor>,
    pub intent: Option<DispatchIntentObservation>,
    pub attempts: Vec<DispatchAttemptObservation>,
}
fn identifier(s: &str) -> bool {
    (16..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())
}
fn source_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
pub(super) fn descriptor_matches(
    e: &Envelope,
    r: &StoredNativeDispatchRequest,
    d: &DispatchDescriptor,
) -> Result<()> {
    let candidate = candidate_for_source(e, &r.source)?;
    let agreement = &candidate.proposal.manifest.agreement;
    if d.operation_id != r.operation_id
        || !identifier(&d.operation_id)
        || d.obligation_id != agreement.obligation_id
        || !identifier(&d.obligation_id)
        || d.proposal_id != candidate.proposal.proposal_id
        || !identifier(&d.proposal_id)
        || d.transaction_id != r.source.txid
        || !digest(&d.transaction_id)
        || d.bytes_sha256 != r.source.transaction_digest
        || !digest(&d.bytes_sha256)
        || d.expiry_height != candidate.proposal.manifest.expiry_height
        || d.expiry_height == 0
        || agreement.network_profile_id != candidates::PROFILE_ID
        || d.network != "testnet"
        || d.consensus_branch_id
            != wholepact_core::manual_roster_construction_v3::COMMON_CONTEXT_NU7_BRANCH_ID
    {
        return Err(inconsistent());
    }
    Ok(())
}
pub(super) fn validate_observation(
    e: &Envelope,
    r: &StoredNativeDispatchRequest,
    o: &DispatchObservation,
) -> Result<()> {
    if r.submission_journal_identity.as_deref() != Some(o.submission_journal_identity.as_str())
        || !valid_journal_identity(&o.submission_journal_identity)
        || o.attempts.len() > MAX_DISPATCH_ATTEMPTS
    {
        return Err(inconsistent());
    }
    match (&o.descriptor, &o.intent) {
        (None, None) if o.attempts.is_empty() => return Ok(()),
        (Some(descriptor), Some(intent)) => {
            descriptor_matches(e, r, descriptor)?;
            if intent.operation_id != descriptor.operation_id
                || intent.bytes_sha256 != descriptor.bytes_sha256
            {
                return Err(inconsistent());
            }
        }
        _ => return Err(inconsistent()),
    }
    let mut previous_time = 0;
    for (index, attempt) in o.attempts.iter().enumerate() {
        if attempt.number as usize != index + 1
            || !source_id(&attempt.source_id)
            || attempt.started_at_unix_seconds > i64::MAX as u64
            || attempt.started_at_unix_seconds < previous_time
            || matches!(
                attempt.outcome,
                DispatchAttemptOutcome::Rejected { code: 0 }
            )
        {
            return Err(inconsistent());
        }
        previous_time = attempt.started_at_unix_seconds;
    }
    Ok(())
}
/// A newer observation may enrich original journal facts, never erase them.
/// Exact historical replay is handled before this check and never replaces latest.
pub(super) fn monotone(previous: &DispatchObservation, next: &DispatchObservation) -> bool {
    if previous.submission_journal_identity != next.submission_journal_identity
        || previous
            .descriptor
            .as_ref()
            .is_some_and(|d| Some(d) != next.descriptor.as_ref())
        || previous.attempts.len() > next.attempts.len()
    {
        return false;
    }
    match (&previous.intent, &next.intent) {
        (Some(a), Some(b)) => {
            if a.operation_id != b.operation_id || a.bytes_sha256 != b.bytes_sha256 {
                return false;
            }
            use DispatchProviderState::*;
            if !matches!(
                (a.historical_provider_state, b.historical_provider_state),
                (SubmissionUnknown, _)
                    | (BackendRejected, BackendRejected | BackendAcknowledged)
                    | (BackendAcknowledged, BackendAcknowledged)
            ) {
                return false;
            }
        }
        (Some(_), None) => return false,
        _ => {}
    }
    previous.attempts.iter().zip(&next.attempts).all(|(a, b)| {
        a.number == b.number
            && a.source_id == b.source_id
            && a.started_at_unix_seconds == b.started_at_unix_seconds
            && (a.outcome == b.outcome || a.outcome == DispatchAttemptOutcome::Unknown {})
    })
}
pub(super) fn validate_observations(e: &Envelope, r: &StoredNativeDispatchRequest) -> Result<()> {
    if r.observations.len() > MAX_DISPATCH_OBSERVATIONS {
        return Err(exhausted());
    }
    for (i, observation) in r.observations.iter().enumerate() {
        validate_observation(e, r, observation)?;
        if r.observations[..i].contains(observation)
            || i > 0 && !monotone(&r.observations[i - 1], observation)
        {
            return Err(inconsistent());
        }
    }
    Ok(())
}
