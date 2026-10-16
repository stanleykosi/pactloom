//! Bounded historical metadata only. The actual journal reader restores reports
//! as stale, including reports whose historical provider policy was once met.
use super::*;
use crate::native_dispatch_requests::DispatchObservation;
pub const MAX_RECONCILIATION_OBSERVATIONS: usize = 16;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalConfirmationPolicy {
    pub required_confirmations: u32,
    pub expiry_observation_depth: u32,
    pub sources: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalBlockIdentity {
    pub height: u64,
    pub hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalSourceTip {
    pub source_id: String,
    pub tip: HistoricalBlockIdentity,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalReconciliationState {
    Stale {},
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalReconciliationReport {
    pub transaction_id: String,
    pub expiry_height: u32,
    pub policy: HistoricalConfirmationPolicy,
    pub observed_at_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub state: HistoricalReconciliationState,
    pub last_inclusion: Option<HistoricalBlockIdentity>,
    pub confidence_lost: bool,
    pub reorganization_observed: bool,
    pub source_ids: Vec<String>,
    pub source_tips: Vec<HistoricalSourceTip>,
    pub independently_consensus_verified: bool,
    pub clears_authorization_exposure: bool,
    pub permits_replacement: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationJournalObservation {
    pub submission: DispatchObservation,
    pub report: Option<HistoricalReconciliationReport>,
}
fn source_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn valid_block(b: &HistoricalBlockIdentity) -> bool {
    b.height > 0
        && b.hash.len() == 64
        && b.hash.bytes().all(|b| b.is_ascii_hexdigit())
        && b.hash.bytes().any(|b| b != b'0')
}
fn valid_report(r: &HistoricalReconciliationReport) -> bool {
    (1..=100).contains(&r.policy.required_confirmations)
        && (1..=100).contains(&r.policy.expiry_observation_depth)
        && (1..=8).contains(&r.policy.sources.len())
        && r.policy.sources.iter().all(|s| source_id(s))
        && r.policy.sources.iter().collect::<BTreeSet<_>>().len() == r.policy.sources.len()
        && r.source_ids.len() <= 8
        && r.source_tips.len() <= 8
        && r.source_ids.iter().all(|s| r.policy.sources.contains(s))
        && r.source_ids.iter().collect::<BTreeSet<_>>().len() == r.source_ids.len()
        && r.source_tips
            .iter()
            .all(|t| r.source_ids.contains(&t.source_id) && valid_block(&t.tip))
        && r.source_tips
            .iter()
            .map(|t| &t.source_id)
            .collect::<BTreeSet<_>>()
            .len()
            == r.source_tips.len()
        && r.last_inclusion.as_ref().is_none_or(valid_block)
        && r.valid_until_unix_seconds >= r.observed_at_unix_seconds
        && !r.independently_consensus_verified
        && !r.clears_authorization_exposure
        && !r.permits_replacement
}
pub(super) fn validate_observation(
    e: &Envelope,
    r: &StoredNativeReconciliationRequest,
    o: &ReconciliationJournalObservation,
) -> Result<()> {
    native_dispatch_requests::validate_reconciliation_observation(
        e,
        &r.principal_id,
        r.request.dispatch_request_id(),
        &o.submission,
    )?;
    if let Some(report) = &o.report {
        let descriptor = o.submission.descriptor.as_ref().ok_or_else(inconsistent)?;
        if !valid_report(report)
            || report.transaction_id != r.source.txid
            || report.transaction_id != descriptor.transaction_id
            || report.expiry_height != descriptor.expiry_height
        {
            return Err(inconsistent());
        }
    }
    Ok(())
}
pub(super) fn monotone(
    a: &ReconciliationJournalObservation,
    b: &ReconciliationJournalObservation,
) -> bool {
    if !native_dispatch_requests::reconciliation_observation_monotone(&a.submission, &b.submission)
    {
        return false;
    }
    match (&a.report, &b.report) {
        (Some(a), Some(b)) => {
            a.transaction_id == b.transaction_id
                && a.expiry_height == b.expiry_height
                && a.policy == b.policy
                && a.observed_at_unix_seconds <= b.observed_at_unix_seconds
                && (a.last_inclusion.is_none() || b.last_inclusion.is_some())
        }
        (Some(_), None) => false,
        _ => true,
    }
}
pub(super) fn validate_observations(
    e: &Envelope,
    r: &StoredNativeReconciliationRequest,
) -> Result<()> {
    if r.observations.len() > MAX_RECONCILIATION_OBSERVATIONS {
        return Err(exhausted());
    }
    for (i, o) in r.observations.iter().enumerate() {
        validate_observation(e, r, o)?;
        if r.observations[..i].contains(o) || (i > 0 && !monotone(&r.observations[i - 1], o)) {
            return Err(inconsistent());
        }
    }
    Ok(())
}
