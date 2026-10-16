//! Separate exact-inventory retired-history disclosure. Records are historical
//! audit data only; they never assert an active writer or financial freshness.
use super::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Component, PathBuf},
    time::{Duration, Instant},
};
use wholepact_authority::{
    AccountPolicy, AccountSnapshot, AutomaticKeyUseAdmission, ReservationPermit,
    WitnessDisclosureDescriptor,
    account_use::{AccountUseGenesis, PermanentAccountExclusion},
    account_use_link::{AccountExclusionReceipt, account_use_witness_origin_digest},
};
const MAX_AUDIT_BYTES: usize = 2_000_000;
const DISCLOSURE_LIFETIME: Duration = Duration::from_secs(30);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredHistoryRequest {
    pub schema_version: u16,
    pub inventory_digest: String,
    pub semantic_inventory_digest: String,
    pub generation_id: String,
    pub plan_digest: String,
    pub target_profile: PathBuf,
    pub expected_genesis: AccountUseGenesis,
    pub original_witness: WitnessDisclosureDescriptor,
}
impl RetiredHistoryRequest {
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.inventory_digest,
            &self.semantic_inventory_digest,
            &self.generation_id,
            &self.plan_digest,
        ] {
            hash(value)?;
        }
        self.expected_genesis.validate()?;
        self.original_witness.validate()?;
        let target = self.target_profile.to_str().ok_or(BridgeError::Binding)?;
        let identity = &self.expected_genesis.identity;
        if self.schema_version != 1
            || identity.account_id != self.original_witness.account_id
            || identity.network_profile_id != self.original_witness.network_profile_id
            || self.expected_genesis.witness_id != self.original_witness.witness_id
            || self.expected_genesis.witness_origin_digest != account_use_witness_origin_digest(&self.original_witness)?
            || !self.target_profile.is_absolute() || self.target_profile.file_name().is_none()
            || target.len() > 4096 || target.contains("//") || target.ends_with('/')
            || target.split('/').any(|s| matches!(s, "." | ".."))
            || target.chars().any(|c| c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
            || self.target_profile.components().any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        { return Err(BridgeError::Binding); }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical("wholepact:retired-host-history-request:v1", self)
    }
}

/// Immutable local snapshot, with pending/unacknowledged exclusions preserved.
/// A true recovery flag or historical epoch does not block an informational read
/// and is never cleared, refreshed or used as a writer admission by this route.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredLocalAudit {
    pub genesis: AccountUseGenesis,
    pub local_exclusion: Option<PermanentAccountExclusion>,
    pub local_witness_ack: Option<AccountExclusionReceipt>,
    pub recovery_required: bool,
    pub historical_writer_epoch: u64,
}
impl RetiredLocalAudit {
    pub(crate) fn validate_against(
        &self,
        genesis: &AccountUseGenesis,
        witnessed_exclusion: &PermanentAccountExclusion,
        witnessed_ack: &AccountExclusionReceipt,
    ) -> Result<()> {
        genesis.validate()?;
        witnessed_exclusion.validate()?;
        witnessed_ack.digest()?;
        if &self.genesis != genesis
            || self.historical_writer_epoch == 0
            || self.historical_writer_epoch > i64::MAX as u64
            || witnessed_exclusion.identity != genesis.identity
            || witnessed_exclusion.genesis_digest != genesis.digest()?
            || witnessed_ack.genesis_digest != genesis.digest()?
            || witnessed_ack.exclusion_digest != witnessed_exclusion.digest()?
            || witnessed_ack.witness_origin_digest != genesis.witness_origin_digest
            || witnessed_ack.operation_id != witnessed_exclusion.operation_id
            || self
                .local_exclusion
                .as_ref()
                .is_some_and(|e| e != witnessed_exclusion)
            || self
                .local_witness_ack
                .as_ref()
                .is_some_and(|ack| self.local_exclusion.is_none() || ack != witnessed_ack)
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredHistoryRecipient {
    pub grant_id: String,
    pub channel_digest: String,
    pub process_instance: String,
    pub uid: u32,
    pub pid: u32,
    pub application_label: String,
}
/// This single-purpose tag is never a configurable financial-ready flag.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetiredHistoryPurpose {
    InformationalRetiredHistoryOnly,
}

/// Deserialization verifies neither native disclosure nor complete replay. A
/// saved record never recreates RetiredHistoryDisclosureAdmission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredHistoryAuditRecord {
    pub purpose: RetiredHistoryPurpose,
    pub request: RetiredHistoryRequest,
    pub local: RetiredLocalAudit,
    pub recipient: RetiredHistoryRecipient,
    pub native_review_digest: String,
    pub witness_policy: AccountPolicy,
    pub witnessed_exclusion: PermanentAccountExclusion,
    pub witnessed_ack: AccountExclusionReceipt,
    pub snapshot: AccountSnapshot,
    pub history_digest: String,
    /// All original permits, including consumed, expired and resolved exposure.
    pub conservative_permits: Vec<ReservationPermit>,
    pub automatic_key_use_history: Vec<AutomaticKeyUseAdmission>,
}
impl RetiredHistoryAuditRecord {
    /// Syntax and mutual audit-binding checks, never authentication or eligibility.
    pub fn validate_audit(&self) -> Result<()> {
        self.request.validate()?;
        hash(&self.native_review_digest)?;
        hash(&self.history_digest)?;
        validate_recipient(&self.recipient)?;
        self.witness_policy.validate()?;
        self.local.validate_against(
            &self.request.expected_genesis,
            &self.witnessed_exclusion,
            &self.witnessed_ack,
        )?;
        let genesis = &self.request.expected_genesis;
        let checkpoint = self
            .snapshot
            .account_use_checkpoint
            .as_ref()
            .ok_or(BridgeError::Binding)?;
        if self.witness_policy.account_use_genesis.as_ref() != Some(genesis)
            || self.witness_policy.policy_digest()? != self.request.original_witness.policy_digest
            || self.snapshot.policy_digest != self.request.original_witness.policy_digest
            || self.snapshot.account_id != genesis.identity.account_id
            || self.snapshot.network_profile_id != genesis.identity.network_profile_id
            || self.snapshot.witness_id != genesis.witness_id
            || checkpoint.genesis_digest != genesis.digest()?
            || checkpoint.permanent_exclusion_digest.as_deref()
                != Some(self.witnessed_exclusion.digest()?.as_str())
            || self.witnessed_ack.committed_head.sequence > self.snapshot.head.sequence
            || self.snapshot.aggregate_budget_zatoshis
                != self.witness_policy.aggregate_budget_zatoshis
        {
            return Err(BridgeError::Binding);
        }
        self.snapshot.remaining_budget_zatoshis()?;
        hash(&checkpoint.history_digest)?;
        hash(&self.snapshot.head.digest)?;
        let mut ids = BTreeSet::new();
        for permit in &self.conservative_permits {
            permit.matches_request(&permit.request)?;
            if permit.request.account_id != genesis.identity.account_id
                || permit.request.network_profile_id != genesis.identity.network_profile_id
                || permit.witness_id != genesis.witness_id
                || permit.policy_digest != self.snapshot.policy_digest
                || permit.committed_head.sequence > self.snapshot.head.sequence
                || !ids.insert(&permit.request.authorization_id)
            {
                return Err(BridgeError::Binding);
            }
        }
        for admission in &self.automatic_key_use_history {
            admission.matches_request(&admission.request)?;
            if admission.committed_head.sequence > self.snapshot.head.sequence
                || !self.conservative_permits.contains(&admission.reservation)
            {
                return Err(BridgeError::Binding);
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| BridgeError::Binding)?
            .len()
            > MAX_AUDIT_BYTES
        {
            return Err(BridgeError::Limit);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate_audit()?;
        canonical("wholepact:retired-host-history-audit:v1", self)
    }
}

/// One-shot exact-recipient informational disclosure result. No constructor from
/// DTOs, Deserialize, Clone, Serialize or financial conversion exists. It is NOT
/// host publication admission, live witness lease or proof of external completeness.
///
/// ```compile_fail
/// use wholepact_signer::{authority_bridge::retired_history::RetiredHistoryDisclosureAdmission, consent_journal::ApprovedSpendConsent};
/// fn signing(x: RetiredHistoryDisclosureAdmission<'_>) -> ApprovedSpendConsent { x.into() }
/// ```
/// ```compile_fail
/// use wholepact_signer::{authority_bridge::retired_history::RetiredHistoryDisclosureAdmission, consent_journal::ApprovedEnrollment};
/// fn enrollment(x: RetiredHistoryDisclosureAdmission<'_>) -> ApprovedEnrollment { x.into() }
/// ```
/// ```compile_fail
/// use wholepact_signer::authority_bridge::{retired_history::RetiredHistoryDisclosureAdmission, dispatch_ipc::SignerDispatchAdmission};
/// fn dispatch<'a>(x: RetiredHistoryDisclosureAdmission<'_>) -> SignerDispatchAdmission<'a> { x.into() }
/// ```
/// ```compile_fail
/// use wholepact_signer::authority_bridge::{retired_history::RetiredHistoryDisclosureAdmission, host_publication_ipc::HostRecoveryPublicationAdmission};
/// fn publication(x: RetiredHistoryDisclosureAdmission<'_>) -> HostRecoveryPublicationAdmission { x.into() }
/// ```
/// ```compile_fail
/// use wholepact_signer::authority_bridge::retired_history::RetiredHistoryDisclosureAdmission;
/// fn saved(x: &RetiredHistoryDisclosureAdmission<'_>) { let _ = serde_json::to_string(x); }
/// ```
/// ```compile_fail
/// use wholepact_signer::authority_bridge::retired_history::RetiredHistoryDisclosureAdmission;
/// fn load(bytes: &[u8]) { let _: RetiredHistoryDisclosureAdmission<'_> = serde_json::from_slice(bytes).unwrap(); }
/// ```
/// ```compile_fail
/// use wholepact_signer::authority_bridge::retired_history::RetiredHistoryDisclosureAdmission;
/// fn duplicate<'a>(x: &RetiredHistoryDisclosureAdmission<'a>) -> RetiredHistoryDisclosureAdmission<'a> { x.clone() }
/// ```
/// ```compile_fail
/// use wholepact_signer::authority_bridge::retired_history::{RetiredHistoryDisclosureAdmission, RetiredHistoryAuditRecord};
/// fn upgrade(x: RetiredHistoryAuditRecord) -> RetiredHistoryDisclosureAdmission<'static> { x.into() }
/// ```
/// Import-only positive doc qualification keeps the compile-fail conversion
/// checks honest. Run the full doc suite on Linux, where these routes exist.
/// ```no_run
/// use wholepact_signer::consent_journal::{ApprovedSpendConsent, ApprovedEnrollment};
/// use wholepact_signer::authority_bridge::{dispatch_ipc::SignerDispatchAdmission, host_publication_ipc::HostRecoveryPublicationAdmission, retired_history::{RetiredHistoryAuditRecord, RetiredHistoryDisclosureAdmission}};
/// fn types_exist(_: Option<ApprovedSpendConsent>, _: Option<ApprovedEnrollment>, _: Option<SignerDispatchAdmission<'_>>, _: Option<HostRecoveryPublicationAdmission>, _: Option<RetiredHistoryAuditRecord>, _: Option<RetiredHistoryDisclosureAdmission<'_>>) {}
/// ```
pub struct RetiredHistoryDisclosureAdmission<'a> {
    record: RetiredHistoryAuditRecord,
    issued: Instant,
    current: Box<dyn Fn() -> Result<()> + 'a>,
}
impl RetiredHistoryDisclosureAdmission<'_> {
    pub fn audit_record(&self) -> &RetiredHistoryAuditRecord {
        &self.record
    }
    /// Consumes only the exact fresh disclosure result into inert audit data.
    /// This does not admit a disk write, financial action or a different recipient.
    pub fn into_audit_for(
        self,
        exact: &RetiredHistoryRequest,
    ) -> Result<RetiredHistoryAuditRecord> {
        (self.current)()?;
        require_exact_consumption(&self.record.request, exact, self.issued.elapsed())?;
        self.record.validate_audit()?;
        Ok(self.record)
    }
}
fn require_exact_consumption(
    actual: &RetiredHistoryRequest,
    exact: &RetiredHistoryRequest,
    age: Duration,
) -> Result<()> {
    exact.validate()?;
    if actual != exact || age >= DISCLOSURE_LIFETIME {
        return Err(BridgeError::Permission);
    }
    Ok(())
}
fn validate_recipient(recipient: &RetiredHistoryRecipient) -> Result<()> {
    for value in [
        &recipient.grant_id,
        &recipient.channel_digest,
        &recipient.process_instance,
    ] {
        hash(value)?;
    }
    if recipient.pid == 0 || recipient.application_label.is_empty() || recipient.application_label.len() > 256
        || recipient.application_label.chars().any(|c| c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
    { return Err(BridgeError::Binding); }
    Ok(())
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
fn canonical<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| BridgeError::Binding)
}

// No UI/IPC caller exists until genuine immutable born-vault ownership is wired.
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
#[allow(dead_code)]
pub(crate) mod native;
#[cfg(test)]
mod tests;
