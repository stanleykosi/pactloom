//! Bounded exact-operation descriptors. Deserializing evidence never authenticates it.
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PROTOCOL_VERSION: u16 = 2;

/// Exact remote recipient to show at native disclosure approval. Public identity
/// metadata only; no client credentials or session secrets are exposed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessDisclosureDescriptor {
    pub endpoint: String,
    pub server_name: String,
    pub witness_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub policy_digest: String,
    pub pinned_server_certificate_digest: String,
}
impl WitnessDisclosureDescriptor {
    pub fn validate(&self) -> Result<()> {
        for value in [&self.witness_id, &self.account_id, &self.network_profile_id] {
            id(value)?;
        }
        hash(&self.policy_digest)?;
        hash(&self.pinned_server_certificate_digest)?;
        let endpoint: std::net::SocketAddr = self
            .endpoint
            .parse()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        if endpoint.to_string() != self.endpoint
            || endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || endpoint.ip().is_multicast()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| AuthorityError::InvalidBinding)?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    /// Exact persisted append metadata, never portable admission authority.
    /// Omitted only for legacy events whose original hash omitted the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_request_link: Option<crate::offline_retry::OriginalCommitLink>,
    pub sequence: u64,
    pub previous_head: String,
    pub head: String,
    pub mutation: AuthorityMutation,
    pub authenticated_certificate_digest: String,
    pub witness_time_ms: u64,
    pub writer_session_id: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_birth_commit: Option<crate::pending_birth::PendingBirthCommitRecord>,
    pub policy: AccountPolicy,
    pub snapshot: AccountSnapshot,
    pub entries: Vec<HistoryEntry>,
    pub next_after_sequence: Option<u64>,
}

/// Complete verified witness history; cannot be fabricated by deserializing
/// summaries. Original permits are evidence, never newly minted signing tokens.
pub struct ReconciledAuthorityHistory {
    pub(crate) construction_transport_history:
        crate::construction_transport_handoff_v1::ConstructionTransportHistoryV1,
    pub(crate) manual_roster_construction_records_v3: std::collections::BTreeMap<
        String,
        crate::manual_roster_construction_v3::ManualRosterConstructionHistoryRecordV3,
    >,
    pub(crate) manual_roster_construction_records: std::collections::BTreeMap<
        String,
        crate::manual_roster_construction_v2::ManualRosterConstructionHistoryRecordV2,
    >,
    pub(crate) manual_roster_attempt:
        Option<crate::manual_roster_witness_v2::ManualRosterAttemptObservationV2>,
    pub(crate) manual_attempt: Option<crate::manual_session_continuation::ManualAttemptObservation>,
    pub(crate) pending_birth_commit: Option<crate::pending_birth::PendingBirthCommitRecord>,
    pub(crate) account_use_history: crate::account_use::AccountUseHistory,
    pub(crate) account_policy: AccountPolicy,
    pub(crate) snapshot: AccountSnapshot,
    pub(crate) permits: Vec<ReservationPermit>,
    pub(crate) offline_permits: Vec<crate::offline::OfflineAuthorizationAdmission>,
    pub(crate) born_offline_dispatches:
        Vec<crate::born_offline_dispatch_v1::BornOfflineDispatchAdmissionV1>,
    pub(crate) born_offline_permits:
        Vec<crate::born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1>,
    pub(crate) automatic_key_use_admissions: Vec<AutomaticKeyUseAdmission>,
    pub(crate) recovery_fences: Vec<RecoveryFenceReceipt>,
    pub(crate) committed_operation_ids: BTreeSet<String>,
    pub(crate) owner_controls: std::collections::BTreeMap<String, OwnerControlRequest>,
    pub(crate) history_heads: std::collections::BTreeMap<u64, String>,
    pub(crate) disclosure: WitnessDisclosureDescriptor,
}
impl ReconciledAuthorityHistory {
    /// Explicit compatibility admission for callers implementing only V2 origins.
    /// A V3 approval alone is retained history and cannot be silently dropped.
    pub fn require_construction_v2_only(&self) -> Result<()> {
        if !self.construction_transport_history.is_empty()
            || !self.manual_roster_construction_records_v3.is_empty()
            || self.owner_controls.values().any(|r| {
                matches!(
                    r.control,
                    OwnerControl::ApproveManualRosterConstructionV3 { .. }
                )
            })
        {
            return Err(AuthorityError::ConstructionHistoryUnsupported);
        }
        Ok(())
    }
    /// Original roster reentry may carry independently authenticated V3 approval
    /// evidence before its one read. This is never a Reserve/Consume replay path.
    pub fn require_original_roster_preconstruction_history(&self) -> Result<()> {
        self.account_use_history
            .require_not_permanently_excluded()?;
        if !self.permits.is_empty()
            || !self.offline_permits.is_empty()
            || !self.born_offline_permits.is_empty()
            || !self.automatic_key_use_admissions.is_empty()
            || !self.recovery_fences.is_empty()
            || !self.manual_roster_construction_records.is_empty()
            || !self.manual_roster_construction_records_v3.is_empty()
            || self.snapshot.outstanding_reservations != 0
            || self.snapshot.outstanding_debit_zatoshis != 0
            || self.snapshot.settled_debit_zatoshis != 0
            || self.snapshot.reserved_input_value_zatoshis != 0
            || self.snapshot.writer_status != WriterStatus::Active
        {
            return Err(AuthorityError::ConstructionHistoryUnsupported);
        }
        // A complete typed archive verifies every approval against the original
        // extension and birth, including retained exact V3 owner signatures.
        self.construction_history_v2()?.validate()?;
        Ok(())
    }
    /// Exact origin capabilities of this reader, never activation permission.
    pub fn supported_construction_origins(&self) -> &'static [u16] {
        if cfg!(feature = "pending-birth-foundation") {
            &[2, 3]
        } else {
            &[2]
        }
    }

    /// Immutable original birth metadata from the same authenticated complete
    /// history. Evidence only, never current enrollment or financial authority.
    pub fn pending_birth_commit(&self) -> Option<&crate::pending_birth::PendingBirthCommitRecord> {
        self.pending_birth_commit.as_ref()
    }
    /// Complete replay projection, never current financial admission.
    pub fn account_use_history(&self) -> &crate::account_use::AccountUseHistory {
        &self.account_use_history
    }
    /// Original owner-enrolled policy verified by complete authenticated replay.
    /// Reading it is not permission to mutate, disclose, reserve or use keys.
    pub fn account_policy(&self) -> &AccountPolicy {
        &self.account_policy
    }
    /// Owner transitions replayed from complete authenticated history. Audit
    /// evidence only; this does not mint a live recovery fence capability.
    /// Presence/absence from the complete replayed immutable history, never a
    /// truncated cursor or unauthenticated summary. Useful for exact retry review.
    /// Exact chain inclusion from full genesis-to-current replay.
    /// Historical immutable identity lookup, including superseded account caps.
    /// A historical match does not make that policy current again.
    pub fn automation_account_policy_by_id(
        &self,
        policy_id: &str,
    ) -> Option<&WitnessAutomationAccountPolicy> {
        self.owner_controls.values().find_map(|r| match &r.control {
            OwnerControl::SetAutomationGrant { account_policy, .. }
                if account_policy.policy_id == policy_id =>
            {
                Some(account_policy)
            }
            _ => None,
        })
    }
    pub fn automation_account_policy(&self) -> Option<&WitnessAutomationAccountPolicy> {
        self.owner_controls
            .values()
            .filter_map(|r| match &r.control {
                OwnerControl::SetAutomationGrant {
                    grant,
                    account_policy,
                } if grant.status == AutomationGrantStatus::Active => {
                    Some((r.expected_head.sequence, account_policy))
                }
                _ => None,
            })
            .max_by_key(|(sequence, _)| *sequence)
            .map(|(_, policy)| policy)
    }
    pub fn automation_grant(&self, grant_id: &str) -> Option<&WitnessAutomationGrant> {
        self.owner_controls
            .values()
            .filter_map(|r| match &r.control {
                OwnerControl::SetAutomationGrant { grant, .. }
                    if grant.binding.grant_id == grant_id =>
                {
                    Some(grant)
                }
                _ => None,
            })
            .max_by_key(|g| g.binding.revision)
    }
    pub fn contains_head(&self, head: &AuthorityHead) -> bool {
        self.history_heads.get(&head.sequence) == Some(&head.digest)
    }
    pub fn owner_control_request(&self, operation_id: &str) -> Option<&OwnerControlRequest> {
        self.owner_controls.get(operation_id)
    }
    /// Exact immutable enrollment from authenticated complete replay. This does
    /// not assert current policy status or create admission/key-use authority.
    /// Repeated distinct enrollment operations with the same policy digest are
    /// ambiguous provenance and fail closed, even if their policy bytes match.
    pub fn offline_enrollment_operation(
        &self,
        policy_digest: &str,
    ) -> Result<Option<&OwnerControlRequest>> {
        offline_enrollment_operation_from(self.owner_controls.values(), policy_digest)
    }

    pub fn contains_operation(&self, operation_id: &str) -> bool {
        self.committed_operation_ids.contains(operation_id)
    }
    pub fn recovery_fences(&self) -> &[RecoveryFenceReceipt] {
        &self.recovery_fences
    }
    pub fn snapshot(&self) -> &AccountSnapshot {
        &self.snapshot
    }
    /// Immutable complete-replay evidence only. These descriptors cannot mint
    /// or refresh an authenticated key-use admission or signer continuation.
    pub fn automatic_key_use_admissions(&self) -> &[AutomaticKeyUseAdmission] {
        &self.automatic_key_use_admissions
    }
    /// Legacy callers must explicitly reject history with offline origins.
    pub fn permits(&self) -> Result<&[ReservationPermit]> {
        self.require_legacy_online_only()?;
        Ok(&self.permits)
    }
    pub fn require_legacy_online_only(&self) -> Result<()> {
        self.require_construction_v2_only()?;
        if !self.offline_permits.is_empty() || !self.born_offline_permits.is_empty() {
            return Err(AuthorityError::OfflineHistoryUnsupported);
        }
        if !self.manual_roster_construction_records.is_empty()
            || !self.manual_roster_construction_records_v3.is_empty()
        {
            return Err(AuthorityError::ConstructionHistoryUnsupported);
        }
        Ok(())
    }
    /// Financial-origin evidence only. Non-signing construction history is
    /// independently available through manual_roster_construction_records_v2;
    /// callers must include that retained exposure or explicitly refuse it.
    pub fn reservation_evidence(&self) -> impl Iterator<Item = ReservationEvidenceRef<'_>> {
        let mut all: Vec<_> = self
            .permits
            .iter()
            .map(ReservationEvidenceRef::OnlineV2)
            .chain(
                self.offline_permits
                    .iter()
                    .map(ReservationEvidenceRef::OfflineV1),
            )
            .chain(
                self.born_offline_permits
                    .iter()
                    .map(ReservationEvidenceRef::BornOfflineV1),
            )
            .collect();
        all.sort_by_key(|entry| match entry {
            ReservationEvidenceRef::OnlineV2(p) => p.committed_head.sequence,
            ReservationEvidenceRef::OfflineV1(p) => p.committed_head.sequence,
            ReservationEvidenceRef::BornOfflineV1(p) => p.reserved.committed_head.sequence,
        });
        all.into_iter()
    }
    pub fn disclosure(&self) -> &WitnessDisclosureDescriptor {
        &self.disclosure
    }
    pub fn history_digest(&self) -> Result<String> {
        crate::session::history_digest(&self.snapshot)
    }
}

/// Owner-created policy retained by the witness, never a reservation argument.
/// Its amount/input linkages are sensitive. Enrolling a remote witness must
/// disclose its operator, location, retention and the complete transmitted fields.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_use_genesis: Option<crate::account_use::AccountUseGenesis>,
    pub witness_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub owner_certificate_digest: String,
    pub initial_writer_certificate_digest: String,
    pub initial_writer_epoch: u64,
    pub enrollment_refs: Vec<String>,
    pub agreement_ids: Vec<String>,
    pub recipient_scope_digests: Vec<String>,
    pub aggregate_budget_zatoshis: u64,
    pub per_operation_limit_zatoshis: u64,
    pub maximum_fee_share_zatoshis: u64,
    pub maximum_transaction_fee_zatoshis: u64,
    pub maximum_permit_lifetime_ms: u64,
    pub policy_expires_at_ms: u64,
}
impl AccountPolicy {
    pub fn validate(&self) -> Result<()> {
        if let Some(genesis) = &self.account_use_genesis {
            crate::account_use::AccountUseHistory::from_policy_genesis(
                genesis.clone(),
                &self.account_id,
                &self.network_profile_id,
                &self.witness_id,
                &self.owner_certificate_digest,
            )?;
        }
        for s in [&self.witness_id, &self.account_id, &self.network_profile_id] {
            id(s)?;
        }
        for h in [
            &self.owner_certificate_digest,
            &self.initial_writer_certificate_digest,
        ] {
            hash(h)?;
        }
        for values in [
            &self.enrollment_refs,
            &self.agreement_ids,
            &self.recipient_scope_digests,
        ] {
            if values.is_empty()
                || values.len() > 128
                || values.iter().collect::<BTreeSet<_>>().len() != values.len()
            {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        for h in self
            .enrollment_refs
            .iter()
            .chain(&self.recipient_scope_digests)
        {
            hash(h)?;
        }
        for s in &self.agreement_ids {
            id(s)?;
        }
        if self.initial_writer_epoch == 0
            || self.initial_writer_epoch > i64::MAX as u64
            || self.owner_certificate_digest == self.initial_writer_certificate_digest
            || self.aggregate_budget_zatoshis == 0
            || self.aggregate_budget_zatoshis > MAX_MONEY
            || self.per_operation_limit_zatoshis == 0
            || self.per_operation_limit_zatoshis > self.aggregate_budget_zatoshis
            || self.maximum_fee_share_zatoshis > self.per_operation_limit_zatoshis
            || self.maximum_fee_share_zatoshis > self.maximum_transaction_fee_zatoshis
            || self.maximum_transaction_fee_zatoshis > MAX_MONEY
            || self.maximum_permit_lifetime_ms == 0
            || self.maximum_permit_lifetime_ms > 7 * 24 * 60 * 60 * 1000
            || self.policy_expires_at_ms == 0
            || self.policy_expires_at_ms > i64::MAX as u64
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn policy_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:independent-authority-policy:v1", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHead {
    pub sequence: u64,
    pub digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputReservation {
    pub input_id: String,
    pub nullifier: String,
    pub action_index: u64,
    pub value_zatoshis: u64,
}

/// Complete exact offline-capable reservation descriptor. There is no generic
/// account lease and no caller-supplied budget. Retry these same bytes/fields on
/// response loss. Changing expected_head requires a new operation ID only when
/// the old operation is known to have failed, never after an uncertain response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReserveAuthorization {
    /// Absent for manual consent; omission preserves historical canonical bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automation: Option<AutomationGrantBinding>,
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub manifest_digest: String,
    pub effects_digest: String,
    pub artifact_digest: String,
    pub review_binding: String,
    pub recipient_scope_digest: String,
    pub inputs: Vec<InputReservation>,
    pub maximum_debit_zatoshis: u64,
    pub fee_share_zatoshis: u64,
    pub transaction_fee_zatoshis: u64,
    pub transaction_expiry_height: u32,
    pub reviewed_at_ms: u64,
    pub permit_expires_at_ms: u64,
}
impl ReserveAuthorization {
    pub fn validate(&self) -> Result<()> {
        if let Some(binding) = &self.automation {
            binding.validate()?;
        }
        for v in [
            &self.operation_id,
            &self.account_id,
            &self.network_profile_id,
            &self.authorization_id,
            &self.agreement_id,
            &self.obligation_id,
            &self.proposal_id,
        ] {
            id(v)?;
        }
        for v in [
            &self.expected_head.digest,
            &self.original_consent_ref,
            &self.enrollment_ref,
            &self.accepted_manifest_ref,
            &self.proposal_digest,
            &self.manifest_digest,
            &self.effects_digest,
            &self.artifact_digest,
            &self.review_binding,
            &self.recipient_scope_digest,
        ] {
            hash(v)?;
        }
        if self.writer_epoch == 0
            || self.writer_epoch > i64::MAX as u64
            || self.expected_head.sequence > MAX_EVENTS
            || self.inputs.is_empty()
            || self.inputs.len() > 256
            || self.maximum_debit_zatoshis == 0
            || self.maximum_debit_zatoshis > MAX_MONEY
            || self.fee_share_zatoshis > self.maximum_debit_zatoshis
            || self.fee_share_zatoshis > self.transaction_fee_zatoshis
            || self.transaction_fee_zatoshis > MAX_MONEY
            || self.transaction_expiry_height == 0
            || self.permit_expires_at_ms <= self.reviewed_at_ms
            || self.permit_expires_at_ms > i64::MAX as u64
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut ids = BTreeSet::new();
        let mut nfs = BTreeSet::new();
        let mut actions = BTreeSet::new();
        let mut value = 0_u64;
        for i in &self.inputs {
            id(&i.input_id)?;
            hash(&i.nullifier)?;
            if i.action_index > 255
                || i.value_zatoshis == 0
                || i.value_zatoshis > MAX_MONEY
                || !ids.insert(&i.input_id)
                || !nfs.insert(&i.nullifier)
                || !actions.insert(i.action_index)
            {
                return Err(AuthorityError::InvalidBinding);
            }
            value = value
                .checked_add(i.value_zatoshis)
                .ok_or(AuthorityError::InvalidBinding)?;
        }
        if value > MAX_MONEY || value < self.maximum_debit_zatoshis {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub fn request_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:reserve-authorization:v1", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriterStatus {
    Active,
    Paused,
    Revoked,
    Quarantined,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSnapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_fences:
        Option<crate::construction_transport_handoff_v1::ConstructionTransportFenceSnapshotV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_use_checkpoint: Option<crate::account_use::AccountUseCheckpoint>,
    pub witness_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub policy_digest: String,
    pub head: AuthorityHead,
    pub writer_epoch: u64,
    pub writer_certificate_digest: String,
    pub writer_status: WriterStatus,
    pub outstanding_reservations: u64,
    pub outstanding_debit_zatoshis: u64,
    /// Qualified consumed debit remains charged against the lifetime account budget.
    pub settled_debit_zatoshis: u64,
    pub aggregate_budget_zatoshis: u64,
    pub reserved_input_value_zatoshis: u64,
    pub last_witness_time_ms: u64,
    pub pending_writer_session: Option<WriterSessionReceipt>,
    pub active_writer_session: Option<WriterSessionReceipt>,
}

impl AccountSnapshot {
    /// A display calculation only. Reservations recheck the durable shared ledger
    /// atomically; a saved snapshot cannot confer authority or reserve this amount.
    pub fn remaining_budget_zatoshis(&self) -> Result<u64> {
        self.aggregate_budget_zatoshis
            .checked_sub(self.settled_debit_zatoshis)
            .and_then(|remaining| remaining.checked_sub(self.outstanding_debit_zatoshis))
            .ok_or(AuthorityError::BudgetExceeded)
    }
}

/// Historical evidence only unless carried by an opaque AuthenticatedPermit.
/// Its expiry limits use; it does not clear input/obligation/budget exposure.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationPermit {
    pub protocol_version: u16,
    pub witness_id: String,
    pub policy_digest: String,
    pub request_digest: String,
    pub request: ReserveAuthorization,
    pub committed_head: AuthorityHead,
    pub reserved_at_ms: u64,
    pub account_outstanding_debit_zatoshis: u64,
    pub account_reserved_input_value_zatoshis: u64,
    pub writer_session_id: String,
}
impl ReservationPermit {
    pub fn matches_request(&self, request: &ReserveAuthorization) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.request != *request
            || self.request_digest != request.request_digest()?
            || self.committed_head.sequence
                != request
                    .expected_head
                    .sequence
                    .checked_add(1)
                    .ok_or(AuthorityError::InvalidBinding)?
            || self.reserved_at_ms < request.reviewed_at_ms
            || self.reserved_at_ms >= request.permit_expires_at_ms
            || self.account_outstanding_debit_zatoshis < request.maximum_debit_zatoshis
        {
            return Err(AuthorityError::InvalidBinding);
        }
        id(&self.witness_id)?;
        hash(&self.writer_session_id)?;
        hash(&self.policy_digest)?;
        hash(&self.committed_head.digest)?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
// Keep the immutable owner-reviewed wire DTO directly inspectable; its encoded
// frame is already bounded and boxing would not change the protocol boundary.
#[allow(clippy::large_enum_variant)]
pub enum OwnerControl {
    /// Exact native setup only; remote mutation and parsed data cannot install keys.
    InstallBornOfflineArtifactsV1 {
        record: Box<crate::born_offline_artifacts_v1::BornOfflineArtifactRecordV1>,
    },
    /// Purpose-specific local native publication only. No remote DTO can enroll
    /// a born offline policy or bypass the existing legacy issuer restriction.
    EnrollBornOfflineV1 {
        record: Box<crate::born_offline_enrollment_v1::BornOfflineEnrollmentRecordV1>,
    },
    GrantConstructionTransportV1 {
        grant: Box<crate::construction_transport_handoff_v1::ConstructionTransportGrantV1>,
    },
    ApproveManualRosterConstructionV3 {
        record: Box<crate::manual_roster_construction_v3::ManualRosterConstructionApprovalRecordV3>,
    },
    /// Exact local-native approval only. The remote mutation route rejects it.
    ApproveManualRosterConstructionV2 {
        record: Box<crate::manual_roster_construction_v2::ManualRosterConstructionApprovalRecordV2>,
    },
    ExtendManualRosterEnrollmentV2 {
        record: Box<crate::manual_roster_witness_v2::ManualRosterEnrollmentExtensionRecordV2>,
    },
    ContinueManualRosterSessionV2 {
        record: Box<crate::manual_roster_witness_v2::ManualRosterSessionContinuationRecordV2>,
    },
    ContinueManualEnrollmentSession {
        record: Box<crate::manual_session_continuation::ManualEnrollmentSessionContinuationRecord>,
    },
    /// Journal-local native owner publication only; rejected at remote mutation boundary.
    ExtendManualEnrollment {
        record: Box<crate::manual_enrollment::ManualEnrollmentExtensionRecord>,
    },
    PermanentlyExcludeAccount {
        exclusion: crate::account_use::PermanentAccountExclusion,
    },
    EnrollOfflinePolicy {
        policy: crate::offline::OfflineEnrollmentPolicy,
        expected_previous_digest: Option<String>,
    },
    SetOfflinePolicyStatus {
        enrollment_ref: String,
        policy_digest: String,
        status: OfflineEnrollmentStatus,
    },
    SetAutomationGrant {
        grant: WitnessAutomationGrant,
        account_policy: WitnessAutomationAccountPolicy,
    },
    Pause,
    /// Owner-authenticated enrollment of the exact disclosed validating source.
    EnrollResolutionSource {
        source_descriptor_digest: String,
    },
    Revoke,
    /// A replacement is a new epoch; it does not cancel any issued permit.
    ReplaceWriter {
        writer_certificate_digest: String,
    },
    /// Recovery-specific replacement at a surviving witness. The enclosing
    /// operation ID and exact inventory digest bind the restored successor.
    /// This never revokes issued signatures or removes outstanding exposure.
    RecoverWriter {
        writer_certificate_digest: String,
        inventory_digest: String,
    },
    /// One-way quarantine. There is deliberately no unquarantine/reset action.
    RequireRecovery,
    /// Explicit owner activation of a fresh, completely reconciled TLS session.
    ActivateWriter {
        session_id: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquireWriterRequest {
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub reconciled_history_digest: String,
    pub session_id: String,
    pub disclosure: WitnessDisclosureDescriptor,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterSessionReceipt {
    pub session_id: String,
    pub writer_certificate_digest: String,
    pub writer_epoch: u64,
    pub reconciled_head: AuthorityHead,
    pub reconciled_history_digest: String,
    pub acquired_head: AuthorityHead,
    pub expires_at_ms: u64,
    pub acquired_at_ms: u64,
    pub disclosure: WitnessDisclosureDescriptor,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationProgress {
    Prepared,
    SignatureProduced,
    Released,
    SubmissionUncertain,
    ObservationRecorded,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportProgress {
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub reservation_operation_id: String,
    pub reservation_request_digest: String,
    pub progress: AuthorizationProgress,
    pub evidence_digest: String,
}
/// Exact admission of already-signed retained transaction bytes. The backend
/// disclosure digest is separately native-approved; the witness does not endorse
/// that backend or establish chain finality. The original signing window does not
/// recall an already produced signature. A fresh dispatch window is required.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeDispatch {
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub reservation_operation_id: String,
    pub reservation_request_digest: String,
    /// Lowercase SHA-256 of the exact canonical retained transaction wire bytes.
    pub final_transaction_digest: String,
    /// Canonical transaction ID derived by the maintained protocol implementation.
    pub final_transaction_id: String,
    pub transaction_expiry_height: u32,
    pub backend_disclosure_digest: String,
    pub reviewed_at_ms: u64,
    pub admission_expires_at_ms: u64,
}
impl AuthorizeDispatch {
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.operation_id,
            &self.account_id,
            &self.network_profile_id,
            &self.reservation_operation_id,
        ] {
            id(value)?;
        }
        for value in [
            &self.expected_head.digest,
            &self.reservation_request_digest,
            &self.final_transaction_digest,
            &self.final_transaction_id,
            &self.backend_disclosure_digest,
        ] {
            hash(value)?;
        }
        if self.writer_epoch == 0
            || self.writer_epoch > i64::MAX as u64
            || self.transaction_expiry_height == 0
            || self.admission_expires_at_ms <= self.reviewed_at_ms
            || self.admission_expires_at_ms > i64::MAX as u64
            || self.admission_expires_at_ms - self.reviewed_at_ms > 120_000
        {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub fn request_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:authorize-exact-dispatch:v2", self)
    }
}

/// Historical evidence after serialization. Only AuthenticatedDispatchAdmission
/// proves this process received the exact committed admission over enrolled mTLS.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchAdmission {
    pub protocol_version: u16,
    pub witness_id: String,
    pub policy_digest: String,
    pub request_digest: String,
    pub request: AuthorizeDispatch,
    pub reservation: ReservationPermit,
    pub committed_head: AuthorityHead,
    pub admitted_at_ms: u64,
    pub writer_session_id: String,
}
impl DispatchAdmission {
    pub fn matches_request(&self, request: &AuthorizeDispatch) -> Result<()> {
        request.validate()?;
        self.reservation
            .matches_request(&self.reservation.request)?;
        if self.protocol_version != PROTOCOL_VERSION
            || self.request != *request
            || self.request_digest != request.request_digest()?
            || self.witness_id != self.reservation.witness_id
            || self.policy_digest != self.reservation.policy_digest
            || request.reservation_operation_id != self.reservation.request.operation_id
            || request.reservation_request_digest != self.reservation.request_digest
            || request.account_id != self.reservation.request.account_id
            || request.network_profile_id != self.reservation.request.network_profile_id
            || request.transaction_expiry_height
                != self.reservation.request.transaction_expiry_height
            || self.admitted_at_ms < request.reviewed_at_ms
            || self.admitted_at_ms >= request.admission_expires_at_ms
            || self.committed_head.sequence
                != request
                    .expected_head
                    .sequence
                    .checked_add(1)
                    .ok_or(AuthorityError::InvalidBinding)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        hash(&self.writer_session_id)?;
        hash(&self.committed_head.digest)?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerControlRequest {
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub expected_head: AuthorityHead,
    pub writer_epoch: u64,
    pub control: OwnerControl,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "method",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AuthorityMutation {
    ClaimConstructionTransportV1(
        Box<crate::construction_transport_handoff_v1::SignedConstructionTransportClaimV1>,
    ),
    UseConstructionTransportV1(
        Box<crate::construction_transport_handoff_v1::ConstructionTransportRequestV1>,
    ),
    ReserveManualRosterConstructionV3(
        Box<crate::manual_roster_construction_v3::ManualRosterConstructionReservationRequestV3>,
    ),
    ConsumeManualRosterConstructionV3(
        crate::manual_roster_construction_v3::ManualRosterConstructionConsumeRequestV3,
    ),
    ReserveManualRosterConstructionV2(
        Box<crate::manual_roster_construction_v2::ManualRosterConstructionReservationRequestV2>,
    ),
    ConsumeManualRosterConstructionV2(
        crate::manual_roster_construction_v2::ManualRosterConstructionConsumeRequestV2,
    ),
    AdmitBornManualRosterEnrollmentV2(
        crate::manual_roster_witness_v2::BornManualRosterAdmissionRequestV2,
    ),
    AdmitBornManualEnrollment(crate::manual_enrollment::BornManualEnrollmentAdmissionRequest),
    AdmitBornManualEnrollmentV2(
        crate::manual_session_continuation::BornManualEnrollmentAdmissionRequestV2,
    ),
    ReserveBornOfflineV1(Box<crate::born_offline_admission_v1::BornOfflineReservationRecordV1>),
    ReserveOfflineAuthorization(Box<OfflineReservationRecord>),
    AuthorizeAutomaticKeyUse(AuthorizeAutomaticKeyUse),
    ReserveAuthorization(Box<ReserveAuthorization>),
    OwnerControl(OwnerControlRequest),
    AcquireWriter(AcquireWriterRequest),
    ReportProgress(ReportProgress),
    AuthorizeDispatch(AuthorizeDispatch),
    AuthorizeBornOfflineDispatchV1(
        Box<crate::born_offline_dispatch_v1::BornOfflineDispatchRequestV1>,
    ),
    /// Journal-internal only. The remote mutation boundary rejects this variant.
    QualifiedResolution(ResolutionRecord),
    /// Conservative internal reopening of every previously resolved reservation.
    ReopenResolutions(ReopenResolutions),
}
impl AuthorityMutation {
    pub fn operation_id(&self) -> &str {
        match self {
            Self::ClaimConstructionTransportV1(r) => &r.claim.operation_id,
            Self::UseConstructionTransportV1(r) => r.operation_id(),
            Self::ReserveManualRosterConstructionV3(r) => &r.construction.operation_id,
            Self::ConsumeManualRosterConstructionV3(r) => &r.operation_id,
            Self::ReserveManualRosterConstructionV2(r) => &r.construction.operation_id,
            Self::ConsumeManualRosterConstructionV2(r) => &r.operation_id,
            Self::AdmitBornManualRosterEnrollmentV2(r) => &r.operation_id,
            Self::AdmitBornManualEnrollment(r) => &r.operation_id,
            Self::AdmitBornManualEnrollmentV2(r) => &r.operation_id,
            Self::ReserveBornOfflineV1(r) => &r.request.reservation.operation_id,
            Self::ReserveOfflineAuthorization(r) => &r.request.operation_id,
            Self::AuthorizeAutomaticKeyUse(r) => &r.operation_id,
            Self::ReserveAuthorization(r) => &r.operation_id,
            Self::OwnerControl(r) => &r.operation_id,
            Self::AcquireWriter(r) => &r.operation_id,
            Self::ReportProgress(r) => &r.operation_id,
            Self::AuthorizeDispatch(r) => &r.operation_id,
            Self::AuthorizeBornOfflineDispatchV1(r) => &r.dispatch.operation_id,
            Self::QualifiedResolution(r) => &r.operation_id,
            Self::ReopenResolutions(r) => &r.operation_id,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "result",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum MutationResult {
    ConstructionTransportClaimedV1(
        Box<crate::construction_transport_handoff_v1::ConstructionTransportCredentialV1>,
    ),
    ConstructionTransportReservedV1(
        Box<crate::construction_transport_handoff_v1::ConstructionTransportReservationRecordV1>,
    ),
    ConstructionTransportConsumedV1(
        Box<crate::construction_transport_handoff_v1::ConstructionTransportConsumedRecordV1>,
    ),
    ManualRosterConstructionReservedV3(
        Box<crate::manual_roster_construction_v3::ManualRosterConstructionReservationRecordV3>,
    ),
    ManualRosterConstructionConsumedV3(
        Box<crate::manual_roster_construction_v3::ManualRosterConstructionConsumedRecordV3>,
    ),
    ManualRosterConstructionReservedV2(
        Box<crate::manual_roster_construction_v2::ManualRosterConstructionReservationRecordV2>,
    ),
    ManualRosterConstructionConsumedV2(
        Box<crate::manual_roster_construction_v2::ManualRosterConstructionConsumedRecordV2>,
    ),
    ManualRosterEnrollmentAdmittedV2(
        Box<crate::manual_roster_witness_v2::BornManualRosterAdmissionRecordV2>,
    ),
    ManualEnrollmentAdmitted(Box<crate::manual_enrollment::BornManualEnrollmentAdmissionRecord>),
    ManualEnrollmentAdmittedV2(
        Box<crate::manual_session_continuation::BornManualEnrollmentAdmissionRecordV2>,
    ),
    BornOfflineReservedV1(
        Box<crate::born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1>,
    ),
    OfflineReserved(Box<crate::offline::OfflineAuthorizationAdmission>),
    AutomaticKeyUseAdmitted(Box<AutomaticKeyUseAdmission>),
    Reserved(Box<ReservationPermit>),
    Controlled(AccountSnapshot),
    WriterPending(WriterSessionReceipt),
    ProgressRecorded(AccountSnapshot),
    DispatchAdmitted(Box<DispatchAdmission>),
    BornOfflineDispatchAdmittedV1(
        Box<crate::born_offline_dispatch_v1::BornOfflineDispatchAdmissionV1>,
    ),
    ResolutionRecorded(Box<ResolutionReceipt>),
    ResolutionsReopened(AccountSnapshot),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WriterSessionProof {
    pub session_id: String,
    pub tag: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "method",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum WireRequest {
    ObserveBornOfflineAdmissionTimeV1(Box<crate::born_offline_clock_v1::BornOfflineClockRequestV1>),
    AuthorizeBornOfflineDispatchV1 {
        request: Box<crate::born_offline_dispatch_v1::BornOfflineDispatchRequestV1>,
        authentication:
            crate::born_offline_owner_continuation_v1::BornOfflineTransportAuthenticationV1,
    },
    SubmitBornOfflineIntentV1(Box<crate::born_offline_witness_v1::BornOfflineWitnessRequestV1>),
    RecoverBornOfflineDeliveryV1(crate::born_offline_witness_v1::BornOfflineDeliveryLookupV1),
    SubmitOfflineIntentV1(Box<crate::offline_witness_v1::OfflineWitnessRequestV1>),
    RecoverOfflineAdmissionDeliveryV1(crate::offline_witness_v1::OfflineAdmissionDeliveryLookupV1),
    ObserveOfflineAdmissionTimeV1(Box<crate::offline_clock_v1::OfflineClockRequestV1>),
    ClaimConstructionTransport {
        claim: Box<crate::construction_transport_handoff_v1::SignedConstructionTransportClaimV1>,
    },
    ObserveConstructionTransport {
        credential_id: String,
        proof: crate::construction_transport_handoff_v1::ConstructionTransportProofV1,
    },
    MutateConstructionTransport {
        request: Box<crate::construction_transport_handoff_v1::ConstructionTransportRequestV1>,
        proof: crate::construction_transport_handoff_v1::ConstructionTransportProofV1,
    },
    ResolveReservation {
        account_id: String,
        network_profile_id: String,
        reservation_operation_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        conflict: Option<wholepact_chain::local_node::CanonicalConflictCandidate>,
    },
    Snapshot {
        account_id: String,
        network_profile_id: String,
    },
    Mutate {
        mutation: Box<AuthorityMutation>,
        session_proof: Option<WriterSessionProof>,
    },
    ReadHistory {
        account_id: String,
        network_profile_id: String,
        expected_head: AuthorityHead,
        after_sequence: u64,
        maximum_entries: u16,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "result",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum WireResponse {
    BornOfflineAdmissionTimeV1(Box<crate::born_offline_clock_v1::BornOfflineClockResponseV1>),
    BornOfflineDispatchV1(Box<crate::born_offline_dispatch_v1::BornOfflineDispatchAdmissionV1>),
    BornOfflineDeliveryV1(Box<crate::born_offline_witness_v1::BornOfflineDeliveryBodyV1>),
    OfflineAdmissionDeliveryV1(Box<crate::offline_witness_v1::OfflineWitnessDeliveryBodyV1>),
    OfflineAdmissionTimeV1(Box<crate::offline_clock_v1::OfflineClockResponseV1>),
    ConstructionTransportClaimed(
        Box<crate::construction_transport_handoff_v1::ConstructionTransportCredentialV1>,
    ),
    ConstructionTransportObserved(
        Box<crate::construction_transport_handoff_v1::ConstructionTransportObservationV1>,
    ),
    Resolution(Box<ResolutionReceipt>),
    Snapshot(AccountSnapshot),
    Mutation(MutationResult),
    Rejected(AuthorityError),
    History(Box<HistoryPage>),
}

/// Audit evidence only; public/deserialized values never authorize a ledger write.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionRecord {
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub expected_head: AuthorityHead,
    pub reservation_operation_id: String,
    pub reservation_request_digest: String,
    pub final_transaction_id: String,
    pub final_transaction_digest: String,
    pub source_descriptor_digest: String,
    pub evidence_digest: String,
    pub consumed_nullifiers: Vec<String>,
    /// Retained alternative link, not replacement permission. For conflicts the
    /// original debit/input reservations remain conservatively charged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict: Option<wholepact_chain::local_node::CanonicalConflictCandidate>,
    pub inclusion_block_hash: String,
    pub inclusion_block_height: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionReceipt {
    pub record: ResolutionRecord,
    pub committed_head: AuthorityHead,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReopenResolutions {
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub expected_head: AuthorityHead,
}

/// Complete historical reservation origin. Evidence only, never key permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "origin",
    content = "evidence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ReservationEvidence {
    OnlineV2(Box<ReservationPermit>),
    OfflineV1(Box<crate::offline::OfflineAuthorizationAdmission>),
    BornOfflineV1(Box<crate::born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1>),
}
pub enum ReservationEvidenceRef<'a> {
    OnlineV2(&'a ReservationPermit),
    OfflineV1(&'a crate::offline::OfflineAuthorizationAdmission),
    BornOfflineV1(&'a crate::born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1),
}

// Pure matching only; the public entry point owns the authenticated replay.
fn offline_enrollment_operation_from<'a>(
    operations: impl Iterator<Item = &'a OwnerControlRequest>,
    policy_digest: &str,
) -> Result<Option<&'a OwnerControlRequest>> {
    hash(policy_digest)?;
    let mut found = None;
    for operation in operations {
        if let OwnerControl::EnrollOfflinePolicy { policy, .. } = &operation.control {
            if policy.policy_digest()? == policy_digest {
                if found.is_some() {
                    return Err(AuthorityError::Conflict);
                }
                found = Some(operation);
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
#[path = "offline_enrollment_lookup_tests.rs"]
mod offline_enrollment_lookup_tests;
