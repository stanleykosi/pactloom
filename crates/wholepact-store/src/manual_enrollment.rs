//! Generation-local manual audit and historical projection. Optional Linux
//! audit appenders consume concrete installed-signer leases. Append success is
//! never financial authority; existing recovered-generation denials remain.
//! Native Host plan/profile/registry/inherited-identity conjunction is separate.
mod fail_fast;
use fail_fast::ManualPersistenceMode;

use crate::{
    Result, StorageProtection, Store, StoreError, StoredRecord, request_digest, validate_id,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_core::manual_enrollment::{
    BornManualActionIntent, BornManualEnrollmentTerms, ManualAccountIdentity,
};
use wholepact_storage_security::bundle::recovery::generation::GenerationBinding;

pub(crate) const ENROLLMENT: &str = "generation_manual_enrollment_v1";
pub(crate) const SCOPE: &str = "generation_manual_action_v1";
pub(crate) const CONTINUATION: &str = "generation_manual_enrollment_continuation_v2";
pub(crate) const INITIAL_PUBLICATION_V2: &str =
    "generation_manual_enrollment_initial_publication_v2";
pub(crate) const CONTINUATION_V3: &str = "generation_manual_enrollment_continuation_v3";
pub(crate) const ADDITIONAL_PUBLICATION_V3: &str =
    "generation_manual_enrollment_additional_publication_v3";
pub(crate) const CONTINUATION_V4: &str = "generation_manual_enrollment_continuation_v4";
mod additional_publication;
pub use additional_publication::{
    ManualEnrollmentAdditionalPublicationV3, ManualEnrollmentContinuationAuditV4,
    ManualRosterAdmissionV2, ManualRosterEnrollmentEvidenceV2, ManualRosterPublicationAttemptV2,
    ManualRosterPublicationRequestV2,
};
mod initial_publication;
pub use initial_publication::{
    ManualEnrollmentContinuationAuditV3, ManualEnrollmentInitialPublicationV2,
    ManualEnrollmentProjection, ManualInitialAdmissionProvenance,
    OriginalManualEnrollmentAuditLink,
};
mod continuation;
pub use continuation::{
    ManualContinuationAdmissionV2, ManualContinuationCurrentAudit, ManualContinuationEnrollment,
    ManualContinuationEvidenceV2, ManualContinuationRequestV2, ManualEnrollmentContinuationAudit,
};

pub(crate) mod permanent_stop_record;
pub use permanent_stop_record::ManualPermanentStopPublicationV1;
pub(crate) use permanent_stop_record::{PERMANENT_STOP_V1, validate_permanent_stop_set};

pub(crate) const EXCLUSION: &str = "generation_manual_exclusion_v1";
const MAX_AUDITS: usize = 4096;
const MAX_AUDIT_BYTES: u64 = 64 * 1024 * 1024;

/// Historical immutable metadata only. The common terms carry the exact original
/// birth/genesis/witness, actual signer target, host generation and one-obligation
/// manual scope. Current owner/session/history facts are checked anew per effect.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentAudit {
    pub version: u16,
    pub terms: BornManualEnrollmentTerms,
    pub admission: ManualDurableEnrollmentAudit,
    pub enrollment_ref: String,
    pub witness_extension_digest: String,
    pub witness_extension_sequence: u64,
    pub witness_extension_predecessor_digest: Option<String>,
    pub aliases: BTreeSet<String>,
    pub store_sequence: u64,
    /// Store's canonical principal+idempotency identity, not a raw retry key.
    pub request_identity_digest: String,
    pub original_provider_enrollment_ref: String,
    pub original_complete_history_digest: String,
    pub original_exclusion_checkpoint_digest: String,
    pub original_native_review_digest: String,
}
impl ManualEnrollmentAudit {
    pub fn validate(&self) -> Result<()> {
        self.terms
            .validate()
            .map_err(|_| StoreError::RecoveryRequired)?;
        self.admission.validate_for(&self.terms)?;
        identity(&self.terms.identity, &self.aliases)?;
        for value in [
            &self.enrollment_ref,
            &self.witness_extension_digest,
            &self.request_identity_digest,
            &self.original_provider_enrollment_ref,
            &self.original_complete_history_digest,
            &self.original_exclusion_checkpoint_digest,
            &self.original_native_review_digest,
        ] {
            hash(value)?;
        }
        if let Some(value) = &self.witness_extension_predecessor_digest {
            hash(value)?;
        }
        if self.version != 1
            || self.witness_extension_sequence == 0
            || self.store_sequence == 0
            || self.store_sequence > MAX_AUDITS as u64
            || (self.witness_extension_sequence == 1)
                != self.witness_extension_predecessor_digest.is_none()
            || (self.store_sequence == 1) != self.terms.host.scope_predecessor_digest.is_none()
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        domain_digest("wholepact:store-manual-enrollment-audit:v1", self)
    }
}

/// Retained exact action intent and original audit evidence. Neither reading it
/// nor returning an exact retry creates a new invocation or reuses a live lease.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualActionAudit {
    pub version: u16,
    pub enrollment_audit_digest: String,
    pub witness_extension_digest: String,
    pub intent: BornManualActionIntent,
    pub admission: ManualDurableActionAudit,
    pub provider_enrollment_ref: String,
    pub complete_history_digest: String,
    pub exclusion_checkpoint_digest: String,
    pub native_review_digest: String,
}
impl ManualActionAudit {
    fn validate_shape(&self) -> Result<()> {
        if self.version != 1 {
            return Err(StoreError::RecoveryRequired);
        }
        for value in [
            &self.enrollment_audit_digest,
            &self.witness_extension_digest,
            &self.provider_enrollment_ref,
            &self.complete_history_digest,
            &self.exclusion_checkpoint_digest,
            &self.native_review_digest,
            &self.intent.enrollment_ref,
            &self.intent.manifest_digest,
            &self.intent.idempotency_key_digest,
            &self.intent.input_set_digest,
            &self.intent.exact_request_digest,
            &self.intent.invocation_nonce,
        ] {
            hash(value)?;
        }
        for value in [
            &self.intent.candidate_id,
            &self.intent.proposal_id,
            &self.intent.obligation_id,
            &self.intent.operation_id,
        ] {
            validate_id(value)?;
        }
        self.admission.validate_shape()?;
        if self.intent.version != 1 {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn validate_for(&self, enrollment: &ManualEnrollmentAudit) -> Result<()> {
        self.validate_shape()?;
        enrollment.validate()?;
        self.admission.validate_for(enrollment, &self.intent)?;
        self.intent
            .validate_for(&enrollment.terms, &enrollment.enrollment_ref)
            .map_err(|_| StoreError::RecoveryRequired)?;
        if self.enrollment_audit_digest != enrollment.digest()?
            || self.witness_extension_digest != enrollment.witness_extension_digest
            || self.provider_enrollment_ref != enrollment.original_provider_enrollment_ref
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate_shape()?;
        domain_digest("wholepact:store-manual-action-audit:v1", self)
    }
}

/// Exact original enrollment-publication admission. Its separate finite window
/// is not a spending permit and cannot renew after transport/restart retries.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualDurableEnrollmentAudit {
    pub exact_request_digest: String,
    pub signer_intent_digest: String,
    pub witness_admission_digest: String,
    pub admitted_at_ms: u64,
    pub admission_deadline_ms: u64,
}
impl ManualDurableEnrollmentAudit {
    fn validate_for(&self, terms: &BornManualEnrollmentTerms) -> Result<()> {
        for value in [
            &self.exact_request_digest,
            &self.signer_intent_digest,
            &self.witness_admission_digest,
        ] {
            hash(value)?;
        }
        if self.exact_request_digest != enrollment_request_digest(terms)?
            || self.admitted_at_ms == 0
            || self.admitted_at_ms < terms.issued_at_ms
            || self.admission_deadline_ms <= self.admitted_at_ms
            || self.admission_deadline_ms > i64::MAX as u64
            || self.admission_deadline_ms > terms.scope.expires_at_ms
            || self.admission_deadline_ms - self.admitted_at_ms > 120_000
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
}
fn enrollment_request_digest(terms: &BornManualEnrollmentTerms) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:host-manual-enrollment-request:v1",
        &serde_json::json!({"terms": terms}),
    )
    .map_err(|_| StoreError::RecoveryRequired)
}

/// Platform-independent exact mirror of the bridge's durable action audit.
/// Scalar metadata cannot construct a lease or repeat the admitted operation.
/// Both original timestamps and producer commitments are immutable on retry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualDurableActionAudit {
    pub exact_request_digest: String,
    pub signer_intent_digest: String,
    pub witness_admission_digest: String,
    pub admitted_at_ms: u64,
    pub admission_deadline_ms: u64,
}
impl ManualDurableActionAudit {
    fn validate_shape(&self) -> Result<()> {
        for value in [
            &self.exact_request_digest,
            &self.signer_intent_digest,
            &self.witness_admission_digest,
        ] {
            hash(value)?;
        }
        if self.admitted_at_ms == 0
            || self.admission_deadline_ms <= self.admitted_at_ms
            || self.admission_deadline_ms > i64::MAX as u64
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    fn validate_for(
        &self,
        enrollment: &ManualEnrollmentAudit,
        intent: &BornManualActionIntent,
    ) -> Result<()> {
        self.validate_shape()?;
        let digest = action_request_digest(
            &enrollment.terms,
            &enrollment.enrollment_ref,
            &enrollment.witness_extension_digest,
            intent,
        )?;
        if self.exact_request_digest != digest
            || self.admitted_at_ms < enrollment.terms.issued_at_ms
            || self.admission_deadline_ms > enrollment.terms.scope.expires_at_ms
            || self.admission_deadline_ms - self.admitted_at_ms
                > enrollment.terms.scope.maximum_permit_lifetime_ms
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
}
fn action_request_digest(
    terms: &BornManualEnrollmentTerms,
    enrollment_ref: &str,
    extension: &str,
    intent: &BornManualActionIntent,
) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:host-manual-action-request:v1",
        &serde_json::json!({
            "enrollment": terms, "enrollment_ref": enrollment_ref,
            "witness_extension_digest": extension, "intent": intent,
        }),
    )
    .map_err(|_| StoreError::RecoveryRequired)
}

/// Monotone restriction mirror. Absence is never complete exclusion history.
/// Original signer/witness exclusion remains authoritative and is checked live.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualExclusionAudit {
    pub version: u16,
    pub operation_id: String,
    pub identity: ManualAccountIdentity,
    pub aliases: BTreeSet<String>,
    pub account_use_genesis_digest: String,
    pub exclusion_digest: String,
    pub witness_history_digest: String,
}
impl ManualExclusionAudit {
    pub fn validate(&self) -> Result<()> {
        identity(&self.identity, &self.aliases)?;
        validate_id(&self.operation_id)?;
        for value in [
            &self.account_use_genesis_digest,
            &self.exclusion_digest,
            &self.witness_history_digest,
        ] {
            hash(value)?;
        }
        if self.version != 1 {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        domain_digest("wholepact:store-manual-exclusion-audit:v1", self)
    }
}
fn identity(identity: &ManualAccountIdentity, aliases: &BTreeSet<String>) -> Result<()> {
    hash(&identity.account_id)?;
    hash(&identity.full_viewing_key_digest)?;
    validate_id(&identity.network_profile_id)?;
    if identity.derivation_domain != "dedicated-testnet-legacy-zip32-v1"
        || aliases.is_empty()
        || aliases.len() > 64
        || !aliases.contains(&identity.account_id)
    {
        return Err(StoreError::RecoveryRequired);
    }
    for alias in aliases {
        validate_id(alias)?;
    }
    Ok(())
}
fn overlaps(
    a: &ManualAccountIdentity,
    aa: &BTreeSet<String>,
    b: &ManualAccountIdentity,
    ba: &BTreeSet<String>,
) -> bool {
    a.account_id == b.account_id
        || a.full_viewing_key_digest == b.full_viewing_key_digest
        || !aa.is_disjoint(ba)
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}
fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    request_digest(&serde_json::json!([domain, value]))
}
fn strict<T: serde::de::DeserializeOwned + Serialize>(value: &serde_json::Value) -> Result<T> {
    let decoded: T = serde_json::from_value(value.clone())?;
    if serde_json::to_value(&decoded)? != *value {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(decoded)
}
pub(crate) fn validate_recovery_record(
    kind: &str,
    record: &StoredRecord,
) -> Result<BTreeSet<String>> {
    let (digest, accounts) = match kind {
        ENROLLMENT => {
            let a = strict::<ManualEnrollmentAudit>(&record.payload)?;
            (a.digest()?, a.aliases)
        }
        INITIAL_PUBLICATION_V2 => {
            let a = strict::<ManualEnrollmentInitialPublicationV2>(&record.payload)?;
            (a.digest()?, a.aliases)
        }
        ADDITIONAL_PUBLICATION_V3 => {
            let a = strict::<ManualEnrollmentAdditionalPublicationV3>(&record.payload)?;
            (a.digest()?, a.aliases)
        }
        CONTINUATION_V4 => {
            let a = strict::<ManualEnrollmentContinuationAuditV4>(&record.payload)?;
            (a.digest()?, a.aliases)
        }
        CONTINUATION_V3 => {
            let a = strict::<ManualEnrollmentContinuationAuditV3>(&record.payload)?;
            (a.digest()?, a.aliases)
        }
        CONTINUATION => {
            let a = strict::<ManualEnrollmentContinuationAudit>(&record.payload)?;
            (a.digest()?, a.aliases)
        }
        SCOPE => (
            strict::<ManualActionAudit>(&record.payload)?.digest()?,
            BTreeSet::new(),
        ),
        PERMANENT_STOP_V1 => {
            let a = strict::<ManualPermanentStopPublicationV1>(&record.payload)?;
            (a.digest()?, a.exclusion.aliases)
        }
        EXCLUSION => {
            let a = strict::<ManualExclusionAudit>(&record.payload)?;
            (a.digest()?, a.aliases)
        }
        _ => return Err(StoreError::RecoveryRequired),
    };
    if record.id != digest
        || record.revision != 0
        || record.created_at_ms < 0
        || record.updated_at_ms != record.created_at_ms
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(accounts)
}
fn read_audits<T: serde::de::DeserializeOwned + Serialize>(
    c: &rusqlite::Connection,
    kind: &str,
) -> Result<Vec<(String, T)>> {
    let (count,bytes):(u64,u64)=c.query_row("SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM records WHERE aggregate_type=?1",[kind],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if count > MAX_AUDITS as u64 || bytes > MAX_AUDIT_BYTES {
        return Err(StoreError::ResourceExhausted);
    }
    let mut q=c.prepare("SELECT id,revision,payload,created_at_ms,updated_at_ms FROM records WHERE aggregate_type=?1 ORDER BY id")?;
    let raw = q
        .query_map([kind], crate::record_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    raw.into_iter()
        .map(|row| {
            let record = crate::decode_record(row)?;
            validate_recovery_record(kind, &record)?;
            let value = strict(&record.payload)?;
            Ok((record.id, value))
        })
        .collect()
}

/// Restriction-only separation from the generic command/effect namespaces.
/// Audit identities remain occupied even after recovery and exact action expiry.
pub(crate) fn require_generic_request_not_manual(
    c: &rusqlite::Connection,
    context: &crate::CommandContext,
) -> Result<()> {
    let identity = request_digest(&serde_json::json!([
        &context.principal_id,
        &context.idempotency_key
    ]))?;
    for (_, claim) in construction_claim_v2::read_construction_rows(c)?.0 {
        if claim.request_identity()? == identity {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, claim) in construction_claim_v3::read_construction_rows(c)?.0 {
        if claim.request_identity()? == identity {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualEnrollmentAudit>(c, ENROLLMENT)? {
        if audit.request_identity_digest == identity {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualActionAudit>(c, SCOPE)? {
        if audit.intent.idempotency_key_digest == identity {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualEnrollmentContinuationAudit>(c, CONTINUATION)? {
        if audit.request_identity_digest == identity {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in
        read_audits::<ManualEnrollmentInitialPublicationV2>(c, INITIAL_PUBLICATION_V2)?
    {
        if audit.request_identity_digest == identity {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualEnrollmentContinuationAuditV3>(c, CONTINUATION_V3)? {
        if audit.request_identity_digest == identity {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(c, ADDITIONAL_PUBLICATION_V3)?
    {
        if audit.request_identity_digest == identity {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualEnrollmentContinuationAuditV4>(c, CONTINUATION_V4)? {
        if audit.request_identity_digest == identity {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    require_generic_operation_not_manual(c, &crate::operation_id(context))
}
pub(crate) fn require_generic_operation_not_manual(
    c: &rusqlite::Connection,
    operation: &str,
) -> Result<()> {
    for (_, claim) in construction_claim_v2::read_construction_rows(c)?.0 {
        if claim.invocation().operation_id == operation
            || claim
                .consumed
                .iter()
                .any(|a| a.request.operation_id == operation)
        {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, claim) in construction_claim_v3::read_construction_rows(c)?.0 {
        if claim.invocation().operation_id == operation
            || claim
                .consumed
                .iter()
                .any(|a| a.request.operation_id == operation)
        {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualEnrollmentAudit>(c, ENROLLMENT)? {
        if audit.terms.operation_id == operation {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualActionAudit>(c, SCOPE)? {
        if audit.intent.operation_id == operation {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualEnrollmentContinuationAudit>(c, CONTINUATION)? {
        if audit.operation_id == operation {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in
        read_audits::<ManualEnrollmentInitialPublicationV2>(c, INITIAL_PUBLICATION_V2)?
    {
        if audit.operation_id == operation || audit.terms().operation_id == operation {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualEnrollmentContinuationAuditV3>(c, CONTINUATION_V3)? {
        if audit.operation_id == operation {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualExclusionAudit>(c, EXCLUSION)? {
        if audit.operation_id == operation {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(c, ADDITIONAL_PUBLICATION_V3)?
    {
        if audit.operation_id == operation || audit.terms().operation_id == operation {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    for (_, audit) in read_audits::<ManualEnrollmentContinuationAuditV4>(c, CONTINUATION_V4)? {
        if audit.operation_id == operation {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    Ok(())
}

/// Exact rows from an authenticated immutable Store snapshot. This is historical
/// evidence, not fresh signer identity, current eligibility or a live scope.
/// No Deserialize, Clone or raw-row factory is exposed.
pub struct ManualAuditProjection {
    generation_id: String,
    inventory_digest: String,
    store_destination_identity: String,
    digest: String,
    enrollments: Vec<ManualEnrollmentAudit>,
    scope_audits: Vec<ManualActionAudit>,
    continuations: Vec<ManualEnrollmentContinuationAudit>,
    initial_publications_v2: Vec<ManualEnrollmentInitialPublicationV2>,
    continuations_v3: Vec<ManualEnrollmentContinuationAuditV3>,
    additional_publications_v3: Vec<ManualEnrollmentAdditionalPublicationV3>,
    continuations_v4: Vec<ManualEnrollmentContinuationAuditV4>,
    exclusions: Vec<ManualExclusionAudit>,
}
impl ManualAuditProjection {
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub fn inventory_digest(&self) -> &str {
        &self.inventory_digest
    }
    pub fn store_destination_identity(&self) -> &str {
        &self.store_destination_identity
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    /// Complete identity/scope projection across all original-publication kinds.
    /// Callers cannot silently omit a roster-born Host publication from exclusions.
    pub fn enrollments(&self) -> Vec<ManualEnrollmentProjection<'_>> {
        self.enrollments
            .iter()
            .map(ManualEnrollmentProjection::EnrollmentV1)
            .chain(
                self.initial_publications_v2
                    .iter()
                    .map(ManualEnrollmentProjection::InitialPublicationV2),
            )
            .chain(
                self.additional_publications_v3
                    .iter()
                    .map(ManualEnrollmentProjection::AdditionalPublicationV3),
            )
            .collect()
    }
    pub fn additional_publications_v3(&self) -> &[ManualEnrollmentAdditionalPublicationV3] {
        &self.additional_publications_v3
    }
    pub fn continuations_v4(&self) -> &[ManualEnrollmentContinuationAuditV4] {
        &self.continuations_v4
    }
    /// Format-specific retained bytes, unsuitable for complete identity coverage.
    pub fn v1_enrollments(&self) -> &[ManualEnrollmentAudit] {
        &self.enrollments
    }
    pub fn initial_publications_v2(&self) -> &[ManualEnrollmentInitialPublicationV2] {
        &self.initial_publications_v2
    }
    pub fn continuations_v3(&self) -> &[ManualEnrollmentContinuationAuditV3] {
        &self.continuations_v3
    }
    pub fn scope_audits(&self) -> &[ManualActionAudit] {
        &self.scope_audits
    }
    pub fn continuations(&self) -> &[ManualEnrollmentContinuationAudit] {
        &self.continuations
    }
    pub fn exclusions(&self) -> &[ManualExclusionAudit] {
        &self.exclusions
    }
}
/// Called only after the owning recovered snapshot has authenticated its exact
/// immutable generation/schema/lineage. Public snapshot method checks every
/// enrollment's generation and Store destination against actual retained layers.
pub(crate) fn project_snapshot(
    c: &rusqlite::Connection,
    binding: &GenerationBinding,
    destination: &str,
) -> Result<ManualAuditProjection> {
    hash(destination)?;
    let unknown:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM records WHERE aggregate_type GLOB 'generation_manual_*' AND aggregate_type NOT IN(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13))",rusqlite::params![ENROLLMENT,SCOPE,EXCLUSION,CONTINUATION,INITIAL_PUBLICATION_V2,CONTINUATION_V3,ADDITIONAL_PUBLICATION_V3,CONTINUATION_V4,construction_claim_v2::CONSTRUCTION_CLAIM_V2,construction_claim_v2::CONSTRUCTION_CHECKPOINT_V2,construction_claim_v3::CONSTRUCTION_CLAIM_V3,construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3,PERMANENT_STOP_V1],|r|r.get(0))?;
    // Distinct claim history is fully checked by its own complete validator;
    // parsing it never adds enrollment membership or changes this projection.
    construction_claim_v2::read_construction_rows(c)?;
    if unknown {
        return Err(StoreError::RecoveryRequired);
    }
    let (count, bytes): (u64, u64) = c.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM records WHERE aggregate_type IN(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        rusqlite::params![ENROLLMENT, SCOPE, EXCLUSION, CONTINUATION, INITIAL_PUBLICATION_V2, CONTINUATION_V3,ADDITIONAL_PUBLICATION_V3,CONTINUATION_V4,PERMANENT_STOP_V1],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count > MAX_AUDITS as u64 || bytes > MAX_AUDIT_BYTES {
        return Err(StoreError::ResourceExhausted);
    }
    let enrollments = read_audits::<ManualEnrollmentAudit>(c, ENROLLMENT)?;
    let actions = read_audits::<ManualActionAudit>(c, SCOPE)?;
    let continuations = read_audits::<ManualEnrollmentContinuationAudit>(c, CONTINUATION)?;
    let exclusions = read_audits::<ManualExclusionAudit>(c, EXCLUSION)?;
    let initial_publications_v2 =
        read_audits::<ManualEnrollmentInitialPublicationV2>(c, INITIAL_PUBLICATION_V2)?;
    let continuations_v3 = read_audits::<ManualEnrollmentContinuationAuditV3>(c, CONTINUATION_V3)?;
    let additional_publications_v3 =
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(c, ADDITIONAL_PUBLICATION_V3)?;
    let continuations_v4 = read_audits::<ManualEnrollmentContinuationAuditV4>(c, CONTINUATION_V4)?;
    validate_audit_set(
        &enrollments,
        &actions,
        &exclusions,
        &continuations,
        &initial_publications_v2,
        &continuations_v3,
        crate::manual_enrollment::RosterAuditRows {
            additions: &additional_publications_v3,
            continuations: &continuations_v4,
        },
    )?;
    let permanent_stops = read_audits::<ManualPermanentStopPublicationV1>(c, PERMANENT_STOP_V1)?;
    validate_permanent_stop_set(&permanent_stops, &additional_publications_v3, &exclusions)?;
    // Preserve the exact established V1 commitment for an empty V2 list.
    let digest = if !additional_publications_v3.is_empty() || !continuations_v4.is_empty() {
        domain_digest(
            "wholepact:store-manual-audit-projection:v4",
            &(
                binding.generation_id(),
                binding.inventory_digest(),
                destination,
                &enrollments,
                &actions,
                &exclusions,
                &continuations,
                &initial_publications_v2,
                &continuations_v3,
                &additional_publications_v3,
                &continuations_v4,
            ),
        )?
    } else if !initial_publications_v2.is_empty() || !continuations_v3.is_empty() {
        domain_digest(
            "wholepact:store-manual-audit-projection:v3",
            &(
                binding.generation_id(),
                binding.inventory_digest(),
                destination,
                &enrollments,
                &actions,
                &exclusions,
                &continuations,
                &initial_publications_v2,
                &continuations_v3,
            ),
        )?
    } else if continuations.is_empty() {
        domain_digest(
            "wholepact:store-manual-audit-projection:v1",
            &(
                binding.generation_id(),
                binding.inventory_digest(),
                destination,
                &enrollments,
                &actions,
                &exclusions,
            ),
        )?
    } else {
        domain_digest(
            "wholepact:store-manual-audit-projection:v2",
            &(
                binding.generation_id(),
                binding.inventory_digest(),
                destination,
                &enrollments,
                &actions,
                &exclusions,
                &continuations,
            ),
        )?
    };
    let digest = if permanent_stops.is_empty() { digest } else {
        domain_digest("wholepact:store-manual-audit-projection:v5-permanent-stop", &(digest, &permanent_stops))?
    };
    Ok(ManualAuditProjection {
        generation_id: binding.generation_id().into(),
        inventory_digest: binding.inventory_digest().into(),
        store_destination_identity: destination.into(),
        digest,
        enrollments: enrollments.into_iter().map(|(_, a)| a).collect(),
        scope_audits: actions.into_iter().map(|(_, a)| a).collect(),
        continuations: continuations.into_iter().map(|(_, a)| a).collect(),
        initial_publications_v2: initial_publications_v2
            .into_iter()
            .map(|(_, a)| a)
            .collect(),
        continuations_v3: continuations_v3.into_iter().map(|(_, a)| a).collect(),
        additional_publications_v3: additional_publications_v3
            .into_iter()
            .map(|(_, a)| a)
            .collect(),
        continuations_v4: continuations_v4.into_iter().map(|(_, a)| a).collect(),
        exclusions: exclusions.into_iter().map(|(_, a)| a).collect(),
    })
}

/// Actual opened Store correlation only. Not native approval or a financial
/// exception. Its private constructor remains tied to the concrete Store borrow.
pub struct ManualStoreTarget<'store> {
    store: &'store Store,
    generation_id: String,
    inventory_digest: String,
    store_destination_identity: String,
}
impl ManualStoreTarget<'_> {
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub fn inventory_digest(&self) -> &str {
        &self.inventory_digest
    }
    pub fn store_destination_identity(&self) -> &str {
        &self.store_destination_identity
    }
    /// Bounded read of one current agreement from this actual Store target.
    /// The Engine still decodes the full envelope and enforces selected Access;
    /// this record is comparison data, never approval or account authority.
    pub fn current_agreement_record(&self, agreement_id: &str) -> Result<StoredRecord> {
        self.current_agreement_record_with_mode(agreement_id, ManualPersistenceMode::Existing)
    }
    /// Same current-record checks with no Rust/SQLite contention wait.
    pub fn current_agreement_record_fail_fast(&self, agreement_id: &str) -> Result<StoredRecord> {
        self.current_agreement_record_with_mode(agreement_id, ManualPersistenceMode::FailFast)
    }
    fn current_agreement_record_with_mode(
        &self,
        agreement_id: &str,
        mode: ManualPersistenceMode,
    ) -> Result<StoredRecord> {
        validate_id(agreement_id)?;
        let mut c = self
            .store
            .connection
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
                std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
            })?;
        mode.with_connection(&mut c, |c| {
            let actual = self
                .store
                .recovered_binding
                .as_ref()
                .ok_or(StoreError::RecoveryRequired)?;
            if !self.store.recovered_generation
                || self.store.protection != StorageProtection::Encrypted
                || !crate::backup::read_recovery_state(c)?.recovery_required
                || actual.generation_id() != self.generation_id
                || actual.inventory_digest() != self.inventory_digest
                || self.store.current_recovered_settlement_identity(c)?
                    != self.store_destination_identity
                || self.store.generation_fenced(c, "agreement", agreement_id)?
                || self.store.generation_fenced(
                    c,
                    "record",
                    &format!("agreement:{agreement_id}"),
                )?
            {
                return Err(StoreError::RecoveryRequired);
            }
            crate::read_record(c, "agreement", agreement_id)?.ok_or(StoreError::RecoveryRequired)
        })
    }
    pub fn check_current(&self) -> Result<()> {
        self.check_current_with_mode(ManualPersistenceMode::Existing)
    }
    pub fn check_current_fail_fast(&self) -> Result<()> {
        self.check_current_with_mode(ManualPersistenceMode::FailFast)
    }
    fn check_current_with_mode(&self, mode: ManualPersistenceMode) -> Result<()> {
        let actual = self.store.manual_store_target_with_mode(mode)?;
        if actual.generation_id != self.generation_id
            || actual.inventory_digest != self.inventory_digest
            || actual.store_destination_identity != self.store_destination_identity
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
}
impl Store {
    pub fn manual_store_target(&self) -> Result<ManualStoreTarget<'_>> {
        self.manual_store_target_with_mode(ManualPersistenceMode::Existing)
    }
    pub fn manual_store_target_fail_fast(&self) -> Result<ManualStoreTarget<'_>> {
        self.manual_store_target_with_mode(ManualPersistenceMode::FailFast)
    }
    fn manual_store_target_with_mode(
        &self,
        mode: ManualPersistenceMode,
    ) -> Result<ManualStoreTarget<'_>> {
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        mode.with_connection(&mut c, |c| {
            let binding = self
                .recovered_binding
                .as_ref()
                .ok_or(StoreError::RecoveryRequired)?;
            if !self.recovered_generation
                || self.protection != StorageProtection::Encrypted
                || !crate::backup::read_recovery_state(c)?.recovery_required
            {
                return Err(StoreError::RecoveryRequired);
            }
            Ok(ManualStoreTarget {
                store: self,
                generation_id: binding.generation_id().into(),
                inventory_digest: binding.inventory_digest().into(),
                store_destination_identity: self.current_recovered_settlement_identity(c)?,
            })
        })
    }
}
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
mod admission;
#[cfg(any(test, all(feature = "manual-admission", target_os = "linux")))]
mod kernel;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub use admission::{
    ManualPermanentStopReceiptV1, ManualAuditAppendReceipt, ManualCandidateLocalExclusions, ManualEnrollmentRosterHead,
    ManualEnrollmentRosterMember, ManualRosterCandidateLocalExclusionsV2, OriginalManualRosterReadV3,
};
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use additional_publication::append_modeled_roster_layer_audits;
#[cfg(test)]
pub(crate) use tests::{append_modeled_initial_layer_audits, append_modeled_layer_audits};

/// Data-only complete set fold shared by immutable snapshots and recovery
/// inventories. Missing originals, broken chains and namespace reuse deny.
pub(crate) struct RosterAuditRows<'a> {
    pub(crate) additions: &'a [(String, ManualEnrollmentAdditionalPublicationV3)],
    pub(crate) continuations: &'a [(String, ManualEnrollmentContinuationAuditV4)],
}
pub(crate) fn validate_audit_set(
    enrollments: &[(String, ManualEnrollmentAudit)],
    actions: &[(String, ManualActionAudit)],
    exclusions: &[(String, ManualExclusionAudit)],
    continuations: &[(String, ManualEnrollmentContinuationAudit)],
    initials: &[(String, ManualEnrollmentInitialPublicationV2)],
    continuations_v3: &[(String, ManualEnrollmentContinuationAuditV3)],
    roster: RosterAuditRows<'_>,
) -> Result<()> {
    let RosterAuditRows {
        additions,
        continuations: continuations_v4,
    } = roster;
    if [
        enrollments.len(),
        actions.len(),
        exclusions.len(),
        continuations.len(),
        initials.len(),
        continuations_v3.len(),
        additions.len(),
        continuations_v4.len(),
    ]
    .into_iter()
    .fold(0usize, usize::saturating_add)
        > MAX_AUDITS
    {
        return Err(StoreError::ResourceExhausted);
    }
    for (id, audit) in actions {
        if *id != audit.digest()? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (id, audit) in exclusions {
        if *id != audit.digest()? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (id, audit) in continuations {
        if *id != audit.digest()? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (id, audit) in continuations_v3 {
        if *id != audit.digest()? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (id, audit) in continuations_v4 {
        if *id != audit.digest()? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    additional_publication::validate_chains(additions, continuations_v4)?;
    continuation::validate_chains(enrollments, continuations)?;
    initial_publication::validate_chains(initials, continuations_v3)?;
    let all: Vec<_> = enrollments
        .iter()
        .map(|(id, a)| (id, ManualEnrollmentProjection::EnrollmentV1(a)))
        .chain(
            initials
                .iter()
                .map(|(id, a)| (id, ManualEnrollmentProjection::InitialPublicationV2(a))),
        )
        .chain(
            additions
                .iter()
                .map(|(id, a)| (id, ManualEnrollmentProjection::AdditionalPublicationV3(a))),
        )
        .collect();
    for (index, (id, audit)) in all.iter().enumerate() {
        if **id != audit.digest()? {
            return Err(StoreError::RecoveryRequired);
        }
        for (_, other) in &all[..index] {
            if overlaps(
                &audit.terms().identity,
                audit.aliases(),
                &other.terms().identity,
                other.aliases(),
            ) {
                return Err(StoreError::RecoveryRequired);
            }
        }
        for (_, excluded) in exclusions {
            if overlaps(
                &audit.terms().identity,
                audit.aliases(),
                &excluded.identity,
                &excluded.aliases,
            ) && audit.terms().account_use_genesis_digest != excluded.account_use_genesis_digest
            {
                return Err(StoreError::RecoveryRequired);
            }
        }
    }
    let mut generations: BTreeMap<&str, Vec<(&str, &ManualEnrollmentProjection<'_>)>> =
        BTreeMap::new();
    let mut operations = BTreeSet::new();
    let mut refs = BTreeSet::new();
    let mut requests = BTreeSet::new();
    for (id, audit) in &all {
        if !operations.insert(audit.terms().operation_id.as_str())
            || !refs.insert(audit.enrollment_ref())
        {
            return Err(StoreError::RecoveryRequired);
        }
        generations
            .entry(&audit.terms().host.generation_id)
            .or_default()
            .push((id, audit));
    }
    for rows in generations.values_mut() {
        rows.sort_by_key(|(_, a)| a.store_sequence());
        let mut saw_addition = false;
        for (i, (_, a)) in rows.iter().enumerate() {
            if let ManualEnrollmentProjection::AdditionalPublicationV3(extra) = a {
                saw_addition = true;
                let previous = i.checked_sub(1).ok_or(StoreError::RecoveryRequired)?;
                if rows.len() > 32
                    || extra.evidence.request.roster.predecessor
                        != rows[previous].1.roster_link()?
                {
                    return Err(StoreError::RecoveryRequired);
                }
            } else if saw_addition {
                // Established legacy records remain a prefix; never append a
                // legacy scope row after the explicitly approved new protocol.
                return Err(StoreError::RecoveryRequired);
            }
            if a.store_sequence() != i as u64 + 1
                || a.roster_predecessor() != i.checked_sub(1).map(|n| rows[n].0)
            {
                return Err(StoreError::RecoveryRequired);
            }
        }
    }
    for (_, a) in enrollments {
        if !requests.insert(a.request_identity_digest.as_str()) {
            return Err(StoreError::RecoveryRequired);
        }
    }
    let mut attempts = BTreeSet::new();
    for (_, a) in initials {
        if !operations.insert(a.operation_id.as_str())
            || !requests.insert(a.request_identity_digest.as_str())
            || !attempts.insert(a.evidence.admission.attempt_digest.as_str())
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (_, a) in actions {
        let (_, enrollment) = enrollments
            .iter()
            .find(|(id, _)| id == &a.enrollment_audit_digest)
            .ok_or(StoreError::RecoveryRequired)?;
        a.validate_for(enrollment)?;
        if !operations.insert(a.intent.operation_id.as_str())
            || !requests.insert(a.intent.idempotency_key_digest.as_str())
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (_, a) in exclusions {
        if !operations.insert(a.operation_id.as_str()) {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (_, a) in continuations {
        if !operations.insert(a.operation_id.as_str())
            || !requests.insert(a.request_identity_digest.as_str())
            || !attempts.insert(a.evidence.admission.attempt_digest.as_str())
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (_, a) in continuations_v3 {
        if !operations.insert(a.operation_id.as_str())
            || !requests.insert(a.request_identity_digest.as_str())
            || !attempts.insert(a.evidence.admission.attempt_digest.as_str())
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (_, a) in additions {
        if !operations.insert(a.operation_id.as_str())
            || !requests.insert(a.request_identity_digest.as_str())
            || !attempts.insert(a.evidence.admission.attempt_digest.as_str())
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (_, a) in continuations_v4 {
        if !operations.insert(a.operation_id.as_str())
            || !requests.insert(a.request_identity_digest.as_str())
            || !attempts.insert(a.evidence.admission.attempt_digest.as_str())
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(())
}

pub(crate) mod construction_claim_v2;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub use admission::{ManualRosterConstructionClaimOutcomeV2, ManualRosterConstructionClaimTokenV2};
pub use construction_claim_v2::{
    ManualRosterCheckpointScopeV2, ManualRosterConstructionCheckpointV2,
    ManualRosterConstructionClaimV2, ManualRosterConsumedConstructionAuditV2,
};

// Common-context claims retain separate payload domains and share invocation fences.
pub(crate) mod construction_claim_union;
pub(crate) mod construction_claim_v3;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub use admission::{ManualRosterConstructionClaimOutcomeV3, ManualRosterConstructionClaimTokenV3};
pub use construction_claim_v3::{
    ManualRosterCheckpointScopeV3, ManualRosterConstructionCheckpointV3,
    ManualRosterConstructionClaimV3, ManualRosterConsumedConstructionAuditV3,
};
