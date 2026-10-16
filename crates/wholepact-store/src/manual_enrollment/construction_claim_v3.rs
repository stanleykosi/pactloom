//! Immutable pre-randomness intent and exact unsigned-checkpoint provenance.
//! Every field is historical data. Deserialization cannot issue the one-use
//! runtime token. Missing private bytes never mean construction did not happen.
use super::*;
use wholepact_core::{Proposal, manual_roster_construction_v3::ManualRosterConstructionRequestV3};

pub(crate) const CONSTRUCTION_CLAIM_V3: &str = "generation_manual_construction_claim_v3";
pub(crate) const CONSTRUCTION_CHECKPOINT_V3: &str = "generation_manual_construction_checkpoint_v3";
const MAX_CLAIMS: usize = 256;
const MAX_CLAIM_BYTES: u64 = 32 * 1024 * 1024;

/// Platform-independent exact mirror of the actual consumed native response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConsumedConstructionAuditV3 {
    pub version: u16,
    pub request: ManualRosterConstructionRequestV3,
    pub retained_signer_intent_digest: String,
    pub current_attempt_digest: String,
    pub current_attempt_sequence: u64,
    pub native_review_digest: String,
    pub common_context_read_admission_digest: String,
    pub witness_plan_approval_digest: String,
    pub witness_reservation_digest: String,
    pub witness_consumed_digest: String,
    pub reviewed_at_ms: u64,
    pub reserved_at_ms: u64,
    pub consumed_at_ms: u64,
    pub reserved_debit_zatoshis: u64,
    pub reserved_input_value_zatoshis: u64,
    pub writer_session_expires_at_ms: u64,
}
impl ManualRosterConsumedConstructionAuditV3 {
    pub fn validate(&self) -> Result<()> {
        self.request
            .validate()
            .map_err(|_| StoreError::RecoveryRequired)?;
        for h in [
            &self.retained_signer_intent_digest,
            &self.current_attempt_digest,
            &self.native_review_digest,
            &self.common_context_read_admission_digest,
            &self.witness_plan_approval_digest,
            &self.witness_reservation_digest,
            &self.witness_consumed_digest,
        ] {
            hash(h)?;
        }
        let total = self
            .request
            .plan
            .selected_inputs()
            .iter()
            .try_fold(0u64, |n, i| {
                n.checked_add(i.value_zatoshis)
                    .ok_or(StoreError::RecoveryRequired)
            })?;
        if self.version != 3
            || self.current_attempt_sequence < 2
            || self.current_attempt_sequence
                <= self
                    .request
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attempt
                    .attempt_sequence
            || self.current_attempt_digest
                == self
                    .request
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attempt
                    .continuation_digest
            || self.reviewed_at_ms < self.request.requested_at_ms
            || self.reserved_at_ms < self.reviewed_at_ms
            || self.consumed_at_ms < self.reserved_at_ms
            || self.consumed_at_ms >= self.request.admission_expires_at_ms
            || self.consumed_at_ms >= self.writer_session_expires_at_ms
            || self.reserved_debit_zatoshis
                != self
                    .request
                    .plan
                    .maximum_net_debit_zatoshis()
                    .map_err(|_| StoreError::RecoveryRequired)?
            || self.reserved_input_value_zatoshis != total
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:roster-construction-consumed-native-evidence:v3",
            self,
        )
        .map_err(|_| StoreError::RecoveryRequired)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionClaimV3 {
    pub version: u16,
    pub principal_id: String,
    pub construction_key: String,
    pub maximum_actions: usize,
    /// Canonical participant order, complete ACTUAL consumed native responses.
    pub consumed: Vec<ManualRosterConsumedConstructionAuditV3>,
    /// Present only in explicit encoding version 4. Old claim bytes remain exact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reentry_lineages:
        Option<Vec<wholepact_core::common_context_reentry_v1::RosterCommonContextReentryLineageV1>>,
}
impl ManualRosterConstructionClaimV3 {
    pub fn validate(&self) -> Result<Proposal> {
        if !matches!(self.version, 3 | 4)
            || (self.version == 3) != self.reentry_lineages.is_none()
            || !(2..=8).contains(&self.consumed.len())
            || !(1..=8).contains(&self.maximum_actions)
        {
            return Err(StoreError::RecoveryRequired);
        }
        crate::validate_context(&crate::CommandContext {
            principal_id: self.principal_id.clone(),
            idempotency_key: self.construction_key.clone(),
            request_digest: "0".repeat(64),
        })?;
        if self.principal_id.len() > 128 || serde_json::to_vec(self)?.len() > crate::MAX_JSON_BYTES
        {
            return Err(StoreError::ResourceExhausted);
        }
        if let Some(lineages) = &self.reentry_lineages {
            if lineages.len() != self.consumed.len() {
                return Err(StoreError::RecoveryRequired);
            }
            for (lineage, consumed) in lineages.iter().zip(&self.consumed) {
                validate_reentry_lineage(lineage, consumed)?;
            }
        }
        let first = &self.consumed[0].request.plan;
        let selection = &first.retained.selection.scope.selection;
        let proposal = first.validate().map_err(|_| StoreError::RecoveryRequired)?;
        let key_digest = request_digest(&serde_json::json!([
            &self.principal_id,
            &self.construction_key
        ]))?;
        if selection.invocation.idempotency_key_digest != key_digest
            || first.participants.len() != self.consumed.len()
        {
            return Err(StoreError::RecoveryRequired);
        }
        let mut native = BTreeSet::new();
        let mut reservations = BTreeSet::new();
        let mut consumed = BTreeSet::new();
        let mut operations = BTreeSet::new();
        let mut nullifiers = BTreeSet::new();
        for (audit, expected) in self.consumed.iter().zip(&first.participants) {
            audit.validate()?;
            let plan = &audit.request.plan;
            let current = &plan.retained.selection.scope.selection;
            let enrollment = plan.enrollment();
            if plan.proposal != first.proposal
                || plan.participants != first.participants
                || current.economic_intent != selection.economic_intent
                || current.invocation != selection.invocation
                || enrollment.host != first.enrollment().host
                || enrollment.scope.principal_id != self.principal_id
                || enrollment.scope.participant_id != expected.participant_id
                || enrollment.identity.account_id != expected.account_id
                || enrollment.identity.full_viewing_key_digest != expected.full_viewing_key_digest
                || plan
                    .retained
                    .digest()
                    .map_err(|_| StoreError::RecoveryRequired)?
                    != expected.retention_request_digest
                || plan.retained_evidence_digest != expected.retention_evidence_digest
                || plan.common_context != first.common_context
                || plan.common_context_digest != first.common_context_digest
                || plan.originals != first.originals
                || !native.insert(&audit.native_review_digest)
                || !reservations.insert(&audit.witness_reservation_digest)
                || !consumed.insert(&audit.witness_consumed_digest)
                || !operations.insert(&audit.request.operation_id)
            {
                return Err(StoreError::RecoveryRequired);
            }
            for input in plan.selected_inputs() {
                if !nullifiers.insert(&input.nullifier) {
                    return Err(StoreError::RecoveryRequired);
                }
            }
        }
        Ok(proposal)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        domain_digest(
            if self.version == 4 {
                "wholepact:store-roster-construction-claim:v4"
            } else {
                "wholepact:store-roster-construction-claim:v3"
            },
            self,
        )
    }
    pub fn request_digest(&self) -> Result<String> {
        self.validate()?;
        domain_digest(
            if self.version == 4 {
                "wholepact:manual-roster-private-checkpoint-command:v4"
            } else {
                "wholepact:manual-roster-private-checkpoint-command:v3"
            },
            self,
        )
    }
    pub fn proposal(&self) -> &wholepact_core::ProposalInput {
        &self.consumed[0].request.plan.proposal
    }
    pub fn invocation(
        &self,
    ) -> &wholepact_core::manual_candidate_selection::ManualCandidateInvocation {
        &self.consumed[0]
            .request
            .plan
            .retained
            .selection
            .scope
            .selection
            .invocation
    }
    pub fn candidate_id(&self) -> &str {
        &self.consumed[0]
            .request
            .plan
            .retained
            .selection
            .scope
            .selection
            .economic_intent
            .candidate_id
    }
    pub fn agreement_revision(&self) -> u64 {
        self.consumed[0]
            .request
            .plan
            .retained
            .selection
            .scope
            .selection
            .economic_intent
            .candidate_revision
    }
    pub fn request_identity(&self) -> Result<String> {
        request_digest(&serde_json::json!([
            &self.principal_id,
            &self.construction_key
        ]))
    }
}

/// Exact mirror of the non-sensitive proof-store scope, including its original
/// disclosure purpose. No authorization, proof success or journal atomicity flag.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterCheckpointScopeV3 {
    pub principal_id: String,
    pub candidate_id: String,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub effects_commitment: String,
    pub coordination_request_digest: String,
    pub review_binding: String,
    pub account_ids: Vec<String>,
    pub local_operator: String,
    pub purpose: String,
    pub retention_policy: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionCheckpointV3 {
    pub version: u16,
    pub claim_digest: String,
    pub job_id: String,
    pub scope: ManualRosterCheckpointScopeV3,
}
impl ManualRosterConstructionCheckpointV3 {
    pub fn validate_for(&self, claim: &ManualRosterConstructionClaimV3) -> Result<()> {
        let proposal = claim.validate()?;
        let s = &self.scope;
        for h in [
            &self.claim_digest,
            &s.manifest_digest,
            &s.artifact_digest,
            &s.effects_commitment,
            &s.coordination_request_digest,
            &s.review_binding,
        ] {
            hash(h)?;
        }
        let inventory = &claim.consumed[0]
            .request
            .plan
            .retained
            .selection
            .scope
            .selection
            .inventory;
        if self.version != 3
            || self.claim_digest != claim.digest()?
            || self.job_id != expected_job_id(&claim.principal_id, &claim.construction_key)
            || s.principal_id != claim.principal_id
            || s.candidate_id != claim.candidate_id()
            || s.manifest_digest != proposal.manifest_digest()
            || s.coordination_request_digest != claim.request_digest()?
            || s.account_ids
                != proposal
                    .manifest()
                    .participants
                    .iter()
                    .map(|p| p.account_id.clone())
                    .collect::<Vec<_>>()
            || s.local_operator != inventory.operator_name
            || s.purpose != "construct_one_candidate"
            || s.retention_policy != inventory.retention_policy
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn scope_digest(&self) -> Result<String> {
        use sha2::Digest;
        Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
            &self.scope,
        )?)))
    }
}
fn expected_job_id(principal: &str, key: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    // Same framed identity as wholepact-proof-jobs, tested by Engine integration.
    h.update(b"wholepact.private-proof-job.v1\0");
    for value in [principal.as_bytes(), key.as_bytes()] {
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    }
    format!("proof-{}", hex::encode(h.finalize()))
}

pub(crate) fn validate_construction_record(kind: &str, record: &StoredRecord) -> Result<()> {
    if record.revision != 0
        || record.created_at_ms < 0
        || record.updated_at_ms != record.created_at_ms
    {
        return Err(StoreError::RecoveryRequired);
    }
    match kind {
        CONSTRUCTION_CLAIM_V3 => {
            let claim: ManualRosterConstructionClaimV3 = strict(&record.payload)?;
            if record.id != claim.digest()? {
                return Err(StoreError::RecoveryRequired);
            }
        }
        CONSTRUCTION_CHECKPOINT_V3 => {
            let checkpoint: ManualRosterConstructionCheckpointV3 = strict(&record.payload)?;
            hash(&checkpoint.claim_digest)?;
            if checkpoint.version != 3 || record.id != checkpoint.claim_digest {
                return Err(StoreError::RecoveryRequired);
            }
        }
        _ => return Err(StoreError::RecoveryRequired),
    }
    Ok(())
}
pub(crate) fn validate_construction_set(
    claims: &[(String, ManualRosterConstructionClaimV3)],
    checkpoints: &[(String, ManualRosterConstructionCheckpointV3)],
) -> Result<()> {
    if claims.len() > MAX_CLAIMS || checkpoints.len() > claims.len() {
        return Err(StoreError::ResourceExhausted);
    }
    let mut keys = BTreeSet::new();
    let mut invocations = BTreeSet::new();
    let mut candidates = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let mut permit_consumes = BTreeSet::new();
    let mut inputs = BTreeSet::new();
    let mut nullifiers = BTreeSet::new();
    for (id, claim) in claims {
        if id != &claim.digest()?
            || !keys.insert(claim.request_identity()?)
            || !invocations.insert(claim.invocation().operation_id.clone())
            || !nonces.insert(claim.invocation().invocation_nonce.clone())
            || !candidates.insert((
                claim.proposal().manifest.agreement.agreement_id.clone(),
                claim.candidate_id().to_owned(),
            ))
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    for (_, claim) in claims {
        for audit in &claim.consumed {
            if !permit_consumes.insert(&audit.witness_consumed_digest) {
                return Err(StoreError::RecoveryRequired);
            }
            for input in audit.request.plan.selected_inputs() {
                if !inputs.insert((
                    &audit.request.plan.enrollment().identity.account_id,
                    &input.input_id,
                )) || !nullifiers.insert(&input.nullifier)
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
        }
    }
    for (id, checkpoint) in checkpoints {
        let (_, claim) = claims
            .iter()
            .find(|(key, _)| key == id)
            .ok_or(StoreError::RecoveryRequired)?;
        if id != &checkpoint.claim_digest || !receipts.insert(id) {
            return Err(StoreError::RecoveryRequired);
        }
        checkpoint.validate_for(claim)?;
    }
    Ok(())
}
type ConstructionRowsV3 = (
    Vec<(String, ManualRosterConstructionClaimV3)>,
    Vec<(String, ManualRosterConstructionCheckpointV3)>,
);
pub(crate) fn read_local_rows(c: &rusqlite::Connection) -> Result<ConstructionRowsV3> {
    let (count,bytes):(u64,u64)=c.query_row("SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM records WHERE aggregate_type IN(?1,?2)",rusqlite::params![CONSTRUCTION_CLAIM_V3,CONSTRUCTION_CHECKPOINT_V3],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if count > (2 * MAX_CLAIMS) as u64 || bytes > MAX_CLAIM_BYTES {
        return Err(StoreError::ResourceExhausted);
    }
    let mut q=c.prepare("SELECT aggregate_type,id,revision,payload,created_at_ms,updated_at_ms FROM records WHERE aggregate_type IN(?1,?2) ORDER BY aggregate_type,id")?;
    let mut rows = q.query(rusqlite::params![
        CONSTRUCTION_CLAIM_V3,
        CONSTRUCTION_CHECKPOINT_V3
    ])?;
    let mut claims = Vec::new();
    let mut checkpoints = Vec::new();
    while let Some(r) = rows.next()? {
        let kind: String = r.get(0)?;
        let record = StoredRecord {
            id: r.get(1)?,
            revision: r.get(2)?,
            payload: serde_json::from_str(&r.get::<_, String>(3)?)?,
            created_at_ms: r.get(4)?,
            updated_at_ms: r.get(5)?,
        };
        validate_construction_record(&kind, &record)?;
        if kind == CONSTRUCTION_CLAIM_V3 {
            claims.push((record.id, strict(&record.payload)?));
        } else {
            checkpoints.push((record.id, strict(&record.payload)?));
        }
    }
    validate_construction_set(&claims, &checkpoints)?;
    if !claims.is_empty() {
        let (manual_count, manual_bytes): (u64, u64) = c.query_row(
            "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM records WHERE aggregate_type IN(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            rusqlite::params![ENROLLMENT,SCOPE,EXCLUSION,CONTINUATION,INITIAL_PUBLICATION_V2,CONTINUATION_V3,ADDITIONAL_PUBLICATION_V3,CONTINUATION_V4,PERMANENT_STOP_V1],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if manual_count > MAX_AUDITS as u64 || manual_bytes > MAX_AUDIT_BYTES {
            return Err(StoreError::ResourceExhausted);
        }
        let unknown: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE aggregate_type GLOB 'generation_manual_*' AND aggregate_type NOT IN(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13))",
            rusqlite::params![ENROLLMENT,SCOPE,EXCLUSION,CONTINUATION,INITIAL_PUBLICATION_V2,CONTINUATION_V3,ADDITIONAL_PUBLICATION_V3,CONTINUATION_V4,CONSTRUCTION_CLAIM_V3,CONSTRUCTION_CHECKPOINT_V3,super::construction_claim_v2::CONSTRUCTION_CLAIM_V2,super::construction_claim_v2::CONSTRUCTION_CHECKPOINT_V2,PERMANENT_STOP_V1],
            |r| r.get(0),
        )?;
        if unknown {
            return Err(StoreError::RecoveryRequired);
        }
        let additions =
            read_audits::<ManualEnrollmentAdditionalPublicationV3>(c, ADDITIONAL_PUBLICATION_V3)?;
        let continuations = read_audits::<ManualEnrollmentContinuationAuditV4>(c, CONTINUATION_V4)?;
        // Direct open/read receives the same complete roster-chain validation
        // as backup/inventory. A missing root or older retained selection is
        // corruption, never permission to reconstruct an invocation.
        validate_audit_set(
            &read_audits::<ManualEnrollmentAudit>(c, ENROLLMENT)?,
            &read_audits::<ManualActionAudit>(c, SCOPE)?,
            &read_audits::<ManualExclusionAudit>(c, EXCLUSION)?,
            &read_audits::<ManualEnrollmentContinuationAudit>(c, CONTINUATION)?,
            &read_audits::<ManualEnrollmentInitialPublicationV2>(c, INITIAL_PUBLICATION_V2)?,
            &read_audits::<ManualEnrollmentContinuationAuditV3>(c, CONTINUATION_V3)?,
            RosterAuditRows {
                additions: &additions,
                continuations: &continuations,
            },
        )?;
        validate_permanent_stop_set(&read_audits::<ManualPermanentStopPublicationV1>(c, PERMANENT_STOP_V1)?, &additions, &read_audits::<ManualExclusionAudit>(c, EXCLUSION)?)?;
        validate_construction_roster_history(&claims, &additions, &continuations)?;
    }
    Ok((claims, checkpoints))
}
impl Store {
    /// Historical exact evidence only. No token or builder owner can be restored.
    pub fn manual_roster_construction_evidence_v3(
        &self,
        principal: &str,
        key: &str,
    ) -> Result<
        Option<(
            ManualRosterConstructionClaimV3,
            Option<ManualRosterConstructionCheckpointV3>,
        )>,
    > {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let (claims, checkpoints) = read_construction_rows(&c)?;
        Ok(claims
            .into_iter()
            .find(|(_, a)| a.principal_id == principal && a.construction_key == key)
            .map(|(id, a)| {
                let receipt = checkpoints
                    .into_iter()
                    .find(|(key, _)| key == &id)
                    .map(|(_, r)| r);
                (a, receipt)
            }))
    }
}

/// Complete historical relation check, including original account/roster rows
/// and the exact (possibly no longer latest) construction-time continuation.
pub(crate) fn validate_construction_roster_history(
    claims: &[(String, ManualRosterConstructionClaimV3)],
    additions: &[(String, ManualEnrollmentAdditionalPublicationV3)],
    continuations: &[(String, ManualEnrollmentContinuationAuditV4)],
) -> Result<()> {
    for (_, claim) in claims {
        for consumed in &claim.consumed {
            let plan = &consumed.request.plan;
            let selection = &plan.retained.selection.scope;
            let provenance = &selection.provenance;
            let original = additions
                .iter()
                .find(|(id, _)| id == provenance.original_host_audit.audit_digest())
                .ok_or(StoreError::RecoveryRequired)?;
            let inventory = &selection.selection.inventory;
            if original.1.terms() != plan.enrollment()
                || original.1.evidence.enrollment_ref != inventory.enrollment_ref
                || original.1.evidence.witness_extension_digest
                    != inventory.witness_extension_digest
                || original.1.evidence.request.roster != provenance.roster
                || original.1.evidence.signer_roster_record_digest
                    != provenance.signer_roster_record_digest
                || original.1.evidence.witness_roster_extension_digest
                    != provenance.witness_roster_extension_digest
                || !continuations.iter().any(|(_, a)| {
                    a.original_audit.audit_digest() == original.0
                        && a.evidence.admission.attempt_sequence
                            == inventory.attempt.attempt_sequence
                        && a.evidence.admission.attempt_digest
                            == inventory.attempt.continuation_digest
                })
                || !continuations.iter().any(|(_, a)| {
                    a.original_audit.audit_digest() == original.0
                        && a.evidence.admission.attempt_sequence
                            == consumed.current_attempt_sequence
                        && a.evidence.admission.attempt_digest == consumed.current_attempt_digest
                })
            {
                return Err(StoreError::RecoveryRequired);
            }
        }
    }
    Ok(())
}

pub(crate) fn read_construction_rows(c: &rusqlite::Connection) -> Result<ConstructionRowsV3> {
    super::construction_claim_union::validate_current(c)?;
    read_local_rows(c)
}

#[cfg(test)]
#[path = "construction_claim_v3_tests.rs"]
mod tests;
#[cfg(test)]
pub(crate) use tests::{
    append_modeled_construction_rows_v3, append_modeled_reentered_construction_rows_v4,
    exact_manual_rows,
};

pub(crate) fn validate_reentry_lineage(
    lineage: &wholepact_core::common_context_reentry_v1::RosterCommonContextReentryLineageV1,
    consumed: &ManualRosterConsumedConstructionAuditV3,
) -> Result<()> {
    lineage
        .validate()
        .map_err(|_| StoreError::RecoveryRequired)?;
    consumed.validate()?;
    let request = &lineage.request;
    let original = &request.original_read;
    if consumed.request.plan != original.plan
        || consumed.request.current_caller_binding_digest != request.current_caller_binding_digest
        || consumed.request.operation_id == request.operation_id
        || consumed.request.operation_id == original.operation_id
        || consumed.request.requested_at_ms < lineage.admitted_at_ms
        || consumed.request.admission_expires_at_ms > lineage.completion_expires_at_ms
        || consumed.retained_signer_intent_digest != lineage.retained_signer_intent_digest
        || consumed.current_attempt_digest != request.current_attempt_digest
        || consumed.current_attempt_sequence != request.current_attempt_sequence
        || consumed.common_context_read_admission_digest != request.original_read_admission_digest
        || consumed.witness_plan_approval_digest != original.witness_plan_approval_digest
        || consumed.native_review_digest == lineage.native_review_digest
        || consumed.writer_session_expires_at_ms != lineage.current_writer_session_expires_at_ms
        || consumed.consumed_at_ms >= lineage.completion_expires_at_ms
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}
