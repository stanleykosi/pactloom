//! Version-neutral restriction index derived from authenticated immutable rows.
//! Payload versions never create a fresh invocation or input namespace.
use super::construction_claim_v2::ManualRosterConstructionClaimV2;
use super::construction_claim_v3::ManualRosterConstructionClaimV3;
use super::*;
use rusqlite::params;

#[derive(Default)]
struct Fences {
    keys: BTreeSet<String>,
    operations: BTreeSet<String>,
    nonces: BTreeSet<String>,
    candidates: BTreeSet<(String, String)>,
    consumed: BTreeSet<String>,
    inputs: BTreeSet<(String, String)>,
    nullifiers: BTreeSet<String>,
}
macro_rules! add_claim {
    ($f:expr, $claim:expr) => {{
        let c = $claim;
        c.validate()?;
        if !$f.keys.insert(c.request_identity()?)
            || !$f.operations.insert(c.invocation().operation_id.clone())
            || !$f.nonces.insert(c.invocation().invocation_nonce.clone())
            || !$f.candidates.insert((
                c.proposal().manifest.agreement.agreement_id.clone(),
                c.candidate_id().to_owned(),
            ))
        {
            return Err(StoreError::RecoveryRequired);
        }
        for a in &c.consumed {
            if !$f.consumed.insert(a.witness_consumed_digest.clone())
                || !$f.operations.insert(a.request.operation_id.clone())
            {
                return Err(StoreError::RecoveryRequired);
            }
            for i in a.request.plan.selected_inputs() {
                if !$f.inputs.insert((
                    a.request.plan.enrollment().identity.account_id.clone(),
                    i.input_id.clone(),
                )) || !$f.nullifiers.insert(i.nullifier.clone())
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
        }
    }};
}
pub(crate) fn validate_union(
    v2: &[(String, ManualRosterConstructionClaimV2)],
    v3: &[(String, ManualRosterConstructionClaimV3)],
) -> Result<()> {
    if v2.len().checked_add(v3.len()).is_none_or(|n| n > 256) {
        return Err(StoreError::ResourceExhausted);
    }
    let mut f = Fences::default();
    for (_, c) in v2 {
        add_claim!(f, c);
    }
    for (_, c) in v3 {
        add_claim!(f, c);
    }
    Ok(())
}
pub(crate) fn validate_current(c: &rusqlite::Connection) -> Result<()> {
    let unknown: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM records WHERE aggregate_type GLOB 'generation_manual_*' AND aggregate_type NOT IN(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13))",
        params![ENROLLMENT,SCOPE,EXCLUSION,CONTINUATION,INITIAL_PUBLICATION_V2,CONTINUATION_V3,ADDITIONAL_PUBLICATION_V3,CONTINUATION_V4,super::construction_claim_v2::CONSTRUCTION_CLAIM_V2,super::construction_claim_v2::CONSTRUCTION_CHECKPOINT_V2,super::construction_claim_v3::CONSTRUCTION_CLAIM_V3,super::construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3,PERMANENT_STOP_V1], |r|r.get(0))?;
    if unknown {
        return Err(StoreError::RecoveryRequired);
    }
    let (count, bytes): (u64,u64) = c.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM records WHERE aggregate_type GLOB 'generation_manual_*'",
        [], |r|Ok((r.get(0)?,r.get(1)?)))?;
    if count > MAX_AUDITS as u64 + 512 || bytes > MAX_AUDIT_BYTES + 32 * 1024 * 1024 {
        return Err(StoreError::ResourceExhausted);
    }
    let additions =
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(c, ADDITIONAL_PUBLICATION_V3)?;
    let continuations = read_audits::<ManualEnrollmentContinuationAuditV4>(c, CONTINUATION_V4)?;
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
    let v2 = super::construction_claim_v2::read_local_rows(c)?;
    let v3 = super::construction_claim_v3::read_local_rows(c)?;
    validate_union(&v2.0, &v3.0)
}

impl Store {
    /// Restriction-only preflight before NEW common-context approval. This
    /// absence observation is never a reservation, issuer or durable retry token.
    /// Final claim repeats all conflicts inside its Immediate transaction.
    pub fn require_unused_common_context_invocation(
        &self,
        principal: &str,
        key: &str,
        invocation: &wholepact_core::manual_candidate_selection::ManualCandidateInvocation,
    ) -> Result<()> {
        invocation
            .validate()
            .map_err(|_| StoreError::RecoveryRequired)?;
        let context = crate::CommandContext {
            principal_id: principal.into(),
            idempotency_key: key.into(),
            request_digest: invocation
                .digest()
                .map_err(|_| StoreError::RecoveryRequired)?,
        };
        crate::validate_context(&context)?;
        let identity = request_digest(&serde_json::json!([principal, key]))?;
        if invocation.idempotency_key_digest != identity {
            return Err(StoreError::IdempotencyConflict);
        }
        let mut c = self.connection.try_lock().map_err(|e| match e {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        super::ManualPersistenceMode::FailFast.with_connection(&mut c, |c| {
            crate::backup::require_construction_v3_encoding(c)?;
            validate_current(c)?;
            // Mirror deterministic final-claim restrictions before any new
            // witness approval or permanent reservation. This remains only an
            // absence observation; final claim repeats them atomically.
            super::require_generic_request_not_manual(c, &context)?;
            super::require_generic_operation_not_manual(c, &invocation.operation_id)?;
            self.require_current_replay(c, &context)?;
            macro_rules! deny_existing {
                ($rows:expr) => {
                    for (_, claim) in $rows {
                        if claim.request_identity()? == identity
                            || claim.invocation().operation_id == invocation.operation_id
                            || claim.invocation().invocation_nonce == invocation.invocation_nonce {
                            return Err(StoreError::IdempotencyConflict);
                        }
                    }
                };
            }
            deny_existing!(super::construction_claim_v2::read_local_rows(c)?.0);
            deny_existing!(super::construction_claim_v3::read_local_rows(c)?.0);
            let exists: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM idempotency WHERE principal_id=?1 AND idempotency_key=?2 UNION ALL SELECT 1 FROM operations WHERE operation_id=?3 UNION ALL SELECT 1 FROM effect_intents WHERE operation_id=?3)",
                params![principal,key,&invocation.operation_id], |r| r.get(0))?;
            if exists
                || self.generation_fenced(c, "operation", &invocation.operation_id)?
                || self.generation_fenced(c, "effect", &invocation.operation_id)?
            {
                return Err(StoreError::RecoveryRequired);
            }
            Ok(())
        })
    }
}
