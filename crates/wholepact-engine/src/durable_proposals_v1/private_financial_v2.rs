//! Explicit V2 per-owner durable progress. V1 history and binding are unchanged.
//! Only the original-source facade can construct this private kernel.
use super::*;
use wholepact_signer::authority_bridge::financial_continuation_v1::{
    AuthenticatedCompletedDispatchAdmissionV1, AuthenticatedFinancialContinuationHistoryV1,
    AuthenticatedFinancialResultEvidenceV2, AuthorizeCompletedDispatchV1,
    CompletedDispatchAdmissionV1, CompletedDispatchOwnerV1, FinancialContinuationRecordV1,
    OwnerControlRequest,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContinuationReferenceV1 {
    pub request: OwnerControlRequest,
    pub record: FinancialContinuationRecordV1,
    pub authenticated_history_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinancialBindingV2 {
    pub schema_version: u16,
    pub frozen_export_revision: u64,
    pub frozen_export_history_digest: String,
    pub continuations: BTreeMap<String, ContinuationReferenceV1>,
}
impl FinancialBindingV2 {
    pub(crate) fn validate(&self, fixed: &FixedProposalIdentityV1) -> Result<()> {
        if self.schema_version != 2
            || !(8..=16).contains(&self.frozen_export_revision)
            || !digest(&self.frozen_export_history_digest)
            || !(1..=2).contains(&self.continuations.len())
        {
            return Err(damaged());
        }
        let mut plan = None;
        for (account, source) in &self.continuations {
            source
                .record
                .validate_request(&source.request, &source.record.terms.scope.witness)
                .map_err(|_| damaged())?;
            if account != &source.record.terms.scope.authorization.identity.account_id
                || !digest(&source.authenticated_history_digest)
                || serde_json::to_value(&source.record.terms.scope.authorization.fixed)
                    .map_err(|_| damaged())?
                    != serde_json::to_value(fixed).map_err(|_| damaged())?
            {
                return Err(damaged());
            }
            let delivery = &source.record.terms.scope.delivery;
            if plan.is_some_and(|original| original != delivery) {
                return Err(damaged());
            }
            plan = Some(delivery);
        }
        let plan = plan.ok_or_else(damaged)?;
        let expected: BTreeSet<_> = plan.owners.iter().map(|o| o.account_id.as_str()).collect();
        if plan.owners.len() != 2 || expected.len() != 2
            || self.continuations.keys().any(|account| !expected.contains(account.as_str()))
        {
            return Err(damaged());
        }
        Ok(())
    }
}

pub(crate) fn decode_binding(value: &serde_json::Value) -> Result<FinancialBindingV2> {
    if serde_json::to_vec(value).map_err(|_| damaged())?.len() > 64 * 1024 {
        return Err(damaged());
    }
    let parsed: FinancialBindingV2 =
        serde_json::from_value(value.clone()).map_err(|_| damaged())?;
    if parsed.schema_version != 2 { return Err(damaged()); }
    if serde_json::to_value(&parsed).map_err(|_| damaged())? != *value {
        return Err(damaged());
    }
    Ok(parsed)
}
fn stored_binding(stored: &Stored) -> Result<FinancialBindingV2> {
    let binding = decode_binding(stored.financial_binding_v2.as_ref().ok_or_else(damaged)?)?;
    binding.validate(&stored.identity)?;
    Ok(binding)
}
pub(crate) fn binding(envelope: &Envelope) -> Result<Option<FinancialBindingV2>> {
    let candidate = envelope.view.candidates.first().ok_or_else(damaged)?;
    let stored = stored(envelope, &candidate.candidate_id)?;
    stored
        .financial_binding_v2
        .as_ref()
        .map(|v| {
            let binding = decode_binding(v)?;
            binding.validate(&stored.identity)?;
            Ok(binding)
        })
        .transpose()
}
fn stored(envelope: &Envelope, candidate: &str) -> Result<Stored> {
    serde_json::from_value(
        envelope
            .durable_proposals_v1
            .get(candidate)
            .ok_or_else(damaged)?
            .clone(),
    )
    .map_err(|_| damaged())
}
pub(crate) fn progress_accounts(envelope: &Envelope) -> Result<(Vec<String>, Vec<String>)> {
    validate_stored(envelope)?;
    let candidate = envelope.view.candidates.first().ok_or_else(damaged)?;
    let stored = stored(envelope, &candidate.candidate_id)?;
    if stored.financial_binding_v1.is_some() { return Err(damaged()); }
    let bound = stored.financial_binding_v2.as_ref().map(|_| stored_binding(&stored))
        .transpose()?.map(|b| b.continuations.into_keys().collect()).unwrap_or_default();
    Ok((bound, stored.intakes.into_keys().collect()))
}
pub(crate) fn submission_operation_id(envelope: &Envelope) -> Result<Option<String>> {
    let Some(binding) = binding(envelope)? else { return Ok(None); };
    Ok(Some(binding.continuations.values().next().ok_or_else(damaged)?
        .record.terms.scope.delivery.submission_operation_id.clone()))
}
/// Separate V2 shape; the old admission-only validator still rejects progress.
pub(crate) fn validate_export_shape(envelope: &Envelope) -> Result<()> {
    validate_stored(envelope)?;
    let candidate = envelope.view.candidates.first().ok_or_else(damaged)?;
    let stored = stored(envelope, &candidate.candidate_id)?;
    if stored.financial_binding_v1.is_some() || stored.union.is_some()
        || !stored.financial_dispatch_v1.is_empty()
    { return Err(damaged()); }
    if stored.financial_binding_v2.is_none() {
        return super::validate_private_fixed_v2(envelope);
    }
    stored_binding(&stored)?;
    Ok(())
}
pub(crate) fn require_unfinished_export(envelope: &Envelope, account: &str) -> Result<()> {
    validate_export_shape(envelope)?;
    let candidate = envelope.view.candidates.first().ok_or_else(damaged)?;
    let stored = stored(envelope, &candidate.candidate_id)?;
    if stored.intakes.contains_key(account)
        || !stored.mappings.inputs.iter().any(|mapping| mapping.account_id == account)
    { return Err(conflict()); }
    Ok(())
}
pub(crate) fn bind(envelope: &Envelope, binding: FinancialBindingV2) -> Result<Envelope> {
    let id = &envelope
        .view
        .candidates
        .first()
        .ok_or_else(damaged)?
        .candidate_id;
    let mut stored = stored(envelope, id)?;
    binding.validate(&stored.identity)?;
    if stored.financial_binding_v1.is_some() || stored.union.is_some() { return Err(conflict()); }
    if let Some(previous) = stored.financial_binding_v2.as_ref() {
        let previous = decode_binding(previous)?;
        if previous.continuations.len() != 1 || binding.continuations.len() != 2
            || previous.frozen_export_revision != binding.frozen_export_revision
            || previous.frozen_export_history_digest != binding.frozen_export_history_digest
        { return Err(conflict()); }
        for (account, original) in &previous.continuations {
            if binding.continuations.get(account).map(serde_json::to_value).transpose().map_err(|_| damaged())?
                != Some(serde_json::to_value(original).map_err(|_| damaged())?)
            { return Err(conflict()); }
        }
    } else if binding.continuations.len() != 1 || !stored.intakes.is_empty() {
        return Err(conflict());
    }
    stored.financial_binding_v2 = Some(serde_json::to_value(binding).map_err(|_| damaged())?);
    let mut after = envelope.clone();
    put(&mut after, id, &stored)?;
    Ok(after)
}

/// Exact finite delta comparison. All unrelated envelope fields and original
/// fixed/mapping/export contents stay byte-canonically identical.
pub(crate) fn validate_delta(before: &Envelope, after: &Envelope, kind: &str) -> Result<()> {
    let id = &before
        .view
        .candidates
        .first()
        .ok_or_else(damaged)?
        .candidate_id;
    let old = stored(before, id)?;
    let new = stored(after, id)?;
    let mut expected = old.clone();
    match kind {
        "private_financial_owner_bound_v2" => {
            if old.financial_binding_v1.is_some() || old.union.is_some() { return Err(damaged()); }
            let binding = stored_binding(&new)?;
            binding.validate(&old.identity)?;
            if old.financial_binding_v2.is_some() {
                let previous = stored_binding(&old)?;
                if previous.continuations.len() != 1 || binding.continuations.len() != 2
                    || previous.frozen_export_revision != binding.frozen_export_revision
                    || previous.frozen_export_history_digest != binding.frozen_export_history_digest
                { return Err(damaged()); }
                for (account, original) in &previous.continuations {
                    if binding.continuations.get(account).map(serde_json::to_value).transpose().map_err(|_| damaged())?
                        != Some(serde_json::to_value(original).map_err(|_| damaged())?)
                    { return Err(damaged()); }
                }
            } else if binding.continuations.len() != 1 || !old.intakes.is_empty()
                || binding.frozen_export_revision != before.view.revision
            { return Err(damaged()); }
            expected.financial_binding_v2 = new.financial_binding_v2.clone();
        }
        "private_financial_signature_intake_v2" => {
            stored_binding(&old)?;
            if old.union.is_some()
                || old.intakes.len() >= 2
                || new.intakes.len() != old.intakes.len() + 1
            {
                return Err(damaged());
            }
            let added: Vec<_> = new
                .intakes
                .iter()
                .filter(|(id, _)| !old.intakes.contains_key(*id))
                .collect();
            if added.len() != 1 || !stored_binding(&old)?.continuations.contains_key(added[0].0) {
                return Err(damaged());
            }
            expected
                .intakes
                .insert(added[0].0.clone(), added[0].1.clone());
        }
        "private_financial_union_retained_v2" => {
            if old.financial_binding_v2.is_none()
                || old.intakes.len() != 2
                || old.union.is_some()
                || new.union.is_none()
            {
                return Err(damaged());
            }
            expected.union = new.union.clone();
        }
        "private_financial_dispatch_intent_v2" => {
            if old.union.is_none()
                || new.financial_dispatch_v1.len() != old.financial_dispatch_v1.len() + 1
            {
                return Err(damaged());
            }
            let attempt = (old.financial_dispatch_v1.len() + 1) as u32;
            let value = new
                .financial_dispatch_v1
                .get(&attempt)
                .ok_or_else(damaged)?;
            let retained = decode_dispatch(value)?;
            if !retained.admissions.is_empty() {
                return Err(damaged());
            }
            expected
                .financial_dispatch_v1
                .insert(attempt, value.clone());
        }
        "private_financial_dispatch_admission_v2" => {
            let attempt = old.financial_dispatch_v1.len() as u32;
            let old_attempt = decode_dispatch(
                old.financial_dispatch_v1
                    .get(&attempt)
                    .ok_or_else(damaged)?,
            )?;
            let new_attempt = decode_dispatch(
                new.financial_dispatch_v1
                    .get(&attempt)
                    .ok_or_else(damaged)?,
            )?;
            if old_attempt.requests != new_attempt.requests
                || new_attempt.admissions.len() != old_attempt.admissions.len() + 1
                || new_attempt.admissions.len() > 2
            {
                return Err(damaged());
            }
            let added: Vec<_> = new_attempt
                .admissions
                .iter()
                .filter(|(a, _)| !old_attempt.admissions.contains_key(*a))
                .collect();
            if added.len() != 1 {
                return Err(damaged());
            }
            let mut expected_attempt = old_attempt;
            expected_attempt
                .admissions
                .insert(added[0].0.clone(), added[0].1.clone());
            if serde_json::to_value(&expected_attempt).map_err(|_| damaged())?
                != serde_json::to_value(&new_attempt).map_err(|_| damaged())?
            {
                return Err(damaged());
            }
            expected.financial_dispatch_v1.insert(
                attempt,
                serde_json::to_value(new_attempt).map_err(|_| damaged())?,
            );
        }
        _ => return Err(damaged()),
    }
    if serde_json::to_value(&expected).map_err(|_| damaged())?
        != serde_json::to_value(&new).map_err(|_| damaged())?
    {
        return Err(damaged());
    }
    let mut expected_envelope = before.clone();
    put(&mut expected_envelope, id, &expected)?;
    expected_envelope.view.revision = before.view.revision.checked_add(1).ok_or_else(damaged)?;
    expected_envelope.view.updated_at = after.view.updated_at.clone();
    if crate::encode(&expected_envelope)? != crate::encode(after)? {
        return Err(damaged());
    }
    validate_stored(after)
}

pub(crate) struct PreparedFinancialKernelV2 {
    envelope: Envelope,
    stored: Stored,
    checkpoint: VerifiedCheckpoint,
    binding: FinancialBindingV2,
}
impl PreparedFinancialKernelV2 {
    pub(crate) fn new(
        envelope: Envelope,
        access: &Access,
        checkpoint: VerifiedCheckpoint,
    ) -> Result<Self> {
        let candidate = envelope.view.candidates.first().ok_or_else(damaged)?;
        let stored = stored(&envelope, &candidate.candidate_id)?;
        if stored.principal_id != access.principal_id
            || stored.proof_job_id != checkpoint.summary().job_id
        {
            return Err(damaged());
        }
        let binding = stored_binding(&stored)?;
        let fixed = verify_fixed(candidate, &checkpoint, &stored.mappings)?;
        if fixed.identity() != &stored.identity {
            return Err(damaged());
        }
        Ok(Self {
            envelope,
            stored,
            checkpoint,
            binding,
        })
    }
    pub(crate) fn checkpoint_scope(&self) -> &CheckpointScope {
        self.checkpoint.scope()
    }
    pub(crate) fn identity(&self) -> &FixedProposalIdentityV1 {
        &self.stored.identity
    }
    pub(crate) fn binding(&self) -> &FinancialBindingV2 {
        &self.binding
    }
    pub(crate) fn intake(
        &self,
        key: &str,
        delivery: &impl AuthenticatedFinancialResultEvidenceV2,
        retention: LocalSignedRetention<'_>,
        read: &dyn LocalProofConsent,
        historical: bool,
        history: &AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<Option<Envelope>> {
        delivery.check_current().map_err(|_| conflict())?;
        let actual_account = delivery.account_id();
        let authorization_id = delivery.authorization_id();
        let result_digest = delivery.result_digest();
        let continuation = self
            .binding()
            .continuations
            .get(actual_account)
            .ok_or_else(conflict)?;
        if serde_json::to_value(history.continuation_request()).map_err(|_| damaged())?
            != serde_json::to_value(&continuation.request).map_err(|_| damaged())?
            || serde_json::to_value(delivery.continuation_request()).map_err(|_| damaged())?
                != serde_json::to_value(&continuation.request).map_err(|_| damaged())?
            || !digest(result_digest)
            || authorization_id
                != continuation
                    .record
                    .terms
                    .scope
                    .authorization
                    .authorization_id
        {
            return Err(conflict());
        }
        let reservation = history
            .reservation()
            .map_err(|_| damaged())?
            .ok_or_else(damaged)?;
        if reservation.request.account_id != actual_account
            || reservation.request.authorization_id != authorization_id
        {
            return Err(conflict());
        }
        let financial_result = CompletedDispatchOwnerV1 {
            account_id: actual_account.into(),
            continuation_operation_id: continuation.request.operation_id.clone(),
            continuation_request_digest: continuation
                .record
                .request_digest(&continuation.request)
                .map_err(|_| damaged())?,
            reservation_operation_id: reservation.request.operation_id.clone(),
            reservation_request_digest: reservation.request_digest.clone(),
            signature_result_digest: result_digest.into(),
        };
        let (context, signatures) =
            crate::signature_intake::financial_continuation_v1::retention_inputs(
                &self.checkpoint,
                &self.stored.identity,
                delivery,
            )?;
        let first = signatures.first().ok_or_else(conflict)?;
        if signatures
            .iter()
            .any(|s| s.participant_index != first.participant_index)
        {
            return Err(conflict());
        }
        let candidate = self.envelope.view.candidates.first().ok_or_else(damaged)?;
        let participant = candidate
            .proposal
            .manifest
            .participants
            .get(first.participant_index)
            .ok_or_else(damaged)?;
        let account = &participant.account_id;
        if !self.binding().continuations.contains_key(account) {
            return Err(conflict());
        }
        let mut indices: Vec<_> = signatures.iter().map(|s| s.action_index).collect();
        indices.sort_unstable();
        let expected: BTreeSet<_> = self
            .checkpoint
            .policy()
            .inputs
            .iter()
            .filter(|i| i.participant_index == first.participant_index)
            .map(|i| i.action_index)
            .collect();
        if indices.len() != expected.len()
            || indices.iter().copied().collect::<BTreeSet<_>>() != expected
        {
            return Err(conflict());
        }
        let gate = Gate {
            scope: self.checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        if let Some(original) = self.stored.intakes.get(account) {
            if original.retention_key != key
                || original.reference.delivery_provenance_digest
                    != context.delivery_provenance_digest
                || original.financial_result_v1.as_ref()
                    != Some(&serde_json::to_value(&financial_result).map_err(|_| damaged())?)
            {
                return Err(conflict());
            }
            let saved = retention
                .journal
                .verify_completed_existing(
                    context,
                    key,
                    self.checkpoint.pczt_bytes(),
                    self.checkpoint.policy(),
                    &signatures,
                    limits(),
                    &gate,
                )
                .map_err(retention_error)?;
            if saved.result_id != original.reference.result_id
                || saved.request_digest != original.reference.request_digest
                || saved.signed_candidate_digest != original.reference.signed_candidate_digest
            {
                return Err(damaged());
            }
            delivery.check_current().map_err(|_| conflict())?;
            return Ok(None);
        }
        if self.stored.union.is_some() {
            return Err(conflict());
        }
        let summary = if historical {
            retention.journal.reconcile_existing(
                context.clone(),
                key,
                self.checkpoint.pczt_bytes(),
                self.checkpoint.policy(),
                &signatures,
                limits(),
                &gate,
            )
        } else {
            retention.journal.retain(
                context.clone(),
                key,
                self.checkpoint.pczt_bytes(),
                self.checkpoint.policy(),
                &signatures,
                limits(),
                &gate,
            )
        }
        .map_err(retention_error)?;
        delivery.check_current().map_err(|_| conflict())?;
        let mut stored = self.stored.clone();
        stored.intakes.insert(
            account.clone(),
            Intake {
                reference: RetainedIntakeRefV1 {
                    result_id: summary.result_id,
                    request_digest: summary.request_digest,
                    signed_candidate_digest: summary.signed_candidate_digest,
                    delivery_provenance_digest: context.delivery_provenance_digest,
                },
                retention_key: key.into(),
                participant_id: participant.participant_id.clone(),
                action_indices: indices,
                accepted_at: crate::now(),
                financial_result_v1: Some(
                    serde_json::to_value(&financial_result).map_err(|_| damaged())?,
                ),
            },
        );
        let mut after = self.envelope.clone();
        put(&mut after, &stored.identity.proposal_id, &stored)?;
        Ok(Some(after))
    }
    pub(crate) fn retain_union(
        &self,
        key: &str,
        retention: LocalSignedRetention<'_>,
        read: &dyn LocalProofConsent,
    ) -> Result<Option<Envelope>> {
        if self.stored.intakes.len() != 2 {
            return Err(incomplete());
        }
        let gate = Gate {
            scope: self.checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        let union = retention
            .journal
            .load_verified_union(
                union_context(&self.stored, &self.checkpoint)?,
                &sources(&self.stored),
                self.checkpoint.pczt_bytes(),
                self.checkpoint.policy(),
                limits(),
                &gate,
            )
            .map_err(retention_error)?;
        if !union.inspection().signatures_complete {
            return Err(incomplete());
        }
        if let Some(original) = &self.stored.union {
            if original.retention_key != key {
                return Err(conflict());
            }
            check_union(
                &union
                    .verify_completed_existing(key)
                    .map_err(retention_error)?,
                original,
            )?;
            return Ok(None);
        }
        let summary = union.retain(key).map_err(retention_error)?;
        let mut stored = self.stored.clone();
        stored.union = Some(Union {
            retention_key: key.into(),
            source_set_digest: retained_source_set_digest_v1(&sources(&stored))
                .map_err(retention_error)?,
            result_id: summary.result_id,
            request_digest: summary.request_digest,
            signed_candidate_digest: summary.signed_candidate_digest,
        });
        let mut after = self.envelope.clone();
        put(&mut after, &stored.identity.proposal_id, &stored)?;
        Ok(Some(after))
    }
    pub(crate) fn completed_owners(&self) -> Result<Vec<CompletedDispatchOwnerV1>> {
        if self.stored.intakes.len() != 2 || self.stored.union.is_none() {
            return Err(incomplete());
        }
        self.stored
            .intakes
            .iter()
            .map(|(account, intake)| {
                let value = intake.financial_result_v1.as_ref().ok_or_else(damaged)?;
                let owner: CompletedDispatchOwnerV1 =
                    serde_json::from_value(value.clone()).map_err(|_| damaged())?;
                if serde_json::to_value(&owner).map_err(|_| damaged())? != *value
                    || &owner.account_id != account
                {
                    return Err(damaged());
                }
                let continuation = self
                    .binding()
                    .continuations
                    .get(account)
                    .ok_or_else(damaged)?;
                if owner.continuation_operation_id != continuation.request.operation_id
                    || owner.continuation_request_digest
                        != continuation
                            .record
                            .request_digest(&continuation.request)
                            .map_err(|_| damaged())?
                {
                    return Err(damaged());
                }
                Ok(owner)
            })
            .collect()
    }
    pub(crate) fn checkpoint_transaction(
        &self,
        retention: LocalSignedRetention<'_>,
        read: &dyn LocalProofConsent,
        transactions: LocalTransactionCheckpoint<'_>,
    ) -> Result<TransactionCheckpointSummary> {
        let original = self.stored.union.as_ref().ok_or_else(incomplete)?;
        let gate = Gate {
            scope: self.checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        let union = retention
            .journal
            .load_verified_union(
                union_context(&self.stored, &self.checkpoint)?,
                &sources(&self.stored),
                self.checkpoint.pczt_bytes(),
                self.checkpoint.policy(),
                limits(),
                &gate,
            )
            .map_err(retention_error)?;
        union
            .checkpoint_completed_transaction(&original.retention_key, transactions)
            .map_err(retention_error)
    }
    pub(crate) fn verify_submission(
        &self,
        operation: &str,
        retention: LocalSignedRetention<'_>,
        read: &dyn LocalProofConsent,
        transactions: LocalTransactionCheckpoint<'_>,
    ) -> Result<super::submission_verification_v1::VerifiedDurableSubmissionV1> {
        let original = self.stored.union.as_ref().ok_or_else(incomplete)?;
        let gate = Gate {
            scope: self.checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        let union = retention
            .journal
            .load_verified_union(
                union_context(&self.stored, &self.checkpoint)?,
                &sources(&self.stored),
                self.checkpoint.pczt_bytes(),
                self.checkpoint.policy(),
                limits(),
                &gate,
            )
            .map_err(retention_error)?;
        let retained = union
            .verify_retained_submission(
                &original.retention_key,
                &self.stored.identity.obligation_id,
                &self.stored.identity.proposal_id,
                operation,
                &transactions,
            )
            .map_err(|_| submission_error(operation))?;
        if retained.signed_result_id() != original.result_id
            || retained.signed_request_digest() != original.request_digest
            || retained.signed_candidate_digest() != original.signed_candidate_digest
            || retained.context().delivery_provenance_digest != original.source_set_digest
        {
            return Err(damaged());
        }
        Ok(
            super::submission_verification_v1::VerifiedDurableSubmissionV1 {
                retained,
                fixed: self.stored.identity.clone(),
                signature_retention_key: original.retention_key.clone(),
            },
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedDispatchAttemptV1 {
    pub requests: [AuthorizeCompletedDispatchV1; 2],
    pub chain_attempt_number: u32,
    pub previous_outcomes: BTreeMap<String, Option<CompletedDispatchAdmissionV1>>,
    pub previous_history_digests: BTreeMap<String, String>,
    pub admissions: BTreeMap<String, CompletedDispatchAdmissionV1>,
}
fn decode_dispatch(value: &serde_json::Value) -> Result<RetainedDispatchAttemptV1> {
    if serde_json::to_vec(value).map_err(|_| damaged())?.len() > 128 * 1024 {
        return Err(damaged());
    }
    let parsed: RetainedDispatchAttemptV1 =
        serde_json::from_value(value.clone()).map_err(|_| damaged())?;
    if serde_json::to_value(&parsed).map_err(|_| damaged())? != *value {
        return Err(damaged());
    }
    Ok(parsed)
}
pub(super) fn validate_financial_intakes(stored: &Stored) -> Result<()> {
    let binding = stored_binding(stored)?;
    for (account, intake) in &stored.intakes {
        financial_owner(&binding, account, intake)?;
    }
    Ok(())
}
fn financial_owner(
    binding: &FinancialBindingV2,
    account: &str,
    intake: &Intake,
) -> Result<CompletedDispatchOwnerV1> {
    let value = intake.financial_result_v1.as_ref().ok_or_else(damaged)?;
    let owner: CompletedDispatchOwnerV1 =
        serde_json::from_value(value.clone()).map_err(|_| damaged())?;
    let continuation = binding.continuations.get(account).ok_or_else(damaged)?;
    if serde_json::to_value(&owner).map_err(|_| damaged())? != *value
        || owner.account_id != account
        || owner.continuation_operation_id != continuation.request.operation_id
        || owner.continuation_request_digest
            != continuation
                .record
                .request_digest(&continuation.request)
                .map_err(|_| damaged())?
        || !digest(&owner.signature_result_digest)
        || !digest(&owner.reservation_request_digest)
        || owner.reservation_operation_id.is_empty()
        || owner.reservation_operation_id.len() > 256
    {
        return Err(damaged());
    }
    Ok(owner)
}
pub(super) fn validate_dispatch_history(stored: &Stored) -> Result<()> {
    let binding = stored_binding(stored)?;
    let delivery = &binding
        .continuations
        .values()
        .next()
        .ok_or_else(damaged)?
        .record
        .terms
        .scope
        .delivery;
    if stored.union.is_none()
        || stored.financial_dispatch_v1.len()
            > delivery.maximum_explicitly_approved_attempts as usize
    {
        return Err(damaged());
    }
    let mut previous: Option<RetainedDispatchAttemptV1> = None;
    for (index, (attempt, value)) in stored.financial_dispatch_v1.iter().enumerate() {
        if *attempt != (index + 1) as u32 {
            return Err(damaged());
        }
        let current = decode_dispatch(value)?;
        let [left, right] = &current.requests;
        left.validate().map_err(|_| damaged())?;
        right.validate().map_err(|_| damaged())?;
        if left.account_id >= right.account_id
            || left.context != right.context
            || left.context.attempt != *attempt
            || &left.context.delivery != delivery
            || current.admissions.len() > 2
        {
            return Err(damaged());
        }
        let owners = stored
            .intakes
            .iter()
            .map(|(a, i)| financial_owner(&binding, a, i))
            .collect::<Result<Vec<_>>>()?;
        let union = stored.union.as_ref().ok_or_else(damaged)?;
        if left.context.owners != owners
            || left.context.signed_result_request_digest != union.request_digest
            || left.context.signed_artifact_digest != union.signed_candidate_digest
            || serde_json::to_value(&left.context.fixed).map_err(|_| damaged())?
                != serde_json::to_value(&stored.identity).map_err(|_| damaged())?
        {
            return Err(damaged());
        }
        if let Some(old) = &previous {
            if current.chain_attempt_number < old.chain_attempt_number
                || current.chain_attempt_number > old.chain_attempt_number + 1
                || current.previous_outcomes.len() != 2
                || current.previous_history_digests.len() != 2
            {
                return Err(damaged());
            }
            for request in &old.requests {
                let outcome = current
                    .previous_outcomes
                    .get(&request.account_id)
                    .ok_or_else(damaged)?;
                if !current
                    .previous_history_digests
                    .get(&request.account_id)
                    .is_some_and(|d| digest(d))
                {
                    return Err(damaged());
                }
                if let Some(receipt) = outcome {
                    receipt.validate().map_err(|_| damaged())?;
                    if receipt.request != *request {
                        return Err(damaged());
                    }
                }
                if let Some(saved) = old.admissions.get(&request.account_id) {
                    if outcome.as_ref() != Some(saved) {
                        return Err(damaged());
                    }
                }
            }
            let mut context = old.requests[0].context.clone();
            context.attempt = *attempt;
            if context != left.context {
                return Err(damaged());
            }
        } else if current.chain_attempt_number != 1
            || !current.previous_outcomes.is_empty()
            || !current.previous_history_digests.is_empty()
        {
            return Err(damaged());
        }
        for (account, admission) in &current.admissions {
            admission.validate().map_err(|_| damaged())?;
            let request = current
                .requests
                .iter()
                .find(|r| &r.account_id == account)
                .ok_or_else(damaged)?;
            if &admission.request != request {
                return Err(damaged());
            }
        }
        previous = Some(current);
    }
    Ok(())
}
impl PreparedFinancialKernelV2 {
    pub(crate) fn retained_dispatch(&self, attempt: u32) -> Result<RetainedDispatchAttemptV1> {
        validate_dispatch_history(&self.stored)?;
        decode_dispatch(
            self.stored
                .financial_dispatch_v1
                .get(&attempt)
                .ok_or_else(damaged)?,
        )
    }
    pub(crate) fn next_delegation_attempt(&self) -> u32 {
        self.stored.financial_dispatch_v1.len() as u32 + 1
    }
    pub(crate) fn retain_dispatch_intent(
        &self,
        requests: [AuthorizeCompletedDispatchV1; 2],
        chain_attempt_number: u32,
        previous_outcomes: BTreeMap<String, Option<CompletedDispatchAdmissionV1>>,
        previous_history_digests: BTreeMap<String, String>,
    ) -> Result<Envelope> {
        let attempt = requests[0].context.attempt;
        if attempt != self.stored.financial_dispatch_v1.len() as u32 + 1 {
            return Err(conflict());
        }
        let mut stored = self.stored.clone();
        stored.financial_dispatch_v1.insert(
            attempt,
            serde_json::to_value(RetainedDispatchAttemptV1 {
                requests,
                chain_attempt_number,
                previous_outcomes,
                previous_history_digests,
                admissions: BTreeMap::new(),
            })
            .map_err(|_| damaged())?,
        );
        validate_dispatch_history(&stored)?;
        let mut after = self.envelope.clone();
        put(&mut after, &stored.identity.proposal_id, &stored)?;
        Ok(after)
    }
    pub(crate) fn retain_dispatch_admission(
        &self,
        actual: &AuthenticatedCompletedDispatchAdmissionV1,
    ) -> Result<Envelope> {
        // This records a genuine authenticated outcome; a replayed serialized
        // receipt can never become a live submission permit through this method.
        let admission = actual.admission();
        admission.validate().map_err(|_| damaged())?;
        let attempt = admission.request.context.attempt;
        let mut retained = self.retained_dispatch(attempt)?;
        if attempt != self.stored.financial_dispatch_v1.len() as u32
            || retained
                .admissions
                .contains_key(&admission.request.account_id)
            || !retained.requests.iter().any(|r| r == &admission.request)
        {
            return Err(conflict());
        }
        retained
            .admissions
            .insert(admission.request.account_id.clone(), admission.clone());
        let mut stored = self.stored.clone();
        stored.financial_dispatch_v1.insert(
            attempt,
            serde_json::to_value(retained).map_err(|_| damaged())?,
        );
        validate_dispatch_history(&stored)?;
        let mut after = self.envelope.clone();
        put(&mut after, &stored.identity.proposal_id, &stored)?;
        Ok(after)
    }
    pub(crate) fn advance_after_own_commit(mut self, after: Envelope) -> Result<Self> {
        let stored = stored(&after, &self.stored.identity.proposal_id)?;
        if stored.identity != self.stored.identity
            || serde_json::to_value(&stored.mappings).map_err(|_| damaged())?
                != serde_json::to_value(&self.stored.mappings).map_err(|_| damaged())?
            || stored.financial_binding_v2 != self.stored.financial_binding_v2
            || stored.principal_id != self.stored.principal_id
            || stored.proof_job_id != self.stored.proof_job_id
        {
            return Err(damaged());
        }
        self.envelope = after;
        self.stored = stored;
        Ok(self)
    }
}

impl PreparedFinancialKernelV2 {
    pub(crate) fn retain_submission<
        A: wholepact_chain::SubmissionAuthority,
        C: wholepact_chain::SubmissionClock,
    >(
        &self,
        operation: &str,
        retention: LocalSignedRetention<'_>,
        read: &dyn LocalProofConsent,
        local: LocalSubmissionHandoff<'_, A, C>,
    ) -> Result<wholepact_chain::SubmissionDescriptor> {
        let original = self.stored.union.as_ref().ok_or_else(incomplete)?;
        let gate = Gate {
            scope: self.checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        let union = retention
            .journal
            .load_verified_union(
                union_context(&self.stored, &self.checkpoint)?,
                &sources(&self.stored),
                self.checkpoint.pczt_bytes(),
                self.checkpoint.policy(),
                limits(),
                &gate,
            )
            .map_err(retention_error)?;
        union
            .retain_transaction_for_submission(
                &original.retention_key,
                &self.stored.identity.obligation_id,
                &self.stored.identity.proposal_id,
                operation,
                local,
            )
            .map_err(|_| submission_error(operation))
    }
    pub(crate) async fn dispatch_submission<
        A: wholepact_chain::SubmissionAuthority,
        B: wholepact_chain::SubmissionBackend,
        C: wholepact_chain::SubmissionClock,
    >(
        &self,
        operation: &str,
        retention: LocalSignedRetention<'_>,
        read: &dyn LocalProofConsent,
        local: LocalSubmissionDispatch<'_, A, B, C>,
    ) -> Result<wholepact_chain::SubmissionDispatchReport> {
        let original = self.stored.union.as_ref().ok_or_else(incomplete)?;
        let gate = Gate {
            scope: self.checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        let union = retention
            .journal
            .load_verified_union(
                union_context(&self.stored, &self.checkpoint)?,
                &sources(&self.stored),
                self.checkpoint.pczt_bytes(),
                self.checkpoint.policy(),
                limits(),
                &gate,
            )
            .map_err(retention_error)?;
        union
            .dispatch_retained_transaction(
                &original.retention_key,
                &self.stored.identity.obligation_id,
                &self.stored.identity.proposal_id,
                operation,
                local,
            )
            .await
            .map_err(|_| submission_error(operation))
    }
}

impl PreparedFinancialKernelV2 {
    pub(crate) fn preview_retention_scope(
        &self,
        preview:&wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultPreviewV1,
    ) -> Result<wholepact_protocol::authorization::retention::SignedRetentionScope> {
        let original = self
            .binding
            .continuations
            .get(preview.account_id())
            .ok_or_else(damaged)?;
        if preview.continuation_request() != &original.request
            || preview.continuation_record() != &original.record
        {
            return Err(damaged());
        }
        crate::signature_intake::financial_continuation_v1::preview_retention_scope(
            &self.checkpoint,
            &self.stored.identity,
            preview,
        )
    }
}

use super::private_financial_v1::FinancialRetentionContextsV1;
impl PreparedFinancialKernelV2 {
    pub(crate) fn retention_contexts(&self) -> Result<FinancialRetentionContextsV1> {
        validate_stored(&self.envelope)?;
        if self.stored.intakes.len() != 2 || self.binding.continuations.len() != 2 {
            return Err(incomplete());
        }
        let union_context = union_context(&self.stored, &self.checkpoint)?;
        let mut contexts = Vec::with_capacity(2);
        let mut provenances = BTreeSet::new();
        let mut results = BTreeSet::new();
        for (account, intake) in &self.stored.intakes {
            financial_owner(&self.binding, account, intake)?;
            let provenance = &intake.reference.delivery_provenance_digest;
            if !digest(provenance)
                || provenance == &union_context.delivery_provenance_digest
                || !provenances.insert(provenance)
                || !results.insert(&intake.reference.result_id)
            {
                return Err(damaged());
            }
            let mut context = union_context.clone();
            context.delivery_provenance_digest = provenance.clone();
            contexts.push(context);
        }
        Ok(FinancialRetentionContextsV1::from_exact_contexts_v2(
            contexts.try_into().map_err(|_| damaged())?, union_context,
        ))
    }
}
