//! Versioned fixed-proposal orchestration. Durable data survives human waiting;
//! local read/retention permission and signing/submission authority do not.
//!
//! These APIs never reconstruct a candidate, revive native consent, release an
//! authorization, or clear account exposure. All private artifacts remain in the
//! existing encrypted proof, signed-result and transaction journals.
use crate::proof_jobs::LocalProofJob;
use crate::signature_intake::{AuthenticatedSignatureDelivery, LocalSignedRetention};
use crate::{Access, ApiError, Engine, Envelope, Mutation, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, VerifiedCheckpoint};
use wholepact_protocol::{
    authorization::retention::{
        durable_intake_v1::{retained_source_set_digest_v1, RetainedIntakeRefV1},
        transaction::{
            submission_handoff::{LocalSubmissionDispatch, LocalSubmissionHandoff},
            LocalTransactionCheckpoint, TransactionCheckpointSummary,
        },
        RetentionError, SignedCandidateContext, SignedRetentionConsent, SignedRetentionScope,
    },
    construction::{InputActionMapping, OutputActionMapping},
    durable_proposal_v1::{FixedProposalIdentityV1, VerifiedFixedProposal},
    proving::ProvingLimits,
};
use wholepact_transport::Timestamp;

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) mod private_financial_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) mod private_financial_v2;
pub mod submission_verification_v1;

const MAX_ACTIONS: usize = 8;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputMapping {
    input_id: String,
    account_id: String,
    action_index: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputMapping {
    output_id: String,
    action_index: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mappings {
    inputs: Vec<InputMapping>,
    outputs: Vec<OutputMapping>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intake {
    reference: RetainedIntakeRefV1,
    retention_key: String,
    participant_id: String,
    action_indices: Vec<usize>,
    accepted_at: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_financial_binding_v1"
    )]
    financial_result_v1: Option<serde_json::Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Union {
    retention_key: String,
    source_set_digest: String,
    result_id: String,
    request_digest: String,
    signed_candidate_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    schema_version: u16,
    principal_id: String,
    proof_job_id: String,
    identity: FixedProposalIdentityV1,
    mappings: Mappings,
    intakes: BTreeMap<String, Intake>,
    union: Option<Union>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_financial_binding_v1"
    )]
    financial_binding_v1: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_financial_binding_v1")]
    financial_binding_v2: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    financial_dispatch_v1: BTreeMap<u32, serde_json::Value>,
}

fn deserialize_financial_binding_v1<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<serde_json::Value>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() || !value.is_object() {
        return Err(serde::de::Error::custom("invalid financial binding"));
    }
    Ok(Some(value))
}

/// Non-authorizing progress, re-derived from exact encrypted artifacts, never a
/// cached `approved` flag. Cancellation does not mean signatures were recalled.
#[derive(Clone, Debug, Serialize)]
pub struct DurableProposalSummaryV1 {
    pub identity: FixedProposalIdentityV1,
    pub retained_owner_count: usize,
    pub verified_real_inputs: usize,
    pub required_real_inputs: usize,
    pub signatures_complete: bool,
    pub cancellation_requested: bool,
    pub authorization_allowed: bool,
    pub distribution_allowed: bool,
    pub chain_validated: bool,
}

pub(crate) fn validate_stored(envelope: &Envelope) -> Result<()> {
    for (id, value) in &envelope.durable_proposals_v1 {
        let stored: Stored = serde_json::from_value(value.clone()).map_err(|_| damaged())?;
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|c| &c.candidate_id == id)
            .ok_or_else(damaged)?;
        if stored.schema_version != 1
            || stored.identity.schema_version != 1
            || stored.identity.proposal_id != *id
            || stored.identity.agreement_id != envelope.view.agreement.agreement_id
            || stored.identity.obligation_id != envelope.view.agreement.obligation_id
            || stored.identity.manifest_digest != candidate.manifest_digest
            || stored.identity.proposal_digest != candidate.proposal_digest
            || stored.principal_id.is_empty()
            || stored.principal_id.len() > 128
            || stored.proof_job_id.len() > 128
            || stored.intakes.len() > 2
            || stored.mappings.inputs.len() > MAX_ACTIONS
            || stored.mappings.outputs.len() > MAX_ACTIONS
        {
            return Err(damaged());
        }
        if (stored.financial_binding_v1.is_some() || stored.financial_binding_v2.is_some() || !stored.financial_dispatch_v1.is_empty())
            && envelope.private_workspace_origin_v1.is_none()
        {
            return Err(damaged());
        }
        if !stored.financial_dispatch_v1.is_empty() {
            #[cfg(all(feature = "manual-admission", target_os = "linux"))]
            {
                if stored.financial_binding_v2.is_some() {
                    private_financial_v2::validate_dispatch_history(&stored)?;
                } else {
                    private_financial_v1::validate_dispatch_history(&stored)?;
                }
            }
            #[cfg(not(all(feature = "manual-admission", target_os = "linux")))]
            return Err(damaged());
        }
        if stored.financial_binding_v1.is_some() && stored.financial_binding_v2.is_some() {
            return Err(damaged());
        }
        if let Some(binding) = &stored.financial_binding_v2 {
            #[cfg(all(feature = "manual-admission", target_os = "linux"))]
            {
                private_financial_v2::decode_binding(binding)?.validate(&stored.identity)?;
                private_financial_v2::validate_financial_intakes(&stored)?;
            }
            #[cfg(not(all(feature = "manual-admission", target_os = "linux")))]
            return Err(damaged());
        }
        if let Some(binding) = &stored.financial_binding_v1 {
            #[cfg(all(feature = "manual-admission", target_os = "linux"))]
            {
                private_financial_v1::decode_binding(binding)?.validate(&stored.identity)?;
                private_financial_v1::validate_financial_intakes(&stored)?;
            }
            #[cfg(not(all(feature = "manual-admission", target_os = "linux")))]
            return Err(damaged());
        }
        let mut actions = BTreeSet::new();
        for (account, intake) in &stored.intakes {
            if stored.financial_binding_v1.is_none() && stored.financial_binding_v2.is_none() && intake.financial_result_v1.is_some() {
                return Err(damaged());
            }
            let participant = candidate
                .proposal
                .manifest
                .participants
                .iter()
                .find(|p| p.account_id == *account && p.participant_id == intake.participant_id)
                .ok_or_else(damaged)?;
            let _ = participant;
            if intake.action_indices.is_empty()
                || intake.action_indices.len() > MAX_ACTIONS
                || intake
                    .action_indices
                    .iter()
                    .any(|i| *i >= MAX_ACTIONS || !actions.insert(*i))
                || !(16..=128).contains(&intake.retention_key.len())
                || intake.accepted_at.len() > 64
                || retained_source_set_digest_v1(&[intake.reference.clone()]).is_err()
            {
                return Err(damaged());
            }
        }
        if let Some(union) = &stored.union {
            if stored.intakes.len() != 2
                || !(16..=128).contains(&union.retention_key.len())
                || union.source_set_digest
                    != retained_source_set_digest_v1(&sources(&stored)).map_err(retention_error)?
                || !digest(&union.request_digest)
                || !digest(&union.signed_candidate_digest)
                || !union.result_id.strip_prefix("signed-").is_some_and(digest)
            {
                return Err(damaged());
            }
        }
    }
    Ok(())
}

impl Engine {
    /// Freeze an already-proved engine-origin checkpoint and original constructor
    /// mappings. No human must already be waiting in an approval UI. Historical
    /// receipts lacking exact mappings are not silently upgraded into this profile.
    pub fn freeze_durable_proposal_v1(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalProofJob<'_>,
    ) -> Result<Mutation> {
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let mut envelope = self.load(access, &view.agreement.agreement_id)?;
        crate::planning::check_proposer(&envelope, access)?;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        let receipt = envelope
            .checkpoint_receipts
            .values()
            .find(|r| {
                r.job_id == checkpoint.summary().job_id
                    && r.candidate_id == candidate_id
                    && r.principal_id == access.principal_id
            })
            .ok_or_else(damaged)?;
        let mappings: Mappings = serde_json::from_value(receipt.action_mappings_v1.clone().ok_or_else(||
            ApiError::new("DURABLE_PROFILE_UNAVAILABLE", "This historical constructor has no retained exact action mapping; it cannot be promoted to the durable profile"))?)
            .map_err(|_| damaged())?;
        let fixed = verify_fixed(&candidate, &checkpoint, &mappings)?;
        let command = crate::context(
            access,
            key,
            "freeze_durable_proposal_v1",
            candidate_id,
            Some(revision),
            &(checkpoint.summary().job_id.clone(), fixed.identity()),
        )?;
        if let Some(replayed) = self.replay(access, &command)? {
            return Ok(replayed);
        }
        crate::candidates::check_revision(&envelope, revision)?;
        if envelope.durable_proposals_v1.contains_key(candidate_id) {
            return Err(conflict());
        }
        if envelope.view.cancellation_requested {
            return Err(ApiError::new(
                "CANCELLATION_REQUESTED",
                "No new durable proposal may be frozen after coordination cancellation",
            ));
        }
        let stored = Stored {
            schema_version: 1,
            principal_id: access.principal_id.clone(),
            proof_job_id: checkpoint.summary().job_id.clone(),
            identity: fixed.identity().clone(),
            mappings,
            intakes: BTreeMap::new(),
            union: None,
            financial_binding_v1: None,
            financial_binding_v2: None,
            financial_dispatch_v1: BTreeMap::new(),
        };
        put(&mut envelope, candidate_id, &stored)?;
        envelope.view.progress = "awaiting_authorization".into();
        self.commit(
            &command,
            &view.agreement.agreement_id,
            revision,
            envelope,
            "durable_proposal_frozen",
        )
    }

    /// Reopens the same exact data for a NEW immediate local review. This returns
    /// no spend consent, writer permit, release permission, or chain-validity claim.
    pub fn load_durable_proposal_for_local_review_v1(
        &self,
        access: &Access,
        candidate_id: &str,
        local: LocalProofJob<'_>,
    ) -> Result<VerifiedFixedProposal> {
        let (_, _, _, fixed) = self.load_durable(access, candidate_id, local)?;
        Ok(fixed)
    }

    /// Authenticates one owner's detached return and retains it before recording
    /// its provenance receipt. Other owners and their native sessions are absent.
    /// A failed cross-journal metadata CAS leaves an exact retained result, not a
    /// license to sign again; retry the original input/key or reconcile it explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn intake_durable_signature_v1(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        delivery: AuthenticatedSignatureDelivery<'_>,
        now: &Timestamp,
    ) -> Result<Mutation> {
        self.intake_durable_signature_inner(
            access,
            key,
            candidate_id,
            revision,
            local,
            retention,
            delivery,
            now,
            false,
        )
    }

    /// Existing signed-intent-only recovery. Historical transport expiry is not
    /// revived; a missing original intent fails closed rather than admitting one.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_durable_signature_v1(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        delivery: AuthenticatedSignatureDelivery<'_>,
        now: &Timestamp,
    ) -> Result<Mutation> {
        self.intake_durable_signature_inner(
            access,
            key,
            candidate_id,
            revision,
            local,
            retention,
            delivery,
            now,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn intake_durable_signature_inner(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        delivery: AuthenticatedSignatureDelivery<'_>,
        now: &Timestamp,
        historical: bool,
    ) -> Result<Mutation> {
        let read = local.consent;
        let (mut envelope, mut stored, checkpoint, _) =
            self.load_durable(access, candidate_id, local)?;
        let (context, signatures) = crate::signature_intake::retention_inputs(
            &checkpoint,
            &stored.identity.agreement_id,
            candidate_id,
            stored.identity.revision.into(),
            &[delivery],
            now,
            historical,
        )?;
        let first = signatures.first().ok_or_else(conflict)?;
        if signatures
            .iter()
            .any(|s| s.participant_index != first.participant_index)
        {
            return Err(conflict());
        }
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|c| c.candidate_id == candidate_id)
            .ok_or_else(damaged)?;
        let participant = candidate
            .proposal
            .manifest
            .participants
            .get(first.participant_index)
            .ok_or_else(damaged)?;
        let account_id = participant.account_id.clone();
        let participant_id = participant.participant_id.clone();
        let mut indices: Vec<_> = signatures.iter().map(|s| s.action_index).collect();
        indices.sort_unstable();
        let expected: BTreeSet<_> = checkpoint
            .policy()
            .inputs
            .iter()
            .filter(|i| i.participant_index == first.participant_index)
            .map(|i| i.action_index)
            .collect();
        if indices.iter().copied().collect::<BTreeSet<_>>() != expected
            || indices.len() != expected.len()
        {
            return Err(conflict());
        }
        let signature_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:durable-intake-request:v1",
            &signatures
                .iter()
                .map(|s| {
                    (
                        s.participant_index,
                        s.action_index,
                        hex::encode(s.signature),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|_| conflict())?;
        // Recovery can use a fresh metadata revision, but the private retention
        // key always identifies the original exact intent and cannot change it.
        let command = crate::context(
            access,
            key,
            "intake_durable_signature_v1",
            candidate_id,
            Some(revision),
            &(
                &stored.identity.proposal_binding,
                &context.delivery_provenance_digest,
                &signature_digest,
            ),
        )?;
        let gate = Gate {
            scope: checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        if let Some(replayed) = self.replay(access, &command)? {
            let original = stored.intakes.get(&account_id).ok_or_else(damaged)?;
            if original.retention_key != key
                || original.reference.delivery_provenance_digest
                    != context.delivery_provenance_digest
            {
                return Err(damaged());
            }
            retention
                .journal
                .load_verified_union(
                    union_context(&stored, &checkpoint)?,
                    &sources(&stored),
                    checkpoint.pczt_bytes(),
                    checkpoint.policy(),
                    limits(),
                    &gate,
                )
                .map_err(retention_error)?;
            return Ok(replayed);
        }
        crate::candidates::check_revision(&envelope, revision)?;
        if stored.intakes.contains_key(&account_id) || stored.union.is_some() {
            return Err(conflict());
        }
        let summary = if historical {
            retention.journal.reconcile_existing(
                context.clone(),
                key,
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                &signatures,
                limits(),
                &gate,
            )
        } else {
            retention.journal.retain(
                context.clone(),
                key,
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                &signatures,
                limits(),
                &gate,
            )
        }
        .map_err(retention_error)?;
        let reference = RetainedIntakeRefV1 {
            result_id: summary.result_id,
            request_digest: summary.request_digest,
            signed_candidate_digest: summary.signed_candidate_digest,
            delivery_provenance_digest: context.delivery_provenance_digest,
        };
        stored.intakes.insert(
            account_id,
            Intake {
                reference,
                retention_key: key.into(),
                participant_id,
                action_indices: indices,
                accepted_at: crate::now(),
                financial_result_v1: None,
            },
        );
        put(&mut envelope, candidate_id, &stored)?;
        self.commit(&command, &stored.identity.agreement_id, revision, envelope, "durable_signature_intake_recorded")
            .map_err(|mut e| { e.safe_actions = vec!["Preserve the exact private signed intent and retry or reconcile only the original delivery and retention key".into()]; e })
    }

    /// Reloads historical intake receipts from this engine's protected original
    /// agreement. No caller-supplied receipt, signature or sender claim is accepted.
    pub fn durable_proposal_status_v1(
        &self,
        access: &Access,
        candidate_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
    ) -> Result<DurableProposalSummaryV1> {
        let read = local.consent;
        let (envelope, stored, checkpoint, _) = self.load_durable(access, candidate_id, local)?;
        let inspection = if stored.intakes.is_empty() {
            None
        } else {
            let gate = Gate {
                scope: checkpoint.scope(),
                read,
                retain: retention.consent,
            };
            let union = retention
                .journal
                .load_verified_union(
                    union_context(&stored, &checkpoint)?,
                    &sources(&stored),
                    checkpoint.pczt_bytes(),
                    checkpoint.policy(),
                    limits(),
                    &gate,
                )
                .map_err(retention_error)?;
            Some(union.inspection().clone())
        };
        Ok(DurableProposalSummaryV1 {
            identity: stored.identity,
            retained_owner_count: stored.intakes.len(),
            verified_real_inputs: inspection.as_ref().map_or(0, |i| i.verified_real_inputs),
            required_real_inputs: checkpoint.policy().inputs.len(),
            signatures_complete: inspection.as_ref().is_some_and(|i| i.signatures_complete),
            cancellation_requested: envelope.view.cancellation_requested,
            authorization_allowed: false,
            distribution_allowed: false,
            chain_validated: false,
        })
    }

    /// Deterministic signature-only union. The source set is fixed in the request
    /// and metadata, and old authenticated owner sessions are never reopened.
    pub fn assemble_durable_proposal_v1(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
    ) -> Result<Mutation> {
        let read = local.consent;
        let (mut envelope, mut stored, checkpoint, _) =
            self.load_durable(access, candidate_id, local)?;
        let source_set_digest =
            retained_source_set_digest_v1(&sources(&stored)).map_err(retention_error)?;
        let command = crate::context(
            access,
            key,
            "assemble_durable_proposal_v1",
            candidate_id,
            Some(revision),
            &(&stored.identity.proposal_binding, &source_set_digest),
        )?;
        let gate = Gate {
            scope: checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        if let Some(mut replayed) = self.replay(access, &command)? {
            let original = stored.union.as_ref().ok_or_else(damaged)?;
            if original.retention_key != key || original.source_set_digest != source_set_digest {
                return Err(damaged());
            }
            let union = retention
                .journal
                .load_verified_union(
                    union_context(&stored, &checkpoint)?,
                    &sources(&stored),
                    checkpoint.pczt_bytes(),
                    checkpoint.policy(),
                    limits(),
                    &gate,
                )
                .map_err(retention_error)?;
            check_union(&union.retain(key).map_err(retention_error)?, original)?;
            // Idempotent history does not override newer cancellation guidance.
            if envelope.view.cancellation_requested {
                replayed.agreement.cancellation_requested = true;
                replayed.agreement.progress = envelope.view.progress.clone();
            }
            return Ok(replayed);
        }
        crate::candidates::check_revision(&envelope, revision)?;
        if stored.intakes.len() != 2 || stored.union.is_some() {
            return Err(incomplete());
        }
        let union = retention
            .journal
            .load_verified_union(
                union_context(&stored, &checkpoint)?,
                &sources(&stored),
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                limits(),
                &gate,
            )
            .map_err(retention_error)?;
        if !union.inspection().signatures_complete {
            return Err(incomplete());
        }
        let summary = union.retain(key).map_err(retention_error)?;
        stored.union = Some(Union {
            retention_key: key.into(),
            source_set_digest,
            result_id: summary.result_id,
            request_digest: summary.request_digest,
            signed_candidate_digest: summary.signed_candidate_digest,
        });
        put(&mut envelope, candidate_id, &stored)?;
        // Readiness is conditional: fresh chain eligibility and submission
        // authority are still mandatory, and cancellation/exposure are untouched.
        if !envelope.view.cancellation_requested {
            envelope.view.progress = "ready_for_submission".into();
        }
        self.commit(
            &command,
            &stored.identity.agreement_id,
            revision,
            envelope,
            "durable_signature_union_retained",
        )
    }

    pub fn checkpoint_durable_transaction_v1(
        &self,
        access: &Access,
        candidate_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        transaction: LocalTransactionCheckpoint<'_>,
    ) -> Result<TransactionCheckpointSummary> {
        let read = local.consent;
        let (_, stored, checkpoint, _) = self.load_durable(access, candidate_id, local)?;
        let retained = stored.union.as_ref().ok_or_else(incomplete)?;
        let gate = Gate {
            scope: checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        let union = retention
            .journal
            .load_verified_union(
                union_context(&stored, &checkpoint)?,
                &sources(&stored),
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                limits(),
                &gate,
            )
            .map_err(retention_error)?;
        check_union(
            &union
                .retain(&retained.retention_key)
                .map_err(retention_error)?,
            retained,
        )?;
        union
            .checkpoint_transaction(&retained.retention_key, transaction)
            .map_err(retention_error)
    }

    pub fn retain_durable_submission_v1<
        A: wholepact_chain::SubmissionAuthority,
        C: wholepact_chain::SubmissionClock,
    >(
        &self,
        access: &Access,
        candidate_id: &str,
        operation_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        handoff: LocalSubmissionHandoff<'_, A, C>,
    ) -> Result<wholepact_chain::SubmissionDescriptor> {
        let read = local.consent;
        let (envelope, stored, checkpoint, _) = self.load_durable(access, candidate_id, local)?;
        if envelope.view.cancellation_requested {
            return Err(ApiError::new(
                "CANCELLATION_REQUESTED",
                "New submission is blocked; existing exposure and uncertain attempts remain tracked",
            ));
        }
        let retained = stored.union.as_ref().ok_or_else(incomplete)?;
        let gate = Gate {
            scope: checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        let union = retention
            .journal
            .load_verified_union(
                union_context(&stored, &checkpoint)?,
                &sources(&stored),
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                limits(),
                &gate,
            )
            .map_err(retention_error)?;
        check_union(
            &union
                .retain(&retained.retention_key)
                .map_err(retention_error)?,
            retained,
        )?;
        union
            .retain_transaction_for_submission(
                &retained.retention_key,
                &stored.identity.obligation_id,
                candidate_id,
                operation_id,
                handoff,
            )
            .map_err(|_| submission_error(operation_id))
    }

    pub async fn dispatch_durable_submission_v1<
        A: wholepact_chain::SubmissionAuthority,
        B: wholepact_chain::SubmissionBackend,
        C: wholepact_chain::SubmissionClock,
    >(
        &self,
        access: &Access,
        candidate_id: &str,
        operation_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        handoff: LocalSubmissionDispatch<'_, A, B, C>,
    ) -> Result<wholepact_chain::SubmissionDispatchReport> {
        let read = local.consent;
        let (envelope, stored, checkpoint, _) = self.load_durable(access, candidate_id, local)?;
        if envelope.view.cancellation_requested {
            return Err(ApiError::new(
                "CANCELLATION_REQUESTED",
                "Dispatch is blocked; reconcile the original transaction and preserve its outstanding exposure",
            ));
        }
        let retained = stored.union.as_ref().ok_or_else(incomplete)?;
        let gate = Gate {
            scope: checkpoint.scope(),
            read,
            retain: retention.consent,
        };
        let union = retention
            .journal
            .load_verified_union(
                union_context(&stored, &checkpoint)?,
                &sources(&stored),
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                limits(),
                &gate,
            )
            .map_err(retention_error)?;
        check_union(
            &union
                .retain(&retained.retention_key)
                .map_err(retention_error)?,
            retained,
        )?;
        union
            .dispatch_retained_transaction(
                &retained.retention_key,
                &stored.identity.obligation_id,
                candidate_id,
                operation_id,
                handoff,
            )
            .await
            .map_err(|_| submission_error(operation_id))
    }

    // Internal protected export join. No caller-supplied mapping or artifact can
    // enter here; the same original engine receipt and fixed verifier are used.
    pub(super) fn load_durable_review_export_inputs_v1(
        &self,
        access: &Access,
        candidate_id: &str,
        local: LocalProofJob<'_>,
    ) -> Result<(
        Envelope,
        VerifiedCheckpoint,
        VerifiedFixedProposal,
        Vec<OutputActionMapping>,
    )> {
        let (envelope, stored, checkpoint, fixed) =
            self.load_durable(access, candidate_id, local)?;
        let outputs = stored
            .mappings
            .outputs
            .iter()
            .map(|m| OutputActionMapping {
                output_id: m.output_id.clone(),
                action_index: m.action_index,
            })
            .collect();
        Ok((envelope, checkpoint, fixed, outputs))
    }

    fn load_durable(
        &self,
        access: &Access,
        candidate_id: &str,
        local: LocalProofJob<'_>,
    ) -> Result<(Envelope, Stored, VerifiedCheckpoint, VerifiedFixedProposal)> {
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let envelope = self.load(access, &view.agreement.agreement_id)?;
        let stored: Stored = serde_json::from_value(
            envelope
                .durable_proposals_v1
                .get(candidate_id)
                .ok_or_else(|| {
                    ApiError::new(
                        "DURABLE_PROPOSAL_NOT_FOUND",
                        "No exact durable proposal was frozen for this candidate",
                    )
                })?
                .clone(),
        )
        .map_err(|_| damaged())?;
        if stored.principal_id != access.principal_id || stored.proof_job_id != local.job_id {
            return Err(conflict());
        }
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        let fixed = verify_fixed(&candidate, &checkpoint, &stored.mappings)?;
        if fixed.identity() != &stored.identity {
            return Err(damaged());
        }
        Ok((envelope, stored, checkpoint, fixed))
    }
}

enum FixedVerificationFailureV2 {
    Engine(ApiError),
    Protocol(String),
}
impl FixedVerificationFailureV2 {
    fn into_api(self) -> ApiError {
        match self {
            Self::Engine(e) => e,
            Self::Protocol(_) => damaged(),
        }
    }
}
fn verify_fixed(
    candidate: &crate::CandidateView,
    checkpoint: &VerifiedCheckpoint,
    mappings: &Mappings,
) -> Result<VerifiedFixedProposal> {
    verify_fixed_typed_v2(candidate, checkpoint, mappings)
        .map_err(FixedVerificationFailureV2::into_api)
}
fn verify_fixed_typed_v2(
    candidate: &crate::CandidateView,
    checkpoint: &VerifiedCheckpoint,
    mappings: &Mappings,
) -> std::result::Result<VerifiedFixedProposal, FixedVerificationFailureV2> {
    let inputs: Vec<_> = mappings
        .inputs
        .iter()
        .map(|m| InputActionMapping {
            input_id: m.input_id.clone(),
            account_id: m.account_id.clone(),
            action_index: m.action_index,
        })
        .collect();
    let outputs: Vec<_> = mappings
        .outputs
        .iter()
        .map(|m| OutputActionMapping {
            output_id: m.output_id.clone(),
            action_index: m.action_index,
        })
        .collect();
    VerifiedFixedProposal::verify(
        checkpoint.private_unsigned_pczt_bytes(),
        checkpoint.pczt_bytes(),
        &candidate
            .verified_snapshot()
            .map_err(FixedVerificationFailureV2::Engine)?,
        checkpoint.policy(),
        &inputs,
        &outputs,
        limits(),
    )
    .map_err(FixedVerificationFailureV2::Protocol)
}
fn put(envelope: &mut Envelope, id: &str, stored: &Stored) -> Result<()> {
    envelope.durable_proposals_v1.insert(
        id.into(),
        serde_json::to_value(stored).map_err(|_| damaged())?,
    );
    validate_stored(envelope)
}
fn sources(stored: &Stored) -> Vec<RetainedIntakeRefV1> {
    stored
        .intakes
        .values()
        .map(|i| i.reference.clone())
        .collect()
}
fn union_context(
    stored: &Stored,
    checkpoint: &VerifiedCheckpoint,
) -> Result<SignedCandidateContext> {
    let scope = checkpoint.scope();
    Ok(SignedCandidateContext {
        principal_id: stored.principal_id.clone(),
        candidate_id: stored.identity.proposal_id.clone(),
        proof_job_id: stored.proof_job_id.clone(),
        checkpoint_scope_digest: checkpoint.summary().scope_digest.clone(),
        proved_artifact_digest: stored.identity.proved_artifact_digest.clone(),
        manifest_digest: stored.identity.manifest_digest.clone(),
        review_binding: stored.identity.review_binding.clone(),
        delivery_provenance_digest: retained_source_set_digest_v1(&sources(stored))
            .map_err(retention_error)?,
        account_ids: scope.account_ids.clone(),
        local_operator: scope.local_operator.clone(),
        purpose: scope.purpose.clone(),
        retention_policy: scope.retention_policy.clone(),
    })
}
struct Gate<'a> {
    scope: &'a CheckpointScope,
    read: &'a dyn LocalProofConsent,
    retain: &'a dyn SignedRetentionConsent,
}
impl SignedRetentionConsent for Gate<'_> {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        let same = scope.context.principal_id == self.scope.principal_id
            && scope.context.candidate_id == self.scope.candidate_id
            && scope.context.manifest_digest == self.scope.manifest_digest
            && scope.context.review_binding == self.scope.review_binding;
        same && self
            .read
            .permits(self.scope, LocalAction::ReadPrivateArtifact)
            && self.retain.permits(scope)
            && self
                .read
                .permits(self.scope, LocalAction::ReadPrivateArtifact)
    }
}
fn check_union(
    summary: &wholepact_protocol::authorization::retention::SignedResultSummary,
    stored: &Union,
) -> Result<()> {
    if summary.result_id != stored.result_id
        || summary.request_digest != stored.request_digest
        || summary.signed_candidate_digest != stored.signed_candidate_digest
        || !summary.inspection.signatures_complete
    {
        return Err(damaged());
    }
    Ok(())
}
fn limits() -> ProvingLimits {
    ProvingLimits {
        maximum_actions: MAX_ACTIONS,
    }
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn damaged() -> ApiError {
    ApiError::new(
        "DURABLE_PROPOSAL_RECOVERY_REQUIRED",
        "The exact durable proposal or original intake evidence cannot be verified; preserve all original journals",
    )
}
fn conflict() -> ApiError {
    ApiError::new(
        "DURABLE_PROPOSAL_CONFLICT",
        "This operation differs from the immutable proposal, original owner contribution, or retained intent",
    )
}
fn incomplete() -> ApiError {
    ApiError::new(
        "DURABLE_SIGNATURES_INCOMPLETE",
        "Every required owner signature must be retained and verified before transaction extraction",
    )
}
fn retention_error(error: RetentionError) -> ApiError {
    let code = match error {
        RetentionError::ConsentDenied => "DURABLE_RETENTION_DENIED",
        RetentionError::IncompleteSignatures => "DURABLE_SIGNATURES_INCOMPLETE",
        RetentionError::IdempotencyConflict => "DURABLE_RETENTION_CONFLICT",
        RetentionError::IntentNotFound => "DURABLE_ORIGINAL_INTENT_MISSING",
        RetentionError::ResourceExhausted => "RESOURCE_EXHAUSTED",
        _ => "DURABLE_RETENTION_RECOVERY_REQUIRED",
    };
    ApiError::new(
        code,
        "Original private signature evidence was not safely retained or reverified; no new signing or release authority was granted",
    )
}
fn submission_error(id: &str) -> ApiError {
    let mut e = ApiError::new(
        "DURABLE_SUBMISSION_UNRESOLVED",
        "Inspect the exact original submission operation; an error does not establish that no transaction was retained or sent",
    );
    e.operation_id = Some(id.into());
    e.safe_actions = vec!["Reconcile the same retained transaction and operation; never reconstruct a replacement payment".into()];
    e
}

/// Exact nonauthorizing fixed-only precursor shape.
pub(crate) fn validate_private_fixed_v2(envelope: &Envelope) -> Result<()> {
    validate_stored(envelope)?;
    for value in envelope.durable_proposals_v1.values() {
        let stored: Stored = serde_json::from_value(value.clone()).map_err(|_| damaged())?;
        if !stored.intakes.is_empty()
            || stored.union.is_some()
            || stored.financial_binding_v1.is_some()
            || stored.financial_binding_v2.is_some()
            || !stored.financial_dispatch_v1.is_empty()
        {
            return Err(damaged());
        }
    }
    Ok(())
}
/// Shared verifier and serializer, never exported as a raw verified artifact.
pub(crate) fn freeze_private_fixed_v2(
    envelope: &mut Envelope,
    access: &Access,
    checkpoint: &VerifiedCheckpoint,
    receipt: &crate::candidates::CheckpointReceipt,
) -> Result<FixedProposalIdentityV1> {
    freeze_private_fixed_kernel_v2(envelope, access, checkpoint, receipt, &|_| {})
}
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) fn freeze_private_fixed_observed_v2(
    observation: &crate::durable_private_workspace_v1::diagnostics::Observation,
    envelope: &mut Envelope,
    access: &Access,
    checkpoint: &VerifiedCheckpoint,
    receipt: &crate::candidates::CheckpointReceipt,
) -> Result<FixedProposalIdentityV1> {
    use crate::durable_private_workspace_v1::diagnostics::{self, Site};
    freeze_private_fixed_kernel_v2(envelope, access, checkpoint, receipt, &|error| {
        let cause = match error {
            FixedVerificationFailureV2::Engine(e) => diagnostics::engine(e),
            FixedVerificationFailureV2::Protocol(e) => diagnostics::protocol(e),
        };
        observation.record(Site::FixedVerify, cause);
    })
}
fn freeze_private_fixed_kernel_v2(
    envelope: &mut Envelope,
    access: &Access,
    checkpoint: &VerifiedCheckpoint,
    receipt: &crate::candidates::CheckpointReceipt,
    observe: &dyn Fn(&FixedVerificationFailureV2),
) -> Result<FixedProposalIdentityV1> {
    let candidate = envelope.view.candidates.first().ok_or_else(damaged)?;
    let mappings: Mappings =
        serde_json::from_value(receipt.action_mappings_v1.clone().ok_or_else(damaged)?)
            .map_err(|_| damaged())?;
    let fixed = verify_fixed_typed_v2(candidate, checkpoint, &mappings).map_err(|error| {
        observe(&error);
        error.into_api()
    })?;
    let identity = fixed.identity().clone();
    let id = candidate.candidate_id.clone();
    if envelope.durable_proposals_v1.contains_key(&id) {
        return Err(conflict());
    }
    let stored = Stored {
        schema_version: 1,
        principal_id: access.principal_id.clone(),
        proof_job_id: checkpoint.summary().job_id.clone(),
        identity: identity.clone(),
        mappings,
        intakes: BTreeMap::new(),
        union: None,
        financial_binding_v1: None,
            financial_binding_v2: None,
        financial_dispatch_v1: BTreeMap::new(),
    };
    put(envelope, &id, &stored)?;
    envelope.view.progress = "awaiting_authorization".into();
    Ok(identity)
}
pub(crate) fn read_private_fixed_v2(
    envelope: &Envelope,
    access: &Access,
    checkpoint: &VerifiedCheckpoint,
    receipt: &crate::candidates::CheckpointReceipt,
) -> Result<FixedProposalIdentityV1> {
    read_private_fixed_kernel_v2(envelope, access, checkpoint, receipt, &|_| {})
}
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) fn read_private_fixed_observed_v2(
    observation: &crate::durable_private_workspace_v1::diagnostics::Observation,
    envelope: &Envelope,
    access: &Access,
    checkpoint: &VerifiedCheckpoint,
    receipt: &crate::candidates::CheckpointReceipt,
) -> Result<FixedProposalIdentityV1> {
    use crate::durable_private_workspace_v1::diagnostics::{self, Site};
    read_private_fixed_kernel_v2(envelope, access, checkpoint, receipt, &|error| {
        let cause = match error {
            FixedVerificationFailureV2::Engine(e) => diagnostics::engine(e),
            FixedVerificationFailureV2::Protocol(e) => diagnostics::protocol(e),
        };
        observation.record(Site::FixedVerify, cause);
    })
}
fn read_private_fixed_kernel_v2(
    envelope: &Envelope,
    access: &Access,
    checkpoint: &VerifiedCheckpoint,
    receipt: &crate::candidates::CheckpointReceipt,
    observe: &dyn Fn(&FixedVerificationFailureV2),
) -> Result<FixedProposalIdentityV1> {
    let candidate = envelope.view.candidates.first().ok_or_else(damaged)?;
    let stored: Stored = serde_json::from_value(
        envelope
            .durable_proposals_v1
            .get(&candidate.candidate_id)
            .ok_or_else(damaged)?
            .clone(),
    )
    .map_err(|_| damaged())?;
    let mappings: Mappings =
        serde_json::from_value(receipt.action_mappings_v1.clone().ok_or_else(damaged)?)
            .map_err(|_| damaged())?;
    if stored.principal_id != access.principal_id
        || stored.proof_job_id != checkpoint.summary().job_id
        || !stored.intakes.is_empty()
        || stored.union.is_some()
        || stored.financial_binding_v1.is_some()
            || stored.financial_binding_v2.is_some()
        || !stored.financial_dispatch_v1.is_empty()
        || serde_json::to_value(&stored.mappings).map_err(|_| damaged())?
            != serde_json::to_value(&mappings).map_err(|_| damaged())?
    {
        return Err(damaged());
    }
    let fixed = verify_fixed_typed_v2(candidate, checkpoint, &mappings).map_err(|error| {
        observe(&error);
        error.into_api()
    })?;
    if fixed.identity() != &stored.identity {
        return Err(damaged());
    }
    Ok(stored.identity)
}

// Actual verified original checkpoint/receipt join; no public bytes getter or
// marker exception on any generic Engine API. The owning profile retains it.
pub(crate) fn original_review_output_actions_v2(
    envelope: &Envelope,
    access: &Access,
    checkpoint: &VerifiedCheckpoint,
    receipt: &crate::candidates::CheckpointReceipt,
) -> Result<Vec<OutputActionMapping>> {
    read_private_fixed_v2(envelope, access, checkpoint, receipt)?;
    let mappings: Mappings =
        serde_json::from_value(receipt.action_mappings_v1.clone().ok_or_else(damaged)?)
            .map_err(|_| damaged())?;
    Ok(mappings
        .outputs
        .iter()
        .map(|m| OutputActionMapping {
            output_id: m.output_id.clone(),
            action_index: m.action_index,
        })
        .collect())
}
