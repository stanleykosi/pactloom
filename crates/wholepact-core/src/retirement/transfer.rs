//! A separate typed single-owner transaction purpose. This is exact arithmetic
//! and review binding, never signer permission, current evidence or a claim that
//! the complete native retirement flow is available.
use super::ReviewedReclaimPlan;
use crate::{
    AccountingPreview, CoreError, ErrorCode, OutputAllocation, ProposalInput, ProposalManifest,
    Result,
    agreement::validate_timestamp,
    error::validate_id,
    proposal::{canonical_digest, validate_accounting_for_participants},
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;

/// No Deserialize, conversion to ordinary Proposal, or generic single-owner
/// validation entrypoint exists. Restoration must obtain a fresh reviewed plan.
#[derive(Clone, Serialize)]
pub struct ResidualTransferProposal {
    input: ProposalInput,
    reviewed: ReviewedReclaimPlan,
    manifest_digest: String,
    proposal_digest: String,
    accounting: AccountingPreview,
}
impl fmt::Debug for ResidualTransferProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResidualTransferProposal { private_contents: [REDACTED], separate_authorization: REQUIRED }")
    }
}
impl ResidualTransferProposal {
    pub fn bind(reviewed: &ReviewedReclaimPlan, input: ProposalInput) -> Result<Self> {
        validate_id(&input.proposal_id, "residual proposal ID")?;
        validate_timestamp(&input.created_at)?;
        // Reclaim is a separate operation, never an alternative to the original
        // payment or a preauthorized serialized artifact/effects commitment.
        if input.previous_proposal_id.is_some()
            || input.artifact_digest.is_some()
            || input.effects_commitment.is_some()
        {
            return Err(mismatch());
        }
        let manifest = &input.manifest;
        let plan = reviewed.plan();
        if manifest.participants.len() != 1
            || manifest.outputs.len() != 1
            || manifest.agreement.recipients.len() != 1
            || !manifest.agreement.extensions.is_empty()
            || manifest.agreement.network_profile_id != plan.request().network_profile_id
            || manifest.transaction_fee != plan.fee()
        {
            return Err(mismatch());
        }
        let participant = &manifest.participants[0];
        let recipient = &manifest.agreement.recipients[0];
        let output = &manifest.outputs[0];
        if participant.account_id != plan.request().account_id
            || participant.contribution != plan.transfer_amount()
            || participant.fee_share != plan.fee()
            || participant.fee_cap != plan.request().maximum_fee
            || participant.maximum_net_debit != plan.maximum_net_debit()
            || !participant.charges.is_empty()
            || recipient.address != plan.destination().address
            || recipient.amount != plan.transfer_amount()
            || recipient.memo.is_some()
            || output.address != plan.destination().address
            || output.amount != plan.transfer_amount()
            || output.allocation
                != (OutputAllocation::Recipient {
                    recipient_id: recipient.recipient_id.clone(),
                })
        {
            return Err(mismatch());
        }
        let expected: BTreeMap<_, _> = plan
            .inputs()
            .iter()
            .map(|i| (i.input_id.as_str(), i.amount))
            .collect();
        if manifest.inputs.len() != expected.len()
            || manifest.inputs.iter().any(|i| {
                i.account_id != participant.account_id
                    || i.participant_id != participant.participant_id
                    || expected.get(i.input_id.as_str()) != Some(&i.amount)
            })
        {
            return Err(mismatch());
        }
        let accounting = validate_accounting_for_participants(manifest, 1..=1)?;
        // Domain separation commits typed purpose, exact plan and native review;
        // ordinary manifest hashing cannot create this commitment accidentally.
        let manifest_digest = canonical_digest(
            "wholepact:residual-transfer-manifest:v1",
            &(plan.digest(), reviewed.review_record_ref(), manifest),
        )?;
        let proposal_digest = canonical_digest(
            "wholepact:residual-transfer-proposal:v1",
            &(&manifest_digest, &input),
        )?;
        Ok(Self {
            input,
            reviewed: reviewed.clone(),
            manifest_digest,
            proposal_digest,
            accounting,
        })
    }
    pub fn manifest(&self) -> &ProposalManifest {
        &self.input.manifest
    }
    pub fn input(&self) -> &ProposalInput {
        &self.input
    }
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub fn proposal_digest(&self) -> &str {
        &self.proposal_digest
    }
    pub fn reviewed_plan(&self) -> &ReviewedReclaimPlan {
        &self.reviewed
    }
    pub fn accounting(&self) -> &AccountingPreview {
        &self.accounting
    }
    /// Rechecks immutable value binding. The caller must separately refresh
    /// complete account evidence, ownership leases and native authorization.
    pub fn revalidate(&self) -> Result<()> {
        let rebuilt = Self::bind(&self.reviewed, self.input.clone())?;
        if rebuilt.manifest_digest != self.manifest_digest
            || rebuilt.proposal_digest != self.proposal_digest
        {
            return Err(mismatch());
        }
        Ok(())
    }
}
fn mismatch() -> CoreError {
    CoreError::new(
        ErrorCode::RevisionConflict,
        "single-owner residual transaction must exactly match the separately reviewed recovery plan; replacement, extra outputs, charges and implicit change are forbidden",
    )
}
