//! Purpose-specific, non-spending discovery data for the plain durable profile.
//! These values cannot authenticate a signer, authorize a private read/export,
//! reserve notes, or establish current spendability or address ownership. The
//! native issuer and encrypted Engine intake must supply those separate joins.
use crate::{
    agreement::validate_address_text, born_recipient_policy_v2::BornConstructionRecipientPolicyV2,
    error::validate_id, manual_construction::PreconstructionProvider,
    manual_enrollment::BornManualEnrollmentTerms, proposal::canonical_digest, AgreementDraft,
    Amount, CoreError, ErrorCode, FeePolicy, OutputAllocation, PrivacyMode, Proposal,
    ProposalInput, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_PROJECTION_BYTES: usize = 64 * 1024;
pub const MAX_PROJECTION_INPUTS: usize = 32;
pub const MAX_METADATA_VALIDITY_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableInputProjectionPurposeV1 {
    DurablePlainFixedInputProjectionV1,
}

/// A selection budget, not a complete candidate or spending consent. The final
/// action count determines the exact fee only after both projections exist.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableInputProjectionIntentV1 {
    pub version: u16,
    pub purpose: DurableInputProjectionPurposeV1,
    pub agreement: AgreementDraft,
    pub proposal_id: String,
    pub account_id: String,
    pub participant_id: String,
    pub original_recipient_policy_digest: String,
    pub privacy_domain: String,
    pub contribution: Amount,
    pub maximum_fee_share: Amount,
    pub maximum_transaction_fee: Amount,
    pub transaction_expiry_height: u32,
    pub provider: PreconstructionProvider,
    pub anchor_height: u32,
    pub minimum_confirmations: u32,
    pub maximum_scan_blocks: u32,
    pub constructor_principal_id: String,
    pub protected_destination: String,
    pub retention_policy: String,
    /// Explicit onward audience for ONLY this metadata in the final manifest.
    /// Every transfer must authenticate an actual installed signer for one of
    /// these accounts; these strings do not themselves authenticate recipients.
    pub local_reviewer_account_ids: Vec<String>,
    pub valid_from_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableProjectedInputV1 {
    pub input_id: String,
    pub value: Amount,
    pub commitment: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableProjectionContextV1 {
    pub tip_height: u32,
    pub tip_hash: String,
    pub anchor_height: u32,
    pub anchor_hash: String,
    pub anchor_root: String,
}

/// Broadly private wallet metadata, but no FVK, note plaintext, witness,
/// signature or native capability. Retention/export still requires permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableInputProjectionV1 {
    pub version: u16,
    pub intent: DurableInputProjectionIntentV1,
    pub inputs: Vec<DurableProjectedInputV1>,
    pub selected_total: Amount,
    /// Native issuer independently decodes and checks this against the ACTUAL
    /// account FVK. Core validation deliberately makes no ownership assertion.
    pub own_return_receiver: String,
    pub context: DurableProjectionContextV1,
    pub captured_at_unix_seconds: u64,
}

fn invalid() -> CoreError {
    CoreError::new(ErrorCode::InvalidTerms, "invalid durable input projection")
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(invalid());
    }
    Ok(())
}
fn text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}
fn input_id(value: &str) -> Result<()> {
    let mut parts = value.split(':');
    if parts.next() != Some("ironwood") {
        return Err(invalid());
    }
    hash(parts.next().ok_or_else(invalid)?)?;
    let index = parts.next().ok_or_else(invalid)?;
    let parsed: u16 = index.parse().map_err(|_| invalid())?;
    if parts.next().is_some() || parsed.to_string() != index {
        return Err(invalid());
    }
    Ok(())
}
fn bounded<T: Serialize>(value: &T) -> Result<()> {
    if serde_json::to_vec(value).map_err(|_| invalid())?.len() > MAX_PROJECTION_BYTES {
        return Err(invalid());
    }
    Ok(())
}

impl DurableInputProjectionIntentV1 {
    pub fn validate(&self) -> Result<()> {
        self.agreement.validate()?;
        validate_id(&self.proposal_id, "durable proposal ID")?;
        validate_id(&self.participant_id, "durable participant ID")?;
        validate_id(
            &self.constructor_principal_id,
            "durable constructor principal",
        )?;
        hash(&self.account_id)?;
        hash(&self.original_recipient_policy_digest)?;
        for value in [
            &self.privacy_domain,
            &self.provider.source_id,
            &self.provider.endpoint,
            &self.protected_destination,
            &self.retention_policy,
        ] {
            text(value)?;
        }
        if self.version != 1
            || self.agreement.network_profile_id != "ironwood-testnet-nu7-candidate"
            || self.agreement.recipients.len() != 1
            || !self.agreement.extensions.is_empty()
            || !matches!(self.agreement.fee_policy, FeePolicy::ProRata)
            || !matches!(
                self.agreement.privacy_profile.mode,
                PrivacyMode::DeclaredOperator
            )
            || !self.agreement.privacy_profile.dedicated_accounts_required
            || self.contribution == Amount::ZERO
            || self.contribution > self.agreement.recipients[0].amount
            || self.maximum_fee_share > self.maximum_transaction_fee
            || self.transaction_expiry_height <= self.anchor_height
            || self.transaction_expiry_height >= 500_000_000
            || self.anchor_height == 0
            || !(1..=100).contains(&self.minimum_confirmations)
            || !(1..=1000).contains(&self.maximum_scan_blocks)
            || self.provider.trust_profile != "single_tls_provider_report_not_consensus"
            || !self.provider.endpoint.starts_with("https://")
            || self.provider.endpoint.ends_with('/')
            || self.provider.endpoint.chars().any(char::is_whitespace)
            || self.provider.endpoint.contains('@')
            || !self.protected_destination.starts_with('/')
            || self
                .protected_destination
                .split('/')
                .skip(1)
                .any(|p| matches!(p, "" | "." | ".."))
            || self.local_reviewer_account_ids.len() != 2
            || self.local_reviewer_account_ids[0] >= self.local_reviewer_account_ids[1]
            || !self.local_reviewer_account_ids.contains(&self.account_id)
            || self.valid_from_unix_seconds == 0
            || self
                .valid_until_unix_seconds
                .checked_sub(self.valid_from_unix_seconds)
                .is_none_or(|v| v == 0 || v > MAX_METADATA_VALIDITY_SECONDS)
        {
            return Err(invalid());
        }
        for account in &self.local_reviewer_account_ids {
            hash(account)?;
        }
        self.maximum_selection_debit()?;
        bounded(self)
    }

    pub fn maximum_selection_debit(&self) -> Result<Amount> {
        Ok(self.contribution.checked_add(self.maximum_fee_share)?)
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:durable-plain-input-projection-intent:v1", self)
    }

    /// Pure conjunction only. The caller must obtain these original terms and
    /// policy from the actual authenticated retained source, not incoming DTOs.
    pub fn require_original_policy(
        &self,
        terms: &BornManualEnrollmentTerms,
        policy: &BornConstructionRecipientPolicyV2,
    ) -> Result<()> {
        self.validate()?;
        policy.require_enrollment(terms)?;
        let scope = &terms.scope;
        let recipient = &self.agreement.recipients[0];
        if self.original_recipient_policy_digest != policy.digest()?
            || self.account_id != terms.identity.account_id
            || self.agreement.network_profile_id != terms.identity.network_profile_id
            || self.agreement.agreement_id != scope.agreement_id
            || self.agreement.obligation_id != scope.obligation_id
            || self.participant_id != scope.participant_id
            || self.privacy_domain != scope.privacy_domain
            || self.maximum_selection_debit()?.as_zatoshis() > scope.per_operation_limit_zatoshis
            || self.maximum_selection_debit()?.as_zatoshis() > scope.aggregate_budget_zatoshis
            || self.maximum_fee_share.as_zatoshis() > scope.maximum_fee_share_zatoshis
            || self.maximum_transaction_fee.as_zatoshis() > scope.maximum_transaction_fee_zatoshis
            || self
                .valid_from_unix_seconds
                .checked_mul(1000)
                .is_none_or(|v| v < terms.issued_at_ms)
            || self
                .valid_until_unix_seconds
                .checked_mul(1000)
                .is_none_or(|v| v > scope.expires_at_ms)
            || policy.recipients.len() != 1
        {
            return Err(invalid());
        }
        let allowed = &policy.recipients[0];
        if recipient.recipient_id != allowed.recipient_id
            || recipient.address != allowed.address
            || recipient.memo != allowed.memo
            || recipient.instruction_provenance != allowed.instruction_provenance
            || recipient.amount.as_zatoshis() > allowed.maximum_amount_zatoshis
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Metadata validity does not renew an IPC/native grant or prove unspentness.
    pub fn require_metadata_current(&self, now_unix_seconds: u64) -> Result<()> {
        self.validate()?;
        if now_unix_seconds < self.valid_from_unix_seconds
            || now_unix_seconds >= self.valid_until_unix_seconds
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl DurableInputProjectionV1 {
    pub fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        validate_address_text(&self.own_return_receiver)?;
        for value in [
            &self.context.tip_hash,
            &self.context.anchor_hash,
            &self.context.anchor_root,
        ] {
            hash(value)?;
        }
        if self.version != 1
            || self.inputs.is_empty()
            || self.inputs.len() > MAX_PROJECTION_INPUTS
            || self.context.anchor_height != self.intent.anchor_height
            || self.context.tip_height < self.context.anchor_height
            || self.context.tip_height >= self.intent.transaction_expiry_height
            || self.captured_at_unix_seconds < self.intent.valid_from_unix_seconds
            || self.captured_at_unix_seconds >= self.intent.valid_until_unix_seconds
            || self.selected_total < self.intent.maximum_selection_debit()?
        {
            return Err(invalid());
        }
        let mut previous: Option<&str> = None;
        for input in &self.inputs {
            input_id(&input.input_id)?;
            hash(&input.commitment)?;
            if input.value == Amount::ZERO || previous.is_some_and(|v| v >= input.input_id.as_str())
            {
                return Err(invalid());
            }
            previous = Some(&input.input_id);
        }
        if Amount::checked_sum(self.inputs.iter().map(|v| v.value))? != self.selected_total {
            return Err(invalid());
        }
        bounded(self)
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:durable-plain-input-projection:v1", self)
    }

    /// Reject substitution or silent reselection. This checks historical claims
    /// only; final native acceptance, exact maintained recapture and complete
    /// cryptographic verification remain mandatory before any spending action.
    pub fn matches_final_proposal(&self, input: &ProposalInput) -> Result<()> {
        self.validate()?;
        let proposal = Proposal::validate(input.clone())?;
        let m = proposal.manifest();
        let intent = &self.intent;
        let accounts: BTreeSet<_> = m
            .participants
            .iter()
            .map(|p| p.account_id.as_str())
            .collect();
        let expected: BTreeSet<_> = intent
            .local_reviewer_account_ids
            .iter()
            .map(String::as_str)
            .collect();
        if input.proposal_id != intent.proposal_id
            || m.agreement != intent.agreement
            || m.expiry_height != intent.transaction_expiry_height
            || m.participants.len() != 2
            || accounts != expected
            || m.participants.iter().any(|p| !p.charges.is_empty())
            || m.transaction_fee > intent.maximum_transaction_fee
            || m.inputs.iter().any(|i| i.ownership_evidence_ref.is_some())
        {
            return Err(invalid());
        }
        let own = m
            .participants
            .iter()
            .find(|p| {
                p.account_id == intent.account_id && p.participant_id == intent.participant_id
            })
            .ok_or_else(invalid)?;
        if own.contribution != intent.contribution
            || own.fee_share > intent.maximum_fee_share
            || own.fee_cap > intent.maximum_fee_share
            || own.maximum_net_debit != intent.contribution.checked_add(own.fee_share)?
        {
            return Err(invalid());
        }
        let actual: BTreeMap<_, _> = m
            .inputs
            .iter()
            .filter(|i| i.account_id == intent.account_id)
            .map(|i| (i.input_id.as_str(), i.amount))
            .collect();
        let retained: BTreeMap<_, _> = self
            .inputs
            .iter()
            .map(|i| (i.input_id.as_str(), i.value))
            .collect();
        if actual != retained {
            return Err(invalid());
        }
        for output in &m.outputs {
            match &output.allocation {
                OutputAllocation::Charge { .. } => return Err(invalid()),
                OutputAllocation::Return {
                    ownership_evidence_ref,
                    ..
                } if ownership_evidence_ref.is_some() => return Err(invalid()),
                OutputAllocation::Return {
                    participant_id,
                    account_id,
                    ..
                } if account_id == &intent.account_id
                    || participant_id == &intent.participant_id =>
                {
                    if account_id != &intent.account_id
                        || participant_id != &intent.participant_id
                        || output.address != self.own_return_receiver
                    {
                        return Err(invalid());
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
