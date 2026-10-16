//! Untrusted draft schemas. Validation checks syntax and arithmetic only.
use crate::error::validate_id;
use crate::{Amount, CoreError, ErrorCode, FeePolicy, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_RECIPIENTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extension {
    pub name: String,
    pub required: bool,
    pub schema_version: u32,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub recipient_id: String,
    /// Unverified receiving instructions. A qualified protocol adapter must
    /// independently decode the address, network, and shielded receiver.
    pub address: String,
    pub amount: Amount,
    pub memo: Option<String>,
    pub instruction_provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FundingPolicy {
    Exact { target: Amount },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    LocalOnly,
    DeclaredOperator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyProfile {
    pub mode: PrivacyMode,
    pub proving_operator: Option<String>,
    pub dedicated_accounts_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationPolicy {
    pub required_confirmations: u32,
}

impl Default for ConfirmationPolicy {
    fn default() -> Self {
        Self {
            required_confirmations: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgreementDraft {
    pub schema_version: u32,
    pub agreement_id: String,
    pub obligation_id: String,
    pub revision: u32,
    pub purpose: String,
    pub organizer_identity: String,
    pub network_profile_id: String,
    pub recipients: Vec<Recipient>,
    pub funding_policy: FundingPolicy,
    pub fee_policy: FeePolicy,
    pub privacy_profile: PrivacyProfile,
    pub coordination_deadline: Option<String>,
    pub confirmation_policy: ConfirmationPolicy,
    pub extensions: Vec<Extension>,
}

impl AgreementDraft {
    /// No transaction, address, identity, ownership, or signature is verified.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CoreError::new(
                ErrorCode::UnsupportedVersion,
                "unsupported agreement schema version",
            ));
        }
        validate_id(&self.agreement_id, "agreement ID")?;
        validate_id(&self.obligation_id, "obligation ID")?;
        validate_id(&self.organizer_identity, "organizer identity")?;
        validate_id(&self.network_profile_id, "network profile ID")?;
        if self.revision == 0 {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "agreement revision starts at one",
            ));
        }
        bounded_text(&self.purpose, 4096, "purpose")?;
        if self.recipients.is_empty() || self.recipients.len() > MAX_RECIPIENTS {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "agreement requires 1..=64 recipients",
            ));
        }
        let mut ids = BTreeSet::new();
        for recipient in &self.recipients {
            validate_id(&recipient.recipient_id, "recipient ID")?;
            if !ids.insert(&recipient.recipient_id) {
                return Err(CoreError::new(
                    ErrorCode::DuplicateIdentifier,
                    "duplicate recipient ID",
                ));
            }
            validate_address_text(&recipient.address)?;
            if recipient.amount == Amount::ZERO {
                return Err(CoreError::new(
                    ErrorCode::InvalidTerms,
                    "recipient amount must be positive",
                ));
            }
            if let Some(memo) = &recipient.memo {
                if memo.len() > 512 {
                    return Err(CoreError::new(
                        ErrorCode::ResourceLimit,
                        "memo exceeds 512 UTF-8 bytes",
                    ));
                }
            }
            bounded_text(
                &recipient.instruction_provenance,
                1024,
                "instruction provenance",
            )?;
        }
        let recipient_total = Amount::checked_sum(self.recipients.iter().map(|r| r.amount))?;
        let FundingPolicy::Exact { target } = self.funding_policy;
        if target != recipient_total {
            return Err(CoreError::new(
                ErrorCode::ConservationFailure,
                "exact funding target differs from recipient total",
            ));
        }
        if let FeePolicy::Sponsor { participant_id, .. } = &self.fee_policy {
            validate_id(participant_id, "fee sponsor participant ID")?;
        }
        match (
            &self.privacy_profile.mode,
            &self.privacy_profile.proving_operator,
        ) {
            (PrivacyMode::LocalOnly, None) => {}
            (PrivacyMode::DeclaredOperator, Some(operator)) => {
                bounded_text(operator, 256, "proving operator")?;
                if !self.privacy_profile.dedicated_accounts_required {
                    return Err(CoreError::new(
                        ErrorCode::PrivacyIncompatible,
                        "this schema requires dedicated accounts for delegated proving",
                    ));
                }
            }
            _ => {
                return Err(CoreError::new(
                    ErrorCode::PrivacyIncompatible,
                    "proving operator must match the declared privacy mode",
                ))
            }
        }
        if self.confirmation_policy.required_confirmations == 0
            || self.confirmation_policy.required_confirmations > 10_000
        {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "confirmation policy requires 1..=10000 confirmations",
            ));
        }
        if let Some(deadline) = &self.coordination_deadline {
            validate_timestamp(deadline)?;
        }
        if self.extensions.len() > 16 {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "at most 16 optional extensions are permitted",
            ));
        }
        let mut extensions = BTreeSet::new();
        for extension in &self.extensions {
            validate_id(&extension.name, "extension name")?;
            if !extensions.insert(&extension.name) {
                return Err(CoreError::new(
                    ErrorCode::DuplicateIdentifier,
                    "duplicate extension name",
                ));
            }
            if extension.required {
                return Err(CoreError::new(
                    ErrorCode::UnsupportedCapability,
                    "unknown mandatory extension",
                ));
            }
            if extension.schema_version != 1 {
                return Err(CoreError::new(
                    ErrorCode::UnsupportedVersion,
                    "unsupported extension schema version",
                ));
            }
            if serde_json::to_vec(&extension.value)
                .map_err(|_| CoreError::new(ErrorCode::InvalidTerms, "invalid extension"))?
                .len()
                > 16_384
                || json_depth(&extension.value) > 8
            {
                return Err(CoreError::new(
                    ErrorCode::ResourceLimit,
                    "optional extension exceeds size or depth limit",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Active,
    Withdrawn,
    Selected,
    Waitlisted,
    Expired,
    Declined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipationIntent {
    pub intent_id: String,
    pub agreement_id: String,
    pub participant_id: String,
    pub desired_contribution: Amount,
    pub maximum_net_debit: Amount,
    pub fee_cap: Amount,
    pub conditions: Vec<String>,
    pub valid_until: Option<String>,
    pub status: IntentStatus,
}

impl ParticipationIntent {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.intent_id, "intent ID")?;
        validate_id(&self.agreement_id, "agreement ID")?;
        validate_id(&self.participant_id, "participant ID")?;
        if self.desired_contribution == Amount::ZERO
            || self.desired_contribution > self.maximum_net_debit
        {
            return Err(CoreError::new(
                ErrorCode::DebitCapExceeded,
                "desired contribution must be positive and within the maximum debit",
            ));
        }
        if self.conditions.len() > 16 {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "at most 16 intent conditions are permitted",
            ));
        }
        for condition in &self.conditions {
            bounded_text(condition, 1024, "intent condition")?;
        }
        if let Some(timestamp) = &self.valid_until {
            validate_timestamp(timestamp)?;
        }
        Ok(())
    }
}

pub(crate) fn bounded_text(text: &str, max: usize, label: &str) -> Result<()> {
    if text.trim().is_empty()
        || text.len() > max
        || text
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            format!("{label} is empty, oversized, or contains disallowed control characters"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_address_text(address: &str) -> Result<()> {
    if address.is_empty()
        || address.len() > 1024
        || !address.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "receiving instructions must be a bounded address string",
        ));
    }
    // This rejects obvious transparent instructions; it deliberately does not
    // pretend that a textual prefix establishes a supported shielded receiver.
    if address.starts_with("t1")
        || address.starts_with("t3")
        || address.starts_with("tm")
        || address.starts_with("t2")
    {
        return Err(CoreError::new(
            ErrorCode::UnsupportedCapability,
            "transparent recipients are not supported",
        ));
    }
    Ok(())
}

/// Restricted RFC 3339 UTC form. Calendar validity is checked without a clock.
pub fn validate_timestamp(value: &str) -> Result<()> {
    let b = value.as_bytes();
    let valid_structure = b.len() == 20
        && [4, 7].iter().all(|i| b[*i] == b'-')
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && b.iter()
            .enumerate()
            .all(|(i, c)| [4, 7, 10, 13, 16, 19].contains(&i) || c.is_ascii_digit());
    let invalid = || {
        CoreError::new(
            ErrorCode::InvalidTerms,
            "timestamp must be a valid YYYY-MM-DDTHH:MM:SSZ UTC value",
        )
    };
    if !valid_structure {
        return Err(invalid());
    }
    let number = |start: usize, end: usize| -> u32 {
        b[start..end]
            .iter()
            .fold(0, |n, digit| n * 10 + u32::from(digit - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0
        || day == 0
        || day > days
        || number(11, 13) > 23
        || number(14, 16) > 59
        || number(17, 19) > 59
    {
        return Err(invalid());
    }
    Ok(())
}

fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}
