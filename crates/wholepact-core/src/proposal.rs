//! Immutable, numerically reconciled proposal terms. All input ownership,
//! returned value, addresses, and transaction references remain untrusted claims.
use crate::agreement::{bounded_text, validate_address_text, validate_timestamp};
use crate::error::validate_id;
use crate::{AgreementDraft, Amount, CoreError, ErrorCode, FeeWeight, Result, allocate_fees};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChargeConsent {
    pub charge_id: String,
    pub address: String,
    pub amount: Amount,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantAllocation {
    pub participant_id: String,
    pub account_id: String,
    pub contribution: Amount,
    pub fee_share: Amount,
    pub fee_cap: Amount,
    pub maximum_net_debit: Amount,
    pub charges: Vec<ChargeConsent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedInput {
    pub input_id: String,
    pub participant_id: String,
    pub account_id: String,
    pub amount: Amount,
    pub ownership_evidence_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutputAllocation {
    Recipient {
        recipient_id: String,
    },
    Return {
        participant_id: String,
        account_id: String,
        ownership_evidence_ref: Option<String>,
    },
    Charge {
        participant_id: String,
        charge_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedOutput {
    pub output_id: String,
    pub address: String,
    pub amount: Amount,
    pub allocation: OutputAllocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalManifest {
    pub agreement: AgreementDraft,
    pub participants: Vec<ParticipantAllocation>,
    pub inputs: Vec<ClaimedInput>,
    pub outputs: Vec<ClaimedOutput>,
    pub transaction_fee: Amount,
    pub expiry_height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalInput {
    pub proposal_id: String,
    pub previous_proposal_id: Option<String>,
    pub manifest: ProposalManifest,
    /// Hash of artifact bytes, never an effects commitment or verification.
    pub artifact_digest: Option<String>,
    /// An unverified, adapter-defined reference. Not inferred from artifact hash.
    pub effects_commitment: Option<String>,
    pub created_at: String,
}

/// Cannot be deserialized directly. Restored data must pass `validate` again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Proposal {
    input: ProposalInput,
    manifest_digest: String,
    proposal_digest: String,
    accounting: AccountingPreview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountingPreview {
    pub recipient_total: Amount,
    pub transaction_fee: Amount,
    pub charge_total: Amount,
    pub input_total: Amount,
    pub output_total: Amount,
    pub participant_net_debits: BTreeMap<String, Amount>,
    pub authorization_allowed: bool,
    pub assurance: String,
    pub blocking_reasons: Vec<String>,
}

impl Proposal {
    /// Freeze numerically valid terms. Does not authorize or verify real effects.
    pub fn validate(input: ProposalInput) -> Result<Self> {
        validate_id(&input.proposal_id, "proposal ID")?;
        if let Some(previous) = &input.previous_proposal_id {
            validate_id(previous, "previous proposal ID")?;
            if previous == &input.proposal_id {
                return Err(CoreError::new(
                    ErrorCode::RevisionConflict,
                    "a proposal cannot replace itself",
                ));
            }
        }
        validate_timestamp(&input.created_at)?;
        if let Some(digest) = &input.artifact_digest {
            validate_sha256(digest)?;
        }
        if let Some(commitment) = &input.effects_commitment {
            bounded_text(commitment, 512, "effects commitment")?;
        }
        let accounting = validate_claimed_accounting(&input.manifest)?;
        let manifest_digest = canonical_digest("wholepact:manifest:v1", &input.manifest)?;
        let proposal_digest = canonical_digest("wholepact:proposal:v1", &input)?;
        Ok(Self {
            input,
            manifest_digest,
            proposal_digest,
            accounting,
        })
    }

    pub fn input(&self) -> &ProposalInput {
        &self.input
    }
    pub fn manifest(&self) -> &ProposalManifest {
        &self.input.manifest
    }
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub fn proposal_digest(&self) -> &str {
        &self.proposal_digest
    }
    pub fn accounting(&self) -> &AccountingPreview {
        &self.accounting
    }
}

/// Reconcile every declared real input/output exactly once. Ownership remains
/// a claim even if an evidence reference is present. Protocol dummy actions
/// cannot enter this API as real outputs or bypass it by using a zero label.
pub fn validate_claimed_accounting(manifest: &ProposalManifest) -> Result<AccountingPreview> {
    validate_accounting_for_participants(manifest, 2..=32)
}

/// Private arithmetic reuse: only the plan-bound retirement constructor may
/// select single-owner accounting. Public ordinary proposals retain 2..=32.
pub(crate) fn validate_accounting_for_participants(
    manifest: &ProposalManifest,
    participant_count: std::ops::RangeInclusive<usize>,
) -> Result<AccountingPreview> {
    manifest.agreement.validate()?;
    if manifest.expiry_height == 0 {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "transaction expiry must be finite and nonzero",
        ));
    }
    if !participant_count.contains(&manifest.participants.len())
        || manifest.inputs.is_empty()
        || manifest.inputs.len() > 256
        || manifest.outputs.is_empty()
        || manifest.outputs.len() > 256
    {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "participant count is outside this transaction purpose; accounting requires 1..=256 real inputs and outputs",
        ));
    }
    let mut participants = BTreeMap::new();
    let mut accounts = BTreeSet::new();
    let mut input_totals = BTreeMap::new();
    let mut return_totals = BTreeMap::new();
    let mut charge_consents = BTreeMap::new();
    let mut participant_net_debits = BTreeMap::new();
    for participant in &manifest.participants {
        validate_id(&participant.participant_id, "participant ID")?;
        validate_id(&participant.account_id, "account ID")?;
        if participants
            .insert(&participant.participant_id, participant)
            .is_some()
            || !accounts.insert(&participant.account_id)
        {
            return Err(CoreError::new(
                ErrorCode::DuplicateIdentifier,
                "duplicate participant or account allocation",
            ));
        }
        if participant.fee_share > participant.fee_cap {
            return Err(CoreError::new(
                ErrorCode::FeeCapExceeded,
                "allocated fee exceeds a participant's fee cap",
            ));
        }
        if participant.charges.len() > 16 {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "at most 16 separately approved charges per participant",
            ));
        }
        for charge in &participant.charges {
            validate_id(&charge.charge_id, "charge ID")?;
            validate_address_text(&charge.address)?;
            bounded_text(&charge.purpose, 1024, "charge purpose")?;
            if charge.amount == Amount::ZERO
                || charge_consents
                    .insert((&participant.participant_id, &charge.charge_id), charge)
                    .is_some()
            {
                return Err(CoreError::new(
                    ErrorCode::InvalidTerms,
                    "charges must be positive and uniquely assigned",
                ));
            }
        }
        let debit = participant
            .contribution
            .checked_add(participant.fee_share)?
            .checked_add(Amount::checked_sum(
                participant.charges.iter().map(|c| c.amount),
            )?)?;
        if debit > participant.maximum_net_debit {
            return Err(CoreError::new(
                ErrorCode::DebitCapExceeded,
                "contribution, fee and charges exceed the participant's maximum net debit",
            ));
        }
        participant_net_debits.insert(participant.participant_id.clone(), debit);
        input_totals.insert(&participant.participant_id, Amount::ZERO);
        return_totals.insert(&participant.participant_id, Amount::ZERO);
    }
    let weights: Vec<_> = manifest
        .participants
        .iter()
        .map(|p| FeeWeight {
            participant_id: p.participant_id.clone(),
            contribution: p.contribution,
        })
        .collect();
    let fees = allocate_fees(
        manifest.transaction_fee,
        &weights,
        &manifest.agreement.fee_policy,
    )?;
    for participant in &manifest.participants {
        if fees[&participant.participant_id] != participant.fee_share {
            return Err(CoreError::new(
                ErrorCode::ConservationFailure,
                "fee shares do not follow the agreed deterministic fee policy",
            ));
        }
    }
    let recipient_total =
        Amount::checked_sum(manifest.agreement.recipients.iter().map(|r| r.amount))?;
    if Amount::checked_sum(manifest.participants.iter().map(|p| p.contribution))? != recipient_total
    {
        return Err(CoreError::new(
            ErrorCode::ConservationFailure,
            "contributions must exactly fund all recipients",
        ));
    }
    let mut input_ids = BTreeSet::new();
    for input in &manifest.inputs {
        validate_id(&input.input_id, "input ID")?;
        if !input_ids.insert(&input.input_id) {
            return Err(CoreError::new(
                ErrorCode::DuplicateIdentifier,
                "real input allocated more than once",
            ));
        }
        if input.amount == Amount::ZERO {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "real inputs must have positive value",
            ));
        }
        let participant = participants.get(&input.participant_id).ok_or_else(|| {
            CoreError::new(
                ErrorCode::UnknownParticipant,
                "input assigned to unknown participant",
            )
        })?;
        if input.account_id != participant.account_id {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "input account does not match participant allocation",
            ));
        }
        if let Some(reference) = &input.ownership_evidence_ref {
            validate_id(reference, "input evidence reference")?;
        }
        let total = input_totals
            .get_mut(&input.participant_id)
            .expect("participant initialized");
        *total = total.checked_add(input.amount)?;
    }
    let recipients: BTreeMap<_, _> = manifest
        .agreement
        .recipients
        .iter()
        .map(|r| (&r.recipient_id, r))
        .collect();
    let mut observed_recipients = BTreeSet::new();
    let mut observed_charges = BTreeSet::new();
    let mut output_ids = BTreeSet::new();
    for output in &manifest.outputs {
        validate_id(&output.output_id, "output ID")?;
        validate_address_text(&output.address)?;
        if !output_ids.insert(&output.output_id) {
            return Err(CoreError::new(
                ErrorCode::DuplicateIdentifier,
                "real output allocated more than once",
            ));
        }
        if output.amount == Amount::ZERO {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "zero-valued real outputs are unsupported; dummy classification requires a qualified protocol adapter",
            ));
        }
        match &output.allocation {
            OutputAllocation::Recipient { recipient_id } => {
                let recipient = recipients.get(recipient_id).ok_or_else(|| {
                    CoreError::new(ErrorCode::InvalidTerms, "unapproved recipient output")
                })?;
                if !observed_recipients.insert(recipient_id)
                    || recipient.address != output.address
                    || recipient.amount != output.amount
                {
                    return Err(CoreError::new(
                        ErrorCode::ConservationFailure,
                        "recipient output differs from the exact approved allocation",
                    ));
                }
            }
            OutputAllocation::Return {
                participant_id,
                account_id,
                ownership_evidence_ref,
            } => {
                let participant = participants.get(participant_id).ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::UnknownParticipant,
                        "return output assigned to unknown participant",
                    )
                })?;
                if account_id != &participant.account_id {
                    return Err(CoreError::new(
                        ErrorCode::MissingEvidence,
                        "return account differs from participant account",
                    ));
                }
                if let Some(reference) = ownership_evidence_ref {
                    validate_id(reference, "return ownership evidence reference")?;
                }
                let total = return_totals
                    .get_mut(participant_id)
                    .expect("participant initialized");
                *total = total.checked_add(output.amount)?;
            }
            OutputAllocation::Charge {
                participant_id,
                charge_id,
            } => {
                let key = (participant_id, charge_id);
                let charge = charge_consents.get(&key).ok_or_else(|| {
                    CoreError::new(ErrorCode::InvalidTerms, "unapproved service charge output")
                })?;
                if !observed_charges.insert(key)
                    || charge.address != output.address
                    || charge.amount != output.amount
                {
                    return Err(CoreError::new(
                        ErrorCode::ConservationFailure,
                        "charge output differs from the exact approved charge",
                    ));
                }
            }
        }
    }
    if observed_recipients.len() != recipients.len()
        || observed_charges.len() != charge_consents.len()
    {
        return Err(CoreError::new(
            ErrorCode::ConservationFailure,
            "recipient or charge allocation has no exact output",
        ));
    }
    for participant in &manifest.participants {
        let claimed_debit = input_totals[&participant.participant_id]
            .checked_sub(return_totals[&participant.participant_id])?;
        if claimed_debit != participant_net_debits[&participant.participant_id] {
            return Err(CoreError::new(
                ErrorCode::ConservationFailure,
                "participant input minus claimed return differs from contribution, fee and approved charges",
            ));
        }
    }
    let input_total = Amount::checked_sum(manifest.inputs.iter().map(|i| i.amount))?;
    let output_total = Amount::checked_sum(manifest.outputs.iter().map(|o| o.amount))?;
    if input_total != output_total.checked_add(manifest.transaction_fee)? {
        return Err(CoreError::new(
            ErrorCode::ConservationFailure,
            "real inputs do not equal all real outputs plus the transaction fee",
        ));
    }
    Ok(AccountingPreview {
        recipient_total,
        transaction_fee: manifest.transaction_fee,
        charge_total: Amount::checked_sum(charge_consents.values().map(|c| c.amount))?,
        input_total,
        output_total,
        participant_net_debits,
        authorization_allowed: false,
        assurance: "claimed_accounting_only".into(),
        blocking_reasons: vec![
            "No independently verified transaction effects or input/return ownership".into(),
            "No qualified network, protocol, signer, or proving profile".into(),
        ],
    })
}

pub fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "SHA-256 digest must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

/// Wholepact canonical JSON v1: UTF-8, sorted object keys, significant array
/// order, serde_json string escaping, integer numbers only. This is explicitly
/// not a claim of RFC 8785/JCS compatibility. Domain and zero separator are hashed.
pub fn canonical_digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    if domain.is_empty() || domain.len() > 128 || !domain.is_ascii() || domain.contains('\0') {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "invalid digest domain",
        ));
    }
    let value = serde_json::to_value(value)
        .map_err(|_| CoreError::new(ErrorCode::InvalidTerms, "canonical serialization failed"))?;
    let mut encoded = Vec::new();
    canonical_json(&value, &mut encoded, 0)?;
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(encoded);
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn canonical_json(value: &serde_json::Value, out: &mut Vec<u8>, depth: usize) -> Result<()> {
    if depth > 32 || out.len() > 1_048_576 {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "canonical payload exceeds depth or byte limits",
        ));
    }
    match value {
        serde_json::Value::Object(map) => {
            out.push(b'{');
            let sorted: BTreeMap<_, _> = map.iter().collect();
            for (index, (key, value)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(key).expect("string serialization is infallible"));
                out.push(b':');
                canonical_json(value, out, depth + 1)?;
            }
            out.push(b'}');
        }
        serde_json::Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                canonical_json(value, out, depth + 1)?;
            }
            out.push(b']');
        }
        serde_json::Value::Number(number) if !number.is_u64() && !number.is_i64() => {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "canonical manifest numbers must be integers; monetary values are strings",
            ));
        }
        _ => {
            out.extend(serde_json::to_vec(value).map_err(|_| {
                CoreError::new(ErrorCode::InvalidTerms, "canonical encoding failed")
            })?)
        }
    }
    if out.len() > 1_048_576 {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "canonical payload exceeds byte limit",
        ));
    }
    Ok(())
}
