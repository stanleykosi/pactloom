//! Independent recipient amount/destination comparison through an explicit
//! trusted wallet/decryption adapter. Organizer assertions never establish payment.
use crate::agreement::{validate_address_text, validate_timestamp};
use crate::error::validate_id;
use crate::proposal::validate_sha256;
use crate::records::{
    ExactTransactionReference, ObservationPolicy, ObservationWindow, RecordConfidence,
    SourcedChainObservation,
};
use crate::{Amount, ChainStatus, CoreError, ErrorCode, Proposal, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipientEvidenceProvenance {
    /// Authenticated recipient-controlled wallet scanner, with no key material.
    RecipientWallet {
        wallet_adapter_id: String,
        recipient_account_ref: String,
        scan_checkpoint_ref: String,
        decryption_evidence_digest: String,
    },
    /// Explicitly accepted independent maintained verifier; the core does not
    /// implement or qualify an output-disclosure cryptographic protocol itself.
    IndependentOutputVerifier {
        verifier_id: String,
        format_id: String,
        recipient_binding_ref: String,
        evidence_digest: String,
    },
    /// Accepted as input only so the rejection cannot be confused with payment.
    CoordinatorAssertion {
        operator_id: String,
        assertion_ref: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcceptedRecipientSource {
    RecipientWallet {
        wallet_adapter_id: String,
        recipient_account_ref: String,
    },
    IndependentOutputVerifier {
        verifier_id: String,
        format_id: String,
        recipient_binding_ref: String,
    },
}
impl AcceptedRecipientSource {
    fn validate(&self) -> Result<()> {
        let ids = match self {
            Self::RecipientWallet {
                wallet_adapter_id,
                recipient_account_ref,
            } => vec![wallet_adapter_id, recipient_account_ref],
            Self::IndependentOutputVerifier {
                verifier_id,
                format_id,
                recipient_binding_ref,
            } => vec![verifier_id, format_id, recipient_binding_ref],
        };
        for id in ids {
            validate_id(id, "recipient evidence source")?;
        }
        Ok(())
    }
    fn accepts(&self, evidence: &RecipientEvidenceProvenance) -> Result<()> {
        self.validate()?;
        let matches = match (self, evidence) {
            (
                Self::RecipientWallet {
                    wallet_adapter_id: expected_adapter,
                    recipient_account_ref: expected_account,
                },
                RecipientEvidenceProvenance::RecipientWallet {
                    wallet_adapter_id,
                    recipient_account_ref,
                    scan_checkpoint_ref,
                    decryption_evidence_digest,
                },
            ) => {
                validate_id(scan_checkpoint_ref, "wallet scan checkpoint")?;
                validate_sha256(decryption_evidence_digest)?;
                expected_adapter == wallet_adapter_id && expected_account == recipient_account_ref
            }
            (
                Self::IndependentOutputVerifier {
                    verifier_id: expected_verifier,
                    format_id: expected_format,
                    recipient_binding_ref: expected_binding,
                },
                RecipientEvidenceProvenance::IndependentOutputVerifier {
                    verifier_id,
                    format_id,
                    recipient_binding_ref,
                    evidence_digest,
                },
            ) => {
                validate_sha256(evidence_digest)?;
                expected_verifier == verifier_id
                    && expected_format == format_id
                    && expected_binding == recipient_binding_ref
            }
            _ => false,
        };
        if !matches {
            return Err(CoreError::new(ErrorCode::MissingEvidence, "recipient payment needs the configured independent wallet/decryption source; a coordinator assertion is insufficient"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientCheckPolicy {
    pub chain: ObservationPolicy,
    pub recipient_source: AcceptedRecipientSource,
    pub required_confirmations: u32,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RecipientPaymentRequest {
    transaction: ExactTransactionReference,
    recipient_id: String,
    destination: String,
    expected_amount: Amount,
    expiry_height: u32,
}
impl fmt::Debug for RecipientPaymentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecipientPaymentRequest { private_contents: [REDACTED] }")
    }
}
impl RecipientPaymentRequest {
    pub fn for_proposal(
        proposal: &Proposal,
        transaction: ExactTransactionReference,
        recipient_id: &str,
    ) -> Result<Self> {
        transaction.validate()?;
        if transaction.network_profile_id != proposal.manifest().agreement.network_profile_id
            || Some(&transaction.effects_commitment) != proposal.input().effects_commitment.as_ref()
        {
            return Err(CoreError::new(
                ErrorCode::RevisionConflict,
                "recipient check must use the approved transaction effects and network",
            ));
        }
        let recipient = proposal
            .manifest()
            .agreement
            .recipients
            .iter()
            .find(|r| r.recipient_id == recipient_id)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::UnknownParticipant,
                    "recipient is absent from the approved arrangement",
                )
            })?;
        Ok(Self {
            transaction,
            recipient_id: recipient_id.into(),
            destination: recipient.address.clone(),
            expected_amount: recipient.amount,
            expiry_height: proposal.manifest().expiry_height,
        })
    }
    pub fn transaction(&self) -> &ExactTransactionReference {
        &self.transaction
    }
    pub fn recipient_id(&self) -> &str {
        &self.recipient_id
    }
    pub fn destination(&self) -> &str {
        &self.destination
    }
    pub fn expected_amount(&self) -> Amount {
        self.expected_amount
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientObservedOutput {
    /// Pool plus output index/commitment, as supplied by the maintained adapter.
    pub output_ref: String,
    pub destination: String,
    pub amount: Amount,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientSourceObservation {
    pub recipient_id: String,
    pub observed_at: String,
    pub evidence: RecipientEvidenceProvenance,
    pub outputs: Vec<RecipientObservedOutput>,
    pub chain: SourcedChainObservation,
}
impl fmt::Debug for RecipientSourceObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecipientSourceObservation { private_contents: [REDACTED] }")
    }
}
/// A deployment must authenticate/control this adapter independently of its
/// coordinator. It validates receiver/network decoding, complete scoped output
/// decryption and exact-transaction membership using maintained libraries. The
/// return schema alone authenticates none of those facts and has no `verified` flag.
pub trait RecipientObservationSource {
    fn observe_recipient_outputs(
        &mut self,
        request: &RecipientPaymentRequest,
    ) -> Result<RecipientSourceObservation>;
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CheckedRecipientPayment {
    request: RecipientPaymentRequest,
    observation: RecipientSourceObservation,
    amount: Amount,
    confidence: RecordConfidence,
    required_confirmations: u32,
}
impl fmt::Debug for CheckedRecipientPayment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckedRecipientPayment { private_contents: [REDACTED] }")
    }
}
impl CheckedRecipientPayment {
    pub fn request(&self) -> &RecipientPaymentRequest {
        &self.request
    }
    pub fn observation(&self) -> &RecipientSourceObservation {
        &self.observation
    }
    pub fn amount(&self) -> Amount {
        self.amount
    }
    pub fn confidence(&self) -> RecordConfidence {
        self.confidence
    }
    pub fn required_confirmations(&self) -> u32 {
        self.required_confirmations
    }
    /// Re-evaluate cached evidence instead of retaining a stale success label.
    pub fn confidence_at(&self, window: &ObservationWindow) -> Result<RecordConfidence> {
        window.validate()?;
        Ok(
            if window.contains(&self.observation.observed_at)
                && window.contains(&self.observation.chain.observation.observed_at)
            {
                self.confidence
            } else {
                RecordConfidence::Stale
            },
        )
    }
}

pub fn check_recipient_payment(
    source: &mut impl RecipientObservationSource,
    request: &RecipientPaymentRequest,
    policy: &RecipientCheckPolicy,
    window: &ObservationWindow,
) -> Result<CheckedRecipientPayment> {
    window.validate()?;
    policy.chain.validate()?;
    policy.recipient_source.validate()?;
    if policy.required_confirmations == 0 || policy.required_confirmations > 10_000 {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "recipient confirmation policy must be 1..=10000",
        ));
    }
    let observation = source.observe_recipient_outputs(request)?;
    validate_timestamp(&observation.observed_at)?;
    policy.recipient_source.accepts(&observation.evidence)?;
    observation
        .chain
        .validate_for(&request.transaction, &policy.chain)?;
    if observation.recipient_id != request.recipient_id
        || !window.contains(&observation.observed_at)
        || !window.contains(&observation.chain.observation.observed_at)
    {
        return Err(CoreError::new(
            ErrorCode::StaleChain,
            "recipient identity or evidence freshness does not match this check",
        ));
    }
    if observation.outputs.is_empty() || observation.outputs.len() > 256 {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "recipient observation requires 1..=256 scoped real outputs",
        ));
    }
    let mut outputs = BTreeSet::new();
    for output in &observation.outputs {
        validate_id(&output.output_ref, "recipient output reference")?;
        validate_address_text(&output.destination)?;
        if !outputs.insert(&output.output_ref) {
            return Err(CoreError::new(
                ErrorCode::DuplicateIdentifier,
                "duplicate recipient output cannot inflate the received amount",
            ));
        }
        if output.destination != request.destination || output.amount == Amount::ZERO {
            return Err(CoreError::new(ErrorCode::MissingEvidence, "observed output destination or amount differs from the approved receiving instructions"));
        }
    }
    let amount = Amount::checked_sum(observation.outputs.iter().map(|o| o.amount))?;
    if amount != request.expected_amount {
        return Err(CoreError::new(
            ErrorCode::ConservationFailure,
            "independently observed recipient total differs from the approved payment",
        ));
    }
    let chain = &observation.chain.observation;
    if matches!(
        chain.status,
        ChainStatus::Included | ChainStatus::ConfirmationPolicyMet
    ) && chain
        .inclusion_height
        .is_some_and(|height| height > request.expiry_height)
    {
        return Err(CoreError::new(
            ErrorCode::StaleChain,
            "recipient inclusion contradicts the transaction expiry",
        ));
    }
    let confidence = match chain.status {
        ChainStatus::Included | ChainStatus::ConfirmationPolicyMet
            if chain.confirmations >= policy.required_confirmations =>
        {
            RecordConfidence::ConfirmationPolicyMet
        }
        ChainStatus::Included | ChainStatus::ConfirmationPolicyMet => RecordConfidence::Included,
        ChainStatus::PendingObserved => RecordConfidence::Pending,
        ChainStatus::Reorganized => RecordConfidence::Reorganized,
        // Neither conflict/expiry nor a backend response proves incoming payment.
        _ => RecordConfidence::OutcomeUncertain,
    };
    Ok(CheckedRecipientPayment {
        request: request.clone(),
        observation,
        amount,
        confidence,
        required_confirmations: policy.required_confirmations,
    })
}
