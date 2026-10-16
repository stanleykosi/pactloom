//! Explicit field projection and exact destination-bound disclosure review.
//! Only private receipts are implemented here. They are unverified statements,
//! not cryptographic payment proofs or named-operator signature verification.
use crate::agreement::{bounded_text, validate_address_text, validate_timestamp};
use crate::error::validate_id;
use crate::proposal::{canonical_digest, validate_sha256};
use crate::records::{ObservationWindow, RecordAssessment, SettlementRecord};
use crate::{parse_typed_json, Amount, CoreError, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

const PRIVATE_RECEIPT_LIMITATIONS: &str = "Private local receipt: its statements are not independently authenticated proof of payment. Amounts and destinations are approved proposal terms, not independent recipient-wallet observations. Source observations can become stale or be reorganized. It does not prove unique donors, sponsor identity, all donations, complete fundraising history, fulfillment or refund entitlement. Shared information cannot be recalled; deleting a local copy does not revoke it.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisclosureMethod {
    PrivateReceipt,
    NamedOperatorAssertion {
        operator_id: String,
        signature_format: String,
    },
    CryptographicPaymentProof {
        format_id: String,
    },
}
impl DisclosureMethod {
    fn require_supported(&self) -> Result<()> {
        match self {
            Self::PrivateReceipt => Ok(()),
            Self::NamedOperatorAssertion { .. } => Err(CoreError::new(ErrorCode::UnsupportedCapability, "named-operator assertions require an authenticated signed-assertion format and verifier; private receipts cannot substitute for it")),
            Self::CryptographicPaymentProof { .. } => Err(CoreError::new(ErrorCode::UnsupportedCapability, "no cryptographic payment-disclosure format is integrated or qualified; encryption and hashes are not payment proofs")),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureField {
    RecipientAmount,
    RecipientDestination,
    TransactionId,
    ChainConfidence,
    AgreementLinkage,
    OwnNetDebit,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureAudience {
    NamedPrivateRecipient,
    Public,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureDestination {
    pub recipient_id: String,
    /// Display-only destination. Core never follows a URL or opens a connection.
    pub destination: String,
    pub audience: DisclosureAudience,
}
impl DisclosureDestination {
    fn validate(&self) -> Result<()> {
        validate_id(&self.recipient_id, "disclosure recipient")?;
        bounded_text(&self.destination, 2048, "disclosure destination")
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureSelection {
    pub fields: Vec<DisclosureField>,
    /// Required only for selected recipient amount/destination fields.
    pub payment_recipient_id: Option<String>,
    pub destination: DisclosureDestination,
    pub purpose: String,
    pub persistence: String,
}
impl DisclosureSelection {
    fn validate(&self) -> Result<()> {
        self.destination.validate()?;
        bounded_text(&self.purpose, 1024, "disclosure purpose")?;
        bounded_text(
            &self.persistence,
            1024,
            "disclosure persistence implications",
        )?;
        let fields: BTreeSet<_> = self.fields.iter().collect();
        if self.fields.is_empty() || self.fields.len() > 6 || fields.len() != self.fields.len() {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "select 1..=6 unique disclosure fields explicitly",
            ));
        }
        let needs_recipient = self.fields.contains(&DisclosureField::RecipientAmount)
            || self.fields.contains(&DisclosureField::RecipientDestination);
        if needs_recipient != self.payment_recipient_id.is_some() {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "payment recipient selection must match the requested amount/destination fields",
            ));
        }
        if let Some(id) = &self.payment_recipient_id {
            validate_id(id, "selected payment recipient")?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "field",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DisclosedFact {
    RecipientAmount(Amount),
    RecipientDestination(String),
    TransactionId(String),
    ChainConfidence(DisclosedConfidence),
    AgreementLinkage(DisclosedAgreementLinkage),
    OwnNetDebit(Amount),
}
impl DisclosedFact {
    fn field(&self) -> DisclosureField {
        match self {
            Self::RecipientAmount(_) => DisclosureField::RecipientAmount,
            Self::RecipientDestination(_) => DisclosureField::RecipientDestination,
            Self::TransactionId(_) => DisclosureField::TransactionId,
            Self::ChainConfidence(_) => DisclosureField::ChainConfidence,
            Self::AgreementLinkage(_) => DisclosureField::AgreementLinkage,
            Self::OwnNetDebit(_) => DisclosureField::OwnNetDebit,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosedConfidence {
    pub status: crate::records::RecordConfidence,
    pub confirmations: u32,
    pub required_confirmations: u32,
    pub assessed_at: String,
    /// No observation IDs, private evidence references, or internal account IDs.
    pub source_ids: Vec<String>,
    pub trust_profile_ids: Vec<String>,
    pub reconciliation_required: bool,
}
impl DisclosedConfidence {
    fn from_assessment(assessment: RecordAssessment, window: &ObservationWindow) -> Self {
        Self {
            status: assessment.confidence,
            confirmations: assessment.confirmations,
            required_confirmations: assessment.required_confirmations,
            assessed_at: window.now.clone(),
            source_ids: assessment
                .sources
                .iter()
                .map(|s| s.source_id.clone())
                .collect(),
            trust_profile_ids: assessment
                .sources
                .iter()
                .map(|s| s.trust_profile_id.clone())
                .collect(),
            reconciliation_required: assessment.exposure_reconciliation_required,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosedAgreementLinkage {
    pub agreement_id: String,
    pub proposal_id: String,
    pub manifest_digest: String,
}

/// This exact payload, and only this payload, is the prepared export. Neither
/// the participant record nor authorization/proving artifacts are embedded.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateReceipt {
    pub schema_version: u32,
    pub method: DisclosureMethod,
    pub destination: DisclosureDestination,
    pub purpose: String,
    pub persistence: String,
    pub facts: Vec<DisclosedFact>,
    pub limitations: String,
}
impl fmt::Debug for PrivateReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateReceipt { selected_private_contents: [REDACTED] }")
    }
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct DisclosurePreview {
    /// Local-only, never included in the exported PrivateReceipt.
    #[serde(skip)]
    source_record_digest: String,
    preview_digest: String,
    receipt: PrivateReceipt,
}
impl fmt::Debug for DisclosurePreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DisclosurePreview { selected_private_contents: [REDACTED] }")
    }
}
impl DisclosurePreview {
    pub fn build(
        record: &SettlementRecord,
        selection: DisclosureSelection,
        method: DisclosureMethod,
        window: &ObservationWindow,
    ) -> Result<Self> {
        selection.validate()?;
        method.require_supported()?;
        window.validate()?;
        let recipient = selection
            .payment_recipient_id
            .as_ref()
            .map(|id| {
                record
                    .proposal()
                    .manifest()
                    .agreement
                    .recipients
                    .iter()
                    .find(|r| &r.recipient_id == id)
                    .ok_or_else(|| {
                        CoreError::new(
                            ErrorCode::UnknownParticipant,
                            "selected recipient is absent from this settlement record",
                        )
                    })
            })
            .transpose()?;
        let mut fields = selection.fields;
        fields.sort();
        let mut facts = Vec::with_capacity(fields.len());
        for field in fields {
            facts.push(match field {
                DisclosureField::RecipientAmount => DisclosedFact::RecipientAmount(
                    recipient
                        .ok_or_else(|| {
                            CoreError::new(
                                ErrorCode::MissingEvidence,
                                "payment recipient not selected",
                            )
                        })?
                        .amount,
                ),
                DisclosureField::RecipientDestination => DisclosedFact::RecipientDestination(
                    recipient
                        .ok_or_else(|| {
                            CoreError::new(
                                ErrorCode::MissingEvidence,
                                "payment recipient not selected",
                            )
                        })?
                        .address
                        .clone(),
                ),
                DisclosureField::TransactionId => {
                    DisclosedFact::TransactionId(record.transaction().transaction_id.clone())
                }
                DisclosureField::ChainConfidence => DisclosedFact::ChainConfidence(
                    DisclosedConfidence::from_assessment(record.assess(window)?, window),
                ),
                DisclosureField::AgreementLinkage => {
                    DisclosedFact::AgreementLinkage(DisclosedAgreementLinkage {
                        agreement_id: record.proposal().manifest().agreement.agreement_id.clone(),
                        proposal_id: record.proposal().input().proposal_id.clone(),
                        manifest_digest: record.proposal().manifest_digest().into(),
                    })
                }
                DisclosureField::OwnNetDebit => DisclosedFact::OwnNetDebit(
                    record.proposal().accounting().participant_net_debits
                        [&record.own_authorization().participant_id],
                ),
            });
        }
        let receipt = PrivateReceipt {
            schema_version: 1,
            method,
            destination: selection.destination,
            purpose: selection.purpose,
            persistence: selection.persistence,
            facts,
            limitations: PRIVATE_RECEIPT_LIMITATIONS.into(),
        };
        let source_record_digest = record.content_digest()?;
        let preview_digest = canonical_digest(
            "wholepact:disclosure-preview:v1",
            &(&source_record_digest, &receipt),
        )?;
        Ok(Self {
            source_record_digest,
            preview_digest,
            receipt,
        })
    }
    pub fn digest(&self) -> &str {
        &self.preview_digest
    }
    pub fn receipt(&self) -> &PrivateReceipt {
        &self.receipt
    }
    /// Rechecks fresh exact consent at the preparation boundary. The integration
    /// must commit consent/outbox and recheck revocation at its actual export sink.
    pub fn prepare_export(
        &self,
        record: &SettlementRecord,
        consent: &mut impl DisclosureConsentSource,
        window: &ObservationWindow,
    ) -> Result<PreparedPrivateReceipt> {
        window.validate()?;
        if self.source_record_digest != record.content_digest()? {
            return Err(CoreError::new(
                ErrorCode::RevisionConflict,
                "record changed after disclosure preview; review the new evidence",
            ));
        }
        for fact in &self.receipt.facts {
            if let DisclosedFact::ChainConfidence(prior) = fact {
                let current = DisclosedConfidence::from_assessment(record.assess(window)?, window);
                // Advancing the clock alone is harmless; changed confidence isn't.
                if prior.status != current.status
                    || prior.confirmations != current.confirmations
                    || prior.reconciliation_required != current.reconciliation_required
                {
                    return Err(CoreError::new(
                        ErrorCode::StaleChain,
                        "disclosure confidence changed after preview",
                    ));
                }
            }
        }
        match consent.review_current_disclosure(self)? {
            DisclosureDecision::Rejected | DisclosureDecision::Revoked => Err(CoreError::new(
                ErrorCode::UserRejected,
                "disclosure was rejected or its consent revoked",
            )),
            DisclosureDecision::Approved {
                preview_digest,
                consent_record_ref,
                expires_at,
            } => {
                validate_sha256(&preview_digest)?;
                validate_id(&consent_record_ref, "disclosure consent reference")?;
                validate_timestamp(&expires_at)?;
                if preview_digest != self.preview_digest || expires_at <= window.now {
                    return Err(CoreError::new(ErrorCode::MissingEvidence, "disclosure consent is expired or bound to another field/destination/purpose preview"));
                }
                Ok(PreparedPrivateReceipt {
                    receipt: self.receipt.clone(),
                    consent_record_ref,
                    preview_digest,
                })
            }
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosureDecision {
    Rejected,
    Revoked,
    Approved {
        preview_digest: String,
        consent_record_ref: String,
        expires_at: String,
    },
}
/// Trusted local consent UI/authority. Transport authentication, a checkbox in
/// imported JSON, and approval of the original payment are not disclosure consent.
pub trait DisclosureConsentSource {
    fn review_current_disclosure(
        &mut self,
        preview: &DisclosurePreview,
    ) -> Result<DisclosureDecision>;
}
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedPrivateReceipt {
    receipt: PrivateReceipt,
    consent_record_ref: String,
    preview_digest: String,
}
impl fmt::Debug for PreparedPrivateReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedPrivateReceipt { selected_private_contents: [REDACTED] }")
    }
}
impl PreparedPrivateReceipt {
    pub fn receipt(&self) -> &PrivateReceipt {
        &self.receipt
    }
    pub fn consent_record_ref(&self) -> &str {
        &self.consent_record_ref
    }
    pub fn preview_digest(&self) -> &str {
        &self.preview_digest
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.receipt)
            .map_err(|_| CoreError::new(ErrorCode::InvalidTerms, "private receipt encoding failed"))
    }
}

/// Structural inspection only. This returns an explicitly unverified receipt;
/// it never upgrades local receipt text into independent payment verification.
pub fn inspect_private_receipt(
    bytes: &[u8],
    expected_destination: &DisclosureDestination,
) -> Result<PrivateReceipt> {
    if bytes.len() > 32_768 {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "private receipt exceeds 32 KiB",
        ));
    }
    let receipt: PrivateReceipt = parse_typed_json(bytes)?;
    if receipt.schema_version != 1 {
        return Err(CoreError::new(
            ErrorCode::UnsupportedVersion,
            "unsupported private receipt schema",
        ));
    }
    receipt.method.require_supported()?;
    receipt.destination.validate()?;
    if &receipt.destination != expected_destination
        || receipt.limitations != PRIVATE_RECEIPT_LIMITATIONS
    {
        return Err(CoreError::new(
            ErrorCode::PrivacyIncompatible,
            "receipt destination or required assurance limitations changed",
        ));
    }
    bounded_text(&receipt.purpose, 1024, "receipt purpose")?;
    bounded_text(&receipt.persistence, 1024, "receipt persistence")?;
    if receipt.facts.is_empty() || receipt.facts.len() > 6 {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "receipt requires 1..=6 selected facts",
        ));
    }
    let mut seen = BTreeSet::new();
    for fact in &receipt.facts {
        if !seen.insert(fact.field()) {
            return Err(CoreError::new(
                ErrorCode::DuplicateIdentifier,
                "duplicate disclosed field",
            ));
        }
        match fact {
            DisclosedFact::RecipientDestination(address) => validate_address_text(address)?,
            DisclosedFact::TransactionId(id) => validate_sha256(id)?,
            DisclosedFact::AgreementLinkage(link) => {
                validate_id(&link.agreement_id, "agreement linkage")?;
                validate_id(&link.proposal_id, "proposal linkage")?;
                validate_sha256(&link.manifest_digest)?;
            }
            DisclosedFact::ChainConfidence(confidence) => {
                validate_timestamp(&confidence.assessed_at)?;
                if confidence.required_confirmations == 0
                    || confidence.required_confirmations > 10_000
                    || confidence.source_ids.len() > 256
                    || confidence.source_ids.len() != confidence.trust_profile_ids.len()
                {
                    return Err(CoreError::new(
                        ErrorCode::InvalidTerms,
                        "malformed private receipt confidence statement",
                    ));
                }
                for id in confidence
                    .source_ids
                    .iter()
                    .chain(confidence.trust_profile_ids.iter())
                {
                    validate_id(id, "confidence source")?;
                }
                if confidence.status == crate::records::RecordConfidence::ConfirmationPolicyMet
                    && (confidence.confirmations < confidence.required_confirmations
                        || confidence.source_ids.is_empty())
                {
                    return Err(CoreError::new(
                        ErrorCode::MissingEvidence,
                        "private receipt contradicts its own confirmation policy",
                    ));
                }
            }
            DisclosedFact::RecipientAmount(amount) | DisclosedFact::OwnNetDebit(amount)
                if *amount == Amount::ZERO =>
            {
                return Err(CoreError::new(
                    ErrorCode::InvalidAmount,
                    "a disclosed payment amount must be positive",
                ))
            }
            _ => {}
        }
    }
    Ok(receipt)
}
