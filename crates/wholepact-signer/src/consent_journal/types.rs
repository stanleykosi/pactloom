use super::*;
use serde::{Deserialize, Serialize};
use wholepact_core::{Proposal, ProposalInput};
use wholepact_store::authority::ReleaseIntent;

/// Exact evidence category is retained: authenticated local IPC possession is
/// never labeled as remote participant HPKE/public-key control.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransportIdentityBinding {
    RemoteAuthenticatedKeys {
        transport_identity_id: String,
        sender_key_digest: String,
        recipient_key_digest: String,
        channel_binding_digest: String,
    },
    LocalProcess {
        transport_identity_id: String,
        channel_key_digest: String,
        channel_binding_digest: String,
        uid: u32,
        pid: u32,
        process_instance: String,
        signer_generation: u64,
        account_id: String,
        agreement_id: String,
        participant_id: String,
        manifest_digest: String,
    },
}
impl TransportIdentityBinding {
    pub fn identity_id(&self) -> &str {
        match self {
            Self::RemoteAuthenticatedKeys {
                transport_identity_id,
                ..
            }
            | Self::LocalProcess {
                transport_identity_id,
                ..
            } => transport_identity_id,
        }
    }
    pub fn channel_binding_digest(&self) -> &str {
        match self {
            Self::RemoteAuthenticatedKeys {
                channel_binding_digest,
                ..
            }
            | Self::LocalProcess {
                channel_binding_digest,
                ..
            } => channel_binding_digest,
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        id(self.identity_id())?;
        hash(self.channel_binding_digest())?;
        match self {
            Self::RemoteAuthenticatedKeys {
                sender_key_digest,
                recipient_key_digest,
                ..
            } => {
                hash(sender_key_digest)?;
                hash(recipient_key_digest)?;
            }
            Self::LocalProcess {
                channel_key_digest,
                process_instance,
                signer_generation,
                pid,
                account_id,
                agreement_id,
                participant_id,
                manifest_digest,
                ..
            } => {
                for h in [channel_key_digest, process_instance, manifest_digest] {
                    hash(h)?;
                }
                for v in [account_id, agreement_id, participant_id] {
                    id(v)?;
                }
                if *pid == 0 || *signer_generation == 0 {
                    return Err(JournalError::InvalidBinding);
                }
            }
        }
        Ok(())
    }
    pub(super) fn validate_scope(
        &self,
        account: &str,
        agreement: &str,
        participant: &str,
        manifest: Option<&str>,
    ) -> Result<()> {
        self.validate()?;
        if let Self::LocalProcess {
            account_id,
            agreement_id,
            participant_id,
            manifest_digest,
            ..
        } = self
        {
            if account_id != account
                || agreement_id != agreement
                || participant_id != participant
                || manifest.is_some_and(|m| m != manifest_digest)
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConsentReceipt {
    pub(crate) native_session_id: String,
    pub(crate) trusted_launch_measurement: String,
    pub(crate) permission_generation: u64,
    pub(crate) writer_epoch: u64,
    pub(crate) nonce: String,
    pub(crate) reviewed_at_ms: u64,
    pub(crate) expires_at_ms: u64,
}
impl NativeConsentReceipt {
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn writer_epoch(&self) -> u64 {
        self.writer_epoch
    }
    pub fn reviewed_at_ms(&self) -> u64 {
        self.reviewed_at_ms
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    pub fn trusted_launch_measurement(&self) -> &str {
        &self.trusted_launch_measurement
    }
    pub fn native_session_id(&self) -> &str {
        &self.native_session_id
    }
    pub(super) fn validate(&self) -> Result<()> {
        for h in [
            &self.native_session_id,
            &self.trusted_launch_measurement,
            &self.nonce,
        ] {
            hash(h)?;
        }
        if self.writer_epoch == 0
            || self.permission_generation == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120_000
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnrollmentTerms {
    pub account_id: String,
    pub agreement_id: String,
    pub participant_id: String,
    pub principal_id: String,
    pub network_profile_id: String,
    pub privacy_domain: String,
    pub account_fvk_digest: String,
    pub transport: TransportIdentityBinding,
    pub aggregate_budget_limit_zatoshis: u64,
    pub receipt: NativeConsentReceipt,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountEnrollmentRecord {
    pub(super) reference: String,
    pub(super) terms: EnrollmentTerms,
}
impl AccountEnrollmentRecord {
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn account_id(&self) -> &str {
        &self.terms.account_id
    }
    pub fn agreement_id(&self) -> &str {
        &self.terms.agreement_id
    }
    pub fn participant_id(&self) -> &str {
        &self.terms.participant_id
    }
    pub fn principal_id(&self) -> &str {
        &self.terms.principal_id
    }
    pub fn account_fvk_digest(&self) -> &str {
        &self.terms.account_fvk_digest
    }
    pub fn transport(&self) -> &TransportIdentityBinding {
        &self.terms.transport
    }
    pub fn budget_limit_zatoshis(&self) -> u64 {
        self.terms.aggregate_budget_limit_zatoshis
    }
    pub fn receipt(&self) -> &NativeConsentReceipt {
        &self.terms.receipt
    }
    pub(super) fn new(terms: EnrollmentTerms) -> Result<Self> {
        let record = Self {
            reference: digest("wholepact:signer-account-enrollment:v1", &terms)?,
            terms,
        };
        record.validate()?;
        Ok(record)
    }
    pub(super) fn validate(&self) -> Result<()> {
        for value in [
            &self.terms.account_id,
            &self.terms.agreement_id,
            &self.terms.participant_id,
            &self.terms.principal_id,
            &self.terms.network_profile_id,
            &self.terms.privacy_domain,
        ] {
            id(value)?;
        }
        hash(&self.terms.account_fvk_digest)?;
        self.terms.transport.validate_scope(
            &self.terms.account_id,
            &self.terms.agreement_id,
            &self.terms.participant_id,
            None,
        )?;
        self.terms.receipt.validate()?;
        if self.terms.aggregate_budget_limit_zatoshis == 0
            || self.terms.aggregate_budget_limit_zatoshis > MAX_MONEY
            || self.reference != digest("wholepact:signer-account-enrollment:v1", &self.terms)?
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestTerms {
    pub enrollment_ref: String,
    pub account_id: String,
    pub principal_id: String,
    pub proposal: ProposalInput,
    pub proposal_digest: String,
    pub manifest_digest: String,
    pub receipt: NativeConsentReceipt,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedManifestRecord {
    pub(super) reference: String,
    pub(super) terms: ManifestTerms,
}
impl AcceptedManifestRecord {
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn enrollment_ref(&self) -> &str {
        &self.terms.enrollment_ref
    }
    pub fn proposal_input(&self) -> &ProposalInput {
        &self.terms.proposal
    }
    pub fn manifest_digest(&self) -> &str {
        &self.terms.manifest_digest
    }
    pub fn proposal_digest(&self) -> &str {
        &self.terms.proposal_digest
    }
    pub fn receipt(&self) -> &NativeConsentReceipt {
        &self.terms.receipt
    }
    pub(super) fn new(terms: ManifestTerms) -> Result<Self> {
        let record = Self {
            reference: digest("wholepact:signer-accepted-manifest:v1", &terms)?,
            terms,
        };
        record.proposal()?;
        Ok(record)
    }
    pub(crate) fn proposal(&self) -> Result<Proposal> {
        hash(&self.terms.enrollment_ref)?;
        id(&self.terms.account_id)?;
        id(&self.terms.principal_id)?;
        self.terms.receipt.validate()?;
        let proposal = Proposal::validate(self.terms.proposal.clone())
            .map_err(|_| JournalError::InvalidBinding)?;
        if self.reference != digest("wholepact:signer-accepted-manifest:v1", &self.terms)?
            || self.terms.proposal_digest != proposal.proposal_digest()
            || self.terms.manifest_digest != proposal.manifest_digest()
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(proposal)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentInputBinding {
    pub input_id: String,
    pub action_index: u64,
    pub nullifier: String,
    pub value_zatoshis: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletSnapshotBinding {
    pub tip_height: u32,
    pub tip_hash: String,
    pub anchor_height: u32,
    pub anchor_hash: String,
    pub anchor_root: String,
}

/// Exact original spending decision. Reading/deserializing this evidence never
/// creates an ApprovedSpendConsent or a usable signing permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalSpendConsent {
    pub(super) reference: String,
    pub(super) terms: SpendConsentTerms,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) financial_continuation_v1: Option<FinancialSpendBindingV1>,
}
/// Historical data from the explicit financial profile. No field or
/// deserialization grants a live signing decision or restores a native owner.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinancialSpendBindingV1 {
    pub(crate) continuation_operation_id: String,
    pub(crate) continuation_request_digest: String,
    pub(crate) continuation_history_digest: String,
    pub(crate) source_identity_digest: String,
    pub(crate) terms_digest: String,
    pub(crate) signing_terms_digest: String,
    pub(crate) reviewed_head: wholepact_authority::AuthorityHead,
    pub(crate) disclosure: wholepact_authority::WitnessDisclosureDescriptor,
    pub(crate) action_review_digest: String,
    pub(crate) native_session_digest: String,
    pub(crate) principal_id: String,
    pub(crate) measurement: String,
    pub(crate) permission_generation: u64,
    pub(crate) nonce: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendConsentTerms {
    /// Inert exact historical policy mapping; omitted legacy values keep their original hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_born_policy_v1: Option<DurableBornPolicyBindingV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automation: Option<AutomationConsentBinding>,
    pub sponsor_policy: Option<SponsorPolicyBinding>,
    pub sponsor_owner_attestation_digest: Option<String>,
    pub authorization_id: String,
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
    pub account_id: String,
    pub principal_id: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub manifest_digest: String,
    pub effects_digest: String,
    pub artifact_digest: String,
    pub review_binding: String,
    pub transport: TransportIdentityBinding,
    pub input_bindings: Vec<ConsentInputBinding>,
    pub maximum_debit_zatoshis: u64,
    pub fee_share_zatoshis: u64,
    pub transaction_fee_zatoshis: u64,
    pub aggregate_budget_limit_zatoshis: u64,
    pub transaction_expiry_height: u32,
    pub wallet_snapshot: WalletSnapshotBinding,
    /// Absent only in legacy/synthetic history; the production signing bridge requires Some.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_key_use_policy: Option<wholepact_wallet::WalletKeyUsePolicy>,
    pub receipt: NativeConsentReceipt,
}
impl OriginalSpendConsent {
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn terms(&self) -> &SpendConsentTerms {
        &self.terms
    }
    pub(super) fn new(terms: SpendConsentTerms) -> Result<Self> {
        let record = Self {
            reference: digest("wholepact:signer-original-spend-consent:v1", &terms)?,
            terms,
            financial_continuation_v1: None,
        };
        record.validate()?;
        Ok(record)
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self.financial_continuation_v1.is_some() { return Err(JournalError::RecoveryRequired); }
        self.validate_terms()?;
        if self.reference != digest("wholepact:signer-original-spend-consent:v1", &self.terms)? { return Err(JournalError::InvalidBinding); }
        Ok(())
    }
    pub(super) fn new_financial_v1(terms: SpendConsentTerms, binding: FinancialSpendBindingV1) -> Result<Self> {
        let reference = digest("wholepact:signer-original-financial-spend-consent:v1", &(&terms, &binding))?;
        let record = Self { reference, terms, financial_continuation_v1: Some(binding) };
        record.validate_financial_v1()?;
        Ok(record)
    }
    pub(crate) fn financial_binding_v1(&self) -> Option<&FinancialSpendBindingV1> { self.financial_continuation_v1.as_ref() }
    pub(crate) fn validate_financial_v1(&self) -> Result<()> {
        self.validate_terms()?;
        let b = self.financial_continuation_v1.as_ref().ok_or(JournalError::RecoveryRequired)?;
        id(&b.continuation_operation_id)?; id(&b.principal_id)?;
        for value in [&b.continuation_request_digest, &b.continuation_history_digest, &b.source_identity_digest, &b.terms_digest,
            &b.signing_terms_digest, &b.reviewed_head.digest, &b.action_review_digest, &b.native_session_digest, &b.measurement, &b.nonce] { hash(value)?; }
        b.disclosure.validate().map_err(|_| JournalError::InvalidBinding)?;
        let t = &self.terms;
        if b.reviewed_head.sequence == 0 || b.principal_id != t.principal_id || b.native_session_digest != t.receipt.native_session_id || b.measurement != t.receipt.trusted_launch_measurement
            || b.permission_generation != t.receipt.permission_generation || b.permission_generation != 1 || b.nonce != t.receipt.nonce
            || t.automation.is_some() || t.sponsor_policy.is_some() || t.sponsor_owner_attestation_digest.is_some() || t.durable_born_policy_v1.is_some()
            || self.reference != digest("wholepact:signer-original-financial-spend-consent:v1", &(t,b))? { return Err(JournalError::InvalidBinding); }
        Ok(())
    }
    fn validate_terms(&self) -> Result<()> {
        let t = &self.terms;
        for v in [
            &t.authorization_id,
            &t.account_id,
            &t.principal_id,
            &t.agreement_id,
            &t.obligation_id,
            &t.proposal_id,
        ] {
            id(v)?;
        }
        for v in [
            &t.enrollment_ref,
            &t.accepted_manifest_ref,
            &t.proposal_digest,
            &t.manifest_digest,
            &t.effects_digest,
            &t.artifact_digest,
            &t.review_binding,
            &t.wallet_snapshot.tip_hash,
            &t.wallet_snapshot.anchor_hash,
            &t.wallet_snapshot.anchor_root,
        ] {
            hash(v)?;
        }
        if let Some(binding) = &t.sponsor_policy {
            hash(&binding.policy_key)?;
            hash(&binding.terms_digest)?;
            if binding.version == 0 {
                return Err(JournalError::InvalidBinding);
            }
            hash(
                t.sponsor_owner_attestation_digest
                    .as_deref()
                    .ok_or(JournalError::InvalidBinding)?,
            )?;
        } else if t.sponsor_owner_attestation_digest.is_some() {
            return Err(JournalError::InvalidBinding);
        }
        if let Some(binding) = &t.durable_born_policy_v1 {
            binding.validate()?;
        }
        if let Some(automatic) = &t.automation {
            automatic.validate()?;
        }
        t.transport.validate()?;
        t.receipt.validate()?;
        if t.input_bindings.is_empty()
            || t.input_bindings.len() > 256
            || t.transaction_expiry_height == 0
            || t.wallet_snapshot.anchor_height > t.wallet_snapshot.tip_height
            || t.wallet_snapshot.tip_height >= t.transaction_expiry_height
            || t.maximum_debit_zatoshis == 0
            || t.maximum_debit_zatoshis > t.aggregate_budget_limit_zatoshis
            || t.aggregate_budget_limit_zatoshis > MAX_MONEY
            || t.fee_share_zatoshis > t.transaction_fee_zatoshis
            || t.fee_share_zatoshis > t.maximum_debit_zatoshis
            || t.transaction_fee_zatoshis > MAX_MONEY
        {
            return Err(JournalError::InvalidBinding);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut nullifiers = std::collections::BTreeSet::new();
        let mut actions = std::collections::BTreeSet::new();
        for input in &t.input_bindings {
            id(&input.input_id)?;
            hash(&input.nullifier)?;
            if input.value_zatoshis == 0
                || input.value_zatoshis > MAX_MONEY
                || !ids.insert(&input.input_id)
                || !nullifiers.insert(&input.nullifier)
                || !actions.insert(input.action_index)
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        Ok(())
    }
}

/// Exact transactional link absent from the legacy fixture ReleaseIntent DTO.
/// This wrapper has no public constructor or write API accepting its JSON.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentLinkedReleaseIntent {
    pub(super) original_consent_ref: String,
    pub(super) intent: ReleaseIntent,
}
impl ConsentLinkedReleaseIntent {
    pub fn original_consent_ref(&self) -> &str {
        &self.original_consent_ref
    }
    pub fn intent(&self) -> &ReleaseIntent {
        &self.intent
    }
    pub(super) fn from_consent(consent: &OriginalSpendConsent) -> Self {
        let t = &consent.terms;
        Self {
            original_consent_ref: consent.reference.clone(),
            intent: ReleaseIntent {
                authorization_id: t.authorization_id.clone(),
                account_id: t.account_id.clone(),
                writer_epoch: t.receipt.writer_epoch,
                obligation_id: t.obligation_id.clone(),
                proposal_id: t.proposal_id.clone(),
                manifest_digest: t.manifest_digest.clone(),
                effects_digest: t.effects_digest.clone(),
                artifact_digest: t.artifact_digest.clone(),
                maximum_debit: t.maximum_debit_zatoshis.to_string(),
                input_ids: t
                    .input_bindings
                    .iter()
                    .map(|i| i.nullifier.clone())
                    .collect(),
                aggregate_budget_limit: t.aggregate_budget_limit_zatoshis.to_string(),
            },
        }
    }
}

/// Retained historical provenance only. An idempotent replay yields this same
/// evidence and never a new release/signing capability or inferred consent.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct OriginalAuthorizationEvidence {
    pub(super) enrollment: AccountEnrollmentRecord,
    pub(super) manifest: AcceptedManifestRecord,
    pub(super) consent: OriginalSpendConsent,
    pub(super) release: ConsentLinkedReleaseIntent,
}
impl OriginalAuthorizationEvidence {
    pub fn enrollment(&self) -> &AccountEnrollmentRecord {
        &self.enrollment
    }
    pub fn accepted_manifest(&self) -> &AcceptedManifestRecord {
        &self.manifest
    }
    pub fn original_consent(&self) -> &OriginalSpendConsent {
        &self.consent
    }
    pub fn release_intent(&self) -> &ConsentLinkedReleaseIntent {
        &self.release
    }
    pub fn exposure_is_uncertain(&self) -> bool {
        true
    }
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SignerAccountState {
    pub account_id: String,
    pub writer_epoch: u64,
    pub recovery_required: bool,
}
