//! Prospective durable-delivery historical claims and pure comparisons only.
//!
//! A successful validation or comparison does not authenticate an original
//! source, upgrade v1 evidence, approve an attempt, or issue any capability.
//! Future consent, reservation, result, and final-byte links are deliberately
//! absent: they do not exist when this prospective scope is first committed.
//! No clock, environment routing, storage, credentials, or transport is used.
use crate::durable_payment_v1::{DurableFixedCandidateBindingV1, DurablePaymentAdmissionTermsV1};
use crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use crate::{
    decode, digest, encode, hash, id, AccountPolicy, AuthorityError, InputReservation, Result,
    WitnessDisclosureDescriptor,
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use wholepact_core::manual_construction::{
    construction_recipient_scope_digest, PreconstructionProvider,
};
use wholepact_core::Proposal;

/// Reserved claim profile, not an authentication mechanism or bearer grant.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableDeliveryAuthenticationProfileV2 {
    OriginalProtectedHostDispatcherV2,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryDispatcherV2 {
    pub principal_id: String,
    pub public_identity_commitment: String,
    pub authentication_profile: DurableDeliveryAuthenticationProfileV2,
    pub custody_policy_commitment: String,
}

/// The actual adapter must later prove that it uses this exact fixed route.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DurableDeliveryRouteV2 {
    // An empty struct (not a unit variant) strictly rejects extra JSON fields.
    Direct {},
    ExistingHttpConnect { origin: String },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryOwnerLineageV2 {
    pub account_id: String,
    pub participant_id: String,
    pub original_authorization_id: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableDeliveryExtractionRuleV2 {
    FirstDurablyRetainedVerifiedExtraction,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableDeliveryRetryRuleV2 {
    SameRetainedBytesWithFreshAdmission,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableDeliveryAttemptRuleV2 {
    ExplicitImmediateHostDecision,
}

/// Only the original final-transaction/provider and commitment/witness audiences.
/// This rule grants no FVK, note, other private-material, or retention authority.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableDeliveryDisclosureRuleV2 {
    WholeTransactionAndConnectionMetadataToProviderCommitmentsAndLinkageToWitness,
}

/// Shared fixed delivery claims. Equality does not authenticate either owner's
/// separate consent, witness evidence, or material-source lineage.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryPlanV2 {
    pub dispatcher: DurableDeliveryDispatcherV2,
    /// Full historical ManualHostGenerationBinding, under the domain
    /// `wholepact:durable-delivery-original-host:v2` and Authority's encoder.
    /// This provenance is distinct from the later live dispatcher identity.
    pub original_host_generation_binding_digest: String,
    pub original_host_profile_id: String,
    pub submission_journal_identity: String,
    pub submission_operation_id: String,
    pub provider: PreconstructionProvider,
    pub route: DurableDeliveryRouteV2,
    pub owners: Vec<DurableDeliveryOwnerLineageV2>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub minimum_expiry_margin_blocks: u32,
    /// An independent short admission, never a new native-owner lifetime.
    pub maximum_fresh_admission_lifetime_ms: u64,
    pub maximum_explicitly_approved_attempts: u32,
    pub extraction_rule: DurableDeliveryExtractionRuleV2,
    pub retry_rule: DurableDeliveryRetryRuleV2,
    pub attempt_rule: DurableDeliveryAttemptRuleV2,
}

/// Inert projection of one original authenticated construction-material scope.
/// A later real issuer must derive this again from its actual retained source.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryMaterialScopeRefV2 {
    pub account_id: String,
    pub original_scope_digest: String,
    pub valid_from_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryOriginalCeilingsV2 {
    pub payment_valid_from_ms: u64,
    pub payment_valid_until_ms: u64,
    pub enrollment_expires_at_ms: u64,
    pub policy_expires_at_ms: u64,
    pub material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,
}

/// Prospective original signing-time scope. Embedding historical v1 terms is
/// not acceptance of an old v1 admission as delivery permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryScopeV2 {
    pub version: u16,
    pub authorization: DurablePaymentAdmissionTermsV1,
    pub accepted_manifest_ref: String,
    pub original_writer_epoch: u64,
    pub delivery: DurableDeliveryPlanV2,
    pub witness: WitnessDisclosureDescriptor,
    pub original_ceilings: DurableDeliveryOriginalCeilingsV2,
    pub disclosure_rule: DurableDeliveryDisclosureRuleV2,
}

fn milliseconds(value: u64) -> Result<()> {
    if value == 0 || value > i64::MAX as u64 {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}

fn interval(from: u64, until: u64) -> Result<()> {
    milliseconds(from)?;
    milliseconds(until)?;
    if until <= from {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}

fn seconds_to_milliseconds(value: u64) -> Result<u64> {
    let result = value
        .checked_mul(1000)
        .ok_or(AuthorityError::InvalidBinding)?;
    milliseconds(result)?;
    Ok(result)
}

/// Narrow exact origin grammar. No URL parser normalization or IP-looking DNS
/// fallback is permitted, and parsing makes no TLS or network assertion.
fn canonical_origin(origin: &str, scheme: &str, default_port: u16) -> Result<()> {
    let authority = origin
        .strip_prefix(scheme)
        .ok_or(AuthorityError::InvalidBinding)?;
    if authority.is_empty() || !authority.is_ascii() || authority.len() > 260 {
        return Err(AuthorityError::InvalidBinding);
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or(AuthorityError::InvalidBinding)?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let ip: Ipv6Addr = host.parse().map_err(|_| AuthorityError::InvalidBinding)?;
        if ip.to_string() != host
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip
                .to_ipv4()
                .is_some_and(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let port = if tail.is_empty() {
            None
        } else {
            Some(
                tail.strip_prefix(':')
                    .ok_or(AuthorityError::InvalidBinding)?,
            )
        };
        (None, port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        (Some(host), port)
    };
    if let Some(host) = host {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            if ip.to_string() != host || ip.is_unspecified() || ip.is_multicast() {
                return Err(AuthorityError::InvalidBinding);
            }
        } else {
            let last = host
                .rsplit('.')
                .next()
                .ok_or(AuthorityError::InvalidBinding)?;
            if host.is_empty()
                || host.len() > 253
                || last.bytes().all(|c| c.is_ascii_digit())
                || last.starts_with("0x")
            {
                // Failed/noncanonical numeric IPv4 spellings cannot become DNS.
                return Err(AuthorityError::InvalidBinding);
            }
            for label in host.split('.') {
                if label.is_empty()
                    || label.len() > 63
                    || !label.as_bytes()[0].is_ascii_alphanumeric()
                    || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                {
                    return Err(AuthorityError::InvalidBinding);
                }
            }
        }
    }
    if let Some(port) = port {
        if port.is_empty() || port.starts_with('0') || !port.bytes().all(|c| c.is_ascii_digit()) {
            return Err(AuthorityError::InvalidBinding);
        }
        let value: u16 = port.parse().map_err(|_| AuthorityError::InvalidBinding)?;
        if value == 0 || value == default_port {
            return Err(AuthorityError::InvalidBinding);
        }
    }
    Ok(())
}

impl DurableDeliveryScopeV2 {
    /// Bounded, internally coherent historical claims only. No original-source
    /// authentication, current authorization, or authority-bearing return value.
    pub fn validate(&self) -> Result<()> {
        encode(self)?;
        if self.version != 2 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        self.authorization.validate()?;
        self.witness.validate()?;
        hash(&self.accepted_manifest_ref)?;
        if self.original_writer_epoch == 0 || self.original_writer_epoch > i64::MAX as u64 {
            return Err(AuthorityError::InvalidBinding);
        }
        let authorization = &self.authorization;
        let plan = &self.delivery;
        id(&plan.dispatcher.principal_id)?;
        hash(&plan.dispatcher.public_identity_commitment)?;
        hash(&plan.dispatcher.custody_policy_commitment)?;
        hash(&plan.original_host_generation_binding_digest)?;
        id(&plan.original_host_profile_id)?;
        hash(&plan.submission_journal_identity)?;
        id(&plan.submission_operation_id)?;
        id(&plan.provider.source_id)?;
        canonical_origin(&plan.provider.endpoint, "https://", 443)?;
        if let DurableDeliveryRouteV2::ExistingHttpConnect { origin } = &plan.route {
            canonical_origin(origin, "http://", 80)?;
        }
        interval(plan.valid_from_ms, plan.valid_until_ms)?;
        if plan.submission_operation_id.len() < 16
            || plan.provider.trust_profile != "single_tls_provider_report_not_consensus"
            || !(1..=100).contains(&plan.minimum_expiry_margin_blocks)
            || !(1..=120_000).contains(&plan.maximum_fresh_admission_lifetime_ms)
            || !(1..=128).contains(&plan.maximum_explicitly_approved_attempts)
            || plan.owners.len() != 2
            || self.witness.account_id != authorization.identity.account_id
            || self.witness.network_profile_id != authorization.identity.network_profile_id
            || self.witness.policy_digest != authorization.original_policy_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut previous_account: Option<&str> = None;
        let mut current_owner = None;
        for owner in &plan.owners {
            hash(&owner.account_id)?;
            id(&owner.participant_id)?;
            id(&owner.original_authorization_id)?;
            if previous_account.is_some_and(|previous| previous >= owner.account_id.as_str()) {
                return Err(AuthorityError::InvalidBinding);
            }
            previous_account = Some(&owner.account_id);
            // This temporary projection changes ONLY account_id to reuse the
            // maintained fixed-binding/account derivation. It is not validated
            // or exported as an actual second-owner admission record.
            let mut projection = authorization.clone();
            projection.identity.account_id = owner.account_id.clone();
            if owner.original_authorization_id != projection.canonical_authorization_id() {
                return Err(AuthorityError::InvalidBinding);
            }
            if owner.account_id == authorization.identity.account_id {
                current_owner = Some(owner);
            }
        }
        if plan.owners[0].participant_id == plan.owners[1].participant_id
            || current_owner.is_none()
            || current_owner.is_some_and(|owner| {
                owner.original_authorization_id != authorization.authorization_id
            })
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let ceilings = &self.original_ceilings;
        interval(
            ceilings.payment_valid_from_ms,
            ceilings.payment_valid_until_ms,
        )?;
        milliseconds(ceilings.enrollment_expires_at_ms)?;
        milliseconds(ceilings.policy_expires_at_ms)?;
        if ceilings.payment_valid_from_ms != authorization.valid_from_ms
            || ceilings.payment_valid_until_ms != authorization.valid_until_ms
            || ceilings.payment_valid_until_ms > ceilings.enrollment_expires_at_ms
            || ceilings.enrollment_expires_at_ms > ceilings.policy_expires_at_ms
            || plan.valid_from_ms < ceilings.payment_valid_from_ms
            || plan.valid_until_ms > ceilings.payment_valid_until_ms
            || plan.valid_until_ms > ceilings.enrollment_expires_at_ms
            || plan.valid_until_ms > ceilings.policy_expires_at_ms
            || ceilings.material_scopes.len() != 2
        {
            return Err(AuthorityError::InvalidBinding);
        }
        for (material, owner) in ceilings.material_scopes.iter().zip(&plan.owners) {
            hash(&material.account_id)?;
            hash(&material.original_scope_digest)?;
            let from = seconds_to_milliseconds(material.valid_from_unix_seconds)?;
            let until = seconds_to_milliseconds(material.valid_until_unix_seconds)?;
            interval(from, until)?;
            if material.account_id != owner.account_id
                || material.valid_until_unix_seconds - material.valid_from_unix_seconds
                    > 24 * 60 * 60
                || plan.valid_from_ms < from
                || plan.valid_until_ms > until
            {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:durable-delivery-scope:v2", self)
    }

    /// Commits to the fixed candidate AND the entire common delivery plan.
    /// Different owner evidence is intentionally outside this common digest.
    pub fn shared_plan_digest(&self) -> Result<String> {
        self.validate()?;
        digest(
            "wholepact:durable-delivery-shared-plan:v2",
            &(&self.authorization.fixed, &self.delivery),
        )
    }

    /// Compare independently supplied original historical claims. Success is
    /// neither original verification nor current authorization. Core Proposal
    /// supplies numerical/canonical consistency, not PCZT, input ownership,
    /// nullifier, action-index, material-source, or authenticated-source proof.
    /// `inputs` and `material_scopes` must be derived independently by callers;
    /// passing this scope's own projections back does not authenticate them.
    #[allow(clippy::too_many_arguments)]
    pub fn matches_original_claims(
        &self,
        policy: &AccountPolicy,
        extension: &ManualRosterEnrollmentExtensionV2,
        proposal: &Proposal,
        fixed: &DurableFixedCandidateBindingV1,
        accepted_manifest_ref: &str,
        original_writer_epoch: u64,
        witness: &WitnessDisclosureDescriptor,
        inputs: &[InputReservation],
        material_scopes: &[DurableDeliveryMaterialScopeRefV2],
    ) -> Result<()> {
        self.validate()?;
        self.authorization.validate_original(policy, extension)?;
        let authorization = &self.authorization;
        let original = &extension.account_extension.terms;
        let manifest = proposal.manifest();
        let agreement = &manifest.agreement;
        let plan = &self.delivery;
        let ceilings = &self.original_ceilings;
        if fixed != &authorization.fixed
            || accepted_manifest_ref != self.accepted_manifest_ref
            || original_writer_epoch != self.original_writer_epoch
            || original_writer_epoch != policy.initial_writer_epoch
            || original_writer_epoch != original.signer.writer_epoch
            || witness != &self.witness
            || witness.witness_id != policy.witness_id
            || witness.account_id != policy.account_id
            || crate::account_use_link::account_use_witness_origin_digest(witness)?
                != original.original_witness_origin_digest
            || inputs != authorization.inputs.as_slice()
            || material_scopes != ceilings.material_scopes.as_slice()
            || plan.original_host_generation_binding_digest
                != digest(
                    "wholepact:durable-delivery-original-host:v2",
                    &original.host,
                )?
            || plan.original_host_profile_id != original.host.profile_id
            || ceilings.enrollment_expires_at_ms != original.scope.expires_at_ms
            || ceilings.policy_expires_at_ms != policy.policy_expires_at_ms
            || plan.valid_from_ms < original.issued_at_ms
            || fixed.schema_version != agreement.schema_version
            || fixed.network_profile_id != agreement.network_profile_id
            || fixed.agreement_id != agreement.agreement_id
            || fixed.obligation_id != agreement.obligation_id
            || fixed.proposal_id != proposal.input().proposal_id
            || fixed.revision != agreement.revision
            || fixed.expiry_height != manifest.expiry_height
            || fixed.proposal_digest != proposal.proposal_digest()
            || fixed.manifest_digest != proposal.manifest_digest()
            || manifest.participants.len() != 2
            || authorization.transaction_fee_zatoshis != manifest.transaction_fee.as_zatoshis()
            || authorization.concrete_recipient_scope_digest
                != construction_recipient_scope_digest(proposal)
                    .map_err(|_| AuthorityError::InvalidBinding)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        for owner in &plan.owners {
            if !manifest.participants.iter().any(|participant| {
                participant.account_id == owner.account_id
                    && participant.participant_id == owner.participant_id
            }) {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        let own = manifest
            .participants
            .iter()
            .find(|participant| participant.account_id == authorization.identity.account_id)
            .ok_or(AuthorityError::InvalidBinding)?;
        let debit = proposal
            .accounting()
            .participant_net_debits
            .get(&own.participant_id)
            .ok_or(AuthorityError::InvalidBinding)?
            .as_zatoshis();
        if own.participant_id != original.scope.participant_id
            || authorization.maximum_debit_zatoshis != debit
            || authorization.fee_share_zatoshis != own.fee_share.as_zatoshis()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let own_inputs: Vec<_> = manifest
            .inputs
            .iter()
            .filter(|input| {
                input.account_id == own.account_id && input.participant_id == own.participant_id
            })
            .collect();
        if own_inputs.len() != inputs.len() {
            return Err(AuthorityError::InvalidBinding);
        }
        for input in inputs {
            if !own_inputs.iter().any(|claim| {
                claim.input_id == input.input_id
                    && claim.amount.as_zatoshis() == input.value_zatoshis
            }) {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        Ok(())
    }
}

/// Strict bounded JSON is decoded directly into typed DTOs so duplicate keys
/// cannot disappear through a serde_json::Value intermediary.
pub fn parse_durable_delivery_scope_v2(bytes: &[u8]) -> Result<DurableDeliveryScopeV2> {
    let scope: DurableDeliveryScopeV2 = decode(bytes)?;
    scope.validate()?;
    Ok(scope)
}
