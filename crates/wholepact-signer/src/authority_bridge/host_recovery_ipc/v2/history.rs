//! Complete audit-only origin inventory. Neither parsing nor validation creates
//! a journal/native/witness capability. Missing replay coverage stays unknown.
use super::{BridgeError, Result, hash};
use crate::consent_journal::{
    OfflineLocalAdmissionHistory, OfflineLocalKeyUseHistory, OfflineOriginalConsentHistory,
    OfflineRemoteHistoryProvenance, OfflineRetainedResultHistory,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_authority::{
    AuthorityHead, ReservationPermit, WitnessDisclosureDescriptor,
    account_use::{AccountUseGenesis, PermanentAccountExclusion},
    account_use_link::AccountExclusionReceipt,
    offline::{
        OfflineAuthorizationAdmission, OfflineAuthorizationTerms, OfflineEnrollmentPolicy,
        OfflineReservationIntent,
    },
};

pub const MAX_COMPLETE_HISTORY_BYTES: usize = 120 * 1024;
const MAX_ORIGINS: usize = 100_000;
fn binding<E>(_: E) -> BridgeError {
    BridgeError::Binding
}
fn id(s: &str) -> Result<()> {
    crate::review::validate_label(s).map_err(binding)
}
fn head_at_or_before(a: &AuthorityHead, b: &AuthorityHead) -> Result<()> {
    hash(&a.digest)?;
    if a.sequence > b.sequence || (a.sequence == b.sequence && a != b) {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineSignatureKnowledgeV2 {
    HistoricalAdmissionSignatureUnknown,
    OriginalConsentRetainedSignatureUnknown,
    LocalKeyUseStartedSignatureUnknown,
    ExactResultRetainedCurrentValidityUnknown,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedOfflineRemoteV2 {
    pub admission: OfflineAuthorizationAdmission,
    pub policy: OfflineEnrollmentPolicy,
    pub provenance: OfflineRemoteHistoryProvenance,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryOfflineOriginV2 {
    pub replayed_admission: Option<OfflineAuthorizationAdmission>,
    pub retained_remote: Option<RetainedOfflineRemoteV2>,
    pub minimal_local: Option<OfflineLocalAdmissionHistory>,
    pub original: Option<OfflineOriginalConsentHistory>,
    pub key_use: Option<OfflineLocalKeyUseHistory>,
    pub retained_result: Option<OfflineRetainedResultHistory>,
    pub signature_knowledge: OfflineSignatureKnowledgeV2,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
// Keep the audit contract directly inspectable; its exact encoded body is bounded.
#[allow(clippy::large_enum_variant)]
pub enum HostRecoveryReservationOriginV2 {
    Online {
        permit: ReservationPermit,
    },
    Offline {
        origin: Box<HostRecoveryOfflineOriginV2>,
    },
}
/// Monotone reconciled history. A newer witnessed exclusion may be present
/// even when not yet persisted locally; the separate complete journal digest
/// binds actual rows. Absent local genesis is never filled retrospectively.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountUseHistoryV2 {
    pub genesis: Option<AccountUseGenesis>,
    pub exclusion: Option<PermanentAccountExclusion>,
    pub witness_ack: Option<AccountExclusionReceipt>,
}
/// Exact original receipt metadata, with the original field order/digest. No
/// ciphertext or proof/signature bytes cross this account-wide metadata route.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineAuthenticatedReviewMetadataV2 {
    pub account_id: String,
    pub authorization_id: String,
    pub owner_setup_digest: String,
    pub terms_digest: String,
    pub package_digest: String,
    pub preview_json: String,
    pub sequence: u64,
    pub envelope_digest: String,
    pub content_digest: String,
}
impl OfflineAuthenticatedReviewMetadataV2 {
    pub fn receipt_digest(&self) -> Result<String> {
        for value in [
            &self.owner_setup_digest,
            &self.terms_digest,
            &self.package_digest,
            &self.envelope_digest,
            &self.content_digest,
        ] {
            hash(value)?;
        }
        id(&self.account_id)?;
        id(&self.authorization_id)?;
        if self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.preview_json.len() > 512 * 1024
        {
            return Err(BridgeError::Binding);
        }
        wholepact_core::proposal::canonical_digest("wholepact:offline-review-receipt:v1", self)
            .map_err(binding)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineReviewReceiptMetadataV2 {
    pub account_id: String,
    pub authorization_id: String,
    pub terms_digest: String,
    pub package_digest: String,
    pub envelope_digest: String,
    pub authenticated: Option<OfflineAuthenticatedReviewMetadataV2>,
    pub accepted_receipt_digest: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryHistoryV2 {
    pub schema_version: u16,
    pub complete_journal_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_birth_commit: Option<wholepact_authority::pending_birth::PendingBirthCommitRecord>,
    pub origins: Vec<HostRecoveryReservationOriginV2>,
    pub retained_enrollments: Vec<OfflineEnrollmentPolicy>,
    pub retained_reservation_intents: Vec<OfflineReservationIntent>,
    pub review_receipts: Vec<OfflineReviewReceiptMetadataV2>,
    pub account_use: AccountUseHistoryV2,
}
impl HostRecoveryOfflineOriginV2 {
    pub fn terms(&self) -> Result<&OfflineAuthorizationTerms> {
        if let Some(a) = &self.replayed_admission {
            return Ok(&a.request.intent.terms);
        }
        if let Some(a) = &self.retained_remote {
            return Ok(&a.admission.request.intent.terms);
        }
        self.minimal_local
            .as_ref()
            .map(|a| &a.terms)
            .ok_or(BridgeError::Binding)
    }
    pub fn missing_current_witness_replay(&self) -> bool {
        self.replayed_admission.is_none()
    }
    fn validate(
        &self,
        witness: &WitnessDisclosureDescriptor,
        head: &AuthorityHead,
        epoch: u64,
    ) -> Result<()> {
        let terms = self.terms()?;
        terms.validate()?;
        if terms.account_id != witness.account_id
            || terms.network_profile_id != witness.network_profile_id
        {
            return Err(BridgeError::Binding);
        }
        for full in self
            .replayed_admission
            .iter()
            .chain(self.retained_remote.iter().map(|r| &r.admission))
        {
            full.matches_request(&full.request)?;
            if &full.request.intent.terms != terms
                || full.witness_id != witness.witness_id
                || full.witness_policy_digest != witness.policy_digest
                || full.request.writer_epoch > epoch
            {
                return Err(BridgeError::Binding);
            }
            head_at_or_before(&full.committed_head, head)?;
        }
        if let Some(retained) = &self.retained_remote {
            retained
                .provenance
                .validate(&retained.admission, &retained.policy)
                .map_err(binding)?;
            if retained.provenance.witness != *witness
                || self
                    .replayed_admission
                    .as_ref()
                    .is_some_and(|a| a != &retained.admission)
            {
                return Err(BridgeError::Binding);
            }
            head_at_or_before(&retained.provenance.history_head, head)?;
        }
        if let Some(local) = &self.minimal_local {
            local.validate().map_err(binding)?;
            if &local.terms != terms
                || local.statement.witness_id != witness.witness_id
                || local.statement.witness_policy_digest != witness.policy_digest
                || local.pinned_witness_certificate_digest
                    != witness.pinned_server_certificate_digest
            {
                return Err(BridgeError::Binding);
            }
            head_at_or_before(&local.statement.committed_head, head)?;
            for full in self
                .replayed_admission
                .iter()
                .chain(self.retained_remote.iter().map(|r| &r.admission))
            {
                local.validate_remote(full).map_err(binding)?;
            }
        }
        // A witness admission, intent or native reservation review is never a
        // final original. Only its actual retained minimal-local chain may link it.
        if let Some(original) = &self.original {
            let local = self.minimal_local.as_ref().ok_or(BridgeError::Binding)?;
            original.validate().map_err(binding)?;
            if original.account_id != terms.account_id
                || original.authorization_id != terms.authorization_id
                || original.return_recipient_key_digest != terms.return_recipient_key_digest
                || original.terms_digest != terms.terms_digest()?
                || original.intent_digest != local.intent_digest
                || original.admission_request_digest != local.admission_request_digest
                || original.authenticated_package_digest != local.authenticated_package_digest
            {
                return Err(BridgeError::Binding);
            }
            for full in self
                .replayed_admission
                .iter()
                .chain(self.retained_remote.iter().map(|r| &r.admission))
            {
                original.validate_admission(full).map_err(binding)?;
            }
        }
        if let Some(key_use) = &self.key_use {
            key_use
                .validate(self.original.as_ref().ok_or(BridgeError::Binding)?)
                .map_err(binding)?;
        }
        if let Some(result) = &self.retained_result {
            let original = self.original.as_ref().ok_or(BridgeError::Binding)?;
            if self.key_use.is_none()
                || result.authorization_id != original.authorization_id
                || result.original_consent_ref != original.reference
                || result.admission_request_digest != original.admission_request_digest
                || result.authenticated_package_digest != original.authenticated_package_digest
                || result.return_recipient_key_digest != original.return_recipient_key_digest
            {
                return Err(BridgeError::Binding);
            }
            hash(&result.signed_artifact_digest)?;
        }
        let expected = if self.retained_result.is_some() {
            OfflineSignatureKnowledgeV2::ExactResultRetainedCurrentValidityUnknown
        } else if self.key_use.is_some() {
            OfflineSignatureKnowledgeV2::LocalKeyUseStartedSignatureUnknown
        } else if self.original.is_some() {
            OfflineSignatureKnowledgeV2::OriginalConsentRetainedSignatureUnknown
        } else {
            OfflineSignatureKnowledgeV2::HistoricalAdmissionSignatureUnknown
        };
        if self.signature_knowledge != expected {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
impl HostRecoveryReservationOriginV2 {
    pub fn authorization_id(&self) -> Result<&str> {
        match self {
            Self::Online { permit } => Ok(&permit.request.authorization_id),
            Self::Offline { origin } => Ok(&origin.terms()?.authorization_id),
        }
    }
    pub fn obligation_id(&self) -> Result<&str> {
        match self {
            Self::Online { permit } => Ok(&permit.request.obligation_id),
            Self::Offline { origin } => Ok(&origin.terms()?.obligation_id),
        }
    }
    pub fn maximum_debit_zatoshis(&self) -> Result<u64> {
        match self {
            Self::Online { permit } => Ok(permit.request.maximum_debit_zatoshis),
            Self::Offline { origin } => Ok(origin.terms()?.maximum_debit_zatoshis),
        }
    }
}
impl HostRecoveryHistoryV2 {
    pub fn validate(
        &self,
        account: &str,
        network: &str,
        witness: &WitnessDisclosureDescriptor,
        head: &AuthorityHead,
        max_epoch: u64,
    ) -> Result<()> {
        if self.schema_version != 2
            || self.origins.len() > MAX_ORIGINS
            || self.retained_enrollments.len() > MAX_ORIGINS
            || self.retained_reservation_intents.len() > MAX_ORIGINS
            || self.review_receipts.len() > 64
            || account != witness.account_id
            || network != witness.network_profile_id
            || max_epoch == 0
        {
            return Err(BridgeError::Binding);
        }
        hash(&self.complete_journal_digest)?;
        hash(&head.digest)?;
        witness.validate()?;
        let mut previous: Option<&str> = None;
        for origin in &self.origins {
            let authorization = origin.authorization_id()?;
            if previous.is_some_and(|old| old >= authorization) {
                return Err(BridgeError::Binding);
            }
            previous = Some(authorization);
            match origin {
                HostRecoveryReservationOriginV2::Online { permit } => {
                    permit.matches_request(&permit.request)?;
                    permit.request.validate()?;
                    if permit.request.account_id != account
                        || permit.request.network_profile_id != network
                        || permit.witness_id != witness.witness_id
                        || permit.policy_digest != witness.policy_digest
                        || permit.request.writer_epoch > max_epoch
                    {
                        return Err(BridgeError::Binding);
                    }
                    head_at_or_before(&permit.committed_head, head)?;
                }
                HostRecoveryReservationOriginV2::Offline { origin } => {
                    origin.validate(witness, head, max_epoch)?
                }
            }
        }
        let mut policies = BTreeMap::new();
        let mut previous_policy: Option<String> = None;
        for policy in &self.retained_enrollments {
            let digest = policy.policy_digest()?;
            if policy.account_id != account
                || policy.network_profile_id != network
                || policy.witness_id != witness.witness_id
                || policy.witness_certificate_digest != witness.pinned_server_certificate_digest
                || previous_policy.as_ref().is_some_and(|old| old >= &digest)
                || policies.insert(digest.clone(), policy).is_some()
            {
                return Err(BridgeError::Binding);
            }
            previous_policy = Some(digest);
        }
        let mut previous_intent: Option<String> = None;
        let mut intent_authorizations = BTreeSet::new();
        for intent in &self.retained_reservation_intents {
            let digest = intent.intent_digest()?;
            let policy = policies
                .get(&intent.terms.offline_policy_digest)
                .ok_or(BridgeError::Binding)?;
            if intent.terms.account_id != account
                || intent.terms.network_profile_id != network
                || intent.terms.enrollment_ref != policy.enrollment_ref
                || intent.terms.offline_signer_key_digest != policy.offline_signer_key_digest
                || intent.terms.return_recipient_key_digest != policy.return_recipient_key_digest
                || previous_intent.as_ref().is_some_and(|old| old >= &digest)
                || !intent_authorizations.insert(&intent.terms.authorization_id)
            {
                return Err(BridgeError::Binding);
            }
            // A pending intent is not an admission, but a same-ID origin must
            // retain its exact terms and every available original intent pin.
            for origin in &self.origins {
                if origin.authorization_id()? != intent.terms.authorization_id {
                    continue;
                }
                match origin {
                    HostRecoveryReservationOriginV2::Online { .. } => {
                        return Err(BridgeError::Binding);
                    }
                    HostRecoveryReservationOriginV2::Offline { origin } => {
                        if origin.terms()? != &intent.terms
                            || origin
                                .replayed_admission
                                .as_ref()
                                .is_some_and(|a| a.request.intent != *intent)
                            || origin
                                .minimal_local
                                .as_ref()
                                .is_some_and(|local| local.intent_digest != digest)
                        {
                            return Err(BridgeError::Binding);
                        }
                    }
                }
            }
            previous_intent = Some(digest);
        }
        for origin in &self.origins {
            if let HostRecoveryReservationOriginV2::Offline { origin } = origin {
                if let Some(remote) = &origin.retained_remote {
                    if !self.retained_enrollments.contains(&remote.policy)
                        || !self
                            .retained_reservation_intents
                            .contains(&remote.admission.request.intent)
                    {
                        return Err(BridgeError::Binding);
                    }
                }
            }
        }
        let mut previous_receipt: Option<&str> = None;
        for receipt in &self.review_receipts {
            id(&receipt.authorization_id)?;
            if receipt.account_id != account
                || previous_receipt.is_some_and(|old| old >= receipt.authorization_id.as_str())
            {
                return Err(BridgeError::Binding);
            }
            previous_receipt = Some(&receipt.authorization_id);
            for value in [
                &receipt.terms_digest,
                &receipt.package_digest,
                &receipt.envelope_digest,
            ] {
                hash(value)?;
            }
            // Pending-only receipt history remains nonbinding. Once an admitted
            // origin with this authorization exists, both representations must
            // describe the same exact offline terms and review package. A legacy
            // online origin cannot supply an invented offline package binding.
            for origin in &self.origins {
                if origin.authorization_id()? != receipt.authorization_id {
                    continue;
                }
                match origin {
                    HostRecoveryReservationOriginV2::Online { .. } => {
                        return Err(BridgeError::Binding);
                    }
                    HostRecoveryReservationOriginV2::Offline { origin } => {
                        let terms = origin.terms()?;
                        if receipt.terms_digest != terms.terms_digest()?
                            || receipt.package_digest != terms.review_package_digest
                            || origin.minimal_local.as_ref().is_some_and(|local| {
                                local.authenticated_package_digest != receipt.package_digest
                            })
                        {
                            return Err(BridgeError::Binding);
                        }
                    }
                }
            }
            for intent in &self.retained_reservation_intents {
                if intent.terms.authorization_id == receipt.authorization_id
                    && (receipt.terms_digest != intent.terms.terms_digest()?
                        || receipt.package_digest != intent.terms.review_package_digest)
                {
                    return Err(BridgeError::Binding);
                }
            }
            if let Some(auth) = &receipt.authenticated {
                if auth.account_id != receipt.account_id
                    || auth.authorization_id != receipt.authorization_id
                    || auth.terms_digest != receipt.terms_digest
                    || auth.package_digest != receipt.package_digest
                    || auth.envelope_digest != receipt.envelope_digest
                {
                    return Err(BridgeError::Binding);
                }
                let digest = auth.receipt_digest()?;
                if receipt
                    .accepted_receipt_digest
                    .as_ref()
                    .is_some_and(|r| r != &digest)
                {
                    return Err(BridgeError::Binding);
                }
            } else if receipt.accepted_receipt_digest.is_some() {
                return Err(BridgeError::Binding);
            }
        }
        match (&self.pending_birth_commit, &self.account_use.genesis) {
            (None, None) => {}
            (Some(commit), Some(genesis)) => {
                commit.validate()?;
                if commit.request.disclosure != *witness
                    || commit.request.policy.account_use_genesis.as_ref() != Some(genesis)
                {
                    return Err(BridgeError::Binding);
                }
            }
            _ => return Err(BridgeError::Binding),
        }
        match &self.account_use.genesis {
            None if self.account_use.exclusion.is_some()
                || self.account_use.witness_ack.is_some() =>
            {
                return Err(BridgeError::Binding);
            }
            None => {}
            Some(genesis) => {
                genesis.validate()?;
                if genesis.identity.account_id != account
                    || genesis.identity.network_profile_id != network
                    || genesis.witness_id != witness.witness_id
                    || genesis.witness_origin_digest
                        != wholepact_authority::account_use_link::account_use_witness_origin_digest(
                            witness,
                        )?
                {
                    return Err(BridgeError::Binding);
                }
                if let Some(exclusion) = &self.account_use.exclusion {
                    exclusion.validate()?;
                    if exclusion.identity != genesis.identity
                        || exclusion.genesis_digest != genesis.digest()?
                    {
                        return Err(BridgeError::Binding);
                    }
                }
                if let Some(ack) = &self.account_use.witness_ack {
                    let exclusion = self
                        .account_use
                        .exclusion
                        .as_ref()
                        .ok_or(BridgeError::Binding)?;
                    ack.digest()?;
                    if ack.genesis_digest != genesis.digest()?
                        || ack.exclusion_digest != exclusion.digest()?
                        || ack.witness_origin_digest != genesis.witness_origin_digest
                        || ack.operation_id != exclusion.operation_id
                    {
                        return Err(BridgeError::Binding);
                    }
                    head_at_or_before(&ack.committed_head, head)?;
                }
            }
        }
        // Check the exact serialized body, including nested receipt previews,
        // before copying it into an IPC frame or showing the native review.
        if serde_json::to_vec(self).map_err(binding)?.len() > MAX_COMPLETE_HISTORY_BYTES {
            return Err(BridgeError::Binding);
        }
        self.conservative_debit_zatoshis()?;
        Ok(())
    }
    pub fn conservative_debit_zatoshis(&self) -> Result<u64> {
        self.origins.iter().try_fold(0u64, |sum, o| {
            sum.checked_add(o.maximum_debit_zatoshis()?)
                .ok_or(BridgeError::Binding)
        })
    }
    pub fn unresolved_offline_authorizations(&self) -> Result<BTreeSet<String>> {
        let mut result = BTreeSet::new();
        for origin in &self.origins {
            if let HostRecoveryReservationOriginV2::Offline { origin } = origin {
                if origin.missing_current_witness_replay() {
                    result.insert(origin.terms()?.authorization_id.clone());
                }
            }
        }
        Ok(result)
    }
    pub fn conservative_obligations(&self) -> Result<BTreeSet<String>> {
        self.origins
            .iter()
            .map(|o| o.obligation_id().map(str::to_owned))
            .collect()
    }
}
