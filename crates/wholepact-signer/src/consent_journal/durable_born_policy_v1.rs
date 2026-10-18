//! Inert, exact bridge from a freshly reviewed local consent to the ORIGINAL
//! immutable born/manual witness policy. Parsing this evidence grants nothing.
//! Current vault/native/journal ownership must be checked separately by the
//! genuine durable-entry caller before release and immediate key use.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wholepact_authority::{
    account_use::AccountUseGenesis, manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
};
use wholepact_core::manual_enrollment::BornManualEnrollmentTerms;

/// Unconditional historical projection of the complete original account record.
/// Exact serde keys and canonical hash domains match BornManualEnrollmentRecord;
/// this copy deliberately has no native, vault, journal or signing constructor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalManualRecordV1 {
    terms: BornManualEnrollmentTerms,
    terms_digest: String,
    genesis: AccountUseGenesis,
    first_process_binding: TransportIdentityBinding,
    first_native_principal: String,
    signer_native_review_digest: String,
}
impl OriginalManualRecordV1 {
    fn validate(&self) -> Result<()> {
        let t = &self.terms;
        t.validate().map_err(invalid)?;
        self.genesis.validate().map_err(invalid)?;
        if self.terms_digest != t.terms_digest().map_err(invalid)?
            || self.genesis.identity.account_id != t.identity.account_id
            || self.genesis.identity.full_viewing_key_digest != t.identity.full_viewing_key_digest
            || self.genesis.identity.network_profile_id != t.identity.network_profile_id
            || self.genesis.identity.derivation_domain != t.identity.derivation_domain
            || self.genesis.digest().map_err(invalid)? != t.account_use_genesis_digest
            || self.genesis.witness_origin_digest != t.original_witness_origin_digest
            || self.genesis.native_birth_digest != t.native_birth_digest
            || self.genesis.owner_certificate_digest != t.signer.owner_certificate_digest
            || digest(
                "wholepact:born-manual-transport:v1",
                &self.first_process_binding,
            )? != t.transport_binding_digest
            || self.first_native_principal.is_empty()
            || self.first_native_principal.len() > 128
            || self.signer_native_review_digest
                != digest(
                    "wholepact:native-born-manual-enrollment-review:v1",
                    &(
                        t,
                        &self.genesis,
                        &self.first_process_binding,
                        &self.first_native_principal,
                    ),
                )?
        {
            return Err(JournalError::InvalidBinding);
        }
        match &self.first_process_binding {
            TransportIdentityBinding::LocalProcess {
                account_id,
                agreement_id,
                participant_id,
                pid,
                signer_generation,
                ..
            } if account_id == &t.identity.account_id
                && agreement_id == &t.scope.agreement_id
                && participant_id == &t.scope.participant_id
                && *pid > 0
                && *signer_generation > 0 =>
            {
                Ok(())
            }
            _ => Err(JournalError::InvalidBinding),
        }
    }
    fn reference(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-manual-enrollment-record:v1", self)
    }
}

/// Strict feature-independent metadata projection. It is not a verified PCZT.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedCandidateV1 {
    schema_version: u32,
    network_profile_id: String,
    agreement_id: String,
    obligation_id: String,
    proposal_id: String,
    revision: u32,
    expiry_height: u32,
    proposal_digest: String,
    manifest_digest: String,
    unsigned_artifact_digest: String,
    proved_artifact_digest: String,
    effects_commitment: String,
    policy_digest: String,
    review_binding: String,
    action_mapping_digest: String,
    anchor: String,
    proposal_binding: String,
}
impl FixedCandidateV1 {
    fn binding(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
        h.update(self.schema_version.to_le_bytes());
        h.update(self.revision.to_le_bytes());
        h.update(self.expiry_height.to_le_bytes());
        for value in [
            &self.network_profile_id,
            &self.agreement_id,
            &self.obligation_id,
            &self.proposal_id,
            &self.proposal_digest,
            &self.manifest_digest,
            &self.unsigned_artifact_digest,
            &self.proved_artifact_digest,
            &self.effects_commitment,
            &self.policy_digest,
            &self.review_binding,
            &self.action_mapping_digest,
            &self.anchor,
        ] {
            h.update((value.len() as u64).to_le_bytes());
            h.update(value.as_bytes());
        }
        hex::encode(h.finalize())
    }
    fn validate(&self) -> Result<()> {
        for value in [
            &self.network_profile_id,
            &self.agreement_id,
            &self.obligation_id,
            &self.proposal_id,
        ] {
            id(value)?;
        }
        for value in [
            &self.proposal_digest,
            &self.manifest_digest,
            &self.unsigned_artifact_digest,
            &self.proved_artifact_digest,
            &self.effects_commitment,
            &self.policy_digest,
            &self.review_binding,
            &self.action_mapping_digest,
            &self.anchor,
            &self.proposal_binding,
        ] {
            hash(value)?;
        }
        if self.schema_version != 1
            || self.expiry_height == 0
            || self.proposal_binding != self.binding()
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

/// Strict feature-independent projection of the maintained actual-source export.
/// It retains the complete V2 native-birth preimage and its original witness
/// commit; an allowlisted hash or a version label cannot stand in for either.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalRecipientPolicyExportProjectionV2 {
    version: u16,
    anchor: wholepact_core::born_policy_origin_v2::BornRecipientPolicyOriginV2,
    original_birth_commit: wholepact_authority::pending_birth::PendingBirthCommitRecord,
}
impl OriginalRecipientPolicyExportProjectionV2 {
    fn validate_for(
        &self,
        original: &OriginalManualRecordV1,
        extension: &ManualRosterEnrollmentExtensionV2,
    ) -> Result<()> {
        self.anchor.validate().map_err(invalid)?;
        self.original_birth_commit.validate().map_err(invalid)?;
        extension
            .validate_original_birth(&self.original_birth_commit)
            .map_err(invalid)?;
        let a = &self.anchor;
        let r = &self.original_birth_commit.request;
        let g = &original.genesis;
        if self.version != 2
            || a.birth_digest != g.native_birth_digest
            || a.birth_digest != r.native_birth_digest
            || a.intent.operation_id != r.operation_id
            || a.intent.generation_instance_id != r.generation_instance_id
            || a.intent.original_policy_terms_digest != r.original_terms_digest
            || r.policy.account_use_genesis.as_ref() != Some(g)
            || a.intent.identity.account_id != g.identity.account_id
            || a.intent.identity.full_viewing_key_digest != g.identity.full_viewing_key_digest
            || a.intent.identity.network_profile_id != g.identity.network_profile_id
            || a.intent.identity.derivation_domain != g.identity.derivation_domain
            || a.intent.witness_origin.endpoint != r.disclosure.endpoint
            || a.intent.witness_origin.server_name != r.disclosure.server_name
            || a.intent.witness_origin.witness_id != r.disclosure.witness_id
            || a.intent.witness_origin.pinned_server_certificate_digest
                != r.disclosure.pinned_server_certificate_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        a.recipient_policy
            .require_enrollment(&original.terms)
            .map_err(invalid)?;
        Ok(())
    }
}

/// Explicit meaning of the witness's policy scope. This is not a fallback:
/// stable V2 never reinterprets a V1 concrete output digest, and the exact
/// payment-effect commitment remains independently fixed in both profiles.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DurableBornRecipientPolicyProfileV1 {
    #[default]
    FixedExactV1,
    StableOriginalV2 {
        original: OriginalRecipientPolicyExportProjectionV2,
        policy_scope_digest: String,
    },
}
impl DurableBornRecipientPolicyProfileV1 {
    fn is_exact(&self) -> bool {
        matches!(self, Self::FixedExactV1)
    }
}

/// DATA ONLY. The optional presence is committed by the native consent hash.
/// Local enrollment/transport remain fresh; only the two explicit witness policy
/// fields are derived from this independently source-checked historical mapping.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableBornPolicyBindingV1 {
    version: u16,
    original: OriginalManualRecordV1,
    original_roster_extension: ManualRosterEnrollmentExtensionV2,
    original_genesis_digest: String,
    original_enrollment_ref: String,
    original_extension_digest: String,
    original_roster_extension_digest: String,
    recipient_scope_digest: String,
    local_enrollment_ref: String,
    local_accepted_manifest_ref: String,
    fixed: FixedCandidateV1,
    // The default omission preserves the complete pre-existing exact V1 wire
    // shape and consent hash, not only the older unbound None representation.
    #[serde(
        default,
        skip_serializing_if = "DurableBornRecipientPolicyProfileV1::is_exact"
    )]
    recipient_policy_profile: DurableBornRecipientPolicyProfileV1,
}
impl DurableBornPolicyBindingV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        self.original.validate()?;
        self.original_roster_extension.validate().map_err(invalid)?;
        self.fixed.validate()?;
        for value in [
            &self.original_genesis_digest,
            &self.original_enrollment_ref,
            &self.original_extension_digest,
            &self.original_roster_extension_digest,
            &self.recipient_scope_digest,
            &self.local_enrollment_ref,
            &self.local_accepted_manifest_ref,
        ] {
            hash(value)?;
        }
        let extension = &self.original_roster_extension.account_extension;
        #[derive(Serialize)]
        struct OriginalRosterRecord<'a> {
            version: u16,
            account_record: &'a OriginalManualRecordV1,
            roster: &'a wholepact_core::manual_roster_v2::HostRosterAppendBindingV2,
            signer_roster_native_review_digest: String,
        }
        let roster_record = OriginalRosterRecord {
            version: 2,
            account_record: &self.original,
            roster: &self.original_roster_extension.roster,
            signer_roster_native_review_digest: digest(
                "wholepact:native-born-manual-roster-enrollment-review:v2",
                &(&self.original, &self.original_roster_extension.roster),
            )?,
        };
        if self.version != 1
            || self.original_genesis_digest != self.original.genesis.digest().map_err(invalid)?
            || self.original_enrollment_ref != self.original.reference()?
            || extension.enrollment_ref != self.original_enrollment_ref
            || extension.terms != self.original.terms
            || self.original_roster_extension.signer_roster_record_digest
                != digest(
                    "wholepact:born-manual-roster-enrollment-record:v2",
                    &roster_record,
                )?
            || self.original_extension_digest != extension.digest().map_err(invalid)?
            || self.original_roster_extension_digest
                != self.original_roster_extension.digest().map_err(invalid)?
        {
            return Err(JournalError::InvalidBinding);
        }
        if let DurableBornRecipientPolicyProfileV1::StableOriginalV2 {
            original,
            policy_scope_digest,
        } = &self.recipient_policy_profile
        {
            original.validate_for(&self.original, &self.original_roster_extension)?;
            hash(policy_scope_digest)?;
            if *policy_scope_digest != original.anchor.recipient_policy.digest().map_err(invalid)? {
                return Err(JournalError::InvalidBinding);
            }
        }
        Ok(())
    }

    pub(crate) fn uses_stable_recipient_policy_v2(&self) -> bool {
        !self.recipient_policy_profile.is_exact()
    }

    /// Pure requirements, NOT proof of address ownership. The live adapter must
    /// join each returned output to its verified action and actual account FVK.
    pub(crate) fn stable_return_requirements_v2(
        &self,
        manifest: &AcceptedManifestRecord,
    ) -> Result<Vec<wholepact_core::born_recipient_policy_v2::OwnReturnRequirementV2>> {
        self.validate()?;
        let DurableBornRecipientPolicyProfileV1::StableOriginalV2 { original, .. } =
            &self.recipient_policy_profile
        else {
            return Err(JournalError::InvalidBinding);
        };
        let proposal = manifest.proposal()?;
        if manifest.reference() != self.local_accepted_manifest_ref
            || proposal.proposal_digest() != self.fixed.proposal_digest
            || proposal.manifest_digest() != self.fixed.manifest_digest
            || wholepact_core::manual_construction::construction_recipient_scope_digest(&proposal)
                .map_err(invalid)?
                != self.recipient_scope_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        let (validated, requirements) = original
            .anchor
            .recipient_policy
            .validate_candidate_for_enrollment(&self.original.terms, proposal.input())
            .map_err(invalid)?;
        if validated.input() != proposal.input() {
            return Err(JournalError::InvalidBinding);
        }
        Ok(requirements)
    }

    /// Pure historical conjunction. No wall-clock expiry, current native owner,
    /// or old-epoch equality is inferred here. Old exposure remains readable.
    pub(crate) fn validate_consent(
        &self,
        t: &SpendConsentTerms,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
    ) -> Result<()> {
        self.validate()?;
        enrollment.validate()?;
        let proposal = manifest.proposal()?;
        let m = proposal.manifest();
        let e = &self.original.terms;
        let s = &e.scope;
        let f = &self.fixed;
        let own = m
            .participants
            .iter()
            .find(|p| p.account_id == e.identity.account_id && p.participant_id == s.participant_id)
            .ok_or(JournalError::InvalidBinding)?;
        let payment =
            wholepact_core::manual_construction::construction_recipient_scope_digest(&proposal)
                .map_err(invalid)?;
        match &self.recipient_policy_profile {
            DurableBornRecipientPolicyProfileV1::FixedExactV1 => {
                if !s.recipient_scope_digests.contains(&payment) {
                    return Err(JournalError::InvalidBinding);
                }
            }
            DurableBornRecipientPolicyProfileV1::StableOriginalV2 { .. } => {
                // Historical arithmetic/descriptor validation does not claim
                // that these address-ownership obligations were discharged.
                let _requirements = self.stable_return_requirements_v2(manifest)?;
            }
        }
        let reviewed = t.receipt.reviewed_at_ms();
        let expires = t.receipt.expires_at_ms();
        if t.automation.is_some()
            || t.sponsor_policy.is_some()
            || t.sponsor_owner_attestation_digest.is_some()
            || self.local_enrollment_ref != enrollment.reference()
            || self.local_accepted_manifest_ref != manifest.reference()
            || t.enrollment_ref != enrollment.reference()
            || t.accepted_manifest_ref != manifest.reference()
            || manifest.enrollment_ref() != enrollment.reference()
            || t.account_id != e.identity.account_id
            || enrollment.account_id() != e.identity.account_id
            || enrollment.account_fvk_digest() != e.identity.full_viewing_key_digest
            || enrollment.terms.network_profile_id != e.identity.network_profile_id
            || enrollment.terms.privacy_domain != s.privacy_domain
            || enrollment.participant_id() != s.participant_id
            || enrollment.agreement_id() != s.agreement_id
            || t.principal_id != enrollment.principal_id()
            || t.transport != *enrollment.transport()
            || !storage::same_native_origin(enrollment.receipt(), manifest.receipt())
            || !storage::same_native_origin(manifest.receipt(), &t.receipt)
            || t.agreement_id != s.agreement_id
            || t.obligation_id != s.obligation_id
            || m.agreement.agreement_id != s.agreement_id
            || m.agreement.obligation_id != s.obligation_id
            || m.agreement.network_profile_id != e.identity.network_profile_id
            || self.recipient_scope_digest != payment
            || t.aggregate_budget_limit_zatoshis != enrollment.budget_limit_zatoshis()
            || t.aggregate_budget_limit_zatoshis > s.aggregate_budget_zatoshis
            || t.maximum_debit_zatoshis > s.per_operation_limit_zatoshis
            || t.maximum_debit_zatoshis > s.aggregate_budget_zatoshis
            || t.maximum_debit_zatoshis > own.maximum_net_debit.as_zatoshis()
            || proposal
                .accounting()
                .participant_net_debits
                .get(&own.participant_id)
                .map(|a| a.as_zatoshis())
                != Some(t.maximum_debit_zatoshis)
            || t.fee_share_zatoshis != own.fee_share.as_zatoshis()
            || t.fee_share_zatoshis > s.maximum_fee_share_zatoshis
            || t.transaction_fee_zatoshis != m.transaction_fee.as_zatoshis()
            || t.transaction_fee_zatoshis > s.maximum_transaction_fee_zatoshis
            || reviewed < e.issued_at_ms
            || expires > s.expires_at_ms
            || expires <= reviewed
            || expires - reviewed > s.maximum_permit_lifetime_ms
            || f.network_profile_id != m.agreement.network_profile_id
            || f.agreement_id != t.agreement_id
            || f.obligation_id != t.obligation_id
            || f.proposal_id != t.proposal_id
            || f.proposal_id != proposal.input().proposal_id
            || f.revision != m.agreement.revision
            || f.expiry_height != m.expiry_height
            || f.expiry_height != t.transaction_expiry_height
            || f.proposal_digest != proposal.proposal_digest()
            || f.proposal_digest != t.proposal_digest
            || f.manifest_digest != proposal.manifest_digest()
            || f.manifest_digest != t.manifest_digest
            || f.proved_artifact_digest != t.artifact_digest
            || f.effects_commitment != t.effects_digest
            || f.review_binding != t.review_binding
            || f.anchor != t.wallet_snapshot.anchor_root
            || proposal
                .input()
                .artifact_digest
                .as_ref()
                .is_some_and(|v| v != &f.proved_artifact_digest)
            || proposal
                .input()
                .effects_commitment
                .as_ref()
                .is_some_and(|v| v != &f.effects_commitment)
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }

    pub(crate) fn require_current_time(&self, now: u64) -> Result<()> {
        self.validate()?;
        if now < self.original.terms.issued_at_ms || now >= self.original.terms.scope.expires_at_ms
        {
            return Err(JournalError::Expired);
        }
        Ok(())
    }

    #[cfg(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn require_fixed_identity(
        &self,
        fixed: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<()> {
        self.validate()?;
        if serde_json::to_value(&self.fixed).map_err(invalid)?
            != serde_json::to_value(fixed).map_err(invalid)?
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }

    #[cfg(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn from_original_source(
        source: &crate::account::birth::enrollment::roster_v2::BornManualRosterEnrollmentRecordV2,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
        fixed: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<Self> {
        let result = Self::from_source_data(source, enrollment, manifest, fixed)?;
        if !result
            .original
            .terms
            .scope
            .recipient_scope_digests
            .contains(&result.recipient_scope_digest)
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(result)
    }

    #[cfg(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn from_original_stable_source_v2(
        source: &crate::account::birth::enrollment::roster_v2::BornManualRosterEnrollmentRecordV2,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
        fixed: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
        actual_export: &crate::account::birth::recipient_policy_v2::OriginalRecipientPolicyExportV2,
    ) -> Result<Self> {
        actual_export.validate().map_err(invalid)?;
        let original: OriginalRecipientPolicyExportProjectionV2 =
            serde_json::from_value(serde_json::to_value(actual_export).map_err(invalid)?)
                .map_err(invalid)?;
        let mut result = Self::from_source_data(source, enrollment, manifest, fixed)?;
        let policy_scope_digest = original.anchor.recipient_policy.digest().map_err(invalid)?;
        result.recipient_policy_profile = DurableBornRecipientPolicyProfileV1::StableOriginalV2 {
            original,
            policy_scope_digest,
        };
        result.validate_stable_original_source_v2(
            source,
            &source.account_record.genesis,
            actual_export,
        )?;
        let _requirements = result.stable_return_requirements_v2(manifest)?;
        Ok(result)
    }

    #[cfg(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn validate_original_source(
        &self,
        source: &crate::account::birth::enrollment::roster_v2::BornManualRosterEnrollmentRecordV2,
        genesis: &AccountUseGenesis,
    ) -> Result<()> {
        // A former exact-profile caller cannot accidentally authorize stable
        // policy data without comparing its complete actual original export.
        if !self.recipient_policy_profile.is_exact() {
            return Err(JournalError::InvalidBinding);
        }
        self.validate_common_original_source(source, genesis)
    }

    #[cfg(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn validate_stable_original_source_v2(
        &self,
        source: &crate::account::birth::enrollment::roster_v2::BornManualRosterEnrollmentRecordV2,
        genesis: &AccountUseGenesis,
        actual_export: &crate::account::birth::recipient_policy_v2::OriginalRecipientPolicyExportV2,
    ) -> Result<()> {
        self.validate_common_original_source(source, genesis)?;
        actual_export.validate().map_err(invalid)?;
        let DurableBornRecipientPolicyProfileV1::StableOriginalV2 { original, .. } =
            &self.recipient_policy_profile
        else {
            return Err(JournalError::InvalidBinding);
        };
        if serde_json::to_value(original).map_err(invalid)?
            != serde_json::to_value(actual_export).map_err(invalid)?
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }

    #[cfg(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    ))]
    fn from_source_data(
        source: &crate::account::birth::enrollment::roster_v2::BornManualRosterEnrollmentRecordV2,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
        fixed: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<Self> {
        source.validate().map_err(invalid)?;
        let original: OriginalManualRecordV1 =
            serde_json::from_value(serde_json::to_value(&source.account_record).map_err(invalid)?)
                .map_err(invalid)?;
        let extension = source.extension().map_err(invalid)?;
        let result = Self {
            version: 1,
            original_genesis_digest: original.genesis.digest().map_err(invalid)?,
            original_enrollment_ref: original.reference()?,
            original_extension_digest: extension.account_extension.digest().map_err(invalid)?,
            original_roster_extension_digest: extension.digest().map_err(invalid)?,
            recipient_scope_digest:
                wholepact_core::manual_construction::construction_recipient_scope_digest(
                    &manifest.proposal()?,
                )
                .map_err(invalid)?,
            local_enrollment_ref: enrollment.reference().into(),
            local_accepted_manifest_ref: manifest.reference().into(),
            fixed: serde_json::from_value(serde_json::to_value(fixed).map_err(invalid)?)
                .map_err(invalid)?,
            original,
            original_roster_extension: extension,
            recipient_policy_profile: DurableBornRecipientPolicyProfileV1::FixedExactV1,
        };
        result.validate()?;
        Ok(result)
    }

    #[cfg(all(
        feature = "durable-proposal",
        feature = "native-ui",
        target_os = "linux"
    ))]
    fn validate_common_original_source(
        &self,
        source: &crate::account::birth::enrollment::roster_v2::BornManualRosterEnrollmentRecordV2,
        genesis: &AccountUseGenesis,
    ) -> Result<()> {
        self.validate()?;
        source.validate().map_err(invalid)?;
        if self.original.genesis != *genesis
            || serde_json::to_value(&self.original).map_err(invalid)?
                != serde_json::to_value(&source.account_record).map_err(invalid)?
            || self.original_roster_extension != source.extension().map_err(invalid)?
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

fn invalid<T>(_: T) -> JournalError {
    JournalError::InvalidBinding
}

/// Join against actual retained genesis and already-loaded complete original
/// evidence, never against the optional mapping DTO alone. No recursive reads.
pub(crate) fn validate_retained_original(
    c: &rusqlite::Connection,
    original: &OriginalAuthorizationEvidence,
) -> Result<()> {
    let Some(binding) = &original.consent.terms.durable_born_policy_v1 else {
        return Ok(());
    };
    let stored = account_use_storage::inspect(c, original.enrollment.account_id())?;
    if stored.genesis() != Some(&binding.original.genesis) {
        return Err(JournalError::InvalidBinding);
    }
    binding.validate_consent(
        original.consent.terms(),
        &original.enrollment,
        &original.manifest,
    )
}

/// The sole exact mapping for request creation, retained request validation and
/// historical permit reconciliation. None keeps the old transport-bound digest.
pub(crate) fn witness_policy_scope(
    original: &OriginalAuthorizationEvidence,
) -> Result<(String, String)> {
    let t = original.consent.terms();
    if let Some(binding) = &t.durable_born_policy_v1 {
        binding.validate_consent(t, &original.enrollment, &original.manifest)?;
        Ok((
            binding.original_enrollment_ref.clone(),
            match &binding.recipient_policy_profile {
                DurableBornRecipientPolicyProfileV1::FixedExactV1 => {
                    binding.recipient_scope_digest.clone()
                }
                DurableBornRecipientPolicyProfileV1::StableOriginalV2 {
                    policy_scope_digest,
                    ..
                } => policy_scope_digest.clone(),
            },
        ))
    } else {
        Ok((
            original.enrollment.reference().into(),
            digest(
                "wholepact:signer-exact-authorization-recipient:v1",
                &(
                    original.enrollment.transport(),
                    crate::authority_bridge::protocol::AuthorizationDeliveryScope {
                        candidate_id: t.proposal_id.clone(),
                    },
                ),
            )?,
        ))
    }
}

#[cfg(test)]
#[path = "durable_born_policy_v1_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "durable_born_policy_v2_tests.rs"]
mod stable_tests;
