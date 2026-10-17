//! Inert purpose-distinct born parent evidence retained in the same immutable
//! original row. Parsing this never authenticates history or grants a permit.
use super::*;
use rusqlite::Connection;
use wholepact_authority::{
    AuthorityHead,
    account_use::AccountUseGenesis,
    born_offline_admission_v1::BornOfflineReservationRequestV1,
    born_offline_artifacts_v1::BornOfflineArtifactRecordV1,
    born_offline_enrollment_v1::{BornOfflineAssuranceV1, BornOfflineEnrollmentRecordV1},
    manual_enrollment::{ManualEnrollmentExtension, ManualEnrollmentExtensionRecord},
    manual_roster_witness_v2::ManualRosterEnrollmentExtensionRecordV2,
    pending_birth::PendingBirthCommitRecord,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BornNamedManualParentV1 {
    Single {
        record: ManualEnrollmentExtensionRecord,
    },
    RosterV2 {
        record: ManualRosterEnrollmentExtensionRecordV2,
    },
}
impl BornNamedManualParentV1 {
    pub(crate) fn extension(&self) -> &ManualEnrollmentExtension {
        match self {
            Self::Single { record } => &record.extension,
            Self::RosterV2 { record } => &record.account_record.extension,
        }
    }
    pub(crate) fn digest(&self) -> Result<String> {
        match self {
            Self::Single { record } => record.extension.digest(),
            Self::RosterV2 { record } => record.extension.digest(),
        }
        .map_err(invalid_named_record)
    }
    fn validate(&self, birth: &PendingBirthCommitRecord) -> Result<()> {
        let account = match self {
            Self::Single { record } => record,
            Self::RosterV2 { record } => {
                record
                    .extension
                    .validate_original_birth(birth)
                    .map_err(invalid_named_record)?;
                if record.extension.account_extension != record.account_record.extension {
                    return Err(JournalError::InvalidBinding);
                }
                &record.account_record
            }
        };
        account
            .extension
            .validate_original_birth(birth)
            .map_err(invalid_named_record)?;
        hash(&account.owner_signature_evidence_digest)?;
        hash(&account.native_review_digest)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornNamedRecipientOriginV1 {
    pub(crate) version: u16,
    pub(crate) request: BornOfflineReservationRequestV1,
    pub(crate) enrollment: BornOfflineEnrollmentRecordV1,
    pub(crate) artifacts: BornOfflineArtifactRecordV1,
    pub(crate) birth: PendingBirthCommitRecord,
    pub(crate) manual_parent: BornNamedManualParentV1,
    pub(crate) signer_genesis: AccountUseGenesis,
    pub(crate) parent_history_digest: String,
    pub(crate) parent_head: AuthorityHead,
    pub(crate) checkpoint_origin:
        wholepact_authority::born_offline_checkpoint_origin_v1::BornOfflineCheckpointOriginV1,
    pub(crate) checkpoint_receipt: BornNamedCheckpointReceiptV1,
}
impl BornNamedRecipientOriginV1 {
    pub(crate) fn manual_extension(&self) -> &ManualEnrollmentExtension {
        self.manual_parent.extension()
    }
    pub(crate) fn digest(&self) -> Result<String> {
        digest("wholepact:born-named-recipient-origin:v1", self)
    }
    /// Excludes only the native review field (which this digest will help
    /// create). Every other original request field, including terms/head/time,
    /// is preserved. No authority or current-clock assertion is returned.
    pub(crate) fn parent_binding_digest(&self) -> Result<String> {
        let mut request = self.request.clone();
        request
            .reservation
            .intent
            .native_reservation_review_digest
            .clear();
        digest(
            "wholepact:born-named-recipient-parent-review:v1",
            &(
                self.version,
                &request,
                &self.enrollment,
                &self.artifacts,
                &self.birth,
                &self.manual_parent,
                &self.signer_genesis,
                &self.parent_history_digest,
                &self.parent_head,
                &self.checkpoint_origin,
                &self.checkpoint_receipt,
            ),
        )
    }
    pub(crate) fn validate_structure(
        &self,
        profile: &NamedRecipientProfileRecordV1,
        original: &NamedRecipientOriginalRecordV1,
    ) -> Result<()> {
        self.birth.validate().map_err(invalid_named_record)?;
        self.signer_genesis
            .validate()
            .map_err(invalid_named_record)?;
        self.enrollment
            .enrollment
            .validate_original_birth(&self.birth)
            .map_err(invalid_named_record)?;
        hash(&self.enrollment.owner_signature_evidence_digest)?;
        hash(&self.enrollment.native_review_digest)?;
        self.artifacts.validate().map_err(invalid_named_record)?;
        self.artifacts
            .binding
            .validate_enrollment(&self.enrollment.enrollment)
            .map_err(invalid_named_record)?;
        self.manual_parent.validate(&self.birth)?;
        hash(&self.parent_history_digest)?;
        hash(&self.parent_head.digest)?;
        let e = &self.enrollment.enrollment;
        let r = &self.request.reservation;
        let policy = &self.birth.request.policy;
        let manual = self.manual_extension();
        let born_profile = profile
            .born_profile
            .as_ref()
            .ok_or(JournalError::InvalidBinding)?;
        born_profile.validate()?;
        self.request
            .construction_link
            .validate_for(&born_profile.construction, r)
            .map_err(invalid_named_record)?;
        self.checkpoint_origin
            .validate_for_origin(&born_profile.construction)
            .map_err(invalid_named_record)?;
        if born_profile.genesis != self.signer_genesis
            || &born_profile.construction.extension.account_extension != manual
            || !matches!(&self.manual_parent, BornNamedManualParentV1::RosterV2 { record } if record.extension == born_profile.construction.extension)
        {
            return Err(JournalError::InvalidBinding);
        }
        self.checkpoint_origin
            .validate_for_link(&self.request.construction_link)
            .map_err(invalid_named_record)?;
        self.checkpoint_receipt
            .validate_for(profile, &self.checkpoint_origin)?;
        let checkpoint = &self.checkpoint_origin;
        // Old carrier1 remains historical readback only. Active owners require2 below.
        if checkpoint.version == 2 {
            checkpoint
                .require_historical_provenance_v2()
                .map_err(invalid_named_record)?;
            checkpoint
                .validate_snapshot_terms(&original.terms)
                .map_err(invalid_named_record)?;
        }
        if checkpoint.proved_artifact_digest != original.original_artifact_digest
            || checkpoint.network_profile_id != original.terms.network_profile_id
            || checkpoint.agreement_id != original.terms.agreement_id
            || checkpoint.proposal_id != original.terms.proposal_id
            || checkpoint.proposal_revision != original.terms.proposal_revision
            || checkpoint.proposal_digest != original.terms.proposal_digest
            || checkpoint.manifest_digest != original.terms.manifest_digest
            || checkpoint.effects_commitment != original.terms.effects_digest
            || checkpoint.review_binding != original.terms.review_binding
        {
            return Err(JournalError::InvalidBinding);
        }
        self.request
            .validate_policy_bounds(policy, e, &self.artifacts, manual, r.requested_at_ms)
            .map_err(invalid_named_record)?;
        if self.version != 1
            || policy.account_use_genesis.as_ref() != Some(&self.signer_genesis)
            || self.signer_genesis.identity.account_id != profile.account_id
            || self.signer_genesis.identity.full_viewing_key_digest
                != profile.full_viewing_key_digest
            || self.request.reservation != original.reservation_request
            || manual.enrollment_ref != profile.witness_enrollment_ref()
            || e.manual_extension_digest != self.manual_parent.digest()?
            || self.parent_head != r.expected_head
            || self.artifacts.binding.expected_head.sequence >= self.parent_head.sequence
            || e.expected_head.sequence >= self.artifacts.binding.expected_head.sequence
            || e.policy.witness_certificate_digest != profile.witness_certificate_digest
            || self.artifacts.binding.witness_public_key_hex
                != hex::encode(profile.witness_transport_public_key)
            || self.artifacts.binding.offline_signer_public_key_hex
                != hex::encode(profile.transport_public_key)
            || e.policy.return_recipient_key_digest
                != transport_fingerprint(&profile.return_transport_public_key)
            || !matches!(&e.assurance, BornOfflineAssuranceV1::NamedVerifierOwnEffectsV1 { owner_setup_digest } if owner_setup_digest == &profile.original_setup_digest)
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    /// Read only the actual original signer account-use and enrollment rows.
    /// Callers separately hold/recheck the genuine native/session lease. No
    /// serialized origin can replace this check or the authenticated history.
    pub(crate) fn require_actual_signer(
        &self,
        c: &Connection,
        profile: &NamedRecipientProfileRecordV1,
        enrollment: &AccountEnrollmentRecord,
    ) -> Result<()> {
        // Version1 preserves exact historical evidence, never new permission.
        self.checkpoint_origin
            .require_historical_provenance_v2()
            .map_err(invalid_named_record)?;
        self.require_retained_signer(c, profile, enrollment)?;
        let actual = super::super::account_use_storage::inspect(c, &profile.account_id)?;
        if actual.exclusion().is_some() {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    /// Historical inventory preserves permanently stopped origins; this does
    /// not authorize any new write or signing attempt.
    pub(crate) fn require_retained_signer(
        &self,
        c: &Connection,
        profile: &NamedRecipientProfileRecordV1,
        enrollment: &AccountEnrollmentRecord,
    ) -> Result<()> {
        let actual = super::super::account_use_storage::inspect(c, &profile.account_id)?;
        if actual.genesis() != Some(&self.signer_genesis) {
            return Err(JournalError::InvalidBinding);
        }
        let retained =
            storage::read_enrollment(c, &profile.enrollment_ref)?.ok_or(JournalError::NotFound)?;
        let born_profile = profile
            .born_profile
            .as_ref()
            .ok_or(JournalError::InvalidBinding)?;
        if &retained != enrollment
            || born_profile.genesis != self.signer_genesis
            || &born_profile.construction.extension.account_extension != self.manual_extension()
        {
            return Err(JournalError::InvalidBinding);
        }
        born_profile.validate_local_enrollment(profile, enrollment)?;
        if self.checkpoint_origin.version == 2 {
            // Validate the actual encrypted local complete read/reentry inventory,
            // not a caller's claimed read hash or nonexistent peer witness history.
            let audit = super::super::common_context_reentry_audit_v1::read_complete(
                c,
                &profile.account_id,
            )?;
            let [super::super::CommonContextSignerAuditV1::ReadAdmitted { evidence: read, .. }] =
                audit.original.rows.as_slice()
            else {
                return Err(JournalError::Conflict);
            };
            if audit.reentry.rows.len() != 6 {
                return Err(JournalError::Conflict);
            }
            let actual = &born_profile.construction;
            let mut reserved = false;
            let mut consumed = false;
            for row in &audit.reentry.rows {
                match &row.record {
                    super::super::CommonContextReentryAuditPhaseV1::Reserved {
                        extension,
                        continuation,
                        record,
                        ..
                    } => {
                        if reserved
                            || extension.as_ref() != &actual.extension
                            || continuation.as_ref() != &actual.continuation
                            || record.original != actual.reservation
                            || actual.transport_credential_id.as_ref()
                                != Some(&record.credential_id)
                        {
                            return Err(JournalError::Conflict);
                        }
                        reserved = true;
                    }
                    super::super::CommonContextReentryAuditPhaseV1::Consumed {
                        record,
                        evidence,
                        ..
                    } => {
                        if consumed
                            || record.original != actual.consumed
                            || actual.transport_credential_id.as_ref()
                                != Some(&record.credential_id)
                            || evidence.reentry_lineage.request.original_read != read.request
                        {
                            return Err(JournalError::Conflict);
                        }
                        consumed = true;
                    }
                    _ => {}
                }
            }
            if !reserved || !consumed {
                return Err(JournalError::InvalidBinding);
            }
            self.checkpoint_origin
                .validate_historical_read(
                    &born_profile
                        .construction
                        .reservation
                        .request
                        .construction
                        .plan,
                    &read.request,
                    &read.digest().map_err(invalid_named_record)?,
                )
                .map_err(invalid_named_record)?;
        }

        Ok(())
    }
}
