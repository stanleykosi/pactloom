//! Synthetic-only public historical metadata derived from the SAME genuine
//! consumed source, local profile and actual complete witness replay. No permit.
use super::*;
use crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::ConsumedBornNamedSourceV1;
use crate::native_ui::PendingAccountNativeAuthority;
use wholepact_authority::{AuthorityClient, AuthorityHead, WriterSessionReceipt,
    born_offline_enrollment_v1::{BornOfflineAssuranceV1, BornOfflineEnrollmentV1},
    born_offline_owner_continuation_v1::BornOfflineOwnerContinuationV1,
    offline::{OfflineEnrollmentPolicy, OfflineAuthoritySemantics}};

/// Inert original evidence, never authority or a fresh observation. The Host
/// cannot reconstruct a signer owner, admission, checkpoint or lease from this.
#[derive(Clone)]
pub struct OriginalNamedSetupMetadataV1 {
    pub account_id: String,
    pub profile_ref: String,
    pub local_enrollment_ref: String,
    pub accepted_manifest_ref: String,
    pub witness_enrollment_ref: String,
    pub signer_transport_public_key: [u8; 32],
    pub offline_policy: OfflineEnrollmentPolicy,
    pub original_session: WriterSessionReceipt,
    pub construction_expires_at_ms: u64,
    pub head: AuthorityHead,
    pub enrollment_digest: String,
    pub artifact_binding_digest: String,
}
fn wall() -> crate::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| crate::Error::Locked)?
        .as_millis()
        .try_into()
        .map_err(|_| crate::Error::Locked)
}
impl LiveNamedRecipientProfile {
    pub(crate) fn synthetic_born_enrollment_draft(
        &self,
        actual: &ConsumedBornNamedSourceV1,
        native: &PendingAccountNativeAuthority,
        session: &SignerConsentSession,
        client: &AuthorityClient,
        source_identity_digest: &str,
        source_policy_digest: &str,
    ) -> crate::Result<BornOfflineEnrollmentV1> {
        actual.check(native)?;
        self.check_current(actual.journal(), session)?;
        let op = NamedRecipientOperation::new();
        let deadline = op
            .deadline()
            .min(native.native().binding().bounded_deadline()?);
        let h = client
            .reconcile_history_checked_until(deadline, || {
                native
                    .check_current()
                    .and_then(|_| actual.check(native))
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)?;
                op.check()
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| crate::Error::Uncertain)?;
        let p = &self.record;
        let original = actual.construction();
        let birth = h
            .pending_birth_commit()
            .ok_or(crate::Error::ReviewMismatch)?;
        let policy = h.account_policy();
        let terms = &original.extension.account_extension.terms;
        let now = wall()?;
        let expires = original
            .reservation
            .session
            .expires_at_ms
            .min(original.reservation.construction_expires_at_ms)
            .min(terms.scope.expires_at_ms)
            .min(policy.policy_expires_at_ms);
        if now >= expires {
            return Err(crate::Error::Locked);
        }
        let attempt = h
            .latest_manual_roster_attempt_v2(p.witness_enrollment_ref())
            .map_err(|_| crate::Error::Verification)?;
        let admission = attempt
            .admission
            .as_ref()
            .ok_or(crate::Error::ReviewMismatch)?;
        let e = BornOfflineEnrollmentV1 {
            version: 1,
            policy: OfflineEnrollmentPolicy {
                schema_version: 1,
                account_id: p.account_id.clone(),
                network_profile_id: policy.network_profile_id.clone(),
                witness_id: policy.witness_id.clone(),
                witness_transport_key_digest: named_recipient_records::transport_fingerprint(
                    &p.witness_transport_public_key,
                ),
                witness_certificate_digest: p.witness_certificate_digest.clone(),
                enrollment_ref: p.witness_enrollment_ref().into(),
                offline_signer_key_digest: named_recipient_records::transport_fingerprint(
                    &p.transport_public_key,
                ),
                return_recipient_key_digest: named_recipient_records::transport_fingerprint(
                    &p.return_transport_public_key,
                ),
                source_identity_digest: source_identity_digest.into(),
                source_policy_digest: source_policy_digest.into(),
                maximum_admission_lifetime_ms: terms
                    .scope
                    .maximum_permit_lifetime_ms
                    .min(policy.maximum_permit_lifetime_ms),
                valid_from_ms: now,
                expires_at_ms: expires,
                semantics:
                    OfflineAuthoritySemantics::ExactEffectsPreReservedMayDrainAfterRevocation,
            },
            assurance: BornOfflineAssuranceV1::NamedVerifierOwnEffectsV1 {
                owner_setup_digest: p.original_setup_digest.clone(),
            },
            owner_continuation: Some(BornOfflineOwnerContinuationV1 {
                version: 1,
                construction_reservation_operation_id: original
                    .reservation
                    .request
                    .construction
                    .operation_id
                    .clone(),
                construction_consume_operation_id: original.consumed.request.operation_id.clone(),
                construction_origin_digest: original
                    .digest()
                    .map_err(|_| crate::Error::InvalidData)?,
                construction_transport_credential_id: original
                    .transport_credential_id
                    .clone()
                    .ok_or(crate::Error::ReviewMismatch)?,
            }),
            original_policy_digest: policy
                .policy_digest()
                .map_err(|_| crate::Error::InvalidData)?,
            account_use_genesis_digest: actual
                .genesis()
                .digest()
                .map_err(|_| crate::Error::InvalidData)?,
            birth_request_digest: birth.request_digest.clone(),
            birth_commit_digest:
                wholepact_authority::manual_enrollment::original_birth_commit_digest(birth)
                    .map_err(|_| crate::Error::InvalidData)?,
            native_birth_digest: actual.genesis().native_birth_digest.clone(),
            original_witness_origin_digest: actual.genesis().witness_origin_digest.clone(),
            owner_certificate_digest: actual.genesis().owner_certificate_digest.clone(),
            manual_extension_digest: original
                .extension
                .digest()
                .map_err(|_| crate::Error::InvalidData)?,
            manual_attempt_digest: attempt.attempt_digest.clone(),
            manual_admission_digest: admission
                .digest_for(&original.extension, attempt.continuation.as_ref())
                .map_err(|_| crate::Error::InvalidData)?,
            original_writer_session: original.reservation.session.clone(),
            expected_head: h.snapshot().head.clone(),
            issued_at_ms: now,
            first_commit_deadline_ms: now
                .checked_add(120_000)
                .ok_or(crate::Error::InvalidData)?
                .min(expires),
        };
        e.validate().map_err(|_| crate::Error::ReviewMismatch)?;
        actual.check(native)?;
        self.check_current(actual.journal(), session)?;
        Ok(e)
    }
    pub(crate) fn synthetic_installed_born_metadata(
        &self,
        actual: &ConsumedBornNamedSourceV1,
        native: &PendingAccountNativeAuthority,
        session: &SignerConsentSession,
        client: &AuthorityClient,
        signed: &BornOfflineEnrollmentV1,
    ) -> crate::Result<OriginalNamedSetupMetadataV1> {
        actual.check(native)?;
        self.check_current(actual.journal(), session)?;
        let op = NamedRecipientOperation::new();
        let h = client
            .reconcile_history_checked_until(
                op.deadline()
                    .min(native.native().binding().bounded_deadline()?),
                || {
                    native
                        .check_current()
                        .and_then(|_| actual.check(native))
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)?;
                    op.check()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                },
            )
            .map_err(|_| crate::Error::Uncertain)?;
        let e = h
            .born_offline_enrollment_v1()
            .map_err(|_| crate::Error::Verification)?
            .ok_or(crate::Error::Unavailable)?;
        let a = h
            .born_offline_artifacts_v1()
            .map_err(|_| crate::Error::Verification)?
            .ok_or(crate::Error::Unavailable)?;
        a.binding
            .validate_enrollment(&e.enrollment)
            .map_err(|_| crate::Error::ReviewMismatch)?;
        if &e.enrollment != signed
            || h.account_use_history().genesis() != Some(actual.genesis())
            || a.binding.offline_signer_public_key_hex
                != hex::encode(self.record.transport_public_key)
            || a.binding.witness_public_key_hex
                != hex::encode(self.record.witness_transport_public_key)
            || wall()? >= signed.policy.expires_at_ms
        {
            return Err(crate::Error::ReviewMismatch);
        }
        signed
            .owner_continuation
            .as_ref()
            .ok_or(crate::Error::ReviewMismatch)?
            .validate_origin(signed, actual.construction())
            .map_err(|_| crate::Error::ReviewMismatch)?;
        actual.check(native)?;
        self.check_current(actual.journal(), session)?;
        Ok(OriginalNamedSetupMetadataV1 {
            account_id: self.record.account_id.clone(),
            profile_ref: self.reference().into(),
            local_enrollment_ref: self.record.enrollment_ref.clone(),
            accepted_manifest_ref: self.record.manifest_ref.clone(),
            witness_enrollment_ref: self.record.witness_enrollment_ref().into(),
            signer_transport_public_key: self.record.transport_public_key,
            offline_policy: signed.policy.clone(),
            original_session: signed.original_writer_session.clone(),
            construction_expires_at_ms: actual
                .construction()
                .reservation
                .construction_expires_at_ms,
            head: h.snapshot().head.clone(),
            enrollment_digest: signed.digest().map_err(|_| crate::Error::InvalidData)?,
            artifact_binding_digest: a.binding.digest().map_err(|_| crate::Error::InvalidData)?,
        })
    }
}
