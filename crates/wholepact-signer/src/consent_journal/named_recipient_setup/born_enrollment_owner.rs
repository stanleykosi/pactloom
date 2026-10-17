//! Purpose-specific original-owner signature for an already consumed born V3.
//! Uses maintained P-256; the actual native decision is separate from profile,
//! construction and witness-owner installation. No session or MAC is created.
use super::*;
use crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::ConsumedBornNamedSourceV1;
use crate::native_ui::PendingAccountNativeAuthority;
use wholepact_authority::{
    AuthorityClient, ReconciledAuthorityHistory, WriterStatus,
    born_offline_enrollment_v1::{BornOfflineAssuranceV1, BornOfflineEnrollmentV1},
    born_offline_enrollment_signature_v1::{BornOfflineEnrollmentOwnerSignatureV1,
        born_offline_enrollment_v1_owner_signing_bytes, verify_born_offline_enrollment_v1_owner_signature},
};

pub(crate) struct PreparedBornOfflineOwnerEnrollmentV1 {
    profile: LiveNamedRecipientProfile,
    enrollment: BornOfflineEnrollmentV1,
    operation: NamedRecipientOperation,
    digest: String,
    display: String,
    deadline: Instant,
    wall_floor: u64,
}
fn now_ms() -> crate::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| crate::Error::InvalidData)?
        .as_millis()
        .try_into()
        .map_err(|_| crate::Error::InvalidData)
}
impl PreparedBornOfflineOwnerEnrollmentV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        profile: &LiveNamedRecipientProfile,
        actual: &ConsumedBornNamedSourceV1,
        native: &PendingAccountNativeAuthority,
        session: &SignerConsentSession,
        client: &AuthorityClient,
        enrollment: BornOfflineEnrollmentV1,
        operation: NamedRecipientOperation,
    ) -> crate::Result<Self> {
        actual.check(native)?;
        profile.check_current(actual.journal(), session)?;
        enrollment
            .validate()
            .map_err(|_| crate::Error::ReviewMismatch)?;
        let wall_floor = now_ms()?;
        let deadline = operation
            .deadline()
            .min(
                Instant::now()
                    + Duration::from_millis(
                        enrollment
                            .first_commit_deadline_ms
                            .checked_sub(wall_floor)
                            .filter(|n| *n > 0)
                            .ok_or(crate::Error::ReviewMismatch)?,
                    ),
            )
            .min(native.native().binding().bounded_deadline()?);
        let current = || {
            operation
                .check()
                .map_err(|_| wholepact_authority::AuthorityError::Permission)?;
            native
                .check_current()
                .map_err(|_| wholepact_authority::AuthorityError::Permission)?;
            if Instant::now() >= deadline
                || now_ms().map_or(true, |now| {
                    now < wall_floor || now >= enrollment.first_commit_deadline_ms
                })
            {
                return Err(wholepact_authority::AuthorityError::Permission);
            }
            Ok(())
        };
        let history = client
            .reconcile_history_checked_until(deadline, current)
            .map_err(|_| crate::Error::Uncertain)?;
        require_exact(
            profile,
            actual,
            native,
            session,
            client,
            &enrollment,
            &history,
        )?;
        current().map_err(|_| crate::Error::Locked)?;
        let digest = super::digest(
            "wholepact:native-born-offline-owner-enrollment-review:v1",
            &(
                enrollment.digest().map_err(|_| crate::Error::InvalidData)?,
                profile.reference(),
                profile.source.entry_digest(),
                history
                    .history_digest()
                    .map_err(|_| crate::Error::InvalidData)?,
            ),
        )?;
        let display = format!(
            "AUTHORIZE ORIGINAL-OWNER BORN CONTINUATION ENROLLMENT\n{}\n\nThis signs the exact displayed consumed construction, original session, local named-verifier setup and HPKE identities using the already pinned original owner certificate. The old general writer transport remains permanently fenced. This is not a transaction signature, an offline admission, current-input proof, a renewed writer session or permission to select different inputs. The original witness owner must independently review and install this exact signed enrollment. Your separately authenticated verifier remains trusted for peer ownership. Original deadlines and conservative charged exposure remain unchanged.\nExact review: {}",
            serde_json::to_string_pretty(&enrollment).map_err(|_| crate::Error::InvalidData)?,
            digest
        );
        Ok(Self {
            profile: profile.clone(),
            enrollment,
            operation,
            digest,
            display,
            deadline,
            wall_floor,
        })
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn approve_and_sign(
        self,
        decision: NativeDecision,
        actual: &ConsumedBornNamedSourceV1,
        native: &PendingAccountNativeAuthority,
        session: &SignerConsentSession,
        client: &AuthorityClient,
        signer: &dyn rustls::sign::Signer,
        certificate: &[u8],
    ) -> crate::Result<BornOfflineEnrollmentOwnerSignatureV1> {
        if decision.binding() != &self.profile.source
            || decision.reviewed_digest() != self.digest
            || native.native().binding() != self.profile.source
        {
            return Err(crate::Error::ReviewMismatch);
        }
        let current = || {
            self.operation
                .check()
                .map_err(|_| wholepact_authority::AuthorityError::Permission)?;
            native
                .check_current()
                .map_err(|_| wholepact_authority::AuthorityError::Permission)?;
            if Instant::now() >= self.deadline
                || now_ms().map_or(true, |now| {
                    now < self.wall_floor || now >= self.enrollment.first_commit_deadline_ms
                })
            {
                return Err(wholepact_authority::AuthorityError::Permission);
            }
            Ok(())
        };
        let history = client
            .reconcile_history_checked_until(self.deadline, current)
            .map_err(|_| crate::Error::Uncertain)?;
        require_exact(
            &self.profile,
            actual,
            native,
            session,
            client,
            &self.enrollment,
            &history,
        )?;
        let records = actual.journal().acquire_preconstruction_records(
            &self.profile.record.enrollment_ref,
            &self.profile.record.manifest_ref,
            session,
        )?;
        records.require_native_origin(&self.profile.source)?;
        let binding = native.native().binding();
        let _publication = binding.publication_lease()?;
        current().map_err(|_| crate::Error::Locked)?;
        records.check_current()?;
        if wholepact_authority::transport::certificate_digest(
            &wholepact_authority::CertificateDer::from(certificate),
        ) != self.enrollment.owner_certificate_digest
            || signer.scheme() != rustls::SignatureScheme::ECDSA_NISTP256_SHA256
        {
            return Err(crate::Error::Authentication);
        }
        let bytes = born_offline_enrollment_v1_owner_signing_bytes(&self.enrollment)
            .map_err(|_| crate::Error::InvalidData)?;
        let signature = signer.sign(&bytes).map_err(|_| crate::Error::Crypto)?;
        let envelope = BornOfflineEnrollmentOwnerSignatureV1 {
            version: 1,
            enrollment: self.enrollment,
            scheme: "ecdsa-p256-sha256-asn1-v1".into(),
            owner_certificate_der: certificate.to_vec(),
            signature,
        };
        verify_born_offline_enrollment_v1_owner_signature(
            &envelope,
            &actual.genesis().owner_certificate_digest,
        )
        .map_err(|_| crate::Error::Authentication)?;
        records.check_current()?;
        native.check_current()?;
        self.operation.check().map_err(|_| crate::Error::Locked)?;
        Ok(envelope)
    }
}
#[allow(clippy::too_many_arguments)]
fn require_exact(
    profile: &LiveNamedRecipientProfile,
    actual: &ConsumedBornNamedSourceV1,
    native: &PendingAccountNativeAuthority,
    session: &SignerConsentSession,
    client: &AuthorityClient,
    e: &BornOfflineEnrollmentV1,
    h: &ReconciledAuthorityHistory,
) -> crate::Result<()> {
    actual.check(native)?;
    profile.check_current(actual.journal(), session)?;
    if profile.source != native.native().binding() {
        return Err(crate::Error::ReviewMismatch);
    }
    let p = &profile.record;
    let born = p
        .born_profile
        .as_ref()
        .ok_or(crate::Error::ReviewMismatch)?;
    if born.genesis != *actual.genesis() || born.construction != *actual.construction() {
        return Err(crate::Error::ReviewMismatch);
    }
    let birth = h
        .pending_birth_commit()
        .ok_or(crate::Error::ReviewMismatch)?;
    e.validate_original_birth(birth)
        .map_err(|_| crate::Error::ReviewMismatch)?;
    let owner = e
        .owner_continuation
        .as_ref()
        .ok_or(crate::Error::ReviewMismatch)?;
    owner
        .validate_origin(e, actual.construction())
        .map_err(|_| crate::Error::ReviewMismatch)?;
    let original = actual.construction();
    let transport = h
        .construction_transport_history_v1()
        .map_err(|_| crate::Error::ReviewMismatch)?;
    let credential_id = original
        .transport_credential_id
        .as_ref()
        .ok_or(crate::Error::ReviewMismatch)?;
    let reservations: Vec<_> = transport
        .reservations
        .iter()
        .filter(|r| {
            r.original.request.construction.operation_id
                == original.reservation.request.construction.operation_id
        })
        .collect();
    let consumptions: Vec<_> = transport
        .consumptions
        .iter()
        .filter(|r| r.original.request.operation_id == original.consumed.request.operation_id)
        .collect();
    let credentials: Vec<_> = transport
        .credentials
        .iter()
        .filter(|r| r.credential_id() == credential_id)
        .collect();
    if reservations.len() != 1
        || consumptions.len() != 1
        || credentials.len() != 1
        || reservations[0].original != original.reservation
        || reservations[0].credential_id != *credential_id
        || consumptions[0].original != original.consumed
        || consumptions[0].credential_id != *credential_id
        || credentials[0].authorization().original_session != original.reservation.session
        || h.snapshot().transport_fences.as_ref().is_none_or(|f| {
            f.version != 1
                || !f
                    .fenced_session_ids
                    .contains(&original.reservation.session.session_id)
        })
        || !h.contains_head(&original.reservation.snapshot.head)
        || !h.contains_head(&original.consumed.snapshot.head)
    {
        return Err(crate::Error::ReviewMismatch);
    }
    let attempt = h
        .latest_manual_roster_attempt_v2(p.witness_enrollment_ref())
        .map_err(|_| crate::Error::ReviewMismatch)?;
    let admitted = attempt
        .admission
        .as_ref()
        .ok_or(crate::Error::ReviewMismatch)?;
    let terms = &original.extension.account_extension.terms;
    if h.disclosure() != &client.disclosure_descriptor()
        || h.snapshot().head != e.expected_head
        || h.snapshot().writer_status != WriterStatus::Active
        || h.snapshot().active_writer_session.as_ref() != Some(&original.reservation.session)
        || h.account_use_history().genesis() != Some(actual.genesis())
        || h.account_use_history().exclusion().is_some()
        || h.born_offline_enrollment_v1()
            .map_err(|_| crate::Error::ReviewMismatch)?
            .is_some()
        || h.manual_roster_enrollment_extension(p.witness_enrollment_ref())
            .map_err(|_| crate::Error::ReviewMismatch)?
            != Some(&original.extension)
        || e.manual_extension_digest
            != original
                .extension
                .digest()
                .map_err(|_| crate::Error::InvalidData)?
        || e.manual_attempt_digest != attempt.attempt_digest
        || e.manual_admission_digest
            != admitted
                .digest_for(&original.extension, attempt.continuation.as_ref())
                .map_err(|_| crate::Error::InvalidData)?
        || e.original_writer_session != original.reservation.session
        || e.policy.enrollment_ref != p.witness_enrollment_ref()
        || e.policy.witness_certificate_digest != p.witness_certificate_digest
        || e.policy.offline_signer_key_digest
            != named_recipient_records::transport_fingerprint(&p.transport_public_key)
        || e.policy.witness_transport_key_digest
            != named_recipient_records::transport_fingerprint(&p.witness_transport_public_key)
        || e.policy.return_recipient_key_digest
            != named_recipient_records::transport_fingerprint(&p.return_transport_public_key)
        || e.policy.expires_at_ms > terms.scope.expires_at_ms
        || e.policy.maximum_admission_lifetime_ms > terms.scope.maximum_permit_lifetime_ms
        || !matches!(&e.assurance,BornOfflineAssuranceV1::NamedVerifierOwnEffectsV1{owner_setup_digest} if owner_setup_digest==&p.original_setup_digest)
    {
        return Err(crate::Error::ReviewMismatch);
    }
    Ok(())
}
