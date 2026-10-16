//! Native exact-plan original-owner signature review and one-use producer.
//! Source foundation: signer native-ui module. Existing owner credential signing is
//! reachable only after real pending native review. Results remain private until
//! the separate exact destination disclosure consumes its own native decision.
//! This does not attest fresh-key generation to the witness.
use super::super::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority};
use crate::account::birth::enrollment::roster_v2::RetainedBornManualRosterEnrollmentV2;
use crate::{Error, Result};
use rustls::{SignatureScheme, sign::Signer};
use std::{
    path::Path,
    time::{Duration, Instant},
};
use wholepact_authority::manual_roster_construction_signature_v2::{
    ManualRosterConstructionOwnerSignatureV2, verify_manual_roster_construction_owner_signature_v2,
};
use wholepact_authority::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zeroize::Zeroizing;

pub(super) struct PreparedRosterConstructionOwnerSignatureV2 {
    retained: RetainedBornManualRosterEnrollmentV2,
    approval:
        wholepact_authority::manual_roster_construction_v2::ManualRosterConstructionApprovalV2,
    source: NativeAuthorityBinding,
    signer: Box<dyn Signer>,
    certificate: Vec<u8>,
    digest: String,
    display: Zeroizing<String>,
    created: Instant,
}
impl PreparedRosterConstructionOwnerSignatureV2 {
    pub(super) fn prepare(
        retained: RetainedBornManualRosterEnrollmentV2,
        owner: &PendingAccountNativeAuthority,
        certificate_path: &Path,
        existing_key_path: &Path,
        plan_path: &Path,
    ) -> Result<Self> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        retained.check_current_source(owner)?;
        let plan = read_plan(plan_path)?;
        crate::account::birth::enrollment::roster_v2::retention::read_exact(
            &retained,
            &plan.retained,
            &plan.retained_evidence_digest,
        )?;
        let now = now_ms()?;
        let approval=wholepact_authority::manual_roster_construction_v2::ManualRosterConstructionApprovalV2{
            version:2,extension_digest:retained.record().extension()?.digest().map_err(|_|Error::InvalidData)?,
            initial_commit_deadline_ms:now.checked_add(120_000).ok_or(Error::InvalidData)?.min(plan.completion_expires_at_ms()),
            issued_at_ms:now,plan,
        };
        approval
            .validate_for(&retained.record().extension()?)
            .map_err(|_| Error::ReviewMismatch)?;
        let certificate =
            super::super::witness_workspace::read_private_credential(certificate_path)?;
        let certificate_digest = wholepact_authority::transport::certificate_digest(
            &CertificateDer::from(certificate.as_slice()),
        );
        if certificate_digest
            != retained
                .record()
                .account_record
                .terms
                .signer
                .owner_certificate_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let key = super::super::witness_workspace::read_private_credential(existing_key_path)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));
        let signing_key =
            rustls::crypto::ring::sign::any_supported_type(&key).map_err(|_| Error::InvalidData)?;
        let signer = signing_key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .ok_or(Error::Unavailable)?;
        let source = owner.native().binding();
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-manual-roster-construction-owner-signature:v2",
            &(
                retained
                    .record()
                    .extension()?
                    .digest()
                    .map_err(|_| Error::InvalidData)?,
                &approval,
                plan_path,
                &certificate_digest,
                certificate_path,
                existing_key_path,
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let request_text =
            serde_json::to_string_pretty(&approval).map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "Approve this exact full-proposal construction plan with the selected existing owner credential.\n\nOwner certificate: {certificate_digest}\nCertificate file: {}\nExisting private credential file: {}\n\n{request_text}\n\nThis authenticates owner approval of these immutable full-proposal terms to the independently selected local witness owner. It fixes actual selected inputs, nullifiers, return, all recipient amounts and participant commitments. Cancellation stops NEW admission; admitted credential use may finish after focus changes, and disclosed data cannot be recalled. It never changes the original invocation deadline. A saved signed approval is not signing or dispatch authority. It does not prove that this key or account is fresh, create a witness journal, authorize spending, clear old exposure, or export this request. Independent native witness-owner review and create-once checks remain required. The original policy, account budget and all exposure remain unchanged.",
            certificate_path.display(),
            existing_key_path.display()
        ));
        Ok(Self {
            retained,
            approval,
            source,
            signer,
            certificate: certificate.to_vec(),
            digest,
            display,
            created: Instant::now(),
        })
    }
    pub(super) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.source.check_current()?;
        if owner.native().binding() != self.source
            || self.created.elapsed() >= Duration::from_secs(120)
        {
            return Err(Error::ReviewMismatch);
        }
        self.retained.check_current_source(owner)?;
        if now_ms()? < self.approval.issued_at_ms
            || now_ms()? >= self.approval.initial_commit_deadline_ms
        {
            return Err(Error::ReviewMismatch);
        }
        if now_ms()?
            >= self
                .retained
                .record()
                .account_record
                .terms
                .scope
                .expires_at_ms
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    /// Result stays inside the native workspace; a separate exact destination
    /// disclosure is required before any export/transmission. One-shot self use.
    pub(super) fn approve_and_sign(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ManualRosterConstructionOwnerSignatureV2> {
        self.check(owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let _lease = self.source.publication_lease()?;
        self.check(owner)?;
        let bytes =
            wholepact_authority::manual_roster_construction_signature_v2::manual_roster_construction_owner_signing_bytes_v2(
                &self.retained.record().extension()?,
                &self.approval,
            )
            .map_err(|_| Error::InvalidData)?;
        let signature = self.signer.sign(&bytes).map_err(|_| Error::Crypto)?;
        let envelope = ManualRosterConstructionOwnerSignatureV2 {
            version: 2,
            extension: self.retained.record().extension()?,
            approval: self.approval.clone(),
            scheme: "ecdsa-p256-sha256-asn1-v1".into(),
            owner_certificate_der: self.certificate.clone(),
            signature,
        };
        // Maintained verification proves selected private key matches the pinned
        // certificate and exact approved message before any result leaves scope.
        verify_manual_roster_construction_owner_signature_v2(
            &envelope,
            &self
                .retained
                .record()
                .account_record
                .terms
                .signer
                .owner_certificate_digest,
        )
        .map_err(|_| Error::Authentication)?;
        self.check(owner)?;
        Ok(envelope)
    }
}
fn now_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidData)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::InvalidData)
}

fn read_plan(
    path: &Path,
) -> Result<wholepact_core::manual_roster_construction_v2::ManualRosterConstructionPlanV2> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    if !path.is_absolute() || std::fs::canonicalize(path)? != path {
        return Err(Error::InvalidData);
    }
    let parent = std::fs::symlink_metadata(path.parent().ok_or(Error::InvalidData)?)?;
    let uid = unsafe { libc::geteuid() };
    if !parent.is_dir() || parent.uid() != uid || parent.mode() & 0o077 != 0 {
        return Err(Error::InvalidData);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != uid
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > 512 * 1024
    {
        return Err(Error::InvalidData);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(512 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 512 * 1024 {
        return Err(Error::InvalidData);
    }
    let plan: wholepact_core::manual_roster_construction_v2::ManualRosterConstructionPlanV2 =
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidData)?;
    plan.validate().map_err(|_| Error::InvalidData)?;
    Ok(plan)
}
