//! Existing credential selection under exact original origin. No caller may
//! supply a substitute server/account/policy, history, approval, or session key.
use super::super::{
    NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{
    Error, Result,
    account::birth::enrollment::{PreparedBornManualPublication, RetainedBornManualEnrollment},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use wholepact_authority::manual_enrollment::BornManualEnrollmentAdmissionRequest;
use wholepact_authority::{
    AuthorityClient, CertificateDer, ClientTls, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use zeroize::Zeroizing;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    trusted_server_root_der: PathBuf,
    writer_certificate_der: PathBuf,
    writer_private_key_pkcs8_der: PathBuf,
    owner_certificate_der: PathBuf,
    owner_private_key_pkcs8_der: PathBuf,
    operator_name: String,
    retention_statement: String,
}
pub(super) struct PreparedManualWitnessSetup {
    retained: RetainedBornManualEnrollment,
    source: NativeAuthorityBinding,
    writer: AuthorityClient,
    owner: AuthorityClient,
    writer_pin: String,
    owner_pin: String,
    digest: String,
    display: Zeroizing<String>,
}
pub(in crate::native_ui) struct ApprovedManualWitnessSetup {
    source: NativeAuthorityBinding,
    account: String,
    writer: AuthorityClient,
    owner: AuthorityClient,
    writer_pin: String,
    owner_pin: String,
}
impl ApprovedManualWitnessSetup {
    pub(in crate::native_ui) fn into_parts(
        self,
    ) -> (
        NativeAuthorityBinding,
        String,
        AuthorityClient,
        AuthorityClient,
        String,
        String,
    ) {
        (
            self.source,
            self.account,
            self.writer,
            self.owner,
            self.writer_pin,
            self.owner_pin,
        )
    }
}
impl PreparedManualWitnessSetup {
    pub(super) fn prepare(
        retained: RetainedBornManualEnrollment,
        setup: &str,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        retained.check_current_source(owner)?;
        owner.native().binding().bounded_deadline()?;
        if setup.len() > 16 * 1024 {
            return Err(Error::InvalidData);
        }
        let setup: Setup = serde_json::from_str(setup).map_err(|_| Error::InvalidData)?;
        for text in [&setup.operator_name, &setup.retention_statement] {
            if text.is_empty()
                || text.len() > 2048
                || text.chars().any(|c| c.is_control() && c != '\n')
            {
                return Err(Error::InvalidData);
            }
        }
        let disclosure = retained.disclosure()?;
        let record = retained.record();
        let read = super::super::witness_workspace::read_private_credential;
        let root = read(&setup.trusted_server_root_der)?;
        let client =
            |certificate: &PathBuf, key: &PathBuf, expected: &str| -> Result<AuthorityClient> {
                let certificate = read(certificate)?;
                if hex::encode(Sha256::digest(&*certificate)) != expected {
                    return Err(Error::ReviewMismatch);
                }
                let key = read(key)?;
                let tls = ClientTls::new(
                    disclosure.server_name.clone(),
                    disclosure.pinned_server_certificate_digest.clone(),
                    vec![CertificateDer::from(root.to_vec())],
                    vec![CertificateDer::from(certificate.to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
                )
                .map_err(|_| Error::Authentication)?;
                AuthorityClient::new(
                    disclosure
                        .endpoint
                        .parse()
                        .map_err(|_| Error::InvalidData)?,
                    tls,
                    disclosure.witness_id.clone(),
                    disclosure.account_id.clone(),
                    disclosure.network_profile_id.clone(),
                    disclosure.policy_digest.clone(),
                )
                .map_err(|_| Error::InvalidData)
            };
        let writer_pin = record.terms.signer.writer_certificate_digest.clone();
        let owner_pin = record.terms.signer.owner_certificate_digest.clone();
        let writer = client(
            &setup.writer_certificate_der,
            &setup.writer_private_key_pkcs8_der,
            &writer_pin,
        )?;
        let owner_client = client(
            &setup.owner_certificate_der,
            &setup.owner_private_key_pkcs8_der,
            &owner_pin,
        )?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-born-manual-witness-selection:v1",
            &(
                &setup,
                &disclosure,
                record.reference()?,
                hex::encode(Sha256::digest(&*root)),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "CONTACT EXACT ORIGINAL WITNESS FOR MANUAL ENROLLMENT\n{}\n{}\n\n{}\n\nExisting credential selections:\n{}\n\nThis contacts only the immutable pinned witness using the original owner and writer identities. It discloses connection/certificate/account/policy metadata and retrieves complete history/extension state. Fresh writer acquisition, separate owner activation and local journal publication each require a later exact native decision. Original account-wide exposure, policy and exclusions remain unchanged. Credential selection does not establish current authority.\nExact review: {}",
            setup.operator_name,
            setup.retention_statement,
            serde_json::to_string_pretty(&disclosure).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&setup).map_err(|_| Error::InvalidData)?,
            digest
        ));
        retained.check_current_source(owner)?;
        Ok(Self {
            retained,
            source: owner.native().binding(),
            writer,
            owner: owner_client,
            writer_pin,
            owner_pin,
            digest,
            display,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<(Arc<NativeWitnessWorkspace>, Arc<NativeWitnessWorkspace>)> {
        self.retained.check_current_source(owner)?;
        self.source.check_current()?;
        if owner.native().binding() != self.source
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        let account = self.retained.record().terms.identity.account_id.clone();
        let approved = ApprovedManualWitnessSetup {
            source: self.source,
            account,
            writer: self.writer,
            owner: self.owner,
            writer_pin: self.writer_pin,
            owner_pin: self.owner_pin,
        };
        let (writer, owner) = NativeWitnessWorkspace::from_born_manual(approved);
        Ok((Arc::new(writer), Arc::new(owner)))
    }
}
/// Frozen complete-history request prepared BEFORE any remote durable admission.
pub(super) struct PreparedManualAdmission {
    retained: RetainedBornManualEnrollment,
    workspace: Arc<NativeWitnessWorkspace>,
    peer: crate::ipc::AuthenticatedPeer,
    history: wholepact_authority::ReconciledAuthorityHistory,
    request: BornManualEnrollmentAdmissionRequest,
    source: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
pub(super) struct ApprovedManualAdmission(PreparedManualAdmission);
impl PreparedManualAdmission {
    pub(super) fn prepare(
        retained: RetainedBornManualEnrollment,
        workspace: Arc<NativeWitnessWorkspace>,
        pairing: &crate::native_ui::AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        retained.check_current_source(owner)?;
        workspace.check_current()?;
        pairing.check_current()?;
        if workspace.disclosure() != retained.disclosure()?
            || pairing.native_origin() != &owner.native().binding()
        {
            return Err(Error::ReviewMismatch);
        }
        let history = workspace
            .client()
            .reconcile_history_checked(|| {
                owner
                    .check_current()
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        let active = workspace
            .client()
            .verify_active_session(&history)
            .map_err(|_| Error::Authentication)?;
        let extension = retained.record().extension()?;
        if history
            .manual_enrollment_extension(&extension.enrollment_ref)
            .map_err(|_| Error::ReviewMismatch)?
            != Some(&extension)
        {
            return Err(Error::ReviewMismatch);
        }
        let request = BornManualEnrollmentAdmissionRequest {
            version: 1,
            operation_id: extension
                .admission_operation_id()
                .map_err(|_| Error::InvalidData)?,
            account_id: history.snapshot().account_id.clone(),
            network_profile_id: history.snapshot().network_profile_id.clone(),
            extension_digest: extension.digest().map_err(|_| Error::InvalidData)?,
            enrollment_ref: retained.record().reference()?,
            writer_epoch: history.snapshot().writer_epoch,
            expected_head: history.snapshot().head.clone(),
            session_id: active.receipt().session_id.clone(),
        };
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-born-manual-witness-admission:v1",
            &(
                &request,
                &extension,
                pairing.binding(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "ADMIT ONE EXACT LOCAL MANUAL JOURNAL PUBLICATION AT THE ORIGINAL WITNESS\n\n{}\n\n{}\n\nThis appends the exact publication admission to independent witness history. It grants no transaction signing or financial permission. The request/head/session and operation below are frozen before first send. Only this same in-process request may retry after uncertainty; process loss/expiry does not authorize a new request. A later separate native review still controls local journal publication.\nExact review: {}",
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&extension).map_err(|_| Error::InvalidData)?,
            digest
        ));
        Ok(Self {
            retained,
            workspace,
            peer: pairing.current_peer(),
            history,
            request,
            source: owner.native().binding(),
            digest,
            display,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        self.peer.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ApprovedManualAdmission> {
        self.retained.check_current_source(owner)?;
        self.source.check_current()?;
        self.peer.check_current()?;
        if self.source != owner.native().binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedManualAdmission(self))
    }
}
impl ApprovedManualAdmission {
    pub(super) fn attempt(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedBornManualPublication> {
        let p = &self.0;
        p.retained.check_current_source(owner)?;
        p.source.check_current()?;
        p.peer.check_current()?;
        p.workspace.check_current()?;
        if p.source != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        let extension = p.retained.record().extension()?;
        let proof = p
            .workspace
            .client()
            .admit_born_manual_enrollment(&p.history, &extension, &p.request)
            .map_err(|_| Error::Uncertain)?;
        // Durable admission changes the head. Refresh COMPLETE history rather
        // than combining pre-admission history with the post-admission proof.
        let history = p
            .workspace
            .client()
            .reconcile_history_checked(|| {
                owner
                    .check_current()
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        if history.snapshot() != proof.snapshot() {
            return Err(Error::ReviewMismatch);
        }
        let retained = p.retained.reopen_exact(owner)?;
        let pairing =
            crate::native_ui::AuthenticatedPairing::from_authenticated_request(p.peer.clone())?;
        retained.prepare_publication(history, proof, &pairing, owner)
    }
}
