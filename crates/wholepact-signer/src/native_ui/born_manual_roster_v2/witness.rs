//! STAGED, UNCOMPILED. Typed roster V2 clients; no V1 authority conversion.
//! Existing credential selection under exact original origin. No caller may
//! supply a substitute server/account/policy, history, approval, or session key.
use super::super::{
    NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{
    Error, Result,
    account::birth::enrollment::roster_v2::{
        RetainedBornManualRosterEnrollmentV2, continuation,
        publication::PreparedBornManualRosterPublicationV2,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use wholepact_authority::manual_roster_witness_v2::{
    BornManualRosterAdmissionRequestV2, initial_manual_roster_attempt_digest_v2,
};
use wholepact_authority::{
    AuthorityClient, CertificateDer, ClientTls, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use wholepact_signer_origin::manual_roster_v2::{
    HostManualRosterPublicationRequestV2, ManualRosterPublicationAttemptV2,
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
    retained: RetainedBornManualRosterEnrollmentV2,
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
        retained: RetainedBornManualRosterEnrollmentV2,
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
        let writer_pin = record
            .account_record
            .terms
            .signer
            .writer_certificate_digest
            .clone();
        let owner_pin = record
            .account_record
            .terms
            .signer
            .owner_certificate_digest
            .clone();
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
            "wholepact:native-born-manual-roster-witness-selection:v2",
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
            "CONTACT EXACT ORIGINAL WITNESS FOR EXACT ROSTER V2 ENROLLMENT\n{}\n{}\n\n{}\n\nExisting credential selections:\n{}\n\nThis contacts only the immutable pinned witness using the original owner and writer identities. It discloses connection/certificate/account/policy metadata and retrieves complete history/extension state. Fresh writer acquisition, separate owner activation and local journal publication each require a later exact native decision. Original account-wide exposure, policy and exclusions remain unchanged. Credential selection does not establish current authority.\nExact review: {}",
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
        let account = self
            .retained
            .record()
            .account_record
            .terms
            .identity
            .account_id
            .clone();
        let approved = ApprovedManualWitnessSetup {
            source: self.source,
            account,
            writer: self.writer,
            owner: self.owner,
            writer_pin: self.writer_pin,
            owner_pin: self.owner_pin,
        };
        let (writer, owner) = NativeWitnessWorkspace::from_born_manual_roster_v2(approved);
        Ok((Arc::new(writer), Arc::new(owner)))
    }
}
/// A peer's current manifest is the full V2 publication request, including its
/// exact attempt. It is never the nested V1 request or the original-intent digest.
pub(super) fn require_publication_pairing(
    retained: &RetainedBornManualRosterEnrollmentV2,
    request: &HostManualRosterPublicationRequestV2,
    pairing: &crate::native_ui::AuthenticatedPairing,
    owner: &PendingAccountNativeAuthority,
) -> Result<()> {
    retained.check_current_source(owner)?;
    owner.native().binding().bounded_deadline()?;
    pairing.check_current()?;
    request
        .require_original(&retained.record().request()?)
        .map_err(|_| Error::ReviewMismatch)?;
    let peer = pairing.current_peer();
    let terms = &retained.record().account_record.terms;
    let now: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidData)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::InvalidData)?;
    if pairing.native_origin() != &owner.native().binding()
        || peer.scope.account_id != terms.identity.account_id
        || peer.scope.agreement_id != terms.scope.agreement_id
        || peer.scope.participant_id != terms.scope.participant_id
        || peer.scope.manifest_digest != request.digest().map_err(|_| Error::InvalidData)?
        || peer.scope.history_read
        || peer.scope.authorization_export
        || peer.scope.preconstruction_export
        || now < terms.issued_at_ms
        || now >= terms.scope.expires_at_ms
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

/// Frozen complete-history request prepared BEFORE any remote durable admission.
/// This owner keeps the complete V2 Host request and frozen witness mutation
/// across uncertain retries. Repreparing a different request is not a retry.
pub(super) struct PreparedManualAdmission {
    retained: RetainedBornManualRosterEnrollmentV2,
    workspace: Arc<NativeWitnessWorkspace>,
    peer: crate::ipc::AuthenticatedPeer,
    history: wholepact_authority::ReconciledAuthorityHistory,
    request: BornManualRosterAdmissionRequestV2,
    publication_request: HostManualRosterPublicationRequestV2,
    source: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
pub(super) struct ApprovedManualAdmission(PreparedManualAdmission);
impl PreparedManualAdmission {
    pub(super) fn prepare(
        retained: RetainedBornManualRosterEnrollmentV2,
        workspace: Arc<NativeWitnessWorkspace>,
        publication_request: HostManualRosterPublicationRequestV2,
        pairing: &crate::native_ui::AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        require_publication_pairing(&retained, &publication_request, pairing, owner)?;
        continuation::require_attempted_source(&retained, owner)?;
        workspace.check_native_source(&owner.native().binding())?;
        if workspace.disclosure() != retained.disclosure()?
            || workspace.writer_certificate_digest()
                != retained
                    .record()
                    .account_record
                    .terms
                    .signer
                    .writer_certificate_digest
            || !matches!(
                publication_request.attempt,
                ManualRosterPublicationAttemptV2::InitialV2 {}
            )
        {
            return Err(Error::ReviewMismatch);
        }
        let history = workspace
            .client()
            .reconcile_history_checked(|| {
                require_publication_pairing(&retained, &publication_request, pairing, owner)
                    .and_then(|()| workspace.check_native_source(&owner.native().binding()))
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        let active = workspace
            .client()
            .verify_active_session(&history)
            .map_err(|_| Error::Authentication)?;
        let extension = retained.record().extension()?;
        let observed = history
            .latest_manual_roster_attempt_v2(&extension.account_extension.enrollment_ref)
            .map_err(|_| Error::ReviewMismatch)?;
        let attempt_digest =
            initial_manual_roster_attempt_digest_v2(&extension).map_err(|_| Error::InvalidData)?;
        if history
            .manual_roster_enrollment_extension(&extension.account_extension.enrollment_ref)
            .map_err(|_| Error::ReviewMismatch)?
            != Some(&extension)
            || observed.continuation.is_some()
            || observed.sequence != 1
            || observed.attempt_digest != attempt_digest
            || observed.admission.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let request = BornManualRosterAdmissionRequestV2 {
            version: 2,
            operation_id: extension
                .admission_operation_id()
                .map_err(|_| Error::InvalidData)?,
            account_id: history.snapshot().account_id.clone(),
            network_profile_id: history.snapshot().network_profile_id.clone(),
            extension_digest: extension.digest().map_err(|_| Error::InvalidData)?,
            // The account witness indexes its immutable INNER enrollment ref;
            // extension_digest above commits to the entire V2 roster wrapper.
            enrollment_ref: extension.account_extension.enrollment_ref.clone(),
            writer_epoch: history.snapshot().writer_epoch,
            expected_head: history.snapshot().head.clone(),
            session_id: active.receipt().session_id.clone(),
            attempt_digest,
            attempt_sequence: 1,
        };
        request
            .validate_for(&extension, None)
            .map_err(|_| Error::ReviewMismatch)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-born-manual-roster-witness-admission:v2",
            &(
                &request,
                &publication_request,
                &extension,
                history.history_digest().map_err(|_| Error::InvalidData)?,
                pairing.binding(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "ADMIT ONE EXACT ROSTER V2 LOCAL JOURNAL PUBLICATION AT THE ORIGINAL WITNESS\n\nHost publication request:\n{}\n\nFrozen witness admission:\n{}\n\nExact original roster extension:\n{}\n\nThis appends the exact publication admission to independent witness history. It grants no transaction signing or financial permission. The full V2 Host request, exact roster extension, head, session and operation are frozen before first send. Only this same in-process request may retry after uncertainty; process loss or expiry cannot create a replacement request. Host roster ancestry and this account's first witness attempt are separate. A later separate native review controls local journal publication.\nExact review: {}",
            serde_json::to_string_pretty(&publication_request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&extension).map_err(|_| Error::InvalidData)?,
            digest
        ));
        require_publication_pairing(&retained, &publication_request, pairing, owner)?;
        Ok(Self {
            retained,
            workspace,
            peer: pairing.current_peer(),
            history,
            request,
            publication_request,
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
        self.workspace.check_native_source(&self.source)?;
        Ok(self.display.to_string())
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.source.check_current()?;
        self.peer.check_current()?;
        self.workspace.check_native_source(&self.source)?;
        if self.source != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        let pairing =
            crate::native_ui::AuthenticatedPairing::from_authenticated_request(self.peer.clone())?;
        require_publication_pairing(&self.retained, &self.publication_request, &pairing, owner)?;
        continuation::require_attempted_source(&self.retained, owner)?;
        self.request
            .validate_for(&self.retained.record().extension()?, None)
            .map_err(|_| Error::ReviewMismatch)
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ApprovedManualAdmission> {
        self.check(owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedManualAdmission(self))
    }
}
impl ApprovedManualAdmission {
    pub(super) fn attempt(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedBornManualRosterPublicationV2> {
        let p = &self.0;
        p.check(owner)?;
        let extension = p.retained.record().extension()?;
        let proof = p
            .workspace
            .client()
            .admit_born_manual_roster_enrollment_v2(&p.history, &extension, None, &p.request)
            .map_err(|_| Error::Uncertain)?;
        // Durable admission changes the head. Refresh COMPLETE history rather
        // than combining pre-admission history with the post-admission proof.
        let history = p
            .workspace
            .client()
            .reconcile_history_checked(|| {
                p.check(owner)
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        p.check(owner)?;
        proof.check_current().map_err(|_| Error::ReviewMismatch)?;
        if history.snapshot() != proof.snapshot() {
            return Err(Error::ReviewMismatch);
        }
        let retained = p.retained.reopen_exact(owner)?;
        let pairing =
            crate::native_ui::AuthenticatedPairing::from_authenticated_request(p.peer.clone())?;
        PreparedBornManualRosterPublicationV2::prepare(
            retained,
            history,
            proof,
            p.publication_request.clone(),
            &pairing,
            owner,
        )
    }
}
