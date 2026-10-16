//! Prepare credentials locally, then disclose only to the immutable original
//! pinned witness after separate genuine native approval. JSON supplies paths
//! and descriptive labels only; it cannot supply authenticated witness history.
use super::super::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority};
use crate::{
    Error, Result,
    account::birth::{
        PendingBirthVault, PreparedPendingBirthAcknowledgement,
        request::RetainedPendingOwnerRequest,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use wholepact_authority::{
    AuthorityClient, CertificateDer, ClientTls, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use zeroize::Zeroizing;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HistorySetup {
    trusted_server_root_der: PathBuf,
    owner_certificate_der: PathBuf,
    owner_private_key_pkcs8_der: PathBuf,
    operator_name: String,
    retention_statement: String,
}
pub(super) struct PreparedHistoryRead {
    pending: Arc<PendingBirthVault>,
    retained: RetainedPendingOwnerRequest,
    source: NativeAuthorityBinding,
    client: AuthorityClient,
    digest: String,
    display: Zeroizing<String>,
    started: Instant,
}
impl PreparedHistoryRead {
    pub(super) fn prepare(
        pending: Arc<PendingBirthVault>,
        setup: &str,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        if setup.len() > 16 * 1024 {
            return Err(Error::InvalidData);
        }
        let setup: HistorySetup = serde_json::from_str(setup).map_err(|_| Error::InvalidData)?;
        for label in [&setup.operator_name, &setup.retention_statement] {
            if label.is_empty() || label.len() > 2048 {
                return Err(Error::InvalidData);
            }
        }
        let retained = pending
            .retained_owner_request()?
            .ok_or(Error::RecoveryRequired)?;
        retained.recheck_for_acknowledgement()?;
        let disclosure = &retained.request().disclosure;
        let read = super::super::witness_workspace::read_private_credential;
        let root = read(&setup.trusted_server_root_der)?;
        let certificate = read(&setup.owner_certificate_der)?;
        let key = read(&setup.owner_private_key_pkcs8_der)?;
        let certificate_digest = hex::encode(Sha256::digest(&*certificate));
        if certificate_digest != retained.request().policy.owner_certificate_digest {
            return Err(Error::ReviewMismatch);
        }
        let root_digest = hex::encode(Sha256::digest(&*root));
        let tls = ClientTls::new(
            disclosure.server_name.clone(),
            disclosure.pinned_server_certificate_digest.clone(),
            vec![CertificateDer::from(root.to_vec())],
            vec![CertificateDer::from(certificate.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .map_err(|_| Error::Authentication)?;
        let client = AuthorityClient::new(
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
        .map_err(|_| Error::InvalidData)?;
        if client.disclosure_descriptor() != *disclosure {
            return Err(Error::ReviewMismatch);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-pending-history-disclosure:v1",
            &(
                &setup,
                &root_digest,
                &certificate_digest,
                retained
                    .request()
                    .digest()
                    .map_err(|_| Error::InvalidData)?,
                disclosure,
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "READ AUTHENTICATED ORIGINAL WITNESS HISTORY\nOperator and retention statement are owner-entered, not independently verified:\n{}\n{}\n\nImmutable destination and public account binding:\n{}\n\nExact credential file selection:\n{}\nTrusted root fingerprint: {root_digest}\nSelected existing owner certificate: {certificate_digest}\n\nThis contacts only the original pinned witness over mutually authenticated TLS. It discloses your connection metadata, owner certificate and exact account/network/policy binding, and requests the complete witness history and original enrollment commit. No seed, spending key, raw FVK, PCZT or local vault password is sent. The existing credential proves possession only. No journal creation, writer activation, reservation, budget change or spending operation is requested. Fetching is not acknowledgement: a separate exact native review must approve local retention of the authenticated birth record. Expired requests remain audit-only; their original deadline is never renewed.",
            setup.operator_name,
            setup.retention_statement,
            serde_json::to_string_pretty(disclosure).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&setup).map_err(|_| Error::InvalidData)?
        ));
        Ok(Self {
            pending,
            retained,
            source: owner.native().binding(),
            client,
            digest,
            display,
            started: Instant::now(),
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        self.source.check_current()?;
        self.retained.recheck_for_acknowledgement()?;
        if self.source != owner.native().binding()
            || self.started.elapsed() >= Duration::from_secs(120)
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn fetch(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedPendingBirthAcknowledgement> {
        self.check(owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        // No GUI lock or publication lease is held during bounded client I/O.
        // A disclosure already sent cannot be recalled; loss of native ownership
        // discards its result and prevents the separate acknowledgement commit.
        let history = self
            .client
            .reconcile_history_checked(|| {
                self.check(owner)
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        self.check(owner)?;
        if history.disclosure() != &self.retained.request().disclosure {
            return Err(Error::ReviewMismatch);
        }
        PreparedPendingBirthAcknowledgement::prepare(self.pending, history, owner)
    }
}

#[cfg(test)]
pub(super) fn parse_setup_for_test(input: &str) -> Result<()> {
    serde_json::from_str::<HistorySetup>(input)
        .map(|_| ())
        .map_err(|_| Error::InvalidData)
}
