//! Genuine native review producers for one-way routine-use exclusion. Complete
//! witness reads, local restriction, existing-owner signing and file disclosure
//! each consume a separate final native decision. No account key is used here.
use super::super::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority};
use crate::account::birth::enrollment::roster_v2::permanent_stop::{
    BornPermanentStopSourceV1, PreparedBornPermanentStopV1,
};
use crate::{Error, Result};
use rustls::{sign::Signer, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use wholepact_authority::permanent_exclusion_signature::{
    permanent_exclusion_owner_signing_bytes_v1, verify_permanent_exclusion_owner_signature_v1,
    PermanentExclusionOwnerSignatureV1,
};
use wholepact_authority::{
    AuthorityClient, CertificateDer, ClientTls, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessSelection {
    operator_name: String,
    retention_statement: String,
    trusted_server_root_der: PathBuf,
    owner_certificate_der: PathBuf,
    owner_private_key_pkcs8_der: PathBuf,
}
pub(super) struct PreparedPermanentStopReadV1 {
    source: BornPermanentStopSourceV1,
    client: AuthorityClient,
    native: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
pub(super) enum ReadOutcome {
    LocalReview(Box<PreparedBornPermanentStopV1>),
    Stopped(Box<BornPermanentStopSourceV1>),
}
impl PreparedPermanentStopReadV1 {
    pub(super) fn prepare(
        source: BornPermanentStopSourceV1,
        text: &str,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.check(owner)?;
        if text.is_empty() || text.len() > 16 * 1024 {
            return Err(Error::InvalidData);
        }
        let selection: WitnessSelection =
            serde_json::from_str(text).map_err(|_| Error::InvalidData)?;
        for value in [&selection.operator_name, &selection.retention_statement] {
            if value.is_empty()
                || value.len() > 2048
                || value.chars().any(|c| c.is_control() && c != '\n')
            {
                return Err(Error::InvalidData);
            }
        }
        let disclosure = source.disclosure()?;
        let read = super::super::witness_workspace::read_private_credential;
        let root = read(&selection.trusted_server_root_der)?;
        let certificate = read(&selection.owner_certificate_der)?;
        let actual_pin = wholepact_authority::transport::certificate_digest(&CertificateDer::from(
            certificate.as_slice(),
        ));
        if actual_pin != source.genesis().owner_certificate_digest {
            return Err(Error::Authentication);
        }
        let key = read(&selection.owner_private_key_pkcs8_der)?;
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
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-permanent-stop-witness-read:v1",
            &(
                &selection,
                &disclosure,
                source.record(),
                source.snapshot()?,
                owner.native().principal_id(),
                owner.native().measurement(),
                hex::encode(crate::vault::random::<32>()?),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!("READ COMPLETE ORIGINAL WITNESS HISTORY FOR PERMANENT STOP OF ROUTINE REUSE\n\n{}\n{}\n\nThis independently approves a read-only authenticated connection using the selected existing original owner credential. It reveals certificate, account and policy connection metadata to this exact pinned witness. Full bounded history and all local financial, offline, construction and transport origins are checked without dropping pending exposure. It neither acquires nor activates a writer.\nIf the exact local exclusion already exists, this read may durably retain only its original witnessed acknowledgment. A missing witness exclusion remains pending; no replacement operation is minted. No account emptiness or funds recovery is claimed.\nExact review: {}", serde_json::to_string_pretty(&selection).map_err(|_| Error::InvalidData)?, serde_json::to_string_pretty(&disclosure).map_err(|_| Error::InvalidData)?, digest));
        Ok(Self {
            source,
            client,
            native: owner.native().binding(),
            digest,
            display,
        })
    }
    pub(super) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn review_json(&self) -> Result<String> {
        self.native.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve_and_read(
        mut self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ReadOutcome> {
        self.source.check(owner)?;
        if self.native != owner.native().binding()
            || decision.binding() != &self.native
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        {
            let _admit = self.native.publication_lease()?;
            self.source.check(owner)?;
        }
        let history = self
            .client
            .reconcile_history_checked(|| {
                self.source
                    .check(owner)
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        self.source.check(owner)?;
        if self.source.snapshot()?.exclusion.is_some()
            && history.account_use_history().exclusion().is_some()
        {
            self.source.accept_witness_history(&history, owner)?;
        }
        self.source.observe_history(history, owner)?;
        if self.source.snapshot()?.exclusion.is_some() {
            Ok(ReadOutcome::Stopped(Box::new(self.source)))
        } else {
            Ok(ReadOutcome::LocalReview(Box::new(
                PreparedBornPermanentStopV1::prepare(self.source, owner)?,
            )))
        }
    }
}

pub(super) struct PreparedPermanentStopSignatureV1 {
    source: BornPermanentStopSourceV1,
    signer: Option<Box<dyn Signer>>,
    original: Option<PermanentExclusionOwnerSignatureV1>,
    certificate: Vec<u8>,
    native: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedPermanentStopSignatureV1 {
    pub(super) fn prepare(
        source: BornPermanentStopSourceV1,
        certificate_path: &Path,
        key_path: &Path,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.check(owner)?;
        let exclusion = source.exclusion()?;
        let original = source.retained_signature()?;
        let (signer, certificate) = if original.is_some() {
            (None, Vec::new())
        } else {
            let read = super::super::witness_workspace::read_private_credential;
            let certificate = read(certificate_path)?;
            let pin = wholepact_authority::transport::certificate_digest(&CertificateDer::from(
                certificate.as_slice(),
            ));
            if pin != source.genesis().owner_certificate_digest {
                return Err(Error::Authentication);
            }
            let key = read(key_path)?;
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));
            let signing = rustls::crypto::ring::sign::any_supported_type(&key)
                .map_err(|_| Error::InvalidData)?;
            let signer = signing
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .ok_or(Error::Unavailable)?;
            (Some(signer), certificate.to_vec())
        };
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-permanent-stop-existing-owner-signature:v1",
            &(
                source.genesis(),
                &exclusion,
                certificate_path,
                key_path,
                original.is_some(),
                owner.native().principal_id(),
                owner.native().measurement(),
                hex::encode(crate::vault::random::<32>()?),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!("SIGN OR RETAIN THE EXACT ORIGINAL PERMANENT EXCLUSION\n\n{}\nOwner certificate file: {}\nExisting private credential file: {}\nOriginal signature already retained: {}\n\nThe local tombstone already exists. This authorizes only the existing owner credential to authenticate that exact tombstone to the original witness owner. The first signed bytes are encrypted and retained before any export; retry never creates a replacement signature. No account spend key is used and no data is exported by this step. Independent witness-native review remains required.\nExact review: {}", serde_json::to_string_pretty(&exclusion).map_err(|_| Error::InvalidData)?, certificate_path.display(), key_path.display(), original.is_some(), digest));
        Ok(Self {
            source,
            signer,
            original,
            certificate,
            native: owner.native().binding(),
            digest,
            display,
        })
    }
    pub(super) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn review_json(&self) -> Result<String> {
        self.native.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve_and_sign(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<BornPermanentStopSourceV1> {
        self.source.check(owner)?;
        if self.native != owner.native().binding()
            || decision.binding() != &self.native
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        let _admitted = self.native.publication_lease()?;
        let envelope = match self.original {
            Some(original) => original,
            None => {
                let bytes = permanent_exclusion_owner_signing_bytes_v1(
                    self.source.genesis(),
                    &self.source.exclusion()?,
                )
                .map_err(|_| Error::InvalidData)?;
                PermanentExclusionOwnerSignatureV1 {
                    version: 1,
                    genesis: self.source.genesis().clone(),
                    exclusion: self.source.exclusion()?,
                    scheme: "ecdsa-p256-sha256-asn1-v1".into(),
                    owner_certificate_der: self.certificate,
                    signature: self
                        .signer
                        .ok_or(Error::Unavailable)?
                        .sign(&bytes)
                        .map_err(|_| Error::Crypto)?,
                }
            }
        };
        verify_permanent_exclusion_owner_signature_v1(
            &envelope,
            &self.source.genesis().owner_certificate_digest,
        )
        .map_err(|_| Error::Authentication)?;
        drop(_admitted);
        self.source.retain_signature(&envelope, owner)?;
        Ok(self.source)
    }
}
