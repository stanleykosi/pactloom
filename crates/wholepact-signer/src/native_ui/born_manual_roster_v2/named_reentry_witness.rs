//! Fresh purpose-bound selection of the EXISTING original owner credentials.
//! Preparation reads local protected files; only a separate exact native
//! decision permits later witness contact. The old general writer stays fenced.
use super::{
    common_context_handoff::PinnedOwnerSigner, named_continuation::ConsumedBornNamedOwnerV1,
};
use crate::{
    Error, Result,
    account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::ConsumedBornNamedSourceV1,
    native_ui::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use wholepact_authority::{
    AuthorityClient, CertificateDer, ClientTls, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use zeroize::Zeroizing;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    trusted_server_root_der: PathBuf,
    owner_certificate_der: PathBuf,
    owner_private_key_pkcs8_der: PathBuf,
    operator_name: String,
    retention_statement: String,
}

pub(super) struct PreparedNamedWitnessV1 {
    source: ConsumedBornNamedSourceV1,
    client: AuthorityClient,
    signer: PinnedOwnerSigner,
    native: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedNamedWitnessV1 {
    pub(super) fn prepare(
        source: ConsumedBornNamedSourceV1,
        setup_json: &str,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.check(owner)?;
        if setup_json.len() > 16 * 1024 {
            return Err(Error::InvalidData);
        }
        let setup: Setup = serde_json::from_str(setup_json).map_err(|_| Error::InvalidData)?;
        for text in [&setup.operator_name, &setup.retention_statement] {
            if text.is_empty()
                || text.len() > 2048
                || text.chars().any(|c| c.is_control() && c != '\n')
            {
                return Err(Error::InvalidData);
            }
        }
        let disclosure = source.original_witness_disclosure(owner)?;
        let read = crate::native_ui::witness_workspace::read_private_credential;
        let root = read(&setup.trusted_server_root_der)?;
        let certificate = read(&setup.owner_certificate_der)?;
        if wholepact_authority::transport::certificate_digest(&CertificateDer::from(
            certificate.as_slice(),
        )) != source.genesis().owner_certificate_digest
        {
            return Err(Error::Authentication);
        }
        let private_key = read(&setup.owner_private_key_pkcs8_der)?;
        let tls = ClientTls::new(
            disclosure.server_name.clone(),
            disclosure.pinned_server_certificate_digest.clone(),
            vec![CertificateDer::from(root.to_vec())],
            vec![CertificateDer::from(certificate.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key.to_vec())),
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
        let signer = PinnedOwnerSigner::open(
            &source.genesis().owner_certificate_digest,
            &setup.owner_certificate_der,
            &setup.owner_private_key_pkcs8_der,
        )?;
        let native = owner.native().binding();
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-consumed-born-named-witness-selection:v1",
            &(
                &setup,
                &disclosure,
                source.genesis(),
                source.construction(),
                native.entry_digest(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "SELECT EXISTING ORIGINAL OWNER CREDENTIALS FOR EXACT BORN PAYMENT\n{}\n{}\nOriginal consumed construction digest: {}\n\nThis fresh native decision permits contact only with the immutable pinned witness as the original owner. It restores neither the permanently fenced general writer nor a writer session. Original construction, account policy, session and financial deadlines remain unchanged. Separate exact local pairing, profile, original-history, final-signing and dispatch decisions remain mandatory. Existing Started, signed return, dispatch and uncertain exposure records cannot be reset.\nExact review: {}",
            serde_json::to_string_pretty(&disclosure).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&setup).map_err(|_| Error::InvalidData)?,
            source
                .construction()
                .digest()
                .map_err(|_| Error::InvalidData)?,
            digest,
        ));
        source.check(owner)?;
        Ok(Self {
            source,
            client,
            signer,
            native,
            digest,
            display,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.native.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ConsumedBornNamedOwnerV1> {
        self.source.check(owner)?;
        if owner.native().binding() != self.native
            || decision.binding() != &self.native
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        // Actual source and actual original TLS/signer objects are moved, never
        // reconstructed from caller assurances or a deserialized capability.
        ConsumedBornNamedOwnerV1::from_consumed(self.source, self.client, self.signer, owner)
    }
}
