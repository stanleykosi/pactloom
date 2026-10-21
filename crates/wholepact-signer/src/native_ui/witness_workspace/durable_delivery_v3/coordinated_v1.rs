//! Exact inert owner selection for coordinated V3 PrepareRead. No private key,
//! TLS client, socket or positive read/action authority exists in this value.
//! The private-key pathname is retained unchanged, never opened during prepare.
use super::*;
use std::time::Duration;

pub(in crate::native_ui) struct PreparedCoordinatedDeliveryWitnessV1 {
    setup: WitnessSetup,
    setup_json: String,
    root: Zeroizing<Vec<u8>>,
    certificate: Zeroizing<Vec<u8>>,
    root_digest: String,
    certificate_digest: String,
    disclosure: WitnessDisclosureDescriptor,
    source_identity: String,
    selection_digest: String,
    display: String,
    original_source_deadline: Instant,
    original_channel_deadline: Instant,
    original_material_deadline: Instant,
    original_service_deadline: Instant,
    original_read_deadline: Instant,
}

fn require_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::InvalidData);
    }
    Ok(())
}

impl PreparedCoordinatedDeliveryWitnessV1 {
    /// All arguments are ordinary exact selection data. The actual source and
    /// original Host must be checked separately by the genuine Read issuer.
    /// This method can select only public certificate bytes and fixed paths.
    pub(in crate::native_ui) fn prepare(
        json: &str,
        disclosure: &WitnessDisclosureDescriptor,
        owner_certificate_digest: &str,
        source_identity: &str,
        original_source_deadline: Instant,
        original_channel_deadline: Instant,
        original_material_deadline: Instant,
    ) -> Result<Self> {
        let now = Instant::now();
        let original_service_deadline = original_source_deadline.min(original_channel_deadline);
        if now >= original_service_deadline
            || now >= original_material_deadline
            || original_material_deadline > original_service_deadline
        {
            return Err(Error::Locked);
        }
        if json.len() > MAX_CONFIG {
            return Err(Error::InvalidData);
        }
        require_digest(owner_certificate_digest)?;
        require_digest(source_identity)?;
        disclosure.validate().map_err(|_| Error::InvalidData)?;
        // Freeze once before public I/O; no later approval renews this bound.
        let original_read_deadline = original_service_deadline
            .min(original_material_deadline)
            .min(
                now.checked_add(Duration::from_secs(120))
                    .ok_or(Error::Locked)?,
            );
        let setup: WitnessSetup = serde_json::from_str(json).map_err(|_| Error::InvalidData)?;
        if setup.schema_version != 1 {
            return Err(Error::InvalidData);
        }
        for text in [&setup.operator_name, &setup.retention_statement] {
            if text.is_empty()
                || text.len() > 2048
                || text.chars().any(|c| c.is_control() && c != '\n')
            {
                return Err(Error::InvalidData);
            }
        }
        let selected = WitnessDisclosureDescriptor {
            endpoint: setup.endpoint.to_string(),
            server_name: setup.server_name.clone(),
            witness_id: setup.witness_id.clone(),
            account_id: setup.account_id.clone(),
            network_profile_id: setup.network_profile_id.clone(),
            policy_digest: setup.policy_digest.clone(),
            pinned_server_certificate_digest: setup.pinned_server_certificate_digest.clone(),
        };
        selected.validate().map_err(|_| Error::InvalidData)?;
        if &selected != disclosure {
            return Err(Error::Authentication);
        }
        // Public certificates only. In particular, do not call the legacy
        // prepare_selected_witness_configuration: it also opens the key.
        let root = read_private_credential(&setup.trusted_server_root_der)?;
        if Instant::now() >= original_read_deadline {
            return Err(Error::Locked);
        }
        let certificate = read_private_credential(&setup.client_certificate_der)?;
        if Instant::now() >= original_read_deadline {
            return Err(Error::Locked);
        }
        let certificate_digest = hex::encode(Sha256::digest(&*certificate));
        let root_digest = hex::encode(Sha256::digest(&*root));
        if certificate_digest != owner_certificate_digest {
            return Err(Error::Authentication);
        }
        // Same maintained inert selection preimage as the original owner
        // reader. Its historical domain name is not a native grant assertion.
        let selection_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-witness-setup:v1",
            &(&setup, &certificate_digest, &root_digest, &selected),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = serde_json::to_string_pretty(&serde_json::json!({
            "purpose": "coordinated-v3-prepare-read-owner-selection",
            "source_identity_digest": source_identity,
            "selected_owner_configuration": setup,
            "disclosure": selected,
            "client_certificate_digest": certificate_digest,
            "trusted_root_digest": root_digest,
            "owner_selection_digest": selection_digest,
            "private_key_notice": "Only public certificates have been selected. The exact selected private key may be opened only under a genuine separate PrepareRead Final. This selection authorizes no history read, Receive, Admit, Audit or financial action."
        })).map_err(|_| Error::InvalidData)?;
        let result = Self {
            setup,
            setup_json: json.to_owned(),
            root,
            certificate,
            root_digest,
            certificate_digest,
            disclosure: selected,
            source_identity: source_identity.into(),
            selection_digest,
            display,
            original_source_deadline,
            original_channel_deadline,
            original_material_deadline,
            original_service_deadline,
            original_read_deadline,
        };
        result.check_selection()?;
        Ok(result)
    }

    /// Ordinary review metadata only, never permission to use a credential.
    pub(in crate::native_ui) fn selection_digest(&self) -> &str {
        &self.selection_digest
    }
    pub(in crate::native_ui) fn display(&self) -> &str {
        &self.display
    }
    pub(in crate::native_ui) fn source_identity(&self) -> &str {
        &self.source_identity
    }
    pub(in crate::native_ui) fn disclosure(&self) -> &WitnessDisclosureDescriptor {
        &self.disclosure
    }
    pub(in crate::native_ui) fn certificate_digest(&self) -> &str {
        &self.certificate_digest
    }
    pub(in crate::native_ui) fn original_source_deadline(&self) -> Instant {
        self.original_source_deadline
    }
    pub(in crate::native_ui) fn original_channel_deadline(&self) -> Instant {
        self.original_channel_deadline
    }
    pub(in crate::native_ui) fn original_material_deadline(&self) -> Instant {
        self.original_material_deadline
    }
    pub(in crate::native_ui) fn original_service_deadline(&self) -> Instant {
        self.original_service_deadline
    }
    pub(in crate::native_ui) fn original_read_deadline(&self) -> Instant {
        self.original_read_deadline
    }

    pub(in crate::native_ui) fn check_selection(&self) -> Result<()> {
        if Instant::now() >= self.original_read_deadline
            || self.original_read_deadline > self.original_service_deadline
            || self.original_read_deadline > self.original_material_deadline
            || self.original_material_deadline > self.original_service_deadline
            || self.original_service_deadline
                != self
                    .original_source_deadline
                    .min(self.original_channel_deadline)
            || hex::encode(Sha256::digest(&*self.root)) != self.root_digest
            || hex::encode(Sha256::digest(&*self.certificate)) != self.certificate_digest
            || wholepact_core::proposal::canonical_digest(
                "wholepact:native-witness-setup:v1",
                &(
                    &self.setup,
                    &self.certificate_digest,
                    &self.root_digest,
                    &self.disclosure,
                ),
            )
            .map_err(|_| Error::InvalidData)?
                != self.selection_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_selection_digests_are_exact_lowercase_not_paths_or_labels() {
        assert!(require_digest(&"a".repeat(64)).is_ok());
        for value in [
            "A".repeat(64),
            "g".repeat(64),
            "0".repeat(63),
            "0".repeat(65),
            String::new(),
        ] {
            assert!(require_digest(&value).is_err());
        }
    }
}

use wholepact_financial_coordinator_origin::{
    SignerV3PrepareReadFinalV1, SignerV3PreparedLifetimeV1,
};

impl PreparedCoordinatedDeliveryWitnessV1 {
    pub(in crate::native_ui) fn disclosure_digest(&self) -> Result<String> {
        wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-v3-owner-disclosure:v1",
            &self.disclosure,
        )
        .map_err(|_| Error::InvalidData)
    }

    fn require_final(&self, action: &SignerV3PrepareReadFinalV1) -> Result<()> {
        action.check_current()?;
        self.check_selection()?;
        action.presentation().validate()?;
        let facts = action.facts();
        require_digest(&facts.preparation_digest)?;
        if facts.source_identity_digest != self.source_identity
            || facts.owner_selection_digest != self.selection_digest
            || facts.owner_certificate_digest != self.certificate_digest
            || facts.disclosure_digest != self.disclosure_digest()?
            || facts.owner_setup_json != self.setup_json
            || action.original_source_deadline() != self.original_source_deadline
            || action.original_channel_deadline() != self.original_channel_deadline
            || action.original_material_deadline() != self.original_material_deadline
            || action.original_service_deadline() != self.original_service_deadline
            || action.original_read_deadline() != self.original_read_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        action.check_current()?;
        Ok(())
    }

    /// The only private-key opener for this exact selection. Borrow the actual
    /// one-use PrepareRead Final; the source owner consumes it only after both
    /// source preparation and this local client construction have succeeded.
    /// No remote connection/history authentication is asserted here.
    pub(in crate::native_ui) fn open_read(
        self,
        action: &SignerV3PrepareReadFinalV1,
    ) -> Result<OpenedCoordinatedDeliveryWitnessV1> {
        self.require_final(action)?;
        let key = crate::native_ui::witness_workspace::coordinated_credential_read_v1::read_private_credential_checked_v1(
            &self.setup.client_private_key_pkcs8_der, || self.require_final(action),
        )?;
        self.require_final(action)?;
        // Maintained TLS kernel verifies exact certificate/private-key match.
        let tls = ClientTls::new(
            self.setup.server_name.clone(),
            self.setup.pinned_server_certificate_digest.clone(),
            vec![CertificateDer::from(self.root.to_vec())],
            vec![CertificateDer::from(self.certificate.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        );
        drop(key);
        self.require_final(action)?;
        let tls = tls.map_err(|_| Error::Authentication)?;
        let client = AuthorityClient::new(
            self.setup.endpoint,
            tls,
            self.setup.witness_id.clone(),
            self.setup.account_id.clone(),
            self.setup.network_profile_id.clone(),
            self.setup.policy_digest.clone(),
        );
        self.require_final(action)?;
        let client = client.map_err(|_| Error::InvalidData)?;
        if client.disclosure_descriptor() != self.disclosure {
            return Err(Error::Authentication);
        }
        // Unique identity is minted only after actual client/key construction.
        // It commits local custody, NOT remote peer authentication or consent.
        let nonce = Zeroizing::new(crate::vault::random::<32>()?);
        self.require_final(action)?;
        let preparation_digest = action.facts().preparation_digest.clone();
        let owner_service_digest = service_digest(
            &self.source_identity,
            &preparation_digest,
            &self.selection_digest,
            &self.certificate_digest,
            &self.root_digest,
            &nonce,
        )?;
        self.require_final(action)?;
        Ok(OpenedCoordinatedDeliveryWitnessV1 {
            client,
            disclosure: self.disclosure,
            certificate_digest: self.certificate_digest,
            root_digest: self.root_digest,
            source_identity: self.source_identity,
            selection_digest: self.selection_digest,
            preparation_digest,
            prepare_read_presentation_digest: action.presentation().presentation_digest.clone(),
            nonce,
            owner_service_digest,
            original_source_deadline: self.original_source_deadline,
            original_channel_deadline: self.original_channel_deadline,
            original_material_deadline: self.original_material_deadline,
            original_service_deadline: self.original_service_deadline,
        })
    }
}

fn service_digest(
    source: &str,
    preparation: &str,
    selection: &str,
    certificate: &str,
    root: &str,
    nonce: &[u8; 32],
) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:coordinated-v3-owner-service:v1",
        &(
            source,
            preparation,
            selection,
            certificate,
            root,
            hex::encode(nonce),
        ),
    )
    .map_err(|_| Error::InvalidData)
}

/// Actual local TLS client, still without the joined source restriction owner.
/// Its private client has no getter and no history, Receive or action methods.
pub(in crate::native_ui) struct OpenedCoordinatedDeliveryWitnessV1 {
    client: AuthorityClient,
    disclosure: WitnessDisclosureDescriptor,
    certificate_digest: String,
    root_digest: String,
    source_identity: String,
    selection_digest: String,
    preparation_digest: String,
    prepare_read_presentation_digest: String,
    nonce: Zeroizing<[u8; 32]>,
    owner_service_digest: String,
    original_source_deadline: Instant,
    original_channel_deadline: Instant,
    original_material_deadline: Instant,
    original_service_deadline: Instant,
}
impl OpenedCoordinatedDeliveryWitnessV1 {
    pub(in crate::native_ui) fn owner_service_digest(&self) -> &str {
        &self.owner_service_digest
    }
    pub(in crate::native_ui) fn original_service_deadline(&self) -> Instant {
        self.original_service_deadline
    }

    pub(in crate::native_ui) fn seal_read(
        self,
        lifetime: Arc<SignerV3PreparedLifetimeV1>,
    ) -> Result<CoordinatedDeliveryWitnessV1> {
        lifetime.check_current()?;
        if lifetime.prepare_read_presentation_digest() != self.prepare_read_presentation_digest
            || lifetime.source_identity_digest() != self.source_identity
            || lifetime.original_service_deadline() != self.original_service_deadline
            || lifetime.original_source_deadline() != self.original_source_deadline
            || lifetime.original_channel_deadline() != self.original_channel_deadline
            || lifetime.original_material_deadline() != self.original_material_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        let witness = CoordinatedDeliveryWitnessV1 {
            opened: self,
            lifetime,
        };
        witness.check_custody()?;
        Ok(witness)
    }
}

/// Same actual original owner client in closed custody. The shared lifetime is
/// denial-only: it authorizes no I/O. Later history/Admit/Audit methods must each
/// require their own fresh nominal grant; no client accessor is exposed.
pub(in crate::native_ui) struct CoordinatedDeliveryWitnessV1 {
    opened: OpenedCoordinatedDeliveryWitnessV1,
    lifetime: Arc<SignerV3PreparedLifetimeV1>,
}
impl CoordinatedDeliveryWitnessV1 {
    pub(in crate::native_ui) fn owner_service_digest(&self) -> &str {
        &self.opened.owner_service_digest
    }
    pub(in crate::native_ui) fn original_service_deadline(&self) -> Instant {
        self.opened.original_service_deadline
    }
    pub(in crate::native_ui) fn check_custody(&self) -> Result<()> {
        self.lifetime.check_current()?;
        if Instant::now() >= self.opened.original_service_deadline
            || self.opened.client.disclosure_descriptor() != self.opened.disclosure
            || service_digest(
                &self.opened.source_identity,
                &self.opened.preparation_digest,
                &self.opened.selection_digest,
                &self.opened.certificate_digest,
                &self.opened.root_digest,
                &self.opened.nonce,
            )? != self.opened.owner_service_digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.lifetime.check_current()?;
        Ok(())
    }
}
