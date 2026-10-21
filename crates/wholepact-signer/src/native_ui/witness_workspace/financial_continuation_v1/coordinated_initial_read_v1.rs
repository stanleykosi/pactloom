//! Private exact public owner selection followed by a genuine
//! one-use v2 Read: one complete history read plus one immutable local Continue
//! preparation. No private TLS key or client is opened before Final.
use super::*;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::OpenedCoordinatedOriginalFinancialSourceV2;
use crate::native_peer::PeerProcess;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wholepact_authority::durable_financial_continuation_v1::FinancialContinuationTermsV1;
use wholepact_financial_coordinator_origin::{
    SignerFinancialReadFactsV1, SignerFinancialReadFinalV1, SignerFinancialReadPresentationV1,
    SignerSourceEntryPresentationV1,
};

fn wall_now() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Locked)?
            .as_millis(),
    )
    .map_err(|_| Error::Locked)
}
fn disclosure_digest(disclosure: &WitnessDisclosureDescriptor) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:coordinated-original-financial-disclosure:v1",
        disclosure,
    )
    .map_err(|_| Error::InvalidData)
}
fn selected_digest(
    setup: &WitnessSetup,
    certificate: &str,
    root: &str,
    disclosure: &WitnessDisclosureDescriptor,
) -> Result<String> {
    // Exact maintained SelectedWitnessConfiguration preimage and domain. A
    // matching digest is selection evidence, not proof of key possession.
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-witness-setup:v1",
        &(setup, certificate, root, disclosure),
    )
    .map_err(|_| Error::InvalidData)
}

/// Frozen public bytes and nonsecret paths only. No key, AuthorityClient,
/// action, session or source owner is embedded in this preparation.
pub(in crate::native_ui) struct PreparedCoordinatedInitialReadV1 {
    setup: WitnessSetup,
    root: Zeroizing<Vec<u8>>,
    certificate: Zeroizing<Vec<u8>>,
    root_digest: String,
    disclosure: WitnessDisclosureDescriptor,
    facts: SignerFinancialReadFactsV1,
    terms: FinancialContinuationTermsV1,
    entry: SignerSourceEntryPresentationV1,
    original_read_deadline: Instant,
    original_source_deadline: Instant,
}
impl PreparedCoordinatedInitialReadV1 {
    pub(in crate::native_ui) fn prepare(
        json: &str,
        source: &OpenedCoordinatedOriginalFinancialSourceV2,
        original_host: &PeerProcess,
        terms: FinancialContinuationTermsV1,
        entry: SignerSourceEntryPresentationV1,
    ) -> Result<Self> {
        source.check_public(original_host)?;
        entry.validate()?;
        if json.len() > MAX_CONFIG {
            return Err(Error::InvalidData);
        }
        let setup: WitnessSetup = serde_json::from_str(json).map_err(|_| Error::InvalidData)?;
        let disclosure = &terms.scope.witness;
        if setup.schema_version != 1
            || setup.account_id != disclosure.account_id
            || setup.network_profile_id != disclosure.network_profile_id
        {
            return Err(Error::ReviewMismatch);
        }
        for text in [&setup.operator_name, &setup.retention_statement] {
            if text.is_empty()
                || text.len() > 2048
                || text.chars().any(|c| c.is_control() && c != '\n')
            {
                return Err(Error::InvalidData);
            }
        }
        let selected_disclosure = WitnessDisclosureDescriptor {
            endpoint: setup.endpoint.to_string(),
            server_name: setup.server_name.clone(),
            witness_id: setup.witness_id.clone(),
            account_id: setup.account_id.clone(),
            network_profile_id: setup.network_profile_id.clone(),
            policy_digest: setup.policy_digest.clone(),
            pinned_server_certificate_digest: setup.pinned_server_certificate_digest.clone(),
        };
        selected_disclosure
            .validate()
            .map_err(|_| Error::InvalidData)?;
        if &selected_disclosure != disclosure {
            return Err(Error::Authentication);
        }
        // Public certificates only. Never read the selected private-key path
        // and never construct a TLS/client object during ordinary preparation.
        let root = read_private_credential(&setup.trusted_server_root_der)?;
        source.check_public(original_host)?;
        let certificate = read_private_credential(&setup.client_certificate_der)?;
        source.check_public(original_host)?;
        let certificate_digest = hex::encode(Sha256::digest(&*certificate));
        let root_digest = hex::encode(Sha256::digest(&*root));
        source.require_owner(disclosure, &certificate_digest)?;
        let owner_selection_digest =
            selected_digest(&setup, &certificate_digest, &root_digest, disclosure)?;
        let journal_digest = source.journal_digest().to_owned();
        let monotonic_now = Instant::now();
        let now = wall_now()?;
        terms.require_live(now).map_err(|_| Error::Locked)?;
        let original_source_deadline = source.original_deadline();
        let original_read_deadline = original_source_deadline.min(
            monotonic_now
                .checked_add(Duration::from_secs(120))
                .ok_or(Error::InvalidData)?,
        );
        let read_ms = u64::try_from(
            original_read_deadline
                .checked_duration_since(monotonic_now)
                .ok_or(Error::Locked)?
                .as_millis(),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = serde_json::to_string_pretty(&serde_json::json!({
            "purpose": "original-history-and-one-local-continue-preparation-v2",
            "local_preparation_notice": "This Read also permits exactly one local original enrollment, principal and full original19 audit to freeze one immutable Continue request and presentation under this same Read deadline. It does not authorize saving that request or any mutation. Separate Continue Arm and final approval remain required.",
            "selected_root": source.original_root(),
            "selected_owner_configuration": setup,
            "client_certificate_digest": certificate_digest,
            "trusted_root_digest": root_digest,
            "owner_selection_digest": owner_selection_digest,
            "private_key_notice": "The exact selected private credential is opened only after this Read approval. Its certificate match is checked before any network send. This does not authorize Continue or Admit.",
            "source_identity_digest": source.identity_digest(),
            "original_journal_digest": journal_digest,
            "original_host_process_instance": original_host.instance(),
            "financial_terms": terms,
            "source_entry_presentation_digest": entry.presentation_digest,
            "head_notice": "The displayed delivery head is the original committed head. The remote current head is not known until this complete authenticated read.",
        })).map_err(|_| Error::InvalidData)?;
        let mut facts = SignerFinancialReadFactsV1 {
            read_digest: String::new(),
            display,
            source_identity_digest: source.identity_digest().to_owned(),
            original_journal_digest: journal_digest,
            terms_digest: terms
                .intent_terms_digest()
                .map_err(|_| Error::InvalidData)?,
            original_delivery_operation_id: terms.original_delivery_operation_id.clone(),
            original_delivery_request_digest: terms.original_delivery_request_digest.clone(),
            original_delivery_head_sequence: terms.original_delivery_committed_head.sequence,
            original_delivery_head_digest: terms.original_delivery_committed_head.digest.clone(),
            original_host_process_instance: original_host.instance().to_owned(),
            account_id: disclosure.account_id.clone(),
            owner_certificate_digest: certificate_digest,
            owner_selection_digest,
            disclosure_digest: disclosure_digest(disclosure)?,
            session_digest: entry.facts.session_digest.clone(),
            reviewed_at_ms: now,
            expires_at_ms: now
                .checked_add(read_ms)
                .ok_or(Error::InvalidData)?
                .min(source.original_ceiling_ms()),
            source_expires_at_ms: source.original_ceiling_ms(),
        };
        facts.read_digest = facts.calculate_read_digest()?;
        facts.validate()?;
        let prepared = Self {
            setup,
            root,
            certificate,
            root_digest,
            disclosure: selected_disclosure,
            facts,
            terms,
            entry,
            original_read_deadline,
            original_source_deadline,
        };
        prepared.check_source(source, original_host)?;
        Ok(prepared)
    }
    pub(in crate::native_ui) fn facts(&self) -> &SignerFinancialReadFactsV1 {
        &self.facts
    }
    pub(in crate::native_ui) fn original_read_deadline(&self) -> Instant {
        self.original_read_deadline
    }
    pub(in crate::native_ui) fn original_source_deadline(&self) -> Instant {
        self.original_source_deadline
    }

    fn check_source(
        &self,
        source: &OpenedCoordinatedOriginalFinancialSourceV2,
        host: &PeerProcess,
    ) -> Result<()> {
        source.check_public(host)?;
        source.require_owner(&self.disclosure, &self.facts.owner_certificate_digest)?;
        if source.entry_presentation_digest() != self.entry.presentation_digest
            || source.selection_digest() != self.entry.facts.selection_digest
            || source.terms_digest() != self.facts.terms_digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.check_frozen_source_data(
            source.identity_digest(),
            source.journal_digest(),
            source.original_deadline(),
            source.original_ceiling_ms(),
            host,
        )?;
        source.check_public(host)
    }

    fn check_read_source(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        host: &PeerProcess,
        read: &SignerFinancialReadFinalV1,
    ) -> Result<()> {
        read.check_current()?;
        source.check_coordinated_read_custody_v2(read)?;
        read.check_current()?;
        source.check_coordinated_public_custody_v2(host)?;
        source.require_coordinated_owner_metadata_v2(
            &self.disclosure,
            &self.facts.owner_certificate_digest,
        )?;
        self.check_frozen_source_data(
            source.identity_digest(),
            &source.coordinated_public_journal_digest_v2()?,
            source.original_deadline(),
            source.original_ceiling_ms(),
            host,
        )?;
        read.check_current()?;
        Ok(())
    }

    fn check_frozen_source_data(
        &self,
        source_identity: &str,
        journal_digest: &str,
        source_deadline: Instant,
        source_ceiling: u64,
        host: &PeerProcess,
    ) -> Result<()> {
        self.facts.validate()?;
        self.entry.validate()?;
        let now = wall_now()?;
        self.terms.require_live(now).map_err(|_| Error::Locked)?;
        let entry = &self.entry.facts;
        if Instant::now() >= self.original_read_deadline
            || self.original_read_deadline > self.original_source_deadline
            || self.original_source_deadline != source_deadline
            || self.facts.source_identity_digest != source_identity
            || self.facts.original_journal_digest != journal_digest
            || self.facts.original_host_process_instance != host.instance()
            || self.facts.source_expires_at_ms != source_ceiling
            || self.facts.source_expires_at_ms != self.terms.valid_until_ms
            || now < self.facts.reviewed_at_ms
            || now >= self.facts.expires_at_ms
            || self.facts.terms_digest
                != self
                    .terms
                    .intent_terms_digest()
                    .map_err(|_| Error::InvalidData)?
            || self.facts.disclosure_digest != disclosure_digest(&self.disclosure)?
            || self.facts.owner_selection_digest
                != selected_digest(
                    &self.setup,
                    &self.facts.owner_certificate_digest,
                    &self.root_digest,
                    &self.disclosure,
                )?
            || self.facts.owner_certificate_digest
                != hex::encode(Sha256::digest(&*self.certificate))
            || self.root_digest != hex::encode(Sha256::digest(&*self.root))
            || entry.original_host_process_instance != self.facts.original_host_process_instance
            || entry.account_id != self.facts.account_id
            || entry.owner_certificate_digest != self.facts.owner_certificate_digest
            || entry.disclosure_digest != self.facts.disclosure_digest
            || entry.terms_digest != self.facts.terms_digest
            || entry.session_digest != self.facts.session_digest
            || entry.source_expires_at_ms != self.facts.source_expires_at_ms
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }

    pub(in crate::native_ui) fn freeze_presentation(
        self,
        presentation: SignerFinancialReadPresentationV1,
    ) -> Result<PresentedCoordinatedInitialReadV1> {
        presentation.validate()?;
        if presentation.facts != self.facts
            || presentation.actor != self.entry.actor
            || presentation.selection_digest != self.entry.facts.selection_digest
            || presentation.source_entry_presentation_digest != self.entry.presentation_digest
            || presentation.source_ceiling_ms != self.entry.source_ceiling_ms
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(PresentedCoordinatedInitialReadV1 {
            prepared: self,
            presentation,
        })
    }
}

/// Actual one-use owner state, not a presentation or a post-completion lease.
/// The same Read Final remains current until local immutable preparation ends.
/// Fields stay in Signer; no DTO constructor, Clone, serde or retry conversion.
pub(in crate::native_ui) struct ReadFinancialContinueInputsV2 {
    pub(in crate::native_ui) source: PreparedOriginalFinancialSourceV1,
    pub(in crate::native_ui) owner: FinancialWitnessCustodyV1,
    pub(in crate::native_ui) history: ReconciledAuthorityHistory,
    pub(in crate::native_ui) final_read: SignerFinancialReadFinalV1,
}

pub(in crate::native_ui) struct PresentedCoordinatedInitialReadV1 {
    prepared: PreparedCoordinatedInitialReadV1,
    presentation: SignerFinancialReadPresentationV1,
}
impl PresentedCoordinatedInitialReadV1 {
    fn check(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        host: &PeerProcess,
        final_read: &SignerFinancialReadFinalV1,
    ) -> Result<()> {
        self.check_final(host, final_read)?;
        self.prepared.check_read_source(source, host, final_read)?;
        final_read.check_current()?;
        Ok(())
    }

    // Match the exact receipt before any private source audit or key opening.
    fn check_final(
        &self,
        host: &PeerProcess,
        final_read: &SignerFinancialReadFinalV1,
    ) -> Result<()> {
        final_read.check_current()?;
        self.presentation.validate()?;
        if final_read.presentation() != &self.presentation
            || self.presentation.facts != self.prepared.facts
            || final_read.read_digest() != self.prepared.facts.read_digest
            || final_read.presentation_digest() != self.presentation.presentation_digest
            || final_read.original_host_process_instance() != host.instance()
            || final_read.original_read_deadline() != self.prepared.original_read_deadline
            || final_read.original_source_deadline() != self.prepared.original_source_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        final_read.check_current()?;
        Ok(())
    }

    /// Consumes one genuine Read and this exact selection. On any error, keys,
    /// client and Final drop; nothing is returned for reissue or hidden retry.
    /// Actual client/history and the still-current Read Final move together for
    /// the one explicitly displayed local preparation. No post-completion lease
    /// or mutation authority is created; the original Read clock is unchanged.
    pub(in crate::native_ui) fn read_history_for_continue_preparation_v2(
        self,
        opened: OpenedCoordinatedOriginalFinancialSourceV2,
        original_host: &PeerProcess,
        final_read: SignerFinancialReadFinalV1,
    ) -> Result<ReadFinancialContinueInputsV2> {
        self.check_final(original_host, &final_read)?;
        let source = opened.into_read(&final_read)?;
        self.check(&source, original_host, &final_read)?;
        let key = read_private_credential(&self.prepared.setup.client_private_key_pkcs8_der)?;
        self.check(&source, original_host, &final_read)?;
        let setup = &self.prepared.setup;
        let tls = ClientTls::new(
            setup.server_name.clone(),
            setup.pinned_server_certificate_digest.clone(),
            vec![CertificateDer::from(self.prepared.root.to_vec())],
            vec![CertificateDer::from(self.prepared.certificate.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .map_err(|_| Error::Authentication)?;
        drop(key);
        self.check(&source, original_host, &final_read)?;
        let client = AuthorityClient::new_restricted_v1(
            setup.endpoint,
            tls,
            setup.witness_id.clone(),
            setup.account_id.clone(),
            setup.network_profile_id.clone(),
            setup.policy_digest.clone(),
            source.coordinated_authority_transport_restriction_v1()?,
        )
        .map_err(|_| Error::InvalidData)?;
        self.check(&source, original_host, &final_read)?;
        let disclosure = client.disclosure_descriptor();
        if disclosure != self.prepared.disclosure
            || selected_digest(
                setup,
                &self.prepared.facts.owner_certificate_digest,
                &self.prepared.root_digest,
                &disclosure,
            )? != self.prepared.facts.owner_selection_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let owner = FinancialWitnessCustodyV1 {
            client,
            certificate_digest: self.prepared.facts.owner_certificate_digest.clone(),
            owner: true,
        };
        let check = || {
            self.check(&source, original_host, &final_read)?;
            source.require_coordinated_owner_metadata_v2(
                &owner.client.disclosure_descriptor(),
                &owner.certificate_digest,
            )?;
            final_read.check_current()?;
            Ok(())
        };
        check()?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .ok_or(Error::InvalidData)?
            .min(self.prepared.original_read_deadline)
            .min(self.prepared.original_source_deadline);
        // Every callback returns after source/journal guards have dropped.
        let history = owner
            .client
            .reconcile_history_checked_until(deadline, || {
                check().map_err(|_: Error| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        check()?;
        // Do not finish Read here: the explicitly scoped local preparation
        // still needs this very same live, R-sensitive Final and original clock.
        Ok(ReadFinancialContinueInputsV2 {
            source,
            owner,
            history,
            final_read,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_setup() -> WitnessSetup {
        WitnessSetup {
            schema_version: 1,
            endpoint: "127.0.0.1:443".parse().unwrap(),
            server_name: "owner.example".into(),
            witness_id: "witness".into(),
            account_id: "01".repeat(32),
            network_profile_id: "network".into(),
            policy_digest: "02".repeat(32),
            pinned_server_certificate_digest: "03".repeat(32),
            trusted_server_root_der: "/synthetic/root.der".into(),
            client_certificate_der: "/synthetic/owner.der".into(),
            client_private_key_pkcs8_der: "/synthetic/owner.pk8".into(),
            operator_name: "Synthetic public selector".into(),
            retention_statement: "Synthetic notice, no credential files are opened.".into(),
        }
    }
    fn public_disclosure() -> WitnessDisclosureDescriptor {
        let setup = public_setup();
        WitnessDisclosureDescriptor {
            endpoint: setup.endpoint.to_string(),
            server_name: setup.server_name,
            witness_id: setup.witness_id,
            account_id: setup.account_id,
            network_profile_id: setup.network_profile_id,
            policy_digest: setup.policy_digest,
            pinned_server_certificate_digest: setup.pinned_server_certificate_digest,
        }
    }

    #[test]
    fn public_owner_selection_preserves_maintained_digest_preimage() {
        let setup = public_setup();
        let certificate = "04".repeat(32);
        let root = "05".repeat(32);
        let disclosure = public_disclosure();
        let maintained = wholepact_core::proposal::canonical_digest(
            "wholepact:native-witness-setup:v1",
            &(&setup, &certificate, &root, &disclosure),
        )
        .unwrap();
        assert_eq!(
            selected_digest(&setup, &certificate, &root, &disclosure).unwrap(),
            maintained
        );
    }

    #[test]
    fn public_owner_selection_binds_every_field_and_public_certificate_digest() {
        let certificate = "04".repeat(32);
        let root = "05".repeat(32);
        let disclosure = public_disclosure();
        let expected = selected_digest(&public_setup(), &certificate, &root, &disclosure).unwrap();
        for field in 0..13 {
            let mut changed = public_setup();
            match field {
                0 => changed.schema_version = 2,
                1 => changed.endpoint = "127.0.0.1:444".parse().unwrap(),
                2 => changed.server_name.push('x'),
                3 => changed.witness_id.push('x'),
                4 => changed.account_id = "ff".repeat(32),
                5 => changed.network_profile_id.push('x'),
                6 => changed.policy_digest = "ff".repeat(32),
                7 => changed.pinned_server_certificate_digest = "ff".repeat(32),
                8 => changed.trusted_server_root_der = "/synthetic/other-root.der".into(),
                9 => changed.client_certificate_der = "/synthetic/other-owner.der".into(),
                10 => changed.client_private_key_pkcs8_der = "/synthetic/other-owner.pk8".into(),
                11 => changed.operator_name.push('x'),
                12 => changed.retention_statement.push('x'),
                _ => unreachable!(),
            }
            assert_ne!(
                selected_digest(&changed, &certificate, &root, &disclosure).unwrap(),
                expected
            );
        }
        assert_ne!(
            selected_digest(&public_setup(), &"ff".repeat(32), &root, &disclosure).unwrap(),
            expected
        );
        assert_ne!(
            selected_digest(&public_setup(), &certificate, &"ff".repeat(32), &disclosure).unwrap(),
            expected
        );
        let mut other_disclosure = disclosure;
        other_disclosure.witness_id.push('x');
        assert_ne!(
            selected_digest(&public_setup(), &certificate, &root, &other_disclosure).unwrap(),
            expected
        );
    }
}
