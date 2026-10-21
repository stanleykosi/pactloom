//! Fresh selected-writer Read on the retained coordinated owner. Before A this
//! retains public bytes and paths only. After A one exact key/TLS setup and one
//! complete history read precede one immutable Acquire recipe preparation.
use super::*;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::FinancialOperationSourcePinV1;
use crate::native_peer::PeerProcess;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wholepact_authority::durable_financial_continuation_v1::{
    AuthenticatedFinancialContinuationHistoryV1, FinancialContinuationTermsV1,
};
use wholepact_financial_coordinator_origin::{
    SignerAcquireArmV1, SignerAdmitPresentationV1, SignerContinuePresentationV1,
    SignerFinancialWriterReadFactsV1, SignerFinancialWriterReadFinalV1,
    SignerFinancialWriterReadPresentationV1,
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
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-witness-setup:v1",
        &(setup, certificate, root, disclosure),
    )
    .map_err(|_| Error::InvalidData)
}

pub(in crate::native_ui) struct PreparedCoordinatedWriterReadV1 {
    setup: WitnessSetup,
    root: Zeroizing<Vec<u8>>,
    certificate: Zeroizing<Vec<u8>>,
    disclosure: WitnessDisclosureDescriptor,
    facts: SignerFinancialWriterReadFactsV1,
    admitted: SignerAdmitPresentationV1,
    admitted_snapshot: AccountSnapshot,
    original_read_deadline: Instant,
    original_source_deadline: Instant,
}
impl PreparedCoordinatedWriterReadV1 {
    pub(in crate::native_ui) fn prepare(
        json: &str,
        source: &PreparedOriginalFinancialSourceV1,
        owner: &FinancialWitnessCustodyV1,
        host: &PeerProcess,
        terms: &FinancialContinuationTermsV1,
        admitted: SignerAdmitPresentationV1,
        admitted_snapshot: AccountSnapshot,
        session_deadline: Instant,
    ) -> Result<Self> {
        source.check_coordinated_public_custody_v2(host)?;
        admitted.validate()?;
        if !owner.owner || json.len() > MAX_CONFIG {
            return Err(Error::Authentication);
        }
        let disclosure = owner.client.disclosure_descriptor();
        source.require_coordinated_owner_metadata_v2(&disclosure, &owner.certificate_digest)?;
        let request: wholepact_authority::OwnerControlRequest =
            serde_json::from_str(&admitted.facts.request_json).map_err(|_| Error::InvalidData)?;
        let record = match &request.control {
            wholepact_authority::OwnerControl::AdmitFinancialContinuationV1 { record } => record,
            _ => return Err(Error::ReviewMismatch),
        };
        record
            .validate_request(&request, &disclosure)
            .map_err(|_| Error::ReviewMismatch)?;
        if &record.terms != terms
            || disclosure != terms.scope.witness
            || admitted.facts.source_identity_digest != source.identity_digest()
            || admitted.facts.original_host_process_instance != host.instance()
            || admitted.facts.owner_certificate_digest != owner.certificate_digest
            || admitted.facts.disclosure_json
                != serde_json::to_string(&disclosure).map_err(|_| Error::InvalidData)?
            || admitted.facts.disclosure_digest != disclosure_digest(&disclosure)?
            || admitted.facts.request_json
                != serde_json::to_string(&request).map_err(|_| Error::InvalidData)?
            || admitted.facts.request_digest
                != SignerContinuePresentationV1::calculate_request_digest(
                    &admitted.facts.request_json,
                )
            || admitted.facts.source_expires_at_ms != source.original_ceiling_ms()
            || terms.valid_until_ms != source.original_ceiling_ms()
        {
            return Err(Error::ReviewMismatch);
        }
        let setup: WitnessSetup = serde_json::from_str(json).map_err(|_| Error::InvalidData)?;
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
        if selected_disclosure != disclosure {
            return Err(Error::Authentication);
        }
        // Public bytes only. The selected private key path is not opened here.
        let root = read_private_credential(&setup.trusted_server_root_der)?;
        source.check_coordinated_public_custody_v2(host)?;
        let certificate = read_private_credential(&setup.client_certificate_der)?;
        source.check_coordinated_public_custody_v2(host)?;
        let certificate_digest = hex::encode(Sha256::digest(&*certificate));
        let root_digest = hex::encode(Sha256::digest(&*root));
        if certificate_digest != terms.scope.authorization.writer_certificate_digest {
            return Err(Error::Authentication);
        }
        let writer_selection_digest =
            selected_digest(&setup, &certificate_digest, &root_digest, &disclosure)?;
        let monotonic_now = Instant::now();
        let now = wall_now()?;
        terms.require_live(now).map_err(|_| Error::Locked)?;
        let original_source_deadline = source.original_deadline();
        let original_read_deadline = original_source_deadline.min(session_deadline).min(
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
            "purpose": "original-financial-history-and-selected-writer-setup-v1",
            "notice": "This Read opens only the exact displayed writer private key, validates its selected certificate/root, retains one restricted writer client, reads one complete financial history through the SAME original owner, and prepares one immutable Acquire recipe. It does not authorize Acquire, Activate, signing or any mutation. A separate Acquire Arm and final approval are required.",
            "selected_original_root": source.original_root(),
            "selected_writer_configuration": setup,
            "writer_certificate_digest": certificate_digest,
            "writer_root_digest": root_digest,
            "writer_selection_digest": writer_selection_digest,
            "private_key_notice": "The exact selected private credential path above is opened only after this Read approval. No private key is sent to the coordinator or Host.",
            "source_identity_digest": source.identity_digest(),
            "original_host_process_instance": host.instance(),
            "original_owner_certificate_digest": owner.certificate_digest,
            "original_owner_disclosure": disclosure,
            "admit_presentation_digest": admitted.presentation_digest,
            "authenticated_admitted_snapshot": admitted_snapshot,
            "exact_continuation_request": request,
            "financial_terms": terms,
            "head_notice": "This is the retained authenticated Admit result, not a newly read remote head. The one complete Read authenticates the current head before an immutable Acquire recipe is prepared."
        })).map_err(|_| Error::InvalidData)?;
        let facts = SignerFinancialWriterReadFactsV1 {
            display,
            source_identity_digest: source.identity_digest().to_owned(),
            terms_digest: terms
                .intent_terms_digest()
                .map_err(|_| Error::InvalidData)?,
            continuation_request_json: admitted.facts.request_json.clone(),
            continuation_request_digest: admitted.facts.request_digest.clone(),
            admit_presentation_digest: admitted.presentation_digest.clone(),
            admit_request_digest: admitted.facts.request_digest.clone(),
            admitted_head_sequence: admitted_snapshot.head.sequence,
            admitted_head_digest: admitted_snapshot.head.digest.clone(),
            original_host_process_instance: host.instance().to_owned(),
            owner_certificate_digest: owner.certificate_digest.clone(),
            owner_disclosure_digest: disclosure_digest(&disclosure)?,
            writer_selection_digest,
            writer_certificate_digest: certificate_digest,
            writer_root_digest: root_digest,
            writer_disclosure_json: serde_json::to_string(&disclosure)
                .map_err(|_| Error::InvalidData)?,
            writer_disclosure_digest: disclosure_digest(&disclosure)?,
            reviewed_at_ms: now,
            expires_at_ms: now
                .checked_add(read_ms)
                .ok_or(Error::InvalidData)?
                .min(source.original_ceiling_ms()),
            source_expires_at_ms: source.original_ceiling_ms(),
        };
        facts.validate()?;
        let prepared = Self {
            setup,
            root,
            certificate,
            disclosure,
            facts,
            admitted,
            admitted_snapshot,
            original_read_deadline,
            original_source_deadline,
        };
        prepared.check_public(source, owner, host)?;
        Ok(prepared)
    }

    pub(in crate::native_ui) fn facts(&self) -> &SignerFinancialWriterReadFactsV1 {
        &self.facts
    }
    pub(in crate::native_ui) fn original_source_deadline(&self) -> Instant {
        self.original_source_deadline
    }
    pub(in crate::native_ui) fn original_read_deadline(&self) -> Instant {
        self.original_read_deadline
    }

    fn check_public(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        owner: &FinancialWitnessCustodyV1,
        host: &PeerProcess,
    ) -> Result<()> {
        source.check_coordinated_public_custody_v2(host)?;
        self.facts.validate()?;
        self.admitted.validate()?;
        if !owner.owner
            || self.facts.source_identity_digest != source.identity_digest()
            || self.facts.original_host_process_instance != host.instance()
            || self.facts.owner_certificate_digest != owner.certificate_digest
            || self.facts.owner_disclosure_digest
                != disclosure_digest(&owner.client.disclosure_descriptor())?
            || owner.client.disclosure_descriptor() != self.disclosure
            || self.facts.writer_disclosure_json
                != serde_json::to_string(&self.disclosure).map_err(|_| Error::InvalidData)?
            || self.facts.writer_disclosure_digest != disclosure_digest(&self.disclosure)?
            || self.facts.writer_certificate_digest
                != hex::encode(Sha256::digest(&*self.certificate))
            || self.facts.writer_root_digest != hex::encode(Sha256::digest(&*self.root))
            || self.facts.writer_selection_digest
                != selected_digest(
                    &self.setup,
                    &self.facts.writer_certificate_digest,
                    &self.facts.writer_root_digest,
                    &self.disclosure,
                )?
            || self.facts.admit_presentation_digest != self.admitted.presentation_digest
            || self.facts.continuation_request_json != self.admitted.facts.request_json
            || self.facts.continuation_request_digest != self.admitted.facts.request_digest
            || self.facts.admitted_head_sequence != self.admitted_snapshot.head.sequence
            || self.facts.admitted_head_digest != self.admitted_snapshot.head.digest
            || self.original_source_deadline != source.original_deadline()
            || self.facts.source_expires_at_ms != source.original_ceiling_ms()
            || Instant::now() >= self.original_read_deadline
            || wall_now()? >= self.facts.expires_at_ms
        {
            return Err(Error::ReviewMismatch);
        }
        source
            .require_coordinated_owner_metadata_v2(&self.disclosure, &owner.certificate_digest)?;
        source.check_coordinated_public_custody_v2(host)
    }

    pub(in crate::native_ui) fn freeze_presentation(
        self,
        presentation: SignerFinancialWriterReadPresentationV1,
    ) -> Result<PresentedCoordinatedWriterReadV1> {
        presentation.validate()?;
        if presentation.facts != self.facts
            || presentation.actor != self.admitted.actor
            || presentation.source_ceiling_ms != self.admitted.source_ceiling_ms
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(PresentedCoordinatedWriterReadV1 {
            prepared: self,
            presentation,
        })
    }
}

pub(in crate::native_ui) struct PresentedCoordinatedWriterReadV1 {
    prepared: PreparedCoordinatedWriterReadV1,
    presentation: SignerFinancialWriterReadPresentationV1,
}

/// Actual same-action preparation state. This is not a post-completion lease:
/// the genuine Read must remain live until all immutable recipe work ends.
pub(in crate::native_ui) struct ReadFinancialAcquireInputsV1 {
    pub(in crate::native_ui) writer: FinancialWitnessCustodyV1,
    pub(in crate::native_ui) history: AuthenticatedFinancialContinuationHistoryV1,
    pub(in crate::native_ui) final_read: SignerFinancialWriterReadFinalV1,
    pin: FinancialOperationSourcePinV1,
}
impl ReadFinancialAcquireInputsV1 {
    /// Consumes only the actual live Read inputs, after Origin has retained the
    /// complete immutable Acquire presentation. The token itself requires that
    /// exact preparation before advancing; no historical receipt can replace it.
    pub(in crate::native_ui) fn finish_preparation(
        self,
        source: &PreparedOriginalFinancialSourceV1,
        owner: &FinancialWitnessCustodyV1,
        host: &PeerProcess,
    ) -> Result<(
        FinancialWitnessCustodyV1,
        AuthenticatedFinancialContinuationHistoryV1,
    )> {
        self.check_preparation_current(source, owner, host)?;
        let Self {
            writer,
            history,
            final_read,
            pin: _,
        } = self;
        final_read.finish_read()?;
        Ok((writer, history))
    }
    pub(in crate::native_ui) fn check_preparation_current(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        owner: &FinancialWitnessCustodyV1,
        host: &PeerProcess,
    ) -> Result<()> {
        self.final_read.check_current()?;
        if !owner.owner
            || self.writer.owner
            || self.writer.certificate_digest
                != self
                    .final_read
                    .presentation()
                    .facts
                    .writer_certificate_digest
            || self.writer.client.disclosure_descriptor() != self.history.disclosure().clone()
            || self.history.continuation_request() != self.pin.continuation_request()
        {
            return Err(Error::ReviewMismatch);
        }
        source.check_coordinated_writer_read_source_pin_v1(
            &self.pin,
            &owner.client.disclosure_descriptor(),
            &owner.certificate_digest,
            host,
            &self.final_read,
        )?;
        self.final_read.check_current()?;
        Ok(())
    }
}

impl PresentedCoordinatedWriterReadV1 {
    pub(in crate::native_ui) fn read_once_for_acquire_preparation(
        self,
        source: &PreparedOriginalFinancialSourceV1,
        owner: &FinancialWitnessCustodyV1,
        host: &PeerProcess,
        final_read: SignerFinancialWriterReadFinalV1,
    ) -> Result<ReadFinancialAcquireInputsV1> {
        final_read.check_current()?;
        if final_read.presentation() != &self.presentation
            || final_read.original_source_deadline() != self.prepared.original_source_deadline
            || final_read.original_read_deadline() != self.prepared.original_read_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        self.prepared.check_public(source, owner, host)?;
        final_read.check_current()?;
        let pin = source.prepare_coordinated_writer_read_source_pin_v1(
            &owner.client.disclosure_descriptor(),
            &owner.certificate_digest,
            host,
            &final_read,
        )?;
        let check = || -> Result<()> {
            final_read.check_current()?;
            source.check_coordinated_writer_read_source_pin_v1(
                &pin,
                &owner.client.disclosure_descriptor(),
                &owner.certificate_digest,
                host,
                &final_read,
            )?;
            final_read.check_current()?;
            Ok(())
        };
        check()?;
        let key = crate::native_ui::witness_workspace::coordinated_credential_read_v1::read_private_credential_checked_v1(
            &self.prepared.setup.client_private_key_pkcs8_der,
            || { final_read.check_current()?; Ok(()) },
        )?;
        check()?;
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
        check()?;
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
        check()?;
        let disclosure = client.disclosure_descriptor();
        if disclosure != self.prepared.disclosure
            || selected_digest(
                setup,
                &self.prepared.facts.writer_certificate_digest,
                &self.prepared.facts.writer_root_digest,
                &disclosure,
            )? != self.prepared.facts.writer_selection_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let writer = FinancialWitnessCustodyV1 {
            client,
            certificate_digest: self.prepared.facts.writer_certificate_digest.clone(),
            owner: false,
        };
        check()?;
        // A writer client exists but has never opened a TLS session or acquired
        // an exporter key. The original OWNER performs this one complete Read.
        let history = owner
            .client
            .financial_continuation_history_v1_checked_until(
                &pin.continuation_request().operation_id,
                self.prepared
                    .original_read_deadline
                    .min(self.prepared.original_source_deadline)
                    .min(final_read.original_service_deadline()),
                || check().map_err(|_| wholepact_authority::AuthorityError::Permission),
            )
            .map_err(|_| Error::Uncertain)?;
        check()?;
        if history.continuation_request() != pin.continuation_request()
            || history.disclosure() != &self.prepared.disclosure
            || !history.contains_head(&self.prepared.admitted_snapshot.head)
        {
            return Err(Error::ReviewMismatch);
        }
        history
            .financial_continuation_online_permits_v1(&pin.continuation_request().operation_id)
            .map_err(|_| Error::ReviewMismatch)?;
        check()?;
        Ok(ReadFinancialAcquireInputsV1 {
            writer,
            history,
            final_read,
            pin,
        })
    }
}

impl FinancialWitnessCustodyV1 {
    /// Exact borrowed purpose adapter on the actual retained writer and owner.
    /// No key/client accessor, new TLS configuration, network call or action
    /// conversion is exposed. All private source reads require this actual Arm.
    pub(in crate::native_ui) fn prepare_coordinated_acquire_pin_v1(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        owner: &FinancialWitnessCustodyV1,
        host: &PeerProcess,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        arm: &SignerAcquireArmV1,
    ) -> Result<FinancialOperationSourcePinV1> {
        arm.check_current()?;
        let p = arm.presentation();
        p.validate()?;
        let facts = &p.facts;
        let disclosure = owner.client.disclosure_descriptor();
        let request = history.continuation_request();
        let record = history.continuation_record();
        if self.owner
            || !owner.owner
            || self.certificate_digest != facts.writer_certificate_digest
            || owner.certificate_digest != facts.owner_certificate_digest
            || self.client.disclosure_descriptor() != disclosure
            || history.disclosure() != &disclosure
            || facts.owner_disclosure_digest != disclosure_digest(&disclosure)?
            || facts.writer_disclosure_digest != facts.owner_disclosure_digest
            || facts.writer_disclosure_json
                != serde_json::to_string(&disclosure).map_err(|_| Error::InvalidData)?
            || facts.continuation_request_json
                != serde_json::to_string(request).map_err(|_| Error::InvalidData)?
            || facts.authenticated_history_digest != history.history_digest()
            || facts.authenticated_snapshot_json
                != serde_json::to_string(history.snapshot()).map_err(|_| Error::InvalidData)?
            || facts.expected_head_sequence != history.snapshot().head.sequence
            || facts.expected_head_digest != history.snapshot().head.digest
            || facts.writer_epoch != history.snapshot().writer_epoch
            || self.certificate_digest != history.snapshot().writer_certificate_digest
            || facts.acquire_operation_id
                != record
                    .acquire_operation_id(request)
                    .map_err(|_| Error::ReviewMismatch)?
            || facts.terms_digest
                != record
                    .terms
                    .intent_terms_digest()
                    .map_err(|_| Error::InvalidData)?
            || record.terms.scope.witness != disclosure
        {
            return Err(Error::ReviewMismatch);
        }
        history
            .financial_continuation_online_permits_v1(&request.operation_id)
            .map_err(|_| Error::ReviewMismatch)?;
        arm.check_current()?;
        let pin = source.prepare_coordinated_acquire_source_pin_v1(
            &disclosure,
            &owner.certificate_digest,
            host,
            arm,
        )?;
        arm.check_current()?;
        if pin.continuation_request() != request || pin.terms() != &record.terms {
            return Err(Error::ReviewMismatch);
        }
        source.check_coordinated_acquire_arm_source_pin_v1(
            &pin,
            &disclosure,
            &owner.certificate_digest,
            host,
            arm,
        )?;
        arm.check_current()?;
        Ok(pin)
    }
}
