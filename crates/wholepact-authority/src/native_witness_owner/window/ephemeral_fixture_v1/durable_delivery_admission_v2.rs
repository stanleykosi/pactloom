//! Isolated synthetic pointer driving of the genuine production native owner.
//! No fixture manufactures a source, approval, request or immutable journal row.
use super::*;
use crate::{AuthorityHead, OwnerControl, OwnerControlRequest};
const PREPARE: &str = "Prepare original TLS listener and exact delivery scope for review";
#[derive(Default)]
pub(super) struct FixturePhaseV2 {
    // At most the exact two independently reviewed owners of one shared plan.
    // Completion never removes owner1 when owner2 is denied or uncertain.
    pub(super) historical_only: bool,
    pub(super) native_historical_audit: bool,
    pub(super) original_signed_births: std::collections::BTreeMap<String, Vec<u8>>,
    pending: Option<OwnerControlRequest>,
    pub(super) committed: std::collections::BTreeMap<String, OwnerControlRequest>,
}

// Correlate inert typed data only. Human review text is not a wire format, and
// matching this data neither checks freshness nor supplies native approval.
fn require_exact_retained_request(
    retained: &OwnerControlRequest,
    requested: &OwnerControlRequest,
) -> Result<()> {
    if retained != requested {
        return Err(AuthorityError::Conflict);
    }
    Ok(())
}

impl EphemeralNativeWitnessV1 {
    /// The caller first drops its informational server, after the signer has
    /// finished preparing this actual request from the imported fixed source.
    /// This starts the real final-primary-click worker but does not wait for the
    /// independent signer's retained-intent-first owner-mTLS dispatch.
    pub fn start_exact_durable_delivery_admission_v2(
        &mut self,
        account_id: &str,
        request: &OwnerControlRequest,
    ) -> Result<()> {
        // A failed NEW preflight must never expose a prior attempt's sidecar.
        // Reset is inert; it neither checks nor revokes any native authority.
        crate::transport::admission_diagnostics_v1::reset_observation(
            &mut self.window.admission_observer,
        );
        crate::hash(account_id)?;
        if !self.window.can_select()
            || self.durable_delivery.historical_only
            || self.durable_delivery.pending.is_some()
            || self.durable_delivery.committed.contains_key(account_id)
            || self.durable_delivery.committed.len() >= 2
            || self.listener.server_handles.load(Ordering::Acquire) != 0
            || request.account_id != account_id
            || request.network_profile_id != self.window.input.network_profile_id
            || !matches!(
                &request.control,
                OwnerControl::AdmitDurablePaymentWithDeliveryV2 { .. }
            )
        {
            return Err(AuthorityError::Permission);
        }
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
            return Err(AuthorityError::Permission);
        };
        record.validate()?;
        for committed in self.durable_delivery.committed.values() {
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record: original } =
                &committed.control
            else {
                return Err(AuthorityError::CorruptHistory);
            };
            if record.scope.shared_plan_digest()? != original.scope.shared_plan_digest()? {
                return Err(AuthorityError::Conflict);
            }
        }
        // The prior native listener is fully drained. Rebind only its exact
        // original address; a second account is never a replacement endpoint.
        if self.listener.bound.is_none() {
            let listener =
                TcpListener::bind(self.listener.address).map_err(|_| AuthorityError::Permission)?;
            if listener.local_addr().map_err(|_| AuthorityError::Storage)? != self.listener.address
            {
                return Err(AuthorityError::Authentication);
            }
            self.listener.bound = Some(listener);
        }
        let original_address = self.listener.address;
        if self
            .listener
            .local_addr()
            .map_err(|_| AuthorityError::Permission)?
            != original_address
            || self.window.input.endpoint != original_address.to_string()
        {
            return Err(AuthorityError::Authentication);
        }
        let request_json =
            serde_json::to_string(request).map_err(|_| AuthorityError::InvalidBinding)?;
        if request_json.is_empty() || request_json.len() > crate::MAX_FRAME_BYTES {
            return Err(AuthorityError::Limit);
        }
        // Reselect only the actual account, original owner certificate and
        // nominal retained installation, using the existing native form path.
        drop(self.original_namespace_input(account_id)?);
        let path = |name: &str| -> Result<String> {
            self.root
                .join(name)
                .to_str()
                .map(str::to_owned)
                .ok_or(AuthorityError::InvalidBinding)
        };
        let certificate = path("server.der")?;
        let private_key = path("server.pk8")?;
        let trusted_root = path("ca.der")?;
        self.window
            .input
            .durable_delivery_admission_v2
            .set_synthetic_form_data(request_json, certificate, private_key, trusted_root);
        // Every informational server handle has already joined. Release the
        // original socket BEFORE the real native prepare binds this same address.
        // Failure leaves it absent; no replacement endpoint or fallback exists.
        drop(
            self.listener
                .bound
                .take()
                .ok_or(AuthorityError::Permission)?,
        );
        self.click(PREPARE)?;
        self.drain()?;
        let pending = self
            .window
            .pending
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        let Proposal::DurableDeliveryV2(prepared) = &pending.prepared.proposal else {
            return Err(AuthorityError::Permission);
        };
        if pending.phase != Phase::Reading
            || prepared
                .listener
                .local_addr()
                .map_err(|_| AuthorityError::Storage)?
                != original_address
        {
            return Err(AuthorityError::Authentication);
        }
        prepared.proposal.require_endpoint(
            &self.server_certificate_digest,
            &original_address.to_string(),
        )?;
        require_exact_retained_request(
            prepared
                .proposal
                .retained_request_for_synthetic_qualification(),
            request,
        )?;
        self.durable_delivery.pending = Some(request.clone());
        self.window.admission_observer =
            Some(crate::transport::admission_diagnostics_v1::AdmissionWitnessObserverV1::new());
        // Continue, understood and focused final primary click are exactly the
        // existing native controls. No fixture constructs any decision/source.
        self.start_approve_exact()?;
        if self.window.job.is_none() || self.window.pending.is_some() {
            return Err(AuthorityError::Uncertain);
        }
        Ok(())
    }

    /// Drain the same actual admission worker while the signer independently
    /// retains its intent and dispatches. Only exact committed evidence permits
    /// the later separate original-namespace reopen; uncertainty stops here.
    pub fn finish_exact_durable_delivery_admission_v2(&mut self) -> Result<()> {
        use crate::transport::admission_diagnostics_v1::{
            AdmissionWitnessCorrelationV1, AdmissionWitnessStageV1,
        };
        let observer = self.window.admission_observer.clone();
        let stage = std::cell::Cell::new(AdmissionWitnessStageV1::FixtureDrain);
        let result = crate::transport::admission_measure!(
            observer.as_ref(),
            FixtureFinish,
            (|| {
                let Some(request) = &self.durable_delivery.pending else {
                    return Err(AuthorityError::Permission);
                };
                let request = request.clone();
                if self.listener.bound.is_some()
                    || self.listener.server_handles.load(Ordering::Acquire) != 0
                {
                    return Err(AuthorityError::Permission);
                }
                self.drain()?;
                stage.set(AdmissionWitnessStageV1::FixtureReceipt);
                if !self.window.can_select() {
                    return Err(AuthorityError::Uncertain);
                }
                let receipt = self.completed_native_receipt()?;
                if receipt.get("kind").and_then(serde_json::Value::as_str)
                    != Some("durable_delivery_admission_v2_committed")
                {
                    return Err(AuthorityError::Uncertain);
                }
                let committed_head: AuthorityHead = serde_json::from_value(
                    receipt
                        .get("committed_head")
                        .cloned()
                        .ok_or(AuthorityError::CorruptHistory)?,
                )
                .map_err(|_| AuthorityError::CorruptHistory)?;
                {
                    stage.set(AdmissionWitnessStageV1::FixtureCorrelation);
                    // The actual worker has dropped its socket/source/namespace before
                    // emitting completion. This is read-only correlation, not issuance.
                    let journal = crate::witness_locator::open_born_history(
                        self.original_namespace_input(&request.account_id)?,
                    )?;
                    journal.require_born_read_current()?;
                    let connection = journal
                        .connection
                        .lock()
                        .map_err(|_| AuthorityError::Storage)?;
                    let ledger = crate::journal::load(connection.connection())?;
                    if ledger.selected_durable_delivery_admission_v2()? != Some(&request)
                        || ledger.snapshot.head != committed_head
                        || request.expected_head.sequence.checked_add(1)
                            != Some(committed_head.sequence)
                    {
                        if let Some(observer) = &observer {
                            observer.final_correlation(AdmissionWitnessCorrelationV1::Rejected);
                        }
                        return Err(AuthorityError::Uncertain);
                    }
                    if let Some(observer) = &observer {
                        observer.final_correlation(AdmissionWitnessCorrelationV1::Matched);
                    }
                    journal.require_born_read_current()?;
                }
                if self
                    .durable_delivery
                    .committed
                    .contains_key(&request.account_id)
                {
                    return Err(AuthorityError::Conflict);
                }
                self.durable_delivery
                    .committed
                    .insert(request.account_id.clone(), request);
                self.durable_delivery.pending = None;
                Ok(())
            })()
        );
        if let Some(observer) = &observer {
            observer.fixture_result(stage.get(), &result);
        }
        result
    }

    /// Reopen the exact original as history only. Generic mutation denies v2
    /// before old bootstrap replay, operational receipt/key lookup or MAC use.
    pub fn serve_committed_durable_delivery_history_v2(
        &mut self,
        admission_operation_id: &str,
    ) -> Result<EphemeralHistoryServerV1> {
        let request = self
            .durable_delivery
            .committed
            .values()
            .find(|request| request.operation_id == admission_operation_id)
            .ok_or(AuthorityError::Permission)?;
        if self.durable_delivery.pending.is_some()
            || !self.window.can_select()
            || self.listener.server_handles.load(Ordering::Acquire) != 0
            || self.window.input.endpoint != self.listener.address.to_string()
        {
            return Err(AuthorityError::Permission);
        }
        let request = request.clone();
        let input = self.original_namespace_input(&request.account_id)?;
        if self.listener.bound.is_none() {
            let listener =
                TcpListener::bind(self.listener.address).map_err(|_| AuthorityError::Permission)?;
            if listener.local_addr().map_err(|_| AuthorityError::Storage)? != self.listener.address
            {
                return Err(AuthorityError::Authentication);
            }
            self.listener.bound = Some(listener);
        }
        let journal = crate::born_history_server::open_born_history_from_namespace(
            input,
            &self.server_certificate_digest,
            &self.listener.address.to_string(),
        )?;
        {
            let connection = journal
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let ledger = crate::journal::load(connection.connection())?;
            if ledger.selected_durable_delivery_admission_v2()? != Some(&request) {
                return Err(AuthorityError::CorruptHistory);
            }
        }
        self.serve_exact_server(AuthorityServer::new(Arc::new(journal), self.tls.clone()))
    }
}

// Inert comparison metadata only. No keys, native state, lifetime, grant, lease,
// inferred freshness or reconstructed FixturePhase is serializable here.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservedWitnessV2 {
    version: u16,
    installation: Vec<u8>,
    endpoint: String,
    server_name: String,
    witness_id: String,
    network_profile_id: String,
    server_pin: String,
    owner_pin: String,
    writer_pin: String,
    accounts: Vec<PreservedAccountV2>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservedAccountV2 {
    request: OwnerControlRequest,
    original_signed_birth: String,
    original_source_commitment: String,
}
const MAX_PRESERVED_BYTES: usize = 2 * 1024 * 1024;
const ENROLLED: &str = "The exact original witness enrollment and authenticated completion record agree. This is witness enrollment only; signer acknowledgement and active-vault publication remain separate gates.";

// The actual original namespace opener authenticates the registry's complete
// inventory, exact retained intent/completion and database identities first.
// This comparison then covers its original registry namespace + birth target,
// review, genesis and completion commitments plus complete authenticated journal
// history/session data. It is not a substitute for that concrete source opener.
fn original_source_commitment(journal: &crate::AuthorityJournal) -> Result<String> {
    journal.require_born_read_current()?;
    let namespace = journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?
        .namespace_binding_digest_v1()?;
    let connection = journal
        .connection
        .lock()
        .map_err(|_| AuthorityError::Storage)?;
    let ledger = crate::journal::load(connection.connection())?;
    let birth = crate::pending_birth_storage::read(connection.connection(), &ledger.policy)?
        .ok_or(AuthorityError::RecoveryRequired)?;
    let events: u64 =
        connection
            .connection()
            .query_row("SELECT count(*) FROM authority_events", [], |r| r.get(0))?;
    let keys: u64 = connection.connection().query_row(
        "SELECT count(*) FROM authority_session_keys",
        [],
        |r| r.get(0),
    )?;
    let result = crate::digest(
        "wholepact:synthetic-original-delivery-history:v2",
        &(
            namespace,
            birth,
            &ledger.policy,
            &ledger.snapshot,
            &ledger.operations,
            &ledger.sessions,
            &ledger.activated_sessions,
            events,
            keys,
        ),
    )?;
    journal.require_born_read_current()?;
    Ok(result)
}

impl EphemeralNativeWitnessV1 {
    /// Select and authenticate this SAME original account's pristine four-event
    /// bootstrap before the independent Signer prepares its prospective scope.
    /// This has no admission or mutation capability and never adopts DTO phase.
    pub fn serve_original_delivery_bootstrap_history_v2(
        &mut self,
        account_id: &str,
    ) -> Result<EphemeralHistoryServerV1> {
        if self.durable_delivery.historical_only
            || self.durable_delivery.pending.is_some()
            || self.durable_delivery.committed.contains_key(account_id)
            || self.listener.server_handles.load(Ordering::Acquire) != 0
            || !self.window.can_select()
        {
            return Err(AuthorityError::Permission);
        }
        let input = self.original_namespace_input(account_id)?;
        self.rebind_original_delivery_listener_v2()?;
        let journal = crate::born_history_server::open_born_history_from_namespace(
            input,
            &self.server_certificate_digest,
            &self.listener.address.to_string(),
        )?;
        {
            let connection = journal
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let ledger = crate::journal::load(connection.connection())?;
            ledger.require_supported_durable_payment_history_v1()?;
            if ledger.snapshot.head.sequence != 4
                || ledger.operations.len() != 4
                || ledger.selected_durable_payment_admission_v1()?.is_some()
                || ledger.selected_durable_delivery_admission_v2()?.is_some()
            {
                return Err(AuthorityError::PolicyDenied);
            }
        }
        self.serve_exact_server(AuthorityServer::new(Arc::new(journal), self.tls.clone()))
    }

    fn rebind_original_delivery_listener_v2(&mut self) -> Result<()> {
        if self.listener.server_handles.load(Ordering::Acquire) != 0
            || self.window.input.endpoint != self.listener.address.to_string()
            || !self.window.can_select()
        {
            return Err(AuthorityError::Permission);
        }
        if self.listener.bound.is_none() {
            let listener =
                TcpListener::bind(self.listener.address).map_err(|_| AuthorityError::Permission)?;
            if listener.local_addr().map_err(|_| AuthorityError::Storage)? != self.listener.address
            {
                return Err(AuthorityError::Authentication);
            }
            self.listener.bound = Some(listener);
        }
        Ok(())
    }

    /// Consuming lifetime transfer for the actual synthetic originals only.
    /// All Signer workers, credential-origin borrowers, native workers, probes,
    /// journals and history servers must already be drained. Outer qualification
    /// cleanup owns deletion after the genuine fresh-process reader finishes.
    pub fn preserve_durable_delivery_originals_v2(mut self) -> Result<Vec<u8>> {
        if self.durable_delivery.historical_only
            || self.durable_delivery.pending.is_some()
            || self.durable_delivery.committed.is_empty()
            || self.durable_delivery.committed.len() > 2
            || !self.window.can_select()
            || self.listener.server_handles.load(Ordering::Acquire) != 0
        {
            return Err(AuthorityError::Permission);
        }
        let requests: Vec<_> = self.durable_delivery.committed.values().cloned().collect();
        let mut accounts = Vec::new();
        for request in requests {
            let envelope = self
                .durable_delivery
                .original_signed_births
                .get(&request.account_id)
                .ok_or(AuthorityError::RecoveryRequired)?
                .clone();
            if envelope.is_empty() || envelope.len() > crate::MAX_FRAME_BYTES {
                return Err(AuthorityError::Limit);
            }
            let journal = crate::witness_locator::open_born_history(
                self.original_namespace_input(&request.account_id)?,
            )?;
            {
                let connection = journal
                    .connection
                    .lock()
                    .map_err(|_| AuthorityError::Storage)?;
                let ledger = crate::journal::load(connection.connection())?;
                if ledger.selected_durable_delivery_admission_v2()? != Some(&request) {
                    return Err(AuthorityError::CorruptHistory);
                }
            }
            accounts.push(PreservedAccountV2 {
                request,
                original_signed_birth: String::from_utf8(envelope)
                    .map_err(|_| AuthorityError::InvalidBinding)?,
                original_source_commitment: original_source_commitment(&journal)?,
            });
        }
        let writer = wholepact_storage_security::witness_namespace_fs::read_existing_private_file(
            &self.root.join("writer.der"),
            65_536,
        )?;
        let mut descriptor = PreservedWitnessV2 {
            version: 2,
            installation: Vec::new(),
            endpoint: self.window.input.endpoint.clone(),
            server_name: self.window.input.server_name.clone(),
            witness_id: self.window.input.witness_id.clone(),
            network_profile_id: self.window.input.network_profile_id.clone(),
            server_pin: self.server_certificate_digest.clone(),
            owner_pin: crate::transport::certificate_digest(&CertificateDer::from(
                self.owner_certificate.as_slice(),
            )),
            writer_pin: crate::transport::certificate_digest(&CertificateDer::from(
                writer.as_slice(),
            )),
            accounts,
        };
        // Reject size before irreversible ownership transfer; the storage leaf's
        // bounded descriptor adds at most 16 KiB represented as JSON bytes.
        if serde_json::to_vec(&descriptor)
            .map_err(|_| AuthorityError::InvalidBinding)?
            .len()
            > MAX_PRESERVED_BYTES - 64 * 1024
        {
            return Err(AuthorityError::Limit);
        }
        let installation = self.installation.clone();
        self.window.input.synthetic_installation.take();
        drop(self); // revokes/drains the actual native owner and closes its socket
        descriptor.installation = installation.preserve_original_for_process_exit_v2()?;
        let bytes = serde_json::to_vec(&descriptor).map_err(|_| AuthorityError::InvalidBinding)?;
        if bytes.len() > MAX_PRESERVED_BYTES {
            return Err(AuthorityError::Limit);
        }
        Ok(bytes)
    }

    /// Reopen only the actual preserved original files. Inert metadata never
    /// restores a native phase: each selected journal is fully authenticated and
    /// then separately passes the SAME real native existing-committed audit UI.
    /// No setup, new envelope, signature, genesis, account, key or deadline exists.
    pub fn reopen_durable_delivery_originals_v2(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PRESERVED_BYTES {
            return Err(AuthorityError::Limit);
        }
        let descriptor: PreservedWitnessV2 =
            serde_json::from_slice(bytes).map_err(|_| AuthorityError::InvalidBinding)?;
        if descriptor.version != 2
            || descriptor.accounts.is_empty()
            || descriptor.accounts.len() > 2
            || descriptor.server_name != "localhost"
            || descriptor.network_profile_id != PROFILE
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let address: std::net::SocketAddr = descriptor
            .endpoint
            .parse()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        if !address.ip().is_loopback()
            || address.port() == 0
            || address.to_string() != descriptor.endpoint
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut shared_plan = None;
        for account in &descriptor.accounts {
            if !seen.insert(account.request.account_id.clone())
                || account.original_signed_birth.is_empty()
                || account.original_signed_birth.len() > crate::MAX_FRAME_BYTES
            {
                return Err(AuthorityError::InvalidBinding);
            }
            crate::hash(&account.original_source_commitment)?;
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } =
                &account.request.control
            else {
                return Err(AuthorityError::Permission);
            };
            record.validate()?;
            let plan = record.scope.shared_plan_digest()?;
            if shared_plan
                .as_ref()
                .is_some_and(|original| original != &plan)
            {
                return Err(AuthorityError::Conflict);
            }
            shared_plan = Some(plan);
            if record.scope.witness.endpoint != descriptor.endpoint
                || record.scope.witness.witness_id != descriptor.witness_id
                || record.scope.witness.pinned_server_certificate_digest != descriptor.server_pin
                || record.scope.authorization.writer_certificate_digest != descriptor.writer_pin
            {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        let installation =
            EphemeralWitnessInstallation::reopen_preserved_original_v2(&descriptor.installation)?;
        let root = installation
            .probe()?
            .root_path()
            .parent()
            .ok_or(AuthorityError::Storage)?
            .to_path_buf();
        let read = |name: &str| -> Result<Zeroizing<Vec<u8>>> {
            wholepact_storage_security::witness_namespace_fs::read_existing_private_file(
                &root.join(name),
                65_536,
            )
            .map_err(Into::into)
        };
        let certificate = CertificateDer::from(read("server.der")?.to_vec());
        let owner_certificate = read("owner.der")?.to_vec();
        let writer = read("writer.der")?;
        if crate::transport::certificate_digest(&certificate) != descriptor.server_pin
            || crate::transport::certificate_digest(&CertificateDer::from(
                owner_certificate.as_slice(),
            )) != descriptor.owner_pin
            || crate::transport::certificate_digest(&CertificateDer::from(writer.as_slice()))
                != descriptor.writer_pin
        {
            return Err(AuthorityError::Authentication);
        }
        let tls = ServerTls::new(
            vec![CertificateDer::from(read("ca.der")?.to_vec())],
            vec![certificate],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(read("server.pk8")?.to_vec())),
        )?;
        let mut window = Window::new();
        window.input.endpoint = descriptor.endpoint;
        window.input.server_name = descriptor.server_name;
        window.input.witness_id = descriptor.witness_id;
        window.input.network_profile_id = descriptor.network_profile_id;
        window.input.pinned_server_certificate_digest = descriptor.server_pin.clone();
        window.input.storage_key_file = root
            .join("synthetic-namespace.key")
            .to_str()
            .ok_or(AuthorityError::InvalidBinding)?
            .into();
        window.input.owner_certificate_hex = Zeroizing::new(hex::encode(&owner_certificate));
        window.input.synthetic_installation = Some(installation.clone());
        let context = egui::Context::default();
        configure_style(&context);
        let mut result = Self {
            window,
            context,
            qualification_entry: None,
            construction_client_grants: std::collections::BTreeSet::new(),
            construction_client_scope_revoked: Arc::new(AtomicBool::new(true)),
            installation,
            listener: OriginalListenerV1 {
                bound: None,
                address,
                server_handles: Arc::new(AtomicUsize::new(0)),
            },
            durable_payment: durable_payment_v1::FixturePhaseV1::Idle,
            financial_continuation: financial_continuation_v1::FixtureFinancialPhaseV1::default(),
            durable_delivery: FixturePhaseV2 {
                historical_only: true,
                ..FixturePhaseV2::default()
            },
            tls,
            server_certificate_digest: descriptor.server_pin,
            owner_certificate,
            root,
        };
        for expected in descriptor.accounts {
            let account_id = expected.request.account_id.clone();
            let (before, actual) = {
                let journal = crate::witness_locator::open_born_history(
                    result.original_namespace_input(&account_id)?,
                )?;
                let actual = {
                    let connection = journal
                        .connection
                        .lock()
                        .map_err(|_| AuthorityError::Storage)?;
                    let ledger = crate::journal::load(connection.connection())?;
                    ledger
                        .selected_durable_delivery_admission_v2()?
                        .ok_or(AuthorityError::Permission)?
                        .clone()
                };
                if actual != expected.request {
                    return Err(AuthorityError::CorruptHistory);
                }
                let before = original_source_commitment(&journal)?;
                if before != expected.original_source_commitment {
                    return Err(AuthorityError::CorruptHistory);
                }
                (before, actual)
            };
            // The exact original signed public bytes are ONLY native form input.
            // Its signature, request and original completion are independently
            // verified by the maintained prepare worker against actual originals.
            result.window.input.signed_request_json =
                Zeroizing::new(expected.original_signed_birth.clone());
            result.durable_delivery.native_historical_audit = true;
            result.click(ENROLL)?;
            result.drain()?;
            let Some(pending) = result.window.pending.as_ref() else {
                return Err(AuthorityError::Permission);
            };
            let Proposal::Enrollment(proposal) = &pending.prepared.proposal else {
                return Err(AuthorityError::Permission);
            };
            // This maintained exhaustive accessor returns None ONLY for
            // BirthDisposition::ExistingCommittedAuditOnly. Reject every absent,
            // incomplete or new target BEFORE any final native decision.
            if proposal.first_commit_deadline_ms().is_some() || pending.phase != Phase::Reading {
                return Err(AuthorityError::Permission);
            }
            proposal.check_current()?;
            result.approve_exact()?;
            result.durable_delivery.native_historical_audit = false;
            // Static local WorkResult::Enrolled outcome only, not receipt JSON or
            // user-controlled text. Failed native workers cannot pass unchanged
            // history comparison alone as evidence of a successful native entry.
            if result.window.message != ENROLLED {
                return Err(AuthorityError::Uncertain);
            }
            let journal = crate::witness_locator::open_born_history(
                result.original_namespace_input(&account_id)?,
            )?;
            if original_source_commitment(&journal)? != before {
                return Err(AuthorityError::CorruptHistory);
            }
            drop(journal);
            result.durable_delivery.original_signed_births.insert(
                account_id.clone(),
                expected.original_signed_birth.into_bytes(),
            );
            // Map insertion uses the request read from the real full journal,
            // and occurs only after the fresh final-primary native audit.
            result.durable_delivery.committed.insert(account_id, actual);
        }
        Ok(result)
    }

    /// Deny-only audit of the actual originals. Retained bootstrap keys remain
    /// required by complete-history integrity; no operational key lookup or MAC
    /// is authorized. No denial is accepted unless the unchanged early v2 gate
    /// independently returns PolicyDenied for every exact attempted mutation.
    pub fn require_durable_delivery_financial_denials_v2(
        &mut self,
        operation_id: &str,
    ) -> Result<()> {
        if self.durable_delivery.pending.is_some()
            || !self.window.can_select()
            || self.listener.server_handles.load(Ordering::Acquire) != 0
        {
            return Err(AuthorityError::Permission);
        }
        let request = self
            .durable_delivery
            .committed
            .values()
            .find(|r| r.operation_id == operation_id)
            .ok_or(AuthorityError::Permission)?
            .clone();
        let journal = crate::witness_locator::open_born_history(
            self.original_namespace_input(&request.account_id)?,
        )?;
        let before = original_source_commitment(&journal)?;
        let attempts = {
            let connection = journal
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let ledger = crate::journal::load(connection.connection())?;
            if ledger.selected_durable_delivery_admission_v2()? != Some(&request) {
                return Err(AuthorityError::CorruptHistory);
            }
            let mut attempts = Vec::new();
            for (mutation, _, _) in ledger.operations.values() {
                match mutation {
                    crate::AuthorityMutation::AcquireWriter(_) => attempts.push((
                        ledger.policy.initial_writer_certificate_digest.clone(),
                        mutation.clone(),
                    )),
                    crate::AuthorityMutation::OwnerControl(OwnerControlRequest {
                        control: OwnerControl::ActivateWriter { .. },
                        ..
                    }) => attempts.push((
                        ledger.policy.owner_certificate_digest.clone(),
                        mutation.clone(),
                    )),
                    _ => {}
                }
            }
            if attempts.len() != 2 {
                return Err(AuthorityError::CorruptHistory);
            }
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control
            else {
                return Err(AuthorityError::Permission);
            };
            let terms = &record.scope.authorization;
            let fixed = &terms.fixed;
            let reserve = crate::ReserveAuthorization {
                automation: None,
                operation_id: terms.authorization_id.clone(),
                account_id: terms.identity.account_id.clone(),
                network_profile_id: terms.identity.network_profile_id.clone(),
                writer_epoch: request.writer_epoch,
                expected_head: ledger.snapshot.head.clone(),
                authorization_id: terms.authorization_id.clone(),
                original_consent_ref: record.scope.digest()?,
                enrollment_ref: terms.original_enrollment_ref.clone(),
                accepted_manifest_ref: record.scope.accepted_manifest_ref.clone(),
                agreement_id: fixed.agreement_id.clone(),
                obligation_id: fixed.obligation_id.clone(),
                proposal_id: fixed.proposal_id.clone(),
                proposal_digest: fixed.proposal_digest.clone(),
                manifest_digest: fixed.manifest_digest.clone(),
                effects_digest: fixed.effects_commitment.clone(),
                artifact_digest: fixed.proved_artifact_digest.clone(),
                review_binding: fixed.review_binding.clone(),
                recipient_scope_digest: terms.recipient_policy_scope_digest.clone(),
                inputs: terms.inputs.clone(),
                maximum_debit_zatoshis: terms.maximum_debit_zatoshis,
                fee_share_zatoshis: terms.fee_share_zatoshis,
                transaction_fee_zatoshis: terms.transaction_fee_zatoshis,
                transaction_expiry_height: fixed.expiry_height,
                reviewed_at_ms: record.scope.delivery.valid_from_ms,
                permit_expires_at_ms: record.scope.delivery.valid_until_ms,
            };
            reserve.validate()?;
            attempts.push((
                terms.writer_certificate_digest.clone(),
                crate::AuthorityMutation::ReserveAuthorization(Box::new(reserve)),
            ));
            for (_, mutation) in &attempts {
                if !matches!(
                    ledger.require_delivery_admission_only_v2(mutation),
                    Err(AuthorityError::PolicyDenied)
                ) {
                    return Err(AuthorityError::Permission);
                }
            }
            attempts
        };
        for (peer, mutation) in attempts {
            // Synthetic wrapper enters the real early gate before constructing
            // any operational proof. Actual owner/read-only rejection is also
            // permitted, but unexpected authentication/expiry errors are not.
            if !matches!(
                journal.mutate(&peer, mutation, crate::now_ms()?),
                Err(AuthorityError::PolicyDenied) | Err(AuthorityError::Permission)
            ) {
                return Err(AuthorityError::Permission);
            }
        }
        if original_source_commitment(&journal)? != before {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(())
    }
}
