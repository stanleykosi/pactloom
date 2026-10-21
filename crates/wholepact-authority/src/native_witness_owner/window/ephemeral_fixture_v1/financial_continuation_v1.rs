//! Isolated qualification drives the real new native controls. No fixture
//! constructs a native decision, financial source, journal row or capability.
use super::durable_delivery_admission_v2::FixturePhaseV2;
use super::*;
use crate::{AuthorityHead, OwnerControl, OwnerControlRequest};
const PREPARE: &str = "Prepare original TLS listener and exact financial continuation for review";
#[derive(Default)]
pub(super) struct FixtureFinancialPhaseV1 {
    pending: Option<OwnerControlRequest>,
    committed: std::collections::BTreeMap<String, OwnerControlRequest>,
}
impl FixtureFinancialPhaseV1 {
    pub(super) fn is_idle_for_original_transport_v1(&self) -> bool {
        self.pending.is_none() && self.committed.is_empty()
    }
}
impl EphemeralNativeWitnessV1 {
    pub fn start_exact_financial_continuation_v1(
        &mut self,
        account_id: &str,
        request: &OwnerControlRequest,
    ) -> Result<()> {
        crate::hash(account_id)?;
        if !self.window.can_select()
            || self.financial_continuation.pending.is_some()
            || self
                .financial_continuation
                .committed
                .contains_key(account_id)
            || self.financial_continuation.committed.len() >= 2
            || self.listener.server_handles.load(Ordering::Acquire) != 0
            || request.account_id != account_id
            || request.network_profile_id != self.window.input.network_profile_id
        {
            return Err(AuthorityError::Permission);
        }
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
            return Err(AuthorityError::Permission);
        };
        record.validate_request(request, &record.terms.scope.witness)?;
        // The existing original B1 commitment is required, not imported as
        // authority. The production preparation audits its actual journal.
        let original = self
            .durable_delivery
            .committed
            .get(account_id)
            .ok_or(AuthorityError::Permission)?;
        if original.operation_id != record.terms.original_delivery_operation_id {
            return Err(AuthorityError::Conflict);
        }
        for committed in self.financial_continuation.committed.values() {
            let OwnerControl::AdmitFinancialContinuationV1 { record: prior } = &committed.control
            else {
                return Err(AuthorityError::CorruptHistory);
            };
            if prior.terms.scope.shared_plan_digest()? != record.terms.scope.shared_plan_digest()? {
                return Err(AuthorityError::Conflict);
            }
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
        let address = self.listener.address;
        if self.window.input.endpoint != address.to_string() {
            return Err(AuthorityError::Authentication);
        }
        drop(self.original_namespace_input(account_id)?);
        let path = |name: &str| {
            self.root
                .join(name)
                .to_str()
                .map(str::to_owned)
                .ok_or(AuthorityError::InvalidBinding)
        };
        self.window
            .input
            .financial_continuation_v1
            .set_synthetic_form_data(
                serde_json::to_string(request).map_err(|_| AuthorityError::InvalidBinding)?,
                path("server.der")?,
                path("server.pk8")?,
                path("ca.der")?,
            );
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
        let Proposal::FinancialContinuationV1(prepared) = &pending.prepared.proposal else {
            return Err(AuthorityError::Permission);
        };
        if pending.phase != Phase::Reading
            || prepared
                .listener
                .local_addr()
                .map_err(|_| AuthorityError::Storage)?
                != address
            || prepared
                .proposal
                .retained_request_for_synthetic_qualification()
                != request
        {
            return Err(AuthorityError::Authentication);
        }
        prepared
            .proposal
            .require_endpoint(&self.server_certificate_digest, &address.to_string())?;
        self.financial_continuation.pending = Some(request.clone());
        self.start_approve_exact()?;
        if self.window.job.is_none() || self.window.pending.is_some() {
            return Err(AuthorityError::Uncertain);
        }
        Ok(())
    }
    pub fn finish_exact_financial_continuation_v1(&mut self) -> Result<()> {
        let request = self
            .financial_continuation
            .pending
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .clone();
        if self.listener.bound.is_some()
            || self.listener.server_handles.load(Ordering::Acquire) != 0
        {
            return Err(AuthorityError::Permission);
        }
        self.drain()?;
        if !self.window.can_select() {
            return Err(AuthorityError::Uncertain);
        }
        let receipt = self.completed_native_receipt()?;
        if receipt.get("kind").and_then(serde_json::Value::as_str)
            != Some("financial_continuation_v1_committed")
        {
            return Err(AuthorityError::Uncertain);
        }
        let head: AuthorityHead = serde_json::from_value(
            receipt
                .get("committed_head")
                .cloned()
                .ok_or(AuthorityError::CorruptHistory)?,
        )
        .map_err(|_| AuthorityError::CorruptHistory)?;
        let journal = crate::witness_locator::open_born_financial_history_v1(
            self.original_namespace_input(&request.account_id)?,
        )?;
        journal.require_born_read_current()?;
        {
            let connection = journal
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let ledger = crate::journal::load_financial_continuation_v1(connection.connection())?;
            if ledger.selected_financial_continuation_v1()? != Some(&request)
                || ledger.snapshot.head != head
                || request.expected_head.sequence.checked_add(1) != Some(head.sequence)
            {
                return Err(AuthorityError::Uncertain);
            }
        }
        journal.require_born_read_current()?;
        if self
            .financial_continuation
            .committed
            .insert(request.account_id.clone(), request)
            .is_some()
        {
            return Err(AuthorityError::Conflict);
        }
        self.financial_continuation.pending = None;
        Ok(())
    }
}

impl EphemeralNativeWitnessV1 {
    /// A separate exact original configured serving purpose, after the prior
    /// Window listener has drained. This cannot manufacture a financial record.
    pub fn serve_committed_financial_signing_v1(
        &mut self,
        continuation_operation_id: &str,
    ) -> Result<EphemeralHistoryServerV1> {
        let request = self
            .financial_continuation
            .committed
            .values()
            .find(|request| request.operation_id == continuation_operation_id)
            .ok_or(AuthorityError::Permission)?
            .clone();
        if self.financial_continuation.pending.is_some()
            || self.listener.server_handles.load(Ordering::Acquire) != 0
            || !self.window.can_select()
        {
            return Err(AuthorityError::Permission);
        }
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
        let server = AuthorityServer::from_born_financial_signing_namespace_v1(
            input,
            continuation_operation_id,
            self.tls.clone(),
            &self.listener.address.to_string(),
        )?;
        self.serve_exact_server(server)
    }
}

// Inert comparison metadata only. No keys, native state, lifetime, grant, lease,
// inferred freshness or reconstructed FixturePhase is serializable here.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservedFinancialWitnessV1 {
    version: u16,
    installation: Vec<u8>,
    endpoint: String,
    server_name: String,
    witness_id: String,
    network_profile_id: String,
    server_pin: String,
    owner_pin: String,
    writer_pin: String,
    accounts: Vec<PreservedFinancialAccountV1>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservedFinancialAccountV1 {
    request: OwnerControlRequest,
    original_signed_birth: String,
    original_source_commitment: String,
}
const MAX_PRESERVED_BYTES: usize = 2 * 1024 * 1024;

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
    let ledger = crate::journal::load_financial_continuation_v1(connection.connection())?;
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
        "wholepact:synthetic-original-financial-history:v1",
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
    pub fn preserve_financial_originals_v1(mut self) -> Result<Vec<u8>> {
        if self.financial_continuation.pending.is_some()
            || self.financial_continuation.committed.is_empty()
            || self.financial_continuation.committed.len() > 2
            || !self.window.can_select()
            || self.listener.server_handles.load(Ordering::Acquire) != 0
        {
            return Err(AuthorityError::Permission);
        }
        let requests: Vec<_> = self
            .financial_continuation
            .committed
            .values()
            .cloned()
            .collect();
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
            let journal = crate::witness_locator::open_born_financial_history_v1(
                self.original_namespace_input(&request.account_id)?,
            )?;
            {
                let connection = journal
                    .connection
                    .lock()
                    .map_err(|_| AuthorityError::Storage)?;
                let ledger =
                    crate::journal::load_financial_continuation_v1(connection.connection())?;
                if ledger.selected_financial_continuation_v1()? != Some(&request) {
                    return Err(AuthorityError::CorruptHistory);
                }
            }
            accounts.push(PreservedFinancialAccountV1 {
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
        let mut descriptor = PreservedFinancialWitnessV1 {
            version: 1,
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

    /// Recover configured service custody from actual original encrypted files.
    /// This does not restore human read/effect consent or any native phase.
    /// No setup, new envelope, signature, genesis, account, key or deadline exists.
    pub fn reopen_financial_originals_v1(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PRESERVED_BYTES {
            return Err(AuthorityError::Limit);
        }
        let descriptor: PreservedFinancialWitnessV1 =
            serde_json::from_slice(bytes).map_err(|_| AuthorityError::InvalidBinding)?;
        if descriptor.version != 1
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
            let OwnerControl::AdmitFinancialContinuationV1 { record } = &account.request.control
            else {
                return Err(AuthorityError::Permission);
            };
            record.validate()?;
            let plan = record.terms.scope.shared_plan_digest()?;
            if shared_plan
                .as_ref()
                .is_some_and(|original| original != &plan)
            {
                return Err(AuthorityError::Conflict);
            }
            shared_plan = Some(plan);
            if record.terms.scope.witness.endpoint != descriptor.endpoint
                || record.terms.scope.witness.witness_id != descriptor.witness_id
                || record.terms.scope.witness.pinned_server_certificate_digest
                    != descriptor.server_pin
                || record.terms.scope.authorization.writer_certificate_digest
                    != descriptor.writer_pin
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
                server_join_failed: Arc::new(AtomicBool::new(false)),
            },
            durable_payment: durable_payment_v1::FixturePhaseV1::Idle,
            financial_continuation: financial_continuation_v1::FixtureFinancialPhaseV1::default(),
            durable_delivery: {
                let mut phase = FixturePhaseV2::default();
                phase.historical_only = true;
                phase
            },
            tls,
            server_certificate_digest: descriptor.server_pin,
            owner_certificate,
            root,
        };
        for expected in descriptor.accounts {
            let account_id = expected.request.account_id.clone();
            let (before, actual) = {
                let journal = crate::witness_locator::open_born_financial_history_v1(
                    result.original_namespace_input(&account_id)?,
                )?;
                let actual = {
                    let connection = journal
                        .connection
                        .lock()
                        .map_err(|_| AuthorityError::Storage)?;
                    let ledger =
                        crate::journal::load_financial_continuation_v1(connection.connection())?;
                    ledger
                        .selected_financial_continuation_v1()?
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
            // Only configured service custody is recovered. No native human
            // decision, read lease, effect grant or deadline is deserialized.
            let journal = crate::witness_locator::open_born_financial_history_v1(
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
            // Serving scope comes from the fully authenticated actual history.
            result
                .financial_continuation
                .committed
                .insert(account_id, actual);
        }
        Ok(result)
    }
}

impl EphemeralNativeWitnessV1 {
    pub fn serve_committed_completed_dispatch_v1(
        &mut self,
        continuation_operation_id: &str,
    ) -> Result<EphemeralHistoryServerV1> {
        let request = self
            .financial_continuation
            .committed
            .values()
            .find(|request| request.operation_id == continuation_operation_id)
            .ok_or(AuthorityError::Permission)?
            .clone();
        if self.financial_continuation.pending.is_some()
            || self.listener.server_handles.load(Ordering::Acquire) != 0
            || !self.window.can_select()
        {
            return Err(AuthorityError::Permission);
        }
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
        let server = AuthorityServer::from_born_completed_dispatch_namespace_v1(
            input,
            continuation_operation_id,
            self.tls.clone(),
            &self.listener.address.to_string(),
        )?;
        self.serve_exact_server(server)
    }
}

impl EphemeralNativeWitnessV1 {
    /// Two logical original account sources, not two independent server processes.
    pub fn serve_committed_completed_dispatch_pair_v1(
        &mut self,
    ) -> Result<EphemeralHistoryServerV1> {
        if self.financial_continuation.pending.is_some()
            || self.financial_continuation.committed.len() != 2
            || self.listener.server_handles.load(Ordering::Acquire) != 0
            || !self.window.can_select()
        {
            return Err(AuthorityError::Permission);
        }
        let requests: Vec<_> = self
            .financial_continuation
            .committed
            .values()
            .cloned()
            .collect();
        let mut inputs = Vec::new();
        for request in requests {
            inputs.push((
                self.original_namespace_input(&request.account_id)?,
                request.operation_id,
            ));
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
        let server = AuthorityServer::from_born_completed_dispatch_namespaces_v1(
            inputs,
            self.tls.clone(),
            &self.listener.address.to_string(),
        )?;
        self.serve_exact_server(server)
    }
}
