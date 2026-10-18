//! Synthetic pointer delivery over the real original-owner admission window.
//! Requests and phase observations are inert data, never native approval,
//! financial source/scope, a publication lease or a manufactured journal row.
use super::*;
use crate::{AuthorityHead, OwnerControl, OwnerControlRequest};

const PREPARE: &str = "Prepare original TLS listener and exact durable record for review";

// This fixture bookkeeping only prevents out-of-order calls. Every transition
// below observes the real Window result and/or original immutable journal.
pub(super) enum FixturePhaseV1 {
    Idle,
    Admitting(OwnerControlRequest),
    Verified(OwnerControlRequest),
}

impl EphemeralNativeWitnessV1 {
    /// The caller first drops its informational server, after the signer has
    /// finished preparing this actual request from the imported fixed source.
    /// This starts the real final-primary-click worker but does not wait for the
    /// independent signer's retained-intent-first owner-mTLS dispatch.
    pub fn start_exact_durable_payment_admission(
        &mut self,
        account_id: &str,
        request: &OwnerControlRequest,
    ) -> Result<()> {
        crate::hash(account_id)?;
        if !self.window.can_select()
            || !matches!(&self.durable_payment, FixturePhaseV1::Idle)
            || self.listener.server_handles.load(Ordering::Acquire) != 0
            || request.account_id != account_id
            || request.network_profile_id != self.window.input.network_profile_id
            || !matches!(&request.control, OwnerControl::AdmitDurablePaymentV1 { .. })
        {
            return Err(AuthorityError::Permission);
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
            .durable_payment_v1
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
        let Proposal::DurablePaymentV1(prepared) = &pending.prepared.proposal else {
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
        let display: serde_json::Value = serde_json::from_str(&pending.prepared.display)
            .map_err(|_| AuthorityError::CorruptHistory)?;
        let displayed_request: OwnerControlRequest = serde_json::from_value(
            display
                .get("request")
                .cloned()
                .ok_or(AuthorityError::CorruptHistory)?,
        )
        .map_err(|_| AuthorityError::CorruptHistory)?;
        if &displayed_request != request {
            return Err(AuthorityError::Conflict);
        }
        self.durable_payment = FixturePhaseV1::Admitting(request.clone());
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
    pub fn finish_exact_durable_payment_admission(&mut self) -> Result<()> {
        let FixturePhaseV1::Admitting(request) = &self.durable_payment else {
            return Err(AuthorityError::Permission);
        };
        let request = request.clone();
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
            != Some("durable_payment_admission_v1_committed")
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
            ledger.require_supported_durable_payment_history_v1()?;
            if ledger.durable_payment_admission_v1(&request.operation_id)? != Some(&request)
                || ledger.snapshot.head != committed_head
                || request.expected_head.sequence.checked_add(1) != Some(committed_head.sequence)
            {
                return Err(AuthorityError::Uncertain);
            }
            journal.require_born_read_current()?;
        }
        self.durable_payment = FixturePhaseV1::Verified(request);
        Ok(())
    }

    /// Reopen only the exact committed record through the shared production
    /// opener with the actual retained nominal installation and same endpoint.
    /// This creates no financial record or authority outside that normal opener.
    pub fn serve_committed_durable_payment(
        &mut self,
        admission_operation_id: &str,
    ) -> Result<EphemeralHistoryServerV1> {
        let FixturePhaseV1::Verified(request) = &self.durable_payment else {
            return Err(AuthorityError::Permission);
        };
        if request.operation_id != admission_operation_id
            || request.account_id != self.window.input.expected_account_id
            || !self.window.can_select()
            || self.listener.bound.is_some()
            || self.listener.server_handles.load(Ordering::Acquire) != 0
            || self.window.input.endpoint != self.listener.address.to_string()
        {
            return Err(AuthorityError::Permission);
        }
        let account_id = request.account_id.clone();
        let input = self.original_namespace_input(&account_id)?;
        let listener =
            TcpListener::bind(self.listener.address).map_err(|_| AuthorityError::Permission)?;
        let actual_listen = listener.local_addr().map_err(|_| AuthorityError::Storage)?;
        if actual_listen != self.listener.address {
            return Err(AuthorityError::Authentication);
        }
        let server = AuthorityServer::from_born_durable_payment_namespace_v1(
            input,
            admission_operation_id,
            self.tls.clone(),
            &actual_listen.to_string(),
        )?;
        self.listener.bound = Some(listener);
        let serving = self.serve_exact_server(server)?;
        self.durable_payment = FixturePhaseV1::Idle;
        Ok(serving)
    }
}
