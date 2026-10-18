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
        require_exact_retained_request(
            prepared
                .proposal
                .retained_request_for_synthetic_qualification(),
            request,
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request_data() -> OwnerControlRequest {
        let (birth, _, events, terms) = crate::durable_payment_v1::tests::fixture();
        let request = crate::durable_payment_v1::tests::admission(&birth, &events, terms);
        let OwnerControl::AdmitDurablePaymentV1 { record } = &request.control else {
            panic!("expected inert durable admission data");
        };
        assert!(record
            .validate_request(&request, &birth.request.disclosure)
            .is_ok());
        request
    }

    #[test]
    fn pure_durable_payment_human_review_footer_is_not_standalone_json() {
        // Pure presentation-format regression, not native execution. Reproduce
        // Prepared::new's human footer with the actual Window sanitizer and
        // notice, without constructing a proposal, source, decision or owner.
        let display =
            serde_json::to_string_pretty(&serde_json::json!({ "request": request_data() }))
                .unwrap();
        let digest = crate::durable_payment_v1::tests::h('f');
        assert!(serde_json::from_str::<serde_json::Value>(&display).is_ok());
        let human_review = inert_text(&format!(
            "{display}\n\nExact owner review digest: {digest}\n\n{TRUST_NOTICE}"
        ));
        assert!(serde_json::from_str::<serde_json::Value>(&human_review).is_err());
    }

    #[test]
    fn pure_durable_payment_retained_request_correlation_is_exact() {
        // Genuine-shaped inert request data from pure history helpers. The
        // same correlation helper runs before the fixture's real native click.
        let retained = request_data();
        assert!(require_exact_retained_request(&retained, &retained.clone()).is_ok());
        fn change_digest(value: &mut String) {
            let first = if value.starts_with('0') { "1" } else { "0" };
            value.replace_range(..1, first);
        }
        let changes: [(&str, fn(&mut OwnerControlRequest)); 9] = [
            ("operation", |r| r.operation_id.push_str("-different")),
            ("account", |r| change_digest(&mut r.account_id)),
            ("network", |r| r.network_profile_id.push_str("-different")),
            ("head sequence", |r| r.expected_head.sequence += 1),
            ("head digest", |r| {
                change_digest(&mut r.expected_head.digest)
            }),
            ("epoch", |r| r.writer_epoch += 1),
            ("control", |r| r.control = OwnerControl::Pause),
            ("fixed revision", |r| {
                let OwnerControl::AdmitDurablePaymentV1 { record } = &mut r.control else {
                    panic!("expected inert durable admission data");
                };
                record.terms.fixed.revision += 1;
            }),
            ("fixed artifact digest", |r| {
                let OwnerControl::AdmitDurablePaymentV1 { record } = &mut r.control else {
                    panic!("expected inert durable admission data");
                };
                change_digest(&mut record.terms.fixed.proved_artifact_digest);
            }),
        ];
        for (field, change) in changes {
            let mut requested = retained.clone();
            change(&mut requested);
            assert!(
                matches!(
                    require_exact_retained_request(&retained, &requested),
                    Err(AuthorityError::Conflict)
                ),
                "changed {field} must not correlate"
            );
        }
    }
}
