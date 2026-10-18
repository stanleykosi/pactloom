//! Additive deny-only custody checks around the maintained TLS kernel. These
//! callbacks do not authenticate a peer or create permission. Checks surround
//! connect, each handshake iteration, frame construction/write/read and response
//! validation, NOT every internal write_all syscall. A sent mutation can remain
//! uncertain after cancellation; only exact authenticated history resolves it.
use super::born_offline_witness_v1::lock_born_session_until;
use super::*;

impl AuthorityClient {
    /// After dispatch may have started, ANY error (including cancellation or
    /// Permission from a restriction callback) requires exact retained-history
    /// inspection. Keep the original request, ID, head and workspace; errors do
    /// not prove rollback, authorize replacement, or refund exposure.
    pub fn admit_durable_payment_v1_checked_until(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        check_current()?;
        let OwnerControl::AdmitDurablePaymentV1 { record } = &request.control else {
            return Err(AuthorityError::Permission);
        };
        record.validate_request(request, &self.disclosure_descriptor())?;
        self.durable_payment_control_checked_v1(request, deadline, &mut check_current)
    }

    /// Retain this same client's original request/key across every uncertain
    /// error. A callback denial after dispatch is not proof of rollback; inspect
    /// exact history and never allocate a replacement session or operation ID.
    pub fn acquire_durable_payment_writer_v1_checked_until(
        &self,
        history: &ReconciledAuthorityHistory,
        admission_operation_id: &str,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<WriterSessionReceipt> {
        check_current()?;
        require_before_caller_deadline(deadline)?;
        history.durable_payment_online_permits_v1(admission_operation_id)?;
        let admission = history
            .durable_payment_admission_v1(admission_operation_id)?
            .ok_or(AuthorityError::Permission)?;
        let OwnerControl::AdmitDurablePaymentV1 { record } = &admission.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        let operation_id = record.acquire_operation_id(admission)?;
        if history.disclosure != self.disclosure_descriptor()
            || history.snapshot.writer_certificate_digest != self.tls.client_certificate
            || record.terms.writer_certificate_digest != self.tls.client_certificate
        {
            return Err(AuthorityError::Permission);
        }
        if history.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        let mut state = lock_born_session_until(&self.session, deadline, &mut check_current)?;
        if let Some(session) = state.as_ref() {
            if session.request.operation_id != operation_id
                || session.request.expected_head != history.snapshot.head
            {
                return Err(AuthorityError::Conflict);
            }
        } else if history.committed_operation_ids.contains(&operation_id) {
            // A used operation without this client's retained original key is
            // recovery, never a new exporter/session with the same or fresh ID.
            return Err(AuthorityError::RecoveryRequired);
        }
        let response = self.call_with_inner_checked(
            |exporter| {
                let retry = state.is_some();
                if state.is_none() {
                    *state = Some(ClientWriterSession {
                        request: AcquireWriterRequest {
                            operation_id: operation_id.clone(),
                            account_id: self.account.clone(),
                            network_profile_id: self.network.clone(),
                            writer_epoch: history.snapshot.writer_epoch,
                            expected_head: history.snapshot.head.clone(),
                            reconciled_history_digest: history.history_digest()?,
                            session_id: crate::session::session_id(exporter),
                            disclosure: self.disclosure_descriptor(),
                        },
                        key: Zeroizing::new(*exporter),
                        receipt: None,
                    });
                }
                let session = state.as_ref().ok_or(AuthorityError::SessionRequired)?;
                let mutation = AuthorityMutation::AcquireWriter(session.request.clone());
                let session_proof = if retry {
                    Some(crate::session::proof(
                        &session.key,
                        (
                            &session.request.session_id,
                            &session.request.disclosure,
                            session.request.writer_epoch,
                        ),
                        exporter,
                        &mutation,
                    )?)
                } else {
                    None
                };
                Ok(WireRequest::Mutate {
                    mutation: Box::new(mutation),
                    session_proof,
                })
            },
            Some(deadline),
            &mut check_current,
        )?;
        check_current()?;
        let WireResponse::Mutation(MutationResult::WriterPending(receipt)) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        let session = state.as_mut().ok_or(AuthorityError::SessionRequired)?;
        if receipt.session_id != session.request.session_id
            || receipt.writer_certificate_digest != self.tls.client_certificate
            || receipt.writer_epoch != session.request.writer_epoch
            || receipt.reconciled_head != session.request.expected_head
            || receipt.reconciled_history_digest != session.request.reconciled_history_digest
            || receipt.disclosure != session.request.disclosure
            || receipt.expires_at_ms <= receipt.acquired_at_ms
            || receipt.expires_at_ms > record.terms.valid_until_ms
        {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &session.request.expected_head,
            &receipt.acquired_head,
            AuthorityMutation::AcquireWriter(session.request.clone()),
            receipt.acquired_at_ms,
            None,
        )?;
        // Retain the authentic receipt even when a final restriction fails. It
        // remains inert until all checks pass; deleting it would lose retry state.
        session.receipt = Some(receipt.clone());
        check_current()?;
        require_before_caller_deadline(deadline)?;
        Ok(receipt)
    }

    /// Exact owner-client activation. Any post-dispatch error requires retained
    /// history reconciliation with this same request; never copy a writer key
    /// into the owner client or infer cancellation rolled back the append.
    pub fn activate_durable_payment_writer_v1_checked_until(
        &self,
        history: &ReconciledAuthorityHistory,
        admission_operation_id: &str,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        check_current()?;
        validate_pending_activation_v1(
            history,
            admission_operation_id,
            request,
            &self.disclosure_descriptor(),
            &self.tls.client_certificate,
            now_ms()?,
        )?;
        check_current()?;
        require_before_caller_deadline(deadline)?;
        self.durable_payment_control_checked_v1(request, deadline, &mut check_current)
    }

    pub fn verify_durable_payment_session_v1_checked_until(
        &self,
        history: &ReconciledAuthorityHistory,
        admission_operation_id: &str,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedWriterSession> {
        check_current()?;
        history
            .durable_payment_admission_v1(admission_operation_id)?
            .ok_or(AuthorityError::Permission)?;
        if history.disclosure != self.disclosure_descriptor() {
            return Err(AuthorityError::Authentication);
        }
        let state = lock_born_session_until(&self.session, deadline, &mut check_current)?;
        let session = state.as_ref().ok_or(AuthorityError::RecoveryRequired)?;
        let receipt = session
            .receipt
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if crate::session::session_id(&session.key) != receipt.session_id {
            return Err(AuthorityError::Authentication);
        }
        let observed = Instant::now();
        let observed_at_ms = now_ms()?;
        let response = self.call_with_inner_checked(
            |_| {
                Ok(WireRequest::Snapshot {
                    account_id: self.account.clone(),
                    network_profile_id: self.network.clone(),
                })
            },
            Some(deadline),
            &mut check_current,
        )?;
        let WireResponse::Snapshot(snapshot) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        check_current()?;
        self.check_snapshot(&snapshot)?;
        snapshot.require_unfenced_transport(&receipt.session_id)?;
        if snapshot != history.snapshot {
            return Err(AuthorityError::StaleHead);
        }
        if snapshot.writer_status != WriterStatus::Active
            || snapshot.active_writer_session.as_ref() != Some(receipt)
            || receipt.writer_certificate_digest != self.tls.client_certificate
            || receipt.writer_epoch != snapshot.writer_epoch
            || now_ms()? >= receipt.expires_at_ms
        {
            return Err(AuthorityError::SessionRequired);
        }
        let active = AuthenticatedWriterSession {
            observed,
            observed_at_ms,
            snapshot,
            receipt: receipt.clone(),
            disclosure: self.disclosure_descriptor(),
            history_digest: history.history_digest()?,
        };
        history.require_durable_payment_session_v1(admission_operation_id, &active)?;
        check_current()?;
        require_before_caller_deadline(deadline)?;
        Ok(active)
    }

    fn durable_payment_control_checked_v1(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        check_current: &mut impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        if request.account_id != self.account || request.network_profile_id != self.network {
            return Err(AuthorityError::InvalidBinding);
        }
        let response = self.call_with_inner_checked(
            |_| {
                Ok(WireRequest::Mutate {
                    mutation: Box::new(AuthorityMutation::OwnerControl(request.clone())),
                    session_proof: None,
                })
            },
            Some(deadline),
            &mut *check_current,
        )?;
        check_current()?;
        let WireResponse::Mutation(MutationResult::Controlled(snapshot)) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        self.check_snapshot(&snapshot)?;
        self.check_committed_head(
            &request.expected_head,
            &snapshot.head,
            AuthorityMutation::OwnerControl(request.clone()),
            snapshot.last_witness_time_ms,
            None,
        )?;
        check_current()?;
        require_before_caller_deadline(deadline)?;
        Ok(snapshot)
    }
}

// Inert validation only. This does not access or mint any writer/owner key.
fn validate_pending_activation_v1(
    history: &ReconciledAuthorityHistory,
    admission_operation_id: &str,
    request: &OwnerControlRequest,
    disclosure: &WitnessDisclosureDescriptor,
    owner_certificate: &str,
    now: u64,
) -> Result<()> {
    history.durable_payment_online_permits_v1(admission_operation_id)?;
    let admission = history
        .durable_payment_admission_v1(admission_operation_id)?
        .ok_or(AuthorityError::Permission)?;
    let OwnerControl::AdmitDurablePaymentV1 { record } = &admission.control else {
        return Err(AuthorityError::CorruptHistory);
    };
    let OwnerControl::ActivateWriter { session_id } = &request.control else {
        return Err(AuthorityError::Permission);
    };
    if history.disclosure != *disclosure
        || history.account_policy.owner_certificate_digest != owner_certificate
        || request.expected_head != history.snapshot.head
        || request.writer_epoch != history.snapshot.writer_epoch
    {
        return Err(AuthorityError::Authentication);
    }
    // The owner and writer are distinct real mTLS clients. The owner joins
    // the exact authenticated pending receipt without copying or installing
    // the writer's exporter key in this client.
    let receipt = history
        .snapshot
        .pending_writer_session
        .as_ref()
        .ok_or(AuthorityError::SessionRequired)?;
    let admitted_sequence = admission
        .expected_head
        .sequence
        .checked_add(1)
        .ok_or(AuthorityError::Limit)?;
    if !history
        .committed_operation_ids
        .contains(&record.acquire_operation_id(admission)?)
        || receipt.session_id != *session_id
        || receipt.writer_certificate_digest != record.terms.writer_certificate_digest
        || receipt.reconciled_head.sequence != admitted_sequence
        || history.history_heads.get(&admitted_sequence) != Some(&receipt.reconciled_head.digest)
        || request.expected_head != receipt.acquired_head
        || now >= receipt.expires_at_ms
    {
        return Err(AuthorityError::SessionRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_payment_v1::tests::{activate, admitted_fixture, history};
    #[test]
    fn activation_uses_distinct_owner_certificate_and_pending_history_not_writer_key() {
        let (birth, mut ledger, mut events, admission) = admitted_fixture();
        activate(&birth, &mut ledger, &mut events, &admission);
        let event = events.pop().unwrap();
        let AuthorityMutation::OwnerControl(request) = event.mutation else {
            panic!()
        };
        let pending = history(&birth, &events);
        assert!(
            pending.account_policy.owner_certificate_digest
                != pending.account_policy.initial_writer_certificate_digest
        );
        validate_pending_activation_v1(
            &pending,
            &admission.operation_id,
            &request,
            &birth.request.disclosure,
            &pending.account_policy.owner_certificate_digest,
            130_000,
        )
        .unwrap();
        assert!(validate_pending_activation_v1(
            &pending,
            &admission.operation_id,
            &request,
            &birth.request.disclosure,
            &pending.account_policy.initial_writer_certificate_digest,
            130_000
        )
        .is_err());
        let mut wrong = request.clone();
        wrong.control = OwnerControl::ActivateWriter {
            session_id: "f".repeat(64),
        };
        assert!(validate_pending_activation_v1(
            &pending,
            &admission.operation_id,
            &wrong,
            &birth.request.disclosure,
            &pending.account_policy.owner_certificate_digest,
            130_000
        )
        .is_err());
    }
}
