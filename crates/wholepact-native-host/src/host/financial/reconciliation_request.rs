//! Explicit native provider observation or independently qualified record resolution.
//! Client requests are inert. No provider report can select the positive path.
use super::*;
use wholepact_engine::native_reconciliation_requests::{
    NativeReconciliationAttempt, ReconciliationRequestKind,
};
use wholepact_engine::native_requests::NativeRequestState;

impl Host {
    pub(in crate::host) fn native_reconciliation_request(&self, status_only: bool) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let agreement = self.terminal.ask("Exact selected agreement ID: ")?;
        self.terminal.json(
            &self
                .engine
                .native_reconciliation_requests(self.access()?, &agreement)?,
        )?;
        let id = self
            .terminal
            .ask("Exact original native reconciliation request ID: ")?;
        let view = self
            .engine
            .native_reconciliation_request(self.access()?, &agreement, &id)?;
        self.terminal.json(&view)?;
        if status_only {
            if view.state != NativeRequestState::AttemptStarted {
                return Err(Error::Invalid);
            }
            let inspection =
                self.engine
                    .native_reconciliation_inspection(self.access()?, &agreement, &id)?;
            let journal = self.submission.lock().map_err(|_| Error::Storage)?;
            let observed = self.authority.with_reconciliation_status_read(
                &self.access()?.principal_id,
                &view,
                journal.identity(),
                || {
                    Ok(self.engine.inspect_native_reconciliation_status(
                        self.access()?,
                        inspection,
                        &journal,
                    )?)
                },
            )?;
            return self.terminal.json(&observed);
        }
        if view.state != NativeRequestState::Queued {
            return Err(Error::Invalid);
        }
        self.terminal.confirm("Start this EXACT native reconciliation request once? Starting records uncertain history before private work. Provider observation needs a separate exact native linkage-disclosure and conservative-invalidation decision; it cannot release exposure. Independent record resolution additionally needs the selected existing private record, current enrolled independent host node, original signer settlement review, and separate positive mutation approval. Retain bounded historical result metadata for this authenticated client under the selected agreement scope? A lost result may leave partial durable effects. Preserve original request, operation and journals; no payment, replacement or spending permission is implied.")?;
        let attempt =
            self.engine
                .mark_native_reconciliation_attempt(self.access()?, &agreement, &id)?;
        if attempt.source() != &view.source
            || attempt.operation_id() != view.operation_id
            || attempt.submission_journal_identity() != view.submission_journal_identity
            || attempt.dispatch_request_id() != view.dispatch_request_id
            || attempt.kind() != view.kind
            || attempt.participant_id() != view.participant_id.as_deref()
            || attempt.record_id() != view.record_id.as_deref()
            || view.queued_revision.checked_add(1) != Some(attempt.revision())
        {
            return Err(Error::Invalid);
        }
        match attempt.kind() {
            ReconciliationRequestKind::ProviderObservation => {
                let started =
                    self.engine
                        .native_reconciliation_request(self.access()?, &agreement, &id)?;
                self.native_provider_observation(attempt, &started)
            }
            ReconciliationRequestKind::IndependentRecordResolution => {
                self.financial_record_resolve_request(attempt)?;
                self.terminal
                    .json(&self.engine.native_reconciliation_request(
                        self.access()?,
                        &agreement,
                        &id,
                    )?)
            }
        }
    }

    fn native_provider_observation(
        &self,
        attempt: NativeReconciliationAttempt,
        view: &wholepact_engine::native_reconciliation_requests::NativeReconciliationRequestView,
    ) -> Result<()> {
        use wholepact_service::operator::OperatorTask;
        // Do not replace an already enrolled periodic observer with a one-shot.
        if self.observation.is_some() {
            return Err(Error::Permission);
        }
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let access = self.access()?.clone();
        let descriptor = {
            let journal = self.submission.lock().map_err(|_| Error::Storage)?;
            self.engine
                .validate_native_reconciliation_attempt(&access, &attempt, &journal)?;
            journal
                .retained_submission_descriptor(attempt.operation_id())?
                .ok_or(Error::Invalid)?
        };
        let source = self
            .terminal
            .ask("Explicit provider source ID for this one observation: ")?;
        let endpoint = self.terminal.ask("Exact HTTPS testnet provider origin: ")?;
        let adapter = ChainAdapter::testnet(&source, &endpoint, NetworkPolicy::default())?;
        let policy = ConfirmationPolicy::new(10, 10, vec![source.to_string()])?;
        let scope = ObservationScope {
            profile_id: self.secrets.profile(),
            journal_identity: attempt.submission_journal_identity().to_owned(),
            transaction: descriptor,
            sources: vec![adapter.identity().clone()],
            policy: policy.clone(),
        };
        let expires = now()?.checked_add(120).ok_or(Error::Invalid)?;
        self.authority.approve_observation(scope.clone(), expires)?;
        let sink_scope = self
            .engine
            .settlement_sink_scope(&scope.journal_identity, &scope.transaction)?;
        let mutation = self.authority.approve_settlement_sink(
            self.engine.clone(),
            access.clone(),
            sink_scope,
            expires,
        )?;
        let sink = EngineSettlementSink::new(
            self.engine.clone(),
            &scope.journal_identity,
            &scope.transaction,
            mutation,
        )
        .map_err(|_| Error::Permission)?;
        let task = ChainObservationTask::new(
            self.secrets.profile(),
            attempt.operation_id(),
            policy,
            vec![adapter],
            self.submission.clone(),
            self.authority.clone(),
        )
        .map_err(|_| Error::Permission)?
        .with_sinks(vec![Arc::new(sink)])
        .map_err(|_| Error::Permission)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Storage)?;
        let result = runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(30), task.tick()).await });
        // The actual task owns its current lease, typed provider evidence and
        // durable conservative fanout. Timeout/cancellation cannot undo prior reads
        // or commits. Never replace it with a report or a browser-provided status.
        if !matches!(result, Ok(Ok(()))) {
            return Err(Error::Permission);
        }
        self.authority
            .check_financial_principal(&access.principal_id)?;
        let inspection = attempt.into_inspection();
        let journal = self.submission.lock().map_err(|_| Error::Storage)?;
        let observed = self.authority.with_reconciliation_status_read(
            &access.principal_id,
            view,
            journal.identity(),
            || {
                Ok(self
                    .engine
                    .inspect_native_reconciliation_status(&access, inspection, &journal)?)
            },
        )?;
        self.terminal.json(&observed)
    }
}
