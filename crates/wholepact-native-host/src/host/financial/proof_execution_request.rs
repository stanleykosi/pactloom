//! Exact inert client request handed to the existing foreground native proof owner.
use super::*;
use wholepact_engine::{native_requests::NativeRequestState, proof_jobs::LocalProofJob};
use wholepact_proof_jobs::LocalAction;
impl Host {
    pub(in crate::host) fn native_proof_execute_request(&self) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let profile = self.financial.as_ref().ok_or(Error::Locked)?;
        profile.inventory()?;
        let access = self.access()?;
        let agreement = self.terminal.ask("Exact selected agreement ID: ")?;
        self.terminal.json(
            &self
                .engine
                .native_proof_execution_requests(access, &agreement)?,
        )?;
        let request_id = self
            .terminal
            .ask("Exact queued proof execution request ID: ")?;
        let view = self
            .engine
            .native_proof_execution_request(access, &agreement, &request_id)?;
        if view.state != NativeRequestState::Queued {
            return Err(Error::Invalid);
        }
        let (_, candidate) = self.engine.candidate(access, &view.candidate_id)?;
        self.terminal.json(&view)?;
        self.terminal.confirm("Run bounded local proof work for this exact original encrypted checkpoint? Private witness retention has its own native decision. This does not approve signatures, disclosure or submission. Once started, this foreground worker must drain; withdrawing a browser request cannot stop it. A crash leaves durable uncertainty and never permits automatic restart.")?;
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let attempt =
            self.engine
                .mark_native_proof_execution_attempt(access, &agreement, &request_id)?;
        if !exact_execution_binding(
            [
                &view.candidate_id,
                &view.job_id,
                &view.receipt_storage_key,
                &view.receipt_digest,
                &view.scope_digest,
                &view.coordination_request_digest,
                &view.execution_key(),
            ],
            [
                attempt.candidate_id(),
                attempt.job_id(),
                attempt.receipt_storage_key(),
                attempt.receipt_digest(),
                attempt.scope_digest(),
                attempt.coordination_request_digest(),
                attempt.execution_key(),
            ],
            view.queued_revision.checked_add(1),
            attempt.revision(),
        ) {
            return Err(Error::Invalid);
        }
        let consent = self.authority.proof_consent(
            &access.principal_id,
            attempt.candidate_id(),
            &candidate.manifest_digest,
            vec![
                LocalAction::InspectStatus,
                LocalAction::ProveLocally,
                LocalAction::RetainPrivateWitnesses,
            ],
        )?;
        let status = self.engine.candidate_proof_status(
            access,
            attempt.candidate_id(),
            LocalProofJob {
                job_id: attempt.job_id(),
                jobs: &profile.proof,
                consent: &consent,
            },
        )?;
        if status.scope_digest != attempt.scope_digest()
            || status.coordination_request_digest != attempt.coordination_request_digest()
        {
            return Err(Error::Invalid);
        }
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let result = self.run_native_proof_owned(
            access,
            attempt.candidate_id(),
            attempt.job_id(),
            attempt.revision(),
            attempt.execution_key(),
            &consent,
        )?;
        self.terminal.json(&result)?;
        self.terminal.message("Original proof operation recorded. Inspect the retained job and reconcile metadata after any interrupted handoff. No signature or transaction was released.\n")
    }
    pub(super) fn run_native_proof_owned(
        &self,
        access: &wholepact_engine::Access,
        candidate_id: &str,
        job_id: &str,
        revision: u64,
        key: &str,
        consent: &crate::authority::financial::NativeProofConsent,
    ) -> Result<wholepact_engine::Mutation> {
        self.financial_permission(Permission::Coordinate)?;
        let profile = self.financial.as_ref().ok_or(Error::Locked)?;
        // The bounded journal permits at most eight actions. Execute on
        // one worker; the foreground emits progress while work runs.
        let engine = &self.engine;
        let jobs = &profile.proof;
        let terminal = &self.terminal;
        let result = std::thread::scope(|scope| {
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            let worker = scope.spawn(move || {
                let result = engine.run_candidate_proof_locally(
                    access,
                    key,
                    candidate_id,
                    revision,
                    LocalProofJob {
                        job_id,
                        jobs,
                        consent,
                    },
                );
                let _ = send.send(result);
            });
            let result = loop {
                match receive.recv_timeout(Duration::from_secs(1)) {
                    Ok(result) => break result.map_err(Error::from),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // A lost terminal never abandons a live worker or
                        // pretends cancellation; retain and join it first.
                        let _ = terminal.message(
                            "Local proof work is active; no transaction is being submitted.\n",
                        );
                    }
                    Err(_) => break Err(Error::Storage),
                }
            };
            worker.join().map_err(|_| Error::Storage)?;
            result
        })?;
        Ok(result)
    }
}

fn exact_execution_binding(
    reviewed: [&str; 7],
    retained: [&str; 7],
    expected: Option<u64>,
    revision: u64,
) -> bool {
    reviewed == retained && expected == Some(revision)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn execution_dispatch_binds_original_checkpoint_and_request_without_authority_flags() {
        let exact = [
            "candidate",
            "job",
            "receipt-key",
            "receipt-digest",
            "scope",
            "original-command",
            "execution-key",
        ];
        assert!(exact_execution_binding(exact, exact, Some(12), 12));
        for index in 0..7 {
            let mut changed = exact;
            changed[index] = "changed";
            assert!(!exact_execution_binding(exact, changed, Some(12), 12));
        }
        assert!(!exact_execution_binding(exact, exact, Some(12), 13));
        assert!(!exact_execution_binding(exact, exact, None, 12));
    }
}
