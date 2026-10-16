//! Ordinary native exact-job cache reconciliation only. No proof execution,
//! artifact export, signer approval or recovery fallback is reachable here.
use super::*;
use wholepact_engine::{native_requests::NativeRequestState, proof_jobs::LocalProofJob};
use wholepact_proof_jobs::LocalAction;

impl Host {
    pub(in crate::host) fn native_construction_original_status(&self) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let profile = self.financial.as_ref().ok_or(Error::Locked)?;
        profile.inventory()?;
        let access = self.access()?;
        let agreement = self.terminal.ask("Exact selected agreement ID: ")?;
        self.terminal
            .json(&self.engine.native_requests(access, &agreement)?)?;
        let request_id = self
            .terminal
            .ask("Exact original started construction request ID: ")?;
        let evidence =
            self.engine
                .original_native_construction_checkpoint(access, &agreement, &request_id)?;
        self.terminal.json(&evidence)?;
        self.terminal.message("Missing receipt or checkpoint never proves that signer disclosure, wallet import, scanning or earlier private work did not occur. The original construction fence remains closed. No reconstruction or approval is requested.\n")?;
        if evidence.receipt_digest.is_none() {
            return Ok(());
        }
        self.terminal.confirm("Inspect only the original encrypted proof-job status under fresh native consent? This will not construct, prove, recover a worker or change coordination history. A recorded operation is past evidence; current private availability is checked separately.")?;
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let consent = self.authority.proof_consent(
            &access.principal_id,
            &evidence.request.candidate_id,
            &evidence.request.manifest_digest,
            vec![LocalAction::InspectStatus],
        )?;
        let status = self.engine.candidate_proof_status(
            access,
            &evidence.request.candidate_id,
            LocalProofJob {
                job_id: &evidence.expected_job_id,
                jobs: &profile.proof,
                consent: &consent,
            },
        )?;
        if evidence.scope_digest.as_deref() != Some(status.scope_digest.as_str())
            || evidence.coordination_request_digest.as_deref()
                != Some(status.coordination_request_digest.as_str())
        {
            return Err(Error::Invalid);
        }
        self.terminal.json(&status)?;
        self.terminal.message("Exact original checkpoint status observed. To refresh its coordination cache, request existing-job metadata reconciliation using this same job ID; do not rerun construction. Unknown prior disclosure and account exposure remain unknown.\n")
    }

    pub(in crate::host) fn native_proof_reconcile_request(&self) -> Result<()> {
        self.native_proof_request_inner(false)
    }

    pub(in crate::host) fn native_proof_reconcile_original(&self) -> Result<()> {
        self.native_proof_request_inner(true)
    }

    fn native_proof_request_inner(&self, original: bool) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let profile = self.financial.as_ref().ok_or(Error::Locked)?;
        profile.inventory()?;
        let access = self.access()?;
        let agreement = self.terminal.ask("Exact selected agreement ID: ")?;
        self.terminal
            .json(&self.engine.native_proof_requests(access, &agreement)?)?;
        let request_id = self
            .terminal
            .ask("Exact retained proof-reconciliation request ID: ")?;
        let view = self
            .engine
            .native_proof_request(access, &agreement, &request_id)?;
        if view.state
            != if original {
                NativeRequestState::AttemptStarted
            } else {
                NativeRequestState::Queued
            }
        {
            return Err(Error::Invalid);
        }
        let (_, candidate) = self.engine.candidate(access, &view.candidate_id)?;
        let reconciliation_key = view.reconciliation_key();
        self.terminal.json(&view)?;
        self.terminal.message(&format!("Exact native reconciliation key: {reconciliation_key}\nOriginal private job: {}\nCandidate: {}\nReceipt storage key: {}\nReceipt digest: {}\nThis key differs from the browser enqueue key.\n", view.job_id, view.candidate_id, view.receipt_storage_key, view.receipt_digest))?;
        if original {
            self.terminal.message("Original metadata retry only: the existing attempt fence remains. This does not establish whether a prior private status read occurred. Only the same retained key, revision and receipt may be reconciled; current native consent is required again. No construction or proof worker is restarted.\n")?;
        }
        self.terminal.confirm("Inspect this exact retained proof job under separate native consent and reconcile only its cached coordination metadata? No prover, recovery mutation, artifact export, signature or submission is requested. Private worker liveness, chain validity and account-wide exposure remain separately unknown. An interrupted attempt cannot be reset or replaced; the explicit original-metadata retry can only repeat its exact idempotent coordination operation.")?;
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let attempt = if original {
            self.engine.original_native_proof_reconciliation_attempt(
                access,
                &agreement,
                &request_id,
            )?
        } else {
            self.engine
                .mark_native_proof_reconciliation_attempt(access, &agreement, &request_id)?
        };
        if !exact_dispatch_matches(
            DispatchBinding {
                identities: [
                    &view.candidate_id,
                    &view.job_id,
                    &reconciliation_key,
                    &view.receipt_storage_key,
                    &view.receipt_digest,
                    &view.scope_digest,
                    &view.coordination_request_digest,
                ],
                revision: view.queued_revision.checked_add(1).ok_or(Error::Invalid)?,
            },
            DispatchBinding {
                identities: [
                    attempt.candidate_id(),
                    attempt.job_id(),
                    attempt.reconciliation_key(),
                    attempt.receipt_storage_key(),
                    attempt.receipt_digest(),
                    attempt.scope_digest(),
                    attempt.coordination_request_digest(),
                ],
                revision: attempt.revision(),
            },
        ) {
            return Err(Error::Invalid);
        }
        let consent = self.authority.proof_consent(
            &access.principal_id,
            attempt.candidate_id(),
            &candidate.manifest_digest,
            vec![LocalAction::InspectStatus],
        )?;
        let local = || LocalProofJob {
            job_id: attempt.job_id(),
            jobs: &profile.proof,
            consent: &consent,
        };
        // Actual encrypted job and original engine receipt are checked by this
        // existing API before the independent coordination commit below.
        let status = self
            .engine
            .candidate_proof_status(access, attempt.candidate_id(), local())?;
        if status.scope_digest != attempt.scope_digest()
            || status.coordination_request_digest != attempt.coordination_request_digest()
        {
            return Err(Error::Invalid);
        }
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let result = self.engine.reconcile_candidate_proof_job(
            access,
            attempt.reconciliation_key(),
            attempt.candidate_id(),
            attempt.revision(),
            local(),
        )?;
        self.terminal.json(&result)?;
        self.terminal.message("Exact existing-job metadata reconciled. No proof was run or recovered, and no signature, transaction or private artifact was exported. Browser status is cached evidence only.\n")
    }
}

// Data-only equality at the native dispatch boundary. This cannot construct an
// attempt or grant consent; the concrete encrypted job and consent remain above.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DispatchBinding<'a> {
    identities: [&'a str; 7],
    revision: u64,
}
fn exact_dispatch_matches(reviewed: DispatchBinding<'_>, attempt: DispatchBinding<'_>) -> bool {
    reviewed == attempt
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reviewed_native_dispatch_preserves_every_original_identity() {
        let original = DispatchBinding {
            identities: [
                "candidate",
                "job",
                "native-key",
                "receipt-key",
                "receipt-digest",
                "scope",
                "original-command",
            ],
            revision: 12,
        };
        assert!(exact_dispatch_matches(original, original));
        for index in 0..7 {
            let mut changed = original;
            changed.identities[index] = "substituted";
            assert!(!exact_dispatch_matches(original, changed));
        }
        let mut changed = original;
        changed.revision += 1;
        assert!(!exact_dispatch_matches(original, changed));
    }
}
