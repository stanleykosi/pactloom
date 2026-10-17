//! Separate genuine native first-proof owner for saved V3/V4 construction.
//! Does not admit construction, retry uncertainty, or ordinary financial use.
use super::Host;
use crate::authority::Held;
use crate::recovery_generation::manual_target::ManualCommittedTarget;
use crate::terminal::born_offline_proof_v1::BornSavedProofApprovalV1;
use crate::{Error, Result, now};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};
use wholepact_engine::born_offline_checkpoint_original_v1::PreparedBornOfflineCheckpointOriginalV1;
use wholepact_proof_jobs::{CheckpointScope, JobSummary, LocalAction, LocalProofConsent};
use wholepact_store::manual_enrollment::{
    ManualRosterConstructionCheckpointV3, ManualRosterConstructionClaimV3,
};

struct NativeOriginalProofSourceV1<'host> {
    host: &'host Host,
    committed: ManualCommittedTarget<'host>,
    claim: ManualRosterConstructionClaimV3,
    receipt: ManualRosterConstructionCheckpointV3,
    scope: CheckpointScope,
    exact_digest: String,
}
impl NativeOriginalProofSourceV1<'_> {
    fn check_current(&self) -> Result<()> {
        self.host.require_manual_session()?;
        self.committed.check_current()?;
        self.committed.coverage().require_complete()?;
        let actual = self
            .host
            .engine
            .prepare_born_offline_checkpoint_original_v1(
                self.host.access()?,
                &self.claim.consumed[0]
                    .request
                    .plan
                    .enrollment()
                    .scope
                    .agreement_id,
                &self.claim.construction_key,
            )?;
        if actual.claim() != &self.claim
            || actual.receipt() != &self.receipt
            || actual.scope() != &self.scope
        {
            return Err(Error::Authentication);
        }
        let host = &self.claim.consumed[0].request.plan.enrollment().host;
        let primary = self.host.financial.as_ref().ok_or(Error::Locked)?;
        primary.check_current_journals()?;
        let financial_origin = primary
            .manual_original_primary_origin_digest(&self.host.directory, &self.host.secrets)?;
        if host.generation_id != self.committed.generation_id()
            || host.inventory_digest != self.committed.inventory_digest()
            || host.generation_plan_digest != self.committed.plan_digest()
            || host.profile_id != self.committed.profile_id()
            || host.canonical_root != self.committed.canonical_root()
            || host.destination_identity_digest != self.committed.destination_identity_digest()
            || host.financial_journal_origin_digest != financial_origin
            || host.inherited_identity_digest != self.committed.coverage().digest()?
            || host.scope_predecessor_digest.is_some()
            || self.claim.invocation().checkpoint_destination != self.committed.canonical_root()
        {
            return Err(Error::Authentication);
        }
        actual.check_current(self.host.access()?)?;
        self.committed.check_current()
    }
    fn permits(
        &self,
        approval: &BornSavedProofApprovalV1,
        held: &Held,
        scope: &CheckpointScope,
        action: LocalAction,
    ) -> bool {
        scope == &self.scope
            && permitted_action(action)
            && approval.check(&self.exact_digest).is_ok()
            && held.check().is_ok()
            && self.check_current().is_ok()
            && approval.check(&self.exact_digest).is_ok()
            && held.check().is_ok()
    }
}
fn permitted_action(action: LocalAction) -> bool {
    matches!(
        action,
        LocalAction::InspectStatus
            | LocalAction::ProveLocally
            | LocalAction::RetainPrivateWitnesses
            | LocalAction::ReadPrivateArtifact
    )
}

impl Host {
    pub(in crate::host) fn born_offline_proof_run_v1_command(&self) -> Result<()> {
        self.require_manual_session()?;
        let agreement = self.terminal.ask("Exact original V3/V4 agreement ID: ")?;
        let key = self
            .terminal
            .ask("Exact original construction key for FIRST queued proof attempt only: ")?;
        self.prove_born_offline_original_queued_v1(&agreement, &key)?;
        self.terminal.message("The original saved local proof completed and was independently verified. No construction, signature, disclosure, current-input admission or dispatch was granted. Preserve the original journals and construction key.\n")
    }

    pub(in crate::host) fn prove_born_offline_original_queued_v1(
        &self,
        agreement_id: &str,
        construction_key: &str,
    ) -> Result<JobSummary> {
        self.require_manual_session()?;
        crate::id(agreement_id)?;
        if !(16..=128).contains(&construction_key.len())
            || !construction_key.bytes().all(|b| (33..=126).contains(&b))
        {
            return Err(Error::Invalid);
        }
        let key_commitment = wholepact_store::request_digest(&serde_json::json!([
            &self.access()?.principal_id,
            construction_key,
        ]))?;
        let initial = self.terminal.approve_historical(&format!(
            "Read the actual current-generation sealed parent capsule and complete bounded private coordination claim/audit history to select ONLY this original common-context constructor checkpoint (claim encodings 3–5). Authenticate the actual primary financial attachment and original journal identities. These records may include other accounts and private input/nullifier/value facts; none are displayed or exported. This initial read does not authorize proving. A separate exact saved-job native decision will authorize only one first local proof attempt plus its source-integrity rechecks for a fixed one-hour deadline. Existing construction/witness/source clocks are historical and never renewed.\nProfile: {}\nPrincipal: {}\nAgreement: {}\nOriginal key commitment: {}\nEncrypted temporary verification copies may survive a crash or cleanup failure; secure deletion is not promised. Missing constructor or private bytes never permits reconstruction or a replacement job.",
            self.secrets.profile(), self.access()?.principal_id, agreement_id, key_commitment,
        ))?;
        let mut opened = None;
        initial.effect(&mut || {
            initial.check()?;
            self.require_manual_session()?;
            let committed = ManualCommittedTarget::open(&self.directory, &self.secrets)?;
            committed.coverage().require_complete()?;
            let prepared = self.engine.prepare_born_offline_checkpoint_original_v1(
                self.access()?,
                agreement_id,
                construction_key,
            )?;
            let exact_digest = wholepact_store::request_digest(&serde_json::json!([
                "wholepact:native-original-v3-saved-proof:v1",
                prepared.claim().digest()?,
                prepared.receipt(),
                prepared.scope(),
                self.secrets.profile(),
            ]))?;
            let source = NativeOriginalProofSourceV1 {
                host: self,
                committed,
                claim: prepared.claim().clone(),
                receipt: prepared.receipt().clone(),
                scope: prepared.scope().clone(),
                exact_digest,
            };
            source.check_current()?;
            initial.check()?;
            opened = Some((source, prepared));
            Ok(())
        })?;
        let (source, prepared) = opened.ok_or(Error::Authentication)?;
        let approval = self.terminal.approve_born_saved_proof_v1(&initial, &source.exact_digest, &format!(
            "NEW purpose-specific local privacy/CPU approval for ONLY this exact actual saved constructor checkpoint. For at most one hour from this decision, retain the already saved unsigned transaction/policy/witnesses, perform current-generation and complete bounded claim/source-integrity rechecks, read this exact private job, execute ONE first proof attempt only when atomically queued at attempt zero, retain the resulting proof, independently verify its exact predecessor/policy/account bindings, and display its status metadata here.\nOriginal claim: {}\nOriginal job: {}\nExact saved scope: {}\nMaximum actions: {}\nNo wallet/network observation, new construction, key provision, source authorization, spending signature, external disclosure or dispatch is permitted. Running, uncertain, failed and completed jobs are refused rather than reset or retried. This NEW proof-only decision does not renew any original construction, witness, source or transport permission. The single CPU worker must drain even if foreground/approval is lost; no immediate cancellation or real-time guarantee is claimed. Expiry/revocation denies success admission, preserving uncertain durable state and never allowing automatic retry. Private encrypted records and verification copies may persist; no secure deletion guarantee.",
            source.claim.digest()?, source.receipt.job_id, serde_json::to_string_pretty(&source.scope)?, source.claim.maximum_actions,
        ))?;
        let held = self
            .authority
            .fence
            .acquire(now()?.checked_add(3600).ok_or(Error::Invalid)?)?;
        let output = self.terminal.historical_output()?;
        approval.effect(&source.exact_digest, || {
            source.check_current()?;
            approval.check(&source.exact_digest)?;
            held.check()?;
            let summary = run_one_worker(&source, prepared, &approval, &held)
                .map_err(|_| Error::Receipt("Original saved proof execution did not finish cleanly; its first attempt may be running, uncertain or complete. Preserve the exact claim and proof journal. No retry, reset or reconstruction is permitted by this command".into()))?;
            let check = || {
                source.check_current()?;
                held.check()?;
                approval.check(&source.exact_digest)
            };
            output.json_checked(&summary, check).map_err(|_| Error::Receipt(
                "Original saved proof completed but native status delivery is uncertain; preserve the exact completed checkpoint and never restart proof work".into(),
            ))?;
            check().map_err(|_| Error::Receipt(
                "Original saved proof and status delivery may have completed before source approval was lost; preserve the exact checkpoint".into(),
            ))?;
            Ok(summary)
        })
    }
}

enum ProofEvent {
    Check {
        scope: CheckpointScope,
        action: LocalAction,
        reply: mpsc::SyncSender<bool>,
    },
    Finished(Result<JobSummary>),
}
struct ForegroundConsentChannel {
    events: mpsc::SyncSender<ProofEvent>,
    deadline: Instant,
}
impl LocalProofConsent for ForegroundConsentChannel {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        if Instant::now() >= self.deadline || !permitted_action(action) {
            return false;
        }
        let (reply, receive) = mpsc::sync_channel(1);
        if self
            .events
            .send(ProofEvent::Check {
                scope: scope.clone(),
                action,
                reply,
            })
            .is_err()
        {
            return false;
        }
        receive
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(false)
    }
}
fn run_one_worker(
    source: &NativeOriginalProofSourceV1<'_>,
    prepared: PreparedBornOfflineCheckpointOriginalV1<'_>,
    approval: &BornSavedProofApprovalV1,
    held: &Held,
) -> Result<JobSummary> {
    let jobs = &source.host.financial.as_ref().ok_or(Error::Locked)?.proof;
    let access = source.host.access()?.clone();
    let deadline = approval.deadline();
    std::thread::scope(|threads| {
        let (send, receive) = mpsc::sync_channel(1);
        let worker = threads.spawn(move || {
            let gate = ForegroundConsentChannel {
                events: send.clone(),
                deadline,
            };
            let result = prepared
                .prove_original_queued_v1(&access, jobs, &gate)
                .map(|original| original.checkpoint().summary().clone())
                .map_err(Error::from);
            let _ = send.send(ProofEvent::Finished(result));
        });
        let mut denied = false;
        let mut progress = Instant::now();
        let result = loop {
            match receive.recv_timeout(Duration::from_secs(1)) {
                Ok(ProofEvent::Check {
                    scope,
                    action,
                    reply,
                }) => {
                    let allowed = !denied && source.permits(approval, held, &scope, action);
                    if !allowed {
                        denied = true;
                    }
                    let _ = reply.send(allowed);
                }
                Ok(ProofEvent::Finished(result)) => break result,
                Err(mpsc::RecvTimeoutError::Disconnected) => break Err(Error::Storage),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if approval.check(&source.exact_digest).is_err() || held.check().is_err() {
                        denied = true;
                    }
                    if !denied && progress.elapsed() >= Duration::from_secs(5) {
                        if approval.progress(&source.exact_digest).is_err() {
                            denied = true;
                        }
                        progress = Instant::now();
                    }
                    // Never return early or abandon an already admitted worker.
                }
            }
        };
        worker.join().map_err(|_| Error::Storage)?;
        if denied {
            return Err(Error::Permission);
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_proof_permission_never_admits_interrupted_recovery() {
        assert!(!permitted_action(LocalAction::RecoverInterrupted));
        for action in [
            LocalAction::InspectStatus,
            LocalAction::ProveLocally,
            LocalAction::RetainPrivateWitnesses,
            LocalAction::ReadPrivateArtifact,
        ] {
            assert!(permitted_action(action));
        }
    }
    #[test]
    fn expired_worker_channel_denies_without_waiting_for_a_source() {
        let (send, _receive) = mpsc::sync_channel(1);
        let gate = ForegroundConsentChannel {
            events: send,
            deadline: Instant::now(),
        };
        let scope = CheckpointScope {
            principal_id: "synthetic-owner".into(),
            candidate_id: "synthetic-candidate".into(),
            manifest_digest: "a".repeat(64),
            artifact_digest: "b".repeat(64),
            effects_commitment: "c".repeat(64),
            coordination_request_digest: "d".repeat(64),
            review_binding: "e".repeat(64),
            account_ids: vec!["synthetic-account".into()],
            local_operator: "synthetic-prover".into(),
            purpose: "synthetic-negative-test".into(),
            retention_policy: "temporary".into(),
        };
        assert!(!gate.permits(&scope, LocalAction::ProveLocally));
    }
}
