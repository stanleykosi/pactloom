use super::manual_roster_exact_input_observation_v1::RosterExactInputCompletionV1;
// Separate Host additional-read admission. The actual native owner remains mandatory.
use crate::{
    Error, Result,
    terminal::{Terminal, historical::HistoricalApproval},
};
use std::time::Instant;
use wholepact_core::manual_roster_construction_v3::{
    CommonContextReadProfileV1, CommonContextReadPurposeV1, ManualRosterConstructionPlanV3,
    RosterCommonContextReadRequestV1,
};
use wholepact_signer_origin::AdmittedRosterCommonContextReadV1;

pub(crate) struct RosterCommonContextReadAdmissionV1 {
    plan: ManualRosterConstructionPlanV3,
    receipt: String,
    witness_approval: String,
    operation_id: String,
    profile: CommonContextReadProfileV1,
    admission_deadline: Instant,
    completion_deadline: Instant,
}
impl RosterCommonContextReadAdmissionV1 {
    pub(crate) fn review(
        terminal: &Terminal,
        prior: &HistoricalApproval,
        plan: &ManualRosterConstructionPlanV3,
        receipt: &str,
        witness_approval: &str,
        operation_id: String,
        original_completion_deadline: Instant,
    ) -> Result<Self> {
        plan.validate().map_err(|_| Error::Invalid)?;
        let profile = CommonContextReadProfileV1::for_plan(plan).map_err(|_| Error::Invalid)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:host-common-context-read-admission:v1",
            &(plan, receipt, witness_approval, &operation_id, &profile),
        )
        .map_err(|_| Error::Invalid)?;
        let approval = terminal.approve_publication_reviewed(prior, &digest, &format!(
            "Approve ONE additional exact-input observation separately from full-plan construction.\nPlan: {}\nOperation: {}\nBounds: {}\nContact only the ORIGINAL public-block provider (revealing IP, timing and queried heights), scan only the SAME already imported dedicated wallet, and reread only its exact retained inputs and old anchor. Bounded scan progress may be durable. No viewing material export, selection, proof, signing or dispatch is approved. A separate genuine native decision is required BEFORE Reserve/Consume. Once both decisions admit this one bounded read it may run after focus changes while other owners finish, only before the ORIGINAL completion deadline. Loss, failure or cancellation cannot renew or repeat it. The newly signed common target is fixed at maximum ORIGINAL tip plus one; every original selection context, shared original anchor, expiry, exposure and receipt remains unchanged. This read occurs before Reserve/Consume and is never repeated if sequential construction decisions exhaust its lifetime. Provider continuity and old-anchor reports are single-provider observations, never independent consensus or proof of unspentness.",
            plan.digest().map_err(|_| Error::Invalid)?, operation_id, serde_json::to_string(&profile)?,
        ))?;
        let admission_deadline = approval.deadline().min(original_completion_deadline);
        approval.commit(
            &digest,
            || prior.check(),
            |_| {
                Ok(Self {
                    plan: plan.clone(),
                    receipt: receipt.into(),
                    witness_approval: witness_approval.into(),
                    operation_id,
                    profile,
                    admission_deadline,
                    completion_deadline: original_completion_deadline,
                })
            },
        )
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.admission_deadline
    }
    pub(crate) fn request(
        &self,
        caller: String,
        now: u64,
    ) -> Result<RosterCommonContextReadRequestV1> {
        if Instant::now() >= self.admission_deadline {
            return Err(Error::Permission);
        }
        let request = RosterCommonContextReadRequestV1 {
            version: 1,
            operation_id: self.operation_id.clone(),
            plan: self.plan.clone(),
            original_durable_receipt_digest: self.receipt.clone(),
            witness_plan_approval_digest: self.witness_approval.clone(),
            purpose: CommonContextReadPurposeV1::RevalidateExactRetainedNotesAndCommonContext,
            profile: self.profile.clone(),
            current_caller_binding_digest: caller,
            requested_at_ms: now,
            admission_expires_at_ms: now
                .checked_add(30_000)
                .ok_or(Error::Invalid)?
                .min(self.plan.completion_expires_at_ms()),
            completion_expires_at_ms: self
                .plan
                .completion_expires_at_ms()
                .min(now.checked_add(60_000).ok_or(Error::Invalid)?),
        };
        request.validate().map_err(|_| Error::Invalid)?;
        Ok(request)
    }
    pub(crate) fn finish(
        self,
        native: AdmittedRosterCommonContextReadV1,
    ) -> Result<HostAdmittedRosterCommonContextReadV1> {
        native.check_completion().map_err(|_| Error::Permission)?;
        let request = native.request().map_err(|_| Error::Permission)?;
        if Instant::now() >= self.admission_deadline
            || request.plan != self.plan
            || request.original_durable_receipt_digest != self.receipt
            || request.witness_plan_approval_digest != self.witness_approval
            || request.operation_id != self.operation_id
            || request.profile != self.profile
        {
            return Err(Error::Authentication);
        }
        let completion = RosterExactInputCompletionV1 {
            deadline: self.completion_deadline.min(native.completion_deadline()),
        };
        completion.check()?;
        Ok(HostAdmittedRosterCommonContextReadV1 { native, completion })
    }
}
pub(crate) struct HostAdmittedRosterCommonContextReadV1 {
    native: AdmittedRosterCommonContextReadV1,
    completion: RosterExactInputCompletionV1,
}
impl HostAdmittedRosterCommonContextReadV1 {
    pub(crate) fn completion_deadline(&self) -> Result<Instant> {
        self.completion.check()?;
        self.native
            .check_completion()
            .map_err(|_| Error::Permission)?;
        Ok(self.completion.deadline)
    }
    pub(crate) fn request(&self) -> Result<&RosterCommonContextReadRequestV1> {
        self.completion.check()?;
        self.native.request().map_err(|_| Error::Permission)
    }
    pub(crate) fn into_parts(
        self,
    ) -> Result<(
        AdmittedRosterCommonContextReadV1,
        RosterExactInputCompletionV1,
    )> {
        self.completion_deadline()?;
        Ok((self.native, self.completion))
    }
}
