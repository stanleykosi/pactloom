//! Separate Host additional-read admission. The actual native owner remains mandatory.
use crate::{
    Error, Result,
    terminal::{Terminal, historical::HistoricalApproval},
};
use std::time::Instant;
use wholepact_core::{
    manual_roster_construction_v2::ManualRosterConstructionPlanV2,
    manual_roster_exact_input_observation_v1::{
        ExactInputObservationProfileV1, ExactInputObservationPurposeV1,
        ManualRosterExactInputObservationRequestV1,
    },
};
use wholepact_signer_origin::AdmittedRosterExactInputObservationV1;

pub(crate) struct RosterExactInputObservationAdmissionV1 {
    plan: ManualRosterConstructionPlanV2,
    receipt: String,
    operation_id: String,
    profile: ExactInputObservationProfileV1,
    admission_deadline: Instant,
    completion_deadline: Instant,
}
impl RosterExactInputObservationAdmissionV1 {
    pub(crate) fn review(
        terminal: &Terminal,
        prior: &HistoricalApproval,
        plan: &ManualRosterConstructionPlanV2,
        receipt: &str,
        operation_id: String,
        original_completion_deadline: Instant,
    ) -> Result<Self> {
        plan.validate().map_err(|_| Error::Invalid)?;
        let profile = ExactInputObservationProfileV1::for_plan(plan).map_err(|_| Error::Invalid)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:host-exact-input-observation-admission:v1",
            &(plan, receipt, &operation_id, &profile),
        )
        .map_err(|_| Error::Invalid)?;
        let approval = terminal.approve_publication_reviewed(prior, &digest, &format!(
            "Approve ONE additional exact-input observation separately from full-plan construction.\nPlan: {}\nOperation: {}\nBounds: {}\nContact only the ORIGINAL public-block provider (revealing IP, timing and queried heights), scan only the SAME already imported dedicated wallet, and reread only its exact retained inputs and old anchor. Bounded scan progress may be durable. No viewing material export, selection, proof, signing or dispatch is approved. A separate genuine native decision is required BEFORE Reserve/Consume. Once both decisions admit this one bounded read it may run after focus changes while other owners finish, only before the ORIGINAL completion deadline. Loss, failure or cancellation cannot renew or repeat it. Original context, exposure and receipts remain unchanged. Provider continuity and old-anchor reports are single-provider observations, never independent consensus or proof of unspentness.",
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
    ) -> Result<ManualRosterExactInputObservationRequestV1> {
        if Instant::now() >= self.admission_deadline {
            return Err(Error::Permission);
        }
        let request = ManualRosterExactInputObservationRequestV1 {
            version: 1,
            operation_id: self.operation_id.clone(),
            plan: self.plan.clone(),
            original_durable_receipt_digest: self.receipt.clone(),
            purpose: ExactInputObservationPurposeV1::ObserveRetainedInputsOnly,
            profile: self.profile.clone(),
            current_caller_binding_digest: caller,
            requested_at_ms: now,
            admission_expires_at_ms: now
                .checked_add(30_000)
                .ok_or(Error::Invalid)?
                .min(self.plan.completion_expires_at_ms()),
            completion_expires_at_ms: self.plan.completion_expires_at_ms(),
        };
        request.validate().map_err(|_| Error::Invalid)?;
        Ok(request)
    }
    pub(crate) fn finish(
        self,
        native: AdmittedRosterExactInputObservationV1,
    ) -> Result<HostAdmittedRosterExactInputObservationV1> {
        native.check_completion().map_err(|_| Error::Permission)?;
        let request = native.request().map_err(|_| Error::Permission)?;
        if Instant::now() >= self.admission_deadline
            || request.plan != self.plan
            || request.original_durable_receipt_digest != self.receipt
            || request.operation_id != self.operation_id
            || request.profile != self.profile
        {
            return Err(Error::Authentication);
        }
        let completion = RosterExactInputCompletionV1 {
            deadline: self.completion_deadline.min(native.completion_deadline()),
        };
        completion.check()?;
        Ok(HostAdmittedRosterExactInputObservationV1 { native, completion })
    }
}
pub(crate) struct RosterExactInputCompletionV1 {
    pub(super) deadline: Instant,
}
impl RosterExactInputCompletionV1 {
    pub(crate) fn check(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            Err(Error::Permission)
        } else {
            Ok(())
        }
    }
}
pub(crate) struct HostAdmittedRosterExactInputObservationV1 {
    native: AdmittedRosterExactInputObservationV1,
    completion: RosterExactInputCompletionV1,
}
impl HostAdmittedRosterExactInputObservationV1 {
    pub(crate) fn completion_deadline(&self) -> Result<Instant> {
        self.completion.check()?;
        self.native
            .check_completion()
            .map_err(|_| Error::Permission)?;
        Ok(self.completion.deadline)
    }
    pub(crate) fn request(&self) -> Result<&ManualRosterExactInputObservationRequestV1> {
        self.completion.check()?;
        self.native.request().map_err(|_| Error::Permission)
    }
    pub(crate) fn into_parts(
        self,
    ) -> Result<(
        AdmittedRosterExactInputObservationV1,
        RosterExactInputCompletionV1,
    )> {
        self.completion_deadline()?;
        Ok((self.native, self.completion))
    }
}

impl super::Authority {
    /// Read-only current principal/revocation restriction under no-wait mutexes.
    /// The locks span the entire check, as does the existing temporary Held
    /// check; this method issues no lease and performs no effect after return.
    pub(crate) fn check_financial_principal_fail_fast(&self, principal: &str) -> Result<()> {
        let current = self.principal.try_lock().map_err(|_| Error::Permission)?;
        let fence = self.fence.state.try_lock().map_err(|_| Error::Permission)?;
        if current.as_deref() != Some(principal) || fence.blocked {
            return Err(Error::Permission);
        }
        // Preserve the ordinary gate's requirement for a valid system clock.
        super::now()?.checked_add(1).ok_or(Error::Invalid)?;
        Ok(())
    }
}
