//! Distinct V2 roster selection exclusions; Access and complete agreement checks
//! precede and follow the concrete lower-native owner read. No V1 conversion.
use super::*;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
impl Engine {
    /// Local exclusion metadata under an actual current native preparation
    /// lease. No new candidate or financial authority is created by this read.
    pub fn manual_roster_candidate_local_exclusions_v2(
        &self,
        access: &Access,
        lease: &wholepact_signer_origin::ManualRosterCandidateSelectionLeaseV2<'_>,
    ) -> Result<wholepact_store::manual_enrollment::ManualRosterCandidateLocalExclusionsV2<'_>>
    {
        lease.check_current().map_err(|_| manual_denied())?;
        let request = lease.binding();
        let scope = &request.scope.selection;
        let target = self.manual_enrollment_target(access, &scope.inventory.enrollment)?;
        let envelope = decode(&target.agreement_record)?;
        if scope.economic_intent.agreement != envelope.view.agreement
            || scope.economic_intent.candidate_revision != target.agreement_revision
            || envelope
                .view
                .candidates
                .iter()
                .any(|candidate| candidate.candidate_id == scope.economic_intent.candidate_id)
        {
            return Err(manual_denied());
        }
        let result = self
            .store
            .manual_roster_candidate_local_exclusions_v2(
                &target.store,
                &target.agreement_record,
                lease,
            )
            .map_err(store_error)?;
        target.check_current(access)?;
        lease.check_current().map_err(|_| manual_denied())?;
        Ok(result)
    }
}

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
impl Engine {
    pub fn manual_roster_candidate_current_exclusions_v2<'snapshot>(
        &self,
        access: &Access,
        request: &wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionRequestV2,
        snapshot: &'snapshot wholepact_store::manual_enrollment::ManualRosterCandidateLocalExclusionsV2<'_>,
    ) -> Result<&'snapshot wholepact_store::financial_preflight::RetainedInputExclusions> {
        let target =
            self.manual_enrollment_target(access, &request.scope.selection.inventory.enrollment)?;
        let envelope = decode(&target.agreement_record)?;
        if request.scope.selection.economic_intent.agreement != envelope.view.agreement
            || request.scope.selection.economic_intent.candidate_revision
                != target.agreement_revision
            || envelope.view.candidates.iter().any(|candidate| {
                candidate.candidate_id == request.scope.selection.economic_intent.candidate_id
            })
        {
            return Err(manual_denied());
        }
        let result = snapshot
            .current_for(&self.store, request)
            .map_err(store_error)?;
        target.check_current(access)?;
        Ok(result)
    }
}

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
impl Engine {
    /// Read-only retained-stage restrictions. No new selection, current native
    /// continuation, construction permit or financial exception is returned.
    pub fn manual_roster_retained_current_exclusions_v2<'snapshot>(
        &self,
        access: &Access,
        retained: &wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
        snapshot: &'snapshot wholepact_store::manual_enrollment::ManualRosterCandidateLocalExclusionsV2<'_>,
    ) -> Result<&'snapshot wholepact_store::financial_preflight::RetainedInputExclusions> {
        retained.validate().map_err(|_| manual_denied())?;
        let request = &retained.selection;
        let target =
            self.manual_enrollment_target(access, &request.scope.selection.inventory.enrollment)?;
        let envelope = decode(&target.agreement_record)?;
        if request.scope.selection.economic_intent.agreement != envelope.view.agreement
            || request.scope.selection.economic_intent.candidate_revision
                != target.agreement_revision
            || envelope.view.candidates.iter().any(|candidate| {
                candidate.candidate_id == request.scope.selection.economic_intent.candidate_id
            })
        {
            return Err(manual_denied());
        }
        let exclusions = snapshot
            .current_retained_for(&self.store, retained)
            .map_err(store_error)?;
        target.check_current(access)?;
        Ok(exclusions)
    }
    pub fn manual_roster_retained_current_exclusions_v2_fail_fast<'snapshot>(
        &self,
        access: &Access,
        retained: &wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
        snapshot: &'snapshot wholepact_store::manual_enrollment::ManualRosterCandidateLocalExclusionsV2<'_>,
    ) -> Result<&'snapshot wholepact_store::financial_preflight::RetainedInputExclusions> {
        retained.validate().map_err(|_| manual_denied())?;
        let request = &retained.selection;
        let target = self.manual_enrollment_target_fail_fast(
            access,
            &request.scope.selection.inventory.enrollment,
        )?;
        let envelope = decode(&target.agreement_record)?;
        if request.scope.selection.economic_intent.agreement != envelope.view.agreement
            || request.scope.selection.economic_intent.candidate_revision
                != target.agreement_revision
            || envelope.view.candidates.iter().any(|candidate| {
                candidate.candidate_id == request.scope.selection.economic_intent.candidate_id
            })
        {
            return Err(manual_denied());
        }
        let exclusions = snapshot
            .current_retained_for_fail_fast(&self.store, retained)
            .map_err(store_error)?;
        target.check_current_fail_fast(access)?;
        Ok(exclusions)
    }
}
