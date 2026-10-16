//! The original encrypted account ledger remains the sole budget and conflict
//! authority. Construction reservation, consumption and expiry never refund it.
use crate::{
    manual_roster_construction_v2::*,
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    manual_roster_witness_v2::ManualRosterSessionContinuationV2,
    policy::{Event, Ledger},
    *,
};
use wholepact_core::manual_roster_construction_v2::ManualRosterConstructionPlanV2;
impl Ledger {
    pub(crate) fn require_unconsumed_roster_construction_v2(
        &self,
        m: &AuthorityMutation,
    ) -> Result<()> {
        if let AuthorityMutation::ConsumeManualRosterConstructionV2(r) = m {
            if let Some((original, _, _)) = self.operations.get(&r.operation_id) {
                if original != m {
                    return Err(AuthorityError::Conflict);
                }
                // Historical replay can return the immutable event; a live
                // channel must never mint a second contribution from it.
                return Err(AuthorityError::Uncertain);
            }
        }
        Ok(())
    }
    pub(crate) fn current_roster_construction_terms_v2(
        &self,
    ) -> Result<(
        &ManualRosterEnrollmentExtensionV2,
        ManualRosterSessionContinuationV2,
    )> {
        self.require_supported_manual_history()?;
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        e.validate_original_policy(&self.policy)?;
        let c = self
            .latest_manual_roster_attempt_v2()?
            .continuation
            .ok_or(AuthorityError::Permission)?;
        Ok((e, c))
    }
    /// The retained original selection is historical, never silently relabelled
    /// as the new attempt. Its original V2 extension AND continued admission must
    /// appear in this same complete ledger before a new plan can be approved.
    pub(crate) fn require_retained_roster_construction_origin_v2(
        &self,
        p: &ManualRosterConstructionPlanV2,
    ) -> Result<()> {
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        validate_plan_original(p, e)?;
        let selection = &p.retained.selection;
        let attempt = &selection.scope.selection.inventory.attempt;
        let mut continuation = None;
        for (m, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ContinueManualRosterSessionV2 { record },
                ..
            }) = m
            {
                if record.continuation.digest_for(e)? == attempt.continuation_digest {
                    if continuation.is_some() {
                        return Err(AuthorityError::CorruptHistory);
                    }
                    continuation = Some(&record.continuation);
                }
            }
        }
        let c = continuation.ok_or(AuthorityError::Permission)?;
        if c.sequence() != attempt.attempt_sequence {
            return Err(AuthorityError::InvalidBinding);
        }
        let Some((_, _, MutationResult::ManualRosterEnrollmentAdmittedV2(a))) =
            self.operations.get(&c.admission_operation_id(e)?)
        else {
            return Err(AuthorityError::Permission);
        };
        a.validate_for(e, Some(c))?;
        if selection.requested_at_ms < a.admitted_at_ms
            || selection.requested_at_ms >= a.publication_expires_at_ms
            || selection.disclosure_expires_at_ms > a.session.expires_at_ms
        {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
    pub(crate) fn roster_construction_approval_v2(
        &self,
        r: &ManualRosterConstructionReservationRequestV2,
    ) -> Result<&ManualRosterConstructionApprovalRecordV2> {
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        let invocation = r.invocation_digest()?;
        let mut found = None;
        for (m, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ApproveManualRosterConstructionV2 { record },
                ..
            }) = m
            {
                if record
                    .approval
                    .plan
                    .invocation_digest()
                    .map_err(|_| AuthorityError::CorruptHistory)?
                    == invocation
                {
                    record.validate_for(e)?;
                    record.approval.matches_request(&r.construction, e)?;
                    if found.is_some() {
                        return Err(AuthorityError::CorruptHistory);
                    }
                    found = Some(record.as_ref());
                }
            }
        }
        found.ok_or(AuthorityError::Permission)
    }
    pub(crate) fn validate_new_roster_construction_approval_v2(
        &self,
        r: &ManualRosterConstructionApprovalRecordV2,
        now: u64,
    ) -> Result<()> {
        self.require_supported_manual_history()?;
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        e.validate_original_policy(&self.policy)?;
        r.validate_for(e)?;
        self.require_retained_roster_construction_origin_v2(&r.approval.plan)?;
        self.require_original_construction_slot(
            &r.approval
                .plan
                .retained
                .selection
                .scope
                .selection
                .invocation
                .idempotency_key_digest,
            2,
            true,
            None,
        )?;
        if now < r.approval.issued_at_ms || now >= r.approval.initial_commit_deadline_ms {
            return Err(AuthorityError::Expired);
        }
        if self
            .obligations
            .contains(&e.account_extension.terms.scope.obligation_id)
        {
            return Err(AuthorityError::ObligationReserved);
        }
        let invocation = r
            .approval
            .plan
            .invocation_digest()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        for (m, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ApproveManualRosterConstructionV2 { record },
                ..
            }) = m
            {
                if record
                    .approval
                    .plan
                    .invocation_digest()
                    .map_err(|_| AuthorityError::CorruptHistory)?
                    == invocation
                {
                    return Err(AuthorityError::Conflict);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn require_roster_construction_scope_v2(
        &self,
        m: &AuthorityMutation,
        now: u64,
    ) -> Result<()> {
        let (e, c) = self.current_roster_construction_terms_v2()?;
        let active = self
            .snapshot
            .active_writer_session
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if now < active.acquired_at_ms || now >= active.expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        match m {
            AuthorityMutation::ReserveManualRosterConstructionV2(r) => {
                r.validate_for(e, &c)?;
                self.require_retained_roster_construction_origin_v2(&r.construction.plan)?;
                self.roster_construction_approval_v2(r)?;
                self.require_original_construction_slot(
                    &r.construction
                        .plan
                        .retained
                        .selection
                        .scope
                        .selection
                        .invocation
                        .idempotency_key_digest,
                    2,
                    false,
                    Some(&r.construction.operation_id),
                )?;
                if r.session_id != active.session_id
                    || now < r.reviewed_at_ms
                    || now >= r.construction.admission_expires_at_ms
                {
                    return Err(AuthorityError::Expired);
                }
                if let Some((_, _, result)) = self.operations.get(&r.construction.operation_id) {
                    let MutationResult::ManualRosterConstructionReservedV2(old) = result else {
                        return Err(AuthorityError::Conflict);
                    };
                    old.validate_for(e, &c)?;
                    if self
                        .operations
                        .contains_key(&construction_consume_operation_id_v2(old, e, &c)?)
                    {
                        return Err(AuthorityError::Uncertain);
                    }
                    if old.snapshot.head != self.snapshot.head {
                        return Err(AuthorityError::StaleHead);
                    }
                }
            }
            AuthorityMutation::ConsumeManualRosterConstructionV2(r) => {
                let old = self.roster_construction_reservation_v2(&r.reservation_operation_id)?;
                r.validate_for(old, e, &c)?;
                if r.session_id != active.session_id
                    || now < old.admitted_at_ms
                    || now >= old.request.construction.admission_expires_at_ms
                {
                    return Err(AuthorityError::Expired);
                }
            }
            _ => return Err(AuthorityError::Permission),
        }
        Ok(())
    }
    pub(crate) fn roster_construction_reservation_v2(
        &self,
        id: &str,
    ) -> Result<&ManualRosterConstructionReservationRecordV2> {
        match self.operations.get(id) {
            Some((_, _, MutationResult::ManualRosterConstructionReservedV2(r))) => Ok(r),
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
    fn roster_construction_event_session_v2(
        &self,
        event: &Event,
        expected: &AuthorityHead,
        epoch: u64,
        id: &str,
    ) -> Result<WriterSessionReceipt> {
        self.fence(expected, epoch)?;
        self.require_roster_construction_scope_v2(&event.mutation, event.witness_time_ms)?;
        let active = self
            .snapshot
            .active_writer_session
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if event.writer_session_id.as_deref() != Some(active.session_id.as_str())
            || id != active.session_id
            || event.authenticated_certificate_digest != active.writer_certificate_digest
        {
            return Err(AuthorityError::SessionRequired);
        }
        Ok(active.clone())
    }
    pub(crate) fn apply_roster_construction_reservation_v2(
        &mut self,
        r: &ManualRosterConstructionReservationRequestV2,
        event: &Event,
        next: &AuthorityHead,
    ) -> Result<ManualRosterConstructionReservationRecordV2> {
        let session = self.roster_construction_event_session_v2(
            event,
            &r.expected_head,
            r.writer_epoch,
            &r.session_id,
        )?;
        let (e, c) = self.current_roster_construction_terms_v2()?;
        let debit = r.maximum_net_debit_zatoshis()?;
        self.check_account_outstanding_limit(debit)?;
        self.check_input_obligation_exclusions(
            &r.enrollment().scope.obligation_id,
            r.selected_inputs()
                .iter()
                .map(|i| (i.input_id.as_str(), i.nullifier.as_str())),
        )?;
        let reserved = r.input_value_zatoshis()?;
        let mut snapshot = self.snapshot.clone();
        snapshot.head = next.clone();
        snapshot.last_witness_time_ms = event.witness_time_ms;
        snapshot.outstanding_debit_zatoshis = snapshot
            .outstanding_debit_zatoshis
            .checked_add(debit)
            .filter(|n| {
                n.checked_add(snapshot.settled_debit_zatoshis)
                    .is_some_and(|total| {
                        total <= self.policy.aggregate_budget_zatoshis
                            && total <= e.account_extension.terms.scope.aggregate_budget_zatoshis
                    })
            })
            .ok_or(AuthorityError::BudgetExceeded)?;
        snapshot.reserved_input_value_zatoshis = snapshot
            .reserved_input_value_zatoshis
            .checked_add(reserved)
            .filter(|n| *n <= MAX_MONEY)
            .ok_or(AuthorityError::BudgetExceeded)?;
        snapshot.outstanding_reservations = snapshot
            .outstanding_reservations
            .checked_add(1)
            .ok_or(AuthorityError::Limit)?;
        let record = ManualRosterConstructionReservationRecordV2 {
            request: r.clone(),
            snapshot: snapshot.clone(),
            session,
            admitted_at_ms: event.witness_time_ms,
            construction_expires_at_ms: r.completion_deadline_ms(),
            reserved_debit_zatoshis: debit,
            reserved_input_value_zatoshis: reserved,
        };
        record.validate_for(e, &c)?;
        self.snapshot = snapshot;
        self.obligations
            .insert(r.enrollment().scope.obligation_id.clone());
        for i in r.selected_inputs() {
            self.input_ids.insert(i.input_id.clone());
            self.nullifiers.insert(i.nullifier.clone());
        }
        Ok(record)
    }
    pub(crate) fn apply_roster_construction_consume_v2(
        &self,
        r: &ManualRosterConstructionConsumeRequestV2,
        event: &Event,
        next: &AuthorityHead,
    ) -> Result<ManualRosterConstructionConsumedRecordV2> {
        self.roster_construction_event_session_v2(
            event,
            &r.expected_head,
            r.writer_epoch,
            &r.session_id,
        )?;
        let (e, c) = self.current_roster_construction_terms_v2()?;
        let old = self.roster_construction_reservation_v2(&r.reservation_operation_id)?;
        let mut snapshot = self.snapshot.clone();
        snapshot.head = next.clone();
        snapshot.last_witness_time_ms = event.witness_time_ms;
        let record = ManualRosterConstructionConsumedRecordV2 {
            request: r.clone(),
            snapshot,
            consumed_at_ms: event.witness_time_ms,
            construction_expires_at_ms: old.construction_expires_at_ms,
        };
        record.validate_for(old, e, &c)?;
        Ok(record)
    }
    /// All originally admitted non-signing work drains before a successor fences
    /// this account's session. Cancellation never shortens or renews the bound.
    pub(crate) fn roster_construction_drain_deadline_v2(&self, attempt: &str) -> u64 {
        self.operations
            .values()
            .filter_map(|(_, _, r)| match r {
                MutationResult::ManualRosterConstructionReservedV2(r)
                    if r.request.attempt_digest == attempt =>
                {
                    Some(r.construction_expires_at_ms)
                }
                _ => None,
            })
            .max()
            .unwrap_or(0)
    }
}
