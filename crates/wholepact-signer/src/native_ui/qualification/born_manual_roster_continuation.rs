//! Exact manual-roster successor delivery only. This does not change its existing
//! envelope/domain, revive an old MAC/session, or extend an original deadline.
use super::*;

pub(in crate::native_ui) fn close_publication(
    fixture: PublicationRosterFixture,
) -> AcknowledgedBornFixture {
    let PublicationRosterFixture {
        controller,
        original,
        ..
    } = fixture;
    drop(controller); // revoke then join before either temporary owner can drop
    original
}

pub(in crate::native_ui) struct ContinuationExportFixture {
    controller: DrainingRosterController,
    original: AcknowledgedBornFixture,
    intent: HostIntent,
    scope: PairScope,
    epoch: u64,
    proposed: bool,
}
impl ContinuationExportFixture {
    pub(in crate::native_ui) fn open(
        ui: BornManualRosterUiV2,
        original: AcknowledgedBornFixture,
        intent: HostIntent,
    ) -> Result<Self> {
        intent.validate().map_err(|_| Error::InvalidData)?;
        let mut controller = DrainingRosterController::new(ui, &original);
        let epoch = controller
            .owner
            .as_ref()
            .ok_or(Error::Locked)?
            .focus_epoch();
        drain(&mut controller, epoch)?;
        let owner = controller.owner(epoch)?;
        let open = controller.opened.as_ref().ok_or(Error::Locked)?;
        if !open.attempted
            || !controller.continuation_controller.can_propose()
            || open.account_id != original.account_id
            || open
                .account
                .historical_birth_anchor()?
                .anchor()
                .birth_digest()
                != original.birth_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let retained = open
            .account
            .retained_born_manual_roster_enrollment_v2(&owner)?
            .ok_or(Error::RecoveryRequired)?;
        if retained.record().intent()? != intent {
            return Err(Error::ReviewMismatch);
        }
        drop(retained);
        let scope = PairScope {
            account_id: original.account_id.clone(),
            agreement_id: intent.account_intent.scope.agreement_id.clone(),
            participant_id: intent.account_intent.scope.participant_id.clone(),
            manifest_digest: intent.digest().map_err(|_| Error::InvalidData)?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        Ok(Self {
            controller,
            original,
            intent,
            scope,
            epoch,
            proposed: false,
        })
    }
    pub(in crate::native_ui) fn endpoint(&self) -> Result<PathBuf> {
        self.controller.owner(self.epoch)?;
        let open = self.controller.opened.as_ref().ok_or(Error::Locked)?;
        let ipc = open.ipc.lock().map_err(|_| Error::Locked)?;
        Ok(ipc.socket_path().to_path_buf())
    }
    pub(in crate::native_ui) fn deadline(&self) -> Result<Instant> {
        self.controller
            .owner(self.epoch)?
            .native()
            .binding()
            .bounded_deadline()
    }
    /// The actual producer independently enforces that the previous publication
    /// deadline has elapsed, and that the unchanged original scope has not.
    pub(in crate::native_ui) fn poll_proposal(&mut self) -> Result<bool> {
        let ui = &mut self.controller;
        ui.poll_lifecycle(true, self.epoch);
        ui.owner(self.epoch)?;
        if ui.job.is_some() {
            return Ok(false);
        }
        if let Some(review) = ui.review.as_ref() {
            let proposal = match &review.step {
                Step::Pair(pair) if !self.proposed && pair.scope == self.scope => false,
                Step::Witness(_)
                    if !self.proposed
                        && ui.peer.as_ref().is_some_and(|p| p.scope == self.scope) =>
                {
                    false
                }
                Step::ContinuationProposal(_)
                    if !self.proposed
                        && ui.peer.as_ref().is_some_and(|p| p.scope == self.scope) =>
                {
                    true
                }
                _ => return Err(Error::ReviewMismatch),
            };
            approve_current(ui, self.epoch)?;
            self.proposed |= proposal;
            return Ok(self.proposed);
        }
        if !self.proposed && ui.peer.as_ref().is_some_and(|p| p.scope == self.scope) {
            let context = ui.context()?;
            if ui.writer.is_none() {
                ui.start(
                    Work::PrepareWitness(context, self.original.credentials.roster_setup_json()?),
                    self.epoch,
                )?;
            } else {
                if !ui.continuation_controller.can_propose() {
                    return Err(Error::ReviewMismatch);
                }
                ui.start(Work::PrepareContinuationProposal(context), self.epoch)?;
            }
        }
        Ok(self.proposed)
    }
    pub(in crate::native_ui) fn export(
        self,
        destination: &Path,
    ) -> Result<ExportedContinuationFixture> {
        let Self {
            mut controller,
            original,
            intent,
            epoch,
            proposed,
            ..
        } = self;
        if !proposed || !destination.starts_with(original.temporary.path()) {
            return Err(Error::ReviewMismatch);
        }
        let owner = controller.owner(epoch)?;
        let continuation = controller
            .continuation
            .as_ref()
            .ok_or(Error::RecoveryRequired)?;
        continuation.check(&owner)?;
        if continuation.retained.record().intent()? != intent {
            return Err(Error::ReviewMismatch);
        }
        let context = controller.context()?;
        controller.start(
            Work::PrepareContinuationSign(
                context,
                original.credentials.certificate_der.clone(),
                original.credentials.private_key_pkcs8_der.clone(),
            ),
            epoch,
        )?;
        drain(&mut controller, epoch)?;
        if !matches!(
            controller.review.as_ref().map(|r| &r.step),
            Some(Step::ContinuationSign(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve_current(&mut controller, epoch)?;
        let signature = controller
            .continuation
            .as_ref()
            .ok_or(Error::RecoveryRequired)?
            .signature(controller.owner(epoch)?.as_ref())?
            .ok_or(Error::RecoveryRequired)?;
        let expected =
            Zeroizing::new(serde_json::to_vec_pretty(&signature).map_err(|_| Error::InvalidData)?);
        let exported_file = destination.join(format!(
            "manual-roster-owner-continuation-v2-{}.json",
            hex::encode(Sha256::digest(expected.as_slice()))
        ));
        let context = controller.context()?;
        controller.start(
            Work::PrepareContinuationExport(context, destination.to_path_buf()),
            epoch,
        )?;
        drain(&mut controller, epoch)?;
        if !matches!(
            controller.review.as_ref().map(|r| &r.step),
            Some(Step::ContinuationExport(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve_current(&mut controller, epoch)?;
        if std::fs::read(&exported_file)?.as_slice() != expected.as_slice()
            || controller.continuation_controller.can_acquire()
            || controller.enrolled.is_some()
            || controller.receipt.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ExportedContinuationFixture {
            controller,
            original,
            exported_file,
        })
    }
}
pub(in crate::native_ui) struct ExportedContinuationFixture {
    controller: DrainingRosterController,
    original: AcknowledgedBornFixture,
    pub(in crate::native_ui) exported_file: PathBuf,
}
impl ExportedContinuationFixture {
    pub(in crate::native_ui) fn close(self) -> AcknowledgedBornFixture {
        let Self {
            controller,
            original,
            ..
        } = self;
        drop(controller);
        original
    }
}

/// Owns another genuine fresh entry, not the export-only continuation entry.
pub(in crate::native_ui) struct ContinuedPublicationFixture(PublicationRosterFixture);
impl ContinuedPublicationFixture {
    pub(in crate::native_ui) fn open(
        ui: BornManualRosterUiV2,
        original: AcknowledgedBornFixture,
        request: HostPublication,
    ) -> Result<Self> {
        request.validate().map_err(|_| Error::InvalidData)?;
        let ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest,
            attempt_sequence,
        } = &request.attempt
        else {
            return Err(Error::ReviewMismatch);
        };
        let mut controller = DrainingRosterController::new(ui, &original);
        let epoch = controller
            .owner
            .as_ref()
            .ok_or(Error::Locked)?
            .focus_epoch();
        drain(&mut controller, epoch)?;
        let owner = controller.owner(epoch)?;
        let open = controller.opened.as_ref().ok_or(Error::Locked)?;
        if !open.attempted
            || open.account_id != original.account_id
            || open
                .account
                .historical_birth_anchor()?
                .anchor()
                .birth_digest()
                != original.birth_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let retained = open
            .account
            .retained_born_manual_roster_enrollment_v2(&owner)?
            .ok_or(Error::RecoveryRequired)?;
        let original_request = retained.record().request()?;
        if original_request.enrollment != request.enrollment
            || original_request.roster != request.roster
        {
            return Err(Error::ReviewMismatch);
        }
        let selected = attempts::select(retained, continuation_digest, &owner)?;
        if selected.proposal.continuation.sequence() != *attempt_sequence {
            return Err(Error::ReviewMismatch);
        }
        drop(selected);
        let terms = &request.enrollment.terms;
        let scope = PairScope {
            account_id: original.account_id.clone(),
            agreement_id: terms.scope.agreement_id.clone(),
            participant_id: terms.scope.participant_id.clone(),
            manifest_digest: request.digest().map_err(|_| Error::InvalidData)?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        Ok(Self(PublicationRosterFixture {
            controller,
            original,
            request,
            scope,
            epoch,
        }))
    }
    pub(in crate::native_ui) fn endpoint(&self) -> Result<PathBuf> {
        self.0.endpoint()
    }
    pub(in crate::native_ui) fn deadline(&self) -> Result<Instant> {
        self.0.deadline()
    }
    pub(in crate::native_ui) fn close(self) -> AcknowledgedBornFixture {
        close_publication(self.0)
    }
    pub(in crate::native_ui) fn poll_publication(&mut self) -> Result<bool> {
        let fixture = &mut self.0;
        let ui = &mut fixture.controller;
        ui.poll_lifecycle(true, fixture.epoch);
        ui.owner(fixture.epoch)?;
        if ui.job.is_some() {
            return Ok(false);
        }
        if let Some(queued) = ui.queued_continuation.as_ref() {
            if *queued.request != fixture.request || queued.peer.scope != fixture.scope {
                return Err(Error::ReviewMismatch);
            }
        }
        if let Some(review) = ui.review.as_ref() {
            match &review.step {
                Step::Pair(pair) if pair.scope == fixture.scope && ui.peer.is_none() => {}
                Step::Witness(_)
                | Step::ContinuedReentry(_)
                | Step::Acquire(_)
                | Step::Activate(_)
                | Step::ContinuedAdmit(_)
                | Step::Publish(_)
                | Step::ContinuedServe(_)
                    if ui.peer.as_ref().is_some_and(|p| p.scope == fixture.scope) => {}
                _ => return Err(Error::ReviewMismatch),
            }
            let serving = matches!(&review.step, Step::ContinuedServe(_));
            approve_current(ui, fixture.epoch)?;
            return Ok(serving && ui.enrolled.is_some() && ui.job.is_none() && ui.review.is_none());
        }
        if ui.queued_continuation.is_some() && ui.writer.is_none() {
            let context = ui.context()?;
            ui.start(
                Work::PrepareWitness(context, fixture.original.credentials.roster_setup_json()?),
                fixture.epoch,
            )?;
        } else if ui.writer.is_some()
            && ui.continued_reentry.is_none()
            && ui.queued_continuation.is_some()
        {
            let context = ui.context()?;
            let request = ui
                .queued_continuation
                .as_ref()
                .ok_or(Error::RecoveryRequired)?
                .request
                .clone();
            ui.start(
                Work::PrepareContinuedReentry(context, request),
                fixture.epoch,
            )?;
        } else if ui.continued_reentry.is_some() && ui.receipt.is_none() {
            if ui.acquire_retry.is_some() {
                return Err(Error::Uncertain);
            }
            ui.continuation_controller.begin_acquire()?;
            let context = ui.context()?;
            ui.start(Work::PrepareAcquire(context), fixture.epoch)?;
        } else if ui.receipt.is_some() && !ui.activated {
            if ui.activation_retry.is_some() {
                return Err(Error::Uncertain);
            }
            let context = ui.context()?;
            let receipt = Box::new(ui.receipt.clone().ok_or(Error::Locked)?);
            ui.start(Work::PrepareActivate(context, receipt), fixture.epoch)?;
        } else if ui.activated && ui.enrolled.is_none() {
            if ui.continued_admission_retry.is_some() {
                return Err(Error::Uncertain);
            }
            let context = ui.context()?;
            ui.start(Work::PreparePublication(context), fixture.epoch)?;
        }
        Ok(ui.enrolled.is_some()
            && ui.queued_continuation.is_none()
            && ui.job.is_none()
            && ui.review.is_none())
    }
}

pub(in crate::native_ui) struct ExpectedDisclosures {
    pub(in crate::native_ui) inventory:
        wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryScopeV2,
    pub(in crate::native_ui) inventory_operation: String,
    pub(in crate::native_ui) selection:
        wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionScopeV2,
    pub(in crate::native_ui) selection_operation: String,
    pub(in crate::native_ui) retention_operation: String,
}
#[derive(Clone, Copy)]
enum DisclosurePhase {
    Publication,
    InventoryPair,
    Inventory,
    SelectionPair,
    Selection,
    Retention,
    Complete,
}
/// Only the actual Host's predetermined inventory/selection scopes and operation
/// IDs are approved. Request timestamps and caller bindings remain source-owned.
pub(in crate::native_ui) struct ContinuedDisclosuresFixture {
    publication: ContinuedPublicationFixture,
    expected: ExpectedDisclosures,
    phase: DisclosurePhase,
}
impl ContinuedDisclosuresFixture {
    pub(in crate::native_ui) fn new(
        publication: ContinuedPublicationFixture,
        expected: ExpectedDisclosures,
    ) -> Result<Self> {
        expected
            .inventory
            .validate()
            .map_err(|_| Error::InvalidData)?;
        expected
            .selection
            .validate()
            .map_err(|_| Error::InvalidData)?;
        if expected.inventory.inventory.enrollment != publication.0.request.enrollment.terms
            || expected.selection.selection.inventory != expected.inventory.inventory
            || expected.inventory_operation.is_empty()
            || expected.selection_operation.is_empty()
            || expected.retention_operation.is_empty()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(Self {
            publication,
            expected,
            phase: DisclosurePhase::Publication,
        })
    }
    pub(in crate::native_ui) fn endpoint(&self) -> Result<PathBuf> {
        self.publication.endpoint()
    }
    pub(in crate::native_ui) fn deadline(&self) -> Result<Instant> {
        self.publication.deadline()
    }
    pub(in crate::native_ui) fn close(self) -> AcknowledgedBornFixture {
        self.publication.close()
    }
    pub(in crate::native_ui) fn poll(&mut self) -> Result<bool> {
        if matches!(self.phase, DisclosurePhase::Publication) {
            if self.publication.poll_publication()? {
                self.phase = DisclosurePhase::InventoryPair;
            }
            return Ok(false);
        }
        if matches!(self.phase, DisclosurePhase::Complete) {
            return Ok(true);
        }
        let fixture = &mut self.publication.0;
        let ui = &mut fixture.controller;
        ui.poll_lifecycle(true, fixture.epoch);
        ui.owner(fixture.epoch)?;
        if ui.job.is_some() || ui.review.is_none() {
            return Ok(false);
        }
        let review = ui.review.as_ref().ok_or(Error::ReviewMismatch)?;
        let mut pair_scope = fixture.scope.clone();
        match (&self.phase, &review.step) {
            (DisclosurePhase::InventoryPair, Step::Pair(pair)) => {
                pair_scope.manifest_digest = self
                    .expected
                    .inventory
                    .pairing_digest()
                    .map_err(|_| Error::InvalidData)?;
                if pair.scope != pair_scope {
                    return Err(Error::ReviewMismatch);
                }
            }
            (DisclosurePhase::Inventory, Step::Inventory(prepared)) => {
                let request = prepared.synthetic_request();
                if request.scope != self.expected.inventory
                    || request.operation_id != self.expected.inventory_operation
                {
                    return Err(Error::ReviewMismatch);
                }
            }
            (DisclosurePhase::SelectionPair, Step::Pair(pair)) => {
                pair_scope.manifest_digest = self
                    .expected
                    .selection
                    .pairing_digest()
                    .map_err(|_| Error::InvalidData)?;
                if pair.scope != pair_scope {
                    return Err(Error::ReviewMismatch);
                }
            }
            (DisclosurePhase::Selection, Step::CandidateSelection(prepared)) => {
                let request = prepared.synthetic_request();
                if request.scope != self.expected.selection
                    || request.operation_id != self.expected.selection_operation
                {
                    return Err(Error::ReviewMismatch);
                }
            }
            (DisclosurePhase::Retention, Step::ContributionRetention(prepared)) => {
                let request = prepared.synthetic_request();
                if request.operation_id != self.expected.retention_operation
                    || request.selection.scope != self.expected.selection
                    || request.selection.operation_id != self.expected.selection_operation
                {
                    return Err(Error::ReviewMismatch);
                }
            }
            _ => return Err(Error::ReviewMismatch),
        }
        approve_current(ui, fixture.epoch)?;
        self.phase = match self.phase {
            DisclosurePhase::InventoryPair => DisclosurePhase::Inventory,
            DisclosurePhase::Inventory => DisclosurePhase::SelectionPair,
            DisclosurePhase::SelectionPair => DisclosurePhase::Selection,
            DisclosurePhase::Selection => DisclosurePhase::Retention,
            DisclosurePhase::Retention => DisclosurePhase::Complete,
            _ => return Err(Error::ReviewMismatch),
        };
        Ok(matches!(self.phase, DisclosurePhase::Complete))
    }
}

#[path = "born_roster_construction_v3.rs"]
pub(in crate::native_ui) mod construction_fixture;
