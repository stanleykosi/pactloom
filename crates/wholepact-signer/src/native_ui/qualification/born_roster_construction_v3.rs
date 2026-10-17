//! Finite synthetic event delivery for the same genuinely retained born owner.
//! Child of `born_manual_roster::continuation_fixture`; never a decision, peer,
//! source, or completed-record constructor. Production qualification stays shut.
use super::*;
use wholepact_core::manual_roster_construction_v3::{
    ManualRosterConstructionPlanV3, RosterCommonContextReadRequestV1,
};

/// Inert correlation from the Host's actual prepared full-plan owner. These
/// values cannot create a fixture original, native decision, read or admission.
#[derive(Clone)]
pub(in crate::native_ui) struct ExpectedCommonContextReadV3 {
    pub(in crate::native_ui) plan: ManualRosterConstructionPlanV3,
    pub(in crate::native_ui) durable_receipt_digest: String,
    pub(in crate::native_ui) witness_plan_approval_digest: String,
    pub(in crate::native_ui) read_operation: String,
    pub(in crate::native_ui) handoff_operation: String,
}

#[derive(Clone, Copy)]
enum ReadPhaseV3 {
    Publication,
    Pair,
    Read,
    Handoff,
    Complete,
}

pub(in crate::native_ui) struct CommonContextReadFixtureV3 {
    publication: ContinuedPublicationFixture,
    expected: ExpectedCommonContextReadV3,
    dispatch: Option<Arc<ScopedV3FixtureDispatch>>,
    phase: ReadPhaseV3,
}
impl CommonContextReadFixtureV3 {
    pub(in crate::native_ui) fn new(
        publication: ContinuedPublicationFixture,
        expected: ExpectedCommonContextReadV3,
    ) -> Result<Self> {
        expected.plan.validate().map_err(|_| Error::InvalidData)?;
        for digest in [
            &expected.durable_receipt_digest,
            &expected.witness_plan_approval_digest,
        ] {
            wholepact_core::proposal::validate_sha256(digest).map_err(|_| Error::InvalidData)?;
        }
        if expected.plan.enrollment() != &publication.0.request.enrollment.terms
            || expected.read_operation.is_empty()
            || expected.handoff_operation.is_empty()
            || expected.read_operation == expected.handoff_operation
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(Self {
            publication,
            expected,
            dispatch: None,
            phase: ReadPhaseV3::Publication,
        })
    }
    pub(in crate::native_ui) fn endpoint(&self) -> Result<PathBuf> {
        self.publication.endpoint()
    }
    pub(in crate::native_ui) fn deadline(&self) -> Result<Instant> {
        self.publication.deadline()
    }

    fn attach_exact_read_scope(&mut self) -> Result<()> {
        let fixture = &mut self.publication.0;
        let ui = &mut fixture.controller;
        let owner = ui.owner(fixture.epoch)?;
        if ui.job.is_some() || ui.review.is_some() || ui.enrolled.is_none() {
            return Err(Error::ReviewMismatch);
        }
        let opened = ui.opened.as_ref().ok_or(Error::Locked)?;
        if opened.account_id != fixture.original.account_id
            || opened
                .account
                .historical_birth_anchor()?
                .anchor()
                .birth_digest()
                != fixture.original.birth_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let retained = opened
            .account
            .retained_born_manual_roster_enrollment_v2(&owner)?
            .ok_or(Error::RecoveryRequired)?;
        retained.check_current_source(&owner)?;
        crate::account::birth::enrollment::roster_v2::retention::read_exact_with_ciphertext_digest(
            &retained,
            &self.expected.plan.retained,
            &self.expected.plan.retained_evidence_digest,
            &self.expected.durable_receipt_digest,
        )?;
        drop(retained);
        let mut scope = fixture.scope.clone();
        scope.manifest_digest = self
            .expected
            .plan
            .digest()
            .map_err(|_| Error::InvalidData)?;
        let mut ipc = opened.ipc.try_lock().map_err(|_| Error::Locked)?;
        let dispatch = Arc::new(ScopedV3FixtureDispatch {
            endpoint: ipc.socket_path().to_path_buf(),
            native: owner.native().binding(),
            scope,
            family: ExactDispatchFamilyV3::ReadAndHandoff(self.expected.clone()),
            next: Mutex::new(0),
        });
        ipc.attach_scoped_born_qualification_v3(dispatch.clone())?;
        drop(ipc);
        ui.certificate = Zeroizing::new(
            fixture
                .original
                .credentials
                .certificate_der
                .to_str()
                .ok_or(Error::InvalidData)?
                .to_owned(),
        );
        ui.key = Zeroizing::new(
            fixture
                .original
                .credentials
                .private_key_pkcs8_der
                .to_str()
                .ok_or(Error::InvalidData)?
                .to_owned(),
        );
        self.dispatch = Some(dispatch);
        Ok(())
    }
    /// Drives only the predetermined publication, exact plan pairing, one read
    /// and separate future-handoff native review. It sends no fabricated event.
    pub(in crate::native_ui) fn poll(&mut self) -> Result<bool> {
        if matches!(self.phase, ReadPhaseV3::Publication) {
            if self.publication.poll_publication()? {
                self.attach_exact_read_scope()?;
                self.phase = ReadPhaseV3::Pair;
            }
            return Ok(false);
        }
        if matches!(self.phase, ReadPhaseV3::Complete) {
            return Ok(true);
        }
        let fixture = &mut self.publication.0;
        let ui = &mut fixture.controller;
        ui.poll_lifecycle(true, fixture.epoch);
        ui.owner(fixture.epoch)?;
        if ui.job.is_some() || ui.review.is_none() {
            return Ok(false);
        }
        let dispatch = self.dispatch.as_ref().ok_or(Error::ReviewMismatch)?;
        match (
            &self.phase,
            &ui.review.as_ref().ok_or(Error::ReviewMismatch)?.step,
        ) {
            (ReadPhaseV3::Pair, Step::Pair(pair)) => dispatch.require_scope(&pair.scope)?,
            (ReadPhaseV3::Read, Step::CommonContextRead(_))
            | (ReadPhaseV3::Handoff, Step::CommonContextHandoffAuthorization(_)) => {
                dispatch.require_scope(&ui.peer.as_ref().ok_or(Error::Authentication)?.scope)?;
            }
            _ => return Err(Error::ReviewMismatch),
        }
        if let Step::CommonContextHandoffAuthorization(prepared) =
            &ui.review.as_ref().ok_or(Error::ReviewMismatch)?.step
        {
            // Exercise the SAME maintained borrowed check with the actual
            // prepared owner, not an archival DTO or manufactured source.
            let owner = ui.owner(fixture.epoch)?;
            prepared.qualification_check_wrong_read_and_caller(&owner)?;
        }
        approve_current(ui, fixture.epoch)?;
        self.phase = match self.phase {
            ReadPhaseV3::Pair => ReadPhaseV3::Read,
            ReadPhaseV3::Read => ReadPhaseV3::Handoff,
            ReadPhaseV3::Handoff => ReadPhaseV3::Complete,
            _ => return Err(Error::ReviewMismatch),
        };
        Ok(matches!(self.phase, ReadPhaseV3::Complete))
    }
    /// Actual focus loss invokes the maintained revoke-first path and retains
    /// its process-local, key-free original completion token. Nothing is rebuilt
    /// from the Host's read DTO or from saved receipt text.
    pub(in crate::native_ui) fn into_dormant(self) -> Result<DormantConstructionFixtureV3> {
        if !matches!(self.phase, ReadPhaseV3::Complete) {
            return Err(Error::ReviewMismatch);
        }
        let PublicationRosterFixture {
            mut controller,
            original,
            epoch,
            ..
        } = self.publication.0;
        controller.owner(epoch)?;
        controller
            .inventory_source
            .as_ref()
            .ok_or(Error::RecoveryRequired)?
            .check_common_context_completion_only()?;
        controller.blur();
        for cleanup in controller.cleanup.drain(..) {
            cleanup.join().map_err(|_| Error::Uncertain)?;
        }
        if controller.is_active() || !controller.has_dormant_common_context() {
            return Err(Error::ReviewMismatch);
        }
        Ok(DormantConstructionFixtureV3 {
            controller,
            original,
        })
    }
}

/// The original controller containing the actual key-free token is retained.
/// It is neither Clone nor reconstructible from a request, path or timestamp.
pub(in crate::native_ui) struct DormantConstructionFixtureV3 {
    controller: DrainingRosterController,
    original: AcknowledgedBornFixture,
}

enum ExactDispatchFamilyV3 {
    ReadAndHandoff(ExpectedCommonContextReadV3),
    Completion {
        original_read: RosterCommonContextReadRequestV1,
        original_read_admission_digest: String,
        reentry_operation: String,
        construction_operation: String,
    },
}

/// Restriction-only qualification owner. No public constructor, Clone or
/// Deserialize. Only this finite fixture module can create it after validating
/// the actual retained account/controller. It is attached once to THAT already
/// bound LocalIpc and only relaxes its outer unqualified-product refusal. The
/// ordinary token/kernel authentication, DTO validation and native handlers are
/// still mandatory. No public executable or environment flag selects it.
pub(crate) struct ScopedV3FixtureDispatch {
    endpoint: PathBuf,
    native: crate::native_ui::NativeAuthorityBinding,
    scope: PairScope,
    family: ExactDispatchFamilyV3,
    next: Mutex<u8>,
}
impl ScopedV3FixtureDispatch {
    pub(crate) fn require_native(
        &self,
        actual: &crate::native_ui::NativeAuthorityBinding,
    ) -> Result<()> {
        self.native.check_current()?;
        actual.check_current()?;
        if actual != &self.native {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }

    pub(crate) fn require_endpoint(&self, endpoint: &Path) -> Result<()> {
        self.native.check_current()?;
        if endpoint != self.endpoint {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn require_scope(&self, scope: &PairScope) -> Result<()> {
        self.native.check_current()?;
        if scope != &self.scope {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    /// Called only AFTER real kernel/process/token authentication. A failed or
    /// interrupted admitted frame consumes its phase; no uncertain new request
    /// can reuse this instance. Status is not a phase or spending authority.
    pub(crate) fn admit_authenticated(
        &self,
        request: &crate::ipc::AppRequest,
        scope: &PairScope,
    ) -> Result<()> {
        use crate::ipc::AppRequest as R;
        self.require_scope(scope)?;
        if matches!(request, R::Status {}) {
            return Ok(());
        }
        let mut next = self.next.try_lock().map_err(|_| Error::Locked)?;
        let accepted = match (&self.family, *next, request) {
            (
                ExactDispatchFamilyV3::ReadAndHandoff(expected),
                0,
                R::RequestBornRosterCommonContextReadV1 { request },
            ) => {
                request.plan == expected.plan
                    && request.operation_id == expected.read_operation
                    && request.original_durable_receipt_digest == expected.durable_receipt_digest
                    && request.witness_plan_approval_digest == expected.witness_plan_approval_digest
            }
            (
                ExactDispatchFamilyV3::ReadAndHandoff(expected),
                1,
                R::RequestBornRosterCommonContextHandoffAuthorizationV1 { request },
            ) => request.operation_id == expected.handoff_operation,
            (
                ExactDispatchFamilyV3::Completion {
                    original_read,
                    original_read_admission_digest,
                    reentry_operation,
                    ..
                },
                0,
                R::RequestBornRosterCommonContextReentryV1 { request, .. },
            ) => {
                request.original_read == *original_read
                    && request.original_read_admission_digest == *original_read_admission_digest
                    && request.operation_id == *reentry_operation
            }
            (
                ExactDispatchFamilyV3::Completion {
                    original_read,
                    construction_operation,
                    ..
                },
                1,
                R::RequestBornRosterReenteredConstructionV1 { request, .. },
            ) => {
                request.plan == original_read.plan
                    && request.operation_id == *construction_operation
            }
            _ => false,
        };
        if !accepted {
            return Err(Error::ReviewMismatch);
        }
        self.native.check_current()?;
        *next += 1;
        Ok(())
    }
}

/// Keeps the real controller and both temporary installations alive until the
/// independent witness reviews this exact native-signed export. It cannot be
/// promoted into a read or construction owner in place.
pub(in crate::native_ui) struct ExportedFullPlanFixtureV3 {
    controller: DrainingRosterController,
    original: AcknowledgedBornFixture,
    pub(in crate::native_ui) exported_file: PathBuf,
}
impl ExportedFullPlanFixtureV3 {
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

/// The caller supplies an inert file from the actual Host prepared-plan export.
/// The production preparation authenticates the original retained contribution
/// rows, complete plan, immutable policy and exact existing owner credential.
pub(in crate::native_ui) fn sign_and_export_full_plan_v3(
    ui: BornManualRosterUiV2,
    original: AcknowledgedBornFixture,
    plan_path: &Path,
    destination: &Path,
) -> Result<ExportedFullPlanFixtureV3> {
    if !original.root.starts_with(original.temporary.path())
        || !destination.starts_with(original.temporary.path())
        || !plan_path.is_absolute()
    {
        return Err(Error::ReviewMismatch);
    }
    let mut controller = DrainingRosterController::new(ui, &original);
    let epoch = controller
        .owner
        .as_ref()
        .ok_or(Error::Locked)?
        .focus_epoch();
    drain(&mut controller, epoch)?;
    let owner = controller.owner(epoch)?;
    let opened = controller.opened.as_ref().ok_or(Error::Locked)?;
    if !opened.attempted
        || opened.account_id != original.account_id
        || opened
            .account
            .historical_birth_anchor()?
            .anchor()
            .birth_digest()
            != original.birth_digest
        || controller.peer.is_some()
        || controller.writer.is_some()
        || controller.enrolled.is_some()
        || controller.inventory_source.is_some()
    {
        return Err(Error::ReviewMismatch);
    }
    let retained = opened
        .account
        .retained_born_manual_roster_enrollment_v2(&owner)?
        .ok_or(Error::RecoveryRequired)?;
    retained.check_current_source(&owner)?;
    drop(retained);
    drop(owner);
    let context = controller.context()?;
    controller.start(
        Work::PrepareConstructionV3Sign(
            context,
            original.credentials.certificate_der.clone(),
            original.credentials.private_key_pkcs8_der.clone(),
            plan_path.to_path_buf(),
        ),
        epoch,
    )?;
    drain(&mut controller, epoch)?;
    if !matches!(
        controller.review.as_ref().map(|r| &r.step),
        Some(Step::ConstructionV3Sign(_))
    ) {
        return Err(Error::ReviewMismatch);
    }
    approve_current(&mut controller, epoch)?;
    let envelope = controller
        .construction_v3_signed
        .as_ref()
        .ok_or(Error::RecoveryRequired)?
        .clone();
    if envelope.approval.plan.enrollment().identity.account_id != original.account_id {
        return Err(Error::ReviewMismatch);
    }
    let expected = Zeroizing::new(
        serde_json::to_vec_pretty(envelope.as_ref()).map_err(|_| Error::InvalidData)?,
    );
    let exported_file = destination.join(format!(
        "manual-roster-construction-approval-v3-{}.json",
        hex::encode(Sha256::digest(expected.as_slice())),
    ));
    let context = controller.context()?;
    controller.start(
        Work::PrepareConstructionV3Export(context, envelope, destination.to_path_buf()),
        epoch,
    )?;
    drain(&mut controller, epoch)?;
    if !matches!(
        controller.review.as_ref().map(|r| &r.step),
        Some(Step::ConstructionV3Export(_))
    ) {
        return Err(Error::ReviewMismatch);
    }
    approve_current(&mut controller, epoch)?;
    if std::fs::read(&exported_file)?.as_slice() != expected.as_slice()
        || controller.peer.is_some()
        || controller.writer.is_some()
        || controller.enrolled.is_some()
        || controller.inventory_source.is_some()
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(ExportedFullPlanFixtureV3 {
        controller,
        original,
        exported_file,
    })
}

#[derive(Clone)]
pub(in crate::native_ui) struct ExpectedCompletionOperationsV3 {
    pub(in crate::native_ui) reentry_operation: String,
    pub(in crate::native_ui) construction_operation: String,
}
#[derive(Clone, Copy)]
enum CompletionPhaseV3 {
    Pair,
    Request,
    Witness,
    Claim,
    Construction,
    Park,
    Complete,
}
pub(in crate::native_ui) struct CompletionFixtureV3 {
    controller: DrainingRosterController,
    original: AcknowledgedBornFixture,
    dispatch: Arc<ScopedV3FixtureDispatch>,
    client_scope:
        Option<wholepact_authority::native_witness_owner::EphemeralConstructionClientScopeV1>,
    epoch: u64,
    deadline: Instant,
    phase: CompletionPhaseV3,
}
impl DormantConstructionFixtureV3 {
    pub(in crate::native_ui) fn reopen(
        self,
        expected: ExpectedCompletionOperationsV3,
        client_scope: wholepact_authority::native_witness_owner::EphemeralConstructionClientScopeV1,
    ) -> Result<CompletionFixtureV3> {
        let Self {
            mut controller,
            original,
        } = self;
        if controller.is_active()
            || !controller.has_dormant_common_context()
            || expected.reentry_operation.is_empty()
            || expected.construction_operation.is_empty()
            || expected.reentry_operation == expected.construction_operation
        {
            return Err(Error::ReviewMismatch);
        }
        let actual = std::mem::take(&mut controller.0);
        let actual = crate::native_ui::runtime::NativeRuntime::entered_born_common_context_for_qualification(
            actual, &original.root,
        )?;
        // The old wrapper now owns only an empty controller. The SAME dormant
        // slot moved into the real focused runtime branch, not into a factory.
        drop(controller);
        let mut controller = DrainingRosterController::new(actual, &original);
        let epoch = controller
            .owner
            .as_ref()
            .ok_or(Error::Locked)?
            .focus_epoch();
        drain(&mut controller, epoch)?;
        let owner = controller.owner(epoch)?;
        let deadline = owner.native().binding().bounded_deadline()?;
        let opened = controller
            .completion_opened
            .as_ref()
            .ok_or(Error::RecoveryRequired)?;
        let source = opened.source.as_ref().ok_or(Error::RecoveryRequired)?;
        source.check(&owner)?;
        let read = source.original_read();
        let plan = &read.request.plan;
        if plan.enrollment().identity.account_id != original.account_id
            || plan.enrollment().native_birth_digest != original.birth_digest
            || expected.reentry_operation == read.request.operation_id
            || expected.construction_operation == read.request.operation_id
        {
            return Err(Error::ReviewMismatch);
        }
        let scope = PairScope {
            account_id: original.account_id.clone(),
            agreement_id: plan.enrollment().scope.agreement_id.clone(),
            participant_id: plan.enrollment().scope.participant_id.clone(),
            manifest_digest: plan.digest().map_err(|_| Error::InvalidData)?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        let mut ipc = opened.ipc.try_lock().map_err(|_| Error::Locked)?;
        let dispatch = Arc::new(ScopedV3FixtureDispatch {
            endpoint: ipc.socket_path().into(),
            native: owner.native().binding(),
            scope,
            family: ExactDispatchFamilyV3::Completion {
                original_read: read.request.clone(),
                original_read_admission_digest: read.digest().map_err(|_| Error::InvalidData)?,
                reentry_operation: expected.reentry_operation,
                construction_operation: expected.construction_operation,
            },
            next: Mutex::new(0),
        });
        ipc.attach_scoped_born_qualification_v3(dispatch.clone())?;
        drop(ipc);
        drop(owner);
        Ok(CompletionFixtureV3 {
            controller,
            original,
            dispatch,
            client_scope: Some(client_scope),
            epoch,
            deadline,
            phase: CompletionPhaseV3::Pair,
        })
    }
}
impl CompletionFixtureV3 {
    pub(in crate::native_ui) fn endpoint(&self) -> Result<PathBuf> {
        self.controller.owner(self.epoch)?;
        let open = self
            .controller
            .completion_opened
            .as_ref()
            .ok_or(Error::Locked)?;
        let ipc = open.ipc.try_lock().map_err(|_| Error::Locked)?;
        self.dispatch.require_endpoint(ipc.socket_path())?;
        Ok(ipc.socket_path().into())
    }
    pub(in crate::native_ui) fn deadline(&self) -> Result<Instant> {
        self.controller.owner(self.epoch)?;
        if Instant::now() >= self.deadline {
            return Err(Error::ReviewMismatch);
        }
        Ok(self.deadline)
    }
    pub(in crate::native_ui) fn poll(&mut self) -> Result<bool> {
        let ui = &mut self.controller;
        ui.poll_lifecycle(true, self.epoch);
        if matches!(self.phase, CompletionPhaseV3::Complete) {
            return Ok(true);
        }
        if matches!(self.phase, CompletionPhaseV3::Park) {
            // Final Consume revokes its old native entry before draining. Its
            // absence is expected here, never evidence of failed/rolled-back
            // consumption. Only the actual finished key-free token is success.
            if ui.has_dormant_named() && !ui.is_active() {
                self.phase = CompletionPhaseV3::Complete;
                return Ok(true);
            }
            if ui.job.is_none() && ui.cleanup.is_empty() && !ui.named_reentry.draining() {
                return Err(Error::Uncertain);
            }
            return Ok(false);
        }
        ui.owner(self.epoch)?;
        if Instant::now() >= self.deadline {
            return Err(Error::ReviewMismatch);
        }
        if ui.job.is_some() {
            return Ok(false);
        }
        if matches!(self.phase, CompletionPhaseV3::Request) && ui.review.is_none() {
            let open = ui.completion_opened.as_mut().ok_or(Error::Locked)?;
            if open.queued.is_none() {
                return Ok(false);
            }
            let source = open.source.take().ok_or(Error::ReviewMismatch)?;
            let request = open.queued.take().ok_or(Error::ReviewMismatch)?;
            let setup = self.original.credentials.roster_setup_json()?;
            ui.start(
                Work::PrepareCompletionWitness(Box::new(CompletionWork {
                    source,
                    request,
                    setup,
                })),
                self.epoch,
            )?;
            self.phase = CompletionPhaseV3::Witness;
            return Ok(false);
        }
        let Some(review) = ui.review.as_ref() else {
            return Ok(false);
        };
        match (&self.phase, &review.step) {
            (CompletionPhaseV3::Pair, Step::Pair(pair)) => {
                self.dispatch.require_scope(&pair.scope)?
            }
            (CompletionPhaseV3::Witness, Step::CompletionWitness(_))
            | (CompletionPhaseV3::Claim, Step::CompletionClaim(_))
            | (CompletionPhaseV3::Construction, Step::ReenteredConstruction(_)) => {
                let peer = ui.peer.as_ref().ok_or(Error::Authentication)?;
                self.dispatch.require_scope(&peer.scope)?;
                self.dispatch.require_native(&peer.native_origin)?;
            }
            _ => return Err(Error::ReviewMismatch),
        }
        if matches!(self.phase, CompletionPhaseV3::Witness) {
            let owner = ui.owner(self.epoch)?;
            let Step::CompletionWitness(prepared) =
                &mut ui.review.as_mut().ok_or(Error::ReviewMismatch)?.step
            else {
                return Err(Error::ReviewMismatch);
            };
            // Move the genuine witness-issued one-use scope into this actual
            // prepared contact only. Native review and source checks still run.
            prepared.attach_qualification_scope(
                self.client_scope.take().ok_or(Error::ReviewMismatch)?,
                &owner,
            )?;
        }
        if matches!(self.phase, CompletionPhaseV3::Construction) {
            let Step::ReenteredConstruction(prepared) =
                &ui.review.as_ref().ok_or(Error::ReviewMismatch)?.step
            else {
                return Err(Error::ReviewMismatch);
            };
            let owner = ui.owner(self.epoch)?;
            prepared.qualification_check_wrong_lineage(&owner)?;
            drop(owner);
            approve_exact_consumption_without_old_owner_drain(ui, self.epoch)?;
            self.phase = CompletionPhaseV3::Park;
            return Ok(false);
        }
        approve_current(ui, self.epoch)?;
        self.phase = match self.phase {
            CompletionPhaseV3::Pair => CompletionPhaseV3::Request,
            CompletionPhaseV3::Witness => CompletionPhaseV3::Claim,
            CompletionPhaseV3::Claim => CompletionPhaseV3::Construction,
            _ => return Err(Error::ReviewMismatch),
        };
        Ok(false)
    }
    pub(in crate::native_ui) fn into_named(self) -> Result<ConsumedNamedFixtureV3> {
        if !matches!(self.phase, CompletionPhaseV3::Complete)
            || self.controller.is_active()
            || !self.controller.has_dormant_named()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ConsumedNamedFixtureV3 {
            controller: self.controller,
            original: self.original,
        })
    }
}

fn approve_exact_consumption_without_old_owner_drain(
    ui: &mut BornManualRosterUiV2,
    epoch: u64,
) -> Result<()> {
    ui.owner(epoch)?;
    let review = ui.review.as_mut().ok_or(Error::ReviewMismatch)?;
    if !matches!(review.step, Step::ReenteredConstruction(_))
        || review.exact.display().is_empty()
        || review.exact.confirming()
    {
        return Err(Error::ReviewMismatch);
    }
    review.displayed_to_end = true;
    if review
        .exact
        .continue_from_native_click(false, epoch)
        .is_ok()
        || review
            .exact
            .continue_from_native_click(true, epoch.wrapping_add(1))
            .is_ok()
    {
        return Err(Error::ReviewMismatch);
    }
    review.exact.continue_from_native_click(true, epoch)?;
    ui.confirmation = Zeroizing::new(format!("AUTHORIZE {}", &review.exact.digest()[..12]));
    ui.approve(true, epoch)
}

/// Only actual completed Reserve/Consume plus revoke/drain can produce this.
/// The next native entry is owned by the purpose-distinct named controller.
pub(in crate::native_ui) struct ConsumedNamedFixtureV3 {
    controller: DrainingRosterController,
    original: AcknowledgedBornFixture,
}
impl ConsumedNamedFixtureV3 {
    pub(in crate::native_ui) fn into_parts(
        self,
    ) -> Result<(BornManualRosterUiV2, AcknowledgedBornFixture)> {
        let Self {
            mut controller,
            original,
        } = self;
        if controller.is_active() || !controller.has_dormant_named() {
            return Err(Error::ReviewMismatch);
        }
        let actual = std::mem::take(&mut controller.0);
        drop(controller);
        Ok((actual, original))
    }
}

#[path = "born_named_continuation_v1.rs"]
pub(in crate::native_ui) mod named_fixture;
