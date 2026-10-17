//! Finite synthetic delivery after the SAME actual V3 consume and key-free park.
//! Child of construction_fixture. No raw token, owner, decision or source input.
use super::*;
use crate::native_ui::born_manual_roster_v2::named_controls::NamedStep;
use crate::native_ui::runtime::NativeRuntime;

struct DrainingNamedController {
    ui: BornManualRosterUiV2,
    // Keep both actual temporary installations alive through every child drain.
    _account: Arc<tempfile::TempDir>,
    _credentials: EphemeralOwnerCredentials,
    epoch: u64,
}
impl Drop for DrainingNamedController {
    fn drop(&mut self) {
        self.ui.clear();
        // The real workers retain their original deadlines. Do not drop files
        // beneath them or manufacture an early successful cancellation result.
        while self.ui.is_active() {
            self.ui.poll_lifecycle(false, self.epoch);
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
#[derive(Clone, Copy)]
enum Phase {
    Pair,
    LocalRecords,
    Ready,
}

pub(in crate::native_ui) struct NamedContinuationFixtureV1 {
    controller: DrainingNamedController,
    original: AcknowledgedBornFixture,
    scope: wholepact_signer_origin::PairScope,
    proposal: wholepact_core::proposal::ProposalInput,
    proposal_digest: String,
    account_fvk_digest: String,
    budget: u64,
    existing_records: bool,
    reviewed_enrollment: bool,
    reviewed_manifest: bool,
    phase: Phase,
    payment: Option<payment_fixture::RetainedPayment>,
    completed_verifier_scopes:
        Vec<wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyScopeV1>,
    selected_verifier_scope:
        Option<wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyScopeV1>,
}
impl NamedContinuationFixtureV1 {
    pub(in crate::native_ui) fn open(actual: ConsumedNamedFixtureV3) -> Result<Self> {
        let (ui, original) = actual.into_parts()?;
        let mut controller = DrainingNamedController {
            ui,
            _account: original.temporary.clone(),
            _credentials: original.credentials.clone(),
            epoch: 1,
        };
        if !original.root.starts_with(original.temporary.path())
            || !controller.ui.has_dormant_named()
            || controller.ui.is_active()
        {
            return Err(Error::ReviewMismatch);
        }
        NativeRuntime::enter_consumed_named_for_qualification(&mut controller.ui, &original.root)?;
        controller.epoch = controller
            .ui
            .owner
            .as_ref()
            .ok_or(Error::Locked)?
            .focus_epoch();
        drain(&mut controller.ui, controller.epoch)?;
        if controller.ui.named_continuation.is_some()
            || controller.ui.named_reentry.source.is_none()
        {
            return Err(Error::ReviewMismatch);
        }
        // Paths come solely from the nominal prior authority installation. This
        // finite operation never accepts replacement credentials or a writer key.
        controller.ui.witness_setup = Zeroizing::new(
            serde_json::to_string(&serde_json::json!({
                "trusted_server_root_der": original.credentials.trusted_server_root_der,
                "owner_certificate_der": original.credentials.certificate_der,
                "owner_private_key_pkcs8_der": original.credentials.private_key_pkcs8_der,
                "operator_name": "Explicit synthetic never-funded ephemeral witness",
                "retention_statement": "Only the same concrete temporary qualification installation",
            })).map_err(|_| Error::InvalidData)?,
        );
        controller
            .ui
            .prepare_named_original_owner_contact(controller.epoch)?;
        drain(&mut controller.ui, controller.epoch)?;
        if !matches!(
            controller.ui.review.as_ref().map(|review| &review.step),
            Some(Step::NamedReentryWitness(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        // Actual ExactNativeReview transition; synthetic event delivery is not
        // attended-human evidence and does not claim pixel-level GUI testing.
        approve_current(&mut controller.ui, controller.epoch)?;
        let owner = controller.ui.owner(controller.epoch)?;
        let named = controller
            .ui
            .named_continuation
            .as_ref()
            .ok_or(Error::Locked)?;
        named.check(&owner)?;
        let source = named.source();
        if source.genesis().identity.account_id != original.account_id
            || source.genesis().native_birth_digest != original.birth_digest
            || source.genesis().owner_certificate_digest
                != original.credentials.origin().owner_certificate_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let construction = source.construction();
        let plan = &construction.reservation.request.construction.plan;
        let proposal = plan.validate().map_err(|_| Error::InvalidData)?;
        let scope = wholepact_signer_origin::PairScope {
            account_id: original.account_id.clone(),
            agreement_id: plan.enrollment().scope.agreement_id.clone(),
            participant_id: plan.enrollment().scope.participant_id.clone(),
            manifest_digest: proposal.manifest_digest().to_owned(),
            history_read: true,
            authorization_export: false,
            preconstruction_export: false,
        };
        let account_fvk_digest = source.genesis().identity.full_viewing_key_digest.clone();
        let budget = plan.enrollment().scope.aggregate_budget_zatoshis;
        let existing_records = match source.local_records(&owner)? {
            (Some(_), Some(_)) => true,
            (None, None) => false,
            _ => return Err(Error::RecoveryRequired),
        };
        let proposal_input = proposal.input().clone();
        let proposal_digest = proposal.proposal_digest().to_owned();
        drop(owner);
        Ok(Self {
            controller,
            original,
            scope,
            proposal: proposal_input,
            proposal_digest,
            account_fvk_digest,
            budget,
            existing_records,
            reviewed_enrollment: false,
            reviewed_manifest: false,
            phase: Phase::Pair,
            selected_verifier_scope: None,
            payment: None,
            completed_verifier_scopes: Vec::new(),
        })
    }
    pub(in crate::native_ui) fn endpoint(&self) -> Result<PathBuf> {
        self.check_source()?;
        let opened = self
            .controller
            .ui
            .completion_opened
            .as_ref()
            .ok_or(Error::Locked)?;
        let ipc = opened.ipc.try_lock().map_err(|_| Error::Locked)?;
        Ok(ipc.socket_path().to_path_buf())
    }
    pub(in crate::native_ui) fn deadline(&self) -> Result<Instant> {
        self.controller
            .ui
            .owner(self.controller.epoch)?
            .native()
            .binding()
            .bounded_deadline()
    }
    pub(in crate::native_ui) fn pairing_scope(&self) -> Result<wholepact_signer_origin::PairScope> {
        self.check_source()?;
        Ok(self.scope.clone())
    }
    fn check_source(&self) -> Result<()> {
        let owner = self.controller.ui.owner(self.controller.epoch)?;
        let actual = self
            .controller
            .ui
            .named_continuation
            .as_ref()
            .ok_or(Error::Locked)?;
        actual.check(&owner)?;
        if actual.source().genesis().identity.account_id != self.original.account_id
            || actual.source().genesis().native_birth_digest != self.original.birth_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn require_enrollment(
        &self,
        record: &crate::consent_journal::AccountEnrollmentRecord,
    ) -> Result<()> {
        if record.account_id() != self.scope.account_id
            || record.agreement_id() != self.scope.agreement_id
            || record.participant_id() != self.scope.participant_id
            || record.account_fvk_digest() != self.account_fvk_digest
            || record.budget_limit_zatoshis() != self.budget
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn require_manifest(
        &self,
        record: &crate::consent_journal::AcceptedManifestRecord,
    ) -> Result<()> {
        if record.proposal_input() != &self.proposal
            || record.proposal_digest() != self.proposal_digest
            || record.manifest_digest() != self.scope.manifest_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    /// Poll only actual kernel Pair/Status and the two exact local reviews.
    /// The Host must remain the original process. No request or peer is injected.
    pub(in crate::native_ui) fn poll_exact_pairing_and_local_records(&mut self) -> Result<bool> {
        let epoch = self.controller.epoch;
        self.controller.ui.poll_lifecycle(true, epoch);
        self.controller.ui.owner(epoch)?;
        if self.controller.ui.job.is_some() {
            return Ok(false);
        }
        self.check_source()?;
        if let Some(review) = self.controller.ui.review.as_ref() {
            match (&self.phase, &review.step) {
                (Phase::Pair, Step::Pair(pair)) if pair.scope == self.scope => {}
                (Phase::LocalRecords, Step::Named(step)) => match step.as_ref() {
                    NamedStep::Enrollment(prepared)
                        if !self.existing_records
                            && !self.reviewed_enrollment
                            && !self.reviewed_manifest =>
                    {
                        self.require_enrollment(prepared.record())?;
                    }
                    NamedStep::Manifest(prepared)
                        if !self.existing_records
                            && self.reviewed_enrollment
                            && !self.reviewed_manifest =>
                    {
                        self.require_manifest(prepared.record())?;
                    }
                    _ => return Err(Error::ReviewMismatch),
                },
                _ => return Err(Error::ReviewMismatch),
            }
            let enrollment = matches!(&review.step, Step::Named(step) if matches!(step.as_ref(), NamedStep::Enrollment(_)));
            let manifest = matches!(&review.step, Step::Named(step) if matches!(step.as_ref(), NamedStep::Manifest(_)));
            approve_current(&mut self.controller.ui, epoch)?;
            self.reviewed_enrollment |= enrollment;
            self.reviewed_manifest |= manifest;
            if matches!(self.phase, Phase::Pair) {
                self.phase = Phase::LocalRecords;
            }
        }
        if matches!(self.phase, Phase::LocalRecords | Phase::Ready)
            && self.controller.ui.job.is_none()
            && self.controller.ui.review.is_none()
        {
            let named = self
                .controller
                .ui
                .named_continuation
                .as_ref()
                .ok_or(Error::Locked)?;
            if named.session().is_ok() {
                if let Ok((enrollment, manifest)) = named.local_records() {
                    self.require_enrollment(enrollment)?;
                    self.require_manifest(manifest)?;
                    if manifest.enrollment_ref() != enrollment.reference()
                        || (!self.existing_records
                            && !(self.reviewed_enrollment && self.reviewed_manifest))
                    {
                        return Err(Error::ReviewMismatch);
                    }
                    self.phase = Phase::Ready;
                }
            }
        }
        Ok(matches!(self.phase, Phase::Ready))
    }
}

#[path = "born_named_profile_v1.rs"]
mod profile_fixture;

#[path = "born_named_verifier_v1.rs"]
mod verifier_fixture;

#[path = "born_named_enrollment_v1.rs"]
mod enrollment_fixture;

#[path = "born_named_payment_v1.rs"]
mod payment_fixture;
