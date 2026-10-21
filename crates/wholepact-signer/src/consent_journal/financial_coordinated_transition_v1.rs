//! Private one-effect consuming join. No source constructor, runtime registration,
//! transport wait, NativeDecision conversion or key use occurs here. Display and
//! Arm precede Ready outside all source locks; only genuine Final permits commit.
use super::*;
use wholepact_financial_coordinator_origin::{
    SignerContinueArmV1, SignerContinueFinalV1, SignerContinuePresentationV1,
    SignerContinueReviewDataV1, SignerContinueRoleV1,
};

// Closed genuine-token observation only. No ordinary-data constructor can
// supply either branch. Legacy narrow entries pass no workflow guard.
#[cfg(feature = "coordinated-financial-workflow-v1")]
enum WorkflowPrivateReadV2<'a> {
    Arm(&'a SignerContinueArmV1),
    Final(&'a SignerContinueFinalV1),
}
#[cfg(feature = "coordinated-financial-workflow-v1")]
impl WorkflowPrivateReadV2<'_> {
    fn check(&self) -> Result<()> {
        match self {
            Self::Arm(value) => value.check_current(),
            Self::Final(value) => value.check_current(),
        }
        .map_err(|_| JournalError::Permission)
    }
}

/// Frozen presentation and inert exact preparation, not effect authority.
/// The actual source owner must remain separately retained. No Clone or serde.
pub(crate) struct PresentedCoordinatedFinancialContinuationV1 {
    prepared: PreparedCoordinatedFinancialContinuationV1,
    presentation_digest: String,
}

/// Result classification only, never a retry signal or permission. An uncertain
/// rollback is distinguished from an actual commit attempt; neither returns the
/// consumed source, ticket or genuine Final to a caller.
#[derive(Debug)]
pub(crate) struct CoordinatedContinuationCommitFailureV1 {
    cause: crate::Error,
    commit_attempted: bool,
    uncertain: bool,
}
impl CoordinatedContinuationCommitFailureV1 {
    pub(crate) fn before_effect(cause: crate::Error) -> Self {
        Self {
            cause,
            commit_attempted: false,
            uncertain: false,
        }
    }
    pub(crate) fn after_commit_attempt(cause: crate::Error) -> Self {
        Self {
            cause,
            commit_attempted: true,
            uncertain: true,
        }
    }
    pub(crate) fn cause(&self) -> &crate::Error {
        &self.cause
    }
    pub(crate) fn commit_attempted(&self) -> bool {
        self.commit_attempted
    }
    pub(crate) fn is_uncertain(&self) -> bool {
        self.uncertain
    }
}

fn review_matches(
    local: &CoordinatedContinueReviewDataV1,
    original: &SignerContinueReviewDataV1,
) -> bool {
    local.coordinator_process_instance == original.coordinator_process_instance
        && local.coordinator_focus_epoch == original.coordinator_focus_epoch
        && matches!(
            (local.signer_role, original.signer_role),
            (
                CoordinatedContinueSignerRoleV1::Signer1,
                SignerContinueRoleV1::Signer1
            ) | (
                CoordinatedContinueSignerRoleV1::Signer2,
                SignerContinueRoleV1::Signer2
            )
        )
        && local.signer_process_instance == original.signer_process_instance
        && local.original_host_process_instance == original.original_host_process_instance
        && local.signer_principal_id == original.signer_principal_id
        && local.signer_image_measurement == original.signer_image_measurement
        && local.source_identity_digest == original.source_identity_digest
        && local.terms_digest == original.terms_digest
        && local.session_digest == original.session_digest
        && local.review_challenge == original.review_challenge
        && local.review_digest == original.review_digest
        && local.reviewed_at_ms == original.reviewed_at_ms
        && local.expires_at_ms == original.expires_at_ms
        && local.session_expires_at_ms == original.session_expires_at_ms
}

impl PreparedCoordinatedFinancialContinuationV1 {
    /// Consumes ordinary preparation into another inert value. The full canonical
    /// request must be exactly the one bound into the origin's presentation. A
    /// valid DTO can never construct an Arm, Final or a source owner.
    pub(crate) fn freeze_presentation_v1(
        self,
        presentation: &SignerContinuePresentationV1,
    ) -> Result<PresentedCoordinatedFinancialContinuationV1> {
        presentation
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        self.check_retained_preparation()?;
        if !review_matches(
            &self.intent.coordinated_provenance.review,
            &presentation.review,
        ) || presentation.request_json != encode(self.request())?.as_str()
            || presentation.prepared_digest != self.prepared_digest
            || self.recompute_prepared_digest()? != self.prepared_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        // request_digest is the origin's request-bytes domain, not Authority's
        // different semantic request domain. validate() checks that byte digest.
        Ok(PresentedCoordinatedFinancialContinuationV1 {
            prepared: self,
            presentation_digest: presentation.presentation_digest.clone(),
        })
    }
    fn recompute_prepared_digest(&self) -> Result<String> {
        digest(
            PREPARED_DOMAIN,
            &(
                &self.intent,
                &self.source_identity,
                &self.original_rows_digest,
                self.source_revision,
                self.history
                    .history_digest()
                    .map_err(|_| JournalError::InvalidBinding)?,
                self.history.snapshot(),
                self.original_host.instance(),
                self.original_ceiling_ms,
            ),
        )
    }
    /// During transition the held write transaction makes its own schema/row
    /// changes. Compare the original frozen source revision here; actual current
    /// connection revision is additionally checked before beginning the effect.
    fn check_frozen(
        &self,
        journal: &SignerConsentJournal,
        source: &FinancialSourceBindingV1,
        c: &Connection,
    ) -> Result<()> {
        self.check_frozen_inner_v2(
            journal,
            source,
            c,
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            None,
        )
    }
    fn check_frozen_inner_v2(
        &self,
        journal: &SignerConsentJournal,
        source: &FinancialSourceBindingV1,
        c: &Connection,
        #[cfg(feature = "coordinated-financial-workflow-v1")] workflow: Option<
            &WorkflowPrivateReadV2<'_>,
        >,
    ) -> Result<()> {
        macro_rules! check_workflow {
            () => {
                #[cfg(feature = "coordinated-financial-workflow-v1")]
                if let Some(guard) = workflow {
                    guard.check()?;
                }
            };
        }
        check_workflow!();
        self.check_retained_preparation()?;
        if self.journal != journal.binding()
            || self.source_identity != source.source_digest
            || self.original_rows_digest != source.original_rows_digest
            || self.source_revision
                != (
                    source.revision.data_version,
                    source.revision.total_changes,
                    source.revision.schema_version,
                    source.revision.user_version,
                )
            || source.continuation_digest.is_some()
            || self
                .intent
                .coordinated_provenance
                .review
                .original_host_process_instance
                != self.original_host.instance()
        {
            return Err(JournalError::Permission);
        }
        source.require(journal, c)?;
        check_workflow!();
        if original_rows_digest(c)? != self.original_rows_digest {
            return Err(JournalError::Conflict);
        }
        check_workflow!();
        let record = self.intent.record()?;
        record
            .terms
            .require_live(now_ms()?)
            .map_err(|_| JournalError::Expired)?;
        if record.terms.valid_until_ms != self.original_ceiling_ms
            || prepare_financial_continuation_request_v1(
                record.terms.clone(),
                self.intent.seed()?,
                &self.history,
            )
            .map_err(|_| JournalError::InvalidBinding)?
                != self.intent.request
            || self.recompute_prepared_digest()? != self.prepared_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        check_workflow!();
        self.intent.validate_original(c)?;
        check_workflow!();
        self.check_retained_preparation()
    }
}

impl PresentedCoordinatedFinancialContinuationV1 {
    pub(crate) fn request(&self) -> &OwnerControlRequest {
        self.prepared.request()
    }
    pub(crate) fn prepared_digest(&self) -> &str {
        &self.prepared.prepared_digest
    }
    pub(crate) fn presentation_digest(&self) -> &str {
        &self.presentation_digest
    }
    pub(crate) fn check_source(
        &self,
        identity: &str,
        original_deadline: Instant,
        original_ceiling_ms: u64,
    ) -> Result<()> {
        if self.prepared.source_identity != identity
            || self.prepared.original_deadline != original_deadline
            || self.prepared.original_ceiling_ms != original_ceiling_ms
        {
            return Err(JournalError::Permission);
        }
        self.prepared.check_retained_preparation()
    }
    fn matches_original(
        &self,
        review: &SignerContinueReviewDataV1,
        prepared_digest: &str,
        presentation_digest: &str,
        original_source_deadline: Instant,
        original_review_deadline: Instant,
    ) -> Result<()> {
        if !review_matches(&self.prepared.intent.coordinated_provenance.review, review)
            || prepared_digest != self.prepared.prepared_digest
            || presentation_digest != self.presentation_digest
            || original_source_deadline != self.prepared.original_deadline
            || original_review_deadline != self.prepared.original_review_deadline
        {
            return Err(JournalError::Permission);
        }
        self.prepared.check_retained_preparation()
    }
    pub(crate) fn check_arm(&self, arm: &SignerContinueArmV1) -> Result<()> {
        arm.check_current().map_err(|_| JournalError::Permission)?;
        self.matches_original(
            arm.review(),
            arm.prepared_digest(),
            arm.presentation_digest(),
            arm.original_source_deadline(),
            arm.original_review_deadline(),
        )?;
        arm.check_current().map_err(|_| JournalError::Permission)
    }
    pub(crate) fn check_final(&self, final_admission: &SignerContinueFinalV1) -> Result<()> {
        final_admission
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        self.matches_original(
            final_admission.review(),
            final_admission.prepared_digest(),
            final_admission.presentation_digest(),
            final_admission.original_source_deadline(),
            final_admission.original_review_deadline(),
        )?;
        final_admission
            .check_current()
            .map_err(|_| JournalError::Permission)
    }
}

impl SignerConsentJournal {
    /// Read-only same-ticket check; no guard survives return to the Ready sender.
    pub(crate) fn check_coordinated_financial_preparation_v1(
        &self,
        source: &FinancialSourceBindingV1,
        presented: &PresentedCoordinatedFinancialContinuationV1,
        arm: &SignerContinueArmV1,
    ) -> Result<()> {
        self.check_coordinated_financial_preparation_inner_v2(source, presented, arm, false)
    }
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(crate) fn check_coordinated_financial_preparation_workflow_v2(
        &self,
        source: &FinancialSourceBindingV1,
        presented: &PresentedCoordinatedFinancialContinuationV1,
        arm: &SignerContinueArmV1,
    ) -> Result<()> {
        self.check_coordinated_financial_preparation_inner_v2(source, presented, arm, true)
    }
    fn check_coordinated_financial_preparation_inner_v2(
        &self,
        source: &FinancialSourceBindingV1,
        presented: &PresentedCoordinatedFinancialContinuationV1,
        arm: &SignerContinueArmV1,
        workflow: bool,
    ) -> Result<()> {
        macro_rules! check_workflow {
            () => {
                if workflow {
                    presented.check_arm(arm)?;
                }
            };
        }
        check_workflow!();
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        presented.check_arm(arm)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        presented.check_arm(arm)?;
        source.require(self, &c)?;
        check_workflow!();
        source.require_pin(&c)?;
        check_workflow!();
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        presented.check_arm(arm)?;
        original_delivery::validate(&tx, &source.genesis, self.capacity_limits())?;
        check_workflow!();
        if workflow {
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            presented.prepared.check_frozen_inner_v2(
                self,
                source,
                &tx,
                Some(&WorkflowPrivateReadV2::Arm(arm)),
            )?;
            #[cfg(not(feature = "coordinated-financial-workflow-v1"))]
            return Err(JournalError::Permission);
        } else {
            presented.prepared.check_frozen(self, source, &tx)?;
        }
        check_workflow!();
        source.require_pin(&tx)?;
        presented.check_arm(arm)?;
        tx.commit()?;
        check_workflow!();
        source.require_pin(&c)?;
        presented.check_arm(arm)?;
        Ok(())
    }
}

impl FinancialConsentJournalV1 {
    /// Consumes actual original journal/source and one genuine Final. Errors
    /// report whether commit was attempted, without enabling any implicit retry.
    pub(crate) fn transition_coordinated_original_v1(
        journal: SignerConsentJournal,
        source: FinancialSourceBindingV1,
        presented: PresentedCoordinatedFinancialContinuationV1,
        final_admission: SignerContinueFinalV1,
    ) -> std::result::Result<
        (Self, PendingFinancialContinuationAdmissionV1),
        CoordinatedContinuationCommitFailureV1,
    > {
        Self::transition_coordinated_original_inner_v2(
            journal,
            source,
            presented,
            final_admission,
            false,
        )
    }
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(crate) fn transition_coordinated_original_workflow_v2(
        journal: SignerConsentJournal,
        source: FinancialSourceBindingV1,
        presented: PresentedCoordinatedFinancialContinuationV1,
        final_admission: SignerContinueFinalV1,
    ) -> std::result::Result<
        (Self, PendingFinancialContinuationAdmissionV1),
        CoordinatedContinuationCommitFailureV1,
    > {
        Self::transition_coordinated_original_inner_v2(
            journal,
            source,
            presented,
            final_admission,
            true,
        )
    }
    fn transition_coordinated_original_inner_v2(
        journal: SignerConsentJournal,
        mut source: FinancialSourceBindingV1,
        presented: PresentedCoordinatedFinancialContinuationV1,
        final_admission: SignerContinueFinalV1,
        workflow: bool,
    ) -> std::result::Result<
        (Self, PendingFinancialContinuationAdmissionV1),
        CoordinatedContinuationCommitFailureV1,
    > {
        macro_rules! check_workflow {
            () => {
                if workflow {
                    presented.check_final(&final_admission)?;
                }
            };
        }
        let mut commit_attempted = false;
        let mut rollback_uncertain = false;
        let result: Result<RetainedFinancialContinuationIntentV1> = (|| {
            if Arc::strong_count(&journal.source_registration) != 1 {
                return Err(JournalError::Conflict);
            }
            presented.check_final(&final_admission)?;
            let retained;
            {
                let _fence = journal
                    .authority_fence
                    .write()
                    .map_err(|_| JournalError::Permission)?;
                presented.check_final(&final_admission)?;
                let mut c = journal
                    .connection
                    .lock()
                    .map_err(|_| JournalError::Database)?;
                presented.check_final(&final_admission)?;
                source.require(&journal, &c)?;
                check_workflow!();
                source.require_pin(&c)?;
                check_workflow!();
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let staged: Result<RetainedFinancialContinuationIntentV1> = (|| {
                    presented.check_final(&final_admission)?;
                    source.require_pin(&tx)?;
                    check_workflow!();
                    original_delivery::validate(
                        &tx,
                        &source.genesis,
                        journal.capacity_limits(),
                    )?;
                    check_workflow!();
                    if workflow {
                        #[cfg(feature = "coordinated-financial-workflow-v1")]
                        presented.prepared.check_frozen_inner_v2(
                            &journal,
                            &source,
                            &tx,
                            Some(&WorkflowPrivateReadV2::Final(&final_admission)),
                        )?;
                        #[cfg(not(feature = "coordinated-financial-workflow-v1"))]
                        return Err(JournalError::Permission);
                    } else {
                        presented.prepared.check_frozen(&journal, &source, &tx)?;
                    }
                    presented.check_final(&final_admission)?;
                    // One exact local profile19->20 transaction, not a network
                    // send or permission for Witness Admit, acquisition or keys.
                    tx.execute_batch(EXTENSION)?;
                    check_workflow!();
                    let i = &presented.prepared.intent;
                    i.validate_original(&tx)?;
                    check_workflow!();
                    let r = i.record()?;
                    let payload = encode(i)?;
                    tx.execute("INSERT INTO signer_financial_continuation_intents(operation_id,authorization_id,original_admission_operation_id,request_digest,enrollment_ref,manifest_ref,payload) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                        params![i.request.operation_id, r.terms.scope.authorization.authorization_id, r.terms.original_delivery_operation_id,
                            r.request_digest(&i.request).map_err(|_| JournalError::InvalidBinding)?, r.terms.original_recipient_enrollment_ref,
                            r.terms.original_recipient_manifest_ref, payload.as_str()])?;
                    check_workflow!();
                    tx.pragma_update(None, "user_version", VERSION)?;
                    check_workflow!();
                    validate(&tx, &source.genesis)?;
                    check_workflow!();
                    if workflow {
                        #[cfg(feature = "coordinated-financial-workflow-v1")]
                        presented.prepared.check_frozen_inner_v2(
                            &journal,
                            &source,
                            &tx,
                            Some(&WorkflowPrivateReadV2::Final(&final_admission)),
                        )?;
                        #[cfg(not(feature = "coordinated-financial-workflow-v1"))]
                        return Err(JournalError::Permission);
                    } else {
                        presented.prepared.check_frozen(&journal, &source, &tx)?;
                    }
                    check_workflow!();
                    let retained = intent::read(&tx)?;
                    check_workflow!();
                    source.continuation_digest = Some(retained.history_digest()?);
                    source.revision = revision(&tx)?;
                    presented.check_final(&final_admission)?;
                    Ok(retained)
                })();
                retained = match staged {
                    Ok(retained) => retained,
                    Err(error) => {
                        // Never call a failed rollback 'known no effect'. The
                        // owned connection/source still drop on this error path.
                        rollback_uncertain = tx.rollback().is_err();
                        return Err(error);
                    }
                };
                // Set before the call, including a commit error whose durable
                // result cannot be classified safely from the error alone.
                commit_attempted = true;
                tx.commit()?;
                if workflow {
                    // Final remains retained here. Metadata/revision is enough:
                    // the exact committed intent/rows were read inside this tx.
                    presented.check_final(&final_admission)?;
                    source.require(&journal, &c)?;
                    presented.check_final(&final_admission)?;
                    if source.revision != revision(&c)? {
                        return Err(JournalError::Conflict);
                    }
                    presented.check_final(&final_admission)?;
                } else {
                    source.require_pin(&c)?;
                }
            }
            Ok(retained)
        })();
        let retained = result.map_err(|cause| CoordinatedContinuationCommitFailureV1 {
            cause: cause.into(),
            commit_attempted,
            uncertain: commit_attempted || rollback_uncertain,
        })?;
        // Neither opaque grant nor peer/history custody becomes a new permission.
        drop(final_admission);
        drop(presented);
        let genesis = source.genesis.clone();
        Ok((
            Self { journal, genesis },
            PendingFinancialContinuationAdmissionV1 { source, retained },
        ))
    }
}

#[cfg(test)]
mod pure_binding_tests {
    use super::*;

    fn facts() -> CoordinatedContinueReviewDataV1 {
        CoordinatedContinueReviewDataV1 {
            coordinator_process_instance: "01".repeat(32),
            coordinator_focus_epoch: 1,
            signer_role: CoordinatedContinueSignerRoleV1::Signer1,
            signer_process_instance: "02".repeat(32),
            original_host_process_instance: "03".repeat(32),
            signer_principal_id: "shape-only".into(),
            signer_image_measurement: "04".repeat(32),
            source_identity_digest: "05".repeat(32),
            terms_digest: "06".repeat(32),
            session_digest: "07".repeat(32),
            review_challenge: "08".repeat(32),
            review_digest: "09".repeat(32),
            reviewed_at_ms: 1_000,
            expires_at_ms: 121_000,
            session_expires_at_ms: 300_000,
        }
    }
    #[test]
    fn ordinary_origin_field_matching_is_exact_and_never_constructs_a_token() {
        let local = facts();
        let original: SignerContinueReviewDataV1 =
            serde_json::from_value(serde_json::to_value(&local).unwrap()).unwrap();
        assert!(review_matches(&local, &original));
        let value = serde_json::to_value(&original).unwrap();
        for key in value.as_object().unwrap().keys() {
            let mut changed = value.clone();
            let field = changed.get_mut(key).unwrap();
            *field = match key.as_str() {
                "signer_role" => serde_json::json!("signer2"),
                "signer_principal_id" => serde_json::json!("other-principal"),
                _ if field.is_number() => serde_json::json!(field.as_u64().unwrap() + 1),
                _ => serde_json::json!("ff".repeat(32)),
            };
            let changed: SignerContinueReviewDataV1 = serde_json::from_value(changed).unwrap();
            assert!(!review_matches(&local, &changed), "unmatched field: {key}");
        }
    }
    #[test]
    fn commit_failure_classification_never_loses_uncertainty() {
        let before =
            CoordinatedContinuationCommitFailureV1::before_effect(crate::Error::ReviewMismatch);
        assert!(!before.commit_attempted());
        assert!(!before.is_uncertain());
        let rollback = CoordinatedContinuationCommitFailureV1 {
            cause: crate::Error::ConsentJournal(JournalError::Database),
            commit_attempted: false,
            uncertain: true,
        };
        assert!(!rollback.commit_attempted());
        assert!(rollback.is_uncertain());
        let commit = CoordinatedContinuationCommitFailureV1::after_commit_attempt(
            crate::Error::ReviewMismatch,
        );
        assert!(commit.commit_attempted());
        assert!(commit.is_uncertain());
        assert!(matches!(commit.cause(), crate::Error::ReviewMismatch));
    }
}
