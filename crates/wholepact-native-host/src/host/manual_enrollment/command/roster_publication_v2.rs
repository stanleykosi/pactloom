//! Actual Host owner conjunction for roster-bound audit publication. This route
//! retains audit-only first saves; explicit existing-original continuation routes
//! can add separately admitted fresh viewing and selection, never construction/signing.
mod continuation_intent;
mod import_target_v2;
mod inventory_v2;
mod selection_v2;
mod sequential_construction_v2;
mod sequential_construction_v3;
use super::*;
use import_target_v2::CommittedRosterAudit;
pub(in crate::host) use import_target_v2::CommittedRosterImportTarget;
use wholepact_authority::manual_roster_continuation_signature_v2::ManualRosterContinuationOwnerSignatureV2;
use wholepact_authority::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use wholepact_authority::manual_roster_signature_v2::ManualRosterEnrollmentOwnerSignatureV2;
use wholepact_signer_origin::{
    ManualRosterEnrollmentLeaseV2,
    manual_roster_v2::{HostManualRosterPublicationRequestV2, ManualRosterPublicationAttemptV2},
};

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
enum RosterAuditPurpose {
    InitialPublicationV3,
    ExistingOriginalContinuationV4,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparationMode {
    AuditOnly,
    Inventory,
    InventoryAndSelection,
    InventoryAndRetainedSelection,
}
impl PreparationMode {
    fn require_purpose(self, continuation: bool, purpose: RosterAuditPurpose) -> Result<()> {
        if self != Self::AuditOnly
            && (!continuation || purpose != RosterAuditPurpose::ExistingOriginalContinuationV4)
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
}
struct PreparedRosterPublication<'host> {
    original: PreparedManualEnrollment<'host>,
    request: HostManualRosterPublicationRequestV2,
    extension: ManualRosterEnrollmentExtensionV2,
    purpose: RosterAuditPurpose,
    prior_digest: Option<String>,
    approval: PublicationApproval,
    review_digest: String,
}
impl<'host> PreparedRosterPublication<'host> {
    fn read_original(
        &self,
    ) -> Result<Option<wholepact_store::manual_enrollment::ManualEnrollmentAdditionalPublicationV3>>
    {
        let source = &self.original.source;
        source
            .host
            .engine
            .manual_roster_request_original(
                source.host.access()?,
                &source.engine,
                &self.request,
                &self.extension.account_extension.enrollment_ref,
                &self
                    .extension
                    .account_extension
                    .digest()
                    .map_err(|_| Error::Invalid)?,
                &self.extension.digest().map_err(|_| Error::Invalid)?,
                &self.extension.signer_roster_record_digest,
            )
            .map_err(Into::into)
    }
    fn check_before(&self) -> Result<()> {
        self.original.source.check_current()?;
        self.original.approval.check()?;
        self.approval.check()?;
        let actual = self.read_original()?;
        let digest = actual.as_ref().map(|a| a.digest()).transpose()?;
        if digest != self.prior_digest {
            return Err(Error::Authentication);
        }
        if let Some(a) = &actual {
            if self.purpose == RosterAuditPurpose::InitialPublicationV3
                && serde_json::to_value(&a.evidence.request)?
                    != serde_json::to_value(&self.request)?
            {
                return Err(Error::Authentication);
            }
        } else if self.purpose == RosterAuditPurpose::ExistingOriginalContinuationV4 {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn require_lease(&self, lease: &ManualRosterEnrollmentLeaseV2<'_>) -> Result<()> {
        self.check_before()?;
        lease.check_current().map_err(|_| Error::Permission)?;
        let e = lease.evidence();
        if lease.binding() != &self.request
            || e.enrollment_ref != self.extension.account_extension.enrollment_ref
            || e.witness_extension_digest
                != self
                    .extension
                    .account_extension
                    .digest()
                    .map_err(|_| Error::Invalid)?
            || e.witness_roster_extension_digest
                != self.extension.digest().map_err(|_| Error::Invalid)?
            || e.signer_roster_record_digest != self.extension.signer_roster_record_digest
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn append(
        self,
        lease: ManualRosterEnrollmentLeaseV2<'_>,
    ) -> Result<wholepact_store::manual_enrollment::ManualAuditAppendReceipt> {
        self.append_owned(lease).map(|(receipt, _)| receipt)
    }
    fn append_owned(
        self,
        lease: ManualRosterEnrollmentLeaseV2<'_>,
    ) -> Result<(
        wholepact_store::manual_enrollment::ManualAuditAppendReceipt,
        CommittedRosterAudit<'host>,
    )> {
        self.require_lease(&lease)?;
        let original_signer_intent_digest = lease.evidence().admission.signer_intent_digest.clone();
        let deadline = self
            .original
            .source
            .history_review
            .deadline()
            .min(self.original.approval.deadline())
            .min(self.approval.deadline());
        let Self {
            original,
            request,
            extension,
            purpose,
            prior_digest,
            approval,
            review_digest,
        } = self;
        approval.commit(
            &review_digest,
            || {
                original.source.check_current()?;
                original.approval.check()?;
                lease.check_current().map_err(|_| Error::Permission)?;
                // The Store transaction repeats complete original/predecessor CAS.
                Ok((lease, original))
            },
            |(lease, original)| {
                let source = &original.source;
                let receipt = match purpose {
                    RosterAuditPurpose::InitialPublicationV3 => {
                        source.host.engine.append_manual_roster_initial_v3(
                            source.host.access()?,
                            &source.engine,
                            &original.idempotency_key,
                            lease,
                        )?
                    }
                    RosterAuditPurpose::ExistingOriginalContinuationV4 => {
                        source.host.engine.append_manual_roster_continuation_v4(
                            source.host.access()?,
                            &source.engine,
                            &original.idempotency_key,
                            lease,
                        )?
                    }
                };
                // The pre-append roster owner is deliberately not revalidated as
                // current here. Transition to the exact newly retained original.
                source.check_current()?;
                let after = source
                    .host
                    .engine
                    .manual_roster_request_original(
                        source.host.access()?,
                        &source.engine,
                        &request,
                        &extension.account_extension.enrollment_ref,
                        &extension
                            .account_extension
                            .digest()
                            .map_err(|_| Error::Invalid)?,
                        &extension.digest().map_err(|_| Error::Invalid)?,
                        &extension.signer_roster_record_digest,
                    )?
                    .ok_or(Error::Authentication)?;
                let expected = match purpose {
                    RosterAuditPurpose::InitialPublicationV3 => receipt.audit_digest().to_owned(),
                    RosterAuditPurpose::ExistingOriginalContinuationV4 => {
                        prior_digest.ok_or(Error::Authentication)?
                    }
                };
                if after.digest()? != expected {
                    return Err(Error::Authentication);
                }
                let committed = CommittedRosterAudit {
                    original,
                    request,
                    extension,
                    original_audit_digest: expected,
                    original_signer_intent_digest,
                    review_digest: review_digest.clone(),
                    deadline,
                };
                committed.check_current()?;
                Ok((receipt, committed))
            },
        )
    }
}
impl Host {
    fn prepare_manual_roster_account_owner<'host>(
        &'host self,
        request: &HostManualEnrollmentRequest,
        idempotency_key: &str,
    ) -> Result<PreparedManualEnrollment<'host>> {
        request.validate().map_err(|_| Error::Invalid)?;
        require_session(self, &request.terms)?;
        // This is separate real private-history consent, not a serialized
        // continuity/status field. No financial or current signer claim follows.
        let review = self.terminal.approve_historical(&format!(
            "Inspect the complete protected ancestor capsule for exact manual-enrollment distinctness.\nCurrent local profile: {}\nAgreement: {}\nObligation: {}\nOnly historical identities/exclusions are compared; this does not spend, prove, sign or submit.",
            self.secrets.profile(), request.terms.scope.agreement_id, request.terms.scope.obligation_id,
        ))?;
        let mut committed = None;
        review.effect(&mut || {
            committed = Some(ManualCommittedTarget::open(&self.directory, &self.secrets)?);
            Ok(())
        })?;
        let committed = committed.ok_or(Error::Authentication)?;
        let engine = self
            .engine
            .manual_enrollment_target(self.access()?, &request.terms)?;
        let financial_origin_digest = self
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .manual_original_primary_origin_digest(&self.directory, &self.secrets)?;
        let source = ManualEnrollmentOwners {
            host: self,
            engine,
            committed,
            history_review: review,
            financial_origin_digest,
            request: request.clone(),
        };
        source.check_current()?;
        let context = wholepact_store::CommandContext::for_request(
            &request.terms.scope.principal_id,
            idempotency_key,
            &serde_json::to_value(request)?,
        )?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-roster-account-owner-review:v2",
            &(
                &context,
                source.engine.agreement_record_digest(),
                source.engine.agreement_revision(),
                source.engine.owner_client_id(),
            ),
        )
        .map_err(|_| Error::Authentication)?;
        let detail = format!(
            "Review the immutable original account owner for an exact additional-account roster AUDIT in this already-open recovered host.\nProfile: {}\nRoot: {}\nPrincipal: {}\nAgreement: {}\nObligation: {}\nAccount/FVK commitment: {}/{}\nExact reviewed terms: {}\nStore and journal bindings, complete inherited identity coverage, original signer/witness admission and this native decision are checked independently. This does not create an ordinary authority account, restore a grant, reserve funds, clear historical exposure or enable a financial action.\nExact local review: {}",
            source.committed.profile_id(),
            source.committed.canonical_root(),
            request.terms.scope.principal_id,
            request.terms.scope.agreement_id,
            request.terms.scope.obligation_id,
            request.terms.identity.account_id,
            request.terms.identity.full_viewing_key_digest,
            request.digest().map_err(|_| Error::Invalid)?,
            review_digest,
        );
        let approval = self.terminal.approve_publication_reviewed(
            &source.history_review,
            &review_digest,
            &detail,
        )?;
        source.check_current()?;
        Ok(PreparedManualEnrollment {
            source,
            approval,
            review_digest,
            idempotency_key: idempotency_key.into(),
        })
    }
    fn prepare_roster_publication<'host>(
        &'host self,
        request: HostManualRosterPublicationRequestV2,
        extension: ManualRosterEnrollmentExtensionV2,
        purpose: RosterAuditPurpose,
        idempotency_key: &str,
    ) -> Result<PreparedRosterPublication<'host>> {
        request.validate().map_err(|_| Error::Invalid)?;
        extension.validate().map_err(|_| Error::Invalid)?;
        if request.enrollment.terms != extension.account_extension.terms
            || request.roster != extension.roster
        {
            return Err(Error::Authentication);
        }
        let original =
            self.prepare_manual_roster_account_owner(&request.enrollment, idempotency_key)?;
        let prior = self.engine.manual_roster_request_original(
            self.access()?,
            &original.source.engine,
            &request,
            &extension.account_extension.enrollment_ref,
            &extension
                .account_extension
                .digest()
                .map_err(|_| Error::Invalid)?,
            &extension.digest().map_err(|_| Error::Invalid)?,
            &extension.signer_roster_record_digest,
        )?;
        if purpose == RosterAuditPurpose::ExistingOriginalContinuationV4 && prior.is_none() {
            return Err(Error::Authentication);
        }
        if let Some(a) = &prior {
            if purpose == RosterAuditPurpose::InitialPublicationV3
                && serde_json::to_value(&a.evidence.request)? != serde_json::to_value(&request)?
            {
                return Err(Error::Authentication);
            }
        }
        let prior_digest = prior.as_ref().map(|a| a.digest()).transpose()?;
        let context = wholepact_store::CommandContext::for_request(
            &request.enrollment.terms.scope.principal_id,
            idempotency_key,
            &serde_json::to_value(&request)?,
        )?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-roster-audit-publication-review:v2",
            &(
                &context,
                &request,
                &extension,
                purpose,
                &prior_digest,
                original.source.engine.agreement_record_digest(),
                original.source.engine.agreement_revision(),
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let approval = self.terminal.approve_publication_reviewed(&original.source.history_review, &review_digest, &format!(
            "Retain this exact roster-bound audit under the original account ledger and unchanged exclusions.\nOriginal prior Host audit: {}\nExact request and predecessor: {}\nExact witness extension: {}\nStale ancestry rejects; no automatic rebase. All Host review occurs before signer focus. The actual installed signer and witness must independently approve and remain current. This adds audit history only; no wallet import, construction, proof, signing or dispatch permission follows.",
            prior_digest.as_deref().unwrap_or("absent: explicit new additional-account publication"),
            serde_json::to_string_pretty(&request)?, extension.digest().map_err(|_| Error::Invalid)?,
        ))?;
        let prepared = PreparedRosterPublication {
            original,
            request,
            extension,
            purpose,
            prior_digest,
            approval,
            review_digest,
        };
        prepared.check_before()?;
        Ok(prepared)
    }

    pub(in crate::host) fn manual_roster_initial_publish_v2_command(&self) -> Result<()> {
        self.roster_publish_v2(
            false,
            RosterAuditPurpose::InitialPublicationV3,
            PreparationMode::AuditOnly,
        )
    }
    pub(in crate::host) fn manual_roster_initial_continued_publish_v2_command(&self) -> Result<()> {
        self.roster_publish_v2(
            true,
            RosterAuditPurpose::InitialPublicationV3,
            PreparationMode::AuditOnly,
        )
    }
    pub(in crate::host) fn manual_roster_continue_publish_v2_command(&self) -> Result<()> {
        self.roster_publish_v2(
            true,
            RosterAuditPurpose::ExistingOriginalContinuationV4,
            PreparationMode::AuditOnly,
        )
    }
    pub(in crate::host) fn manual_roster_continue_inventory_v2_command(&self) -> Result<()> {
        self.roster_publish_v2(
            true,
            RosterAuditPurpose::ExistingOriginalContinuationV4,
            PreparationMode::Inventory,
        )
    }
    pub(in crate::host) fn manual_roster_continue_select_v2_command(&self) -> Result<()> {
        self.roster_publish_v2(
            true,
            RosterAuditPurpose::ExistingOriginalContinuationV4,
            PreparationMode::InventoryAndSelection,
        )
    }
    fn roster_publish_v2(
        &self,
        continuation: bool,
        requested_purpose: RosterAuditPurpose,
        preparation: PreparationMode,
    ) -> Result<()> {
        if preparation == PreparationMode::InventoryAndRetainedSelection {
            return Err(Error::Permission);
        }
        let retained =
            self.roster_publish_v2_collect(continuation, requested_purpose, preparation)?;
        if retained.is_some() {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn roster_publish_v2_collect<'host>(
        &'host self,
        continuation: bool,
        requested_purpose: RosterAuditPurpose,
        preparation: PreparationMode,
    ) -> Result<Option<crate::host::financial::manual_roster_inventory_setup_v2::RetainedRosterCandidateInputsV2<'host>>>{
        preparation.require_purpose(continuation, requested_purpose)?;
        self.require_manual_session()?;
        let key = self
            .terminal
            .ask("Exact roster Host audit idempotency key (new for each new attempt; preserve for its exact retry): ")?;
        id(&key)?;
        let (extension, attempt, purpose) = if continuation {
            let signed: ManualRosterContinuationOwnerSignatureV2 = self.read_manual_private(
                "Exact private roster-continuation signature JSON file: ",
                "reviewing the exact existing roster enrollment continuation",
            )?;
            signed.extension.validate().map_err(|_| Error::Invalid)?;
            signed
                .continuation
                .validate_for(&signed.extension)
                .map_err(|_| Error::Invalid)?;
            let attempt = ManualRosterPublicationAttemptV2::ContinuationV2 {
                continuation_digest: signed
                    .continuation
                    .digest_for(&signed.extension)
                    .map_err(|_| Error::Invalid)?,
                attempt_sequence: signed.continuation.sequence(),
            };
            (signed.extension, attempt, requested_purpose)
        } else {
            let signed: ManualRosterEnrollmentOwnerSignatureV2 = self.read_manual_private(
                "Exact private initial roster owner-signature JSON file: ",
                "reviewing exact new account and roster predecessor",
            )?;
            (
                signed.extension,
                ManualRosterPublicationAttemptV2::InitialV2 {},
                RosterAuditPurpose::InitialPublicationV3,
            )
        };
        // Files remain correlation data. Embedded certificate pins are never
        // installed; the actual native signer/witness independently authenticate.
        let request = HostManualRosterPublicationRequestV2 {
            version: 2,
            enrollment: HostManualEnrollmentRequest {
                terms: extension.account_extension.terms.clone(),
            },
            roster: extension.roster.clone(),
            attempt,
        };
        let prepared = self.prepare_roster_publication(request, extension, purpose, &key)?;
        let inventory = if preparation != PreparationMode::AuditOnly {
            Some(inventory_v2::prepare(
                self,
                &prepared,
                matches!(
                    preparation,
                    PreparationMode::InventoryAndSelection
                        | PreparationMode::InventoryAndRetainedSelection
                ),
                preparation == PreparationMode::InventoryAndRetainedSelection,
            )?)
        } else {
            None
        };
        let exact_digest = prepared.request.digest().map_err(|_| Error::Invalid)?;
        let terms = &prepared.request.enrollment.terms;
        let request_approval = self.terminal.approve_publication_reviewed(&prepared.original.source.history_review, &exact_digest, &format!(
            "Send this exact full roster publication request to the fixed installed signer after fresh native pairing.\nAccount: {}\nAgreement/participant: {}/{}\nFull request: {}\nThe original deadline survives pairing; no new admission is inferred from a retained file.",
            terms.identity.account_id, terms.scope.agreement_id, terms.scope.participant_id, exact_digest))?;
        let pair_approval = self.terminal.approve_publication_reviewed(&prepared.original.source.history_review, &exact_digest,
            "Approve exact bounded local pairing metadata for this full roster request. Complete all terminal interaction now, then stay in the signer workspace for independent review.")?;
        let deadline = prepared
            .original
            .source
            .history_review
            .deadline()
            .min(prepared.original.approval.deadline())
            .min(prepared.approval.deadline())
            .min(request_approval.deadline())
            .min(pair_approval.deadline());
        let deadline = inventory
            .as_ref()
            .map_or(deadline, |owner| deadline.min(owner.deadline()));
        if let Some(owner) = &inventory {
            owner.check_before(&prepared)?;
        }
        prepared.check_before()?;
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        provider.launch_native().map_err(|_| Error::Permission)?;
        let endpoint = wait_manual_endpoint_before(&provider, deadline)?;
        let pending_pair = pair_approval.commit(
            &exact_digest,
            || prepared.check_before(),
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    &endpoint,
                    "wholepact-native-roster-publication-v2",
                    PairScope {
                        account_id: terms.identity.account_id.clone(),
                        agreement_id: terms.scope.agreement_id.clone(),
                        participant_id: terms.scope.participant_id.clone(),
                        manifest_digest: exact_digest.clone(),
                        history_read: false,
                        authorization_export: false,
                        preconstruction_export: false,
                    },
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        let client = pending_pair.finish().map_err(|_| Error::Permission)?;
        let pending = request_approval.commit(
            &exact_digest,
            || prepared.check_before(),
            |_| {
                client
                    .begin_roster_enrollment_v2_before(&prepared.request, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        let lease = pending.finish().map_err(|_| Error::Permission)?;
        let (receipt, retained) = if let Some(inventory) = inventory {
            inventory.check_before(&prepared)?;
            let (receipt, committed) = prepared.append_owned(lease)?;
            let retained = inventory.run(self, client, &committed)?;
            (receipt, retained)
        } else {
            (prepared.append(lease)?, None)
        };
        self.terminal.message(&format!("Exact roster audit retained. Operation: {}. Original enrollment: {}. Audit: {}. Exact retry: {}. No financial permission was issued.\n",
            receipt.operation_id(), receipt.enrollment_ref(), receipt.audit_digest(), receipt.replayed()))?;
        Ok(retained)
    }
}

#[cfg(test)]
mod preparation_tests {
    use super::*;
    #[test]
    fn viewing_and_selection_require_existing_original_continuation() {
        for mode in [
            PreparationMode::Inventory,
            PreparationMode::InventoryAndSelection,
        ] {
            assert!(
                mode.require_purpose(false, RosterAuditPurpose::InitialPublicationV3)
                    .is_err()
            );
            assert!(
                mode.require_purpose(true, RosterAuditPurpose::InitialPublicationV3)
                    .is_err()
            );
            assert!(
                mode.require_purpose(false, RosterAuditPurpose::ExistingOriginalContinuationV4)
                    .is_err()
            );
            assert!(
                mode.require_purpose(true, RosterAuditPurpose::ExistingOriginalContinuationV4)
                    .is_ok()
            );
        }
    }
    #[test]
    fn audit_only_first_save_keeps_original_version_semantics() {
        assert!(
            PreparationMode::AuditOnly
                .require_purpose(false, RosterAuditPurpose::InitialPublicationV3)
                .is_ok()
        );
        assert!(
            PreparationMode::AuditOnly
                .require_purpose(true, RosterAuditPurpose::InitialPublicationV3)
                .is_ok()
        );
        assert!(
            PreparationMode::AuditOnly
                .require_purpose(true, RosterAuditPurpose::ExistingOriginalContinuationV4)
                .is_ok()
        );
    }
}
