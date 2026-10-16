//! Ownership-preserving bridge from original retained V2 material into a single
//! new V3 read and construction. No historical record can manufacture a source.
use super::*;
use wholepact_signer_origin::{
    AdmittedManualRosterConstructionContributionV3, AdmittedRosterCommonContextReadV1,
    PendingRosterCommonContextReadV1,
};
use wholepact_wallet::wallet::protected_sync::exact_input_observation::{
    CommonContextVerifierSnapshot, FreshCommonContextObservation,
    HeldCommonContextRosterObservation,
};

impl SignerRetainedRosterContributionV2 {
    /// Consumes BOTH original owners into this transition. The pending native
    /// request owns the original native retained object and its once-only gate;
    /// this wrapper owns the actual maintained material. Failure drops both.
    pub fn begin_common_context_read_before<'client>(
        self,
        client: &'client wholepact_signer_origin::NativeManualClient,
        request: &wholepact_core::manual_roster_construction_v3::RosterCommonContextReadRequestV1,
        expected_current_attempt_digest: &str,
        expected_current_attempt_sequence: u64,
        deadline: std::time::Instant,
        original_host_deadline: std::time::Instant,
    ) -> Result<PendingSignerCommonContextReadV1<'client>> {
        self.check_retained()?;
        let evidence = self.native.evidence().clone();
        let durable_receipt_digest = self.native.durable_receipt_digest().to_owned();
        let provider_enrollment_reference = self.native.provider_enrollment_reference().to_owned();
        let pending = client.begin_roster_common_context_read_before(
            request,
            self.native,
            expected_current_attempt_digest,
            expected_current_attempt_sequence,
            deadline,
            original_host_deadline,
        )?;
        Ok(PendingSignerCommonContextReadV1 {
            pending,
            selected: self.selected,
            evidence,
            durable_receipt_digest,
            provider_enrollment_reference,
        })
    }
}
pub struct PendingSignerCommonContextReadV1<'client> {
    pending: PendingRosterCommonContextReadV1<'client>,
    selected: RetainedExactWalletMaterial,
    evidence: ManualRosterContributionRetentionEvidenceV2,
    durable_receipt_digest: String,
    provider_enrollment_reference: String,
}
impl PendingSignerCommonContextReadV1<'_> {
    pub fn finish(
        self,
    ) -> Result<(
        SignerRetainedCommonContextContributionV3,
        AdmittedRosterCommonContextReadV1,
    )> {
        let admitted = self.pending.finish()?;
        let retained = SignerRetainedCommonContextContributionV3 {
            selected: self.selected,
            evidence: self.evidence,
            durable_receipt_digest: self.durable_receipt_digest,
            provider_enrollment_reference: self.provider_enrollment_reference,
        };
        retained.check_retained()?;
        admitted.check_completion()?;
        Ok((retained, admitted))
    }
}
/// Original material remains opaque and one-use. The original live native
/// completion owner remains in the read, which the wallet observation retains.
pub struct SignerRetainedCommonContextContributionV3 {
    selected: RetainedExactWalletMaterial,
    evidence: ManualRosterContributionRetentionEvidenceV2,
    durable_receipt_digest: String,
    provider_enrollment_reference: String,
}
impl SignerRetainedCommonContextContributionV3 {
    pub fn check_retained(&self) -> Result<()> {
        self.evidence.validate()?;
        self.selected
            .check_retained_lineage()
            .map_err(|_| BridgeError::Permission)?;
        let facts = retained_selection_facts(self.selected.selection())?;
        let r = &self.evidence.request;
        if facts.0 != r.selected_inputs
            || facts.1 != r.selection_context
            || facts.2 != r.change_address
            || facts.3 != r.change_value_zatoshis
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub fn request(&self) -> Result<&ManualRosterContributionRetentionRequestV2> {
        self.check_retained()?;
        Ok(&self.evidence.request)
    }
    pub fn evidence(&self) -> Result<&ManualRosterContributionRetentionEvidenceV2> {
        self.check_retained()?;
        Ok(&self.evidence)
    }
    pub fn durable_receipt_digest(&self) -> &str {
        &self.durable_receipt_digest
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        &self.provider_enrollment_reference
    }
    pub fn check_held(&self, held: &HeldCommonContextRosterObservation<'_>) -> Result<()> {
        self.check_retained()?;
        held.check_all_current()
            .map_err(|_| BridgeError::Permission)?;
        held.matches_material(&self.selected)
            .map_err(|_| BridgeError::Binding)
    }
    pub async fn observe_common_context(
        &mut self,
        wallet: &mut ProtectedWalletSync,
        admitted: AdmittedRosterCommonContextReadV1,
        access: &impl wholepact_wallet::wallet::protected_sync::LocalWalletAccess,
    ) -> std::result::Result<
        FreshCommonContextObservation,
        wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError,
    > {
        use wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError as E;
        self.check_retained().map_err(|_| E::Permission)?;
        let request = admitted.request().map_err(|_| E::Permission)?;
        if request.plan.retained != self.evidence.request
            || request.plan.retained_evidence_digest
                != self.evidence.digest().map_err(|_| E::Binding)?
            || request.original_durable_receipt_digest != self.durable_receipt_digest
        {
            return Err(E::Binding);
        }
        let fresh = wallet
            .observe_retained_common_context(&mut self.selected, admitted, access)
            .await?;
        self.check_retained().map_err(|_| E::Permission)?;
        fresh.check_current()?;
        Ok(fresh)
    }
    pub fn common_context_verifier_snapshot(
        &self,
        fresh: &FreshCommonContextObservation,
    ) -> Result<CommonContextVerifierSnapshot> {
        self.check_retained()?;
        fresh
            .prepare_verifier(&self.selected)
            .map_err(|_| BridgeError::Permission)
    }
    /// Drop the old client grant while preserving only its installed-peer
    /// provenance. The real maintained observation and selected material must
    /// already match; the actual original Started read stays inside `fresh`.
    pub fn detach_common_context_reentry_source(
        &self,
        client: wholepact_signer_origin::NativeManualClient,
        fresh: &FreshCommonContextObservation,
    ) -> Result<wholepact_signer_origin::CommonContextReentrySourceV1> {
        self.common_context_verifier_snapshot(fresh)?;
        client
            .into_common_context_reentry_source(fresh.native_read())
            .map_err(Into::into)
    }
    /// A fresh purpose-specific native transition. This does not scan, select,
    /// reserve, consume, or grant construction by itself.
    pub fn begin_common_context_reentry_before<'a>(
        &self,
        client: &'a wholepact_signer_origin::CommonContextReentryClientV1,
        request: &wholepact_core::common_context_reentry_v1::RosterCommonContextReentryRequestV1,
        pending_grant: &wholepact_authority::construction_transport_handoff_v1::PendingConstructionTransportGrantV1,
        authorization: &SignerObservedCommonContextHandoffV1,
        fresh: &'a FreshCommonContextObservation,
        deadline: std::time::Instant,
    ) -> Result<PendingSignerCommonContextReentryV1<'a>> {
        self.common_context_verifier_snapshot(fresh)?;
        authorization.check_observed_read(fresh)?;
        pending_grant.validate().map_err(|_| BridgeError::Binding)?;
        if pending_grant.grant.authorization != *authorization.authorization()
            || pending_grant.digest().map_err(|_| BridgeError::Binding)?
                != request.pending_grant_digest
        {
            return Err(BridgeError::Binding);
        }
        let pending_grant_json = zeroize::Zeroizing::new(
            serde_json::to_string(pending_grant).map_err(|_| BridgeError::Binding)?,
        );
        let original_read = fresh.native_read();
        let pending = client
            .begin_reentry_before(request, &pending_grant_json, original_read, deadline)?;
        Ok(PendingSignerCommonContextReentryV1 {
            pending,
            original_read,
            pending_grant: pending_grant.clone(),
        })
    }
    /// Consumes the opaque same-read reentry result. All owners' observations
    /// must already exist in the Host phase barrier before this is called.
    pub fn begin_reentered_construction_before<'a>(
        &self,
        client: &'a wholepact_signer_origin::CommonContextReentryClientV1,
        request: &wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3,
        fresh: &'a FreshCommonContextObservation,
        reentered: wholepact_signer_origin::ReenteredCommonContextConstruction,
        deadline: std::time::Instant,
    ) -> Result<wholepact_signer_origin::PendingReenteredRosterConstructionV1<'a>> {
        self.common_context_verifier_snapshot(fresh)?;
        reentered.check_original_read(fresh.native_read())?;
        client
            .begin_construction_before(request, fresh.native_read(), reentered, deadline)
            .map_err(Into::into)
    }
    pub fn into_common_context_construction(
        self,
        admitted: AdmittedManualRosterConstructionContributionV3,
        held: &HeldCommonContextRosterObservation<'_>,
    ) -> Result<SignerConsumedRosterConstructionV3> {
        self.check_held(held)?;
        admitted.check_completion()?;
        let request = admitted.request()?;
        if request.plan.retained != self.evidence.request
            || request.plan.retained_evidence_digest != self.evidence.digest()?
            || request.plan.common_context_digest != held.common_context_digest()
            || admitted.evidence().retained_signer_intent_digest
                != self.evidence.retained_signer_intent_digest
            || admitted.evidence().current_attempt_sequence
                <= self
                    .evidence
                    .request
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attempt
                    .attempt_sequence
        {
            return Err(BridgeError::Binding);
        }
        let value = SignerConsumedRosterConstructionV3 {
            retained: self,
            admitted,
        };
        value.check_current(held)?;
        Ok(value)
    }
}
pub struct SignerConsumedRosterConstructionV3 {
    retained: SignerRetainedCommonContextContributionV3,
    admitted: AdmittedManualRosterConstructionContributionV3,
}
impl SignerConsumedRosterConstructionV3 {
    pub fn check_current(&self, held: &HeldCommonContextRosterObservation<'_>) -> Result<()> {
        self.retained.check_held(held)?;
        self.admitted.check_completion().map_err(Into::into)
    }
    pub fn plan(
        &self,
        held: &HeldCommonContextRosterObservation<'_>,
    ) -> Result<&wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3>
    {
        self.check_current(held)?;
        Ok(&self.admitted.request()?.plan)
    }
    pub fn evidence(&self) -> &wholepact_signer_origin::manual_roster_construction_v3::ManualRosterConstructionContributionEvidenceV3{
        self.admitted.evidence()
    }
    /// Explicit new lineage must accompany the unchanged V3 consumed bytes in
    /// every receipt/history mirror. It is inert and grants no saved authority.
    pub fn reentry_lineage(
        &self,
    ) -> Option<&wholepact_core::common_context_reentry_v1::RosterCommonContextReentryLineageV1>
    {
        self.admitted.reentry_lineage()
    }
    pub fn into_exact_parts(
        self,
        held: &HeldCommonContextRosterObservation<'_>,
    ) -> Result<(
        wholepact_protocol::construction::OwnedContribution,
        wholepact_protocol::construction::ConstructionContext,
        SignerRosterConstructionCompletionGuardV3,
    )> {
        self.check_current(held)?;
        let (contribution, context) = self
            .retained
            .selected
            .into_common_context_construction(held, &self.admitted)
            .map_err(|_| BridgeError::Permission)?;
        self.admitted.check_completion()?;
        Ok((
            contribution,
            context,
            SignerRosterConstructionCompletionGuardV3 {
                admitted: self.admitted,
            },
        ))
    }
}
/// Actual consumed native guard shares the original retained clock/high-water;
/// it survives wallet unwind and postcommit output checks in Engine custody.
pub struct SignerRosterConstructionCompletionGuardV3 {
    admitted: AdmittedManualRosterConstructionContributionV3,
}
impl SignerRosterConstructionCompletionGuardV3 {
    pub fn check_current(&self) -> Result<()> {
        self.admitted.check_completion().map_err(Into::into)
    }
}

/// A separately signed preauthorization from the actual installed native peer,
/// joined to the actual completed maintained-wallet read. This cannot issue a
/// witness grant, current session, Reserve, Consume, or financial permission.
pub struct SignerObservedCommonContextHandoffV1 {
    native: wholepact_signer_origin::NativeCommonContextHandoffAuthorizationV1,
    authorization: wholepact_authority::construction_transport_handoff_v1::SignedConstructionTransportPreauthorizationV1,
}
impl SignerObservedCommonContextHandoffV1 {
    pub fn from_observed_read(
        native: wholepact_signer_origin::NativeCommonContextHandoffAuthorizationV1,
        observed: &FreshCommonContextObservation,
    ) -> Result<Self> {
        observed
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        let read = observed.native_read();
        native.check_original_read(read)?;
        let authorization: wholepact_authority::construction_transport_handoff_v1::SignedConstructionTransportPreauthorizationV1 =
            serde_json::from_str(native.signed_authorization_json(read)?)
                .map_err(|_| BridgeError::Binding)?;
        let request = read.request()?;
        let terms = request.plan.enrollment();
        authorization
            .verify(&terms.signer.owner_certificate_digest)
            .map_err(|_| BridgeError::Binding)?;
        let a = &authorization.authorization;
        if authorization.digest().map_err(|_| BridgeError::Binding)?
            != native.signed_authorization_digest()
            || a.operation_id != native.request().operation_id
            || a.account_id != terms.identity.account_id
            || a.network_profile_id != terms.identity.network_profile_id
            || a.policy_digest != terms.original_policy_digest
            || a.genesis_digest != terms.account_use_genesis_digest
            || a.native_review_digest == read.evidence().native_review_digest
            || a.read_request_digest != request.digest().map_err(|_| BridgeError::Binding)?
            || a.read_evidence_digest != read.evidence().digest()?
            || a.plan_approval_digest != request.witness_plan_approval_digest
            || a.invocation_digest != request.plan.invocation_digest().map_err(|_| BridgeError::Binding)?
            || a.original_caller_binding_digest != request.current_caller_binding_digest
            || a.attempt_digest != read.evidence().current_attempt_digest
            || a.attempt_sequence != read.evidence().current_attempt_sequence
            || a.authorized_at_ms < read.evidence().admitted_at_ms
            || a.expires_at_ms > request.completion_expires_at_ms
            || a.original_session.expires_at_ms != read.evidence().writer_session_expires_at_ms
        {
            return Err(BridgeError::Binding);
        }
        observed
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        Ok(Self {
            native,
            authorization,
        })
    }
    pub fn check_observed_read(&self, observed: &FreshCommonContextObservation) -> Result<()> {
        observed
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        self.native.check_original_read(observed.native_read())?;
        Ok(())
    }
    /// Historical evidence only. An independent genuine witness owner must
    /// authorize any grant; serialization cannot reconstruct this owner.
    pub fn authorization(&self) -> &wholepact_authority::construction_transport_handoff_v1::SignedConstructionTransportPreauthorizationV1{
        &self.authorization
    }
}

/// Retains only the exact pending grant and the actual original read while the
/// installed-peer exchange runs. Finishing validates independently available
/// references before releasing its one-use reentry owner. No saved DTO can
/// construct this pending wrapper or create a native permission.
pub struct PendingSignerCommonContextReentryV1<'a> {
    pending: wholepact_signer_origin::PendingCommonContextReentryV1<'a>,
    original_read: &'a wholepact_signer_origin::StartedRosterCommonContextReadV1,
    pending_grant: wholepact_authority::construction_transport_handoff_v1::PendingConstructionTransportGrantV1,
}
impl PendingSignerCommonContextReentryV1<'_> {
    pub fn finish(self) -> Result<wholepact_signer_origin::ReenteredCommonContextConstruction> {
        let reentered = self.pending.finish()?;
        require_exact_reentry_references(
            reentered.lineage(),
            self.original_read.evidence(),
            &self.pending_grant,
        )?;
        reentered.check_original_read(self.original_read)?;
        Ok(reentered)
    }
}

/// Reference equality only. New exporter/credential/fence/current-history facts
/// are not derivable from a pending grant: their exact authenticated joins stay
/// in the native producer's signed claim and durable signer audit validation.
fn require_exact_reentry_references(
    lineage: &wholepact_core::common_context_reentry_v1::RosterCommonContextReentryLineageV1,
    read: &wholepact_signer_origin::roster_common_context_read_v1::RosterCommonContextReadEvidenceV1,
    pending: &wholepact_authority::construction_transport_handoff_v1::PendingConstructionTransportGrantV1,
) -> Result<()> {
    lineage.validate().map_err(|_| BridgeError::Binding)?;
    read.validate()?;
    pending.validate().map_err(|_| BridgeError::Binding)?;
    let a = &pending.grant.authorization.authorization;
    let terms = read.request.plan.enrollment();
    let session_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:common-context-reentry-writer-session:v1",
        &a.original_session,
    )
    .map_err(|_| BridgeError::Binding)?;
    if lineage.request.original_read != read.request
        || lineage.request.original_read_admission_digest != read.digest()?
        || lineage.request.pending_grant_digest
            != pending.digest().map_err(|_| BridgeError::Binding)?
        || lineage.request.original_attempt_digest != read.current_attempt_digest
        || lineage.request.original_attempt_sequence != read.current_attempt_sequence
        || lineage.retained_signer_intent_digest != read.retained_signer_intent_digest
        || lineage.original_record_digest
            != read.request.plan.retained.selection.scope.provenance.signer_roster_record_digest
        || lineage.original_genesis_digest != a.genesis_digest
        || lineage.original_genesis_digest != terms.account_use_genesis_digest
        || lineage.original_birth_digest != terms.native_birth_digest
        || lineage.original_native_binding_digest != a.original_native_binding_digest
        || lineage.original_host_process_digest != a.original_host_process_commitment
        || lineage.current_writer_session_digest != session_digest
        || lineage.current_writer_session_expires_at_ms != a.original_session.expires_at_ms
        || lineage.current_writer_session_expires_at_ms != read.writer_session_expires_at_ms
        || lineage.current_witness_continuation_digest != a.attempt_digest
        || lineage.request.requested_at_ms < pending.grant.granted_at_ms
        || lineage.admitted_at_ms < pending.grant.granted_at_ms
        || lineage.request.admission_expires_at_ms > a.expires_at_ms
        || lineage.completion_expires_at_ms > a.expires_at_ms
        || lineage.native_review_digest == read.native_review_digest
        || lineage.native_review_digest == a.native_review_digest
        || lineage.native_review_digest == pending.grant.native_review_digest
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

#[cfg(test)]
mod reentry_reference_tests {
    use super::*;
    use wholepact_authority::construction_transport_handoff_v1::{
        ConstructionTransportCredentialV1, PendingConstructionTransportGrantV1,
    };
    use wholepact_core::common_context_reentry_v1::{
        CommonContextReentryPurposeV1, RosterCommonContextReentryLineageV1,
        RosterCommonContextReentryRequestV1,
    };
    use wholepact_signer_origin::roster_common_context_read_v1::RosterCommonContextReadEvidenceV1;

    // Existing never-funded signed archive is read as inert fixture data only.
    // No signature is generated, native owner issued, channel opened, wallet
    // read, provider contacted, or proof run by these reference-only tests.
    fn fixture() -> (
        RosterCommonContextReentryLineageV1,
        RosterCommonContextReadEvidenceV1,
        PendingConstructionTransportGrantV1,
    ) {
        let raw: serde_json::Value = serde_json::from_str(include_str!(
            "../consent_journal/fixtures/common-context-handoff-audit.synthetic.json"
        ))
        .unwrap();
        assert_eq!(raw["native_actors_exercised"], false);
        assert_eq!(raw["sockets_or_provider_reads_exercised"], false);
        let read: RosterCommonContextReadEvidenceV1 =
            serde_json::from_value(raw["modeled_read_evidence"].clone()).unwrap();
        let credential: ConstructionTransportCredentialV1 = serde_json::from_value(
            raw["complete_history"]["transport"]["credentials"][0].clone(),
        )
        .unwrap();
        let a = credential.authorization();
        let claim = &credential.signed_claim.claim;
        let pending = &credential.pending_grant;
        let lineage = RosterCommonContextReentryLineageV1 {
            version: 1,
            request: RosterCommonContextReentryRequestV1 {
                version: 1,
                operation_id: "modeled-bridge-reentry-references".into(),
                original_read: read.request.clone(),
                original_read_admission_digest: read.digest().unwrap(),
                pending_grant_digest: pending.digest().unwrap(),
                original_attempt_digest: read.current_attempt_digest.clone(),
                original_attempt_sequence: read.current_attempt_sequence,
                current_caller_binding_digest: claim.new_caller_binding_digest.clone(),
                current_attempt_digest: read.current_attempt_digest.clone(),
                current_attempt_sequence: read.current_attempt_sequence,
                purpose: CommonContextReentryPurposeV1::ResumeAlreadyAdmittedConstructionOnly,
                requested_at_ms: pending.grant.granted_at_ms,
                admission_expires_at_ms: a.expires_at_ms,
            },
            retained_signer_intent_digest: read.retained_signer_intent_digest.clone(),
            original_native_binding_digest: a.original_native_binding_digest.clone(),
            current_native_binding_digest: claim.new_native_binding_digest.clone(),
            original_host_process_digest: a.original_host_process_commitment.clone(),
            original_record_digest: read
                .request.plan.retained.selection.scope.provenance.signer_roster_record_digest
                .clone(),
            original_genesis_digest: a.genesis_digest.clone(),
            original_birth_digest: read.request.plan.enrollment().native_birth_digest.clone(),
            current_witness_history_digest: raw["claimed_history"]["original"]
                ["complete_replay_digest"]
                .as_str().unwrap().into(),
            current_witness_continuation_digest: a.attempt_digest.clone(),
            current_writer_session_digest: wholepact_core::proposal::canonical_digest(
                "wholepact:common-context-reentry-writer-session:v1",
                &a.original_session,
            ).unwrap(),
            construction_transport_credential_digest: credential.digest().unwrap(),
            construction_transport_credential_id: credential.credential_id().into(),
            original_transport_fence_digest: credential.old_key_fence_digest.clone(),
            current_writer_session_expires_at_ms: a.original_session.expires_at_ms,
            native_review_digest: claim.native_review_digest.clone(),
            admitted_at_ms: claim.claimed_at_ms,
            completion_expires_at_ms: a.expires_at_ms,
        };
        (lineage, read, pending.clone())
    }

    #[test]
    fn exact_pending_and_read_references_accept_inert_fixture() {
        let (lineage, read, pending) = fixture();
        require_exact_reentry_references(&lineage, &read, &pending).unwrap();
    }

    #[test]
    fn independently_available_reentry_reference_substitutions_are_rejected() {
        let (original, read, pending) = fixture();
        require_exact_reentry_references(&original, &read, &pending).unwrap();
        for mutation in 0..17 {
            let mut lineage = original.clone();
            let changed = "f1".repeat(32);
            match mutation {
                0 => lineage.original_record_digest = changed,
                1 => lineage.original_genesis_digest = changed,
                2 => lineage.original_birth_digest = changed,
                3 => lineage.original_native_binding_digest = changed,
                4 => lineage.original_host_process_digest = changed,
                5 => lineage.current_writer_session_digest = changed,
                6 => lineage.current_writer_session_expires_at_ms += 1,
                7 => lineage.request.pending_grant_digest = changed,
                8 => lineage.request.original_read_admission_digest = changed,
                9 => lineage.retained_signer_intent_digest = changed,
                10 => lineage.request.requested_at_ms = pending.grant.granted_at_ms - 1,
                11 => lineage.request.admission_expires_at_ms += 1,
                12 => lineage.completion_expires_at_ms += 1,
                13 => lineage.native_review_digest = read.native_review_digest.clone(),
                14 => lineage.native_review_digest = pending.grant.native_review_digest.clone(),
                15 => lineage.native_review_digest = pending.grant.authorization
                    .authorization.native_review_digest.clone(),
                _ => {
                    lineage.request.original_attempt_digest = changed.clone();
                    lineage.request.current_attempt_digest = changed.clone();
                    lineage.current_witness_continuation_digest = changed;
                }
            }
            // Each variant remains a well-shaped inert lineage. The exact
            // original-reference comparison, not just parsing, must reject it.
            lineage.validate().unwrap();
            assert!(require_exact_reentry_references(&lineage, &read, &pending).is_err(),
                "reference substitution {mutation}");
        }
    }
}
