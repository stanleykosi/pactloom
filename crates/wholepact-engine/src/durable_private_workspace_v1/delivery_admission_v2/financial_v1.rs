//! Distinct source-owned financial continuation. No admission object is promoted
//! and no generic Engine marker exception exists. Original rows are never edited.
use super::*;
use crate::durable_proposals_v1::private_financial_v1 as kernel;
use crate::signature_intake::LocalSignedRetention;
use wholepact_proof_jobs::OriginalProofReadRevisionV3;
use wholepact_protocol::authorization::retention::transaction::{
    LocalTransactionCheckpoint, TransactionCheckpointSummary,
};
use wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1;
use wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultLeaseV1;
use wholepact_store::{OriginalPrivateRevisionPinV3, OriginalSourceReadRevisionPinV3};

const BIND: &str = "private_financial_continuations_bound_v1";
const INTAKE: &str = "private_financial_signature_intake_v1";
const UNION: &str = "private_financial_union_retained_v1";
const MAX_EVENTS: usize = PREFIX_EVENTS + MAX_EXPORT_INTENTS + 4 + 3 * 128;
const DISPATCH_INTENT: &str = "private_financial_dispatch_intent_v1";
const DISPATCH_ADMISSION: &str = "private_financial_dispatch_admission_v1";

pub trait LocalPrivateDurableFinancialConsentV1 {
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool;
}
struct SourceConsent<'a>(&'a dyn LocalPrivateDurableFinancialConsentV1);
impl LocalPrivateDurableAdmissionConsentV2 for SourceConsent<'_> {
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        self.0.permits_source(scope)
    }
}
/// This owns original storage privately, not the admission profile's grants.
pub struct PrivateDurableFinancialCoordinatorV1<'source> {
    source: PrivateDurableAdmissionCoordinatorV2<'source>,
    commands: std::sync::Mutex<BTreeMap<String, CommandContext>>,
}
struct FinancialHistory {
    current: Envelope,
    original: History,
    frozen: Envelope,
}
#[derive(Serialize)]
pub struct PrivateDurableFinancialInspectionV1 {
    workspace_scope: PrivateWorkspaceScopeV1,
    materials: Vec<PrivateFixedMaterialReviewV3>,
    checkpoint_scope: CheckpointScope,
    proof_job_id: String,
    pub revision: u64,
    pub fixed_identity: FixedProposalIdentityV1,
    pub frozen_export_history_digest: String,
    pub financial_continuations_bound: bool,
    pub authorization_allowed: bool,
    pub distribution_allowed: bool,
}
impl PrivateDurableFinancialInspectionV1 {
    pub fn proof_job_id(&self) -> &str {
        &self.proof_job_id
    }
    pub fn workspace_scope(&self) -> &PrivateWorkspaceScopeV1 {
        &self.workspace_scope
    }
    pub fn materials(&self) -> &[PrivateFixedMaterialReviewV3] {
        &self.materials
    }
    pub fn checkpoint_scope(&self) -> &CheckpointScope {
        &self.checkpoint_scope
    }
    pub fn fixed_identity(&self) -> &FixedProposalIdentityV1 {
        &self.fixed_identity
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
}
impl<'source> PrivateDurableFinancialCoordinatorV1<'source> {
    #[allow(clippy::too_many_arguments)]
    pub fn open_original(
        source: PrivateDurableWorkspaceSourceV1<'source>,
        access: &Access,
        destination: &Path,
        key: &DatabaseKey,
        expected_origin: [u8; 32],
        retention_policy: &str,
        native_association_digest: &str,
        proof: wholepact_proof_jobs::OriginalProofJobSourceV1<'source>,
        expected_proof_origin: [u8; 32],
        plan: &PrivateWorkspaceInitializationPlanV1,
        binding: &PrivateWorkspaceSeedBindingV1,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
    ) -> Result<Self> {
        crate::private_workspace_origin_v1::validate_association_digest(native_association_digest)?;
        let scope = scope(&source, destination, retention_policy)?;
        check_source(&source, access, &scope, &SourceConsent(consent))?;
        let observation = Observation::new(Operation::OpenOriginal);
        preflight_original_metadata_profile_v2(
            destination,
            key,
            expected_origin,
            Some(&observation),
            OriginalMetadataProfileV2::Financial,
        )?;
        let (prefix_commands, commands) =
            original_commands_bounded(destination, key, expected_origin, MAX_EVENTS)?;
        let original = PrivateDurableCoordinatorV1::open_original_storage_v2(
            source,
            access,
            destination,
            key,
            expected_origin,
            scope,
            native_association_digest,
            proof,
            expected_proof_origin,
            &observation,
            OriginalMetadataProfileV2::Financial,
        )?;
        original.audit_original_seed_v1(access, plan, binding)?;
        let result = Self {
            source: PrivateDurableAdmissionCoordinatorV2 {
                original,
                prefix_commands,
                seed_command: binding.command.clone(),
            },
            commands: std::sync::Mutex::new(commands),
        };
        result.check(access, consent)?;
        Ok(result)
    }
    pub fn workspace_scope(&self) -> &PrivateWorkspaceScopeV1 {
        &self.source.original.scope
    }
    pub fn origin_marker_digest(&self) -> Result<String> {
        self.source.original.origin_marker_digest()
    }
    pub fn original_origin(&self) -> [u8; 32] {
        self.source.original.origin
    }
    fn check(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
    ) -> Result<FinancialHistory> {
        self.source
            .original
            .proof
            .check_current()
            .map_err(original_job_error_v2)?;
        let result = self.check_without_proof(access, consent)?;
        self.source
            .original
            .proof
            .check_current()
            .map_err(original_job_error_v2)?;
        Ok(result)
    }
    fn check_without_proof(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
    ) -> Result<FinancialHistory> {
        let o = &self.source.original;
        check_source(&o.source, access, &o.scope, &SourceConsent(consent))?;
        if o.engine
            .store
            .verify_original_encrypted_destination(o.scope.protected_destination())
            .map_err(crate::store_error)?
            != o.origin
            || crate::private_workspace_origin_v1::from_source(
                &o.source,
                access,
                &o.scope,
                &o.marker.native_association_digest,
                o.origin,
            )? != o.marker
        {
            return Err(damaged());
        }
        let record = o
            .engine
            .store
            .get_agreement(o.source.agreement_id())
            .map_err(crate::store_error)?
            .ok_or_else(damaged)?;
        let current = decode_private_record(&record)?;
        o.require_original_identity_v2(&current)?;
        let events = o
            .engine
            .store
            .events_after(0, (MAX_EVENTS + 1) as u32)
            .map_err(crate::store_error)?;
        if events.len() < PREFIX_EVENTS
            || events.len() > MAX_EVENTS
            || events.len() as u64 != current.view.revision
        {
            return Err(damaged());
        }
        let boundary = events
            .iter()
            .position(|e| e.kind == BIND)
            .unwrap_or(events.len());
        if boundary < PREFIX_EVENTS || boundary > PREFIX_EVENTS + MAX_EXPORT_INTENTS {
            return Err(damaged());
        }
        let frozen_op = o
            .engine
            .store
            .get_operation(&events[boundary - 1].operation_id)
            .map_err(crate::store_error)?
            .ok_or_else(damaged)?;
        let frozen_saved: MutationResult =
            serde_json::from_value(frozen_op.result).map_err(|_| damaged())?;
        let frozen = decode_private_record(&frozen_saved.record)?;
        let original =
            self.source
                .audit_admission_rows(access, &frozen, None, &events[..boundary])?;
        let mut before = frozen.clone();
        for (offset, event) in events[boundary..].iter().enumerate() {
            let revision = (boundary + offset + 1) as u64;
            let expected_kind = match offset {
                0 => BIND,
                1 | 2 => INTAKE,
                3 => UNION,
                _ => {
                    if event.kind != DISPATCH_INTENT && event.kind != DISPATCH_ADMISSION {
                        return Err(damaged());
                    }
                    event.kind.as_str()
                }
            };
            if event.kind != expected_kind
                || event.aggregate_type != "agreement"
                || event.aggregate_id != o.source.agreement_id()
                || event.aggregate_revision != revision
                || event.sequence != revision
                || event.payload
                    != serde_json::json!({"id":o.source.agreement_id(),"revision":revision})
            {
                return Err(damaged());
            }
            let op = o
                .engine
                .store
                .get_operation(&event.operation_id)
                .map_err(crate::store_error)?
                .ok_or_else(damaged)?;
            let saved: MutationResult =
                serde_json::from_value(op.result.clone()).map_err(|_| damaged())?;
            if op.kind != event.kind
                || op.resource_id != event.aggregate_id
                || op.principal_id != access.principal_id
                || op.status != "succeeded"
                || op.operation_id != event.operation_id
                || saved.operation_id != event.operation_id
                || saved.event_sequence != event.sequence
                || saved.record.revision != revision
                || saved.record.id != event.aggregate_id
                || saved.replayed
            {
                return Err(damaged());
            }
            let after = decode_private_record(&saved.record)?;
            o.require_original_identity_v2(&after)?;
            kernel::validate_delta(&before, &after, &event.kind)?;
            let commands = self.commands.lock().map_err(|_| damaged())?;
            let saved_command = commands.get(&event.operation_id).ok_or_else(damaged)?;
            let expected = financial_command(
                access,
                &saved_command.idempotency_key,
                &before,
                &after,
                &event.kind,
            )?;
            if expected.principal_id != saved_command.principal_id
                || expected.idempotency_key != saved_command.idempotency_key
                || expected.request_digest != saved_command.request_digest
            {
                return Err(damaged());
            }
            let replay = o
                .engine
                .store
                .find_replay(&expected)
                .map_err(crate::store_error)?
                .ok_or_else(damaged)?;
            if replay.record != saved.record
                || replay.operation_id != saved.operation_id
                || replay.event_sequence != saved.event_sequence
            {
                return Err(damaged());
            }
            if offset == 0 {
                let binding = kernel::binding(&after)?.ok_or_else(damaged)?;
                self.check_bound_exports(&binding, &original, &frozen)?;
            }
            before = after;
        }
        if crate::encode(&before)? != crate::encode(&current)? {
            return Err(damaged());
        }
        o.stage_materials_v3(access, &current, &current.view.candidates[0].candidate_id)?;
        check_source(&o.source, access, &o.scope, &SourceConsent(consent))?;
        Ok(FinancialHistory {
            current,
            original,
            frozen,
        })
    }
    fn check_bound_exports(
        &self,
        binding: &kernel::FinancialBindingV1,
        history: &History,
        frozen: &Envelope,
    ) -> Result<()> {
        if binding.frozen_export_revision != frozen.view.revision
            || binding.frozen_export_history_digest != history.full_digest
        {
            return Err(damaged());
        }
        let roster = original_roster_v2(frozen)?;
        for (account, reference) in &binding.continuations {
            let terms = &reference.record.terms;
            let matches: Vec<_> = roster
                .review_exports_v3
                .values()
                .filter(|export| {
                    export.scope.recipient.account_id == *account
                        && export.scope.recipient.digest().ok().as_deref()
                            == Some(terms.original_recipient_intent_digest.as_str())
                })
                .collect();
            if matches.len() != 1 {
                return Err(damaged());
            }
            let recipient = &matches[0].scope.recipient;
            if account != &terms.scope.authorization.identity.account_id
                || terms.scope.delivery != recipient.delivery
                || terms.scope.original_ceilings.material_scopes != recipient.material_scopes
                || terms.original_recipient_enrollment_ref != recipient.original_enrollment_ref
                || terms.original_recipient_manifest_ref != recipient.original_manifest_ref
                || terms.scope.accepted_manifest_ref != recipient.original_manifest_ref
                || serde_json::to_value(&terms.scope.authorization.fixed).map_err(|_| damaged())?
                    != serde_json::to_value(&recipient.fixed).map_err(|_| damaged())?
            {
                return Err(damaged());
            }
        }
        Ok(())
    }
    pub fn inspect_original_financial_v1(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
    ) -> Result<PrivateDurableFinancialInspectionV1> {
        let h = self.check(access, consent)?;
        let fixed = serde_json::from_value(
            h.original
                .prefix
                .durable_proposals_v1
                .values()
                .next()
                .ok_or_else(damaged)?
                .get("identity")
                .cloned()
                .ok_or_else(damaged)?,
        )
        .map_err(|_| damaged())?;
        let candidate = h
            .original
            .prefix
            .view
            .candidates
            .first()
            .ok_or_else(damaged)?;
        let materials =
            self.source
                .original
                .stage_materials_v3(access, &h.current, &candidate.candidate_id)?;
        let receipt = h
            .original
            .prefix
            .checkpoint_receipts
            .values()
            .next()
            .ok_or_else(damaged)?;
        let checkpoint_scope =
            exact_fixed_v2::retained_review_scope_v3(candidate, receipt, &materials)?;
        Ok(PrivateDurableFinancialInspectionV1 {
            workspace_scope: self.workspace_scope().clone(),
            materials,
            checkpoint_scope,
            proof_job_id: candidate
                .proof_jobs
                .first()
                .ok_or_else(damaged)?
                .job_id
                .clone(),
            revision: h.current.view.revision,
            fixed_identity: fixed,
            frozen_export_history_digest: h.original.full_digest,
            financial_continuations_bound: kernel::binding(&h.current)?.is_some(),
            authorization_allowed: false,
            distribution_allowed: false,
        })
    }
}
fn financial_command(
    access: &Access,
    key: &str,
    before: &Envelope,
    after: &Envelope,
    kind: &str,
) -> Result<CommandContext> {
    // Exact full private delta is committed, not a generic profile toggle.
    crate::context(
        access,
        key,
        kind,
        &before.view.agreement.agreement_id,
        Some(before.view.revision),
        &(&before.durable_proposals_v1, &after.durable_proposals_v1),
    )
}

struct FinancialProofGate<'a, 'source> {
    owner: &'a PrivateDurableFinancialCoordinatorV1<'source>,
    access: &'a Access,
    consent: &'a dyn LocalPrivateDurableFinancialConsentV1,
    proof: &'a dyn LocalProofConsent,
    material: &'a dyn LocalDurableMaterialConsentV1,
}
impl FinancialProofGate<'_, '_> {
    fn check(&self) -> Result<()> {
        let h = self.owner.check_without_proof(self.access, self.consent)?;
        for intake in original_roster_v2(&h.current)?.owners.values() {
            self.owner.source.original.check_intake(
                self.access,
                intake,
                self.material,
                DurableMaterialActionV1::ReadForExactConstruction,
            )?;
        }
        self.owner.check_without_proof(self.access, self.consent)?;
        Ok(())
    }
}
impl LocalProofConsent for FinancialProofGate<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        self.check().is_ok() && self.proof.permits(scope, action) && self.check().is_ok()
    }
}
struct PreparedRawFinancialV1<'owner, 'source> {
    owner: &'owner PrivateDurableFinancialCoordinatorV1<'source>,
    history: FinancialHistory,
    checkpoint: VerifiedCheckpoint,
    metadata: OriginalPrivateRevisionPinV3<'owner>,
    root: OriginalSourceReadRevisionPinV3<'owner>,
    proof: OriginalProofReadRevisionV3<'source>,
}
pub struct PreparedPrivateFinancialV1<'owner, 'source> {
    owner: &'owner PrivateDurableFinancialCoordinatorV1<'source>,
    history: FinancialHistory,
    kernel: kernel::PreparedFinancialKernelV1,
    metadata: OriginalPrivateRevisionPinV3<'owner>,
    root: OriginalSourceReadRevisionPinV3<'owner>,
    proof: OriginalProofReadRevisionV3<'source>,
}
impl<'source> PrivateDurableFinancialCoordinatorV1<'source> {
    fn prepare_raw<'owner>(
        &'owner self,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PreparedRawFinancialV1<'owner, 'source>> {
        let initial = self.check(access, consent)?;
        let candidate = initial
            .original
            .prefix
            .view
            .candidates
            .first()
            .ok_or_else(damaged)?;
        let materials = self.source.original.stage_materials_v3(
            access,
            &initial.current,
            &candidate.candidate_id,
        )?;
        let receipt = initial
            .original
            .prefix
            .checkpoint_receipts
            .values()
            .next()
            .ok_or_else(damaged)?;
        let scope = exact_fixed_v2::retained_review_scope_v3(candidate, receipt, &materials)?;
        let job = &candidate.proof_jobs.first().ok_or_else(damaged)?.job_id;
        let metadata = self
            .source
            .original
            .engine
            .store
            .pin_original_revision_v3(self.source.original.source.agreement_id())
            .map_err(crate::store_error)?;
        let root = self
            .source
            .original
            .source
            .engine
            .store
            .pin_original_source_read_revision_v3(self.source.original.source.agreement_id())
            .map_err(crate::store_error)?;
        let proof_pin = self
            .source
            .original
            .proof
            .pin_original_read_revision_v3(&access.principal_id, job, &scope)
            .map_err(original_job_error_v2)?;
        let history = self.check(access, consent)?;
        let gate = FinancialProofGate {
            owner: self,
            access,
            consent,
            proof,
            material,
        };
        gate.check()?;
        let key = &receipt
            .original_request_v2
            .as_ref()
            .ok_or_else(damaged)?
            .command
            .idempotency_key;
        let observation = Observation::new(Operation::ReadFixed);
        let checkpoint = self.source.original.load_original_verified(
            &history.original.prefix,
            access,
            &candidate.candidate_id,
            key,
            &gate,
            &observation,
        )?;
        crate::durable_proposals_v1::read_private_fixed_v2(
            &history.original.prefix,
            access,
            &checkpoint,
            receipt,
        )?;
        if checkpoint.scope() != &scope || checkpoint.summary().job_id != *job {
            return Err(damaged());
        }
        gate.check()?;
        metadata.check_current_v3().map_err(crate::store_error)?;
        root.check_current_v3().map_err(crate::store_error)?;
        proof_pin
            .check_current_v3()
            .map_err(original_job_error_v2)?;
        Ok(PreparedRawFinancialV1 {
            owner: self,
            history,
            checkpoint,
            metadata,
            root,
            proof: proof_pin,
        })
    }
    pub fn prepare_original_financial_v1<'owner>(
        &'owner self,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PreparedPrivateFinancialV1<'owner, 'source>> {
        let raw = self.prepare_raw(access, consent, proof, material)?;
        let kernel = kernel::PreparedFinancialKernelV1::new(
            raw.history.current.clone(),
            access,
            raw.checkpoint,
        )?;
        let result = PreparedPrivateFinancialV1 {
            owner: self,
            history: raw.history,
            kernel,
            metadata: raw.metadata,
            root: raw.root,
            proof: raw.proof,
        };
        result.check_current_v1(access, consent, proof, material)?;
        Ok(result)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn bind_financial_continuations_v1(
        &self,
        access: &Access,
        key: &str,
        revision: u64,
        continuations: [&AuthenticatedFinancialContinuationHistoryV1; 2],
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<u64> {
        let raw = self.prepare_raw(access, consent, proof, material)?;
        if raw.history.current.view.revision != revision
            || kernel::binding(&raw.history.current)?.is_some()
        {
            return Err(damaged());
        }
        let mut refs = BTreeMap::new();
        for history in continuations {
            let record = history.continuation_record();
            let account = record.terms.scope.authorization.identity.account_id.clone();
            if refs
                .insert(
                    account,
                    kernel::ContinuationReferenceV1 {
                        request: history.continuation_request().clone(),
                        record: record.clone(),
                        authenticated_history_digest: history.history_digest().into(),
                    },
                )
                .is_some()
            {
                return Err(damaged());
            }
        }
        let binding = kernel::FinancialBindingV1 {
            schema_version: 1,
            frozen_export_revision: revision,
            frozen_export_history_digest: raw.history.original.full_digest.clone(),
            continuations: refs,
        };
        self.check_bound_exports(&binding, &raw.history.original, &raw.history.frozen)?;
        let after = kernel::bind(&raw.history.current, binding)?;
        raw.root.check_current_v3().map_err(crate::store_error)?;
        raw.proof
            .check_current_v3()
            .map_err(original_job_error_v2)?;
        FinancialProofGate {
            owner: self,
            access,
            consent,
            proof,
            material,
        }
        .check()?;
        self.commit(
            access,
            key,
            &raw.history.current,
            after,
            BIND,
            raw.metadata,
            consent,
        )
    }
    fn commit(
        &self,
        access: &Access,
        key: &str,
        before: &Envelope,
        mut after: Envelope,
        kind: &str,
        pin: OriginalPrivateRevisionPinV3<'_>,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
    ) -> Result<u64> {
        after.view.revision = before.view.revision.checked_add(1).ok_or_else(damaged)?;
        after.view.updated_at = crate::now();
        kernel::validate_delta(before, &after, kind)?;
        let command = financial_command(access, key, before, &after, kind)?;
        if !consent.permits_source(self.workspace_scope()) {
            return Err(denied());
        }
        let (saved,_next)=self.source.original.engine.store.update_original_agreement_pinned_v3(pin,&command,
            self.source.original.source.agreement_id(),before.view.revision,crate::encode(&after)?,kind).map_err(|e| {
                let mut error=crate::store_error(e);error.safe_actions=vec!["Preserve original retained financial results; reopen and reconcile the original operation without re-signing or re-extracting".into()];error
            })?;
        self.commands
            .lock()
            .map_err(|_| damaged())?
            .insert(saved.operation_id, command);
        self.check(access, consent)?;
        Ok(saved.record.revision)
    }
}
impl<'owner, 'source> PreparedPrivateFinancialV1<'owner, 'source> {
    /// Enumerate only the original two source contexts and their exact union.
    /// This reads no signatures and grants no retention or financial effect.
    pub fn financial_retention_contexts_v1(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<crate::FinancialRetentionContextsV1> {
        self.check_current_v1(access, consent, proof, material)?;
        let contexts = self.kernel.retention_contexts()?;
        self.check_current_v1(access, consent, proof, material)?;
        Ok(contexts)
    }

    pub fn original_financial_valid_until_ms_v1(&self) -> Result<u64> {
        let records = &self.kernel.binding().continuations;
        if records.len() != 2 {
            return Err(damaged());
        }
        records
            .values()
            .map(|r| r.record.terms.valid_until_ms)
            .min()
            .ok_or_else(damaged)
    }
    pub fn next_dispatch_attempt_v1(&self) -> Result<u32> {
        Ok(self.kernel.next_delegation_attempt())
    }
    pub fn fixed_identity(&self) -> &FixedProposalIdentityV1 {
        self.kernel.identity()
    }
    pub fn checkpoint_scope(&self) -> &CheckpointScope {
        self.kernel.checkpoint_scope()
    }
    pub fn check_current_v1(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<()> {
        self.metadata
            .check_current_v3()
            .map_err(crate::store_error)?;
        self.root.check_current_v3().map_err(crate::store_error)?;
        self.proof
            .check_current_v3()
            .map_err(original_job_error_v2)?;
        let gate = FinancialProofGate {
            owner: self.owner,
            access,
            consent,
            proof,
            material,
        };
        if !gate.permits(
            self.kernel.checkpoint_scope(),
            LocalAction::ReadPrivateArtifact,
        ) {
            return Err(denied());
        }
        self.metadata
            .check_current_v3()
            .map_err(crate::store_error)?;
        self.root.check_current_v3().map_err(crate::store_error)?;
        self.proof.check_current_v3().map_err(original_job_error_v2)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn intake_original_signature_v1(
        self,
        access: &Access,
        key: &str,
        delivery: &AuthenticatedFinancialResultLeaseV1,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        retention: LocalSignedRetention<'_>,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<u64> {
        self.check_current_v1(access, consent, proof, material)?;
        let gate = FinancialProofGate {
            owner: self.owner,
            access,
            consent,
            proof,
            material,
        };
        let after = self
            .kernel
            .intake(key, delivery, retention, &gate, false, history)?;
        self.check_current_v1(access, consent, proof, material)?;
        match after {
            Some(after) => self.owner.commit(
                access,
                key,
                &self.history.current,
                after,
                INTAKE,
                self.metadata,
                consent,
            ),
            None => Ok(self.history.current.view.revision),
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_original_signature_v1(
        self,
        access: &Access,
        key: &str,
        delivery: &AuthenticatedFinancialResultLeaseV1,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        retention: LocalSignedRetention<'_>,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<u64> {
        self.check_current_v1(access, consent, proof, material)?;
        let gate = FinancialProofGate {
            owner: self.owner,
            access,
            consent,
            proof,
            material,
        };
        let after = self
            .kernel
            .intake(key, delivery, retention, &gate, true, history)?;
        self.check_current_v1(access, consent, proof, material)?;
        match after {
            Some(after) => self.owner.commit(
                access,
                key,
                &self.history.current,
                after,
                INTAKE,
                self.metadata,
                consent,
            ),
            None => Ok(self.history.current.view.revision),
        }
    }
    pub fn retain_original_union_v1(
        self,
        access: &Access,
        key: &str,
        retention: LocalSignedRetention<'_>,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<u64> {
        self.check_current_v1(access, consent, proof, material)?;
        let gate = FinancialProofGate {
            owner: self.owner,
            access,
            consent,
            proof,
            material,
        };
        let after = self.kernel.retain_union(key, retention, &gate)?;
        self.check_current_v1(access, consent, proof, material)?;
        match after {
            Some(after) => self.owner.commit(
                access,
                key,
                &self.history.current,
                after,
                UNION,
                self.metadata,
                consent,
            ),
            None => Ok(self.history.current.view.revision),
        }
    }
    pub fn checkpoint_original_transaction_v1(
        &self,
        access: &Access,
        retention: LocalSignedRetention<'_>,
        transactions: LocalTransactionCheckpoint<'_>,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<TransactionCheckpointSummary> {
        self.check_current_v1(access, consent, proof, material)?;
        let gate = FinancialProofGate {
            owner: self.owner,
            access,
            consent,
            proof,
            material,
        };
        let result = self
            .kernel
            .checkpoint_transaction(retention, &gate, transactions)?;
        self.check_current_v1(access, consent, proof, material)?;
        Ok(result)
    }
    pub fn verify_completed_submission_v1<'prepared>(
        &'prepared self,
        access: &Access,
        operation: &str,
        retention: LocalSignedRetention<'_>,
        transactions: LocalTransactionCheckpoint<'_>,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<VerifiedPrivateDurableSubmissionV1<'prepared, 'owner, 'source>> {
        self.check_current_v1(access, consent, proof, material)?;
        if self
            .kernel
            .binding()
            .continuations
            .values()
            .any(|c| c.record.terms.scope.delivery.submission_operation_id != operation)
        {
            return Err(denied());
        }
        let gate = FinancialProofGate {
            owner: self.owner,
            access,
            consent,
            proof,
            material,
        };
        let retained = self
            .kernel
            .verify_submission(operation, retention, &gate, transactions)?;
        let owners = self.kernel.completed_owners()?;
        self.check_current_v1(access, consent, proof, material)?;
        Ok(VerifiedPrivateDurableSubmissionV1 {
            prepared: self,
            retained,
            owners,
        })
    }
}
pub struct VerifiedPrivateDurableSubmissionV1<'prepared, 'owner, 'source> {
    prepared: &'prepared PreparedPrivateFinancialV1<'owner, 'source>,
    retained: crate::durable_proposals_v1::submission_verification_v1::VerifiedDurableSubmissionV1,
    owners: Vec<
        wholepact_signer::authority_bridge::financial_continuation_v1::CompletedDispatchOwnerV1,
    >,
}
impl VerifiedPrivateDurableSubmissionV1<'_, '_, '_> {
    /// Inert exact local chain lineage. Actual currentness and live pair
    /// admissions remain mandatory at the Host and final send boundary.
    pub fn expected_dispatch_chain_attempt_v1(&self) -> Result<u32> {
        let latest = self.prepared.kernel.retained_dispatch(
            self.prepared
                .kernel
                .next_delegation_attempt()
                .checked_sub(1)
                .ok_or_else(damaged)?,
        )?;
        if latest.admissions.len() != 2 {
            return Err(denied());
        }
        self.validate_completed_dispatch_context_v1(&latest.requests[0].context)?;
        Ok(latest.chain_attempt_number)
    }

    pub fn retained(
        &self,
    ) -> &crate::durable_proposals_v1::submission_verification_v1::VerifiedDurableSubmissionV1 {
        &self.retained
    }
    pub fn continuation_record(&self,account:&str)->Option<&wholepact_signer::authority_bridge::financial_continuation_v1::FinancialContinuationRecordV1>{
        self.prepared
            .kernel
            .binding()
            .continuations
            .get(account)
            .map(|r| &r.record)
    }
    pub fn completed_owners(
        &self,
    ) -> &[wholepact_signer::authority_bridge::financial_continuation_v1::CompletedDispatchOwnerV1]
    {
        &self.owners
    }
    pub fn delivery_plan(
        &self,
    ) -> &wholepact_signer::authority_bridge::durable_review_ipc_v3::DurableDeliveryPlanV2 {
        &self
            .prepared
            .kernel
            .binding()
            .continuations
            .values()
            .next()
            .expect("validated two-owner binding")
            .record
            .terms
            .scope
            .delivery
    }
    pub fn check_current_v1(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<()> {
        self.prepared
            .check_current_v1(access, consent, proof, material)
    }
}

use wholepact_signer::authority_bridge::financial_continuation_v1::{
    AuthenticatedCompletedDispatchAdmissionV1, AuthorizeCompletedDispatchV1,
    CompletedDispatchContextV1,
};
impl VerifiedPrivateDurableSubmissionV1<'_, '_, '_> {
    pub fn validate_completed_dispatch_context_v1(
        &self,
        context: &CompletedDispatchContextV1,
    ) -> Result<()> {
        context.validate().map_err(|_| damaged())?;
        let descriptor = self.retained.descriptor();
        if serde_json::to_value(&context.fixed).map_err(|_| damaged())?
            != serde_json::to_value(self.retained.fixed_identity()).map_err(|_| damaged())?
            || &context.delivery != self.delivery_plan()
            || context.owners != self.owners
            || context.signed_result_request_digest != self.retained.signed_request_digest()
            || context.signed_artifact_digest != self.retained.signed_candidate_digest()
            || context.transaction_checkpoint_id != self.retained.checkpoint_id()
            || context.final_transaction_digest != descriptor.bytes_sha256
            || context.final_transaction_id != descriptor.transaction_id
            || context.transaction_expiry_height != descriptor.expiry_height
            || context.network != descriptor.network
            || context.consensus_branch_id != descriptor.consensus_branch_id
            || context.delivery.submission_operation_id != descriptor.operation_id
        {
            return Err(damaged());
        }
        Ok(())
    }
}
/// Exact retained data, not a submission permit. It borrows actual original pins
/// and cannot be constructed from serialized requests or history receipts.
pub struct RetainedPrivateDispatchIntentV1<'prepared, 'owner, 'source> {
    prepared: &'prepared PreparedPrivateFinancialV1<'owner, 'source>,
    retained: kernel::RetainedDispatchAttemptV1,
}
impl RetainedPrivateDispatchIntentV1<'_, '_, '_> {
    pub fn requests(&self) -> &[AuthorizeCompletedDispatchV1; 2] {
        &self.retained.requests
    }
    pub fn context_digest(&self) -> Result<String> {
        self.retained.requests[0]
            .context
            .digest()
            .map_err(|_| damaged())
    }
    pub fn check_current_v1(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<()> {
        self.prepared
            .check_current_v1(access, consent, proof, material)?;
        let original = self
            .prepared
            .kernel
            .retained_dispatch(self.retained.requests[0].context.attempt)?;
        if original.requests != self.retained.requests {
            return Err(damaged());
        }
        Ok(())
    }
}
impl<'owner, 'source> PreparedPrivateFinancialV1<'owner, 'source> {
    pub fn retained_dispatch_intent_v1<'prepared>(
        &'prepared self,
        attempt: u32,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<RetainedPrivateDispatchIntentV1<'prepared, 'owner, 'source>> {
        self.check_current_v1(access, consent, proof, material)?;
        let retained = self.kernel.retained_dispatch(attempt)?;
        Ok(RetainedPrivateDispatchIntentV1 {
            prepared: self,
            retained,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn retain_dispatch_intent_v1(
        self,
        access: &Access,
        key: &str,
        requests: [AuthorizeCompletedDispatchV1; 2],
        histories: [&AuthenticatedFinancialContinuationHistoryV1; 2],
        submissions: &wholepact_chain::EncryptedSubmissionJournal,
        retention: LocalSignedRetention<'_>,
        transactions: LocalTransactionCheckpoint<'_>,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<Self> {
        self.check_current_v1(access, consent, proof, material)?;
        let operation = &requests[0].context.delivery.submission_operation_id;
        let chain_attempt_number;
        let mut previous_outcomes = BTreeMap::new();
        let mut previous_history_digests = BTreeMap::new();
        {
            let verified = self.verify_completed_submission_v1(
                access,
                operation,
                retention,
                transactions,
                consent,
                proof,
                material,
            )?;
            for request in &requests {
                request.validate().map_err(|_| damaged())?;
                verified.validate_completed_dispatch_context_v1(&request.context)?;
                let actual = histories
                    .iter()
                    .find(|h| h.snapshot().account_id == request.account_id)
                    .ok_or_else(damaged)?;
                let original = self
                    .kernel
                    .binding()
                    .continuations
                    .get(&request.account_id)
                    .ok_or_else(damaged)?;
                if serde_json::to_value(actual.continuation_request()).map_err(|_| damaged())?
                    != serde_json::to_value(&original.request).map_err(|_| damaged())?
                    || actual.snapshot().head != request.expected_head
                    || actual.snapshot().writer_epoch != request.writer_epoch
                    || actual.snapshot().network_profile_id != request.network_profile_id
                {
                    return Err(damaged());
                }
            }
            if submissions.identity() != verified.delivery_plan().submission_journal_identity {
                return Err(damaged());
            }
            let saved = submissions
                .retained_submission_descriptor(operation)
                .map_err(|_| damaged())?;
            if saved
                .as_ref()
                .is_some_and(|d| d != verified.retained().descriptor())
            {
                return Err(damaged());
            }
            let attempts = submissions
                .submission_attempts(operation)
                .map_err(|_| damaged())?;
            if saved.is_none() && !attempts.is_empty() {
                return Err(damaged());
            }
            if attempts
                .iter()
                .enumerate()
                .any(|(i, a)| a.number != (i + 1) as u32)
            {
                return Err(damaged());
            }
            chain_attempt_number = attempts.len() as u32 + 1;
            let next = self.kernel.next_delegation_attempt();
            if requests[0].context.attempt != next {
                return Err(damaged());
            }
            if next > 1 {
                let previous = self.kernel.retained_dispatch(next - 1)?;
                for request in &previous.requests {
                    let history = histories
                        .iter()
                        .find(|h| h.snapshot().account_id == request.account_id)
                        .ok_or_else(damaged)?;
                    let outcome = history
                        .completed_dispatch_outcome(request)
                        .map_err(|_| damaged())?
                        .cloned();
                    if previous
                        .admissions
                        .get(&request.account_id)
                        .is_some_and(|saved| outcome.as_ref() != Some(saved))
                    {
                        return Err(damaged());
                    }
                    previous_outcomes.insert(request.account_id.clone(), outcome);
                    previous_history_digests.insert(
                        request.account_id.clone(),
                        history.history_digest().to_owned(),
                    );
                }
            }
        }
        let after = self.kernel.retain_dispatch_intent(
            requests,
            chain_attempt_number,
            previous_outcomes,
            previous_history_digests,
        )?;
        self.advance_dispatch_metadata(
            access,
            key,
            after,
            DISPATCH_INTENT,
            consent,
            proof,
            material,
        )
    }
    pub fn retain_dispatch_admission_v1(
        self,
        access: &Access,
        key: &str,
        admission: &AuthenticatedCompletedDispatchAdmissionV1,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<Self> {
        self.check_current_v1(access, consent, proof, material)?;
        let after = self.kernel.retain_dispatch_admission(admission)?;
        self.advance_dispatch_metadata(
            access,
            key,
            after,
            DISPATCH_ADMISSION,
            consent,
            proof,
            material,
        )
    }
    fn advance_dispatch_metadata(
        mut self,
        access: &Access,
        key: &str,
        mut after: Envelope,
        kind: &str,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<Self> {
        self.check_current_v1(access, consent, proof, material)?;
        after.view.revision = self
            .history
            .current
            .view
            .revision
            .checked_add(1)
            .ok_or_else(damaged)?;
        after.view.updated_at = crate::now();
        kernel::validate_delta(&self.history.current, &after, kind)?;
        let command = financial_command(access, key, &self.history.current, &after, kind)?;
        let (saved,next)=self.owner.source.original.engine.store.update_original_agreement_pinned_v3(self.metadata,&command,
            self.owner.source.original.source.agreement_id(),self.history.current.view.revision,crate::encode(&after)?,kind)
            .map_err(|error| {let mut e=crate::store_error(error);e.safe_actions=vec!["Preserve the exact original dispatch intent and reconcile the same operation; do not regenerate heads or timestamps".into()];e})?;
        self.owner
            .commands
            .lock()
            .map_err(|_| damaged())?
            .insert(saved.operation_id, command);
        self.metadata = next;
        self.history = self.owner.check(access, consent)?;
        self.kernel = self
            .kernel
            .advance_after_own_commit(self.history.current.clone())?;
        self.check_current_v1(access, consent, proof, material)?;
        Ok(self)
    }
}

impl PreparedPrivateFinancialV1<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    pub fn retain_original_submission_v1<
        A: wholepact_chain::SubmissionAuthority,
        C: wholepact_chain::SubmissionClock,
    >(
        &self,
        access: &Access,
        operation: &str,
        retention: LocalSignedRetention<'_>,
        local:wholepact_protocol::authorization::retention::transaction::submission_handoff::LocalSubmissionHandoff<'_,A,C>,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<wholepact_chain::SubmissionDescriptor> {
        self.check_current_v1(access, consent, proof, material)?;
        if self.kernel.binding().continuations.values().any(|r| {
            r.record.terms.scope.delivery.submission_operation_id != operation
                || r.record.terms.scope.delivery.submission_journal_identity
                    != local.submission_journal.identity()
        }) {
            return Err(denied());
        }
        let latest = self.kernel.retained_dispatch(
            self.kernel
                .next_delegation_attempt()
                .checked_sub(1)
                .ok_or_else(damaged)?,
        )?;
        let attempts = local
            .submission_journal
            .submission_attempts(operation)
            .map_err(|_| damaged())?;
        if latest.admissions.len() != 2
            || latest.chain_attempt_number != attempts.len() as u32 + 1
            || latest.requests[0].context.delivery.submission_operation_id != operation
        {
            return Err(denied());
        }
        let gate = FinancialProofGate {
            owner: self.owner,
            access,
            consent,
            proof,
            material,
        };
        let result = self
            .kernel
            .retain_submission(operation, retention, &gate, local)?;
        self.check_current_v1(access, consent, proof, material)
            .map_err(|_| financial_outcome_unknown())?;
        Ok(result)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_original_submission_v1<
        A: wholepact_chain::SubmissionAuthority,
        B: wholepact_chain::SubmissionBackend,
        C: wholepact_chain::SubmissionClock,
    >(
        &self,
        access: &Access,
        operation: &str,
        retention: LocalSignedRetention<'_>,
        local:wholepact_protocol::authorization::retention::transaction::submission_handoff::LocalSubmissionDispatch<'_,A,B,C>,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<wholepact_chain::SubmissionDispatchReport> {
        self.check_current_v1(access, consent, proof, material)?;
        if self.kernel.binding().continuations.values().any(|r| {
            r.record.terms.scope.delivery.submission_operation_id != operation
                || r.record.terms.scope.delivery.submission_journal_identity
                    != local.submission_journal.identity()
        }) {
            return Err(denied());
        }
        let latest = self.kernel.retained_dispatch(
            self.kernel
                .next_delegation_attempt()
                .checked_sub(1)
                .ok_or_else(damaged)?,
        )?;
        let attempts = local
            .submission_journal
            .submission_attempts(operation)
            .map_err(|_| damaged())?;
        if latest.admissions.len() != 2
            || latest.chain_attempt_number != attempts.len() as u32 + 1
            || latest.requests[0].context.delivery.submission_operation_id != operation
        {
            return Err(denied());
        }
        let gate = FinancialProofGate {
            owner: self.owner,
            access,
            consent,
            proof,
            material,
        };
        let result = self
            .kernel
            .dispatch_submission(operation, retention, &gate, local)
            .await?;
        self.check_current_v1(access, consent, proof, material)
            .map_err(|_| financial_outcome_unknown())?;
        Ok(result)
    }
}
fn financial_outcome_unknown() -> ApiError {
    ApiError::new("FINANCIAL_OUTCOME_REQUIRES_RECONCILIATION",
        "Preserve original financial and submission journals; a late permission change cannot imply that no retention or dispatch occurred")
}

impl PreparedPrivateFinancialV1<'_, '_> {
    /// Prepare an exact privacy review before the actual short Return lease.
    /// Inert metadata cannot authorize Return, retention, signing or dispatch.
    pub fn financial_result_retention_scope_v1(
        &self,
        preview:&wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultPreviewV1,
        access: &Access,
        consent: &dyn LocalPrivateDurableFinancialConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<wholepact_protocol::authorization::retention::SignedRetentionScope> {
        self.check_current_v1(access, consent, proof, material)?;
        let scope = self.kernel.preview_retention_scope(preview)?;
        self.check_current_v1(access, consent, proof, material)?;
        Ok(scope)
    }
}
