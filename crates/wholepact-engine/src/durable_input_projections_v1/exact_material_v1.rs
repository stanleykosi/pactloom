//! INACTIVE exact recapture composition for the exclusive private coordinator.
//! The retained receipt owner never leaves this crate. Its callback only removes
//! permission: the actual consumed native preconstruction lease still supplies
//! the independent import/scan authority, and a new native decision is required
//! before any durable material can be exported.
use super::material_capture_reservations_v1::{
    load_reserved_capture, LocalDurableCaptureConsentV1, MaterialCaptureActionV1,
    NewMaterialCaptureDispatchV1,
};
use super::*;
use wholepact_chain::{BackendIdentity, ChainAdapter};
use wholepact_signer::authority_bridge::{
    durable_construction_v1::{
        exact_capture_v1::DurableExactCaptureRestrictionsV1,
        AuthenticatedDurableConstructionDisclosureV1, DurableConstructionCaptureRequestV1,
        DurableConstructionOutboxV1, DurableConstructionRedisclosureLinkV1,
        DurableConstructionRequestV1,
    },
    ipc::OriginalHistoryClient,
    preconstruction_ipc::SignerPreconstructionLease,
};
use wholepact_storage_security::EncryptedConnection;
use wholepact_wallet::wallet::{
    protected_sync::{
        durable_exact_selection_v1::{
            DurableExactConstructionAnchorV1, DurableExactInputV1,
            DurableExactSelectionExpectationV1,
        },
        ProtectedWalletSync,
    },
    SelectionContext,
};

/// Exact original provenance held by the Engine which admitted the sealed
/// receipt. No public constructor, serde, Clone, raw projection getter or
/// conversion into a native permission exists.
pub(crate) struct RetainedProjectionCaptureV1<'a> {
    engine: &'a Engine,
    access: &'a Access,
    consent: &'a (dyn LocalDurableDiscoveryConsentV1 + Sync),
    capture_consent: &'a (dyn LocalDurableCaptureConsentV1 + Sync),
    agreement_id: String,
    candidate_id: String,
    account_id: String,
    retained_binding: String,
    intent_identity: String,
    request: DurableConstructionCaptureRequestV1,
    construction_anchor: DurableExactConstructionAnchorV1,
}

impl Engine {
    /// This crate-private factory is reachable only through the exclusive
    /// private workspace. It cannot admit a public projection/receipt DTO.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn retained_projection_capture_v1<'a>(
        &'a self,
        access: &'a Access,
        agreement_id: &str,
        candidate_id: &str,
        operation_id: &str,
        dispatch: NewMaterialCaptureDispatchV1<'a>,
        consent: &'a (dyn LocalDurableDiscoveryConsentV1 + Sync),
        capture_consent: &'a (dyn LocalDurableCaptureConsentV1 + Sync),
    ) -> Result<RetainedProjectionCaptureV1<'a>> {
        // Mandatory saved-operation lookup, never replacement request/anchor
        // parameters. Only a newly committed, one-use scheduling ticket permits
        // initial dispatch. Losing that ticket requires exact native recovery,
        // not recreating the old capture or reusing expired enrollment refs.
        let (intent, _) = load_reserved_capture(
            self,
            access,
            agreement_id,
            candidate_id,
            operation_id,
            consent,
            capture_consent,
            MaterialCaptureActionV1::DispatchNewCapture,
        )?;
        dispatch.require_exact(self, agreement_id, candidate_id, operation_id, &intent)?;
        Ok(RetainedProjectionCaptureV1 {
            engine: self,
            access,
            consent,
            capture_consent,
            agreement_id: agreement_id.into(),
            candidate_id: candidate_id.into(),
            account_id: intent.request.scope.account_id.clone(),
            retained_binding: intent.binding().into(),
            intent_identity: intent.identity()?,
            construction_anchor: intent.anchor()?,
            request: intent.request,
        })
    }
}

impl RetainedProjectionCaptureV1<'_> {
    fn current_projection(&self) -> Result<DurableInputProjectionV1> {
        let (intent, projection) = load_reserved_capture(
            self.engine,
            self.access,
            &self.agreement_id,
            &self.candidate_id,
            &self.request.operation_id,
            self.consent,
            self.capture_consent,
            MaterialCaptureActionV1::DispatchNewCapture,
        )?;
        if intent.binding() != self.retained_binding
            || intent.identity()? != self.intent_identity
            || intent.request != self.request
            || intent.request.scope.account_id != self.account_id
        {
            return Err(denied());
        }
        Ok(projection)
    }

    /// Returns only the actual authenticated native disclosure to its private
    /// caller. A later Engine admission is separate and may fail after the
    /// native immutable outbox committed; preserve the exact original operation
    /// locator and treat that interruption as disclosed-or-unknown, not erasure.
    pub(crate) async fn capture(
        self,
        client: &OriginalHistoryClient,
        original: SignerPreconstructionLease<'_>,
        destination: EncryptedConnection,
        source: ChainAdapter,
    ) -> Result<(
        ProtectedWalletSync,
        AuthenticatedDurableConstructionDisclosureV1,
    )> {
        let projection = self.current_projection()?;
        let restrictions = restrictions(&projection, source.identity(), &self.construction_anchor)?;
        // This callback is only an additional current-source/privacy restriction.
        // The signer adapter independently validates the real consumed lease,
        // actual wallet/FVK/provider/destination and exact native manifest.
        let current = || self.current_projection().is_ok();
        let result = client
            .capture_exact_and_request_durable_construction_v1(
                original,
                destination,
                source,
                self.request.clone(),
                restrictions,
                &current,
            )
            .await
            .map_err(|_| ApiError::new("DURABLE_CONSTRUCTION_UNAVAILABLE", "Exact native capture did not complete. Preserve the original operation and journals: an approved disclosure may already be committed; no replacement input or fresh retry authority was created"))?;
        self.current_projection()?;
        Ok(result)
    }
}

/// Joins only material-free claims. Actual admission additionally requires the
/// sealed installed-native observation, immutable original digest and validated
/// material below; passing this predicate cannot manufacture such an owner.
fn join_disclosed_capture_request(
    saved: &DurableConstructionCaptureRequestV1,
    actual: &DurableConstructionCaptureRequestV1,
    redelivery: Option<&DurableConstructionRedisclosureLinkV1>,
    current_grant: &str,
) -> Result<()> {
    let mut expected = saved.clone();
    if let Some(link) = redelivery {
        if link.original_operation_id != saved.operation_id
            || actual.operation_id == saved.operation_id
            || !digest(&link.original_request_digest)
            || !digest(&link.original_outbox_reference)
            || !digest(&actual.enrollment_ref)
            || !digest(&actual.accepted_manifest_ref)
            || !digest(current_grant)
        {
            return Err(denied());
        }
        // These are the ONLY deltas allowed by the actual signer's immutable
        // original-row redisclosure join. No validity/audience/material change.
        expected.operation_id = actual.operation_id.clone();
        expected.enrollment_ref = actual.enrollment_ref.clone();
        expected.accepted_manifest_ref = actual.accepted_manifest_ref.clone();
        expected.scope.constructor.authenticated_local_grant_digest = current_grant.into();
        expected.scope.prover.authenticated_local_grant_digest = current_grant.into();
    }
    if expected != *actual {
        return Err(denied());
    }
    Ok(())
}

/// Pure exact-facts comparison, never an authentication or material issuer.
fn require_material_facts(
    projection: &DurableInputProjectionV1,
    anchor: &DurableExactConstructionAnchorV1,
    account_id: &str,
    context: &SelectionContext,
    own_return: &str,
    inputs: &[(String, u64, [u8; 32])],
) -> Result<()> {
    if account_id != projection.intent.account_id
        || context.anchor_height != anchor.height
        || context.anchor_hash_protocol != anchor.block_hash_protocol
        || context.anchor_root != anchor.root
        || own_return != projection.own_return_receiver
        || inputs.len() != projection.inputs.len()
    {
        return Err(denied());
    }
    let mut ids = BTreeSet::new();
    for (id, value, commitment) in inputs {
        if !ids.insert(id)
            || !projection.inputs.iter().any(|input| {
                input.input_id == *id
                    && input.value.as_zatoshis() == *value
                    && bytes(&input.commitment).is_ok_and(|original| original == *commitment)
            })
        {
            return Err(denied());
        }
    }
    Ok(())
}

/// Historical sealed-outbox/data correlation. This function never admits a
/// public outbox; the mutation entry below still consumes the nominal native
/// owner. Reusing it for protected historical validation creates no authority.
pub(super) fn join_saved_disclosure(
    saved: &material_capture_reservations_v1::MaterialCaptureIntentV1,
    projection: &DurableInputProjectionV1,
    outbox: &DurableConstructionOutboxV1,
) -> Result<()> {
    outbox.validate().map_err(|_| damaged())?;
    let full = outbox.request();
    let actual = DurableConstructionCaptureRequestV1 {
        operation_id: full.operation_id.clone(),
        enrollment_ref: full.enrollment_ref.clone(),
        accepted_manifest_ref: full.accepted_manifest_ref.clone(),
        scope: full.scope.clone(),
    };
    join_disclosed_capture_request(
        &saved.request,
        &actual,
        outbox.redisclosure(),
        outbox.recipient_grant_digest(),
    )?;
    // Only NOW, with actual sealed material, can the original full native
    // request digest be reconstructed. No pre-capture digest was invented.
    let original = DurableConstructionRequestV1 {
        operation_id: saved.request.operation_id.clone(),
        enrollment_ref: saved.request.enrollment_ref.clone(),
        accepted_manifest_ref: saved.request.accepted_manifest_ref.clone(),
        scope: saved.request.scope.clone(),
        material: full.material.clone(),
    };
    let original_digest = original.digest().map_err(|_| damaged())?;
    let expected = outbox
        .redisclosure()
        .map_or(outbox.request_digest(), |link| {
            link.original_request_digest.as_str()
        });
    if original_digest != expected {
        return Err(denied());
    }
    let evidence = full
        .material
        .historical_review_evidence()
        .map_err(|_| damaged())?;
    if wholepact_protocol::durable_proposal_v1::canonical_durable_account_id(&evidence.fvk)
        != projection.intent.account_id
    {
        return Err(denied());
    }
    let material_source = full.material.review_summary();
    let provider = &projection.intent.provider;
    let source = material_source
        .get("historical_source")
        .ok_or_else(damaged)?;
    if source.get("source_id").and_then(|v| v.as_str()) != Some(provider.source_id.as_str())
        || source.get("endpoint").and_then(|v| v.as_str()) != Some(provider.endpoint.as_str())
        || source.get("trust_profile").and_then(|v| v.as_str())
            != Some(provider.trust_profile.as_str())
    {
        return Err(denied());
    }
    let inputs = evidence
        .inputs
        .iter()
        .map(|input| {
            (
                input.input_id.clone(),
                input.value_zatoshis,
                input.commitment,
            )
        })
        .collect::<Vec<_>>();
    require_material_facts(
        projection,
        &saved.anchor()?,
        &evidence.account_id,
        &evidence.context,
        &wholepact_protocol::review::encode_testnet_receiver(&evidence.change_address),
        &inputs,
    )
}

struct ExactCaptureAdmissionGate<'a> {
    engine: &'a Engine,
    access: &'a Access,
    agreement_id: &'a str,
    candidate_id: &'a str,
    original_operation_id: &'a str,
    intent_identity: String,
    actual_scope:
        wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionScopeV1,
    material_digest: String,
    discovery: &'a dyn LocalDurableDiscoveryConsentV1,
    capture: &'a dyn LocalDurableCaptureConsentV1,
    material: &'a dyn crate::durable_construction_v1::LocalDurableMaterialConsentV1,
}
impl crate::durable_construction_v1::LocalDurableMaterialConsentV1
    for ExactCaptureAdmissionGate<'_>
{
    fn permits(
        &self,
        scope: &wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionScopeV1,
        material_digest: &str,
        action: crate::durable_construction_v1::DurableMaterialActionV1,
    ) -> bool {
        let check = || -> Result<()> {
            let (intent, _) = load_reserved_capture(
                self.engine,
                self.access,
                self.agreement_id,
                self.candidate_id,
                self.original_operation_id,
                self.discovery,
                self.capture,
                MaterialCaptureActionV1::AdmitMaterial,
            )?;
            if intent.identity()? != self.intent_identity
                || scope != &self.actual_scope
                || material_digest != self.material_digest
            {
                return Err(denied());
            }
            Ok(())
        };
        check().is_ok() && self.material.permits(scope, material_digest, action) && check().is_ok()
    }
}
impl Engine {
    /// The exclusive facade must use this exact reserved-intent admission, not
    /// generic intake. Both direct and separately approved linked redisclosures
    /// join the original operation, immutable scope, all commitments and common
    /// anchor before any protected admission. Only a sealed native owner enters.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn intake_reserved_material_capture_v1(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        candidate_id: &str,
        original_operation_id: &str,
        revision: u64,
        disclosure: AuthenticatedDurableConstructionDisclosureV1,
        discovery: &dyn LocalDurableDiscoveryConsentV1,
        capture: &dyn LocalDurableCaptureConsentV1,
        material: &dyn crate::durable_construction_v1::LocalDurableMaterialConsentV1,
    ) -> Result<Mutation> {
        let (intent, projection) = load_reserved_capture(
            self,
            access,
            agreement_id,
            candidate_id,
            original_operation_id,
            discovery,
            capture,
            MaterialCaptureActionV1::AdmitMaterial,
        )?;
        let outbox = disclosure.outbox();
        join_saved_disclosure(&intent, &projection, outbox)?;
        let envelope = self.load(access, agreement_id)?;
        if let Some(existing) = material_capture_reservations_v1::admitted_outbox(
            &envelope,
            candidate_id,
            &intent.request.scope.account_id,
        )? {
            // Only the already committed exact sealed result may reach the
            // generic command's idempotent replay before its CAS check. A later
            // redisclosure, even of identical material, cannot replace intake.
            if existing != *outbox {
                return Err(conflict());
            }
        } else {
            crate::candidates::check_revision(&envelope, revision)?;
        }
        let gate = ExactCaptureAdmissionGate {
            engine: self,
            access,
            agreement_id,
            candidate_id,
            original_operation_id,
            intent_identity: intent.identity()?,
            actual_scope: outbox.request().scope.clone(),
            material_digest: outbox.material_digest().into(),
            discovery,
            capture,
            material,
        };
        // The maintained generic path rechecks exact CAS revision and runs this
        // additional deny-only source/privacy gate at each admission boundary.
        self.intake_durable_construction_v1(access, key, candidate_id, revision, disclosure, &gate)
    }
}

pub(super) fn join_capture_request(
    projection: &DurableInputProjectionV1,
    candidate: &wholepact_core::ProposalInput,
    request: &DurableConstructionCaptureRequestV1,
    anchor: &DurableExactConstructionAnchorV1,
) -> Result<()> {
    projection
        .matches_final_proposal(candidate)
        .map_err(|_| denied())?;
    request.scope.validate().map_err(|_| denied())?;
    let intent = &projection.intent;
    let scope = &request.scope;
    if scope.version != 2
        || scope.proposal != *candidate
        || scope.account_id != intent.account_id
        || scope.participant_id != intent.participant_id
        || scope.privacy_domain != intent.privacy_domain
        || scope.constructor.principal_id != intent.constructor_principal_id
        || scope.prover.principal_id != intent.constructor_principal_id
        || scope.protected_destination != intent.protected_destination
        || scope.valid_from_unix_seconds < intent.valid_from_unix_seconds
        || scope.valid_until_unix_seconds > intent.valid_until_unix_seconds
        || scope.minimum_confirmations < intent.minimum_confirmations
        || scope.maximum_scan_blocks > intent.maximum_scan_blocks
        || anchor.height < projection.context.anchor_height
        || anchor.height >= candidate.manifest.expiry_height
        || scope
            .reviewers
            .iter()
            .map(|r| r.account_id())
            .collect::<BTreeSet<_>>()
            != intent
                .local_reviewer_account_ids
                .iter()
                .map(String::as_str)
                .collect()
        || (anchor.height == projection.context.anchor_height
            && (anchor.block_hash_protocol != bytes(&projection.context.anchor_hash)?
                || anchor.root != bytes(&projection.context.anchor_root)?))
    {
        return Err(denied());
    }
    // Material retention is a DIFFERENT freshly displayed native purpose from
    // metadata retention, so its validated text need not equal the old text.
    // Both original metadata permissions remain necessary throughout this
    // recapture; the new scope cannot extend their audience or validity.
    Ok(())
}

pub(super) fn bytes(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)
        .map_err(|_| damaged())?
        .try_into()
        .map_err(|_| damaged())
}

/// Pure restriction conversion. It is private and only called after the exact
/// journal-owned intake join. Every originally retained commitment is mandatory.
fn restrictions(
    projection: &DurableInputProjectionV1,
    actual: &BackendIdentity,
    anchor: &DurableExactConstructionAnchorV1,
) -> Result<DurableExactCaptureRestrictionsV1> {
    projection.validate().map_err(|_| damaged())?;
    let provider = &projection.intent.provider;
    if actual.source_id != provider.source_id
        || actual.endpoint != provider.endpoint
        || actual.trust_profile != provider.trust_profile
    {
        return Err(denied());
    }
    Ok(DurableExactCaptureRestrictionsV1 {
        expected: DurableExactSelectionExpectationV1 {
            provider: actual.clone(),
            original_context: SelectionContext {
                tip_height: projection.context.tip_height,
                tip_hash_protocol: bytes(&projection.context.tip_hash)?,
                anchor_height: projection.context.anchor_height,
                anchor_hash_protocol: bytes(&projection.context.anchor_hash)?,
                anchor_root: bytes(&projection.context.anchor_root)?,
            },
            construction_anchor: anchor.clone(),
            inputs: projection
                .inputs
                .iter()
                .map(|input| {
                    Ok(DurableExactInputV1 {
                        input_id: input.input_id.clone(),
                        value_zatoshis: input.value.as_zatoshis(),
                        commitment: Some(bytes(&input.commitment)?),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        },
        original_own_return_receiver: projection.own_return_receiver.clone(),
    })
}

#[cfg(test)]
#[path = "exact_material_v1_tests.rs"]
pub(super) mod tests;
