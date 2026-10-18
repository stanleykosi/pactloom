//! INACTIVE private, material-free capture intent history. This is coordination
//! before native dispatch, never an input/debit reservation, refund, approval,
//! admission, proof or signing capability. Every attempt remains immutable and
//! potentially disclosed after cancellation, expiry, crash or a lost response.
use super::*;
use wholepact_signer::authority_bridge::durable_construction_v1::{
    DurableConstructionCaptureRequestV1, DurableConstructionRedisclosureSourceV1,
};
use wholepact_store::CommandContext;
use wholepact_wallet::wallet::protected_sync::durable_exact_selection_v1::DurableExactConstructionAnchorV1;

const MAX_CAPTURE_INTENTS_PER_OWNER: usize = 4;
const MAX_CAPTURE_INTENTS: usize = 8;
const MAX_CAPTURE_INTENT_BYTES: usize = 128 * 1024;
const MAX_CAPTURE_HISTORY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum MaterialCaptureActionV1 {
    RetainIntent,
    ReadOriginalLocator,
    DispatchNewCapture,
    AdmitMaterial,
}

/// A fresh private-workspace permission for the actual verified encrypted Store
/// destination AND exact material-free request. It is additional to permission
/// for both original metadata requests, and can only deny native capture.
/// Hold the genuine foreground permission through every synchronous check; a
/// saved boolean or a decoded intent is never an implementation of this gate.
pub(crate) trait LocalDurableCaptureConsentV1 {
    fn permits(
        &self,
        request: &DurableConstructionCaptureRequestV1,
        verified_store_origin: &str,
        action: MaterialCaptureActionV1,
    ) -> bool;
}

/// Private persistence DTO, deliberately not a native permission or a public
/// construction-anchor import API. Lower-case hex has one canonical encoding.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedConstructionAnchorV1 {
    height: u32,
    block_hash_protocol: String,
    root: String,
}
impl SavedConstructionAnchorV1 {
    fn from_anchor(anchor: &DurableExactConstructionAnchorV1) -> Self {
        Self {
            height: anchor.height,
            block_hash_protocol: hex::encode(anchor.block_hash_protocol),
            root: hex::encode(anchor.root),
        }
    }
    fn anchor(&self) -> Result<DurableExactConstructionAnchorV1> {
        if !digest(&self.block_hash_protocol) || !digest(&self.root) {
            return Err(damaged());
        }
        Ok(DurableExactConstructionAnchorV1 {
            height: self.height,
            block_hash_protocol: exact_material_v1::bytes(&self.block_hash_protocol)?,
            root: exact_material_v1::bytes(&self.root)?,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MaterialCaptureIntentV1 {
    version: u16,
    pub(super) request: DurableConstructionCaptureRequestV1,
    source_set_binding: String,
    construction_anchor: SavedConstructionAnchorV1,
    created_at_unix_seconds: u64,
    expected_revision: u64,
    command: CommandContext,
}
impl MaterialCaptureIntentV1 {
    pub(super) fn anchor(&self) -> Result<DurableExactConstructionAnchorV1> {
        self.construction_anchor.anchor()
    }
    pub(super) fn binding(&self) -> &str {
        &self.source_set_binding
    }
    pub(super) fn identity(&self) -> Result<String> {
        crate::hash_domain(
            b"wholepact:engine-material-free-capture-intent:v1\0",
            &serde_json::to_value(self).map_err(|_| damaged())?,
        )
    }
    fn original_locator(&self) -> DurableConstructionRedisclosureSourceV1 {
        // No material exists at reservation time, so the full native request
        // digest cannot be invented. Native redisclosure must resolve this exact
        // operation under a NEW approval; this value cannot initiate capture.
        DurableConstructionRedisclosureSourceV1 {
            operation_id: self.request.operation_id.clone(),
            expected_request_digest: None,
        }
    }
}

/// Non-clone, non-serde, one-use scheduling ticket from a newly committed intent.
/// It is not native authority. The original live lease and separate full-material
/// decision remain mandatory. A crash loses this ticket, never the saved intent.
/// Replay/lookup cannot recreate it, so uncertainty never becomes redispatch.
pub(crate) struct NewMaterialCaptureDispatchV1<'a> {
    engine: &'a Engine,
    agreement_id: String,
    candidate_id: String,
    operation_id: String,
    intent_identity: String,
}
impl NewMaterialCaptureDispatchV1<'_> {
    pub(super) fn require_exact(
        self,
        engine: &Engine,
        agreement_id: &str,
        candidate_id: &str,
        operation_id: &str,
        intent: &MaterialCaptureIntentV1,
    ) -> Result<()> {
        if !std::ptr::eq(self.engine, engine)
            || self.agreement_id != agreement_id
            || self.candidate_id != candidate_id
            || self.operation_id != operation_id
            || self.intent_identity != intent.identity()?
        {
            return Err(denied());
        }
        Ok(())
    }
}

fn valid_operation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:./@".contains(&b))
}
fn require_bounded(value: &impl Serialize, maximum: usize) -> Result<()> {
    let raw = serde_json::to_vec(value).map_err(|_| damaged())?;
    let _: serde_json::Value =
        wholepact_core::strict_json::parse_typed_json_with_byte_limit(&raw, maximum)
            .map_err(|_| damaged())?;
    Ok(())
}

/// Source-set identity excludes capture history. Appending the other owner's
/// exact intent cannot invalidate a live callback; changing any original source
/// request, saved receipt, or exact candidate does invalidate it.
pub(super) fn source_binding(round: &Round, proposal: &Proposal) -> Result<String> {
    crate::hash_domain(
        b"wholepact:engine-retained-exact-recapture-source:v1\0",
        &serde_json::json!((
            &round.metadata_origin,
            &round.requests,
            &round.intakes,
            proposal.input(),
            proposal.manifest_digest(),
            proposal.proposal_digest(),
        )),
    )
}

#[allow(clippy::too_many_arguments)]
fn reservation_command(
    access: &Access,
    key: &str,
    agreement_id: &str,
    candidate_id: &str,
    revision: u64,
    request: &DurableConstructionCaptureRequestV1,
    source: &str,
    anchor: &SavedConstructionAnchorV1,
) -> Result<CommandContext> {
    crate::context(
        access,
        key,
        "reserve_material_capture_v1",
        agreement_id,
        Some(revision),
        // This private retained command must correlate its saved replay key
        // with its exact request digest. Generic command keys remain separate
        // from request identity; only this new purpose adds the explicit join.
        // This is data integrity, not authentication or a dispatch permission.
        &(key, candidate_id, request, source, anchor),
    )
}
fn same_command(left: &CommandContext, right: &CommandContext) -> bool {
    left.principal_id == right.principal_id
        && left.idempotency_key == right.idempotency_key
        && left.request_digest == right.request_digest
}

/// Historical integrity only. No current clock, live signer process, surviving
/// old grant or native execution is required merely to read a saved record.
pub(super) fn validate_history(round: &Round, candidate_id: &str) -> Result<()> {
    if round.capture_intents.is_empty() {
        return Ok(());
    }
    require_bounded(&round.capture_intents, MAX_CAPTURE_HISTORY_BYTES)?;
    let proposal = round.candidate_from_validated_receipts()?;
    if round.capture_intents.len() > MAX_CAPTURE_INTENTS
        || round.frozen_manifest_digest.as_deref() != Some(proposal.manifest_digest())
    {
        return Err(damaged());
    }
    let source = source_binding(round, &proposal)?;
    let mut counts = BTreeMap::<&str, usize>::new();
    let mut common_anchor = None;
    let mut command_keys = BTreeSet::new();
    let mut revisions = BTreeSet::new();
    for (operation, intent) in &round.capture_intents {
        require_bounded(intent, MAX_CAPTURE_INTENT_BYTES)?;
        let request = &intent.request;
        let projection = &round
            .intakes
            .get(&request.scope.account_id)
            .ok_or_else(damaged)?
            .outbox
            .projection;
        if intent.version != 1
            || operation != &request.operation_id
            || !valid_operation(operation)
            || !digest(&request.enrollment_ref)
            || !digest(&request.accepted_manifest_ref)
            || !digest(&intent.source_set_binding)
            || intent.source_set_binding != source
            || round
                .requests
                .values()
                .any(|r| r.operation_id == *operation)
            || intent.command.principal_id != round.principal_id
            || !command_keys.insert(intent.command.idempotency_key.as_str())
            || !revisions.insert(intent.expected_revision)
        {
            return Err(damaged());
        }
        for original in round.requests.values() {
            original
                .require_valid_at(intent.created_at_unix_seconds)
                .map_err(|_| damaged())?;
        }
        require_common_anchor(round, &intent.anchor()?).map_err(|_| damaged())?;
        request
            .scope
            .check_valid_at(intent.created_at_unix_seconds)
            .map_err(|_| damaged())?;
        exact_material_v1::join_capture_request(
            projection,
            proposal.input(),
            request,
            &intent.anchor()?,
        )
        .map_err(|_| damaged())?;
        let reconstructed = reservation_command(
            &Access {
                principal_id: round.principal_id.clone(),
                ..Access::default()
            },
            &intent.command.idempotency_key,
            &proposal.manifest().agreement.agreement_id,
            candidate_id,
            intent.expected_revision,
            request,
            &source,
            &intent.construction_anchor,
        )
        .map_err(|_| damaged())?;
        if !same_command(&intent.command, &reconstructed)
            || common_anchor.is_some_and(|a| a != &intent.construction_anchor)
        {
            return Err(damaged());
        }
        common_anchor = Some(&intent.construction_anchor);
        let count = counts.entry(&request.scope.account_id).or_default();
        *count += 1;
        if *count > MAX_CAPTURE_INTENTS_PER_OWNER {
            return Err(damaged());
        }
    }
    Ok(())
}

pub(super) fn admitted_outbox(
    envelope: &Envelope,
    candidate_id: &str,
    account_id: &str,
) -> Result<
    Option<
        wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionOutboxV1,
    >,
> {
    let Some(roster) = envelope.durable_construction_v1.get(candidate_id) else {
        return Ok(None);
    };
    let owners = roster
        .get("owners")
        .and_then(|v| v.as_object())
        .ok_or_else(damaged)?;
    let Some(intake) = owners.get(account_id) else {
        return Ok(None);
    };
    Ok(Some(
        serde_json::from_value(intake.get("outbox").ok_or_else(damaged)?.clone())
            .map_err(|_| damaged())?,
    ))
}

/// Cross-join any already-admitted material under a discovery candidate to its
/// exact original intent. Generic unrelated sealed intake cannot become this
/// round's history, even if its manifest and principal look plausible.
pub(super) fn validate_admitted_history(
    envelope: &Envelope,
    id: &str,
    round: &Round,
) -> Result<()> {
    let Some(roster) = envelope.durable_construction_v1.get(id) else {
        return Ok(());
    };
    let owners = roster
        .get("owners")
        .and_then(|v| v.as_object())
        .ok_or_else(damaged)?;
    for (account, intake) in owners {
        let outbox: wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionOutboxV1 =
            serde_json::from_value(intake.get("outbox").ok_or_else(damaged)?.clone()).map_err(|_| damaged())?;
        let original_operation = outbox
            .redisclosure()
            .map_or(outbox.request().operation_id.as_str(), |link| {
                link.original_operation_id.as_str()
            });
        let intent = round
            .capture_intents
            .get(original_operation)
            .ok_or_else(damaged)?;
        if intent.request.scope.account_id != *account {
            return Err(damaged());
        }
        let projection = &round
            .intakes
            .get(account)
            .ok_or_else(damaged)?
            .outbox
            .projection;
        exact_material_v1::join_saved_disclosure(intent, projection, &outbox)
            .map_err(|_| damaged())?;
    }
    Ok(())
}

fn append_intent(
    round: &mut Round,
    candidate_id: &str,
    intent: MaterialCaptureIntentV1,
) -> Result<()> {
    if round
        .capture_intents
        .contains_key(&intent.request.operation_id)
    {
        return Err(conflict());
    }
    if round.capture_intents.len() >= MAX_CAPTURE_INTENTS
        || round
            .capture_intents
            .values()
            .filter(|old| old.request.scope.account_id == intent.request.scope.account_id)
            .count()
            >= MAX_CAPTURE_INTENTS_PER_OWNER
    {
        return Err(ApiError::new(
            "RESOURCE_EXHAUSTED",
            "At most four immutable capture attempts per owner and eight per candidate are retained; old uncertainty cannot be overwritten or cleared",
        ));
    }
    if round
        .capture_intents
        .values()
        .any(|old| old.construction_anchor != intent.construction_anchor)
    {
        return Err(conflict());
    }
    // Validate a proposed copy before altering even this in-memory history.
    let mut proposed = round.clone();
    proposed
        .capture_intents
        .insert(intent.request.operation_id.clone(), intent);
    proposed.validate(candidate_id)?;
    *round = proposed;
    Ok(())
}

/// One conservative common anchor is fixed from the FIRST intent, even if
/// native dispatch never happened. It must already fit BOTH original contexts;
/// unavailable anchors require a separately explicit round, never history reset.
fn require_common_anchor(round: &Round, anchor: &DurableExactConstructionAnchorV1) -> Result<()> {
    if round.intakes.len() != 2 {
        return Err(denied());
    }
    for intake in round.intakes.values() {
        let projection = &intake.outbox.projection;
        if anchor.height < projection.context.anchor_height
            || anchor.height >= projection.intent.transaction_expiry_height
            || (anchor.height == projection.context.anchor_height
                && (anchor.block_hash_protocol
                    != exact_material_v1::bytes(&projection.context.anchor_hash)?
                    || anchor.root != exact_material_v1::bytes(&projection.context.anchor_root)?))
        {
            return Err(denied());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn checked_source(
    engine: &Engine,
    access: &Access,
    envelope: &Envelope,
    candidate_id: &str,
    round: &Round,
    request: &DurableConstructionCaptureRequestV1,
    anchor: &DurableExactConstructionAnchorV1,
    discovery: &dyn LocalDurableDiscoveryConsentV1,
    privacy: &dyn LocalDurableCaptureConsentV1,
    action: MaterialCaptureActionV1,
) -> Result<(String, DurableInputProjectionV1)> {
    let check = || -> Result<(String, DurableInputProjectionV1)> {
        engine.check_discovery(
            access,
            envelope,
            candidate_id,
            round,
            discovery,
            DurableDiscoveryActionV1::ReadForExactRecapture,
        )?;
        require_common_anchor(round, anchor)?;
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == candidate_id)
            .ok_or_else(denied)?;
        let derived = round.candidate(candidate_id)?;
        if round.frozen_manifest_digest.as_deref() != Some(candidate.manifest_digest.as_str())
            || candidate.proposal != *derived.input()
            || candidate.manifest_digest != derived.manifest_digest()
            || candidate.proposal_digest != derived.proposal_digest()
            || !valid_operation(&request.operation_id)
            || !digest(&request.enrollment_ref)
            || !digest(&request.accepted_manifest_ref)
        {
            return Err(denied());
        }
        let projection = &round
            .intakes
            .get(&request.scope.account_id)
            .ok_or_else(denied)?
            .outbox
            .projection;
        let existing = admitted_outbox(envelope, candidate_id, &request.scope.account_id)?;
        let exact_existing = if let Some(outbox) = &existing {
            if matches!(
                action,
                MaterialCaptureActionV1::RetainIntent | MaterialCaptureActionV1::DispatchNewCapture
            ) {
                return Err(denied());
            }
            let saved = round
                .capture_intents
                .get(&request.operation_id)
                .ok_or_else(denied)?;
            if saved.request != *request {
                return Err(denied());
            }
            exact_material_v1::join_saved_disclosure(saved, projection, outbox)?;
            true
        } else {
            false
        };
        if (!candidate.proof_jobs.is_empty()
            || envelope.durable_proposals_v1.contains_key(candidate_id))
            && !exact_existing
        {
            return Err(denied());
        }
        exact_material_v1::join_capture_request(projection, &candidate.proposal, request, anchor)?;
        if !matches!(action, MaterialCaptureActionV1::ReadOriginalLocator) {
            request
                .scope
                .check_valid_at(now_seconds()?)
                .map_err(|_| denied())?;
        }
        // Check the actual Store destination separately from the original
        // metadata requests, even though the scope join also requires equality.
        let actual = engine
            .store
            .verify_original_encrypted_destination(Path::new(&request.scope.protected_destination))
            .map_err(crate::store_error)?;
        if hex::encode(actual) != round.metadata_origin {
            return Err(denied());
        }
        Ok((source_binding(round, &derived)?, projection.clone()))
    };
    check()?;
    if !privacy.permits(request, &round.metadata_origin, action) {
        return Err(denied());
    }
    check()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn load_reserved_capture(
    engine: &Engine,
    access: &Access,
    agreement_id: &str,
    candidate_id: &str,
    operation_id: &str,
    discovery: &dyn LocalDurableDiscoveryConsentV1,
    privacy: &dyn LocalDurableCaptureConsentV1,
    action: MaterialCaptureActionV1,
) -> Result<(MaterialCaptureIntentV1, DurableInputProjectionV1)> {
    let envelope = engine.load(access, agreement_id)?;
    let round = engine.discovery_round(&envelope, candidate_id)?;
    let intent = round.capture_intents.get(operation_id).ok_or_else(denied)?;
    let (source, projection) = checked_source(
        engine,
        access,
        &envelope,
        candidate_id,
        &round,
        &intent.request,
        &intent.anchor()?,
        discovery,
        privacy,
        action,
    )?;
    if source != intent.source_set_binding || intent.request.operation_id != operation_id {
        return Err(denied());
    }
    Ok((intent.clone(), projection))
}

impl Engine {
    /// Commit an exact material-free intent BEFORE the private facade can obtain
    /// a one-use dispatcher. The only returned Mutation is for that facade to
    /// sanitize; neither the operation history nor raw AgreementView may escape.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reserve_material_capture_v1<'a>(
        &'a self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        candidate_id: &str,
        revision: u64,
        request: DurableConstructionCaptureRequestV1,
        anchor: DurableExactConstructionAnchorV1,
        discovery: &dyn LocalDurableDiscoveryConsentV1,
        privacy: &dyn LocalDurableCaptureConsentV1,
    ) -> Result<(Mutation, Option<NewMaterialCaptureDispatchV1<'a>>)> {
        let mut envelope = self.load(access, agreement_id)?;
        let mut round = self.discovery_round(&envelope, candidate_id)?;
        let (source, _) = checked_source(
            self,
            access,
            &envelope,
            candidate_id,
            &round,
            &request,
            &anchor,
            discovery,
            privacy,
            MaterialCaptureActionV1::RetainIntent,
        )?;
        let saved_anchor = SavedConstructionAnchorV1::from_anchor(&anchor);
        let command = reservation_command(
            access,
            key,
            agreement_id,
            candidate_id,
            revision,
            &request,
            &source,
            &saved_anchor,
        )?;
        if let Some(existing) = round.capture_intents.get(&request.operation_id) {
            if existing.request != request
                || existing.source_set_binding != source
                || existing.construction_anchor != saved_anchor
                || existing.expected_revision != revision
                || !same_command(&existing.command, &command)
            {
                return Err(conflict());
            }
            // The original command must still exist. A history-only row is not
            // license to invent a replacement idempotency entry or dispatcher.
            let replay = self.replay(access, &command)?.ok_or_else(damaged)?;
            return Ok((replay, None));
        }
        if self.replay(access, &command)?.is_some() {
            return Err(damaged());
        }
        crate::candidates::check_revision(&envelope, revision)?;
        for id in envelope.durable_input_projections_v1.keys() {
            let other = self.discovery_round(&envelope, id)?;
            if other.capture_intents.contains_key(&request.operation_id)
                || other
                    .requests
                    .values()
                    .any(|r| r.operation_id == request.operation_id)
            {
                return Err(conflict());
            }
        }
        let intent = MaterialCaptureIntentV1 {
            version: 1,
            request,
            source_set_binding: source,
            construction_anchor: saved_anchor,
            created_at_unix_seconds: now_seconds()?,
            expected_revision: revision,
            command: command.clone(),
        };
        let identity = intent.identity()?;
        let operation_id = intent.request.operation_id.clone();
        append_intent(&mut round, candidate_id, intent)?;
        put(&mut envelope, candidate_id, &round)?;
        let saved = round
            .capture_intents
            .get(&operation_id)
            .ok_or_else(damaged)?;
        checked_source(
            self,
            access,
            &envelope,
            candidate_id,
            &round,
            &saved.request,
            &saved.anchor()?,
            discovery,
            privacy,
            MaterialCaptureActionV1::RetainIntent,
        )?;
        let mutation = self.commit(
            &command,
            agreement_id,
            revision,
            envelope,
            "durable_material_capture_intent_retained",
        )?;
        // A concurrent exact replay from Store must not produce a second ticket.
        let dispatch = if mutation.replayed {
            None
        } else {
            Some(NewMaterialCaptureDispatchV1 {
                engine: self,
                agreement_id: agreement_id.into(),
                candidate_id: candidate_id.into(),
                operation_id,
                intent_identity: identity,
            })
        };
        Ok((mutation, dispatch))
    }

    /// Exact recovery lookup only. No scan, pairing, disclosure or approval is
    /// attempted. Old enrollment/manifest refs are not returned or renewed.
    /// This current recovery operation is denied after metadata expiry,
    /// or cancellation. After owner admission/proof it requires the exact
    /// already-admitted outbox for THIS original operation, not any owner row.
    /// Inert historical decode always preserves records without old permission.
    /// The caller may start a separate newly approved native redisclosure using
    /// this exact original operation; it must not call initial capture again.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn read_material_capture_locator_v1(
        &self,
        access: &Access,
        agreement_id: &str,
        candidate_id: &str,
        account_id: &str,
        operation_id: &str,
        discovery: &dyn LocalDurableDiscoveryConsentV1,
        privacy: &dyn LocalDurableCaptureConsentV1,
    ) -> Result<DurableConstructionRedisclosureSourceV1> {
        let (intent, _) = load_reserved_capture(
            self,
            access,
            agreement_id,
            candidate_id,
            operation_id,
            discovery,
            privacy,
            MaterialCaptureActionV1::ReadOriginalLocator,
        )?;
        if intent.request.scope.account_id != account_id {
            return Err(denied());
        }
        Ok(intent.original_locator())
    }
}

#[cfg(test)]
#[path = "material_capture_reservations_v1_tests.rs"]
mod tests;
