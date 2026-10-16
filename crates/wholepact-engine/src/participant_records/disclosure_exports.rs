//! Exact selected local receipt export with a separate held disclosure lease.
//! The encrypted intent and attempt precede filesystem effects. This is an
//! intentionally plaintext local file, not relay delivery or payment proof.
use super::*;
use wholepact_core::disclosure::{
    DisclosureConsentSource, DisclosureDecision, inspect_private_receipt,
};
use wholepact_storage_security::receipt_file::{
    MAX_RECEIPT_BYTES, PrivateReceiptTarget, ReceiptFileError, ReceiptFileIdentity,
    ReceiptTargetBinding,
};

const MAX_EXPORTS: usize = 16;
const MAX_ATTEMPTS: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptExportPhase {
    StageExactPayload,
    WriteExactLocalFile,
}

/// Native-only scope. Both source and sink identities are exact and held. The
/// preview includes the selected facts, recipient, audience and irrevocability
/// warning. It is never replaced by an untrusted imported verified/approved flag.
#[derive(Clone, PartialEq, Eq)]
pub struct DisclosureExportScope {
    pub record: ParticipantRecordScope,
    pub export_id: String,
    pub preview_id: String,
    pub source_record_digest: String,
    pub preview: DisclosurePreview,
    pub payload_digest: String,
    pub payload_length: usize,
    pub target: ReceiptFileIdentity,
    pub target_binding: ReceiptTargetBinding,
    pub phase: ReceiptExportPhase,
}
impl fmt::Debug for DisclosureExportScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DisclosureExportScope { selected_private_export: [REDACTED] }")
    }
}
/// Must keep the exact original consent, revocation state and source snapshot
/// stable through the final sink and completion commit. A production issuer must
/// interlock this with record observation changes and recovery transitions; if it
/// cannot do so, it must deny. Ordinary record/payment/proving consent is not an
/// issuer. Reopening either store or target requires newly bound held leases.
pub trait DisclosureExportLease {
    fn scope(&self) -> &DisclosureExportScope;
    fn consent_record_ref(&self) -> &str;
    fn expires_at(&self) -> &str;
    fn check_current(&self) -> Result<()>;
}
pub trait DisclosureExportAuthority: Send + Sync {
    fn acquire<'a>(
        &'a self,
        scope: &DisclosureExportScope,
        window: &ObservationWindow,
    ) -> Result<Box<dyn DisclosureExportLease + 'a>>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageParticipantReceiptExport {
    pub record_id: String,
    pub expected_record_revision: u64,
    pub preview_id: String,
    pub export_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteParticipantReceiptExport {
    pub record_id: String,
    pub export_id: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptExportState {
    StagedNoFileEffect,
    FileOutcomeUnknown,
    LocalFileWrittenHistorical,
}
/// Safe metadata only. Completion is historical local file creation/verification,
/// not current file availability, delivery to a reviewer, consent or settlement.
#[derive(Clone, Debug, Serialize)]
pub struct ParticipantReceiptExportView {
    pub export_id: String,
    pub preview_id: String,
    pub state: ReceiptExportState,
    pub attempts: usize,
    pub agreement_revision: u64,
    pub assurance: &'static str,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredReceiptExport {
    export_id: String,
    preview_id: String,
    record_digest: String,
    preview_digest: String,
    target: ReceiptFileIdentity,
    /// Exact only-selected canonical receipt bytes, encrypted inside the journal.
    payload: String,
    payload_digest: String,
    consent_record_ref: String,
    staged_at: String,
    attempts: BTreeMap<String, String>,
    completed_at: Option<String>,
}
impl StoredReceiptExport {
    fn state(&self) -> ReceiptExportState {
        if self.completed_at.is_some() {
            ReceiptExportState::LocalFileWrittenHistorical
        } else if self.attempts.is_empty() {
            ReceiptExportState::StagedNoFileEffect
        } else {
            ReceiptExportState::FileOutcomeUnknown
        }
    }
    fn view(&self, revision: u64) -> ParticipantReceiptExportView {
        ParticipantReceiptExportView {
            export_id: self.export_id.clone(),
            preview_id: self.preview_id.clone(),
            state: self.state(),
            attempts: self.attempts.len(),
            agreement_revision: revision,
            assurance: "selected_unverified_private_receipt_local_file_only_no_external_delivery",
        }
    }
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn stage_participant_receipt_export(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: StageParticipantReceiptExport,
        runtime: ParticipantRecordRuntime<'_>,
        target: &PrivateReceiptTarget,
        authority: &dyn DisclosureExportAuthority,
    ) -> Result<ParticipantReceiptExportView> {
        require_mutable_records(self, agreement_id)?;
        for id in [&request.export_id, &request.preview_id] {
            validate_identifier(id)?;
        }
        target.check_current().map_err(file_error)?;
        let mut envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, &request.record_id, runtime.profile_id)?;
        let record_scope = make_scope(
            self,
            access,
            agreement_id,
            stored,
            &runtime,
            ParticipantRecordAction::ExportReceipt,
        );
        let record_lease = checked_lease(&runtime, &record_scope)?;
        let (record, preview) = current_preview(self, stored, &request.preview_id)?;
        let payload = serde_json::to_string(preview.receipt()).map_err(|_| internal())?;
        if payload.len() > MAX_RECEIPT_BYTES {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Selected receipt exceeds the local file limit",
            ));
        }
        let scope = export_scope(
            record_scope.clone(),
            &request.export_id,
            &request.preview_id,
            &record,
            preview,
            &payload,
            target,
            ReceiptExportPhase::StageExactPayload,
        )?;
        let lease = acquire_export_lease(authority, &scope, runtime.window)?;
        prepare_exact(&scope, &record, &*lease, runtime.window, &payload)?;
        let command = context(
            access,
            key,
            "stage_participant_receipt_export",
            agreement_id,
            Some(revision),
            &json!({"request":request,"target":target.identity()}),
        )?;
        if self
            .store
            .find_replay(&command)
            .map_err(store_error)?
            .is_some()
        {
            let prior = stored
                .disclosure_exports
                .get(&request.export_id)
                .ok_or_else(corrupt_record)?;
            require_same_intent(prior, &scope, &payload, &*lease)?;
            check_lease(&*record_lease, &record_scope, runtime.window)?;
            check_export_lease(&*lease, &scope, runtime.window)?;
            return Ok(prior.view(envelope.view.revision));
        }
        candidates::check_revision(&envelope, revision)?;
        check_record_revision(stored, request.expected_record_revision)?;
        if stored.disclosure_exports.len() >= MAX_EXPORTS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Private receipt export limit reached; preserve existing disclosure history",
            ));
        }
        if stored.disclosure_exports.contains_key(&request.export_id) {
            return Err(ApiError::new(
                "REVISION_CONFLICT",
                "Export IDs and selected payloads are immutable; retry the original intent",
            ));
        }
        let intent = StoredReceiptExport {
            export_id: request.export_id.clone(),
            preview_id: request.preview_id.clone(),
            record_digest: scope.source_record_digest.clone(),
            preview_digest: scope.preview.digest().into(),
            target: target.identity().clone(),
            payload,
            payload_digest: scope.payload_digest.clone(),
            consent_record_ref: lease.consent_record_ref().into(),
            staged_at: runtime.window.now.clone(),
            attempts: BTreeMap::new(),
            completed_at: None,
        };
        envelope
            .participant_records
            .get_mut(&request.record_id)
            .ok_or_else(not_found)?
            .disclosure_exports
            .insert(request.export_id.clone(), intent);
        check_lease(&*record_lease, &record_scope, runtime.window)?;
        check_export_lease(&*lease, &scope, runtime.window)?;
        target.check_current().map_err(file_error)?;
        self.commit_private_record(
            access,
            &command,
            revision,
            envelope,
            &request.record_id,
            &runtime,
            Some(request.export_id.clone()),
            "participant_receipt_export_staged",
        )?;
        self.receipt_export_view_unchecked(
            access,
            agreement_id,
            &request.record_id,
            &request.export_id,
            &runtime,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write_participant_receipt_export(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        request: WriteParticipantReceiptExport,
        runtime: ParticipantRecordRuntime<'_>,
        target: &PrivateReceiptTarget,
        authority: &dyn DisclosureExportAuthority,
    ) -> Result<ParticipantReceiptExportView> {
        require_mutable_records(self, agreement_id)?;
        target.check_current().map_err(file_error)?;
        let mut envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, &request.record_id, runtime.profile_id)?;
        let record_scope = make_scope(
            self,
            access,
            agreement_id,
            stored,
            &runtime,
            ParticipantRecordAction::ExportReceipt,
        );
        let record_lease = checked_lease(&runtime, &record_scope)?;
        let intent = stored
            .disclosure_exports
            .get(&request.export_id)
            .ok_or_else(not_found)?
            .clone();
        let (record, preview) = current_preview(self, stored, &intent.preview_id)?;
        let scope = export_scope(
            record_scope.clone(),
            &request.export_id,
            &intent.preview_id,
            &record,
            preview,
            &intent.payload,
            target,
            ReceiptExportPhase::WriteExactLocalFile,
        )?;
        let lease = acquire_export_lease(authority, &scope, runtime.window)?;
        require_same_intent(&intent, &scope, &intent.payload, &*lease)?;
        prepare_exact(&scope, &record, &*lease, runtime.window, &intent.payload)?;
        let command = context(
            access,
            key,
            "attempt_participant_receipt_export",
            agreement_id,
            None,
            &json!({"request":request,"target":target.identity(),"payload_digest":intent.payload_digest}),
        )?;
        // The exact idempotency key is not exposed in the private history either.
        let attempt_id = digest_bytes(b"wholepact:receipt-attempt-key:v1\0", key.as_bytes());
        let replay = self
            .store
            .find_replay(&command)
            .map_err(store_error)?
            .is_some();
        if intent.completed_at.is_some() {
            check_lease(&*record_lease, &record_scope, runtime.window)?;
            check_export_lease(&*lease, &scope, runtime.window)?;
            return Ok(intent.view(envelope.view.revision));
        }
        if !replay {
            if intent.attempts.len() >= MAX_ATTEMPTS {
                return Err(ApiError::new(
                    "RESOURCE_EXHAUSTED",
                    "Local receipt attempt limit reached; inspect retained export history",
                ));
            }
            let revision = envelope.view.revision;
            envelope
                .participant_records
                .get_mut(&request.record_id)
                .ok_or_else(not_found)?
                .disclosure_exports
                .get_mut(&request.export_id)
                .ok_or_else(not_found)?
                .attempts
                .insert(attempt_id.clone(), runtime.window.now.clone());
            check_lease(&*record_lease, &record_scope, runtime.window)?;
            check_export_lease(&*lease, &scope, runtime.window)?;
            self.commit_private_record(
                access,
                &command,
                revision,
                envelope,
                &request.record_id,
                &runtime,
                Some(request.export_id.clone()),
                "participant_receipt_export_attempted",
            )?;
        } else if !intent.attempts.contains_key(&attempt_id) {
            return Err(corrupt_record());
        }
        // Re-read after durable intent/attempt. The held issuer must interlock
        // subsequent source/consent changes until this scope's effect completes.
        require_mutable_records(self, agreement_id)?;
        let envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, &request.record_id, runtime.profile_id)?;
        let (record, current) = current_preview(self, stored, &intent.preview_id)?;
        if current != scope.preview || record.content_digest()? != scope.source_record_digest {
            return Err(stale_export());
        }
        check_lease(&*record_lease, &record_scope, runtime.window)?;
        check_export_lease(&*lease, &scope, runtime.window)?;
        prepare_exact(&scope, &record, &*lease, runtime.window, &intent.payload)?;
        target
            .write_exact(intent.payload.as_bytes())
            .map_err(file_error)?;
        // Any failure here preserves the durable unknown attempt. A retry may
        // verify only this same exact private file; partial files are not repaired.
        check_export_lease(&*lease, &scope, runtime.window)?;
        check_lease(&*record_lease, &record_scope, runtime.window)?;
        require_mutable_records(self, agreement_id)?;
        let mut envelope = self.load(access, agreement_id)?;
        let revision = envelope.view.revision;
        let stored = owned_record(&envelope, access, &request.record_id, runtime.profile_id)?;
        let (record, current) = current_preview(self, stored, &intent.preview_id)?;
        if current != scope.preview || record.content_digest()? != scope.source_record_digest {
            return Err(stale_export());
        }
        let current_intent = stored
            .disclosure_exports
            .get(&request.export_id)
            .ok_or_else(corrupt_record)?;
        if current_intent.completed_at.is_some() {
            return Ok(current_intent.view(revision));
        }
        let completion_key = digest_bytes(b"wholepact:receipt-completion-key:v1\0", key.as_bytes());
        let completion = context(
            access,
            &completion_key,
            "complete_participant_receipt_export",
            agreement_id,
            None,
            &json!({"request":request,"target":target.identity(),"payload_digest":intent.payload_digest}),
        )?;
        envelope
            .participant_records
            .get_mut(&request.record_id)
            .ok_or_else(not_found)?
            .disclosure_exports
            .get_mut(&request.export_id)
            .ok_or_else(not_found)?
            .completed_at = Some(runtime.window.now.clone());
        self.commit_private_record(
            access,
            &completion,
            revision,
            envelope,
            &request.record_id,
            &runtime,
            Some(request.export_id.clone()),
            "participant_receipt_local_file_written",
        )?;
        self.receipt_export_view_unchecked(
            access,
            agreement_id,
            &request.record_id,
            &request.export_id,
            &runtime,
        )
    }
    pub fn participant_receipt_export_status(
        &self,
        access: &Access,
        agreement_id: &str,
        record_id: &str,
        export_id: &str,
        runtime: ParticipantRecordRuntime<'_>,
    ) -> Result<ParticipantReceiptExportView> {
        require_encrypted(self)?;
        let envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, record_id, runtime.profile_id)?;
        let scope = make_scope(
            self,
            access,
            agreement_id,
            stored,
            &runtime,
            ParticipantRecordAction::ReadPrivate,
        );
        let lease = checked_lease(&runtime, &scope)?;
        let intent = stored
            .disclosure_exports
            .get(export_id)
            .ok_or_else(not_found)?;
        check_lease(&*lease, &scope, runtime.window)?;
        Ok(intent.view(envelope.view.revision))
    }
    fn receipt_export_view_unchecked(
        &self,
        access: &Access,
        agreement_id: &str,
        record_id: &str,
        export_id: &str,
        runtime: &ParticipantRecordRuntime<'_>,
    ) -> Result<ParticipantReceiptExportView> {
        let envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, record_id, runtime.profile_id)?;
        Ok(stored
            .disclosure_exports
            .get(export_id)
            .ok_or_else(not_found)?
            .view(envelope.view.revision))
    }
}
fn current_preview(
    engine: &Engine,
    stored: &StoredParticipantRecord,
    id: &str,
) -> Result<(SettlementRecord, DisclosurePreview)> {
    let recipe = stored.disclosure_previews.get(id).ok_or_else(not_found)?;
    let record = load_private_record(engine, stored)?;
    if record.content_digest()? != recipe.record_digest {
        return Err(stale_export());
    }
    let preview = DisclosurePreview::build(
        &record,
        recipe.selection.clone(),
        recipe.method.clone(),
        &recipe.preview_window,
    )?;
    if preview.digest() != recipe.preview_digest {
        return Err(corrupt_record());
    }
    Ok((record, preview))
}
#[allow(clippy::too_many_arguments)]
fn export_scope(
    record_scope: ParticipantRecordScope,
    export_id: &str,
    preview_id: &str,
    record: &SettlementRecord,
    preview: DisclosurePreview,
    payload: &str,
    target: &PrivateReceiptTarget,
    phase: ReceiptExportPhase,
) -> Result<DisclosureExportScope> {
    Ok(DisclosureExportScope {
        record: record_scope,
        export_id: export_id.into(),
        preview_id: preview_id.into(),
        source_record_digest: record.content_digest()?,
        preview,
        payload_digest: digest_bytes(b"wholepact:selected-receipt:v1\0", payload.as_bytes()),
        payload_length: payload.len(),
        target: target.identity().clone(),
        target_binding: target.binding(),
        phase,
    })
}
fn acquire_export_lease<'a>(
    authority: &'a dyn DisclosureExportAuthority,
    scope: &DisclosureExportScope,
    window: &ObservationWindow,
) -> Result<Box<dyn DisclosureExportLease + 'a>> {
    let lease = authority.acquire(scope, window)?;
    check_export_lease(&*lease, scope, window)?;
    Ok(lease)
}
fn check_export_lease(
    lease: &dyn DisclosureExportLease,
    scope: &DisclosureExportScope,
    window: &ObservationWindow,
) -> Result<()> {
    wholepact_core::agreement::validate_timestamp(lease.expires_at())?;
    validate_identifier(lease.consent_record_ref())?;
    if lease.scope() != scope || lease.expires_at() <= window.now.as_str() {
        return Err(ApiError::new(
            "DISCLOSURE_CONSENT_DENIED",
            "Current exact source, selected fields, destination and local target consent are required",
        ));
    }
    lease.check_current()
}
struct HeldConsent<'a>(&'a dyn DisclosureExportLease);
impl DisclosureConsentSource for HeldConsent<'_> {
    fn review_current_disclosure(
        &mut self,
        preview: &DisclosurePreview,
    ) -> wholepact_core::Result<DisclosureDecision> {
        self.0.check_current().map_err(|_| {
            CoreError::new(
                wholepact_core::ErrorCode::UserRejected,
                "Held disclosure consent is no longer current",
            )
        })?;
        if preview != &self.0.scope().preview {
            return Ok(DisclosureDecision::Rejected);
        }
        Ok(DisclosureDecision::Approved {
            preview_digest: preview.digest().into(),
            consent_record_ref: self.0.consent_record_ref().into(),
            expires_at: self.0.expires_at().into(),
        })
    }
}
fn prepare_exact(
    scope: &DisclosureExportScope,
    record: &SettlementRecord,
    lease: &dyn DisclosureExportLease,
    window: &ObservationWindow,
    expected: &str,
) -> Result<()> {
    check_export_lease(lease, scope, window)?;
    let prepared = scope
        .preview
        .prepare_export(record, &mut HeldConsent(lease), window)?;
    if prepared.encode()? != expected.as_bytes() {
        return Err(corrupt_record());
    }
    Ok(())
}
fn require_same_intent(
    intent: &StoredReceiptExport,
    scope: &DisclosureExportScope,
    payload: &str,
    lease: &dyn DisclosureExportLease,
) -> Result<()> {
    if intent.export_id != scope.export_id
        || intent.preview_id != scope.preview_id
        || intent.record_digest != scope.source_record_digest
        || intent.preview_digest != scope.preview.digest()
        || intent.payload != payload
        || intent.payload_digest != scope.payload_digest
        || intent.target != scope.target
        || intent.consent_record_ref != lease.consent_record_ref()
    {
        return Err(ApiError::new(
            "DISCLOSURE_INTENT_MISMATCH",
            "The retained disclosure intent binds different original consent, source, selected bytes or target",
        ));
    }
    Ok(())
}
fn digest_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hex::encode(hash.finalize())
}
fn stale_export() -> ApiError {
    ApiError::new(
        "REVISION_CONFLICT",
        "The source changed after disclosure review; preserve this intent and review a new exact preview",
    )
}
fn file_error(error: ReceiptFileError) -> ApiError {
    let code = match error {
        ReceiptFileError::UnsupportedPlatform => "UNSUPPORTED_CAPABILITY",
        ReceiptFileError::ExistingDifferent => "DISCLOSURE_FILE_CONFLICT",
        ReceiptFileError::OutcomeUnknown => "DISCLOSURE_FILE_OUTCOME_UNKNOWN",
        ReceiptFileError::InvalidPayload => "RESOURCE_EXHAUSTED",
        ReceiptFileError::UnsafeTarget | ReceiptFileError::TargetChanged => {
            "DISCLOSURE_TARGET_UNSAFE"
        }
    };
    ApiError::new(code, &error.to_string())
}

pub(super) fn validate_exports(stored: &StoredParticipantRecord) -> Result<()> {
    if stored.disclosure_exports.len() > MAX_EXPORTS {
        return Err(corrupt_record());
    }
    for (id, intent) in &stored.disclosure_exports {
        for identifier in [
            id,
            &intent.export_id,
            &intent.preview_id,
            &intent.consent_record_ref,
        ] {
            validate_identifier(identifier).map_err(|_| corrupt_record())?;
        }
        let recipe = stored
            .disclosure_previews
            .get(&intent.preview_id)
            .ok_or_else(corrupt_record)?;
        if id != &intent.export_id
            || intent.record_digest != recipe.record_digest
            || intent.preview_digest != recipe.preview_digest
            || intent.payload.is_empty()
            || intent.payload.len() > MAX_RECEIPT_BYTES
            || digest_bytes(
                b"wholepact:selected-receipt:v1\0",
                intent.payload.as_bytes(),
            ) != intent.payload_digest
            || intent.attempts.len() > MAX_ATTEMPTS
            || (intent.completed_at.is_some() && intent.attempts.is_empty())
        {
            return Err(corrupt_record());
        }
        intent.target.validate().map_err(|_| corrupt_record())?;
        wholepact_core::agreement::validate_timestamp(&intent.staged_at)
            .map_err(|_| corrupt_record())?;
        inspect_private_receipt(intent.payload.as_bytes(), &recipe.selection.destination)
            .map_err(|_| corrupt_record())?;
        for (attempt, time) in &intent.attempts {
            wholepact_core::proposal::validate_sha256(attempt).map_err(|_| corrupt_record())?;
            wholepact_core::agreement::validate_timestamp(time).map_err(|_| corrupt_record())?;
            if time < &intent.staged_at {
                return Err(corrupt_record());
            }
        }
        if let Some(completed) = &intent.completed_at {
            wholepact_core::agreement::validate_timestamp(completed)
                .map_err(|_| corrupt_record())?;
            if completed < &intent.staged_at
                || !intent.attempts.values().any(|attempt| attempt <= completed)
            {
                return Err(corrupt_record());
            }
        }
        // Exact selected facts can be reconstructed while this is the current
        // source. After later observations, keep the historical immutable bytes;
        // they remain explicitly unverified and cannot be freshly exported.
        let record = SettlementRecord::load_retained_archive(stored.record.clone())
            .map_err(|_| corrupt_record())?;
        if record.content_digest()? == intent.record_digest {
            let preview = DisclosurePreview::build(
                &record,
                recipe.selection.clone(),
                recipe.method.clone(),
                &recipe.preview_window,
            )?;
            if preview.digest() != intent.preview_digest
                || serde_json::to_string(preview.receipt()).map_err(|_| corrupt_record())?
                    != intent.payload
            {
                return Err(corrupt_record());
            }
        }
    }
    Ok(())
}
