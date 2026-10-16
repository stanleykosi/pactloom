//! Explicit first Host publication and tagged continuation paths. Original enrollment/owner/epoch and
//! every financial denial stay unchanged. Private files select correlation data;
//! the actual fixed installed native signer/witness channel issues the lease.
mod import_target;
#[path = "preliminary_inventory.rs"]
mod inventory;
use super::*;
pub(in crate::host) use import_target::CommittedImportTarget;
use serde::Serialize;
use wholepact_authority::manual_session_continuation_signature::ManualEnrollmentSessionContinuationOwnerSignature;
use wholepact_signer_origin::{
    ManualEnrollmentContinuationLeaseV2,
    manual_continuation_v2::{
        HostManualEnrollmentContinuationRequestV2, ManualEnrollmentContinuationEvidenceV2,
    },
};
use wholepact_store::manual_enrollment::OriginalManualEnrollmentAuditLink;

/// Only a selected command purpose. This serializable review input cannot
/// manufacture the native decision or the installed-origin lease.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManualAuditPurpose {
    InitialPublicationV2,
    ExistingEnrollmentContinuation,
}
impl ManualAuditPurpose {
    fn description(self) -> &'static str {
        match self {
            Self::InitialPublicationV2 => "FIRST HOST PUBLICATION THROUGH A V2 SUCCESSOR ATTEMPT",
            Self::ExistingEnrollmentContinuation => {
                "SESSION CONTINUATION OF AN EXISTING HOST AUDIT"
            }
        }
    }
    fn publish_command(self) -> &'static str {
        match self {
            Self::InitialPublicationV2 => "manual-enrollment-initial-v2-publish",
            Self::ExistingEnrollmentContinuation => "manual-enrollment-continuation-publish",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManualAuditConsumer {
    InitialPublicationV2,
    ContinuationV2,
    ContinuationV3,
}
fn select_consumer(
    purpose: ManualAuditPurpose,
    original: &Option<OriginalManualEnrollmentAuditLink>,
) -> Result<ManualAuditConsumer> {
    match (purpose, original) {
        (
            ManualAuditPurpose::InitialPublicationV2,
            None | Some(OriginalManualEnrollmentAuditLink::InitialPublicationV2 { .. }),
        ) => Ok(ManualAuditConsumer::InitialPublicationV2),
        (
            ManualAuditPurpose::ExistingEnrollmentContinuation,
            Some(OriginalManualEnrollmentAuditLink::EnrollmentV1 { .. }),
        ) => Ok(ManualAuditConsumer::ContinuationV2),
        (
            ManualAuditPurpose::ExistingEnrollmentContinuation,
            Some(OriginalManualEnrollmentAuditLink::InitialPublicationV2 { .. }),
        ) => Ok(ManualAuditConsumer::ContinuationV3),
        _ => Err(Error::RecoveryFinancialUnsupported),
    }
}
fn require_selected_original(
    purpose: ManualAuditPurpose,
    original: &Option<OriginalManualEnrollmentAuditLink>,
) -> Result<()> {
    select_consumer(purpose, original).map(|_| ())
}
fn require_preparation_original(
    purpose: ManualAuditPurpose,
    original: &Option<OriginalManualEnrollmentAuditLink>,
) -> Result<()> {
    require_selected_original(purpose, original)?;
    if purpose == ManualAuditPurpose::InitialPublicationV2 && original.is_some() {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    Ok(())
}
fn original_description(original: &Option<OriginalManualEnrollmentAuditLink>) -> String {
    match original {
        Some(OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 { .. }) => {
            "Roster V3 audit requires its distinct V2 roster route; this legacy route is denied"
                .into()
        }
        None => "Original Host audit: ABSENT (explicit initial-publication route only)".into(),
        Some(OriginalManualEnrollmentAuditLink::EnrollmentV1 { audit_digest }) => format!(
            "Original Host audit: V1 enrollment {audit_digest}; continuation audit format V2"
        ),
        Some(OriginalManualEnrollmentAuditLink::InitialPublicationV2 { audit_digest }) => format!(
            "Original Host audit: explicit V2 initial publication {audit_digest}; later continuation audit format V3"
        ),
    }
}
fn require_original_unchanged(
    purpose: ManualAuditPurpose,
    expected: &Option<OriginalManualEnrollmentAuditLink>,
    actual: &Option<OriginalManualEnrollmentAuditLink>,
) -> Result<()> {
    require_selected_original(purpose, expected)?;
    require_selected_original(purpose, actual)?;
    if expected != actual {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn require_original_after_append(
    purpose: ManualAuditPurpose,
    before: &Option<OriginalManualEnrollmentAuditLink>,
    after: &Option<OriginalManualEnrollmentAuditLink>,
    receipt_digest: &str,
) -> Result<()> {
    require_selected_original(purpose, before)?;
    match purpose {
        ManualAuditPurpose::ExistingEnrollmentContinuation => {
            require_original_unchanged(purpose, before, after)
        }
        ManualAuditPurpose::InitialPublicationV2 => {
            let exact = Some(OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
                audit_digest: receipt_digest.into(),
            });
            if after != &exact
                || before
                    .as_ref()
                    .is_some_and(|prior| Some(prior) != exact.as_ref())
            {
                return Err(Error::Authentication);
            }
            Ok(())
        }
    }
}
fn publication_review_digest(
    context: &wholepact_store::CommandContext,
    agreement_record_digest: &str,
    agreement_revision: u64,
    owner_client_id: &str,
    purpose: ManualAuditPurpose,
    original_audit: &Option<OriginalManualEnrollmentAuditLink>,
) -> Result<String> {
    require_selected_original(purpose, original_audit)?;
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-host-manual-tagged-publication-review:v3",
        &(
            context,
            agreement_record_digest,
            agreement_revision,
            owner_client_id,
            purpose,
            original_audit,
        ),
    )
    .map_err(|_| Error::Invalid)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PublicationMode {
    AuditOnly,
    PreliminaryInventory,
}
impl PublicationMode {
    fn completion(self) -> &'static str {
        match self {
            Self::AuditOnly => "Host completion is automatic and audit-only.",
            Self::PreliminaryInventory => {
                "After the audit, the separately reviewed preliminary viewing disclosure and bounded local inventory run automatically in this SAME signer process. Stay in its window; no further terminal prompts occur."
            }
        }
    }
}

/// Opaque continuation of the actual native-reviewed append. Cannot be parsed
/// or reconstructed from a saved audit. Retains every original target owner.
struct CommittedManualAudit<'host> {
    source: ContinuationOwners<'host>,
    receipt: wholepact_store::manual_enrollment::ManualAuditAppendReceipt,
    original_signer_intent_digest: String,
    review_digest: String,
    request: HostManualEnrollmentContinuationRequestV2,
    deadline: std::time::Instant,
}
impl CommittedManualAudit<'_> {
    fn check_current(&self) -> Result<()> {
        if std::time::Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        self.source.check_after_append(&self.receipt)
    }
}

struct PreparedManualContinuation<'host> {
    source: ContinuationOwners<'host>,
    approval: PublicationApproval,
    review_digest: String,
    idempotency_key: String,
    request: HostManualEnrollmentContinuationRequestV2,
}
struct ContinuationOwners<'host> {
    original: ManualEnrollmentOwners<'host>,
    enrollment_ref: String,
    extension_digest: String,
    purpose: ManualAuditPurpose,
    original_audit: Option<OriginalManualEnrollmentAuditLink>,
}
impl<'host> std::ops::Deref for ContinuationOwners<'host> {
    type Target = ManualEnrollmentOwners<'host>;
    fn deref(&self) -> &Self::Target {
        &self.original
    }
}
impl ContinuationOwners<'_> {
    fn current_original(&self) -> Result<Option<OriginalManualEnrollmentAuditLink>> {
        self.host
            .engine
            .manual_enrollment_original_audit_link(
                self.host.access()?,
                &self.engine,
                &self.enrollment_ref,
                &self.extension_digest,
            )
            .map_err(Into::into)
    }
    fn require_route_preflight(&self) -> Result<()> {
        let access = self.host.access()?;
        match select_consumer(self.purpose, &self.original_audit)? {
            ManualAuditConsumer::InitialPublicationV2 => self
                .host
                .engine
                .require_manual_enrollment_initial_publication_v2(
                    access,
                    &self.engine,
                    &self.enrollment_ref,
                    &self.extension_digest,
                )?,
            ManualAuditConsumer::ContinuationV2 => self
                .host
                .engine
                .require_manual_enrollment_continuation_original(
                    access,
                    &self.engine,
                    &self.enrollment_ref,
                    &self.extension_digest,
                )?,
            ManualAuditConsumer::ContinuationV3 => self
                .host
                .engine
                .require_manual_enrollment_continuation_original_v2(
                    access,
                    &self.engine,
                    &self.enrollment_ref,
                    &self.extension_digest,
                )?,
        }
        Ok(())
    }
    fn check_current(&self) -> Result<()> {
        self.original.check_current()?;
        require_original_unchanged(
            self.purpose,
            &self.original_audit,
            &self.current_original()?,
        )?;
        self.require_route_preflight()
    }
    fn check_after_append(
        &self,
        receipt: &wholepact_store::manual_enrollment::ManualAuditAppendReceipt,
    ) -> Result<()> {
        self.original.check_current()?;
        if receipt.enrollment_ref() != self.enrollment_ref {
            return Err(Error::Authentication);
        }
        // The opaque receipt came only from the selected concrete consumer of
        // the exact owned key/request committed by the native review below.
        require_original_after_append(
            self.purpose,
            &self.original_audit,
            &self.current_original()?,
            receipt.audit_digest(),
        )?;
        self.require_route_preflight()
    }
}
impl Host {
    /// All six actual shell arms pass through this exact parser and current session
    /// gate before any target/file/native operation; there is no ordinary
    /// financial fallback path for these commands.
    pub(in crate::host) fn manual_enrollment_continuation_command(
        &self,
        command: &str,
    ) -> Result<()> {
        let route = crate::host::manual_continuation_route(command).ok_or(Error::Unsupported)?;
        self.require_manual_session()?;
        match route {
            crate::host::ManualContinuationRoute::Intent => self
                .manual_enrollment_continuation_intent_command(
                    ManualAuditPurpose::ExistingEnrollmentContinuation,
                ),
            crate::host::ManualContinuationRoute::Publish => self
                .manual_enrollment_continuation_publish_command(
                    ManualAuditPurpose::ExistingEnrollmentContinuation,
                    PublicationMode::AuditOnly,
                ),
            crate::host::ManualContinuationRoute::InitialV2Intent => self
                .manual_enrollment_continuation_intent_command(
                    ManualAuditPurpose::InitialPublicationV2,
                ),
            crate::host::ManualContinuationRoute::InitialV2Publish => self
                .manual_enrollment_continuation_publish_command(
                    ManualAuditPurpose::InitialPublicationV2,
                    PublicationMode::AuditOnly,
                ),
            crate::host::ManualContinuationRoute::PublishInventory => self
                .manual_enrollment_continuation_publish_command(
                    ManualAuditPurpose::ExistingEnrollmentContinuation,
                    PublicationMode::PreliminaryInventory,
                ),
            crate::host::ManualContinuationRoute::InitialV2PublishInventory => self
                .manual_enrollment_continuation_publish_command(
                    ManualAuditPurpose::InitialPublicationV2,
                    PublicationMode::PreliminaryInventory,
                ),
        }
    }

    fn manual_continuation_owners<'host>(
        &'host self,
        request: &HostManualEnrollmentRequest,
        enrollment_ref: &str,
        extension_digest: &str,
        purpose: ManualAuditPurpose,
    ) -> Result<ContinuationOwners<'host>> {
        request.validate().map_err(|_| Error::Invalid)?;
        self.require_manual_session()?;
        require_session(self, &request.terms)?;
        let review=self.terminal.approve_historical(&format!(
            "Inspect the complete protected ancestor capsule for this SAME original manual enrollment before {}.\nAccount: {}\nAgreement: {}\nOriginal operation: {}\nThe original signer enrollment, birth, owner, policy, certificate and writer epoch remain unchanged. Only the explicitly selected Host audit may be retained; no financial permission is created.",
            purpose.description(),request.terms.identity.account_id,request.terms.scope.agreement_id,request.terms.operation_id))?;
        let mut committed = None;
        review.effect(&mut || {
            committed = Some(ManualCommittedTarget::open(&self.directory, &self.secrets)?);
            Ok(())
        })?;
        let committed = committed.ok_or(Error::Authentication)?;
        let engine = self
            .engine
            .manual_enrollment_target(self.access()?, &request.terms)?;
        let original_audit = self.engine.manual_enrollment_original_audit_link(
            self.access()?, &engine, enrollment_ref, extension_digest,
        ).map_err(|error| {
            let _ = self.terminal.message("Manual audit selection denied: the exact current scope or original Host audit could not be authenticated. No private request was sent. Preserve original files and IDs; there is no parser or route fallback.\n");
            Error::from(error)
        })?;
        if let Err(error) = require_selected_original(purpose, &original_audit) {
            let message = match purpose {
                ManualAuditPurpose::ExistingEnrollmentContinuation => {
                    "Continuation denied: the original Host enrollment audit is absent. This continuation command cannot create an initial audit. Use the separate explicit manual-enrollment-initial-v2-intent flow for an interrupted first attempt. No private request was sent.\n"
                }
                ManualAuditPurpose::InitialPublicationV2 => {
                    "Initial V2 publication denied: an original V1 Host enrollment audit already exists. Use its existing-audit continuation flow. No private request was sent.\n"
                }
            };
            self.terminal.message(message)?;
            return Err(error);
        }
        // Attachment V2 composition must use manual_original_primary_origin_digest
        // here and in ManualEnrollmentOwners::check_current, preserving this exact
        // original v1 anchor. Never substitute the current extension digest.
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
        let source = ContinuationOwners {
            original: source,
            enrollment_ref: enrollment_ref.into(),
            extension_digest: extension_digest.into(),
            purpose,
            original_audit,
        };
        source.check_current()?;
        Ok(source)
    }
    fn prepare_manual_continuation<'host>(
        &'host self,
        request: &HostManualEnrollmentContinuationRequestV2,
        key: &str,
        enrollment_ref: &str,
        extension_digest: &str,
        purpose: ManualAuditPurpose,
    ) -> Result<PreparedManualContinuation<'host>> {
        request.validate().map_err(|_| Error::Invalid)?;
        id(key)?;
        let source = self.manual_continuation_owners(
            &request.enrollment,
            enrollment_ref,
            extension_digest,
            purpose,
        )?;
        let context = wholepact_store::CommandContext::for_request(
            &request.enrollment.terms.scope.principal_id,
            key,
            &serde_json::to_value(request)?,
        )?;
        let review_digest = publication_review_digest(
            &context,
            source.engine.agreement_record_digest(),
            source.engine.agreement_revision(),
            source.engine.owner_client_id(),
            purpose,
            &source.original_audit,
        )?;
        let approval=self.terminal.approve_publication(&review_digest,&format!(
            "Retain one exact {} under the SAME original signer enrollment.\n{}\nAccount: {}\nOriginal enrollment operation: {}\nContinuation commitment: {}\nActual Store root: {}\nPrincipal: {}\nAgreement/obligation: {}/{}\nExact V2 request: {}\nHost idempotency key: {}\nNative review commitment: {}\nOnly a genuine current native signer/witness V2 admission can be consumed. The original certificate, writer epoch, policy, birth and enrollment remain immutable. No spending, proving, dispatch, viewing-key disclosure, construction or generic financial action is enabled. Failure after commit is uncertain; preserve this original key and inspect the retained audit rather than creating another admission.",
            purpose.description(),original_description(&source.original_audit),request.enrollment.terms.identity.account_id,request.enrollment.terms.operation_id,request.continuation_digest,source.committed.canonical_root(),request.enrollment.terms.scope.principal_id,request.enrollment.terms.scope.agreement_id,request.enrollment.terms.scope.obligation_id,request.digest().map_err(|_|Error::Invalid)?,key,review_digest))?;
        source.check_current()?;
        Ok(PreparedManualContinuation {
            source,
            approval,
            review_digest,
            idempotency_key: key.into(),
            request: request.clone(),
        })
    }
    fn manual_enrollment_continuation_intent_command(
        &self,
        purpose: ManualAuditPurpose,
    ) -> Result<()> {
        self.require_manual_session()?;
        let original:ManualEnrollmentExtensionOwnerSignature=self.read_manual_private(
            "Exact ORIGINAL private manual-enrollment owner-signature JSON file: ",
            "reviewing the unchanged original account/Host intent before an independently approved session continuation")?;
        original.extension.validate().map_err(|_| Error::Invalid)?;
        let request = HostManualEnrollmentRequest {
            terms: original.extension.terms.clone(),
        };
        let source = self.manual_continuation_owners(
            &request,
            &original.extension.enrollment_ref,
            &original.extension.digest().map_err(|_| Error::Invalid)?,
            purpose,
        )?;
        if let Err(error) = require_preparation_original(purpose, &source.original_audit) {
            self.terminal.message("Initial V2 preparation denied: its exact first Host publication already exists. Retry that exact publication with its original key, or use manual-enrollment-continuation-intent for a separately approved later attempt. No private request was sent.\n")?;
            return Err(error);
        }
        let intent = HostManualEnrollmentIntent {
            version: 1,
            operation_id: request.terms.operation_id.clone(),
            host: request.terms.host.clone(),
            scope: request.terms.scope.clone(),
        };
        let intent_digest = intent.digest().map_err(|_| Error::Invalid)?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-manual-tagged-continuation-preparation:v2",
            &(
                &intent,
                &original.extension.enrollment_ref,
                original.extension.digest().map_err(|_| Error::Invalid)?,
                purpose,
                &source.original_audit,
                source.engine.agreement_record_digest(),
                source.engine.agreement_revision(),
                source.engine.owner_client_id(),
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let request_approval=self.terminal.approve_publication(&review_digest,&format!(
            "Send the SAME original request-only manual enrollment intent for {} preparation.\n{}\nAccount: {}\nOriginal enrollment: {}\nOriginal intent commitment: {}\nExact Host claims: {}\nThe signer must authenticate its existing attempted/completed history and independently review a new session-only continuation. No new birth, original enrollment, policy, certificate or writer epoch is authorized. The later owner-signature export and witness-owner review are separate native steps. No current lease or financial permission is returned now.",purpose.description(),original_description(&source.original_audit),request.terms.identity.account_id,original.extension.enrollment_ref,intent_digest,serde_json::to_string_pretty(&intent)?))?;
        let pair_approval=self.terminal.approve_publication(&review_digest,&format!(
            "Approve the finite original-intent pairing metadata send for continuation preparation.\nAccount: {}\nAgreement: {}\nParticipant: {}\nExact original intent commitment: {}\nThis pairing requests no viewing key, private transaction witness, construction, proof, signature or dispatch. Original deadlines cannot be renewed by waiting.",request.terms.identity.account_id,request.terms.scope.agreement_id,request.terms.scope.participant_id,intent_digest))?;
        let deadline = source
            .history_review
            .deadline()
            .min(request_approval.deadline())
            .min(pair_approval.deadline());
        source.check_current()?;
        request_approval.check()?;
        pair_approval.check()?;
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        provider.launch_native().map_err(|_| Error::Permission)?;
        let endpoint = wait_manual_endpoint_before(&provider, deadline)?;
        source.check_current()?;
        request_approval.check()?;
        let pending = pair_approval.commit(
            &review_digest,
            || source.check_current(),
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    &endpoint,
                    "wholepact-native-continuation-intent",
                    PairScope {
                        account_id: request.terms.identity.account_id.clone(),
                        agreement_id: request.terms.scope.agreement_id.clone(),
                        participant_id: request.terms.scope.participant_id.clone(),
                        manifest_digest: intent_digest,
                        history_read: false,
                        authorization_export: false,
                        preconstruction_export: false,
                    },
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        let client = pending.finish().map_err(|_| Error::Permission)?;
        request_approval.commit(
            &review_digest,
            || source.check_current(),
            |_| {
                client
                    .submit_enrollment_intent_before(&intent, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        drop(source);
        // Launcher retained solely for child parent-channel liveness. No Host
        // historical/native/witness owner or admission spans this cleanup wait.
        self.terminal.message("Exact original request-only intent queued. STAY IN THE SIGNER WINDOW to authenticate original history, separately review/retain/sign and privately export the exact continuation. Do not acquire a new session in this preparation phase. Then return here only to close the launcher channel, and complete the separate witness-owner continuation review. This Host receives no export-success or approval claim.\n")?;
        let _cleanup_only=self.terminal.ask("After leaving the native preparation phase, press Enter to close the request channel (cleanup only): ")?;
        drop(client);
        self.terminal.message(&format!("Preparation channel closed. Use {} with the exact signed continuation after separate witness-owner review. It launches a fresh native process after all terminal approvals; financial actions remain disabled.\n", purpose.publish_command()))
    }
    fn manual_enrollment_continuation_publish_command(
        &self,
        purpose: ManualAuditPurpose,
        mode: PublicationMode,
    ) -> Result<()> {
        self.require_manual_session()?;
        let key = self.terminal.ask(match purpose {
            ManualAuditPurpose::InitialPublicationV2 => {
                "Exact first-publication V2 Host audit idempotency key (preserve for retries): "
            }
            ManualAuditPurpose::ExistingEnrollmentContinuation => {
                "Original continuation Host audit idempotency key (preserve for retries): "
            }
        })?;
        id(&key)?;
        let envelope:ManualEnrollmentSessionContinuationOwnerSignature=self.read_manual_private(
            "Exact private native signer-exported continuation owner-signature JSON file: ",
            "correlating the immutable original extension and exact continuation with actual current Host owners")?;
        // Embedded certificate/signature is never adopted as a local trust pin.
        // The actual installed issuer must match this exact envelope content.
        envelope
            .continuation
            .validate_for(&envelope.extension)
            .map_err(|_| Error::Invalid)?;
        let request = HostManualEnrollmentContinuationRequestV2 {
            version: 2,
            enrollment: HostManualEnrollmentRequest {
                terms: envelope.extension.terms.clone(),
            },
            continuation_digest: envelope
                .continuation
                .digest_for(&envelope.extension)
                .map_err(|_| Error::Invalid)?,
        };
        request.validate().map_err(|_| Error::Invalid)?;
        let request_digest = request.digest().map_err(|_| Error::Invalid)?;
        let prepared = self.prepare_manual_continuation(
            &request,
            &key,
            &envelope.extension.enrollment_ref,
            &envelope.extension.digest().map_err(|_| Error::Invalid)?,
            purpose,
        )?;
        let inventory = match mode {
            PublicationMode::AuditOnly => None,
            PublicationMode::PreliminaryInventory => {
                Some(inventory::prepare(self, &prepared, &envelope)?)
            }
        };
        let disclosure_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-manual-tagged-continuation-disclosure:v3",
            &(
                &request,
                &envelope.extension.enrollment_ref,
                envelope.continuation.sequence,
                purpose,
                &prepared.source.original_audit,
                &prepared.review_digest,
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let request_approval=self.terminal.approve_publication(&disclosure_digest,&format!(
            "Send this exact V2 successor-attempt request for {} after fresh native reentry.\n{}\nAccount: {}\nOriginal enrollment: {}\nContinuation sequence: {}\nFull V2 request commitment: {}\nThe exact original private account/birth/policy/Host linkage and continuation commitment will be disclosed. This cannot renew the original witness admission or replay an earlier acquisition. All terminal input and approval is collected before launch. Stay in the signer window during native reentry/acquire/publication/disclosure; {}",purpose.description(),original_description(&prepared.source.original_audit),request.enrollment.terms.identity.account_id,envelope.extension.enrollment_ref,envelope.continuation.sequence,request_digest,mode.completion()))?;
        let pair_approval=self.terminal.approve_publication(&disclosure_digest,&format!(
            "Approve only the finite exact current pairing metadata send.\nAccount: {}\nAgreement: {}\nParticipant: {}\nPairing commitment is FULL CONTINUATION V2 REQUEST: {}\nNo existing constructor pairing or first-enrollment intent commitment is reinterpreted. Launch/pair/review delay never resets any Host approval.",request.enrollment.terms.identity.account_id,request.enrollment.terms.scope.agreement_id,request.enrollment.terms.scope.participant_id,request_digest))?;
        let deadline = prepared
            .source
            .history_review
            .deadline()
            .min(prepared.approval.deadline())
            .min(request_approval.deadline())
            .min(pair_approval.deadline());
        let deadline = inventory
            .as_ref()
            .map_or(deadline, |i| deadline.min(i.deadline()));
        prepared.source.check_current()?;
        prepared.approval.check()?;
        request_approval.check()?;
        pair_approval.check()?;
        if let Some(inventory) = &inventory {
            inventory.check_before(&prepared.source)?;
        }
        // No terminal prompts follow this point. All waits occur outside the
        // finite publication commit guard; only bounded sends/append are inside.
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        provider.launch_native().map_err(|_| Error::Permission)?;
        let endpoint = wait_manual_endpoint_before(&provider, deadline)?;
        prepared.source.check_current()?;
        prepared.approval.check()?;
        request_approval.check()?;
        let pending_pair = pair_approval.commit(
            &disclosure_digest,
            || prepared.source.check_current(),
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    &endpoint,
                    "wholepact-native-manual-continuation",
                    PairScope {
                        account_id: request.enrollment.terms.identity.account_id.clone(),
                        agreement_id: request.enrollment.terms.scope.agreement_id.clone(),
                        participant_id: request.enrollment.terms.scope.participant_id.clone(),
                        manifest_digest: request_digest,
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
        prepared.source.check_current()?;
        prepared.approval.check()?;
        let pending = request_approval.commit(
            &disclosure_digest,
            || prepared.source.check_current(),
            |_| {
                client
                    .begin_enrollment_continuation_v2_before(&request, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        let lease = pending.finish().map_err(|_| Error::Permission)?;
        require_continuation_export(&envelope, lease.evidence())?;
        let committed = prepared.append_audit(lease, deadline)?;
        if let Some(inventory) = inventory {
            inventory.run(self, client, &committed)?;
        }
        committed.check_current()?;
        let receipt = &committed.receipt;
        let restriction = match mode {
            PublicationMode::AuditOnly => "No financial capability was enabled.",
            PublicationMode::PreliminaryInventory => {
                "Only the separately reviewed preliminary inventory ran; no spending capability was enabled."
            }
        };
        self.terminal.message(&format!("{} retained. Operation: {}. Original enrollment: {}. Audit digest: {}. Exact replay: {}. {}\n",purpose.description(),receipt.operation_id(),receipt.enrollment_ref(),receipt.audit_digest(),receipt.replayed(),restriction))
    }
}
impl<'host> PreparedManualContinuation<'host> {
    fn require_lease(&self, lease: &ManualEnrollmentContinuationLeaseV2<'_>) -> Result<()> {
        let context = wholepact_store::CommandContext::for_request(
            &self.request.enrollment.terms.scope.principal_id,
            &self.idempotency_key,
            &serde_json::to_value(&self.request)?,
        )?;
        let current_review = publication_review_digest(
            &context,
            self.source.engine.agreement_record_digest(),
            self.source.engine.agreement_revision(),
            self.source.engine.owner_client_id(),
            self.source.purpose,
            &self.source.original_audit,
        )?;
        if lease.binding() != &self.request || current_review != self.review_digest {
            return Err(Error::Authentication);
        }
        lease.check_current().map_err(|_| Error::Permission)?;
        self.source.check_current()
    }
    fn append_audit(
        self,
        lease: ManualEnrollmentContinuationLeaseV2<'_>,
        deadline: std::time::Instant,
    ) -> Result<CommittedManualAudit<'host>> {
        self.approval.check()?;
        self.require_lease(&lease)?;
        // This independent expected commitment comes only from the actual
        // authenticated lower owner BEFORE its concrete Store consumption.
        let original_signer_intent_digest = lease.evidence().admission.signer_intent_digest.clone();
        let deadline = deadline
            .min(self.approval.deadline())
            .min(self.source.history_review.deadline());
        if std::time::Instant::now() >= deadline {
            return Err(Error::Permission);
        }
        let Self {
            source,
            approval,
            review_digest,
            idempotency_key,
            request,
        } = self;
        let receipt = approval.commit(
            &review_digest,
            || {
                if lease.binding() != &request {
                    return Err(Error::Authentication);
                }
                lease.check_current().map_err(|_| Error::Permission)?;
                source.check_current()?;
                Ok(lease)
            },
            |lease| {
                // The same owned key and exact request reviewed above enter one
                // concrete consumer. No parse error or absence can switch routes.
                let result = match select_consumer(source.purpose, &source.original_audit)? {
                    ManualAuditConsumer::InitialPublicationV2 => source
                        .host
                        .engine
                        .append_manual_enrollment_initial_publication_v2(
                            source.host.access()?,
                            &source.engine,
                            &idempotency_key,
                            lease,
                        )?,
                    ManualAuditConsumer::ContinuationV2 => source
                        .host
                        .engine
                        .append_manual_enrollment_continuation_audit(
                            source.host.access()?,
                            &source.engine,
                            &idempotency_key,
                            lease,
                        )?,
                    ManualAuditConsumer::ContinuationV3 => source
                        .host
                        .engine
                        .append_manual_enrollment_continuation_audit_v3(
                            source.host.access()?,
                            &source.engine,
                            &idempotency_key,
                            lease,
                        )?,
                };
                source.check_after_append(&result)?;
                Ok(result)
            },
        )?;
        let committed = CommittedManualAudit {
            source,
            receipt,
            original_signer_intent_digest,
            review_digest,
            request,
            deadline,
        };
        committed.check_current()?;
        Ok(committed)
    }
}
fn require_continuation_export(
    envelope: &ManualEnrollmentSessionContinuationOwnerSignature,
    evidence: &ManualEnrollmentContinuationEvidenceV2,
) -> Result<()> {
    envelope
        .continuation
        .validate_for(&envelope.extension)
        .map_err(|_| Error::Invalid)?;
    evidence.validate().map_err(|_| Error::Invalid)?;
    if envelope.version != 1
        || envelope.scheme != "ecdsa-p256-sha256-asn1-v1"
        || evidence.request.enrollment.terms != envelope.extension.terms
    {
        return Err(Error::Authentication);
    }
    let extension_digest = envelope.extension.digest().map_err(|_| Error::Invalid)?;
    let continuation_digest = envelope
        .continuation
        .digest_for(&envelope.extension)
        .map_err(|_| Error::Invalid)?;
    require_reference_projection(
        &ContinuationReferences {
            enrollment_ref: &envelope.extension.enrollment_ref,
            extension_digest: &extension_digest,
            extension_sequence: envelope.extension.sequence,
            extension_predecessor: envelope.extension.predecessor_digest.as_deref(),
            continuation_digest: &continuation_digest,
            attempt_sequence: envelope.continuation.sequence,
        },
        &ContinuationReferences {
            enrollment_ref: &evidence.enrollment_ref,
            extension_digest: &evidence.witness_extension_digest,
            extension_sequence: evidence.witness_extension_sequence,
            extension_predecessor: evidence.witness_extension_predecessor_digest.as_deref(),
            continuation_digest: &evidence.request.continuation_digest,
            attempt_sequence: evidence.admission.attempt_sequence,
        },
    )?;
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
struct ContinuationReferences<'a> {
    enrollment_ref: &'a str,
    extension_digest: &'a str,
    extension_sequence: u64,
    extension_predecessor: Option<&'a str>,
    continuation_digest: &'a str,
    attempt_sequence: u64,
}
fn require_reference_projection(
    expected: &ContinuationReferences<'_>,
    actual: &ContinuationReferences<'_>,
) -> Result<()> {
    if expected != actual {
        return Err(Error::Authentication);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_extension_and_exact_attempt_references_cannot_be_defaulted_or_substituted() {
        // Pure comparison only. No provider/native/witness/Store owner is minted.
        let original = ContinuationReferences {
            enrollment_ref: "original",
            extension_digest: "extension",
            extension_sequence: 1,
            extension_predecessor: None,
            continuation_digest: "continued",
            attempt_sequence: 2,
        };
        require_reference_projection(&original, &original).unwrap();
        for index in 0..6 {
            let mut changed = original.clone();
            match index {
                0 => changed.enrollment_ref = "different",
                1 => changed.extension_digest = "different",
                2 => changed.extension_sequence = 2,
                3 => changed.extension_predecessor = Some("different"),
                4 => changed.continuation_digest = "different",
                _ => changed.attempt_sequence = 3,
            }
            assert!(changed != original);
            assert!(require_reference_projection(&original, &changed).is_err());
        }
    }
}

#[cfg(test)]
mod initial_publication_tests {
    use super::*;
    fn v1(value: char) -> Option<OriginalManualEnrollmentAuditLink> {
        Some(OriginalManualEnrollmentAuditLink::EnrollmentV1 {
            audit_digest: value.to_string().repeat(64),
        })
    }
    fn v2(value: char) -> Option<OriginalManualEnrollmentAuditLink> {
        Some(OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
            audit_digest: value.to_string().repeat(64),
        })
    }
    #[test]
    fn explicit_initial_route_does_not_convert_missing_or_v1_originals_into_continuation() {
        // Pure dispatch data only. No native approval, Host or lease is minted.
        let initial = ManualAuditPurpose::InitialPublicationV2;
        let continuation = ManualAuditPurpose::ExistingEnrollmentContinuation;
        let roster = Some(OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 {
            audit_digest: "c".repeat(64),
        });
        assert!(require_selected_original(initial, &roster).is_err());
        assert!(require_selected_original(continuation, &roster).is_err());
        assert!(require_preparation_original(initial, &roster).is_err());
        assert!(require_selected_original(continuation, &None).is_err());
        assert!(require_preparation_original(continuation, &None).is_err());
        assert_eq!(
            select_consumer(continuation, &v1('a')).unwrap(),
            ManualAuditConsumer::ContinuationV2
        );
        assert_eq!(
            select_consumer(continuation, &v2('a')).unwrap(),
            ManualAuditConsumer::ContinuationV3
        );
        assert_eq!(
            select_consumer(initial, &None).unwrap(),
            ManualAuditConsumer::InitialPublicationV2
        );
        assert_eq!(
            select_consumer(initial, &v2('a')).unwrap(),
            ManualAuditConsumer::InitialPublicationV2
        );
        require_selected_original(initial, &None).unwrap();
        require_selected_original(initial, &v2('a')).unwrap(); // Exact first-publication retry only.
        assert!(require_selected_original(initial, &v1('a')).is_err());
        require_preparation_original(initial, &None).unwrap();
        assert!(require_preparation_original(initial, &v2('a')).is_err());
    }
    #[test]
    fn original_kind_digest_and_absence_cannot_change_before_publication() {
        let initial = ManualAuditPurpose::InitialPublicationV2;
        let continuation = ManualAuditPurpose::ExistingEnrollmentContinuation;
        require_original_unchanged(initial, &None, &None).unwrap();
        assert!(require_original_unchanged(initial, &None, &v2('a')).is_err());
        assert!(require_original_unchanged(initial, &v2('a'), &None).is_err());
        for (before, after) in [
            (v1('a'), v1('b')),
            (v1('a'), v2('a')),
            (v2('a'), v1('a')),
            (v2('a'), v2('b')),
            (v2('a'), None),
        ] {
            assert!(require_original_unchanged(continuation, &before, &after).is_err());
        }
        require_original_unchanged(continuation, &v1('a'), &v1('a')).unwrap();
        require_original_unchanged(continuation, &v2('a'), &v2('a')).unwrap();
    }
    #[test]
    fn first_publication_postcondition_accepts_only_its_exact_v2_receipt() {
        let initial = ManualAuditPurpose::InitialPublicationV2;
        let receipt = "a".repeat(64);
        require_original_after_append(initial, &None, &v2('a'), &receipt).unwrap();
        require_original_after_append(initial, &v2('a'), &v2('a'), &receipt).unwrap();
        for (before, after, digest) in [
            (None, None, receipt.clone()),
            (None, v1('a'), receipt.clone()),
            (None, v2('b'), receipt.clone()),
            (v2('b'), v2('a'), receipt.clone()),
            (v1('a'), v2('a'), receipt.clone()),
            (v2('a'), v2('a'), "b".repeat(64)),
        ] {
            assert!(require_original_after_append(initial, &before, &after, &digest).is_err());
        }
        let continuation = ManualAuditPurpose::ExistingEnrollmentContinuation;
        assert!(require_original_after_append(continuation, &None, &v2('a'), &receipt).is_err());
        assert!(require_original_after_append(continuation, &v1('a'), &v2('a'), &receipt).is_err());
        require_original_after_append(continuation, &v1('a'), &v1('a'), &"c".repeat(64)).unwrap();
        require_original_after_append(continuation, &v2('a'), &v2('a'), &"c".repeat(64)).unwrap();
    }
    #[test]
    fn native_publication_review_binds_exact_key_request_target_purpose_and_original_tag() {
        let purpose = ManualAuditPurpose::ExistingEnrollmentContinuation;
        let original = v1('a');
        let context = wholepact_store::CommandContext::for_request(
            "owner",
            "original-key",
            &serde_json::json!({"attempt":"synthetic"}),
        )
        .unwrap();
        let digest =
            publication_review_digest(&context, &"b".repeat(64), 1, "owner", purpose, &original)
                .unwrap();
        for field in 0..7 {
            let mut changed = context.clone();
            let mut agreement = "b".repeat(64);
            let mut revision = 1;
            let mut owner = "owner";
            let mut original = original.clone();
            match field {
                0 => changed.principal_id = "other-owner".into(),
                1 => changed.idempotency_key = "different-key".into(),
                2 => changed.request_digest = "c".repeat(64),
                3 => agreement = "c".repeat(64),
                4 => revision = 2,
                5 => owner = "different-owner",
                _ => original = v1('c'),
            }
            assert_ne!(
                digest,
                publication_review_digest(
                    &changed, &agreement, revision, owner, purpose, &original
                )
                .unwrap()
            );
        }
        assert_ne!(
            digest,
            publication_review_digest(&context, &"b".repeat(64), 1, "owner", purpose, &v2('a'))
                .unwrap()
        );
        let initial = ManualAuditPurpose::InitialPublicationV2;
        let absent =
            publication_review_digest(&context, &"b".repeat(64), 1, "owner", initial, &None)
                .unwrap();
        let retry =
            publication_review_digest(&context, &"b".repeat(64), 1, "owner", initial, &v2('a'))
                .unwrap();
        assert_ne!(absent, retry);
        assert_ne!(
            retry,
            publication_review_digest(&context, &"b".repeat(64), 1, "owner", purpose, &v2('a'))
                .unwrap()
        );
        assert!(
            publication_review_digest(&context, &"b".repeat(64), 1, "owner", purpose, &None)
                .is_err()
        );
        assert!(
            publication_review_digest(&context, &"b".repeat(64), 1, "owner", initial, &v1('a'))
                .is_err()
        );
    }
    #[test]
    fn denied_native_publication_owner_cannot_enter_first_publication_or_continuation() {
        for purpose in [
            ManualAuditPurpose::InitialPublicationV2,
            ManualAuditPurpose::ExistingEnrollmentContinuation,
        ] {
            let original = if purpose == ManualAuditPurpose::InitialPublicationV2 {
                None
            } else {
                v2('a')
            };
            let context = wholepact_store::CommandContext::for_request(
                "owner",
                "original-key",
                &serde_json::json!({}),
            )
            .unwrap();
            let digest = publication_review_digest(
                &context,
                &"b".repeat(64),
                1,
                "owner",
                purpose,
                &original,
            )
            .unwrap();
            for expired in [false, true] {
                // Existing regular-file/expired negative owner cannot satisfy
                // native foreground; this never constructs a usable approval.
                let approval = PublicationApproval::denied_for_test(&digest, expired);
                let entered = std::cell::Cell::new(false);
                let effect = std::cell::Cell::new(false);
                assert!(
                    approval
                        .commit(
                            &digest,
                            || {
                                entered.set(true);
                                Ok(())
                            },
                            |_| {
                                effect.set(true);
                                Ok(())
                            }
                        )
                        .is_err()
                );
                assert!(!entered.get());
                assert!(!effect.get());
            }
        }
    }
}
