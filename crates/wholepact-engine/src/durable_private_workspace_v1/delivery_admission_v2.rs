//! Original-source, admission-only private delivery. There is deliberately no
//! conversion back to the precursor, generic Engine, raw Store or private bytes.
//! The immutable fixed prefix and the append-only export history are distinct.
use super::*;
use crate::durable_construction_v1::{
    original_roster_v2,
    review_export_v1::{
        self, DurableReviewExportScopeV1, ExportExposure, ExportIntent,
        LocalDurableReviewExportConsentV1, MAX_EXPORT_INTENTS,
    },
    DurableMaterialActionV1, LocalDurableMaterialConsentV1,
};
use crate::Envelope;
use sha2::{Digest, Sha256};
use wholepact_proof_jobs::{
    CheckpointScope, JobSummary, LocalAction, LocalProofConsent, VerifiedCheckpoint,
};
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
use wholepact_signer::authority_bridge::{
    durable_review_ipc_v1::{
        DurableReviewOutputActionV1, DurableReviewPayloadV1, PreparedDurableReviewDeliveryV1,
        PreparedDurableReviewPayloadV2,
    },
    BridgeError,
};
use wholepact_store::{CommandContext, MutationResult};

mod closed_review_v3;
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use closed_review_v3::{ClosedCoordinatedPrivateDurableAdmissionReviewV1, CoordinatedPrivateDurableAdmissionStatusV1};
fn is_coordinated_export_event_v1(kind: &str) -> bool {
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    { kind == closed_review_v3::COORDINATED_EXPORT_EVENT_V1 }
    #[cfg(not(feature = "coordinated-financial-workflow-v1"))]
    { let _ = kind; false }
}
fn audit_coordinated_export_v1(before: &Envelope, after: &Envelope, access: &Access) -> Result<(String, String, CommandContext)> {
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    {
        let scope = closed_review_v3::validate_coordinated_export_delta_v1(before, after)?;
        let command = closed_review_v3::coordinated_export_command_v1(access, before.view.revision, &scope)?;
        Ok((scope.principal_id, scope.recipient.request.operation_id, command))
    }
    #[cfg(not(feature = "coordinated-financial-workflow-v1"))]
    { let _ = (before, after, access); Err(damaged()) }
}
pub(super) mod financial_v1;
pub(super) mod financial_v2;
pub use closed_review_v3::{
    ClosedPrivateDurableAdmissionReviewV3, PreparedPrivateDurableAdmissionDeliveryV3,
    PrivateDurableAdmissionDeliveryV3, PrivateDurableAdmissionStatusV3,
};

const EXPORT_CAUSE_KEY: &str = "private_durable_delivery_cause_v2";
const EXPORT_CAUSE_COLLISION_KEY: &str = "private_durable_delivery_cause_collision_v2";

// These labels are inert diagnostic vocabulary, not authority or caller input.
macro_rules! cause_labels {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum $name { $($variant),+ }
        impl $name {
            #[cfg(test)]
            const ALL: &'static [Self] = &[$(Self::$variant),+];
            fn label(self) -> &'static str {
                match self { $(Self::$variant => stringify!($variant)),+ }
            }
            fn from_label(label: &str) -> Option<Self> {
                match label { $(stringify!($variant) => Some(Self::$variant)),+, _ => None }
            }
        }
    };
}
cause_labels! { ExportCauseSite {
    ExportProofCurrent, ExportProofOrigin, ExportSourceBefore, ExportSourceAfter,
    ExportMetadataOrigin, ExportMarker, ExportHistory, ExportMaterialCeilings,
    ExportIntake, ExportVerifiedProof, ExportRoster, ExportPayload,
    ExportOutputActions, ExportRecipientBinding, ExportSources,
    ExportCheckpointScope, ExportProofPermission, ExportPermission,
    ExportReplayScope, ExportCommand, ExportReplayLookup, ExportDelta, ExportEntry,
    RecipientMutex, RecipientDeadline, RecipientOrigin, RecipientObserverClone,
    RecipientWriteSerialize, RecipientWriteLimit, RecipientWriteDeadline,
    RecipientWriteTimeout, RecipientWriteIo, RecipientWriteEmpty, RecipientFrame,
    RecipientResponseDecode, RecipientResponseDigest, RecipientResponse,
} }
cause_labels! { ExportCauseOutcome {
    PredicateDenied, EngineDisclosureUnknown, EngineDisclosureDenied,
    EngineRecoveryRequired, EngineIdempotencyConflict, EngineRevisionConflict,
    EngineDurableProposalConflict, EngineDurableConstructionUnavailable,
    EngineDurableProfileUnavailable, EngineResourceExhausted, EngineUnclassified,
    BridgeBinding, BridgeConflict, BridgeMissing, BridgeUncertain, BridgeLimit,
    BridgePermission, BridgeRecoveryRequired, BridgeCompleteOriginRecoveryUnavailable,
    BridgeVerification, BridgeSignerOriginUnavailable, BridgeJournal, BridgeAuthority,
    BridgeWallet, BridgeIpc, OriginPermanentStopUnavailable,
    OriginRetirementEvidenceUnavailable, OriginSignerOriginUnavailable,
    OriginPeerLifetimeUnavailable, OriginAuthentication, OriginBinding,
    OriginConflict, OriginPermission, OriginInvalidData, OriginLocked, OriginCrypto,
    OriginIpc, OriginLimit, OriginIoTimedOut, OriginIoWouldBlock,
    OriginIoUnexpectedEof, OriginIoBrokenPipe, OriginIoConnectionReset,
    OriginIoConnectionAborted, OriginIoNotConnected, OriginIoInterrupted,
    OriginIoPermissionDenied, OriginIoOther,
} }
impl ExportCauseOutcome {
    fn engine(error: &ApiError) -> Self {
        match error.code.as_str() {
            "DISCLOSURE_UNKNOWN" => Self::EngineDisclosureUnknown,
            "DISCLOSURE_DENIED" => Self::EngineDisclosureDenied,
            "RECOVERY_REQUIRED" | "DURABLE_PROPOSAL_RECOVERY_REQUIRED" => {
                Self::EngineRecoveryRequired
            }
            "IDEMPOTENCY_CONFLICT" => Self::EngineIdempotencyConflict,
            "REVISION_CONFLICT" => Self::EngineRevisionConflict,
            "DURABLE_PROPOSAL_CONFLICT" => Self::EngineDurableProposalConflict,
            "DURABLE_CONSTRUCTION_UNAVAILABLE" => Self::EngineDurableConstructionUnavailable,
            "DURABLE_PROFILE_UNAVAILABLE" => Self::EngineDurableProfileUnavailable,
            "RESOURCE_EXHAUSTED" => Self::EngineResourceExhausted,
            _ => Self::EngineUnclassified,
        }
    }
    fn is_bridge(self) -> bool {
        matches!(
            self,
            Self::BridgeBinding
                | Self::BridgeConflict
                | Self::BridgeMissing
                | Self::BridgeUncertain
                | Self::BridgeLimit
                | Self::BridgePermission
                | Self::BridgeRecoveryRequired
                | Self::BridgeCompleteOriginRecoveryUnavailable
                | Self::BridgeVerification
                | Self::BridgeSignerOriginUnavailable
                | Self::BridgeJournal
                | Self::BridgeAuthority
                | Self::BridgeWallet
                | Self::BridgeIpc
        )
    }
    fn is_origin_io(self) -> bool {
        matches!(
            self,
            Self::OriginIoTimedOut
                | Self::OriginIoWouldBlock
                | Self::OriginIoUnexpectedEof
                | Self::OriginIoBrokenPipe
                | Self::OriginIoConnectionReset
                | Self::OriginIoConnectionAborted
                | Self::OriginIoNotConnected
                | Self::OriginIoInterrupted
                | Self::OriginIoPermissionDenied
                | Self::OriginIoOther
        )
    }
    fn is_origin(self) -> bool {
        self.is_origin_io()
            || matches!(
                self,
                Self::OriginPermanentStopUnavailable
                    | Self::OriginRetirementEvidenceUnavailable
                    | Self::OriginSignerOriginUnavailable
                    | Self::OriginPeerLifetimeUnavailable
                    | Self::OriginAuthentication
                    | Self::OriginBinding
                    | Self::OriginConflict
                    | Self::OriginPermission
                    | Self::OriginInvalidData
                    | Self::OriginLocked
                    | Self::OriginCrypto
                    | Self::OriginIpc
                    | Self::OriginLimit
            )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FirstExportCause {
    Vacant,
    // Failure was observed but its evidence was unavailable. A later wrapper
    // must not impersonate that first failure.
    Unavailable,
    Seen(ExportCauseSite, ExportCauseOutcome),
}
struct ExportCause {
    first: std::cell::Cell<FirstExportCause>,
    active: std::cell::Cell<bool>,
}
impl ExportCause {
    fn new() -> Self {
        Self {
            first: std::cell::Cell::new(FirstExportCause::Vacant),
            active: std::cell::Cell::new(true),
        }
    }
    fn record(&self, cause: FirstExportCause) {
        if self.active.get() && self.first.get() == FirstExportCause::Vacant {
            self.first.set(cause);
        }
    }
    fn freeze(&self) {
        self.active.set(false);
    }
    fn attach<T>(&self, result: Result<T>) -> Result<T> {
        result.map_err(|mut error| {
            let Some(details) = error.details.as_object_mut() else {
                return error;
            };
            // An inherited valid-looking sidecar is not evidence from this
            // invocation. Preserve it exactly and add only a deny marker. The
            // Host rejects ANY marker presence, including pre-existing values.
            // This precedes the Vacant/Unavailable/frozen paths deliberately.
            if details.contains_key(EXPORT_CAUSE_KEY) {
                details
                    .entry(EXPORT_CAUSE_COLLISION_KEY)
                    .or_insert(serde_json::Value::Bool(true));
                return error;
            }
            if details.contains_key(EXPORT_CAUSE_COLLISION_KEY) {
                return error;
            }
            if let FirstExportCause::Seen(site, outcome) = self.first.get() {
                details.insert(
                    EXPORT_CAUSE_KEY.into(),
                    serde_json::json!({
                        "version": 1, "site": site.label(), "outcome": outcome.label(),
                    }),
                );
            }
            error
        })
    }
}
type ExportObservation<'a> = Option<&'a ExportCause>;

// Consume and return the same owned result. In particular, observe failures
// before ProofGate's existing conversion to bool can erase their actual cause.
fn export_result<T>(
    cause: ExportObservation<'_>,
    site: ExportCauseSite,
    result: Result<T>,
) -> Result<T> {
    if let (Some(cause), Err(error)) = (cause, &result) {
        cause.record(FirstExportCause::Seen(
            site,
            ExportCauseOutcome::engine(error),
        ));
    }
    result
}
fn export_predicate(cause: ExportObservation<'_>, site: ExportCauseSite, permitted: bool) -> bool {
    if !permitted {
        if let Some(cause) = cause {
            cause.record(FirstExportCause::Seen(
                site,
                ExportCauseOutcome::PredicateDenied,
            ));
        }
    }
    permitted
}
fn export_predicate_error<T>(
    cause: ExportObservation<'_>,
    site: ExportCauseSite,
    error: ApiError,
) -> Result<T> {
    export_predicate(cause, site, false);
    Err(error)
}
fn recipient_cause(site: &str, outcome: &str) -> Option<FirstExportCause> {
    use ExportCauseOutcome as O;
    use ExportCauseSite as S;
    let site = S::from_label(site)?;
    let outcome = O::from_label(outcome)?;
    let valid = match site {
        S::RecipientMutex | S::RecipientWriteEmpty => outcome == O::BridgeIpc,
        S::RecipientDeadline | S::RecipientWriteDeadline | S::RecipientResponse => {
            outcome == O::BridgePermission
        }
        S::RecipientOrigin => outcome.is_bridge(),
        S::RecipientObserverClone | S::RecipientWriteTimeout | S::RecipientWriteIo => {
            outcome.is_origin_io()
        }
        S::RecipientWriteSerialize | S::RecipientResponseDecode | S::RecipientResponseDigest => {
            outcome == O::BridgeBinding
        }
        S::RecipientWriteLimit => outcome == O::BridgeLimit,
        S::RecipientFrame => outcome.is_origin(),
        _ => false,
    };
    valid.then_some(FirstExportCause::Seen(site, outcome))
}
fn recipient_result<T>(
    cause: &ExportCause,
    result: std::result::Result<T, BridgeError>,
    diagnostic: Option<FirstExportCause>,
) -> std::result::Result<T, BridgeError> {
    if result.is_err() {
        cause.record(diagnostic.unwrap_or(FirstExportCause::Unavailable));
    }
    result
}
fn check_recipient(
    recipient: &PreparedDurableReviewDeliveryV1<'_>,
    cause: ExportObservation<'_>,
) -> Result<()> {
    let result = if let Some(cause) = cause.filter(|cause| cause.active.get()) {
        let (result, diagnostic) = recipient.check_current_observed_v2();
        recipient_result(
            cause,
            result,
            diagnostic.and_then(|d| recipient_cause(d.site_label(), d.outcome_label())),
        )
    } else {
        recipient.check_current()
    };
    result.map_err(|_| denied())
}

fn proof_permission(
    cause: ExportObservation<'_>,
    mut check: impl FnMut() -> Result<()>,
    permits: impl FnOnce() -> bool,
) -> bool {
    export_result(cause, ExportCauseSite::ExportProofPermission, check()).is_ok()
        && export_predicate(cause, ExportCauseSite::ExportProofPermission, permits())
        && export_result(cause, ExportCauseSite::ExportProofPermission, check()).is_ok()
}
fn delivery_permission(
    cause: ExportObservation<'_>,
    proof: impl FnOnce() -> bool,
    export: impl FnOnce() -> bool,
) -> bool {
    export_predicate(cause, ExportCauseSite::ExportProofPermission, proof())
        && export_predicate(cause, ExportCauseSite::ExportPermission, export())
}
fn replay_scope_matches(
    cause: ExportObservation<'_>,
    retained: &DurableReviewExportScopeV1,
    expected: &DurableReviewExportScopeV1,
) -> bool {
    export_predicate(
        cause,
        ExportCauseSite::ExportReplayScope,
        retained == expected,
    )
}

const PREFIX_EVENTS: usize = 8;
const EXPORT_EVENT: &str = "private_durable_admission_review_disclosed_v2";
const EXPORT_COMMAND: &str = "private_durable_admission_review_export_v2";
const PREFIX_KINDS: [&str; PREFIX_EVENTS] = [
    "agreement.created",
    "private_exact_candidate_prepared_v2",
    "private_exact_material_retained_v2",
    "private_exact_material_retained_v2",
    "private_original_constructor_recorded_v2",
    "private_original_checkpoint_linked_v2",
    "private_original_proof_observed_v2",
    "private_verified_fixed_frozen_v2",
];

/// Distinct live original-source inspection permission. This is not old fixed
/// stage consent, financial admission, material export or proof-read permission.
/// The trusted Host must retain its genuine native/source owner for every call.
pub trait LocalPrivateDurableAdmissionConsentV2 {
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool;
    /// Denial-only zero-wait observer, not source/consent re-entry. The legacy
    /// default adds no restriction; coordinated Host implementations override.
    fn check_final_effect_restriction_v1(&self, _original_deadline: Option<std::time::Instant>) -> bool { true }
}
struct AdmissionCommitRestrictionV3<'a>(&'a dyn LocalPrivateDurableAdmissionConsentV2, std::time::Instant);
impl wholepact_store::OriginalCommitRestrictionV3 for AdmissionCommitRestrictionV3<'_> {
    fn check_before_commit(&self) -> wholepact_store::Result<()> {
        if self.0.check_final_effect_restriction_v1(Some(self.1)) { Ok(()) }
        else { Err(wholepact_store::StoreError::InvalidInput("original effect restriction denied")) }
    }
}

/// Exclusive same-original owner. No Clone, serde, Deref or caller-data factory.
pub struct PrivateDurableAdmissionCoordinatorV2<'source> {
    original: PrivateDurableCoordinatorV1<'source>,
    // Exact authenticated original request contexts, never authority or keys.
    prefix_commands: BTreeMap<String, CommandContext>,
    seed_command: CommandContext,
}

/// Inert exact inspection metadata. No private artifact/outbox or capability.
#[derive(Serialize)]
pub struct PrivateDurableAdmissionInspectionV2 {
    workspace_scope: PrivateWorkspaceScopeV1,
    materials: Vec<PrivateFixedMaterialReviewV3>,
    checkpoint_scope: CheckpointScope,
    fixed_identity: FixedProposalIdentityV1,
    marker_digest: String,
    native_association_digest: String,
    metadata_origin: String,
    proof_origin: String,
    revision: u64,
    export_count: usize,
}
impl PrivateDurableAdmissionInspectionV2 {
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
    pub fn marker_digest(&self) -> &str {
        &self.marker_digest
    }
    pub fn native_association_digest(&self) -> &str {
        &self.native_association_digest
    }
    pub fn metadata_origin(&self) -> &str {
        &self.metadata_origin
    }
    pub fn proof_origin(&self) -> &str {
        &self.proof_origin
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn export_count(&self) -> usize {
        self.export_count
    }
}
#[derive(Serialize)]
pub struct PrivateDurableAdmissionStatusV2 {
    /// Calculated from actual saved event eight, never current state with its
    /// exports erased. This remains byte-identical to the completed precursor.
    pub fixed: PrivateVerifiedFixedV2,
    pub export_history_digest: String,
    pub export_count: usize,
    pub revision: u64,
}
#[derive(Serialize)]
pub struct PrivateDurableAdmissionDeliveryV2 {
    pub revision: u64,
    pub replayed: bool,
    pub export_count: usize,
    pub export_history_digest: String,
}
/// One local immutable preparation, borrowing the actual original coordinator.
/// This owns private bytes but grants no disclosure permission. No Clone, serde,
/// Debug, raw-byte getter, caller-data constructor or reusable authority exists.
pub struct PreparedPrivateDurableAdmissionDeliveryV2<'owner, 'source> {
    owner: &'owner PrivateDurableAdmissionCoordinatorV2<'source>,
    payload: PreparedDurableReviewPayloadV2,
    source: OriginalDeliverySourceBindingV2,
    proof: OriginalDeliveryProofBindingV2,
}

/// Consuming join of those exact prepared bytes and one actual sealed recipient.
/// The only public projection is inert review metadata, never a send permission.
pub struct BoundPrivateDurableAdmissionDeliveryV2<'owner, 'source, 'recipient> {
    prepared: PreparedPrivateDurableAdmissionDeliveryV2<'owner, 'source>,
    recipient: PreparedDurableReviewDeliveryV1<'recipient>,
    scope: DurableReviewExportScopeV1,
}

// Exact private comparison records. These contain commitments and metadata, not
// capabilities; only the original coordinator can populate production records.
#[derive(PartialEq, Eq)]
struct OriginalDeliverySourceBindingV2 {
    principal_id: String,
    workspace: serde_json::Value,
    metadata_origin: [u8; 32],
    proof_origin: [u8; 32],
    marker_digest: String,
    native_association_digest: String,
    prefix_history_digest: String,
    full_history_digest: String,
    materials: serde_json::Value,
    sources: Vec<review_export_v1::DurableReviewSourceV1>,
}
#[derive(PartialEq, Eq)]
struct OriginalDeliveryProofBindingV2 {
    original_request_key: String,
    identity: FixedProposalIdentityV1,
    summary: JobSummary,
    scope: CheckpointScope,
    unsigned_digest: [u8; 32],
    proved_digest: [u8; 32],
    output_actions: Vec<DurableReviewOutputActionV1>,
}
fn require_prepared_binding<T: PartialEq>(
    expected: &T,
    actual: &T,
    cause: ExportObservation<'_>,
    site: ExportCauseSite,
) -> Result<()> {
    if expected != actual {
        return export_predicate_error(cause, site, denied());
    }
    Ok(())
}
impl<'owner, 'source> PreparedPrivateDurableAdmissionDeliveryV2<'owner, 'source> {
    /// Consume the local preparation and bind only the real current recipient.
    /// Current local read approval must be supplied anew; preparation approval
    /// is neither retained nor reused as present inspection/export permission.
    pub fn bind_current_v2<'recipient>(
        self,
        access: &Access,
        recipient: PreparedDurableReviewDeliveryV1<'recipient>,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<BoundPrivateDurableAdmissionDeliveryV2<'owner, 'source, 'recipient>> {
        self.bind_observed(
            access,
            recipient,
            consent,
            proof,
            material,
            DurableMaterialActionV1::ReadForExactConstruction,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn bind_observed<'recipient>(
        self,
        access: &Access,
        recipient: PreparedDurableReviewDeliveryV1<'recipient>,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        action: DurableMaterialActionV1,
        cause: ExportObservation<'_>,
    ) -> Result<BoundPrivateDurableAdmissionDeliveryV2<'owner, 'source, 'recipient>> {
        let gate = ProofGate {
            owner: self.owner,
            access,
            consent,
            proof,
            material,
            action,
            cause,
        };
        let scope = self.review_scope(access, &recipient, &gate)?;
        Ok(BoundPrivateDurableAdmissionDeliveryV2 {
            prepared: self,
            recipient,
            scope,
        })
    }
    fn review_scope(
        &self,
        access: &Access,
        recipient: &PreparedDurableReviewDeliveryV1<'_>,
        gate: &ProofGate<'_, '_>,
    ) -> Result<DurableReviewExportScopeV1> {
        use ExportCauseSite as S;
        let cause = gate.cause;
        check_recipient(recipient, cause)?;
        gate.check()?;
        let (current, history) = self.owner.check_observed(access, gate.consent, cause)?;
        if (!original_roster_v2(&current)?.review_exports_v3.is_empty() || original_roster_v2(&current)?.coordinated_exports_present()) {
            return Err(denied());
        }
        let source = self
            .owner
            .delivery_source_binding(access, &history, cause)?;
        require_prepared_binding(&self.source, &source, cause, S::ExportSources)?;
        let scope = DurableReviewExportScopeV1 {
            schema_version: 1,
            principal_id: source.principal_id,
            proposal: self.proof.identity.clone(),
            recipient: recipient.descriptor().clone(),
            sources: source.sources,
            payload_digest: self.payload.payload_digest().into(),
            payload_length: self.payload.payload_bytes(),
        };
        let roster = export_result(cause, S::ExportRoster, original_roster_v2(&history.prefix))?;
        export_result(
            cause,
            S::ExportRecipientBinding,
            review_export_v1::validate_recipient(
                &roster,
                &history.prefix.view.candidates[0],
                &scope,
            ),
        )?;
        gate.check()?;
        let (_, after) = self.owner.check_observed(access, gate.consent, cause)?;
        require_prepared_binding(
            &self.source.full_history_digest,
            &after.full_digest,
            cause,
            S::ExportHistory,
        )?;
        check_recipient(recipient, cause)?;
        Ok(scope)
    }
}
impl BoundPrivateDurableAdmissionDeliveryV2<'_, '_, '_> {
    pub fn scope(&self) -> &DurableReviewExportScopeV1 {
        &self.scope
    }

    /// Check the same owned sealed recipient without exposing or cloning it.
    /// Host keeps its original before/after foreground-review checks here.
    pub fn check_current_v2(&self) -> std::result::Result<(), BridgeError> {
        self.recipient.check_current()
    }

    /// Consume before any fallible final check. The final original verified proof
    /// is comparison evidence only; it never regenerates the transport payload.
    pub fn deliver_v2(
        self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        export: &dyn LocalDurableReviewExportConsentV1,
    ) -> Result<PrivateDurableAdmissionDeliveryV2> {
        let cause = ExportCause::new();
        let result = export_result(
            Some(&cause),
            ExportCauseSite::ExportEntry,
            self.deliver_observed(access, consent, proof, material, export, &cause),
        );
        cause.attach(result)
    }
    #[allow(clippy::too_many_arguments)]
    fn deliver_observed(
        self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        export: &dyn LocalDurableReviewExportConsentV1,
        cause: &ExportCause,
    ) -> Result<PrivateDurableAdmissionDeliveryV2> {
        let Self {
            prepared,
            recipient,
            scope,
        } = self;
        let owner = prepared.owner;
        owner.deliver_prepared_observed(
            access, prepared, recipient, scope, consent, proof, material, export, cause,
        )
    }
}

struct History {
    prefix: Envelope,
    prefix_digest: String,
    full_digest: String,
    export_revisions: BTreeMap<String, u64>,
    rows: Vec<(
        wholepact_store::StoredEvent,
        wholepact_store::StoredOperation,
    )>,
}

impl<'source> PrivateDurableAdmissionCoordinatorV2<'source> {
    /// Read-only exact initialized source preflight, not an authority opener.
    /// Only the concrete combined-v4 Host publication/open path may use this.
    pub fn check_initialized_admission_original_v2(
        destination: &Path,
        key: &DatabaseKey,
        expected: [u8; 32],
    ) -> Result<()> {
        preflight_original_metadata_profile_v2(
            destination,
            key,
            expected,
            None,
            OriginalMetadataProfileV2::Admission,
        )?;
        original_commands(destination, key, expected)?;
        Ok(())
    }

    /// Only actual source owners and original anchored initialization evidence
    /// can open this profile. It never initializes or repairs metadata/proof.
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
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
    ) -> Result<Self> {
        crate::private_workspace_origin_v1::validate_association_digest(native_association_digest)?;
        let scope = scope(&source, destination, retention_policy)?;
        check_source(&source, access, &scope, consent)?;
        let observation = Observation::new(Operation::OpenOriginal);
        preflight_original_metadata_profile_v2(
            destination,
            key,
            expected_origin,
            Some(&observation),
            OriginalMetadataProfileV2::Admission,
        )?;
        let prefix_commands = original_commands(destination, key, expected_origin)?;
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
            OriginalMetadataProfileV2::Admission,
        )?;
        original.audit_original_seed_v1(access, plan, binding)?;
        let result = Self {
            original,
            prefix_commands,
            seed_command: binding.command.clone(),
        };
        result.check(access, consent)?;
        Ok(result)
    }
    pub fn workspace_scope(&self) -> &PrivateWorkspaceScopeV1 {
        &self.original.scope
    }
    pub fn original_origin(&self) -> [u8; 32] {
        self.original.origin
    }
    pub fn origin_marker_digest(&self) -> Result<String> {
        self.original.origin_marker_digest()
    }

    pub fn inspect_original_for_admission_v2(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
    ) -> Result<PrivateDurableAdmissionInspectionV2> {
        let (current, history) = self.check(access, consent)?;
        let candidate = history.prefix.view.candidates.first().ok_or_else(damaged)?;
        let materials =
            self.original
                .stage_materials_v3(access, &current, &candidate.candidate_id)?;
        let receipt = history
            .prefix
            .checkpoint_receipts
            .values()
            .next()
            .ok_or_else(damaged)?;
        let checkpoint_scope =
            exact_fixed_v2::retained_review_scope_v3(candidate, receipt, &materials)?;
        let fixed_identity: FixedProposalIdentityV1 = serde_json::from_value(
            history
                .prefix
                .durable_proposals_v1
                .get(&candidate.candidate_id)
                .and_then(|v| v.get("identity"))
                .cloned()
                .ok_or_else(damaged)?,
        )
        .map_err(|_| damaged())?;
        let result = PrivateDurableAdmissionInspectionV2 {
            workspace_scope: self.original.scope.clone(),
            materials,
            checkpoint_scope,
            fixed_identity,
            marker_digest: self.origin_marker_digest()?,
            native_association_digest: self.original.marker.native_association_digest.clone(),
            metadata_origin: hex::encode(self.original.origin),
            proof_origin: hex::encode(self.original.proof_origin),
            revision: current.view.revision,
            export_count: history.export_revisions.len(),
        };
        if serde_json::to_vec(&result).map_err(|_| damaged())?.len() > 64 * 1024 {
            return Err(denied());
        }
        let (_, after) = self.check(access, consent)?;
        if after.full_digest != history.full_digest {
            return Err(damaged());
        }
        Ok(result)
    }

    pub fn read_original_fixed_v2(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PrivateDurableAdmissionStatusV2> {
        let (current, history) = self.check(access, consent)?;
        let gate = ProofGate {
            owner: self,
            access,
            consent,
            proof,
            material,
            action: DurableMaterialActionV1::ReadForExactConstruction,
            cause: None,
        };
        gate.check()?;
        let (checkpoint, key, identity) = self.verified(&history, access, &gate)?;
        let observation = Observation::new(Operation::ReadFixed);
        let fixed = self.original.verified_output_from_audited_prefix_v2(
            &history.prefix,
            access,
            &key,
            &checkpoint,
            &identity,
            &gate,
            &observation,
            history.prefix_digest.clone(),
        )?;
        gate.check()?;
        let (_, after) = self.check(access, consent)?;
        if after.full_digest != history.full_digest {
            return Err(damaged());
        }
        Ok(PrivateDurableAdmissionStatusV2 {
            fixed,
            export_history_digest: history.full_digest,
            export_count: history.export_revisions.len(),
            revision: current.view.revision,
        })
    }

    /// Prepare and encode exactly once before a genuinely new native recipient
    /// exists. This is local private reading/custody, not disclosure permission.
    pub fn prepare_original_delivery_v2(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PreparedPrivateDurableAdmissionDeliveryV2<'_, 'source>> {
        self.prepare_original_delivery_observed(
            access,
            consent,
            proof,
            material,
            DurableMaterialActionV1::ReadForExactConstruction,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_original_delivery_observed(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        action: DurableMaterialActionV1,
        cause: ExportObservation<'_>,
    ) -> Result<PreparedPrivateDurableAdmissionDeliveryV2<'_, 'source>> {
        use ExportCauseSite as S;
        let (_, history) = self.check_observed(access, consent, cause)?;
        let gate = ProofGate {
            owner: self,
            access,
            consent,
            proof,
            material,
            action,
            cause,
        };
        gate.check()?;
        let (checkpoint, key, identity) = self.verified(&history, access, &gate)?;
        let output_actions = self.delivery_output_actions(access, &history, &checkpoint, cause)?;
        let source = self.delivery_source_binding(access, &history, cause)?;
        let proof = delivery_proof_binding(&checkpoint, key, identity, output_actions);
        let roster = export_result(cause, S::ExportRoster, original_roster_v2(&history.prefix))?;
        // This is the sole construction and encoding of the prepared transport
        // payload. The opaque Bridge owner retains that exact allocation.
        let payload = export_result(
            cause,
            S::ExportPayload,
            DurableReviewPayloadV1 {
                version: 1,
                unsigned_pczt_hex: hex::encode(checkpoint.private_unsigned_pczt_bytes()),
                proved_pczt_hex: hex::encode(checkpoint.pczt_bytes()),
                contributions: roster.owners.values().map(|i| i.outbox.clone()).collect(),
                output_actions: proof.output_actions.clone(),
            }
            .into_prepared_v2()
            .map_err(|_| damaged()),
        )?;
        gate.check()?;
        let (_, after) = self.check_observed(access, consent, cause)?;
        require_prepared_binding(
            &source.full_history_digest,
            &after.full_digest,
            cause,
            S::ExportHistory,
        )?;
        Ok(PreparedPrivateDurableAdmissionDeliveryV2 {
            owner: self,
            payload,
            source,
            proof,
        })
    }

    /// Compatibility preview for an already live recipient. New Host paths use
    /// the consuming preparation before opening the genuine recipient instead.
    pub fn review_original_delivery_v2(
        &self,
        access: &Access,
        recipient: &PreparedDurableReviewDeliveryV1<'_>,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<DurableReviewExportScopeV1> {
        recipient.check_current().map_err(|_| denied())?;
        let prepared = self.prepare_original_delivery_observed(
            access,
            consent,
            proof,
            material,
            DurableMaterialActionV1::ExportForLocalNativeReview,
            None,
        )?;
        let gate = ProofGate {
            owner: self,
            access,
            consent,
            proof,
            material,
            action: DurableMaterialActionV1::ExportForLocalNativeReview,
            cause: None,
        };
        prepared.review_scope(access, recipient, &gate)
    }

    /// Commit permanent DisclosedOrUnknown before invoking the only sealed
    /// private-byte transport. Retry identity and request revision are derived
    /// from actual retained history, never selected or renewed by the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn deliver_original_for_admission_v2(
        &self,
        access: &Access,
        recipient: PreparedDurableReviewDeliveryV1<'_>,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        export: &dyn LocalDurableReviewExportConsentV1,
    ) -> Result<PrivateDurableAdmissionDeliveryV2> {
        let cause = ExportCause::new();
        let result = export_result(
            Some(&cause),
            ExportCauseSite::ExportEntry,
            self.deliver_observed(access, recipient, consent, proof, material, export, &cause),
        );
        cause.attach(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn deliver_observed(
        &self,
        access: &Access,
        recipient: PreparedDurableReviewDeliveryV1<'_>,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        export: &dyn LocalDurableReviewExportConsentV1,
        observation: &ExportCause,
    ) -> Result<PrivateDurableAdmissionDeliveryV2> {
        check_recipient(&recipient, Some(observation))?;
        self.prepare_original_delivery_observed(
            access,
            consent,
            proof,
            material,
            DurableMaterialActionV1::ExportForLocalNativeReview,
            Some(observation),
        )?
        .bind_observed(
            access,
            recipient,
            consent,
            proof,
            material,
            DurableMaterialActionV1::ExportForLocalNativeReview,
            Some(observation),
        )?
        .deliver_observed(access, consent, proof, material, export, observation)
    }

    #[allow(clippy::too_many_arguments)]
    fn deliver_prepared_observed(
        &self,
        access: &Access,
        prepared: PreparedPrivateDurableAdmissionDeliveryV2<'_, 'source>,
        recipient: PreparedDurableReviewDeliveryV1<'_>,
        scope: DurableReviewExportScopeV1,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        export: &dyn LocalDurableReviewExportConsentV1,
        observation: &ExportCause,
    ) -> Result<PrivateDurableAdmissionDeliveryV2> {
        use ExportCauseSite as S;
        let cause = Some(observation);
        let PreparedPrivateDurableAdmissionDeliveryV2 {
            payload,
            source,
            proof: prepared_proof,
            ..
        } = prepared;
        check_recipient(&recipient, cause)?;
        let (_, history) = self.check_observed(access, consent, cause)?;
        let gate = ProofGate {
            owner: self,
            access,
            consent,
            proof,
            material,
            action: DurableMaterialActionV1::ExportForLocalNativeReview,
            cause,
        };
        gate.check()?;
        // Do not substitute proof connection currentness for full original
        // verification. Reloaded private bytes are comparison evidence only.
        let (checkpoint, key, identity) = self.verified(&history, access, &gate)?;
        let output_actions = self.delivery_output_actions(access, &history, &checkpoint, cause)?;
        let actual_proof = delivery_proof_binding(&checkpoint, key, identity, output_actions);
        require_prepared_binding(
            &prepared_proof,
            &actual_proof,
            cause,
            S::ExportVerifiedProof,
        )?;
        // Proof verification can take time. Re-read and authenticate the full
        // current history again before comparing it to the original preparation.
        let (before, history) = self.check_observed(access, consent, cause)?;
        let actual_source = self.delivery_source_binding(access, &history, cause)?;
        require_prepared_binding(&source, &actual_source, cause, S::ExportSources)?;
        let actual_scope = DurableReviewExportScopeV1 {
            schema_version: 1,
            principal_id: actual_source.principal_id,
            proposal: actual_proof.identity,
            recipient: recipient.descriptor().clone(),
            sources: actual_source.sources,
            payload_digest: payload.payload_digest().into(),
            payload_length: payload.payload_bytes(),
        };
        require_prepared_binding(&scope, &actual_scope, cause, S::ExportRecipientBinding)?;
        drop(checkpoint);
        let delivery_gate = DeliveryGate {
            proof: &gate,
            scope: &scope,
            export,
        };
        delivery_gate.check(false)?;
        check_recipient(&recipient, cause)?;
        let mut roster = export_result(cause, S::ExportRoster, original_roster_v2(&before))?;
        if !roster.review_exports_v3.is_empty() || roster.coordinated_exports_present() {
            return Err(denied());
        }
        let prior_revision = history
            .export_revisions
            .get(&scope.recipient.request.operation_id)
            .copied();
        let revision = prior_revision
            .map(|n| n - 1)
            .unwrap_or(before.view.revision);
        let command = export_result(
            cause,
            S::ExportCommand,
            export_command(access, revision, &scope),
        )?;
        let saved = if let Some(saved_revision) = prior_revision {
            let retained = export_result(
                cause,
                S::ExportReplayScope,
                roster
                    .review_exports
                    .get(&scope.recipient.request.operation_id)
                    .ok_or_else(damaged),
            )?;
            if !replay_scope_matches(cause, &retained.scope, &scope) {
                return Err(denied());
            }
            let saved = export_result(
                cause,
                S::ExportReplayLookup,
                self.original
                    .engine
                    .store
                    .find_replay(&command)
                    .map_err(crate::store_error)
                    .and_then(|saved| saved.ok_or_else(damaged)),
            )?;
            if saved.record.revision != saved_revision {
                return export_predicate_error(cause, S::ExportReplayLookup, damaged());
            }
            saved
        } else {
            if roster.review_exports.len() >= MAX_EXPORT_INTENTS {
                return export_predicate_error(cause, S::ExportRoster, capacity());
            }
            if export_result(
                cause,
                S::ExportReplayLookup,
                self.original
                    .engine
                    .store
                    .find_replay(&command)
                    .map_err(crate::store_error),
            )?
            .is_some()
            {
                return export_predicate_error(cause, S::ExportReplayLookup, damaged());
            }
            roster.review_exports.insert(
                scope.recipient.request.operation_id.clone(),
                ExportIntent {
                    scope: scope.clone(),
                    exposure: ExportExposure::DisclosedOrUnknown,
                },
            );
            let mut after = before.clone();
            after.durable_construction_v1.insert(
                scope.proposal.proposal_id.clone(),
                export_result(
                    cause,
                    S::ExportDelta,
                    serde_json::to_value(&roster).map_err(|_| damaged()),
                )?,
            );
            after.view.revision = export_result(
                cause,
                S::ExportDelta,
                revision.checked_add(1).ok_or_else(damaged),
            )?;
            after.view.updated_at = crate::now();
            validate_export_delta_observed(&before, &after, cause)?;
            delivery_gate.check(false)?;
            check_recipient(&recipient, cause)?;
            let encoded = export_result(cause, S::ExportDelta, crate::encode(&after))?;
            observation.freeze();
            // No private transport before this original Store transaction.
            self.original
                .engine
                .store
                .update_agreement(
                    &command,
                    self.original.source.agreement_id(),
                    revision,
                    encoded,
                    EXPORT_EVENT,
                )
                .map_err(|error| disclosure_unknown(crate::store_error(error)))?
        };
        // From this existing boundary onward the original UNKNOWN wrapper is
        // authoritative. No post-update observation can claim a pre-Store cause.
        observation.freeze();
        // Reload and authenticate the actual saved operation on fresh AND replay
        // paths; a successful mutation return alone is never send permission.
        let result = (|| {
            delivery_gate.check(true)?;
            let actual = self
                .original
                .engine
                .store
                .find_replay(&command)
                .map_err(crate::store_error)?
                .ok_or_else(damaged)?;
            if actual.record != saved.record || actual.operation_id != saved.operation_id {
                return Err(damaged());
            }
            recipient.check_current().map_err(|_| denied())?;
            let check = || {
                delivery_gate
                    .check(true)
                    .map_err(|_| BridgeError::Permission)
            };
            recipient
                .deliver_prepared_v2(payload, &check)
                .map_err(|_| denied())?;
            delivery_gate.check(true)?;
            let (current, history) = self.check(access, consent)?;
            Ok(PrivateDurableAdmissionDeliveryV2 {
                revision: current.view.revision,
                replayed: saved.replayed,
                export_count: history.export_revisions.len(),
                export_history_digest: history.full_digest,
            })
        })();
        result.map_err(disclosure_unknown)
    }

    fn verified(
        &self,
        history: &History,
        access: &Access,
        gate: &ProofGate<'_, '_>,
    ) -> Result<(VerifiedCheckpoint, String, FixedProposalIdentityV1)> {
        use ExportCauseSite as S;
        let cause = gate.cause;
        let candidate = export_result(
            cause,
            S::ExportVerifiedProof,
            history.prefix.view.candidates.first().ok_or_else(damaged),
        )?;
        let receipt = export_result(
            cause,
            S::ExportVerifiedProof,
            history
                .prefix
                .checkpoint_receipts
                .values()
                .next()
                .ok_or_else(damaged),
        )?;
        let key = export_result(
            cause,
            S::ExportVerifiedProof,
            receipt.original_request_v2.as_ref().ok_or_else(damaged),
        )?
        .command
        .idempotency_key
        .clone();
        let observation = Observation::new(Operation::ReadFixed);
        let checkpoint = export_result(
            cause,
            S::ExportVerifiedProof,
            self.original.load_original_verified(
                &history.prefix,
                access,
                &candidate.candidate_id,
                &key,
                gate,
                &observation,
            ),
        )?;
        let identity = export_result(
            cause,
            S::ExportVerifiedProof,
            crate::durable_proposals_v1::read_private_fixed_v2(
                &history.prefix,
                access,
                &checkpoint,
                receipt,
            ),
        )?;
        gate.check()?;
        Ok((checkpoint, key, identity))
    }
    fn delivery_output_actions(
        &self,
        access: &Access,
        history: &History,
        checkpoint: &VerifiedCheckpoint,
        cause: ExportObservation<'_>,
    ) -> Result<Vec<DurableReviewOutputActionV1>> {
        let receipt = export_result(
            cause,
            ExportCauseSite::ExportOutputActions,
            history
                .prefix
                .checkpoint_receipts
                .values()
                .next()
                .ok_or_else(damaged),
        )?;
        let mappings = export_result(
            cause,
            ExportCauseSite::ExportOutputActions,
            crate::durable_proposals_v1::original_review_output_actions_v2(
                &history.prefix,
                access,
                checkpoint,
                receipt,
            ),
        )?;
        Ok(mappings
            .into_iter()
            .map(|m| DurableReviewOutputActionV1 {
                output_id: m.output_id,
                action_index: m.action_index,
            })
            .collect())
    }
    fn delivery_source_binding(
        &self,
        access: &Access,
        history: &History,
        cause: ExportObservation<'_>,
    ) -> Result<OriginalDeliverySourceBindingV2> {
        use ExportCauseSite as S;
        let roster = export_result(cause, S::ExportRoster, original_roster_v2(&history.prefix))?;
        let candidate = export_result(
            cause,
            S::ExportSources,
            history.prefix.view.candidates.first().ok_or_else(damaged),
        )?;
        let materials = export_result(
            cause,
            S::ExportMaterialCeilings,
            self.original
                .stage_materials_v3(access, &history.prefix, &candidate.candidate_id),
        )?;
        Ok(OriginalDeliverySourceBindingV2 {
            principal_id: access.principal_id.clone(),
            workspace: export_result(
                cause,
                S::ExportSources,
                serde_json::to_value(&self.original.scope).map_err(|_| damaged()),
            )?,
            metadata_origin: self.original.origin,
            proof_origin: self.original.proof_origin,
            marker_digest: export_result(cause, S::ExportMarker, self.origin_marker_digest())?,
            native_association_digest: self.original.marker.native_association_digest.clone(),
            prefix_history_digest: history.prefix_digest.clone(),
            full_history_digest: history.full_digest.clone(),
            materials: export_result(
                cause,
                S::ExportMaterialCeilings,
                serde_json::to_value(&materials).map_err(|_| damaged()),
            )?,
            sources: export_result(cause, S::ExportSources, review_export_v1::sources(&roster))?,
        })
    }

    fn check(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
    ) -> Result<(Envelope, History)> {
        self.check_observed(access, consent, None)
    }
    fn check_observed(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        cause: ExportObservation<'_>,
    ) -> Result<(Envelope, History)> {
        use ExportCauseSite as S;
        export_result(
            cause,
            S::ExportProofCurrent,
            self.original
                .proof
                .check_current()
                .map_err(original_job_error_v2),
        )?;
        if self.original.proof.origin_commitment() != self.original.proof_origin {
            return export_predicate_error(cause, S::ExportProofOrigin, damaged());
        }
        let result = self.check_without_proof_lock(access, consent, cause)?;
        export_result(
            cause,
            S::ExportProofCurrent,
            self.original
                .proof
                .check_current()
                .map_err(original_job_error_v2),
        )?;
        Ok(result)
    }
    // Proof permission callbacks execute with its mutex held. This path checks
    // the actual independent source/metadata/material owners, never that mutex.
    fn check_without_proof_lock(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        cause: ExportObservation<'_>,
    ) -> Result<(Envelope, History)> {
        use ExportCauseSite as S;
        let o = &self.original;
        check_source_observed(&o.source, access, &o.scope, consent, cause)?;
        if export_result(
            cause,
            S::ExportMetadataOrigin,
            o.engine
                .store
                .verify_original_encrypted_destination(o.scope.protected_destination())
                .map_err(crate::store_error),
        )? != o.origin
        {
            return export_predicate_error(cause, S::ExportMetadataOrigin, damaged());
        }
        let marker = export_result(
            cause,
            S::ExportMarker,
            crate::private_workspace_origin_v1::from_source(
                &o.source,
                access,
                &o.scope,
                &o.marker.native_association_digest,
                o.origin,
            ),
        )?;
        if marker != o.marker {
            return export_predicate_error(cause, S::ExportMarker, damaged());
        }
        let record = export_result(
            cause,
            S::ExportHistory,
            o.engine
                .store
                .get_agreement(o.source.agreement_id())
                .map_err(crate::store_error)
                .and_then(|record| record.ok_or_else(damaged)),
        )?;
        let current = export_result(cause, S::ExportHistory, decode_private_record(&record))?;
        let history = export_result(cause, S::ExportHistory, self.audit(access, &current, cause))?;
        // Always enforce BOTH original immutable material ceilings, including
        // during opening and inspection; historical availability is separate.
        export_result(
            cause,
            S::ExportMaterialCeilings,
            o.stage_materials_v3(access, &current, &current.view.candidates[0].candidate_id),
        )?;
        check_source_observed(&o.source, access, &o.scope, consent, cause)?;
        Ok((current, history))
    }
    fn audit(
        &self,
        access: &Access,
        current: &Envelope,
        cause: ExportObservation<'_>,
    ) -> Result<History> {
        let o = &self.original;
        let events = o
            .engine
            .store
            .events_after(0, (PREFIX_EVENTS + MAX_EXPORT_INTENTS + 1) as u32)
            .map_err(crate::store_error)?;
        self.audit_admission_rows(access, current, cause, &events)
    }
    // Exact original prefix/export validator shared only with the source-owned
    // financial profile. It receives a bounded original prefix of real rows;
    // its caller separately authenticates every later financial event.
    fn audit_admission_rows(
        &self,
        access: &Access,
        current: &Envelope,
        cause: ExportObservation<'_>,
        events: &[wholepact_store::StoredEvent],
    ) -> Result<History> {
        let o = &self.original;
        if events.len() < PREFIX_EVENTS
            || events.len() > PREFIX_EVENTS + MAX_EXPORT_INTENTS
            || events.len() as u64 != current.view.revision
        {
            return export_predicate_error(cause, ExportCauseSite::ExportHistory, damaged());
        }
        let mut previous: Option<Envelope> = None;
        let mut history = Vec::with_capacity(events.len());
        let mut prefix = None;
        let mut export_revisions = BTreeMap::new();
        for (i, event) in events.iter().enumerate() {
            if event.aggregate_type != "agreement"
                || event.aggregate_id != o.source.agreement_id()
                || event.aggregate_revision != (i + 1) as u64
                || event.sequence != (i + 1) as u64
                || event.payload
                    != serde_json::json!({"id":o.source.agreement_id(),"revision":i + 1})
                || if i < PREFIX_EVENTS {
                    event.kind != PREFIX_KINDS[i]
                } else {
                    event.kind != EXPORT_EVENT && event.kind != closed_review_v3::EXPORT_EVENT_V3 && !is_coordinated_export_event_v1(&event.kind)
                }
            {
                return export_predicate_error(cause, ExportCauseSite::ExportHistory, damaged());
            }
            let operation = o
                .engine
                .store
                .get_operation(&event.operation_id)
                .map_err(crate::store_error)?
                .ok_or_else(damaged)?;
            let saved: MutationResult =
                serde_json::from_value(operation.result.clone()).map_err(|_| damaged())?;
            if operation.kind != event.kind
                || operation.resource_id != event.aggregate_id
                || operation.principal_id != o.source.principal_id()
                || operation.status != "succeeded"
                || operation.operation_id != event.operation_id
                || saved.operation_id != event.operation_id
                || saved.event_sequence != event.sequence
                || saved.record.revision != event.aggregate_revision
                || saved.record.id != event.aggregate_id
                || saved.replayed
            {
                return export_predicate_error(cause, ExportCauseSite::ExportHistory, damaged());
            }
            let envelope = decode_private_record(&saved.record)?;
            if i < PREFIX_EVENTS {
                o.require_original_envelope(&envelope)?;
                if let Some(before) = &previous {
                    let purpose = match i {
                        1 => operation_v1::EffectV2::PrepareExactCandidate,
                        2 | 3 => operation_v1::EffectV2::RetainExactMaterial,
                        4 => operation_v1::EffectV2::ConstructorReceipt,
                        5 => operation_v1::EffectV2::MetadataLink,
                        6 => operation_v1::EffectV2::RecordOriginalProofOutcome,
                        7 => operation_v1::EffectV2::FreezeVerifiedFixed,
                        _ => {
                            return export_predicate_error(
                                cause,
                                ExportCauseSite::ExportHistory,
                                damaged(),
                            )
                        }
                    };
                    operation_v1::validate_delta_after_checked_shapes_v2(
                        before, &envelope, purpose,
                    )?;
                } else if !envelope.view.candidates.is_empty()
                    || !envelope.durable_construction_v1.is_empty()
                    || !envelope.checkpoint_receipts.is_empty()
                    || !envelope.durable_proposals_v1.is_empty()
                {
                    return export_predicate_error(
                        cause,
                        ExportCauseSite::ExportHistory,
                        damaged(),
                    );
                }
                let command = self
                    .prefix_commands
                    .get(&event.operation_id)
                    .ok_or_else(damaged)?;
                validate_prefix_command_observed(
                    i,
                    access,
                    &self.seed_command,
                    command,
                    previous.as_ref(),
                    &envelope,
                    cause,
                )?;
                let replay = o
                    .engine
                    .store
                    .find_replay(command)
                    .map_err(crate::store_error)?
                    .ok_or_else(damaged)?;
                if replay.record != saved.record
                    || replay.operation_id != saved.operation_id
                    || replay.event_sequence != saved.event_sequence
                {
                    return export_predicate_error(
                        cause,
                        ExportCauseSite::ExportHistory,
                        damaged(),
                    );
                }
                if i + 1 == PREFIX_EVENTS {
                    require_completed_prefix_observed(&envelope, cause)?;
                    prefix = Some(envelope.clone());
                }
            } else {
                o.require_original_identity_v2(&envelope)?;
                let before = previous.as_ref().ok_or_else(damaged)?;
                let (principal, operation_id, command) = if event.kind == EXPORT_EVENT {
                    let scope = validate_export_delta_observed(before, &envelope, cause)?;
                    let command = export_command(access, before.view.revision, &scope)?;
                    (
                        scope.principal_id,
                        scope.recipient.request.operation_id,
                        command,
                    )
                } else if is_coordinated_export_event_v1(&event.kind) {
                    audit_coordinated_export_v1(before, &envelope, access)?
                } else {
                    let scope = closed_review_v3::validate_export_delta_v3(before, &envelope)?;
                    let command =
                        closed_review_v3::export_command_v3(access, before.view.revision, &scope)?;
                    (
                        scope.principal_id,
                        scope.recipient.request.operation_id,
                        command,
                    )
                };
                if principal != access.principal_id
                    || export_revisions
                        .insert(operation_id, envelope.view.revision)
                        .is_some()
                {
                    return export_predicate_error(
                        cause,
                        ExportCauseSite::ExportHistory,
                        damaged(),
                    );
                }
                let replay = o
                    .engine
                    .store
                    .find_replay(&command)
                    .map_err(crate::store_error)?
                    .ok_or_else(damaged)?;
                if replay.record != saved.record
                    || replay.operation_id != saved.operation_id
                    || replay.event_sequence != saved.event_sequence
                {
                    return export_predicate_error(
                        cause,
                        ExportCauseSite::ExportHistory,
                        damaged(),
                    );
                }
            }
            history.push((event.clone(), operation));
            previous = Some(envelope);
        }
        if crate::encode(previous.as_ref().ok_or_else(damaged)?)? != crate::encode(current)? {
            return export_predicate_error(cause, ExportCauseSite::ExportHistory, damaged());
        }
        let prefix_digest = digest(
            "wholepact:private-exact-operation-history:v2",
            &history[..PREFIX_EVENTS],
        )?;
        let full_digest = digest("wholepact:private-admission-export-history:v2", &history)?;
        Ok(History {
            prefix: prefix.ok_or_else(damaged)?,
            prefix_digest,
            full_digest,
            export_revisions,
            rows: history,
        })
    }
}

fn delivery_proof_binding(
    checkpoint: &VerifiedCheckpoint,
    original_request_key: String,
    identity: FixedProposalIdentityV1,
    output_actions: Vec<DurableReviewOutputActionV1>,
) -> OriginalDeliveryProofBindingV2 {
    OriginalDeliveryProofBindingV2 {
        original_request_key,
        identity,
        summary: checkpoint.summary().clone(),
        scope: checkpoint.scope().clone(),
        unsigned_digest: Sha256::digest(checkpoint.private_unsigned_pczt_bytes()).into(),
        proved_digest: Sha256::digest(checkpoint.pczt_bytes()).into(),
        output_actions,
    }
}

fn check_source(
    source: &PrivateDurableWorkspaceSourceV1<'_>,
    access: &Access,
    scope: &PrivateWorkspaceScopeV1,
    consent: &dyn LocalPrivateDurableAdmissionConsentV2,
) -> Result<()> {
    check_source_observed(source, access, scope, consent, None)
}
fn check_source_observed(
    source: &PrivateDurableWorkspaceSourceV1<'_>,
    access: &Access,
    scope: &PrivateWorkspaceScopeV1,
    consent: &dyn LocalPrivateDurableAdmissionConsentV2,
    cause: ExportObservation<'_>,
) -> Result<()> {
    use ExportCauseSite as S;
    export_result(cause, S::ExportSourceBefore, source.check_current(access))?;
    if !export_predicate(cause, S::ExportSourceBefore, consent.permits_source(scope)) {
        return Err(denied());
    }
    export_result(cause, S::ExportSourceAfter, source.check_current(access))
}
fn digest<T: Serialize + ?Sized>(domain: &str, value: &T) -> Result<String> {
    // Serialize the borrowed slice as its canonical array; the original domain
    // remains exactly the precursor domain for the immutable eight-event prefix.
    wholepact_core::proposal::canonical_digest(domain, &value).map_err(Into::into)
}
#[cfg(all(test, feature = "synthetic-qualification"))]
fn require_completed_prefix(e: &Envelope) -> Result<()> {
    require_completed_prefix_observed(e, None)
}
fn require_completed_prefix_observed(e: &Envelope, cause: ExportObservation<'_>) -> Result<()> {
    operation_v1::validate_shape(e)?;
    if e.view.revision != PREFIX_EVENTS as u64
        || e.view.progress != "awaiting_authorization"
        || e.view.candidates.len() != 1
        || e.checkpoint_receipts.len() != 1
        || e.durable_proposals_v1.len() != 1
    {
        return export_predicate_error(cause, ExportCauseSite::ExportHistory, damaged());
    }
    let roster = original_roster_v2(e)?;
    let c = &e.view.candidates[0];
    if roster.owners.len() != 2
        || !roster.review_exports.is_empty()
        || !roster.review_exports_v3.is_empty() || roster.coordinated_exports_present()
        || c.proof_jobs.len() != 1
        || c.proof_jobs[0].state != "succeeded"
        || c.proof_jobs[0].attempt != 1
        || !c.proof_jobs[0].proof_verified
        || c.proof_jobs[0].result_digest.is_none()
    {
        return export_predicate_error(cause, ExportCauseSite::ExportHistory, damaged());
    }
    Ok(())
}
fn export_command(
    access: &Access,
    revision: u64,
    scope: &DurableReviewExportScopeV1,
) -> Result<CommandContext> {
    scope.recipient.request.validate().map_err(|_| damaged())?;
    let key = format!(
        "admission-review-{}",
        digest(
            "wholepact:private-admission-export-idempotency:v2",
            &scope.recipient.request.operation_id
        )?
    );
    crate::context(
        access,
        &key,
        EXPORT_COMMAND,
        &scope.proposal.proposal_id,
        Some(revision),
        scope,
    )
}
/// Compare the entire typed envelope, admitting only one exact export-map
/// insertion and the maintained revision/time increment. No historical field is
/// removed or replaced to simulate a precursor. Existing exports stay exact.
#[cfg(all(test, feature = "synthetic-qualification"))]
fn validate_export_delta(
    before: &Envelope,
    after: &Envelope,
) -> Result<DurableReviewExportScopeV1> {
    validate_export_delta_observed(before, after, None)
}
fn validate_export_delta_observed(
    before: &Envelope,
    after: &Envelope,
    cause: ExportObservation<'_>,
) -> Result<DurableReviewExportScopeV1> {
    export_result(
        cause,
        ExportCauseSite::ExportDelta,
        validate_export_delta_kernel(before, after, cause),
    )
}
fn validate_export_delta_kernel(
    before: &Envelope,
    after: &Envelope,
    cause: ExportObservation<'_>,
) -> Result<DurableReviewExportScopeV1> {
    for e in [before, after] {
        operation_v1::validate_common_shape(e)?;
        crate::durable_construction_v1::validate_stored(e)?;
        crate::durable_proposals_v1::validate_private_fixed_v2(e)?;
    }
    if after.view.revision != before.view.revision.checked_add(1).ok_or_else(damaged)?
        || time::OffsetDateTime::parse(
            &after.view.updated_at,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return export_predicate_error(cause, ExportCauseSite::ExportDelta, damaged());
    }
    let old = original_roster_v2(before)?;
    let new = original_roster_v2(after)?;
    if !old.review_exports_v3.is_empty() || !new.review_exports_v3.is_empty() || old.coordinated_exports_present() || new.coordinated_exports_present() {
        return Err(damaged());
    }
    if new.owners.len() != 2 {
        return export_predicate_error(cause, ExportCauseSite::ExportDelta, damaged());
    }
    let (id, intent) = added_export_observed(&old.review_exports, &new.review_exports, cause)?;
    let mut allowed_roster = old.clone();
    allowed_roster.review_exports.insert(id, intent.clone());
    if serde_json::to_value(&allowed_roster).map_err(|_| damaged())?
        != serde_json::to_value(&new).map_err(|_| damaged())?
    {
        return export_predicate_error(cause, ExportCauseSite::ExportDelta, damaged());
    }
    let mut permitted = before.clone();
    permitted.view.revision = after.view.revision;
    permitted.view.updated_at = after.view.updated_at.clone();
    permitted.durable_construction_v1.insert(
        intent.scope.proposal.proposal_id.clone(),
        serde_json::to_value(&allowed_roster).map_err(|_| damaged())?,
    );
    if crate::encode(&permitted)? != crate::encode(after)? {
        return export_predicate_error(cause, ExportCauseSite::ExportDelta, damaged());
    }
    Ok(intent.scope.clone())
}

#[cfg(test)]
fn added_export(
    old: &BTreeMap<String, ExportIntent>,
    new: &BTreeMap<String, ExportIntent>,
) -> Result<(String, ExportIntent)> {
    added_export_observed(old, new, None)
}
fn added_export_observed(
    old: &BTreeMap<String, ExportIntent>,
    new: &BTreeMap<String, ExportIntent>,
    cause: ExportObservation<'_>,
) -> Result<(String, ExportIntent)> {
    if new.len() != old.len() + 1 || new.len() > MAX_EXPORT_INTENTS {
        return export_predicate_error(cause, ExportCauseSite::ExportDelta, damaged());
    }
    let added = new
        .iter()
        .filter(|(key, _)| !old.contains_key(*key))
        .collect::<Vec<_>>();
    if added.len() != 1 {
        return export_predicate_error(cause, ExportCauseSite::ExportDelta, damaged());
    }
    let (id, intent) = added[0];
    let mut expected = old.clone();
    expected.insert(id.clone(), intent.clone());
    if serde_json::to_value(&expected).map_err(|_| damaged())?
        != serde_json::to_value(new).map_err(|_| damaged())?
        || id != &intent.scope.recipient.request.operation_id
    {
        return export_predicate_error(cause, ExportCauseSite::ExportDelta, damaged());
    }
    Ok((id.clone(), intent.clone()))
}
struct ProofGate<'a, 'source> {
    owner: &'a PrivateDurableAdmissionCoordinatorV2<'source>,
    access: &'a Access,
    consent: &'a dyn LocalPrivateDurableAdmissionConsentV2,
    proof: &'a dyn LocalProofConsent,
    material: &'a dyn LocalDurableMaterialConsentV1,
    action: DurableMaterialActionV1,
    cause: ExportObservation<'a>,
}
impl ProofGate<'_, '_> {
    fn check(&self) -> Result<()> {
        use ExportCauseSite as S;
        let (current, _) =
            self.owner
                .check_without_proof_lock(self.access, self.consent, self.cause)?;
        for intake in export_result(self.cause, S::ExportRoster, original_roster_v2(&current))?
            .owners
            .values()
        {
            export_result(
                self.cause,
                S::ExportIntake,
                self.owner
                    .original
                    .check_intake(self.access, intake, self.material, self.action),
            )?;
        }
        self.owner
            .check_without_proof_lock(self.access, self.consent, self.cause)?;
        Ok(())
    }
}
impl LocalProofConsent for ProofGate<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        proof_permission(
            self.cause,
            || self.check(),
            || self.proof.permits(scope, action),
        )
    }
}
struct DeliveryGate<'a, 'source> {
    proof: &'a ProofGate<'a, 'source>,
    scope: &'a DurableReviewExportScopeV1,
    export: &'a dyn LocalDurableReviewExportConsentV1,
}
impl DeliveryGate<'_, '_> {
    fn check(&self, require_committed: bool) -> Result<()> {
        use ExportCauseSite as S;
        let cause = self.proof.cause;
        self.proof.check()?;
        let (current, _) =
            self.proof
                .owner
                .check_observed(self.proof.access, self.proof.consent, cause)?;
        let roster = export_result(cause, S::ExportRoster, original_roster_v2(&current))?;
        export_result(
            cause,
            S::ExportRecipientBinding,
            review_export_v1::validate_recipient(&roster, &current.view.candidates[0], self.scope),
        )?;
        if export_result(cause, S::ExportSources, review_export_v1::sources(&roster))?
            != self.scope.sources
        {
            return export_predicate_error(cause, S::ExportSources, damaged());
        }
        if require_committed
            && roster
                .review_exports
                .get(&self.scope.recipient.request.operation_id)
                .is_none_or(|i| i.scope != *self.scope)
        {
            return export_predicate_error(cause, S::ExportReplayScope, damaged());
        }
        let materials = export_result(
            cause,
            S::ExportMaterialCeilings,
            self.proof.owner.original.stage_materials_v3(
                self.proof.access,
                &current,
                &current.view.candidates[0].candidate_id,
            ),
        )?;
        let checkpoint_scope = export_result(
            cause,
            S::ExportCheckpointScope,
            exact_fixed_v2::retained_review_scope_v3(
                &current.view.candidates[0],
                export_result(
                    cause,
                    S::ExportCheckpointScope,
                    current
                        .checkpoint_receipts
                        .values()
                        .next()
                        .ok_or_else(damaged),
                )?,
                &materials,
            ),
        )?;
        if !delivery_permission(
            cause,
            || {
                self.proof
                    .permits(&checkpoint_scope, LocalAction::ReadPrivateArtifact)
            },
            || self.export.permits(self.scope),
        ) {
            return Err(denied());
        }
        self.proof.check()
    }
}
fn capacity() -> ApiError {
    ApiError::new(
        "CONFLICT",
        "The bounded original review-export capacity is exhausted; retained exposure cannot be cleared",
    )
}
fn disclosure_unknown(mut cause: ApiError) -> ApiError {
    // Preserve the original cause; the caller must not report a rollback merely
    // because the source, peer or native approval expired after the commit.
    let original_code = cause.code.clone();
    cause.code = "DISCLOSURE_UNKNOWN".into();
    cause.retryable = false;
    cause.message = "The original review-export may be retained or disclosed; preserve its exact identity and audit the original history".into();
    operation_v1::merge_error_details_v2(
        &mut cause,
        &serde_json::json!({
            "original_code": original_code, "disclosure_state": "disclosed_or_unknown",
            "new_recipient_requires_new_review": true,
        }),
    );
    cause
}

fn original_commands(
    destination: &Path,
    key: &DatabaseKey,
    expected: [u8; 32],
) -> Result<BTreeMap<String, CommandContext>> {
    original_commands_bounded(
        destination,
        key,
        expected,
        PREFIX_EVENTS + MAX_EXPORT_INTENTS,
    )
    .map(|(prefix, _)| prefix)
}
fn original_commands_bounded(
    destination: &Path,
    key: &DatabaseKey,
    expected: [u8; 32],
    maximum: usize,
) -> Result<(
    BTreeMap<String, CommandContext>,
    BTreeMap<String, CommandContext>,
)> {
    let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(destination, key)
        .map_err(|_| damaged())?;
    if snapshot
        .source_database_identity()
        .map_err(|_| damaged())?
        .origin_commitment()
        != expected
    {
        return Err(damaged());
    }
    let mut statement = snapshot.connection().prepare(
        "SELECT principal_id,idempotency_key,request_digest,result FROM idempotency ORDER BY principal_id,idempotency_key LIMIT 405",
    ).map_err(|_| damaged())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| damaged())?;
    let mut commands = BTreeMap::new();
    let mut all_commands = BTreeMap::new();
    let mut count = 0;
    for row in rows {
        count += 1;
        let (principal_id, idempotency_key, request_digest, encoded) =
            row.map_err(|_| damaged())?;
        if count > maximum || encoded.len() > 1024 * 1024 {
            return Err(damaged());
        }
        let saved: MutationResult = serde_json::from_str(&encoded).map_err(|_| damaged())?;
        // Duplicate/unknown fields and alternate encodings cannot disappear in
        // an intermediate Value before this canonical stored-result check.
        if serde_json::to_string(&saved).map_err(|_| damaged())? != encoded || saved.replayed {
            return Err(damaged());
        }
        let command = CommandContext {
            principal_id,
            idempotency_key,
            request_digest,
        };
        if all_commands
            .insert(saved.operation_id.clone(), command.clone())
            .is_some()
        {
            return Err(damaged());
        }
        if saved.record.revision <= PREFIX_EVENTS as u64 {
            if commands.insert(saved.operation_id, command).is_some() {
                return Err(damaged());
            }
        }
    }
    if commands.len() != PREFIX_EVENTS {
        return Err(damaged());
    }
    snapshot.check_source_unchanged().map_err(|_| damaged())?;
    Ok((commands, all_commands))
}
#[cfg(all(test, feature = "synthetic-qualification"))]
fn validate_prefix_command(
    index: usize,
    access: &Access,
    seed: &CommandContext,
    command: &CommandContext,
    before: Option<&Envelope>,
    after: &Envelope,
) -> Result<()> {
    validate_prefix_command_observed(index, access, seed, command, before, after, None)
}
fn validate_prefix_command_observed(
    index: usize,
    access: &Access,
    seed: &CommandContext,
    command: &CommandContext,
    before: Option<&Envelope>,
    after: &Envelope,
    cause: ExportObservation<'_>,
) -> Result<()> {
    let key = &command.idempotency_key;
    let expected = if index == 0 {
        seed.clone()
    } else {
        let before = before.ok_or_else(damaged)?;
        let c = after.view.candidates.first().ok_or_else(damaged)?;
        let receipt = after.checkpoint_receipts.values().next();
        match index {
            1 => crate::context(
                access,
                key,
                "private_prepare_exact_candidate_v2",
                &after.view.agreement.agreement_id,
                Some(before.view.revision),
                &crate::CandidateRequest {
                    manifest: c.proposal.manifest.clone(),
                    previous_candidate_id: None,
                },
            )?,
            2 | 3 => {
                let new = original_roster_v2(after)?;
                let old: crate::durable_construction_v1::Roster = before
                    .durable_construction_v1
                    .get(&c.candidate_id)
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()
                    .map_err(|_| damaged())?
                    .unwrap_or_default();
                let added = new
                    .owners
                    .iter()
                    .filter(|(account, _)| !old.owners.contains_key(*account))
                    .collect::<Vec<_>>();
                if added.len() != 1 {
                    return export_predicate_error(
                        cause,
                        ExportCauseSite::ExportHistory,
                        damaged(),
                    );
                }
                let intake = added[0].1;
                crate::context(
                    access,
                    key,
                    "private_retain_exact_material_v2",
                    &c.candidate_id,
                    Some(before.view.revision),
                    &(
                        &intake.metadata_origin,
                        intake.outbox.reference(),
                        intake.outbox.request_digest(),
                        intake.outbox.material_digest(),
                        &intake.signer_enrollment_reference,
                    ),
                )?
            }
            4 => {
                let receipt = receipt.ok_or_else(damaged)?;
                let original = receipt.original_request_v2.as_ref().ok_or_else(damaged)?;
                exact_fixed_v2::validate_original_request_v2(
                    receipt,
                    access,
                    &original.command.idempotency_key,
                )?;
                if key
                    != &format!(
                        "prepare-{}",
                        exact_fixed_v2::receipt_key(access, &original.command.idempotency_key)?
                    )
                {
                    return export_predicate_error(
                        cause,
                        ExportCauseSite::ExportHistory,
                        damaged(),
                    );
                }
                crate::context(
                    access,
                    key,
                    "private_prepare_constructor_receipt_v2",
                    &c.candidate_id,
                    Some(before.view.revision),
                    receipt,
                )?
            }
            5 => {
                let receipt = receipt.ok_or_else(damaged)?;
                let original = receipt.original_request_v2.as_ref().ok_or_else(damaged)?;
                exact_fixed_v2::validate_original_request_v2(
                    receipt,
                    access,
                    &original.command.idempotency_key,
                )?;
                original.command.clone()
            }
            6 => {
                let receipt = receipt.ok_or_else(damaged)?;
                crate::context(
                    access,
                    key,
                    "private_prove_original_once_v2",
                    &c.candidate_id,
                    Some(before.view.revision),
                    &(&receipt.job_id, &receipt.coordination_request_digest),
                )?
            }
            7 => {
                let receipt = receipt.ok_or_else(damaged)?;
                let original = receipt.original_request_v2.as_ref().ok_or_else(damaged)?;
                let link = c.proof_jobs.first().ok_or_else(damaged)?;
                let mut summary = serde_json::to_value(link).map_err(|_| damaged())?;
                let object = summary.as_object_mut().ok_or_else(damaged)?;
                object.remove("observed_at");
                object.remove("observation_source");
                crate::context(
                    access,
                    key,
                    "private_freeze_verified_fixed_v2",
                    &c.candidate_id,
                    Some(before.view.revision),
                    &(
                        &original.command.idempotency_key,
                        &receipt.coordination_request_digest,
                        summary,
                    ),
                )?
            }
            _ => return export_predicate_error(cause, ExportCauseSite::ExportHistory, damaged()),
        }
    };
    if command.principal_id != access.principal_id
        || serde_json::to_value(command).map_err(|_| damaged())?
            != serde_json::to_value(expected).map_err(|_| damaged())?
    {
        return export_predicate_error(cause, ExportCauseSite::ExportHistory, damaged());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_signer::authority_bridge::{
        durable_construction_v1::DurableConstructionHistoryRequestV1,
        durable_review_ipc_v1::{DurableReviewDeliveryRequestV1, DurableReviewRecipientV1},
    };
    // Inert request data only. This cannot create a sealed recipient, native
    // consent, original coordinator, verified checkpoint or financial source.
    fn scope(operation: &str) -> DurableReviewExportScopeV1 {
        let h = "ab".repeat(32);
        let identity = FixedProposalIdentityV1 {
            schema_version: 1,
            network_profile_id: "synthetic".into(),
            agreement_id: "agreement".into(),
            obligation_id: "obligation".into(),
            proposal_id: "candidate".into(),
            revision: 1,
            expiry_height: 10,
            proposal_digest: h.clone(),
            manifest_digest: h.clone(),
            unsigned_artifact_digest: h.clone(),
            proved_artifact_digest: h.clone(),
            effects_commitment: h.clone(),
            policy_digest: h.clone(),
            review_binding: h.clone(),
            action_mapping_digest: h.clone(),
            anchor: h.clone(),
            proposal_binding: h.clone(),
        };
        DurableReviewExportScopeV1 {
            schema_version: 1,
            principal_id: "operator".into(),
            proposal: identity,
            recipient: DurableReviewRecipientV1 {
                version: 1,
                request: DurableReviewDeliveryRequestV1 {
                    operation_id: operation.into(),
                    enrollment_ref: h.clone(),
                    accepted_manifest_ref: h.clone(),
                    own_disclosure: DurableConstructionHistoryRequestV1 {
                        operation_id: "original-material".into(),
                        expected_request_digest: h.clone(),
                    },
                    current_disclosure: None,
                    proposal_binding: h.clone(),
                },
                account_id: h.clone(),
                participant_id: "alice".into(),
                agreement_id: "agreement".into(),
                manifest_digest: h.clone(),
                provider_enrollment_reference: h.clone(),
                signer_process_instance: h.clone(),
                local_grant_id: h.clone(),
                local_channel_digest: h.clone(),
            },
            sources: vec![review_export_v1::DurableReviewSourceV1 {
                account_id: h.clone(),
                outbox_reference: h.clone(),
                request_digest: h.clone(),
                material_digest: h.clone(),
                scope_digest: h.clone(),
            }],
            payload_digest: h,
            payload_length: 123,
        }
    }
    // Inert comparison fixtures only. They cannot manufacture an original
    // coordinator, verified checkpoint, prepared owner or sealed recipient.
    fn prepared_source_binding() -> OriginalDeliverySourceBindingV2 {
        OriginalDeliverySourceBindingV2 {
            principal_id: "operator".into(),
            workspace: serde_json::json!({"source_digest":"source","protected_destination":"original"}),
            metadata_origin: [1; 32],
            proof_origin: [2; 32],
            marker_digest: "marker".into(),
            native_association_digest: "association".into(),
            prefix_history_digest: "prefix".into(),
            full_history_digest: "full-with-original-export-suffix".into(),
            materials: serde_json::json!([
                {"material_digest":"first","scope":{"valid_from_unix_seconds":10,"valid_until_unix_seconds":90}},
                {"material_digest":"second","scope":{"valid_from_unix_seconds":20,"valid_until_unix_seconds":80}}
            ]),
            sources: scope("review").sources,
        }
    }
    fn prepared_proof_binding() -> OriginalDeliveryProofBindingV2 {
        OriginalDeliveryProofBindingV2 {
            original_request_key: "original-key".into(),
            identity: scope("review").proposal,
            summary: JobSummary {
                job_id: "job".into(),
                scope_digest: "scope".into(),
                candidate_id: "candidate".into(),
                state: wholepact_proof_jobs::JobState::Succeeded,
                attempt: 1,
                input_digest: "input".into(),
                manifest_digest: "manifest".into(),
                effects_commitment: "effects".into(),
                coordination_request_digest: "request".into(),
                result_digest: Some("result".into()),
                review_binding: "review".into(),
                encrypted_checkpoint_created: true,
                proof_verified: true,
                chain_validated: false,
                authorization_allowed: false,
                distribution_allowed: false,
            },
            scope: CheckpointScope {
                principal_id: "operator".into(),
                candidate_id: "candidate".into(),
                manifest_digest: "manifest".into(),
                artifact_digest: "artifact".into(),
                effects_commitment: "effects".into(),
                coordination_request_digest: "request".into(),
                review_binding: "review".into(),
                account_ids: vec!["first".into(), "second".into()],
                local_operator: "operator".into(),
                purpose: "local-read-only".into(),
                retention_policy: "original".into(),
            },
            unsigned_digest: [3; 32],
            proved_digest: [4; 32],
            output_actions: vec![DurableReviewOutputActionV1 {
                output_id: "output".into(),
                action_index: 1,
            }],
        }
    }
    fn assert_prepared_comparison_stops_effect<T: PartialEq>(expected: &T, changed: &T) {
        let effects = std::cell::Cell::new(0);
        let cause = ExportCause::new();
        let result = (|| {
            require_prepared_binding(
                expected,
                changed,
                Some(&cause),
                ExportCauseSite::ExportPayload,
            )?;
            effects.set(effects.get() + 1);
            Ok::<(), ApiError>(())
        })();
        assert_eq!(result.unwrap_err().code, "DISCLOSURE_DENIED");
        assert_eq!(effects.get(), 0);
        assert_eq!(
            cause_pair(&cause),
            Some(("ExportPayload", "PredicateDenied"))
        );
    }
    #[test]
    fn admission_prepared_source_comparison_rejects_every_original_binding_change() {
        let original = prepared_source_binding();
        require_prepared_binding(
            &original,
            &prepared_source_binding(),
            None,
            ExportCauseSite::ExportSources,
        )
        .unwrap();
        let mutations: &[fn(&mut OriginalDeliverySourceBindingV2)] = &[
            |v| v.principal_id.push('x'),
            |v| v.workspace["source_digest"] = "other".into(),
            |v| v.workspace["protected_destination"] = "other".into(),
            |v| v.metadata_origin[0] ^= 1,
            |v| v.proof_origin[0] ^= 1,
            |v| v.marker_digest.push('x'),
            |v| v.native_association_digest.push('x'),
            |v| v.prefix_history_digest.push('x'),
            |v| v.full_history_digest.push('x'),
            |v| v.materials[0]["material_digest"] = "other".into(),
            |v| v.materials[1]["material_digest"] = "other".into(),
            |v| v.materials[0]["scope"]["valid_from_unix_seconds"] = 120.into(),
            |v| v.materials[1]["scope"]["valid_from_unix_seconds"] = 120.into(),
            |v| v.materials[0]["scope"]["valid_until_unix_seconds"] = 120.into(),
            |v| v.materials[1]["scope"]["valid_until_unix_seconds"] = 120.into(),
            |v| v.sources[0].account_id.push('x'),
            |v| v.sources[0].outbox_reference.push('x'),
            |v| v.sources[0].request_digest.push('x'),
            |v| v.sources[0].material_digest.push('x'),
            |v| v.sources[0].scope_digest.push('x'),
            |v| v.sources.clear(),
        ];
        for mutate in mutations {
            let mut changed = prepared_source_binding();
            mutate(&mut changed);
            assert_prepared_comparison_stops_effect(&original, &changed);
        }
    }
    #[test]
    fn admission_prepared_proof_comparison_rejects_every_verified_binding_change() {
        let original = prepared_proof_binding();
        require_prepared_binding(
            &original,
            &prepared_proof_binding(),
            None,
            ExportCauseSite::ExportVerifiedProof,
        )
        .unwrap();
        let mutations: &[fn(&mut OriginalDeliveryProofBindingV2)] = &[
            |v| v.original_request_key.push('x'),
            |v| v.identity.network_profile_id.push('x'),
            |v| v.identity.agreement_id.push('x'),
            |v| v.identity.obligation_id.push('x'),
            |v| v.identity.proposal_id.push('x'),
            |v| v.identity.proposal_digest.push('x'),
            |v| v.identity.manifest_digest.push('x'),
            |v| v.identity.unsigned_artifact_digest.push('x'),
            |v| v.identity.proved_artifact_digest.push('x'),
            |v| v.identity.effects_commitment.push('x'),
            |v| v.identity.policy_digest.push('x'),
            |v| v.identity.review_binding.push('x'),
            |v| v.identity.action_mapping_digest.push('x'),
            |v| v.identity.anchor.push('x'),
            |v| v.identity.proposal_binding.push('x'),
            |v| v.identity.schema_version += 1,
            |v| v.identity.revision += 1,
            |v| v.identity.expiry_height += 1,
            |v| v.summary.job_id.push('x'),
            |v| v.summary.scope_digest.push('x'),
            |v| v.summary.candidate_id.push('x'),
            |v| v.summary.input_digest.push('x'),
            |v| v.summary.manifest_digest.push('x'),
            |v| v.summary.effects_commitment.push('x'),
            |v| v.summary.coordination_request_digest.push('x'),
            |v| v.summary.review_binding.push('x'),
            |v| v.summary.state = wholepact_proof_jobs::JobState::Failed,
            |v| v.summary.attempt += 1,
            |v| v.summary.result_digest = None,
            |v| v.summary.encrypted_checkpoint_created = !v.summary.encrypted_checkpoint_created,
            |v| v.summary.proof_verified = !v.summary.proof_verified,
            |v| v.summary.chain_validated = !v.summary.chain_validated,
            |v| v.summary.authorization_allowed = !v.summary.authorization_allowed,
            |v| v.summary.distribution_allowed = !v.summary.distribution_allowed,
            |v| v.scope.principal_id.push('x'),
            |v| v.scope.candidate_id.push('x'),
            |v| v.scope.manifest_digest.push('x'),
            |v| v.scope.artifact_digest.push('x'),
            |v| v.scope.effects_commitment.push('x'),
            |v| v.scope.coordination_request_digest.push('x'),
            |v| v.scope.review_binding.push('x'),
            |v| v.scope.local_operator.push('x'),
            |v| v.scope.purpose.push('x'),
            |v| v.scope.retention_policy.push('x'),
            |v| v.scope.account_ids.swap(0, 1),
            |v| v.unsigned_digest[0] ^= 1,
            |v| v.proved_digest[0] ^= 1,
            |v| v.output_actions[0].output_id.push('x'),
            |v| v.output_actions[0].action_index += 1,
            |v| v.output_actions.clear(),
        ];
        for mutate in mutations {
            let mut changed = prepared_proof_binding();
            mutate(&mut changed);
            assert_prepared_comparison_stops_effect(&original, &changed);
        }
    }
    #[test]
    fn admission_prepared_scope_comparison_rejects_recipient_or_payload_substitution() {
        let original = scope("review");
        let mutations: &[fn(&mut DurableReviewExportScopeV1)] = &[
            |v| v.principal_id.push('x'),
            |v| v.payload_digest.push('x'),
            |v| v.schema_version += 1,
            |v| v.payload_length += 1,
            |v| v.proposal.proposal_binding.push('x'),
            |v| v.sources[0].material_digest.push('x'),
            |v| v.recipient.version += 1,
            |v| v.recipient.account_id.push('x'),
            |v| v.recipient.participant_id.push('x'),
            |v| v.recipient.agreement_id.push('x'),
            |v| v.recipient.manifest_digest.push('x'),
            |v| v.recipient.provider_enrollment_reference.push('x'),
            |v| v.recipient.signer_process_instance.push('x'),
            |v| v.recipient.local_grant_id.push('x'),
            |v| v.recipient.local_channel_digest.push('x'),
            |v| v.recipient.request.operation_id.push('x'),
            |v| v.recipient.request.enrollment_ref.push('x'),
            |v| v.recipient.request.accepted_manifest_ref.push('x'),
            |v| v.recipient.request.proposal_binding.push('x'),
            |v| v.recipient.request.own_disclosure.operation_id.push('x'),
            |v| {
                v.recipient
                    .request
                    .own_disclosure
                    .expected_request_digest
                    .push('x')
            },
            |v| {
                v.recipient.request.current_disclosure =
                    Some(v.recipient.request.own_disclosure.clone())
            },
        ];
        for mutate in mutations {
            let mut changed = scope("review");
            mutate(&mut changed);
            assert_prepared_comparison_stops_effect(&original, &changed);
        }
    }
    #[test]
    fn admission_prepared_owners_are_consuming_and_not_clone_serde_or_debug() {
        macro_rules! not_impl {
            ($ty:ty, $bound:path) => {{
                trait AmbiguousIfImpl<A> {
                    fn check() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                struct Implemented;
                impl<T: ?Sized + $bound> AmbiguousIfImpl<Implemented> for T {}
                let _ = <$ty as AmbiguousIfImpl<_>>::check;
            }};
        }
        type Prepared = PreparedPrivateDurableAdmissionDeliveryV2<'static, 'static>;
        type Bound = BoundPrivateDurableAdmissionDeliveryV2<'static, 'static, 'static>;
        not_impl!(Prepared, Clone);
        not_impl!(Prepared, std::fmt::Debug);
        not_impl!(Prepared, serde::Serialize);
        not_impl!(Prepared, serde::Deserialize<'static>);
        not_impl!(Bound, Clone);
        not_impl!(Bound, std::fmt::Debug);
        not_impl!(Bound, serde::Serialize);
        not_impl!(Bound, serde::Deserialize<'static>);
    }
    #[test]
    fn admission_prepared_production_keeps_full_verification_and_commit_before_bytes() {
        let production = include_str!("delivery_admission_v2.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap();
        let preparation = production
            .split("    fn prepare_original_delivery_observed(")
            .nth(1)
            .unwrap()
            .split("    /// Compatibility preview")
            .next()
            .unwrap();
        assert_eq!(preparation.matches("DurableReviewPayloadV1 {").count(), 1);
        assert_eq!(preparation.matches(".into_prepared_v2()").count(), 1);
        assert!(!preparation.contains("PreparedDurableReviewDeliveryV1"));
        let final_delivery = production
            .split("    fn deliver_prepared_observed(")
            .nth(1)
            .unwrap()
            .split("    fn verified(")
            .next()
            .unwrap();
        assert!(final_delivery.contains("self.verified(&history, access, &gate)?"));
        assert!(final_delivery
            .contains("self.delivery_output_actions(access, &history, &checkpoint, cause)?"));
        assert!(production.contains("self.original.load_original_verified("));
        assert!(
            production.contains("crate::durable_proposals_v1::original_review_output_actions_v2(")
        );
        assert!(!final_delivery.contains("DurableReviewPayloadV1 {"));
        assert!(!final_delivery.contains(".into_prepared_v2()"));
        assert!(!final_delivery.contains("payload.encode()"));
        assert!(!final_delivery.contains("payload.digest()"));
        let verify = final_delivery.find("self.verified(").unwrap();
        let source_compare = final_delivery
            .find("require_prepared_binding(&source, &actual_source")
            .unwrap();
        let intent = final_delivery
            .find("ExportExposure::DisclosedOrUnknown")
            .unwrap();
        let store = final_delivery.find(".update_agreement(").unwrap();
        let transport = final_delivery
            .find(".deliver_prepared_v2(payload, &check)")
            .unwrap();
        assert!(
            verify < source_compare
                && source_compare < intent
                && intent < store
                && store < transport
        );
        assert!(final_delivery.contains("result.map_err(disclosure_unknown)"));
        assert_eq!(final_delivery.matches("observation.freeze()").count(), 2);
        assert!(production.contains("full_history_digest: history.full_digest.clone()"));
        assert!(production.contains("prefix_history_digest: history.prefix_digest.clone()"));
        assert!(production.contains(
            "unsigned_digest: Sha256::digest(checkpoint.private_unsigned_pczt_bytes()).into()"
        ));
        assert!(
            production.contains("proved_digest: Sha256::digest(checkpoint.pczt_bytes()).into()")
        );
    }
    fn intent(operation: &str) -> ExportIntent {
        ExportIntent {
            scope: scope(operation),
            exposure: ExportExposure::DisclosedOrUnknown,
        }
    }
    fn cause_pair(cause: &ExportCause) -> Option<(&'static str, &'static str)> {
        match cause.first.get() {
            FirstExportCause::Seen(site, outcome) => Some((site.label(), outcome.label())),
            _ => None,
        }
    }
    #[test]
    fn admission_export_observation_forwards_owned_result_and_success_without_clone() {
        #[derive(Debug)]
        struct NotClone(Box<u8>);
        let cause = ExportCause::new();
        let value = NotClone(Box::new(7));
        let pointer = &*value.0 as *const u8;
        let returned =
            export_result(Some(&cause), ExportCauseSite::ExportPayload, Ok(value)).unwrap();
        assert_eq!(&*returned.0 as *const u8, pointer);
        assert_eq!(cause.first.get(), FirstExportCause::Vacant);

        let mut error = ApiError::new("RECOVERY_REQUIRED", "original lower cause");
        error.retryable = true;
        error.operation_id = Some("inert-operation".into());
        error.safe_actions = vec!["preserve original evidence".into()];
        error.details = Box::new(serde_json::json!({"retained": [1, 2, 3]}));
        let expected = serde_json::to_value(&error).unwrap();
        let message_pointer = error.message.as_ptr();
        let details_pointer = &*error.details as *const serde_json::Value;
        let returned = export_result::<()>(Some(&cause), ExportCauseSite::ExportIntake, Err(error))
            .unwrap_err();
        assert_eq!(serde_json::to_value(&returned).unwrap(), expected);
        assert_eq!(returned.message.as_ptr(), message_pointer);
        assert_eq!(
            &*returned.details as *const serde_json::Value,
            details_pointer
        );
        assert_eq!(
            cause_pair(&cause),
            Some(("ExportIntake", "EngineRecoveryRequired"))
        );
    }
    #[test]
    fn admission_export_first_cause_survives_bool_and_higher_denied_conversion() {
        let cause = ExportCause::new();
        let permitted = proof_permission(
            Some(&cause),
            || {
                export_result(
                    Some(&cause),
                    ExportCauseSite::ExportMaterialCeilings,
                    Err(ApiError::new("not-a-public-code", "private lower detail")),
                )
            },
            || panic!("the original first failure must short circuit permission"),
        );
        assert!(!permitted);
        assert!(!export_predicate(
            Some(&cause),
            ExportCauseSite::ExportProofPermission,
            permitted
        ));
        let terminal = cause
            .attach(export_result::<()>(
                Some(&cause),
                ExportCauseSite::ExportEntry,
                Err(denied()),
            ))
            .unwrap_err();
        assert_eq!(terminal.code, "DISCLOSURE_DENIED");
        assert_eq!(
            terminal.details[EXPORT_CAUSE_KEY],
            serde_json::json!({
                "version": 1, "site": "ExportMaterialCeilings", "outcome": "EngineUnclassified",
            })
        );
        assert!(!serde_json::to_string(&terminal.details)
            .unwrap()
            .contains("private lower detail"));
        assert!(!serde_json::to_string(&terminal.details)
            .unwrap()
            .contains("not-a-public-code"));
    }
    #[test]
    fn admission_export_proof_permission_preserves_every_short_circuit_and_none_path() {
        for observed in [false, true] {
            for (failed_check, allowed, expected_calls, expected_decisions, expected) in [
                (Some(1), true, 1, 0, false),
                (None, false, 1, 1, false),
                (Some(2), true, 2, 1, false),
                (None, true, 2, 1, true),
            ] {
                let cause = ExportCause::new();
                let observation = observed.then_some(&cause);
                let calls = std::cell::Cell::new(0);
                let decisions = std::cell::Cell::new(0);
                let trace = std::cell::RefCell::new(Vec::new());
                let actual = proof_permission(
                    observation,
                    || {
                        calls.set(calls.get() + 1);
                        trace.borrow_mut().push("check");
                        if failed_check == Some(calls.get()) {
                            Err(damaged())
                        } else {
                            Ok(())
                        }
                    },
                    || {
                        decisions.set(decisions.get() + 1);
                        trace.borrow_mut().push("permission");
                        allowed
                    },
                );
                assert_eq!(actual, expected);
                assert_eq!(calls.get(), expected_calls);
                assert_eq!(decisions.get(), expected_decisions);
                let expected_trace = if expected_decisions == 0 {
                    vec!["check"]
                } else if expected_calls == 1 {
                    vec!["check", "permission"]
                } else {
                    vec!["check", "permission", "check"]
                };
                assert_eq!(*trace.borrow(), expected_trace);
                if !observed || expected {
                    assert_eq!(cause.first.get(), FirstExportCause::Vacant);
                } else {
                    assert_eq!(
                        cause_pair(&cause),
                        Some((
                            "ExportProofPermission",
                            if failed_check.is_some() {
                                "EngineRecoveryRequired"
                            } else {
                                "PredicateDenied"
                            }
                        ))
                    );
                }
            }
        }
    }
    #[test]
    fn admission_export_delivery_permission_preserves_boolean_precedence() {
        for observed in [false, true] {
            for (proof, export) in [(false, false), (false, true), (true, false), (true, true)] {
                let cause = ExportCause::new();
                let calls = std::cell::RefCell::new(Vec::new());
                let actual = delivery_permission(
                    observed.then_some(&cause),
                    || {
                        calls.borrow_mut().push("proof");
                        proof
                    },
                    || {
                        calls.borrow_mut().push("export");
                        export
                    },
                );
                assert_eq!(actual, proof && export);
                assert_eq!(
                    *calls.borrow(),
                    if proof {
                        vec!["proof", "export"]
                    } else {
                        vec!["proof"]
                    }
                );
                if observed && !actual {
                    assert_eq!(
                        cause_pair(&cause),
                        Some((
                            if proof {
                                "ExportPermission"
                            } else {
                                "ExportProofPermission"
                            },
                            "PredicateDenied"
                        ))
                    );
                } else {
                    assert_eq!(cause.first.get(), FirstExportCause::Vacant);
                }
            }
        }
    }
    #[test]
    fn admission_export_recipient_missing_or_invalid_evidence_blocks_later_cause() {
        for diagnostic in [
            None,
            recipient_cause("RecipientDeadline", "OriginAuthentication"),
            recipient_cause("ExportProofCurrent", "BridgePermission"),
            recipient_cause("private-account", "BridgePermission"),
        ] {
            let cause = ExportCause::new();
            let actual = recipient_result::<()>(&cause, Err(BridgeError::Permission), diagnostic);
            assert!(matches!(actual, Err(BridgeError::Permission)));
            let terminal = cause
                .attach(export_result::<()>(
                    Some(&cause),
                    ExportCauseSite::ExportEntry,
                    Err(denied()),
                ))
                .unwrap_err();
            assert_eq!(cause.first.get(), FirstExportCause::Unavailable);
            assert!(terminal.details.get(EXPORT_CAUSE_KEY).is_none());
        }
        let cause = ExportCause::new();
        let result = recipient_result(
            &cause,
            Ok(Box::new(7)),
            recipient_cause("RecipientDeadline", "BridgePermission"),
        );
        assert_eq!(*result.unwrap(), 7);
        assert_eq!(cause.first.get(), FirstExportCause::Vacant);
    }
    #[test]
    fn admission_export_recipient_inventory_is_closed_and_stage_specific() {
        assert_eq!(ExportCauseSite::ALL.len(), 37);
        assert_eq!(ExportCauseOutcome::ALL.len(), 48);
        for site in ExportCauseSite::ALL {
            assert_eq!(ExportCauseSite::from_label(site.label()), Some(*site));
        }
        for outcome in ExportCauseOutcome::ALL {
            assert_eq!(
                ExportCauseOutcome::from_label(outcome.label()),
                Some(*outcome)
            );
        }
        for (site, outcome) in [
            ("RecipientMutex", "BridgeIpc"),
            ("RecipientDeadline", "BridgePermission"),
            ("RecipientOrigin", "BridgeSignerOriginUnavailable"),
            ("RecipientObserverClone", "OriginIoOther"),
            ("RecipientWriteSerialize", "BridgeBinding"),
            ("RecipientWriteLimit", "BridgeLimit"),
            ("RecipientWriteDeadline", "BridgePermission"),
            ("RecipientWriteTimeout", "OriginIoTimedOut"),
            ("RecipientWriteIo", "OriginIoBrokenPipe"),
            ("RecipientWriteEmpty", "BridgeIpc"),
            ("RecipientFrame", "OriginAuthentication"),
            ("RecipientResponseDecode", "BridgeBinding"),
            ("RecipientResponseDigest", "BridgeBinding"),
            ("RecipientResponse", "BridgePermission"),
        ] {
            assert!(recipient_cause(site, outcome).is_some());
            assert!(recipient_cause(site, "EngineDisclosureDenied").is_none());
            assert!(recipient_cause(site, "PredicateDenied").is_none());
            assert!(recipient_cause(site, "OriginSecretPrivateData").is_none());
        }
        assert!(recipient_cause("RecipientFrame", "BridgePermission").is_none());
        assert!(recipient_cause("RecipientDeadline", "OriginAuthentication").is_none());
        assert!(recipient_cause("RecipientUnknown", "BridgePermission").is_none());
    }
    #[test]
    fn admission_export_sidecar_is_additive_terminal_only_and_collision_safe() {
        let cause = ExportCause::new();
        export_predicate(Some(&cause), ExportCauseSite::ExportPermission, false);
        let mut error = ApiError::new("DISCLOSURE_DENIED", "keep original message");
        error.retryable = true;
        error.operation_id = Some("original-operation".into());
        error.safe_actions = vec!["original-action".into()];
        error.details = Box::new(serde_json::json!({"original": {"nested": [1, 2]}}));
        let expected = serde_json::to_value(&error).unwrap();
        let message_pointer = error.message.as_ptr();
        let details_pointer = &*error.details as *const serde_json::Value;
        let mut returned = cause.attach::<()>(Err(error)).unwrap_err();
        assert_eq!(returned.message.as_ptr(), message_pointer);
        assert_eq!(
            &*returned.details as *const serde_json::Value,
            details_pointer
        );
        assert_eq!(
            returned
                .details
                .as_object_mut()
                .unwrap()
                .remove(EXPORT_CAUSE_KEY)
                .unwrap(),
            serde_json::json!({
                "version": 1, "site": "ExportPermission", "outcome": "PredicateDenied",
            })
        );
        assert_eq!(serde_json::to_value(&returned).unwrap(), expected);
        assert_eq!(cause.attach(Ok(17)).unwrap(), 17);

        for details in [
            serde_json::Value::Null,
            serde_json::json!([]),
            serde_json::json!("original"),
        ] {
            let mut error = denied();
            error.details = Box::new(details);
            let expected = serde_json::to_value(&error).unwrap();
            let actual = cause.attach::<()>(Err(error)).unwrap_err();
            assert_eq!(serde_json::to_value(actual).unwrap(), expected);
        }
    }
    #[test]
    fn admission_export_collisions_are_marked_before_vacant_unavailable_or_frozen() {
        for state in [
            FirstExportCause::Vacant,
            FirstExportCause::Unavailable,
            FirstExportCause::Seen(
                ExportCauseSite::ExportPermission,
                ExportCauseOutcome::PredicateDenied,
            ),
        ] {
            for frozen in [false, true] {
                for collision in [
                    serde_json::Value::Null,
                    serde_json::json!({
                        "version":1,"site":"RecipientDeadline","outcome":"BridgePermission"
                    }),
                ] {
                    let cause = ExportCause::new();
                    cause.first.set(state);
                    if frozen {
                        cause.freeze();
                    }
                    let mut error = denied();
                    error.details = Box::new(
                        serde_json::json!({EXPORT_CAUSE_KEY: collision, "original": true}),
                    );
                    let expected = serde_json::to_value(&error).unwrap();
                    let mut actual = cause.attach::<()>(Err(error)).unwrap_err();
                    assert_eq!(
                        actual
                            .details
                            .as_object_mut()
                            .unwrap()
                            .remove(EXPORT_CAUSE_COLLISION_KEY),
                        Some(serde_json::Value::Bool(true))
                    );
                    assert_eq!(serde_json::to_value(actual).unwrap(), expected);
                }
                for marker in [
                    serde_json::Value::Null,
                    serde_json::json!(false),
                    serde_json::json!(1),
                    serde_json::json!("pre-existing"),
                    serde_json::json!([]),
                    serde_json::json!({"old":true}),
                ] {
                    for has_cause in [false, true] {
                        let cause = ExportCause::new();
                        cause.first.set(state);
                        if frozen {
                            cause.freeze();
                        }
                        let mut error = denied();
                        error.details = Box::new(
                            serde_json::json!({EXPORT_CAUSE_COLLISION_KEY: marker, "original": true}),
                        );
                        if has_cause {
                            error.details.as_object_mut().unwrap().insert(EXPORT_CAUSE_KEY.into(), serde_json::json!({
                                "version":1,"site":"RecipientDeadline","outcome":"BridgePermission"
                            }));
                        }
                        let expected = serde_json::to_value(&error).unwrap();
                        let actual = cause.attach::<()>(Err(error)).unwrap_err();
                        assert_eq!(serde_json::to_value(actual).unwrap(), expected);
                    }
                }
            }
        }
    }
    #[test]
    fn admission_export_frozen_vacant_preserves_unknown_and_cannot_claim_entry() {
        let cause = ExportCause::new();
        cause.freeze();
        let mut original = denied();
        original.operation_id = Some("retained-operation".into());
        original.safe_actions = vec!["preserve".into()];
        original.details = Box::new(serde_json::json!({"original_detail": true}));
        let unknown = disclosure_unknown(original);
        let expected = serde_json::to_value(&unknown).unwrap();
        let actual = cause
            .attach(export_result::<()>(
                Some(&cause),
                ExportCauseSite::ExportEntry,
                Err(unknown),
            ))
            .unwrap_err();
        assert_eq!(serde_json::to_value(&actual).unwrap(), expected);
        assert_eq!(cause.first.get(), FirstExportCause::Vacant);
        assert_eq!(actual.details["original_code"], "DISCLOSURE_DENIED");
        assert_eq!(actual.details["disclosure_state"], "disclosed_or_unknown");
        assert!(actual.details.get(EXPORT_CAUSE_KEY).is_none());

        let prior = ExportCause::new();
        export_predicate(Some(&prior), ExportCauseSite::ExportPermission, false);
        prior.freeze();
        let unknown = disclosure_unknown(denied());
        let expected = serde_json::to_value(&unknown).unwrap();
        let mut actual = prior.attach::<()>(Err(unknown)).unwrap_err();
        actual
            .details
            .as_object_mut()
            .unwrap()
            .remove(EXPORT_CAUSE_KEY);
        assert_eq!(serde_json::to_value(actual).unwrap(), expected);
    }
    #[test]
    fn admission_export_collectors_are_invocation_local_and_success_is_silent() {
        let first = ExportCause::new();
        let second = ExportCause::new();
        assert!(export_predicate(
            Some(&first),
            ExportCauseSite::ExportPermission,
            true
        ));
        assert_eq!(first.first.get(), FirstExportCause::Vacant);
        assert!(!export_predicate(
            Some(&first),
            ExportCauseSite::ExportPermission,
            false
        ));
        let terminal = second.attach::<()>(Err(denied())).unwrap_err();
        assert!(terminal.details.get(EXPORT_CAUSE_KEY).is_none());
        assert_eq!(second.first.get(), FirstExportCause::Vacant);
    }
    #[test]
    fn admission_export_actual_replay_scope_and_suffix_predicates_remain_exact() {
        let original = scope("inert-review");
        let mut changed = original.clone();
        changed.recipient.local_channel_digest = "cd".repeat(32);
        for observation in [false, true] {
            let cause = ExportCause::new();
            assert!(replay_scope_matches(
                observation.then_some(&cause),
                &original,
                &original
            ));
            assert!(!replay_scope_matches(
                observation.then_some(&cause),
                &changed,
                &original
            ));
            if observation {
                assert_eq!(
                    cause_pair(&cause),
                    Some(("ExportReplayScope", "PredicateDenied"))
                );
            } else {
                assert_eq!(cause.first.get(), FirstExportCause::Vacant);
            }
        }
        let cause = ExportCause::new();
        let mut exports = BTreeMap::new();
        exports.insert("wrong-key".into(), intent("different-operation"));
        let expected = added_export(&BTreeMap::new(), &exports).err().unwrap();
        let actual = added_export_observed(&BTreeMap::new(), &exports, Some(&cause))
            .err()
            .unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        assert_eq!(cause_pair(&cause), Some(("ExportDelta", "PredicateDenied")));
    }
    #[test]
    fn admission_owner_is_nominal_nonclone_and_nonserializable() {
        trait AmbiguousIfClone<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}
        let _ = <PrivateDurableAdmissionCoordinatorV2<'static> as AmbiguousIfClone<_>>::marker;
        trait AmbiguousIfSerialize<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
        impl<T: ?Sized + Serialize> AmbiguousIfSerialize<u8> for T {}
        let _ = <PrivateDurableAdmissionCoordinatorV2<'static> as AmbiguousIfSerialize<_>>::marker;
        trait AmbiguousIfDeserialize<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
        impl<T: serde::de::DeserializeOwned> AmbiguousIfDeserialize<u8> for T {}
        let _ =
            <PrivateDurableAdmissionCoordinatorV2<'static> as AmbiguousIfDeserialize<_>>::marker;
    }
    #[test]
    fn admission_metadata_profile_preserves_precursor_eight_event_bound() {
        for revision in -1..=18 {
            assert_eq!(
                OriginalMetadataProfileV2::Precursor.accepts_revision(revision),
                (0..=8).contains(&revision)
            );
            assert_eq!(
                OriginalMetadataProfileV2::Admission.accepts_revision(revision),
                (8..=16).contains(&revision)
            );
        }
        assert_eq!(PREFIX_KINDS.len(), 8);
        assert_eq!(PREFIX_KINDS[7], "private_verified_fixed_frozen_v2");
        assert!(!PREFIX_KINDS.contains(&EXPORT_EVENT));
    }
    #[test]
    fn admission_export_request_binds_revision_recipient_payload_and_sources() {
        let access = Access {
            principal_id: "operator".into(),
            ..Access::default()
        };
        let original = scope("original-review");
        let command = export_command(&access, 8, &original).unwrap();
        assert!(command.idempotency_key.len() <= 128);
        assert_eq!(
            command.idempotency_key,
            export_command(&access, 9, &original)
                .unwrap()
                .idempotency_key
        );
        assert_ne!(
            command.request_digest,
            export_command(&access, 9, &original)
                .unwrap()
                .request_digest
        );
        let mut changes = Vec::new();
        let mut s = original.clone();
        s.payload_digest = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.payload_length += 1;
        changes.push(s);
        let mut s = original.clone();
        s.recipient.local_channel_digest = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.recipient.signer_process_instance = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.recipient.local_grant_id = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.recipient.request.accepted_manifest_ref = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.sources[0].material_digest = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.proposal.proved_artifact_digest = "cd".repeat(32);
        changes.push(s);
        for changed in changes {
            assert_ne!(
                command.request_digest,
                export_command(&access, 8, &changed).unwrap().request_digest
            );
        }
        let long = scope(&"a".repeat(128));
        assert!(export_command(&access, 8, &long).is_ok());
    }
    #[test]
    fn admission_suffix_preserves_every_exposure_and_exact_eight_intent_cap() {
        let mut saved = BTreeMap::new();
        for i in 0..MAX_EXPORT_INTENTS {
            let id = format!("review-{i}");
            let mut next = saved.clone();
            next.insert(id.clone(), intent(&id));
            let (actual, _) = added_export(&saved, &next).unwrap();
            assert_eq!(actual, id);
            assert!(added_export(&next, &next).is_err());
            if i > 0 {
                let mut tampered = next.clone();
                tampered.get_mut("review-0").unwrap().scope.payload_length += 1;
                assert!(added_export(&saved, &tampered).is_err());
            }
            saved = next;
        }
        let mut ninth = saved.clone();
        ninth.insert("review-8".into(), intent("review-8"));
        assert!(added_export(&saved, &ninth).is_err());
        let mut replacement = saved.clone();
        replacement.remove("review-0");
        replacement.insert("review-other".into(), intent("review-other"));
        assert!(added_export(&saved, &replacement).is_err());
        let mut wrong_key = BTreeMap::new();
        wrong_key.insert("different".into(), intent("review"));
        assert!(added_export(&BTreeMap::new(), &wrong_key).is_err());
    }
    #[test]
    fn admission_exposure_cannot_decode_as_recalled_or_cancelled() {
        let encoded = serde_json::to_string(&intent("review")).unwrap();
        assert!(encoded.contains("disclosed_or_unknown"));
        for substitute in ["not_shared", "cancelled", "recalled", "acknowledged"] {
            assert!(serde_json::from_str::<ExportIntent>(
                &encoded.replace("disclosed_or_unknown", substitute)
            )
            .is_err());
        }
        let mut value = serde_json::to_value(intent("review")).unwrap();
        value["extra"] = true.into();
        assert!(serde_json::from_value::<ExportIntent>(value).is_err());
    }
    #[test]
    fn admission_prefix_digest_is_independent_of_export_suffix() {
        let prefix = (0..8)
            .map(|n| serde_json::json!({"original":n}))
            .collect::<Vec<_>>();
        let original = digest("wholepact:private-exact-operation-history:v2", &prefix).unwrap();
        let mut full = prefix.clone();
        let before = digest("wholepact:private-admission-export-history:v2", &full).unwrap();
        full.push(serde_json::json!({"export":"disclosed_or_unknown"}));
        assert_eq!(
            original,
            digest("wholepact:private-exact-operation-history:v2", &full[..8]).unwrap()
        );
        assert_ne!(
            before,
            digest("wholepact:private-admission-export-history:v2", &full).unwrap()
        );
    }
    #[test]
    fn admission_unknown_commit_keeps_cause_and_forbids_blind_retry() {
        let error = disclosure_unknown(ApiError::new("DISCLOSURE_DENIED", "expired after commit"));
        assert_eq!(error.code, "DISCLOSURE_UNKNOWN");
        assert!(!error.retryable);
        assert_eq!(error.details["original_code"], "DISCLOSURE_DENIED");
        assert_eq!(error.details["disclosure_state"], "disclosed_or_unknown");
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod request_history_tests {
    mod durable_financial_v2_state_tests {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/durable_proposals_v1/private_financial_v2_tests.rs"));
    }
    // Inert mathematical/source-row components only. No marked original,
    // native approval, sealed recipient, proof or coordinator is manufactured.
    use super::*;
    use crate::durable_construction_v1::{Intake, Roster};
    use crate::{
        candidates::{CheckpointReceipt, OriginalCheckpointRequestV2},
        CandidateRequest,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wholepact_core::*;
    use wholepact_proof_jobs::{JobState, JobSummary};
    use wholepact_protocol::construction::{ConstructionContext, OwnedContribution, PROFILE_ID};
    use wholepact_protocol::durable_proposal_v1::canonical_durable_account_id;
    use wholepact_protocol::review::encode_testnet_receiver;
    use wholepact_signer::authority_bridge::durable_construction_v1::{
        DurableConstructionOutboxV1, DurableConstructionRequestV1, HistoricalConstructionMaterialV1,
    };
    use wholepact_signer::consent_journal::TransportIdentityBinding;
    use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
        ConstructionRecipientV1, ConstructionReviewerV1, DurableConstructionScopeV1, PURPOSE,
    };
    use wholepact_wallet::wallet::synthetic_scanned_contributions;
    fn checked<T, E>(r: std::result::Result<T, E>) -> T {
        match r {
            Ok(v) => v,
            Err(_) => panic!("inert admission history component failed"),
        }
    }
    fn amount(n: u64) -> Amount {
        Amount::from_zatoshis(n).unwrap()
    }
    fn hash(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }
    struct Fixture {
        agreement: AgreementDraft,
        request: CandidateRequest,
        chain: ConstructionContext,
        packages: Vec<OwnedContribution>,
        account_ids: Vec<String>,
        selection: wholepact_wallet::wallet::SelectionContext,
    }
    fn fixture() -> Fixture {
        let (wallets, selection) = synthetic_scanned_contributions().unwrap();
        let receiver = encode_testnet_receiver(&wallets[0].notes()[0].note.recipient());
        // The scanner fixture's owner-a/owner-b labels are not durable account
        // identities. Derive the same canonical IDs from the actual scanned FVKs
        // before constructing the candidate, policy, receipt, or proof.
        let account_ids: Vec<_> = wallets
            .iter()
            .map(|w| canonical_durable_account_id(w.fvk()))
            .collect();
        let agreement = AgreementDraft {
            schema_version: 1,
            agreement_id: "scanner-to-engine-synthetic".into(),
            obligation_id: "never-funded-obligation".into(),
            revision: 1,
            purpose: "Synthetic scanner to candidate qualification; no network or funds".into(),
            organizer_identity: "fixture-organizer".into(),
            network_profile_id: PROFILE_ID.into(),
            recipients: vec![Recipient {
                recipient_id: "fixture-recipient".into(),
                address: receiver.clone(),
                amount: amount(300_000),
                memo: None,
                instruction_provenance: "Synthetic owner receiver, not a live payment".into(),
            }],
            funding_policy: FundingPolicy::Exact {
                target: amount(300_000),
            },
            fee_policy: FeePolicy::ProRata,
            privacy_profile: PrivacyProfile {
                mode: PrivacyMode::DeclaredOperator,
                proving_operator: Some("synthetic-local-constructor".into()),
                dedicated_accounts_required: true,
            },
            coordination_deadline: None,
            confirmation_policy: ConfirmationPolicy::default(),
            extensions: vec![],
        };
        let participants: Vec<_> = wallets
            .iter()
            .enumerate()
            .map(|(i, w)| ParticipantAllocation {
                participant_id: format!("participant-{i}"),
                account_id: account_ids[i].clone(),
                contribution: amount(if i == 0 { 100_000 } else { 200_000 }),
                fee_share: amount(if i == 0 { 5_000 } else { 10_000 }),
                fee_cap: amount(if i == 0 { 5_000 } else { 10_000 }),
                maximum_net_debit: amount(w.requested_debit_zatoshis()),
                charges: vec![],
            })
            .collect();
        let mut inputs = vec![];
        let mut outputs = vec![ClaimedOutput {
            output_id: "recipient-output".into(),
            address: receiver,
            amount: amount(300_000),
            allocation: OutputAllocation::Recipient {
                recipient_id: "fixture-recipient".into(),
            },
        }];
        for (i, w) in wallets.iter().enumerate() {
            for n in w.notes() {
                inputs.push(ClaimedInput {
                    input_id: n.input_id.clone(),
                    participant_id: participants[i].participant_id.clone(),
                    account_id: account_ids[i].clone(),
                    amount: amount(n.note.value().inner()),
                    ownership_evidence_ref: None,
                });
            }
            outputs.push(ClaimedOutput {
                output_id: format!("change-{i}"),
                address: encode_testnet_receiver(&w.change_address()),
                amount: amount(w.selected_zatoshis() - w.requested_debit_zatoshis()),
                allocation: OutputAllocation::Return {
                    participant_id: participants[i].participant_id.clone(),
                    account_id: account_ids[i].clone(),
                    ownership_evidence_ref: None,
                },
            });
        }
        let request = CandidateRequest {
            manifest: ProposalManifest {
                agreement: agreement.clone(),
                participants: participants.clone(),
                inputs,
                outputs,
                transaction_fee: amount(15_000),
                expiry_height: selection.tip_height + 30,
            },
            previous_candidate_id: None,
        };
        let chain = ConstructionContext {
            anchor: selection.anchor_root,
            anchor_height: selection.anchor_height,
            anchor_block_hash: selection.anchor_hash_protocol,
            target_height: selection.tip_height + 1,
        };
        let packages: Vec<_> = wallets
            .into_iter()
            .map(|w| {
                let mut contribution = w.into_contribution();
                contribution.account_id = canonical_durable_account_id(&contribution.fvk);
                contribution
            })
            .collect();
        Fixture {
            agreement,
            request,
            chain,
            packages,
            account_ids,
            selection,
        }
    }
    fn material(f: &Fixture, index: usize) -> HistoricalConstructionMaterialV1 {
        let owner = &f.packages[index];
        let notes: Vec<_> = owner.notes.iter().map(|n| {
                let mut fields = n.input_id.split(':');
                assert!(fields.next() == Some("ironwood"));
                let mut txid = checked(hex::decode(fields.next().unwrap_or("")));
                txid.reverse();
                let output_index = checked(fields.next().unwrap_or("").parse::<u16>());
                assert!(fields.next().is_none());
                json!({"input_id":n.input_id,"txid_protocol":hex::encode(txid),"output_index":output_index,
                    "recipient":hex::encode(n.note.recipient().to_raw_address_bytes()),
                    "value_zatoshis":n.note.value().inner(),"rho":hex::encode(n.note.rho().to_bytes()),
                    "rseed":hex::encode(n.note.rseed().as_bytes()),
                    "nullifier":hex::encode(n.note.nullifier(&owner.fvk).to_bytes()),
                    "commitment":hex::encode(orchard::note::ExtractedNoteCommitment::from(n.note.commitment()).to_bytes()),
                    "position":n.witness.position(),
                    "authentication_path":n.witness.auth_path().iter().map(|p|hex::encode(p.to_bytes())).collect::<Vec<_>>()})
            }).collect();
        let c = &f.selection;
        checked(HistoricalConstructionMaterialV1::decode(&checked(
            serde_json::to_vec(&json!({
                "version":1,"account_id":owner.account_id,"fvk_hex":hex::encode(owner.fvk.to_bytes()),
                "fvk_digest":hex::encode(Sha256::digest(owner.fvk.to_bytes())),
                "selected_zatoshis":owner.notes.iter().map(|n|n.note.value().inner()).sum::<u64>(),
                "requested_debit_zatoshis":f.request.manifest.participants[index].maximum_net_debit.as_zatoshis(),
                "change_address":hex::encode(owner.change_address.to_raw_address_bytes()),
                "birthday_height":c.anchor_height,
                "context":{"tip_height":c.tip_height,"tip_hash_protocol":hex::encode(c.tip_hash_protocol),
                    "anchor_height":c.anchor_height,"anchor_hash_protocol":hex::encode(c.anchor_hash_protocol),
                    "anchor_root":hex::encode(c.anchor_root)},
                "source":{"source_id":"inert-engine-math-component","endpoint":"https://component.invalid",
                    "trust_profile":"single_tls_provider_report_not_consensus","network":"test",
                    "branch_id":"0x77190ad9","lightwalletd_version":"synthetic-component",
                    "backend_subversion":"synthetic-no-backend","protocol_version":"synthetic-component-v1",
                    "request_started":1800000000u64,"observed_at":1800000001u64,"valid_until":1800000060u64},
                "notes":notes
            })),
        )))
    }
    fn outbox(
        proposal: &ProposalInput,
        material: HistoricalConstructionMaterialV1,
        index: usize,
        destination: &Path,
        valid_from: u64,
        valid_until: u64,
    ) -> DurableConstructionOutboxV1 {
        let grant = hash(0x20 + index as u8);
        let channel = hash(0x30 + index as u8);
        let grant_id = hash(0x40 + index as u8);
        let principal = "synthetic-local-constructor";
        let scope = DurableConstructionScopeV1 {
            version: 2,
            purpose: PURPOSE.into(),
            proposal: proposal.clone(),
            account_id: proposal.manifest.participants[index].account_id.clone(),
            participant_id: proposal.manifest.participants[index].participant_id.clone(),
            privacy_domain: "inert-private-component".into(),
            constructor: ConstructionRecipientV1 {
                principal_id: principal.into(),
                authenticated_local_grant_digest: grant.clone(),
            },
            prover: ConstructionRecipientV1 {
                principal_id: principal.into(),
                authenticated_local_grant_digest: grant.clone(),
            },
            reviewers: proposal
                .manifest
                .participants
                .iter()
                .map(|p| ConstructionReviewerV1::local_installed_signer(p.account_id.clone()))
                .collect(),
            protected_destination: destination.to_str().unwrap().into(),
            retention_policy: "temporary inert encrypted component".into(),
            valid_from_unix_seconds: valid_from,
            valid_until_unix_seconds: valid_until,
            minimum_confirmations: 1,
            maximum_scan_blocks: 100,
        };
        let verified = checked(Proposal::validate(proposal.clone()));
        let transport = TransportIdentityBinding::LocalProcess {
            transport_identity_id: grant_id.clone(),
            channel_key_digest: grant.clone(),
            channel_binding_digest: channel.clone(),
            uid: 42,
            pid: 100 + index as u32,
            process_instance: hash(0x50 + index as u8),
            signer_generation: 1,
            account_id: scope.account_id.clone(),
            agreement_id: proposal.manifest.agreement.agreement_id.clone(),
            participant_id: scope.participant_id.clone(),
            manifest_digest: verified.manifest_digest().into(),
        };
        let request = DurableConstructionRequestV1 {
            operation_id: format!("inert-math-operation-{index}"),
            enrollment_ref: hash(0x60 + index as u8),
            accepted_manifest_ref: hash(0x70 + index as u8),
            scope,
            material,
        };
        let request_digest = checked(request.digest());
        let material_digest = checked(request.material.digest());
        let review = hash(0x80 + index as u8);
        let entry = hash(0x90 + index as u8);
        let reference = checked(wholepact_core::proposal::canonical_digest(
            "wholepact:durable-construction-consent-outbox:v1",
            &(
                &request_digest,
                &material_digest,
                &review,
                &entry,
                &grant,
                &channel,
                &grant_id,
                &transport,
                Option::<serde_json::Value>::None,
            ),
        ));
        let value = checked(serde_json::from_value(
            json!({"request":request,"request_digest":request_digest,
                "material_digest":material_digest,"native_review_digest":review,"native_entry_digest":entry,
                "recipient_grant_digest":grant,"original_channel_digest":channel,"original_grant_id":grant_id,
                "recipient_transport":transport,"reference":reference}),
        ));
        let value: DurableConstructionOutboxV1 = value;
        checked(value.validate());
        value
    }
    #[test]
    fn admission_prepared_material_scope_absolute_ceilings_do_not_renew() {
        // Reuse only the existing inert mathematical scope fixture and the
        // exact check_valid_at kernel called by stage_materials_v3. No native
        // grant, original coordinator, recipient or successful delivery exists.
        let fixture = fixture();
        let candidate =
            crate::candidates::build_exact_candidate_v2(fixture.request.clone()).unwrap();
        let originals = (0..2)
            .map(|index| {
                outbox(
                    &candidate.proposal,
                    material(&fixture, index),
                    index,
                    Path::new("/inert/original"),
                    100,
                    200 + index as u64,
                )
            })
            .collect::<Vec<_>>();
        for (index, original) in originals.iter().enumerate() {
            let scope = &original.request().scope;
            let before = serde_json::to_value(scope).unwrap();
            let ceiling = 200 + index as u64;
            assert!(scope.check_valid_at(99).is_err());
            scope.check_valid_at(100).unwrap();
            scope.check_valid_at(ceiling - 1).unwrap();
            assert!(scope.check_valid_at(ceiling).is_err());
            assert!(scope.check_valid_at(ceiling + 1).is_err());
            assert_eq!(serde_json::to_value(scope).unwrap(), before);
        }
        assert!(originals[0].request().scope.check_valid_at(200).is_err());
        originals[1].request().scope.check_valid_at(200).unwrap();
    }
    fn advance(e: &Envelope) -> Envelope {
        let mut e = e.clone();
        e.view.revision += 1;
        e.view.updated_at = crate::now();
        e
    }
    struct SavedHistory {
        _dir: tempfile::TempDir,
        path: PathBuf,
        key: DatabaseKey,
        store: wholepact_store::Store,
        origin: [u8; 32],
        access: Access,
        envelopes: Vec<Envelope>,
        commands: Vec<CommandContext>,
        saved: Vec<MutationResult>,
    }
    fn saved_history() -> SavedHistory {
        saved_history_with_fixed_identity(|_| {})
    }
    fn saved_history_with_fixed_identity(
        prepare_identity: impl FnOnce(&mut FixedProposalIdentityV1),
    ) -> SavedHistory {
        let f = fixture();
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("inert-admission-history.sqlite");
        let key = DatabaseKey::from_bytes([143; 32]);
        let store = wholepact_store::Store::create_encrypted(&path, &key).unwrap();
        let origin = store.verify_original_encrypted_destination(&path).unwrap();
        let access = Access {
            principal_id: "synthetic-local-constructor".into(),
            include_owned_agreements: true,
            ..Access::default()
        };
        let seed_engine = Engine::in_memory().unwrap();
        seed_engine
            .create(&access, "inert-admission-create", f.agreement.clone())
            .unwrap();
        let record = seed_engine
            .store
            .get_agreement(&f.agreement.agreement_id)
            .unwrap()
            .unwrap();
        let mut seed = crate::decode_unprojected(&record).unwrap();
        seed.terms_editing_origin = false;
        seed.view.roster_selected = true;
        seed.view.progress = "preparing_proposal".into();
        assert!(seed.private_workspace_origin_v1.is_none());
        let seed_command = CommandContext::for_request(
            &access.principal_id,
            "inert-admission-seed",
            &json!({"inert_seed":true}),
        )
        .unwrap();
        let mut commands = vec![seed_command];
        let mut envelopes = vec![seed];
        let mut candidate = advance(&envelopes[0]);
        candidate
            .view
            .candidates
            .push(crate::candidates::build_exact_candidate_v2(f.request.clone()).unwrap());
        commands.push(
            crate::context(
                &access,
                "inert-admission-candidate",
                "private_prepare_exact_candidate_v2",
                &f.agreement.agreement_id,
                Some(1),
                &f.request,
            )
            .unwrap(),
        );
        envelopes.push(candidate);
        let c = envelopes[1].view.candidates[0].clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut roster = Roster::default();
        for i in 0..2 {
            let intake = Intake {
                schema_version: 1,
                principal_id: access.principal_id.clone(),
                metadata_origin: hex::encode(origin),
                signer_enrollment_reference: hash(0xa0 + i as u8),
                signer_process_instance: hash(0xb0 + i as u8),
                outbox: outbox(&c.proposal, material(&f, i), i, &path, now - 1, now + 3599),
            };
            let before = envelopes.last().unwrap();
            commands.push(
                crate::context(
                    &access,
                    &format!("inert-admission-intake-{i}"),
                    "private_retain_exact_material_v2",
                    &c.candidate_id,
                    Some(before.view.revision),
                    &(
                        &intake.metadata_origin,
                        intake.outbox.reference(),
                        intake.outbox.request_digest(),
                        intake.outbox.material_digest(),
                        &intake.signer_enrollment_reference,
                    ),
                )
                .unwrap(),
            );
            roster
                .owners
                .insert(intake.outbox.request().scope.account_id.clone(), intake);
            let mut after = advance(before);
            after.durable_construction_v1.insert(
                c.candidate_id.clone(),
                serde_json::to_value(&roster).unwrap(),
            );
            envelopes.push(after);
        }
        let original_key = "inert-admission-original-checkpoint";
        let original_command = crate::context(
            &access,
            original_key,
            "private_checkpoint_exact_original_v2",
            &c.candidate_id,
            Some(4),
            &json!({"local_input_digest":hash(0xc1),"maximum_actions":8}),
        )
        .unwrap();
        let receipt = CheckpointReceipt {
            original_request_v2: Some(OriginalCheckpointRequestV2 {
                command: original_command.clone(),
                expected_revision: 4,
                local_input_digest: hash(0xc1),
                maximum_actions: 8,
            }),
            action_mappings_v1: Some(json!({"inputs":[],"outputs":[]})),
            job_id: wholepact_proof_jobs::job_id_for_key(&access.principal_id, original_key)
                .unwrap(),
            scope_digest: hash(0xc2),
            principal_id: access.principal_id.clone(),
            candidate_id: c.candidate_id.clone(),
            manifest_digest: c.manifest_digest.clone(),
            coordination_request_digest: original_command.request_digest.clone(),
            artifact_digest: hash(0xc3),
            review_binding: hash(0xc4),
            effects_commitment: hash(0xc5),
            prepared_revision: 5,
        };
        let index = exact_fixed_v2::receipt_key(&access, original_key).unwrap();
        commands.push(
            crate::context(
                &access,
                &format!("prepare-{index}"),
                "private_prepare_constructor_receipt_v2",
                &c.candidate_id,
                Some(4),
                &receipt,
            )
            .unwrap(),
        );
        let mut after = advance(envelopes.last().unwrap());
        after.checkpoint_receipts.insert(index, receipt.clone());
        envelopes.push(after);
        let mut summary = JobSummary {
            job_id: receipt.job_id.clone(),
            scope_digest: receipt.scope_digest.clone(),
            candidate_id: c.candidate_id.clone(),
            state: JobState::Queued,
            attempt: 0,
            input_digest: receipt.artifact_digest.clone(),
            manifest_digest: c.manifest_digest.clone(),
            effects_commitment: receipt.effects_commitment.clone(),
            coordination_request_digest: original_command.request_digest.clone(),
            result_digest: None,
            review_binding: receipt.review_binding.clone(),
            encrypted_checkpoint_created: true,
            proof_verified: false,
            chain_validated: false,
            authorization_allowed: false,
            distribution_allowed: false,
        };
        let mut after = advance(envelopes.last().unwrap());
        crate::proof_jobs::upsert_link(&mut after, &summary).unwrap();
        commands.push(original_command.clone());
        envelopes.push(after);
        commands.push(
            crate::context(
                &access,
                "inert-admission-proof",
                "private_prove_original_once_v2",
                &c.candidate_id,
                Some(6),
                &(&summary.job_id, &original_command.request_digest),
            )
            .unwrap(),
        );
        summary.state = JobState::Succeeded;
        summary.attempt = 1;
        summary.proof_verified = true;
        summary.result_digest = Some(hash(0xc6));
        let mut after = advance(envelopes.last().unwrap());
        crate::proof_jobs::upsert_link(&mut after, &summary).unwrap();
        envelopes.push(after);
        commands.push(
            crate::context(
                &access,
                "inert-admission-freeze",
                "private_freeze_verified_fixed_v2",
                &c.candidate_id,
                Some(7),
                &(original_key, &receipt.coordination_request_digest, &summary),
            )
            .unwrap(),
        );
        let mut identity = FixedProposalIdentityV1 {
            schema_version: 1,
            network_profile_id: PROFILE_ID.into(),
            agreement_id: f.agreement.agreement_id.clone(),
            obligation_id: f.agreement.obligation_id.clone(),
            proposal_id: c.candidate_id.clone(),
            revision: 1,
            expiry_height: f.request.manifest.expiry_height,
            proposal_digest: c.proposal_digest.clone(),
            manifest_digest: c.manifest_digest.clone(),
            unsigned_artifact_digest: receipt.artifact_digest.clone(),
            proved_artifact_digest: hash(0xc6),
            effects_commitment: receipt.effects_commitment.clone(),
            policy_digest: hash(0xc7),
            review_binding: receipt.review_binding.clone(),
            action_mapping_digest: hash(0xc8),
            anchor: hash(0xc9),
            proposal_binding: hash(0xca),
        };
        prepare_identity(&mut identity);
        let mut after = advance(envelopes.last().unwrap());
        after.view.progress = "awaiting_authorization".into();
        after.durable_proposals_v1.insert(c.candidate_id.clone(),json!({"schema_version":1,"principal_id":access.principal_id,
            "proof_job_id":summary.job_id,"identity":identity,"mappings":receipt.action_mappings_v1,"intakes":{},"union":null}));
        envelopes.push(after);
        let mut saved = Vec::new();
        for (i, e) in envelopes.iter().enumerate() {
            operation_v1::validate_shape(e).unwrap();
            validate_prefix_command(
                i,
                &access,
                &commands[0],
                &commands[i],
                i.checked_sub(1).map(|n| &envelopes[n]),
                e,
            )
            .unwrap();
            if i == 0 {
                saved.push(
                    store
                        .create_agreement(
                            &commands[i],
                            &f.agreement.agreement_id,
                            crate::encode(e).unwrap(),
                        )
                        .unwrap(),
                );
            } else {
                saved.push(
                    store
                        .update_agreement(
                            &commands[i],
                            &f.agreement.agreement_id,
                            i as u64,
                            crate::encode(e).unwrap(),
                            PREFIX_KINDS[i],
                        )
                        .unwrap(),
                );
            }
        }
        require_completed_prefix(envelopes.last().unwrap()).unwrap();
        SavedHistory {
            _dir: dir,
            path,
            key,
            store,
            origin,
            access,
            envelopes,
            commands,
            saved,
        }
    }
    #[test]
    fn admission_original_requests_reconstruct_all_eight_saved_contexts() {
        let f = saved_history();
        let read = original_commands(&f.path, &f.key, f.origin).unwrap();
        assert_eq!(read.len(), 8);
        for i in 0..8 {
            let command = read.get(&f.saved[i].operation_id).unwrap();
            assert_eq!(
                serde_json::to_value(command).unwrap(),
                serde_json::to_value(&f.commands[i]).unwrap()
            );
            assert_eq!(
                f.store.find_replay(command).unwrap().unwrap().record,
                f.saved[i].record
            );
            let before = i.checked_sub(1).map(|n| &f.envelopes[n]);
            let mut changed = command.clone();
            changed.request_digest = hash(0xdd);
            assert!(validate_prefix_command(
                i,
                &f.access,
                &f.commands[0],
                &changed,
                before,
                &f.envelopes[i]
            )
            .is_err());
            if i > 0 {
                let mut prior = before.unwrap().clone();
                prior.view.revision += 1;
                if i != 5 {
                    assert!(validate_prefix_command(
                        i,
                        &f.access,
                        &f.commands[0],
                        command,
                        Some(&prior),
                        &f.envelopes[i]
                    )
                    .is_err());
                }
            }
        }
        for i in [0, 4, 5] {
            let mut command = f.commands[i].clone();
            command.idempotency_key.push('x');
            assert!(validate_prefix_command(
                i,
                &f.access,
                &f.commands[0],
                &command,
                i.checked_sub(1).map(|n| &f.envelopes[n]),
                &f.envelopes[i]
            )
            .is_err());
        }
        let mut mapping = f.envelopes[4].clone();
        mapping
            .checkpoint_receipts
            .values_mut()
            .next()
            .unwrap()
            .action_mappings_v1 =
            Some(json!({"inputs":[],"outputs":[{"output_id":"changed","action_index":0}]}));
        assert!(validate_prefix_command(
            4,
            &f.access,
            &f.commands[0],
            &f.commands[4],
            Some(&f.envelopes[3]),
            &mapping
        )
        .is_err());
        let mut summary = f.envelopes[7].clone();
        summary.view.candidates[0].proof_jobs[0].result_digest = Some(hash(0xee));
        assert!(validate_prefix_command(
            7,
            &f.access,
            &f.commands[0],
            &f.commands[7],
            Some(&f.envelopes[6]),
            &summary
        )
        .is_err());
        assert!(original_commands(&f.path, &f.key, [0; 32]).is_err());
    }
    #[test]
    fn admission_real_saved_suffix_changes_only_export_history_not_prefix() {
        use wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1;
        use wholepact_signer::authority_bridge::durable_review_ipc_v1::{
            DurableReviewDeliveryRequestV1, DurableReviewRecipientV1,
        };
        let f = saved_history();
        let before = f.envelopes.last().unwrap();
        let mut roster = original_roster_v2(before).unwrap();
        let own = roster.owners.values().next().unwrap();
        let identity: FixedProposalIdentityV1 = serde_json::from_value(
            before.durable_proposals_v1.values().next().unwrap()["identity"].clone(),
        )
        .unwrap();
        let scope = DurableReviewExportScopeV1 {
            schema_version: 1,
            principal_id: f.access.principal_id.clone(),
            proposal: identity.clone(),
            recipient: DurableReviewRecipientV1 {
                version: 1,
                request: DurableReviewDeliveryRequestV1 {
                    operation_id: "inert-exact-export".into(),
                    enrollment_ref: own.outbox.request().enrollment_ref.clone(),
                    accepted_manifest_ref: own.outbox.request().accepted_manifest_ref.clone(),
                    own_disclosure: DurableConstructionHistoryRequestV1 {
                        operation_id: own.outbox.request().operation_id.clone(),
                        expected_request_digest: own.outbox.request_digest().into(),
                    },
                    current_disclosure: None,
                    proposal_binding: identity.proposal_binding.clone(),
                },
                account_id: own.outbox.request().scope.account_id.clone(),
                participant_id: own.outbox.request().scope.participant_id.clone(),
                agreement_id: identity.agreement_id.clone(),
                manifest_digest: identity.manifest_digest.clone(),
                provider_enrollment_reference: hash(1),
                signer_process_instance: hash(2),
                local_grant_id: hash(3),
                local_channel_digest: hash(4),
            },
            sources: review_export_v1::sources(&roster).unwrap(),
            payload_digest: hash(5),
            payload_length: 123,
        };
        roster.review_exports.insert(
            scope.recipient.request.operation_id.clone(),
            ExportIntent {
                scope: scope.clone(),
                exposure: ExportExposure::DisclosedOrUnknown,
            },
        );
        let mut after = advance(before);
        after.durable_construction_v1.insert(
            identity.proposal_id.clone(),
            serde_json::to_value(roster).unwrap(),
        );
        assert_eq!(
            validate_export_delta(before, &after)
                .unwrap()
                .payload_digest,
            scope.payload_digest
        );
        assert!(operation_v1::validate_shape(&after).is_err());
        let command = export_command(&f.access, 8, &scope).unwrap();
        f.store
            .update_agreement(
                &command,
                &identity.agreement_id,
                8,
                crate::encode(&after).unwrap(),
                EXPORT_EVENT,
            )
            .unwrap();
        assert_eq!(
            original_commands(&f.path, &f.key, f.origin).unwrap().len(),
            8
        );
        assert_eq!(
            f.store.find_replay(&f.commands[7]).unwrap().unwrap().record,
            f.saved[7].record
        );
        assert!(
            PreparedPrivateDurableCoordinatorV1::check_initialized_original_v1(
                &f.path, &f.key, f.origin
            )
            .is_err()
        );
        PrivateDurableAdmissionCoordinatorV2::check_initialized_admission_original_v2(
            &f.path, &f.key, f.origin,
        )
        .unwrap();
        let mut altered = after.clone();
        altered
            .checkpoint_receipts
            .values_mut()
            .next()
            .unwrap()
            .artifact_digest = hash(6);
        assert!(validate_export_delta(before, &altered).is_err());
        let mut altered = after.clone();
        altered.view.candidates[0].proof_jobs[0].result_digest = Some(hash(6));
        assert!(validate_export_delta(before, &altered).is_err());
        let mut altered = after;
        altered.view.agreement.purpose.push('x');
        assert!(validate_export_delta(before, &altered).is_err());
    }
    #[test]
    fn admission_encrypted_v3_lineage_keeps_capture_refs_and_current_recipient_distinct() {
        use crate::durable_construction_v1::review_export_v3::{
            self, DurableReviewExportScopeV3, ExportIntentV3,
        };
        use wholepact_signer::authority_bridge::{
            durable_construction_v1::DurableConstructionHistoryRequestV1,
            durable_proposal_v1::manual_authorization_id,
            durable_review_ipc_v1::DurableReviewDeliveryRequestV1,
            durable_review_ipc_v3::RecipientIntentV3,
        };

        // DATA-only encrypted Store/Bridge/Engine component. The descriptors
        // below are inert claims, not native owners, a sealed recipient, a
        // verified proof, or permission to disclose. The genuine route is B1.
        let f = saved_history_with_fixed_identity(|identity| {
            // Canonicalize only this inert identity BEFORE its initial row is
            // saved. The default fixture remains byte-for-byte unchanged. This
            // encoding matches the private Protocol/Authority binding kernels;
            // actual Bridge validation below independently checks the result.
            let mut binding = Sha256::new();
            binding.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
            binding.update(identity.schema_version.to_le_bytes());
            binding.update(identity.revision.to_le_bytes());
            binding.update(identity.expiry_height.to_le_bytes());
            for value in [
                &identity.network_profile_id,
                &identity.agreement_id,
                &identity.obligation_id,
                &identity.proposal_id,
                &identity.proposal_digest,
                &identity.manifest_digest,
                &identity.unsigned_artifact_digest,
                &identity.proved_artifact_digest,
                &identity.effects_commitment,
                &identity.policy_digest,
                &identity.review_binding,
                &identity.action_mapping_digest,
                &identity.anchor,
            ] {
                binding.update((value.len() as u64).to_le_bytes());
                binding.update(value.as_bytes());
            }
            identity.proposal_binding = hex::encode(binding.finalize());
        });
        let agreement_id = &f.envelopes.last().unwrap().view.agreement.agreement_id;
        let before_record = checked(f.store.get_agreement(agreement_id)).unwrap();
        assert!(before_record == f.saved[7].record);
        let before_envelope = checked(decode_private_record(&before_record));
        let before = &before_envelope;
        let candidate = &before.view.candidates[0];
        let roster = checked(original_roster_v2(before));
        let own = roster.owners.values().next().unwrap();
        let identity: FixedProposalIdentityV1 = checked(serde_json::from_value(
            before.durable_proposals_v1[&candidate.candidate_id]["identity"].clone(),
        ));
        let material_scopes = checked(review_export_v3::material_scopes(&roster));
        let owners: Vec<_> = roster
            .owners
            .iter()
            .map(|(account, intake)| {
                json!({
                    "account_id": account,
                    "participant_id": intake.outbox.request().scope.participant_id,
                    "original_authorization_id": checked(manual_authorization_id(&identity, account)),
                })
            })
            .collect();
        let source = checked(serde_json::to_value(&own.outbox.request().material));
        let valid_from_ms = material_scopes
            .iter()
            .map(|s| s.valid_from_unix_seconds)
            .max()
            .unwrap()
            * 1000;
        let valid_until_ms = material_scopes
            .iter()
            .map(|s| s.valid_until_unix_seconds)
            .min()
            .unwrap()
            * 1000;
        let current_enrollment = hash(0xd1);
        let current_manifest = hash(0xd2);
        assert!(current_enrollment != own.outbox.request().enrollment_ref);
        assert!(current_manifest != own.outbox.request().accepted_manifest_ref);
        let recipient = RecipientIntentV3 {
            version: 3,
            request: DurableReviewDeliveryRequestV1 {
                operation_id: "inert-lineage-v3-export".into(),
                enrollment_ref: current_enrollment.clone(),
                accepted_manifest_ref: current_manifest.clone(),
                own_disclosure: DurableConstructionHistoryRequestV1 {
                    operation_id: own.outbox.request().operation_id.clone(),
                    expected_request_digest: own.outbox.request_digest().into(),
                },
                current_disclosure: Some(DurableConstructionHistoryRequestV1 {
                    operation_id: "inert-lineage-v3-redisclosure".into(),
                    expected_request_digest: hash(0xd3),
                }),
                proposal_binding: identity.proposal_binding.clone(),
            },
            fixed: identity.clone(),
            payload_digest: hash(0xd4),
            payload_bytes: 123,
            delivery: checked(serde_json::from_value(json!({
                "dispatcher": {
                    "principal_id": f.access.principal_id,
                    "public_identity_commitment": hash(0xd5),
                    "authentication_profile": "original_protected_host_dispatcher_v2",
                    "custody_policy_commitment": hash(0xd6),
                },
                "original_host_generation_binding_digest": hash(0xd7),
                "original_host_profile_id": "data-only-no-native-host",
                "submission_journal_identity": hash(0xd8),
                "submission_operation_id": "inert-lineage-v3-submission",
                "provider": {
                    "source_id": source["source"]["source_id"],
                    "endpoint": source["source"]["endpoint"],
                    "trust_profile": source["source"]["trust_profile"],
                },
                "route": {"kind": "direct"},
                "owners": owners,
                "valid_from_ms": valid_from_ms,
                "valid_until_ms": valid_until_ms,
                "minimum_expiry_margin_blocks": 1,
                "maximum_fresh_admission_lifetime_ms": 1000,
                "maximum_explicitly_approved_attempts": 1,
                "extraction_rule": "first_durably_retained_verified_extraction",
                "retry_rule": "same_retained_bytes_with_fresh_admission",
                "attempt_rule": "explicit_immediate_host_decision",
            }))),
            material_scopes,
            account_id: own.outbox.request().scope.account_id.clone(),
            participant_id: own.outbox.request().scope.participant_id.clone(),
            agreement_id: identity.agreement_id.clone(),
            manifest_digest: identity.manifest_digest.clone(),
            provider_enrollment_reference: own.signer_enrollment_reference.clone(),
            signer_process_instance: own.signer_process_instance.clone(),
            authorized_host_process_instance: hash(0xd9),
            source_identity_digest: hash(0xda),
            source_generation: 1,
            read_session_digest: hash(0xdb),
            receive_decision_digest: hash(0xdc),
            // These name the recipient's retained admission rows, not the
            // old capture rows committed by own_disclosure's complete digest.
            original_enrollment_ref: current_enrollment,
            original_manifest_ref: current_manifest,
        };
        let scope = DurableReviewExportScopeV3 {
            schema_version: 3,
            principal_id: f.access.principal_id.clone(),
            proposal: identity.clone(),
            sources: checked(review_export_v1::sources(&roster)),
            payload_digest: recipient.payload_digest.clone(),
            payload_length: recipient.payload_bytes,
            recipient,
        };
        #[cfg(feature = "coordinated-financial-workflow-v1")]
        {
            use wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_recipient_v1::CoordinatedRecipientIntentV1;
            use crate::durable_construction_v1::review_export_coordinated_v1::{self, CoordinatedDurableReviewExportScopeV1, CoordinatedExportIntentV1};
            // TEST DATA ONLY: independently construct inert coordinated history;
            // no recipient transport/source/action owner is created or converted.
            let r = &scope.recipient;
            let coordinated = CoordinatedRecipientIntentV1 {
                version: 1, request: r.request.clone(), fixed: r.fixed.clone(),
                payload_digest: r.payload_digest.clone(), payload_bytes: r.payload_bytes,
                delivery: r.delivery.clone(), material_scopes: r.material_scopes.clone(),
                account_id: r.account_id.clone(), participant_id: r.participant_id.clone(),
                agreement_id: r.agreement_id.clone(), manifest_digest: r.manifest_digest.clone(),
                coordinated_provider_reference: hash(0xe1), signer_process_instance: r.signer_process_instance.clone(),
                authorized_host_process_instance: r.authorized_host_process_instance.clone(),
                source_identity_digest: r.source_identity_digest.clone(), source_generation: 1,
                read_session_digest: r.read_session_digest.clone(), receive_decision_digest: r.receive_decision_digest.clone(),
                original_enrollment_ref: r.original_enrollment_ref.clone(), original_manifest_ref: r.original_manifest_ref.clone(),
            };
            checked(coordinated.validate());
            assert!(serde_json::from_value::<RecipientIntentV3>(checked(serde_json::to_value(&coordinated))).is_err());
            assert!(serde_json::from_value::<CoordinatedRecipientIntentV1>(checked(serde_json::to_value(r))).is_err());
            let export = CoordinatedDurableReviewExportScopeV1 {
                schema_version: 1, principal_id: scope.principal_id.clone(), proposal: scope.proposal.clone(),
                recipient: coordinated.clone(), sources: scope.sources.clone(),
                payload_digest: scope.payload_digest.clone(), payload_length: scope.payload_length,
            };
            checked(review_export_coordinated_v1::validate_recipient(&roster, candidate, &export));
            for field in 0..5 {
                let mut wrong = export.clone();
                match field {
                    0 => wrong.payload_digest = hash(0xe2),
                    1 => wrong.sources[0].request_digest = hash(0xe2),
                    2 => wrong.recipient.request.own_disclosure.expected_request_digest = hash(0xe2),
                    3 => wrong.proposal.proposal_digest = hash(0xe2),
                    _ => wrong.recipient.material_scopes[0].original_scope_digest = hash(0xe2),
                }
                assert!(review_export_coordinated_v1::validate_recipient(&roster, candidate, &wrong).is_err());
            }
            let mut coordinated_roster = roster.clone();
            let operation = coordinated.request.operation_id.clone();
            coordinated_roster.coordinated_review_exports_v1.insert(operation.clone(), CoordinatedExportIntentV1 { scope: export.clone(), exposure: ExportExposure::DisclosedOrUnknown });
            let digest = checked(coordinated.digest());
            assert!(financial_v1::coordinated_financial_recipient_v1(&coordinated_roster, &coordinated.account_id, &digest).is_ok());
            assert!(financial_v1::coordinated_financial_recipient_v1(&coordinated_roster, "other-account", &digest).is_err());
            assert!(financial_v1::coordinated_financial_recipient_v1(&coordinated_roster, &coordinated.account_id, &hash(0xe3)).is_err());
            let mut ambiguous = coordinated_roster.clone();
            ambiguous.coordinated_review_exports_v1.insert("duplicate".into(), CoordinatedExportIntentV1 { scope: export.clone(), exposure: ExportExposure::DisclosedOrUnknown });
            assert!(financial_v1::coordinated_financial_recipient_v1(&ambiguous, &coordinated.account_id, &digest).is_err());
            let mut mixed = coordinated_roster.clone();
            mixed.review_exports_v3.insert(operation, crate::durable_construction_v1::review_export_v3::ExportIntentV3 { scope: scope.clone(), exposure: ExportExposure::DisclosedOrUnknown });
            assert!(financial_v1::coordinated_financial_recipient_v1(&mixed, &coordinated.account_id, &digest).is_err());
            let mut after = before.clone();
            after.view.revision += 1;
            after.view.updated_at = crate::now();
            after.durable_construction_v1.insert(identity.proposal_id.clone(), checked(serde_json::to_value(&coordinated_roster)));
            assert!(checked(closed_review_v3::validate_coordinated_export_delta_v1(before, &after)) == export);
            assert!(closed_review_v3::validate_export_delta_v3(before, &after).is_err());
            let mut changed = after.clone();
            changed.checkpoint_receipts.values_mut().next().unwrap().artifact_digest = hash(0xe4);
            assert!(closed_review_v3::validate_coordinated_export_delta_v1(before, &changed).is_err());
        }
        let snapshot = || {
            checked(
                PrivateDurableAdmissionCoordinatorV2::check_initialized_admission_original_v2(
                    &f.path, &f.key, f.origin,
                ),
            );
            let events = checked(f.store.events_after(0, 17));
            let operations: Vec<_> = events
                .iter()
                .map(|event| checked(f.store.get_operation(&event.operation_id)).unwrap())
                .collect();
            checked(serde_json::to_vec(&(
                checked(f.store.list_agreements()),
                events,
                operations,
                checked(original_commands(&f.path, &f.key, f.origin)),
            )))
        };
        let original_rows = snapshot();
        let original_events = checked(f.store.events_after(0, 17));
        let original_operations: Vec<_> = original_events
            .iter()
            .map(|event| checked(f.store.get_operation(&event.operation_id)).unwrap())
            .collect();
        assert_eq!(original_events.len(), 8);
        assert!(f
            .commands
            .iter()
            .all(|command| command.idempotency_key.len() >= 16));
        checked(scope.recipient.validate());
        checked(review_export_v3::validate_recipient(
            &roster, candidate, &scope,
        ));

        // Every mutation below is still just a data check. In particular, an
        // attacker changing both fresh references coherently is NOT authenticated
        // or rejected by this comparison; the sealed native route owns that check.
        for mutation in 0..14 {
            let mut changed = scope.clone();
            match mutation {
                0 => {
                    changed.recipient.request.own_disclosure.operation_id = scope
                        .recipient
                        .request
                        .current_disclosure
                        .as_ref()
                        .unwrap()
                        .operation_id
                        .clone();
                }
                1 => {
                    changed
                        .recipient
                        .request
                        .own_disclosure
                        .expected_request_digest = scope
                        .recipient
                        .request
                        .current_disclosure
                        .as_ref()
                        .unwrap()
                        .expected_request_digest
                        .clone();
                }
                2 => changed.recipient.request.enrollment_ref = hash(0xee),
                3 => changed.recipient.request.accepted_manifest_ref = hash(0xee),
                4 => {
                    changed.recipient.original_enrollment_ref =
                        own.outbox.request().enrollment_ref.clone();
                }
                5 => {
                    changed.recipient.original_manifest_ref =
                        own.outbox.request().accepted_manifest_ref.clone();
                }
                6 => changed.recipient.request.current_disclosure = None,
                7 => changed.payload_digest = hash(0xee),
                8 => changed.payload_length += 1,
                9 => changed.sources[0].outbox_reference = hash(0xee),
                10 => changed.sources[0].request_digest = hash(0xee),
                11 => changed.sources[0].material_digest = hash(0xee),
                12 => changed.recipient.material_scopes[0].original_scope_digest = hash(0xee),
                13 => changed.recipient.material_scopes[0].valid_until_unix_seconds += 1,
                _ => unreachable!(),
            }
            if (2..=5).contains(&mutation) {
                assert!(changed.recipient.validate().is_err());
            } else {
                checked(changed.recipient.validate());
            }
            assert!(
                review_export_v3::validate_recipient(&roster, candidate, &changed).is_err(),
                "inert lineage substitution {mutation} was accepted"
            );
            assert!(snapshot() == original_rows);
        }
        assert!(snapshot() == original_rows);

        let mut exported = roster.clone();
        exported.review_exports_v3.insert(
            scope.recipient.request.operation_id.clone(),
            ExportIntentV3 {
                scope: scope.clone(),
                exposure: ExportExposure::DisclosedOrUnknown,
            },
        );
        let mut after = advance(before);
        after.durable_construction_v1.insert(
            identity.proposal_id.clone(),
            checked(serde_json::to_value(exported)),
        );
        assert!(checked(closed_review_v3::validate_export_delta_v3(before, &after)) == scope);
        let mut changed_prefix = after.clone();
        changed_prefix
            .checkpoint_receipts
            .values_mut()
            .next()
            .unwrap()
            .artifact_digest = hash(0xee);
        assert!(closed_review_v3::validate_export_delta_v3(before, &changed_prefix).is_err());
        assert!(snapshot() == original_rows);
        let command = checked(closed_review_v3::export_command_v3(&f.access, 8, &scope));
        assert!(command.idempotency_key.len() >= 16);
        assert!(checked(f.store.find_replay(&command)).is_none());
        let appended = checked(f.store.update_agreement(
            &command,
            &identity.agreement_id,
            8,
            checked(crate::encode(&after)),
            closed_review_v3::EXPORT_EVENT_V3,
        ));
        assert_eq!(appended.record.revision, 9);
        assert_eq!(appended.event_sequence, 9);
        assert!(!appended.replayed);

        drop(f.store);
        let reopened = checked(wholepact_store::Store::open_encrypted(&f.path, &f.key));
        assert!(reopened.protection() == wholepact_store::StorageProtection::Encrypted);
        assert!(checked(reopened.verify_original_encrypted_destination(&f.path)) == f.origin);
        checked(reopened.verify_integrity());
        checked(
            PrivateDurableAdmissionCoordinatorV2::check_initialized_admission_original_v2(
                &f.path, &f.key, f.origin,
            ),
        );
        let events = checked(reopened.events_after(0, 17));
        assert_eq!(events.len(), 9);
        assert!(events[..8] == original_events[..]);
        let prefix_commands = checked(original_commands(&f.path, &f.key, f.origin));
        assert_eq!(prefix_commands.len(), 8);
        for i in 0..8 {
            let event = &events[i];
            assert!(event.kind == PREFIX_KINDS[i]);
            assert!(event.operation_id == f.saved[i].operation_id);
            assert_eq!(event.aggregate_revision, (i + 1) as u64);
            let operation = checked(reopened.get_operation(&event.operation_id)).unwrap();
            assert!(operation == original_operations[i]);
            let saved: MutationResult = checked(serde_json::from_value(operation.result));
            assert!(saved == f.saved[i]);
            let original_command = &prefix_commands[&event.operation_id];
            assert!(
                checked(serde_json::to_value(original_command))
                    == checked(serde_json::to_value(&f.commands[i]))
            );
            assert!(
                checked(reopened.find_replay(original_command))
                    .unwrap()
                    .record
                    == f.saved[i].record
            );
        }
        assert!(events[8].kind == closed_review_v3::EXPORT_EVENT_V3);
        assert!(events[8].operation_id == appended.operation_id);
        let replay = checked(reopened.find_replay(&command)).unwrap();
        assert!(replay.record == appended.record);
        let reopened_record = checked(reopened.get_agreement(&identity.agreement_id)).unwrap();
        assert!(reopened_record == appended.record);
        let reopened_envelope = checked(decode_private_record(&reopened_record));
        assert!(
            checked(closed_review_v3::validate_export_delta_v3(
                before,
                &reopened_envelope
            )) == scope
        );
        let reopened_roster = checked(original_roster_v2(&reopened_envelope));
        assert_eq!(reopened_roster.owners.len(), 2);
        assert!(reopened_roster.review_exports.is_empty());
        assert_eq!(reopened_roster.review_exports_v3.len(), 1);
        for (account, original) in &roster.owners {
            let retained = &reopened_roster.owners[account];
            checked(retained.outbox.validate());
            assert!(retained.outbox == original.outbox);
        }
        assert!(
            checked(serde_json::to_value(&reopened_roster.owners))
                == checked(serde_json::to_value(&roster.owners))
        );
    }
}
