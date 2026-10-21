//! Closed original-source receive lifecycle. Public records are inert commitments;
//! only the retained installed provider and kernel process own a continuation.
use super::{durable_review_ipc_v1::{self as v1, DurableReviewDeliveryRequestV1, PreparedDurableReviewPayloadV2}, ipc::OriginalHistoryClient, BridgeError, Result};
use crate::native_peer::PeerProcess;
use serde::{Deserialize, Serialize};
use std::{os::{fd::AsRawFd, unix::net::UnixStream}, path::PathBuf, time::{Duration, Instant}};
pub use wholepact_authority::durable_delivery_scope_v2::{DurableDeliveryMaterialScopeRefV2, DurableDeliveryPlanV2};
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;

#[cfg(feature = "coordinated-financial-workflow-v1")]
pub mod coordinated_v1;
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub mod coordinated_recipient_v1;

pub(crate) const MAX_METADATA_V3: usize = 512 * 1024;

// Diagnostic data only. Every observer sees the original result once and
// returns it unchanged; production builds perform no diagnostic output.
fn emit_closed_observation_v3(_site:&'static str,_outcome:&'static str) {
    #[cfg(feature="synthetic-born-joined-qualification")]
    {
        use std::io::Write;
        let _=writeln!(&mut std::io::stderr().lock(),"\n[JOINED_DIAGNOSTIC {} {}]",_site,_outcome);
    }
}
pub(super) fn observe_origin_v3<T>(result:wholepact_signer_origin::Result<T>)->wholepact_signer_origin::Result<T> {
    #[cfg(feature="synthetic-born-joined-qualification")]
    if let Err(error)=&result {
        use wholepact_signer_origin::Error as E;
        let outcome=match error {
            E::PermanentStopUnavailable=>"OriginPermanentStopUnavailable",E::RetirementEvidenceUnavailable=>"OriginRetirementEvidenceUnavailable",
            E::SignerOriginUnavailable=>"OriginSignerOriginUnavailable",E::PeerLifetimeUnavailable=>"OriginPeerLifetimeUnavailable",
            E::Authentication=>"OriginAuthentication",E::Binding=>"OriginBinding",E::Conflict=>"OriginConflict",E::Permission=>"OriginPermission",E::InvalidData=>"OriginInvalidData",E::Locked=>"OriginLocked",E::Crypto=>"OriginCrypto",E::Ipc=>"OriginIpc",E::Limit=>"OriginLimit",
            E::Io(error)=>match error.kind() {
                std::io::ErrorKind::TimedOut=>"OriginIoTimedOut",std::io::ErrorKind::WouldBlock=>"OriginIoWouldBlock",std::io::ErrorKind::UnexpectedEof=>"OriginIoUnexpectedEof",std::io::ErrorKind::BrokenPipe=>"OriginIoBrokenPipe",std::io::ErrorKind::ConnectionReset=>"OriginIoConnectionReset",std::io::ErrorKind::ConnectionAborted=>"OriginIoConnectionAborted",std::io::ErrorKind::NotConnected=>"OriginIoNotConnected",std::io::ErrorKind::Interrupted=>"OriginIoInterrupted",std::io::ErrorKind::PermissionDenied=>"OriginIoPermissionDenied",_=>"OriginIoOther",
            },
        };
        emit_closed_observation_v3("DeliveryRecipientOrigin",outcome);
    }
    result
}
pub(super) fn observe_frame_v3<T>(result:std::result::Result<T,wholepact_signer_origin::framing::ObservedFrameError>)->Result<T> {
    result.map_err(|observed| {
        #[cfg(feature="synthetic-born-joined-qualification")]
        {
            use wholepact_signer_origin::framing::FrameReadCause as C;
            let outcome=match observed.cause {
                C::Unclassified=>"OriginFrameUnclassified",C::Deadline=>"OriginFrameDeadline",C::Eof=>"OriginFrameEof",C::CredentialsMissing=>"OriginFrameCredentialsMissing",C::CredentialsMismatch=>"OriginFrameCredentialsMismatch",C::AncillaryRejected=>"OriginFrameAncillaryRejected",C::Truncated=>"OriginFrameTruncated",C::PeerNotLive=>"OriginFramePeerNotLive",C::CurrentCheck=>"OriginFrameCurrentCheck",C::Io=>"OriginFrameIo",C::FrameLimit=>"OriginFrameLimit",C::InvalidFrame=>"OriginFrameInvalidFrame",C::InvalidBudget=>"OriginFrameInvalidBudget",
            };
            emit_closed_observation_v3("DeliveryRecipientFrame",outcome);
        }
        let _=observed;
        BridgeError::Ipc
    })
}
fn observe_bridge_v3<T>(result:Result<T>,site:&'static str)->Result<T> {
    #[cfg(feature="synthetic-born-joined-qualification")]
    if let Err(error)=&result {
        let outcome=match error {
            BridgeError::Binding=>"BridgeBinding",BridgeError::Conflict=>"BridgeConflict",BridgeError::Missing=>"BridgeMissing",BridgeError::Uncertain=>"BridgeUncertain",BridgeError::Limit=>"BridgeLimit",BridgeError::Permission=>"BridgePermission",BridgeError::RecoveryRequired=>"BridgeRecoveryRequired",BridgeError::CompleteOriginRecoveryUnavailable=>"BridgeCompleteOriginRecoveryUnavailable",BridgeError::Verification=>"BridgeVerification",BridgeError::SignerOriginUnavailable=>"BridgeSignerOriginUnavailable",BridgeError::Journal(_)=>"BridgeJournal",BridgeError::Authority(_)=>"BridgeAuthority",BridgeError::Ipc=>"BridgeIpc",
            #[cfg(feature="authority-signing")]
            BridgeError::Wallet(_)=>"BridgeWallet",
        };
        emit_closed_observation_v3(site,outcome);
    }
    let _=site;
    result
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareClosedRecipientRequestV3 {
    pub version: u16,
    pub request: DurableReviewDeliveryRequestV1,
    pub fixed: FixedProposalIdentityV1,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub delivery: DurableDeliveryPlanV2,
    pub material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,
    pub provider_enrollment_reference: String,
    pub signer_process_instance: String,
}
impl PrepareClosedRecipientRequestV3 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 3 || serde_json::to_vec(self).map_err(|_| BridgeError::Binding)?.len() > 128 * 1024 {
            return Err(BridgeError::Binding);
        }
        validate_preparation_body(&self.request, &self.fixed, &self.payload_digest, self.payload_bytes,
            &self.delivery, &self.material_scopes, &self.provider_enrollment_reference, &self.signer_process_instance)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest("wholepact:closed-recipient-preparation:v3", self).map_err(|_| BridgeError::Binding)
    }
}
/// Shared pure body validation only. Profile/version and provider provenance
/// remain distinct; this helper creates neither recipient nor transport owner.
fn validate_preparation_body(
    request: &DurableReviewDeliveryRequestV1, fixed: &FixedProposalIdentityV1,
    payload_digest: &str, payload_bytes: u64, delivery: &DurableDeliveryPlanV2,
    material_scopes: &[DurableDeliveryMaterialScopeRefV2],
    provider_enrollment_reference: &str, signer_process_instance: &str,
) -> Result<()> {
        request.validate()?;
        delivery.validate_origins().map_err(|_| BridgeError::Binding)?;
        fixed_binding_v3(fixed)?.validate().map_err(|_| BridgeError::Binding)?;
        for value in [payload_digest, provider_enrollment_reference, signer_process_instance] { super::durable_construction_v1::hash(value)?; }
        if fixed.schema_version != 1 || fixed.proposal_binding != request.proposal_binding
            || payload_bytes == 0 || payload_bytes > v1::MAX_PAYLOAD as u64
            || material_scopes.len() != 2 || delivery.owners.len() != 2
            || material_scopes[0].account_id >= material_scopes[1].account_id
 {
            return Err(BridgeError::Binding);
        }
        for scope in material_scopes {
            super::durable_construction_v1::hash(&scope.account_id)?;
            super::durable_construction_v1::hash(&scope.original_scope_digest)?;
            if scope.account_id.is_empty() || scope.valid_from_unix_seconds == 0 || scope.valid_until_unix_seconds <= scope.valid_from_unix_seconds || scope.valid_until_unix_seconds > i64::MAX as u64 / 1000 { return Err(BridgeError::Binding); }
        }
        if material_scopes.iter().map(|scope| &scope.account_id).ne(delivery.owners.iter().map(|owner| &owner.account_id)) { return Err(BridgeError::Binding); }
        Ok(())
}

pub(crate) fn fixed_binding_v3(fixed:&FixedProposalIdentityV1)->Result<wholepact_authority::durable_payment_v1::DurableFixedCandidateBindingV1> {
    wholepact_core::parse_typed_json(&serde_json::to_vec(fixed).map_err(|_| BridgeError::Binding)?).map_err(|_| BridgeError::Binding)
}

/// Reviewable source/process commitment, never a grant, socket or native owner.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientIntentV3 {
    pub version: u16,
    pub request: DurableReviewDeliveryRequestV1,
    pub fixed: FixedProposalIdentityV1,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub delivery: DurableDeliveryPlanV2,
    pub material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,
    pub account_id: String,
    pub participant_id: String,
    pub agreement_id: String,
    pub manifest_digest: String,
    pub provider_enrollment_reference: String,
    pub signer_process_instance: String,
    pub authorized_host_process_instance: String,
    pub source_identity_digest: String,
    pub source_generation: u64,
    pub read_session_digest: String,
    pub receive_decision_digest: String,
    pub original_enrollment_ref: String,
    pub original_manifest_ref: String,
}
impl RecipientIntentV3 {
    pub fn validate(&self) -> Result<()> {
        self.preparation().validate()?;
        for value in [&self.manifest_digest, &self.authorized_host_process_instance, &self.source_identity_digest, &self.read_session_digest, &self.receive_decision_digest, &self.original_enrollment_ref, &self.original_manifest_ref] { super::durable_construction_v1::hash(value)?; }
        for value in [&self.account_id, &self.participant_id, &self.agreement_id] { crate::review::validate_label(value).map_err(|_| BridgeError::Binding)?; }
        if self.version != 3 || self.source_generation == 0 || self.fixed.agreement_id != self.agreement_id || self.fixed.manifest_digest != self.manifest_digest || self.original_enrollment_ref != self.request.enrollment_ref || self.original_manifest_ref != self.request.accepted_manifest_ref || !self.delivery.owners.iter().any(|owner| owner.account_id == self.account_id && owner.participant_id == self.participant_id) { return Err(BridgeError::Binding); }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest("wholepact:closed-recipient-intent:v3", self).map_err(|_| BridgeError::Binding)
    }
    pub(crate) fn preparation(&self) -> PrepareClosedRecipientRequestV3 {
        PrepareClosedRecipientRequestV3 { version: 3, request: self.request.clone(), fixed: self.fixed.clone(), payload_digest: self.payload_digest.clone(), payload_bytes: self.payload_bytes, delivery: self.delivery.clone(), material_scopes: self.material_scopes.clone(), provider_enrollment_reference: self.provider_enrollment_reference.clone(), signer_process_instance: self.signer_process_instance.clone() }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableReviewDeliveryReceiptV3 {
    pub version: u16,
    pub intent_digest: String,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub state: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedDurableReviewReceiptV3 {
    pub version: u16,
    pub intent_digest: String,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub verified_fixed_identity_digest: String,
    pub state: String,
}
pub(crate) fn verified_fixed_identity_digest_v3(fixed: &FixedProposalIdentityV1) -> Result<String> {
    wholepact_core::proposal::canonical_digest("wholepact:durable-review-verified-fixed-identity:v3", fixed).map_err(|_| BridgeError::Binding)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ClosedRecipientCommandV3 {
    PreparationStatus { request_digest: String, nonce: String },
    Activate { intent_digest: String, nonce: String },
    VerifyImport { intent_digest: String, nonce: String },
    Admit { intent_digest: String, nonce: String },
    AdmissionStatus { intent_digest: String, nonce: String },
    History { intent_digest: String, authorization_id: String, nonce: String },
}
impl ClosedRecipientCommandV3 {
    pub(crate) fn validate(&self) -> Result<()> {
        let (commitment, nonce) = match self {
            Self::PreparationStatus {request_digest, nonce} => (request_digest, nonce),
            Self::Activate {intent_digest, nonce} | Self::VerifyImport {intent_digest, nonce} | Self::Admit {intent_digest, nonce} | Self::AdmissionStatus {intent_digest, nonce} => (intent_digest, nonce),
            Self::History {intent_digest, authorization_id, nonce} => { crate::review::validate_label(authorization_id).map_err(|_| BridgeError::Binding)?; (intent_digest, nonce) }
        };
        super::durable_construction_v1::hash(commitment)?;
        super::durable_construction_v1::hash(nonce)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ClosedRecipientResponseV3 {
    Staged { request_digest: String },
    Preparing { nonce: String },
    Prepared { nonce: String, intent: RecipientIntentV3, remaining_read_ms: u64 },
    Ready { intent_digest: String, nonce: String, remaining_read_ms: u64 },
    Current { intent_digest: String },
    Receiving { received_bytes: u64 },
    BytesReceived { receipt: DurableReviewDeliveryReceiptV3 },
    Verifying { nonce: String },
    Verified { nonce: String, receipt: VerifiedDurableReviewReceiptV3 },
    Admitting { nonce: String },
    Admission { nonce: String, admission: super::durable_delivery_admission_ipc_v3::DurableDeliveryAdmissionStatusV3 },
    Denied,
}

/// Actual installed-provider/process custody. Closed transfer obtains it by
/// destroying the old grant; fresh historical reopening authenticates a new
/// process for History only. Scope fields are comparison data, never a grant.
pub(super) struct ClosedRecipientOriginV3 {
    pub(super) provider: super::provider::InstalledSignerProvider,
    pub(super) socket: PathBuf,
    pub(super) peer: PeerProcess,
    pub(super) scope: crate::ipc::PairScope,
}
impl ClosedRecipientOriginV3 {
    pub(super) fn check(&self, stream: Option<&UnixStream>) -> Result<()> {
        observe_origin_v3(self.peer.check_alive()).map_err(|_| BridgeError::Permission)?;
        if let Some(stream) = stream { let observed = observe_origin_v3(self.provider.verify_server(stream))?; observe_origin_v3(self.peer.same_live_process(&observed)).map_err(|_| BridgeError::Permission)?; }
        Ok(())
    }
    pub(super) fn open(&self, command: &ClosedRecipientCommandV3, deadline: Instant) -> Result<UnixStream> {
        command.validate()?;
        require_before(deadline)?;
        self.check(None)?;
        let mut stream = observe_origin_v3(wholepact_signer_origin::connect_local_checked_until(&self.socket, deadline, || {
            require_before(deadline).and_then(|_| self.check(None)).map_err(|_| wholepact_signer_origin::Error::Permission)
        })).map_err(|_| BridgeError::Ipc)?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        self.check(Some(&stream))?;
        let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
        observe_bridge_v3(v1::bounded_write(&mut stream, &serde_json::json!({"command":"closed_recipient_v3", "schema_version":3, "request":command}), deadline, || self.check(Some(&observer))),"DeliveryRecipientWriteIo")?;
        Ok(stream)
    }
    pub(super) fn read(&self, stream: &UnixStream, deadline: Instant) -> Result<ClosedRecipientResponseV3> {
        self.read_checked(stream,deadline,&|| Ok(()))
    }
    fn read_checked(&self, stream: &UnixStream, deadline: Instant, check: &dyn Fn() -> Result<()>) -> Result<ClosedRecipientResponseV3> {
        let current = || { check()?; require_before(deadline)?; self.check(Some(stream)) };
        let bytes = observe_frame_v3(wholepact_signer_origin::framing::read_frame_capped_checked_observed_until(stream, &self.peer, MAX_METADATA_V3, deadline, || current().map_err(|_| wholepact_signer_origin::Error::Permission)))?;
        require_before(deadline)?;
        current()?;
        observe_bridge_v3(wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, MAX_METADATA_V3).map_err(|_| BridgeError::Binding),"DeliveryRecipientResponseDecode")
    }
}
pub(super) fn fresh_nonce() -> Result<String> { Ok(hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?)) }
pub(crate) fn require_before(deadline: Instant) -> Result<()> { observe_bridge_v3(if Instant::now() >= deadline { Err(BridgeError::Permission) } else { Ok(()) },"DeliveryRecipientDeadline") }
fn narrowed_deadline(started: Instant, remaining_ms: u64, ceiling: Instant) -> Result<Instant> {
    if remaining_ms == 0 || remaining_ms > 120_000 { return Err(BridgeError::Permission); }
    let deadline = (started + Duration::from_millis(remaining_ms)).min(ceiling);
    require_before(deadline)?;
    Ok(deadline)
}
/// Prepared source/native intent with no socket or action grant during Host review.
pub struct PreparedDurableReviewRecipientV3 { origin: ClosedRecipientOriginV3, intent: RecipientIntentV3, deadline: Instant }
pub struct FreshDurableReviewDeliveryV3 { origin: ClosedRecipientOriginV3, intent: RecipientIntentV3, stream: std::sync::Mutex<UnixStream>, deadline: Instant, read_deadline: Instant }
/// Bytes acknowledged only. This type deliberately has no admission method.
pub struct ImportedDurableReviewSessionV3 { origin: ClosedRecipientOriginV3, intent: RecipientIntentV3, receipt: DurableReviewDeliveryReceiptV3, deadline: Instant }
/// Constructed only after the actual prepared source reports its completed native
/// proof/economics verification over the exact retained payload and fixed identity.
pub struct VerifiedImportedDurableReviewSessionV3 { pub(super) origin: ClosedRecipientOriginV3, pub(super) intent: RecipientIntentV3, pub(super) receipt: VerifiedDurableReviewReceiptV3, pub(super) deadline: Instant }
impl OriginalHistoryClient {
    pub fn prepare_closed_recipient_v3(self, request: DurableReviewDeliveryRequestV1, fixed: FixedProposalIdentityV1, payload_digest: String, payload_bytes: u64, delivery: DurableDeliveryPlanV2, material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>) -> Result<PreparedDurableReviewRecipientV3> {
        let preparation = PrepareClosedRecipientRequestV3 { version: 3, request, fixed, payload_digest, payload_bytes, delivery, material_scopes, provider_enrollment_reference: self.closed_provider_reference_v3().to_owned(), signer_process_instance: self.peer().instance().to_owned() };
        preparation.validate()?;
        let request_digest = preparation.digest()?;
        let stage_deadline = self.durable_delivery_exchange_deadline_v2();
        let stream = self.open_closed_stage_request_v3(serde_json::json!({"operation":"prepare_durable_recipient_v3", "request":preparation}), true, stage_deadline)?;
        let frame = observe_frame_v3(wholepact_signer_origin::framing::read_frame_capped_checked_observed_until(&stream, self.peer(), MAX_METADATA_V3, stage_deadline, || self.check_closed_stage_origin_v3(&stream, true, stage_deadline).map_err(|_| wholepact_signer_origin::Error::Permission)))?;
        self.check_closed_stage_origin_v3(&stream, true, stage_deadline)?;
        if !matches!(wholepact_core::strict_json::parse_typed_json_with_byte_limit::<ClosedRecipientResponseV3>(&frame, MAX_METADATA_V3).map_err(|_| BridgeError::Binding)?, ClosedRecipientResponseV3::Staged { request_digest: actual } if actual == request_digest) { return Err(BridgeError::Permission); }
        drop(stream);
        let origin = self.into_closed_origin_v3()?;
        // This is a bounded UI wait, not read/action authority. The server starts
        // its independently revocable READ120 only after the genuine decision.
        let preparation_wait = Instant::now() + Duration::from_secs(120);
        loop {
            let nonce = fresh_nonce()?;
            let started = Instant::now();
            let stream = origin.open(&ClosedRecipientCommandV3::PreparationStatus { request_digest: request_digest.clone(), nonce: nonce.clone() }, preparation_wait)?;
            match origin.read(&stream, preparation_wait)? {
                ClosedRecipientResponseV3::Prepared {nonce: actual, intent, remaining_read_ms} if actual == nonce => {
                    intent.validate()?;
                    if intent.preparation() != preparation || intent.account_id != origin.scope.account_id || intent.participant_id != origin.scope.participant_id || intent.agreement_id != origin.scope.agreement_id || intent.manifest_digest != origin.scope.manifest_digest { return Err(BridgeError::Binding); }
                    let deadline = narrowed_deadline(started, remaining_read_ms, started + Duration::from_secs(120))?;
                    drop(stream);
                    return Ok(PreparedDurableReviewRecipientV3 { origin, intent, deadline });
                }
                ClosedRecipientResponseV3::Preparing {nonce: actual} if actual == nonce => { drop(stream); require_before(preparation_wait)?; std::thread::sleep(Duration::from_millis(100)); }
                _ => return Err(BridgeError::Permission),
            }
        }
    }
}
impl PreparedDurableReviewRecipientV3 {
    pub fn intent(&self) -> &RecipientIntentV3 { &self.intent }
    pub fn activate(self, host_action_deadline: Instant) -> Result<FreshDurableReviewDeliveryV3> {
        let started = Instant::now();
        let deadline = self.deadline.min(host_action_deadline).min(started + Duration::from_secs(120));
        require_before(deadline)?;
        let nonce = fresh_nonce()?;
        let digest = self.intent.digest()?;
        let stream = self.origin.open(&ClosedRecipientCommandV3::Activate {intent_digest: digest.clone(), nonce:nonce.clone()}, deadline)?;
        let ClosedRecipientResponseV3::Ready {intent_digest, nonce:actual, remaining_read_ms} = self.origin.read(&stream, deadline)? else { return Err(BridgeError::Permission); };
        if intent_digest != digest || actual != nonce { return Err(BridgeError::Binding); }
        let read_deadline = narrowed_deadline(started, remaining_read_ms, self.deadline)?;
        let deadline = read_deadline.min(deadline);
        Ok(FreshDurableReviewDeliveryV3 { origin:self.origin, intent:self.intent, stream:std::sync::Mutex::new(stream), deadline, read_deadline })
    }
}
impl FreshDurableReviewDeliveryV3 {
    /// The already-retained original recipient/read/action minimum. This is
    /// only an immutable ceiling observation, never consent or a new lifetime.
    pub fn original_delivery_deadline_v3(&self) -> Instant { self.deadline }
    pub fn intent(&self) -> &RecipientIntentV3 { &self.intent }
    pub fn check_current(&self) -> Result<()> {
        require_before(self.deadline)?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
        v1::bounded_write(&mut stream, &v1::DeliveryCommandV1::CheckCurrent, self.deadline, || self.origin.check(Some(&observer)))?;
        match self.origin.read(&stream, self.deadline)? { ClosedRecipientResponseV3::Current { intent_digest } if intent_digest == self.intent.digest()? => Ok(()), _ => Err(BridgeError::Permission) }
    }
    pub fn deliver_prepared_v3(self, payload: PreparedDurableReviewPayloadV2, check: &dyn Fn() -> Result<()>) -> Result<ImportedDurableReviewSessionV3> {
        self.deliver_prepared_restricted_v3(payload, check, &|| Ok(()))
    }
    /// Adds only a zero-wait final restriction. The same real recipient and full
    /// consent/source checks remain mandatory; no positive receipt is created.
    pub fn deliver_prepared_restricted_v3(self, payload: PreparedDurableReviewPayloadV2, check: &dyn Fn() -> Result<()>, final_restriction: &dyn Fn() -> Result<()>) -> Result<ImportedDurableReviewSessionV3> {
        check()?;
        self.check_current()?;
        if payload.payload_digest() != self.intent.payload_digest || payload.payload_bytes() != self.intent.payload_bytes { return Err(BridgeError::Binding); }
        let (raw, digest) = payload.into_exact_parts_v3();
        let mut stream = self.stream.into_inner().map_err(|_| BridgeError::Ipc)?;
        let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
        let current = || { check()?; require_before(self.deadline)?; self.origin.check(Some(&observer)) };
        v1::bounded_write_restricted(&mut stream, &v1::DeliveryCommandV1::Begin {payload_digest:digest.clone(),payload_bytes:raw.len() as u64}, self.deadline, current, final_restriction)?;
        expect_receiving(&self.origin, &stream, self.deadline, 0, &current)?;
        for (index, bytes) in raw.chunks(v1::CHUNK_BYTES).enumerate() {
            let offset = index * v1::CHUNK_BYTES;
            v1::bounded_write_restricted(&mut stream, &v1::DeliveryCommandV1::Chunk {offset:offset as u64,data_hex:hex::encode(bytes)}, self.deadline, current, final_restriction)?;
            expect_receiving(&self.origin, &stream, self.deadline, (offset + bytes.len()) as u64, &current)?;
        }
        v1::bounded_write_restricted(&mut stream, &v1::DeliveryCommandV1::Finish, self.deadline, current, final_restriction)?;
        let ClosedRecipientResponseV3::BytesReceived {receipt} = self.origin.read_checked(&stream, self.deadline, &current)? else { return Err(BridgeError::Permission); };
        current()?;
        if receipt.version != 3 || receipt.intent_digest != self.intent.digest()? || receipt.payload_digest != digest || receipt.payload_bytes != raw.len() as u64 || receipt.state != "bytes_received_unverified" { return Err(BridgeError::Binding); }
        drop(raw); drop(stream); drop(observer);
        Ok(ImportedDurableReviewSessionV3 {origin:self.origin,intent:self.intent,receipt,deadline:self.read_deadline})
    }
}
fn expect_receiving(origin: &ClosedRecipientOriginV3, stream: &UnixStream, deadline: Instant, expected: u64, check: &dyn Fn() -> Result<()>) -> Result<()> {
    match origin.read_checked(stream, deadline, check)? { ClosedRecipientResponseV3::Receiving {received_bytes} if received_bytes == expected => Ok(()), _ => Err(BridgeError::Permission) }
}
impl ImportedDurableReviewSessionV3 {
    pub fn intent(&self) -> &RecipientIntentV3 { &self.intent }
    pub fn receipt(&self) -> &DurableReviewDeliveryReceiptV3 { &self.receipt }
    pub fn await_verified_v3(self) -> Result<VerifiedImportedDurableReviewSessionV3> {
        loop {
            require_before(self.deadline)?;
            let nonce = fresh_nonce()?;
            let stream = self.origin.open(&ClosedRecipientCommandV3::VerifyImport {intent_digest:self.intent.digest()?,nonce:nonce.clone()},self.deadline)?;
            match self.origin.read(&stream,self.deadline)? {
                ClosedRecipientResponseV3::Verified {nonce:actual,receipt} if actual == nonce => {
                    if receipt.version != 3 || receipt.intent_digest != self.intent.digest()? || receipt.payload_digest != self.intent.payload_digest || receipt.payload_bytes != self.intent.payload_bytes || receipt.verified_fixed_identity_digest != verified_fixed_identity_digest_v3(&self.intent.fixed)? || receipt.state != "verified_import_for_review" { return Err(BridgeError::Binding); }
                    drop(stream);
                    return Ok(VerifiedImportedDurableReviewSessionV3 {origin:self.origin,intent:self.intent,receipt,deadline:self.deadline});
                }
                ClosedRecipientResponseV3::Verifying {nonce:actual} if actual == nonce => { drop(stream); std::thread::sleep(Duration::from_millis(100)); }
                _ => return Err(BridgeError::Permission),
            }
        }
    }
}
impl VerifiedImportedDurableReviewSessionV3 {
    pub fn intent(&self) -> &RecipientIntentV3 { &self.intent }
    pub fn receipt(&self) -> &VerifiedDurableReviewReceiptV3 { &self.receipt }
}
