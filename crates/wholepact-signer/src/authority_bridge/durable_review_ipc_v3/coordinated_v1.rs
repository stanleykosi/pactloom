//! Explicit original-fork coordinated profile. No native provider enrollment,
//! NativeDecision or legacy closed-recipient authority is reconstructed here.
use super::*;
mod admission_v1;
mod redisclosure_v1;
pub use redisclosure_v1::*;
mod lifecycle_v1;
use crate::ipc::PairScope;
pub use admission_v1::*;
pub use lifecycle_v1::*;
use wholepact_financial_coordinator_origin::{OriginalForkSignerVerifier, SignerV3PairEndpointV1};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatedPrepareClosedRecipientRequestV1 {
    pub version: u16,
    pub request: DurableReviewDeliveryRequestV1,
    pub fixed: FixedProposalIdentityV1,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub delivery: DurableDeliveryPlanV2,
    pub material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,
    pub coordinated_provider_reference: String,
    pub signer_process_instance: String,
}
impl CoordinatedPrepareClosedRecipientRequestV1 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || serde_json::to_vec(self)
                .map_err(|_| BridgeError::Binding)?
                .len()
                > 128 * 1024
        {
            return Err(BridgeError::Binding);
        }
        validate_preparation_body(
            &self.request,
            &self.fixed,
            &self.payload_digest,
            self.payload_bytes,
            &self.delivery,
            &self.material_scopes,
            &self.coordinated_provider_reference,
            &self.signer_process_instance,
        )
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-closed-recipient-preparation:v1",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinatedAppRequestV1 {
    FinancialResult {
        request: crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1,
    },
    Closed {
        request: CoordinatedClosedCommandV1,
    },
    Status,
    Redisclosure {
        request:
            Box<super::super::durable_construction_v1::DurableConstructionRedisclosureRequestV1>,
    },
    Prepare {
        request: Box<CoordinatedPrepareClosedRecipientRequestV1>,
    },
}
impl CoordinatedAppRequestV1 {
    pub(crate) fn validate(&self, scope: &PairScope) -> Result<()> {
        scope.validate().map_err(|_| BridgeError::Binding)?;
        if !scope.history_read || !scope.preconstruction_export || scope.authorization_export {
            return Err(BridgeError::Permission);
        }
        match self {
            Self::Status => Ok(()),
            Self::FinancialResult { request } => {
                request.validate()?;
                if request.account_id != scope.account_id
                    || request.fixed.agreement_id != scope.agreement_id
                    || request.fixed.manifest_digest != scope.manifest_digest
                {
                    return Err(BridgeError::Binding);
                }
                Ok(())
            }
            Self::Closed { request } => request.validate(),
            Self::Redisclosure { request } => request.validate(),
            Self::Prepare { request } => {
                request.validate()?;
                if request.fixed.agreement_id != scope.agreement_id
                    || request.fixed.manifest_digest != scope.manifest_digest
                {
                    return Err(BridgeError::Binding);
                }
                Ok(())
            }
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairResponse {
    schema_version: u32,
    accepted: bool,
    reason_code: String,
    grant_id: String,
    token_hex: String,
    expires_in_seconds: u64,
    profile: String,
    channel_digest: String,
    observed_host_process_instance: String,
    original_host_process_instance: String,
    pair_presentation_digest: String,
    source_identity_digest: String,
    generation: u64,
}
impl Drop for PairResponse {
    fn drop(&mut self) {
        self.token_hex.zeroize();
    }
}
#[derive(Serialize)]
struct RequestEnvelope<'a> {
    command: &'static str,
    schema_version: u32,
    grant_id: &'a str,
    token_hex: &'a str,
    request: &'a CoordinatedAppRequestV1,
}
/// Finite boundary of one actual original Pair failure; no identity or payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatedPairFailureStageV1 {EndpointValidate, ScopeValidate, OriginalCustody, Connect, EnableCredentials, VerifySigner, ObservePeer, CloneObserver, RequestWrite, ResponseRead, ResponseDecode, ResponseValidate, ResponseDigest, ChannelDigest, InitialCurrent, StatusOpen, StatusRead, StatusDecode, StatusValidate, FinalCurrent}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatedPairFailureClassV1 {BridgeBinding, BridgeConflict, BridgeMissing, BridgeUncertain, BridgeLimit, BridgePermission, BridgeRecoveryRequired, BridgeCompleteOriginRecoveryUnavailable, BridgeVerification, BridgeSignerOriginUnavailable, BridgeJournal, BridgeAuthority, BridgeWallet, BridgeIpc, FrameUnclassified, FrameDeadline, FrameEof, FrameCredentialsMissing, FrameCredentialsMismatch, FrameAncillaryRejected, FrameTruncated, FramePeerNotLive, FrameCurrentCheck, FrameIo, FrameLimit, FrameInvalidFrame, FrameInvalidBudget}
/// Retains the unchanged original error. No Display/serialization or authority.
pub struct CoordinatedPairFailureV1 {
    stage: CoordinatedPairFailureStageV1,
    frame_cause: Option<wholepact_signer_origin::framing::FrameReadCause>,
    error: BridgeError,
}
impl CoordinatedPairFailureV1 {
    pub fn stage(&self) -> CoordinatedPairFailureStageV1 { self.stage }
    pub fn class(&self) -> CoordinatedPairFailureClassV1 {
        use CoordinatedPairFailureClassV1 as C;
        if let Some(cause) = self.frame_cause {
            use wholepact_signer_origin::framing::FrameReadCause as F;
            return match cause {
                F::Unclassified=>C::FrameUnclassified,
                F::Deadline=>C::FrameDeadline,
                F::Eof=>C::FrameEof,
                F::CredentialsMissing=>C::FrameCredentialsMissing,
                F::CredentialsMismatch=>C::FrameCredentialsMismatch,
                F::AncillaryRejected=>C::FrameAncillaryRejected,
                F::Truncated=>C::FrameTruncated,
                F::PeerNotLive=>C::FramePeerNotLive,
                F::CurrentCheck=>C::FrameCurrentCheck,
                F::Io=>C::FrameIo,
                F::FrameLimit=>C::FrameLimit,
                F::InvalidFrame=>C::FrameInvalidFrame,
                F::InvalidBudget=>C::FrameInvalidBudget,
            };
        }
        match &self.error {
            BridgeError::Binding=>C::BridgeBinding,
            BridgeError::Conflict=>C::BridgeConflict,
            BridgeError::Missing=>C::BridgeMissing,
            BridgeError::Uncertain=>C::BridgeUncertain,
            BridgeError::Limit=>C::BridgeLimit,
            BridgeError::Permission=>C::BridgePermission,
            BridgeError::RecoveryRequired=>C::BridgeRecoveryRequired,
            BridgeError::CompleteOriginRecoveryUnavailable=>C::BridgeCompleteOriginRecoveryUnavailable,
            BridgeError::Verification=>C::BridgeVerification,
            BridgeError::SignerOriginUnavailable=>C::BridgeSignerOriginUnavailable,
            BridgeError::Journal(_)=>C::BridgeJournal,
            BridgeError::Authority(_)=>C::BridgeAuthority,
            #[cfg(feature="authority-signing")]
            BridgeError::Wallet(_)=>C::BridgeWallet,
            BridgeError::Ipc=>C::BridgeIpc,
        }
    }
    pub fn into_error(self) -> BridgeError { self.error }
}
fn observe_pair_result<T>(
    result: Result<T>,
    stage: CoordinatedPairFailureStageV1,
    frame_cause: Option<wholepact_signer_origin::framing::FrameReadCause>,
) -> std::result::Result<T, CoordinatedPairFailureV1> {
    result.map_err(|error| CoordinatedPairFailureV1 { stage, frame_cause, error })
}
/// Genuine H-owned, original-S authenticated request channel. Pair grants only
/// this narrow transport; every source Read/export remains a separate C action.
pub struct CoordinatedOriginalClientV1 {
    verifier: OriginalForkSignerVerifier,
    endpoint: SignerV3PairEndpointV1,
    peer: PeerProcess,
    scope: PairScope,
    grant_id: String,
    token: Zeroizing<String>,
    deadline: Instant,
    channel_digest: String,
    observed_host_process_instance: String,
    original_host_process_instance: String,
    pair_presentation_digest: String,
    redisclosure_attempt: Option<String>,
}
impl CoordinatedOriginalClientV1 {
    /// Validate inert committed receipt observations against this exact original channel.
    pub fn check_current_disclosure_v1(
        &self,
        data: &wholepact_financial_coordinator_origin::SignerV3CurrentDisclosureV1,
    ) -> Result<()> {
        self.check_current()?;
        data.validate().map_err(|_| BridgeError::Binding)?;
        if data.source_identity_digest != self.endpoint.source_identity_digest
            || data.entry_presentation_digest != self.endpoint.entry_presentation_digest
            || data.pair_presentation_digest != self.pair_presentation_digest
            || data.pair_grant_id != self.grant_id
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub fn pair(
        verifier: OriginalForkSignerVerifier,
        endpoint: SignerV3PairEndpointV1,
        scope: PairScope,
    ) -> Result<Self> {
        Self::pair_observed(verifier, endpoint, scope).map_err(CoordinatedPairFailureV1::into_error)
    }
    /// Same original Pair attempt, with finite failure-only observations.
    /// No extra transport, authority, retry or renewed deadline is introduced.
    pub fn pair_observed(
        verifier: OriginalForkSignerVerifier,
        endpoint: SignerV3PairEndpointV1,
        scope: PairScope,
    ) -> std::result::Result<Self, CoordinatedPairFailureV1> {
        let mut stage = CoordinatedPairFailureStageV1::EndpointValidate;
        let mut frame_cause = None;
        let result = Self::pair_inner(verifier, endpoint, scope, &mut stage, &mut frame_cause);
        observe_pair_result(result, stage, frame_cause)
    }
    fn pair_inner(
        verifier: OriginalForkSignerVerifier,
        endpoint: SignerV3PairEndpointV1,
        scope: PairScope,
        stage: &mut CoordinatedPairFailureStageV1,
        frame_cause: &mut Option<wholepact_signer_origin::framing::FrameReadCause>,
    ) -> Result<Self> {
        endpoint.validate().map_err(|_| BridgeError::Binding)?;
        *stage = CoordinatedPairFailureStageV1::ScopeValidate;
        CoordinatedAppRequestV1::Status.validate(&scope)?;
        *stage = CoordinatedPairFailureStageV1::OriginalCustody;
        verifier
            .check_original_custody_alive()
            .map_err(|_| BridgeError::Permission)?;
        let started = Instant::now();
        let deadline = started + Duration::from_secs(120);
        let current = || {
            require_before(deadline)?;
            verifier
                .check_original_custody_alive()
                .map_err(|_| BridgeError::Permission)
        };
        *stage = CoordinatedPairFailureStageV1::Connect;
        let mut stream = wholepact_signer_origin::connect_local_checked_until(
            std::path::Path::new(&endpoint.endpoint_path),
            deadline,
            || current().map_err(|_| wholepact_signer_origin::Error::Permission),
        )
        .map_err(|_| BridgeError::Ipc)?;
        *stage = CoordinatedPairFailureStageV1::EnableCredentials;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        *stage = CoordinatedPairFailureStageV1::VerifySigner;
        verifier
            .verify_connected_signer(&stream)
            .map_err(|_| BridgeError::Permission)?;
        *stage = CoordinatedPairFailureStageV1::ObservePeer;
        let peer = PeerProcess::observe(&stream).map_err(|_| BridgeError::Permission)?;
        *stage = CoordinatedPairFailureStageV1::CloneObserver;
        let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
        *stage = CoordinatedPairFailureStageV1::RequestWrite;
        v1::bounded_write(
            &mut stream,
            &serde_json::json!({
                "command":"request_pairing","schema_version":1,
                "application_label":"wholepact-original-fork-v3","scope":scope,
            }),
            deadline,
            || {
                current()?;
                verifier
                    .verify_connected_signer(&observer)
                    .map_err(|_| BridgeError::Permission)
            },
        )?;
        *stage = CoordinatedPairFailureStageV1::ResponseRead;
        let bytes = wholepact_signer_origin::framing::read_frame_capped_checked_observed_until(
            &stream,
            &peer,
            16 * 1024,
            deadline,
            || {
                current().map_err(|_| wholepact_signer_origin::Error::Permission)?;
                verifier
                    .verify_connected_signer(&stream)
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            },
        )
        .map_err(|failure| {
            *frame_cause = Some(failure.cause);
            BridgeError::Ipc
        })?;
        *stage = CoordinatedPairFailureStageV1::ResponseDecode;
        let mut reply: PairResponse =
            wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, 16 * 1024)
                .map_err(|_| BridgeError::Binding)?;
        *stage = CoordinatedPairFailureStageV1::ResponseValidate;
        if reply.schema_version != 1
            || !reply.accepted
            || reply.reason_code != "LOCAL_PROCESS_REQUEST_SCOPE"
            || reply.expires_in_seconds == 0
            || reply.expires_in_seconds > 900
            || reply.profile != "coordinated_original_fork_v1"
            || reply.generation != 1
            || reply.source_identity_digest != endpoint.source_identity_digest
        {
            return Err(BridgeError::Permission);
        }
        *stage = CoordinatedPairFailureStageV1::ResponseDigest;
        super::super::durable_construction_v1::hash(&reply.grant_id)?;
        super::super::durable_construction_v1::hash(&reply.token_hex)?;
        for value in [
            &reply.channel_digest,
            &reply.pair_presentation_digest,
            &reply.observed_host_process_instance,
            &reply.original_host_process_instance,
        ] {
            super::super::durable_construction_v1::hash(value)?;
        }
        *stage = CoordinatedPairFailureStageV1::ChannelDigest;
        let mut channel = sha2::Sha256::new();
        use sha2::Digest;
        channel.update(b"wholepact:local-process-pairing:v1\0");
        channel.update(reply.observed_host_process_instance.as_bytes());
        channel.update(1u64.to_le_bytes());
        channel.update(serde_json::to_vec(&scope).map_err(|_| BridgeError::Binding)?);
        if reply.channel_digest != hex::encode(channel.finalize()) {
            return Err(BridgeError::Binding);
        }

        let client = Self {
            verifier,
            endpoint,
            peer,
            scope,
            grant_id: std::mem::take(&mut reply.grant_id),
            token: Zeroizing::new(std::mem::take(&mut reply.token_hex)),
            deadline: started + Duration::from_secs(reply.expires_in_seconds),
            channel_digest: std::mem::take(&mut reply.channel_digest),
            observed_host_process_instance: std::mem::take(
                &mut reply.observed_host_process_instance,
            ),
            original_host_process_instance: std::mem::take(
                &mut reply.original_host_process_instance,
            ),
            pair_presentation_digest: std::mem::take(&mut reply.pair_presentation_digest),
            redisclosure_attempt: None,
        };
        drop(stream);
        *stage = CoordinatedPairFailureStageV1::InitialCurrent;
        client.check_current()?;
        *stage = CoordinatedPairFailureStageV1::StatusOpen;
        let proof = client.open_request(&CoordinatedAppRequestV1::Status, deadline)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Proof {
            accepted: bool,
            reason_code: String,
        }
        *stage = CoordinatedPairFailureStageV1::StatusRead;
        let bytes = client.read_metadata(&proof, 4096, deadline)?;
        *stage = CoordinatedPairFailureStageV1::StatusDecode;
        let proof: Proof =
            wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, 4096)
                .map_err(|_| BridgeError::Binding)?;
        *stage = CoordinatedPairFailureStageV1::StatusValidate;
        if !proof.accepted || proof.reason_code != "REQUEST_ONLY" {
            return Err(BridgeError::Permission);
        }
        *stage = CoordinatedPairFailureStageV1::FinalCurrent;
        client.check_current()?;
        Ok(client)
    }
    pub fn check_current(&self) -> Result<()> {
        require_before(self.deadline)?;
        self.verifier
            .check_original_custody_alive()
            .map_err(|_| BridgeError::Permission)?;
        self.peer
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| BridgeError::Permission)?
            .as_millis();
        if now >= u128::from(self.endpoint.source_expires_at_ms) {
            return Err(BridgeError::Permission);
        }
        Ok(())
    }
    pub fn endpoint(&self) -> &SignerV3PairEndpointV1 {
        &self.endpoint
    }
    pub fn scope(&self) -> &PairScope {
        &self.scope
    }
    /// Called only with the actual retained H payload preparation. The result
    /// is inert request metadata, not a receive/read/admission permission.
    pub fn build_preparation(
        &self,
        request: DurableReviewDeliveryRequestV1,
        fixed: FixedProposalIdentityV1,
        payload_digest: String,
        payload_bytes: u64,
        delivery: DurableDeliveryPlanV2,
        material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,
    ) -> Result<CoordinatedPrepareClosedRecipientRequestV1> {
        self.check_current()?;
        let result = CoordinatedPrepareClosedRecipientRequestV1 {
            version: 1,
            request,
            fixed,
            payload_digest,
            payload_bytes,
            delivery,
            material_scopes,
            coordinated_provider_reference: self.endpoint.coordinated_provider_reference.clone(),
            signer_process_instance: self.endpoint.signer_process_instance.clone(),
        };
        result.validate()?;
        if result.fixed.agreement_id != self.scope.agreement_id
            || result.fixed.manifest_digest != self.scope.manifest_digest
        {
            return Err(BridgeError::Binding);
        }
        Ok(result)
    }
    pub(super) fn open_request(
        &self,
        request: &CoordinatedAppRequestV1,
        deadline: Instant,
    ) -> Result<UnixStream> {
        self.open_request_restricted(request, deadline, &|| Ok(()))
    }
    fn open_request_restricted(
        &self,
        request: &CoordinatedAppRequestV1,
        deadline: Instant,
        restriction: &dyn Fn() -> Result<()>,
    ) -> Result<UnixStream> {
        restriction()?;
        self.check_current()?;
        request.validate(&self.scope)?;
        let deadline = deadline.min(self.deadline);
        let mut stream = wholepact_signer_origin::connect_local_checked_until(
            std::path::Path::new(&self.endpoint.endpoint_path),
            deadline,
            || {
                self.check_current()
                    .and_then(|()| restriction())
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            },
        )
        .map_err(|_| BridgeError::Ipc)?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        self.check_stream(&stream)?;
        restriction()?;
        let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
        let envelope = RequestEnvelope {
            command: "coordinated_v3_request",
            schema_version: 1,
            grant_id: &self.grant_id,
            token_hex: &self.token,
            request,
        };
        v1::bounded_write_restricted(
            &mut stream,
            &envelope,
            deadline,
            || self.check_stream(&observer).and_then(|()| restriction()),
            restriction,
        )?;
        Ok(stream)
    }
    pub(crate) fn original_peer(&self) -> PeerProcess {
        self.peer.clone()
    }
    pub(crate) fn original_channel_deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn open_result_preview(
        &self,
        socket: &std::path::Path,
        request: &crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1,
        deadline: Instant,
        restriction: &dyn Fn() -> Result<()>,
    ) -> Result<UnixStream> {
        if socket != std::path::Path::new(&self.endpoint.endpoint_path) {
            return Err(BridgeError::Binding);
        }
        self.open_request_restricted(
            &CoordinatedAppRequestV1::FinancialResult {
                request: request.clone(),
            },
            deadline,
            restriction,
        )
    }
    pub(crate) fn check_stream(&self, stream: &UnixStream) -> Result<()> {
        self.check_current()?;
        self.verifier
            .verify_connected_signer(stream)
            .map_err(|_| BridgeError::Permission)?;
        let peer = PeerProcess::observe(stream).map_err(|_| BridgeError::Permission)?;
        self.peer
            .same_live_process(&peer)
            .map_err(|_| BridgeError::Permission)
    }
    pub(super) fn read_metadata(
        &self,
        stream: &UnixStream,
        limit: usize,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check_stream(stream)?;
        wholepact_signer_origin::framing::read_frame_capped_checked_until(
            stream,
            &self.peer,
            limit,
            deadline.min(self.deadline),
            || {
                self.check_stream(stream)
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            },
        )
        .map_err(|_| BridgeError::Ipc)
    }
}

#[cfg(test)]
mod pair_failure_tests {
    use super::*;
    const STAGES: [CoordinatedPairFailureStageV1; 20] = [
        CoordinatedPairFailureStageV1::EndpointValidate,
        CoordinatedPairFailureStageV1::ScopeValidate,
        CoordinatedPairFailureStageV1::OriginalCustody,
        CoordinatedPairFailureStageV1::Connect,
        CoordinatedPairFailureStageV1::EnableCredentials,
        CoordinatedPairFailureStageV1::VerifySigner,
        CoordinatedPairFailureStageV1::ObservePeer,
        CoordinatedPairFailureStageV1::CloneObserver,
        CoordinatedPairFailureStageV1::RequestWrite,
        CoordinatedPairFailureStageV1::ResponseRead,
        CoordinatedPairFailureStageV1::ResponseDecode,
        CoordinatedPairFailureStageV1::ResponseValidate,
        CoordinatedPairFailureStageV1::ResponseDigest,
        CoordinatedPairFailureStageV1::ChannelDigest,
        CoordinatedPairFailureStageV1::InitialCurrent,
        CoordinatedPairFailureStageV1::StatusOpen,
        CoordinatedPairFailureStageV1::StatusRead,
        CoordinatedPairFailureStageV1::StatusDecode,
        CoordinatedPairFailureStageV1::StatusValidate,
        CoordinatedPairFailureStageV1::FinalCurrent,
    ];
    #[test]
    fn finite_stage_errors_preserve_the_original_error_variant() {
        // Inert Result injection only: no verifier, socket or Pair authority.
        for stage in STAGES {
            for error in [BridgeError::Binding, BridgeError::Permission, BridgeError::Ipc] {
                let original = std::mem::discriminant(&error);
                let failure = match observe_pair_result::<()>(Err(error), stage, None) {
                    Err(failure) => failure,
                    Ok(()) => panic!("error disappeared"),
                };
                assert_eq!(failure.stage(), stage);
                assert_eq!(std::mem::discriminant(&failure.into_error()), original);
            }
        }
    }
    #[test]
    fn successful_result_has_no_failure_observation() {
        for stage in STAGES {
            assert!(matches!(observe_pair_result(Ok(7), stage, None), Ok(7)));
        }
    }
    #[test]
    fn frame_cause_retained_without_changing_original_ipc_error() {
        use wholepact_signer_origin::framing::FrameReadCause as F;
        use CoordinatedPairFailureClassV1 as C;
        for (cause, class) in [
            (F::Unclassified, C::FrameUnclassified),
            (F::Deadline, C::FrameDeadline),
            (F::Eof, C::FrameEof),
            (F::CredentialsMissing, C::FrameCredentialsMissing),
            (F::CredentialsMismatch, C::FrameCredentialsMismatch),
            (F::AncillaryRejected, C::FrameAncillaryRejected),
            (F::Truncated, C::FrameTruncated),
            (F::PeerNotLive, C::FramePeerNotLive),
            (F::CurrentCheck, C::FrameCurrentCheck),
            (F::Io, C::FrameIo),
            (F::FrameLimit, C::FrameLimit),
            (F::InvalidFrame, C::FrameInvalidFrame),
            (F::InvalidBudget, C::FrameInvalidBudget),
        ] {
            let failure = match observe_pair_result::<()>(
                Err(BridgeError::Ipc), CoordinatedPairFailureStageV1::ResponseRead, Some(cause),
            ) { Err(failure) => failure, Ok(()) => panic!("error disappeared") };
            assert_eq!(failure.class(), class);
            assert!(matches!(failure.into_error(), BridgeError::Ipc));
        }
    }
    #[test]
    fn ordinary_pair_error_class_is_not_mislabeled_as_frame_failure() {
        use CoordinatedPairFailureClassV1 as C;
        for (error, class) in [(BridgeError::Binding, C::BridgeBinding),
            (BridgeError::Permission, C::BridgePermission), (BridgeError::Ipc, C::BridgeIpc)] {
            let failure = match observe_pair_result::<()>(Err(error), STAGES[0], None) {
                Err(failure) => failure, Ok(()) => panic!("error disappeared"),
            };
            assert_eq!(failure.class(), class);
        }
    }
}
