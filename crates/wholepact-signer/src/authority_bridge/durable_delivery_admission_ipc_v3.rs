//! Source-bound V3 continuation over unchanged prospective V2 business data.
//! Neither a receipt nor a status DTO can construct an admission continuation.
use super::{durable_review_ipc_v3::*, durable_delivery_admission_ipc_v2::DurableDeliveryAdmissionStatusV2, ipc::OriginalHistoryClient, BridgeError, Result};
use serde::{Deserialize,Serialize};
use wholepact_authority::OwnerControlRequest;
use std::time::{Duration,Instant};
use std::{os::fd::AsRawFd,path::Path};

#[path = "durable_delivery_admission_ipc_v3/retained_financial_result_v1.rs"]
mod retained_financial_result_v1;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum DurableDeliveryAdmissionStateV3 { AwaitingAudit, Unknown, Verified }
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryAdmissionStatusV3 {
    pub version: u16,
    pub intent_digest: String,
    pub request: OwnerControlRequest,
    pub original_local_intent_digest: String,
    pub state: DurableDeliveryAdmissionStateV3,
    pub audit: Option<DurableDeliveryAdmissionStatusV2>,
}
impl DurableDeliveryAdmissionStatusV3 {
    pub fn validate(&self) -> Result<()> {
        super::durable_construction_v1::hash(&self.intent_digest)?;
        super::durable_construction_v1::hash(&self.original_local_intent_digest)?;
        let wholepact_authority::OwnerControl::AdmitDurablePaymentWithDeliveryV2 {record} = &self.request.control else {return Err(BridgeError::Binding)};
        record.validate_request(&self.request,&record.scope.witness).map_err(|_| BridgeError::Binding)?;
        if self.version != 3 { return Err(BridgeError::Binding); }
        match (&self.state,&self.audit) {
            (DurableDeliveryAdmissionStateV3::Verified,Some(audit)) => {
                audit.validate()?;
                if !audit.witness_committed || audit.request != self.request || audit.original_local_intent_digest != self.original_local_intent_digest { return Err(BridgeError::Binding); }
            }
            (DurableDeliveryAdmissionStateV3::AwaitingAudit | DurableDeliveryAdmissionStateV3::Unknown,None) => {},
            _ => return Err(BridgeError::Binding),
        }
        Ok(())
    }
    /// Checked historical business-data projection, never a permission owner.
    pub fn verified_audit(&self) -> Result<&DurableDeliveryAdmissionStatusV2> {
        self.validate()?;
        if self.state != DurableDeliveryAdmissionStateV3::Verified { return Err(BridgeError::Uncertain); }
        self.audit.as_ref().ok_or(BridgeError::Uncertain)
    }
}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryHistoryRequestV3 { pub intent_digest:String, pub authorization_id:String }
impl DurableDeliveryHistoryRequestV3 {
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest("wholepact:durable-delivery-history-request:v3",self).map_err(|_| BridgeError::Binding)
    }
    pub fn validate(&self)->Result<()> {
        super::durable_construction_v1::hash(&self.intent_digest)?;
        crate::review::validate_label(&self.authorization_id).map_err(|_| BridgeError::Binding)
    }
}
impl VerifiedImportedDurableReviewSessionV3 {
    /// Sends the conditional native-review request once. After its metadata ACK,
    /// every exchange is a read-only poll over the same retained operation.
    pub fn request_admission_v3(self) -> Result<DurableDeliveryAdmissionStatusV3> {
        self.request_admission_retained_v3()?.await_status_v3()
    }
    /// Retains the sealed original process/source continuation before attempting
    /// the one Admit. A lost ACK or later timeout never permits a second Admit.
    pub fn request_admission_retained_v3(self) -> Result<PendingDurableDeliveryAdmissionV3> {
        require_before(self.deadline)?;
        let intent_digest = self.intent.digest()?;
        let nonce = fresh_nonce()?;
        self.origin.check(None)?;
        // Preflight errors above prove no request was attempted. From here the
        // custody owner exists BEFORE the first possible Admit metadata byte.
        let mut pending=PendingDurableDeliveryAdmissionV3 {origin:self.origin,intent:self.intent,deadline:self.deadline,status:None,attempt:DurableAdmissionAttemptStateV3::PossiblyStarted,attempt_error:None};
        let exchange = (|| -> Result<()> {
            let stream = pending.origin.open(&ClosedRecipientCommandV3::Admit {intent_digest:intent_digest.clone(),nonce:nonce.clone()},pending.deadline)?;
            if !matches!(pending.origin.read(&stream,pending.deadline)?,ClosedRecipientResponseV3::Admitting {nonce:actual} if actual == nonce) {return Err(BridgeError::Uncertain);}
            Ok(())
        })();
        // Once an Admit write is attempted, even a lost/malformed ACK must
        // preserve original custody. It may only request fresh exact history.
        match exchange {
            Ok(()) => pending.attempt=DurableAdmissionAttemptStateV3::Acknowledged,
            Err(error) => pending.attempt_error=Some(error),
        }
        Ok(pending)
    }
}
/// Same original installed process and exact intent after the one Admit. This
/// is custody, not renewed read/action permission, and is never serializable.
#[derive(Clone,Copy,PartialEq,Eq)]
pub enum DurableAdmissionAttemptStateV3 { PossiblyStarted, Acknowledged }
pub struct PendingDurableDeliveryAdmissionV3 {
    origin: ClosedRecipientOriginV3,
    intent: RecipientIntentV3,
    deadline: Instant,
    status: Option<DurableDeliveryAdmissionStatusV3>,
    attempt: DurableAdmissionAttemptStateV3,
    attempt_error: Option<BridgeError>,
}
impl PendingDurableDeliveryAdmissionV3 {
    pub fn intent(&self)->&RecipientIntentV3 {&self.intent}
    pub fn status(&self)->Option<&DurableDeliveryAdmissionStatusV3> {self.status.as_ref()}
    pub fn attempt_state(&self)->DurableAdmissionAttemptStateV3 {self.attempt}
    pub fn attempt_error(&self)->Option<&BridgeError> {self.attempt_error.as_ref()}
    pub fn admission_acknowledged(&self)->bool {self.attempt==DurableAdmissionAttemptStateV3::Acknowledged}
    /// Wait under only the original read deadline. Failure preserves this
    /// owner for separately reviewed exact history, never another mutation.
    pub fn await_status_v3(&mut self)->Result<DurableDeliveryAdmissionStatusV3> {
        if let Some(status)=&self.status {return Ok(status.clone());}
        if !self.admission_acknowledged() {return Err(BridgeError::Uncertain);}
        let intent_digest=self.intent.digest()?;
        loop {
            require_before(self.deadline)?;
            let nonce = fresh_nonce()?;
            let stream = self.origin.open(&ClosedRecipientCommandV3::AdmissionStatus {intent_digest:intent_digest.clone(),nonce:nonce.clone()},self.deadline)?;
            match self.origin.read(&stream,self.deadline)? {
                ClosedRecipientResponseV3::Admitting {nonce:actual} if actual == nonce => {drop(stream);std::thread::sleep(Duration::from_millis(100));}
                ClosedRecipientResponseV3::Admission {nonce:actual,admission} if actual == nonce => {
                    self.check_status(&admission)?;
                    self.status=Some(admission.clone());
                    drop(stream);
                    return Ok(admission);
                }
                _ => return Err(BridgeError::Uncertain),
            }
        }
    }
    /// A new metadata request prompts a separately fresh native read decision
    /// against the same retained original operation. No old READ120/action is
    /// consulted or reconstructed. Every socket closes between status polls.
    pub fn read_original_status_v3(mut self)->Result<DurableDeliveryAdmissionStatusV3> {
        self.read_original_status_retained_v3()
    }
    /// The identical separately approved read while keeping actual original
    /// peer/provider custody on return, including uncertainty or refusal. This
    /// neither resends admission nor recovers or renews any prior permission.
    pub fn read_original_status_retained_v3(&mut self)->Result<DurableDeliveryAdmissionStatusV3> {
        let intent_digest=self.intent.digest()?;
        let authorization_id=self.intent.delivery.owners.iter().find(|owner|owner.account_id==self.intent.account_id && owner.participant_id==self.intent.participant_id).ok_or(BridgeError::Binding)?.original_authorization_id.clone();
        let wait=Instant::now()+Duration::from_secs(120);
        loop {
            require_before(wait)?;
            let nonce=fresh_nonce()?;
            let stream=self.origin.open(&ClosedRecipientCommandV3::History {intent_digest:intent_digest.clone(),authorization_id:authorization_id.clone(),nonce:nonce.clone()},wait)?;
            match self.origin.read(&stream,wait)? {
                ClosedRecipientResponseV3::Preparing {nonce:actual} if actual==nonce => {drop(stream);std::thread::sleep(Duration::from_millis(100));}
                ClosedRecipientResponseV3::Admission {nonce:actual,admission} if actual==nonce => {
                    self.check_status(&admission)?;
                    if let Some(previous)=&self.status {
                        if previous.request!=admission.request || previous.original_local_intent_digest!=admission.original_local_intent_digest {return Err(BridgeError::Binding);}
                    }
                    self.status=Some(admission.clone());
                    return Ok(admission);
                }
                _ => return Err(BridgeError::Permission),
            }
        }
    }
    fn check_status(&self,admission:&DurableDeliveryAdmissionStatusV3)->Result<()> {
        check_original_status_v3(&self.intent,admission)
    }
}
fn check_original_status_v3(intent:&RecipientIntentV3,admission:&DurableDeliveryAdmissionStatusV3)->Result<()> {
        admission.validate()?;
        let wholepact_authority::OwnerControl::AdmitDurablePaymentWithDeliveryV2 {record}=&admission.request.control else {return Err(BridgeError::Binding)};
        if admission.intent_digest!=intent.digest()? || admission.request.account_id!=intent.account_id || record.scope.delivery!=intent.delivery || record.scope.authorization.fixed!=fixed_binding_v3(&intent.fixed)? || record.scope.accepted_manifest_ref!=intent.request.accepted_manifest_ref || record.scope.original_ceilings.material_scopes!=intent.material_scopes {return Err(BridgeError::Binding);}
        if let Some(audit)=&admission.audit {
            if audit.original_enrollment_ref!=intent.original_enrollment_ref || audit.original_accepted_manifest_ref!=intent.original_manifest_ref {return Err(BridgeError::Binding);}
        }
        Ok(())
}

/// A freshly authenticated installed process for one separately approved
/// original-history disclosure. Historical intent fields remain historical;
/// none is rebound into a new receive, admission or financial capability.
pub struct ReopenedDurableDeliveryHistoryClientV3 {
    origin: ClosedRecipientOriginV3,
    original: RecipientIntentV3,
    request: DurableDeliveryHistoryRequestV3,
}
impl ReopenedDurableDeliveryHistoryClientV3 {
    pub fn connect(
        provider: super::provider::InstalledSignerProvider,
        endpoint: &Path,
        original: RecipientIntentV3,
        request: DurableDeliveryHistoryRequestV3,
    )->Result<Self> {
        original.validate()?;request.validate()?;
        if !endpoint.is_absolute() || request.intent_digest!=original.digest()? || !original.delivery.owners.iter().any(|owner|owner.account_id==original.account_id && owner.participant_id==original.participant_id && owner.original_authorization_id==request.authorization_id) {return Err(BridgeError::Binding);}
        let deadline=Instant::now()+Duration::from_secs(2);
        let stream=observe_origin_v3(wholepact_signer_origin::connect_local_checked_until(endpoint,deadline,||require_before(deadline).map_err(|_|wholepact_signer_origin::Error::Permission))).map_err(|_|BridgeError::Ipc)?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_|BridgeError::Ipc)?;
        let peer=observe_origin_v3(provider.verify_server(&stream))?;
        require_before(deadline)?;
        observe_origin_v3(peer.check_alive()).map_err(|_|BridgeError::Permission)?;
        drop(stream);
        let scope=crate::ipc::PairScope {account_id:original.account_id.clone(),participant_id:original.participant_id.clone(),agreement_id:original.agreement_id.clone(),manifest_digest:original.manifest_digest.clone(),history_read:true,authorization_export:false,preconstruction_export:false};
        // Scope fields above are comparison data only; no pairing protocol or
        // grant was issued. This owner exposes only the exact History method.
        Ok(Self {origin:ClosedRecipientOriginV3 {provider,socket:endpoint.to_owned(),peer,scope},original,request})
    }
    pub fn read_original_status_v3(self)->Result<DurableDeliveryAdmissionStatusV3> {
        // A bounded metadata/UI wait, NOT a read deadline. The server must
        // obtain a genuine new recipient-bound native read before disclosure.
        let wait=Instant::now()+Duration::from_secs(120);
        loop {
            require_before(wait)?;
            let nonce=fresh_nonce()?;
            let stream=self.origin.open(&ClosedRecipientCommandV3::History {intent_digest:self.request.intent_digest.clone(),authorization_id:self.request.authorization_id.clone(),nonce:nonce.clone()},wait)?;
            match self.origin.read(&stream,wait)? {
                ClosedRecipientResponseV3::Preparing {nonce:actual} if actual==nonce => {drop(stream);std::thread::sleep(Duration::from_millis(100));}
                ClosedRecipientResponseV3::Admission {nonce:actual,admission} if actual==nonce => {
                    check_original_status_v3(&self.original,&admission)?;
                    let wholepact_authority::OwnerControl::AdmitDurablePaymentWithDeliveryV2 {record}=&admission.request.control else{return Err(BridgeError::Binding)};
                    if record.scope.authorization.authorization_id!=self.request.authorization_id {return Err(BridgeError::Binding);}
                    return Ok(admission);
                }
                _ => return Err(BridgeError::Permission),
            }
        }
    }
}
impl OriginalHistoryClient {
    /// A separately authorized fresh history read. This route never resends the
    /// admission and cannot reuse/recover an old native or conditional grant.
    pub fn durable_delivery_admission_history_v3(self,request:&DurableDeliveryHistoryRequestV3)->Result<DurableDeliveryAdmissionStatusV3> {
        request.validate()?;
        let deadline = self.durable_delivery_exchange_deadline_v2();
        let stream = self.open_closed_stage_request_v3(serde_json::json!({"operation":"request_durable_delivery_history_v3","request":request}),false,deadline)?;
        let current = || self.check_closed_stage_origin_v3(&stream,false,deadline);
        let bytes = observe_frame_v3(wholepact_signer_origin::framing::read_frame_capped_checked_observed_until(&stream,self.peer(),MAX_METADATA_V3,deadline,|| current().map_err(|_| wholepact_signer_origin::Error::Permission)))?;
        current()?;
        let response:ClosedRecipientResponseV3 = wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes,MAX_METADATA_V3).map_err(|_| BridgeError::Binding)?;
        if !matches!(response,ClosedRecipientResponseV3::Staged {request_digest} if request_digest == request.digest()?) {return Err(BridgeError::Permission);}
        drop(stream);
        let origin = self.into_closed_history_origin_v3()?;
        let read_wait = Instant::now() + Duration::from_secs(120);
        loop {
            require_before(read_wait)?;
            let nonce = fresh_nonce()?;
            let stream = origin.open(&ClosedRecipientCommandV3::History {intent_digest:request.intent_digest.clone(),authorization_id:request.authorization_id.clone(),nonce:nonce.clone()},read_wait)?;
            match origin.read(&stream,read_wait)? {
                ClosedRecipientResponseV3::Preparing {nonce:actual} if actual == nonce => {drop(stream);std::thread::sleep(Duration::from_millis(100));}
                ClosedRecipientResponseV3::Admission {nonce:actual,admission} if actual == nonce => {
                    admission.validate()?;
                    let wholepact_authority::OwnerControl::AdmitDurablePaymentWithDeliveryV2 {record} = &admission.request.control else {return Err(BridgeError::Binding)};
                    if admission.intent_digest != request.intent_digest || record.scope.authorization.authorization_id != request.authorization_id || admission.request.account_id != origin.scope.account_id || record.scope.authorization.fixed.agreement_id != origin.scope.agreement_id || record.scope.authorization.fixed.manifest_digest != origin.scope.manifest_digest {return Err(BridgeError::Binding);}
                    return Ok(admission);
                }
                _ => return Err(BridgeError::Permission),
            }
        }
    }
}
