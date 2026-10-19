//! Bounded exact v2 admission/history and original-witness public evidence.
//! Only a live paired client constructs the nominal evidence owner. Wire data
//! grants neither file ownership, trust roots, native consent nor spending.
use super::{ipc::OriginalHistoryClient, BridgeError, Result};
use super::durable_review_ipc_v1::DurableReviewDeliveryRequestV1;
use serde::{Deserialize, Serialize};
use std::{os::unix::net::UnixStream, time::Instant};
use wholepact_authority::{
    durable_delivery_scope_v2::{DurableDeliveryPlanV2, DurableDeliveryScopeV2},
    OwnerControlRequest, WitnessDisclosureDescriptor,
};
use wholepact_core::{
    manual_enrollment::BornManualEnrollmentTerms, manual_roster_v2::HostRosterAppendBindingV2,
};
const MAX_FRAME: usize = 512 * 1024;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryAdmissionRequestV2 {
    pub version: u16,
    pub import_request: DurableReviewDeliveryRequestV1,
    pub delivery: DurableDeliveryPlanV2,
}
impl DurableDeliveryAdmissionRequestV2 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 2
            || serde_json::to_vec(self)
                .map_err(|_| BridgeError::Binding)?
                .len()
                > 128 * 1024
        {
            return Err(BridgeError::Binding);
        }
        self.import_request.validate()
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryHistoryRequestV2 {
    pub authorization_id: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub enum DurableDeliveryCommandV2 {
    OriginalWitnessEvidence {},
    Admit {
        request: DurableDeliveryAdmissionRequestV2,
    },
    History {
        request: DurableDeliveryHistoryRequestV2,
    },
}
impl DurableDeliveryCommandV2 {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::OriginalWitnessEvidence {} => Ok(()),
            Self::Admit { request } => request.validate(),
            Self::History { request } => crate::review::validate_label(&request.authorization_id)
                .map_err(|_| BridgeError::Binding),
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalWitnessPublicDataV2 {
    pub(crate) version: u16,
    pub(crate) original_terms: BornManualEnrollmentTerms,
    pub(crate) original_roster: HostRosterAppendBindingV2,
    pub(crate) original_signer_roster_record_digest: String,
    pub(crate) witness: WitnessDisclosureDescriptor,
    pub(crate) native_entry_digest: String,
    pub(crate) original_enrollment_ref: String,
    pub(crate) original_witness_extension_digest: String,
    pub(crate) local_grant_id: String,
    pub(crate) local_channel_digest: String,
}
impl OriginalWitnessPublicDataV2 {
    pub(crate) fn validate(&self) -> Result<()> {
        self.original_terms
            .validate()
            .map_err(|_| BridgeError::Binding)?;
        self.original_roster
            .validate_for_host(&self.original_terms.host)
            .map_err(|_| BridgeError::Binding)?;
        self.witness.validate().map_err(|_| BridgeError::Binding)?;
        for h in [
            &self.original_signer_roster_record_digest,
            &self.local_channel_digest,
            &self.native_entry_digest,
            &self.original_enrollment_ref,
            &self.original_witness_extension_digest,
        ] {
            super::durable_construction_v1::hash(h)?;
        }
        if self.version != 2
            || self.witness.account_id != self.original_terms.identity.account_id
            || self.witness.network_profile_id != self.original_terms.identity.network_profile_id
            || self.witness.policy_digest != self.original_terms.original_policy_digest
            || wholepact_authority::account_use_link::account_use_witness_origin_digest(
                &self.witness,
            )
            .map_err(|_| BridgeError::Binding)?
                != self.original_terms.original_witness_origin_digest
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
/// Inert exact status, never permission to Acquire, Activate, Reserve or dispatch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDeliveryAdmissionStatusV2 {
    pub version: u16,
    pub request: OwnerControlRequest,
    pub scope: DurableDeliveryScopeV2,
    pub original_enrollment_ref: String,
    pub original_accepted_manifest_ref: String,
    pub original_local_intent_digest: String,
    pub authenticated_witness_history_digest: String,
    pub witness_committed: bool,
    /// This Signer does not own or attest the current Host private workspace.
    pub current_fixed_material_source: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DurableDeliveryResponseV2 {
    OriginalWitnessEvidence {
        evidence: OriginalWitnessPublicDataV2,
    },
    Admission {
        admission: DurableDeliveryAdmissionStatusV2,
    },
    Denied,
}
/// A borrowed actual paired process/stream owner, not a deserializable assertion.
pub struct OriginalWitnessEvidenceV2<'a> {
    client: &'a OriginalHistoryClient,
    stream: UnixStream,
    data: OriginalWitnessPublicDataV2,
    deadline: Instant,
}
impl OriginalWitnessEvidenceV2<'_> {
    pub fn witness(&self) -> &WitnessDisclosureDescriptor {
        &self.data.witness
    }
    pub fn original_terms(&self) -> &BornManualEnrollmentTerms {
        &self.data.original_terms
    }
    pub fn original_roster(&self) -> &HostRosterAppendBindingV2 {
        &self.data.original_roster
    }
    pub fn original_signer_roster_record_digest(&self) -> &str {
        &self.data.original_signer_roster_record_digest
    }
    pub fn enrollment_ref(&self) -> &str {
        &self.data.original_enrollment_ref
    }
    pub fn witness_extension_digest(&self) -> &str {
        &self.data.original_witness_extension_digest
    }
    pub fn check_current(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(BridgeError::Permission);
        }
        self.client
            .check_durable_delivery_peer_v2(&self.stream, &self.data)?;
        // Reauthenticate the actual original native source without extending
        // this owner's original deadline or adopting a new grant/process.
        let (_, response) = self.client.delivery_exchange_v2(
            &DurableDeliveryCommandV2::OriginalWitnessEvidence {},
            self.deadline,
        )?;
        let DurableDeliveryResponseV2::OriginalWitnessEvidence { evidence } = response else {
            return Err(BridgeError::Permission);
        };
        if evidence != self.data {
            return Err(BridgeError::Binding);
        }
        self.client
            .check_durable_delivery_peer_v2(&self.stream, &self.data)
    }
}
impl OriginalHistoryClient {
    fn delivery_exchange_v2(
        &self,
        request: &DurableDeliveryCommandV2,
        deadline: Instant,
    ) -> Result<(UnixStream, DurableDeliveryResponseV2)> {
        request.validate()?;
        if Instant::now() >= deadline {
            return Err(BridgeError::Permission);
        }
        let frame =
            serde_json::json!({"operation":"request_durable_delivery_v2", "request":request});
        let stream = if matches!(request, DurableDeliveryCommandV2::Admit { .. }) {
            self.open_preconstruction_request(frame)?
        } else {
            self.open_inspection_request(frame)?
        };
        self.check_durable_delivery_request_origin_v2(&stream, request)?;
        let bytes = wholepact_signer_origin::framing::read_frame_capped_checked_until(
            &stream,
            self.peer(),
            MAX_FRAME,
            deadline,
            || {
                self.check_durable_delivery_request_origin_v2(&stream, request)
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            },
        )
        .map_err(|_| BridgeError::Ipc)?;
        let response =
            wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, MAX_FRAME)
                .map_err(|_| BridgeError::Binding)?;
        self.check_durable_delivery_request_origin_v2(&stream, request)?;
        Ok((stream, response))
    }
    pub fn original_witness_evidence_v2(&self) -> Result<OriginalWitnessEvidenceV2<'_>> {
        let deadline = self.durable_delivery_exchange_deadline_v2();
        let (stream, response) = self.delivery_exchange_v2(
            &DurableDeliveryCommandV2::OriginalWitnessEvidence {},
            deadline,
        )?;
        let DurableDeliveryResponseV2::OriginalWitnessEvidence { evidence } = response else {
            return Err(BridgeError::Permission);
        };
        self.check_durable_delivery_peer_v2(&stream, &evidence)?;
        Ok(OriginalWitnessEvidenceV2 {
            client: self,
            stream,
            data: evidence,
            deadline,
        })
    }
    pub fn request_durable_delivery_admission_v2(
        &self,
        request: &DurableDeliveryAdmissionRequestV2,
    ) -> Result<DurableDeliveryAdmissionStatusV2> {
        let (_, response) = self.delivery_exchange_v2(
            &DurableDeliveryCommandV2::Admit {
                request: request.clone(),
            },
            self.durable_delivery_exchange_deadline_v2(),
        )?;
        let DurableDeliveryResponseV2::Admission { admission } = response else {
            return Err(BridgeError::Permission);
        };
        self.check_durable_delivery_status_v2(&admission)?;
        if admission.version != 2
            || admission.original_enrollment_ref != request.import_request.enrollment_ref
            || admission.scope.authorization.fixed.proposal_binding
                != request.import_request.proposal_binding
            || admission.scope.delivery != request.delivery
            || admission.scope.accepted_manifest_ref != request.import_request.accepted_manifest_ref
        {
            return Err(BridgeError::Binding);
        }
        Ok(admission)
    }
    pub fn durable_delivery_admission_history_v2(
        &self,
        request: &DurableDeliveryHistoryRequestV2,
    ) -> Result<DurableDeliveryAdmissionStatusV2> {
        let (_, response) = self.delivery_exchange_v2(
            &DurableDeliveryCommandV2::History {
                request: request.clone(),
            },
            self.durable_delivery_exchange_deadline_v2(),
        )?;
        let DurableDeliveryResponseV2::Admission { admission } = response else {
            return Err(BridgeError::Permission);
        };
        self.check_durable_delivery_status_v2(&admission)?;
        if admission.version != 2
            || admission.scope.authorization.authorization_id != request.authorization_id
        {
            return Err(BridgeError::Binding);
        }
        Ok(admission)
    }
}

impl DurableDeliveryAdmissionStatusV2 {
    /// Strict inert response coherence only. Actual source custody remains with
    /// the producing native runtime and the receiving authenticated client.
    pub fn validate(&self) -> Result<()> {
        self.scope.validate().map_err(|_| BridgeError::Binding)?;
        let wholepact_authority::OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } =
            &self.request.control
        else {
            return Err(BridgeError::Binding);
        };
        record
            .validate_request(&self.request, &self.scope.witness)
            .map_err(|_| BridgeError::Binding)?;
        for hash in [
            &self.original_enrollment_ref,
            &self.original_accepted_manifest_ref,
            &self.original_local_intent_digest,
            &self.authenticated_witness_history_digest,
        ] {
            super::durable_construction_v1::hash(hash)?;
        }
        if self.version != 2
            || record.scope != self.scope
            || self.original_accepted_manifest_ref != self.scope.accepted_manifest_ref
            || self.current_fixed_material_source != "unchecked"
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
