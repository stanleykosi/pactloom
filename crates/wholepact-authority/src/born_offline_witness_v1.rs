//! Separate born wire origin. A returned ciphertext remains inert until the
//! dedicated recipient verifies its exact native enrollment and actual history.
use crate::born_offline_owner_continuation_v1::BornOfflineTransportAuthenticationV1;
use crate::{born_offline_admission_v1::*, offline_witness_v1::*, *};
use serde::{Deserialize, Serialize};
/// Pure exact wire-size preflight. The fixed-width proof below is inert sizing
/// data only, never returned, transmitted, authenticated or used as authority.
pub fn validate_born_offline_intent_delivery_size_v1(
    request: &BornOfflineReservationRequestV1,
    original_envelope: &[u8],
    export_template: &OfflineAdmissionExportPlan,
) -> Result<()> {
    if original_envelope.is_empty()
        || original_envelope.len() > MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1
    {
        return Err(AuthorityError::Limit);
    }
    let mut wire = BornOfflineWitnessRequestV1 {
        request: request.clone(),
        original_envelope_hex: hex::encode(original_envelope),
        export_template: export_template.clone(),
        authentication: BornOfflineTransportAuthenticationV1::OriginalWriterSessionV1 {
            proof: protocol::WriterSessionProof {
                session_id: "0".repeat(64),
                tag: "0".repeat(64),
            },
        },
    };
    wire.record()?;
    encode(&protocol::WireRequest::SubmitBornOfflineIntentV1(Box::new(
        wire.clone(),
    )))?;
    wire.authentication = BornOfflineTransportAuthenticationV1::OriginalOwnerContinuationV1 {
        enrollment_digest: "0".repeat(64),
        continuation_digest: "0".repeat(64),
    };
    encode(&protocol::WireRequest::SubmitBornOfflineIntentV1(Box::new(
        wire,
    )))
    .map(|_| ())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornOfflineWitnessRequestV1 {
    pub(crate) request: BornOfflineReservationRequestV1,
    pub(crate) original_envelope_hex: String,
    pub(crate) export_template: OfflineAdmissionExportPlan,
    pub(crate) authentication: BornOfflineTransportAuthenticationV1,
}
impl BornOfflineWitnessRequestV1 {
    #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
    pub(crate) fn envelope(&self) -> Result<Vec<u8>> {
        decode_ciphertext(&self.original_envelope_hex)
    }
    pub(crate) fn record(&self) -> Result<BornOfflineReservationRecordV1> {
        self.request.validate()?;
        let inner = offline_reservation_record_from_wire_v1(
            &self.request.reservation,
            &self.original_envelope_hex,
            &self.export_template,
        )?;
        Ok(BornOfflineReservationRecordV1 {
            request: self.request.clone(),
            authentication: inner.authentication,
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineDeliveryLookupV1 {
    pub original: OfflineAdmissionDeliveryLookupV1,
    pub original_born_request_digest: String,
    pub enrollment_digest: String,
    pub artifact_binding_digest: String,
}
impl BornOfflineDeliveryLookupV1 {
    pub fn from_request(r: &BornOfflineReservationRequestV1) -> Result<Self> {
        r.validate()?;
        Ok(Self {
            original: OfflineAdmissionDeliveryLookupV1::from_request(&r.reservation)?,
            original_born_request_digest: r.request_digest()?,
            enrollment_digest: r.enrollment_digest.clone(),
            artifact_binding_digest: r.artifact_binding_digest.clone(),
        })
    }
    pub fn validate(&self) -> Result<()> {
        self.original.validate()?;
        for h in [
            &self.original_born_request_digest,
            &self.enrollment_digest,
            &self.artifact_binding_digest,
        ] {
            hash(h)?;
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornOfflineDeliveryBodyV1 {
    pub(crate) origin: BornOfflineDeliveryLookupV1,
    pub(crate) delivery: OfflineWitnessDeliveryBodyV1,
}
impl BornOfflineDeliveryBodyV1 {
    pub(crate) fn validate(&self) -> Result<Vec<u8>> {
        self.origin.validate()?;
        if self.origin.original != self.delivery.original {
            return Err(AuthorityError::InvalidBinding);
        }
        self.delivery.validate()
    }
}
/// Actual pinned mTLS result metadata and original ciphertext, never a permit.
pub struct BornOfflineDeliveryV1 {
    pub(crate) body: BornOfflineDeliveryBodyV1,
    pub(crate) ciphertext: Vec<u8>,
}
impl BornOfflineDeliveryV1 {
    pub fn original(&self) -> &BornOfflineDeliveryLookupV1 {
        &self.body.origin
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn original_admission_digest(&self) -> &str {
        &self.body.delivery.original_admission_digest
    }
    pub fn export_plan(&self) -> &OfflineAdmissionExportPlan {
        &self.body.delivery.export_plan
    }
    pub fn committed_head(&self) -> &AuthorityHead {
        &self.body.delivery.committed_head
    }
    pub fn recovered_original(&self) -> bool {
        self.body.delivery.recovered_original
    }
    pub fn signing_authority(&self) -> bool {
        false
    }
}

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
mod size_tests {
    use super::*;
    #[test]
    fn born_preflight_preserves_distinct_wire_origin_and_exact_frame_ceiling() {
        let (ledger, _, record) = crate::born_offline_admission_v1::tests::fixture();
        let p = &ledger
            .born_offline_enrollment_v1()
            .unwrap()
            .unwrap()
            .enrollment
            .policy;
        let t = &record.request.reservation.intent.terms;
        let plan = OfflineAdmissionExportPlan {
            message_id: "11".repeat(16),
            sequence: 0,
            issued_at_unix_seconds: 254,
            expires_at_unix_seconds: 255,
            purpose: "Synthetic sizing data only".into(),
            persistence_warning: "No authenticated delivery".into(),
            sender_id: format!("offline-admission:{}", t.offline_policy_digest),
            recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
            sender_key_fingerprint: p.witness_transport_key_digest.clone(),
            recipient_key_fingerprint: p.offline_signer_key_digest.clone(),
        };
        // Deliberately not an HPKE envelope: this function can only prove sizing.
        assert!(
            validate_born_offline_intent_delivery_size_v1(&record.request, b"inert", &plan).is_ok()
        );
        assert!(
            validate_born_offline_intent_delivery_size_v1(&record.request, &[], &plan).is_err()
        );
        assert!(
            validate_born_offline_intent_delivery_size_v1(
                &record.request,
                &vec![0; MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1 + 1],
                &plan
            )
            .is_err()
        );
        let mut changed = plan.clone();
        changed.sequence = 1;
        assert!(
            validate_born_offline_intent_delivery_size_v1(&record.request, b"inert", &changed)
                .is_err()
        );
        let mut request = record.request;
        request.version = 2;
        assert!(validate_born_offline_intent_delivery_size_v1(&request, b"inert", &plan).is_err());
    }
}
