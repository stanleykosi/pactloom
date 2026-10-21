//! Genuine Read -> Receive -> independently verified original source custody.
//! No legacy NativeDecision/AuthenticatedPeer/recipient owner is reconstructed.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::{
    CoordinatedPreparedDeliverySourceV1, CoordinatedPreparingDeliverySourceV1,
};
use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::{
    CoordinatedClosedResponseV1, CoordinatedRecipientIntentV1, CoordinatedVerifiedReceiptV1,
};
use crate::native_ui::durable_proposal_v1::VerifiedDurableEconomicsV1;
use crate::native_ui::witness_workspace::durable_delivery_v3::coordinated_v1::{
    CoordinatedDeliveryWitnessV1, PreparedCoordinatedDeliveryWitnessV1,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use std::sync::Arc;
use std::time::Duration;
use std::{
    os::unix::net::UnixStream,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_financial_coordinator_origin::{
    SignerV3PrepareReadFactsV1, SignerV3PrepareReadFinalV1, SignerV3PreparedV1,
    SignerV3ReceiveFactsV1, SignerV3ReceiveFinalV1, SignerV3ReceivedV1,
};
#[path = "coordinated_v3_delivery_v1/receive_wire_v1.rs"]
mod receive_wire_v1;
#[path = "coordinated_v3_delivery_v1/verify_payload_v1.rs"]
mod verify_payload_v1;
fn unix_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Locked)?
            .as_millis(),
    )
    .map_err(|_| Error::Locked)
}
fn remaining(deadline: Instant) -> Result<u64> {
    let n = u64::try_from(
        deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
    )
    .map_err(|_| Error::Locked)?;
    if n == 0 {
        Err(Error::Locked)
    } else {
        Ok(n)
    }
}
fn wall_at(captured: Instant, wall: u64, deadline: Instant, ceiling: u64) -> Result<u64> {
    let n = u64::try_from(deadline.saturating_duration_since(captured).as_millis())
        .map_err(|_| Error::Locked)?;
    if n == 0 {
        return Err(Error::Locked);
    }
    wall.checked_add(n)
        .map(|v| v.min(ceiling))
        .ok_or(Error::Locked)
}
fn canonical<T: serde::Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::InvalidData)
}

pub(super) struct PreparedCoordinatedDeliveryReviewV1 {
    source: CoordinatedPreparingDeliverySourceV1,
    witness: PreparedCoordinatedDeliveryWitnessV1,
    facts: SignerV3PrepareReadFactsV1,
    read_deadline: Instant,
    service_deadline: Instant,
    material_deadline: Instant,
}
pub(super) struct CoordinatedReceiveReviewV1 {
    source: CoordinatedPreparedDeliverySourceV1,
    witness: CoordinatedDeliveryWitnessV1,
    prepared: SignerV3PreparedV1,
    facts: SignerV3ReceiveFactsV1,
    deadline: Instant,
}
pub(super) struct CoordinatedReadyToReceiveV1 {
    source: CoordinatedPreparedDeliverySourceV1,
    witness: CoordinatedDeliveryWitnessV1,
    prepared: SignerV3PreparedV1,
    intent: CoordinatedRecipientIntentV1,
    action: SignerV3ReceiveFinalV1,
}
pub(super) struct CoordinatedReceivedBytesV1 {
    ready: CoordinatedReadyToReceiveV1,
    bytes: Zeroizing<Vec<u8>>,
}
/// The sole constructor follows actual payload digest/canonical decoding and
/// independent proof/economics verification under the original Receive Final.
pub(crate) struct CoordinatedVerifiedImportV1 {
    pub(super) source: CoordinatedPreparedDeliverySourceV1,
    pub(super) witness: CoordinatedDeliveryWitnessV1,
    pub(super) intent: CoordinatedRecipientIntentV1,
    pub(super) fixed: VerifiedDurableEconomicsV1,
    pub(super) receipt: CoordinatedVerifiedReceiptV1,
    pub(super) report: SignerV3ReceivedV1,
}
impl PreparedCoordinatedDeliveryReviewV1 {
    pub(super) fn prepare(
        source: CoordinatedPreparingDeliverySourceV1,
        owner_setup_json: String,
        owner_selection_challenge: String,
    ) -> Result<Self> {
        source.check_current()?;
        let witness = PreparedCoordinatedDeliveryWitnessV1::prepare(
            &owner_setup_json,
            &source.disclosure()?,
            source.owner_certificate_digest(),
            source.source_identity(),
            source.original_source_deadline(),
            source.original_channel_deadline(),
            source.original_material_deadline(),
        )?;
        let captured = Instant::now();
        let wall = unix_ms()?;
        let read_deadline = witness.original_read_deadline();
        let service_deadline = witness.original_service_deadline();
        let material_deadline = source.original_material_deadline();
        let p = source.preparation();
        let peer = source.peer();
        let facts = SignerV3PrepareReadFactsV1 {
            entry_presentation_digest: source.entry_digest().into(),
            source_identity_digest: source.source_identity().into(),
            pair_grant_id: peer.grant_id().into(),
            pair_key_digest: peer.key_digest().into(),
            pair_channel_digest: peer.channel_digest().into(),
            pair_generation: peer.generation(),
            coordinated_session_id: source.enrollment().receipt().native_session_id().into(),
            current_enrollment_ref: source.enrollment().reference().into(),
            current_manifest_ref: source.manifest().reference().into(),
            current_outbox_reference: source.outbox().reference().into(),
            current_request_digest: source.outbox().request_digest().into(),
            preparation_digest: source.preparation_digest().into(),
            preparation_json: serde_json::to_string(p).map_err(|_| Error::InvalidData)?,
            owner_setup_json,
            owner_selection_challenge,
            owner_selection_digest: witness.selection_digest().into(),
            owner_certificate_digest: witness.certificate_digest().into(),
            disclosure_digest: witness.disclosure_digest()?,
            payload_digest: p.payload_digest.clone(),
            payload_bytes: p.payload_bytes,
            fixed_identity_digest:
                crate::authority_bridge::durable_review_ipc_v3::verified_fixed_identity_digest_v3(
                    &p.fixed,
                )
                .map_err(|_| Error::ReviewMismatch)?,
            material_scopes_digest: canonical(
                "wholepact:coordinated-v3-material-scopes:v1",
                &p.material_scopes,
            )?,
            coordinated_provider_reference: peer.coordinated_provider_reference().into(),
            original_host_process_instance: peer.original_host_process_instance().into(),
            display: witness.display().into(),
            reviewed_at_ms: wall,
            expires_at_ms: wall_at(captured, wall, read_deadline, source.source_wall_expiry())?,
            source_expires_at_ms: source.source_wall_expiry(),
            service_expires_at_ms: wall_at(
                captured,
                wall,
                service_deadline,
                source.source_wall_expiry(),
            )?,
            material_expires_at_ms: wall_at(
                captured,
                wall,
                material_deadline,
                source.source_wall_expiry(),
            )?,
        };
        facts.validate()?;
        source.check_current()?;
        Ok(Self {
            source,
            witness,
            facts,
            read_deadline,
            service_deadline,
            material_deadline,
        })
    }
    pub(super) fn facts(&self) -> &SignerV3PrepareReadFactsV1 {
        &self.facts
    }
    pub(super) fn deadlines(&self) -> (Instant, Instant, Instant) {
        (
            self.read_deadline,
            self.service_deadline,
            self.material_deadline,
        )
    }
    pub(super) fn check_current(&self) -> Result<()> {
        self.source.check_current()?;
        self.witness.check_selection()?;
        if Instant::now() >= self.read_deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(super) fn consume_read(
        self,
        action: SignerV3PrepareReadFinalV1,
    ) -> Result<CoordinatedReceiveReviewV1> {
        self.check_current()?;
        action.check_current()?;
        if action.facts() != &self.facts || action.original_read_deadline() != self.read_deadline {
            return Err(Error::ReviewMismatch);
        }
        let opened = self.source.read(&action)?;
        let witness = self.witness.open_read(&action)?;
        action.check_current()?;
        let read_digest = action.presentation().presentation_digest.clone();
        let lifetime = Arc::new(action.into_prepared_custody_lifetime()?);
        let source = opened.seal_read(Arc::clone(&lifetime))?;
        let witness = witness.seal_read(lifetime)?;
        let prepared = SignerV3PreparedV1 {
            prepare_read_presentation_digest: read_digest.clone(),
            preparation_digest: self.facts.preparation_digest.clone(),
            source_identity_digest: self.facts.source_identity_digest.clone(),
            owner_service_digest: witness.owner_service_digest().into(),
            read_session_digest: read_digest.clone(),
        };
        prepared.validate()?;
        let captured = Instant::now();
        let wall = unix_ms()?;
        let deadline = captured
            .checked_add(Duration::from_secs(120))
            .ok_or(Error::Locked)?
            .min(source.original_material_deadline());
        let f = self.facts;
        let facts=SignerV3ReceiveFactsV1{entry_presentation_digest:f.entry_presentation_digest,source_identity_digest:f.source_identity_digest,pair_grant_id:f.pair_grant_id,pair_key_digest:f.pair_key_digest,pair_channel_digest:f.pair_channel_digest,pair_generation:f.pair_generation,coordinated_session_id:f.coordinated_session_id,current_enrollment_ref:f.current_enrollment_ref,current_manifest_ref:f.current_manifest_ref,current_outbox_reference:f.current_outbox_reference,current_request_digest:f.current_request_digest,preparation_digest:f.preparation_digest,owner_selection_digest:f.owner_selection_digest,owner_certificate_digest:f.owner_certificate_digest,disclosure_digest:f.disclosure_digest,payload_digest:f.payload_digest,payload_bytes:f.payload_bytes,fixed_identity_digest:f.fixed_identity_digest,material_scopes_digest:f.material_scopes_digest,coordinated_provider_reference:f.coordinated_provider_reference,original_host_process_instance:f.original_host_process_instance,prepare_read_presentation_digest:read_digest.clone(),owner_service_digest:prepared.owner_service_digest.clone(),read_session_digest:read_digest,display:"Receive and independently verify exactly this fixed payload from the original paired Host. No admission or financial effect is approved.".into(),reviewed_at_ms:wall,expires_at_ms:wall_at(captured,wall,deadline,f.material_expires_at_ms)?,source_expires_at_ms:f.source_expires_at_ms,service_expires_at_ms:f.service_expires_at_ms,material_expires_at_ms:f.material_expires_at_ms};
        facts.validate()?;
        Ok(CoordinatedReceiveReviewV1 {
            source,
            witness,
            prepared,
            facts,
            deadline,
        })
    }
}
impl CoordinatedReceiveReviewV1 {
    pub(super) fn facts(&self) -> &SignerV3ReceiveFactsV1 {
        &self.facts
    }
    pub(super) fn prepared_report(&self) -> &SignerV3PreparedV1 {
        &self.prepared
    }
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(super) fn check_current(&self) -> Result<()> {
        self.source.check_current()?;
        if Instant::now() >= self.deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(super) fn consume_final(
        self,
        action: SignerV3ReceiveFinalV1,
    ) -> Result<CoordinatedReadyToReceiveV1> {
        self.check_current()?;
        action.check_current()?;
        if action.facts() != &self.facts || action.original_receive_deadline() != self.deadline {
            return Err(Error::ReviewMismatch);
        }
        let p = self.source.preparation();
        let peer = self.source.peer();
        let intent = CoordinatedRecipientIntentV1 {
            version: 1,
            request: p.request.clone(),
            fixed: p.fixed.clone(),
            payload_digest: p.payload_digest.clone(),
            payload_bytes: p.payload_bytes,
            delivery: p.delivery.clone(),
            material_scopes: p.material_scopes.clone(),
            account_id: self.source.enrollment().account_id().into(),
            participant_id: self.source.enrollment().participant_id().into(),
            agreement_id: self.source.enrollment().agreement_id().into(),
            manifest_digest: self.source.manifest().proposal()?.manifest_digest().into(),
            coordinated_provider_reference: peer.coordinated_provider_reference().into(),
            signer_process_instance: peer.signer_process_instance().into(),
            authorized_host_process_instance: peer.original_host_process_instance().into(),
            source_identity_digest: self.source.source_identity().into(),
            source_generation: peer.generation(),
            read_session_digest: self.source.read_presentation_digest().into(),
            receive_decision_digest: action.presentation().presentation_digest.clone(),
            original_enrollment_ref: self.source.enrollment().reference().into(),
            original_manifest_ref: self.source.manifest().reference().into(),
        };
        intent.validate().map_err(|_| Error::ReviewMismatch)?;
        Ok(CoordinatedReadyToReceiveV1 {
            source: self.source,
            witness: self.witness,
            prepared: self.prepared,
            intent,
            action,
        })
    }
}
impl CoordinatedReadyToReceiveV1 {
    pub(super) fn check_current(&self) -> Result<()> {
        self.source.check_current()?;
        self.action.check_current()?;
        Ok(())
    }
    pub(super) fn next_event(&self) -> Result<Option<crate::ipc::CoordinatedLocalEventV1>> {
        self.check_current()?;
        self.source.next_event()
    }
    pub(super) fn preparation_digest(&self) -> &str {
        &self.prepared.preparation_digest
    }
    pub(super) fn respond_prepared(
        self,
        peer: crate::ipc::CoordinatedPairPeerV1,
        mut stream: UnixStream,
        nonce: String,
        request_deadline: Instant,
    ) -> Result<Self> {
        self.check_current()?;
        self.source.peer().require_same_grant(&peer)?;
        let response = CoordinatedClosedResponseV1::Prepared {
            nonce,
            intent: self.intent.clone(),
            remaining_read_ms: remaining(self.action.original_receive_deadline())?.min(120_000),
            remaining_material_ms: remaining(self.source.original_material_deadline())?
                .min(900_000),
        };
        self.write_response(&mut stream, &response, request_deadline)?;
        Ok(self)
    }
    fn write_response(
        &self,
        stream: &mut UnixStream,
        response: &CoordinatedClosedResponseV1,
        request_deadline: Instant,
    ) -> Result<()> {
        let deadline = request_deadline
            .min(self.action.original_receive_deadline())
            .min(self.source.original_material_deadline());
        crate::authority_bridge::durable_review_ipc_v1::bounded_write_restricted(
            stream,
            response,
            deadline,
            || {
                self.check_current()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)
            },
            &|| {
                self.source
                    .peer()
                    .check_current()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
                self.action
                    .check_current()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)
            },
        )
        .map_err(|_| Error::Uncertain)
    }
    pub(super) fn receive(
        self,
        peer: crate::ipc::CoordinatedPairPeerV1,
        mut stream: UnixStream,
        intent_digest: String,
        nonce: String,
        request_deadline: Instant,
    ) -> Result<CoordinatedReceivedBytesV1> {
        self.check_current()?;
        self.source.peer().require_same_grant(&peer)?;
        if self.intent.digest().map_err(|_| Error::ReviewMismatch)? != intent_digest {
            return Err(Error::ReviewMismatch);
        }
        let deadline = request_deadline
            .min(self.action.original_receive_deadline())
            .min(self.source.original_material_deadline());
        self.write_response(
            &mut stream,
            &CoordinatedClosedResponseV1::Ready {
                intent_digest,
                nonce,
                remaining_read_ms: remaining(deadline)?.min(120_000),
            },
            deadline,
        )?;
        let bytes =
            receive_wire_v1::receive_exact(stream, &peer, &self.intent, &self.action, deadline)
                .map_err(|_| Error::Uncertain)?;
        Ok(CoordinatedReceivedBytesV1 { ready: self, bytes })
    }
}
impl CoordinatedReceivedBytesV1 {
    pub(super) fn check_current(&self) -> Result<()> {
        self.ready.check_current()
    }
    pub(super) fn next_event(&self) -> Result<Option<crate::ipc::CoordinatedLocalEventV1>> {
        self.ready.next_event()
    }
    pub(super) fn verify(
        self,
        peer: crate::ipc::CoordinatedPairPeerV1,
        mut stream: UnixStream,
        intent_digest: String,
        nonce: String,
        request_deadline: Instant,
    ) -> Result<CoordinatedVerifiedImportV1> {
        self.check_current()?;
        self.ready.source.peer().require_same_grant(&peer)?;
        if self
            .ready
            .intent
            .digest()
            .map_err(|_| Error::ReviewMismatch)?
            != intent_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let (fixed, receipt) = verify_payload_v1::verify_exact(
            &self.ready.source,
            &self.ready.intent,
            &self.ready.action,
            self.bytes,
        )?;
        self.ready.write_response(
            &mut stream,
            &CoordinatedClosedResponseV1::Verified {
                nonce,
                receipt: receipt.clone(),
            },
            request_deadline,
        )?;
        let report = SignerV3ReceivedV1 {
            receive_presentation_digest: self
                .ready
                .action
                .presentation()
                .presentation_digest
                .clone(),
            prepare_read_presentation_digest: self.ready.source.read_presentation_digest().into(),
            source_identity_digest: self.ready.source.source_identity().into(),
            owner_service_digest: self.ready.witness.owner_service_digest().into(),
            recipient_intent_digest: intent_digest,
            payload_digest: self.ready.intent.payload_digest.clone(),
            payload_bytes: self.ready.intent.payload_bytes,
            fixed_identity_digest: receipt.verified_fixed_identity_digest.clone(),
        };
        report.validate()?;
        self.ready
            .action
            .finish_receive()
            .map_err(|_| Error::Uncertain)?;
        Ok(CoordinatedVerifiedImportV1 {
            source: self.ready.source,
            witness: self.ready.witness,
            intent: self.ready.intent,
            fixed,
            receipt,
            report,
        })
    }
}
impl CoordinatedVerifiedImportV1 {
    pub(super) fn check_current(&self) -> Result<()> {
        self.source.check_current()
    }
    pub(super) fn report(&self) -> SignerV3ReceivedV1 {
        self.report.clone()
    }
    pub(super) fn next_event(&self) -> Result<Option<crate::ipc::CoordinatedLocalEventV1>> {
        self.source.next_event()
    }
}
/// Staging is inert: reply only after exact original peer/request selection,
/// without private source/key reads or any Receive authority.
pub(super) fn stage_preparation(
    source:crate::account::birth::enrollment::roster_v2::durable_entry_v1::CoordinatedRedisclosedSourceV1,
    peer: crate::ipc::CoordinatedPairPeerV1,
    mut stream: UnixStream,
    request:crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedPrepareClosedRecipientRequestV1,
    request_deadline: Instant,
) -> Result<CoordinatedPreparingDeliverySourceV1> {
    let source = source.begin_preparation(&peer, request)?;
    let response = CoordinatedClosedResponseV1::Staged {
        request_digest: source.preparation_digest().into(),
    };
    crate::authority_bridge::durable_review_ipc_v1::bounded_write_restricted(
        &mut stream,
        &response,
        request_deadline.min(source.original_material_deadline()),
        || {
            source
                .check_current()
                .map_err(|_| crate::authority_bridge::BridgeError::Permission)
        },
        &|| {
            peer.check_current()
                .map_err(|_| crate::authority_bridge::BridgeError::Permission)
        },
    )
    .map_err(|_| Error::Uncertain)?;
    Ok(source)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coordinated_delivery_original_material_ceiling_is_not_receive_renewal(){
        let captured=Instant::now();let original=captured+Duration::from_secs(25);
        assert_eq!(wall_at(captured,1_000,original,900_000).unwrap(),26_000);
        assert!(wall_at(original,26_000,original,900_000).is_err());
    }
    #[test]
    fn coordinated_delivery_original_source_wall_remains_ceiling(){
        let captured=Instant::now();
        assert_eq!(wall_at(captured,1_000,captured+Duration::from_secs(120),3_000).unwrap(),3_000);
    }
}
