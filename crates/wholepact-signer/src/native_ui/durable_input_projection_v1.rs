//! Inactive genuine native projection disclosure and one-hop redisclosure.
//! Pairing permits no export. Only the exact local decision can create these
//! opaque journal append inputs, and the immutable outbox commits before bytes.
use super::wallet_workspace::durable_input_projection_v1::CapturedDurableInputProjectionV1;
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1;
use crate::ipc::durable_input_projection_v1::{
    AuthenticatedInputProjectionPeerV1, AuthenticatedProjectionRedisclosurePeerV1, write_checked_v1,
};
use crate::{Error, Result};
use std::{os::unix::net::UnixStream, sync::Arc, time::Instant};
use wholepact_signer_origin::durable_input_projection_v1::{
    DurableInputProjectionOutboxV1, DurableInputProjectionRequestV1,
    MAX_INPUT_PROJECTION_FRAME_BYTES_V1, ProjectionResponseV1,
    redisclosure::{
        DurableInputProjectionDeliveryV1, DurableInputProjectionRedisclosureRequestV1,
        encode_redisclosure_response_v1,
    },
};
use zeroize::Zeroizing;

fn invalid(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::Locked)
}

/// Call BEFORE the first scan. Existing operations cannot be silently selected
/// again. This lookup returns no old private metadata; redisclosure is separate.
pub(super) fn preflight_initial_v1(
    source: &FreshDurableBornEntryV1,
    peer: &AuthenticatedInputProjectionPeerV1,
    request: &DurableInputProjectionRequestV1,
) -> Result<()> {
    source.check_current()?;
    source.require_input_projection_intent_v1(&request.intent)?;
    peer.require_request(request)?;
    if peer.native_origin() != &source.native_binding() {
        return Err(Error::Authentication);
    }
    source
        .journal()
        .require_new_durable_input_projection_v1(source, request)
        .map_err(invalid)?;
    source.check_original_source_current()?;
    peer.require_request(request)
}

pub(super) struct PreparedDurableInputProjectionV1 {
    source: Arc<FreshDurableBornEntryV1>,
    captured: CapturedDurableInputProjectionV1,
    peer: AuthenticatedInputProjectionPeerV1,
    stream: UnixStream,
    outbox: DurableInputProjectionOutboxV1,
    display: Zeroizing<String>,
    deadline: Instant,
}
pub(crate) struct ApprovedDurableInputProjectionV1 {
    prepared: PreparedDurableInputProjectionV1,
    decision: NativeDecision,
}
impl PreparedDurableInputProjectionV1 {
    pub(super) fn prepare(
        captured: CapturedDurableInputProjectionV1,
        request: DurableInputProjectionRequestV1,
        source: Arc<FreshDurableBornEntryV1>,
        peer: AuthenticatedInputProjectionPeerV1,
        stream: UnixStream,
    ) -> Result<Self> {
        preflight_initial_v1(&source, &peer, &request)?;
        peer.require_stream(&stream)?;
        captured.require_origin(&source, &peer, &request)?;
        let native = source.native_binding();
        let recipient = peer.binding()?;
        let projection = captured.projection().clone();
        let projection_digest = projection.digest().map_err(invalid)?;
        let request_digest = request.digest().map_err(invalid)?;
        // The nonce only prevents accidentally reusing a different UI event;
        // actual current native origin, exact source, peer, request and result
        // are all committed independently. A matching hash issues no consent.
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-durable-input-projection-disclosure:v1",
            &(
                native.entry_digest(),
                source.record().reference()?,
                &request_digest,
                &projection_digest,
                &recipient,
                hex::encode(crate::vault::random::<32>()?),
            ),
        )
        .map_err(invalid)?;
        let mut outbox = DurableInputProjectionOutboxV1 {
            version: 1,
            request,
            request_digest,
            projection,
            projection_digest,
            native_review_digest: digest,
            native_entry_digest: native.entry_digest().into(),
            recipient,
            reference: String::new(),
        };
        outbox.reference = outbox.compute_reference().map_err(invalid)?;
        outbox.validate().map_err(invalid)?;
        encode_initial(&outbox)?; // exact response cap BEFORE approval/commit
        let display = Zeroizing::new(format!(
            "DISCLOSE EXACT NONSPENDING WALLET METADATA\nAccount: {}\nActual local recipient PID/UID: {}/{}\nOriginal policy: {}\nProtected destination: {}\nRetention statement: {}\nValidity: {} until {} (Unix seconds)\nExact request and selected metadata:\n{}\n\nThis copies exact input IDs, values, commitments, provider/chain context and this account's return RECEIVER to the actual paired application, for its stated encrypted destination and the two displayed installed-signer account audiences. The labels and destination statement are not portable proof of recipient behavior. No FVK, note plaintext, witness, spend key or signature is exported.\nSelection targets contribution plus MAXIMUM own fee share. It does not decide the final fee or return amount and reserves no funds. This is NOT a payment approval, a current unspentness guarantee, proof of a named person, distinct people, independent funding, or prior peer approval. Later full-manifest acceptance and exact fixed-proposal review remain separate.\nThe original signer outbox commits before any response. Failed or ambiguous delivery remains retained. Restart redisclosure needs a new exact native decision with the same original material, destination, audience and validity; it cannot rescan or renew old permission.",
            outbox.request.intent.account_id,
            outbox.recipient.pid,
            outbox.recipient.uid,
            outbox.request.intent.original_recipient_policy_digest,
            outbox.request.intent.protected_destination,
            outbox.request.intent.retention_policy,
            outbox.request.intent.valid_from_unix_seconds,
            outbox.request.intent.valid_until_unix_seconds,
            serde_json::to_string_pretty(&outbox).map_err(|_| Error::InvalidData)?,
        ));
        let deadline = peer.deadline().min(native.bounded_deadline()?);
        let result = Self {
            source,
            captured,
            peer,
            stream,
            outbox,
            display,
            deadline,
        };
        result.check_current()?;
        Ok(result)
    }
    pub(super) fn digest(&self) -> &str {
        &self.outbox.native_review_digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.display.to_string())
    }
    fn check_current(&self) -> Result<()> {
        self.source.check_original_source_current()?;
        self.source
            .require_input_projection_intent_v1(&self.outbox.request.intent)?;
        self.peer.require_request(&self.outbox.request)?;
        self.peer.require_stream(&self.stream)?;
        self.captured
            .require_origin(&self.source, &self.peer, &self.outbox.request)?;
        if self.peer.native_origin() != &self.source.native_binding()
            || Instant::now() >= self.deadline
            || self.source.native_binding().entry_digest() != self.outbox.native_entry_digest
            || self.peer.binding()? != self.outbox.recipient
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedDurableInputProjectionV1> {
        self.source.check_current()?;
        self.check_current()?;
        if authority.binding() != self.source.native_binding()
            || decision.binding() != &authority.binding()
            || decision.reviewed_digest() != self.digest()
        {
            return Err(Error::ReviewMismatch);
        }
        let approved = ApprovedDurableInputProjectionV1 {
            prepared: self,
            decision,
        };
        approved.check_current()?;
        Ok(approved)
    }
}
impl ApprovedDurableInputProjectionV1 {
    pub(crate) fn source(&self) -> &FreshDurableBornEntryV1 {
        &self.prepared.source
    }
    pub(crate) fn native_origin(&self) -> &NativeAuthorityBinding {
        self.decision.binding()
    }
    pub(crate) fn outbox(&self) -> &DurableInputProjectionOutboxV1 {
        &self.prepared.outbox
    }
    /// NO journal lock acquisition. Safe while the journal holds its own fence.
    pub(crate) fn check_current(&self) -> Result<()> {
        self.prepared.check_current()?;
        if self.decision.binding() != &self.source().native_binding()
            || self.decision.reviewed_digest() != self.outbox().native_review_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn serve(self) -> Result<()> {
        self.source().check_current()?;
        self.check_current()?;
        // Journal owns the single publication fence AFTER its authority fence
        // and transaction, preserving journal -> native lock ordering.
        let outbox = self
            .source()
            .journal()
            .record_durable_input_projection_v1(&self)
            .map_err(invalid)?;
        // The journal must return the exact candidate, not silently substitute
        // an older operation/native decision/channel. Never expose on mismatch.
        if &outbox != self.outbox() {
            return Err(Error::ReviewMismatch);
        }
        let raw = encode_initial(&outbox)?;
        let mut stream = self.prepared.stream.try_clone()?;
        write_checked_v1(
            &mut stream,
            raw,
            self.prepared.deadline,
            self.native_origin(),
            || self.check_current(),
        )
    }
}
fn encode_initial(outbox: &DurableInputProjectionOutboxV1) -> Result<Zeroizing<Vec<u8>>> {
    outbox.validate().map_err(invalid)?;
    let raw = Zeroizing::new(
        serde_json::to_vec(&ProjectionResponseV1::Retained {
            outbox: Box::new(outbox.clone()),
        })
        .map_err(|_| Error::InvalidData)?,
    );
    if raw.len() >= MAX_INPUT_PROJECTION_FRAME_BYTES_V1 {
        return Err(Error::InvalidData);
    }
    Ok(raw)
}

pub(super) struct PreparedDurableProjectionRedeliveryV1 {
    source: Arc<FreshDurableBornEntryV1>,
    peer: AuthenticatedProjectionRedisclosurePeerV1,
    stream: UnixStream,
    original: DurableInputProjectionOutboxV1,
    delivery: DurableInputProjectionDeliveryV1,
    display: Zeroizing<String>,
    deadline: Instant,
}
pub(crate) struct ApprovedDurableProjectionRedeliveryV1 {
    prepared: PreparedDurableProjectionRedeliveryV1,
    decision: NativeDecision,
}
impl PreparedDurableProjectionRedeliveryV1 {
    pub(super) fn prepare(
        request: DurableInputProjectionRedisclosureRequestV1,
        source: Arc<FreshDurableBornEntryV1>,
        peer: AuthenticatedProjectionRedisclosurePeerV1,
        stream: UnixStream,
    ) -> Result<Self> {
        source.check_current()?;
        source.require_input_projection_intent_v1(&request.original_request.intent)?;
        peer.require_request(&request)?;
        peer.require_stream(&stream)?;
        if peer.native_origin() != &source.native_binding() {
            return Err(Error::Authentication);
        }
        // Historical private read only from this ACTUAL original journal. No
        // host-supplied projection, optional locator, delivery chain, or scan.
        let original = source
            .journal()
            .prepare_durable_input_projection_redisclosure_source_v1(
                &source,
                &request.original_request,
            )
            .map_err(invalid)?;
        original.validate().map_err(invalid)?;
        if original.request != request.original_request {
            return Err(Error::ReviewMismatch);
        }
        original.request.require_valid_at(now()?).map_err(invalid)?;
        let native = source.native_binding();
        let recipient = peer.binding()?;
        let request_digest = request.digest().map_err(invalid)?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-durable-input-projection-redisclosure:v1",
            &(
                native.entry_digest(),
                source.record().reference()?,
                &request_digest,
                &original.reference,
                &original.projection_digest,
                &recipient,
                hex::encode(crate::vault::random::<32>()?),
            ),
        )
        .map_err(invalid)?;
        let mut delivery = DurableInputProjectionDeliveryV1 {
            version: 1,
            request,
            request_digest,
            original_outbox_reference: original.reference.clone(),
            original_projection_digest: original.projection_digest.clone(),
            native_review_digest: review_digest,
            native_entry_digest: native.entry_digest().into(),
            recipient,
            reference: String::new(),
        };
        delivery.reference = delivery.compute_reference().map_err(invalid)?;
        delivery.require_original(&original).map_err(invalid)?;
        encode_redisclosure_response_v1(&original, &delivery).map_err(invalid)?;
        let display = Zeroizing::new(format!(
            "NEW DISCLOSURE OF THE EXACT ORIGINAL WALLET METADATA\nOriginal operation: {}\nOriginal request digest: {}\nOriginal outbox: {}\nNew delivery operation: {}\nActual new local recipient PID/UID: {}/{}\nExact original retained data:\n{}\nExact new delivery link:\n{}\n\nThis is a NEW privacy disclosure, not continuation of old permission. The original destination, two-account audience, retention statement and validity are unchanged. Metadata was selected at the ORIGINAL capture time and is NOT refreshed, reserved, or currently spendable merely because it is redelivered. No scan, reselection, FVK/note/witness export, manifest acceptance, financial approval or signature occurs.\nA one-hop immutable delivery receipt is committed before bytes; the original row is neither replaced nor relabelled. Partial/failed delivery remains disclosed-or-unknown. Copied data cannot be recalled by closing this window.",
            original.request.operation_id,
            original.request_digest,
            original.reference,
            delivery.request.operation_id,
            delivery.recipient.pid,
            delivery.recipient.uid,
            serde_json::to_string_pretty(&original).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&delivery).map_err(|_| Error::InvalidData)?,
        ));
        let deadline = peer.deadline().min(native.bounded_deadline()?);
        let result = Self {
            source,
            peer,
            stream,
            original,
            delivery,
            display,
            deadline,
        };
        result.check_current()?;
        Ok(result)
    }
    pub(super) fn digest(&self) -> &str {
        &self.delivery.native_review_digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.display.to_string())
    }
    fn check_current(&self) -> Result<()> {
        self.source.check_original_source_current()?;
        self.source
            .require_input_projection_intent_v1(&self.original.request.intent)?;
        self.peer.require_request(&self.delivery.request)?;
        self.peer.require_stream(&self.stream)?;
        self.delivery
            .require_original(&self.original)
            .map_err(invalid)?;
        if self.peer.native_origin() != &self.source.native_binding()
            || self.source.native_binding().entry_digest() != self.delivery.native_entry_digest
            || self.peer.binding()? != self.delivery.recipient
            || Instant::now() >= self.deadline
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedDurableProjectionRedeliveryV1> {
        self.source.check_current()?;
        self.check_current()?;
        if authority.binding() != self.source.native_binding()
            || decision.binding() != &authority.binding()
            || decision.reviewed_digest() != self.digest()
        {
            return Err(Error::ReviewMismatch);
        }
        let approved = ApprovedDurableProjectionRedeliveryV1 {
            prepared: self,
            decision,
        };
        approved.check_current()?;
        Ok(approved)
    }
}
impl ApprovedDurableProjectionRedeliveryV1 {
    pub(crate) fn source(&self) -> &FreshDurableBornEntryV1 {
        &self.prepared.source
    }
    pub(crate) fn native_origin(&self) -> &NativeAuthorityBinding {
        self.decision.binding()
    }
    pub(crate) fn original(&self) -> &DurableInputProjectionOutboxV1 {
        &self.prepared.original
    }
    pub(crate) fn delivery(&self) -> &DurableInputProjectionDeliveryV1 {
        &self.prepared.delivery
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.prepared.check_current()?;
        if self.decision.binding() != &self.source().native_binding()
            || self.decision.reviewed_digest() != self.delivery().native_review_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn serve(self) -> Result<()> {
        self.source().check_current()?;
        self.check_current()?;
        // No outer publication lease: the journal owns its final bounded commit
        // fence in journal -> native order. Never recursively acquire either.
        let delivery = self
            .source()
            .journal()
            .record_durable_input_projection_redelivery_v1(&self)
            .map_err(invalid)?;
        if &delivery != self.delivery() {
            return Err(Error::ReviewMismatch);
        }
        let raw = encode_redisclosure_response_v1(self.original(), &delivery).map_err(invalid)?;
        let mut stream = self.prepared.stream.try_clone()?;
        write_checked_v1(
            &mut stream,
            raw,
            self.prepared.deadline,
            self.native_origin(),
            || self.check_current(),
        )
    }
}
