//! Activation-gated borrowed-vault retirement observation transport. Both exact native
//! preparations survive their decisions and every bounded reply write. There is
//! no ownership DTO importer or financial capability conversion. The dedicated
//! native entry retains these exact owners on its one worker stack.
#![allow(dead_code)] // Activation remains gated until attended/transport qualification.
use super::{
    NativeAuthority, NativeDecision,
    retirement_destination::{
        ApprovedRecoveryDestination, PreparedRecoveryDestination, RecoveryDestinationRequest,
    },
    retirement_recipient::RetirementEvidenceRecipient,
    retirement_source::{PreparedRetirementSource, RetirementSourceRead},
};
use crate::{
    Error, Result,
    account::AccountVault,
    ipc::{
        AuthenticatedPeer,
        retirement_evidence::{
            AuthenticatedRetirementEvidenceRequestV1, RetirementEvidenceReplyBinding,
        },
    },
};
use sha2::{Digest, Sha256};
use std::time::Instant;
use wholepact_signer_origin::retirement_evidence::{
    RetirementDestinationEvidenceRequestV1, RetirementDestinationEvidenceResponseV1,
    RetirementEvidencePoolV1,
};

/// Only a successful private authenticated request seam can provide `reply`.
/// Actual vault borrows deliberately prevent detached or self-referential GUI
/// storage. No request-supplied destination account/FVK/recipient is accepted.
pub(super) struct PreparedRetirementEvidenceV1<'a> {
    reply: AuthenticatedRetirementEvidenceRequestV1,
    request: RecoveryDestinationRequest,
    source_vault: &'a AccountVault,
    destination_vault: &'a AccountVault,
    source: PreparedRetirementSource,
}
pub(super) struct PreparedRetirementDestinationEvidenceV1<'a> {
    reply: AuthenticatedRetirementEvidenceRequestV1,
    request: RecoveryDestinationRequest,
    source_vault: &'a AccountVault,
    source: RetirementSourceRead,
    destination: PreparedRecoveryDestination<'a>,
}
pub(super) struct ApprovedRetirementEvidenceV1<'a> {
    reply: AuthenticatedRetirementEvidenceRequestV1,
    delivery: RetirementEvidenceDelivery<'a>,
}
/// Concrete, nonserializable retained approvals. The IPC sender accepts this
/// type, never a caller-supplied approval predicate or already-detached DTO.
pub(crate) struct RetirementEvidenceDelivery<'a> {
    source: RetirementSourceRead,
    source_vault: &'a AccountVault,
    destination: ApprovedRecoveryDestination<'a>,
    request: RecoveryDestinationRequest,
    wire_digest: String,
    reply_binding: RetirementEvidenceReplyBinding,
    deadline: Instant,
}

impl<'a> PreparedRetirementEvidenceV1<'a> {
    pub(super) fn prepare(
        reply: AuthenticatedRetirementEvidenceRequestV1,
        source_vault: &'a AccountVault,
        destination_vault: &'a AccountVault,
        source_native: &NativeAuthority,
        destination_native: &NativeAuthority,
    ) -> Result<Self> {
        reply.check_current()?;
        let wire = reply.request();
        wire.require_pair_scope(&reply.peer().scope)
            .map_err(|_| Error::Authentication)?;
        let request = RecoveryDestinationRequest {
            operation_id: wire.operation_id.clone(),
            destination_account_id: destination_vault.account_id()?,
            address: wire.address.clone(),
            network_profile_id: wire.network_profile_id.clone(),
            source_account_id: source_vault.account_id()?,
            source_fvk_digest: hex::encode(Sha256::digest(
                source_vault.account().fvk()?.to_bytes(),
            )),
            local_recipient: reply.peer().grant_id.clone(),
        };
        if request.source_account_id != wire.source_account_id {
            return Err(Error::ReviewMismatch);
        }
        // Check actual destination membership before exposing the source review.
        // This local preparation is discarded; it grants no decision or delivery.
        PreparedRecoveryDestination::prepare(
            destination_vault,
            destination_native,
            request.clone(),
        )?;
        let source = PreparedRetirementSource::prepare_for_peer(
            source_vault,
            source_native,
            &request,
            reply.peer().clone(),
        )?;
        reply.check_current()?;
        Ok(Self {
            reply,
            request,
            source_vault,
            destination_vault,
            source,
        })
    }
    /// Recheck the original reply and preparation while the worker waits. This
    /// borrows the same actual vault; no new preparation or lease is minted.
    pub(super) fn check_current(&self) -> Result<()> {
        self.reply.check_current()?;
        self.source.check_current(self.source_vault)?;
        self.reply.check_current()
    }
    pub(super) fn deadline(&self) -> Instant {
        self.reply.deadline()
    }
    pub(super) fn digest(&self) -> &str {
        self.source.digest()
    }
    pub(super) fn display(&self) -> Result<String> {
        self.reply.check_current()?;
        Ok(self.source.display() + &transport_display(self.reply.request())?)
    }
    pub(super) fn approve_source(
        self,
        native: &NativeAuthority,
        decision: NativeDecision,
        destination_native: &NativeAuthority,
    ) -> Result<PreparedRetirementDestinationEvidenceV1<'a>> {
        self.reply.check_current()?;
        let source = self.source.approve(self.source_vault, native, decision)?;
        let destination = PreparedRecoveryDestination::prepare_for_retirement_recipient(
            self.destination_vault,
            destination_native,
            self.request.clone(),
            &source,
            self.source_vault,
        )?;
        self.reply.check_current()?;
        Ok(PreparedRetirementDestinationEvidenceV1 {
            reply: self.reply,
            request: self.request,
            source_vault: self.source_vault,
            source,
            destination,
        })
    }
}
impl<'a> PreparedRetirementDestinationEvidenceV1<'a> {
    pub(super) fn check_current(&self) -> Result<()> {
        self.reply.check_current()?;
        self.source
            .check_destination(self.source_vault, &self.request)?;
        self.destination.check_current()?;
        self.reply.check_current()
    }
    pub(super) fn deadline(&self) -> Instant {
        self.reply.deadline().min(self.source.deadline())
    }
    pub(super) fn digest(&self) -> &str {
        self.destination.digest()
    }
    pub(super) fn display(&self) -> Result<String> {
        self.reply.check_current()?;
        self.source
            .check_destination(self.source_vault, &self.request)?;
        Ok(self.destination.display() + &transport_display(self.reply.request())?)
    }
    pub(super) fn approve_destination(
        self,
        native: &NativeAuthority,
        decision: NativeDecision,
    ) -> Result<ApprovedRetirementEvidenceV1<'a>> {
        self.reply.check_current()?;
        self.source
            .check_destination(self.source_vault, &self.request)?;
        // Consume this exact stored preparation; never re-prepare after a click.
        let destination = self.destination.approve(decision, native)?;
        let delivery = RetirementEvidenceDelivery::new(
            self.source,
            self.source_vault,
            destination,
            self.request,
            self.reply.request(),
            self.reply.binding()?,
        )?;
        delivery.check(self.reply.peer(), self.reply.request())?;
        self.reply.check_current()?;
        Ok(ApprovedRetirementEvidenceV1 {
            reply: self.reply,
            delivery,
        })
    }
}
impl ApprovedRetirementEvidenceV1<'_> {
    pub(super) fn check_current(&self) -> Result<()> {
        self.reply.check_current()?;
        self.delivery.require_reply(&self.reply)?;
        self.delivery
            .check(self.reply.peer(), self.reply.request())?;
        self.reply.check_current()
    }
    pub(super) fn deliver(self) -> Result<()> {
        self.reply.deliver(self.delivery)
    }
}
impl<'a> RetirementEvidenceDelivery<'a> {
    pub(super) fn new(
        source: RetirementSourceRead,
        source_vault: &'a AccountVault,
        destination: ApprovedRecoveryDestination<'a>,
        request: RecoveryDestinationRequest,
        wire: &RetirementDestinationEvidenceRequestV1,
        reply_binding: RetirementEvidenceReplyBinding,
    ) -> Result<Self> {
        reply_binding.check_current()?;
        let deadline = reply_binding
            .deadline()
            .min(source.deadline())
            .min(destination.deadline());
        let wire_digest = wire.digest().map_err(|_| Error::InvalidData)?;
        reply_binding.require_request_digest(&wire_digest)?;
        let owner = Self {
            source,
            source_vault,
            destination,
            request,
            wire_digest,
            reply_binding,
            deadline,
        };
        let recipient = owner.source.recipient().ok_or(Error::Authentication)?;
        owner.check_recipient(recipient, wire)?;
        Ok(owner)
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn require_reply(
        &self,
        reply: &AuthenticatedRetirementEvidenceRequestV1,
    ) -> Result<()> {
        reply.require_binding(&self.reply_binding)
    }
    pub(crate) fn check(
        &self,
        peer: &AuthenticatedPeer,
        wire: &RetirementDestinationEvidenceRequestV1,
    ) -> Result<()> {
        let recipient = RetirementEvidenceRecipient::from_peer(peer.clone())?;
        self.check_recipient(&recipient, wire)
    }
    pub(super) fn check_recipient(
        &self,
        recipient: &RetirementEvidenceRecipient,
        wire: &RetirementDestinationEvidenceRequestV1,
    ) -> Result<()> {
        self.reply_binding.check_current()?;
        if Instant::now() >= self.deadline
            || wire.digest().map_err(|_| Error::InvalidData)? != self.wire_digest
            || wire.operation_id != self.request.operation_id
            || wire.source_account_id != self.request.source_account_id
            || wire.network_profile_id != self.request.network_profile_id
            || wire.address != self.request.address
        {
            return Err(Error::ReviewMismatch);
        }
        wire.require_pair_scope(recipient.scope())
            .map_err(|_| Error::Authentication)?;
        self.source
            .check_destination(self.source_vault, &self.request)?;
        self.source.check_recipient(Some(recipient))?;
        self.destination.evidence_for_retirement_delivery(
            &self.source,
            self.source_vault,
            recipient,
        )?;
        self.reply_binding.check_current()?;
        if Instant::now() >= self.deadline {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn response(
        &self,
        peer: &AuthenticatedPeer,
        wire: &RetirementDestinationEvidenceRequestV1,
    ) -> Result<RetirementDestinationEvidenceResponseV1> {
        let recipient = RetirementEvidenceRecipient::from_peer(peer.clone())?;
        self.response_for_recipient(&recipient, wire)
    }
    pub(super) fn response_for_recipient(
        &self,
        recipient: &RetirementEvidenceRecipient,
        wire: &RetirementDestinationEvidenceRequestV1,
    ) -> Result<RetirementDestinationEvidenceResponseV1> {
        self.check_recipient(recipient, wire)?;
        let fact = self.destination.evidence_for_retirement_delivery(
            &self.source,
            self.source_vault,
            recipient,
        )?;
        let response = RetirementDestinationEvidenceResponseV1::Observed {
            schema_version: wire.schema_version,
            purpose: wire.purpose.clone(),
            request_digest: self.wire_digest.clone(),
            request_nonce: wire.request_nonce.clone(),
            operation_id: wire.operation_id.clone(),
            source_account_id: self.request.source_account_id.clone(),
            destination_account_id: fact.user_controlled_account_ref,
            address: fact.address,
            network_profile_id: fact.network_profile_id,
            pool: RetirementEvidencePoolV1::Ironwood,
            source_review_ref: self.source.review_digest().into(),
            destination_review_ref: fact.ownership_evidence_digest,
            recipient_grant_id: recipient.grant_id().into(),
        };
        response
            .require_request_binding(wire, recipient.grant_id())
            .map_err(|_| Error::ReviewMismatch)?;
        self.check_recipient(recipient, wire)?;
        Ok(response)
    }
}

fn transport_display(request: &RetirementDestinationEvidenceRequestV1) -> Result<String> {
    Ok(format!(
        "\nTransport purpose: retirement destination observation only\nExact V1 request commitment: {}\nRequest nonce: {}\nDisclosed fields: operation and request correlation, actual source/destination account association, exact address/network/pool, original source and destination review references, and this recipient's grant ID. The recipient can retain this historical information; it is not current ownership authority, permission to reclaim, or complete retirement evidence.",
        request.digest().map_err(|_| Error::InvalidData)?,
        request.request_nonce,
    ))
}
