//! Concrete restriction-only publication owner. The actual born source, exact
//! authenticated request channel and genuine native decision survive every byte.
use super::super::{NativeDecision, PendingAccountNativeAuthority};
use crate::{
    account::birth::enrollment::roster_v2::permanent_stop::BornPermanentStopSourceV1,
    ipc::permanent_stop::AuthenticatedPermanentStopRequestV1, Error, Result,
};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
use wholepact_signer_origin::permanent_stop_v1::{
    encode_frame, HostPermanentStopAcknowledgmentV1, PermanentStopCommandV1,
    PermanentStopEvidenceV1, PermanentStopResponseV1,
};
use zeroize::Zeroizing;
pub(super) struct PreparedPermanentStopPublicationV1 {
    source: BornPermanentStopSourceV1,
    request: AuthenticatedPermanentStopRequestV1,
    evidence: PermanentStopEvidenceV1,
    digest: String,
    reply_binding: crate::ipc::permanent_stop::PermanentStopReplyBinding,
    display: Zeroizing<String>,
}
impl PreparedPermanentStopPublicationV1 {
    pub(super) fn prepare(
        source: BornPermanentStopSourceV1,
        request: AuthenticatedPermanentStopRequestV1,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.check(owner)?;
        request.check_current()?;
        if source.native_binding() != &request.peer().native_origin {
            return Err(Error::Authentication);
        }
        let pairing =
            super::super::AuthenticatedPairing::from_authenticated_request(request.peer().clone())?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-permanent-stop-host-publication:v1",
            &(
                source.record(),
                source.snapshot()?,
                request.request(),
                pairing.binding(),
                hex::encode(crate::vault::random::<32>()?),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let evidence = source.host_evidence(request.request(), &digest)?;
        let (_, history) = source.complete_display()?;
        let display = Zeroizing::new(format!("PUBLISH THE EXACT PERMANENT RESTRICTION TO THIS FRESHLY PAIRED HOST\n\n{}\n\n{}\n\nComplete supported pending exposure remains:\n{}\n\nThe source is the actual retained born vault and original journal. The original witness exclusion receipt is historical evidence. The paired Host must independently authenticate its own exact original encrypted enrollment; client-supplied identifiers never establish that ownership. This channel permits only restriction publication and its durable acknowledgment. Every bounded partial write rechecks the original source, grant, channel and deadline. Cancellation cannot recall bytes already admitted. The first exact Host acknowledgment is encrypted and retained before the final reply. Interrupted publication remains pending and retry preserves durable originals. No funds movement, readiness, empty-account or recovery completion is claimed.\nExact native review: {}", serde_json::to_string_pretty(pairing.binding()).map_err(|_| Error::InvalidData)?, serde_json::to_string_pretty(&evidence).map_err(|_| Error::InvalidData)?, serde_json::to_string_pretty(&history).map_err(|_| Error::InvalidData)?, digest));
        let reply_binding = request.reply_binding();
        Ok(Self {
            source,
            request,
            evidence,
            digest,
            reply_binding,
            display,
        })
    }
    pub(super) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn review_json(&self) -> Result<String> {
        self.request.check_current()?;
        self.source.native_binding().check_current()?;
        Ok(self.display.to_string())
    }
    fn check(&self, owner: &PendingAccountNativeAuthority, deadline: Instant) -> Result<()> {
        self.source.check(owner)?;
        self.request.check_current()?;
        self.request.require_reply_binding(&self.reply_binding)?;
        if Instant::now() >= deadline
            || self.source.native_binding() != &self.request.peer().native_origin
            || self
                .source
                .host_evidence(self.request.request(), &self.digest)?
                != self.evidence
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn send(
        &mut self,
        response: &PermanentStopResponseV1,
        owner: &PendingAccountNativeAuthority,
        deadline: Instant,
    ) -> Result<()> {
        let bytes = encode_frame(response).map_err(|_| Error::InvalidData)?;
        let mut progress =
            crate::ipc::permanent_stop::PermanentStopFrameProgress::new(bytes.len(), deadline)?;
        while !progress.complete() {
            self.check(owner, deadline)?;
            // A short admitted write holds native invalidation until this syscall
            // drains, never across the next peer read or durable Host operation.
            let binding = self.source.native_binding().clone();
            let _native = binding.publication_lease()?;
            self.check(owner, deadline)?;
            let wrote = self
                .request
                .write_part(&bytes[progress.offset()..], deadline)?;
            progress.advance(wrote, Instant::now())?;
            self.check(owner, deadline)?;
        }
        Ok(())
    }
    pub(super) fn approve_and_publish(
        mut self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<BornPermanentStopSourceV1> {
        let deadline = self
            .request
            .deadline()
            .min(Instant::now() + Duration::from_secs(30));
        self.check(owner, deadline)?;
        if decision.binding() != self.source.native_binding()
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        let lease_id = hex::encode(crate::vault::random::<32>()?);
        let evidence_digest = self.evidence.digest().map_err(|_| Error::InvalidData)?;
        self.send(
            &PermanentStopResponseV1::Held {
                lease_id: lease_id.clone(),
                evidence: Box::new(self.evidence.clone()),
            },
            owner,
            deadline,
        )?;
        let mut challenges = BTreeSet::new();
        for _ in 0..128 {
            self.check(owner, deadline)?;
            let command = self.request.read_command(deadline)?;
            self.check(owner, deadline)?;
            match command {
                PermanentStopCommandV1::CheckCurrent {
                    lease_id: claimed,
                    evidence_digest: digest,
                    challenge_nonce,
                } => {
                    if claimed != lease_id
                        || digest != evidence_digest
                        || challenge_nonce.len() != 64
                        || hex::decode(&challenge_nonce).is_err()
                        || !challenges.insert(challenge_nonce.clone())
                    {
                        return Err(Error::Authentication);
                    }
                    self.send(
                        &PermanentStopResponseV1::Current {
                            lease_id: lease_id.clone(),
                            evidence_digest: evidence_digest.clone(),
                            challenge_nonce,
                        },
                        owner,
                        deadline,
                    )?;
                }
                PermanentStopCommandV1::Acknowledge {
                    lease_id: claimed,
                    evidence_digest: digest,
                    acknowledgment,
                } => {
                    if claimed != lease_id || digest != evidence_digest {
                        return Err(Error::Authentication);
                    }
                    acknowledgment
                        .require_evidence(&self.evidence)
                        .map_err(|_| Error::Authentication)?;
                    let receipt = AuthenticatedPermanentStopHostReceiptV1 {
                        publication: &self,
                        acknowledgment: &acknowledgment,
                        owner,
                        deadline,
                    };
                    self.source.retain_host_ack(&receipt)?;
                    self.send(&PermanentStopResponseV1::Acknowledged {}, owner, deadline)?;
                    return Ok(self.source);
                }
            }
        }
        Err(Error::Unavailable)
    }
}
/// Not constructible from an acknowledgment DTO. This borrow retains the exact
/// producer, authenticated channel and original native owner through persistence.
pub(crate) struct AuthenticatedPermanentStopHostReceiptV1<'a> {
    publication: &'a PreparedPermanentStopPublicationV1,
    acknowledgment: &'a HostPermanentStopAcknowledgmentV1,
    owner: &'a PendingAccountNativeAuthority,
    deadline: Instant,
}
impl AuthenticatedPermanentStopHostReceiptV1<'_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.publication.check(self.owner, self.deadline)
    }
    pub(crate) fn evidence(&self) -> &PermanentStopEvidenceV1 {
        &self.publication.evidence
    }
    pub(crate) fn acknowledgment(&self) -> &HostPermanentStopAcknowledgmentV1 {
        self.acknowledgment
    }
    pub(crate) fn source(&self) -> &BornPermanentStopSourceV1 {
        &self.publication.source
    }
}
