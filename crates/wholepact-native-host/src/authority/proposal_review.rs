//! Foreground native issuer for non-authorizing economic proposal intake.
//! The incoming peer is pinned independently; the engine supplies local policy,
//! mappings and exact artifact digests. This lease never authorizes signing.
use super::*;
use wholepact_engine::transport_workflows::proposal_review::{
    ProposalTransportReviewAuthority, ProposalTransportReviewLease, ProposalTransportReviewScope,
};
use wholepact_transport::ArtifactKind;

struct ProposalLease {
    scope: ProposalTransportReviewScope,
    expires: Timestamp,
    held: Held,
}
impl ProposalTransportReviewLease for ProposalLease {
    fn scope(&self) -> &ProposalTransportReviewScope {
        &self.scope
    }
    fn expires_at(&self) -> &Timestamp {
        &self.expires
    }
    fn check_current(&self) -> std::result::Result<(), ApiError> {
        api(self.held.check())
    }
}
impl ProposalTransportReviewAuthority for Authority {
    fn acquire<'a>(
        &'a self,
        scope: &ProposalTransportReviewScope,
        preview: &DisclosurePreview,
    ) -> std::result::Result<Box<dyn ProposalTransportReviewLease + 'a>, ApiError> {
        api((|| {
            self.principal(&scope.principal_id)?;
            if scope.store != self.store
                || scope.context != preview.context
                || scope.context.artifact_kind != ArtifactKind::Proposal
                || scope.preview_digest != preview.digest()?
                || scope.sender_key_fingerprint != preview.sender_key_fingerprint
                || scope.recipient_key_fingerprint != preview.recipient_key_fingerprint
                || scope.expected_agreement_revision == 0
                || preview.fields.len() != 2
                || !preview
                    .fields
                    .iter()
                    .any(|f| f.name == "proposal_review_request_v1")
                || !preview
                    .fields
                    .iter()
                    .any(|f| f.name == "proposal_pczt_v2" && f.sha256 == scope.artifact_digest)
            {
                return Err(Error::Permission);
            }
            for digest in [
                &scope.artifact_digest,
                &scope.manifest_digest,
                &scope.policy_fingerprint,
                &scope.mapping_fingerprint,
            ] {
                if digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(Error::Permission);
                }
            }
            let expiry = now()?.saturating_add(60);
            let held = self.fence.acquire(expiry)?;
            let pins = self.pins.lock().map_err(|_| Error::Permission)?;
            let pin = pins
                .get(&pin_key(
                    &scope.principal_id,
                    &scope.context,
                    TransportDirection::Incoming,
                )?)
                .ok_or(Error::Permission)?;
            let own = TransportSecret::from_bytes(*self.secret)?
                .public_key()?
                .fingerprint();
            if pin.principal != scope.principal_id
                || pin.context != scope.context
                || pin.direction != TransportDirection::Incoming
                || pin.peer.fingerprint() != scope.sender_key_fingerprint
                || own != scope.recipient_key_fingerprint
            {
                return Err(Error::Permission);
            }
            drop(pins);
            self.terminal.confirm(&format!(
                "Review this exact authenticated incoming proposal against independently supplied local policy. This records economic verification only. It does not approve spending, account attribution, disclosure to another party, or submission. Historical replays cannot create a new review.\nProfile: {}\nRuntime: {}\nPrincipal: {}\nPurpose: economic proposal review\nExact source/destination and selected fields:\n{}\nArtifact: {}\nManifest: {}\nLocal policy: {}\nLocal action mapping: {}\nExpected agreement revision: {}\nConsent expires Unix: {}\n",
                self.profile, self.runtime, scope.principal_id, serde_json::to_string_pretty(preview)?,
                scope.artifact_digest, scope.manifest_digest, scope.policy_fingerprint,
                scope.mapping_fingerprint, scope.expected_agreement_revision, expiry,
            ))?;
            held.check()?;
            Ok(Box::new(ProposalLease {
                scope: scope.clone(),
                expires: Timestamp::from_unix_seconds(expiry as i64)?,
                held,
            }) as Box<dyn ProposalTransportReviewLease>)
        })())
    }
}
