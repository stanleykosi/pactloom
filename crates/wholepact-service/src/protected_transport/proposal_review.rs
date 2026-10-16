//! Native file-to-economic-review path and exact interrupted-import recovery.
//! Private policy and action mappings originate locally, never in HTTP input.
use super::*;
use wholepact_engine::transport_workflows::proposal_review::LocalProposalTransportReview;

impl ProtectedTransportRuntime {
    pub fn review_incoming_proposal(
        &mut self,
        access: &Access,
        expected: MessageContext,
        envelope: &EncryptedEnvelope,
        local: LocalProposalTransportReview<'_>,
    ) -> Result<Mutation> {
        let keys = self.proposal_keys(access, &expected)?;
        let received = open_envelope(
            envelope,
            &keys.local_secret,
            &keys.pinned_peer,
            &expected,
            &trusted_now()?,
            &mut self.inbox,
        )
        .map_err(transport_error)?;
        self.engine
            .import_proposal_review_transport(access, &mut self.inbox, &received, local)
    }

    /// Reauthenticate the persisted original envelope. Engine idempotency and
    /// inbox completion are reconciled under the original stable import key;
    /// historical bytes cannot manufacture a fresh review or renewed validity.
    pub fn recover_proposal_review(
        &mut self,
        access: &Access,
        expected: MessageContext,
        sequence: u64,
        local: LocalProposalTransportReview<'_>,
    ) -> Result<Mutation> {
        let keys = self.proposal_keys(access, &expected)?;
        let retained = self
            .inbox
            .retained_for_context(&expected, sequence)
            .map_err(transport_error)?
            .ok_or_else(not_found)?;
        let recovered =
            recover_received(&retained, &keys.local_secret, &keys.pinned_peer, &expected)
                .map_err(transport_error)?;
        self.engine.import_proposal_review_transport(
            access,
            &mut self.inbox,
            recovered.artifact(),
            local,
        )
    }

    fn proposal_keys(
        &self,
        access: &Access,
        expected: &MessageContext,
    ) -> Result<ProtectedTransportKeys> {
        self.current_owner(access, &expected.agreement_id)?;
        if expected.artifact_kind != ArtifactKind::Proposal {
            return Err(ApiError::new(
                "INVALID_TERMS",
                "Economic review requires an exact proposal transport context",
            ));
        }
        self.keys.keys(&TransportKeyScope {
            principal_id: access.principal_id.clone(),
            context: expected.clone(),
            direction: TransportDirection::Incoming,
        })
    }
}
