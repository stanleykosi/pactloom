//! Native-only exact authorization artifact lending. The callback runs under all
//! current key/disclosure leases. No HTTP route, raw plaintext getter or account
//! association issuer is introduced; the engine still requires real signer IPC.
use super::*;
use wholepact_transport::ReceivedArtifact;

pub enum AuthorizationArtifactSource<'a> {
    Incoming {
        context: MessageContext,
        envelope: &'a EncryptedEnvelope,
    },
    Retained {
        context: MessageContext,
        sequence: u64,
    },
}
enum OpenedAuthorization {
    Incoming(ReceivedArtifact),
    Retained(RecoveredArtifact),
}
impl OpenedAuthorization {
    fn artifact(&self) -> &ReceivedArtifact {
        match self {
            Self::Incoming(a) => a,
            Self::Retained(a) => a.artifact(),
        }
    }
}
impl ProtectedTransportRuntime {
    pub fn with_authorization_artifacts<R>(
        &mut self,
        access: &Access,
        sources: &[AuthorizationArtifactSource<'_>],
        operation: impl FnOnce(&[&ReceivedArtifact]) -> Result<R>,
    ) -> Result<R> {
        self.with_authorization_artifacts_and_transport(access, sources, |artifacts, _, _| operation(artifacts))
    }
    /// Lend the runtime while the original incoming privacy leases remain held.
    /// The final effect must recheck the supplied guard after any interactive wait.
    pub fn with_authorization_artifacts_and_transport<R>(
        &mut self, access: &Access, sources: &[AuthorizationArtifactSource<'_>],
        operation: impl FnOnce(&[&ReceivedArtifact], &mut Self, &dyn Fn() -> Result<()>) -> Result<R>,
    ) -> Result<R> {
        if sources.is_empty() || sources.len() > 32 {
            return Err(denied());
        }
        let mut artifacts = Vec::new();
        let mut bindings = Vec::new();
        for source in sources {
            let context = match source {
                AuthorizationArtifactSource::Incoming { context, .. }
                | AuthorizationArtifactSource::Retained { context, .. } => context,
            };
            if context.artifact_kind != ArtifactKind::Authorization {
                return Err(denied());
            }
            self.current_owner(access, &context.agreement_id)?;
            let keys = self.keys.keys(&TransportKeyScope {
                principal_id: access.principal_id.clone(),
                context: context.clone(),
                direction: TransportDirection::Incoming,
            })?;
            let opened = match source {
                AuthorizationArtifactSource::Incoming { envelope, .. } => {
                    OpenedAuthorization::Incoming(
                        open_envelope(
                            envelope,
                            &keys.local_secret,
                            &keys.pinned_peer,
                            context,
                            &trusted_now()?,
                            &mut self.inbox,
                        )
                        .map_err(transport_error)?,
                    )
                }
                AuthorizationArtifactSource::Retained { sequence, .. } => {
                    let retained = self
                        .inbox
                        .retained_for_context(context, *sequence)
                        .map_err(transport_error)?
                        .ok_or_else(not_found)?;
                    OpenedAuthorization::Retained(
                        recover_received(&retained, &keys.local_secret, &keys.pinned_peer, context)
                            .map_err(transport_error)?,
                    )
                }
            };
            let artifact = opened.artifact();
            // Only the bounded existing signatures schema is eligible. Parsing,
            // original account attribution and cryptography remain engine gates.
            if artifact.fields().len() != 1
                || artifact.fields()[0].name() != "external_spend_signatures_v1"
                || artifact.fields()[0].bytes().len() > 16_384
            {
                return Err(denied());
            }
            bindings.push(binding(
                access,
                artifact.preview(),
                TransportDirection::Incoming,
                matches!(source, AuthorizationArtifactSource::Retained { .. }),
                &trusted_now()?,
            )?);
            artifacts.push(opened);
        }
        let authority = self.consent.clone();
        let mut leases = Vec::new();
        for (binding, artifact) in bindings.iter().zip(&artifacts) {
            leases.push(self.acquire_consent(
                authority.as_ref(),
                access,
                binding,
                LocalTransportAction::ReadAuthorization,
                artifact.artifact().fields(),
            )?);
        }
        for lease in &leases {
            check_lease(lease.as_ref())?;
        }
        let refs = artifacts
            .iter()
            .map(OpenedAuthorization::artifact)
            .collect::<Vec<_>>();
        let check = || { for lease in &leases { check_lease(lease.as_ref())?; } Ok(()) };
        let result = operation(&refs, self, &check)?;
        for (binding, lease) in bindings.iter().zip(&leases) {
            check_lease(lease.as_ref())?;
            self.current_keys(access, binding)?;
        }
        Ok(result)
    }
}
