//! Native-only exact release export. No HTTP request supplies signer history,
//! artifact bytes, keys, consent flags or a delivery path.
use super::*;
use wholepact_signer_release::PreparedAuthorizationExport;

impl ProtectedTransportRuntime {
    /// Commit or retry original immutable ciphertext, then execute the native
    /// delivery callback while BOTH signer-origin and exact disclosure leases are
    /// held. The callback chooses no destination on the browser's behalf.
    pub fn deliver_released_authorization<R>(
        &mut self,
        access: &Access,
        released: PreparedAuthorizationExport<'_>,
        retry_only: bool,
        deliver: impl FnOnce(&EncryptedEnvelope) -> Result<R>,
    ) -> Result<R> {
        let preview = released.preview().clone();
        self.current_owner(access, &preview.context.agreement_id)?;
        let keys = self.keys.keys(&TransportKeyScope {
            principal_id: access.principal_id.clone(),
            context: preview.context.clone(),
            direction: TransportDirection::Outgoing,
        })?;
        if keys
            .local_secret
            .public_key()
            .map_err(transport_error)?
            .fingerprint()
            != preview.sender_key_fingerprint
            || keys.pinned_peer.fingerprint() != preview.recipient_key_fingerprint
        {
            return Err(denied());
        }
        let scope = LocalTransportScope {
            principal_id: access.principal_id.clone(),
            agreement_id: preview.context.agreement_id.clone(),
            context: preview.context.clone(),
            artifact_fingerprint: preview.digest().map_err(transport_error)?,
        };
        let action = if retry_only {
            LocalTransportAction::RetrieveEncryptedExport
        } else {
            LocalTransportAction::SealExport
        };
        let authority = self.consent.clone();
        let lease = authority.acquire(&scope, action, &preview, released.fields())?;
        if lease.scope() != &scope || lease.action() != action {
            return Err(denied());
        }
        check_lease(lease.as_ref())?;
        let authorization_outbox = self.authorization_outbox.as_mut().ok_or_else(|| {
            ApiError::new(
                "SIGNER_RELEASE_UNAVAILABLE",
                "No same-database signer-release adapter is configured",
            )
        })?;
        let guard = if retry_only {
            authorization_outbox.recover_authorization(
                &self.outbox,
                released,
                &keys.pinned_peer,
                &scope.artifact_fingerprint,
            )
        } else {
            authorization_outbox.enqueue_authorization(
                &self.outbox,
                released,
                &keys.local_secret,
                &keys.pinned_peer,
                &scope.artifact_fingerprint,
                &trusted_now()?,
            )
        }
        .map_err(transport_error)?;
        self.current_owner(access, &preview.context.agreement_id)?;
        check_lease(lease.as_ref())?;
        // The profile owner lock is held for both connections' lifetime. Still
        // revalidate the exact actual handles at the handoff boundary, alongside
        // original-signer and current native disclosure permission.
        self.authorization_outbox
            .as_ref()
            .ok_or_else(denied)?
            .check_binding(&self.outbox)
            .map_err(transport_error)?;
        let result = deliver(guard.artifact().map_err(transport_error)?.envelope())?;
        self.authorization_outbox
            .as_ref()
            .ok_or_else(denied)?
            .check_binding(&self.outbox)
            .map_err(transport_error)?;
        guard.check_current().map_err(transport_error)?;
        check_lease(lease.as_ref())?;
        Ok(result)
    }
}
