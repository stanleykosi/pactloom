//! Native participant-scoped file delivery. Ciphertext retention is not payment
//! evidence; domain import cannot mint signer consent or account history.
use super::*;
use wholepact_transport::{DisclosureField, ExportRequest, open_envelope_checked, prepare_export};

pub enum PortableSource<'a> {
    Incoming(&'a EncryptedEnvelope),
    Retained(u64),
}
fn eligible(context: &MessageContext, fields: &[DisclosureField]) -> Result<()> {
    let expected = match context.artifact_kind {
        ArtifactKind::FinalTransaction => "finalized_transaction_v1",
        ArtifactKind::SettlementEvidence => "selected_private_receipt_v1",
        _ => return Err(denied()),
    };
    if fields.len() != 1 || fields[0].name() != expected || fields[0].bytes().is_empty() {
        return Err(denied());
    }
    Ok(())
}
impl ProtectedTransportRuntime {
    /// Exact retries recover original ciphertext and cannot silently renew expiry.
    /// The callback must invoke its current guard after prompts, before file I/O.
    /// Original-source permission is also rechecked before ciphertext retention.
    pub fn deliver_portable<R>(
        &mut self,
        access: &Access,
        request: ExportRequest,
        field: DisclosureField,
        retry_only: bool,
        source_current: &dyn Fn() -> Result<()>,
        deliver: impl FnOnce(&EncryptedEnvelope, &dyn Fn() -> Result<()>) -> Result<R>,
    ) -> Result<R> {
        self.current_owner(access, &request.context.agreement_id)?;
        eligible(&request.context, std::slice::from_ref(&field))?;
        let keys = self.keys.keys(&TransportKeyScope {
            principal_id: access.principal_id.clone(),
            context: request.context.clone(),
            direction: TransportDirection::Outgoing,
        })?;
        let clock = if retry_only {
            request.order.issued_at.clone()
        } else {
            trusted_now()?
        };
        let prepared = prepare_export(
            request,
            vec![field],
            &keys.local_secret.public_key().map_err(transport_error)?,
            &keys.pinned_peer,
            &clock,
        )
        .map_err(transport_error)?;
        let binding = binding(
            access,
            prepared.preview(),
            TransportDirection::Outgoing,
            retry_only,
            &trusted_now()?,
        )?;
        let authority = self.consent.clone();
        let action = if retry_only {
            LocalTransportAction::RetrieveEncryptedExport
        } else {
            LocalTransportAction::SealExport
        };
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            &binding,
            action,
            prepared.fields(),
        )?;
        source_current()?;
        let prior = self
            .outbox
            .recover_for_recipient(
                &binding.context,
                &keys.pinned_peer,
                binding.preview.order.sequence,
            )
            .map_err(transport_error)?;
        let record = match prior {
            Some(record) => {
                if record.preview_digest() != binding.artifact_fingerprint {
                    return Err(denied());
                }
                record
            }
            None if retry_only => return Err(not_found()),
            None => self
                .outbox
                .enqueue(
                    prepared,
                    &keys.local_secret,
                    &binding.artifact_fingerprint,
                    &clock,
                )
                .map_err(transport_error)?,
        };
        self.current_keys(access, &binding)?;
        check_lease(lease.as_ref())?;
        let current = || {
            source_current()?;
            check_lease(lease.as_ref())?;
            self.current_keys(access, &binding)?;
            Ok(())
        };
        let result = deliver(record.envelope(), &current)?;
        check_lease(lease.as_ref())?;
        Ok(result)
    }

    /// Validate domain bytes before inbox mutation. A denied native decision never
    /// writes plaintext. Restart explicitly reopens retained ciphertext with fresh
    /// permission, even after expiry; it never makes that history current authority.
    pub fn import_portable<R>(
        &mut self,
        access: &Access,
        context: MessageContext,
        source: PortableSource<'_>,
        validate: impl Fn(&[u8]) -> Result<()>,
        import: impl FnOnce(&[u8], &str, &dyn Fn() -> Result<()>) -> Result<R>,
    ) -> Result<R> {
        self.current_owner(access, &context.agreement_id)?;
        let keys = self.keys.keys(&TransportKeyScope {
            principal_id: access.principal_id.clone(),
            context: context.clone(),
            direction: TransportDirection::Incoming,
        })?;
        let check = |artifact: &wholepact_transport::ReceivedArtifact| {
            eligible(&context, artifact.fields()).map_err(|_| TransportError::Malformed)?;
            validate(artifact.fields()[0].bytes()).map_err(|_| TransportError::Malformed)
        };
        let (artifact, historical) = match source {
            PortableSource::Incoming(envelope) => (
                open_envelope_checked(
                    envelope,
                    &keys.local_secret,
                    &keys.pinned_peer,
                    &context,
                    &trusted_now()?,
                    &mut self.inbox,
                    check,
                )
                .map_err(transport_error)?,
                false,
            ),
            PortableSource::Retained(sequence) => {
                let record = self
                    .inbox
                    .retained_for_context(&context, sequence)
                    .map_err(transport_error)?
                    .ok_or_else(not_found)?;
                let recovered =
                    recover_received(&record, &keys.local_secret, &keys.pinned_peer, &context)
                        .map_err(transport_error)?;
                check(recovered.artifact()).map_err(transport_error)?;
                (recovered.into_artifact(), true)
            }
        };
        let binding = binding(
            access,
            artifact.preview(),
            TransportDirection::Incoming,
            historical,
            &trusted_now()?,
        )?;
        let authority = self.consent.clone();
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            &binding,
            LocalTransportAction::ReadRetained,
            artifact.fields(),
        )?;
        let ticket = self
            .inbox
            .domain_import_ticket(&artifact, "native-portable-read-v1")
            .map_err(transport_error)?;
        self.current_keys(access, &binding)?;
        check_lease(lease.as_ref())?;
        let current = || {
            check_lease(lease.as_ref())?;
            self.current_keys(access, &binding)?;
            Ok(())
        };
        let result = import(
            artifact.fields()[0].bytes(),
            ticket.idempotency_key(),
            &current,
        )?;
        check_lease(lease.as_ref())?;
        // This records local authenticated read only. File effects are explicitly
        // repeatable under fresh native approval and cannot overwrite existing data.
        self.inbox
            .complete_domain_import(
                &ticket,
                DomainImportResult {
                    outcome: DomainOutcome::Applied,
                    result_digest: artifact.content_digest().into(),
                },
            )
            .map_err(transport_error)?;
        Ok(result)
    }
}
