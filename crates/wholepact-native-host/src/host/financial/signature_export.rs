//! Exact existing signer result to protected immutable authorization transport.
use super::*;
use wholepact_service::protected_transport::{LocalTransportKeyController, TransportKeyScope};
use wholepact_signer::{
    authority_bridge::{
        ipc::{HistoryRequest, OriginalHistoryClient},
        provider::InstalledSignerProvider,
    },
    consent_journal::ResultRedeliveryRequest,
    ipc::PairScope,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureExportInput {
    signer_socket: PathBuf,
    history: HistoryRequest,
    redelivery_operation_id: String,
    context: MessageContext,
    order: MessageOrder,
    purpose: String,
    persistence_warning: String,
    destination: PathBuf,
    retry_only: bool,
}
impl Host {
    pub(in crate::host) fn financial_signature_export(&self) -> Result<()> {
        self.financial_permission(Permission::Disclose)?;
        let access = self.access()?;
        let input: SignatureExportInput =
            self.read_json("Exact original signature export configuration (no signature bytes): ")?;
        self.directory.external_destination(&input.destination)?;
        let (_, candidate) = self.engine.candidate(access, &input.context.proposal_id)?;
        let participant = candidate
            .proposal
            .manifest
            .participants
            .iter()
            .find(|p| p.participant_id == input.context.sender_id)
            .ok_or(Error::Invalid)?;
        if input.context.artifact_kind != wholepact_transport::ArtifactKind::Authorization
            || input.context.agreement_id != candidate.proposal.manifest.agreement.agreement_id
            || !input.signer_socket.is_absolute()
        {
            return Err(Error::Invalid);
        }
        self.terminal.confirm(&format!("Request the original retained authorization {} from installed signer {} and prepare exact encrypted transport to {}. The signer separately approves redelivery to this local process; the native host separately approves the pinned encrypted recipient. No new signatures or transaction submission will occur. Destination: {}", input.history.authorization_id, input.signer_socket.display(), input.context.recipient_id, input.destination.display()))?;
        let client = OriginalHistoryClient::pair(
            InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
            &input.signer_socket,
            "wholepact-native-signature-export",
            PairScope {
                account_id: participant.account_id.clone(),
                agreement_id: input.context.agreement_id.clone(),
                participant_id: participant.participant_id.clone(),
                manifest_digest: candidate.manifest_digest,
                history_read: true,
                authorization_export: true,
                preconstruction_export: false,
            },
        )
        .map_err(|_| Error::Permission)?;
        let history = &input.history;
        let redelivery = client
            .request_result_redelivery(&ResultRedeliveryRequest {
                operation_id: input.redelivery_operation_id,
                authorization_id: history.authorization_id.clone(),
                expected_original_consent_ref: history.expected_original_consent_ref.clone(),
                expected_enrollment_ref: history.expected_enrollment_ref.clone(),
                expected_manifest_ref: history.expected_manifest_ref.clone(),
            })
            .map_err(|_| Error::Permission)?;
        self.terminal.json(&redelivery)?;
        let keys = self.authority.keys(&TransportKeyScope {
            principal_id: access.principal_id.clone(),
            context: input.context.clone(),
            direction: TransportDirection::Outgoing,
        })?;
        let now = if input.retry_only {
            input.order.issued_at.clone()
        } else {
            Timestamp::from_unix_seconds(i64::try_from(now()?).map_err(|_| Error::Invalid)?)?
        };
        let released = wholepact_signer_release::prepare_redelivered_authorization_export(
            &client,
            history,
            &redelivery,
            ExportRequest {
                context: input.context,
                order: input.order,
                purpose: input.purpose,
                persistence_warning: input.persistence_warning,
            },
            &keys.local_secret.public_key()?,
            &keys.pinned_peer,
            &now,
        )?;
        self.transport.lock().map_err(|_| Error::Storage)?.deliver_released_authorization(access, released, input.retry_only, |envelope| {
            use sha2::Digest;
            self.terminal.confirm(&format!("Write this exact immutable encrypted authorization to NEW private file {}. Ciphertext SHA256: {}. Delivery to a remote party is not established; preserve this file and original outbox state for retries.", input.destination.display(), hex::encode(sha2::Sha256::digest(envelope.as_bytes())))).map_err(|_| wholepact_engine::ApiError::new("NATIVE_EXPORT_DENIED", "The exact local export was not approved; retained ciphertext is preserved"))?;
            files::write_new(&input.destination, envelope.as_bytes()).map_err(|_| wholepact_engine::ApiError::new("NATIVE_EXPORT_WRITE_FAILED", "Preserve any partial output and the exact retained encrypted outbox; no new signature was created"))
        })?;
        self.terminal.message("Exact encrypted authorization file written under held signer and disclosure permission. No new signature or network delivery was performed.\n")
    }
}
