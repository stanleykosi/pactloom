//! Foreground minimal participant file delivery and authenticated local import.
use super::*;
use wholepact_service::protected_transport::portable::PortableSource;
use wholepact_transport::{ArtifactKind, DisclosureField};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PortableExportInput {
    pub context: MessageContext,
    pub order: MessageOrder,
    pub purpose: String,
    pub persistence_warning: String,
    pub destination: PathBuf,
    pub retry_only: bool,
}
impl PortableExportInput {
    fn request(&self) -> ExportRequest {
        ExportRequest {
            context: self.context.clone(),
            order: self.order.clone(),
            purpose: self.purpose.clone(),
            persistence_warning: self.persistence_warning.clone(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableImportInput {
    context: MessageContext,
    envelope_path: Option<PathBuf>,
    retained_sequence: Option<u64>,
    destination: PathBuf,
    receipt_destination: Option<wholepact_core::disclosure::DisclosureDestination>,
}
impl Host {
    pub(super) fn deliver_participant_field(
        &self,
        input: &PortableExportInput,
        field: DisclosureField,
    ) -> Result<()> {
        let mut transport = self.transport.lock().map_err(|_| Error::Storage)?;
        self.deliver_participant_field_with_transport(input, field, &mut transport, &|| Ok(()))
    }
    pub(super) fn deliver_participant_field_with_transport(
        &self,
        input: &PortableExportInput,
        field: DisclosureField,
        transport: &mut wholepact_service::protected_transport::ProtectedTransportRuntime,
        source_current: &dyn Fn() -> std::result::Result<(), wholepact_engine::ApiError>,
    ) -> Result<()> {
        self.financial_permission(Permission::Disclose)?;
        self.directory.external_destination(&input.destination)?;
        source_current()?;
        transport.deliver_portable(self.access()?, input.request(), field, input.retry_only, source_current, |envelope, current| {
            use sha2::Digest;
            self.terminal.confirm(&format!("Write exact recipient-scoped encrypted portable artifact to NEW private file {}. Ciphertext SHA256: {}. This is local file preparation; remote delivery and payment are not established. Preserve retained outbox and identifiers for exact retry.", input.destination.display(), hex::encode(sha2::Sha256::digest(envelope.as_bytes())))).map_err(portable_error)?;
            source_current()?;
            current()?;
            files::write_new(&input.destination, envelope.as_bytes()).map_err(portable_error)
        })?;
        self.terminal.message("Exact encrypted participant file written. No external delivery, payment verification or submission occurred.\n")
    }
    pub(in crate::host) fn portable_receipt_export(&self) -> Result<()> {
        self.financial_permission(Permission::Disclose)?;
        let input: PortableExportInput =
            self.read_json("Selected private receipt encrypted delivery configuration JSON: ")?;
        if input.context.artifact_kind != ArtifactKind::SettlementEvidence {
            return Err(Error::Invalid);
        }
        let expected: wholepact_core::disclosure::DisclosureDestination =
            self.read_json("Exact selected receipt recipient/destination JSON: ")?;
        if expected.recipient_id != input.context.recipient_id {
            return Err(Error::Permission);
        }
        let source = self.path("Previously explicitly exported selected private receipt file: ")?;
        let bytes = zeroize::Zeroizing::new(files::read_artifact(&source, 32768)?);
        wholepact_core::disclosure::inspect_private_receipt(&bytes, &expected)
            .map_err(|_| Error::Invalid)?;
        self.deliver_participant_field(
            &input,
            DisclosureField::new("selected_private_receipt_v1", bytes.to_vec())?,
        )
    }
    pub(in crate::host) fn portable_import(&self) -> Result<()> {
        self.financial_permission(Permission::Read)?;
        self.financial_permission(Permission::Disclose)?;
        let input: PortableImportInput =
            self.read_json("Exact pinned participant portable import configuration JSON: ")?;
        self.directory.external_destination(&input.destination)?;
        let envelope = input
            .envelope_path
            .as_ref()
            .map(|path| {
                files::read_artifact(path, wholepact_transport::MAX_FILE_BYTES)
                    .and_then(|bytes| EncryptedEnvelope::from_bytes(bytes).map_err(Error::from))
            })
            .transpose()?;
        let source = match (&envelope, input.retained_sequence) {
            (Some(envelope), None) => PortableSource::Incoming(envelope),
            (None, Some(sequence)) => PortableSource::Retained(sequence),
            _ => return Err(Error::Invalid),
        };
        let kind = input.context.artifact_kind;
        let recipient = input.context.recipient_id.clone();
        self.transport.lock().map_err(|_| Error::Storage)?.import_portable(self.access()?, input.context, source,
            |bytes| {
                match kind {
                    ArtifactKind::FinalTransaction if input.receipt_destination.is_none() => wholepact_protocol::recipient_local::inspect_finalized_encoding(bytes).map_err(|_| portable_error(Error::Invalid)),
                    ArtifactKind::SettlementEvidence => {
                        let expected = input.receipt_destination.as_ref().ok_or_else(|| portable_error(Error::Invalid))?;
                        if expected.recipient_id != recipient { return Err(portable_error(Error::Permission)); }
                        wholepact_core::disclosure::inspect_private_receipt(bytes, expected).map(|_| ()).map_err(|_| portable_error(Error::Invalid))
                    }
                    _ => Err(portable_error(Error::Invalid)),
                }
            },
            |bytes, operation, current| {
                use sha2::Digest;
                self.terminal.confirm(&format!("Import authenticated sender's selected portable artifact as UNVERIFIED local data into NEW private file {}. SHA256: {}. Stable import reference: {}. This plaintext copy cannot establish payment, account control, signing consent, chain inclusion or complete history. Finalized transactions may be broadcast by anyone with the bytes. Verify payment separately with recipient-owned native instructions and viewing authority.", input.destination.display(), hex::encode(sha2::Sha256::digest(bytes)), operation)).map_err(portable_error)?;
                current()?;
                files::write_new(&input.destination, bytes).map_err(portable_error)
            })?;
        self.terminal.message("Authenticated portable data imported as unverified local data. For payment, use the signer companion's recipient verification on this exact transaction file. Receipt statements remain unverified.\n")
    }
}
fn portable_error(_: Error) -> wholepact_engine::ApiError {
    wholepact_engine::ApiError::new(
        "PORTABLE_DELIVERY_BLOCKED",
        "Portable operation stopped; preserve any partial file and original encrypted inbox/outbox. No payment or authority was inferred",
    )
}
