//! Native selected-receipt commands. This module borrows the foreground Host
//! exclusively while the engine holds both record and separate disclosure leases.
//! No HTTP router or background worker can run while these methods are entered:
//! Host::serve owns/drops its entire Tokio runtime before returning to the shell.
use super::*;
use crate::authority::Held;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use wholepact_core::records::ObservationWindow;
use wholepact_engine::participant_records::{
    ParticipantRecordAction, ParticipantRecordRuntime, PreviewParticipantDisclosureRequest,
    RecordStoreBinding, disclosure_exports::*,
};
use wholepact_storage_security::receipt_file::PrivateReceiptTarget;
use wholepact_store::{CommandContext, Store};

fn runtime_window() -> Result<ObservationWindow> {
    let current = now()?;
    Ok(ObservationWindow {
        now: Timestamp::from_unix_seconds(current as i64)?
            .as_str()
            .into(),
        oldest_acceptable: Timestamp::from_unix_seconds(current.saturating_sub(60) as i64)?
            .as_str()
            .into(),
    })
}
fn receipt_error(e: wholepact_engine::ApiError) -> Error {
    Error::Receipt(e.code)
}
fn runtime<'a>(
    profile: &'a str,
    authority: &'a Authority,
    window: &'a ObservationWindow,
) -> ParticipantRecordRuntime<'a> {
    ParticipantRecordRuntime {
        profile_id: profile,
        authority,
        window,
    }
}

/// The lifetime is tied to an actual exclusive borrow of the only host owning
/// mutable records. It is not a caller-supplied quiet/approved Boolean. The engine
/// clones used below cannot escape this synchronous command, and there are no
/// independently running record observers or external record connections.
struct ReceiptAuthority<'a> {
    // Retain the constructor's exclusive borrow for 'a without claiming that
    // the host's unopened/unrelated wallet connections are shared by this issuer.
    // Only the concrete thread-safe fields below are reachable through it.
    _exclusive_host: PhantomData<&'a mut ()>,
    native: &'a Authority,
    terminal: &'a Terminal,
    profile: String,
    principal: String,
    store: RecordStoreBinding,
    agreement: String,
    record: String,
    export: String,
    target: &'a PrivateReceiptTarget,
    journal: Store,
}
impl<'a> ReceiptAuthority<'a> {
    fn new(
        host: &'a mut Host,
        target: &'a PrivateReceiptTarget,
        agreement: &str,
        record: &str,
        export: &str,
    ) -> Result<Self> {
        host.directory.check()?;
        let principal = host.access()?.principal_id.clone();
        Ok(Self {
            _exclusive_host: PhantomData,
            native: host.authority.as_ref(),
            terminal: &host.terminal,
            profile: host.secrets.profile(),
            principal,
            store: host.engine.protected_record_store_binding()?,
            agreement: agreement.into(),
            record: record.into(),
            export: export.into(),
            target,
            journal: Store::from_encrypted_connection(
                wholepact_storage_security::open_encrypted_quiescent(
                    host.directory.path(JOURNALS[0])?,
                    &host.secrets.key(0)?,
                )?,
            )?,
        })
    }
}
struct ReceiptLease<'a> {
    scope: DisclosureExportScope,
    reference: String,
    expires: String,
    held: Held,
    target: &'a PrivateReceiptTarget,
}
impl DisclosureExportLease for ReceiptLease<'_> {
    fn scope(&self) -> &DisclosureExportScope {
        &self.scope
    }
    fn consent_record_ref(&self) -> &str {
        &self.reference
    }
    fn expires_at(&self) -> &str {
        &self.expires
    }
    fn check_current(&self) -> wholepact_engine::Result<()> {
        self.held.check().map_err(|_| denied())?;
        self.target.check_current().map_err(|_| denied())
    }
}
fn denied() -> wholepact_engine::ApiError {
    wholepact_engine::ApiError::new(
        "DISCLOSURE_CONSENT_DENIED",
        "Current exact native record, selected payload, local target and separate export approval are required",
    )
}
impl DisclosureExportAuthority for ReceiptAuthority<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &DisclosureExportScope,
        _: &ObservationWindow,
    ) -> wholepact_engine::Result<Box<dyn DisclosureExportLease + 'a>> {
        if scope.record.store != self.store
            || scope.record.profile_id != self.profile
            || scope.record.principal_id != self.principal
            || scope.record.agreement_id != self.agreement
            || scope.record.record_id != self.record
            || scope.record.action != ParticipantRecordAction::ExportReceipt
            || scope.export_id != self.export
            || scope.target != *self.target.identity()
            || scope.target_binding != self.target.binding()
        {
            return Err(denied());
        }
        self.target.check_current().map_err(|_| denied())?;
        let expires = now().map_err(|_| denied())?.saturating_add(120);
        let held = self.native.fence.acquire(expires).map_err(|_| denied())?;
        // The separate immutable consent is persisted in a private aggregate in
        // the SAME encrypted coordination journal before engine staging. Bundle
        // backups include it. It is historical evidence, never an active grant.
        let identity = serde_json::json!({
            "profile":scope.record.profile_id,"principal":scope.record.principal_id,
            "agreement":scope.record.agreement_id,"record":scope.record.record_id,
            "participant":scope.record.participant_id,"account":scope.record.account_id,
            "export":scope.export_id,"preview":scope.preview_id,
            "record_digest":scope.source_record_digest,"preview_digest":scope.preview.digest(),
            "payload_digest":scope.payload_digest,"payload_length":scope.payload_length,
            "target":scope.target,
        });
        let mut hash = Sha256::new();
        hash.update(b"wholepact:native-selected-receipt-consent-id:v1\0");
        let name = serde_json::json!({"profile":self.profile,"principal":self.principal,"agreement":self.agreement,"record":self.record,"export":self.export});
        hash.update(serde_json::to_vec(&name).map_err(|_| denied())?);
        let consent_id = format!("receipt-{}", hex::encode(hash.finalize()));
        let existing = self
            .journal
            .get_record(CONSENT_AGGREGATE, &consent_id)
            .map_err(|_| denied())?;
        let original = existing
            .as_ref()
            .map(|stored| {
                if stored.revision != 1 {
                    return Err(denied());
                }
                let value: StoredNativeConsent =
                    serde_json::from_value(stored.payload.clone()).map_err(|_| denied())?;
                if value.version != 1
                    || value.identity != identity
                    || crate::id(&value.reference).is_err()
                {
                    return Err(denied());
                }
                Ok(value)
            })
            .transpose()?;
        if scope.phase == ReceiptExportPhase::WriteExactLocalFile && original.is_none() {
            return Err(denied());
        }
        if original.is_none()
            && self
                .journal
                .list_records(CONSENT_AGGREGATE)
                .map_err(|_| denied())?
                .len()
                >= 512
        {
            return Err(denied());
        }
        let reference = match &original {
            Some(record) => record.reference.clone(),
            None => format!(
                "native-receipt-{}",
                hex::encode(crate::random::<16>().map_err(|_| denied())?)
            ),
        };
        let selected = Zeroizing::new(
            serde_json::to_string_pretty(scope.preview.receipt()).map_err(|_| denied())?,
        );
        let detail = Zeroizing::new(format!(
            "SEPARATE SELECTIVE RECEIPT CONSENT\nPhase: {:?}\nProfile: {}\nPrincipal: {}\nAgreement: {}\nExisting record: {}\nRetained participant/account: {} / {}\nExport: {}\nOriginal preview: {}\nSource digest: {}\nPayload digest: {}\nPayload bytes: {}\nExact local PLAINTEXT destination: {}\nConsent reference: {}\nCurrent consent expires Unix: {}\nAll and only these selected receipt fields will be written:\n{}\nThis is an unverified private statement, not payment proof, current wallet control or external delivery. Read/payment consent does not approve this export. The selected file is deliberately plaintext with private permissions. Other copies cannot be recalled. Existing different/partial output will be preserved, and historical completion never recreates a deleted file.",
            scope.phase,
            self.profile,
            self.principal,
            self.agreement,
            self.record,
            scope.record.participant_id,
            scope.record.account_id,
            self.export,
            scope.preview_id,
            scope.source_record_digest,
            scope.payload_digest,
            scope.payload_length,
            self.target.identity().path(),
            reference,
            expires,
            selected.as_str()
        ));
        self.terminal.confirm(&detail).map_err(|_| denied())?;
        held.check().map_err(|_| denied())?;
        self.target.check_current().map_err(|_| denied())?;
        if original.is_none() {
            let entry = StoredNativeConsent {
                version: 1,
                identity,
                reference: reference.clone(),
                approved_at: Timestamp::from_unix_seconds(now().map_err(|_| denied())? as i64)
                    .map_err(|_| denied())?
                    .as_str()
                    .into(),
            };
            let value = serde_json::to_value(&entry).map_err(|_| denied())?;
            let context = CommandContext::for_request(
                &self.principal,
                format!("native-consent-{}", &consent_id[8..]),
                &value,
            )
            .map_err(|_| denied())?;
            self.journal
                .commit_record(
                    &context,
                    CONSENT_AGGREGATE,
                    &consent_id,
                    None,
                    value,
                    "native_receipt_consent_recorded",
                )
                .map_err(|_| denied())?;
            held.check().map_err(|_| denied())?;
            let saved = self
                .journal
                .get_record(CONSENT_AGGREGATE, &consent_id)
                .map_err(|_| denied())?
                .ok_or_else(denied)?;
            let saved: StoredNativeConsent =
                serde_json::from_value(saved.payload).map_err(|_| denied())?;
            if saved != entry {
                return Err(denied());
            }
        }
        Ok(Box::new(ReceiptLease {
            scope: scope.clone(),
            reference,
            expires: Timestamp::from_unix_seconds(expires as i64)
                .map_err(|_| denied())?
                .as_str()
                .into(),
            held,
            target: self.target,
        }))
    }
}

const CONSENT_AGGREGATE: &str = "native_receipt_consent";
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredNativeConsent {
    version: u16,
    identity: serde_json::Value,
    reference: String,
    approved_at: String,
}

impl Host {
    pub(super) fn receipt_preview(&mut self) -> Result<()> {
        let agreement = self.terminal.ask("Agreement ID: ")?.to_string();
        let revision = parse_number(&self.terminal.ask("Current agreement revision: ")?)?;
        let key = self
            .terminal
            .ask("Original preview command idempotency key (retain for retry): ")?
            .to_string();
        let request: PreviewParticipantDisclosureRequest =
            self.read_json("Selected receipt preview request JSON file: ")?;
        let details = Zeroizing::new(serde_json::to_string_pretty(&request)?);
        self.terminal.confirm(&format!("Prepare a private selected-field preview from an EXISTING retained record. This does not approve file export.\nAgreement: {agreement}\nRevision: {revision}\n{}",details.as_str()))?;
        let profile = self.secrets.profile();
        let window = runtime_window()?;
        let result = self
            .engine
            .preview_participant_disclosure(
                self.access()?,
                &key,
                &agreement,
                revision,
                request,
                runtime(&profile, self.authority.as_ref(), &window),
            )
            .map_err(receipt_error)?;
        self.terminal.json(&result)
    }
    pub(super) fn receipt_preview_read(&mut self) -> Result<()> {
        let agreement = self.terminal.ask("Agreement ID: ")?;
        let record = self.terminal.ask("Existing record ID: ")?;
        let preview = self.terminal.ask("Original preview ID: ")?;
        let profile = self.secrets.profile();
        let window = runtime_window()?;
        let result = self
            .engine
            .read_participant_disclosure_preview(
                self.access()?,
                &agreement,
                &record,
                &preview,
                runtime(&profile, self.authority.as_ref(), &window),
            )
            .map_err(receipt_error)?;
        self.terminal.json(&result)
    }
    pub(super) fn receipt_stage(&mut self) -> Result<()> {
        let agreement = self.terminal.ask("Agreement ID: ")?.to_string();
        let revision = parse_number(&self.terminal.ask("Original stage agreement revision: ")?)?;
        let key = self
            .terminal
            .ask("Original stage command idempotency key (retain for retry): ")?
            .to_string();
        let request: StageParticipantReceiptExport =
            self.read_json("Exact staged receipt export request JSON file: ")?;
        let destination = self.path("Exact private PLAINTEXT receipt destination: ")?;
        self.directory
            .external_destination(&destination)
            .map_err(|_| Error::Receipt("DISCLOSURE_TARGET_PROTECTED_PROFILE_OR_UNSAFE".into()))?;
        let target = PrivateReceiptTarget::open(destination)
            .map_err(|_| Error::Receipt("DISCLOSURE_TARGET_UNSAFE".into()))?;
        let engine = self.engine.clone();
        let access = self.access()?.clone();
        let native = self.authority.clone();
        let profile = self.secrets.profile();
        let window = runtime_window()?;
        let consent = ReceiptAuthority::new(
            self,
            &target,
            &agreement,
            &request.record_id,
            &request.export_id,
        )?;
        let result = engine
            .stage_participant_receipt_export(
                &access,
                &key,
                &agreement,
                revision,
                request,
                runtime(&profile, native.as_ref(), &window),
                &target,
                &consent,
            )
            .map_err(receipt_error)?;
        consent.terminal.json(&result)
    }
    pub(super) fn receipt_write(&mut self) -> Result<()> {
        let agreement = self.terminal.ask("Agreement ID: ")?.to_string();
        let key = self
            .terminal
            .ask("Original write attempt idempotency key (reuse for retry): ")?
            .to_string();
        let request: WriteParticipantReceiptExport =
            self.read_json("Exact retained receipt write request JSON file: ")?;
        let destination = self.path("Original exact private PLAINTEXT receipt destination: ")?;
        self.directory
            .external_destination(&destination)
            .map_err(|_| Error::Receipt("DISCLOSURE_TARGET_PROTECTED_PROFILE_OR_UNSAFE".into()))?;
        let target = PrivateReceiptTarget::open(destination)
            .map_err(|_| Error::Receipt("DISCLOSURE_TARGET_UNSAFE".into()))?;
        let engine = self.engine.clone();
        let access = self.access()?.clone();
        let native = self.authority.clone();
        let profile = self.secrets.profile();
        let window = runtime_window()?;
        let consent = ReceiptAuthority::new(
            self,
            &target,
            &agreement,
            &request.record_id,
            &request.export_id,
        )?;
        let result = engine
            .write_participant_receipt_export(
                &access,
                &key,
                &agreement,
                request,
                runtime(&profile, native.as_ref(), &window),
                &target,
                &consent,
            )
            .map_err(receipt_error)?;
        consent.terminal.json(&result)
    }
    pub(super) fn receipt_status(&mut self) -> Result<()> {
        let agreement = self.terminal.ask("Agreement ID: ")?;
        let record = self.terminal.ask("Existing record ID: ")?;
        let export = self.terminal.ask("Original export ID: ")?;
        let profile = self.secrets.profile();
        let window = runtime_window()?;
        let result = self
            .engine
            .participant_receipt_export_status(
                self.access()?,
                &agreement,
                &record,
                &export,
                runtime(&profile, self.authority.as_ref(), &window),
            )
            .map_err(receipt_error)?;
        self.terminal.json(&result)
    }
}
