//! Installed-signer-origin authorization exchange. The durable signer result is
//! acquired over authenticated native IPC; a serializable assertion cannot mint
//! this capability. Export is a separate disclosure decision, never new signing.
use sha2::{Digest, Sha256};
use wholepact_signer::authority_bridge::ipc::{
    HistoryRequest, OriginalHistoryClient, OriginalHistoryLease,
};
use wholepact_transport::*;

pub const AUTHORIZATION_FIELD: &str = "external_spend_signatures_v1";

/// Exact retained release and its held original-signer authority. No Clone,
/// Deserialize, Debug, public fields or constructor from application bytes.
pub struct PreparedAuthorizationExport<'a> {
    pub(crate) prepared: PreparedExport,
    pub(crate) original: OriginalHistoryLease<'a>,
    pub(crate) authorization_id: String,
    pub(crate) original_consent_ref: String,
    pub(crate) result_digest: String,
    pub(crate) outbox_digest: String,
}
impl PreparedAuthorizationExport<'_> {
    pub fn preview(&self) -> &DisclosurePreview {
        self.prepared.preview()
    }
    pub fn fields(&self) -> &[DisclosureField] {
        self.prepared.fields()
    }
    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }
    pub fn original_consent_ref(&self) -> &str {
        &self.original_consent_ref
    }
    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }
    pub fn outbox_digest(&self) -> &str {
        &self.outbox_digest
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.original
            .check_current()
            .map_err(|_| TransportError::AuthorityUnavailable)
    }
}

/// Retrieve only the immutable already-released signer payload. The request fixes
/// the original journal references; all message contexts are checked against that
/// authenticated original. The caller still needs separate exact disclosure
/// consent for the HPKE destination, purpose, selected field and retention warning.
pub fn prepare_authorization_export<'a>(
    client: &'a OriginalHistoryClient,
    history: &HistoryRequest,
    request: ExportRequest,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedAuthorizationExport<'a>> {
    prepare_authorization_export_inner(client, history, None, request, sender, recipient, now)
}

/// Same exact immutable signature payload after the original signer separately
/// approved redelivery to this current native process. The reference is a lookup,
/// never an authority token; live signer history and payload are reauthenticated.
#[allow(clippy::too_many_arguments)]
pub fn prepare_redelivered_authorization_export<'a>(
    client: &'a OriginalHistoryClient,
    history: &HistoryRequest,
    redelivery: &wholepact_signer::consent_journal::ResultRedeliveryReference,
    request: ExportRequest,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedAuthorizationExport<'a>> {
    prepare_authorization_export_inner(
        client,
        history,
        Some(redelivery),
        request,
        sender,
        recipient,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_authorization_export_inner<'a>(
    client: &'a OriginalHistoryClient,
    history: &HistoryRequest,
    redelivery: Option<&wholepact_signer::consent_journal::ResultRedeliveryReference>,
    request: ExportRequest,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedAuthorizationExport<'a>> {
    let original = match redelivery {
        Some(reference) => client.acquire_redelivered(history, reference),
        None => client.acquire(history),
    }
    .map_err(|_| TransportError::AuthorityUnavailable)?;
    let evidence = original.evidence();
    let result = evidence
        .retained_result
        .as_ref()
        .ok_or(TransportError::AuthorityUnavailable)?;
    let terms = evidence.consent.terms();
    let manifest = &evidence.accepted_manifest.proposal_input().manifest;
    if request.context.artifact_kind != ArtifactKind::Authorization
        || request.context.agreement_id != terms.agreement_id
        || request.context.proposal_id != terms.proposal_id
        || request.context.proposal_revision != u64::from(manifest.agreement.revision)
        || request.context.network_profile_id != manifest.agreement.network_profile_id
        || request.context.sender_id != evidence.enrollment.participant_id()
        || result.authorization_id != terms.authorization_id
        || result.original_consent_ref != evidence.consent.reference()
        || (&result.exact_local_recipient != evidence.transport() && result.redelivery.is_none())
        || evidence.release_intent.original_consent_ref() != evidence.consent.reference()
        || evidence.accepted_manifest.manifest_digest() != terms.manifest_digest
    {
        return Err(TransportError::WrongContext);
    }
    let bytes = match redelivery {
        Some(reference) => client.retrieve_redelivered_authorization(history, reference),
        None => client.retrieve_original_authorization(history),
    }
    .map_err(|_| TransportError::AuthorityUnavailable)?;
    if hex::encode(Sha256::digest(bytes.as_slice())) != result.outbox_digest {
        return Err(TransportError::Authentication);
    }
    original
        .check_current()
        .map_err(|_| TransportError::AuthorityUnavailable)?;
    let authorization_id = result.authorization_id.clone();
    let original_consent_ref = result.original_consent_ref.clone();
    let result_digest = result.result_digest.clone();
    let outbox_digest = result.outbox_digest.clone();
    let prepared = prepare_export(
        request,
        vec![DisclosureField::new(AUTHORIZATION_FIELD, bytes.to_vec())?],
        sender,
        recipient,
        now,
    )?;
    Ok(PreparedAuthorizationExport {
        prepared,
        original,
        authorization_id,
        original_consent_ref,
        result_digest,
        outbox_digest,
    })
}

/// Committed immutable ciphertext with original signer permission still held.
/// Keep this guard alive through the actual file/adapter handoff. A failed check
/// never changes the stored original or permits a replacement signature.
/// This guard holds signer permission. The native owner must separately retain
/// its profile lock and call AuthorizationOutbox::check_binding with both actual
/// mailbox owners immediately before and after its delivery callback.
pub struct AuthorizationOutboxArtifact<'a> {
    pub(crate) artifact: OutboxArtifact,
    pub(crate) original: OriginalHistoryLease<'a>,
}
impl AuthorizationOutboxArtifact<'_> {
    pub fn artifact(&self) -> Result<&OutboxArtifact> {
        self.check_current()?;
        Ok(&self.artifact)
    }
    pub fn check_current(&self) -> Result<()> {
        self.original
            .check_current()
            .map_err(|_| TransportError::AuthorityUnavailable)
    }
}

/// Reconstruct the exact original preview for ciphertext-only retry, including
/// after transport expiry. The caller supplies the retained original order, not
/// a new message ID or sequence. `recover_authorization` demands an exact durable
/// preview match. This does not extend import validity or create a new release.
pub fn prepare_authorization_retry<'a>(
    client: &'a OriginalHistoryClient,
    history: &HistoryRequest,
    original_request: ExportRequest,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
) -> Result<PreparedAuthorizationExport<'a>> {
    let original_time = original_request.order.issued_at.clone();
    prepare_authorization_export(
        client,
        history,
        original_request,
        sender,
        recipient,
        &original_time,
    )
}
