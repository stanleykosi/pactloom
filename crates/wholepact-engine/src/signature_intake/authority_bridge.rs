//! Concrete authenticated signer IPC adapters. The coordinator holds only a
//! request-only channel and read-only originals, never a signer vault/key or an
//! unlock/sign-anything API. Deserialized records and collected signatures cannot
//! manufacture original consent or current account association.
use super::record_source::{
    OriginalAuthorizationConsentLease, OriginalAuthorizationConsentScope,
    OriginalAuthorizationConsentSource,
};
use super::*;
use wholepact_signer::{
    authority_bridge::{
        ipc::{HistoryRequest, OriginalHistoryClient, OriginalHistoryLease},
        protocol::OriginalAuthorizationView,
    },
    consent_journal::TransportIdentityBinding,
};
use wholepact_store::{StorageProtection, Store};

/// A concrete source for the existing record-intake contract. Its only source is
/// exact original signer records read under authenticated current native IPC.
pub struct SignerOriginalConsentSource<'a> {
    client: &'a OriginalHistoryClient,
    request: HistoryRequest,
}
impl<'a> SignerOriginalConsentSource<'a> {
    pub fn new(client: &'a OriginalHistoryClient, request: HistoryRequest) -> Self {
        Self { client, request }
    }
}
struct HeldOriginalConsent<'a> {
    scope: OriginalAuthorizationConsentScope,
    expires_at: Timestamp,
    original: OriginalHistoryLease<'a>,
}
impl OriginalAuthorizationConsentLease for HeldOriginalConsent<'_> {
    fn scope(&self) -> &OriginalAuthorizationConsentScope {
        &self.scope
    }
    fn original_consent_record_ref(&self) -> &str {
        self.original.evidence().consent.reference()
    }
    fn expires_at(&self) -> &Timestamp {
        &self.expires_at
    }
    fn check_current(&self) -> Result<()> {
        self.original
            .check_current()
            .map_err(|_| original_unavailable())
    }
}
impl OriginalAuthorizationConsentSource for SignerOriginalConsentSource<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &OriginalAuthorizationConsentScope,
        release_journal: &Store,
        now: &Timestamp,
    ) -> Result<Box<dyn OriginalAuthorizationConsentLease + 'a>> {
        if self.request.authorization_id != scope.authorization_id
            || release_journal.protection() != StorageProtection::Encrypted
        {
            return Err(original_unavailable());
        }
        let original = self
            .client
            .acquire(&self.request)
            .map_err(|_| original_unavailable())?;
        let e = original.evidence();
        validate_original_scope(e, scope)?;
        let retained = release_journal
            .exposure(&scope.authorization_id)
            .map_err(crate::store_error)?
            .ok_or_else(original_unavailable)?;
        if !retained.release_intent_recorded || &retained.intent != e.release_intent.intent() {
            return Err(original_unavailable());
        }
        let digest = wholepact_store::request_digest(
            &serde_json::to_value(e.release_intent.intent()).map_err(|_| original_unavailable())?,
        )
        .map_err(crate::store_error)?;
        if digest != scope.release_intent_digest {
            return Err(original_unavailable());
        }
        original
            .check_current()
            .map_err(|_| original_unavailable())?;
        // This is a current read-window assessment, never an invented original
        // approval timestamp. The live server lease is checked on every use and
        // stays held through the record source's final encrypted CAS and replay.
        let expires_at = Timestamp::from_unix_seconds(
            now.unix_seconds()
                .checked_add(60)
                .ok_or_else(original_unavailable)?,
        )
        .map_err(|_| original_unavailable())?;
        Ok(Box::new(HeldOriginalConsent {
            scope: scope.clone(),
            expires_at,
            original,
        }))
    }
}
pub(super) fn validate_original_scope(
    e: &OriginalAuthorizationView,
    s: &OriginalAuthorizationConsentScope,
) -> Result<()> {
    let t = e.consent.terms();
    let mut inputs: Vec<_> = t
        .input_bindings
        .iter()
        .map(|i| i.nullifier.clone())
        .collect();
    inputs.sort();
    let mut expected = s.input_ids.clone();
    expected.sort();
    if t.principal_id != s.principal_id
        || t.agreement_id != s.agreement_id
        || t.proposal_id != s.candidate_id
        || e.enrollment.participant_id() != s.participant_id
        || t.account_id != s.account_id
        || t.authorization_id != s.authorization_id
        || t.account_id != e.enrollment.account_id()
        || t.principal_id != e.enrollment.principal_id()
        || t.agreement_id != e.enrollment.agreement_id()
        || &t.transport != e.enrollment.transport()
        || e.accepted_manifest.enrollment_ref() != e.enrollment.reference()
        || t.enrollment_ref != e.enrollment.reference()
        || t.accepted_manifest_ref != e.accepted_manifest.reference()
        || e.release_intent.original_consent_ref() != e.consent.reference()
        || t.manifest_digest != s.manifest_digest
        || t.effects_digest != s.effects_commitment
        || t.artifact_digest != s.proved_artifact_digest
        || t.review_binding != s.review_binding
        || inputs != expected
        || t.maximum_debit_zatoshis != s.exact_net_debit.as_zatoshis()
    {
        return Err(original_unavailable());
    }
    Ok(())
}
fn original_unavailable() -> ApiError {
    ApiError::new(
        "ORIGINAL_SIGNER_CONSENT_UNAVAILABLE",
        "The exact original signer consent or its current authenticated native history permission is unavailable; preserve the retained authorization and reconnect the originally enrolled signer",
    )
}

/// Run an engine intake/retention/record operation while its original signer
/// account association is held. The association is borrowed only inside this
/// closure and cannot escape its authenticated history lease. Nested calls hold
/// several participants through the same final effect.
///
/// Remote key enrollment retains its strict HPKE identity checks. The separately
/// tagged local route requires exact already-authorized signer outbox bytes and
/// current access by the original process recipient; the envelope sender is only
/// a relay identity. Maintained cryptographic signature verification still runs.
pub fn with_signer_account_association<R>(
    client: &OriginalHistoryClient,
    request: &HistoryRequest,
    artifact: &ReceivedArtifact,
    operation: impl for<'lease> FnOnce(&'lease AuthenticatedAccountAssociation) -> Result<R>,
) -> Result<R> {
    with_signer_account_association_checked(client, request, artifact, |association, _| operation(association))
}
/// Supplies the real held history lease check for an eventual effect after a
/// native prompt; the association and guard must not escape this callback.
pub fn with_signer_account_association_checked<R>(
    client: &OriginalHistoryClient, request: &HistoryRequest, artifact: &ReceivedArtifact,
    operation: impl FnOnce(&AuthenticatedAccountAssociation, &dyn Fn() -> Result<()>) -> Result<R>,
) -> Result<R> {
    let held = client.acquire(request).map_err(|_| association_missing())?;
    let original = held.evidence();
    let association =
        association_from_original(original, artifact, held.provider_enrollment_reference())?;
    held.check_current().map_err(|_| association_missing())?;
    let check = || held.check_current().map_err(|_| association_missing());
    let result = operation(&association, &check)?;
    held.check_current().map_err(|_| association_missing())?;
    Ok(result)
}

/// Same association boundary after a separate exact native redelivery decision.
/// The reference is only a lookup: current pinned signer IPC authenticates its
/// immutable original/result linkage and exact newly approved process recipient.
pub fn with_redelivered_signer_account_association<R>(
    client: &OriginalHistoryClient,
    request: &HistoryRequest,
    redelivery: &wholepact_signer::consent_journal::ResultRedeliveryReference,
    artifact: &ReceivedArtifact,
    operation: impl for<'lease> FnOnce(&'lease AuthenticatedAccountAssociation) -> Result<R>,
) -> Result<R> {
    with_redelivered_signer_account_association_checked(client, request, redelivery, artifact, |association, _| operation(association))
}
/// Checked redelivery counterpart: recheck the actual held lease immediately
/// before an effect after any interactive wait.
pub fn with_redelivered_signer_account_association_checked<R>(
    client: &OriginalHistoryClient, request: &HistoryRequest,
    redelivery: &wholepact_signer::consent_journal::ResultRedeliveryReference,
    artifact: &ReceivedArtifact,
    operation: impl FnOnce(&AuthenticatedAccountAssociation, &dyn Fn() -> Result<()>) -> Result<R>,
) -> Result<R> {
    let held = client
        .acquire_redelivered(request, redelivery)
        .map_err(|_| association_missing())?;
    let association = association_from_original(
        held.evidence(),
        artifact,
        held.provider_enrollment_reference(),
    )?;
    held.check_current().map_err(|_| association_missing())?;
    let check = || held.check_current().map_err(|_| association_missing());
    let result = operation(&association, &check)?;
    held.check_current().map_err(|_| association_missing())?;
    Ok(result)
}

fn association_from_original(
    original: &OriginalAuthorizationView,
    artifact: &ReceivedArtifact,
    provider_ref: &str,
) -> Result<AuthenticatedAccountAssociation> {
    use sha2::{Digest, Sha256};
    let preview = artifact.preview();
    let context = &preview.context;
    let t = original.consent.terms();
    if context.artifact_kind != ArtifactKind::Authorization
        || context.agreement_id != t.agreement_id
        || context.proposal_id != t.proposal_id
        || context.network_profile_id
            != original
                .accepted_manifest
                .proposal_input()
                .manifest
                .agreement
                .network_profile_id
        || t.account_id != original.enrollment.account_id()
        || t.principal_id != original.enrollment.principal_id()
        || t.agreement_id != original.enrollment.agreement_id()
        || &t.transport != original.enrollment.transport()
        || original.accepted_manifest.enrollment_ref() != original.enrollment.reference()
        || t.enrollment_ref != original.enrollment.reference()
        || t.accepted_manifest_ref != original.accepted_manifest.reference()
        || original.release_intent.original_consent_ref() != original.consent.reference()
        || t.manifest_digest != original.accepted_manifest.manifest_digest()
    {
        return Err(rejected());
    }
    let origin = match original.transport() {
        TransportIdentityBinding::RemoteAuthenticatedKeys {
            sender_key_digest,
            recipient_key_digest,
            ..
        } => {
            if context.sender_id != original.enrollment.participant_id()
                || preview.sender_key_fingerprint != *sender_key_digest
                || preview.recipient_key_fingerprint != *recipient_key_digest
            {
                return Err(rejected());
            }
            AccountAssociationOrigin::RemoteKeys
        }
        TransportIdentityBinding::LocalProcess { .. } => {
            let result = original
                .retained_result
                .as_ref()
                .ok_or_else(association_missing)?;
            let fields = artifact.fields();
            if result.authorization_id != t.authorization_id
                || result.original_consent_ref != original.consent.reference()
                || (&result.exact_local_recipient != original.transport()
                    && result.redelivery.is_none())
                || fields.len() != 1
                || fields[0].name() != "external_spend_signatures_v1"
                || result.outbox_digest != hex::encode(Sha256::digest(fields[0].bytes()))
                || !canonical_hash(provider_ref)
                || !canonical_hash(&result.result_digest)
            {
                return Err(rejected());
            }
            AccountAssociationOrigin::LocalSignerResult {
                provider_enrollment_ref: provider_ref.into(),
                original_consent_ref: result.original_consent_ref.clone(),
                authorization_id: result.authorization_id.clone(),
                result_digest: result.result_digest.clone(),
                outbox_digest: result.outbox_digest.clone(),
            }
        }
    };
    Ok(AuthenticatedAccountAssociation {
        origin,
        sender_fingerprint: preview.sender_key_fingerprint.clone(),
        recipient_fingerprint: preview.recipient_key_fingerprint.clone(),
        sender_id: context.sender_id.clone(),
        recipient_id: context.recipient_id.clone(),
        account_id: t.account_id.clone(),
        fvk_digest: original.enrollment.account_fvk_digest().into(),
        manifest_digest: t.manifest_digest.clone(),
        candidate_id: t.proposal_id.clone(),
    })
}

fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
