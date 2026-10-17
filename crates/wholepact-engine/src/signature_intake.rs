//! Authenticated transport to exact saved-proof signature inspection. This is not
//! a release path. Native signer originals may establish a separately tagged local
//! result origin; transport authentication alone never establishes account control.
use crate::{Access, ApiError, Engine, Result, proof_jobs::LocalProofJob};
use serde::Deserialize;
use wholepact_proof_jobs::VerifiedCheckpoint;
use wholepact_protocol::authorization::retention::{
    RetentionError, SignedCandidateContext, SignedResultJournal, SignedResultSummary,
    SignedRetentionConsent, SignedRetentionScope,
};
use wholepact_protocol::authorization::{ExternalSignature, SignatureInspection};
use wholepact_transport::{ArtifactKind, ReceivedArtifact, Timestamp};

/// Dedicated encrypted retention and its current exact-scope privacy gate.
/// Neither field grants spending, account identity, export or human approval.
pub struct LocalSignedRetention<'a> {
    pub journal: &'a SignedResultJournal,
    pub consent: &'a dyn SignedRetentionConsent,
}

/// Sealed application association. Transport authentication cannot construct it.
/// Remote keys and exact native-local signer results are distinct provenance.
/// The local adapter lends this object only while authenticated current signer
/// permission is held; a relay sender is never labeled as a signer HPKE identity.
#[derive(serde::Serialize)]
#[serde(tag = "origin", rename_all = "snake_case")]
enum AccountAssociationOrigin {
    #[cfg(any(
        all(feature = "signer-authority-bridge", target_os = "linux"),
        all(test, feature = "synthetic-qualification")
    ))]
    RemoteKeys,
    #[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
    LocalSignerResult {
        provider_enrollment_ref: String,
        original_consent_ref: String,
        authorization_id: String,
        result_digest: String,
        outbox_digest: String,
    },
}
pub struct AuthenticatedAccountAssociation {
    origin: AccountAssociationOrigin,
    sender_fingerprint: String,
    recipient_fingerprint: String,
    sender_id: String,
    recipient_id: String,
    account_id: String,
    fvk_digest: String,
    manifest_digest: String,
    candidate_id: String,
}

pub struct AuthenticatedSignatureDelivery<'a> {
    pub artifact: &'a ReceivedArtifact,
    pub association: Option<&'a AuthenticatedAccountAssociation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignaturePayload {
    schema_version: u16,
    candidate_id: String,
    manifest_digest: String,
    proved_artifact_digest: String,
    review_binding: String,
    account_id: String,
    signatures: Vec<SignatureRecord>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureRecord {
    action_index: usize,
    signature_hex: String,
}

fn rejected() -> ApiError {
    ApiError::new(
        "SIGNATURE_INTAKE_REJECTED",
        "Signature delivery does not match the authenticated account, exact saved proof, current envelope scope or bounded signature format",
    )
}
fn association_missing() -> ApiError {
    ApiError::new(
        "ACCOUNT_ASSOCIATION_UNAVAILABLE",
        "A current authenticated signer association for this exact original account, accepted manifest and retained authorization is unavailable; transport authentication alone cannot authorize account attribution",
    )
}

impl Engine {
    /// Loads the engine-origin checkpoint with its existing exact-scope local
    /// read gate. Only a non-sensitive inspection is returned; no signed artifact
    /// is retained, exported, extracted, released or represented as settlement.
    /// `now` is the embedding's supplied evaluation time, not an independently
    /// authenticated clock. Inspection is stateless and repeatable: the transport
    /// owns delivery replay checks; this method creates no durable intake receipt.
    pub fn inspect_candidate_signatures(
        &self,
        access: &Access,
        candidate_id: &str,
        local: LocalProofJob<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<SignatureInspection> {
        if deliveries.iter().any(|d| d.association.is_none()) {
            return Err(association_missing());
        }
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        inspect_deliveries(
            &checkpoint,
            &candidate.proposal.manifest.agreement.agreement_id,
            &candidate.proposal.proposal_id,
            candidate.proposal.manifest.agreement.revision.into(),
            deliveries,
            now,
        )
    }
}

fn authenticate_deliveries(
    checkpoint: &VerifiedCheckpoint,
    agreement_id: &str,
    proposal_id: &str,
    revision: u64,
    deliveries: &[AuthenticatedSignatureDelivery<'_>],
    now: &Timestamp,
    historical: bool,
) -> Result<Vec<ExternalSignature>> {
    use sha2::{Digest, Sha256};
    if deliveries.len() > 32 {
        return Err(rejected());
    }
    let scope = checkpoint.scope();
    let mut signatures = Vec::new();
    let mut senders = std::collections::BTreeSet::new();
    for delivery in deliveries {
        let a = delivery.association.ok_or_else(association_missing)?;
        let preview = delivery.artifact.preview();
        let c = &preview.context;
        if c.artifact_kind != ArtifactKind::Authorization
            || c.network_profile_id != crate::candidates::PROFILE_ID
            || c.agreement_id != agreement_id
            || c.proposal_id != proposal_id
            || c.proposal_revision != revision
            || c.sender_id != a.sender_id
            || c.recipient_id != a.recipient_id
            || preview.sender_key_fingerprint != a.sender_fingerprint
            || preview.recipient_key_fingerprint != a.recipient_fingerprint
            || a.manifest_digest != scope.manifest_digest
            || a.candidate_id != scope.candidate_id
            || now.unix_seconds() < preview.order.issued_at.unix_seconds()
            || (!historical && now.unix_seconds() >= preview.order.expires_at.unix_seconds())
            || !senders.insert(a.account_id.as_str())
        {
            return Err(rejected());
        }
        let fields = delivery.artifact.fields();
        if fields.len() != 1
            || fields[0].name() != "external_spend_signatures_v1"
            || fields[0].bytes().len() > 16_384
        {
            return Err(rejected());
        }
        #[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
        if let AccountAssociationOrigin::LocalSignerResult { outbox_digest, .. } = &a.origin {
            if hex::encode(Sha256::digest(fields[0].bytes())) != *outbox_digest {
                return Err(rejected());
            }
        }
        let payload: SignaturePayload =
            wholepact_core::strict_json::parse_typed_json(fields[0].bytes())
                .map_err(|_| rejected())?;
        if payload.schema_version != 1
            || payload.candidate_id != scope.candidate_id
            || payload.manifest_digest != scope.manifest_digest
            || Some(payload.proved_artifact_digest.as_str())
                != checkpoint.summary().result_digest.as_deref()
            || payload.review_binding != scope.review_binding
            || payload.account_id != a.account_id
            || payload.signatures.is_empty()
            || payload.signatures.len() > 64
        {
            return Err(rejected());
        }
        let participant_index = checkpoint
            .policy()
            .participants
            .iter()
            .position(|p| {
                p.account_id == a.account_id
                    && hex::encode(Sha256::digest(p.fvk.to_bytes())) == a.fvk_digest
            })
            .ok_or_else(rejected)?;
        for record in payload.signatures {
            if record.signature_hex.len() != 128
                || record
                    .signature_hex
                    .bytes()
                    .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
            {
                return Err(rejected());
            }
            let signature: [u8; 64] = hex::decode(record.signature_hex)
                .map_err(|_| rejected())?
                .try_into()
                .map_err(|_| rejected())?;
            signatures.push(ExternalSignature {
                participant_index,
                action_index: record.action_index,
                signature,
            });
            if signatures.len() > 64 {
                return Err(rejected());
            }
        }
    }
    Ok(signatures)
}

fn inspect_deliveries(
    checkpoint: &VerifiedCheckpoint,
    agreement_id: &str,
    proposal_id: &str,
    revision: u64,
    deliveries: &[AuthenticatedSignatureDelivery<'_>],
    now: &Timestamp,
) -> Result<SignatureInspection> {
    let signatures = authenticate_deliveries(
        checkpoint,
        agreement_id,
        proposal_id,
        revision,
        deliveries,
        now,
        false,
    )?;
    wholepact_protocol::authorization::inspect_external_signatures(
        checkpoint.pczt_bytes(),
        checkpoint.policy(),
        &checkpoint.scope().review_binding,
        &signatures,
        wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
    )
    .map_err(|_| rejected())
}

impl Engine {
    /// Authenticate the same known signature fields as inspection, then retain a
    /// separate immutable signed PCZT. Current checkpoint provenance/read consent
    /// and dedicated signed-retention consent are mandatory on every replay.
    /// Static association objects do not establish revocation freshness; their
    /// production issuer remains unavailable. No transaction bytes are extracted.
    // Keep checkpoint, delivery and consent boundaries explicit at this adapter.
    #[allow(clippy::too_many_arguments)]
    pub fn retain_candidate_signatures(
        &self,
        access: &Access,
        idempotency_key: &str,
        candidate_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<SignedResultSummary> {
        self.retain_candidate_signatures_inner(
            access,
            idempotency_key,
            candidate_id,
            local,
            retention,
            deliveries,
            now,
            false,
        )
    }

    /// Reconcile an already committed exact signature intent using historical
    /// authenticated envelopes. No intent may be created by this path, including
    /// if the database has been replaced/restored without the expected record.
    /// Historical delivery is not new approval, signing or release authority.
    // Keep checkpoint, delivery and consent boundaries explicit at this adapter.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_retained_candidate_signatures(
        &self,
        access: &Access,
        idempotency_key: &str,
        candidate_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<SignedResultSummary> {
        self.retain_candidate_signatures_inner(
            access,
            idempotency_key,
            candidate_id,
            local,
            retention,
            deliveries,
            now,
            true,
        )
    }

    // Keep checkpoint, delivery and consent boundaries explicit at this adapter.
    #[allow(clippy::too_many_arguments)]
    fn retain_candidate_signatures_inner(
        &self,
        access: &Access,
        idempotency_key: &str,
        candidate_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
        historical: bool,
    ) -> Result<SignedResultSummary> {
        if deliveries.iter().any(|d| d.association.is_none()) {
            return Err(association_missing());
        }
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let read_consent = local.consent;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        retain_deliveries(
            &checkpoint,
            &candidate.proposal.manifest.agreement.agreement_id,
            &candidate.proposal.proposal_id,
            candidate.proposal.manifest.agreement.revision.into(),
            deliveries,
            now,
            idempotency_key,
            retention,
            read_consent,
            historical,
        )
    }
}

pub(crate) fn retention_inputs(
    checkpoint: &VerifiedCheckpoint,
    agreement_id: &str,
    proposal_id: &str,
    revision: u64,
    deliveries: &[AuthenticatedSignatureDelivery<'_>],
    now: &Timestamp,
    historical: bool,
) -> Result<(SignedCandidateContext, Vec<ExternalSignature>)> {
    use sha2::{Digest, Sha256};
    let signatures = authenticate_deliveries(
        checkpoint,
        agreement_id,
        proposal_id,
        revision,
        deliveries,
        now,
        historical,
    )?;
    let mut provenance = Vec::new();
    for d in deliveries {
        let association = d.association.ok_or_else(association_missing)?;
        provenance.push((
            d.artifact.preview().digest().map_err(|_| rejected())?,
            association.account_id.clone(),
            association.fvk_digest.clone(),
            d.artifact.stream_digest().to_owned(),
            wholepact_core::proposal::canonical_digest(
                "wholepact:account-association-origin:v1",
                &association.origin,
            )
            .map_err(|_| rejected())?,
        ));
    }
    provenance.sort();
    let provenance = serde_json::to_vec(&provenance).map_err(|_| rejected())?;
    let scope = checkpoint.scope();
    let context = SignedCandidateContext {
        principal_id: scope.principal_id.clone(),
        candidate_id: scope.candidate_id.clone(),
        proof_job_id: checkpoint.summary().job_id.clone(),
        checkpoint_scope_digest: checkpoint.summary().scope_digest.clone(),
        proved_artifact_digest: checkpoint
            .summary()
            .result_digest
            .clone()
            .ok_or_else(rejected)?,
        manifest_digest: scope.manifest_digest.clone(),
        review_binding: scope.review_binding.clone(),
        delivery_provenance_digest: hex::encode(Sha256::digest(&provenance)),
        account_ids: scope.account_ids.clone(),
        local_operator: scope.local_operator.clone(),
        purpose: scope.purpose.clone(),
        retention_policy: scope.retention_policy.clone(),
    };
    Ok((context, signatures))
}

struct Gate<'a> {
    original: &'a wholepact_proof_jobs::CheckpointScope,
    read: &'a dyn wholepact_proof_jobs::LocalProofConsent,
    retain: &'a dyn SignedRetentionConsent,
}
impl SignedRetentionConsent for Gate<'_> {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        let read = || {
            self.read.permits(
                self.original,
                wholepact_proof_jobs::LocalAction::ReadPrivateArtifact,
            )
        };
        read() && self.retain.permits(scope) && read()
    }
}

// Shared by the production engine bridge and synthetic authenticated-envelope
// integration test. It cannot issue associations or bypass the original proof.
// Keep checkpoint, delivery and consent boundaries explicit at this adapter.
#[allow(clippy::too_many_arguments)]
fn retain_deliveries(
    checkpoint: &VerifiedCheckpoint,
    agreement_id: &str,
    proposal_id: &str,
    revision: u64,
    deliveries: &[AuthenticatedSignatureDelivery<'_>],
    now: &Timestamp,
    key: &str,
    retention: LocalSignedRetention<'_>,
    read_consent: &dyn wholepact_proof_jobs::LocalProofConsent,
    historical: bool,
) -> Result<SignedResultSummary> {
    let (context, signatures) = retention_inputs(
        checkpoint,
        agreement_id,
        proposal_id,
        revision,
        deliveries,
        now,
        historical,
    )?;
    let scope = checkpoint.scope();
    let consent = Gate {
        original: scope,
        read: read_consent,
        retain: retention.consent,
    };
    let result = if historical {
        retention.journal.reconcile_existing(
            context,
            key,
            checkpoint.pczt_bytes(),
            checkpoint.policy(),
            &signatures,
            wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
            &consent,
        )
    } else {
        retention.journal.retain(
            context,
            key,
            checkpoint.pczt_bytes(),
            checkpoint.policy(),
            &signatures,
            wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
            &consent,
        )
    };
    result
        .map_err(|error| {
            let code = match error {
                RetentionError::ConsentDenied => "SIGNED_RETENTION_CONSENT_DENIED",
                RetentionError::RecoveryRequired => "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED",
                RetentionError::IncompleteSignatures => "TRANSACTION_SIGNATURES_INCOMPLETE",
                RetentionError::IntentNotFound => "SIGNED_RETENTION_INTENT_NOT_FOUND",
                RetentionError::IdempotencyConflict => "SIGNED_RETENTION_IDEMPOTENCY_CONFLICT",
                RetentionError::ResourceExhausted => "SIGNED_RETENTION_CAPACITY_REACHED",
                RetentionError::Storage => "SIGNED_RETENTION_STORAGE_FAILED",
                RetentionError::UnsupportedSchema => "SIGNED_RETENTION_SCHEMA_UNSUPPORTED",
                RetentionError::InvalidRequest | RetentionError::VerificationFailed => "SIGNED_RETENTION_REJECTED",
            };
            ApiError::new(code, "Signed-result retention failed closed; the original proof and any committed signature intent remain unchanged. No release or transaction extraction was enabled")
        })
}

#[cfg(feature = "transaction-checkpoint")]
impl Engine {
    /// Privately extract and durably retain a transaction from an existing exact
    /// signed result. Historical envelopes can only refer to that saved result.
    /// An incomplete extraction intent is fenced; this is never a release API.
    #[allow(clippy::too_many_arguments)]
    pub fn checkpoint_retained_candidate_transaction(
        &self,
        access: &Access,
        signature_idempotency_key: &str,
        candidate_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        transaction: wholepact_protocol::authorization::retention::transaction::LocalTransactionCheckpoint<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<
        wholepact_protocol::authorization::retention::transaction::TransactionCheckpointSummary,
    > {
        if deliveries.iter().any(|d| d.association.is_none()) {
            return Err(association_missing());
        }
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let read_consent = local.consent;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        checkpoint_transaction_deliveries(
            &checkpoint,
            &candidate.proposal.manifest.agreement.agreement_id,
            &candidate.proposal.proposal_id,
            candidate.proposal.manifest.agreement.revision.into(),
            deliveries,
            now,
            signature_idempotency_key,
            retention,
            read_consent,
            transaction,
        )
    }
}

#[cfg(feature = "transaction-checkpoint")]
#[allow(clippy::too_many_arguments)]
fn checkpoint_transaction_deliveries(
    checkpoint: &VerifiedCheckpoint,
    agreement_id: &str,
    proposal_id: &str,
    revision: u64,
    deliveries: &[AuthenticatedSignatureDelivery<'_>],
    now: &Timestamp,
    key: &str,
    retention: LocalSignedRetention<'_>,
    read_consent: &dyn wholepact_proof_jobs::LocalProofConsent,
    transaction: wholepact_protocol::authorization::retention::transaction::LocalTransactionCheckpoint<'_>,
) -> Result<wholepact_protocol::authorization::retention::transaction::TransactionCheckpointSummary>
{
    let (context, signatures) = retention_inputs(
        checkpoint,
        agreement_id,
        proposal_id,
        revision,
        deliveries,
        now,
        true,
    )?;
    retention.journal.checkpoint_transaction(context, key, checkpoint.pczt_bytes(), checkpoint.policy(), &signatures,
        wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
        &Gate { original: checkpoint.scope(), read: read_consent, retain: retention.consent }, transaction)
        .map_err(|error| {
            let code = match error {
                RetentionError::ConsentDenied => "TRANSACTION_RETENTION_CONSENT_DENIED",
                RetentionError::RecoveryRequired => "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED",
                RetentionError::IncompleteSignatures => "TRANSACTION_SIGNATURES_INCOMPLETE",
                RetentionError::IntentNotFound => "SIGNED_RETENTION_INTENT_NOT_FOUND",
                RetentionError::IdempotencyConflict => "TRANSACTION_CHECKPOINT_CONFLICT",
                RetentionError::ResourceExhausted => "TRANSACTION_CHECKPOINT_CAPACITY_REACHED",
                RetentionError::Storage => "TRANSACTION_CHECKPOINT_STORAGE_FAILED",
                RetentionError::UnsupportedSchema => "TRANSACTION_CHECKPOINT_SCHEMA_UNSUPPORTED",
                RetentionError::InvalidRequest | RetentionError::VerificationFailed => "TRANSACTION_CHECKPOINT_REJECTED",
            };
            ApiError::new(code, "Transaction checkpoint failed closed. Any incomplete extraction intent remains fenced and cannot be automatically retried; completed bytes remain private. No release authority was granted")
        })
}

#[cfg(feature = "transaction-checkpoint")]
impl Engine {
    /// Recover only an existing exact transaction checkpoint from an authenticated
    /// encrypted retained copy. Missing originals stay fenced; this never invokes
    /// extraction, creates a new payment, or grants release authority.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_retained_candidate_transaction(
        &self,
        access: &Access,
        signature_idempotency_key: &str,
        candidate_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        recovery: wholepact_protocol::authorization::retention::transaction::LocalTransactionRecovery<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<wholepact_protocol::authorization::retention::transaction::TransactionRecoverySummary>
    {
        if deliveries
            .iter()
            .any(|delivery| delivery.association.is_none())
        {
            return Err(association_missing());
        }
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let read_consent = local.consent;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        let (context, signatures) = retention_inputs(
            &checkpoint,
            &candidate.proposal.manifest.agreement.agreement_id,
            &candidate.proposal.proposal_id,
            candidate.proposal.manifest.agreement.revision.into(),
            deliveries,
            now,
            true,
        )?;
        retention.journal.recover_transaction_checkpoint(
            context,
            signature_idempotency_key,
            checkpoint.pczt_bytes(),
            checkpoint.policy(),
            &signatures,
            wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
            &Gate { original: checkpoint.scope(), read: read_consent, retain: retention.consent },
            recovery,
        ).map_err(|error| {
            let code = match error {
                RetentionError::ConsentDenied => "TRANSACTION_RECOVERY_CONSENT_DENIED",
                RetentionError::RecoveryRequired => "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED",
                RetentionError::IncompleteSignatures => "TRANSACTION_SIGNATURES_INCOMPLETE",
                RetentionError::IntentNotFound => "TRANSACTION_CHECKPOINT_INTENT_NOT_FOUND",
                RetentionError::IdempotencyConflict => "TRANSACTION_CHECKPOINT_CONFLICT",
                RetentionError::ResourceExhausted => "TRANSACTION_CHECKPOINT_CAPACITY_REACHED",
                RetentionError::Storage => "TRANSACTION_CHECKPOINT_STORAGE_FAILED",
                RetentionError::UnsupportedSchema => "TRANSACTION_CHECKPOINT_SCHEMA_UNSUPPORTED",
                RetentionError::InvalidRequest | RetentionError::VerificationFailed => "TRANSACTION_CHECKPOINT_REJECTED",
            };
            ApiError::new(code, "Exact transaction recovery failed closed. Preserve the original encrypted journals; no transaction was regenerated and no release authority was granted")
        })
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
#[path = "signature_intake_tests.rs"]
mod tests;

#[cfg(feature = "submission-handoff")]
#[path = "submission_handoff.rs"]
mod submission_handoff;
#[cfg(feature = "submission-handoff")]
pub use submission_handoff::VerifiedCandidateSubmission;

#[cfg(all(
    test,
    feature = "synthetic-qualification",
    feature = "submission-handoff",
    target_os = "linux"
))]
#[path = "connected_flow_tests.rs"]
mod connected_flow_tests;

#[cfg(feature = "transaction-checkpoint")]
#[path = "signature_intake/record_source.rs"]
pub mod record_source;

#[cfg(feature = "transaction-checkpoint")]
#[path = "signature_intake/recipient_source.rs"]
pub mod recipient_source;

#[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
#[path = "signature_intake/authority_bridge.rs"]
pub mod authority_bridge;

#[cfg(all(
    test,
    feature = "synthetic-qualification",
    feature = "signer-authority-bridge",
    target_os = "linux"
))]
#[path = "signer_authority_connected_tests.rs"]
mod signer_authority_connected_tests;

#[cfg(feature = "transaction-checkpoint")]
mod portable;

#[cfg(feature = "offline-return-foundation")]
#[allow(dead_code)]
mod offline_return;
