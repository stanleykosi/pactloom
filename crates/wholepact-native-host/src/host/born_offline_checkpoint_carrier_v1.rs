//! Native owner of the dedicated completed-checkpoint origin carrier.
//! No imported DTO, transport receipt, old construction consent or metadata
//! status can create this owner. It grants no signature, permit or dispatch.
#[path = "born_offline_checkpoint_codec_v1.rs"]
pub(in crate::host) mod codec;
use super::Host;
use crate::authority::Held;
use crate::recovery_generation::manual_target::ManualCommittedTarget;
use crate::terminal::{
    born_checkpoint_retention_v1::BornCheckpointRetentionV1, historical::HistoricalApproval,
};
use crate::{Error, Result, files, now, vault::JOURNALS};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use wholepact_authority::born_offline_checkpoint_origin_v1::{
    BornOfflineCheckpointConstructionV1, BornOfflineCheckpointExportPlanV1,
    BornOfflineCheckpointOriginV1,
};
use wholepact_core::manual_enrollment::ManualHostGenerationBinding;
use wholepact_engine::born_offline_checkpoint_original_v1::BornOfflineCheckpointOriginalV1;
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent};
use wholepact_service::protected_transport::{
    LocalTransportKeyController, TransportDirection, TransportKeyScope,
};
use wholepact_storage_security::DatabaseFileIdentity;
use wholepact_transport::{
    TransportPublicKey, born_offline_checkpoint_context_v1, born_offline_checkpoint_fields_v1,
};

/// Private native ownership, not a serializable export or consumption token.
pub(in crate::host) struct PreparedBornOfflineCheckpointCarrierV1<'host> {
    host: &'host Host,
    committed: ManualCommittedTarget<'host>,
    original: BornOfflineCheckpointOriginalV1<'host>,
    retention: BornCheckpointRetentionV1,
    held: Held,
    origin: BornOfflineCheckpointOriginV1,
    plan: BornOfflineCheckpointExportPlanV1,
    peer: TransportPublicKey,
    outbox: codec::SqliteOutbox,
    outbox_identity: DatabaseFileIdentity,
    prepared: Option<codec::PreparedExport>,
}

/// A local encrypted-file result only. Delivery, signer acceptance, current
/// spendability, authorization and settlement are deliberately not asserted.
#[derive(Serialize)]
pub(in crate::host) struct BornOfflineCheckpointCarrierExportV1 {
    pub checkpoint_origin_digest: String,
    pub export_plan: BornOfflineCheckpointExportPlanV1,
    pub ciphertext_digest: String,
    pub recovered_original_ciphertext: bool,
}

/// Actual immutable outbox row, lent together with its native original owner.
/// No constructor accepts an envelope, statement or plan supplied by a caller.
pub(in crate::host) struct RetainedBornOfflineCheckpointCarrierV1<'owner, 'host> {
    owner: &'owner PreparedBornOfflineCheckpointCarrierV1<'host>,
    artifact: codec::OutboxArtifact,
}

impl Host {
    /// `expected_peer` selects an ALREADY independently pinned session peer.
    /// A supplied original plan is inert retry metadata, never consent or an
    /// authenticated original. The actual origin always comes from held owners.
    pub(in crate::host) fn prepare_born_offline_checkpoint_carrier_v1<'host>(
        &'host self,
        agreement_id: &str,
        construction_key: &str,
        account_id: &str,
        expected_peer: &TransportPublicKey,
        original_export_plan: Option<BornOfflineCheckpointExportPlanV1>,
    ) -> Result<PreparedBornOfflineCheckpointCarrierV1<'host>> {
        self.require_manual_session()?;
        crate::id(agreement_id)?;
        if !(16..=128).contains(&construction_key.len())
            || !construction_key.bytes().all(|b| (33..=126).contains(&b))
        {
            return Err(Error::Invalid);
        }
        let principal = self.access()?.principal_id.clone();
        let key_commitment =
            wholepact_store::request_digest(&serde_json::json!([&principal, construction_key]))?;
        let primary = self.financial.as_ref().ok_or(Error::Locked)?;
        let initial = self.terminal.approve_historical(&format!(
            "Read the current authenticated generation's complete sealed parent capsule, inherited identity coverage and complete bounded coordination construction/audit records, then select the actual completed version-5 construction with immutable original scanner provenance below. Authenticate the actual primary financial attachment and its four original journals. This private history can include other accounts and agreements and original input/nullifier/value facts; it is not printed or exported. A separate exact saved-scope approval is required before reading and verifying the selected unsigned private proof. No prover, wallet source, reservation, repair, signature or network dispatch is run.\nProfile: {}\nPrimary financial directory: {}\nPrincipal: {}\nAgreement: {}\nOriginal construction key commitment: {}\nSelected account: {}\nAlready-pinned offline signer fingerprint: {}\nThe existing Host ciphertext outbox may be opened on its SAME authenticated file identity, read for exact retry/order metadata and retain ordinary SQLite sidecars. Private encrypted temporary copies used by source authentication can survive a crash or cleanup failure; secure deletion is not promised. This approval neither renews construction nor permits export. A separate exact origin/recipient/path publication decision precedes any carrier ciphertext write.",
            self.secrets.profile(), primary.current_directory()?.display(), principal,
            agreement_id, key_commitment, account_id, expected_peer.fingerprint(),
        ))?;
        let mut source = None;
        initial.effect(&mut || {
            initial.check()?;
            self.require_manual_session()?;
            let committed = ManualCommittedTarget::open(&self.directory, &self.secrets)?;
            committed.coverage().require_complete()?;
            let prepared = self.engine.prepare_born_offline_checkpoint_original_v1(
                self.access()?,
                agreement_id,
                construction_key,
            )?;
            let original_host = &prepared.claim().consumed[0].request.plan.enrollment().host;
            check_source(
                self,
                &committed,
                original_host,
                &prepared.claim().invocation().checkpoint_destination,
            )?;
            let held = self.authority.fence.acquire(now()?.saturating_add(120))?;
            let identity = live_outbox_identity(self)?;
            // Ordinary serialized connection: the live Host already owns this
            // profile. No new file/key/provisioning or quiescent-copy claim.
            let connection = wholepact_storage_security::open_encrypted(
                self.directory.path(JOURNALS[2])?,
                &self.secrets.key(2)?,
            )?;
            if connection.database_identity()? != identity {
                return Err(Error::Authentication);
            }
            let outbox =
                codec::SqliteOutbox::from_encrypted_connection(connection).map_err(codec_error)?;
            if outbox.database_identity().map_err(codec_error)? != identity
                || live_outbox_identity(self)? != identity
            {
                return Err(Error::Authentication);
            }
            prepared.check_current(self.access()?)?;
            initial.check()?;
            source = Some((committed, prepared, held, outbox, identity));
            Ok(())
        })?;
        let (committed, prepared, held, outbox, outbox_identity) =
            source.ok_or(Error::Authentication)?;
        let read = self.terminal.approve_historical_reviewed(&initial, &format!(
            "Read and independently verify ONLY the actual completed private checkpoint for this exact saved scope. This opens the saved unsigned predecessor, proved private transaction and proof policy, including all participant viewing keys and private witnesses, in this non-signing Host's memory. These private bytes and keys are not printed or exported. Verification checks proof validity, exact predecessor normalization, original artifact and policy commitments, every retained account's viewing-key digest and own input nullifier/value set. It does not establish current chain validity, freshness or unspentness. No new proof, source observation, signing, reservation, repair or dispatch is permitted. No old construction permission is revived.\n{}\nOnly after this check may a separate native publication review disclose selected checkpoint-origin metadata, not these private proof bytes, to the independently pinned offline signer.",
            serde_json::to_string_pretty(prepared.scope())?,
        ))?;
        let original_host = prepared.claim().consumed[0]
            .request
            .plan
            .enrollment()
            .host
            .clone();
        let destination = prepared.claim().invocation().checkpoint_destination.clone();
        let scope = prepared.scope().clone();
        let consent = NativeCheckpointReadConsentV1 {
            host: self,
            committed: &committed,
            original_host: &original_host,
            destination: &destination,
            scope: &scope,
            initial: &initial,
            read: &read,
            held: &held,
        };
        let mut prepared = Some(prepared);
        let mut original = None;
        read.effect(&mut || {
            consent.check()?;
            original = Some(prepared.take().ok_or(Error::Permission)?.load_verified(
                self.access()?,
                &primary.proof,
                &consent,
            )?);
            consent.check()
        })?;
        let original = original.ok_or(Error::Authentication)?;
        let origin = derive_origin(
            &original,
            account_id,
            expected_peer,
            &self.secrets.transport()?.public_key()?,
        )?;
        // A NEW explicit privacy-retention purpose, not renewal of the initial read
        // or any original construction/signing authority.
        let retention = self
            .terminal
            .approve_born_checkpoint_retention_v1(&initial, &read, &origin)?;
        let held = self
            .authority
            .fence
            .acquire(now()?.checked_add(900).ok_or(Error::Invalid)?)?;
        let context = born_offline_checkpoint_context_v1(&origin)?;
        let keys = self.authority.keys(&TransportKeyScope {
            principal_id: principal,
            context: context.clone(),
            direction: TransportDirection::Outgoing,
        })?;
        if keys.pinned_peer != *expected_peer
            || keys.local_secret.public_key()?.fingerprint() != origin.host_return_key_digest
        {
            return Err(Error::Authentication);
        }
        let nominal_context = serde_json::from_slice(&serde_json::to_vec(&context)?)?;
        let plan = match original_export_plan {
            Some(plan) => plan,
            None => {
                let issued = i64::try_from(now()?).map_err(|_| Error::Invalid)?;
                BornOfflineCheckpointExportPlanV1 {
                    message_id: codec::random_message_id().map_err(codec_error)?,
                    sequence: outbox.next_sequence(&nominal_context).map_err(codec_error)?,
                    issued_at_unix_seconds: issued,
                    expires_at_unix_seconds: issued.checked_add(3600).ok_or(Error::Invalid)?,
                    purpose: "Authenticate this original completed checkpoint to its pinned offline signer".into(),
                    persistence_warning: "The recipient may retain this private origin metadata indefinitely; ciphertext recovery never renews validity or grants transaction authority".into(),
                    sender_id: context.sender_id.clone(), recipient_id: context.recipient_id.clone(),
                    sender_key_fingerprint: origin.host_return_key_digest.clone(),
                    recipient_key_fingerprint: origin.signer_key_digest.clone(),
                }
            }
        };
        plan.validate_for(&origin)
            .map_err(|_| Error::Authentication)?;
        let fields = born_offline_checkpoint_fields_v1(&origin)?
            .iter()
            .map(|field| {
                codec::DisclosureField::new(field.name(), field.bytes().to_vec())
                    .map_err(codec_error)
            })
            .collect::<Result<Vec<_>>>()?;
        let sender = nominal_key(&keys.local_secret.public_key()?)?;
        let recipient = nominal_key(&keys.pinned_peer)?;
        // Historical reconstruction is solely for exact persisted retry matching.
        // First sealing still enforces real current time and monotonic approval.
        let original_time = codec::Timestamp::from_unix_seconds(plan.issued_at_unix_seconds)
            .map_err(codec_error)?;
        let export = codec::prepare_export(
            codec::ExportRequest {
                context: nominal_context,
                order: codec::MessageOrder {
                    message_id: plan.message_id.clone(),
                    sequence: plan.sequence,
                    issued_at: original_time.clone(),
                    expires_at: codec::Timestamp::from_unix_seconds(plan.expires_at_unix_seconds)
                        .map_err(codec_error)?,
                },
                purpose: plan.purpose.clone(),
                persistence_warning: plan.persistence_warning.clone(),
            },
            fields,
            &sender,
            &recipient,
            &original_time,
        )
        .map_err(codec_error)?;
        let owner = PreparedBornOfflineCheckpointCarrierV1 {
            host: self,
            committed,
            original,
            retention,
            held,
            origin,
            plan,
            peer: expected_peer.clone(),
            outbox,
            outbox_identity,
            prepared: Some(export),
        };
        owner.check_current()?;
        Ok(owner)
    }
}

impl<'host> PreparedBornOfflineCheckpointCarrierV1<'host> {
    /// Historical projection only, never a constructor for this native owner.
    pub(in crate::host) fn origin(&self) -> &BornOfflineCheckpointOriginV1 {
        &self.origin
    }
    pub(in crate::host) fn export_plan(&self) -> &BornOfflineCheckpointExportPlanV1 {
        &self.plan
    }
    pub(in crate::host) fn original(&self) -> &BornOfflineCheckpointOriginalV1<'host> {
        &self.original
    }
    /// Require the exact previously committed original, including all reviewed
    /// ordering/times, payload and recipient metadata. Absence fails closed.
    pub(in crate::host) fn retained_export(
        &self,
    ) -> Result<RetainedBornOfflineCheckpointCarrierV1<'_, 'host>> {
        self.check_current()?;
        let preview = self.prepared.as_ref().ok_or(Error::Permission)?.preview();
        let sender = nominal_key(&self.host.secrets.transport()?.public_key()?)?;
        let peer = nominal_key(&self.peer)?;
        let artifact = self
            .outbox
            .recover_message_for_recipient(
                &preview.context,
                &peer,
                &self.plan.message_id,
                &preview.payload_digest,
                &sender,
            )
            .map_err(codec_error)?
            .ok_or(Error::Authentication)?;
        if artifact.preview_digest() != preview.digest().map_err(codec_error)?
            || artifact.sequence() != self.plan.sequence
        {
            return Err(Error::Authentication);
        }
        self.check_current()?;
        Ok(RetainedBornOfflineCheckpointCarrierV1 {
            owner: self,
            artifact,
        })
    }
    pub(in crate::host) fn check_current(&self) -> Result<()> {
        self.retention.check(&self.origin)?;
        self.held.check()?;
        self.original.check_current(self.host.access()?)?;
        check_source(
            self.host,
            &self.committed,
            &self.origin.host,
            &self.original.claim().invocation().checkpoint_destination,
        )?;
        if self.origin
            != derive_origin(
                &self.original,
                &self.origin.account_id,
                &self.peer,
                &self.host.secrets.transport()?.public_key()?,
            )?
            || live_outbox_identity(self.host)? != self.outbox_identity
            || self.outbox.database_identity().map_err(codec_error)? != self.outbox_identity
        {
            return Err(Error::Authentication);
        }
        let keys = self.host.authority.keys(&TransportKeyScope {
            principal_id: self.origin.principal_id.clone(),
            context: born_offline_checkpoint_context_v1(&self.origin)?,
            direction: TransportDirection::Outgoing,
        })?;
        if keys.pinned_peer != self.peer
            || keys.local_secret.public_key()?.fingerprint() != self.origin.host_return_key_digest
        {
            return Err(Error::Authentication);
        }
        self.plan
            .validate_for(&self.origin)
            .map_err(|_| Error::Authentication)?;
        self.held.check()?;
        self.retention.check(&self.origin)
    }
    /// Writes only once-sealed ciphertext to a newly created external path.
    /// A retry requires this exact original plan and returns original bytes;
    /// expired historical ciphertext is never resealed or made current again.
    pub(in crate::host) fn export_to(
        mut self,
        path: &Path,
    ) -> Result<BornOfflineCheckpointCarrierExportV1> {
        self.check_current()?;
        check_destination(self.host, path)?;
        let preview = self.prepared.as_ref().ok_or(Error::Permission)?.preview();
        let preview_digest = preview.digest().map_err(codec_error)?;
        let publication_digest = wholepact_store::request_digest(&serde_json::json!([
            "wholepact:native-born-checkpoint-carrier-publication:v1",
            self.origin.digest().map_err(|_| Error::Authentication)?,
            self.plan.digest().map_err(|_| Error::Authentication)?,
            &preview_digest,
            path.to_str().ok_or(Error::Invalid)?,
        ]))?;
        let approval = self.retention.approve_publication(&self.origin, &publication_digest,
            &format!("Export exactly this completed-checkpoint origin metadata, HPKE-authenticated by the existing Host return key to the independently pinned offline signer. The private origin includes profile/generation identifiers, canonical Host and Store paths, principal, account and viewing-key digests, original construction key and commitments, proof job/scope identifiers and construction lineage. NO transaction, private witness, viewing key or signer key bytes are disclosed. The recipient can retain the metadata indefinitely. This statement proves retained original completion only, not current chain validity, unspentness, permission, signature or dispatch.\nExact origin: {}\nExact original export plan: {}\nExact preview: {}\nCreate-only ciphertext destination: {}\nThe SAME protected Host outbox durably retains the original ciphertext before file output. If output or acknowledgment fails, preserve the plan and all files and recover the identical original; never change the key, times or order, reseal, overwrite or assume no effect occurred. Expired recovery remains historical and does not become importable again.",
                serde_json::to_string_pretty(&self.origin)?, serde_json::to_string_pretty(&self.plan)?,
                serde_json::to_string_pretty(preview)?, path.display()))?;
        let deadline = approval.deadline().min(self.retention.deadline());
        approval.commit(&publication_digest, || Ok(()), |_| {
            self.check_current()?;
            check_destination(self.host, path)?;
            let prepared = self.prepared.take().ok_or(Error::Permission)?;
            let preview = prepared.preview();
            let sender = codec::TransportSecret::from_bytes(*self.host.secrets.transport_material()?).map_err(codec_error)?;
            let peer = nominal_key(&self.peer)?;
            let existing = self.outbox.recover_message_for_recipient(
                &preview.context, &peer, &self.plan.message_id, &preview.payload_digest,
                &sender.public_key().map_err(codec_error)?,
            ).map_err(codec_error)?;
            let recovered = existing.is_some();
            let artifact = if let Some(artifact) = existing {
                if artifact.preview_digest() != preview_digest || artifact.sequence() != self.plan.sequence {
                    return Err(Error::Authentication);
                }
                artifact
            } else {
                self.check_current()?;
                let first_wall_ms = wall_ms()?;
                let timestamp = codec::Timestamp::from_unix_seconds(
                    i64::try_from(first_wall_ms / 1000).map_err(|_| Error::Invalid)?,
                ).map_err(codec_error)?;
                self.outbox.enqueue_validated_before(prepared, &sender, &preview_digest,
                    &timestamp, deadline, first_wall_ms).map_err(codec_error)?
            };
            self.check_current()?;
            if std::time::Instant::now() >= deadline { return Err(Error::Permission); }
            check_destination(self.host, path)?;
            let result = BornOfflineCheckpointCarrierExportV1 {
                checkpoint_origin_digest: self.origin.digest().map_err(|_| Error::Authentication)?,
                export_plan: self.plan.clone(),
                ciphertext_digest: hex::encode(Sha256::digest(artifact.envelope().as_bytes())),
                recovered_original_ciphertext: recovered,
            };
            files::write_new(path, artifact.envelope().as_bytes())
                .map_err(|_| Error::Receipt("original checkpoint carrier is retained; ciphertext file output is uncertain".into()))?;
            self.check_current().map_err(|_| Error::Receipt(
                "original checkpoint carrier was retained and file output may have completed; preserve exact bytes".into(),
            ))?;
            Ok(result)
        })
    }
}

impl<'host> RetainedBornOfflineCheckpointCarrierV1<'_, 'host> {
    /// Restriction-only bound from the original native private-data retention.
    pub(in crate::host) fn deadline(&self) -> std::time::Instant {
        self.owner.retention.deadline()
    }
    pub(in crate::host) fn belongs_to(&self, host: &Host) -> bool {
        std::ptr::eq(self.owner.host, host)
    }
    pub(in crate::host) fn origin(&self) -> &BornOfflineCheckpointOriginV1 {
        &self.owner.origin
    }
    pub(in crate::host) fn export_plan(&self) -> &BornOfflineCheckpointExportPlanV1 {
        &self.owner.plan
    }
    pub(in crate::host) fn original(&self) -> &BornOfflineCheckpointOriginalV1<'host> {
        &self.owner.original
    }
    pub(in crate::host) fn ciphertext(&self) -> &[u8] {
        self.artifact.envelope().as_bytes()
    }
    pub(in crate::host) fn ciphertext_digest(&self) -> String {
        hex::encode(Sha256::digest(self.ciphertext()))
    }
    pub(in crate::host) fn check_current(&self) -> Result<()> {
        self.owner.check_current()?;
        let actual = self.owner.retained_export()?;
        if actual.artifact.envelope().as_bytes() != self.artifact.envelope().as_bytes() {
            return Err(Error::Authentication);
        }
        self.owner.check_current()
    }
}

struct NativeCheckpointReadConsentV1<'a, 'host> {
    host: &'host Host,
    committed: &'a ManualCommittedTarget<'host>,
    original_host: &'a ManualHostGenerationBinding,
    destination: &'a str,
    scope: &'a CheckpointScope,
    initial: &'a HistoricalApproval,
    read: &'a HistoricalApproval,
    held: &'a Held,
}
impl NativeCheckpointReadConsentV1<'_, '_> {
    fn check(&self) -> Result<()> {
        self.initial.check()?;
        self.read.check()?;
        self.held.check()?;
        check_source(
            self.host,
            self.committed,
            self.original_host,
            self.destination,
        )?;
        self.initial.check()?;
        self.read.check()?;
        self.held.check()
    }
}
impl LocalProofConsent for NativeCheckpointReadConsentV1<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        saved_scope_read_matches(self.scope, scope, action) && self.check().is_ok()
    }
}
fn saved_scope_read_matches(
    saved: &CheckpointScope,
    actual: &CheckpointScope,
    action: LocalAction,
) -> bool {
    saved == actual
        && matches!(
            action,
            LocalAction::InspectStatus | LocalAction::ReadPrivateArtifact
        )
}
fn check_source(
    host: &Host,
    committed: &ManualCommittedTarget<'_>,
    actual: &ManualHostGenerationBinding,
    checkpoint_destination: &str,
) -> Result<()> {
    host.require_manual_session()?;
    committed.check_current()?;
    committed.coverage().require_complete()?;
    let primary = host.financial.as_ref().ok_or(Error::Locked)?;
    primary.check_current_journals()?;
    let origin = primary.manual_original_primary_origin_digest(&host.directory, &host.secrets)?;
    if actual.generation_id != committed.generation_id()
        || actual.inventory_digest != committed.inventory_digest()
        || actual.generation_plan_digest != committed.plan_digest()
        || actual.profile_id != committed.profile_id()
        || actual.canonical_root != committed.canonical_root()
        || actual.destination_identity_digest != committed.destination_identity_digest()
        || actual.financial_journal_origin_digest != origin
        || actual.inherited_identity_digest != committed.coverage().digest()?
        || actual.scope_predecessor_digest.is_some()
        || checkpoint_destination != committed.canonical_root()
    {
        return Err(Error::Authentication);
    }
    committed.check_current()
}
fn derive_origin(
    original: &BornOfflineCheckpointOriginalV1<'_>,
    account_id: &str,
    peer: &TransportPublicKey,
    sender: &TransportPublicKey,
) -> Result<BornOfflineCheckpointOriginV1> {
    let selected: Vec<_> = original
        .claim()
        .consumed
        .iter()
        .filter(|a| a.request.plan.enrollment().identity.account_id == account_id)
        .collect();
    if selected.len() != 1 {
        return Err(Error::Authentication);
    }
    let a = selected[0];
    let p = &a.request.plan;
    let e = p.enrollment();
    let r = original.receipt();
    let summary = original.checkpoint().summary();
    // This actual saved owner rejects legacy/missing provenance before any
    // private proof access. Carry its exact immutable historical record, never
    // manufacture observation time from this export's current wall clock.
    let provenance = original.historical_provenance()?.clone();
    let origin = BornOfflineCheckpointOriginV1 {
        version: 2,
        historical_provenance: Some(provenance),
        host: e.host.clone(),
        principal_id: original.claim().principal_id.clone(),
        construction_key: original.claim().construction_key.clone(),
        claim_digest: original.claim().digest()?,
        checkpoint_receipt_digest: wholepact_store::request_digest(&serde_json::to_value(r)?)?,
        job_id: r.job_id.clone(),
        scope_digest: r.scope_digest()?,
        input_artifact_digest: r.scope.artifact_digest.clone(),
        proved_artifact_digest: summary.result_digest.clone().ok_or(Error::Authentication)?,
        coordination_request_digest: r.scope.coordination_request_digest.clone(),
        network_profile_id: e.identity.network_profile_id.clone(),
        agreement_id: e.scope.agreement_id.clone(),
        proposal_id: original.proposal().input().proposal_id.clone(),
        proposal_revision: p.common_context.candidate_revision,
        proposal_digest: original.proposal().proposal_digest().into(),
        manifest_digest: original.proposal().manifest_digest().into(),
        effects_commitment: r.scope.effects_commitment.clone(),
        review_binding: r.scope.review_binding.clone(),
        account_id: e.identity.account_id.clone(),
        full_viewing_key_digest: e.identity.full_viewing_key_digest.clone(),
        signer_key_digest: peer.fingerprint(),
        host_return_key_digest: sender.fingerprint(),
        construction: BornOfflineCheckpointConstructionV1 {
            version: 1,
            reservation_operation_id: a.request.operation_id.clone(),
            reservation_digest: a.witness_reservation_digest.clone(),
            consume_operation_id: format!(
                "roster-construct-consume-v3-{}",
                a.witness_reservation_digest
            ),
            consume_digest: a.witness_consumed_digest.clone(),
            plan_digest: p.digest().map_err(|_| Error::Authentication)?,
            common_context_digest: p.common_context_digest.clone(),
            invocation_digest: p.invocation_digest().map_err(|_| Error::Authentication)?,
        },
    };
    origin.validate().map_err(|_| Error::Authentication)?;
    Ok(origin)
}
fn live_outbox_identity(host: &Host) -> Result<DatabaseFileIdentity> {
    host.transport
        .lock()
        .map_err(|_| Error::Locked)?
        .original_outbox_identity()
        .map_err(Error::from)
}
fn nominal_key(key: &TransportPublicKey) -> Result<codec::TransportPublicKey> {
    codec::TransportPublicKey::from_bytes(*key.as_bytes()).map_err(codec_error)
}
fn codec_error(_: codec::TransportError) -> Error {
    Error::Authentication
}
fn wall_ms() -> Result<u64> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Invalid)?
            .as_millis(),
    )
    .map_err(|_| Error::Invalid)
}
fn check_destination(host: &Host, path: &Path) -> Result<()> {
    host.directory.external_destination(path)?;
    if path.starts_with(
        host.financial
            .as_ref()
            .ok_or(Error::Locked)?
            .current_directory()?,
    ) {
        return Err(Error::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> CheckpointScope {
        CheckpointScope {
            principal_id: "synthetic-principal".into(),
            candidate_id: "synthetic-candidate".into(),
            manifest_digest: "a".repeat(64),
            artifact_digest: "b".repeat(64),
            effects_commitment: "c".repeat(64),
            coordination_request_digest: "d".repeat(64),
            review_binding: "e".repeat(64),
            account_ids: vec!["synthetic-account".into()],
            local_operator: "synthetic-host".into(),
            purpose: "construct_one_candidate".into(),
            retention_policy: "synthetic-private-retention".into(),
        }
    }
    #[test]
    fn exact_original_scope_never_admits_construction_or_worker_recovery() {
        let original = scope();
        assert!(saved_scope_read_matches(
            &original,
            &original,
            LocalAction::InspectStatus
        ));
        assert!(saved_scope_read_matches(
            &original,
            &original,
            LocalAction::ReadPrivateArtifact
        ));
        for action in [
            LocalAction::RetainPrivateWitnesses,
            LocalAction::ProveLocally,
            LocalAction::RecoverInterrupted,
        ] {
            assert!(!saved_scope_read_matches(&original, &original, action));
        }
        let mut changed = original.clone();
        changed.artifact_digest = "f".repeat(64);
        assert!(!saved_scope_read_matches(
            &original,
            &changed,
            LocalAction::ReadPrivateArtifact
        ));
        let mut changed = original.clone();
        changed.account_ids.push("other-account".into());
        assert!(!saved_scope_read_matches(
            &original,
            &changed,
            LocalAction::InspectStatus
        ));
        let mut changed = original.clone();
        changed.purpose = "construct_a_replacement".into();
        assert!(!saved_scope_read_matches(
            &original,
            &changed,
            LocalAction::ReadPrivateArtifact
        ));
    }
}
