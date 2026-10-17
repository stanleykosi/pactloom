//! Concrete protected Host born return intake and exact full-original merge.
//! Receipt persistence precedes deterministic merge; missing or interrupted state
//! never means no signatures exist. No legacy association or dispatch is minted.
#[path = "born_offline_dispatch_owner_v1.rs"]
mod dispatch;
use super::{
    Host,
    born_offline_checkpoint_carrier_v1::{RetainedBornOfflineCheckpointCarrierV1, codec},
    born_offline_return_validation_v1::{self, VerifiedBornReturnV1},
};
use crate::{
    Error, Result,
    authority::{Held, retention::NativeRetentionConsent},
    now,
    vault::JOURNALS,
};
use codec::ReplayLedger;
use std::{cell::RefCell, collections::BTreeSet};
use wholepact_authority::born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1;
use wholepact_engine::born_offline_checkpoint_original_v1::BornOfflineCheckpointOriginalV1;
use wholepact_protocol::{
    authorization::{
        ExternalSignature,
        retention::{
            SignedCandidateContext, SignedRetentionConsent, SignedRetentionScope,
            transaction::{
                LocalTransactionCheckpoint, TransactionRetentionConsent, TransactionRetentionScope,
                submission_handoff::VerifiedRetainedSubmission,
            },
        },
    },
    proving::ProvingLimits,
};
use wholepact_service::protected_transport::{
    LocalTransportKeyController, TransportDirection, TransportKeyScope,
};
use wholepact_signer::authority_bridge::born_history_ipc::BornOriginalHistoryLeaseV1;
use wholepact_storage_security::DatabaseFileIdentity;
use zeroize::Zeroize;

pub(in crate::host) struct RetainedBornReturnV1<'read, 'owner, 'host> {
    host: &'host Host,
    source: &'read RetainedBornOfflineCheckpointCarrierV1<'owner, 'host>,
    history: &'read BornOriginalHistoryLeaseV1<'owner>,
    verified: VerifiedBornReturnV1,
    receipt: codec::AuthenticatedReceipt,
    envelope: codec::EncryptedEnvelope,
    inbox: codec::SqliteReplayLedger,
    inbox_identity: DatabaseFileIdentity,
    held: Held,
}
impl Host {
    /// Only the actual native checkpoint-outbox owner supplies expected origin.
    /// The file contributes authenticated signatures, never expected policy.
    pub(in crate::host) fn retain_born_return_v1<'read, 'owner, 'host>(
        &'host self,
        source: &'read RetainedBornOfflineCheckpointCarrierV1<'owner, 'host>,
        history: &'read BornOriginalHistoryLeaseV1<'owner>,
        bytes: Vec<u8>,
    ) -> Result<RetainedBornReturnV1<'read, 'owner, 'host>> {
        source.check_current()?;
        if !source.belongs_to(self) {
            return Err(Error::Authentication);
        }
        let origin = source.origin();
        history.check_current().map_err(|_| Error::Permission)?;
        let disclosure = &history.evidence().witness;
        if disclosure.account_id != origin.account_id
            || disclosure.network_profile_id != origin.network_profile_id
        {
            return Err(Error::Authentication);
        }
        let envelope = codec::EncryptedEnvelope::from_bytes(bytes).map_err(codec_error)?;
        let cipher_digest = digest_bytes(envelope.as_bytes());
        self.terminal.confirm(&format!("Authenticate and retain this exact born signature return in the existing encrypted Host inbox, then independently verify its signature-only delta against the ORIGINAL completed proof and full private policy. This reads private original proof/account/viewing data already approved for the actual checkpoint, decrypts own signatures, and uses the installed signer's held native-reviewed authenticated complete witness-history lease. The Host never receives the signer's writer credential or session key. No spending key is read, no new signature is made, and no transaction is submitted. The inbox may retain ciphertext indefinitely. This separate native private-return use permission lasts at most15 minutes, ends on lock/revoke/foreground loss, and does not renew original signing, packet, session or current-input authority. A committed inbox receipt survives later merge failure; recover only these original bytes. Historical packet expiry never becomes fresh authority.\nAccount: {}\nOriginal completed checkpoint: {}\nOriginal checkpoint ciphertext: {}\nReturn ciphertext: {}\nPinned witness disclosure: {}\nSeparate native usable-signature/transaction retention and fresh current-input/witness/backend approval are required before dispatch.",origin.account_id,origin.digest().map_err(|_|Error::Authentication)?,source.ciphertext_digest(),cipher_digest,serde_json::to_string_pretty(&disclosure)?))?;
        let held = self
            .authority
            .fence
            .acquire(now()?.checked_add(900).ok_or(Error::Invalid)?)?;
        source.check_current()?;
        held.check()?;
        let context = wholepact_transport::MessageContext {
            network_profile_id: origin.network_profile_id.clone(),
            agreement_id: origin.agreement_id.clone(),
            proposal_id: origin.proposal_id.clone(),
            proposal_revision: origin.proposal_revision,
            sender_id: format!("born-offline-return:{}", origin.signer_key_digest),
            recipient_id: format!("born-offline-return:{}", origin.host_return_key_digest),
            artifact_kind: wholepact_transport::ArtifactKind::BornOfflineAuthorizationReturnV1,
        };
        let keys = self.authority.keys(&TransportKeyScope {
            principal_id: origin.principal_id.clone(),
            context: context.clone(),
            direction: TransportDirection::Incoming,
        })?;
        if keys.pinned_peer.fingerprint() != origin.signer_key_digest
            || keys.local_secret.public_key()?.fingerprint() != origin.host_return_key_digest
        {
            return Err(Error::Authentication);
        }
        let recipient = codec::TransportSecret::from_bytes(*self.secrets.transport_material()?)
            .map_err(codec_error)?;
        let sender = codec::TransportPublicKey::from_bytes(*keys.pinned_peer.as_bytes())
            .map_err(codec_error)?;
        let context = serde_json::from_slice(&serde_json::to_vec(&context)?)?;
        let (artifact, receipt) =
            codec::authenticate_born_return(&envelope, &recipient, &sender, &context)
                .map_err(codec_error)?;
        let verified = born_offline_return_validation_v1::inspect(source, history, &artifact)?;
        if history
            .evidence()
            .account_policy
            .account_use_genesis
            .as_ref()
            .is_none_or(|g| {
                g.identity.account_id != origin.account_id
                    || g.identity.full_viewing_key_digest != origin.full_viewing_key_digest
            })
        {
            return Err(Error::Authentication);
        }
        history.check_current().map_err(|_| Error::Permission)?;
        source.check_current()?;
        held.check()?;
        let inbox_identity = live_inbox_identity(self)?;
        let connection = wholepact_storage_security::open_encrypted(
            self.directory.path(JOURNALS[1])?,
            &self.secrets.key(1)?,
        )?;
        if connection.database_identity()? != inbox_identity {
            return Err(Error::Authentication);
        }
        let mut inbox = codec::SqliteReplayLedger::from_encrypted_connection(connection)
            .map_err(codec_error)?;
        if inbox.database_identity().map_err(codec_error)? != inbox_identity {
            return Err(Error::Authentication);
        }
        match inbox
            .retained_envelope(receipt.stream_digest(), receipt.sequence())
            .map_err(codec_error)?
        {
            Some(prior)
                if prior.matches(&receipt) && prior.envelope.as_bytes() == envelope.as_bytes() => {}
            Some(_) => return Err(Error::Authentication),
            None => {
                source.check_current()?;
                held.check()?;
                inbox
                    .accept_authenticated(&receipt, envelope.as_bytes())
                    .map_err(|_| born_retention_uncertain())?;
            }
        }
        let retained = RetainedBornReturnV1 {
            host: self,
            source,
            history,
            verified,
            receipt,
            envelope,
            inbox,
            inbox_identity,
            held,
        };
        // A failure here has an uncertain retained outcome, never reseal/re-sign.
        retained
            .check_current()
            .map_err(|_| born_retention_uncertain())?;
        Ok(retained)
    }
}
impl RetainedBornReturnV1<'_, '_, '_> {
    pub(in crate::host) fn admission(&self) -> &BornOfflineAuthorizationAdmissionV1 {
        &self.verified.admission
    }
    pub(in crate::host) fn check_current(&self) -> Result<()> {
        self.check_current_until(self.source.deadline())
    }
    pub(in crate::host) fn check_current_until(&self, deadline: std::time::Instant) -> Result<()> {
        if std::time::Instant::now() >= deadline {
            return Err(Error::Permission);
        }
        self.source.check_current()?;
        self.history
            .check_current_until(deadline)
            .map_err(|_| Error::Permission)?;
        self.held.check()?;
        if live_inbox_identity(self.host)? != self.inbox_identity
            || self.inbox.database_identity().map_err(codec_error)? != self.inbox_identity
        {
            return Err(Error::Authentication);
        }
        let retained = self
            .inbox
            .retained_envelope(self.receipt.stream_digest(), self.receipt.sequence())
            .map_err(codec_error)?
            .ok_or(Error::Authentication)?;
        if !retained.matches(&self.receipt)
            || retained.envelope.as_bytes() != self.envelope.as_bytes()
        {
            return Err(Error::Authentication);
        }
        self.source.check_current()?;
        self.history
            .check_current_until(deadline)
            .map_err(|_| Error::Permission)?;
        self.held.check()
    }
    fn provenance(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
        "family":"born-offline-authorization-return-v1","checkpoint":self.source.origin().digest().map_err(|_|Error::Authentication)?,"checkpoint_ciphertext":self.source.ciphertext_digest(),"admission":self.admission().admission_digest().map_err(|_|Error::Authentication)?,"envelope":self.receipt.envelope_digest(),"stream":self.receipt.stream_digest(),"sequence":self.receipt.sequence(),"content":self.receipt.content_digest(),"payload":self.verified.payload_digest,"signer_origin_identifier":self.verified.origin_identifier,"signer_consent_identifier":self.verified.consent_identifier,"signed_canonical":self.verified.signed_canonical_digest}))
    }
}

/// Existing completed transaction, not permission to dispatch. All predecessors
/// remain borrowed actual owners. Only this module's exact full-roster path can
/// construct it; no raw descriptor, online association or deserialization exists.
pub(in crate::host) struct RetainedBornMergedTransactionV1<'read, 'owner, 'host> {
    host: &'host Host,
    returns: &'read [RetainedBornReturnV1<'read, 'owner, 'host>],
    context: SignedCandidateContext,
    signature_key: String,
    submission_operation_id: String,
    signatures: Vec<ExternalSignature>,
    native: NativeRetentionConsent,
    signed_scope: SignedRetentionScope,
    verified: VerifiedRetainedSubmission,
}
impl Drop for RetainedBornMergedTransactionV1<'_, '_, '_> {
    fn drop(&mut self) {
        for s in &mut self.signatures {
            s.signature.zeroize();
        }
    }
}
impl Host {
    pub(in crate::host) fn merge_born_returns_v1<'read, 'owner, 'host>(
        &'host self,
        returns: &'read [RetainedBornReturnV1<'read, 'owner, 'host>],
        submission_operation_id: &str,
    ) -> Result<RetainedBornMergedTransactionV1<'read, 'owner, 'host>> {
        if !(2..=8).contains(&returns.len()) {
            return Err(Error::Invalid);
        }
        crate::id(submission_operation_id)?;
        let first = &returns[0];
        let original = first.source.original();
        let checkpoint = original.checkpoint();
        let accounts: BTreeSet<_> = checkpoint
            .policy()
            .participants
            .iter()
            .map(|p| p.account_id.clone())
            .collect();
        let mut seen = BTreeSet::new();
        let mut provenance = Vec::new();
        let mut signatures = Vec::new();
        for item in returns {
            item.check_current()?;
            if !std::ptr::eq(self, item.host)
                || item.source.origin().claim_digest != first.source.origin().claim_digest
                || item.source.origin().proved_artifact_digest
                    != first.source.origin().proved_artifact_digest
                || item.source.origin().scope_digest != first.source.origin().scope_digest
                || item.source.original().checkpoint().pczt_bytes() != checkpoint.pczt_bytes()
                || !seen.insert(item.source.origin().account_id.clone())
            {
                return Err(Error::Authentication);
            }
            provenance.push((item.source.origin().account_id.clone(), item.provenance()?));
            signatures.extend(item.verified.signatures.iter().map(|s| ExternalSignature {
                participant_index: s.participant_index,
                action_index: s.action_index,
                signature: s.signature,
            }));
        }
        if seen != accounts {
            return Err(Error::Authentication);
        }
        provenance.sort_by(|a, b| a.0.cmp(&b.0));
        signatures.sort_by_key(|s| s.action_index);
        let provenance_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:born-return-complete-roster-provenance:v1",
            &provenance,
        )
        .map_err(|_| Error::Invalid)?;
        let scope = checkpoint.scope();
        let context = SignedCandidateContext {
            principal_id: scope.principal_id.clone(),
            candidate_id: scope.candidate_id.clone(),
            proof_job_id: checkpoint.summary().job_id.clone(),
            checkpoint_scope_digest: checkpoint.summary().scope_digest.clone(),
            proved_artifact_digest: first.source.origin().proved_artifact_digest.clone(),
            manifest_digest: scope.manifest_digest.clone(),
            review_binding: scope.review_binding.clone(),
            delivery_provenance_digest: provenance_digest.clone(),
            account_ids: scope.account_ids.clone(),
            local_operator: scope.local_operator.clone(),
            purpose: "retain_exact_born_offline_return_set_v1".into(),
            retention_policy: scope.retention_policy.clone(),
        };
        let signature_key = format!("born-return-{provenance_digest}");
        let native = self.authority.retention_consent(
            &context.principal_id,
            &context.candidate_id,
            &context.manifest_digest,
            &context.proof_job_id,
            accounts,
        )?;
        let gate = BoundRetention {
            returns,
            native: &native,
            context: &context,
            signed_scope: RefCell::new(None),
        };
        let financial = self.financial.as_ref().ok_or(Error::Locked)?;
        financial.check_current_journals()?;
        let limits = ProvingLimits {
            maximum_actions: original.claim().maximum_actions,
        };
        let summary = financial
            .signed
            .retain(
                context.clone(),
                &signature_key,
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                &signatures,
                limits,
                &gate,
            )
            .map_err(|_| born_retention_uncertain())?;
        if !summary.inspection.signatures_complete || !summary.inspection.exact_candidate_preserved
        {
            return Err(born_retention_uncertain());
        }
        financial
            .signed
            .checkpoint_transaction(
                context.clone(),
                &signature_key,
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                &signatures,
                limits,
                &gate,
                LocalTransactionCheckpoint {
                    journal: &financial.transactions,
                    consent: &gate,
                },
            )
            .map_err(|_| born_retention_uncertain())?;
        let proposal = original.proposal();
        let verified = financial
            .signed
            .verify_retained_submission(
                context.clone(),
                &signature_key,
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                &signatures,
                limits,
                &gate,
                &proposal.manifest().agreement.obligation_id,
                &proposal.input().proposal_id,
                submission_operation_id,
                &LocalTransactionCheckpoint {
                    journal: &financial.transactions,
                    consent: &gate,
                },
            )
            .map_err(|_| born_retention_uncertain())?;
        let signed_scope = gate
            .signed_scope
            .into_inner()
            .ok_or_else(born_retention_uncertain)?;
        let result = RetainedBornMergedTransactionV1 {
            host: self,
            returns,
            context,
            signature_key,
            submission_operation_id: submission_operation_id.into(),
            signatures,
            native,
            signed_scope,
            verified,
        };
        result
            .check_current()
            .map_err(|_| born_retention_uncertain())?;
        Ok(result)
    }
}
impl RetainedBornMergedTransactionV1<'_, '_, '_> {
    pub(in crate::host) fn verified_submission(&self) -> &VerifiedRetainedSubmission {
        &self.verified
    }
    pub(in crate::host) fn original(&self) -> &BornOfflineCheckpointOriginalV1<'_> {
        self.returns[0].source.original()
    }
    pub(in crate::host) fn admissions(
        &self,
    ) -> impl Iterator<Item = &BornOfflineAuthorizationAdmissionV1> {
        self.returns.iter().map(|r| r.admission())
    }
    pub(in crate::host) fn check_current(&self) -> Result<()> {
        self.check_current_until(
            self.returns
                .iter()
                .map(|item| item.source.deadline())
                .min()
                .ok_or(Error::Authentication)?,
        )
    }
    pub(in crate::host) fn check_current_until(&self, deadline: std::time::Instant) -> Result<()> {
        for item in self.returns {
            item.check_current_until(deadline)?;
        }
        self.original().check_current(self.host.access()?)?;
        self.host
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .check_current_journals()?;
        if !SignedRetentionConsent::permits(&self.native, &self.signed_scope)
            || serde_json::to_vec(self.verified.context())? != serde_json::to_vec(&self.context)?
            || std::time::Instant::now() >= deadline
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
}
struct BoundRetention<'a, 'read, 'owner, 'host> {
    returns: &'a [RetainedBornReturnV1<'read, 'owner, 'host>],
    native: &'a NativeRetentionConsent,
    context: &'a SignedCandidateContext,
    signed_scope: RefCell<Option<SignedRetentionScope>>,
}
impl SignedRetentionConsent for BoundRetention<'_, '_, '_, '_> {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        let current = || self.returns.iter().all(|r| r.check_current().is_ok());
        if !current()
            || serde_json::to_vec(&scope.context).ok() != serde_json::to_vec(self.context).ok()
            || !SignedRetentionConsent::permits(self.native, scope)
            || !current()
        {
            return false;
        }
        let mut saved = self.signed_scope.borrow_mut();
        if let Some(old) = saved.as_ref() {
            return old.signature_set_digest == scope.signature_set_digest;
        }
        *saved = Some(SignedRetentionScope {
            context: scope.context.clone(),
            signature_set_digest: scope.signature_set_digest.clone(),
        });
        true
    }
}
impl TransactionRetentionConsent for BoundRetention<'_, '_, '_, '_> {
    fn permits(&self, scope: &TransactionRetentionScope) -> bool {
        SignedRetentionConsent::permits(self, &scope.signed_scope)
            && TransactionRetentionConsent::permits(self.native, scope)
            && self.returns.iter().all(|r| r.check_current().is_ok())
    }
}
fn live_inbox_identity(host: &Host) -> Result<DatabaseFileIdentity> {
    host.transport
        .lock()
        .map_err(|_| Error::Locked)?
        .original_inbox_identity()
        .map_err(Error::from)
}
fn codec_error(_: codec::TransportError) -> Error {
    Error::Authentication
}
fn digest_bytes(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn born_retention_uncertain() -> Error {
    Error::Receipt("exact born ciphertext, signature or transaction retention may have committed; preserve original journals and bytes; no submission is performed by this retention step".into())
}
