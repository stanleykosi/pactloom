//! Genuine native, purpose-distinct durable construction disclosure. A decision
//! is consumed locally and the immutable consent/outbox commits before export.
//! Closing this native UI does not revoke already copied privacy-sensitive data.
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::authority_bridge::{
    self, BridgeError,
    durable_construction_v1::{
        DurableConstructionHistoryRequestV1, DurableConstructionOutboxV1,
        DurableConstructionRedisclosureLinkV1, DurableConstructionRedisclosureRequestV1,
        DurableConstructionRequestV1, DurableConstructionResponseV1,
    },
};
use crate::{
    Error, Result,
    account::AccountVault,
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::ReviewMismatch)
}
fn error(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}

fn write_bounded(
    stream: &mut UnixStream,
    outbox: DurableConstructionOutboxV1,
    deadline: Instant,
    source: &NativeAuthorityBinding,
    peer: &AuthenticatedPeer,
    check_record: impl Fn() -> authority_bridge::Result<()>,
) -> authority_bridge::Result<()> {
    let value = DurableConstructionResponseV1::Retained {
        outbox: Box::new(outbox),
    };
    let mut raw = Zeroizing::new(serde_json::to_vec(&value).map_err(|_| BridgeError::Binding)?);
    if raw.len() > 128 * 1024 {
        return Err(BridgeError::Limit);
    }
    raw.push(b'\n');
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(BridgeError::Permission)
    };
    let mut offset = 0;
    while offset < raw.len() {
        source
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        peer.check_current().map_err(|_| BridgeError::Permission)?;
        check_record()?;
        stream
            .set_write_timeout(Some(remaining()?.min(Duration::from_secs(2))))
            .map_err(|_| BridgeError::Ipc)?;
        let publication = source
            .publication_lease()
            .map_err(|_| BridgeError::Permission)?;
        peer.check_current().map_err(|_| BridgeError::Permission)?;
        remaining()?;
        let count = stream.write(&raw[offset..]).map_err(|_| BridgeError::Ipc)?;
        drop(publication);
        source
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        peer.check_current().map_err(|_| BridgeError::Permission)?;
        check_record()?;
        remaining()?;
        if count == 0 {
            return Err(BridgeError::Ipc);
        }
        offset += count;
    }
    remaining()?;
    Ok(())
}

pub(super) struct PreparedDurableConstructionV1 {
    request: DurableConstructionRequestV1,
    redisclosure: Option<DurableConstructionRedisclosureLinkV1>,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
    started: Instant,
}
/// No public constructor and no deserialization. Only consuming the real native
/// decision for this exact prepared view can produce this journal append input.
pub(crate) struct ApprovedDurableConstructionV1 {
    prepared: PreparedDurableConstructionV1,
    decision: NativeDecision,
}
fn validate_peer(
    request: &DurableConstructionRequestV1,
    peer: &AuthenticatedPeer,
) -> authority_bridge::Result<()> {
    let proposal = request.validate()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    if !peer.scope.preconstruction_export
        || peer.scope.account_id != request.scope.account_id
        || peer.scope.participant_id != request.scope.participant_id
        || peer.scope.agreement_id != proposal.manifest().agreement.agreement_id
        || peer.scope.manifest_digest != proposal.manifest_digest()
        || request.scope.constructor.authenticated_local_grant_digest != peer.key_digest
        || request.scope.prover.authenticated_local_grant_digest != peer.key_digest
    {
        return Err(BridgeError::Permission);
    }
    Ok(())
}
fn validate_original(
    request: &DurableConstructionRequestV1,
    lease: &crate::consent_journal::PreconstructionRecordLease<'_>,
) -> authority_bridge::Result<()> {
    let proposal = request.validate()?;
    if lease.sponsor_required()
        || lease.sponsor_policy().is_some()
        || lease.enrollment().account_id() != request.scope.account_id
        || lease.enrollment().participant_id() != request.scope.participant_id
        || lease.enrollment().agreement_id() != proposal.manifest().agreement.agreement_id
        || lease.enrollment().account_fvk_digest() != request.material.fvk_digest()
        || lease.manifest().proposal_input() != &request.scope.proposal
        || lease.manifest().enrollment_ref() != request.enrollment_ref
    {
        return Err(BridgeError::Binding);
    }
    lease.check_current()?;
    Ok(())
}
impl PreparedDurableConstructionV1 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        request: DurableConstructionRequestV1,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        authority: &NativeAuthorityBinding,
        vault: &AccountVault,
    ) -> Result<Self> {
        Self::prepare_internal(
            request, None, peer, stream, journal, session, authority, vault,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_redisclosure(
        request: DurableConstructionRedisclosureRequestV1,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        authority: &NativeAuthorityBinding,
        vault: &AccountVault,
    ) -> Result<Self> {
        request.validate().map_err(error)?;
        peer.check_current()?;
        authority.check_current()?;
        if !peer.scope.history_read || !peer.scope.preconstruction_export {
            return Err(Error::ReviewMismatch);
        }
        // Read only inside the signer under a current native session. No old
        // material or prior consent is exported before this NEW exact decision.
        let original = journal
            .durable_construction_history_v1(&request.original, session)
            .map_err(error)?;
        if original.redisclosure().is_some() {
            return Err(Error::ReviewMismatch);
        }
        let link = DurableConstructionRedisclosureLinkV1 {
            original_operation_id: original.request().operation_id.clone(),
            original_request_digest: original.request_digest().into(),
            original_outbox_reference: original.reference().into(),
        };
        let mut next = original.request().clone();
        next.operation_id = request.operation_id;
        next.scope.constructor.authenticated_local_grant_digest = peer.key_digest.clone();
        next.scope.prover.authenticated_local_grant_digest = peer.key_digest.clone();
        let prepared = Self::prepare_internal(
            next,
            Some(link),
            peer,
            stream,
            journal,
            session,
            authority,
            vault,
        )?;
        prepared
            .outbox_data()
            .map_err(error)?
            .validate_redisclosure_of(&original)
            .map_err(error)?;
        Ok(prepared)
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_internal(
        request: DurableConstructionRequestV1,
        redisclosure: Option<DurableConstructionRedisclosureLinkV1>,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        authority: &NativeAuthorityBinding,
        vault: &AccountVault,
    ) -> Result<Self> {
        authority.check_current()?;
        validate_peer(&request, &peer).map_err(error)?;
        request.scope.check_valid_at(now()?).map_err(error)?;
        if &peer.native_origin != authority
            || vault.account().recovery_required()
            || vault.account_id()? != request.scope.account_id
            || vault.account().privacy_domain() != request.scope.privacy_domain
        {
            return Err(Error::ReviewMismatch);
        }
        // Mathematical checks independently use this actual unlocked account.
        // Host-supplied FVK fingerprints and note ownership are never authority.
        request
            .material
            .verify_owner(&vault.account().fvk()?)
            .map_err(error)?;
        let lease = journal
            .acquire_preconstruction_records(
                &request.enrollment_ref,
                &request.accepted_manifest_ref,
                session,
            )
            .map_err(error)?;
        lease.require_native_origin(authority).map_err(error)?;
        validate_original(&request, &lease).map_err(error)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-durable-construction-review:v1",
            &(
                &request.digest().map_err(error)?,
                &redisclosure,
                &peer.key_digest,
                &peer.channel_digest,
                &peer.grant_id,
                crate::vault::random::<32>()?,
            ),
        )
        .map_err(error)?;
        let audience_notice = if request.scope.version == 2 {
            "NEW LOCAL REVIEWER AUDIENCE: You approve sequential disclosure to the exact listed canonical account IDs through their actual installed local signer and fresh account-bound pairing, including after earlier pairings close. Account IDs are cryptographic account identifiers, not people, distinct-person guarantees, or prior peer approvals. Each forwarding still requires current local export consent, exact recipient authentication, and a committed protected export intent. No remote or arbitrary onward recipient is authorized."
        } else {
            "LEGACY EXACT TRANSPORT AUDIENCE: Reviewer fingerprints name only the exact intended transport keys. This local channel does not authenticate those remote keys or people. This scope does NOT authorize local account-scoped forwarding; a new explicit purpose-specific scope is required."
        };
        let redisclosure_notice = redisclosure.as_ref().map(|link| format!(
            "NEW IRREVERSIBLE REDISCLOSURE of original operation {} / outbox {}. This is not replay, restoration, renewal, or extension of the previous recipient grant. Exact original material, manifest, purpose, destination, retention, reviewer audience and validity ceiling remain unchanged. You are approving another copy to the CURRENT authenticated local application.\n\n",
            link.original_operation_id, link.original_outbox_reference
        )).unwrap_or_default();
        // Show the scope and exact material commitment, NOT raw viewing material.
        let display = Zeroizing::new(format!(
            "{}DISCLOSE AND RETAIN EXACT CONSTRUCTION MATERIAL\n\n{}\n\nMaterial commitment: {}\nAccount FVK commitment: {}\nExact historical material review: {}\n\nActual local recipient: {} (PID {}, UID {}, authenticated local grant fingerprint {}). Constructor and prover are this same authenticated local application for THIS grant. This fingerprint is not a persistent public key; a new pairing cannot silently inherit this disclosure recipient. {} Protected destination is exact and must also be checked by the recipient's authenticated encrypted-store intake.\n\nThis NEW purpose permits retention across process closure and fresh bounded public-block reads for these exact inputs and provider until the listed validity limit. It does not renew any V3 permit. Old consumed records remain unchanged.\n\nThe full viewing key reveals this dedicated account's past and future activity. Selected notes, values, nullifiers, witnesses, change ownership, and participant linkages are privacy-sensitive. Disclosure is irreversible. Retention is a recipient commitment, not technical erasure. Provider contact reveals IP, timing and height ranges; it receives no viewing key. A provider snapshot is not independent consensus or proof of unspentness.\n\nNo spending key, native decision, writer credential, executable witness permit or released signature is exported. This reserves no inputs and authorizes no spending, replacement or submission. Later signing requires separate fresh exact transaction review and independent writer/exposure reconciliation.\n\nNative review binding: {}",
            redisclosure_notice,
            serde_json::to_string_pretty(&request.scope).map_err(error)?,
            request.material.digest().map_err(error)?,
            request.material.fvk_digest(),
            serde_json::to_string_pretty(&request.material.review_summary()).map_err(error)?,
            peer.label,
            peer.peer.pid(),
            peer.peer.uid(),
            peer.key_digest,
            audience_notice,
            digest
        ));
        let prepared = Self {
            request,
            redisclosure,
            peer,
            stream,
            source: authority.clone(),
            digest,
            display,
            started: Instant::now(),
        };
        // Preflight the exact serialized response before asking for the native
        // decision. A committed outbox must fit the existing framing ceiling.
        let preview = DurableConstructionResponseV1::Retained {
            outbox: Box::new(prepared.outbox_data().map_err(error)?),
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&preview).map_err(error)?);
        if encoded.len() > 128 * 1024 {
            return Err(Error::ReviewMismatch);
        }
        Ok(prepared)
    }
    // Produces data only; the journal append still accepts exclusively an
    // ApprovedDurableConstructionV1 that owns the exact real native decision.
    fn outbox_data(&self) -> authority_bridge::Result<DurableConstructionOutboxV1> {
        let p = self;
        let mut outbox = DurableConstructionOutboxV1 {
            request: p.request.clone(),
            request_digest: p.request.digest()?,
            material_digest: p
                .request
                .material
                .digest()
                .map_err(|_| BridgeError::Binding)?,
            native_review_digest: p.digest.clone(),
            native_entry_digest: p.source.entry_digest().into(),
            recipient_grant_digest: p.peer.key_digest.clone(),
            original_channel_digest: p.peer.channel_digest.clone(),
            original_grant_id: p.peer.grant_id.clone(),
            recipient_transport: crate::consent_journal::TransportIdentityBinding::LocalProcess {
                transport_identity_id: p.peer.grant_id.clone(),
                channel_key_digest: p.peer.key_digest.clone(),
                channel_binding_digest: p.peer.channel_digest.clone(),
                uid: p.peer.peer.uid(),
                pid: p.peer.peer.pid(),
                process_instance: p.peer.peer.instance().into(),
                signer_generation: p.peer.generation,
                account_id: p.peer.scope.account_id.clone(),
                agreement_id: p.peer.scope.agreement_id.clone(),
                participant_id: p.peer.scope.participant_id.clone(),
                manifest_digest: p.peer.scope.manifest_digest.clone(),
            },
            redisclosure: p.redisclosure.clone(),
            reference: String::new(),
        };
        outbox.reference = outbox.compute_reference()?;
        outbox.validate()?;
        Ok(outbox)
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<ApprovedDurableConstructionV1> {
        self.source.check_current()?;
        authority.check_current()?;
        validate_peer(&self.request, &self.peer).map_err(error)?;
        self.request.scope.check_valid_at(now()?).map_err(error)?;
        if self.source != authority.binding()
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.started.elapsed() >= Duration::from_secs(120)
            || vault.account().recovery_required()
            || vault.account_id()? != self.request.scope.account_id
            || vault.account().privacy_domain() != self.request.scope.privacy_domain
        {
            return Err(Error::ReviewMismatch);
        }
        self.request
            .material
            .verify_owner(&vault.account().fvk()?)
            .map_err(error)?;
        Ok(ApprovedDurableConstructionV1 {
            prepared: self,
            decision,
        })
    }
}
impl ApprovedDurableConstructionV1 {
    pub(crate) fn check_current(&self) -> authority_bridge::Result<()> {
        self.prepared
            .source
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        validate_peer(&self.prepared.request, &self.prepared.peer)?;
        self.prepared
            .request
            .scope
            .check_valid_at(now().map_err(|_| BridgeError::Permission)?)
            .map_err(|_| BridgeError::Permission)?;
        if self.prepared.started.elapsed() >= Duration::from_secs(120)
            || self.decision.binding() != &self.prepared.source
            || self.decision.reviewed_digest() != self.prepared.digest
        {
            return Err(BridgeError::Permission);
        }
        Ok(())
    }
    pub(crate) fn source(&self) -> &NativeAuthorityBinding {
        &self.prepared.source
    }
    pub(crate) fn request(&self) -> &DurableConstructionRequestV1 {
        &self.prepared.request
    }
    pub(crate) fn historical_outbox(
        &self,
    ) -> authority_bridge::Result<DurableConstructionOutboxV1> {
        self.check_current()?;
        self.prepared.outbox_data()
    }

    pub(super) fn serve(
        mut self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
    ) -> authority_bridge::Result<()> {
        let lease = journal.acquire_preconstruction_records(
            &self.prepared.request.enrollment_ref,
            &self.prepared.request.accepted_manifest_ref,
            session,
        )?;
        lease.require_native_origin(&self.prepared.source)?;
        validate_original(&self.prepared.request, &lease)?;
        // Commit is fenced against lock. Export holds that fence only across
        // each bounded syscall, never across the entire possibly slow delivery.
        let outbox = {
            let _publication = self
                .prepared
                .source
                .publication_lease()
                .map_err(|_| BridgeError::Permission)?;
            journal.record_durable_construction_v1(&self, &lease)?
        };
        self.check_current()?;
        let deadline =
            (self.prepared.started + Duration::from_secs(120)).min(self.prepared.peer.deadline());
        let p = &mut self.prepared;
        write_bounded(&mut p.stream, outbox, deadline, &p.source, &p.peer, || {
            lease.check_current()?;
            p.request
                .scope
                .check_valid_at(now().map_err(|_| BridgeError::Permission)?)
                .map_err(|_| BridgeError::Permission)
        })
    }
}
pub(super) fn serve_durable_construction_history_v1(
    mut stream: UnixStream,
    peer: AuthenticatedPeer,
    request: DurableConstructionHistoryRequestV1,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
) -> authority_bridge::Result<()> {
    request.validate()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    if !peer.scope.history_read || !peer.scope.preconstruction_export {
        return Err(BridgeError::Permission);
    }
    // Read only. This path never creates a decision or a new outbox record.
    let outbox = journal.durable_construction_history_v1(&request, session)?;
    validate_peer(outbox.request(), &peer)?;
    if !authority_bridge::ipc::exact_local_recipient(outbox.recipient_transport(), &peer) {
        return Err(BridgeError::Permission);
    }
    let lease = journal.acquire_preconstruction_records(
        &outbox.request().enrollment_ref,
        &outbox.request().accepted_manifest_ref,
        session,
    )?;
    lease.require_native_origin(&peer.native_origin)?;
    validate_original(outbox.request(), &lease)?;
    let deadline = (Instant::now() + Duration::from_secs(30)).min(peer.deadline());
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    lease.check_current()?;
    write_bounded(
        &mut stream,
        outbox,
        deadline,
        &peer.native_origin,
        &peer,
        || {
            lease.check_current()?;
            Ok(())
        },
    )
}
