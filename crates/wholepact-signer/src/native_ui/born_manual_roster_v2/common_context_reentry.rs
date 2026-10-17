//! One actual fresh unlock, one exact prepared TLS claim, and a separate full
//! proposal decision. No DTO, history, saved signature or callback issues these
//! private owners. Every error consumes the source and closes the live channel.
use super::super::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority};
use super::common_context_handoff::PinnedOwnerSigner;
use crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::FreshCommonContextReentrySource;
use crate::consent_journal::{
    CommonContextReentryAuditPhaseV1 as Phase, CommonContextReentrySignerAuditV1 as Row,
};
use crate::{Error, Result, ipc::AuthenticatedPeer};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    path::PathBuf,
    time::{Duration, Instant},
};
use wholepact_authority::construction_transport_handoff_v1::*;
use wholepact_authority::manual_roster_construction_v3::{
    ManualRosterConstructionConsumeRequestV3, ManualRosterConstructionReservationRequestV3,
    construction_consume_operation_id_v3,
};
use wholepact_authority::transport::{
    ObservedConstructionTransportV1, PreparedConstructionTransportHandoffV1,
};
use wholepact_authority::{
    AuthorityClient, CertificateDer, ClientTls, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use wholepact_core::common_context_reentry_v1::{
    RosterCommonContextReentryLineageV1, RosterCommonContextReentryRequestV1,
};
use wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3;
use wholepact_signer_origin::common_context_reentry_v1::{
    MAX_COMMON_CONTEXT_REENTRY_FRAME, RosterCommonContextReentryResponseV1,
    RosterReenteredConstructionEvidenceV1, RosterReenteredConstructionResponseV1,
};
use wholepact_signer_origin::manual_roster_construction_v3::ManualRosterConstructionContributionEvidenceV3;
use zeroize::Zeroizing;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    trusted_server_root_der: PathBuf,
    writer_certificate_der: PathBuf,
    writer_private_key_pkcs8_der: PathBuf,
    owner_certificate_der: PathBuf,
    owner_private_key_pkcs8_der: PathBuf,
    operator_name: String,
    retention_statement: String,
}
fn canonical<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::InvalidData)
}
fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidData)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::InvalidData)
}
fn connected(stream: &UnixStream, peer: &AuthenticatedPeer) -> Result<()> {
    peer.check_current()?;
    peer.peer
        .same_live_process(&crate::native_peer::PeerProcess::observe(stream)?)
        .map_err(|_| Error::Authentication)
}
fn decision(d: &NativeDecision, native: &NativeAuthorityBinding, digest: &str) -> Result<()> {
    if d.binding() != native || d.reviewed_digest() != digest {
        return Err(Error::ReviewMismatch);
    }
    native.check_current()
}
fn append(source: &FreshCommonContextReentrySource, phase: Phase) -> Result<()> {
    let read = source.original_read();
    source
        .journal()
        .retain_common_context_reentry_audit_v1(&Row {
            version: 1,
            account_id: read.request.plan.enrollment().identity.account_id.clone(),
            invocation_digest: read
                .request
                .plan
                .invocation_digest()
                .map_err(|_| Error::InvalidData)?,
            original_read_admission_digest: read.digest().map_err(|_| Error::InvalidData)?,
            record: phase,
        })
        .map_err(|_| Error::Uncertain)
}
fn send<T: Serialize>(
    stream: &mut UnixStream,
    peer: &AuthenticatedPeer,
    value: &T,
    deadline: Instant,
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::InvalidData)?);
    if bytes.len() >= MAX_COMMON_CONTEXT_REENTRY_FRAME {
        return Err(Error::Unavailable);
    }
    bytes.push(b'\n');
    let deadline = deadline.min(Instant::now() + Duration::from_secs(2));
    let mut offset = 0;
    while offset < bytes.len() {
        check()?;
        connected(stream, peer)?;
        stream.set_write_timeout(Some(
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(Error::Uncertain)?,
        ))?;
        let n = stream.write(&bytes[offset..])?;
        if n == 0 {
            return Err(Error::Uncertain);
        }
        offset += n;
    }
    check()?;
    if Instant::now() >= deadline {
        return Err(Error::Uncertain);
    }
    Ok(())
}

/// First exact privacy decision selects existing pinned credentials and permits
/// contact. Preparation reads local credential files only; no exporter exists.
pub(super) struct PreparedCommonContextWitnessV1 {
    source: FreshCommonContextReentrySource,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    request: RosterCommonContextReentryRequestV1,
    pending: PendingConstructionTransportGrantV1,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    qualification_scope:
        Option<wholepact_authority::native_witness_owner::EphemeralConstructionClientScopeV1>,
    client: AuthorityClient,
    owner_client: AuthorityClient,
    cancellation: wholepact_authority::transport::ConstructionTransportCancellationV1,
    signer: PinnedOwnerSigner,
    native: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedCommonContextWitnessV1 {
    pub(super) fn prepare(
        source: FreshCommonContextReentrySource,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: RosterCommonContextReentryRequestV1,
        pending_json: &str,
        setup_json: &str,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.check_peer(&peer, owner)?;
        connected(&stream, &peer)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        if pending_json.len() > 16 * 1024 || setup_json.len() > 16 * 1024 {
            return Err(Error::InvalidData);
        }
        let pending: PendingConstructionTransportGrantV1 =
            serde_json::from_str(pending_json).map_err(|_| Error::InvalidData)?;
        pending.validate().map_err(|_| Error::InvalidData)?;
        let read = source.original_read();
        if pending.grant.authorization != *source.original_authorization()
            || request.pending_grant_digest != pending.digest().map_err(|_| Error::InvalidData)?
            || request.original_read != read.request
            || request.original_read_admission_digest
                != read.digest().map_err(|_| Error::InvalidData)?
            || request.original_attempt_digest != read.current_attempt_digest
            || request.original_attempt_sequence != read.current_attempt_sequence
            || request.requested_at_ms < pending.grant.granted_at_ms
            || pending.grant.native_review_digest == read.native_review_digest
            || pending.grant.native_review_digest
                == pending
                    .grant
                    .authorization
                    .authorization
                    .native_review_digest
            || request.current_caller_binding_digest
                != wholepact_signer_origin::manual_current_caller_binding_digest(
                    &peer.grant_id,
                    &peer.scope,
                )
                .map_err(|_| Error::InvalidData)?
            || request.admission_expires_at_ms
                > pending.grant.authorization.authorization.expires_at_ms
        {
            return Err(Error::ReviewMismatch);
        }
        let setup: Setup = serde_json::from_str(setup_json).map_err(|_| Error::InvalidData)?;
        for text in [&setup.operator_name, &setup.retention_statement] {
            if text.is_empty()
                || text.len() > 2048
                || text.chars().any(|c| c.is_control() && c != '\n')
            {
                return Err(Error::InvalidData);
            }
        }
        let disclosure = source.retained().disclosure()?;
        let terms = &source.retained().record().account_record.terms;
        let read_credential = super::super::witness_workspace::read_private_credential;
        let root = read_credential(&setup.trusted_server_root_der)?;
        let certificate = read_credential(&setup.writer_certificate_der)?;
        if wholepact_authority::transport::certificate_digest(&CertificateDer::from(
            certificate.as_slice(),
        )) != terms.signer.writer_certificate_digest
        {
            return Err(Error::Authentication);
        }
        let key = read_credential(&setup.writer_private_key_pkcs8_der)?;
        let tls = ClientTls::new(
            disclosure.server_name.clone(),
            disclosure.pinned_server_certificate_digest.clone(),
            vec![CertificateDer::from(root.to_vec())],
            vec![CertificateDer::from(certificate.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .map_err(|_| Error::Authentication)?;
        let client = AuthorityClient::new(
            disclosure
                .endpoint
                .parse()
                .map_err(|_| Error::InvalidData)?,
            tls,
            disclosure.witness_id.clone(),
            disclosure.account_id.clone(),
            disclosure.network_profile_id.clone(),
            disclosure.policy_digest.clone(),
        )
        .map_err(|_| Error::InvalidData)?;
        let owner_certificate = read_credential(&setup.owner_certificate_der)?;
        if wholepact_authority::transport::certificate_digest(&CertificateDer::from(
            owner_certificate.as_slice(),
        )) != terms.signer.owner_certificate_digest
        {
            return Err(Error::Authentication);
        }
        let owner_key = read_credential(&setup.owner_private_key_pkcs8_der)?;
        let owner_tls = ClientTls::new(
            disclosure.server_name.clone(),
            disclosure.pinned_server_certificate_digest.clone(),
            vec![CertificateDer::from(root.to_vec())],
            vec![CertificateDer::from(owner_certificate.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(owner_key.to_vec())),
        )
        .map_err(|_| Error::Authentication)?;
        let owner_client = AuthorityClient::new(
            disclosure
                .endpoint
                .parse()
                .map_err(|_| Error::InvalidData)?,
            owner_tls,
            disclosure.witness_id.clone(),
            disclosure.account_id.clone(),
            disclosure.network_profile_id.clone(),
            disclosure.policy_digest.clone(),
        )
        .map_err(|_| Error::InvalidData)?;
        let signer = PinnedOwnerSigner::open(
            &terms.signer.owner_certificate_digest,
            &setup.owner_certificate_der,
            &setup.owner_private_key_pkcs8_der,
        )?;
        let native = owner.native().binding();
        let revocation = wholepact_authority::transport::ConstructionTransportRevocationV1::new();
        let cancellation = revocation.cancellation_token();
        native.retain_construction_transport_revocation(revocation)?;
        let digest = canonical(
            "wholepact:native-common-context-reentry-witness-contact:v1",
            &(
                &request,
                &pending,
                &setup,
                &disclosure,
                native.entry_digest(),
            ),
        )?;
        let display = Zeroizing::new(format!(
            "CONTACT EXACT ORIGINAL WITNESS FOR ONE EXISTING READ COMPLETION\n{}\n{}\n{}\n\nThis privacy decision contacts only the immutable pinned witness with the original writer identity, retrieves complete current history, and prepares ONE fresh TLS channel. No writer acquisition, renewal, activation or ordinary mutation is allowed. A DIFFERENT exact native review must sign the new actual exporter commitment. Focus loss, cancellation, timeout or uncertainty destroys this source and channel permanently. Original completion expiry: {}.\nExact review: {}",
            serde_json::to_string_pretty(&disclosure).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&setup).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&pending).map_err(|_| Error::InvalidData)?,
            read.request.completion_expires_at_ms,
            digest
        ));
        let value = Self {
            source,
            peer,
            stream,
            request,
            pending,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            qualification_scope: None,
            client,
            owner_client,
            cancellation,
            signer,
            native,
            digest,
            display,
        };
        value.check(owner)?;
        Ok(value)
    }
    /// Only the finite predecessor-owned fixture can supply this concrete
    /// one-use witness scope. It creates no source, peer or native decision.
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn attach_qualification_scope(
        &mut self,
        scope: wholepact_authority::native_witness_owner::EphemeralConstructionClientScopeV1,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        if self.qualification_scope.is_some() {
            return Err(Error::ReviewMismatch);
        }
        scope
            .require_exact_pending(&self.pending)
            .map_err(|_| Error::ReviewMismatch)?;
        // Actual-scope negative: valid inert shape, guaranteed other original.
        // This borrows the scope and cannot consume a grant or open a socket.
        let mut substituted = self.pending.clone();
        substituted.committed_head.digest = if substituted.committed_head.digest == "d0".repeat(32)
        {
            "d1".repeat(32)
        } else {
            "d0".repeat(32)
        };
        substituted.validate().map_err(|_| Error::InvalidData)?;
        if !matches!(
            scope.require_exact_pending(&substituted),
            Err(wholepact_authority::AuthorityError::InvalidBinding)
        ) {
            return Err(Error::ReviewMismatch);
        }
        scope
            .require_exact_pending(&self.pending)
            .map_err(|_| Error::ReviewMismatch)?;
        self.qualification_scope = Some(scope);
        self.check(owner)
    }

    fn prepare_transport(
        &mut self,
        history: wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<PreparedConstructionTransportHandoffV1> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if let Some(scope) = self.qualification_scope.take() {
            scope
                .require_exact_pending(&self.pending)
                .map_err(|_| Error::ReviewMismatch)?;
            return scope
                .prepare(
                    &self.client,
                    history,
                    self.request.current_caller_binding_digest.clone(),
                    self.native.entry_digest().into(),
                    self.source.completion_deadline(),
                    self.source.shared_wall_high_water(),
                    self.cancellation.clone(),
                )
                .map_err(|_| Error::Uncertain);
        }
        // The production and every unscoped route keep their original global
        // refusal. No imported pending grant can select the finite route.
        self.client
            .prepare_construction_transport_handoff_v1(
                history,
                self.pending.clone(),
                self.request.current_caller_binding_digest.clone(),
                self.native.entry_digest().into(),
                self.source.completion_deadline(),
                self.source.shared_wall_high_water(),
                self.cancellation.clone(),
            )
            .map_err(|_| Error::Uncertain)
    }

    pub(super) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn review_json(&self) -> Result<String> {
        self.native.check_current()?;
        self.request
            .remaining_admission_ms(now()?)
            .map_err(|_| Error::ReviewMismatch)?;
        Ok(self.display.to_string())
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.source.check_peer(&self.peer, owner)?;
        connected(&self.stream, &self.peer)?;
        self.review_json()?;
        Ok(())
    }
    pub(super) fn approve(
        mut self,
        d: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedCommonContextClaimV1> {
        self.check(owner)?;
        decision(&d, &self.native, &self.digest)?;
        let history = self
            .client
            .reconcile_history_checked(|| {
                self.source
                    .check_peer(&self.peer, owner)
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        self.check(owner)?;
        self.source
            .require_current_handoff_history(&history, &self.pending)?;
        let prepared = self.prepare_transport(history)?;
        self.check(owner)?;
        let digest = canonical(
            "wholepact:native-common-context-exact-channel-claim:v1",
            &(
                &self.request,
                prepared.unsigned_claim_binding(),
                prepared.review_digest().map_err(|_| Error::InvalidData)?,
                self.native.entry_digest(),
            ),
        )?;
        if digest == self.source.original_read().native_review_digest
            || digest
                == self
                    .pending
                    .grant
                    .authorization
                    .authorization
                    .native_review_digest
            || digest == self.pending.grant.native_review_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let display = Zeroizing::new(format!(
            "CLAIM ONE EXACT NEW CONSTRUCTION TRANSPORT KEY\n{}\n{}\n\nThis NEW owner signature binds the displayed actual TLS exporter commitment and immutable pending-grant POST-APPEND head. It permanently fences the original general transport key and grants only one exact observation and original V3 Reserve/Consume pair. It cannot renew the unchanged original session, acquire general writer authority, sign a transaction, disclose another wallet read, change inputs, reset budget or dispatch. The prepared channel has its ORIGINAL ten-second total budget; review never renews it. The full proposal still needs a separate native decision.\nExact review: {}",
            serde_json::to_string_pretty(prepared.unsigned_claim_binding())
                .map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&self.pending).map_err(|_| Error::InvalidData)?,
            digest
        ));
        Ok(PreparedCommonContextClaimV1 {
            source: self.source,
            peer: self.peer,
            stream: self.stream,
            request: self.request,
            prepared,
            signer: self.signer,
            owner_client: self.owner_client,
            native: self.native,
            digest,
            display,
        })
    }
}

pub(super) struct PreparedCommonContextClaimV1 {
    owner_client: AuthorityClient,
    source: FreshCommonContextReentrySource,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    request: RosterCommonContextReentryRequestV1,
    prepared: PreparedConstructionTransportHandoffV1,
    signer: PinnedOwnerSigner,
    native: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedCommonContextClaimV1 {
    pub(super) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn review_json(&self) -> Result<String> {
        self.native.check_current()?;
        self.prepared
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        self.request
            .remaining_admission_ms(now()?)
            .map_err(|_| Error::ReviewMismatch)?;
        Ok(self.display.to_string())
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.source.check_peer(&self.peer, owner)?;
        connected(&self.stream, &self.peer)?;
        self.review_json()?;
        Ok(())
    }
    pub(super) fn approve_and_serve(
        mut self,
        d: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ReenteredCommonContextOwnerV1> {
        self.check(owner)?;
        decision(&d, &self.native, &self.digest)?;
        let mut claim = self.prepared.unsigned_claim_binding().clone();
        claim.native_review_digest = self.digest.clone();
        let signed = self.signer.sign_claim(claim)?;
        self.check(owner)?;
        append(
            &self.source,
            Phase::Granted {
                grant: Box::new(self.prepared.pending_grant().clone()),
            },
        )?;
        self.check(owner)?;
        let claimed = self.prepared.claim(signed).map_err(|_| Error::Uncertain)?;
        self.source.check_peer(&self.peer, owner)?;
        append(
            &self.source,
            Phase::Claimed {
                credential: Box::new(claimed.credential().clone()),
            },
        )?;
        let observed = claimed.observe().map_err(|_| Error::Uncertain)?;
        self.source.check_peer(&self.peer, owner)?;
        let history = observed
            .history()
            .construction_history_with_transport_v1()
            .map_err(|_| Error::ReviewMismatch)?;
        let credential = observed.credential();
        let a = credential.authorization();
        let birth = history
            .original
            .original_birth()
            .ok_or(Error::ReviewMismatch)?;
        let continuation = observed
            .history()
            .manual_roster_session_continuation_v2(&a.attempt_digest)
            .map_err(|_| Error::ReviewMismatch)?
            .ok_or(Error::ReviewMismatch)?;
        let extension = self.source.retained().record().extension()?;
        if continuation
            .digest_for(&extension)
            .map_err(|_| Error::InvalidData)?
            != a.attempt_digest
            || continuation.sequence() != a.attempt_sequence
        {
            return Err(Error::ReviewMismatch);
        }
        let read = self.source.original_read();
        let lineage = RosterCommonContextReentryLineageV1 {
            version: 1,
            request: self.request,
            retained_signer_intent_digest: read.retained_signer_intent_digest.clone(),
            original_native_binding_digest: a.original_native_binding_digest.clone(),
            current_native_binding_digest: self.native.entry_digest().into(),
            original_host_process_digest: a.original_host_process_commitment.clone(),
            original_record_digest: read
                .request
                .plan
                .retained
                .selection
                .scope
                .provenance
                .signer_roster_record_digest
                .clone(),
            original_genesis_digest: a.genesis_digest.clone(),
            original_birth_digest: birth.request.native_birth_digest.clone(),
            current_witness_history_digest: history.original.complete_replay_digest().into(),
            current_witness_continuation_digest: a.attempt_digest.clone(),
            current_writer_session_digest: canonical(
                "wholepact:common-context-reentry-writer-session:v1",
                &a.original_session,
            )?,
            current_writer_session_expires_at_ms: a.original_session.expires_at_ms,
            construction_transport_credential_digest: credential
                .digest()
                .map_err(|_| Error::InvalidData)?,
            construction_transport_credential_id: credential.credential_id().into(),
            original_transport_fence_digest: credential.old_key_fence_digest.clone(),
            native_review_digest: self.digest,
            admitted_at_ms: now()?,
            completion_expires_at_ms: a.expires_at_ms.min(read.request.completion_expires_at_ms),
        };
        lineage.validate().map_err(|_| Error::InvalidData)?;
        append(
            &self.source,
            Phase::Reentered {
                lineage: Box::new(lineage.clone()),
                witness_history: Box::new(history),
            },
        )?;
        self.source.check_peer(&self.peer, owner)?;
        send(
            &mut self.stream,
            &self.peer,
            &RosterCommonContextReentryResponseV1::CommonContextReenteredV1 {
                lineage: Box::new(lineage.clone()),
            },
            self.source.completion_deadline(),
            || {
                self.source.check_peer(&self.peer, owner)?;
                observed.check_current().map_err(|_| Error::ReviewMismatch)
            },
        )?;
        Ok(ReenteredCommonContextOwnerV1 {
            source: self.source,
            peer: self.peer,
            native: self.native,
            lineage,
            observed,
            owner_client: self.owner_client,
            signer: self.signer,
        })
    }
}

pub(super) struct ReenteredCommonContextOwnerV1 {
    owner_client: AuthorityClient,
    signer: PinnedOwnerSigner,
    source: FreshCommonContextReentrySource,
    peer: AuthenticatedPeer,
    native: NativeAuthorityBinding,
    lineage: RosterCommonContextReentryLineageV1,
    observed: ObservedConstructionTransportV1,
}
impl ReenteredCommonContextOwnerV1 {
    pub(super) fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.source.check_peer(&self.peer, owner)?;
        self.observed
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        if now()? >= self.lineage.completion_expires_at_ms {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    /// Original request/lineage predicate only. It borrows the real retained
    /// owner and never reconstructs its lineage from the supplied digest.
    fn require_exact_request(
        &self,
        peer: &AuthenticatedPeer,
        request: &ManualRosterConstructionRequestV3,
        lineage_digest: &str,
    ) -> Result<()> {
        request.validate().map_err(|_| Error::InvalidData)?;
        if peer.grant_id != self.peer.grant_id
            || lineage_digest != self.lineage.digest().map_err(|_| Error::InvalidData)?
            || request.plan != self.lineage.request.original_read.plan
            || request.current_caller_binding_digest
                != self.lineage.request.current_caller_binding_digest
            || request.requested_at_ms < self.lineage.admitted_at_ms
            || request.admission_expires_at_ms > self.lineage.completion_expires_at_ms
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn prepare(
        self,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: ManualRosterConstructionRequestV3,
        lineage_digest: &str,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedReenteredConstructionV1> {
        self.check(owner)?;
        connected(&stream, &peer)?;
        self.require_exact_request(&peer, &request, lineage_digest)?;
        self.source.require_exact_change(&request)?;
        let extension = self.source.retained().record().extension()?;
        self.observed
            .history()
            .manual_roster_construction_approval_v3(
                &request
                    .plan
                    .invocation_digest()
                    .map_err(|_| Error::InvalidData)?,
            )
            .map_err(|_| Error::ReviewMismatch)?
            .ok_or(Error::ReviewMismatch)?
            .matches_request(&request, &extension)
            .map_err(|_| Error::ReviewMismatch)?;
        let digest = canonical(
            "wholepact:native-reentered-full-construction-review:v1",
            &(
                &request,
                &self.lineage,
                self.observed.snapshot(),
                self.native.entry_digest(),
            ),
        )?;
        let display = Zeroizing::new(format!(
            "APPROVE EXACT FULL COMMON-CONTEXT CONSTRUCTION\n{}\n\nThis is a separate full-proposal financial exposure decision AFTER read admission and transport handoff. Review every recipient, amount, fee, owned input/nullifier, same-account return, original target/anchor/expiry and disclosure destination. This reserves conservative lifetime exposure, then consumes it once for NON-SIGNING construction. Failure, cancel or lost response never refunds that charge or permits a second attempt. No additional read, wallet selection, transaction signature, proof or dispatch is allowed. The original session and original completion ceiling remain unchanged.\nExact old-read/new-native lineage:\n{}\nExact review: {}",
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&self.lineage).map_err(|_| Error::InvalidData)?,
            digest
        ));
        Ok(PreparedReenteredConstructionV1 {
            owner: self,
            stream,
            request,
            digest,
            display,
        })
    }
}
pub(super) struct PreparedReenteredConstructionV1 {
    owner: ReenteredCommonContextOwnerV1,
    stream: UnixStream,
    request: ManualRosterConstructionRequestV3,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedReenteredConstructionV1 {
    /// Borrow this actual prepared request/owner before native authorization.
    /// No Reserve/Consume, transport claim, owner clone or attempted retry occurs.
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn qualification_check_wrong_lineage(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.owner.check(owner)?;
        connected(&self.stream, &self.owner.peer)?;
        self.review_json()?;
        let lineage_digest = self
            .owner
            .lineage
            .digest()
            .map_err(|_| Error::InvalidData)?;
        self.owner
            .require_exact_request(&self.owner.peer, &self.request, &lineage_digest)?;
        let wrong_lineage = if lineage_digest == "c0".repeat(32) {
            "c1".repeat(32)
        } else {
            "c0".repeat(32)
        };
        wholepact_core::proposal::validate_sha256(&wrong_lineage)
            .map_err(|_| Error::InvalidData)?;
        if !matches!(
            self.owner
                .require_exact_request(&self.owner.peer, &self.request, &wrong_lineage),
            Err(Error::ReviewMismatch)
        ) {
            return Err(Error::ReviewMismatch);
        }
        self.owner
            .require_exact_request(&self.owner.peer, &self.request, &lineage_digest)?;
        self.owner.check(owner)?;
        connected(&self.stream, &self.owner.peer)?;
        self.review_json()?;
        Ok(())
    }
    pub(super) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn review_json(&self) -> Result<String> {
        self.owner.native.check_current()?;
        self.owner
            .observed
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        self.request
            .remaining_admission_ms(now()?)
            .map_err(|_| Error::ReviewMismatch)?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve_and_serve(
        mut self,
        d: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<super::named_continuation::ConsumedBornNamedOwnerV1> {
        self.owner.check(owner)?;
        connected(&self.stream, &self.owner.peer)?;
        self.review_json()?;
        decision(&d, &self.owner.native, &self.digest)?;
        let source = self.owner.source;
        let extension = source.retained().record().extension()?;
        let continuation = self
            .owner
            .observed
            .history()
            .manual_roster_session_continuation_v2(
                &self.owner.lineage.request.current_attempt_digest,
            )
            .map_err(|_| Error::ReviewMismatch)?
            .ok_or(Error::ReviewMismatch)?
            .clone();
        let reviewed_at_ms = now()?;
        let request = ManualRosterConstructionReservationRequestV3 {
            version: 3,
            construction: self.request.clone(),
            attempt_digest: self.owner.lineage.request.current_attempt_digest.clone(),
            attempt_sequence: self.owner.lineage.request.current_attempt_sequence,
            writer_epoch: self.owner.observed.snapshot().writer_epoch,
            expected_head: self.owner.observed.snapshot().head.clone(),
            session_id: self
                .owner
                .observed
                .credential()
                .authorization()
                .original_session
                .session_id
                .clone(),
            signer_intent_digest: self.owner.lineage.retained_signer_intent_digest.clone(),
            native_review_digest: self.digest.clone(),
            reviewed_at_ms,
        };
        request
            .validate_for(&extension, &continuation)
            .map_err(|_| Error::ReviewMismatch)?;
        // self and its ORIGINAL read receipt move into this one call. No error
        // path returns an owner, repairs a grant, or restores a spent read slot.
        source.check_peer(&self.owner.peer, owner)?;
        let reservation = self
            .owner
            .observed
            .reserve(&extension, &continuation, &request)
            .map_err(|_| Error::Uncertain)?;
        let lineage_digest = self
            .owner
            .lineage
            .digest()
            .map_err(|_| Error::InvalidData)?;
        append(
            &source,
            Phase::Reserved {
                reentry_lineage_digest: lineage_digest.clone(),
                extension: Box::new(extension.clone()),
                continuation: Box::new(continuation.clone()),
                record: Box::new(reservation.record().clone()),
            },
        )?;
        source.check_peer(&self.owner.peer, owner)?;
        let r = &reservation.record().original;
        let consume = ManualRosterConstructionConsumeRequestV3 {
            version: 3,
            operation_id: construction_consume_operation_id_v3(r, &extension, &continuation)
                .map_err(|_| Error::InvalidData)?,
            reservation_operation_id: r.request.construction.operation_id.clone(),
            reservation_digest: r
                .digest_for(&extension, &continuation)
                .map_err(|_| Error::InvalidData)?,
            account_id: extension
                .account_extension
                .terms
                .identity
                .account_id
                .clone(),
            network_profile_id: extension
                .account_extension
                .terms
                .identity
                .network_profile_id
                .clone(),
            writer_epoch: r.request.writer_epoch,
            expected_head: r.snapshot.head.clone(),
            session_id: r.session.session_id.clone(),
            common_invocation_digest: r
                .request
                .invocation_digest()
                .map_err(|_| Error::InvalidData)?,
            current_caller_binding_digest: self.request.current_caller_binding_digest.clone(),
        };
        let binding = self.owner.native.clone();
        let _lease = binding.publication_lease()?;
        source.check_peer(&self.owner.peer, owner)?;
        let contribution = reservation
            .consume(&consume)
            .map_err(|_| Error::Uncertain)?;
        contribution
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        let r = &contribution.reservation().original;
        let c = &contribution.consumed().original;
        let construction = ManualRosterConstructionContributionEvidenceV3 {
            version: 3,
            request: self.request,
            retained_signer_intent_digest: r.request.signer_intent_digest.clone(),
            current_attempt_digest: r.request.attempt_digest.clone(),
            current_attempt_sequence: r.request.attempt_sequence,
            native_review_digest: self.digest,
            common_context_read_admission_digest: self
                .owner
                .lineage
                .request
                .original_read_admission_digest
                .clone(),
            witness_plan_approval_digest: self
                .owner
                .lineage
                .request
                .original_read
                .witness_plan_approval_digest
                .clone(),
            witness_reservation_digest: r
                .digest_for(&extension, &continuation)
                .map_err(|_| Error::InvalidData)?,
            witness_consumed_digest: c
                .digest_for(r, &extension, &continuation)
                .map_err(|_| Error::InvalidData)?,
            reviewed_at_ms,
            reserved_at_ms: r.admitted_at_ms,
            consumed_at_ms: c.consumed_at_ms,
            reserved_debit_zatoshis: r.reserved_debit_zatoshis,
            reserved_input_value_zatoshis: r.reserved_input_value_zatoshis,
            writer_session_expires_at_ms: r.session.expires_at_ms,
        };
        let evidence = RosterReenteredConstructionEvidenceV1 {
            version: 1,
            reentry_lineage: self.owner.lineage,
            construction,
        };
        evidence.validate().map_err(|_| Error::InvalidData)?;
        append(
            &source,
            Phase::Consumed {
                reentry_lineage_digest: lineage_digest,
                record: Box::new(contribution.consumed().clone()),
                evidence: Box::new(evidence.clone()),
            },
        )?;
        send(
            &mut self.stream,
            &self.owner.peer,
            &RosterReenteredConstructionResponseV1::ReenteredConstructionConsumedV1 {
                evidence: Box::new(evidence.clone()),
            },
            source.completion_deadline(),
            || {
                contribution
                    .check_current()
                    .map_err(|_| Error::ReviewMismatch)
            },
        )?;
        let source = source.into_named_recipient_after_consumed(evidence, owner)?;
        super::named_continuation::ConsumedBornNamedOwnerV1::from_consumed(
            source,
            self.owner.owner_client,
            self.owner.signer,
            owner,
        )
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod native_decision_tests {
    use super::*;
    use crate::native_ui::{recovery_test_authority, recovery_test_decision};
    #[test]
    fn old_read_or_another_native_decision_cannot_sign_new_channel_review() {
        // Pure native decision identity check only; no socket/exporter/key/signature.
        let current = recovery_test_authority();
        let other = recovery_test_authority();
        let old_read = "a1".repeat(32);
        let exact_claim = "a2".repeat(32);
        assert!(
            decision(
                &recovery_test_decision(&current, &old_read),
                &current.binding(),
                &exact_claim
            )
            .is_err()
        );
        assert!(
            decision(
                &recovery_test_decision(&other, &exact_claim),
                &current.binding(),
                &exact_claim
            )
            .is_err()
        );
        assert!(
            decision(
                &recovery_test_decision(&current, &exact_claim),
                &current.binding(),
                &exact_claim
            )
            .is_ok()
        );
    }
    #[test]
    fn credential_selection_rejects_caller_supplied_completion_or_authority_flags() {
        for text in [
            r#"{"completed_all_reads":true}"#,
            r#"{"restore_session":true}"#,
            r#"{"approved":true,"exporter":"00"}"#,
        ] {
            assert!(serde_json::from_str::<Setup>(text).is_err());
        }
    }
}
