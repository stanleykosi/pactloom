//! Genuine purpose-distinct native consent for a future construction-only
//! transport handoff. The old read decision cannot authorize this signature.
use super::super::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority};
use crate::account::birth::enrollment::roster_v2::inventory::{
    common_context_reentry_v1::OriginalCommonContextHandoffSource, BornRosterInventorySourceV2,
};
use crate::{ipc::AuthenticatedPeer, Error, Result};
use rustls::{sign::Signer, SignatureScheme};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};
use wholepact_authority::construction_transport_handoff_v1::{
    construction_transport_preauthorization_signing_bytes_v1,
    ConstructionTransportPreauthorizationV1, SignedConstructionTransportPreauthorizationV1,
};
use wholepact_authority::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use wholepact_signer_origin::common_context_handoff_v1::{
    RosterCommonContextHandoffAuthorizationRequestV1,
    RosterCommonContextHandoffAuthorizationResponseV1,
};
use zeroize::Zeroizing;

pub(super) struct PinnedOwnerSigner {
    signer: Box<dyn Signer>,
    certificate: Vec<u8>,
    pin: String,
}
impl PinnedOwnerSigner {
    pub(super) fn open(pin: &str, certificate_path: &Path, key_path: &Path) -> Result<Self> {
        let certificate =
            super::super::witness_workspace::read_private_credential(certificate_path)?;
        if wholepact_authority::transport::certificate_digest(&CertificateDer::from(
            certificate.as_slice(),
        )) != pin
        {
            return Err(Error::Authentication);
        }
        let key = super::super::witness_workspace::read_private_credential(key_path)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));
        let signing_key =
            rustls::crypto::ring::sign::any_supported_type(&key).map_err(|_| Error::InvalidData)?;
        let signer = signing_key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .ok_or(Error::Unavailable)?;
        Ok(Self {
            signer,
            certificate: certificate.to_vec(),
            pin: pin.to_owned(),
        })
    }
    pub(super) fn sign_claim(
        &self,
        claim: wholepact_authority::construction_transport_handoff_v1::ConstructionTransportClaimV1,
    ) -> Result<
        wholepact_authority::construction_transport_handoff_v1::SignedConstructionTransportClaimV1,
    > {
        use wholepact_authority::construction_transport_handoff_v1::{
            construction_transport_claim_signing_bytes_v1, SignedConstructionTransportClaimV1,
        };
        let bytes = construction_transport_claim_signing_bytes_v1(&claim)
            .map_err(|_| Error::InvalidData)?;
        let signed = SignedConstructionTransportClaimV1 {
            claim,
            scheme: "ecdsa-p256-sha256-asn1-v1".into(),
            owner_certificate_der: self.certificate.clone(),
            signature: self.signer.sign(&bytes).map_err(|_| Error::Crypto)?,
        };
        signed
            .verify(&self.pin)
            .map_err(|_| Error::Authentication)?;
        Ok(signed)
    }
    fn sign_authorization(
        &self,
        authorization: ConstructionTransportPreauthorizationV1,
    ) -> Result<SignedConstructionTransportPreauthorizationV1> {
        let bytes = construction_transport_preauthorization_signing_bytes_v1(&authorization)
            .map_err(|_| Error::InvalidData)?;
        let result = SignedConstructionTransportPreauthorizationV1 {
            authorization,
            scheme: "ecdsa-p256-sha256-asn1-v1".into(),
            owner_certificate_der: self.certificate.clone(),
            signature: self.signer.sign(&bytes).map_err(|_| Error::Crypto)?,
        };
        result
            .verify(&self.pin)
            .map_err(|_| Error::Authentication)?;
        Ok(result)
    }
}

pub(super) struct PreparedCommonContextHandoffAuthorizationV1 {
    source: OriginalCommonContextHandoffSource,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    authorization: ConstructionTransportPreauthorizationV1,
    signer: PinnedOwnerSigner,
    native: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedCommonContextHandoffAuthorizationV1 {
    pub(super) fn prepare(
        source: BornRosterInventorySourceV2,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: RosterCommonContextHandoffAuthorizationRequestV1,
        certificate_path: &Path,
        key_path: &Path,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        request.validate().map_err(|_| Error::InvalidData)?;
        let source = OriginalCommonContextHandoffSource::prepare(
            source,
            peer.clone(),
            owner,
            &request.original_read_admission_digest,
            &request.current_caller_binding_digest,
        )?;
        let read = source.read();
        let record = source.record();
        let wall = now()?;
        let remaining = source
            .completion_deadline()
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or(Error::ReviewMismatch)?;
        let expires_at_ms = wall
            .checked_add(u64::try_from(remaining.as_millis()).map_err(|_| Error::InvalidData)?)
            .ok_or(Error::InvalidData)?
            .min(read.request.completion_expires_at_ms)
            .min(source.session().expires_at_ms);
        if request.operation_id == read.request.operation_id
            || request.operation_id == read.request.plan.retained.operation_id
            || request.operation_id
                == read
                    .request
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .invocation
                    .operation_id
        {
            return Err(Error::ReviewMismatch);
        }
        let mut authorization = ConstructionTransportPreauthorizationV1 {
            version: 1,
            operation_id: request.operation_id,
            account_id: record.account_record.terms.identity.account_id.clone(),
            network_profile_id: record
                .account_record
                .terms
                .identity
                .network_profile_id
                .clone(),
            genesis_digest: record
                .account_record
                .genesis
                .digest()
                .map_err(|_| Error::InvalidData)?,
            policy_digest: record.account_record.terms.original_policy_digest.clone(),
            original_session: source.session().clone(),
            attempt_digest: read.current_attempt_digest.clone(),
            attempt_sequence: read.current_attempt_sequence,
            read_request_digest: read.request.digest().map_err(|_| Error::InvalidData)?,
            read_evidence_digest: read.digest().map_err(|_| Error::InvalidData)?,
            plan_approval_digest: read.request.witness_plan_approval_digest.clone(),
            invocation_digest: read
                .request
                .plan
                .invocation_digest()
                .map_err(|_| Error::InvalidData)?,
            original_caller_binding_digest: read.request.current_caller_binding_digest.clone(),
            original_host_process_commitment: source.host_commitment().to_owned(),
            original_native_binding_digest: source.native_binding_digest().to_owned(),
            native_review_digest: "00".repeat(32),
            nonce: hex::encode(crate::vault::random::<32>()?),
            authorized_at_ms: wall,
            expires_at_ms,
        };
        let pairing =
            crate::native_ui::AuthenticatedPairing::from_authenticated_request(peer.clone())?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-common-context-future-handoff-review:v1",
            &(
                &authorization,
                pairing.binding(),
                certificate_path,
                key_path,
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        if digest == read.native_review_digest {
            return Err(Error::ReviewMismatch);
        }
        authorization.native_review_digest = digest.clone();
        authorization.validate().map_err(|_| Error::InvalidData)?;
        let signer = PinnedOwnerSigner::open(
            &record.account_record.terms.signer.owner_certificate_digest,
            certificate_path,
            key_path,
        )?;
        let display = Zeroizing::new(format!(
            "AUTHORIZE ONE FUTURE CONSTRUCTION-ONLY TRANSPORT HANDOFF\n{}\n\nThis is a NEW consent, separate from the privacy read. It signs and sends this exact bounded authorization to the same paired Host for relay to your independently selected witness owner. The witness must separately approve one inert grant only after every participant's actual read observation exists. The receipt above proves read admission, never provider-read completion or usable inputs.\n\nA future fresh unlock, exact source/journal verification, new native decision and new TLS-bound original-owner signature remain mandatory. Claiming the grant permanently fences the original transport key, preserving its history and all exposure. No account key or new exporter is transmitted here. No provider read, new note selection, transaction signature, proof, dispatch, ordinary writer authority, budget reset or deadline renewal is permitted. Original expiry: {}.\nActual process:\n{}\nExact review: {}",
            serde_json::to_string_pretty(&authorization).map_err(|_|Error::InvalidData)?, expires_at_ms,
            serde_json::to_string_pretty(pairing.binding()).map_err(|_|Error::InvalidData)?, digest,
        ));
        let value = Self {
            source,
            peer,
            stream,
            authorization,
            signer,
            native: owner.native().binding(),
            digest,
            display,
        };
        value.check(owner)?;
        Ok(value)
    }
    pub(super) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn review_json(&self) -> Result<String> {
        self.native.check_current()?;
        self.peer.check_current()?;
        if now()? >= self.authorization.expires_at_ms
            || Instant::now() >= self.source.completion_deadline()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(self.display.to_string())
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.source.check(owner)?;
        if self.native != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        self.peer.check_current()?;
        self.peer
            .peer
            .same_live_process(&crate::native_peer::PeerProcess::observe(&self.stream)?)
            .map_err(|_| Error::Authentication)?;
        self.review_json()?;
        Ok(())
    }
    pub(super) fn approve_and_serve(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<BornRosterInventorySourceV2> {
        self.check(owner)?;
        if decision.binding() != &self.native || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let binding = self.native.clone();
        let _lease = binding.publication_lease()?;
        self.check(owner)?;
        let signed = self.signer.sign_authorization(self.authorization)?;
        let read = self.source.read();
        self.source
            .journal()
            .retain_common_context_reentry_audit_v1(
                &crate::consent_journal::CommonContextReentrySignerAuditV1 {
                    version: 1,
                    account_id: signed.authorization.account_id.clone(),
                    invocation_digest: signed.authorization.invocation_digest.clone(),
                    original_read_admission_digest: read
                        .digest()
                        .map_err(|_| Error::InvalidData)?,
                    record: crate::consent_journal::CommonContextReentryAuditPhaseV1::Authorized {
                        authorization: Box::new(signed.clone()),
                    },
                },
            )
            .map_err(|_| Error::Uncertain)?;
        let expires = signed.authorization.expires_at_ms;
        let deadline = self
            .source
            .completion_deadline()
            .min(Instant::now() + Duration::from_secs(2));
        let source = self.source.finish(signed.clone(), owner)?;
        let response =
            RosterCommonContextHandoffAuthorizationResponseV1::CommonContextHandoffAuthorizedV1 {
                signed_authorization_json: serde_json::to_string(&signed)
                    .map_err(|_| Error::InvalidData)?,
                signed_authorization_digest: signed.digest().map_err(|_| Error::InvalidData)?,
            };
        let mut bytes =
            Zeroizing::new(serde_json::to_vec(&response).map_err(|_| Error::InvalidData)?);
        if bytes.len() >= 32 * 1024 {
            return Err(Error::Unavailable);
        }
        bytes.push(b'\n');
        let mut stream = self.stream;
        let mut offset = 0;
        while offset < bytes.len() {
            source.check_common_context_completion_only()?;
            self.peer
                .peer
                .same_live_process(&crate::native_peer::PeerProcess::observe(&stream)?)
                .map_err(|_| Error::Authentication)?;
            let wall = now()?;
            if wall >= expires {
                return Err(Error::Uncertain);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|v| !v.is_zero())
                .ok_or(Error::Uncertain)?
                .min(Duration::from_millis(expires - wall));
            stream.set_write_timeout(Some(remaining))?;
            let n = stream.write(&bytes[offset..])?;
            if n == 0 {
                return Err(Error::Uncertain);
            }
            offset += n;
        }
        source.check_common_context_completion_only()?;
        if Instant::now() >= deadline {
            return Err(Error::Uncertain);
        }
        Ok(source)
    }
}
fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidData)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::InvalidData)
}
