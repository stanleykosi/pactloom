//! Native-only enrollment and exact retained-authorization reconciliation.
//! Requests carry identities, never chain evidence or a positive-resolution flag.
use super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{Error, Result, consent_journal::*};
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use wholepact_authority::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use wholepact_authority::{OwnerControl, OwnerControlRequest, WitnessDisclosureDescriptor};
use wholepact_chain::local_node::{LocalNodeSourceDescriptor, LocalNodeTls, LocalValidatingNode};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeSetup {
    #[serde(default)]
    existing_source_reference: Option<String>,
    source_id: String,
    endpoint: std::net::SocketAddr,
    server_name: String,
    pinned_certificate_sha256: String,
    trusted_root_der: PathBuf,
    client_certificate_der: PathBuf,
    client_private_key_pkcs8_der: PathBuf,
    required_confirmations: u32,
    witness_source: LocalNodeSourceDescriptor,
}
enum Action {
    Attach {
        reference: String,
        node: Arc<LocalValidatingNode>,
    },
    Signer {
        prepared: PreparedSettlementSource,
        node: Arc<LocalValidatingNode>,
    },
    Owner {
        request: OwnerControlRequest,
        witness: Arc<NativeWitnessWorkspace>,
        disclosure: WitnessDisclosureDescriptor,
    },
    Observe {
        authorization: String,
        dispatch: String,
        source_reference: String,
        conflict: Option<wholepact_chain::local_node::CanonicalConflictCandidate>,
        witness: Arc<NativeWitnessWorkspace>,
    },
}
pub(super) struct PreparedResolution {
    native: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
    action: Action,
    reply: Option<SettlementReply>,
}
pub(super) struct SettlementReply {
    request: crate::authority_bridge::settlement_ipc::SettlementRequest,
    peer: crate::ipc::AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
}
pub(super) enum ApprovedResolution {
    Attach {
        reference: String,
        node: Arc<LocalValidatingNode>,
        native: NativeAuthorityBinding,
        deadline: Instant,
    },
    Ipc {
        inner: Box<ApprovedResolution>,
        reply: SettlementReply,
    },
    Signer {
        approved: ApprovedSettlementSource,
        node: Arc<LocalValidatingNode>,
    },
    Owner {
        request: OwnerControlRequest,
        witness: Arc<NativeWitnessWorkspace>,
        disclosure: WitnessDisclosureDescriptor,
        native: NativeAuthorityBinding,
        deadline: Instant,
    },
    Observe {
        authorization: String,
        dispatch: String,
        source_reference: String,
        conflict: Option<wholepact_chain::local_node::CanonicalConflictCandidate>,
        witness: Arc<NativeWitnessWorkspace>,
        native: NativeAuthorityBinding,
        deadline: Instant,
    },
}
impl PreparedResolution {
    pub(super) fn signer(
        json: &str,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        authority: &NativeAuthority,
    ) -> Result<Self> {
        authority.check_current()?;
        if json.len() > 32768 {
            return Err(Error::InvalidData);
        }
        let setup: NodeSetup = serde_json::from_str(json).map_err(|_| Error::InvalidData)?;
        let root = super::witness_workspace::read_private_credential(&setup.trusted_root_der)?;
        let cert =
            super::witness_workspace::read_private_credential(&setup.client_certificate_der)?;
        let key =
            super::witness_workspace::read_private_credential(&setup.client_private_key_pkcs8_der)?;
        let tls = LocalNodeTls::new(
            setup.server_name,
            setup.pinned_certificate_sha256,
            vec![CertificateDer::from(root.to_vec())],
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .map_err(|_| Error::Authentication)?;
        let node = Arc::new(
            LocalValidatingNode::new(
                setup.source_id,
                setup.endpoint,
                tls,
                setup.required_confirmations,
            )
            .map_err(|_| Error::InvalidData)?,
        );
        let witness_digest = wholepact_authority::resolution_source_digest(&setup.witness_source)
            .map_err(|_| Error::InvalidData)?;
        if let Some(reference) = setup.existing_source_reference {
            let enrolled = journal.settlement_source(&reference, session)?;
            if enrolled.source() != &node.source_descriptor()
                || enrolled.witness_source_digest() != witness_digest
            {
                return Err(Error::ReviewMismatch);
            }
            let digest = wholepact_core::proposal::canonical_digest(
                "wholepact:native-reattach-resolution-source:v1",
                &enrolled,
            )
            .map_err(|_| Error::InvalidData)?;
            let display = format!(
                "REATTACH EXACT PREVIOUSLY ENROLLED SIGNER SOURCE\nReference: {}\nComplete descriptor:\n{}\nWitness source:\n{}\nTrust this exact owner-controlled node and TLS terminator for canonical state. Reads disclose transaction linkage. This only attaches the runtime source after restart; it never clears recovery quarantine, grants spending authority, changes enrollment or resolves exposure.",
                reference,
                serde_json::to_string_pretty(enrolled.source()).map_err(|_| Error::InvalidData)?,
                serde_json::to_string_pretty(&setup.witness_source)
                    .map_err(|_| Error::InvalidData)?
            );
            return Ok(Self {
                native: authority.binding(),
                digest,
                display: Zeroizing::new(display),
                reply: None,
                action: Action::Attach { reference, node },
            });
        }
        let prepared =
            session.prepare_settlement_source(journal, node.source_descriptor(), witness_digest)?;
        let display = format!(
            "{}\n\nCOMPLETE INDEPENDENT WITNESS SOURCE (must already be owner-enrolled at the witness):\n{}\n\nPrivate credential files are read only locally, never exported. Existing credentials are selected; no credential is generated or installed. Node release/commit are declared pins, not independently attested binary measurements.",
            prepared.display()?,
            serde_json::to_string_pretty(&setup.witness_source).map_err(|_| Error::InvalidData)?
        );
        // Bind all displayed witness fields, not merely a host-supplied trust flag.
        Ok(Self {
            native: authority.binding(),
            digest: prepared.review_digest().into(),
            display: Zeroizing::new(display),
            reply: None,
            action: Action::Signer { prepared, node },
        })
    }
    pub(super) fn owner(
        json: &str,
        witness: Arc<NativeWitnessWorkspace>,
        authority: NativeAuthorityBinding,
    ) -> Result<Self> {
        authority.check_current()?;
        witness.check_current()?;
        if json.len() > 32768 {
            return Err(Error::InvalidData);
        }
        let source: LocalNodeSourceDescriptor =
            serde_json::from_str(json).map_err(|_| Error::InvalidData)?;
        let source_descriptor_digest = wholepact_authority::resolution_source_digest(&source)
            .map_err(|_| Error::InvalidData)?;
        let snapshot = witness.client().snapshot().map_err(|_| Error::Uncertain)?;
        // The server independently authenticates the owner credential for control.
        let request = OwnerControlRequest {
            operation_id: hex::encode(crate::vault::random::<32>()?),
            account_id: snapshot.account_id.clone(),
            network_profile_id: snapshot.network_profile_id.clone(),
            expected_head: snapshot.head,
            writer_epoch: snapshot.writer_epoch,
            control: OwnerControl::EnrollResolutionSource {
                source_descriptor_digest,
            },
        };
        let disclosure = witness.disclosure();
        let exact_owner_request =
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-resolution-source-owner:v1",
            &(&request, &source, &disclosure),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "OWNER: ENROLL INDEPENDENT WITNESS RESOLUTION SOURCE\nWitness: {}\nEndpoint: {}\nAccount: {}\nNetwork: {}\nComplete validating source:\n{}\n\nTrust the named independently operated validating node and TLS terminator for fresh uncached canonical state. Reads disclose transaction and account linkage to this operator. Exact endpoint, TLS identities, release/commit, network and confirmation policy are pinned. Source replacement is unsupported. The witness must separately attach its matching local runtime node. This does not deploy a node, install credentials, sign, broadcast, erase original permits or grant a writer session. Node version pins are not binary attestation.\nExact request: {}\n{exact_owner_request}",
            disclosure.witness_id,
            disclosure.endpoint,
            request.account_id,
            request.network_profile_id,
            serde_json::to_string_pretty(&source).map_err(|_| Error::InvalidData)?,
            digest
        );
        Ok(Self {
            native: authority,
            digest,
            display: Zeroizing::new(display),
            reply: None,
            action: Action::Owner {
                request,
                witness,
                disclosure,
            },
        })
    }
    pub(super) fn observe(
        authorization: &str,
        dispatch: &str,
        source_reference: &str,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        witness: Arc<NativeWitnessWorkspace>,
        authority: &NativeAuthority,
    ) -> Result<Self> {
        authority.check_current()?;
        if [authorization, dispatch, source_reference]
            .iter()
            .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
        {
            return Err(Error::InvalidData);
        }
        let binding = journal.settlement_binding(authorization, session)?;
        let source = journal.settlement_source(source_reference, session)?;
        let lease = journal.acquire_original_authorization(authorization, session)?;
        let retained = journal
            .retained_dispatch(&lease, dispatch)
            .map_err(|_| Error::ReviewMismatch)?
            .ok_or(Error::ReviewMismatch)?;
        let exact_dispatch = serde_json::to_string_pretty(&retained.request.backend.descriptor)
            .map_err(|_| Error::InvalidData)?;
        lease.check_current()?;

        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-exact-resolution:v1",
            &(
                authorization,
                dispatch,
                &source,
                binding.original_consent_ref(),
                &retained.request.backend.descriptor,
                witness.disclosure(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "CHECK EXACT ORIGINAL AUTHORIZATION SETTLEMENT\nAuthorization: {authorization}\nDispatch: {dispatch}\nOriginal consent: {}\nAccount: {}\nObligation: {}\nExact retained effects: {}\nSelected input count: {}\nExact retained dispatch transaction:\n{exact_dispatch}\nSigner source:\n{}\nWitness: {} at {}\nIndependent witness source digest: {}\n\nThis discloses the exact transaction linkage to the already selected sources. Both signer and witness independently read their own original immutable records and enrolled canonical node. Only exact consumed original inputs under the pinned policy can resolve exposure. Missing, stale or changed evidence fails closed. Reorganizations reopen exposure and fence future authority. This does not sign, submit or replace a payment; source DTOs and saved verified flags cannot authorize settlement.",
            binding.original_consent_ref(),
            binding.account_id(),
            binding.obligation_id(),
            binding.effects_digest(),
            binding.inputs().len(),
            serde_json::to_string_pretty(source.source()).map_err(|_| Error::InvalidData)?,
            witness.disclosure().witness_id,
            witness.disclosure().endpoint,
            source.witness_source_digest()
        );
        Ok(Self {
            native: authority.binding(),
            digest,
            display: Zeroizing::new(display),
            reply: None,
            action: Action::Observe {
                authorization: authorization.into(),
                dispatch: dispatch.into(),
                source_reference: source_reference.into(),
                conflict: None,
                witness,
            },
        })
    }
    pub(super) fn bind_ipc(
        mut self,
        request: crate::authority_bridge::settlement_ipc::SettlementRequest,
        peer: crate::ipc::AuthenticatedPeer,
        stream: std::os::unix::net::UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
    ) -> Result<Self> {
        crate::authority_bridge::settlement_ipc::validate_native_request(
            &request, &peer, journal, session,
        )
        .map_err(|_| Error::Authentication)?;
        match &mut self.action {
            Action::Observe {
                authorization,
                dispatch,
                conflict,
                ..
            } if authorization == &request.history.authorization_id
                && dispatch == &request.dispatch_operation_id =>
            {
                *conflict = request.conflict.clone();
            }
            _ => return Err(Error::ReviewMismatch),
        }
        if let Some(candidate) = &request.conflict {
            self.display.push_str(&format!("\nCANONICAL CONFLICT CHECK\nKnown alternative transaction: {}\nExact original Ironwood nullifier: {}\nThe carried original bytes have been matched against retained dispatch, effects and your own input bindings. Each enrolled source must independently establish this exact conflict. A successful check retains the alternative link and keeps the original debit and obligation blocked. It grants no replacement, revised terms or spending permission.", candidate.included_transaction_id, candidate.nullifier));
        }
        let request_digest = request.digest().map_err(|_| Error::InvalidData)?;
        self.digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-requested-resolution:v1",
            &(
                &self.digest,
                &request_digest,
                &peer.grant_id,
                &peer.channel_digest,
                peer.generation,
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        self.display.push_str(&format!("\nAuthenticated local request: {request_digest}\nApplication: {}\nGrant: {}\nChannel binding: {}\nThe app receives only a durable commit acknowledgement, never current settlement authority.", super::state::inert_text(&peer.label),peer.grant_id,peer.channel_digest));
        self.reply = Some(SettlementReply {
            request,
            peer,
            stream,
        });
        Ok(self)
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.native.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        session: &SignerConsentSession,
    ) -> Result<ApprovedResolution> {
        self.native.check_current()?;
        authority.check_current()?;
        if decision.binding() != &self.native
            || authority.binding() != self.native
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        let deadline = Instant::now() + Duration::from_secs(120);
        let approved = match self.action {
            Action::Attach { reference, node } => ApprovedResolution::Attach {
                reference,
                node,
                native: self.native,
                deadline,
            },
            Action::Signer { prepared, node } => ApprovedResolution::Signer {
                approved: session
                    .approve_settlement_source(prepared, session.native_decision(decision)?)?,
                node,
            },
            Action::Owner {
                request,
                witness,
                disclosure,
            } => ApprovedResolution::Owner {
                request,
                witness,
                disclosure,
                native: self.native,
                deadline,
            },
            Action::Observe {
                authorization,
                dispatch,
                source_reference,
                conflict,
                witness,
            } => ApprovedResolution::Observe {
                authorization,
                dispatch,
                source_reference,
                conflict,
                witness,
                native: self.native,
                deadline,
            },
        };
        Ok(if let Some(reply) = self.reply {
            ApprovedResolution::Ipc {
                inner: Box::new(approved),
                reply,
            }
        } else {
            approved
        })
    }
}
impl ApprovedResolution {
    pub(super) fn run(
        self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
    ) -> Result<Option<String>> {
        match self {
            Self::Attach {
                reference,
                node,
                native,
                deadline,
            } => {
                native.check_current()?;
                if Instant::now() > deadline {
                    return Err(Error::ReviewMismatch);
                }
                journal.attach_settlement_node(&reference, node, session)?;
                Ok(Some(reference))
            }
            Self::Ipc { inner, mut reply } => {
                crate::authority_bridge::settlement_ipc::validate_native_request(
                    &reply.request,
                    &reply.peer,
                    journal,
                    session,
                )
                .map_err(|_| Error::Authentication)?;
                let result = inner.run(journal, session)?;
                reply.peer.check_current()?;
                crate::authority_bridge::settlement_ipc::acknowledge_commit(
                    &mut reply.stream,
                    &reply.request,
                )
                .map_err(|_| Error::Uncertain)?;
                Ok(result)
            }
            Self::Signer { approved, node } => {
                let source = journal.record_settlement_source(approved)?;
                journal.attach_settlement_node(source.reference(), node, session)?;
                Ok(Some(source.reference().into()))
            }
            Self::Owner {
                request,
                witness,
                disclosure,
                native,
                deadline,
            } => {
                native.check_current()?;
                witness.check_current()?;
                if Instant::now() > deadline || witness.disclosure() != disclosure {
                    return Err(Error::ReviewMismatch);
                }
                witness
                    .client()
                    .control(request)
                    .map_err(|_| Error::Uncertain)?;
                native.check_current()?;
                Ok(None)
            }
            Self::Observe {
                authorization,
                dispatch,
                source_reference,
                conflict,
                witness,
                native,
                deadline,
            } => {
                native.check_current()?;
                witness.check_current()?;
                if Instant::now() > deadline {
                    return Err(Error::ReviewMismatch);
                }
                journal.observe_and_resolve_settlement_selected(
                    &authorization,
                    &dispatch,
                    &source_reference,
                    conflict.as_ref(),
                    witness.client(),
                    session,
                )?;
                native.check_current()?;
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> serde_json::Value {
        serde_json::json!({
            "source_id":"synthetic-node", "endpoint":"127.0.0.1:18232",
            "server_name":"synthetic.invalid", "pinned_certificate_sha256":"11".repeat(32),
            "trusted_root_der":"/synthetic-private/root.der",
            "client_certificate_der":"/synthetic-private/client.der",
            "client_private_key_pkcs8_der":"/synthetic-private/client-key.der",
            "required_confirmations":10,
            "witness_source": {
                "source_id":"synthetic-independent-node", "endpoint":"127.0.0.1:18233",
                "server_name":"synthetic-witness.invalid", "pinned_certificate_sha256":"22".repeat(32),
                "client_certificate_sha256":"33".repeat(32), "trusted_root_sha256":["44".repeat(32)],
                "node_release":wholepact_chain::local_node::ZEBRA_RELEASE,
                "node_source_commit":wholepact_chain::local_node::ZEBRA_SOURCE_COMMIT,
                "network":"testnet", "consensus_branch_id":wholepact_chain::NU7_BRANCH_ID,
                "activation_height":wholepact_chain::NU7_ACTIVATION_HEIGHT,
                "confirmation_policy":wholepact_chain::ConfirmationPolicy::new(10,10,vec!["synthetic-independent-node".into()]).unwrap()
            }
        })
    }
    #[test]
    fn native_resolution_setup_rejects_secret_inline_and_positive_flags() {
        let original = setup();
        let parsed: NodeSetup = serde_json::from_value(original.clone()).unwrap();
        assert!(parsed.existing_source_reference.is_none());
        for field in ["verified", "resolved", "client_private_key", "approval"] {
            let mut value = original.clone();
            value[field] = serde_json::json!("untrusted");
            assert!(serde_json::from_value::<NodeSetup>(value).is_err());
        }
        let mut incomplete = original;
        incomplete["witness_source"]
            .as_object_mut()
            .unwrap()
            .remove("pinned_certificate_sha256");
        assert!(serde_json::from_value::<NodeSetup>(incomplete).is_err());
    }
    #[test]
    fn native_resolution_credential_reader_rejects_exposed_and_symlink_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("synthetic-not-a-real-credential.der");
        std::fs::write(&path, b"synthetic-noncredential").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(super::super::witness_workspace::read_private_credential(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(super::super::witness_workspace::read_private_credential(&path).is_ok());
        let link = dir.path().join("symlink.der");
        symlink(&path, &link).unwrap();
        assert!(super::super::witness_workspace::read_private_credential(&link).is_err());
    }
}
