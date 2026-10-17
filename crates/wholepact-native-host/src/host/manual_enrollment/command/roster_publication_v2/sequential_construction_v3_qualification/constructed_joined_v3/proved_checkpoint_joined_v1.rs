//! Same actual constructor owner to its first saved proof, genuine named profile
//! and protected Host checkpoint carrier. No serialized success can enter here.
//! All controller delivery is explicitly synthetic; no runtime acceptance claim.
use super::super::joined_signer_worker_v1::JoinedOriginalProfilePublicV1;
use super::*;
use crate::host::born_offline_checkpoint_carrier_v1::PreparedBornOfflineCheckpointCarrierV1;
use std::path::PathBuf;
use wholepact_authority::native_witness_owner::EphemeralBornTransportKeyV1;
use wholepact_proof_jobs::{JobState, JobSummary};
use wholepact_service::protected_transport::TransportDirection;
use wholepact_signer::authority_bridge::{BridgeError, ipc::OriginalHistoryClient};
use wholepact_transport::{ArtifactKind, MessageContext, TransportPublicKey};

pub(in super::super) struct CarriedJoinedOwnerV1<'host> {
    profile: JoinedOriginalProfilePublicV1,
    witness_key: EphemeralBornTransportKeyV1,
    ciphertext_file: PathBuf,
    carrier: PreparedBornOfflineCheckpointCarrierV1<'host>,
}
impl<'host> CarriedJoinedOwnerV1<'host> {
    pub(in super::super) fn profile(&self) -> &JoinedOriginalProfilePublicV1 {
        &self.profile
    }
    pub(in super::super) fn witness_key(&self) -> &EphemeralBornTransportKeyV1 {
        &self.witness_key
    }
    pub(in super::super) fn ciphertext_file(&self) -> &Path {
        &self.ciphertext_file
    }
    pub(in super::super) fn carrier(
        &self,
    ) -> Result<&PreparedBornOfflineCheckpointCarrierV1<'host>> {
        self.carrier.check_current()?;
        Ok(&self.carrier)
    }
}

/// The SAME Host, provider/runtime and actual immutable constructor preparation
/// stay retained. Carriers each own independently verified actual saved proof
/// and genuine fresh purpose-limited private-data retention. No native owner,
/// verification flag or journal row can construct this private result.
pub(in super::super) struct CarriedJoinedStageV1<'host> {
    constructed: ConstructedJoinedStageV3<'host>,
    owners: Vec<CarriedJoinedOwnerV1<'host>>,
    // Same actual FIRST Pair clients, in exact owners order. This contiguous
    // slice is retained through history and synchronous dispatch, not rebuilt.
    original_clients: Vec<OriginalHistoryClient>,
    host_public: TransportPublicKey,
}
impl<'host> CarriedJoinedStageV1<'host> {
    pub(in super::super) fn owners(&self) -> &[CarriedJoinedOwnerV1<'host>] {
        &self.owners
    }
    pub(in super::super) fn original_clients(&self) -> &[OriginalHistoryClient] {
        &self.original_clients
    }
    pub(in super::super) fn host_public_key(&self) -> &TransportPublicKey {
        &self.host_public
    }
    pub(in super::super) fn same_host(&self) -> &'host Host {
        self.constructed.host
    }
    pub(in super::super) fn provider(
        &self,
    ) -> &super::super::synthetic_born_provider_v1::SyntheticBornProviderV1 {
        &self.constructed.provider
    }
}

impl<'host> ConstructedJoinedStageV3<'host> {
    /// Purpose-specific original proof operation is invoked exactly once. An
    /// error may mean uncertain durable work and is terminal, never retried.
    /// Native proof approval is independent of expired constructor/read clocks.
    pub(in super::super) fn prove_and_prepare_carriers_v1(
        self,
        witness: &mut EphemeralNativeWitnessV1,
        signers: &JoinedSignerWorkerV1,
        born: &[PublicJoinedBornV1; 3],
        temporary_root: &Path,
        original_scenario_deadline: Instant,
    ) -> Result<CarriedJoinedStageV1<'host>> {
        self.prove_and_prepare_carriers_inner_v1(
            super::super::full_joined_v3::JoinedWitnessRouteV1::ConstructorOnly(witness),
            signers,
            born,
            temporary_root,
            original_scenario_deadline,
        )
    }
    pub(in super::super) fn prove_and_prepare_carriers_with_original_witnesses_v1(
        self,
        witnesses: &mut super::super::full_joined_v3::OriginalJoinedWitnessSetV1,
        signers: &JoinedSignerWorkerV1,
        born: &[PublicJoinedBornV1; 3],
        temporary_root: &Path,
        original_scenario_deadline: Instant,
    ) -> Result<CarriedJoinedStageV1<'host>> {
        self.prove_and_prepare_carriers_inner_v1(
            super::super::full_joined_v3::JoinedWitnessRouteV1::Distinct(witnesses),
            signers,
            born,
            temporary_root,
            original_scenario_deadline,
        )
    }
    fn prove_and_prepare_carriers_inner_v1(
        mut self,
        mut witnesses: super::super::full_joined_v3::JoinedWitnessRouteV1<'_>,
        signers: &JoinedSignerWorkerV1,
        born: &[PublicJoinedBornV1; 3],
        temporary_root: &Path,
        original_scenario_deadline: Instant,
    ) -> Result<CarriedJoinedStageV1<'host>> {
        let host = self.host;
        check_scenario(original_scenario_deadline)?;
        // Capture only original saved-job correlation while its genuine initial
        // read is current. It is not proof evidence or a substitute for a job.
        let receipt = self.original(host)?.receipt().clone();
        diagnostic::host(B::ProvedConstructionDrain, || {
            // The actual constructor and saved-original checks have already
            // succeeded. Its admitted/liveness owners were consumed there;
            // only immutable Engine original evidence is retained here.
            self.original(host)?;
            if self.history_servers.len() != 2 {
                return Err(Error::Authentication);
            }
            // Drop/join sealed server namespace handles on a non-native worker,
            // before new named enrollment can mutate those same namespaces.
            // Each existing handler retains its original bounded deadline;
            // this never unseals, restarts or renews a server/source.
            std::thread::scope(|scope| -> Result<()> {
                let servers = &mut self.history_servers;
                let drain = std::thread::Builder::new()
                    .name("synthetic-completed-construction-drain".into())
                    .spawn_scoped(scope, move || servers.clear())
                    .map_err(|_| failed("completed construction drain worker unavailable"))?;
                drain
                    .join()
                    .map_err(|_| failed("completed construction drain uncertain"))
            })?;
            if !self.history_servers.is_empty() {
                return Err(Error::Authentication);
            }
            self.original(host)?;
            check_scenario(original_scenario_deadline)
        })?;
        let summary = diagnostic::host(B::ProvedOriginalJob, || {
            host.prove_born_offline_original_queued_v1(AGREEMENT_ID, CONSTRUCTION_KEY)
        })?;
        diagnostic::host(B::ProvedOriginalCorrelation, || {
            check_scenario(original_scenario_deadline)?;
            if summary.job_id != receipt.job_id
                || summary.scope_digest != receipt.scope_digest()?
                || summary.input_digest != receipt.scope.artifact_digest
                || summary.candidate_id != receipt.scope.candidate_id
                || summary.manifest_digest != receipt.scope.manifest_digest
                || summary.effects_commitment != receipt.scope.effects_commitment
                || summary.coordination_request_digest != receipt.scope.coordination_request_digest
                || summary.review_binding != receipt.scope.review_binding
                || summary.state != JobState::Succeeded
                || summary.attempt != 1
                || !summary.encrypted_checkpoint_created
                || !summary.proof_verified
                || summary.result_digest.is_none()
                || summary.chain_validated
                || summary.authorization_allowed
                || summary.distribution_allowed
            {
                return Err(Error::Authentication);
            }
            Ok(())
        })?;
        let host_public = diagnostic::host(B::ProvedHostPublic, || {
            // Exactly the ordinary Host public-key command: use the existing
            // protected key, never provision/replace one or expose secret bytes.
            host.require_manual_session()?;
            let public = host.secrets.transport()?.public_key()?;
            host.require_manual_session()?;
            Ok(public)
        })?;
        let exports = temporary_root.join("synthetic-actual-checkpoint-carriers-v1");
        std::fs::DirBuilder::new().mode(0o700).create(&exports)?;
        let mut owners = Vec::with_capacity(2);
        let mut original_clients = Vec::with_capacity(2);
        for actual_born in &born[1..] {
            check_scenario(original_scenario_deadline)?;
            let witness = witnesses.for_original(actual_born)?;
            let witness_key = diagnostic::host(B::ProvedWitnessKey, || {
                witness
                    .prepare_original_born_transport_v1(&actual_born.account_id)
                    .map_err(|_| failed("actual original temporary witness transport key"))
            })?;
            let snapshot = witness_key
                .snapshot_for_original(witness, &actual_born.account_id)
                .map_err(|_| Error::Authentication)?;
            diagnostic::host(B::ProvedNamedOpen, || {
                signers
                    .send(Command::OpenOriginalNamedPayment(actual_born.index))
                    .map_err(failed)
            })?;
            let (peer, scope) = match signers.receive().map_err(failed)? {
                Reply::NamedPeer { index, peer, scope } if index == actual_born.index => {
                    (peer, scope)
                }
                _ => return Err(Error::Authentication),
            };
            // A NEW genuine read permits exact original metadata comparison for
            // this new nonspending Pair; old construction consent is not reused.
            let read = host.terminal.approve_historical("SYNTHETIC JOINED CONTROLLER TEST: read only the actual saved construction claim/proposal metadata to check this same original account's fresh named Pair scope. No private proof/FVK read, signing, new construction or dispatch is authorized.")?;
            let mut context = None;
            read.effect(&mut || {
                read.check()?;
                let actual = host.engine.prepare_born_offline_checkpoint_original_v1(
                    host.access()?,
                    AGREEMENT_ID,
                    CONSTRUCTION_KEY,
                )?;
                if actual.claim() != self.original.claim()
                    || actual.receipt() != self.original.receipt()
                    || scope.account_id != actual_born.account_id
                    || scope.agreement_id != AGREEMENT_ID
                    || scope.participant_id != actual_born.participant_id
                    || scope.manifest_digest != actual.proposal().manifest_digest()
                    || !scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
                let own = actual
                    .claim()
                    .consumed
                    .iter()
                    .find(|c| {
                        c.request.plan.enrollment().identity.account_id == actual_born.account_id
                    })
                    .ok_or(Error::Authentication)?;
                context = Some((
                    own.request
                        .plan
                        .enrollment()
                        .identity
                        .network_profile_id
                        .clone(),
                    actual.proposal().input().proposal_id.clone(),
                    own.request.plan.common_context.candidate_revision,
                ));
                actual.check_current(host.access()?)?;
                read.check()
            })?;
            let (network_profile_id, proposal_id, proposal_revision) =
                context.ok_or(Error::Authentication)?;
            let digest = wholepact_store::request_digest(&serde_json::json!([
                "synthetic-original-named-pair-v1",
                scope,
                actual_born.account_id,
            ]))?;
            let pairing = host.terminal.approve_publication_reviewed(&read, &digest,
                "SYNTHETIC JOINED CONTROLLER TEST: pair this exact fresh named request-only scope with the SAME retained original installed signer process and complete its authenticated Status handshake. Separate signer exact Pair/local enrollment/manifest reviews remain mandatory. No FVK disclosure, signature or dispatch is authorized.")?;
            // Distinct immutable purposes: the retained request-only grant is
            // capped by the original scenario AND actual native peer/source;
            // the initial Pair ceremony also keeps its shorter approvals.
            let grant_deadline = original_scenario_deadline.min(peer.deadline);
            let deadline = pairing.deadline().min(read.deadline()).min(grant_deadline);
            let original_pair_scope = scope.clone();
            let check_pair_ceremony = || {
                read.check().map_err(|_| BridgeError::Permission)?;
                host.require_manual_session()
                    .map_err(|_| BridgeError::Permission)?;
                if Instant::now() >= deadline {
                    return Err(BridgeError::Permission);
                }
                Ok(())
            };
            let pending = diagnostic::host(B::ProvedNamedPair, || {
                pairing.commit(
                    &digest,
                    || {
                        host.require_manual_session()?;
                        Ok(())
                    },
                    |_| {
                        OriginalHistoryClient::begin_born_pair_checked_until(
                            peer.provider,
                            &peer.endpoint,
                            "synthetic-original-born-named-profile-v1",
                            scope,
                            grant_deadline,
                            check_pair_ceremony,
                        )
                        .map_err(|_| Error::Permission)
                    },
                )
            })?;
            signers
                .send(Command::PollOriginalNamedPayment(actual_born.index))
                .map_err(failed)?;
            let client = diagnostic::host(B::ProvedNamedStatus, || {
                pending
                    .finish_checked(check_pair_ceremony)
                    .map_err(|_| Error::Permission)
            })?;
            diagnostic::host(B::ProvedNamedRecords, || {
                match signers.receive().map_err(failed)? {
                    Reply::Done { index } if index == actual_born.index => Ok(()),
                    _ => Err(Error::Authentication),
                }
            })?;
            let profile = diagnostic::host(B::ProvedNamedProfile, || {
                signers
                    .send(Command::RetainOriginalNamedProfile(
                        actual_born.index,
                        snapshot,
                        host_public.clone(),
                    ))
                    .map_err(failed)?;
                match signers.receive().map_err(failed)? {
                    Reply::OriginalProfile(profile)
                        if profile.index() == actual_born.index
                            && profile.account_id() == actual_born.account_id =>
                    {
                        Ok(profile)
                    }
                    _ => Err(Error::Authentication),
                }
            })?;
            if client.pairing_scope() != &original_pair_scope
                || client.pairing_scope().account_id != profile.account_id()
                || client.pairing_scope().participant_id != actual_born.participant_id
                || client.pairing_scope().agreement_id != AGREEMENT_ID
                || !client.pairing_scope().history_read
                || client.pairing_scope().authorization_export
                || client.pairing_scope().preconstruction_export
            {
                return Err(Error::Authentication);
            }
            let peer_key = profile.signer_public_key().clone();
            diagnostic::host(B::ProvedNativePins, || {
                check_scenario(original_scenario_deadline)?;
                // Selection is inert public context from actual source/profile.
                // Ordinary Authority::pin itself performs the genuine native
                // session-scoped confirmation and refuses replacement pins.
                let outgoing = MessageContext {
                    network_profile_id: network_profile_id.clone(),
                    agreement_id: AGREEMENT_ID.into(),
                    proposal_id: proposal_id.clone(),
                    proposal_revision,
                    sender_id: format!("born-offline-checkpoint:{}", host_public.fingerprint()),
                    recipient_id: format!("born-offline-checkpoint:{}", peer_key.fingerprint()),
                    artifact_kind: ArtifactKind::BornOfflineCheckpointOriginV1,
                };
                host.authority.pin(
                    &host.access()?.principal_id,
                    outgoing,
                    TransportDirection::Outgoing,
                    peer_key.clone(),
                )?;
                let incoming = MessageContext {
                    network_profile_id,
                    agreement_id: AGREEMENT_ID.into(),
                    proposal_id,
                    proposal_revision,
                    sender_id: format!("born-offline-return:{}", peer_key.fingerprint()),
                    recipient_id: format!("born-offline-return:{}", host_public.fingerprint()),
                    artifact_kind: ArtifactKind::BornOfflineAuthorizationReturnV1,
                };
                host.authority.pin(
                    &host.access()?.principal_id,
                    incoming,
                    TransportDirection::Incoming,
                    peer_key.clone(),
                )
            })?;
            let carrier = diagnostic::host(B::ProvedCarrierPrepare, || {
                host.prepare_born_offline_checkpoint_carrier_v1(
                    AGREEMENT_ID,
                    CONSTRUCTION_KEY,
                    &actual_born.account_id,
                    &peer_key,
                    None,
                )
            })?;
            require_original_proof(&carrier, &summary, &self, actual_born)?;
            let plan = carrier.export_plan().clone();
            let origin_digest = carrier
                .origin()
                .digest()
                .map_err(|_| Error::Authentication)?;
            let ciphertext_file =
                exports.join(format!("owner-{}-checkpoint.hpke", actual_born.index));
            let exported = diagnostic::host(B::ProvedCarrierExport, || {
                carrier.export_to(&ciphertext_file)
            })?;
            if exported.export_plan != plan
                || exported.checkpoint_origin_digest != origin_digest
                || exported.recovered_original_ciphertext
            {
                return Err(Error::Authentication);
            }
            // Export consumes its native owner. NEW explicit private-read and
            // retention approvals reopen only the SAME immutable plan/outbox
            // original. No second export, reseal or packet-time renewal occurs.
            let carrier = diagnostic::host(B::ProvedCarrierRecover, || {
                host.prepare_born_offline_checkpoint_carrier_v1(
                    AGREEMENT_ID,
                    CONSTRUCTION_KEY,
                    &actual_born.account_id,
                    &peer_key,
                    Some(plan),
                )
            })?;
            require_original_proof(&carrier, &summary, &self, actual_born)?;
            diagnostic::host(B::ProvedCarrierRetained, || {
                let retained = carrier.retained_export()?;
                if retained.ciphertext_digest() != exported.ciphertext_digest
                    || retained
                        .origin()
                        .digest()
                        .map_err(|_| Error::Authentication)?
                        != origin_digest
                {
                    return Err(Error::Authentication);
                }
                retained.check_current()
            })?;
            owners.push(CarriedJoinedOwnerV1 {
                profile,
                witness_key,
                ciphertext_file,
                carrier,
            });
            original_clients.push(client);
        }
        diagnostic::host(B::ProvedCarrierInvariant, || {
            check_scenario(original_scenario_deadline)?;
            if owners.len() != 2
                || original_clients.len() != owners.len()
                || host.require_financial_generation_admission().is_ok()
            {
                return Err(Error::Authentication);
            }
            for (owner, client) in owners.iter().zip(&original_clients) {
                if owner.profile.account_id() != client.pairing_scope().account_id {
                    return Err(Error::Authentication);
                }
                owner.carrier.check_current()?;
            }
            Ok(())
        })?;
        Ok(CarriedJoinedStageV1 {
            constructed: self,
            owners,
            original_clients,
            host_public,
        })
    }
}

fn require_original_proof(
    carrier: &PreparedBornOfflineCheckpointCarrierV1<'_>,
    actual_summary: &JobSummary,
    constructed: &ConstructedJoinedStageV3<'_>,
    born: &PublicJoinedBornV1,
) -> Result<()> {
    carrier.check_current()?;
    if carrier.original().claim() != constructed.original.claim()
        || carrier.original().receipt() != constructed.original.receipt()
        || carrier.original().checkpoint().summary() != actual_summary
        || carrier.origin().account_id != born.account_id
        || carrier.origin().full_viewing_key_digest != born.full_viewing_key_digest
    {
        return Err(Error::Authentication);
    }
    carrier.check_current()
}
