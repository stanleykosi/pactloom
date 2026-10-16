//! A distinct native privacy decision before construction. An accepted manifest
//! and pairing do not alone authorize sharing full viewing capability.
use super::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use crate::authority_bridge::{
    self, BridgeError,
    dispatch_ipc::write_frame,
    preconstruction_ipc::{
        PreconstructionCommand, PreconstructionRequest, PreconstructionResponse,
    },
};
use crate::{
    Error, Result,
    account::AccountVault,
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use sha2::{Digest, Sha256};
use std::{
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(super) struct PreparedPreconstruction {
    request: PreconstructionRequest,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    source: NativeAuthorityBinding,
    fvk_digest: String,
    digest: String,
    display: Zeroizing<String>,
    started: Instant,
    sponsor_witness: Option<std::sync::Arc<super::witness_workspace::NativeWitnessWorkspace>>,
    sponsor_budget: Option<wholepact_authority::AccountSnapshot>,
}
pub(super) struct ApprovedPreconstruction {
    prepared: PreparedPreconstruction,
    fvk: Zeroizing<[u8; 96]>,
    sponsor_binding: Option<crate::consent_journal::ApprovedSponsorManifestBinding>,
}
fn error(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
fn validate_records(
    request: &PreconstructionRequest,
    peer: &AuthenticatedPeer,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    fvk_digest: &str,
) -> authority_bridge::Result<()> {
    let proposal = request.validate()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    let scope = &request.scope;
    if !peer.scope.preconstruction_export
        || peer.scope.account_id != scope.account_id
        || peer.scope.participant_id != scope.participant_id
        || peer.scope.agreement_id != proposal.manifest().agreement.agreement_id
        || peer.scope.manifest_digest != proposal.manifest_digest()
    {
        return Err(BridgeError::Permission);
    }
    let enrollment = journal
        .enrollment(&request.enrollment_ref, session)?
        .ok_or(BridgeError::Missing)?;
    let accepted = journal
        .accepted_manifest(&request.accepted_manifest_ref, session)?
        .ok_or(BridgeError::Missing)?;
    if enrollment.account_id() != scope.account_id
        || enrollment.participant_id() != scope.participant_id
        || enrollment.agreement_id() != proposal.manifest().agreement.agreement_id
        || enrollment.account_fvk_digest() != fvk_digest
        || accepted.enrollment_ref() != enrollment.reference()
        || accepted.manifest_digest() != proposal.manifest_digest()
        || accepted.proposal_input() != &scope.proposal
    {
        return Err(BridgeError::Binding);
    }
    // An established binding cannot be silently stripped from a later request.
    // This short lease is dropped before staging any native mutation.
    let lease = journal.acquire_preconstruction_records(
        &request.enrollment_ref,
        &request.accepted_manifest_ref,
        session,
    )?;
    lease.require_native_origin(&peer.native_origin)?;
    if lease.sponsor_required() && request.sponsor_policy.is_none() {
        return Err(BridgeError::Binding);
    }
    if let Some(policy) = lease.sponsor_policy() {
        if request.sponsor_policy.as_ref() != Some(&policy.terms) {
            return Err(BridgeError::Binding);
        }
    }
    Ok(())
}
impl PreparedPreconstruction {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        request: PreconstructionRequest,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        authority: &NativeAuthorityBinding,
        vault: &AccountVault,
        witness: Option<std::sync::Arc<super::witness_workspace::NativeWitnessWorkspace>>,
    ) -> Result<Self> {
        authority.check_current()?;
        if &peer.native_origin != authority
            || vault.account().recovery_required()
            || vault.account_id()? != request.scope.account_id
            || vault.account().privacy_domain() != request.scope.privacy_domain
        {
            return Err(Error::ReviewMismatch);
        }
        let fvk_digest = hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes()));
        validate_records(&request, &peer, journal, session, &fvk_digest).map_err(error)?;
        let (sponsor_witness, sponsor_budget) = if let Some(terms) = &request.sponsor_policy {
            let witness = witness.ok_or(Error::Unavailable)?;
            witness.check_current()?;
            let history = witness.client().reconcile_history().map_err(error)?;
            let budget = history.snapshot().clone();
            let formula = wholepact_core::sponsor::evaluate_sponsor_policy(
                terms,
                request.validate().map_err(error)?.manifest(),
            )
            .map_err(error)?;
            let used = budget
                .outstanding_debit_zatoshis
                .checked_add(budget.settled_debit_zatoshis)
                .ok_or(Error::ReviewMismatch)?;
            if budget.account_id != request.scope.account_id
                || budget.network_profile_id != terms.network_profile_id
                || budget.aggregate_budget_zatoshis > terms.aggregate_budget.as_zatoshis()
                || budget.writer_status != wholepact_authority::WriterStatus::Active
                || formula.sponsor_net_debit.as_zatoshis()
                    > budget.remaining_budget_zatoshis().map_err(error)?
                || used
                    .checked_add(formula.sponsor_net_debit.as_zatoshis())
                    .is_none_or(|v| v > terms.aggregate_budget.as_zatoshis())
            {
                return Err(Error::ReviewMismatch);
            }
            (Some(witness), Some(budget))
        } else {
            (None, None)
        };
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-preconstruction-review:v1",
            &(
                &request,
                &fvk_digest,
                &sponsor_budget,
                &peer.grant_id,
                &peer.channel_digest,
                crate::vault::random::<32>()?,
            ),
        )
        .map_err(error)?;
        let mut display = Zeroizing::new(format!(
            "DISCLOSE DEDICATED ACCOUNT VIEWING CAPABILITY\n\nExact accepted construction and disclosure scope:\n{}\n\nActual recipient: locally paired application {} (PID {}, UID {}, grant {}). This identifies an OS process, not a publisher or remote participant.\n\nThis separately approves exporting this account's FULL VIEWING KEY to the named local host and importing it into the exact encrypted wallet destination. The constructor/prover receives selected notes, witnesses, values and outputs. The complete listed participant reviewer roster receives the broad review evidence required by this construction. Those remote account names are not authenticated by local process identity; onward sharing requires independently authenticated recipients.\n\nFULL VIEWING KEY DISCLOSURE IS PERSISTENT AND CANNOT BE REVOKED. It reveals this dedicated privacy domain's past and future activity, not just selected inputs. Account reuse can expose unrelated payments. Retention statements are the operator's commitments, not technical erasure guarantees. Lock, timeout and lease expiry prevent new authorized operations but cannot retract material already copied.\n\nThe named public-block provider and configured proxy can observe IP, timing, heights and history ranges; no FVK is sent to that provider. Its snapshot is not independent consensus or proof of unspentness. The birthday is an accepted source claim and may omit history if incorrect. Provider contact and selection are bounded by this exact scope; no provider substitution is permitted.\n\nNo spending key leaves the signer. This decision does not sign, reserve inputs, authorize transaction release or prove payment. Exact spending review remains separate.\n\nReview binding: {}",
            serde_json::to_string_pretty(&request).map_err(error)?,
            peer.label,
            peer.peer.pid(),
            peer.peer.uid(),
            peer.grant_id,
            digest
        ));
        if let Some(terms) = &request.sponsor_policy {
            let key = wholepact_core::proposal::canonical_digest(
                "wholepact:sponsor-policy-terms:v1",
                terms,
            )
            .map_err(error)?;
            display.push_str(&format!("\nInitial native sponsor policy key: {key}\nExisting native policy updates retain their original stable key and current version; this terms digest is not proof of identity or approval."));
        }
        if let Some(budget) = &sponsor_budget {
            display.push_str(&format!("\n\nSEPARATE SPONSOR BUDGET DISCLOSURE: Approving also shares this account's complete pending/settled/lifetime-limit totals and witness head with the paired local constructor, for the exact sponsor policy above. This exposes sensitive spending information. Current snapshot: {}\nYou explicitly select the policy's named local verifier as a trusted ATTESTATION source for participant/account attribution. Its actual paired OS process, PID, UID and grant are shown above and bound to this decision; the name alone grants no authority. This verifier will attest the exact participant/account/FVK roster from independently approved owner disclosures. The signer will separately verify transaction commitments against that roster. This is attested attribution, not independent protocol proof of role identity, distinct people, organizations or independent economic sources. This also installs the exact sponsor constraints in this signer for this immutable accepted manifest. Later signing must enforce their current version, pause/revocation, expiry and the same shared witness budget; the snapshot itself reserves nothing.", serde_json::to_string(budget).map_err(error)?));
        }
        Ok(Self {
            sponsor_witness,
            sponsor_budget,
            request,
            peer,
            stream,
            source: authority.clone(),
            fvk_digest,
            digest,
            display,
            started: Instant::now(),
        })
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
    ) -> Result<ApprovedPreconstruction> {
        self.source.check_current()?;
        authority.check_current()?;
        self.peer.check_current()?;
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
        let fvk = Zeroizing::new(vault.account().fvk()?.to_bytes());
        if hex::encode(Sha256::digest(*fvk)) != self.fvk_digest {
            return Err(Error::ReviewMismatch);
        }
        let sponsor_binding = self
            .request
            .sponsor_policy
            .as_ref()
            .map(|terms| {
                crate::consent_journal::ApprovedSponsorManifestBinding::from_native(
                    terms.clone(),
                    self.request.accepted_manifest_ref.clone(),
                    &self.source,
                    &self.digest,
                    self.sponsor_budget.as_ref().ok_or(Error::ReviewMismatch)?,
                    &self.peer,
                    &decision,
                )
                .map_err(error)
            })
            .transpose()?;
        Ok(ApprovedPreconstruction {
            prepared: self,
            fvk,
            sponsor_binding,
        })
    }
}
impl ApprovedPreconstruction {
    pub(super) fn serve(
        mut self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
    ) -> authority_bridge::Result<()> {
        if let Some(binding) = self.sponsor_binding.take() {
            journal.record_sponsor_manifest_binding(binding, session)?;
        }
        // Acquire one read fence before disclosure and hold it through the host's
        // final commit, including an ambiguous disconnect. Never nest journal reads
        // inside the check while a revocation writer might be waiting.
        let lease = journal.acquire_preconstruction_records(
            &self.prepared.request.enrollment_ref,
            &self.prepared.request.accepted_manifest_ref,
            session,
        )?;
        lease.require_native_origin(&self.prepared.source)?;
        // Repeat under the held fence: another native policy decision between
        // staging and disclosure must not yield a downgraded construction lease.
        if lease.sponsor_policy().map(|p| &p.terms) != self.prepared.request.sponsor_policy.as_ref()
        {
            return Err(BridgeError::Binding);
        }
        let proposal = self.prepared.request.validate()?;
        if lease.enrollment().account_fvk_digest() != self.prepared.fvk_digest
            || lease.enrollment().account_id() != self.prepared.request.scope.account_id
            || lease.enrollment().participant_id() != self.prepared.request.scope.participant_id
            || lease.enrollment().agreement_id() != proposal.manifest().agreement.agreement_id
            || lease.manifest().proposal_input() != &self.prepared.request.scope.proposal
        {
            return Err(BridgeError::Binding);
        }
        let started = Instant::now();
        let check = |p: &PreparedPreconstruction| -> authority_bridge::Result<()> {
            p.source
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            if started.elapsed() >= Duration::from_secs(900) {
                return Err(BridgeError::Permission);
            }
            p.peer
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
            lease.check_current()?;
            if let (Some(witness), Some(budget)) = (&p.sponsor_witness, &p.sponsor_budget) {
                witness
                    .check_current()
                    .map_err(error)
                    .map_err(|_| BridgeError::Permission)?;
                if witness
                    .client()
                    .snapshot()
                    .map_err(|_| BridgeError::Permission)?
                    != *budget
                {
                    return Err(BridgeError::Binding);
                }
            }
            Ok(())
        };
        check(&self.prepared)?;
        // The request's entire native approval is consumed before material exists
        // on the wire. A failed send is possible disclosure, never safe retraction.
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        let sent = write_frame(
            &mut self.prepared.stream,
            &PreconstructionResponse::Disclosed {
                lease_id: lease_id.clone(),
                request_digest: self.prepared.request.digest()?,
                account_fvk_hex: hex::encode(*self.fvk),
                sponsor_budget: self.prepared.sponsor_budget.clone().map(Box::new),
            },
        );
        if sent.is_err() {
            retain_until_finished(&mut self.prepared.stream, &self.prepared.peer);
            return Err(BridgeError::Ipc);
        }
        loop {
            let command = crate::ipc::read_frame_with_deadline(
                &self.prepared.stream,
                &self.prepared.peer.peer,
                Duration::from_secs(120),
            )
            .ok()
            .and_then(|frame| serde_json::from_slice::<PreconstructionCommand>(&frame).ok());
            match command {
                Some(PreconstructionCommand::Finish) => {
                    let _ = write_frame(
                        &mut self.prepared.stream,
                        &PreconstructionResponse::Finished,
                    );
                    return Ok(());
                }
                Some(PreconstructionCommand::AttestSponsorOwners { attestation })
                    if check(&self.prepared).is_ok()
                        && self.prepared.request.sponsor_policy.is_some() =>
                {
                    let attestation_digest = wholepact_core::proposal::canonical_digest(
                        "wholepact:sponsor-owner-attestation:v1",
                        &attestation,
                    )
                    .map_err(|_| BridgeError::Binding)?;
                    journal.record_sponsor_owner_attestation(
                        &lease,
                        &self.prepared.peer,
                        attestation,
                    )?;
                    check(&self.prepared)?;
                    write_frame(
                        &mut self.prepared.stream,
                        &PreconstructionResponse::SponsorAttestationRetained {
                            lease_id: lease_id.clone(),
                            attestation_digest,
                        },
                    )?;
                    continue;
                }
                Some(PreconstructionCommand::CheckCurrent) if check(&self.prepared).is_ok() => {
                    if write_frame(
                        &mut self.prepared.stream,
                        &PreconstructionResponse::Current {
                            lease_id: lease_id.clone(),
                        },
                    )
                    .is_ok()
                    {
                        continue;
                    }
                }
                _ => {
                    let _ =
                        write_frame(&mut self.prepared.stream, &PreconstructionResponse::Denied);
                }
            }
            retain_until_finished(&mut self.prepared.stream, &self.prepared.peer);
            return Err(BridgeError::Permission);
        }
    }
}
fn retain_until_finished(stream: &mut UnixStream, peer: &AuthenticatedPeer) {
    while peer.peer.check_alive().is_ok() {
        if crate::ipc::read_frame_with_deadline(stream, &peer.peer, Duration::from_secs(2))
            .ok()
            .and_then(|frame| serde_json::from_slice::<PreconstructionCommand>(&frame).ok())
            .is_some_and(|command| matches!(command, PreconstructionCommand::Finish))
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
