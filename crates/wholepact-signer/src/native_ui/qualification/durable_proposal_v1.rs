//! Finite synthetic delivery through the genuine NEW durable native entry.
//!
//! This is a runtime child, not an authority factory. It owns a genuinely born,
//! never-funded temporary account, drives the maintained native review machine,
//! and drains every real owner before returning the historical fixture. No FVK,
//! decision, writer credential, wallet ticket or signing capability is exposed.
//! A host leaf must independently own encrypted intake, proof and exact union.

use super::*;
use crate::authority_bridge::{
    durable_construction_v1::{
        DurableConstructionCaptureRequestV1, DurableConstructionHistoryRequestV1,
        DurableConstructionRedisclosureRequestV1, DurableConstructionRequestV1,
    },
    durable_review_ipc_v1::DurableReviewDeliveryRequestV1,
    preconstruction_ipc::PreconstructionRequest,
};
use crate::native_ui::pending_enrollment::born_pending_continuation::AcknowledgedBornFixture;
use std::{path::PathBuf, time::Instant};
use wholepact_signer_origin::{InstalledSignerProvider, PairScope};

const EPOCH: u64 = 1;

/// Public correlation only. These exact references never restore a session.
#[derive(Clone, PartialEq, Eq)]
pub struct DurableNativeRecordsV1 {
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pair,
    Paired,
    Accepted,
    Disclosure,
    Disclosed,
    Imported,
}

enum ExpectedDisclosure {
    Initial(PreconstructionRequest),
    Durable(DurableConstructionRequestV1),
    Capture(DurableConstructionCaptureRequestV1, PreconstructionRequest),
}

pub(in crate::native_ui) struct DurableNativeFixtureV1 {
    // Drop drains this runtime before releasing the temporary source lifetime.
    runtime: NativeRuntime,
    original: Option<AcknowledgedBornFixture>,
    proposal: Proposal,
    scope: PairScope,
    budget: u64,
    phase: Phase,
    expected: Option<ExpectedDisclosure>,
    entry: String,
}

impl DurableNativeFixtureV1 {
    pub(in crate::native_ui) fn open(
        original: AcknowledgedBornFixture,
        input: ProposalInput,
        budget: u64,
    ) -> Result<Self> {
        let proposal = Proposal::validate(input).map_err(|_| Error::Verification)?;
        require_plain_two_owner_manifest(&proposal, &original.account_id)?;
        if !original.root.starts_with(original.temporary.path())
            || original.root == original.temporary.path()
            || budget == 0
        {
            return Err(Error::ReviewMismatch);
        }
        let participant = proposal
            .manifest()
            .participants
            .iter()
            .find(|p| p.account_id == original.account_id)
            .ok_or(Error::ReviewMismatch)?;
        let scope = PairScope {
            account_id: original.account_id.clone(),
            agreement_id: proposal.manifest().agreement.agreement_id.clone(),
            participant_id: participant.participant_id.clone(),
            manifest_digest: proposal.manifest_digest().into(),
            history_read: true,
            authorization_export: true,
            preconstruction_export: true,
        };
        let mut runtime = NativeRuntime::new(None);
        runtime.root = original.root.to_str().ok_or(Error::InvalidData)?.into();
        runtime.password = Zeroizing::new(
            crate::native_ui::birth_workspace::born_roster_v3::SYNTHETIC_PENDING_PASSWORD.into(),
        );
        // The actual focused-click gate must reject before KDF/native creation.
        if runtime.begin_durable_entry_v1(false, EPOCH).is_ok()
            || runtime.begin_durable_entry_v1(true, 0).is_ok()
            || runtime.open.is_some()
            || runtime.durable_entry_job.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        runtime.begin_durable_entry_v1(true, EPOCH)?;
        while runtime.durable_entry_job.is_some() {
            runtime.poll_durable_entry_v1(true, EPOCH);
            std::thread::sleep(Duration::from_millis(2));
        }
        let open = runtime.open.as_ref().ok_or(Error::RecoveryRequired)?;
        let source = open
            .durable_born_entry
            .as_ref()
            .ok_or(Error::RecoveryRequired)?;
        source.check_current()?;
        let OpenNativeAuthority::DurableBorn(actual_owner) = &open.authority else {
            return Err(Error::ReviewMismatch);
        };
        if !Arc::ptr_eq(actual_owner, source.native_owner())
            || open.vault.account_id()? != original.account_id
            || source.genesis().identity.account_id != original.account_id
            || open.session.is_some()
            || open.pairing.is_some()
            || open.enrollment.is_some()
            || open.manifest.is_some()
            || open.writer_receipt.is_some()
            || open.writer_reconciled
        {
            return Err(Error::ReviewMismatch);
        }
        let entry = open.authority.binding().entry_digest().to_owned();
        Ok(Self {
            runtime,
            original: Some(original),
            proposal,
            scope,
            budget,
            phase: Phase::Pair,
            expected: None,
            entry,
        })
    }
    fn check(&self) -> Result<()> {
        let original = self.original.as_ref().ok_or(Error::Locked)?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let source = open.durable_born_entry.as_ref().ok_or(Error::Locked)?;
        source.check_current()?;
        if open.vault.account_id()? != original.account_id
            || open.authority.binding().entry_digest() != self.entry
            || open.authority.binding() != source.native_binding()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(in crate::native_ui) fn endpoint(&self) -> Result<PathBuf> {
        self.check()?;
        Ok(self
            .runtime
            .open
            .as_ref()
            .ok_or(Error::Locked)?
            .ipc
            .socket_path()
            .to_path_buf())
    }
    pub(in crate::native_ui) fn provider(&self) -> Result<InstalledSignerProvider> {
        self.check()?;
        InstalledSignerProvider::qualification_current_process().map_err(|_| Error::Authentication)
    }
    pub(in crate::native_ui) fn deadline(&self) -> Result<Instant> {
        self.check()?;
        self.runtime
            .open
            .as_ref()
            .ok_or(Error::Locked)?
            .authority
            .binding()
            .bounded_deadline()
    }
    pub(in crate::native_ui) fn scope(&self) -> &PairScope {
        &self.scope
    }
    pub(in crate::native_ui) fn entry_digest(&self) -> &str {
        &self.entry
    }

    /// Only the predetermined exact Pair can be approved. A genuine Status
    /// challenge must subsequently establish possession before enrollment.
    pub(in crate::native_ui) fn poll_pair(&mut self) -> Result<bool> {
        self.check()?;
        if !matches!(self.phase, Phase::Pair | Phase::Paired) {
            return Err(Error::ReviewMismatch);
        }
        self.runtime.poll(EPOCH);
        if let Some(pending) = &self.runtime.pending {
            if self.phase != Phase::Pair
                || !matches!(&pending.operation,
                Operation::Pair(pair) if pair.scope == self.scope)
            {
                return Err(Error::ReviewMismatch);
            }
            approve(&mut self.runtime)?;
            self.phase = Phase::Paired;
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        if let Some(pairing) = &open.pairing {
            pairing.check_current()?;
            if pairing.peer.scope != self.scope || open.session.is_none() {
                return Err(Error::ReviewMismatch);
            }
            return Ok(self.phase == Phase::Paired);
        }
        Ok(false)
    }
    pub(in crate::native_ui) fn accept_exact_manifest(&mut self) -> Result<DurableNativeRecordsV1> {
        self.check()?;
        if self.phase != Phase::Paired {
            return Err(Error::ReviewMismatch);
        }
        self.runtime.proposal = Zeroizing::new(
            serde_json::to_string(self.proposal.input()).map_err(|_| Error::InvalidData)?,
        );
        self.runtime.budget = self.budget.to_string();
        self.runtime.stage_enrollment(EPOCH)?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::Enroll(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve(&mut self.runtime)?;
        self.runtime.stage_manifest(EPOCH)?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::Manifest(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve(&mut self.runtime)?;
        self.phase = Phase::Accepted;
        self.records()
    }
    pub(in crate::native_ui) fn records(&self) -> Result<DurableNativeRecordsV1> {
        self.check()?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let enrollment = open.enrollment.as_ref().ok_or(Error::ReviewMismatch)?;
        let manifest = open.manifest.as_ref().ok_or(Error::ReviewMismatch)?;
        if manifest.proposal_input() != self.proposal.input()
            || manifest.enrollment_ref() != enrollment.reference()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(DurableNativeRecordsV1 {
            enrollment_ref: enrollment.reference().into(),
            accepted_manifest_ref: manifest.reference().into(),
        })
    }
    pub(in crate::native_ui) fn expect_initial_disclosure(
        &mut self,
        request: PreconstructionRequest,
    ) -> Result<()> {
        self.check()?;
        request.validate().map_err(|_| Error::Verification)?;
        let refs = self.records()?;
        if self.phase != Phase::Accepted
            || request.sponsor_policy.is_some()
            || request.scope.proposal != *self.proposal.input()
            || request.scope.account_id != self.scope.account_id
            || request.scope.participant_id != self.scope.participant_id
            || request.enrollment_ref != refs.enrollment_ref
            || request.accepted_manifest_ref != refs.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        self.expected = Some(ExpectedDisclosure::Initial(request));
        self.phase = Phase::Disclosure;
        Ok(())
    }
    pub(in crate::native_ui) fn expect_durable_disclosure(
        &mut self,
        request: DurableConstructionRequestV1,
    ) -> Result<()> {
        self.check()?;
        request.validate().map_err(|_| Error::Verification)?;
        let refs = self.records()?;
        if self.phase != Phase::Accepted
            || request.scope.version != 2
            || request.scope.proposal != *self.proposal.input()
            || request.scope.account_id != self.scope.account_id
            || request.scope.participant_id != self.scope.participant_id
            || request.enrollment_ref != refs.enrollment_ref
            || request.accepted_manifest_ref != refs.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        self.expected = Some(ExpectedDisclosure::Durable(request));
        self.phase = Phase::Disclosure;
        Ok(())
    }
    pub(in crate::native_ui) fn expect_durable_capture(
        &mut self,
        request: DurableConstructionCaptureRequestV1,
    ) -> Result<()> {
        self.check()?;
        let Some(ExpectedDisclosure::Initial(initial)) = &self.expected else {
            return Err(Error::ReviewMismatch);
        };
        let refs = self.records()?;
        if self.phase != Phase::Disclosed
            || request.scope.version != 2
            || request.scope.proposal != *self.proposal.input()
            || request.scope.account_id != self.scope.account_id
            || request.scope.participant_id != self.scope.participant_id
            || request.enrollment_ref != refs.enrollment_ref
            || request.accepted_manifest_ref != refs.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        request.scope.validate().map_err(|_| Error::Verification)?;
        self.expected = Some(ExpectedDisclosure::Capture(request, initial.clone()));
        self.phase = Phase::Disclosure;
        Ok(())
    }
    /// Derive only expected immutable data from the actual original journal.
    /// This does not issue the redisclosure; its separate native decision must
    /// consume the maintained prepared operation from the real IPC request.
    pub(in crate::native_ui) fn expect_redisclosure(
        &mut self,
        request: DurableConstructionRedisclosureRequestV1,
    ) -> Result<()> {
        self.check()?;
        request.validate().map_err(|_| Error::Verification)?;
        let refs = self.records()?;
        if self.phase != Phase::Accepted
            || request.enrollment_ref != refs.enrollment_ref
            || request.accepted_manifest_ref != refs.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let original = open
            .journal
            .prepare_durable_construction_redisclosure_source_v1(
                &request.original,
                open.session.as_ref().ok_or(Error::Locked)?,
            )
            .map_err(|_| Error::ReviewMismatch)?;
        if original.redisclosure().is_some()
            || original.request().enrollment_ref == refs.enrollment_ref
            || original.request().accepted_manifest_ref == refs.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        // Attack: the old account is genuine, but its old accepted records are
        // NOT current native authority. Exercise the maintained preparation with
        // the actual current authenticated peer and expect refusal before review.
        // This local negative-only stream never supplies a positive issuer.
        let mut stale = request.clone();
        stale.enrollment_ref = original.request().enrollment_ref.clone();
        stale.accepted_manifest_ref = original.request().accepted_manifest_ref.clone();
        let (rejected_stream, _discarded_peer) =
            std::os::unix::net::UnixStream::pair().map_err(|_| Error::Unavailable)?;
        if crate::native_ui::durable_construction_v1::PreparedDurableConstructionV1::prepare_redisclosure(
            stale, open.pairing.as_ref().ok_or(Error::Locked)?.peer.clone(), rejected_stream,
            &open.journal, open.session.as_ref().ok_or(Error::Locked)?,
            &open.authority.binding(), &open.vault,
        ).is_ok() {
            return Err(Error::ReviewMismatch);
        }
        let grant = &open.pairing.as_ref().ok_or(Error::Locked)?.peer.key_digest;
        let mut expected = original.request().clone();
        expected.operation_id = request.operation_id;
        expected.enrollment_ref = refs.enrollment_ref;
        expected.accepted_manifest_ref = refs.accepted_manifest_ref;
        expected.scope.constructor.authenticated_local_grant_digest = grant.clone();
        expected.scope.prover.authenticated_local_grant_digest = grant.clone();
        self.expected = Some(ExpectedDisclosure::Durable(expected));
        self.phase = Phase::Disclosure;
        Ok(())
    }
    pub(in crate::native_ui) fn poll_disclosure(&mut self) -> Result<bool> {
        self.check()?;
        if self.phase == Phase::Disclosed {
            return Ok(true);
        }
        if self.phase != Phase::Disclosure {
            return Err(Error::ReviewMismatch);
        }
        self.runtime.poll(EPOCH);
        let Some(pending) = &self.runtime.pending else {
            return Ok(false);
        };
        let same = match (&self.expected, &pending.operation) {
            (Some(ExpectedDisclosure::Initial(request)), Operation::Preconstruction(prepared)) => {
                prepared
                    .qualification_request_digest()
                    .map_err(|_| Error::Verification)?
                    == request.digest().map_err(|_| Error::Verification)?
            }
            (
                Some(ExpectedDisclosure::Durable(request)),
                Operation::DurableConstructionV1(prepared),
            ) => {
                prepared
                    .qualification_request_digest()
                    .map_err(|_| Error::Verification)?
                    == request.digest().map_err(|_| Error::Verification)?
            }
            (
                Some(ExpectedDisclosure::Capture(expected, initial)),
                Operation::DurableConstructionV1(prepared),
            ) => {
                let actual = prepared.qualification_request();
                let evidence = actual
                    .material
                    .historical_review_evidence()
                    .map_err(|_| Error::Verification)?;
                let summary = actual.material.review_summary();
                actual.operation_id == expected.operation_id
                    && actual.enrollment_ref == expected.enrollment_ref
                    && actual.accepted_manifest_ref == expected.accepted_manifest_ref
                    && actual.scope == expected.scope
                    && evidence.account_id == self.scope.account_id
                    && evidence.context.anchor_height == initial.scope.anchor_height
                    && summary["historical_source"]["source_id"].as_str()
                        == Some(initial.scope.provider.source_id.as_str())
                    && summary["historical_source"]["endpoint"].as_str()
                        == Some(initial.scope.provider.endpoint.as_str())
                    && summary["historical_source"]["trust_profile"].as_str()
                        == Some(initial.scope.provider.trust_profile.as_str())
                    && evidence.inputs.len()
                        == self
                            .proposal
                            .manifest()
                            .inputs
                            .iter()
                            .filter(|input| input.account_id == self.scope.account_id)
                            .count()
                    && evidence.inputs.iter().all(|note| {
                        self.proposal.manifest().inputs.iter().any(|input| {
                            input.account_id == self.scope.account_id
                                && input.input_id == note.input_id
                                && input.amount.as_zatoshis() == note.value_zatoshis
                        })
                    })
            }
            _ => false,
        };
        if !same {
            return Err(Error::ReviewMismatch);
        }
        let captured = match &pending.operation {
            Operation::DurableConstructionV1(prepared) => {
                Some(prepared.qualification_request().clone())
            }
            _ => None,
        };
        approve(&mut self.runtime)?;
        if let Some(request) = captured {
            self.expected = Some(ExpectedDisclosure::Durable(request));
        }
        self.phase = Phase::Disclosed;
        Ok(true)
    }
    /// Assert the maintained native append committed its exact immutable request,
    /// not just that a review click returned. No outbox bytes leave via this API.
    pub(in crate::native_ui) fn durable_disclosure_committed(&self) -> Result<String> {
        self.check()?;
        let Some(ExpectedDisclosure::Durable(request)) = &self.expected else {
            return Err(Error::ReviewMismatch);
        };
        if self.phase != Phase::Disclosed {
            return Err(Error::ReviewMismatch);
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let outbox = open
            .journal
            .durable_construction_history_v1(
                &DurableConstructionHistoryRequestV1 {
                    operation_id: request.operation_id.clone(),
                    expected_request_digest: request.digest().map_err(|_| Error::Verification)?,
                },
                open.session.as_ref().ok_or(Error::Locked)?,
            )
            .map_err(|_| Error::ReviewMismatch)?;
        if outbox.request() != request {
            return Err(Error::ReviewMismatch);
        }
        Ok(outbox.reference().into())
    }
    pub(in crate::native_ui) fn configure_wallet(&mut self, setup_json: &str) -> Result<()> {
        self.check()?;
        if !matches!(self.phase, Phase::Accepted | Phase::Disclosed)
            || self.runtime.pending.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        self.runtime.wallet_setup = Zeroizing::new(setup_json.into());
        self.runtime.stage_wallet_setup(EPOCH)?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::Wallet(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve(&mut self.runtime)
    }
    /// Uses only the credential lifetime retained by this original nominal
    /// witness fixture; neither arbitrary paths nor caller witness pins enter.
    pub(in crate::native_ui) fn configure_original_witness(&mut self) -> Result<()> {
        self.check()?;
        let original = self.original.as_ref().ok_or(Error::Locked)?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let source = open.durable_born_entry.as_ref().ok_or(Error::Locked)?;
        let descriptor = source.original_witness_disclosure()?;
        let origin = original.credentials.origin();
        if descriptor.endpoint != origin.endpoint
            || descriptor.witness_id != origin.witness_id
            || descriptor.pinned_server_certificate_digest != origin.server_certificate_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let setup = |owner: bool| -> Result<Zeroizing<String>> {
            Ok(Zeroizing::new(serde_json::to_string(&serde_json::json!({
                "schema_version": 1, "endpoint": descriptor.endpoint,
                "server_name": descriptor.server_name, "witness_id": descriptor.witness_id,
                "account_id": descriptor.account_id, "network_profile_id": descriptor.network_profile_id,
                "policy_digest": descriptor.policy_digest,
                "pinned_server_certificate_digest": descriptor.pinned_server_certificate_digest,
                "trusted_server_root_der": origin.trusted_server_root_file,
                "client_certificate_der": if owner { &origin.owner_certificate_file } else { &origin.writer_certificate_file },
                "client_private_key_pkcs8_der": if owner { &origin.owner_key_file } else { &origin.writer_key_file },
                "operator_name": "Synthetic original never-funded witness",
                "retention_statement": "Exact temporary qualification original only"
            })).map_err(|_| Error::InvalidData)?))
        };
        let writer = setup(false)?;
        let owner = setup(true)?;
        self.runtime.witness_setup = writer;
        self.runtime.stage_witness_setup(EPOCH)?;
        approve(&mut self.runtime)?;
        self.runtime.owner_witness_setup = owner;
        self.runtime.stage_owner_witness_setup(EPOCH)?;
        approve(&mut self.runtime)
    }
    pub(in crate::native_ui) fn reconcile_original_writer(&mut self) -> Result<()> {
        self.check()?;
        self.runtime.prepare_writer_session(EPOCH)?;
        self.drain_witness_to_review()?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::WriterSession(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve(&mut self.runtime)?;
        self.drain_witness_to_review()?;
        self.runtime.prepare_writer_activation(EPOCH)?;
        self.drain_witness_to_review()?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::WriterActivation(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve(&mut self.runtime)?;
        self.drain_witness_to_review()?;
        self.runtime.prepare_writer_reconciliation(EPOCH)?;
        self.drain_witness_to_review()?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::Reconcile(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve(&mut self.runtime)?;
        self.drain_witness_to_review()?;
        if !self
            .runtime
            .open
            .as_ref()
            .is_some_and(|o| o.writer_reconciled)
        {
            return Err(Error::ReviewMismatch);
        }
        self.check()
    }
    fn drain_witness_to_review(&mut self) -> Result<()> {
        loop {
            self.check()?;
            self.runtime.poll_witness(EPOCH);
            if self
                .runtime
                .open
                .as_ref()
                .is_none_or(|o| o.witness_job.is_none())
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        self.check()
    }
    /// Called after each host IPC boundary while no approval is pending. Import
    /// success is still data-only: this method never starts financial review.
    pub(in crate::native_ui) fn poll_data_only(&mut self) -> Result<()> {
        self.check()?;
        self.runtime.poll(EPOCH);
        self.runtime.poll_durable_import_v1(EPOCH);
        if self.runtime.pending.is_some() {
            return Err(Error::ReviewMismatch);
        }
        self.check()
    }
    /// Imported is private memory only. It neither persists remote material nor
    /// starts a wallet review, financial decision, writer or signing operation.
    pub(in crate::native_ui) fn poll_exact_import(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<bool> {
        self.poll_data_only()?;
        if !matches!(self.phase, Phase::Disclosed | Phase::Imported) {
            return Err(Error::ReviewMismatch);
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        if open.writer_reconciled
            || open.writer_receipt.is_some()
            || open.durable_wallet_job.is_some()
            || self.runtime.signing_job.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let Some(imported) = &open.durable_review else {
            return Ok(false);
        };
        if &imported.request != request || imported.fixed.verified().identity() != identity {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::Imported;
        Ok(true)
    }
    pub(in crate::native_ui) fn close(mut self) -> Result<AcknowledgedBornFixture> {
        self.drain_close()?;
        self.original.take().ok_or(Error::Locked)
    }
    fn drain_close(&mut self) -> Result<()> {
        self.runtime.lock();
        // Finishing a previously admitted operation is not permission renewal.
        // Keep the real account directory and original witness fixture alive
        // until every close completion says the owner actually terminated.
        while self.runtime.signing_job.is_some() || !self.runtime.closing_accounts.is_empty() {
            self.runtime.poll_signing();
            self.runtime
                .closing_accounts
                .retain(|done| !done.load(Ordering::Acquire));
            std::thread::sleep(Duration::from_millis(2));
        }
        if self.runtime.open.is_some()
            || self.runtime.pending.is_some()
            || self.runtime.durable_entry_job.is_some()
        {
            return Err(Error::Uncertain);
        }
        Ok(())
    }
}
impl Drop for DurableNativeFixtureV1 {
    fn drop(&mut self) {
        let _ = self.drain_close();
    }
}

fn approve(runtime: &mut NativeRuntime) -> Result<()> {
    let pending = runtime.pending.as_mut().ok_or(Error::ReviewMismatch)?;
    if pending.review.display().is_empty()
        || pending.review.confirming()
        || pending
            .review
            .continue_from_native_click(false, EPOCH)
            .is_ok()
        || pending
            .review
            .continue_from_native_click(true, EPOCH + 1)
            .is_ok()
    {
        return Err(Error::ReviewMismatch);
    }
    pending.review.continue_from_native_click(true, EPOCH)?;
    runtime.confirmation = Zeroizing::new(format!("AUTHORIZE {}", &pending.review.digest()[..12]));
    runtime.approve(true, EPOCH)
}

fn require_plain_two_owner_manifest(proposal: &Proposal, own: &str) -> Result<()> {
    let m = proposal.manifest();
    if m.participants.len() != 2
        || m.agreement.recipients.len() != 1
        || !m.agreement.extensions.is_empty()
        || m.participants.iter().any(|p| !p.charges.is_empty())
        || !m.participants.iter().any(|p| p.account_id == own)
        || m.participants[0].account_id == m.participants[1].account_id
        || m.participants.iter().any(|p| {
            p.account_id.len() != 64
                || !p
                    .account_id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_focused_entry_rejects_unfocused_and_zero_epoch_before_effects() {
        let mut runtime = NativeRuntime::new(None);
        assert!(runtime.begin_durable_entry_v1(false, EPOCH).is_err());
        assert!(runtime.begin_durable_entry_v1(true, 0).is_err());
        assert!(runtime.durable_entry_job.is_none());
        assert!(runtime.open.is_none());
        assert!(runtime.pending.is_none());
        assert!(runtime.closing_accounts.is_empty());
    }
}
