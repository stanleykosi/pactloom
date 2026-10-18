//! Version-distinct native intake and immediate manual review. The immutable
//! data may wait, but old permissions/wallet snapshots never do. Received bytes
//! stay memory-only; another process lifetime requires a fresh exact import.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1;
use crate::authority_bridge::{
    BridgeError,
    durable_proposal_v1::{self as bridge, PreparedDurableProposalReview},
    durable_review_ipc_v1::{
        self as wire, DeliveryCommandV1, DeliveryResponseV1, DurableReviewDeliveryReceiptV1,
        DurableReviewDeliveryRequestV1, DurableReviewPayloadV1,
    },
};
use crate::native_ui::durable_proposal_v1::VerifiedDurableEconomicsV1;
use sha2::{Digest, Sha256};
use std::{
    os::unix::net::UnixStream,
    sync::mpsc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionScopeV1;
fn bridge_error(_: impl std::fmt::Display) -> BridgeError {
    BridgeError::Permission
}
fn now() -> authority_bridge::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| BridgeError::Permission)
}

pub(super) struct ImportedDurableReviewV1 {
    pub(super) fixed: Arc<VerifiedDurableEconomicsV1>,
    pub(super) request: DurableReviewDeliveryRequestV1,
    source: Arc<FreshDurableBornEntryV1>,
    peer: AuthenticatedPeer,
    scopes: Vec<DurableConstructionScopeV1>,
}
impl ImportedDurableReviewV1 {
    fn material_time_current(&self) -> bool {
        now().is_ok_and(|time| {
            self.scopes.iter().all(|scope| {
                time >= scope.valid_from_unix_seconds && time < scope.valid_until_unix_seconds
            })
        })
    }
    fn check_data_source(&self) -> authority_bridge::Result<()> {
        // No recursive journal authority lock: financial preflight/held-lease
        // checks are performed separately by the specialized signer adapter.
        self.source
            .check_original_source_current()
            .map_err(bridge_error)?;
        self.peer.check_current().map_err(bridge_error)?;
        for scope in &self.scopes {
            scope.check_valid_at(now()?).map_err(bridge_error)?;
        }
        Ok(())
    }
    fn proposal_source(self: &Arc<Self>) -> bridge::FixedProposalSource {
        let retained = self.clone();
        Arc::new(move || {
            retained.check_data_source()?;
            Ok(retained.fixed.verified().clone())
        })
    }
}
pub(super) struct DurableImportJobV1 {
    receive: mpsc::Receiver<authority_bridge::Result<ImportedDurableReviewV1>>,
    epoch: u64,
}
pub(super) struct DurableWalletJobV1 {
    receive: mpsc::Receiver<(
        NativeWalletWorkspace,
        Result<(
            crate::manifest::ReviewInputs,
            wholepact_authority::AuthorityHead,
        )>,
    )>,
    done: Arc<AtomicBool>,
    revoke: NativeWalletRevocation,
    epoch: u64,
    imported: Arc<ImportedDurableReviewV1>,
}
pub(super) struct DurableSpendFlowV1 {
    prepared: PreparedDurableProposalReview,
    head: wholepact_authority::AuthorityHead,
    imported: Arc<ImportedDurableReviewV1>,
}

fn receive_durable(
    mut stream: UnixStream,
    peer: AuthenticatedPeer,
    request: DurableReviewDeliveryRequestV1,
    source: Arc<FreshDurableBornEntryV1>,
    session: Arc<SignerConsentSession>,
) -> authority_bridge::Result<ImportedDurableReviewV1> {
    let deadline = Instant::now() + Duration::from_secs(120);
    request.validate()?;
    source.check_current().map_err(bridge_error)?;
    let journal = source.journal();
    let original = journal.durable_construction_history_v1(&request.own_disclosure, &session)?;
    if original.redisclosure().is_some() {
        return Err(BridgeError::Binding);
    }
    let current = if let Some(current) = &request.current_disclosure {
        let renewed = journal.durable_construction_history_v1(current, &session)?;
        renewed.validate_redisclosure_of(&original)?;
        renewed
    } else {
        original.clone()
    };
    if !authority_bridge::ipc::exact_local_recipient(current.recipient_transport(), &peer)
        || !peer.scope.history_read
        || !peer.scope.preconstruction_export
        || peer.native_origin != source.native_binding()
    {
        return Err(BridgeError::Permission);
    }
    original
        .request()
        .material
        .verify_owner(&source.account().fvk().map_err(bridge_error)?)
        .map_err(bridge_error)?;
    let lease = journal.acquire_preconstruction_records(
        &request.enrollment_ref,
        &request.accepted_manifest_ref,
        &session,
    )?;
    lease.require_native_origin(&source.native_binding())?;
    let proposal = Proposal::validate(lease.manifest().proposal_input().clone())
        .map_err(|_| BridgeError::Binding)?;
    let account_id = source.account().account_id().map_err(bridge_error)?;
    let original_scope = &original.request().scope;
    let born_scope = &source.record().account_record.terms.scope;
    if lease.enrollment().account_id() != account_id
        || lease.enrollment().participant_id() != peer.scope.participant_id
        || lease.enrollment().agreement_id() != peer.scope.agreement_id
        || lease.manifest().manifest_digest() != peer.scope.manifest_digest
        || original_scope.proposal != *proposal.input()
        || original_scope.account_id != account_id
        || proposal.manifest().agreement.agreement_id != born_scope.agreement_id
        || proposal.manifest().agreement.obligation_id != born_scope.obligation_id
        || !original_scope
            .permits_local_reviewer_account(&account_id)
            .map_err(bridge_error)?
    {
        return Err(BridgeError::Binding);
    }
    let check = || -> authority_bridge::Result<()> {
        if Instant::now() >= deadline {
            return Err(BridgeError::Permission);
        }
        source
            .check_original_source_current()
            .map_err(bridge_error)?;
        peer.check_current().map_err(bridge_error)?;
        lease.require_native_origin(&source.native_binding())?;
        lease.check_current()?;
        original_scope
            .check_valid_at(now()?)
            .map_err(bridge_error)?;
        Ok(())
    };
    let request_digest = request.digest()?;
    wire::bounded_write(
        &mut stream,
        &DeliveryResponseV1::Ready {
            request_digest: request_digest.clone(),
            account_id: account_id.clone(),
            participant_id: peer.scope.participant_id.clone(),
            agreement_id: peer.scope.agreement_id.clone(),
            manifest_digest: peer.scope.manifest_digest.clone(),
            local_grant_id: peer.grant_id.clone(),
            local_channel_digest: peer.channel_digest.clone(),
        },
        deadline,
        &check,
    )?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut expected: Option<(String, usize)> = None;
    loop {
        check()?;
        // Waiting for the engine's independently verified export intent is not
        // a new permission window. Preserve the original absolute deadline and
        // partial frame while polling actual revocation/scope every 100 ms.
        let frame = wholepact_signer_origin::framing::read_frame_capped_checked_until(
            &stream,
            &peer.peer,
            128 * 1024,
            deadline,
            || check().map_err(|_| wholepact_signer_origin::Error::Permission),
        )
        .map_err(|_| BridgeError::Ipc)?;
        check()?;
        let command: DeliveryCommandV1 =
            wholepact_core::parse_typed_json(&frame).map_err(|_| BridgeError::Binding)?;
        match &command {
            DeliveryCommandV1::CheckCurrent if expected.is_none() => {
                wire::bounded_write(
                    &mut stream,
                    &DeliveryResponseV1::Current {
                        request_digest: request_digest.clone(),
                    },
                    deadline,
                    &check,
                )?;
            }
            DeliveryCommandV1::Begin {
                payload_digest,
                payload_bytes,
            } if expected.is_none() => {
                if payload_digest.len() != 64
                    || !payload_digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(BridgeError::Binding);
                }
                let size = usize::try_from(*payload_bytes).map_err(|_| BridgeError::Limit)?;
                if size == 0 || size > wire::MAX_PAYLOAD {
                    return Err(BridgeError::Limit);
                }
                bytes.reserve(size);
                expected = Some((payload_digest.clone(), size));
                wire::bounded_write(
                    &mut stream,
                    &DeliveryResponseV1::Receiving { received_bytes: 0 },
                    deadline,
                    &check,
                )?;
            }
            DeliveryCommandV1::Chunk { offset, data_hex } => {
                let (_, size) = expected.as_ref().ok_or(BridgeError::Binding)?;
                if *offset != bytes.len() as u64
                    || data_hex.is_empty()
                    || data_hex.len() > wire::CHUNK_BYTES * 2
                    || data_hex.len() % 2 != 0
                    || !data_hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(BridgeError::Binding);
                }
                let chunk =
                    Zeroizing::new(hex::decode(data_hex).map_err(|_| BridgeError::Binding)?);
                if bytes
                    .len()
                    .checked_add(chunk.len())
                    .is_none_or(|n| n > *size)
                {
                    return Err(BridgeError::Limit);
                }
                bytes.extend_from_slice(&chunk);
                wire::bounded_write(
                    &mut stream,
                    &DeliveryResponseV1::Receiving {
                        received_bytes: bytes.len() as u64,
                    },
                    deadline,
                    &check,
                )?;
            }
            DeliveryCommandV1::Finish => break,
            _ => return Err(BridgeError::Binding),
        }
    }
    let (digest, size) = expected.ok_or(BridgeError::Binding)?;
    if bytes.len() != size || hex::encode(Sha256::digest(bytes.as_slice())) != digest {
        return Err(BridgeError::Binding);
    }
    let payload: DurableReviewPayloadV1 =
        wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, wire::MAX_PAYLOAD)
            .map_err(|_| BridgeError::Binding)?;
    if payload.encode()?.as_slice() != bytes.as_slice() {
        return Err(BridgeError::Binding);
    }
    let own = payload
        .contributions
        .iter()
        .find(|c| c.request().scope.account_id == account_id)
        .ok_or(BridgeError::Binding)?;
    if own != &original {
        return Err(BridgeError::Binding);
    }
    for contribution in &payload.contributions {
        contribution
            .request()
            .scope
            .check_valid_at(now()?)
            .map_err(bridge_error)?;
    }
    let unsigned =
        Zeroizing::new(hex::decode(&payload.unsigned_pczt_hex).map_err(|_| BridgeError::Binding)?);
    let proved =
        Zeroizing::new(hex::decode(&payload.proved_pczt_hex).map_err(|_| BridgeError::Binding)?);
    check()?;
    let fixed = VerifiedDurableEconomicsV1::verify(
        &proposal,
        &unsigned,
        &proved,
        &payload.contributions,
        &account_id,
        payload
            .output_actions
            .iter()
            .map(|m| wholepact_protocol::construction::OutputActionMapping {
                output_id: m.output_id.clone(),
                action_index: m.action_index,
            })
            .collect(),
        wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
    )
    .map_err(|_| BridgeError::Binding)?;
    if fixed.verified().identity().proposal_binding != request.proposal_binding {
        return Err(BridgeError::Binding);
    }
    check()?;
    let imported = ImportedDurableReviewV1 {
        fixed: Arc::new(fixed),
        request,
        source: source.clone(),
        peer: peer.clone(),
        scopes: payload
            .contributions
            .iter()
            .map(|c| c.request().scope.clone())
            .collect(),
    };
    imported.check_data_source()?;
    wire::bounded_write(
        &mut stream,
        &DeliveryResponseV1::Imported {
            receipt: DurableReviewDeliveryReceiptV1 {
                version: 1,
                recipient_request_digest: request_digest,
                payload_digest: digest,
                payload_bytes: size as u64,
                state: "imported_for_review".into(),
            },
        },
        deadline,
        &check,
    )?;
    drop(lease);
    Ok(imported)
}

impl OpenAccount {
    pub(super) fn clear_durable_review_v1(&mut self) {
        self.durable_review = None;
        self.durable_import_job = None;
        if let Some(job) = self.durable_wallet_job.take() {
            job.revoke.revoke();
            self.revocations.push(job.done);
        }
    }
}
impl NativeRuntime {
    pub(super) fn poll_durable_material_lifetime_v1(&mut self) {
        let material_expired = self.open.as_ref().is_some_and(|open| {
            open.durable_review
                .as_ref()
                .is_some_and(|review| !review.material_time_current())
                || open
                    .durable_wallet_job
                    .as_ref()
                    .is_some_and(|job| !job.imported.material_time_current())
        }) || self.pending.as_ref().is_some_and(|pending| {
            match &pending.operation {
                Operation::DurableDisclosureV1 { flow, .. }
                | Operation::DurableSpendV1 { flow, .. } => !flow.imported.material_time_current(),
                _ => false,
            }
        });
        if !material_expired {
            return;
        }
        if let Some(open) = self.open.as_mut() {
            open.clear_durable_review_v1();
        }
        if self.pending.as_ref().is_some_and(|pending| {
            matches!(
                pending.operation,
                Operation::DurableDisclosureV1 { .. } | Operation::DurableSpendV1 { .. }
            )
        }) {
            self.pending = None;
            self.confirmation.zeroize();
        }
        // Only unusable private memory and derived work are discarded. The
        // original outboxes, release intents, reservations and source remain.
        self.message = "The original material-use window ended. Imported private review data and derived pending review were discarded; retained history and financial exposure were not changed.";
    }
    pub(super) fn start_durable_import_v1(
        &mut self,
        stream: UnixStream,
        peer: AuthenticatedPeer,
        request: DurableReviewDeliveryRequestV1,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?;
        if self.pending.is_some()
            || open.durable_import_job.is_some()
            || open.durable_wallet_job.is_some()
            || open.wallet_job.is_some()
            || open.witness_job.is_some()
            || open.history_workers.len() >= 8
            || open
                .pairing
                .as_ref()
                .is_none_or(|p| p.peer.grant_id != peer.grant_id)
            || open
                .enrollment
                .as_ref()
                .is_none_or(|e| e.reference() != request.enrollment_ref)
            || open
                .manifest
                .as_ref()
                .is_none_or(|m| m.reference() != request.accepted_manifest_ref)
        {
            return Err(Error::ReviewMismatch);
        }
        let source = open.durable_born_entry.clone().ok_or(Error::Unavailable)?;
        let session = open.session.clone().ok_or(Error::Locked)?;
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = send.send(receive_durable(stream, peer, request, source, session));
        });
        open.history_workers.push(worker);
        open.durable_review = None;
        open.durable_import_job = Some(DurableImportJobV1 { receive, epoch });
        self.message = "Receiving only the exact authorized fixed proposal into private memory. Full all-account verification is required; this request grants no approval or signature.";
        Ok(())
    }
    pub(super) fn poll_durable_import_v1(&mut self, epoch: u64) {
        let Some(open) = self.open.as_mut() else {
            return;
        };
        let Some(job) = open.durable_import_job.as_ref() else {
            return;
        };
        let result = match job.receive.try_recv() {
            Ok(v) => v,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(_) => Err(BridgeError::Ipc),
        };
        let job = open.durable_import_job.take().expect("checked import job");
        if job.epoch != epoch || open.check_pairing().is_err() {
            return;
        }
        match result {
            Ok(imported) if imported.check_data_source().is_ok() => {
                open.durable_review = Some(Arc::new(imported));
                self.message = "Exact fixed proof and full two-account economics verified in private memory. Canonical accounts are not named people or prior peer approvals. Fresh wallet, witness and native spend decisions are still required.";
            }
            _ => {
                self.message = "Fixed proposal intake failed, expired or changed. No arbitrary forwarded data, old approval or signing permission was accepted.";
            }
        }
    }
}

impl NativeRuntime {
    pub(super) fn start_durable_wallet_review_v1(&mut self, epoch: u64) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?;
        if !open.writer_reconciled
            || self.pending.is_some()
            || open.durable_wallet_job.is_some()
            || open.durable_import_job.is_some()
            || open.wallet_job.is_some()
            || open.witness_job.is_some()
        {
            return Err(Error::Locked);
        }
        let imported = open.durable_review.clone().ok_or(Error::ReviewMismatch)?;
        imported
            .check_data_source()
            .map_err(|_| Error::ReviewMismatch)?;
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        if open
            .enrollment
            .as_ref()
            .is_none_or(|e| e.reference() != imported.request.enrollment_ref)
            || open
                .manifest
                .as_ref()
                .is_none_or(|m| m.reference() != imported.request.accepted_manifest_ref)
            || !Arc::ptr_eq(
                open.durable_born_entry.as_ref().ok_or(Error::Unavailable)?,
                &imported.source,
            )
        {
            return Err(Error::ReviewMismatch);
        }
        match bridge::retained_manual_commit(
            &imported.proposal_source(),
            &open.journal,
            session,
            open.vault.account(),
        )
        .map_err(|_| Error::RecoveryRequired)?
        {
            Some(receipt) => {
                self.last_receipt = Some(receipt.original_consent_ref);
                self.message = "Exact original signature result already retained. Use original authenticated retrieval or a separately approved redelivery; no new wallet selection, reservation or key use was started.";
                return Ok(());
            }
            None => {}
        }
        let witness = open.witness.clone().ok_or(Error::Locked)?;
        witness.check_current()?;
        if witness.client().disclosure_descriptor()
            != imported.source.original_witness_disclosure()?
        {
            return Err(Error::Authentication);
        }
        let mut wallet = open.wallet.take().ok_or(Error::Locked)?;
        let revoke = wallet.revoke_handle();
        let done = Arc::new(AtomicBool::new(false));
        let finished = done.clone();
        let (send, receive) = mpsc::channel();
        let worker_imported = imported.clone();
        std::thread::spawn(move || {
            let _done = WorkerCompletion(finished);
            let result = (|| {
                worker_imported
                    .check_data_source()
                    .map_err(|_| Error::ReviewMismatch)?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| Error::Unavailable)?;
                let inputs = runtime.block_on(wallet.synchronize_durable_review_v1(
                    &worker_imported.fixed,
                    &worker_imported.source,
                    &worker_imported.peer,
                ))?;
                wallet.check_current()?;
                worker_imported
                    .check_data_source()
                    .map_err(|_| Error::ReviewMismatch)?;
                let head = witness.snapshot_head()?;
                worker_imported
                    .check_data_source()
                    .map_err(|_| Error::ReviewMismatch)?;
                Ok((inputs, head))
            })();
            let _ = send.send((wallet, result));
        });
        open.durable_wallet_job = Some(DurableWalletJobV1 {
            receive,
            done,
            revoke,
            epoch,
            imported,
        });
        self.message = "Checking the original fixed inputs at the same anchor with a fresh wallet snapshot and independent witness. No input is reselected and no proof is replaced.";
        Ok(())
    }
    pub(super) fn poll_durable_wallet_review_v1(&mut self, epoch: u64) {
        let Some(open) = self.open.as_mut() else {
            return;
        };
        let Some(job) = open.durable_wallet_job.as_ref() else {
            return;
        };
        let (wallet, result) = match job.receive.try_recv() {
            Ok(value) => value,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(_) => {
                open.durable_wallet_job = None;
                self.message = "Exact durable wallet worker stopped; no approval was created.";
                return;
            }
        };
        let job = open.durable_wallet_job.take().expect("checked wallet job");
        open.wallet = Some(wallet);
        if job.epoch != epoch || open.check_pairing().is_err() {
            job.revoke.revoke();
            return;
        }
        let result = result.and_then(|(inputs, head)| {
            self.stage_durable_spend_v1(job.imported, inputs, head, epoch)
        });
        if result.is_err() {
            self.message = "Fresh fixed-proposal checks failed or expired. Original data and existing exposure are preserved; no substitute transaction or consent was created.";
        }
    }
    fn stage_durable_spend_v1(
        &mut self,
        imported: Arc<ImportedDurableReviewV1>,
        inputs: crate::manifest::ReviewInputs,
        head: wholepact_authority::AuthorityHead,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        open.check_pairing()?;
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        let prepared = bridge::prepare_manual_review(
            imported.proposal_source(),
            &open.journal,
            session,
            open.enrollment.as_ref().ok_or(Error::ReviewMismatch)?,
            open.manifest.as_ref().ok_or(Error::ReviewMismatch)?,
            open.vault.account(),
            inputs,
        )
        .map_err(|_| Error::ReviewMismatch)?;
        // The original witnessed account-policy pin is not a fresh native
        // consent reference. Bind both explicitly, under the actual original
        // source, before either disclosure or spending review is displayed.
        let prepared = prepared
            .with_durable_born_policy_v1(
                open.durable_born_entry
                    .as_deref()
                    .ok_or(Error::Unavailable)?,
                open.enrollment.as_ref().ok_or(Error::ReviewMismatch)?,
                open.manifest.as_ref().ok_or(Error::ReviewMismatch)?,
            )
            .map_err(|_| Error::ReviewMismatch)?;
        let witness = open.witness.as_ref().ok_or(Error::Locked)?;
        witness.check_current()?;
        let disclosure =
            WitnessDisclosureReview::new(witness.client(), prepared.prepared_spend(), head.clone())
                .map_err(|_| Error::Verification)?;
        let review = ExactNativeReview::stage(
            &open.authority,
            disclosure.review_digest(),
            disclosure.display().into(),
            epoch,
        )?;
        self.pending = Some(PendingDecision {
            review,
            operation: Operation::DurableDisclosureV1 {
                flow: Box::new(DurableSpendFlowV1 {
                    prepared,
                    head,
                    imported,
                }),
                review: Box::new(disclosure),
            },
        });
        Ok(())
    }
    pub(super) fn approve_durable_disclosure_v1(
        &mut self,
        flow: DurableSpendFlowV1,
        review: WitnessDisclosureReview,
        decision: super::super::NativeDecision,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        open.check_pairing()?;
        flow.imported
            .check_data_source()
            .map_err(|_| Error::ReviewMismatch)?;
        let disclosure = review
            .approve(decision, &open.authority)
            .map_err(|_| Error::Authentication)?;
        let display = format!(
            "AUTHORIZE THIS EXACT FIXED DURABLE PROPOSAL\n{}\n\nCOMPLETE ACCEPTED MANIFEST\n{}\n\nThis full-account profile verifies the exact accepted canonical account/FVK identities, real note/nullifier/action mapping, recipient and change outputs, fees and every account's net debit against the same proved transaction. It does NOT authenticate named people or organisations, distinct humans or funding sources, or prior peer approval. Required final spend signatures establish executable account control only when combined. No sponsor, matching or identity-dependent condition is supported.\n\nThis fresh one-action decision does not restore an old native approval. The current protected wallet and original independent witness are checked again before key use. Previously committed exposure remains reserved. Only this account's assigned detached signatures can be retained; this signer does not broadcast.",
            serde_json::to_string_pretty(flow.prepared.prepared_spend().record())
                .map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(open.manifest.as_ref().ok_or(Error::ReviewMismatch)?)
                .map_err(|_| Error::InvalidData)?
        );
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                flow.prepared.prepared_spend().review_digest(),
                display,
                epoch,
            )?,
            operation: Operation::DurableSpendV1 {
                flow: Box::new(flow),
                disclosure: Box::new(disclosure),
            },
        });
        self.message = "Exact witness disclosure accepted. Review the separate fresh fixed-proposal spending decision; account attribution does not identify a person or imply prior peer consent.";
        Ok(())
    }
    pub(super) fn begin_durable_signing_v1(
        &mut self,
        flow: DurableSpendFlowV1,
        disclosure: ApprovedWitnessDisclosure,
        decision: super::super::NativeDecision,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        let peer = open.check_pairing()?.peer.clone();
        let session = open.session.clone().ok_or(Error::Locked)?;
        flow.imported
            .check_data_source()
            .map_err(|_| Error::ReviewMismatch)?;
        let approved = flow
            .prepared
            .approve(&session, session.native_decision(decision)?)
            .map_err(|_| Error::ReviewMismatch)?;
        let source = open.durable_born_entry.clone().ok_or(Error::Unavailable)?;
        if !Arc::ptr_eq(&source, &flow.imported.source) {
            return Err(Error::Authentication);
        }
        let witness = open.witness.clone().ok_or(Error::Locked)?;
        witness.check_current()?;
        let wallet = open.wallet.as_mut().ok_or(Error::Locked)?;
        let wallet_revoke = wallet.revoke_handle();
        let ticket = wallet.take_ticket()?;
        let admission = open.ipc.revocation();
        let mut open = self.open.take().ok_or(Error::Locked)?;
        let worker_session = session.clone();
        let (send, receive) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = (|| {
                open.check_pairing().map_err(bridge_error)?;
                source
                    .require_account_identity(open.vault.account())
                    .map_err(bridge_error)?;
                source
                    .require_journal_identity(&open.journal)
                    .map_err(bridge_error)?;
                approved.authorize_from_durable_born_v1(
                    &source,
                    &worker_session,
                    flow.head,
                    disclosure,
                    witness.client(),
                    open.wallet
                        .as_mut()
                        .ok_or(BridgeError::Permission)?
                        .wallet_mut(),
                    &ticket,
                )
            })();
            if let Err(unsent) = send.send((open, result)) {
                unsent.0.0.close();
            }
        });
        self.signing_job = Some(SigningJob {
            receive,
            session,
            admission,
            wallet_revoke,
            peer,
            lock_requested: false,
        });
        self.message = "Exact durable one-action authorization is in progress. Release intent and exposure commit before key use; uncertain attempts never receive replacement signatures. No payment is broadcast.";
        Ok(())
    }
}

pub(super) fn allowed_event(event: &LocalEvent) -> bool {
    match event {
        LocalEvent::Pairing(_)
        | LocalEvent::History { .. }
        | LocalEvent::Export { .. }
        | LocalEvent::Redelivery { .. }
        | LocalEvent::Redelivered { .. }
        | LocalEvent::Preconstruction { .. }
        | LocalEvent::DurableConstructionV1 { .. }
        | LocalEvent::DurableConstructionHistoryV1 { .. }
        | LocalEvent::DurableConstructionRedisclosureV1 { .. }
        | LocalEvent::DurableProposalReviewV1 { .. } => true,
        LocalEvent::Request { request, .. } => {
            matches!(request, crate::ipc::AppRequest::Status { .. })
        }
        _ => false,
    }
}
pub(super) fn allowed_operation(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Pair(_)
            | Operation::Enroll(_)
            | Operation::Manifest(_)
            | Operation::DurableBornWalletV1(_)
            | Operation::Witness(_)
            | Operation::OwnerWitness(_)
            | Operation::WriterSession(_)
            | Operation::WriterActivation(_)
            | Operation::Reconcile(_)
            | Operation::Preconstruction(_)
            | Operation::DurableConstructionV1(_)
            | Operation::Redelivery { .. }
            | Operation::DurableDisclosureV1 { .. }
            | Operation::DurableSpendV1 { .. }
    )
}
pub(super) fn check_plain_proposal(open: &OpenAccount, proposal: &Proposal) -> Result<()> {
    let Some(source) = &open.durable_born_entry else {
        return Ok(());
    };
    source.check_current()?;
    crate::native_ui::durable_proposal_v1::plain_profile(proposal)?;
    let scope = &source.record().account_record.terms.scope;
    let account_id = source.account().account_id()?;
    let own = proposal
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == account_id)
        .ok_or(Error::ReviewMismatch)?;
    if proposal.manifest().agreement.agreement_id != scope.agreement_id
        || proposal.manifest().agreement.obligation_id != scope.obligation_id
        || own.participant_id != scope.participant_id
        || own.maximum_net_debit.as_zatoshis() > scope.per_operation_limit_zatoshis
        || own.fee_share.as_zatoshis() > scope.maximum_fee_share_zatoshis
        || own.fee_cap.as_zatoshis() > scope.maximum_fee_share_zatoshis
        || proposal.manifest().transaction_fee.as_zatoshis()
            > scope.maximum_transaction_fee_zatoshis
        || now()
            .map_err(|_| Error::ReviewMismatch)?
            .checked_mul(1000)
            .is_none_or(|v| v >= scope.expires_at_ms)
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
pub(super) fn check_plain_preconstruction(
    open: &OpenAccount,
    request: &authority_bridge::preconstruction_ipc::PreconstructionRequest,
) -> Result<()> {
    if open.durable_born_entry.is_none() {
        return Ok(());
    }
    if request.sponsor_policy.is_some() {
        return Err(Error::Unavailable);
    }
    let proposal = request.validate().map_err(|_| Error::ReviewMismatch)?;
    check_plain_proposal(open, &proposal)?;
    if open
        .enrollment
        .as_ref()
        .is_none_or(|e| e.reference() != request.enrollment_ref)
        || open
            .manifest
            .as_ref()
            .is_none_or(|m| m.reference() != request.accepted_manifest_ref)
    {
        return Err(Error::ReviewMismatch);
    }
    let session = open.session.as_ref().ok_or(Error::Locked)?;
    let lease = open.journal.acquire_preconstruction_records(
        &request.enrollment_ref,
        &request.accepted_manifest_ref,
        session,
    )?;
    lease.require_native_origin(&open.authority.binding())?;
    if lease.sponsor_required() || lease.sponsor_policy().is_some() {
        return Err(Error::Unavailable);
    }
    lease.check_current()?;
    Ok(())
}

/// Reject a foreign witness before any session contact or journal mutation.
/// This uses historical origin only as an exact destination constraint; the
/// configured workspace and native owner must still be freshly current.
pub(super) fn check_witness_descriptor(
    open: &OpenAccount,
    descriptor: &wholepact_authority::WitnessDisclosureDescriptor,
) -> Result<()> {
    if let Some(source) = &open.durable_born_entry {
        source.check_current()?;
        if source.original_witness_disclosure()? != *descriptor {
            return Err(Error::ReviewMismatch);
        }
    }
    Ok(())
}
pub(super) fn check_selected_witness_setup(open: &OpenAccount, json: &str) -> Result<()> {
    if open.durable_born_entry.is_some() {
        let selected = crate::native_ui::witness_workspace::prepare_selected_witness_configuration(
            json,
            &open.vault.account_id()?,
            None,
        )?;
        check_witness_descriptor(open, &selected.client.disclosure_descriptor())?;
    }
    Ok(())
}
pub(super) fn check_configured_witnesses(open: &OpenAccount) -> Result<()> {
    if open.durable_born_entry.is_some() {
        for witness in [open.witness.as_ref(), open.owner_witness.as_ref()]
            .into_iter()
            .flatten()
        {
            witness.check_current()?;
            check_witness_descriptor(open, &witness.disclosure())?;
        }
    }
    Ok(())
}
