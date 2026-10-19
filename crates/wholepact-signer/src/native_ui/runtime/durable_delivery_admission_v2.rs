//! Genuine v2 imported-source issuer and historical-only native runtime.
//! No v1 financial owner, permit, writer session, signature or dispatch adapter.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableDeliveryEntryV2;
use crate::authority_bridge::{
    BridgeError,
    durable_delivery_admission_ipc_v2::*,
    durable_review_ipc_v1::{
        self as wire, DurableReviewDeliveryRequestV1, DurableReviewPayloadV1,
        DurableReviewDeliveryReceiptV1, DeliveryCommandV1, DeliveryResponseV1,
    },
};
use crate::native_ui::{durable_proposal_v1::VerifiedDurableEconomicsV1, NativeDecision};
use crate::consent_journal::{
    PreparedDurableDeliveryAdmissionIntentV2, RetainedDurableDeliveryAdmissionIntentV2,
};
use wholepact_authority::{
    durable_delivery_scope_v2::*,
    durable_payment_v1::{DurablePaymentAdmissionTermsV1, DurableFixedCandidateBindingV1},
    OwnerControl, OwnerControlRequest, ReconciledAuthorityHistory,
};
use wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionScopeV1;
use std::{
    os::unix::net::UnixStream,
    sync::mpsc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use sha2::{Digest, Sha256};
fn bridge_error(_: impl std::fmt::Display) -> BridgeError {
    BridgeError::Permission
}
fn now() -> authority_bridge::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| BridgeError::Permission)
}
fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::ReviewMismatch)?
            .as_millis(),
    )
    .map_err(|_| Error::ReviewMismatch)
}
fn canonical<T: serde::Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::InvalidData)
}
pub(super) struct ImportedDeliveryReviewV2 {
    pub(super) fixed: Arc<VerifiedDurableEconomicsV1>,
    pub(super) request: DurableReviewDeliveryRequestV1,
    source: Arc<FreshDurableDeliveryEntryV2>,
    peer: AuthenticatedPeer,
    session: Arc<SignerConsentSession>,
    scopes: Vec<DurableConstructionScopeV1>,
}
impl ImportedDeliveryReviewV2 {
    fn check_data_current(&self) -> Result<()> {
        self.source.check_original_source_current()?;
        self.peer.check_current()?;
        if self.peer.native_origin != self.source.native_binding()
            || Instant::now() >= self.deadline()?
            || self.scopes.len() != 2
        {
            return Err(Error::ReviewMismatch);
        }
        for scope in &self.scopes {
            scope
                .check_valid_at(now().map_err(|_| Error::ReviewMismatch)?)
                .map_err(|_| Error::ReviewMismatch)?;
            if scope.proposal != *self.fixed.proposal().input() {
                return Err(Error::ReviewMismatch);
            }
        }
        Ok(())
    }
    fn check_current(&self) -> Result<()> {
        self.check_data_current()?;
        let lease = self.source.journal().acquire_preconstruction_records(
            &self.request.enrollment_ref,
            &self.request.accepted_manifest_ref,
            &self.session,
        )?;
        lease.require_native_origin(&self.source.native_binding())?;
        self.source
            .check_current_under_preconstruction_lease(&lease)?;
        lease.require_current_durable_disclosure_receipts_v1()?;
        if lease.manifest().proposal_input() != self.fixed.proposal().input()
            || lease.enrollment().participant_id() != self.peer.scope.participant_id
        {
            return Err(Error::ReviewMismatch);
        }
        self.check_data_current()?;
        drop(lease);
        Ok(())
    }
    fn deadline(&self) -> Result<Instant> {
        Ok(self
            .peer
            .deadline()
            .min(self.source.native_binding().bounded_deadline()?))
    }
}
fn receive_delivery(
    mut stream: UnixStream,
    peer: AuthenticatedPeer,
    request: DurableReviewDeliveryRequestV1,
    source: Arc<FreshDurableDeliveryEntryV2>,
    session: Arc<SignerConsentSession>,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
) -> authority_bridge::Result<ImportedDeliveryReviewV2> {
    let deadline = (Instant::now() + Duration::from_secs(120))
        .min(peer.deadline())
        .min(
            source
                .native_binding()
                .bounded_deadline()
                .map_err(bridge_error)?,
        );
    request.validate()?;
    durable_flow_observe_v1!(
        observer,
        flow_diag_v1::DurableFlowStageV1::ImportSource,
        source.check_current()
    )
    .map_err(bridge_error)?;
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
    source
        .check_current_under_preconstruction_lease(&lease)
        .map_err(bridge_error)?;
    lease.require_current_durable_disclosure_receipts_v1()?;
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
        durable_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::ImportSource,
            peer.check_current()
        )
        .map_err(bridge_error)?;
        lease.require_native_origin(&source.native_binding())?;
        lease.require_current_durable_disclosure_receipts_v1()?;
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
    let imported = ImportedDeliveryReviewV2 {
        fixed: Arc::new(fixed),
        request,
        source: source.clone(),
        peer: peer.clone(),
        session: session.clone(),
        scopes: payload
            .contributions
            .iter()
            .map(|c| c.request().scope.clone())
            .collect(),
    };
    imported.check_data_current().map_err(bridge_error)?;
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

fn fixed_binding(source: &ImportedDeliveryReviewV2) -> Result<DurableFixedCandidateBindingV1> {
    wholepact_core::parse_typed_json(
        &serde_json::to_vec(source.fixed.verified().identity()).map_err(|_| Error::InvalidData)?,
    )
    .map_err(|_| Error::InvalidData)
}
fn terms_from_current_policy_records(
    source: &ImportedDeliveryReviewV2,
    from: u64,
    until: u64,
) -> Result<DurablePaymentAdmissionTermsV1> {
    let entry = source.source.as_ref();
    let extension = entry.record().extension()?;
    let old = &extension.account_extension;
    let economics = source.fixed.as_ref();
    let fixed = economics.verified();
    let lease = entry.journal().acquire_preconstruction_records(
        &source.request.enrollment_ref,
        &source.request.accepted_manifest_ref,
        &source.session,
    )?;
    lease.require_native_origin(&entry.native_binding())?;
    lease.require_current_durable_disclosure_receipts_v1()?;
    let recipient_policy_scope_digest = authority_bridge::validate_durable_delivery_policy_v2(
        entry,
        lease.enrollment(),
        lease.manifest(),
        fixed,
        economics.input_actions(),
        economics.output_actions(),
    )
    .map_err(|_| Error::ReviewMismatch)?;
    let account = entry.account().account_id()?;
    let proposal = economics.proposal();
    let owner = proposal
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == account)
        .ok_or(Error::ReviewMismatch)?;
    let inputs = economics
        .input_actions()
        .iter()
        .filter(|i| i.account_id == account)
        .map(|map| {
            let input = fixed
                .private_review_policy()
                .inputs
                .iter()
                .find(|i| i.action_index == map.action_index)
                .ok_or(Error::ReviewMismatch)?;
            Ok(wholepact_authority::InputReservation {
                input_id: map.input_id.clone(),
                nullifier: hex::encode(input.nullifier),
                action_index: map.action_index as u64,
                value_zatoshis: input.value_zatoshis,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let result = DurablePaymentAdmissionTermsV1 {
        version: 1,
        identity: old.terms.identity.clone(),
        original_policy_digest: old.terms.original_policy_digest.clone(),
        original_genesis_digest: entry
            .genesis()
            .digest()
            .map_err(|_| Error::ReviewMismatch)?,
        original_birth_commit_digest: old.terms.birth_commit_digest.clone(),
        original_roster_extension_digest: extension.digest().map_err(|_| Error::ReviewMismatch)?,
        original_enrollment_ref: old.enrollment_ref.clone(),
        writer_certificate_digest: old.terms.signer.writer_certificate_digest.clone(),
        fixed: fixed_binding(source)?,
        authorization_id: authority_bridge::durable_proposal_v1::manual_authorization_id(
            fixed.identity(),
            &account,
        )
        .map_err(|_| Error::ReviewMismatch)?,
        recipient_policy_scope_digest,
        concrete_recipient_scope_digest:
            wholepact_core::manual_construction::construction_recipient_scope_digest(proposal)
                .map_err(|_| Error::ReviewMismatch)?,
        inputs,
        maximum_debit_zatoshis: proposal
            .accounting()
            .participant_net_debits
            .get(&owner.participant_id)
            .ok_or(Error::ReviewMismatch)?
            .as_zatoshis(),
        fee_share_zatoshis: owner.fee_share.as_zatoshis(),
        transaction_fee_zatoshis: proposal.manifest().transaction_fee.as_zatoshis(),
        valid_from_ms: from,
        valid_until_ms: until,
    };
    result.validate().map_err(|_| Error::ReviewMismatch)?;
    source.check_data_current()?;
    drop(lease);
    Ok(result)
}
fn scope_from_original(
    source: &ImportedDeliveryReviewV2,
    delivery: &DurableDeliveryPlanV2,
    history: &ReconciledAuthorityHistory,
) -> Result<DurableDeliveryScopeV2> {
    source.check_current()?;
    let terms =
        terms_from_current_policy_records(source, delivery.valid_from_ms, delivery.valid_until_ms)?;
    let extension = source.source.record().extension()?;
    let witness = source.source.original_witness_disclosure_data_v1()?;
    if history.disclosure() != &witness
        || history
            .account_policy()
            .policy_digest()
            .map_err(|_| Error::ReviewMismatch)?
            != source
                .source
                .record()
                .account_record
                .terms
                .original_policy_digest
    {
        return Err(Error::Authentication);
    }
    let mut materials = source
        .scopes
        .iter()
        .map(|s| {
            Ok(DurableDeliveryMaterialScopeRefV2 {
                account_id: s.account_id.clone(),
                original_scope_digest: s.digest().map_err(|_| Error::ReviewMismatch)?,
                valid_from_unix_seconds: s.valid_from_unix_seconds,
                valid_until_unix_seconds: s.valid_until_unix_seconds,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    materials.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    let independently_derived_inputs = terms.inputs.clone();
    let scope = DurableDeliveryScopeV2 {
        version:2, accepted_manifest_ref:source.request.accepted_manifest_ref.clone(), original_writer_epoch:extension.account_extension.terms.signer.writer_epoch,
        original_ceilings:DurableDeliveryOriginalCeilingsV2 { payment_valid_from_ms:terms.valid_from_ms, payment_valid_until_ms:terms.valid_until_ms, enrollment_expires_at_ms:extension.account_extension.terms.scope.expires_at_ms, policy_expires_at_ms:history.account_policy().policy_expires_at_ms, material_scopes:materials.clone() },
        authorization:terms, delivery:delivery.clone(), witness:witness.clone(), disclosure_rule:DurableDeliveryDisclosureRuleV2::WholeTransactionAndConnectionMetadataToProviderCommitmentsAndLinkageToWitness,
    };
    scope
        .matches_original_claims(
            history.account_policy(),
            &extension,
            source.fixed.proposal(),
            &fixed_binding(source)?,
            &source.request.accepted_manifest_ref,
            extension.account_extension.terms.signer.writer_epoch,
            &witness,
            &independently_derived_inputs,
            &materials,
        )
        .map_err(|_| Error::ReviewMismatch)?;
    // Inputs above were derived independently from the imported verified PCZT
    // action map, never supplied by the plan or a caller's scope projection.
    source.check_current()?;
    Ok(scope)
}
fn require_workspace(
    source: &FreshDurableDeliveryEntryV2,
    owner: &NativeWitnessWorkspace,
) -> Result<()> {
    source.check_original_source_current()?;
    owner.require_durable_credential_v1(
        &source.native_binding(),
        &source.original_witness_disclosure_data_v1()?,
        &source
            .record()
            .account_record
            .terms
            .signer
            .owner_certificate_digest,
    )
}
fn source_history(
    source: &ImportedDeliveryReviewV2,
    owner: &NativeWitnessWorkspace,
    #[cfg(feature = "synthetic-born-joined-qualification")] failure: &mut Option<
        wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1,
    >,
) -> Result<ReconciledAuthorityHistory> {
    owner.durable_delivery_history_v2(
        source.deadline()?,
        || {
            require_workspace(&source.source, owner)?;
            source.check_current()
        },
        #[cfg(feature = "synthetic-born-joined-qualification")]
        failure,
    )
}
fn require_live(scope: &DurableDeliveryScopeV2) -> Result<()> {
    let time = now_ms()?;
    if time < scope.delivery.valid_from_ms || time >= scope.delivery.valid_until_ms {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
fn retained_scope(
    intent: &RetainedDurableDeliveryAdmissionIntentV2,
) -> Result<&DurableDeliveryScopeV2> {
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &intent.request().control
    else {
        return Err(Error::ReviewMismatch);
    };
    Ok(&record.scope)
}
fn status_from_history(
    entry: &FreshDurableDeliveryEntryV2,
    intent: &RetainedDurableDeliveryAdmissionIntentV2,
    history: &ReconciledAuthorityHistory,
) -> Result<DurableDeliveryAdmissionStatusV2> {
    entry.check_current()?;
    let scope = retained_scope(intent)?;
    let remote = history
        .durable_delivery_admission_v2(&intent.request().operation_id)
        .map_err(|_| Error::RecoveryRequired)?;
    if remote.is_some_and(|request| request != intent.request())
        || history.disclosure() != intent.disclosure()
        || history.account_policy().owner_certificate_digest != intent.owner_certificate_digest()
        || scope.accepted_manifest_ref != intent.manifest_ref()
    {
        return Err(Error::ReviewMismatch);
    }
    if remote.is_none() && history.snapshot().head != intent.request().expected_head {
        return Err(Error::RecoveryRequired);
    }
    Ok(DurableDeliveryAdmissionStatusV2 {
        version: 2,
        request: intent.request().clone(),
        scope: scope.clone(),
        original_enrollment_ref: intent.enrollment_ref().into(),
        original_accepted_manifest_ref: intent.manifest_ref().into(),
        original_local_intent_digest: intent.history_digest()?,
        authenticated_witness_history_digest: history
            .history_digest()
            .map_err(|_| Error::ReviewMismatch)?,
        witness_committed: remote.is_some(),
        current_fixed_material_source: "unchecked".into(),
    })
}
/// Only the dedicated same-original redisclosure ingress creates this nominal
/// wrapper. General initial capture/construction never enters the v2 profile.
pub(super) struct PreparedRedisclosureV2 {
    source: Arc<FreshDurableDeliveryEntryV2>,
    prepared: crate::native_ui::durable_construction_v1::PreparedDurableConstructionV1,
}
impl PreparedRedisclosureV2 {
    pub(super) fn check_current(&self) -> Result<()> {
        self.source.check_current()
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn request(
        &self,
    ) -> &crate::authority_bridge::durable_construction_v1::DurableConstructionRequestV1 {
        self.prepared.qualification_request()
    }
}
pub(super) struct PreparedAdmissionV2 {
    source: Arc<ImportedDeliveryReviewV2>,
    owner: Arc<NativeWitnessWorkspace>,
    request: OwnerControlRequest,
    prepared: PreparedDurableDeliveryAdmissionIntentV2,
    stream: UnixStream,
    peer: AuthenticatedPeer,
    attempt: u64,
    deadline: Instant,
}
impl PreparedAdmissionV2 {
    pub(super) fn request(&self) -> &OwnerControlRequest {
        &self.request
    }
    fn current(&self) -> Result<()> {
        self.source.check_current()?;
        self.peer.check_current()?;
        self.peer.require_same_grant(&self.source.peer)?;
        require_workspace(&self.source.source, &self.owner)?;
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &self.request.control
        else {
            return Err(Error::ReviewMismatch);
        };
        require_live(&record.scope)?;
        if Instant::now() >= self.deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
    fn display(&self) -> Result<String> {
        self.current()?;
        Ok(format!(
            "PROSPECTIVE V2 DELIVERY ADMISSION ONLY\n\n{}\n\nReview the exact dispatcher leaf and custody commitment, original Host and submission-journal binding, fixed candidate, BOTH owner IDs, provider and route, finite attempt/expiry bounds and original material ceilings. This immutably admits only this complete prospective scope at the independent Witness. Acquire, Activate, Reserve, signing, extraction and dispatch are DISABLED. No v1 admission is upgraded. A partial/unknown remote outcome remains retained and must be audited exactly; it is not rolled back.",
            self.prepared.display()?
        ))
    }
}
/// A real owner-mTLS Controlled response is NOT complete-history evidence.
/// This private owner preserves the original connection, clock and exact local
/// commitment even if the one permitted read-only audit subsequently fails.
struct PendingAuditV2 {
    entry: Arc<FreshDurableDeliveryEntryV2>,
    session: Arc<SignerConsentSession>,
    owner: Arc<NativeWitnessWorkspace>,
    retained: RetainedDurableDeliveryAdmissionIntentV2,
    controlled: wholepact_authority::AccountSnapshot,
    stream: UnixStream,
    peer: AuthenticatedPeer,
    attempt: u64,
    deadline: Instant,
    audit_started: std::sync::atomic::AtomicBool,
}
fn start_readonly_audit_once(started: &std::sync::atomic::AtomicBool) -> Result<()> {
    if started.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return Err(Error::Unavailable);
    }
    Ok(())
}
fn require_same_committed_snapshot(
    controlled: &wholepact_authority::AccountSnapshot,
    history: &wholepact_authority::AccountSnapshot,
) -> Result<()> {
    if history != controlled {
        return Err(Error::Uncertain);
    }
    Ok(())
}
impl PendingAuditV2 {
    fn check_current(&self) -> Result<()> {
        self.entry.check_current()?;
        self.peer.check_current()?;
        require_workspace(&self.entry, &self.owner)?;
        let original = self
            .entry
            .journal()
            .durable_delivery_admission_intent_v2(
                &retained_scope(&self.retained)?
                    .authorization
                    .authorization_id,
                &self.session,
            )?
            .ok_or(Error::RecoveryRequired)?;
        if original != self.retained
            || self.peer.native_origin != self.entry.native_binding()
            || Instant::now() >= self.deadline
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableDeliveryStageV2 {
    Import,
    OriginalEvidence,
    Source,
    History,
    Scope,
    PrepareIntent,
    NativeReview,
    RetainIntent,
    OwnerSend,
    Audit,
}
pub struct DurableDeliveryFailureV2 {
    attempt: u64,
    stage: DurableDeliveryStageV2,
    error: Error,
    import_error: Option<BridgeError>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    transport:
        Option<wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1>,
}
impl DurableDeliveryFailureV2 {
    pub fn attempt(&self) -> u64 {
        self.attempt
    }
    pub fn stage(&self) -> DurableDeliveryStageV2 {
        self.stage
    }
    pub fn into_error(self) -> Error {
        self.error
    }
    pub fn into_import_error(self) -> Option<BridgeError> {
        self.import_error
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub fn into_parts(
        self,
    ) -> (
        u64,
        DurableDeliveryStageV2,
        Error,
        Option<BridgeError>,
        Option<wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1>,
    ) {
        (
            self.attempt,
            self.stage,
            self.error,
            self.import_error,
            self.transport,
        )
    }
}
enum DeliveryOutcomeV2 {
    Prepared(PreparedAdmissionV2),
    AwaitingAudit(Arc<PendingAuditV2>),
    Completed(DurableDeliveryAdmissionStatusV2),
}
struct DeliveryJobV2 {
    receive: mpsc::Receiver<std::result::Result<DeliveryOutcomeV2, DurableDeliveryFailureV2>>,
    epoch: u64,
    attempt: u64,
}
struct ImportJobV2 {
    receive: mpsc::Receiver<authority_bridge::Result<ImportedDeliveryReviewV2>>,
    epoch: u64,
    attempt: u64,
}
#[derive(Default)]
pub(super) struct DurableDeliveryRuntimeV2 {
    pub(super) imported: Option<Arc<ImportedDeliveryReviewV2>>,
    import: Option<ImportJobV2>,
    job: Option<DeliveryJobV2>,
    next_attempt: u64,
    awaiting_audit: Option<Arc<PendingAuditV2>>,
    pub(super) status: Option<DurableDeliveryAdmissionStatusV2>,
    pub(super) failure: Option<DurableDeliveryFailureV2>,
}
impl DurableDeliveryRuntimeV2 {
    pub(super) fn clear(&mut self) {
        self.imported = None;
        self.import = None;
        self.job = None;
        self.awaiting_audit = None;
    }
    pub(super) fn response_received(&self) -> bool {
        self.awaiting_audit.is_some()
    }
    fn attempt(&mut self) -> Result<u64> {
        self.next_attempt = self.next_attempt.checked_add(1).ok_or(Error::Unavailable)?;
        self.failure = None;
        self.status = None;
        Ok(self.next_attempt)
    }
}
fn send_response(
    stream: &mut UnixStream,
    peer: &AuthenticatedPeer,
    deadline: Instant,
    response: &DurableDeliveryResponseV2,
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    wire::bounded_write(stream, response, deadline, || {
        check().map_err(bridge_error)?;
        peer.check_current().map_err(bridge_error)
    })
    .map_err(|_| Error::Uncertain)
}
fn public_evidence(
    open: &OpenAccount,
    peer: &AuthenticatedPeer,
) -> Result<OriginalWitnessPublicDataV2> {
    open.check_pairing()?.peer.require_same_grant(peer)?;
    macro_rules! derive {
        ($source:expr) => {{
            let source = $source;
            source.check_current()?;
            if source.native_binding() != peer.native_origin {
                return Err(Error::Authentication);
            }
            let record = source.record();
            let extension = record.extension()?;
            let evidence = OriginalWitnessPublicDataV2 {
                version: 2,
                original_terms: record.account_record.terms.clone(),
                original_roster: record.roster.clone(),
                original_signer_roster_record_digest: record.reference()?,
                witness: source.original_witness_disclosure_data_v1()?,
                native_entry_digest: source.native_binding().entry_digest().into(),
                original_enrollment_ref: extension.account_extension.enrollment_ref.clone(),
                original_witness_extension_digest: extension
                    .account_extension
                    .digest()
                    .map_err(|_| Error::ReviewMismatch)?,
                local_grant_id: peer.grant_id.clone(),
                local_channel_digest: peer.channel_digest.clone(),
            };
            evidence.validate().map_err(|_| Error::ReviewMismatch)?;
            source.check_current()?;
            evidence
        }};
    }
    let evidence = if let Some(source) = &open.durable_delivery_entry {
        derive!(source)
    } else if let Some(source) = &open.durable_born_entry {
        derive!(source)
    } else {
        return Err(Error::Unavailable);
    };
    peer.check_current()?;
    Ok(evidence)
}
impl NativeRuntime {
    pub(super) fn prepare_durable_delivery_redisclosure_v2(
        &mut self,
        stream: UnixStream,
        peer: AuthenticatedPeer,
        request: crate::authority_bridge::durable_construction_v1::DurableConstructionRedisclosureRequestV1,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        let source = open
            .durable_delivery_entry
            .clone()
            .ok_or(Error::Unavailable)?;
        source.check_current()?;
        open.check_pairing()?.peer.require_same_grant(&peer)?;
        if self.pending.is_some()
            || open.history_workers.len() >= 8
            || open.durable_delivery.import.is_some()
            || open.durable_delivery.job.is_some()
            || open.durable_delivery.imported.is_some()
            || open.durable_delivery.awaiting_audit.is_some()
            || open
                .enrollment
                .as_ref()
                .is_none_or(|e| e.reference() != request.enrollment_ref)
            || open
                .manifest
                .as_ref()
                .is_none_or(|m| m.reference() != request.accepted_manifest_ref)
            || request.original.expected_request_digest.is_none()
        {
            return Err(Error::ReviewMismatch);
        }
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        let prepared = crate::native_ui::durable_construction_v1::PreparedDurableConstructionV1::prepare_redisclosure(
            request, peer, stream, &open.journal, session, &source.native_binding(), &open.vault)?;
        source.check_current()?;
        let review = ExactNativeReview::stage(
            &open.authority,
            prepared.digest(),
            prepared.display()?,
            epoch,
        )?;
        self.pending = Some(PendingDecision {
            review,
            operation: Operation::DurableDeliveryRedisclosureV2(Box::new(PreparedRedisclosureV2 {
                source,
                prepared,
            })),
        });
        self.message = "Review a fresh privacy disclosure of exactly the same original material to this current recipient. Original bytes, audience and absolute expiry cannot change. No financial action is authorized.";
        Ok(())
    }
    pub(super) fn approve_durable_delivery_redisclosure_v2(
        &mut self,
        prepared: PreparedRedisclosureV2,
        decision: NativeDecision,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        prepared.check_current()?;
        open.check_pairing()?;
        if !open
            .durable_delivery_entry
            .as_ref()
            .is_some_and(|source| Arc::ptr_eq(source, &prepared.source))
            || open.history_workers.len() >= 8
        {
            return Err(Error::ReviewMismatch);
        }
        let approved = prepared
            .prepared
            .approve(decision, &open.authority, &open.vault)?;
        let source = prepared.source;
        let session = open.session.clone().ok_or(Error::Locked)?;
        let journal = open.journal.clone();
        let worker = std::thread::spawn(move || {
            // The checked serve observes its same terminal Result before its
            // owned stream drops. Do not emit a duplicate after this return.
            let _ = approved.serve_with_original_source_check_v2(&journal, &session, |lease| {
                source
                    .check_current_under_preconstruction_lease(lease)
                    .map_err(bridge_error)
            });
        });
        open.disclosure_worker_ids.insert(worker.thread().id());
        open.history_workers.push(worker);
        Ok(())
    }
}
impl NativeRuntime {
    pub(super) fn start_durable_delivery_import_v2(
        &mut self,
        stream: UnixStream,
        peer: AuthenticatedPeer,
        request: DurableReviewDeliveryRequestV1,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?.peer.require_same_grant(&peer)?;
        if self.pending.is_some()
            || open.durable_delivery.job.is_some()
            || open.durable_delivery.import.is_some()
            || open.durable_delivery.awaiting_audit.is_some()
            || open.history_workers.len() >= 8
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
        let source = open
            .durable_delivery_entry
            .clone()
            .ok_or(Error::Unavailable)?;
        source.check_current()?;
        let session = open.session.clone().ok_or(Error::Locked)?;
        let attempt = open.durable_delivery.attempt()?;
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = receive_delivery(
                stream,
                peer,
                request,
                source,
                session,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                None,
            );
            let _ = send.send(result);
        });
        open.history_workers.push(worker);
        open.durable_delivery.imported = None;
        open.durable_delivery.import = Some(ImportJobV2 {
            receive,
            epoch,
            attempt,
        });
        Ok(())
    }
    pub(super) fn handle_durable_delivery_v2(
        &mut self,
        mut stream: UnixStream,
        peer: AuthenticatedPeer,
        command: DurableDeliveryCommandV2,
        epoch: u64,
    ) -> Result<()> {
        command.validate().map_err(|_| Error::InvalidData)?;
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?.peer.require_same_grant(&peer)?;
        let deadline = peer
            .deadline()
            .min(open.authority.binding().bounded_deadline()?);
        if let DurableDeliveryCommandV2::OriginalWitnessEvidence {} = command {
            let evidence = public_evidence(open, &peer)?;
            return send_response(
                &mut stream,
                &peer,
                deadline,
                &DurableDeliveryResponseV2::OriginalWitnessEvidence { evidence },
                || public_evidence(open, &peer).map(|_| ()),
            );
        }
        let entry = open
            .durable_delivery_entry
            .clone()
            .ok_or(Error::Unavailable)?;
        if self.pending.is_some()
            || open.durable_delivery.job.is_some()
            || open.durable_delivery.import.is_some()
            || open.durable_delivery.awaiting_audit.is_some()
            || open.history_workers.len() >= 8
        {
            return Err(Error::Locked);
        }
        let owner = open.owner_witness.clone().ok_or(Error::Locked)?;
        require_workspace(&entry, &owner)?;
        let session = open.session.clone().ok_or(Error::Locked)?;
        let imported = open.durable_delivery.imported.clone();
        let attempt = open.durable_delivery.attempt()?;
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut stage = DurableDeliveryStageV2::Source;
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let mut transport = None;
            let result = (|| -> Result<DeliveryOutcomeV2> {
                entry.check_current()?;
                peer.check_current()?;
                match command {
                    DurableDeliveryCommandV2::History { request } => {
                        stage = DurableDeliveryStageV2::History;
                        let intent = entry
                            .journal()
                            .durable_delivery_admission_intent_v2(
                                &request.authorization_id,
                                &session,
                            )?
                            .ok_or(Error::RecoveryRequired)?;
                        let history = owner.durable_delivery_history_v2(
                            deadline,
                            || {
                                entry.check_current()?;
                                peer.check_current()?;
                                require_workspace(&entry, &owner)
                            },
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            &mut transport,
                        )?;
                        let status = status_from_history(&entry, &intent, &history)?;
                        send_response(
                            &mut stream,
                            &peer,
                            deadline,
                            &DurableDeliveryResponseV2::Admission {
                                admission: status.clone(),
                            },
                            || entry.check_current(),
                        )?;
                        Ok(DeliveryOutcomeV2::Completed(status))
                    }
                    DurableDeliveryCommandV2::Admit { request } => {
                        let source = imported.ok_or(Error::Unavailable)?;
                        if request.import_request != source.request
                            || !Arc::ptr_eq(&source.source, &entry)
                        {
                            return Err(Error::ReviewMismatch);
                        }
                        source.peer.require_same_grant(&peer)?;
                        source.check_current()?;
                        stage = DurableDeliveryStageV2::History;
                        let history = source_history(
                            &source,
                            &owner,
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            &mut transport,
                        )?;
                        stage = DurableDeliveryStageV2::Scope;
                        let scope = scope_from_original(&source, &request.delivery, &history)?;
                        require_live(&scope)?;
                        if let Some(intent) = entry.journal().durable_delivery_admission_intent_v2(
                            &scope.authorization.authorization_id,
                            &session,
                        )? {
                            if retained_scope(&intent)? != &scope {
                                return Err(Error::ReviewMismatch);
                            }
                            let status = status_from_history(&entry, &intent, &history)?;
                            // Retained-but-unconfirmed requests are history only; no
                            // fresh operation ID, renewed approval or hidden retry.
                            send_response(
                                &mut stream,
                                &peer,
                                deadline,
                                &DurableDeliveryResponseV2::Admission {
                                    admission: status.clone(),
                                },
                                || source.check_current(),
                            )?;
                            return Ok(DeliveryOutcomeV2::Completed(status));
                        }
                        let exact=wholepact_authority::durable_delivery_admission_v2::prepare_durable_delivery_admission_request_v2(scope,&history).map_err(|_|Error::ReviewMismatch)?;
                        stage = DurableDeliveryStageV2::PrepareIntent;
                        let prepared = session.prepare_durable_delivery_admission_intent_v2(
                            entry.journal(),
                            exact.clone(),
                            entry.original_witness_disclosure_data_v1()?,
                            &entry
                                .record()
                                .account_record
                                .terms
                                .signer
                                .owner_certificate_digest,
                            &source.request.enrollment_ref,
                            &source.request.accepted_manifest_ref,
                        )?;
                        source.check_current()?;
                        Ok(DeliveryOutcomeV2::Prepared(PreparedAdmissionV2 {
                            source,
                            owner,
                            request: exact,
                            prepared,
                            stream: stream.try_clone()?,
                            peer: peer.clone(),
                            attempt,
                            deadline,
                        }))
                    }
                    _ => Err(Error::Unavailable),
                }
            })();
            if result.is_err() {
                let _ = send_response(
                    &mut stream,
                    &peer,
                    deadline,
                    &DurableDeliveryResponseV2::Denied,
                    || entry.check_original_source_current(),
                );
            }
            let _ = send.send(result.map_err(|error| DurableDeliveryFailureV2 {
                attempt,
                stage,
                error,
                import_error: None,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                transport,
            }));
        });
        open.history_workers.push(worker);
        open.durable_delivery.job = Some(DeliveryJobV2 {
            receive,
            epoch,
            attempt,
        });
        Ok(())
    }
    pub(super) fn approve_durable_delivery_v2(
        &mut self,
        prepared: PreparedAdmissionV2,
        decision: NativeDecision,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?
            .peer
            .require_same_grant(&prepared.peer)?;
        prepared.current()?;
        if decision.binding() != &prepared.source.source.native_binding()
            || decision.reviewed_digest() != prepared.prepared.digest()
            || decision.consumed_at() >= prepared.deadline
            || open.authority.binding() != prepared.source.source.native_binding()
            || !open
                .owner_witness
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &prepared.owner))
        {
            return Err(Error::ReviewMismatch);
        }
        let local = prepared.source.session.native_decision(decision)?;
        let approved = prepared
            .source
            .session
            .approve_durable_delivery_admission_intent_v2(prepared.prepared, local)?;
        let attempt = prepared.attempt;
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut stage = DurableDeliveryStageV2::RetainIntent;
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let mut transport = None;
            let source = prepared.source;
            let owner = prepared.owner;
            let peer = prepared.peer;
            let deadline = prepared.deadline;
            let request = prepared.request;
            let mut stream = prepared.stream;
            let result = (|| -> Result<DeliveryOutcomeV2> {
                source.check_current()?;
                let retained = source
                    .source
                    .journal()
                    .retain_durable_delivery_admission_intent_v2(approved, || {
                        source
                            .check_data_current()
                            .map_err(|_| JournalError::Permission)?;
                        peer.check_current().map_err(|_| JournalError::Permission)?;
                        require_workspace(&source.source, &owner)
                            .map_err(|_| JournalError::Permission)?;
                        if Instant::now() >= deadline {
                            return Err(JournalError::Permission);
                        }
                        Ok(())
                    })?;
                if retained.request() != &request {
                    return Err(Error::RecoveryRequired);
                }
                // The complete immutable local intent exists before the first
                // owner-mTLS request byte, including every callback thereafter.
                source.check_current()?;
                stage = DurableDeliveryStageV2::OwnerSend;
                let controlled = owner.durable_delivery_admit_v2(
                    &request,
                    deadline,
                    || {
                        source.check_current()?;
                        peer.check_current()?;
                        require_workspace(&source.source, &owner)
                    },
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    &mut transport,
                )?;
                // Do not race the one-record admission listener with an
                // automatic History request. An explicit production UI action
                // continues this same connection after a read-only listener is
                // ready. No final status exists at this intermediate boundary.
                Ok(DeliveryOutcomeV2::AwaitingAudit(Arc::new(PendingAuditV2 {
                    entry: source.source.clone(),
                    session: source.session.clone(),
                    owner: owner.clone(),
                    retained,
                    controlled,
                    stream: stream.try_clone()?,
                    peer: peer.clone(),
                    attempt,
                    deadline,
                    audit_started: std::sync::atomic::AtomicBool::new(false),
                })))
            })();
            if result.is_err() {
                let _ = send_response(
                    &mut stream,
                    &peer,
                    deadline,
                    &DurableDeliveryResponseV2::Denied,
                    || source.source.check_original_source_current(),
                );
            }
            let _ = send.send(result.map_err(|error| DurableDeliveryFailureV2 {
                attempt,
                stage,
                error,
                import_error: None,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                transport,
            }));
        });
        open.history_workers.push(worker);
        open.durable_delivery.job = Some(DeliveryJobV2 {
            receive,
            epoch,
            attempt,
        });
        Ok(())
    }
    /// Read-only continuation, available in the production native UI. It
    /// consumes no approval and sends no admission request a second time.
    pub(super) fn begin_durable_delivery_history_audit_v2(&mut self, epoch: u64) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        if self.pending.is_some()
            || open.durable_delivery.job.is_some()
            || open.history_workers.len() >= 8
        {
            return Err(Error::Locked);
        }
        let pending = open
            .durable_delivery
            .awaiting_audit
            .clone()
            .ok_or(Error::Unavailable)?;
        open.check_pairing()?
            .peer
            .require_same_grant(&pending.peer)?;
        if !open
            .durable_delivery_entry
            .as_ref()
            .is_some_and(|entry| Arc::ptr_eq(entry, &pending.entry))
            || !open
                .owner_witness
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &pending.owner))
        {
            return Err(Error::ReviewMismatch);
        }
        pending.check_current()?;
        start_readonly_audit_once(&pending.audit_started)?;
        let attempt = pending.attempt;
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let mut transport = None;
            let result = (|| -> Result<DeliveryOutcomeV2> {
                pending.check_current()?;
                let history = pending.owner.durable_delivery_history_v2(
                    pending.deadline,
                    || pending.check_current(),
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    &mut transport,
                )?;
                pending.check_current()?;
                // Exact committed snapshot joins the authentic Controlled
                // response to the complete original history, not a DTO claim.
                require_same_committed_snapshot(&pending.controlled, history.snapshot())?;
                let status = status_from_history(&pending.entry, &pending.retained, &history)?;
                if !status.witness_committed {
                    return Err(Error::Uncertain);
                }
                let mut stream = pending.stream.try_clone()?;
                send_response(
                    &mut stream,
                    &pending.peer,
                    pending.deadline,
                    &DurableDeliveryResponseV2::Admission {
                        admission: status.clone(),
                    },
                    || pending.check_current(),
                )?;
                Ok(DeliveryOutcomeV2::Completed(status))
            })();
            // On audit failure the real Controlled reply, original intent and
            // stream remain owned in awaiting_audit. Never downgrade them to a
            // fabricated denial, retry admission, or claim full-history success.
            let _ = send.send(result.map_err(|error| DurableDeliveryFailureV2 {
                attempt,
                stage: DurableDeliveryStageV2::Audit,
                error,
                import_error: None,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                transport,
            }));
        });
        open.history_workers.push(worker);
        open.durable_delivery.job = Some(DeliveryJobV2 {
            receive,
            epoch,
            attempt,
        });
        self.message = "Checking complete authenticated history for the exact already-committed request. No new admission or approval is sent.";
        Ok(())
    }
    pub(super) fn poll_durable_delivery_v2(&mut self, epoch: u64) {
        let Some(open) = self.open.as_mut() else {
            return;
        };
        if let Some(job) = open.durable_delivery.import.as_ref() {
            match job.receive.try_recv() {
                Err(mpsc::TryRecvError::Empty) => {}
                result => {
                    let job = open.durable_delivery.import.take().expect("checked job");
                    match result {
                        Ok(Ok(imported))
                            if job.epoch == epoch
                                && open.durable_delivery.next_attempt == job.attempt =>
                        {
                            match open.check_pairing().and_then(|_| imported.check_current()) {
                                Ok(()) => {
                                    open.durable_delivery.imported = Some(Arc::new(imported));
                                    self.message = "Verified exact original fixed artifact and both original material scopes for prospective v2 admission only.";
                                }
                                Err(error) => {
                                    open.durable_delivery.failure =
                                        Some(DurableDeliveryFailureV2 {
                                            attempt: job.attempt,
                                            stage: DurableDeliveryStageV2::Source,
                                            error,
                                            import_error: None,
                                            #[cfg(feature = "synthetic-born-joined-qualification")]
                                            transport: None,
                                        });
                                }
                            }
                        }
                        Ok(Err(error)) if open.durable_delivery.next_attempt == job.attempt => {
                            open.durable_delivery.failure = Some(DurableDeliveryFailureV2 {
                                attempt: job.attempt,
                                stage: DurableDeliveryStageV2::Import,
                                error: Error::Verification,
                                import_error: Some(error),
                                #[cfg(feature = "synthetic-born-joined-qualification")]
                                transport: None,
                            });
                        }
                        _ => {
                            self.message = "V2 import failed or lost its exact native/peer source.";
                        }
                    }
                }
            }
        }
        if open
            .durable_delivery
            .imported
            .as_ref()
            .is_some_and(|source| {
                source.scopes.iter().any(|scope| {
                    now().is_err() || now().is_ok_and(|now| now >= scope.valid_until_unix_seconds)
                })
            })
        {
            open.durable_delivery.imported = None;
            if self
                .pending
                .as_ref()
                .is_some_and(|p| matches!(&p.operation, Operation::DurableDeliveryV2(_)))
            {
                self.pending = None;
                self.confirmation.zeroize();
            }
        }
        let Some(job) = open.durable_delivery.job.as_ref() else {
            return;
        };
        let result = match job.receive.try_recv() {
            Err(mpsc::TryRecvError::Empty) => return,
            Ok(result) => result,
            Err(_) => Err(DurableDeliveryFailureV2 {
                attempt: job.attempt,
                stage: DurableDeliveryStageV2::Audit,
                error: Error::Uncertain,
                import_error: None,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                transport: None,
            }),
        };
        let job = open.durable_delivery.job.take().expect("checked job");
        // Keep the exact worker error for its actual attempt even when native
        // presentation has become stale. A lost/late success creates no current
        // decision and cannot replace a later attempt's diagnostic.
        let outcome = match result {
            Err(failure) => {
                if failure.attempt == job.attempt
                    && open.durable_delivery.next_attempt == job.attempt
                {
                    open.durable_delivery.failure = Some(failure);
                }
                self.message = "V2 admission did not complete. Exact original intent and any remote commitment remain; audit the same operation before proceeding.";
                return;
            }
            Ok(outcome) => outcome,
        };
        // Preserve the actual response as historical/uncertain evidence even
        // if presentation changed after the send. This creates no status or
        // current authority: the explicit audit rechecks every source again.
        let outcome = match outcome {
            DeliveryOutcomeV2::AwaitingAudit(pending) => {
                if open.durable_delivery.next_attempt == job.attempt {
                    open.durable_delivery.awaiting_audit = Some(pending);
                    open.durable_delivery.imported = None;
                    self.message = "Owner-mTLS committed response received; full history is NOT yet verified. Start the original read-only history listener, then check exact original history. No financial action is enabled.";
                }
                return;
            }
            outcome => outcome,
        };
        if job.epoch != epoch
            || open.check_pairing().is_err()
            || open.durable_delivery.next_attempt != job.attempt
        {
            return;
        }
        match outcome {
            DeliveryOutcomeV2::AwaitingAudit(_) => unreachable!("handled inert response above"),
            DeliveryOutcomeV2::Completed(status) => {
                open.durable_delivery.awaiting_audit = None;
                open.durable_delivery.status = Some(status);
                open.durable_delivery.imported = None;
                self.message = "Exact prospective v2 admission/history retained. Financial actions remain disabled.";
            }
            DeliveryOutcomeV2::Prepared(prepared) => {
                let result = prepared.display().and_then(|display| {
                    ExactNativeReview::stage(
                        &open.authority,
                        prepared.prepared.digest(),
                        display,
                        epoch,
                    )
                });
                match result {
                    Ok(review) => {
                        self.pending = Some(PendingDecision {
                            review,
                            operation: Operation::DurableDeliveryV2(Box::new(prepared)),
                        });
                        self.message = "Review the complete prospective v2 scope. This is not signing or dispatch permission.";
                    }
                    Err(error) => {
                        open.durable_delivery.failure = Some(DurableDeliveryFailureV2 {
                            attempt: prepared.attempt,
                            stage: DurableDeliveryStageV2::NativeReview,
                            error,
                            import_error: None,
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            transport: None,
                        });
                    }
                }
            }
        }
    }
    pub(super) fn durable_delivery_ui_v2(
        &mut self,
        ui: &mut egui::Ui,
        focused: bool,
        epoch: u64,
    ) -> bool {
        if self
            .open
            .as_ref()
            .is_none_or(|open| open.durable_delivery_entry.is_none())
        {
            return false;
        }
        ui.label("V2 original-source prospective admission and exact historical audit only. No Acquire, Activate, Reserve, signing, extraction or dispatch route exists.");
        if self.pending.is_some() {
            return false;
        }
        if self
            .open
            .as_ref()
            .is_some_and(|open| open.durable_delivery.awaiting_audit.is_some())
        {
            ui.label("A checked committed response and exact local intent are retained. Complete authenticated history has NOT been verified.");
            let ready = self.open.as_ref().is_some_and(|open| {
                open.durable_delivery.job.is_none()
                    && open
                        .durable_delivery
                        .awaiting_audit
                        .as_ref()
                        .is_some_and(|p| {
                            !p.audit_started.load(std::sync::atomic::Ordering::Acquire)
                        })
            });
            if ui
                .add_enabled(ready, egui::Button::new("Check exact original history"))
                .clicked_by(egui::PointerButton::Primary)
                && focused
            {
                let _ = self.begin_durable_delivery_history_audit_v2(epoch);
            }
            return true;
        }
        ui.label("Select the original owner-mTLS witness configuration. Credentials are read only; no enrollment or replacement is performed.");
        ui.add(egui::TextEdit::multiline(&mut *self.owner_witness_setup).char_limit(16 * 1024));
        if ui
            .button("Review original owner witness configuration")
            .clicked_by(egui::PointerButton::Primary)
            && focused
        {
            let _ = self.stage_owner_witness_setup(epoch);
        }
        ui.label("For a new prospective import only, accept the exact same enrollment and manifest after pairing. Historical status requires neither a new manifest nor a private import.");
        ui.add(egui::TextEdit::multiline(&mut *self.proposal).char_limit(128 * 1024));
        ui.add(egui::TextEdit::singleline(&mut self.budget));
        if ui
            .button("Review exact enrollment for v2 import")
            .clicked_by(egui::PointerButton::Primary)
            && focused
        {
            let _ = self.stage_enrollment(epoch);
        }
        if ui
            .button("Review exact manifest for v2 import")
            .clicked_by(egui::PointerButton::Primary)
            && focused
        {
            let _ = self.stage_manifest(epoch);
        }
        true
    }
}
pub(super) fn allowed_event(event: &LocalEvent) -> bool {
    match event {
        LocalEvent::Pairing(_)
        | LocalEvent::DurableDeliveryV2 { .. }
        | LocalEvent::DurableProposalReviewV1 { .. }
        | LocalEvent::DurableConstructionRedisclosureV1 { .. } => true,
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
            | Operation::OwnerWitness(_)
            | Operation::DurableDeliveryV2(_)
            | Operation::DurableDeliveryRedisclosureV2(_)
    )
}
pub(super) fn check_plain_proposal(open: &OpenAccount, proposal: &Proposal) -> Result<()> {
    let source = open
        .durable_delivery_entry
        .as_ref()
        .ok_or(Error::Unavailable)?;
    source.check_current()?;
    crate::native_ui::durable_proposal_v1::plain_profile(proposal)?;
    let scope = &source.record().account_record.terms.scope;
    let account = source.account().account_id()?;
    let own = proposal
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == account)
        .ok_or(Error::ReviewMismatch)?;
    if proposal.manifest().agreement.agreement_id != scope.agreement_id
        || proposal.manifest().agreement.obligation_id != scope.obligation_id
        || own.participant_id != scope.participant_id
        || own.maximum_net_debit.as_zatoshis() > scope.per_operation_limit_zatoshis
        || own.fee_share.as_zatoshis() > scope.maximum_fee_share_zatoshis
        || own.fee_cap.as_zatoshis() > scope.maximum_fee_share_zatoshis
        || proposal.manifest().transaction_fee.as_zatoshis()
            > scope.maximum_transaction_fee_zatoshis
        || now_ms()? >= scope.expires_at_ms
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod continuation_source_contract_tests {
    use super::*;
    #[test]
    fn exact_readonly_audit_is_one_shot_even_after_failure() {
        let started = std::sync::atomic::AtomicBool::new(false);
        assert!(start_readonly_audit_once(&started).is_ok());
        assert!(matches!(
            start_readonly_audit_once(&started),
            Err(Error::Unavailable)
        ));
        assert!(matches!(
            start_readonly_audit_once(&started),
            Err(Error::Unavailable)
        ));
    }
    #[test]
    fn actual_snapshot_join_refuses_changed_history_without_issuing_status() {
        // Inert snapshots exercise the actual comparison predicate only; they
        // cannot construct PendingAudit, a native owner, or a final status.
        let controlled = wholepact_authority::AccountSnapshot {
            transport_fences: None,
            account_use_checkpoint: None,
            witness_id: "synthetic-witness".into(),
            account_id: "synthetic-account".into(),
            network_profile_id: "synthetic-network".into(),
            policy_digest: "01".repeat(32),
            head: wholepact_authority::AuthorityHead {
                sequence: 5,
                digest: "02".repeat(32),
            },
            writer_epoch: 1,
            writer_certificate_digest: "03".repeat(32),
            writer_status: wholepact_authority::WriterStatus::Active,
            outstanding_reservations: 0,
            outstanding_debit_zatoshis: 0,
            settled_debit_zatoshis: 0,
            aggregate_budget_zatoshis: 100,
            reserved_input_value_zatoshis: 0,
            last_witness_time_ms: 7,
            pending_writer_session: None,
            active_writer_session: None,
        };
        assert!(require_same_committed_snapshot(&controlled, &controlled).is_ok());
        let mut changed = controlled.clone();
        changed.head.digest = "04".repeat(32);
        assert!(matches!(
            require_same_committed_snapshot(&controlled, &changed),
            Err(Error::Uncertain)
        ));
        changed = controlled.clone();
        changed.head.sequence += 1;
        assert!(require_same_committed_snapshot(&controlled, &changed).is_err());
        changed = controlled.clone();
        changed.account_id = "another-account".into();
        assert!(require_same_committed_snapshot(&controlled, &changed).is_err());
    }
    #[test]
    fn production_owner_response_is_distinct_from_full_history_status() {
        // Static contract regression, not a substitute for the actual native
        // qualification. The actual response owns the complete retained intent.
        let source = include_str!("durable_delivery_admission_v2.rs");
        let send = source
            .split("pub(super) fn approve_durable_delivery_v2(")
            .nth(1)
            .unwrap()
            .split("pub(super) fn begin_durable_delivery_history_audit_v2")
            .next()
            .unwrap();
        assert!(
            send.find("retain_durable_delivery_admission_intent_v2")
                .unwrap()
                < send.find("durable_delivery_admit_v2").unwrap()
        );
        assert!(send.contains("let controlled = owner.durable_delivery_admit_v2"));
        assert!(send.contains("DeliveryOutcomeV2::AwaitingAudit"));
        assert!(!send.contains("source_history("));
        assert!(!send.contains("DeliveryOutcomeV2::Completed"));
        let audit = source
            .split("pub(super) fn begin_durable_delivery_history_audit_v2")
            .nth(1)
            .unwrap()
            .split("pub(super) fn poll_durable_delivery_v2")
            .next()
            .unwrap();
        assert!(!audit.contains("durable_delivery_admit_v2"));
        assert!(audit.contains("start_readonly_audit_once(&pending.audit_started)"));
        assert!(audit.contains("pending.deadline"));
        assert!(
            audit.find("durable_delivery_history_v2").unwrap()
                < audit.find("send_response(").unwrap()
        );
        assert!(
            audit.contains(
                "require_same_committed_snapshot(&pending.controlled, history.snapshot())"
            )
        );
        assert!(!audit.contains("awaiting_audit.take()"));
    }
}
