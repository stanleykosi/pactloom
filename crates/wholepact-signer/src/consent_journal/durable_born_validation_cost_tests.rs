//! No-socket, never-funded mathematical/history component measurement only.
//! The actual encrypted journal checker reads one original disclosure and two
//! DIRECT redisclosures of unchanged one-note material. This is the CI12 row
//! topology, not its balances: maintained synthetic owners select 200_000 and
//! 300_000 zatoshis and debit 105_000 and 210_000, respectively. No native owner,
//! authenticated peer, source/certificate admission, privacy callback, signing,
//! or full native callback equivalence is claimed or manufactured here.
use super::*;
use crate::authority_bridge::durable_construction_v1::{
    DurableConstructionOutboxV1, DurableConstructionRedisclosureLinkV1,
    DurableConstructionRequestV1,
};
use crate::consent_journal::storage::validation_cost_v1::{emit, measure, Phase, Sample};
use crate::consent_journal::{Result as JournalResult, SCHEMA_VERSION as JOURNAL_SCHEMA_VERSION};
use wholepact_core::*;
use wholepact_protocol::{
    durable_proposal_v1::canonical_durable_account_id, review::encode_testnet_receiver,
};
use wholepact_wallet::wallet::{
    protected_sync::durable_construction_v1::{
        ConstructionRecipientV1, ConstructionReviewerV1, DurableConstructionScopeV1,
        HistoricalConstructionMaterialV1, PURPOSE,
    },
    WalletContribution,
};
use zeroize::Zeroizing;

// No error formatting or value-rendering assertions: neither measurements nor
// failure output should disclose material, identifiers, witnesses or payloads.
#[track_caller]
fn checked<T, E>(result: std::result::Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("synthetic measurement fixture operation failed"),
    }
}

fn hash_label(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn amount(value: u64) -> Amount {
    checked(Amount::from_zatoshis(value))
}

fn mathematical_material(owner: &WalletContribution) -> Zeroizing<Vec<u8>> {
    let context = owner.context();
    let notes = owner
        .notes()
        .iter()
        .map(|selected| {
            // Public IDs use display-order txids, whereas the material codec
            // requires protocol order and independently verifies their join.
            let mut fields = selected.input_id.split(':');
            assert!(fields.next() == Some("ironwood"));
            let mut txid = checked(hex::decode(fields.next().unwrap_or("")));
            assert!(txid.len() == 32);
            txid.reverse();
            let index = checked(fields.next().unwrap_or("").parse::<u16>());
            assert!(fields.next().is_none());
            serde_json::json!({
                "input_id": selected.input_id,
                "txid_protocol": hex::encode(txid),
                "output_index": index,
                "recipient": hex::encode(selected.note.recipient().to_raw_address_bytes()),
                "value_zatoshis": selected.note.value().inner(),
                "rho": hex::encode(selected.note.rho().to_bytes()),
                "rseed": hex::encode(selected.note.rseed().as_bytes()),
                "nullifier": hex::encode(selected.note.nullifier(owner.fvk()).to_bytes()),
                "commitment": hex::encode(orchard::note::ExtractedNoteCommitment::from(selected.note.commitment()).to_bytes()),
                "position": selected.witness.position(),
                "authentication_path": selected.witness.auth_path().iter().map(|p| hex::encode(p.to_bytes())).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    Zeroizing::new(checked(serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "account_id": canonical_durable_account_id(owner.fvk()),
        "fvk_hex": hex::encode(owner.fvk().to_bytes()),
        "fvk_digest": hex::encode(Sha256::digest(owner.fvk().to_bytes())),
        "selected_zatoshis": owner.selected_zatoshis(),
        "requested_debit_zatoshis": owner.requested_debit_zatoshis(),
        "change_address": hex::encode(owner.change_address().to_raw_address_bytes()),
        "birthday_height": context.anchor_height,
        "context": {
            "tip_height": context.tip_height,
            "tip_hash_protocol": hex::encode(context.tip_hash_protocol),
            "anchor_height": context.anchor_height,
            "anchor_hash_protocol": hex::encode(context.anchor_hash_protocol),
            "anchor_root": hex::encode(context.anchor_root)
        },
        // Historical data labels only. This does not construct or authenticate
        // a ChainContext, source permit, TLS connection, or network observation.
        "source": {
            "source_id": "synthetic-journal-cost-component",
            "endpoint": "https://component.invalid",
            "trust_profile": "single_tls_provider_report_not_consensus",
            "network": "test",
            "branch_id": "0x77190ad9",
            "lightwalletd_version": "synthetic-component",
            "backend_subversion": "synthetic-no-backend",
            "protocol_version": "synthetic-component-v1",
            "request_started": 1_800_000_000u64,
            "observed_at": 1_800_000_001u64,
            "valid_until": 1_800_000_060u64
        },
        "notes": notes
    }))))
}

fn scope(owners: &[WalletContribution]) -> DurableConstructionScopeV1 {
    assert!(owners.len() == 2);
    assert!(owners.iter().all(|owner| owner.notes().len() == 1));
    assert!(owners[0].selected_zatoshis() == 200_000);
    assert!(owners[1].selected_zatoshis() == 300_000);
    assert!(owners[0].requested_debit_zatoshis() == 105_000);
    assert!(owners[1].requested_debit_zatoshis() == 210_000);
    let receiver = encode_testnet_receiver(&owners[0].notes()[0].note.recipient());
    let mut participants = Vec::new();
    let mut inputs = Vec::new();
    let mut outputs = vec![ClaimedOutput {
        output_id: "synthetic-recipient-output".into(),
        address: receiver.clone(),
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: "synthetic-recipient".into(),
        },
    }];
    for (index, owner) in owners.iter().enumerate() {
        let account = canonical_durable_account_id(owner.fvk());
        let participant = format!("synthetic-participant-{index}");
        let fee = if index == 0 { 5_000 } else { 10_000 };
        participants.push(ParticipantAllocation {
            participant_id: participant.clone(),
            account_id: account.clone(),
            contribution: amount(owner.requested_debit_zatoshis() - fee),
            fee_share: amount(fee),
            fee_cap: amount(fee),
            maximum_net_debit: amount(owner.requested_debit_zatoshis()),
            charges: vec![],
        });
        let note = &owner.notes()[0];
        inputs.push(ClaimedInput {
            input_id: note.input_id.clone(),
            participant_id: participant.clone(),
            account_id: account.clone(),
            amount: amount(note.note.value().inner()),
            ownership_evidence_ref: None,
        });
        outputs.push(ClaimedOutput {
            output_id: format!("synthetic-return-{index}"),
            address: encode_testnet_receiver(&owner.change_address()),
            amount: amount(owner.selected_zatoshis() - owner.requested_debit_zatoshis()),
            allocation: OutputAllocation::Return {
                participant_id: participant,
                account_id: account,
                ownership_evidence_ref: None,
            },
        });
    }
    DurableConstructionScopeV1 {
        version: 2,
        purpose: PURPOSE.into(),
        proposal: ProposalInput {
            proposal_id: "synthetic-fixed-candidate".into(),
            previous_proposal_id: None,
            manifest: ProposalManifest {
                agreement: AgreementDraft {
                    schema_version: 1,
                    agreement_id: "synthetic-journal-cost-agreement".into(),
                    obligation_id: "synthetic-never-funded-obligation".into(),
                    revision: 1,
                    purpose: "Data-only encrypted journal validation cost".into(),
                    organizer_identity: "synthetic-component".into(),
                    network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
                    recipients: vec![Recipient {
                        recipient_id: "synthetic-recipient".into(),
                        address: receiver,
                        amount: amount(300_000),
                        memo: None,
                        instruction_provenance: "synthetic-component".into(),
                    }],
                    funding_policy: FundingPolicy::Exact {
                        target: amount(300_000),
                    },
                    fee_policy: FeePolicy::ProRata,
                    privacy_profile: PrivacyProfile {
                        mode: PrivacyMode::DeclaredOperator,
                        proving_operator: Some("synthetic-local-component".into()),
                        dedicated_accounts_required: true,
                    },
                    coordination_deadline: None,
                    confirmation_policy: ConfirmationPolicy::default(),
                    extensions: vec![],
                },
                participants,
                inputs,
                outputs,
                transaction_fee: amount(15_000),
                expiry_height: owners[0].context().tip_height + 30,
            },
            artifact_digest: None,
            effects_commitment: None,
            created_at: "2026-10-17T00:00:00Z".into(),
        },
        account_id: canonical_durable_account_id(owners[0].fvk()),
        participant_id: "synthetic-participant-0".into(),
        privacy_domain: "synthetic-dedicated-domain".into(),
        constructor: ConstructionRecipientV1 {
            principal_id: "synthetic-constructor".into(),
            authenticated_local_grant_digest: hash_label(0x20),
        },
        prover: ConstructionRecipientV1 {
            principal_id: "synthetic-prover".into(),
            authenticated_local_grant_digest: hash_label(0x20),
        },
        reviewers: owners
            .iter()
            .map(|owner| {
                ConstructionReviewerV1::local_installed_signer(canonical_durable_account_id(
                    owner.fvk(),
                ))
            })
            .collect(),
        protected_destination: "/synthetic-component/private/intake.sqlite".into(),
        retention_policy: "Retain exact encrypted synthetic construction data only".into(),
        valid_from_unix_seconds: 1_800_000_000,
        valid_until_unix_seconds: 1_800_003_600,
        minimum_confirmations: 1,
        maximum_scan_blocks: 100,
    }
}

pub(crate) struct MaterialFixture {
    encrypted: Fixture,
    rows: Vec<DurableConstructionOutboxV1>,
    material_bytes: Zeroizing<Vec<u8>>,
}

impl MaterialFixture {
    fn new() -> Self {
        Self::with_generations(false)
    }

    // Historical DATA only. Preserve the legacy 1+index fixture above.
    pub(crate) fn coordinated() -> Self {
        Self::with_generations(true)
    }

    pub(crate) fn legacy() -> Self { Self::new() }
    pub(crate) fn journal(&self) -> &SignerConsentJournal { &self.encrypted.journal }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis { &self.encrypted.genesis }
    pub(crate) fn disclosure(&self) -> &WitnessDisclosureDescriptor { &self.encrypted.disclosure }
    pub(crate) fn rows(&self) -> &[DurableConstructionOutboxV1] { &self.rows }

    fn with_generations(coordinated: bool) -> Self {
        let (owners, _) = checked(wholepact_wallet::wallet::synthetic_scanned_contributions());
        let base_scope = scope(&owners);
        let material_bytes = mathematical_material(&owners[0]);
        // This is the actual mathematical decoder, not a fixture bypass.
        let material = checked(HistoricalConstructionMaterialV1::decode(&material_bytes));
        checked(material.verify_owner(owners[0].fvk()));
        assert!(material.input_ids().count() == 1);
        let encrypted = Fixture::with_identity(AccountUseIdentity {
            account_id: material.account_id().into(),
            full_viewing_key_digest: material.fvk_digest().into(),
            network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        });
        let material_digest = checked(material.digest());
        let proposal = checked(Proposal::validate(base_scope.proposal.clone()));
        let mut rows: Vec<DurableConstructionOutboxV1> = Vec::new();
        {
            let mut connection = checked(encrypted.journal.connection.lock());
            let tx = checked(connection.transaction());
            for index in 0u8..3 {
                let grant = hash_label(0x20 + index);
                let grant_id = hash_label(0x30 + index);
                let channel = hash_label(0x40 + index);
                // Inert serialized historical data labels, NOT a real process
                // identity, pairing grant, native receipt issuer or approval.
                let transport = TransportIdentityBinding::LocalProcess {
                    transport_identity_id: grant_id.clone(),
                    channel_key_digest: grant.clone(),
                    channel_binding_digest: channel.clone(),
                    uid: 42,
                    pid: 100 + u32::from(index),
                    process_instance: hash_label(0x50 + index),
                    signer_generation: if coordinated { 1 } else { 1 + u64::from(index) },
                    account_id: base_scope.account_id.clone(),
                    agreement_id: proposal.manifest().agreement.agreement_id.clone(),
                    participant_id: base_scope.participant_id.clone(),
                    manifest_digest: proposal.manifest_digest().into(),
                };
                let receipt = NativeConsentReceipt {
                    native_session_id: hash_label(0x60 + index),
                    trusted_launch_measurement: hash_label(0x70),
                    permission_generation: if coordinated { 1 } else { 1 + u64::from(index) },
                    writer_epoch: 7,
                    nonce: hash_label(0x80 + index),
                    reviewed_at_ms: 100_000,
                    expires_at_ms: 160_000,
                };
                let enrollment = checked(AccountEnrollmentRecord::new(EnrollmentTerms {
                    account_id: base_scope.account_id.clone(),
                    agreement_id: proposal.manifest().agreement.agreement_id.clone(),
                    participant_id: base_scope.participant_id.clone(),
                    principal_id: "synthetic-historical-owner-label".into(),
                    network_profile_id: proposal.manifest().agreement.network_profile_id.clone(),
                    privacy_domain: base_scope.privacy_domain.clone(),
                    account_fvk_digest: material.fvk_digest().into(),
                    transport: transport.clone(),
                    aggregate_budget_limit_zatoshis: 1_000_000,
                    receipt: receipt.clone(),
                }));
                let manifest = checked(AcceptedManifestRecord::new(ManifestTerms {
                    enrollment_ref: enrollment.reference().into(),
                    account_id: base_scope.account_id.clone(),
                    principal_id: enrollment.principal_id().into(),
                    proposal: base_scope.proposal.clone(),
                    proposal_digest: proposal.proposal_digest().into(),
                    manifest_digest: proposal.manifest_digest().into(),
                    receipt,
                }));
                assert!(same_native_origin(enrollment.receipt(), manifest.receipt()));
                let mut current_scope = base_scope.clone();
                current_scope.constructor.authenticated_local_grant_digest = grant.clone();
                current_scope.prover.authenticated_local_grant_digest = grant.clone();
                let request = DurableConstructionRequestV1 {
                    operation_id: format!("synthetic-material-operation-{index}"),
                    enrollment_ref: enrollment.reference().into(),
                    accepted_manifest_ref: manifest.reference().into(),
                    scope: current_scope,
                    material: material.clone(),
                };
                let redisclosure =
                    rows.first()
                        .map(|original| DurableConstructionRedisclosureLinkV1 {
                            original_operation_id: original.request.operation_id.clone(),
                            original_request_digest: original.request_digest.clone(),
                            original_outbox_reference: original.reference.clone(),
                        });
                let mut outbox = DurableConstructionOutboxV1 {
                    request_digest: checked(request.digest()),
                    request,
                    material_digest: material_digest.clone(),
                    native_review_digest: hash_label(0x90 + index),
                    native_entry_digest: hash_label(0xa0 + index),
                    recipient_grant_digest: grant,
                    original_channel_digest: channel,
                    original_grant_id: grant_id,
                    recipient_transport: transport,
                    redisclosure,
                    reference: String::new(),
                };
                outbox.reference = checked(outbox.compute_reference());
                checked(tx.execute(
                    "INSERT INTO signer_enrollments(reference,account_id,agreement_id,participant_id,payload) VALUES(?1,?2,?3,?4,?5)",
                    params![enrollment.reference(), enrollment.account_id(), enrollment.agreement_id(), enrollment.participant_id(), checked(encode(&enrollment)).as_str()],
                ));
                checked(tx.execute(
                    "INSERT INTO signer_accepted_manifests(reference,enrollment_ref,proposal_id,proposal_digest,payload) VALUES(?1,?2,?3,?4,?5)",
                    params![manifest.reference(), manifest.enrollment_ref(), manifest.proposal_input().proposal_id, manifest.proposal_digest(), checked(encode(&manifest)).as_str()],
                ));
                checked(tx.execute(
                    "INSERT INTO signer_durable_construction_outbox(operation_id,request_digest,enrollment_ref,manifest_ref,payload) VALUES(?1,?2,?3,?4,?5)",
                    params![outbox.request.operation_id, outbox.request_digest, outbox.request.enrollment_ref, outbox.request.accepted_manifest_ref, checked(encode(&outbox)).as_str()],
                ));
                rows.push(outbox);
            }
            checked(tx.commit());
        }
        Self {
            encrypted,
            rows,
            material_bytes,
        }
    }

    fn assert_topology(&self) {
        assert!(self.rows.len() == 3);
        assert!(self.rows[0].redisclosure.is_none());
        for (index, row) in self.rows.iter().enumerate().skip(1) {
            checked(row.validate_redisclosure_of(&self.rows[0]));
            for prior in &self.rows[..index] {
                assert!(row.request.operation_id != prior.request.operation_id);
                assert!(row.request.enrollment_ref != prior.request.enrollment_ref);
                assert!(row.request.accepted_manifest_ref != prior.request.accepted_manifest_ref);
                assert!(row.recipient_grant_digest != prior.recipient_grant_digest);
            }
            assert!(row.request.material == self.rows[0].request.material);
        }
        let c = checked(self.encrypted.journal.connection.lock());
        let counts: (u64, u64, u64, u64, u64) = checked(c.query_row(
            "SELECT (SELECT count(*) FROM signer_enrollments), (SELECT count(*) FROM signer_accepted_manifests), (SELECT count(*) FROM signer_durable_construction_outbox), (SELECT count(*) FROM signer_original_consents), (SELECT count(*) FROM signer_release_intents)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ));
        assert!(counts == (3, 3, 3, 0, 0));
        let mut query = checked(c.prepare(
            "SELECT operation_id,request_digest,enrollment_ref,manifest_ref,payload FROM signer_durable_construction_outbox ORDER BY operation_id",
        ));
        let stored = checked(query.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        }));
        let stored = checked(stored.collect::<std::result::Result<Vec<_>, _>>());
        assert!(stored.len() == 3);
        for ((operation, digest, enrollment, manifest, payload), expected) in
            stored.into_iter().zip(&self.rows)
        {
            let actual: DurableConstructionOutboxV1 = checked(decode(payload));
            assert!(actual == *expected);
            assert!(operation == actual.request.operation_id);
            assert!(digest == actual.request_digest);
            assert!(enrollment == actual.request.enrollment_ref);
            assert!(manifest == actual.request.accepted_manifest_ref);
        }
    }
}

// Frozen pre-consolidation composition. Keep the independent public request
// validator/digest and material digest calls, including their original order.
// This is DATA-ONLY validation of inert DTOs, never a native authority source.
// Do not replace this reference with validate_with_proposal or a shared helper.
fn frozen_outbox_hash(value: &str) -> crate::authority_bridge::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(crate::authority_bridge::BridgeError::Binding);
    }
    Ok(())
}

fn frozen_outbox_reference(
    outbox: &DurableConstructionOutboxV1,
) -> crate::authority_bridge::Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:durable-construction-consent-outbox:v1",
        &(
            &outbox.request_digest,
            &outbox.material_digest,
            &outbox.native_review_digest,
            &outbox.native_entry_digest,
            &outbox.recipient_grant_digest,
            &outbox.original_channel_digest,
            &outbox.original_grant_id,
            &outbox.recipient_transport,
            &outbox.redisclosure,
        ),
    )
    .map_err(|_| crate::authority_bridge::BridgeError::Binding)
}

fn frozen_outbox_proposal(
    outbox: &DurableConstructionOutboxV1,
) -> crate::authority_bridge::Result<Proposal> {
    use crate::authority_bridge::BridgeError;

    if let Some(link) = &outbox.redisclosure {
        crate::review::validate_label(&link.original_operation_id)
            .map_err(|_| BridgeError::Binding)?;
        frozen_outbox_hash(&link.original_request_digest)?;
        frozen_outbox_hash(&link.original_outbox_reference)?;
        if link.original_operation_id == outbox.request.operation_id {
            return Err(BridgeError::Binding);
        }
    }
    let TransportIdentityBinding::LocalProcess {
        transport_identity_id,
        channel_key_digest,
        channel_binding_digest,
        uid: _,
        pid,
        process_instance,
        signer_generation,
        account_id,
        agreement_id,
        participant_id,
        manifest_digest,
    } = &outbox.recipient_transport
    else {
        return Err(BridgeError::Binding);
    };
    frozen_outbox_hash(process_instance)?;
    let proposal = outbox.request.validate()?;
    if *pid == 0
        || *signer_generation == 0
        || transport_identity_id != &outbox.original_grant_id
        || channel_key_digest != &outbox.recipient_grant_digest
        || channel_binding_digest != &outbox.original_channel_digest
        || account_id != &outbox.request.scope.account_id
        || agreement_id != &proposal.manifest().agreement.agreement_id
        || participant_id != &outbox.request.scope.participant_id
        || manifest_digest != proposal.manifest_digest()
    {
        return Err(BridgeError::Binding);
    }
    for h in [
        &outbox.request_digest,
        &outbox.material_digest,
        &outbox.native_review_digest,
        &outbox.native_entry_digest,
        &outbox.recipient_grant_digest,
        &outbox.original_channel_digest,
        &outbox.reference,
    ] {
        frozen_outbox_hash(h)?;
    }
    frozen_outbox_hash(&outbox.original_grant_id)?;
    let encoded = Zeroizing::new(serde_json::to_vec(outbox).map_err(|_| BridgeError::Binding)?);
    if encoded.len() > 128 * 1024 - 64 {
        return Err(BridgeError::Limit);
    }
    if outbox.request.digest()? != outbox.request_digest
        || outbox
            .request
            .material
            .digest()
            .map_err(|_| BridgeError::Binding)?
            != outbox.material_digest
        || outbox
            .request
            .scope
            .constructor
            .authenticated_local_grant_digest
            != outbox.recipient_grant_digest
        || outbox.request.scope.prover.authenticated_local_grant_digest
            != outbox.recipient_grant_digest
        || frozen_outbox_reference(outbox)? != outbox.reference
    {
        return Err(BridgeError::Binding);
    }
    Ok(proposal)
}

#[derive(Clone, Copy)]
enum ExpectedOutboxResult {
    Valid,
    Binding,
    Limit,
}

fn same_bridge_result_category<T, U>(
    left: &crate::authority_bridge::Result<T>,
    right: &crate::authority_bridge::Result<U>,
) -> bool {
    match (left, right) {
        (Ok(_), Ok(_)) => true,
        (Err(left), Err(right)) => std::mem::discriminant(left) == std::mem::discriminant(right),
        _ => false,
    }
}

fn assert_outbox_composition_results(
    outbox: &DurableConstructionOutboxV1,
    frozen: crate::authority_bridge::Result<Proposal>,
    combined: crate::authority_bridge::Result<Proposal>,
    expected: ExpectedOutboxResult,
) {
    use crate::authority_bridge::BridgeError;

    assert!(
        same_bridge_result_category(&frozen, &combined),
        "frozen and combined outbox result categories differed"
    );
    assert!(
        same_bridge_result_category(&frozen, &outbox.validate()),
        "public outbox result category differed"
    );
    assert!(
        matches!(
            (&frozen, expected),
            (Ok(_), ExpectedOutboxResult::Valid)
                | (Err(BridgeError::Binding), ExpectedOutboxResult::Binding)
                | (Err(BridgeError::Limit), ExpectedOutboxResult::Limit)
        ),
        "frozen outbox result category differed from expected"
    );
    if let (Ok(frozen), Ok(combined)) = (frozen, combined) {
        // Equality covers the complete Proposal, including accounting and both
        // Proposal digests, without printing any material on assertion failure.
        assert!(frozen == combined, "validated Proposals differed");
        assert!(
            frozen == checked(Proposal::validate(outbox.request.scope.proposal.clone())),
            "validated Proposal differed from independent proposal validation"
        );
        let request_digest = checked(outbox.request.digest());
        let material_digest = checked(outbox.request.material.digest());
        assert!(request_digest == outbox.request_digest);
        assert!(material_digest == outbox.material_digest);
        assert!(
            request_digest
                == checked(wholepact_core::proposal::canonical_digest(
                    "wholepact:durable-construction-disclosure-request:v1",
                    &outbox.request,
                ))
        );
        assert!(
            material_digest
                == checked(wholepact_core::proposal::canonical_digest(
                    "wholepact:historical-construction-material:v1",
                    &outbox.request.material,
                ))
        );
        assert!(outbox.reference == checked(frozen_outbox_reference(outbox)));
    }
}

fn assert_outbox_composition(outbox: &DurableConstructionOutboxV1, expected: ExpectedOutboxResult) {
    assert_outbox_composition_results(
        outbox,
        frozen_outbox_proposal(outbox),
        outbox.validate_with_proposal(),
        expected,
    );
}

fn mutated_outbox_field(
    original: &DurableConstructionOutboxV1,
    pointer: &str,
    replacement: serde_json::Value,
) -> DurableConstructionOutboxV1 {
    let mut value = checked(serde_json::to_value(original));
    *value
        .pointer_mut(pointer)
        .expect("synthetic outbox field missing") = replacement;
    checked(serde_json::from_value(value))
}

#[test]
fn encrypted_material_outbox_composition_matches_frozen_original_and_direct_links() {
    let f = MaterialFixture::new();
    f.assert_topology();
    let before = f.logical_commitment();
    for (ordinal, outbox) in f.rows.iter().enumerate() {
        let (frozen, frozen_costs) = measure(|| frozen_outbox_proposal(outbox));
        let (combined, combined_costs) = measure(|| outbox.validate_with_proposal());
        assert_outbox_composition_results(outbox, frozen, combined, ExpectedOutboxResult::Valid);
        for costs in [&frozen_costs, &combined_costs] {
            assert!(costs.calls(Phase::SampleTotal) == 1);
            assert!(costs.calls(Phase::SnapshotTotal) == 0);
            assert!(!costs.is_clamped() && !costs.is_incomplete());
        }
        // Exactly three paired samples on inert values. No timing threshold,
        // speedup claim, material, digests, payloads or native qualification.
        eprintln!(
            "LOCAL_DURABLE_OUTBOX_COMPOSITION_V1 component_only=true ordinal={} frozen_us={} combined_us={} proposal_and_digests_equal=true",
            ordinal + 1,
            frozen_costs.inclusive_us(Phase::SampleTotal),
            combined_costs.inclusive_us(Phase::SampleTotal),
        );
    }
    f.assert_topology();
    assert!(
        before == f.logical_commitment(),
        "composition changed retained history"
    );
}

#[test]
fn encrypted_material_outbox_composition_matches_frozen_mutations() {
    let f = MaterialFixture::new();
    f.assert_topology();
    let before = f.logical_commitment();
    // Every case starts from the same real original material, not a previous
    // corruption. Serde permits inspecting invalid inert DTOs without decoding
    // them through a validating material API or creating a live wallet owner.
    for (pointer, replacement) in [
        ("/request/operation_id", serde_json::json!("")),
        (
            "/request/operation_id",
            serde_json::json!("invalid operation"),
        ),
        ("/request/operation_id", serde_json::json!("x".repeat(129))),
        ("/request/enrollment_ref", serde_json::json!("bad")),
        (
            "/request/enrollment_ref",
            serde_json::json!("AB".repeat(32)),
        ),
        (
            "/request/enrollment_ref",
            serde_json::json!(hash_label(0xe1)),
        ),
        ("/request/accepted_manifest_ref", serde_json::json!("bad")),
        (
            "/request/accepted_manifest_ref",
            serde_json::json!(hash_label(0xe2)),
        ),
        ("/request/scope/version", serde_json::json!(0)),
        ("/request/scope/purpose", serde_json::json!("other-purpose")),
        (
            "/request/scope/account_id",
            serde_json::json!(hash_label(0xe3)),
        ),
        (
            "/request/scope/participant_id",
            serde_json::json!("other-participant"),
        ),
        ("/request/scope/minimum_confirmations", serde_json::json!(0)),
        (
            "/request/scope/maximum_scan_blocks",
            serde_json::json!(1001),
        ),
        (
            "/request/scope/valid_until_unix_seconds",
            serde_json::json!(1_800_000_000u64),
        ),
        (
            "/request/scope/protected_destination",
            serde_json::json!("relative/intake.sqlite"),
        ),
        ("/request/scope/reviewers", serde_json::json!([])),
        (
            "/request/scope/proposal/manifest/expiry_height",
            serde_json::json!(1),
        ),
        (
            "/request/scope/constructor/authenticated_local_grant_digest",
            serde_json::json!(hash_label(0xe4)),
        ),
        (
            "/request/scope/prover/authenticated_local_grant_digest",
            serde_json::json!(hash_label(0xe5)),
        ),
        ("/request/material/version", serde_json::json!(2)),
        (
            "/request/material/account_id",
            serde_json::json!(hash_label(0xe6)),
        ),
        (
            "/request/material/fvk_hex",
            serde_json::json!("00".repeat(96)),
        ),
        (
            "/request/material/fvk_digest",
            serde_json::json!(hash_label(0xe7)),
        ),
        (
            "/request/material/selected_zatoshis",
            serde_json::json!(199_999u64),
        ),
        (
            "/request/material/requested_debit_zatoshis",
            serde_json::json!(105_001u64),
        ),
        ("/request/material/birthday_height", serde_json::json!(0)),
        (
            "/request/material/source/network",
            serde_json::json!("main"),
        ),
        (
            "/request/material/source/endpoint",
            serde_json::json!("http://component.invalid"),
        ),
        (
            "/request/material/source/observed_at",
            serde_json::json!(1_800_000_060u64),
        ),
        (
            "/request/material/context/anchor_root",
            serde_json::json!(hash_label(0xe8)),
        ),
        (
            "/request/material/notes/0/value_zatoshis",
            serde_json::json!(199_999u64),
        ),
        (
            "/request/material/notes/0/nullifier",
            serde_json::json!(hash_label(0xe9)),
        ),
        (
            "/request/material/notes/0/commitment",
            serde_json::json!(hash_label(0xea)),
        ),
        (
            "/request/material/notes/0/authentication_path/0",
            serde_json::json!(hash_label(0xeb)),
        ),
        ("/request_digest", serde_json::json!("bad")),
        ("/request_digest", serde_json::json!(hash_label(0xec))),
        ("/material_digest", serde_json::json!("bad")),
        ("/material_digest", serde_json::json!(hash_label(0xed))),
        ("/native_review_digest", serde_json::json!(hash_label(0xee))),
        ("/native_entry_digest", serde_json::json!(hash_label(0xef))),
        (
            "/recipient_grant_digest",
            serde_json::json!(hash_label(0xf0)),
        ),
        (
            "/original_channel_digest",
            serde_json::json!(hash_label(0xf1)),
        ),
        ("/original_grant_id", serde_json::json!(hash_label(0xf2))),
        ("/reference", serde_json::json!("bad")),
        ("/reference", serde_json::json!(hash_label(0xf3))),
        (
            "/recipient_transport/process_instance",
            serde_json::json!("bad"),
        ),
        ("/recipient_transport/pid", serde_json::json!(0)),
        (
            "/recipient_transport/signer_generation",
            serde_json::json!(0),
        ),
        (
            "/recipient_transport/transport_identity_id",
            serde_json::json!(hash_label(0xf4)),
        ),
        (
            "/recipient_transport/channel_key_digest",
            serde_json::json!(hash_label(0xf5)),
        ),
        (
            "/recipient_transport/channel_binding_digest",
            serde_json::json!(hash_label(0xf6)),
        ),
        (
            "/recipient_transport/account_id",
            serde_json::json!(hash_label(0xf7)),
        ),
        (
            "/recipient_transport/agreement_id",
            serde_json::json!("other-agreement"),
        ),
        (
            "/recipient_transport/participant_id",
            serde_json::json!("other-participant"),
        ),
        (
            "/recipient_transport/manifest_digest",
            serde_json::json!(hash_label(0xf8)),
        ),
        (
            "/recipient_transport",
            serde_json::json!({
                "kind": "remote_authenticated_keys",
                "transport_identity_id": hash_label(0xf9),
                "sender_key_digest": hash_label(0xfa),
                "recipient_key_digest": hash_label(0xfb),
                "channel_binding_digest": hash_label(0xfc),
            }),
        ),
    ] {
        let changed = mutated_outbox_field(&f.rows[0], pointer, replacement);
        assert_outbox_composition(&changed, ExpectedOutboxResult::Binding);
    }
    for (pointer, replacement) in [
        (
            "/redisclosure/original_operation_id",
            serde_json::json!("invalid original"),
        ),
        (
            "/redisclosure/original_operation_id",
            serde_json::json!(f.rows[2].request.operation_id),
        ),
        (
            "/redisclosure/original_request_digest",
            serde_json::json!("bad"),
        ),
        (
            "/redisclosure/original_outbox_reference",
            serde_json::json!("bad"),
        ),
    ] {
        let changed = mutated_outbox_field(&f.rows[2], pointer, replacement);
        assert_outbox_composition(&changed, ExpectedOutboxResult::Binding);
    }
    f.assert_topology();
    assert!(
        before == f.logical_commitment(),
        "mutation comparison changed retained history"
    );
}

// Fill only optional, bounded inert extension strings. This leaves the actual
// scanned note, arithmetic and material topology unchanged. Raw canonical
// digests construct test inputs only; neither result is trusted for validation.
fn outbox_with_request_bytes(
    original: &DurableConstructionOutboxV1,
    target: usize,
) -> DurableConstructionOutboxV1 {
    let mut outbox = original.clone();
    outbox.request.scope.proposal.manifest.agreement.extensions = (0..8)
        .map(|index| Extension {
            name: format!("synthetic-size-padding-{index}"),
            required: false,
            schema_version: 1,
            value: serde_json::json!(""),
        })
        .collect();
    let initial = Zeroizing::new(checked(serde_json::to_vec(&outbox.request))).len();
    assert!(target >= initial);
    let mut remaining = target - initial;
    for extension in &mut outbox.request.scope.proposal.manifest.agreement.extensions {
        let count = remaining.min(16_382);
        extension.value = serde_json::json!("x".repeat(count));
        remaining -= count;
    }
    assert!(
        remaining == 0,
        "size fixture exceeded bounded extension capacity"
    );
    assert!(Zeroizing::new(checked(serde_json::to_vec(&outbox.request))).len() == target);
    let proposal = checked(outbox.request.scope.validate());
    checked(outbox.request.material.validate_for(&outbox.request.scope));
    let TransportIdentityBinding::LocalProcess {
        manifest_digest, ..
    } = &mut outbox.recipient_transport
    else {
        panic!("synthetic local transport missing");
    };
    *manifest_digest = proposal.manifest_digest().into();
    outbox.request_digest = checked(wholepact_core::proposal::canonical_digest(
        "wholepact:durable-construction-disclosure-request:v1",
        &outbox.request,
    ));
    outbox.reference = checked(frozen_outbox_reference(&outbox));
    outbox
}

#[test]
fn encrypted_material_outbox_composition_matches_frozen_size_limits() {
    let f = MaterialFixture::new();
    f.assert_topology();
    let before = f.logical_commitment();
    for bytes in [120 * 1024 - 1, 120 * 1024, 120 * 1024 + 1] {
        let changed = outbox_with_request_bytes(&f.rows[0], bytes);
        assert_outbox_composition(
            &changed,
            if bytes <= 120 * 1024 {
                ExpectedOutboxResult::Valid
            } else {
                ExpectedOutboxResult::Limit
            },
        );
    }
    let oversized = outbox_with_request_bytes(&f.rows[0], 120 * 1024 + 1);
    // The original process hash precedes request validation, but the PID join
    // and outbox hash checks follow the request limit. Competing failures must
    // retain those exact categories, not merely return any refusal.
    for (pointer, replacement, expected) in [
        (
            "/recipient_transport/process_instance",
            serde_json::json!("bad"),
            ExpectedOutboxResult::Binding,
        ),
        (
            "/recipient_transport/pid",
            serde_json::json!(0),
            ExpectedOutboxResult::Limit,
        ),
        (
            "/request/enrollment_ref",
            serde_json::json!("bad"),
            ExpectedOutboxResult::Binding,
        ),
        (
            "/request/material/fvk_digest",
            serde_json::json!(hash_label(0xfd)),
            ExpectedOutboxResult::Binding,
        ),
        (
            "/native_review_digest",
            serde_json::json!("bad"),
            ExpectedOutboxResult::Limit,
        ),
    ] {
        let changed = mutated_outbox_field(&oversized, pointer, replacement);
        assert_outbox_composition(&changed, expected);
    }
    // With valid bounded transport fields, a <=120 KiB request cannot reach
    // the larger 128 KiB envelope bound. A malformed hash can make that envelope
    // oversized, but must still fail its earlier hash check as Binding.
    let mut oversized_envelope = f.rows[0].clone();
    oversized_envelope.native_review_digest = "a".repeat(128 * 1024);
    assert!(
        Zeroizing::new(checked(serde_json::to_vec(&oversized_envelope))).len() > 128 * 1024 - 64
    );
    assert_outbox_composition(&oversized_envelope, ExpectedOutboxResult::Binding);
    f.assert_topology();
    assert!(
        before == f.logical_commitment(),
        "size comparison changed retained history"
    );
}

#[test]
fn encrypted_material_outbox_composition_matches_frozen_link_reference_substitutions() {
    let f = MaterialFixture::new();
    f.assert_valid_baseline();
    let before = f.logical_commitment();
    for case in 0..6 {
        let mut changed = f.rows[2].clone();
        match case {
            0 => changed.request.enrollment_ref = f.rows[1].request.enrollment_ref.clone(),
            1 => {
                changed.request.accepted_manifest_ref =
                    f.rows[1].request.accepted_manifest_ref.clone()
            }
            _ => {
                let link = changed
                    .redisclosure
                    .as_mut()
                    .expect("synthetic direct link missing");
                match case {
                    2 => link.original_request_digest = hash_label(0xe1),
                    3 => link.original_outbox_reference = hash_label(0xe2),
                    4 => link.original_operation_id = "synthetic-missing-original".into(),
                    5 => {
                        link.original_operation_id = f.rows[1].request.operation_id.clone();
                        link.original_request_digest = f.rows[1].request_digest.clone();
                        link.original_outbox_reference = f.rows[1].reference.clone();
                    }
                    _ => unreachable!(),
                }
            }
        }
        changed.request_digest = checked(changed.request.digest());
        changed.reference = checked(frozen_outbox_reference(&changed));
        // The closed composition validates only the actual object, not a
        // persistent origin. These coherent substitutions remain locally valid
        // under BOTH paths and MUST still fail their independent journal join.
        assert_outbox_composition(&changed, ExpectedOutboxResult::Valid);
        f.replace_outbox(2, &changed);
        {
            let connection = checked(f.encrypted.journal.connection.lock());
            assert_exact_executable_schema(&connection);
        }
        f.assert_reader_parity(
            &f.encrypted.genesis,
            Err(if case == 4 {
                JournalError::NotFound
            } else {
                JournalError::InvalidBinding
            }),
        );
        f.replace_outbox(2, &f.rows[2]);
        assert!(
            before == f.logical_commitment(),
            "substituted history was not restored"
        );
    }
    f.assert_valid_baseline();
    assert!(
        before == f.logical_commitment(),
        "join comparison changed retained history"
    );
}

#[test]
fn encrypted_material_callback_components_are_measured() {
    let (f, setup) = measure(MaterialFixture::new);
    emit(Sample::Setup, &setup);
    f.assert_topology();
    let before = f.encrypted.commitment();

    // First means first full populated snapshot in THIS test, not OS-cold:
    // creation and fixture digesting already exercised storage/math. All three
    // scans retain the SAME live encrypted handle, real identity and read-only
    // production checker. No prewarm standalone measurement precedes them.
    for sample in [Sample::First, Sample::Repeat1, Sample::Repeat2] {
        let (result, costs) = measure(|| {
            f.encrypted
                .journal
                .check_durable_born_entry_v1(&f.encrypted.genesis)
        });
        assert!(
            result.is_ok(),
            "complete historical checker rejected fixture"
        );
        assert!(costs.calls(Phase::SnapshotTotal) == 1);
        assert!(costs.calls(Phase::SchemaTotal) == 1);
        assert!(costs.calls(Phase::DurableMaterialRows) == 1);
        assert!(!costs.is_clamped() && !costs.is_incomplete());
        emit(sample, &costs);
    }

    // Isolated mathematical/request/outbox values are additional diagnostics,
    // NOT subtractable constituents or a model of the entire native callback.
    let (material, costs) = measure(|| HistoricalConstructionMaterialV1::decode(&f.material_bytes));
    assert!(material.is_ok(), "material decoder rejected fixture");
    emit(Sample::Material, &costs);
    let (request, costs) = measure(|| f.rows[0].request.validate());
    assert!(request.is_ok(), "request validator rejected fixture");
    emit(Sample::Request, &costs);
    let (outbox, costs) = measure(|| f.rows[0].validate());
    assert!(outbox.is_ok(), "outbox validator rejected fixture");
    emit(Sample::Outbox, &costs);

    f.assert_topology();
    assert!(
        before == f.encrypted.commitment(),
        "read-only logical commitment changed"
    );
}

#[test]
fn encrypted_material_three_versus_one_checker_sequence_is_component_only() {
    // Separate encrypted fixtures isolate the two bounded sequences. They are
    // not OS-cold samples and do not instantiate Admission/Acquire/Activate,
    // native custody, policy export, a peer or a callback. No speedup ratio or
    // transport-budget claim follows from repeating this component 3 vs 1.
    for invocations in [3u64, 1] {
        let f = MaterialFixture::new();
        f.assert_topology();
        let before = f.logical_commitment();
        DURABLE_BORN_SNAPSHOT_VALIDATIONS_V1.with(|count| count.set(0));
        let mut snapshot_calls = 0;
        let mut schema_calls = 0;
        let mut material_calls = 0;
        for ordinal in 1..=invocations {
            let (result, costs) = measure(|| {
                f.encrypted
                    .journal
                    .check_durable_born_entry_v1(&f.encrypted.genesis)
            });
            assert!(
                result.is_ok(),
                "component checker rejected material history"
            );
            assert!(costs.calls(Phase::SampleTotal) == 1);
            assert!(costs.calls(Phase::SnapshotTotal) == 1);
            assert!(costs.calls(Phase::SchemaTotal) == 1);
            assert!(costs.calls(Phase::DurableMaterialRows) == 1);
            assert!(!costs.is_clamped() && !costs.is_incomplete());
            snapshot_calls += costs.calls(Phase::SnapshotTotal);
            schema_calls += costs.calls(Phase::SchemaTotal);
            material_calls += costs.calls(Phase::DurableMaterialRows);
            DURABLE_BORN_SNAPSHOT_VALIDATIONS_V1.with(|count| assert!(count.get() == ordinal));
            assert!(
                before == f.logical_commitment(),
                "component read changed history"
            );
            // Fixed labels, bounded individual counts/durations, and a boolean
            // commitment comparison only. Never emit raw rows or commitments.
            eprintln!(
                "LOCAL_DURABLE_CHECKER_SEQUENCE_V1 component_only=true invocations={} ordinal={} snapshot_calls={} schema_calls={} material_calls={} sample_us={} snapshot_us={} schema_us={} material_us={} logical_commitment_unchanged=true",
                invocations,
                ordinal,
                costs.calls(Phase::SnapshotTotal),
                costs.calls(Phase::SchemaTotal),
                costs.calls(Phase::DurableMaterialRows),
                costs.inclusive_us(Phase::SampleTotal),
                costs.inclusive_us(Phase::SnapshotTotal),
                costs.inclusive_us(Phase::SchemaTotal),
                costs.inclusive_us(Phase::DurableMaterialRows),
            );
        }
        assert!(snapshot_calls == invocations);
        assert!(schema_calls == invocations);
        assert!(material_calls == invocations);
        f.assert_topology();
        assert!(
            before == f.logical_commitment(),
            "sequence changed material history"
        );
    }
}

// Differential readers deliberately share the retained SQLCipher handle. Each
// uses a separate real Deferred transaction over the identical logical rows;
// no decrypted copy, alternate schema or cached success is supplied to either.
// The reference is the unchanged three-schema-pass validator, not an alternate
// handwritten semantic implementation. Neither path creates native authority.
fn legacy_snapshot(f: &MaterialFixture, genesis: &AccountUseGenesis) -> JournalResult<()> {
    let journal = &f.encrypted.journal;
    let _fence = journal
        .authority_fence
        .read()
        .map_err(|_| JournalError::Permission)?;
    let mut connection = journal
        .connection
        .lock()
        .map_err(|_| JournalError::Database)?;
    if !connection.is_autocommit() {
        return Err(JournalError::Database);
    }
    journal.database_identity.check_current(&connection)?;
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
    super::super::validate(&tx, genesis, journal.capacity_limits())?;
    journal.database_identity.check_current(&tx)?;
    tx.commit()?;
    Ok(())
}

fn same_result_category(left: &JournalResult<()>, right: &JournalResult<()>) -> bool {
    match (left, right) {
        (Ok(()), Ok(())) => true,
        (Err(left), Err(right)) => std::mem::discriminant(left) == std::mem::discriminant(right),
        _ => false,
    }
}

// This checks ONLY executable schema equality, not row semantics. Calling the
// full schema validator here would itself reject malformed material, masking
// whether the readers under comparison actually inspect the changed rows.
fn assert_exact_executable_schema(connection: &Connection) {
    fn objects(connection: &Connection) -> Vec<(String, String, String, Option<String>)> {
        let mut query = checked(
            connection
                .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"),
        );
        let rows = checked(query.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        }));
        checked(rows.collect::<std::result::Result<Vec<_>, _>>())
    }
    let expected = checked(Connection::open_in_memory());
    checked(expected.execute_batch(SCHEMA));
    assert!(
        objects(connection) == objects(&expected),
        "synthetic schema was not restored"
    );
    let application: i64 =
        checked(connection.pragma_query_value(None, "application_id", |r| r.get(0)));
    let version: i64 = checked(connection.pragma_query_value(None, "user_version", |r| r.get(0)));
    assert!(application == APPLICATION_ID && version == JOURNAL_SCHEMA_VERSION);
}

impl MaterialFixture {
    fn logical_commitment(&self) -> String {
        let connection = checked(self.encrypted.journal.connection.lock());
        checked(writer_history::complete_journal_commitment(&connection))
    }

    fn assert_reader_parity(&self, genesis: &AccountUseGenesis, expected: JournalResult<()>) {
        let before = self.logical_commitment();
        let legacy = legacy_snapshot(self, genesis);
        assert!(
            same_result_category(&legacy, &expected),
            "legacy result category differed"
        );
        assert!(
            before == self.logical_commitment(),
            "legacy read changed retained rows"
        );
        // Invoke the real guarded callback route, retaining its identity and
        // transaction checks. No test-only validated token is passed to it.
        let optimized = self.encrypted.journal.check_durable_born_entry_v1(genesis);
        assert!(
            same_result_category(&optimized, &expected),
            "callback result category differed"
        );
        assert!(
            same_result_category(&legacy, &optimized),
            "reader result categories differed"
        );
        assert!(
            before == self.logical_commitment(),
            "callback read changed retained rows"
        );
    }

    fn assert_valid_baseline(&self) {
        self.assert_topology();
        self.assert_reader_parity(&self.encrypted.genesis, Ok(()));
    }

    // Test-only corruption of inert historical DTO rows. Triggers are copied
    // only after exact executable-schema equality and restored byte-for-byte
    // before either reader runs. Foreign keys are disabled only to create the
    // explicit orphan cases, then enabled again before any validation.
    fn change_rows(
        &self,
        triggers: &[&str],
        allow_orphans: bool,
        change: impl FnOnce(&Connection),
    ) {
        let mut connection = checked(self.encrypted.journal.connection.lock());
        assert_exact_executable_schema(&connection);
        let enabled: bool =
            checked(connection.pragma_query_value(None, "foreign_keys", |r| r.get(0)));
        assert!(enabled && connection.is_autocommit());
        if allow_orphans {
            checked(connection.pragma_update(None, "foreign_keys", false));
        }
        let tx = checked(connection.transaction());
        let saved = triggers
            .iter()
            .map(|name| {
                let sql: String = checked(tx.query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
                    [name],
                    |r| r.get(0),
                ));
                checked(tx.execute_batch(&format!("DROP TRIGGER \"{name}\"")));
                sql
            })
            .collect::<Vec<_>>();
        change(&tx);
        for sql in saved {
            checked(tx.execute_batch(&sql));
        }
        assert_exact_executable_schema(&tx);
        checked(tx.commit());
        if allow_orphans {
            checked(connection.pragma_update(None, "foreign_keys", true));
        }
        let enabled: bool =
            checked(connection.pragma_query_value(None, "foreign_keys", |r| r.get(0)));
        assert!(enabled);
        assert_exact_executable_schema(&connection);
    }

    fn replace_outbox(&self, index: usize, value: &DurableConstructionOutboxV1) {
        self.change_rows(&["signer_durable_construction_outbox_no_update"], false, |c| {
            checked(c.execute(
                "UPDATE signer_durable_construction_outbox SET operation_id=?1,request_digest=?2,enrollment_ref=?3,manifest_ref=?4,payload=?5 WHERE operation_id=?6",
                params![value.request.operation_id, value.request_digest, value.request.enrollment_ref,
                    value.request.accepted_manifest_ref, checked(encode(value)).as_str(), self.rows[index].request.operation_id],
            ));
        });
    }
}

#[test]
fn encrypted_material_legacy_and_callback_match_on_valid_history() {
    let f = MaterialFixture::new();
    f.assert_topology();
    let before = f.logical_commitment();
    let (legacy, legacy_costs) = measure(|| legacy_snapshot(&f, &f.encrypted.genesis));
    assert!(legacy.is_ok(), "legacy reader rejected populated fixture");
    assert!(legacy_costs.calls(Phase::SchemaTotal) == 3);
    assert!(legacy_costs.calls(Phase::DurableMaterialRows) == 3);
    assert!(!legacy_costs.is_clamped() && !legacy_costs.is_incomplete());
    assert!(
        before == f.logical_commitment(),
        "legacy read changed retained rows"
    );
    let (optimized, costs) = measure(|| f.encrypted.check());
    assert!(same_result_category(&legacy, &optimized));
    assert!(costs.calls(Phase::SnapshotTotal) == 1);
    assert!(costs.calls(Phase::SchemaTotal) == 1);
    assert!(costs.calls(Phase::DurableMaterialRows) == 1);
    assert!(!costs.is_clamped() && !costs.is_incomplete());
    assert!(
        before == f.logical_commitment(),
        "callback read changed retained rows"
    );
    f.assert_topology();
}

#[test]
fn encrypted_material_schema_mismatch_matches_legacy() {
    let f = MaterialFixture::new();
    f.assert_valid_baseline();
    let original_trigger: String = {
        let connection = checked(f.encrypted.journal.connection.lock());
        checked(connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name='signer_durable_construction_outbox_no_update'",
            [], |r| r.get(0),
        ))
    };
    // Both absence and a same-name, weakened trigger must fail exact matching.
    for replacement in [None, Some("CREATE TRIGGER signer_durable_construction_outbox_no_update BEFORE UPDATE ON signer_durable_construction_outbox BEGIN SELECT 1; END")] {
        {
            let connection = checked(f.encrypted.journal.connection.lock());
            checked(connection.execute_batch("DROP TRIGGER signer_durable_construction_outbox_no_update"));
            if let Some(sql) = replacement {
                checked(connection.execute_batch(sql));
            }
        }
        f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::UnsupportedSchema));
        {
            let connection = checked(f.encrypted.journal.connection.lock());
            if replacement.is_some() {
                checked(connection.execute_batch("DROP TRIGGER signer_durable_construction_outbox_no_update"));
            }
            checked(connection.execute_batch(&original_trigger));
            assert_exact_executable_schema(&connection);
        }
    }
    for (pragma, wrong, correct) in [
        ("application_id", 0, APPLICATION_ID),
        (
            "user_version",
            JOURNAL_SCHEMA_VERSION - 1,
            JOURNAL_SCHEMA_VERSION,
        ),
    ] {
        checked(checked(f.encrypted.journal.connection.lock()).pragma_update(None, pragma, wrong));
        f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::UnsupportedSchema));
        checked(
            checked(f.encrypted.journal.connection.lock()).pragma_update(None, pragma, correct),
        );
    }
    f.assert_valid_baseline();
}

#[test]
fn encrypted_material_malformed_original_matches_legacy() {
    let f = MaterialFixture::new();
    f.assert_valid_baseline();
    let baseline = f.logical_commitment();
    // Corrupt mathematical material in serialized data, not a live wallet.
    for pointer in [
        "/request/material/notes/0/value_zatoshis",
        "/request/material/notes/0/commitment",
        "/request/material/notes/0/authentication_path/0",
        "/request/material/fvk_digest",
    ] {
        let mut payload = checked(serde_json::to_value(&f.rows[0]));
        let field = payload
            .pointer_mut(pointer)
            .expect("synthetic material field missing");
        *field = if pointer.ends_with("value_zatoshis") {
            serde_json::json!(199_999u64)
        } else {
            serde_json::json!(hash_label(0xff))
        };
        f.change_rows(
            &["signer_durable_construction_outbox_no_update"],
            false,
            |c| {
                checked(c.execute(
                "UPDATE signer_durable_construction_outbox SET payload=?1 WHERE operation_id=?2",
                params![checked(encode(&payload)).as_str(), f.rows[0].request.operation_id],
            ));
            },
        );
        f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::InvalidBinding));
        f.replace_outbox(0, &f.rows[0]);
        assert!(
            baseline == f.logical_commitment(),
            "original material was not restored"
        );
    }
    f.assert_topology();
}

#[test]
fn encrypted_material_direct_link_corruption_matches_legacy() {
    let f = MaterialFixture::new();
    f.assert_valid_baseline();
    let baseline = f.logical_commitment();
    for case in 0..4 {
        let mut changed = f.rows[2].clone();
        let link = changed
            .redisclosure
            .as_mut()
            .expect("synthetic direct link missing");
        match case {
            0 => link.original_request_digest = hash_label(0xe1),
            1 => link.original_outbox_reference = hash_label(0xe2),
            2 => link.original_operation_id = "synthetic-missing-original".into(),
            3 => {
                link.original_operation_id = f.rows[1].request.operation_id.clone();
                link.original_request_digest = f.rows[1].request_digest.clone();
                link.original_outbox_reference = f.rows[1].reference.clone();
            }
            _ => unreachable!(),
        }
        changed.reference = checked(changed.compute_reference());
        // Its own request, material and reference remain valid. Refusal must
        // come from the missing/mismatched/direct-only ancestor join.
        checked(changed.validate());
        f.replace_outbox(2, &changed);
        f.assert_reader_parity(
            &f.encrypted.genesis,
            Err(if case == 2 {
                JournalError::NotFound
            } else {
                JournalError::InvalidBinding
            }),
        );
        f.replace_outbox(2, &f.rows[2]);
        assert!(
            baseline == f.logical_commitment(),
            "direct disclosure was not restored"
        );
    }
    f.assert_topology();
}

#[test]
fn encrypted_material_denormalized_columns_match_legacy() {
    let f = MaterialFixture::new();
    f.assert_valid_baseline();
    let baseline = f.logical_commitment();
    for (column, replacement) in [
        ("operation_id", "synthetic-other-operation".to_string()),
        ("request_digest", hash_label(0xe3)),
        ("enrollment_ref", f.rows[1].request.enrollment_ref.clone()),
        (
            "manifest_ref",
            f.rows[1].request.accepted_manifest_ref.clone(),
        ),
    ] {
        f.change_rows(&["signer_durable_construction_outbox_no_update"], false, |c| {
            checked(c.execute(&format!("UPDATE signer_durable_construction_outbox SET {column}=?1 WHERE operation_id=?2"), params![replacement, f.rows[2].request.operation_id]));
        });
        f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::InvalidBinding));
        let operation = if column == "operation_id" {
            replacement.as_str()
        } else {
            &f.rows[2].request.operation_id
        };
        f.change_rows(&["signer_durable_construction_outbox_no_update"], false, |c| {
            checked(c.execute("UPDATE signer_durable_construction_outbox SET operation_id=?1,request_digest=?2,enrollment_ref=?3,manifest_ref=?4 WHERE operation_id=?5", params![f.rows[2].request.operation_id, f.rows[2].request_digest, f.rows[2].request.enrollment_ref, f.rows[2].request.accepted_manifest_ref, operation]));
        });
        assert!(
            baseline == f.logical_commitment(),
            "outbox columns were not restored"
        );
    }
    // These fail in the later complete local-cell reader, not only in the
    // durable-material reader nested inside the first schema validation.
    for (table, column, reference, trigger) in [
        (
            "signer_enrollments",
            "account_id",
            &f.rows[2].request.enrollment_ref,
            "signer_enrollments_no_update",
        ),
        (
            "signer_accepted_manifests",
            "proposal_digest",
            &f.rows[2].request.accepted_manifest_ref,
            "signer_manifests_no_update",
        ),
    ] {
        let original: String = checked(checked(f.encrypted.journal.connection.lock()).query_row(
            &format!("SELECT {column} FROM {table} WHERE reference=?1"),
            [reference],
            |r| r.get(0),
        ));
        f.change_rows(&[trigger], false, |c| {
            checked(c.execute(
                &format!("UPDATE {table} SET {column}=?1 WHERE reference=?2"),
                params![hash_label(0xe4), reference],
            ));
        });
        f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::InvalidBinding));
        f.change_rows(&[trigger], false, |c| {
            checked(c.execute(
                &format!("UPDATE {table} SET {column}=?1 WHERE reference=?2"),
                params![original, reference],
            ));
        });
        assert!(
            baseline == f.logical_commitment(),
            "local columns were not restored"
        );
    }
    f.assert_topology();
}

#[test]
fn encrypted_material_enrollment_manifest_join_matches_legacy() {
    let f = MaterialFixture::new();
    f.assert_valid_baseline();
    let baseline = f.logical_commitment();
    for change_enrollment in [true, false] {
        let mut changed = f.rows[2].clone();
        if change_enrollment {
            changed.request.enrollment_ref = f.rows[1].request.enrollment_ref.clone();
        } else {
            changed.request.accepted_manifest_ref = f.rows[1].request.accepted_manifest_ref.clone();
        }
        changed.request_digest = checked(changed.request.digest());
        changed.reference = checked(changed.compute_reference());
        checked(changed.validate());
        checked(changed.validate_redisclosure_of(&f.rows[0]));
        f.replace_outbox(2, &changed);
        f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::InvalidBinding));
        f.replace_outbox(2, &f.rows[2]);
        assert!(
            baseline == f.logical_commitment(),
            "historical join was not restored"
        );
    }
    f.assert_topology();
}

#[test]
fn encrypted_material_unsupported_nonempty_history_matches_legacy() {
    let f = MaterialFixture::new();
    f.assert_valid_baseline();
    // Exact schema, unsupported nonempty table. This is deliberately an inert
    // row, not a fabricated authenticated settlement observation or owner.
    f.change_rows(&[], false, |c| {
        checked(c.execute(
            "INSERT INTO signer_settlement_sources(reference,account_id,payload) VALUES(?1,?2,?3)",
            params![
                "synthetic-unsupported-source",
                f.encrypted.genesis.identity.account_id,
                "{}"
            ],
        ));
    });
    f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::RecoveryRequired));
}

#[test]
fn encrypted_material_capacity_bounds_match_legacy() {
    let mut f = MaterialFixture::new();
    f.assert_valid_baseline();
    let original_limits = f.encrypted.journal.capacity_limits();
    let (rows, bytes) = {
        let connection = checked(f.encrypted.journal.connection.lock());
        checked(storage::capacity_estimate(&connection))
    };
    assert!(rows > 0 && bytes > 0);
    for limits in [
        (rows - 1, original_limits.1),
        (original_limits.0, bytes - 1),
    ] {
        f.encrypted.journal.capacity_limits = limits;
        f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::Limit));
    }
    f.encrypted.journal.capacity_limits = (rows, bytes);
    f.assert_reader_parity(&f.encrypted.genesis, Ok(()));
    f.encrypted.journal.capacity_limits = original_limits;
    f.assert_topology();
}

#[test]
fn encrypted_material_genesis_recovery_exclusion_match_legacy() {
    let f = MaterialFixture::new();
    f.assert_valid_baseline();
    let mut wrong = f.encrypted.genesis.clone();
    wrong.native_birth_digest = hash_label(0xe5);
    checked(wrong.validate());
    f.assert_reader_parity(&wrong, Err(JournalError::InvalidBinding));
    wrong.version = 2;
    f.assert_reader_parity(&wrong, Err(JournalError::InvalidBinding));
    f.change_rows(&[], false, |c| {
        checked(c.execute("UPDATE signer_account SET recovery_required=1", []));
    });
    f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::RecoveryRequired));
    f.change_rows(&[], false, |c| {
        checked(c.execute("UPDATE signer_account SET recovery_required=0", []));
    });
    f.assert_reader_parity(&f.encrypted.genesis, Ok(()));
    let exclusion = PermanentAccountExclusion {
        version: 1,
        identity: f.encrypted.genesis.identity.clone(),
        genesis_digest: checked(f.encrypted.genesis.digest()),
        operation_id: "synthetic-retirement-data".into(),
        native_review_digest: hash_label(0xe6),
        reason: ExclusionReason::RetirementRequested,
    };
    f.change_rows(&[], false, |c| {
        checked(c.execute(
            "INSERT INTO signer_account_use_exclusion VALUES(1,?1,?2,?3)",
            params![
                exclusion.genesis_digest,
                checked(exclusion.digest()),
                checked(encode(&exclusion)).as_str()
            ],
        ));
    });
    f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::Permission));
}

#[test]
fn encrypted_material_repeated_reads_observe_changed_rows() {
    let f = MaterialFixture::new();
    f.assert_valid_baseline();
    let before = f.logical_commitment();
    f.change_rows(&["signer_durable_construction_outbox_no_update"], false, |c| {
        checked(c.execute("UPDATE signer_durable_construction_outbox SET request_digest=?1 WHERE operation_id=?2", params![hash_label(0xe7), f.rows[2].request.operation_id]));
    });
    assert!(
        before != f.logical_commitment(),
        "synthetic row mutation did not take effect"
    );
    f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::InvalidBinding));
    f.replace_outbox(2, &f.rows[2]);
    assert!(
        before == f.logical_commitment(),
        "synthetic row was not restored"
    );
    f.assert_reader_parity(&f.encrypted.genesis, Ok(()));
    f.assert_topology();
}

#[test]
fn encrypted_material_orphan_uncertainties_match_legacy() {
    let f = MaterialFixture::new();
    f.assert_valid_baseline();
    let baseline = f.logical_commitment();
    // No native/session approval, original financial evidence or usable permit
    // is manufactured. These intentionally malformed/orphan inert rows prove
    // release counts, foreign-key linkage and typed exposure parsing still run.
    for (insert, table, delete_trigger) in [
        ("INSERT INTO signer_release_intents VALUES('synthetic-orphan','synthetic-absent-original','synthetic-account','synthetic-obligation','1','{}','outstanding_uncertain')", "signer_release_intents", Some("signer_releases_no_delete")),
        ("INSERT INTO signer_input_reservations VALUES('synthetic-account','synthetic-input','synthetic-orphan')", "signer_input_reservations", None),
        ("INSERT INTO signer_remote_inputs VALUES('synthetic-orphan','synthetic-account','synthetic-nullifier')", "signer_remote_inputs", Some("signer_remote_inputs_no_delete")),
        ("INSERT INTO signer_remote_exposures VALUES('synthetic-orphan','synthetic-absent-original','synthetic-account','synthetic-obligation','1','{}')", "signer_remote_exposures", Some("signer_remote_exposures_no_delete")),
        ("INSERT INTO signer_bridge_keyuse VALUES('synthetic-orphan')", "signer_bridge_keyuse", Some("signer_bridge_keyuse_no_delete")),
    ] {
        f.change_rows(&[], true, |c| { checked(c.execute(insert, [])); });
        f.assert_reader_parity(&f.encrypted.genesis, Err(JournalError::InvalidBinding));
        let triggers = delete_trigger.into_iter().collect::<Vec<_>>();
        f.change_rows(&triggers, true, |c| { checked(c.execute(&format!("DELETE FROM {table}"), [])); });
        assert!(baseline == f.logical_commitment(), "orphan row was not removed from fixture");
    }
    f.assert_valid_baseline();
}

// Include the exact fixture wait kernel, not a rewritten test model or an
// expanded native_ui API. These inert callbacks qualify sequencing only: they
// do not instantiate or qualify native liveness, consent, source or authority.
#[path = "../native_ui/qualification/durable_proposal_v1/witness_wait_v1.rs"]
mod witness_wait_v1;

const WAIT_PENDING_POLLS: usize = 4;
// A deadlock-cleanup watchdog only, never a performance or transport deadline.
const WAIT_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Copy)]
enum QueuedWaitChange {
    Unchanged,
    Recovery,
    OutboxColumn,
}

impl QueuedWaitChange {
    fn apply(self, connection: &mut Connection, f: &MaterialFixture) {
        if matches!(self, Self::Unchanged) {
            return;
        }
        assert_exact_executable_schema(connection);
        let tx = checked(connection.transaction());
        match self {
            Self::Unchanged => unreachable!(),
            Self::Recovery => {
                assert!(
                    checked(tx.execute("UPDATE signer_account SET recovery_required=1", [])) == 1
                );
            }
            Self::OutboxColumn => {
                let trigger: String = checked(tx.query_row(
                    "SELECT sql FROM sqlite_schema WHERE name='signer_durable_construction_outbox_no_update'",
                    [],
                    |row| row.get(0),
                ));
                checked(
                    tx.execute_batch("DROP TRIGGER signer_durable_construction_outbox_no_update"),
                );
                assert!(checked(tx.execute(
                    "UPDATE signer_durable_construction_outbox SET request_digest=?1 WHERE operation_id=?2",
                    params![hash_label(0xe8), f.rows[2].request.operation_id],
                )) == 1);
                checked(tx.execute_batch(&trigger));
            }
        }
        assert_exact_executable_schema(&tx);
        checked(tx.commit());
    }
}

struct WaitHolderObservation {
    explicitly_released: bool,
    before: String,
    after: String,
}

struct WaitHolderRelease(Option<std::sync::mpsc::Sender<()>>);

impl WaitHolderRelease {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            // A disconnected holder has already released its mutex. Cleanup
            // must not panic, including while unwinding another assertion.
            let _ = sender.send(());
        }
    }
}

impl Drop for WaitHolderRelease {
    fn drop(&mut self) {
        self.release();
    }
}

struct EncryptedWaitState<'scope, 'fixture> {
    fixture: &'fixture MaterialFixture,
    start: Option<std::sync::mpsc::Sender<()>>,
    held: std::sync::mpsc::Receiver<()>,
    release: WaitHolderRelease,
    worker: Option<std::thread::ScopedJoinHandle<'scope, Option<WaitHolderObservation>>>,
    observation: Option<WaitHolderObservation>,
    entries: usize,
    live_checks: usize,
    polls: usize,
    sleeps: usize,
    exits: usize,
}

impl EncryptedWaitState<'_, '_> {
    fn assert_pending_contention(&self) {
        assert!(self.entries == 1 && self.exits == 0);
        DURABLE_BORN_SNAPSHOT_VALIDATIONS_V1.with(|count| assert!(count.get() == 1));
        assert!(matches!(
            self.fixture.encrypted.journal.connection.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
    }

    fn finish_worker(&mut self) {
        self.release.release();
        // Disconnect the start channel too, so an entry failure cannot leave
        // the scoped worker waiting for a command that will never arrive.
        self.start.take();
        if let Some(worker) = self.worker.take() {
            self.observation = checked(worker.join());
        }
    }
}

impl Drop for EncryptedWaitState<'_, '_> {
    fn drop(&mut self) {
        // This runs before thread::scope joins on panic or early return. The
        // holder's bounded receive additionally breaks an accidental scan
        // while it owns the mutex, rather than hanging the whole test runner.
        self.release.release();
        self.start.take();
    }
}

fn encrypted_material_wait_component(change: QueuedWaitChange) {
    use std::sync::mpsc;

    let f = MaterialFixture::new();
    f.assert_topology();
    let original = f.logical_commitment();
    DURABLE_BORN_SNAPSHOT_VALIDATIONS_V1.with(|count| count.set(0));
    std::thread::scope(|scope| {
        let (start_tx, start_rx) = mpsc::channel();
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let fixture = &f;
        let worker = scope.spawn(move || {
            if start_rx.recv().is_err() {
                return None;
            }
            // The same retained SQLCipher connection used by both full
            // production checks, not a mock lock or another journal handle.
            let mut connection = checked(fixture.encrypted.journal.connection.lock());
            let before = checked(writer_history::complete_journal_commitment(&connection));
            if held_tx.send(()).is_err() {
                return None;
            }
            let explicitly_released = release_rx.recv_timeout(WAIT_CLEANUP_TIMEOUT).is_ok();
            if explicitly_released {
                change.apply(&mut connection, fixture);
            }
            let after = checked(writer_history::complete_journal_commitment(&connection));
            drop(connection);
            Some(WaitHolderObservation {
                explicitly_released,
                before,
                after,
            })
        });
        let mut state = EncryptedWaitState {
            fixture: &f,
            start: Some(start_tx),
            held: held_rx,
            release: WaitHolderRelease(Some(release_tx)),
            worker: Some(worker),
            observation: None,
            entries: 0,
            live_checks: 0,
            polls: 0,
            sleeps: 0,
            exits: 0,
        };
        let (result, costs) = measure(|| {
            witness_wait_v1::run(
                &mut state,
                |state| {
                    state.entries += 1;
                    state.fixture.encrypted.check()?;
                    checked(
                        state
                            .start
                            .as_ref()
                            .expect("holder start channel missing")
                            .send(()),
                    );
                    checked(state.held.recv_timeout(WAIT_CLEANUP_TIMEOUT));
                    Ok(())
                },
                |state| {
                    // Inert component liveness only. The actual native owner
                    // is neither manufactured nor emulated by this callback.
                    state.assert_pending_contention();
                    state.live_checks += 1;
                    Ok(())
                },
                |state| {
                    state.assert_pending_contention();
                    state.polls += 1;
                    assert!(state.polls <= WAIT_PENDING_POLLS);
                    assert!(state.live_checks == state.polls);
                    if state.polls == WAIT_PENDING_POLLS {
                        state.finish_worker();
                        true
                    } else {
                        false
                    }
                },
                |state| {
                    assert!(state.worker.is_none());
                    assert!(state
                        .observation
                        .as_ref()
                        .is_some_and(|o| o.explicitly_released));
                    assert!(state.polls == WAIT_PENDING_POLLS);
                    state.exits += 1;
                    // No cached success: queued changes must be observed by
                    // this unchanged full production checker after joining.
                    state.fixture.encrypted.check()
                },
                |state| {
                    state.assert_pending_contention();
                    state.sleeps += 1;
                    assert!(state.sleeps == state.polls);
                },
            )
        });
        // Cleanup precedes every result/count assertion, including an early
        // kernel error that never reached its completion poll or exit check.
        state.finish_worker();
        assert!(state.entries == 1 && state.exits == 1);
        assert!(state.live_checks == WAIT_PENDING_POLLS);
        assert!(state.polls == WAIT_PENDING_POLLS);
        assert!(state.sleeps == WAIT_PENDING_POLLS - 1);
        DURABLE_BORN_SNAPSHOT_VALIDATIONS_V1.with(|count| assert!(count.get() == 2));
        assert!(costs.calls(Phase::SnapshotTotal) == 2);
        assert!(costs.calls(Phase::SchemaTotal) == 2);
        assert!(costs.calls(Phase::DurableMaterialRows) == 2);
        assert!(!costs.is_clamped() && !costs.is_incomplete());
        let observed = state
            .observation
            .take()
            .expect("holder observation missing");
        assert!(observed.explicitly_released);
        assert!(original == observed.before);
        assert!(
            observed.after == f.logical_commitment(),
            "final checker changed retained rows"
        );
        match change {
            QueuedWaitChange::Unchanged => {
                assert!(result.is_ok(), "unchanged history was refused");
                assert!(original == observed.after, "component wait changed history");
            }
            QueuedWaitChange::Recovery => {
                assert!(matches!(result, Err(JournalError::RecoveryRequired)));
                assert!(
                    original != observed.after,
                    "queued recovery was not recorded"
                );
                f.change_rows(&[], false, |connection| {
                    checked(
                        connection.execute("UPDATE signer_account SET recovery_required=0", []),
                    );
                });
            }
            QueuedWaitChange::OutboxColumn => {
                assert!(matches!(result, Err(JournalError::InvalidBinding)));
                assert!(
                    original != observed.after,
                    "queued corruption was not recorded"
                );
                f.replace_outbox(2, &f.rows[2]);
            }
        }
    });
    f.assert_topology();
    assert!(
        original == f.logical_commitment(),
        "original 1+2 material history was not retained"
    );
}

#[test]
fn encrypted_material_wait_progresses_while_real_journal_mutex_is_held() {
    encrypted_material_wait_component(QueuedWaitChange::Unchanged);
}

#[test]
fn encrypted_material_wait_exit_refuses_worker_queued_recovery() {
    encrypted_material_wait_component(QueuedWaitChange::Recovery);
}

#[test]
fn encrypted_material_wait_exit_refuses_worker_queued_corruption() {
    encrypted_material_wait_component(QueuedWaitChange::OutboxColumn);
}

// These tests use the SAME private incremental kernel as the borrowed facade
// waiters. Their liveness and approval callbacks remain inert component data,
// not fabricated native/peer permission or qualification of those real owners.
#[derive(Clone, Copy)]
enum IncrementalWaitRoute {
    FinancialImport,
    Disclosure,
}

#[derive(Clone, Copy)]
enum IncrementalWaitFinish {
    Complete,
    DropPending,
}

struct EncryptedIncrementalWaitState<'scope, 'fixture> {
    wait: EncryptedWaitState<'scope, 'fixture>,
    preapprovals: usize,
    inert_actions: usize,
}

fn encrypted_material_incremental_wait_component(
    change: QueuedWaitChange,
    route: IncrementalWaitRoute,
    finish: IncrementalWaitFinish,
) {
    use std::sync::mpsc;

    let f = MaterialFixture::new();
    f.assert_topology();
    let original = f.logical_commitment();
    let dropping_pending = matches!(finish, IncrementalWaitFinish::DropPending);
    assert!(!dropping_pending || matches!(change, QueuedWaitChange::Unchanged));
    DURABLE_BORN_SNAPSHOT_VALIDATIONS_V1.with(|count| count.set(0));
    std::thread::scope(|scope| {
        let (start_tx, start_rx) = mpsc::channel();
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let fixture = &f;
        let worker = scope.spawn(move || {
            if start_rx.recv().is_err() {
                return None;
            }
            let mut connection = checked(fixture.encrypted.journal.connection.lock());
            let before = checked(writer_history::complete_journal_commitment(&connection));
            if held_tx.send(()).is_err() {
                return None;
            }
            let explicitly_released = release_rx.recv_timeout(WAIT_CLEANUP_TIMEOUT).is_ok();
            if explicitly_released {
                change.apply(&mut connection, fixture);
            }
            let after = checked(writer_history::complete_journal_commitment(&connection));
            drop(connection);
            Some(WaitHolderObservation {
                explicitly_released,
                before,
                after,
            })
        });
        let mut state = EncryptedIncrementalWaitState {
            wait: EncryptedWaitState {
                fixture: &f,
                start: Some(start_tx),
                held: held_rx,
                release: WaitHolderRelease(Some(release_tx)),
                worker: Some(worker),
                observation: None,
                entries: 0,
                live_checks: 0,
                polls: 0,
                sleeps: 0,
                exits: 0,
            },
            preapprovals: 0,
            inert_actions: 0,
        };
        let (result, costs) = measure(|| {
            let (mut pending, ()) = checked(witness_wait_v1::begin(&mut state, |state| {
                state.wait.entries += 1;
                state.wait.fixture.encrypted.check()?;
                checked(
                    state
                        .wait
                        .start
                        .as_ref()
                        .expect("incremental holder start channel missing")
                        .send(()),
                );
                checked(state.wait.held.recv_timeout(WAIT_CLEANUP_TIMEOUT));
                Ok::<(), JournalError>(())
            }));
            let bounded_polls = if dropping_pending {
                WAIT_PENDING_POLLS - 1
            } else {
                WAIT_PENDING_POLLS
            };
            let mut last = Ok(false);
            for ordinal in 1..=bounded_polls {
                last = pending.poll(
                    &mut state,
                    || JournalError::Permission,
                    |state| {
                        state.wait.assert_pending_contention();
                        state.wait.live_checks += 1;
                        Ok(())
                    },
                    |state| {
                        state.wait.assert_pending_contention();
                        state.wait.polls += 1;
                        assert!(state.wait.live_checks == state.wait.polls);
                        if state.wait.polls < WAIT_PENDING_POLLS {
                            return Ok(false);
                        }
                        assert!(state.wait.polls == WAIT_PENDING_POLLS);
                        state.wait.finish_worker();
                        match route {
                            IncrementalWaitRoute::FinancialImport => Ok(true),
                            IncrementalWaitRoute::Disclosure => witness_wait_v1::before_approval(
                                state,
                                |state| {
                                    state.preapprovals += 1;
                                    state.wait.fixture.encrypted.check()
                                },
                                |state| {
                                    // Data-only action marker. No native
                                    // approval/session/receipt is constructed.
                                    state.inert_actions += 1;
                                    Ok(true)
                                },
                            ),
                        }
                    },
                    |state| {
                        assert!(state.wait.worker.is_none());
                        assert!(state
                            .wait
                            .observation
                            .as_ref()
                            .is_some_and(|o| o.explicitly_released));
                        state.wait.exits += 1;
                        state.wait.fixture.encrypted.check()
                    },
                );
                if ordinal < WAIT_PENDING_POLLS {
                    assert!(matches!(last, Ok(false)));
                    state.wait.assert_pending_contention();
                    assert!(state.wait.exits == 0 && state.preapprovals == 0);
                    assert!(state.inert_actions == 0);
                }
            }
            if dropping_pending {
                // Dropping an unfinished wait does not manufacture a final
                // validation or turn previous pending results into success.
                drop(pending);
            } else {
                // A success OR first refusal makes the actual same kernel
                // terminal. Repeating cannot return cached success, repeat
                // an action or reacquire even one historical snapshot.
                let repeated = pending.poll(
                    &mut state,
                    || JournalError::Permission,
                    |_| panic!("terminal wait repeated its liveness callback"),
                    |_| panic!("terminal wait repeated its poll callback"),
                    |_| panic!("terminal wait repeated its full exit callback"),
                );
                assert!(matches!(repeated, Err(JournalError::Permission)));
            }
            last
        });
        // Explicit cleanup also covers pending-drop. On panic/early error the
        // contained state's Drop releases both channels before scoped join.
        state.wait.finish_worker();
        let disclosure = matches!(route, IncrementalWaitRoute::Disclosure);
        let unchanged = matches!(change, QueuedWaitChange::Unchanged);
        let expected_scans = if dropping_pending {
            1
        } else if disclosure && unchanged {
            3
        } else {
            2
        };
        let expected_polls = if dropping_pending {
            WAIT_PENDING_POLLS - 1
        } else {
            WAIT_PENDING_POLLS
        };
        assert!(state.wait.entries == 1);
        assert!(state.wait.live_checks == expected_polls && state.wait.polls == expected_polls);
        assert!(state.wait.sleeps == 0);
        assert!(state.wait.exits == usize::from(!dropping_pending && (!disclosure || unchanged)));
        assert!(state.preapprovals == usize::from(!dropping_pending && disclosure));
        assert!(state.inert_actions == usize::from(!dropping_pending && disclosure && unchanged));
        DURABLE_BORN_SNAPSHOT_VALIDATIONS_V1.with(|count| assert!(count.get() == expected_scans));
        assert!(costs.calls(Phase::SnapshotTotal) == expected_scans);
        assert!(costs.calls(Phase::SchemaTotal) == expected_scans);
        assert!(costs.calls(Phase::DurableMaterialRows) == expected_scans);
        assert!(!costs.is_clamped() && !costs.is_incomplete());
        let observed = state
            .wait
            .observation
            .take()
            .expect("incremental holder observation missing");
        assert!(observed.explicitly_released);
        assert!(original == observed.before);
        assert!(
            observed.after == f.logical_commitment(),
            "incremental checker changed retained rows"
        );
        match change {
            QueuedWaitChange::Unchanged => {
                assert!(matches!(result, Ok(done) if done != dropping_pending));
                assert!(
                    original == observed.after,
                    "incremental wait changed history"
                );
            }
            QueuedWaitChange::Recovery => {
                assert!(matches!(result, Err(JournalError::RecoveryRequired)));
                assert!(
                    original != observed.after,
                    "incremental queued recovery was not recorded"
                );
                f.change_rows(&[], false, |connection| {
                    checked(
                        connection.execute("UPDATE signer_account SET recovery_required=0", []),
                    );
                });
            }
            QueuedWaitChange::OutboxColumn => {
                assert!(matches!(result, Err(JournalError::InvalidBinding)));
                assert!(
                    original != observed.after,
                    "incremental queued corruption was not recorded"
                );
                f.replace_outbox(2, &f.rows[2]);
            }
        }
    });
    f.assert_topology();
    assert!(
        original == f.logical_commitment(),
        "incremental wait lost original 1+2 material history"
    );
}

#[test]
fn encrypted_material_incremental_import_progresses_under_real_journal_contention() {
    encrypted_material_incremental_wait_component(
        QueuedWaitChange::Unchanged,
        IncrementalWaitRoute::FinancialImport,
        IncrementalWaitFinish::Complete,
    );
}

#[test]
fn encrypted_material_incremental_import_exit_refuses_queued_recovery() {
    encrypted_material_incremental_wait_component(
        QueuedWaitChange::Recovery,
        IncrementalWaitRoute::FinancialImport,
        IncrementalWaitFinish::Complete,
    );
}

#[test]
fn encrypted_material_incremental_import_exit_refuses_queued_corruption() {
    encrypted_material_incremental_wait_component(
        QueuedWaitChange::OutboxColumn,
        IncrementalWaitRoute::FinancialImport,
        IncrementalWaitFinish::Complete,
    );
}

#[test]
fn encrypted_material_incremental_disclosure_keeps_full_preapproval_and_exit_gates() {
    encrypted_material_incremental_wait_component(
        QueuedWaitChange::Unchanged,
        IncrementalWaitRoute::Disclosure,
        IncrementalWaitFinish::Complete,
    );
}

#[test]
fn encrypted_material_incremental_disclosure_preapproval_refuses_queued_recovery() {
    encrypted_material_incremental_wait_component(
        QueuedWaitChange::Recovery,
        IncrementalWaitRoute::Disclosure,
        IncrementalWaitFinish::Complete,
    );
}

#[test]
fn encrypted_material_incremental_disclosure_preapproval_refuses_queued_corruption() {
    encrypted_material_incremental_wait_component(
        QueuedWaitChange::OutboxColumn,
        IncrementalWaitRoute::Disclosure,
        IncrementalWaitFinish::Complete,
    );
}

#[test]
fn encrypted_material_incremental_drop_pending_has_no_successful_exit() {
    for route in [
        IncrementalWaitRoute::FinancialImport,
        IncrementalWaitRoute::Disclosure,
    ] {
        encrypted_material_incremental_wait_component(
            QueuedWaitChange::Unchanged,
            route,
            IncrementalWaitFinish::DropPending,
        );
    }
}
