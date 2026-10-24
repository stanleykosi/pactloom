//! Actual pure producer projections over shared complete inert historical DTOs.
//! Material, encrypted rows, fixed identity, recipient and original request are
//! the maintained real codec fixture. Snapshot/receipt/activation/result data
//! are NOT authenticated history, a signed result, a Final or a permission.
//! In particular this does not execute Return Evidence::from_retained, the
//! genuine prepared-owner constructors, cryptographic signing, or any socket.
use super::*;
use wholepact_financial_coordinator_origin as o;
use wholepact_authority::durable_financial_continuation_v1::{
    FinancialContinuationTermsV1, FinancialContinuationRecordV1,
    original_delivery_request_digest_v1,
};
use wholepact_authority::{AccountSnapshot, WriterSessionReceipt, WriterStatus};
use crate::consent_journal::{SpendConsentTerms, ConsentInputBinding, WalletSnapshotBinding, NativeConsentReceipt};
use crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1;
use std::path::Path;

fn json<T: serde::Serialize>(v:&T)->String { checked(serde_json::to_string(v)) }
fn actor(i:&CoordinatedAdmissionIntentV1)->o::FinancialActorContextV1 {
    o::FinancialActorContextV1 {
        profile:"coordinated-financial-workflow-v1".into(), coordinator_process_instance:h(0xd0),
        coordinator_focus_epoch:1, signer_role:o::SignerContinueRoleV1::Signer1,
        signer_process_instance:i.recipient_intent.signer_process_instance.clone(),
        common_image_measurement:i.read.measurement.clone(), session_challenge:h(0xd1),
    }
}
struct Shared {
    intent:CoordinatedAdmissionIntentV1,
    continuation:OwnerControlRequest,
    terms:FinancialContinuationTermsV1,
    continue_snapshot:AccountSnapshot,
    continue_history_digest:String,
    snapshot:AccountSnapshot,
    receipt:WriterSessionReceipt,
    history_digest:String,
    spend:SpendConsentTerms,
    original:o::SignerWalletOriginalV1,
    observed:o::SignerWalletObservedV1,
    read:o::SignerSignReadPresentationV1,
}
fn fixture()->Shared {
    let material = MaterialFixture::coordinated();
    let mut i = complete(&material);
    let evidence=checked(material.rows()[0].request().material.historical_review_evidence());
    assert_eq!(evidence.inputs.len(),1);
    let proposal=checked(material.rows()[0].request().validate());
    let participant=proposal.manifest().participants.iter().find(|p|p.account_id==i.request.account_id).unwrap();
    // Historical material exposes note-tree position, NOT a verified fixed
    // transaction action index. Keep the retained inert index explicitly0;
    // this test does not claim actual fixed-artifact action mapping proof.
    assert_eq!(checked(record(&i.request)).scope.authorization.inputs[0].action_index,0);
    let (fixed,delivery)={
        let scope=scope_mut(&mut i);let authorization=&mut scope.authorization;
        authorization.inputs[0].input_id=evidence.inputs[0].input_id.clone();
        authorization.inputs[0].nullifier=hex::encode(evidence.inputs[0].nullifier);
        authorization.inputs[0].value_zatoshis=evidence.inputs[0].value_zatoshis;
        authorization.maximum_debit_zatoshis=participant.maximum_net_debit.as_zatoshis();
        authorization.fee_share_zatoshis=participant.fee_share.as_zatoshis();
        authorization.transaction_fee_zatoshis=proposal.manifest().transaction_fee.as_zatoshis();
        authorization.fixed.anchor=hex::encode(evidence.context.anchor_root);
        authorization.fixed.proposal_binding=fixed_binding(&authorization.fixed);
        authorization.authorization_id=checked(canonical_durable_authorization_id_v2(&authorization.fixed,&authorization.identity));
        for owner in &mut scope.delivery.owners {
            let mut identity=authorization.identity.clone();identity.account_id=owner.account_id.clone();
            owner.original_authorization_id=checked(canonical_durable_authorization_id_v2(&authorization.fixed,&identity));
        }
        (authorization.fixed.clone(),scope.delivery.clone())
    };
    i.recipient_intent.fixed=checked(serde_json::from_value(checked(serde_json::to_value(&fixed))));
    i.recipient_intent.request.proposal_binding=fixed.proposal_binding.clone();
    i.recipient_intent.delivery=delivery;
    rebind_recipient(&mut i);rebind_request(&mut i); retain(&mut i);
    assert!(i.validate().is_ok(), "composition complete admission DTO");
    {
        let c=checked(material.journal().connection.lock());let before=c.total_changes();
        assert!(storage::verify_schema(&c).is_ok(), "composition encrypted schema");
        assert!(validate_original_rows(&c,&i).is_ok(), "composition actual original rows");
        assert!(before==c.total_changes());
    }
    let scope=checked(record(&i.request)).scope.clone();
    let from=scope.delivery.valid_from_ms;
    let terms=FinancialContinuationTermsV1 {
        scope:scope.clone(), original_delivery_operation_id:i.request.operation_id.clone(),
        original_delivery_request_digest:checked(original_delivery_request_digest_v1(&i.request)),
        original_delivery_committed_head:AuthorityHead {sequence:5,digest:h(0xd2)},
        original_local_intent_digest:checked(i.review_digest()),
        original_recipient_intent_digest:checked(i.recipient_intent.digest()),
        original_recipient_enrollment_ref:i.enrollment_ref.clone(),
        original_recipient_manifest_ref:i.manifest_ref.clone(),
        valid_from_ms:scope.delivery.valid_from_ms,valid_until_ms:scope.delivery.valid_until_ms,
    };
    assert!(terms.validate().is_ok(), "composition continuation terms");
    // Same Authority domains/order as the real constructor; no fabricated
    // ReconciledAuthorityHistory is used to enter that authority-dependent API.
    let signer_intent=authority_digest("inert:composition:continuation-preimage",&(&terms,&i.read));
    let mut continuation=OwnerControlRequest {
        account_id:i.request.account_id.clone(),network_profile_id:i.request.network_profile_id.clone(),
        writer_epoch:i.request.writer_epoch,expected_head:terms.original_delivery_committed_head.clone(),
        operation_id:String::new(),control:OwnerControl::AdmitFinancialContinuationV1 {record:Box::new(
            FinancialContinuationRecordV1 {terms:terms.clone(),signer_continuation_intent_digest:signer_intent.clone(),witness_native_review_digest:h(0)})},
    };
    continuation.operation_id=format!("financial-continuation-admit-v1-{}",authority_digest(
        "wholepact:financial-continuation-operation:v1",&(&terms,&signer_intent,&continuation.account_id,
        &continuation.network_profile_id,continuation.writer_epoch,&continuation.expected_head)));
    let review=authority_digest("wholepact:financial-continuation-native-review:v1",&(&terms,&signer_intent,
        &continuation.account_id,&continuation.network_profile_id,continuation.writer_epoch,&continuation.expected_head,&i.disclosure));
    let OwnerControl::AdmitFinancialContinuationV1{record:continuation_record}=&mut continuation.control else {panic!()};
    continuation_record.witness_native_review_digest=review;
    let OwnerControl::AdmitFinancialContinuationV1{record:continuation_record}=&continuation.control else {panic!()};
    assert!(continuation_record.validate_request(&continuation,&i.disclosure).is_ok(),"composition Authority continuation request");
    let history_digest=authority_digest("inert:composition:historical-requests",&(&i.request,&continuation));
    let receipt=WriterSessionReceipt {
        session_id:h(0xd3),writer_certificate_digest:scope.authorization.writer_certificate_digest.clone(),
        writer_epoch:continuation.writer_epoch,reconciled_head:AuthorityHead{sequence:6,digest:h(0xd4)},
        reconciled_history_digest:history_digest.clone(),acquired_head:AuthorityHead{sequence:7,digest:h(0xd5)},
        expires_at_ms:from+2_400_000,acquired_at_ms:from+700_000,disclosure:i.disclosure.clone(),
    };
    let snapshot=AccountSnapshot {
        transport_fences:None,account_use_checkpoint:None,witness_id:i.disclosure.witness_id.clone(),
        account_id:continuation.account_id.clone(),network_profile_id:continuation.network_profile_id.clone(),
        policy_digest:i.disclosure.policy_digest.clone(),head:AuthorityHead{sequence:8,digest:h(0xd6)},
        writer_epoch:continuation.writer_epoch,writer_certificate_digest:receipt.writer_certificate_digest.clone(),
        writer_status:WriterStatus::Active,outstanding_reservations:0,outstanding_debit_zatoshis:0,
        settled_debit_zatoshis:0,aggregate_budget_zatoshis:1_000_000,reserved_input_value_zatoshis:0,
        last_witness_time_ms:from+800_000,pending_writer_session:None,active_writer_session:Some(receipt.clone()),
    };
    assert_eq!(checked(snapshot.remaining_budget_zatoshis()),1_000_000);
    let mut continue_snapshot=snapshot.clone();
    continue_snapshot.head=terms.original_delivery_committed_head.clone();
    continue_snapshot.active_writer_session=None;
    continue_snapshot.last_witness_time_ms=from+450_000;
    let continue_history_digest=authority_digest("inert:composition:original-delivery-history",&(&i.request,&continue_snapshot));
    let history_digest=authority_digest("inert:composition:activated-history",&(&continuation,&snapshot));
    assert!(history_digest!=receipt.reconciled_history_digest,"history epochs must have independent commitments");
    let a=&scope.authorization;let fixed=&a.fixed;
    let spend=SpendConsentTerms {
        durable_born_policy_v1:None,automation:None,sponsor_policy:None,sponsor_owner_attestation_digest:None,
        authorization_id:a.authorization_id.clone(),enrollment_ref:i.enrollment_ref.clone(),
        accepted_manifest_ref:i.manifest_ref.clone(),account_id:continuation.account_id.clone(),principal_id:i.read.principal_id.clone(),
        agreement_id:fixed.agreement_id.clone(),obligation_id:fixed.obligation_id.clone(),proposal_id:fixed.proposal_id.clone(),
        proposal_digest:fixed.proposal_digest.clone(),manifest_digest:fixed.manifest_digest.clone(),effects_digest:fixed.effects_commitment.clone(),
        artifact_digest:fixed.proved_artifact_digest.clone(),review_binding:fixed.review_binding.clone(),
        transport:material.rows()[1].recipient_transport().clone(),
        input_bindings:a.inputs.iter().map(|v|ConsentInputBinding {input_id:v.input_id.clone(),action_index:v.action_index,
            nullifier:v.nullifier.clone(),value_zatoshis:v.value_zatoshis}).collect(),
        maximum_debit_zatoshis:a.maximum_debit_zatoshis,fee_share_zatoshis:a.fee_share_zatoshis,
        transaction_fee_zatoshis:a.transaction_fee_zatoshis,aggregate_budget_limit_zatoshis:snapshot.aggregate_budget_zatoshis,
        transaction_expiry_height:fixed.expiry_height,
        wallet_snapshot:WalletSnapshotBinding {tip_height:evidence.context.tip_height,tip_hash:hex::encode(evidence.context.tip_hash_protocol),
            anchor_height:evidence.context.anchor_height,anchor_hash:hex::encode(evidence.context.anchor_hash_protocol),anchor_root:hex::encode(evidence.context.anchor_root)},
        wallet_key_use_policy:Some(wholepact_wallet::WalletKeyUsePolicy {
            confidence:wholepact_wallet::WalletKeyUseConfidence::TrustedSingleProviderSnapshot,
            source_id:scope.delivery.provider.source_id.clone(),endpoint:scope.delivery.provider.endpoint.clone(),
            maximum_observation_age_seconds:300,minimum_confirmations:1,minimum_expiry_margin_blocks:1}),
        receipt:NativeConsentReceipt {native_session_id:h(0xd9),trusted_launch_measurement:i.read.measurement.clone(),
            permission_generation:1,writer_epoch:continuation.writer_epoch,nonce:h(0xda),reviewed_at_ms:from+900_000,expires_at_ms:from+1_020_000},
    };
    assert_eq!(spend.input_bindings.len(),a.inputs.len());
    assert_eq!(spend.input_bindings[0].action_index,a.inputs[0].action_index);
    let original=wallet_original(&i,&continuation,&terms,&snapshot,&receipt,&history_digest);
    let observed=o::SignerWalletObservedV1 {
        observe_presentation_digest:h(0xdb),prepare_presentation_digest:h(0xdc),activation_presentation_digest:original.activation.presentation_digest.clone(),
        fixed_identity_digest:original.fixed_identity_digest.clone(),configuration_digest:original.configuration_digest.clone(),
        wallet_review_digest:h(0xdd),wallet_observation_digest:h(0xde),tip_height:spend.wallet_snapshot.tip_height,
        tip_hash:spend.wallet_snapshot.tip_hash.clone(),anchor_height:spend.wallet_snapshot.anchor_height,
        anchor_hash:spend.wallet_snapshot.anchor_hash.clone(),anchor_root:spend.wallet_snapshot.anchor_root.clone(),input_count:spend.input_bindings.len() as u32,
    };
    assert!(observed.validate().is_ok(),"composition observed wallet DTO");
    let mut read=o::SignerSignReadPresentationV1 {
        actor:actor(&i),facts:o::SignerSignReadFactsV1 {original:original.clone(),observed:observed.clone(),
            display:"Authenticate only the retained original writer and fixed-wallet observation".into(),reviewed_at_ms:from+900_000,expires_at_ms:from+1_020_000},
        notice:SIGN_READ_NOTICE.into(),challenge:h(0xdf),source_ceiling_ms:1_800_000,read_ceiling_ms:120_000,
        service_ceiling_ms:1_500_000,writer_session_ceiling_ms:1_500_000,presentation_digest:String::new(),
    };
    read.presentation_digest=checked(read.calculate_presentation_digest());
    assert!(read.validate().is_ok(),"composition original SignRead presentation");
    Shared{intent:i,continuation,terms,continue_snapshot,continue_history_digest,snapshot,receipt,history_digest,spend,original,observed,read}
}

const INITIAL_READ_PURPOSE: &str = "original-history-and-one-local-continue-preparation-v2";

const INITIAL_READ_NOTICE: &str = "Read the complete original financial history from this exact selected owner and prepare exactly one immutable local Continue request from this same original Signer source. This does not authorize Continue, Admit or any mutation. Cancel remains restrictive through the history read and complete local preparation.";

const ACTIVATE_PURPOSE: &str = "activate-one-exact-original-financial-writer-v1";

const ACTIVATE_NOTICE: &str = "Activate only the exact reviewed pending session through the same original owner client and genuine current FinancialSigning service. The writer key remains solely in the same retained writer client. One attempt only; an uncertain response never permits retry, a replacement session, wallet preparation, signing or Return.";

const SIGN_READ_NOTICE: &str = "Authenticate only the same retained writer active session and full history, and read the same guarded original source to prepare one immutable exact spend. No reservation, journal mutation, private spending key, signature or return.";

const SIGN_EXACT_NOTICE: &str = "Approve only this exact prepared spend: release and request commits, same-writer reservation, authenticated permit commit, Started commit, one entered protected key derivation and exact signing operation, then one result commit. Original source, wallet, writer session and all deadlines remain fixed; errors or uncertain effects are terminal, never retry.";

const RETURN_READ_NOTICE: &str = "Read only this actual retained coordinated signature result and exact original request, construct and send one preview to the same original Host on the same retained channel. No signature payload or Return is authorized; waiting for HostPrepared retains custody only.";

const RETURN_EXACT_NOTICE: &str = "Return only the exact reviewed persisted signature set/result/outbox to the same original Host and the same retained prepared stream. One attempt, original deadlines, exact Ready/Held/Current/Finished checks; partial transfer or report loss is uncertain and never permits retry.";

fn wallet_original(i:&CoordinatedAdmissionIntentV1, continuation:&OwnerControlRequest, terms:&FinancialContinuationTermsV1,
    snapshot:&AccountSnapshot, receipt:&WriterSessionReceipt, _history_digest:&str)->o::SignerWalletOriginalV1 {
    let from=terms.valid_from_ms;
    let disclosure_digest=authority_digest("inert:composition:disclosure",&i.disclosure);
    let original=o::SignerActivateOriginalV1 {
        source_identity_digest:i.read.source_identity_digest.clone(),terms_digest:checked(terms.intent_terms_digest()),
        continuation_request_json:json(continuation),continuation_request_digest:o::SignerContinuePresentationV1::calculate_request_digest(&json(continuation)),
        original_host_process_instance:i.recipient_intent.authorized_host_process_instance.clone(),
        owner_certificate_digest:i.owner_certificate_digest.clone(),owner_disclosure_digest:disclosure_digest.clone(),writer_selection_digest:h(0xe0),
        acquired:o::SignerAcquireCommittedV1 {
            presentation_digest:h(0xe1),recipe_digest:h(0xe2),acquire_ready_digest:h(0xe3),signing_service_digest:h(0xe4),
            session_id:receipt.session_id.clone(),writer_certificate_digest:receipt.writer_certificate_digest.clone(),writer_epoch:receipt.writer_epoch,
            reconciled_head_sequence:receipt.reconciled_head.sequence,reconciled_head_digest:receipt.reconciled_head.digest.clone(),
            reconciled_history_digest:receipt.reconciled_history_digest.clone(),acquired_head_sequence:receipt.acquired_head.sequence,
            acquired_head_digest:receipt.acquired_head.digest.clone(),acquired_at_ms:receipt.acquired_at_ms,expires_at_ms:receipt.expires_at_ms,
            disclosure_json:json(&receipt.disclosure),disclosure_digest,
        },source_expires_at_ms:i.ceilings.original_source_expires_at_ms,
    };
    let activate_request=OwnerControlRequest {
        operation_id:"inert-composition-activate-original-writer".into(),account_id:continuation.account_id.clone(),
        network_profile_id:continuation.network_profile_id.clone(),writer_epoch:receipt.writer_epoch,expected_head:receipt.acquired_head.clone(),
        control:OwnerControl::ActivateWriter {session_id:receipt.session_id.clone()},
    };
    let mut before_activation=snapshot.clone();
    before_activation.head=receipt.acquired_head.clone();
    before_activation.active_writer_session=None;
    before_activation.pending_writer_session=Some(receipt.clone());
    before_activation.last_witness_time_ms=from+740_000;
    let activation_history_digest=authority_digest("inert:composition:pending-writer-history",&(&i.request,continuation,&before_activation));
    let facts=o::SignerActivateFactsV1 {
        display:"Activate only the retained original writer session".into(),original,activate_read_presentation_digest:h(0xe5),
        authenticated_history_digest:activation_history_digest,authenticated_snapshot_json:json(&before_activation),
        activation_request_json:json(&activate_request),activation_request_digest:o::SignerActivateFactsV1::calculate_request_digest(&json(&activate_request)),
        activation_terms_digest:authority_digest("inert:composition:activation",&activate_request),
        expected_head_sequence:receipt.acquired_head.sequence,expected_head_digest:receipt.acquired_head.digest.clone(),writer_epoch:receipt.writer_epoch,
        reviewed_at_ms:from+750_000,expires_at_ms:from+870_000,
    };
    let mut activation=o::SignerActivatePresentationV1 {
        version:1,purpose:ACTIVATE_PURPOSE.into(),actor:actor(i),notice:ACTIVATE_NOTICE.into(),recipe_digest:checked(facts.calculate_recipe_digest()),facts,
        activate_challenge:h(0xe6),source_ceiling_ms:1_800_000,activate_ceiling_ms:120_000,presentation_digest:String::new(),
    };
    activation.presentation_digest=checked(activation.calculate_presentation_digest());
    assert!(activation.validate().is_ok(),"composition historical activation DTO");
    let activated=o::SignerActivateCommittedV1 {
        presentation_digest:activation.presentation_digest.clone(),activate_ready_digest:h(0xe7),
        activation_request_digest:activation.facts.activation_request_digest.clone(),signing_service_digest:activation.facts.original.acquired.signing_service_digest.clone(),
        session_id:receipt.session_id.clone(),writer_epoch:receipt.writer_epoch,head_sequence:snapshot.head.sequence,head_digest:snapshot.head.digest.clone(),
    };
    // Complete ordinary wallet setup schema, matching Host's actual full
    // projection. The birthday is the maintained synthetic scanner's empty
    // prior state (height4465039/hash[50;32]), NOT live chain or sync evidence.
    let configuration_json=serde_json::json!({"schema_version":1,
        "purpose":"fresh_born_ephemeral_viewing_wallet_v1","retention":"current_native_owner_only","maximum_blocks":16,
        "policy":{"confidence":"trusted_single_provider_snapshot","source_id":terms.scope.delivery.provider.source_id,
            "endpoint":terms.scope.delivery.provider.endpoint,"maximum_observation_age_seconds":300,"minimum_confirmations":1,"minimum_expiry_margin_blocks":1},
        "birthday":{"prior_height":4_465_039,"prior_block_hash":h(50),"sapling_tree":"","orchard_tree":"","ironwood_tree":""}}).to_string();
    assert!(o::SignerFinancialWalletSetupSelectionV1::parse_json(&configuration_json).is_ok(),"complete ordinary wallet setup schema");
    let original=o::SignerWalletOriginalV1 {
        activation,activated,fixed_identity_digest:checked(crate::authority_bridge::durable_review_ipc_v3::verified_fixed_identity_digest_v3(&i.recipient_intent.fixed)),
        configuration_digest:checked(o::SignerWalletOriginalV1::calculate_configuration_digest(&configuration_json)),configuration_json,
    };
    assert!(original.validate().is_ok(),"composition full original wallet DTO");original
}

// Exact private Packet serde projection, NOT actual encoder or transport. The
// separate Origin test executes its real private payload() bound. Source audit
// pins these variants, ContinueWire/Start layouts, MAX_PACKET and8-byte framing.
#[derive(serde::Serialize)]
#[serde(tag="kind")]
enum PacketProjection<'a> {
    ContinueDisplay {binding:ContinueWireProjection<'a>},
    SignExactDisplay {presentation:&'a o::SignerSignExactPresentationV1},
    ReturnReadDisplay {presentation:&'a o::SignerReturnReadPresentationV1},
    ReturnExactDisplay {presentation:&'a o::SignerReturnExactPresentationV1},
}
#[derive(serde::Serialize)]
struct ContinueWireProjection<'a> {context:serde_json::Value,presentation:&'a o::SignerContinuePresentationV1,source_ceiling_ms:u64,review_ceiling_ms:u64}
fn wire_bytes(p:&PacketProjection<'_>)->usize {checked(serde_json::to_vec(p)).len()+8}
fn initial_read(s:&Shared)->o::SignerFinancialReadPresentationV1 {
    let mut facts=o::SignerFinancialReadFactsV1 {
        read_digest:String::new(),display:"Reconcile the full original owner history and immutable continuation".into(),
        source_identity_digest:s.intent.read.source_identity_digest.clone(),original_journal_digest:authority_digest("inert:composition:journal",&s.intent),
        terms_digest:checked(s.terms.intent_terms_digest()),original_delivery_operation_id:s.intent.request.operation_id.clone(),
        original_delivery_request_digest:s.terms.original_delivery_request_digest.clone(),original_delivery_head_sequence:s.terms.original_delivery_committed_head.sequence,
        original_delivery_head_digest:s.terms.original_delivery_committed_head.digest.clone(),original_host_process_instance:s.intent.recipient_intent.authorized_host_process_instance.clone(),
        account_id:s.intent.request.account_id.clone(),owner_certificate_digest:s.intent.owner_certificate_digest.clone(),owner_selection_digest:s.intent.read.owner_selection_digest.clone(),
        disclosure_digest:authority_digest("inert:composition:disclosure",&s.intent.disclosure),session_digest:s.intent.read.read_session_digest.clone(),
        reviewed_at_ms:s.terms.valid_from_ms+500_000,expires_at_ms:s.terms.valid_from_ms+620_000,source_expires_at_ms:s.terms.valid_until_ms,
    };
    facts.read_digest=checked(facts.calculate_read_digest());
    let mut read=o::SignerFinancialReadPresentationV1 {
        version:2,purpose:INITIAL_READ_PURPOSE.into(),actor:actor(&s.intent),facts,notice:INITIAL_READ_NOTICE.into(),selection_digest:h(0xe8),
        source_entry_presentation_digest:h(0xe9),read_challenge:h(0xea),source_ceiling_ms:1_800_000,read_ceiling_ms:120_000,presentation_digest:String::new(),
    };
    read.presentation_digest=checked(read.calculate_presentation_digest());
    assert!(read.validate().is_ok(),"composition initial Read DTO");read
}

#[test]
fn complete_continue_projection_preserves_request_and_fits_full_packet() {
    let s=fixture();let read=initial_read(&s);let a=&read.actor;let f=&read.facts;
    let review=o::SignerContinueReviewDataV1 {
        coordinator_process_instance:a.coordinator_process_instance.clone(),coordinator_focus_epoch:a.coordinator_focus_epoch,
        signer_role:a.signer_role,signer_process_instance:a.signer_process_instance.clone(),
        original_host_process_instance:f.original_host_process_instance.clone(),signer_principal_id:s.intent.read.principal_id.clone(),
        signer_image_measurement:a.common_image_measurement.clone(),source_identity_digest:f.source_identity_digest.clone(),terms_digest:f.terms_digest.clone(),
        session_digest:f.session_digest.clone(),review_challenge:h(0xeb),review_digest:authority_digest("inert:composition:continue-review",&(&read,&s.continuation)),
        reviewed_at_ms:f.reviewed_at_ms+1_000,expires_at_ms:f.expires_at_ms+1_000,session_expires_at_ms:f.source_expires_at_ms,
    };
    let p=checked(crate::native_ui::project_continue_presentation(&s.continuation,&h(0xec),review.clone(),
        Path::new("/synthetic/original-retained-signer/account-root"),&f.source_identity_digest,&f.original_journal_digest,
        &s.intent.owner_certificate_digest,&read,&s.continue_history_digest,&checked(serde_json::to_value(&s.continue_snapshot))));
    assert!(p.validate().is_ok(),"actual Continue producer/validator composition");
    assert!(p.request_json==json(&s.continuation),"Continue exact request bytes");
    let displayed:serde_json::Value=checked(serde_json::from_str(&p.display));
    assert!(displayed["exact_request"]==checked(serde_json::to_value(&s.continuation)));
    assert!(displayed["authenticated_snapshot"]==checked(serde_json::to_value(&s.continue_snapshot)));
    assert!(displayed["completed_read_presentation_digest"]==read.presentation_digest);
    assert!(displayed["owner_selection_digest"]==read.facts.owner_selection_digest);
    assert!(review.original_host_process_instance!=review.signer_process_instance,"distinct original Host and Signer domains");
    assert!(review.original_host_process_instance!=review.coordinator_process_instance,"distinct original Host and Coordinator domains");
    let context=serde_json::json!({"start":{"profile":a.profile,"coordinator":a.coordinator_process_instance,"session":a.session_challenge,
        "role":a.signer_role,"request_challenge":h(0xed),"native_ceiling_ms":120000,"sender_public_key":h(0xee)},
        "entry_presentation_digest":read.source_entry_presentation_digest,"read_presentation_digest":read.presentation_digest,
        "challenge":h(0xef),"native_ceiling_ms":120000});
    let bytes=wire_bytes(&PacketProjection::ContinueDisplay {binding:ContinueWireProjection {context,presentation:&p,source_ceiling_ms:read.source_ceiling_ms,review_ceiling_ms:120_000}});
    size_metric("continue",p.display.len(),p.request_json.len(),0,checked(serde_json::to_vec(&p)).len(),bytes);
    assert!(bytes<=65_536,"actual Continue projection exceeds full packet: display={}, request={}, packet={}",p.display.len(),p.request_json.len(),bytes);
}

fn sign_exact(s:&Shared,emit:bool)->o::SignerSignExactPresentationV1 {
    let signing_digest=authority_digest("inert:composition:signing-terms",&s.spend);
    let lower_calls=std::cell::Cell::new(0usize);
    let display=checked(crate::consent_journal::project_spend_display(&s.spend,&s.intent.disclosure,&s.snapshot.head,|| {
        lower_calls.set(lower_calls.get()+1);Ok(&s.terms.scope.delivery)
    },&signing_digest));
    assert_eq!(lower_calls.get(),1,"lower display must evaluate delivery once");
    assert!(display.contains(&json(&s.terms.scope.delivery)));
    assert!(display.contains(&s.spend.input_bindings[0].input_id));
    if emit {size_metric("sign_lower",display.len(),0,0,0,0);}
    assert!(display.len()<=8192,"actual lower Sign display exceeds unchanged bound: {}",display.len());
    let display_calls=std::cell::Cell::new(0usize);
    let facts=checked(crate::consent_journal::project_sign_exact_facts(&s.read,&s.spend,&signing_digest,&s.history_digest,
        &json(&s.snapshot),&json(&s.receipt),|| {display_calls.set(display_calls.get()+1);Ok(display.clone())},
        s.terms.valid_from_ms+1_000_000,s.terms.valid_from_ms+1_120_000));
    assert_eq!(display_calls.get(),1,"exact facts must evaluate lower display once");
    assert!(facts.validate().is_ok(),"actual Sign producer/validator composition");
    let spend_json:serde_json::Value=checked(serde_json::from_str(&facts.spend_terms_json));
    assert!(spend_json.get("receipt").is_none(),"historical receipt is not renewed");
    assert!(spend_json["input_bindings"][0]["input_id"]==s.spend.input_bindings[0].input_id);
    assert!(facts.authenticated_snapshot_json==json(&s.snapshot),"Sign complete snapshot bytes");
    assert!(facts.active_receipt_json==json(&s.receipt),"Sign complete receipt bytes");
    let mut p=o::SignerSignExactPresentationV1 {actor:s.read.actor.clone(),facts,notice:SIGN_EXACT_NOTICE.into(),challenge:h(0xf0),
        source_ceiling_ms:s.read.source_ceiling_ms,sign_ceiling_ms:120_000,service_ceiling_ms:s.read.service_ceiling_ms,
        writer_session_ceiling_ms:s.read.writer_session_ceiling_ms,presentation_digest:String::new()};
    p.presentation_digest=checked(p.calculate_presentation_digest());
    if emit {size_metric("sign",p.facts.display.len(),p.facts.spend_terms_json.len(),checked(serde_json::to_vec(&p.facts)).len(),
        checked(serde_json::to_vec(&p)).len(),wire_bytes(&PacketProjection::SignExactDisplay{presentation:&p}));}
    assert!(p.validate().is_ok(),"actual Sign full presentation");p
}
#[test]
fn complete_sign_projection_preserves_lower_display_and_original_wallet_join() {
    let s=fixture();let p=sign_exact(&s,true);
    let bytes=wire_bytes(&PacketProjection::SignExactDisplay{presentation:&p});
    assert!(bytes<=65_536,"actual Sign packet bytes={bytes}");
    assert_eq!(bytes,checked(serde_json::to_vec(&p)).len()+43+8);
    let mut wrong_read=s.read.clone();wrong_read.facts.observed.fixed_identity_digest=h(0xf1);
    assert!(crate::consent_journal::project_sign_exact_facts(&wrong_read,&s.spend,&p.facts.signing_terms_digest,&s.history_digest,
        &json(&s.snapshot),&json(&s.receipt),||Ok(p.facts.display.clone()),p.facts.reviewed_at_ms,p.facts.expires_at_ms).is_err(),
        "actual Sign projection must not accept a different observed fixed source");
}

#[test]
fn complete_return_projection_preserves_original_host_result_and_full_packet() {
    let s=fixture();let sign=sign_exact(&s,false);
    // These are historical observations of an inert result, not real produced
    // signatures or OriginalAuthorizationEvidence. Their identity joins and
    // complete wire representation are the obligations exercised here.
    let signed=o::SignerSignCommittedV1 {
        sign_presentation_digest:sign.presentation_digest.clone(),authorization_id:s.spend.authorization_id.clone(),
        original_consent_ref:authority_digest("inert:composition:original-consent",&s.spend),
        result_digest:authority_digest("inert:composition:result",&(&s.spend,&s.receipt)),
        outbox_digest:authority_digest("inert:composition:outbox",&s.spend.input_bindings),fixed_identity_digest:s.original.fixed_identity_digest.clone(),
    };
    assert!(signed.validate().is_ok());
    let request=FinancialResultRequestV1 {account_id:s.intent.request.account_id.clone(),authorization_id:signed.authorization_id.clone(),
        original_consent_ref:signed.original_consent_ref.clone(),fixed:s.intent.recipient_intent.fixed.clone()};
    assert!(request.validate().is_ok(),"actual full return request validator");
    let host=&s.intent.recipient_intent.authorized_host_process_instance;
    assert!(host!=&s.intent.recipient_intent.signer_process_instance,"distinct Return Host/Signer domains");
    let from=s.terms.valid_from_ms;
    let facts=checked(crate::native_ui::project_return_read_facts(&s.original,&s.observed,&signed,&request,host,from+1_200_000,from+1_320_000));
    assert!(facts.validate().is_ok(),"actual ReturnRead projection");
    assert!(facts.request_json==json(&request),"Return exact request bytes");
    let mut read=o::SignerReturnReadPresentationV1 {
        actor:s.read.actor.clone(),facts,notice:RETURN_READ_NOTICE.into(),challenge:h(0xf2),source_ceiling_ms:s.read.source_ceiling_ms,
        read_ceiling_ms:120_000,service_ceiling_ms:s.read.service_ceiling_ms,writer_session_ceiling_ms:s.read.writer_session_ceiling_ms,
        channel_ceiling_ms:1_800_000,material_ceiling_ms:1_800_000,channel_expires_at_ms:s.terms.valid_until_ms,material_expires_at_ms:s.terms.valid_until_ms,
        presentation_digest:String::new(),
    };
    read.presentation_digest=checked(read.calculate_presentation_digest());
    size_metric("return_read",read.facts.display.len(),read.facts.request_json.len(),checked(serde_json::to_vec(&read.facts)).len(),
        checked(serde_json::to_vec(&read)).len(),wire_bytes(&PacketProjection::ReturnReadDisplay{presentation:&read}));
    assert!(read.validate().is_ok(),"actual ReturnRead full presentation");
    let review=authority_digest("inert:composition:return-review",&(&request,&signed));
    let display=crate::authority_bridge::project_return_display(&request,&signed.result_digest,&signed.outbox_digest,host,&review);
    assert!(display.contains(host)&&display.contains(&request.authorization_id));
    let expiry_calls=std::cell::Cell::new(0usize);
    let facts=checked(crate::native_ui::project_return_exact_facts(&read,&h(0xf3),&review,&h(0xf4),||display,from+1_300_000,
        ||{expiry_calls.set(expiry_calls.get()+1);Ok(from+1_420_000)}));
    assert_eq!(expiry_calls.get(),1);
    assert!(facts.validate().is_ok(),"actual ReturnExact projection");
    let mut exact=o::SignerReturnExactPresentationV1 {
        actor:read.actor.clone(),facts,notice:RETURN_EXACT_NOTICE.into(),challenge:h(0xf5),source_ceiling_ms:read.source_ceiling_ms,
        return_ceiling_ms:120_000,service_ceiling_ms:read.service_ceiling_ms,writer_session_ceiling_ms:read.writer_session_ceiling_ms,
        channel_ceiling_ms:read.channel_ceiling_ms,material_ceiling_ms:read.material_ceiling_ms,channel_expires_at_ms:read.channel_expires_at_ms,
        material_expires_at_ms:read.material_expires_at_ms,presentation_digest:String::new(),
    };
    exact.presentation_digest=checked(exact.calculate_presentation_digest());
    size_metric("return_exact",exact.facts.display.len(),0,checked(serde_json::to_vec(&exact.facts)).len(),
        checked(serde_json::to_vec(&exact)).len(),wire_bytes(&PacketProjection::ReturnExactDisplay{presentation:&exact}));
    assert!(exact.validate().is_ok(),"actual ReturnExact full presentation");
    for bytes in [wire_bytes(&PacketProjection::ReturnReadDisplay{presentation:&read}),wire_bytes(&PacketProjection::ReturnExactDisplay{presentation:&exact})] {
        assert!(bytes<=65_536,"actual Return packet bytes={bytes}");
    }
    let wrong_host=checked(crate::native_ui::project_return_read_facts(&s.original,&s.observed,&signed,&request,
        &s.intent.recipient_intent.signer_process_instance,from+1_200_000,from+1_320_000));
    assert!(wrong_host.validate().is_err(),"observed signer label cannot replace original Host");
    let mut wrong_request=request.clone();wrong_request.authorization_id.push_str("-replacement");
    let wrong_result=checked(crate::native_ui::project_return_read_facts(&s.original,&s.observed,&signed,&wrong_request,host,from+1_200_000,from+1_320_000));
    assert!(wrong_result.validate().is_err(),"full request must match actual retained Sign observation");
}

// Closed stage vocabulary and numeric lengths only. If an unchanged producer
// rejects before returning its DTO, no unavailable length is invented; hosted
// evidence may retain only this bounded prefix on test failure.
fn size_metric(stage:&'static str,display_bytes:usize,request_json_bytes:usize,facts_bytes:usize,presentation_bytes:usize,packet_bytes:usize) {
    assert!(matches!(stage,"continue"|"sign_lower"|"sign"|"return_read"|"return_exact"));
    eprintln!("COORDINATED_COMPOSITION_SIZE_V1 {}",serde_json::json!({
        "stage":stage,"display_bytes":display_bytes,"request_json_bytes":request_json_bytes,
        "facts_bytes":facts_bytes,"presentation_bytes":presentation_bytes,"packet_bytes":packet_bytes
    }));
}
