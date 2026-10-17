//! One concrete next stage of the same temporary born scenario. Public funding
//! blocks are fabricated for the actual two generated receiver addresses. Every
//! wallet, inventory, selection and retained contribution is nevertheless made
//! by the maintained native-reviewed producer; no completed rows are seeded.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

use super::continued_joined_v3::{prepare_original_continuation, retain_continued_candidate};
use super::joined_signer_worker_v1::{AGREEMENT_ID, JoinedSignerWorkerV1, PublicJoinedBornV1};
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B};
use super::synthetic_born_provider_v1::SyntheticBornProviderV1;
use super::*;
use crate::host::financial::manual_roster_inventory_setup_v2::RetainedRosterCandidateInputsV2;
use std::path::{Path, PathBuf};
use wholepact_authority::native_witness_owner::EphemeralNativeWitnessV1;
use wholepact_core::{
    Amount,
    born_policy_origin_v2::BornRecipientPolicyOriginV2,
    born_recipient_policy_v2::BornOwnReturnRuleV2,
    manual_candidate_selection::{ManualCandidateEconomicIntent, ManualCandidateInvocation},
    manual_construction::{PreconstructionBirthday, PreconstructionProvider},
    proposal::ParticipantAllocation,
};
use wholepact_signer_origin::manual_roster_v2::{
    HostManualRosterEnrollmentIntentV2, HostManualRosterPublicationRequestV2,
};
use wholepact_wallet::wallet::synthetic_born_receiver_blocks_v1::{
    SyntheticBornChainSpecV1, SyntheticBornReceiverBlocksV1,
};

pub(super) const CONSTRUCTION_KEY: &str = "synthetic-same-original-roster-construction-v3";
const OPERATOR: &str = "synthetic-local-host";
const RETENTION_POLICY: &str = "Temporary synthetic exact retained-input qualification; remove with owning scenario; no network funds.";

/// The live multithread runtime is retained while synchronous Host methods run.
/// This is not a construction owner. The contributions are genuine retained
/// owners and must still pass the unchanged full-candidate and native V3 path.
pub(super) struct RetainedJoinedStageV3<'host> {
    pub(super) contributions: Vec<RetainedRosterCandidateInputsV2<'host>>,
    pub(super) provider: SyntheticBornProviderV1,
    pub(super) runtime: tokio::runtime::Runtime,
}

fn stage(label: &'static str) -> Error {
    Error::Receipt(format!("synthetic retained-input stage failed: {label}"))
}
fn wall_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Invalid)
}
fn amount(value: u64) -> Result<Amount> {
    Amount::from_zatoshis(value).map_err(|_| Error::Invalid)
}
fn public_path(host: &Host, marker: &str, path: &Path) -> Result<()> {
    // Only this scenario's exact temporary paths reach the private PTY driver.
    // No wallet key, policy contents, credential or transcript is printed.
    host.terminal
        .message(&format!("{marker}={}\n", path.display()))
}

fn exact_economics(
    host: &Host,
    born: &[PublicJoinedBornV1; 3],
    requests: &[wholepact_signer_origin::manual_roster_v2::HostManualRosterPublicationRequestV2; 2],
    now_ms: u64,
    target_height: u32,
    expiry_height: u32,
) -> Result<ManualCandidateEconomicIntent> {
    host.require_manual_session()?;
    let current = host
        .engine
        .manual_roster_intent_target(host.access()?, AGREEMENT_ID)?;
    let agreement = current.agreement().clone();
    current.check_current(host.access()?)?;
    let target = host
        .engine
        .manual_enrollment_target(host.access()?, &requests[0].enrollment.terms)?;
    target.require_current_agreement(host.access()?, &agreement)?;
    let revision = target.agreement_revision();
    let other = host
        .engine
        .manual_enrollment_target(host.access()?, &requests[1].enrollment.terms)?;
    other.require_current_agreement(host.access()?, &agreement)?;
    if other.agreement_revision() != revision || agreement.recipients.len() != 1 {
        return Err(Error::Authentication);
    }
    let shape = known_two_owner_shape(target_height)?;
    let mut participants = born[1..]
        .iter()
        .map(|owner| {
            Ok(ParticipantAllocation {
                participant_id: owner.participant_id.clone(),
                account_id: owner.account_id.clone(),
                contribution: amount(150_000)?,
                fee_share: shape.per_owner_fee,
                fee_cap: amount(10_000)?,
                maximum_net_debit: shape.per_owner_debit,
                charges: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    participants.sort_by(|a, b| a.participant_id.cmp(&b.participant_id));
    let result = candidate_economics(
        agreement,
        revision,
        participants,
        now_ms,
        expiry_height,
        shape.fee,
    )?;
    target.check_current(host.access()?)?;
    other.check_current(host.access()?)?;
    Ok(result)
}

/// Exact synthetic inputs are one funded note per actual owner and outputs
/// are one recipient plus two positive same-account returns. Delegate the
/// padding AND fee rules to the same maintained versions used by construction.
/// This is pure upfront review material, never construction or fund evidence.
struct KnownTwoOwnerShapeV3 {
    actions: usize,
    fee: Amount,
    per_owner_fee: Amount,
    per_owner_debit: Amount,
}
fn known_two_owner_shape(target_height: u32) -> Result<KnownTwoOwnerShapeV3> {
    use zcash_primitives::transaction::{
        builder::BundlePadding,
        fees::{FeeRule as _, zip317},
    };
    let flags = orchard::bundle::BundleVersion::ironwood_v3().default_flags();
    let actions = BundlePadding::DEFAULT
        .bundle_type()
        .num_actions(flags, 2, 3)
        .map_err(|_| Error::Invalid)?;
    let fee = u64::from(
        zip317::FeeRule::standard()
            .fee_required(
                &zcash_protocol::consensus::TEST_NETWORK,
                target_height.into(),
                [],
                [],
                0,
                0,
                0,
                actions,
            )
            .map_err(|_| Error::Invalid)?,
    );
    if actions > 4 || fee == 0 || fee > 20_000 || fee % 2 != 0 {
        return Err(Error::Invalid);
    }
    let per_owner_fee = fee.checked_div(2).ok_or(Error::Invalid)?;
    let per_owner_debit = 150_000u64
        .checked_add(per_owner_fee)
        .ok_or(Error::Invalid)?;
    if per_owner_fee > 10_000 || per_owner_debit >= 300_000 {
        return Err(Error::Invalid);
    }
    Ok(KnownTwoOwnerShapeV3 {
        actions,
        fee: amount(fee)?,
        per_owner_fee: amount(per_owner_fee)?,
        per_owner_debit: amount(per_owner_debit)?,
    })
}

/// Inert arithmetic only. The caller above supplies the actual authenticated
/// agreement revision and separately retains/checks its genuine Engine owners.
fn candidate_economics(
    agreement: wholepact_core::AgreementDraft,
    revision: u64,
    participants: Vec<ParticipantAllocation>,
    now_ms: u64,
    expiry_height: u32,
    transaction_fee: Amount,
) -> Result<ManualCandidateEconomicIntent> {
    let created_at =
        chrono::DateTime::from_timestamp_millis(now_ms.try_into().map_err(|_| Error::Invalid)?)
            .ok_or(Error::Invalid)?
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let result = ManualCandidateEconomicIntent {
        version: 1,
        candidate_id: "synthetic-same-original-candidate-v3".into(),
        candidate_revision: revision,
        proposal_id: "synthetic-same-original-proposal-v3".into(),
        previous_proposal_id: None,
        created_at,
        agreement,
        participants,
        transaction_fee,
        expiry_height,
        own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
    };
    result.validate().map_err(|_| Error::Invalid)?;
    Ok(result)
}

/// Parses only the actual file produced by the retained signer's policy-export
/// review. It is input data, not accepted as an owner or a native admission.
fn read_original_policy(
    path: &Path,
    owner: &PublicJoinedBornV1,
) -> Result<BornRecipientPolicyOriginV2> {
    let bytes = zeroize::Zeroizing::new(crate::files::read_private(path, 131_072)?);
    let original: BornRecipientPolicyOriginV2 = serde_json::from_slice(&bytes)?;
    original.validate().map_err(|_| Error::Invalid)?;
    if original.birth_digest != owner.birth_digest
        || original.intent.identity.account_id != owner.account_id
        || original.intent.identity.full_viewing_key_digest != owner.full_viewing_key_digest
        || original.recipient_policy.participant_id != owner.participant_id
    {
        return Err(Error::Authentication);
    }
    Ok(original)
}

struct SelectedFilesV3 {
    inventory: PathBuf,
    selection: PathBuf,
    new_wallet: PathBuf,
}
#[allow(clippy::too_many_arguments)]
fn write_selections(
    root: &Path,
    owner: &PublicJoinedBornV1,
    policy_file: &Path,
    terms: &wholepact_core::manual_enrollment::BornManualEnrollmentTerms,
    provider: &PreconstructionProvider,
    birthday: &PreconstructionBirthday,
    material: &SyntheticBornReceiverBlocksV1,
    economics: &ManualCandidateEconomicIntent,
    invocation: &ManualCandidateInvocation,
) -> Result<SelectedFilesV3> {
    let original = diagnostic::host(B::RetainedPolicyRead, || {
        read_original_policy(policy_file, owner)
    })?;
    diagnostic::host(B::RetainedPolicyMatch, || {
        economics
            .require_policy(&original.recipient_policy, terms)
            .map_err(|_| Error::Invalid)
    })?;
    let inventory = root.join(format!("synthetic-inventory-owner-{}.json", owner.index));
    let selection = root.join(format!("synthetic-selection-owner-{}.json", owner.index));
    let new_wallet = root.join(format!("synthetic-new-preliminary-owner-{}", owner.index));
    // These two files contain choices only. The real Host derives generation,
    // attachment, provenance, caller binding and all approval clocks itself.
    crate::files::write_new(
        &inventory,
        &serde_json::to_vec(&serde_json::json!({
            "operation_id": format!("synthetic-inventory-owner-{}-v3", owner.index),
            "original_recipient_policy": &original.recipient_policy,
            "operator_name": OPERATOR,
            "retention_policy": RETENTION_POLICY,
            "provider": provider,
            "birthday": birthday,
            "minimum_confirmations": 10,
            "maximum_blocks": material.spec().block_count,
            "anchor_height": material.fabricated_context().anchor_height,
        }))?,
    )?;
    crate::files::write_new(
        &selection,
        &serde_json::to_vec(&serde_json::json!({
            "operation_id": format!("synthetic-selection-owner-{}-v3", owner.index),
            "original_policy_origin": original,
            "economic_intent": economics,
            "invocation": invocation,
        }))?,
    )?;
    Ok(SelectedFilesV3 {
        inventory,
        selection,
        new_wallet,
    })
}

/// The scenario itself is not moved or reconstructed. Splitting its actual
/// fields lets the retained Host borrow survive independent witness reviews.
/// This entry is intended for one joined child, not repeated attempts.
#[allow(clippy::too_many_arguments)]
pub(super) fn retain_two<'host>(
    host: &'host Host,
    witness: &mut EphemeralNativeWitnessV1,
    signers: &JoinedSignerWorkerV1,
    born: &[PublicJoinedBornV1; 3],
    roster_intents: &[HostManualRosterEnrollmentIntentV2; 2],
    roster_requests: &[HostManualRosterPublicationRequestV2; 2],
    roster_signed_extension_files: &[PathBuf; 2],
    roster_original_policy_files: &[PathBuf; 2],
    original_scope_expiry_ms: u64,
    temporary_root: &Path,
    original_scenario_deadline: Instant,
) -> Result<RetainedJoinedStageV3<'host>> {
    retain_two_inner(
        host,
        super::full_joined_v3::JoinedWitnessRouteV1::ConstructorOnly(witness),
        signers,
        born,
        roster_intents,
        roster_requests,
        roster_signed_extension_files,
        roster_original_policy_files,
        original_scope_expiry_ms,
        temporary_root,
        original_scenario_deadline,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn retain_two_with_original_witnesses<'host>(
    host: &'host Host,
    witnesses: &mut super::full_joined_v3::OriginalJoinedWitnessSetV1,
    signers: &JoinedSignerWorkerV1,
    born: &[PublicJoinedBornV1; 3],
    roster_intents: &[HostManualRosterEnrollmentIntentV2; 2],
    roster_requests: &[HostManualRosterPublicationRequestV2; 2],
    roster_signed_extension_files: &[PathBuf; 2],
    roster_original_policy_files: &[PathBuf; 2],
    original_scope_expiry_ms: u64,
    temporary_root: &Path,
    original_scenario_deadline: Instant,
) -> Result<RetainedJoinedStageV3<'host>> {
    retain_two_inner(
        host,
        super::full_joined_v3::JoinedWitnessRouteV1::Distinct(witnesses),
        signers,
        born,
        roster_intents,
        roster_requests,
        roster_signed_extension_files,
        roster_original_policy_files,
        original_scope_expiry_ms,
        temporary_root,
        original_scenario_deadline,
    )
}

#[allow(clippy::too_many_arguments)]
fn retain_two_inner<'host>(
    host: &'host Host,
    mut witnesses: super::full_joined_v3::JoinedWitnessRouteV1<'_>,
    signers: &JoinedSignerWorkerV1,
    born: &[PublicJoinedBornV1; 3],
    roster_intents: &[HostManualRosterEnrollmentIntentV2; 2],
    roster_requests: &[HostManualRosterPublicationRequestV2; 2],
    roster_signed_extension_files: &[PathBuf; 2],
    roster_original_policy_files: &[PathBuf; 2],
    original_scope_expiry_ms: u64,
    temporary_root: &Path,
    original_scenario_deadline: Instant,
) -> Result<RetainedJoinedStageV3<'host>> {
    let (now_ms, remaining) = diagnostic::host(B::RetainedPredecessor, || {
        host.require_manual_session()?;
        let now_ms = wall_ms()?;
        let remaining = original_scenario_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || remaining > Duration::from_secs(900) {
            return Err(Error::Permission);
        }
        Ok((now_ms, remaining))
    })?;
    // Fixed public synthetic chain parameters. The maintained builder also
    // enforces the qualified NU7 branch; these are never network observations.
    let material = diagnostic::host(B::RetainedMaterial, || {
        SyntheticBornReceiverBlocksV1::build(
            [
                &born[1].public_receive_address,
                &born[2].public_receive_address,
            ],
            [300_000, 300_000],
            SyntheticBornChainSpecV1 {
                prior_height: 4_465_039,
                prior_hash_protocol: crate::random::<32>()?,
                block_count: 12,
                timestamp: (now_ms / 1000).try_into().map_err(|_| Error::Invalid)?,
            },
        )
        .map_err(|_| stage("actual public receiver block material"))
    })?;
    let prior = material.trees().first().ok_or(Error::Invalid)?;
    let birthday = PreconstructionBirthday {
        prior_height: material.spec().prior_height,
        prior_block_hash: prior.hash.clone(),
        sapling_tree: prior.sapling_tree.clone(),
        orchard_tree: prior.orchard_tree.clone(),
        ironwood_tree: prior.ironwood_tree.clone(),
    };
    let economics = diagnostic::host(B::RetainedEconomics, || {
        exact_economics(
            host,
            born,
            roster_requests,
            now_ms,
            material
                .fabricated_context()
                .tip_height
                .checked_add(1)
                .ok_or(Error::Invalid)?,
            material
                .fabricated_context()
                .tip_height
                .checked_add(32)
                .ok_or(Error::Invalid)?,
        )
    })?;
    let invocation = diagnostic::host(B::RetainedInvocation, || {
        let completion = now_ms
            .checked_add(
                remaining
                    .as_millis()
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            )
            .ok_or(Error::Invalid)?
            .min(original_scope_expiry_ms);
        let invocation = ManualCandidateInvocation {
            version: 2,
            operation_id: "synthetic-original-retention-invocation-v2".into(),
            idempotency_key_digest: wholepact_store::request_digest(&serde_json::json!([
                &host.access()?.principal_id,
                CONSTRUCTION_KEY
            ]))?,
            invocation_nonce: hex::encode(crate::random::<32>()?),
            economic_intent_digest: economics.digest().map_err(|_| Error::Invalid)?,
            checkpoint_destination: roster_intents[0].account_intent.host.canonical_root.clone(),
            requested_at_ms: now_ms,
            construction_expires_at_ms: completion,
        };
        invocation.validate().map_err(|_| Error::Invalid)?;
        if roster_intents[1].account_intent.host.canonical_root != invocation.checkpoint_destination
        {
            return Err(Error::Authentication);
        }
        Ok(invocation)
    })?;
    let runtime = diagnostic::host(B::RetainedRuntime, || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| Error::Storage)
    })?;
    let provider = diagnostic::host(B::RetainedProvider, || {
        runtime
            .block_on(SyntheticBornProviderV1::start(
                material.clone(),
                diagnostic::host(B::RetainedTls, || {
                    super::synthetic_provider_tls_v1::child_server_config()
                        .map_err(|_| Error::Storage)
                })?,
                original_scenario_deadline,
            ))
            .map_err(|_| stage("finite actual TLS provider start"))
    })?;
    let configuration = PreconstructionProvider {
        source_id: "synthetic-same-original-public-blocks-v1".into(),
        endpoint: provider.endpoint().into(),
        trust_profile: "single_tls_provider_report_not_consensus".into(),
    };
    let mut contributions = Vec::with_capacity(2);
    for index in 0..2 {
        let owner = &born[index + 1];
        let witness = diagnostic::host(B::RetainedWitness, || witnesses.for_original(owner))?;
        let files = diagnostic::host(B::RetainedSelectionFiles, || {
            write_selections(
                temporary_root,
                owner,
                &roster_original_policy_files[index],
                &roster_requests[index].enrollment.terms,
                &configuration,
                &birthday,
                &material,
                &economics,
                &invocation,
            )
        })?;
        let reviewed = prepare_original_continuation(
            host,
            witness,
            signers,
            owner,
            &roster_intents[index],
            &roster_signed_extension_files[index],
            original_scenario_deadline,
        )?;
        public_path(
            host,
            "SYNTHETIC_JOINED_INVENTORY_SELECTION_PATH",
            &files.inventory,
        )?;
        public_path(
            host,
            "SYNTHETIC_JOINED_CANDIDATE_SELECTION_PATH",
            &files.selection,
        )?;
        public_path(
            host,
            "SYNTHETIC_JOINED_PRELIMINARY_WALLET_PATH",
            &files.new_wallet,
        )?;
        contributions.push(retain_continued_candidate(
            host,
            witness,
            signers,
            owner,
            reviewed,
            &format!("synthetic-retained-audit-owner-{}-v3", owner.index),
        )?);
    }
    if Instant::now() >= original_scenario_deadline
        || provider.served_requests() == 0
        || provider.denied_requests() != 0
    {
        return Err(Error::Authentication);
    }
    for retained in &contributions {
        retained.require_original_retention_scope_v2(host)?;
    }
    Ok(RetainedJoinedStageV3 {
        contributions,
        provider,
        runtime,
    })
}

/// Bounded executable boundary before the full-plan/read/Reserve/Consume join.
/// It starts from three actual births in this same child, never saved fixture
/// rows. Success establishes retained inputs only, not proof or authorization.
pub(super) fn exercise_retained_input_stage(terminal: crate::terminal::Terminal) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(840);
    let mut scenario = super::initial_joined_v3::prepare(terminal)?;
    let retained = retain_two(
        &scenario.host,
        &mut scenario.witness,
        &scenario.signers,
        &scenario.born,
        &scenario.roster_intents,
        &scenario.roster_requests,
        &scenario.roster_signed_extension_files,
        &scenario.roster_original_policy_files,
        scenario.expiry_ms,
        scenario.temporary.path(),
        deadline,
    )?;
    if retained.contributions.len() != 2
        || scenario
            .host
            .require_financial_generation_admission()
            .is_ok()
    {
        return Err(Error::Authentication);
    }
    let RetainedJoinedStageV3 {
        contributions,
        provider,
        runtime,
    } = retained;
    drop(contributions);
    runtime
        .block_on(provider.shutdown())
        .map_err(|_| stage("finite provider drain"))?;
    drop(runtime);
    drop(scenario);
    Ok(())
}

pub(super) fn inputs() -> Vec<Input<'static>> {
    let mut result = super::initial_joined_v3::inputs();
    let review = |detail| Input::ExactReview {
        detail,
        approve: true,
    };
    for operation in [
        "synthetic-native-retention-owner-1-v3",
        "synthetic-native-retention-owner-2-v3",
    ] {
        result.push(Input::CapturedPath {
            marker: "SYNTHETIC_JOINED_ORIGINAL_ROSTER_PATH=",
            prompt: "Exact ORIGINAL private roster owner-signature JSON file: ",
        });
        for detail in [
            "Read this exact private local file into the current non-signing host for reviewing unchanged original account",
            "Inspect the complete protected ancestor capsule for exact manual-enrollment distinctness.",
            "Review the immutable original account owner for an exact additional-account roster AUDIT",
            "SYNTHETIC JOINED CONTROLLER TEST, NOT ATTENDED CONSENT.",
            "SYNTHETIC JOINED CONTROLLER TEST: approve only finite original-intent pairing metadata",
            "Inspect the complete protected ancestor capsule for exact manual-enrollment distinctness.",
            "Review the immutable original account owner for an exact additional-account roster AUDIT",
            "Retain this exact roster-bound audit under the original account ledger",
        ] {
            result.push(review(detail));
        }
        result.push(Input::CapturedPath {
            marker: "SYNTHETIC_JOINED_INVENTORY_SELECTION_PATH=",
            prompt: "Exact private preliminary-inventory selection JSON file: ",
        });
        result.push(review("Read this exact private local file into the current non-signing host for reviewing the full original V2 recipient policy"));
        result.push(Input::CapturedPath {
            marker: "SYNTHETIC_JOINED_PRELIMINARY_WALLET_PATH=",
            prompt: "NEW private encrypted preliminary wallet directory (absolute; no reopen or pending retry): ",
        });
        for prompt in [
            "New preliminary wallet passphrase (12–1024 bytes): ",
            "Repeat preliminary wallet passphrase: ",
        ] {
            result.push(Input::Text {
                prompt,
                response: "synthetic-recovery-review-password",
            });
        }
        for detail in [
            "This explicit command creates a NEW encrypted preliminary wallet before signer launch.",
            "Admit one exact roster-native V2 preliminary account inventory operation",
            "After the exact reviewed audit commits, send one DISTINCT preliminary-inventory pairing",
            "After that same-process pairing, send ONE preliminary viewing request for this exact scope.",
        ] {
            result.push(review(detail));
        }
        result.push(Input::CapturedPath {
            marker: "SYNTHETIC_JOINED_CANDIDATE_SELECTION_PATH=",
            prompt: "Exact private input-free candidate selection JSON file: ",
        });
        for detail in [
            "Read this exact private local file into the current non-signing host for reviewing exact candidate economics",
            "Prepare exactly one private contribution for these exact economic terms.",
            "After the exact reviewed audit and preliminary wallet import/scan, send one DISTINCT candidate-selection pairing",
            "After that separate same-process pairing, send ONE candidate-selection request",
        ] {
            result.push(review(detail));
        }
        result.push(Input::Text {
            prompt: "Exact distinct native retention operation ID: ",
            response: operation,
        });
        for detail in [
            "Retain the ONE maintained contribution selected for these exact input-free economics",
            "SYNTHETIC JOINED TEST: send ONLY this actual prepared roster request",
            "SYNTHETIC JOINED TEST: approve the exact bounded pairing metadata for this original roster publication",
        ] {
            result.push(review(detail));
        }
    }
    result
}

#[test]
fn actual_three_born_same_original_retained_inputs_preserve_refusal() {
    foreground_child("three-born-retained-inputs-v3", &inputs()).expect(
        "actual temporary continued inventories and retained contributions; no construction, proof, return, dispatch or attended qualification",
    );
}

#[test]
fn original_retention_economics_uses_complete_canonical_seconds_contract() {
    // Pure untrusted test claims, NOT a native approval, source or account.
    let agreement = serde_json::from_value(serde_json::json!({
        "schema_version":1, "agreement_id":"synthetic-economics-agreement",
        "obligation_id":"synthetic-economics-obligation", "revision":1,
        "purpose":"Synthetic inert timestamp and economics regression only",
        "organizer_identity":"synthetic-roster-host",
        "network_profile_id":wholepact_protocol::construction::PROFILE_ID,
        "recipients":[{"recipient_id":"synthetic-recipient", "address":"syntheticreceiver0001",
            "amount":"300000", "memo":null, "instruction_provenance":"Inert syntax fixture only"}],
        "funding_policy":{"kind":"exact", "target":"300000"},
        "fee_policy":{"kind":"pro_rata"},
        "privacy_profile":{"mode":"declared_operator", "proving_operator":OPERATOR,
            "dedicated_accounts_required":true},
        "coordination_deadline":null, "confirmation_policy":{"required_confirmations":10},
        "extensions":[]
    }))
    .unwrap();
    let shape = known_two_owner_shape(4_465_052).unwrap();
    let participants = [("synthetic-owner-a", "a"), ("synthetic-owner-b", "b")]
        .into_iter()
        .map(|(id, account)| ParticipantAllocation {
            participant_id: id.into(),
            account_id: account.repeat(64),
            contribution: amount(150_000).unwrap(),
            fee_share: shape.per_owner_fee,
            fee_cap: amount(10_000).unwrap(),
            maximum_net_debit: shape.per_owner_debit,
            charges: Vec::new(),
        })
        .collect();
    let original_milliseconds = 1_792_185_600_987;
    let intent = candidate_economics(
        agreement,
        1,
        participants,
        original_milliseconds,
        4_465_083,
        shape.fee,
    )
    .unwrap();
    let debits = intent.validate().unwrap();
    // The actual caller uses this SAME maintained padding/fee result before
    // any approval or retention; the constructor still checks actual notes.
    assert_eq!(shape.actions, 3);
    assert_eq!(shape.fee.as_zatoshis(), 15_000);
    assert_eq!(shape.per_owner_fee.as_zatoshis(), 7_500);
    assert_eq!(shape.per_owner_debit.as_zatoshis(), 157_500);
    assert_eq!(intent.transaction_fee, shape.fee);
    assert_eq!(debits.len(), 2);
    assert!(
        debits
            .values()
            .all(|value| *value == amount(157_500).unwrap())
    );
    assert_eq!(intent.created_at.len(), 20);
    assert!(intent.created_at.ends_with('Z'));
    assert!(!intent.created_at.contains('.'));
    // Only canonical proposal display precision changed. Millisecond authority
    // clocks are not truncated, regenerated or renewed by this helper.
    let mut fractional = intent;
    fractional.created_at = chrono::DateTime::from_timestamp_millis(original_milliseconds as i64)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    assert!(fractional.validate().is_err());
}
