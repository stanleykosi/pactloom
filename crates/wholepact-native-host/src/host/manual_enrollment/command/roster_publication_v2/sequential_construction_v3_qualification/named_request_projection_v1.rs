//! Key-free claims and exact proved bytes projected from the actual retained
//! Host checkpoint. No imported digest, scope or metadata creates that owner.
//! The verifier still obtains its own real account-policy leases and performs
//! independent complete proof/economic verification. This is not authority.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

use crate::host::{
    Host, born_offline_checkpoint_carrier_v1::RetainedBornOfflineCheckpointCarrierV1,
};
use crate::{Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use wholepact_authority::offline::{OfflineAuthorizationTerms, OfflineEnrollmentPolicy};
use wholepact_protocol::{
    construction::{InputActionMapping, OutputActionMapping},
    review::{OutputPurpose, ReviewPolicy},
    review_manifest::verify_manifest_policy,
};
use wholepact_signer::native_ui::synthetic_born_joined_qualification::OriginalNamedSetupMetadataV1;
use wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyScopeV1;
use zeroize::Zeroizing;

const MAX_REQUEST: usize = 2 * 1024 * 1024;

#[derive(Serialize)]
struct ParticipantClaim<'a> {
    account_id: &'a str,
    contribution_zatoshis: u64,
    fee_share_zatoshis: u64,
    maximum_net_debit_zatoshis: u64,
}
#[derive(Serialize)]
struct InputClaim<'a> {
    input_id: &'a str,
    action_index: usize,
    participant_index: usize,
    nullifier: String,
    value_zatoshis: u64,
}
#[derive(Serialize)]
struct OutputClaim<'a> {
    output_id: &'a str,
    action_index: usize,
    receiver: String,
    value_zatoshis: u64,
    memo: &'a [u8],
    return_participant_index: Option<usize>,
}
#[derive(Serialize)]
struct PolicyClaims<'a> {
    manifest_digest: String,
    participants: Vec<ParticipantClaim<'a>>,
    inputs: Vec<InputClaim<'a>>,
    outputs: Vec<OutputClaim<'a>>,
    exact_fee_zatoshis: u64,
    expiry_height: u32,
    anchor: String,
}
#[derive(Serialize)]
struct RequestFile<'a> {
    version: u16,
    scopes: &'a [NamedVerifierPolicyScopeV1],
    endpoints: &'a [String],
    original_artifact: &'a [u8],
    terms: &'a OfflineAuthorizationTerms,
    policy: PolicyClaims<'a>,
}

/// Explicitly disclosed local request bytes. This cannot be converted to a
/// verifier assertion, approval, retained source, signature or witness permit.
/// The consuming same-worker caller must pass it to the actual verifier UI.
pub(super) struct DisclosedNamedRequestV1 {
    request: Zeroizing<Vec<u8>>,
    own_context: Zeroizing<Vec<u8>>,
    terms: OfflineAuthorizationTerms,
    expected_transformation_digest: String,
}
impl DisclosedNamedRequestV1 {
    pub(super) fn request_bytes(&self) -> &[u8] {
        &self.request
    }
    pub(super) fn own_context_bytes(&self) -> &[u8] {
        &self.own_context
    }
    pub(super) fn terms(&self) -> &OfflineAuthorizationTerms {
        &self.terms
    }
    pub(super) fn expected_transformation_digest(&self) -> &str {
        &self.expected_transformation_digest
    }
}

/// Inert exact selected-recipient terms and request scopes. Only the caller
/// retaining the same actual carriers/controllers may use these as inputs to
/// their separately native-approved disclosure. No imported DTO grants trust.
pub(super) struct OriginalNamedRequestClaimsV1 {
    pub(super) terms: OfflineAuthorizationTerms,
    pub(super) scopes: [NamedVerifierPolicyScopeV1; 2],
    pub(super) original_deadline: std::time::Instant,
}

/// Each selected recipient gets a DISTINCT actual verifier assertion request.
/// All original construction/session/policy/carrier bounds continue to apply.
pub(super) fn original_request_claims(
    host: &Host,
    carriers: [&RetainedBornOfflineCheckpointCarrierV1<'_, '_>; 2],
    metadata: [&OriginalNamedSetupMetadataV1; 2],
    verifier_public_key: [u8; 32],
    selected: usize,
    scenario_deadline: std::time::Instant,
) -> Result<OriginalNamedRequestClaimsV1> {
    let source = *carriers.get(selected).ok_or(Error::Invalid)?;
    host.require_manual_session()?;
    let started = std::time::Instant::now();
    let now = wall_milliseconds()?;
    let mut deadline = scenario_deadline.min(
        started
            .checked_add(std::time::Duration::from_secs(120))
            .ok_or(Error::Invalid)?,
    );
    let mut expiry = now.checked_add(120_000).ok_or(Error::Invalid)?;
    for (carrier, setup) in carriers.iter().zip(metadata) {
        if !carrier.belongs_to(host) {
            return Err(Error::Authentication);
        }
        carrier.check_current()?;
        let actual = carrier.original();
        if actual.claim() != source.original().claim()
            || actual.receipt() != source.original().receipt()
            || actual.checkpoint().summary() != source.original().checkpoint().summary()
            || setup.account_id != carrier.origin().account_id
        {
            return Err(Error::Authentication);
        }
        carrier
            .origin()
            .require_historical_provenance_v2()
            .map_err(|_| Error::Authentication)?;
        deadline = deadline.min(carrier.deadline());
        expiry = expiry
            .min(setup.construction_expires_at_ms)
            .min(setup.original_session.expires_at_ms)
            .min(setup.offline_policy.expires_at_ms);
    }
    let remaining: u64 = deadline
        .checked_duration_since(started)
        .ok_or(Error::Permission)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Permission)?;
    expiry = expiry.min(now.checked_add(remaining).ok_or(Error::Invalid)?);
    if now >= expiry {
        return Err(Error::Permission);
    }
    deadline = deadline.min(
        started
            .checked_add(std::time::Duration::from_millis(expiry - now))
            .ok_or(Error::Invalid)?,
    );
    let nonce = hex::encode(crate::random::<32>()?);
    let verifier_digest = hex::encode(Sha256::digest(verifier_public_key));
    let original_request_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:named-verifier-original-request:v1",
        &(
            &nonce,
            source.original().proposal().proposal_digest(),
            &source.origin().proved_artifact_digest,
            &verifier_digest,
            now,
            expiry,
        ),
    )
    .map_err(|_| Error::Invalid)?;
    let mut scopes = Vec::with_capacity(2);
    for (carrier, setup) in carriers.iter().zip(metadata) {
        let proposal = carrier.original().proposal();
        let participant = proposal
            .manifest()
            .participants
            .iter()
            .find(|p| p.account_id == setup.account_id)
            .ok_or(Error::Authentication)?;
        let scope = NamedVerifierPolicyScopeV1 {
            version: 1,
            proposal: proposal.input().clone(),
            account_id: setup.account_id.clone(),
            participant_id: participant.participant_id.clone(),
            enrollment_ref: setup.local_enrollment_ref.clone(),
            accepted_manifest_ref: setup.accepted_manifest_ref.clone(),
            original_request_digest: original_request_digest.clone(),
            original_nonce: nonce.clone(),
            original_artifact_digest: carrier.origin().proved_artifact_digest.clone(),
            verifier_key_digest: verifier_digest.clone(),
            verifier_public_key,
            verifier_destination: format!(
                "same retained synthetic local named verifier {verifier_digest}"
            ),
            original_validity_not_before_ms: now,
            original_validity_expires_ms: expiry,
            requested_at_ms: now,
            disclosure_expires_at_ms: expiry,
        };
        scope.validate().map_err(|_| Error::Authentication)?;
        scopes.push(scope);
    }
    let authorization_id = format!("born-payment-{}", hex::encode(crate::random::<16>()?));
    let terms = original_terms(source, metadata[selected], authorization_id)?;
    for carrier in carriers {
        carrier.check_current()?;
    }
    if std::time::Instant::now() >= deadline {
        return Err(Error::Permission);
    }
    Ok(OriginalNamedRequestClaimsV1 {
        terms,
        scopes: scopes.try_into().map_err(|_| Error::Invalid)?,
        original_deadline: deadline,
    })
}

fn original_terms(
    source: &RetainedBornOfflineCheckpointCarrierV1<'_, '_>,
    metadata: &OriginalNamedSetupMetadataV1,
    authorization_id: String,
) -> Result<OfflineAuthorizationTerms> {
    let o = source.origin();
    let actual = source.original();
    let p = actual.proposal();
    let policy = actual.checkpoint().policy();
    let row = actual
        .claim()
        .consumed
        .iter()
        .find(|c| c.request.plan.enrollment().identity.account_id == o.account_id)
        .ok_or(Error::Authentication)?;
    let common = &row.request.plan.common_context;
    let own = policy
        .participants
        .iter()
        .position(|a| a.account_id == o.account_id)
        .ok_or(Error::Authentication)?;
    let allocation = &policy.participants[own];
    let (mappings, _) = original_mappings(p, policy)?;
    let mut inputs = policy
        .inputs
        .iter()
        .filter(|i| i.participant_index == own)
        .map(|i| {
            let m = mappings
                .iter()
                .find(|m| m.action_index == i.action_index)
                .ok_or(Error::Authentication)?;
            Ok(wholepact_authority::InputReservation {
                input_id: m.input_id.clone(),
                nullifier: hex::encode(i.nullifier),
                action_index: i.action_index.try_into().map_err(|_| Error::Invalid)?,
                value_zatoshis: i.value_zatoshis,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    inputs.sort_by_key(|i| i.action_index);
    let snapshot = o
        .require_historical_provenance_v2()
        .map_err(|_| Error::Authentication)?
        .reference_snapshot()
        .map_err(|_| Error::Authentication)?;
    let pending = wholepact_core::proposal::canonical_digest(
        "wholepact:named-verifier-package-pending:v1",
        &(
            o.digest().map_err(|_| Error::Authentication)?,
            &authorization_id,
        ),
    )
    .map_err(|_| Error::Invalid)?;
    let terms = OfflineAuthorizationTerms {
        account_id: o.account_id.clone(),
        network_profile_id: o.network_profile_id.clone(),
        consensus_branch_id: common.consensus_branch_id,
        authorization_id,
        enrollment_ref: metadata.witness_enrollment_ref.clone(),
        accepted_manifest_ref: metadata.accepted_manifest_ref.clone(),
        agreement_id: o.agreement_id.clone(),
        obligation_id: p.manifest().agreement.obligation_id.clone(),
        proposal_id: o.proposal_id.clone(),
        proposal_revision: o.proposal_revision,
        proposal_digest: o.proposal_digest.clone(),
        manifest_digest: o.manifest_digest.clone(),
        effects_digest: o.effects_commitment.clone(),
        artifact_digest: o.proved_artifact_digest.clone(),
        review_binding: o.review_binding.clone(),
        review_package_digest: pending,
        recipient_scope_digest: row
            .request
            .plan
            .retained
            .selection
            .scope
            .selection
            .original_policy_origin
            .recipient_policy
            .digest()
            .map_err(|_| Error::Authentication)?,
        offline_signer_key_digest: o.signer_key_digest.clone(),
        return_recipient_key_digest: o.host_return_key_digest.clone(),
        offline_policy_digest: metadata
            .offline_policy
            .policy_digest()
            .map_err(|_| Error::Authentication)?,
        snapshot: wholepact_authority::offline::OfflineSnapshotCommitment {
            source_id: snapshot.source_id,
            source_identity_digest: snapshot.source_identity_digest,
            source_policy_digest: snapshot.source_policy_digest,
            snapshot_digest: snapshot.snapshot_digest,
            observed_at_ms: snapshot.observed_at_ms,
            tip_height: snapshot.tip_height,
            tip_hash: snapshot.tip_hash,
            anchor_height: snapshot.anchor_height,
            anchor_hash: snapshot.anchor_hash,
            anchor_root: snapshot.anchor_root,
        },
        inputs,
        maximum_debit_zatoshis: allocation.maximum_net_debit_zatoshis,
        fee_share_zatoshis: allocation.fee_share_zatoshis,
        transaction_fee_zatoshis: policy.exact_fee_zatoshis,
        transaction_expiry_height: policy.expiry_height,
        unknown_facts: wholepact_authority::offline::OfflineUnknownFact::ALL.to_vec(),
        semantics: metadata.offline_policy.semantics.clone(),
    };
    terms.validate().map_err(|_| Error::Authentication)?;
    o.validate_snapshot_terms(&terms)
        .map_err(|_| Error::Authentication)?;
    require_exact_terms(source, &terms, &metadata.offline_policy, &mappings)?;
    Ok(terms)
}

/// `terms`, `policy` and the native-selected scopes are inert claims. Every
/// checkpoint/economic/action field is independently compared below against
/// the actual opaque retained original. Their remaining local setup fields
/// must still be authenticated by the genuine verifier/signer controllers.
pub(super) fn disclose_original_request(
    host: &Host,
    source: &RetainedBornOfflineCheckpointCarrierV1<'_, '_>,
    terms: OfflineAuthorizationTerms,
    metadata: &OriginalNamedSetupMetadataV1,
    scopes: &[NamedVerifierPolicyScopeV1],
    endpoints: &[String],
) -> Result<DisclosedNamedRequestV1> {
    host.require_manual_session()?;
    if !source.belongs_to(host) {
        return Err(Error::Authentication);
    }
    source.check_current()?;
    let origin = source.origin();
    let original = source.original();
    original.check_current(host.access()?)?;
    let checkpoint = original.checkpoint();
    let proposal = original.proposal();
    let policy = checkpoint.policy();
    terms.validate().map_err(|_| Error::Authentication)?;
    let enrollment = &metadata.offline_policy;
    enrollment.validate().map_err(|_| Error::Authentication)?;
    require_actual_setup(source, &terms, metadata, scopes)?;
    let (inputs, outputs) = original_mappings(proposal, policy)?;
    require_exact_terms(source, &terms, enrollment, &inputs)?;
    require_scopes(proposal, &terms, scopes, endpoints)?;
    require_current_scopes(scopes)?;
    let layout = wholepact_protocol::canonical_role_layout::produce_canonical_layout(
        checkpoint.pczt_bytes(),
        policy,
    )
    .map_err(|_| Error::Authentication)?;
    let expected_transformation_digest = layout.transformation().commitment().to_owned();
    if layout.transformation().original_digest() != origin.proved_artifact_digest {
        return Err(Error::Authentication);
    }
    let claims = PolicyClaims {
        manifest_digest: hex::encode(policy.manifest_digest),
        participants: policy
            .participants
            .iter()
            .map(|p| ParticipantClaim {
                account_id: &p.account_id,
                contribution_zatoshis: p.contribution_zatoshis,
                fee_share_zatoshis: p.fee_share_zatoshis,
                maximum_net_debit_zatoshis: p.maximum_net_debit_zatoshis,
            })
            .collect(),
        inputs: policy
            .inputs
            .iter()
            .zip(&inputs)
            .map(|(p, m)| InputClaim {
                input_id: &m.input_id,
                action_index: p.action_index,
                participant_index: p.participant_index,
                nullifier: hex::encode(p.nullifier),
                value_zatoshis: p.value_zatoshis,
            })
            .collect(),
        outputs: policy
            .outputs
            .iter()
            .zip(&outputs)
            .map(|(p, m)| OutputClaim {
                output_id: &m.output_id,
                action_index: p.action_index,
                receiver: hex::encode(p.receiver.to_raw_address_bytes()),
                value_zatoshis: p.value_zatoshis,
                memo: &p.memo,
                return_participant_index: match p.purpose {
                    OutputPurpose::Recipient => None,
                    OutputPurpose::Return { participant_index } => Some(participant_index),
                },
            })
            .collect(),
        exact_fee_zatoshis: policy.exact_fee_zatoshis,
        expiry_height: policy.expiry_height,
        anchor: hex::encode(policy.anchor),
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&RequestFile {
        version: 1,
        scopes,
        endpoints,
        original_artifact: checkpoint.pczt_bytes(),
        terms: &terms,
        policy: claims,
    })?);
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err(Error::Invalid);
    }
    let common = &original
        .claim()
        .consumed
        .first()
        .ok_or(Error::Authentication)?
        .request
        .plan
        .common_context;
    let own_context = Zeroizing::new(serde_json::to_vec(&serde_json::json!({
        "schema_version": 1, "manifest_digest": proposal.manifest_digest(),
        "construction_context": {
            "anchor": common.anchor_root, "anchor_height": common.anchor_height,
            "anchor_block_hash": common.anchor_hash_protocol, "target_height": common.target_height,
        },
        "input_actions": inputs.iter().map(|m| serde_json::json!({
            "input_id":m.input_id,"account_id":m.account_id,"action_index":m.action_index
        })).collect::<Vec<_>>(),
        "output_actions": outputs.iter().map(|m| serde_json::json!({
            "output_id":m.output_id,"action_index":m.action_index
        })).collect::<Vec<_>>(),
    }))?);
    if own_context.len() > 1024 * 1024 {
        return Err(Error::Invalid);
    }
    let digest = wholepact_core::proposal::canonical_digest(
        "wholepact:synthetic-actual-named-request-disclosure:v1",
        &(
            origin.digest().map_err(|_| Error::Authentication)?,
            hex::encode(Sha256::digest(&bytes)),
            hex::encode(Sha256::digest(&own_context)),
            &expected_transformation_digest,
            scopes,
            endpoints,
        ),
    )
    .map_err(|_| Error::Invalid)?;
    let approval = host.terminal.approve_publication(&digest, &format!(
        "SYNTHETIC JOINED CONTROLLER TEST: disclose this exact ACTUAL independently verified saved full private transaction to the separately selected local named verifier, plus exact key-free action/context claims to the original offline recipients. The verifier receives the complete private PCZT, potentially including private transaction metadata, note/witness material and account linkage; it is not the minimal recipient artifact. No FVK bytes are copied from the Host review policy into these claims. Each account must separately approve its actual viewing-policy lease in its own native controller. This new disclosure creates no assertion, reservation, signing permission, current-input truth or dispatch authority. The test-only local request remains in zeroizing memory and may be retained in a private temporary file by the actual verifier; secure deletion is not promised. The final package must come from the actual verifier's independent proof checks, native assertion signature and separate exact HPKE export.\nActual checkpoint: {}\nSelected original account: {}\nVerifier fingerprint: {}\nBounded request bytes: {}\nDisclosure digest: {}",
        origin.digest().map_err(|_| Error::Authentication)?, terms.account_id,
        scopes.first().ok_or(Error::Invalid)?.verifier_key_digest, bytes.len(), digest,
    ))?;
    approval.commit(
        &digest,
        || {
            host.require_manual_session()?;
            source.check_current()?;
            require_current_scopes(scopes)?;
            original.check_current(host.access()?)?;
            Ok(())
        },
        |_| {
            source.check_current()?;
            require_current_scopes(scopes)?;
            Ok(DisclosedNamedRequestV1 {
                request: bytes,
                own_context,
                terms,
                expected_transformation_digest,
            })
        },
    )
}

/// Metadata is only an inert projection from the actual named controller. All
/// locally recoverable identities must still agree with the actual carrier;
/// private native/profile/history checks remain independently mandatory there.
fn require_actual_setup(
    source: &RetainedBornOfflineCheckpointCarrierV1<'_, '_>,
    terms: &OfflineAuthorizationTerms,
    metadata: &OriginalNamedSetupMetadataV1,
    scopes: &[NamedVerifierPolicyScopeV1],
) -> Result<()> {
    let scope = scopes
        .iter()
        .find(|s| s.account_id == terms.account_id)
        .ok_or(Error::Authentication)?;
    let key =
        wholepact_transport::TransportPublicKey::from_bytes(metadata.signer_transport_public_key)
            .map_err(|_| Error::Authentication)?;
    let bound = metadata
        .construction_expires_at_ms
        .min(metadata.original_session.expires_at_ms)
        .min(metadata.offline_policy.expires_at_ms);
    if metadata.account_id != source.origin().account_id
        || terms.account_id != metadata.account_id
        || terms.enrollment_ref != metadata.witness_enrollment_ref
        || terms.accepted_manifest_ref != metadata.accepted_manifest_ref
        || scope.enrollment_ref != metadata.local_enrollment_ref
        || scope.accepted_manifest_ref != metadata.accepted_manifest_ref
        || key.fingerprint() != source.origin().signer_key_digest
        || scope.original_validity_expires_ms > bound
        || metadata.offline_policy.enrollment_ref != metadata.witness_enrollment_ref
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn original_mappings(
    proposal: &wholepact_core::Proposal,
    policy: &ReviewPolicy,
) -> Result<(Vec<InputActionMapping>, Vec<OutputActionMapping>)> {
    if proposal.manifest().inputs.len() != policy.inputs.len()
        || proposal.manifest().outputs.len() != policy.outputs.len()
    {
        return Err(Error::Authentication);
    }
    // The maintained constructor appends these policy vectors in manifest
    // order before persisting them. Each stores the actual randomized index.
    // Do not sort, infer a sequential action index, or match equal outputs.
    let inputs = proposal
        .manifest()
        .inputs
        .iter()
        .zip(&policy.inputs)
        .map(|(m, p)| InputActionMapping {
            input_id: m.input_id.clone(),
            account_id: m.account_id.clone(),
            action_index: p.action_index,
        })
        .collect::<Vec<_>>();
    let outputs = proposal
        .manifest()
        .outputs
        .iter()
        .zip(&policy.outputs)
        .map(|(m, p)| OutputActionMapping {
            output_id: m.output_id.clone(),
            action_index: p.action_index,
        })
        .collect::<Vec<_>>();
    verify_manifest_policy(proposal, policy, &inputs, &outputs)
        .map_err(|_| Error::Authentication)?;
    Ok((inputs, outputs))
}

fn require_scopes(
    proposal: &wholepact_core::Proposal,
    terms: &OfflineAuthorizationTerms,
    scopes: &[NamedVerifierPolicyScopeV1],
    endpoints: &[String],
) -> Result<()> {
    let first = scopes.first().ok_or(Error::Invalid)?;
    if scopes.len() != proposal.manifest().participants.len()
        || scopes.len() != endpoints.len()
        || scopes.len() != 2
    {
        return Err(Error::Authentication);
    }
    let mut accounts = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for (scope, endpoint) in scopes.iter().zip(endpoints) {
        scope.validate().map_err(|_| Error::Authentication)?;
        if scope.proposal != *proposal.input()
            || scope.original_artifact_digest != terms.artifact_digest
            || scope.original_request_digest != first.original_request_digest
            || scope.original_nonce != first.original_nonce
            || scope.verifier_public_key != first.verifier_public_key
            || scope.verifier_destination != first.verifier_destination
            || scope.original_validity_not_before_ms != first.original_validity_not_before_ms
            || scope.original_validity_expires_ms != first.original_validity_expires_ms
            || !accounts.insert(scope.account_id.as_str())
            || !paths.insert(endpoint.as_str())
            || endpoint.len() > 4096
            || !std::path::Path::new(endpoint).is_absolute()
            || endpoint.chars().any(char::is_control)
        {
            return Err(Error::Authentication);
        }
    }
    if proposal
        .manifest()
        .participants
        .iter()
        .any(|p| !accounts.contains(p.account_id.as_str()))
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn require_exact_terms(
    source: &RetainedBornOfflineCheckpointCarrierV1<'_, '_>,
    t: &OfflineAuthorizationTerms,
    enrollment: &OfflineEnrollmentPolicy,
    inputs: &[InputActionMapping],
) -> Result<()> {
    let o = source.origin();
    o.validate_snapshot_terms(t)
        .map_err(|_| Error::Authentication)?;
    let actual = source.original();
    let p = actual.proposal();
    let policy = actual.checkpoint().policy();
    let owner = policy
        .participants
        .iter()
        .position(|a| a.account_id == t.account_id)
        .ok_or(Error::Authentication)?;
    let allocation = &policy.participants[owner];
    let consumed = actual
        .claim()
        .consumed
        .iter()
        .find(|c| c.request.plan.enrollment().identity.account_id == t.account_id)
        .ok_or(Error::Authentication)?;
    let common = &consumed.request.plan.common_context;
    let mut exact = policy
        .inputs
        .iter()
        .filter(|i| i.participant_index == owner)
        .map(|i| {
            let mapping = inputs
                .iter()
                .find(|m| m.action_index == i.action_index)
                .ok_or(Error::Authentication)?;
            Ok(wholepact_authority::InputReservation {
                input_id: mapping.input_id.clone(),
                nullifier: hex::encode(i.nullifier),
                value_zatoshis: i.value_zatoshis,
                action_index: u64::try_from(i.action_index).map_err(|_| Error::Invalid)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    exact.sort_by_key(|i| i.action_index);
    if t.account_id != o.account_id
        || t.network_profile_id != o.network_profile_id
        || t.agreement_id != o.agreement_id
        || t.obligation_id != p.manifest().agreement.obligation_id
        || t.proposal_id != o.proposal_id
        || t.proposal_revision != o.proposal_revision
        || t.proposal_digest != o.proposal_digest
        || t.manifest_digest != o.manifest_digest
        || t.artifact_digest != o.proved_artifact_digest
        || t.effects_digest != o.effects_commitment
        || t.review_binding != o.review_binding
        || t.inputs != exact
        || t.maximum_debit_zatoshis != allocation.maximum_net_debit_zatoshis
        || t.fee_share_zatoshis != allocation.fee_share_zatoshis
        || t.transaction_fee_zatoshis != policy.exact_fee_zatoshis
        || t.transaction_expiry_height != policy.expiry_height
        || t.consensus_branch_id != common.consensus_branch_id
        || t.snapshot.tip_height != common.reference_tip_height
        || t.snapshot.tip_hash != common.reference_tip_hash_protocol
        || t.snapshot.anchor_height != common.anchor_height
        || t.snapshot.anchor_hash != common.anchor_hash_protocol
        || t.snapshot.anchor_root != common.anchor_root
        || t.snapshot.source_id != common.provider.source_id
        || t.offline_policy_digest
            != enrollment
                .policy_digest()
                .map_err(|_| Error::Authentication)?
        || t.account_id != enrollment.account_id
        || t.enrollment_ref != enrollment.enrollment_ref
        || t.network_profile_id != enrollment.network_profile_id
        || t.semantics != enrollment.semantics
        || t.offline_signer_key_digest != enrollment.offline_signer_key_digest
        || t.offline_signer_key_digest != o.signer_key_digest
        || t.return_recipient_key_digest != o.host_return_key_digest
        || t.return_recipient_key_digest != enrollment.return_recipient_key_digest
        || t.snapshot.source_identity_digest != enrollment.source_identity_digest
        || t.snapshot.source_policy_digest != enrollment.source_policy_digest
        || t.recipient_scope_digest
            != consumed
                .request
                .plan
                .retained
                .selection
                .scope
                .selection
                .original_policy_origin
                .recipient_policy
                .digest()
                .map_err(|_| Error::Authentication)?
        || !consumed
            .request
            .plan
            .enrollment()
            .scope
            .recipient_scope_digests
            .contains(&t.recipient_scope_digest)
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

// One wall sample only restricts existing exact scopes; it never resets their
// original bounds or supplies chain-observation time. The actual controllers
// independently enforce their immutable monotonic deadlines.
fn require_current_scopes(scopes: &[NamedVerifierPolicyScopeV1]) -> Result<()> {
    let now = wall_milliseconds()?;
    for scope in scopes {
        require_scope_time(
            now,
            scope.original_validity_not_before_ms,
            scope.original_validity_expires_ms,
            scope.requested_at_ms,
            scope.disclosure_expires_at_ms,
        )?;
    }
    Ok(())
}
fn require_scope_time(
    now: u64,
    original_start: u64,
    original_end: u64,
    requested: u64,
    disclosure_end: u64,
) -> Result<()> {
    if original_start == 0
        || original_start > requested
        || requested >= disclosure_end
        || disclosure_end > original_end
        || disclosure_end - requested > 120_000
        || now < requested
        || now >= disclosure_end
    {
        return Err(Error::Permission);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_window_is_original_and_never_renewed() {
        assert!(require_scope_time(1000, 900, 2000, 950, 1500).is_ok());
        for now in [0, 949, 1500, 2000, u64::MAX] {
            assert!(require_scope_time(now, 900, 2000, 950, 1500).is_err());
        }
        assert!(require_scope_time(1000, 900, 1200, 950, 1500).is_err());
        assert!(require_scope_time(1000, 900, 200000, 950, 121000).is_err());
    }
}

fn wall_milliseconds() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Permission)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Permission)
}
