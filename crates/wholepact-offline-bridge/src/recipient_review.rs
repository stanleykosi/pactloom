//! Staged owner-pinned recipient composition. There is intentionally no setup,
//! expectation, or minimum-disclosure qualification factory in this source slice.
//! Current broad-PCZT profile cannot pass the missing minimum-role qualification.
use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use wholepact_authority::offline::{
    OfflineAuthorizationTerms, OfflineEnrollmentPolicy, OfflineReservationIntent,
    OfflineSnapshotCommitment,
};
use wholepact_authority::{AuthorityHead, InputReservation, OfflineAdmissionExportPlan};
use wholepact_core::{Proposal, ProposalInput, parse_typed_json};
use wholepact_protocol::{
    construction::{InputActionMapping, OutputActionMapping},
    proving::{ProvingLimits, verify_proved_candidate},
    review::{OutputPurpose, ReviewPolicy},
    review_manifest::{policy_fingerprint, verify_manifest_policy},
};
use wholepact_transport::*;
use zeroize::Zeroizing;

mod receipt;
pub use receipt::*;
mod reinspection;

const META: &str = "offline-review-bindings-v1";
const PCZT: &str = "offline-review-pczt-v1";
const PROPOSAL: &str = "offline-review-proposal-v1";
const SNAPSHOT: &str = "offline-review-snapshot-v1";
const PROFILE: &str = "ironwood-testnet-nu7-minimal-review-v1";

/// No available constructor. An upstream redactor exists, but no minimum-role
/// transformation has passed proof/economic/privacy qualification in Wholepact.
/// A new public boolean, DTO or success string must never replace this boundary.
struct MinimalReviewQualification;

/// Owner-established protected state, never deserialized from an incoming file.
/// Establishment must authenticate witness certificate/key, source identity/key,
/// signer account/FVK and return key in a separately approved native setup flow.
/// That setup flow does not exist; this type deliberately has no factory.
/// ```compile_fail
/// use wholepact_offline_bridge::OwnerEstablishedOfflineSetup;
/// let _ = serde_json::from_str::<OwnerEstablishedOfflineSetup>("{}");
/// ```
pub struct OwnerEstablishedOfflineSetup {
    policy: OfflineEnrollmentPolicy,
    inbox_identity: InboxDatabaseIdentity,
    witness_key: TransportPublicKey,
    source_key: TransportPublicKey,
    signer_key: TransportPublicKey,
    return_key: TransportPublicKey,
    witness_account_policy_digest: String,
    own_fvk_digest: String,
    owner_setup_digest: String,
    qualification: MinimalReviewQualification,
}

/// Independent local originals only. An imported policy or FVK cannot fill this.
/// The future setup adapter must authenticate *all* policy account associations;
/// the current strict verifier needs peer FVKs held locally before import.
pub struct RetainedOfflineReviewInputs {
    terms: OfflineAuthorizationTerms,
    proposal: Proposal,
    policy: ReviewPolicy,
    input_actions: Vec<InputActionMapping>,
    output_actions: Vec<OutputActionMapping>,
    maximum_actions: usize,
}

impl RetainedOfflineReviewInputs {
    pub fn terms(&self) -> &OfflineAuthorizationTerms {
        &self.terms
    }
}

/// Exact original reservation continuation retained locally after native intent.
/// The controller may supply assertions, but only the future authenticated
/// original-operation protocol can construct this object; no DTO conversion.
pub struct RetainedOfflineReservation {
    intent: OfflineReservationIntent,
    operation_id: String,
    request_digest: String,
    plan: OfflineAdmissionExportPlan,
    expected_committed_head: AuthorityHead,
    admission_expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewBindings {
    schema_version: u16,
    disclosure_profile: String,
    owner_setup_digest: String,
    proposal_digest: String,
    manifest_digest: String,
    review_policy_digest: String,
    artifact_digest: String,
    effects_digest: String,
    review_binding: String,
}

/// Exact source-authenticated observation, not current consensus or unspentness.
/// Only selected transaction inputs appear. No unrelated history or account total.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotObservationV1 {
    schema_version: u16,
    source_id: String,
    source_identity_digest: String,
    source_policy_digest: String,
    observed_at_ms: u64,
    tip_height: u32,
    tip_hash: String,
    anchor_height: u32,
    anchor_hash: String,
    anchor_root: String,
    selected_inputs: Vec<InputReservation>,
}

fn hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    hex::encode(h.finalize())
}
fn canonical<T: Serialize + serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(TransportError::ResourceLimit);
    }
    let value: T = parse_typed_json(bytes).map_err(|_| TransportError::Malformed)?;
    if serde_json::to_vec(&value).map_err(|_| TransportError::Malformed)? != bytes {
        return Err(TransportError::Malformed);
    }
    Ok(value)
}
fn package_digest(fields: &[DisclosureField]) -> Result<String> {
    if fields.len() != 4
        || fields.iter().map(|f| f.name()).collect::<Vec<_>>() != [META, PCZT, PROPOSAL, SNAPSHOT]
    {
        return Err(TransportError::WrongContext);
    }
    let mut h = Sha256::new();
    h.update(b"wholepact:offline-role-package:v1\0");
    let mut total = 0usize;
    for f in fields {
        total = total
            .checked_add(f.bytes().len())
            .ok_or(TransportError::ResourceLimit)?;
        if total > MAX_PAYLOAD_BYTES {
            return Err(TransportError::ResourceLimit);
        }
        h.update((f.name().len() as u64).to_le_bytes());
        h.update(f.name().as_bytes());
        h.update((f.bytes().len() as u64).to_le_bytes());
        h.update(f.bytes());
    }
    Ok(hex::encode(h.finalize()))
}

fn check_setup(
    setup: &OwnerEstablishedOfflineSetup,
    expected: &RetainedOfflineReviewInputs,
) -> Result<()> {
    let _qualification = &setup.qualification;
    setup
        .policy
        .validate()
        .map_err(|_| TransportError::Malformed)?;
    expected
        .terms
        .validate()
        .map_err(|_| TransportError::Malformed)?;
    let p = &setup.policy;
    let t = &expected.terms;
    if setup.witness_key.fingerprint() != p.witness_transport_key_digest
        || setup.signer_key.fingerprint() != p.offline_signer_key_digest
        || setup.return_key.fingerprint() != p.return_recipient_key_digest
        || t.account_id != p.account_id
        || t.network_profile_id != p.network_profile_id
        || t.enrollment_ref != p.enrollment_ref
        || t.offline_policy_digest != p.policy_digest().map_err(|_| TransportError::Malformed)?
        || t.offline_signer_key_digest != p.offline_signer_key_digest
        || t.return_recipient_key_digest != p.return_recipient_key_digest
        || t.snapshot.source_identity_digest != p.source_identity_digest
        || t.snapshot.source_policy_digest != p.source_policy_digest
        || t.semantics != p.semantics
    {
        return Err(TransportError::Authentication);
    }
    let owner = expected
        .policy
        .participants
        .iter()
        .find(|o| o.account_id == t.account_id)
        .ok_or(TransportError::Authentication)?;
    if hash(b"wholepact:offline-owner-fvk:v1\0", &owner.fvk.to_bytes()) != setup.own_fvk_digest
        || hash(
            b"wholepact:dedicated-testnet-account:legacy-zip32:v1\0",
            &owner.fvk.to_bytes(),
        ) != t.account_id
    {
        return Err(TransportError::Authentication);
    }
    Ok(())
}

fn review_context(
    setup: &OwnerEstablishedOfflineSetup,
    t: &OfflineAuthorizationTerms,
) -> MessageContext {
    MessageContext {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        sender_id: format!("offline-review:{}", setup.source_key.fingerprint()),
        recipient_id: format!("offline-review:{}", setup.signer_key.fingerprint()),
        // This carries evidence only. Dedicated direction and exact field layout
        // prevent a generic ProvedProposal from satisfying this recipient import.
        artifact_kind: ArtifactKind::ProvedProposal,
    }
}

/// Opaque independent inspection. It cannot become final consent or reserve/key-use
/// permission. Native intent and final review must be separate new local decisions.
pub struct OfflineReviewInspection {
    terms: OfflineAuthorizationTerms,
    proposal: Proposal,
    policy: ReviewPolicy,
    input_actions: Vec<InputActionMapping>,
    output_actions: Vec<OutputActionMapping>,
    pczt: Zeroizing<Vec<u8>>,
    maximum_actions: usize,
    display: Zeroizing<String>,
    source_envelope_digest: String,
    source_content_digest: String,
    receipt: AuthenticatedOfflineReviewReceipt,
    imported: Instant,
    transport_window_remaining: Duration,
}
impl OfflineReviewInspection {
    pub fn receipt(&self) -> &AuthenticatedOfflineReviewReceipt {
        &self.receipt
    }
    pub fn terms(&self) -> &OfflineAuthorizationTerms {
        &self.terms
    }
    pub fn package_digest(&self) -> &str {
        &self.terms.review_package_digest
    }
    pub fn snapshot(&self) -> &OfflineSnapshotCommitment {
        &self.terms.snapshot
    }
    pub fn source_identity_digest(&self) -> &str {
        &self.terms.snapshot.source_identity_digest
    }
    pub fn source_envelope_digest(&self) -> &str {
        &self.source_envelope_digest
    }
    pub fn source_content_digest(&self) -> &str {
        &self.source_content_digest
    }
    pub fn display(&self) -> &str {
        &self.display
    }
    pub fn recheck(&self) -> Result<()> {
        // A process-local age bound never upgrades the source timestamp to a
        // trusted clock. There is no deserialization/restart continuation here.
        if self.imported.elapsed() >= self.transport_window_remaining
            || self.imported.elapsed() > Duration::from_secs(120)
        {
            return Err(TransportError::InvalidTime);
        }
        verify_exact(
            &self.terms,
            &self.proposal,
            &self.policy,
            &self.input_actions,
            &self.output_actions,
            &self.pczt,
            self.maximum_actions,
        )?;
        if self.imported.elapsed() >= self.transport_window_remaining
            || self.imported.elapsed() > Duration::from_secs(120)
        {
            return Err(TransportError::InvalidTime);
        }
        Ok(())
    }
}

fn verify_exact(
    t: &OfflineAuthorizationTerms,
    proposal: &Proposal,
    policy: &ReviewPolicy,
    inputs: &[InputActionMapping],
    outputs: &[OutputActionMapping],
    bytes: &[u8],
    maximum_actions: usize,
) -> Result<String> {
    if proposal.proposal_digest() != t.proposal_digest
        || proposal.manifest_digest() != t.manifest_digest
        || proposal.input().proposal_id != t.proposal_id
        || proposal.manifest().agreement.network_profile_id != t.network_profile_id
        || proposal.manifest().agreement.agreement_id != t.agreement_id
        || proposal.manifest().agreement.obligation_id != t.obligation_id
        || u64::from(proposal.manifest().agreement.revision) != t.proposal_revision
        || t.consensus_branch_id != 0x77190ad9
        || hex::encode(Sha256::digest(bytes)) != t.artifact_digest
        || hex::encode(policy.anchor) != t.snapshot.anchor_root
    {
        return Err(TransportError::WrongContext);
    }
    verify_manifest_policy(proposal, policy, inputs, outputs)
        .map_err(|_| TransportError::WrongContext)?;
    let proved = verify_proved_candidate(
        bytes,
        policy,
        &t.review_binding,
        ProvingLimits { maximum_actions },
    )
    .map_err(|_| TransportError::Authentication)?;
    let _proved_copy = Zeroizing::new(proved.pczt_bytes);
    let review = proved.economic_review;
    let owner = policy
        .participants
        .iter()
        .position(|p| p.account_id == t.account_id)
        .ok_or(TransportError::WrongContext)?;
    if review.review_binding() != t.review_binding
        || review.shielded_sighash() != t.effects_digest
        || review.fee_zatoshis() != t.transaction_fee_zatoshis
        || policy.expiry_height != t.transaction_expiry_height
        || policy.participants[owner].fee_share_zatoshis != t.fee_share_zatoshis
        || policy.participants[owner].maximum_net_debit_zatoshis != t.maximum_debit_zatoshis
    {
        return Err(TransportError::WrongContext);
    }
    let mut own_inputs = policy
        .inputs
        .iter()
        .filter(|i| i.participant_index == owner)
        .map(|i| {
            let mapping = inputs
                .iter()
                .find(|m| m.action_index == i.action_index)
                .ok_or(TransportError::WrongContext)?;
            Ok(InputReservation {
                input_id: mapping.input_id.clone(),
                nullifier: hex::encode(i.nullifier),
                value_zatoshis: i.value_zatoshis,
                action_index: u64::try_from(i.action_index)
                    .map_err(|_| TransportError::ResourceLimit)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    own_inputs.sort_by_key(|i| i.action_index);
    if own_inputs != t.inputs {
        return Err(TransportError::WrongContext);
    }
    let mut display = format!(
        "OFFLINE EXACT TRANSACTION INSPECTION; NO SPENDING CONSENT\nAccount: {}\nNetwork: {}\nBranch: {:08x}\nProposal: {} revision {}\nManifest: {}\nEffects: {}\nOwn verified net debit: {} zatoshis\nMaximum debit: {} zatoshis\nOwn fee share: {} zatoshis\nTransaction fee: {} zatoshis\nExpiry height: {}\n",
        t.account_id,
        t.network_profile_id,
        t.consensus_branch_id,
        t.proposal_id,
        t.proposal_revision,
        t.manifest_digest,
        t.effects_digest,
        review.net_debits_zatoshis()[owner],
        t.maximum_debit_zatoshis,
        t.fee_share_zatoshis,
        t.transaction_fee_zatoshis,
        t.transaction_expiry_height
    );
    for o in &policy.outputs {
        let role = match o.purpose {
            OutputPurpose::Recipient => "Recipient".to_owned(),
            OutputPurpose::Return { participant_index } => format!(
                "Verified return to {}",
                policy.participants[participant_index].account_id
            ),
        };
        display.push_str(&format!(
            "{role}: {} zatoshis; address {}; memo bytes {}\n",
            o.value_zatoshis,
            wholepact_protocol::review::encode_testnet_receiver(&o.receiver),
            hex::encode(o.memo)
        ));
    }
    display.push_str(&format!("Source: {}; identity {}; policy {}\nObserved at: {} ms since Unix epoch (source assertion)\nTip: {} / {}\nAnchor: {} / {}; root {}\nChain-context age: unknown unless separately established by a trusted local clock.\nThis verifies snapshot provenance and exact transaction data, not current tip, unspentness, mempool, reorganization, remote revocation or globally unique key use.\n",
        t.snapshot.source_id, t.snapshot.source_identity_digest, t.snapshot.source_policy_digest,
        t.snapshot.observed_at_ms, t.snapshot.tip_height, t.snapshot.tip_hash,
        t.snapshot.anchor_height, t.snapshot.anchor_hash, t.snapshot.anchor_root));
    // Untrusted labels and manifest prose must never become terminal/UI controls.
    Ok(display
        .chars()
        .flat_map(|c| {
            if c == '\n' || c == ' ' || c.is_ascii_graphic() {
                c.to_string().chars().collect::<Vec<_>>()
            } else {
                c.escape_default().collect()
            }
        })
        .collect())
}

fn check_snapshot(
    snapshot: &SnapshotObservationV1,
    t: &OfflineAuthorizationTerms,
    raw: &[u8],
) -> Result<()> {
    let s = &t.snapshot;
    if snapshot.schema_version != 1
        || snapshot.source_id != s.source_id
        || snapshot.source_identity_digest != s.source_identity_digest
        || snapshot.source_policy_digest != s.source_policy_digest
        || snapshot.observed_at_ms != s.observed_at_ms
        || snapshot.tip_height != s.tip_height
        || snapshot.tip_hash != s.tip_hash
        || snapshot.anchor_height != s.anchor_height
        || snapshot.anchor_hash != s.anchor_hash
        || snapshot.anchor_root != s.anchor_root
        || snapshot.selected_inputs != t.inputs
        || hash(b"wholepact:offline-snapshot-observation:v1\0", raw) != s.snapshot_digest
    {
        return Err(TransportError::WrongContext);
    }
    Ok(())
}

fn inspect_fields(
    fields: &[DisclosureField],
    setup: &OwnerEstablishedOfflineSetup,
    expected: &RetainedOfflineReviewInputs,
) -> Result<String> {
    check_setup(setup, expected)?;
    let t = &expected.terms;
    if package_digest(fields)? != t.review_package_digest {
        return Err(TransportError::WrongContext);
    }
    let b: ReviewBindings = canonical(fields[0].bytes())?;
    let proposal: ProposalInput = canonical(fields[2].bytes())?;
    let snapshot: SnapshotObservationV1 = canonical(fields[3].bytes())?;
    if b.schema_version != 1
        || b.disclosure_profile != PROFILE
        || b.owner_setup_digest != setup.owner_setup_digest
        || b.proposal_digest != t.proposal_digest
        || b.manifest_digest != t.manifest_digest
        || b.review_policy_digest != policy_fingerprint(&expected.policy)
        || b.artifact_digest != t.artifact_digest
        || b.effects_digest != t.effects_digest
        || b.review_binding != t.review_binding
        || proposal != *expected.proposal.input()
    {
        return Err(TransportError::WrongContext);
    }
    check_snapshot(&snapshot, t, fields[3].bytes())?;
    validate_minimal_role_artifact(fields[1].bytes(), &expected.policy)?;
    let proposal = Proposal::validate(proposal).map_err(|_| TransportError::Malformed)?;
    verify_exact(
        t,
        &proposal,
        &expected.policy,
        &expected.input_actions,
        &expected.output_actions,
        fields[1].bytes(),
        expected.maximum_actions,
    )
}

/// Concrete HPKE/proof composition, unusable until protected setup and the role
/// redactor qualification can create their constructor-free prerequisites.
pub fn import_offline_review_package(
    envelope: &EncryptedEnvelope,
    signer_secret: &TransportSecret,
    setup: &OwnerEstablishedOfflineSetup,
    expected: &RetainedOfflineReviewInputs,
    now: &Timestamp,
    inbox: &mut SqliteReplayLedger,
) -> Result<OfflineReviewInspection> {
    import_offline_review_package_recording(
        envelope,
        signer_secret,
        setup,
        expected,
        now,
        inbox,
        |_| Ok(()),
    )
}

/// Receipt callback runs only after exact HPKE/layout/proof/economic validation,
/// before inbox acceptance. The callback cannot create or modify this evidence.
/// It is evidence persistence only, never final native spending consent.
pub fn import_offline_review_package_recording(
    envelope: &EncryptedEnvelope,
    signer_secret: &TransportSecret,
    setup: &OwnerEstablishedOfflineSetup,
    expected: &RetainedOfflineReviewInputs,
    now: &Timestamp,
    inbox: &mut SqliteReplayLedger,
    retain_authenticated: impl FnOnce(&AuthenticatedOfflineReviewReceipt) -> Result<()>,
) -> Result<OfflineReviewInspection> {
    let imported = Instant::now();
    check_setup(setup, expected)?;
    if inbox.protection() != MailboxProtection::Encrypted
        || inbox.database_identity()? != setup.inbox_identity
        || signer_secret.public_key()? != setup.signer_key
    {
        return Err(TransportError::Authentication);
    }
    let mut display = None;
    let artifact = open_envelope_checked(
        envelope,
        signer_secret,
        &setup.source_key,
        &review_context(setup, &expected.terms),
        now,
        inbox,
        |a| {
            display = Some(inspect_fields(a.fields(), setup, expected)?);
            retain_authenticated(&receipt::from_artifact(a, setup, expected)?)
        },
    )?;
    if inbox.database_identity()? != setup.inbox_identity {
        return Err(TransportError::Authentication);
    }
    let remaining = artifact
        .preview()
        .order
        .expires_at
        .unix_seconds()
        .checked_sub(now.unix_seconds())
        .filter(|t| *t > 0)
        .ok_or(TransportError::InvalidTime)?;
    Ok(OfflineReviewInspection {
        terms: expected.terms.clone(),
        proposal: expected.proposal.clone(),
        policy: expected.policy.clone(),
        input_actions: expected.input_actions.clone(),
        output_actions: expected.output_actions.clone(),
        pczt: Zeroizing::new(artifact.fields()[1].bytes().to_vec()),
        maximum_actions: expected.maximum_actions,
        display: Zeroizing::new(display.ok_or(TransportError::Malformed)?),
        source_envelope_digest: artifact.envelope_digest().into(),
        source_content_digest: artifact.content_digest().into(),
        receipt: receipt::from_artifact(&artifact, setup, expected)?,
        imported,
        transport_window_remaining: Duration::from_secs(remaining as u64),
    })
}

/// No interpretation of a raw admission DTO or caller-created witness success flag.
pub struct OfflineWitnessAdmissionEvidence {
    intent: OfflineReservationIntent,
    receipt: OfflineMinimalAdmissionReceipt,
    admission_digest: String,
    imported: Instant,
    remaining: Duration,
}
impl OfflineWitnessAdmissionEvidence {
    pub fn intent(&self) -> &OfflineReservationIntent {
        &self.intent
    }
    pub fn terms(&self) -> &OfflineAuthorizationTerms {
        &self.intent.terms
    }
    pub fn package_digest(&self) -> &str {
        &self.intent.terms.review_package_digest
    }
    pub fn snapshot(&self) -> &OfflineSnapshotCommitment {
        &self.intent.terms.snapshot
    }
    pub fn statement(&self) -> &OfflineMinimalAdmission {
        self.receipt.statement()
    }
    pub fn intent_digest(&self) -> &str {
        &self.receipt.statement().intent_digest
    }
    pub fn admission_digest(&self) -> &str {
        &self.admission_digest
    }
    pub fn witness_id(&self) -> &str {
        &self.receipt.statement().witness_id
    }
    pub fn committed_head(&self) -> &AuthorityHead {
        &self.receipt.statement().committed_head
    }
    pub fn envelope_digest(&self) -> &str {
        self.receipt.envelope_digest()
    }
    pub fn recheck(&self) -> Result<()> {
        if self.imported.elapsed() >= self.remaining
            || self.imported.elapsed() > Duration::from_secs(120)
        {
            return Err(TransportError::InvalidTime);
        }
        self.intent
            .validate()
            .map_err(|_| TransportError::Malformed)?;
        let s = self.receipt.statement();
        if s.intent_digest
            != self
                .intent
                .intent_digest()
                .map_err(|_| TransportError::Malformed)?
            || s.terms_digest
                != self
                    .intent
                    .terms
                    .terms_digest()
                    .map_err(|_| TransportError::Malformed)?
            || s.review_package_digest != self.intent.terms.review_package_digest
            || s.statement_digest()? != self.admission_digest
        {
            return Err(TransportError::WrongContext);
        }
        Ok(())
    }
}

pub fn import_offline_witness_admission(
    envelope: &EncryptedEnvelope,
    signer_secret: &TransportSecret,
    setup: &OwnerEstablishedOfflineSetup,
    review: &OfflineReviewInspection,
    original: &RetainedOfflineReservation,
    now: &Timestamp,
    inbox: &mut SqliteReplayLedger,
) -> Result<OfflineWitnessAdmissionEvidence> {
    let imported = Instant::now();
    review.recheck()?;
    if inbox.database_identity()? != setup.inbox_identity {
        return Err(TransportError::Authentication);
    }
    if original.intent.terms != review.terms || signer_secret.public_key()? != setup.signer_key {
        return Err(TransportError::WrongContext);
    }
    let expected = OfflineMinimalAdmissionExpected {
        intent: &original.intent,
        offline_policy: &setup.policy,
        witness_account_policy_digest: &setup.witness_account_policy_digest,
        original_operation_id: &original.operation_id,
        original_request_digest: &original.request_digest,
        original_export_plan: &original.plan,
        expected_committed_head: &original.expected_committed_head,
        admission_expires_at_ms: original.admission_expires_at_ms,
    };
    let receipt = open_offline_minimal_admission(
        envelope,
        signer_secret,
        &setup.witness_key,
        &expected,
        now,
        inbox,
    )?;
    let admission_digest = receipt.statement().statement_digest()?;
    let now_ms = u64::try_from(now.unix_seconds())
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .ok_or(TransportError::InvalidTime)?;
    let transport_end_ms = u64::try_from(original.plan.expires_at_unix_seconds)
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .ok_or(TransportError::InvalidTime)?;
    let remaining_ms = original
        .admission_expires_at_ms
        .min(transport_end_ms)
        .checked_sub(now_ms)
        .filter(|v| *v > 0)
        .ok_or(TransportError::InvalidTime)?;
    let evidence = OfflineWitnessAdmissionEvidence {
        intent: original.intent.clone(),
        receipt,
        admission_digest,
        imported,
        remaining: Duration::from_millis(remaining_ms),
    };
    evidence.recheck()?;
    Ok(evidence)
}

/// There is no pass-through based on the imported profile label. This must be
/// replaced only by a version-pinned, qualification-backed canonical role-layout
/// verifier, including canaries and preserved proof/economic checks. In particular
/// current real-input FVKs, derivations, bsk and unused metadata must not leak.
fn require_qualified_minimal_profile() -> Result<()> {
    Err(TransportError::AuthorityUnavailable)
}
fn validate_minimal_role_artifact(_bytes: &[u8], _policy: &ReviewPolicy) -> Result<()> {
    require_qualified_minimal_profile()
}

/// Exact preview and durable encrypted export are composed, but the missing
/// role-layout qualification above keeps both preparation and import unavailable.
/// This is a disclosure adapter only; the preview digest is not evidence that a
/// person consented. Protected native disclosure approval must supply that digest.
pub struct PreparedOfflineReviewPackage {
    prepared: PreparedExport,
}
impl PreparedOfflineReviewPackage {
    pub fn preview(&self) -> &DisclosurePreview {
        self.prepared.preview()
    }
    pub fn fields(&self) -> &[DisclosureField] {
        self.prepared.fields()
    }
    pub fn enqueue(
        self,
        source_secret: &TransportSecret,
        approved_preview_digest: &str,
        now: &Timestamp,
        outbox: &mut SqliteOutbox,
    ) -> Result<OutboxArtifact> {
        if outbox.protection() != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        outbox.enqueue(self.prepared, source_secret, approved_preview_digest, now)
    }
}
pub fn prepare_offline_review_package(
    fields: Vec<DisclosureField>,
    setup: &OwnerEstablishedOfflineSetup,
    expected: &RetainedOfflineReviewInputs,
    order: MessageOrder,
    purpose: String,
    persistence_warning: String,
    now: &Timestamp,
) -> Result<PreparedOfflineReviewPackage> {
    inspect_fields(&fields, setup, expected)?;
    let prepared = prepare_export(
        ExportRequest {
            context: review_context(setup, &expected.terms),
            order,
            purpose,
            persistence_warning,
        },
        fields,
        &setup.source_key,
        &setup.signer_key,
        now,
    )?;
    Ok(PreparedOfflineReviewPackage { prepared })
}

/// Honest capability query: neither a profile string nor a public DTO enables it.
pub fn minimal_offline_review_unavailability() -> &'static str {
    "No qualified recipient-minimal PCZT redactor or owner-authenticated recipient setup exists; the current verifier requires broad selected-note evidence and independently established participant viewing authority."
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extra_missing_or_reordered_role_fields_reject_without_proof_or_crypto() {
        let fields = [META, PCZT, PROPOSAL, SNAPSHOT]
            .into_iter()
            .map(|n| DisclosureField::new(n, vec![1]).unwrap())
            .collect::<Vec<_>>();
        assert!(package_digest(&fields).is_ok());
        assert!(package_digest(&fields[..3]).is_err());
        let mut swapped = fields;
        swapped.swap(0, 1);
        assert!(package_digest(&swapped).is_err());
    }
    #[test]
    fn package_digest_commits_every_exact_byte() {
        let fields = |value| {
            [META, PCZT, PROPOSAL, SNAPSHOT]
                .into_iter()
                .map(|n| DisclosureField::new(n, vec![value]).unwrap())
                .collect::<Vec<_>>()
        };
        assert_ne!(
            package_digest(&fields(1)).unwrap(),
            package_digest(&fields(2)).unwrap()
        );
    }
    #[test]
    fn imported_trust_or_history_cannot_be_a_snapshot_field() {
        for bytes in [
            br#"{"verified":true}"#.as_slice(),
            br#"{"writer_session_id":"canary"}"#,
            br#"{"account_history":["canary"]}"#,
            br#"{"schema_version":1,"schema_version":1}"#,
        ] {
            assert!(canonical::<SnapshotObservationV1>(bytes).is_err());
        }
    }
    #[test]
    fn no_minimal_profile_is_advertised() {
        assert!(minimal_offline_review_unavailability().contains("No qualified"));
        assert_eq!(
            require_qualified_minimal_profile(),
            Err(TransportError::AuthorityUnavailable)
        );
    }
}

mod named_verifier;
pub use named_verifier::*;
