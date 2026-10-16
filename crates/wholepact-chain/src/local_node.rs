//! Named owner-controlled validating-node resolution source. No node enrollment,
//! credentials, deployment, generic nullifier lookup, or implicit trust fallback.
//! The local TLS terminator is explicitly part of the selected trusted source.
mod transport;
use crate::settlement_evidence::{RetainedSettlementObservation, SourceBoundSettlementObservation};
use crate::{
    BlockIdentity, ChainError, ConfirmationPolicy, EncryptedSubmissionJournal,
    ReconciliationReport, SettlementObservationState, SourceTip, SubmissionDescriptor,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Cursor,
    net::SocketAddr,
    time::{Duration, Instant},
};
pub use transport::LocalNodeTls;
use zcash_primitives::transaction::{
    Authorization, Authorized, Transaction, TxVersion,
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};
use zcash_protocol::consensus::BranchId;

pub const ZEBRA_RELEASE: &str = "v7.0.0-rc.0";
pub const ZEBRA_SOURCE_COMMIT: &str = "6d1e414d6f55e4180d0e47baaa934bf97d5b4fec";
const TESTNET_GENESIS: &str = "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38";
const MAX_TRANSACTION_BYTES: usize = 64 * 1024;

/// Public enrollment description, not authority. Only comparison with the live
/// issuer-held copy can bind a permit to an independently enrolled source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalNodeSourceDescriptor {
    pub source_id: String,
    pub endpoint: String,
    pub server_name: String,
    pub pinned_certificate_sha256: String,
    pub client_certificate_sha256: String,
    pub trusted_root_sha256: Vec<String>,
    pub node_release: String,
    pub node_source_commit: String,
    pub network: String,
    pub consensus_branch_id: u32,
    pub activation_height: u64,
    pub confirmation_policy: ConfirmationPolicy,
}

impl LocalNodeSourceDescriptor {
    /// Validate an enrollment description without connecting or accepting trust.
    pub fn validate(&self) -> Result<(), ChainError> {
        let endpoint: SocketAddr = self
            .endpoint
            .parse()
            .map_err(|_| ChainError::InvalidConfiguration)?;
        if !endpoint.ip().is_loopback()
            || endpoint.port() == 0
            || endpoint.to_string() != self.endpoint
            || self.node_release != ZEBRA_RELEASE
            || self.node_source_commit != ZEBRA_SOURCE_COMMIT
            || self.network != "testnet"
            || self.consensus_branch_id != crate::NU7_BRANCH_ID
            || self.activation_height != crate::NU7_ACTIVATION_HEIGHT
            || self.trusted_root_sha256.is_empty()
            || self.trusted_root_sha256.len() > 8
            || self.trusted_root_sha256.windows(2).any(|w| w[0] >= w[1])
            || self.confirmation_policy
                != ConfirmationPolicy::new(
                    self.confirmation_policy.required_confirmations(),
                    10,
                    vec![self.source_id.clone()],
                )?
        {
            return Err(ChainError::InvalidConfiguration);
        }
        rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| ChainError::InvalidConfiguration)?;
        for value in self.trusted_root_sha256.iter().chain([
            &self.pinned_certificate_sha256,
            &self.client_certificate_sha256,
        ]) {
            hash(value)?;
        }
        Ok(())
    }
}

/// Enrollment is trusted native configuration. Its owner accepts that this exact
/// local TLS endpoint serves this pinned node's uncached public-testnet state.
/// Merely instantiating this object performs no I/O or enrollment.
pub struct LocalValidatingNode {
    source_id: String,
    endpoint: SocketAddr,
    tls: LocalNodeTls,
    policy: ConfirmationPolicy,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalResolutionKind {
    ExactTransactionConsumed,
    /// Only this exact pool-specific nullifier establishes a consensus conflict.
    IronwoodInputConflict {
        nullifier: String,
    },
}
/// Untrusted request to inspect one known alternative transaction. It cannot
/// assert canonicality, replace the original, or confer settlement authority.
/// Raw bytes are public transaction ciphertext retained only in private journals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalConflictCandidate {
    pub included_transaction_id: String,
    pub original_transaction_hex: String,
    pub nullifier: String,
}
impl CanonicalConflictCandidate {
    /// Recover only the exact original already retained in this private journal.
    /// This exports an untrusted lookup request, never a live resolution permit.
    pub fn from_retained_original(
        journal: &EncryptedSubmissionJournal,
        operation_id: &str,
        included_transaction_id: String,
        nullifier: String,
    ) -> Result<Self, ChainError> {
        let descriptor = journal
            .retained_submission_descriptor(operation_id)?
            .ok_or(ChainError::MalformedEvidence)?;
        let (intent, _) = journal
            .recover_exact_intent(operation_id)?
            .ok_or(ChainError::MalformedEvidence)?;
        let (inputs, effects) = target_mapping(intent.exact_bytes())?;
        let candidate = Self {
            included_transaction_id,
            original_transaction_hex: hex::encode(intent.exact_bytes()),
            nullifier,
        };
        candidate.validate_original(&descriptor, &effects, &inputs)?;
        Ok(candidate)
    }
    pub fn validate_shape(&self) -> Result<(), ChainError> {
        hash(&self.included_transaction_id)?;
        hash(&self.nullifier)?;
        // Bound the hex envelope below the existing 128 KiB signer IPC ceiling.
        if self.original_transaction_hex.is_empty()
            || self.original_transaction_hex.len() > 48 * 1024 * 2
            || !self.original_transaction_hex.len().is_multiple_of(2)
            || !self
                .original_transaction_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ChainError::ResourceLimit);
        }
        Ok(())
    }
    /// Pure exact-original validation, required BEFORE making any node request.
    /// All expected fields must come from the caller's protected original history.
    pub fn validate_original(
        &self,
        expected: &SubmissionDescriptor,
        effects: &str,
        inputs: &[(u64, String)],
    ) -> Result<(), ChainError> {
        self.validate_shape()?;
        let bytes = hex::decode(&self.original_transaction_hex)
            .map_err(|_| ChainError::MalformedEvidence)?;
        let original = parse_tx(&bytes)?;
        let (actual_inputs, actual_effects) = target_mapping(&bytes)?;
        if expected.network != "testnet"
            || expected.consensus_branch_id != crate::NU7_BRANCH_ID
            || self.included_transaction_id == expected.transaction_id
            || original.txid().to_string() != expected.transaction_id
            || hex::encode(Sha256::digest(&bytes)) != expected.bytes_sha256
            || u32::from(original.expiry_height()) != expected.expiry_height
            || actual_effects != effects
            || inputs.is_empty()
            || inputs.len() > 256
            || inputs.iter().map(|(i, _)| i).collect::<BTreeSet<_>>().len() != inputs.len()
            || inputs.iter().map(|(_, n)| n).collect::<BTreeSet<_>>().len() != inputs.len()
            || inputs.iter().any(|i| !actual_inputs.contains(i))
            || !inputs.iter().any(|(_, n)| n == &self.nullifier)
        {
            return Err(ChainError::MalformedEvidence);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct CanonicalEvidence {
    source: LocalNodeSourceDescriptor,
    target_inputs: Vec<(u64, String)>,
    target_shielded_sighash: String,
    source_id: String,
    source_release: String,
    source_commit: String,
    certificate_sha256: String,
    session_binding_sha256: String,
    target: SubmissionDescriptor,
    included_transaction_id: String,
    included_transaction_hex: String,
    inclusion: BlockIdentity,
    tip: BlockIdentity,
    tip_mined_at: u64,
    observed_at: u64,
    required_confirmations: u32,
    kind: LocalResolutionKind,
}
/// Live opaque qualification. It is not a signature/authorization-to-record
/// mapping. The sink must additionally establish the exact retained authorization
/// provenance before mutating its authority ledger; proposal labels do not suffice.
pub struct QualifiedLocalResolution {
    canonical: CanonicalEvidence,
    journal_identity: String,
    deadline: Instant,
    report: ReconciliationReport,
}
/// Positive authority cannot be serialized, reconstructed from a journal, or
/// refreshed by a caller-provided clock. It expires on a monotonic deadline.
pub struct LocalResolutionPermit {
    source: LocalNodeSourceDescriptor,
    target_inputs: Vec<(u64, String)>,
    target_shielded_sighash: String,
    evidence_id: String,
    journal_identity: String,
    descriptor: SubmissionDescriptor,
    kind: LocalResolutionKind,
    included_transaction_id: String,
    inclusion: BlockIdentity,
    deadline: Instant,
}
/// Live independent node result for a witness's immutable dispatch admission.
/// The witness must atomically retain evidence before resolving its admission;
/// serialized evidence alone never recreates current authority.
pub struct QualifiedNodeAdmission {
    canonical: CanonicalEvidence,
    deadline: Instant,
}
pub type QualifiedAdmissionResolution = QualifiedNodeAdmission;
impl QualifiedNodeAdmission {
    pub fn check_current(&self) -> Result<(), ChainError> {
        if Instant::now() > self.deadline {
            Err(ChainError::StaleChain)
        } else {
            Ok(())
        }
    }
    pub fn check_source(&self, enrolled: &LocalNodeSourceDescriptor) -> Result<(), ChainError> {
        self.check_current()?;
        if &self.canonical.source != enrolled {
            return Err(ChainError::SubmissionNotAuthorized);
        }
        Ok(())
    }
    pub fn source_descriptor(&self) -> &LocalNodeSourceDescriptor {
        &self.canonical.source
    }
    pub fn source_descriptor_digest(&self) -> Result<String, ChainError> {
        descriptor_digest(&self.canonical.source)
    }
    pub fn descriptor(&self) -> &SubmissionDescriptor {
        &self.canonical.target
    }
    pub fn target_inputs(&self) -> &[(u64, String)] {
        &self.canonical.target_inputs
    }
    pub fn target_shielded_sighash(&self) -> &str {
        &self.canonical.target_shielded_sighash
    }
    pub fn kind(&self) -> &LocalResolutionKind {
        &self.canonical.kind
    }
    pub fn included_transaction_id(&self) -> &str {
        &self.canonical.included_transaction_id
    }
    pub fn consumed_nullifiers(&self) -> Vec<String> {
        match &self.canonical.kind {
            LocalResolutionKind::ExactTransactionConsumed => self
                .canonical
                .target_inputs
                .iter()
                .map(|(_, n)| n.clone())
                .collect(),
            LocalResolutionKind::IronwoodInputConflict { nullifier } => vec![nullifier.clone()],
        }
    }
    pub fn inclusion(&self) -> &BlockIdentity {
        &self.canonical.inclusion
    }
    pub fn tip(&self) -> &BlockIdentity {
        &self.canonical.tip
    }
    /// Private journal retention only. This archive is not a permit, public
    /// receipt or log message and contains full public transaction ciphertext.
    pub fn evidence_json(&self) -> Result<String, ChainError> {
        self.check_current()?;
        let encoded =
            serde_json::to_string(&self.canonical).map_err(|_| ChainError::MalformedEvidence)?;
        if encoded.len() > 262144 {
            return Err(ChainError::ResourceLimit);
        }
        Ok(encoded)
    }
    pub fn evidence_digest(&self) -> Result<String, ChainError> {
        Ok(hex::encode(Sha256::digest(
            self.evidence_json()?.as_bytes(),
        )))
    }
    pub fn evidence_id(&self) -> Result<String, ChainError> {
        self.evidence_digest()
    }
}
fn descriptor_digest(source: &LocalNodeSourceDescriptor) -> Result<String, ChainError> {
    let encoded = serde_json::to_vec(source).map_err(|_| ChainError::MalformedEvidence)?;
    Ok(hex::encode(Sha256::digest(encoded)))
}
impl LocalResolutionPermit {
    /// Does not authorize anything by itself. Check the independently enrolled
    /// source and live deadline immediately before each durable sink mutation.
    pub fn target_inputs(&self) -> &[(u64, String)] {
        &self.target_inputs
    }
    pub fn target_shielded_sighash(&self) -> &str {
        &self.target_shielded_sighash
    }
    pub fn check_source(
        &self,
        evidence: &RetainedSettlementObservation,
        enrolled: &LocalNodeSourceDescriptor,
    ) -> Result<(), ChainError> {
        self.check(evidence)?;
        if &self.source != enrolled {
            return Err(ChainError::SubmissionNotAuthorized);
        }
        Ok(())
    }

    pub fn kind(&self) -> &LocalResolutionKind {
        &self.kind
    }
    pub fn included_transaction_id(&self) -> &str {
        &self.included_transaction_id
    }
    pub fn inclusion(&self) -> &BlockIdentity {
        &self.inclusion
    }
    pub fn check(&self, evidence: &RetainedSettlementObservation) -> Result<(), ChainError> {
        if Instant::now() > self.deadline {
            return Err(ChainError::StaleChain);
        }
        if self.evidence_id != evidence.evidence_id()
            || self.journal_identity != evidence.journal_identity()
            || &self.descriptor != evidence.descriptor()
        {
            return Err(ChainError::IdempotencyConflict);
        }
        Ok(())
    }
}
impl QualifiedLocalResolution {
    /// Durable evidence precedes any exposure change. Historical replay retains
    /// audit/reorg lineage but cannot recreate this live permit after a crash.
    pub fn retain(
        self,
        journal: &mut EncryptedSubmissionJournal,
        destinations: &[String],
    ) -> Result<(RetainedSettlementObservation, LocalResolutionPermit), ChainError> {
        if Instant::now() > self.deadline || journal.identity() != self.journal_identity {
            return Err(ChainError::StaleChain);
        }
        let descriptor = self.canonical.target.clone();
        let kind = self.canonical.kind.clone();
        let source = self.canonical.source.clone();
        let included_transaction_id = self.canonical.included_transaction_id.clone();
        let inclusion = self.canonical.inclusion.clone();
        let target_inputs = self.canonical.target_inputs.clone();
        let target_shielded_sighash = self.canonical.target_shielded_sighash.clone();
        let canonical =
            serde_json::to_value(self.canonical).map_err(|_| ChainError::MalformedEvidence)?;
        let observation = SourceBoundSettlementObservation::from_local_node(
            descriptor.clone(),
            self.report,
            canonical,
        );
        let evidence = journal.retain_settlement_observation(observation, destinations)?;
        let permit = LocalResolutionPermit {
            source,
            target_inputs,
            target_shielded_sighash,
            evidence_id: evidence.evidence_id().into(),
            journal_identity: self.journal_identity,
            descriptor,
            kind,
            included_transaction_id,
            inclusion,
            deadline: self.deadline,
        };
        permit.check(&evidence)?;
        Ok((evidence, permit))
    }
}
impl LocalValidatingNode {
    pub fn source_descriptor(&self) -> LocalNodeSourceDescriptor {
        LocalNodeSourceDescriptor {
            source_id: self.source_id.clone(),
            endpoint: self.endpoint.to_string(),
            server_name: self.tls.server_name.clone(),
            pinned_certificate_sha256: self.tls.pin.clone(),
            client_certificate_sha256: self.tls.client_certificate.clone(),
            trusted_root_sha256: self.tls.trusted_roots.clone(),
            node_release: ZEBRA_RELEASE.into(),
            node_source_commit: ZEBRA_SOURCE_COMMIT.into(),
            network: "testnet".into(),
            consensus_branch_id: crate::NU7_BRANCH_ID,
            activation_height: crate::NU7_ACTIVATION_HEIGHT,
            confirmation_policy: self.policy.clone(),
        }
    }

    pub fn new(
        source_id: String,
        endpoint: SocketAddr,
        tls: LocalNodeTls,
        required_confirmations: u32,
    ) -> Result<Self, ChainError> {
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err(ChainError::InvalidConfiguration);
        }
        let policy = ConfirmationPolicy::new(required_confirmations, 10, vec![source_id.clone()])?;
        Ok(Self {
            source_id,
            endpoint,
            tls,
            policy,
        })
    }
    /// Blocking bounded native read; call on the runtime's blocking lane while
    /// holding the exact transaction-linkage disclosure and writer/source lease.
    /// `included_txid=None` checks the retained transaction; a different known
    /// txid requests actual shared-nullifier conflict evidence, not an input scan.
    pub fn qualify(
        &self,
        journal: &EncryptedSubmissionJournal,
        operation_id: &str,
        included_txid: Option<&str>,
    ) -> Result<QualifiedLocalResolution, ChainError> {
        self.qualify_selected(journal, operation_id, included_txid, None)
    }
    /// Uses the already-retained original bytes, never candidate-supplied identity.
    pub fn qualify_conflict(
        &self,
        journal: &EncryptedSubmissionJournal,
        operation_id: &str,
        candidate: &CanonicalConflictCandidate,
        effects: &str,
        inputs: &[(u64, String)],
    ) -> Result<QualifiedLocalResolution, ChainError> {
        let descriptor = journal
            .retained_submission_descriptor(operation_id)?
            .ok_or(ChainError::MalformedEvidence)?;
        candidate.validate_original(&descriptor, effects, inputs)?;
        let (intent, _) = journal
            .recover_exact_intent(operation_id)?
            .ok_or(ChainError::MalformedEvidence)?;
        if hex::encode(intent.exact_bytes()) != candidate.original_transaction_hex {
            return Err(ChainError::MalformedEvidence);
        }
        self.qualify_selected(
            journal,
            operation_id,
            Some(&candidate.included_transaction_id),
            Some(&candidate.nullifier),
        )
    }
    fn qualify_selected(
        &self,
        journal: &EncryptedSubmissionJournal,
        operation_id: &str,
        included_txid: Option<&str>,
        conflict_nullifier: Option<&str>,
    ) -> Result<QualifiedLocalResolution, ChainError> {
        let descriptor = journal
            .retained_submission_descriptor(operation_id)?
            .ok_or(ChainError::MalformedEvidence)?;
        let (intent, _) = journal
            .recover_exact_intent(operation_id)?
            .ok_or(ChainError::MalformedEvidence)?;
        let txid = included_txid
            .unwrap_or(&descriptor.transaction_id)
            .to_owned();
        let (canonical, deadline, valid_until) = self.read_canonical(
            descriptor.clone(),
            &txid,
            Some(intent.exact_bytes()),
            conflict_nullifier,
        )?;
        let kind = canonical.kind.clone();
        let inclusion = canonical.inclusion.clone();
        let tip = canonical.tip.clone();
        let now = canonical.observed_at;
        let prior = journal
            .recover_reconciler(operation_id)?
            .and_then(|r| r.last_report().cloned());
        let consumed = matches!(kind, LocalResolutionKind::ExactTransactionConsumed);
        let previous_inclusion = prior.as_ref().and_then(|r| r.last_inclusion.clone());
        let changed = consumed
            && previous_inclusion
                .as_ref()
                .is_some_and(|old| old != &inclusion);
        let report = ReconciliationReport {
            transaction_id: descriptor.transaction_id.clone(),
            expiry_height: descriptor.expiry_height,
            policy: self.policy.clone(),
            observed_at_unix_seconds: now,
            valid_until_unix_seconds: valid_until,
            state: if consumed {
                SettlementObservationState::ConfirmationPolicyMet {
                    block: inclusion.clone(),
                    confirmations: tip.height - inclusion.height + 1,
                }
            } else {
                SettlementObservationState::NotObserved
            },
            last_inclusion: if consumed {
                Some(inclusion.clone())
            } else {
                previous_inclusion
            },
            confidence_lost: changed
                || (!consumed
                    && prior
                        .as_ref()
                        .is_some_and(|r| r.confidence_lost || r.last_inclusion.is_some())),
            reorganization_observed: changed,
            source_ids: vec![self.source_id.clone()],
            source_tips: vec![SourceTip {
                source_id: self.source_id.clone(),
                tip: tip.clone(),
            }],
            independently_consensus_verified: false,
            clears_authorization_exposure: false,
            permits_replacement: false,
        };
        report.validate()?;
        Ok(QualifiedLocalResolution {
            canonical,
            journal_identity: journal.identity().into(),
            deadline,
            report,
        })
    }
    /// Independently validates the witness's immutable exact dispatch admission.
    /// Caller must obtain expected fields from its protected journal, not JSON.
    pub fn qualify_admission(
        &self,
        expected: &SubmissionDescriptor,
    ) -> Result<QualifiedNodeAdmission, ChainError> {
        let (canonical, deadline, _) =
            self.read_canonical(expected.clone(), &expected.transaction_id, None, None)?;
        Ok(QualifiedNodeAdmission {
            canonical,
            deadline,
        })
    }
    /// Independently reads only after immutable original bytes/effects/own input
    /// bindings agree. A candidate transaction ID alone is never sufficient.
    pub fn qualify_admission_conflict(
        &self,
        expected: &SubmissionDescriptor,
        candidate: &CanonicalConflictCandidate,
        effects: &str,
        inputs: &[(u64, String)],
    ) -> Result<QualifiedNodeAdmission, ChainError> {
        candidate.validate_original(expected, effects, inputs)?;
        let bytes = zeroize::Zeroizing::new(
            hex::decode(&candidate.original_transaction_hex)
                .map_err(|_| ChainError::MalformedEvidence)?,
        );
        let (canonical, deadline, _) = self.read_canonical(
            expected.clone(),
            &candidate.included_transaction_id,
            Some(&bytes),
            Some(&candidate.nullifier),
        )?;
        Ok(QualifiedNodeAdmission {
            canonical,
            deadline,
        })
    }
    pub fn qualify_admitted(
        &self,
        transaction_id: &str,
        bytes_sha256: &str,
        expiry_height: u32,
        inputs: &[(u64, String)],
    ) -> Result<QualifiedAdmissionResolution, ChainError> {
        hash(transaction_id)?;
        hash(bytes_sha256)?;
        if inputs.is_empty()
            || inputs.len() > 330
            || inputs.iter().map(|(i, _)| i).collect::<BTreeSet<_>>().len() != inputs.len()
            || inputs.iter().map(|(_, n)| n).collect::<BTreeSet<_>>().len() != inputs.len()
            || inputs.iter().any(|(i, n)| *i >= 330 || hash(n).is_err())
        {
            return Err(ChainError::MalformedEvidence);
        }
        // These local evidence labels identify only the exact transaction. They
        // are never used to map authority to an application obligation/proposal.
        let id = format!("node-admission-{}", transaction_id);
        let target = SubmissionDescriptor {
            operation_id: id.clone(),
            obligation_id: id.clone(),
            proposal_id: id,
            transaction_id: transaction_id.into(),
            bytes_sha256: bytes_sha256.into(),
            expiry_height,
            network: "testnet".into(),
            consensus_branch_id: crate::NU7_BRANCH_ID,
        };
        let qualified = self.qualify_admission(&target)?;
        if inputs.is_empty()
            || inputs.len() > 330
            || inputs.iter().map(|(i, _)| i).collect::<BTreeSet<_>>().len() != inputs.len()
            || inputs.iter().map(|(_, n)| n).collect::<BTreeSet<_>>().len() != inputs.len()
            || inputs
                .iter()
                .any(|input| !qualified.canonical.target_inputs.contains(input))
        {
            return Err(ChainError::MalformedEvidence);
        }
        Ok(qualified)
    }
    pub fn source_descriptor_digest(&self) -> Result<String, ChainError> {
        descriptor_digest(&self.source_descriptor())
    }
    fn read_canonical(
        &self,
        descriptor: SubmissionDescriptor,
        txid: &str,
        retained: Option<&[u8]>,
        conflict_nullifier: Option<&str>,
    ) -> Result<(CanonicalEvidence, Instant, u64), ChainError> {
        let started = Instant::now();
        let observed_at = crate::now()?;
        hash(&descriptor.transaction_id)?;
        hash(&descriptor.bytes_sha256)?;
        for id in [
            &descriptor.operation_id,
            &descriptor.obligation_id,
            &descriptor.proposal_id,
        ] {
            crate::submission::validate_operation_id(id)?;
        }
        if descriptor.network != "testnet"
            || descriptor.consensus_branch_id != crate::NU7_BRANCH_ID
            || descriptor.expiry_height == 0
        {
            return Err(ChainError::WrongNetwork);
        }
        let txid = txid.to_owned();
        hash(&txid)?;
        let mut session = transport::NodeSession::connect(self.endpoint, &self.tls)?;
        let info = session.call("getinfo", json!([]))?;
        validate_version(&info)?;
        if session.call("getblockhash", json!([0]))?.as_str() != Some(TESTNET_GENESIS) {
            return Err(ChainError::WrongNetwork);
        }
        let before = session.call("getblockchaininfo", json!([]))?;
        let tip = validate_chain(&before)?;
        let tip_block = session.call("getblock", json!([tip.hash, 1]))?;
        let raw = session.call("getrawtransaction", json!([txid, 1]))?;
        let inclusion = BlockIdentity {
            height: number(&raw, "height")?,
            hash: string(&raw, "blockhash")?.into(),
        };
        hash(&inclusion.hash)?;
        let block = session.call("getblock", json!([inclusion.hash, 1]))?;
        let canonical_hash = session.call("getblockhash", json!([inclusion.height]))?;
        let after = session.call("getblockchaininfo", json!([]))?;
        if validate_chain(&after)? != tip || canonical_hash.as_str() != Some(&inclusion.hash) {
            return Err(ChainError::ContradictoryChain);
        }
        let tip_mined_at = number(&tip_block, "time")?;
        let now = crate::now()?;
        if now < observed_at
            || now - observed_at > 30
            || now.saturating_sub(tip_mined_at) > 1200
            || tip_mined_at > now.saturating_add(30)
            || started.elapsed() > Duration::from_secs(30)
        {
            return Err(ChainError::StaleChain);
        }
        verify_membership(
            &tip,
            &tip_block,
            &inclusion,
            &block,
            &raw,
            &txid,
            self.policy.required_confirmations(),
        )?;
        let raw_hex = string(&raw, "hex")?;
        if raw_hex.len() > MAX_TRANSACTION_BYTES * 2 {
            return Err(ChainError::ResourceLimit);
        }
        let bytes = zeroize::Zeroizing::new(
            hex::decode(raw_hex).map_err(|_| ChainError::MalformedEvidence)?,
        );
        let target_bytes = retained.unwrap_or(bytes.as_slice());
        let kind = qualify_bytes_for_nullifier(
            &descriptor,
            target_bytes,
            &txid,
            &bytes,
            conflict_nullifier,
        )?;
        let parsed = parse_tx(target_bytes)?;
        if u32::from(parsed.expiry_height()) != descriptor.expiry_height
            || inclusion.height > u64::from(u32::from(parse_tx(&bytes)?.expiry_height()))
        {
            return Err(ChainError::MalformedEvidence);
        }
        let (target_inputs, target_shielded_sighash) = target_mapping(target_bytes)?;
        let canonical = CanonicalEvidence {
            source: self.source_descriptor(),
            target_inputs,
            target_shielded_sighash,
            source_id: self.source_id.clone(),
            source_release: ZEBRA_RELEASE.into(),
            source_commit: ZEBRA_SOURCE_COMMIT.into(),
            certificate_sha256: session.certificate,
            session_binding_sha256: session.binding,
            target: descriptor,
            included_transaction_id: txid,
            included_transaction_hex: raw_hex.into(),
            inclusion,
            tip,
            tip_mined_at,
            observed_at: now,
            required_confirmations: self.policy.required_confirmations(),
            kind,
        };
        Ok((
            canonical,
            started + Duration::from_secs(30),
            observed_at + 30,
        ))
    }
}
fn hash(value: &str) -> Result<(), ChainError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || value.bytes().all(|b| b == b'0')
    {
        Err(ChainError::MalformedEvidence)
    } else {
        Ok(())
    }
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str, ChainError> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or(ChainError::MalformedEvidence)
}
fn number(v: &Value, key: &str) -> Result<u64, ChainError> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or(ChainError::MalformedEvidence)
}
fn validate_version(v: &Value) -> Result<(), ChainError> {
    if !matches!(string(v, "build")?, "v7.0.0-rc.0" | "7.0.0-rc.0")
        || v.get("testnet").and_then(Value::as_bool) != Some(true)
        || number(v, "protocolversion")? < 170180
        || number(v, "connections")? == 0
    {
        return Err(ChainError::UnsupportedCapability);
    }
    Ok(())
}
fn validate_chain(v: &Value) -> Result<BlockIdentity, ChainError> {
    if string(v, "chain")? != "test" {
        return Err(ChainError::WrongNetwork);
    }
    if v.pointer("/consensus/chaintip").and_then(Value::as_str) != Some("77190ad9")
        || v.pointer("/upgrades/77190ad9/activationheight")
            .and_then(Value::as_u64)
            != Some(crate::NU7_ACTIVATION_HEIGHT)
        || v.pointer("/upgrades/77190ad9/status")
            .and_then(Value::as_str)
            != Some("active")
    {
        return Err(ChainError::WrongBranch);
    }
    let tip = BlockIdentity {
        height: number(v, "blocks")?,
        hash: string(v, "bestblockhash")?.into(),
    };
    hash(&tip.hash)?;
    if tip.height < crate::NU7_ACTIVATION_HEIGHT
        || number(v, "headers")? != tip.height
        || number(v, "estimatedheight")?.abs_diff(tip.height) > 2
    {
        return Err(ChainError::StaleChain);
    }
    Ok(tip)
}
fn verify_membership(
    tip: &BlockIdentity,
    tip_block: &Value,
    inclusion: &BlockIdentity,
    block: &Value,
    raw: &Value,
    txid: &str,
    required: u32,
) -> Result<(), ChainError> {
    if string(tip_block, "hash")? != tip.hash
        || number(tip_block, "height")? != tip.height
        || inclusion.height < crate::NU7_ACTIVATION_HEIGHT
        || inclusion.height > tip.height
        || string(block, "hash")? != inclusion.hash
        || number(block, "height")? != inclusion.height
        || string(raw, "txid")? != txid
    {
        return Err(ChainError::ContradictoryChain);
    }
    let confirmations = tip.height - inclusion.height + 1;
    let txs = block
        .get("tx")
        .and_then(Value::as_array)
        .ok_or(ChainError::MalformedEvidence)?;
    if confirmations < u64::from(required)
        || number(raw, "confirmations")? != confirmations
        || number(block, "confirmations")? != confirmations
        || txs.len() > 1000
        || txs.iter().filter(|v| v.as_str() == Some(txid)).count() != 1
    {
        return Err(ChainError::ContradictoryChain);
    }
    Ok(())
}
fn parse_tx(bytes: &[u8]) -> Result<Transaction, ChainError> {
    if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(ChainError::ResourceLimit);
    }
    let mut cursor = Cursor::new(bytes);
    let tx =
        Transaction::read(&mut cursor, BranchId::Nu7).map_err(|_| ChainError::MalformedEvidence)?;
    if cursor.position() != bytes.len() as u64
        || tx.version() != TxVersion::V6
        || tx.consensus_branch_id() != BranchId::Nu7
        || tx.transparent_bundle().is_some()
        || tx.sprout_bundle().is_some()
        || tx.sapling_bundle().is_some()
        || tx.orchard_bundle().is_some()
        || tx.ironwood_bundle().is_none()
    {
        return Err(ChainError::UnsupportedCapability);
    }
    let mut canonical = zeroize::Zeroizing::new(vec![]);
    tx.write(&mut *canonical)
        .map_err(|_| ChainError::MalformedEvidence)?;
    if canonical.as_slice() != bytes {
        return Err(ChainError::MalformedEvidence);
    }
    Ok(tx)
}
fn target_mapping(bytes: &[u8]) -> Result<(Vec<(u64, String)>, String), ChainError> {
    let tx = parse_tx(bytes)?;
    let bundle = tx
        .ironwood_bundle()
        .ok_or(ChainError::UnsupportedCapability)?;
    if !bundle.flags().spends_enabled() {
        return Err(ChainError::UnsupportedCapability);
    }
    let inputs: Vec<_> = bundle
        .actions()
        .iter()
        .enumerate()
        .map(|(index, action)| (index as u64, hex::encode(action.nullifier().to_bytes())))
        .collect();
    if inputs.is_empty()
        || inputs.len() > 330
        || inputs
            .iter()
            .map(|(_, nf)| nf)
            .collect::<BTreeSet<_>>()
            .len()
            != inputs.len()
    {
        return Err(ChainError::MalformedEvidence);
    }
    // Same maintained authorizing-context conversion as protocol retained
    // transaction verification. Transparent input/output bundles are forbidden.
    struct ShieldedEffects;
    impl Authorization for ShieldedEffects {
        type TransparentAuth = zcash_transparent::bundle::EffectsOnly;
        type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
        type OrchardAuth = <Authorized as Authorization>::OrchardAuth;
    }
    let effects = (*tx)
        .clone()
        .map_bundles::<ShieldedEffects>(|_| None, |s| s, |o| o);
    let sighash = signature_hash(
        &effects,
        &SignableInput::Shielded,
        &effects.digest(TxIdDigester),
    );
    Ok((inputs, hex::encode(sighash.as_ref())))
}

#[cfg(test)]
fn qualify_bytes(
    target: &SubmissionDescriptor,
    retained: &[u8],
    included_txid: &str,
    included: &[u8],
) -> Result<LocalResolutionKind, ChainError> {
    qualify_bytes_for_nullifier(target, retained, included_txid, included, None)
}
fn qualify_bytes_for_nullifier(
    target: &SubmissionDescriptor,
    retained: &[u8],
    included_txid: &str,
    included: &[u8],
    expected_nullifier: Option<&str>,
) -> Result<LocalResolutionKind, ChainError> {
    let original = parse_tx(retained)?;
    let canonical = parse_tx(included)?;
    if original.txid().to_string() != target.transaction_id
        || hex::encode(Sha256::digest(retained)) != target.bytes_sha256
        || canonical.txid().to_string() != included_txid
    {
        return Err(ChainError::MalformedEvidence);
    }
    if included_txid == target.transaction_id {
        // Exact bytes also bind authorizing data, not merely ZIP-244 effects ID.
        if retained != included {
            return Err(ChainError::MalformedEvidence);
        }
        return Ok(LocalResolutionKind::ExactTransactionConsumed);
    }
    if !original
        .ironwood_bundle()
        .ok_or(ChainError::MalformedEvidence)?
        .flags()
        .spends_enabled()
        || !canonical
            .ironwood_bundle()
            .ok_or(ChainError::MalformedEvidence)?
            .flags()
            .spends_enabled()
    {
        return Err(ChainError::UnsupportedCapability);
    }
    let nullifiers: BTreeSet<_> = original
        .ironwood_bundle()
        .ok_or(ChainError::MalformedEvidence)?
        .actions()
        .iter()
        .map(|a| a.nullifier().to_bytes())
        .collect();
    let conflict = canonical
        .ironwood_bundle()
        .ok_or(ChainError::MalformedEvidence)?
        .actions()
        .iter()
        .map(|a| a.nullifier().to_bytes())
        .find(|n| {
            nullifiers.contains(n)
                && expected_nullifier.is_none_or(|expected| hex::encode(n) == expected)
        })
        .ok_or(ChainError::UnsupportedCapability)?;
    Ok(LocalResolutionKind::IronwoodInputConflict {
        nullifier: hex::encode(conflict),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Private synthetic lifecycle fixture only; never a node observation or payment.
    fn synthetic_admission() -> QualifiedNodeAdmission {
        let source = LocalNodeSourceDescriptor {
            source_id: "synthetic-node".into(),
            endpoint: "127.0.0.1:12345".into(),
            server_name: "localhost".into(),
            pinned_certificate_sha256: "11".repeat(32),
            client_certificate_sha256: "22".repeat(32),
            trusted_root_sha256: vec!["33".repeat(32)],
            node_release: ZEBRA_RELEASE.into(),
            node_source_commit: ZEBRA_SOURCE_COMMIT.into(),
            network: "testnet".into(),
            consensus_branch_id: crate::NU7_BRANCH_ID,
            activation_height: crate::NU7_ACTIVATION_HEIGHT,
            confirmation_policy: ConfirmationPolicy::new(10, 10, vec!["synthetic-node".into()])
                .unwrap(),
        };
        QualifiedNodeAdmission {
            deadline: Instant::now() + Duration::from_secs(30),
            canonical: CanonicalEvidence {
                source: source.clone(),
                target_inputs: vec![(0, "44".repeat(32))],
                target_shielded_sighash: "55".repeat(32),
                source_id: source.source_id,
                source_release: ZEBRA_RELEASE.into(),
                source_commit: ZEBRA_SOURCE_COMMIT.into(),
                certificate_sha256: source.pinned_certificate_sha256,
                session_binding_sha256: "66".repeat(32),
                target: SubmissionDescriptor {
                    operation_id: "synthetic-operation".into(),
                    obligation_id: "synthetic-obligation".into(),
                    proposal_id: "synthetic-proposal".into(),
                    transaction_id: "77".repeat(32),
                    bytes_sha256: "88".repeat(32),
                    expiry_height: 4_500_030,
                    network: "testnet".into(),
                    consensus_branch_id: crate::NU7_BRANCH_ID,
                },
                included_transaction_id: "77".repeat(32),
                included_transaction_hex: "synthetic-not-a-transaction".into(),
                inclusion: BlockIdentity {
                    height: 4_500_000,
                    hash: "99".repeat(32),
                },
                tip: BlockIdentity {
                    height: 4_500_020,
                    hash: "aa".repeat(32),
                },
                tip_mined_at: 100,
                observed_at: 100,
                required_confirmations: 10,
                kind: LocalResolutionKind::ExactTransactionConsumed,
            },
        }
    }
    #[test]
    fn admission_matches_exact_enrollment_and_archive_digest() {
        let admission = synthetic_admission();
        let enrolled = admission.source_descriptor().clone();
        assert!(admission.check_source(&enrolled).is_ok());
        for changed in 0..5 {
            let mut other = enrolled.clone();
            match changed {
                0 => other.endpoint = "127.0.0.1:12346".into(),
                1 => other.pinned_certificate_sha256 = "cc".repeat(32),
                2 => other.client_certificate_sha256 = "dd".repeat(32),
                3 => other.node_source_commit = "ee".repeat(20),
                _ => {
                    other.confirmation_policy =
                        ConfirmationPolicy::new(1, 10, vec!["synthetic-node".into()]).unwrap()
                }
            }
            assert_eq!(
                admission.check_source(&other),
                Err(ChainError::SubmissionNotAuthorized)
            );
            assert_ne!(
                descriptor_digest(&other).unwrap(),
                admission.source_descriptor_digest().unwrap()
            );
        }
        let encoded = admission.evidence_json().unwrap();
        assert_eq!(
            admission.evidence_id().unwrap(),
            hex::encode(Sha256::digest(encoded.as_bytes()))
        );
        let archive: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(archive["target_shielded_sighash"], "55".repeat(32));
        assert_eq!(admission.target_inputs(), &[(0, "44".repeat(32))]);
    }
    #[test]
    fn expired_admission_cannot_supply_fresh_archive_or_authority() {
        let mut admission = synthetic_admission();
        let enrolled = admission.source_descriptor().clone();
        admission.deadline = Instant::now() - Duration::from_secs(1);
        assert_eq!(admission.check_current(), Err(ChainError::StaleChain));
        assert_eq!(
            admission.check_source(&enrolled),
            Err(ChainError::StaleChain)
        );
        assert!(admission.evidence_json().is_err());
        assert!(admission.evidence_id().is_err());
    }
    fn chain() -> Value {
        json!({"chain":"test","blocks":4_500_020,"headers":4_500_020,
            "estimatedheight":4_500_020,"bestblockhash":"11".repeat(32),
            "consensus":{"chaintip":"77190ad9"},"upgrades":{"77190ad9":{"activationheight":4_465_026,"status":"active"}}})
    }
    #[test]
    fn pinned_network_and_activation_are_required() {
        let value = chain();
        assert!(validate_chain(&value).is_ok());
        for (field, value) in [
            ("chain", json!("main")),
            ("blocks", json!(4_400_000)),
            ("headers", json!(4_500_019)),
            ("estimatedheight", json!(4_500_100)),
        ] {
            let mut wrong = chain();
            wrong[field] = value;
            assert!(validate_chain(&wrong).is_err());
        }
        let mut wrong = chain();
        wrong["upgrades"]["77190ad9"]["activationheight"] = json!(1);
        assert!(validate_chain(&wrong).is_err());
        let valid =
            json!({"build":"v7.0.0-rc.0","testnet":true,"protocolversion":170180,"connections":2});
        assert!(validate_version(&valid).is_ok());
        let mut wrong = valid;
        wrong["build"] = json!("v7.0.0-rc.1");
        assert!(validate_version(&wrong).is_err());
    }
    #[test]
    fn membership_checks_canonical_block_exact_tx_and_depth() {
        let tip = BlockIdentity {
            height: 4_500_020,
            hash: "11".repeat(32),
        };
        let inclusion = BlockIdentity {
            height: 4_500_000,
            hash: "22".repeat(32),
        };
        let txid = "33".repeat(32);
        let tip_block = json!({"hash":tip.hash,"height":tip.height});
        let block =
            json!({"hash":inclusion.hash,"height":inclusion.height,"confirmations":21,"tx":[txid]});
        let raw = json!({"txid":txid,"confirmations":21});
        assert!(verify_membership(&tip, &tip_block, &inclusion, &block, &raw, &txid, 10).is_ok());
        assert!(verify_membership(&tip, &tip_block, &inclusion, &block, &raw, &txid, 22).is_err());
        let mut duplicate = block.clone();
        duplicate["tx"] = json!([txid, txid]);
        assert!(
            verify_membership(&tip, &tip_block, &inclusion, &duplicate, &raw, &txid, 10).is_err()
        );
        let mut stale = raw.clone();
        stale["confirmations"] = json!(20);
        assert!(
            verify_membership(&tip, &tip_block, &inclusion, &block, &stale, &txid, 10).is_err()
        );
        let mut other = block;
        other["hash"] = json!("44".repeat(32));
        assert!(verify_membership(&tip, &tip_block, &inclusion, &other, &raw, &txid, 10).is_err());
    }
    #[test]
    fn no_empty_or_unrecognized_transaction_resolution() {
        assert!(parse_tx(&[]).is_err());
        assert!(parse_tx(b"synthetic-not-a-payment").is_err());
        assert!(hash(&"00".repeat(32)).is_err());
        assert!(hash(&"AA".repeat(32)).is_err());
    }
}

#[cfg(test)]
mod conflict_tests {
    use super::*;
    // Codec-only fixture: invalid zero proof/signatures, no key use or node I/O.
    fn fixture() -> (Vec<u8>, SubmissionDescriptor, Vec<(u64, String)>, String) {
        // Synthetic codec-only bytes with invalid zero proofs/signatures/ciphertexts.
        // Curve point: first ak vector in orchard 0.16.0 keys.rs, sourced from
        // https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/orchard/key_components.py
        let bytes =
            hex::decode(include_str!("fixtures/synthetic-conflict-original.hex").trim()).unwrap();
        let tx = parse_tx(&bytes).unwrap();
        let (inputs, effects) = target_mapping(&bytes).unwrap();
        let descriptor = SubmissionDescriptor {
            operation_id: "synthetic-original-operation".into(),
            obligation_id: "synthetic-obligation".into(),
            proposal_id: "synthetic-original-proposal".into(),
            transaction_id: tx.txid().to_string(),
            bytes_sha256: hex::encode(Sha256::digest(&bytes)),
            expiry_height: u32::from(tx.expiry_height()),
            network: "testnet".into(),
            consensus_branch_id: crate::NU7_BRANCH_ID,
        };
        (bytes, descriptor, inputs, effects)
    }
    #[test]
    fn conflict_requires_exact_original_bytes_effects_and_selected_own_input() {
        let (bytes, descriptor, inputs, effects) = fixture();
        let mut alternative = bytes.clone();
        alternative[12] = 1; // Synthetic lock_time, preserves the exact nullifier.
        let alternative_id = parse_tx(&alternative).unwrap().txid().to_string();
        let candidate = CanonicalConflictCandidate {
            included_transaction_id: alternative_id.clone(),
            original_transaction_hex: hex::encode(&bytes),
            nullifier: inputs[0].1.clone(),
        };
        candidate
            .validate_original(&descriptor, &effects, &inputs)
            .unwrap();
        assert_eq!(
            qualify_bytes_for_nullifier(
                &descriptor,
                &bytes,
                &alternative_id,
                &alternative,
                Some(&candidate.nullifier)
            )
            .unwrap(),
            LocalResolutionKind::IronwoodInputConflict {
                nullifier: candidate.nullifier.clone()
            }
        );
        assert_eq!(
            qualify_bytes(&descriptor, &bytes, &descriptor.transaction_id, &bytes).unwrap(),
            LocalResolutionKind::ExactTransactionConsumed
        );
        for mode in 0..9 {
            let mut c = candidate.clone();
            let mut d = descriptor.clone();
            let mut e = effects.clone();
            let mut i = inputs.clone();
            match mode {
                0 => d.transaction_id = "11".repeat(32),
                1 => d.bytes_sha256 = "22".repeat(32),
                2 => d.expiry_height += 1,
                3 => e = "33".repeat(32),
                4 => i[0].0 += 1,
                5 => c.nullifier = "44".repeat(32),
                6 => c.included_transaction_id = descriptor.transaction_id.clone(),
                7 => c.original_transaction_hex.push_str("00"),
                _ => {
                    let last = c.original_transaction_hex.len() - 2;
                    c.original_transaction_hex.replace_range(last.., "01");
                }
            }
            assert!(
                c.validate_original(&d, &e, &i).is_err(),
                "mismatch mode {mode}"
            );
        }
    }
    #[test]
    fn conflict_candidate_never_qualifies_unrelated_input_or_disabled_spend_pool() {
        let (bytes, descriptor, inputs, _) = fixture();
        let mut unrelated = bytes.clone();
        unrelated[58] = 2; // First action nullifier, after 26-byte prefix + cv.
        let id = parse_tx(&unrelated).unwrap().txid().to_string();
        assert!(
            qualify_bytes_for_nullifier(&descriptor, &bytes, &id, &unrelated, Some(&inputs[0].1))
                .is_err()
        );
        let mut outputs_only = bytes.clone();
        outputs_only[26 + 820] = 2;
        let id = parse_tx(&outputs_only).unwrap().txid().to_string();
        assert!(
            qualify_bytes_for_nullifier(
                &descriptor,
                &bytes,
                &id,
                &outputs_only,
                Some(&inputs[0].1)
            )
            .is_err()
        );
    }
    #[test]
    fn conflict_candidate_cannot_smuggle_authority_flags_or_unbounded_raw_bytes() {
        let (bytes, _, inputs, _) = fixture();
        let candidate = CanonicalConflictCandidate {
            included_transaction_id: "11".repeat(32),
            original_transaction_hex: hex::encode(bytes),
            nullifier: inputs[0].1.clone(),
        };
        for field in [
            "verified",
            "expired",
            "canonical",
            "source",
            "approval",
            "replaces_original",
        ] {
            let mut value = serde_json::to_value(&candidate).unwrap();
            value[field] = true.into();
            assert!(serde_json::from_value::<CanonicalConflictCandidate>(value).is_err());
        }
        let mut oversized = candidate;
        oversized.original_transaction_hex = "01".repeat(48 * 1024 + 1);
        assert!(oversized.validate_shape().is_err());
    }
}
