//! Source-only witness locator foundation. Every exported value in
//! this file is audit data. No DTO can enroll an origin, create a journal, clear
//! quarantine, recover a native owner, or establish that a key was newly born.
//! The connected owner source accepts only genuine native decisions. Attended
//! operation and financial activation remain unqualified.
use crate::account_use::{AccountUseIdentity, PermanentAccountExclusion};
use crate::account_use_link::account_use_witness_origin_digest;
use crate::pending_birth::{PendingBirthCommitRecord, PendingBirthRequest};
use crate::{AuthorityError, Result, digest, encode, hash, id};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
#[path = "witness_namespace_owner.rs"]
mod owner;
#[path = "witness_locator_storage.rs"]
mod storage;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) use owner::*;

const MAX_INTENTS: usize = 1024;
const MAX_EXCLUSIONS: usize = 2048;
const MAX_PAYLOAD_BYTES: usize = 262_144;
const MAX_TOTAL_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const MAX_NAMESPACE_BYTES: usize = 16_384;

/// Historical filesystem stamp, not an open handle or a directory lock. Only
/// the future concrete native namespace owner may capture/compare the live path.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryIdentity {
    pub(crate) platform: String,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) owner_uid: u32,
}
impl DirectoryIdentity {
    fn validate(&self) -> Result<()> {
        // No cross-platform fallback to path text alone.
        if self.platform != "linux-unix-v1" || self.inode == 0 {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}

/// Immutable original namespace installation. These bytes must match BOTH the
/// authenticated locator and the protected canonical origin-to-root registry.
/// Missing either side is unknown. There is deliberately no installer/reset API.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WitnessNamespaceBinding {
    pub(crate) version: u16,
    pub(crate) namespace_instance_id: String,
    pub(crate) initial_inventory_digest: String,
    pub(crate) witness_id: String,
    pub(crate) witness_origin_digest: String,
    pub(crate) pinned_server_certificate_digest: String,
    pub(crate) owner_certificate_digest: String,
    pub(crate) network_profile_id: String,
    pub(crate) canonical_private_root: String,
    pub(crate) root_identity: DirectoryIdentity,
    pub(crate) journals_identity: DirectoryIdentity,
}
impl WitnessNamespaceBinding {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        for v in [
            &self.namespace_instance_id,
            &self.initial_inventory_digest,
            &self.witness_origin_digest,
            &self.pinned_server_certificate_digest,
            &self.owner_certificate_digest,
        ] {
            hash(v)?;
        }
        id(&self.witness_id)?;
        id(&self.network_profile_id)?;
        self.root_identity.validate()?;
        self.journals_identity.validate()?;
        let p = &self.canonical_private_root;
        if !p.starts_with('/')
            || p.len() < 2
            || p.len() > 4096
            || p.ends_with('/')
            || p.bytes().any(|b| b == 0 || b.is_ascii_control())
            || p[1..]
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || self.root_identity.owner_uid != self.journals_identity.owner_uid
            || self.root_identity == self.journals_identity
            || encode(self)?.len() > MAX_NAMESPACE_BYTES
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:witness-locator-namespace:v1", self)
    }
    fn require_request(&self, request: &PendingBirthRequest) -> Result<()> {
        self.validate()?;
        request.validate()?;
        if self.witness_id != request.policy.witness_id
            || self.witness_origin_digest != account_use_witness_origin_digest(&request.disclosure)?
            || self.pinned_server_certificate_digest
                != request.disclosure.pinned_server_certificate_digest
            || self.owner_certificate_digest != request.policy.owner_certificate_digest
            || self.network_profile_id != request.policy.network_profile_id
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}

/// There is exactly one supported child for an actual account in this namespace.
/// An arbitrary selected file never becomes a fresh enrollment destination.
fn derived_child(account_id: &str) -> Result<String> {
    hash(account_id)?;
    Ok(format!("journals/{account_id}.wp"))
}
fn target_digest(namespace: &WitnessNamespaceBinding, account_id: &str) -> Result<String> {
    digest(
        "wholepact:witness-locator-child-target:v1",
        &(namespace.digest()?, derived_child(account_id)?),
    )
}

/// Immutable preparation content. Fresh native review on retry must reapprove
/// these exact bytes, but cannot rewrite the original request or its deadline.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreationIntent {
    pub(crate) version: u16,
    pub(crate) namespace_digest: String,
    pub(crate) request: PendingBirthRequest,
    pub(crate) request_digest: String,
    pub(crate) derived_child: String,
    pub(crate) local_target_digest: String,
    pub(crate) local_owner_review_digest: String,
    pub(crate) owner_approval_evidence_digest: String,
}
impl CreationIntent {
    fn validate(&self, namespace: &WitnessNamespaceBinding) -> Result<()> {
        namespace.require_request(&self.request)?;
        for v in [
            &self.namespace_digest,
            &self.request_digest,
            &self.local_target_digest,
            &self.local_owner_review_digest,
            &self.owner_approval_evidence_digest,
        ] {
            hash(v)?;
        }
        if self.version != 1
            || self.namespace_digest != namespace.digest()?
            || self.request_digest != self.request.digest()?
            || self.derived_child != derived_child(&self.identity().account_id)?
            || self.local_target_digest != target_digest(namespace, &self.identity().account_id)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        if encode(self)?.len() > MAX_PAYLOAD_BYTES {
            return Err(AuthorityError::Limit);
        }
        Ok(())
    }
    // Only called after PendingBirthRequest::validate has established genesis.
    fn identity(&self) -> &AccountUseIdentity {
        &self
            .request
            .policy
            .account_use_genesis
            .as_ref()
            .expect("validated pending request contains genesis")
            .identity
    }
    fn digest(&self, namespace: &WitnessNamespaceBinding) -> Result<String> {
        self.validate(namespace)?;
        digest("wholepact:witness-locator-creation-intent:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedIntent {
    intent: CreationIntent,
    prepared_at_ms: u64,
}
impl PreparedIntent {
    fn validate(&self, namespace: &WitnessNamespaceBinding) -> Result<()> {
        self.intent.validate(namespace)?;
        self.intent
            .request
            .require_initial_commit_time(self.prepared_at_ms)?;
        if self.prepared_at_ms > i64::MAX as u64 {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}

/// Captured journal file identity. No statement of authenticity follows from
/// deserializing it; completion additionally needs a concrete authenticated read.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalIdentity {
    device: u64,
    inode: u64,
    owner_uid: u32,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionEvidence {
    version: u16,
    intent_digest: String,
    journal_identity: JournalIdentity,
    journal_genesis_commitment: String,
    birth_commit: PendingBirthCommitRecord,
}
impl CompletionEvidence {
    fn validate(
        &self,
        namespace: &WitnessNamespaceBinding,
        prepared: &PreparedIntent,
    ) -> Result<()> {
        prepared.validate(namespace)?;
        self.birth_commit.validate()?;
        let i = &prepared.intent;
        hash(&self.intent_digest)?;
        hash(&self.journal_genesis_commitment)?;
        // Commit to COMPLETE policy and birth record, including original limits.
        let genesis_commitment = digest(
            "wholepact:witness-locator-journal-genesis:v1",
            &(&i.request.policy, &self.birth_commit),
        )?;
        if self.version != 1
            || self.intent_digest != i.digest(namespace)?
            || self.birth_commit.request != i.request
            || self.birth_commit.request_digest != i.request_digest
            || self.birth_commit.local_target_digest != i.local_target_digest
            || self.birth_commit.local_owner_review_digest != i.local_owner_review_digest
            || self.birth_commit.owner_approval_evidence_digest != i.owner_approval_evidence_digest
            || self.birth_commit.committed_at_ms < prepared.prepared_at_ms
            || self.journal_genesis_commitment != genesis_commitment
            || self.journal_identity.inode == 0
            || self.journal_identity.owner_uid != namespace.root_identity.owner_uid
        {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionRecord {
    evidence: CompletionEvidence,
    completed_at_ms: u64,
}
impl CompletionRecord {
    fn validate(
        &self,
        namespace: &WitnessNamespaceBinding,
        prepared: &PreparedIntent,
    ) -> Result<()> {
        self.evidence.validate(namespace, prepared)?;
        if self.completed_at_ms < self.evidence.birth_commit.committed_at_ms
            || self.completed_at_ms > i64::MAX as u64
        {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedExclusion {
    version: u16,
    namespace_digest: String,
    source_history_digest: String,
    exclusion: PermanentAccountExclusion,
}
impl RetainedExclusion {
    fn validate(&self, namespace: &WitnessNamespaceBinding) -> Result<()> {
        self.exclusion.validate()?;
        hash(&self.source_history_digest)?;
        if self.version != 1 || self.namespace_digest != namespace.digest()? {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(())
    }
    fn digest(&self, namespace: &WitnessNamespaceBinding) -> Result<String> {
        self.validate(namespace)?;
        digest("wholepact:witness-locator-retained-exclusion:v1", self)
    }
}

/// Data-only complete fold. Its presence, checksums and candidate classifications
/// never prove canonical registry continuity, native consent or current liveness.
struct LocatorHistory {
    namespace: WitnessNamespaceBinding,
    prepared: BTreeMap<String, PreparedIntent>,
    completed: BTreeMap<String, CompletionRecord>,
    exclusions: Vec<RetainedExclusion>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum CandidateAudit {
    UnusedInRecordedNamespace,
    ReservedExactIncomplete,
    CompletedOriginalAudit { permanently_excluded: bool },
}
impl LocatorHistory {
    fn from_records(
        namespace: WitnessNamespaceBinding,
        prepared: Vec<PreparedIntent>,
        completed: Vec<CompletionRecord>,
        exclusions: Vec<RetainedExclusion>,
    ) -> Result<Self> {
        namespace.validate()?;
        if prepared.len() > MAX_INTENTS
            || completed.len() > MAX_INTENTS
            || exclusions.len() > MAX_EXCLUSIONS
        {
            return Err(AuthorityError::Limit);
        }
        let mut records = BTreeMap::new();
        let mut accounts = BTreeSet::new();
        let mut fvks = BTreeSet::new();
        let mut operations = BTreeSet::new();
        let mut generations = BTreeSet::new();
        let mut requests = BTreeSet::new();
        let mut children = BTreeSet::new();
        let mut bytes = encode(&namespace)?.len();
        for p in prepared {
            p.validate(&namespace)?;
            add_payload_size(&mut bytes, &p)?;
            let i = &p.intent;
            if !accounts.insert(i.identity().account_id.clone())
                || !fvks.insert(i.identity().full_viewing_key_digest.clone())
                || !operations.insert(i.request.operation_id.clone())
                || !generations.insert(i.request.generation_instance_id.clone())
                || !requests.insert(i.request_digest.clone())
                || !children.insert(i.derived_child.clone())
                || records.insert(i.digest(&namespace)?, p).is_some()
            {
                return Err(AuthorityError::CorruptHistory);
            }
        }
        let mut completions = BTreeMap::new();
        for c in completed {
            let p = records
                .get(&c.evidence.intent_digest)
                .ok_or(AuthorityError::CorruptHistory)?;
            c.validate(&namespace, p)?;
            add_payload_size(&mut bytes, &c)?;
            if completions
                .insert(c.evidence.intent_digest.clone(), c)
                .is_some()
            {
                return Err(AuthorityError::CorruptHistory);
            }
        }
        let mut exclusion_digests = BTreeSet::new();
        for e in &exclusions {
            e.validate(&namespace)?;
            add_payload_size(&mut bytes, e)?;
            if !exclusion_digests.insert(e.digest(&namespace)?) {
                return Err(AuthorityError::CorruptHistory);
            }
        }
        Ok(Self {
            namespace,
            prepared: records,
            completed: completions,
            exclusions,
        })
    }
    fn classify(&self, candidate: &CreationIntent) -> Result<CandidateAudit> {
        candidate.validate(&self.namespace)?;
        let excluded = self
            .exclusions
            .iter()
            .any(|e| e.exclusion.identity.overlaps(candidate.identity()));
        let mut exact = None;
        for p in self.prepared.values() {
            let i = &p.intent;
            if i.identity().overlaps(candidate.identity())
                || i.request.operation_id == candidate.request.operation_id
                || i.request.generation_instance_id == candidate.request.generation_instance_id
                || i.request_digest == candidate.request_digest
                || i.derived_child == candidate.derived_child
            {
                if i != candidate {
                    return Err(AuthorityError::Conflict);
                }
                exact = Some(i.digest(&self.namespace)?);
            }
        }
        if let Some(key) = exact {
            if self.completed.contains_key(&key) {
                // Existing immutable audit remains readable after expiry/retirement.
                return Ok(CandidateAudit::CompletedOriginalAudit {
                    permanently_excluded: excluded,
                });
            }
            if excluded {
                return Err(AuthorityError::PolicyDenied);
            }
            return Ok(CandidateAudit::ReservedExactIncomplete);
        }
        if excluded {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(CandidateAudit::UnusedInRecordedNamespace)
    }
}
fn add_payload_size<T: Serialize>(total: &mut usize, value: &T) -> Result<()> {
    let size = encode(value)?.len();
    if size > MAX_PAYLOAD_BYTES {
        return Err(AuthorityError::Limit);
    }
    *total = total.checked_add(size).ok_or(AuthorityError::Limit)?;
    if *total > MAX_TOTAL_PAYLOAD_BYTES {
        return Err(AuthorityError::Limit);
    }
    Ok(())
}
