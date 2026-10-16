//! Historical linkage only. None of these values authorizes key use or enrollment.
use crate::{account_use::*, *};
use serde::{Deserialize, Serialize};

/// Origin excludes policy_digest because genesis is itself committed by policy.
/// Account/network and owner are bound separately by the genesis and policy.
pub fn account_use_witness_origin_digest(
    disclosure: &WitnessDisclosureDescriptor,
) -> Result<String> {
    disclosure.validate()?;
    digest(
        "wholepact:account-use-witness-origin:v1",
        &(
            &disclosure.endpoint,
            &disclosure.server_name,
            &disclosure.witness_id,
            &disclosure.pinned_server_certificate_digest,
        ),
    )
}

/// Non-deserializable evidence of a permanent exclusion in complete reconciled
/// witness history. It has no fresh-session or financial-admission semantics.
pub struct ReconciledAccountExclusion {
    evidence: AccountExclusionReceipt,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountExclusionReceipt {
    pub genesis_digest: String,
    pub exclusion_digest: String,
    pub witness_origin_digest: String,
    pub committed_head: AuthorityHead,
    pub operation_id: String,
}
impl AccountExclusionReceipt {
    /// Checks archived audit syntax only. Deserialization confers no authenticity.
    pub fn digest(&self) -> Result<String> {
        hash(&self.genesis_digest)?;
        hash(&self.exclusion_digest)?;
        hash(&self.witness_origin_digest)?;
        hash(&self.committed_head.digest)?;
        id(&self.operation_id)?;
        if self.committed_head.sequence == 0 || self.committed_head.sequence > crate::MAX_EVENTS {
            return Err(AuthorityError::InvalidBinding);
        }
        digest("wholepact:account-exclusion-receipt:v1", self)
    }
}
impl ReconciledAccountExclusion {
    pub fn evidence(&self) -> &AccountExclusionReceipt {
        &self.evidence
    }
    pub fn receipt_digest(&self) -> Result<String> {
        self.evidence.digest()
    }
}
/// Caller supplies the ORIGINAL immutable vault-bound witness disclosure. An
/// ordinary JSON descriptor does not prove that ownership; this function only
/// verifies exact equality against authenticated replay and returns audit data.
/// Birth-vault/native integration must enforce the input's origin before use.
pub fn reconcile_account_exclusion(
    history: &ReconciledAuthorityHistory,
    expected_genesis: &AccountUseGenesis,
    original_disclosure: &WitnessDisclosureDescriptor,
    expected_exclusion: &PermanentAccountExclusion,
) -> Result<ReconciledAccountExclusion> {
    history.require_legacy_online_only()?;
    reconcile_account_exclusion_complete(
        history,
        expected_genesis,
        original_disclosure,
        expected_exclusion,
    )
}

/// Complete authenticated-history variant for coordinated typed recovery.
/// Includes offline-bearing replay without projecting it to online permits.
/// This retains only the original permanent-exclusion event acknowledgement;
/// it cannot issue native consent, fresh account admission, budget or key use.
/// Callers still own original vault provenance and live recovery/publication
/// fences. The legacy entry point above deliberately keeps its support gate.
pub fn reconcile_account_exclusion_complete(
    history: &ReconciledAuthorityHistory,
    expected_genesis: &AccountUseGenesis,
    original_disclosure: &WitnessDisclosureDescriptor,
    expected_exclusion: &PermanentAccountExclusion,
) -> Result<ReconciledAccountExclusion> {
    expected_genesis.validate()?;
    expected_exclusion.validate()?;
    original_disclosure.validate()?;
    if &history.disclosure != original_disclosure
        || history.account_policy.account_use_genesis.as_ref() != Some(expected_genesis)
        || history.account_use_history.genesis() != Some(expected_genesis)
        || history.account_use_history.exclusion() != Some(expected_exclusion)
        || expected_exclusion.genesis_digest != expected_genesis.digest()?
        || expected_exclusion.identity != expected_genesis.identity
        || history.snapshot.account_use_checkpoint != history.account_use_history.checkpoint()?
        || original_disclosure.account_id != expected_genesis.identity.account_id
        || original_disclosure.network_profile_id != expected_genesis.identity.network_profile_id
        || original_disclosure.witness_id != expected_genesis.witness_id
        || account_use_witness_origin_digest(original_disclosure)?
            != expected_genesis.witness_origin_digest
        || original_disclosure.policy_digest != history.account_policy.policy_digest()?
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let request = history
        .owner_control_request(&expected_exclusion.operation_id)
        .ok_or(AuthorityError::CorruptHistory)?;
    if !matches!(&request.control, OwnerControl::PermanentlyExcludeAccount { exclusion } if exclusion == expected_exclusion)
        || !history.contains_head(&request.expected_head)
    {
        return Err(AuthorityError::CorruptHistory);
    }
    let sequence = request
        .expected_head
        .sequence
        .checked_add(1)
        .ok_or(AuthorityError::Limit)?;
    let committed_head = AuthorityHead {
        sequence,
        digest: history
            .history_heads
            .get(&sequence)
            .ok_or(AuthorityError::CorruptHistory)?
            .clone(),
    };
    // Bind the original event head, not a later observed head, so ack loss/retry
    // cannot produce a conflicting immutable receipt as unrelated history grows.
    Ok(ReconciledAccountExclusion {
        evidence: AccountExclusionReceipt {
            genesis_digest: expected_genesis.digest()?,
            exclusion_digest: expected_exclusion.digest()?,
            witness_origin_digest: account_use_witness_origin_digest(original_disclosure)?,
            committed_head,
            operation_id: expected_exclusion.operation_id.clone(),
        },
    })
}
