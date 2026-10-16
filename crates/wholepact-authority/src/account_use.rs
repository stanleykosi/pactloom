//! Staged deterministic provenance fold. No native issuer or capability here.
//! Intended authority module; current production graph does not include it.
use crate::{AuthorityError, Result, digest, hash, id};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountUseIdentity {
    pub account_id: String,
    pub full_viewing_key_digest: String,
    pub network_profile_id: String,
    pub derivation_domain: String,
}
impl AccountUseIdentity {
    pub fn validate(&self) -> Result<()> {
        hash(&self.account_id)?;
        hash(&self.full_viewing_key_digest)?;
        id(&self.network_profile_id)?;
        if self.derivation_domain != "dedicated-testnet-legacy-zip32-v1" {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn overlaps(&self, other: &Self) -> bool {
        self.account_id == other.account_id
            || self.full_viewing_key_digest == other.full_viewing_key_digest
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountUseGenesis {
    pub version: u16,
    pub identity: AccountUseIdentity,
    pub witness_id: String,
    pub witness_origin_digest: String,
    pub owner_certificate_digest: String,
    pub native_birth_digest: String,
}
impl AccountUseGenesis {
    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        id(&self.witness_id)?;
        hash(&self.witness_origin_digest)?;
        hash(&self.owner_certificate_digest)?;
        hash(&self.native_birth_digest)?;
        if self.version != 1 {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:account-use-genesis:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermanentAccountExclusion {
    pub version: u16,
    pub identity: AccountUseIdentity,
    pub genesis_digest: String,
    pub operation_id: String,
    pub native_review_digest: String,
    pub reason: ExclusionReason,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    RetirementRequested,
}
impl PermanentAccountExclusion {
    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        hash(&self.genesis_digest)?;
        id(&self.operation_id)?;
        hash(&self.native_review_digest)?;
        if self.version != 1 {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:permanent-account-exclusion:v1", self)
    }
}
/// A historical state projection, not a live admission. Private fields prevent
/// arbitrary deserialization into the folded state. Every native action still
/// needs actual current authenticated owner history and session checks.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountUseCheckpoint {
    pub genesis_digest: String,
    pub history_digest: String,
    pub permanent_exclusion_digest: Option<String>,
}
#[derive(Clone)]
pub struct AccountUseHistory {
    genesis: Option<AccountUseGenesis>,
    exclusion: Option<PermanentAccountExclusion>,
}
impl AccountUseHistory {
    pub(crate) fn unknown_legacy() -> Self {
        Self {
            genesis: None,
            exclusion: None,
        }
    }
    /// Invoke only during a NEW policy genesis, never as a legacy migration,
    /// recovered scope update or replacement witness enrollment.
    pub(crate) fn from_policy_genesis(
        genesis: AccountUseGenesis,
        account: &str,
        network: &str,
        witness: &str,
        owner: &str,
    ) -> Result<Self> {
        genesis.validate()?;
        if genesis.identity.account_id != account
            || genesis.identity.network_profile_id != network
            || genesis.witness_id != witness
            || genesis.owner_certificate_digest != owner
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(Self {
            genesis: Some(genesis),
            exclusion: None,
        })
    }
    /// Owner-authenticated ledger dispatch must call this inside the SAME durable
    /// event transaction. It never refunds any reservation or consumed capacity.
    pub(crate) fn exclude(&mut self, event: PermanentAccountExclusion) -> Result<()> {
        event.validate()?;
        let genesis = self
            .genesis
            .as_ref()
            .ok_or(AuthorityError::RecoveryRequired)?;
        if event.genesis_digest != genesis.digest()? || event.identity != genesis.identity {
            return Err(AuthorityError::InvalidBinding);
        }
        if let Some(old) = &self.exclusion {
            return if old == &event {
                Ok(())
            } else {
                Err(AuthorityError::Conflict)
            };
        }
        self.exclusion = Some(event);
        Ok(())
    }
    pub fn checkpoint(&self) -> Result<Option<AccountUseCheckpoint>> {
        self.genesis
            .as_ref()
            .map(|g| {
                Ok(AccountUseCheckpoint {
                    genesis_digest: g.digest()?,
                    history_digest: self
                        .checkpoint_digest()?
                        .ok_or(AuthorityError::RecoveryRequired)?,
                    permanent_exclusion_digest: self
                        .exclusion
                        .as_ref()
                        .map(|e| e.digest())
                        .transpose()?,
                })
            })
            .transpose()
    }
    /// Legacy unknown does not alter ordinary legacy policy. Successor enrollment
    /// separately requires complete birth/history, never this compatibility gate.
    pub(crate) fn require_not_permanently_excluded(&self) -> Result<()> {
        if self.exclusion.is_some() {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(())
    }
    pub fn genesis(&self) -> Option<&AccountUseGenesis> {
        self.genesis.as_ref()
    }
    pub fn exclusion(&self) -> Option<&PermanentAccountExclusion> {
        self.exclusion.as_ref()
    }
    pub fn checkpoint_digest(&self) -> Result<Option<String>> {
        self.genesis
            .as_ref()
            .map(|g| digest("wholepact:account-use-history:v1", &(g, &self.exclusion)))
            .transpose()
    }
    /// Necessary historical condition only; cannot mint a permission.
    pub fn review_successor_eligibility(&self, candidate: &AccountUseIdentity) -> Result<()> {
        candidate.validate()?;
        let genesis = self
            .genesis
            .as_ref()
            .ok_or(AuthorityError::RecoveryRequired)?;
        if &genesis.identity != candidate {
            return Err(AuthorityError::InvalidBinding);
        }
        if self.exclusion.is_some() {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(())
    }
    /// Joining recovered and surviving histories never removes exclusion. A
    /// missing/unknown branch cannot establish completeness or be dropped.
    pub fn union_history(&self, other: &Self) -> Result<Self> {
        let a = self
            .genesis
            .as_ref()
            .ok_or(AuthorityError::RecoveryRequired)?;
        let b = other
            .genesis
            .as_ref()
            .ok_or(AuthorityError::RecoveryRequired)?;
        if a != b {
            return Err(AuthorityError::Conflict);
        }
        let mut result = self.clone();
        if let Some(event) = &other.exclusion {
            result.exclude(event.clone())?;
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn genesis() -> AccountUseGenesis {
        AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: "11".repeat(32),
                full_viewing_key_digest: "22".repeat(32),
                network_profile_id: "synthetic".into(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: "witness".into(),
            witness_origin_digest: "77".repeat(32),
            owner_certificate_digest: "33".repeat(32),
            native_birth_digest: "44".repeat(32),
        }
    }
    fn history() -> AccountUseHistory {
        let g = genesis();
        AccountUseHistory::from_policy_genesis(
            g.clone(),
            &g.identity.account_id,
            &g.identity.network_profile_id,
            &g.witness_id,
            &g.owner_certificate_digest,
        )
        .unwrap()
    }
    fn event() -> PermanentAccountExclusion {
        let g = genesis();
        PermanentAccountExclusion {
            version: 1,
            identity: g.identity.clone(),
            genesis_digest: g.digest().unwrap(),
            operation_id: "retire".into(),
            native_review_digest: "55".repeat(32),
            reason: ExclusionReason::RetirementRequested,
        }
    }
    #[test]
    fn legacy_unknown_is_not_empty() {
        let h = AccountUseHistory::unknown_legacy();
        assert!(h.review_successor_eligibility(&genesis().identity).is_err());
        assert!(history().union_history(&h).is_err());
    }
    #[test]
    fn post_backup_retirement_survives_union_and_exact_retry() {
        let old = history();
        let mut current = history();
        current.exclude(event()).unwrap();
        current.exclude(event()).unwrap();
        let union = old.union_history(&current).unwrap();
        assert!(union.exclusion().is_some());
        assert!(
            union
                .review_successor_eligibility(&genesis().identity)
                .is_err()
        );
        assert!(current.union_history(&old).unwrap().exclusion().is_some());
    }
    #[test]
    fn conflicting_witness_origin_never_replaces_history() {
        let a = history();
        let mut g = genesis();
        g.witness_id = "other".into();
        let b = AccountUseHistory::from_policy_genesis(
            g.clone(),
            &g.identity.account_id,
            &g.identity.network_profile_id,
            &g.witness_id,
            &g.owner_certificate_digest,
        )
        .unwrap();
        assert!(a.union_history(&b).is_err());
    }
    #[test]
    fn alias_fingerprint_and_retirement_rebinding_reject() {
        let mut id = genesis().identity;
        let old = id.clone();
        id.account_id = "66".repeat(32);
        assert!(id.overlaps(&old));
        let mut e = event();
        e.identity = id;
        assert!(history().exclude(e).is_err());
    }
}
