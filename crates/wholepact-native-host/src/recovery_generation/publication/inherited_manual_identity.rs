//! Complete inherited identity coverage from authenticated generation capsules.
//! This is historical restriction evidence, never a signer or financial admission.
use super::complete_origins::CheckedContinuityRows;
use super::*;
use std::collections::BTreeMap;
use wholepact_core::manual_enrollment::ManualAccountIdentity;
use wholepact_store::manual_enrollment::ManualAuditProjection;

#[derive(Clone, Serialize)]
struct IdentityEntry {
    identity: ManualAccountIdentity,
    genesis_digest: String,
    aliases: BTreeSet<String>,
    exclusion_digests: BTreeSet<String>,
}
/// No Deserialize or raw public constructor. Only the complete capsule owner
/// builds this union after validating every original node and current Store rows.
pub(crate) struct InheritedManualIdentityCoverage {
    capsule_manifest_digest: String,
    node_commitments: BTreeMap<String, String>,
    identities: BTreeMap<String, IdentityEntry>,
    unknown_accounts: BTreeSet<String>,
    construction_history_requires_financial_qualification: bool,
}
impl InheritedManualIdentityCoverage {
    pub(super) fn require_financial_history_supported(&self) -> Result<()> {
        if self.construction_history_requires_financial_qualification {
            return Err(Error::RecoveryFinancialUnsupported);
        }
        Ok(())
    }

    pub(super) fn empty_for_verified_capsule(manifest_digest: &str) -> Result<Self> {
        canonical_hash(manifest_digest)?;
        Ok(Self {
            capsule_manifest_digest: manifest_digest.into(),
            node_commitments: BTreeMap::new(),
            identities: BTreeMap::new(),
            unknown_accounts: BTreeSet::new(),
            construction_history_requires_financial_qualification: false,
        })
    }
    pub(super) fn include_checked_node(
        &mut self,
        generation: &str,
        manifest: &str,
        expected: &BTreeSet<String>,
        complete: Option<&CheckedContinuityRows>,
        current: &ManualAuditProjection,
    ) -> Result<()> {
        canonical_hash(generation)?;
        canonical_hash(manifest)?;
        if self
            .node_commitments
            .insert(generation.into(), manifest.into())
            .is_some()
            || self.node_commitments.len() > 16
            || expected.len() > 4096
        {
            return Err(Error::Authentication);
        }
        let mut covered = BTreeSet::new();
        if let Some(complete) = complete {
            if matches!(
                complete,
                CheckedContinuityRows::V3(_)
                    | CheckedContinuityRows::V4(_)
                    | CheckedContinuityRows::V5(_)
            ) {
                self.construction_history_requires_financial_qualification = true;
            }
            for (account_id, use_history) in complete.checked_identity_rows()? {
                let Some(genesis) = &use_history.genesis else {
                    continue;
                };
                let identity = ManualAccountIdentity {
                    account_id: genesis.identity.account_id.clone(),
                    full_viewing_key_digest: genesis.identity.full_viewing_key_digest.clone(),
                    network_profile_id: genesis.identity.network_profile_id.clone(),
                    derivation_domain: genesis.identity.derivation_domain.clone(),
                };
                if identity.account_id != account_id {
                    return Err(Error::Authentication);
                }
                let aliases = BTreeSet::from([identity.account_id.clone()]);
                let exclusions = use_history
                    .exclusion
                    .as_ref()
                    .map(|x| x.digest().map_err(|_| Error::Authentication))
                    .transpose()?
                    .into_iter()
                    .collect();
                self.include(
                    identity,
                    genesis.digest().map_err(|_| Error::Authentication)?,
                    aliases,
                    exclusions,
                )?;
                covered.insert(account_id.to_owned());
            }
        }
        for row in current.enrollments() {
            row.validate().map_err(|_| Error::Authentication)?;
            // The snapshot owner has checked original row bindings and exact
            // sequence/predecessor relations, including archived ancestral rows.
            self.include(
                row.terms().identity.clone(),
                row.terms().account_use_genesis_digest.clone(),
                row.aliases().clone(),
                BTreeSet::new(),
            )?;
            covered.extend(row.aliases().iter().cloned());
        }
        for row in current.exclusions() {
            row.validate().map_err(|_| Error::Authentication)?;
            self.include(
                row.identity.clone(),
                row.account_use_genesis_digest.clone(),
                row.aliases.clone(),
                BTreeSet::from([row.exclusion_digest.clone()]),
            )?;
            covered.extend(row.aliases.iter().cloned());
        }
        // Unknown coverage is monotone: a later record never retroactively
        // invents a missing older exclusion history or an empty genesis.
        self.unknown_accounts
            .extend(expected.difference(&covered).cloned());
        if self.identities.len() > 4096 || self.unknown_accounts.len() > 4096 {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn include(
        &mut self,
        identity: ManualAccountIdentity,
        genesis_digest: String,
        aliases: BTreeSet<String>,
        exclusions: BTreeSet<String>,
    ) -> Result<()> {
        for value in [
            &identity.account_id,
            &identity.full_viewing_key_digest,
            &genesis_digest,
        ] {
            canonical_hash(value)?;
        }
        if identity.network_profile_id.is_empty()
            || identity.network_profile_id.len() > 256
            || identity.derivation_domain != "dedicated-testnet-legacy-zip32-v1"
            || aliases.is_empty()
            || aliases.len() > 64
            || !aliases.contains(&identity.account_id)
        {
            return Err(Error::Authentication);
        }
        for alias in &aliases {
            crate::id(alias)?;
        }
        for exclusion in &exclusions {
            canonical_hash(exclusion)?;
        }
        for old in self.identities.values() {
            if (old.identity.account_id == identity.account_id
                || old.identity.full_viewing_key_digest == identity.full_viewing_key_digest
                || !old.aliases.is_disjoint(&aliases))
                && (old.identity != identity || old.genesis_digest != genesis_digest)
            {
                return Err(Error::Authentication);
            }
        }
        let entry = self
            .identities
            .entry(identity.account_id.clone())
            .or_insert_with(|| IdentityEntry {
                identity,
                genesis_digest,
                aliases: BTreeSet::new(),
                exclusion_digests: BTreeSet::new(),
            });
        entry.aliases.extend(aliases);
        entry.exclusion_digests.extend(exclusions);
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        wholepact_core::proposal::canonical_digest(
            "wholepact:inherited-manual-identity-coverage:v1",
            &(
                &self.capsule_manifest_digest,
                &self.node_commitments,
                &self.identities,
                &self.unknown_accounts,
            ),
        )
        .map_err(|_| Error::Authentication)
    }
    /// Fail early before any new signer ceremony when inherited provenance is unknown.
    /// Completeness is historical coverage only and grants no current authority.
    pub(crate) fn require_complete(&self) -> Result<()> {
        if self.node_commitments.is_empty() || !self.unknown_accounts.is_empty() {
            return Err(Error::RecoveryFinancialUnsupported);
        }
        Ok(())
    }
    /// Only a negative predicate. Success cannot admit an action: it still needs
    /// the current actual Store, genuine native owner and live signer/witness.
    pub(crate) fn require_distinct(
        &self,
        candidate: &ManualAccountIdentity,
        aliases: &BTreeSet<String>,
    ) -> Result<()> {
        self.require_financial_history_supported()?;
        self.require_complete()?;
        canonical_hash(&candidate.account_id)?;
        canonical_hash(&candidate.full_viewing_key_digest)?;
        if aliases.is_empty()
            || aliases.len() > 64
            || candidate.network_profile_id.is_empty()
            || candidate.network_profile_id.len() > 256
            || candidate.derivation_domain != "dedicated-testnet-legacy-zip32-v1"
            || !aliases.contains(&candidate.account_id)
        {
            return Err(Error::RecoveryFinancialUnsupported);
        }
        for alias in aliases {
            crate::id(alias)?;
        }
        if self.identities.values().any(|old| {
            old.identity.account_id == candidate.account_id
                || old.identity.full_viewing_key_digest == candidate.full_viewing_key_digest
                || !old.aliases.is_disjoint(aliases)
        }) {
            return Err(Error::RecoveryFinancialUnsupported);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(account: char, fvk: char) -> ManualAccountIdentity {
        ManualAccountIdentity {
            account_id: account.to_string().repeat(64),
            full_viewing_key_digest: fvk.to_string().repeat(64),
            network_profile_id: "testnet".into(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        }
    }
    fn fixture() -> InheritedManualIdentityCoverage {
        let mut out =
            InheritedManualIdentityCoverage::empty_for_verified_capsule(&"11".repeat(32)).unwrap();
        out.node_commitments
            .insert("22".repeat(32), "33".repeat(32));
        out
    }
    #[test]
    fn distinctness_rejects_incomplete_identity_and_alias_shapes() {
        let coverage = fixture();
        let mut fresh = identity('a', 'b');
        let aliases = BTreeSet::from([fresh.account_id.clone()]);
        fresh.derivation_domain.clear();
        assert!(coverage.require_distinct(&fresh, &aliases).is_err());
        fresh.derivation_domain = "dedicated-testnet-legacy-zip32-v1".into();
        fresh.network_profile_id.clear();
        assert!(coverage.require_distinct(&fresh, &aliases).is_err());
        fresh.network_profile_id = "testnet".into();
        let mut oversized = aliases.clone();
        oversized.extend((0..64).map(|n| format!("alias-{n}")));
        assert!(coverage.require_distinct(&fresh, &oversized).is_err());
    }
    #[test]
    fn missing_legacy_identity_history_is_never_an_empty_exclusion_set() {
        let mut old = fixture();
        old.unknown_accounts.insert("unknown-old-account".into());
        let new = identity('a', 'b');
        assert!(
            old.require_distinct(&new, &BTreeSet::from([new.account_id.clone()]))
                .is_err()
        );
    }
    #[test]
    fn renamed_account_or_network_cannot_escape_inherited_authority() {
        let mut old = fixture();
        let a = identity('a', 'b');
        old.include(
            a.clone(),
            "44".repeat(32),
            BTreeSet::from([a.account_id.clone(), "old-alias".into()]),
            BTreeSet::new(),
        )
        .unwrap();
        let mut renamed = identity('c', 'b');
        renamed.network_profile_id = "different-label".into();
        assert!(
            old.require_distinct(&renamed, &BTreeSet::from([renamed.account_id.clone()]))
                .is_err()
        );
        let fresh = identity('c', 'd');
        assert!(
            old.require_distinct(
                &fresh,
                &BTreeSet::from([fresh.account_id.clone(), "old-alias".into()])
            )
            .is_err()
        );
    }
    #[test]
    fn exclusions_union_and_conflicting_identity_bindings_never_replace() {
        let mut old = fixture();
        let a = identity('a', 'b');
        let aliases = BTreeSet::from([a.account_id.clone()]);
        old.include(
            a.clone(),
            "44".repeat(32),
            aliases.clone(),
            BTreeSet::from(["55".repeat(32)]),
        )
        .unwrap();
        old.include(a.clone(), "44".repeat(32), aliases.clone(), BTreeSet::new())
            .unwrap();
        assert_eq!(old.identities[&a.account_id].exclusion_digests.len(), 1);
        assert!(
            old.include(
                identity('a', 'c'),
                "44".repeat(32),
                aliases,
                BTreeSet::new()
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod construction_history_gate_tests {
    use super::*;
    #[test]
    fn v3_ancestral_identity_coverage_stays_readable_but_cannot_admit_financial_work() {
        let mut coverage =
            InheritedManualIdentityCoverage::empty_for_verified_capsule(&"11".repeat(32)).unwrap();
        coverage.require_financial_history_supported().unwrap();
        coverage.construction_history_requires_financial_qualification = true;
        assert!(matches!(
            coverage.require_financial_history_supported(),
            Err(Error::RecoveryFinancialUnsupported)
        ));
        assert!(coverage.unknown_accounts.is_empty());
    }
}
