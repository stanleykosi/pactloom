//! Original birth-to-witness historical linkage only. Requires the witness-owner
//! genesis/checkpoint patch. No live session, enrollment or activation issuer.
use super::*;
use wholepact_authority::{
    AuthorityHead, ReconciledAuthorityHistory,
    account_use::{
        AccountUseCheckpoint, AccountUseGenesis, AccountUseIdentity, PermanentAccountExclusion,
    },
};

/// Historical audit with permanent exclusion retained exactly. This is NOT an
/// eligibility token, acknowledgement-to-activation transition or current lease.
pub(crate) struct HistoricalBirthLinkAudit {
    genesis: AccountUseGenesis,
    original_disclosure: WitnessDisclosureDescriptor,
    checkpoint: AccountUseCheckpoint,
    permanent_exclusion: Option<PermanentAccountExclusion>,
    observed_head: AuthorityHead,
}
impl HistoricalBirthLinkAudit {
    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        &self.genesis
    }
    pub(crate) fn original_disclosure(&self) -> &WitnessDisclosureDescriptor {
        &self.original_disclosure
    }
    pub(crate) fn checkpoint(&self) -> &AccountUseCheckpoint {
        &self.checkpoint
    }
    pub(crate) fn permanent_exclusion(&self) -> Option<&PermanentAccountExclusion> {
        self.permanent_exclusion.as_ref()
    }
    pub(crate) fn observed_head(&self) -> &AuthorityHead {
        &self.observed_head
    }
}
impl BirthAnchor {
    /// Derives an ordinary proposed/audit DTO, never the missing opaque witness
    /// enrollment issuer. The original account vault remains permanently pending.
    pub(crate) fn expected_account_use_genesis(&self) -> Result<AccountUseGenesis> {
        let identity = self.identity();
        let genesis = AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: identity.account_id().into(),
                full_viewing_key_digest: identity.full_viewing_key_digest().into(),
                network_profile_id: identity.network_profile_id().into(),
                derivation_domain: identity.derivation_domain().into(),
            },
            witness_id: self.witness_origin().witness_id().into(),
            witness_origin_digest:
                wholepact_authority::account_use_link::account_use_witness_origin_digest(
                    // Only the four immutable origin fields enter this digest. This
                    // syntactically valid placeholder is not an enrolled policy hash.
                    &self
                        .original_disclosure_for_digest(self.original_policy_terms_digest().into()),
                )
                .map_err(|_| Error::InvalidData)?,
            owner_certificate_digest: self
                .original_policy_terms()
                .owner_certificate_digest()
                .into(),
            native_birth_digest: self.birth_digest().into(),
        };
        genesis.validate().map_err(|_| Error::InvalidData)?;
        Ok(genesis)
    }

    fn original_disclosure_for_digest(&self, policy_digest: String) -> WitnessDisclosureDescriptor {
        let origin = self.witness_origin();
        WitnessDisclosureDescriptor {
            endpoint: origin.endpoint().into(),
            server_name: origin.server_name().into(),
            witness_id: origin.witness_id().into(),
            pinned_server_certificate_digest: origin.pinned_server_certificate_digest().into(),
            account_id: self.identity().account_id().into(),
            network_profile_id: self.identity().network_profile_id().into(),
            policy_digest,
        }
    }

    pub(super) fn audit_policy_match(
        &self,
        policy: &AccountPolicy,
    ) -> Result<(AccountUseGenesis, WitnessDisclosureDescriptor)> {
        policy.validate().map_err(|_| Error::InvalidData)?;
        let genesis = self.expected_account_use_genesis()?;
        if policy.account_use_genesis.as_ref() != Some(&genesis) {
            return Err(Error::ReviewMismatch);
        }
        let mut genesis_free = policy.clone();
        genesis_free.account_use_genesis = None;
        let actual_terms = OriginalPolicyTerms::from_policy(&genesis_free)?;
        if actual_terms != *self.original_policy_terms()
            || actual_terms.digest()? != self.original_policy_terms_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        let disclosure = self.original_disclosure_for_digest(
            policy.policy_digest().map_err(|_| Error::InvalidData)?,
        );
        disclosure.validate().map_err(|_| Error::InvalidData)?;
        Ok((genesis, disclosure))
    }

    /// Requires the owner's genuine complete reconciled history. Plain policy or
    /// checkpoint JSON cannot satisfy the signature. Offline-origin history is
    /// explicitly unsupported. Existing exclusions remain visible in the result.
    pub(crate) fn audit_historical_witness_link(
        &self,
        history: &ReconciledAuthorityHistory,
    ) -> Result<HistoricalBirthLinkAudit> {
        history
            .require_legacy_online_only()
            .map_err(|_| Error::Unavailable)?;
        self.audit_historical_linkage(history)
    }

    /// Original-roster preconstruction only. This admits independently signed
    /// approval history, never reserved/consumed construction or financial
    /// exposure. The caller supplies its actual retained record's extension.
    /// Generic birth/Single/retirement readers retain the legacy gate above.
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(in crate::account::birth) fn audit_original_roster_preconstruction_witness_link(
        &self,
        history: &ReconciledAuthorityHistory,
        extension: &wholepact_authority::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    ) -> Result<HistoricalBirthLinkAudit> {
        use super::enrollment::roster_v2::continuation::diagnostics::{self as diag, Phase as P};
        diag::authority(
            P::RosterBirthHistoryGate,
            history.require_original_roster_preconstruction_history(),
        )
        .map_err(|_| Error::Unavailable)?;
        let actual_extension = diag::authority(
            P::RosterBirthExtension,
            history.manual_roster_enrollment_extension(&extension.account_extension.enrollment_ref),
        )
        .map_err(|_| Error::Authentication)?;
        if actual_extension != Some(extension) {
            return diag::signer(P::RosterBirthExtension, Err(Error::Authentication));
        }
        let birth = history
            .pending_birth_commit()
            .ok_or(Error::RecoveryRequired)?;
        diag::authority(
            P::RosterBirthOriginal,
            extension.validate_original_birth(birth),
        )
        .map_err(|_| Error::Authentication)?;
        diag::signer(P::RosterBirthLinkage, self.audit_historical_linkage(history))
    }

    // Private shared linkage kernel. Each caller above applies its own explicit
    // history-support gate first; this returns historical audit data only.
    fn audit_historical_linkage(
        &self,
        history: &ReconciledAuthorityHistory,
    ) -> Result<HistoricalBirthLinkAudit> {
        let (genesis, original_disclosure) = self.audit_policy_match(history.account_policy())?;
        let projection = history.account_use_history();
        let checkpoint = projection
            .checkpoint()
            .map_err(|_| Error::InvalidData)?
            .ok_or(Error::RecoveryRequired)?;
        if projection.genesis() != Some(&genesis)
            || history.disclosure() != &original_disclosure
            || history.snapshot().account_use_checkpoint.as_ref() != Some(&checkpoint)
            || history.snapshot().account_id != self.identity().account_id()
            || history.snapshot().network_profile_id != self.identity().network_profile_id()
            || history.snapshot().witness_id != self.witness_origin().witness_id()
            || history.snapshot().policy_digest != original_disclosure.policy_digest
            || !history.contains_head(&history.snapshot().head)
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(HistoricalBirthLinkAudit {
            genesis,
            original_disclosure,
            checkpoint,
            permanent_exclusion: projection.exclusion().cloned(),
            observed_head: history.snapshot().head.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::birth::tests::{data_account, data_anchor, data_policy};

    #[test]
    fn modeled_genesis_is_derived_from_exact_immutable_birth_and_origin() {
        let account = data_account();
        let anchor = data_anchor(&account);
        let genesis = anchor.expected_account_use_genesis().unwrap();
        assert_eq!(genesis.identity.account_id, anchor.identity().account_id());
        assert_eq!(
            genesis.identity.full_viewing_key_digest,
            anchor.identity().full_viewing_key_digest()
        );
        assert_eq!(
            genesis.identity.network_profile_id,
            anchor.identity().network_profile_id()
        );
        assert_eq!(
            genesis.identity.derivation_domain,
            anchor.identity().derivation_domain()
        );
        assert_eq!(
            genesis.owner_certificate_digest,
            anchor.original_policy_terms().owner_certificate_digest()
        );
        assert_eq!(genesis.native_birth_digest, anchor.birth_digest());
        assert_eq!(
            genesis.witness_origin_digest,
            anchor.witness_origin().digest().unwrap()
        );
        // These are modeled audit DTOs; no complete-history or native capability
        // fixture is fabricated to claim a successful ownership transition.
    }

    #[test]
    fn modeled_historical_policy_requires_exact_genesis_and_all_original_terms() {
        let account = data_account();
        let anchor = data_anchor(&account);
        let original = data_policy(&account);
        assert!(anchor.audit_policy_match(&original).is_err());
        let mut proposed = original.clone();
        proposed.account_use_genesis = Some(anchor.expected_account_use_genesis().unwrap());
        let (_, disclosure) = anchor.audit_policy_match(&proposed).unwrap();
        assert_eq!(disclosure.policy_digest, proposed.policy_digest().unwrap());
        assert_eq!(disclosure.endpoint, anchor.witness_origin().endpoint());
        assert_eq!(
            disclosure.server_name,
            anchor.witness_origin().server_name()
        );
        assert_eq!(
            disclosure.pinned_server_certificate_digest,
            anchor.witness_origin().pinned_server_certificate_digest()
        );
        assert_ne!(disclosure.policy_digest, original.policy_digest().unwrap());
        for field in [
            "aggregate_budget_zatoshis",
            "policy_expires_at_ms",
            "initial_writer_epoch",
        ] {
            let mut changed = serde_json::to_value(&proposed).unwrap();
            let old = changed[field].as_u64().unwrap();
            changed[field] = serde_json::json!(old + 1);
            let changed: AccountPolicy = serde_json::from_value(changed).unwrap();
            assert!(anchor.audit_policy_match(&changed).is_err(), "{field}");
        }
        for field in [
            "native_birth_digest",
            "witness_origin_digest",
            "owner_certificate_digest",
        ] {
            let mut changed = serde_json::to_value(&proposed).unwrap();
            changed["account_use_genesis"][field] = serde_json::json!("98".repeat(32));
            let changed: AccountPolicy = serde_json::from_value(changed).unwrap();
            assert!(anchor.audit_policy_match(&changed).is_err(), "{field}");
        }
    }
}

#[cfg(all(test, feature = "pending-birth-owner-signing", feature = "synthetic-qualification"))]
#[path = "history/preconstruction_tests.rs"]
mod preconstruction_tests;
