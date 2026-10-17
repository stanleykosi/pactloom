//! Inert completed-checkpoint statement. Only the concrete native Host derives
//! it from actual Store and private verified checkpoint records. Parsing, hashes
//! and witness construction consumes never establish completion or key use.
use crate::offline::OfflineAuthorizationTerms;
use crate::{born_offline_construction_v1::*, *};
use serde::{Deserialize, Serialize};
use wholepact_core::common_context_historical_provenance_v1::{
    CommonContextHistoricalProvenanceV1, selected_inputs_digest,
};
use wholepact_core::manual_enrollment::ManualHostGenerationBinding;
use wholepact_core::manual_roster_construction_v3::{
    ManualRosterConstructionPlanV3, RosterCommonContextReadRequestV1,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineCheckpointConstructionV1 {
    pub version: u16,
    pub reservation_operation_id: String,
    pub reservation_digest: String,
    pub consume_operation_id: String,
    pub consume_digest: String,
    pub plan_digest: String,
    pub common_context_digest: String,
    pub invocation_digest: String,
}
impl BornOfflineCheckpointConstructionV1 {
    pub fn from_link(link: &BornOfflineConstructionLinkV1) -> Result<Self> {
        link.validate()?;
        Ok(Self {
            version: link.version,
            reservation_operation_id: link.reservation_operation_id.clone(),
            reservation_digest: link.reservation_digest.clone(),
            consume_operation_id: link.consume_operation_id.clone(),
            consume_digest: link.consume_digest.clone(),
            plan_digest: link.plan_digest.clone(),
            common_context_digest: link.common_context_digest.clone(),
            invocation_digest: link.invocation_digest.clone(),
        })
    }
    pub fn link(&self, checkpoint_origin_digest: String) -> BornOfflineConstructionLinkV1 {
        BornOfflineConstructionLinkV1 {
            version: self.version,
            reservation_operation_id: self.reservation_operation_id.clone(),
            reservation_digest: self.reservation_digest.clone(),
            consume_operation_id: self.consume_operation_id.clone(),
            consume_digest: self.consume_digest.clone(),
            plan_digest: self.plan_digest.clone(),
            common_context_digest: self.common_context_digest.clone(),
            invocation_digest: self.invocation_digest.clone(),
            checkpoint_origin_digest,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineCheckpointOriginV1 {
    pub version: u16,
    pub host: ManualHostGenerationBinding,
    pub principal_id: String,
    pub construction_key: String,
    pub claim_digest: String,
    pub checkpoint_receipt_digest: String,
    pub job_id: String,
    pub scope_digest: String,
    pub input_artifact_digest: String,
    pub proved_artifact_digest: String,
    pub coordination_request_digest: String,
    pub network_profile_id: String,
    pub agreement_id: String,
    pub proposal_id: String,
    pub proposal_revision: u64,
    pub proposal_digest: String,
    pub manifest_digest: String,
    pub effects_commitment: String,
    pub review_binding: String,
    pub account_id: String,
    pub full_viewing_key_digest: String,
    pub signer_key_digest: String,
    pub host_return_key_digest: String,
    pub construction: BornOfflineCheckpointConstructionV1,
    /// Exact authenticated Host historical claims, not current chain truth.
    /// Each signer independently joins only its own original native read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub historical_provenance: Option<CommonContextHistoricalProvenanceV1>,
}
impl BornOfflineCheckpointOriginV1 {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.version, 1 | 2) || self.construction.version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        if (self.version == 2) != self.historical_provenance.is_some() {
            return Err(AuthorityError::InvalidBinding);
        }
        if let Some(provenance) = &self.historical_provenance {
            provenance
                .validate()
                .map_err(|_| AuthorityError::InvalidBinding)?;
            let row = provenance
                .observations
                .iter()
                .find(|r| r.account_id == self.account_id)
                .ok_or(AuthorityError::InvalidBinding)?;
            if provenance.common_context_digest != self.construction.common_context_digest
                || row.full_viewing_key_digest != self.full_viewing_key_digest
                || row.plan_digest != self.construction.plan_digest
            {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        for value in [
            &self.principal_id,
            &self.job_id,
            &self.network_profile_id,
            &self.agreement_id,
            &self.proposal_id,
            &self.host.profile_id,
        ] {
            id(value)?;
        }
        if !(16..=128).contains(&self.construction_key.len())
            || !self
                .construction_key
                .bytes()
                .all(|b| (33..=126).contains(&b))
        {
            return Err(AuthorityError::InvalidBinding);
        }
        for value in [
            &self.claim_digest,
            &self.checkpoint_receipt_digest,
            &self.scope_digest,
            &self.input_artifact_digest,
            &self.proved_artifact_digest,
            &self.coordination_request_digest,
            &self.proposal_digest,
            &self.manifest_digest,
            &self.effects_commitment,
            &self.review_binding,
            &self.account_id,
            &self.full_viewing_key_digest,
            &self.signer_key_digest,
            &self.host_return_key_digest,
            &self.host.generation_id,
            &self.host.inventory_digest,
            &self.host.generation_plan_digest,
            &self.host.financial_journal_origin_digest,
            &self.host.destination_identity_digest,
            &self.host.inherited_identity_digest,
        ] {
            hash(value)?;
        }
        if let Some(value) = &self.host.scope_predecessor_digest {
            hash(value)?;
        }
        for path in [
            &self.host.canonical_root,
            &self.host.store_destination_identity,
        ] {
            if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        self.construction.link("0".repeat(64)).validate()
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(
            if self.version == 2 {
                "wholepact:born-offline-checkpoint-origin:v2"
            } else {
                "wholepact:born-offline-checkpoint-origin:v1"
            },
            self,
        )
    }
    /// Requires explicit encoding 2; legacy absence never receives defaults.
    pub fn require_historical_provenance_v2(&self) -> Result<&CommonContextHistoricalProvenanceV1> {
        self.validate()?;
        if self.version != 2 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        self.historical_provenance
            .as_ref()
            .ok_or(AuthorityError::InvalidBinding)
    }
    fn validate_historical_plan(&self, plan: &ManualRosterConstructionPlanV3) -> Result<()> {
        let provenance = self.require_historical_provenance_v2()?;
        plan.validate()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        provenance
            .validate_common_for(&plan.common_context)
            .map_err(|_| AuthorityError::InvalidBinding)?;
        let enrollment = plan.enrollment();
        let row = provenance
            .observations
            .iter()
            .find(|r| r.account_id == self.account_id)
            .ok_or(AuthorityError::InvalidBinding)?;
        if self.account_id != enrollment.identity.account_id
            || self.full_viewing_key_digest != enrollment.identity.full_viewing_key_digest
            || row.participant_id != enrollment.scope.participant_id
            || row.plan_digest != plan.digest().map_err(|_| AuthorityError::InvalidBinding)?
            || row.retained_request_digest
                != plan
                    .retained
                    .digest()
                    .map_err(|_| AuthorityError::InvalidBinding)?
            || row.selected_inputs_digest
                != selected_inputs_digest(plan).map_err(|_| AuthorityError::InvalidBinding)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    /// Independently authenticates only this account's actual original read.
    /// Peer rows remain authenticated Host historical claims, not independently
    /// witnessed reads or fresh chain authority.
    pub fn validate_historical_read(
        &self,
        plan: &ManualRosterConstructionPlanV3,
        read: &RosterCommonContextReadRequestV1,
        admission_digest: &str,
    ) -> Result<()> {
        self.validate_historical_plan(plan)?;
        self.require_historical_provenance_v2()?
            .validate_participant_for(plan, read, admission_digest)
            .map_err(|_| AuthorityError::InvalidBinding)
    }
    /// Exact unchanged OfflineSnapshot semantics: the original observation of
    /// the deterministic reference participant, never the later revalidation.
    /// The established terms contract binds the full original proved PCZT.
    /// The separately reviewed canonical signer projection may have a different
    /// digest; callers retain its maintained projection/proof/request checks.
    pub fn validate_snapshot_terms(&self, terms: &OfflineAuthorizationTerms) -> Result<()> {
        let provenance = self.require_historical_provenance_v2()?;
        terms.validate()?;
        let expected = provenance
            .reference_snapshot()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        let snapshot = &terms.snapshot;
        if terms.account_id != self.account_id
            || terms.network_profile_id != self.network_profile_id
            || terms.agreement_id != self.agreement_id
            || terms.proposal_id != self.proposal_id
            || terms.proposal_revision != self.proposal_revision
            || terms.proposal_digest != self.proposal_digest
            || terms.manifest_digest != self.manifest_digest
            || terms.effects_digest != self.effects_commitment
            || terms.artifact_digest != self.proved_artifact_digest
            || terms.review_binding != self.review_binding
            || terms.offline_signer_key_digest != self.signer_key_digest
            || terms.return_recipient_key_digest != self.host_return_key_digest
            || snapshot.source_id != expected.source_id
            || snapshot.source_identity_digest != expected.source_identity_digest
            || snapshot.source_policy_digest != expected.source_policy_digest
            || snapshot.snapshot_digest != expected.snapshot_digest
            || snapshot.observed_at_ms != expected.observed_at_ms
            || snapshot.tip_height != expected.tip_height
            || snapshot.tip_hash != expected.tip_hash
            || snapshot.anchor_height != expected.anchor_height
            || snapshot.anchor_hash != expected.anchor_hash
            || snapshot.anchor_root != expected.anchor_root
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn validate_for_link(&self, link: &BornOfflineConstructionLinkV1) -> Result<()> {
        self.validate()?;
        link.validate()?;
        if self.construction.link(self.digest()?) != *link {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn validate_for_origin(&self, origin: &BornOfflineConstructionOriginV1) -> Result<()> {
        let link = self.construction.link(self.digest()?);
        link.validate_origin(origin)?;
        let p = &origin.reservation.request.construction.plan;
        let proposal = p.validate().map_err(|_| AuthorityError::InvalidBinding)?;
        let enrollment = p.enrollment();
        if self.version == 2 {
            self.validate_historical_plan(p)?;
        }
        if self.host != enrollment.host
            || self.principal_id != enrollment.scope.principal_id
            || self.account_id != enrollment.identity.account_id
            || self.full_viewing_key_digest != enrollment.identity.full_viewing_key_digest
            || self.network_profile_id != enrollment.identity.network_profile_id
            || self.agreement_id != enrollment.scope.agreement_id
            || self.proposal_id != proposal.input().proposal_id
            || self.proposal_revision != p.common_context.candidate_revision
            || self.proposal_digest != proposal.proposal_digest()
            || self.manifest_digest != proposal.manifest_digest()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}

/// Exact inert export metadata. Allocation and once sealing belong solely to
/// the concrete protected Host owner; this type is not an export capability.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineCheckpointExportPlanV1 {
    pub message_id: String,
    pub sequence: u64,
    pub issued_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
    pub purpose: String,
    pub persistence_warning: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub sender_key_fingerprint: String,
    pub recipient_key_fingerprint: String,
}
impl BornOfflineCheckpointExportPlanV1 {
    pub fn validate(&self) -> Result<()> {
        if self.message_id.len() != 32
            || !self
                .message_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
        {
            return Err(AuthorityError::InvalidBinding);
        }
        for text in [&self.purpose, &self.persistence_warning] {
            if text.is_empty() || text.len() > 512 || text.chars().any(char::is_control) {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        id(&self.sender_id)?;
        id(&self.recipient_id)?;
        hash(&self.sender_key_fingerprint)?;
        hash(&self.recipient_key_fingerprint)?;
        if self.issued_at_unix_seconds < 0
            || self.expires_at_unix_seconds <= self.issued_at_unix_seconds
            || self
                .expires_at_unix_seconds
                .checked_sub(self.issued_at_unix_seconds)
                .is_none_or(|d| d > 7 * 24 * 60 * 60)
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn validate_for(&self, origin: &BornOfflineCheckpointOriginV1) -> Result<()> {
        self.validate()?;
        origin.validate()?;
        if self.sender_id != format!("born-offline-checkpoint:{}", origin.host_return_key_digest)
            || self.recipient_id != format!("born-offline-checkpoint:{}", origin.signer_key_digest)
            || self.sender_key_fingerprint != origin.host_return_key_digest
            || self.recipient_key_fingerprint != origin.signer_key_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-offline-checkpoint-export-plan:v1", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }
    fn statement() -> BornOfflineCheckpointOriginV1 {
        // Deliberately inert synthetic statement. No Store, proof, native
        // approval, HPKE receipt or completion capability is manufactured.
        BornOfflineCheckpointOriginV1 {
            version: 1,
            historical_provenance: None,
            host: ManualHostGenerationBinding {
                generation_id: h(1),
                inventory_digest: h(2),
                generation_plan_digest: h(3),
                financial_journal_origin_digest: h(4),
                store_destination_identity: "synthetic-store".into(),
                profile_id: "synthetic-profile".into(),
                canonical_root: "/synthetic/root".into(),
                destination_identity_digest: h(5),
                inherited_identity_digest: h(6),
                scope_predecessor_digest: None,
            },
            principal_id: "synthetic-owner".into(),
            construction_key: "synthetic-construction-key".into(),
            claim_digest: h(7),
            checkpoint_receipt_digest: h(8),
            job_id: "synthetic-proof-job".into(),
            scope_digest: h(9),
            input_artifact_digest: h(10),
            proved_artifact_digest: h(11),
            coordination_request_digest: h(12),
            network_profile_id: "test-profile".into(),
            agreement_id: "agreement".into(),
            proposal_id: "proposal".into(),
            proposal_revision: 1,
            proposal_digest: h(13),
            manifest_digest: h(14),
            effects_commitment: h(15),
            review_binding: h(16),
            account_id: h(17),
            full_viewing_key_digest: h(18),
            signer_key_digest: h(19),
            host_return_key_digest: h(20),
            construction: BornOfflineCheckpointConstructionV1 {
                version: 1,
                reservation_operation_id: "reserve-original".into(),
                reservation_digest: h(21),
                consume_operation_id: "consume-original".into(),
                consume_digest: h(22),
                plan_digest: h(23),
                common_context_digest: h(24),
                invocation_digest: h(25),
            },
        }
    }
    #[test]
    fn checkpoint_link_commits_every_original_completion_field_without_a_cycle() {
        let original = statement();
        let link = original.construction.link(original.digest().unwrap());
        original.validate_for_link(&link).unwrap();
        for mutate in [
            (|s: &mut BornOfflineCheckpointOriginV1| s.proved_artifact_digest = h(31))
                as fn(&mut BornOfflineCheckpointOriginV1),
            |s| s.claim_digest = h(32),
            |s| s.checkpoint_receipt_digest = h(33),
            |s| s.scope_digest = h(34),
            |s| s.host.inventory_digest = h(35),
            |s| s.signer_key_digest = h(36),
            |s| s.host_return_key_digest = h(37),
            |s| s.construction.consume_digest = h(38),
            |s| s.proposal_revision += 1,
        ] {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert!(changed.validate_for_link(&link).is_err());
        }
        let bytes = serde_json::to_vec(&original).unwrap();
        let decoded: BornOfflineCheckpointOriginV1 = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded == original);
        assert_eq!(decoded.digest().unwrap(), original.digest().unwrap());
    }
    fn historical_statement() -> BornOfflineCheckpointOriginV1 {
        use wholepact_core::common_context_historical_provenance_v1::*;
        let plan: ManualRosterConstructionPlanV3 = serde_json::from_slice(include_bytes!(
            "../../wholepact-store/src/manual_enrollment/fixtures/synthetic_plan_v3.json"
        ))
        .unwrap();
        let mut original = statement();
        let rows = (0..2)
            .map(|i| CommonContextHistoricalParticipantV1 {
                participant_id: format!("participant-{i}"),
                account_id: if i == 0 {
                    original.account_id.clone()
                } else {
                    h(40)
                },
                full_viewing_key_digest: if i == 0 {
                    original.full_viewing_key_digest.clone()
                } else {
                    h(41)
                },
                plan_digest: if i == 0 {
                    original.construction.plan_digest.clone()
                } else {
                    h(42)
                },
                retained_request_digest: h(43),
                read_request_digest: h(44),
                read_admission_digest: h(45),
                selected_inputs_digest: h(46),
                original: HistoricalChainObservationV1 {
                    request_started_at_unix_seconds: 1,
                    observed_at_unix_seconds: 1 + i as u64,
                    valid_until_unix_seconds: 3,
                    tip_height: 4_465_042 + i,
                    tip_hash_protocol: h(50 + i as u8),
                },
                revalidation: HistoricalChainObservationV1 {
                    request_started_at_unix_seconds: 3,
                    observed_at_unix_seconds: 3,
                    valid_until_unix_seconds: 4,
                    tip_height: 4_465_043,
                    tip_hash_protocol: h(51),
                },
                anchor_height: 4_465_040,
                anchor_hash_protocol: h(52),
                anchor_root: h(53),
                required_ancestry_digest: h(54),
            })
            .collect();
        original.version = 2;
        original.historical_provenance = Some(CommonContextHistoricalProvenanceV1 {
            version: 1,
            common_context_digest: original.construction.common_context_digest.clone(),
            reference_participant_id: "participant-1".into(),
            provider: plan.common_context.provider,
            read_profile: plan.common_context.read_profile,
            observations: rows,
        });
        original.validate().unwrap();
        original
    }
    #[test]
    fn checkpoint_provenance_v2_commits_complete_historical_claims_and_exact_snapshot_terms() {
        // Inert structural DTO exercise, not a witness/native/Store producer.
        let original = historical_statement();
        let reference = original
            .require_historical_provenance_v2()
            .unwrap()
            .reference_snapshot()
            .unwrap();
        let mut terms = crate::offline::tests::fixture().0.intent.terms;
        terms.account_id = original.account_id.clone();
        terms.network_profile_id = original.network_profile_id.clone();
        terms.agreement_id = original.agreement_id.clone();
        terms.proposal_id = original.proposal_id.clone();
        terms.proposal_revision = original.proposal_revision;
        terms.proposal_digest = original.proposal_digest.clone();
        terms.manifest_digest = original.manifest_digest.clone();
        terms.effects_digest = original.effects_commitment.clone();
        terms.artifact_digest = original.proved_artifact_digest.clone();
        // This snapshot/full-proof binding does not equate the separate signer
        // projection digest with the full online proof artifact.
        let canonical_signer_projection_digest = h(70);
        assert_ne!(canonical_signer_projection_digest, terms.artifact_digest);
        terms.review_binding = original.review_binding.clone();
        terms.offline_signer_key_digest = original.signer_key_digest.clone();
        terms.return_recipient_key_digest = original.host_return_key_digest.clone();
        terms.snapshot = crate::offline::OfflineSnapshotCommitment {
            source_id: reference.source_id,
            source_identity_digest: reference.source_identity_digest,
            source_policy_digest: reference.source_policy_digest,
            snapshot_digest: reference.snapshot_digest,
            observed_at_ms: reference.observed_at_ms,
            tip_height: reference.tip_height,
            tip_hash: reference.tip_hash,
            anchor_height: reference.anchor_height,
            anchor_hash: reference.anchor_hash,
            anchor_root: reference.anchor_root,
        };
        // The original fixture expiry may be below this explicitly modeled tip.
        terms.transaction_expiry_height = terms.snapshot.tip_height + 32;
        original.validate_snapshot_terms(&terms).unwrap();
        assert_eq!(
            original.digest().unwrap(),
            digest("wholepact:born-offline-checkpoint-origin:v2", &original).unwrap()
        );
        let link = original.construction.link(original.digest().unwrap());
        for case in 0..13 {
            let mut altered = terms.clone();
            match case {
                0 => altered.snapshot.source_id = "other-source".into(),
                1 => altered.snapshot.source_identity_digest = h(61),
                2 => altered.snapshot.source_policy_digest = h(62),
                3 => altered.snapshot.snapshot_digest = h(63),
                4 => altered.snapshot.observed_at_ms += 1000,
                5 => altered.snapshot.tip_height += 1,
                6 => altered.snapshot.tip_hash = h(64),
                7 => altered.snapshot.anchor_height -= 1,
                8 => altered.snapshot.anchor_hash = h(65),
                9 => altered.snapshot.anchor_root = h(66),
                10 => altered.account_id = h(67),
                11 => altered.offline_signer_key_digest = h(68),
                12 => altered.artifact_digest = canonical_signer_projection_digest.clone(),
                _ => unreachable!(),
            }
            assert!(
                original.validate_snapshot_terms(&altered).is_err(),
                "case {case}"
            );
        }
        let mut changed = original.clone();
        changed.historical_provenance.as_mut().unwrap().observations[1].read_admission_digest =
            h(69);
        changed.validate().unwrap();
        assert!(changed.validate_for_link(&link).is_err());
        let mut legacy = original;
        legacy.version = 1;
        assert!(legacy.validate().is_err());
    }
    #[test]
    fn checkpoint_provenance_v2_requires_explicit_history_and_preserves_v1_bytes() {
        let original = statement();
        let value = serde_json::to_value(&original).unwrap();
        assert!(
            !value
                .as_object()
                .unwrap()
                .contains_key("historical_provenance")
        );
        assert_eq!(
            original.digest().unwrap(),
            digest("wholepact:born-offline-checkpoint-origin:v1", &original).unwrap()
        );
        assert!(matches!(
            original.require_historical_provenance_v2(),
            Err(AuthorityError::UnsupportedVersion)
        ));
        let mut missing = original.clone();
        missing.version = 2;
        assert!(matches!(
            missing.validate(),
            Err(AuthorityError::InvalidBinding)
        ));
        // No old statement, parsed empty field or current timestamp can supply
        // missing original scanner provenance.
        let mut encoded = value;
        encoded["version"] = 2.into();
        encoded["historical_provenance"] = serde_json::Value::Null;
        let absent: BornOfflineCheckpointOriginV1 = serde_json::from_value(encoded).unwrap();
        assert!(absent.require_historical_provenance_v2().is_err());
    }
    #[test]
    fn checkpoint_plan_is_purpose_distinct_and_never_extends_its_fixed_window() {
        let o = statement();
        let mut plan = BornOfflineCheckpointExportPlanV1 {
            message_id: "11".repeat(16),
            sequence: 1,
            issued_at_unix_seconds: 1,
            expires_at_unix_seconds: 121,
            purpose: "Synthetic completed origin".into(),
            persistence_warning: "Inert test only".into(),
            sender_id: format!("born-offline-checkpoint:{}", o.host_return_key_digest),
            recipient_id: format!("born-offline-checkpoint:{}", o.signer_key_digest),
            sender_key_fingerprint: o.host_return_key_digest.clone(),
            recipient_key_fingerprint: o.signer_key_digest.clone(),
        };
        plan.validate_for(&o).unwrap();
        plan.sender_id = format!("offline-admission:{}", o.host_return_key_digest);
        assert!(plan.validate_for(&o).is_err());
        plan.sender_id = format!("born-offline-checkpoint:{}", o.host_return_key_digest);
        plan.sequence = 0;
        assert!(plan.validate().is_err());
        plan.sequence = 1;
        plan.expires_at_unix_seconds = plan.issued_at_unix_seconds;
        assert!(plan.validate().is_err());
        let mut bad = o;
        bad.construction_key = "contains a space!".into();
        assert!(bad.validate().is_err());
    }
}
