//! Projection only from the SAME private original material, completed native
//! read and held-wallet roster. No timestamp/DTO input or recovered owner issuer.
use super::*;
use wholepact_core::common_context_historical_provenance_v1::{
    CommonContextHistoricalParticipantV1, CommonContextHistoricalProvenanceV1,
    HistoricalChainObservationV1, required_ancestry_digest, selected_inputs_digest,
};

pub(super) struct SnapshotHistorical {
    original: ChainContext,
    revalidation: ChainContext,
}
impl SnapshotHistorical {
    pub(super) fn capture(
        material: &RetainedExactWalletMaterial,
        fresh: &FreshCommonContextObservation,
    ) -> Result<Self> {
        fresh.check_current()?;
        material.check_retained_lineage()?;
        if !Arc::ptr_eq(&material.identity, &fresh.material)
            || !Weak::ptr_eq(&material.generation, &fresh.generation)
            || material.original_observation().source() != fresh.observation().source()
        {
            return Err(ExactObservationError::Lineage);
        }
        let original = material.selection().context();
        let old = observation(material.original_observation())?;
        let current = observation(fresh.observation())?;
        if old.tip_height != original.tip_height
            || old.tip_hash_protocol != hex::encode(original.tip_hash_protocol)
            || current.tip_height != fresh.current.tip_height
            || current.tip_hash_protocol != hex::encode(fresh.current.tip_hash_protocol)
        {
            return Err(ExactObservationError::Binding);
        }
        // Deliberately do not check the ORIGINAL provider TTL as current. It is
        // an old truthful label; actual Fresh/native/wallet guards remain live.
        Ok(Self {
            original: material.original_observation().clone(),
            revalidation: fresh.observation().clone(),
        })
    }
}
fn observation(context: &ChainContext) -> Result<HistoricalChainObservationV1> {
    // Reuse the maintained profile boundary, including its canonical "test"
    // network label and maximum observation lifetime, instead of duplicating it.
    verify_observation_profile(context, context)?;
    let value = HistoricalChainObservationV1 {
        request_started_at_unix_seconds: context.request_started_at_unix_seconds(),
        observed_at_unix_seconds: context.observed_at_unix_seconds(),
        valid_until_unix_seconds: context.valid_until_unix_seconds(),
        tip_height: u32::try_from(context.tip().height)
            .map_err(|_| ExactObservationError::Binding)?,
        tip_hash_protocol: hex::encode(protocol_hash(&context.tip().hash)?),
    };
    value
        .validate()
        .map_err(|_| ExactObservationError::Binding)?;
    Ok(value)
}
impl HeldCommonContextRosterObservation<'_> {
    /// Restriction-only conjunction with the SAME consumed native owners. No
    /// DTO, cloned value, or similarly-valued alternate read can substitute.
    pub fn require_original_admissions(
        &self,
        admitted: &[&AdmittedManualRosterConstructionContributionV3],
    ) -> Result<()> {
        self.check_all_current()?;
        if admitted.len() != self.count
            || self.native_reads.len() != self.count
            || self.common.context.participants.len() != self.count
        {
            return Err(ExactObservationError::Lineage);
        }
        for (owner, expected) in admitted.iter().zip(&self.common.context.participants) {
            owner
                .check_completion()
                .map_err(|_| ExactObservationError::Permission)?;
            let plan = &owner
                .request()
                .map_err(|_| ExactObservationError::Permission)?
                .plan;
            let account = &expected.commitment.account_id;
            let read = self
                .native_reads
                .get(account)
                .ok_or(ExactObservationError::Lineage)?;
            if plan.enrollment().identity.account_id != *account
                || plan.enrollment().scope.participant_id != expected.commitment.participant_id
                || plan.enrollment().identity.full_viewing_key_digest
                    != expected.commitment.full_viewing_key_digest
                || plan.common_context_digest != self.common.digest
                || self.plans.get(account)
                    != Some(&plan.digest().map_err(|_| ExactObservationError::Binding)?)
            {
                return Err(ExactObservationError::Binding);
            }
            owner
                .check_original_read(read)
                .map_err(|_| ExactObservationError::Binding)?;
            owner
                .check_completion()
                .map_err(|_| ExactObservationError::Permission)?;
        }
        self.check_all_current()
    }
    /// Historical metadata only; never another current read owner. The caller
    /// must preserve original native/financial clocks and durable one-use claim.
    /// An incomplete component-test native map cannot issue this projection.
    pub fn historical_provenance_v1(&self) -> Result<CommonContextHistoricalProvenanceV1> {
        self.check_all_current()?;
        if self.native_reads.len() != self.count
            || self.historical.len() != self.count
            || self.common.context.participants.len() != self.count
        {
            return Err(ExactObservationError::Lineage);
        }
        let mut plans = Vec::with_capacity(self.count);
        let mut requests = Vec::with_capacity(self.count);
        let mut admissions = Vec::with_capacity(self.count);
        let mut observations = Vec::with_capacity(self.count);
        let mut common = None;
        for expected in &self.common.context.participants {
            let account = &expected.commitment.account_id;
            let native = self
                .native_reads
                .get(account)
                .ok_or(ExactObservationError::Lineage)?;
            native
                .check_completion()
                .map_err(|_| ExactObservationError::Permission)?;
            let request = native
                .request()
                .map_err(|_| ExactObservationError::Permission)?;
            let plan = &request.plan;
            let historical = self
                .historical
                .get(account)
                .ok_or(ExactObservationError::Lineage)?;
            let id = &plan.enrollment().identity;
            let provider = &plan.common_context.provider;
            for context in [&historical.original, &historical.revalidation] {
                if context.source().source_id != provider.source_id
                    || context.source().endpoint != provider.endpoint
                    || context.source().trust_profile != provider.trust_profile
                {
                    return Err(ExactObservationError::Binding);
                }
            }
            let plan_digest = plan.digest().map_err(|_| ExactObservationError::Binding)?;
            let read_digest = request
                .digest()
                .map_err(|_| ExactObservationError::Binding)?;
            let admission_digest = native
                .evidence()
                .digest()
                .map_err(|_| ExactObservationError::Binding)?;
            if id.account_id != *account
                || self.plans.get(account) != Some(&plan_digest)
                || plan.common_context_digest != self.common.digest
                || native.evidence().request != *request
                || plan.enrollment().scope.participant_id != expected.commitment.participant_id
                || id.full_viewing_key_digest != expected.commitment.full_viewing_key_digest
                || common
                    .as_ref()
                    .is_some_and(|old| old != &plan.common_context)
            {
                return Err(ExactObservationError::Binding);
            }
            let current = observation(&historical.revalidation)?;
            if current.tip_height != self.current.tip_height
                || current.tip_hash_protocol != hex::encode(self.current.tip_hash_protocol)
            {
                return Err(ExactObservationError::Binding);
            }
            observations.push(CommonContextHistoricalParticipantV1 {
                participant_id: expected.commitment.participant_id.clone(),
                account_id: account.clone(),
                full_viewing_key_digest: id.full_viewing_key_digest.clone(),
                plan_digest,
                retained_request_digest: plan
                    .retained
                    .digest()
                    .map_err(|_| ExactObservationError::Binding)?,
                read_request_digest: read_digest,
                read_admission_digest: admission_digest.clone(),
                selected_inputs_digest: selected_inputs_digest(plan)
                    .map_err(|_| ExactObservationError::Binding)?,
                original: observation(&historical.original)?,
                revalidation: current,
                anchor_height: plan.common_context.anchor_height,
                anchor_hash_protocol: plan.common_context.anchor_hash_protocol.clone(),
                anchor_root: plan.common_context.anchor_root.clone(),
                required_ancestry_digest: required_ancestry_digest(&plan.common_context)
                    .map_err(|_| ExactObservationError::Binding)?,
            });
            common = Some(plan.common_context.clone());
            plans.push(plan.clone());
            requests.push(request.clone());
            admissions.push(admission_digest);
        }
        let common = common.ok_or(ExactObservationError::Lineage)?;
        let reference_participant_id = observations
            .iter()
            .max_by_key(|r| r.original.tip_height)
            .ok_or(ExactObservationError::Lineage)?
            .participant_id
            .clone();
        let value = CommonContextHistoricalProvenanceV1 {
            version: 1,
            common_context_digest: self.common.digest.clone(),
            reference_participant_id,
            provider: common.provider,
            read_profile: common.read_profile,
            observations,
        };
        let reads = requests
            .iter()
            .zip(&admissions)
            .map(|(r, a)| (r, a.as_str()))
            .collect::<Vec<_>>();
        value
            .validate_for(&plans, &reads)
            .map_err(|_| ExactObservationError::Binding)?;
        // The reference-selection rule ignores time; no caller can relabel a
        // revalidation as the original by selecting a newer timestamp.
        for native in self.native_reads.values() {
            native
                .check_completion()
                .map_err(|_| ExactObservationError::Permission)?;
        }
        self.check_all_current()?;
        Ok(value)
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;
    #[test]
    fn historical_projection_uses_actual_maintained_context_labels_and_clocks() {
        // Existing fixed synthetic ChainContext only; no wallet/native/held owner.
        let source =
            wholepact_chain::synthetic_wallet_chain_context_for_qualification(1_800_000_000)
                .unwrap();
        assert_eq!(source.network(), "test");
        let projected = observation(&source).unwrap();
        assert_eq!(
            projected.request_started_at_unix_seconds,
            source.request_started_at_unix_seconds()
        );
        assert_eq!(
            projected.observed_at_unix_seconds,
            source.observed_at_unix_seconds()
        );
        assert_eq!(
            projected.valid_until_unix_seconds,
            source.valid_until_unix_seconds()
        );
        assert_eq!(u64::from(projected.tip_height), source.tip().height);
        assert_eq!(
            projected.tip_hash_protocol,
            hex::encode(protocol_hash(&source.tip().hash).unwrap())
        );
        assert_eq!(projected.observed_at_ms().unwrap(), 1_800_000_000_000);
    }
}
