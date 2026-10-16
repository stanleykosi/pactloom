//! Inert, purpose-distinct additional-read claims. Parsing this data creates no
//! native admission, retained-material owner, scanner or financial permission.
use crate::{
    CoreError, ErrorCode, Result, manual_roster_construction_v2::ManualRosterConstructionPlanV2,
    proposal::canonical_digest,
};
use serde::{Deserialize, Serialize};

// Conservative INITIAL staging profile, not a measured execution-time promise.
// Activation requires exact producer/consumer and boundary qualification.
pub const EXACT_OBSERVATION_MAX_OWNERS: usize = 8;
pub const EXACT_OBSERVATION_MAX_ADDITIONAL_BLOCKS: u32 = 32;
pub const EXACT_OBSERVATION_MAX_SCAN_RUNTIME_MS: u64 = 30_000;
pub const EXACT_OBSERVATION_POST_SCAN_RUNWAY_MS: u64 = 10_000;
pub const EXACT_OBSERVATION_MIN_EXPIRY_MARGIN_BLOCKS: u32 = 10;
pub const EXACT_OBSERVATION_MAX_PARALLEL_SCANS: u8 = 2;
pub const EXACT_OBSERVATION_MAX_ADMISSION_MS: u64 = 30_000;
pub const EXACT_OBSERVATION_SOURCE_TTL_MS: u64 = 60_000;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactInputObservationPurposeV1 {
    ObserveRetainedInputsOnly,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactInputObservationModeV1 {
    AppendOnlySameOriginalAnchor,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactInputObservationCompletionV1 {
    AdmittedBoundedCompletion,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactInputObservationProfileV1 {
    pub mode: ExactInputObservationModeV1,
    pub completion: ExactInputObservationCompletionV1,
    pub maximum_additional_blocks: u32,
    pub maximum_scan_runtime_ms: u64,
    pub post_scan_runway_ms: u64,
    pub minimum_expiry_margin_blocks: u32,
    pub maximum_parallel_scans: u8,
    pub minimum_confirmations: u32,
}
impl ExactInputObservationProfileV1 {
    pub fn for_plan(plan: &ManualRosterConstructionPlanV2) -> Result<Self> {
        plan.validate()?;
        let inventory = &plan.retained.selection.scope.selection.inventory;
        let value = Self {
            mode: ExactInputObservationModeV1::AppendOnlySameOriginalAnchor,
            completion: ExactInputObservationCompletionV1::AdmittedBoundedCompletion,
            maximum_additional_blocks: inventory
                .maximum_blocks
                .min(EXACT_OBSERVATION_MAX_ADDITIONAL_BLOCKS),
            maximum_scan_runtime_ms: EXACT_OBSERVATION_MAX_SCAN_RUNTIME_MS,
            post_scan_runway_ms: EXACT_OBSERVATION_POST_SCAN_RUNWAY_MS,
            minimum_expiry_margin_blocks: EXACT_OBSERVATION_MIN_EXPIRY_MARGIN_BLOCKS,
            maximum_parallel_scans: EXACT_OBSERVATION_MAX_PARALLEL_SCANS,
            minimum_confirmations: inventory.minimum_confirmations,
        };
        value.validate_for(plan)?;
        Ok(value)
    }
    pub fn validate_for(&self, plan: &ManualRosterConstructionPlanV2) -> Result<()> {
        plan.validate()?;
        let inventory = &plan.retained.selection.scope.selection.inventory;
        if !(2..=EXACT_OBSERVATION_MAX_OWNERS).contains(&plan.participants.len())
            || self.maximum_additional_blocks == 0
            || self.maximum_additional_blocks > EXACT_OBSERVATION_MAX_ADDITIONAL_BLOCKS
            || self.maximum_additional_blocks > inventory.maximum_blocks
            || self.maximum_scan_runtime_ms != EXACT_OBSERVATION_MAX_SCAN_RUNTIME_MS
            || self.post_scan_runway_ms != EXACT_OBSERVATION_POST_SCAN_RUNWAY_MS
            || self.minimum_expiry_margin_blocks != EXACT_OBSERVATION_MIN_EXPIRY_MARGIN_BLOCKS
            || self.maximum_parallel_scans != EXACT_OBSERVATION_MAX_PARALLEL_SCANS
            || self.minimum_confirmations < inventory.minimum_confirmations
            || !(1..=100).contains(&self.minimum_confirmations)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterExactInputObservationRequestV1 {
    pub version: u16,
    pub operation_id: String,
    // Full original plan carries exact account/FVK, original Host/import and
    // attachment destination, provider, retention, inputs, anchor and return.
    pub plan: ManualRosterConstructionPlanV2,
    pub original_durable_receipt_digest: String,
    pub purpose: ExactInputObservationPurposeV1,
    pub profile: ExactInputObservationProfileV1,
    pub current_caller_binding_digest: String,
    pub requested_at_ms: u64,
    pub admission_expires_at_ms: u64,
    // Additional restriction only. Original already-captured Instant survives
    // in the genuine consumer and is never reconstructed from this wall value.
    pub completion_expires_at_ms: u64,
}
impl ManualRosterExactInputObservationRequestV1 {
    pub fn validate(&self) -> Result<()> {
        self.plan.validate()?;
        self.profile.validate_for(&self.plan)?;
        crate::error::validate_id(&self.operation_id, "roster exact-input observation")?;
        for value in [
            &self.original_durable_receipt_digest,
            &self.current_caller_binding_digest,
        ] {
            hash(value)?;
        }
        let retained = &self.plan.retained;
        if self.version != 1
            || self.operation_id == retained.operation_id
            || self.operation_id == retained.selection.operation_id
            || self.operation_id == retained.selection.scope.selection.invocation.operation_id
            || self.requested_at_ms < retained.requested_at_ms
            || self.requested_at_ms == 0
            || self.completion_expires_at_ms > i64::MAX as u64
            || self.admission_expires_at_ms <= self.requested_at_ms
            || self.admission_expires_at_ms - self.requested_at_ms
                > EXACT_OBSERVATION_MAX_ADMISSION_MS
            || self.admission_expires_at_ms > self.completion_expires_at_ms
            || self.completion_expires_at_ms > self.plan.completion_expires_at_ms()
            || self.completion_expires_at_ms <= self.requested_at_ms
            || self.completion_expires_at_ms - self.requested_at_ms
                <= self.profile.post_scan_runway_ms
            || serde_json::to_vec(self).map_err(|_| invalid())?.len() > 384 * 1024
        {
            return Err(invalid());
        }
        self.maximum_additional_blocks()?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(
            "wholepact:manual-roster-exact-input-observation-request:v1",
            self,
        )
    }
    pub fn remaining_admission_ms(&self, now: u64) -> Result<u64> {
        self.validate()?;
        if now < self.requested_at_ms || now >= self.admission_expires_at_ms {
            return Err(invalid());
        }
        Ok(self.admission_expires_at_ms - now)
    }
    /// Strict existing expiry convention: observed tip + margin < expiry.
    pub fn maximum_observed_tip(&self) -> Result<u32> {
        self.plan
            .retained
            .selection
            .scope
            .selection
            .economic_intent
            .expiry_height
            .checked_sub(self.profile.minimum_expiry_margin_blocks)
            .and_then(|h| h.checked_sub(1))
            .ok_or_else(invalid)
    }
    /// Zero is meaningful: an explicit same-tip read may fetch no added block.
    /// This never changes the reviewed positive policy cap or generic SyncLimits.
    pub fn maximum_additional_blocks(&self) -> Result<u32> {
        let headroom = self
            .maximum_observed_tip()?
            .checked_sub(self.plan.retained.selection_context.tip_height)
            .ok_or_else(invalid)?;
        Ok(headroom
            .min(self.profile.maximum_additional_blocks)
            .min(
                self.plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .maximum_blocks,
            )
            .min(EXACT_OBSERVATION_MAX_ADDITIONAL_BLOCKS))
    }
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid exact-input additional-read scope or fixed profile",
    )
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Err(invalid())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn purpose_and_completion_are_closed_not_approval_flags() {
        assert!(
            serde_json::from_str::<ExactInputObservationPurposeV1>(
                r#""observe_retained_inputs_only""#
            )
            .is_ok()
        );
        for forbidden in [
            "select_new_inputs",
            "sign",
            "prove",
            "dispatch",
            "renew",
            "true",
        ] {
            assert!(
                serde_json::from_str::<ExactInputObservationPurposeV1>(&format!("\"{forbidden}\""))
                    .is_err()
            );
        }
        assert!(serde_json::from_str::<ExactInputObservationModeV1>(r#""reanchor""#).is_err());
        assert!(
            serde_json::from_str::<ExactInputObservationCompletionV1>(r#""unbounded""#).is_err()
        );
    }
}

#[cfg(test)]
mod boundaries {
    use super::*;
    fn request() -> ManualRosterExactInputObservationRequestV1 {
        let plan = crate::manual_roster_construction_v2::tests::plan();
        let profile = ExactInputObservationProfileV1::for_plan(&plan).unwrap();
        ManualRosterExactInputObservationRequestV1 {
            version: 1,
            operation_id: "synthetic-extra-read".into(),
            plan,
            profile,
            original_durable_receipt_digest: "af".repeat(32),
            purpose: ExactInputObservationPurposeV1::ObserveRetainedInputsOnly,
            current_caller_binding_digest: "bc".repeat(32),
            requested_at_ms: 40_000,
            admission_expires_at_ms: 70_000,
            completion_expires_at_ms: 100_000,
        }
    }
    #[test]
    fn fresh_admission_cannot_renew_or_relabel_original_completion() {
        let r = request();
        r.validate().unwrap();
        let mut changed = r.clone();
        changed.completion_expires_at_ms += 1;
        assert!(changed.validate().is_err());
        let mut changed = r.clone();
        changed.admission_expires_at_ms += 1;
        assert!(changed.validate().is_err());
        let mut changed = r.clone();
        changed.operation_id = r.plan.retained.operation_id.clone();
        assert!(changed.validate().is_err());
        assert!(r.remaining_admission_ms(39_999).is_err());
        assert_eq!(r.remaining_admission_ms(69_999).unwrap(), 1);
        assert!(r.remaining_admission_ms(70_000).is_err());
    }
    #[test]
    fn every_fixed_profile_boundary_and_original_stricter_cap_is_enforced() {
        let r = request();
        r.validate().unwrap();
        let mutations: [fn(&mut ExactInputObservationProfileV1); 8] = [
            |p: &mut ExactInputObservationProfileV1| p.maximum_additional_blocks = 0,
            |p: &mut ExactInputObservationProfileV1| p.maximum_additional_blocks = 11,
            |p: &mut ExactInputObservationProfileV1| p.maximum_additional_blocks = 33,
            |p: &mut ExactInputObservationProfileV1| p.maximum_scan_runtime_ms = 30_001,
            |p: &mut ExactInputObservationProfileV1| p.post_scan_runway_ms = 9_999,
            |p: &mut ExactInputObservationProfileV1| p.minimum_expiry_margin_blocks = 9,
            |p: &mut ExactInputObservationProfileV1| p.maximum_parallel_scans = 3,
            |p: &mut ExactInputObservationProfileV1| p.minimum_confirmations = 0,
        ];
        for mutate in mutations {
            let mut changed = r.clone();
            mutate(&mut changed.profile);
            assert!(changed.validate().is_err());
        }
        assert_eq!(r.maximum_additional_blocks().unwrap(), 10);
        let mut changed = r;
        changed.completion_expires_at_ms = changed.requested_at_ms + 10_000;
        changed.admission_expires_at_ms = changed.completion_expires_at_ms;
        assert!(changed.validate().is_err());
    }
    #[test]
    fn exact_headroom_zero_means_zero_added_blocks_and_underflow_denies() {
        let mut r = request();
        let expiry = r
            .plan
            .retained
            .selection
            .scope
            .selection
            .economic_intent
            .expiry_height;
        let ceiling = expiry - 11;
        assert_eq!(r.maximum_observed_tip().unwrap(), ceiling);
        r.plan.retained.selection_context.tip_height = ceiling;
        assert_eq!(r.maximum_additional_blocks().unwrap(), 0);
        r.plan.retained.selection_context.tip_height = ceiling + 1;
        assert!(r.maximum_additional_blocks().is_err());
        r.plan
            .retained
            .selection
            .scope
            .selection
            .economic_intent
            .expiry_height = 10;
        assert!(r.maximum_observed_tip().is_err());
    }
    #[test]
    fn request_digest_binds_complete_provider_wallet_caller_and_retention_claims() {
        let r = request();
        let d = r.digest().unwrap();
        let mut changed = r.clone();
        changed.current_caller_binding_digest = "de".repeat(32);
        assert_ne!(d, changed.digest().unwrap());
        let mut changed = r.clone();
        changed.original_durable_receipt_digest = "ef".repeat(32);
        assert_ne!(d, changed.digest().unwrap());
        let mut data = serde_json::to_value(&r).unwrap();
        data["approved"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<ManualRosterExactInputObservationRequestV1>(data).is_err()
        );
        // Altering original retained plan data without its matching original
        // commitment fails even though a new extra-read digest could be made.
        let mut changed = r;
        changed
            .plan
            .retained
            .selection
            .scope
            .selection
            .inventory
            .provider
            .source_id = "other-provider".into();
        assert!(changed.validate().is_err());
    }
}
