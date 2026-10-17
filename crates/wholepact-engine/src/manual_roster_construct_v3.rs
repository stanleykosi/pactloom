//! Dedicated actual-owner non-signing constructor. Ordinary recovered-financial
//! entrypoints remain denied. Native receipts or a Proposal alone cannot enter:
//! every original actual selection and new witness-consumed owner is required.
use crate::{Access, ApiError, Engine, Result};
use sha2::{Digest, Sha256};
use wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3;
use wholepact_proof_jobs::{
    CheckpointScope, JobSummary, LocalAction, LocalProofConsent, ProofJobStore,
};
use wholepact_protocol::{
    construction::{DisclosureAcknowledgement, DisclosureScope},
    proving::ProvingLimits,
};
use wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::{
    SignerRetainedCommonContextContributionV3, SignerRosterConstructionCompletionGuardV3,
};
use wholepact_signer_origin::AdmittedManualRosterConstructionContributionV3;
use wholepact_store::manual_enrollment::{
    ManualRosterCheckpointScopeV3, ManualRosterConstructionCheckpointV3,
    ManualRosterConstructionClaimOutcomeV3,
};
use wholepact_wallet::wallet::protected_sync::exact_input_observation::HeldCommonContextRosterObservation;

/// An embedding RESTRICTION only. It cannot substitute for the actual native,
/// witness, wallet and Store claim owners independently required below. There
/// is no synthetic prebuild CheckpointScope containing placeholder digests.
pub trait ManualRosterConstructionRestrictionV3: LocalProofConsent {
    fn check_before_constructor(
        &self,
        plans: &[ManualRosterConstructionPlanV3],
        construction_key: &str,
        maximum_actions: usize,
    ) -> Result<()>;
}
pub struct ManualRosterPrivateConstructionV3<'local, 'guard, 'held> {
    pub contributions: Vec<(
        SignerRetainedCommonContextContributionV3,
        AdmittedManualRosterConstructionContributionV3,
    )>,
    pub held: &'guard HeldCommonContextRosterObservation<'held>,
    pub progress: &'local ManualRosterConstructionProgressV3,
    pub jobs: &'local ProofJobStore,
    pub maximum_actions: usize,
    pub restriction: &'local dyn ManualRosterConstructionRestrictionV3,
}
/// Diagnostic state only; it grants no constructor or retry authority. Kept
/// outside the wallet callback so outer final checks/commits cannot erase that
/// a claim MAY have become durable even when the claim call returns an error.
#[derive(Default)]
pub struct ManualRosterConstructionProgressV3 {
    attempted: std::cell::Cell<bool>,
    claim_digest: std::cell::RefCell<Option<String>>,
}
impl ManualRosterConstructionProgressV3 {
    pub fn claim_may_exist(&self) -> bool {
        self.attempted.get()
    }
    pub fn claim_digest(&self) -> Option<String> {
        self.claim_digest.borrow().clone()
    }
    /// Diagnostic classification only; never a retry or persistence capability.
    pub fn classify_outer_result<T, E>(
        &self,
        result: std::result::Result<T, E>,
    ) -> std::result::Result<T, ManualRosterConstructionOuterErrorV3<E>> {
        result.map_err(|error| {
            if self.claim_may_exist() {
                ManualRosterConstructionOuterErrorV3::ClaimMayExist(error)
            } else {
                ManualRosterConstructionOuterErrorV3::BeforeClaim(error)
            }
        })
    }
    pub(crate) fn with_claim_attempt<T, E>(
        &self,
        claim: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        // Set before the actual call; even its error may follow a durable commit.
        self.attempted.set(true);
        claim()
    }
    fn mark_claim(&self, digest: String) {
        *self.claim_digest.borrow_mut() = Some(digest);
    }
}
/// An error classification for safe output only. Neither variant admits work.
pub enum ManualRosterConstructionOuterErrorV3<E> {
    BeforeClaim(E),
    ClaimMayExist(E),
}
#[derive(serde::Serialize)]
pub struct ManualRosterPrivateCheckpointV3 {
    pub claim_digest: String,
    pub checkpoint: JobSummary,
}
/// A successful constructor leaf is not yet a successful outer wallet commit.
/// Retains the ACTUAL original construction owners and original restriction
/// through every wallet commit. No held transaction escapes, and no metadata is
/// accessible until the post-unwind native/restriction conjunction succeeds.
/// Deliberately non-Clone, non-Debug and non-serializable, with private fields.
///
/// ```compile_fail
/// use wholepact_engine::manual_roster_construct_v3::ManualRosterPendingCheckpointV3;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ManualRosterPendingCheckpointV3<'static>>();
/// ```
///
/// ```compile_fail
/// use wholepact_engine::manual_roster_construct_v3::ManualRosterPendingCheckpointV3;
/// let _: ManualRosterPendingCheckpointV3<'static> = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// use wholepact_engine::manual_roster_construct_v3::ManualRosterPendingCheckpointV3;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<ManualRosterPendingCheckpointV3<'static>>();
/// ```
///
/// ```compile_fail
/// use wholepact_engine::manual_roster_construct_v3::ManualRosterPendingCheckpointV3;
/// fn expose(owner: ManualRosterPendingCheckpointV3<'_>) {
///     let _ = owner.metadata;
/// }
/// ```
#[must_use = "complete after all wallet commits before exposing checkpoint metadata"]
pub struct ManualRosterPendingCheckpointV3<'local> {
    native_guards: Vec<SignerRosterConstructionCompletionGuardV3>,
    restriction: &'local dyn ManualRosterConstructionRestrictionV3,
    plans: Vec<ManualRosterConstructionPlanV3>,
    construction_key: String,
    maximum_actions: usize,
    scope: CheckpointScope,
    metadata: ManualRosterPrivateCheckpointV3,
}
impl ManualRosterPendingCheckpointV3<'_> {
    /// Call only after the enclosing maintained wallet callbacks have returned.
    /// This cannot create an owner or retry construction; it consumes this one
    /// pending result and checks the original actual owners again.
    pub fn finish(self) -> Result<ManualRosterPrivateCheckpointV3> {
        complete_after_unwind(
            || check_native_guards(&self.native_guards),
            || {
                self.restriction.check_before_constructor(
                    &self.plans,
                    &self.construction_key,
                    self.maximum_actions,
                )?;
                if !self
                    .restriction
                    .permits(&self.scope, LocalAction::RetainPrivateWitnesses)
                    || !self
                        .restriction
                        .permits(&self.scope, LocalAction::InspectStatus)
                {
                    return Err(denied());
                }
                Ok(())
            },
        )
        .map_err(|error| {
            checkpoint_error(error, &self.metadata.claim_digest, &self.construction_key)
        })?;
        Ok(self.metadata)
    }
}
// Private orchestration only. Production always supplies actual opaque guards
// and the originally borrowed restriction; component tests cannot create them.
fn complete_after_unwind(
    mut native: impl FnMut() -> Result<()>,
    restriction: impl FnOnce() -> Result<()>,
) -> Result<()> {
    native()?;
    restriction()?;
    native()
}
impl Engine {
    /// The only new builder entry in this route. It consumes all concrete
    /// retained/native owners once, claims the immutable whole invocation before
    /// randomness, writes the exact constructor receipt before private enqueue,
    /// and returns an opaque pending completion. Metadata remains inaccessible
    /// until post-wallet-unwind completion. It cannot prove, sign or dispatch.
    pub fn checkpoint_manual_roster_from_retained_v3<'local>(
        &self,
        access: &Access,
        construction_key: &str,
        mut local: ManualRosterPrivateConstructionV3<'local, '_, '_>,
    ) -> Result<ManualRosterPendingCheckpointV3<'local>> {
        if self.store.protection() != wholepact_store::StorageProtection::Encrypted
            || !(2..=8).contains(&local.contributions.len())
            || local.held.participant_count() != local.contributions.len()
            || !(1..=8).contains(&local.maximum_actions)
        {
            return Err(denied());
        }
        local.contributions.sort_by(|a, b| {
            a.1.evidence()
                .request
                .plan
                .enrollment()
                .scope
                .participant_id
                .cmp(
                    &b.1.evidence()
                        .request
                        .plan
                        .enrollment()
                        .scope
                        .participant_id,
                )
        });
        let mut plans = Vec::with_capacity(local.contributions.len());
        for (retained, admitted) in &local.contributions {
            retained.check_held(local.held).map_err(|_| denied())?;
            admitted.check_completion().map_err(|_| denied())?;
            let request = admitted.request().map_err(|_| denied())?;
            if request.plan.retained != *retained.request().map_err(|_| denied())?
                || request.plan.retained_evidence_digest
                    != retained
                        .evidence()
                        .map_err(|_| denied())?
                        .digest()
                        .map_err(|_| denied())?
            {
                return Err(denied());
            }
            plans.push(request.plan.clone());
        }
        local.restriction.check_before_constructor(
            &plans,
            construction_key,
            local.maximum_actions,
        )?;
        let borrowed: Vec<_> = local
            .contributions
            .iter()
            .map(|(_, native)| native)
            .collect();
        check_held(local.held)?;
        let outcome = self
            .claim_manual_roster_construction_v5_fail_fast(
                access,
                construction_key,
                local.maximum_actions,
                &borrowed,
                local.held,
                local.progress,
            )
            .map_err(|error| claim_error(error, local.progress, construction_key))?;
        let token = match outcome {
            ManualRosterConstructionClaimOutcomeV3::Started(token) => token,
            ManualRosterConstructionClaimOutcomeV3::ExistingOnly(claim) => {
                let digest = claim
                    .digest()
                    .map_err(crate::store_error)
                    .map_err(|error| claim_error(error, local.progress, construction_key))?;
                local.progress.mark_claim(digest.clone());
                return Err(uncertain(&digest, construction_key));
            }
        };
        let claim = token.row().clone();
        let claim_digest = claim
            .digest()
            .map_err(crate::store_error)
            .map_err(|error| claim_error(error, local.progress, construction_key))?;
        local.progress.mark_claim(claim_digest.clone());
        // Every error from this point means the durable claim remains consumed.
        // No code path reconstructs randomized bytes for an existing claim.
        (|| {
            let proposal = claim.validate().map_err(crate::store_error)?;
            let coordination_request_digest = claim.request_digest().map_err(crate::store_error)?;
            let manifest_digest: [u8; 32] = hex::decode(proposal.manifest_digest())
                .map_err(|_| denied())?
                .try_into()
                .map_err(|_| denied())?;
            let reviewer_account_ids: Vec<_> = proposal
                .manifest()
                .participants
                .iter()
                .map(|p| p.account_id.clone())
                .collect();
            let mut declarations = Vec::with_capacity(plans.len());
            for plan in &plans {
                let inventory = &plan.retained.selection.scope.selection.inventory;
                declarations.push(DisclosureAcknowledgement {
                    account_id: plan.enrollment().identity.account_id.clone(),
                    manifest_digest,
                    operator: inventory.operator_name.clone(),
                    reviewer_account_ids: reviewer_account_ids.clone(),
                    purpose: "construct_one_candidate".into(),
                    retention_policy: inventory.retention_policy.clone(),
                    scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
                });
            }
            check_held(local.held)?;
            let mut contributions = Vec::with_capacity(local.contributions.len());
            let mut common = None;
            let mut native_guards = Vec::with_capacity(local.contributions.len());
            for (retained, admitted) in local.contributions {
                let consumed = retained
                    .into_common_context_construction(admitted, local.held)
                    .map_err(|_| denied())?;
                let (selected, context, guard) = consumed
                    .into_exact_parts(local.held)
                    .map_err(|_| denied())?;
                // A fresh tip cannot replace ORIGINAL constructor target/anchor.
                if common.as_ref().is_some_and(
                    |c: &wholepact_protocol::construction::ConstructionContext| {
                        c.anchor != context.anchor
                            || c.anchor_height != context.anchor_height
                            || c.anchor_block_hash != context.anchor_block_hash
                            || c.target_height != context.target_height
                    },
                ) {
                    return Err(denied());
                }
                common = Some(context);
                contributions.push(selected);
                native_guards.push(guard);
            }
            let context = common.ok_or_else(denied)?;
            check_native_guards(&native_guards)?;
            check_held(local.held)?;
            local.restriction.check_before_constructor(
                &plans,
                construction_key,
                local.maximum_actions,
            )?;
            // Last current-source/native gate immediately before randomness.
            check_native_guards(&native_guards)?;
            check_held(local.held)?;
            let built = wholepact_protocol::construction::construct_proposal(
                &proposal,
                context,
                contributions,
                &declarations,
            )
            .map_err(|_| {
                ApiError::new(
                    "CANDIDATE_VERIFICATION_FAILED",
                    "Exact retained contribution construction failed",
                )
            })?;
            check_native_guards(&native_guards)?;
            check_held(local.held)?;
            local.restriction.check_before_constructor(
                &plans,
                construction_key,
                local.maximum_actions,
            )?;
            let structure =
                wholepact_protocol::inspect_candidate(&built.pczt_bytes).map_err(|_| denied())?;
            if structure.actions > local.maximum_actions {
                return Err(denied());
            }
            let first = plans.first().ok_or_else(denied)?;
            let inventory = &first.retained.selection.scope.selection.inventory;
            let scope = CheckpointScope {
                principal_id: access.principal_id.clone(),
                candidate_id: claim.candidate_id().into(),
                manifest_digest: proposal.manifest_digest().into(),
                artifact_digest: hex::encode(Sha256::digest(&built.pczt_bytes)),
                effects_commitment: built.economic_review.shielded_sighash().into(),
                coordination_request_digest,
                review_binding: built.economic_review.review_binding().into(),
                account_ids: reviewer_account_ids,
                local_operator: inventory.operator_name.clone(),
                purpose: "construct_one_candidate".into(),
                retention_policy: inventory.retention_policy.clone(),
            };
            let consent = CompletionRestriction {
                restriction: local.restriction,
                native: &native_guards,
                held: local.held,
                exact_scope: &scope,
            };
            if !consent.permits(&scope, LocalAction::RetainPrivateWitnesses) {
                return Err(denied());
            }
            let receipt = ManualRosterConstructionCheckpointV3 {
                version: 3,
                claim_digest: claim_digest.clone(),
                job_id: wholepact_proof_jobs::job_id_for_key(
                    &access.principal_id,
                    construction_key,
                )
                .map_err(|_| denied())?,
                scope: ManualRosterCheckpointScopeV3 {
                    principal_id: scope.principal_id.clone(),
                    candidate_id: scope.candidate_id.clone(),
                    manifest_digest: scope.manifest_digest.clone(),
                    artifact_digest: scope.artifact_digest.clone(),
                    effects_commitment: scope.effects_commitment.clone(),
                    coordination_request_digest: scope.coordination_request_digest.clone(),
                    review_binding: scope.review_binding.clone(),
                    account_ids: scope.account_ids.clone(),
                    local_operator: scope.local_operator.clone(),
                    purpose: scope.purpose.clone(),
                    retention_policy: scope.retention_policy.clone(),
                },
            };
            receipt.validate_for(&claim).map_err(crate::store_error)?;
            // Full exact constructor receipt is durable BEFORE the separate
            // encrypted proof journal write. Missing/ambiguous artifact later
            // means uncertain; neither receipt nor claim can mint a new token.
            token
                .record_checkpoint_fail_fast(receipt)
                .map_err(crate::store_error)?;
            if !consent.permits(&scope, LocalAction::RetainPrivateWitnesses) {
                return Err(denied());
            }
            let checkpoint = local
                .jobs
                .enqueue_fail_fast(
                    &scope,
                    construction_key,
                    &built.pczt_bytes,
                    &built.review_policy,
                    ProvingLimits {
                        maximum_actions: local.maximum_actions,
                    },
                    &consent,
                )
                .map_err(|_| uncertain(&claim_digest, construction_key))?;
            if !consent.permits(&scope, LocalAction::RetainPrivateWitnesses) {
                return Err(denied());
            }
            Ok(ManualRosterPendingCheckpointV3 {
                native_guards,
                restriction: local.restriction,
                plans,
                construction_key: construction_key.into(),
                maximum_actions: local.maximum_actions,
                scope,
                metadata: ManualRosterPrivateCheckpointV3 {
                    claim_digest: claim_digest.clone(),
                    checkpoint,
                },
            })
        })()
        .map_err(|error| checkpoint_error(error, &claim_digest, construction_key))
    }
}
struct CompletionRestriction<'a, 'held> {
    restriction: &'a dyn ManualRosterConstructionRestrictionV3,
    native: &'a [SignerRosterConstructionCompletionGuardV3],
    held: &'a HeldCommonContextRosterObservation<'held>,
    exact_scope: &'a CheckpointScope,
}
impl LocalProofConsent for CompletionRestriction<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        let current = || check_native_guards(self.native).is_ok() && check_held(self.held).is_ok();
        checkpoint_only(action)
            && scope == self.exact_scope
            && current()
            && self.restriction.permits(scope, action)
            && current()
    }
}
fn check_held(held: &HeldCommonContextRosterObservation<'_>) -> Result<()> {
    held.check_all_current().map_err(|_| ApiError::new(
        "RETAINED_INPUT_OBSERVATION_UNAVAILABLE",
        "Current same-input observation or held original-wallet revalidation failed; original exposure is unchanged",
    ))
}
fn claim_error(
    mut error: ApiError,
    progress: &ManualRosterConstructionProgressV3,
    key: &str,
) -> ApiError {
    if progress.claim_may_exist() {
        error.details = Box::new(serde_json::json!({
            "claim_may_be_durable": true, "construction_key": key,
            "claim_digest": progress.claim_digest(),
            "randomized_retry_allowed": false, "journals_are_atomic_together": false,
        }));
        error.safe_actions = vec!["Preserve the original invocation and journals; use only exact original checkpoint inspection. Never retry construction".into()];
    }
    error
}
fn checkpoint_error(mut error: ApiError, claim: &str, key: &str) -> ApiError {
    error.details = Box::new(serde_json::json!({
        "durable_construction_claim": claim, "construction_key": key,
        "randomized_retry_allowed": false, "journals_are_atomic_together": false,
    }));
    error.safe_actions = vec!["Inspect the original exact claim, constructor receipt and encrypted checkpoint; never regenerate this invocation".into()];
    error
}
fn check_native_guards(guards: &[SignerRosterConstructionCompletionGuardV3]) -> Result<()> {
    for guard in guards {
        guard.check_current().map_err(|_| denied())?;
    }
    Ok(())
}
fn denied() -> ApiError {
    ApiError::new(
        "MANUAL_CONSTRUCTION_DENIED",
        "The exact non-signing retained-owner construction conjunction is no longer current",
    )
}
fn uncertain(claim: &str, key: &str) -> ApiError {
    let mut error = ApiError::new(
        "RECOVERY_REQUIRED",
        "This invocation is already durably claimed; only exact original checkpoint inspection is allowed",
    );
    error.details = Box::new(
        serde_json::json!({"claim_digest":claim,"construction_key":key,"randomized_retry_allowed":false}),
    );
    error
}

fn checkpoint_only(action: LocalAction) -> bool {
    matches!(
        action,
        LocalAction::RetainPrivateWitnesses | LocalAction::InspectStatus
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn construction_completion_never_admits_proof_private_read_or_recovery() {
        assert!(checkpoint_only(LocalAction::RetainPrivateWitnesses));
        assert!(checkpoint_only(LocalAction::InspectStatus));
        assert!(!checkpoint_only(LocalAction::ProveLocally));
        assert!(!checkpoint_only(LocalAction::ReadPrivateArtifact));
        assert!(!checkpoint_only(LocalAction::RecoverInterrupted));
    }
    #[test]
    fn private_completion_orchestration_brackets_original_restriction() {
        // Only the production-shared ordering helper is exercised. These
        // closures are not actual native owners and cannot enter the constructor.
        let calls = std::cell::RefCell::new(Vec::new());
        complete_after_unwind(
            || {
                calls.borrow_mut().push("native");
                Ok(())
            },
            || {
                calls.borrow_mut().push("original restriction");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            *calls.borrow(),
            ["native", "original restriction", "native"]
        );

        for failure in ["first native", "restriction", "second native"] {
            let native_calls = std::cell::Cell::new(0);
            let restriction_called = std::cell::Cell::new(false);
            let metadata_released = std::cell::Cell::new(false);
            let result = complete_after_unwind(
                || {
                    native_calls.set(native_calls.get() + 1);
                    if (failure == "first native" && native_calls.get() == 1)
                        || (failure == "second native" && native_calls.get() == 2)
                    {
                        Err(denied())
                    } else {
                        Ok(())
                    }
                },
                || {
                    restriction_called.set(true);
                    if failure == "restriction" {
                        Err(denied())
                    } else {
                        Ok(())
                    }
                },
            )
            .map(|()| metadata_released.set(true));
            assert!(result.is_err());
            assert!(!metadata_released.get());
            assert_eq!(restriction_called.get(), failure != "first native");
        }
    }

    #[test]
    fn independent_construction_failure_denies_metadata_at_post_unwind_helper() {
        // A component model of the state AFTER wallet completion, not actual
        // maintained-wallet or native acceptance evidence. The production
        // helper must still reject an independent, earlier construction expiry
        // even though exact-read/wallet completion succeeded.
        let exact_read_current = true;
        let construction_current = std::cell::Cell::new(true);
        let metadata_released = std::cell::Cell::new(false);
        construction_current.set(false);
        let completion = complete_after_unwind(
            || {
                if construction_current.get() {
                    Ok(())
                } else {
                    Err(denied())
                }
            },
            || {
                if exact_read_current {
                    Ok(())
                } else {
                    Err(denied())
                }
            },
        )
        .map(|()| metadata_released.set(true));
        assert!(completion.is_err());
        assert!(!metadata_released.get());
        assert!(exact_read_current);
    }

    #[test]
    fn diagnostic_classification_is_not_a_claim_or_retry_capability() {
        let progress = ManualRosterConstructionProgressV3::default();
        assert!(matches!(
            progress.classify_outer_result::<(), _>(Err("before")),
            Err(ManualRosterConstructionOuterErrorV3::BeforeClaim("before"))
        ));
        let returned: std::result::Result<(), &str> = progress.with_claim_attempt(|| {
            assert!(progress.claim_may_exist());
            Err("call failed before a digest was returned")
        });
        assert!(matches!(
            progress.classify_outer_result(returned),
            Err(ManualRosterConstructionOuterErrorV3::ClaimMayExist(_))
        ));
        let error = claim_error(denied(), &progress, "synthetic-original-key");
        assert_eq!(error.details["construction_key"], "synthetic-original-key");
        assert_eq!(error.details["claim_may_be_durable"], true);
        assert_eq!(error.details["randomized_retry_allowed"], false);
        assert!(error.details["claim_digest"].is_null());
        assert!(progress.claim_digest().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn real_encrypted_sqlite_commit_error_preserves_shared_diagnostic_progress() {
        use std::os::unix::fs::PermissionsExt;
        use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
        // Real encrypted SQLite COMMIT failure, with a durable component marker.
        // NOT a Store claim, actual native admission, maintained wallet callback,
        // constructor receipt, proof enqueue, or full native acceptance fixture.
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("component.sqlite");
        let key = DatabaseKey::from_bytes([0x7b; 32]);
        let encrypted = create_encrypted(&path, &key).unwrap();
        let conn = encrypted.connection();
        conn.execute_batch(
            "PRAGMA foreign_keys=ON;
            CREATE TABLE component_marker (id INTEGER PRIMARY KEY);
            CREATE TABLE parent (id INTEGER PRIMARY KEY);
            CREATE TABLE child (parent_id INTEGER REFERENCES parent(id)
                DEFERRABLE INITIALLY DEFERRED);",
        )
        .unwrap();
        let unknown_digest = ManualRosterConstructionProgressV3::default();
        let after_durable_marker: Result<()> = unknown_digest.with_claim_attempt(|| {
            assert!(unknown_digest.claim_may_exist());
            conn.execute("INSERT INTO component_marker VALUES (1)", [])
                .unwrap();
            // The marker is committed, while the call returns an error before
            // its caller could obtain any digest. The marker is not a claim.
            assert!(conn.is_autocommit());
            Err(denied())
        });
        assert!(matches!(
            unknown_digest.classify_outer_result(after_durable_marker),
            Err(ManualRosterConstructionOuterErrorV3::ClaimMayExist(_))
        ));
        assert!(unknown_digest.claim_digest().is_none());

        let known_digest = ManualRosterConstructionProgressV3::default();
        known_digest
            .with_claim_attempt(|| {
                assert!(known_digest.claim_may_exist());
                conn.execute("INSERT INTO component_marker VALUES (2)", [])
            })
            .unwrap();
        let synthetic_digest = "a".repeat(64);
        known_digest.mark_claim(synthetic_digest.clone());
        conn.execute_batch("BEGIN IMMEDIATE; INSERT INTO child VALUES (99);")
            .unwrap();
        let actual_commit = conn.execute_batch("COMMIT;");
        assert!(
            actual_commit.is_err(),
            "deferred foreign-key violation fails at COMMIT"
        );
        assert!(!conn.is_autocommit());
        assert!(matches!(
            known_digest.classify_outer_result(actual_commit),
            Err(ManualRosterConstructionOuterErrorV3::ClaimMayExist(_))
        ));
        assert_eq!(known_digest.claim_digest(), Some(synthetic_digest.clone()));
        let error = claim_error(denied(), &known_digest, "synthetic-original-key");
        assert_eq!(error.details["construction_key"], "synthetic-original-key");
        assert_eq!(error.details["claim_digest"], synthetic_digest);
        assert_eq!(error.details["randomized_retry_allowed"], false);
        conn.execute_batch("ROLLBACK;").unwrap();
        drop(encrypted);
        let reopened = open_encrypted(&path, &key).unwrap();
        let count: i64 = reopened
            .connection()
            .query_row("SELECT COUNT(*) FROM component_marker", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            count, 2,
            "prior durable markers survive failed outer COMMIT"
        );
        let count: i64 = reopened
            .connection()
            .query_row("SELECT COUNT(*) FROM child", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}
