//! Current-generation historical metadata only. Fresh native approvals precede
//! private claim reads and hold the exact final status delivery. No constructor,
//! original wallet, signer process, witness owner or expired approval is restored.
use super::*;
use crate::recovery_generation::construction_inspection_target::CurrentConstructionInspectionTargetV2;
use crate::terminal::historical::HistoricalApproval;
use wholepact_engine::manual_enrollment::{
    ManualRosterConstructionInspectionMetadataV2, PreparedManualRosterConstructionInspectionV2,
};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent};

struct NativeConstructionInspectionOwnersV2<'host> {
    host: &'host Host,
    committed: CurrentConstructionInspectionTargetV2<'host>,
    prepared: PreparedManualRosterConstructionInspectionV2,
}
impl NativeConstructionInspectionOwnersV2<'_> {
    fn check_current(&self) -> Result<()> {
        self.host.require_manual_session()?;
        self.committed.check_current()?;
        self.prepared.check_current(self.host.access()?)?;
        let saved = self.prepared.metadata();
        let actual = &saved.original_host;
        let primary = self.host.financial.as_ref().ok_or(Error::Locked)?;
        primary.inventory()?;
        let origin = primary
            .manual_original_primary_origin_digest(&self.host.directory, &self.host.secrets)?;
        if actual.generation_id != self.committed.generation_id()
            || actual.inventory_digest != self.committed.inventory_digest()
            || actual.generation_plan_digest != self.committed.plan_digest()
            || actual.profile_id != self.committed.profile_id()
            || actual.canonical_root != self.committed.canonical_root()
            || actual.destination_identity_digest != self.committed.destination_identity_digest()
            || actual.financial_journal_origin_digest != origin
            || actual.scope_predecessor_digest.is_some()
            || saved.checkpoint_destination != self.committed.canonical_root()
            || saved.principal_id != self.host.access()?.principal_id
        {
            return Err(Error::Authentication);
        }
        // The original primary anchor authenticates this held writer's canonical
        // directory and all four actual DB identities. No caller path is opened.
        self.committed.check_current()?;
        self.prepared
            .check_current(self.host.access()?)
            .map_err(Error::from)
    }
    fn metadata(&self) -> &ManualRosterConstructionInspectionMetadataV2 {
        self.prepared.metadata()
    }
}

/// This private native read owner is created only after the exact saved-scope
/// terminal review. permits never prompts or relocks the held terminal mutex.
struct NativeConstructionInspectionConsentV2<'a, 'host> {
    owners: &'a NativeConstructionInspectionOwnersV2<'host>,
    approval: &'a HistoricalApproval,
}
impl NativeConstructionInspectionConsentV2<'_, '_> {
    fn check(&self) -> Result<()> {
        self.approval.check()?;
        self.owners.check_current()?;
        self.approval.check()
    }
}
impl LocalProofConsent for NativeConstructionInspectionConsentV2<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        inspection_scope_matches(
            self.owners.metadata().saved_checkpoint_scope.as_ref(),
            scope,
            action,
        ) && self.check().is_ok()
    }
}
fn inspection_scope_matches(
    saved: Option<&CheckpointScope>,
    actual: &CheckpointScope,
    action: LocalAction,
) -> bool {
    action == LocalAction::InspectStatus && saved.is_some_and(|expected| expected == actual)
}

impl Host {
    pub(in crate::host) fn manual_roster_construction_inspect_v2_command(&self) -> Result<()> {
        self.require_manual_session()?;
        let agreement = self
            .terminal
            .ask("Exact original construction agreement ID: ")?;
        id(&agreement)?;
        let key = self
            .terminal
            .ask("Exact original construction key (never a replacement key): ")?;
        if !(16..=128).contains(&key.len()) || !key.bytes().all(|b| (33..=126).contains(&b)) {
            return Err(Error::Invalid);
        }
        let principal = self.access()?.principal_id.clone();
        let key_digest =
            wholepact_store::request_digest(&serde_json::json!([&principal, key.as_str()]))?;
        let primary = self.financial.as_ref().ok_or(Error::Locked)?;
        let actual_primary_directory = primary.current_directory()?;
        let initial = self.terminal.approve_historical(&format!(
            "Inspect the complete current coordination journal integrity, including retained original rows, monetary counters, exposures, reservations and recovery fences, and the complete bounded construction claim/checkpoint and related audit set, then select ONLY the exact original principal/agreement/key for local metadata inspection in this CURRENT authenticated generation.\nProfile: {}\nPrimary financial directory: {}\nPrincipal: {}\nAgreement: {}\nOriginal key commitment: {}\nThe protected records include original private selection facts and may include other local principals or agreements. Those coordination records are read only for complete-set integrity; only the selected claim supplies review metadata, and no inputs, nullifiers, values or witness bytes are displayed or exported. The sealed current-generation lineage and structural parent-capsule commitment are authenticated; archived financial ciphertext is hashed for integrity without opening ancestor financial journals or private artifact contents. Coordination and structural archive inspection use bounded private encrypted temporary copies outside this profile. The later exact-scope review separately authorizes a bounded encrypted copy of the primary proof journal for schema/integrity and status metadata inspection. Normal/error cleanup is attempted for every copy, but a crash or cleanup failure may leave encrypted remnants. This is not a secure-deletion guarantee. Saved inherited-identity and retirement data remain historical, without a new completeness or eligibility assertion. A separate exact-scope native review precedes proof-status metadata and final delivery. Missing, corrupt or ambiguous evidence never permits a new construction, proof, repair, signature or dispatch.",
            self.secrets.profile(), actual_primary_directory.display(), principal, agreement.as_str(), key_digest,
        ))?;
        let mut owners = None;
        initial.effect(&mut || {
            initial.check()?;
            self.require_manual_session()?;
            let committed =
                CurrentConstructionInspectionTargetV2::open(&self.directory, &self.secrets)?;
            let prepared =
                wholepact_engine::Engine::prepare_manual_roster_construction_inspection_v2(
                    committed.coordination_snapshot()?,
                    self.access()?,
                    &agreement,
                    &key,
                )?;
            let actual = NativeConstructionInspectionOwnersV2 {
                host: self,
                committed,
                prepared,
            };
            actual.check_current()?;
            initial.check()?;
            owners = Some(actual);
            Ok(())
        })?;
        let owners = owners.ok_or(Error::Authentication)?;
        initial.check()?;
        // This reviewed prompt checks the first approval on the same terminal
        // before it reveals the saved scope. It does not infer approval from JSON.
        let approval = self.terminal.approve_historical_reviewed(&initial, &format!(
            "Inspect and display ONLY the exact original claim/constructor-receipt/private-checkpoint metadata described below, once in this native command.\n{}\nThe immutable coordination snapshot and its original source identity remain held during this exact selected read. A bounded encrypted copy of the exact primary proof journal is captured now for complete schema/integrity checks and selected status metadata only; no private artifact values are exported or interpreted. Temporary encrypted remnants may survive a crash or cleanup failure. An absent constructor receipt authorizes no unexpected private-checkpoint scope. Original construction/source expiry remains historical, not renewed. Reported job state is an observed metadata snapshot. Any succeeded or proof_verified fields describe retained historical job-state metadata; this read does not open or verify proof bytes and does not establish current worker liveness or chain validity. This read cannot reconstruct private bytes, run or recover a proof worker, clear any fence, reserve, consume, sign, export or dispatch. Missing or mismatched evidence stays uncertain and randomized retry stays prohibited.",
            serde_json::to_string_pretty(owners.metadata())?,
        ))?;
        // Duplicate the SAME actual TTY before acquiring the effect lock. The
        // output helper never calls Terminal::json or asks a nested question.
        let output = self.terminal.historical_output()?;
        let consent = NativeConstructionInspectionConsentV2 {
            owners: &owners,
            approval: &approval,
        };
        approval.effect(&mut || {
            consent.check()?;
            let primary = self.financial.as_ref().ok_or(Error::Locked)?;
            let proof = primary.original_proof_status_snapshot()?;
            consent.check()?;
            let view = owners.prepared.inspect(self.access()?, &proof, &consent)?;
            let check_delivery = || {
                consent.check()?;
                proof
                    .check_source_unchanged()
                    .map_err(|_| Error::Authentication)?;
                consent.check()
            };
            check_delivery()?;
            output.json_checked(&view, check_delivery)?;
            consent.check()?;
            proof
                .check_source_unchanged()
                .map_err(|_| Error::Authentication)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> CheckpointScope {
        CheckpointScope {
            principal_id: "synthetic-principal".into(),
            candidate_id: "synthetic-candidate".into(),
            manifest_digest: "a".repeat(64),
            artifact_digest: "b".repeat(64),
            effects_commitment: "c".repeat(64),
            coordination_request_digest: "d".repeat(64),
            review_binding: "e".repeat(64),
            account_ids: vec!["synthetic-account".into()],
            local_operator: "synthetic-host".into(),
            purpose: "construct_one_candidate".into(),
            retention_policy: "synthetic-local-retention".into(),
        }
    }
    #[test]
    fn inspection_requires_exact_saved_receipt_scope_and_status_only() {
        let original = scope();
        assert!(inspection_scope_matches(
            Some(&original),
            &original,
            LocalAction::InspectStatus
        ));
        assert!(!inspection_scope_matches(
            None,
            &original,
            LocalAction::InspectStatus
        ));
        for action in [
            LocalAction::RetainPrivateWitnesses,
            LocalAction::ReadPrivateArtifact,
            LocalAction::ProveLocally,
            LocalAction::RecoverInterrupted,
        ] {
            assert!(!inspection_scope_matches(
                Some(&original),
                &original,
                action
            ));
        }
        let mut altered = original.clone();
        altered.artifact_digest = "f".repeat(64);
        assert!(!inspection_scope_matches(
            Some(&original),
            &altered,
            LocalAction::InspectStatus
        ));
        altered = original.clone();
        altered.account_ids.push("other-account".into());
        assert!(!inspection_scope_matches(
            Some(&original),
            &altered,
            LocalAction::InspectStatus
        ));
        altered = original.clone();
        altered.purpose = "prove_locally".into();
        assert!(!inspection_scope_matches(
            Some(&original),
            &altered,
            LocalAction::InspectStatus
        ));
    }
    #[test]
    fn disconnected_native_read_approval_never_reaches_private_read_or_output() {
        use std::cell::Cell;
        for expired in [false, true] {
            let denied = HistoricalApproval::denied_for_test(expired);
            let entered = Cell::new(false);
            assert!(denied
                .effect(&mut || {
                    entered.set(true);
                    Ok(())
                })
                .is_err());
            assert!(!entered.get());
        }
    }
}
