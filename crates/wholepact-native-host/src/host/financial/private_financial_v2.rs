//! Durable V2 local composition: independently current actions over exact retained results.
//! Legacy V1 functions are unchanged; no writer lifetime is renewed or bypassed.
//! Original private financial orchestration. Read/source permission, artifact
//! retention, actual signing and final dispatch are separate nominal purposes.
use super::Host;
use crate::host::durable_dispatcher_v2::OriginalFinancialOwnerV2;
use crate::terminal::historical::HistoricalApproval;
use crate::{Error, Result};
use wholepact_engine::durable_construction_v1::{
    DurableMaterialActionV1, LocalDurableMaterialConsentV1,
};
use wholepact_engine::{
    LocalPrivateDurableFinancialConsentV1, PrivateDurableFinancialInspectionV2,
    PrivateWorkspaceScopeV1,
};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent};
use wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionScopeV1;

#[cfg(all(test, feature = "synthetic-born-joined-qualification", feature = "durable-proposal"))]
#[path = "private_financial_v2/qualification_fault_v2.rs"]
mod qualification_fault_v2;

#[cfg(all(test, feature = "synthetic-born-joined-qualification", feature = "durable-proposal"))]
impl Host {
    pub(in crate::host) fn arm_durable_intake_ack_fault_v2(
        &self, account: &str, key: &str, original_outer_cutoff: std::time::Instant,
    ) -> Result<()> {
        self.require_private_workspace_read_session_v1()?;
        qualification_fault_v2::arm_once(account, key, original_outer_cutoff)
    }
}

// Diagnostics are erased outside the explicit synthetic qualification build.
macro_rules! financial_record {
    ($kind:ident, $stage:ident, $state:ident, $error:expr) => {{
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        crate::host::financial_diagnostics_v1::$kind(
            crate::host::financial_diagnostics_v1::FinancialStageV1::$stage,
            crate::host::financial_diagnostics_v1::FinancialCommitStateV1::$state,
            $error,
        );
    }};
}
macro_rules! financial_step {
    ($stage:ident, $state:ident) => {{
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        crate::host::financial_diagnostics_v1::set_stage(
            crate::host::financial_diagnostics_v1::FinancialStageV1::$stage,
            crate::host::financial_diagnostics_v1::FinancialCommitStateV1::$state,
        );
    }};
}
fn same<T: serde::Serialize>(left: &T, right: &T) -> bool {
    serde_json::to_vec(left)
        .ok()
        .zip(serde_json::to_vec(right).ok())
        .is_some_and(|(left, right)| left == right)
}
fn original_source_clocks_current(bounds: Option<(u64, u64)>) -> bool {
    let Some((from, until)) = bounds else { return false; };
    let Ok(elapsed) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else { return false; };
    let Ok(now) = u64::try_from(elapsed.as_millis()) else { return false; };
    original_source_clocks_at((from, until), now)
}
fn original_source_clocks_at((from, until): (u64, u64), now: u64) -> bool {
    from <= now && now < until
}
fn original_material_clocks_current(inspection: &PrivateDurableFinancialInspectionV2) -> Result<()> {
    if inspection.materials().len() != 2 { return Err(Error::Authentication); }
    let now = crate::now()?;
    if inspection.materials().iter().any(|m| now < m.scope().valid_from_unix_seconds || now >= m.scope().valid_until_unix_seconds) {
        return Err(Error::Permission);
    }
    Ok(())
}
fn original_materials_current(inspection: &PrivateDurableFinancialInspectionV2) -> Result<()> {
    if inspection.materials().len() != 2 {
        return Err(Error::Authentication);
    }
    let now = crate::now()?;
    for material in inspection.materials() {
        material
            .scope()
            .check_valid_at(now)
            .map_err(|_| Error::Permission)?;
    }
    Ok(())
}
/// No terminal or lazy review method. This exact read permission cannot export,
/// reserve, sign, extract, retain new results or dispatch. Engine pins separately
/// bind its pure mathematical verification to the actual original connection.
struct ClosedFinancialReadConsentV2<'a, 'host> {
    owner: &'a OriginalFinancialOwnerV2<'host>,
    inspection: &'a PrivateDurableFinancialInspectionV2,
    approval: &'a HistoricalApproval,
}
impl ClosedFinancialReadConsentV2<'_, '_> {
    fn check(&self) -> Result<()> {
        self.approval.check()?;
        self.owner.check_read_source()?;
        original_materials_current(self.inspection)?;
        if !same(
            self.owner.workspace_scope(),
            self.inspection.workspace_scope(),
        ) {
            return Err(Error::Authentication);
        }
        self.approval.check()
    }
}
fn financial_prompt_bounds(read: &ClosedFinancialReadConsentV2<'_, '_>, source: Option<(u64, u64)>) -> Result<Option<crate::terminal::OriginalPromptBoundsV1>> {
    if !crate::terminal::coordinated_restriction_required() { return Ok(None); }
    let materials = read.inspection.materials();
    if materials.len() != 2 { return Err(Error::Authentication); }
    let from = materials.iter().map(|m| m.scope().valid_from_unix_seconds).max().ok_or(Error::Authentication)?
        .checked_mul(1000).ok_or(Error::Permission)?;
    let until = materials.iter().map(|m| m.scope().valid_until_unix_seconds).min().ok_or(Error::Authentication)?
        .checked_mul(1000).ok_or(Error::Permission)?;
    let bounds = source.map_or((from, until), |(a, b)| (from.max(a), until.min(b)));
    Ok(Some(crate::terminal::OriginalPromptBoundsV1::new(read.approval.deadline(), bounds)?))
}
impl LocalPrivateDurableFinancialConsentV1 for ClosedFinancialReadConsentV2<'_, '_> {
    fn check_final_effect_restriction_v1(&self) -> bool {
        !crate::terminal::coordinated_restriction_required()
            || (original_material_clocks_current(self.inspection).is_ok() && self.approval.check().is_ok())
    }
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.inspection.workspace_scope()) && self.check().is_ok()
    }
}
impl LocalProofConsent for ClosedFinancialReadConsentV2<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        scope == self.inspection.checkpoint_scope()
            && matches!(
                action,
                LocalAction::InspectStatus | LocalAction::ReadPrivateArtifact
            )
            && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for ClosedFinancialReadConsentV2<'_, '_> {
    fn permits(
        &self,
        scope: &DurableConstructionScopeV1,
        digest: &str,
        action: DurableMaterialActionV1,
    ) -> bool {
        matches!(action, DurableMaterialActionV1::ReadForExactConstruction)
            && self
                .inspection
                .materials()
                .iter()
                .any(|m| m.scope() == scope && m.material_digest() == digest)
            && self.check().is_ok()
    }
}

/// An independently reviewed local financial step. It is neither a historical
/// read grant nor a final network-dispatch decision. Its private constructor is
/// the exact foreground Host command below; no remote effect uses this type.
struct ClosedFinancialPreparationConsentV2<'a, 'host> {
    read: &'a ClosedFinancialReadConsentV2<'a, 'host>,
    effect: &'a HistoricalApproval,
    original_bounds_ms: Option<(u64, u64)>,
}
impl LocalPrivateDurableFinancialConsentV1 for ClosedFinancialPreparationConsentV2<'_, '_> {
    fn check_final_effect_restriction_v1(&self) -> bool {
        !crate::terminal::coordinated_restriction_required()
            || (original_source_clocks_current(self.original_bounds_ms) && original_material_clocks_current(self.read.inspection).is_ok() && self.read.approval.check().is_ok() && self.effect.check().is_ok())
    }
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.read.inspection.workspace_scope())
            && self.read.check().is_ok()
            && self.read.owner.check_effect_source().is_ok()
            && self.effect.check().is_ok()
    }
}
struct OriginalCompletionRetentionV2<'a, 'read, 'host> {
    native: &'a crate::authority::retention::NativeFinancialRetentionConsentV1,
    effect: &'a ClosedFinancialPreparationConsentV2<'read, 'host>,
}
impl wholepact_protocol::authorization::retention::SignedRetentionConsent for OriginalCompletionRetentionV2<'_, '_, '_> {
    fn permits(&self, scope: &wholepact_protocol::authorization::retention::SignedRetentionScope) -> bool {
        wholepact_protocol::authorization::retention::SignedRetentionConsent::permits(self.native, scope)
            && self.effect.check_final_effect_restriction_v1()
    }
}
impl wholepact_protocol::authorization::retention::transaction::TransactionRetentionConsent for OriginalCompletionRetentionV2<'_, '_, '_> {
    fn permits(&self, scope: &wholepact_protocol::authorization::retention::transaction::TransactionRetentionScope) -> bool {
        wholepact_protocol::authorization::retention::transaction::TransactionRetentionConsent::permits(self.native, scope)
            && self.effect.check_final_effect_restriction_v1()
    }
    fn check_final_effect_restriction(&self) -> bool {
        wholepact_protocol::authorization::retention::transaction::TransactionRetentionConsent::check_final_effect_restriction(self.native)
            && self.effect.check_final_effect_restriction_v1()
    }
}
struct OriginalIntakeRetentionV2<'a, 'setup, 'host> {
    native: &'a crate::authority::retention::FrozenNativeSignedIntakeConsentV1,
    setup: &'a ClosedFinancialIntakeSetupV2<'setup, 'host>,
}
impl wholepact_protocol::authorization::retention::SignedRetentionConsent for OriginalIntakeRetentionV2<'_, '_, '_> {
    fn permits(&self, scope: &wholepact_protocol::authorization::retention::SignedRetentionScope) -> bool {
        wholepact_protocol::authorization::retention::SignedRetentionConsent::permits(self.native, scope)
            && self.setup.check_final_effect_restriction_v1()
    }
}
impl Host {
    pub(in crate::host) fn bind_original_financial_owner_v2(
        &self,
        root: &std::path::Path,
        key: &str,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<u64> {
        let histories = [history];
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            crate::id(key)?;
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v2(root).map_err(|error| {
                financial_record!(host, OriginalSource, NotEstablished, &error);
                financial_failure("ORIGINAL_SOURCE")
            })?;
            let inspection = owner.initial_inspection();
            financial_step!(ReadConsent, NotEstablished);
            let approval = self.terminal.approve_historical("Read this exact original saved fixed proof and the selected original financial continuation record. No signing, repair or dispatch is permitted by this read.")?;
            let read = ClosedFinancialReadConsentV2 {
                owner: &owner,
                inspection,
                approval: &approval,
            };
            financial_step!(EffectConsent, NotEstablished);
            let prompt_source = if crate::terminal::coordinated_restriction_required() {
                Some((
                    histories.iter().map(|h| { let t = &h.continuation_record().terms; t.valid_from_ms.max(t.scope.authorization.valid_from_ms) }).max().ok_or(Error::Authentication)?,
                    histories.iter().map(|h| { let t = &h.continuation_record().terms; t.valid_until_ms.min(t.scope.authorization.valid_until_ms) }).min().ok_or(Error::Authentication)?,
                ))
            } else { None };
            let prompt_bounds = financial_prompt_bounds(&read, prompt_source)?;
            let approval = self.terminal.approve_historical_original(&format!("Record this one authenticated owner financial continuation against this exact original fixed proposal {} at revision {}, command {}. This local association does not sign, reserve, extract or dispatch, and does not extend any owner deadline.", inspection.fixed_identity().proposal_id, inspection.revision(), key), prompt_bounds.as_ref())?;
            let effect = ClosedFinancialPreparationConsentV2 {
                read: &read,
                effect: &approval,
                original_bounds_ms: if crate::terminal::coordinated_restriction_required() {
                    Some((
                        histories.iter().map(|h| { let t = &h.continuation_record().terms; t.valid_from_ms.max(t.scope.authorization.valid_from_ms) }).max().ok_or(Error::Authentication)?,
                        histories.iter().map(|h| { let t = &h.continuation_record().terms; t.valid_until_ms.min(t.scope.authorization.valid_until_ms) }).min().ok_or(Error::Authentication)?,
                    ))
                } else { None },
            };
            financial_step!(ContinuationBinding, OutcomeUncertain);
            owner
                .coordinator()
                .bind_financial_owner_v2(
                    self.access()?,
                    key,
                    inspection.revision(),
                    history,
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, ContinuationBinding, OutcomeUncertain, &error);
                    financial_failure("CONTINUATION_BIND")
                })
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }

    pub(in crate::host) fn intake_original_financial_result_v2(
        &self, root: &std::path::Path, key: &str,
        receiver: wholepact_signer::authority_bridge::financial_continuation_v1::PreparedDurableFinancialResultReceiverV2,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<u64> {
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            use wholepact_engine::signature_intake::LocalSignedRetention;
            use wholepact_protocol::authorization::retention::SignedRetentionConsent;
            crate::id(key)?;
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v2(root).map_err(|error| {
                financial_record!(host, OriginalSource, NotEstablished, &error);
                financial_failure("ORIGINAL_SOURCE")
            })?;
            let inspection = owner.initial_inspection();
            financial_step!(ReadConsent, NotEstablished);
            let read_approval = self.terminal.approve_historical("Read the exact original financial fixed proof and existing intake lineage for protected signer-result verification. No missing result may be regenerated.")?;
            let read = ClosedFinancialReadConsentV2 {
                owner: &owner,
                inspection,
                approval: &read_approval,
            };
            financial_step!(EffectConsent, NotEstablished);
            let prompt_source = if crate::terminal::coordinated_restriction_required() {
                let t = &history.continuation_record().terms;
                Some((t.valid_from_ms.max(t.scope.authorization.valid_from_ms), t.valid_until_ms.min(t.scope.authorization.valid_until_ms)))
            } else { None };
            let prompt_bounds = financial_prompt_bounds(&read, prompt_source)?;
            let effect_approval = self.terminal.approve_historical_original(&format!("Verify and retain one actual authenticated original signer result for fixed proposal {}, revision {}, command {}. The installed protected receive route and original source provenance must match. This cannot invoke signing or extract a transaction.", inspection.fixed_identity().proposal_id, inspection.revision(), key), prompt_bounds.as_ref())?;
            let effect = ClosedFinancialPreparationConsentV2 {
                read: &read,
                effect: &effect_approval,
                original_bounds_ms: None,
            };
            let scope = inspection.checkpoint_scope();
            financial_step!(SignedRetentionApproval, NotEstablished);
            let retention = self.authority.retention_consent(
                &scope.principal_id,
                &scope.candidate_id,
                &scope.manifest_digest,
                inspection.proof_job_id(),
                scope.account_ids.iter().cloned().collect(),
            )?;
            let financial = self.financial.as_ref().ok_or(Error::Locked)?;
            financial_step!(SourcePreparation, NotEstablished);
            let prepared = owner
                .coordinator()
                .prepare_original_financial_v2(self.access()?, &effect, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, SourcePreparation, NotEstablished, &error);
                    financial_failure("FIXED_SOURCE_VERIFICATION")
                })?;
            let effect = ClosedFinancialPreparationConsentV2 {
                original_bounds_ms: if crate::terminal::coordinated_restriction_required() {
                    Some(prepared.original_financial_clock_bounds_ms_v2()?)
                } else { None },
                ..effect
            };
            let prompt_bounds = financial_prompt_bounds(&read, effect.original_bounds_ms)?;
            let retention = if let Some(bounds) = prompt_bounds { retention.bind_original_prompt_bounds(bounds)? } else { retention };
            financial_step!(ResultPreview, NotEstablished);
            let expected_scope = prepared
                .financial_result_retention_scope_v2(
                    receiver.preview(),
                    self.access()?,
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, ResultPreview, NotEstablished, &error);
                    financial_failure("RESULT_PREFLIGHT")
                })?;
            financial_step!(SignedRetentionApproval, NotEstablished);
            if !SignedRetentionConsent::permits(&retention, &expected_scope) {
                return Err(Error::Permission);
            }
            let original_until = inspection
                .materials()
                .iter()
                .map(|m| m.scope().valid_until_unix_seconds)
                .chain(std::iter::once(
                    prepared
                        .original_financial_valid_until_ms_v2()
                        .map_err(|error| {
                            financial_record!(engine, Currentness, NotEstablished, &error);
                            error
                        })?
                        / 1000,
                ))
                .min()
                .ok_or(Error::Authentication)?;
            financial_step!(IntakeSetupApproval, NotEstablished);
            let setup_approval = self
                .terminal
                .approve_financial_intake_setup_original_v1(&expected_scope, original_until, prompt_bounds.as_ref())?;
            let setup = ClosedFinancialIntakeSetupV2 {
                owner: &owner,
                inspection,
                approval: &setup_approval,
                exact_scope: &expected_scope,
                original_bounds_ms: effect.original_bounds_ms,
            };
            financial_step!(RetentionFreeze, NotEstablished);
            let retention = retention.freeze_for_signed_intake()?;
            let restricted_retention = OriginalIntakeRetentionV2 { native: &retention, setup: &setup };
            drop(effect);
            drop(read);
            drop(effect_approval);
            drop(read_approval);
            let source = original_result_material_bounds(
                inspection, prepared.original_financial_clock_bounds_ms_v2()?,
            )?;
            let receiver = receiver.bind_intake_restriction_v2(Box::new(DurableResultIoRestrictionV2 {
                bounds: setup_approval.durable_restriction_bounds_v2(source)?,
            })).map_err(|_| Error::Permission)?;
            // Only now may the independently approved Signer ReturnExact begin.
            // All later gates are closed; no Host human wait consumes its lease.
            financial_step!(ResultReceive, NotEstablished);
            let delivery = receiver.receive().map_err(|error| {
                financial_record!(bridge, ResultReceive, NotEstablished, &error);
                financial_failure("RESULT_RECEIVE")
            })?;
            financial_step!(AuthenticatedIntake, OutcomeUncertain);
            let revision = prepared
                .intake_original_signature_v2(
                    self.access()?,
                    key,
                    &delivery,
                    history,
                    LocalSignedRetention {
                        journal: &financial.signed,
                        consent: &restricted_retention,
                    },
                    &setup,
                    &setup,
                    &setup,
                )
                .map_err(|error| {
                    financial_record!(engine, AuthenticatedIntake, OutcomeUncertain, &error);
                    financial_failure("AUTHENTICATED_INTAKE")
                })?;
            #[cfg(all(test, feature = "synthetic-born-joined-qualification", feature = "durable-proposal"))]
            qualification_fault_v2::after_committed_intake(delivery.account_id(), key)?;
            financial_step!(ResultFinishAcknowledgement, IntakeCommitted);
            delivery.finish().map_err(|error| {
                financial_record!(bridge, ResultFinishAcknowledgement, IntakeCommitted, &error);
                financial_failure("RESULT_FINISH_ACKNOWLEDGEMENT")
            })?;
            Ok(revision)
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }

    pub(in crate::host) fn complete_original_financial_transaction_v2(
        &self,
        root: &std::path::Path,
        key: &str,
    ) -> Result<
        wholepact_protocol::authorization::retention::transaction::TransactionCheckpointSummary,
    > {
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            use wholepact_engine::signature_intake::LocalSignedRetention;
            use wholepact_protocol::authorization::retention::transaction::LocalTransactionCheckpoint;
            crate::id(key)?;
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v2(root).map_err(|error| {
                financial_record!(host, OriginalSource, NotEstablished, &error);
                financial_failure("ORIGINAL_SOURCE")
            })?;
            let inspection = owner.initial_inspection();
            financial_step!(ReadConsent, NotEstablished);
            let approval = self.terminal.approve_historical("Read and verify the exact two retained financial signer results and original proof. Incomplete or uncertain result lineage remains fenced.")?;
            let read = ClosedFinancialReadConsentV2 {
                owner: &owner,
                inspection,
                approval: &approval,
            };
            financial_step!(EffectConsent, NotEstablished);
            let prompt_bounds = financial_prompt_bounds(&read, None)?;
            let approval = self.terminal.approve_historical_original(&format!("Combine only the two exact retained original signature subsets for proposal {}, revision {}, command {}, then create its single immutable completed transaction checkpoint. An existing extraction intent without a result is RecoveryRequired, never permission to re-extract. This performs no network submission.", inspection.fixed_identity().proposal_id, inspection.revision(), key), prompt_bounds.as_ref())?;
            let effect = ClosedFinancialPreparationConsentV2 {
                read: &read,
                effect: &approval,
                original_bounds_ms: None,
            };
            let financial = self.financial.as_ref().ok_or(Error::Locked)?;
            financial_step!(SourcePreparation, NotEstablished);
            let prepared = owner
                .coordinator()
                .prepare_original_financial_v2(self.access()?, &effect, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, SourcePreparation, NotEstablished, &error);
                    financial_failure("FIXED_SOURCE_VERIFICATION")
                })?;
            let effect = ClosedFinancialPreparationConsentV2 {
                original_bounds_ms: if crate::terminal::coordinated_restriction_required() {
                    Some(prepared.original_financial_clock_bounds_ms_v2()?)
                } else { None },
                ..effect
            };
            financial_step!(RetentionContexts, NotEstablished);
            let contexts = prepared
                .financial_retention_contexts_v2(self.access()?, &effect, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, RetentionContexts, NotEstablished, &error);
                    financial_failure("RETENTION_CONTEXTS")
                })?;
            financial_step!(SignedRetentionApproval, NotEstablished);
            let retention = self.authority.financial_retention_consent_v1(&contexts)?;
            let prompt_bounds = if crate::terminal::coordinated_restriction_required() {
                financial_prompt_bounds(&read, Some(prepared.original_financial_clock_bounds_ms_v2()?))?
            } else { None };
            let retention = if let Some(bounds) = prompt_bounds { retention.bind_original_prompt_bounds(bounds)? } else { retention };
            let restricted_retention = OriginalCompletionRetentionV2 { native: &retention, effect: &effect };
            financial_step!(UnionRetention, OutcomeUncertain);
            prepared
                .retain_original_union_v2(
                    self.access()?,
                    key,
                    LocalSignedRetention {
                        journal: &financial.signed,
                        consent: &restricted_retention,
                    },
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, UnionRetention, OutcomeUncertain, &error);
                    financial_failure("UNION_RETENTION")
                })?;
            // Reload only after our own successful append. The coordinator audits the
            // complete bounded lineage; no stale prepared pin is silently refreshed.
            financial_step!(SourcePreparation, NotEstablished);
            let prepared = owner
                .coordinator()
                .prepare_original_financial_v2(self.access()?, &effect, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, SourcePreparation, NotEstablished, &error);
                    financial_failure("FIXED_SOURCE_VERIFICATION")
                })?;
            financial_step!(TransactionCheckpoint, OutcomeUncertain);
            prepared
                .checkpoint_original_transaction_v2(
                    self.access()?,
                    LocalSignedRetention {
                        journal: &financial.signed,
                        consent: &restricted_retention,
                    },
                    LocalTransactionCheckpoint {
                        journal: &financial.transactions,
                        consent: &restricted_retention,
                    },
                    &effect,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, TransactionCheckpoint, OutcomeUncertain, &error);
                    financial_failure("EXTRACTION_CHECKPOINT")
                })
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }
}

fn financial_failure(stage: &'static str) -> Error {
    Error::Receipt(format!(
        "FINANCIAL_{stage}: preserve original journals and reconcile exact retained operations; do not regenerate or infer non-delivery"
    ))
}

impl Host {
    pub(in crate::host) fn read_original_financial_history_v2(
        &self, root: &std::path::Path, account: &str, continuation_operation: &str,
    ) -> Result<wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1>{
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v2(root)?;
            financial_step!(ReadConsent, NotEstablished);
            let approval = self.terminal.approve_historical("Read the complete authenticated original financial Witness history through the planned dispatcher, including exact partial/uncertain dispatch outcomes. This read cannot append a request or recreate a live admission or old Host decision.")?;
            financial_step!(FinancialHistory, NotEstablished);
            owner.financial_history_v2(account, continuation_operation, &approval)
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }
}

/// Closed setup for exactly one pre-reviewed signature intake. It is not usable
/// by the union, extraction or dispatch compositions, and exposes no terminal.
struct ClosedFinancialIntakeSetupV2<'a, 'host> {
    owner: &'a OriginalFinancialOwnerV2<'host>,
    inspection: &'a PrivateDurableFinancialInspectionV2,
    approval: &'a crate::terminal::historical::FinancialIntakeSetupApprovalV1,
    exact_scope: &'a wholepact_protocol::authorization::retention::SignedRetentionScope,
    original_bounds_ms: Option<(u64, u64)>,
}
impl ClosedFinancialIntakeSetupV2<'_, '_> {
    fn check(&self) -> Result<()> {
        self.approval.require_scope(self.exact_scope)?;
        self.owner.check_effect_source()?;
        original_materials_current(self.inspection)?;
        if !same(
            self.owner.workspace_scope(),
            self.inspection.workspace_scope(),
        ) {
            return Err(Error::Authentication);
        }
        self.approval.check()
    }
}
impl LocalPrivateDurableFinancialConsentV1 for ClosedFinancialIntakeSetupV2<'_, '_> {
    fn check_final_effect_restriction_v1(&self) -> bool {
        !crate::terminal::coordinated_restriction_required()
            || (original_source_clocks_current(self.original_bounds_ms) && original_material_clocks_current(self.inspection).is_ok() && self.approval.check().is_ok())
    }
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.inspection.workspace_scope()) && self.check().is_ok()
    }
}
impl LocalProofConsent for ClosedFinancialIntakeSetupV2<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        scope == self.inspection.checkpoint_scope()
            && matches!(
                action,
                LocalAction::InspectStatus | LocalAction::ReadPrivateArtifact
            )
            && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for ClosedFinancialIntakeSetupV2<'_, '_> {
    fn permits(
        &self,
        scope: &DurableConstructionScopeV1,
        digest: &str,
        action: DurableMaterialActionV1,
    ) -> bool {
        matches!(action, DurableMaterialActionV1::ReadForExactConstruction)
            && self
                .inspection
                .materials()
                .iter()
                .any(|m| m.scope() == scope && m.material_digest() == digest)
            && self.check().is_ok()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(in crate::host) struct CompletedPrivateFinancialSummaryV2 {
    pub checkpoint_id: String,
    pub transaction_digest: String,
    pub transaction_id: String,
    pub fixed_identity: serde_json::Value,
    pub frozen_export_history_digest: String,
    pub original_valid_until_ms: u64,
}
impl Host {
    /// Inert audit output from the same completed-only production verification.
    /// The operation claim is checked against both actual bound continuations.
    pub(in crate::host) fn verify_completed_private_financial_summary_v2(
        &self,
        root: &std::path::Path,
        operation: &str,
    ) -> Result<CompletedPrivateFinancialSummaryV2> {
        self.completed_private_financial_summary_kernel_v2(root, operation, false)
    }
    /// Concrete coordinated disclosure under the same genuine completed-only
    /// Read and original source owner; never accepts a detached summary DTO.
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(in crate::host) fn display_completed_private_financial_summary_v2(
        &self, root: &std::path::Path, operation: &str,
    ) -> Result<()> {
        if !crate::terminal::coordinated_restriction_required() { return Err(Error::Permission); }
        self.completed_private_financial_summary_kernel_v2(root, operation, true).map(|_| ())
    }
    fn completed_private_financial_summary_kernel_v2(
        &self, root: &std::path::Path, operation: &str, display: bool,
    ) -> Result<CompletedPrivateFinancialSummaryV2> {
        financial_step!(InputValidation, NotEstablished);
        let result = (|| -> Result<_> {
            use wholepact_engine::signature_intake::LocalSignedRetention;
            use wholepact_protocol::authorization::retention::transaction::LocalTransactionCheckpoint;
            financial_step!(OriginalSource, NotEstablished);
            let owner = self.original_financial_owner_v2(root)?;
            let inspection = owner.initial_inspection();
            financial_step!(ReadConsent, NotEstablished);
            let approval = self.terminal.approve_historical(if display {
                "Read, verify and locally display the exact completed original financial transaction and retained dispatch lineage as an inert audit summary. This cannot repair, extract, renew an admission or send a request."
            } else {
                "Read and verify the exact completed original financial transaction and retained dispatch lineage for an inert audit summary. This cannot repair, extract, renew an admission or send a request."
            })?;
            let read = ClosedFinancialReadConsentV2 {
                owner: &owner,
                inspection,
                approval: &approval,
            };
            let financial = self.financial.as_ref().ok_or(Error::Locked)?;
            financial_step!(SourcePreparation, NotEstablished);
            let prepared = owner
                .coordinator()
                .prepare_original_financial_v2(self.access()?, &read, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, SourcePreparation, NotEstablished, &error);
                    error
                })?;
            financial_step!(RetentionContexts, NotEstablished);
            let contexts = prepared
                .financial_retention_contexts_v2(self.access()?, &read, &read, &read)
                .map_err(|error| {
                    financial_record!(engine, RetentionContexts, NotEstablished, &error);
                    financial_failure("RETENTION_CONTEXTS")
                })?;
            financial_step!(SignedRetentionApproval, NotEstablished);
            let retention = self.authority.financial_retention_consent_v1(&contexts)?;
            let prompt_bounds = if crate::terminal::coordinated_restriction_required() {
                financial_prompt_bounds(&read, Some(prepared.original_financial_clock_bounds_ms_v2()?))?
            } else { None };
            let retention = if let Some(bounds) = prompt_bounds { retention.bind_original_prompt_bounds(bounds)? } else { retention };
            financial_step!(CompletedVerification, NotEstablished);
            let verified = prepared
                .verify_completed_submission_v2(
                    self.access()?,
                    operation,
                    LocalSignedRetention {
                        journal: &financial.signed,
                        consent: &retention,
                    },
                    LocalTransactionCheckpoint {
                        journal: &financial.transactions,
                        consent: &retention,
                    },
                    &read,
                    &read,
                    &read,
                )
                .map_err(|error| {
                    financial_record!(engine, CompletedVerification, NotEstablished, &error);
                    error
                })?;
            financial_step!(AuditSummary, NotEstablished);
            read.check()?;
            let summary = CompletedPrivateFinancialSummaryV2 {
                checkpoint_id: verified.retained().checkpoint_id(),
                transaction_digest: verified.retained().descriptor().bytes_sha256.clone(),
                transaction_id: verified.retained().descriptor().transaction_id.clone(),
                fixed_identity: serde_json::to_value(verified.retained().fixed_identity())?,
                frozen_export_history_digest: inspection.frozen_export_history_digest.clone(),
                original_valid_until_ms: prepared.original_financial_valid_until_ms_v2().map_err(
                    |error| {
                        financial_record!(engine, Currentness, NotEstablished, &error);
                        error
                    },
                )?,
            };
            if display {
                let bounds = financial_prompt_bounds(
                    &read, Some(prepared.original_financial_clock_bounds_ms_v2()?),
                )?.ok_or(Error::Permission)?;
                let output = self.terminal.historical_output()?;
                read.check()?;
                approval.effect(&mut || output.json_checked_original(
                    &summary, || read.check(), &approval, &bounds,
                ))?;
                read.check()?;
            }
            Ok(summary)
        })();
        #[cfg(all(
            test,
            feature = "synthetic-born-joined-qualification",
            feature = "durable-proposal"
        ))]
        if let Err(error) = &result {
            crate::host::financial_diagnostics_v1::host_current(error);
        }
        result
    }
}


// The new return channel retains original policy/material ceilings, not an old
// writer lease. Actual native Read and Return permissions remain independent.
struct DurableResultIoRestrictionV2 {
    bounds: crate::terminal::OriginalPromptBoundsV1,
}
impl wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRestrictionV1
    for DurableResultIoRestrictionV2
{
    fn check_before_io(&self) -> wholepact_signer::authority_bridge::Result<()> {
        self.bounds.check()
            .and_then(|()| crate::terminal::check_original_coordinator_restriction())
            .map_err(|_| wholepact_signer::authority_bridge::BridgeError::Permission)
    }
}
fn original_result_material_bounds(
    inspection: &PrivateDurableFinancialInspectionV2, source: (u64, u64),
) -> Result<(u64, u64)> {
    if inspection.materials().len() != 2 { return Err(Error::Authentication); }
    let from = inspection.materials().iter().map(|m| m.scope().valid_from_unix_seconds)
        .max().ok_or(Error::Authentication)?.checked_mul(1000).ok_or(Error::Permission)?;
    let until = inspection.materials().iter().map(|m| m.scope().valid_until_unix_seconds)
        .min().ok_or(Error::Authentication)?.checked_mul(1000).ok_or(Error::Permission)?;
    Ok((from.max(source.0), until.min(source.1)))
}
fn original_result_deadline_v2(from_ms: u64, until_ms: u64) -> Result<std::time::Instant> {
    // Snapshot monotonic first: never extend an authenticated wall ceiling by
    // moving work before the conversion or issuing a fresh relative lifetime.
    let monotonic = std::time::Instant::now();
    let now = u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Permission)?.as_millis()).map_err(|_| Error::Permission)?;
    if now < from_ms || now >= until_ms { return Err(Error::Permission); }
    monotonic.checked_add(std::time::Duration::from_millis(until_ms - now))
        .ok_or(Error::Permission)
}
impl Host {
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    pub(in crate::host) fn qualification_original_financial_history_commitment_v2(
        &self, root: &std::path::Path,
    ) -> Result<(u64, String)> {
        let owner = self.original_financial_owner_v2(root)?;
        let approval = self.terminal.approve_historical(
            "Read the exact original durable V2 history commitment only. This cannot sign, acquire, export, retry a transport or complete a transaction.")?;
        let read = ClosedFinancialReadConsentV2 { owner: &owner,
            inspection: owner.initial_inspection(), approval: &approval };
        let result = owner.coordinator().qualification_history_commitment_v2(self.access()?, &read)?;
        read.check()?;
        Ok(result)
    }

    pub(in crate::host) fn inspect_original_financial_progress_v2(
        &self, root: &std::path::Path,
    ) -> Result<PrivateDurableFinancialInspectionV2> {
        let owner = self.original_financial_owner_v2(root)?;
        let approval = self.terminal.approve_historical(
            "Read the exact original durable V2 progress only. Zero or one retained owner is incomplete. This cannot sign, acquire, export, retry a transport or complete a transaction.")?;
        let read = ClosedFinancialReadConsentV2 { owner: &owner,
            inspection: owner.initial_inspection(), approval: &approval };
        let result = owner.coordinator().inspect_original_financial_v2(self.access()?, &read)?;
        read.check()?;
        Ok(result)
    }

    pub(in crate::host) fn prepare_durable_financial_preview_v2(
        &self, root: &std::path::Path, socket: &std::path::Path,
        request: &wholepact_signer::authority_bridge::financial_continuation_v1::DurableFinancialResultRequestV2,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<wholepact_signer::authority_bridge::financial_continuation_v1::PreparedDurableFinancialResultReceiverV2> {
        self.prepare_durable_financial_preview_kernel_v2(root, socket, request, history, || {
            wholepact_signer::authority_bridge::provider::InstalledSignerProvider::load().map_err(|_| Error::Permission)
        })
    }

    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    pub(in crate::host) fn prepare_durable_financial_preview_with_provider_v2(
        &self, root: &std::path::Path, socket: &std::path::Path,
        request: &wholepact_signer::authority_bridge::financial_continuation_v1::DurableFinancialResultRequestV2,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        provider: wholepact_signer::authority_bridge::provider::InstalledSignerProvider,
    ) -> Result<wholepact_signer::authority_bridge::financial_continuation_v1::PreparedDurableFinancialResultReceiverV2> {
        self.prepare_durable_financial_preview_kernel_v2(root, socket, request, history, || Ok(provider))
    }

    fn prepare_durable_financial_preview_kernel_v2(
        &self, root: &std::path::Path, socket: &std::path::Path,
        request: &wholepact_signer::authority_bridge::financial_continuation_v1::DurableFinancialResultRequestV2,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        load_provider: impl FnOnce() -> Result<wholepact_signer::authority_bridge::provider::InstalledSignerProvider>,
    ) -> Result<wholepact_signer::authority_bridge::financial_continuation_v1::PreparedDurableFinancialResultReceiverV2> {
        use wholepact_signer::authority_bridge::financial_continuation_v1::PreparedDurableFinancialResultReceiverV2;
        let owner = self.original_financial_owner_v2(root)?;
        let inspection = owner.initial_inspection();
        let terms = &history.continuation_record().terms;
        if request.request.fixed != *inspection.fixed_identity()
            || request.request.account_id != terms.scope.authorization.identity.account_id
            || request.request.authorization_id != terms.scope.authorization.authorization_id
        { return Err(Error::Authentication); }
        let source = original_result_material_bounds(inspection, (
            terms.valid_from_ms.max(terms.scope.authorization.valid_from_ms),
            terms.valid_until_ms.min(terms.scope.authorization.valid_until_ms),
        ))?;
        let deadline = original_result_deadline_v2(source.0, source.1)?;
        let bounds = crate::terminal::OriginalPromptBoundsV1::new(deadline, source)?;
        let approval = self.terminal.approve_historical_original(
            "Read ONLY exact V2 retained-result preview metadata from this currently installed authenticated Signer. Match the original account, proposal, authorization, full result/outbox and recipient. This does not authorize result bytes, signing, reservation, extraction or network dispatch. A separate fresh ReturnExact and closed intake decision are required.",
            Some(&bounds),
        )?;
        let read = ClosedFinancialReadConsentV2 { owner: &owner, inspection, approval: &approval };
        let preview_read = DurableResultIoRestrictionV2 { bounds: bounds.narrow_deadline(approval.deadline()) };
        read.check()?;
        let provider = load_provider()?;
        let receiver = PreparedDurableFinancialResultReceiverV2::prepare(
            provider, socket, request, deadline,
            Box::new(DurableResultIoRestrictionV2 { bounds }), &preview_read,
        ).map_err(|_| financial_failure("V2_RESULT_PREVIEW"))?;
        read.check()?;
        Ok(receiver)
    }
}
