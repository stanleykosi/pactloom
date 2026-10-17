//! Purpose-distinct durable non-spending construction. Only the authenticated
//! native disclosure client can admit material; decoded DTOs cannot. Historical
//! material remains private data and never renews a native or writer capability.
#[path = "durable_construction_v1/review_export_v1.rs"]
pub mod review_export_v1;

use crate::proof_jobs::LocalCheckpoint;
use crate::{Access, ApiError, Engine, Envelope, Mutation, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, ProofJobStore};
use wholepact_protocol::{
    construction::{DisclosureAcknowledgement, DisclosureScope},
    proving::ProvingLimits,
};
use wholepact_signer::authority_bridge::durable_construction_v1::{
    AuthenticatedDurableConstructionDisclosureV1, DurableConstructionOutboxV1,
    DurableConstructionScopeV1,
};
use wholepact_wallet::wallet::protected_sync::{
    durable_construction_v1::{
        with_durable_construction_roster_v1, DurableConstructionError,
        DurableConstructionWalletSlotV1, FreshDurableConstructionObservationV1,
        HeldDurableConstructionRosterV1,
    },
    LocalWalletAccess, ProtectedWalletSync,
};

#[derive(Clone, Copy)]
pub enum DurableMaterialActionV1 {
    RetainAuthenticatedDisclosure,
    ReadForExactConstruction,
    ExportForLocalNativeReview,
}
/// Current local privacy/retention gate supplied by the trusted embedding. It
/// does not authenticate owner provenance and cannot replace native admission.
pub trait LocalDurableMaterialConsentV1 {
    fn permits(
        &self,
        scope: &DurableConstructionScopeV1,
        material_digest: &str,
        action: DurableMaterialActionV1,
    ) -> bool;
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intake {
    schema_version: u16,
    principal_id: String,
    metadata_origin: String,
    signer_enrollment_reference: String,
    signer_process_instance: String,
    outbox: DurableConstructionOutboxV1,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Roster {
    owners: BTreeMap<String, Intake>,
    #[serde(default)]
    review_exports: BTreeMap<String, review_export_v1::ExportIntent>,
}
fn damaged() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Original authenticated durable disclosure history is missing or inconsistent; preserve all original journals",
    )
}
fn denied() -> ApiError {
    ApiError::new(
        "DISCLOSURE_DENIED",
        "Current exact private-material permission, original destination or validity is unavailable",
    )
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| denied())
}
impl From<DurableConstructionError> for ApiError {
    fn from(_: DurableConstructionError) -> Self {
        ApiError::new(
            "DURABLE_CONSTRUCTION_UNAVAILABLE",
            "Exact original material or fresh all-input source eligibility failed; no replacement was selected",
        )
    }
}
pub(crate) fn validate_stored(envelope: &Envelope) -> Result<()> {
    for (id, value) in &envelope.durable_construction_v1 {
        let roster: Roster = serde_json::from_value(value.clone()).map_err(|_| damaged())?;
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|c| c.candidate_id == *id)
            .ok_or_else(damaged)?;
        if roster.owners.is_empty() || roster.owners.len() > 2 {
            return Err(damaged());
        }
        review_export_v1::validate_exports(&roster, candidate)?;
        review_export_v1::validate_export_identity(&roster, envelope.durable_proposals_v1.get(id))?;
        for (account, intake) in roster.owners {
            intake.outbox.validate().map_err(|_| damaged())?;
            let request = intake.outbox.request();
            if intake.schema_version != 1
                || !valid_digest(&intake.metadata_origin)
                || intake.principal_id.is_empty()
                || intake.principal_id.len() > 128
                || intake.signer_enrollment_reference.is_empty()
                || intake.signer_enrollment_reference.len() > 128
                || intake.signer_process_instance.is_empty()
                || intake.signer_process_instance.len() > 128
                || request.scope.account_id != account
                || request.scope.proposal != candidate.proposal
                || request.scope.constructor.principal_id != intake.principal_id
                || request.scope.prover.principal_id != intake.principal_id
            {
                return Err(damaged());
            }
        }
    }
    Ok(())
}
impl Engine {
    /// Admission consumes a sealed observation of actual authenticated native
    /// IPC. No overload accepts a serialized outbox, material or approval flag.
    #[allow(clippy::too_many_arguments)]
    pub fn intake_durable_construction_v1(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        disclosure: AuthenticatedDurableConstructionDisclosureV1,
        consent: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<Mutation> {
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let mut envelope = self.load(access, &view.agreement.agreement_id)?;
        crate::planning::check_proposer(&envelope, access)?;
        let outbox = disclosure.outbox();
        outbox.validate().map_err(|_| damaged())?;
        let scope = &outbox.request().scope;
        if scope.proposal != candidate.proposal
            || scope.constructor.principal_id != access.principal_id
            || scope.prover.principal_id != access.principal_id
        {
            return Err(denied());
        }
        let intake = Intake {
            schema_version: 1,
            principal_id: access.principal_id.clone(),
            metadata_origin: hex::encode(
                self.store
                    .verify_original_encrypted_destination(Path::new(&scope.protected_destination))
                    .map_err(crate::store_error)?,
            ),
            signer_enrollment_reference: disclosure.signer_enrollment_reference().into(),
            signer_process_instance: disclosure.signer_process_instance().into(),
            outbox: outbox.clone(),
        };
        self.check_durable_material(
            access,
            &intake,
            consent,
            DurableMaterialActionV1::RetainAuthenticatedDisclosure,
        )?;
        // Provider/process evidence is retained once as the original admission.
        // Already admitted data needs no old signer process. A restart before
        // intake instead requires a new linked native disclosure/outbox; exact
        // same-grant history cannot relabel the original process or recipient.
        let command = crate::context(
            access,
            key,
            "intake_durable_construction_v1",
            candidate_id,
            Some(revision),
            &(
                &intake.metadata_origin,
                outbox.reference(),
                outbox.request_digest(),
                outbox.material_digest(),
                disclosure.signer_enrollment_reference(),
            ),
        )?;
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        crate::candidates::check_revision(&envelope, revision)?;
        crate::candidates::check_current_terms(&envelope.view, &candidate.proposal.manifest)?;
        if envelope.view.cancellation_requested {
            return Err(denied());
        }
        let mut roster = self.durable_roster(&envelope, candidate_id)?;
        if roster.owners.contains_key(&scope.account_id)
            || envelope.durable_proposals_v1.contains_key(candidate_id)
            || !candidate.proof_jobs.is_empty()
        {
            return Err(ApiError::new(
                "CONFLICT",
                "Original account material is immutable and cannot be replaced after admission or construction",
            ));
        }
        if envelope.durable_construction_v1.len() >= 4
            && !envelope.durable_construction_v1.contains_key(candidate_id)
        {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "At most four bounded durable construction rosters may be retained per agreement",
            ));
        }
        self.check_durable_material(
            access,
            &intake,
            consent,
            DurableMaterialActionV1::RetainAuthenticatedDisclosure,
        )?;
        roster.owners.insert(scope.account_id.clone(), intake);
        envelope.durable_construction_v1.insert(
            candidate_id.into(),
            serde_json::to_value(roster).map_err(|_| damaged())?,
        );
        self.commit(
            &command,
            &view.agreement.agreement_id,
            revision,
            envelope,
            "durable_construction_disclosure_admitted",
        )
    }

    /// Fresh maintained public-block read for only an already-admitted exact
    /// material package. No original signer process or native decision is held.
    #[allow(clippy::too_many_arguments)]
    pub async fn observe_durable_construction_v1(
        &self,
        access: &Access,
        candidate_id: &str,
        account_id: &str,
        wallet: &mut ProtectedWalletSync,
        privacy: &dyn LocalDurableMaterialConsentV1,
        wallet_access: &impl LocalWalletAccess,
    ) -> Result<FreshDurableConstructionObservationV1> {
        let (view, _) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let envelope = self.load(access, &view.agreement.agreement_id)?;
        if envelope.view.cancellation_requested {
            return Err(denied());
        }
        let roster = self.durable_roster(&envelope, candidate_id)?;
        let intake = roster.owners.get(account_id).ok_or_else(damaged)?;
        self.check_durable_material(
            access,
            intake,
            privacy,
            DurableMaterialActionV1::ReadForExactConstruction,
        )?;
        let request = intake.outbox.request();
        let guarded_access = MaterialWalletGate {
            engine: self,
            access,
            candidate_id,
            intake,
            material: privacy,
            wallet: wallet_access,
        };
        let fresh = wallet
            .observe_durable_material_v1(&request.material, &request.scope, &guarded_access)
            .await?;
        self.check_durable_material(
            access,
            intake,
            privacy,
            DurableMaterialActionV1::ReadForExactConstruction,
        )?;
        Ok(fresh)
    }

    /// Joins both actual fresh wallet slots to original authenticated native
    /// receipts, holds maintained transactions, then uses the existing exact
    /// constructor+pre-effect checkpoint journal. No V3 capability is renewed.
    #[allow(clippy::too_many_arguments)]
    pub fn checkpoint_durable_construction_v1(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        slots: Vec<DurableConstructionWalletSlotV1<'_>>,
        jobs: &ProofJobStore,
        limits: ProvingLimits,
        proof_consent: &dyn LocalProofConsent,
        material_consent: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<Mutation> {
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let envelope = self.load(access, &view.agreement.agreement_id)?;
        if envelope.view.cancellation_requested {
            return Err(denied());
        }
        let roster = self.durable_roster(&envelope, candidate_id)?;
        if roster.owners.len() != 2 || slots.len() != 2 {
            return Err(denied());
        }
        let mut expected = BTreeSet::new();
        let mut declarations = Vec::new();
        for intake in roster.owners.values() {
            self.check_durable_material(
                access,
                intake,
                material_consent,
                DurableMaterialActionV1::ReadForExactConstruction,
            )?;
            let scope = &intake.outbox.request().scope;
            expected.insert((intake.outbox.material_digest().to_owned(), scope.digest()?));
            declarations.push(DisclosureAcknowledgement {
                account_id: scope.account_id.clone(),
                manifest_digest: hex::decode(&candidate.manifest_digest)
                    .map_err(|_| damaged())?
                    .try_into()
                    .map_err(|_| damaged())?,
                operator: scope.prover.principal_id.clone(),
                reviewer_account_ids: scope
                    .reviewers
                    .iter()
                    .map(|r| r.account_id().to_string())
                    .collect(),
                purpose: scope.purpose.clone(),
                retention_policy: scope.retention_policy.clone(),
                scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
            });
        }
        let actual: BTreeSet<_> = slots
            .iter()
            .map(|s| Ok((s.material_digest()?, s.scope_digest()?)))
            .collect::<Result<_>>()?;
        if actual.len() != 2 || actual != expected {
            return Err(damaged());
        }
        with_durable_construction_roster_v1(slots, |held, contributions, context| {
            let gate = ConstructionGate {
                engine: self,
                access,
                roster: &roster,
                held,
                proof: proof_consent,
                material: material_consent,
            };
            gate.check()?;
            let result = self.checkpoint_candidate_locally(
                access,
                key,
                candidate_id,
                revision,
                LocalCheckpoint {
                    construction: crate::candidates::LocalConstruction {
                        context,
                        contributions,
                        declarations: &declarations,
                    },
                    jobs,
                    limits,
                    consent: &gate,
                },
            );
            // Failure preserves any already-committed exact receipt/artifact.
            // The existing recovery path never reconstructs saved randomness.
            gate.check()?;
            result
        })
    }
    fn durable_roster(&self, envelope: &Envelope, candidate: &str) -> Result<Roster> {
        envelope
            .durable_construction_v1
            .get(candidate)
            .map(|v| serde_json::from_value(v.clone()).map_err(|_| damaged()))
            .unwrap_or_else(|| Ok(Roster::default()))
    }
    fn check_durable_material(
        &self,
        access: &Access,
        intake: &Intake,
        consent: &dyn LocalDurableMaterialConsentV1,
        action: DurableMaterialActionV1,
    ) -> Result<()> {
        let check = || -> Result<()> {
            intake.outbox.validate().map_err(|_| damaged())?;
            let scope = &intake.outbox.request().scope;
            scope.check_valid_at(now()?)?;
            if intake.principal_id != access.principal_id
                || hex::encode(
                    self.store
                        .verify_original_encrypted_destination(Path::new(
                            &scope.protected_destination,
                        ))
                        .map_err(crate::store_error)?,
                ) != intake.metadata_origin
            {
                return Err(denied());
            }
            Ok(())
        };
        check()?;
        if !consent.permits(
            &intake.outbox.request().scope,
            intake.outbox.material_digest(),
            action,
        ) {
            return Err(denied());
        }
        check()
    }
}
struct ConstructionGate<'a, 'g> {
    engine: &'a Engine,
    access: &'a Access,
    roster: &'a Roster,
    held: &'a HeldDurableConstructionRosterV1<'g>,
    proof: &'a dyn LocalProofConsent,
    material: &'a dyn LocalDurableMaterialConsentV1,
}
impl ConstructionGate<'_, '_> {
    fn check(&self) -> Result<()> {
        self.held.check_current()?;
        for intake in self.roster.owners.values() {
            self.engine.check_durable_material(
                self.access,
                intake,
                self.material,
                DurableMaterialActionV1::ReadForExactConstruction,
            )?;
        }
        self.held.check_current()?;
        Ok(())
    }
}
impl LocalProofConsent for ConstructionGate<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        self.check().is_ok() && self.proof.permits(scope, action) && self.check().is_ok()
    }
}

// Public-provider contact is itself a private action. A material permission
// revoked during an asynchronous scan must stop subsequent contact, not merely
// reject the completed result after disclosure has already happened.
struct MaterialWalletGate<'a, W> {
    engine: &'a Engine,
    access: &'a Access,
    candidate_id: &'a str,
    intake: &'a Intake,
    material: &'a dyn LocalDurableMaterialConsentV1,
    wallet: &'a W,
}
impl<W: LocalWalletAccess> MaterialWalletGate<'_, W> {
    fn current(&self) -> bool {
        let check = || -> Result<()> {
            let (view, _) = self.engine.candidate(self.access, self.candidate_id)?;
            self.engine
                .require_current_agreement(&view.agreement.agreement_id)?;
            if view.cancellation_requested {
                return Err(denied());
            }
            self.engine.check_durable_material(
                self.access,
                self.intake,
                self.material,
                DurableMaterialActionV1::ReadForExactConstruction,
            )
        };
        check().is_ok()
    }
}
impl<W: LocalWalletAccess> LocalWalletAccess for MaterialWalletGate<'_, W> {
    fn permits(
        &self,
        account: wholepact_wallet::wallet::AccountUuid,
        provider: &wholepact_wallet::wallet::protected_sync::BackendIdentity,
        purpose: wholepact_wallet::wallet::protected_sync::WalletAccessPurpose,
    ) -> bool {
        self.current() && self.wallet.permits(account, provider, purpose) && self.current()
    }
}
