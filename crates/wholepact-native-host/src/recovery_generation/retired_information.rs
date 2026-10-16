//! Separate review-only route. This module never changes publication manifests,
//! active continuity, local restrictions, retained obligations or generation state.
//! No command/IPC caller is wired: a saved audit DTO cannot create its admission.
use super::*;
use wholepact_authority::{WitnessDisclosureDescriptor, account_use::AccountUseGenesis};
use wholepact_signer::authority_bridge::retired_history::{
    RetiredHistoryAuditRecord, RetiredHistoryDisclosureAdmission, RetiredHistoryRequest,
};

/// Inert historical display for one exact account/inventory. No Deserialize,
/// financial/publication conversion or durable write method exists.
pub(crate) struct RetiredInventoryAudit {
    record: RetiredHistoryAuditRecord,
}
impl RetiredInventoryAudit {
    pub(crate) fn record(&self) -> &RetiredHistoryAuditRecord {
        &self.record
    }
}
fn require_exact_plan(
    plan: &Plan,
    plan_digest: &str,
    request: &RetiredHistoryRequest,
) -> Result<()> {
    request.validate().map_err(|_| Error::Authentication)?;
    if plan.version != 1
        || !plan.unknown_external_signatures
        || !plan.recovered_obligations_fenced
        || plan.generation_id != request.generation_id
        || plan.inventory_digest != request.inventory_digest
        || plan.semantic_inventory_digest != request.semantic_inventory_digest
        || plan_digest != request.plan_digest
        || plan.target != request.target_profile
        || !plan
            .affected_accounts
            .contains(&request.expected_genesis.identity.account_id)
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
impl ConstructedGeneration {
    /// Uses the host-owned sealed plan and rechecks its complete source inventory.
    /// The genesis/origin inputs are requests, not accepted proof of provenance.
    pub(crate) fn retired_history_request(
        &self,
        expected_genesis: AccountUseGenesis,
        original_witness: WitnessDisclosureDescriptor,
    ) -> Result<RetiredHistoryRequest> {
        let p = &self.pending;
        p.source.check()?;
        if crate::recovery_semantics::inspect(&p.source)?.digest()
            != p.plan.semantic_inventory_digest
        {
            return Err(Error::Authentication);
        }
        let request = RetiredHistoryRequest {
            schema_version: 1,
            inventory_digest: p.plan.inventory_digest.clone(),
            semantic_inventory_digest: p.plan.semantic_inventory_digest.clone(),
            generation_id: p.plan.generation_id.clone(),
            plan_digest: p.plan_digest.clone(),
            target_profile: p.plan.target.clone(),
            expected_genesis,
            original_witness,
        };
        require_exact_plan(&p.plan, &p.plan_digest, &request)?;
        Ok(request)
    }
    /// This in-process typed boundary is intentionally uncalled. A future
    /// authenticated disclosure transport must preserve exact native recipient
    /// ownership; deserialized audit data must never be upgraded into admission.
    /// It confers no eligibility to publish even an informational generation.
    pub(crate) fn review_retired_history(
        &self,
        exact: &RetiredHistoryRequest,
        admission: RetiredHistoryDisclosureAdmission<'_>,
    ) -> Result<RetiredInventoryAudit> {
        let p = &self.pending;
        p.source.check()?;
        if crate::recovery_semantics::inspect(&p.source)?.digest()
            != p.plan.semantic_inventory_digest
        {
            return Err(Error::Authentication);
        }
        require_exact_plan(&p.plan, &p.plan_digest, exact)?;
        let record = admission
            .into_audit_for(exact)
            .map_err(|_| Error::Authentication)?;
        p.source.check()?;
        Ok(RetiredInventoryAudit { record })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Plain data predicate fixtures; no source Inventory, native decision,
    // reconciled witness, generation owner or disclosure admission is fabricated.
    fn data() -> (Plan, String, RetiredHistoryRequest) {
        use wholepact_authority::account_use::{AccountUseGenesis, AccountUseIdentity};
        let descriptor = WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:443".into(),
            server_name: "witness.example".into(),
            witness_id: "witness-a".into(),
            account_id: "a".repeat(64),
            network_profile_id: "ironwood-testnet-nu7-candidate".into(),
            policy_digest: "b".repeat(64),
            pinned_server_certificate_digest: "c".repeat(64),
        };
        let genesis = AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: descriptor.account_id.clone(),
                full_viewing_key_digest: "d".repeat(64),
                network_profile_id: descriptor.network_profile_id.clone(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: descriptor.witness_id.clone(),
            witness_origin_digest:
                wholepact_authority::account_use_link::account_use_witness_origin_digest(
                    &descriptor,
                )
                .unwrap(),
            owner_certificate_digest: "e".repeat(64),
            native_birth_digest: "f".repeat(64),
        };
        let request = RetiredHistoryRequest {
            schema_version: 1,
            inventory_digest: "1".repeat(64),
            semantic_inventory_digest: "2".repeat(64),
            generation_id: "3".repeat(64),
            plan_digest: "4".repeat(64),
            target_profile: "/private/successor".into(),
            expected_genesis: genesis,
            original_witness: descriptor,
        };
        let plan = Plan {
            version: 1,
            generation_id: request.generation_id.clone(),
            inventory_digest: request.inventory_digest.clone(),
            target: request.target_profile.clone(),
            source_profile: "source".into(),
            successor_profile: "successor".into(),
            components: vec![],
            affected_accounts: [request.expected_genesis.identity.account_id.clone()].into(),
            semantic_inventory_digest: request.semantic_inventory_digest.clone(),
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
        };
        (plan, request.plan_digest.clone(), request)
    }
    #[test]
    fn modeled_plan_requires_every_exact_inventory_dimension() {
        let (plan, digest, request) = data();
        assert!(require_exact_plan(&plan, &digest, &request).is_ok());
        let edits: [fn(&mut RetiredHistoryRequest); 6] = [
            |r: &mut RetiredHistoryRequest| r.inventory_digest = "5".repeat(64),
            |r: &mut RetiredHistoryRequest| r.semantic_inventory_digest = "5".repeat(64),
            |r: &mut RetiredHistoryRequest| r.generation_id = "5".repeat(64),
            |r: &mut RetiredHistoryRequest| r.plan_digest = "5".repeat(64),
            |r: &mut RetiredHistoryRequest| r.target_profile = "/private/other".into(),
            |r: &mut RetiredHistoryRequest| {
                r.expected_genesis.identity.account_id = "5".repeat(64);
                r.original_witness.account_id = "5".repeat(64);
            },
        ];
        for edit in edits {
            let mut changed = request.clone();
            edit(&mut changed);
            assert!(require_exact_plan(&plan, &digest, &changed).is_err());
        }
    }
    #[test]
    fn modeled_plan_never_clears_unknown_or_retained_fences() {
        let (mut plan, digest, request) = data();
        plan.unknown_external_signatures = false;
        assert!(require_exact_plan(&plan, &digest, &request).is_err());
        plan.unknown_external_signatures = true;
        plan.recovered_obligations_fenced = false;
        assert!(require_exact_plan(&plan, &digest, &request).is_err());
    }
}
