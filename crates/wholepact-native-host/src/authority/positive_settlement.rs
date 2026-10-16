//! Independently enrolled host node and exact, non-signing positive mutation grant.
use super::*;
use wholepact_chain::local_node::{LocalNodeSourceDescriptor, LocalValidatingNode};
use wholepact_engine::{
    Access, Engine,
    settlement_fanout::{SettlementSinkAuthority, SettlementSinkLease, SettlementSinkScope},
};

pub(crate) struct EnrolledResolutionSource {
    pub(crate) node: LocalValidatingNode,
    descriptor: LocalNodeSourceDescriptor,
    principal: String,
    profile: String,
    runtime: String,
}
impl EnrolledResolutionSource {
    pub(crate) fn descriptor(&self) -> &LocalNodeSourceDescriptor {
        &self.descriptor
    }
}
pub(crate) struct PositiveSettlementAuthority {
    native: Arc<Authority>,
    engine: Engine,
    access: Access,
    scope: SettlementSinkScope,
    source: Arc<EnrolledResolutionSource>,
    conflict: Option<wholepact_chain::local_node::CanonicalConflictCandidate>,
    expires: u64,
}
impl Authority {
    pub(crate) fn enroll_resolution_source(
        &self,
        principal: &str,
        node: LocalValidatingNode,
    ) -> Result<Arc<EnrolledResolutionSource>> {
        self.principal(principal)?;
        let descriptor = node.source_descriptor();
        descriptor.validate()?;
        self.terminal.confirm(&format!("Enroll this complete independent HOST resolution source for this unlocked session?\n{}\nTrust includes the selected local TLS terminator, uncached canonical node responses and pinned testnet software. Existing host TLS credentials stay local; no signer credentials are requested or copied. This creates no credentials, performs no connection and grants no signing authority. Enrollment ends at lock/revoke/restart; replacement within this session is refused.", serde_json::to_string_pretty(&descriptor)?))?;
        let held = self.fence.acquire(now()?.saturating_add(60))?;
        held.check()?;
        Ok(Arc::new(EnrolledResolutionSource {
            node,
            descriptor,
            principal: principal.into(),
            profile: self.profile.clone(),
            runtime: self.runtime.clone(),
        }))
    }
    pub(crate) fn approve_positive_settlement(
        self: &Arc<Self>,
        engine: Engine,
        access: Access,
        scope: SettlementSinkScope,
        source: Arc<EnrolledResolutionSource>,
        conflict: Option<wholepact_chain::local_node::CanonicalConflictCandidate>,
    ) -> Result<PositiveSettlementAuthority> {
        let grant = PositiveSettlementAuthority {
            native: self.clone(),
            engine,
            access,
            scope,
            source,
            conflict,
            expires: now()?.saturating_add(600),
        };
        grant.check()?;
        if let Some(candidate) = &grant.conflict {
            candidate.validate_shape()?;
            self.terminal.confirm(&format!("Approve disclosure of the retained original transaction bytes, exact original nullifier {} and known alternative transaction ID {} to the independently selected signer and witness, and lookup by the enrolled host node?\nExact HOST source: {}\nExact original and local mutation scope: {:#?}\nExpires Unix: {}\nA fresh canonical conflict can append the alternative link and private record confidence. All original debit, input reservations and the obligation remain blocked. Each signer and witness still requires its own native authority. No replacement or terms revision is permitted.", candidate.nullifier, candidate.included_transaction_id, serde_json::to_string_pretty(grant.source.descriptor())?, grant.scope, grant.expires))?;
        } else {
            self.terminal.confirm(&format!("Approve exact transaction-linkage disclosure to this independently enrolled HOST source and positive mutation of the listed local settlement ledger?\nSource: {}\nScope: {:#?}\nThis may mark only an authenticated original release consumed after a fresh exact canonical node permit AND a matching signer settlement receipt. Signer and witness perform their own separately approved independent checks. Other releases and recovery fences remain. This is not spending permission, replacement permission or a public receipt. Partial commits remain possible; retry the same originals, never a new payment. Expires Unix: {}", serde_json::to_string_pretty(grant.source.descriptor())?, grant.scope, grant.expires))?;
        }
        grant.check()?;
        Ok(grant)
    }
}
impl PositiveSettlementAuthority {
    pub(crate) fn check(&self) -> Result<()> {
        self.native.principal(&self.access.principal_id)?;
        if self.expires <= now()?
            || self.source.profile != self.native.profile
            || self.source.runtime != self.native.runtime
            || self.source.principal != self.access.principal_id
            || self.scope.store != self.native.store
            || self.scope.affected_agreement_ids.is_empty()
            || self.source.node.source_descriptor() != self.source.descriptor
            || self
                .engine
                .settlement_sink_scope(&self.scope.journal_identity, &self.scope.transaction)?
                != self.scope
        {
            return Err(Error::Permission);
        }
        for agreement in &self.scope.affected_agreement_ids {
            self.engine.get(&self.access, agreement)?;
        }
        let held = self.native.fence.acquire(self.expires)?;
        held.check()
    }
    pub(crate) fn hold(&self) -> Result<Held> {
        self.check()?;
        self.native.fence.acquire(self.expires)
    }
}
struct PositiveLease<'a> {
    grant: &'a PositiveSettlementAuthority,
    held: Held,
}
impl SettlementSinkAuthority for PositiveSettlementAuthority {
    fn acquire<'a>(
        &'a self,
        _: &SettlementSinkScope,
    ) -> std::result::Result<Box<dyn SettlementSinkLease + 'a>, ApiError> {
        Err(denied())
    }
    fn acquire_conflict_resolution<'a>(
        &'a self,
        scope: &SettlementSinkScope,
        source: &LocalNodeSourceDescriptor,
        candidate: &wholepact_chain::local_node::CanonicalConflictCandidate,
    ) -> std::result::Result<Box<dyn SettlementSinkLease + 'a>, ApiError> {
        if scope != &self.scope
            || source != self.source.descriptor()
            || self.conflict.as_ref() != Some(candidate)
        {
            return Err(denied());
        }
        Ok(Box::new(PositiveLease {
            grant: self,
            held: api(self.hold())?,
        }))
    }
    fn acquire_resolution<'a>(
        &'a self,
        scope: &SettlementSinkScope,
        source: &LocalNodeSourceDescriptor,
    ) -> std::result::Result<Box<dyn SettlementSinkLease + 'a>, ApiError> {
        if self.conflict.is_some() || scope != &self.scope || source != self.source.descriptor() {
            return Err(denied());
        }
        Ok(Box::new(PositiveLease {
            grant: self,
            held: api(self.hold())?,
        }))
    }
}
impl SettlementSinkLease for PositiveLease<'_> {
    fn scope(&self) -> &SettlementSinkScope {
        &self.grant.scope
    }
    fn check_current(&self) -> std::result::Result<(), ApiError> {
        api(self.held.check())?;
        api(self.grant.check())
    }
}
