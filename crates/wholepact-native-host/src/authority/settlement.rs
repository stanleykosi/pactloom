//! Exact native permission to conservatively reopen local coordination records.
//! This neither resolves exposure nor grants signer/witness mutation authority.
use super::*;
use wholepact_engine::{
    Access, Engine,
    settlement_fanout::{SettlementSinkAuthority, SettlementSinkLease, SettlementSinkScope},
};

pub(crate) struct NativeSettlementAuthority {
    native: Arc<Authority>,
    engine: Engine,
    access: Access,
    approved: SettlementSinkScope,
    observation: ObservationScope,
    expires: u64,
}
struct NativeSettlementLease<'a> {
    authority: &'a NativeSettlementAuthority,
    held: Held,
}
impl Authority {
    pub(crate) fn approve_settlement_sink(
        self: &Arc<Self>,
        engine: Engine,
        access: Access,
        scope: SettlementSinkScope,
        expires: u64,
    ) -> Result<Arc<NativeSettlementAuthority>> {
        self.principal(&access.principal_id)?;
        if scope.store != self.store
            || scope.affected_agreement_ids.is_empty()
            || expires <= now()?
            || expires > now()?.saturating_add(3600)
        {
            return Err(Error::Permission);
        }
        let observation = self
            .observation
            .lock()
            .map_err(|_| Error::Permission)?
            .as_ref()
            .map(|(scope, _)| scope.clone())
            .ok_or(Error::Permission)?;
        let proposed = NativeSettlementAuthority {
            native: self.clone(),
            engine,
            access,
            approved: scope,
            observation,
            expires,
        };
        proposed.check()?;
        self.terminal.confirm(&format!(
            "Allow CONSERVATIVE LOCAL SETTLEMENT INVALIDATION for this exact retained transaction until Unix {expires}?\nProfile: {}\nPrincipal: {}\nSubmission journal: {}\nLocal destination: {}\nExact transaction: {:#?}\nALL affected alternative agreement IDs: {:?}\nALL affected local account IDs: {:?}\nThis is a separate mutation permission, not the read-only provider disclosure approval. Qualifying uncertainty/reorganization evidence may invalidate local settlement confidence and reopen outstanding exposure across exactly these alternatives/accounts. It can block replacement or further authorization. It cannot clear exposure, declare settlement, transfer funds or mutate independent signer/witness stores. A new alternative or account requires new approval; this grant never silently widens. Lock/revoke and expiry stop new mutations. Interrupted fanout remains pending and replays the same original evidence.\n",
            self.profile, proposed.access.principal_id, proposed.approved.journal_identity,
            proposed.approved.destination, proposed.approved.transaction,
            proposed.approved.affected_agreement_ids, proposed.approved.affected_account_ids,
        ))?;
        let held = self.fence.acquire(expires)?;
        proposed.check()?;
        held.check()?;
        drop(held);
        Ok(Arc::new(proposed))
    }
}
impl NativeSettlementAuthority {
    fn check(&self) -> Result<()> {
        self.native.principal(&self.access.principal_id)?;
        if self.expires <= now()? {
            return Err(Error::Permission);
        }
        let current = self
            .engine
            .settlement_sink_scope(&self.approved.journal_identity, &self.approved.transaction)?;
        if current != self.approved || current.store != self.native.store {
            return Err(Error::Permission);
        }
        // Enrolled app scope is rechecked for every affected alternative. Native
        // terminal approval cannot silently bypass a principal's narrower access.
        for id in &current.affected_agreement_ids {
            let agreement = self.engine.get(&self.access, id)?;
            if agreement.agreement.obligation_id != current.transaction.obligation_id {
                return Err(Error::Permission);
            }
        }
        let observation = self
            .native
            .observation
            .lock()
            .map_err(|_| Error::Permission)?;
        let (source, expires) = observation.as_ref().ok_or(Error::Permission)?;
        if source != &self.observation
            || source.profile_id != self.native.profile
            || source.journal_identity != current.journal_identity
            || source.transaction != current.transaction
            || *expires < self.expires
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
}
impl SettlementSinkAuthority for NativeSettlementAuthority {
    fn acquire<'a>(
        &'a self,
        scope: &SettlementSinkScope,
    ) -> std::result::Result<Box<dyn SettlementSinkLease + 'a>, ApiError> {
        if scope != &self.approved {
            return Err(denied());
        }
        api(self.check())?;
        let held = api(self.native.fence.acquire(self.expires))?;
        api(self.check())?;
        Ok(Box::new(NativeSettlementLease {
            authority: self,
            held,
        }))
    }
}
impl SettlementSinkLease for NativeSettlementLease<'_> {
    fn scope(&self) -> &SettlementSinkScope {
        &self.authority.approved
    }
    fn check_current(&self) -> std::result::Result<(), ApiError> {
        api(self.held.check())?;
        api(self.authority.check())
    }
}
