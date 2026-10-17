//! Nonportable, one-use synthetic qualification admission from the actual
//! native-published witness grant and its exact live temporary server. This is
//! not a public activation switch, imported grant factory, or writer authority.
use super::*;
use crate::construction_transport_handoff_v1::PendingConstructionTransportGrantV1;
use crate::transport::{
    AuthorityClient, ConstructionTransportCancellationV1, PreparedConstructionTransportHandoffV1,
};
use std::sync::{Weak, atomic::AtomicU64};

/// No Clone, Default, serde, boolean admission or caller-selected namespace.
/// Only the actual temporary native witness below can create this owner.
pub struct EphemeralConstructionClientScopeV1 {
    journal: Arc<crate::AuthorityJournal>,
    pending: PendingConstructionTransportGrantV1,
    server_stop: Weak<AtomicBool>,
    owner_revoked: Arc<AtomicBool>,
    original_native_clock: ReviewClock,
    deadline: Instant,
    high_water_ms: AtomicU64,
}
/// Restriction only: no journal, pending grant or client can be manufactured
/// from this value. The exact live channel retains it through every stage.
pub(crate) struct RetainedConstructionFixtureLivenessV1 {
    server_stop: Weak<AtomicBool>,
    owner_revoked: Arc<AtomicBool>,
    original_native_clock: ReviewClock,
    deadline: Instant,
}
impl RetainedConstructionFixtureLivenessV1 {
    pub(crate) fn check(&self) -> Result<()> {
        self.original_native_clock.check()?;
        let server = self.server_stop.upgrade().ok_or(AuthorityError::Expired)?;
        if self.owner_revoked.load(Ordering::Acquire)
            || server.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
        {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn permanently_revoked_for_clock_test() -> Result<Arc<Self>> {
        // Denial-only test input, never a scope/owner or an allowed liveness guard.
        Ok(Arc::new(Self {
            server_stop: Weak::new(),
            owner_revoked: Arc::new(AtomicBool::new(true)),
            original_native_clock: ReviewClock::start(None)?,
            deadline: Instant::now(),
        }))
    }
}
impl EphemeralConstructionClientScopeV1 {
    fn check_current(&self) -> Result<()> {
        self.original_native_clock.check()?;
        let server = self.server_stop.upgrade().ok_or(AuthorityError::Expired)?;
        if self.owner_revoked.load(Ordering::Acquire)
            || server.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
        {
            return Err(AuthorityError::Expired);
        }
        self.journal.require_born_read_current()?;
        let now = crate::now_ms()?;
        let previous = self.high_water_ms.fetch_max(now, Ordering::AcqRel);
        if now < previous {
            return Err(AuthorityError::Expired);
        }
        let connection = self
            .journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(connection.connection())?;
        let authorization = &self.pending.grant.authorization.authorization;
        if ledger.construction_transport_grant(&self.pending.digest()?)? != self.pending
            || ledger.snapshot.head != self.pending.committed_head
            || ledger
                .construction_transport_history_v1()
                .credentials
                .iter()
                .any(|credential| credential.pending_grant == self.pending)
        {
            return Err(AuthorityError::Conflict);
        }
        ledger.validate_construction_transport_authorization(authorization, now)?;
        ledger.require_unfenced_transport(&authorization.original_session.session_id)?;
        drop(connection);
        self.journal.require_born_read_current()?;
        self.original_native_clock.check()?;
        if Instant::now() >= self.deadline
            || self.owner_revoked.load(Ordering::Acquire)
            || server.load(Ordering::Acquire)
        {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }

    /// Restriction-only coupling to the actual signer prepared/native-reviewed
    /// pending grant. Public evidence can narrow this scope, never create one.
    pub fn require_exact_pending(
        &self,
        expected: &PendingConstructionTransportGrantV1,
    ) -> Result<()> {
        expected.validate()?;
        self.check_current()?;
        if &self.pending != expected {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }

    /// Consumes the concrete scope even on refusal. All ordinary client mTLS,
    /// complete-history, original clock, cancellation, session and exact grant
    /// checks still execute in the unchanged maintained handoff implementation.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        self,
        client: &AuthorityClient,
        history: crate::ReconciledAuthorityHistory,
        new_caller_binding_digest: String,
        new_native_binding_digest: String,
        original_deadline: Instant,
        original_high_water_ms: Arc<AtomicU64>,
        cancellation: ConstructionTransportCancellationV1,
    ) -> Result<PreparedConstructionTransportHandoffV1> {
        self.check_current()?;
        let prepared = client.prepare_retained_construction_transport_handoff_v1(
            history,
            self.pending.clone(),
            new_caller_binding_digest,
            new_native_binding_digest,
            original_deadline.min(self.deadline),
            original_high_water_ms,
            cancellation,
        )?;
        // A late socket completion is never promoted into a surviving owner.
        self.check_current()?;
        prepared.check_current()?;
        prepared.retain_qualification_liveness(Arc::new(RetainedConstructionFixtureLivenessV1 {
            server_stop: self.server_stop,
            owner_revoked: self.owner_revoked,
            original_native_clock: self.original_native_clock,
            deadline: self.deadline,
        }))
    }
}

impl EphemeralNativeWitnessV1 {
    /// Must immediately follow the actual native grant publication. Supplying
    /// copied public hashes cannot select another installation or native event.
    /// Each original grant is irreversibly scoped once, including failed opens.
    pub fn serve_original_construction_handoff_scoped_v1(
        &mut self,
        account_id: &str,
        extension_digest: &str,
        attempt_digest: &str,
        pending_grant_digest: &str,
    ) -> Result<(EphemeralHistoryServerV1, EphemeralConstructionClientScopeV1)> {
        if crate::COMMON_CONTEXT_V3_ACTIVATION_QUALIFIED {
            return Err(AuthorityError::Conflict);
        }
        let receipt = self.completed_native_receipt()?;
        let pending: PendingConstructionTransportGrantV1 = serde_json::from_value(
            receipt
                .get("pending_grant")
                .cloned()
                .ok_or(AuthorityError::Permission)?,
        )
        .map_err(|_| AuthorityError::CorruptHistory)?;
        if pending.digest()? != pending_grant_digest
            || pending.grant.authorization.authorization.account_id != account_id
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let original_native_clock = self
            .window
            .last_archive_receipt
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .0
            .clone();
        original_native_clock.check()?;
        // No eviction, retry reset, orphan cleanup or expiry refund of this set.
        if self.construction_client_grants.len() >= 32
            || !self
                .construction_client_grants
                .insert(pending_grant_digest.to_owned())
        {
            return Err(AuthorityError::Conflict);
        }
        let input = self.original_namespace_input(account_id)?;
        let actual_listen = self
            .listener
            .local_addr()
            .map_err(|_| AuthorityError::Storage)?
            .to_string();
        let journal = Arc::new(
            crate::born_history_server::open_born_manual_roster_attempt_v2_from_namespace(
                input,
                extension_digest,
                attempt_digest,
                &self.server_certificate_digest,
                &actual_listen,
            )?,
        );
        // Both the public refusal and exact private server validator execute.
        if !matches!(
            AuthorityServer::for_construction_transport_v1(
                journal.clone(),
                self.tls.clone(),
                pending_grant_digest,
            ),
            Err(AuthorityError::ConstructionHistoryUnsupported)
        ) {
            return Err(AuthorityError::Conflict);
        }
        let now = crate::now_ms()?;
        let remaining = pending
            .grant
            .authorization
            .authorization
            .expires_at_ms
            .checked_sub(now)
            .filter(|v| *v > 0)
            .ok_or(AuthorityError::Expired)?;
        let deadline =
            Instant::now() + Duration::from_millis(remaining).min(Duration::from_secs(120));
        let server = AuthorityServer::for_retained_construction_transport_v1(
            journal.clone(),
            self.tls.clone(),
            pending_grant_digest,
        )?;
        let serving = self.serve_exact_server(server)?;
        let scope = EphemeralConstructionClientScopeV1 {
            journal,
            pending,
            server_stop: Arc::downgrade(&serving.stop),
            owner_revoked: self.construction_client_scope_revoked.clone(),
            original_native_clock,
            deadline,
            high_water_ms: AtomicU64::new(now),
        };
        scope.check_current()?;
        Ok((serving, scope))
    }
}
