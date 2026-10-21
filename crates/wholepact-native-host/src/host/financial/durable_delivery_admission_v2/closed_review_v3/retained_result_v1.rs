//! Retained actual Host/provider/peer lineage. Cached clocks only restrict;
//! preview Read, intake setup and Signer ReturnExact remain distinct decisions.
use super::*;
use wholepact_signer::authority_bridge::financial_continuation_v1::{
    AuthenticatedFinancialContinuationHistoryV1, FinancialResultRequestV1,
    FinancialResultRestrictionV1, PreparedFinancialResultReceiverV1,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(super) struct HostMaterialDeliveryRestrictionV1 {
    original_deadline: Instant,
    bounds: crate::terminal::OriginalPromptBoundsV1,
}
impl HostMaterialDeliveryRestrictionV1 {
    /// Only for the sealed no-effect interstage wait. This cached clock check
    /// cannot authorize source/TTY/network work or bypass ordinary park denial.
    pub(super) fn check_parked_wait_bounds(&self) -> Result<()> {
        self.bounds.check()
    }

    // Called once only from actual source-backed V3 recipient preparation,
    // before any pairing prompt/provider IPC. Never accepts a caller duration.
    pub(super) fn capture(
        delivery: &DurableDeliveryPlanV2, materials: &[DurableDeliveryMaterialScopeRefV2],
    ) -> Result<Self> {
        if materials.len() != 2 { return Err(Error::Authentication); }
        let from = materials.iter().map(|m| m.valid_from_unix_seconds).max().ok_or(Error::Authentication)?
            .checked_mul(1000).ok_or(Error::Permission)?.max(delivery.valid_from_ms);
        let until = materials.iter().map(|m| m.valid_until_unix_seconds).min().ok_or(Error::Authentication)?
            .checked_mul(1000).ok_or(Error::Permission)?.min(delivery.valid_until_ms);
        // Monotonic is sampled BEFORE wall conversion, never after a delay.
        let monotonic = Instant::now();
        let wall_floor_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Permission)?.as_millis()).map_err(|_| Error::Permission)?;
        // Ceiling conversion rounds wall time upward; millisecond truncation
        // must never lengthen the retained absolute monotonic restriction.
        let wall_ms = wall_floor_ms.checked_add(1).ok_or(Error::Permission)?;
        if wall_floor_ms < from || wall_ms >= until { return Err(Error::Permission); }
        let original_deadline = monotonic.checked_add(Duration::from_millis(until - wall_ms))
            .ok_or(Error::Permission)?.min(crate::terminal::original_coordinated_session_ceiling()?);
        let bounds = crate::terminal::OriginalPromptBoundsV1::new(original_deadline, (from, until))?;
        bounds.check()?;
        crate::terminal::check_original_coordinator_restriction()?;
        Ok(Self { original_deadline, bounds })
    }
    pub(super) fn into_narrowed_original_restriction_v1(self, history: &AuthenticatedFinancialContinuationHistoryV1) -> Result<(Instant, Box<dyn FinancialResultRestrictionV1>)> {
        let restriction = self.narrow_history(history)?;
        Ok((restriction.original_deadline, Box::new(restriction)))
    }
    fn narrow_history(mut self, history: &AuthenticatedFinancialContinuationHistoryV1) -> Result<Self> {
        let terms = &history.continuation_record().terms;
        self.bounds = self.bounds.narrow_wall((
            terms.valid_from_ms.max(terms.scope.authorization.valid_from_ms),
            terms.valid_until_ms.min(terms.scope.authorization.valid_until_ms),
        ))?;
        self.bounds.check()?;
        Ok(self)
    }
}
impl FinancialResultRestrictionV1 for HostMaterialDeliveryRestrictionV1 {
    fn check_before_io(&self) -> wholepact_signer::authority_bridge::Result<()> {
        self.bounds.check().and_then(|()| crate::terminal::check_original_coordinator_restriction())
            .map_err(|_| wholepact_signer::authority_bridge::BridgeError::Permission)
    }
}
impl RetainedCoordinatedAdmissionV1<'_> {
    pub(in crate::host::financial) fn prepare_original_result(
        self, host: &Host, workspace: &Path, socket: &Path,
        request: &FinancialResultRequestV1,
        history: &AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<PreparedFinancialResultReceiverV1> {
        if !std::ptr::eq(host, self.host) || workspace != self.workspace {
            return Err(Error::Authentication);
        }
        self.checked_export()?;
        if self.admitted.as_ref() != self.pending.status() { return Err(Error::Authentication); }
        let restriction = self.material_delivery_restriction.narrow_history(history)?;
        let ceiling = restriction.original_deadline;
        host.prepare_retained_original_financial_preview_v3(
            workspace, self.pending, socket, request, history, ceiling, Box::new(restriction),
        )
    }
}
