//! Same-S consuming handoff only. No runner, SourceEntry or review issuer.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::OriginalFinancialReentrySelectionV1;

/// An inert prepared handoff. The caller must keep the actual V3 role owner
/// alive separately; this value neither owns it nor grants SourceEntry.
pub(in crate::native_ui::runtime) struct PreparedFinancialRoleHandoffV1 {
    selection: OriginalFinancialReentrySelectionV1,
    original_material_deadline: Instant,
}
impl PreparedFinancialRoleHandoffV1 {
    pub(in crate::native_ui::runtime) fn selection(&self) -> &OriginalFinancialReentrySelectionV1 {
        &self.selection
    }
    pub(in crate::native_ui::runtime) fn original_material_deadline(&self) -> Instant {
        self.original_material_deadline
    }
}

/// Actual role custody, never a presentation/IPC DTO. The old V3 source and
/// grants have ended; opening the selected originals needs fresh permission.
pub(in crate::native_ui::runtime) struct DetachedFinancialRoleV1 {
    pub(in crate::native_ui::runtime) selection: OriginalFinancialReentrySelectionV1,
    pub(in crate::native_ui::runtime) material: VerifiedDurableEconomicsV1,
    pub(in crate::native_ui::runtime) original_host_peer: PeerProcess,
    pub(in crate::native_ui::runtime) original_material_deadline: Instant,
}

impl NativeRuntime {
    pub(in crate::native_ui::runtime) fn prepare_coordinated_financial_role_handoff_v1(
        &self,
    ) -> Result<PreparedFinancialRoleHandoffV1> {
        let terms = self.financial_continuation_terms_v1()?;
        let (selection, original_material_deadline) = {
            let closed = self.closed_delivery_v3.as_ref().ok_or(Error::Unavailable)?;
            if closed.phase != DurableDeliveryPhaseV3::Complete
                || closed.job.is_some()
                || self.pending.is_some()
            {
                return Err(Error::Unavailable);
            }
            let active = closed.active.as_ref().ok_or(Error::Unavailable)?;
            let original_material_deadline =
                active.original_material_deadline.ok_or(Error::Locked)?;
            if Instant::now() >= original_material_deadline {
                return Err(Error::Locked);
            }
            terms.require_live(unix_ms()?).map_err(|_| Error::Locked)?;
            let peer = active.peer.as_ref().ok_or(Error::Authentication)?;
            let selection = active.source.capture_financial_reentry_selection_v1(
                &terms,
                &active.intent,
                peer,
            )?;
            (selection, original_material_deadline)
        };
        Ok(PreparedFinancialRoleHandoffV1 {
            selection,
            original_material_deadline,
        })
    }

    pub(in crate::native_ui::runtime) fn detach_coordinated_financial_role_v1(
        &mut self,
        prepared: PreparedFinancialRoleHandoffV1,
    ) -> Result<DetachedFinancialRoleV1> {
        let PreparedFinancialRoleHandoffV1 {
            selection,
            original_material_deadline,
        } = prepared;
        let terms = self.financial_continuation_terms_v1()?;
        {
            let closed = self.closed_delivery_v3.as_ref().ok_or(Error::Unavailable)?;
            if closed.phase != DurableDeliveryPhaseV3::Complete
                || closed.job.is_some()
                || self.pending.is_some()
            {
                return Err(Error::Unavailable);
            }
            let active = closed.active.as_ref().ok_or(Error::Unavailable)?;
            if active.original_material_deadline != Some(original_material_deadline)
                || &terms != selection.terms()
                || Instant::now() >= original_material_deadline
            {
                return Err(Error::ReviewMismatch);
            }
            terms.require_live(unix_ms()?).map_err(|_| Error::Locked)?;
            active.source.check_financial_reentry_selection_v1(
                &selection,
                &active.intent,
                active.peer.as_ref().ok_or(Error::Authentication)?,
            )?;
        }
        // Preserve the existing exact read-revoke, IPC-revoke, material/peer
        // take and old-source-drop order. No source lock crosses this call.
        let (material, original_host_peer) = self.detach_financial_material_v1()?;
        selection.check_host(&original_host_peer)?;
        if Instant::now() >= original_material_deadline {
            return Err(Error::Locked);
        }
        selection
            .terms()
            .require_live(unix_ms()?)
            .map_err(|_| Error::Locked)?;
        Ok(DetachedFinancialRoleV1 {
            selection,
            material,
            original_host_peer,
            original_material_deadline,
        })
    }
}
