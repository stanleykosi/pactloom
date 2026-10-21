//! Private concrete no-effect boundary after actual V3 audit/display.
//! The retained admission is the real owner, never a copied completed flag.
//! Origin supplies/authenticates the exact retirement request and Resume; this
//! holder does not attest that any Witness purpose completed or was disposed.
use super::*;
use std::{thread, time::Duration};
use wholepact_financial_coordinator_origin::{
    HostFinancialForegroundV1, HostFinancialInterstageWaitV1,
};

pub(in crate::host::financial) struct RetainedOwnerWorkflowWaitV1<'host> {
    // Drop order is deliberate: deny before releasing retained provider/peer.
    wait: HostFinancialInterstageWaitV1,
    admission: RetainedCoordinatedAdmissionV1<'host>,
}

impl<'host> RetainedCoordinatedAdmissionV1<'host> {
    pub(in crate::host::financial) fn into_owner_workflow_wait(
        self,
        foreground: HostFinancialForegroundV1,
    ) -> Result<RetainedOwnerWorkflowWaitV1<'host>> {
        // This succeeds only after verify_admission completed status/audit
        // validation AND its separately approved scoped local display.
        self.checked_export()?;
        self.material_delivery_restriction.check_parked_wait_bounds()?;
        let wait = foreground.enter_owner_workflow_wait()?;
        Ok(RetainedOwnerWorkflowWaitV1 { wait, admission: self })
    }
}

impl<'host> RetainedOwnerWorkflowWaitV1<'host> {
    /// No source, TTY, Pending metadata or protected-result operation occurs in
    /// this wait. Every error consumes the holder, so its guard poisons rather
    /// than allowing a caller to ignore an error and retry an effect.
    pub(in crate::host::financial) fn wait_for_next_retirement(mut self) -> Result<Self> {
        self.wait_for_original_resume()?;
        // Genuine Resume alone does not release the parked effects.
        // Recheck original material/delivery clocks before any leave.
        self.admission.material_delivery_restriction.check_parked_wait_bounds()?;
        Ok(self)
    }

    fn wait_for_original_resume(&mut self) -> Result<()> {
        loop {
            self.admission.material_delivery_restriction.check_parked_wait_bounds()?;
            if let Some(guard) = self.wait.try_next_retirement()? {
                guard.wait_resume()?;
                return Ok(());
            }
            // Idle polling only. The actual origin checks original actors,
            // session/shared R and exact cutoff on each attempt; this sleep
            // creates no replacement deadline or positive permission.
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(in crate::host::financial) fn leave_after_resume(
        self,
    ) -> Result<(RetainedCoordinatedAdmissionV1<'host>, HostFinancialForegroundV1)> {
        self.admission.material_delivery_restriction.check_parked_wait_bounds()?;
        // Origin accepts only the genuine consumed-Resume state. An idle wait,
        // caller boolean, prompt text or absent queued message cannot leave.
        let foreground = self.wait.leave_after_resume()?;
        Ok((self.admission, foreground))
    }
}
