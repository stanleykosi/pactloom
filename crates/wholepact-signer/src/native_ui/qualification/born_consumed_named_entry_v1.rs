//! Same focused runtime branch for an actually parked consumed named source.
//! The finite fixture borrows the original controller and cannot supply a token.
use super::*;

impl NativeRuntime {
    pub(super) fn reopen_consumed_named_from_native_click(
        &mut self,
        focused: bool,
        epoch: u64,
    ) -> Result<()> {
        if !focused
            || self.open.is_some()
            || self.pending_account.is_some()
            || self.birth.is_active()
            || self.pending_enrollment.is_active()
            || self.born_origin.is_active()
            || self.born_manual_roster_v2.is_active()
            || !self.born_manual_roster_v2.has_dormant_named()
            || self.born_manual.is_active()
            || self.born_enrolled_backup.is_active()
            || !self.closing_accounts.is_empty()
            || self.signing_job.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let entry = PendingBirthEntry {
            focus_epoch: epoch,
            parent_channel: self.parent_channel.clone(),
        };
        let result =
            self.born_manual_roster_v2
                .begin_named(entry, Path::new(&self.root), &self.password);
        self.password.zeroize();
        if result.is_err() {
            self.born_manual_roster_v2.clear();
        }
        self.message = if result.is_ok() {
            "Authenticating exact consumed named-payment source."
        } else {
            "Exact source reentry failed; no old authority was restored."
        };
        result
    }

    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn enter_consumed_named_for_qualification(
        actual: &mut super::super::born_manual_roster_v2::BornManualRosterUiV2,
        root: &Path,
    ) -> Result<()> {
        let mut runtime = Self::new(None);
        runtime.root = root.to_str().ok_or(Error::InvalidData)?.to_owned();
        runtime.password = Zeroizing::new(
            super::super::birth_workspace::born_roster_v3::SYNTHETIC_PENDING_PASSWORD.into(),
        );
        std::mem::swap(&mut runtime.born_manual_roster_v2, actual);
        let result = (|| {
            // False focus neither creates an owner nor consumes the real slot.
            if runtime
                .reopen_consumed_named_from_native_click(false, 1)
                .is_ok()
                || runtime.born_manual_roster_v2.is_active()
                || !runtime.born_manual_roster_v2.has_dormant_named()
            {
                return Err(Error::ReviewMismatch);
            }
            runtime.reopen_consumed_named_from_native_click(true, 1)
        })();
        // Return the same controller even on failure, so the caller's draining
        // guard retains temporary owners until every admitted child has ended.
        std::mem::swap(&mut runtime.born_manual_roster_v2, actual);
        result
    }
}
