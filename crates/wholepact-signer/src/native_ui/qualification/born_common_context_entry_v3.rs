//! Shared genuine focused entry for the already parked original completion.
//! The synthetic wrapper moves the SAME controller; it cannot create a token.
use super::*;

impl NativeRuntime {
    pub(super) fn reopen_born_common_context_from_native_click(
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
            || !self.born_manual_roster_v2.has_dormant_common_context()
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
        let result = self.born_manual_roster_v2.begin_common_context(
            entry,
            Path::new(&self.root),
            &self.password,
        );
        self.password.zeroize();
        if result.is_err() {
            self.born_manual_roster_v2.clear();
        }
        self.message = if result.is_ok() {
            "Authenticating exact original completion."
        } else {
            "Original completion ended; no retry was created."
        };
        result
    }

    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn entered_born_common_context_for_qualification(
        actual: super::super::born_manual_roster_v2::BornManualRosterUiV2,
        root: &Path,
    ) -> Result<super::super::born_manual_roster_v2::BornManualRosterUiV2> {
        let mut runtime = Self::new(None);
        runtime.root = root.to_str().ok_or(Error::InvalidData)?.to_owned();
        runtime.password = Zeroizing::new(
            super::super::birth_workspace::born_roster_v3::SYNTHETIC_PENDING_PASSWORD.into(),
        );
        runtime.born_manual_roster_v2 = actual;
        // A false-focus event must not consume the genuine dormant slot.
        if runtime
            .reopen_born_common_context_from_native_click(false, 1)
            .is_ok()
            || runtime.born_manual_roster_v2.is_active()
            || !runtime.born_manual_roster_v2.has_dormant_common_context()
        {
            return Err(Error::ReviewMismatch);
        }
        runtime.reopen_born_common_context_from_native_click(true, 1)?;
        Ok(std::mem::take(&mut runtime.born_manual_roster_v2))
    }
}
