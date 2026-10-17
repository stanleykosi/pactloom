//! Finite private dispatcher over actual child jobs; no alternate native issuer.
use super::*;
use crate::native_ui::witness_workspace::NativeWitnessWorkspace;
use std::{path::Path, sync::Arc};
impl NamedRecipientWorkspace {
    pub(in crate::native_ui) fn synthetic_retain_born_payment(
        &mut self,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: &Arc<NativeWitnessWorkspace>,
        inputs: crate::consent_journal::BornNamedRecipientOriginalInputs,
        path: &Path,
        epoch: u64,
    ) -> Result<String> {
        if self.final_active() || self.pending.is_some() {
            return Err(Error::Locked);
        }
        let live = self.live.as_ref().ok_or(Error::Locked)?;
        live.check_current(owner.journal, owner.session)?;
        self.born_inbox
            .synthetic_retain_and_export(live, owner, witness, inputs, path, epoch)
    }
    pub(in crate::native_ui) fn synthetic_submit_born_payment(
        &mut self,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: &Arc<NativeWitnessWorkspace>,
        path: &Path,
        epoch: u64,
    ) -> Result<()> {
        if self.final_active() || self.pending.is_some() {
            return Err(Error::Locked);
        }
        self.born_courier.synthetic_submit_original(
            self.live.as_ref().ok_or(Error::Locked)?,
            owner,
            witness,
            path,
            epoch,
        )
    }
    pub(in crate::native_ui) fn synthetic_sign_born_payment(
        &mut self,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: &Arc<NativeWitnessWorkspace>,
        authorization: &str,
        path: &Path,
        epoch: u64,
    ) -> Result<crate::consent_journal::OriginalNamedReturnReferencesV1> {
        if self.final_active() || self.pending.is_some() {
            return Err(Error::Locked);
        }
        self.born_signing.synthetic_sign_and_export(
            self.live.as_ref().ok_or(Error::Locked)?,
            owner,
            witness,
            authorization,
            path,
            epoch,
        )
    }
}
