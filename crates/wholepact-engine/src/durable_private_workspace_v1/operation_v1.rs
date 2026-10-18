//! Nominal internal private metadata operations. Never a public Engine bypass.
//! No native/financial effect or discovery command is activated by this owner.
//! Stage A deliberately has no replay/commit method: an owner checked for a
//! read must never become a generic mutation capability. Future commands need
//! their own exact effect-purpose and allowed-delta binding.
use super::*;
use crate::{Envelope, StoredRecord};

/// Borrowed from the exclusive facade after its actual source/Store/privacy
/// check. No Clone, Deserialize, public factory, owner getter or generic flag.
pub(super) struct PrivateWorkspaceOperationV1<'op, 'source> {
    workspace: &'op PrivateDurableCoordinatorV1<'source>,
    access: &'op Access,
    consent: &'op dyn LocalPrivateWorkspaceConsentV1,
    action: PrivateWorkspaceActionV1,
}
impl<'op, 'source> PrivateWorkspaceOperationV1<'op, 'source> {
    pub(super) fn new(
        workspace: &'op PrivateDurableCoordinatorV1<'source>,
        access: &'op Access,
        consent: &'op dyn LocalPrivateWorkspaceConsentV1,
        action: PrivateWorkspaceActionV1,
    ) -> Self {
        Self {
            workspace,
            access,
            consent,
            action,
        }
    }
    fn check(&self) -> Result<()> {
        self.workspace.check(self.access, self.consent, self.action)
    }
    fn decode(&self, record: &StoredRecord) -> Result<Envelope> {
        let envelope = crate::decode_unprojected(record)?;
        if record.id != self.workspace.source.agreement_id() {
            return Err(damaged());
        }
        self.workspace.require_original_envelope(&envelope)?;
        Ok(envelope)
    }
    pub(super) fn load(&self) -> Result<Envelope> {
        self.check()?;
        let record = self
            .workspace
            .engine
            .store
            .get_agreement(self.workspace.source.agreement_id())
            .map_err(crate::store_error)?
            .ok_or_else(damaged)?;
        let envelope = self.decode(&record)?;
        self.check()?;
        Ok(envelope)
    }
}
