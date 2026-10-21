//! Nominal coordinated wrapper over the shared exact result intake kernel.
//! No installed provider is synthesized; the original verifier/client remains
//! in the closed backing origin through Preview, Held, Current and Finish.
use super::*;
use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedOriginalClientV1;
pub struct PreparedCoordinatedFinancialResultReceiverV1 {
    inner: PreparedFinancialResultReceiverV1,
}
impl PreparedCoordinatedFinancialResultReceiverV1 {
    /// Called only by consuming actual coordinated Pending custody after its
    /// complete original history/operation/intent joins have been checked.
    pub(crate) fn prepare_retained_coordinated_v1(
        client: CoordinatedOriginalClientV1,
        socket: &Path,
        request: &FinancialResultRequestV1,
        original_deadline: Instant,
        original: Box<dyn FinancialResultRestrictionV1>,
        preview_read: &dyn FinancialResultRestrictionV1,
    ) -> Result<Self> {
        client.check_current()?;
        let deadline = original_deadline.min(client.original_channel_deadline());
        let peer = client.original_peer();
        let inner = PreparedFinancialResultReceiverV1::prepare_retained_origin(
            ResultPeerOriginV1::Coordinated(client),
            peer,
            socket,
            request,
            deadline,
            original,
            preview_read,
        )?;
        Ok(Self { inner })
    }
    pub fn preview(&self) -> &AuthenticatedFinancialResultPreviewV1 {
        self.inner.preview()
    }
    pub fn bind_original_intake_restriction_v1(
        self,
        intake: Box<dyn FinancialResultRestrictionV1>,
    ) -> Result<Self> {
        Ok(Self {
            inner: self.inner.bind_original_intake_restriction_v1(intake)?,
        })
    }
    pub fn receive(self) -> Result<AuthenticatedFinancialResultLeaseV1> {
        self.inner.receive()
    }
}
