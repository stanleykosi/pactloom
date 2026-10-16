//! Actual installed-peer provenance for a separately approved future handoff.
//! The signed JSON remains inert until the Authority-owning bridge checks it.
use super::roster_common_context_read_v1::CommonContextCompletionBinding;
use super::*;
use crate::common_context_handoff_v1::*;

impl NativeManualClient {
    pub fn begin_roster_common_context_handoff_authorization_before<'a>(
        &'a self,
        read: &'a AdmittedRosterCommonContextReadV1,
        request: &RosterCommonContextHandoffAuthorizationRequestV1,
        deadline: Instant,
    ) -> Result<PendingCommonContextHandoffAuthorizationV1<'a>> {
        request.validate()?;
        read.check_completion()?;
        self.check_channel()?;
        self.handoff.check()?;
        if request.original_read_admission_digest != read.evidence().digest()?
            || request.current_caller_binding_digest != self.current_caller_binding_digest()?
            || request.current_caller_binding_digest
                != read.request()?.current_caller_binding_digest
            || request.operation_id == read.request()?.operation_id
            || self.scope.manifest_digest
                != read.request()?.plan.digest().map_err(|_| Error::Binding)?
            || self.scope.history_read
            || self.scope.authorization_export
            || self.scope.preconstruction_export
        {
            return Err(Error::Binding);
        }
        let deadline = deadline
            .min(read.completion_deadline())
            .min(self.grant.expires);
        remaining_before(deadline)?;
        let attempt = PendingRosterV2Attempt::new(&self.handoff, self.acquire_slot()?);
        // Irreversible before the first transport effect. A lost response cannot retry.
        let binding = read.claim_handoff_authorization()?;
        binding.original_signer_peer.same_live_process(&self.peer)?;
        let stream = self.open_request_before_bounded(
            serde_json::json!({"operation":"request_born_roster_common_context_handoff_authorization_v1","request":request}),
            deadline, MAX_HANDOFF_AUTHORIZATION_FRAME,
        )?;
        Ok(PendingCommonContextHandoffAuthorizationV1 {
            client: self,
            read,
            request: request.clone(),
            binding,
            stream: PendingRosterV2Stream(Some(stream)),
            attempt,
            deadline,
        })
    }
}
pub struct PendingCommonContextHandoffAuthorizationV1<'a> {
    client: &'a NativeManualClient,
    read: &'a AdmittedRosterCommonContextReadV1,
    request: RosterCommonContextHandoffAuthorizationRequestV1,
    binding: CommonContextCompletionBinding,
    stream: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'a>,
    deadline: Instant,
}
impl PendingCommonContextHandoffAuthorizationV1<'_> {
    pub fn finish(mut self) -> Result<NativeCommonContextHandoffAuthorizationV1> {
        self.read.check_completion()?;
        let bytes = Zeroizing::new(framing::read_frame_with_deadline(
            self.stream.stream()?,
            &self.client.peer,
            remaining_before(self.deadline)?,
        )?);
        if bytes.len() > MAX_HANDOFF_AUTHORIZATION_FRAME {
            return Err(Error::Limit);
        }
        let response: RosterCommonContextHandoffAuthorizationResponseV1 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let RosterCommonContextHandoffAuthorizationResponseV1::CommonContextHandoffAuthorizedV1 {
            signed_authorization_json,
            signed_authorization_digest,
        } = response
        else {
            return Err(Error::Permission);
        };
        if signed_authorization_json.len() > MAX_HANDOFF_AUTHORIZATION_JSON {
            return Err(Error::Limit);
        }
        hash(&signed_authorization_digest)?;
        self.read.check_completion()?;
        self.client.check_channel()?;
        remaining_before(self.deadline)?;
        drop(self.attempt.slot.take().ok_or(Error::Permission)?);
        Ok(NativeCommonContextHandoffAuthorizationV1 {
            request: self.request,
            binding: self.binding,
            signed_authorization_json: Zeroizing::new(signed_authorization_json),
            signed_authorization_digest,
        })
    }
}
/// Non-clone installed-peer response owner. It contains no transport key and
/// confers neither a grant nor permission to reserve, consume, or sign.
pub struct NativeCommonContextHandoffAuthorizationV1 {
    request: RosterCommonContextHandoffAuthorizationRequestV1,
    binding: CommonContextCompletionBinding,
    signed_authorization_json: Zeroizing<String>,
    signed_authorization_digest: String,
}
impl NativeCommonContextHandoffAuthorizationV1 {
    pub fn check_original_read(&self, read: &StartedRosterCommonContextReadV1) -> Result<()> {
        read.matches_reentry_identity(&self.binding.identity)?;
        if read.evidence().digest()? != self.request.original_read_admission_digest {
            return Err(Error::Binding);
        }
        Ok(())
    }
    /// Inert bytes, not an Authority capability. Consumers must validate the exact
    /// signed DTO and its owner pin and original read commitments independently.
    pub fn signed_authorization_json<'a>(
        &'a self,
        read: &StartedRosterCommonContextReadV1,
    ) -> Result<&'a str> {
        self.check_original_read(read)?;
        Ok(&self.signed_authorization_json)
    }
    pub fn signed_authorization_digest(&self) -> &str {
        &self.signed_authorization_digest
    }
    pub fn request(&self) -> &RosterCommonContextHandoffAuthorizationRequestV1 {
        &self.request
    }
}
