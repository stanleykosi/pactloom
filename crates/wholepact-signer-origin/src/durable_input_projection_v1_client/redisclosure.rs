//! Distinct actual installed-signer client for exact original redisclosure.
//! Reuses only bounded framing/provider/kernel helpers, never an ordinary or
//! initial-selection grant. The sole result issuer verifies the exact link.
use super::*;
use crate::durable_input_projection_v1::redisclosure::{
    DurableInputProjectionRedisclosureRequestV1, ProjectionRedisclosureChannelBindingV1,
    ProjectionRedisclosurePairResponseV1, ProjectionRedisclosurePairScopeV1,
    ProjectionRedisclosureRequestV1, ProjectionRedisclosureResponseV1, REDISCLOSURE_PAIR_REASON_V1,
    decode_redisclosure_response_v1,
};
const PAIR: &str = "request_durable_input_projection_redisclosure_pairing_v1";
const REQUEST: &str = "request_durable_input_projection_redisclosure_v1";

pub struct NativeInputProjectionRedisclosureClientV1 {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    peer: PeerProcess,
    request: DurableInputProjectionRedisclosureRequestV1,
    scope: ProjectionRedisclosurePairScopeV1,
    binding: ProjectionRedisclosureChannelBindingV1,
    grant: ClientGrant,
    deadline: Instant,
    requested: AtomicBool,
}
impl NativeInputProjectionRedisclosureClientV1 {
    pub fn pair(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        request: DurableInputProjectionRedisclosureRequestV1,
    ) -> Result<Self> {
        Self::begin_pair_before(
            provider,
            socket,
            application_label,
            request,
            projection_deadline(Instant::now(), None)?,
        )?
        .finish()
    }
    pub fn begin_pair_before(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        request: DurableInputProjectionRedisclosureRequestV1,
        deadline: Instant,
    ) -> Result<PendingInputProjectionRedisclosurePairV1> {
        let started = Instant::now();
        let deadline = projection_deadline(started, Some(deadline))?;
        label(application_label)?;
        request.require_valid_at(now_ms()? / 1000)?;
        let scope = request.pair_scope()?;
        let stream = connect_local_before(socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        framing::enable_credentials(stream.as_raw_fd())?;
        let peer = provider.verify_server(&stream)?;
        let pending = ProjectionStreamV1(stream);
        #[derive(Serialize)]
        struct Envelope<'a> {
            command: &'static str,
            schema_version: u16,
            application_label: &'a str,
            request: &'a DurableInputProjectionRedisclosureRequestV1,
        }
        write_projection_frame(
            &pending.0,
            &Envelope {
                command: PAIR,
                schema_version: 1,
                application_label,
                request: &request,
            },
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
            || {
                peer.check_alive()?;
                remaining_before(deadline)?;
                request.require_valid_at(now_ms()? / 1000)
            },
        )?;
        peer.same_live_process(&provider.verify_server(&pending.0)?)?;
        Ok(PendingInputProjectionRedisclosurePairV1 {
            provider,
            socket: socket.into(),
            peer,
            request,
            scope,
            pending,
            started,
            deadline,
        })
    }
    fn check_current(&self) -> Result<()> {
        remaining_before(self.deadline.min(self.grant.expires))?;
        self.request.require_valid_at(now_ms()? / 1000)?;
        self.peer.check_alive()
    }
    fn require_channel(&self, stream: &UnixStream) -> Result<()> {
        self.check_current()?;
        self.peer
            .same_live_process(&self.provider.verify_server(stream)?)?;
        self.check_current()
    }
    fn open_request(
        &self,
        request: &ProjectionRedisclosureRequestV1,
        deadline: Instant,
    ) -> Result<ProjectionStreamV1> {
        self.check_current()?;
        let deadline = deadline.min(self.deadline).min(self.grant.expires);
        let stream =
            connect_local_before(&self.socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        framing::enable_credentials(stream.as_raw_fd())?;
        let pending = ProjectionStreamV1(stream);
        self.require_channel(&pending.0)?;
        #[derive(Serialize)]
        struct Envelope<'a> {
            command: &'static str,
            schema_version: u16,
            grant_id: &'a str,
            token_hex: &'a str,
            request: &'a ProjectionRedisclosureRequestV1,
        }
        write_projection_frame(
            &pending.0,
            &Envelope {
                command: REQUEST,
                schema_version: 1,
                grant_id: &self.grant.grant_id,
                token_hex: self.grant.token_hex.as_str(),
                request,
            },
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
            || self.require_channel(&pending.0),
        )?;
        self.require_channel(&pending.0)?;
        Ok(pending)
    }
    pub fn begin_redelivery_before(
        &self,
        deadline: Instant,
    ) -> Result<PendingDurableInputProjectionRedeliveryV1<'_>> {
        self.check_current()?;
        self.request.require_scope(&self.scope)?;
        self.requested
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Conflict)?;
        let deadline = deadline.min(self.deadline).min(self.grant.expires);
        let pending = self.open_request(
            &ProjectionRedisclosureRequestV1::Redisclose {
                request: Box::new(self.request.clone()),
            },
            deadline,
        )?;
        Ok(PendingDurableInputProjectionRedeliveryV1 {
            client: self,
            pending,
            deadline,
        })
    }
}

pub struct PendingInputProjectionRedisclosurePairV1 {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    peer: PeerProcess,
    request: DurableInputProjectionRedisclosureRequestV1,
    scope: ProjectionRedisclosurePairScopeV1,
    pending: ProjectionStreamV1,
    started: Instant,
    deadline: Instant,
}
impl PendingInputProjectionRedisclosurePairV1 {
    pub fn finish(self) -> Result<NativeInputProjectionRedisclosureClientV1> {
        self.finish_checked(|| Ok(()))
    }
    pub fn finish_checked(
        self,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<NativeInputProjectionRedisclosureClientV1> {
        check_current()?;
        self.peer
            .same_live_process(&self.provider.verify_server(&self.pending.0)?)?;
        let bytes = framing::read_frame_capped_checked_until(
            &self.pending.0,
            &self.peer,
            MAX_INPUT_PROJECTION_FRAME_BYTES_V1,
            self.deadline,
            || {
                check_current()?;
                self.peer.check_alive()?;
                self.request.require_valid_at(now_ms()? / 1000)
            },
        )?;
        let response: ProjectionRedisclosurePairResponseV1 =
            wholepact_core::parse_typed_json(&bytes).map_err(|_| Error::InvalidData)?;
        validate_redisclosure_pair(&response, &self.scope)?;
        self.peer
            .same_live_process(&self.provider.verify_server(&self.pending.0)?)?;
        check_current()?;
        let expires = self
            .started
            .checked_add(Duration::from_secs(response.expires_in_seconds))
            .ok_or(Error::Permission)?
            .min(self.deadline);
        remaining_before(expires)?;
        let client = NativeInputProjectionRedisclosureClientV1 {
            provider: self.provider,
            socket: self.socket,
            peer: self.peer,
            request: self.request,
            scope: self.scope,
            binding: response.binding.clone(),
            grant: ClientGrant {
                grant_id: response.grant_id.clone(),
                token_hex: Zeroizing::new(response.token_hex.clone()),
                expires,
            },
            deadline: self.deadline,
            requested: AtomicBool::new(false),
        };
        // Prove actual token possession in the REDISCLOSURE dialect, not an
        // ordinary status route and not an initial projection status route.
        let pending = client.open_request(&ProjectionRedisclosureRequestV1::Status, expires)?;
        let bytes = framing::read_frame_capped_checked_until(
            &pending.0,
            &client.peer,
            MAX_INPUT_PROJECTION_FRAME_BYTES_V1,
            restricted_phase(expires, MAX_CURRENT_WAIT)?,
            || {
                check_current()?;
                client.check_current()
            },
        )?;
        let ProjectionRedisclosureResponseV1::Current { binding } =
            decode_redisclosure_response_v1(&bytes)?
        else {
            return Err(Error::Permission);
        };
        binding.validate()?;
        if binding != client.binding {
            return Err(Error::Binding);
        }
        client.require_channel(&pending.0)?;
        check_current()?;
        Ok(client)
    }
}
pub struct PendingDurableInputProjectionRedeliveryV1<'a> {
    client: &'a NativeInputProjectionRedisclosureClientV1,
    pending: ProjectionStreamV1,
    deadline: Instant,
}
impl PendingDurableInputProjectionRedeliveryV1<'_> {
    pub fn finish(self) -> Result<AuthenticatedDurableInputProjectionV1> {
        self.finish_checked(|| Ok(()))
    }
    pub fn finish_checked(
        self,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedDurableInputProjectionV1> {
        check_current()?;
        self.client.require_channel(&self.pending.0)?;
        let bytes = framing::read_frame_capped_checked_until(
            &self.pending.0,
            &self.client.peer,
            MAX_INPUT_PROJECTION_FRAME_BYTES_V1,
            self.deadline,
            || {
                check_current()?;
                self.client.check_current()
            },
        )?;
        let ProjectionRedisclosureResponseV1::Retained { original, delivery } =
            decode_redisclosure_response_v1(&bytes)?
        else {
            return Err(Error::Permission);
        };
        delivery.require_original(&original)?;
        if delivery.request != self.client.request
            || delivery.recipient != self.client.binding
            || original.request != self.client.request.original_request
        {
            return Err(Error::Binding);
        }
        self.client.require_channel(&self.pending.0)?;
        remaining_before(self.deadline)?;
        check_current()?;
        Ok(AuthenticatedDurableInputProjectionV1 {
            outbox: *original,
            redelivery: Some(*delivery),
            signer_enrollment_reference: self.client.provider.native_enrollment_reference().into(),
            signer_process_instance: self.client.peer.instance().into(),
        })
    }
}
fn validate_redisclosure_pair(
    response: &ProjectionRedisclosurePairResponseV1,
    scope: &ProjectionRedisclosurePairScopeV1,
) -> Result<()> {
    scope.validate()?;
    response.binding.validate()?;
    hash(&response.grant_id)?;
    hash(&response.token_hex)?;
    let token =
        Zeroizing::new(hex::decode(&response.token_hex).map_err(|_| Error::Authentication)?);
    if response.schema_version != 1
        || !response.accepted
        || response.reason_code != REDISCLOSURE_PAIR_REASON_V1
        || !(1..=MAX_PROJECTION_OPERATION.as_secs()).contains(&response.expires_in_seconds)
        || response.binding.scope != *scope
        || response.binding.grant_id != response.grant_id
        || response.binding.authenticated_local_grant_digest
            != hex::encode(Sha256::digest(token.as_slice()))
        || response.binding.pid != std::process::id()
        || response.binding.uid != unsafe { libc::geteuid() }
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair_response() -> ProjectionRedisclosurePairResponseV1 {
        let scope = ProjectionRedisclosurePairScopeV1 { schema_version: 1,
            operation_id: "new-delivery".into(), original_request_digest: "e".repeat(64),
            original_scope: ProjectionPairScopeV1 { schema_version: 1,
                purpose: wholepact_core::durable_input_projection_v1::DurableInputProjectionPurposeV1::DurablePlainFixedInputProjectionV1,
                operation_id: "original".into(), account_id: "a".repeat(64),
                agreement_id: "agreement".into(), obligation_id: "obligation".into(),
                participant_id: "participant".into(), intent_digest: "b".repeat(64) } };
        let instance = "c".repeat(64);
        let token = "11".repeat(32);
        let grant = "d".repeat(64);
        ProjectionRedisclosurePairResponseV1 { schema_version: 1, accepted: true,
            reason_code: REDISCLOSURE_PAIR_REASON_V1.into(), grant_id: grant.clone(),
            token_hex: token.clone(), expires_in_seconds: 60,
            binding: ProjectionRedisclosureChannelBindingV1 { version: 1,
                channel_binding_digest: crate::durable_input_projection_v1::redisclosure::redisclosure_pairing_review_digest_v1(&scope, &instance, 1).unwrap(),
                scope, grant_id: grant,
                authenticated_local_grant_digest: hex::encode(Sha256::digest(hex::decode(token).unwrap())),
                uid: unsafe { libc::geteuid() }, pid: std::process::id(),
                process_instance: instance, signer_generation: 1 } }
    }
    #[test]
    fn redisclosure_pair_requires_exact_grant_original_locator_and_current_process() {
        let good = pair_response();
        let scope = good.binding.scope.clone();
        assert!(validate_redisclosure_pair(&good, &scope).is_ok());
        for mutation in 0..10 {
            let mut changed = pair_response();
            match mutation {
                0 => changed.grant_id = "e".repeat(64),
                1 => changed.token_hex = "22".repeat(32),
                2 => changed.binding.pid = changed.binding.pid.wrapping_add(1),
                3 => changed.binding.uid = changed.binding.uid.wrapping_add(1),
                4 => changed.binding.scope.operation_id.push_str("-other"),
                5 => changed.binding.scope.original_request_digest = "f".repeat(64),
                6 => changed.expires_in_seconds = 0,
                7 => changed.expires_in_seconds = 121,
                8 => changed.reason_code = INPUT_PROJECTION_PAIR_REASON_V1.into(),
                _ => changed
                    .binding
                    .scope
                    .original_scope
                    .operation_id
                    .push_str("-other"),
            }
            assert!(
                validate_redisclosure_pair(&changed, &scope).is_err(),
                "mutation {mutation}"
            );
        }
    }
    #[test]
    fn initial_pair_scope_cannot_be_redisclosure_scope() {
        let s = serde_json::json!({"schema_version":1,
            "purpose":"durable_plain_fixed_input_projection_v1","operation_id":"initial",
            "account_id":"a".repeat(64),"agreement_id":"agreement","obligation_id":"obligation",
            "participant_id":"participant","intent_digest":"b".repeat(64)});
        assert!(
            wholepact_core::parse_typed_json::<ProjectionRedisclosurePairScopeV1>(
                &serde_json::to_vec(&s).unwrap()
            )
            .is_err()
        );
    }
}
