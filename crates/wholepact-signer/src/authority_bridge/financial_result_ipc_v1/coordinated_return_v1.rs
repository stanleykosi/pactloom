//! Consuming original coordinated result request. No installed provider/native
//! action is constructed; the original registry, stream and source stay owned.
use super::*;
use crate::account::birth::enrollment::roster_v2::{
    durable_entry_v1::CoordinatedFinancialRoleTransportV1,
    financial_source_v1::CoordinatedFinancialReturnSourcePinV1,
};
use wholepact_financial_coordinator_origin::{
    SignerReturnExactFinalV1, SignerReturnReadCompletedV1, SignerReturnReadFinalV1,
    SignerReturnReadPresentationV1,
};

pub(crate) struct PreparedCoordinatedFinancialReturnV1 {
    source: Arc<PreparedOriginalFinancialSourceV1>,
    pin: CoordinatedFinancialReturnSourcePinV1,
    transport: CoordinatedFinancialRoleTransportV1,
    registry_peer: crate::ipc::CoordinatedPairPeerV1,
    host: PeerProcess,
    stream: Option<UnixStream>,
    evidence: Evidence,
    read: SignerReturnReadPresentationV1,
    read_completion: Option<SignerReturnReadCompletedV1>,
    setup_deadline: Instant,
    original_bounds: [Instant; 4],
    digest: String,
    preview_digest: String,
}
impl PreparedCoordinatedFinancialReturnV1 {
    /// Runs in an owned worker. Origin remains on its control/R pump thread.
    pub(crate) fn prepare(
        source: Arc<PreparedOriginalFinancialSourceV1>,
        transport: CoordinatedFinancialRoleTransportV1,
        host: PeerProcess,
        event: crate::ipc::CoordinatedFinancialResultEventV1,
        read: SignerReturnReadFinalV1,
        setup_deadline: Instant,
    ) -> Result<Self> {
        read.check_current().map_err(|_| BridgeError::Permission)?;
        transport
            .require_peer(&event.peer)
            .map_err(|_| BridgeError::Permission)?;
        host.same_live_process(event.peer.actual_peer())
            .map_err(|_| BridgeError::Permission)?;
        event.request.validate()?;
        if crate::authority_bridge::durable_review_ipc_v3::verified_fixed_identity_digest_v3(
            &event.request.fixed,
        )? != read.presentation().facts.signed.fixed_identity_digest
        {
            return Err(BridgeError::Binding);
        }
        let original_bounds = [
            read.original_service_deadline(),
            read.original_writer_session_deadline(),
            read.original_channel_deadline(),
            read.original_material_deadline(),
        ];
        if read.original_channel_deadline() != event.peer.deadline() {
            return Err(BridgeError::Binding);
        }
        let raw = serde_json::to_string(&event.request).map_err(|_| BridgeError::Binding)?;
        if raw != read.presentation().facts.request_json {
            return Err(BridgeError::Binding);
        }
        check_setup_ceiling(
            Instant::now(),
            setup_deadline,
            &[
                event.original_request_deadline,
                source.original_deadline(),
                event.peer.deadline(),
                read.original_service_deadline(),
                read.original_writer_session_deadline(),
                read.original_channel_deadline(),
                read.original_material_deadline(),
            ],
        )?;
        source
            .check_coordinated_return_read_v1(&host, &read)
            .map_err(|_| BridgeError::Permission)?;
        let (original, _, _, result, journal_pin, continuation) = source
            .financial_journal()
            .map_err(|_| BridgeError::Permission)?
            .coordinated_financial_retained_result_v1(
                &*source
                    .financial_binding()
                    .map_err(|_| BridgeError::Permission)?,
                &read,
            )?;
        source
            .check_coordinated_return_read_v1(&host, &read)
            .map_err(|_| BridgeError::Permission)?;
        let evidence = Evidence::from_retained(&original, &result, continuation, &event.request)?;
        if journal_pin.result_digest() != evidence.result_digest {
            return Err(BridgeError::Binding);
        }
        let pin = source
            .prepare_coordinated_return_source_pin_v1(journal_pin, &host, &read)
            .map_err(|_| BridgeError::Permission)?;
        let preview = PreviewData::from_evidence(&evidence);
        let preview_digest = preview.digest()?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:financial-exact-result-return:v1",
            &(source.identity_digest(), host.instance(), &preview),
        )
        .map_err(|_| BridgeError::Binding)?;
        let mut stream = event.stream;
        let observed = PeerProcess::observe(&stream).map_err(|_| BridgeError::Permission)?;
        host.same_live_process(&observed)
            .map_err(|_| BridgeError::Permission)?;
        write(
            &mut stream,
            &Response::Preview { preview },
            setup_deadline.min(read.original_read_deadline()),
            &|| {
                read.check_current().map_err(|_| BridgeError::Permission)?;
                transport
                    .require_peer(&event.peer)
                    .map_err(|_| BridgeError::Permission)?;
                source
                    .check_coordinated_return_source_pin_v1(&pin, &host)
                    .map_err(|_| BridgeError::Permission)?;
                read.check_current().map_err(|_| BridgeError::Permission)
            },
        )?;
        let presentation = read.presentation().clone();
        let completion = read.finish_read().map_err(|_| BridgeError::Permission)?;
        let prepared = Self {
            source,
            pin,
            transport,
            registry_peer: event.peer,
            host,
            stream: Some(stream),
            evidence,
            read: presentation,
            read_completion: Some(completion),
            setup_deadline,
            original_bounds,
            digest,
            preview_digest,
        };
        // This is custody-only waiting: no expired Read action is rebound.
        match read_setup(
            prepared.stream.as_ref().ok_or(BridgeError::Permission)?,
            &prepared.host,
            setup_deadline,
            &|| prepared.check_custody(),
        )? {
            Command::HostPrepared { preview_digest }
                if preview_digest == prepared.preview_digest =>
            {
                ()
            }
            _ => return Err(BridgeError::Permission),
        }
        prepared.check_custody()?;
        Ok(prepared)
    }
    pub(crate) fn take_read_completion(&mut self) -> Result<SignerReturnReadCompletedV1> {
        self.check_custody()?;
        self.read_completion.take().ok_or(BridgeError::Permission)
    }
    pub(crate) fn approve(
        self,
        action: SignerReturnExactFinalV1,
    ) -> Result<ApprovedCoordinatedFinancialReturnV1> {
        self.check_custody()?;
        action
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        let facts = &action.presentation().facts;
        if self.read_completion.is_some()
            || facts.read != self.read
            || facts.preview_digest != self.preview_digest
            || facts.reviewed_digest != self.digest
            || facts.signature_set_digest != self.evidence.signature_set_digest
            || action.original_source_deadline() != self.source.original_deadline()
            || [
                action.original_service_deadline(),
                action.original_writer_session_deadline(),
                action.original_channel_deadline(),
                action.original_material_deadline(),
            ] != self.original_bounds
            || action.original_return_deadline() > self.setup_deadline
        {
            return Err(BridgeError::Binding);
        }
        Ok(ApprovedCoordinatedFinancialReturnV1 {
            prepared: self,
            action,
        })
    }
    fn check_custody(&self) -> Result<()> {
        if let Some(completed) = &self.read_completion {
            completed
                .check_current()
                .map_err(|_| BridgeError::Permission)?;
        }
        if Instant::now() >= self.setup_deadline {
            return Err(BridgeError::Permission);
        }
        self.transport
            .require_peer(&self.registry_peer)
            .map_err(|_| BridgeError::Permission)?;
        self.host
            .same_live_process(self.registry_peer.actual_peer())
            .map_err(|_| BridgeError::Permission)?;
        self.source
            .check_coordinated_return_source_pin_v1(&self.pin, &self.host)
            .map_err(|_| BridgeError::Permission)
    }
    pub(crate) fn read_presentation(&self) -> &SignerReturnReadPresentationV1 {
        &self.read
    }
    pub(crate) fn preview_digest(&self) -> &str {
        &self.preview_digest
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn signature_set_digest(&self) -> &str {
        &self.evidence.signature_set_digest
    }
    pub(crate) fn setup_deadline(&self) -> Instant {
        self.setup_deadline
    }
    pub(crate) fn display(&self) -> String {
        project_return_display(
            &self.evidence.request, &self.evidence.result_digest, &self.evidence.outbox_digest,
            self.host.instance(), &self.digest,
        )
    }
}

pub(crate) struct ApprovedCoordinatedFinancialReturnV1 {
    prepared: PreparedCoordinatedFinancialReturnV1,
    action: SignerReturnExactFinalV1,
}
impl ApprovedCoordinatedFinancialReturnV1 {
    pub(super) fn peer(&self) -> &PeerProcess {
        &self.prepared.host
    }
    pub(super) fn evidence(&self) -> &Evidence {
        &self.prepared.evidence
    }
    pub(super) fn deadline(&self) -> Instant {
        self.action
            .original_return_deadline()
            .min(self.prepared.setup_deadline)
    }
    pub(super) fn finish(self) -> Result<()> {
        self.action
            .finish_return()
            .map_err(|_| BridgeError::Permission)
    }
    pub(super) fn check(&self) -> Result<()> {
        self.action
            .check_current()
            .map_err(|_| BridgeError::Permission)?;
        self.prepared.check_custody()?;
        self.action
            .check_current()
            .map_err(|_| BridgeError::Permission)
    }
    pub(crate) fn serve(mut self) -> Result<()> {
        self.check()?;
        let stream = self.prepared.stream.take().ok_or(BridgeError::Permission)?;
        // One consuming invocation only. Unknown send/final ACK is terminal;
        // neither the stream nor approved owner is returned for retry.
        FinancialReturnSenderV1::Coordinated(self).serve(stream)
    }
}

// Restriction-only clock comparison. A later review can narrow, never renew,
// the original authenticated request/source/channel/service/writer ceiling.
fn check_setup_ceiling(now: Instant, selected: Instant, originals: &[Instant]) -> Result<()> {
    if originals.is_empty() || now >= selected || originals.iter().any(|bound| selected > *bound) {
        return Err(BridgeError::Permission);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_setup_ceilings_cannot_be_extended_by_a_later_review() {
        let now = Instant::now();
        let early = now + Duration::from_secs(10);
        let late = now + Duration::from_secs(20);
        assert!(check_setup_ceiling(now, early, &[late, early, late]).is_ok());
        assert!(check_setup_ceiling(now, late, &[late, early, late]).is_err());
        assert!(check_setup_ceiling(early, early, &[late, early]).is_err());
        assert!(check_setup_ceiling(now, early, &[]).is_err());
    }
    #[test]
    fn already_expired_original_bound_cannot_be_rebased() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        assert!(check_setup_ceiling(now, later, &[now, later]).is_err());
        assert!(check_setup_ceiling(now, now, &[later]).is_err());
    }
}

// Pure complete Return display; no result/permission/stream constructor.
pub(crate) fn project_return_display(
    request: &FinancialResultRequestV1, result_digest: &str, outbox_digest: &str,
    original_host: &str, reviewed_digest: &str,
) -> String {
    format!(
        "RETURN ONLY THE ALREADY RETAINED EXACT FINANCIAL SIGNATURE RESULT\nAccount: {}\nAuthorization: {}\nOriginal consent: {}\nResult: {}\nOutbox: {}\nOriginal recipient: {}\nNo new signature, reservation or transaction.\nExact return: {}",
        request.account_id,
        request.authorization_id,
        request.original_consent_ref,
        result_digest,
        outbox_digest,
        original_host,
        reviewed_digest
    )
}
