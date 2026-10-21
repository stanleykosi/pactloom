//! Actual same-stream RedisclosureRead then separate Redisclose; no request grants.
use super::coordinated_receipts_v1::CoordinatedPreconstructionReadyV1;
use super::*;
use crate::authority_bridge::durable_construction_v1::{
    DurableConstructionOutboxV1, DurableConstructionRedisclosureLinkV1,
    DurableConstructionRedisclosureRequestV1, DurableConstructionResponseV1,
};
use crate::consent_journal::CoordinatedConstructionActionV1;
use crate::ipc::{CoordinatedLocalEventV1, CoordinatedPairPeerV1};
use std::os::unix::net::UnixStream;
use wholepact_financial_coordinator_origin::{
    SignerV3RediscloseFactsV1, SignerV3RediscloseFinalV1, SignerV3RedisclosedV1,
    SignerV3RedisclosurePreparedV1, SignerV3RedisclosureReadFactsV1,
    SignerV3RedisclosureReadFinalV1,
};
pub(crate) struct CoordinatedRedisclosureReadV1 {
    ready: CoordinatedPreconstructionReadyV1,
    stream: UnixStream,
    selector: DurableConstructionRedisclosureRequestV1,
    facts: SignerV3RedisclosureReadFactsV1,
    deadline: Instant,
}
pub(crate) struct CoordinatedRediscloseV1 {
    ready: CoordinatedPreconstructionReadyV1,
    stream: UnixStream,
    original: DurableConstructionOutboxV1,
    candidate: DurableConstructionOutboxV1,
    facts: SignerV3RediscloseFactsV1,
    deadline: Instant,
}
pub(crate) struct CoordinatedRedisclosedSourceV1 {
    pub(super) ready: CoordinatedPreconstructionReadyV1,
    pub(super) outbox: DurableConstructionOutboxV1,
    // None retains a real committed outbox after postcommit/send uncertainty.
    // It is terminal custody, not permission or a successful export report.
    report: Option<SignerV3RedisclosedV1>,
}
fn wall_deadline(captured: Instant, wall: u64, deadline: Instant, source_wall: u64) -> Result<u64> {
    let left = u64::try_from(deadline.saturating_duration_since(captured).as_millis())
        .map_err(|_| Error::Locked)?;
    if left == 0 {
        return Err(Error::Locked);
    }
    wall.checked_add(left)
        .map(|v| v.min(source_wall))
        .ok_or(Error::Locked)
}
impl CoordinatedPreconstructionReadyV1 {
    pub(crate) fn next_event(&self) -> Result<Option<CoordinatedLocalEventV1>> {
        self.check_current()?;
        self.pairing.next_event()
    }
    pub(crate) fn begin_redisclosure(
        self,
        peer: CoordinatedPairPeerV1,
        stream: UnixStream,
        selector: DurableConstructionRedisclosureRequestV1,
        original_request_deadline: Instant,
    ) -> Result<CoordinatedRedisclosureReadV1> {
        let captured = Instant::now();
        let wall = wall_ms()?;
        self.check_current()?;
        self.peer.require_same_grant(&peer)?;
        selector.validate().map_err(|_| Error::ReviewMismatch)?;
        if selector.enrollment_ref != self.enrollment.reference()
            || selector.accepted_manifest_ref != self.manifest.reference()
        {
            return Err(Error::ReviewMismatch);
        }
        let deadline = entry_deadline(
            captured,
            self.peer
                .deadline()
                .min(self.pairing.source.original_source_deadline)
                .min(original_request_deadline)
                .min(self.session.current_receipt_deadline(&self.enrollment,&self.manifest)?),
        )?;
        let mut facts=SignerV3RedisclosureReadFactsV1 {
            entry_presentation_digest:self.pairing.source.opened.entry_presentation_digest.clone(),
            source_identity_digest:self.pairing.source.opened.source_identity_digest.clone(),
            pair_grant_id:self.peer.grant_id().into(),pair_key_digest:self.peer.key_digest().into(),pair_channel_digest:self.peer.channel_digest().into(),pair_generation:self.peer.generation(),
            coordinated_session_id:self.enrollment.receipt().native_session_id().into(),
            current_enrollment_ref:self.enrollment.reference().into(),current_manifest_ref:self.manifest.reference().into(),
            selector_json:serde_json::to_string(&selector).map_err(|_|Error::InvalidData)?,selector_digest:String::new(),
            reviewed_at_ms:wall,expires_at_ms:wall_deadline(captured,wall,deadline,self.pairing.source.facts.source_expires_at_ms)?.min(self.enrollment.receipt().expires_at_ms()).min(self.manifest.receipt().expires_at_ms()),source_expires_at_ms:self.pairing.source.facts.source_expires_at_ms,
            display:format!("READ EXACT ORIGINAL OUTBOX ONLY\nOriginal operation: {}\nExpected original digest: {:?}\nNew operation: {}\nFresh enrollment: {}\nFresh manifest: {}\nNo append or material export is approved.",selector.original.operation_id,selector.original.expected_request_digest,selector.operation_id,self.enrollment.reference(),self.manifest.reference()),
        };
        facts.selector_digest = facts.calculate_selector_digest()?;
        facts.validate()?;
        Ok(CoordinatedRedisclosureReadV1 {
            ready: self,
            stream,
            selector,
            facts,
            deadline,
        })
    }
}
impl CoordinatedRedisclosureReadV1 {
    pub(crate) fn facts(&self) -> &SignerV3RedisclosureReadFactsV1 {
        &self.facts
    }
    pub(crate) fn original_review_deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.ready.check_current()?;
        if Instant::now() >= self.deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(crate) fn read(
        self,
        action: SignerV3RedisclosureReadFinalV1,
    ) -> Result<CoordinatedRediscloseV1> {
        self.check_current()?;
        action.check_current()?;
        if action.facts() != &self.facts || action.original_read_deadline() != self.deadline {
            return Err(Error::ReviewMismatch);
        }
        let source = &self.ready.pairing.source;
        source.retained.check()?;
        action.check_current()?;
        let pin = source.revision.as_ref().ok_or(Error::Unavailable)?;
        source
            .journal
            .check_coordinated_v3_redisclosure_revision(pin, &action)?;
        let lease = self.ready.session.acquire_construction_records(
            &source.journal,
            self.ready.enrollment.reference(),
            self.ready.manifest.reference(),
            &CoordinatedConstructionActionV1::Read(&action),
        )?;
        let original = source.journal.read_coordinated_redisclosure_original_v1(
            &self.selector.original,
            &lease,
            &action,
        )?;
        let mut request = original.request().clone();
        request.operation_id = self.selector.operation_id.clone();
        request.enrollment_ref = self.ready.enrollment.reference().into();
        request.accepted_manifest_ref = self.ready.manifest.reference().into();
        request.scope.constructor.authenticated_local_grant_digest =
            self.ready.peer.key_digest().into();
        request.scope.prover.authenticated_local_grant_digest = self.ready.peer.key_digest().into();
        crate::native_ui::durable_construction_v1::validate_original(&request, &lease)
            .map_err(|_| Error::ReviewMismatch)?;
        request
            .scope
            .check_valid_at(wall_ms()? / 1000)
            .map_err(|_| Error::Locked)?;
        if source.retained.account.account().recovery_required()
            || source.retained.account.account_id()? != request.scope.account_id
            || source.retained.account.account().privacy_domain() != request.scope.privacy_domain
        {
            return Err(Error::ReviewMismatch);
        }
        request
            .material
            .verify_owner(&source.retained.account.account().fvk()?)
            .map_err(|_| Error::ReviewMismatch)?;
        action.check_current()?;
        lease.require_current_durable_disclosure_receipts_v1()?;
        drop(lease);
        source
            .journal
            .check_coordinated_v3_redisclosure_revision(pin, &action)?;
        let prepared=SignerV3RedisclosurePreparedV1 {
            read_presentation_digest:action.presentation().presentation_digest.clone(),source_identity_digest:self.facts.source_identity_digest.clone(),current_enrollment_ref:self.facts.current_enrollment_ref.clone(),current_manifest_ref:self.facts.current_manifest_ref.clone(),coordinated_session_id:self.facts.coordinated_session_id.clone(),
            next_request_digest:request.digest().map_err(|_|Error::ReviewMismatch)?,material_digest:request.material.digest().map_err(|_|Error::ReviewMismatch)?,original_outbox_reference:original.reference().into(),original_request_digest:original.request_digest().into(),scope_digest:request.scope.digest().map_err(|_|Error::ReviewMismatch)?,
            display:format!("REDISCLOSE SAME ORIGINAL MATERIAL TO ACTUAL PAIRED HOST\nOriginal operation: {}\nOriginal outbox: {}\nNew operation: {}\nFresh enrollment: {}\nFresh manifest: {}\nExact material scope:\n{}",original.request().operation_id,original.reference(),request.operation_id,request.enrollment_ref,request.accepted_manifest_ref,serde_json::to_string(&request.scope).map_err(|_|Error::InvalidData)?),
        };
        prepared.validate()?;
        let candidate = DurableConstructionOutboxV1 {
            request,
            request_digest: prepared.next_request_digest.clone(),
            material_digest: prepared.material_digest.clone(),
            native_review_digest: String::new(),
            native_entry_digest: self.facts.entry_presentation_digest.clone(),
            recipient_grant_digest: self.ready.peer.key_digest().into(),
            original_channel_digest: self.ready.peer.channel_digest().into(),
            original_grant_id: self.ready.peer.grant_id().into(),
            recipient_transport: self.ready.enrollment.transport().clone(),
            redisclosure: Some(DurableConstructionRedisclosureLinkV1 {
                original_operation_id: original.request().operation_id.clone(),
                original_request_digest: original.request_digest().into(),
                original_outbox_reference: original.reference().into(),
            }),
            reference: String::new(),
        };
        // Freeze the second action now, still capped by the ORIGINAL received
        // request/stream deadline. No display or approval renews that bound.
        let captured = Instant::now();
        let wall = wall_ms()?;
        let material_deadline = captured
            .checked_add(Duration::from_millis(
                candidate
                    .request
                    .scope
                    .valid_until_unix_seconds
                    .saturating_mul(1000)
                    .saturating_sub(wall),
            ))
            .ok_or(Error::Locked)?;
        let deadline = self.deadline.min(material_deadline);
        let facts=SignerV3RediscloseFactsV1{entry_presentation_digest:self.facts.entry_presentation_digest.clone(),source_identity_digest:self.facts.source_identity_digest.clone(),pair_grant_id:self.facts.pair_grant_id.clone(),pair_key_digest:self.facts.pair_key_digest.clone(),pair_channel_digest:self.facts.pair_channel_digest.clone(),pair_generation:self.facts.pair_generation,coordinated_session_id:self.facts.coordinated_session_id.clone(),current_enrollment_ref:self.facts.current_enrollment_ref.clone(),current_manifest_ref:self.facts.current_manifest_ref.clone(),display:"Approve exactly this newly prepared redisclosure. Original row remains immutable; no delivery or spending.".into(),prepared,reviewed_at_ms:wall,expires_at_ms:wall_deadline(captured,wall,deadline,self.facts.source_expires_at_ms)?.min(self.facts.expires_at_ms),source_expires_at_ms:self.facts.source_expires_at_ms};
        facts.validate()?;
        action.finish_read()?;
        Ok(CoordinatedRediscloseV1 {
            ready: self.ready,
            stream: self.stream,
            original,
            candidate,
            facts,
            deadline,
        })
    }
}
impl CoordinatedRediscloseV1 {
    pub(crate) fn facts(&self) -> &SignerV3RediscloseFactsV1 {
        &self.facts
    }
    pub(crate) fn prepared_report(&self) -> &SignerV3RedisclosurePreparedV1 {
        &self.facts.prepared
    }
    pub(crate) fn original_review_deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.ready.check_current()?;
        if Instant::now() >= self.deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(crate) fn export(
        mut self,
        action: SignerV3RediscloseFinalV1,
    ) -> Result<CoordinatedRedisclosedSourceV1> {
        self.check_current()?;
        action.check_current()?;
        if action.facts() != &self.facts || action.original_export_deadline() != self.deadline {
            return Err(Error::ReviewMismatch);
        }
        self.candidate.native_review_digest = action.presentation().presentation_digest.clone();
        self.candidate.reference = self
            .candidate
            .compute_reference()
            .map_err(|_| Error::ReviewMismatch)?;
        self.candidate
            .validate_redisclosure_of(&self.original)
            .map_err(|_| Error::ReviewMismatch)?;
        let source = &mut self.ready.pairing.source;
        source.retained.check()?;
        action.check_current()?;
        let lease = self.ready.session.acquire_construction_records(
            &source.journal,
            self.ready.enrollment.reference(),
            self.ready.manifest.reference(),
            &CoordinatedConstructionActionV1::Export(&action),
        )?;
        crate::native_ui::durable_construction_v1::validate_original(
            self.candidate.request(),
            &lease,
        )
        .map_err(|_| Error::ReviewMismatch)?;
        let pin = source.revision.take().ok_or(Error::Unavailable)?;
        let (outbox, pin) = source
            .journal
            .append_coordinated_redisclosure_v1(pin, &lease, &self.candidate, &action)
            .map_err(|_| Error::Uncertain)?;
        let pin = match pin {
            Ok(pin) => pin,
            Err(_) => {
                drop(lease);
                return Ok(CoordinatedRedisclosedSourceV1 {
                    ready: self.ready, outbox, report: None,
                });
            }
        };
        source.revision = Some(pin);
        let response = DurableConstructionResponseV1::Retained {
            outbox: Box::new(outbox.clone()),
        };
        // Maintained entered-send boundary: readiness/waits precede final R and
        // immutable-deadline checks, immediately followed by one bounded syscall.
        // A syscall already entered may settle after R. Never retry on ambiguity.
        let sent = crate::authority_bridge::durable_review_ipc_v1::bounded_write_restricted(
            &mut self.stream,
            &response,
            self.deadline,
            || {
                action
                    .check_current()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
                self.ready
                    .peer
                    .check_current()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
                lease
                    .require_current_durable_disclosure_receipts_v1()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
                outbox
                    .request()
                    .scope
                    .check_valid_at(
                        wall_ms().map_err(|_| crate::authority_bridge::BridgeError::Permission)?
                            / 1000,
                    )
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)
            },
            &|| {
                self.ready
                    .peer
                    .check_current()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
                action
                    .check_current()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)
            },
        );
        drop(lease);
        if sent.is_err() {
            return Ok(CoordinatedRedisclosedSourceV1 {
                ready: self.ready, outbox, report: None,
            });
        }
        let report = SignerV3RedisclosedV1 {
            presentation_digest: action.presentation().presentation_digest.clone(),
            outbox_reference: outbox.reference().into(),
            request_digest: outbox.request_digest().into(),
        };
        let report = action.finish_export().ok().map(|()| report);
        Ok(CoordinatedRedisclosedSourceV1 {
            ready: self.ready,
            outbox,
            report,
        })
    }
}
impl CoordinatedRedisclosedSourceV1 {
    pub(crate) fn report(&self) -> Option<SignerV3RedisclosedV1> {
        self.report.clone()
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        if self.report.is_none() { return Err(Error::Uncertain); }
        self.ready.check_current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coordinated_redisclosure_original_request_clock_never_renews() {
        let start = Instant::now();
        let original = start + Duration::from_secs(120);
        let later = start + Duration::from_secs(95);
        assert_eq!(
            wall_deadline(later, 96_000, original, 901_000).unwrap(),
            121_000
        );
        assert!(wall_deadline(original, 121_000, original, 901_000).is_err());
    }
    #[test]
    fn coordinated_redisclosure_source_wall_is_still_a_ceiling() {
        let now = Instant::now();
        assert_eq!(
            wall_deadline(now, 1_000, now + Duration::from_secs(120), 9_000).unwrap(),
            9_000
        );
    }
}
