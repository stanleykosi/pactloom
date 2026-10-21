//! Actual endpoint and source custody, never a historical pairing importer.
use super::*;
use crate::ipc::{CoordinatedLocalEventV1, CoordinatedLocalIpcV1, PendingPairing};
use std::os::unix::fs::PermissionsExt;
use wholepact_financial_coordinator_origin::{
    SignerV3PairEndpointV1, SignerV3PairFactsV1, SignerV3PairFinalV1,
};

pub(crate) struct CoordinatedSourcePairingV1 {
    // Stop/revoke/join listener before releasing the actual source or tempdir.
    ipc: CoordinatedLocalIpcV1,
    pub(super) source: CoordinatedOriginalDeliverySourceV1,
    _temporary: tempfile::TempDir,
    receipt_binding_taken: bool,
}
impl CoordinatedOriginalDeliverySourceV1 {
    pub(crate) fn into_pairing_endpoint(self) -> Result<CoordinatedSourcePairingV1> {
        self.check_retained_restriction()?;
        let root = std::fs::canonicalize(&self.facts.canonical_root)?;
        let parent = std::fs::canonicalize(std::env::temp_dir())?;
        if parent.starts_with(&root) {
            return Err(Error::InvalidData);
        }
        let temporary = tempfile::Builder::new()
            .prefix("wholepact-coordinated-v3-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)?;
        self.check_retained_restriction()?;
        let directory = crate::files::PrivateDirectory::open(temporary.path())?;
        self.check_retained_restriction()?;
        let ipc = CoordinatedLocalIpcV1::bind(
            directory,
            self.host.clone(),
            self.opened.source_identity_digest.clone(),
            Arc::clone(&self.lifetime),
            self.original_source_deadline,
        )?;
        self.check_retained_restriction()?;
        Ok(CoordinatedSourcePairingV1 {
            ipc,
            source: self,
            _temporary: temporary,
            receipt_binding_taken: false,
        })
    }
}
impl CoordinatedSourcePairingV1 {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.source.check_retained_restriction()?;
        self.ipc.check_current()
    }
    pub(crate) fn endpoint_path(&self) -> Result<&str> {
        self.check_current()?;
        self.ipc.socket_path().to_str().ok_or(Error::InvalidData)
    }
    pub(crate) fn next_event(&self) -> Result<Option<CoordinatedLocalEventV1>> {
        self.check_current()?;
        Ok(self.ipc.next_event())
    }
    pub(crate) fn pair_facts(
        &self,
        pending: &PendingPairing,
        endpoint: &SignerV3PairEndpointV1,
    ) -> Result<(SignerV3PairFactsV1, Instant, Instant)> {
        self.check_current()?;
        pending.same_live_process(&self.source.host)?;
        endpoint.validate()?;
        let enrollment = &self.source.enrollment;
        let proposal = self.source.manifest.proposal()?;
        if endpoint.endpoint_path != self.endpoint_path()?
            || endpoint.entry_presentation_digest != self.source.opened.entry_presentation_digest
            || endpoint.source_identity_digest != self.source.opened.source_identity_digest
            || endpoint.source_expires_at_ms != self.source.facts.source_expires_at_ms
            || pending.scope.account_id != enrollment.account_id()
            || pending.scope.participant_id != enrollment.participant_id()
            || pending.scope.agreement_id != enrollment.agreement_id()
            || pending.scope.manifest_digest != proposal.manifest_digest()
            || !pending.scope.history_read
            || !pending.scope.preconstruction_export
            || pending.scope.authorization_export
        {
            return Err(Error::ReviewMismatch);
        }
        let captured = Instant::now();
        let reviewed_at_ms = wall_ms()?;
        let channel_deadline = self.source.original_source_deadline.min(
            captured
                .checked_add(Duration::from_secs(900))
                .ok_or(Error::Locked)?,
        );
        let channel_expires_at_ms = reviewed_at_ms
            .checked_add(900_000)
            .ok_or(Error::Locked)?
            .min(self.source.facts.source_expires_at_ms);
        let deadline = entry_deadline(captured, channel_deadline)?.min(pending.original_deadline());
        let remaining_ms = u64::try_from(deadline.saturating_duration_since(captured).as_millis())
            .map_err(|_| Error::Locked)?;
        if remaining_ms == 0 { return Err(Error::Locked); }
        let expires_at_ms = reviewed_at_ms.checked_add(remaining_ms)
            .ok_or(Error::Locked)?.min(self.source.facts.source_expires_at_ms);
        let facts = SignerV3PairFactsV1 {
            entry_presentation_digest: endpoint.entry_presentation_digest.clone(),
            source_identity_digest: endpoint.source_identity_digest.clone(),
            endpoint_digest: endpoint.endpoint_digest.clone(),
            pairing_review_digest: pending.review_digest(self.ipc.generation())?,
            scope_json: serde_json::to_string(&pending.scope).map_err(|_| Error::InvalidData)?,
            generation: self.ipc.generation(),
            original_host_uid: self.source.host.uid(), original_host_pid: self.source.host.pid(),
            original_host_process_instance: self.source.host.instance().into(),
            signer_process_instance: endpoint.signer_process_instance.clone(),
            coordinated_provider_reference: endpoint.coordinated_provider_reference.clone(),
            reviewed_at_ms, expires_at_ms, source_expires_at_ms: endpoint.source_expires_at_ms,
            channel_expires_at_ms,
            display: format!("PAIR ORIGINAL HOST ONLY\nAccount: {}\nAgreement: {}\nParticipant: {}\nManifest: {}\nHost UID/PID: {}/{}\nNo enrollment, manifest acceptance, private Read, export or spending is approved.",
                enrollment.account_id(), enrollment.agreement_id(), enrollment.participant_id(),
                proposal.manifest_digest(), self.source.host.uid(), self.source.host.pid()),
        };
        let mut facts = facts;
        facts.display.push_str(&format!(
            "\nOriginal channel expires at unix-ms: {}",
            channel_expires_at_ms
        ));
        facts.validate()?;
        self.check_current()?;
        Ok((facts, deadline, channel_deadline))
    }
    pub(crate) fn approve_pairing(
        &self,
        pending: PendingPairing,
        action: SignerV3PairFinalV1,
    ) -> Result<()> {
        self.check_current()?;
        self.ipc.approve_pairing(pending, action)?;
        self.check_current()
    }
}

/// One-use link from this actual source owner, not a journal/record DTO importer.
pub(crate) struct CoordinatedSourceReceiptBindingV1 {
    journal: crate::consent_journal::SignerJournalBinding,
    enrollment: crate::consent_journal::AccountEnrollmentRecord,
    manifest: crate::consent_journal::AcceptedManifestRecord,
    peer: crate::ipc::CoordinatedPairPeerV1,
    source_expires_at_ms: u64,
}
impl CoordinatedSourcePairingV1 {
    pub(crate) fn take_receipt_binding(
        &mut self,
        peer: &crate::ipc::CoordinatedPairPeerV1,
    ) -> Result<CoordinatedSourceReceiptBindingV1> {
        self.check_current()?;
        peer.check_current()?;
        peer.actual_peer().same_live_process(&self.source.host)?;
        if self.receipt_binding_taken
            || peer.source_identity() != self.source.opened.source_identity_digest
            || peer.original_host_process_instance() != self.source.host.instance()
        {
            return Err(Error::ReviewMismatch);
        }
        self.receipt_binding_taken = true;
        Ok(CoordinatedSourceReceiptBindingV1 {
            journal: self.source.journal.binding(),
            enrollment: self.source.enrollment.clone(),
            manifest: self.source.manifest.clone(),
            peer: peer.clone(),
            source_expires_at_ms: self.source.facts.source_expires_at_ms,
        })
    }
}
impl CoordinatedSourceReceiptBindingV1 {
    pub(crate) fn into_session_parts(
        self,
    ) -> Result<(
        crate::consent_journal::SignerJournalBinding,
        crate::consent_journal::AccountEnrollmentRecord,
        crate::consent_journal::AcceptedManifestRecord,
        crate::ipc::CoordinatedPairPeerV1,
        u64,
    )> {
        self.peer.check_current()?;
        Ok((
            self.journal,
            self.enrollment,
            self.manifest,
            self.peer,
            self.source_expires_at_ms,
        ))
    }
}

/// Same original endpoint and token, monotonically narrowed to Return requests.
/// No old source, database, consent session or private Read owner survives here.
pub(crate) struct CoordinatedFinancialRoleTransportV1 {
    transport: crate::ipc::CoordinatedReturnTransportV1,
    _temporary: tempfile::TempDir,
    completed: wholepact_financial_coordinator_origin::SignerV3CompletedLifetimeV1,
}
impl CoordinatedFinancialRoleTransportV1 {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.completed.check_current()?;
        self.transport.check_current()
    }
    pub(crate) fn next_result(&self) -> Result<Option<crate::ipc::CoordinatedFinancialResultEventV1>> {
        self.check_current()?;
        self.transport.next_result()
    }
    pub(crate) fn require_peer(&self,peer:&crate::ipc::CoordinatedPairPeerV1)->Result<()> {
        self.transport.original_peer().require_same_grant(peer)?;
        self.check_current()
    }
}
impl CoordinatedSourcePairingV1 {
    /// Called by the actual consumed completed source only, with no worker or
    /// response stream outstanding. ACK/drain occurs before dropping old files.
    pub(super) fn into_financial_role_transport(
        self, completed:wholepact_financial_coordinator_origin::SignerV3CompletedLifetimeV1,
    )->Result<(CoordinatedFinancialRoleTransportV1,PeerProcess)> {
        self.check_current()?;
        completed.check_current()?;
        if completed.source_identity_digest()!=self.source.opened.source_identity_digest
            || completed.original_source_deadline()!=self.source.original_source_deadline
        {return Err(Error::ReviewMismatch);}
        let transport=self.ipc.enter_financial_return_only(&completed)?;
        completed.check_current()?;
        // This is the same original kernel-backed H token, never the random
        // observed socket instance or a newly imported PID/descriptor.
        let host=self.source.host.clone();
        host.check_alive()?;
        drop(self.source);
        let retained=CoordinatedFinancialRoleTransportV1 {
            transport,_temporary:self._temporary,completed,
        };
        retained.check_current()?;
        Ok((retained,host))
    }
}
