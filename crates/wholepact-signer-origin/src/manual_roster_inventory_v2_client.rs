//! Concrete installed-peer preliminary inventory consumer. There is no public
//! constructor, Clone or Deserialize for the current viewing owner.
use super::*;
use crate::manual_roster_inventory_v2::{
    ManualRosterInventoryEvidenceV2, ManualRosterInventoryResponseV2,
    MAX_PRELIMINARY_INVENTORY_FRAME,
};
use sha2::{Digest, Sha256};
use wholepact_core::manual_roster_inventory_v2::{
    ManualRosterInventoryRequestV2, ManualRosterInventoryScopeV2,
};

impl NativeManualClient {
    /// A distinct native pairing in the same actual live installed process.
    /// Reuses neither the old grant nor its publication purpose. The native
    /// producer independently requires its actual retained continued source.
    pub fn begin_roster_inventory_pair_before(
        self,
        application_label: &str,
        inventory: &ManualRosterInventoryScopeV2,
        deadline: Instant,
    ) -> Result<PendingNativeManualPair> {
        inventory.validate().map_err(|_| Error::Binding)?;
        self.require_scope(&inventory.inventory.enrollment)?;
        if self.active_leases.load(Ordering::Acquire) != 0 {
            return Err(Error::Locked);
        }
        label(application_label)?;
        let scope = PairScope {
            account_id: inventory.inventory.enrollment.identity.account_id.clone(),
            agreement_id: inventory.inventory.enrollment.scope.agreement_id.clone(),
            participant_id: inventory.inventory.enrollment.scope.participant_id.clone(),
            manifest_digest: inventory.pairing_digest().map_err(|_| Error::Binding)?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        let deadline = deadline.min(self.grant.expires);
        let mut stream =
            connect_local_before(&self.socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        framing::enable_credentials(stream.as_raw_fd())?;
        let peer = self.provider.verify_server(&stream)?;
        self.peer.same_live_process(&peer)?;
        let started = Instant::now();
        write_frame_until(
            &mut stream,
            &serde_json::json!({"command":"request_pairing","schema_version":1,"application_label":application_label,"scope":scope}),
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
            None,
        )?;
        remaining_before(deadline)?;
        Ok(PendingNativeManualPair {
            provider: self.provider,
            socket: self.socket,
            peer,
            scope,
            stream,
            started,
            deadline,
        })
    }
    fn require_roster_inventory_scope(
        &self,
        request: &ManualRosterInventoryRequestV2,
    ) -> Result<()> {
        request.validate().map_err(|_| Error::Binding)?;
        self.require_scope(&request.scope.inventory.enrollment)?;
        if self.scope.manifest_digest
            != request.scope.pairing_digest().map_err(|_| Error::Binding)?
            || self.scope.history_read
            || self.scope.authorization_export
            || self.scope.preconstruction_export
            || request.current_caller_binding_digest != self.current_caller_binding_digest()?
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn begin_roster_inventory_before(
        &self,
        request: &ManualRosterInventoryRequestV2,
        expected_retained_signer_intent_digest: &str,
        deadline: Instant,
    ) -> Result<PendingManualRosterInventoryV2<'_>> {
        hash(expected_retained_signer_intent_digest)?;
        self.require_roster_inventory_scope(request)?;
        let now = Instant::now();
        let window = request
            .remaining_ms(now_ms()?)
            .map_err(|_| Error::Permission)?;
        let deadline = deadline.min(self.grant.expires).min(
            now.checked_add(Duration::from_millis(window))
                .ok_or(Error::Permission)?,
        );
        remaining_before(deadline)?;
        let attempt = PendingRosterV2Attempt::new(&self.handoff, self.acquire_slot()?);
        // Guard is already armed if connect/write fails after partial delivery.
        let stream = self.open_request_before(
            serde_json::json!({"operation":"request_born_roster_inventory_v2","request":request}),
            deadline,
        )?;
        Ok(PendingManualRosterInventoryV2 {
            client: self,
            request: request.clone(),
            expected_retained_signer_intent_digest: expected_retained_signer_intent_digest.into(),
            pending: PendingRosterV2Stream(Some(stream)),
            attempt,
            deadline,
        })
    }
}
/// A queued request only. No privacy or current-owner capability exists until
/// the actual native producer discloses under the fixed original deadline.
pub struct PendingManualRosterInventoryV2<'client> {
    client: &'client NativeManualClient,
    request: ManualRosterInventoryRequestV2,
    expected_retained_signer_intent_digest: String,
    pending: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'client>,
    deadline: Instant,
}
impl<'client> PendingManualRosterInventoryV2<'client> {
    pub fn finish(mut self) -> Result<ManualRosterInventoryLeaseV2<'client>> {
        let bytes = Zeroizing::new(framing::read_frame_with_deadline(
            self.pending.stream()?,
            &self.client.peer,
            remaining_before(self.deadline)?,
        )?);
        if bytes.len() > MAX_PRELIMINARY_INVENTORY_FRAME {
            return Err(Error::Limit);
        }
        let response: ManualRosterInventoryResponseV2 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let ManualRosterInventoryResponseV2::RosterInventoryDisclosedV2 {
            lease_id,
            evidence,
            account_fvk_hex,
        } = &response
        else {
            return Err(Error::Permission);
        };
        evidence.validate()?;
        hash(lease_id)?;
        if evidence.request != self.request
            || evidence.retained_signer_intent_digest != self.expected_retained_signer_intent_digest
        {
            return Err(Error::Binding);
        }
        let fvk = checked_inventory_fvk(
            account_fvk_hex,
            &self
                .request
                .scope
                .inventory
                .enrollment
                .identity
                .full_viewing_key_digest,
        )?;
        let observed = Instant::now();
        let observed_at_ms = now_ms()?;
        let lifetime = original_deadline_budget(
            self.request.requested_at_ms,
            self.request.disclosure_expires_at_ms,
            observed_at_ms,
        )?
        .min(remaining_before(self.deadline)?);
        self.client.require_roster_inventory_scope(&self.request)?;
        let lease = ManualRosterInventoryLeaseV2 {
            held: HeldLease {
                client: self.client,
                stream: Mutex::new(self.pending.take()?),
                lease_id: lease_id.clone(),
                evidence_digest: evidence.digest()?,
                started: observed,
                lifetime,
                original_deadline: Some((observed_at_ms, self.request.disclosure_expires_at_ms)),
                failed: AtomicBool::new(false),
                completion: CompletionState::Pending,
                // Last field: no fallible initialization follows the transfer.
                _slot: self.attempt.transfer_to_held()?,
            },
            evidence: evidence.as_ref().clone(),
            fvk,
        };
        lease.check_current()?;
        Ok(lease)
    }
}
/// One live candidate-free viewing owner. It cannot be converted to construction,
/// signing, dispatch, a saved contribution, or an admitted completion owner.
pub struct ManualRosterInventoryLeaseV2<'client> {
    held: HeldLease<'client>,
    evidence: ManualRosterInventoryEvidenceV2,
    fvk: Zeroizing<[u8; 96]>,
}
impl ManualRosterInventoryLeaseV2<'_> {
    /// Finish this exact purpose and await the native producer's bounded ack.
    /// Failure poisons the current client for any later request or re-pairing.
    /// Durable external effects remain retained even if acknowledgment fails.
    pub fn finish(self) -> Result<()> {
        self.held.finish()
    }

    pub fn binding(&self) -> &ManualRosterInventoryRequestV2 {
        &self.evidence.request
    }
    pub fn evidence(&self) -> &ManualRosterInventoryEvidenceV2 {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.held.client.provider.native_enrollment_reference()
    }
    pub fn check_current(&self) -> Result<()> {
        self.held.check_current()
    }
    pub fn full_viewing_key_bytes(&self) -> Result<&[u8; 96]> {
        self.check_current()?;
        Ok(&self.fvk)
    }
}
fn checked_inventory_fvk(encoded: &str, expected: &str) -> Result<Zeroizing<[u8; 96]>> {
    hash(expected)?;
    if encoded.len() != 192 {
        return Err(Error::Binding);
    }
    let decoded = Zeroizing::new(hex::decode(encoded).map_err(|_| Error::Binding)?);
    let fvk = Zeroizing::new(<[u8; 96]>::try_from(decoded.as_slice()).map_err(|_| Error::Binding)?);
    if hex::encode(Sha256::digest(fvk.as_slice())) != expected {
        return Err(Error::Binding);
    }
    Ok(fvk)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preliminary_viewing_bytes_require_exact_actual_account_digest() {
        let bytes = [7u8; 96];
        let expected = hex::encode(Sha256::digest(bytes));
        assert_eq!(
            checked_inventory_fvk(&hex::encode(bytes), &expected)
                .unwrap()
                .as_slice(),
            &bytes
        );
        for bad in [
            String::new(),
            "0".repeat(190),
            "g".repeat(192),
            "0".repeat(192),
        ] {
            assert!(checked_inventory_fvk(&bad, &expected).is_err());
        }
        assert!(checked_inventory_fvk(&hex::encode(bytes), &"0".repeat(64)).is_err());
    }
    #[test]
    fn preliminary_deadline_is_remaining_original_time_not_reacquisition() {
        assert_eq!(
            original_deadline_budget(100, 30100, 30000).unwrap(),
            Duration::from_millis(100)
        );
        assert!(original_deadline_budget(100, 30100, 30100).is_err());
        assert!(original_deadline_budget(100, 30100, 99).is_err());
    }
}
