//! Second native review on the SAME still-current exact selection stream. This
//! does not reopen a source or reinterpret serialized data as native approval.
use super::*;
use wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2;
use wholepact_signer_origin::manual_roster_construction_v2::{
    ManualRosterContributionRetentionEvidenceV2, ManualRosterContributionRetentionResponseV2,
};

pub(crate) struct PreparedRosterContributionRetentionV2 {
    selected: candidate::PreparedRosterCandidateSelectionV2,
    request: ManualRosterContributionRetentionRequestV2,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedRosterContributionRetentionV2 {
    pub(super) fn prepare(
        selected: candidate::PreparedRosterCandidateSelectionV2,
        request: ManualRosterContributionRetentionRequestV2,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        selected.check(owner)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        if request.selection != selected.request
            || request.selection_evidence_digest
                != selected.evidence.digest().map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        request
            .remaining_admission_ms(now()?)
            .map_err(|_| Error::ReviewMismatch)?;
        let account = selected.source.enrolled.retained.account.account();
        let fvk = account.fvk()?;
        let change = wholepact_protocol::review::decode_testnet_receiver(&request.change_address)
            .map_err(|_| Error::ReviewMismatch)?;
        if fvk.scope_for_address(&change) != Some(orchard::keys::Scope::Internal) {
            return Err(Error::ReviewMismatch);
        }
        let pairing = crate::native_ui::AuthenticatedPairing::from_authenticated_request(
            selected.peer.clone(),
        )?;
        let digest = canonical(
            "wholepact:native-roster-exact-contribution-retention-review:v2",
            &(
                &request,
                pairing.binding(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        let display = Zeroizing::new(format!(
            "RETAIN THESE EXACT SELECTED INPUTS FOR SEQUENTIAL PROPOSAL ASSEMBLY\n{}\n\nActual paired process:\n{}\n\nApprove the displayed input IDs, nullifiers, values, selected chain context, actual same-account internal change, economic intent, participant roster, original checkpoint destination, provider and private wallet destination. The inputs/context are Host-reported maintained-wallet evidence; this review does not prove unspentness or consensus. The signer independently verifies that the displayed change belongs to this account. This purpose only retains and discloses this exact contribution to the paired local process for the fixed original invocation; it cannot construct, reserve budget, sign, prove, dispatch or spend. Every full-proposal contribution needs separate exact native review and witness Reserve/Consume. Retention stops at the original invocation completion deadline {} and never renews on re-pair, retry, restart or focus change. Cancellation and focus loss stop NEW admission. An already-admitted exact durable write and response may finish after focus changes; disclosed data cannot be recalled. A saved receipt is history, never signing, dispatch or reusable construction authority.\nExact review: {}",
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(pairing.binding()).map_err(|_| Error::InvalidData)?,
            request.completion_expires_at_ms(),
            digest
        ));
        let value = Self {
            selected,
            request,
            digest,
            display,
        };
        value.check(owner)?;
        Ok(value)
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.selected.check(owner)?;
        self.request
            .remaining_admission_ms(now()?)
            .map_err(|_| Error::ReviewMismatch)?;
        Ok(())
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.selected.review_json()?;
        self.request
            .remaining_admission_ms(now()?)
            .map_err(|_| Error::ReviewMismatch)?;
        Ok(self.display.to_string())
    }
    pub(crate) fn approve_and_retain(
        mut self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<BornRosterInventorySourceV2> {
        self.check(owner)?;
        if decision.binding() != &self.selected.native || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        let admitted_at_ms = now()?;
        let evidence = ManualRosterContributionRetentionEvidenceV2 {
            version: 2,
            request: self.request.clone(),
            retained_signer_intent_digest: self
                .selected
                .evidence
                .retained_signer_intent_digest
                .clone(),
            native_review_digest: self.digest.clone(),
            admitted_at_ms,
            selection_observation: self.selected.evidence.current.clone(),
        };
        evidence.validate().map_err(|_| Error::InvalidData)?;
        let remaining = self
            .selected
            .remaining()?
            .min(Duration::from_millis(
                self.request
                    .remaining_admission_ms(admitted_at_ms)
                    .map_err(|_| Error::ReviewMismatch)?,
            ))
            .min(Duration::from_secs(2));
        let deadline = Instant::now()
            .checked_add(remaining)
            .ok_or(Error::ReviewMismatch)?;
        let binding = self.selected.native.clone();
        let _admitted = binding.publication_lease()?;
        self.check(owner)?;
        // Admission boundary: no later focus/current checks turn a durable
        // receipt back into cancellation. Only exact bounded completion follows.
        let durable_receipt_digest = super::super::retention::retain_once(
            &self.selected.source.enrolled.retained,
            &evidence,
        )?;
        let response = ManualRosterContributionRetentionResponseV2::ExactContributionRetainedV2 {
            evidence: Box::new(evidence),
            durable_receipt_digest,
        };
        let mut bytes =
            Zeroizing::new(serde_json::to_vec(&response).map_err(|_| Error::InvalidData)?);
        if bytes.len()
            >= wholepact_signer_origin::manual_roster_construction_v2::MAX_ROSTER_CONSTRUCTION_FRAME
        {
            return Err(Error::Unavailable);
        }
        bytes.push(b'\n');
        let mut offset = 0;
        while offset < bytes.len() {
            let wall = now()?;
            if wall < admitted_at_ms || wall >= self.request.admission_expires_at_ms {
                return Err(Error::Uncertain);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(Error::Uncertain)?
                .min(Duration::from_millis(
                    self.request.admission_expires_at_ms - wall,
                ));
            self.selected.stream.set_write_timeout(Some(remaining))?;
            let n = self.selected.stream.write(&bytes[offset..])?;
            if n == 0 {
                return Err(Error::Uncertain);
            }
            offset += n;
        }
        if Instant::now() >= deadline {
            return Err(Error::Uncertain);
        }
        Ok(self.selected.source)
    }
}
