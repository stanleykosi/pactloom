//! Distinct fresh Enrollment and Manifest on this SAME paired original source.
use super::*;
use crate::consent_journal::{
    AcceptedManifestRecord, AccountEnrollmentRecord, CoordinatedPreconstructionSessionV1,
    PreparedCoordinatedEnrollmentV1, PreparedCoordinatedManifestV1,
};
use crate::ipc::CoordinatedPairPeerV1;
use sha2::Digest;
use wholepact_financial_coordinator_origin::{
    SignerV3EnrollmentFactsV1, SignerV3EnrollmentFinalV1, SignerV3ManifestFactsV1,
    SignerV3ManifestFinalV1,
};

pub(crate) struct CoordinatedEnrollmentReviewV1 {
    pairing: CoordinatedSourcePairingV1,
    session: CoordinatedPreconstructionSessionV1,
    peer: CoordinatedPairPeerV1,
    prepared: PreparedCoordinatedEnrollmentV1,
    facts: SignerV3EnrollmentFactsV1,
    deadline: Instant,
}
pub(crate) struct CoordinatedManifestReviewV1 {
    pairing: CoordinatedSourcePairingV1,
    session: CoordinatedPreconstructionSessionV1,
    peer: CoordinatedPairPeerV1,
    enrollment: AccountEnrollmentRecord,
    prepared: PreparedCoordinatedManifestV1,
    facts: SignerV3ManifestFactsV1,
    deadline: Instant,
}
pub(crate) struct CoordinatedPreconstructionReadyV1 {
    pub(super) pairing: CoordinatedSourcePairingV1,
    pub(super) session: CoordinatedPreconstructionSessionV1,
    pub(super) peer: CoordinatedPairPeerV1,
    pub(super) enrollment: AccountEnrollmentRecord,
    pub(super) manifest: AcceptedManifestRecord,
}
impl CoordinatedSourcePairingV1 {
    pub(crate) fn begin_enrollment(
        mut self,
        peer: CoordinatedPairPeerV1,
    ) -> Result<CoordinatedEnrollmentReviewV1> {
        self.check_current()?;
        let session = CoordinatedPreconstructionSessionV1::from_original_pair(
            self.take_receipt_binding(&peer)?,
        )?;
        let prepared = session.stage_enrollment()?;
        let record = prepared.record();
        let receipt = record.receipt();
        let (historical_enrollment_ref, historical_manifest_ref) = prepared.historical_references();
        let facts = SignerV3EnrollmentFactsV1 {
            entry_presentation_digest: self.source.opened.entry_presentation_digest.clone(),
            source_identity_digest: self.source.opened.source_identity_digest.clone(),
            pair_grant_id: peer.grant_id().into(), pair_key_digest: peer.key_digest().into(), pair_channel_digest: peer.channel_digest().into(), pair_generation: peer.generation(),
            record_reference: record.reference().into(), record_json: serde_json::to_string(record).map_err(|_| Error::InvalidData)?,
            coordinated_session_id: receipt.native_session_id().into(), receipt_nonce: receipt.nonce().into(),
            historical_enrollment_ref: historical_enrollment_ref.into(), historical_manifest_ref: historical_manifest_ref.into(),
            reviewed_at_ms: receipt.reviewed_at_ms(), expires_at_ms: receipt.expires_at_ms(), source_expires_at_ms: self.source.facts.source_expires_at_ms,
            display: format!("FRESH ACCOUNT ENROLLMENT\nAccount: {}\nAgreement: {}\nParticipant: {}\nBudget limit (zatoshis): {}\nActual local Host grant: {}\nFresh record: {}\nThis does not approve the manifest, export or spending.",record.account_id(),record.agreement_id(),record.participant_id(),record.budget_limit_zatoshis(),peer.grant_id(),record.reference()),
        };
        let mut facts = facts;
        facts.display.push_str("\nCOMPLETE ORIGINAL PROPOSAL (fresh enrollment scope):\n");
        facts.display.push_str(&serde_json::to_string(self.source.manifest.proposal()?.input()).map_err(|_| Error::InvalidData)?);
        facts.validate()?;
        let deadline = prepared
            .original_review_deadline()?
            .min(self.source.original_source_deadline);
        self.check_current()?;
        Ok(CoordinatedEnrollmentReviewV1 {
            pairing: self,
            session,
            peer,
            prepared,
            facts,
            deadline,
        })
    }
}
impl CoordinatedEnrollmentReviewV1 {
    pub(crate) fn facts(&self) -> &SignerV3EnrollmentFactsV1 {
        &self.facts
    }
    pub(crate) fn original_review_deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.pairing.check_current()?;
        self.session.check_current()?;
        self.peer.check_current()
    }
    pub(crate) fn commit(
        mut self,
        action: SignerV3EnrollmentFinalV1,
    ) -> Result<CoordinatedManifestReviewV1> {
        self.check_current()?;
        action.check_current()?;
        if action.facts() != &self.facts || action.original_review_deadline() != self.deadline {
            return Err(Error::ReviewMismatch);
        }
        // Mathematical identity is checked only under the genuine Enrollment
        // Final, using the same actual account, never a Host-provided FVK.
        let account = &self.pairing.source.retained.account;
        if account.account_id()? != self.prepared.record().account_id()
            || hex::encode(sha2::Sha256::digest(account.account().fvk()?.to_bytes()))
                != self.prepared.record().account_fvk_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        action.check_current()?;
        self.pairing.source.retained.check()?;
        action.check_current()?;
        let pin = self
            .pairing
            .source
            .revision
            .take()
            .ok_or(Error::Unavailable)?;
        let (enrollment, pin) = self
            .session
            .commit_enrollment(&self.pairing.source.journal, pin, self.prepared, action)
            .map_err(|_| Error::Uncertain)?;
        self.pairing.source.revision = Some(pin);
        // Candidate/session/actual source are retained BEFORE the later Origin
        // report. Staging next public cached record grants no next approval.
        let prepared = self.session.stage_manifest(&enrollment)?;
        let record = prepared.record();
        let receipt = record.receipt();
        let facts = SignerV3ManifestFactsV1 {
            entry_presentation_digest: self.pairing.source.opened.entry_presentation_digest.clone(),
            source_identity_digest: self.pairing.source.opened.source_identity_digest.clone(),
            pair_grant_id:self.peer.grant_id().into(),pair_key_digest:self.peer.key_digest().into(),pair_channel_digest:self.peer.channel_digest().into(),pair_generation:self.peer.generation(),
            record_reference:record.reference().into(),record_json:serde_json::to_string(record).map_err(|_|Error::InvalidData)?,
            coordinated_session_id:receipt.native_session_id().into(),receipt_nonce:receipt.nonce().into(),current_enrollment_ref:enrollment.reference().into(),
            reviewed_at_ms:receipt.reviewed_at_ms(),expires_at_ms:receipt.expires_at_ms(),source_expires_at_ms:self.pairing.source.facts.source_expires_at_ms,
            display:format!("FRESH MANIFEST ACCEPTANCE\nCurrent enrollment: {}\nProposal: {}\nManifest: {}\nFresh record: {}\nNo private Read, export, delivery or spending is approved.",enrollment.reference(),record.proposal_digest(),record.proposal()?.manifest_digest(),record.reference()),
        };
        facts.validate()?;
        let deadline = prepared
            .original_review_deadline()?
            .min(self.pairing.source.original_source_deadline);
        Ok(CoordinatedManifestReviewV1 {
            pairing: self.pairing,
            session: self.session,
            peer: self.peer,
            enrollment,
            prepared,
            facts,
            deadline,
        })
    }
}
impl CoordinatedManifestReviewV1 {
    pub(crate) fn facts(&self) -> &SignerV3ManifestFactsV1 {
        &self.facts
    }
    pub(crate) fn original_review_deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.pairing.check_current()?;
        self.session.check_current()?;
        self.peer.check_current()
    }
    pub(crate) fn commit(
        mut self,
        action: SignerV3ManifestFinalV1,
    ) -> Result<CoordinatedPreconstructionReadyV1> {
        self.check_current()?;
        action.check_current()?;
        if action.facts() != &self.facts || action.original_review_deadline() != self.deadline {
            return Err(Error::ReviewMismatch);
        }
        self.pairing.source.retained.check()?;
        action.check_current()?;
        let pin = self
            .pairing
            .source
            .revision
            .take()
            .ok_or(Error::Unavailable)?;
        let (manifest, pin) = self
            .session
            .commit_manifest(&self.pairing.source.journal, pin, self.prepared, action)
            .map_err(|_| Error::Uncertain)?;
        self.pairing.source.revision = Some(pin);
        let ready = CoordinatedPreconstructionReadyV1 {
            pairing: self.pairing,
            session: self.session,
            peer: self.peer,
            enrollment: self.enrollment,
            manifest,
        };
        ready.check_current()?;
        Ok(ready)
    }
}
impl CoordinatedPreconstructionReadyV1 {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.pairing.check_current()?;
        self.peer.check_current()?;
        self.session
            .require_current_receipts(&self.enrollment, &self.manifest)?;
        Ok(())
    }
}
