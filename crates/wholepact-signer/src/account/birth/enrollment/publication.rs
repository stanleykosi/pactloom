//! Typed finite publication proof variants. Audit decoding never constructs one.
use super::*;
use wholepact_authority::manual_session_continuation::{
    AuthenticatedBornManualEnrollmentV2, BornManualEnrollmentAdmissionRecordV2,
    ManualEnrollmentSessionContinuation,
};
use wholepact_authority::{AccountSnapshot, WriterSessionReceipt};
pub(super) enum BornManualWitness {
    First(Box<AuthenticatedBornManualEnrollment>),
    Continued(Box<AuthenticatedBornManualEnrollmentV2>),
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::account::birth) struct ContinuedAdmissionAudit {
    continuation: ManualEnrollmentSessionContinuation,
    record: BornManualEnrollmentAdmissionRecordV2,
}
/// Untagged inner format retains exact V1 admission bytes; outer version is
/// independently validated and V2 requires a distinct continuation+record shape.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(in crate::account::birth) enum AdmissionAudit {
    First(Box<BornManualEnrollmentAdmissionRecord>),
    Continued(Box<ContinuedAdmissionAudit>),
}
impl AdmissionAudit {
    pub(in crate::account::birth) fn version(&self) -> u16 {
        match self {
            Self::First(_) => 1,
            Self::Continued(_) => 2,
        }
    }
    pub(in crate::account::birth) fn validate(
        &self,
        extension: &ManualEnrollmentExtension,
    ) -> Result<()> {
        match self {
            Self::First(r) => r.validate_for(extension),
            Self::Continued(r) => r.record.validate_for(extension, &r.continuation),
        }
        .map_err(|_| Error::Authentication)
    }
}
impl BornManualWitness {
    pub(super) fn check_current(&self) -> wholepact_authority::Result<()> {
        match self {
            Self::First(p) => p.check_current(),
            Self::Continued(p) => p.check_current(),
        }
    }
    pub(super) fn extension(&self) -> &ManualEnrollmentExtension {
        match self {
            Self::First(p) => p.extension(),
            Self::Continued(p) => p.extension(),
        }
    }
    pub(super) fn snapshot(&self) -> &AccountSnapshot {
        match self {
            Self::First(p) => p.snapshot(),
            Self::Continued(p) => p.snapshot(),
        }
    }
    pub(super) fn session(&self) -> &WriterSessionReceipt {
        match self {
            Self::First(p) => p.session(),
            Self::Continued(p) => p.session(),
        }
    }
    pub(super) fn audit(&self) -> AdmissionAudit {
        match self {
            Self::First(p) => AdmissionAudit::First(Box::new(p.record().clone())),
            Self::Continued(p) => AdmissionAudit::Continued(Box::new(ContinuedAdmissionAudit {
                continuation: p.continuation().clone(),
                record: p.record().clone(),
            })),
        }
    }
    pub(super) fn retain_actual(&self, retained: &RetainedBornManualEnrollment) -> Result<()> {
        match self {
            Self::First(_) => Ok(()),
            Self::Continued(p) => attempts::retain_admission(retained, p),
        }
    }
    pub(super) fn require_retained(
        &self,
        retained: &RetainedBornManualEnrollment,
        commit: &BornManualCommit,
    ) -> Result<()> {
        if commit.extension != *self.extension() {
            return Err(Error::Authentication);
        }
        match self {
            Self::First(_) if commit.admission == self.audit() => Ok(()),
            Self::First(_) => Err(Error::Authentication),
            Self::Continued(proof) => {
                let exact = attempts::load(retained)?
                    .into_iter()
                    .find(|entry| &entry.proposal.continuation == proof.continuation())
                    .ok_or(Error::RecoveryRequired)?;
                if exact.admission.as_ref() != Some(proof.record()) {
                    return Err(Error::Authentication);
                }
                Ok(())
            }
        }
    }
}
impl RetainedBornManualEnrollment {
    pub(crate) fn prepare_publication_v2(
        self,
        history: ReconciledAuthorityHistory,
        witness: AuthenticatedBornManualEnrollmentV2,
        pairing: &crate::native_ui::AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedBornManualPublication> {
        let observed = history
            .latest_manual_attempt(&self.record.reference()?)
            .map_err(|_| Error::RecoveryRequired)?;
        if observed.continuation.as_ref() != Some(witness.continuation()) {
            return Err(Error::RecoveryRequired);
        }
        self.prepare_publication_inner(
            history,
            BornManualWitness::Continued(Box::new(witness)),
            pairing,
            owner,
        )
    }
}

impl AdmissionAudit {
    pub(in crate::account::birth) fn require_attempt_history(
        &self,
        entries: &[attempts::LocalContinuation],
    ) -> Result<()> {
        if let Self::Continued(a) = self {
            if !entries.iter().any(|entry| {
                entry.proposal.continuation == a.continuation
                    && entry.admission.as_ref() == Some(&a.record)
            }) {
                return Err(Error::Authentication);
            }
        }
        Ok(())
    }
}
impl BornManualEnrolledSigner {
    pub(crate) fn host_continuation_evidence(
        &self,
        request:&wholepact_signer_origin::manual_continuation_v2::HostManualEnrollmentContinuationRequestV2,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
        reviewed_digest: &str,
    ) -> Result<
        wholepact_signer_origin::manual_continuation_v2::ManualEnrollmentContinuationEvidenceV2,
    > {
        use wholepact_signer_origin::manual::ManualCurrentState;
        use wholepact_signer_origin::manual_continuation_v2::{
            DurableManualEnrollmentContinuationAdmissionV2, ManualEnrollmentContinuationEvidenceV2,
        };
        self.require_host_owner(peer, owner)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        let BornManualWitness::Continued(witness) = &self.witness else {
            return Err(Error::Unavailable);
        };
        let extension = witness.extension();
        let attempt_digest = witness
            .continuation()
            .digest_for(extension)
            .map_err(|_| Error::InvalidData)?;
        if request.enrollment.terms != self.retained.record.terms
            || request.continuation_digest != attempt_digest
            || !is_hash(reviewed_digest)
        {
            return Err(Error::ReviewMismatch);
        }
        let audit = original(&self.retained.account)?
            .anchor()
            .audit_historical_witness_link(&self.history)?;
        let snapshot = self.history.snapshot();
        let session = witness.session();
        let record = witness.record();
        let evidence = ManualEnrollmentContinuationEvidenceV2 {
            version: 2,
            request: request.clone(),
            enrollment_ref: self.retained.record.reference()?,
            witness_extension_digest: extension.digest().map_err(|_| Error::InvalidData)?,
            witness_extension_sequence: extension.sequence,
            witness_extension_predecessor_digest: extension.predecessor_digest.clone(),
            admission: DurableManualEnrollmentContinuationAdmissionV2 {
                version: 2,
                exact_request_digest: request.digest().map_err(|_| Error::InvalidData)?,
                signer_intent_digest: self.retained.intent_digest.clone(),
                witness_admission_digest: record
                    .digest_for(extension, witness.continuation())
                    .map_err(|_| Error::InvalidData)?,
                attempt_digest,
                attempt_sequence: witness.continuation().sequence,
                admitted_at_ms: record.admitted_at_ms,
                admission_deadline_ms: record.publication_expires_at_ms,
            },
            current: ManualCurrentState {
                writer_certificate_digest: session.writer_certificate_digest.clone(),
                writer_epoch: snapshot.writer_epoch,
                writer_session_digest: canonical(
                    "wholepact:born-manual-writer-session:v1",
                    session,
                )?,
                writer_session_expires_at_ms: session.expires_at_ms,
                witness_head_sequence: snapshot.head.sequence,
                witness_head_digest: snapshot.head.digest.clone(),
                complete_history_digest: self
                    .history
                    .history_digest()
                    .map_err(|_| Error::InvalidData)?,
                exclusion_checkpoint_digest: canonical(
                    "wholepact:born-manual-exclusion-checkpoint:v1",
                    audit.checkpoint(),
                )?,
                native_review_digest: reviewed_digest.into(),
            },
        };
        evidence.validate().map_err(|_| Error::InvalidData)?;
        self.require_host_owner(peer, owner)?;
        Ok(evidence)
    }
}
