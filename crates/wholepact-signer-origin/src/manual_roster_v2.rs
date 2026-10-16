//! STAGED, UNCOMPILED. Intended wholepact-signer-origin::manual_roster_v2.
//! These exact wire envelopes do not manufacture a current peer or lease.
use crate::manual::{
    HostManualEnrollmentIntent, HostManualEnrollmentRequest, ManualCurrentState,
    validate_admission_window,
};
use crate::{Error, Result, digest, hash};
use serde::{Deserialize, Serialize};
use wholepact_core::manual_enrollment::BornManualEnrollmentTerms;
pub use wholepact_core::manual_roster_v2::{HostRosterAppendBindingV2, HostRosterPredecessorV2};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostManualRosterEnrollmentIntentV2 {
    pub version: u16,
    pub account_intent: HostManualEnrollmentIntent,
    pub roster: HostRosterAppendBindingV2,
}
impl HostManualRosterEnrollmentIntentV2 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 2 {
            return Err(Error::Binding);
        }
        self.account_intent.validate()?;
        self.roster
            .validate_for_host(&self.account_intent.host)
            .map_err(|_| Error::Binding)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:host-manual-roster-enrollment-intent:v2", self)
    }
    pub fn matches_terms(
        &self,
        terms: &BornManualEnrollmentTerms,
        roster: &HostRosterAppendBindingV2,
    ) -> Result<()> {
        self.validate()?;
        self.account_intent.matches_terms(terms)?;
        if &self.roster != roster {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

/// Immutable account+roster native intent. No publication attempt is substituted
/// into this record when a new current session is separately approved.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostManualRosterEnrollmentRequestV2 {
    pub version: u16,
    pub enrollment: HostManualEnrollmentRequest,
    pub roster: HostRosterAppendBindingV2,
}
impl HostManualRosterEnrollmentRequestV2 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 2 {
            return Err(Error::Binding);
        }
        self.enrollment.validate()?;
        self.roster
            .validate_for_host(&self.enrollment.terms.host)
            .map_err(|_| Error::Binding)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:host-manual-roster-enrollment-request:v2", self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualRosterPublicationAttemptV2 {
    InitialV2 {},
    /// Digest of the NEW roster-bound authority continuation. Never the old
    /// V1 per-account continuation with a roster value appended by a caller.
    ContinuationV2 {
        continuation_digest: String,
        attempt_sequence: u64,
    },
}
impl ManualRosterPublicationAttemptV2 {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::InitialV2 {} => Ok(()),
            Self::ContinuationV2 {
                continuation_digest,
                attempt_sequence,
            } => {
                hash(continuation_digest)?;
                if *attempt_sequence < 2 || *attempt_sequence > i64::MAX as u64 {
                    return Err(Error::Binding);
                }
                Ok(())
            }
        }
    }
    pub fn sequence(&self) -> u64 {
        match self {
            Self::InitialV2 {} => 1,
            Self::ContinuationV2 {
                attempt_sequence, ..
            } => *attempt_sequence,
        }
    }
    pub fn digest_for(&self, witness_roster_extension_digest: &str) -> Result<String> {
        self.validate()?;
        hash(witness_roster_extension_digest)?;
        match self {
            Self::InitialV2 {} => digest(
                "wholepact:manual-roster-enrollment-initial-attempt:v2",
                &witness_roster_extension_digest,
            ),
            Self::ContinuationV2 {
                continuation_digest,
                ..
            } => Ok(continuation_digest.clone()),
        }
    }
}

/// This exact request is the lower publication pairing manifest. A native
/// original-intent pairing uses HostManualRosterEnrollmentIntentV2.digest(),
/// not this digest and never the nested V1 intent or request digest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostManualRosterPublicationRequestV2 {
    pub version: u16,
    pub enrollment: HostManualEnrollmentRequest,
    pub roster: HostRosterAppendBindingV2,
    pub attempt: ManualRosterPublicationAttemptV2,
}
impl HostManualRosterPublicationRequestV2 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 2 {
            return Err(Error::Binding);
        }
        self.enrollment.validate()?;
        self.roster
            .validate_for_host(&self.enrollment.terms.host)
            .map_err(|_| Error::Binding)?;
        self.attempt.validate()
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:host-manual-roster-publication-request:v2", self)
    }
    pub fn require_original(&self, original: &HostManualRosterEnrollmentRequestV2) -> Result<()> {
        self.validate()?;
        original.validate()?;
        if self.enrollment != original.enrollment || self.roster != original.roster {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableManualRosterAdmissionV2 {
    pub version: u16,
    pub exact_request_digest: String,
    /// Exact immutable encrypted V2 signer intent envelope, unchanged on retry
    /// and continuation. No V1 original is rewritten or retroactively wrapped.
    pub signer_intent_digest: String,
    /// Full ACTUAL new authority roster-admission record's digest_for result.
    pub witness_admission_digest: String,
    pub attempt_digest: String,
    pub attempt_sequence: u64,
    pub admitted_at_ms: u64,
    pub admission_deadline_ms: u64,
}
impl DurableManualRosterAdmissionV2 {
    pub fn validate_for(
        &self,
        request: &HostManualRosterPublicationRequestV2,
        witness_roster_extension_digest: &str,
    ) -> Result<()> {
        request.validate()?;
        for value in [
            &self.exact_request_digest,
            &self.signer_intent_digest,
            &self.witness_admission_digest,
            &self.attempt_digest,
        ] {
            hash(value)?;
        }
        if self.version != 2
            || self.exact_request_digest != request.digest()?
            || self.attempt_sequence != request.attempt.sequence()
            || self.attempt_digest
                != request
                    .attempt
                    .digest_for(witness_roster_extension_digest)?
        {
            return Err(Error::Binding);
        }
        let terms = &request.enrollment.terms;
        validate_admission_window(
            self.admitted_at_ms,
            self.admission_deadline_ms,
            terms.issued_at_ms,
            terms.scope.expires_at_ms,
            120_000,
        )
    }
    pub fn digest_for(
        &self,
        request: &HostManualRosterPublicationRequestV2,
        witness_roster_extension_digest: &str,
    ) -> Result<String> {
        self.validate_for(request, witness_roster_extension_digest)?;
        digest("wholepact:durable-manual-roster-admission:v2", self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterEnrollmentEvidenceV2 {
    pub version: u16,
    pub request: HostManualRosterPublicationRequestV2,
    pub enrollment_ref: String,
    pub signer_roster_record_digest: String,
    pub witness_roster_extension_digest: String,
    /// Actual INNER V1 account extension digest/ancestry. Host roster_sequence
    /// is independent, and cannot be used to claim another account extension.
    pub witness_extension_digest: String,
    pub witness_extension_sequence: u64,
    pub witness_extension_predecessor_digest: Option<String>,
    pub admission: DurableManualRosterAdmissionV2,
    pub current: ManualCurrentState,
}
impl ManualRosterEnrollmentEvidenceV2 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        for value in [
            &self.enrollment_ref,
            &self.signer_roster_record_digest,
            &self.witness_roster_extension_digest,
            &self.witness_extension_digest,
        ] {
            hash(value)?;
        }
        self.admission
            .validate_for(&self.request, &self.witness_roster_extension_digest)?;
        self.current.validate()?;
        let terms = &self.request.enrollment.terms;
        if self.version != 2
            || self.witness_extension_sequence != 1
            || self.witness_extension_predecessor_digest.is_some()
            || terms.host.scope_predecessor_digest.is_some()
            || self.current.writer_certificate_digest != terms.signer.writer_certificate_digest
            || self.current.writer_epoch != terms.signer.writer_epoch
            || self.admission.admission_deadline_ms > self.current.writer_session_expires_at_ms
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:manual-roster-enrollment-evidence:v2", self)
    }
    pub fn require_exact_retry(&self, original: &Self) -> Result<()> {
        self.validate()?;
        original.validate()?;
        if self.request != original.request
            || self.enrollment_ref != original.enrollment_ref
            || self.signer_roster_record_digest != original.signer_roster_record_digest
            || self.witness_roster_extension_digest != original.witness_roster_extension_digest
            || self.witness_extension_digest != original.witness_extension_digest
            || self.witness_extension_sequence != original.witness_extension_sequence
            || self.witness_extension_predecessor_digest
                != original.witness_extension_predecessor_digest
            || self.admission != original.admission
            || self.current.writer_session_digest != original.current.writer_session_digest
            || self.current.writer_session_expires_at_ms
                != original.current.writer_session_expires_at_ms
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_core::manual_roster_v2::HostRosterPredecessorV2;
    fn request() -> HostManualRosterPublicationRequestV2 {
        let enrollment = crate::manual_continuation_v2::tests::enrollment_request();
        let roster = HostRosterAppendBindingV2 {
            version: 2,
            generation_id: enrollment.terms.host.generation_id.clone(),
            store_destination_identity: enrollment.terms.host.store_destination_identity.clone(),
            roster_sequence: 2,
            predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: "a".repeat(64),
            },
        };
        HostManualRosterPublicationRequestV2 {
            version: 2,
            enrollment,
            roster,
            attempt: ManualRosterPublicationAttemptV2::InitialV2 {},
        }
    }
    #[test]
    fn roster_request_preserves_inner_bytes_and_separates_attempt_domain() {
        let request = request();
        request.validate().unwrap();
        let inner = serde_json::to_vec(&request.enrollment).unwrap();
        assert_ne!(
            request.digest().unwrap(),
            request.enrollment.digest().unwrap()
        );
        let mut continued = request.clone();
        continued.attempt = ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest: "b".repeat(64),
            attempt_sequence: 2,
        };
        continued.validate().unwrap();
        assert_eq!(inner, serde_json::to_vec(&continued.enrollment).unwrap());
        assert_ne!(request.digest().unwrap(), continued.digest().unwrap());
        let original = HostManualRosterEnrollmentRequestV2 {
            version: 2,
            enrollment: request.enrollment.clone(),
            roster: request.roster.clone(),
        };
        continued.require_original(&original).unwrap();
        continued.roster.predecessor = HostRosterPredecessorV2::EnrollmentV1 {
            audit_digest: "c".repeat(64),
        };
        assert!(continued.require_original(&original).is_err());
    }
    #[test]
    fn roster_admission_keeps_original_window_and_exact_attempt() {
        let request = request();
        let outer = "c".repeat(64);
        let mut admission = DurableManualRosterAdmissionV2 {
            version: 2,
            exact_request_digest: request.digest().unwrap(),
            signer_intent_digest: "d".repeat(64),
            witness_admission_digest: "e".repeat(64),
            attempt_digest: request.attempt.digest_for(&outer).unwrap(),
            attempt_sequence: 1,
            admitted_at_ms: 100,
            admission_deadline_ms: 1000,
        };
        admission.validate_for(&request, &outer).unwrap();
        assert!(admission.validate_for(&request, &"f".repeat(64)).is_err());
        admission.attempt_sequence = 2;
        assert!(admission.validate_for(&request, &outer).is_err());
        admission.attempt_sequence = 1;
        admission.admission_deadline_ms = 200_001;
        assert!(admission.validate_for(&request, &outer).is_err());
    }
    #[test]
    fn roster_request_rejects_unknown_fields_and_v1_downgrade() {
        let request = request();
        let mut json = serde_json::to_value(&request).unwrap();
        assert!(serde_json::from_value::<HostManualEnrollmentRequest>(json.clone()).is_err());
        json.as_object_mut()
            .unwrap()
            .insert("verified".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<HostManualRosterPublicationRequestV2>(json).is_err());
        let mut request = request;
        request.version = 1;
        assert!(request.validate().is_err());
    }
}
