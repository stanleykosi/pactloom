//! Purpose-distinct, native-reviewed born history over the installed signer's
//! held authenticated local channel. Public evidence is inert, never a lease.
use super::{BridgeError, Result, ipc::OriginalHistoryClient};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::net::UnixStream,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use wholepact_authority::{
    AccountPolicy, AuthorityHead, ManualEnrollmentExtension, WitnessDisclosureDescriptor,
    born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1,
    born_offline_artifacts_v1::BornOfflineArtifactRecordV1,
    born_offline_construction_v1::BornOfflineConstructionOriginV1,
    born_offline_enrollment_v1::BornOfflineEnrollmentRecordV1,
};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOriginalHistoryRequestV1 {
    pub authorization_id: String,
    pub expected_original_ref: String,
    pub expected_born_origin_digest: String,
}
pub(crate) fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl BornOriginalHistoryRequestV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::review::validate_label(&self.authorization_id).map_err(|_| BridgeError::Binding)?;
        hash(&self.expected_original_ref)?;
        hash(&self.expected_born_origin_digest)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOriginalHistoryEvidenceV1 {
    pub account_policy: AccountPolicy,
    pub witness: WitnessDisclosureDescriptor,
    pub head: AuthorityHead,
    pub history_digest: String,
    pub admission: BornOfflineAuthorizationAdmissionV1,
    pub enrollment: BornOfflineEnrollmentRecordV1,
    pub artifacts: BornOfflineArtifactRecordV1,
    pub manual_extension: ManualEnrollmentExtension,
    pub construction: BornOfflineConstructionOriginV1,
    pub original_ref: String,
    pub born_origin_digest: String,
    pub retained_final_native_review_digest: String,
}
impl BornOriginalHistoryEvidenceV1 {
    pub(crate) fn matches(&self, request: &BornOriginalHistoryRequestV1) -> Result<()> {
        request.validate()?;
        self.witness.validate()?;
        self.admission.matches_request(&self.admission.request)?;
        self.admission.validate_reserved_policy_bounds(
            &self.account_policy,
            &self.enrollment.enrollment,
            &self.artifacts,
            &self.manual_extension,
        )?;
        self.admission
            .request
            .construction_link
            .validate_for(&self.construction, &self.admission.request.reservation)?;
        for h in [
            &self.history_digest,
            &self.head.digest,
            &self.retained_final_native_review_digest,
        ] {
            hash(h)?;
        }
        let t = &self.admission.request.reservation.intent.terms;
        if self.original_ref != request.expected_original_ref
            || self.born_origin_digest != request.expected_born_origin_digest
            || t.authorization_id != request.authorization_id
            || self.witness.account_id != t.account_id
            || self.witness.network_profile_id != t.network_profile_id
            || self.witness.witness_id != self.admission.reserved.witness_id
            || self.witness.policy_digest != self.admission.reserved.witness_policy_digest
            || self.head.sequence < self.admission.reserved.committed_head.sequence
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BornHistoryResponseV1 {
    Held {
        lease_id: String,
        evidence: Box<BornOriginalHistoryEvidenceV1>,
    },
    Current {
        lease_id: String,
        check_id: String,
    },
    Finished,
    Denied,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BornHistoryCommandV1 {
    CheckCurrent { check_id: String },
    Finish,
}
/// No deserialization, cloning or constructor from caller-supplied evidence.
pub struct BornOriginalHistoryLeaseV1<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    failed: AtomicBool,
    lease_id: String,
    evidence: BornOriginalHistoryEvidenceV1,
    deadline: Instant,
}
impl OriginalHistoryClient {
    pub fn acquire_born_original_history_checked_until(
        &self,
        request: &BornOriginalHistoryRequestV1,
        original_deadline: Instant,
        check_current: impl Fn() -> Result<()>,
    ) -> Result<BornOriginalHistoryLeaseV1<'_>> {
        request.validate()?;
        let deadline = Instant::now() + Duration::from_secs(900);
        let preflight_deadline = original_deadline.min(Instant::now() + Duration::from_secs(120));
        let (stream, preflight_deadline) = self.open_born_request_checked_until(
            serde_json::json!({"operation":"request_born_original_history_v1","request":request}),
            preflight_deadline,
            &check_current,
        )?;
        let bytes = super::born_ipc_io::read_checked(
            &stream,
            self.peer(),
            preflight_deadline,
            &check_current,
        )?;
        let BornHistoryResponseV1::Held { lease_id, evidence } =
            serde_json::from_slice(&bytes).map_err(|_| BridgeError::Ipc)?
        else {
            return Err(BridgeError::Permission);
        };
        hash(&lease_id)?;
        evidence.matches(request)?;
        let lease = BornOriginalHistoryLeaseV1 {
            client: self,
            stream: Mutex::new(stream),
            failed: AtomicBool::new(false),
            lease_id,
            evidence: *evidence,
            deadline,
        };
        lease.check_current_until(preflight_deadline)?;
        super::born_ipc_io::require_current(preflight_deadline, &check_current)?;
        Ok(lease)
    }
}
impl BornOriginalHistoryLeaseV1<'_> {
    pub fn evidence(&self) -> &BornOriginalHistoryEvidenceV1 {
        &self.evidence
    }
    pub fn check_current(&self) -> Result<()> {
        self.check_current_until(Instant::now() + Duration::from_secs(2))
    }
    /// Restricts this same lease; never renews either the original source or its deadline.
    pub fn check_current_until(&self, original_deadline: Instant) -> Result<()> {
        use super::born_ipc_io::{lock_until, read_checked, require_current, write_checked};
        let deadline = self
            .deadline
            .min(original_deadline)
            .min(Instant::now() + Duration::from_secs(2));
        let current = || {
            if self.failed.load(Ordering::Acquire) {
                return Err(BridgeError::Permission);
            }
            self.client
                .peer()
                .check_alive()
                .map_err(|_| BridgeError::Permission)
        };
        let result = (|| {
            require_current(deadline, &current)?;
            let mut stream = lock_until(&self.stream, deadline, &current)?;
            let check_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
            write_checked(
                &mut stream,
                &BornHistoryCommandV1::CheckCurrent {
                    check_id: check_id.clone(),
                },
                deadline,
                &current,
            )?;
            let bytes = read_checked(&stream, self.client.peer(), deadline, &current)?;
            require_current(deadline, &current)?;
            match serde_json::from_slice(&bytes).map_err(|_| BridgeError::Ipc)? {
                BornHistoryResponseV1::Current {
                    lease_id,
                    check_id: actual,
                } if lease_id == self.lease_id && actual == check_id => Ok(()),
                _ => Err(BridgeError::Permission),
            }
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
}
impl Drop for BornOriginalHistoryLeaseV1<'_> {
    fn drop(&mut self) {
        // Exclusive Drop cannot contend on the channel mutex. Finishing is a
        // bounded release notice, never renewed permission after expiry.
        if let Ok(stream) = self.stream.get_mut() {
            if self.failed.load(Ordering::Acquire) {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
            let _ = super::born_ipc_io::write_checked(
                stream,
                &BornHistoryCommandV1::Finish,
                Instant::now() + Duration::from_millis(100),
                &|| Ok(()),
            );
        }
    }
}

#[cfg(test)]
mod born_tests {
    use super::*;
    #[test]
    fn born_history_selector_is_exact_bounded_data_not_an_approval() {
        let r = BornOriginalHistoryRequestV1 {
            authorization_id: "synthetic-original".into(),
            expected_original_ref: "ab".repeat(32),
            expected_born_origin_digest: "cd".repeat(32),
        };
        r.validate().unwrap();
        for change in 0..4 {
            let mut other = r.clone();
            match change {
                0 => other.authorization_id.clear(),
                1 => other.expected_original_ref = "AB".repeat(32),
                2 => other.expected_born_origin_digest.pop().map(|_| ()).unwrap(),
                _ => other.authorization_id = "untrusted\nreview".into(),
            };
            assert!(other.validate().is_err());
        }
        let mut value = serde_json::to_value(&r).unwrap();
        value["native_approved"] = true.into();
        assert!(serde_json::from_value::<BornOriginalHistoryRequestV1>(value).is_err());
    }
}
