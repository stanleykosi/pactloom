//! Pinned live signer dispatch channel. Wire evidence is never a public authority
//! constructor; the opaque receipt retains the authenticated connection.
use super::{
    ipc::{HistoryRequest, OriginalHistoryClient},
    BridgeError, Result,
};
use serde::{Deserialize, Serialize};
use std::{io::Write, os::unix::net::UnixStream, sync::Mutex, time::Duration};
use wholepact_authority::{AuthorizeDispatch, DispatchAdmission};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchTransaction {
    pub operation_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub transaction_id: String,
    pub bytes_sha256: String,
    pub expiry_height: u32,
    pub network: String,
    pub consensus_branch_id: u32,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchBackend {
    pub source_id: String,
    pub endpoint: String,
    pub trust_profile: String,
}
/// The complete reviewed descriptor, not an opaque host-supplied hash. Shape and
/// canonical domain intentionally match the host's exact native disclosure.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendDisclosure {
    pub schema_version: u16,
    pub profile_id: String,
    pub principal_id: String,
    pub agreement_id: String,
    pub submission_journal_identity: String,
    pub descriptor: DispatchTransaction,
    pub backend: DispatchBackend,
    pub purpose: String,
    pub confidence: String,
    pub minimum_expiry_margin_blocks: u32,
}
impl BackendDisclosure {
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:submission-backend-disclosure:v1",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
    fn validate(&self) -> Result<()> {
        let encoded = serde_json::to_string(self).map_err(|_| BridgeError::Binding)?;
        if encoded.len() > 16_384
            || self.schema_version != 1
            || self.purpose != "submit_exact_retained_transaction"
            || self.confidence != "single_tls_provider_report_not_consensus"
            || self.backend.trust_profile != self.confidence
            || !(1..=100).contains(&self.minimum_expiry_margin_blocks)
            || self.descriptor.network != "testnet"
            || self.descriptor.consensus_branch_id != 0x77190ad9
            || self.descriptor.expiry_height == 0
        {
            return Err(BridgeError::Binding);
        }
        for text in [
            &self.profile_id,
            &self.principal_id,
            &self.agreement_id,
            &self.submission_journal_identity,
            &self.descriptor.operation_id,
            &self.descriptor.obligation_id,
            &self.descriptor.proposal_id,
            &self.backend.source_id,
            &self.backend.endpoint,
        ] {
            if text.is_empty() || text.len() > 2048 || text.chars().any(char::is_control) {
                return Err(BridgeError::Binding);
            }
        }
        for hash in [
            &self.descriptor.transaction_id,
            &self.descriptor.bytes_sha256,
        ] {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(BridgeError::Binding);
            }
        }
        if !self.backend.endpoint.starts_with("https://") {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchRequest {
    pub history: HistoryRequest,
    pub operation_id: String,
    pub backend: BackendDisclosure,
}
impl DispatchRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        self.history.validate()?;
        crate::review::validate_label(&self.operation_id).map_err(|_| BridgeError::Binding)?;
        self.backend.validate()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DispatchResponse {
    Admitted {
        lease_id: String,
        admission: Box<DispatchAdmission>,
    },
    Current {
        lease_id: String,
    },
    Finished,
    Denied,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DispatchCommand {
    CheckCurrent,
    Finish,
}
pub(crate) fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| BridgeError::Ipc)?);
    if bytes.len() > 128 * 1024 {
        return Err(BridgeError::Limit);
    }
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| BridgeError::Ipc)?;
    stream
        .write_all(&bytes)
        .and_then(|_| stream.write_all(b"\n"))
        .and_then(|_| stream.flush())
        .map_err(|_| BridgeError::Ipc)
}
/// No Deserialize, Clone, or caller-provided evidence constructor. The live
/// pinned signer owns the witness credentials and holds the original lease.
pub struct SignerDispatchAdmission<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    lease_id: String,
    admission: DispatchAdmission,
}
impl OriginalHistoryClient {
    pub fn request_dispatch(
        &self,
        request: &DispatchRequest,
    ) -> Result<SignerDispatchAdmission<'_>> {
        request.validate()?;
        let stream = self.open_authenticated_request(
            serde_json::json!({"operation":"request_dispatch", "request":request}),
        )?;
        let bytes =
            crate::ipc::read_frame_with_deadline(&stream, self.peer(), Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let response: DispatchResponse =
            serde_json::from_slice(&bytes).map_err(|_| BridgeError::Ipc)?;
        let DispatchResponse::Admitted {
            lease_id,
            admission,
        } = response
        else {
            return Err(BridgeError::Permission);
        };
        let r = &admission.request;
        admission.matches_request(r)?;
        if lease_id.len() != 64
            || r.operation_id != request.operation_id
            || r.backend_disclosure_digest != request.backend.digest()?
            || r.final_transaction_id != request.backend.descriptor.transaction_id
            || r.final_transaction_digest != request.backend.descriptor.bytes_sha256
            || r.transaction_expiry_height != request.backend.descriptor.expiry_height
            || admission.reservation.request.authorization_id != request.history.authorization_id
            || admission.reservation.request.original_consent_ref
                != request.history.expected_original_consent_ref
            || admission.reservation.request.enrollment_ref
                != request.history.expected_enrollment_ref
            || admission.reservation.request.accepted_manifest_ref
                != request.history.expected_manifest_ref
        {
            return Err(BridgeError::Binding);
        }
        let receipt = SignerDispatchAdmission {
            client: self,
            stream: Mutex::new(stream),
            lease_id,
            admission: *admission,
        };
        receipt.check_current()?;
        Ok(receipt)
    }
}
impl SignerDispatchAdmission<'_> {
    pub fn descriptor(&self) -> &DispatchAdmission {
        &self.admission
    }
    pub fn matches_request(&self, request: &AuthorizeDispatch) -> Result<()> {
        self.admission.matches_request(request)?;
        self.check_current()
    }
    pub fn check_current(&self) -> Result<()> {
        self.client
            .peer()
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        write_frame(&mut stream, &DispatchCommand::CheckCurrent)?;
        let frame = crate::ipc::read_frame_with_deadline(
            &stream,
            self.client.peer(),
            Duration::from_secs(2),
        )
        .map_err(|_| BridgeError::Ipc)?;
        match serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)? {
            DispatchResponse::Current { lease_id } if lease_id == self.lease_id => Ok(()),
            _ => Err(BridgeError::Permission),
        }
    }
}
impl Drop for SignerDispatchAdmission<'_> {
    fn drop(&mut self) {
        if let Ok(mut stream) = self.stream.lock() {
            let _ = write_frame(&mut stream, &DispatchCommand::Finish);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> BackendDisclosure {
        BackendDisclosure {
            schema_version: 1,
            profile_id: "synthetic-profile".into(),
            principal_id: "synthetic-owner".into(),
            agreement_id: "synthetic-agreement".into(),
            submission_journal_identity: "synthetic-journal".into(),
            descriptor: DispatchTransaction {
                operation_id: "synthetic-submission".into(),
                obligation_id: "synthetic-obligation".into(),
                proposal_id: "synthetic-proposal".into(),
                transaction_id: "12".repeat(32),
                bytes_sha256: "34".repeat(32),
                expiry_height: 4_100_000,
                network: "testnet".into(),
                consensus_branch_id: 0x77190ad9,
            },
            backend: DispatchBackend {
                source_id: "synthetic-provider".into(),
                endpoint: "https://example.invalid:443".into(),
                trust_profile: "single_tls_provider_report_not_consensus".into(),
            },
            purpose: "submit_exact_retained_transaction".into(),
            confidence: "single_tls_provider_report_not_consensus".into(),
            minimum_expiry_margin_blocks: 10,
        }
    }
    #[test]
    fn complete_backend_and_transaction_are_canonical_digest_bound() {
        let original = fixture();
        let digest = original.digest().unwrap();
        let mut changed = original.clone();
        changed.backend.endpoint = "https://different.invalid".into();
        assert_ne!(digest, changed.digest().unwrap());
        let mut changed = original.clone();
        changed.descriptor.bytes_sha256 = "56".repeat(32);
        assert_ne!(digest, changed.digest().unwrap());
        let mut changed = original.clone();
        changed.minimum_expiry_margin_blocks += 1;
        assert_ne!(digest, changed.digest().unwrap());
        let mut changed = original.clone();
        changed.submission_journal_identity.push('2');
        assert_ne!(digest, changed.digest().unwrap());
        let value = serde_json::to_value(&original).unwrap();
        assert_eq!(
            digest,
            wholepact_core::proposal::canonical_digest(
                "wholepact:submission-backend-disclosure:v1",
                &value
            )
            .unwrap()
        );
    }
    #[test]
    fn malformed_or_misleading_disclosure_fails_closed() {
        let mut bad = fixture();
        bad.backend.endpoint = "http://example.invalid".into();
        assert!(bad.digest().is_err());
        let mut bad = fixture();
        bad.backend.source_id = "provider\nconsensus verified".into();
        assert!(bad.digest().is_err());
        let mut bad = fixture();
        bad.confidence = "consensus_verified".into();
        assert!(bad.digest().is_err());
        let mut bad = fixture();
        bad.descriptor.network = "mainnet".into();
        assert!(bad.digest().is_err());
        let mut bad = fixture();
        bad.descriptor.transaction_id = "ab".repeat(31);
        assert!(bad.digest().is_err());
        let mut value = serde_json::to_value(fixture()).unwrap();
        value["approved"] = true.into();
        assert!(serde_json::from_value::<BackendDisclosure>(value).is_err());
    }
}
