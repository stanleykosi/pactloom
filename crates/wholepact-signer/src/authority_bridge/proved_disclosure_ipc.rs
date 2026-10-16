//! Separate native permission to disclose one exact sensitive proved PCZT.
//! Descriptors are requests only; only the authenticated native response issues a lease.
use super::{BridgeError, Result, dispatch_ipc::write_frame, ipc::OriginalHistoryClient};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    os::unix::net::UnixStream,
    sync::Mutex,
    time::{Duration, Instant},
};
use wholepact_core::{Proposal, ProposalInput};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvedDisclosureRecipient {
    pub account_id: String,
    pub provider_enrollment_reference: String,
    pub process_instance: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvedDisclosureRequest {
    pub schema_version: u16,
    pub proposal: ProposalInput,
    pub account_id: String,
    pub participant_id: String,
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
    pub proved_artifact_sha256: String,
    pub review_binding: String,
    pub recipients: Vec<ProvedDisclosureRecipient>,
    pub purpose: String,
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl ProvedDisclosureRequest {
    pub fn validate(&self) -> Result<Proposal> {
        if serde_json::to_vec(self)
            .map_err(|_| BridgeError::Binding)?
            .len()
            > 128 * 1024
        {
            return Err(BridgeError::Limit);
        }
        for h in [
            &self.enrollment_ref,
            &self.accepted_manifest_ref,
            &self.proved_artifact_sha256,
            &self.review_binding,
        ] {
            hash(h)?;
        }
        let p = Proposal::validate(self.proposal.clone()).map_err(|_| BridgeError::Binding)?;
        if self.schema_version != 1
            || self.purpose != "private_proved_pczt_export_and_exact_review"
            || self.recipients.is_empty()
            || self.recipients.len() > 32
            || !p
                .manifest()
                .participants
                .iter()
                .any(|p| p.account_id == self.account_id && p.participant_id == self.participant_id)
        {
            return Err(BridgeError::Binding);
        }
        let actual: BTreeSet<_> = p
            .manifest()
            .participants
            .iter()
            .map(|p| &p.account_id)
            .collect();
        let listed: BTreeSet<_> = self.recipients.iter().map(|r| &r.account_id).collect();
        if actual != listed || listed.len() != self.recipients.len() {
            return Err(BridgeError::Binding);
        }
        for r in &self.recipients {
            hash(&r.provider_enrollment_reference)?;
            if r.process_instance.is_empty()
                || r.process_instance.len() > 2048
                || r.process_instance.chars().any(char::is_control)
            {
                return Err(BridgeError::Binding);
            }
        }
        Ok(p)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest("wholepact:proved-disclosure:v1", self)
            .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ProvedDisclosureResponse {
    Approved {
        lease_id: String,
        request_digest: String,
    },
    Current {
        lease_id: String,
    },
    Finished,
    Denied,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ProvedDisclosureCommand {
    CheckCurrent,
    Finish,
}
/// Non-cloneable live native permission. Hold every original owner's lease through
/// private artifact export and delivery to every exact installed recipient.
pub struct SignerProvedDisclosureLease<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    lease_id: String,
    request: ProvedDisclosureRequest,
    started: Instant,
}
impl OriginalHistoryClient {
    pub fn request_proved_disclosure(
        &self,
        request: &ProvedDisclosureRequest,
    ) -> Result<SignerProvedDisclosureLease<'_>> {
        request.validate()?;
        let stream = self.open_disclosure_request(
            serde_json::json!({"operation":"request_proved_disclosure", "request":request}),
        )?;
        let frame =
            crate::ipc::read_frame_with_deadline(&stream, self.peer(), Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let response: ProvedDisclosureResponse =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        let ProvedDisclosureResponse::Approved {
            lease_id,
            request_digest,
        } = response
        else {
            return Err(BridgeError::Permission);
        };
        hash(&lease_id)?;
        if request_digest != request.digest()? {
            return Err(BridgeError::Binding);
        }
        let lease = SignerProvedDisclosureLease {
            client: self,
            stream: Mutex::new(stream),
            lease_id,
            request: request.clone(),
            started: Instant::now(),
        };
        lease.check_current()?;
        Ok(lease)
    }
}
impl SignerProvedDisclosureLease<'_> {
    pub fn request(&self) -> &ProvedDisclosureRequest {
        &self.request
    }
    pub fn check_current(&self) -> Result<()> {
        if self.started.elapsed() >= Duration::from_secs(900) {
            return Err(BridgeError::Permission);
        }
        self.client
            .peer()
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        write_frame(&mut stream, &ProvedDisclosureCommand::CheckCurrent)?;
        let frame = crate::ipc::read_frame_with_deadline(
            &stream,
            self.client.peer(),
            Duration::from_secs(2),
        )
        .map_err(|_| BridgeError::Ipc)?;
        match serde_json::from_slice::<ProvedDisclosureResponse>(&frame)
            .map_err(|_| BridgeError::Ipc)?
        {
            ProvedDisclosureResponse::Current { lease_id } if lease_id == self.lease_id => Ok(()),
            _ => Err(BridgeError::Permission),
        }
    }
}
impl Drop for SignerProvedDisclosureLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut stream) = self.stream.lock() {
            let _ = write_frame(&mut stream, &ProvedDisclosureCommand::Finish);
        }
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;
    fn request() -> ProvedDisclosureRequest {
        let (accepted, _, _) = crate::manifest::tests::consent_fixture();
        let owner = &accepted.proposal.manifest().participants[0];
        ProvedDisclosureRequest {
            schema_version: 1,
            proposal: accepted.proposal.input().clone(),
            account_id: owner.account_id.clone(),
            participant_id: owner.participant_id.clone(),
            enrollment_ref: "11".repeat(32),
            accepted_manifest_ref: "22".repeat(32),
            proved_artifact_sha256: "33".repeat(32),
            review_binding: "44".repeat(32),
            recipients: accepted
                .proposal
                .manifest()
                .participants
                .iter()
                .map(|p| ProvedDisclosureRecipient {
                    account_id: p.account_id.clone(),
                    provider_enrollment_reference: "55".repeat(32),
                    process_instance: format!("synthetic-process-{}", p.account_id),
                })
                .collect(),
            purpose: "private_proved_pczt_export_and_exact_review".into(),
        }
    }
    #[test]
    fn rejects_broadened_missing_or_duplicate_disclosure_scope() {
        let original = request();
        assert!(original.validate().is_ok());
        for case in 0..7 {
            let mut r = original.clone();
            match case {
                0 => r.recipients.clear(),
                1 => r.recipients.push(r.recipients[0].clone()),
                2 => r.recipients[0].account_id = "unlisted-account".into(),
                3 => r.purpose = "all_future_proofs".into(),
                4 => r.proved_artifact_sha256.clear(),
                5 => r.recipients[0].provider_enrollment_reference.clear(),
                _ => r.participant_id = "substituted-owner".into(),
            }
            assert!(r.validate().is_err(), "case {case}");
        }
        let mut json = serde_json::to_value(original).unwrap();
        json["approved"] = true.into();
        assert!(serde_json::from_value::<ProvedDisclosureRequest>(json).is_err());
    }
    #[test]
    fn binds_exact_artifact_review_and_installed_recipient_process() {
        let original = request();
        let digest = original.digest().unwrap();
        for case in 0..6 {
            let mut r = original.clone();
            match case {
                0 => r.proved_artifact_sha256 = "66".repeat(32),
                1 => r.review_binding = "66".repeat(32),
                2 => r.recipients[0].process_instance = "different-process".into(),
                3 => r.recipients[0].provider_enrollment_reference = "66".repeat(32),
                4 => r.enrollment_ref = "66".repeat(32),
                _ => r.accepted_manifest_ref = "66".repeat(32),
            }
            assert_ne!(digest, r.digest().unwrap());
        }
    }
}
