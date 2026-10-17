//! Held, purpose-distinct native-born dispatch channel. No writer credential,
//! legacy permit, or caller-provided evidence can construct this receipt.
pub use super::born_history_ipc::BornOriginalHistoryLeaseV1;
use super::{
    BridgeError, Result,
    born_history_ipc::{BornOriginalHistoryRequestV1, hash},
    dispatch_ipc::BackendDisclosure,
    ipc::OriginalHistoryClient,
};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::net::UnixStream,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_authority::{
    born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1,
    born_offline_dispatch_v1::{BornOfflineDispatchAdmissionV1, BornOfflineDispatchRequestV1},
};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BornSubmissionRouteKindV1 {
    Direct,
    ExistingHttpConnect { origin: String },
}
/// Owned wire disclosure only. It cannot construct an adapter or claim a route
/// was used; the Host must compare it with its actual held adapter before use.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornSubmissionRouteV1 {
    pub backend: super::dispatch_ipc::DispatchBackend,
    pub route: BornSubmissionRouteKindV1,
    pub destination_tls_native_roots: bool,
    pub request_timeout_ms: u64,
    pub retries: u8,
    pub retry_delay_ms: u64,
    pub maximum_response_bytes: usize,
    pub observation_ttl_ms: u64,
    pub maximum_tip_age_ms: u64,
    pub maximum_clock_skew_ms: u64,
    pub maximum_reported_height_gap: u64,
}
impl BornSubmissionRouteV1 {
    pub fn from_actual(
        p: &wholepact_chain::public_read_profile_v1::PublicReadProfileV1,
    ) -> Result<Self> {
        use wholepact_chain::public_read_profile_v1::PublicReadRouteV1;
        let value = Self {
            backend: super::dispatch_ipc::DispatchBackend {
                source_id: p.backend.source_id.clone(),
                endpoint: p.backend.endpoint.clone(),
                trust_profile: p.backend.trust_profile.into(),
            },
            route: match &p.route {
                PublicReadRouteV1::Direct => BornSubmissionRouteKindV1::Direct,
                PublicReadRouteV1::ExistingHttpConnect { origin } => {
                    BornSubmissionRouteKindV1::ExistingHttpConnect {
                        origin: origin.clone(),
                    }
                }
            },
            destination_tls_native_roots: p.destination_tls_native_roots,
            request_timeout_ms: p.request_timeout_ms,
            retries: p.retries,
            retry_delay_ms: p.retry_delay_ms,
            maximum_response_bytes: p.maximum_response_bytes,
            observation_ttl_ms: p.observation_ttl_ms,
            maximum_tip_age_ms: p.maximum_tip_age_ms,
            maximum_clock_skew_ms: p.maximum_clock_skew_ms,
            maximum_reported_height_gap: p.maximum_reported_height_gap,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if !self.destination_tls_native_roots
            || !self.backend.endpoint.starts_with("https://")
            || self.backend.trust_profile != "single_tls_provider_report_not_consensus"
            || !(1..=30_000).contains(&self.request_timeout_ms)
            || self.retries > 2
            || self.retry_delay_ms > 2_000
            || !(1024..=8 * 1024 * 1024).contains(&self.maximum_response_bytes)
            || !(1..=300_000).contains(&self.observation_ttl_ms)
            || !(1..=1_800_000).contains(&self.maximum_tip_age_ms)
            || self.maximum_clock_skew_ms > 60_000
            || self.maximum_reported_height_gap > 3
        {
            return Err(BridgeError::Binding);
        }
        if let BornSubmissionRouteKindV1::ExistingHttpConnect { origin } = &self.route {
            let authority = origin
                .strip_prefix("http://")
                .ok_or(BridgeError::Binding)?
                .strip_suffix('/')
                .unwrap_or_else(|| origin.strip_prefix("http://").expect("checked scheme"));
            if authority.is_empty()
                || authority.len() > 2048
                || authority
                    .bytes()
                    .any(|b| !b.is_ascii_alphanumeric() && !b".-:[]".contains(&b))
            {
                return Err(BridgeError::Binding);
            }
            // The actual maintained adapter permits the default port and an
            // optional root slash. This wire reader never creates a route.
            let port = if authority.starts_with('[') {
                let end = authority.find(']').ok_or(BridgeError::Binding)?;
                let rest = &authority[end + 1..];
                if rest.is_empty() {
                    None
                } else {
                    Some(rest.strip_prefix(':').ok_or(BridgeError::Binding)?)
                }
            } else {
                authority
                    .rsplit_once(':')
                    .map(|(host, port)| if host.is_empty() { "" } else { port })
            };
            if port.is_some_and(|p| p.parse::<u16>().ok().filter(|v| *v > 0).is_none()) {
                return Err(BridgeError::Binding);
            }
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornDispatchRequestV1 {
    pub authorization_id: String,
    pub expected_original_ref: String,
    pub expected_born_origin_digest: String,
    pub operation_id: String,
    pub backend: BackendDisclosure,
    pub submission_route: BornSubmissionRouteV1,
    pub original_admission_digest: String,
    pub construction_link_digest: String,
    pub current_input_observation_digest: String,
    pub observed_at_ms: u64,
    pub observation_expires_at_ms: u64,
}
impl BornDispatchRequestV1 {
    pub fn backend_digest(&self) -> Result<String> {
        self.backend.digest()?;
        self.submission_route.validate()?;
        if self.backend.backend != self.submission_route.backend {
            return Err(BridgeError::Binding);
        }
        wholepact_core::proposal::canonical_digest(
            "wholepact:born-submission-backend-route:v1",
            &(&self.backend, &self.submission_route),
        )
        .map_err(|_| BridgeError::Binding)
    }
    pub(crate) fn history(&self) -> BornOriginalHistoryRequestV1 {
        BornOriginalHistoryRequestV1 {
            authorization_id: self.authorization_id.clone(),
            expected_original_ref: self.expected_original_ref.clone(),
            expected_born_origin_digest: self.expected_born_origin_digest.clone(),
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.history().validate()?;
        crate::review::validate_label(&self.operation_id).map_err(|_| BridgeError::Binding)?;
        self.backend_digest()?;
        for h in [
            &self.original_admission_digest,
            &self.construction_link_digest,
            &self.current_input_observation_digest,
        ] {
            hash(h)?;
        }
        if self.observed_at_ms == 0
            || self.observation_expires_at_ms <= self.observed_at_ms
            || self.observation_expires_at_ms - self.observed_at_ms > 60_000
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub(crate) fn matches_admission(&self, a: &BornOfflineDispatchAdmissionV1) -> Result<()> {
        a.matches_request(&a.request)?;
        self.matches_exact(&a.request, &a.original)
    }
    pub(crate) fn matches_exact(
        &self,
        r: &BornOfflineDispatchRequestV1,
        original: &BornOfflineAuthorizationAdmissionV1,
    ) -> Result<()> {
        self.validate()?;
        r.validate_original(original)?;
        let d = &r.dispatch;
        let t = &original.request.reservation.intent.terms;
        if d.operation_id != self.operation_id
            || d.backend_disclosure_digest != self.backend_digest()?
            || d.final_transaction_id != self.backend.descriptor.transaction_id
            || d.final_transaction_digest != self.backend.descriptor.bytes_sha256
            || d.transaction_expiry_height != self.backend.descriptor.expiry_height
            || r.original_admission_digest != self.original_admission_digest
            || r.construction_link_digest != self.construction_link_digest
            || r.current_input_observation_digest != self.current_input_observation_digest
            || r.observed_at_ms != self.observed_at_ms
            || r.observation_expires_at_ms != self.observation_expires_at_ms
            || t.authorization_id != self.authorization_id
            || t.agreement_id != self.backend.agreement_id
            || t.proposal_id != self.backend.descriptor.proposal_id
            || t.obligation_id != self.backend.descriptor.obligation_id
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BornDispatchResponseV1 {
    Admitted {
        lease_id: String,
        admission: Box<BornOfflineDispatchAdmissionV1>,
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
pub(crate) enum BornDispatchCommandV1 {
    CheckCurrent { check_id: String },
    Finish,
}
pub struct BornSignerDispatchAdmissionV1<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    failed: AtomicBool,
    lease_id: String,
    admission: BornOfflineDispatchAdmissionV1,
    deadline: Instant,
    wall_floor: u64,
}
fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BridgeError::Permission)?
        .as_millis()
        .try_into()
        .map_err(|_| BridgeError::Permission)
}
impl OriginalHistoryClient {
    pub fn request_born_dispatch_checked_until(
        &self,
        request: &BornDispatchRequestV1,
        original_deadline: Instant,
        check_current: impl Fn() -> Result<()>,
    ) -> Result<BornSignerDispatchAdmissionV1<'_>> {
        request.validate()?;
        let wall_floor = now_ms()?;
        if wall_floor < request.observed_at_ms || wall_floor >= request.observation_expires_at_ms {
            return Err(BridgeError::Permission);
        }
        let duration = Duration::from_millis(request.observation_expires_at_ms - wall_floor);
        let deadline = original_deadline.min(Instant::now() + duration);
        let current = || {
            check_current()?;
            let now = now_ms()?;
            if now < wall_floor || now >= request.observation_expires_at_ms {
                return Err(BridgeError::Permission);
            }
            Ok(())
        };
        let (stream, deadline) = self.open_born_request_checked_until(
            serde_json::json!({"operation":"request_born_dispatch_v1","request":request}),
            deadline,
            &current,
        )?;
        let bytes = super::born_ipc_io::read_checked(&stream, self.peer(), deadline, &current)?;
        let BornDispatchResponseV1::Admitted {
            lease_id,
            admission,
        } = serde_json::from_slice(&bytes).map_err(|_| BridgeError::Ipc)?
        else {
            return Err(BridgeError::Permission);
        };
        hash(&lease_id)?;
        request.matches_admission(&admission)?;
        let receipt = BornSignerDispatchAdmissionV1 {
            client: self,
            stream: Mutex::new(stream),
            failed: AtomicBool::new(false),
            lease_id,
            admission: *admission,
            deadline,
            wall_floor,
        };
        receipt.check_current_until(deadline)?;
        super::born_ipc_io::require_current(deadline, &current)?;
        Ok(receipt)
    }
}
impl BornSignerDispatchAdmissionV1<'_> {
    pub fn descriptor(&self) -> &BornOfflineDispatchAdmissionV1 {
        &self.admission
    }
    pub fn matches_request(&self, request: &BornDispatchRequestV1) -> Result<()> {
        request.matches_admission(&self.admission)?;
        self.check_current()
    }
    pub fn matches_request_until(
        &self,
        request: &BornDispatchRequestV1,
        original_deadline: Instant,
    ) -> Result<()> {
        request.matches_admission(&self.admission)?;
        self.check_current_until(original_deadline)
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
            let now = now_ms()?;
            if now < self.wall_floor
                || now >= self.admission.request.dispatch.admission_expires_at_ms
            {
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
                &BornDispatchCommandV1::CheckCurrent {
                    check_id: check_id.clone(),
                },
                deadline,
                &current,
            )?;
            let bytes = read_checked(&stream, self.client.peer(), deadline, &current)?;
            require_current(deadline, &current)?;
            match serde_json::from_slice(&bytes).map_err(|_| BridgeError::Ipc)? {
                BornDispatchResponseV1::Current {
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
impl Drop for BornSignerDispatchAdmissionV1<'_> {
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
                &BornDispatchCommandV1::Finish,
                Instant::now() + Duration::from_millis(100),
                &|| Ok(()),
            );
        }
    }
}

#[cfg(test)]
pub(crate) fn born_synthetic_request() -> BornDispatchRequestV1 {
    use super::dispatch_ipc::{DispatchBackend, DispatchTransaction};
    let backend = DispatchBackend {
        source_id: "synthetic-provider".into(),
        endpoint: "https://synthetic.invalid:443".into(),
        trust_profile: "single_tls_provider_report_not_consensus".into(),
    };
    BornDispatchRequestV1 {
        authorization_id: "synthetic-original".into(),
        expected_original_ref: "11".repeat(32),
        expected_born_origin_digest: "12".repeat(32),
        operation_id: "synthetic-born-dispatch".into(),
        backend: BackendDisclosure {
            schema_version: 1,
            profile_id: "synthetic-profile".into(),
            principal_id: "synthetic-owner".into(),
            agreement_id: "synthetic-agreement".into(),
            submission_journal_identity: "synthetic-journal".into(),
            descriptor: DispatchTransaction {
                operation_id: "synthetic-submit".into(),
                obligation_id: "synthetic-obligation".into(),
                proposal_id: "synthetic-proposal".into(),
                transaction_id: "13".repeat(32),
                bytes_sha256: "14".repeat(32),
                expiry_height: 4465100,
                network: "testnet".into(),
                consensus_branch_id: 0x77190ad9,
            },
            backend: backend.clone(),
            purpose: "submit_exact_retained_transaction".into(),
            confidence: "single_tls_provider_report_not_consensus".into(),
            minimum_expiry_margin_blocks: 10,
        },
        submission_route: BornSubmissionRouteV1 {
            backend,
            route: BornSubmissionRouteKindV1::Direct,
            destination_tls_native_roots: true,
            request_timeout_ms: 10000,
            retries: 1,
            retry_delay_ms: 250,
            maximum_response_bytes: 4 * 1024 * 1024,
            observation_ttl_ms: 60000,
            maximum_tip_age_ms: 1200000,
            maximum_clock_skew_ms: 30000,
            maximum_reported_height_gap: 2,
        },
        original_admission_digest: "15".repeat(32),
        construction_link_digest: "16".repeat(32),
        current_input_observation_digest: "17".repeat(32),
        observed_at_ms: 1000,
        observation_expires_at_ms: 61000,
    }
}
#[cfg(test)]
mod born_tests {
    use super::*;
    #[test]
    fn born_dispatch_data_binds_complete_backend_route_and_limits() {
        let request = born_synthetic_request();
        request.validate().unwrap();
        let digest = request.backend_digest().unwrap();
        assert_ne!(digest, request.backend.digest().unwrap());
        for change in 0..6 {
            let mut other = request.clone();
            match change {
                0 => {
                    other.submission_route.route = BornSubmissionRouteKindV1::ExistingHttpConnect {
                        origin: "http://proxy.invalid:8080/".into(),
                    }
                }
                1 => other.submission_route.request_timeout_ms += 1,
                2 => other.submission_route.observation_ttl_ms -= 1,
                3 => other.submission_route.maximum_response_bytes -= 1,
                4 => other.backend.descriptor.bytes_sha256 = "23".repeat(32),
                _ => other.backend.submission_journal_identity.push('2'),
            };
            assert_ne!(other.backend_digest().unwrap(), digest);
        }
    }
    #[test]
    fn born_dispatch_rejects_unbounded_expanded_or_credentialed_wire_data() {
        let request = born_synthetic_request();
        for change in 0..8 {
            let mut other = request.clone();
            match change {
                0 => other.observation_expires_at_ms += 1,
                1 => other.observed_at_ms = 0,
                2 => other.submission_route.backend.source_id.push('x'),
                3 => other.submission_route.destination_tls_native_roots = false,
                4 => other.submission_route.request_timeout_ms = 30001,
                5 => {
                    other.submission_route.route = BornSubmissionRouteKindV1::ExistingHttpConnect {
                        origin: "http://user:secret@proxy.invalid:8080".into(),
                    }
                }
                6 => {
                    other.submission_route.route = BornSubmissionRouteKindV1::ExistingHttpConnect {
                        origin: "https://proxy.invalid:8080".into(),
                    }
                }
                _ => {
                    other.submission_route.route = BornSubmissionRouteKindV1::ExistingHttpConnect {
                        origin: "http://proxy.invalid:8080/path".into(),
                    }
                }
            };
            assert!(other.validate().is_err(), "mutation {change}");
        }
        let mut raw = serde_json::to_value(&request).unwrap();
        raw["approved"] = true.into();
        assert!(serde_json::from_value::<BornDispatchRequestV1>(raw).is_err());
    }
    #[test]
    fn born_route_owned_projection_preserves_every_actual_disclosure_field() {
        let request = born_synthetic_request();
        let route = &request.submission_route;
        let actual = wholepact_chain::public_read_profile_v1::PublicReadProfileV1 {
            backend: wholepact_chain::BackendIdentity {
                source_id: route.backend.source_id.clone(),
                endpoint: route.backend.endpoint.clone(),
                trust_profile: "single_tls_provider_report_not_consensus",
            },
            route: wholepact_chain::public_read_profile_v1::PublicReadRouteV1::Direct,
            destination_tls_native_roots: route.destination_tls_native_roots,
            request_timeout_ms: route.request_timeout_ms,
            retries: route.retries,
            retry_delay_ms: route.retry_delay_ms,
            maximum_response_bytes: route.maximum_response_bytes,
            observation_ttl_ms: route.observation_ttl_ms,
            maximum_tip_age_ms: route.maximum_tip_age_ms,
            maximum_clock_skew_ms: route.maximum_clock_skew_ms,
            maximum_reported_height_gap: route.maximum_reported_height_gap,
        };
        let owned = BornSubmissionRouteV1::from_actual(&actual).unwrap();
        assert!(owned == *route);
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&owned).unwrap()
        );
        for origin in [
            "http://proxy.invalid",
            "http://proxy.invalid/",
            "http://proxy.invalid:8080/",
            "http://[::1]:8080",
        ] {
            let mut owned = owned.clone();
            owned.route = BornSubmissionRouteKindV1::ExistingHttpConnect {
                origin: origin.into(),
            };
            owned.validate().unwrap();
        }
    }
}
