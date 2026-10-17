//! Inert disclosure of the route already captured by a maintained adapter.
//! Never reads credentials, changes proxy settings, connects or grants access.
use crate::{BackendIdentity, ChainAdapter};
use serde::Serialize;
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PublicReadRouteV1 {
    Direct,
    /// Only a validated credential-free HTTP CONNECT proxy origin. Destination
    /// TLS/hostname verification remains enabled inside the tunnel.
    ExistingHttpConnect {
        origin: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicReadProfileV1 {
    pub backend: BackendIdentity,
    pub route: PublicReadRouteV1,
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
impl ChainAdapter {
    pub fn public_read_profile_v1(&self) -> PublicReadProfileV1 {
        let p = self.policy;
        // NetworkPolicy validation bounds every duration well below u64 millis.
        PublicReadProfileV1 {
            backend: self.identity.clone(),
            route: self.rpc.public_read_route_v1(),
            destination_tls_native_roots: self.identity.endpoint.starts_with("https://"),
            request_timeout_ms: p.request_timeout.as_millis() as u64,
            retries: p.retries,
            retry_delay_ms: p.retry_delay.as_millis() as u64,
            maximum_response_bytes: p.maximum_response_bytes,
            observation_ttl_ms: p.observation_ttl.as_millis() as u64,
            maximum_tip_age_ms: p.maximum_tip_age.as_millis() as u64,
            maximum_clock_skew_ms: p.maximum_clock_skew.as_millis() as u64,
            maximum_reported_height_gap: p.maximum_reported_height_gap,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_adapter_route_disclosure_preserves_bounds_without_connecting() {
        let adapter = ChainAdapter {
            identity: BackendIdentity {
                source_id: "test".into(),
                endpoint: "http://127.0.0.1:1".into(),
                trust_profile: "synthetic_never_chain_evidence",
            },
            policy: crate::NetworkPolicy::default(),
            rpc: crate::rpc::Rpc::for_test("http://127.0.0.1:1", crate::NetworkPolicy::default()),
        };
        let profile = adapter.public_read_profile_v1();
        assert_eq!(profile.route, PublicReadRouteV1::Direct);
        assert!(!profile.destination_tls_native_roots);
        assert_eq!(profile.request_timeout_ms, 10000);
        assert_eq!(profile.observation_ttl_ms, 60000);
    }
}
