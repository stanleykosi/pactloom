//! Narrow protobuf projection of pinned lightwallet-protocol. See evidence/ and docs.
//! Field numbers/wire types are unchanged; unused fields are intentionally skipped.
use crate::{CacheStatus, ChainError, NetworkPolicy, RpcCacheObservation, proxy::ProxyRoute};
use prost::Message;
use crate::transport_diagnostics::{Observer, FailureSite};
use tonic::{
    Request,
    transport::{ClientTlsConfig, Endpoint},
};
use tonic_prost::ProstCodec;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Empty {}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct BlockId {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub hash: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct LightdInfo {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "2")]
    pub vendor: String,
    #[prost(string, tag = "4")]
    pub chain_name: String,
    #[prost(uint64, tag = "5")]
    pub sapling_activation_height: u64,
    #[prost(string, tag = "6")]
    pub consensus_branch_id: String,
    #[prost(uint64, tag = "7")]
    pub block_height: u64,
    #[prost(uint64, tag = "12")]
    pub estimated_height: u64,
    #[prost(string, tag = "14")]
    pub zcashd_subversion: String,
    #[prost(string, tag = "18")]
    pub protocol_version: String,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct CompactBlock {
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub prev_hash: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub time: u32,
    #[prost(message, repeated, tag = "7")]
    pub vtx: Vec<CompactTx>,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct CompactTx {
    #[prost(uint64, tag = "1")]
    pub index: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub txid: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct TxFilter {
    #[prost(bytes = "vec", tag = "3")]
    pub hash: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct RawTransaction {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub height: u64,
}
#[cfg(feature = "submission-dispatch")]
#[derive(Clone, PartialEq, Message)]
struct SendResponse {
    #[prost(int32, tag = "1")]
    error_code: i32,
    // Upstream text is bounded by the response cap and deliberately never retained.
    #[prost(string, tag = "2")]
    error_message: String,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct TreeState {
    #[prost(string, tag = "1")]
    pub network: String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(string, tag = "3")]
    pub hash: String,
    #[prost(uint32, tag = "4")]
    pub time: u32,
    #[prost(string, tag = "7")]
    pub ironwood_tree: String,
}

#[derive(Debug)]
pub(crate) struct Observed<T> {
    pub message: T,
    pub cache: RpcCacheObservation,
}
impl<T> std::ops::Deref for Observed<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.message
    }
}
pub(crate) fn cache_observation(
    method: &'static str,
    metadata: &tonic::metadata::MetadataMap,
) -> RpcCacheObservation {
    let cache_status = match metadata.get("x-cache").and_then(|v| v.to_str().ok()) {
        None if !metadata.contains_key("x-cache") => CacheStatus::NotReported,
        Some(s) if s.eq_ignore_ascii_case("hit") => CacheStatus::Hit,
        Some(s) if s.eq_ignore_ascii_case("miss") => CacheStatus::Miss,
        _ => CacheStatus::OtherReported,
    };
    let age = metadata.get("age");
    let reported_age_seconds = age.and_then(|v| v.to_str().ok()).and_then(|s| {
        if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
            None
        } else {
            s.parse().ok()
        }
    });
    RpcCacheObservation {
        method: method.rsplit('/').next().unwrap_or("unknown"),
        cache_status,
        reported_age_seconds,
        malformed_age: age.is_some() && reported_age_seconds.is_none(),
    }
}

// Unary decoding bounds do not cap all bytes while draining trailers. Bound
// the complete HTTP/2 body too, including its five-byte gRPC envelope.
#[derive(Clone)]
struct BoundedChannel(tonic::transport::Channel, usize, Observer);
impl tower::Service<tonic::codegen::http::Request<tonic::body::Body>> for BoundedChannel {
    type Response = tonic::codegen::http::Response<tonic::body::Body>;
    type Error = tonic::Status;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0
            .poll_ready(cx)
            .map_err(|error| {
                self.2.record(FailureSite::Readiness);
                tonic::Status::from_error(Box::new(error))
            })
    }
    fn call(&mut self, request: tonic::codegen::http::Request<tonic::body::Body>) -> Self::Future {
        let method = request.uri().path().to_owned();
        let response = self.0.call(request);
        let limit = self.1;
        let observer = self.2.clone();
        Box::pin(async move {
            let response = response
                .await
                .map_err(|error| {
                    observer.record(FailureSite::Request);
                    tonic::Status::from_error(Box::new(error))
                })?;
            crate::wire_guard::guard_response_observed(response, limit, &method, &observer)
                .await
                .map_err(|error| match error {
                    ChainError::ResourceLimit => {
                        tonic::Status::resource_exhausted("bounded response resource limit")
                    }
                    ChainError::TransportUnavailable => {
                        tonic::Status::unavailable("bounded response interrupted")
                    }
                    _ => tonic::Status::data_loss("malformed bounded response"),
                })
        })
    }
}

pub(crate) struct Rpc {
    endpoint: Endpoint,
    policy: NetworkPolicy,
    route: ProxyRoute,
    pub(crate) observer: Observer,
}
impl Rpc {
    pub(crate) fn public_read_route_v1(&self) -> crate::public_read_profile_v1::PublicReadRouteV1 {
        use crate::public_read_profile_v1::PublicReadRouteV1;
        match &self.route {
            ProxyRoute::Direct => PublicReadRouteV1::Direct,
            ProxyRoute::HttpTunnel(origin) => PublicReadRouteV1::ExistingHttpConnect {
                origin: origin.to_string(),
            },
        }
    }

    #[cfg(feature = "submission-dispatch")]
    async fn connect_observed(&self) -> Result<tonic::transport::Channel, ChainError> {
        self.route.connect(&self.endpoint).await.map_err(|error| {
            self.observer.record(FailureSite::ConnectIncludingTls);
            error
        })
    }
    async fn connect_read_observed_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<tonic::transport::Channel, ChainError> {
        crate::connect_driver::connect_until(self.route.clone(), self.endpoint.clone(), deadline)
            .await
            .map_err(|error| {
                if error == ChainError::TransportUnavailable {
                    self.observer.record(FailureSite::ConnectIncludingTls);
                }
                error
            })
    }
    pub(crate) async fn connect(&self) -> Result<tonic::transport::Channel, ChainError> {
        let deadline = tokio::time::Instant::now() + self.policy.request_timeout;
        self.connect_read_observed_until(deadline).await
    }
    pub fn new(endpoint: &str, policy: NetworkPolicy) -> Result<Self, ChainError> {
        let endpoint = Endpoint::from_shared(endpoint.to_owned())
            .map_err(|_| ChainError::InvalidConfiguration)?
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .map_err(|_| ChainError::InvalidConfiguration)?
            .connect_timeout(policy.request_timeout)
            .concurrency_limit(1)
            .http2_max_header_list_size(16 * 1024);
        let route = ProxyRoute::from_environment(endpoint.uri())?;
        Ok(Self {
            endpoint,
            policy,
            route,
            observer: Observer::default(),
        })
    }
    #[cfg(any(test, feature = "synthetic-qualification"))]
    pub(crate) fn for_test(endpoint: &str, policy: NetworkPolicy) -> Self {
        Self {
            endpoint: Endpoint::from_shared(endpoint.to_owned())
                .unwrap()
                .connect_timeout(policy.request_timeout),
            policy,
            route: ProxyRoute::Direct,
            observer: Observer::default(),
        }
    }
    #[cfg(test)]
    pub(crate) fn for_proxy_test(
        endpoint: &str,
        proxy: &str,
        policy: NetworkPolicy,
        test_ca: Option<&[u8]>,
    ) -> Self {
        let mut tls = ClientTlsConfig::new().with_native_roots();
        if let Some(ca) = test_ca {
            tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(ca));
        }
        let endpoint = Endpoint::from_shared(endpoint.to_owned())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect_timeout(policy.request_timeout)
            .http2_max_header_list_size(16 * 1024);
        let route = ProxyRoute::from_configuration(endpoint.uri(), Some(proxy), None).unwrap();
        Self {
            endpoint,
            policy,
            route,
            observer: Observer::default(),
        }
    }
    pub(crate) async fn call<Req, Resp>(
        &self,
        method: &'static str,
        request: Req,
    ) -> Result<Observed<Resp>, ChainError>
    where
        Req: Message + Default + Clone + Send + Sync + 'static,
        Resp: Message + Default + Send + 'static,
    {
        let operation_deadline = tokio::time::Instant::now() + self.policy.request_timeout;
        tokio::time::timeout_at(
            operation_deadline,
            self.call_with_retries(method, request, operation_deadline),
        )
        .await
        .unwrap_or(Err(ChainError::Timeout))
    }
    async fn call_with_retries<Req, Resp>(
        &self,
        method: &'static str,
        request: Req,
        operation_deadline: tokio::time::Instant,
    ) -> Result<Observed<Resp>, ChainError>
    where
        Req: Message + Default + Clone + Send + Sync + 'static,
        Resp: Message + Default + Send + 'static,
    {
        for attempt in 0..=self.policy.retries {
            let mut req = Request::new(request.clone());
            req.set_timeout(self.policy.request_timeout);
            let attempt_deadline = tokio::time::Instant::now() + self.policy.request_timeout;
            let connection_deadline = operation_deadline.min(attempt_deadline);
            let result = tokio::time::timeout_at(attempt_deadline, async {
                let channel = self.connect_read_observed_until(connection_deadline).await?;
                let mut grpc = tonic::client::Grpc::new(BoundedChannel(
                    channel,
                    self.policy.maximum_response_bytes + 5,
                    self.observer.clone(),
                ))
                .max_decoding_message_size(self.policy.maximum_response_bytes)
                .max_encoding_message_size(1024);
                grpc.ready()
                    .await
                    .map_err(|_| ChainError::TransportUnavailable)?;
                if tokio::time::Instant::now() >= connection_deadline {
                    return Err(ChainError::Timeout);
                }
                let path = tonic::codegen::http::uri::PathAndQuery::from_static(method);
                grpc.unary(req, path, ProstCodec::<Req, Resp>::default())
                    .await
                    .map(|r| {
                        let cache = cache_observation(method, r.metadata());
                        Observed {
                            message: r.into_inner(),
                            cache,
                        }
                    })
                    .map_err(|s| match s.code() {
                        tonic::Code::NotFound => ChainError::NotObserved,
                        tonic::Code::Cancelled => ChainError::ObservationInterrupted,
                        tonic::Code::DeadlineExceeded => ChainError::Timeout,
                        tonic::Code::Unavailable => {
                            self.observer.record(FailureSite::UnaryStatus);
                            ChainError::TransportUnavailable
                        },
                        tonic::Code::ResourceExhausted => ChainError::ResourceLimit,
                        tonic::Code::Unimplemented => ChainError::UnsupportedCapability,
                        // Do not expose server-provided errors, metadata, or transaction bytes.
                        _ => ChainError::BackendFailure {
                            grpc_code: s.code() as i32,
                        },
                    })
            })
            .await
            .unwrap_or(Err(ChainError::Timeout));
            if attempt < self.policy.retries
                && matches!(
                    result,
                    Err(ChainError::Timeout
                        | ChainError::TransportUnavailable
                        | ChainError::ObservationInterrupted)
                )
            {
                tokio::time::sleep(self.policy.retry_delay).await;
                continue;
            }
            return result;
        }
        Err(ChainError::TransportUnavailable)
    }
    /// Exactly one network attempt. No retry loop, server text logging, or read-only
    /// call helper (whose retry policy would be inappropriate for side effects).
    #[cfg(feature = "submission-dispatch")]
    pub(crate) async fn submit_once(
        &self,
        bytes: &[u8],
        valid_until_unix_seconds: u64,
    ) -> Result<crate::BackendSubmissionResult, ChainError> {
        self.submit_once_restricted(bytes, valid_until_unix_seconds, None).await
    }
    #[cfg(feature = "submission-dispatch")]
    pub(crate) async fn submit_once_restricted(
        &self,
        bytes: &[u8],
        valid_until_unix_seconds: u64,
        restriction: Option<&dyn crate::SubmissionEffectRestriction>,
    ) -> Result<crate::BackendSubmissionResult, ChainError> {
        if bytes.is_empty() || bytes.len() > 2 * 1024 * 1024 {
            return Err(ChainError::ResourceLimit);
        }
        tokio::time::timeout(self.policy.request_timeout, async {
            let channel = self.connect_observed().await?;
            let mut grpc = tonic::client::Grpc::new(BoundedChannel(channel, 4096 + 5, self.observer.clone()))
                .max_decoding_message_size(4096)
                .max_encoding_message_size(2 * 1024 * 1024 + 16);
            grpc.ready()
                .await
                .map_err(|_| ChainError::TransportUnavailable)?;
            let mut request = Request::new(RawTransaction {
                data: bytes.to_vec(),
                height: 0,
            });
            request.set_timeout(self.policy.request_timeout);
            if crate::now()? > valid_until_unix_seconds {
                return Err(ChainError::StaleChain);
            }
            let method = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction";
            if let Some(restriction) = restriction {
                restriction.check_before_effect()?;
            }
            let response = grpc
                .unary(
                    request,
                    tonic::codegen::http::uri::PathAndQuery::from_static(method),
                    ProstCodec::<RawTransaction, SendResponse>::default(),
                )
                .await
                .map_err(|s| match s.code() {
                    tonic::Code::Cancelled => ChainError::ObservationInterrupted,
                    tonic::Code::DeadlineExceeded => ChainError::Timeout,
                    tonic::Code::Unavailable => {
                            self.observer.record(FailureSite::UnaryStatus);
                            ChainError::TransportUnavailable
                        },
                    tonic::Code::ResourceExhausted => ChainError::ResourceLimit,
                    tonic::Code::Unimplemented => ChainError::UnsupportedCapability,
                    _ => ChainError::BackendFailure {
                        grpc_code: s.code() as i32,
                    },
                })?;
            let cache = cache_observation(method, response.metadata());
            if cache.malformed_age
                || cache.reported_age_seconds.is_some_and(|age| age > 0)
                || cache.cache_status == CacheStatus::Hit
            {
                return Err(ChainError::ContradictoryChain);
            }
            let response = response.into_inner();
            if response.error_code == 0 {
                Ok(crate::BackendSubmissionResult::Acknowledged)
            } else {
                Ok(crate::BackendSubmissionResult::Rejected {
                    code: response.error_code,
                })
            }
        })
        .await
        .unwrap_or(Err(ChainError::Timeout))
    }
    pub async fn info(&self) -> Result<Observed<LightdInfo>, ChainError> {
        self.call(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo",
            Empty {},
        )
        .await
    }
    pub async fn latest(&self) -> Result<Observed<BlockId>, ChainError> {
        self.call(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
            Empty {},
        )
        .await
    }
    pub async fn block(&self, height: u64) -> Result<Observed<CompactBlock>, ChainError> {
        self.call(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlock",
            BlockId {
                height,
                hash: vec![],
            },
        )
        .await
    }
    pub async fn tree(&self, height: u64) -> Result<Observed<TreeState>, ChainError> {
        self.call(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState",
            BlockId {
                height,
                hash: vec![],
            },
        )
        .await
    }
    pub async fn transaction(
        &self,
        hash: [u8; 32],
    ) -> Result<Observed<RawTransaction>, ChainError> {
        self.call(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction",
            TxFilter {
                hash: hash.to_vec(),
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_headers_are_normalized_and_untrusted_values_are_not_retained() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert("x-cache", "unknown-secret-canary".parse().unwrap());
        m.insert("age", "+15".parse().unwrap());
        let cache = cache_observation("/test/ReadOnly", &m);
        assert_eq!(cache.cache_status, CacheStatus::OtherReported);
        assert!(cache.malformed_age);
        assert_eq!(cache.reported_age_seconds, None);
        assert!(
            !serde_json::to_string(&cache)
                .unwrap()
                .contains("secret-canary")
        );
        m.insert("age", "18446744073709551616".parse().unwrap());
        assert!(cache_observation("/test/ReadOnly", &m).malformed_age);
    }
    #[tokio::test]
    async fn aggregate_body_cap_covers_extra_frames_beyond_first_unary_message() {
        use http_body_util::{BodyExt, Full, Limited};
        use tonic::codegen::Bytes;
        let body = tonic::body::Body::new(Full::new(Bytes::from(vec![0; 2050])));
        let error = Limited::new(body, 1029).collect().await.unwrap_err();
        assert!(error.is::<http_body_util::LengthLimitError>());
    }
}
