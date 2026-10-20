//! Public-only streaming transport for the maintained wallet scanner.
use crate::{ChainError, RpcCacheObservation};
use crate::transport_diagnostics::{Observer, FailureSite};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tonic::{
    body::Body,
    codegen::http::{Request, Response},
    transport::Channel,
};
use tower::Service;

/// Opaque shared TLS/proxy transport that allowlists public block/tree RPC paths.
/// This is not an information-flow firewall: trusted Rust callers still supply request
/// bodies/headers. The protected wallet controller emits only public height requests.
#[derive(Clone)]
pub struct PublicSyncChannel {
    channel: Channel,
    maximum_response_bytes: usize,
    observer: Observer,
}
impl PublicSyncChannel {
    pub(crate) fn new(channel: Channel, maximum_response_bytes: usize) -> Self {
        Self {
            channel,
            maximum_response_bytes,
            observer: Observer::default(),
        }
    }
    pub(crate) fn with_observer(mut self, observer: Observer) -> Self {
        self.observer = observer;
        self
    }
    pub fn cache_observation(
        method: &'static str,
        metadata: &tonic::metadata::MetadataMap,
    ) -> RpcCacheObservation {
        crate::rpc::cache_observation(method, metadata)
    }
}
impl Service<Request<Body>> for PublicSyncChannel {
    type Response = Response<Body>;
    type Error = ChainError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.channel
            .poll_ready(cx)
            .map_err(|_| {
                self.observer.record(FailureSite::Readiness);
                ChainError::TransportUnavailable
            })
    }
    fn call(&mut self, request: Request<Body>) -> Self::Future {
        const PREFIX: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";
        let allowed = request
            .uri()
            .path()
            .strip_prefix(PREFIX)
            .is_some_and(|method| {
                matches!(
                    method,
                    "GetLightdInfo"
                        | "GetLatestBlock"
                        | "GetBlock"
                        | "GetBlockRange"
                        | "GetTreeState"
                        | "GetSubtreeRoots"
                )
            });
        if !allowed || request.uri().query().is_some() {
            return Box::pin(async { Err(ChainError::UnsupportedCapability) });
        }
        let method = request.uri().path().to_owned();
        let response = self.channel.call(request);
        let maximum = self.maximum_response_bytes;
        let observer = self.observer.clone();
        Box::pin(async move {
            let response = response
                .await
                .map_err(|_| {
                    observer.record(FailureSite::Request);
                    ChainError::TransportUnavailable
                })?;
            crate::wire_guard::guard_response_observed(response, maximum, &method, &observer).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn both_observer_and_public_channel_reject_amplifying_block_on_the_wire() {
        use crate::{NetworkPolicy, rpc};
        use axum::{Router, body::Body as HttpBody, routing::post};
        let payload = [0x3a, 0].repeat(8193);
        let mut framed = vec![0];
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend(payload);
        let app = Router::new().route(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlock",
            post(move || {
                let framed = framed.clone();
                async move {
                    Response::builder()
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "0")
                        .body(HttpBody::from(framed))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let rpc = rpc::Rpc::for_test(
            &endpoint,
            NetworkPolicy {
                retries: 0,
                ..Default::default()
            },
        );
        assert!(rpc.block(4_465_040).await.is_err());
        let channel = tonic::transport::Endpoint::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = tonic::client::Grpc::new(PublicSyncChannel::new(channel, 4 * 1024 * 1024));
        client.ready().await.unwrap();
        let result: Result<tonic::Response<rpc::CompactBlock>, _> = client
            .unary(
                tonic::Request::new(rpc::BlockId {
                    height: 4_465_040,
                    hash: vec![],
                }),
                tonic::codegen::http::uri::PathAndQuery::from_static(
                    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlock",
                ),
                tonic_prost::ProstCodec::default(),
            )
            .await;
        assert!(result.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn refuses_private_and_write_methods_before_dispatch() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let mut public = PublicSyncChannel::new(channel, 1024);
        for name in [
            "GetTransaction",
            "SendTransaction",
            "GetAddressUtxos",
            "GetTaddressTxids",
            "GetBlock?private=x",
        ] {
            let request = Request::builder()
                .uri(format!("/cash.z.wallet.sdk.rpc.CompactTxStreamer/{name}"))
                .body(Body::empty())
                .unwrap();
            assert!(matches!(
                public.call(request).await,
                Err(ChainError::UnsupportedCapability)
            ));
        }
    }
}
