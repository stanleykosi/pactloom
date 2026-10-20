//! Existing environment proxy routing only. No credentials, security-setting
//! changes, custom tunnel parser, or retry around proxy denials.
use crate::ChainError;
use hyper_util::client::{
    legacy::connect::{HttpConnector, proxy::Tunnel},
    proxy::matcher::Matcher,
};
use tonic::{
    codegen::http::Uri,
    transport::{Channel, Endpoint},
};

#[derive(Clone)]
pub(crate) enum ProxyRoute {
    Direct,
    HttpTunnel(Uri),
}
impl ProxyRoute {
    pub(crate) fn from_environment(destination: &Uri) -> Result<Self, ChainError> {
        fn first(names: &[&str]) -> Result<Option<String>, ChainError> {
            for name in names {
                match std::env::var(name) {
                    Ok(value) => return Ok(Some(value)),
                    Err(std::env::VarError::NotPresent) => (),
                    Err(_) => return Err(ChainError::UnsupportedProxyConfiguration),
                }
            }
            Ok(None)
        }
        let https = first(&["HTTPS_PROXY", "https_proxy"])?;
        let all = first(&["ALL_PROXY", "all_proxy"])?;
        let no = first(&["NO_PROXY", "no_proxy"])?;
        let selected = https
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(all.as_deref());
        Self::from_configuration(destination, selected, no.as_deref())
    }

    pub(crate) fn from_configuration(
        destination: &Uri,
        proxy: Option<&str>,
        no_proxy: Option<&str>,
    ) -> Result<Self, ChainError> {
        let Some(proxy) = proxy.filter(|s| !s.is_empty()) else {
            return Ok(Self::Direct);
        };
        // The maintained matcher skips malformed proxies. Validate first so that
        // a typo or unsupported scheme can never silently become a direct route.
        if proxy.len() > 4096 || no_proxy.is_some_and(|s| s.len() > 16 * 1024) {
            return Err(ChainError::UnsupportedProxyConfiguration);
        }
        let parsed: Uri = proxy
            .parse()
            .map_err(|_| ChainError::UnsupportedProxyConfiguration)?;
        if parsed.scheme_str() != Some("http")
            || parsed.host().is_none()
            || parsed.authority().is_some_and(|a| a.as_str().contains('@'))
            || parsed
                .path_and_query()
                .is_some_and(|p| !matches!(p.as_str(), "" | "/"))
        {
            return Err(ChainError::UnsupportedProxyConfiguration);
        }
        let matcher = Matcher::builder()
            .https(proxy)
            .no(no_proxy.unwrap_or(""))
            .build();
        match matcher.intercept(destination) {
            Some(proxy) if proxy.basic_auth().is_none() && proxy.raw_auth().is_none() => {
                Ok(Self::HttpTunnel(proxy.uri().clone()))
            }
            Some(_) => Err(ChainError::UnsupportedProxyConfiguration),
            None => Ok(Self::Direct), // Only an existing NO_PROXY exclusion.
        }
    }

    pub(crate) async fn connect(&self, endpoint: &Endpoint) -> Result<Channel, ChainError> {
        let result = match self {
            Self::Direct => endpoint.connect().await,
            Self::HttpTunnel(proxy) => {
                let mut tcp = HttpConnector::new();
                tcp.set_connect_timeout(endpoint.get_connect_timeout());
                tcp.set_nodelay(true);
                // The maintained CONNECT parser caps response headers at 8192
                // bytes. Tonic then applies destination TLS and hostname checks
                // inside the tunnel. The endpoint deadline covers both steps.
                endpoint
                    .connect_with_connector(Tunnel::new(proxy.clone(), tcp))
                    .await
            }
        };
        // Never emit a proxy address, response body, authorization, or raw error.
        result.map_err(|_| ChainError::TransportUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_obey_no_proxy_and_reject_unsafe_configuration() {
        let uri = "https://testnet.example.invalid".parse().unwrap();
        assert!(matches!(
            ProxyRoute::from_configuration(&uri, None, None),
            Ok(ProxyRoute::Direct)
        ));
        assert!(matches!(
            ProxyRoute::from_configuration(&uri, Some("http://127.0.0.1:1234"), None),
            Ok(ProxyRoute::HttpTunnel(_))
        ));
        assert!(matches!(
            ProxyRoute::from_configuration(
                &uri,
                Some("http://127.0.0.1:1234"),
                Some("example.invalid")
            ),
            Ok(ProxyRoute::Direct)
        ));
        for bad in [
            "bogus",
            "http://user:secret@localhost:1234",
            "https://localhost:1234",
            "socks5h://localhost:1234",
            "http://localhost:1234/path",
            "http://localhost:1234/?secret=x",
        ] {
            assert!(matches!(
                ProxyRoute::from_configuration(&uri, Some(bad), None),
                Err(ChainError::UnsupportedProxyConfiguration)
            ));
        }
        // A configured unsupported route is never silently discarded.
        assert!(matches!(
            ProxyRoute::from_configuration(&uri, Some("socks5h://localhost:1234"), Some("*")),
            Err(ChainError::UnsupportedProxyConfiguration)
        ));
    }
}
