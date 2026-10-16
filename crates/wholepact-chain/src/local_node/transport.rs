//! Direct enrolled loopback TLS endpoint. The owner's non-caching TLS terminator
//! and its upstream validating node are one explicit trust boundary.
use super::*;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

pub struct LocalNodeTls {
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
    pub(super) pin: String,
    pub(super) server_name: String,
    pub(super) client_certificate: String,
    pub(super) trusted_roots: Vec<String>,
}
impl LocalNodeTls {
    /// Consumes previously enrolled credentials only. Does not create, save,
    /// install, enroll or expand access to any credential or endpoint.
    pub fn new(
        server_name: String,
        pinned_leaf_sha256: String,
        trusted_roots: Vec<CertificateDer<'static>>,
        client_chain: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
    ) -> Result<Self, ChainError> {
        hash(&pinned_leaf_sha256)?;
        if trusted_roots.is_empty()
            || trusted_roots.len() > 8
            || client_chain.is_empty()
            || client_chain.len() > 8
        {
            return Err(ChainError::InvalidConfiguration);
        }
        let client_certificate = hex::encode(Sha256::digest(client_chain[0].as_ref()));
        let mut trusted_root_ids: Vec<_> = trusted_roots
            .iter()
            .map(|cert| hex::encode(Sha256::digest(cert.as_ref())))
            .collect();
        trusted_root_ids.sort();
        trusted_root_ids.dedup();
        let mut roots = RootCertStore::empty();
        for cert in trusted_roots {
            roots
                .add(cert)
                .map_err(|_| ChainError::InvalidConfiguration)?;
        }
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| ChainError::InvalidConfiguration)?
                .with_root_certificates(roots)
                .with_client_auth_cert(client_chain, client_key)
                .map_err(|_| ChainError::InvalidConfiguration)?;
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            config: Arc::new(config),
            name: ServerName::try_from(server_name.clone())
                .map_err(|_| ChainError::InvalidConfiguration)?,
            pin: pinned_leaf_sha256,
            server_name,
            client_certificate,
            trusted_roots: trusted_root_ids,
        })
    }
}
struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
}
impl DeadlineSocket {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "node observation deadline"))
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(b)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}
pub(super) struct NodeSession {
    stream: StreamOwned<ClientConnection, DeadlineSocket>,
    pub binding: String,
    pub certificate: String,
    counter: u64,
}
impl NodeSession {
    pub fn connect(endpoint: SocketAddr, tls: &LocalNodeTls) -> Result<Self, ChainError> {
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err(ChainError::InvalidConfiguration);
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let socket = TcpStream::connect_timeout(&endpoint, Duration::from_secs(5))
            .map_err(|_| ChainError::TransportUnavailable)?;
        let mut socket = DeadlineSocket { socket, deadline };
        let mut connection = ClientConnection::new(tls.config.clone(), tls.name.clone())
            .map_err(|_| ChainError::TransportUnavailable)?;
        while connection.is_handshaking() {
            connection
                .complete_io(&mut socket)
                .map_err(|_| ChainError::TransportUnavailable)?;
        }
        let cert = connection
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or(ChainError::MalformedEvidence)?;
        if hex::encode(Sha256::digest(cert.as_ref())) != tls.pin
            || connection.alpn_protocol() != Some(b"http/1.1")
        {
            return Err(ChainError::MalformedEvidence);
        }
        // Exporter output itself is not retained: retain only a domain-bound hash.
        let exporter = zeroize::Zeroizing::new(
            connection
                .export_keying_material([0u8; 32], b"EXPORTER-wholepact-local-node-v1", None)
                .map_err(|_| ChainError::TransportUnavailable)?,
        );
        let binding = hex::encode(Sha256::digest(exporter.as_ref()));
        Ok(Self {
            stream: StreamOwned::new(connection, socket),
            binding,
            certificate: tls.pin.clone(),
            counter: 0,
        })
    }
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, ChainError> {
        if !matches!(
            method,
            "getinfo" | "getblockchaininfo" | "getblockhash" | "getblock" | "getrawtransaction"
        ) {
            return Err(ChainError::UnsupportedCapability);
        }
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(ChainError::ResourceLimit)?;
        let id = format!("{}-{}", self.binding, self.counter);
        let body = serde_json::to_vec(
            &serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
        )
        .map_err(|_| ChainError::MalformedEvidence)?;
        if body.len() > 4096 {
            return Err(ChainError::ResourceLimit);
        }
        let header = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        );
        self.stream
            .write_all(header.as_bytes())
            .and_then(|_| self.stream.write_all(&body))
            .and_then(|_| self.stream.flush())
            .map_err(|_| ChainError::TransportUnavailable)?;
        let mut header = Vec::new();
        loop {
            if header.len() >= 8192 {
                return Err(ChainError::ResourceLimit);
            }
            let mut byte = [0];
            self.stream
                .read_exact(&mut byte)
                .map_err(|_| ChainError::TransportUnavailable)?;
            header.push(byte[0]);
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        if !response
            .parse(&header)
            .map_err(|_| ChainError::MalformedEvidence)?
            .is_complete()
            || response.code != Some(200)
        {
            return Err(ChainError::MalformedEvidence);
        }
        let mut length = None;
        for field in response.headers {
            if field.name.eq_ignore_ascii_case("content-length") {
                if length.is_some() {
                    return Err(ChainError::MalformedEvidence);
                }
                length = Some(
                    std::str::from_utf8(field.value)
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                        .ok_or(ChainError::MalformedEvidence)?,
                );
            }
            // Strict local endpoint contract; no redirect, transfer coding,
            // compressed response, or cache/proxy response can become authority.
            if [
                "transfer-encoding",
                "content-encoding",
                "age",
                "via",
                "x-cache",
            ]
            .iter()
            .any(|name| field.name.eq_ignore_ascii_case(name))
            {
                return Err(ChainError::MalformedEvidence);
            }
        }
        let length = length
            .filter(|n| *n > 0 && *n <= 4 * 1024 * 1024)
            .ok_or(ChainError::ResourceLimit)?;
        let mut body = zeroize::Zeroizing::new(vec![0; length]);
        self.stream
            .read_exact(&mut body)
            .map_err(|_| ChainError::TransportUnavailable)?;
        let response: Value =
            serde_json::from_slice(&body).map_err(|_| ChainError::MalformedEvidence)?;
        if response.get("id").and_then(Value::as_str) != Some(id.as_str())
            || response.get("error").is_some_and(|e| !e.is_null())
        {
            return Err(ChainError::MalformedEvidence);
        }
        response
            .get("result")
            .cloned()
            .ok_or(ChainError::MalformedEvidence)
    }
}
