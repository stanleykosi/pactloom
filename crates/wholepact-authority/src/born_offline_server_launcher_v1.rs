//! Code-only operator launcher for an already approved native born namespace.
//! No key generation, enrollment, migration, credential persistence or plaintext
//! fallback. Configuration is never approval evidence and cannot make a namespace.
use crate::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Deserialize;
use std::{
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
};
use wholepact_storage_security::witness_namespace_fs::read_existing_private_file;

const MAX_CONFIG_BYTES: usize = 65_536;
const MAX_TLS_BYTES: usize = 65_536;
fn loopback_listener() -> String {
    "127.0.0.1:18556".into()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchConfigurationV1 {
    version: u16,
    #[serde(default = "loopback_listener")]
    listen: String,
    original: OriginalNamespace,
    tls: ExistingTlsFiles,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalNamespace {
    endpoint: String,
    server_name: String,
    witness_id: String,
    pinned_server_certificate_digest: String,
    owner_certificate_digest: String,
    network_profile_id: String,
    storage_key_file: PathBuf,
    expected_account_id: String,
    expected_enrollment_digest: String,
    expected_artifact_binding_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExistingTlsFiles {
    trusted_client_roots_der: Vec<PathBuf>,
    server_chain_der: Vec<PathBuf>,
    server_private_key_pkcs8_der: PathBuf,
}
impl LaunchConfigurationV1 {
    fn validate(&self) -> Result<SocketAddr> {
        if self.version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        let listen: SocketAddr = self
            .listen
            .parse()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        if listen.to_string() != self.listen
            || self.listen != self.original.endpoint
            || listen.port() == 0
            || listen.ip().is_unspecified()
            || listen.ip().is_multicast()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        for value in [
            &self.original.expected_enrollment_digest,
            &self.original.expected_artifact_binding_digest,
            &self.original.owner_certificate_digest,
        ] {
            hash(value)?;
        }
        WitnessDisclosureDescriptor {
            endpoint: self.original.endpoint.clone(),
            server_name: self.original.server_name.clone(),
            witness_id: self.original.witness_id.clone(),
            account_id: self.original.expected_account_id.clone(),
            network_profile_id: self.original.network_profile_id.clone(),
            policy_digest: "0".repeat(64),
            pinned_server_certificate_digest: self
                .original
                .pinned_server_certificate_digest
                .clone(),
        }
        .validate()?;
        if self.tls.trusted_client_roots_der.is_empty()
            || self.tls.trusted_client_roots_der.len() > 8
            || self.tls.server_chain_der.is_empty()
            || self.tls.server_chain_der.len() > 8
        {
            return Err(AuthorityError::Limit);
        }
        for path in self
            .tls
            .trusted_client_roots_der
            .iter()
            .chain(&self.tls.server_chain_der)
            .chain([
                &self.tls.server_private_key_pkcs8_der,
                &self.original.storage_key_file,
            ])
        {
            let text = path.to_str().ok_or(AuthorityError::InvalidBinding)?;
            if !path.is_absolute() || text.len() > 4096 || text.contains('\0') {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        Ok(listen)
    }
    fn into_owner(self) -> BornOfflineWitnessConfigurationV1 {
        let o = self.original;
        BornOfflineWitnessConfigurationV1 {
            endpoint: o.endpoint,
            server_name: o.server_name,
            witness_id: o.witness_id,
            pinned_server_certificate_digest: o.pinned_server_certificate_digest,
            owner_certificate_digest: o.owner_certificate_digest,
            network_profile_id: o.network_profile_id,
            storage_key_file: o.storage_key_file,
            expected_account_id: o.expected_account_id,
            expected_enrollment_digest: o.expected_enrollment_digest,
            expected_artifact_binding_digest: o.expected_artifact_binding_digest,
        }
    }
}
fn parse_configuration(bytes: &[u8]) -> Result<LaunchConfigurationV1> {
    if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
        return Err(AuthorityError::Limit);
    }
    let value: LaunchConfigurationV1 =
        wholepact_core::parse_typed_json(bytes).map_err(|_| AuthorityError::InvalidBinding)?;
    value.validate()?;
    Ok(value)
}
fn prepare(path: &Path) -> Result<(AuthorityServer, SocketAddr)> {
    let raw = read_existing_private_file(path, MAX_CONFIG_BYTES)
        .map_err(|_| AuthorityError::Permission)?;
    let config = parse_configuration(&raw)?;
    let listen = config.validate()?;
    let certs = |paths: &[PathBuf]| -> Result<Vec<CertificateDer<'static>>> {
        paths
            .iter()
            .map(|p| {
                read_existing_private_file(p, MAX_TLS_BYTES)
                    .map(|b| CertificateDer::from(b.to_vec()))
                    .map_err(|_| AuthorityError::Permission)
            })
            .collect()
    };
    let roots = certs(&config.tls.trusted_client_roots_der)?;
    let chain = certs(&config.tls.server_chain_der)?;
    let name = rustls::pki_types::ServerName::try_from(config.original.server_name.clone())
        .map_err(|_| AuthorityError::InvalidBinding)?;
    webpki::EndEntityCert::try_from(chain.first().ok_or(AuthorityError::Authentication)?)
        .map_err(|_| AuthorityError::Authentication)?
        .verify_is_valid_for_subject_name(&name)
        .map_err(|_| AuthorityError::Authentication)?;
    let key = read_existing_private_file(&config.tls.server_private_key_pkcs8_der, MAX_TLS_BYTES)
        .map_err(|_| AuthorityError::Permission)?;
    let tls = ServerTls::new(
        roots,
        chain,
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
    )?;
    // Actual namespace owner and original installed pins are checked before any
    // listener is bound. A parsed config cannot bypass these genuine gates.
    let server = AuthorityServer::for_born_offline_witness_v1(config.into_owner(), tls)?;
    Ok((server, listen))
}
/// Validate existing protected inputs and exact native namespace without serving.
/// This creates no credentials, enrollment, record or listener.
pub fn check_existing_born_offline_server_v1(path: impl AsRef<Path>) -> Result<()> {
    prepare(path.as_ref()).map(|_| ())
}
/// Serve only the exact preexisting namespace endpoint with pinned TLS1.3 mTLS.
/// Default listen is loopback. Non-loopback requires an explicit matching private
/// config and preexisting namespace pin; no wildcard, proxy, redirect or TLS bypass.
pub fn serve_existing_born_offline_server_v1(path: impl AsRef<Path>) -> Result<()> {
    let (server, address) = prepare(path.as_ref())?;
    let listener = TcpListener::bind(address).map_err(|_| AuthorityError::Permission)?;
    if listener.local_addr().map_err(|_| AuthorityError::Storage)? != address {
        return Err(AuthorityError::Authentication);
    }
    server.serve(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn draft() -> serde_json::Value {
        serde_json::json!({"version":1,"original":{"endpoint":"127.0.0.1:18556","server_name":"localhost",
            "witness_id":"synthetic-witness","pinned_server_certificate_digest":"1".repeat(64),"owner_certificate_digest":"2".repeat(64),
            "network_profile_id":"synthetic-network","storage_key_file":"/synthetic/never-read/storage.key",
            "expected_account_id":"synthetic-account","expected_enrollment_digest":"3".repeat(64),"expected_artifact_binding_digest":"4".repeat(64)},
            "tls":{"trusted_client_roots_der":["/synthetic/never-read/root.der"],"server_chain_der":["/synthetic/never-read/server.der"],"server_private_key_pkcs8_der":"/synthetic/never-read/server.pk8"}})
    }
    #[test]
    fn launcher_defaults_to_loopback_and_config_is_data_only() {
        let value = parse_configuration(&serde_json::to_vec(&draft()).unwrap()).unwrap();
        assert_eq!(
            value.validate().unwrap(),
            "127.0.0.1:18556".parse::<SocketAddr>().unwrap()
        );
    }
    #[test]
    fn launcher_rejects_unknown_fields_wildcards_mismatch_and_unbounded_inputs() {
        let mut v = draft();
        v["native_approved"] = serde_json::Value::Bool(true);
        assert!(parse_configuration(&serde_json::to_vec(&v).unwrap()).is_err());
        for address in [
            "0.0.0.0:18556",
            "127.0.0.1:0",
            "[::]:18556",
            "239.0.0.1:18556",
            "127.0.0.1:18557",
        ] {
            let mut v = draft();
            v["listen"] = address.into();
            assert!(parse_configuration(&serde_json::to_vec(&v).unwrap()).is_err());
        }
        let mut v = draft();
        v["tls"]["server_chain_der"] = serde_json::json!([]);
        assert!(parse_configuration(&serde_json::to_vec(&v).unwrap()).is_err());
        let mut v = draft();
        v["tls"]["server_private_key_pkcs8_der"] = "relative.key".into();
        assert!(parse_configuration(&serde_json::to_vec(&v).unwrap()).is_err());
        assert!(parse_configuration(&vec![0; MAX_CONFIG_BYTES + 1]).is_err());
    }
}
