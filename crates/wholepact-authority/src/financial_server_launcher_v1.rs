//! Protected-file launcher for exact, already committed financial continuations.
//! Configuration selects data, never an owner or native approval. Only the
//! maintained production openers authenticate original state and hold the fixed
//! OS-user installation. There is no setup, source construction or fallback.
//!
//! `--check` deliberately stops at protected inputs/TLS/selector validation:
//! original-state openers may use writable SQLite handles and encrypted snapshot
//! copies. Only `--serve` calls them, before binding the exact retained endpoint.
//! One process serves one mode. Initial services must be sequential and all
//! outstanding work resolved before stopping/reaping the previous process.
use crate::{AuthorityError, AuthorityServer, Result, ServerTls, WitnessDisclosureDescriptor};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde::Deserialize;
use std::{
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
};
use wholepact_storage_security::witness_namespace_fs::{
    read_existing_private_file, read_existing_storage_key,
};
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: usize = 65_536;
const MAX_NAMESPACE_BYTES: usize = 16_384;
const MAX_TLS_BYTES: usize = 65_536;

/// Explicit purpose selection. None of these modes can admit a continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinancialWitnessServiceV1 {
    FinancialSigning,
    CompletedDispatch,
    CompletedDispatchPair,
}
impl TryFrom<&str> for FinancialWitnessServiceV1 {
    type Error = AuthorityError;
    fn try_from(value: &str) -> Result<Self> {
        match value {
            "financial-signing-v1" => Ok(Self::FinancialSigning),
            "completed-dispatch-v1" => Ok(Self::CompletedDispatch),
            "completed-dispatch-pair-v1" => Ok(Self::CompletedDispatchPair),
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
}
impl FinancialWitnessServiceV1 {
    fn original_count(self) -> usize {
        match self {
            Self::FinancialSigning | Self::CompletedDispatch => 1,
            Self::CompletedDispatchPair => 2,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchConfigurationV1 {
    version: u16,
    listen: String,
    originals: Vec<OriginalSelectorV1>,
    tls: ExistingTlsFilesV1,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalSelectorV1 {
    namespace_file: PathBuf,
    continuation_operation_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExistingTlsFilesV1 {
    trusted_client_roots_der: Vec<PathBuf>,
    server_chain_der: Vec<PathBuf>,
    server_private_key_pkcs8_der: PathBuf,
}
// This closed data-only shape mirrors NamespaceOpenInput, but deliberately has
// no synthetic_installation or nominal owner field even in qualification builds.
// The exact original bytes, not this value, go to the production source opener.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalNamespaceV1 {
    endpoint: String,
    server_name: String,
    witness_id: String,
    pinned_server_certificate_digest: String,
    owner_certificate_digest: String,
    network_profile_id: String,
    storage_key_file: PathBuf,
    expected_account_id: String,
}

fn validate_path(path: &Path) -> Result<()> {
    let value = path.to_str().ok_or(AuthorityError::InvalidBinding)?;
    if !value.starts_with('/')
        || value.len() > 4096
        || value.bytes().any(|b| b.is_ascii_control())
        || value[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}
impl LaunchConfigurationV1 {
    fn validate(&self, mode: FinancialWitnessServiceV1) -> Result<SocketAddr> {
        if self.version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        let listen: SocketAddr = self
            .listen
            .parse()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        if listen.to_string() != self.listen
            || listen.port() == 0
            || listen.ip().is_unspecified()
            || listen.ip().is_multicast()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        if self.originals.len() != mode.original_count()
            || self.tls.trusted_client_roots_der.is_empty()
            || self.tls.trusted_client_roots_der.len() > 8
            || self.tls.server_chain_der.is_empty()
            || self.tls.server_chain_der.len() > 8
        {
            return Err(AuthorityError::Limit);
        }
        for original in &self.originals {
            validate_path(&original.namespace_file)?;
            crate::id(&original.continuation_operation_id)?;
        }
        for path in self
            .tls
            .trusted_client_roots_der
            .iter()
            .chain(&self.tls.server_chain_der)
            .chain([&self.tls.server_private_key_pkcs8_der])
        {
            validate_path(path)?;
        }
        Ok(listen)
    }
}
impl OriginalNamespaceV1 {
    fn validate(&self, actual_listen: &str) -> Result<()> {
        if self.endpoint != actual_listen {
            return Err(AuthorityError::InvalidBinding);
        }
        crate::hash(&self.owner_certificate_digest)?;
        crate::hash(&self.expected_account_id)?;
        validate_path(&self.storage_key_file)?;
        WitnessDisclosureDescriptor {
            endpoint: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            witness_id: self.witness_id.clone(),
            account_id: self.expected_account_id.clone(),
            network_profile_id: self.network_profile_id.clone(),
            policy_digest: "0".repeat(64),
            pinned_server_certificate_digest: self.pinned_server_certificate_digest.clone(),
        }
        .validate()
    }
    fn same_namespace(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint
            && self.server_name == other.server_name
            && self.witness_id == other.witness_id
            && self.pinned_server_certificate_digest == other.pinned_server_certificate_digest
            && self.owner_certificate_digest == other.owner_certificate_digest
            && self.network_profile_id == other.network_profile_id
            && self.storage_key_file == other.storage_key_file
    }
}
fn parse_configuration(
    bytes: &[u8],
    mode: FinancialWitnessServiceV1,
) -> Result<LaunchConfigurationV1> {
    if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
        return Err(AuthorityError::Limit);
    }
    let value: LaunchConfigurationV1 =
        wholepact_core::parse_typed_json(bytes).map_err(|_| AuthorityError::InvalidBinding)?;
    value.validate(mode)?;
    Ok(value)
}
fn parse_namespace(bytes: &[u8], actual_listen: &str) -> Result<OriginalNamespaceV1> {
    if bytes.is_empty() || bytes.len() > MAX_NAMESPACE_BYTES {
        return Err(AuthorityError::Limit);
    }
    let value: OriginalNamespaceV1 =
        wholepact_core::parse_typed_json(bytes).map_err(|_| AuthorityError::InvalidBinding)?;
    value.validate(actual_listen)?;
    Ok(value)
}
fn validate_originals(originals: &[OriginalNamespaceV1]) -> Result<()> {
    if originals.len() == 2 {
        if originals[0].expected_account_id == originals[1].expected_account_id {
            return Err(AuthorityError::Conflict);
        }
        if !originals[0].same_namespace(&originals[1]) {
            return Err(AuthorityError::InvalidBinding);
        }
    } else if originals.len() != 1 {
        return Err(AuthorityError::Limit);
    }
    Ok(())
}

struct ProtectedInputsV1 {
    config: LaunchConfigurationV1,
    address: SocketAddr,
    namespace_bytes: Vec<Zeroizing<Vec<u8>>>,
    tls: ServerTls,
}
// Only bounded existing file reads and in-memory TLS configuration. Do not add
// namespace/database opening, credential generation or a listener to this path.
fn prepare_inputs(mode: FinancialWitnessServiceV1, path: &Path) -> Result<ProtectedInputsV1> {
    validate_path(path)?;
    let raw = read_existing_private_file(path, MAX_CONFIG_BYTES)
        .map_err(|_| AuthorityError::Permission)?;
    let config = parse_configuration(&raw, mode)?;
    let address = config.validate(mode)?;
    let mut namespace_bytes = Vec::with_capacity(config.originals.len());
    let mut originals = Vec::with_capacity(config.originals.len());
    for original in &config.originals {
        let bytes = read_existing_private_file(&original.namespace_file, MAX_NAMESPACE_BYTES)
            .map_err(|_| AuthorityError::Permission)?;
        originals.push(parse_namespace(&bytes, &config.listen)?);
        namespace_bytes.push(bytes);
    }
    validate_originals(&originals)?;
    for original in &originals {
        // File shape/permissions only, not proof of the original storage key.
        let _key = read_existing_storage_key(&original.storage_key_file)
            .map_err(|_| AuthorityError::Permission)?;
    }
    let certs = |paths: &[PathBuf]| -> Result<Vec<CertificateDer<'static>>> {
        paths
            .iter()
            .map(|path| {
                read_existing_private_file(path, MAX_TLS_BYTES)
                    .map(|bytes| CertificateDer::from(bytes.to_vec()))
                    .map_err(|_| AuthorityError::Permission)
            })
            .collect()
    };
    let roots = certs(&config.tls.trusted_client_roots_der)?;
    let chain = certs(&config.tls.server_chain_der)?;
    let leaf = chain.first().ok_or(AuthorityError::Authentication)?;
    let certificate_digest = crate::transport::certificate_digest(leaf);
    for original in &originals {
        if original.pinned_server_certificate_digest != certificate_digest {
            return Err(AuthorityError::Authentication);
        }
        let name = ServerName::try_from(original.server_name.clone())
            .map_err(|_| AuthorityError::InvalidBinding)?;
        webpki::EndEntityCert::try_from(leaf)
            .map_err(|_| AuthorityError::Authentication)?
            .verify_is_valid_for_subject_name(&name)
            .map_err(|_| AuthorityError::Authentication)?;
    }
    let key = read_existing_private_file(&config.tls.server_private_key_pkcs8_der, MAX_TLS_BYTES)
        .map_err(|_| AuthorityError::Permission)?;
    let tls = ServerTls::new(
        roots,
        chain,
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
    )?;
    Ok(ProtectedInputsV1 {
        config,
        address,
        namespace_bytes,
        tls,
    })
}
/// Validate protected inputs, TLS and selector shape only. Does not open the
/// actual installation, authenticate committed state, establish availability or
/// financial eligibility, bind a listener, or create/modify files or credentials.
pub fn check_existing_financial_server_v1(
    mode: FinancialWitnessServiceV1,
    path: impl AsRef<Path>,
) -> Result<()> {
    prepare_inputs(mode, path.as_ref()).map(|_| ())
}
/// Open authenticated original state before binding its exact retained endpoint.
/// The maintained opener resolves geteuid/getpwuid_r, not HOME/XDG, and owns the
/// installation exclusively. Pair mode authenticates one shared original core;
/// it cannot combine unrelated installations. No mode admits or renews a source.
pub fn serve_existing_financial_server_v1(
    mode: FinancialWitnessServiceV1,
    path: impl AsRef<Path>,
) -> Result<()> {
    let inputs = prepare_inputs(mode, path.as_ref())?;
    let selected = |index: usize| {
        (
            inputs.namespace_bytes[index].as_slice(),
            inputs.config.originals[index]
                .continuation_operation_id
                .as_str(),
        )
    };
    let server: AuthorityServer = match mode {
        FinancialWitnessServiceV1::FinancialSigning => {
            let (bytes, operation) = selected(0);
            crate::transport::open_born_financial_signing_v1_for_server(
                bytes,
                operation,
                inputs.tls.clone(),
                &inputs.config.listen,
            )?
        }
        FinancialWitnessServiceV1::CompletedDispatch => {
            let (bytes, operation) = selected(0);
            crate::transport::open_born_completed_dispatch_v1_for_server(
                bytes,
                operation,
                inputs.tls.clone(),
                &inputs.config.listen,
            )?
        }
        FinancialWitnessServiceV1::CompletedDispatchPair => {
            crate::transport::open_born_completed_dispatch_pair_v1_for_server(
                [selected(0), selected(1)],
                inputs.tls.clone(),
                &inputs.config.listen,
            )?
        }
    };
    let listener = TcpListener::bind(inputs.address).map_err(|_| AuthorityError::Permission)?;
    if listener.local_addr().map_err(|_| AuthorityError::Storage)? != inputs.address {
        return Err(AuthorityError::Authentication);
    }
    server.serve(listener)
}

#[cfg(test)]
mod tests {
    // Pure closed-shape/parser tests. These never open a namespace, file, GUI,
    // database or socket, and cannot produce a nominal owner or native consent.
    use super::*;
    fn config() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "listen": "127.0.0.1:18556",
            "originals": [{"namespace_file": "/data-only/never-read/namespace.json", "continuation_operation_id": "exact-original-operation"}],
            "tls": {"trusted_client_roots_der": ["/data-only/never-read/root.der"], "server_chain_der": ["/data-only/never-read/server.der"], "server_private_key_pkcs8_der": "/data-only/never-read/server.pk8"}
        })
    }
    fn namespace() -> serde_json::Value {
        serde_json::json!({
            "endpoint": "127.0.0.1:18556", "server_name": "localhost",
            "witness_id": "data-only-witness", "pinned_server_certificate_digest": "1".repeat(64),
            "owner_certificate_digest": "2".repeat(64), "network_profile_id": "data-only-network",
            "storage_key_file": "/data-only/never-read/storage.key", "expected_account_id": "3".repeat(64)
        })
    }
    fn parsed_namespace(value: serde_json::Value) -> Result<OriginalNamespaceV1> {
        parse_namespace(&serde_json::to_vec(&value).unwrap(), "127.0.0.1:18556")
    }
    #[test]
    fn exact_mode_and_cardinality_are_required() {
        for mode in [
            FinancialWitnessServiceV1::FinancialSigning,
            FinancialWitnessServiceV1::CompletedDispatch,
        ] {
            assert!(parse_configuration(&serde_json::to_vec(&config()).unwrap(), mode).is_ok());
        }
        let pair = FinancialWitnessServiceV1::CompletedDispatchPair;
        assert!(parse_configuration(&serde_json::to_vec(&config()).unwrap(), pair).is_err());
        for value in [
            "",
            "financial-signing",
            "setup",
            "renew",
            "completed-dispatch-pair-v2",
        ] {
            assert!(FinancialWitnessServiceV1::try_from(value).is_err());
        }
        assert_eq!(
            FinancialWitnessServiceV1::try_from("completed-dispatch-pair-v1").unwrap(),
            pair
        );
        let mut value = config();
        let second = value["originals"][0].clone();
        value["originals"].as_array_mut().unwrap().push(second);
        assert!(parse_configuration(&serde_json::to_vec(&value).unwrap(), pair).is_ok());
        assert!(parse_configuration(
            &serde_json::to_vec(&value).unwrap(),
            FinancialWitnessServiceV1::FinancialSigning
        )
        .is_err());
    }
    #[test]
    fn configuration_is_closed_and_has_no_default_listener() {
        let mode = FinancialWitnessServiceV1::FinancialSigning;
        for field in ["setup", "synthetic_installation", "root", "renew"] {
            let mut value = config();
            value[field] = true.into();
            assert!(parse_configuration(&serde_json::to_vec(&value).unwrap(), mode).is_err());
        }
        for address in [
            "0.0.0.0:18556",
            "[::]:18556",
            "127.0.0.1:0",
            "239.0.0.1:18556",
        ] {
            let mut value = config();
            value["listen"] = address.into();
            assert!(parse_configuration(&serde_json::to_vec(&value).unwrap(), mode).is_err());
        }
        let mut value = config();
        value.as_object_mut().unwrap().remove("listen");
        assert!(parse_configuration(&serde_json::to_vec(&value).unwrap(), mode).is_err());
        for path in [
            "relative.json",
            "/data-only/../namespace.json",
            "/data-only//namespace.json",
        ] {
            let mut value = config();
            value["originals"][0]["namespace_file"] = path.into();
            assert!(parse_configuration(&serde_json::to_vec(&value).unwrap(), mode).is_err());
        }
        let duplicate = serde_json::to_string(&config()).unwrap().replacen(
            "\"version\":1",
            "\"version\":1,\"version\":1",
            1,
        );
        assert!(parse_configuration(duplicate.as_bytes(), mode).is_err());
        assert!(parse_configuration(&vec![0; MAX_CONFIG_BYTES + 1], mode).is_err());
    }
    #[test]
    fn namespace_selectors_cannot_supply_owners_or_another_endpoint() {
        for field in [
            "synthetic_installation",
            "native_approved",
            "canonical_private_root",
        ] {
            let mut value = namespace();
            value[field] = true.into();
            assert!(parsed_namespace(value).is_err());
        }
        let mut value = namespace();
        value["endpoint"] = "127.0.0.1:18557".into();
        assert!(parsed_namespace(value).is_err());
        let duplicate = serde_json::to_string(&namespace()).unwrap().replacen(
            "\"server_name\":\"localhost\"",
            "\"server_name\":\"localhost\",\"server_name\":\"localhost\"",
            1,
        );
        assert!(parse_namespace(duplicate.as_bytes(), "127.0.0.1:18556").is_err());
        assert!(parse_namespace(&vec![0; MAX_NAMESPACE_BYTES + 1], "127.0.0.1:18556").is_err());
    }
    #[test]
    fn pair_requires_distinct_accounts_and_one_exact_original_namespace() {
        assert!(validate_originals(&[
            parsed_namespace(namespace()).unwrap(),
            parsed_namespace(namespace()).unwrap()
        ])
        .is_err());
        let mut other = namespace();
        other["expected_account_id"] = "4".repeat(64).into();
        assert!(validate_originals(&[
            parsed_namespace(namespace()).unwrap(),
            parsed_namespace(other.clone()).unwrap()
        ])
        .is_ok());
        for (field, changed) in [
            ("witness_id", "another-witness".to_owned()),
            ("server_name", "other.invalid".to_owned()),
            ("network_profile_id", "another-network".to_owned()),
            ("owner_certificate_digest", "5".repeat(64)),
            ("pinned_server_certificate_digest", "6".repeat(64)),
            (
                "storage_key_file",
                "/data-only/never-read/another.key".to_owned(),
            ),
        ] {
            let mut changed_other = other.clone();
            changed_other[field] = changed.into();
            assert!(validate_originals(&[
                parsed_namespace(namespace()).unwrap(),
                parsed_namespace(changed_other).unwrap()
            ])
            .is_err());
        }
    }
}
