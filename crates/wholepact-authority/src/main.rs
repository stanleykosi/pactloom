//! Independently runnable owner-operated witness. This program never generates
//! credentials, provisions a remote host or installs a service. Optional node
//! reads require a separately owner-enrolled exact source and existing credentials.
//! Enrollment/configuration files must be prepared through the owner's approved
//! setup. Tests use ephemeral local synthetic certificates only.
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::Arc,
};
use wholepact_authority::*;
use wholepact_storage_security::DatabaseKey;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    database: PathBuf,
    database_key_file: PathBuf,
    account_id: String,
    network_profile_id: String,
    listen: SocketAddr,
    trusted_client_root_der: PathBuf,
    certificate_der: PathBuf,
    private_key_pkcs8_der: PathBuf,
    #[serde(default)]
    resolution_node: Option<ResolutionNodeConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolutionNodeConfig {
    source_id: String,
    endpoint: SocketAddr,
    server_name: String,
    pinned_certificate_sha256: String,
    trusted_root_der: PathBuf,
    client_certificate_der: PathBuf,
    client_private_key_pkcs8_der: PathBuf,
    required_confirmations: u32,
}
impl ResolutionNodeConfig {
    fn node(&self) -> Result<wholepact_chain::local_node::LocalValidatingNode> {
        use wholepact_chain::local_node::{LocalNodeTls, LocalValidatingNode};
        let tls = LocalNodeTls::new(
            self.server_name.clone(),
            self.pinned_certificate_sha256.clone(),
            vec![certificate(&self.trusted_root_der)?],
            vec![certificate(&self.client_certificate_der)?],
            private_key(&self.client_private_key_pkcs8_der)?,
        )
        .map_err(|_| AuthorityError::InvalidBinding)?;
        LocalValidatingNode::new(
            self.source_id.clone(),
            self.endpoint,
            tls,
            self.required_confirmations,
        )
        .map_err(|_| AuthorityError::InvalidBinding)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    endpoint: SocketAddr,
    server_name: String,
    server_certificate_digest: String,
    trusted_server_root_der: PathBuf,
    certificate_der: PathBuf,
    private_key_pkcs8_der: PathBuf,
    witness_id: String,
    account_id: String,
    network_profile_id: String,
    policy_digest: String,
}
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BornHistoryServerConfig {
    namespace: serde_json::Value,
    listen: SocketAddr,
    trusted_client_root_der: PathBuf,
    certificate_der: PathBuf,
    private_key_pkcs8_der: PathBuf,
}
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BornManualEnrollmentServerConfig {
    server: BornHistoryServerConfig,
    extension_digest: String,
}
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BornManualAttemptServerConfig {
    server: BornHistoryServerConfig,
    extension_digest: String,
    attempt_digest: String,
}
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BornConstructionTransportServerConfigV1 {
    original_attempt: BornManualAttemptServerConfig,
    pending_grant_digest: String,
}

/// This selector never falls back to the ordinary writer server. Keep its
/// qualification check before reading private configuration or credentials.
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
fn require_construction_transport_command_qualification() -> Result<()> {
    if !wholepact_authority::COMMON_CONTEXT_V3_ACTIVATION_QUALIFIED {
        return Err(AuthorityError::ConstructionHistoryUnsupported);
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        // Errors are fixed strings. Never print file content, cert subjects,
        // account labels, peer addresses, request bindings or key material.
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") if args.len() == 4 => {
            let policy: AccountPolicy = read_json(Path::new(&args[1]))?;
            let key = database_key(Path::new(&args[3]))?;
            AuthorityJournal::create_encrypted(Path::new(&args[2]), &key, policy)?;
            println!("Owner policy recorded in a new encrypted independent authority journal.");
        }
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        Some("serve-born-history") if args.len() == 2 => {
            let c: BornHistoryServerConfig = read_json(Path::new(&args[1]))?;
            let server_certificate = certificate(&c.certificate_der)?;
            let pin = wholepact_authority::transport::certificate_digest(&server_certificate);
            let namespace = Zeroizing::new(
                serde_json::to_vec(&c.namespace).map_err(|_| AuthorityError::InvalidBinding)?,
            );
            let journal = open_born_history_for_server(&namespace, &pin, &c.listen.to_string())?;
            let tls = ServerTls::new(
                vec![certificate(&c.trusted_client_root_der)?],
                vec![server_certificate],
                private_key(&c.private_key_pkcs8_der)?,
            )?;
            let listener = TcpListener::bind(c.listen).map_err(|_| AuthorityError::Storage)?;
            println!(
                "Canonical born witness history ready. All mutations, financial admission and writer activation are denied."
            );
            AuthorityServer::new(Arc::new(journal), tls).serve(listener)?;
        }
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        Some("serve-born-manual-enrollment") if args.len() == 2 => {
            let selected: BornManualEnrollmentServerConfig = read_json(Path::new(&args[1]))?;
            let c = selected.server;
            let server_certificate = certificate(&c.certificate_der)?;
            let pin = wholepact_authority::transport::certificate_digest(&server_certificate);
            let namespace = Zeroizing::new(
                serde_json::to_vec(&c.namespace).map_err(|_| AuthorityError::InvalidBinding)?,
            );
            let journal = open_born_manual_enrollment_for_server(
                &namespace,
                &selected.extension_digest,
                &pin,
                &c.listen.to_string(),
            )?;
            let tls = ServerTls::new(
                vec![certificate(&c.trusted_client_root_der)?],
                vec![server_certificate],
                private_key(&c.private_key_pkcs8_der)?,
            )?;
            let listener = TcpListener::bind(c.listen).map_err(|_| AuthorityError::Storage)?;
            println!(
                "Canonical native-approved manual enrollment scope ready. Only its exact first writer bootstrap and finite enrollment publication are admitted; financial operations remain denied."
            );
            AuthorityServer::new(Arc::new(journal), tls).serve(listener)?;
        }
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        Some("serve-born-manual-attempt") if args.len() == 2 => {
            let selected: BornManualAttemptServerConfig = read_json(Path::new(&args[1]))?;
            let c = selected.server;
            let server_certificate = certificate(&c.certificate_der)?;
            let pin = wholepact_authority::transport::certificate_digest(&server_certificate);
            let namespace = Zeroizing::new(
                serde_json::to_vec(&c.namespace).map_err(|_| AuthorityError::InvalidBinding)?,
            );
            let journal = wholepact_authority::open_born_manual_attempt_for_server(
                &namespace,
                &selected.extension_digest,
                &selected.attempt_digest,
                &pin,
                &c.listen.to_string(),
            )?;
            let tls = ServerTls::new(
                vec![certificate(&c.trusted_client_root_der)?],
                vec![server_certificate],
                private_key(&c.private_key_pkcs8_der)?,
            )?;
            let listener = TcpListener::bind(c.listen).map_err(|_| AuthorityError::Storage)?;
            println!(
                "Canonical native-approved manual enrollment scope ready. Only its exact selected writer attempt and finite enrollment publication are admitted; financial operations remain denied."
            );
            AuthorityServer::new(Arc::new(journal), tls).serve(listener)?;
        }
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        Some("serve-born-manual-roster-attempt-v2") if args.len() == 2 => {
            let selected: BornManualAttemptServerConfig = read_json(Path::new(&args[1]))?;
            let c = selected.server;
            let server_certificate = certificate(&c.certificate_der)?;
            let pin = wholepact_authority::transport::certificate_digest(&server_certificate);
            let namespace = Zeroizing::new(
                serde_json::to_vec(&c.namespace).map_err(|_| AuthorityError::InvalidBinding)?,
            );
            let journal = wholepact_authority::open_born_manual_roster_attempt_v2_for_server(
                &namespace,
                &selected.extension_digest,
                &selected.attempt_digest,
                &pin,
                &c.listen.to_string(),
            )?;
            let tls = ServerTls::new(
                vec![certificate(&c.trusted_client_root_der)?],
                vec![server_certificate],
                private_key(&c.private_key_pkcs8_der)?,
            )?;
            let listener = TcpListener::bind(c.listen).map_err(|_| AuthorityError::Storage)?;
            println!(
                "Canonical native-approved V2 roster-bound manual enrollment scope ready. Only its exact selected writer attempt and finite enrollment publication are admitted; financial operations remain denied."
            );
            AuthorityServer::new(Arc::new(journal), tls).serve(listener)?;
        }
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        Some("serve-born-construction-transport-v1") if args.len() == 2 => {
            require_construction_transport_command_qualification()?;
            let selected: BornConstructionTransportServerConfigV1 = read_json(Path::new(&args[1]))?;
            let original = selected.original_attempt;
            let c = original.server;
            let server_certificate = certificate(&c.certificate_der)?;
            let pin = wholepact_authority::transport::certificate_digest(&server_certificate);
            let namespace = Zeroizing::new(
                serde_json::to_vec(&c.namespace).map_err(|_| AuthorityError::InvalidBinding)?,
            );
            let journal = wholepact_authority::open_born_manual_roster_attempt_v2_for_server(
                &namespace,
                &original.extension_digest,
                &original.attempt_digest,
                &pin,
                &c.listen.to_string(),
            )?;
            let tls = ServerTls::new(
                vec![certificate(&c.trusted_client_root_der)?],
                vec![server_certificate],
                private_key(&c.private_key_pkcs8_der)?,
            )?;
            // Exact current post-grant head, original session, pin, expiry and
            // unused old-key fence are authenticated before any listener opens.
            let server = AuthorityServer::for_construction_transport_v1(
                Arc::new(journal),
                tls,
                &selected.pending_grant_digest,
            )?;
            let listener = TcpListener::bind(c.listen).map_err(|_| AuthorityError::Storage)?;
            println!(
                "Exact one-grant construction transport scope selected. Original expiry and lifetime charges remain unchanged; only current observation and the exact non-signing construction Reserve/Consume are admitted. No ordinary writer, signing or dispatch authority is served."
            );
            server.serve(listener)?;
        }
        Some("serve") if args.len() == 2 => {
            let c: ServerConfig = read_json(Path::new(&args[1]))?;
            let key = database_key(&c.database_key_file)?;
            let journal = AuthorityJournal::open_encrypted(
                &c.database,
                &key,
                &c.account_id,
                &c.network_profile_id,
            )?;
            if let Some(source) = &c.resolution_node {
                // Attachment checks the full descriptor digest against protected
                // owner enrollment. Construction does not perform a node read.
                journal.attach_resolution_node(Arc::new(source.node()?))?;
            }
            let tls = ServerTls::new(
                vec![certificate(&c.trusted_client_root_der)?],
                vec![certificate(&c.certificate_der)?],
                private_key(&c.private_key_pkcs8_der)?,
            )?;
            let listener = TcpListener::bind(c.listen).map_err(|_| AuthorityError::Storage)?;
            println!("Independent authority ready; mutually authenticated TLS only.");
            AuthorityServer::new(Arc::new(journal), tls).serve(listener)?;
        }
        Some("describe-resolution-source") if args.len() == 3 => {
            let config: ResolutionNodeConfig = read_json(Path::new(&args[1]))?;
            let node = config.node()?;
            write_json(Path::new(&args[2]), &node.source_descriptor())?;
            println!(
                "Exact source descriptor written for independent owner review. No enrollment or node connection was performed."
            );
        }
        Some("snapshot") if args.len() == 3 => {
            let client = client(Path::new(&args[1]))?;
            write_json(Path::new(&args[2]), &client.snapshot()?)?;
            println!("Authenticated account snapshot written to the selected private file.");
        }
        Some("writer") if args.len() == 4 => {
            let client = client(Path::new(&args[1]))?;
            let history = client.reconcile_history()?;
            let pending = client.acquire_writer(&history, &args[2])?;
            write_json(Path::new(&args[3]), &pending)?;
            println!(
                "Fresh reconciled writer session is pending. The independent owner must approve ActivateWriter using the exact private receipt. This process retains the ephemeral session; restart requires fresh reconciliation and owner activation. Enter bounded JSON commands: snapshot, reserve, dispatch, progress or quit, with selected private file paths."
            );
            writer_commands(&client)?;
        }
        Some("control") if args.len() == 4 => {
            let client = client(Path::new(&args[1]))?;
            let request: OwnerControlRequest = read_json(Path::new(&args[2]))?;
            write_json(Path::new(&args[3]), &client.control(request)?)?;
            println!(
                "Owner control recorded. Previously issued permits and exposure remain outstanding."
            );
        }
        _ => {
            eprintln!(
                "Usage: wholepact-authority init POLICY_JSON DATABASE KEY_FILE\n       wholepact-authority serve SERVER_CONFIG_JSON\n       wholepact-authority serve-born-history BORN_HISTORY_CONFIG_JSON (native-witness-owner feature; informational only)\n       wholepact-authority describe-resolution-source NODE_CONFIG_JSON OUTPUT_JSON\n       wholepact-authority snapshot CLIENT_CONFIG_JSON OUTPUT_JSON\n       wholepact-authority writer CLIENT_CONFIG_JSON ACQUIRE_OPERATION_ID PENDING_RECEIPT_JSON\n       wholepact-authority control OWNER_CLIENT_CONFIG_JSON CONTROL_JSON OUTPUT_JSON\nPrivate files must be in owner-private directories. Keys are raw 32-byte database keys or PKCS#8 DER TLS keys, never command-line secret values. Remote enrollment requires explicit sensitive amount/input-linkage disclosure consent. No exposure-clear or reset command exists."
            );
            return Err(AuthorityError::InvalidBinding);
        }
    }
    Ok(())
}
fn client(path: &Path) -> Result<AuthorityClient> {
    let c: ClientConfig = read_json(path)?;
    let tls = ClientTls::new(
        c.server_name,
        c.server_certificate_digest,
        vec![certificate(&c.trusted_server_root_der)?],
        vec![certificate(&c.certificate_der)?],
        private_key(&c.private_key_pkcs8_der)?,
    )?;
    AuthorityClient::new(
        c.endpoint,
        tls,
        c.witness_id,
        c.account_id,
        c.network_profile_id,
        c.policy_digest,
    )
}
fn certificate(path: &Path) -> Result<CertificateDer<'static>> {
    Ok(CertificateDer::from(
        read_private(path, 16 * 1024)?.to_vec(),
    ))
}
fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        read_private(path, 16 * 1024)?.to_vec(),
    )))
}
fn database_key(path: &Path) -> Result<DatabaseKey> {
    let raw = read_private(path, 32)?;
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        raw.as_slice()
            .try_into()
            .map_err(|_| AuthorityError::InvalidBinding)?,
    );
    if *bytes == [0; 32] {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(DatabaseKey::from_bytes(*bytes))
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_private(path, MAX_FRAME_BYTES)?)
        .map_err(|_| AuthorityError::InvalidBinding)
}
fn private_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(AuthorityError::Storage)?;
    let meta = fs::symlink_metadata(parent).map_err(|_| AuthorityError::Storage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err(AuthorityError::Storage);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        return Err(AuthorityError::Storage);
    }
    Ok(())
}
fn read_private(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    private_parent(path)?;
    let meta = fs::symlink_metadata(path).map_err(|_| AuthorityError::Storage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.permissions().mode() & 0o077 != 0
            || meta.len() > maximum as u64
        {
            return Err(AuthorityError::Storage);
        }
    }
    let mut result = Zeroizing::new(Vec::new());
    fs::File::open(path)
        .map_err(|_| AuthorityError::Storage)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut result)
        .map_err(|_| AuthorityError::Storage)?;
    if result.len() > maximum {
        return Err(AuthorityError::Limit);
    }
    Ok(result)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    private_parent(path)?;
    let body =
        Zeroizing::new(serde_json::to_vec(value).map_err(|_| AuthorityError::InvalidBinding)?);
    if body.len() > MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| AuthorityError::Storage)?;
    file.write_all(&body)
        .and_then(|_| file.sync_all())
        .map_err(|_| AuthorityError::Storage)?;
    fs::File::open(path.parent().ok_or(AuthorityError::Storage)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| AuthorityError::Storage)?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum WriterCommand {
    Snapshot { output: PathBuf },
    Reserve { request: PathBuf, output: PathBuf },
    Progress { request: PathBuf, output: PathBuf },
    Dispatch { request: PathBuf, output: PathBuf },
    Quit,
}
fn writer_commands(client: &AuthorityClient) -> Result<()> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut line = Zeroizing::new(Vec::new());
        let count = (&mut input)
            .take(16 * 1024 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|_| AuthorityError::Storage)?;
        if count == 0 {
            break;
        }
        if line.len() > 16 * 1024 {
            return Err(AuthorityError::Limit);
        }
        let command: WriterCommand =
            serde_json::from_slice(&line).map_err(|_| AuthorityError::InvalidBinding)?;
        let result = match command {
            WriterCommand::Snapshot { output } => {
                client.snapshot().and_then(|s| write_json(&output, &s))
            }
            WriterCommand::Reserve { request, output } => {
                read_json::<ReserveAuthorization>(&request)
                    .and_then(|r| client.reserve(r))
                    .and_then(|p| write_json(&output, p.descriptor()))
            }
            WriterCommand::Dispatch { request, output } => read_json::<AuthorizeDispatch>(&request)
                .and_then(|r| client.authorize_dispatch(r))
                .and_then(|p| write_json(&output, p.descriptor())),
            WriterCommand::Progress { request, output } => read_json::<ReportProgress>(&request)
                .and_then(|r| client.report_progress(r))
                .and_then(|s| write_json(&output, &s)),
            WriterCommand::Quit => break,
        };
        match result {
            Ok(()) => println!("Exact result written to the selected private file."),
            Err(error) => eprintln!("{error}"),
        }
    }
    client.forget_writer_session()?;
    Ok(())
}

#[cfg(all(test, feature = "native-witness-owner", target_os = "linux"))]
mod construction_transport_command_tests {
    use super::*;

    #[test]
    fn handoff_server_command_refuses_before_configuration_or_listener() {
        assert!(matches!(
            require_construction_transport_command_qualification(),
            Err(AuthorityError::ConstructionHistoryUnsupported)
        ));
    }

    #[test]
    fn handoff_server_selector_requires_exact_pending_grant() {
        let original = serde_json::json!({
            "server": {
                "namespace": {}, "listen": "127.0.0.1:1",
                "trusted_client_root_der": "synthetic-unused-root",
                "certificate_der": "synthetic-unused-certificate",
                "private_key_pkcs8_der": "synthetic-unused-key"
            },
            "extension_digest": "a".repeat(64),
            "attempt_digest": "b".repeat(64)
        });
        let valid = serde_json::json!({
            "original_attempt": original,
            "pending_grant_digest": "c".repeat(64)
        });
        let _: BornConstructionTransportServerConfigV1 =
            serde_json::from_value(valid.clone()).unwrap();
        let mut missing = valid.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("pending_grant_digest");
        assert!(
            serde_json::from_value::<BornConstructionTransportServerConfigV1>(missing).is_err()
        );
        let mut widened = valid;
        widened["allow_general_writer"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<BornConstructionTransportServerConfigV1>(widened).is_err()
        );
    }
}
