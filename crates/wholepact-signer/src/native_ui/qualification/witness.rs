//! Ephemeral local mutually authenticated witness. Never installed or connected
//! to an external account. Its private credentials live only in the private fixture.
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wholepact_authority::*;
use wholepact_storage_security::DatabaseKey;

pub(super) struct Witness {
    pub(super) writer: AuthorityClient,
    pub(super) owner: AuthorityClient,
    pub(super) account: String,
    pub(super) network: String,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn openssl(root: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(out.status.success(), "ephemeral synthetic TLS setup failed");
}
fn credential(root: &Path, name: &str, key: bool) -> PathBuf {
    root.join(if key {
        format!("{name}.key.der")
    } else {
        format!("{name}.der")
    })
}
impl Witness {
    pub(super) fn start(
        root: &Path,
        account: &str,
        enrollment: &str,
        recipient_scope: &str,
    ) -> Self {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        openssl(
            root,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "1",
                "-subj",
                "/CN=Wholepact fixed never-funded fixture CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        for (name, eku) in [
            ("server", "serverAuth"),
            ("writer", "clientAuth"),
            ("owner", "clientAuth"),
        ] {
            openssl(
                root,
                &[
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    &format!("{name}.key"),
                    "-out",
                    &format!("{name}.csr"),
                    "-subj",
                    &format!("/CN=synthetic-{name}"),
                ],
            );
            fs::write(root.join(format!("{name}.ext")),format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={eku}\nsubjectAltName=DNS:localhost\n")).unwrap();
            openssl(
                root,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &format!("{name}.csr"),
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-out",
                    &format!("{name}.pem"),
                    "-days",
                    "1",
                    "-extfile",
                    &format!("{name}.ext"),
                ],
            );
            openssl(
                root,
                &[
                    "x509",
                    "-in",
                    &format!("{name}.pem"),
                    "-outform",
                    "DER",
                    "-out",
                    &format!("{name}.der"),
                ],
            );
            openssl(
                root,
                &[
                    "pkcs8",
                    "-topk8",
                    "-nocrypt",
                    "-in",
                    &format!("{name}.key"),
                    "-outform",
                    "DER",
                    "-out",
                    &format!("{name}.key.der"),
                ],
            );
        }
        openssl(
            root,
            &["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"],
        );
        for entry in fs::read_dir(root).unwrap() {
            fs::set_permissions(entry.unwrap().path(), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let cert =
            |name: &str| CertificateDer::from(fs::read(credential(root, name, false)).unwrap());
        let key = |name: &str| {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                fs::read(credential(root, name, true)).unwrap(),
            ))
        };
        let policy = AccountPolicy {
            account_use_genesis: None,
            witness_id: "fixed-never-funded-witness".into(),
            account_id: account.into(),
            network_profile_id: super::PROFILE.into(),
            owner_certificate_digest: transport::certificate_digest(&cert("owner")),
            initial_writer_certificate_digest: transport::certificate_digest(&cert("writer")),
            initial_writer_epoch: 1,
            enrollment_refs: vec![enrollment.into()],
            agreement_ids: vec![super::AGREEMENT.into()],
            recipient_scope_digests: vec![recipient_scope.into()],
            aggregate_budget_zatoshis: 110_000,
            per_operation_limit_zatoshis: 110_000,
            maximum_fee_share_zatoshis: 10_000,
            maximum_transaction_fee_zatoshis: 10_000,
            maximum_permit_lifetime_ms: 120_000,
            policy_expires_at_ms: now_ms() + 600_000,
        };
        let digest = policy.policy_digest().unwrap();
        let journal = Arc::new(
            AuthorityJournal::create_encrypted(
                &root.join("witness.sqlite"),
                &DatabaseKey::from_bytes([0x91; 32]),
                policy,
            )
            .unwrap(),
        );
        let server = Arc::new(AuthorityServer::new(
            journal.clone(),
            ServerTls::new(vec![cert("ca")], vec![cert("server")], key("server")).unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = thread::spawn(move || {
            let mut workers = vec![];
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let server = server.clone();
                        workers.push(thread::spawn(move || {
                            let _ = server.serve_connection(socket);
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        let client = |name: &str| {
            AuthorityClient::new(
                address,
                ClientTls::new(
                    "localhost".into(),
                    transport::certificate_digest(&cert("server")),
                    vec![cert("ca")],
                    vec![cert(name)],
                    key(name),
                )
                .unwrap(),
                "fixed-never-funded-witness".into(),
                account.into(),
                super::PROFILE.into(),
                digest.clone(),
            )
            .unwrap()
        };
        Self {
            writer: client("writer"),
            owner: client("owner"),
            account: account.into(),
            network: super::PROFILE.into(),
            stop,
            worker: Some(worker),
        }
    }
    pub(super) fn control(&self, id: &str, control: OwnerControl) -> AccountSnapshot {
        let before = self.owner.snapshot().unwrap();
        self.owner
            .control(OwnerControlRequest {
                operation_id: id.into(),
                account_id: self.account.clone(),
                network_profile_id: self.network.clone(),
                expected_head: before.head,
                writer_epoch: before.writer_epoch,
                control,
            })
            .unwrap()
    }
    pub(super) fn activate(&self) {
        let history = self.writer.reconcile_history().unwrap();
        let receipt = self
            .writer
            .acquire_writer(&history, "fixed-writer-session")
            .unwrap();
        self.control(
            "fixed-owner-activate",
            OwnerControl::ActivateWriter {
                session_id: receipt.session_id,
            },
        );
    }
}
impl Drop for Witness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}
