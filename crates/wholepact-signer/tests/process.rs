#![cfg(feature = "synthetic-qualification")]
//! All passwords, spending keys, notes and accounts here are synthetic and never
//! funded. Real signature operations occur in separate OS processes; no network.
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};
use wholepact_protocol::synthetic::{combine_verify_authorizations, review_fixture};
const PASSWORD: &str = "synthetic-test-password-only";

struct Process {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}
impl Process {
    fn start(root: &Path, fault: Option<&str>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wholepact-signer"));
        command
            .arg("--synthetic-stdio")
            .arg(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(point) = fault {
            command.arg("--crash-at").arg(point);
        }
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
        }
    }
    fn send(&mut self, value: &Value) {
        serde_json::to_writer(&mut self.stdin, value).unwrap();
        writeln!(self.stdin).unwrap();
        self.stdin.flush().unwrap();
    }
    fn read(&mut self) -> Option<Value> {
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).unwrap();
        if n == 0 {
            None
        } else {
            Some(serde_json::from_str(&line).unwrap())
        }
    }
    fn call(&mut self, value: Value) -> Value {
        self.send(&value);
        self.read().expect("process response")
    }
    fn ok(&mut self, value: Value) -> Value {
        let response = self.call(value);
        assert_eq!(response["ok"], true, "{response}");
        response["result"].clone()
    }
    fn ready(&mut self, owner: u8) {
        self.ok(json!({"command":"initialize","owner":owner,"password":PASSWORD}));
        self.ok(json!({"command":"create_backup"}));
        self.ok(json!({"command":"verify_backup"}));
    }
    fn review(&mut self, pczt: &[u8], operation: &str) -> Value {
        self.ok(json!({"command":"review","operation_id":operation,"client_id":"fixture-client","obligation_id":"fixture-obligation","proposal_id":"fixture-proposal","pczt_hex":hex::encode(pczt)}))
    }
    fn approve_request(review: &Value) -> Value {
        json!({"command":"approve","review_nonce":review["review_nonce"],"review_binding":review["review_binding"],"client_id":"fixture-client","acknowledge_synthetic_only":true})
    }
    fn stop_and_check_logs(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        let mut logs = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut logs)
            .unwrap();
        assert!(logs.is_empty(), "signer must not log private material");
    }
    fn retrieve(&mut self, operation: &str) -> Value {
        self.call(
            json!({"command":"retrieve","operation_id":operation,"client_id":"fixture-client"}),
        )
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn independent_owner_processes_sign_exact_review_and_replay_identical_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = review_fixture().unwrap();
    let mut copies = Vec::new();
    for owner in 0..2 {
        let root = temp.path().join(format!("owner-{owner}"));
        let mut p = Process::start(&root, None);
        p.ready(owner);
        let review = p.review(&fixture.pczt_bytes, "operation-1");
        assert_eq!(
            review["maximum_net_debit_zatoshis"],
            ["105000", "210000"][owner as usize]
        );
        assert_eq!(review["chain_validated"], false);
        let mut substituted = Process::approve_request(&review);
        substituted["review_binding"] = json!("0".repeat(64));
        assert_eq!(p.call(substituted)["ok"], false);
        assert_eq!(p.ok(json!({"command":"status"}))["exposures"], 0);
        assert_eq!(p.call(Process::approve_request(&review))["ok"], false); // nonce consumed
        let review = p.review(&fixture.pczt_bytes, "operation-1");
        let signed = p.ok(Process::approve_request(&review));
        assert_eq!(signed["qualification_only"], true);
        assert_eq!(signed["chain_validated"], false);
        assert_eq!(
            signed["evidence_kind"],
            "synthetic-process-authorization-only"
        );
        assert_eq!(p.call(Process::approve_request(&review))["ok"], false);
        assert_eq!(p.retrieve("operation-1")["result"], signed);
        p.ok(json!({"command":"create_backup"}));
        p.ok(json!({"command":"verify_backup"}));
        assert_eq!(p.call(json!({"command":"retrieve","operation_id":"operation-1","client_id":"different-client"}))["ok"],false);
        copies.push(hex::decode(signed["signed_pczt_hex"].as_str().unwrap()).unwrap());
        p.stop_and_check_logs();
        drop(p);
        for entry in std::fs::read_dir(&root).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() {
                continue;
            }
            let contents = std::fs::read(path).unwrap();
            for forbidden in [
                PASSWORD.as_bytes(),
                &[(owner + 1); 32],
                fixture.policy.participants[owner as usize]
                    .fvk
                    .to_bytes()
                    .as_slice(),
                fixture.pczt_bytes.as_slice(),
            ] {
                assert!(
                    !contents.windows(forbidden.len()).any(|w| w == forbidden),
                    "private fixture material leaked to persistent plaintext"
                );
            }
        }
        let mut restarted = Process::start(&root, None);
        let status = restarted.ok(json!({"command":"unlock","password":PASSWORD}));
        assert_eq!(status["exposures"], 1);
        assert_eq!(restarted.retrieve("operation-1")["result"], signed);
        let another = restarted.review(&fixture.pczt_bytes, "operation-2");
        assert_eq!(
            restarted.call(Process::approve_request(&another))["ok"],
            false
        ); // same live obligation
        assert_eq!(restarted.ok(json!({"command":"status"}))["exposures"], 1);
    }
    assert!(combine_verify_authorizations(&[&copies[0]]).is_err());
    assert!(combine_verify_authorizations(&[&copies[1]]).is_err());
    let combined = combine_verify_authorizations(&[&copies[0], &copies[1]]).unwrap();
    assert!(!combined.is_empty());
}

#[test]
fn every_release_crash_boundary_preserves_conservative_exposure() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = review_fixture().unwrap();
    for point in [
        "before-intent",
        "after-intent",
        "after-sign",
        "after-result",
        "before-export",
    ] {
        let root = temp.path().join(point);
        let mut p = Process::start(&root, Some(point));
        p.ready(0);
        let review = p.review(&fixture.pczt_bytes, "crash-operation");
        p.send(&Process::approve_request(&review));
        assert!(p.read().is_none());
        assert_eq!(p.child.wait().unwrap().code(), Some(86));
        drop(p);
        let mut restarted = Process::start(&root, None);
        let status = restarted.ok(json!({"command":"unlock","password":PASSWORD}));
        assert_eq!(
            status["exposures"],
            if point == "before-intent" { 0 } else { 1 }
        );
        let replay = restarted.retrieve("crash-operation");
        if point == "after-result" || point == "before-export" {
            assert_eq!(replay["ok"], true);
            assert_eq!(restarted.retrieve("crash-operation"), replay);
        } else {
            assert_eq!(replay["ok"], false);
        }
        if point != "before-intent" {
            let duplicate = restarted.review(&fixture.pczt_bytes, "fresh-operation");
            assert_eq!(
                restarted.call(Process::approve_request(&duplicate))["ok"],
                false
            );
            assert_eq!(
                restarted.ok(json!({"command":"status"}))["outstanding_debit_zatoshis"],
                "105000"
            );
        }
    }
}

#[test]
fn journal_commit_failure_blocks_signature_export() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("owner");
    let mut p = Process::start(&root, None);
    p.ready(0);
    let db = rusqlite::Connection::open(root.join("authority.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER synthetic_fail BEFORE INSERT ON authority_exposures BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
    let fixture = review_fixture().unwrap();
    let review = p.review(&fixture.pczt_bytes, "blocked-operation");
    assert_eq!(p.call(Process::approve_request(&review))["ok"], false);
    assert_eq!(p.ok(json!({"command":"status"}))["exposures"], 0);
    assert_eq!(p.retrieve("blocked-operation")["ok"], false);
    assert!(!std::fs::read_dir(&root).unwrap().any(|p| p
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("result-")));
}

#[test]
fn missing_journal_and_restored_backups_cannot_sign() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("owner");
    let mut p = Process::start(&root, None);
    p.ready(0);
    let fixture = review_fixture().unwrap();
    let review = p.review(&fixture.pczt_bytes, "original-operation");
    p.ok(Process::approve_request(&review));
    p.ok(json!({"command":"create_backup"}));
    p.ok(json!({"command":"verify_backup"}));
    let backup = std::fs::read(root.join("backup.wp")).unwrap();
    drop(p);
    let restored_root = temp.path().join("restored");
    let mut restored = Process::start(&restored_root, None);
    let status = restored.ok(
        json!({"command":"restore","encrypted_backup_hex":hex::encode(backup),"password":PASSWORD}),
    );
    assert_eq!(status["recovery_required"], true);
    assert_eq!(status["exposure_completeness_known"], false);
    assert!(status["outstanding_debit_zatoshis"].is_null());
    assert_eq!(restored.call(json!({"command":"review","operation_id":"restored-operation","client_id":"fixture-client","obligation_id":"another-obligation","proposal_id":"proposal","pczt_hex":hex::encode(&fixture.pczt_bytes)}))["ok"],false);
    for suffix in [
        "authority.sqlite",
        "authority.sqlite-wal",
        "authority.sqlite-shm",
    ] {
        let _ = std::fs::remove_file(root.join(suffix));
    }
    let mut lost = Process::start(&root, None);
    let status = lost.ok(json!({"command":"unlock","password":PASSWORD}));
    assert_eq!(status["recovery_required"], true);
}

#[test]
fn default_binary_rejects_live_setup_and_unknown_ipc_fields() {
    let output = Command::new(env!("CARGO_BIN_EXE_wholepact-signer"))
        .arg("capabilities")
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["live_signing"], false);
    assert_eq!(value["automation"], false);
    assert!(!Command::new(env!("CARGO_BIN_EXE_wholepact-signer"))
        .arg("initialize")
        .output()
        .unwrap()
        .status
        .success());
    let temp = tempfile::tempdir().unwrap();
    let mut p = Process::start(&temp.path().join("owner"), None);
    assert_eq!(
        p.call(json!({"command":"status","verified":true}))["ok"],
        false
    );
    assert_eq!(
        p.call(json!({"command":"unlock","password":"synthetic-nonexistent-password"}))["ok"],
        false
    );
}

#[test]
#[cfg(target_os = "linux")]
fn app_owned_pty_cannot_establish_provisioning_consent() {
    use std::{
        fs::File,
        os::{fd::FromRawFd, unix::process::CommandExt},
    };
    let mut master_fd = -1;
    let mut slave_fd = -1;
    // SAFETY: valid output pointers and null optional termios/winsize arguments.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    // SAFETY: openpty returned two newly owned file descriptors.
    let mut master = unsafe { File::from_raw_fd(master_fd) };
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    let mut command = Command::new(env!("CARGO_BIN_EXE_wholepact-signer"));
    command
        .arg("--synthetic-terminal-probe")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    // SAFETY: only async-signal-safe libc calls between fork and exec; fd0 is the slave.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop(command);
    let mut transcript = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => transcript.extend_from_slice(&buffer[..n]),
            Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
            Err(e) => panic!("PTY read failed: {e}"),
        }
    }
    assert!(child.wait().unwrap().success());
    let value: Value = serde_json::from_slice(&transcript).unwrap();
    assert_eq!(value["controlling_tty"], true);
    assert_eq!(value["human_origin_authenticated"], false);
    assert_eq!(value["provisioning_consent"], false);
}
