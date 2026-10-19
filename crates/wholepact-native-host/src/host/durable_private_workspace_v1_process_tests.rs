//! Real process death of isolated encrypted storage fixtures only. This is NOT
//! the genuine native fixed-proof qualification, and issues no native grant.
use super::*;
use std::os::unix::process::ExitStatusExt;
use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
const CHILD: &str =
    "host::durable_private_workspace_v1::process_tests::workspace_storage_component_child";
const ROOT_ENV: &str = "WHOLEPACT_WORKSPACE_COMPONENT_ROOT";
const STATE_ENV: &str = "WHOLEPACT_WORKSPACE_COMPONENT_STATE";
const PASSWORD: &[u8] = b"isolated-component-vault-password";
struct ChildOwner(Option<Child>);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
#[test]
#[ignore = "Internal isolated child role; invoked only by exact parent component test"]
fn workspace_storage_component_child() {
    let Some(root) = std::env::var_os(ROOT_ENV) else {
        return;
    };
    let root = PathBuf::from(root);
    let state = std::env::var(STATE_ENV).unwrap();
    let (p, c) = match state.as_str() {
        "staged" => (false, false),
        "pending-final" => (true, false),
        "final" => (true, true),
        _ => panic!("invalid component state"),
    };
    let (directory, secrets) = super::tests::fixture(&root.join("host"), p, c);
    directory
        .write_new("profile.vault", &secrets.seal(PASSWORD).unwrap())
        .unwrap();
    let before = super::tests::fingerprint(&directory);
    crate::files::write_new(
        &root.join("expected.json"),
        &serde_json::to_vec(&before).unwrap(),
    )
    .unwrap();
    crate::files::write_new(&root.join("ready"), b"durable\n").unwrap();
    // Parent kills this exact owned child, never a discovered PID or process group.
    // Keep original locked descriptors and encrypted-key owners live until death.
    loop {
        std::thread::park();
        std::hint::black_box((&directory, &secrets));
    }
}
#[test]
fn actual_storage_process_death_preserves_each_anchored_publication_state() {
    for state in ["staged", "pending-final", "final"] {
        let temp = tempfile::tempdir().unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD, "--ignored", "--nocapture"])
            .env(ROOT_ENV, temp.path())
            .env(STATE_ENV, state)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut owner = ChildOwner(Some(child));
        let deadline = Instant::now() + Duration::from_secs(45);
        while !temp.path().join("ready").exists() {
            assert!(
                Instant::now() < deadline,
                "component child did not reach bounded durable state"
            );
            assert!(
                owner.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "component child exited before durable state"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let original_pid = owner.0.as_ref().unwrap().id();
        owner.0.as_mut().unwrap().kill().unwrap();
        let status = owner.0.as_mut().unwrap().wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        owner.0.take();
        // The reader is this distinct parent process, not a reused producer.
        assert_ne!(original_pid, std::process::id());
        let directory = Directory::open(&temp.path().join("host")).unwrap();
        let expected: Vec<(String, u64, u64, Vec<u8>)> =
            serde_json::from_slice(&fs::read(temp.path().join("expected.json")).unwrap()).unwrap();
        assert_eq!(super::tests::fingerprint(&directory), expected);
        let secrets = Secrets::open_private_workspace_v3(
            &directory.read("profile.vault", 1024).unwrap(),
            PASSWORD,
        )
        .unwrap();
        let publication = OriginalWorkspacePublicationV1::inspect(&directory, &secrets).unwrap();
        assert_eq!(publication.pending_file.is_final(), state != "staged");
        assert_eq!(publication.commit_file.is_final(), state == "final");
        assert_eq!(
            OriginalWorkspaceFilesV1::open_final(&directory, &secrets).is_ok(),
            state == "final"
        );
        assert_eq!(super::tests::fingerprint(&directory), expected);
        assert!(Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).is_err());
    }
}
