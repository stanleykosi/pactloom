//! Owned-child storage-death regressions, NOT installed native admission evidence.
//! No socket, credential, external process discovery or remote execution is used.
use super::*;
use std::{process::{Child,Command,Stdio},time::{Duration,Instant}};
const CHILD:&str="host::durable_dispatcher_v2::process_tests::dispatcher_marker_storage_child";
const MODE:&str="WHOLEPACT_DISPATCHER_STORAGE_COMPONENT_MODE";
const ROOT:&str="WHOLEPACT_DISPATCHER_STORAGE_COMPONENT_ROOT";
struct ChildOwner(Option<Child>);
impl Drop for ChildOwner { fn drop(&mut self) { if let Some(mut child)=self.0.take() { let _=child.kill();let _=child.wait(); } } }
#[test]
#[ignore="Internal isolated storage child; run only by exact component parent"]
fn dispatcher_marker_storage_child() {
    let Some(root)=std::env::var_os(ROOT) else {return};let root=std::path::PathBuf::from(root);
    if std::env::var(MODE).as_deref()==Ok("read") {
        let directory=Directory::open(&root.join("host")).unwrap();
        let before=directory.private_workspace_candidates().unwrap();assert_eq!(before.len(),2);
        let vault=directory.read("profile.vault",1024).unwrap();
        assert!(Secrets::open(&vault,super::tests::PASSWORD).is_err());
        assert!(Secrets::open_private_workspace_v3(&vault,super::tests::PASSWORD).is_err());
        let v4=Secrets::open_workspace_dispatcher_v4(&vault,super::tests::PASSWORD).unwrap();
        assert!(OriginalWorkspaceDispatcherPublicationV4::inspect(&directory,&v4).is_err());
        assert_eq!(before,directory.private_workspace_candidates().unwrap());
        assert_eq!(vault,directory.read("profile.vault",1024).unwrap());
        crate::files::write_new(&root.join("reader-complete"),b"fresh-process-refused-partial-source").unwrap();
        return;
    }
    let directory=Directory::create(&root.join("host")).unwrap();
    let secrets=Secrets::fresh().unwrap().bind_successor_plan([11;32]).unwrap().bind_private_workspace_v3([12;32]).unwrap().bind_workspace_dispatcher_v4([13;32]).unwrap();
    directory.write_new("profile.vault",&secrets.seal(super::tests::PASSWORD).unwrap()).unwrap();
    let pending=DispatcherFileV2::stage(&directory,PENDING,b"component-only-not-source-evidence",MAX_PENDING).unwrap();
    let commit=DispatcherFileV2::stage(&directory,COMMIT,b"component-only-not-source-evidence",MAX_COMMIT).unwrap();
    crate::files::write_new(&root.join("ready"),b"durable-v4-marker").unwrap();
    loop {std::thread::park();std::hint::black_box((&directory,&secrets,&pending,&commit));}
}
#[test]
fn process_death_keeps_v4_marker_and_partial_files_without_automatic_repair() {
    let temp=tempfile::tempdir().unwrap();
    let child=Command::new(std::env::current_exe().unwrap()).args(["--exact",CHILD,"--ignored","--nocapture"]).env(ROOT,temp.path()).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let mut owner=ChildOwner(Some(child));let deadline=Instant::now()+Duration::from_secs(45);
    while !temp.path().join("ready").exists() {assert!(Instant::now()<deadline);assert!(owner.0.as_mut().unwrap().try_wait().unwrap().is_none());std::thread::sleep(Duration::from_millis(20));}
    let child=owner.0.as_mut().unwrap();child.kill().unwrap();assert!(!child.wait().unwrap().success());owner.0.take();
    let reader=Command::new(std::env::current_exe().unwrap()).args(["--exact",CHILD,"--ignored","--nocapture"]).env(ROOT,temp.path()).env(MODE,"read").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let mut reader=ChildOwner(Some(reader));let deadline=Instant::now()+Duration::from_secs(45);
    loop {
        if let Some(status)=reader.0.as_mut().unwrap().try_wait().unwrap() {assert!(status.success());break;}
        assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(20));
    }
    reader.0.take();assert!(temp.path().join("reader-complete").exists());
    let directory=Directory::open(&temp.path().join("host")).unwrap();
    let before=directory.private_workspace_candidates().unwrap();assert_eq!(before.len(),2);
    let vault=directory.read("profile.vault",1024).unwrap();
    assert!(Secrets::open(&vault,super::tests::PASSWORD).is_err());
    assert!(Secrets::open_private_workspace_v3(&vault,super::tests::PASSWORD).is_err());
    let v4=Secrets::open_workspace_dispatcher_v4(&vault,super::tests::PASSWORD).unwrap();
    assert!(OriginalWorkspaceDispatcherPublicationV4::inspect(&directory,&v4).is_err());
    assert_eq!(before,directory.private_workspace_candidates().unwrap());
    assert_eq!(vault,directory.read("profile.vault",1024).unwrap());
}
