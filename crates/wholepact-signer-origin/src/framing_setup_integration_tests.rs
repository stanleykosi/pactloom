//! Real kernel-peer regression. Explicitly ignored outside the bounded CI gate.
//! Only temporary synthetic sockets and a child of this test image are used.
use super::*;
use std::{io::{Read, Write}, os::unix::net::UnixListener, process::{Child, Command, Stdio}, sync::atomic::{AtomicBool, Ordering}, thread};

const CHILD: &str = "framing::setup_integration_tests::financial_setup_peer_child";
// Signal only an observed, still-owned unreaped child. A status error is not
// evidence of ownership; leave uncertain cleanup to the outer CI supervisor.
fn cleanup_owned_child(child: &mut Child) -> bool {
    match child.try_wait() {
        Ok(Some(_)) => true,
        Ok(None) => {
            if child.kill().is_err() { return false; }
            let until=Instant::now()+Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return true,
                    Ok(None) if Instant::now()<until => thread::sleep(Duration::from_millis(5)),
                    _ => return false,
                }
            }
        }
        Err(_) => false,
    }
}
struct PeerFixture { directory: Option<tempfile::TempDir>, stream: UnixStream, peer: PeerProcess, child: Option<Child> }
impl PeerFixture {
    fn start(mode: &str) -> Self {
        let directory=tempfile::tempdir().unwrap();
        let path=directory.path().join("setup.sock");
        let listener=UnixListener::bind(&path).unwrap();
        enable_credentials(listener.as_raw_fd()).unwrap();
        listener.set_nonblocking(true).unwrap();
        let child=Command::new(std::env::current_exe().unwrap())
            .args(["--ignored","--exact",CHILD,"--test-threads=1"])
            .env("WHOLEPACT_SETUP_TEST_SOCKET",&path).env("WHOLEPACT_SETUP_TEST_MODE",mode)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let until=Instant::now()+Duration::from_secs(3);
        let mut child=child;
        let stream=loop {
            match listener.accept() {
                Ok((stream,_))=>break stream,
                Err(e) if e.kind()==std::io::ErrorKind::WouldBlock && Instant::now()<until=>thread::sleep(Duration::from_millis(5)),
                _=>{if !cleanup_owned_child(&mut child){let _=directory.keep();}panic!("synthetic peer did not connect");}
            }
        };
        let peer=match PeerProcess::observe(&stream){Ok(peer)=>peer,Err(_)=>{if !cleanup_owned_child(&mut child){let _=directory.keep();}panic!("synthetic kernel peer unavailable");}};
        Self{directory:Some(directory),stream,peer,child:Some(child)}
    }
    fn finish(mut self) {
        let _=self.stream.write_all(b"x");
        let until=Instant::now()+Duration::from_secs(2);
        loop {
            match self.child.as_mut().unwrap().try_wait() {
                Ok(Some(status))=>{self.child.take();assert!(status.success());break;}
                Ok(None)=>(),
                Err(_)=>{self.child.take();if let Some(directory)=self.directory.take(){let _=directory.keep();}panic!("synthetic peer reap uncertain");}
            }
            assert!(Instant::now()<until,"synthetic peer cleanup deadline");
            thread::sleep(Duration::from_millis(5));
        }
        let directory=self.directory.take().unwrap();let path=directory.path().to_path_buf();directory.close().unwrap();assert!(!path.exists());
    }
}
impl Drop for PeerFixture {
    fn drop(&mut self) {
        if let Some(mut child)=self.child.take() {
            if !cleanup_owned_child(&mut child) {
                if let Some(directory)=self.directory.take(){let _=directory.keep();}
            }
        }
    }
}

#[test]
#[ignore = "CI-only real socket child, invoked by the exact parent selector"]
fn financial_setup_peer_child() {
    let path=std::env::var_os("WHOLEPACT_SETUP_TEST_SOCKET").expect("parent-owned socket");
    let mode=std::env::var("WHOLEPACT_SETUP_TEST_MODE").unwrap();
    let mut stream=UnixStream::connect(path).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    thread::sleep(Duration::from_millis(40));
    match mode.as_str(){
        "full"=>stream.write_all(b"synthetic-preview\n").unwrap(),
        "partial"=>stream.write_all(b"synthetic-partial").unwrap(),
        "exit"=>return,
        "idle"=>(),
        _=>panic!("unknown synthetic mode"),
    }
    let mut stop=[0]; let _=stream.read_exact(&mut stop);
}

#[test]
#[ignore = "CI-only authenticated Unix peer regression; no local execution"]
fn financial_setup_real_peer_contract() {
    fn report(attempt:usize,case:&str,receiver:&str,writer:&str,start:Instant){
        println!("ORIGIN_SETUP_INTEGRATION attempt={attempt} case={case} receiver={receiver} writer={writer} elapsed_ms={} cleanup=true passed=true",start.elapsed().as_millis());
    }
    // Inert setup may wait beyond120, but first readable bytes enter the same
    // authenticated capped receiver. The helper's private deterministic test
    // separately asserts min(original ceiling, first-readable time +120).
    let start=Instant::now();let f=PeerFixture::start("full");
    let ceiling=Instant::now()+Duration::from_secs(899);
    let frame=read_setup_frame_capped_checked_until(&f.stream,&f.peer,128,ceiling,||Ok(())).unwrap();
    assert_eq!(&*frame,b"synthetic-preview"); f.finish();report(0,"SetupSuccess","Frame","Sent",start);

    // The ordinary effect reader is unchanged and rejects an oversized budget
    // before consuming the pending frame.
    let start=Instant::now();let f=PeerFixture::start("full");
    let error=read_frame_capped_checked_observed_until(&f.stream,&f.peer,128,Instant::now()+Duration::from_secs(899),||Ok(())).unwrap_err();
    assert_eq!(error.cause,FrameReadCause::InvalidBudget);
    let frame=read_setup_frame_capped_checked_until(&f.stream,&f.peer,128,Instant::now()+Duration::from_secs(2),||Ok(())).unwrap();
    assert_eq!(&*frame,b"synthetic-preview");f.finish();report(1,"GenericBudget","InvalidBudget","Sent",start);

    // The original ceiling is fixed, including after a partial frame. There is
    // no loop that discards bytes and restarts a fresh receive budget.
    for mode in ["idle","partial"] {
        let f=PeerFixture::start(mode);let start=Instant::now();let ceiling=start+Duration::from_millis(200);
        assert!(read_setup_frame_capped_checked_until(&f.stream,&f.peer,128,ceiling,||Ok(())).is_err());
        assert!(Instant::now()>=ceiling);assert!(start.elapsed()<Duration::from_secs(2));f.finish();report(if mode=="idle"{2}else{3},if mode=="idle"{"IdleCeiling"}else{"PartialCeiling"},"Deadline",if mode=="idle"{"Idle"}else{"Sent"},start);
    }
    // Source revocation is checked during both readiness wait and partial read.
    for mode in ["idle","partial"] {
        let f=PeerFixture::start(mode);let start=Instant::now();let revoked=AtomicBool::new(false);
        let result=read_setup_frame_capped_checked_until(&f.stream,&f.peer,128,start+Duration::from_secs(899),||{
            if start.elapsed()>=Duration::from_millis(150){revoked.store(true,Ordering::Release);return Err(Error::Permission);}Ok(())
        });
        assert!(matches!(result,Err(Error::Permission)));assert!(revoked.load(Ordering::Acquire));assert!(start.elapsed()<Duration::from_secs(2));f.finish();report(if mode=="idle"{4}else{5},if mode=="idle"{"IdleRevocation"}else{"PartialRevocation"},"CurrentCheck",if mode=="idle"{"Idle"}else{"Sent"},start);
    }
    // A real child exit invalidates the actual pidfd, not a serialized label.
    let f=PeerFixture::start("exit");let start=Instant::now();
    assert!(read_setup_frame_capped_checked_until(&f.stream,&f.peer,128,start+Duration::from_secs(899),||Ok(())).is_err());
    assert!(start.elapsed()<Duration::from_secs(2));f.finish();
    report(6,"PeerExit","ReadClosed","Closed",start);
}
