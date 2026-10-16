//! Synthetic loopback failure fixture; no wallet, chain, or external service.
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[test]
fn truncated_post_response_retains_retry_key_and_closes_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let fixture = thread::spawn(move || {
        let mut paths = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while paths.len() < 3 && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0u8; 1024];
            while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
            }
            let request = String::from_utf8(bytes).unwrap();
            let path = request.split_whitespace().nth(1).unwrap().to_owned();
            paths.push(path.clone());
            match path.as_str() {
                "/v1/session" => {
                    let body = r#"{"session_token":"synthetic-local-fixture-token","csrf_token":"synthetic-local-fixture-csrf"}"#;
                    write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                }
                "/v1/agreements" => {
                    write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{{").unwrap();
                }
                "/v1/session/end" => {
                    write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n{{\"ended\":true}}").unwrap();
                }
                _ => panic!("unexpected path {path}"),
            }
        }
        paths
    });
    let input = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../wholepact-core/tests/fixtures/agreement.json");
    let output = Command::new(env!("CARGO_BIN_EXE_wholepact"))
        .args([
            "--development-fixture",
            "--server",
            &format!("http://127.0.0.1:{port}"),
            "agreements",
            "create",
        ])
        .arg(input)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("the request may have committed"),
        "{stderr}"
    );
    assert!(stderr.contains("--idempotency-key "), "{stderr}");
    assert_eq!(
        fixture.join().unwrap(),
        vec!["/v1/session", "/v1/agreements", "/v1/session/end"]
    );
}
