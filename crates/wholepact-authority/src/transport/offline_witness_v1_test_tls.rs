//! Fresh temporary identities; maintained rustls and framing, no sockets.
use super::*;
use std::io::Cursor;

pub(super) struct TlsFixture {
    pub(super) client: ClientTls,
    pub(super) server: ServerTls,
    pub(super) writer: String,
    pub(super) owner: ClientTls,
}
pub(super) fn tls_fixture() -> TlsFixture {
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };
    let temp = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let run = |args: &[&str]| {
        assert!(
            Command::new("openssl")
                .current_dir(temp.path())
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("installed OpenSSL is required for synthetic TLS tests")
                .success(),
            "ephemeral TLS generation failed"
        )
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-sha256",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=Wholepact ephemeral owner CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
    ]);
    for (name, purpose) in [
        ("server", "serverAuth"),
        ("writer", "clientAuth"),
        ("owner", "clientAuth"),
    ] {
        run(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            &format!("/CN=synthetic-{name}"),
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
        ]);
        fs::write(temp.path().join(format!("{name}.ext")),format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={purpose}\nsubjectAltName=DNS:localhost\n")).unwrap();
        run(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.pem"),
        ]);
        run(&[
            "x509",
            "-in",
            &format!("{name}.pem"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ]);
        run(&[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            &format!("{name}.key"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.pk8"),
        ]);
    }
    run(&["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"]);
    let cert = |name: &str| {
        CertificateDer::from(fs::read(temp.path().join(format!("{name}.der"))).unwrap())
    };
    let key = |name: &str| {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fs::read(temp.path().join(format!("{name}.pk8"))).unwrap(),
        ))
    };
    let server = ServerTls::new(vec![cert("ca")], vec![cert("server")], key("server")).unwrap();
    let writer = certificate_digest(&cert("writer"));
    let client = ClientTls::new(
        "localhost".into(),
        server.certificate_digest.clone(),
        vec![cert("ca")],
        vec![cert("writer")],
        key("writer"),
    )
    .unwrap();
    let owner = ClientTls::new(
        "localhost".into(),
        server.certificate_digest.clone(),
        vec![cert("ca")],
        vec![cert("owner")],
        key("owner"),
    )
    .unwrap();
    temp.close().unwrap();
    TlsFixture {
        client,
        server,
        writer,
        owner,
    }
}
pub(super) fn pump(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> std::result::Result<(), rustls::Error> {
    for _ in 0..32 {
        let mut progressed = false;
        if client.wants_write() {
            let mut b = Vec::new();
            client.write_tls(&mut b).unwrap();
            let mut wire = Cursor::new(b);
            while (wire.position() as usize) < wire.get_ref().len() {
                assert!(server.read_tls(&mut wire).unwrap() > 0);
                server.process_new_packets()?;
            }
            progressed = true;
        }
        if server.wants_write() {
            let mut b = Vec::new();
            server.write_tls(&mut b).unwrap();
            let mut wire = Cursor::new(b);
            while (wire.position() as usize) < wire.get_ref().len() {
                assert!(client.read_tls(&mut wire).unwrap() > 0);
                client.process_new_packets()?;
            }
            progressed = true;
        }
        if !progressed {
            return Ok(());
        }
    }
    panic!("synthetic TLS handshake failed to quiesce")
}
pub(super) fn connections(
    client_tls: &ClientTls,
    server_tls: &ServerTls,
) -> (ClientConnection, ServerConnection) {
    let mut client =
        ClientConnection::new(client_tls.config.clone(), client_tls.server_name.clone()).unwrap();
    let mut server = ServerConnection::new(server_tls.config.clone()).unwrap();
    pump(&mut client, &mut server).unwrap();
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert_eq!(client.alpn_protocol(), Some(ALPN));
    assert_eq!(server.alpn_protocol(), Some(ALPN));
    assert_eq!(
        certificate_digest(&client.peer_certificates().unwrap()[0]),
        client_tls.pinned_certificate
    );
    assert_eq!(
        certificate_digest(&server.peer_certificates().unwrap()[0]),
        client_tls.client_certificate
    );
    (client, server)
}
