// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end TLS handshake tests for the ne-api surfaces.
//!
//! Binds ephemeral loopback ports, so these are excluded from the
//! seccomp sandbox (run with the sandbox disabled). They prove:
//!   * gRPC-over-TLS with a valid bearer token round-trips,
//!   * gRPC-over-TLS without a token is UNAUTHENTICATED (TLS+auth compose),
//!   * a plaintext client against the TLS port is rejected,
//!   * the HTTPS REST surface terminates TLS and responds.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use ne_api::auth::ApiKeyStore;
use ne_api::core::RuntimeCore;
use ne_api::supervisor_client::SupervisorClient;
use ne_api::tls::{TlsConfig, install_crypto_provider};
use ne_protocol::grpc::runtime::v1::PingRequest;
use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_rustls::TlsConnector;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

const TOKEN: &str = "nee_testtoken";

// Inline self-signed cert (SAN: localhost) — avoids depending on the `nee`
// crate's tls_cli helper, which would create a dependency cycle.
fn gen_cert() -> (String, String) {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (c.cert.pem(), c.key_pair.serialize_pem())
}

fn store() -> Arc<ApiKeyStore> {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("k");
    std::fs::write(
        &p,
        format!("sha256:{}\n", hex::encode(Sha256::digest(TOKEN.as_bytes()))),
    )
    .unwrap();
    std::mem::forget(dir);
    Arc::new(ApiKeyStore::load(&p).unwrap())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start the server (TLS, auth) on the given ports; returns the CA PEM the
/// client must trust (the self-signed cert, SAN "localhost").
async fn start_server(grpc_port: u16, rest_port: u16) -> Vec<u8> {
    install_crypto_provider();
    let (cert_pem, key_pem) = gen_cert();
    let dir = tempfile::tempdir().unwrap();
    let cp = dir.path().join("cert.pem");
    let kp = dir.path().join("key.pem");
    std::fs::write(&cp, &cert_pem).unwrap();
    std::fs::write(&kp, &key_pem).unwrap();
    let tls = TlsConfig::from_pem_files(&cp, &kp).unwrap();
    std::mem::forget(dir);

    let core = Arc::new(RuntimeCore::new(SupervisorClient::new(
        "/nonexistent.sock".into(),
    )));
    let grpc_bind = format!("127.0.0.1:{grpc_port}").parse().unwrap();
    let rest_bind = format!("127.0.0.1:{rest_port}").parse().unwrap();
    let auth = Some(store());
    tokio::spawn(async move {
        let _ = ne_api::run(core, grpc_bind, rest_bind, auth, Some(tls)).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    cert_pem.into_bytes()
}

fn tls_channel(ca_pem: &[u8], port: u16) -> Endpoint {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name("localhost");
    Channel::from_shared(format!("https://localhost:{port}"))
        .unwrap()
        .tls_config(tls)
        .unwrap()
}

#[tokio::test]
async fn grpc_over_tls_with_token_round_trips() {
    let grpc = free_port();
    let rest = free_port();
    let ca = start_server(grpc, rest).await;

    let channel = tls_channel(&ca, grpc).connect().await.expect("TLS connect");
    let token: tonic::metadata::MetadataValue<_> = format!("Bearer {TOKEN}").parse().unwrap();
    #[allow(clippy::result_large_err)]
    let mut client = RuntimeClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
        req.metadata_mut().insert("authorization", token.clone());
        Ok(req)
    });
    // Ping reaches the (absent) supervisor and fails there — but NOT with
    // UNAUTHENTICATED, proving TLS + auth both passed.
    let status = client
        .ping(PingRequest {})
        .await
        .expect_err("supervisor absent → err");
    assert_ne!(
        status.code(),
        tonic::Code::Unauthenticated,
        "valid token must pass auth: {status:?}"
    );
}

#[tokio::test]
async fn grpc_over_tls_without_token_is_unauthenticated() {
    let grpc = free_port();
    let rest = free_port();
    let ca = start_server(grpc, rest).await;

    let channel = tls_channel(&ca, grpc).connect().await.expect("TLS connect");
    let mut client = RuntimeClient::new(channel);
    let status = client
        .ping(PingRequest {})
        .await
        .expect_err("must be rejected");
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "missing token must be 401-equiv"
    );
}

#[tokio::test]
async fn plaintext_client_against_tls_port_fails() {
    let grpc = free_port();
    let rest = free_port();
    let _ca = start_server(grpc, rest).await;

    // A plaintext HTTP request to the TLS-terminated REST port must NOT get an
    // HTTP response: the rustls server reads the cleartext as a bad ClientHello
    // and aborts the handshake (TLS alert / connection close), never speaking
    // HTTP. A plaintext REST server, by contrast, WOULD answer "HTTP/1.1 401…".
    // (Test `https_rest_terminates_tls` proves a real TLS handshake to this same
    // port succeeds, so this is a true negative control, not a liveness fluke.)
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", rest))
        .await
        .expect("tcp connect");
    tcp.write_all(b"GET /v1/host/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write plaintext request");
    let mut buf = vec![0u8; 64];
    let n = tcp.read(&mut buf).await.unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(
        !head.starts_with("HTTP/1.1 "),
        "TLS-terminated REST port must not answer a cleartext HTTP request, got: {head:?}"
    );
}

#[tokio::test]
async fn https_rest_terminates_tls() {
    let grpc = free_port();
    let rest = free_port();
    let ca = start_server(grpc, rest).await;

    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca.as_slice()) {
        roots.add(c.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", rest))
        .await
        .unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake to REST");

    stream
        .write_all(b"GET /v1/host/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(
        head.starts_with("HTTP/1.1 "),
        "expected an HTTP status line, got: {head:?}"
    );
}
