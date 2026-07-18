// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end TCP test for the privacy-router HTTP proxy.
//!
//! Spins up an ephemeral upstream that echoes the body it receives,
//! spawns the proxy in front of it, then drives requests through the
//! proxy via a real hyper-util client. Three scenarios:
//!
//! 1. Clean body — proxy forwards unchanged; upstream sees the original
//!    bytes and the client gets a 200.
//! 2. Body containing an SSN under a redact policy — upstream sees a
//!    redacted body that no longer contains the raw SSN; client gets
//!    a 200.
//! 3. Body containing an SSN under a block policy — proxy short-circuits
//!    with 403 and the upstream is never called.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ne_privacy_router::PiiEngine;
use ne_privacy_router::proxy::{DEFAULT_MAX_BODY_BYTES, ProxyState, serve};
use ne_privacy_router::{EntityType, PiiAction, PiiPolicy};
use tokio::net::TcpListener;

/// Spawn a tiny upstream that records every received body and echoes
/// it in a JSON envelope. Returns the bound address and the shared
/// vector of received bodies.
async fn spawn_echo_upstream() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received_for_task = received.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let received = received_for_task.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let received = received.clone();
                    async move {
                        let body = req
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes)
                            .unwrap_or_default();
                        received.lock().unwrap().push(body.to_vec());
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
                            .unwrap();
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    (addr, received)
}

/// Spawn the proxy with the given engine on an ephemeral port.
async fn spawn_proxy(engine: PiiEngine) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(ProxyState::new(Arc::new(engine), DEFAULT_MAX_BODY_BYTES));
    tokio::spawn(async move {
        let _ = serve(listener, state).await;
    });
    addr
}

fn engine_with(enforcement: &str, overrides: &[(EntityType, PiiAction)]) -> PiiEngine {
    let mut entities = HashMap::new();
    for (et, action) in overrides {
        entities.insert(*et, *action);
    }
    let policy = PiiPolicy {
        enforcement: enforcement.to_string(),
        entities,
        ..PiiPolicy::default()
    };
    PiiEngine::new(&policy)
}

/// Send a POST through the proxy with `Host:` set to the upstream addr.
async fn post_through_proxy(
    proxy: SocketAddr,
    upstream: SocketAddr,
    body: &'static [u8],
) -> (StatusCode, Vec<u8>) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let uri = format!("http://{proxy}/v1/anything");
    let req = Request::builder()
        .method("POST")
        .uri(&uri)
        .header("host", upstream.to_string())
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from_static(body)))
        .unwrap();
    let resp = client.request(req).await.expect("proxy request");
    let status = resp.status();
    let resp_body = resp
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    (status, resp_body.to_vec())
}

#[tokio::test]
async fn clean_body_forwards_unchanged() {
    let (upstream_addr, received) = spawn_echo_upstream().await;
    let proxy_addr = spawn_proxy(engine_with("redact", &[])).await;

    let (status, _resp_body) =
        post_through_proxy(proxy_addr, upstream_addr, b"plain text with no pii").await;

    assert_eq!(status, StatusCode::OK);
    let received = received.lock().unwrap();
    assert_eq!(
        received.len(),
        1,
        "upstream should have received exactly one request"
    );
    assert_eq!(received[0], b"plain text with no pii");
}

#[tokio::test]
async fn body_with_ssn_is_redacted_before_forwarding() {
    let (upstream_addr, received) = spawn_echo_upstream().await;
    let proxy_addr = spawn_proxy(engine_with("redact", &[])).await;

    let (status, _resp_body) = post_through_proxy(
        proxy_addr,
        upstream_addr,
        b"my ssn is 123-45-6789, take care",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let received = received.lock().unwrap();
    assert_eq!(
        received.len(),
        1,
        "upstream should have received one request"
    );
    let body = std::str::from_utf8(&received[0]).unwrap();
    assert!(
        !body.contains("123-45-6789"),
        "raw SSN leaked to upstream: {body}"
    );
}

#[tokio::test]
async fn body_with_ssn_under_block_policy_short_circuits_with_403() {
    let (upstream_addr, received) = spawn_echo_upstream().await;
    let proxy_addr = spawn_proxy(engine_with("block", &[])).await;

    let (status, resp_body) =
        post_through_proxy(proxy_addr, upstream_addr, b"my ssn is 123-45-6789").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        received.lock().unwrap().is_empty(),
        "upstream should NOT have been called on block"
    );
    let body = std::str::from_utf8(&resp_body).unwrap();
    assert!(
        body.contains("pii_blocked"),
        "block response missing pii_blocked code: {body}"
    );
}

#[tokio::test]
async fn missing_host_header_returns_400() {
    // The proxy depends on Host: to recover the destination. A request
    // without one is malformed in our model and should be rejected
    // before any forward attempt.
    let proxy_addr = spawn_proxy(engine_with("audit", &[])).await;

    // hyper insists on setting a Host header when we use a normal
    // builder; build the request manually with the URI as authority
    // and then strip Host on the wire by using uri with no authority.
    // Simpler: skip this test if the client always sets Host. We
    // approximate by sending a request whose Host header value is
    // empty, which our handler rejects equivalently.
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let uri = format!("http://{proxy_addr}/");
    let req = Request::builder()
        .method("POST")
        .uri(&uri)
        .header("host", "")
        .body(Full::new(Bytes::from_static(b"hi")))
        .unwrap();
    let resp = client.request(req).await.expect("proxy request");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
