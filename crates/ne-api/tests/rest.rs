// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! In-process REST route tests via `tower::ServiceExt::oneshot` (no
//! socket bind — runs in the sandbox) plus one `#[ignore]`d serve-wiring
//! smoke test that binds a real ephemeral TCP port.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ne_api::core::RuntimeCore;
use ne_api::rest::router;
use ne_api::supervisor_client::SupervisorClient;
use ne_protocol::supervisor::{SupervisorErrorKind, SupervisorRequest, SupervisorResponse};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tower::ServiceExt; // for `oneshot`

/// Spawns an in-process NDJSON supervisor and returns a router wired to
/// it. `responder` decides each reply.
fn app_with<F>(responder: F) -> (axum::Router, tempfile::TempDir)
where
    F: Fn(SupervisorRequest) -> SupervisorResponse + Send + Sync + 'static,
{
    let (tmp, path) = spawn_fake_supervisor(responder);
    let core = Arc::new(RuntimeCore::new(SupervisorClient::new(path)));
    (router(core), tmp)
}

fn spawn_fake_supervisor<F>(responder: F) -> (tempfile::TempDir, PathBuf)
where
    F: Fn(SupervisorRequest) -> SupervisorResponse + Send + Sync + 'static,
{
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("super.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let responder = Arc::new(responder);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let responder = Arc::clone(&responder);
            tokio::spawn(async move {
                let (rd, mut wr) = stream.into_split();
                let mut reader = BufReader::new(rd);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_err() {
                    return;
                }
                let Ok(req) = serde_json::from_str::<SupervisorRequest>(line.trim_end()) else {
                    return;
                };
                let resp = responder(req);
                let mut body = serde_json::to_vec(&resp).expect("ser");
                body.push(b'\n');
                let _ = wr.write_all(&body).await;
            });
        }
    });
    (tmp, path)
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn health_returns_ping_payload() {
    let (app, _tmp) = app_with(|_| SupervisorResponse::Pong {
        version: "9.9-fake".into(),
        uptime_ms: 5,
    });
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/host/health")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["supervisor_version"], "9.9-fake");
    assert_eq!(json["supervisor_uptime_ms"], 5);
}

#[tokio::test]
async fn runtime_capabilities_return_the_profile_contract() {
    let capabilities =
        ne_protocol::profile::ExecutionProfile::ConfidentialAzure.capabilities("0.2.0", 1);
    let (app, _tmp) = app_with(move |_| SupervisorResponse::Capabilities(capabilities.clone()));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/runtime/capabilities")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["runtime_version"], "0.2.0");
    assert_eq!(json["execution_profile"], "confidential-azure");
    assert_eq!(json["execution_backend"], "open_shell");
    assert_eq!(json["attestation_backend"], "sev_snp_azure");
    assert_eq!(json["hard_workspace_capacity"], 1);
    assert_eq!(json["evidence_schema_version"], 1);
    assert!(
        json["supported_operations"]
            .as_array()
            .expect("operations")
            .contains(&serde_json::json!("attest"))
    );
    assert!(
        !json["supported_operations"]
            .as_array()
            .expect("operations")
            .contains(&serde_json::json!("snapshot"))
    );
}

#[tokio::test]
async fn supervisor_error_maps_to_status_and_code() {
    let (app, _tmp) = app_with(|_| SupervisorResponse::Error {
        kind: SupervisorErrorKind::WorkspaceNotFound,
        message: "ghost".into(),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/host/health")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "WORKSPACE_NOT_FOUND");
}

#[tokio::test]
async fn create_workspace_returns_201() {
    use ne_protocol::supervisor as sup;
    let (app, _tmp) = app_with(|req| match req {
        SupervisorRequest::CreateWorkspace(c) => {
            SupervisorResponse::WorkspaceCreated(sup::WorkspaceCreated {
                workspace_id: c.workspace_id,
                firecracker_pid: 4242,
                vsock_host_socket: "/x/vsock.sock".into(),
                jailer_chroot: "/x".into(),
                network: None,
                exec_backend: None,
                control_socket: None,
            })
        }
        _ => SupervisorResponse::Error {
            kind: SupervisorErrorKind::Internal,
            message: "no".into(),
        },
    });
    let payload = serde_json::json!({
        "workspace_id": "wks-1",
        "kernel_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        "rootfs_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
        "rootfs_read_only": true,
        "vcpu_count": 1,
        "mem_size_mib": 256,
        "guest_vsock_cid": 3
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/workspaces")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).expect("ser")))
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    assert_eq!(json["firecracker_pid"], 4242);
    assert_eq!(json["workspace_id"], "wks-1");
}

#[tokio::test]
async fn create_workspace_zero_vcpu_is_400() {
    let (app, _tmp) = app_with(|_| SupervisorResponse::Error {
        kind: SupervisorErrorKind::InvalidRequest,
        message: "standard creates require vcpu_count >= 1".into(),
    });
    let payload = serde_json::json!({
        "workspace_id": "w",
        "kernel_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        "rootfs_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
        "rootfs_read_only": true,
        "vcpu_count": 0,
        "mem_size_mib": 256,
        "guest_vsock_cid": 3
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/workspaces")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).expect("ser")))
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "INVALID_REQUEST");
}

#[tokio::test]
async fn destroy_workspace_returns_id() {
    let (app, _tmp) = app_with(|req| match req {
        SupervisorRequest::Terminate(t) => SupervisorResponse::WorkspaceTerminated {
            workspace_id: t.workspace_id,
        },
        _ => SupervisorResponse::Error {
            kind: SupervisorErrorKind::Internal,
            message: "no".into(),
        },
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/workspaces/wks-9?grace_period_ms=500")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["workspace_id"], "wks-9");
}

#[tokio::test]
async fn exec_returns_command_result() {
    use ne_protocol::supervisor as sup;
    let (app, _tmp) = app_with(|req| match req {
        SupervisorRequest::RunCommand(r) => {
            assert_eq!(r.guest_port, 52, "default guest port");
            SupervisorResponse::CommandCompleted(sup::CommandCompleted {
                workspace_id: r.workspace_id,
                stdout: "hello\n".into(),
                stderr: String::new(),
                exit_code: 0,
                elapsed_ms: 2,
                truncated: false,
            })
        }
        _ => SupervisorResponse::Error {
            kind: SupervisorErrorKind::Internal,
            message: "no".into(),
        },
    });
    let payload =
        serde_json::json!({ "command": "/bin/echo", "args": ["hello"], "timeout_ms": 1000 });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/workspaces/w1/exec")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).expect("ser")))
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["exit_code"], 0);
    assert_eq!(json["stdout"], "hello\n");
}

#[tokio::test]
async fn write_then_read_file_roundtrips_base64() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use ne_protocol::supervisor as sup;

    // Write path: assert the supervisor receives the decoded bytes.
    let (app, _tmp) = app_with(|req| match req {
        SupervisorRequest::WriteFile(c) => {
            assert_eq!(c.content, b"fn main() {}");
            SupervisorResponse::FileWritten(sup::FileWritten {
                workspace_id: c.workspace_id,
                bytes_written: c.content.len() as u64,
                absolute_path: "/workspace/src/main.rs".into(),
            })
        }
        _ => SupervisorResponse::Error {
            kind: SupervisorErrorKind::Internal,
            message: "no".into(),
        },
    });
    let payload = serde_json::json!({
        "path": "src/main.rs",
        "content": B64.encode(b"fn main() {}")
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/workspaces/w1/files")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).expect("ser")))
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["bytes_written"], 12);

    // Read path: supervisor returns bytes; REST must base64-encode them.
    let (app2, _tmp2) = app_with(|req| match req {
        SupervisorRequest::ReadFile(c) => SupervisorResponse::FileRead(sup::FileRead {
            workspace_id: c.workspace_id,
            content: b"line1\n".to_vec(),
            size_bytes: 6,
            truncated: false,
        }),
        _ => SupervisorResponse::Error {
            kind: SupervisorErrorKind::Internal,
            message: "no".into(),
        },
    });
    let resp2 = app2
        .oneshot(
            Request::builder()
                .uri("/v1/workspaces/w1/files?path=out/log.txt")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp2.status(), StatusCode::OK);
    let json2 = body_json(resp2).await;
    assert_eq!(json2["size_bytes"], 6);
    let decoded = B64
        .decode(json2["content"].as_str().expect("content str"))
        .expect("b64");
    assert_eq!(decoded, b"line1\n");
}

#[tokio::test]
async fn write_file_invalid_base64_is_400() {
    let (app, _tmp) = app_with(|_| SupervisorResponse::Pong {
        version: "x".into(),
        uptime_ms: 0,
    });
    let payload = serde_json::json!({ "path": "f", "content": "not valid base64 !!!" });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/workspaces/w1/files")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).expect("ser")))
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "VALIDATION");
}

#[tokio::test]
async fn list_events_filters_by_workspace() {
    use ne_protocol::audit;
    let (app, _tmp) = app_with(|req| match req {
        SupervisorRequest::ListEvents(r) => {
            assert_eq!(r.workspace_id.as_deref(), Some("w1"));
            assert_eq!(r.since_chain_index, 3);
            SupervisorResponse::Events(audit::ListEventsResponse { events: vec![] })
        }
        _ => SupervisorResponse::Error {
            kind: SupervisorErrorKind::Internal,
            message: "no".into(),
        },
    });
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/events?workspace_id=w1&since_chain_index=3&limit=10")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["events"].as_array().expect("events array").is_empty());
}

/// Serve-wiring smoke test: binds a real ephemeral TCP port, serves the
/// REST router, and drives `GET /v1/host/health` over a raw `TcpStream`
/// (no HTTP-client dep). Binds a socket → must run sandbox-disabled:
/// `cargo test -p ne-api --test rest -- --ignored`.
#[tokio::test]
#[ignore = "binds a TCP port; run sandbox-disabled / in CI"]
async fn serve_wiring_health_over_real_socket() {
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    let (app, _tmp) = app_with(|_| SupervisorResponse::Pong {
        version: "smoke".into(),
        uptime_ms: 1,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET /v1/host/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "status line was: {:?}",
        text.lines().next()
    );
    assert!(
        text.contains("\"supervisor_version\":\"smoke\""),
        "body missing payload"
    );
}
