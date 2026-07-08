// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! End-to-end IPC round-trip on a temporary unix socket.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use ne_protocol::supervisor::{SupervisorRequest, SupervisorResponse};
use ne_supervisor::command::Dispatcher;
use ne_supervisor::ipc::{IpcServer, PeerAuth};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[tokio::test]
async fn ping_pong_round_trip() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let sock = tmp.path().join("supervisor.sock");

    let server = IpcServer::bind(&sock, PeerAuth::DevDisabled)
        .await
        .expect("bind server");
    let audit_dir = tempfile::tempdir().expect("audit dir");
    let audit = ne_supervisor::audit::AuditLog::open(audit_dir.path())
        .await
        .expect("audit open");
    let workspaces = Arc::new(
        ne_supervisor::workspace::WorkspaceManager::new(
            ne_supervisor::workspace::WorkspaceManagerConfig::dev_defaults(),
            audit.clone(),
            1024,
            32768,
        )
        .expect("workspace manager"),
    );
    let dispatcher = Arc::new(Dispatcher::new(workspaces, audit));
    let server_task = tokio::spawn(async move { server.serve(dispatcher).await });

    let stream = UnixStream::connect(&sock).await.expect("client connect");
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    let req = serde_json::to_vec(&SupervisorRequest::Ping).expect("serialize Ping");
    wr.write_all(&req).await.expect("write request");
    wr.write_all(b"\n").await.expect("write newline");

    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read response");
    let resp: SupervisorResponse =
        serde_json::from_str(line.trim_end()).expect("deserialize response");

    match resp {
        SupervisorResponse::Pong { version, .. } => {
            assert_eq!(version, env!("CARGO_PKG_VERSION"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    drop(wr);
    drop(reader);
    server_task.abort();
}

#[tokio::test]
async fn invalid_json_returns_error_and_keeps_connection_alive() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let sock = tmp.path().join("supervisor.sock");

    let server = IpcServer::bind(&sock, PeerAuth::DevDisabled)
        .await
        .expect("bind server");
    let audit_dir = tempfile::tempdir().expect("audit dir");
    let audit = ne_supervisor::audit::AuditLog::open(audit_dir.path())
        .await
        .expect("audit open");
    let workspaces = Arc::new(
        ne_supervisor::workspace::WorkspaceManager::new(
            ne_supervisor::workspace::WorkspaceManagerConfig::dev_defaults(),
            audit.clone(),
            1024,
            32768,
        )
        .expect("workspace manager"),
    );
    let dispatcher = Arc::new(Dispatcher::new(workspaces, audit));
    let server_task = tokio::spawn(async move { server.serve(dispatcher).await });

    let stream = UnixStream::connect(&sock).await.expect("client connect");
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    wr.write_all(b"not json at all\n").await.expect("write");
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read error");
    let resp: SupervisorResponse =
        serde_json::from_str(line.trim_end()).expect("deserialize error");
    assert!(
        matches!(resp, SupervisorResponse::Error { .. }),
        "expected Error, got {resp:?}"
    );

    // Connection still works: send a valid Ping next.
    let req = serde_json::to_vec(&SupervisorRequest::Ping).expect("serialize Ping");
    wr.write_all(&req).await.expect("write Ping");
    wr.write_all(b"\n").await.expect("write nl");
    line.clear();
    reader.read_line(&mut line).await.expect("read Pong");
    let resp: SupervisorResponse = serde_json::from_str(line.trim_end()).expect("deserialize Pong");
    assert!(
        matches!(resp, SupervisorResponse::Pong { .. }),
        "expected Pong, got {resp:?}"
    );

    drop(wr);
    drop(reader);
    server_task.abort();
}
