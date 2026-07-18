// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end gRPC integration tests: tonic client → `ne-api`
//! gRPC server → fake supervisor over UDS → response flows back
//! through both hops.
//!
//! Cross-platform — the fake supervisor is an in-process tokio task.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ne_api::core::RuntimeCore;
use ne_api::server::RuntimeService;
use ne_api::supervisor_client::SupervisorClient;
use ne_protocol::grpc::runtime::v1 as pb;
use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
use ne_protocol::grpc::runtime::v1::runtime_server::RuntimeServer;
use ne_protocol::supervisor::{
    self as sup, SupervisorErrorKind, SupervisorRequest, SupervisorResponse,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tonic::transport::Server;

#[tokio::test]
async fn ping_round_trips_through_api_and_supervisor() {
    let (client, _tmp) = stand_up_stack(|_| SupervisorResponse::Pong {
        version: "0.0.0-fake-supervisor".into(),
        uptime_ms: 99,
    })
    .await;
    let mut client = client;
    let response = client
        .ping(pb::PingRequest {})
        .await
        .expect("ping rpc")
        .into_inner();
    assert_eq!(response.supervisor_version, "0.0.0-fake-supervisor");
    assert_eq!(response.supervisor_uptime_ms, 99);
    assert_eq!(response.api_version, env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn runtime_capabilities_round_trip_with_typed_enums() {
    let capabilities =
        ne_protocol::profile::ExecutionProfile::ConfidentialAzure.capabilities("0.2.0", 1);
    let (client, _tmp) =
        stand_up_stack(move |_| SupervisorResponse::Capabilities(capabilities.clone())).await;
    let mut client = client;
    let response = client
        .get_runtime_capabilities(pb::GetRuntimeCapabilitiesRequest {})
        .await
        .expect("capabilities rpc")
        .into_inner();

    assert_eq!(response.runtime_version, "0.2.0");
    assert_eq!(
        pb::ExecutionProfile::try_from(response.execution_profile).expect("profile"),
        pb::ExecutionProfile::ConfidentialAzure
    );
    assert_eq!(
        pb::ExecutionBackend::try_from(response.execution_backend).expect("backend"),
        pb::ExecutionBackend::OpenShell
    );
    assert_eq!(
        pb::AttestationBackend::try_from(response.attestation_backend).expect("attestation"),
        pb::AttestationBackend::SevSnpAzure
    );
    assert_eq!(response.hard_workspace_capacity, Some(1));
    assert_eq!(response.evidence_schema_version, 1);
    assert!(
        response
            .supported_operations
            .contains(&(pb::WorkspaceOperation::Attest as i32))
    );
    assert!(
        !response
            .supported_operations
            .contains(&(pb::WorkspaceOperation::Snapshot as i32))
    );
}

#[tokio::test]
async fn create_workspace_round_trips_through_api_and_supervisor() {
    let (client, _tmp) = stand_up_stack(|req| match req {
        SupervisorRequest::CreateWorkspace(c) => {
            SupervisorResponse::WorkspaceCreated(sup::WorkspaceCreated {
                workspace_id: c.workspace_id,
                firecracker_pid: 7777,
                vsock_host_socket: "/srv/jailer/firecracker/x/root/vsock.sock".into(),
                jailer_chroot: "/srv/jailer/firecracker/x/root".into(),
                // E2.b note: the round-trip-with-network case is
                // covered by the in-process test in server.rs.
                // This e2e fake matches the no-network request below.
                network: None,
                exec_backend: None,
                control_socket: None,
            })
        }
        other => SupervisorResponse::Error {
            kind: SupervisorErrorKind::Internal,
            message: format!("unexpected req: {other:?}"),
        },
    })
    .await;
    let mut client = client;
    let response = client
        .create_workspace(pb::CreateWorkspaceRequest {
            workspace_id: "wks-rpc-1".into(),
            kernel_sha256: "11".repeat(32),
            rootfs_sha256: "22".repeat(32),
            rootfs_read_only: true,
            vcpu_count: 2,
            mem_size_mib: 512,
            guest_vsock_cid: 3,
            kernel_boot_args: Some("console=ttyS0 quiet".into()),
            network: None,
            tier: None,
        })
        .await
        .expect("create_workspace rpc")
        .into_inner();
    assert_eq!(response.workspace_id, "wks-rpc-1");
    assert_eq!(response.firecracker_pid, 7777);
}

#[tokio::test]
async fn destroy_workspace_round_trips_through_api_and_supervisor() {
    let (client, _tmp) = stand_up_stack(|req| match req {
        SupervisorRequest::Terminate(t) => SupervisorResponse::WorkspaceTerminated {
            workspace_id: t.workspace_id,
        },
        other => SupervisorResponse::Error {
            kind: SupervisorErrorKind::Internal,
            message: format!("unexpected req: {other:?}"),
        },
    })
    .await;
    let mut client = client;
    let response = client
        .destroy_workspace(pb::DestroyWorkspaceRequest {
            workspace_id: "wks-rpc-2".into(),
            grace_period_ms: 2_000,
        })
        .await
        .expect("destroy_workspace rpc")
        .into_inner();
    assert_eq!(response.workspace_id, "wks-rpc-2");
}

#[tokio::test]
async fn execute_command_round_trips_through_api_and_supervisor() {
    let (client, _tmp) = stand_up_stack(|req| match req {
        SupervisorRequest::RunCommand(r) => {
            SupervisorResponse::CommandCompleted(sup::CommandCompleted {
                workspace_id: r.workspace_id,
                stdout: format!("ran: {} {:?}\n", r.command, r.args),
                stderr: String::new(),
                exit_code: 0,
                elapsed_ms: 5,
                truncated: false,
            })
        }
        other => SupervisorResponse::Error {
            kind: SupervisorErrorKind::Internal,
            message: format!("unexpected req: {other:?}"),
        },
    })
    .await;
    let mut client = client;
    let response = client
        .execute_command(pb::ExecuteCommandRequest {
            workspace_id: "wks-rpc-exec-1".into(),
            command: "/bin/echo".into(),
            args: vec!["hello, enclave".into()],
            timeout_ms: 5_000,
            guest_port: 52,
        })
        .await
        .expect("execute_command rpc")
        .into_inner();
    assert_eq!(response.workspace_id, "wks-rpc-exec-1");
    assert_eq!(response.exit_code, 0);
    assert!(response.stdout.contains("hello, enclave"));
}

#[tokio::test]
async fn destroy_workspace_surfaces_not_found_as_grpc_not_found() {
    let (client, _tmp) = stand_up_stack(|_| SupervisorResponse::Error {
        kind: SupervisorErrorKind::WorkspaceNotFound,
        message: "no such workspace".into(),
    })
    .await;
    let mut client = client;
    let err = client
        .destroy_workspace(pb::DestroyWorkspaceRequest {
            workspace_id: "wks-ghost".into(),
            grace_period_ms: 1_000,
        })
        .await
        .expect_err("expected gRPC error");
    assert_eq!(err.code(), tonic::Code::NotFound);
}

/// Spin up the fake supervisor + the API daemon, then return a
/// connected tonic client. The tempdir lives as long as the caller
/// holds the returned tuple.
async fn stand_up_stack<F>(
    responder: F,
) -> (RuntimeClient<tonic::transport::Channel>, tempfile::TempDir)
where
    F: Fn(SupervisorRequest) -> SupervisorResponse + Send + Sync + 'static,
{
    let tmp = tempfile::tempdir().expect("tmpdir");
    let sup_sock = tmp.path().join("sup.sock");
    spawn_fake_supervisor(sup_sock.clone(), responder);

    let port = find_free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr parse");
    let core = Arc::new(RuntimeCore::new(SupervisorClient::new(PathBuf::from(
        &sup_sock,
    ))));
    let svc = RuntimeService::new(core);
    tokio::spawn(async move {
        Server::builder()
            .add_service(RuntimeServer::new(svc))
            .serve(addr)
            .await
    });

    wait_for_listener(&format!("127.0.0.1:{port}"), Duration::from_secs(2)).await;
    let client = RuntimeClient::connect(format!("http://127.0.0.1:{port}"))
        .await
        .expect("tonic client connect");
    (client, tmp)
}

fn find_free_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind 0");
    listener.local_addr().expect("local_addr").port()
}

async fn wait_for_listener(addr: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("server never started accepting connections on {addr}");
}

fn spawn_fake_supervisor<F>(socket: PathBuf, responder: F)
where
    F: Fn(SupervisorRequest) -> SupervisorResponse + Send + Sync + 'static,
{
    let listener = UnixListener::bind(&socket).expect("bind fake supervisor");
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
                let req: SupervisorRequest = match serde_json::from_str(line.trim_end()) {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let resp = responder(req);
                let mut body = serde_json::to_vec(&resp).expect("ser");
                body.push(b'\n');
                let _ = wr.write_all(&body).await;
            });
        }
    });
}
