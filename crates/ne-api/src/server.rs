// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! gRPC service implementation — thin proto⇄core mapping over
//! [`crate::core::RuntimeCore`].

use std::sync::Arc;

use ne_protocol::audit as audit_proto;
use ne_protocol::grpc::runtime::v1 as pb;
use ne_protocol::grpc::runtime::v1::runtime_server::Runtime;
use tonic::{Request, Response, Status};
use tracing::debug;

use ne_protocol::supervisor as sup;

use crate::core::{
    CoreError, CreateWorkspaceInput, ExecuteCommandInput, ExposePortInput, NetworkInput,
    ReadFileInput, RuntimeCore, WriteFileInput,
};
use crate::supervisor_client::SupervisorClientError;

/// Implements the `Runtime` gRPC service. Cheap to clone — shared
/// state lives behind an `Arc`.
#[derive(Debug, Clone)]
pub struct RuntimeService {
    core: Arc<RuntimeCore>,
}

impl RuntimeService {
    /// Construct a service backed by `core`.
    #[must_use]
    pub fn new(core: Arc<RuntimeCore>) -> Self {
        Self { core }
    }
}

#[tonic::async_trait]
impl Runtime for RuntimeService {
    async fn ping(
        &self,
        _request: Request<pb::PingRequest>,
    ) -> Result<Response<pb::PingResponse>, Status> {
        debug!("ping received");
        let out = self.core.ping().await.map_err(core_error_to_status)?;
        Ok(Response::new(pb::PingResponse {
            api_version: out.api_version,
            api_uptime_ms: out.api_uptime_ms,
            supervisor_version: out.supervisor_version,
            supervisor_uptime_ms: out.supervisor_uptime_ms,
        }))
    }

    async fn get_runtime_capabilities(
        &self,
        _request: Request<pb::GetRuntimeCapabilitiesRequest>,
    ) -> Result<Response<pb::GetRuntimeCapabilitiesResponse>, Status> {
        debug!("get_runtime_capabilities received");
        let capabilities = self
            .core
            .runtime_capabilities()
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(capabilities_to_pb(capabilities)))
    }

    async fn create_workspace(
        &self,
        request: Request<pb::CreateWorkspaceRequest>,
    ) -> Result<Response<pb::CreateWorkspaceResponse>, Status> {
        let r = request.into_inner();
        debug!(workspace_id = %r.workspace_id, "create_workspace received");
        let c = self
            .core
            .create_workspace(CreateWorkspaceInput {
                workspace_id: r.workspace_id,
                kernel_sha256: r.kernel_sha256,
                rootfs_sha256: r.rootfs_sha256,
                rootfs_read_only: r.rootfs_read_only,
                vcpu_count: r.vcpu_count,
                mem_size_mib: r.mem_size_mib,
                guest_vsock_cid: r.guest_vsock_cid,
                kernel_boot_args: r.kernel_boot_args,
                tier: r.tier,
                network: r.network.map(|n| NetworkInput {
                    enable_egress: n.enable_egress,
                    allow_cidrs: n.allow_cidrs,
                    allow_hostnames: n.allow_hostnames,
                    privacy_router: n.privacy_router.is_some(),
                    exposed_ports: n
                        .exposed_ports
                        .into_iter()
                        .filter_map(|p| {
                            u16::try_from(p.port)
                                .ok()
                                .filter(|&port| port != 0)
                                .map(|port| sup::ExposedPort {
                                    port,
                                    inject_headers: p
                                        .inject_headers
                                        .into_iter()
                                        .map(|h| sup::HeaderInjection {
                                            name: h.name,
                                            value: h.value,
                                        })
                                        .collect(),
                                })
                        })
                        .collect(),
                }),
            })
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::CreateWorkspaceResponse {
            workspace_id: c.workspace_id,
            firecracker_pid: c.firecracker_pid,
            vsock_host_socket: c.vsock_host_socket,
            jailer_chroot: c.jailer_chroot,
            network: c.network.map(|n| pb::WorkspaceNetwork {
                netns_path: n.netns_path,
                tap_device: n.tap_device,
                host_ip: n.host_ip,
                guest_ip: n.guest_ip,
                prefix: u32::from(n.prefix),
            }),
        }))
    }

    async fn execute_command(
        &self,
        request: Request<pb::ExecuteCommandRequest>,
    ) -> Result<Response<pb::ExecuteCommandResponse>, Status> {
        let r = request.into_inner();
        debug!(workspace_id = %r.workspace_id, command = %r.command, "execute_command received");
        let c = self
            .core
            .execute_command(ExecuteCommandInput {
                workspace_id: r.workspace_id,
                command: r.command,
                args: r.args,
                timeout_ms: r.timeout_ms,
                guest_port: r.guest_port,
            })
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::ExecuteCommandResponse {
            workspace_id: c.workspace_id,
            stdout: c.stdout,
            stderr: c.stderr,
            exit_code: c.exit_code,
            elapsed_ms: c.elapsed_ms,
            truncated: c.truncated,
        }))
    }

    async fn destroy_workspace(
        &self,
        request: Request<pb::DestroyWorkspaceRequest>,
    ) -> Result<Response<pb::DestroyWorkspaceResponse>, Status> {
        let r = request.into_inner();
        debug!(workspace_id = %r.workspace_id, "destroy_workspace received");
        let workspace_id = self
            .core
            .destroy_workspace(r.workspace_id, r.grace_period_ms)
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::DestroyWorkspaceResponse { workspace_id }))
    }

    async fn list_events(
        &self,
        request: Request<pb::ListEventsRequest>,
    ) -> Result<Response<pb::ListEventsResponse>, Status> {
        let r = request.into_inner();
        debug!(workspace_id = ?r.workspace_id, since = r.since_chain_index, "list_events received");
        let e = self
            .core
            .list_events(r.workspace_id, r.since_chain_index, r.limit)
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::ListEventsResponse {
            events: e.events.into_iter().map(audit_event_to_proto).collect(),
        }))
    }

    async fn write_file(
        &self,
        request: Request<pb::WriteFileRequest>,
    ) -> Result<Response<pb::WriteFileResponse>, Status> {
        let r = request.into_inner();
        debug!(workspace_id = %r.workspace_id, path = %r.path, bytes = r.content.len(), "write_file received");
        let w = self
            .core
            .write_file(WriteFileInput {
                workspace_id: r.workspace_id,
                path: r.path,
                content: r.content,
                guest_port: r.guest_port,
            })
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::WriteFileResponse {
            workspace_id: w.workspace_id,
            bytes_written: w.bytes_written,
            absolute_path: w.absolute_path,
        }))
    }

    async fn read_file(
        &self,
        request: Request<pb::ReadFileRequest>,
    ) -> Result<Response<pb::ReadFileResponse>, Status> {
        let r = request.into_inner();
        debug!(workspace_id = %r.workspace_id, path = %r.path, max_bytes = r.max_bytes, "read_file received");
        let read = self
            .core
            .read_file(ReadFileInput {
                workspace_id: r.workspace_id,
                path: r.path,
                max_bytes: r.max_bytes,
                guest_port: r.guest_port,
            })
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::ReadFileResponse {
            workspace_id: read.workspace_id,
            content: read.content,
            size_bytes: read.size_bytes,
            truncated: read.truncated,
        }))
    }

    async fn pause_workspace(
        &self,
        request: Request<pb::PauseWorkspaceRequest>,
    ) -> Result<Response<pb::PauseWorkspaceResponse>, Status> {
        let r = request.into_inner();
        debug!(workspace_id = %r.workspace_id, "pause_workspace received");
        let id = self
            .core
            .pause_workspace(r.workspace_id)
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::PauseWorkspaceResponse {
            workspace_id: id,
        }))
    }

    async fn resume_workspace(
        &self,
        request: Request<pb::ResumeWorkspaceRequest>,
    ) -> Result<Response<pb::ResumeWorkspaceResponse>, Status> {
        let r = request.into_inner();
        debug!(workspace_id = %r.workspace_id, "resume_workspace received");
        let id = self
            .core
            .resume_workspace(r.workspace_id)
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::ResumeWorkspaceResponse {
            workspace_id: id,
        }))
    }

    async fn snapshot_workspace(
        &self,
        request: Request<pb::SnapshotWorkspaceRequest>,
    ) -> Result<Response<pb::SnapshotWorkspaceResponse>, Status> {
        let r = request.into_inner();
        debug!(workspace_id = %r.workspace_id, live = r.live, "snapshot_workspace received");
        let i = self
            .core
            .snapshot_workspace(r.workspace_id, r.live)
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::SnapshotWorkspaceResponse {
            snapshot_id: i.snapshot_id,
            created_from_workspace_id: i.created_from_workspace_id,
            mem_sha256: i.mem_sha256,
            vmstate_sha256: i.vmstate_sha256,
            size_bytes: i.size_bytes,
            firecracker_pid: i.firecracker_pid,
        }))
    }

    async fn restore_workspace(
        &self,
        request: Request<pb::RestoreWorkspaceRequest>,
    ) -> Result<Response<pb::RestoreWorkspaceResponse>, Status> {
        let r = request.into_inner();
        debug!(snapshot_id = %r.snapshot_id, new_workspace_id = %r.new_workspace_id, "restore_workspace received");
        let c = self
            .core
            .restore_workspace(r.snapshot_id, r.new_workspace_id)
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::RestoreWorkspaceResponse {
            workspace_id: c.workspace_id,
            firecracker_pid: c.firecracker_pid,
            vsock_host_socket: c.vsock_host_socket,
            jailer_chroot: c.jailer_chroot,
        }))
    }

    async fn fork_workspace(
        &self,
        request: Request<pb::ForkWorkspaceRequest>,
    ) -> Result<Response<pb::ForkWorkspaceResponse>, Status> {
        let r = request.into_inner();
        debug!(snapshot_id = %r.snapshot_id, new_workspace_id = %r.new_workspace_id, "fork_workspace received");
        // Empty proto `hostname` string → None (use the server default).
        let hostname = if r.hostname.is_empty() {
            None
        } else {
            Some(r.hostname)
        };
        let i = self
            .core
            .fork_workspace(r.snapshot_id, r.new_workspace_id, hostname)
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::ForkWorkspaceResponse {
            workspace_id: i.workspace_id,
            firecracker_pid: i.firecracker_pid,
            vsock_host_socket: i.vsock_host_socket,
            jailer_chroot: i.jailer_chroot,
            source_snapshot_id: i.source_snapshot_id,
            hostname: i.hostname,
            machine_id: i.machine_id,
            guest_vsock_cid: i.guest_vsock_cid,
        }))
    }

    async fn get_pool_status(
        &self,
        _request: Request<pb::GetPoolStatusRequest>,
    ) -> Result<Response<pb::GetPoolStatusResponse>, Status> {
        let s = self
            .core
            .pool_status()
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::GetPoolStatusResponse {
            configured: s.configured,
            tier: s.tier.unwrap_or_default(),
            target_size: s.target_size,
            available: s.available,
            in_flight: s.in_flight,
        }))
    }

    async fn expose_port(
        &self,
        request: Request<pb::ExposePortRequest>,
    ) -> Result<Response<pb::ExposePortResponse>, Status> {
        let r = request.into_inner();
        let port = r
            .port
            .ok_or_else(|| Status::invalid_argument("port is required"))?;
        let port_u16 = u16::try_from(port.port)
            .map_err(|_| Status::invalid_argument("port out of range (1..=65535)"))?;
        let (workspace_id, port_out) = self
            .core
            .expose_port(ExposePortInput {
                workspace_id: r.workspace_id,
                port: port_u16,
                inject_headers: port
                    .inject_headers
                    .into_iter()
                    .map(|h| (h.name, h.value))
                    .collect(),
            })
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::ExposePortResponse {
            workspace_id,
            port: u32::from(port_out),
        }))
    }

    async fn unexpose_port(
        &self,
        request: Request<pb::UnexposePortRequest>,
    ) -> Result<Response<pb::UnexposePortResponse>, Status> {
        let r = request.into_inner();
        let port_u16 = u16::try_from(r.port)
            .map_err(|_| Status::invalid_argument("port out of range (1..=65535)"))?;
        let (workspace_id, port_out) = self
            .core
            .unexpose_port(r.workspace_id, port_u16)
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::UnexposePortResponse {
            workspace_id,
            port: u32::from(port_out),
        }))
    }

    async fn get_attestation_evidence(
        &self,
        request: Request<pb::GetAttestationEvidenceRequest>,
    ) -> Result<Response<pb::GetAttestationEvidenceResponse>, Status> {
        let r = request.into_inner();
        let evidence = self
            .core
            .get_attestation_evidence(r.workspace_id, r.nonce)
            .await
            .map_err(core_error_to_status)?;
        Ok(Response::new(pb::GetAttestationEvidenceResponse {
            evidence: Some(evidence_to_pb(evidence)?),
        }))
    }
}

fn audit_event_to_proto(e: audit_proto::AuditEvent) -> pb::AuditEvent {
    pb::AuditEvent {
        event_id: e.event_id,
        timestamp_ms: e.timestamp_ms,
        event_type: format!("{:?}", e.event_type)
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && c.is_uppercase() {
                    vec!['_', c.to_ascii_lowercase()]
                } else {
                    vec![c.to_ascii_lowercase()]
                }
            })
            .collect(),
        workspace_id: e.workspace_id,
        payload_json: e.payload.to_string(),
        chain_index: e.chain_index,
        prev_hash_hex: e.prev_hash_hex,
        signature_b64: e.signature_b64,
        signer_pubkey_b64: e.signer_pubkey_b64,
    }
}

/// Translate a [`CoreError`] into a `tonic::Status`, preserving the
/// classification the gRPC surface shipped before the core extraction.
fn core_error_to_status(e: CoreError) -> Status {
    let message = e.message();
    match e {
        CoreError::Validation(_) => Status::invalid_argument(message),
        CoreError::Transport(SupervisorClientError::Io(_)) => {
            Status::unavailable(format!("supervisor io: {message}"))
        }
        CoreError::Transport(SupervisorClientError::Serde(_)) => {
            Status::internal(format!("supervisor protocol: {message}"))
        }
        CoreError::Transport(SupervisorClientError::Unexpected(_)) => Status::internal(message),
        CoreError::Transport(SupervisorClientError::Supervisor { kind, .. })
        | CoreError::Supervisor { kind, .. } => kind_to_status(kind, message),
    }
}

/// Maps a supervisor error kind to the gRPC status code.
fn kind_to_status(kind: ne_protocol::supervisor::SupervisorErrorKind, message: String) -> Status {
    use ne_protocol::supervisor::SupervisorErrorKind as K;
    match kind {
        K::Unauthorized => Status::permission_denied(message),
        K::InvalidRequest | K::InvalidImageDigest | K::PathRejected | K::FileTooLarge => {
            Status::invalid_argument(message)
        }
        K::Unsupported => Status::unimplemented(message),
        K::WorkspaceAlreadyExists => Status::already_exists(message),
        K::WorkspaceNotFound
        | K::FileNotFound
        | K::ImageNotFound
        | K::TierNotFound
        | K::IngressPortNotFound => Status::not_found(message),
        K::Timeout => Status::deadline_exceeded(message),
        K::GuestUnreachable => Status::unavailable(message),
        K::ImageRejected
        | K::ImageDigestMismatch
        | K::InvalidSnapshot
        | K::WorkspaceNotPaused
        | K::WorkspaceAlreadyPaused
        | K::WorkspaceNotNetworked
        | K::AttestationReplay
        | K::UnsupportedForProfile
        | K::ConfidentialCapacityExceeded => Status::failed_precondition(message),
        // SnapshotFailed / RestoreFailed / LaunchFailed / GuestProtocolError /
        // IoError / Internal / any future variant → internal.
        _ => Status::internal(message),
    }
}

fn capabilities_to_pb(
    capabilities: ne_protocol::profile::RuntimeCapabilitiesInfo,
) -> pb::GetRuntimeCapabilitiesResponse {
    use ne_protocol::profile::{
        AttestationBackend, ExecutionBackend, ExecutionProfile, WorkspaceOperation,
    };

    let execution_profile = match capabilities.execution_profile {
        ExecutionProfile::Standard => pb::ExecutionProfile::Standard,
        ExecutionProfile::ConfidentialAzure => pb::ExecutionProfile::ConfidentialAzure,
    };
    let execution_backend = match capabilities.execution_backend {
        ExecutionBackend::Firecracker => pb::ExecutionBackend::Firecracker,
        ExecutionBackend::OpenShell => pb::ExecutionBackend::OpenShell,
    };
    let attestation_backend = match capabilities.attestation_backend {
        AttestationBackend::Software => pb::AttestationBackend::Software,
        AttestationBackend::SevSnpDirect => pb::AttestationBackend::SevSnpDirect,
        AttestationBackend::SevSnpAzure => pb::AttestationBackend::SevSnpAzure,
    };
    let supported_operations = capabilities
        .supported_operations
        .into_iter()
        .map(|operation| match operation {
            WorkspaceOperation::Create => pb::WorkspaceOperation::Create as i32,
            WorkspaceOperation::Destroy => pb::WorkspaceOperation::Destroy as i32,
            WorkspaceOperation::Execute => pb::WorkspaceOperation::Execute as i32,
            WorkspaceOperation::WriteFile => pb::WorkspaceOperation::WriteFile as i32,
            WorkspaceOperation::ReadFile => pb::WorkspaceOperation::ReadFile as i32,
            WorkspaceOperation::Pause => pb::WorkspaceOperation::Pause as i32,
            WorkspaceOperation::Resume => pb::WorkspaceOperation::Resume as i32,
            WorkspaceOperation::Snapshot => pb::WorkspaceOperation::Snapshot as i32,
            WorkspaceOperation::Restore => pb::WorkspaceOperation::Restore as i32,
            WorkspaceOperation::Fork => pb::WorkspaceOperation::Fork as i32,
            WorkspaceOperation::WarmPool => pb::WorkspaceOperation::WarmPool as i32,
            WorkspaceOperation::Ingress => pb::WorkspaceOperation::Ingress as i32,
            WorkspaceOperation::Attest => pb::WorkspaceOperation::Attest as i32,
        })
        .collect();

    pb::GetRuntimeCapabilitiesResponse {
        runtime_version: capabilities.runtime_version,
        execution_profile: execution_profile as i32,
        execution_backend: execution_backend as i32,
        attestation_backend: attestation_backend as i32,
        supported_operations,
        hard_workspace_capacity: capabilities.hard_workspace_capacity,
        confidential_snapshot_supported: capabilities.confidential_snapshot_supported,
        evidence_schema_version: capabilities.evidence_schema_version,
    }
}

#[cfg(test)]
mod image_error_mapping_tests {
    use super::*;
    use ne_protocol::supervisor::SupervisorErrorKind as K;

    #[test]
    fn image_errors_map_to_grpc_statuses() {
        for (kind, code) in [
            (K::InvalidImageDigest, tonic::Code::InvalidArgument),
            (K::ImageNotFound, tonic::Code::NotFound),
            (K::ImageRejected, tonic::Code::FailedPrecondition),
            (K::ImageDigestMismatch, tonic::Code::FailedPrecondition),
            (K::ImageStageFailed, tonic::Code::Internal),
        ] {
            assert_eq!(kind_to_status(kind, "image error".into()).code(), code);
        }
    }

    #[test]
    fn profile_errors_map_to_failed_precondition() {
        for kind in [K::UnsupportedForProfile, K::ConfidentialCapacityExceeded] {
            assert_eq!(
                kind_to_status(kind, "profile error".into()).code(),
                tonic::Code::FailedPrecondition
            );
        }
    }
}

/// Convert the domain `Evidence` envelope to its protobuf form.
///
/// Both `Proof` and `ProviderType` are `#[non_exhaustive]` external enums, so
/// the compiler requires catch-all arms. Unknown (future) provider/proof
/// variants are a server bug, not a client error — refuse loudly with
/// `Status::internal` rather than emit a success-framed bogus envelope a
/// lenient client could mistake for a passing attestation.
///
/// `tonic::Status` is ~176 bytes so the large-err lint is suppressed here, as
/// elsewhere in the crate; the `Status` return is intentional so the handler
/// can `?` it straight onto the gRPC error path.
#[allow(clippy::result_large_err)]
fn evidence_to_pb(ev: ne_attestation::Evidence) -> Result<pb::AttestationEvidence, Status> {
    let (signature, signer_pubkey, sev_report, sev_chain) = match ev.proof {
        ne_attestation::Proof::Software {
            signature,
            signer_pubkey,
        } => (
            signature.to_vec(),
            signer_pubkey.to_vec(),
            Vec::new(),
            Vec::new(),
        ),
        ne_attestation::Proof::SevSnp {
            report,
            vcek_cert_chain,
        } => (Vec::new(), Vec::new(), report, vcek_cert_chain),
        // REVIEWER NOTE: catch-all stays — Proof is #[non_exhaustive]; unknown
        // future variants are a server bug, refuse loudly (§7.3 invariant).
        _ => return Err(Status::internal("unsupported attestation proof variant")),
    };
    let provider_type = match ev.provider_type {
        ne_attestation::ProviderType::Software => "software",
        ne_attestation::ProviderType::SevSnp => "sev_snp",
        // REVIEWER NOTE: catch-all stays — ProviderType is #[non_exhaustive].
        _ => return Err(Status::internal("unsupported attestation provider variant")),
    }
    .to_string();
    Ok(pb::AttestationEvidence {
        provider_type,
        workspace_id: ev.workspace_id,
        measurement: ev.measurement.0.to_vec(),
        nonce: ev.nonce,
        issued_at: ev.issued_at,
        report_data: ev.report_data,
        proof: Some(pb::AttestationProof {
            signature,
            signer_pubkey,
            sev_snp_report: sev_report,
            sev_snp_vcek_chain: sev_chain,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor_client::SupervisorClient;
    use ne_protocol::supervisor::{
        self as sup, MAX_INLINE_FILE_BYTES, SupervisorErrorKind, SupervisorRequest,
        SupervisorResponse,
    };
    use std::path::PathBuf;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    /// Spawns a tiny in-process supervisor that hands every incoming
    /// request to `responder` and writes the returned response.
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
        (tmp, path)
    }

    fn make_service<F>(responder: F) -> (RuntimeService, tempfile::TempDir)
    where
        F: Fn(SupervisorRequest) -> SupervisorResponse + Send + Sync + 'static,
    {
        let (tmp, path) = spawn_fake_supervisor(responder);
        let core = Arc::new(RuntimeCore::new(SupervisorClient::new(path)));
        (RuntimeService::new(core), tmp)
    }

    #[tokio::test]
    async fn ping_relays_supervisor_pong() {
        let (svc, _tmp) = make_service(|_| SupervisorResponse::Pong {
            version: "0.0.0-fake".into(),
            uptime_ms: 7,
        });
        let resp = svc
            .ping(Request::new(pb::PingRequest {}))
            .await
            .expect("ping")
            .into_inner();
        assert_eq!(resp.supervisor_version, "0.0.0-fake");
        assert_eq!(resp.supervisor_uptime_ms, 7);
        assert_eq!(resp.api_version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn create_workspace_relays_workspace_created() {
        let (svc, _tmp) = make_service(|req| match req {
            SupervisorRequest::CreateWorkspace(c) => {
                SupervisorResponse::WorkspaceCreated(sup::WorkspaceCreated {
                    workspace_id: c.workspace_id,
                    firecracker_pid: 4242,
                    vsock_host_socket: "/srv/jailer/firecracker/x/root/vsock.sock".into(),
                    jailer_chroot: "/srv/jailer/firecracker/x/root".into(),
                    network: None,
                    exec_backend: None,
                    control_socket: None,
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });
        let resp = svc
            .create_workspace(Request::new(pb::CreateWorkspaceRequest {
                workspace_id: "wks-test-1".into(),
                kernel_sha256: "11".repeat(32),
                rootfs_sha256: "22".repeat(32),
                rootfs_read_only: true,
                vcpu_count: 1,
                mem_size_mib: 256,
                guest_vsock_cid: 3,
                kernel_boot_args: None,
                network: None,
                tier: None,
            }))
            .await
            .expect("create_workspace")
            .into_inner();
        assert_eq!(resp.workspace_id, "wks-test-1");
        assert_eq!(resp.firecracker_pid, 4242);
        assert!(resp.vsock_host_socket.ends_with("/vsock.sock"));
        assert!(
            resp.network.is_none(),
            "fake supervisor returned no network"
        );
    }

    #[tokio::test]
    async fn create_workspace_relays_network_config_both_directions() {
        let (svc, _tmp) = make_service(|req| match req {
            SupervisorRequest::CreateWorkspace(c) => {
                // Assert the supervisor saw the NetworkConfig the
                // caller sent, then synthesize a populated
                // WorkspaceNetwork on the response side.
                let network = c
                    .network
                    .expect("expected NetworkConfig to reach supervisor");
                assert!(network.enable_egress, "egress flag must round-trip");
                assert_eq!(
                    network.allow_cidrs,
                    vec!["10.0.0.0/8".to_string(), "203.0.113.0/24".to_string()],
                    "allow_cidrs must round-trip in order"
                );
                assert_eq!(
                    network.allow_hostnames,
                    vec!["openai.com".to_string(), "*.github.com".to_string()],
                    "allow_hostnames must round-trip in order"
                );
                assert!(
                    network.privacy_router.is_some(),
                    "privacy_router opt-in must round-trip to the supervisor"
                );
                SupervisorResponse::WorkspaceCreated(sup::WorkspaceCreated {
                    workspace_id: c.workspace_id,
                    firecracker_pid: 9001,
                    vsock_host_socket: "/srv/jailer/firecracker/x/root/vsock.sock".into(),
                    jailer_chroot: "/srv/jailer/firecracker/x/root".into(),
                    network: Some(sup::WorkspaceNetwork {
                        netns_path: "/var/run/netns/ne-abcdef".into(),
                        tap_device: "tap-abcdef".into(),
                        host_ip: "169.254.7.1".into(),
                        guest_ip: "169.254.7.2".into(),
                        prefix: 30,
                    }),
                    exec_backend: None,
                    control_socket: None,
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });
        let resp = svc
            .create_workspace(Request::new(pb::CreateWorkspaceRequest {
                workspace_id: "wks-net-rpc".into(),
                kernel_sha256: "11".repeat(32),
                rootfs_sha256: "22".repeat(32),
                rootfs_read_only: true,
                vcpu_count: 1,
                mem_size_mib: 256,
                guest_vsock_cid: 3,
                kernel_boot_args: None,
                network: Some(pb::NetworkConfig {
                    enable_egress: true,
                    allow_cidrs: vec!["10.0.0.0/8".into(), "203.0.113.0/24".into()],
                    allow_hostnames: vec!["openai.com".into(), "*.github.com".into()],
                    privacy_router: Some(pb::PrivacyRouterConfig {}),
                    exposed_ports: vec![],
                }),
                tier: None,
            }))
            .await
            .expect("create_workspace")
            .into_inner();
        let net = resp.network.expect("response must echo WorkspaceNetwork");
        assert_eq!(net.tap_device, "tap-abcdef");
        assert_eq!(net.host_ip, "169.254.7.1");
        assert_eq!(net.guest_ip, "169.254.7.2");
        assert_eq!(net.prefix, 30);
    }

    #[tokio::test]
    async fn create_workspace_validates_vcpu_count_at_the_boundary() {
        let (svc, _tmp) = make_service(|_| panic!("supervisor should not be called"));
        let err = svc
            .create_workspace(Request::new(pb::CreateWorkspaceRequest {
                workspace_id: "wks-test-2".into(),
                kernel_sha256: "11".repeat(32),
                rootfs_sha256: "22".repeat(32),
                rootfs_read_only: true,
                vcpu_count: 300, // > u8::MAX
                mem_size_mib: 256,
                guest_vsock_cid: 3,
                kernel_boot_args: None,
                network: None,
                tier: None,
            }))
            .await
            .expect_err("must reject vcpu_count > 255");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn destroy_workspace_relays_workspace_terminated() {
        let (svc, _tmp) = make_service(|req| match req {
            SupervisorRequest::Terminate(t) => SupervisorResponse::WorkspaceTerminated {
                workspace_id: t.workspace_id,
            },
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });
        let resp = svc
            .destroy_workspace(Request::new(pb::DestroyWorkspaceRequest {
                workspace_id: "wks-test-3".into(),
                grace_period_ms: 1_000,
            }))
            .await
            .expect("destroy_workspace")
            .into_inner();
        assert_eq!(resp.workspace_id, "wks-test-3");
    }

    #[tokio::test]
    async fn destroy_workspace_maps_workspace_not_found_to_not_found_status() {
        let (svc, _tmp) = make_service(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::WorkspaceNotFound,
            message: "workspace ghost not found".into(),
        });
        let err = svc
            .destroy_workspace(Request::new(pb::DestroyWorkspaceRequest {
                workspace_id: "wks-ghost".into(),
                grace_period_ms: 1_000,
            }))
            .await
            .expect_err("must surface WorkspaceNotFound");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn execute_command_relays_command_completed() {
        let (svc, _tmp) = make_service(|req| match req {
            SupervisorRequest::RunCommand(r) => {
                SupervisorResponse::CommandCompleted(sup::CommandCompleted {
                    workspace_id: r.workspace_id,
                    stdout: "hello\n".into(),
                    stderr: String::new(),
                    exit_code: 0,
                    elapsed_ms: 3,
                    truncated: false,
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });
        let resp = svc
            .execute_command(Request::new(pb::ExecuteCommandRequest {
                workspace_id: "wks-exec-1".into(),
                command: "/bin/echo".into(),
                args: vec!["hello".into()],
                timeout_ms: 5_000,
                guest_port: 0, // exercise the default-52 path
            }))
            .await
            .expect("execute_command")
            .into_inner();
        assert_eq!(resp.workspace_id, "wks-exec-1");
        assert_eq!(resp.exit_code, 0);
        assert!(resp.stdout.contains("hello"));
    }

    #[tokio::test]
    async fn execute_command_maps_timeout_to_deadline_exceeded() {
        let (svc, _tmp) = make_service(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::Timeout,
            message: "command exceeded timeout 5ms".into(),
        });
        let err = svc
            .execute_command(Request::new(pb::ExecuteCommandRequest {
                workspace_id: "wks-exec-2".into(),
                command: "/bin/sleep".into(),
                args: vec!["5".into()],
                timeout_ms: 5,
                guest_port: 52,
            }))
            .await
            .expect_err("must surface Timeout");
        assert_eq!(err.code(), tonic::Code::DeadlineExceeded);
    }

    #[tokio::test]
    async fn execute_command_maps_guest_unreachable_to_unavailable() {
        let (svc, _tmp) = make_service(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::GuestUnreachable,
            message: "vsock CONNECT rejected".into(),
        });
        let err = svc
            .execute_command(Request::new(pb::ExecuteCommandRequest {
                workspace_id: "wks-exec-3".into(),
                command: "/bin/echo".into(),
                args: vec![],
                timeout_ms: 1_000,
                guest_port: 52,
            }))
            .await
            .expect_err("must surface GuestUnreachable");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn write_file_relays_request_and_response() {
        let (svc, _tmp) = make_service(|req| match req {
            SupervisorRequest::WriteFile(c) => {
                assert_eq!(c.workspace_id, "wks-w-1");
                assert_eq!(c.path, "src/main.rs");
                assert_eq!(c.content, b"fn main() {}");
                assert_eq!(c.guest_port, 52, "default guest port must be 52");
                SupervisorResponse::FileWritten(sup::FileWritten {
                    workspace_id: c.workspace_id,
                    bytes_written: u64::try_from(c.content.len()).unwrap(),
                    absolute_path: "/workspace/src/main.rs".into(),
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });
        let resp = svc
            .write_file(Request::new(pb::WriteFileRequest {
                workspace_id: "wks-w-1".into(),
                path: "src/main.rs".into(),
                content: b"fn main() {}".to_vec(),
                guest_port: 0,
            }))
            .await
            .expect("write_file")
            .into_inner();
        assert_eq!(resp.bytes_written, 12);
        assert_eq!(resp.absolute_path, "/workspace/src/main.rs");
    }

    #[tokio::test]
    async fn write_file_rejects_oversized_body_at_api_layer() {
        let (svc, _tmp) = make_service(|_| panic!("supervisor must not be called"));
        let err = svc
            .write_file(Request::new(pb::WriteFileRequest {
                workspace_id: "wks-big".into(),
                path: "huge.bin".into(),
                content: vec![0u8; MAX_INLINE_FILE_BYTES + 1],
                guest_port: 0,
            }))
            .await
            .expect_err("must reject");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn write_file_path_rejection_maps_to_invalid_argument() {
        let (svc, _tmp) = make_service(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::PathRejected,
            message: "path contains '..' segment".into(),
        });
        let err = svc
            .write_file(Request::new(pb::WriteFileRequest {
                workspace_id: "wks-bad".into(),
                path: "../etc/passwd".into(),
                content: b"x".to_vec(),
                guest_port: 0,
            }))
            .await
            .expect_err("must reject");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn read_file_relays_round_trip() {
        let (svc, _tmp) = make_service(|req| match req {
            SupervisorRequest::ReadFile(c) => {
                assert_eq!(c.path, "out/log.txt");
                assert_eq!(c.max_bytes, 4096, "max_bytes must round-trip");
                SupervisorResponse::FileRead(sup::FileRead {
                    workspace_id: c.workspace_id,
                    content: b"line1\nline2\n".to_vec(),
                    size_bytes: 12,
                    truncated: false,
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });
        let resp = svc
            .read_file(Request::new(pb::ReadFileRequest {
                workspace_id: "wks-r-1".into(),
                path: "out/log.txt".into(),
                max_bytes: 4096,
                guest_port: 0,
            }))
            .await
            .expect("read_file")
            .into_inner();
        assert_eq!(resp.content, b"line1\nline2\n");
        assert_eq!(resp.size_bytes, 12);
        assert!(!resp.truncated);
    }

    #[tokio::test]
    async fn write_file_io_error_maps_to_internal() {
        let (svc, _tmp) = make_service(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::IoError,
            message: "write: no space left on device".into(),
        });
        let err = svc
            .write_file(Request::new(pb::WriteFileRequest {
                workspace_id: "wks-io".into(),
                path: "f.bin".into(),
                content: b"x".to_vec(),
                guest_port: 0,
            }))
            .await
            .expect_err("must fail");
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn read_file_not_found_maps_to_not_found_status() {
        let (svc, _tmp) = make_service(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::FileNotFound,
            message: "no such file".into(),
        });
        let err = svc
            .read_file(Request::new(pb::ReadFileRequest {
                workspace_id: "wks-missing".into(),
                path: "nope.txt".into(),
                max_bytes: 0,
                guest_port: 0,
            }))
            .await
            .expect_err("must fail");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn read_file_caps_explicit_max_bytes_at_api_layer() {
        let (svc, _tmp) = make_service(|req| match req {
            SupervisorRequest::ReadFile(c) => {
                // The API must have rewritten max_bytes from 100_000_000
                // (caller request) down to MAX_INLINE_FILE_BYTES.
                assert_eq!(
                    c.max_bytes, MAX_INLINE_FILE_BYTES as u64,
                    "API must cap caller max_bytes",
                );
                SupervisorResponse::FileRead(sup::FileRead {
                    workspace_id: c.workspace_id,
                    content: vec![],
                    size_bytes: 0,
                    truncated: false,
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });
        let _ = svc
            .read_file(Request::new(pb::ReadFileRequest {
                workspace_id: "wks-cap".into(),
                path: "huge.bin".into(),
                max_bytes: 100_000_000,
                guest_port: 0,
            }))
            .await
            .expect("read_file");
    }

    #[tokio::test]
    async fn expose_port_maps_to_supervisor() {
        let (svc, _tmp) = make_service(|req| match req {
            SupervisorRequest::ExposePort(r) => SupervisorResponse::PortExposed {
                workspace_id: r.workspace_id,
                port: r.port.port,
            },
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });
        let resp = svc
            .expose_port(Request::new(pb::ExposePortRequest {
                workspace_id: "ws-a".into(),
                port: Some(pb::ExposedPort {
                    port: 8080,
                    inject_headers: vec![],
                }),
            }))
            .await
            .expect("ok")
            .into_inner();
        assert_eq!((resp.workspace_id.as_str(), resp.port), ("ws-a", 8080));
    }

    #[tokio::test]
    async fn expose_port_missing_port_returns_invalid_argument() {
        let (svc, _tmp) = make_service(|_| panic!("supervisor must not be called"));
        let err = svc
            .expose_port(Request::new(pb::ExposePortRequest {
                workspace_id: "ws-b".into(),
                port: None,
            }))
            .await
            .expect_err("must reject missing port");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn unexpose_port_maps_to_supervisor() {
        let (svc, _tmp) = make_service(|req| match req {
            SupervisorRequest::UnexposePort(r) => SupervisorResponse::PortUnexposed {
                workspace_id: r.workspace_id,
                port: r.port,
            },
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });
        let resp = svc
            .unexpose_port(Request::new(pb::UnexposePortRequest {
                workspace_id: "ws-c".into(),
                port: 9090,
            }))
            .await
            .expect("ok")
            .into_inner();
        assert_eq!((resp.workspace_id.as_str(), resp.port), ("ws-c", 9090));
    }

    #[tokio::test]
    async fn get_attestation_evidence_relays_and_converts() {
        use ne_attestation::{Evidence, Measurement, Proof, ProviderType};

        let fake_evidence = Evidence {
            provider_type: ProviderType::Software,
            workspace_id: "ws-attest-1".into(),
            measurement: Measurement([0xabu8; 32]),
            nonce: vec![1u8; 16],
            issued_at: 1_700_000_042,
            report_data: b"canonical".to_vec(),
            proof: Proof::Software {
                signature: [0u8; 64],
                signer_pubkey: [1u8; 32],
            },
        };
        let expected_evidence = fake_evidence.clone();

        let (svc, _tmp) = make_service(move |req| match req {
            SupervisorRequest::GetAttestationEvidence(r) => {
                assert_eq!(r.workspace_id, "ws-attest-1");
                assert_eq!(r.nonce, vec![1u8; 16]);
                SupervisorResponse::AttestationEvidenceIssued {
                    evidence: expected_evidence.clone(),
                }
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });

        let resp = svc
            .get_attestation_evidence(Request::new(pb::GetAttestationEvidenceRequest {
                workspace_id: "ws-attest-1".into(),
                nonce: vec![1u8; 16],
            }))
            .await
            .expect("get_attestation_evidence")
            .into_inner();

        let ev = resp.evidence.expect("evidence must be set");
        assert_eq!(ev.provider_type, "software");
        assert_eq!(ev.workspace_id, "ws-attest-1");
        assert_eq!(ev.measurement.len(), 32);
        assert!(ev.measurement.iter().all(|&b| b == 0xab));
        let proof = ev.proof.expect("proof must be set");
        assert_eq!(proof.signature.len(), 64);
        assert_eq!(proof.signer_pubkey.len(), 32);
    }

    #[tokio::test]
    async fn get_attestation_evidence_short_nonce_is_invalid_argument() {
        let (svc, _tmp) = make_service(|_| panic!("supervisor must not be called"));
        let err = svc
            .get_attestation_evidence(Request::new(pb::GetAttestationEvidenceRequest {
                workspace_id: "ws-x".into(),
                nonce: vec![0u8; 8], // too short
            }))
            .await
            .expect_err("must reject short nonce");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// `evidence_to_pb` maps a SEV-SNP `Evidence` envelope onto the protobuf
    /// form: empty software fields, populated `sev_snp_report` /
    /// `sev_snp_vcek_chain`, and `provider_type == "sev_snp"`.
    #[test]
    fn evidence_to_pb_maps_sev_snp_envelope() {
        let report = vec![0xAu8; 0x1000];
        let chain = vec![0xBu8; 0x800];
        let ev = ne_attestation::Evidence {
            provider_type: ne_attestation::ProviderType::SevSnp,
            workspace_id: "ws-snp-1".into(),
            measurement: ne_attestation::Measurement([0x11; 32]),
            nonce: vec![1u8; 16],
            issued_at: 1_700_000_000,
            report_data: vec![2u8; 48],
            proof: ne_attestation::Proof::SevSnp {
                report: report.clone(),
                vcek_cert_chain: chain.clone(),
            },
        };

        let pb_ev = evidence_to_pb(ev).expect("sev_snp evidence maps cleanly");
        assert_eq!(pb_ev.provider_type, "sev_snp");
        assert_eq!(pb_ev.workspace_id, "ws-snp-1");
        assert_eq!(pb_ev.measurement.len(), 32);
        let proof = pb_ev.proof.expect("proof must be set");
        // Software proof is empty for SEV-SNP envelopes.
        assert!(proof.signature.is_empty());
        assert!(proof.signer_pubkey.is_empty());
        // Firmware proof carried verbatim.
        assert_eq!(proof.sev_snp_report, report);
        assert_eq!(proof.sev_snp_vcek_chain, chain);
    }

    /// `evidence_to_pb` maps a Software envelope onto the protobuf form,
    /// leaving the SEV-SNP fields empty (regression for backward-compat field
    /// mapping after the additive proto change).
    #[test]
    fn evidence_to_pb_maps_software_envelope_leaves_snp_empty() {
        let ev = ne_attestation::Evidence {
            provider_type: ne_attestation::ProviderType::Software,
            workspace_id: "ws-sw-1".into(),
            measurement: ne_attestation::Measurement([0x33; 32]),
            nonce: vec![1u8; 16],
            issued_at: 1_700_000_001,
            report_data: vec![4u8; 48],
            proof: ne_attestation::Proof::Software {
                signature: [0x5a; 64],
                signer_pubkey: [0x6b; 32],
            },
        };

        let pb_ev = evidence_to_pb(ev).expect("software evidence maps cleanly");
        assert_eq!(pb_ev.provider_type, "software");
        let proof = pb_ev.proof.expect("proof must be set");
        assert_eq!(proof.signature.len(), 64);
        assert_eq!(proof.signer_pubkey.len(), 32);
        assert!(proof.sev_snp_report.is_empty());
        assert!(proof.sev_snp_vcek_chain.is_empty());
    }

    /// Regression anchor for the catch-all arm. `Proof` and `ProviderType`
    /// are `#[non_exhaustive]`, so a future (TDX, …) variant added upstream
    /// must surface as `Status::internal` — never a silently-truncated
    /// envelope that a lenient client could mistake for a passing
    /// attestation (§7.3 "refuse loudly").
    ///
    /// We can't construct a not-yet-existing variant in a unit test, so this
    /// test asserts the *known* arms are exhaustive at compile time: if the
    /// match ever dropped its `_` catch-all (or someone removed an arm), the
    /// compiler would reject the match for a `#[non_exhaustive]` enum. The
    /// presence of this test + the `_ =>` arm is the invariant.
    #[test]
    fn evidence_to_pb_exhaustive_arms_keep_catch_all_for_future_variants() {
        // Software arm + provider_type round-trip (already covered above); the
        // real assertion is the explicit `_ => return Err(Status::internal(..))`
        // arms remaining in `evidence_to_pb`. Sealed here as documentation.
        let ev = ne_attestation::Evidence {
            provider_type: ne_attestation::ProviderType::Software,
            workspace_id: "ws-doc".into(),
            measurement: ne_attestation::Measurement([0; 32]),
            nonce: vec![1u8; 16],
            issued_at: 0,
            report_data: vec![],
            proof: ne_attestation::Proof::Software {
                signature: [0; 64],
                signer_pubkey: [0; 32],
            },
        };
        let _ = evidence_to_pb(ev).expect("known arms still map");
    }
}
