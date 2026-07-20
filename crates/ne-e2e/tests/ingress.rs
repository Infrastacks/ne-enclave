// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! e2e: host-based ingress routing reaches an in-guest HTTP service via
//! `{port}-{workspace_id}.{domain}`, refuses unknown/unexposed routes,
//! supports dynamic expose/unexpose, and injects configured headers.
//!
//! KVM-gated + networking-gated (requires `ip`/`iptables`/root).
//!
//! `#[ignore]` by default. On the KVM host:
//! ```sh
//! cargo test -p ne-e2e --test ingress -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ne_ingress::{AuditSink, DenyReason, IngressRouter, RouterConfig};
use ne_protocol::supervisor::{
    CreateWorkspaceRequest, ExposePortRequest, ExposedPort, HeaderInjection, NetworkConfig,
    SupervisorResponse, TerminateRequest, UnexposePortRequest,
};
use ne_supervisor::audit::AuditLog;
use ne_supervisor::workspace::{WorkspaceManager, WorkspaceManagerConfig};

const VSOCK_PORT: u32 = 52;
const INGRESS_DOMAIN: &str = "apps.test";

// ---------------------------------------------------------------------------
// Host env helpers (identical to live_snapshot.rs)
// ---------------------------------------------------------------------------

struct HostEnv {
    kernel: PathBuf,
    rootfs: PathBuf,
    firecracker: PathBuf,
    jailer: PathBuf,
}

fn env_path(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

/// Returns the host paths if KVM + all required files are present, else None.
fn load_host_env() -> Option<HostEnv> {
    if !ne_e2e::host_can_launch_firecracker() {
        eprintln!("skip: /dev/kvm missing — run on a KVM host");
        return None;
    }
    let env = HostEnv {
        kernel: env_path("NE_E2E_KERNEL", "/var/lib/ne-enclave/vmlinux"),
        rootfs: env_path("NE_E2E_ROOTFS", "/var/lib/ne-enclave/rootfs.img"),
        firecracker: env_path("NE_E2E_FIRECRACKER", "/usr/local/bin/firecracker"),
        jailer: env_path("NE_E2E_JAILER", "/usr/local/bin/jailer"),
    };
    for p in [&env.kernel, &env.rootfs, &env.firecracker, &env.jailer] {
        assert!(p.is_file(), "missing required file: {}", p.display());
    }
    Some(env)
}

// ---------------------------------------------------------------------------
// Recording audit sink
// ---------------------------------------------------------------------------

/// Minimal audit sink that records which events fired so the test can
/// assert `route_allowed` and `route_denied` are emitted correctly.
#[derive(Debug, Default)]
struct RecordingAudit {
    allowed: std::sync::Mutex<Vec<(String, String, u16)>>,
    denied: std::sync::Mutex<Vec<(String, String)>>,
}

impl AuditSink for RecordingAudit {
    fn route_allowed(&self, host: &str, wsid: &str, port: u16) {
        self.allowed
            .lock()
            .unwrap()
            .push((host.to_string(), wsid.to_string(), port));
    }

    fn route_denied(&self, host: &str, reason: DenyReason) {
        self.denied
            .lock()
            .unwrap()
            .push((host.to_string(), reason.as_str().to_string()));
    }
}

// ---------------------------------------------------------------------------
// curl helper
// ---------------------------------------------------------------------------

/// Issue a plain curl GET.  Returns `(http_status_code, body)`.
///
/// Uses `--resolve` to point the virtual hostname at 127.0.0.1:edge_port so
/// the ingress router receives the correct `Host` header without a real DNS
/// entry.
fn curl_get(virtual_host: &str, edge_port: u16, path: &str) -> (u32, String) {
    // `{virtual_host}` already includes the port-prefix label; add the
    // authority port for the --resolve target and the URL.
    let resolve_arg = format!("{virtual_host}:{edge_port}:127.0.0.1");
    let url = format!("http://{virtual_host}:{edge_port}{path}");

    let out = std::process::Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "10",
            "--resolve",
            &resolve_arg,
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            &url,
        ])
        .output()
        .expect("curl not found — install curl on the test host");

    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    // The output is `<body>\n<status_code>` because of `-w "\n%{http_code}"`.
    let (body, code_str) = raw.rsplit_once('\n').unwrap_or(("", "0"));
    let code: u32 = code_str.trim().parse().unwrap_or(0);
    (code, body.to_string())
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires /dev/kvm + firecracker + root + ip/iptables"]
async fn ingress_routes_to_guest_service() {
    let Some(env) = load_host_env() else { return };

    // --- Temp dirs ---
    let tmp = tempfile::tempdir().expect("tempdir");
    let chroot_base = tmp.path().join("chroot");
    let state_dir = tmp.path().join("state");
    let image_store = tmp.path().join("images");
    let (kernel_sha256, rootfs_sha256) =
        ne_e2e::prepare_managed_images(&image_store, &env.kernel, &env.rootfs);
    tokio::fs::create_dir_all(state_dir.join("keys"))
        .await
        .expect("keys dir");
    tokio::fs::create_dir_all(&chroot_base)
        .await
        .expect("chroot dir");

    // --- Audit log ---
    let audit = AuditLog::open(&state_dir).await.expect("audit");

    // --- NetworkController ---
    let network = ne_supervisor::network::NetworkController::new(
        PathBuf::from("/usr/sbin/ip"),
        PathBuf::from("/usr/sbin/iptables"),
        "eth0".to_string(),
        None,                     // dns_filter_binary
        "1.1.1.1:53".to_string(), // dns_upstream
        None,                     // privacy_router_binary
        None,                     // privacy_router_policy
        Some(audit.clone()),      // audit
    );

    // --- WorkspaceManager with networking ---
    let mut cfg = WorkspaceManagerConfig::dev_defaults();
    cfg.firecracker_binary = env.firecracker.clone();
    cfg.jailer_binary = env.jailer.clone();
    cfg.chroot_base = chroot_base.clone();
    cfg.state_dir = state_dir.clone();
    cfg.image_store = image_store;
    cfg.network = Some(network);
    let attestation = ne_supervisor::attestation_factory::build_provider(
        ne_protocol::profile::AttestationBackend::Software,
        audit.signing_key(),
    )
    .expect("software provider");
    let mgr = Arc::new(
        WorkspaceManager::new(cfg, audit, attestation, 1024, 32768).expect("workspace manager"),
    );

    // --- Step 1: Create ws-ing (networked, port 8080 exposed with header injection) ---
    let create_resp = mgr
        .create(CreateWorkspaceRequest {
            workspace_id: "ws-ing".to_string(),
            kernel_sha256,
            rootfs_sha256,
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 128,
            guest_vsock_cid: 3,
            kernel_boot_args: None,
            network: Some(NetworkConfig {
                enable_egress: true,
                allow_cidrs: vec![],
                allow_hostnames: vec![],
                privacy_router: None,
                exposed_ports: vec![ExposedPort {
                    port: 8080,
                    inject_headers: vec![HeaderInjection {
                        name: "x-enclave-auth".to_string(),
                        value: "secret".to_string(),
                    }],
                }],
            }),
            tier: None,
        })
        .await;

    let wc = match create_resp {
        SupervisorResponse::WorkspaceCreated(w) => w,
        other => panic!("expected WorkspaceCreated, got {other:?}"),
    };
    let net = wc.network.as_ref().expect("workspace must be networked");
    eprintln!(
        "ws-ing created: pid={}, guest_ip={}, vsock={}",
        wc.firecracker_pid, net.guest_ip, wc.vsock_host_socket
    );

    // --- Step 2: Wait for guest agent ---
    ne_supervisor::firecracker::wait_for_guest_ready(
        std::path::Path::new(&wc.vsock_host_socket),
        VSOCK_PORT,
        Duration::from_secs(30),
    )
    .await
    .expect("ws-ing guest agent did not become ready within 30s");
    eprintln!("ws-ing guest agent ready");

    // --- Step 3: Start in-guest HTTP server on port 8080 ---
    // busybox httpd + CGI that reflects the X-Enclave-Auth header so we can
    // assert injection. Script written in a single shell one-liner to avoid
    // multi-call vsock round trips.
    //
    // CGI must be executable, output "Content-type: text/plain\n\n<body>".
    // busybox httpd sets HTTP_X_ENCLAVE_AUTH from the X-Enclave-Auth request header.
    let setup_script = concat!(
        "mkdir -p /workspace/cgi-bin && ",
        // Write CGI script
        "printf '#!/bin/sh\\necho \"Content-type: text/plain\"\\necho\\n",
        "echo \"X-Enclave-Auth=${HTTP_X_ENCLAVE_AUTH}\"\\n' > /workspace/cgi-bin/echo && ",
        "chmod +x /workspace/cgi-bin/echo && ",
        // Write index.html
        "echo 'INGRESS-OK' > /workspace/index.html && ",
        // Start httpd on 8080 in daemon mode (busybox httpd -f keeps foreground;
        // without -f it daemonizes and the shell command returns immediately)
        "busybox httpd -p 8080 -h /workspace"
    );

    let run_resp = mgr
        .run_command(ne_protocol::supervisor::RunCommandRequest {
            workspace_id: "ws-ing".to_string(),
            guest_port: VSOCK_PORT,
            command: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), setup_script.to_string()],
            timeout_ms: 10_000,
        })
        .await;
    match &run_resp {
        SupervisorResponse::CommandCompleted(c) => {
            // busybox httpd daemonizes; exit_code 0 means the setup succeeded.
            assert_eq!(c.exit_code, 0, "httpd setup failed: stderr={}", c.stderr);
        }
        other => panic!("expected CommandCompleted for httpd setup, got {other:?}"),
    }
    eprintln!("in-guest httpd started on port 8080");

    // Give httpd a moment to bind inside the guest.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Step 4: Start in-process IngressRouter ---
    let recording_audit: Arc<RecordingAudit> = Arc::new(RecordingAudit::default());
    let registry = mgr.ingress_registry();
    let router = IngressRouter::new(
        registry.clone(),
        RouterConfig::new(INGRESS_DOMAIN.to_string()),
        Arc::clone(&recording_audit) as Arc<dyn AuditSink>,
    );

    // Bind on an ephemeral loopback port; plaintext is always allowed on loopback.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress listener");
    let edge_port = listener.local_addr().unwrap().port();
    eprintln!("ingress edge listening on 127.0.0.1:{edge_port}");
    tokio::spawn(Arc::clone(&router).serve_plaintext(listener));

    // The virtual ingress hostname for port 8080 on ws-ing.
    let host_8080 = format!("8080-ws-ing.{INGRESS_DOMAIN}");

    // --- Step 5: Basic routing — GET /index.html should return "INGRESS-OK" ---
    // (request the static file explicitly rather than relying on busybox
    // httpd's directory-index default, which varies by build config.)
    let (status, body) = curl_get(&host_8080, edge_port, "/index.html");
    eprintln!("GET /index.html → {status}: {body:?}");
    assert_eq!(
        status, 200,
        "expected 200 from ingress, got {status}; body={body:?}"
    );
    assert!(
        body.contains("INGRESS-OK"),
        "expected 'INGRESS-OK' in body, got: {body:?}"
    );

    // Verify allowed audit event was recorded.
    {
        let allowed = recording_audit.allowed.lock().unwrap();
        assert!(
            !allowed.is_empty(),
            "expected at least one route_allowed audit event"
        );
        assert_eq!(allowed[0].1, "ws-ing", "audit wsid mismatch");
        assert_eq!(allowed[0].2, 8080u16, "audit port mismatch");
    }

    // --- Step 6: Header injection — CGI echoes the injected header ---
    let (status, body) = curl_get(&host_8080, edge_port, "/cgi-bin/echo");
    eprintln!("GET /cgi-bin/echo → {status}: {body:?}");
    assert_eq!(
        status, 200,
        "expected 200 from CGI, got {status}; body={body:?}"
    );
    assert!(
        body.contains("X-Enclave-Auth=secret"),
        "expected header injection 'X-Enclave-Auth=secret' in CGI output, got: {body:?}"
    );

    // --- Step 7: Deny — unknown workspace → 404 ---
    let host_unknown = format!("8080-ws-zzz.{INGRESS_DOMAIN}");
    let (status, _body) = curl_get(&host_unknown, edge_port, "/");
    eprintln!("GET unknown workspace → {status}");
    assert_eq!(
        status, 404,
        "expected 404 for unknown workspace, got {status}"
    );

    {
        let denied = recording_audit.denied.lock().unwrap();
        assert!(
            denied
                .iter()
                .any(|(_, reason)| reason == "unknown_workspace"),
            "expected unknown_workspace deny audit event, got: {denied:?}"
        );
    }

    // --- Step 8: Deny — unexposed port → 404 ---
    let host_9090 = format!("9090-ws-ing.{INGRESS_DOMAIN}");
    let (status, _body) = curl_get(&host_9090, edge_port, "/");
    eprintln!("GET unexposed port 9090 → {status}");
    assert_eq!(
        status, 404,
        "expected 404 for unexposed port 9090, got {status}"
    );

    {
        let denied = recording_audit.denied.lock().unwrap();
        assert!(
            denied.iter().any(|(_, reason)| reason == "unexposed_port"),
            "expected unexposed_port deny audit event, got: {denied:?}"
        );
    }

    // --- Step 9: Dynamic expose — start a second httpd on 9090, expose it ---
    // Start httpd on 9090 (reuse the same /workspace root).
    let run_resp2 = mgr
        .run_command(ne_protocol::supervisor::RunCommandRequest {
            workspace_id: "ws-ing".to_string(),
            guest_port: VSOCK_PORT,
            command: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                "busybox httpd -p 9090 -h /workspace".to_string(),
            ],
            timeout_ms: 5_000,
        })
        .await;
    match &run_resp2 {
        SupervisorResponse::CommandCompleted(c) => {
            assert_eq!(
                c.exit_code, 0,
                "httpd 9090 setup failed: stderr={}",
                c.stderr
            );
        }
        other => panic!("expected CommandCompleted for httpd 9090, got {other:?}"),
    }
    eprintln!("in-guest httpd started on port 9090");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Expose port 9090 dynamically.
    let expose_resp = mgr
        .expose_port(ExposePortRequest {
            workspace_id: "ws-ing".to_string(),
            port: ExposedPort {
                port: 9090,
                inject_headers: vec![],
            },
        })
        .await;
    match &expose_resp {
        SupervisorResponse::PortExposed { workspace_id, port } => {
            assert_eq!(workspace_id, "ws-ing");
            assert_eq!(*port, 9090u16);
        }
        other => panic!("expected PortExposed, got {other:?}"),
    }
    eprintln!("port 9090 dynamically exposed");

    // Should now be routable.
    let (status, body) = curl_get(&host_9090, edge_port, "/index.html");
    eprintln!("GET 9090-ws-ing (after expose) → {status}: {body:?}");
    assert_eq!(
        status, 200,
        "expected 200 after dynamic expose on port 9090, got {status}"
    );
    assert!(
        body.contains("INGRESS-OK"),
        "expected 'INGRESS-OK' in body from port 9090, got: {body:?}"
    );

    // Unexpose port 9090.
    let unexpose_resp = mgr
        .unexpose_port(UnexposePortRequest {
            workspace_id: "ws-ing".to_string(),
            port: 9090,
        })
        .await;
    match &unexpose_resp {
        SupervisorResponse::PortUnexposed { workspace_id, port } => {
            assert_eq!(workspace_id, "ws-ing");
            assert_eq!(*port, 9090u16);
        }
        other => panic!("expected PortUnexposed, got {other:?}"),
    }
    eprintln!("port 9090 dynamically unexposed");

    // Should be 404 again.
    let (status, _body) = curl_get(&host_9090, edge_port, "/");
    eprintln!("GET 9090-ws-ing (after unexpose) → {status}");
    assert_eq!(
        status, 404,
        "expected 404 after dynamic unexpose on port 9090, got {status}"
    );

    // --- Step 10: Teardown ---
    let term_resp = mgr
        .terminate(TerminateRequest {
            workspace_id: "ws-ing".to_string(),
            grace_period_ms: 2_000,
        })
        .await;
    match &term_resp {
        SupervisorResponse::WorkspaceTerminated { workspace_id } => {
            assert_eq!(workspace_id, "ws-ing");
        }
        other => panic!("expected WorkspaceTerminated, got {other:?}"),
    }
    eprintln!("ws-ing terminated");

    // Registry must be empty for ws-ing after termination.
    assert!(
        registry.resolve("ws-ing", 8080).await.is_none(),
        "ingress registry must have no entry for ws-ing:8080 after terminate"
    );
    assert!(
        !registry.workspace_exists("ws-ing").await,
        "ingress registry must not contain ws-ing after terminate"
    );

    eprintln!("ingress_routes_to_guest_service: PASSED");
}
