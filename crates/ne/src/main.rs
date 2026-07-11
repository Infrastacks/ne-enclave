// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! NeuronEdge Enclave single fused binary entry point.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod cli;

use ne::install;

use anyhow::{Context as _, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // The per-workspace filter/router subcommands write their JSON
    // audit lines to stdout for the supervisor to relay into its
    // signed chain, so their tracing output must go to stderr to keep
    // stdout clean. The serve-* daemons have no such stdout contract
    // and log JSON to stdout.
    match &cli.command {
        // stdout must stay clean for the printed token / verify JSON line,
        // so api-key generate and audit subcommands route tracing to stderr
        // exactly like the audit-line producers.
        Command::DnsFilter(_)
        | Command::PrivacyRouter(_)
        | Command::ApiKey(_)
        | Command::Tls(_)
        | Command::Audit(_)
        | Command::Snapshot(_)
        | Command::Pool(_)
        | Command::Workspace(_) => {
            init_tracing_stderr()?;
        }
        Command::ServeApi(_)
        | Command::ServeSupervisor(_)
        | Command::Install(_)
        | Command::Uninstall(_)
        | Command::Doctor(_)
        | Command::Image(_) => init_tracing()?,
    }
    match cli.command {
        Command::ServeApi(a) => {
            let api_keys = match &a.api_key_file {
                Some(path) => std::sync::Arc::new(ne_api::auth::ApiKeyStore::load(path)?),
                None => std::sync::Arc::new(ne_api::auth::ApiKeyStore::default()),
            };
            let tls = match (&a.tls_cert, &a.tls_key) {
                (Some(cert), Some(key)) => Some(ne_api::tls::TlsConfig::from_pem_files(cert, key)?),
                (None, None) => None,
                (Some(_), None) => {
                    anyhow::bail!("--tls-cert was given without --tls-key (both are required)")
                }
                (None, Some(_)) => {
                    anyhow::bail!("--tls-key was given without --tls-cert (both are required)")
                }
            };
            ne_api::serve(ne_api::ApiConfig {
                grpc_bind: a.bind,
                rest_bind: a.rest_bind,
                supervisor_socket: a.supervisor_socket,
                dev_mode: a.dev_mode,
                api_keys,
                tls,
            })
            .await
        }
        Command::ServeSupervisor(a) => {
            install_parent_death_signal();
            let a = *a;
            ne_supervisor::serve::serve(ne_supervisor::serve::SupervisorConfig {
                socket: a.socket,
                expected_peer_uid: a.expected_peer_uid,
                dev_mode: a.dev_mode,
                firecracker_binary: a.firecracker_binary,
                jailer_binary: a.jailer_binary,
                jailer_chroot_base: a.jailer_chroot_base,
                image_store: a.image_store,
                jailer_uid: a.jailer_uid,
                jailer_gid: a.jailer_gid,
                openshell_sandbox_binary: a.openshell_sandbox_binary,
                api_socket_timeout_ms: a.api_socket_timeout_ms,
                state_dir: a.state_dir,
                enable_networking: a.enable_networking,
                ip_binary: a.ip_binary,
                iptables_binary: a.iptables_binary,
                upstream_iface: a.upstream_iface,
                dns_filter_binary: a.dns_filter_binary,
                dns_upstream: a.dns_upstream,
                privacy_router_binary: a.privacy_router_binary,
                privacy_router_policy: a.privacy_router_policy,
                warm_pool_tier: a.warm_pool_tier,
                warm_pool_snapshot: a.warm_pool_snapshot,
                warm_pool_size: a.warm_pool_size,
                warm_pool_max_in_flight: a.warm_pool_max_in_flight,
                ingress_domain: a.ingress_domain,
                ingress_listen: a.ingress_listen,
                ingress_max_connections: a.ingress_max_connections,
                ingress_tls_cert: a.ingress_tls_cert,
                ingress_tls_key: a.ingress_tls_key,
            })
            .await
        }
        Command::DnsFilter(a) => {
            let allowlist = ne_dns_filter::Allowlist::new(a.allow);
            ne_dns_filter::run(a.listen, a.upstream, allowlist).await?;
            Ok(())
        }
        Command::PrivacyRouter(a) => {
            ne_privacy_router::run(ne_privacy_router::RouterConfig {
                listen: a.listen,
                policy: a.policy,
                max_body_bytes: a.max_body_bytes,
                emit_audit_stdout: a.emit_audit_stdout,
            })
            .await
        }
        Command::Install(a) => {
            let root = a.prefix.clone().unwrap_or_else(|| "/".into());
            let layout = install::layout::Layout::new(root);
            let ne_uid = resolve_ne_uid(a.prefix.is_some());
            install::run::install(install::run::InstallOptions {
                layout,
                fakeroot: a.prefix.is_some(),
                no_start: a.no_start,
                no_image: a.no_image,
                dry_run: a.dry_run,
                ne_uid,
            })
        }
        Command::Doctor(a) => {
            let root = a.prefix.unwrap_or_else(|| "/".into());
            let layout = install::layout::Layout::new(root);
            let report = install::run::doctor(&layout);
            for c in &report.checks {
                tracing::info!(name = %c.name, ok = c.ok, detail = %c.detail, "preflight check");
            }
            if report.ok() {
                Ok(())
            } else {
                anyhow::bail!("preflight failed")
            }
        }
        Command::Uninstall(a) => {
            let root = a.prefix.clone().unwrap_or_else(|| "/".into());
            let layout = install::layout::Layout::new(root);
            install::run::uninstall(&layout, a.purge, a.prefix.is_some())
        }
        Command::Image(a) => match a.command {
            cli::ImageCommand::Import {
                kernel,
                kernel_sha256,
                rootfs,
                rootfs_sha256,
                prefix,
            } => {
                let root = prefix.unwrap_or_else(|| "/".into());
                let layout = install::layout::Layout::new(root);
                install::image::import_artifact(
                    &layout.images_dir(),
                    "kernels",
                    "vmlinux",
                    &kernel,
                    &kernel_sha256,
                )?;
                install::image::import_artifact(
                    &layout.images_dir(),
                    "rootfs",
                    "rootfs.img",
                    &rootfs,
                    &rootfs_sha256,
                )?;
                Ok(())
            }
        },
        Command::ApiKey(a) => match a.command {
            cli::ApiKeyCommand::Generate { key_file } => {
                let token = ne::apikey::generate_api_key(&key_file)?;
                // Intentional: token is printed ONCE to stdout for the operator to capture;
                // notices go to stderr so scripts can isolate the token via `$(...)`.
                print_api_key_result(&token, &key_file);
                Ok(())
            }
        },
        Command::Tls(a) => match a.command {
            cli::TlsCommand::GenerateCert {
                out_dir,
                subject_alt_name,
            } => {
                let (cert, key) = ne::tls_cli::generate_cert(&out_dir, &subject_alt_name)?;
                print_tls_generate_cert_result(&cert, &key);
                Ok(())
            }
        },
        Command::Audit(a) => match a.command {
            cli::AuditCommand::Export {
                state_dir,
                out,
                allow_broken,
            } => {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                let dir = ne::audit_cli::export(&state_dir, &out, allow_broken, now_ms)?;
                print_audit_export_result(&dir);
                Ok(())
            }
            cli::AuditCommand::Verify { path } => ne::audit_cli::verify(&path),
        },
        Command::Snapshot(a) => match a.command {
            cli::SnapshotCommand::Verify { path } => ne::snapshot_cli::verify(&path).await,
        },
        Command::Pool(a) => match a.command {
            cli::PoolCommand::Status { endpoint } => {
                use ne_protocol::grpc::runtime::v1::GetPoolStatusRequest;
                use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
                let mut client = RuntimeClient::connect(endpoint)
                    .await
                    .context("connecting to Enclave API gRPC endpoint")?;
                let resp = client
                    .get_pool_status(GetPoolStatusRequest {})
                    .await
                    .context("GetPoolStatus RPC failed")?
                    .into_inner();
                print_pool_status(
                    resp.configured,
                    &resp.tier,
                    resp.target_size,
                    resp.available,
                    resp.in_flight,
                );
                Ok(())
            }
        },
        Command::Workspace(a) => match a.command {
            cli::WorkspaceCommand::ExposePort {
                workspace_id,
                port,
                headers,
                endpoint,
            } => {
                use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
                use ne_protocol::grpc::runtime::v1::{
                    ExposePortRequest, ExposedPort, HeaderInjection,
                };
                let mut client = RuntimeClient::connect(endpoint)
                    .await
                    .context("connecting to Enclave API gRPC endpoint")?;
                let resp = client
                    .expose_port(ExposePortRequest {
                        workspace_id,
                        port: Some(ExposedPort {
                            port: u32::from(port),
                            inject_headers: headers
                                .into_iter()
                                .map(|(name, value)| HeaderInjection { name, value })
                                .collect(),
                        }),
                    })
                    .await
                    .context("ExposePort RPC failed")?
                    .into_inner();
                print_expose_port_result(&resp.workspace_id, resp.port);
                Ok(())
            }
            cli::WorkspaceCommand::UnexposePort {
                workspace_id,
                port,
                endpoint,
            } => {
                use ne_protocol::grpc::runtime::v1::UnexposePortRequest;
                use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
                let mut client = RuntimeClient::connect(endpoint)
                    .await
                    .context("connecting to Enclave API gRPC endpoint")?;
                let resp = client
                    .unexpose_port(UnexposePortRequest {
                        workspace_id,
                        port: u32::from(port),
                    })
                    .await
                    .context("UnexposePort RPC failed")?
                    .into_inner();
                print_unexpose_port_result(&resp.workspace_id, resp.port);
                Ok(())
            }
            cli::WorkspaceCommand::Attest {
                workspace_id,
                nonce,
                endpoint,
            } => {
                use ne_protocol::grpc::runtime::v1::GetAttestationEvidenceRequest;
                use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
                let nonce_bytes = if let Some(hexstr) = nonce {
                    hex::decode(&hexstr).context("nonce must be valid hex")?
                } else {
                    use rand::RngCore;
                    let mut b = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut b);
                    b.to_vec()
                };
                let mut client = RuntimeClient::connect(endpoint)
                    .await
                    .context("connecting to Enclave API gRPC endpoint")?;
                let resp = client
                    .get_attestation_evidence(GetAttestationEvidenceRequest {
                        workspace_id,
                        nonce: nonce_bytes,
                    })
                    .await
                    .context("GetAttestationEvidence RPC failed")?
                    .into_inner();
                print_attestation_evidence(resp.evidence.as_ref());
                Ok(())
            }
        },
    }
}

/// Print the audit export result to the operator.
///
/// The export directory path is emitted to stdout so it can be captured by
/// scripts; the human notice goes to stderr.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn print_audit_export_result(dir: &std::path::Path) {
    eprintln!("exported to {}", dir.display());
    println!("{}", dir.display());
}

/// Print the generated API key result to the operator.
///
/// The token is emitted to stdout exactly once so the operator can capture it
/// with `$(…)` or shell redirection. All notices go to stderr to keep stdout
/// clean for scripting.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn print_api_key_result(token: &str, key_file: &std::path::Path) {
    eprintln!("API key generated. Store it now \u{2014} it is shown only once:");
    println!("{token}");
    eprintln!("Hash appended to {}", key_file.display());
}

/// Print the warm-pool status from `nee pool status`.
///
/// Output goes to stdout so operators and scripts can capture it directly.
#[allow(clippy::print_stdout)]
fn print_pool_status(
    configured: bool,
    tier: &str,
    target_size: u32,
    available: u32,
    in_flight: u32,
) {
    println!(
        "configured={} tier={} target={} available={} in_flight={}",
        configured,
        if tier.is_empty() { "-" } else { tier },
        target_size,
        available,
        in_flight,
    );
}

/// Print the TLS generate-cert result to the operator.
///
/// The cert and key paths are emitted to stdout so they can be captured by
/// scripts; the human warning goes to stderr to keep stdout clean.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn print_tls_generate_cert_result(cert: &std::path::Path, key: &std::path::Path) {
    eprintln!("DEV/TEST ONLY \u{2014} self-signed, not for production.");
    println!("{}", cert.display());
    println!("{}", key.display());
}

/// Print the result of `nee workspace expose-port`.
///
/// Output goes to stdout so operators and scripts can capture it directly.
#[allow(clippy::print_stdout)]
fn print_expose_port_result(workspace_id: &str, port: u32) {
    println!("exposed {workspace_id}:{port}");
}

/// Print the result of `nee workspace unexpose-port`.
///
/// Output goes to stdout so operators and scripts can capture it directly.
#[allow(clippy::print_stdout)]
fn print_unexpose_port_result(workspace_id: &str, port: u32) {
    println!("unexposed {workspace_id}:{port}");
}

/// Print the attestation evidence returned by `nee workspace attest`.
///
/// Output goes to stdout so operators and scripts can capture it directly.
#[allow(clippy::print_stdout)]
fn print_attestation_evidence(ev: Option<&ne_protocol::grpc::runtime::v1::AttestationEvidence>) {
    match ev {
        Some(ev) => {
            println!("provider:    {}", ev.provider_type);
            println!("workspace:   {}", ev.workspace_id);
            println!("measurement: {}", hex::encode(&ev.measurement));
            println!("nonce:       {}", hex::encode(&ev.nonce));
            println!("issued_at:   {}", ev.issued_at);
        }
        None => println!("(no evidence returned)"),
    }
}

/// Resolve the uid of the `ne` service account for the Install dispatch.
/// Under fakeroot (`--prefix`) return a deterministic test uid (991).
/// On real Linux installs the user is created inside `install()` before this
/// value is needed for rendering; the returned value here is only the initial
/// seed — `install()` re-resolves the uid after `ensure_service_user`.
fn resolve_ne_uid(fakeroot: bool) -> u32 {
    if fakeroot {
        return 991; // deterministic for tests
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(Some(u)) = nix::unistd::User::from_name("ne") {
            return u.uid.as_raw();
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn install_parent_death_signal() {
    if let Err(e) = nix::sys::prctl::set_pdeathsig(Some(nix::sys::signal::Signal::SIGTERM)) {
        tracing::warn!("PR_SET_PDEATHSIG failed: {e} (supervisor may outlive its parent)");
    }
}

#[cfg(not(target_os = "linux"))]
fn install_parent_death_signal() {}

fn init_tracing() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Route human-readable tracing to stderr so stdout stays clean for
/// the JSON audit decision lines the supervisor relays into its signed
/// chain (`relay_dns_audit_lines` / `relay_privacy_audit_lines`). Used
/// by the `dns-filter` and `privacy-router` subcommands.
fn init_tracing_stderr() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .json()
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))
}
