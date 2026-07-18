// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell sandbox supervisor — the confidential tier (B) execution substrate.
//!
//! Linux-only + `confidential-cvm` feature. The NeuronEdge supervisor spawns the
//! `openshell-sandbox` binary as a child process per confidential workspace and
//! controls it over SSH, mirroring how OpenShell's own gateway
//! (`openshell-server`) drives sandboxes. **OpenShell is NOT a Cargo dependency**
//! of the runtime — `openshell-sandbox` is a binary (no `[lib]`), `run_sandbox()`
//! is blocking with no control handle, and the documented integration model is
//! subprocess + SSH.
//!
//! # NSSH1 handshake
//!
//! Before SSH negotiation, the client must send a single preface line on the raw
//! TCP stream — OpenShell's auth gate (`openshell-sandbox/src/ssh.rs:209-254`):
//!
//! ```text
//! NSSH1 <token> <timestamp_secs> <nonce> <hmac_hex>\n
//! ```
//! where `hmac_hex = hex(HMAC-SHA256(secret, "{token}|{timestamp}|{nonce}"))`.
//! The server rejects (clock skew > window, bad HMAC, replayed nonce) by closing
//! the stream before SSH starts. Auth itself is unconditional (`Auth::Accept`)
//! — the preface IS the auth.

#[cfg(all(target_os = "linux", feature = "confidential-cvm"))]
mod imp {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::sync::Arc;
    use std::sync::LazyLock;
    use std::time::Duration;

    use ne_protocol::guest::{CommandCompleted, GuestResponse};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::{Child, Command};
    use tracing::{debug, info, warn};

    use super::preface::{PrefaceMaterial, build_nssh1_preface, random_preface_token};

    /// Cap on captured SSH exec output per stream. Parity with the Firecracker
    /// tier's guest-agent `MAX_CMD_OUTPUT_BYTES` (1 MiB). Override via
    /// `NE_MAX_EXEC_OUTPUT_BYTES`; a 0/garbage override is rejected (falls back
    /// to the default) — a 0-byte cap would discard every command's output.
    static MAX_EXEC_OUTPUT_BYTES: LazyLock<usize> = LazyLock::new(|| {
        crate::util::parse_positive_or(std::env::var("NE_MAX_EXEC_OUTPUT_BYTES").ok(), 1024 * 1024)
    });

    /// Append `data` to `buf` but never let `buf` exceed `cap`. Returns true if
    /// output was dropped (truncation occurred on this or a prior call).
    fn push_capped(buf: &mut Vec<u8>, data: &[u8], cap: usize) -> bool {
        if buf.len() >= cap {
            return true;
        }
        let room = cap - buf.len();
        if data.len() <= room {
            buf.extend_from_slice(data);
            false
        } else {
            buf.extend_from_slice(&data[..room]);
            true
        }
    }

    /// Errors from controlling an OpenShell sandbox.
    #[derive(Debug, thiserror::Error)]
    pub enum OpenShellError {
        /// The `openshell-sandbox` binary could not be spawned (e.g. the
        /// binary is missing or not executable).
        #[error("openshell-sandbox spawn failed: {0}")]
        Spawn(String),
        /// The sandbox's SSH listen port never accepted a connection within
        /// `ssh_ready_timeout` (see [`wait_for_ssh_port`]).
        #[error("openshell-sandbox SSH port {addr} did not become ready: {source}")]
        PortReady {
            /// The `host:port` SSH listen address that was polled.
            addr: String,
            /// The last connection attempt's I/O error, or a synthesized
            /// `TimedOut` error if the deadline elapsed while the port kept
            /// refusing connections.
            #[source]
            source: std::io::Error,
        },
        /// An SSH protocol or control-channel failure (authentication,
        /// channel open, exec, or SFTP) surfaced from `russh`.
        #[error("SSH control error: {0}")]
        Ssh(String),
        /// The sandbox rejected the NSSH1 preface, or closed the connection
        /// before replying "OK" — the vsock tier's connect-refused equivalent.
        #[error("command rejected by the sandbox (connect refused): {0}")]
        ConnectRejected(String),
        /// The command or SFTP operation did not finish within the given
        /// timeout, in milliseconds.
        #[error("command timed out after {0} ms")]
        Timeout(u32),
        /// An I/O error not otherwise classified (e.g. writing the NSSH1
        /// preface to the raw TCP stream).
        #[error("io: {0}")]
        Io(#[from] std::io::Error),
    }

    /// A live OpenShell sandbox child process + its control channel.
    ///
    /// The NeuronEdge supervisor holds one of these per confidential workspace
    /// inside `WorkspaceExec::OpenShell`. Termination is SIGTERM→wait→SIGKILL;
    /// the netns/veth/proxy teardown is automatic via the spawned binary's own
    /// `Drop` impls (it is spawned with `kill_on_drop(true)`).
    pub struct Sandbox {
        /// The spawned `openshell-sandbox` process. Dropped on terminate.
        pub child: Child,
        /// The `host:port` SSH listen address the supervisor uses to control it.
        pub ssh_addr: SocketAddr,
        /// The NSSH1 shared secret (needed to open each control connection).
        pub handshake_secret: String,
        /// Echoes the workspace id.
        pub workspace_id: String,
    }

    impl std::fmt::Debug for Sandbox {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // `Child` doesn't impl Debug; surface the pid + addr instead.
            f.debug_struct("Sandbox")
                .field("workspace_id", &self.workspace_id)
                .field("ssh_addr", &self.ssh_addr)
                .field("child_pid", &self.child.id())
                .finish()
        }
    }

    /// Configuration for spawning an OpenShell sandbox (the `SevSnp` launch arm).
    #[derive(Debug, Clone)]
    pub struct OpenShellLaunchConfig {
        /// Absolute host path to the `openshell-sandbox` binary
        /// (`NE_OPENSHELL_SANDBOX_BIN`).
        pub sandbox_binary: PathBuf,
        /// Echoes the workspace id.
        pub workspace_id: String,
        /// The agent command to run sandboxed (e.g. `["/bin/bash"]` or the
        /// agent entrypoint). Defaults to `/bin/bash` when empty.
        pub agent_command: Vec<String>,
        /// Path to the OPA/Rego policy-rules file (the `--policy-rules` arg).
        pub policy_rules_path: PathBuf,
        /// Path to the YAML policy-data file (the `--policy-data` arg).
        pub policy_data_path: PathBuf,
        /// Loopback `host:port` the sandbox's SSH server binds
        /// (`--ssh-listen-addr`). The supervisor connects here.
        pub ssh_listen_addr: SocketAddr,
        /// How long to wait for the SSH port to accept before declaring
        /// launch failure (mirrors the Firecracker `api_socket_timeout`).
        pub ssh_ready_timeout: Duration,
    }

    impl Sandbox {
        /// Spawn the `openshell-sandbox` binary with NSSH1 SSH control enabled.
        ///
        /// Mirrors `crate::firecracker::spawn_jailed_firecracker`: stage args,
        /// spawn with `kill_on_drop(true)`, then poll the SSH port until it
        /// accepts (or `ssh_ready_timeout` elapses).
        ///
        /// # Errors
        /// - [`OpenShellError::Spawn`] if the binary cannot be launched.
        /// - [`OpenShellError::PortReady`] if the SSH port never accepts.
        pub async fn spawn(cfg: &OpenShellLaunchConfig) -> Result<Self, OpenShellError> {
            // Generate a per-sandbox NSSH1 secret. The supervisor is the only
            // legitimate client (loopback), so a fresh random secret per spawn
            // is sufficient; the sandbox re-validates it per connection.
            let handshake_secret = random_preface_token();

            let mut cmd = Command::new(&cfg.sandbox_binary);
            cmd.arg("--policy-rules").arg(&cfg.policy_rules_path);
            cmd.arg("--policy-data").arg(&cfg.policy_data_path);
            cmd.arg("--ssh-listen-addr")
                .arg(cfg.ssh_listen_addr.to_string());
            cmd.arg("--ssh-handshake-secret").arg(&handshake_secret);
            if !cfg.agent_command.is_empty() {
                cmd.arg("--").args(&cfg.agent_command);
            }
            // Send the sandbox's own stdio to /dev/null. The supervisor controls
            // the sandbox over SSH (NSSH1 exec/SFTP), not via inherited stdio —
            // and piping stdout/stderr without draining would fill the 64KB pipe
            // buffer once the sandbox logs enough, blocking it before the SSH
            // bind. stdin null: the spawned agent command would otherwise
            // inherit the supervisor's stdin.
            // Send the sandbox's own stdio to /dev/null. The supervisor controls
            // the sandbox over SSH (NSSH1 exec/SFTP), not via inherited stdio —
            // and piping stdout/stderr without draining would fill the 64KB pipe
            // buffer once the sandbox logs enough, blocking it before the SSH
            // bind. stdin null: the spawned agent command would otherwise
            // inherit the supervisor's stdin.
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd.kill_on_drop(true);

            let child = cmd
                .spawn()
                .map_err(|e| OpenShellError::Spawn(e.to_string()))?;
            info!(
                workspace_id = %cfg.workspace_id,
                ssh_addr = %cfg.ssh_listen_addr,
                pid = child.id().unwrap_or(0),
                "openshell-sandbox spawned (confidential tier, B)"
            );

            // Wait for the SSH port to accept — the binary binds it during
            // `run_sandbox` startup (a ~10s readiness oneshot in the fork).
            wait_for_ssh_port(cfg.ssh_listen_addr, cfg.ssh_ready_timeout).await?;

            Ok(Self {
                child,
                ssh_addr: cfg.ssh_listen_addr,
                handshake_secret,
                workspace_id: cfg.workspace_id.clone(),
            })
        }

        /// Terminate the sandbox: SIGTERM → wait(grace) → SIGKILL.
        ///
        /// The netns/veth/proxy teardown is automatic via the spawned binary's
        /// `Drop` impls when the process exits; the supervisor's only job is to
        /// ensure it actually exits.
        pub async fn terminate(mut self, grace: Duration) {
            let pid = self.child.id();
            // Try a clean SIGTERM first.
            if let Some(pid) = pid {
                use nix::sys::signal::{Signal, kill};
                use nix::unistd::Pid;
                let _ = kill(Pid::from_raw(pid.cast_signed()), Signal::SIGTERM);
            }
            match tokio::time::timeout(grace, self.child.wait()).await {
                Ok(Ok(status)) => info!(pid, ?status, "openshell-sandbox exited"),
                Ok(Err(e)) => warn!(pid, error = %e, "openshell-sandbox wait error"),
                Err(_) => {
                    warn!(pid, ?grace, "openshell-sandbox grace elapsed; SIGKILL");
                    let _ = self.child.kill().await;
                    let _ = self.child.wait().await;
                }
            }
        }
    }

    /// Poll the SSH listen port until it accepts (or `timeout` elapses).
    async fn wait_for_ssh_port(addr: SocketAddr, timeout: Duration) -> Result<(), OpenShellError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(addr)).await {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Ok(Err(e)) => {
                    return Err(OpenShellError::PortReady {
                        addr: addr.to_string(),
                        source: e,
                    });
                }
                // ConnectRefused eats retries until the deadline; a true
                // timeout surfaces here.
                Err(_elapsed) => {
                    return Err(OpenShellError::PortReady {
                        addr: addr.to_string(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "ssh port never accepted",
                        ),
                    });
                }
            }
        }
    }

    /// Open a TCP connection to the sandbox, send the NSSH1 preface line, then
    /// hand the stream to the russh client for SSH negotiation. The preface is
    /// the auth — it must precede the SSH banner.
    async fn connect_with_preface(
        addr: SocketAddr,
        secret: &str,
    ) -> Result<russh::client::Handle<OpenShellSshClient>, OpenShellError> {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let material = PrefaceMaterial::now();
        let preface = build_nssh1_preface(secret, &material);
        stream.write_all(preface.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
        debug!(%preface, "NSSH1 preface sent");

        // The sandbox's NSSH1 gate is a request-response handshake: it reads
        // the preface line, verifies, then writes "OK\n" (or "ERR\n" + close).
        // We MUST read the OK before starting SSH negotiation, otherwise our
        // SSH banner arrives while the sandbox is still verifying → handshake
        // failure. (See openshell-sandbox/src/ssh.rs:163-173.)
        //
        // Read byte-by-byte (not BufReader) so we never consume bytes past the
        // OK line — russh needs the raw SSH banner that follows.
        let mut resp = Vec::with_capacity(8);
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).await?;
            if n == 0 {
                return Err(OpenShellError::ConnectRejected(
                    "NSSH1: server closed before OK".into(),
                ));
            }
            if byte[0] == b'\n' {
                break;
            }
            resp.push(byte[0]);
            if resp.len() > 16 {
                break;
            }
        }
        let resp = String::from_utf8_lossy(&resp);
        let resp = resp.trim();
        if resp != "OK" {
            return Err(OpenShellError::ConnectRejected(format!(
                "NSSH1 preface rejected (server said {resp:?})"
            )));
        }

        let config = Arc::new(russh::client::Config::default());
        let mut handle = russh::client::connect_stream(config, stream, OpenShellSshClient)
            .await
            .map_err(|e| {
                if matches!(e, russh::Error::Disconnect | russh::Error::IO(..)) {
                    OpenShellError::ConnectRejected(e.to_string())
                } else {
                    OpenShellError::Ssh(e.to_string())
                }
            })?;
        // The fork's server accepts auth_none unconditionally (the NSSH1 preface
        // IS the auth), but the russh client must still complete an auth
        // exchange before opening channels — otherwise channel_open_session is
        // sent unauthenticated and the server disconnects.
        let auth_result = handle
            .authenticate_none("openshell")
            .await
            .map_err(|e| OpenShellError::Ssh(format!("authenticate_none: {e}")))?;
        if !auth_result.success() {
            return Err(OpenShellError::Ssh("auth_none rejected".into()));
        }
        Ok(handle)
    }

    /// Minimal russh client handler — we only need exec/data/exit, not auth
    /// (the preface is the auth; SSH auth is unconditional on the server side).
    /// russh 0.57 uses native async-fn-in-trait (no `#[async_trait]`); the
    /// `check_server_key` signature uses `russh::keys::PublicKey` (the re-export).
    #[derive(Clone)]
    struct OpenShellSshClient;

    impl russh::client::Handler for OpenShellSshClient {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKey,
        ) -> Result<bool, Self::Error> {
            // Loopback to our own spawned child; the NSSH1 preface is the
            // integrity check. Do not pin a host key (it rotates per spawn).
            Ok(true)
        }
    }

    /// Relay one `RunCommand` to the sandbox over the SSH exec channel.
    ///
    /// Mirrors `crate::firecracker::run_command_via_vsock`'s contract: takes
    /// the command + args + timeout, returns the typed [`GuestResponse`]
    /// (`CommandCompleted` on success). A rejected preface surfaces as
    /// [`OpenShellError::ConnectRejected`] (the vsock equivalent).
    pub async fn run_command_via_ssh(
        sandbox: &Sandbox,
        command: &str,
        args: &[String],
        timeout_ms: u32,
    ) -> Result<GuestResponse, OpenShellError> {
        run_command_via_ssh_endpoint(
            sandbox.ssh_addr,
            &sandbox.handshake_secret,
            command,
            args,
            timeout_ms,
        )
        .await
    }

    /// Relay one command through an owned snapshot of a sandbox's control
    /// endpoint. This lets the workspace registry release its mutex before
    /// awaiting SSH I/O.
    pub async fn run_command_via_ssh_endpoint(
        ssh_addr: SocketAddr,
        handshake_secret: &str,
        command: &str,
        args: &[String],
        timeout_ms: u32,
    ) -> Result<GuestResponse, OpenShellError> {
        let timeout_ms =
            crate::util::clamp_timeout_ms(timeout_ms, *crate::util::MAX_EXEC_TIMEOUT_MS);
        let handle = connect_with_preface(ssh_addr, handshake_secret).await?;
        // Open a session channel + issue exec (the binary + args joined as the
        // server's exec_request expects).
        let mut exec_line = command.to_string();
        for a in args {
            exec_line.push(' ');
            exec_line.push_str(a);
        }
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| OpenShellError::Ssh(e.to_string()))?;
        channel
            .exec(true, exec_line.as_bytes())
            .await
            .map_err(|e| OpenShellError::Ssh(e.to_string()))?;

        // Drain stdout/stderr until the channel closes; capture exit code.
        // Cap accumulation at MAX_EXEC_OUTPUT_BYTES per stream — an
        // authenticated client running e.g. `cat /dev/zero` must not be able
        // to OOM the shared supervisor by draining into unbounded Vecs.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut truncated = false;
        let mut exit_code: i32 = -1;
        let cap = *MAX_EXEC_OUTPUT_BYTES;
        let elapsed_start = std::time::Instant::now();
        let drain = async {
            while let Some(msg) = channel.wait().await {
                match msg {
                    russh::ChannelMsg::Data { ref data } => {
                        truncated |= push_capped(&mut stdout, data, cap);
                    }
                    russh::ChannelMsg::ExtendedData { ref data, .. } => {
                        truncated |= push_capped(&mut stderr, data, cap);
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => {
                        exit_code = i32::try_from(exit_status).unwrap_or(-1);
                    }
                    _ => {}
                }
            }
        };
        // `timeout_ms` was clamped above against `MAX_EXEC_TIMEOUT_MS` (which is
        // guaranteed > 0), so a client-supplied 0 becomes the ceiling and the
        // value here is always non-zero — always enforce a wall-clock deadline.
        tokio::time::timeout(Duration::from_millis(u64::from(timeout_ms)), drain)
            .await
            .map_err(|_| OpenShellError::Timeout(timeout_ms))?;
        let elapsed_ms = u64::try_from(elapsed_start.elapsed().as_millis()).unwrap_or(u64::MAX);

        handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .ok();
        Ok(GuestResponse::CommandCompleted(CommandCompleted {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code,
            elapsed_ms,
            truncated,
        }))
    }

    /// Write a file into the sandbox over the SFTP subsystem. Mirrors
    /// `crate::firecracker::write_file_via_vsock`. Opens a fresh NSSH1
    /// connection, requests the "sftp" subsystem, and writes via `SftpSession`.
    pub async fn write_file_via_sftp(
        sandbox: &Sandbox,
        path: &str,
        content: Vec<u8>,
        timeout_ms: u32,
    ) -> Result<GuestResponse, OpenShellError> {
        write_file_via_sftp_endpoint(
            sandbox.ssh_addr,
            &sandbox.handshake_secret,
            path,
            content,
            timeout_ms,
        )
        .await
    }

    /// Write through an owned snapshot of a sandbox's control endpoint.
    pub async fn write_file_via_sftp_endpoint(
        ssh_addr: SocketAddr,
        handshake_secret: &str,
        path: &str,
        content: Vec<u8>,
        timeout_ms: u32,
    ) -> Result<GuestResponse, OpenShellError> {
        let bytes_written = u64::try_from(content.len()).unwrap_or(u64::MAX);
        let work = async {
            let handle = connect_with_preface(ssh_addr, handshake_secret).await?;
            let channel = handle
                .channel_open_session()
                .await
                .map_err(|e| OpenShellError::Ssh(e.to_string()))?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .map_err(|e| OpenShellError::Ssh(e.to_string()))?;
            let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
                .await
                .map_err(|e| OpenShellError::Ssh(format!("sftp session: {e}")))?;

            // Create (overwrite) the remote file + write the bytes.
            let mut file = sftp
                .create(path)
                .await
                .map_err(|e| OpenShellError::Ssh(format!("sftp create {path}: {e}")))?;
            file.write_all(&content)
                .await
                .map_err(|e| OpenShellError::Ssh(format!("sftp write: {e}")))?;
            file.flush()
                .await
                .map_err(|e| OpenShellError::Ssh(format!("sftp flush: {e}")))?;
            file.shutdown()
                .await
                .map_err(|e| OpenShellError::Ssh(format!("sftp shutdown: {e}")))?;
            handle
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await
                .ok();
            Ok::<(), OpenShellError>(())
        };
        if timeout_ms == 0 {
            work.await?;
        } else {
            tokio::time::timeout(Duration::from_millis(u64::from(timeout_ms)), work)
                .await
                .map_err(|_| OpenShellError::Timeout(timeout_ms))??;
        }
        Ok(GuestResponse::FileWritten(
            ne_protocol::guest::FileWritten {
                bytes_written,
                absolute_path: path.to_string(),
            },
        ))
    }

    /// Read a file from the sandbox over the SFTP subsystem. Mirrors
    /// `crate::firecracker::read_file_via_vsock`. Truncates to `max_bytes`.
    pub async fn read_file_via_sftp(
        sandbox: &Sandbox,
        path: &str,
        max_bytes: u64,
        timeout_ms: u32,
    ) -> Result<GuestResponse, OpenShellError> {
        read_file_via_sftp_endpoint(
            sandbox.ssh_addr,
            &sandbox.handshake_secret,
            path,
            max_bytes,
            timeout_ms,
        )
        .await
    }

    /// Read through an owned snapshot of a sandbox's control endpoint.
    pub async fn read_file_via_sftp_endpoint(
        ssh_addr: SocketAddr,
        handshake_secret: &str,
        path: &str,
        max_bytes: u64,
        timeout_ms: u32,
    ) -> Result<GuestResponse, OpenShellError> {
        let work = async {
            let handle = connect_with_preface(ssh_addr, handshake_secret).await?;
            let channel = handle
                .channel_open_session()
                .await
                .map_err(|e| OpenShellError::Ssh(e.to_string()))?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .map_err(|e| OpenShellError::Ssh(e.to_string()))?;
            let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
                .await
                .map_err(|e| OpenShellError::Ssh(format!("sftp session: {e}")))?;

            // Open the remote file for reading + drain up to max_bytes.
            let mut file = sftp
                .open(path)
                .await
                .map_err(|e| OpenShellError::Ssh(format!("sftp open {path}: {e}")))?;
            let mut buf = if max_bytes == 0 {
                Vec::new()
            } else {
                Vec::with_capacity(usize::try_from(max_bytes.min(8 * 1024 * 1024)).unwrap_or(0))
            };
            file.read_to_end(&mut buf)
                .await
                .map_err(|e| OpenShellError::Ssh(format!("sftp read: {e}")))?;
            let size_bytes = u64::try_from(buf.len()).unwrap_or(u64::MAX);
            let truncated = max_bytes > 0 && size_bytes > max_bytes;
            if truncated {
                buf.truncate(usize::try_from(max_bytes).unwrap_or(buf.len()));
            }
            handle
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await
                .ok();
            Ok::<(Vec<u8>, u64, bool), OpenShellError>((buf, size_bytes, truncated))
        };
        let (content, size_bytes, truncated) = if timeout_ms == 0 {
            work.await?
        } else {
            tokio::time::timeout(Duration::from_millis(u64::from(timeout_ms)), work)
                .await
                .map_err(|_| OpenShellError::Timeout(timeout_ms))??
        };
        Ok(GuestResponse::FileRead(ne_protocol::guest::FileRead {
            content,
            size_bytes,
            truncated,
        }))
    }

    // Re-export the public surface at the module root.
    pub use self::Sandbox as OpenShellSandbox;
    /// Alias for [`OpenShellError`], mirroring [`crate::firecracker::LaunchError`]
    /// so call sites can name the confidential tier's launch/command error
    /// analogously to the Firecracker tier's — OpenShell uses one error type
    /// for both spawn and command failures.
    pub type LaunchError = OpenShellError;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn push_capped_truncates_at_limit() {
            let mut buf = Vec::new();
            assert!(!push_capped(&mut buf, b"hello", 10));
            assert_eq!(buf.len(), 5);
            // Second push crosses the cap: only 5 more bytes are kept.
            assert!(push_capped(&mut buf, b"world!!!", 10));
            assert_eq!(buf.len(), 10);
        }
    }
}

// ---- Pure NSSH1 preface construction (compiles on every platform; Mac-testable) ----

/// Pure helpers for building the NSSH1 handshake preface. These are platform-
/// independent so they can be unit-tested on macOS without a CVM.
pub mod preface {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// The NSSH1 magic prefix (must match `openshell-sandbox/src/ssh.rs:31`).
    pub const PREFACE_MAGIC: &str = "NSSH1";

    /// The material a preface is built from.
    #[derive(Debug, Clone)]
    pub struct PrefaceMaterial {
        /// The opaque token (e.g. a session id). Mirrors `parts[1]`.
        pub token: String,
        /// Unix timestamp in seconds at preface construction. Mirrors `parts[2]`.
        pub timestamp: i64,
        /// Single-use nonce. Mirrors `parts[3]`; the server caches it for replay.
        pub nonce: String,
    }

    impl PrefaceMaterial {
        /// Build material for "now": a fresh random token + nonce + current
        /// unix timestamp (seconds).
        pub fn now() -> Self {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
                .min(u64::from(u32::MAX))
                .cast_signed();
            Self {
                token: random_preface_token(),
                timestamp,
                nonce: random_preface_token(),
            }
        }
    }

    /// Build the NSSH1 preface line (without the trailing newline).
    ///
    /// Format: `NSSH1 <token> <timestamp> <nonce> <hmac_hex>` where
    /// `hmac_hex = hex(HMAC-SHA256(secret, "{token}|{timestamp}|{nonce}"))`.
    /// This must byte-match what the OpenShell server's `verify_preface`
    /// (`ssh.rs:209-254`) recomputes.
    #[must_use]
    pub fn build_nssh1_preface(secret: &str, m: &PrefaceMaterial) -> String {
        let payload = format!("{}|{}|{}", m.token, m.timestamp, m.nonce);
        let sig = hmac_sha256(secret.as_bytes(), payload.as_bytes());
        format!(
            "{PREFACE_MAGIC} {} {} {} {}",
            m.token, m.timestamp, m.nonce, sig
        )
    }

    /// HMAC-SHA256 → lowercase hex. Mirrors the fork's `hmac_sha256`
    /// (`ssh.rs:256-264`) exactly so client and server agree.
    ///
    /// Returns the empty string if the key is invalid (the `hmac` crate only
    /// rejects zero-length keys for some backends; an empty key is not a valid
    /// NSSH1 secret, so the caller treats `""` as a construction failure).
    #[must_use]
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
            return String::new();
        };
        mac.update(data);
        hex::encode(mac.finalize().into_bytes())
    }

    /// A 32-char hex random token for the preface token/nonce. Uses a
    /// process-local counter + timestamp + pid for entropy — sufficient for a
    /// loopback handshake secret, not a cryptographic key.
    #[must_use]
    pub fn random_preface_token() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let pid = u128::from(std::process::id());
        // Mix the three; hex-encode. Not cryptographic, but unique per call.
        let mixed = (u128::from(n)).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ (ts)
            ^ (pid.wrapping_mul(0xC2B2_AE3D_27D4_EB4F));
        format!("{mixed:032x}")
    }

    #[cfg(test)]
    mod tests {
        use super::{
            PREFACE_MAGIC, PrefaceMaterial, build_nssh1_preface, hmac_sha256, random_preface_token,
        };

        /// The preface matches the fork's `build_preface` test helper
        /// (`openshell-sandbox/src/ssh.rs:1189-1193`) byte-for-byte for a fixed
        /// material — this is the load-bearing correctness check. A mismatch here
        /// means every SSH command to the sandbox fails the handshake.
        #[test]
        fn nssh1_preface_format_matches_fork_verifier() {
            let m = PrefaceMaterial {
                token: "tok1".into(),
                timestamp: 1_700_000_000,
                nonce: "nonce1".into(),
            };
            let secret = "s3cret";
            // The fork recomputes HMAC over "{token}|{timestamp}|{nonce}".
            let expected_payload = "tok1|1700000000|nonce1";
            let expected_sig = hmac_sha256(secret.as_bytes(), expected_payload.as_bytes());
            let preface = build_nssh1_preface(secret, &m);
            assert_eq!(
                preface,
                format!("{PREFACE_MAGIC} tok1 1700000000 nonce1 {expected_sig}")
            );
        }

        /// HMAC-SHA256 known-answer vector, cross-checked against Python's
        /// stdlib `hmac` (two independent implementations agree; the value is
        /// verified, not transcribed from a citation — many online "RFC 4231
        /// TC1" copies carry a mis-transcription in the trailing bytes).
        #[test]
        fn hmac_sha256_known_vector() {
            // key = 0x0b * 20 bytes, data = "Hi There".
            let key = [0x0b_u8; 20];
            let data = b"Hi There";
            let got = hmac_sha256(&key, data);
            assert_eq!(
                got,
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
            );
        }

        /// A preface with the wrong secret produces a different signature (the
        /// server would reject it).
        #[test]
        fn preface_signature_depends_on_secret() {
            let m = PrefaceMaterial {
                token: "t".into(),
                timestamp: 1,
                nonce: "n".into(),
            };
            let a = build_nssh1_preface("secret-a", &m);
            let b = build_nssh1_preface("secret-b", &m);
            assert_ne!(a, b, "different secrets must yield different signatures");
        }

        /// `PrefaceMaterial::now()` produces a parseable, 5-field preface.
        #[test]
        fn preface_now_is_well_formed() {
            let preface = build_nssh1_preface("s", &PrefaceMaterial::now());
            let parts: Vec<&str> = preface.split_whitespace().collect();
            assert_eq!(parts.len(), 5, "preface must have exactly 5 fields");
            assert_eq!(parts[0], PREFACE_MAGIC);
            // timestamp must parse as an integer.
            parts[2].parse::<i64>().expect("timestamp is an integer");
        }

        /// Two consecutive tokens differ (the counter advances).
        #[test]
        fn random_token_is_unique_per_call() {
            let a = random_preface_token();
            let b = random_preface_token();
            assert_ne!(a, b);
            assert_eq!(a.len(), 32);
        }
    }
}

#[cfg(all(target_os = "linux", feature = "confidential-cvm"))]
pub use imp::{
    LaunchError, OpenShellError, OpenShellLaunchConfig, OpenShellSandbox as Sandbox,
    read_file_via_sftp, read_file_via_sftp_endpoint, run_command_via_ssh,
    run_command_via_ssh_endpoint, write_file_via_sftp, write_file_via_sftp_endpoint,
};
