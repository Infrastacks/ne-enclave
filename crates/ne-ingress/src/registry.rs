// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! In-process ingress route table.
//!
//! Maps workspace IDs to their guest IP and the set of exposed ports. All
//! mutating operations take `&self` — the internal `Mutex` provides
//! interior mutability so callers share an `Arc<IngressRegistry>` without
//! needing `&mut`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex;

/// One exposed guest port and the headers to inject before forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRoute {
    /// Guest-side TCP port number.
    pub port: u16,
    /// Additional HTTP headers forwarded verbatim to the guest service.
    pub inject_headers: Vec<(String, String)>,
}

/// All routes registered for one workspace, keyed by guest port.
#[derive(Debug, Clone)]
pub struct WorkspaceRoutes {
    /// Guest-side IPv4 address (TAP bridge IP assigned at VM create time).
    pub guest_ip: Ipv4Addr,
    /// Exposed ports for this workspace.
    pub ports: HashMap<u16, PortRoute>,
}

/// Resolved upstream target for a single proxied request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Guest-side IPv4 address to connect to.
    pub guest_ip: Ipv4Addr,
    /// Port on the guest to connect to.
    pub port: u16,
    /// Headers to inject into the forwarded request.
    pub inject_headers: Vec<(String, String)>,
}

/// Errors returned by mutating registry operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    /// The requested workspace ID is not registered.
    #[error("workspace not found")]
    WorkspaceNotFound,
    /// The requested port is not exposed for this workspace.
    #[error("exposed port not found")]
    PortNotFound,
}

/// In-process ingress route table.
///
/// Owns its own `Mutex`, separate from the supervisor's Firecracker instance
/// map (mirrors the warm-pool pattern from `ne-supervisor`). Always
/// constructed via [`IngressRegistry::new`], which returns an `Arc<Self>` for
/// cheap sharing across the ingress server tasks.
#[derive(Debug, Default)]
pub struct IngressRegistry {
    inner: Mutex<HashMap<String, WorkspaceRoutes>>,
}

impl IngressRegistry {
    /// Create a new, empty registry wrapped in an `Arc`.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
        })
    }

    /// Insert or replace a workspace's routes (call on VM create).
    ///
    /// REPLACES the full port table for `wsid`: any ports previously added via
    /// [`expose_port`](Self::expose_port) are discarded in favour of `ports`.
    /// Do not call on a running workspace unless you intend to reset its
    /// exposed ports.
    pub async fn upsert_workspace(&self, wsid: &str, guest_ip: Ipv4Addr, ports: Vec<PortRoute>) {
        let ports = ports.into_iter().map(|p| (p.port, p)).collect();
        self.inner
            .lock()
            .await
            .insert(wsid.to_string(), WorkspaceRoutes { guest_ip, ports });
    }

    /// Add or replace one exposed port on an existing workspace.
    ///
    /// Returns [`RegistryError::WorkspaceNotFound`] if `wsid` is not
    /// registered.
    pub async fn expose_port(&self, wsid: &str, route: PortRoute) -> Result<(), RegistryError> {
        let mut g = self.inner.lock().await;
        let ws = g.get_mut(wsid).ok_or(RegistryError::WorkspaceNotFound)?;
        ws.ports.insert(route.port, route);
        Ok(())
    }

    /// Remove one exposed port from a workspace.
    ///
    /// Returns [`RegistryError::WorkspaceNotFound`] if the workspace is
    /// unknown, or [`RegistryError::PortNotFound`] if the port is not
    /// currently exposed.
    pub async fn unexpose_port(&self, wsid: &str, port: u16) -> Result<(), RegistryError> {
        let mut g = self.inner.lock().await;
        let ws = g.get_mut(wsid).ok_or(RegistryError::WorkspaceNotFound)?;
        ws.ports.remove(&port).ok_or(RegistryError::PortNotFound)?;
        Ok(())
    }

    /// Drop all routes for a workspace (call on VM terminate).
    ///
    /// A no-op if `wsid` was never registered.
    pub async fn remove_workspace(&self, wsid: &str) {
        self.inner.lock().await.remove(wsid);
    }

    /// Resolve `(wsid, port)` to an upstream target, or `None` if the
    /// workspace is unknown or the port is not exposed.
    pub async fn resolve(&self, wsid: &str, port: u16) -> Option<Target> {
        let g = self.inner.lock().await;
        let ws = g.get(wsid)?;
        let route = ws.ports.get(&port)?;
        Some(Target {
            guest_ip: ws.guest_ip,
            port,
            inject_headers: route.inject_headers.clone(),
        })
    }

    /// Return `true` if the workspace is registered (regardless of how many
    /// ports are exposed). Used to distinguish *unknown workspace* from
    /// *unexposed port* for audit-log clarity.
    pub async fn workspace_exists(&self, wsid: &str) -> bool {
        self.inner.lock().await.contains_key(wsid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn resolve_hits_exposed_port() {
        let r = IngressRegistry::new();
        r.upsert_workspace(
            "ws-a",
            ip("169.254.7.6"),
            vec![PortRoute {
                port: 8080,
                inject_headers: vec![],
            }],
        )
        .await;
        let t = r.resolve("ws-a", 8080).await.expect("hit");
        assert_eq!(t.guest_ip, ip("169.254.7.6"));
        assert_eq!(t.port, 8080);
    }

    #[tokio::test]
    async fn resolve_propagates_inject_headers() {
        let r = IngressRegistry::new();
        r.upsert_workspace(
            "ws-a",
            ip("169.254.7.6"),
            vec![PortRoute {
                port: 8080,
                inject_headers: vec![("X-Workspace-Id".into(), "ws-a".into())],
            }],
        )
        .await;
        let t = r.resolve("ws-a", 8080).await.expect("hit");
        assert_eq!(
            t.inject_headers,
            vec![("X-Workspace-Id".into(), "ws-a".into())]
        );
    }

    #[tokio::test]
    async fn resolve_misses_unexposed_and_unknown() {
        let r = IngressRegistry::new();
        r.upsert_workspace(
            "ws-a",
            ip("169.254.7.6"),
            vec![PortRoute {
                port: 8080,
                inject_headers: vec![],
            }],
        )
        .await;
        assert!(r.resolve("ws-a", 9090).await.is_none());
        assert!(r.resolve("ws-z", 8080).await.is_none());
    }

    #[tokio::test]
    async fn expose_then_unexpose_then_remove() {
        let r = IngressRegistry::new();
        r.upsert_workspace("ws-a", ip("169.254.7.6"), vec![]).await;
        r.expose_port(
            "ws-a",
            PortRoute {
                port: 8080,
                inject_headers: vec![],
            },
        )
        .await
        .unwrap();
        assert!(r.resolve("ws-a", 8080).await.is_some());
        r.unexpose_port("ws-a", 8080).await.unwrap();
        assert!(r.resolve("ws-a", 8080).await.is_none());
        r.expose_port(
            "ws-a",
            PortRoute {
                port: 8080,
                inject_headers: vec![],
            },
        )
        .await
        .unwrap();
        r.remove_workspace("ws-a").await;
        assert!(r.resolve("ws-a", 8080).await.is_none());
    }

    #[tokio::test]
    async fn expose_on_unknown_workspace_errors() {
        let r = IngressRegistry::new();
        let e = r
            .expose_port(
                "nope",
                PortRoute {
                    port: 1,
                    inject_headers: vec![],
                },
            )
            .await;
        assert!(matches!(e, Err(RegistryError::WorkspaceNotFound)));
    }

    #[tokio::test]
    async fn unexpose_missing_port_errors() {
        let r = IngressRegistry::new();
        r.upsert_workspace("ws-a", ip("169.254.7.6"), vec![]).await;
        assert!(matches!(
            r.unexpose_port("ws-a", 8080).await,
            Err(RegistryError::PortNotFound)
        ));
    }

    #[tokio::test]
    async fn workspace_exists_reflects_membership() {
        let r = IngressRegistry::new();
        assert!(!r.workspace_exists("ws-a").await);
        r.upsert_workspace("ws-a", ip("169.254.7.6"), vec![]).await;
        assert!(r.workspace_exists("ws-a").await);
    }
}
