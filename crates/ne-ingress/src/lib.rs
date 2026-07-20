// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Host-based ingress edge for NeuronEdge Enclave. L7 HTTP reverse proxy that routes
//! `{port}-{workspace_id}.{ingress_domain}` to a service inside the named
//! networked workspace, refusing unknown/unexposed routes.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod host;
pub mod registry;
pub mod router;
pub mod tls;

pub use host::{IngressError, parse_ingress_host};
pub use registry::{IngressRegistry, PortRoute, RegistryError, Target, WorkspaceRoutes};
pub use router::{AuditSink, Decision, DenyReason, IngressRouter, RouterConfig};
pub use tls::{TlsError, load_server_config, plaintext_listener_allowed};
