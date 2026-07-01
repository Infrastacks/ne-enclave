// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! NeuronEdge Enclave privileged supervisor library.
//!
//! Per ARCH §4.2 the supervisor owns the privileged side of workspace
//! lifecycle: network namespaces, TAP devices, nftables / eBPF rules,
//! cgroups v2, Firecracker launch under jailer, snapshot coordination,
//! and resource reconciliation.
//!
//! Phase 0 surface (this commit): typed IPC server on a unix socket,
//! workspace registry, Firecracker launch path under jailer. Network
//! namespace + TAP + nftables enforcement (ARCH §4.7) land in Phase 1.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod audit;
pub mod command;
#[cfg(target_os = "linux")]
pub mod firecracker;
// `openshell` carries the NSSH1 preface helpers (pure, compiled everywhere for
// Mac tests) + the gated SSH-control `imp` (Linux + confidential-cvm only).
// Declared unconditionally so the pure preface tests run off-silicon; the
// spawn/SSH surface is cfg-gated inside the module.
pub mod ipc;
#[cfg(target_os = "linux")]
pub mod network;
pub mod openshell;
#[cfg(target_os = "linux")]
pub mod pool;
pub mod seal;
pub mod serve;
pub mod signing;
pub mod snapshot;
pub mod workspace;
