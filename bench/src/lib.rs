// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! NeuronEdge Enclave public benchmark harness (`ne-bench`).
//!
//! Drives the runtime gRPC surface to measure cold-start, boot-storm, density,
//! exec-latency, and snapshot/restore benchmarks. Emits raw + summary CSV
//! and a run manifest capturing every required-reporting field. Purely a
//! measurement client — no runtime code lives here.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod benchmarks;
pub mod cli;
pub mod client;
pub mod csv;
pub mod manifest;
pub mod stats;
