// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Library surface of the fused binary, exposed for integration tests.
// Test helpers throughout this crate use unwrap/expect idiomatically.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
pub mod apikey;
pub mod attestation_cli;
pub mod audit_cli;
pub mod install;
pub mod snapshot_cli;
pub mod tls_cli;
