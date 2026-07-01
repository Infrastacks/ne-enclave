// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test harness for NeuronEdge Enclave.
//!
//! This crate exists to host Firecracker-dependent tests outside the
//! main workspace test pass. All meaningful code lives under `tests/`.
//!
//! Run the suite manually on a Linux host with `/dev/kvm`:
//!
//! ```sh
//! cargo test -p ne-e2e -- --ignored
//! ```

/// Returns whether the current host can launch Firecracker.
/// Used by tests to skip cleanly when KVM is unavailable.
#[must_use]
pub fn host_can_launch_firecracker() -> bool {
    std::path::Path::new("/dev/kvm").exists()
}
