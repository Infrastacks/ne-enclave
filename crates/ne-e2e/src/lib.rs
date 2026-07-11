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

/// Populate a temporary managed image store from e2e fixture artifacts.
pub fn prepare_managed_images(
    store: &std::path::Path,
    kernel: &std::path::Path,
    rootfs: &std::path::Path,
) -> (String, String) {
    use sha2::Digest as _;

    let kernel_bytes = std::fs::read(kernel).expect("read e2e kernel");
    let rootfs_bytes = std::fs::read(rootfs).expect("read e2e rootfs");
    let kernel_sha256 = hex::encode(sha2::Sha256::digest(&kernel_bytes));
    let rootfs_sha256 = hex::encode(sha2::Sha256::digest(&rootfs_bytes));
    let kernel_path = store.join("kernels").join(&kernel_sha256).join("vmlinux");
    let rootfs_path = store.join("rootfs").join(&rootfs_sha256).join("rootfs.img");
    std::fs::create_dir_all(kernel_path.parent().unwrap()).expect("kernel image dir");
    std::fs::create_dir_all(rootfs_path.parent().unwrap()).expect("rootfs image dir");
    std::fs::write(kernel_path, kernel_bytes).expect("managed e2e kernel");
    std::fs::write(rootfs_path, rootfs_bytes).expect("managed e2e rootfs");
    (kernel_sha256, rootfs_sha256)
}
