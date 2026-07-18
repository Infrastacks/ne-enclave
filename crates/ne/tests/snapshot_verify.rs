// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

// Builds a valid artifact via ne_supervisor::snapshot::write_manifest, then
// runs `nee snapshot verify` and asserts exit 0; tampers mem and asserts non-zero.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::process::Command;

#[tokio::test]
async fn verify_accepts_good_and_rejects_tampered() {
    let dir = tempfile::tempdir().unwrap();
    let snap = ne_supervisor::snapshot::snapshot_dir(dir.path(), "01J0SNAP");
    tokio::fs::create_dir_all(&snap).await.unwrap();
    tokio::fs::write(snap.join("mem"), b"MEM").await.unwrap();
    tokio::fs::write(snap.join("vmstate"), b"VM").await.unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    ne_supervisor::snapshot::write_manifest(
        &snap,
        &signer,
        "01J0SNAP",
        "ws-a",
        "1.7.0",
        &"11".repeat(32),
        &"22".repeat(32),
        ne_protocol::snapshot::GuestIdentity {
            hostname: "ne-enclave".into(),
            mac: "unset".into(),
            guest_vsock_cid: 3,
            vcpu_count: 1,
            mem_size_mib: 128,
        },
        "console=ttyS0",
    )
    .await
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_nee");
    let ok = Command::new(bin)
        .args(["snapshot", "verify", snap.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(ok.success(), "valid artifact must verify");

    tokio::fs::write(snap.join("mem"), b"TAMPERED")
        .await
        .unwrap();
    let bad = Command::new(bin)
        .args(["snapshot", "verify", snap.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!bad.success(), "tampered artifact must fail verification");
}
