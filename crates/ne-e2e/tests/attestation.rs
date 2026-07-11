// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! e2e: attestation generate → client-side verify → replay rejection.
//!
//! Boots a real Firecracker microVM (no networking needed), calls
//! `get_attestation_evidence` with a fresh 32-byte nonce, verifies the
//! returned [`Evidence`] client-side with the pinned runtime signing key,
//! replays the same nonce and asserts replay rejection, then checks the
//! audit chain for `AttestationEvidenceIssued` and `AttestationReplayed` events
//! before tearing the workspace down.
//!
//! KVM-gated (`#[ignore]` by default). On the KVM host:
//! ```sh
//! cargo test -p ne-e2e --test attestation -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ne_attestation::{Nonce, Proof, ProviderType, VerifyOutcome, VerifyParams, verify};
use ne_protocol::audit::{EventType, ListEventsRequest};
use ne_protocol::supervisor::{
    CreateWorkspaceRequest, GetAttestationEvidenceRequest, SupervisorErrorKind, SupervisorResponse,
    TerminateRequest,
};
use ne_supervisor::audit::AuditLog;
use ne_supervisor::workspace::{WorkspaceManager, WorkspaceManagerConfig};

// ---------------------------------------------------------------------------
// Host env helpers (identical to ingress.rs)
// ---------------------------------------------------------------------------

struct HostEnv {
    kernel: PathBuf,
    rootfs: PathBuf,
    firecracker: PathBuf,
    jailer: PathBuf,
}

fn env_path(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

/// Returns the host paths if KVM + all required files are present, else None.
fn load_host_env() -> Option<HostEnv> {
    if !ne_e2e::host_can_launch_firecracker() {
        eprintln!("skip: /dev/kvm missing — run on a KVM host");
        return None;
    }
    let env = HostEnv {
        kernel: env_path("NE_E2E_KERNEL", "/var/lib/ne-enclave/vmlinux"),
        rootfs: env_path("NE_E2E_ROOTFS", "/var/lib/ne-enclave/rootfs.img"),
        firecracker: env_path("NE_E2E_FIRECRACKER", "/usr/local/bin/firecracker"),
        jailer: env_path("NE_E2E_JAILER", "/usr/local/bin/jailer"),
    };
    for p in [&env.kernel, &env.rootfs, &env.firecracker, &env.jailer] {
        assert!(p.is_file(), "missing required file: {}", p.display());
    }
    Some(env)
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires /dev/kvm + firecracker + root"]
async fn attestation_generate_verify_replay() {
    let Some(env) = load_host_env() else { return };

    // --- Temp dirs ---
    let tmp = tempfile::tempdir().expect("tempdir");
    let chroot_base = tmp.path().join("chroot");
    let state_dir = tmp.path().join("state");
    let image_store = tmp.path().join("images");
    let (kernel_sha256, rootfs_sha256) =
        ne_e2e::prepare_managed_images(&image_store, &env.kernel, &env.rootfs);
    tokio::fs::create_dir_all(state_dir.join("keys"))
        .await
        .expect("keys dir");
    tokio::fs::create_dir_all(&chroot_base)
        .await
        .expect("chroot dir");

    // --- Audit log ---
    let audit = AuditLog::open(&state_dir).await.expect("audit");

    // Capture the verifying key BEFORE moving `audit` into the manager
    // (borrow-after-move guard: the manager takes ownership of audit).
    let signer_vk = audit.signing_key().verifying_key();

    // --- WorkspaceManager (no networking needed for attestation) ---
    let mut cfg = WorkspaceManagerConfig::dev_defaults();
    cfg.firecracker_binary = env.firecracker.clone();
    cfg.jailer_binary = env.jailer.clone();
    cfg.chroot_base = chroot_base.clone();
    cfg.state_dir = state_dir.clone();
    cfg.image_store = image_store;
    // network stays None: attestation is purely in-process (measurement
    // is computed from the FC launch config, no vsock interaction needed).
    let mgr = Arc::new(WorkspaceManager::new(cfg, audit.clone()).expect("workspace manager"));

    // --- Step 1: Create ws-att ---
    let create_resp = mgr
        .create(CreateWorkspaceRequest {
            workspace_id: "ws-att".to_string(),
            kernel_sha256,
            rootfs_sha256,
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 128,
            guest_vsock_cid: 3,
            kernel_boot_args: None,
            network: None,
            tier: None,
        })
        .await;

    match create_resp {
        SupervisorResponse::WorkspaceCreated(ref w) => {
            eprintln!(
                "ws-att created: pid={}, vsock={}",
                w.firecracker_pid, w.vsock_host_socket
            );
        }
        other => panic!("expected WorkspaceCreated, got {other:?}"),
    }

    // --- Step 2: Generate attestation evidence ---
    let nonce_bytes = vec![5u8; 32];
    let attest_resp = mgr
        .get_attestation_evidence(GetAttestationEvidenceRequest {
            workspace_id: "ws-att".to_string(),
            nonce: nonce_bytes.clone(),
        })
        .await;

    let evidence = match attest_resp {
        SupervisorResponse::AttestationEvidenceIssued { evidence } => evidence,
        other => panic!("expected AttestationEvidenceIssued, got {other:?}"),
    };
    eprintln!(
        "attestation evidence issued: provider={:?}, ws={}, issued_at={}",
        evidence.provider_type, evidence.workspace_id, evidence.issued_at
    );

    // --- Step 3: Assert evidence fields ---
    assert_eq!(
        evidence.provider_type,
        ProviderType::Software,
        "expected Software provider type"
    );
    assert_eq!(
        evidence.workspace_id, "ws-att",
        "workspace_id mismatch in evidence"
    );
    assert_eq!(evidence.nonce, nonce_bytes, "nonce mismatch in evidence");

    // --- Step 4: Client-side verify ---
    let expected_nonce = Nonce::new(nonce_bytes.clone()).expect("nonce must be valid (32 bytes)");
    let now = evidence.issued_at + 1;
    let outcome = verify(
        &evidence,
        &VerifyParams {
            expected_nonce: &expected_nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::Software],
            freshness: Duration::from_secs(300),
            now,
            trust_anchor: ne_attestation::TrustAnchor::Software {
                expected_signer: &signer_vk,
            },
        },
    );
    assert_eq!(
        outcome,
        VerifyOutcome::Verified,
        "client-side verify must return Verified"
    );
    eprintln!("client-side verify: Verified");

    // --- Step 5: Assert embedded signer_pubkey matches the runtime key ---
    match &evidence.proof {
        Proof::Software { signer_pubkey, .. } => {
            assert_eq!(
                *signer_pubkey,
                signer_vk.to_bytes(),
                "embedded signer_pubkey must match the runtime signing key"
            );
        }
        other => panic!("expected a Software proof, got {other:?}"),
    }
    eprintln!("proof signer_pubkey matches runtime key");

    // --- Step 6: Replay the same nonce → expect AttestationReplay error ---
    let replay_resp = mgr
        .get_attestation_evidence(GetAttestationEvidenceRequest {
            workspace_id: "ws-att".to_string(),
            nonce: nonce_bytes.clone(),
        })
        .await;

    match replay_resp {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::AttestationReplay,
            ..
        } => {
            eprintln!("replay correctly rejected with AttestationReplay");
        }
        other => panic!("expected Error {{ kind: AttestationReplay }}, got {other:?}"),
    }

    // --- Step 7: Audit chain must contain AttestationEvidenceIssued + AttestationReplayed ---
    let events = audit
        .list(&ListEventsRequest {
            workspace_id: Some("ws-att".to_string()),
            since_chain_index: 0,
            limit: 100,
        })
        .await
        .expect("audit list");

    let has_issued = events
        .events
        .iter()
        .any(|e| e.event_type == EventType::AttestationEvidenceIssued);
    let has_replayed = events
        .events
        .iter()
        .any(|e| e.event_type == EventType::AttestationReplayed);

    assert!(
        has_issued,
        "audit chain must contain AttestationEvidenceIssued; events: {:?}",
        events
            .events
            .iter()
            .map(|e| e.event_type)
            .collect::<Vec<_>>()
    );
    assert!(
        has_replayed,
        "audit chain must contain AttestationReplayed; events: {:?}",
        events
            .events
            .iter()
            .map(|e| e.event_type)
            .collect::<Vec<_>>()
    );
    eprintln!("audit chain contains AttestationEvidenceIssued and AttestationReplayed");

    // --- Step 8: Teardown ---
    let term_resp = mgr
        .terminate(TerminateRequest {
            workspace_id: "ws-att".to_string(),
            grace_period_ms: 2_000,
        })
        .await;
    match &term_resp {
        SupervisorResponse::WorkspaceTerminated { workspace_id } => {
            assert_eq!(workspace_id, "ws-att");
        }
        other => panic!("expected WorkspaceTerminated, got {other:?}"),
    }
    eprintln!("ws-att terminated");

    eprintln!("attestation_generate_verify_replay: PASSED");
}
