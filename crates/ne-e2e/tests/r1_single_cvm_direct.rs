// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! e2e: R1 confidential tier (B) — single-CVM-direct agent execution on Azure DCasv5.
//!
//! HOST-GATED + FEATURE-GATED: requires (1) an Azure DCasv5/ECasv5 SEV-SNP CVM with
//! `tpm2-tools` ≥ 5.2 + the `openshell-sandbox` binary installed, (2) a live
//! control-plane Worker (`NE_CP_KEY_RELEASE_ENDPOINT` + `NE_CP_API_KEY`), and
//! (3) `--features confidential-cvm` on the test invocation. `#[ignore]` everywhere
//! without a CVM; `cfg(linux)` + `cfg(feature = "confidential-cvm")` gate the body.
//!
//! This is the **R1 confidential-execution round-trip** (spec
//! `2026-06-29-r1-nested-cvm-blocked-design.md` §4). Unlike the Wedge-5
//! `sev_snp_azure` e2e (which exercises the supervisor's attestation + seal/unseal
//! path directly with NO workspace running), this e2e:
//!   - Spawns an OpenShell sandbox IN-CVM (the confidential-tier execution substrate),
//!   - Runs a command in it over the NSSH1 SSH control channel,
//!   - Exercises the Wedge-5 attestation + key-release path (reused verbatim) to
//!     prove the DEK is released only on the 2-layer hardware evidence,
//!   - Seal→unseal restores byte-identical plaintext.
//!
//! TCB = the OpenHCL paravisor + UEFI launch digest (Wedge 5), NOT guest-code
//! measurement. OpenShell's isolation is shared-kernel (Landlock/seccomp/netns),
//! NOT per-workspace hardware isolation (that is C/v2). No nested Firecracker
//! microVM is booted (R1 nesting is blocked — ARCH §6.1).
//!
//! Run manually on a provisioned Azure CVM (Worker + openshell-sandbox installed):
//! ```sh
//! NE_CP_KEY_RELEASE_ENDPOINT=https://<worker>/v1 \
//! NE_CP_API_KEY=<key> \
//! NE_OPENSHELL_SANDBOX_BIN=/opt/ne-enclave/bin/openshell-sandbox \
//! cargo test -p ne-e2e --features confidential-cvm --test r1_single_cvm_direct \
//!   -- --ignored --nocapture --test-threads=1
//! ```
//!
//! **Claim discipline:** until this passes on a named DCasv5, the R1
//! confidential-execution claim stays UNCLAIMED. The bring-up report records the
//! genuine fingerprints + the pass.

#![cfg(all(target_os = "linux", feature = "confidential-cvm"))]

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use ne_attestation::{
    AttestationProvider, AzureVtpmReportSource, EvidenceRequest, Measurement, Nonce, ProviderType,
    SevSnpProvider,
    vcek::{AMD_MILAN_ARK_DER, KdsVcekFetcher, VcekCache, VcekFetcher},
};
use ne_protocol::snapshot::{GuestIdentity, MANIFEST_VERSION, SnapshotManifest};
use ne_seal::key_release_cp::ControlPlaneKeyReleaseClient;
use ne_seal::orchestration::{seal_artifacts, unseal_artifacts};
use ne_seal::types::{KekProvider, SealingPolicy, SealingTrustAnchor};
use sha2::Digest;

fn wall_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn hex_sha256(b: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

/// `#[ignore]` real-silicon e2e: the R1 single-CVM-direct confidential-execution round-trip.
///
/// Asserts: (1) the OpenShell sandbox spawns in-CVM + a command runs over SSH;
/// (2) the Wedge-5 attestation path produces 2-layer evidence; (3) the CP gate
/// releases the DEK only on that evidence; (4) seal→unseal is byte-identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an Azure DCasv5 CVM + tpm2-tools + openshell-sandbox + a live CP Worker"]
async fn r1_single_cvm_direct_round_trip() {
    // ---- Pre-flight: confirm the R1 nesting block empirically (the load-bearing ----
    // finding that justifies the whole B pivot). /dev/kvm MUST be absent on a DCasv5
    // (AMD SEV-SNP strips the virt extensions from the leaf guest; Azure/GCP/AWS all
    // refuse nested virt in a CVM). This is the on-silicon proof of ARCH §6.1.
    assert!(
        !std::path::Path::new("/dev/kvm").exists(),
        "R1.1 nesting-block check FAILED: /dev/kvm exists on this CVM — the nesting premise \
         would not be blocked here. Re-examine before proceeding."
    );
    let cpuinfo = std::fs::read("/proc/cpuinfo").unwrap_or_default();
    let cpu_flags = String::from_utf8_lossy(&cpuinfo);
    let svm_count = cpu_flags.matches("svm").count();
    assert!(
        svm_count == 0,
        "R1.1 nesting-block check FAILED: 'svm' cpu flag present ({svm_count} matches) — \
         nested virt may be available, contradicting the AMD/Azure constraints."
    );
    eprintln!(
        "R1.1 nesting block CONFIRMED: /dev/kvm absent, no svm cpu flag (B's premise holds)."
    );

    // ---- Pre-flight: the Azure vTPM path (NVRAM 0x01400001), NOT /dev/sev-guest. ----
    let probe = Command::new("tpm2")
        .args(["nvread", "-C", "o", "0x01400001"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    assert!(
        matches!(probe, Ok(o) if o.status.success()),
        "pre-flight FAILED: tpm2_nvread -C o 0x01400001 did not succeed — not an Azure CVM, \
         or tpm2-tools missing, or needs sudo (run under `sudo -E`)."
    );
    eprintln!("pre-flight OK: HCLA blob readable from vTPM NVRAM 0x01400001.");

    // ---- Pre-flight: the openshell-sandbox binary. ----
    let sandbox_bin = std::env::var("NE_OPENSHELL_SANDBOX_BIN")
        .unwrap_or_else(|_| "/opt/ne-enclave/bin/openshell-sandbox".to_string());
    assert!(
        std::path::Path::new(&sandbox_bin).exists(),
        "pre-flight FAILED: openshell-sandbox not found at {sandbox_bin} (set NE_OPENSHELL_SANDBOX_BIN)."
    );
    eprintln!("pre-flight OK: openshell-sandbox at {sandbox_bin}.");

    // ---- 1. Spawn an OpenShell sandbox in-CVM (the confidential execution substrate). ----
    // The supervisor's create_confidential() path spawns the sandbox binary with NSSH1
    // SSH control. Here we exercise the same launch directly to prove the in-CVM
    // execution path + governance is live.
    use ne_supervisor::openshell::{OpenShellLaunchConfig, Sandbox};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    let workspace_id = format!("r1-b-{}", wall_now());
    // The OpenShell OPA engine (regorus) requires a valid Rego policy with the
    // data-passthrough rules — a bare `default allow_network` is rejected with
    // "not a valid rule path". Use the committed fixture (a minimal-but-valid
    // subset of the fork's reference sandbox-policy.rego).
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let policy_rules_path = manifest_dir.join("fixtures/sandbox-policy.rego");
    let policy_data_path = manifest_dir.join("fixtures/sandbox-policy.yaml");
    assert!(
        policy_rules_path.exists() && policy_data_path.exists(),
        "missing fixture policy"
    );

    // Bind a concrete ephemeral port (not 0) so we can connect back to the sandbox.
    let ssh_port = std::net::TcpListener::bind("127.0.0.1:0")
        .map(|l| l.local_addr().map(|a| a.port()).unwrap_or(0))
        .unwrap_or(0);
    let cfg = OpenShellLaunchConfig {
        sandbox_binary: PathBuf::from(&sandbox_bin),
        workspace_id: workspace_id.clone(),
        agent_command: vec![
            "/bin/bash".to_string(),
            "-c".to_string(),
            "sleep infinity".to_string(),
        ],
        policy_rules_path,
        policy_data_path,
        ssh_listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, ssh_port)),
        ssh_ready_timeout: Duration::from_secs(15),
    };
    let sandbox = Sandbox::spawn(&cfg).await.expect("openshell-sandbox spawn");
    eprintln!(
        "1. OpenShell sandbox spawned (confidential tier, B): pid={}, ssh={}",
        sandbox.child.id().unwrap_or(0),
        sandbox.ssh_addr
    );

    // ---- 2. Run a command in the sandbox over the NSSH1 SSH control channel. ----
    // Exercise the same run_command_via_ssh the supervisor's run_command path uses.
    let resp = ne_supervisor::openshell::run_command_via_ssh(
        &sandbox,
        "echo",
        &["r1-b-exec-ok".to_string()],
        10_000,
    )
    .await
    .expect("SSH exec in sandbox");
    let ne_protocol::guest::GuestResponse::CommandCompleted(completed) = &resp else {
        panic!("expected CommandCompleted, got {resp:?}");
    };
    assert!(
        completed.stdout.contains("r1-b-exec-ok"),
        "sandbox exec stdout mismatch: {:?}",
        completed.stdout
    );
    eprintln!(
        "2. SSH exec in sandbox OK: stdout={:?}",
        completed.stdout.trim()
    );

    // ---- 3. The Wedge-5 attestation path (reused verbatim): 2-layer evidence. ----
    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let verifying = signing_key.verifying_key();
    let azure_source = AzureVtpmReportSource::open().expect("open Azure vTPM source");
    let vcek: Arc<dyn VcekFetcher> = Arc::new(VcekCache::new(KdsVcekFetcher::new()));
    let provider = SevSnpProvider::new_azure(azure_source, vcek);
    let nonce = Nonce::new(vec![0xACu8; 32]).expect("nonce");
    let req = EvidenceRequest {
        workspace_id: workspace_id.clone(),
        measurement: Measurement([0u8; 32]),
        nonce: nonce.clone(),
    };
    let evidence = provider
        .generate(&req, wall_now())
        .expect("generate Azure evidence");
    assert_eq!(evidence.provider_type, ProviderType::SevSnp);
    eprintln!("3. Wedge-5 attestation evidence produced (2-layer binding).");

    // ---- 4. The CP key-release gate (SoftwareKms, live Worker) — DEK on HW evidence. ----
    let (endpoint, api_key) = match (
        std::env::var("NE_CP_KEY_RELEASE_ENDPOINT"),
        std::env::var("NE_CP_API_KEY"),
    ) {
        (Ok(e), Ok(k)) => (e, k),
        _ => panic!("NE_CP_KEY_RELEASE_ENDPOINT + NE_CP_API_KEY must point at the live Worker"),
    };
    let cp = ControlPlaneKeyReleaseClient::new(endpoint, api_key, Arc::new(wall_now));
    let cp_wrap: Option<&dyn ne_seal::key_release_cp::CpWrapClient> = Some(&cp);

    let tmp = tempfile::tempdir().expect("tempdir");
    let snap = tmp.path().join("snap");
    tokio::fs::create_dir_all(&snap).await.expect("dir");
    let plaintext_mem = b"R1-B-CONFIDENTIAL-MEM";
    let plaintext_vmstate = b"R1-B-CONFIDENTIAL-VMSTATE";
    tokio::fs::write(snap.join("mem"), plaintext_mem)
        .await
        .expect("write mem");
    tokio::fs::write(snap.join("vmstate"), plaintext_vmstate)
        .await
        .expect("write vmstate");

    let mut manifest = SnapshotManifest {
        manifest_version: MANIFEST_VERSION,
        snapshot_id: format!("r1-b-snap-{}", wall_now()),
        created_from_workspace_id: workspace_id.clone(),
        firecracker_version: "1.7.0".into(),
        mem_sha256: hex_sha256(plaintext_mem),
        vmstate_sha256: hex_sha256(plaintext_vmstate),
        kernel_sha256: "bb".repeat(32),
        rootfs_sha256: "cc".repeat(32),
        guest_identity: GuestIdentity {
            hostname: workspace_id.clone(),
            mac: "06:00:00:00:00:01".into(),
            guest_vsock_cid: 0,
            vcpu_count: 1,
            mem_size_mib: 128,
        },
        kernel_boot_args: "console=ttyS0".into(),
        signer_pubkey_b64: String::new(),
        signature_b64: String::new(),
    };
    // Sign the manifest (mirrors the Wedge-5 e2e).
    manifest.signer_pubkey_b64 =
        base64::engine::general_purpose::STANDARD.encode(verifying.as_bytes());
    let manifest_sig = signing_key.sign(
        &manifest
            .canonical_bytes()
            .expect("manifest canonical_bytes"),
    );
    manifest.signature_b64 =
        base64::engine::general_purpose::STANDARD.encode(manifest_sig.to_bytes());
    tokio::fs::write(
        snap.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("ser"),
    )
    .await
    .expect("write manifest.json");

    let policy = SealingPolicy {
        accept_provider_types: vec![ProviderType::SevSnp],
        freshness_seconds: 300,
        trust_anchor: SealingTrustAnchor::SevSnp {
            amd_product_root_der: AMD_MILAN_ARK_DER.to_vec(),
            expected_host_cvm_meas: None,
            min_tcb: 0,
            guest_policy: 0,
        },
        expected_measurement: None,
    };
    let envelope = seal_artifacts(
        &snap,
        &manifest,
        &signing_key,
        policy.clone(),
        KekProvider::ControlPlane,
        cp_wrap,
    )
    .await
    .expect("seal_artifacts");
    eprintln!("4. Sealed under ControlPlane KEK (WASM gate on the 2-layer evidence).");

    // ---- 5. Unseal: the CP gate releases the DEK only on the HW evidence; restore. ----
    let cp_release: Option<&dyn ne_seal::key_release::ControlPlaneKeyRelease> = Some(&cp);
    let out_mem = tmp.path().join("out_mem");
    let out_vmstate = tmp.path().join("out_vmstate");
    unseal_artifacts(
        &snap,
        &verifying,
        None,
        cp_release,
        &provider,
        &workspace_id,
        Measurement([0u8; 32]),
        wall_now(),
        &out_mem,
        &out_vmstate,
    )
    .await
    .expect("unseal_artifacts restores the plaintext");
    let restored_mem = tokio::fs::read(&out_mem).await.expect("read restored mem");
    let restored_vmstate = tokio::fs::read(&out_vmstate)
        .await
        .expect("read restored vmstate");
    assert_eq!(
        restored_mem, plaintext_mem,
        "restored mem must be byte-identical"
    );
    assert_eq!(
        restored_vmstate, plaintext_vmstate,
        "restored vmstate must be byte-identical"
    );
    eprintln!("5. Unseal byte-identical — DEK released on the 2-layer hardware evidence.");

    // ---- 6. Terminate the sandbox (SIGTERM→wait→SIGKILL; netns/veth auto-cleanup). ----
    sandbox.terminate(Duration::from_secs(5)).await;
    eprintln!("6. OpenShell sandbox terminated.");

    eprintln!("\nR1 single-CVM-direct round-trip PASSED:");
    eprintln!("  - R1.1 nesting block confirmed (/dev/kvm absent, no svm flag)");
    eprintln!("  - OpenShell sandbox spawned in-CVM + SSH exec succeeded");
    eprintln!("  - Wedge-5 attestation + CP key-release gate held on 2-layer evidence");
    eprintln!("  - seal->unseal byte-identical");
}
