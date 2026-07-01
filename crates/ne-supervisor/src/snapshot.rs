// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Snapshot artifact orchestration: copy FC output out of the jail chroot,
//! stream-hash mem/vmstate/rootfs, sign the manifest with the host key,
//! and write/verify `manifest.json`.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ne_protocol::snapshot::{
    GuestIdentity, MANIFEST_VERSION, SnapshotManifest, manifest_matches_hashes,
    verify_manifest_signature, verify_manifest_signature_pinned,
};
use ne_protocol::supervisor::SnapshotInfo;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

/// Errors orchestrating a snapshot artifact.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// IO error reading, writing, or hashing artifact files.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Manifest canonical-bytes construction failed.
    #[error("manifest: {0}")]
    Manifest(#[from] ne_protocol::snapshot::ManifestError),
    /// Signature or hash verification failed.
    #[error("verify: {0}")]
    Verify(#[from] ne_protocol::snapshot::VerifyError),
    /// JSON serialization or deserialization failed.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Stream the SHA-256 of a file as lowercase hex without buffering it whole.
pub async fn sha256_hex(path: &Path) -> Result<String, SnapshotError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20]; // 1 MiB
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Directory holding one snapshot artifact.
#[must_use]
pub fn snapshot_dir(state_dir: &Path, snapshot_id: &str) -> PathBuf {
    state_dir.join("snapshots").join(snapshot_id)
}

/// Build, sign, and persist `manifest.json`. `mem`/`vmstate` must already
/// be present in `snapshot_dir`. Returns the IPC `SnapshotInfo`.
#[allow(clippy::too_many_arguments)]
pub async fn write_manifest(
    snapshot_dir: &Path,
    signer: &SigningKey,
    snapshot_id: &str,
    created_from_workspace_id: &str,
    firecracker_version: &str,
    rootfs_path: &Path,
    guest_identity: GuestIdentity,
    kernel_boot_args: &str,
    kernel_path: &Path,
) -> Result<SnapshotInfo, SnapshotError> {
    let mem_path = snapshot_dir.join("mem");
    let vmstate_path = snapshot_dir.join("vmstate");
    let mem_sha256 = sha256_hex(&mem_path).await?;
    let vmstate_sha256 = sha256_hex(&vmstate_path).await?;
    let rootfs_sha256 = sha256_hex(rootfs_path).await?;
    // rootfs is referenced by path, not copied — excluded from artifact size
    let size_bytes = tokio::fs::metadata(&mem_path).await?.len()
        + tokio::fs::metadata(&vmstate_path).await?.len();

    let mut manifest = SnapshotManifest {
        manifest_version: MANIFEST_VERSION,
        snapshot_id: snapshot_id.to_string(),
        created_from_workspace_id: created_from_workspace_id.to_string(),
        firecracker_version: firecracker_version.to_string(),
        mem_sha256: mem_sha256.clone(),
        vmstate_sha256: vmstate_sha256.clone(),
        rootfs_path: rootfs_path.display().to_string(),
        rootfs_sha256,
        guest_identity,
        kernel_boot_args: kernel_boot_args.to_string(),
        kernel_path: kernel_path.display().to_string(),
        signer_pubkey_b64: B64.encode(signer.verifying_key().as_bytes()),
        signature_b64: String::new(),
    };
    let sig = signer.sign(&manifest.canonical_bytes()?);
    manifest.signature_b64 = B64.encode(sig.to_bytes());

    let json = serde_json::to_vec_pretty(&manifest)?;
    tokio::fs::write(snapshot_dir.join("manifest.json"), json).await?;

    Ok(SnapshotInfo {
        snapshot_id: snapshot_id.to_string(),
        created_from_workspace_id: created_from_workspace_id.to_string(),
        mem_sha256,
        vmstate_sha256,
        size_bytes,
        firecracker_pid: None,
    })
}

/// Read `manifest.json`. A present-but-corrupt manifest is a hard error
/// (never silently treated as absent — the 6.6 audit lesson).
pub async fn read_manifest(snapshot_dir: &Path) -> Result<SnapshotManifest, SnapshotError> {
    let bytes = tokio::fs::read(snapshot_dir.join("manifest.json")).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// **Integrity-only** end-to-end check: signature + all three file hashes.
///
/// The signature is checked against the manifest's *embedded* key, so this
/// proves the artifact is internally self-consistent but does NOT authenticate
/// the signer — for any trust decision (restore / fork) use
/// [`verify_artifact_pinned`]. Retained for the offline `nee snapshot verify`
/// diagnostic, where no host key is available.
pub async fn verify_artifact(snapshot_dir: &Path) -> Result<SnapshotManifest, SnapshotError> {
    let m = read_manifest(snapshot_dir).await?;
    verify_manifest_signature(&m)?;
    check_artifact_hashes(snapshot_dir, &m).await?;
    Ok(m)
}

/// Verify a snapshot artifact end-to-end against a **caller-pinned trust anchor**.
///
/// The signature is checked against `expected_signer` (the host's signing key;
/// the manifest-embedded key must equal it), then all three file hashes. This
/// is the authenticity-bearing verifier used on the restore / fork trust path;
/// a snapshot signed by any other key is rejected with `UntrustedSigner` before
/// its bytes are trusted.
pub async fn verify_artifact_pinned(
    snapshot_dir: &Path,
    expected_signer: &VerifyingKey,
) -> Result<SnapshotManifest, SnapshotError> {
    let m = read_manifest(snapshot_dir).await?;
    verify_manifest_signature_pinned(&m, expected_signer)?;
    check_artifact_hashes(snapshot_dir, &m).await?;
    Ok(m)
}

/// Hash the `mem` / `vmstate` / `rootfs` files and compare against the
/// manifest's recorded digests. `rootfs_path` is only opened AFTER the
/// signature has verified, so a path in a forged manifest is never touched.
async fn check_artifact_hashes(
    snapshot_dir: &Path,
    m: &SnapshotManifest,
) -> Result<(), SnapshotError> {
    let mem_h = sha256_hex(&snapshot_dir.join("mem")).await?;
    let vm_h = sha256_hex(&snapshot_dir.join("vmstate")).await?;
    let root_h = sha256_hex(Path::new(&m.rootfs_path)).await?;
    manifest_matches_hashes(m, &mem_h, &vm_h, &root_h)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sha256_matches_known_vector() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        tokio::fs::write(&p, b"abc").await.unwrap();
        assert_eq!(
            sha256_hex(&p).await.unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn sign_then_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let snap = snapshot_dir(dir.path(), "01J0SNAP");
        tokio::fs::create_dir_all(&snap).await.unwrap();
        tokio::fs::write(snap.join("mem"), b"MEM").await.unwrap();
        tokio::fs::write(snap.join("vmstate"), b"VM").await.unwrap();
        let rootfs = dir.path().join("rootfs.squashfs");
        tokio::fs::write(&rootfs, b"ROOT").await.unwrap();

        let signer = SigningKey::from_bytes(&[3u8; 32]);
        let kernel = dir.path().join("vmlinux");
        tokio::fs::write(&kernel, b"KERNEL").await.unwrap();
        let info = write_manifest(
            &snap,
            &signer,
            "01J0SNAP",
            "ws-a",
            "1.7.0",
            &rootfs,
            GuestIdentity {
                hostname: "ne-enclave".into(),
                mac: "06:00:00:00:00:01".into(),
                guest_vsock_cid: 3,
                vcpu_count: 1,
                mem_size_mib: 128,
            },
            "console=ttyS0",
            &kernel,
        )
        .await
        .unwrap();
        assert_eq!(info.snapshot_id, "01J0SNAP");

        let m = read_manifest(&snap).await.unwrap();
        verify_manifest_signature(&m).unwrap();
        let mem_h = sha256_hex(&snap.join("mem")).await.unwrap();
        let vm_h = sha256_hex(&snap.join("vmstate")).await.unwrap();
        let root_h = sha256_hex(&rootfs).await.unwrap();
        manifest_matches_hashes(&m, &mem_h, &vm_h, &root_h).unwrap();
    }

    #[tokio::test]
    async fn verify_artifact_rejects_tampered_mem() {
        let dir = tempfile::tempdir().unwrap();
        let snap = snapshot_dir(dir.path(), "01J0SNAP");
        tokio::fs::create_dir_all(&snap).await.unwrap();
        tokio::fs::write(snap.join("mem"), b"MEM").await.unwrap();
        tokio::fs::write(snap.join("vmstate"), b"VM").await.unwrap();
        let rootfs = dir.path().join("rootfs.squashfs");
        tokio::fs::write(&rootfs, b"ROOT").await.unwrap();
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        let kernel = dir.path().join("vmlinux");
        tokio::fs::write(&kernel, b"KERNEL").await.unwrap();
        write_manifest(
            &snap,
            &signer,
            "01J0SNAP",
            "ws-a",
            "1.7.0",
            &rootfs,
            GuestIdentity {
                hostname: "ne-enclave".into(),
                mac: "06:00:00:00:00:01".into(),
                guest_vsock_cid: 3,
                vcpu_count: 1,
                mem_size_mib: 128,
            },
            "console=ttyS0",
            &kernel,
        )
        .await
        .unwrap();
        // Corrupt the mem file AFTER signing — signature still valid, hash must mismatch.
        tokio::fs::write(snap.join("mem"), b"TAMPERED")
            .await
            .unwrap();
        let err = verify_artifact(&snap).await.unwrap_err();
        assert!(
            matches!(
                err,
                SnapshotError::Verify(ne_protocol::snapshot::VerifyError::HashMismatch {
                    field: "mem",
                    ..
                })
            ),
            "expected mem HashMismatch, got {err:?}"
        );
    }
}
