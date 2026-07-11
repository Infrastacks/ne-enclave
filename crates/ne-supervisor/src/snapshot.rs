// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Snapshot artifact orchestration: copy FC output out of the jail chroot,
//! stream-hash mem/vmstate, bind the managed image digests, sign with the host key,
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

/// Failure while authenticating a snapshot and resolving its managed images.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotRestoreError {
    /// Snapshot signature, serialization, or artifact verification failed.
    #[error(transparent)]
    Artifact(#[from] SnapshotError),
    /// A managed image could not be resolved or verified.
    #[error(transparent)]
    Image(#[from] crate::image::ImageError),
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
    kernel_sha256: &str,
    rootfs_sha256: &str,
    guest_identity: GuestIdentity,
    kernel_boot_args: &str,
) -> Result<SnapshotInfo, SnapshotError> {
    let mem_path = snapshot_dir.join("mem");
    let vmstate_path = snapshot_dir.join("vmstate");
    let mem_sha256 = sha256_hex(&mem_path).await?;
    let vmstate_sha256 = sha256_hex(&vmstate_path).await?;
    // Managed images remain in the supervisor-owned content-addressed store and
    // are therefore excluded from the snapshot artifact size.
    let size_bytes = tokio::fs::metadata(&mem_path).await?.len()
        + tokio::fs::metadata(&vmstate_path).await?.len();

    let mut manifest = SnapshotManifest {
        manifest_version: MANIFEST_VERSION,
        snapshot_id: snapshot_id.to_string(),
        created_from_workspace_id: created_from_workspace_id.to_string(),
        firecracker_version: firecracker_version.to_string(),
        mem_sha256: mem_sha256.clone(),
        vmstate_sha256: vmstate_sha256.clone(),
        kernel_sha256: kernel_sha256.to_string(),
        rootfs_sha256: rootfs_sha256.to_string(),
        guest_identity,
        kernel_boot_args: kernel_boot_args.to_string(),
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

/// **Integrity-only** end-to-end check: signature + snapshot artifact hashes.
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
/// the manifest-embedded key must equal it), then both snapshot artifact hashes. This
/// is the authenticity-bearing verifier used on the restore / fork trust path;
/// a snapshot signed by any other key is rejected with `UntrustedSigner` before
/// its bytes are trusted. Managed image bytes are resolved and verified by the
/// restore path after this artifact check succeeds.
pub async fn verify_artifact_pinned(
    snapshot_dir: &Path,
    expected_signer: &VerifyingKey,
) -> Result<SnapshotManifest, SnapshotError> {
    let m = read_manifest(snapshot_dir).await?;
    verify_manifest_signature_pinned(&m, expected_signer)?;
    check_artifact_hashes(snapshot_dir, &m).await?;
    Ok(m)
}

/// Authenticate a snapshot artifact, then resolve and verify both managed
/// images named by its signed digest pair. No workspace resources are touched.
pub async fn verify_and_resolve_images(
    snapshot_dir: &Path,
    expected_signer: &VerifyingKey,
    image_store: &crate::image::ImageStore,
) -> Result<(SnapshotManifest, crate::image::VerifiedImagePair), SnapshotRestoreError> {
    let manifest = verify_artifact_pinned(snapshot_dir, expected_signer).await?;
    let images = image_store
        .resolve_pair(&manifest.kernel_sha256, &manifest.rootfs_sha256)
        .await?;
    Ok((manifest, images))
}

/// Hash the `mem` and `vmstate` files and compare against the manifest.
async fn check_artifact_hashes(
    snapshot_dir: &Path,
    m: &SnapshotManifest,
) -> Result<(), SnapshotError> {
    let mem_h = sha256_hex(&snapshot_dir.join("mem")).await?;
    let vm_h = sha256_hex(&snapshot_dir.join("vmstate")).await?;
    manifest_matches_hashes(m, &mem_h, &vm_h)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn write_managed_image(
        store: &Path,
        kind: crate::image::ImageKind,
        bytes: &[u8],
    ) -> (String, PathBuf) {
        let digest = hex::encode(Sha256::digest(bytes));
        let path = match kind {
            crate::image::ImageKind::Kernel => store.join("kernels").join(&digest).join("vmlinux"),
            crate::image::ImageKind::Rootfs => {
                store.join("rootfs").join(&digest).join("rootfs.img")
            }
        };
        tokio::fs::create_dir_all(path.parent().expect("artifact parent"))
            .await
            .unwrap();
        tokio::fs::write(&path, bytes).await.unwrap();
        (digest, path)
    }

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
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        let info = write_manifest(
            &snap,
            &signer,
            "01J0SNAP",
            "ws-a",
            "1.7.0",
            &"33".repeat(32),
            &"44".repeat(32),
            GuestIdentity {
                hostname: "ne-enclave".into(),
                mac: "06:00:00:00:00:01".into(),
                guest_vsock_cid: 3,
                vcpu_count: 1,
                mem_size_mib: 128,
            },
            "console=ttyS0",
        )
        .await
        .unwrap();
        assert_eq!(info.snapshot_id, "01J0SNAP");

        let m = read_manifest(&snap).await.unwrap();
        verify_manifest_signature(&m).unwrap();
        let mem_h = sha256_hex(&snap.join("mem")).await.unwrap();
        let vm_h = sha256_hex(&snap.join("vmstate")).await.unwrap();
        assert_eq!(m.kernel_sha256, "33".repeat(32));
        assert_eq!(m.rootfs_sha256, "44".repeat(32));
        manifest_matches_hashes(&m, &mem_h, &vm_h).unwrap();
    }

    #[tokio::test]
    async fn verify_artifact_rejects_tampered_mem() {
        let dir = tempfile::tempdir().unwrap();
        let snap = snapshot_dir(dir.path(), "01J0SNAP");
        tokio::fs::create_dir_all(&snap).await.unwrap();
        tokio::fs::write(snap.join("mem"), b"MEM").await.unwrap();
        tokio::fs::write(snap.join("vmstate"), b"VM").await.unwrap();
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        write_manifest(
            &snap,
            &signer,
            "01J0SNAP",
            "ws-a",
            "1.7.0",
            &"33".repeat(32),
            &"44".repeat(32),
            GuestIdentity {
                hostname: "ne-enclave".into(),
                mac: "06:00:00:00:00:01".into(),
                guest_vsock_cid: 3,
                vcpu_count: 1,
                mem_size_mib: 128,
            },
            "console=ttyS0",
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

    #[tokio::test]
    async fn restore_resolution_rejects_missing_kernel_before_launch() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("images");
        tokio::fs::create_dir_all(&store).await.unwrap();
        let (rootfs_sha256, _) =
            write_managed_image(&store, crate::image::ImageKind::Rootfs, b"ROOT").await;
        let kernel_sha256 = hex::encode(Sha256::digest(b"MISSING KERNEL"));
        let snap = snapshot_dir(dir.path(), "01J0SNAP");
        tokio::fs::create_dir_all(&snap).await.unwrap();
        tokio::fs::write(snap.join("mem"), b"MEM").await.unwrap();
        tokio::fs::write(snap.join("vmstate"), b"VM").await.unwrap();
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        write_manifest(
            &snap,
            &signer,
            "01J0SNAP",
            "ws-a",
            "1.7.0",
            &kernel_sha256,
            &rootfs_sha256,
            GuestIdentity {
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

        let Err(error) = verify_and_resolve_images(
            &snap,
            &signer.verifying_key(),
            &crate::image::ImageStore::new(store),
        )
        .await
        else {
            panic!("missing kernel must fail");
        };
        assert!(matches!(
            error,
            SnapshotRestoreError::Image(crate::image::ImageError::NotFound {
                kind: crate::image::ImageKind::Kernel,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn restore_resolution_rejects_mutated_rootfs() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("images");
        tokio::fs::create_dir_all(&store).await.unwrap();
        let (kernel_sha256, _) =
            write_managed_image(&store, crate::image::ImageKind::Kernel, b"KERNEL").await;
        let (rootfs_sha256, mutated_rootfs) =
            write_managed_image(&store, crate::image::ImageKind::Rootfs, b"ROOT").await;
        let snap = snapshot_dir(dir.path(), "01J0SNAP");
        tokio::fs::create_dir_all(&snap).await.unwrap();
        tokio::fs::write(snap.join("mem"), b"MEM").await.unwrap();
        tokio::fs::write(snap.join("vmstate"), b"VM").await.unwrap();
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        write_manifest(
            &snap,
            &signer,
            "01J0SNAP",
            "ws-a",
            "1.7.0",
            &kernel_sha256,
            &rootfs_sha256,
            GuestIdentity {
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
        tokio::fs::write(mutated_rootfs, b"MUTATED").await.unwrap();

        let Err(error) = verify_and_resolve_images(
            &snap,
            &signer.verifying_key(),
            &crate::image::ImageStore::new(store),
        )
        .await
        else {
            panic!("mutated rootfs must fail");
        };
        assert!(matches!(
            error,
            SnapshotRestoreError::Image(crate::image::ImageError::DigestMismatch {
                kind: crate::image::ImageKind::Rootfs,
                ..
            })
        ));
    }
}
