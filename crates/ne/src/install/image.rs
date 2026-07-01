// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Guest image provisioning: verify a SHA256 digest and place a file
//! into the content-addressed image store.
#![allow(unreachable_pub)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Compute the lowercase-hex SHA256 of a file.
pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

/// Verify `path` matches `expected_hex` (case-insensitive).
pub fn verify_sha256(path: &Path, expected_hex: &str) -> Result<()> {
    let got = sha256_file(path)?;
    if got.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        anyhow::bail!(
            "checksum mismatch for {}: expected {}, got {}",
            path.display(),
            expected_hex,
            got
        )
    }
}

/// Copy a verified `kind` ("kernels"/"rootfs") artifact into the
/// content-addressed store under `images_dir`, returning its final path.
pub fn import_artifact(
    images_dir: &Path,
    kind: &str,
    filename: &str,
    src: &Path,
    expected_hex: &str,
) -> Result<PathBuf> {
    verify_sha256(src, expected_hex)?;
    let dir = images_dir.join(kind).join(expected_hex);
    fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let dest = dir.join(filename);
    fs::copy(src, &dest)
        .with_context(|| format!("copy {} -> {}", src.display(), dest.display()))?;
    Ok(dest)
}

/// The default guest image shipped with this release. Digests are filled
/// from the CI-published image asset (Task 15 sets these to real values).
pub struct ImagePin {
    /// Base URL the kernel + rootfs assets are downloaded from.
    pub url_base: &'static str,
    /// Expected lowercase-hex SHA256 of the kernel asset.
    pub kernel_sha256: &'static str,
    /// Expected lowercase-hex SHA256 of the rootfs asset.
    pub rootfs_sha256: &'static str,
}

/// The default guest image pinned for this build (placeholder digests until
/// CI publishes the real asset; `fetch_default_image` guards against them).
pub const DEFAULT_IMAGE: ImagePin = ImagePin {
    // Replace with the real release asset URL + digests in Task 15.
    url_base: "https://github.com/Infrastacks/ne-enclave/releases/latest/download",
    kernel_sha256: "PLACEHOLDER_KERNEL_SHA256",
    rootfs_sha256: "PLACEHOLDER_ROOTFS_SHA256",
};

/// Download `url` to `dest` via curl (keeps the HTTP dep surface at zero).
pub fn curl_download(url: &str, dest: &Path) -> Result<()> {
    let status = std::process::Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .context("spawning curl")?;
    if !status.success() {
        anyhow::bail!("curl failed for {url} (status {status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_rejects_wrong_digest() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("vmlinux");
        fs::write(&f, b"hello").unwrap();
        assert!(verify_sha256(&f, "0".repeat(64).as_str()).is_err());
    }

    #[test]
    fn import_places_into_content_addressed_dir() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("vmlinux");
        fs::write(&src, b"kernel-bytes").unwrap();
        let digest = sha256_file(&src).unwrap();
        let images = dir.path().join("images");
        let dest = import_artifact(&images, "kernels", "vmlinux", &src, &digest).unwrap();
        assert!(dest.ends_with(format!("kernels/{digest}/vmlinux")));
        assert!(dest.exists());
    }
}
