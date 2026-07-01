// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Operator-facing self-signed TLS certificate generation (DEV/TEST ONLY).
//!
//! Mirrors `nee api-key generate`: writes `cert.pem` (0644) and
//! `key.pem` (0600) into an output directory and prints the paths. The
//! same `generate_self_signed_pem` helper feeds the ne-api TLS
//! integration tests, so test certs and operator dev certs come from one
//! codepath. Production deployments supply real CA-signed PEM instead.

#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::Context as _;

/// Generate a self-signed leaf cert for the given SANs and return
/// `(cert_pem, key_pem)`. ECDSA P-256 via rcgen+ring.
pub fn generate_self_signed_pem(sans: &[String]) -> anyhow::Result<(String, String)> {
    let sans = if sans.is_empty() {
        vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ]
    } else {
        sans.to_vec()
    };
    let certified =
        rcgen::generate_simple_self_signed(sans).context("generating self-signed certificate")?;
    Ok((certified.cert.pem(), certified.key_pair.serialize_pem()))
}

/// Write a self-signed cert+key into `out_dir`. Returns the two paths.
pub fn generate_cert(
    out_dir: &Path,
    sans: &[String],
) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating output dir {}", out_dir.display()))?;
    let (cert_pem, key_pem) = generate_self_signed_pem(sans)?;

    let cert_path = out_dir.join("cert.pem");
    let key_path = out_dir.join("key.pem");
    std::fs::write(&cert_path, cert_pem)
        .with_context(|| format!("writing {}", cert_path.display()))?;
    write_key_0600(&key_path, key_pem.as_bytes())?;
    Ok((cert_path, key_path))
}

/// Write `bytes` to `path`, creating it at mode 0600 (Unix).
///
/// On a re-run over an existing `key.pem` the contents are overwritten but the
/// file's existing permissions are preserved — `OpenOptions::mode` only applies
/// at creation time. This **never** weakens an existing file's permissions, but
/// it also does not re-tighten a file an operator previously loosened.
fn write_key_0600(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_loadable_cert_and_0600_key() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = generate_cert(dir.path(), &[]).unwrap();

        // Cert parses as ≥1 certificate.
        let cert_pem = std::fs::read(&cert_path).unwrap();
        let n = rustls_pemfile_count_certs(&cert_pem);
        assert!(n >= 1, "expected ≥1 cert, got {n}");

        // Key file is 0600 on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key.pem must be 0600, got {mode:o}");
        }
    }

    // Tiny inline PEM cert counter so this crate needs no rustls dep.
    fn rustls_pemfile_count_certs(pem: &[u8]) -> usize {
        std::str::from_utf8(pem)
            .unwrap()
            .matches("BEGIN CERTIFICATE")
            .count()
    }
}
