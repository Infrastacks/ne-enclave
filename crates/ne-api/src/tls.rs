// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TLS material for the runtime API surfaces.
//!
//! Single owner of the server certificate + private key. Loads and
//! validates operator-supplied PEM at startup (fail-fast), installs the
//! **ring** rustls crypto provider as the process default (aws-lc-rs is
//! musl-hostile and the release build targets musl), and hands the same
//! material to both transports: tonic (gRPC) via `Identity`/`ServerTlsConfig`
//! and axum via `axum_server`'s `RustlsConfig`.

#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Once;

use anyhow::Context as _;

/// Validated server TLS material (cert chain + private key), held as PEM bytes.
///
/// Both transports consume it without re-reading disk. `from_pem_files` has
/// already proven the cert chain has ≥1 certificate and the key PEM has a
/// usable key.
#[derive(Clone)]
pub struct TlsConfig {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("TlsConfig")
            .field("cert_bytes", &self.cert_pem.len())
            .finish()
    }
}

/// Install the ring crypto provider as the rustls process default exactly
/// once. Idempotent and panic-free on repeat (a second install is ignored).
pub fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Safe to ignore: ring is the ONLY provider compiled in (every TLS dep is
        // default-features=false + ring; axum-server uses tls-rustls-no-provider).
        // An Err here therefore means ring was already installed, not that a
        // different provider won. If that dep invariant ever changes, revisit.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl TlsConfig {
    /// Load the server cert chain + private key from PEM files.
    ///
    /// Validates that the certificate chain parses with ≥1 certificate and
    /// that a usable private key is present. It does NOT verify that the key
    /// corresponds to the cert — that key↔cert correspondence is enforced
    /// later by rustls when each transport builds its config, not here.
    pub fn from_pem_files(cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        let cert_pem = std::fs::read(cert_path)
            .with_context(|| format!("reading TLS certificate {}", cert_path.display()))?;
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("reading TLS private key {}", key_path.display()))?;

        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("parsing TLS certificate {}", cert_path.display()))?;
        anyhow::ensure!(
            !certs.is_empty(),
            "no certificate found in {}",
            cert_path.display()
        );

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .with_context(|| format!("parsing TLS private key {}", key_path.display()))?;
        anyhow::ensure!(
            key.is_some(),
            "no usable private key found in {}",
            key_path.display()
        );

        Ok(Self { cert_pem, key_pem })
    }

    /// Build a tonic `Identity` from the held PEM (clones into tonic).
    pub fn tonic_identity(&self) -> tonic::transport::Identity {
        tonic::transport::Identity::from_pem(&self.cert_pem, &self.key_pem)
    }

    /// Build an `axum_server` `RustlsConfig` from the held PEM. Async
    /// because that is axum-server's constructor shape.
    pub async fn axum_rustls_config(
        &self,
    ) -> std::io::Result<axum_server::tls_rustls::RustlsConfig> {
        axum_server::tls_rustls::RustlsConfig::from_pem(self.cert_pem.clone(), self.key_pem.clone())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid self-signed cert+key PEM generated via rcgen, shared
    // with the integration tests through the nee crate's helper. Here we
    // generate inline to keep this unit test self-contained.
    //
    // rcgen 0.13.x API: `generate_simple_self_signed` returns
    // `CertifiedKey { cert, key_pair }`. The plan's original code used
    // `signing_key` — corrected to `key_pair` to match the actual API.
    fn cert_and_key() -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (cert.cert.pem(), cert.key_pair.serialize_pem())
    }

    fn write(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn loads_valid_pem() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = cert_and_key();
        let cp = write(dir.path(), "cert.pem", &cert);
        let kp = write(dir.path(), "key.pem", &key);
        TlsConfig::from_pem_files(&cp, &kp).expect("valid PEM loads");
    }

    #[test]
    fn missing_cert_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (_, key) = cert_and_key();
        let kp = write(dir.path(), "key.pem", &key);
        let err = TlsConfig::from_pem_files(&dir.path().join("absent.pem"), &kp).unwrap_err();
        assert!(
            err.to_string().contains("reading TLS certificate"),
            "got: {err}"
        );
    }

    #[test]
    fn missing_key_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, _) = cert_and_key();
        let cp = write(dir.path(), "cert.pem", &cert);
        let err = TlsConfig::from_pem_files(&cp, &dir.path().join("absent.pem")).unwrap_err();
        assert!(
            err.to_string().contains("reading TLS private key"),
            "got: {err}"
        );
    }

    #[test]
    fn empty_cert_pem_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (_, key) = cert_and_key();
        let cp = write(dir.path(), "cert.pem", "not a pem\n");
        let kp = write(dir.path(), "key.pem", &key);
        let err = TlsConfig::from_pem_files(&cp, &kp).unwrap_err();
        assert!(
            err.to_string().contains("no certificate found"),
            "got: {err}"
        );
    }

    #[test]
    fn no_key_in_pem_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, _) = cert_and_key();
        let cp = write(dir.path(), "cert.pem", &cert);
        let kp = write(dir.path(), "key.pem", "not a key\n");
        let err = TlsConfig::from_pem_files(&cp, &kp).unwrap_err();
        assert!(
            err.to_string().contains("no usable private key"),
            "got: {err}"
        );
    }

    #[test]
    fn install_provider_is_idempotent() {
        install_crypto_provider();
        install_crypto_provider(); // must not panic
    }
}
