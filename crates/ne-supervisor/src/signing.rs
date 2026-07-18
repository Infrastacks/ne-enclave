// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared host Ed25519 signing key.
//!
//! The supervisor holds a single host signing identity at
//! `<state_dir>/keys/audit-signing.ed25519`. It signs both the audit
//! event chain (`crate::audit`) and snapshot manifests (`crate::snapshot`).
//! This module owns load-or-create so both consumers share one key.

use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::io;
use tracing::info;

/// Private key filename under the keys dir.
pub const PRIV_KEY_FILE: &str = "audit-signing.ed25519";
/// Public key filename under the keys dir.
pub const PUB_KEY_FILE: &str = "audit-signing.pub.ed25519";

/// Errors loading or creating the host signing key.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// IO error reading or writing key files.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Key file is malformed (wrong length, bad bytes).
    #[error("key error: {0}")]
    Key(String),
}

/// Load the host signing key from `keys_dir`, or generate+persist it on
/// first run. The private key is written `0600`, the public key `0644`.
/// `keys_dir` must already exist.
pub async fn load_or_create_signing_key(keys_dir: &Path) -> Result<SigningKey, KeyError> {
    let priv_path = keys_dir.join(PRIV_KEY_FILE);
    let pub_path = keys_dir.join(PUB_KEY_FILE);

    if priv_path.exists() {
        let bytes = tokio::fs::read(&priv_path).await?;
        if bytes.len() != 32 {
            return Err(KeyError::Key(format!(
                "{} has {} bytes, expected 32",
                priv_path.display(),
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(SigningKey::from_bytes(&arr));
    }

    // Generate a fresh keypair. ed25519-dalek 2.x takes any
    // rand_core::OsRng-compatible CSPRNG.
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    tokio::fs::write(&priv_path, signing_key.to_bytes()).await?;
    tokio::fs::write(&pub_path, verifying_key.as_bytes()).await?;
    chmod_0600(&priv_path).await?;
    info!(priv_path = %priv_path.display(), "generated new host signing key");
    Ok(signing_key)
}

#[cfg(unix)]
async fn chmod_0600(path: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generates_then_loads_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let k1 = load_or_create_signing_key(dir.path()).await.unwrap();
        let k2 = load_or_create_signing_key(dir.path()).await.unwrap();
        assert_eq!(
            k1.to_bytes(),
            k2.to_bytes(),
            "second load must return the persisted key"
        );
    }

    #[tokio::test]
    async fn rejects_wrong_length_key() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join(PRIV_KEY_FILE), b"short")
            .await
            .unwrap();
        assert!(load_or_create_signing_key(dir.path()).await.is_err());
    }
}
