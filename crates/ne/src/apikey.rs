// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Operator-facing API key generation.
//!
//! Mints a high-entropy bearer token (`nee_<base64url 32 bytes>`),
//! prints it ONCE to stdout, and appends only its SHA-256 digest to the
//! designated key file (created mode 0600 if absent). Plaintext is never
//! stored — the file is consumed by `ApiKeyStore::load`.

#![forbid(unsafe_code)]

use std::path::Path;

use base64::Engine as _;
use rand::RngCore as _;
use sha2::Digest as _;

/// Mint a new API key.
///
/// * Generates 32 random bytes via `OsRng`.
/// * Formats the token as `nee_<base64url-nopad>`.
/// * Appends `sha256:<hex>  # generated <ULID>\n` to `key_file`.
/// * Creates `key_file` with mode 0600 (Unix) if it does not exist;
///   **never** weakens an existing file's permissions.
/// * Returns the plaintext token so the caller can print it once and
///   discard it. The token is never written to `key_file`.
pub fn generate_api_key(key_file: &Path) -> anyhow::Result<String> {
    use std::io::Write as _;

    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let token = format!(
        "nee_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    );
    let hex_digest = hex::encode(sha2::Sha256::digest(token.as_bytes()));
    let line = format!("sha256:{hex_digest}  # generated {}\n", ulid::Ulid::new());

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(key_file)
        .map_err(|e| anyhow::anyhow!("opening {}: {e}", key_file.display()))?;
    f.write_all(line.as_bytes())?;

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_appends_hash_and_token_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        let token = generate_api_key(&path).unwrap();
        assert!(token.starts_with("nee_"));
        let store = ne_api::auth::ApiKeyStore::load(&path).unwrap();
        // verify returns Some(label); label is "generated <ULID>" from the appended comment.
        assert!(
            store.verify(&token).is_some(),
            "token must verify against the stored hash"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file must be 0600");
        }
    }
}
