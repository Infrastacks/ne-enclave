// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! NeuronEdge Enclave sealed snapshots (ARCH §952).
//!
//! Encrypted snapshot artifacts whose data-encryption-key (DEK) release is
//! gated runtime-locally on [`ne_attestation::verify`] passing against the
//! snapshot's embedded attestation policy. A software-fallback KEK (HKDF of
//! the host Ed25519 key) makes the path end-to-end-testable without silicon or
//! the control plane; a `key_release::KeyRelease` contract defines the
//! runtime↔control-plane key-release path (real CP KMS lands in the separate
//! BSL repo).
//!
//! **Honest claim:** the software-fallback path is at-rest /
//! confidentiality-vs-the-operator only — NOT a hardware-protection claim. The
//! hardware-rooted claim (genuine SEV-SNP evidence) is unclaimed until the
//! `SevSnp` policy path is exercised on real silicon and the real CP KMS lands.

// STANDARDS §2.1 + workspace lint config: `unwrap_used`/`expect_used` are
// surfaced via lint and suppressed under `cfg(test)` (the test module is the
// one place panicking on failure is idiomatic). This is the documented
// "test-only and cfg(test) override" the workspace relies on.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod crypto;
pub mod gate;
pub mod kek;
pub mod key_release;
#[cfg(feature = "orchestration")]
pub mod key_release_cp;
#[cfg(feature = "orchestration")]
pub mod orchestration;
pub mod types;

use thiserror::Error;

/// Errors produced by seal/unseal operations. Never carries secret material.
#[derive(Debug, Error)]
pub enum SealError {
    /// JSON (de)serialization failed.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    /// IO failure reading/writing an artifact.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Base64 decode failed.
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// An Ed25519 key or signature was malformed.
    #[error("malformed crypto material: {0}")]
    BadCrypto(String),
    /// The seal's schema version is unsupported.
    #[error("seal version {got} unsupported (this build supports {supported})")]
    UnsupportedVersion {
        /// Version found in the seal.
        got: u32,
        /// Version this build supports.
        supported: u32,
    },
    /// The seal was signed by a key other than the pinned host key.
    #[error("seal signed by an untrusted key")]
    UntrustedSigner,
    /// The seal signature is invalid.
    #[error("seal signature does not verify")]
    SignatureMismatch,
    /// The seal does not bind to its companion manifest (`snapshot_id` or
    /// `manifest_canonical_sha256` mismatch — a seal/manifest swap).
    #[error("seal does not bind to the manifest")]
    BindingMismatch,
    /// The attestation gate denied key release (`verify()` != Verified).
    #[error("attestation gate denied: {0:?}")]
    AttestationGateDenied(ne_attestation::FailReason),
    /// The DEK envelope's `kek_provider` is not served by the active release path.
    #[error("unsupported kek provider: {0:?}")]
    UnsupportedKekProvider(types::KekProvider),
    /// AES-GCM authentication failed (wrap or content ciphertext tamper/truncation).
    #[error("ciphertext failed authentication")]
    CiphertextCorrupt,
    /// The control-plane key-release path is not implemented in this wedge.
    #[error("control-plane key release is not implemented")]
    NotImplemented,
    /// A `SevSnp` policy field could not be parsed (e.g. ARK DER, MEAS length).
    #[error("sev-snp policy parse: {0}")]
    SevSnpPolicy(String),
    /// Control-plane key release failed (transport, auth, denial, or malformed
    /// response). See [`crate::key_release_cp::ControlPlaneError`].
    #[cfg(feature = "orchestration")]
    #[error("control-plane key release: {0}")]
    ControlPlaneRelease(#[from] key_release_cp::ControlPlaneError),
}

#[allow(unreachable_pub, dead_code)]
pub(crate) mod b64_vec {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[allow(unreachable_pub, dead_code)]
pub(crate) mod b64_32 {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// Base64 serde helper for `Option<Vec<u8>>` (serde-with doesn't auto-lift
/// `b64_vec` over `Option`; used by `SealingTrustAnchor::SevSnp`).
#[allow(unreachable_pub, dead_code)]
pub(crate) mod b64_vec_option {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_str(&B64.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let s = Option::<String>::deserialize(d)?;
        Ok(match s {
            Some(s) => Some(B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?),
            None => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_vec_roundtrips() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct W(#[serde(with = "b64_vec")] Vec<u8>);
        let w = W(vec![1, 2, 3, 250]);
        let s = serde_json::to_string(&w).unwrap();
        let back: W = serde_json::from_str(&s).unwrap();
        assert_eq!(back.0, w.0);
    }

    #[test]
    fn b64_32_roundtrips() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct W(#[serde(with = "b64_32")] [u8; 32]);
        let w = W([7u8; 32]);
        let s = serde_json::to_string(&w).unwrap();
        let back: W = serde_json::from_str(&s).unwrap();
        assert_eq!(back.0, w.0);
    }
}
