// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Sealed-snapshot data model (ARCH §952, design §4).

use ne_attestation::{Measurement, ProviderType};
use serde::{Deserialize, Serialize};

use crate::{SealError, b64_32, b64_vec, b64_vec_option};

/// Schema version of the seal artifact.
pub const SEAL_VERSION: u32 = 1;
/// Domain-separation tag embedded in every seal signature.
pub const SEAL_DOMAIN_TAG: &str = "ne-enclave-seal-v1";
/// Domain-separation tag for the (unsigned, hashed) policy canonical form used
/// as DEK-wrap GCM associated data (R2 — stable + versioned).
pub const POLICY_DOMAIN_TAG: &str = "ne-enclave-sealing-policy-v1";

/// The attestation policy a sealed snapshot demands at restore time. Embedded
/// in the signed [`SealEnvelope`]; the gate's source of truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealingPolicy {
    /// Provider types the gate will accept (`[Software]` for dev,
    /// `[SevSnp]` for confidential prod).
    pub accept_provider_types: Vec<ProviderType>,
    /// Maximum evidence age in seconds (symmetric around `now`).
    pub freshness_seconds: u64,
    /// Trust anchor the gate pins.
    pub trust_anchor: SealingTrustAnchor,
    /// Optional per-workspace config-hash pin (the 32-byte `Measurement`,
    /// NOT the 48-byte CVM MEAS).
    pub expected_measurement: Option<Measurement>,
}

/// Owned, serializable mirror of `ne_attestation::TrustAnchor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SealingTrustAnchor {
    /// Software trust anchor: pin the expected Ed25519 verifying key.
    Software {
        /// 32-byte Ed25519 verifying key the gate pins.
        #[serde(with = "b64_32")]
        expected_signer: [u8; 32],
    },
    /// SEV-SNP trust anchor: AMD product root DER + host CVM measurement pin.
    SevSnp {
        /// AMD product (ARK) root X.509 DER the gate validates the VCEK chain to.
        #[serde(with = "b64_vec")]
        amd_product_root_der: Vec<u8>,
        /// Optional pinned 48-byte host CVM MEAS (`null` = accept any).
        #[serde(with = "b64_vec_option")]
        expected_host_cvm_meas: Option<Vec<u8>>,
        /// Minimum accepted TCB version (guest firmware/build).
        min_tcb: u64,
        /// SEV-SNP guest policy bitmap the launch demanded.
        guest_policy: u64,
    },
}

/// Where the DEK is wrapped, and how to unwrap it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KekProvider {
    /// Runtime-local software-fallback KEK (HKDF of the host Ed25519 key).
    SoftwareFallback,
    /// Control-plane KMS (future; stub returns `NotImplemented`).
    ControlPlane,
}

/// The wrapped DEK, stored inside the signed [`SealEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DekEnvelope {
    /// Which KEK provider wraps this DEK.
    pub kek_provider: KekProvider,
    /// AES-256-GCM ciphertext of the 32-byte DEK under the KEK.
    #[serde(with = "b64_vec")]
    pub wrapped_dek: Vec<u8>,
    /// GCM nonce used for the DEK wrap.
    #[serde(with = "b64_vec")]
    pub wrap_nonce: Vec<u8>,
}

/// The signed `seal.json` artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealEnvelope {
    /// Schema version of the seal (must equal [`SEAL_VERSION`]).
    pub seal_version: u32,
    /// ULID/ID of the companion encrypted snapshot this seal binds to.
    pub snapshot_id: String,
    /// Optional control-plane attestation-policy ID this seal derives from.
    pub attestation_policy_id: Option<String>,
    /// The attestation policy the restore-time gate enforces.
    pub policy: SealingPolicy,
    /// Wrapped DEK the gate must release before content decryption.
    pub dek_envelope: DekEnvelope,
    /// Hex SHA-256 of the companion snapshot manifest's canonical bytes.
    pub manifest_canonical_sha256: String,
    /// Base64 Ed25519 verifying key that signed this seal.
    pub signer_pubkey_b64: String,
    /// Base64 Ed25519 signature over [`SealEnvelope::canonical_bytes`].
    pub signature_b64: String,
}

impl SealEnvelope {
    /// Deterministic bytes signed/verified: this struct as JSON with
    /// `signature_b64` removed, keys sorted (`BTreeMap`), and the `ctx` domain
    /// tag added. Mirrors `SnapshotManifest::canonical_bytes`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SealError> {
        let mut value = serde_json::to_value(self).map_err(SealError::Serde)?;
        let Some(obj) = value.as_object_mut() else {
            return serde_json::to_vec(&value).map_err(SealError::Serde);
        };
        obj.remove("signature_b64");
        let mut sorted: std::collections::BTreeMap<String, serde_json::Value> =
            obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        sorted.insert(
            "ctx".to_string(),
            serde_json::Value::String(SEAL_DOMAIN_TAG.to_string()),
        );
        serde_json::to_vec(&sorted).map_err(SealError::Serde)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_policy() -> SealingPolicy {
        SealingPolicy {
            accept_provider_types: vec![ProviderType::Software],
            freshness_seconds: 300,
            trust_anchor: SealingTrustAnchor::Software {
                expected_signer: [9u8; 32],
            },
            expected_measurement: None,
        }
    }

    fn sample_seal(signer: &SigningKey) -> SealEnvelope {
        let mut s = SealEnvelope {
            seal_version: SEAL_VERSION,
            snapshot_id: "01J0SNAP".into(),
            attestation_policy_id: Some("att_pol_01".into()),
            policy: sample_policy(),
            dek_envelope: DekEnvelope {
                kek_provider: KekProvider::SoftwareFallback,
                wrapped_dek: vec![0u8; 48],
                wrap_nonce: vec![0u8; 12],
            },
            manifest_canonical_sha256: "deadbeef".into(),
            signer_pubkey_b64: B64.encode(signer.verifying_key().as_bytes()),
            signature_b64: String::new(),
        };
        let sig = signer.sign(&s.canonical_bytes().unwrap());
        s.signature_b64 = B64.encode(sig.to_bytes());
        s
    }

    #[test]
    fn canonical_bytes_carries_domain_tag_and_excludes_sig() {
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        let s = sample_seal(&signer);
        let bytes = s.canonical_bytes().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("\"ctx\":\"ne-enclave-seal-v1\""),
            "missing ctx: {text}"
        );
        assert!(
            !text.contains("signature_b64"),
            "signature leaked into canonical bytes"
        );
    }

    #[test]
    fn seal_serde_roundtrips() {
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        let s = sample_seal(&signer);
        let json = serde_json::to_string(&s).unwrap();
        let back: SealEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn policy_kind_tag_is_snake_case() {
        let p = sample_policy();
        let v = serde_json::to_value(&p.trust_anchor).unwrap();
        assert_eq!(v["kind"], "software");
    }
}
