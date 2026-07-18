// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Public attestation evidence contract.

use serde::{Deserialize, Serialize};

/// Current version of the customer-visible evidence envelope.
pub const PUBLIC_EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// Attestation provider represented by a public evidence envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAttestationProvider {
    /// Software Ed25519 fallback.
    Software,
    /// Direct AMD SEV-SNP firmware report.
    SevSnpDirect,
    /// Azure SEV-SNP report with vTPM quote binding.
    SevSnpAzure,
}

/// Provider-specific proof carried by the public evidence envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "proof_type", rename_all = "snake_case")]
pub enum PublicAttestationProof {
    /// Software Ed25519 signature and public key.
    Software {
        /// Ed25519 signature bytes.
        #[serde(with = "base64_bytes")]
        signature: Vec<u8>,
        /// Ed25519 public key bytes.
        #[serde(with = "base64_bytes")]
        signer_pubkey: Vec<u8>,
    },
    /// Direct AMD SEV-SNP report and VCEK certificate chain.
    SevSnpDirect {
        /// Raw AMD SEV-SNP attestation report.
        #[serde(with = "base64_bytes")]
        report: Vec<u8>,
        /// Concatenated DER VCEK certificate chain.
        #[serde(with = "base64_bytes")]
        vcek_cert_chain: Vec<u8>,
    },
    /// Azure AMD SEV-SNP report plus vTPM quote binding.
    SevSnpAzure {
        /// Raw AMD SEV-SNP attestation report.
        #[serde(with = "base64_bytes")]
        report: Vec<u8>,
        /// Concatenated DER VCEK certificate chain.
        #[serde(with = "base64_bytes")]
        vcek_cert_chain: Vec<u8>,
        /// HCL variable data containing the attestation-key JWK.
        #[serde(with = "base64_bytes")]
        var_data: Vec<u8>,
        /// Raw `TPM2B_PUBLIC` attestation key.
        #[serde(with = "base64_bytes")]
        ak_pub_tpm2b: Vec<u8>,
        /// `TPM2B_ATTEST` quote message.
        #[serde(with = "base64_bytes")]
        quote_msg: Vec<u8>,
        /// TPM quote signature.
        #[serde(with = "base64_bytes")]
        quote_sig: Vec<u8>,
    },
}

/// Versioned, customer-visible attestation evidence envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAttestationEvidence {
    /// Public evidence schema version.
    pub schema_version: u32,
    /// Provider that generated the evidence.
    pub provider: PublicAttestationProvider,
    /// Workspace identifier bound into the evidence.
    pub workspace_id: String,
    /// Workspace launch measurement.
    #[serde(with = "base64_bytes")]
    pub workspace_measurement: Vec<u8>,
    /// Caller challenge nonce.
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,
    /// Unix timestamp in seconds when evidence was issued.
    pub issued_at: i64,
    /// Canonical report data covered by the proof.
    #[serde(with = "base64_bytes")]
    pub report_data: Vec<u8>,
    /// Provider-specific cryptographic proof.
    pub proof: PublicAttestationProof,
}

/// Validation or conversion error for the public attestation envelope.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PublicAttestationError {
    /// The schema version is not supported by this build.
    #[error("unsupported public evidence schema version {0}")]
    UnsupportedSchemaVersion(u32),
    /// The domain provider is newer than this public contract.
    #[error("unsupported attestation provider")]
    UnsupportedProvider,
    /// The domain proof is newer than this public contract.
    #[error("unsupported attestation proof")]
    UnsupportedProof,
    /// The provider enum and proof variant disagree.
    #[error("attestation provider and proof do not agree")]
    ProviderProofMismatch,
    /// Workspace measurement must be exactly 32 bytes.
    #[error("workspace measurement must be 32 bytes, got {0}")]
    InvalidMeasurementLength(usize),
    /// Nonce must be between 16 and 64 bytes.
    #[error("nonce must be 16..=64 bytes, got {0}")]
    InvalidNonceLength(usize),
    /// Software signature must be exactly 64 bytes.
    #[error("software signature must be 64 bytes, got {0}")]
    InvalidSoftwareSignatureLength(usize),
    /// Software public key must be exactly 32 bytes.
    #[error("software signer public key must be 32 bytes, got {0}")]
    InvalidSoftwareKeyLength(usize),
    /// Protobuf provider value is unknown or unspecified.
    #[error("invalid protobuf attestation provider value {0}")]
    InvalidProtobufProvider(i32),
    /// Protobuf envelope omitted its proof oneof.
    #[error("protobuf attestation evidence is missing its proof")]
    MissingProtobufProof,
}

impl TryFrom<ne_attestation::Evidence> for PublicAttestationEvidence {
    type Error = PublicAttestationError;

    fn try_from(evidence: ne_attestation::Evidence) -> Result<Self, Self::Error> {
        use ne_attestation::{Proof, ProviderType};

        if !(16..=64).contains(&evidence.nonce.len()) {
            return Err(PublicAttestationError::InvalidNonceLength(
                evidence.nonce.len(),
            ));
        }
        let provider_type = evidence.provider_type;
        let (provider, proof) = match evidence.proof {
            Proof::Software {
                signature,
                signer_pubkey,
            } => {
                ensure_domain_provider(provider_type, ProviderType::Software)?;
                (
                    PublicAttestationProvider::Software,
                    PublicAttestationProof::Software {
                        signature: signature.to_vec(),
                        signer_pubkey: signer_pubkey.to_vec(),
                    },
                )
            }
            Proof::SevSnp {
                report,
                vcek_cert_chain,
            } => {
                ensure_domain_provider(provider_type, ProviderType::SevSnp)?;
                (
                    PublicAttestationProvider::SevSnpDirect,
                    PublicAttestationProof::SevSnpDirect {
                        report,
                        vcek_cert_chain,
                    },
                )
            }
            Proof::SevSnpAzure {
                report,
                vcek_cert_chain,
                var_data,
                ak_pub_tpm2b,
                quote_msg,
                quote_sig,
            } => {
                ensure_domain_provider(provider_type, ProviderType::SevSnp)?;
                (
                    PublicAttestationProvider::SevSnpAzure,
                    PublicAttestationProof::SevSnpAzure {
                        report,
                        vcek_cert_chain,
                        var_data,
                        ak_pub_tpm2b,
                        quote_msg,
                        quote_sig,
                    },
                )
            }
            _ => return Err(PublicAttestationError::UnsupportedProof),
        };

        Ok(Self {
            schema_version: PUBLIC_EVIDENCE_SCHEMA_VERSION,
            provider,
            workspace_id: evidence.workspace_id,
            workspace_measurement: evidence.measurement.0.to_vec(),
            nonce: evidence.nonce,
            issued_at: evidence.issued_at,
            report_data: evidence.report_data,
            proof,
        })
    }
}

impl TryFrom<PublicAttestationEvidence> for ne_attestation::Evidence {
    type Error = PublicAttestationError;

    fn try_from(evidence: PublicAttestationEvidence) -> Result<Self, Self::Error> {
        use ne_attestation::{Measurement, Proof, ProviderType};

        if evidence.schema_version != PUBLIC_EVIDENCE_SCHEMA_VERSION {
            return Err(PublicAttestationError::UnsupportedSchemaVersion(
                evidence.schema_version,
            ));
        }
        let measurement_len = evidence.workspace_measurement.len();
        let measurement: [u8; 32] = evidence
            .workspace_measurement
            .try_into()
            .map_err(|_| PublicAttestationError::InvalidMeasurementLength(measurement_len))?;
        if !(16..=64).contains(&evidence.nonce.len()) {
            return Err(PublicAttestationError::InvalidNonceLength(
                evidence.nonce.len(),
            ));
        }

        let (provider_type, proof) = match (evidence.provider, evidence.proof) {
            (
                PublicAttestationProvider::Software,
                PublicAttestationProof::Software {
                    signature,
                    signer_pubkey,
                },
            ) => {
                let signature_len = signature.len();
                let signature: [u8; 64] = signature.try_into().map_err(|_| {
                    PublicAttestationError::InvalidSoftwareSignatureLength(signature_len)
                })?;
                let signer_pubkey_len = signer_pubkey.len();
                let signer_pubkey: [u8; 32] = signer_pubkey.try_into().map_err(|_| {
                    PublicAttestationError::InvalidSoftwareKeyLength(signer_pubkey_len)
                })?;
                (
                    ProviderType::Software,
                    Proof::Software {
                        signature,
                        signer_pubkey,
                    },
                )
            }
            (
                PublicAttestationProvider::SevSnpDirect,
                PublicAttestationProof::SevSnpDirect {
                    report,
                    vcek_cert_chain,
                },
            ) => (
                ProviderType::SevSnp,
                Proof::SevSnp {
                    report,
                    vcek_cert_chain,
                },
            ),
            (
                PublicAttestationProvider::SevSnpAzure,
                PublicAttestationProof::SevSnpAzure {
                    report,
                    vcek_cert_chain,
                    var_data,
                    ak_pub_tpm2b,
                    quote_msg,
                    quote_sig,
                },
            ) => (
                ProviderType::SevSnp,
                Proof::SevSnpAzure {
                    report,
                    vcek_cert_chain,
                    var_data,
                    ak_pub_tpm2b,
                    quote_msg,
                    quote_sig,
                },
            ),
            _ => return Err(PublicAttestationError::ProviderProofMismatch),
        };

        Ok(Self {
            provider_type,
            workspace_id: evidence.workspace_id,
            measurement: Measurement(measurement),
            nonce: evidence.nonce,
            issued_at: evidence.issued_at,
            report_data: evidence.report_data,
            proof,
        })
    }
}

fn ensure_domain_provider(
    actual: ne_attestation::ProviderType,
    expected: ne_attestation::ProviderType,
) -> Result<(), PublicAttestationError> {
    use ne_attestation::ProviderType;

    match actual {
        ProviderType::Software | ProviderType::SevSnp if actual == expected => Ok(()),
        ProviderType::Software | ProviderType::SevSnp => {
            Err(PublicAttestationError::ProviderProofMismatch)
        }
        _ => Err(PublicAttestationError::UnsupportedProvider),
    }
}

#[cfg(feature = "grpc")]
impl TryFrom<PublicAttestationEvidence> for crate::grpc::runtime::v1::PublicAttestationEvidence {
    type Error = PublicAttestationError;

    fn try_from(evidence: PublicAttestationEvidence) -> Result<Self, Self::Error> {
        use crate::grpc::runtime::v1 as pb;

        let _: ne_attestation::Evidence = evidence.clone().try_into()?;
        let provider = match evidence.provider {
            PublicAttestationProvider::Software => pb::AttestationProvider::Software,
            PublicAttestationProvider::SevSnpDirect => pb::AttestationProvider::SevSnpDirect,
            PublicAttestationProvider::SevSnpAzure => pb::AttestationProvider::SevSnpAzure,
        };
        let proof = match evidence.proof {
            PublicAttestationProof::Software {
                signature,
                signer_pubkey,
            } => pb::public_attestation_evidence::Proof::Software(pb::SoftwareProof {
                signature,
                signer_pubkey,
            }),
            PublicAttestationProof::SevSnpDirect {
                report,
                vcek_cert_chain,
            } => pb::public_attestation_evidence::Proof::SevSnpDirect(pb::SevSnpDirectProof {
                report,
                vcek_cert_chain,
            }),
            PublicAttestationProof::SevSnpAzure {
                report,
                vcek_cert_chain,
                var_data,
                ak_pub_tpm2b,
                quote_msg,
                quote_sig,
            } => pb::public_attestation_evidence::Proof::SevSnpAzure(pb::SevSnpAzureProof {
                report,
                vcek_cert_chain,
                var_data,
                ak_pub_tpm2b,
                quote_msg,
                quote_sig,
            }),
        };

        Ok(Self {
            schema_version: evidence.schema_version,
            provider: provider as i32,
            workspace_id: evidence.workspace_id,
            workspace_measurement: evidence.workspace_measurement,
            nonce: evidence.nonce,
            issued_at: evidence.issued_at,
            report_data: evidence.report_data,
            proof: Some(proof),
        })
    }
}

#[cfg(feature = "grpc")]
impl TryFrom<crate::grpc::runtime::v1::PublicAttestationEvidence> for PublicAttestationEvidence {
    type Error = PublicAttestationError;

    fn try_from(
        evidence: crate::grpc::runtime::v1::PublicAttestationEvidence,
    ) -> Result<Self, Self::Error> {
        use crate::grpc::runtime::v1 as pb;

        let provider = match pb::AttestationProvider::try_from(evidence.provider) {
            Ok(pb::AttestationProvider::Software) => PublicAttestationProvider::Software,
            Ok(pb::AttestationProvider::SevSnpDirect) => PublicAttestationProvider::SevSnpDirect,
            Ok(pb::AttestationProvider::SevSnpAzure) => PublicAttestationProvider::SevSnpAzure,
            Ok(pb::AttestationProvider::Unspecified) | Err(_) => {
                return Err(PublicAttestationError::InvalidProtobufProvider(
                    evidence.provider,
                ));
            }
        };
        let proof = match evidence
            .proof
            .ok_or(PublicAttestationError::MissingProtobufProof)?
        {
            pb::public_attestation_evidence::Proof::Software(proof) => {
                PublicAttestationProof::Software {
                    signature: proof.signature,
                    signer_pubkey: proof.signer_pubkey,
                }
            }
            pb::public_attestation_evidence::Proof::SevSnpDirect(proof) => {
                PublicAttestationProof::SevSnpDirect {
                    report: proof.report,
                    vcek_cert_chain: proof.vcek_cert_chain,
                }
            }
            pb::public_attestation_evidence::Proof::SevSnpAzure(proof) => {
                PublicAttestationProof::SevSnpAzure {
                    report: proof.report,
                    vcek_cert_chain: proof.vcek_cert_chain,
                    var_data: proof.var_data,
                    ak_pub_tpm2b: proof.ak_pub_tpm2b,
                    quote_msg: proof.quote_msg,
                    quote_sig: proof.quote_sig,
                }
            }
        };
        let public = Self {
            schema_version: evidence.schema_version,
            provider,
            workspace_id: evidence.workspace_id,
            workspace_measurement: evidence.workspace_measurement,
            nonce: evidence.nonce,
            issued_at: evidence.issued_at,
            report_data: evidence.report_data,
            proof,
        };
        let _: ne_attestation::Evidence = public.clone().try_into()?;
        Ok(public)
    }
}

mod base64_bytes {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::de::Error as _;
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ne_attestation::{Evidence, Measurement, Proof, ProviderType};

    fn azure_domain_evidence() -> Evidence {
        Evidence {
            provider_type: ProviderType::SevSnp,
            workspace_id: "ws-azure".to_string(),
            measurement: Measurement([0xa5; 32]),
            nonce: vec![0xb6; 16],
            issued_at: 1_700_000_007,
            report_data: vec![0xc7; 48],
            proof: Proof::SevSnpAzure {
                report: vec![1, 2, 3],
                vcek_cert_chain: vec![4, 5, 6],
                var_data: vec![7, 8, 9],
                ak_pub_tpm2b: vec![10, 11, 12],
                quote_msg: vec![13, 14, 15],
                quote_sig: vec![16, 17, 18],
            },
        }
    }

    fn software_domain_evidence() -> Evidence {
        Evidence {
            provider_type: ProviderType::Software,
            workspace_id: "ws-software".to_string(),
            measurement: Measurement([0x11; 32]),
            nonce: vec![0x22; 16],
            issued_at: 1_700_000_008,
            report_data: vec![0x33; 48],
            proof: Proof::Software {
                signature: [0x44; 64],
                signer_pubkey: [0x55; 32],
            },
        }
    }

    fn direct_domain_evidence() -> Evidence {
        Evidence {
            provider_type: ProviderType::SevSnp,
            workspace_id: "ws-direct".to_string(),
            measurement: Measurement([0x66; 32]),
            nonce: vec![0x77; 16],
            issued_at: 1_700_000_009,
            report_data: vec![0x88; 48],
            proof: Proof::SevSnp {
                report: vec![0x99, 0xaa],
                vcek_cert_chain: vec![0xbb, 0xcc],
            },
        }
    }

    #[test]
    fn azure_domain_public_round_trip_preserves_all_proof_fields() {
        let domain = azure_domain_evidence();
        let public = PublicAttestationEvidence::try_from(domain.clone()).expect("domain -> public");

        assert_eq!(public.schema_version, PUBLIC_EVIDENCE_SCHEMA_VERSION);
        assert_eq!(public.provider, PublicAttestationProvider::SevSnpAzure);
        let PublicAttestationProof::SevSnpAzure {
            report,
            vcek_cert_chain,
            var_data,
            ak_pub_tpm2b,
            quote_msg,
            quote_sig,
        } = &public.proof
        else {
            panic!("expected Azure proof");
        };
        assert_eq!(report, &[1, 2, 3]);
        assert_eq!(vcek_cert_chain, &[4, 5, 6]);
        assert_eq!(var_data, &[7, 8, 9]);
        assert_eq!(ak_pub_tpm2b, &[10, 11, 12]);
        assert_eq!(quote_msg, &[13, 14, 15]);
        assert_eq!(quote_sig, &[16, 17, 18]);

        let round_trip = Evidence::try_from(public).expect("public -> domain");
        assert_eq!(round_trip, domain);
    }

    #[test]
    fn software_and_direct_domain_public_round_trips_are_lossless() {
        for domain in [software_domain_evidence(), direct_domain_evidence()] {
            let public =
                PublicAttestationEvidence::try_from(domain.clone()).expect("domain -> public");
            let round_trip = Evidence::try_from(public).expect("public -> domain");
            assert_eq!(round_trip, domain);
        }
    }

    #[test]
    fn public_json_uses_base64_strings_and_rejects_invalid_base64() {
        let public =
            PublicAttestationEvidence::try_from(azure_domain_evidence()).expect("domain -> public");
        let mut json = serde_json::to_value(&public).expect("serialize");
        assert!(json["workspace_measurement"].is_string());
        assert!(json["nonce"].is_string());
        assert!(json["report_data"].is_string());
        assert!(json["proof"]["quote_sig"].is_string());

        json["proof"]["quote_sig"] = serde_json::Value::String("%%%not-base64%%%".to_string());
        assert!(serde_json::from_value::<PublicAttestationEvidence>(json).is_err());
    }

    #[test]
    fn reverse_conversion_rejects_invalid_public_contract() {
        let mut public =
            PublicAttestationEvidence::try_from(azure_domain_evidence()).expect("domain -> public");
        public.provider = PublicAttestationProvider::SevSnpDirect;
        assert!(Evidence::try_from(public).is_err());

        let mut public =
            PublicAttestationEvidence::try_from(azure_domain_evidence()).expect("domain -> public");
        public.workspace_measurement.pop();
        assert!(Evidence::try_from(public).is_err());

        let mut public =
            PublicAttestationEvidence::try_from(azure_domain_evidence()).expect("domain -> public");
        public.nonce.truncate(15);
        assert!(Evidence::try_from(public).is_err());

        let mut public =
            PublicAttestationEvidence::try_from(azure_domain_evidence()).expect("domain -> public");
        public.schema_version += 1;
        assert_eq!(
            Evidence::try_from(public).expect_err("unsupported schema"),
            PublicAttestationError::UnsupportedSchemaVersion(PUBLIC_EVIDENCE_SCHEMA_VERSION + 1)
        );

        let mut public = PublicAttestationEvidence::try_from(software_domain_evidence())
            .expect("domain -> public");
        let PublicAttestationProof::Software { signature, .. } = &mut public.proof else {
            panic!("expected software proof");
        };
        signature.pop();
        assert_eq!(
            Evidence::try_from(public).expect_err("short software signature"),
            PublicAttestationError::InvalidSoftwareSignatureLength(63)
        );

        let mut public = PublicAttestationEvidence::try_from(software_domain_evidence())
            .expect("domain -> public");
        let PublicAttestationProof::Software { signer_pubkey, .. } = &mut public.proof else {
            panic!("expected software proof");
        };
        signer_pubkey.pop();
        assert_eq!(
            Evidence::try_from(public).expect_err("short software key"),
            PublicAttestationError::InvalidSoftwareKeyLength(31)
        );
    }

    #[test]
    fn domain_conversion_rejects_invalid_nonce_length() {
        let mut domain = software_domain_evidence();
        domain.nonce.truncate(15);

        assert_eq!(
            PublicAttestationEvidence::try_from(domain)
                .expect_err("short domain nonce must be rejected"),
            PublicAttestationError::InvalidNonceLength(15)
        );
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn azure_public_protobuf_round_trip_preserves_typed_proof() {
        use crate::grpc::runtime::v1 as pb;

        let public =
            PublicAttestationEvidence::try_from(azure_domain_evidence()).expect("domain -> public");
        let protobuf =
            pb::PublicAttestationEvidence::try_from(public.clone()).expect("public -> proto");
        assert_eq!(
            protobuf.provider,
            pb::AttestationProvider::SevSnpAzure as i32
        );
        let Some(pb::public_attestation_evidence::Proof::SevSnpAzure(proof)) =
            protobuf.proof.as_ref()
        else {
            panic!("expected Azure protobuf oneof");
        };
        assert_eq!(proof.report, vec![1, 2, 3]);
        assert_eq!(proof.vcek_cert_chain, vec![4, 5, 6]);
        assert_eq!(proof.var_data, vec![7, 8, 9]);
        assert_eq!(proof.ak_pub_tpm2b, vec![10, 11, 12]);
        assert_eq!(proof.quote_msg, vec![13, 14, 15]);
        assert_eq!(proof.quote_sig, vec![16, 17, 18]);

        let round_trip = PublicAttestationEvidence::try_from(protobuf).expect("proto -> public");
        assert_eq!(round_trip, public);
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn protobuf_round_trips_all_known_providers() {
        use crate::grpc::runtime::v1 as pb;

        for domain in [
            software_domain_evidence(),
            direct_domain_evidence(),
            azure_domain_evidence(),
        ] {
            let public = PublicAttestationEvidence::try_from(domain).expect("domain -> public");
            let protobuf =
                pb::PublicAttestationEvidence::try_from(public.clone()).expect("public -> proto");
            let round_trip =
                PublicAttestationEvidence::try_from(protobuf).expect("proto -> public");
            assert_eq!(round_trip, public);
        }
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn protobuf_reverse_rejects_unspecified_provider_and_missing_proof() {
        use crate::grpc::runtime::v1 as pb;

        let public = PublicAttestationEvidence::try_from(software_domain_evidence())
            .expect("domain -> public");
        let mut protobuf =
            pb::PublicAttestationEvidence::try_from(public).expect("public -> proto");
        protobuf.provider = pb::AttestationProvider::Unspecified as i32;
        assert_eq!(
            PublicAttestationEvidence::try_from(protobuf.clone())
                .expect_err("unspecified provider"),
            PublicAttestationError::InvalidProtobufProvider(0)
        );

        protobuf.provider = 99;
        assert_eq!(
            PublicAttestationEvidence::try_from(protobuf.clone()).expect_err("unknown provider"),
            PublicAttestationError::InvalidProtobufProvider(99)
        );

        protobuf.provider = pb::AttestationProvider::Software as i32;
        protobuf.proof = None;
        assert_eq!(
            PublicAttestationEvidence::try_from(protobuf).expect_err("missing proof"),
            PublicAttestationError::MissingProtobufProof
        );
    }

    #[cfg(feature = "grpc")]
    #[test]
    #[allow(deprecated)]
    fn protobuf_response_preserves_legacy_field_one_and_adds_public_field_two() {
        use crate::grpc::runtime::v1 as pb;
        use prost::Message as _;

        let legacy = pb::GetAttestationEvidenceResponse {
            evidence: Some(pb::AttestationEvidence {
                provider_type: "software".to_string(),
                workspace_id: "ws-legacy".to_string(),
                measurement: vec![0x11; 32],
                nonce: vec![0x22; 16],
                issued_at: 1_700_000_010,
                report_data: vec![0x33; 48],
                proof: Some(pb::AttestationProof {
                    signature: vec![0x44; 64],
                    signer_pubkey: vec![0x55; 32],
                    sev_snp_report: Vec::new(),
                    sev_snp_vcek_chain: Vec::new(),
                }),
            }),
            public_evidence: None,
        }
        .encode_to_vec();
        assert_eq!(legacy.first(), Some(&0x0a), "legacy evidence remains tag 1");

        let public = PublicAttestationEvidence::try_from(software_domain_evidence())
            .expect("domain -> public");
        let public = pb::PublicAttestationEvidence::try_from(public).expect("public -> proto");
        let typed = pb::GetAttestationEvidenceResponse {
            evidence: None,
            public_evidence: Some(public),
        }
        .encode_to_vec();
        assert_eq!(typed.first(), Some(&0x12), "public evidence uses tag 2");
    }
}
