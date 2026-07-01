// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Real control-plane key-release client (spec §6). Implements
//! `ControlPlaneKeyRelease` over HTTPS+JSON, replacing the `NotImplemented`
//! stub as the production CP impl. The stub is retained for tests.
//!
//! HONEST (PRD:50): the CP gate is AUTHORITATIVE; the runtime's local gate
//! (orchestration) is fail-fast defense-in-depth — a compromised host cannot be
//! trusted to gate itself. Transport = API key over TLS (mTLS is prod target).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::Zeroizing;

use crate::SealError;
use crate::key_release::ControlPlaneKeyRelease;
use crate::types::{SealEnvelope, SealingPolicy};

/// Seal-time DEK wrap against the CP (design §6.1). Narrower than
/// [`ControlPlaneKeyRelease`] (which is release-only) so the seal path does not
/// require the release transport.
///
/// Returns `(wrapped_dek, wrap_nonce)`. The runtime stores whatever the CP
/// returns verbatim in `DekEnvelope`: the SW backend returns a real 12-byte
/// nonce; the KMS backend returns an empty nonce.
pub trait CpWrapClient: Send + Sync + std::fmt::Debug {
    /// Wrap the 32-byte DEK for `snapshot_id` / `manifest_hash` under the
    /// CP-held KEK, evaluated against `policy`.
    #[allow(clippy::type_complexity)]
    fn wrap_dek<'a>(
        &'a self,
        dek: &'a [u8; 32],
        snapshot_id: &'a str,
        manifest_hash: &'a str,
        policy: &'a SealingPolicy,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<u8>, Vec<u8>), SealError>> + Send + 'a>>;
}

/// CP transport/release error. Never carries secrets.
#[derive(Debug, thiserror::Error)]
pub enum ControlPlaneError {
    /// CP explicitly denied the release (HTTP 403). Carries the CP's
    /// human-readable `reason` (attestation failure, nonce replay, …).
    #[error("control plane denied key release: {0}")]
    Denied(String),
    /// Transport-layer failure (connect, DNS, TLS, read). Carries a
    /// sanitized error string (no secrets).
    #[error("control plane transport: {0}")]
    Transport(String),
    /// CP rejected the client's credentials (HTTP 401).
    #[error("control plane unauthorized")]
    Unauthorized,
    /// CP returned a malformed/unparseable body or a DEK of the wrong size.
    #[error("control plane response malformed: {0}")]
    BadResponse(String),
    /// No CP endpoint was configured for this runtime.
    #[error("control plane not configured")]
    Unconfigured,
}

/// Injectable clock (seconds since epoch) for deterministic tests.
pub type NowFn = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Wire request to the CP `/v1/seal/release-dek` endpoint (spec §6.2).
///
/// NOTE on the two nonces (do not conflate):
/// - `wrap_nonce_b64`: the AES-GCM nonce used to wrap the DEK. Read back from
///   `seal.dek_envelope.wrap_nonce` and forwarded by the CP to `unwrap_dek`.
/// - `nonce_b64`: the attestation challenge nonce pinned by the CP. Read from
///   `evidence.nonce` (the value the runtime stamped when generating the
///   evidence).
#[derive(serde::Serialize)]
struct ReleaseReq<'a> {
    wrapped_dek_b64: String,
    wrap_nonce_b64: String,
    snapshot_id: &'a str,
    manifest_canonical_sha256: &'a str,
    policy: &'a SealingPolicy,
    evidence: &'a ne_attestation::Evidence,
    nonce_b64: String,
}

#[derive(serde::Deserialize)]
struct ReleaseOk {
    dek_b64: String,
}

#[derive(serde::Deserialize)]
struct ReleaseErr {
    reason: String,
}

/// Wire request to the CP `/v1/seal/wrap-dek` endpoint (spec §6.1, seal-time).
#[derive(serde::Serialize)]
struct WrapReq<'a> {
    dek_b64: String,
    snapshot_id: &'a str,
    manifest_canonical_sha256: &'a str,
    policy: &'a SealingPolicy,
}

#[derive(serde::Deserialize)]
struct WrapOk {
    wrapped_dek_b64: String,
    wrap_nonce_b64: String,
}

/// HTTPS client for the CP `/v1/seal/release-dek` endpoint (spec §6.2).
///
/// The client is the production CP implementation of
/// [`ControlPlaneKeyRelease`]; the `NotImplementedControlPlaneClient` stub is
/// retained in `key_release.rs` for negative tests.
pub struct ControlPlaneKeyReleaseClient {
    /// Base URL ending in `/v1` (e.g. `https://cp.example.com/v1`). The path
    /// `/seal/release-dek` is appended.
    endpoint: String,
    api_key: Zeroizing<String>,
    http: reqwest::Client,
    #[allow(dead_code)]
    now: NowFn,
}

impl std::fmt::Debug for ControlPlaneKeyReleaseClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneKeyReleaseClient")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl ControlPlaneKeyReleaseClient {
    /// Construct with a default `reqwest::Client`. `now` is an injectable
    /// clock (seconds since epoch) reserved for request freshness/future use.
    #[must_use]
    pub fn new(endpoint: String, api_key: String, now: NowFn) -> Self {
        Self {
            endpoint,
            api_key: Zeroizing::new(api_key),
            http: reqwest::Client::new(),
            now,
        }
    }

    /// Construct with an injected `reqwest::Client` (test seams / shared
    /// connection pools). `now` is the injectable clock.
    #[must_use]
    pub fn with_http(endpoint: String, api_key: String, http: reqwest::Client, now: NowFn) -> Self {
        Self {
            endpoint,
            api_key: Zeroizing::new(api_key),
            http,
            now,
        }
    }

    /// The attestation challenge nonce the CP pins. Read from `evidence.nonce`
    /// (the value the runtime stamped when minting the evidence). The CP
    /// re-derives its expected nonce from this.
    fn attestation_nonce_b64(ev: &ne_attestation::Evidence) -> String {
        B64.encode(&ev.nonce)
    }
}

impl ControlPlaneKeyRelease for ControlPlaneKeyReleaseClient {
    fn release_dek<'a>(
        &'a self,
        seal: &'a SealEnvelope,
        evidence: &'a ne_attestation::Evidence,
    ) -> Pin<Box<dyn Future<Output = Result<Zeroizing<[u8; 32]>, SealError>> + Send + 'a>> {
        Box::pin(async move {
            let body = ReleaseReq {
                wrapped_dek_b64: B64.encode(&seal.dek_envelope.wrapped_dek),
                wrap_nonce_b64: B64.encode(&seal.dek_envelope.wrap_nonce),
                snapshot_id: &seal.snapshot_id,
                manifest_canonical_sha256: &seal.manifest_canonical_sha256,
                policy: &seal.policy,
                evidence,
                nonce_b64: Self::attestation_nonce_b64(evidence),
            };
            let url = format!("{}/seal/release-dek", self.endpoint.trim_end_matches('/'));
            let resp = self
                .http
                .post(&url)
                .bearer_auth(self.api_key.as_str())
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::Transport(e.to_string()))
                })?;
            let status = resp.status();
            let text = resp.text().await.map_err(|e| {
                SealError::ControlPlaneRelease(ControlPlaneError::Transport(e.to_string()))
            })?;
            if status == reqwest::StatusCode::OK {
                let ok: ReleaseOk = serde_json::from_str(&text).map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(e.to_string()))
                })?;
                let dek = B64.decode(ok.dek_b64.as_bytes()).map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(e.to_string()))
                })?;
                let dek: [u8; 32] = dek.try_into().map_err(|_| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(
                        "dek not 32 bytes".into(),
                    ))
                })?;
                Ok(Zeroizing::new(dek))
            } else if status == reqwest::StatusCode::UNAUTHORIZED {
                Err(SealError::ControlPlaneRelease(
                    ControlPlaneError::Unauthorized,
                ))
            } else if status.as_u16() == 403 {
                let reason = serde_json::from_str::<ReleaseErr>(&text)
                    .map_or_else(|_| "denied".to_string(), |e| e.reason);
                Err(SealError::ControlPlaneRelease(ControlPlaneError::Denied(
                    reason,
                )))
            } else {
                Err(SealError::ControlPlaneRelease(
                    ControlPlaneError::Transport(format!("HTTP {status}: {text}")),
                ))
            }
        })
    }
}

impl CpWrapClient for ControlPlaneKeyReleaseClient {
    fn wrap_dek<'a>(
        &'a self,
        dek: &'a [u8; 32],
        snapshot_id: &'a str,
        manifest_hash: &'a str,
        policy: &'a SealingPolicy,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<u8>, Vec<u8>), SealError>> + Send + 'a>> {
        Box::pin(async move {
            let body = WrapReq {
                dek_b64: B64.encode(dek),
                snapshot_id,
                manifest_canonical_sha256: manifest_hash,
                policy,
            };
            let url = format!("{}/seal/wrap-dek", self.endpoint.trim_end_matches('/'));
            let resp = self
                .http
                .post(&url)
                .bearer_auth(self.api_key.as_str())
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::Transport(e.to_string()))
                })?;
            let status = resp.status();
            let text = resp.text().await.map_err(|e| {
                SealError::ControlPlaneRelease(ControlPlaneError::Transport(e.to_string()))
            })?;
            if status == reqwest::StatusCode::OK {
                let ok: WrapOk = serde_json::from_str(&text).map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(e.to_string()))
                })?;
                let wrapped = B64.decode(ok.wrapped_dek_b64.as_bytes()).map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(e.to_string()))
                })?;
                let nonce = B64.decode(ok.wrap_nonce_b64.as_bytes()).map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(e.to_string()))
                })?;
                Ok((wrapped, nonce))
            } else if status == reqwest::StatusCode::UNAUTHORIZED {
                Err(SealError::ControlPlaneRelease(
                    ControlPlaneError::Unauthorized,
                ))
            } else if status.as_u16() == 403 {
                let reason = serde_json::from_str::<ReleaseErr>(&text)
                    .map_or_else(|_| "denied".to_string(), |e| e.reason);
                Err(SealError::ControlPlaneRelease(ControlPlaneError::Denied(
                    reason,
                )))
            } else {
                Err(SealError::ControlPlaneRelease(
                    ControlPlaneError::Transport(format!("HTTP {status}: {text}")),
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        DekEnvelope, KekProvider, SEAL_VERSION, SealEnvelope, SealingPolicy, SealingTrustAnchor,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use ne_attestation::{Evidence, Measurement, ProviderType};

    fn seal_cp() -> SealEnvelope {
        SealEnvelope {
            seal_version: SEAL_VERSION,
            snapshot_id: "01S".into(),
            attestation_policy_id: None,
            policy: SealingPolicy {
                accept_provider_types: vec![ProviderType::Software],
                freshness_seconds: 300,
                trust_anchor: SealingTrustAnchor::Software {
                    expected_signer: [9u8; 32],
                },
                expected_measurement: None,
            },
            dek_envelope: DekEnvelope {
                kek_provider: KekProvider::ControlPlane,
                wrapped_dek: vec![1u8; 48],
                wrap_nonce: Vec::new(),
            },
            manifest_canonical_sha256: "mh".into(),
            signer_pubkey_b64: String::new(),
            signature_b64: String::new(),
        }
    }
    fn evidence() -> Evidence {
        Evidence {
            provider_type: ProviderType::Software,
            workspace_id: "ws".into(),
            measurement: Measurement([0u8; 32]),
            nonce: vec![1u8; 16],
            issued_at: 1_700_000_010,
            report_data: vec![],
            proof: ne_attestation::Proof::Software {
                signature: [0u8; 64],
                signer_pubkey: [9u8; 32],
            },
        }
    }

    async fn mock_cp(status: u16, body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let h = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
        (url, h)
    }

    #[tokio::test]
    async fn happy_path_returns_dek() {
        let dek = [7u8; 32];
        let body = format!(r#"{{"dek_b64":"{}"}}"#, B64.encode(dek));
        let (url, _h) = mock_cp(200, Box::leak(body.into_boxed_str())).await;
        let client =
            ControlPlaneKeyReleaseClient::new(url, "key".into(), Arc::new(|| 1_700_000_020));
        let got = client.release_dek(&seal_cp(), &evidence()).await.unwrap();
        assert_eq!(*got, dek);
    }

    #[tokio::test]
    async fn deny_403_maps_to_denied() {
        let (url, _h) = mock_cp(403, r#"{"reason":"nonce_replay"}"#).await;
        let client =
            ControlPlaneKeyReleaseClient::new(url, "key".into(), Arc::new(|| 1_700_000_020));
        let err = client
            .release_dek(&seal_cp(), &evidence())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SealError::ControlPlaneRelease(ControlPlaneError::Denied(_))
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn unauth_401_maps_to_unauthorized() {
        let (url, _h) = mock_cp(401, r#"{"reason":"bad key"}"#).await;
        let client =
            ControlPlaneKeyReleaseClient::new(url, "key".into(), Arc::new(|| 1_700_000_020));
        let err = client
            .release_dek(&seal_cp(), &evidence())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SealError::ControlPlaneRelease(ControlPlaneError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn malformed_body_maps_to_bad_response() {
        let (url, _h) = mock_cp(200, "not json").await;
        let client =
            ControlPlaneKeyReleaseClient::new(url, "key".into(), Arc::new(|| 1_700_000_020));
        let err = client
            .release_dek(&seal_cp(), &evidence())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(_))
        ));
    }

    #[tokio::test]
    async fn connection_refused_maps_to_transport() {
        // bind + immediately drop to force ECONNREFUSED
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let client =
            ControlPlaneKeyReleaseClient::new(url, "key".into(), Arc::new(|| 1_700_000_020));
        let err = client
            .release_dek(&seal_cp(), &evidence())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SealError::ControlPlaneRelease(ControlPlaneError::Transport(_))
        ));
    }
}
