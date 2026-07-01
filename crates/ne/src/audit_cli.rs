// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! CLI-side audit export/verify over the on-disk signed chain.
//!
//! Reads `<state_dir>/audit.jsonl`; uses the shared verifier in
//! `ne_protocol::audit` so the result matches the supervisor's signer.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ne_protocol::audit::{AuditEvent, AuditExportManifest, ChainVerification, verify_chain};

/// Parse a JSONL file into events (skipping blank lines).
fn read_events(jsonl: &Path) -> Result<Vec<AuditEvent>> {
    let text =
        std::fs::read_to_string(jsonl).with_context(|| format!("reading {}", jsonl.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let e: AuditEvent = serde_json::from_str(l)
            .with_context(|| format!("{}: malformed JSON on line {}", jsonl.display(), i + 1))?;
        out.push(e);
    }
    Ok(out)
}

/// Resolve a verify target to its events + optional manifest.
fn resolve_target(path: &Path) -> Result<(Vec<AuditEvent>, Option<AuditExportManifest>)> {
    if path.is_dir() {
        let events = read_events(&path.join("audit.jsonl"))?;
        // A MISSING manifest is the normal `None` case, but a PRESENT-but-
        // unparseable manifest is a hard error: silently dropping it would
        // skip the root comparison and let a damaged/truncated manifest pass
        // as clean, defeating the tamper detection this feature exists for.
        let manifest_path = path.join("manifest.json");
        let manifest = if manifest_path.exists() {
            let s = std::fs::read_to_string(&manifest_path)
                .with_context(|| format!("reading {}", manifest_path.display()))?;
            Some(
                serde_json::from_str::<AuditExportManifest>(&s)
                    .with_context(|| format!("parsing {}", manifest_path.display()))?,
            )
        } else {
            None
        };
        Ok((events, manifest))
    } else if path.file_name().is_some_and(|n| n == "manifest.json") {
        let s =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let manifest: AuditExportManifest =
            serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))?;
        let events = read_events(&path.with_file_name("audit.jsonl"))?;
        Ok((events, Some(manifest)))
    } else {
        Ok((read_events(path)?, None))
    }
}

/// `nee audit verify`. Returns `Ok(())` iff the chain verifies (and, if a
/// manifest is present, its root matches). Prints a one-line JSON result to
/// stdout; notices go to stderr.
#[allow(clippy::print_stdout)]
pub fn verify(path: &Path) -> Result<()> {
    let (events, manifest) = resolve_target(path)?;
    let v: ChainVerification = verify_chain(&events);
    let mut ok = v.ok;
    let mut detail = serde_json::to_value(&v)?;
    if let Some(m) = &manifest {
        // S5-F2: a matching `root_hex` alone does NOT prove the chain is whole —
        // front-truncation (dropping leading events) leaves the tail, and hence
        // the root, unchanged, and `verify_chain` accepts a suffix beginning at
        // chain_index != 0 as a "partial export". The manifest pins `count` /
        // `first_index` / `last_index`; require ALL of them to match so a
        // truncated-front (or otherwise resized) chain is detected, not just a
        // changed-tail one.
        if m.root_hex != v.root_hex {
            ok = false;
            detail["manifest_root_mismatch"] = serde_json::json!(true);
        }
        if m.count != v.count {
            ok = false;
            detail["manifest_count_mismatch"] = serde_json::json!(true);
        }
        if m.first_index != v.first_index {
            ok = false;
            detail["manifest_first_index_mismatch"] = serde_json::json!(true);
        }
        if m.last_index != v.last_index {
            ok = false;
            detail["manifest_last_index_mismatch"] = serde_json::json!(true);
        }
    }
    detail["ok"] = serde_json::json!(ok);
    println!("{}", serde_json::to_string(&detail)?);
    if ok {
        Ok(())
    } else {
        anyhow::bail!("audit chain verification FAILED")
    }
}

/// `nee audit export`.
///
/// Verifies first; refuses a broken chain unless `allow_broken`.
/// Writes `<out>/audit-export-<ULID>/{audit.jsonl,manifest.json}`.
/// Returns the path of the newly-created export directory.
pub fn export(state_dir: &Path, out: &Path, allow_broken: bool, now_ms: u64) -> Result<PathBuf> {
    let src = state_dir.join("audit.jsonl");
    let events = read_events(&src)?;
    if events.is_empty() {
        anyhow::bail!("no audit events found at {}", src.display());
    }
    let v: ChainVerification = verify_chain(&events);
    if !v.ok && !allow_broken {
        let (idx, reason) = v.first_error.map(|e| (e.index, e.reason)).ok_or_else(|| {
            anyhow::anyhow!("chain verification failed but produced no error detail")
        })?;
        anyhow::bail!(
            "audit chain is broken at index {idx} ({reason:?}); refusing to export. \
             Pass --allow-broken to override."
        );
    }
    let dir = out.join(format!("audit-export-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir)?;
    std::fs::copy(&src, dir.join("audit.jsonl"))?;
    let manifest = AuditExportManifest {
        count: v.count,
        first_index: v.first_index,
        last_index: v.last_index,
        root_hex: v.root_hex.clone(),
        signer_pubkey_b64: events.last().map(|e| e.signer_pubkey_b64.clone()),
        exported_at_ms: now_ms,
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
        verified: v.ok,
    };
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::{Signer, SigningKey};
    use ne_protocol::audit::{AuditEvent, EventType, canonical_bytes};
    use sha2::{Digest, Sha256};

    /// Build a real signed chain of `n` events in memory, mirroring the
    /// protocol crate's `verify_tests::signed_chain` helper.
    fn build_signed_chain(n: u64) -> Vec<AuditEvent> {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pk_b64 = B64.encode(sk.verifying_key().as_bytes());
        let mut events: Vec<AuditEvent> = Vec::new();
        for i in 0..n {
            let prev_hash_hex = events.last().map_or_else(
                || "00".repeat(32),
                |p| hex::encode(Sha256::digest(canonical_bytes(p).unwrap())),
            );
            let mut e = AuditEvent {
                event_id: format!("e{i}"),
                timestamp_ms: 1_700_000_000_000 + i,
                event_type: EventType::CommandExecuted,
                workspace_id: Some("w".into()),
                payload: serde_json::json!({ "i": i }),
                chain_index: i,
                prev_hash_hex,
                signature_b64: String::new(),
                signer_pubkey_b64: pk_b64.clone(),
            };
            let sig = sk.sign(&canonical_bytes(&e).unwrap());
            e.signature_b64 = B64.encode(sig.to_bytes());
            events.push(e);
        }
        events
    }

    /// Serialize events as a JSONL string (one event per line).
    fn events_to_jsonl(events: &[AuditEvent]) -> String {
        events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Build and write a valid signed chain of `n` events to `path`.
    fn write_signed_chain(path: &Path, n: u64) {
        std::fs::write(path, events_to_jsonl(&build_signed_chain(n))).unwrap();
    }

    /// Write a broken chain (valid events except the last event's signature is corrupted).
    fn write_broken_chain(path: &Path, n: u64) {
        let mut events = build_signed_chain(n);
        // Corrupt the last event's signature.
        if let Some(last) = events.last_mut() {
            let mut sig_bytes = B64.decode(&last.signature_b64).unwrap();
            sig_bytes[0] ^= 0xFF;
            last.signature_b64 = B64.encode(sig_bytes);
        }
        std::fs::write(path, events_to_jsonl(&events)).unwrap();
    }

    #[test]
    fn verify_good_chain_ok() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        write_signed_chain(&jsonl, 3);
        let result = verify(&jsonl);
        assert!(result.is_ok(), "good chain must verify: {result:?}");
    }

    #[test]
    fn verify_tampered_chain_fails() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        // Build a good chain then flip a signature byte in the middle event.
        let mut events = build_signed_chain(3);
        let mut sig_bytes = B64.decode(&events[1].signature_b64).unwrap();
        sig_bytes[0] ^= 0xFF;
        events[1].signature_b64 = B64.encode(sig_bytes);
        std::fs::write(&jsonl, events_to_jsonl(&events)).unwrap();

        let result = verify(&jsonl);
        assert!(result.is_err(), "tampered chain must fail verification");
    }

    #[test]
    fn export_good_chain_writes_manifest_with_matching_root() {
        let state_dir = tempfile::tempdir().unwrap();
        let out_dir = tempfile::tempdir().unwrap();
        write_signed_chain(&state_dir.path().join("audit.jsonl"), 4);

        let export_path = export(state_dir.path(), out_dir.path(), false, 1_700_000_000_000)
            .expect("export must succeed on a good chain");

        // Verify the manifest was written.
        let manifest_bytes =
            std::fs::read(export_path.join("manifest.json")).expect("manifest.json must exist");
        let manifest: AuditExportManifest =
            serde_json::from_slice(&manifest_bytes).expect("manifest must be valid JSON");

        assert!(manifest.verified, "manifest.verified must be true");

        // Re-verify the exported events and confirm the root matches.
        let exported_events = read_events(&export_path.join("audit.jsonl")).unwrap();
        let v = verify_chain(&exported_events);
        assert!(v.ok);
        assert_eq!(
            manifest.root_hex, v.root_hex,
            "manifest.root_hex must match verify_chain root"
        );
    }

    #[test]
    fn export_refuses_broken_chain_without_allow_broken() {
        let state_dir = tempfile::tempdir().unwrap();
        let out_dir = tempfile::tempdir().unwrap();
        write_broken_chain(&state_dir.path().join("audit.jsonl"), 3);

        // Without allow_broken: must fail.
        let result = export(state_dir.path(), out_dir.path(), false, 1_700_000_000_000);
        assert!(
            result.is_err(),
            "must refuse broken chain without --allow-broken"
        );

        // With allow_broken: must succeed and manifest.verified == false.
        let export_path = export(state_dir.path(), out_dir.path(), true, 1_700_000_000_000)
            .expect("export must succeed with --allow-broken");
        let manifest_bytes = std::fs::read(export_path.join("manifest.json")).unwrap();
        let manifest: AuditExportManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        assert!(
            !manifest.verified,
            "manifest.verified must be false for a broken chain"
        );
    }

    #[test]
    fn verify_detects_manifest_root_mismatch_after_truncation() {
        let state_dir = tempfile::tempdir().unwrap();
        let out_dir = tempfile::tempdir().unwrap();
        write_signed_chain(&state_dir.path().join("audit.jsonl"), 4);

        let export_path = export(state_dir.path(), out_dir.path(), false, 1_700_000_000_000)
            .expect("initial export must succeed");

        // Truncate the last line of the exported audit.jsonl.
        let exported_jsonl = export_path.join("audit.jsonl");
        let content = std::fs::read_to_string(&exported_jsonl).unwrap();
        let truncated: String = content
            .lines()
            .take(content.lines().count().saturating_sub(1))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&exported_jsonl, truncated).unwrap();

        // verify(export_dir) must fail because the recomputed root diverges from the manifest.
        let result = verify(&export_path);
        assert!(
            result.is_err(),
            "verify must fail after truncation (root mismatch vs manifest)"
        );
    }

    #[test]
    fn verify_rejects_present_but_corrupt_manifest() {
        let state_dir = tempfile::tempdir().unwrap();
        let out_dir = tempfile::tempdir().unwrap();
        write_signed_chain(&state_dir.path().join("audit.jsonl"), 4);

        let export_path = export(state_dir.path(), out_dir.path(), false, 1_700_000_000_000)
            .expect("initial export must succeed");

        // Damage the manifest in place (e.g. an attacker drops the pinned root).
        // A present-but-unparseable manifest must be a hard error, NOT silently
        // ignored — otherwise the root comparison is skipped and a tampered
        // export could report a false clean.
        std::fs::write(export_path.join("manifest.json"), b"{ not json").unwrap();

        let result = verify(&export_path);
        assert!(
            result.is_err(),
            "verify must reject a present-but-corrupt manifest (no false-clean)"
        );
    }
}
