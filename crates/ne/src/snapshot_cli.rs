// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! CLI-side snapshot artifact verification.
//!
//! Delegates to `ne_supervisor::snapshot::verify_artifact`, which checks
//! the manifest signature and both snapshot artifact hashes (mem, vmstate).

#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::Result;

/// `nee snapshot verify`.
///
/// Returns `Ok(())` and prints a one-line confirmation on success.
/// Returns `Err` (causing non-zero exit) when verification fails.
#[allow(clippy::print_stdout, clippy::print_stderr)]
pub async fn verify(path: &Path) -> Result<()> {
    match ne_supervisor::snapshot::verify_artifact(path).await {
        Ok(m) => {
            println!(
                "OK: snapshot {} verified (created from {})",
                m.snapshot_id, m.created_from_workspace_id
            );
            Ok(())
        }
        Err(e) => anyhow::bail!("snapshot verification failed: {e}"),
    }
}
