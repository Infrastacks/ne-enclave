// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Exec roundtrip benchmark: `/bin/true` in an already-ready workspace.
//!
//! Isolates vsock + RPC + guest-side process-spawn overhead. NOT pure
//! network RTT — it includes a guest fork/exec (documented in the
//! methodology).

use std::path::Path;
use std::time::{Duration, Instant};

use crate::client::{BenchClient, CreateParams};
use crate::csv::RawWriter;

/// Per-trial exec-roundtrip samples (ms) plus bookkeeping.
pub struct ExecOutcome {
    /// Per-trial roundtrip samples in milliseconds.
    pub samples_ms: Vec<f64>,
    /// Number of execs that completed.
    pub completed: usize,
    /// Whether the run terminated before all iterations completed.
    pub terminated_early: bool,
}

/// Boot one workspace, wait until ready, then time `iterations` execs.
pub async fn run(
    endpoint: &str,
    params_base: &CreateParams,
    iterations: usize,
    raw_path: &Path,
) -> anyhow::Result<ExecOutcome> {
    let mut client = BenchClient::connect(endpoint.to_string()).await?;
    let wsid = "exec-bench".to_string();
    let mut p = params_base.clone();
    p.workspace_id = wsid.clone();

    let created_at = Instant::now();
    client.create(&p).await?;
    client
        .wait_ready(
            &wsid,
            created_at,
            Duration::from_secs(30),
            Duration::from_millis(100),
        )
        .await?;

    let file = std::fs::File::create(raw_path)?;
    let mut writer = RawWriter::new(std::io::BufWriter::new(file), &["trial", "roundtrip_ms"])?;

    let mut samples_ms = Vec::with_capacity(iterations);
    let mut completed = 0usize;
    let mut terminated_early = false;

    for i in 0..iterations {
        match client.exec_true(&wsid).await {
            Ok(d) => {
                let ms = d.as_secs_f64() * 1000.0;
                writer.row(&[i.to_string(), format!("{ms:.3}")])?;
                if i % 100 == 0 {
                    writer.flush()?;
                }
                samples_ms.push(ms);
                completed += 1;
            }
            Err(e) => {
                tracing::warn!(trial = i, error = %e, "exec failed; stopping");
                terminated_early = true;
                break;
            }
        }
    }
    writer.flush()?;
    let _ = client.destroy(&wsid).await;

    Ok(ExecOutcome {
        samples_ms,
        completed,
        terminated_early,
    })
}
