// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Cold-start benchmark: fresh boot to guest-agent-ready.
//!
//! Reports BOTH boundaries per the spec — `launch` (create returns) and
//! `ready` (guest agent reachable). Headline is `ready`. The gap is the
//! readiness latency that an immediate exec would otherwise hit.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::client::{BenchClient, CreateParams};
use crate::csv::RawWriter;

/// Result of a cold-start run: the per-trial ready-latency samples (ms)
/// for summarizing, plus completion bookkeeping for the manifest.
pub struct ColdStartOutcome {
    /// Per-trial ready-latency samples in milliseconds.
    pub ready_samples_ms: Vec<f64>,
    /// Number of trials that completed.
    pub completed: usize,
    /// Whether the run terminated before all iterations completed.
    pub terminated_early: bool,
}

/// Run `iterations` sequential cold-start trials, streaming raw rows.
pub async fn run(
    endpoint: &str,
    params_base: &CreateParams,
    iterations: usize,
    raw_path: &Path,
) -> anyhow::Result<ColdStartOutcome> {
    let file = std::fs::File::create(raw_path)?;
    let mut writer = RawWriter::new(
        std::io::BufWriter::new(file),
        &["trial", "launch_ms", "ready_ms", "gap_ms"],
    )?;

    let mut ready_samples_ms = Vec::with_capacity(iterations);
    let mut completed = 0usize;
    let mut terminated_early = false;

    for i in 0..iterations {
        let mut client = BenchClient::connect(endpoint.to_string()).await?;
        let wsid = format!("cs-{i}");
        let mut p = params_base.clone();
        p.workspace_id = wsid.clone();

        let created_at = Instant::now();
        let launch = match client.create(&p).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(trial = i, error = %e, "create failed; stopping");
                terminated_early = true;
                break;
            }
        };
        let ready = match client
            .wait_ready(
                &wsid,
                created_at,
                Duration::from_secs(30),
                Duration::from_millis(100),
            )
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(trial = i, error = %e, "never became ready; destroying + stopping");
                let _ = client.destroy(&wsid).await;
                terminated_early = true;
                break;
            }
        };

        let launch_ms = launch.as_secs_f64() * 1000.0;
        let ready_ms = ready.as_secs_f64() * 1000.0;
        let gap_ms = ready_ms - launch_ms;
        writer.row(&[
            i.to_string(),
            format!("{launch_ms:.3}"),
            format!("{ready_ms:.3}"),
            format!("{gap_ms:.3}"),
        ])?;
        writer.flush()?;
        ready_samples_ms.push(ready_ms);
        completed += 1;

        let _ = client.destroy(&wsid).await;
    }

    Ok(ColdStartOutcome {
        ready_samples_ms,
        completed,
        terminated_early,
    })
}
