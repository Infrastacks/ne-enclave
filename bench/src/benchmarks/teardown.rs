// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Teardown benchmark: destroy latency to host-resource-cleanup-complete.
//!
//! The destroy RPC returns after the supervisor confirms cleanup
//! (it blocks on the jailed Firecracker's `child.wait()`), so the
//! call-return boundary is the cleanup-complete boundary.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::client::{BenchClient, CreateParams};
use crate::csv::RawWriter;

/// Per-trial teardown samples (ms) plus bookkeeping.
pub struct TeardownOutcome {
    /// Per-trial teardown samples in milliseconds.
    pub samples_ms: Vec<f64>,
    /// Number of cycles that completed.
    pub completed: usize,
    /// Whether the run terminated before all iterations completed.
    pub terminated_early: bool,
}

/// Run `iterations` create->ready->destroy cycles, measuring destroy.
pub async fn run(
    endpoint: &str,
    params_base: &CreateParams,
    iterations: usize,
    raw_path: &Path,
) -> anyhow::Result<TeardownOutcome> {
    let file = std::fs::File::create(raw_path)?;
    let mut writer = RawWriter::new(std::io::BufWriter::new(file), &["trial", "teardown_ms"])?;

    let mut samples_ms = Vec::with_capacity(iterations);
    let mut completed = 0usize;
    let mut terminated_early = false;

    for i in 0..iterations {
        let mut client = BenchClient::connect(endpoint.to_string()).await?;
        let wsid = format!("td-{i}");
        let mut p = params_base.clone();
        p.workspace_id = wsid.clone();

        let created_at = Instant::now();
        if let Err(e) = client.create(&p).await {
            tracing::warn!(trial = i, error = %e, "create failed; stopping");
            terminated_early = true;
            break;
        }
        if let Err(e) = client
            .wait_ready(
                &wsid,
                created_at,
                Duration::from_secs(30),
                Duration::from_millis(100),
            )
            .await
        {
            tracing::warn!(trial = i, error = %e, "never ready; destroying + stopping");
            let _ = client.destroy(&wsid).await;
            terminated_early = true;
            break;
        }

        match client.destroy(&wsid).await {
            Ok(d) => {
                let ms = d.as_secs_f64() * 1000.0;
                writer.row(&[i.to_string(), format!("{ms:.3}")])?;
                writer.flush()?;
                samples_ms.push(ms);
                completed += 1;
            }
            Err(e) => {
                tracing::warn!(trial = i, error = %e, "destroy failed; stopping");
                terminated_early = true;
                break;
            }
        }
    }

    Ok(TeardownOutcome {
        samples_ms,
        completed,
        terminated_early,
    })
}
