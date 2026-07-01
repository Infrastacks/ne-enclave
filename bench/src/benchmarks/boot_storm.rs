// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Boot-storm benchmark: N concurrent creates → all ready.
//!
//! Reports each create's ready latency under contention plus the
//! wall-clock time for the whole storm to become fully ready.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::client::{BenchClient, CreateParams};
use crate::csv::RawWriter;

/// Boot-storm result: per-create ready samples (ms), total wall-clock
/// to all-ready (ms), and how many of the N succeeded.
pub struct BootStormOutcome {
    /// Per-create ready-latency samples in milliseconds.
    pub ready_samples_ms: Vec<f64>,
    /// Wall-clock time for the whole storm to become ready, milliseconds.
    pub time_to_all_ready_ms: f64,
    /// Number of workspaces that became ready.
    pub completed: usize,
    /// Whether any workspace failed to come up.
    pub terminated_early: bool,
}

/// Launch `concurrency` workspaces concurrently and measure readiness.
pub async fn run(
    endpoint: &str,
    params_base: &CreateParams,
    concurrency: usize,
    base_vsock_cid: u32,
    raw_path: &Path,
) -> anyhow::Result<BootStormOutcome> {
    let storm_start = Instant::now();

    let mut handles = Vec::with_capacity(concurrency);
    for i in 0..concurrency {
        let endpoint = endpoint.to_string();
        let mut p = params_base.clone();
        p.workspace_id = format!("bs-{i}");
        p.guest_vsock_cid = base_vsock_cid + u32::try_from(i).unwrap_or(0);
        handles.push(tokio::spawn(async move {
            let mut client = BenchClient::connect(endpoint).await?;
            let wsid = p.workspace_id.clone();
            let created_at = Instant::now();
            client.create(&p).await?;
            let ready = client
                .wait_ready(
                    &wsid,
                    created_at,
                    Duration::from_secs(60),
                    Duration::from_millis(100),
                )
                .await?;
            Ok::<(String, f64), anyhow::Error>((wsid, ready.as_secs_f64() * 1000.0))
        }));
    }

    let mut ready_samples_ms = Vec::new();
    let mut ready_ids = Vec::new();
    let mut terminated_early = false;
    for h in handles {
        match h.await {
            Ok(Ok((wsid, ms))) => {
                ready_ids.push(wsid);
                ready_samples_ms.push(ms);
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "a boot-storm workspace failed");
                terminated_early = true;
            }
            Err(e) => {
                tracing::warn!(error = %e, "a boot-storm task panicked");
                terminated_early = true;
            }
        }
    }
    let time_to_all_ready_ms = storm_start.elapsed().as_secs_f64() * 1000.0;

    let file = std::fs::File::create(raw_path)?;
    let mut writer = RawWriter::new(std::io::BufWriter::new(file), &["workspace", "ready_ms"])?;
    for (id, ms) in ready_ids.iter().zip(ready_samples_ms.iter()) {
        writer.row(&[id.clone(), format!("{ms:.3}")])?;
    }
    writer.flush()?;

    // Cleanup: destroy everything that came up.
    for id in &ready_ids {
        if let Ok(mut client) = BenchClient::connect(endpoint.to_string()).await {
            let _ = client.destroy(id).await;
        }
    }

    let completed = ready_samples_ms.len();
    Ok(BootStormOutcome {
        ready_samples_ms,
        time_to_all_ready_ms,
        completed,
        terminated_early,
    })
}
