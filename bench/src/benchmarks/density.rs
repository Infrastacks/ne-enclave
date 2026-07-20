// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Density benchmark: max stable concurrent workspaces under a safety
//! stop-rule, plus measured per-workspace memory footprint.
//!
//! Safety: we stop at a RAM-committed threshold or consecutive failures.
//! We never deliberately drive the host to OOM (the dev VM is shared and
//! remote). The 128 GB reference-host figure is EXTRAPOLATED downstream,
//! never measured here.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::client::{BenchClient, CreateParams};
use crate::csv::RawWriter;
use crate::manifest::parse_mem_total_kib;

/// Density run result.
pub struct DensityOutcome {
    /// Max stable concurrent workspaces reached before the stop-rule.
    pub max_stable: usize,
    /// Measured per-workspace RSS footprint in KiB (committed-RAM delta
    /// from baseline divided by `max_stable`).
    pub per_workspace_kib: f64,
    /// Total host RAM in KiB.
    pub ram_total_kib: u64,
    /// Committed RAM (KiB) at the moment the stop-rule fired.
    pub ram_committed_at_stop_kib: u64,
    /// Human-readable reason the run stopped.
    pub stop_reason: String,
}

/// Parse committed memory (KiB) = `MemTotal` - `MemAvailable`.
fn committed_kib(meminfo: &str) -> Option<u64> {
    let total = parse_mem_total_kib(meminfo)?;
    let avail = meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|n| n.parse::<u64>().ok())?;
    Some(total.saturating_sub(avail))
}

fn read_committed_kib() -> u64 {
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    committed_kib(&meminfo).unwrap_or(0)
}

// KiB values fit f64 exactly for any realistic host RAM and workspace
// count; these casts are lossless in practice.
#[allow(clippy::cast_precision_loss)]
fn per_workspace(delta_kib: u64, count: usize) -> f64 {
    delta_kib as f64 / count as f64
}

/// Boot to the stop-rule, measuring per-workspace footprint along the way.
#[allow(clippy::too_many_arguments)] // each arg is a distinct benchmark knob; a struct would not add clarity
pub async fn run(
    endpoint: &str,
    params_base: &CreateParams,
    ram_stop_percent: u32,
    max_consecutive_failures: u32,
    max_workspaces: usize,
    base_vsock_cid: u32,
    raw_path: &Path,
) -> anyhow::Result<DensityOutcome> {
    let meminfo0 = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let ram_total_kib = parse_mem_total_kib(&meminfo0).unwrap_or(0);
    let baseline_committed = read_committed_kib();
    let stop_threshold_kib = ram_total_kib.saturating_mul(u64::from(ram_stop_percent)) / 100;

    let file = std::fs::File::create(raw_path)?;
    let mut writer = RawWriter::new(std::io::BufWriter::new(file), &["count", "committed_kib"])?;

    // Keep one client per live workspace so we can destroy them all.
    let mut live: Vec<(String, BenchClient)> = Vec::new();
    let mut consecutive_failures = 0u32;
    let mut stop_reason = String::new();

    for i in 0..max_workspaces {
        let mut client = match BenchClient::connect(endpoint.to_string()).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(i, error = %e, "connect failed");
                consecutive_failures += 1;
                if consecutive_failures >= max_consecutive_failures {
                    stop_reason = "consecutive connect failures".to_string();
                    break;
                }
                continue;
            }
        };
        let wsid = format!("den-{i}");
        let mut p = params_base.clone();
        p.workspace_id = wsid.clone();
        p.guest_vsock_cid = base_vsock_cid + u32::try_from(i).unwrap_or(0);

        let created_at = Instant::now();
        let ok = client.create(&p).await.is_ok()
            && client
                .wait_ready(
                    &wsid,
                    created_at,
                    Duration::from_secs(60),
                    Duration::from_millis(200),
                )
                .await
                .is_ok();
        if !ok {
            tracing::warn!(i, "create/ready failed");
            let _ = client.destroy(&wsid).await;
            consecutive_failures += 1;
            if consecutive_failures >= max_consecutive_failures {
                stop_reason = "consecutive create failures".to_string();
                break;
            }
            continue;
        }
        consecutive_failures = 0;
        live.push((wsid, client));

        let committed = read_committed_kib();
        writer.row(&[live.len().to_string(), committed.to_string()])?;
        writer.flush()?;

        if committed >= stop_threshold_kib && stop_threshold_kib > 0 {
            stop_reason = format!("committed RAM reached {ram_stop_percent}% of total");
            break;
        }
    }

    let ram_committed_at_stop_kib = read_committed_kib();
    let max_stable = live.len();
    let per_workspace_kib = if max_stable > 0 {
        per_workspace(
            ram_committed_at_stop_kib.saturating_sub(baseline_committed),
            max_stable,
        )
    } else {
        0.0
    };
    if stop_reason.is_empty() {
        stop_reason = "reached max_workspaces ceiling".to_string();
    }

    // Cleanup.
    for (wsid, mut client) in live {
        let _ = client.destroy(&wsid).await;
    }

    Ok(DensityOutcome {
        max_stable,
        per_workspace_kib,
        ram_total_kib,
        ram_committed_at_stop_kib,
        stop_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_is_total_minus_available() {
        let meminfo = "MemTotal:       1000 kB\nMemAvailable:    400 kB\n";
        assert_eq!(committed_kib(meminfo), Some(600));
    }
}
