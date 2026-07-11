// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! `ne-bench` entry point.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::Path;

use anyhow::Context;
use clap::Parser;

use ne_bench::benchmarks::{boot_storm, cold_start, density, exec, teardown};
use ne_bench::cli::{Args, Command};
use ne_bench::client::CreateParams;
use ne_bench::csv::write_summary;
use ne_bench::manifest::{self, BenchmarkRecord, OperatorInputs};
use ne_bench::stats::summarize;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let raw_dir = args.output_dir.join("raw");
    let summary_dir = args.output_dir.join("summary");
    std::fs::create_dir_all(&raw_dir).context("create raw/ dir")?;
    std::fs::create_dir_all(&summary_dir).context("create summary/ dir")?;

    let inputs = OperatorInputs {
        run_timestamp: args.run_timestamp.clone(),
        instance_sku: args.instance_sku.clone(),
        storage_backend: args.storage_backend.clone(),
        guest_kernel_digest: args.kernel_digest.clone(),
        guest_rootfs_digest: args.rootfs_digest.clone(),
        environment_notes: args.environment_notes.clone(),
        vcpu_count: args.vcpu_count,
        mem_size_mib: args.mem_size_mib,
    };
    let mut man = manifest::collect(&inputs)?;

    let params = CreateParams {
        workspace_id: String::new(), // set per-trial by each benchmark
        kernel_sha256: args.kernel_digest.clone(),
        rootfs_sha256: args.rootfs_digest.clone(),
        vcpu_count: args.vcpu_count,
        mem_size_mib: args.mem_size_mib,
        guest_vsock_cid: args.base_vsock_cid,
    };

    match &args.command {
        Command::ColdStart { iterations } => {
            let raw = raw_dir.join("cold_start.csv");
            let out = cold_start::run(&args.endpoint, &params, *iterations, &raw).await?;
            write_named_summary(&summary_dir, "cold_start", &out.ready_samples_ms)?;
            man.benchmarks.push(BenchmarkRecord {
                name: "cold_start".to_string(),
                workload: "create + poll /bin/true until ready; headline=ready_ms".to_string(),
                iterations_requested: *iterations,
                iterations_completed: out.completed,
                terminated_early: out.terminated_early,
                notes: "raw also has launch_ms + gap_ms columns".to_string(),
            });
            print_summary("cold_start (ready_ms)", &out.ready_samples_ms);
        }
        Command::Exec { iterations } => {
            let raw = raw_dir.join("exec.csv");
            let out = exec::run(&args.endpoint, &params, *iterations, &raw).await?;
            write_named_summary(&summary_dir, "exec", &out.samples_ms)?;
            man.benchmarks.push(BenchmarkRecord {
                name: "exec".to_string(),
                workload: "/bin/true roundtrip in a ready workspace".to_string(),
                iterations_requested: *iterations,
                iterations_completed: out.completed,
                terminated_early: out.terminated_early,
                notes: "includes guest-side fork/exec; not pure vsock RTT".to_string(),
            });
            print_summary("exec (roundtrip_ms)", &out.samples_ms);
        }
        Command::Teardown { iterations } => {
            let raw = raw_dir.join("teardown.csv");
            let out = teardown::run(&args.endpoint, &params, *iterations, &raw).await?;
            write_named_summary(&summary_dir, "teardown", &out.samples_ms)?;
            man.benchmarks.push(BenchmarkRecord {
                name: "teardown".to_string(),
                workload: "destroy() to cleanup-complete".to_string(),
                iterations_requested: *iterations,
                iterations_completed: out.completed,
                terminated_early: out.terminated_early,
                notes: String::new(),
            });
            print_summary("teardown (teardown_ms)", &out.samples_ms);
        }
        Command::BootStorm { concurrency } => {
            let raw = raw_dir.join("boot_storm.csv");
            let out = boot_storm::run(
                &args.endpoint,
                &params,
                *concurrency,
                args.base_vsock_cid,
                &raw,
            )
            .await?;
            write_named_summary(&summary_dir, "boot_storm", &out.ready_samples_ms)?;
            man.benchmarks.push(BenchmarkRecord {
                name: "boot_storm".to_string(),
                workload: format!("{concurrency} concurrent creates to all-ready"),
                iterations_requested: *concurrency,
                iterations_completed: out.completed,
                terminated_early: out.terminated_early,
                notes: format!("time_to_all_ready_ms={:.3}", out.time_to_all_ready_ms),
            });
            print_summary("boot_storm (per-create ready_ms)", &out.ready_samples_ms);
            println!("time_to_all_ready_ms = {:.3}", out.time_to_all_ready_ms);
        }
        Command::Density {
            ram_stop_percent,
            max_consecutive_failures,
            max_workspaces,
        } => {
            let raw = raw_dir.join("density.csv");
            let out = density::run(
                &args.endpoint,
                &params,
                *ram_stop_percent,
                *max_consecutive_failures,
                *max_workspaces,
                args.base_vsock_cid,
                &raw,
            )
            .await?;
            man.benchmarks.push(BenchmarkRecord {
                name: "density".to_string(),
                workload: format!(
                    "boot {}vCPU/{}MiB workspaces to stop-rule",
                    args.vcpu_count, args.mem_size_mib
                ),
                iterations_requested: *max_workspaces,
                iterations_completed: out.max_stable,
                terminated_early: true,
                notes: format!(
                    "max_stable={} per_workspace_kib={:.1} ram_total_kib={} \
                     committed_at_stop_kib={} stop_reason={}",
                    out.max_stable,
                    out.per_workspace_kib,
                    out.ram_total_kib,
                    out.ram_committed_at_stop_kib,
                    out.stop_reason,
                ),
            });
            println!(
                "density: max_stable={} per_workspace_kib={:.1} stop_reason={}",
                out.max_stable, out.per_workspace_kib, out.stop_reason
            );
        }
    }

    let manifest_path = args.output_dir.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&man)?)
        .with_context(|| format!("write {}", manifest_path.display()))?;
    println!("manifest -> {}", manifest_path.display());
    Ok(())
}

fn write_named_summary(summary_dir: &Path, name: &str, samples_ms: &[f64]) -> anyhow::Result<()> {
    if let Some(s) = summarize(samples_ms) {
        let path = summary_dir.join(format!("{name}.csv"));
        let file = std::fs::File::create(&path)?;
        write_summary(file, name, &s)?;
    }
    Ok(())
}

fn print_summary(label: &str, samples_ms: &[f64]) {
    match summarize(samples_ms) {
        Some(s) => println!(
            "{label}: n={} p50={:.3} p90={:.3} p95={:.3} p99={:.3} min={:.3} max={:.3}",
            s.n, s.p50_ms, s.p90_ms, s.p95_ms, s.p99_ms, s.min_ms, s.max_ms
        ),
        None => println!("{label}: no samples"),
    }
}
