// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Command-line surface for `ne-bench`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// NeuronEdge Enclave public benchmark harness (ARCH §15).
#[derive(Debug, Parser)]
#[command(
    name = "ne-bench",
    version,
    about = "NeuronEdge Enclave runtime benchmarks"
)]
pub struct Args {
    /// Runtime gRPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    pub endpoint: String,

    /// Directory to write raw/, summary/, and manifest.json into.
    #[arg(long, default_value = "results")]
    pub output_dir: PathBuf,

    /// ISO-8601 UTC run timestamp (the harness has no wall clock of its
    /// own by policy; the operator supplies it, e.g. `date -u +%FT%TZ`).
    #[arg(long)]
    pub run_timestamp: String,

    /// Guest kernel image host path.
    #[arg(long)]
    pub kernel_path: String,

    /// Guest rootfs image host path.
    #[arg(long)]
    pub rootfs_path: String,

    /// Guest kernel image digest (for the manifest).
    #[arg(long, default_value = "unknown")]
    pub kernel_digest: String,

    /// Guest rootfs image digest (for the manifest).
    #[arg(long, default_value = "unknown")]
    pub rootfs_digest: String,

    /// Cloud SKU / instance type, recorded in the manifest.
    #[arg(long, default_value = "unknown")]
    pub instance_sku: String,

    /// Storage backend description, recorded in the manifest.
    #[arg(long, default_value = "unknown")]
    pub storage_backend: String,

    /// Environment honesty notes (floor-not-ceiling, nested-virt caveat).
    #[arg(long, default_value = "")]
    pub environment_notes: String,

    /// Workspace vCPU count for the tier under test.
    #[arg(long, default_value_t = 1)]
    pub vcpu_count: u32,

    /// Workspace memory (MiB) for the tier under test.
    #[arg(long, default_value_t = 256)]
    pub mem_size_mib: u32,

    /// Base guest vsock CID (incremented per concurrent workspace).
    #[arg(long, default_value_t = 3)]
    pub base_vsock_cid: u32,

    /// The benchmark to run.
    #[command(subcommand)]
    pub command: Command,
}

/// One subcommand per benchmark.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Cold start: report both launch and ready boundaries.
    ColdStart {
        /// Number of trials.
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
    },
    /// Warm exec roundtrip of `/bin/true`.
    Exec {
        /// Number of execs in one long-lived workspace.
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
    },
    /// Density: boot concurrently to the safety stop-rule.
    Density {
        /// Stop when committed RAM reaches this percent of total.
        #[arg(long, default_value_t = 85)]
        ram_stop_percent: u32,
        /// Stop after this many consecutive create failures.
        #[arg(long, default_value_t = 3)]
        max_consecutive_failures: u32,
        /// Hard ceiling on workspaces to attempt (safety backstop).
        #[arg(long, default_value_t = 1000)]
        max_workspaces: usize,
    },
    /// Boot storm: N concurrent creates, measure time-to-all-ready.
    BootStorm {
        /// Concurrency.
        #[arg(long, default_value_t = 50)]
        concurrency: usize,
    },
    /// Teardown: destroy latency.
    Teardown {
        /// Number of create->ready->destroy cycles (destroy is measured).
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }

    #[test]
    fn parses_cold_start_with_defaults() {
        let a = Args::try_parse_from([
            "ne-bench",
            "--run-timestamp",
            "2026-05-31T12:00:00Z",
            "--kernel-path",
            "/k",
            "--rootfs-path",
            "/r",
            "cold-start",
        ])
        .unwrap();
        assert_eq!(a.endpoint, "http://127.0.0.1:50051");
        assert_eq!(a.vcpu_count, 1);
        assert_eq!(a.mem_size_mib, 256);
        assert!(matches!(a.command, Command::ColdStart { iterations: 1000 }));
    }

    #[test]
    fn parses_density_subcommand_flags() {
        let a = Args::try_parse_from([
            "ne-bench",
            "--run-timestamp",
            "t",
            "--kernel-path",
            "/k",
            "--rootfs-path",
            "/r",
            "density",
            "--ram-stop-percent",
            "90",
            "--max-consecutive-failures",
            "5",
        ])
        .unwrap();
        assert!(matches!(
            a.command,
            Command::Density {
                ram_stop_percent: 90,
                max_consecutive_failures: 5,
                max_workspaces: 1000
            }
        ));
    }

    #[test]
    fn missing_required_flags_errors() {
        // run-timestamp / kernel-path / rootfs-path are required.
        let r = Args::try_parse_from(["ne-bench", "cold-start"]);
        assert!(r.is_err());
    }
}
