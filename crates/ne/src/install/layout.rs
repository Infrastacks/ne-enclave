// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Canonical install paths, parameterized by an optional prefix root
//! (the prefix is for fakeroot testing; production uses `/`).

// Items are `pub` so clap / integration tests can name them, but they live
// under `pub mod install` on the lib crate.
#![allow(unreachable_pub)]

use std::path::{Path, PathBuf};

/// Resolved filesystem layout for an install.
#[derive(Debug, Clone)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    /// `root` is `/` in production, or a temp dir under `--prefix`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn at(&self, abs: &str) -> PathBuf {
        // Join an absolute-looking path under the root without letting the
        // leading `/` discard the prefix.
        self.root.join(abs.trim_start_matches('/'))
    }

    /// Directory holding the fused binary + firecracker/jailer.
    pub fn bin_dir(&self) -> PathBuf {
        self.at("/opt/ne-enclave/bin")
    }
    /// Absolute path to the fused `nee` binary.
    pub fn binary(&self) -> PathBuf {
        self.at("/opt/ne-enclave/bin/nee")
    }
    /// Configuration directory (`ne-enclave.env` etc.).
    pub fn etc_dir(&self) -> PathBuf {
        self.at("/etc/ne-enclave")
    }
    /// Path to the systemd `EnvironmentFile` shared by both units.
    pub fn env_file(&self) -> PathBuf {
        self.at("/etc/ne-enclave/ne-enclave.env")
    }
    /// Path to the host-global PII policy the privacy router enforces.
    /// Installed by `nee install` (only if absent, so operator edits
    /// survive re-installs) and referenced by `NE_PRIVACY_ROUTER_POLICY`.
    pub fn privacy_policy_file(&self) -> PathBuf {
        self.at("/etc/ne-enclave/privacy-policy.yaml")
    }
    /// Persistent runtime state directory (audit log, signing key).
    pub fn state_dir(&self) -> PathBuf {
        self.at("/var/lib/ne-enclave")
    }
    /// Directory holding OpenShell policy inputs.
    pub fn openshell_dir(&self) -> PathBuf {
        self.at("/var/lib/ne-enclave/openshell")
    }
    /// Installed OpenShell Rego policy.
    pub fn openshell_policy_rules(&self) -> PathBuf {
        self.at("/var/lib/ne-enclave/openshell/policy.rego")
    }
    /// Installed OpenShell YAML policy data.
    pub fn openshell_policy_data(&self) -> PathBuf {
        self.at("/var/lib/ne-enclave/openshell/policy.yaml")
    }
    /// Installed OpenShell sandbox executable.
    pub fn openshell_sandbox_binary(&self) -> PathBuf {
        self.at("/opt/ne-enclave/bin/openshell-sandbox")
    }
    /// Content-addressed guest image store.
    pub fn images_dir(&self) -> PathBuf {
        self.at("/var/lib/ne-enclave/images")
    }
    /// Per-workspace working directories.
    pub fn workspaces_dir(&self) -> PathBuf {
        self.at("/var/lib/ne-enclave/workspaces")
    }
    /// Saved VM snapshots.
    pub fn snapshots_dir(&self) -> PathBuf {
        self.at("/var/lib/ne-enclave/snapshots")
    }
    /// Base under which jailer creates per-workspace chroots.
    pub fn jailer_base(&self) -> PathBuf {
        self.at("/srv/jailer")
    }
    /// Runtime directory holding the supervisor IPC socket.
    pub fn run_dir(&self) -> PathBuf {
        self.at("/run/ne-enclave")
    }
    /// Directory the systemd unit files are installed into.
    pub fn systemd_dir(&self) -> PathBuf {
        self.at("/etc/systemd/system")
    }
    /// Path to the rendered supervisor systemd unit.
    pub fn supervisor_unit(&self) -> PathBuf {
        self.at("/etc/systemd/system/ne-supervisor.service")
    }
    /// Path to the rendered API systemd unit.
    pub fn api_unit(&self) -> PathBuf {
        self.at("/etc/systemd/system/ne-api.service")
    }
    /// Path to the rendered tmpfiles.d config (recreates `/run/ne-enclave`).
    pub fn tmpfiles_conf(&self) -> PathBuf {
        self.at("/etc/tmpfiles.d/ne-enclave.conf")
    }

    /// The prefix root (`/` in production, a temp dir under `--prefix`).
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_redirects_absolute_paths() {
        let l = Layout::new("/tmp/fakeroot");
        assert_eq!(
            l.binary(),
            Path::new("/tmp/fakeroot/opt/ne-enclave/bin/nee")
        );
        assert_eq!(
            l.env_file(),
            Path::new("/tmp/fakeroot/etc/ne-enclave/ne-enclave.env")
        );
        assert_eq!(
            l.privacy_policy_file(),
            Path::new("/tmp/fakeroot/etc/ne-enclave/privacy-policy.yaml")
        );
        assert_eq!(
            l.openshell_dir(),
            Path::new("/tmp/fakeroot/var/lib/ne-enclave/openshell")
        );
        assert_eq!(
            l.openshell_policy_rules(),
            Path::new("/tmp/fakeroot/var/lib/ne-enclave/openshell/policy.rego")
        );
        assert_eq!(
            l.openshell_policy_data(),
            Path::new("/tmp/fakeroot/var/lib/ne-enclave/openshell/policy.yaml")
        );
        assert_eq!(
            l.openshell_sandbox_binary(),
            Path::new("/tmp/fakeroot/opt/ne-enclave/bin/openshell-sandbox")
        );
        assert_eq!(l.run_dir(), Path::new("/tmp/fakeroot/run/ne-enclave"));
    }

    #[test]
    fn empty_root_is_production_absolute() {
        let l = Layout::new("/");
        assert_eq!(l.binary(), Path::new("/opt/ne-enclave/bin/nee"));
    }
}
