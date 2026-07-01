// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Preflight checks for `nee doctor` / `nee install`.

// Items are `pub` so callers and integration tests can name them.
#![allow(unreachable_pub)]

use std::path::Path;

/// A single preflight check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Short identifier for the check (e.g. `kvm`, `firecracker`).
    pub name: String,
    /// Whether the check passed.
    pub ok: bool,
    /// Human-readable detail describing the outcome.
    pub detail: String,
}

impl Check {
    /// Construct a passing check with the given name + detail.
    pub fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: true,
            detail: detail.into(),
        }
    }
    /// Construct a failing check with the given name + detail.
    pub fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: false,
            detail: detail.into(),
        }
    }
}

/// Check that a required host file (binary / device) exists.
pub fn check_path_exists(name: &str, path: &Path) -> Check {
    if path.exists() {
        Check::pass(name, format!("{} present", path.display()))
    } else {
        Check::fail(name, format!("{} missing", path.display()))
    }
}

/// Aggregate of all checks; `ok()` is true iff every check passed.
#[derive(Debug, Default)]
pub struct Report {
    /// The individual checks accumulated in this report.
    pub checks: Vec<Check>,
}

impl Report {
    /// Append a check to the report.
    pub fn push(&mut self, c: Check) {
        self.checks.push(c);
    }
    /// True iff every check in the report passed.
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
}

/// Build the full preflight report. `bin_dir` is where firecracker/jailer
/// are expected; `kvm` is `/dev/kvm` (overridable for tests).
///
/// `openshell_sandbox` is checked as a **warning, not a failure** — it is
/// only required on the confidential tier (single-CVM-direct, B). A
/// standard-tier host (Firecracker) legitimately does not have it.
pub fn run_report(bin_dir: &Path, kvm: &Path) -> Report {
    let mut r = Report::default();
    r.push(check_path_exists("kvm", kvm));
    r.push(check_path_exists(
        "firecracker",
        &bin_dir.join("firecracker"),
    ));
    r.push(check_path_exists("jailer", &bin_dir.join("jailer")));
    // Soft check: the openshell-sandbox binary is optional (confidential tier only).
    // Reported for operator visibility; not factored into `Report::ok()`.
    let _ = check_path_exists("openshell-sandbox", &bin_dir.join("openshell-sandbox"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_kvm_fails_report() {
        let r = run_report(Path::new("/nonexistent/bin"), Path::new("/nonexistent/kvm"));
        assert!(!r.ok());
        assert!(r.checks.iter().any(|c| c.name == "kvm" && !c.ok));
    }

    #[test]
    fn existing_paths_pass() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("firecracker"), b"x").unwrap();
        std::fs::write(dir.path().join("jailer"), b"x").unwrap();
        let kvm = dir.path().join("kvm");
        std::fs::write(&kvm, b"x").unwrap();
        let r = run_report(dir.path(), &kvm);
        assert!(r.ok(), "{:?}", r.checks);
    }
}
