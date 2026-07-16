// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Preflight checks for `nee doctor` / `nee install`.

// Items are `pub` so callers and integration tests can name them.
#![allow(unreachable_pub)]

use std::path::{Path, PathBuf};

use ne_protocol::profile::ExecutionProfile;

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

/// Check that a required host path exists.
pub fn check_path_exists(name: &str, path: &Path) -> Check {
    if path.exists() {
        Check::pass(name, format!("{} present", path.display()))
    } else {
        Check::fail(name, format!("{} missing", path.display()))
    }
}

/// Check that a required path resolves to a regular file.
pub fn check_regular_file(name: &str, path: &Path) -> Check {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            Check::pass(name, format!("{} is a regular file", path.display()))
        }
        Ok(_) => Check::fail(name, format!("{} is not a regular file", path.display())),
        Err(error) => Check::fail(name, format!("inspect {}: {error}", path.display())),
    }
}

/// Check that a required path resolves to an executable regular file.
pub fn check_executable_file(name: &str, path: &Path) -> Check {
    let regular = check_regular_file(name, path);
    if !regular.ok {
        return regular;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        match std::fs::metadata(path) {
            Ok(metadata) if metadata.permissions().mode() & 0o111 != 0 => {
                Check::pass(name, format!("{} is executable", path.display()))
            }
            Ok(_) => Check::fail(name, format!("{} is not executable", path.display())),
            Err(error) => Check::fail(name, format!("inspect {}: {error}", path.display())),
        }
    }
    #[cfg(not(unix))]
    {
        regular
    }
}

/// Check that a required host path resolves to a character device.
pub fn check_character_device(name: &str, path: &Path) -> Check {
    match std::fs::metadata(path) {
        #[cfg(unix)]
        Ok(metadata) => {
            use std::os::unix::fs::FileTypeExt as _;

            if metadata.file_type().is_char_device() {
                Check::pass(name, format!("{} is a character device", path.display()))
            } else {
                Check::fail(
                    name,
                    format!("{} is not a character device", path.display()),
                )
            }
        }
        #[cfg(not(unix))]
        Ok(_) => Check::pass(name, format!("{} present", path.display())),
        Err(error) => Check::fail(name, format!("inspect {}: {error}", path.display())),
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

/// Host paths inspected by profile-specific install and doctor preflight.
#[derive(Debug, Clone)]
pub struct PreflightPaths {
    /// KVM device.
    pub kvm: PathBuf,
    /// Azure vTPM device.
    pub vtpm: PathBuf,
    /// Firecracker executable.
    pub firecracker: PathBuf,
    /// Jailer executable.
    pub jailer: PathBuf,
    /// OpenShell sandbox executable.
    pub openshell_sandbox: PathBuf,
    /// Installed OpenShell Rego policy.
    pub openshell_policy_rules: PathBuf,
    /// Installed OpenShell YAML policy data.
    pub openshell_policy_data: PathBuf,
    /// `tpm2` command.
    pub tpm2: PathBuf,
    /// Validation result for the `sandbox` service identity and home.
    pub sandbox_identity: Result<(), String>,
}

/// Build the profile-specific path preflight report.
pub fn run_report(profile: ExecutionProfile, paths: &PreflightPaths) -> Report {
    let mut report = Report::default();
    match profile {
        ExecutionProfile::Standard => {
            report.push(check_character_device("kvm", &paths.kvm));
            report.push(check_executable_file("firecracker", &paths.firecracker));
            report.push(check_executable_file("jailer", &paths.jailer));
        }
        ExecutionProfile::ConfidentialAzure => {
            report.push(check_character_device("azure-vtpm", &paths.vtpm));
            report.push(check_executable_file("tpm2", &paths.tpm2));
            report.push(check_executable_file(
                "openshell-sandbox",
                &paths.openshell_sandbox,
            ));
            report.push(check_regular_file(
                "openshell-policy-rules",
                &paths.openshell_policy_rules,
            ));
            report.push(check_regular_file(
                "openshell-policy-data",
                &paths.openshell_policy_data,
            ));
            report.push(match &paths.sandbox_identity {
                Ok(()) => Check::pass("sandbox-identity", "sandbox account and home are valid"),
                Err(detail) => Check::fail("sandbox-identity", detail.clone()),
            });
        }
    }
    report
}

/// Append live Azure vTPM NV-index and attestation-key probes.
pub fn append_azure_tpm_checks(report: &mut Report, tpm2: &Path) {
    report.push(run_command_check(
        "azure-vtpm-nvread",
        tpm2,
        &["nvread", "-C", "o", "0x01400001"],
    ));

    let output = tempfile::tempdir();
    match output {
        Ok(output) => {
            let output_path = output.path().join("ak-public.tss");
            let output_path = output_path.to_string_lossy().into_owned();
            report.push(run_command_check(
                "azure-vtpm-readpublic",
                tpm2,
                &[
                    "readpublic",
                    "-c",
                    "0x81000003",
                    "-f",
                    "tss",
                    "-o",
                    &output_path,
                ],
            ));
        }
        Err(error) => report.push(Check::fail(
            "azure-vtpm-readpublic",
            format!("create temporary output file: {error}"),
        )),
    }
}

fn run_command_check(name: &str, program: &Path, args: &[&str]) -> Check {
    match std::process::Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {
            Check::pass(name, format!("{} {args:?} succeeded", program.display()))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let detail = if stderr.is_empty() {
                format!("{} {args:?} failed ({})", program.display(), output.status)
            } else {
                stderr
            };
            Check::fail(name, detail)
        }
        Err(error) => Check::fail(name, format!("run {}: {error}", program.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ne_protocol::profile::ExecutionProfile;

    #[test]
    fn standard_requires_only_firecracker_host_paths() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["firecracker", "jailer"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            for name in ["firecracker", "jailer"] {
                std::fs::set_permissions(
                    dir.path().join(name),
                    std::fs::Permissions::from_mode(0o755),
                )
                .unwrap();
            }
        }
        let paths = PreflightPaths {
            kvm: PathBuf::from("/dev/null"),
            vtpm: dir.path().join("missing-vtpm"),
            firecracker: dir.path().join("firecracker"),
            jailer: dir.path().join("jailer"),
            openshell_sandbox: dir.path().join("missing-openshell"),
            openshell_policy_rules: dir.path().join("missing-policy.rego"),
            openshell_policy_data: dir.path().join("missing-policy.yaml"),
            tpm2: dir.path().join("missing-tpm2"),
            sandbox_identity: Err("not inspected for standard".to_string()),
        };
        let report = run_report(ExecutionProfile::Standard, &paths);
        assert!(report.ok(), "{:?}", report.checks);
        assert_eq!(
            report
                .checks
                .iter()
                .map(|check| check.name.as_str())
                .collect::<Vec<_>>(),
            ["kvm", "firecracker", "jailer"]
        );
    }

    #[test]
    fn confidential_azure_requires_vtpm_openshell_policy_tpm2_and_sandbox_user() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["openshell-sandbox", "policy.rego", "policy.yaml", "tpm2"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            for name in ["openshell-sandbox", "tpm2"] {
                std::fs::set_permissions(
                    dir.path().join(name),
                    std::fs::Permissions::from_mode(0o755),
                )
                .unwrap();
            }
        }
        let paths = PreflightPaths {
            kvm: dir.path().join("missing-kvm"),
            vtpm: PathBuf::from("/dev/null"),
            firecracker: dir.path().join("missing-firecracker"),
            jailer: dir.path().join("missing-jailer"),
            openshell_sandbox: dir.path().join("openshell-sandbox"),
            openshell_policy_rules: dir.path().join("policy.rego"),
            openshell_policy_data: dir.path().join("policy.yaml"),
            tpm2: dir.path().join("tpm2"),
            sandbox_identity: Ok(()),
        };
        let report = run_report(ExecutionProfile::ConfidentialAzure, &paths);
        assert!(report.ok(), "{:?}", report.checks);
        assert_eq!(
            report
                .checks
                .iter()
                .map(|check| check.name.as_str())
                .collect::<Vec<_>>(),
            [
                "azure-vtpm",
                "tpm2",
                "openshell-sandbox",
                "openshell-policy-rules",
                "openshell-policy-data",
                "sandbox-identity",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn confidential_azure_rejects_unusable_component_types() {
        let dir = tempfile::tempdir().unwrap();
        let non_executable = dir.path().join("openshell-sandbox");
        std::fs::write(&non_executable, b"x").unwrap();
        let tpm2_directory = dir.path().join("tpm2");
        let rules_directory = dir.path().join("policy.rego");
        let data_directory = dir.path().join("policy.yaml");
        for path in [&tpm2_directory, &rules_directory, &data_directory] {
            std::fs::create_dir(path).unwrap();
        }
        let paths = PreflightPaths {
            kvm: dir.path().join("missing-kvm"),
            vtpm: dir.path().join("not-a-device"),
            firecracker: dir.path().join("missing-firecracker"),
            jailer: dir.path().join("missing-jailer"),
            openshell_sandbox: non_executable,
            openshell_policy_rules: rules_directory,
            openshell_policy_data: data_directory,
            tpm2: tpm2_directory,
            sandbox_identity: Ok(()),
        };
        std::fs::write(&paths.vtpm, b"x").unwrap();

        let report = run_report(ExecutionProfile::ConfidentialAzure, &paths);
        assert!(!report.ok(), "{:?}", report.checks);
        assert!(
            report
                .checks
                .iter()
                .filter(|check| !check.ok)
                .map(|check| check.name.as_str())
                .eq([
                    "azure-vtpm",
                    "tpm2",
                    "openshell-sandbox",
                    "openshell-policy-rules",
                    "openshell-policy-data",
                ])
        );
    }

    #[cfg(unix)]
    #[test]
    fn azure_tpm_command_failures_preserve_trimmed_stderr() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let tpm2 = dir.path().join("tpm2");
        std::fs::write(
            &tpm2,
            "#!/bin/sh\nprintf '  simulated TPM failure  \\n' >&2\nexit 7\n",
        )
        .unwrap();
        std::fs::set_permissions(&tpm2, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut report = Report::default();
        append_azure_tpm_checks(&mut report, &tpm2);
        assert_eq!(report.checks.len(), 2);
        assert!(report.checks.iter().all(|check| !check.ok));
        assert!(
            report
                .checks
                .iter()
                .all(|check| check.detail.contains("simulated TPM failure"))
        );
        assert!(
            report
                .checks
                .iter()
                .all(|check| !check.detail.ends_with('\n'))
        );
    }
}
