// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared execution-profile and capability types.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// Customer-visible runtime execution profile.
pub enum ExecutionProfile {
    /// Firecracker workspace execution with software attestation.
    #[default]
    Standard,
    /// OpenShell execution inside an Azure confidential VM with vTPM evidence.
    ConfidentialAzure,
}

impl fmt::Display for ExecutionProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Standard => "standard",
            Self::ConfidentialAzure => "confidential-azure",
        })
    }
}

impl FromStr for ExecutionProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "standard" => Ok(Self::Standard),
            "confidential-azure" => Ok(Self::ConfidentialAzure),
            other => Err(format!(
                "invalid execution profile {other:?}; expected standard or confidential-azure"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Runtime substrate used to execute workspace processes.
pub enum ExecutionBackend {
    /// Firecracker microVM managed through jailer.
    Firecracker,
    /// OpenShell sandbox running inside the host confidential VM.
    OpenShell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Provider used to generate attestation evidence.
pub enum AttestationBackend {
    /// Ed25519 software evidence.
    Software,
    /// Direct AMD SEV-SNP evidence from `/dev/sev-guest`.
    SevSnpDirect,
    /// Azure `OpenHCL` SEV-SNP evidence bound through a vTPM quote.
    SevSnpAzure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Workspace operations advertised by runtime capability discovery.
pub enum WorkspaceOperation {
    /// Create a workspace.
    Create,
    /// Destroy a workspace.
    Destroy,
    /// Execute a command.
    Execute,
    /// Write a file.
    WriteFile,
    /// Read a file.
    ReadFile,
    /// Pause execution.
    Pause,
    /// Resume execution.
    Resume,
    /// Create a snapshot.
    Snapshot,
    /// Restore a snapshot.
    Restore,
    /// Fork a snapshot.
    Fork,
    /// Use a warm pool.
    WarmPool,
    /// Expose ingress.
    Ingress,
    /// Generate attestation evidence.
    Attest,
}

/// Transport-neutral capability description for one running runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilitiesInfo {
    /// Runtime semantic version.
    pub runtime_version: String,
    /// Selected customer-visible execution profile.
    pub execution_profile: ExecutionProfile,
    /// Concrete execution substrate.
    pub execution_backend: ExecutionBackend,
    /// Concrete attestation provider.
    pub attestation_backend: AttestationBackend,
    /// Operations accepted by the selected profile.
    pub supported_operations: Vec<WorkspaceOperation>,
    /// Hard profile-specific workspace capacity, when present.
    pub hard_workspace_capacity: Option<u32>,
    /// Whether the confidential profile supports snapshot semantics.
    pub confidential_snapshot_supported: bool,
    /// Public evidence-envelope schema version.
    pub evidence_schema_version: u32,
}

impl ExecutionProfile {
    /// Build the transport-neutral capabilities advertised by this runtime.
    #[must_use]
    pub fn capabilities(
        self,
        runtime_version: impl Into<String>,
        evidence_schema_version: u32,
    ) -> RuntimeCapabilitiesInfo {
        let supported_operations = [
            WorkspaceOperation::Create,
            WorkspaceOperation::Destroy,
            WorkspaceOperation::Execute,
            WorkspaceOperation::WriteFile,
            WorkspaceOperation::ReadFile,
            WorkspaceOperation::Pause,
            WorkspaceOperation::Resume,
            WorkspaceOperation::Snapshot,
            WorkspaceOperation::Restore,
            WorkspaceOperation::Fork,
            WorkspaceOperation::WarmPool,
            WorkspaceOperation::Ingress,
            WorkspaceOperation::Attest,
        ]
        .into_iter()
        .filter(|operation| self.supports(*operation))
        .collect();

        RuntimeCapabilitiesInfo {
            runtime_version: runtime_version.into(),
            execution_profile: self,
            execution_backend: self.execution_backend(),
            attestation_backend: self.attestation_backend(),
            supported_operations,
            hard_workspace_capacity: self.hard_workspace_capacity(),
            confidential_snapshot_supported: false,
            evidence_schema_version,
        }
    }

    /// Resolve the execution substrate selected by this profile.
    #[must_use]
    pub fn execution_backend(self) -> ExecutionBackend {
        match self {
            Self::Standard => ExecutionBackend::Firecracker,
            Self::ConfidentialAzure => ExecutionBackend::OpenShell,
        }
    }

    /// Resolve the attestation provider selected by this profile.
    #[must_use]
    pub fn attestation_backend(self) -> AttestationBackend {
        match self {
            Self::Standard => AttestationBackend::Software,
            Self::ConfidentialAzure => AttestationBackend::SevSnpAzure,
        }
    }

    /// Return the hard workspace capacity, when the profile imposes one.
    #[must_use]
    pub fn hard_workspace_capacity(self) -> Option<u32> {
        match self {
            Self::Standard => None,
            Self::ConfidentialAzure => Some(1),
        }
    }

    /// Return whether an operation is supported by this profile.
    #[must_use]
    pub fn supports(self, operation: WorkspaceOperation) -> bool {
        match self {
            Self::Standard => true,
            Self::ConfidentialAzure => matches!(
                operation,
                WorkspaceOperation::Create
                    | WorkspaceOperation::Destroy
                    | WorkspaceOperation::Execute
                    | WorkspaceOperation::WriteFile
                    | WorkspaceOperation::ReadFile
                    | WorkspaceOperation::Attest
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_supported_profile_names() {
        assert_eq!(
            "standard".parse::<ExecutionProfile>().expect("standard"),
            ExecutionProfile::Standard
        );
        assert_eq!(
            "confidential-azure"
                .parse::<ExecutionProfile>()
                .expect("azure"),
            ExecutionProfile::ConfidentialAzure
        );
        assert!("confidential".parse::<ExecutionProfile>().is_err());
        assert!("azure".parse::<ExecutionProfile>().is_err());
    }

    #[test]
    fn profile_mapping_is_explicit() {
        assert_eq!(
            ExecutionProfile::Standard.execution_backend(),
            ExecutionBackend::Firecracker
        );
        assert_eq!(
            ExecutionProfile::Standard.attestation_backend(),
            AttestationBackend::Software
        );
        assert_eq!(
            ExecutionProfile::ConfidentialAzure.execution_backend(),
            ExecutionBackend::OpenShell
        );
        assert_eq!(
            ExecutionProfile::ConfidentialAzure.attestation_backend(),
            AttestationBackend::SevSnpAzure
        );
        assert_eq!(
            ExecutionProfile::ConfidentialAzure.hard_workspace_capacity(),
            Some(1)
        );
    }

    #[test]
    fn azure_profile_exposes_only_supported_operations() {
        let profile = ExecutionProfile::ConfidentialAzure;
        assert!(profile.supports(WorkspaceOperation::Create));
        assert!(profile.supports(WorkspaceOperation::Destroy));
        assert!(profile.supports(WorkspaceOperation::Execute));
        assert!(profile.supports(WorkspaceOperation::WriteFile));
        assert!(profile.supports(WorkspaceOperation::ReadFile));
        assert!(profile.supports(WorkspaceOperation::Attest));
        assert!(!profile.supports(WorkspaceOperation::Pause));
        assert!(!profile.supports(WorkspaceOperation::Resume));
        assert!(!profile.supports(WorkspaceOperation::Snapshot));
        assert!(!profile.supports(WorkspaceOperation::Restore));
        assert!(!profile.supports(WorkspaceOperation::Fork));
        assert!(!profile.supports(WorkspaceOperation::WarmPool));
        assert!(!profile.supports(WorkspaceOperation::Ingress));
    }

    #[test]
    fn confidential_azure_capabilities_report_hard_capacity_without_snapshot() {
        let capabilities = ExecutionProfile::ConfidentialAzure.capabilities("0.2.0", 1);
        assert_eq!(capabilities.runtime_version, "0.2.0");
        assert_eq!(capabilities.hard_workspace_capacity, Some(1));
        assert!(
            capabilities
                .supported_operations
                .contains(&WorkspaceOperation::Attest)
        );
        assert!(
            !capabilities
                .supported_operations
                .contains(&WorkspaceOperation::Snapshot)
        );
        assert!(!capabilities.confidential_snapshot_supported);
        assert_eq!(capabilities.evidence_schema_version, 1);
    }
}
