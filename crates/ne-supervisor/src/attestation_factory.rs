// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed attestation provider and startup-requirement selection.

use std::ffi::OsStr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use ne_attestation::AttestationProvider;
use ne_protocol::profile::{AttestationBackend, ExecutionProfile};
use thiserror::Error;

/// Concrete host source used by an attestation backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSource {
    /// Ed25519 software signing.
    Software,
    /// Direct AMD SEV-SNP ioctl device.
    SevGuestIoctl,
    /// Azure `OpenHCL` vTPM report and quote path.
    AzureVtpm,
}

/// Portable snapshot of startup requirements used by the selected profile.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct StartupRequirements {
    /// Host is Linux `x86_64`.
    pub linux_x86_64: bool,
    /// `/dev/kvm` is available.
    pub kvm: bool,
    /// Azure vTPM device is available.
    pub azure_vtpm: bool,
    /// Firecracker binary is executable.
    pub firecracker: bool,
    /// Jailer binary is executable.
    pub jailer: bool,
    /// OpenShell sandbox binary is executable.
    pub openshell_sandbox: bool,
    /// OpenShell Rego policy exists.
    pub openshell_policy_rules: bool,
    /// OpenShell policy data exists.
    pub openshell_policy_data: bool,
    /// OpenShell sandbox service identity exists.
    pub sandbox_user: bool,
}

/// Fail-closed profile startup error.
#[derive(Debug, Error)]
pub enum ProfileStartupError {
    /// Deprecated posture variable was present.
    #[error(
        "NE_CONFIDENTIAL_MODE is no longer supported; set \
         NE_EXECUTION_PROFILE=confidential-azure"
    )]
    LegacyConfidentialSwitch,
    /// Selected attestation provider failed to initialize.
    #[error("attestation provider initialization failed for {backend:?}: {message}")]
    ProviderInit {
        /// Backend that failed.
        backend: AttestationBackend,
        /// Underlying diagnostic.
        message: String,
    },
    /// Required device, binary, policy, or account is absent.
    #[error("execution profile {profile} is missing requirement {requirement}")]
    RequirementMissing {
        /// Selected execution profile.
        profile: ExecutionProfile,
        /// Stable requirement name.
        requirement: &'static str,
    },
    /// Host platform cannot run the selected profile.
    #[error("execution profile {profile} conflicts with host state: {message}")]
    RequirementConflict {
        /// Selected execution profile.
        profile: ExecutionProfile,
        /// Conflict diagnostic.
        message: String,
    },
}

/// Reject the removed presence-based confidential-mode switch.
pub fn validate_legacy_confidential_switch(
    value: Option<&OsStr>,
) -> Result<(), ProfileStartupError> {
    if value.is_some() {
        Err(ProfileStartupError::LegacyConfidentialSwitch)
    } else {
        Ok(())
    }
}

/// Resolve the concrete source selected by an attestation backend.
#[must_use]
pub fn provider_source(backend: AttestationBackend) -> ProviderSource {
    match backend {
        AttestationBackend::Software => ProviderSource::Software,
        AttestationBackend::SevSnpDirect => ProviderSource::SevGuestIoctl,
        AttestationBackend::SevSnpAzure => ProviderSource::AzureVtpm,
    }
}

/// Validate all requirements before the supervisor reports readiness.
pub fn validate_startup_requirements(
    profile: ExecutionProfile,
    requirements: &StartupRequirements,
) -> Result<(), ProfileStartupError> {
    if !requirements.linux_x86_64 {
        return Err(ProfileStartupError::RequirementConflict {
            profile,
            message: "supported runtime hosts are Linux x86_64".into(),
        });
    }
    let require = |requirement: &'static str, present: bool| {
        if present {
            Ok(())
        } else {
            Err(ProfileStartupError::RequirementMissing {
                profile,
                requirement,
            })
        }
    };
    match profile {
        ExecutionProfile::Standard => {
            require("kvm", requirements.kvm)?;
            require("firecracker", requirements.firecracker)?;
            require("jailer", requirements.jailer)?;
        }
        ExecutionProfile::ConfidentialAzure => {
            require("azure-vtpm", requirements.azure_vtpm)?;
            require("openshell-sandbox", requirements.openshell_sandbox)?;
            require(
                "openshell-policy-rules",
                requirements.openshell_policy_rules,
            )?;
            require("openshell-policy-data", requirements.openshell_policy_data)?;
            require("sandbox-user", requirements.sandbox_user)?;
        }
    }
    Ok(())
}

/// Construct the profile-selected provider on Linux.
#[cfg(target_os = "linux")]
pub fn build_provider(
    backend: AttestationBackend,
    signing_key: SigningKey,
) -> Result<Arc<dyn AttestationProvider>, ProfileStartupError> {
    use ne_attestation::snp_source::IoctlSnpReportSource;
    use ne_attestation::vcek::{KdsVcekFetcher, VcekCache, VcekFetcher};
    use ne_attestation::{AzureVtpmReportSource, SevSnpProvider, SoftwareProvider};

    let vcek = || -> Arc<dyn VcekFetcher> { Arc::new(VcekCache::new(KdsVcekFetcher::new())) };

    match provider_source(backend) {
        ProviderSource::Software => Ok(Arc::new(SoftwareProvider::new(signing_key))),
        ProviderSource::SevGuestIoctl => {
            let source = IoctlSnpReportSource::open().map_err(|error| {
                ProfileStartupError::ProviderInit {
                    backend,
                    message: error.to_string(),
                }
            })?;
            Ok(Arc::new(SevSnpProvider::new(Arc::new(source), vcek())))
        }
        ProviderSource::AzureVtpm => {
            let source = AzureVtpmReportSource::open().map_err(|error| {
                ProfileStartupError::ProviderInit {
                    backend,
                    message: error.to_string(),
                }
            })?;
            Ok(Arc::new(SevSnpProvider::new_azure(source, vcek())))
        }
    }
}

/// Construct the software provider or reject hardware providers off Linux.
#[cfg(not(target_os = "linux"))]
pub fn build_provider(
    backend: AttestationBackend,
    signing_key: SigningKey,
) -> Result<Arc<dyn AttestationProvider>, ProfileStartupError> {
    use ne_attestation::SoftwareProvider;

    match backend {
        AttestationBackend::Software => Ok(Arc::new(SoftwareProvider::new(signing_key))),
        AttestationBackend::SevSnpDirect | AttestationBackend::SevSnpAzure => {
            Err(ProfileStartupError::ProviderInit {
                backend,
                message: "hardware attestation providers require Linux".into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ne_protocol::profile::{AttestationBackend, ExecutionProfile};

    #[test]
    fn azure_backend_selects_vtpm_source() {
        assert_eq!(
            provider_source(AttestationBackend::SevSnpAzure),
            ProviderSource::AzureVtpm
        );
    }

    #[test]
    fn direct_backend_selects_ioctl_source() {
        assert_eq!(
            provider_source(AttestationBackend::SevSnpDirect),
            ProviderSource::SevGuestIoctl
        );
    }

    #[test]
    fn legacy_switch_is_always_rejected_when_present() {
        let err = validate_legacy_confidential_switch(Some(OsStr::new("0")))
            .expect_err("legacy switch must fail");
        assert!(err.to_string().contains("NE_EXECUTION_PROFILE"));
    }

    #[test]
    fn azure_profile_rejects_missing_policy_before_readiness() {
        let mut requirements = complete_azure_startup_requirements();
        requirements.openshell_policy_rules = false;
        let err = validate_startup_requirements(ExecutionProfile::ConfidentialAzure, &requirements)
            .expect_err("missing policy must fail");
        assert!(matches!(
            err,
            ProfileStartupError::RequirementMissing {
                requirement: "openshell-policy-rules",
                ..
            }
        ));
    }

    fn complete_azure_startup_requirements() -> StartupRequirements {
        StartupRequirements {
            linux_x86_64: true,
            kvm: false,
            azure_vtpm: true,
            firecracker: false,
            jailer: false,
            openshell_sandbox: true,
            openshell_policy_rules: true,
            openshell_policy_data: true,
            sandbox_user: true,
        }
    }
}
