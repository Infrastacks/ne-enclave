// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Render config / unit / tmpfiles files from embedded templates.
#![allow(unreachable_pub)]

use ne_protocol::profile::ExecutionProfile;

/// Values substituted into the templates.
#[derive(Debug, Clone)]
pub struct RenderVars {
    /// UID of the `ne` service account (peer-cred auth target).
    pub ne_uid: u32,
    /// Selected execution profile.
    pub execution_profile: ExecutionProfile,
}

const ENV_TMPL: &str = include_str!("../../templates/ne-enclave.env.tmpl");
const SUPERVISOR_UNIT: &str = include_str!("../../templates/ne-supervisor.service.tmpl");
const API_UNIT: &str = include_str!("../../templates/ne-api.service.tmpl");
const TMPFILES_CONF: &str = include_str!("../../templates/ne-enclave.conf.tmpl");
const PRIVACY_POLICY: &str = include_str!("../../templates/privacy-policy.yaml.tmpl");
const OPENSHELL_POLICY_RULES: &str = include_str!("../../templates/openshell-policy.rego");
const OPENSHELL_POLICY_DATA: &str = include_str!("../../templates/openshell-policy.yaml");

/// Render the `ne-enclave.env` `EnvironmentFile`, substituting all placeholders.
pub fn render_env(v: &RenderVars) -> String {
    ENV_TMPL
        .replace("__NE_UID__", &v.ne_uid.to_string())
        .replace("__EXECUTION_PROFILE__", &v.execution_profile.to_string())
}

/// Render the supervisor systemd unit for the selected execution profile.
pub fn render_supervisor_unit(v: &RenderVars) -> String {
    let (protect_home, private_tmp, home_bind, read_write_paths) = match v.execution_profile {
        ExecutionProfile::Standard => (
            "true",
            "false",
            "",
            "/var/lib/ne-enclave /run/ne-enclave /srv/jailer",
        ),
        ExecutionProfile::ConfidentialAzure => (
            "tmpfs",
            "true",
            "BindPaths=/home/sandbox",
            "/var/lib/ne-enclave /run/ne-enclave /home/sandbox",
        ),
    };
    SUPERVISOR_UNIT
        .replace("__SUPERVISOR_PROTECT_HOME__", protect_home)
        .replace("__SUPERVISOR_PRIVATE_TMP__", private_tmp)
        .replace("__SUPERVISOR_HOME_BIND__", home_bind)
        .replace("__SUPERVISOR_READ_WRITE_PATHS__", read_write_paths)
}
/// Render the API systemd unit (no substitutions).
pub fn render_api_unit() -> String {
    API_UNIT.to_string()
}
/// Render the tmpfiles.d config (no substitutions).
pub fn render_tmpfiles() -> String {
    TMPFILES_CONF.to_string()
}
/// Render the default host-global PII policy (no substitutions). Installed
/// only when no policy is already present, so operator edits survive.
pub fn render_privacy_policy() -> String {
    PRIVACY_POLICY.to_string()
}
/// Render the release-owned default OpenShell Rego policy.
pub fn render_openshell_policy_rules() -> String {
    OPENSHELL_POLICY_RULES.to_string()
}
/// Render the release-owned default OpenShell YAML policy data.
pub fn render_openshell_policy_data() -> String {
    OPENSHELL_POLICY_DATA.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ne_protocol::profile::ExecutionProfile;

    #[test]
    fn env_substitutes_all_placeholders() {
        let out = render_env(&RenderVars {
            ne_uid: 991,
            execution_profile: ExecutionProfile::Standard,
        });
        assert!(!out.contains("__"), "unsubstituted placeholder: {out}");
        assert!(out.contains("NE_SUPERVISOR_PEER_UID=991"));
        assert!(out.contains("NE_EXECUTION_PROFILE=standard"));
        assert!(!out.contains("NE_KERNEL_PATH"));
        assert!(!out.contains("NE_ROOTFS_PATH"));
        assert!(out.contains("NE_DEV_MODE=true"));
    }

    #[test]
    fn azure_env_renders_profile_and_openshell_binary() {
        let azure = render_env(&RenderVars {
            ne_uid: 991,
            execution_profile: ExecutionProfile::ConfidentialAzure,
        });
        assert!(azure.contains("NE_EXECUTION_PROFILE=confidential-azure"));
        assert!(azure.contains("NE_OPENSHELL_SANDBOX_BIN=/opt/ne-enclave/bin/openshell-sandbox"));
    }

    #[test]
    fn units_have_expected_posture() {
        let standard = RenderVars {
            ne_uid: 991,
            execution_profile: ExecutionProfile::Standard,
        };
        let sup = render_supervisor_unit(&standard);
        assert!(!sup.contains("__"), "unsubstituted placeholder: {sup}");
        assert!(sup.contains("Type=notify"));
        assert!(sup.contains("CAP_CHOWN"));
        assert!(sup.contains("ProtectHome=true"));
        assert!(sup.contains("/srv/jailer"));

        let azure = RenderVars {
            ne_uid: 991,
            execution_profile: ExecutionProfile::ConfidentialAzure,
        };
        let azure_sup = render_supervisor_unit(&azure);
        assert!(
            !azure_sup.contains("__"),
            "unsubstituted placeholder: {azure_sup}"
        );
        assert!(azure_sup.contains("ProtectHome=tmpfs"));
        assert!(azure_sup.contains("BindPaths=/home/sandbox"));
        assert!(azure_sup.contains("PrivateTmp=true"));
        assert!(azure_sup.contains("/home/sandbox"));
        assert!(!azure_sup.contains("/srv/jailer"));
        assert!(!azure_sup.contains("ReadWritePaths=/tmp"));

        let api = render_api_unit();
        assert!(api.contains("User=ne"));
        assert!(api.contains("Requires=ne-supervisor.service"));
        assert!(api.contains("CapabilityBoundingSet="));
    }

    #[test]
    fn privacy_policy_is_valid_redact_default() {
        let out = render_privacy_policy();
        assert!(
            out.contains("enforcement: redact"),
            "default policy must redact: {out}"
        );
        assert!(!out.contains("__"), "unsubstituted placeholder: {out}");
    }

    #[test]
    fn privacy_policy_deserializes_via_runtime_loader() {
        // Guards against shipping a default policy the runtime rejects:
        // the supervisor hands these bytes to ne-privacy-router's loader.
        let policy =
            ne_privacy_router::policy_loader::from_bytes(render_privacy_policy().as_bytes())
                .expect("shipped default policy must deserialize");
        assert_eq!(policy.enforcement, "redact");
        assert_eq!(
            policy.action_for(ne_privacy_router::EntityType::Email),
            ne_privacy_router::PiiAction::Redact,
            "fallback action must be redact for unlisted entities"
        );
    }
}
