// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Render config / unit / tmpfiles files from embedded templates.
#![allow(unreachable_pub)]

/// Values substituted into the templates.
#[derive(Debug, Clone)]
pub struct RenderVars {
    /// UID of the `ne` service account (peer-cred auth target).
    pub ne_uid: u32,
    /// Absolute path to the default guest kernel image.
    pub kernel_path: String,
    /// Absolute path to the default guest rootfs image.
    pub rootfs_path: String,
}

const ENV_TMPL: &str = include_str!("../../templates/ne-enclave.env.tmpl");
const SUPERVISOR_UNIT: &str = include_str!("../../templates/ne-supervisor.service.tmpl");
const API_UNIT: &str = include_str!("../../templates/ne-api.service.tmpl");
const TMPFILES_CONF: &str = include_str!("../../templates/ne-enclave.conf.tmpl");
const PRIVACY_POLICY: &str = include_str!("../../templates/privacy-policy.yaml.tmpl");

/// Render the `ne-enclave.env` `EnvironmentFile`, substituting all placeholders.
pub fn render_env(v: &RenderVars) -> String {
    ENV_TMPL
        .replace("__NE_UID__", &v.ne_uid.to_string())
        .replace("__KERNEL_PATH__", &v.kernel_path)
        .replace("__ROOTFS_PATH__", &v.rootfs_path)
}

/// Render the supervisor systemd unit (no substitutions).
pub fn render_supervisor_unit() -> String {
    SUPERVISOR_UNIT.to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_substitutes_all_placeholders() {
        let out = render_env(&RenderVars {
            ne_uid: 991,
            kernel_path: "/var/lib/ne-enclave/images/kernels/abc/vmlinux".into(),
            rootfs_path: "/var/lib/ne-enclave/images/rootfs/def/rootfs.img".into(),
        });
        assert!(!out.contains("__"), "unsubstituted placeholder: {out}");
        assert!(out.contains("NE_SUPERVISOR_PEER_UID=991"));
        assert!(out.contains("/images/kernels/abc/vmlinux"));
        assert!(out.contains("NE_DEV_MODE=true"));
    }

    #[test]
    fn units_have_expected_posture() {
        let sup = render_supervisor_unit();
        assert!(sup.contains("Type=notify"));
        assert!(sup.contains("CAP_CHOWN"));
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
