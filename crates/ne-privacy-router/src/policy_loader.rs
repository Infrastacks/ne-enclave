// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! YAML policy loader for the privacy-router binary.
//!
//! `PiiPolicy` is `serde::Deserialize` (from the openshell-pii crate),
//! so the loader is a thin file-read + `serde_yaml` deserialize. It
//! lives in its own module so the binary's policy plumbing is
//! independent of where the policy bytes originate — future wedges
//! that drive policy from gRPC config or a fetched file can substitute
//! `from_bytes` without touching the proxy code.

use std::path::Path;

use thiserror::Error;

use crate::PiiPolicy;

/// Failure modes for [`load_from_path`].
#[derive(Debug, Error)]
pub enum LoadError {
    /// The policy file could not be opened or read.
    #[error("read policy file {path}: {source}")]
    Io {
        /// The path we attempted to read.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The policy file contents did not deserialize as a `PiiPolicy`.
    #[error("parse policy YAML at {path}: {source}")]
    Parse {
        /// The path we attempted to parse.
        path: String,
        /// The underlying deserializer error.
        #[source]
        source: serde_yaml::Error,
    },
}

/// Load a [`PiiPolicy`] from a YAML file on disk.
pub fn load_from_path(path: &Path) -> Result<PiiPolicy, LoadError> {
    let bytes = std::fs::read(path).map_err(|source| LoadError::Io {
        path: path.display().to_string(),
        source,
    })?;
    from_bytes(&bytes).map_err(|source| LoadError::Parse {
        path: path.display().to_string(),
        source,
    })
}

/// Deserialize a [`PiiPolicy`] from a YAML byte buffer.
pub fn from_bytes(bytes: &[u8]) -> Result<PiiPolicy, serde_yaml::Error> {
    serde_yaml::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;

    use super::*;
    use crate::{EntityType, PiiAction};

    #[test]
    fn from_bytes_parses_full_policy() {
        let yaml = r#"
enforcement: redact
entities:
  ssn: block
  credit_card: redact
custom_patterns:
  - name: employee_id
    pattern: "EMP-\\d{6}"
    action: redact
"#;
        let policy = from_bytes(yaml.as_bytes()).unwrap();
        assert_eq!(policy.enforcement, "redact");
        assert_eq!(
            policy.entities.get(&EntityType::Ssn),
            Some(&PiiAction::Block)
        );
        assert_eq!(
            policy.entities.get(&EntityType::CreditCard),
            Some(&PiiAction::Redact)
        );
        assert_eq!(policy.custom_patterns.len(), 1);
        assert_eq!(policy.custom_patterns[0].name, "employee_id");
    }

    #[test]
    fn from_bytes_accepts_minimal_policy() {
        // Only `enforcement` is required; everything else has a serde default.
        let policy = from_bytes(b"enforcement: audit\n").unwrap();
        assert_eq!(policy.enforcement, "audit");
        assert!(policy.entities.is_empty());
        assert!(policy.custom_patterns.is_empty());
    }

    #[test]
    fn from_bytes_rejects_malformed_yaml() {
        let err = from_bytes(b"not: [valid yaml").unwrap_err();
        // Just confirm we got a parse error; serde_yaml's exact message is
        // version-dependent.
        let _ = err.to_string();
    }

    #[test]
    fn load_from_path_round_trip() {
        let mut tmp = tempfile_path("ne-privacy-router-policy");
        {
            let mut f = std::fs::File::create(&tmp).unwrap();
            writeln!(f, "enforcement: block").unwrap();
        }
        let policy = load_from_path(&tmp).unwrap();
        assert_eq!(policy.enforcement, "block");
        // action_for falls back to enforcement for unconfigured entities.
        let entities: HashMap<EntityType, PiiAction> = policy.entities.clone();
        assert!(entities.is_empty());
        assert_eq!(policy.action_for(EntityType::Email), PiiAction::Block);

        let _ = std::fs::remove_file(&tmp);
        tmp.pop();
    }

    #[test]
    fn load_from_path_surfaces_missing_file() {
        let err =
            load_from_path(Path::new("/nonexistent/ne-privacy-router/policy.yaml")).unwrap_err();
        assert!(matches!(err, LoadError::Io { .. }));
    }

    /// Minimal `tempfile`-free temp-path helper to avoid pulling another
    /// dev-dep in for two tests.
    fn tempfile_path(prefix: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        p.push(format!("{prefix}-{pid}-{nanos}.yaml"));
        p
    }
}
