// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Hostname parser for the NeuronEdge Enclave ingress edge.
//!
//! Parses `{port}-{wsid}.{ingress_domain}` from an HTTP `Host` header into a
//! `(port, wsid)` pair, enforcing the jailer identifier grammar and port range.

use thiserror::Error;

/// Why a Host header failed to resolve to an ingress route.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IngressError {
    /// The host label did not match `{port}-{wsid}.{domain}`, the port was
    /// out of range, or the wsid violated the jailer identifier grammar.
    #[error("host header does not parse as {{port}}-{{wsid}}.{{domain}}")]
    Parse,
    /// The host domain did not equal the configured ingress domain.
    #[error("host domain does not match the configured ingress domain")]
    DomainMismatch,
}

/// Parse a Host header into `(port, wsid)`.
///
/// Expects the form `{port}-{wsid}.{ingress_domain}`. `wsid` must satisfy
/// the jailer grammar `[a-zA-Z0-9-]{1,64}`; `port` ∈ 1..=65535. Any
/// `:authority-port` suffix is stripped first. The domain must equal
/// `ingress_domain` exactly (no sub-domains).
///
/// Only the FIRST `-` separates port from wsid, so wsid may itself contain
/// hyphens (`8080-ws-a-b` → port 8080, wsid `ws-a-b`).
///
/// The domain match is case-insensitive (DNS/Host headers are), but the wsid
/// is case-sensitive (jailer ids are `[a-zA-Z0-9-]`). Operators should use
/// lowercase workspace ids for ingress reliability, since HTTP intermediaries
/// may lowercase the Host header.
pub fn parse_ingress_host(host: &str, ingress_domain: &str) -> Result<(u16, String), IngressError> {
    // Strip optional `:port` authority suffix (e.g. `:443`).
    let host = host.split(':').next().unwrap_or("").trim();
    let suffix = format!(".{}", ingress_domain.to_ascii_lowercase());
    // DNS is case-insensitive: match the domain on a lowercased copy, but
    // keep the original-case label so the wsid (case-sensitive) is preserved.
    let host_lower = host.to_ascii_lowercase();
    let label_len = host_lower
        .strip_suffix(&suffix)
        .map(str::len)
        .ok_or(IngressError::DomainMismatch)?;
    let label = &host[..label_len];
    // Split only on the FIRST '-' so wsid may contain hyphens.
    let (port_str, wsid) = label.split_once('-').ok_or(IngressError::Parse)?;
    // `parse::<u16>()` rejects values > 65535 and non-numeric strings.
    let port: u16 = port_str.parse().map_err(|_| IngressError::Parse)?;
    if port == 0 {
        return Err(IngressError::Parse);
    }
    if wsid.is_empty()
        || wsid.len() > 64
        || !wsid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(IngressError::Parse);
    }
    Ok((port, wsid.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_host() {
        let (port, ws) =
            parse_ingress_host("8080-ws-a.apps.example.com", "apps.example.com").unwrap();
        assert_eq!(port, 8080);
        assert_eq!(ws, "ws-a");
    }

    #[test]
    fn strips_authority_port_suffix() {
        let (port, ws) =
            parse_ingress_host("8080-ws-a.apps.example.com:443", "apps.example.com").unwrap();
        assert_eq!((port, ws.as_str()), (8080, "ws-a"));
    }

    #[test]
    fn rejects_wrong_domain() {
        assert!(matches!(
            parse_ingress_host("8080-ws-a.evil.com", "apps.example.com"),
            Err(IngressError::DomainMismatch)
        ));
    }

    #[test]
    fn rejects_bad_port_and_wsid() {
        for bad in [
            "0-ws.apps.example.com",
            "99999-ws.apps.example.com",
            "x-ws.apps.example.com",
            "8080-.apps.example.com",
            "8080-ws_a.apps.example.com",
            "ws-a.apps.example.com",
        ] {
            assert!(
                parse_ingress_host(bad, "apps.example.com").is_err(),
                "{bad} should fail"
            );
        }
    }

    #[test]
    fn rejects_oversized_wsid() {
        let big = format!("8080-{}.apps.example.com", "a".repeat(65));
        assert!(matches!(
            parse_ingress_host(&big, "apps.example.com"),
            Err(IngressError::Parse)
        ));
    }

    #[test]
    fn matches_domain_case_insensitively() {
        let (port, ws) =
            parse_ingress_host("8080-ws-a.APPS.EXAMPLE.COM", "apps.example.com").unwrap();
        assert_eq!((port, ws.as_str()), (8080, "ws-a"));
    }

    #[test]
    fn matches_domain_arg_case_insensitively() {
        let (port, ws) =
            parse_ingress_host("8080-ws-a.apps.example.com", "APPS.EXAMPLE.COM").unwrap();
        assert_eq!((port, ws.as_str()), (8080, "ws-a"));
    }

    #[test]
    fn preserves_wsid_case() {
        let (port, ws) =
            parse_ingress_host("8080-WsA.apps.example.com", "apps.example.com").unwrap();
        assert_eq!((port, ws.as_str()), (8080, "WsA"));
    }

    #[test]
    fn preserves_hyphenated_wsid() {
        // wsid may itself contain hyphens; only the FIRST '-' splits port from wsid.
        let (port, ws) =
            parse_ingress_host("3000-ws-a-b-c.apps.example.com", "apps.example.com").unwrap();
        assert_eq!((port, ws.as_str()), (3000, "ws-a-b-c"));
    }
}
