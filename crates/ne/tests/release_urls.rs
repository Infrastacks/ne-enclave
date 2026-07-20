// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

// Locks the canonical release/repository coordinates.
//
// These are behaviour-bearing: `url_base` is where `nee` fetches guest-image
// assets from at runtime, and install.sh's REPO default is where the install
// one-liner pulls from. A bulk find/replace that rewrites only the org (as
// happened during the July 2026 Mindpool transfer) silently produces a URL
// that resolves to a 404 with no compile or test failure. This asserts the
// full owner/repository, not just the org, so that class of edit fails loudly.
//
// GitHub's transfer redirects are deliberately NOT relied on here: pinned
// coordinates must name the canonical location directly.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::{Path, PathBuf};

/// Canonical repository. Update here (and only here) if the repo ever moves.
const CANONICAL_REPO: &str = "Mindpool-Labs/ne-enclave";

/// Orgs that previously hosted this project. Their URLs must not reappear in
/// shipped source, templates, or deploy assets — historical attribution lives
/// in NOTICE, not in fetch coordinates.
const STALE_ORGS: &[&str] = &["github.com/Infrastacks/"];

fn repo_root() -> PathBuf {
    // crates/ne -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).expect("release contract source file must be readable")
}

#[test]
fn default_image_fetches_from_the_canonical_repo() {
    let expected = format!("https://github.com/{CANONICAL_REPO}/releases/latest/download");
    assert_eq!(
        ne::install::image::DEFAULT_IMAGE.url_base,
        expected,
        "guest-image assets must be fetched from {CANONICAL_REPO}"
    );
}

#[test]
fn install_script_defaults_to_the_canonical_repo() {
    let sh = read("deploy/install.sh");
    assert!(
        sh.contains(&format!("NE_REPO:-{CANONICAL_REPO}")),
        "deploy/install.sh REPO default must be {CANONICAL_REPO}"
    );
}

#[test]
fn systemd_units_document_the_canonical_repo() {
    let expected = format!("Documentation=https://github.com/{CANONICAL_REPO}");
    for unit in [
        "crates/ne/templates/ne-api.service.tmpl",
        "crates/ne/templates/ne-supervisor.service.tmpl",
        "deploy/ne-api.service",
        "deploy/ne-supervisor.service",
    ] {
        assert!(
            read(unit).contains(&expected),
            "{unit} must document {CANONICAL_REPO}"
        );
    }
}

#[test]
fn no_stale_org_urls_in_shipped_assets() {
    // Files that carry fetch/reference coordinates a user's machine acts on.
    for rel in [
        "crates/ne/src/install/image.rs",
        "crates/ne/templates/ne-api.service.tmpl",
        "crates/ne/templates/ne-supervisor.service.tmpl",
        "deploy/install.sh",
        "deploy/ne-api.service",
        "deploy/ne-supervisor.service",
        "deploy/release-components.json",
        "crates/ne-privacy-router/Cargo.toml",
        "Cargo.toml",
    ] {
        let body = read(rel);
        for stale in STALE_ORGS {
            assert!(
                !body.contains(stale),
                "{rel} still points at a stale org URL ({stale}) — pinned \
                 coordinates must not rely on GitHub transfer redirects"
            );
        }
    }
}

#[test]
fn openshell_dependency_pins_the_canonical_fork() {
    let manifest = read("crates/ne-privacy-router/Cargo.toml");
    assert!(
        manifest.contains("https://github.com/Mindpool-Labs/OpenShell.git"),
        "openshell-pii must resolve from Mindpool-Labs/OpenShell"
    );
    // The pinned rev is the security-relevant half: rewiring the URL must never
    // silently move the commit the build resolves to.
    assert!(
        manifest.contains("70328542941838612a75b62c3cc365e01594c0c3"),
        "openshell-pii rev pin must be unchanged by any URL rewrite"
    );
}
