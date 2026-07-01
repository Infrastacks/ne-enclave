// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Drives `install::run::install` against a temp prefix root with no
//! systemd / KVM / root. Asserts dirs, env, units, tmpfiles land.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ne::install::layout::Layout;
use ne::install::run::{InstallOptions, install};

#[test]
fn fakeroot_install_creates_layout_and_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let layout = Layout::new(root);

    install(InstallOptions {
        layout: layout.clone(),
        fakeroot: true,
        no_start: true,
        no_image: true,
        dry_run: false,
        ne_uid: 991,
    })
    .expect("fakeroot install");

    for d in [
        layout.images_dir(),
        layout.workspaces_dir(),
        layout.snapshots_dir(),
        layout.jailer_base(),
        layout.etc_dir(),
        layout.systemd_dir(),
    ] {
        assert!(d.is_dir(), "missing dir {}", d.display());
    }

    let env = std::fs::read_to_string(layout.env_file()).unwrap();
    assert!(
        env.contains("NE_SUPERVISOR_PEER_UID=991"),
        "env missing uid line:\n{env}"
    );
    assert!(
        env.contains("NE_DEV_MODE=true"),
        "env missing dev-mode line:\n{env}"
    );

    assert!(
        layout.supervisor_unit().exists(),
        "supervisor unit missing: {}",
        layout.supervisor_unit().display()
    );
    let api = std::fs::read_to_string(layout.api_unit()).unwrap();
    assert!(api.contains("User=ne"), "api unit missing User=ne:\n{api}");

    let tmpfiles = std::fs::read_to_string(layout.tmpfiles_conf()).unwrap();
    assert!(
        tmpfiles.contains("/run/ne-enclave"),
        "tmpfiles missing /run/ne-enclave:\n{tmpfiles}"
    );

    let policy = std::fs::read_to_string(layout.privacy_policy_file()).unwrap();
    assert!(
        policy.contains("enforcement: redact"),
        "privacy policy missing redact default:\n{policy}"
    );
}

#[test]
fn fakeroot_reinstall_preserves_operator_policy_edits() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let layout = Layout::new(root);

    let opts = InstallOptions {
        layout: layout.clone(),
        fakeroot: true,
        no_start: true,
        no_image: true,
        dry_run: false,
        ne_uid: 991,
    };
    install(opts.clone()).expect("first install");

    // Operator hardens the shipped policy.
    std::fs::write(layout.privacy_policy_file(), "enforcement: block\n").unwrap();

    install(opts).expect("re-install");

    let after = std::fs::read_to_string(layout.privacy_policy_file()).unwrap();
    assert_eq!(
        after, "enforcement: block\n",
        "re-install clobbered operator policy"
    );
}
