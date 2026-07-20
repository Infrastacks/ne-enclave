// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Drives `install::run::install` against a temp prefix root with no
//! systemd / KVM / root. Asserts dirs, env, units, tmpfiles land.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ne::install::layout::Layout;
use ne::install::run::{InstallOptions, install};

#[test]
fn fakeroot_install_creates_missing_prefix_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("fakeroot");
    assert!(!root.exists());
    let layout = Layout::new(&root);

    install(InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::Standard,
        layout: layout.clone(),
        fakeroot: true,
        no_start: true,
        no_image: true,
        dry_run: false,
        ne_uid: 991,
        openshell_sandbox_source: None,
        openshell_policy_rules_source: None,
        openshell_policy_data_source: None,
    })
    .expect("fakeroot install with missing prefix");

    assert!(root.is_dir(), "prefix root missing: {}", root.display());
    assert!(
        layout.supervisor_unit().is_file(),
        "supervisor unit missing: {}",
        layout.supervisor_unit().display()
    );
}

#[cfg(unix)]
#[test]
fn fakeroot_install_rejects_symlink_prefix_without_touching_target() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("fakeroot");
    let sentinel = tmp.path().join("sentinel");
    std::fs::create_dir(&sentinel).unwrap();
    std::fs::write(sentinel.join("payload"), b"must-not-change").unwrap();
    std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o711)).unwrap();
    let before = std::fs::metadata(&sentinel).unwrap();
    symlink(&sentinel, &root).unwrap();

    let result = install(InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::Standard,
        layout: Layout::new(&root),
        fakeroot: true,
        no_start: true,
        no_image: true,
        dry_run: false,
        ne_uid: 991,
        openshell_sandbox_source: None,
        openshell_policy_rules_source: None,
        openshell_policy_data_source: None,
    });

    assert!(result.is_err(), "accepted symlink prefix root");
    assert_eq!(
        std::fs::read(sentinel.join("payload")).unwrap(),
        b"must-not-change"
    );
    let after = std::fs::metadata(&sentinel).unwrap();
    assert_eq!(after.mode(), before.mode(), "changed target mode");
    assert_eq!(after.uid(), before.uid(), "changed target owner");
    assert_eq!(after.gid(), before.gid(), "changed target group");
}

#[cfg(unix)]
#[test]
fn fakeroot_install_rejects_regular_file_prefix_without_changing_contents() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("fakeroot");
    std::fs::write(&root, b"must-not-change").unwrap();

    let result = install(InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::Standard,
        layout: Layout::new(&root),
        fakeroot: true,
        no_start: true,
        no_image: true,
        dry_run: false,
        ne_uid: 991,
        openshell_sandbox_source: None,
        openshell_policy_rules_source: None,
        openshell_policy_data_source: None,
    });

    assert!(result.is_err(), "accepted regular file prefix root");
    assert_eq!(std::fs::read(&root).unwrap(), b"must-not-change");
}

#[test]
fn fakeroot_install_creates_layout_and_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let layout = Layout::new(root);

    install(InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::Standard,
        layout: layout.clone(),
        fakeroot: true,
        no_start: true,
        no_image: true,
        dry_run: false,
        ne_uid: 991,
        openshell_sandbox_source: None,
        openshell_policy_rules_source: None,
        openshell_policy_data_source: None,
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
    assert!(!env.contains("NE_KERNEL_PATH"));
    assert!(!env.contains("NE_ROOTFS_PATH"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(layout.images_dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
        assert_eq!(mode & 0o022, 0, "service identity could write image store");
    }

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

#[cfg(unix)]
#[test]
fn fakeroot_confidential_install_provisions_openshell_without_guest_images() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().unwrap();
    let layout = Layout::new(tmp.path().join("root"));
    let source = tmp.path().join("openshell-sandbox");
    std::fs::write(&source, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
    let rules_source = tmp.path().join("policy.rego");
    let data_source = tmp.path().join("policy.yaml");
    std::fs::write(&rules_source, "package test\n").unwrap();
    std::fs::write(&data_source, "version: 1\nnetwork_policies: {}\n").unwrap();

    let options = InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::ConfidentialAzure,
        layout: layout.clone(),
        fakeroot: true,
        no_start: true,
        no_image: false,
        dry_run: false,
        ne_uid: 991,
        openshell_sandbox_source: Some(source),
        openshell_policy_rules_source: Some(rules_source),
        openshell_policy_data_source: Some(data_source),
    };
    install(options.clone()).expect("confidential fakeroot install");

    assert!(layout.openshell_sandbox_binary().is_file());
    assert_eq!(
        std::fs::metadata(layout.openshell_sandbox_binary())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(layout.openshell_policy_rules().is_file());
    assert!(layout.openshell_policy_data().is_file());
    assert_eq!(
        std::fs::metadata(layout.openshell_policy_rules())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(
        std::fs::metadata(layout.openshell_policy_data())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(
        std::fs::read_to_string(layout.openshell_policy_rules()).unwrap(),
        "package test\n"
    );
    assert_eq!(
        std::fs::read_to_string(layout.openshell_policy_data()).unwrap(),
        "version: 1\nnetwork_policies: {}\n"
    );
    let env = std::fs::read_to_string(layout.env_file()).unwrap();
    assert!(env.contains("NE_EXECUTION_PROFILE=confidential-azure"));
    assert!(!layout.images_dir().join("kernels").exists());
    assert!(!layout.images_dir().exists());
    assert!(!layout.jailer_base().exists());
    let supervisor_unit = std::fs::read_to_string(layout.supervisor_unit()).unwrap();
    assert!(supervisor_unit.contains("ProtectHome=tmpfs"));
    assert!(supervisor_unit.contains("BindPaths=/home/sandbox"));
    assert!(supervisor_unit.contains("PrivateTmp=true"));
    assert!(supervisor_unit.contains("/home/sandbox"));
    assert!(!supervisor_unit.contains("/srv/jailer"));
    assert!(!supervisor_unit.contains("ReadWritePaths=/tmp"));
    assert!(!supervisor_unit.contains("__"));

    std::fs::write(layout.openshell_policy_rules(), "operator edit\n").unwrap();
    install(options).expect("confidential reinstall");
    assert_eq!(
        std::fs::read_to_string(layout.openshell_policy_rules()).unwrap(),
        "operator edit\n"
    );
}

#[cfg(unix)]
#[test]
fn fakeroot_confidential_install_uses_embedded_release_policies() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().unwrap();
    let layout = Layout::new(tmp.path().join("root"));
    let source = tmp.path().join("openshell-sandbox");
    std::fs::write(&source, b"binary").unwrap();

    install(InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::ConfidentialAzure,
        layout: layout.clone(),
        fakeroot: true,
        no_start: true,
        no_image: false,
        dry_run: false,
        ne_uid: 991,
        openshell_sandbox_source: Some(source),
        openshell_policy_rules_source: None,
        openshell_policy_data_source: None,
    })
    .expect("confidential install with embedded policies");

    assert!(
        std::fs::read_to_string(layout.openshell_policy_rules())
            .unwrap()
            .contains("package openshell.sandbox")
    );
    assert!(
        std::fs::read_to_string(layout.openshell_policy_data())
            .unwrap()
            .contains("network_policies: {}")
    );
    assert_eq!(
        std::fs::metadata(layout.openshell_policy_rules())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[cfg(unix)]
#[test]
fn confidential_install_rejects_policy_destination_symlink() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let layout = Layout::new(tmp.path().join("root"));
    let source = tmp.path().join("openshell-sandbox");
    std::fs::write(&source, b"binary").unwrap();
    std::fs::create_dir_all(layout.openshell_dir()).unwrap();
    let outside = tmp.path().join("outside-policy");
    std::fs::write(&outside, b"outside").unwrap();
    symlink(&outside, layout.openshell_policy_rules()).unwrap();

    let result = install(InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::ConfidentialAzure,
        layout,
        fakeroot: true,
        no_start: true,
        no_image: false,
        dry_run: false,
        ne_uid: 991,
        openshell_sandbox_source: Some(source),
        openshell_policy_rules_source: None,
        openshell_policy_data_source: None,
    });

    assert!(result.is_err(), "accepted policy destination symlink");
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
}

#[test]
fn confidential_install_requires_sandbox_source_before_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let result = install(InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::ConfidentialAzure,
        layout: Layout::new(&root),
        fakeroot: true,
        no_start: true,
        no_image: false,
        dry_run: false,
        ne_uid: 991,
        openshell_sandbox_source: None,
        openshell_policy_rules_source: None,
        openshell_policy_data_source: None,
    });
    assert!(result.is_err());
    assert!(!root.exists(), "failed validation mutated the install root");
}

#[test]
fn confidential_dry_run_rejects_missing_component_sources() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let result = install(InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::ConfidentialAzure,
        layout: Layout::new(&root),
        fakeroot: true,
        no_start: true,
        no_image: false,
        dry_run: true,
        ne_uid: 991,
        openshell_sandbox_source: Some(tmp.path().join("missing-openshell-sandbox")),
        openshell_policy_rules_source: None,
        openshell_policy_data_source: None,
    });
    assert!(result.is_err());
    assert!(!root.exists(), "failed dry-run validation mutated the root");
}

#[test]
fn fakeroot_reinstall_preserves_operator_policy_edits() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let layout = Layout::new(root);

    let opts = InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::Standard,
        layout: layout.clone(),
        fakeroot: true,
        no_start: true,
        no_image: true,
        dry_run: false,
        ne_uid: 991,
        openshell_sandbox_source: None,
        openshell_policy_rules_source: None,
        openshell_policy_data_source: None,
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

#[test]
fn fakeroot_reinstall_corrects_existing_image_store_modes() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let layout = Layout::new(tmp.path());
    let artifact = layout
        .images_dir()
        .join("kernels")
        .join("a".repeat(64))
        .join("vmlinux");
    std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
    std::fs::write(&artifact, b"kernel").unwrap();
    std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o666)).unwrap();
    std::fs::set_permissions(
        artifact.parent().unwrap(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();

    install(InstallOptions {
        execution_profile: ne_protocol::profile::ExecutionProfile::Standard,
        layout,
        fakeroot: true,
        no_start: true,
        no_image: true,
        dry_run: false,
        ne_uid: 991,
        openshell_sandbox_source: None,
        openshell_policy_rules_source: None,
        openshell_policy_data_source: None,
    })
    .unwrap();

    assert_eq!(
        std::fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
        0o444
    );
    assert_eq!(
        std::fs::metadata(artifact.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[test]
fn fakeroot_reinstall_rejects_legacy_state_child_symlinks_without_touching_targets() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    for child in ["images", "workspaces", "snapshots"] {
        let tmp = tempfile::tempdir().unwrap();
        let layout = Layout::new(tmp.path());
        std::fs::create_dir_all(layout.state_dir()).unwrap();
        let sentinel = tmp.path().join(format!("{child}-sentinel"));
        std::fs::create_dir(&sentinel).unwrap();
        std::fs::write(sentinel.join("payload"), b"must-not-change").unwrap();
        std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o711)).unwrap();
        let before = std::fs::metadata(&sentinel).unwrap();
        symlink(&sentinel, layout.state_dir().join(child)).unwrap();

        let result = install(InstallOptions {
            execution_profile: ne_protocol::profile::ExecutionProfile::Standard,
            layout,
            fakeroot: true,
            no_start: true,
            no_image: true,
            dry_run: false,
            ne_uid: 991,
            openshell_sandbox_source: None,
            openshell_policy_rules_source: None,
            openshell_policy_data_source: None,
        });

        assert!(result.is_err(), "accepted legacy {child} symlink");
        assert_eq!(
            std::fs::read(sentinel.join("payload")).unwrap(),
            b"must-not-change"
        );
        let after = std::fs::metadata(&sentinel).unwrap();
        assert_eq!(after.mode(), before.mode(), "changed {child} target mode");
        assert_eq!(after.uid(), before.uid(), "changed {child} target owner");
        assert_eq!(after.gid(), before.gid(), "changed {child} target group");
    }
}

#[test]
fn direct_import_prepare_rejects_image_store_symlink_without_touching_target() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    let tmp = tempfile::tempdir().unwrap();
    let layout = Layout::new(tmp.path());
    std::fs::create_dir_all(layout.state_dir()).unwrap();
    let sentinel = tmp.path().join("import-sentinel");
    std::fs::create_dir(&sentinel).unwrap();
    std::fs::write(sentinel.join("payload"), b"must-not-change").unwrap();
    std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o711)).unwrap();
    let before = std::fs::metadata(&sentinel).unwrap();
    symlink(&sentinel, layout.images_dir()).unwrap();

    let result = ne::install::run::prepare_image_store(&layout, true);

    assert!(result.is_err());
    assert_eq!(
        std::fs::read(sentinel.join("payload")).unwrap(),
        b"must-not-change"
    );
    let after = std::fs::metadata(&sentinel).unwrap();
    assert_eq!(after.mode(), before.mode());
    assert_eq!(after.uid(), before.uid());
    assert_eq!(after.gid(), before.gid());
}
