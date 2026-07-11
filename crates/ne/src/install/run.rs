// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Idempotent host provisioning.

use std::fs;

use anyhow::{Context, Result};

use crate::install::image;
use crate::install::layout::Layout;
use crate::install::preflight;
use crate::install::render::{self, RenderVars};

/// Options resolved by the CLI before running an install.
// Four bools is the natural shape here; a state-machine refactor would add
// more complexity than clarity for a configuration struct.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Resolved filesystem layout (carries the `--prefix` root).
    pub layout: Layout,
    /// True when `--prefix` is set: skip user/group + systemctl.
    pub fakeroot: bool,
    /// Do not `systemctl enable --now` the units after rendering them.
    pub no_start: bool,
    /// Do not fetch the default guest image.
    pub no_image: bool,
    /// Print actions without mutating the filesystem.
    pub dry_run: bool,
    /// UID for the `ne` service account used in the env file.
    /// Callers should set this to a deterministic value (e.g. 991) for
    /// fakeroot tests. On real installs `install()` re-resolves the uid
    /// after `ensure_service_user` so any value passed here is overridden.
    pub ne_uid: u32,
}

/// Provision the host. Idempotent: re-running is a no-op where state exists.
pub fn install(opts: InstallOptions) -> Result<()> {
    let l = &opts.layout;

    // 1. Directories (always safe to create).
    for d in [
        l.bin_dir(),
        l.etc_dir(),
        l.state_dir(),
        l.images_dir(),
        l.workspaces_dir(),
        l.snapshots_dir(),
        l.jailer_base(),
        l.systemd_dir(),
        l.run_dir(),
    ] {
        if opts.dry_run {
            tracing::info!("[dry-run] mkdir -p {}", d.display());
        } else {
            fs::create_dir_all(&d).with_context(|| format!("mkdir {}", d.display()))?;
        }
    }

    // 2. Service user/group (real installs only); resolve uid after creation.
    let ne_uid = if opts.fakeroot || opts.dry_run {
        opts.ne_uid
    } else {
        ensure_service_user("ne")?;
        resolve_uid_after_creation("ne")
    };

    // 2b. Apply directory ownership + modes (real installs only).
    if !opts.fakeroot && !opts.dry_run {
        apply_ownership(l)?;
    }
    if !opts.dry_run {
        image::harden_store(&l.images_dir(), opts.fakeroot)?;
    }

    // 3. Guest image (default pin), unless --no-image. Custom/air-gap
    //    images are provisioned separately via `nee image import`/`pull`.
    if !opts.no_image {
        if opts.dry_run {
            tracing::info!("[dry-run] fetch default guest image");
        } else {
            fetch_default_image(l)?;
            image::harden_store(&l.images_dir(), opts.fakeroot)?;
        }
    }

    // 4. Render config + units + tmpfiles.
    let vars = RenderVars { ne_uid };
    write_file(l.env_file(), &render::render_env(&vars), opts.dry_run)?;
    write_file(
        l.supervisor_unit(),
        &render::render_supervisor_unit(),
        opts.dry_run,
    )?;
    write_file(l.api_unit(), &render::render_api_unit(), opts.dry_run)?;
    write_file(l.tmpfiles_conf(), &render::render_tmpfiles(), opts.dry_run)?;

    // 4b. Default PII policy — installed only when absent so operator
    //     edits survive a re-install. The supervisor references this via
    //     NE_PRIVACY_ROUTER_POLICY in the env file; without it the
    //     per-workspace privacy router is never spawned even for opt-in
    //     workspaces (both binary + policy must be set).
    let policy = l.privacy_policy_file();
    if opts.dry_run {
        tracing::info!(
            "[dry-run] install default PII policy -> {}",
            policy.display()
        );
    } else if !policy.exists() {
        write_file(policy, &render::render_privacy_policy(), false)?;
    }

    // 5. Activate (real installs only).
    if !opts.fakeroot && !opts.dry_run && !opts.no_start {
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", "ne-supervisor.service", "ne-api.service"])?;
    }

    print_next_steps(&opts);
    Ok(())
}

/// Reverse an install. Stops/disables the two units (unless fakeroot),
/// removes rendered unit files + env + tmpfiles, and optionally purges state.
pub fn uninstall(layout: &Layout, purge: bool, fakeroot: bool) -> Result<()> {
    if !fakeroot {
        // Best-effort: units may not be installed yet.
        let _ = systemctl(&[
            "disable",
            "--now",
            "ne-supervisor.service",
            "ne-api.service",
        ]);
    }

    for path in [
        layout.supervisor_unit(),
        layout.api_unit(),
        layout.env_file(),
        layout.tmpfiles_conf(),
        layout.privacy_policy_file(),
    ] {
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
    }

    if purge && layout.state_dir().exists() {
        fs::remove_dir_all(layout.state_dir())
            .with_context(|| format!("purging {}", layout.state_dir().display()))?;
    }

    Ok(())
}

/// Preflight wrapper for `nee doctor`.
pub fn doctor(l: &Layout) -> preflight::Report {
    // /dev/kvm is always the real host device, even under `--prefix`: the
    // prefix redirects install paths, not the kernel's KVM character device.
    preflight::run_report(&l.bin_dir(), std::path::Path::new("/dev/kvm"))
}

fn write_file(path: std::path::PathBuf, body: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        tracing::info!("[dry-run] write {}", path.display());
        return Ok(());
    }
    // Most parents are created by the step-1 dir loop in `install()`, but
    // `/etc/tmpfiles.d` is not — create the parent and surface the real error.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::write(&path, body).with_context(|| format!("writing {}", path.display()))
}

fn fetch_default_image(l: &Layout) -> Result<()> {
    let pin = &image::DEFAULT_IMAGE;
    anyhow::ensure!(
        !pin.kernel_sha256.starts_with("PLACEHOLDER"),
        "no default image is pinned in this build; use `nee image import` or `--no-image`"
    );
    let tmp = tempfile::tempdir().context("temp dir for image download")?;
    let k = tmp.path().join("vmlinux");
    let r = tmp.path().join("rootfs.img");
    image::curl_download(&format!("{}/vmlinux", pin.url_base), &k)?;
    image::curl_download(&format!("{}/rootfs.img", pin.url_base), &r)?;
    image::import_artifact(&l.images_dir(), "kernels", "vmlinux", &k, pin.kernel_sha256)?;
    image::import_artifact(
        &l.images_dir(),
        "rootfs",
        "rootfs.img",
        &r,
        pin.rootfs_sha256,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_service_user(name: &str) -> Result<()> {
    // Idempotent: getent succeeds → already exists.
    let exists = std::process::Command::new("getent")
        .args(["passwd", name])
        .status()
        .is_ok_and(|s| s.success());
    if exists {
        return Ok(());
    }
    let status = std::process::Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            name,
        ])
        .status()
        .context("running useradd")?;
    anyhow::ensure!(status.success(), "useradd {name} failed ({status})");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_service_user(_name: &str) -> Result<()> {
    anyhow::bail!("user creation is only supported on Linux")
}

/// Resolve the uid of a user that was just created (or already existed).
/// Falls back to 0 on non-Linux or lookup failure (root — will be corrected
/// by the chown step in Task 12).
#[cfg(target_os = "linux")]
fn resolve_uid_after_creation(name: &str) -> u32 {
    nix::unistd::User::from_name(name)
        .ok()
        .flatten()
        .map_or(0, |u| u.uid.as_raw())
}

#[cfg(not(target_os = "linux"))]
fn resolve_uid_after_creation(_name: &str) -> u32 {
    0
}

/// Apply the owner + mode from [`dir_ownership`] to each managed
/// directory that exists under the layout root. Real installs only
/// (requires root); never called on the fakeroot path.
#[cfg(target_os = "linux")]
fn apply_ownership(l: &Layout) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for (abs, (user, group), mode) in dir_ownership() {
        let path = l.root().join(abs.trim_start_matches('/'));
        if !path.exists() {
            continue;
        }
        let uid = nix::unistd::User::from_name(user)
            .with_context(|| format!("looking up user {user}"))?
            .map(|u| u.uid);
        let gid = nix::unistd::Group::from_name(group)
            .with_context(|| format!("looking up group {group}"))?
            .map(|g| g.gid);
        nix::unistd::chown(&path, uid, gid)
            .with_context(|| format!("chown {} {user}:{group}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {} {mode:o}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn apply_ownership(_l: &Layout) -> Result<()> {
    Ok(())
}

fn systemctl(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("systemctl")
        .args(args)
        .status()
        .context("running systemctl")?;
    anyhow::ensure!(status.success(), "systemctl {args:?} failed ({status})");
    Ok(())
}

fn print_next_steps(opts: &InstallOptions) {
    if opts.fakeroot || opts.dry_run {
        return;
    }
    tracing::info!(
        "NeuronEdge Enclave installed. API is dev-mode on 127.0.0.1:50051 (gRPC) / :8080 (REST). \
         Production external auth is NOT yet available; do not expose these ports."
    );
}

/// Desired owner + mode for each managed directory. `owner` is
/// ("user","group"); resolved to uids at apply time.
pub fn dir_ownership() -> Vec<(&'static str, (&'static str, &'static str), u32)> {
    vec![
        ("/var/lib/ne-enclave", ("root", "ne"), 0o750),
        ("/var/lib/ne-enclave/images", ("root", "root"), 0o755),
        ("/var/lib/ne-enclave/workspaces", ("ne", "ne"), 0o750),
        ("/var/lib/ne-enclave/snapshots", ("ne", "ne"), 0o750),
        ("/srv/jailer", ("root", "root"), 0o700),
        ("/etc/ne-enclave", ("root", "ne"), 0o750),
        ("/run/ne-enclave", ("root", "ne"), 0o750),
    ]
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    #[test]
    fn jailer_base_is_root_only() {
        let t = dir_ownership();
        let j = t.iter().find(|(p, _, _)| *p == "/srv/jailer").unwrap();
        assert_eq!(j.1, ("root", "root"));
        assert_eq!(j.2, 0o700);
    }

    #[test]
    fn etc_is_group_ne_readable() {
        let t = dir_ownership();
        let e = t.iter().find(|(p, _, _)| *p == "/etc/ne-enclave").unwrap();
        assert_eq!(e.1, ("root", "ne"));
    }

    #[test]
    fn image_store_is_root_owned_and_not_service_writable() {
        let t = dir_ownership();
        let state = t
            .iter()
            .find(|(p, _, _)| *p == "/var/lib/ne-enclave")
            .unwrap();
        let images = t
            .iter()
            .find(|(p, _, _)| *p == "/var/lib/ne-enclave/images")
            .unwrap();
        assert_eq!(state.1, ("root", "ne"));
        assert_eq!(images.1, ("root", "root"));
        assert_eq!(
            images.2 & 0o022,
            0,
            "API identity must not write image store"
        );
    }
}

#[cfg(test)]
mod uninstall_tests {
    use super::*;

    #[test]
    fn purge_removes_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = Layout::new(tmp.path());
        // Create state dir + some nested content.
        let state = layout.state_dir();
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("audit.log"), b"data").unwrap();
        // Create unit files so uninstall has something to remove.
        fs::create_dir_all(layout.systemd_dir()).unwrap();
        fs::create_dir_all(layout.etc_dir()).unwrap();
        fs::create_dir_all(
            layout
                .tmpfiles_conf()
                .parent()
                .expect("tmpfiles_conf has parent"),
        )
        .unwrap();

        uninstall(&layout, true, true).unwrap();

        assert!(!state.exists(), "state_dir should be removed after --purge");
    }

    #[test]
    fn non_purge_leaves_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = Layout::new(tmp.path());
        let state = layout.state_dir();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(layout.systemd_dir()).unwrap();
        fs::create_dir_all(layout.etc_dir()).unwrap();
        fs::create_dir_all(
            layout
                .tmpfiles_conf()
                .parent()
                .expect("tmpfiles_conf has parent"),
        )
        .unwrap();

        uninstall(&layout, false, true).unwrap();

        assert!(state.exists(), "state_dir should remain when purge=false");
    }
}
