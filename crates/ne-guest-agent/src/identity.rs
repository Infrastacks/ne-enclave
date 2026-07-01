// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::redundant_pub_crate)]
//! Fork identity reset, applied inside the guest on a host
//! `ResetIdentity` request. The rootfs is read-only: hostname is a
//! runtime syscall, `/etc/machine-id` is a symlink to writable
//! `/run/machine-id`, and entropy is mixed into `/dev/urandom`.

use std::io::Write;
use std::path::Path;

use ne_protocol::guest::{GuestErrorKind, GuestResponse, ResetIdentityRequest};

/// Real machine-id path inside the guest (symlink → `/run/machine-id`).
const MACHINE_ID_PATH: &str = "/etc/machine-id";
/// Kernel RNG device the entropy seed is written to.
const URANDOM_PATH: &str = "/dev/urandom";
/// Minimum accepted entropy seed length (the supervisor sends 32 bytes).
const MIN_ENTROPY_SEED_LEN: usize = 32;

// `RNDRESEEDCRNG` (`_IO('R', 0x07)`, linux/random.h): force the kernel CRNG to
// reseed from the input pool. No argument. Defined via nix's ioctl macro.
nix::ioctl_none!(rnd_reseed_crng, b'R', 0x07);

/// Apply a fork identity reset. Returns the guest response to relay.
pub(crate) fn reset_identity(req: &ResetIdentityRequest) -> GuestResponse {
    if let Err(msg) = validate_machine_id(&req.machine_id) {
        return GuestResponse::Error {
            kind: GuestErrorKind::InvalidRequest,
            message: msg,
        };
    }
    if let Err(msg) = validate_hostname(&req.hostname) {
        return GuestResponse::Error {
            kind: GuestErrorKind::InvalidRequest,
            message: msg,
        };
    }
    // S3-F4: reject a missing/short entropy seed before any side effect — a
    // zero-length seed would make `mix_entropy` a no-op yet still report a
    // successful reset, leaving the fork's RNG un-diverged.
    if req.entropy_seed.len() < MIN_ENTROPY_SEED_LEN {
        return GuestResponse::Error {
            kind: GuestErrorKind::InvalidRequest,
            message: format!(
                "entropy_seed must be >= {MIN_ENTROPY_SEED_LEN} bytes, got {}",
                req.entropy_seed.len()
            ),
        };
    }
    if let Err(e) = apply_hostname(&req.hostname) {
        return GuestResponse::Error {
            kind: GuestErrorKind::IoError,
            message: format!("sethostname: {e}"),
        };
    }
    if let Err(e) = write_text(Path::new(MACHINE_ID_PATH), &format!("{}\n", req.machine_id)) {
        return GuestResponse::Error {
            kind: GuestErrorKind::IoError,
            message: format!("write machine-id: {e}"),
        };
    }
    if let Err(e) = mix_entropy(Path::new(URANDOM_PATH), &req.entropy_seed) {
        return GuestResponse::Error {
            kind: GuestErrorKind::IoError,
            message: format!("mix entropy: {e}"),
        };
    }
    GuestResponse::IdentityReset {
        hostname: req.hostname.clone(),
        machine_id: req.machine_id.clone(),
    }
}

/// machine-id must be exactly 32 lowercase hex chars (systemd convention).
fn validate_machine_id(id: &str) -> Result<(), String> {
    if id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(format!(
            "machine_id must be 32 lowercase hex chars, got {id:?}"
        ))
    }
}

/// Hostname: non-empty, <= 64 bytes, label chars only (`[a-zA-Z0-9-]`).
fn validate_hostname(h: &str) -> Result<(), String> {
    if !h.is_empty() && h.len() <= 64 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        Ok(())
    } else {
        Err(format!(
            "hostname must be 1..=64 of [a-zA-Z0-9-], got {h:?}"
        ))
    }
}

/// Set the kernel hostname (runtime; never touches the RO `/etc/hostname`).
fn apply_hostname(hostname: &str) -> std::io::Result<()> {
    nix::unistd::sethostname(hostname).map_err(std::io::Error::from)
}

/// Write `content` to `path` (machine-id is tiny; a single truncating
/// write is fine — the consumer reads it once at fork time).
fn write_text(path: &Path, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content.as_bytes())
}

/// Mix `seed` into the kernel RNG and force an immediate CRNG reseed so the
/// forked clone's randomness diverges from its source *now*.
///
/// S3-F1: on kernels >= 5.18 a plain write to `/dev/urandom` only folds bytes
/// into the input pool — it does NOT reseed the per-CPU `ChaCha` CRNG. After a
/// snapshot restore the CRNG state is identical across forks, so without an
/// explicit reseed two sibling forks would return identical `getrandom()` /
/// `/dev/urandom` output until the periodic (~minute) reseed. We therefore
/// issue `RNDRESEEDCRNG` after the write to reseed from the freshly-mixed pool.
/// Best-effort: if the ioctl is unavailable/refused the write above still
/// applied, so behavior never regresses below the prior write-only path.
fn mix_entropy(path: &Path, seed: &[u8]) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.write_all(seed)?;
    f.flush()?;
    if let Err(e) = force_crng_reseed(f.as_raw_fd()) {
        tracing::debug!(error = %e, "RNDRESEEDCRNG failed; CRNG will reseed on its periodic interval");
    }
    Ok(())
}

/// Issue the `RNDRESEEDCRNG` ioctl on an open `/dev/urandom` fd.
#[allow(unsafe_code)]
fn force_crng_reseed(fd: std::os::unix::io::RawFd) -> nix::Result<()> {
    // SAFETY: `fd` is a valid, open, writable fd for /dev/urandom owned by the
    // caller's `File`, which outlives this call. RNDRESEEDCRNG takes no
    // argument and only triggers a kernel CRNG reseed from the input pool — it
    // reads/writes no user memory, so it cannot cause memory unsafety. The
    // agent runs as root (CAP_SYS_ADMIN), so the call is permitted; any error
    // (e.g. an older kernel without the ioctl) is propagated and handled by
    // the best-effort caller.
    unsafe { rnd_reseed_crng(fd) }?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_machine_id_accepts_32_lower_hex() {
        assert!(validate_machine_id("0123456789abcdef0123456789abcdef").is_ok());
        assert!(
            validate_machine_id("0123456789ABCDEF0123456789abcdef").is_err(),
            "uppercase"
        );
        assert!(validate_machine_id("tooshort").is_err());
        assert!(
            validate_machine_id("0123456789abcdef0123456789abcdeg").is_err(),
            "non-hex"
        );
    }

    #[test]
    fn validate_hostname_rules() {
        assert!(validate_hostname("fork-a").is_ok());
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("bad_host").is_err(), "underscore");
        assert!(validate_hostname(&"a".repeat(65)).is_err(), "too long");
    }

    #[test]
    fn write_text_then_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("machine-id");
        write_text(&p, "0123456789abcdef0123456789abcdef\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "0123456789abcdef0123456789abcdef\n"
        );
    }

    #[test]
    fn mix_entropy_writes_all_bytes_to_a_regular_file() {
        // Regular file stands in for /dev/urandom (write semantics identical).
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("urandom");
        std::fs::write(&p, b"").unwrap();
        mix_entropy(&p, &[7u8; 32]).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), vec![7u8; 32]);
    }

    #[test]
    fn reset_identity_rejects_bad_machine_id_before_any_side_effect() {
        let resp = reset_identity(&ResetIdentityRequest {
            hostname: "fork-a".into(),
            machine_id: "nope".into(),
            entropy_seed: vec![1, 2, 3],
        });
        match resp {
            GuestResponse::Error {
                kind: GuestErrorKind::InvalidRequest,
                ..
            } => {}
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }
}
