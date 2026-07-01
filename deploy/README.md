# NeuronEdge Enclave Self-Host Install Guide

Operator guide for running the NeuronEdge Enclave runtime on a single bare-metal or VM host.
Validated on Ubuntu 24.04 / x86_64 with KVM.

---

## Requirements

| Requirement | Detail |
|---|---|
| OS | Ubuntu 24.04 (x86_64) |
| KVM | `/dev/kvm` present and accessible |
| Firecracker + jailer | Operator-installed at `/opt/ne-enclave/bin/{firecracker,jailer}` |
| Privileges | Root for install; the runtime itself drops to `nee` where possible |

NeuronEdge Enclave does not bundle Firecracker or jailer. Install them from the
[Firecracker releases page](https://github.com/firecracker-microvm/firecracker/releases)
and place both binaries at `/opt/ne-enclave/bin/` before running `nee install`.

---

## Security posture (read before installing)

> **WARNING:** Production external authentication (mTLS / JWT / API key) is
> **not yet implemented**. The API binds to **localhost only**
> (`127.0.0.1:50051` gRPC, `127.0.0.1:8080` REST) and runs in dev-mode.
> **Do NOT expose these ports to untrusted networks.** The supervisor IPC
> boundary (Unix-socket peer-credential auth) is enforced.
>
> Production auth (mTLS, API-key rotation) ships in a later phase.

---

## Quick install

```sh
curl -fsSL https://github.com/Infrastacks/ne-enclave/releases/latest/download/install.sh | sh
```

The thin `install.sh` (in this directory) does three things:

1. Downloads the static-musl `nee` binary from the GitHub release.
2. Verifies the SHA-256 checksum against the published `SHA256SUMS` file.
3. Drops the binary to `/opt/ne-enclave/bin/nee` and execs `sudo nee install`.

Cosign signature verification is a documented future step (see the commented
block in `deploy/install.sh`).

To pin a specific release:

```sh
NE_VERSION=v0.3.0 curl -fsSL \
  https://github.com/Infrastacks/ne-enclave/releases/latest/download/install.sh | sh
```

---

## What `nee install` does

`nee install` is **idempotent** — safe to re-run on an already-provisioned
host (re-renders config; does not restart running services unless asked).

Steps in order:

1. **Preflight** — runs `nee doctor` (checks `/dev/kvm`, `firecracker`,
   `jailer` at expected paths, kernel module state).
2. **System user/group** — creates the `nee` system user + group if absent.
3. **Directory layout** — creates all directories listed in the
   [Filesystem layout](#filesystem-layout) section below.
4. **Guest image** — fetches and SHA-256-verifies the default guest image
   into the content-addressed store. Skip with `--no-image` for air-gapped
   installs (see [Air-gapped / custom images](#air-gapped--custom-images)).
5. **Config rendering** — writes `/etc/ne-enclave/ne-enclave.env` (EnvironmentFile
   sourced by both units) with paths resolved to the installed layout.
6. **systemd units** — renders `ne-supervisor.service` and
   `ne-api.service` into `/etc/systemd/system/` plus a tmpfiles entry
   into `/etc/tmpfiles.d/ne-enclave.conf`.
7. **Enable + start** — runs `systemctl daemon-reload &&
   systemctl enable --now ne-supervisor.service ne-api.service`
   (suppressed by `--no-start`).

### `nee install` flags

| Flag | Effect |
|---|---|
| `--no-start` | Render config + units but do not enable/start |
| `--no-image` | Skip guest image fetch (air-gapped; import manually) |
| `--prefix <dir>` | Install under `<dir>` instead of `/` (fakeroot / CI testing) |
| `--dry-run` | Print every action without executing |

---

## The single binary

One fused static binary at `/opt/ne-enclave/bin/nee`. Subcommands:

| Subcommand | Description |
|---|---|
| `serve-supervisor` | Privileged workspace lifecycle manager (spawns Firecracker via jailer) |
| `serve-api` | Unprivileged gRPC + REST API server |
| `dns-filter` | Per-workspace DNS filter (spawned by supervisor) |
| `privacy-router` | Per-workspace egress proxy (spawned by supervisor) |
| `install` | Host provisioner (described above) |
| `uninstall` | Remove units, config, user; optionally state |
| `doctor` | Preflight checks: KVM, Firecracker, jailer |
| `image import` | Import a kernel + rootfs from local paths |
| `image pull` | Fetch a named image from the NeuronEdge Enclave image registry |

---

## Filesystem layout

```
/opt/ne-enclave/bin/nee                     # fused binary (this package)
/opt/ne-enclave/bin/firecracker               # operator-provided
/opt/ne-enclave/bin/jailer                    # operator-provided
/etc/ne-enclave/ne-enclave.env                     # EnvironmentFile (both units)
/var/lib/ne-enclave/images/
    kernels/<sha256>/vmlinux               # content-addressed guest kernels
    rootfs/<sha256>/rootfs.img             # content-addressed guest rootfs
/var/lib/ne-enclave/workspaces/               # live workspace state  (ne:ne 0750)
/var/lib/ne-enclave/snapshots/                # snapshot state        (ne:ne 0750)
/run/ne-enclave/supervisor.sock               # IPC socket            (root:ne 0660)
/srv/jailer/                               # jailer chroot base
/etc/systemd/system/ne-supervisor.service
/etc/systemd/system/ne-api.service
/etc/tmpfiles.d/ne-enclave.conf
```

---

## The two systemd units

### `ne-supervisor.service`

Privileged service that owns the Firecracker jailer and workspace lifecycle.

- `User=root`, `Group=ne`, `Type=notify`
- IPC peer-credential auth: the supervisor verifies the connecting peer's UID
  via `SO_PEERCRED` (controlled by `NE_SUPERVISOR_PEER_UID` in the env
  file).
- Capability bounding set (the bounding set caps uid-0, so each required
  capability must be listed explicitly):

  ```
  CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_KILL, CAP_MKNOD,
  CAP_NET_ADMIN, CAP_SETGID, CAP_SETUID, CAP_SYS_ADMIN, CAP_SYS_CHROOT
  ```

  - `CAP_KILL` — terminate the jailed Firecracker process (runs as a
    different uid inside the jailer chroot).
  - `CAP_MKNOD` + `CAP_SYS_CHROOT` — jailer chroot setup.
  - `CAP_NET_ADMIN` — TAP device creation for the workspace network
    namespace.

### `ne-api.service`

Unprivileged service that exposes the gRPC and REST API.

- `User=ne`, `Group=ne`
- Aggressively sandboxed: `NoNewPrivileges=true`,
  `CapabilityBoundingSet=` (empty), `MemoryDenyWriteExecute=true`,
  `ProtectSystem=strict`
- Binds `127.0.0.1:50051` (gRPC) and `127.0.0.1:8080` (REST).
- Communicates with the supervisor via the Unix socket
  `/run/ne-enclave/supervisor.sock` (group `ne`, mode `0660`).

---

## Two execution tiers (standard + confidential)

NeuronEdge Enclave ships a **two-tier** runtime (ARCH §6.1). The install above
covers the **standard tier** (Firecracker microVM isolation — the default). The
**confidential tier** (single-CVM-direct, B) runs the agent + OpenShell directly
inside an operator-provisioned SEV-SNP CVM, with key release gated on
hardware-rooted attestation evidence. The two tiers share the same `nee` binary
and API; the profile is selected at runtime.

### Activating the confidential tier (B)

The confidential tier is an opt-in profile, **not** a separate install. On a
host that is itself a SEV-SNP confidential VM (e.g. Azure DCasv5):

1. **Install the `openshell-sandbox` binary** alongside Firecracker/jailer.
   Build it from the [Infrastacks OpenShell fork](https://github.com/Infrastacks/OpenShell)
   (`cargo build -p openshell-sandbox --release`) and place it at
   `/opt/ne-enclave/bin/openshell-sandbox`. (The standard tier does not need it.)
2. **Provision the CVM** with a `sandbox` user/group (OpenShell's privilege-drop
   target): `sudo useradd -r -m sandbox`.
3. **Enable confidential mode** in the env file (`/etc/ne-enclave/ne-enclave.env`):
   ```
   NE_CONFIDENTIAL_MODE=1
   NE_OPENSHELL_SANDBOX_BIN=/opt/ne-enclave/bin/openshell-sandbox
   ```
   The supervisor detects the CVM via `/dev/sev-guest` (GCP/bare-metal) OR
   `/dev/tpmrm0` (Azure OpenHCL paravisor) and refuses to start if neither is
   present (fail-closed — a confidential deployment never silently falls back).
4. `sudo systemctl restart ne-supervisor.service`.

On the confidential tier, `CreateWorkspace` spawns an OpenShell sandbox in the
CVM (not a Firecracker microVM) and governs it via the L7 OPA proxy. The
attestation evidence + sealed-snapshot key release reuse the verified Wedge-5 path
(verified end-to-end on Azure DCasv5, 2026-06-30: the boot-fixed AMD report bound to
a TPM-Quote nonce, validated against the genuine AMD Milan ARK).

> **B v1 scope:** the confidential tier supports create / run-command /
> write-file / read-file / terminate + attestation. Snapshot / restore / fork
> return `Unsupported` for the OpenShell arm in v1 (Firecracker-vmstate-coupled;
> a process-checkpoint format is a later wedge).

---

## Air-gapped / custom images

```sh
# 1. Install without fetching the default image
sudo nee install --no-image

# 2. Import your own kernel + rootfs (SHA-256 values are verified on import)
nee image import \
  --kernel   /path/to/vmlinux       --kernel-sha256  <hex> \
  --rootfs   /path/to/rootfs.img    --rootfs-sha256  <hex>
```

When creating workspaces, specify the image paths explicitly in the
`CreateWorkspace` request (`kernel_image_path` / `rootfs_image_path` fields).
The paths recorded in `ne-enclave.env` are informational defaults.

---

## Verifying the install

`deploy/smoke-install.sh` drives a full end-to-end roundtrip through the
installed API:

```sh
sudo deploy/smoke-install.sh /path/to/nee /path/to/vmlinux /path/to/rootfs.img
```

The script: installs the local binary, imports the image, starts the units,
then runs **create → exec → write → read → destroy** against the REST API at
`http://127.0.0.1:8080/v1`. Exits `0` and prints `SMOKE OK` on success.

The script stages Firecracker + jailer into `/opt/ne-enclave/bin/` (where the
installed runtime expects them) from `NE_E2E_FIRECRACKER`/`NE_E2E_JAILER`, then
`/usr/local/bin`, then `PATH`, and errors with guidance if neither is found. An
operator-provided binary already under `/opt/ne-enclave/bin/` is left as-is.

> **Note:** File paths in `WriteFile` / `ReadFile` requests are **relative**
> to the `/workspace` jail root (e.g., `"path": "proof.txt"` lands at
> `/workspace/proof.txt`). The guest agent rejects absolute paths.

---

## Checking service status

```sh
systemctl --no-pager status ne-supervisor.service ne-api.service
journalctl -u ne-supervisor.service -u ne-api.service -f
nee doctor
```

---

## Uninstall

```sh
# Remove units + config + ne user; preserve /var/lib/ne-enclave state
sudo nee uninstall

# Full removal including workspace + image state
sudo nee uninstall --purge
```

---

## KVM dev host

Firecracker needs `/dev/kvm`, which macOS and most non-nested virtualization
guests cannot provide. Provision any KVM-capable Ubuntu 24.04 / x86_64 host
(bare metal, a VM with nested virtualization, or a cloud VM such as Azure
Dv4+/Ev4+). Install Firecracker v1.16.0 + jailer to `/opt/ne-enclave/bin/`
(see the Requirements section above), then run the same `install.sh` / `nee`
flow.
