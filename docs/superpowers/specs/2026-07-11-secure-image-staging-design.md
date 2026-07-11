# Secure Image Staging Design

**Status:** Approved  
**Date:** 2026-07-11  
**Scope:** Replace caller-controlled host image paths with content-addressed image digests and eliminate hard-linked workspace artifacts.

## Problem

`CreateWorkspace` currently accepts absolute host paths for the kernel and rootfs. The privileged supervisor passes those paths into the Firecracker launcher, which prefers a hard link into the workspace chroot and then changes ownership on the staged name. When source and destination share a mount, the staged name aliases the source inode: changing ownership affects the source, and a writable rootfs can mutate the canonical image or share writes across workspaces.

The security boundary must not depend on systemd mount topology, cross-filesystem behavior, SDK defaults, or the caller remembering to request a read-only rootfs.

## Goals

- Remove arbitrary host paths from every public workspace-create contract.
- Resolve cold-boot images only from the supervisor-owned content-addressed image store.
- Verify image identity from canonical lowercase SHA-256 digests before allocating network or VM resources.
- Stage every kernel and rootfs as a fresh inode owned by the jailer identity.
- Preserve writable rootfs support without cross-workspace or source-image aliasing.
- Store image digests, never host paths, in signed snapshot manifests.
- Apply the breaking contract consistently across Rust, protobuf, REST, Python, TypeScript, LangChain, Mastra, examples, tests, and documentation.

## Non-goals

- Named image manifests, aliases, registries, image garbage collection, or remote image pulls.
- Backward compatibility for `kernel_image_path` or `rootfs_image_path`.
- Migrating snapshot manifests created before schema version 5.
- Optimizing large-image verification with caches, reflinks, sparse copies, or copy-on-write storage.
- Changing confidential-CVM or warm-pool execution semantics beyond removing path-shaped inputs.
- Fixing the other audit findings in the same change.

## Public Contract

### Workspace creation

The protobuf and transport-neutral request fields become:

```text
string kernel_sha256 = 2;
string rootfs_sha256 = 3;
bool rootfs_read_only = 4;
```

Field numbers 2 and 3 are intentionally reused for the breaking pre-1.0 schema. The removed path names must not remain as aliases in protobuf, REST, supervisor IPC, SDKs, generated bindings, or examples.

For a standard cold boot (`tier` absent under the Firecracker profile), both digests are required and must each be exactly 64 lowercase ASCII hexadecimal characters. Uppercase values are rejected rather than normalized so one canonical identifier exists throughout logs, manifests, and APIs.

Warm-pool creates and confidential-CVM creates obtain their execution artifacts from the configured tier or backend. They may send empty digest strings; if either digest is non-empty, both must be non-empty and syntactically valid. The values are not used to override the tier or confidential backend.

### Image-store configuration

`SupervisorConfig` gains `image_store: PathBuf`. The `nee serve-supervisor` CLI exposes `--image-store`, backed by `NE_IMAGE_STORE`, with production default:

```text
/var/lib/ne-enclave/images
```

The installed environment template explicitly sets the same value.

Given digest `D`, the only valid source paths are:

```text
<image_store>/kernels/D/vmlinux
<image_store>/rootfs/D/rootfs.img
```

Callers never provide a store-relative path, filename, directory name, or artifact kind.

### SDKs

- Python: `kernel_sha256` and `rootfs_sha256` replace the two path parameters.
- TypeScript: `kernelSha256` and `rootfsSha256` replace the two path options.
- LangChain and Mastra adapters expose the same digest names and use `NE_KERNEL_SHA256` / `NE_ROOTFS_SHA256` for environment configuration.
- Cold-create helper APIs require the digest pair. Tier-backed helpers may omit both.

## Resolver and Data Flow

A focused supervisor image module owns digest parsing, store resolution, verification, and staging. Neither the API daemon nor Firecracker launcher joins caller-controlled strings into host paths.

For a standard cold create:

1. Parse both digest strings into a validated digest type.
2. Canonicalize the configured image-store root.
3. Construct the fixed kernel and rootfs paths from the validated digests.
4. Reject a symlink endpoint or non-regular file using symlink metadata.
5. Canonicalize each artifact and require it to remain beneath the canonical store root.
6. Open each source with `O_NOFOLLOW` and retain the opened handle.
7. Hash the bytes read from that handle and compare them with the requested digest.
8. Rewind the verified handle and retain it in a `VerifiedImageFile` value.
9. Only after both sources verify may workspace network allocation and chroot setup begin.
10. Copy each retained source handle into a destination opened with `create_new`.
11. Apply jailer ownership and final permissions to the new destination inode.
12. Launch Firecracker using only the new chroot-local copies.

The verified handle pins the source inode between digest verification and copying. The managed store remains operator-owned and non-writable by API clients; a hostile root operator remains outside this control's threat boundary.

## Staging Invariants

- Hard links are forbidden for both kernel and rootfs.
- A destination that already exists is an error; staging never unlinks and replaces an unexpected file.
- Kernel mode is exactly `0400` after staging.
- A read-only rootfs mode is exactly `0400` after staging.
- A writable rootfs mode is exactly `0600` after staging.
- Kernel and rootfs destination inodes must differ from their respective source inodes.
- Each workspace receives a distinct rootfs inode, including when multiple workspaces use the same digest.
- Any copy, hash, ownership, or permission failure removes artifacts created by that staging attempt.
- Launch does not begin with a partial or unverified image pair.

## Snapshot Schema and Restore

Snapshot manifest version increases from 4 to 5. Version 5:

- removes `kernel_path`;
- removes `rootfs_path`;
- adds `kernel_sha256`;
- retains `rootfs_sha256` as the content identity;
- signs both image digests in the canonical manifest bytes.

`Instance` and snapshot capture metadata carry the digest pair. Snapshot creation does not reintroduce paths into the manifest.

Restore and fork first verify the manifest signature and snapshot artifact hashes, then resolve and verify the manifest's image digests through the same image resolver used for cold create. They do not open any image path supplied by the manifest. Version 4 and older manifests fail with `UnsupportedVersion`; there is no migration path in this pre-1.0 break.

The configuration measurement used by software attestation replaces `kernel_path` and `rootfs_path` with `kernel_sha256` and `rootfs_sha256`.

## Error Contract

`SupervisorErrorKind` gains stable variants with these transport mappings:

| Error kind | Condition | REST | gRPC |
|---|---|---:|---|
| `InvalidImageDigest` | Missing, uppercase, wrong-length, or non-hex digest for a cold create | 400 | `INVALID_ARGUMENT` |
| `ImageNotFound` | Expected managed artifact is absent | 404 | `NOT_FOUND` |
| `ImageRejected` | Symlink, non-regular file, or canonical path outside the store | 409 | `FAILED_PRECONDITION` |
| `ImageDigestMismatch` | Artifact bytes do not match the requested digest | 409 | `FAILED_PRECONDITION` |
| `ImageStageFailed` | Open, copy, ownership, permission, rewind, or cleanup failure | 500 | `INTERNAL` |

Error messages identify the artifact kind and digest but never disclose arbitrary host paths outside the configured image store.

All image resolution errors occur before network setup. Staging failures use the existing launch cleanup path and must not leave a child process, chroot artifact, or registry entry.

## Testing Strategy

### Portable unit tests

- Accept exactly 64 lowercase hexadecimal characters.
- Reject empty cold-create digests, uppercase text, wrong length, and non-hex text.
- Resolve the exact kernel and rootfs store layouts.
- Reject missing files, symlink endpoints, directories, and canonical escapes.
- Reject bytes whose SHA-256 differs from the requested digest.
- Preserve source owner, mode, content, and inode metadata.
- Produce destination inodes distinct from the source and from another workspace's copy.
- Prove writes to one writable rootfs copy do not affect the store or a second copy.
- Remove partial destinations after injected copy or permission failure.
- Pin serialization and stable error-code mappings.

### Contract tests

- Protobuf, supervisor NDJSON, gRPC, and REST round-trip the digest pair and contain no path fields.
- Python and TypeScript clients send the new fields and preserve their existing read-only defaults.
- LangChain and Mastra adapters read the new environment variable names and send digests.
- Generated protobuf sources are regenerated and checked into the same change.

### Snapshot tests

- Version 5 manifests sign and verify the digest pair.
- Pre-version-5 manifests are rejected.
- Restore/fork reject missing or mutated managed images before Firecracker launch.
- Attestation configuration measurements change when either image digest changes.

### Linux integration tests

- A complete cold create uses managed images and independent staged inodes.
- Two writable workspaces created from one rootfs digest cannot observe each other's disk writes.
- Arbitrary paths cannot enter the create protocol or supervisor request.

The normal verification gate is `cargo test --workspace --all-targets`, followed by the existing TypeScript, Python, LangChain, and Mastra package tests. KVM-dependent tests remain separately gated where hardware is required.

## Documentation and Release Treatment

README quickstarts, deployment documentation, SDK guides, examples, and threat-model image-integrity claims must use digests. Release notes must call out the breaking request and snapshot-manifest changes.

The threat model may claim managed-image enforcement only after the public create path, cold launch, snapshot restore, and SDK contract tests pass. This change does not claim artifact signing, SBOM provenance, remote registry trust, or protection from a hostile host root.
