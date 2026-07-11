# Secure Image Staging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace caller-controlled kernel/rootfs host paths with verified SHA-256 image identities and stage independent workspace inodes across create, snapshot/restore, SDKs, and documentation.

**Architecture:** A new `ne-supervisor::image` module validates canonical lowercase digests, resolves fixed files beneath the configured image store, opens them without following symlinks, verifies their bytes, and copies retained handles into fresh chroot files. Public requests and snapshot manifests carry only digests; restore uses the same resolver and never trusts a stored path.

**Tech Stack:** Rust 1.95, Tokio, SHA-256 (`sha2`), Unix `O_NOFOLLOW`/metadata, serde, protobuf/tonic, Python gRPC SDK, TypeScript gRPC SDK, Vitest, pytest.

## Global Constraints

- This is a breaking pre-1.0 change: remove `kernel_image_path` and `rootfs_image_path`; do not retain compatibility aliases.
- Cold Firecracker creates require exactly 64 lowercase ASCII hexadecimal characters for both `kernel_sha256` and `rootfs_sha256`.
- Warm-pool/confidential creates may omit both digests; if either is present, both must be canonical digests.
- The only source layouts are `<image_store>/kernels/<digest>/vmlinux` and `<image_store>/rootfs/<digest>/rootfs.img`.
- Never hard-link kernel or rootfs artifacts. Every staged file is a fresh inode opened with `create_new`.
- Final modes are exactly `0400` for kernel/read-only rootfs and `0600` for writable rootfs.
- Resolve and verify both source images before network allocation, chroot creation, or process spawn.
- Snapshot manifest version is exactly `5`; versions `0..=4` are rejected without migration.
- Do not add named manifests, aliases, registries, caches, reflinks, sparse-copy logic, or fixes for unrelated audit findings.
- Preserve user work and keep all changes on `codex/secure-image-staging` in the linked worktree.

---

### Task 1: Verified image resolver and independent staging primitive

**Files:**
- Create: `crates/ne-supervisor/src/image.rs`
- Modify: `crates/ne-supervisor/src/lib.rs`
- Modify: `crates/ne-supervisor/Cargo.toml`

**Interfaces:**
- Consumes: a configured `PathBuf` image-store root, a caller digest string, and jailer uid/gid.
- Produces: `ImageDigest`, `ImageStore`, `VerifiedImageFile`, `VerifiedImagePair`, `ImageError`, `ImageKind`, and `stage_verified_pair` used by Task 2.

- [ ] **Step 1: Add failing digest and resolver tests**

Add a `#[cfg(test)] mod tests` in `image.rs` covering canonical syntax and fixed paths:

```rust
#[test]
fn digest_requires_canonical_lower_hex() {
    let good = "ab".repeat(32);
    assert_eq!(ImageDigest::parse(ImageKind::Kernel, &good).unwrap().as_str(), good);
    for bad in [String::new(), "A".repeat(64), "g".repeat(64), "a".repeat(63)] {
        assert!(matches!(ImageDigest::parse(ImageKind::Kernel, &bad), Err(ImageError::InvalidDigest { .. })));
    }
}

#[tokio::test]
async fn resolver_uses_only_fixed_managed_paths() {
    use sha2::Digest as _;
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"kernel";
    let digest = hex::encode(sha2::Sha256::digest(bytes));
    let path = temp.path().join("kernels").join(&digest).join("vmlinux");
    tokio::fs::create_dir_all(path.parent().unwrap()).await.unwrap();
    tokio::fs::write(&path, bytes).await.unwrap();
    let store = ImageStore::new(temp.path().to_path_buf());
    let verified = store.resolve(ImageKind::Kernel, &digest).await.unwrap();
    assert_eq!(verified.digest().as_str(), digest);
}
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test -p ne-supervisor image::tests -- --nocapture`  
Expected: compilation fails because `ImageDigest`, `ImageStore`, and related types do not exist.

- [ ] **Step 3: Implement canonical parsing and managed resolution**

Implement these exact public shapes:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDigest(String);

impl ImageDigest {
    pub fn parse(kind: ImageKind, raw: &str) -> Result<Self, ImageError>;
    pub fn as_str(&self) -> &str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind { Kernel, Rootfs }

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("invalid {kind} image digest {digest:?}")]
    InvalidDigest { kind: ImageKind, digest: String },
    #[error("{kind} image {digest} not found")]
    NotFound { kind: ImageKind, digest: String },
    #[error("{kind} image {digest} rejected: {reason}")]
    Rejected { kind: ImageKind, digest: String, reason: String },
    #[error("{kind} image {digest} content digest mismatch (actual {actual})")]
    DigestMismatch { kind: ImageKind, digest: String, actual: String },
    #[error("staging {kind} image {digest}: {source}")]
    Stage { kind: ImageKind, digest: String, #[source] source: std::io::Error },
}

#[derive(Debug, Clone)]
pub struct ImageStore { root: std::path::PathBuf }

pub struct VerifiedImageFile {
    kind: ImageKind,
    digest: ImageDigest,
    file: tokio::fs::File,
}

pub struct VerifiedImagePair {
    pub kernel: VerifiedImageFile,
    pub rootfs: VerifiedImageFile,
}

impl ImageStore {
    pub fn new(root: std::path::PathBuf) -> Self;
    pub async fn resolve(&self, kind: ImageKind, raw_digest: &str)
        -> Result<VerifiedImageFile, ImageError>;
    pub async fn resolve_pair(&self, kernel: &str, rootfs: &str)
        -> Result<VerifiedImagePair, ImageError>;
}

impl VerifiedImageFile {
    pub fn digest(&self) -> &ImageDigest;
    pub async fn stage(
        &mut self,
        destination: &std::path::Path,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(), ImageError>;
}
```

Implement `Display` for `ImageKind` with the stable strings `kernel` and `rootfs`. `resolve` must canonicalize the store root, reject symlink endpoints and non-regular files, require the canonical artifact path to start with the canonical root, open with `O_NOFOLLOW`, hash through the retained handle, compare against the requested digest, rewind, and return that handle. Map `NotFound` separately; do not include paths outside the image root in errors.

- [ ] **Step 4: Add failing independent-inode and cleanup tests**

```rust
#[tokio::test]
async fn writable_stages_are_independent_and_leave_source_unchanged() {
    use sha2::Digest as _;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let source_bytes = b"rootfs";
    let digest = hex::encode(sha2::Sha256::digest(source_bytes));
    let source = temp.path().join("rootfs").join(&digest).join("rootfs.img");
    tokio::fs::create_dir_all(source.parent().unwrap()).await.unwrap();
    tokio::fs::write(&source, source_bytes).await.unwrap();
    tokio::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).await.unwrap();
    let before = std::fs::metadata(&source).unwrap();
    let store = ImageStore::new(temp.path().to_path_buf());
    let mut first = store.resolve(ImageKind::Rootfs, &digest).await.unwrap();
    let mut second = store.resolve(ImageKind::Rootfs, &digest).await.unwrap();
    let d1 = temp.path().join("w1/rootfs.img");
    let d2 = temp.path().join("w2/rootfs.img");
    tokio::fs::create_dir_all(d1.parent().unwrap()).await.unwrap();
    tokio::fs::create_dir_all(d2.parent().unwrap()).await.unwrap();
    first.stage(&d1, 0o600, before.uid(), before.gid()).await.unwrap();
    second.stage(&d2, 0o600, before.uid(), before.gid()).await.unwrap();
    tokio::fs::write(&d1, b"changed").await.unwrap();
    assert_eq!(tokio::fs::read(&source).await.unwrap(), b"rootfs");
    assert_eq!(tokio::fs::read(&d2).await.unwrap(), b"rootfs");
    let after = std::fs::metadata(&source).unwrap();
    assert_eq!(before.uid(), after.uid());
    assert_eq!(before.gid(), after.gid());
    assert_eq!(before.mode(), after.mode());
    assert_ne!(before.ino(), std::fs::metadata(&d1).unwrap().ino());
    assert_ne!(std::fs::metadata(&d1).unwrap().ino(), std::fs::metadata(&d2).unwrap().ino());
}
```

Also test symlink rejection, canonical escape rejection, non-regular rejection, mismatched bytes, `create_new` refusal, exact `0400`/`0600` modes, and removal of a partially created destination after a forced copy error.

- [ ] **Step 5: Implement staging and make tests GREEN**

`VerifiedImageFile::stage` must seek to byte zero, open the destination with `write(true).create_new(true).mode(mode)`, copy from the retained handle, flush, `chown` the destination to the jailer uid/gid, set the exact final mode, and remove the destination on any post-create error. No call to `hard_link` is permitted.

Run: `cargo test -p ne-supervisor image::tests -- --nocapture`  
Expected: all image-module tests pass.

- [ ] **Step 6: Run crate verification and commit**

Run: `cargo fmt --all -- --check`  
Run: `cargo clippy -p ne-supervisor --all-targets -- -D warnings`  
Run: `cargo test -p ne-supervisor --all-targets`  
Expected: all commands exit 0.

Commit:

```bash
git add crates/ne-supervisor/src/image.rs crates/ne-supervisor/src/lib.rs crates/ne-supervisor/Cargo.toml
git commit -m "fix(supervisor): stage verified images as independent files"
```

---

### Task 2: Breaking Rust request contract and cold-create integration

**Files:**
- Modify: `proto/ne/runtime/v1/runtime.proto`
- Modify: `crates/ne-protocol/src/supervisor.rs`
- Modify: `crates/ne-api/src/core.rs`
- Modify: `crates/ne-api/src/server.rs`
- Modify: `crates/ne-api/src/rest.rs`
- Modify: `crates/ne-supervisor/src/serve.rs`
- Modify: `crates/ne-supervisor/src/workspace.rs`
- Modify: `crates/ne-supervisor/src/firecracker.rs`
- Modify: `crates/ne/src/cli.rs`
- Modify: `crates/ne/src/main.rs`
- Modify: `crates/ne/templates/ne-enclave.env.tmpl`
- Modify: `crates/ne-api/tests/grpc_e2e.rs`
- Modify: `crates/ne-api/tests/rest.rs`
- Modify: `crates/ne-api/tests/tls.rs`
- Modify: `crates/ne-supervisor/tests/firecracker_lifecycle.rs`
- Modify: `crates/ne-supervisor/tests/run_command_e2e.rs`

**Interfaces:**
- Consumes: Task 1 `ImageStore::resolve_pair` and verified staging APIs.
- Produces: digest-only create requests, `SupervisorConfig.image_store`, typed image error responses, and a cold-launch path with no caller-controlled image paths.

- [ ] **Step 1: Write failing protocol and mapping tests**

Update request round-trip tests to construct:

```rust
CreateWorkspaceRequest {
    workspace_id: "ws-1".into(),
    kernel_sha256: "11".repeat(32),
    rootfs_sha256: "22".repeat(32),
    rootfs_read_only: true,
    vcpu_count: 1,
    mem_size_mib: 256,
    guest_vsock_cid: 3,
    kernel_boot_args: None,
    network: None,
    tier: None,
}
```

Add serialization tests for `InvalidImageDigest`, `ImageNotFound`, `ImageRejected`, `ImageDigestMismatch`, and `ImageStageFailed`. Add REST/gRPC mapping assertions matching the design table.

- [ ] **Step 2: Run protocol/API tests and verify RED**

Run: `cargo test -p ne-protocol supervisor::tests`  
Run: `cargo test -p ne-api --lib`  
Expected: compile failures for missing digest fields and error variants.

- [ ] **Step 3: Replace path fields end-to-end**

Change protobuf fields 2/3 to `kernel_sha256` / `rootfs_sha256`. Make the same replacement in `CreateWorkspaceRequest`, `CreateWorkspaceInput`, REST `CreateWorkspaceBody`, gRPC conversion, debug fields, fake supervisors, and every Rust request fixture. Remove all create-contract references to `kernel_image_path` and `rootfs_image_path`.

Add the five error variants to `SupervisorErrorKind`, stable code mapping in `ne-api::core`, REST mappings `400/404/409/500`, and gRPC mappings `invalid_argument/not_found/failed_precondition/internal`.

- [ ] **Step 4: Add failing configuration and pre-allocation tests**

Add `image_store: PathBuf` to supervisor test fixtures and assert CLI default/env resolution is `/var/lib/ne-enclave/images`. Add a workspace test with a missing digest image and a fake network controller assertion proving no slot/setup command is touched before `ImageNotFound` returns.

- [ ] **Step 5: Integrate verified images into cold launch**

Add `image_store` to `SupervisorArgs`, `SupervisorConfig`, `WorkspaceManagerConfig`, the installed env, and `WorkspaceManager` construction. For standard cold creates, resolve the pair before `NetworkController::setup`.

Refactor Firecracker launch so its staging inputs are `VerifiedImagePair`, not source `PathBuf`s. Delete the old `stage_file` helper. Stage into `vmlinux` and `rootfs.img` using exact modes based on `rootfs_read_only`, then pass only chroot-relative paths to Firecracker. Internal `Instance` may still retain digest plus managed source path temporarily until Task 3 removes manifest paths, but no public request or path join may use caller text.

Warm-pool and confidential paths accept both digests empty. Reject a half-present pair and syntactically invalid non-empty pair with `InvalidImageDigest`.

- [ ] **Step 6: Verify GREEN and absence of path fields**

Run: `cargo test -p ne-protocol`  
Run: `cargo test -p ne-api --all-targets`  
Run: `cargo test -p ne-supervisor --all-targets`  
Run: `rg -n "kernel_image_path|rootfs_image_path|hard_link\(" proto crates/ne-protocol crates/ne-api crates/ne-supervisor crates/ne`  
Expected: tests exit 0; search returns no public-contract or staging matches (historical migration documentation may be listed separately and adjudicated).

- [ ] **Step 7: Commit**

```bash
git add proto crates/ne-protocol crates/ne-api crates/ne-supervisor crates/ne
git commit -m "feat(runtime): require managed image digests for workspace create"
```

---

### Task 3: Snapshot manifest v5, restore/fork resolution, and attestation measurement

**Files:**
- Modify: `crates/ne-protocol/src/snapshot.rs`
- Modify: `crates/ne-supervisor/src/snapshot.rs`
- Modify: `crates/ne-supervisor/src/workspace.rs`
- Modify: `crates/ne-supervisor/src/firecracker.rs`
- Modify: `crates/ne-supervisor/src/seal.rs`
- Modify: `crates/ne/tests/snapshot_verify.rs`
- Modify: `crates/ne-e2e/tests/snapshot_restore.rs`
- Modify: `crates/ne-e2e/tests/fork_concurrent.rs`
- Modify: `crates/ne-e2e/tests/live_snapshot.rs`
- Modify: `crates/ne-e2e/tests/warm_pool.rs`

**Interfaces:**
- Consumes: Task 1 resolver/stager and Task 2 instance digest metadata.
- Produces: path-free signed manifest v5 and restore/fork paths that re-resolve managed images.

- [ ] **Step 1: Write failing manifest v5 tests**

Change `MANIFEST_VERSION` expectations to 5 and use:

```rust
SnapshotManifest {
    manifest_version: 5,
    snapshot_id: "01J0SNAP".into(),
    created_from_workspace_id: "ws-a".into(),
    firecracker_version: "1.13.1".into(),
    mem_sha256: "11".repeat(32),
    vmstate_sha256: "22".repeat(32),
    kernel_sha256: "33".repeat(32),
    rootfs_sha256: "44".repeat(32),
    guest_identity,
    kernel_boot_args: "console=ttyS0".into(),
    signer_pubkey_b64,
    signature_b64: String::new(),
}
```

Assert serialized JSON contains both digest names and contains neither `kernel_path` nor `rootfs_path`. Assert a v4 manifest fails `UnsupportedVersion { got: 4, supported: 5 }`.

- [ ] **Step 2: Run snapshot tests and verify RED**

Run: `cargo test -p ne-protocol snapshot::tests`  
Run: `cargo test -p ne-supervisor snapshot::tests`  
Expected: compile failures until the v5 fields and call sites exist.

- [ ] **Step 3: Implement manifest and capture changes**

Set `MANIFEST_VERSION = 5`, document the field break, remove both path fields, add `kernel_sha256`, and retain `rootfs_sha256`. Change `write_manifest` to accept the digest pair and stop hashing/opening a rootfs path. `Instance` must carry `kernel_sha256: String` and `rootfs_sha256: String`; snapshot capture copies those values into the signed manifest.

- [ ] **Step 4: Add failing restore and measurement tests**

Test that restore/fork with a valid signed manifest but missing managed kernel returns `ImageNotFound` before Firecracker spawn. Mutate a managed rootfs after manifest creation and assert `ImageDigestMismatch`. Construct two instances differing only in `kernel_sha256` and assert `measure_config` differs; repeat for `rootfs_sha256`.

- [ ] **Step 5: Re-resolve images during restore/fork**

After pinned manifest verification and before `firecracker::restore`, call the same image-store resolver with the two manifest digests. Pass verified files to restore staging; never turn manifest text into a host path. Update seal fixtures, offline snapshot verification fixtures, and E2E manifest constructors to v5.

- [ ] **Step 6: Verify and commit**

Run: `cargo test -p ne-protocol snapshot`  
Run: `cargo test -p ne-supervisor --all-targets`  
Run: `cargo test -p ne-enclave --all-targets`  
Run: `rg -n "kernel_path|rootfs_path" crates/ne-protocol/src/snapshot.rs crates/ne-supervisor/src`  
Expected: all tests exit 0 and search returns no snapshot/instance path fields.

Commit:

```bash
git add crates/ne-protocol crates/ne-supervisor crates/ne crates/ne-e2e
git commit -m "feat(snapshot): bind manifest v5 to managed image digests"
```

---

### Task 4: Regenerated bindings and core SDK contracts

**Files:**
- Modify: `sdk/python/src/ne/runtime/v1/runtime_pb2.py`
- Modify: `sdk/python/src/ne/runtime/v1/runtime_pb2_grpc.py` if regeneration changes it
- Modify: `sdk/python/src/ne/client.py`
- Modify: `sdk/python/tests/test_client.py`
- Modify: `sdk/python/README.md`
- Modify: `sdk/typescript/src/generated/ne/runtime/v1/runtime.ts`
- Modify: `sdk/typescript/src/client.ts`
- Modify: `sdk/typescript/tests/client.test.ts`
- Modify: `sdk/typescript/README.md`

**Interfaces:**
- Consumes: Task 2 protobuf field names.
- Produces: generated and handwritten Python/TypeScript SDKs that send only image digests.

- [ ] **Step 1: Change SDK tests first**

Python assertions must call `create_workspace(kernel_sha256="11" * 32, rootfs_sha256="22" * 32, ...)` and assert the sent protobuf fields. TypeScript assertions must pass `kernelSha256` / `rootfsSha256` and inspect those wire fields. Add source checks that the removed parameter names are absent.

- [ ] **Step 2: Run SDK tests and verify RED**

Run: `python3 -m pytest -q sdk/python/tests/test_client.py`  
Run: `npm test -- --run` from `sdk/typescript`  
Expected: failures because clients still expose path parameters.

- [ ] **Step 3: Regenerate bindings and update clients**

Run `sdk/python/scripts/codegen.sh` and `sdk/typescript/codegen.sh` from the repository root. Update handwritten clients to expose the digest names, preserve `rootfs_read_only=True` / `rootfsReadOnly ?? true`, and remove path arguments. Update core SDK READMEs with digest examples.

- [ ] **Step 4: Verify generated drift and GREEN**

Run: `python3 -m pytest -q sdk/python/tests/test_client.py`  
Run from `sdk/typescript`: `npm run lint && npm run typecheck && npm test -- --run && npm run build`  
Run: `rg -n "kernel_image_path|rootfs_image_path|kernelImagePath|rootfsImagePath" sdk/python sdk/typescript`  
Expected: tests/builds exit 0 and search returns no API or generated-field matches.

- [ ] **Step 5: Commit**

```bash
git add sdk/python sdk/typescript
git commit -m "feat(sdk): create workspaces from managed image digests"
```

---

### Task 5: Framework adapters, examples, and operator documentation

**Files:**
- Modify: `sdk/python-langchain/src/ne_langchain/workspace.py`
- Modify: `sdk/python-langchain/tests/test_workspace.py`
- Modify: `sdk/python-langchain/examples/quickstart.py`
- Modify: `sdk/python-langchain/README.md`
- Modify: `sdk/typescript-mastra/src/workspace.ts`
- Modify: `sdk/typescript-mastra/tests/workspace.test.ts`
- Modify: `sdk/typescript-mastra/examples/quickstart.ts`
- Modify: `sdk/typescript-mastra/README.md`
- Modify: `README.md`
- Create: `docs/BREAKING-CHANGES.md`
- Modify: `deploy/README.md`
- Modify: `deploy/smoke-install.sh`
- Modify: `docs/THREAT-MODEL.md`

**Interfaces:**
- Consumes: Task 4 SDK method names and Task 2 environment/configuration names.
- Produces: adapter APIs and documentation with no arbitrary image paths.

- [ ] **Step 1: Change adapter tests first**

LangChain tests must set `NE_KERNEL_SHA256` / `NE_ROOTFS_SHA256`, assert digest arguments reach `Client.create_workspace`, and assert old environment variables are ignored. Mastra tests must pass camel-case digest options and assert the core client receives them.

- [ ] **Step 2: Run adapter tests and verify RED**

Run: `python3 -m pytest -q sdk/python-langchain/tests`  
Run from `sdk/typescript-mastra`: `npm test -- --run`  
Expected: failures while adapters still read path names.

- [ ] **Step 3: Update adapters and examples**

Replace adapter constructor fields and environment names with the approved digest names. Cold-create adapters require both values; raise their existing configuration error listing `kernel_sha256` and `rootfs_sha256` when absent. Preserve the LangChain adapter's current writable-rootfs default and Mastra's existing default unless their underlying SDK explicitly overrides it.

- [ ] **Step 4: Update operator documentation and smoke request**

Change all create examples to use the SHA-256 values emitted by `nee image import`. Add `NE_IMAGE_STORE=/var/lib/ne-enclave/images` to deployment configuration documentation. Update the threat model to state that create and restore resolve verified managed digests and stage independent files; explicitly retain the hostile-root and unsigned-release limitations. Create `docs/BREAKING-CHANGES.md` with a `## Next release` section naming the removed request fields, their digest replacements, the `NE_KERNEL_SHA256` / `NE_ROOTFS_SHA256` adapter variables, and the rejection of snapshot manifests older than version 5.

- [ ] **Step 5: Verify adapters and repository-wide absence**

Run: `python3 -m pytest -q sdk/python-langchain/tests`  
Run from `sdk/typescript-mastra`: `npm run lint && npm run typecheck && npm test -- --run && npm run build`  
Run: `rg -n "kernel_image_path|rootfs_image_path|kernelImagePath|rootfsImagePath|NE_KERNEL_IMAGE_PATH|NE_ROOTFS_IMAGE_PATH" --glob '!docs/superpowers/**' .`  
Expected: adapter checks exit 0; remaining search hits exist only in an explicit release-note sentence naming removed fields, if retained.

- [ ] **Step 6: Commit**

```bash
git add sdk/python-langchain sdk/typescript-mastra README.md deploy docs/BREAKING-CHANGES.md docs/THREAT-MODEL.md
git commit -m "docs: migrate image workflows to managed digests"
```

---

### Task 6: Full verification and claim audit

**Files:**
- Modify only files required to fix failures discovered by the commands below.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: a fully verified branch and an evidence report for final review.

- [ ] **Step 1: Run formatting, lint, and all Rust targets**

Run: `cargo fmt --all -- --check`  
Run: `cargo clippy --workspace --all-targets -- -D warnings`  
Run: `cargo test --workspace --all-targets`  
Expected: all commands exit 0 with zero failures.

- [ ] **Step 2: Run every SDK and adapter gate**

Run: `python3 -m pytest -q sdk/python/tests sdk/python-langchain/tests`  
Run from `sdk/typescript`: `npm run lint && npm run typecheck && npm test -- --run && npm run build`  
Run from `sdk/typescript-mastra`: `npm run lint && npm run typecheck && npm test -- --run && npm run build`  
Expected: all commands exit 0.

- [ ] **Step 3: Verify security invariants by search and diff**

Run:

```bash
rg -n "hard_link\(|kernel_image_path|rootfs_image_path|kernelImagePath|rootfsImagePath|NE_KERNEL_IMAGE_PATH|NE_ROOTFS_IMAGE_PATH" --glob '!docs/superpowers/**' .
rg -n "kernel_path|rootfs_path" crates/ne-protocol/src/snapshot.rs crates/ne-supervisor/src
git diff --check
git status --short
```

Expected: no forbidden runtime/SDK matches; any historical release-note match is manually confirmed non-executable; diff check is clean; status lists no uncommitted implementation files after the final commit.

- [ ] **Step 4: Run final independent review**

Create a review package from branch base through `HEAD`, dispatch `ROLE: SOL REVIEW — review inline; do not delegate or modify files.`, and require explicit adjudication of digest validation, symlink handling, retained-handle verification, inode independence, cleanup, snapshot v5, error mappings, and all SDK contracts. Critical or Important findings must be fixed and freshly re-reviewed.

- [ ] **Step 5: Close the review gate**

If review is clean, record the reviewer verdict and verification outputs in the task report without creating an empty commit. If review finds Critical or Important issues, dispatch one bounded fix task containing the complete findings list; that fixer must name and stage each file it changes, commit with `fix: address secure image staging review`, rerun the covering tests, and return the new commit for re-review.
