# Missing Install Prefix and v0.1.3 Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore safe creation of a missing `nee install --prefix` root and publish the corrective `v0.1.3` release.

**Architecture:** Root preparation is added at the existing validation boundary, while descendant creation continues through the component-wise no-follow helper. A focused integration test proves the original CLI condition, and release metadata is advanced monotonically before tagging.

**Tech Stack:** Rust 1.95.0, Cargo integration tests, GitHub Actions, TypeScript and Python package manifests, Git.

## Global Constraints

- Existing prefix symlinks and non-directories must remain rejected.
- Missing fakeroot prefixes must be created without changing production `/` behavior.
- No CI-only directory-creation workaround may replace the CLI fix.
- The release tag and all workflow-enforced version sources must be exactly `0.1.3`.
- Follow feature branch → `dev` → `main` → tag → `dev` gitflow.

---

### Task 1: Reproduce and fix missing-prefix installation

**Files:**
- Modify: `crates/ne/tests/install_fakeroot.rs`
- Modify: `crates/ne/src/install/run.rs`

**Interfaces:**
- Consumes: `Layout::new`, `InstallOptions`, `install`, `validate_directory`.
- Produces: `ensure_layout_root(root: &Path) -> Result<()>`, called by `validate_existing_directory_chains`.

- [ ] **Step 1: Write the failing integration test**

Add a test that creates a temporary parent, chooses an uncreated `fakeroot`
child, runs `install` with `fakeroot: true`, `no_start: true`, and
`no_image: true`, and asserts both the root and rendered supervisor unit exist.

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
cargo test -p ne-enclave --test install_fakeroot fakeroot_install_creates_missing_prefix_root -- --exact
```

Expected: nonzero exit with the install error containing `inspect` and the
missing `fakeroot` path.

- [ ] **Step 3: Implement the minimal root preparation**

Add `ensure_layout_root`. Use `fs::symlink_metadata`; validate an existing
root, create a missing root with contextual `create_dir_all`, then validate
the created root. Propagate any other inspection error with `inspect <path>`
context. Call it at the start of `validate_existing_directory_chains`.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run the exact command from Step 2. Expected: one test passes.

- [ ] **Step 5: Run the complete fakeroot suite**

```bash
cargo test -p ne-enclave --test install_fakeroot
```

Expected: all tests pass, including existing symlink-rejection coverage.

- [ ] **Step 6: Commit the behavioral fix**

```bash
git add crates/ne/src/install/run.rs crates/ne/tests/install_fakeroot.rs
git commit -m "fix(install): create missing fakeroot prefix"
```

### Task 2: Advance release sources to 0.1.3

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `sdk/typescript/package.json`
- Modify: `sdk/python/pyproject.toml`
- Modify: `sdk/python/src/ne/__init__.py`

**Interfaces:**
- Consumes: `.github/workflows/release.yml` version-check source list.
- Produces: four checked version sources and Rust lockfile package versions at `0.1.3`.

- [ ] **Step 1: Demonstrate current version inconsistency**

Run the release workflow's four-source extraction locally and compare each
value with `0.1.3`. Expected: all four report `0.1.1` before the bump.

- [ ] **Step 2: Update release sources**

Change the workspace, TypeScript SDK, Python project, and Python `__version__`
values to `0.1.3`. Run `cargo check -p ne-enclave` to refresh `Cargo.lock`.

- [ ] **Step 3: Verify version consistency**

Run the same extraction and assert every value is `0.1.3`; also confirm
`cargo metadata --no-deps --format-version 1` reports workspace packages at
`0.1.3`.

- [ ] **Step 4: Commit the version bump**

```bash
git add Cargo.toml Cargo.lock sdk/typescript/package.json sdk/python/pyproject.toml sdk/python/src/ne/__init__.py
git commit -m "chore(release): v0.1.3"
```

### Task 3: Review, verify, integrate, and release

**Files:**
- Verify: all files changed since `dev`

**Interfaces:**
- Consumes: reviewed feature commits and repository CI/release workflows.
- Produces: synchronized `dev` and `main`, annotated `v0.1.3`, published release workflow, final checkout on `dev`.

- [ ] **Step 1: Run local branch gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --lib
cargo test -p ne-enclave --test install_fakeroot
npm ci --prefix sdk/typescript
npm run --prefix sdk/typescript lint
npm run --prefix sdk/typescript typecheck
npm run --prefix sdk/typescript test
npm run --prefix sdk/typescript build
```

Expected: every command exits zero.

- [ ] **Step 2: Obtain independent code review**

Review the diff from the feature base through `HEAD`. Critical and Important
findings block integration until fixed, retested, and re-reviewed.

- [ ] **Step 3: Merge through gitflow**

Merge the feature branch into `dev`, rerun the focused and workspace gates,
push `dev`; merge `dev` into `main`, rerun release-critical gates, and push
`main`.

- [ ] **Step 4: Tag and verify release**

Create annotated tag `v0.1.3` on the verified `main` commit and push it. Wait
for the tag-triggered Release workflow and main CI to complete, inspect any
failed logs, and do not report success unless required jobs pass and the
GitHub Release exists with its expected assets.

- [ ] **Step 5: Return to dev**

Remove the owned feature worktree and branch after successful integration,
then leave the primary checkout on clean `dev` synchronized with
`origin/dev`.
