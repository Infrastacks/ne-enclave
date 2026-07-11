# Missing Install Prefix and v0.1.3 Release Design

## Problem

The secure image-staging hardening changed installer directory creation from
`create_dir_all` to no-follow validation and component-wise creation. The new
validation requires the layout root to exist before managed directories are
created. As a result, the documented CLI form
`nee install --prefix <new-directory>` fails when the prefix does not already
exist, and the `unit-lint` job on `main` cannot render its fakeroot.

The existing fakeroot integration test did not catch the regression because
`tempfile::tempdir()` creates the exact path passed to `Layout::new`.

The latest tag is `v0.1.2`, but the current `dev` and `main` trees contain
`0.1.1` in the release-checked version sources. The corrective release must
therefore restore monotonic versioning at `0.1.3`.

## Scope

- Preserve `--prefix` behavior: a missing prefix is created by the installer.
- Preserve hardening: an existing prefix that is a symlink or non-directory is
  rejected before managed-path mutation.
- Add a regression test using a missing child beneath a temporary directory.
- Bump every source enforced by the release workflow to `0.1.3`, and refresh
  the Rust lockfile.
- Release through the established feature-to-`dev`-to-`main` gitflow and tag
  `v0.1.3` from the resulting `main` commit.

## Design

`validate_existing_directory_chains` will first prepare the layout root. If
`symlink_metadata` reports that the root exists, the existing no-follow
directory validation remains unchanged. If it reports `NotFound`, the
installer creates the root and immediately validates it. Other inspection or
creation errors retain path context and fail closed.

This is deliberately confined to the layout root. Managed descendants still
use `ensure_directory_chain`, which inspects each existing component with
`symlink_metadata`, creates one component at a time, and rejects symlinks and
non-directories. Production installs use `/`, so missing-root creation is a
fakeroot behavior and does not weaken production layout checks.

## Testing

The TDD regression test constructs `Layout::new(tmp.path().join("fakeroot"))`
without creating that child. Before the fix it must fail with `inspect
.../fakeroot`; after the fix it must pass and produce the expected layout.
Existing tests continue to cover pre-existing roots and hostile legacy
symlinks.

Verification includes the focused fakeroot integration test, workspace tests,
formatting, clippy, TypeScript SDK checks, release version consistency, and the
GitHub CI/release workflows. The tag is pushed only after merged-tree local
verification succeeds.

## Release Flow

1. Commit the behavioral fix and regression test on
   `codex/install-prefix-v0.1.3`.
2. Commit the `0.1.3` version bump on the same branch.
3. Review and verify the branch.
4. Merge and push into `dev`.
5. Merge `dev` into `main`, verify and push.
6. Create and push annotated tag `v0.1.3` from `main`.
7. Verify CI and release results, then check out `dev`.
