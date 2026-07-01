# Contributing to NeuronEdge Enclave

Thanks for your interest in contributing to NeuronEdge Enclave. This guide
covers the expectations for contributions — code quality, licensing, and the
process for getting changes merged.

## Quick rules

1. **Code quality is the bar, not "good enough for now."** No lint warnings,
   no type errors, no `unwrap()`/`expect()` outside tests, and every test
   passes before review. See the engineering standards below.
2. **Sign the CLA.** Every contributor must agree to the
   [Contributor License Agreement](CLA.md) before a pull request can be
   merged. See the "Why a CLA" section in `CLA.md` — it preserves the
   project's licensing flexibility.
3. **No strong-copyleft dependencies.** Do not introduce code under AGPL,
   SSPL, or other licenses incompatible with Apache-2.0. CI rejects these.
4. **Clean-room discipline for competing projects.** See below.

## How to contribute

1. **Open an issue first** for anything beyond a small fix. A short design
   discussion avoids wasted work and keeps changes aligned with the roadmap.
2. **Fork and branch** from `main`. Use a descriptive branch name.
3. **Follow the code standards** below. The CI gate is strict.
4. **Open a pull request** against `main`. Reference the issue. Mark the PR
   ready for review only when CI is green and you've self-reviewed the diff.
5. **Sign the CLA** if you haven't already (see `CLA.md`).

## Engineering standards

The project uses Rust, strict, top-to-bottom. The gate that CI enforces:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Conventions:

- **No `unwrap()` / `expect()` outside tests and process startup.** Surface
  errors; the `unwrap_used` / `expect_used` clippy lints are on.
- **`unsafe` is forbidden at the workspace floor.** A crate that needs it
  (e.g. the vsock guest agent) opts in with `#![allow(unsafe_code)]` and a
  `// SAFETY:` comment justifying each use.
- **No `console.log` / `println!` / `eprintln!`** in library or production
  paths. Use structured logging (`tracing`) or return errors.
- **Tests must pass locally.** End-to-end tests that need `/dev/kvm` are
  `#[ignore]`'d; the unit + doc-test gate must always be green.

## Clean-room discipline

NeuronEdge Enclave is a privacy- and security-focused runtime. To protect the
project's license cleanliness and our contributors:

- **Do not read the source of strongly-copyleft competing projects**
  (e.g., Daytona, which is AGPL). Reading their *architecture documentation*
  for inspiration is fair use; importing or closely reproducing their code is
  not, and would taint this repository.
- **Do not submit code you did not write** or do not have the rights to
  contribute (see CLA section 5).
- **Disclose any third-party restrictions** (patents, trademarks, licenses)
  attached to your contribution.

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add TDX attestation report parsing
fix: correct TAP device cleanup race on workspace destroy
docs: expand the two-tier section of the README
test: add snapshot-restore cold-path coverage
refactor: extract key-release transport from ne-seal
perf: cut warm-pool pre-fork latency by 40%
chore: bump Firecracker pin to v1.16.1
```

- Keep the subject line to ~72 characters, imperative mood.
- The body explains *why*, not just *what* — the diff already shows what.

## Branching and releases

- **`main`** is the stable, releasable branch. PRs land here.
- **`dev`** is the integration branch for unreleased work. (If `dev` is
  present, PRs target `dev`; otherwise target `main`.)
- Releases are tagged from `main` (`v0.1.0`, `v0.1.1`, …). Release artifacts
  (static binaries, install script) are published as GitHub Releases.

## Reporting security issues

**Do not open a public issue for security vulnerabilities.** See
[SECURITY.md](SECURITY.md) for the private disclosure process.

## Questions

- Open a [Discussion](https://github.com/Infrastacks/ne-enclave/discussions)
  for questions and design chat.
- Open an [Issue](https://github.com/Infrastacks/ne-enclave/issues) for bugs
  and concrete feature requests.
- Email eng@infrastacks.com for anything sensitive.
