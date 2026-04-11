# Contributing to Snapfzz Seal

This document describes the procedures and standards expected of contributors to the Snapfzz Seal project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Setup](#development-setup)
- [Workspace Structure](#workspace-structure)
- [Building](#building)
- [Testing](#testing)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Security Considerations](#security-considerations)

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).

## Development Setup

### Prerequisites

- **Rust** — stable toolchain, minimum version 1.85 (declared as `rust-version` in
  `crates/snapfzz-seal/Cargo.toml`). Install via [rustup](https://rustup.rs/). All crates
  use `edition = "2024"`.
- **cargo-nextest** — test runner used by CI:
  ```bash
  cargo install cargo-nextest
  ```
- **cargo-llvm-cov** — coverage tool used by CI:
  ```bash
  cargo install cargo-llvm-cov
  ```
- **musl toolchain** (Linux, required by the `lint` and `build` CI jobs for the
  `x86_64-unknown-linux-musl` target):
  ```bash
  sudo apt-get install musl-tools
  ```

### Clone and Build

```bash
git clone https://github.com/0xtrou/snapfzz-seal.git
cd snapfzz-seal
cargo build
```

## Workspace Structure

The repository is a Cargo workspace with resolver version 3. The six crates are:

| Crate | Binary | Purpose |
|---|---|---|
| `snapfzz-seal` | `seal` | CLI entry point (keygen, compile, sign, verify) |
| `snapfzz-seal-launcher` | `seal-launcher` | Runtime launcher with seccomp sandboxing |
| `snapfzz-seal-core` | — | Cryptographic primitives, key derivation, signing |
| `snapfzz-seal-compiler` | — | Backend-specific packaging (PyInstaller, Nuitka, Go) |
| `snapfzz-seal-fingerprint` | — | Environment fingerprint collection |
| `snapfzz-seal-server` | — | Sandbox HTTP server |

Workspace-level lint configuration (`Cargo.toml`) sets `unsafe_code = "deny"` and
`missing_docs = "warn"` for all crates, and `clippy::all = "warn"`. Any unsafe block
requires an explicit `// SAFETY:` justification comment.

## Building

### Development build

```bash
cargo build --workspace
```

### Release build — BUILD_ID constraint

`snapfzz-seal` and `snapfzz-seal-launcher` must be compiled with the **same `BUILD_ID`
value**. Both `build.rs` scripts derive deterministic binary markers from this value using
`SHA-256(build_id || label || "deterministic_marker_v1")`. If the two binaries are built
with different `BUILD_ID` values the marker lookup will fail at runtime.

```bash
BUILD_ID=<value> cargo build --release -p snapfzz-seal -p snapfzz-seal-launcher
```

If `BUILD_ID` is not set, both build scripts fall back to the string `"dev"`. This default
is acceptable for local development but must not be used for distributed sealed binaries.

In CI (`e2e-test.yml`), the `build-binaries` job sets `BUILD_ID=${{ github.sha }}`,
ensuring every binary pair built within a workflow run shares a consistent identifier.

The `ci.yml` `build` job runs `cargo build --workspace --release` without `BUILD_ID`, which
is appropriate for a compilation smoke-test; the resulting binaries are not used for E2E
execution.

### Release profile

The workspace `[profile.release]` uses `opt-level = 3`, `lto = true`,
`codegen-units = 1`, and `strip = true`. Stripped binaries contain no debug information;
attach a debugger only to debug builds.

## Testing

### Unit tests

Run the full workspace test suite with nextest (matches the `ci.yml` `test` job):

```bash
cargo nextest run --workspace
```

The `e2e-test.yml` `lint-and-test` job uses `cargo test --workspace` (standard libtest)
rather than nextest. Both runners are acceptable locally; CI requires nextest for the
coverage job.

### Coverage

The `ci.yml` `coverage` job enforces a minimum of 90% line coverage, excluding `main.rs`
files. The exact command run in CI is:

```bash
cargo llvm-cov nextest \
  --workspace \
  --lcov --output-path lcov.info \
  --summary-only \
  --ignore-filename-regex "main\.rs" \
  --fail-under-lines 90
```

Branch coverage has no enforced threshold in CI and is aspirational only. The 90% line
coverage threshold is the binding requirement.

To generate a local HTML report:

```bash
cargo llvm-cov nextest --workspace --ignore-filename-regex "main\.rs" --html
open target/llvm-cov/html/index.html
```

### End-to-end tests

The `e2e-test.yml` workflow exercises three backends — PyInstaller, Nuitka, and Go — against
a live example agent. The E2E jobs run in parallel after `build-binaries` passes, which
itself depends on `lint-and-test`. These tests require repository secrets
(`SNAPFZZ_SEAL_API_KEY`, `SNAPFZZ_SEAL_API_BASE`, `SNAPFZZ_SEAL_MODEL`,
`SNAPFZZ_SEAL_MASTER_SECRET_HEX`) and cannot be run locally without those credentials.

### Test placement

Unit tests belong in the same file as the code they cover, inside a `#[cfg(test)]` module.
Integration tests that span multiple modules or crates belong in a `tests/` directory
within the relevant crate.

## Code Style

### Formatting

All code must pass `cargo fmt` with default settings:

```bash
cargo fmt --all -- --check
```

### Linting

All clippy warnings are treated as errors in CI. The exact invocation used in both
`ci.yml` and `e2e-test.yml` is:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Note: neither CI workflow passes `--all-features`. Use the same invocation locally to
match CI behavior.

### Documentation

All public items require doc comments (`missing_docs = "warn"` at workspace level). Use
`///` syntax. Include `# Errors`, `# Panics`, and `# Safety` sections where applicable.

### Unsafe code

`unsafe_code = "deny"` is set at workspace level. Any unsafe block requires a
`// SAFETY:` comment explaining why the invariants required by the operation are upheld.

### Memory safety

Use `zeroize` (workspace dependency, includes the `derive` feature) for all types that
hold key material or other sensitive data. Do not store such data in types that do not
implement `Zeroize` or `ZeroizeOnDrop`.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

Recognized types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`.

The scope should correspond to the affected crate or subsystem (e.g., `core`, `launcher`,
`compiler`, `fingerprint`, `seccomp`).

Examples:

```
feat(compiler): add Nuitka backend for compiled Python agents

Integrate the Nuitka compilation pipeline as an alternative to
PyInstaller. Backend is selected via --backend nuitka at compile time.

Closes #123
```

```
fix(seccomp): allow io_uring syscalls for async runtimes

The seccomp allowlist was blocking io_uring_setup and related syscalls.
Added syscalls 425, 426, 427.

Fixes #456
```

## Pull Request Process

### Before submitting

Run the following checks locally and confirm they pass before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo llvm-cov nextest \
  --workspace \
  --lcov --output-path lcov.info \
  --summary-only \
  --ignore-filename-regex "main\.rs" \
  --fail-under-lines 90
```

Rebase on `main` before opening a PR:

```bash
git fetch origin
git rebase origin/main
```

### Requirements

- All CI jobs (`lint`, `test`, `build`, `coverage` in `ci.yml`; `lint-and-test`,
  `build-binaries`, and the three E2E jobs in `e2e-test.yml`) must pass.
- Line coverage must remain at or above 90%.
- At least one maintainer approval is required before merge.
- Address review comments with new commits; do not rewrite history on a PR branch after
  review has begun.

### Review timeline

Maintainers aim to provide an initial review within a few business days. There is no
guaranteed SLA.

## Security Considerations

Changes to the following areas carry elevated risk and will receive closer scrutiny during
review:

- `crates/snapfzz-seal-core/src/crypto.rs` — AES-256-GCM encryption and decryption
- `crates/snapfzz-seal-core/src/derive.rs` — HKDF key derivation
- `crates/snapfzz-seal-core/src/signing.rs` — Ed25519 signature operations
- `crates/snapfzz-seal-core/src/shamir.rs` — Secret sharing
- `crates/snapfzz-seal-fingerprint/src/collect.rs` — Environment fingerprint collection
- `crates/snapfzz-seal-launcher/src/protection/seccomp.rs` — seccomp BPF filter
- Any file containing `unsafe` blocks
- Either `build.rs` file — they embed `BUILD_ID`-derived markers into the binary; a change
  here affects binary compatibility between `seal` and `seal-launcher`

### Reporting vulnerabilities

Do not open public issues for security vulnerabilities. Contact maintainers through private
channels on GitHub. Include a description of the vulnerability, reproduction steps, an
assessment of potential impact, and a suggested fix if one is available.

### General practices

- Never commit secrets, keys, or credentials of any kind.
- Use constant-time comparisons wherever secret data is involved; the `subtle` crate is
  already a workspace dependency for this purpose.
- Validate all external inputs before use.
- Document security assumptions and invariants in doc comments or inline comments adjacent
  to the relevant code.

## License

By contributing to Snapfzz Seal, you agree that your contributions will be licensed under
the MIT License.
