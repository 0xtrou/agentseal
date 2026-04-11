# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Fixed

- **BUILD_ID marker stability**: `snapfzz-seal-core` and `snapfzz-seal-launcher` build scripts
  now fall back to a shared `"dev"` literal when the `BUILD_ID` environment variable is absent,
  preventing marker divergence between crates during local and CI builds.
- **Nuitka invocation fallback**: the Nuitka compile backend now falls back to
  `python3 -m nuitka` when the standalone `nuitka` binary is not present on `PATH`;
  `--static-libpython=no` is also passed for compatibility with pyenv-managed interpreters.
- **Rust 1.88 Docker upgrade**: Dockerfile base image bumped from `rust:1.86` to `rust:1.88`
  to support `let-chain` syntax stabilised in Rust 1.88.
- **Launcher path resolution in E2E tests**: `full_interaction_test.sh` now resolves the
  `seal-launcher` binary dynamically from the workspace build output with a `PATH` fallback,
  so both Docker and local developer runs locate the binary correctly.
- **Test race condition in route validation**: each path-validation test in `routes.rs` now
  uses a unique temporary directory name to prevent conflicts when tests run in parallel.
- **macOS Nuitka skip**: `full_interaction_test.sh` skips the Nuitka backend on macOS due to
  Homebrew dynamic-library scanning incompatibility in onefile mode.
- **Unused dependency removed**: `chrono` build-dependency removed from `snapfzz-seal-core`.
- **quick_test.sh always rebuilds**: the quick test script now forces a rebuild on every
  invocation to prevent stale artifacts from masking failures.

---

## Previous releases (chronological summary)

### Backend-aware execution dispatch

#### Added

- `TempFileExecutor` as a fallback execution path for backends (Nuitka, PyInstaller) that do not
  support `memfd_create`-based in-memory execution.
- `BackendType` field added to `PayloadFooter`; supported values: `Unknown`, `Go`,
  `PyInstaller`, `Nuitka`.
- Launcher now dispatches on `BackendType` from the payload footer: Go uses `MemfdExecutor`;
  PyInstaller and Nuitka use `TempFileExecutor`; unknown backends attempt memfd with a
  temp-file fallback.

#### Fixed

- ETXTBSY error on Linux: temp-file file descriptor is now closed before calling `exec`.
- Nuitka artifact stripping: the `strip` step is skipped for Nuitka binaries to preserve the
  attached payload section.

---

### Go backend

#### Added

- Go compile backend added to the `seal` CLI (`seal compile --backend go`).

#### Fixed

- `ldflags` format passed to `go build` corrected.
- Key derivation, seccomp filter, and E2E test compatibility verified for Go-compiled agents.

---

### E2E test infrastructure

#### Added

- Comprehensive end-to-end tests covering Go, PyInstaller, and Nuitka backends under
  `e2e-tests/`.

#### Fixed

- Artifact download path in the E2E GitHub Actions workflow.
- Launcher binary renamed to `seal-launcher`; workspace `members` list updated accordingly.
- Marker embedding in the launcher binary: LTO stripping of marker symbols prevented via
  `#[unsafe(no_mangle)]` export and `read_volatile` preservation.

---

### Defense-in-depth security layers

#### Added

- **Layer 1 — Deterministic markers**: BUILD-time markers derived from `BUILD_ID` embedded in
  both the launcher and core crates. Five secret-share markers and ten decoy marker sets are
  generated at compile time via `build.rs` code generation.
- **Layer 2 — Shamir Secret Sharing**: pure-Rust 5-of-3 threshold implementation over the
  secp256k1 prime field. The master secret is split into five shares at assembly time; three
  are required for reconstruction at launch.
- **Layer 3 — Decoy secrets**: ten decoy marker sets embedded alongside real markers to raise
  the cost of static forensic analysis. Decoys are wired into the assembly pipeline.
- **Layer 4 — Anti-analysis**: debugger detection (Linux `TracerPid` check, `ptrace TRACEME`,
  software-breakpoint scan, timing anomaly); VM detection (CPUID hypervisor bit on x86_64,
  DMI artifact files and MAC address OUI matching on Linux). Environment poisoning with decoy
  environment variables and files on every launch.
- **Layer 5 — Integrity binding**: SHA-256 hash of launcher code and data regions computed at
  assembly time and stored in the payload footer. On Linux the hash is re-derived at launch
  and mixed into the decryption key, binding the key to the unmodified launcher binary.
- **Layer 6 — White-box cryptography**: T-box, Type I, and Type II lookup tables generated
  from the master key at assembly time and embedded in the launcher binary behind an
  `ASL_WB_TABLES_v1` marker. The runtime decryption path continues to use standard
  AES-256-GCM; the white-box tables are embedded but not yet consumed at launch.

---

### Security hardening

#### Added

- Mandatory Ed25519 signature verification at launch; payloads without a valid `ASL\x02`
  signature block are rejected with `MissingSignature`.
- `prctl(PR_SET_DUMPABLE, 0)` and `ptrace TRACEME` applied as anti-debug protections on Linux.

#### Removed

- `io_uring` syscalls removed from the seccomp allowlist following an audit finding.

#### Fixed

- All 15 findings from the independent security audit addressed.

---

### Core features (v0.2)

#### Added

- `AgentMode` enum (`Standard` / `Interactive`).
- Interactive launch mode (`--interactive`) with configurable `max_lifetime_secs` and a
  concurrent monitor thread for lifetime enforcement.
- Ed25519 signing CLI commands (`seal sign`, `seal verify`).
- Payload footer stores original payload hash and launcher hash for tamper verification.
- `SandboxBackend` and `CompileBackend` traits extracted for multi-platform support.
- Environment scrubbing applied before agent execution.
- Platform support extended: macOS fingerprint signals (MAC address, DMI), Linux seccomp
  filter, cross-platform file descriptor handling.

#### Removed

- `agent-seal-proxy` crate removed; orchestration now handled by `snapfzz-seal-server`.

---

### Initial release

#### Added

- Scaffolded encrypted sandbox-bound agent delivery system with six Rust crates:
  `snapfzz-seal` (CLI), `snapfzz-seal-core`, `snapfzz-seal-compiler`,
  `snapfzz-seal-fingerprint`, `snapfzz-seal-launcher`, `snapfzz-seal-server`.
- AES-256-GCM chunked streaming encryption (64 KB chunks, per-chunk nonce).
- HKDF-based key derivation from master secret, stable fingerprint hash, and optional user
  fingerprint.
- PyInstaller and Nuitka compile backends.
- Orchestration HTTP server with payload assembly endpoint.
- CI: 90% line-coverage gate, automated badge generation, parallel test and coverage jobs.
