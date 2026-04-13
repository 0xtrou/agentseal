# Agent Getting Started Guide

Comprehensive reference for AI coding assistants working on Snapfzz Seal.

## What This Project Does

Snapfzz Seal compiles Python/Go agents into sealed, signed, encrypted binaries that are fingerprint-locked to a specific user and host. The binary self-destructs (decryption fails) if moved to a different environment.

**Target platform: Linux only.** macOS is used for `cargo build`/`check`/`clippy` during development, but all runtime features (memfd, seccomp, anti-debug, fingerprinting) require Linux. E2E tests run inside Docker.

---

## Crate Map

| Crate | Binary | Purpose |
|---|---|---|
| `snapfzz-seal` | `seal` | CLI entry point: 7 subcommands (compile, sign, verify, launch, keygen, fingerprint, server) |
| `snapfzz-seal-compiler` | — | Drives backend build tools (PyInstaller, Nuitka, Go), assembles sealed binary with embedded secrets |
| `snapfzz-seal-launcher` | `seal-launcher` | Runtime launcher embedded inside sealed binary; reconstructs master secret, decrypts payload, executes agent |
| `snapfzz-seal-core` | — | Cryptographic primitives: AES-256-GCM, HKDF, Shamir SSS, Ed25519 signing, payload envelope format |
| `snapfzz-seal-fingerprint` | — | Collects stable/ephemeral environment fingerprints (machine_id, hostname, kernel, cgroup, namespace inodes, MAC, DMI UUID) |
| `snapfzz-seal-server` | — | Optional Axum HTTP orchestration API with Bearer token auth |

---

## The Pipeline: Compile -> Sign -> Launch

```
COMPILE PHASE
  1. Backend tool (nuitka/pyinstaller/go) compiles agent source to ELF binary
  2. Generate random master_secret (32 bytes)
  3. Collect stable environment fingerprint (auto or manual hex)
  4. Split master_secret into 5 Shamir shares (threshold 3, secp256k1 field)
  5. Embed shares at marker-delimited slots in seal-launcher ELF
  6. Embed 50 decoy marker sets (10x5) for obfuscation
  7. Embed white-box AES lookup tables (~165 KB)
  8. Derive encryption key via HKDF chain:
       env_key       = HKDF(master_secret, stable_fp || user_fp, "snapfzz-seal/env/v1")
       integrity_key = HKDF(env_key, launcher_bytes, "snapfzz-seal/session/v1")
  9. AES-256-GCM encrypt agent binary (STREAM-BE32, 64 KB chunks)
 10. Assemble: launcher || sentinel || encrypted_payload || footer

SIGN PHASE
  1. Ed25519 sign entire binary (excluding signature block)
  2. Append signature block: ASL\x02 (4B) || signature (64B) || pubkey (32B)

LAUNCH PHASE
  1. Load binary from /proc/self/exe or --payload arg
  2. Verify Ed25519 signature
  3. Strip signature block, extract payload + footer
  4. Scan launcher ELF for Shamir shares at marker offsets
     - >= 3 shares: reconstruct secret (Lagrange interpolation)
     - < 3 shares: fallback to SNAPFZZ_SEAL_MASTER_SECRET_HEX env var
  5. Collect environment fingerprint (same HKDF fp_hmac_key derivation)
  6. Derive decryption key (same HKDF chain as compile)
  7. Verify launcher integrity hash
  8. Anti-analysis checks, apply protections (prctl, ptrace), poison env vars
  9. Apply seccomp filter (x86_64 or aarch64 allowlist)
 10. Decrypt payload (AES-256-GCM STREAM-BE32)
 11. Execute via memfd_create + fexecve (primary) or temp file (fallback)
 12. Relay stdin/stdout/stderr, enforce max_lifetime, output JSON result
```

### Binary Layout (Final)

```
[ launcher ELF with embedded Shamir shares + decoys + white-box tables ]
[ PAYLOAD_SENTINEL: 32 bytes (BUILD_ID-derived SHA-256) ]
[ encrypted payload: ASL\x01 magic || encrypted chunks || footer (65 bytes) ]
[ signature block: ASL\x02 || Ed25519 sig (64B) || pubkey (32B) ]
```

---

## Key Types

```rust
// Error type used throughout (snapfzz-seal-core/src/error.rs)
enum SealError {
    EncryptionFailed(String),
    DecryptionFailed(String),
    InvalidPayload(String),
    UnsupportedPayloadVersion(u16),
    TamperDetected,
    FingerprintMismatch,
    InvalidSignature,
    MissingSignature,
    Io(std::io::Error),
    InvalidInput(String),
    CompilationError(String),
    CompilationTimeout(u64),
    Other(anyhow::Error),
}

// Payload envelope (snapfzz-seal-core/src/types.rs)
struct PayloadHeader {
    magic: [u8; 4],           // "ASL\x01"
    version: u16,             // 0x0001
    enc_alg: u16,             // 0x0001 = AES-256-GCM
    fmt_version: u16,         // 0x0001 = STREAM-BE32
    chunk_count: u32,
    header_hmac: [u8; 32],
    mode: AgentMode,          // Batch or Interactive
}

struct PayloadFooter {
    original_hash: [u8; 32],  // SHA-256 of compiled agent
    launcher_hash: [u8; 32],  // SHA-256 of launcher (integrity check)
    backend_type: BackendType,
}

enum BackendType { Unknown=0, Go=1, PyInstaller=2, Nuitka=3 }
enum AgentMode  { Batch=0, Interactive=1 }

// Fingerprint (snapfzz-seal-fingerprint/src/model.rs)
enum RuntimeKind { Docker, Firecracker, Gvisor, Kata, Nspawn, GenericLinux, Unknown }
enum Stability   { Stable, SemiStable, Ephemeral }

struct SourceValue {
    id: String,          // e.g. "linux.hostname"
    value: Vec<u8>,
    confidence: u8,      // 0-100
    stability: Stability,
}

struct FingerprintSnapshot {
    runtime: RuntimeKind,
    stable: Vec<SourceValue>,
    ephemeral: Vec<SourceValue>,
    collected_at_unix_ms: u64,
}
```

---

## Cryptography Reference

| Purpose | Algorithm | Details |
|---|---|---|
| Master secret | `OsRng` | 32 random bytes |
| Envelope encryption | AES-256-GCM | STREAM-BE32: 12-byte nonce = prefix(7) \|\| counter_BE32(4) \|\| last_flag(1), 64 KB chunks |
| Key derivation | HKDF-SHA256 | Three stages: env_key, integrity_key, session_key |
| Signing | Ed25519 | Dalek library, optional compile-time pubkey pinning |
| Secret sharing | Shamir SSS | secp256k1 field, threshold=3, total=5, constant-time Lagrange via `subtle` |
| Integrity | SHA-256 | Launcher binary hash stored in payload footer |
| Fingerprint HMAC | HMAC-SHA256 | Per-build key derived via HKDF from master_secret |

### Key Derivation Chain

```
master_secret (32 random bytes)
  |
  +-- fp_hmac_key = HKDF(master_secret, salt=None, info="snapfzz-seal/fingerprint-hmac-key/v1")
  |     Used to HMAC fingerprint source values at both compile and launch time
  |
  +-- env_key = HKDF(master_secret, salt=stable_fp||user_fp, info="snapfzz-seal/env/v1")
        |
        +-- integrity_key = HKDF(env_key, salt=launcher_bytes, info="snapfzz-seal/session/v1")
              |
              +-- [optional] session_key = HKDF(integrity_key, salt=ephemeral_fp, info="snapfzz-seal/session/v1")
              |
              +-- final encryption/decryption key
```

---

## Fingerprint System

**11 Linux sources** collected by `FingerprintCollector`:

| Source ID | Stability | Origin |
|---|---|---|
| `linux.machine_id_hmac` | Stable | /etc/machine-id |
| `linux.hostname` | SemiStable | kernel hostname |
| `linux.kernel_release` | Stable | uname |
| `linux.cgroup_path` | SemiStable | /proc/self/cgroup |
| `linux.proc_cmdline_hash` | Stable | allowlisted boot args |
| `linux.mac_address` | Stable | first non-loopback MAC |
| `linux.dmi_product_uuid_hmac` | Stable | /sys/class/dmi/id/product_uuid |
| `linux.mount_namespace_inode` | Ephemeral | /proc/self/ns/mnt |
| `linux.pid_namespace_inode` | Ephemeral | /proc/self/ns/pid |
| `linux.net_namespace_inode` | Ephemeral | /proc/self/ns/net |
| `linux.uts_namespace_inode` | Ephemeral | /proc/self/ns/uts |

Source values are HMAC'd with `fp_hmac_key` (derived from master_secret via HKDF). Canonicalization sorts by ID and produces a SHA-256 hash.

**If the environment changes between compile and launch, the fingerprint hash changes, key derivation produces a different key, and decryption fails.** Re-provisioning (re-compile) is required.

---

## Execution Backends

### memfd_exec (Primary, Linux only)

1. `memfd_create()` -> anonymous in-memory file descriptor
2. Write decrypted agent binary to memfd
3. Seal memfd (make immutable)
4. `execveat(memfd, "", AT_EMPTY_PATH)` -> execute from memory
5. Binary never touches disk, no `/proc/<pid>/exe` readable path

### temp_exec (Fallback)

1. Create temp file in `/dev/shm` (preferred, tmpfs) or `/tmp`
2. Write decrypted binary, chmod +x
3. Open fd, unlink path from filesystem, `fexecve(fd)` (Linux) or `execve(path)` (non-Linux)
4. Open-unlink-exec pattern: file disappears from directory before child is live
5. Relay stdin/stdout/stderr through pipes

Both backends use:
- `O_CLOEXEC` / `pipe2(O_CLOEXEC)` on all pipe/fd creation to prevent fd leaks across fork
- Interruptible lifetime/heartbeat monitors (100ms poll loops, not blocking sleeps)
- SIGTERM -> grace period -> SIGKILL escalation for max_lifetime enforcement

---

## Seccomp Sandbox

Applied after anti-debug checks and key loading, before decryption. Inherited across fork/clone/execve.

- **x86_64:** ~168 allowed syscalls
- **aarch64:** ~165 allowed syscalls (asm-generic numbering, no legacy open/fork/pipe/stat)
- **Default action:** `EPERM` on blocked syscalls
- Key allowed syscalls: `execveat` (memfd execution), `memfd_create` (PyInstaller), `seccomp` (Python sub-sandboxes), `getrandom`, all networking, all I/O

---

## Compilation Backends

| Backend | Detection | Timeout | Notes |
|---|---|---|---|
| PyInstaller | `main.py` present | 1800s | `pyinstaller` must be on PATH |
| Nuitka | `main.py` present | 1800s | Onefile mode fails on macOS Homebrew; use Docker |
| Go | `go.mod` present | 600s | Static binary: `CGO_ENABLED=0 GOOS=linux` |

---

## Server Crate

Optional Axum HTTP API for orchestrating compilation jobs.

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | None | Health check |
| `POST /api/v1/jobs` | Bearer | Create compilation job |
| `GET /api/v1/jobs/<id>` | Bearer | Get job status |
| `DELETE /api/v1/jobs/<id>` | Bearer | Cancel job |

Auth: `SNAPFZZ_SEAL_API_KEY` env var or `--api-key` flag. If unset, auth is skipped (dev mode).

---

## Build System

### Workspace Configuration

- **Edition:** Rust 2024, resolver = "3"
- **Lints:** `unsafe_code = "deny"`, all clippy warnings
- **Release profile:** `opt-level = 3`, `lto = true`, `strip = true`, `codegen-units = 1`

### BUILD_ID Invariant

Both `snapfzz-seal-core` and `snapfzz-seal-launcher` have `build.rs` scripts that derive marker values from the `BUILD_ID` environment variable. **Both crates must be built with the same BUILD_ID** or marker scanning will fail.

```bash
# Always build the whole workspace together
BUILD_ID="$(openssl rand -hex 16)" cargo build --release
```

Default: `BUILD_ID=dev` if unset (fine for local development).

### Launcher Features

```toml
[features]
ci-bypass = []        # Bypass env-var plaintext secret fallback in release
skip-pubkey-pin = []  # Skip compile-time pubkey pinning
```

---

## CI/CD (.github/workflows/ci.yml)

1. **lint** — `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --check`
2. **test** — `cargo nextest run --workspace` (5 min timeout)
3. **build** — `BUILD_ID=$GITHUB_SHA cargo build --workspace --release` (musl target)
4. **coverage** — `cargo llvm-cov` with nextest, threshold >= 88% line coverage

---

## Docker & E2E Tests

**Multi-stage build** (`e2e-tests/Dockerfile`):
- Stage 1 (rust:1.88-alpine): builds Rust workspace
- Stage 2 (alpine:3.21): runtime with Python, Go, pyinstaller, nuitka

**Run e2e tests:**
```bash
docker compose -f e2e-tests/docker-compose.yml up --build --abort-on-container-exit

# With LLM API for live testing:
SNAPFZZ_SEAL_API_KEY=xxx docker compose -f e2e-tests/docker-compose.yml up --build
```

Tests exercise all three backends: compile -> sign -> verify -> launch.

---

## Example Agents

All in `examples/`:

| Agent | Language | Purpose |
|---|---|---|
| `chat_agent` | Python | LLM chat via API (reads `SNAPFZZ_SEAL_API_KEY`, `SNAPFZZ_SEAL_API_BASE`, `SNAPFZZ_SEAL_MODEL`) |
| `demo_agent` | Python | Simple demo for quick testing |
| `go_agent` | Go | Same LLM pattern as Python, static binary |

---

## Critical Invariants

1. **BUILD_ID must be consistent** across a single `cargo build` invocation. Different BUILD_IDs between core and launcher = assembly/launch failure.

2. **Fingerprint binding is strict.** Environment change between compile and launch = decryption failure. Must re-compile to rebind.

3. **Don't modify the launcher binary** between compile and launch. The integrity hash in the payload footer is checked against the launcher bytes before the sentinel.

4. **Launcher integrity uses bytes before sentinel.** At compile time, `derive_key_with_integrity_from_binary` is called on the raw launcher bytes *before* sentinel + payload are appended. At launch time, the same region is extracted by finding the last sentinel marker.

5. **fp_hmac_key must be derived identically** at compile and launch. Both use `HKDF(master_secret, None, "snapfzz-seal/fingerprint-hmac-key/v1")`.

6. **Shamir reconstruction requires >= 3 of 5 shares.** If fewer are found (corrupted binary), fallback to `SNAPFZZ_SEAL_MASTER_SECRET_HEX` env var.

7. **Ed25519 pubkey pinning is optional.** Set `SNAPFZZ_SEAL_ROOT_PUBKEY_HEX` at launcher compile time to pin. Without it, TOFU (trust on first use) applies.

8. **`seal verify` exit codes:** 0 = valid, 1 = operational error, 2 = invalid signature, 3 = unsigned binary.

9. **Nuitka onefile fails on macOS Homebrew.** Always use Docker/Linux for Nuitka builds.

10. **memfd_create requires Linux kernel 3.17+.** On failure, temp_exec fallback is automatic.

11. **All pipes use O_CLOEXEC.** This prevents fd leaks to forked children and avoids ETXTBSY races in temp_exec.

12. **White-box AES tables are embedded but not yet active for runtime decryption.** They exist for obfuscation; expect future integration.

---

## Quick Reference Commands

```bash
# Dev build
cargo build

# Release build
BUILD_ID=some-id cargo build --release

# Lint
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Test (unit tests, macOS OK)
cargo nextest run --workspace

# E2E tests (Docker required)
docker compose -f e2e-tests/docker-compose.yml up --build --abort-on-container-exit

# Full pipeline
USER_FP=$(openssl rand -hex 32)
seal keygen
seal compile --project ./examples/chat_agent --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto --output ./agent.sealed \
  --launcher ./target/release/seal-launcher --backend pyinstaller
seal sign --key ~/.snapfzz-seal/keys/builder_secret.key --binary ./agent.sealed
seal verify --binary ./agent.sealed
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

---

## Repository Layout

```
agent-seal/
  Cargo.toml                        # Workspace root
  Cargo.lock
  .github/workflows/ci.yml          # CI pipeline
  crates/
    snapfzz-seal/src/               # CLI: main.rs, compile.rs, sign.rs, verify.rs, launch.rs, keygen.rs, fingerprint.rs, server.rs
    snapfzz-seal-compiler/src/      # lib.rs, compile.rs, assemble.rs, embed.rs, decoys.rs, backend/{mod,pyinstaller,nuitka,golang}.rs
    snapfzz-seal-core/src/          # lib.rs, types.rs, error.rs, crypto.rs, derive.rs, shamir.rs, signing.rs, payload.rs, integrity.rs, secret.rs, tamper.rs, constants.rs + build.rs
    snapfzz-seal-launcher/src/      # main.rs, lib.rs, memfd_exec.rs, temp_exec.rs, seccomp.rs, anti_analysis.rs, anti_debug.rs, protection/{mod,linux,macos}.rs, cleanup/{mod,linux,macos}.rs, markers.rs, audit.rs + build.rs
    snapfzz-seal-fingerprint/src/   # lib.rs, model.rs, collect.rs, canonical.rs, detect.rs, error.rs
    snapfzz-seal-server/src/        # main.rs, lib.rs, routes.rs, auth.rs, state.rs, sandbox/{mod,docker}.rs
  examples/
    chat_agent/main.py
    demo_agent/main.py
    go_agent/{main.go, go.mod}
  e2e-tests/
    Dockerfile                      # Multi-stage Alpine build
    docker-compose.yml
    run_tests.sh
    full_interaction_test.sh
```
