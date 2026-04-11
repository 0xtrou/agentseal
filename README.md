# Snapfzz Seal

![Build](docs/badges/build-status.svg)
![Coverage](docs/badges/coverage.svg)
![Rust](docs/badges/rust-version.svg)

**Encrypted, sandbox-bound agent delivery system.**

[Full Documentation](https://0xtrou.github.io/snapfzz-seal/) | [GitHub](https://github.com/0xtrou/snapfzz-seal)

---

## Overview

Snapfzz Seal (`agent-seal`) is a Rust workspace that compiles AI agent binaries into self-contained, encrypted payloads bound to a specific execution environment. The sealed binary carries its own launcher; at runtime the launcher reconstructs the master secret from embedded Shamir shares, derives a decryption key from the environment fingerprint and user identity, decrypts the agent payload, and executes it.

Execution is filesystem-resident in all current configurations. On Linux, Go-backend payloads are executed via `memfd_create`/`fexecve` (anonymous memory, no filesystem path). PyInstaller- and Nuitka-backend payloads are executed via a temporary file on all platforms. Both execution paths are only fully operational on Linux; macOS support is limited to the compile, sign, and verify operations.

The primary use-case is protecting secrets and agent logic from trivial static extraction while keeping the operational model simple: compile once, ship a single binary, execute in the target sandbox.

---

## Architecture

The workspace contains six crates:

| Crate | Role |
|---|---|
| `snapfzz-seal` | CLI entry point (`seal` binary) — subcommands: `compile`, `keygen`, `launch`, `server`, `sign`, `verify` |
| `snapfzz-seal-compiler` | Drives backend build tools and assembles the sealed binary |
| `snapfzz-seal-core` | Cryptographic primitives, payload format, Shamir secret sharing, signing |
| `snapfzz-seal-launcher` | Self-contained launcher binary (`seal-launcher`), embedded into the sealed output |
| `snapfzz-seal-fingerprint` | Environment fingerprint collection and canonicalization |
| `snapfzz-seal-server` | Optional HTTP orchestration API (Axum) |

### Assembly pipeline

```
agent source
    |
    v
[backend: nuitka | pyinstaller | go]
    |
    v  compiled agent binary
[assemble]
    |-- reads seal-launcher ELF
    |-- embeds master secret into 5 marker-delimited share slots
    |-- embeds tamper hash (SHA-256 of launcher after secret embedding)
    |-- embeds white-box AES lookup tables (derived from master secret)
    |-- embeds 50 decoy marker slots (10 sets of 5)
    |-- derives env_key = HKDF(master_secret, stable_fingerprint || user_fingerprint)
    |-- derives integrity_key = HKDF(env_key, launcher_bytes)
    |-- AES-256-GCM encrypts agent in 64 KB chunks (ASL\x01 payload format)
    |-- appends payload footer (original_hash, launcher_hash, backend_type, 65 bytes)
    v
sealed binary  (launcher_elf || payload_sentinel(32) || encrypted_payload || footer(65))
    |
[seal sign]
    |-- appends ASL\x02 signature block (4-byte magic || 64-byte Ed25519 sig || 32-byte pubkey)
    v
signed sealed binary
```

Note: decoy markers are embedded as zero-filled slots using a master seed value of `0` in the current implementation. The 50 decoy slots are structurally identical to the live share slots in the binary layout.

### Binary layout

```
[ launcher ELF with embedded secrets and white-box tables ]
[ PAYLOAD_SENTINEL (32 bytes, BUILD_ID-derived) ]
[ encrypted payload: ASL\x01 header | AES-256-GCM chunks (64 KB each) ]
[ footer (65 bytes: original_hash[32] || launcher_hash[32] || backend_type[1]) ]
[ signature block (4-byte ASL\x02 || 64-byte Ed25519 sig || 32-byte pubkey) ]  ← appended by seal sign
```

---

## Security Model

Snapfzz Seal applies several complementary protections. Each is described with its actual implementation status.

### 1. Marker obfuscation (fully implemented)

All markers embedded in the launcher binary — secret share slots, tamper marker, payload sentinel — are derived deterministically from `BUILD_ID` via SHA-256:

```
marker[i] = SHA-256(BUILD_ID || label_i || "deterministic_marker_v1")
```

Both `snapfzz-seal-core` (used by the `seal` CLI) and `snapfzz-seal-launcher` run independent `build.rs` scripts that derive the same set of markers from `BUILD_ID` at compile time using the identical derivation function. **If the two crates are compiled with different `BUILD_ID` values, the markers embedded by the compiler will not match the marker slots in the launcher binary.** The assembler will fail to locate the share slots and report an embedding error. See [Build](#build) for the required procedure.

### 2. Shamir secret sharing (fully implemented)

The master secret is split into **5 shares** with a **threshold of 3** (constants `SHAMIR_TOTAL_SHARES = 5`, `SHAMIR_THRESHOLD = 3` in `snapfzz-seal-core/src/types.rs`). The shares are written into the launcher binary at five marker-delimited 32-byte slots. At runtime, the launcher scans its own bytes for at least 3 valid shares and reconstructs the master secret. If fewer than 3 shares are found, the launcher falls back to reading the `SNAPFZZ_SEAL_MASTER_SECRET_HEX` environment variable, and fails if that is also absent.

### 3. Decoy markers (fully implemented)

50 additional 32-byte decoy marker slots (10 sets of 5) are embedded in the launcher. They are structurally identical to the live share slots, raising the cost of identifying the live shares through static analysis. In the current implementation the decoys are generated with a seed of `0` rather than the master secret; their purpose is binary layout obfuscation, not cryptographic blinding.

### 4. Anti-analysis and anti-debug (Linux-only)

- `prctl(PR_SET_DUMPABLE, 0)` — prevents core dumps and `/proc/<pid>/mem` access.
- `ptrace(PTRACE_TRACEME)` — makes the process harder to attach a debugger to.
- `anti_analysis::is_being_analyzed()` — heuristic environment checks; if triggered the launcher aborts before decryption.
- `anti_analysis::poison_environment()` — called after fingerprint collection to clear sensitive variables from the process environment before exec.

On non-Linux platforms these protections compile to no-ops.

### 5. Binary integrity binding (Linux check; key derivation on all platforms)

A SHA-256 integrity hash of the launcher is computed at assemble time and recorded in the payload footer. At runtime on Linux, the launcher recomputes this hash and aborts if it does not match, detecting post-assembly binary tampering. On non-Linux platforms the verification step is skipped, but the integrity hash still participates in key derivation (the key is always bound to the launcher bytes via `derive_key_with_integrity_from_binary`).

The decryption key derivation chain is:

```
env_key          = HKDF(master_secret, stable_fingerprint || user_fingerprint)
integrity_key    = HKDF(env_key, launcher_bytes)            -- key bound to launcher byte content
session_key      = HKDF(integrity_key, ephemeral_hash)      -- only in --fingerprint-mode session
```

### 6. White-box AES tables (tables embedded; runtime integration partial)

At assemble time, white-box AES lookup tables (~165 KB) derived from the master secret are generated and embedded in the launcher binary. The tables are present in the binary and contribute to obfuscation of the master secret, but active runtime white-box decryption is not yet integrated into the key reconstruction path. The tables serve as an additional layer of obfuscation against static extraction of the master secret.

### Signing (fully implemented)

Payloads are signed with Ed25519. `seal sign` appends a 100-byte block (`ASL\x02` || 64-byte Ed25519 signature || 32-byte public key) to the sealed binary. The launcher verifies this block at startup and refuses to execute an unsigned or signature-invalid payload.

`seal verify` validates the signature using either the public key embedded in the binary (TOFU mode, no `--pubkey` flag) or an explicit pinned public key file (`--pubkey <path>`).

### Platform scope

| Protection | Linux x86_64 | macOS arm64 | Other |
|---|---|---|---|
| Payload encryption / decryption | Yes | Yes | Yes |
| Shamir secret reconstruction | Yes | Yes | Yes |
| Ed25519 signing / verification | Yes | Yes | Yes |
| memfd / fexecve execution (Go backend) | Yes | No | No |
| Temp-file execution (PyInstaller / Nuitka) | Yes | Not tested | No |
| Binary integrity verification | Yes | Skipped (warning) | Skipped (warning) |
| seccomp syscall filter | Yes | No-op | No-op |
| Anti-debug (prctl, ptrace) | Yes | No-op | No-op |

---

## Backends

Three compilation backends are supported. Each converts the agent source into a single self-contained binary before encryption and assembly. All three backends always target Linux (`GOOS=linux` for Go; PyInstaller and Nuitka produce Linux ELF binaries when run on Linux). Building for and executing on non-Linux targets is not supported by the backend implementations.

| Backend | `--backend` value | Project detection | Compile timeout | Execution path | Notes |
|---|---|---|---|---|---|
| Nuitka | `nuitka` (default) | `main.py` present | 1800 s (30 min) | TempFileExecutor | Requires `nuitka` or `python3 -m nuitka` on PATH. On macOS via Homebrew, onefile mode fails due to dynamic library embedding incompatibilities; use Docker or a Linux host for Nuitka builds. |
| PyInstaller | `pyinstaller` | `main.py` or `setup.py` present | configurable | TempFileExecutor | Requires `pyinstaller` on PATH. |
| Go | `go` | `go.mod` present | 600 s (10 min) | MemfdExecutor (Linux) | Requires `go` on PATH. Builds with `CGO_ENABLED=0 GOOS=linux`. Respects `GOARCH` env var; defaults to `amd64` or `arm64` based on host architecture. |

---

## Build

### Prerequisites

- Rust toolchain (stable, edition 2021 or later)
- Backend tooling as required: `nuitka` or `pyinstaller` for Python agents, `go` for Go agents

### Critical: BUILD_ID must match across crates

`snapfzz-seal-core` and `snapfzz-seal-launcher` each contain a `build.rs` that derives the binary marker values from the `BUILD_ID` environment variable. The `seal` CLI uses the markers computed by `snapfzz-seal-core` when embedding share data into the launcher binary; the launcher uses the markers compiled into `snapfzz-seal-launcher` to locate those shares at runtime. If the two crates are compiled with different `BUILD_ID` values, the markers will not match and the assembled binary will be non-functional.

**Always build all crates in a single `cargo build` invocation with the same `BUILD_ID`:**

```bash
export BUILD_ID="$(openssl rand -hex 16)"  # stable identifier for this release
BUILD_ID="$BUILD_ID" cargo build --release
```

Do not build `snapfzz-seal` and `snapfzz-seal-launcher` separately with different `BUILD_ID` values, and do not mix release artifacts from builds with different `BUILD_ID` values.

If `BUILD_ID` is not set, it defaults to `"dev"` in both build scripts. This is acceptable for local development as long as all crates are built together in the same `cargo build` invocation.

### Install the `seal` CLI

```bash
BUILD_ID="$BUILD_ID" cargo install --path crates/snapfzz-seal
```

The `seal-launcher` binary is produced as part of the workspace build and is located at `./target/release/seal-launcher`. It must be provided to `seal compile` via `--launcher` or the `SNAPFZZ_SEAL_LAUNCHER_PATH` environment variable.

---

## Usage

### 1. Generate signing keys

```bash
# Keys written to ~/.snapfzz-seal/keys/builder_secret.key and builder_public.key
seal keygen

# Optionally specify a different directory
seal keygen --keys-dir ./my-keys
```

### 2. Compile and seal

```bash
USER_FP=$(openssl rand -hex 32)

seal compile \
  --project ./examples/chat_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/release/seal-launcher \
  --backend pyinstaller
```

`--sandbox-fingerprint auto` collects the current host's stable fingerprint at compile time and binds the payload to it. Pass a 64-character hex string to bind to a pre-known fingerprint instead.

`--launcher` is required unless `SNAPFZZ_SEAL_LAUNCHER_PATH` is set in the environment.

Available backends: `nuitka` (default), `pyinstaller`, `go`.

Available modes: `--mode batch` (default), `--mode interactive`.

### 3. Sign

```bash
seal sign \
  --key ~/.snapfzz-seal/keys/builder_secret.key \
  --binary ./agent.sealed
```

The signature block is appended in place to the binary. The public key is inferred from the same directory as `--key` (file `builder_public.key`).

### 4. Verify signature

```bash
# TOFU: use the public key embedded in the binary (no pinning)
seal verify --binary ./agent.sealed

# Pinned: verify against an explicit public key file
seal verify --binary ./agent.sealed --pubkey ~/.snapfzz-seal/keys/builder_public.key
```

Note: `seal verify` returns exit code 0 and prints `WARNING: unsigned` when the binary has no signature block. It does not error on unsigned binaries; the launcher does.

### 5. Launch

```bash
seal launch \
  --payload ./agent.sealed \
  --user-fingerprint "$USER_FP"
```

Optional launch flags:

| Flag | Default | Description |
|---|---|---|
| `--fingerprint-mode` | `stable` | `stable`: bind to persistent environment properties. `session`: additionally bind to ephemeral properties. |
| `--mode` | `batch` | `batch` or `interactive` |
| `--verbose` | false | Enable debug logging |
| `--max-lifetime` | none | Maximum agent runtime in seconds (enforced by the `seal launch` wrapper; not forwarded to the launcher binary itself in the current implementation) |
| `--grace-period` | 30 | Grace period in seconds after `--max-lifetime` before SIGKILL |

When `--payload` is omitted, the launcher reads its own executable from `/proc/self/exe` (Linux only). This is the path taken when running a sealed binary directly.

If fewer than 3 embedded Shamir shares are found, the launcher falls back to reading `SNAPFZZ_SEAL_MASTER_SECRET_HEX` from the environment.

### 6. Orchestration server (optional)

```bash
seal server \
  --bind 0.0.0.0:9090 \
  --compile-dir ./.snapfzz-seal/compile \
  --output-dir ./.snapfzz-seal/output
```

---

## Testing

Run the unit and integration test suite:

```bash
cargo test
```

Run the end-to-end smoke test (requires the relevant backend tooling):

```bash
# Default backend: pyinstaller
./e2e-tests/quick_test.sh

# Specify backend
./e2e-tests/quick_test.sh go
./e2e-tests/quick_test.sh nuitka
```

The quick E2E test builds all crates with a consistent `BUILD_ID`, generates keys, compiles with the chosen backend, signs, and verifies the output. It does not execute the sealed binary. `BUILD_ID` defaults to `local-test-<unix-timestamp>` if not set.

The full interaction test (`./e2e-tests/full_interaction_test.sh`) additionally launches the sealed binary and captures agent output. It is designed to run inside Docker on Linux for `memfd_exec` support. On macOS, the Nuitka backend is automatically skipped with an explanatory message.

---

## Payload Format Reference

| Field | Value |
|---|---|
| Magic | `ASL\x01` (4 bytes) |
| Version | `0x0001` |
| Encryption algorithm | AES-256-GCM (`0x0001`) |
| Format | Chunked streaming (`0x0001`) |
| Chunk size | 65536 bytes (64 KB) |
| KDF info (env key) | `snapfzz-seal/env/v1` |
| KDF info (session key) | `snapfzz-seal/session/v1` |
| Footer size | 65 bytes: `original_hash[32] || launcher_hash[32] || backend_type[1]` |
| Signature magic | `ASL\x02` (4 bytes, appended by `seal sign`) |
| Signature block size | 100 bytes: `ASL\x02[4] || Ed25519_sig[64] || pubkey[32]` |
| Shamir shares | 5 total, threshold 3 |

---

## Known Limitations

Snapfzz Seal raises the cost of extracting secrets and agent logic but does not eliminate that cost. It is not a substitute for host-level access control, hardware attestation, or a secure key distribution infrastructure.

- **Linux-only execution.** The `seal-launcher` binary executes payloads only on Linux. `memfd_create`/`fexecve` is Linux-specific. The `TempFileExecutor` path uses POSIX `fork`/`fexecve` and has not been tested on macOS or other platforms.
- **No Windows support.** The launcher makes no provision for Windows execution.
- **Nuitka on macOS.** Building with the Nuitka backend on macOS fails in onefile mode due to Homebrew dynamic library embedding; use Docker or a Linux host.
- **White-box AES integration is partial.** The tables are embedded and occupy space in the binary, contributing to obfuscation, but active white-box decryption is not yet used in the runtime key reconstruction path.
- **Anti-debug and binary integrity checks are Linux-only.** An attacker executing the sealed binary on macOS or another platform will bypass those checks.
- **Decoy seed is fixed.** The 50 decoy marker slots are generated with a seed of `0` rather than the master secret, which reduces their cryptographic strength as blinding values, though they still contribute to structural obfuscation.
- **Self-delete is heuristic.** The launcher attempts to delete itself when running from an embedded payload, but this is not guaranteed under all operating system conditions.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
