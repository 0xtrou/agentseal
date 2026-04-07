# Agent Seal

![Build Status Badge Placeholder](./.github/badges/build-status.svg)
![Coverage Badge Placeholder](./.github/badges/coverage.svg)
![Release Badge Placeholder](./.github/badges/release.svg)

Agent Seal is an encrypted, sandbox-bound agent delivery system for Linux. It compiles agents into sealed payloads, binds decryption to runtime fingerprints, executes from memory, and avoids shipping API keys in delivered binaries.

## Architecture

```text
                              ┌─────────────────────────┐
                              │  agent-seal-server      │
                              │  orchestration API      │
                              └──────────┬──────────────┘
                                         │
                     ┌───────────────────┴───────────────────┐
                     │                                       │
         ┌───────────▼───────────┐               ┌──────────▼───────────┐
         │  agent-seal-compiler  │               │   agent-seal-proxy   │
         │  compile + seal       │               │   LLM access proxy   │
         └───────────┬───────────┘               └──────────┬───────────┘
                     │                                       │
                     └──────────────┬────────────────────────┘
                                    │
                         ┌──────────▼──────────┐
                         │   agent-seal-core   │
                         │ crypto + payloads   │
                         └──────────┬──────────┘
                                    │
                         ┌──────────▼───────────────┐
                         │ agent-seal-fingerprint   │
                         │ env identity collection  │
                         └──────────┬───────────────┘
                                    │
                         ┌──────────▼──────────┐
                         │ agent-seal-launcher │
                         │ decrypt + exec memfd│
                         └─────────────────────┘
```

## How It Works

1. **Compile**: `agent-seal-compiler` turns source projects into Linux executables.
2. **Encrypt**: the artifact is chunk-encrypted with AES-256-GCM and sealed with versioned payload metadata.
3. **Ship**: launcher + encrypted payload are distributed to target environments.
4. **Run**: launcher derives runtime keys from fingerprint input and attempts payload decrypt.
5. **Capture**: execution output is collected (stdout/stderr/exit code) for orchestration.
6. **Destroy**: runtime design aims to minimize residual plaintext footprint.

## Encryption Design

### Streaming encryption

- Algorithm: **AES-256-GCM**
- Mode: **chunked streaming payload format**
- Chunk size baseline: **64 KiB**
- Intent: avoid loading large binaries into memory as one plaintext block

### Dual HKDF derivation model

- `K_env = HKDF(master_secret, stable_fingerprint || user_fingerprint, "agent-seal/env/v1")`
- `K_session = HKDF(K_env, ephemeral_fingerprint, "agent-seal/session/v1")`

### Payload format (v1)

```text
┌──────────┬─────────┬─────────┬──────────┬────────────┬─────────────┐
│ magic    │ version │ enc_alg │ fmt_ver  │ chunk_count│ header_hmac │
│ ASL\x01  │ u16     │ u16     │ u16      │ u32        │ [u8; 32]    │
└──────────┴─────────┴─────────┴──────────┴────────────┴─────────────┘
┌──────────────────────────────────────────────────────────────────────┐
│ chunk records: [len:u32][ciphertext+tag] * N                        │
└──────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────┐
│ footer: original_hash[32] + launcher_hash[32]                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Sandbox Fingerprinting

Fingerprinting is split into:

- **Stable signals** (restart-survivable): machine identity, container/runtime identifiers, kernel/runtime context.
- **Ephemeral signals** (session-level): values expected to vary across short-lived sessions and namespaces.

Current target runtimes:

- Docker / OCI containers
- Firecracker microVM environments
- gVisor-style sandboxed Linux runtime contexts

## Threat Model

### Protected against

- Casual payload extraction from static binaries
- Running encrypted payload in an unrelated sandbox environment
- Direct exposure of provider API keys from shipped agent artifacts

### Not protected against

- **Root-level compromise** on host or sandbox
- Hardware-backed attestation bypass scenarios
- Full runtime memory extraction by privileged adversaries

In short: Agent Seal raises attacker cost and narrows abuse windows; it is not a replacement for host trust or attestation systems.

## Crate Overview

| Crate | Type | Role |
|---|---|---|
| `agent-seal-core` | lib | Shared types, crypto boundaries, payload metadata, derivation primitives |
| `agent-seal-fingerprint` | lib | Fingerprint collection, canonicalization, mismatch detection |
| `agent-seal-launcher` | bin | Runtime launcher entrypoint for decrypt + execution flow |
| `agent-seal-compiler` | lib + bin | Build/seal pipeline, backend adapters (`nuitka`, `pyinstaller`) |
| `agent-seal-proxy` | lib + bin | LLM provider proxy, auth/rate-limit/routing surface |
| `agent-seal-server` | bin | Orchestration API that composes compiler + proxy services |

## Quick Start

### Prerequisites

- Rust toolchain (stable, edition 2024)
- `clippy` and `rustfmt` components
- Linux musl linker support (`x86_64-linux-musl-gcc` / `musl-tools`)
- Optional for CI parity: `cargo-nextest`, `cargo-llvm-cov`

### Build

```bash
cargo build --workspace
```

### Demo stubs

```bash
cargo run -p agent-seal-launcher -- --payload ./sealed.bin --fingerprint-mode stable
cargo run -p agent-seal-compiler -- --project ./agent --user-fingerprint u1 --sandbox-fingerprint s1 --output ./out --backend nuitka
cargo run -p agent-seal-proxy
cargo run -p agent-seal-server
```

All current binaries return a `not implemented` stub response while interfaces stabilize.

## Configuration

### Environment variables

- `RUST_LOG`: tracing level/filter for all binaries
- `AGENT_SEAL_MASTER_SECRET_HEX`: intended master secret injection point (future)
- `AGENT_SEAL_PROXY_BASE_URL`: server→proxy routing base URL (future)
- `AGENT_SEAL_RATE_LIMIT_RPS`: proxy rate limiter configuration (future)

### CLI flags

`agent-seal-launcher`:

- `--payload <PATH>`
- `--fingerprint-mode <stable|session>`
- `--user-fingerprint <STRING>`

`agent-seal-compiler`:

- `--project <PATH>`
- `--user-fingerprint <STRING>`
- `--sandbox-fingerprint <STRING>`
- `--output <PATH>`
- `--backend <nuitka|pyinstaller>`

`agent-seal-proxy` / `agent-seal-server`:

- Stub entrypoints today; argument surface will be added with routing/auth/runtime config as implementation lands.

## Development

### Format and lint

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

### Tests and coverage

```bash
cargo nextest run --workspace
cargo llvm-cov nextest --workspace --lcov --output-path lcov.info --fail-under-lines 85
```

### CI summary

CI runs on pushes to `main` and pull requests:

- `fmt` (check mode)
- `clippy` (workspace)
- `nextest` + `llvm-cov` (85% minimum)
- release workspace build

## License

MIT
