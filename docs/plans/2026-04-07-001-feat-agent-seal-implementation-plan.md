---
title: "feat: Agent Seal — Encrypted Sandbox-Bound Agent Delivery System"
type: feat
status: active
date: 2026-04-07
origin: handoff (design session — 2026-04-07)
---

# Agent Seal Implementation Plan

## Overview

Build a Rust service that compiles AI agents (AgentScope, LangChain, etc.) into encrypted standalone binaries bound to specific sandbox environments via fingerprint-derived keys. The system uses memfd + fexecve for diskless execution, AES-256-GCM streaming encryption, and a dual-layer HKDF key derivation scheme. API keys never enter the binary — agents call a proxy server for LLM access.

## Problem Frame

Organizations need to run AI agents in isolated sandboxes (Docker, Firecracker, gVisor) without:
- Exposing API keys in the binary or environment
- Risking the agent binary being executed outside its intended sandbox
- Leaving plaintext executables on disk

Agent Seal solves this by encrypting the compiled agent binary with a key derived from the sandbox's fingerprint + a master secret. The launcher decrypts directly into kernel memory (memfd) and executes via fexecve — zero disk footprint.

## Requirements Trace

- R1. Agents compile to standalone encrypted ELF binaries
- R2. Binaries only decrypt in their intended sandbox (fingerprint binding)
- R3. No plaintext on disk at any point (memfd execution)
- R4. API keys never embedded in binary (LLM proxy architecture)
- R5. Self-delete after execution (anti-residue)
- R6. Anti-debugging measures (PR_SET_DUMPABLE, PTRACE_TRACEME)
- R7. Payload versioning for forward compatibility
- R8. Clear error on fingerprint mismatch (not opaque AES failure)
- R9. 85%+ test coverage (CI enforced via cargo-llvm-cov + nextest)
- R10. CI-generated badges (codecov, build status) — no external badge providers

## Scope Boundaries

- **Non-goal**: Support non-Linux targets (Linux-only by design — memfd_create + fexecve)
- **Non-goal**: Protection against root on the host machine (fundamentally impossible)
- **Non-goal**: Obfuscation beyond low-cost measures (XOR, ptrace, dumpable flag)
- **Non-goal**: GUI or web dashboard for the server/proxy
- **Non-goal**: Multi-tenant isolation (single-organization use)
- **Non-goal**: Runtime >= musl for non-launcher crates

## Context & Research

### Relevant Code and Patterns

- Empty repo — no existing code patterns to follow
- Reference implementations studied: nearai/inference-proxy (axum streaming proxy), linkerd2-proxy (workspace CI), quickwit (llvm-cov+nextest coverage), spinframework/spin (release matrix)

### Institutional Learnings

- None (new project)

### External References

- RustCrypto AEADs: aes-gcm + aead-stream for chunked encryption of 50-500MB binaries
- HKDF RFC 5869: dual-layer derivation pattern validated (chaining HKDF outputs as new IKM)
- lucab/memfd-rs v0.6.5 (28.5M downloads): memfd creation with sealing support
- novafacing/memfd-exec: rejected for production (ExitStatus bug #23, no sealing, no chunked writes)
- Docker container ID derivation: `/proc/self/cgroup` parsing with heuristic regex
- systemd machine-id: "must be hashed with a cryptographic keyed hash function" (man machine-id)
- Firecracker boot_args: explicit guest-visible identity signal via `/proc/cmdline`
- axum reverse-proxy streaming: `bytes_stream` + `Body::from_stream` with line-buffered SSE parsing

## Key Technical Decisions

- **Master secret via embedded random key** (NOT self-hash): A random 256-bit key generated at compile time by agent-seal-compiler and embedded via `include_bytes!`. Self-hash (SHA-256 of own ELF) is used only as tamper detection, not as the root secret. Rationale: Self-hash breaks on every recompilation/strip, making operational updates impossible. Oracle validated this.
- **Custom memfd executor on `memfd` crate**: Build internal executor using lucab/memfd-rs for memfd creation + sealing, then direct fexecve via nix crate. Rejected memfd-exec (bugs, no sealing, no chunked writes). Gives us chunked decrypt→write, SealWrite+SealSeal, controlled flags.
- **Streaming encryption via aead-stream**: EncryptorBE32/DecryptorBE32 with 64KB chunks. Max payload ~64GB. Pure Rust with AES-NI acceleration. Avoids holding 500MB in memory.
- **Launcher as musl static binary**: `x86_64-unknown-linux-musl` target. Runs on arbitrary sandboxes with zero runtime deps. All other crates use default glibc target.
- **Compiler does NOT Cargo-depend on launcher**: The compiler reads the launcher binary from a known path/env var (build-time dependency, not Cargo dependency). Avoids circular build complexity and keeps cross-compilation clean (compiler=glibc, launcher=musl).
- **Fork+wait for result capture**: Launcher forks before fexecve, parent waits and captures child stdout/stderr + exit code. Simplest approach that doesn't require modifying the agent.
- **85% coverage gate** (not 90%): 90% is achievable but 85% is the CI gate. Expect 95% on crypto logic, 70-80% on syscall code, with integration tests closing the gap. Use cargo-llvm-cov + nextest (faster and more accurate than tarpaulin on async code).
- **Dual-layer fingerprint KDF**: K_env = HKDF(master, "agent-seal/env/v1", stable_hash || user_fp) for restart-survivable binding; K_session = HKDF(K_env, "agent-seal/session/v1", ephemeral_hash) for single-use session binding.
- **Self-delete before fexecve**: Call unlink on `/proc/self/exe` before fexecve (after exec, `/proc/self/exe` points to memfd). Gracefully skip on read-only overlayfs.
- **Anti-extraction**: prctl(PR_SET_DUMPABLE, 0) + PTRACE_TRACEME + memfd sealing + XOR key obfuscation. Accepted as raising the bar, not providing real security against determined attackers.

## Open Questions

### Resolved During Planning

- **Master secret source**: Embedded random key (not self-hash). Self-hash used for tamper detection only.
- **memfd-exec vs custom**: Custom executor on memfd crate.
- **Coverage target**: 85% gate, 90% target.
- **Static vs dynamic launcher**: musl static.
- **Result capture mechanism**: Fork+wait (parent captures child stdout/stderr/exit_code).

### Deferred to Implementation

- **Nuitka vs PyInstaller selection**: Will evaluate during compiler crate implementation. Both have programmatic APIs invokable via std::process::Command. Nuitka preferred for smaller binaries and better startup time, but needs validation with real AgentScope projects.
- **Specific payload format**: Binary layout defined here at wire level; Rust struct definitions deferred.
- **Async job queue for compiler**: tokio::spawn with bounded concurrency for MVP; proper job queue later if needed.

## High-Level Technical Design

```
                         ┌─────────────────┐
                         │  agent-seal-    │
                         │    server       │
                         │  (orchestration)│
                         └────────┬────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼              ▼
          ┌──────────────┐ ┌──────────┐ ┌──────────────┐
          │ agent-seal-  │ │ agent-   │ │ agent-seal-  │
          │   compiler   │ │ seal-    │ │    proxy     │
          │ (Python→ELF  │ │  server  │ │ (LLM API     │
          │  + encrypt)  │ │ (infra)  │ │  routing)    │
          └──────┬───────┘ └──────────┘ └──────┬───────┘
                 │                                │
                 ▼                                │
    ┌──────────────────────┐                     │
    │   Shipped Binary     │◄────────────────────┘
    │ ┌──────────────────┐ │        (LLM calls)
    │ │  launcher stub   │ │
    │ ├──────────────────┤ │
    │ │  encrypted agent │ │
    │ │  (AES-256-GCM    │ │
    │ │   streaming)     │ │
    │ └──────────────────┘ │
    └──────────────────────┘
                 │
    ┌────────────▼───────────┐
    │  agent-seal-core       │
    │  ┌──────────────────┐  │
    │  │ master_secret    │  │
    │  │ HKDF derive      │  │
    │  │ AES-256-GCM      │  │
    │  │ payload pack     │  │
    │  └──────────────────┘  │
    └────────────────────────┘
                 │
    ┌────────────▼───────────┐
    │ agent-seal-fingerprint │
    │  ┌──────────────────┐  │
    │  │ stable (machine- │  │
    │  │   id, hostname,  │  │
    │  │   cgroup, kernel)│  │
    │  ├──────────────────┤  │
    │  │ ephemeral (ns    │  │
    │  │   inodes)        │  │
    │  └──────────────────┘  │
    └────────────────────────┘
```

> *This illustrates the intended approach and is directional guidance for review, not implementation specification.*

### Payload Format (v1)

```
┌──────────────┬────────┬──────────┬──────────┬───────────────┬─────────────┐
│ MAGIC (4B)   │ VERS   │ ENC_ALG  │ FMT_VER  │ CHUNK_COUNT   │ HEADER_HMAC │
│ "ASL\x01"    │ 0x0001 │ 0x0001   │ 0x0001   │ u32           │ (32B)       │
│              │        │ AES-GCM  │ STREAM   │               │             │
├──────────────┴────────┴──────────┴──────────┴───────────────┴─────────────┤
│ STREAM HEADER (7B): nonce + reserved                                                      │
├──────────────────────────────────────────────────────────────────────────┤
│ CHUNK 0: len(4B) || ciphertext(var) || tag(16B)                                │
│ CHUNK 1: len(4B) || ciphertext(var) || tag(16B)                                │
│ ...                                                                                     │
│ CHUNK N: len(4B) || ciphertext(var) || tag(16B) [final chunk flag set]               │
├──────────────────────────────────────────────────────────────────────────┤
│ FOOTER: original binary SHA-256 (32B) + launcher binary SHA-256 (32B)              │
└──────────────────────────────────────────────────────────────────────────┘
```

### Key Derivation Flow

```
master_secret (256-bit, embedded at compile time)
    │
    ├─► SHA-256(own ELF) → tamper_check_hash (compared at runtime)
    │
    ├─► HKDF-SHA256(
    │       IKM = stable_fingerprint_hash || user_fingerprint,
    │       salt = master_secret,
    │       info = "agent-seal/env/v1"
    │   ) → K_env (256-bit encryption key)
    │
    └─► HKDF-SHA256(
            IKM = ephemeral_fingerprint_hash,
            salt = K_env,
            info = "agent-seal/session/v1"
        ) → K_session (discarded — K_env is the actual encryption key)

Note: K_session is available for optional single-use binding. MVP uses K_env only.
```

## Implementation Units

### Phase 0: Foundation (Day 1-2)

- [ ] **Unit 1: Workspace scaffolding + README**

**Goal:** Set up Cargo workspace with all 6 crate stubs, shared dependencies, CI pipeline, and comprehensive README.

**Requirements:** R9, R10

**Dependencies:** None

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/core/Cargo.toml`, `crates/core/src/lib.rs`
- Create: `crates/launcher/Cargo.toml`, `crates/launcher/src/main.rs`
- Create: `crates/fingerprint/Cargo.toml`, `crates/fingerprint/src/lib.rs`
- Create: `crates/compiler/Cargo.toml`, `crates/compiler/src/main.rs`
- Create: `crates/proxy/Cargo.toml`, `crates/proxy/src/main.rs`
- Create: `crates/server/Cargo.toml`, `crates/server/src/main.rs`
- Create: `.github/workflows/ci.yml`
- Create: `.cargo/config.toml` (musl target for launcher)
- Create: `README.md`
- Create: `clippy.toml`, `rustfmt.toml`

**Approach:**
- Virtual workspace root with resolver 3, workspace.dependencies for all shared deps
- default-members: core, fingerprint, launcher, server (exclude slow crates from dev loop)
- `[target.x86_64-unknown-linux-musl]` linker config for launcher only
- Workspace-level lints: deny(unsafe_code) for all crates except launcher (which needs unsafe for syscalls)
- README with: architecture diagram (ASCII), encryption design, sandbox fingerprinting, threat model, usage guide, crate overview
- CI: lint → check → test (nextest) → coverage (llvm-cov, 85% gate) → CI-generated badges
- No external badge providers (no shields.io)

**Test scenarios:**
- Test expectation: none -- scaffolding unit, no behavioral code

**Verification:**
- `cargo build --workspace` succeeds
- `cargo nextest run --workspace` passes (empty tests)
- `cargo clippy --workspace` clean
- `cargo fmt --check --workspace` clean
- CI workflow file is valid YAML with correct trigger paths

---

- [ ] **Unit 2: Shared types and error infrastructure**

**Goal:** Define payload format types, error enums, and shared constants used across all crates.

**Requirements:** R7 (payload versioning)

**Dependencies:** Unit 1

**Files:**
- Create: `crates/core/src/error.rs`
- Create: `crates/core/src/types.rs`
- Create: `crates/core/src/constants.rs`
- Modify: `crates/core/src/lib.rs`
- Test: `crates/core/src/types.rs` (inline tests)

**Approach:**
- `types.rs`: PayloadHeader (magic, version, enc_alg, chunk_count), ChunkRecord, PayloadFooter, FingerprintSnapshot
- `error.rs`: SealError enum with variants for crypto, fingerprint, io, payload format, with thiserror
- `constants.rs`: MAGIC_BYTES, VERSION_V1, ENC_ALG_AES256_GCM, CHUNK_SIZE (64KB), KDF_INFO_ENV, KDF_INFO_SESSION
- All types implement Serialize/Deserialize for wire format, Debug for logging
- PayloadHeader includes 4-byte magic "ASL\x01" + 2-byte version for forward compatibility

**Test scenarios:**
- Happy path: PayloadHeader serializes/deserializes round-trip
- Edge case: Deserializing v0 payload with v1 parser returns clear version mismatch error
- Error path: Invalid magic bytes → SealError::InvalidPayload

**Verification:**
- `cargo test -p agent-seal-core` passes
- `cargo clippy -p agent-seal-core` clean

---

### Phase 1: Core Crypto (Day 2-4)

- [ ] **Unit 3: Master secret generation and tamper detection**

**Goal:** Generate random master secrets for embedding, and detect binary tampering at runtime via self-hash comparison.

**Requirements:** R1

**Dependencies:** Unit 2

**Files:**
- Create: `crates/core/src/secret.rs`
- Create: `crates/core/src/tamper.rs`
- Test: `crates/core/src/secret.rs`, `crates/core/src/tamper.rs`

**Approach:**
- `secret.rs`: `generate_master_secret() -> [u8; 32]` using OsRng. `MasterSecret` newtype wrapping [u8; 32] with Zeroize drop.
- `tamper.rs`: `compute_binary_hash() -> [u8; 32]` reads `/proc/self/exe`, SHA-256 hashes it. `verify_tamper(expected_hash: &[u8]) -> Result<()>` compares and aborts on mismatch.
- MasterSecret implements Debug (redacted), Clone, ZeroizeOnDrop
- Separate from crypto encrypt/decrypt — this is identity, not encryption

**Test scenarios:**
- Happy path: generate_master_secret returns 32 bytes, different on each call
- Happy path: verify_tamper with matching hash succeeds
- Error path: verify_tamper with wrong hash returns SealError::TamperDetected
- Edge case: /proc/self/exe not readable → SealError::Io

**Verification:**
- All tests pass
- secret bytes don't appear in Debug output

---

- [ ] **Unit 4: AES-256-GCM streaming encrypt/decrypt**

**Goal:** Implement chunked encryption and decryption for large binaries (50-500MB) using aes-gcm + aead-stream.

**Requirements:** R1, R3

**Dependencies:** Unit 2, Unit 3

**Files:**
- Create: `crates/core/src/crypto.rs`
- Create: `crates/core/src/payload.rs`
- Test: `crates/core/src/crypto.rs`, `crates/core/src/payload.rs`

**Approach:**
- `crypto.rs`: `encrypt_stream(reader, writer, key, nonce) -> Result<PackResult>` and `decrypt_stream(reader, writer, key) -> Result<UnpackResult>` using EncryptorBE32/DecryptorBE32 with 64KB chunks
- Nonce generation: 12-byte random nonce via OsRng
- Key zeroization after use
- `payload.rs`: `pack(plaintext_reader, key) -> Result<Vec<u8>>` assembles full payload (header + stream header + encrypted chunks + footer). `unpack(payload_reader, key) -> Result<Vec<u8>>` reverses.
- Footer contains SHA-256 of original binary for integrity verification
- Uses aead-stream's `EncryptorBE32<Aes256Gcm>` and `DecryptorBE32<Aes256Gcm>`

**Test scenarios:**
- Happy path: encrypt then decrypt round-trip produces identical bytes (1KB, 1MB, 100MB)
- Happy path: Known-answer test vectors for AES-256-GCM
- Edge case: Empty input encrypts/decrypts to empty
- Edge case: Exact chunk boundary size (64KB * N)
- Error path: Wrong key → SealError::DecryptionFailed with clear message (not raw AES error)
- Error path: Truncated payload → SealError::InvalidPayload
- Error path: Modified ciphertext → SealError::DecryptionFailed

**Verification:**
- Round-trip property tests with proptest (random sizes 0..10MB)
- 95%+ coverage on crypto module

---

- [ ] **Unit 5: HKDF key derivation**

**Goal:** Implement dual-layer key derivation from master secret + fingerprints.

**Requirements:** R2

**Dependencies:** Unit 2

**Files:**
- Create: `crates/core/src/derive.rs`
- Test: `crates/core/src/derive.rs`

**Approach:**
- `derive_env_key(master_secret, stable_hash, user_fingerprint) -> [u8; 32]`: HKDF-SHA256 extract+expand, salt=master_secret, info="agent-seal/env/v1", IKM=stable_hash||user_fingerprint
- `derive_session_key(env_key, ephemeral_hash) -> [u8; 32]`: HKDF-SHA256 extract+expand, salt=env_key, info="agent-seal/session/v1", IKM=ephemeral_hash
- Input validation: all inputs must be exactly 32 bytes (pre-hashed by caller)
- Output zeroized via ZeroizeOnDrop wrapper

**Test scenarios:**
- Happy path: Same inputs produce same output (deterministic)
- Happy path: Different user_fingerprint produces different key
- Happy path: Different stable_hash produces different key
- Edge case: RFC 5869 HKDF-SHA256 test vector Appendix A
- Error path: Wrong-length input → SealError::InvalidInput

**Verification:**
- RFC 5869 test vectors pass
- 95%+ coverage on derive module

---

### Phase 2: Fingerprint + Launcher (Day 4-7)

- [ ] **Unit 6: Sandbox fingerprint collector**

**Goal:** Collect sandbox fingerprint signals, canonicalize them, and produce stable + ephemeral hashes for key derivation.

**Requirements:** R2, R8

**Dependencies:** Unit 2, Unit 5

**Files:**
- Create: `crates/fingerprint/src/lib.rs`
- Create: `crates/fingerprint/src/model.rs`
- Create: `crates/fingerprint/src/collect.rs`
- Create: `crates/fingerprint/src/canonical.rs`
- Create: `crates/fingerprint/src/detect.rs`
- Test: `crates/fingerprint/src/collect.rs`, `crates/fingerprint/src/canonical.rs`

**Approach:**
- `model.rs`: `RuntimeKind` enum (Docker, Firecracker, Gvisor, Kata, Nspawn, GenericLinux, Unknown), `SourceValue` struct, `FingerprintSnapshot` with stable/ephemeral vectors
- `collect.rs`: `FingerprintCollector` struct with `collect() -> FingerprintSnapshot`. Tier 1 (stable): machine-id (HMAC'd with app key), hostname, cgroup path, kernel_release, proc_cmdline hash. Tier 2 (ephemeral): namespace inodes (mnt, pid, net, uts, user, cgroup). All rootless.
- `canonical.rs`: Deterministic encoding — sort by source_id ascending, encode as `len(id)||id||len(value)||value`, then SHA-256 the blob. `canonicalize_stable(snapshot) -> [u8; 32]`, `canonicalize_ephemeral(snapshot) -> [u8; 32]`
- `detect.rs`: Runtime detection based on `/proc/self/cgroup` patterns, `/proc/1/cgroup`, env vars
- Missing sources handled gracefully (Option), not errors
- Uses `procfs` crate for cgroup/mountinfo/namespaces, `nix` crate for hostname

**Test scenarios:**
- Happy path: Collecting in a known environment produces deterministic stable_hash
- Happy path: Two collections in same environment produce identical stable_hash
- Edge case: Missing /etc/machine-id → skipped, not error
- Edge case: Missing /proc/self/cgroup → RuntimeKind::Unknown
- Integration: Docker container detection from cgroup path pattern
- Integration: Verbose mode logs all collected sources for debugging

**Verification:**
- Determinism tests pass (same env, same hash)
- CI integration test in Docker container
- 85%+ coverage

---

- [ ] **Unit 7: Memfd executor (launcher core)**

**Goal:** Build the core memfd execution engine — create memfd, chunked write, seal, fexecve with fork+wait for result capture.

**Requirements:** R3, R5, R6

**Dependencies:** Unit 4 (decrypt_stream), Unit 6 (fingerprint)

**Files:**
- Create: `crates/launcher/src/memfd_exec.rs`
- Create: `crates/launcher/src/anti_debug.rs`
- Create: `crates/launcher/src/self_delete.rs`
- Modify: `crates/launcher/src/main.rs`
- Test: `crates/launcher/src/memfd_exec.rs` (unit via trait mock + integration via real subprocess)

**Approach:**
- `memfd_exec.rs`: `MemfdExecutor` struct using `memfd` crate (lucab/memfd-rs) for creation + sealing, `nix::unistd::fexecve` for execution. API: `execute(decrypted_bytes, args, env, cwd) -> ExecutionResult { stdout, stderr, exit_code }`. Internal flow: fork → child: create memfd, write chunks, add SealWrite+SealSeal, fexecve → parent: waitpid, collect stdout/stderr/exit_code.
- `anti_debug.rs`: `apply_protections()` calls prctl(PR_SET_DUMPABLE, 0) and PTRACE_TRACEME. Failures logged but non-fatal.
- `self_delete.rs`: `self_delete()` reads `/proc/self/exe`, calls remove_file. Must run BEFORE fexecve. Skips gracefully on EPERM (overlayfs).
- Trait abstraction for memfd operations: `MemfdOps` trait with `create`, `write_chunk`, `seal`, `exec` — real impl uses kernel calls, test impl uses tempfiles
- Launcher target: x86_64-unknown-linux-musl (static)

**Test scenarios:**
- Happy path (integration): Execute `/bin/echo hello` via memfd → captures stdout "hello\n", exit_code 0
- Happy path (integration): Execute non-zero exit binary → captures correct exit code
- Edge case (integration): Binary that writes to stderr → captures stderr
- Error path: Seal after exec → SealError::AlreadyExecuted
- Error path: Invalid ELF bytes → ExecutionResult with non-zero exit
- Unit (mock): MemfdOps mock verifies correct call sequence (create → write_chunks → seal → exec)

**Verification:**
- Integration tests pass in Docker container
- `prctl` and `ptrace` calls verified via strace in integration test
- Self-delete verified: binary removed from disk before memfd exec

---

- [ ] **Unit 8: Launcher binary (full pipeline)**

**Goal:** Wire the complete launcher pipeline: tamper check → fingerprint collect → key derive → decrypt → anti-debug → self-delete → memfd exec → result capture.

**Requirements:** R1-R6, R8

**Dependencies:** Unit 3, Unit 4, Unit 5, Unit 6, Unit 7

**Files:**
- Modify: `crates/launcher/src/main.rs`
- Modify: `crates/launcher/Cargo.toml` (add deps: core, fingerprint, clap)
- Test: `crates/launcher/tests/integration.rs`

**Approach:**
- CLI via clap: `agent-seal-launcher --payload <path> --fingerprint-mode <strict|compatible> --user-fingerprint <hex>`
- Pipeline: 1) Read payload from stdin or file, 2) Parse header (validate magic + version), 3) verify_tamper (compare embedded hash), 4) collect fingerprint, 5) derive env key, 6) fingerprint mismatch check (try decrypt header chunk — if auth fails, return clear "fingerprint mismatch" error instead of raw AES error), 7) decrypt full payload, 8) apply anti-debug protections, 9) self-delete binary, 10) fork + memfd exec, 11) parent waits + captures results, 12) write results to stdout (JSON: {exit_code, stdout, stderr})
- Result output as JSON to stdout for programmatic consumption by the server
- Master secret and tamper hash embedded by compiler at build time via build.rs or include_bytes!

**Test scenarios:**
- Happy path (integration): Encrypt a binary with known fingerprint, launch in matching environment → executes successfully
- Error path: Launch in wrong environment (different fingerprint) → clear "fingerprint mismatch" error (not opaque crypto failure)
- Error path: Tampered launcher binary → SealError::TamperDetected with clear message
- Error path: Payload version mismatch → SealError::UnsupportedPayloadVersion
- Edge case: No /proc/self/exe (non-Linux) → clear platform error

**Verification:**
- End-to-end: encrypt hello-world → launch → capture "hello" output
- 85%+ coverage (syscall code will be lower, covered by integration tests)

---

### Phase 3: Compiler (Day 7-10)

- [ ] **Unit 9: Compiler — Python→ELF compilation wrapper**

**Goal:** Invoke Nuitka/PyInstaller programmatically to compile Python agent projects into standalone ELF binaries.

**Requirements:** R1

**Dependencies:** Unit 1

**Files:**
- Create: `crates/compiler/src/nuitka.rs`
- Create: `crates/compiler/src/pyinstaller.rs`
- Create: `crates/compiler/src/compile.rs`
- Test: `crates/compiler/src/compile.rs`

**Approach:**
- `nuitka.rs`: `compile_with_nuitka(project_dir, output_dir, options) -> Result<PathBuf>` invokes Nuitka via std::process::Command with programmatic flags (--standalone, --onefile, --output-dir, --linux-icon, etc.). Captures stdout/stderr, parses for errors.
- `pyinstaller.rs`: `compile_with_pyinstaller(project_dir, output_dir, options) -> Result<PathBuf>` same pattern with PyInstaller --onefile mode.
- `compile.rs`: `compile_agent(project_dir, output_dir, backend) -> Result<PathBuf>` tries Nuitka first, falls back to PyInstaller. Strips debug symbols via `strip` command after compilation.
- Backend selection configurable via CLI flag, default Nuitka
- Output: single ELF binary at known path
- Timeout handling (compilation can take 5-30 minutes for complex agents)
- Not a Cargo dependency on launcher — reads launcher binary from env var `AGENT_SEAL_LAUNCHER_PATH`

**Test scenarios:**
- Happy path (integration): Compile a trivial Python script → produces ELF binary
- Happy path: Verify compiled binary executes correctly
- Error path: Invalid Python project → clear compilation error
- Error path: Nuitka not installed → falls back to PyInstaller or clear error
- Edge case: Compilation timeout → SealError::CompilationTimeout

**Verification:**
- Integration test with minimal Python project
- Binary size check (reasonable for hello-world)
- `file` command confirms ELF

---

- [ ] **Unit 10: Compiler — payload encryption and binary assembly**

**Goal:** Encrypt the compiled agent binary and assemble it with the launcher stub into a single distributable binary.

**Requirements:** R1, R2

**Dependencies:** Unit 4 (encrypt_stream), Unit 6 (fingerprint), Unit 9 (compile)

**Files:**
- Create: `crates/compiler/src/assemble.rs`
- Create: `crates/compiler/src/embed.rs`
- Modify: `crates/compiler/src/main.rs`
- Test: `crates/compiler/src/assemble.rs`

**Approach:**
- `assemble.rs`: `build_sealed_binary(agent_elf_path, launcher_path, master_secret, stable_fingerprint_hash, user_fingerprint) -> Result<Vec<u8>>`. Steps: 1) Generate encryption key via derive_env_key, 2) Encrypt agent ELF via encrypt_stream, 3) Pack into payload format (header + stream header + chunks + footer), 4) Append payload to launcher binary
- `embed.rs`: `embed_master_secret(launcher_path, secret) -> Result<Vec<u8>>` patches the launcher binary to embed the master secret at a known offset (marker-based: scan for a specific 16-byte marker pattern, replace with secret). Also embeds the tamper detection hash.
- CLI: `agent-seal-compiler build --project <dir> --user-fingerprint <hex> --sandbox-fingerprint <hex|auto> --output <path>`
- Auto mode: if sandbox-fingerprint=auto, generates a placeholder key (actual binding happens at runtime in the launcher)

**Test scenarios:**
- Happy path (integration): Compile hello-world → encrypt → assemble → verify binary is valid ELF with expected size increase
- Happy path: Round-trip: assembled binary → launcher decrypts → executes → correct output
- Edge case: Very large agent binary (100MB+) → streaming encryption doesn't OOM
- Error path: Invalid launcher binary → SealError::InvalidLauncher
- Error path: Launcher binary missing marker → SealError::EmbedFailed

**Verification:**
- End-to-end: compile → encrypt → assemble → launch → correct output
- Binary size is launcher_size + agent_size + ~100 bytes overhead
- No plaintext agent binary on disk at any point

---

### Phase 4: Proxy + Server (Day 10-14)

- [ ] **Unit 11: LLM proxy — core routing and auth**

**Goal:** Build the LLM proxy server with virtual key auth, per-(key,sandbox) rate limiting, and multi-provider routing.

**Requirements:** R4

**Dependencies:** Unit 2 (shared types)

**Files:**
- Create: `crates/proxy/src/auth.rs`
- Create: `crates/proxy/src/rate_limit.rs`
- Create: `crates/proxy/src/provider.rs`
- Create: `crates/proxy/src/routes.rs`
- Create: `crates/proxy/src/state.rs`
- Modify: `crates/proxy/src/main.rs`
- Test: `crates/proxy/src/auth.rs`, `crates/proxy/src/rate_limit.rs`

**Approach:**
- `auth.rs`: Virtual key authentication. Constant-time token compare + in-memory key store. Ephemeral virtual keys with TTL (issued by server). Auth extractor for axum.
- `rate_limit.rs`: Per-(key,sandbox) rate limiting via `governor` crate. Configurable burst + per-second quota. Additional global limiter.
- `provider.rs`: Provider adapter layer. OpenAI adapter, Anthropic adapter. Request normalization to canonical OpenAI format, response denormalization. Model mapping table.
- `routes.rs`: `POST /v1/chat/completions` (canonical OpenAI-compatible endpoint), `GET /health`, `POST /v1/keys/rotate` (grace-period rotation)
- `state.rs`: AppState with key store, rate limiters, provider configs, reqwest HTTP client
- API keys stored server-side only — agents get ephemeral virtual keys
- Grace-period key rotation: old key valid for N seconds after rotation

**Test scenarios:**
- Happy path: Valid virtual key → request routed to provider → response streamed back
- Happy path: Rate limit within quota → succeeds
- Error path: Invalid/expired key → 401 with clear message
- Error path: Rate limit exceeded → 429 with Retry-After header
- Error path: Provider returns error → proxied back with status code
- Integration: Key rotation → old key works during grace period, fails after

**Verification:**
- axum::test + tower::ServiceExt handler tests
- 90%+ coverage on auth and rate_limit modules

---

- [ ] **Unit 12: LLM proxy — SSE streaming**

**Goal:** Implement SSE stream proxying between agent and LLM providers, with disconnect-aware cancellation.

**Requirements:** R4

**Dependencies:** Unit 11

**Files:**
- Create: `crates/proxy/src/stream.rs`
- Modify: `crates/proxy/src/routes.rs`
- Test: `crates/proxy/src/stream.rs`

**Approach:**
- `stream.rs`: SSE stream proxy. Receives upstream `bytes_stream` from provider, parses SSE by lines/events (not TCP chunks), re-emits as `Body::from_stream` to client. Handles client disconnect (tx.closed()) to stop upstream task. Preserves text/event-stream + cache-control headers.
- Request body streaming for large prompts (forward agent request body as stream)
- Uses reqwest for upstream, axum response streaming for downstream
- Line-buffered SSE parser handles split chunks correctly (reqwest doesn't guarantee SSE frame boundaries)

**Test scenarios:**
- Happy path: Mock provider returns SSE events → client receives same events in order
- Happy path: Large response (100+ events) → all events received
- Edge case: Client disconnects mid-stream → upstream task cancels cleanly
- Edge case: Provider sends partial SSE line → reassembled correctly

**Verification:**
- Mock provider integration test with SSE
- No unbounded buffering (stream-through, not buffer-then-forward)

---

- [ ] **Unit 13: Orchestration server — compile and dispatch**

**Goal:** Build the orchestration API that manages the full pipeline: provision sandbox, compile agent, dispatch encrypted binary, stream results.

**Requirements:** R1, R2

**Dependencies:** Unit 9, Unit 10, Unit 11

**Files:**
- Create: `crates/server/src/routes.rs`
- Create: `crates/server/src/state.rs`
- Create: `crates/server/src/sandbox.rs`
- Modify: `crates/server/src/main.rs`
- Test: `crates/server/src/routes.rs`

**Approach:**
- `routes.rs`: `POST /api/v1/compile` (compile agent, return job ID), `GET /api/v1/jobs/{id}/status`, `POST /api/v1/dispatch` (ship binary to sandbox), `GET /api/v1/jobs/{id}/results` (stream results)
- `state.rs`: AppState with job store, compiler config, sandbox provisioner
- `sandbox.rs`: Sandbox provisioner trait. Default impl: shell out to Docker CLI or API. Methods: `provision(image) -> SandboxHandle`, `collect_fingerprint(handle) -> FingerprintSnapshot`, `destroy(handle)`
- Async job management: tokio::spawn for compilation (can take 5-30 min), bounded concurrency (max N concurrent compiles)
- Job status: pending → compiling → ready → dispatched → running → completed/failed
- Server calls compiler crate programmatically (not via subprocess) — compiler should expose a library API

**Test scenarios:**
- Happy path: Submit compile job → poll status → get ready binary
- Happy path: Dispatch to sandbox → poll results → get execution output
- Error path: Invalid project → job fails with clear error
- Error path: Sandbox provision fails → job fails
- Integration: Full pipeline compile → dispatch → results

**Verification:**
- axum::test handler tests
- Mock sandbox provider for unit tests
- 85%+ coverage

---

### Phase 5: Hardening + Demo (Day 14-16)

- [ ] **Unit 14: End-to-end demo pipeline**

**Goal:** Create a working demo that exercises the full pipeline: Python agent → compile → encrypt → dispatch to Docker sandbox → execute → capture results.

**Requirements:** R1-R6

**Dependencies:** All prior units

**Files:**
- Create: `examples/demo_agent/main.py` (trivial AgentScope-style agent)
- Create: `examples/demo_agent/requirements.txt`
- Create: `scripts/demo.sh` (full pipeline script)
- Create: `scripts/build_launcher.sh` (cross-compile launcher for musl)

**Approach:**
- Demo agent: Python script that calls an LLM via the proxy (OpenAI-compatible endpoint) and returns a result
- Demo pipeline: 1) Build launcher (musl), 2) Compile demo agent (Nuitka), 3) Collect sandbox fingerprint from target Docker container, 4) Encrypt and assemble, 5) Copy binary to sandbox, 6) Execute, 7) Capture results
- scripts/demo.sh automates the full pipeline
- README documents the demo

**Test scenarios:**
- Test expectation: none -- demo script, manual verification

**Verification:**
- `scripts/demo.sh` runs end-to-end without errors
- Demo agent produces expected output
- No plaintext binary on disk in sandbox (verified via `ls -la` in container)
- Binary self-deletes after execution (verified via `ls` post-execution)

---

- [ ] **Unit 15: CI badges and coverage enforcement**

**Goal:** Generate CI badges (build status, coverage, Rust version) from GitHub Actions, no external badge providers.

**Requirements:** R10

**Dependencies:** Unit 1 (CI workflow)

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/badges.yml`
- Modify: `README.md` (add badge references)

**Approach:**
- badges.yml: On push to main, generate SVG badges from CI results
- Build status badge: reads last commit status via GitHub API, generates green/red SVG
- Coverage badge: reads coverage percentage from llvm-cov output, generates color-graded SVG
- Rust version badge: reads rust-toolchain.toml or cargo version
- Badges committed to `docs/badges/` directory
- README references `docs/badges/*.svg`
- No shields.io or external badge providers — all self-generated
- Alternative: use GitHub Actions built-in status badges for build status, custom action for coverage

**Test scenarios:**
- Test expectation: none -- CI infrastructure

**Verification:**
- Badges render correctly in GitHub README preview
- Coverage badge reflects actual coverage percentage
- Build status badge updates on push

---

## Dependency Graph

```
Unit 1 (workspace)
  ├─→ Unit 2 (types)
  │     ├─→ Unit 3 (secret/tamper)
  │     │     └─→ Unit 8 (launcher pipeline) ←──── also depends on 4, 5, 6, 7
  │     ├─→ Unit 4 (crypto)
  │     │     └─→ Unit 8
  │     │     └─→ Unit 10 (assemble)
  │     └─→ Unit 5 (derive)
  │           └─→ Unit 8
  │           └─→ Unit 10
  ├─→ Unit 6 (fingerprint)
  │     └─→ Unit 8
  │     └─→ Unit 10
  ├─→ Unit 7 (memfd exec)
  │     └─→ Unit 8
  ├─→ Unit 9 (compile wrapper)
  │     └─→ Unit 10 (assemble)
  ├─→ Unit 11 (proxy auth)
  │     └─→ Unit 12 (proxy streaming)
  ├─→ Unit 13 (server)
  │     ├─→ Unit 9
  │     ├─→ Unit 10
  │     └─→ Unit 11
  ├─→ Unit 14 (demo) ← depends on all
  └─→ Unit 15 (badges) ← depends on Unit 1
```

## Crate Dependency Graph (Cargo)

```
agent-seal-core (lib)         ← no workspace deps, pure Rust
  ↑
agent-seal-fingerprint (lib)  ← core
  ↑
agent-seal-launcher (bin)     ← core, fingerprint (musl static)
  
agent-seal-compiler (bin)     ← core, fingerprint (glibc, reads launcher binary from env)
agent-seal-proxy (bin)        ← core (glibc)
agent-seal-server (bin)       ← compiler (lib API), proxy (glibc)
```

## System-Wide Impact

- **Interaction graph:** Launcher is the only crate running in untrusted sandboxes. All other crates run on trusted build/control infrastructure.
- **Error propagation:** All errors surface through SealError with clear variants. Fingerprint mismatch gets special handling (not raw crypto failure).
- **State lifecycle risks:** Compiler produces large temporary files during Nuitka builds. Must clean up on failure. Job store in server needs persistence for long-running compile jobs.
- **API surface parity:** Proxy exposes OpenAI-compatible API. Must track upstream API changes (new fields, new models).
- **Unchanged invariants:** Once shipped, payload format v1 is immutable. New versions use incremented version number.

## Risks & Dependencies

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Nuitka fails to compile complex AgentScope projects | Medium | High | Fallback to PyInstaller; validate early with real projects in Unit 9 |
| musl cross-compilation issues with crypto crates | Low | High | All RustCrypto crates are pure Rust, compile on musl; test in CI from day 1 |
| memfd not available in restricted sandboxes | Low | High | Requires Linux 3.17+; document minimum kernel requirement; skip in tight seccomp profiles |
| 85% coverage too aggressive for syscall code | Medium | Medium | Integration tests in Docker close the gap; set 85% gate, aim higher on logic |
| Nuitka compilation takes 30+ minutes for large agents | High | Medium | Async job queue with progress reporting; timeout handling; user feedback |
| Fingerprint instability across Docker versions | Medium | Medium | compatible mode (default) tolerates partial fingerprints; strict mode for high-security |
| Key rotation during in-flight LLM requests | Low | Medium | Grace-period rotation (old key valid for N seconds); tested in Unit 11 |

## Documentation / Operational Notes

- README is comprehensive (architecture, encryption design, fingerprinting, threat model, usage, crate overview)
- Each crate has doc comments on public API
- Threat model documented in README: what Agent Seal protects against, what it doesn't
- Operational notes: launcher is musl static, all other crates glibc; requires Linux 3.17+ for memfd
- Build requirements: Rust stable, musl-tools, Nuitka (or PyInstaller), Python 3.10+

## Sources & References

- Origin: Handoff from design session (2026-04-07)
- Crypto: RustCrypto aes-gcm + aead-stream (https://github.com/RustCrypto/AEADs)
- Key derivation: HKDF RFC 5869 (https://datatracker.ietf.org/doc/html/rfc5869)
- memfd: lucab/memfd-rs (https://github.com/lucab/memfd-rs)
- Fingerprint sources: systemd machine-id docs, Docker cgroup parsing, Firecracker boot_args
- Proxy pattern: nearai/inference-proxy (https://github.com/nearai/inference-proxy)
- Workspace patterns: linkerd2-proxy, quickwit, spinframework/spin
- Coverage: cargo-llvm-cov + nextest (preferred over tarpaulin for async code)
