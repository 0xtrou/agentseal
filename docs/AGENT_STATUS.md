# Snapfzz Seal — Implementation Status

**Last updated:** 2026-04-11
**Branch:** main
**Head commit:** 2049c86

This document is a ground-truth status matrix for every major feature area of the Snapfzz Seal
project. Status is derived from direct code inspection; no speculative or aspirational claims
are made.

---

## Status key

| Symbol | Meaning |
|--------|---------|
| Implemented | Code is present, wired into the runtime path, and covered by tests. |
| Partial | Code exists but has known gaps, is not wired end-to-end, or carries significant platform caveats. |
| Not Implemented | Not yet present in any crate. |

---

## Core encryption pipeline

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| AES-256-GCM chunked streaming encryption | Implemented | All | `snapfzz-seal-core::payload`; 64 KB chunks with per-chunk nonce |
| HKDF key derivation (env key) | Implemented | All | `derive_env_key`: master secret + stable fingerprint + optional user fingerprint |
| Session key derivation (ephemeral signals) | Implemented | All | `derive_session_key`: extends env key with ephemeral fingerprint hash |
| Payload header with HMAC | Implemented | All | `PayloadHeader` with `header_hmac` field written and validated at launch |
| Payload footer (hashes + backend type) | Implemented | All | 65-byte footer; fields: `original_hash`, `launcher_hash`, `backend_type` |
| Integrity-bound key derivation | Partial | Linux only | `derive_key_with_integrity_from_binary` mixes launcher binary hash into key on Linux; on all other platforms the function is a no-op that returns the secret unchanged |

---

## Assembly pipeline (`snapfzz-seal-compiler`)

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| Go compile backend | Implemented | All | `backend/golang.rs`; `ldflags` format fixed |
| PyInstaller compile backend | Implemented | All | `backend/pyinstaller.rs` |
| Nuitka compile backend | Implemented | Linux, Windows | `backend/nuitka.rs`; falls back to `python3 -m nuitka`; `strip` step skipped to preserve payload; skipped on macOS in E2E tests due to Homebrew incompatibility |
| Master secret embedding (Shamir shares) | Implemented | All | `embed::embed_master_secret` writes five share markers; wired in `assemble.rs` |
| Decoy secret embedding | Implemented | All | `decoys::embed_decoy_secrets` embeds ten decoy sets; wired in `assemble.rs` |
| Tamper hash embedding | Implemented | All | SHA-256 of launcher-with-decoys written via `embed_tamper_hash` |
| White-box table embedding | Implemented | All | Tables appended behind `ASL_WB_TABLES_v1` marker; `whitebox_embed.rs` wired in `assemble.rs` |
| Binary integrity hash (assemble-time) | Implemented | All | SHA-256 over ELF code/data regions stored in footer |
| Ed25519 signing (`seal sign`) | Implemented | All | Appends 100-byte `ASL\x02` signature block to assembled binary |

---

## Launcher (`snapfzz-seal-launcher`)

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| Mandatory signature verification | Implemented | All | All unsigned payloads rejected with `MissingSignature` |
| Payload extraction from self (appended) | Implemented | All | Sentinel scan + footer read |
| Shamir secret reconstruction | Implemented | All | `reconstruct_secret` via `load_master_secret`; threshold = 3 of 5 |
| Fingerprint collection (stable) | Implemented | All | Hostname, CPU, OS, MAC address, DMI signals |
| Fingerprint collection (session/ephemeral) | Implemented | All | Adds boot time and process-level signals |
| Key derivation at launch | Implemented | All | Mirrors assembly-time derivation |
| AES-256-GCM decryption | Implemented | All | Streaming unpack with per-chunk authentication tag verification |
| Memfd execution (Go, unknown backends) | Implemented | Linux only | `memfd_create` + `execveat`; no-op path on non-Linux platforms |
| Temp-file execution (Nuitka, PyInstaller) | Implemented | All | `TempFileExecutor`; fd closed before exec to avoid ETXTBSY on Linux |
| Interactive mode (`--interactive`) | Implemented | All | Lifetime enforcement via concurrent monitor thread; `max_lifetime_secs` configurable |
| Self-delete after launch | Implemented | All | `cleanup::self_delete()` called when running from embedded payload |
| Environment scrubbing | Implemented | All | `protection::apply_protections` runs before agent exec |
| Backend-aware dispatch | Implemented | All | `BackendType` from footer selects executor |

---

## Anti-debug (`anti_debug.rs`)

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| `prctl(PR_SET_DUMPABLE, 0)` | Implemented | Linux only | Applied via `anti_debug::apply_protections`; no-op on non-Linux |
| `ptrace TRACEME` protection | Implemented | Linux only | `nix::sys::ptrace::traceme()` called at launch; no-op on non-Linux |

---

## Anti-analysis (`anti_analysis.rs`)

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| Linux TracerPid check | Implemented | Linux only | Reads `/proc/self/status`; not called on non-Linux |
| ptrace TRACEME detection | Implemented | Linux only | `libc::ptrace(PTRACE_TRACEME)` returns -1 if already traced; not called on non-Linux |
| Software breakpoint scan | Implemented | All | Scans first 32 bytes of three probe functions for `0xCC` opcode |
| Timing anomaly detection | Implemented | All | 100k-iteration loop; double-confirms anomaly before flagging to reduce false positives |
| CPUID hypervisor bit | Implemented | x86_64 only | `__cpuid(1)` ECX bit 31; returns `false` on non-x86_64 architectures |
| DMI artifact file scan | Implemented | Linux only | Reads `/sys/class/dmi/id/*`, `/proc/scsi/scsi`, `/proc/cpuinfo`; not invoked on non-Linux |
| MAC address VM OUI check | Implemented | Linux only | Reads `/sys/class/net/<iface>/address`; checks known VMware, VirtualBox, QEMU prefixes; not invoked on non-Linux |
| Environment poisoning | Implemented | All | Writes three decoy env vars and three decoy files on every launch |
| Windows / macOS anti-debug | Not Implemented | Windows, macOS | `anti_debug::apply_protections` is a no-op on non-Linux; `detect_debugger` skips TracerPid and ptrace checks |

---

## Seccomp filter (`seccomp.rs`)

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| Linux x86_64 syscall allowlist | Implemented | Linux x86_64 | ~130 syscalls; default deny action is `EPERM` |
| Go runtime syscalls included | Implemented | Linux x86_64 | `set_tid_address`, `set_robust_list`, `madvise`, `gettid`, etc. |
| PyInstaller / Nuitka syscalls included | Implemented | Linux x86_64 | `memfd_create`, `futex`, `statfs` |
| Filter application at launch | Implemented | Linux x86_64 | Called from `protection` module before exec |
| Windows seccomp stub | Implemented (no-op) | Windows | Logs and returns `Ok(())` |
| macOS / other platforms stub | Implemented (no-op) | macOS, other | Returns `Ok(())` silently |
| ARM / aarch64 syscall table | Not Implemented | aarch64 | Allowlist is x86_64-only; filter is not applied on ARM architectures |

---

## White-box cryptography (`core::whitebox`)

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| T-box generation (SubBytes + AddRoundKey) | Implemented | All | 14 rounds x 16 bytes = 224 T-boxes per key |
| Type I / Type II mixing tables | Implemented | All | 13 pairs; GF(2^8) MixColumns coefficients |
| Table randomization | Partial | All | `tables.randomize()` is called but does not apply proper affine external encodings; the current implementation provides structural obfuscation only, not cryptographic white-box security |
| Round key derivation | Partial | All | Uses SHA-256 hash of key + round index rather than the standard AES-256 key schedule; result is functionally distinct from standard AES-256 |
| White-box decryption at launch | Not Implemented | All | `WhiteBoxAES::decrypt` exists in `snapfzz-seal-core` but is not called during the launch decryption path; the runtime uses standard AES-256-GCM |
| Embedded table size | ~165 KB | All | Within the ~2 MB upper bound; `estimate_whitebox_size` reports up to 2 MB conservatively |

---

## Integrity verification (`core::integrity`)

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| ELF section parsing (`find_integrity_regions`) | Implemented | Linux only | Locates executable PT_LOAD segments; computes exclusion list for mutable areas (Shamir slots, tamper marker, payload tail) |
| Binary integrity hash computation | Implemented | All | SHA-256 over code/data with exclusions applied |
| Hash stored in payload footer | Implemented | All | `PayloadFooter::launcher_hash` |
| Hash verified at launch | Implemented | Linux only | `verify_launcher_integrity` called before decryption on Linux; silently skipped on non-Linux |
| Integrity-bound key derivation | Implemented | Linux only | Hash mixed into decryption key on Linux; non-Linux binds secret to itself (no integrity binding) |
| Non-Linux fallback | Partial | macOS, Windows | `find_integrity_regions` falls back to a full-binary scan with no ELF parsing; `verify_binary_integrity` is a no-op (always returns `Ok(())`) |

---

## Fingerprinting (`snapfzz-seal-fingerprint`)

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| Stable signals (hostname, CPU, OS) | Implemented | All | |
| MAC address signal | Implemented | All | |
| DMI / hardware signals | Implemented | Linux, macOS | |
| Ephemeral signals (boot time, PID) | Implemented | All | Session mode only |
| Stable hash canonicalization | Implemented | All | Deterministic ordering via sorted signal map |
| Ephemeral hash canonicalization | Implemented | All | |

---

## Orchestration server (`snapfzz-seal-server`)

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| HTTP assembly endpoint | Implemented | All | Accepts agent binary + config, returns assembled artifact |
| Path validation | Implemented | All | Parallel-test race condition fixed in commit 2049c86 |
| Authentication | Not Implemented | All | API is unauthenticated; disclosed in threat model documentation |

---

## CLI (`snapfzz-seal`)

| Feature | Status | Platform | Notes |
|---------|--------|----------|-------|
| `seal compile` (go / pyinstaller / nuitka) | Implemented | All | |
| `seal assemble` | Implemented | All | |
| `seal sign` / `seal verify` | Implemented | All | Ed25519 with `ASL\x02` signature block |
| `seal launch` | Implemented | All | Delegates to `seal-launcher` binary |
| `seal launch --interactive` | Implemented | All | |

---

## Test coverage

| Area | Status | Platform | Notes |
|------|--------|----------|-------|
| CI coverage gate | Implemented | All | 90% line-coverage enforced; measured with `cargo-llvm-cov` |
| Unit tests (all crates) | Implemented | All | Anti-analysis, seccomp, integrity, Shamir, crypto, fingerprint |
| E2E tests (go / pyinstaller / nuitka) | Implemented | Linux (Docker) | `e2e-tests/` scripts; Docker-based; Nuitka backend skipped on macOS |
| Interactive mode E2E | Partial | Linux (Docker) | `full_interaction_test.sh` covers basic interactive flow; lifetime enforcement is not stress-tested in CI |
