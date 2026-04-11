# Oracle Evaluation Report -- Snapfzz Seal

*Evaluator: Independent Oracle Agent | Date: 2026-04-11*

## Executive Summary

Snapfzz Seal is a well-structured Rust workspace that delivers on its stated goal of raising the cost of static secret extraction from shipped agent binaries. The cryptographic core -- HKDF key derivation, AES-256-GCM chunked encryption, Ed25519 signing, and Shamir secret sharing over secp256k1's field -- is implemented correctly and tested thoroughly (465 unit tests, all passing). However, several design choices limit the system's security ceiling: the anti-analysis layer is trivially bypassable by a motivated attacker, the white-box AES integration is incomplete, decoy markers use a fixed seed, and the entire runtime protection stack (anti-debug, integrity verification, seccomp) is Linux-only with silent no-ops elsewhere. The system is honest about these limitations in its README, which is commendable.

**Security Posture: 6/10** -- Sound cryptographic foundation with significant gaps in anti-tamper and anti-analysis that limit it to a speed-bump against skilled reverse engineers.

**Utility Rating: 7/10** -- Solves the "ship a single encrypted agent binary" problem well for Linux targets with good CLI ergonomics, but operational complexity (BUILD_ID discipline, Linux-only execution) and incomplete features (white-box AES, session fingerprinting) reduce practical value.

---

## 1. Security Readiness

### 1.1 Threat Model Coverage

| Stated Threat | Mitigation | Effectiveness | Gap |
|---|---|---|---|
| Static extraction of master secret from binary | Shamir 5-of-3 splitting into marker-delimited slots; 50 decoy slots; white-box AES tables | Medium | Decoys use fixed seed `0` (`assemble.rs:48`), not master-secret-derived. White-box tables are embedded but not used in runtime decryption path. An attacker with IDA/Ghidra can identify live slots by cross-referencing with `reconstruct_secret` call sites. |
| Payload decryption outside target environment | Key derivation binds to `stable_fingerprint || user_fingerprint` via HKDF (`derive.rs:18-22`) | High | Fingerprint binding depends on `/etc/machine-id`, hostname, kernel release -- all spoofable by an attacker who has observed the target once. No hardware attestation. |
| Binary tampering post-assembly | SHA-256 integrity hash in footer; launcher verifies at runtime (`lib.rs:528-557`) | Medium (Linux) / None (other) | On non-Linux: `verify_launcher_integrity` unconditionally returns `Ok(())` (`lib.rs:550-556`). Launcher integrity check uses non-constant-time `==` comparison (`lib.rs:537`). |
| Debugger attachment | `prctl(PR_SET_DUMPABLE, 0)` + `ptrace(PTRACE_TRACEME)` (`anti_debug.rs:7-26`) | Low | Standard bypass: LD_PRELOAD to stub ptrace, or patch the binary. Both protections are Linux-only. |
| Dynamic analysis / VM detection | CPUID hypervisor bit, VM MAC prefixes, artifact file checks, timing analysis (`anti_analysis.rs:59-110`) | Low | VM detection is trivially defeated by MAC spoofing and removing DMI files. Timing check uses a fixed 25ms threshold (`500us * 50`) that will false-positive on loaded systems and miss sophisticated debuggers. Breakpoint scan checks only 3 stub functions (`decrypt_payload_probe`, etc.) that are not the actual decryption functions. |
| Unsigned payload execution | Ed25519 signature block appended by `seal sign`; launcher verifies at startup (`lib.rs:72-99`) | High | Signature is TOFU by default -- public key is embedded in the binary alongside the signature. An attacker who can modify the binary can replace both. Pinned verification requires out-of-band key distribution. |

### 1.2 Cryptographic Implementation

**Shamir Secret Sharing (`shamir.rs`):** Implemented over the secp256k1 prime field (p = 2^256 - 2^32 - 977). Field arithmetic is hand-rolled with 4-limb 64-bit representation. The implementation is functionally correct:
- `split_secret_with_rng` generates random non-zero polynomial coefficients and evaluates at x=1..n.
- `reconstruct_secret` uses Lagrange interpolation with proper duplicate/zero-index rejection.
- Secret-out-of-range validation prevents values >= modulus.
- Tests cover round-trip with multiple share subsets, edge cases, and field arithmetic properties.

**Concern:** The modular inverse (`pow(MODULUS_MINUS_TWO)` at `shamir.rs:129`) uses square-and-multiply exponentiation that is **not constant-time**. The exponent bits directly control branching. This is a theoretical side-channel concern during reconstruction, though exploitation requires physical proximity or shared-hardware timing measurement.

**AES-256-GCM Encryption (`payload.rs`):** Uses `aes-gcm` 0.11.0-rc.3 and `aead-stream` 0.6.0-rc.3. These are **release candidate** versions of the RustCrypto crates, not stable releases. The chunked streaming encryption with 64KB chunks is standard. Header HMAC verification uses `subtle::ConstantTimeEq` (`payload.rs:91`) -- correct.

**HKDF Key Derivation (`derive.rs`):** Standard HKDF-SHA256 with domain-separated info strings (`snapfzz-seal/env/v1`, `snapfzz-seal/session/v1`). Salt is `stable_hash || user_fingerprint` (64 bytes). Intermediate values are zeroized (`derive.rs:23`). This is textbook-correct.

**Ed25519 Signing (`signing.rs`):** Uses `ed25519-dalek` via standard API. Keygen uses `OsRng`. No issues identified.

### 1.3 Secret Handling

**Generation:** Master secret is 32 random bytes generated externally (by the caller of `seal compile`).

**Embedding:** `embed_master_secret_with_shamir` (`embed.rs:14-41`) splits into 5 shares and writes each into a marker-delimited 32-byte slot in the launcher binary. The markers are BUILD_ID-derived SHA-256 values.

**Runtime extraction:** `extract_embedded_master_secret` (`lib.rs:486-526`) scans the binary for marker+slot patterns, collects shares, and calls `reconstruct_secret`. Falls back to `SNAPFZZ_SEAL_MASTER_SECRET_HEX` environment variable if fewer than 3 shares found.

**In-memory handling:** The launcher uses `Zeroizing<Vec<u8>>` for the decrypted payload (`lib.rs:167`) and explicitly calls `.zeroize()` on `decryption_key` and `master_secret` (`lib.rs:180-181`). However:
- The `env_key` intermediate in `derive_decryption_key` (`lib.rs:233`) is a stack `[u8; 32]` that is **not** explicitly zeroized. Rust may or may not zero the stack frame.
- The Shamir shares extracted in `extract_embedded_master_secret` (`lib.rs:506`) are stack arrays that are not zeroized.
- The `integrity_bound_key` in `derive_decryption_key` (`lib.rs:244`) is not zeroized.

**Environment fallback risk:** When embedded shares are insufficient, the master secret is read from `SNAPFZZ_SEAL_MASTER_SECRET_HEX`. This environment variable is in the `ENV_DENYLIST` for child process exec (`memfd_exec.rs:54-59`), which is good. However, `poison_environment` (`anti_analysis.rs:118`) replaces it with a decoy value rather than unsetting it -- a reverse engineer who knows the decoy value `deadbeef...` can distinguish it from a real secret.

### 1.4 Anti-Analysis Effectiveness

The anti-analysis module (`anti_analysis.rs`) implements five checks:

1. **TracerPid check** (`check_tracer_pid`): Reads `/proc/self/status`. Effective against naive `strace`/`gdb` attachment. Trivially bypassed by modifying the binary or using LD_PRELOAD.

2. **ptrace(TRACEME)** (`detect_ptrace`): If already traced, returns -1. Redundant with `anti_debug.rs`'s `ptrace(TRACEME)` -- the system calls it twice (once in `detect_ptrace` at line 141, once in `apply_protections` at line 18). The second call will always fail after the first succeeds, potentially triggering a false-positive debugger detection.

3. **Breakpoint scanning** (`detect_breakpoints`): Scans 32 bytes at the entry of three **stub probe functions** (`decrypt_payload_probe`, `verify_signature_probe`, `load_master_secret_probe`). These are `black_box(N)` stubs, not the actual critical functions. An attacker can set breakpoints on the real `unpack_payload`, `verify_signature`, or `reconstruct_secret` functions without triggering this check.

4. **Timing check** (`timing_check_with_profile`): Runs 100K iterations of a wrapping-add loop and checks if it exceeds 25ms. This is a blunt instrument that will false-positive under load and miss hardware-assisted debugging (e.g., Intel PT).

5. **VM detection** (`detect_virtual_machine`): Checks CPUID hypervisor bit, VM MAC prefixes, and DMI artifact files. This will flag **all** cloud instances (AWS, GCP, Azure) since they run on hypervisors. This means `is_being_analyzed()` returns `true` for the most common deployment targets, rendering it useless unless the operator disables it.

**Critical design flaw:** `is_being_analyzed()` combines debugger detection OR VM detection (`anti_analysis.rs:108-109`). Since most production environments are virtualized, this function would refuse to run on most target infrastructure.

### 1.5 Integrity Guarantees

The integrity system has two layers:

1. **Footer launcher_hash** (`assemble.rs:69`): SHA-256 of the launcher portion (with secret regions excluded) stored in the 65-byte footer. Verified by `verify_launcher_integrity` (`lib.rs:528-557`).

2. **Key-binding integrity** (`integrity.rs:94-110`): The decryption key is derived through the launcher binary bytes via `derive_key_with_integrity_from_binary`. Even without explicit verification, a tampered binary produces a different key that will fail AES-GCM decryption.

**What it covers:** Any modification to the launcher's code or non-excluded data segments will either fail the explicit integrity check (Linux) or fail decryption (all platforms, since the key derivation binds to binary content).

**What it misses:**
- On non-Linux: `derive_key_with_integrity_from_binary` falls back to `bind_secret_to_hash(embedded_secret, embedded_secret)` (`integrity.rs:108`) -- the key is **not** bound to binary content at all. An attacker could modify the launcher on macOS and the key derivation would still succeed.
- The integrity comparison in `verify_launcher_integrity` uses `==` (`lib.rs:537`) instead of constant-time comparison. `tamper.rs:61` correctly uses `ct_eq`, but this separate code path does not.
- The signature block is excluded from the integrity hash (it's stripped before verification at `lib.rs:109`), which is correct.

### 1.6 Fingerprint Binding

The fingerprint system (`snapfzz-seal-fingerprint`) collects:
- **Stable sources:** `/etc/machine-id` (HMAC'd if app_key set), hostname, kernel release, DMI product name, MAC addresses, kernel cmdline (allowlisted parameters)
- **Ephemeral sources:** PID namespace inode, boot ID, cgroup paths, container runtime indicators

Canonicalization (`canonical.rs`) sorts sources by ID and produces a SHA-256 hash with length-prefixed encoding, preventing extension attacks.

**Strengths:** Deterministic canonicalization; multiple signal sources; allowlist filtering for volatile cmdline parameters.

**Weaknesses:**
- All stable fingerprint sources are trivially spoofable by an attacker with root access (machine-id, hostname, kernel release, MAC addresses).
- The fingerprint is computed at compile time and baked into the key derivation. If any stable property changes legitimately (kernel update, hostname change), the sealed binary becomes non-functional with no recovery path except recompilation.
- No hardware-backed attestation (TPM, SGX).

### 1.7 Known Security Gaps (Critical to Low)

**1. [HIGH] VM detection blocks all cloud deployments**
`is_being_analyzed()` (`anti_analysis.rs:108-109`) returns true on any hypervisor, including production cloud instances. The CPUID hypervisor bit check (`anti_analysis.rs:242-243`) will flag AWS, GCP, and Azure.
*File:* `crates/snapfzz-seal-launcher/src/anti_analysis.rs:86-110`
*Fix:* Separate VM detection from debugger detection; make VM check opt-in or remove it.

**2. [HIGH] Non-Linux integrity binding is a no-op**
`derive_key_with_integrity_from_binary` on non-Linux returns `SHA256(secret || secret)` (`integrity.rs:108`), removing all binary-binding from the key. `verify_launcher_integrity` returns `Ok(())` unconditionally (`lib.rs:550-556`).
*File:* `crates/snapfzz-seal-core/src/integrity.rs:105-109`
*Fix:* On non-Linux, at minimum hash the binary and bind to it, even without ELF parsing.

**3. [HIGH] Pre-release crypto dependencies**
`aes-gcm = "0.11.0-rc.3"`, `aead = "0.6.0-rc.10"`, `aead-stream = "0.6.0-rc.3"` are release candidates. These may contain bugs not present in stable releases and may have breaking API changes.
*File:* `Cargo.toml:15-17`
*Fix:* Pin to stable releases when available, or document the risk explicitly.

**4. [MEDIUM] Decoy markers use fixed seed**
`embed_decoy_secrets` is called with seed `0` (`assemble.rs:48`). All decoys are deterministically derivable from the BUILD_ID and the constant `0`. An attacker who knows the BUILD_ID can distinguish decoy slots from live slots.
*File:* `crates/snapfzz-seal-compiler/src/assemble.rs:48`
*Fix:* Derive decoy seed from master secret.

**5. [MEDIUM] Breakpoint scan checks stub functions, not real targets**
`detect_breakpoints` scans `decrypt_payload_probe`, `verify_signature_probe`, `load_master_secret_probe` -- three no-op stubs -- not the actual `unpack_payload`, `verify_signature`, or `load_master_secret` functions.
*File:* `crates/snapfzz-seal-launcher/src/anti_analysis.rs:162-183`
*Fix:* Scan the actual critical function entry points.

**6. [MEDIUM] TOFU signature model**
`seal verify` without `--pubkey` uses the public key embedded in the signed binary (`verify.rs:14-16`). This provides no protection against an attacker who replaces both the signature and the embedded public key. Furthermore, `seal verify` returns exit code 0 for unsigned binaries with only a "WARNING: unsigned" message.
*File:* `crates/snapfzz-seal/src/verify.rs:14-16`
*Fix:* `seal verify` should return non-zero for unsigned binaries by default. Document that TOFU mode is not secure against binary replacement.

**7. [MEDIUM] Non-constant-time integrity comparison**
`verify_launcher_integrity` uses `==` for hash comparison (`lib.rs:537`), while the parallel `tamper.rs:61` correctly uses `ct_eq`. The launcher path leaks timing information about the expected hash.
*File:* `crates/snapfzz-seal-launcher/src/lib.rs:537`
*Fix:* Use `subtle::ConstantTimeEq` consistently.

**8. [MEDIUM] Non-constant-time Shamir field inversion**
The `pow` function in `FieldElement` (`shamir.rs:132-145`) uses variable-time square-and-multiply. The branching pattern leaks the exponent bits through timing.
*File:* `crates/snapfzz-seal-core/src/shamir.rs:132-145`
*Fix:* Use Montgomery ladder or constant-time exponentiation if side-channel resistance is desired.

**9. [LOW] Intermediate secrets not zeroized**
`env_key`, `integrity_bound_key`, and Shamir share arrays in `derive_decryption_key` and `extract_embedded_master_secret` are stack-allocated `[u8; 32]` values that are not explicitly zeroized.
*File:* `crates/snapfzz-seal-launcher/src/lib.rs:224-253, 486-526`
*Fix:* Wrap intermediates in `Zeroizing<[u8; 32]>`.

**10. [LOW] Double ptrace(TRACEME) call**
`detect_ptrace` in `anti_analysis.rs:141` and `apply_protections` in `anti_debug.rs:18` both call `ptrace(TRACEME)`. After the first succeeds, the process is already self-traced, so the second will fail and may trigger a false debugger detection positive.
*File:* `crates/snapfzz-seal-launcher/src/anti_analysis.rs:141` and `anti_debug.rs:18`
*Fix:* Consolidate into a single ptrace call or coordinate between modules.

**11. [LOW] Workspace strip = true may interfere with marker embedding**
The workspace `Cargo.toml` sets `strip = true` in the release profile (`Cargo.toml:52`). The commit history shows a fix for Nuitka backend (`edeeb7a`), but the launcher binary's markers are placed in a `#[link_section]` data segment. Stripping should not affect `.data` sections, but this is toolchain-dependent.
*File:* `Cargo.toml:52`

**12. [LOW] Poison environment writes to predictable paths**
`poison_environment` writes decoy files to `/tmp/.snapfzz_seal_cache`, `/tmp/.snapfzz_key_backup`, `/var/tmp/snapfzz_debug.log` (`anti_analysis.rs:131-136`). These are easily identifiable by an analyst and serve as indicators of Snapfzz Seal execution.
*File:* `crates/snapfzz-seal-launcher/src/anti_analysis.rs:131-136`

---

## 2. Practical Utility

### 2.1 Use Case Fit

**Solves well:**
- Packaging an AI agent binary into a single encrypted, environment-bound artifact
- Preventing casual/opportunistic extraction of agent logic and embedded secrets
- Ensuring payload integrity via Ed25519 signatures
- Supporting multiple compilation backends (Go, PyInstaller, Nuitka)

**Does NOT solve:**
- Protection against a skilled reverse engineer with access to a running instance (anti-debug/anti-analysis are speed bumps, not barriers)
- Cross-platform execution (Linux-only for the runtime; macOS limited to compile+sign+verify)
- Key distribution (no PKI, no key rotation, no revocation)
- Runtime secret injection (secrets are baked in at compile time)
- Hardware-attested environment binding

### 2.2 Operational Complexity

**BUILD_ID discipline** is the primary operational hazard. If `snapfzz-seal-core` and `snapfzz-seal-launcher` are built with different BUILD_ID values, the resulting binary is silently non-functional -- the embedded markers will not match. The README documents this clearly, and the E2E test enforces a single `cargo build --release` invocation. However, in CI/CD pipelines with caching, incremental builds, or separate build stages, this is a likely failure mode.

**Linux-only execution** means the sealed binary cannot run on macOS or Windows. The compile step works on macOS, but the output must be deployed to Linux. This is reasonable for server-side agents but limits desktop/edge use cases.

**Backend tooling requirements** (Nuitka, PyInstaller, Go compiler) must be available at build time. Nuitka on macOS is explicitly broken in onefile mode. Docker is the recommended build environment for Nuitka.

### 2.3 Developer Experience

**CLI ergonomics** are good. The `seal` CLI uses `clap` with derive macros, provides clear subcommands (`compile`, `keygen`, `launch`, `server`, `sign`, `verify`), and surfaces descriptive error messages via `format_user_error` (`lib.rs:269-293`).

**Error messages** are specific. Fingerprint mismatches produce a clear user-facing message: "fingerprint mismatch -- sandbox environment has changed, re-provisioning required" (`lib.rs:171-175`). Missing markers report which marker index is absent.

**Documentation** is thorough. The README covers architecture, binary layout, security model with honest limitations, usage examples, and payload format reference. The security model section explicitly states what is fully implemented vs. partial vs. Linux-only.

**Debugging** is supported via `--verbose` flag and `RUST_LOG` environment variable integration.

**Weakness:** No `seal inspect` or `seal info` command to examine a sealed binary's metadata (backend type, signature status, fingerprint mode) without attempting decryption.

### 2.4 Production Readiness

**Blocking issues:**
1. Pre-release crypto dependencies (aes-gcm RC, aead RC) -- not suitable for production without pinning to stable releases
2. VM detection in `is_being_analyzed()` will reject all cloud-hosted deployments
3. No key rotation or revocation mechanism
4. No migration path when fingerprint sources change (kernel updates, hostname changes)
5. White-box AES tables are embedded (~165KB overhead) but not used in any runtime path

**Non-blocking but notable:**
- `seal verify` exits 0 for unsigned binaries (confusing for CI pipelines)
- No support for Windows targets
- No telemetry or audit logging for launch attempts
- `--max-lifetime` flag exists but the README notes it is "not forwarded to the launcher binary itself in the current implementation"

### 2.5 Helpfulness Score Breakdown

| Dimension | Score | Justification |
|---|---|---|
| Core functionality | 8/10 | Compile-seal-sign-verify pipeline works reliably across three backends with 465 passing tests |
| Security value-add | 6/10 | Strong crypto primitives, but anti-analysis and anti-tamper are limited to speed bumps on Linux and no-ops elsewhere |
| Documentation | 8/10 | Honest, detailed, covers architecture and limitations. Missing `seal inspect` command and troubleshooting guide |
| CLI ergonomics | 7/10 | Clean clap-based interface with good error messages. Missing binary inspection tool. `seal verify` exit-code behavior is surprising |
| Operational fitness | 5/10 | BUILD_ID fragility, Linux-only execution, no key management, no fingerprint migration, VM detection breaks cloud deployments |
| Test coverage | 8/10 | 465 unit tests, E2E scripts for all backends. Tests cover round-trips, edge cases, and error paths. Missing: integration tests that exercise the full launcher on Linux |
| Code quality | 8/10 | Idiomatic Rust, workspace lints enforced, `unsafe_code = "deny"` at workspace level (overridden where needed in launcher). Consistent error handling with `SealError` |

---

## 3. Recommendations

### Critical

1. **Remove or gate VM detection in `is_being_analyzed()`** -- The current implementation rejects all cloud/VM environments. Either remove `detect_virtual_machine()` from `is_being_analyzed()`, make it configurable, or move it behind a feature flag. This is the single highest-impact production blocker.

2. **Upgrade to stable crypto dependencies** -- Pin `aes-gcm`, `aead`, and `aead-stream` to stable releases. Using release candidates in a security-critical system is unacceptable for production.

### High

3. **Fix non-Linux integrity binding** -- On non-Linux platforms, `derive_key_with_integrity_from_binary` should still hash the binary and bind the key to it. The current fallback of `SHA256(secret || secret)` removes all binary-binding protection.

4. **Use constant-time comparison in `verify_launcher_integrity`** -- Replace `==` with `subtle::ConstantTimeEq` at `lib.rs:537` to match the pattern already used in `tamper.rs:61` and `payload.rs:91`.

5. **Make `seal verify` return non-zero for unsigned binaries** -- Exit code 0 with "WARNING: unsigned" is a footgun for CI/CD pipelines. Add a `--require-signature` flag or change the default.

### Medium

6. **Derive decoy seed from master secret** -- Change `embed_decoy_secrets(&launcher_with_secret, 0)` to use a seed derived from the master secret, making decoys indistinguishable from live slots without the secret.

7. **Fix breakpoint scanning to cover actual critical functions** -- Replace stub probe functions with pointers to real `unpack_payload`, `verify_signature`, and `reconstruct_secret` entry points.

8. **Add `seal inspect` command** -- Allow operators to examine a sealed binary's metadata (backend type, signature presence, payload size, BUILD_ID if recoverable) without attempting decryption.

9. **Complete white-box AES integration or remove the dead code** -- The ~165KB of embedded lookup tables contribute to binary size but provide no runtime security benefit. Either integrate them into the key reconstruction path or remove them to reduce attack surface and binary size.

10. **Zeroize intermediate secrets** -- Wrap `env_key`, `integrity_bound_key`, and Shamir share arrays in `Zeroizing` wrappers.

### Low

11. **Consolidate ptrace calls** -- Coordinate between `anti_analysis.rs` and `anti_debug.rs` to avoid double `ptrace(TRACEME)` and potential false positives.

12. **Randomize poison environment paths** -- Use runtime-generated paths instead of hardcoded `/tmp/.snapfzz_seal_cache` etc. to avoid creating reliable indicators of Snapfzz Seal execution.

13. **Document BUILD_ID failure mode in error messages** -- When marker embedding fails, include a hint about BUILD_ID mismatch in the error message, not just "marker N not found."

14. **Implement `--max-lifetime` forwarding** -- The flag is accepted but not forwarded to the launcher binary. Either implement it or remove it from the CLI.
