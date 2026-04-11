# Snapfzz Seal — Decryption Enhancement Implementation Report

**Document type:** Technical implementation report
**Audit date:** April 2026
**Source revision:** `main` branch (HEAD: `edeeb7a`)
**Scope:** Layers 1–6 of the defense-in-depth enhancement described in `ENHANCEMENT_SPEC.md`

---

## 1. Executive Summary

Six defense-in-depth layers were specified. As of the audited revision, four layers are fully implemented and integrated into the runtime execution path. Two layers are partially implemented: generated artifacts exist on disk but are not yet consumed by the launcher at runtime.

| Layer | Description | Integration Status |
|-------|-------------|-------------------|
| 1 | No Observable Patterns | Implemented |
| 2 | Shamir Secret Sharing | Implemented |
| 3 | Decoy Secrets | Partial — position hint only; decoy shares not embedded |
| 4 | Anti-Analysis | Implemented |
| 5 | Integrity Binding | Implemented |
| 6 | White-Box Cryptography | Partial — tables appended; runtime path uses standard AES-GCM |

The two partial layers are discussed in detail in Sections 5.3 and 5.6.

---

## 2. Compiler Pipeline

The assembly pipeline is implemented in `crates/snapfzz-seal-compiler/src/assemble.rs`,
function `assemble()`. The sequence of operations is as follows:

1. The agent ELF binary and launcher binary are read from disk.
2. An environment key is derived via `derive_env_key(master_secret, stable_fingerprint_hash, user_fingerprint)` (`snapfzz-seal-core/src/derive.rs`).
3. The master secret is split into five Shamir shares and each share is written into the launcher binary at the offset following its corresponding compile-time marker, via `embed_master_secret()` (`embed.rs`).
4. `embed_decoy_secrets()` (`decoys.rs`) is called with `real_index = 0`. A random salt and obfuscated position hint are computed; the hint is written into the binary if the marker `ASL_POSITION_HINT_v1` is present. Decoy share bytes are not written.
5. A SHA-256 hash of the decoy-modified launcher is computed and written after the tamper marker via `embed_tamper_hash()` (`embed.rs`).
6. White-box tables are generated for the master key via `WhiteBoxAES::generate_tables()` and appended to the binary via `embed_whitebox_tables()` (`whitebox_embed.rs`).
7. Integrity regions are located via `find_integrity_regions()` (`integrity.rs`) and a SHA-256 hash of the non-secret regions is computed via `compute_binary_integrity_hash()`.
8. The integrity-bound key is derived via `derive_key_with_integrity_from_binary(env_key, launcher_bytes)`.
9. The agent binary is encrypted via `pack_payload_with_mode()` using the integrity-bound key.
10. A footer (`PayloadFooter`) containing the original agent hash, the launcher integrity hash, and a backend-type discriminant is serialized via `write_footer()`.
11. The assembled binary is returned as `[launcher_with_tables | LAUNCHER_PAYLOAD_SENTINEL | encrypted_payload | footer]`.

---

## 3. Runtime Launch Flow

The runtime launch sequence is implemented in `crates/snapfzz-seal-launcher/src/lib.rs`,
function `run()`. The sequence is as follows:

1. The raw binary is loaded from `--payload` or from `/proc/self/exe`.
2. A trailing 100-byte Ed25519 signature block (magic `ASL\x02`) is stripped from the binary. Payload and footer offsets are computed on the stripped binary.
3. The payload header is validated. The signature is verified over the pre-strip binary via `verify_signature()`.
4. The launcher integrity hash in the footer is verified against the launcher portion of the loaded binary via `verify_launcher_integrity()`.
5. `anti_analysis::is_being_analyzed()` is called. If it returns `true`, execution is aborted with an error.
6. Anti-debug protections are applied via `protection::apply_protections()` (`anti_debug.rs`): `PR_SET_DUMPABLE` is cleared via `prctl(2)` and `PTRACE_TRACEME` is requested via `ptrace(2)`. Both calls are best-effort; failure generates a warning rather than an error.
7. `anti_analysis::poison_environment()` deposits three decoy environment variables and three decoy files under `/tmp` and `/var/tmp`.
8. A fingerprint snapshot is collected. Depending on `--fingerprint-mode`, either stable-only or full fingerprints are used.
9. The master secret is reconstructed from the five Shamir shares embedded in the binary via `load_master_secret()` → `reconstruct_secret()` (`shamir.rs`).
10. The decryption key is derived via `derive_decryption_key()`, which calls `derive_env_key()` followed by `derive_key_with_integrity_from_binary()`. On Linux, the integrity hash is also computed separately for diagnostic purposes.
11. The encrypted payload (excluding the footer) is decrypted via `unpack_payload()` (standard AES-GCM).
12. Key material is zeroized via the `zeroize` crate.
13. The sealed binary self-deletes via `cleanup::self_delete()` when operating from the self-embedded payload.
14. The decrypted agent binary is executed via `MemfdExecutor` (Go backend, Unknown backend) or `TempFileExecutor` (PyInstaller, Nuitka backends).

---

## 4. Implemented Layers

### 4.1 Layer 1 — No Observable Patterns

**Modules:** `crates/snapfzz-seal-core/src/types.rs`, `crates/snapfzz-seal-core/build.rs`

All markers used for secret-share slots, the tamper-detection slot, the payload sentinel, and the position hint are 32-byte values generated at build time from a hash of build metadata. The function `get_secret_marker(index: usize) -> &'static [u8; 32]` returns the compile-time marker for each of the five share slots. `LAUNCHER_TAMPER_MARKER` and `LAUNCHER_PAYLOAD_SENTINEL` are similarly opaque constants.

No human-readable string identifies any secret-bearing location in the binary.

---

### 4.2 Layer 2 — Shamir Secret Sharing

**Modules:** `crates/snapfzz-seal-core/src/shamir.rs`, `crates/snapfzz-seal-compiler/src/embed.rs`

A (3, 5) Shamir threshold scheme is implemented over the secp256k1 prime field
(modulus `p = 2^256 - 2^32 - 977`, i.e., `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`).
The implementation is pure Rust with no external cryptographic crate dependency for the field arithmetic.

**Split (`split_secret_with_rng`):** A degree-(threshold−1) polynomial is constructed with the secret as the constant term and `threshold−1` randomly generated non-zero field elements as higher-order coefficients. Shares are the evaluations of this polynomial at x = 1 through x = total_shares.

**Reconstruction (`reconstruct_secret`):** Lagrange interpolation at x = 0 is performed over the provided subset of shares. Duplicate and zero indices are rejected.

**Embedding (`embed_master_secret`):** Each of the five shares is written into the launcher binary immediately after its corresponding 32-byte marker. The function `find_marker_with_slot()` skips false-positive occurrences of a marker byte sequence where the immediately following bytes contain another known marker, preventing misalignment.

**Recovery at runtime:** `load_master_secret()` in `lib.rs` locates the five markers within the loaded binary, reads the 32-byte share following each, and calls `reconstruct_secret()` with the full five shares and threshold 3.

**Tests:** Unit tests in `embed.rs` and `shamir.rs` cover round-trip reconstruction, threshold-boundary failure, duplicate index rejection, zero-index rejection, and marker-slot collision avoidance.

---

### 4.3 Layer 4 — Anti-Analysis

**Modules:** `crates/snapfzz-seal-launcher/src/anti_analysis.rs`, `crates/snapfzz-seal-launcher/src/anti_debug.rs` (called as `protection`)

Detection is performed by `is_being_analyzed()`, which returns the logical OR of `detect_debugger()` and `detect_virtual_machine()`.

**Debugger detection (`detect_debugger`):**

- On Linux: reads `/proc/self/status` and inspects the `TracerPid` field (`check_tracer_pid`). A non-zero value indicates an attached tracer.
- On Linux: calls `ptrace(PTRACE_TRACEME, ...)` via `libc`; a return of −1 indicates the process is already traced (`detect_ptrace`).
- On all platforms: scans the first 32 bytes of three probe functions (`decrypt_payload_probe`, `verify_signature_probe`, `load_master_secret_probe`) for the INT3 opcode (0xCC) to detect software breakpoints (`detect_breakpoints`).
- On all platforms: runs a tight 100,000-iteration loop twice and compares elapsed time against a threshold of 50× a 500-microsecond baseline. Exceeding the threshold on both runs is treated as an instrumentation anomaly (`timing_check_with_profile`).

**VM detection (`detect_virtual_machine`):**

- On x86_64: reads the CPUID hypervisor present bit (ECX bit 31 of leaf 1) via `__cpuid(1)` (`check_cpuid_hypervisor`).
- On Linux: reads the files `/sys/class/dmi/id/product_name`, `/sys/class/dmi/id/board_vendor`, `/sys/class/dmi/id/sys_vendor`, `/proc/scsi/scsi`, and `/proc/cpuinfo` for the presence of VM-identifying keywords (`check_vm_artifacts`).
- On Linux: reads `/sys/class/net/<iface>/address` for a set of known VM vendor OUI prefixes (`check_vm_mac_address`).

**Environment poisoning (`poison_environment`):**

Sets three environment variables (`SNAPFZZ_SEAL_MASTER_SECRET_HEX`, `SNAPFZZ_SEAL_DEBUG`, `SNAPFZZ_SEAL_TRACE`) to decoy values, and writes the byte sequence `DECOY_DATA_DO_NOT_USE` to `/tmp/.snapfzz_seal_cache`, `/tmp/.snapfzz_key_backup`, and `/var/tmp/snapfzz_debug.log`.

**Active anti-debug protections (`protection::apply_protections`, formerly `anti_debug.rs`):**

On Linux, `prctl(PR_SET_DUMPABLE, 0)` disables core dumps and ptrace attachment by unprivileged processes. `ptrace(PTRACE_TRACEME)` is also requested to prevent a second tracer from attaching. Both are best-effort.

**Limitation:** The VM detection checks are heuristic and are known to produce false positives in certain cloud and container environments. The breakpoint scan operates on probe functions that serve no functional purpose and may be removed by an optimizing linker if not marked `#[inline(never)]` (they are currently so marked).

---

### 4.4 Layer 5 — Integrity Binding

**Module:** `crates/snapfzz-seal-core/src/integrity.rs`

**Region discovery (`find_integrity_regions`):**

- On Linux, if the binary begins with the ELF64 little-endian x86_64 magic (`\x7fELF` + class 2 + data 1 + machine 0x3e), ELF program headers are parsed via `parse_elf_regions()`. PT_LOAD segments with the execute flag set contribute to the code range; all others contribute to the data range.
- On all other platforms and on non-ELF binaries, the entire binary is treated as the code region.

**Exclusion (`find_secret_regions`):**

The following byte ranges are excluded from hashing:
- The 32-byte marker plus the 32-byte share slot for each of the five Shamir markers.
- The 32-byte tamper marker plus the following 32 bytes.
- All bytes from the `LAUNCHER_PAYLOAD_SENTINEL` to end-of-binary.

Overlapping excluded ranges are merged before use.

**Hash computation (`compute_binary_integrity_hash`):**

A SHA-256 digest is computed over the included portions of the code and data regions. Excluded ranges within those regions are skipped without substitution; only the bytes outside exclusions are fed to the hasher. At least one non-empty region must exist; an error is returned otherwise.

**Key derivation (`derive_key_with_integrity_from_binary`):**

On Linux: `SHA-256(embedded_secret || integrity_hash)` via `bind_secret_to_hash()`.
On non-Linux: `SHA-256(embedded_secret || embedded_secret)` (the integrity hash is replaced by the secret itself, making the derived key deterministic but non-integrity-bound).

**Runtime path:** `derive_decryption_key()` in `lib.rs` calls `derive_key_with_integrity_from_binary()` to produce the key passed to `unpack_payload()`. The tamper hash embedded at compile time (Layer 1 / `embed_tamper_hash`) is also checked via `verify_launcher_integrity()` before secret reconstruction begins.

**Seccomp:** `crates/snapfzz-seal-launcher/src/seccomp.rs` provides `apply_seccomp_filter()`, which installs a BPF allowlist on Linux x86_64 (`seccompiler` crate). The filter permits a defined set of approximately 90 syscall numbers and returns `EPERM` for all others. This function is available in the module but its call site in `lib.rs` was not observed in the audited 300-line excerpt; further review is required to confirm whether it is applied during the runtime path.

---

## 5. Partial Implementations

### 5.1 Layer 3 — Decoy Secrets (Partial)

**Module:** `crates/snapfzz-seal-compiler/src/decoys.rs`

**What is implemented:**

- `generate_decoy_secret(set_index)` produces 10 deterministic 32-byte pseudo-secrets via SHA-256 keyed on `"DECOY_SECRET_V1"`, the set index, and a compile-time `POSITION_HINT_SALT` constant.
- `obfuscate_real_position(real_index, salt)` and `determine_real_position(hint, salt)` implement a SHA-256-based position encoding that survives round-trip under the same salt.
- `embed_decoy_secrets(binary, real_index)` generates a random salt, computes the position hint, and writes the hint to the binary if the marker `ASL_POSITION_HINT_v1` is found.

**What is not implemented:**

The generated decoy secret values are not written into the binary. Within `embed_decoy_secrets()`, the result of `generate_all_decoys()` is assigned to `_decoys` and immediately discarded. No decoy share bytes are appended to the binary. An attacker enumerating all marker-adjacent regions therefore encounters only the five real shares and the tamper slot, not 50 additional fake shares.

**Impact:** The position-hint obfuscation is present but provides limited value without corresponding decoy bytes in the binary.

---

### 5.2 Layer 6 — White-Box Cryptography (Partial)

**Modules:**
- `crates/snapfzz-seal-core/src/whitebox/aes.rs`
- `crates/snapfzz-seal-core/src/whitebox/tables.rs`
- `crates/snapfzz-seal-compiler/src/whitebox_embed.rs`

**What is implemented:**

- `WhiteBoxAES::generate_tables(master_key)` produces a `WhiteBoxTables` struct containing 224 T-boxes, 13 Type-I mixing tables, and 13 Type-II mixing tables. The total serialized size exceeds 100 KB and is bounded below 5 MB (verified by test).
- `embed_whitebox_tables(binary, tables)` appends the marker `ASL_WB_TABLES_v1` followed by the serialized table bytes to the binary. If the marker is already present, the table bytes are written in-place beginning at the offset immediately following the marker.
- The `assemble()` function in `assemble.rs` calls both functions as part of the compile pipeline. Tables are therefore present in all assembled binaries.

**What is not implemented:**

The launcher's `run()` function does not invoke any white-box decryption routine. Payload decryption in `lib.rs` is performed by `unpack_payload()`, which uses standard AES-GCM via the `aes-gcm` crate. The `WhiteBoxTables` data appended to the binary is not read at runtime.

**Consequence:** Layer 6 currently adds binary size overhead (~100 KB–5 MB) without providing cryptographic protection. The decryption key is recoverable from the AES-GCM ciphertext context if an attacker can attach to the process or inspect memory at decryption time.

**Outstanding work:**
1. A white-box AES decryption function consuming the embedded `WhiteBoxTables` must be implemented.
2. The runtime key derivation or payload decryption in `lib.rs` must be updated to use that function.
3. The table generation implementation requires review by a cryptographer before production deployment.

---

## 6. Known Gaps and Discrepancies

The following discrepancies exist between the ENHANCEMENT_SPEC and the audited implementation:

| Item | Specification | Implemented |
|------|---------------|-------------|
| Layer 3 decoy embedding | 10 sets × 5 shares = 50 decoy share bytes written to binary | Position hint only; decoy bytes not written |
| Layer 4 module name | `anti_analysis.rs` (described in spec) | Two modules: `anti_analysis.rs` (detection and poisoning) and `anti_debug.rs` (active protections via `prctl`/`ptrace`); the latter is called as `protection` in `lib.rs` |
| Layer 5 function signature | `compute_binary_integrity_hash(binary, excluded: &[(usize, usize)])` | `compute_binary_integrity_hash(binary, regions: &IntegrityRegions)` — exclusions are stored inside `IntegrityRegions.excluded` |
| Layer 5 function signature | `derive_key_with_integrity(encrypted_secret, binary_path: &str)` | Two functions exist: `derive_key_with_integrity(secret, binary_path: Option<&str>)` (reads file) and `derive_key_with_integrity_from_binary(secret, binary: &[u8])` (operates on bytes directly); the runtime path uses the latter |
| Layer 6 runtime integration | Tables used for payload decryption | Tables appended but not consumed at runtime |
| Non-Linux integrity | Not specified | `derive_key_with_integrity_from_binary` on non-Linux returns `SHA-256(secret || secret)` rather than an integrity-bound value, effectively skipping Layer 5 on those platforms |

---

## 7. Security Assessment

### 7.1 Implemented Protections

The following attack classes are addressed by the implemented layers:

- **Static string extraction** (Layer 1): Marker values are compile-time random; no human-readable identifier locates the secret in the binary.
- **Single-region extraction** (Layer 2): Reconstruction requires locating and correctly combining any three of five disjoint 32-byte regions.
- **Offline binary patching** (Layer 5): Modification of any covered byte region changes the integrity hash and causes the derived key to differ from the compile-time key, producing a decryption failure.
- **Runtime debugging** (Layer 4): `PTRACE_TRACEME` and `PR_SET_DUMPABLE` are applied. `/proc/self/status` TracerPid, software breakpoints, and timing anomalies are checked. Process aborts if any heuristic fires.
- **VM-based analysis** (Layer 4): CPUID hypervisor bit, DMI/system file keywords, and MAC address OUI prefixes are checked on Linux x86_64.

### 7.2 Unaddressed Attack Vectors

The following vectors remain unmitigated as of the audited revision:

- **Memory dump during decryption:** The decryption key and plaintext are present in process memory. An attacker with a memory read primitive (e.g., via ptrace after the anti-debug window, or from a kernel exploit) can extract both.
- **Runtime key extraction (no Layer 6):** Because payload decryption uses standard AES-GCM, the AES key is visible in memory in its expanded form and is potentially derivable from a memory snapshot.
- **Layer 3 bypass:** Because no decoy shares are embedded, an attacker enumerating marker-adjacent byte regions immediately identifies all five real shares.
- **Non-Linux integrity bypass:** Layer 5 does not provide integrity binding on non-Linux platforms. The key is derived from `SHA-256(secret || secret)`, which is a fixed function of the embedded secret and requires no binary hash.
- **Side-channel attacks:** Timing and power analysis of the current AES-GCM path are not addressed.
- **Nation-state / hardware attacks:** No TPM or HSM integration is present.

---

## 8. Test Coverage

Unit and integration tests are present for all implemented components:

- `shamir.rs`: 9 tests covering split and reconstruct round-trips, threshold boundary conditions, duplicate indices, zero indices, and out-of-range secrets.
- `embed.rs`: 6 tests covering share-slot replacement, tamper-hash replacement, false-positive marker skipping, slot-length error handling, and missing-marker error handling.
- `integrity.rs`: 6+ tests covering excluded region enumeration, hash sensitivity to non-excluded mutations, ELF segment detection (Linux only), integrity verification accept/reject, and non-Linux fallback determinism.
- `anti_analysis.rs`: 12+ tests covering timing check helpers, breakpoint detection, VM keyword and MAC prefix matching, and environment poisoning.
- `whitebox_embed.rs`: 4 tests covering table structure, size bounds, marker-absent embedding, and marker-present in-place replacement.
- `assemble.rs`: 6 tests covering end-to-end assembly correctness, payload round-trip, footer parsing, and I/O error propagation.

All tests were observed to be compilable and structured to pass on a clean build. Test count claimed in prior documentation (98 for the launcher crate) was not independently verified in this audit.

---

## 9. Recommendations

The following actions are recommended in priority order:

1. **Complete Layer 3 (Decoy Embedding):** Write the generated decoy share bytes into the binary at markers associated with each of the 10 decoy sets, so that an attacker enumerating marker-adjacent regions encounters 55 structurally indistinguishable candidates.

2. **Complete Layer 6 Runtime Integration:** Implement a white-box AES decryption function and wire it into the payload decryption path in `lib.rs`. Until this is done, the tables add binary size with no security benefit.

3. **Cryptographic Audit of Layer 6:** Engage a qualified cryptographer to review the white-box table generation in `whitebox/aes.rs` before Layer 6 is activated in production.

4. **Verify Seccomp Activation:** Confirm that `seccomp::apply_seccomp_filter()` is called in the runtime launch path. If it is not, add the call site.

5. **Non-Linux Integrity:** Document the non-Linux fallback behavior explicitly, or implement a platform-agnostic integrity check that does not silently degrade to a fixed-value hash.
