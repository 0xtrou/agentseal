# Snapfzz Seal — Decryption Enhancement Specification

**Document type:** Design specification
**Status:** Partially implemented (see Section 6 for layer-by-layer status)
**Scope:** Defense-in-depth measures preventing trivial extraction of the master secret from sealed binaries

---

## 1. Problem Statement

Prior to the enhancements described herein, the master secret embedded in a sealed binary was stored as a contiguous, marker-delimited plaintext block. An attacker with read access to the binary could recover the secret by locating the known string literal marker (e.g., `"ASL"`) using standard tools such as `strings(1)` or `grep(1)`. The extraction time under that model was on the order of minutes.

The objective of this specification is to raise the practical cost of secret extraction to weeks or months of skilled reverse-engineering effort.

---

## 2. Target Architecture

The proposed defense model consists of six independent but complementary layers:

```
Layer 1 — No Observable Patterns     (compile-time random markers)
Layer 2 — Shamir Secret Sharing      (3-of-5 split of the master secret)
Layer 3 — Decoy Secrets              (10 indistinguishable fake secret sets)
Layer 4 — Anti-Analysis              (debugger and VM detection at runtime)
Layer 5 — Integrity Binding          (decryption key tied to binary hash)
Layer 6 — White-Box Cryptography     (key-hiding AES table construction)
```

Layers are designed to be independently deployable; failure or absence of one layer does not invalidate the others.

---

## 3. Data Structures (Specified)

The following data structures were defined in the original specification. Not all are reflected in the current implementation exactly as written; see Section 6 for the implemented forms.

### 3.1 Marker System

```rust
pub struct BinaryMarkers {
    pub secret_markers: [[u8; 32]; 5],   // real secret markers (3-of-5 needed)
    pub tamper_marker:  [u8; 32],         // tamper detection marker
    pub payload_sentinel: [u8; 32],       // payload boundary marker
    pub decoy_markers: Vec<[[u8; 32]; 5]>, // 10 sets of 5 decoy markers
    pub position_hint: [u8; 32],          // obfuscated real-position hint
}
```

### 3.2 Shamir Share Record

```rust
pub struct SecretShare {
    pub marker_index:      usize,
    pub location:          usize,
    pub encrypted_share:   [u8; 32],
    pub location_key:      [u8; 32], // XOR obfuscation key
}
```

### 3.3 Integrity Regions

```rust
pub struct IntegrityRegions {
    pub code_start: usize,
    pub code_end:   usize,
    pub data_start: usize,
    pub data_end:   usize,
    pub excluded_regions: Vec<(usize, usize)>, // secret slot locations
}
```

Note: The implemented `IntegrityRegions` struct in
`crates/snapfzz-seal-core/src/integrity.rs` uses the field name `excluded`
rather than `excluded_regions`.

---

## 4. Layer Specifications

### Layer 1 — No Observable Patterns

**Goal:** Eliminate all fixed, searchable byte sequences that identify secret-bearing locations.

**Mechanism:** All markers (secret-share slots, tamper slot, payload sentinel, decoy position hint) are generated from a build-time hash. No human-readable string literals are used as markers.

**Specified functions:**

```rust
// snapfzz-seal-core (build.rs)
fn generate_random_marker(seed: &[u8]) -> [u8; 32];
fn generate_all_markers(build_id: &str) -> BinaryMarkers;

// snapfzz-seal-core (types.rs)
pub fn get_secret_marker(index: usize) -> &'static [u8; 32];
pub fn get_tamper_marker()             -> &'static [u8; 32];
pub fn get_payload_sentinel()          -> &'static [u8; 32];
```

**Success criterion:** A binary produced by the compiler must contain no string matches for `"SECRET"`, `"MARKER"`, `"ASL"`, or similar identifying literals in marker positions.

---

### Layer 2 — Shamir Secret Sharing

**Goal:** Require an attacker to locate and correctly combine at least three of five disjoint byte regions to reconstruct the master secret.

**Mechanism:** The master secret is split using a (3, 5) Shamir threshold scheme over a finite field. Each share is embedded into the launcher binary at the location following a randomly-generated 32-byte marker.

**Specified functions:**

```rust
// embed.rs
fn split_master_secret(
    master:    &[u8; 32],
    threshold: usize,
    total:     usize,
) -> Result<Vec<[u8; 32]>, SealError>;

fn embed_shares_with_obfuscation(
    binary:  &mut Vec<u8>,
    shares:  &[[u8; 32]],
    markers: &[[u8; 32]],
) -> Result<Vec<SecretShare>, SealError>;

fn reconstruct_master_secret(
    binary:  &[u8],
    markers: &[[u8; 32]],
) -> Result<[u8; 32], SealError>;
```

**Parameters:** SHAMIR_THRESHOLD = 3, SHAMIR_TOTAL_SHARES = 5 (defined in `snapfzz-seal-core/src/types.rs`).

---

### Layer 3 — Decoy Secrets

**Goal:** Force the attacker to distinguish the real secret-share set from 10 structurally identical fake sets, multiplying brute-force search space by a factor of 11.

**Mechanism:** Ten deterministically-generated fake secret values are embedded alongside the real shares. A salted position-hint value is embedded at a known marker location to allow legitimate reconstruction while being opaque without the salt.

**Specified functions:**

```rust
// embed.rs / decoys.rs
fn generate_decoy_secret(index: usize)                   -> [u8; 32];
fn embed_decoy_secrets(binary: &mut Vec<u8>, count: usize) -> Result<(), SealError>;
fn obfuscate_real_position(real_index: usize)             -> [u8; 32];
fn determine_real_position(hint: &[u8; 32])               -> usize;
```

Note: The implemented signatures diverge slightly; see Section 6.

---

### Layer 4 — Anti-Analysis

**Goal:** Detect debuggers and virtual machines at runtime and refuse to proceed with key reconstruction under those conditions.

**Mechanism:** Multiple independent detection heuristics are applied. If any heuristic indicates an analysis environment, execution is aborted. A separate environment-poisoning step deposits misleading files and environment variables to confuse a passive observer.

**Specified functions:**

```rust
// anti_analysis.rs
pub fn detect_debugger()       -> bool;
pub fn detect_virtual_machine() -> bool;
pub fn is_being_analyzed()     -> bool;
pub fn poison_environment();
```

---

### Layer 5 — Integrity Binding

**Goal:** Prevent offline patching attacks by binding the decryption key to a hash of the launcher binary's non-secret regions. Modification of any covered byte causes decryption to fail.

**Mechanism:** At compile time, an integrity hash is computed over the ELF code and data segments, excluding the secret-share slots, tamper-marker slot, and appended payload. At runtime, the decryption key is derived as `SHA-256(env_key || integrity_hash)`.

**Specified functions:**

```rust
// integrity.rs
pub fn compute_binary_integrity_hash(
    binary:   &[u8],
    excluded: &[(usize, usize)],
) -> Result<[u8; 32], SealError>;

pub fn derive_key_with_integrity(
    encrypted_secret: &[u8],
    binary_path:      &str,
) -> Result<[u8; 32], SealError>;

pub fn verify_binary_integrity(
    expected_hash: &[u8; 32],
) -> Result<(), SealError>;
```

---

### Layer 6 — White-Box Cryptography

**Goal:** Conceal the AES round keys such that even an attacker with full memory access during decryption cannot trivially extract the key material.

**Mechanism:** The Chow et al. (2002) white-box AES construction is used. T-boxes combining SubBytes and AddRoundKey transformations are generated per master key. Additional Type-I and Type-II mixing tables are produced. Tables are embedded into the compiled artifact and used in place of standard AES during payload decryption.

**Specified functions:**

```rust
// whitebox_embed.rs / whitebox/aes.rs
pub fn generate_whitebox_tables(master_key: &[u8; 32]) -> WhiteBoxTables;
pub fn embed_whitebox_tables(binary: &[u8], tables: &WhiteBoxTables) -> Result<Vec<u8>, SealError>;
```

**Implementation priority:** Highest. Without Layer 6, a sufficiently skilled attacker can recover the key from memory at runtime.

---

## 5. Dependencies

```toml
[dependencies]
sha2     = "0.10"
rand     = "0.8"
zeroize  = "1.5"
# Shamir implemented in-house; no external crate dependency
```

---

## 6. Implementation Status

The following table reflects the status as determined by source-code audit (April 2026):

| Layer | Description | Status |
|-------|-------------|--------|
| 1 | No Observable Patterns — compile-time random markers | Implemented |
| 2 | Shamir Secret Sharing — (3, 5) split over secp256k1 prime field | Implemented |
| 3 | Decoy Secrets — 10 fake sets with position hint | Partial — decoy values generated; actual decoy shares are not embedded into the binary (see note) |
| 4 | Anti-Analysis — debugger / VM detection, environment poisoning | Implemented |
| 5 | Integrity Binding — key derived from binary hash, ELF-aware exclusions | Implemented |
| 6 | White-Box Cryptography — T-box and mixing-table generation and embedding | Partial — tables generated and appended to binary; runtime decryption path still uses standard AES-GCM |

**Note on Layer 3:** `embed_decoy_secrets()` in `decoys.rs` generates decoy values and computes a position hint but does not currently write decoy Shamir share bytes into the binary. The `_decoys` binding is explicitly suppressed. Runtime reconstruction therefore has no decoy shares to encounter.

**Note on Layer 6:** `embed_whitebox_tables()` in `whitebox_embed.rs` appends serialized table data (marker `ASL_WB_TABLES_v1`) to the launcher binary. The launcher's `run()` function in `lib.rs` does not call any white-box decryption path; `unpack_payload()` uses standard AES-GCM via `snapfzz-seal-core`.

---

## 7. Testing Requirements

Each layer is required to have:

1. Unit tests covering core algorithmic correctness.
2. An integration test exercising the full compile-and-run flow.
3. Negative tests simulating relevant attack inputs (tampered binary, insufficient shares, duplicate share indices, etc.).

---

## 8. Success Criteria

- [ ] No searchable fixed-pattern strings in secret-bearing binary regions
- [ ] Shamir split implemented and tested with all threshold boundary conditions
- [ ] At least 5 decoy sets with indistinguishable structure from real shares (embedded, not merely generated)
- [ ] Anti-analysis checks active in runtime startup path
- [ ] Integrity check verified to cause decryption failure on binary modification
- [ ] White-box decryption path wired into runtime launcher
- [ ] All tests pass with no warnings on `cargo test --workspace`
- [ ] Documentation reflects final implemented state

---

## 9. Future Work

The following items are not yet implemented and are recommended as separate engineering efforts:

1. **Layer 3 completion:** Embed generated decoy share bytes into the binary at positions guarded by decoy markers, so that an attacker enumerating all marker-adjacent byte regions encounters structurally valid but incorrect shares.

2. **Layer 6 runtime integration:** Wire `WhiteBoxAES::decrypt()` into the launcher's key-derivation and payload-decryption flow, replacing the current standard AES-GCM call.

3. **Layer 6 security audit:** The white-box table generation has not been reviewed by a cryptographer. Publication of a white-box AES implementation without expert review risks introduction of cryptographic weaknesses.

4. **Hardware binding (Layer 7 candidate):** Integration with a TPM or HSM would provide key material that cannot be extracted from software alone.

5. **Side-channel resistance:** Timing and power analysis of the current implementation have not been assessed.
