# Decryption Enhancement Specification

## Overview

Implement defense-in-depth to prevent trivial extraction of master secret from sealed binaries.

**Current vulnerability:** Plaintext marker + grep = 1 minute extraction

**Target:** Weeks-months of reverse engineering required

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SEALED BINARY                        │
│                                                         │
│  Layer 1: No Observable Patterns                       │
│  Layer 2: Split Secret (Shamir 3-of-5)                 │
│  Layer 3: Decoy Secrets                                │
│  Layer 4: Anti-Analysis                                │
│  Layer 5: Integrity Binding                            │
│  Layer 6: White-Box Cryptography (MANDATORY)          │
└─────────────────────────────────────────────────────────┘
```

---

## Data Structures

### Marker System

```rust
// Generated at build time - no searchable patterns
pub struct BinaryMarkers {
    // Real secret markers (3-of-5 needed)
    pub secret_markers: [[u8; 32]; 5],
    
    // Tamper detection marker
    pub tamper_marker: [u8; 32],
    
    // Payload sentinel
    pub payload_sentinel: [u8; 32],
    
    // Decoy markers (10 sets of 5 each)
    pub decoy_markers: Vec<[[u8; 32]; 5]>,
    
    // Position hint (obfuscated)
    pub position_hint: [u8; 32],
}
```

### Shamir Shares

```rust
pub struct SecretShare {
    pub marker_index: usize,
    pub location: usize,
    pub encrypted_share: [u8; 32],
    pub location_key: [u8; 32], // XOR key
}
```

### Integrity Regions

```rust
pub struct IntegrityRegions {
    pub code_start: usize,
    pub code_end: usize,
    pub data_start: usize,
    pub data_end: usize,
    pub excluded_regions: Vec<(usize, usize)>, // Secret locations
}
```

---

## Function Signatures

### Layer 1: Marker Generation

```rust
// build.rs
fn generate_random_marker(seed: &[u8]) -> [u8; 32];
fn generate_all_markers(build_id: &str) -> BinaryMarkers;

// types.rs
pub fn get_secret_marker(index: usize) -> &'static [u8; 32];
pub fn get_tamper_marker() -> &'static [u8; 32];
pub fn get_payload_sentinel() -> &'static [u8; 32];
```

### Layer 2: Split Secret

```rust
// embed.rs
fn split_master_secret(
    master: &[u8; 32],
    threshold: usize,
    total: usize,
) -> Result<Vec<[u8; 32]>, SealError>;

fn embed_shares_with_obfuscation(
    binary: &mut Vec<u8>,
    shares: &[[u8; 32]],
    markers: &[[u8; 32]],
) -> Result<Vec<SecretShare>, SealError>;

fn reconstruct_master_secret(
    binary: &[u8],
    markers: &[[u8; 32]],
) -> Result<[u8; 32], SealError>;
```

### Layer 3: Decoys

```rust
// embed.rs
fn generate_decoy_secret(index: usize) -> [u8; 32];
fn embed_decoy_secrets(
    binary: &mut Vec<u8>,
    count: usize,
) -> Result<(), SealError>;
fn obfuscate_real_position(real_index: usize) -> [u8; 32];
fn determine_real_position(hint: &[u8; 32]) -> usize;
```

### Layer 4: Anti-Analysis

```rust
// anti_analysis.rs
pub fn detect_debugger() -> bool;
pub fn detect_virtual_machine() -> bool;
pub fn is_being_analyzed() -> bool;
pub fn poison_environment();
```

### Layer 5: Integrity

```rust
// integrity.rs
pub fn compute_binary_integrity_hash(
    binary: &[u8],
    excluded: &[(usize, usize)],
) -> Result<[u8; 32], SealError>;

pub fn derive_key_with_integrity(
    encrypted_secret: &[u8],
    binary_path: &str,
) -> Result<[u8; 32], SealError>;

pub fn verify_binary_integrity(
    expected_hash: &[u8; 32],
) -> Result<(), SealError>;
```

---

## Dependencies

```toml
[dependencies]
sha2 = "0.10"
rand = "0.8"
# shamir-secret-sharing = "0.1"  # Need to find/implement
zeroize = "1.5"  # Already have
```

---

## Testing Requirements

Each layer must have:
1. Unit tests for core functionality
2. Integration test with full flow
3. Negative tests (attack scenarios)

---

## Implementation Order

1. **Parallel (All layers simultaneously):**
   - Agent 1: Layer 1 (Markers) + Layer 3 (Decoys)
   - Agent 2: Layer 2 (Shamir split)
   - Agent 3: Layer 4 (Anti-analysis)
   - Agent 4: Layer 5 (Integrity)
   - Agent 5: Layer 6 (White-box cryptography) - MOST CRITICAL

---

## Success Criteria

- [ ] No searchable strings in binary
- [ ] Shamir split implemented with tests
- [ ] At least 5 decoy secrets
- [ ] Anti-debugging working
- [ ] Integrity check prevents modification
- [ ] All tests pass
- [ ] Documentation updated