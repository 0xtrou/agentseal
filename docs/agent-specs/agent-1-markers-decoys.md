# Agent 1: Markers + Decoys

## Mission

Eliminate observable patterns and add decoy secrets to confuse attackers.

---

## Layer 1: No Observable Patterns

### Problem

```rust
// CURRENT - Searchable with grep/strings
pub const LAUNCHER_SECRET_MARKER: &[u8; 32] = 
    b"ASL_SECRET_MRK_v1\x00\x01\x02\x03\x04\x05\x06\x07...";
```

### Solution

Generate random markers at compile time with no searchable strings.

### Implementation

**File: `crates/snapfzz-seal-core/build.rs`** (NEW FILE)

```rust
use sha2::{Sha256, Digest};
use std::io::Write;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("generated_markers.rs");
    
    // Generate markers deterministically from build hash
    let build_id = std::env::var("BUILD_ID").unwrap_or_else(|_| {
        format!("{}", chrono::Utc::now().timestamp())
    });
    
    let mut file = std::fs::File::create(&dest_path).unwrap();
    
    // Generate 5 real markers
    for i in 0..5 {
        let mut hasher = Sha256::new();
        hasher.update(build_id.as_bytes());
        hasher.update(format!("secret_marker_{}", i));
        hasher.update(rand::random::<[u8; 16]>());
        let marker = hasher.finalize();
        
        writeln!(file, 
            "pub const SECRET_MARKER_{}: [u8; 32] = {:?};",
            i, marker.as_slice()
        ).unwrap();
    }
    
    // Generate tamper marker
    let mut hasher = Sha256::new();
    hasher.update(build_id.as_bytes());
    hasher.update(b"tamper_marker");
    hasher.update(rand::random::<[u8; 16]>());
    let tamper = hasher.finalize();
    writeln!(file, 
        "pub const TAMPER_MARKER: [u8; 32] = {:?};",
        tamper.as_slice()
    ).unwrap();
    
    // Generate payload sentinel
    let mut hasher = Sha256::new();
    hasher.update(build_id.as_bytes());
    hasher.update(b"payload_sentinel");
    hasher.update(rand::random::<[u8; 16]>());
    let sentinel = hasher.finalize();
    writeln!(file, 
        "pub const PAYLOAD_SENTINEL: [u8; 32] = {:?};",
        sentinel.as_slice()
    ).unwrap();
    
    // Generate 50 decoy markers (10 sets × 5)
    writeln!(file, "pub const DECOY_MARKERS: [[u8; 32]; 50] = [").unwrap();
    for i in 0..50 {
        let mut hasher = Sha256::new();
        hasher.update(build_id.as_bytes());
        hasher.update(format!("decoy_marker_{}", i));
        hasher.update(rand::random::<[u8; 16]>());
        let marker = hasher.finalize();
        writeln!(file, "    {:?},", marker.as_slice()).unwrap();
    }
    writeln!(file, "];").unwrap();
    
    // Generate position hint salt
    writeln!(file, 
        "pub const POSITION_HINT_SALT: [u8; 32] = {:?};",
        rand::random::<[u8; 32]>()
    ).unwrap();
    
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-env=BUILD_ID={}", build_id);
}
```

**File: `crates/snapfzz-seal-core/src/types.rs`** (MODIFY)

```rust
// Remove old constants, include generated ones
include!(concat!(env!("OUT_DIR"), "/generated_markers.rs"));

// Remove these:
// pub const LAUNCHER_SECRET_MARKER: &[u8; 32] = ...
// pub const LAUNCHER_TAMPER_MARKER: &[u8; 32] = ...
// pub const LAUNCHER_PAYLOAD_SENTINEL: &[u8; 32] = ...

// Add accessor functions
pub fn get_secret_marker(index: usize) -> &'static [u8; 32] {
    match index {
        0 => &SECRET_MARKER_0,
        1 => &SECRET_MARKER_1,
        2 => &SECRET_MARKER_2,
        3 => &SECRET_MARKER_3,
        4 => &SECRET_MARKER_4,
        _ => panic!("Invalid marker index"),
    }
}

pub fn get_decoy_marker(set: usize, index: usize) -> &'static [u8; 32] {
    &DECOY_MARKERS[set * 5 + index]
}
```

**File: `crates/snapfzz-seal-core/Cargo.toml`** (MODIFY)

```toml
[build-dependencies]
sha2 = "0.10"
rand = "0.8"
chrono = "0.4"

[dependencies]
sha2 = "0.10"
rand = "0.8"
```

---

## Layer 3: Decoy Secrets

### Goal

Embed 10 fake secret sets to force attacker to try all combinations.

### Implementation

**File: `crates/snapfzz-seal-compiler/src/decoys.rs`** (NEW FILE)

```rust
use sha2::{Sha256, Digest};
use snapfzz_seal_core::error::SealError;

const DECOY_SETS: usize = 10;

/// Generate deterministic but random-looking decoy secret
pub fn generate_decoy_secret(set_index: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DECOY_SECRET_V1");
    hasher.update(set_index.to_le_bytes());
    hasher.update(include_bytes!("decoy_salt.bin")); // Random salt at compile time
    
    let result = hasher.finalize();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&result);
    secret
}

/// Generate all decoy secrets
pub fn generate_all_decoys() -> Vec<[u8; 32]> {
    (0..DECOY_SETS)
        .map(|i| generate_decoy_secret(i))
        .collect()
}

/// Obfuscate the real position
pub fn obfuscate_real_position(real_index: usize, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"REAL_POSITION_HINT");
    hasher.update(real_index.to_le_bytes());
    hasher.update(salt);
    
    let result = hasher.finalize();
    let mut hint = [0u8; 32];
    hint.copy_from_slice(&result);
    hint
}

/// Determine real position from hint
pub fn determine_real_position(hint: &[u8; 32], salt: &[u8; 32]) -> usize {
    // Try all possible positions
    for i in 0..(DECOY_SETS + 1) {
        let expected = obfuscate_real_position(i, salt);
        if expected == *hint {
            return i;
        }
    }
    0 // Default to first if no match
}

/// Embed decoy secrets into binary
pub fn embed_decoy_secrets(
    binary: &mut Vec<u8>,
    real_index: usize,
) -> Result<[u8; 32], SealError> {
    let decoys = generate_all_decoys();
    
    // Embed position hint
    let salt = rand::random::<[u8; 32]>();
    let hint = obfuscate_real_position(real_index, &salt);
    
    // Find location for hint
    let hint_marker = b"POSITION_HINT_MARKER";
    let hint_location = find_or_create_slot(binary, hint_marker)?;
    binary[hint_location..hint_location + 32].copy_from_slice(&hint);
    
    // Store salt somewhere accessible
    // (in another marker location)
    
    Ok(salt)
}

fn find_or_create_slot(binary: &mut Vec<u8>, marker: &[u8]) -> Result<usize, SealError> {
    // Find marker in binary
    if let Some(pos) = binary.windows(marker.len())
        .position(|w| w == marker) 
    {
        return Ok(pos + marker.len());
    }
    
    // If not found, append
    let pos = binary.len();
    binary.extend_from_slice(marker);
    binary.extend_from_slice(&[0u8; 32]);
    Ok(pos + marker.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decoy_generation() {
        let d1 = generate_decoy_secret(0);
        let d2 = generate_decoy_secret(1);
        assert_ne!(d1, d2);
        
        // Deterministic
        let d1_again = generate_decoy_secret(0);
        assert_eq!(d1, d1_again);
    }
    
    #[test]
    fn test_position_obfuscation() {
        let salt = [0xAA; 32];
        let hint = obfuscate_real_position(0, &salt);
        let determined = determine_real_position(&hint, &salt);
        assert_eq!(determined, 0);
        
        let hint2 = obfuscate_real_position(5, &salt);
        let determined2 = determine_real_position(&hint2, &salt);
        assert_eq!(determined2, 5);
    }
}
```

---

## Testing

**File: `crates/snapfzz-seal-core/tests/markers_test.rs`** (NEW FILE)

```rust
use snapfzz_seal_core::types::*;

#[test]
fn no_searchable_strings() {
    // Verify no marker contains "SECRET" or "MARKER" strings
    for i in 0..5 {
        let marker = get_secret_marker(i);
        let marker_str = String::from_utf8_lossy(marker);
        assert!(!marker_str.contains("SECRET"));
        assert!(!marker_str.contains("MARKER"));
        assert!(!marker_str.contains("ASL"));
    }
}

#[test]
fn markers_are_unique() {
    let markers: Vec<_> = (0..5).map(|i| get_secret_marker(i)).collect();
    
    for i in 0..markers.len() {
        for j in (i+1)..markers.len() {
            assert_ne!(markers[i], markers[j]);
        }
    }
}
```

---

## Files to Create/Modify

1. **CREATE:** `crates/snapfzz-seal-core/build.rs`
2. **CREATE:** `crates/snapfzz-seal-compiler/src/decoys.rs`
3. **CREATE:** `crates/snapfzz-seal-core/tests/markers_test.rs`
4. **MODIFY:** `crates/snapfzz-seal-core/src/types.rs`
5. **MODIFY:** `crates/snapfzz-seal-core/Cargo.toml`
6. **MODIFY:** `crates/snapfzz-seal-compiler/src/lib.rs` (add mod decoys)

---

## Success Criteria

- [ ] Build generates random markers
- [ ] No marker contains searchable strings
- [ ] All markers are unique
- [ ] Decoy generation works
- [ ] Position obfuscation round-trips correctly
- [ ] All tests pass
- [ ] `cargo build` succeeds