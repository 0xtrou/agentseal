# Agent 5: White-Box Cryptography (CRITICAL)

## Mission

Implement white-box AES to make key extraction computationally infeasible.

**This is the most important layer.**

---

## Background

White-box cryptography hides the key inside lookup tables instead of storing it directly.

**Standard AES:**
```
key → AES_encrypt(plaintext, key) → ciphertext
```

**White-Box AES:**
```
lookup_tables → WB_encrypt(plaintext, tables) → ciphertext
// Key is "spread" across thousands of tables
// No single table reveals the key
// Must reverse-engineer entire structure
```

---

## Implementation Strategy

### Option A: Use Existing Library (RECOMMENDED)

**Find/implement:**
1. `whitebox-aes` crate (if exists)
2. Port from C library (e.g., Chow's implementation)
3. Implement from academic papers

### Option B: Implement from Scratch

Based on:
- Chow et al. 2002: "White-Box Cryptography and an AES Implementation"
- Karroumi 2010: "Protecting White-Box AES with Dual Ciphers"

---

## Architecture

```rust
// Build time: Generate tables
let master_key = [0x42; 32];
let wb_tables = WhiteBoxAES::generate_tables(&master_key);

// Tables contain:
// - T-boxes (key-dependent S-box transformations)
// - Type I tables (input mixing)
// - Type II tables (output mixing)
// - Randomization (obfuscation)

// Runtime: Use tables for decryption
let plaintext = wb_tables.decrypt(&ciphertext);

// Key is NEVER extracted from tables
```

---

## Implementation

**File: `crates/snapfzz-seal-core/src/whitebox/mod.rs`** (NEW FILE)

```rust
pub mod aes;
pub mod tables;

pub use aes::WhiteBoxAES;
pub use tables::WhiteBoxTables;
```

**File: `crates/snapfzz-seal-core/src/whitebox/aes.rs`** (NEW FILE)

```rust
use super::tables::{WhiteBoxTables, TBox, TypeI, TypeII};
use sha2::{Sha256, Digest};

/// White-Box AES-256 implementation
pub struct WhiteBoxAES {
    tables: WhiteBoxTables,
}

impl WhiteBoxAES {
    /// Generate white-box tables from key
    /// This is done at BUILD time
    pub fn generate_tables(key: &[u8; 32]) -> WhiteBoxTables {
        let mut tables = WhiteBoxTables::new();
        
        // AES-256 has 14 rounds
        for round in 0..14 {
            // Generate round key
            let round_key = Self::derive_round_key(key, round);
            
            // Create T-boxes for this round
            for byte_idx in 0..16 {
                tables.t_boxes.push(Self::generate_t_box(
                    &round_key,
                    round,
                    byte_idx,
                ));
            }
        }
        
        // Generate mixing tables
        for round in 0..13 {
            tables.type_i.push(Self::generate_type_i(round));
            tables.type_ii.push(Self::generate_type_ii(round + 1));
        }
        
        // Add randomization for security
        tables.randomize();
        
        tables
    }
    
    /// Generate T-box for one byte position
    /// T-box combines SubBytes + ShiftRows + AddRoundKey
    fn generate_t_box(
        round_key: &[u8; 16],
        round: usize,
        byte_idx: usize,
    ) -> TBox {
        let mut t_box = [0u8; 256];
        
        for input_byte in 0u8..=255 {
            // Apply S-box
            let s_box_out = SBOX[input_byte as usize];
            
            // Add round key byte
            let key_byte = round_key[byte_idx];
            let output = s_box_out ^ key_byte;
            
            t_box[input_byte as usize] = output;
        }
        
        TBox {
            round,
            byte_idx,
            table: t_box,
        }
    }
    
    /// Generate Type I mixing tables (input side)
    fn generate_type_i(round: usize) -> TypeI {
        // Type I tables mix the outputs of T-boxes
        // using the MixColumns transformation
        
        let mut tables = Vec::new();
        
        // For each column of the state
        for col in 0..4 {
            let mut column_table = [[0u8; 256]; 4];
            
            for row in 0..4 {
                for input in 0u8..=255 {
                    // MixColumns coefficients
                    let coeff = match row {
                        0 => 2,
                        1 => 3,
                        2 => 1,
                        3 => 1,
                        _ => unreachable!(),
                    };
                    
                    // GF(2^8) multiplication
                    let output = gf_mult(coeff, input);
                    column_table[row][input as usize] = output;
                }
            }
            
            tables.push(column_table);
        }
        
        TypeI { round, tables }
    }
    
    /// Generate Type II mixing tables (output side)
    fn generate_type_ii(round: usize) -> TypeII {
        // Type II tables are the inverse of Type I
        // Applied before next round's T-boxes
        
        let mut tables = Vec::new();
        
        for col in 0..4 {
            let mut column_table = [[0u8; 256]; 4];
            
            for row in 0..4 {
                for input in 0u8..=255 {
                    // Use inverse MixColumns coefficients
                    let coeff = match row {
                        0 => 0x0e,
                        1 => 0x0b,
                        2 => 0x0d,
                        3 => 0x09,
                        _ => unreachable!(),
                    };
                    
                    let output = gf_mult(coeff, input);
                    column_table[row][input as usize] = output;
                }
            }
            
            tables.push(column_table);
        }
        
        TypeII { round, tables }
    }
    
    /// Derive round key from master key
    fn derive_round_key(key: &[u8; 32], round: usize) -> [u8; 16] {
        // Simplified: use SHA-256 to derive round keys
        // For production: use proper AES key schedule
        
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update((round as u32).to_le_bytes());
        
        let result = hasher.finalize();
        let mut round_key = [0u8; 16];
        round_key.copy_from_slice(&result[..16]);
        
        round_key
    }
    
    /// Decrypt using white-box tables
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, WhiteBoxError> {
        if ciphertext.len() % 16 != 0 {
            return Err(WhiteBoxError::InvalidLength);
        }
        
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        
        for block in ciphertext.chunks(16) {
            let decrypted_block = self.decrypt_block(block);
            plaintext.extend_from_slice(&decrypted_block);
        }
        
        Ok(plaintext)
    }
    
    /// Decrypt single 16-byte block
    fn decrypt_block(&self, block: &[u8]) -> [u8; 16] {
        let mut state = [0u8; 16];
        state.copy_from_slice(block);
        
        // Reverse rounds (14 rounds for AES-256)
        for round in (0..14).rev() {
            state = self.apply_round_tables(round, &state);
        }
        
        state
    }
    
    /// Apply lookup tables for one round
    fn apply_round_tables(&self, round: usize, state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        
        // Apply T-boxes
        for byte_idx in 0..16 {
            let t_box_idx = round * 16 + byte_idx;
            if t_box_idx < self.tables.t_boxes.len() {
                let t_box = &self.tables.t_boxes[t_box_idx];
                new_state[byte_idx] = t_box.table[state[byte_idx] as usize];
            }
        }
        
        // Apply mixing tables (except last round)
        if round < 13 {
            if round < self.tables.type_i.len() {
                new_state = self.apply_mixing(&self.tables.type_i[round], &new_state);
            }
        }
        
        new_state
    }
    
    fn apply_mixing(&self, type_i: &TypeI, state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];
        
        for (col_idx, column_table) in type_i.tables.iter().enumerate() {
            for row in 0..4 {
                let state_idx = col_idx * 4 + row;
                let mut mixed = 0u8;
                
                for (i, table) in column_table.iter().enumerate() {
                    mixed ^= table[state[col_idx * 4 + i] as usize];
                }
                
                new_state[state_idx] = mixed;
            }
        }
        
        new_state
    }
}

/// AES S-box (lookup table for SubBytes)
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// GF(2^8) multiplication
fn gf_mult(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        
        let hi_bit = a & 0x80;
        a <<= 1;
        
        if hi_bit != 0 {
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        }
        
        b >>= 1;
    }
    
    result
}

#[derive(Debug)]
pub enum WhiteBoxError {
    InvalidLength,
    DecryptionFailed,
}

// Import types at top
use crate::error::SealError;
```

**File: `crates/snapfzz-seal-core/src/whitebox/tables.rs`** (NEW FILE)

```rust
/// T-box: combines SubBytes + AddRoundKey
#[derive(Clone)]
pub struct TBox {
    pub round: usize,
    pub byte_idx: usize,
    pub table: [u8; 256],
}

/// Type I mixing tables (input mixing)
#[derive(Clone)]
pub struct TypeI {
    pub round: usize,
    pub tables: Vec<[[u8; 256]; 4]>,
}

/// Type II mixing tables (output mixing)
#[derive(Clone)]
pub struct TypeII {
    pub round: usize,
    pub tables: Vec<[[u8; 256]; 4]>,
}

/// Complete white-box table set
#[derive(Clone)]
pub struct WhiteBoxTables {
    pub t_boxes: Vec<TBox>,
    pub type_i: Vec<TypeI>,
    pub type_ii: Vec<TypeII>,
    pub randomization: Vec<[u8; 16]>,
}

impl WhiteBoxTables {
    pub fn new() -> Self {
        Self {
            t_boxes: Vec::new(),
            type_i: Vec::new(),
            type_ii: Vec::new(),
            randomization: Vec::new(),
        }
    }
    
    /// Add randomization to tables
    /// Makes reverse engineering harder
    pub fn randomize(&mut self) {
        use rand::Rng;
        
        // Generate random bijections
        for _ in 0..16 {
            let mut bijection: [u8; 16] = rand::random();
            self.randomization.push(bijection);
        }
        
        // Apply randomization to T-boxes
        for (i, t_box) in self.t_boxes.iter_mut().enumerate() {
            let rand_idx = i % self.randomization.len();
            let rand_val = &self.randomization[rand_idx];
            
            for (j, entry) in t_box.table.iter_mut().enumerate() {
                *entry ^= rand_val[j % 16];
            }
        }
    }
    
    /// Serialize tables to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Number of T-boxes
        bytes.extend_from_slice(&(self.t_boxes.len() as u32).to_le_bytes());
        
        // T-boxes
        for t_box in &self.t_boxes {
            bytes.push(t_box.round as u8);
            bytes.push(t_box.byte_idx as u8);
            bytes.extend_from_slice(&t_box.table);
        }
        
        // Number of Type I tables
        bytes.extend_from_slice(&(self.type_i.len() as u32).to_le_bytes());
        
        // Type I tables (simplified serialization)
        for type_i in &self.type_i {
            bytes.push(type_i.round as u8);
            for column_table in &type_i.tables {
                for row_table in column_table {
                    bytes.extend_from_slice(row_table);
                }
            }
        }
        
        // Type II tables (similar)
        bytes.extend_from_slice(&(self.type_ii.len() as u32).to_le_bytes());
        
        bytes
    }
    
    /// Estimate size in bytes
    pub fn estimate_size(&self) -> usize {
        let t_box_size = self.t_boxes.len() * (2 + 256);
        let type_i_size = self.type_i.len() * (1 + 4 * 4 * 256);
        let type_ii_size = self.type_ii.len() * (1 + 4 * 4 * 256);
        
        t_box_size + type_i_size + type_ii_size + 1000 // overhead
    }
}

impl Default for WhiteBoxTables {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## Integration

**File: `crates/snapfzz-seal-compiler/src/whitebox_embed.rs`** (NEW FILE)

```rust
use snapfzz_seal_core::whitebox::{WhiteBoxAES, WhiteBoxTables};

/// Embed white-box tables instead of plaintext key
pub fn embed_whitebox_tables(
    launcher_bytes: &[u8],
    master_key: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    // Generate white-box tables
    let tables = WhiteBoxAES::generate_tables(master_key);
    
    // Serialize tables
    let tables_bytes = tables.to_bytes();
    
    // Embed tables in binary
    let mut modified = launcher_bytes.to_vec();
    
    // Find tables marker
    let marker = b"WHITEBOX_TABLES_MARKER";
    if let Some(pos) = modified.windows(marker.len())
        .position(|w| w == marker) 
    {
        let table_start = pos + marker.len();
        
        // Ensure we have space
        if table_start + tables_bytes.len() > modified.len() {
            // Extend binary
            modified.extend_from_slice(&[0u8; 1024 * 1024]); // +1MB
        }
        
        modified[table_start..table_start + tables_bytes.len()]
            .copy_from_slice(&tables_bytes);
    } else {
        // Append tables
        modified.extend_from_slice(marker);
        modified.extend_from_slice(&tables_bytes);
    }
    
    tracing::info!(
        tables_size = tables_bytes.len(),
        "Embedded white-box tables"
    );
    
    Ok(modified)
}
```

---

## Files to Create

1. **CREATE:** `crates/snapfzz-seal-core/src/whitebox/mod.rs`
2. **CREATE:** `crates/snapfzz-seal-core/src/whitebox/aes.rs`
3. **CREATE:** `crates/snapfzz-seal-core/src/whitebox/tables.rs`
4. **CREATE:** `crates/snapfzz-seal-compiler/src/whitebox_embed.rs`
5. **MODIFY:** `crates/snapfzz-seal-core/src/lib.rs` (add pub mod whitebox)
6. **MODIFY:** `crates/snapfzz-seal-compiler/src/lib.rs` (add mod whitebox_embed)

---

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_whitebox_roundtrip() {
        let key = [0x42u8; 32];
        let tables = WhiteBoxAES::generate_tables(&key);
        
        let plaintext = b"Hello, World!!!"; // 16 bytes
        let ciphertext = some_aes_encrypt(plaintext, &key);
        
        let decrypted = tables.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_tables_size() {
        let key = [0x42u8; 32];
        let tables = WhiteBoxAES::generate_tables(&key);
        
        let size = tables.estimate_size();
        println!("White-box tables size: {} bytes", size);
        
        // Should be ~500KB - 2MB
        assert!(size > 100_000);
        assert!(size < 5_000_000);
    }
}
```

---

## Success Criteria

- [ ] White-box tables generated correctly
- [ ] Decryption produces correct plaintext
- [ ] Tables are ~500KB - 2MB in size
- [ ] No way to extract key from single table
- [ ] Integration with compiler works
- [ ] All tests pass
- [ ] Performance acceptable (<10x slowdown)

---

## Notes

This is a simplified implementation. For production:

1. **Use proven library** if available
2. **Implement proper AES key schedule** (not SHA-256 derivation)
3. **Add more randomization layers**
4. **Consider side-channel resistance**
5. **Get security audit**

**Critical:** A bad white-box implementation is worse than no white-box!