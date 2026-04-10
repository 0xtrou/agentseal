# Agent 4: Integrity Binding

## Mission

Make decryption key depend on binary integrity. Any modification breaks decryption.

---

## Concept

```rust
// Current: key = extract_secret(binary)
// Enhanced: key = derive(integrity_hash(binary), embedded_secret)

// If binary is modified:
// - integrity_hash changes
// - key changes
// - decryption fails
```

---

## Implementation

**File: `crates/snapfzz-seal-launcher/src/integrity.rs`** (NEW FILE)

```rust
use sha2::{Sha256, Digest};
use std::fs;
use snapfzz_seal_core::error::SealError;

/// Binary regions for integrity checking
pub struct IntegrityRegions {
    /// Code section boundaries
    pub code_start: usize,
    pub code_end: usize,
    
    /// Read-only data section
    pub data_start: usize,
    pub data_end: usize,
    
    /// Regions to exclude (where secrets are embedded)
    pub excluded: Vec<(usize, usize)>,
}

/// Compute hash of running binary
pub fn compute_binary_integrity_hash(
    binary: &[u8],
    regions: &IntegrityRegions,
) -> Result<[u8; 32], SealError> {
    let mut hasher = Sha256::new();
    
    // Hash code section (excluding embedded secrets)
    hash_region_with_exclusions(
        &mut hasher,
        binary,
        regions.code_start,
        regions.code_end,
        &regions.excluded,
    );
    
    // Hash data section (excluding embedded secrets)
    hash_region_with_exclusions(
        &mut hasher,
        binary,
        regions.data_start,
        regions.data_end,
        &regions.excluded,
    );
    
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    
    Ok(hash)
}

fn hash_region_with_exclusions(
    hasher: &mut Sha256,
    binary: &[u8],
    start: usize,
    end: usize,
    excluded: &[(usize, usize)],
) {
    let mut pos = start;
    
    // Sort exclusions by start position
    let mut sorted_exclusions = excluded.to_vec();
    sorted_exclusions.sort_by_key(|(s, _)| *s);
    
    for (excl_start, excl_end) in &sorted_exclusions {
        // Hash everything before this exclusion
        if pos < *excl_start && *excl_start <= end {
            hasher.update(&binary[pos..*excl_start]);
        }
        
        // Skip the excluded region
        pos = (*excl_end).max(pos);
    }
    
    // Hash remaining portion
    if pos < end {
        hasher.update(&binary[pos..end]);
    }
}

/// Derive decryption key with integrity binding
pub fn derive_key_with_integrity(
    embedded_secret: &[u8; 32],
    binary_path: Option<&str>,
) -> Result<[u8; 32], SealError> {
    // Read running binary
    #[cfg(target_os = "linux")]
    let binary = {
        let path = binary_path.unwrap_or("/proc/self/exe");
        fs::read(path).map_err(|e| {
            SealError::IntegrityError(format!("Failed to read binary: {}", e))
        })?
    };
    
    #[cfg(not(target_os = "linux"))]
    let binary = {
        return Err(SealError::IntegrityError(
            "Integrity check only supported on Linux".to_string()
        ));
    };
    
    // Find integrity regions
    let regions = find_integrity_regions(&binary)?;
    
    // Compute integrity hash
    let integrity_hash = compute_binary_integrity_hash(&binary, &regions)?;
    
    // Derive key: hash(secret || integrity_hash)
    let mut hasher = Sha256::new();
    hasher.update(embedded_secret);
    hasher.update(&integrity_hash);
    
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    
    tracing::debug!(
        integrity_hash = %hex::encode(&integrity_hash[..8]),
        "Derived integrity-bound key"
    );
    
    Ok(key)
}

/// Find integrity regions in the binary
fn find_integrity_regions(binary: &[u8]) -> Result<IntegrityRegions, SealError> {
    // Simple approach: use entire binary except secret regions
    
    // Find ELF sections if possible
    #[cfg(target_os = "linux")]
    {
        // Try to parse ELF headers for more precise regions
        if binary.len() > 64 && &binary[0..4] == b"\x7fELF" {
            return parse_elf_regions(binary);
        }
    }
    
    // Fallback: use entire binary
    Ok(IntegrityRegions {
        code_start: 0,
        code_end: binary.len(),
        data_start: 0,
        data_end: 0, // No separate data section
        excluded: find_secret_regions(binary)?,
    })
}

/// Find regions where secrets are embedded (to exclude from integrity hash)
fn find_secret_regions(binary: &[u8]) -> Result<Vec<(usize, usize)>, SealError> {
    let mut regions = Vec::new();
    
    // Find secret markers
    use snapfzz_seal_core::types::{
        SECRET_MARKER_0, SECRET_MARKER_1, SECRET_MARKER_2,
        SECRET_MARKER_3, SECRET_MARKER_4,
        TAMPER_MARKER, PAYLOAD_SENTINEL,
    };
    
    let markers: &[&[u8; 32]] = &[
        &SECRET_MARKER_0,
        &SECRET_MARKER_1,
        &SECRET_MARKER_2,
        &SECRET_MARKER_3,
        &SECRET_MARKER_4,
        &TAMPER_MARKER,
        &PAYLOAD_SENTINEL,
    ];
    
    for marker in markers {
        if let Some(pos) = binary.windows(32).position(|w| w == *marker) {
            // Exclude marker + 32 bytes after (the secret)
            regions.push((pos, pos + 32 + 32));
        }
    }
    
    // Also exclude payload section (after PAYLOAD_SENTINEL)
    // This is the encrypted agent, not part of integrity
    
    Ok(regions)
}

/// Parse ELF binary to find code and data sections
#[cfg(target_os = "linux")]
fn parse_elf_regions(binary: &[u8]) -> Result<IntegrityRegions, SealError> {
    // ELF header parsing (simplified)
    // For production, use proper ELF parser
    
    let mut code_start = 0;
    let mut code_end = 0;
    let mut data_start = 0;
    let mut data_end = 0;
    
    // ELF64 header
    if binary.len() < 64 {
        return Err(SealError::IntegrityError("Binary too small".to_string()));
    }
    
    // Check ELF magic
    if &binary[0..4] != b"\x7fELF" {
        return Err(SealError::IntegrityError("Not an ELF binary".to_string()));
    }
    
    // Get program header offset (at offset 32 for ELF64)
    let phoff = u64::from_le_bytes([
        binary[32], binary[33], binary[34], binary[35],
        binary[36], binary[37], binary[38], binary[39],
    ]);
    
    // Get number of program headers (at offset 56 for ELF64)
    let phnum = u16::from_le_bytes([binary[56], binary[57]]) as usize;
    
    // Parse program headers
    for i in 0..phnum {
        let ph_offset = phoff as usize + i * 56; // 56 bytes per program header
        
        if ph_offset + 56 > binary.len() {
            break;
        }
        
        // Get segment type (at offset 0 in program header)
        let p_type = u32::from_le_bytes([
            binary[ph_offset], binary[ph_offset + 1],
            binary[ph_offset + 2], binary[ph_offset + 3],
        ]);
        
        // Get segment flags (at offset 4)
        let p_flags = u32::from_le_bytes([
            binary[ph_offset + 4], binary[ph_offset + 5],
            binary[ph_offset + 6], binary[ph_offset + 7],
        ]);
        
        // Get segment file offset (at offset 8)
        let p_offset = u64::from_le_bytes([
            binary[ph_offset + 8], binary[ph_offset + 9],
            binary[ph_offset + 10], binary[ph_offset + 11],
            binary[ph_offset + 12], binary[ph_offset + 13],
            binary[ph_offset + 14], binary[ph_offset + 15],
        ]);
        
        // Get segment file size (at offset 32)
        let p_filesz = u64::from_le_bytes([
            binary[ph_offset + 32], binary[ph_offset + 33],
            binary[ph_offset + 34], binary[ph_offset + 35],
            binary[ph_offset + 36], binary[ph_offset + 37],
            binary[ph_offset + 38], binary[ph_offset + 39],
        ]);
        
        // PT_LOAD = 1
        if p_type == 1 {
            // Check if executable (PF_X = 0x1)
            if p_flags & 0x1 != 0 {
                // Code segment
                if code_start == 0 {
                    code_start = p_offset as usize;
                }
                code_end = (p_offset + p_filesz) as usize;
            } else {
                // Data segment
                if data_start == 0 {
                    data_start = p_offset as usize;
                }
                data_end = (p_offset + p_filesz) as usize;
            }
        }
    }
    
    let excluded = find_secret_regions(binary)?;
    
    Ok(IntegrityRegions {
        code_start,
        code_end,
        data_start,
        data_end,
        excluded,
    })
}

/// Verify binary hasn't been modified
pub fn verify_integrity(
    expected_hash: &[u8; 32],
) -> Result<(), SealError> {
    #[cfg(target_os = "linux")]
    {
        let binary = fs::read("/proc/self/exe")?;
        let regions = find_integrity_regions(&binary)?;
        let computed = compute_binary_integrity_hash(&binary, &regions)?;
        
        if computed != *expected_hash {
            tracing::error!(
                expected = %hex::encode(expected_hash),
                computed = %hex::encode(&computed),
                "Integrity check failed"
            );
            return Err(SealError::IntegrityViolation);
        }
        
        tracing::info!("Integrity check passed");
        Ok(())
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        // Skip on non-Linux
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_integrity_regions() {
        // Create test binary
        let mut binary = vec![0u8; 1024];
        
        // Add a marker
        binary[100..132].copy_from_slice(&SECRET_MARKER_0);
        
        let regions = find_integrity_regions(&binary).unwrap();
        
        // Should exclude marker + 32 bytes
        assert!(regions.excluded.contains(&(100, 164)));
    }
    
    #[test]
    fn test_hash_with_exclusions() {
        let mut binary = vec![0xAAu8; 100];
        binary[40..60].fill(0xBB); // This will be excluded
        
        let regions = IntegrityRegions {
            code_start: 0,
            code_end: 100,
            data_start: 0,
            data_end: 0,
            excluded: vec![(40, 60)],
        };
        
        let hash = compute_binary_integrity_hash(&binary, &regions).unwrap();
        
        // Hash should be deterministic
        let hash2 = compute_binary_integrity_hash(&binary, &regions).unwrap();
        assert_eq!(hash, hash2);
        
        // Changing excluded region shouldn't change hash
        binary[45] = 0xCC;
        let hash3 = compute_binary_integrity_hash(&binary, &regions).unwrap();
        assert_eq!(hash, hash3);
        
        // Changing non-excluded region should change hash
        binary[10] = 0xDD;
        let hash4 = compute_binary_integrity_hash(&binary, &regions).unwrap();
        assert_ne!(hash, hash4);
    }
}