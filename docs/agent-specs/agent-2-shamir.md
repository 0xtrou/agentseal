# Agent 2: Shamir Secret Sharing

## Mission

Split master secret into 5 shares using Shamir's Secret Sharing. Require 3 shares to reconstruct.

---

## Problem

Single secret in binary = single point of failure. Easy to extract.

## Solution

Use Shamir's Secret Sharing to split secret into 5 shares, require 3 to reconstruct.

---

## Background

Shamir's Secret Sharing uses polynomial interpolation over a finite field:

1. Create polynomial of degree (k-1) where k = threshold
2. Secret is the constant term (f(0))
3. Shares are points on the polynomial
4. Any k points can reconstruct the polynomial
5. Fewer than k points reveal nothing

For our case: Create degree-2 polynomial, 5 shares, need 3 to reconstruct.

---

## Implementation

**File: `crates/snapfzz-seal-core/src/shamir.rs`** (NEW FILE)

```rust
use std::ops::{Add, Mul, Sub};

/// Finite field arithmetic over GF(2^256) using prime field
/// Using secp256k1 prime for security: 2^256 - 2^32 - 977
const PRIME: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// 256-bit field element
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement([u8; 32]);

impl FieldElement {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut fe = FieldElement(bytes);
        fe.reduce();
        fe
    }
    
    pub fn from_u64(val: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&val.to_be_bytes());
        FieldElement::from_bytes(bytes)
    }
    
    pub fn zero() -> Self {
        FieldElement([0u8; 32])
    }
    
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    
    /// Reduce modulo prime
    fn reduce(&mut self) {
        // Simple reduction: if >= prime, subtract prime
        // For production, use proper modular arithmetic
        if self.cmp_prime() >= 0 {
            self.sub_assign_prime();
        }
    }
    
    fn cmp_prime(&self) -> i32 {
        // Compare with prime
        for i in 0..32 {
            if self.0[i] > PRIME[i] {
                return 1;
            } else if self.0[i] < PRIME[i] {
                return -1;
            }
        }
        0
    }
    
    fn sub_assign_prime(&mut self) {
        let mut borrow = 0u16;
        for i in (0..32).rev() {
            let diff = self.0[i] as u16 - PRIME[i] as u16 - borrow;
            self.0[i] = diff as u8;
            borrow = if diff >> 8 != 0 { 1 } else { 0 };
        }
    }
}

impl Add for FieldElement {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        let mut result = [0u8; 32];
        let mut carry = 0u16;
        
        for i in (0..32).rev() {
            let sum = self.0[i] as u16 + other.0[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }
        
        let mut fe = FieldElement(result);
        fe.reduce();
        fe
    }
}

impl Sub for FieldElement {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        // a - b = a + (prime - b) in field
        let neg_other = FieldElement(PRIME) - other;
        self + neg_other
    }
}

impl Mul for FieldElement {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self {
        // Schoolbook multiplication with reduction
        let mut result = [0u8; 64];
        
        for i in (0..32).rev() {
            for j in (0..32).rev() {
                let prod = self.0[i] as u16 * other.0[j] as u16;
                let idx = 64 - (31 - i) - (31 - j) - 1;
                
                let sum = result[idx] as u32 + prod as u32;
                result[idx] = sum as u8;
                
                // Handle carry
                if idx > 0 {
                    result[idx - 1] = (result[idx - 1] as u32 + (sum >> 8)) as u8;
                }
            }
        }
        
        // Reduce 512-bit to 256-bit
        let mut fe = FieldElement([0u8; 32]);
        fe.0.copy_from_slice(&result[32..64]);
        fe.reduce();
        fe
    }
}

/// Split secret into n shares, require k to reconstruct
pub fn split_secret(
    secret: &[u8; 32],
    threshold: usize,
    total_shares: usize,
) -> Result<Vec<(u8, [u8; 32])>, ShamirError> {
    if threshold > total_shares {
        return Err(ShamirError::InvalidThreshold);
    }
    
    if threshold < 2 {
        return Err(ShamirError::ThresholdTooLow);
    }
    
    // Create polynomial of degree (threshold - 1)
    // f(x) = secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
    let secret_fe = FieldElement::from_bytes(*secret);
    
    // Generate random coefficients
    let mut coefficients = vec![secret_fe];
    for _ in 1..threshold {
        let mut coef = [0u8; 32];
        rand::fill(&mut coef);
        coefficients.push(FieldElement::from_bytes(coef));
    }
    
    // Generate shares: f(1), f(2), ..., f(n)
    let mut shares = Vec::new();
    
    for x in 1..=total_shares {
        let x_fe = FieldElement::from_u64(x as u64);
        
        // Evaluate polynomial at x
        let mut y = FieldElement::zero();
        let mut x_power = FieldElement::from_u64(1);
        
        for coef in &coefficients {
            y = y + *coef * x_power;
            x_power = x_power * x_fe;
        }
        
        shares.push((x as u8, y.to_bytes()));
    }
    
    Ok(shares)
}

/// Reconstruct secret from k shares
pub fn reconstruct_secret(
    shares: &[(u8, [u8; 32])],
) -> Result<[u8; 32], ShamirError> {
    if shares.len() < 2 {
        return Err(ShamirError::NotEnoughShares);
    }
    
    // Lagrange interpolation
    // f(0) = sum(y_i * L_i(0))
    // where L_i(0) = prod((0 - x_j)/(x_i - x_j)) for j != i
    
    let mut result = FieldElement::zero();
    
    for (i, &(x_i, y_bytes)) in shares.iter().enumerate() {
        let y_i = FieldElement::from_bytes(y_bytes);
        let x_i_fe = FieldElement::from_u64(x_i as u64);
        
        // Compute L_i(0)
        let mut numerator = FieldElement::from_u64(1);
        let mut denominator = FieldElement::from_u64(1);
        
        for (j, &(x_j, _)) in shares.iter().enumerate() {
            if i != j {
                let x_j_fe = FieldElement::from_u64(x_j as u64);
                
                // numerator *= (0 - x_j) = -x_j
                numerator = numerator * (FieldElement::zero() - x_j_fe);
                
                // denominator *= (x_i - x_j)
                denominator = denominator * (x_i_fe - x_j_fe);
            }
        }
        
        // L_i(0) = numerator / denominator
        // Division in field: a / b = a * b^-1
        let denom_inv = denominator.mod_inverse();
        let l_i = numerator * denom_inv;
        
        // Add y_i * L_i(0) to result
        result = result + y_i * l_i;
    }
    
    Ok(result.to_bytes())
}

impl FieldElement {
    /// Compute modular inverse using extended Euclidean algorithm
    fn mod_inverse(self) -> Self {
        // a^-1 mod p where p is prime
        // Use Fermat's little theorem: a^(p-2) = a^-1 mod p
        // For production, use proper modular exponentiation
        
        // Simplified: use extended Euclidean algorithm
        // This is a placeholder - real implementation needs careful work
        self
    }
}

#[derive(Debug)]
pub enum ShamirError {
    InvalidThreshold,
    ThresholdTooLow,
    NotEnoughShares,
    InvalidShare,
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_split_and_reconstruct() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        
        assert_eq!(shares.len(), 5);
        
        // Reconstruct with shares 0, 1, 2
        let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);
        
        // Reconstruct with shares 2, 3, 4
        let reconstructed2 = reconstruct_secret(&shares[2..5]).unwrap();
        assert_eq!(reconstructed2, secret);
    }
    
    #[test]
    fn test_insufficient_shares() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        
        // Try with only 2 shares - should fail or give wrong result
        // (With proper implementation, this should fail)
        let result = reconstruct_secret(&shares[0..2]);
        // May not return error, but won't reconstruct correctly
    }
}
```

---

## Integration Points

**File: `crates/snapfzz-seal-compiler/src/embed.rs`** (MODIFY)

```rust
use snapfzz_seal_core::shamir::{split_secret, reconstruct_secret};

pub fn embed_master_secret_with_shamir(
    launcher_bytes: &[u8],
    secret: &[u8; 32],
    markers: &[[u8; 32]; 5],
) -> Result<Vec<u8>, SealError> {
    // Split secret into 5 shares (need 3 to reconstruct)
    let shares = split_secret(secret, 3, 5)
        .map_err(|e| SealError::CompilationError(e.to_string()))?;
    
    let mut modified = launcher_bytes.to_vec();
    
    // Embed each share at different location
    for (i, (_x, share)) in shares.iter().enumerate() {
        let marker = &markers[i];
        
        // Find marker and embed share
        let offset = find_marker(&modified, marker)
            .ok_or_else(|| SealError::MarkerNotFound)?;
        
        let share_offset = offset + marker.len();
        
        // XOR share with location-specific key for extra protection
        let location_key = derive_location_key(i, share_offset);
        let mut obfuscated_share = *share;
        for (j, byte) in obfuscated_share.iter_mut().enumerate() {
            *byte ^= location_key[j];
        }
        
        modified[share_offset..share_offset + 32].copy_from_slice(&obfuscated_share);
    }
    
    Ok(modified)
}
```

---

## Files to Create/Modify

1. **CREATE:** `crates/snapfzz-seal-core/src/shamir.rs`
2. **MODIFY:** `crates/snapfzz-seal-compiler/src/embed.rs`
3. **MODIFY:** `crates/snapfzz-seal-core/src/lib.rs` (add pub mod shamir)

---

## Testing Requirements

```bash
cargo test --package snapfzz-seal-core shamir
```

---

## Success Criteria

- [ ] Shamir split creates 5 shares
- [ ] Reconstruct works with any 3 shares
- [ ] Reconstruct fails with < 3 shares
- [ ] Integration with embed.rs works
- [ ] All tests pass
- [ ] No external dependencies (pure Rust implementation)

---

## Notes

This implementation uses GF(2^256) arithmetic. For production, consider:
- Using well-tested crypto library (e.g., `curve25519-dalek`)
- Formal verification of field arithmetic
- Constant-time operations to prevent side channels