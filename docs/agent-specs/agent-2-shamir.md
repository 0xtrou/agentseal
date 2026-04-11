# Agent 2: Shamir Secret Sharing

## 1. Purpose

The Shamir Secret Sharing subsystem distributes the master decryption secret across five independent binary locations. An adversary performing offline binary analysis must locate and correctly read at least three of the five share slots to reconstruct the secret. Extraction of fewer than three shares yields no information about the secret under the security model of Shamir's scheme over a prime field.

---

## 2. Design Rationale

### 2.1 Threshold Scheme Parameters

The system uses a (3, 5) threshold scheme: the secret is split into five shares and any three shares suffice for reconstruction. This parameterization is encoded in `SHAMIR_THRESHOLD = 3` and `SHAMIR_TOTAL_SHARES = 5` in `crates/snapfzz-seal-core/src/types.rs`. The choice of five shares allows up to two share slots to be unreadable (due to binary modification, partial extraction, or deliberate decoy corruption) while still permitting reconstruction.

### 2.2 Field Selection

The implementation uses arithmetic over a 256-bit prime field. The modulus is the secp256k1 scalar field order:

```
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

represented in the source as the four-limb little-endian constant `MODULUS: [u64; 4]`. This prime was chosen because it is close to 2^256 (minimizing the probability that a uniformly random 32-byte secret falls outside the field), is well-studied, and has efficient reduction properties exploited by the `TWO_256_MINUS_MODULUS` constant used in the Barrett-style reduction path.

The secret must satisfy `secret < p`; inputs at or above the modulus are rejected with `ShamirError::SecretOutOfRange`.

### 2.3 Polynomial Evaluation

Split uses a degree-(threshold-1) polynomial whose constant term is the secret:

```
f(x) = secret + a_1 * x + a_2 * x^2 + ... + a_{k-1} * x^{k-1}
```

Coefficients `a_1` through `a_{k-1}` are drawn from `FieldElement::random_nonzero`, which loops rejection-sampling until the sampled value is both within the field range and non-zero. The polynomial is evaluated at `x = 1, 2, ..., n` using Horner's method in `eval_polynomial`.

Reconstruction uses Lagrange interpolation at `x = 0`:

```
f(0) = sum_i( y_i * prod_{j != i}( x_j / (x_j - x_i) ) )
```

The division `1 / (x_j - x_i)` is computed using Fermat's little theorem: `a^{-1} = a^{p-2} mod p`, implemented in `FieldElement::invert` via `self.pow(MODULUS_MINUS_TWO)`.

---

## 3. Implementation Details

### 3.1 FieldElement Representation

`FieldElement` stores a 256-bit value as four 64-bit limbs in little-endian order (`limbs[0]` holds the least significant 64 bits). The core arithmetic operations are:

- `field_add`: 256-bit addition with carry, followed by conditional subtraction of the modulus.
- `field_sub`: 256-bit subtraction with borrow; on underflow, adds `TWO_256_MINUS_MODULUS` (the two's complement of the modulus modulo 2^256) to recover the correct field representative.
- `field_mul`: Full 512-bit schoolbook multiplication via `mul_words`, followed by `reduce_product` which performs a Barrett-style reduction exploiting the Solinas-like structure of the modulus.

The reduction in `reduce_product` proceeds by extracting the high 256 bits, multiplying them by `TWO_256_MINUS_MODULUS` (i.e., `2^256 - p`), and adding the result back to the low 256 bits, iterating until the overflow limb (`reduced[4]`) is zero, then performing a final conditional subtraction to ensure the result is strictly less than `p`.

The `from_bytes` constructor interprets the input as a big-endian 256-bit integer and returns `ShamirError::SecretOutOfRange` if the value is `>= p`. `to_bytes` serializes in big-endian order. The `from_u64` constructor produces a field element from a small integer, used for share indices.

### 3.2 Public API

`crates/snapfzz-seal-core/src/shamir.rs` exposes:

```rust
pub fn split_secret(
    secret: &[u8; 32],
    threshold: usize,
    total_shares: usize,
) -> Result<Vec<(u8, [u8; 32])>, ShamirError>
```

This delegates to `split_secret_with_rng` using `rand::thread_rng()`. The RNG-parameterized variant is also public for deterministic testing:

```rust
pub fn split_secret_with_rng(
    secret: &[u8; 32],
    threshold: usize,
    total_shares: usize,
    rng: &mut impl RngCore,
) -> Result<Vec<(u8, [u8; 32])>, ShamirError>
```

Each share is returned as a tuple `(x: u8, y: [u8; 32])` where `x` is the evaluation point (1-indexed, `x = i` for the i-th share) and `y` is the field element value in big-endian byte form.

Reconstruction:

```rust
pub fn reconstruct_secret(
    shares: &[(u8, [u8; 32])],
    threshold: usize,
) -> Result<[u8; 32], ShamirError>
```

This function takes the first `threshold` shares from the slice, validates that all indices are non-zero and distinct (using a `BTreeSet`), and performs Lagrange interpolation.

### 3.3 Error Conditions

The `ShamirError` enum covers:

| Variant | Condition |
|---|---|
| `InvalidThreshold` | `threshold > total_shares` |
| `ThresholdTooLow` | `threshold < 2` |
| `TooManyShares` | `total_shares == 0 || total_shares > 255` |
| `NotEnoughShares` | `shares.len() < threshold` |
| `DuplicateShareIndex` | Repeated `x` value in reconstruction input |
| `InvalidShare(String)` | `x == 0`, or share value `>= p` |
| `SecretOutOfRange` | Secret bytes represent a value `>= p` |

`ShamirError` implements `std::fmt::Display` and `std::error::Error`.

### 3.4 Integration with embed.rs

`crates/snapfzz-seal-compiler/src/embed.rs` calls `split_secret` with the system constants:

```rust
let shares = split_secret(secret, SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES)
    .map_err(|e| embed_failed(&format!("shamir split failed: {e}")))?;
```

Each share `(x, share_bytes)` is embedded after the corresponding marker `get_secret_marker(i)` in the launcher binary using `find_marker_with_slot`. The `x` value is not stored separately; share indices are implicitly reconstructed from the position of the marker (share at `SECRET_MARKER_i` has index `x = i + 1`).

During reconstruction in the launcher, the `x` values must be supplied correctly. The launcher reads five shares from fixed marker positions and passes them to `reconstruct_secret` with `x` values `1` through `5` respectively.

---

## 4. Security Properties

**Implemented:**
- The scheme is information-theoretically secure for secrets below the field modulus: any `k-1 = 2` shares reveal no information about the secret under standard assumptions, because the remaining free coefficients are drawn uniformly at random.
- Shares are stored in nominally distinct binary regions separated by unique per-build marker values, requiring an adversary to locate all five regions independently.
- The reconstruction function rejects share index `0`, duplicate indices, and out-of-range share values, preventing trivial malformed-input attacks.
- Tampering with any single share value (without knowing the other shares and the polynomial structure) will produce an incorrect but computationally plausible reconstructed value, not a detectable error — consistent with the information-theoretic model.

**Limitations:**
- The modular inverse is computed via binary exponentiation (`pow(MODULUS_MINUS_TWO)`), which is not constant-time. A side-channel attacker with sufficient hardware access could potentially observe timing variations during reconstruction.
- The `x` values used during embedding are implicit (derived from marker position), not stored as part of the share record. If the launcher reconstructs shares in the wrong order, it may call `reconstruct_secret` with incorrect `x` assignments, producing garbage output silently.
- Rejection sampling in `random_nonzero` loops indefinitely in the cryptographically negligible event that all sampled values are either `0` or `>= p`. This does not represent a security risk but is a theoretical liveness concern.
- The field arithmetic implementation has not been subjected to formal verification or independent cryptographic audit.

---

## 5. Platform Restrictions

The Shamir implementation in `snapfzz-seal-core/src/shamir.rs` is platform-independent pure Rust with no OS-specific code paths. The `rand` dependency uses the platform's entropy source for coefficient generation; this source is available on all supported platforms.

---

## 6. Known Limitations

1. The round key derivation used by the whitebox layer (separate from Shamir) uses SHA-256 rather than the AES key schedule. This is noted in that module; it does not affect Shamir correctness.
2. The `reconstruct_secret` function uses the first `threshold` entries of the input slice, discarding any additional shares. This behavior is documented implicitly by the slice indexing `let selected = &shares[..threshold]` but is not surfaced as a warning to callers that pass more shares than needed.
3. The `to_bytes` / `from_bytes` contract uses big-endian representation while the internal limb array is little-endian. Any code that manually constructs `FieldElement` byte representations must observe this convention to avoid silent field encoding errors.
