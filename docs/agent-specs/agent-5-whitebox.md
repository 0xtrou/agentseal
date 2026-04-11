# Agent 5: White-Box Cryptography

## 1. Purpose

The white-box subsystem generates a set of key-dependent lookup tables that are embedded in the launcher binary in place of the raw master key. The intent is to raise the cost of static key extraction: rather than a 32-byte key appearing as a contiguous blob, the key material is dispersed across approximately 57 000 bytes of lookup table data structured as T-boxes and mixing tables. At runtime, these tables are used to perform AES-like decryption without a directly recoverable key value.

**Important caveat:** The current implementation is a structural approximation of the Chow et al. white-box AES construction and does not constitute a cryptographically sound white-box scheme. The limitations are described in detail in Section 6.

---

## 2. Design Rationale

### 2.1 White-Box AES Concept

In a standard AES implementation, the key is loaded into registers at runtime and is in principle recoverable by a debugger or memory dump. White-box AES replaces the key-schedule-dependent transformations with precomputed lookup tables that absorb the key into their entries. An adversary who can observe only the table lookups cannot straightforwardly extract the key, because each table entry is a function of both the key and the plaintext/ciphertext bytes.

The Chow et al. (2002) construction achieves this by:
1. Combining SubBytes and AddRoundKey into key-dependent T-boxes.
2. Composing T-box outputs with MixColumns using XOR-decomposed lookup tables.
3. Applying random bijections at table boundaries to prevent the key from appearing at any intermediate computation point.

The current implementation incorporates steps 1 and 2 structurally, but the bijection application (step 3) is partial and does not achieve the security properties of the full Chow construction.

### 2.2 Non-Standard Round Key Derivation

AES-256 key schedule uses an iterative process involving S-box substitution and XOR with round constants. This implementation derives each of the 14 round keys using SHA-256:

```rust
fn derive_round_key(key: &[u8; 32], round: usize) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update((round as u32).to_le_bytes());
    hasher.finalize().into()  // uses first 16 bytes
}
```

This substitution means the generated tables are **not** compatible with standard AES-256 encryption. Ciphertext produced by standard AES-256 with the same key cannot be decrypted using these tables. The tables form their own self-consistent cipher, but it is not standard AES.

---

## 3. Implementation Details

### 3.1 Table Types

Three table types are defined in `crates/snapfzz-seal-core/src/whitebox/tables.rs`:

- **`TBox`**: A 256-entry byte-to-byte lookup table for a single byte position in a round. Fields: `round: usize`, `byte_idx: usize`, `table: [u8; 256]`.
- **`TypeI`**: A set of four column tables, each containing four 256-entry row tables, for use in mixing. Fields: `round: usize`, `tables: Vec<[[u8; 256]; 4]>`.
- **`TypeII`**: Identical structure to `TypeI`, used for the inverse mixing pass. Fields: `round: usize`, `tables: Vec<[[u8; 256]; 4]>`.

`WhiteBoxTables` aggregates these:

```rust
pub struct WhiteBoxTables {
    pub t_boxes: Vec<TBox>,
    pub type_i: Vec<TypeI>,
    pub type_ii: Vec<TypeII>,
    pub randomization: Vec<[u8; 16]>,
}
```

The `zeroize` method zeroes T-box table entries and clears the randomization vector using the `zeroize` crate.

### 3.2 Table Generation

`WhiteBoxAES::generate_tables(key: &[u8; 32]) -> WhiteBoxTables` in `crates/snapfzz-seal-core/src/whitebox/aes.rs`:

1. For each of 14 rounds (AES-256 round count), derives a 16-byte round key via `derive_round_key`. For each of 16 byte positions, calls `generate_t_box` to produce a `TBox`.
2. For rounds 0..13, calls `generate_type_i(round)` and `generate_type_ii(round + 1)` to produce one `TypeI` and one `TypeII` table per round (13 each).
3. Calls `tables.randomize()`.

The resulting counts are: 14 * 16 = **224 T-boxes**, **13 TypeI tables**, **13 TypeII tables**.

**T-box generation:** Each T-box entry for input byte `b` is computed as `INV_SBOX[b] XOR round_key[byte_idx]`. The use of `INV_SBOX` (the AES inverse S-box) is consistent with a decryption-oriented construction.

**Type I (mixing) tables:** GF(2^8) multiplication of each input byte by the inverse MixColumns coefficients (`0x0e, 0x0b, 0x0d, 0x09`), one coefficient per row. These are used to apply the InvMixColumns linear transformation in tabular form.

**Type II tables:** GF(2^8) multiplication by standard MixColumns coefficients (`2, 3, 1, 1`). These apply the forward MixColumns in tabular form.

**Randomization:** `randomize()` generates 16 random 16-byte values and XORs each T-box entry `table[j]` with `randomization[t_box_index % 16][j % 16]`. This randomization is **not invertible** without storing the randomization values alongside the tables. As currently implemented, the randomization corrupts the T-box lookups for any use outside a matched decryption path that accounts for the XOR. The randomization vectors are stored in `WhiteBoxTables.randomization` and are serialized into the embedded binary.

**GF(2^8) arithmetic:** The `gf_mult` function implements multiplication in GF(2^8) with the AES irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (reduction constant `0x1b`) using the standard shift-and-XOR method.

### 3.3 Serialization

`WhiteBoxTables::to_bytes()` serializes in the following order:
1. 4-byte little-endian T-box count.
2. For each T-box: 1-byte round, 1-byte byte_idx, 256-byte table. (258 bytes each)
3. 4-byte little-endian Type I count.
4. For each Type I entry: 1-byte round, then 4 * 4 * 256 = 4096 bytes of column/row table data. (4097 bytes each)
5. 4-byte little-endian Type II count. (Type II table data is not serialized beyond the count.)

Note: Type II table data is **not included** in the serialized output despite being present in the `WhiteBoxTables` struct. Only the count is written. This is a current implementation limitation.

Estimated serialized size for a full table set: 224 * 258 + 13 * 4097 + 1000 ≈ 111 273 bytes. The `estimate_whitebox_size` function in `whitebox_embed.rs` returns the hardcoded value `2_000_000`, which overestimates significantly.

### 3.4 Compiler Integration (whitebox_embed.rs)

`crates/snapfzz-seal-compiler/src/whitebox_embed.rs` exposes:

- `WHITEBOX_TABLES_MARKER: &[u8] = b"ASL_WB_TABLES_v1"` — the binary marker used to locate the embedded table slot.
- `generate_whitebox_tables(master_key: &[u8; 32]) -> WhiteBoxTables`: calls `WhiteBoxAES::generate_tables`.
- `embed_whitebox_tables(binary: &[u8], tables: &WhiteBoxTables) -> Result<Vec<u8>, SealError>`: searches for `WHITEBOX_TABLES_MARKER` in the binary. If found, writes the serialized tables immediately after the marker, extending the binary slice if needed. If the marker is not found, appends the marker followed by the serialized tables to the end of the binary.
- `estimate_whitebox_size() -> usize`: returns `2_000_000` (hardcoded, overestimates actual table size by approximately 18x).

In the assembly pipeline (`assemble.rs`):

```rust
let whitebox_tables = generate_whitebox_tables(&config.master_secret);
let launcher_with_whitebox = embed_whitebox_tables(&launcher_with_tamper, &whitebox_tables)?;
```

The whitebox tables are embedded after the tamper hash is computed, so the tables are excluded from the tamper-bounded hash only if they appear after the payload sentinel in the final binary layout.

---

## 4. Security Properties

**Implemented:**
- The master key does not appear as a contiguous 32-byte value in the embedded binary. A static search for the key bytes will not find a direct match.
- T-box entries are key-dependent: each entry encodes the application of the inverse S-box and a round key byte to one input value. The key is distributed across 224 tables of 256 entries each.
- Randomization adds a per-build XOR layer over T-box entries using values from `rand::random`, making each build's table set distinct in byte content even for the same key.
- The `WhiteBoxTables::zeroize` method supports explicit clearing of sensitive table content from memory.

**Limitations (see Section 6):**
- The bijection layer required for the Chow construction to achieve its claimed security properties is absent. The randomization applied is a simple XOR that does not satisfy the algebraic independence requirements of a true white-box implementation.
- Round keys are derived via SHA-256 rather than the AES key schedule, making the tables incompatible with standard AES and preventing verification against known-answer tests.
- The Type II table data is not serialized. Any launcher code that attempts to deserialize and use Type II tables from the binary will find them absent.
- No formal security reduction or hardness argument applies to this construction.

---

## 5. Platform Restrictions

The white-box module (`snapfzz-seal-core/src/whitebox/`) is pure Rust with no platform-specific code. Table generation, serialization, and embedding are platform-independent. The `rand::random` calls in `randomize()` use the platform entropy source.

---

## 6. Known Limitations

1. **Not a sound white-box implementation.** The Chow et al. construction requires that the composition of encoded T-boxes with random bijections produce tables whose outputs are indistinguishable from random without knowledge of the bijections. The current implementation's `randomize()` applies a non-invertible XOR and does not implement compatible inverse bijections on the input or output side. A decryption path using these tables would need to account for the randomization layer, which is not the case in the current `decrypt` implementation, making the tables non-functional for actual decryption.

2. **Non-standard round key schedule.** SHA-256-based round key derivation is not the AES key schedule and produces different subkeys than standard AES. The resulting cipher is custom and has no published security analysis.

3. **Type II table data omitted from serialization.** The `to_bytes` method serializes only the Type II count, not the actual table data. Any deserialization code expecting Type II data will find an empty result.

4. **Duplicate Type I coefficients between Type I and Type II.** In the current code, `generate_type_i` uses inverse MixColumns coefficients (`0x0e, 0x0b, 0x0d, 0x09`) and `generate_type_ii` uses forward MixColumns coefficients (`2, 3, 1, 1`). Architecturally these are labelled in opposition to the Chow convention (Type I should use forward MixColumns to transform T-box output; Type II should provide the inverse). The labeling inversion does not affect correctness if both types are consistently applied in the same order, but it differs from the reference construction and complicates maintenance.

5. **Overestimated size constant.** `estimate_whitebox_size()` returns `2_000_000` bytes. Actual serialized table size is approximately 111 000 bytes for 224 T-boxes and 13 Type I entries (with Type II data absent). Code using the estimate for memory allocation or transport sizing will over-allocate significantly.

6. **No production readiness.** This implementation was developed as a structural approximation to inform compiler pipeline integration. Any use of this module for actual key protection requires replacement with a formally analyzed construction (such as a published white-box AES library) or a formal security audit of the full construction including bijection layer, serialization format, and decryption path.
