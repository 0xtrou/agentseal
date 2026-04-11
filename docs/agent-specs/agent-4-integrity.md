# Agent 4: Binary Integrity Binding

## 1. Purpose

The integrity subsystem binds the launcher's decryption key to the content of the launcher binary itself. Rather than using the embedded secret directly as a decryption key, the launcher derives its working key as a function of both the embedded secret and a hash of the binary's non-secret regions. Any post-compilation modification to the launcher binary — such as patching anti-analysis checks, injecting code, or altering constants — changes the integrity hash, which in turn changes the derived key, causing decryption to fail. The tamper detection mechanism also supports explicit integrity verification against a hash embedded at compile time.

---

## 2. Design Rationale

### 2.1 Key Derivation with Integrity Binding

The core security property is expressed by `bind_secret_to_hash`:

```rust
fn bind_secret_to_hash(secret: &[u8; 32], integrity_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(integrity_hash);
    hasher.finalize().into()
}
```

The resulting key is `SHA-256(secret || integrity_hash)`. Any change to the binary that affects the integrity hash produces a completely different key, which in practice causes AES-GCM decryption to fail with an authentication tag mismatch rather than producing incorrect plaintext.

### 2.2 Region Exclusion

The embedded secret shares, tamper hash, and payload content are all variable by design: they are written into the binary at compile time and change with each build or key rotation. These regions must be excluded from the integrity hash to prevent the hash from being invalidated by the embedding process itself. The `find_secret_regions` function identifies all such excluded regions by scanning for known marker values in the binary.

### 2.3 ELF-Aware Region Selection

On Linux, the integrity hash covers the ELF executable (`PT_LOAD` executable flag set) and data (non-executable `PT_LOAD`) segments rather than the entire binary. This ensures that the hash covers the sections that a binary patcher would modify (code, read-only data, initialized data) while avoiding sections such as padding or dynamic linking metadata that may not be meaningful targets. On non-Linux platforms, the entire binary slice is used as a single code region.

---

## 3. Implementation Details

### 3.1 IntegrityRegions

`crates/snapfzz-seal-core/src/integrity.rs` defines:

```rust
pub struct IntegrityRegions {
    pub code_start: usize,
    pub code_end: usize,
    pub data_start: usize,
    pub data_end: usize,
    pub excluded: Vec<(usize, usize)>,
}
```

Regions are expressed as byte offsets into the binary slice. The `excluded` list is sorted and merged by `merge_regions` before use to ensure correct handling of overlapping exclusion intervals.

### 3.2 find_secret_regions

```rust
pub fn find_secret_regions(binary: &[u8]) -> Vec<(usize, usize)>
```

This function scans the binary for all occurrences of each of the following markers and adds each found region to the exclusion list:

- `SECRET_MARKER_0` through `SECRET_MARKER_4` (via `get_secret_marker(idx)`): each occurrence excludes the marker (32 bytes) plus the following 32-byte slot.
- `LAUNCHER_TAMPER_MARKER`: excludes the marker plus the following 32-byte slot.
- `LAUNCHER_PAYLOAD_SENTINEL`: excludes from the first occurrence of the sentinel to the end of the binary (`binary.len()`).

The function `collect_marker_regions` handles multi-occurrence scanning within each marker type. Overlapping or adjacent exclusion regions are merged by `merge_regions`, which sorts by start offset and extends intervals greedily.

### 3.3 ELF Parsing (Linux)

The function `is_supported_elf` validates that the binary is ELF64 little-endian x86-64 by checking the magic bytes, ELF class (byte 4 == 2 for 64-bit), data encoding (byte 5 == 1 for little-endian), and machine type (bytes 18-19 == `0x3e` for x86-64).

`parse_elf_regions` reads the program header table using `phoff` (offset 32), `phentsize` (offset 54), and `phnum` (offset 56). For each `PT_LOAD` segment (type == 1), it categorizes the segment as code (flags & `PF_X = 0x1`) or data (non-executable). The file offset (`p_offset` at header offset 8) and file size (`p_filesz` at header offset 32) are used to compute byte ranges. Multiple executable segments are merged into a single `code_range` by `extend_range`; similarly for data. The function requires at least one executable segment; absence causes an `InvalidInput` error. An absent data segment results in `data_range = (0, 0)` (zero-length, excluded from hashing).

Bounds checking is performed at every binary read via `read_slice`, `read_u16`, and `read_u64`, each of which return `InvalidInput` on out-of-bounds access.

### 3.4 hash_region_with_exclusions

```rust
fn hash_region_with_exclusions(
    hasher: &mut Sha256,
    binary: &[u8],
    start: usize,
    end: usize,
    excluded: &[(usize, usize)],
)
```

This function feeds contiguous byte ranges of `binary[start..end]` into the hasher, skipping any subranges that overlap with the exclusion list. The exclusion list is assumed to be pre-sorted by `merge_regions`. A `cursor` variable tracks the current hashing position; for each exclusion interval clipped to the region boundaries, content before the exclusion is hashed and the cursor advances past the exclusion.

### 3.5 Public API

Three public functions are provided:

**`compute_binary_integrity_hash`**: Hashes the code and data regions (minus exclusions). Requires at least one non-empty region; returns `InvalidInput` otherwise.

**`derive_key_with_integrity`** (Linux: reads `/proc/self/exe`; non-Linux: uses `bind_secret_to_hash(secret, secret)` as a deterministic fallback):

```rust
pub fn derive_key_with_integrity(
    embedded_secret: &[u8; 32],
    binary_path: Option<&str>,
) -> Result<[u8; 32], SealError>
```

**`derive_key_with_integrity_from_binary`** (takes binary bytes directly; used in assembly and tests):

```rust
pub fn derive_key_with_integrity_from_binary(
    embedded_secret: &[u8; 32],
    binary: &[u8],
) -> Result<[u8; 32], SealError>
```

**`verify_binary_integrity`** (Linux: reads the binary and compares computed hash against expected; non-Linux: always returns `Ok(())`; mismatch returns `SealError::TamperDetected`):

```rust
pub fn verify_binary_integrity(
    expected_hash: &[u8; 32],
    binary_path: Option<&str>,
) -> Result<(), SealError>
```

### 3.6 Assembly Integration

`crates/snapfzz-seal-compiler/src/assemble.rs` integrates the integrity subsystem as follows:

```rust
let regions = find_integrity_regions(&launcher_with_whitebox)?;
let launcher_integrity_hash = compute_binary_integrity_hash(&launcher_with_whitebox, &regions)?;
let integrity_key = derive_key_with_integrity_from_binary(&env_key, &launcher_with_whitebox)?;
```

The `env_key` (derived from the master secret and user/session fingerprints) is bound to the launcher's integrity hash to produce `integrity_key`, which is then used to encrypt the payload. The tamper hash embedded in the binary via `embed_tamper_hash` is a SHA-256 digest of the assembled launcher bytes (before whitebox table embedding), computed as:

```rust
let mut tamper_hash = [0_u8; 32];
tamper_hash.copy_from_slice(&Sha256::digest(&launcher_with_decoys));
```

This tamper hash is embedded at the `LAUNCHER_TAMPER_MARKER` slot and is itself excluded from the integrity region, so the integrity-bound key derivation remains consistent.

---

## 4. Security Properties

**Implemented:**
- Any modification to the executable or data regions of the launcher binary outside the excluded marker/slot/payload zones will change `compute_binary_integrity_hash`, which will change `derive_key_with_integrity`, which will cause AES-GCM decryption to fail with an authentication tag mismatch.
- The exclusion mechanism correctly handles all variable regions (share slots, tamper hash slot, appended payload) so that re-embedding does not invalidate the hash.
- `verify_binary_integrity` enables explicit hash comparison against the compile-time-embedded tamper hash, providing a secondary check independent of decryption success.
- The non-Linux fallback for `derive_key_with_integrity_from_binary` uses `bind_secret_to_hash(secret, secret)` — a deterministic but non-binary-dependent derivation — rather than silently returning the raw secret.

**Limitations:**
- On non-Linux platforms, `derive_key_with_integrity` does not perform binary integrity binding. The derived key is a fixed function of the secret only, providing no protection against binary modification on those platforms.
- An adversary who can read the binary at rest can compute the same integrity hash and derive the same key, since the hash is deterministic and uses only the binary content as input.
- `verify_binary_integrity` on non-Linux always returns `Ok(())` regardless of the `expected_hash` argument, offering no protection.
- The ELF parser does not validate all consistency constraints of the ELF format; a carefully malformed binary could produce unexpected region boundaries.

---

## 5. Platform Restrictions

- **Linux only:** ELF parsing, `find_integrity_regions` ELF path, `derive_key_with_integrity` binary read (via `/proc/self/exe`), and `verify_binary_integrity` all execute functional code only on Linux.
- **Linux x86-64 only:** `is_supported_elf` validates ELF class, encoding, and machine type fields. Binaries for other architectures (e.g., aarch64 Linux) will not match `is_supported_elf` and will fall back to whole-binary hashing.
- **macOS / other:** All integrity operations fall back to deterministic stubs that do not read the binary.

---

## 6. Known Limitations

1. The `hash_region_with_exclusions` function requires the exclusion list to be pre-sorted in ascending order by start offset. `merge_regions` guarantees this invariant, but callers that construct `IntegrityRegions` manually and pass unsorted exclusion lists will produce incorrect hashes silently.
2. The tamper hash embedded in the binary covers the launcher bytes before whitebox table embedding. The whitebox tables are appended to the binary after the tamper hash is computed and are excluded from the tamper hash region by the payload sentinel mechanism only if the sentinel appears before the tables. If the whitebox tables are appended after the payload sentinel, they are automatically excluded by the `LAUNCHER_PAYLOAD_SENTINEL` exclusion in `find_secret_regions`. Callers should verify this ordering assumption holds for their assembly pipeline.
3. The integrity hash operates on file offsets, not virtual addresses. If the binary is loaded at a different memory address (as is typical for PIE executables), the integrity hash computed against `/proc/self/exe` will still match the compile-time hash, which is correct behavior. However, in-memory patching (e.g., modifying `.text` after `mmap`) will not be detected unless the launcher re-reads and hashes the on-disk binary.
4. There is no mechanism to re-verify integrity after secret reconstruction. The single integrity check occurs during key derivation; subsequent in-memory modifications to the launcher are undetected.
