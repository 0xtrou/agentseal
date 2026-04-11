# Agent 1: Build-Time Marker Generation and Decoy Injection

## 1. Purpose

The marker and decoy subsystem eliminates static, human-readable string patterns from the compiled launcher binary. Sentinel values that carry semantic content are trivially discoverable by binary analysis tools such as `strings`, `binwalk`, and YARA rule scanners. By replacing all sentinel and slot values with build-time-derived pseudorandom byte sequences, the system ensures no static signature survives into the output binary. A companion decoy injection mechanism is partially implemented to increase the cost of secret extraction.

---

## 2. Design Rationale

### 2.1 Deterministic Derivation from Build Identity

Markers must be reproducible across two independent compilation units — `snapfzz-seal-core` and `snapfzz-seal-launcher` — because the compiler embeds data at offsets located by scanning for markers, and the launcher reconstructs secrets by scanning for those same markers at runtime. The derivation function uses SHA-256 keyed on a `BUILD_ID` environment variable (defaulting to the string `"dev"` when absent). Each marker class is domain-separated by a fixed label suffix `b"deterministic_marker_v1"` and an instance-specific label (e.g., `b"secret_marker_0"`), preventing collisions across marker types while guaranteeing reproducibility within a build.

### 2.2 Compile-Time Code Generation

Both `snapfzz-seal-core` and `snapfzz-seal-launcher` emit marker constants from Cargo build scripts (`build.rs`). This is the correct Rust mechanism for producing values that are (a) embedded as static data in the binary and (b) known at compile time to the tooling that embeds payloads. The generated files are consumed via `include!` macros in `src/types.rs` (core) and `src/markers.rs` (launcher).

### 2.3 Launcher ELF Section Placement

The launcher's marker structure (`LAUNCHER_MARKERS`) is placed in a named linker section to separate it from general `.data` and make its file offset predictable. The section is platform-conditional: `.data.snapfzz_markers` on Linux, `__DATA,__snapfzz_mrk` on macOS. The structure is decorated with `#[used]`, `#[unsafe(no_mangle)]`, and `#[unsafe(link_section = ...)]` to prevent linker elimination and guarantee symbol addressability.

---

## 3. Implementation Details

### 3.1 Marker Derivation Function

Both `crates/snapfzz-seal-core/build.rs` and `crates/snapfzz-seal-launcher/build.rs` implement an identical derivation function:

```rust
fn derive_marker(build_id: &str, label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(build_id.as_bytes());
    hasher.update(label);
    hasher.update(b"deterministic_marker_v1");
    hasher.finalize().into()
}
```

The domain separator `b"deterministic_marker_v1"` is a fixed suffix included in every derivation to provide versioning and prevent cross-label collisions.

### 3.2 Generated Marker Constants (snapfzz-seal-core)

`crates/snapfzz-seal-core/build.rs` generates `OUT_DIR/generated_markers.rs` containing the following constants:

| Constant | Derivation Label | Purpose |
|---|---|---|
| `SECRET_MARKER_0` .. `SECRET_MARKER_4` | `"secret_marker_0"` .. `"secret_marker_4"` | Shamir share slot sentinels (one per share) |
| `TAMPER_MARKER` | `"tamper_marker"` | Tamper hash slot sentinel |
| `PAYLOAD_SENTINEL` | `"payload_sentinel"` | Launcher/payload boundary marker |
| `DECOY_MARKERS: [[u8; 32]; 50]` | `"decoy_marker_0"` .. `"decoy_marker_49"` | 10 sets of 5 decoy markers |
| `POSITION_HINT_SALT` | `"position_hint_salt"` | Salt used in decoy position obfuscation |

These constants are exposed in `crates/snapfzz-seal-core/src/types.rs` via:

```rust
include!(concat!(env!("OUT_DIR"), "/generated_markers.rs"));
```

Accessor functions `get_secret_marker(index: usize) -> &'static [u8; 32]` and `get_decoy_marker(set: usize, index: usize) -> &'static [u8; 32]` provide access. `get_secret_marker` panics on `index >= 5` (enforced by a `match` with no default arm other than `panic!`). `get_decoy_marker` uses flat indexing into `DECOY_MARKERS` as `set * 5 + index`.

### 3.3 Launcher Marker Structure (snapfzz-seal-launcher)

`crates/snapfzz-seal-launcher/build.rs` generates `OUT_DIR/launcher_markers.rs` containing C-layout structs:

```
MarkerSlot { marker: [u8; 32], slot: [u8; 32] }   // compile-time size assertion: 64 bytes
LauncherMarkers {                                   // compile-time size assertion: 416 bytes
    secret_share_0 .. secret_share_4: MarkerSlot,
    tamper_hash: MarkerSlot,
    payload_sentinel: [u8; 32],
}
```

The size assertions (`const _: [(); 64] = [(); core::mem::size_of::<MarkerSlot>()]` and `const _: [(); 416] = [(); core::mem::size_of::<LauncherMarkers>()]`) are compile-time guards that detect unintended layout changes across compiler versions.

The static variable `LAUNCHER_MARKERS: LauncherMarkers` is initialized with the five secret share markers and the tamper marker (each followed by a zero-initialized 32-byte slot), plus the payload sentinel. This layout allows compiler tooling to locate each slot by scanning for the corresponding marker prefix in the binary.

Note: the launcher `build.rs` emits the `#[cfg]` attribute for link section selection at build script evaluation time (using `#[cfg(target_os = "linux")]` / `#[cfg(target_os = "macos")]` in the build script itself), producing the correct section name string in the emitted source. Other platforms will not receive a `#[link_section]` attribute for a valid section name via this path.

### 3.4 Decoy Injection (snapfzz-seal-compiler)

`crates/snapfzz-seal-compiler/src/decoys.rs` implements the decoy embedding phase with four functions:

- `generate_decoy_secret(set_index: usize) -> [u8; 32]`: Produces a deterministic 32-byte value via SHA-256 over `b"DECOY_SECRET_V1"`, `set_index.to_le_bytes()`, and `POSITION_HINT_SALT`. The use of the build-time-derived salt ensures decoy secrets are build-specific.
- `generate_all_decoys() -> Vec<[u8; 32]>`: Calls `generate_decoy_secret` for all 10 sets (`DECOY_SETS = 10`).
- `obfuscate_real_position(real_index: usize, salt: &[u8; 32]) -> [u8; 32]`: Encodes the real slot index as a SHA-256 digest of `b"REAL_POSITION_HINT"`, the index bytes, and a per-invocation random salt.
- `determine_real_position(hint: &[u8; 32], salt: &[u8; 32]) -> usize`: Recovers the index by iterating `0..(DECOY_SETS + 1)` and comparing each candidate's obfuscated form against the hint; returns `0` if no match is found.
- `embed_decoy_secrets(binary: &[u8], real_index: usize) -> Result<Vec<u8>, SealError>`: Scans the binary for the marker `b"ASL_POSITION_HINT_v1"` (`POSITION_HINT_MARKER`) and overwrites the following 32 bytes with the position hint. The random salt is generated via `rand::random::<[u8; 32]>()` at embed time.

**Implemented but incomplete:** `embed_decoy_secrets` generates the decoy secrets via `generate_all_decoys()` and binds the result to `let _decoys`. The generated decoys are not written into the binary. Only the position hint field is written if the `ASL_POSITION_HINT_v1` marker is present in the binary.

### 3.5 Assembly Integration

In `crates/snapfzz-seal-compiler/src/assemble.rs`, the assembly pipeline calls:

```rust
let launcher_with_secret = embed_master_secret(&launcher_bytes, &config.master_secret)?;
let launcher_with_decoys = embed_decoy_secrets(&launcher_with_secret, 0)?;
let launcher_with_tamper = embed_tamper_hash(&launcher_with_decoys, &tamper_hash)?;
let launcher_with_whitebox = embed_whitebox_tables(&launcher_with_tamper, &whitebox_tables)?;
```

The decoy injection step precedes tamper hash calculation, ensuring that any future decoy content would be incorporated into the tamper hash. The `real_index` argument is currently hardcoded to `0`.

---

## 4. Shamir Integration Constants

`crates/snapfzz-seal-core/src/types.rs` defines the system-wide Shamir parameters:

```rust
pub const SHAMIR_TOTAL_SHARES: usize = 5;
pub const SHAMIR_THRESHOLD: usize = 3;
```

These constants govern both the split phase (compiler) and the reconstruction phase (launcher). The aliases `LAUNCHER_SECRET_MARKER`, `LAUNCHER_TAMPER_MARKER`, and `LAUNCHER_PAYLOAD_SENTINEL` re-export `SECRET_MARKER_0`, `TAMPER_MARKER`, and `PAYLOAD_SENTINEL` respectively, providing a stable naming boundary between crates.

---

## 5. Security Properties

**Implemented:**
- All markers in the compiled binary are SHA-256 digests derived from `BUILD_ID`. A `strings` scan over the output binary will not reveal semantically meaningful marker names.
- Markers are build-specific: changing `BUILD_ID` regenerates all markers, invalidating any payload embedded against a prior build.
- Five distinct marker values (`SECRET_MARKER_0` through `SECRET_MARKER_4`) ensure that no two Shamir share slots share the same sentinel, preventing ambiguity during embedding and reconstruction.
- The `marker_is_followed_by_slot` validation in `embed.rs` rejects any candidate marker occurrence whose following 32 bytes overlap another known marker (payload sentinel, tamper marker, or any share marker), preventing false-positive slot selection during compilation.
- Decoy position obfuscation uses a fresh random salt per assembly invocation, so the position hint value in the binary changes on every compile even for the same `BUILD_ID`.

**Aspirational / Not Yet Implemented:**
- Embedding of the full set of 10 decoy secrets as distinct in-binary data blobs. The generation infrastructure (`generate_all_decoys`, `DECOY_MARKERS`) exists but the actual multi-slot decoy embedding is not implemented.
- The launcher reconstruction path does not use `determine_real_position` to select which share slots to reconstruct from; it uses `SECRET_MARKER_0` through `SECRET_MARKER_4` unconditionally.

---

## 6. Platform Restrictions

- **Build consistency**: The `BUILD_ID` environment variable must be set identically for both `snapfzz-seal-core` and `snapfzz-seal-launcher` compilation units for marker agreement. When absent, both default to `"dev"`.
- **Linker section names**: The `#[link_section]` attribute uses platform-conditional section names derived at build script evaluation time. Linux and macOS are accommodated; other platforms are not.
- **Decoy injection**: `embed_decoy_secrets` operates on raw byte slices via marker scanning and is platform-independent.

---

## 7. Known Limitations

1. The `derive_marker` function produces values that are fully deterministic from `BUILD_ID`. Any party with knowledge of the `BUILD_ID` value and the derivation procedure can reproduce all markers. The `BUILD_ID` is re-emitted as a Cargo environment variable (`cargo:rustc-env=BUILD_ID=...` in `snapfzz-seal-core/build.rs`) and may be discoverable through build artifact metadata.
2. The decoy injection step computes 10 decoy secrets but discards them (`let _decoys = generate_all_decoys()`). Only the position hint field is conditionally written. There are no in-binary decoy secret slots.
3. The `DECOY_MARKERS` array (50 entries) is referenced by `get_decoy_marker` and by tests verifying distinctness from secret markers, but the launcher reconstruction path does not reference it at runtime.
4. The `real_index` parameter to `embed_decoy_secrets` is hardcoded to `0` in the assembly pipeline, making the position hint value predictable for any analyst who reconstructs the derivation logic.
