# Payload Format

This document defines the binary structure used by Snapfzz Seal artifacts. All values are sourced from `crates/snapfzz-seal-core/src/types.rs`.

## Artifact structure overview

After assembly and signing, a complete artifact is laid out as:

```text
[launcher bytes]
[LAUNCHER_PAYLOAD_SENTINEL: 32 bytes]
[payload section]
[footer: 65 bytes]
[signature block: 100 bytes, after `seal sign`]
```

The `LAUNCHER_PAYLOAD_SENTINEL` is a 32-byte compile-time random marker (`PAYLOAD_SENTINEL`) that separates the launcher binary from the payload section.

## Payload section specification

The payload section consists of:

1. Header (46 bytes)
2. Mode byte (1 byte)
3. Encrypted stream body (variable length)

Total fixed preamble: **47 bytes**.

### Header structure (46 bytes)

| Offset | Size | Field | Type | Value / Description |
|---:|---:|---|---|---|
| 0 | 4 | `magic` | `[u8; 4]` | `0x41 0x53 0x4C 0x01` (`ASL\x01`) |
| 4 | 2 | `version` | little-endian `u16` | `0x0001` (`VERSION_V1`) |
| 6 | 2 | `enc_alg` | little-endian `u16` | `0x0001` (`ENC_ALG_AES256_GCM`, AES-256-GCM) |
| 8 | 2 | `fmt_version` | little-endian `u16` | `0x0001` (`FMT_STREAM`) |
| 10 | 4 | `chunk_count` | little-endian `u32` | Number of plaintext chunks |
| 14 | 32 | `header_hmac` | `[u8; 32]` | HMAC-SHA256 over header fields preceding this field |

The `magic` bytes in ASCII are `A`, `S`, `L` followed by the byte `0x01`. This is distinct from the signature block magic `ASL\x02`.

### Mode byte (1 byte)

Follows the 46-byte header immediately at offset 46:

| Value | Constant | Meaning |
|---:|---|---|
| `0x00` | `AgentMode::Batch` | Batch (non-interactive) mode |
| `0x01` | `AgentMode::Interactive` | Interactive mode |

`AgentMode::Batch` is the default.

### Encryption envelope format

The encrypted stream body uses AEAD stream framing (`aead-stream` crate).

- Plaintext chunk size: up to `65536` bytes (`CHUNK_SIZE = 65536`, i.e., 64 KiB)
- Authentication tag per chunk: 16 bytes appended to each ciphertext chunk
- Initial stream nonce: provided by the stream cipher initialization

Each encrypted chunk record carries:

| Field | Type | Description |
|---|---|---|
| `len` | `u32` | Byte length of this chunk's ciphertext (excluding tag) |
| `data` | `Vec<u8>` | Ciphertext bytes plus 16-byte authentication tag |

No plaintext length prefix is stored in the wire format; chunk boundaries are determined by the stream framing logic and the `chunk_count` field in the header.

## Footer format (65 bytes)

The footer is appended immediately after the encrypted stream body.

| Offset | Size | Field | Type | Description |
|---:|---:|---|---|---|
| 0 | 32 | `original_hash` | `[u8; 32]` | SHA-256 hash of the compiled agent binary before encryption |
| 32 | 32 | `launcher_hash` | `[u8; 32]` | SHA-256 hash of the launcher segment for tamper detection |
| 64 | 1 | `backend_type` | `u8` | Backend identifier (see table below) |

The footer is **65 bytes** total, not 64. The extra byte encodes the backend type.

### `BackendType` encoding

| Value | Constant | Backend |
|---:|---|---|
| `0x00` | `BackendType::Unknown` | Unknown / unset |
| `0x01` | `BackendType::Go` | Go backend |
| `0x02` | `BackendType::PyInstaller` | PyInstaller backend |
| `0x03` | `BackendType::Nuitka` | Nuitka backend |

The launcher reads this byte to determine which execution path to use (`MemfdExecutor` for Go, `TempFileExecutor` for PyInstaller and Nuitka).

## Signature block format (100 bytes)

Added by `seal sign`:

| Offset from block start | Size | Field | Description |
|---:|---:|---|---|
| 0 | 4 | Signature magic | `0x41 0x53 0x4C 0x02` (`ASL\x02`) |
| 4 | 64 | Ed25519 signature | Signature over all bytes preceding this block |
| 68 | 32 | Builder public key | Ed25519 public key of the signing party |

## Practical inspection example

```bash
# Confirm file size and locate payload magic
python3 - <<'PY'
from pathlib import Path
b = Path("./agent.sealed").read_bytes()
idx = b.find(b"ASL\x01")
print(f"payload magic at offset: {idx}")
print(f"signature magic: {b[-100:-96].hex()}")  # expects 41534c02
print(f"backend_type byte: 0x{b[-(100+1)]:#04x}")  # byte before signature block
PY
```

## Security considerations

- Header HMAC prevents silent manipulation of algorithm identifiers, format version, and chunk count.
- Footer `launcher_hash` allows runtime tamper detection of the launcher bytes.
- The `backend_type` field determines execution strategy; a tampered value is caught by the header HMAC because it would invalidate the authenticated header.
- The signature block binds builder identity to the full artifact. Signature verification is performed by the launcher before any decryption or execution.

## Limitations

- Format versioning is single-track and does not include backward compatibility negotiation.
- The signature block model assumes one active signature record at the artifact tail.

## References

- **Ed25519**: Bernstein, D. et al. (2012). "High-speed high-security signatures". Journal of Cryptographic Engineering 4(2).
- **AES-GCM**: Dworkin, M. (2007). NIST SP 800-38D.
- **SHA-256**: NIST FIPS 180-4. Secure Hash Standard.
- **HKDF**: Krawczyk, H. (2010). RFC 5869.
