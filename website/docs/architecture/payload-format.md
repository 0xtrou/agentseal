# Payload Format

This document defines the binary structure used by Snapfzz Seal artifacts.

## Artifact structure overview

After assembly and signing, a complete artifact is laid out as:

```text
[launcher bytes]
[LAUNCHER_PAYLOAD_SENTINEL: 32 bytes]
[payload section]
[footer: 64 bytes]
[signature block: 100 bytes, after `seal sign`]
```

## Payload section specification

The payload section consists of:

1. Header (46 bytes)
2. Mode byte (1 byte)
3. Encrypted stream body (variable length)

Total fixed preamble: **47 bytes**.

### Header structure (46 bytes)

| Offset | Size | Field | Type | Description |
|---:|---:|---|---|---|
| 0 | 4 | `magic` | bytes | `ASL\x01` |
| 4 | 2 | `version` | little-endian `u16` | currently `0x0001` |
| 6 | 2 | `enc_alg` | little-endian `u16` | currently `0x0001` for AES-256-GCM |
| 8 | 2 | `fmt_version` | little-endian `u16` | currently `0x0001` |
| 10 | 4 | `chunk_count` | little-endian `u32` | plaintext chunk count |
| 14 | 32 | `header_hmac` | bytes | HMAC-SHA256 over header fields excluding this field |

### Mode byte (1 byte)

| Value | Meaning |
|---:|---|
| `0x00` | Batch mode |
| `0x01` | Interactive mode |

### Encryption envelope format

The encrypted stream body uses stream AEAD framing.

- Initial stream nonce: 7 bytes
- Encrypted chunks: plaintext chunk size up to 65,536 bytes
- Authentication tag per chunk: 16 bytes

No explicit per-chunk length prefix is stored in the payload body. Chunk interpretation relies on stream framing logic and total body length.

## Footer format (64 bytes)

The footer is appended after encrypted payload bytes.

| Offset | Size | Field | Description |
|---:|---:|---|---|
| 0 | 32 | `original_hash` | SHA-256 hash of compiled agent binary before encryption |
| 32 | 32 | `launcher_hash` | SHA-256 hash of launcher segment used for tamper check |

## Signature block format (100 bytes)

Added by `seal sign`:

| Offset from block start | Size | Field |
|---:|---:|---|
| 0 | 4 | Signature magic `ASL\x02` |
| 4 | 64 | Ed25519 signature |
| 68 | 32 | Builder public key |

## Practical inspection example

```bash
# file size and trailing signature marker inspection
stat -c "%s" ./agent.sealed
python - <<'PY'
from pathlib import Path
b = Path("./agent.sealed").read_bytes()
print("signature magic:", b[-100:-96])
print("payload magic index:", b.find(b"ASL\x01"))
PY
```

## Security considerations

- Header authentication prevents silent manipulation of algorithm identifiers and chunk metadata.
- Footer launcher hash allows runtime tamper detection of launcher bytes.
- Signature block binds builder identity to full artifact contents before block append.

## Limitations

- Format versioning is single-track at present and does not include backward compatibility negotiation.
- The signature block model assumes one active signature record at artifact tail.

## References

- **Ed25519**: Bernstein, D. et al. (2012). "High-speed high-security signatures". Journal of Cryptographic Engineering 4(2).
- **AES-GCM**: Dworkin, M. (2007). NIST SP 800-38D.
- **SHA-256**: NIST FIPS 180-4. Secure Hash Standard.
