---
sidebar_position: 4
---

# Encryption Design

This document specifies the cryptographic primitives, key derivation scheme, and payload format used by Snapfzz Seal. All values are derived from the source in `crates/snapfzz-seal-core/src/`.

---

## Primitive set

| Purpose | Algorithm | Crate |
|---------|-----------|-------|
| Authenticated encryption | AES-256-GCM | `aes-gcm` |
| Stream AEAD framing | `aead-stream` `EncryptorBE32` / `DecryptorBE32` | `aead-stream` |
| Key derivation | HKDF-SHA256 | `hkdf` |
| Signing | Ed25519 | `ed25519-dalek` |
| Hashing and HMAC | SHA-256, HMAC-SHA256 | `sha2` |
| Key zeroization | `Zeroize` | `zeroize` |

---

## Wire constants

These constants are defined in `crates/snapfzz-seal-core/src/types.rs` and form the canonical wire format:

| Constant | Value | Description |
|----------|-------|-------------|
| `MAGIC_BYTES` | `ASL\x01` (4 bytes) | Payload header magic |
| `VERSION_V1` | `0x0001` | Payload format version |
| `ENC_ALG_AES256_GCM` | `0x0001` | Encryption algorithm identifier |
| `FMT_STREAM` | `0x0001` | Stream format identifier |
| `CHUNK_SIZE` | `65536` (64 KB) | Plaintext chunk size |
| `KDF_INFO_ENV` | `b"snapfzz-seal/env/v1"` | HKDF info label for environment key |
| `KDF_INFO_SESSION` | `b"snapfzz-seal/session/v1"` | HKDF info label for session key |
| `SHAMIR_TOTAL_SHARES` | `5` | Total Shamir shares embedded |
| `SHAMIR_THRESHOLD` | `3` | Minimum shares required to reconstruct |

The signature block appended by `seal sign` uses a separate magic value `ASL\x02` (not part of the encrypted payload header).

---

## AES-256-GCM stream encryption

Encryption is performed using the `aead-stream` crate's `StreamBE32` counter construction over `Aes256Gcm`.

### Stream layout

```
[ 7-byte stream nonce (random, CSPRNG) ]
[ encrypted chunk 0 (up to 65536 + 16 bytes) ]
[ encrypted chunk 1 (up to 65536 + 16 bytes) ]
...
[ encrypted last chunk (variable length + 16-byte tag) ]
```

### Parameters

| Parameter | Value |
|-----------|-------|
| Key size | 256 bits (32 bytes) |
| Stream nonce size | 7 bytes (generated with OS CSPRNG per encryption) |
| Plaintext chunk size | 65,536 bytes (64 KB) |
| Authentication tag size | 16 bytes per chunk |
| Encrypted chunk size | up to 65,552 bytes (chunk + tag) |

### Processing model

**Encryption:**

1. Generate a 7-byte stream nonce using the OS CSPRNG.
2. Write the nonce as the first 7 bytes of the output.
3. Read plaintext in 65,536-byte chunks.
4. For all chunks except the last, call `encrypt_next`; for the final chunk, call `encrypt_last`. Each encrypted chunk includes a 16-byte authentication tag.
5. Zeroize key and nonce material after use.

**Decryption:**

1. Read the 7-byte stream nonce from the start of the ciphertext.
2. Read ciphertext in 65,552-byte (chunk + tag) segments.
3. Decrypt each segment with `decrypt_next` / `decrypt_last`.
4. Reject any stream with a missing, truncated, or misauthenticated segment.

---

## Payload header

The `PayloadHeader` is written at the start of the encrypted payload and authenticated by an HMAC-SHA256 field:

```
[ magic: 4 bytes "ASL\x01" ]
[ version: u16 = 0x0001 ]
[ enc_alg: u16 = 0x0001 (AES-256-GCM) ]
[ fmt_version: u16 = 0x0001 (stream) ]
[ chunk_count: u32 ]
[ header_hmac: 32 bytes (HMAC-SHA256 over the above fields) ]
[ mode: AgentMode (u8: 0=Batch, 1=Interactive) ]
```

The `header_hmac` covers the fixed metadata fields (magic, version, enc_alg, fmt_version, chunk_count) and prevents silent mutation of parsing-critical fields before decryption.

## Payload footer

A `PayloadFooter` is appended after all chunk data:

```
[ original_hash: 32 bytes (SHA-256 of the unencrypted agent binary) ]
[ launcher_hash: 32 bytes (SHA-256 of the launcher binary) ]
[ backend_type: u8 (0=Unknown, 1=Go, 2=PyInstaller, 3=Nuitka) ]
```

---

## HKDF key derivation

Key derivation uses HKDF-SHA256 (`hkdf` crate). Two derivation steps are defined, controlled by the `--fingerprint-mode` flag on `seal launch`.

### Environment key (stable mode)

Used in both `stable` and `session` fingerprint modes.

```
env_key = HKDF-SHA256(
  ikm  = master_secret,          // 32 bytes
  salt = stable_hash || user_fingerprint,  // 64 bytes
  info = "snapfzz-seal/env/v1",
  L    = 32
)
```

- `stable_hash`: SHA-256 canonicalization of the stable fingerprint source set (see [Fingerprinting](./fingerprinting.md))
- `user_fingerprint`: 32-byte caller-supplied value passed via `--user-fingerprint`

### Session key (session mode only)

Derived from the environment key using ephemeral fingerprint material.

```
session_key = HKDF-SHA256(
  ikm  = env_key,                // 32 bytes
  salt = ephemeral_hash,         // 32 bytes
  info = "snapfzz-seal/session/v1",
  L    = 32
)
```

- `ephemeral_hash`: SHA-256 canonicalization of the ephemeral fingerprint source set (namespace inodes)

### Derivation mode summary

| `--fingerprint-mode` | Key used for decryption |
|----------------------|------------------------|
| `stable` | `env_key` |
| `session` | `session_key` |

---

## Master secret

The master secret is a 32-byte value generated with `OsRng` at compile time by `seal compile`. It is split into 5 Shamir shares (threshold 3) and embedded into the launcher binary at 5 marker-delimited slots.

At launch time the launcher scans its own bytes for at least 3 valid shares, reconstructs the master secret, then derives the decryption key. If fewer than 3 shares are found, it falls back to `SNAPFZZ_SEAL_MASTER_SECRET_HEX` from the environment.

---

## Security properties

- **256-bit symmetric keys** provide margin against brute-force attacks.
- **HKDF info label separation** (`env/v1` vs `session/v1`) prevents key reuse across derivation contexts.
- **Per-encryption stream nonce** (7 bytes, CSPRNG) ensures that re-encrypting the same plaintext with the same key produces distinct ciphertexts.
- **Per-chunk authentication tags** ensure that truncation or chunk reordering is detected.
- **Header HMAC** prevents silent mutation of metadata before decryption begins.
- **Zeroization** of key copies and nonce material after use reduces key exposure in memory.

---

## Security considerations

- Master secrets must be generated from cryptographically secure randomness. The compiler uses `OsRng` for this purpose.
- Distinct master secrets should be used for independent trust domains.
- Software-only controls cannot prevent key extraction on fully compromised hosts.
- Embedded secret markers are documented and locatable by static analysis; security depends on access controls and the binding of decryption keys to the correct fingerprint.
- No hardware-backed key custody is enforced by default.

---

## Limitations

- The stream nonce is 7 bytes. At 64 KB per chunk, a single encryption can handle approximately 2^32 chunks before counter exhaustion (the `StreamBE32` counter is 32 bits). This is approximately 256 TB of plaintext per encryption — sufficient for practical agent payloads.
- No hardware security module (HSM) or TPM integration is provided.

---

## Standards references

- **AES-GCM**: Dworkin, M. (2007). "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC". NIST SP 800-38D. [doi:10.6028/NIST.SP.800-38D](https://doi.org/10.6028/NIST.SP.800-38D)
- **HKDF**: Krawczyk, H. (2010). "Cryptographic Extraction and Key Derivation: The HKDF Scheme". RFC 5869. [doi:10.17487/RFC5869](https://doi.org/10.17487/RFC5869)
- **Ed25519**: Bernstein, D. et al. (2012). "High-speed high-security signatures". Journal of Cryptographic Engineering 4(2).
- **Shamir's Secret Sharing**: Shamir, A. (1979). "How to share a secret". Communications of the ACM 22(11).
