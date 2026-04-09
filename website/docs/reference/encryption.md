# Encryption Design

This document specifies cryptographic primitives and key derivation behavior used in Snapfzz Seal.

## Primitive set

- Authenticated encryption: **AES-256-GCM**
- KDF: **HKDF-SHA256**
- Signature: **Ed25519**
- Hashes: **SHA-256**, **HMAC-SHA256**

## AES-256-GCM stream usage

Encryption is performed in chunked stream mode.

### Parameters

- Key size: 256 bits
- Nonce prefix length for stream envelope: 7 bytes
- Plaintext chunk size: 65,536 bytes
- Authentication tag length: 16 bytes per encrypted segment

### Processing model

1. Generate stream nonce prefix with OS CSPRNG.
2. Encrypt sequential chunks with stream AEAD framing.
3. Append tag material per segment.
4. On decrypt, reject malformed or truncated streams.

## HKDF key derivation details

Environment key derivation:

```text
env_key = HKDF-SHA256(
  ikm = master_secret,
  salt = stable_hash || user_fingerprint,
  info = "snapfzz-seal/env/v1",
  L = 32
)
```

Session key derivation:

```text
session_key = HKDF-SHA256(
  ikm = env_key,
  salt = ephemeral_hash,
  info = "snapfzz-seal/session/v1",
  L = 32
)
```

Associated implementation constants:

- `KDF_INFO_ENV = b"snapfzz-seal/env/v1"`
- `KDF_INFO_SESSION = b"snapfzz-seal/session/v1"`

## Header authentication

Payload headers include an HMAC-SHA256 field over selected metadata fields:

- magic
- version
- encryption algorithm id
- format version
- chunk count

This prevents silent mutation of parsing-critical metadata before decryption.

## Security parameters and rationale

- 256-bit symmetric keys are used for margin against brute-force attacks.
- HKDF label separation is used to prevent key reuse across derivation contexts.
- Chunked stream design supports large payload processing while preserving AEAD guarantees.

## Practical derivation test snippet

```rust
use snapfzz_seal_core::derive::{derive_env_key, derive_session_key};

let master = [0x11u8; 32];
let stable = [0x22u8; 32];
let user = [0x33u8; 32];
let eph = [0x44u8; 32];

let env = derive_env_key(&master, &stable, &user).unwrap();
let session = derive_session_key(&env, &eph).unwrap();
assert_ne!(env, session);
```

## Security considerations

- Master secrets must be generated from cryptographically secure randomness.
- Distinct master secrets should be used for independent trust domains.
- Key material should be zeroized after use where possible.

## Limitations

- Software-only controls cannot prevent key extraction on fully compromised hosts.
- Embedded secret markers are documented and can be located by determined analysts.
- No hardware-backed key custody is enforced by default.

## Standards references

- NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation: GCM
- RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
