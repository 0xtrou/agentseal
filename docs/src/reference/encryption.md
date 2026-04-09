# Encryption Design

Agent Seal uses AES-256-GCM streaming encryption with HKDF key derivation.

## Streaming Encryption

| Property | Value |
|----------|-------|
| Algorithm | AES-256-GCM |
| Mode | Chunked streaming |
| Chunk size | 64 KiB |
| Tag size | 16 bytes per chunk |

### Why Streaming?

- Avoids loading large binaries into memory as one plaintext block
- Enables bounded memory usage during encryption/decryption
- Each chunk authenticated independently

## Dual HKDF Derivation

Two-stage key derivation binds decryption to environment:

### Environment Key

```
K_env = HKDF(
  ikm = master_secret,
  salt = stable_fingerprint || user_fingerprint,
  info = "agent-seal/env/v1"
)
```

Binds to stable environment signals + user identity.

### Session Key

```
K_session = HKDF(
  ikm = K_env,
  salt = ephemeral_fingerprint,
  info = "agent-seal/session/v1"
)
```

Adds session-level binding (namespace inodes, UIDs).

## Payload Format (v1)

```text
┌──────────┬─────────┬─────────┬──────────┬────────────┬─────────────┐
│ magic    │ version │ enc_alg │ fmt_ver  │ chunk_count│ header_hmac │
│ ASL\x01  │ u16     │ u16     │ u16      │ u32        │ [u8; 32]    │
└──────────┴─────────┴─────────┴──────────┴────────────┴─────────────┘
┌──────────────┐
│ mode_byte[1] │ 0x00=batch, 0x01=interactive
└──────────────┘
┌──────────────────────────────────────────────────────────────────────┐
│ chunk records: [len:u32][ciphertext+tag] * N                        │
└──────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────┐
│ footer: original_hash[32] + launcher_hash[32]                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Master Secret Delivery

| Method | Security | Use Case |
|--------|----------|----------|
| Embedded in binary | Extractable via marker scan | Portable, single-file distribution |
| Environment variable | Visible in `/proc/[pid]/environ` | CI/CD, ephemeral secrets |

> **Note:** Embedded secret is recoverable via known marker (`ASL_SECRET_MRK_v1...`). Protection is against casual inspection, not determined reverse engineering.