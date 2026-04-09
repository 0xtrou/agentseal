# Payload Format

Version 1 payload structure.

## Header (fixed)

```text
Offset  Size  Field
0       4     magic ("ASL\x01")
4       2     version (0x0001)
6       2     enc_alg (0x0001 = AES-256-GCM)
8       2     fmt_version (0x0001 = streaming)
10      4     chunk_count
14      32    header_hmac
46      1     mode_byte (0x00=batch, 0x01=interactive)
```

## Chunk Records (variable)

```text
For each chunk:
  - 4 bytes: chunk length (ciphertext + tag)
  - N bytes: ciphertext
  - 16 bytes: GCM authentication tag
```

Chunk size baseline: 64 KiB plaintext → ~64 KiB + 16 bytes ciphertext.

## Footer (fixed)

```text
Offset  Size  Field
0       32    original_hash (hash of pre-encryption agent)
32      32    launcher_hash (hash of launcher with embedded secret)
```

Total footer size: 64 bytes.

## Signature Block (appended after signing)

```text
Offset  Size  Field
0       4     magic ("ASL\x02")
4       64    Ed25519 signature
68      32    Ed25519 public key
```

Total signature block: 100 bytes.

## Full Layout

```text
┌─────────────┐
│ Header      │  47 bytes
├─────────────┤
│ Chunks      │  variable
├─────────────┤
│ Footer      │  64 bytes
├─────────────┤
│ Signature   │  100 bytes (if signed)
└─────────────┘
```