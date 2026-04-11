---
sidebar_position: 5
---

# Signing Workflow

This document specifies key lifecycle and signature verification procedures for Snapfzz Seal artifacts.

## Overview

Snapfzz Seal uses Ed25519 (EdDSA over Curve25519) for artifact signing. The `seal sign` subcommand appends a 100-byte signature block to an assembled artifact. The `seal verify` subcommand checks that block using either the public key embedded in the artifact (TOFU) or an externally pinned public key file.

## Key generation

```bash
seal keygen
```

Default output directory: `~/.snapfzz-seal/keys/`

To write keys to a custom directory:

```bash
seal keygen --keys-dir /path/to/keys
```

Generated files:

| File | Content |
|------|---------|
| `builder_secret.key` | Hex-encoded 32-byte Ed25519 signing (private) key |
| `builder_public.key` | Hex-encoded 32-byte Ed25519 verifying (public) key |

Example console output:

```text
secret: /home/<user>/.snapfzz-seal/keys/builder_secret.key
public: /home/<user>/.snapfzz-seal/keys/builder_public.key
builder id: <16-hex-prefix>
```

The `builder id` is the first 16 hex characters of the public key, useful as a human-readable key identifier in logs and release metadata.

Protect private key files with restrictive permissions:

```bash
chmod 600 ~/.snapfzz-seal/keys/builder_secret.key
```

## Signing procedure

```bash
seal sign \
  --key ~/.snapfzz-seal/keys/builder_secret.key \
  --binary ./agent.sealed
```

`seal sign` reads the public key from the same directory as `--key` automatically (it expects a file named `builder_public.key` in the same parent directory). Both files must be present.

On success, no output is printed. The binary is modified in-place: the following 100-byte block is appended to the file:

```text
ASL\x02          (4 bytes — magic marker)
signature        (64 bytes — Ed25519 signature over all preceding bytes)
embedded_pubkey  (32 bytes — Ed25519 public key of the signer)
```

The signature covers all bytes of the artifact prior to this block. Appending the block after signing does not invalidate the signature because the signature is over the pre-block content only.

### Flag reference for `seal sign`

| Flag | Required | Description |
|------|----------|-------------|
| `--key` | Yes | Path to the hex-encoded Ed25519 private key file |
| `--binary` | Yes | Path to the assembled artifact to sign (modified in-place) |

## Verification workflow

### Pinned verification (recommended for production)

Pinned verification checks the signature against an externally supplied public key. This provides assurance that the artifact was signed by the expected builder identity.

```bash
seal verify \
  --binary ./agent.sealed \
  --pubkey ~/.snapfzz-seal/keys/builder_public.key
```

Expected output on success:

```text
VALID (pinned to explicit public key)
```

### TOFU verification (embedded key)

When `--pubkey` is omitted, `seal verify` uses the public key embedded in the artifact's signature block.

```bash
seal verify --binary ./agent.sealed
```

Expected output on success:

```text
VALID (TOFU: using embedded key — use --pubkey for pinned builder identity)
```

TOFU verification detects accidental corruption and verifies self-consistency, but it does **not** verify who signed the artifact. An attacker who replaces the payload and re-signs with a new key will produce a TOFU-valid artifact. Always use `--pubkey` in production.

### Output when unsigned

If the artifact does not contain a signature block, `seal verify` prints:

```text
WARNING: unsigned
```

and exits with code 0. A missing signature does not cause a non-zero exit. CI pipelines that require a signed artifact should check for this warning string or enforce signing as a separate gate.

### Flag reference for `seal verify`

| Flag | Required | Description |
|------|----------|-------------|
| `--binary` | Yes | Path to the artifact to verify |
| `--pubkey` | No | Path to the hex-encoded Ed25519 public key file for pinned verification |

## Key management procedures

### Storage policy

- Store private keys in dedicated secret backends or HSM-backed systems where available.
- Restrict file permissions to the signing principal (`chmod 600`).
- Keep production and non-production key material isolated.
- Never commit key files to source control.

### Distribution policy

- Publish public keys through authenticated channels.
- Version public keys and associate validity intervals in deployment metadata.
- The `builder id` (16-hex prefix of the public key) is a useful stable identifier for tracking which key signed a given artifact.

### Incident response

If key compromise is suspected:

1. Remove the compromised public key from all verifier configurations.
2. Generate a replacement key pair with `seal keygen`.
3. Re-sign all active release artifacts with the new key.
4. Distribute the new public key to all verifiers through authenticated channels.

## Key rotation strategy

A staged rotation procedure minimizes disruption.

### Phase A: introduce new key

- Generate `K2` while `K1` remains active.
- Distribute the `K2` public key to all verifiers.

### Phase B: dual acceptance window

- Update verifier policy to accept signatures from both `K1` and `K2`.
- Sign all new artifacts with `K2` only.

### Phase C: retire old key

- Remove `K1` from all trusted verifier configurations.
- Archive `K1` records for audit traceability.

## Security considerations

- Signing should be performed in controlled CI runners with restricted outbound access and no persistent shell sessions.
- Signature verification with `--pubkey` must be mandatory in pre-deploy and pre-launch checks for production pipelines.
- Build provenance logs should include the `builder id` (public key prefix) and the artifact SHA-256 digest alongside the signature.

## Limitations

- The CLI appends one signature block per invocation. Running `seal sign` on an already-signed artifact will append a second block, which the verifier will not recognize correctly. Re-signing an artifact requires stripping the existing signature block first.
- Verifier output is human-readable text. CI pipelines should parse the `VALID` / `INVALID` / `WARNING: unsigned` strings or use a non-zero exit on `INVALID` to enforce policy.
- There is no multi-signer or signature chain mechanism.

## References

- **Ed25519**: Bernstein, D. et al. (2012). "High-speed high-security signatures". Journal of Cryptographic Engineering 4(2). [doi:10.1007/s13389-012-0007-1](https://doi.org/10.1007/s13389-012-0007-1)
- **Key Management**: Barker, E. et al. (2020). NIST SP 800-57 Part 1 Rev. 5. Recommendation for Key Management.
