# Quick Start

Seal your first agent in 5 minutes.

## 1. Generate Signing Keys

```bash
seal keygen
```

Creates `~/.agent-seal/keys/key` (secret) and `~/.agent-seal/keys/key.pub` (public).

## 2. Compile an Agent

```bash
# Generate user fingerprint (any 64-hex string)
export USER_FP=$(openssl rand -hex 32)

# Compile and seal
seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint $USER_FP \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/release/agent-seal-launcher
```

> **Note:** `--sandbox-fingerprint auto` generates a random binding nonce. For real environment binding, collect a fingerprint from your target sandbox.

## 3. Sign the Binary

```bash
seal sign --key ~/.agent-seal/keys/key --binary ./agent.sealed
```

Signing is **mandatory** — unsigned payloads are rejected at launch.

## 4. Launch the Agent

```bash
AGENT_SEAL_MASTER_SECRET_HEX=... \
  seal launch \
  --payload ./agent.sealed \
  --user-fingerprint $USER_FP \
  --verbose
```

## What Happens

1. **Signature verification** — Ed25519 signature checked against embedded pubkey
2. **Fingerprint collection** — Runtime environment signals collected
3. **Key derivation** — HKDF derives decryption key from master secret + fingerprints
4. **Decryption** — AES-256-GCM decrypts payload chunks
5. **Tamper check** — Launcher hash verified against footer
6. **Execution** — Agent runs from memory (memfd + fexecve)

## Next Steps

- [Signing Workflow](./signing-workflow.md) — Understand the signing model
- [Fingerprinting](../reference/fingerprinting.md) — How environment binding works
- [CLI Reference](../reference/cli.md) — All commands and options