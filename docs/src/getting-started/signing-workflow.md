# Signing Workflow

Agent Seal uses Ed25519 signatures to verify builder identity and payload integrity.

## Key Generation

```bash
seal keygen
```

Creates:
- `~/.agent-seal/keys/key` — 64-hex secret key (**keep secret**)
- `~/.agent-seal/keys/key.pub` — 64-hex public key (safe to distribute)

## Signing Process

```bash
seal sign --key ~/.agent-seal/keys/key --binary ./agent.sealed
```

The signature:
1. Covers all bytes before the signature block (header + payload + footer)
2. Appends to the binary: 4-byte magic + 64-byte signature + 32-byte pubkey

## Verification

### Option 1: TOFU (Trust-on-First-Use)

```bash
seal verify --binary ./agent.sealed
```

Uses the embedded public key. Trusts the first key seen for each binary.

### Option 2: Pinned Public Key

```bash
seal verify --binary ./agent.sealed --pubkey ./builder-key.pub
```

Verifies against an explicit public key file. **Recommended for production.**

## Workflow Diagram

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ seal keygen │ ──▶ │  seal sign  │ ──▶ │ seal verify │
│ generate    │     │ append sig  │     │ check sig   │
│ Ed25519     │     │ + pubkey    │     │ + pubkey    │
└─────────────┘     └─────────────┘     └─────────────┘
```

## Security Model

| Mode | Trust Anchor | Use Case |
|------|--------------|----------|
| TOFU | First-seen key | Development, trusted networks |
| Pinned | Explicit pubkey file | Production, supply chain security |

### Mandatory Enforcement

As of commit `977a6dc`, **signing is mandatory**:
- Unsigned payloads assembled before this change fail with `MissingSignature`
- `seal sign` must run before `seal launch`
- No silent bypass — verification failure blocks execution

## Best Practices

1. **Generate keys per builder** — Each builder/CI pipeline has its own keypair
2. **Distribute pubkeys out-of-band** — Don't include pubkey in the same channel as the binary
3. **Rotate keys periodically** — Generate new keypairs and re-sign binaries
4. **Pin pubkeys in production** — Use `--pubkey` for explicit verification