# Signing Workflow

## Key Generation

```bash
seal keygen
```

Creates:
- `~/.snapfzz-seal/keys/key` — Secret key (keep secret!)
- `~/.snapfzz-seal/keys/key.pub` — Public key (distribute)

## Signing

```bash
seal sign --key ~/.snapfzz-seal/keys/key --binary ./agent.sealed
```

## Verification

**TOFU (Trust-on-First-Use):**
```bash
seal verify --binary ./agent.sealed
```

**Pinned Key (recommended for production):**
```bash
seal verify --binary ./agent.sealed --pubkey ./builder-key.pub
```

Signing is **mandatory** — unsigned payloads are rejected at launch.