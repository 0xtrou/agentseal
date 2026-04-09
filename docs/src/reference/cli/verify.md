# seal verify

Verify a sealed binary's Ed25519 signature.

## Usage

```text
seal verify --binary <BINARY> [--pubkey <PUBKEY>]
```

## Options

| Option | Description |
|--------|-------------|
| `--binary <PATH>` | Path to sealed binary to verify |
| `--pubkey <PATH>` | Path to 64-hex public key (optional) |

## Verification Modes

### TOFU (Trust-on-First-Use)

```bash
seal verify --binary ./agent.sealed
```

Uses the embedded public key. Trusts the first key seen for each binary.

### Pinned Public Key

```bash
seal verify --binary ./agent.sealed --pubkey ./builder-key.pub
```

Verifies against an explicit public key file. **Recommended for production.**

## Exit Codes

| Code | Meaning |
|--------|---------|
| 0 | Signature valid |
| 1 | Signature invalid or missing |

## See Also

- [seal sign](./sign.md) — Sign a binary
- [Signing Workflow](../../getting-started/signing-workflow.md) — Full workflow