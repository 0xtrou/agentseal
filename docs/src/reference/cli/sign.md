# seal sign

Sign a sealed binary with Ed25519.

## Usage

```text
seal sign --key <KEY> --binary <BINARY>
```

## Options

| Option | Description |
|--------|-------------|
| `--key <PATH>` | Path to 64-hex secret key file |
| `--binary <PATH>` | Path to sealed binary to sign |

## What It Does

1. Reads the binary
2. Computes Ed25519 signature over all bytes (header + payload + footer)
3. Appends: 4-byte magic + 64-byte signature + 32-byte pubkey

## Examples

```bash
seal sign --key ~/.agent-seal/keys/key --binary ./agent.sealed
```

## See Also

- [seal verify](./verify.md) — Verify the signature
- [Signing Workflow](../../getting-started/signing-workflow.md) — Full workflow