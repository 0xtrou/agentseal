# seal keygen

Generate Ed25519 signing keys.

## Usage

```text
seal keygen [OPTIONS]
```

## Options

| Option | Description |
|--------|-------------|
| `--keys-dir <PATH>` | Output directory [default: ~/.agent-seal/keys] |

## Output

Creates two files:
- `key` — 64-hex secret key (**keep secret**)
- `key.pub` — 64-hex public key (safe to distribute)

## Examples

```bash
# Generate keys in default location
seal keygen

# Generate in custom directory
seal keygen --keys-dir ./my-keys
```

## Security

- Secret key should never be shared or committed to version control
- Generate separate keys per builder/CI pipeline
- Rotate keys periodically