# CLI Reference

The `seal` binary provides six subcommands:

| Command | Description |
|---------|-------------|
| [`seal compile`](./cli/compile.md) | Compile and seal an agent payload |
| [`seal launch`](./cli/launch.md) | Launch a sealed agent payload |
| [`seal keygen`](./cli/keygen.md) | Generate Ed25519 signing keys |
| [`seal sign`](./cli/sign.md) | Sign a sealed binary |
| [`seal verify`](./cli/verify.md) | Verify a sealed binary signature |
| [`seal server`](./cli/server.md) | Start the orchestration API server |

## Common Options

These options apply to most commands:

| Option | Description |
|--------|-------------|
| `--verbose` | Enable debug-level logging |
| `--help` | Show command help |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 101 | Fingerprint mismatch (decryption failed) |