# Configuration

## Environment Variables

| Variable | Component | Description |
|----------|-----------|-------------|
| `AGENT_SEAL_MASTER_SECRET_HEX` | launch | 64-hex master secret for HKDF |
| `AGENT_SEAL_LAUNCHER_PATH` | compile | Path to launcher binary |
| `AGENT_SEAL_LAUNCHER_SIZE` | launch | Launcher size for self-extraction |
| `RUST_LOG` | all | Tracing level (`debug`, `info`, `trace`) |

## Examples

### Set Master Secret

```bash
export AGENT_SEAL_MASTER_SECRET_HEX=$(openssl rand -hex 32)
```

### Enable Debug Logging

```bash
export RUST_LOG=agent_seal=debug,info
```

### Override Launcher Path

```bash
seal compile \
  --project ./agent \
  --user-fingerprint $FP \
  --output ./out \
  --launcher ./custom/launcher
```

Or via environment:

```bash
export AGENT_SEAL_LAUNCHER_PATH=./custom/launcher
seal compile --project ./agent --user-fingerprint $FP --output ./out
```

## File Locations

| Path | Description |
|------|-------------|
| `~/.agent-seal/keys/` | Signing keys (keygen output) |
| `./.agent-seal/compile/` | Server compile artifacts |
| `./.agent-seal/output/` | Server output binaries |