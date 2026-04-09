# seal launch

Execute a sealed agent payload.

## Usage

```text
seal launch [OPTIONS]
```

## Options

| Option | Description |
|--------|-------------|
| `--payload <PATH>` | Path to sealed binary or encrypted payload |
| `--fingerprint-mode <MODE>` | Collection mode: `stable`, `session` [default: stable] |
| `--user-fingerprint <HEX>` | 64-hex user identity (32 bytes) [required] |
| `--mode <MODE>` | Execution mode: `batch`, `interactive` [default: batch] |
| `--max-lifetime <SECS>` | Maximum process lifetime (interactive mode) |
| `--grace-period <SECS>` | Grace period before SIGKILL [default: 30] |
| `--verbose` | Enable debug-level logging |

## Fingerprint Modes

| Mode | Signals | Use Case |
|------|---------|----------|
| `stable` | machine-id, hostname, kernel, cgroup | Persistent environments |
| `session` | + namespace inodes, UIDs | Short-lived containers, stricter binding |

## Execution Modes

### Batch (default)

- Runs agent once
- Captures stdout/stderr/exit code
- Returns `ExecutionResult`

### Interactive

- Forks agent with stdin/stdout/stderr pipes
- Launcher becomes process supervisor
- Supports `--max-lifetime` for timeout enforcement

## Payload Types

`--payload` accepts:
- **Assembled binary** (launcher + payload) — self-extracting
- **Standalone payload** — encrypted payload only

If `--payload` is omitted or `self`, extracts from own executable.

## Examples

```bash
# Run assembled binary (self-extracting)
AGENT_SEAL_MASTER_SECRET_HEX=... ./agent.sealed --user-fingerprint $FP

# Run with explicit payload
AGENT_SEAL_MASTER_SECRET_HEX=... \
  seal launch \
  --payload ./payload.asl \
  --user-fingerprint $FP \
  --fingerprint-mode stable

# Session mode for containers
AGENT_SEAL_MASTER_SECRET_HEX=... \
  seal launch \
  --payload ./payload.asl \
  --user-fingerprint $FP \
  --fingerprint-mode session

# Interactive with lifetime limit
AGENT_SEAL_MASTER_SECRET_HEX=... \
  seal launch \
  --payload ./payload.asl \
  --user-fingerprint $FP \
  --mode interactive \
  --max-lifetime 300
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 101 | Fingerprint mismatch (decryption failed) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENT_SEAL_MASTER_SECRET_HEX` | 64-hex master secret for HKDF |
| `AGENT_SEAL_LAUNCHER_SIZE` | Launcher size for self-extraction |