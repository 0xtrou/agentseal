# seal compile

Compile and seal an agent payload.

## Usage

```text
seal compile [OPTIONS] --project <PROJECT> --user-fingerprint <USER_FINGERPRINT> --output <OUTPUT>
```

## Options

| Option | Description |
|--------|-------------|
| `--project <PATH>` | Path to the agent source directory |
| `--user-fingerprint <HEX>` | 64-hex user identity (32 bytes) |
| `--sandbox-fingerprint <HEX>` | 64-hex sandbox identity [default: auto] |
| `--output <PATH>` | Output path for the sealed binary |
| `--launcher <PATH>` | Path to launcher binary (for assembly) |
| `--backend <BACKEND>` | Compile backend: `nuitka`, `pyinstaller`, `go` [default: nuitka] |
| `--mode <MODE>` | Execution mode: `batch`, `interactive` [default: batch] |

## Backends

| Backend | Detects | Produces |
|---------|---------|----------|
| Nuitka | `main.py` or `setup.py` | Static Linux ELF (Python → C → native) |
| PyInstaller | `main.py` | Linux ELF (Python import freeze) |
| Go | `go.mod` | Static Linux ELF (`CGO_ENABLED=0`) |

Auto-detection tries backends in order: Nuitka → PyInstaller → Go.

## Modes

- **batch** (default): One-shot execution, captures output
- **interactive**: Multi-turn with stdin/stdout pipes, supports lifetime limits

## Examples

```bash
# Compile a Python agent with Nuitka
seal compile \
  --project ./my-agent \
  --user-fingerprint $USER_FP \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/release/agent-seal-launcher

# Use PyInstaller backend
seal compile \
  --project ./my-agent \
  --user-fingerprint $USER_FP \
  --output ./out.sealed \
  --backend pyinstaller

# Produce only encrypted payload (no launcher)
seal compile \
  --project ./my-agent \
  --user-fingerprint $USER_FP \
  --output ./payload.asl
```

## See Also

- [seal launch](./launch.md) — Execute a sealed payload
- [Signing Workflow](../../getting-started/signing-workflow.md) — Signing after compile