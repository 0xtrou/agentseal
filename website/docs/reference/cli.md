# CLI Commands

This reference describes the `seal` command-line interface.

## Global behavior

- Binary name: `seal`
- Configuration root in examples: `~/.snapfzz-seal/`
- On command failure, process exits with non-zero status.

## Command summary

| Command | Purpose |
|---|---|
| `seal compile` | Compile project, derive keys, assemble sealed artifact |
| `seal keygen` | Generate builder signing key pair |
| `seal launch` | Verify and launch sealed artifact |
| `seal server` | Start orchestration API service |
| `seal sign` | Append signature block to binary |
| `seal verify` | Verify signature with embedded or pinned key |

## `seal compile`

```bash
seal compile \
  --project <path> \
  --user-fingerprint <64-hex> \
  --sandbox-fingerprint <auto|64-hex> \
  --output <path> \
  [--launcher <path>] \
  [--backend <nuitka|pyinstaller>] \
  [--mode <batch|interactive>]
```

Flags:

- `--project`: source project directory
- `--user-fingerprint`: 32-byte fingerprint in hex
- `--sandbox-fingerprint`: `auto` or 32-byte hex value
- `--output`: destination file path
- `--launcher`: explicit launcher path override
- `--backend`: compile backend selection
- `--mode`: payload mode byte selection

## `seal keygen`

```bash
seal keygen [--keys-dir <path>]
```

Flags:

- `--keys-dir`: destination directory for `builder_secret.key` and `builder_public.key`

Default:

- `~/.snapfzz-seal/keys`

## `seal sign`

```bash
seal sign --key <path> --binary <path>
```

Flags:

- `--key`: builder secret key path (hex-encoded 32-byte key)
- `--binary`: target artifact to sign in place

## `seal verify`

```bash
seal verify --binary <path> [--pubkey <path>]
```

Flags:

- `--binary`: artifact path
- `--pubkey`: optional pinned public key path

Output modes:

- `VALID (pinned to explicit public key)`
- `VALID (TOFU: using embedded key ...)`
- `INVALID`
- `WARNING: unsigned`

## `seal launch`

```bash
seal launch \
  [--payload <path>] \
  [--fingerprint-mode <stable|session>] \
  [--user-fingerprint <64-hex>] \
  [--mode <batch|interactive>] \
  [--verbose] \
  [--max-lifetime <seconds>] \
  [--grace-period <seconds>]
```

Flags:

- `--payload`: explicit payload path, optional when self-contained execution is used
- `--fingerprint-mode`: stable or session
- `--user-fingerprint`: required for key derivation
- `--mode`: CLI-level launch mode field
- `--verbose`: enables detailed logging
- `--max-lifetime`: runtime ceiling
- `--grace-period`: post-signal grace interval

## `seal server`

```bash
seal server \
  [--bind <host:port>] \
  [--compile-dir <path>] \
  [--output-dir <path>]
```

Flags:

- `--bind`: listening socket
- `--compile-dir`: working directory for compile jobs
- `--output-dir`: artifact output directory

## Exit codes

Current CLI behavior:

- `0`: command completed without error
- `1`: command returned an error path in CLI dispatcher

Subprocess exit semantics from launched payloads are returned in JSON execution output fields and are distinct from CLI command exit handling.

## Environment variables

| Variable | Purpose |
|---|---|
| `SNAPFZZ_SEAL_MASTER_SECRET_HEX` | 32-byte secret in hex for launch key derivation fallback |
| `SNAPFZZ_SEAL_LAUNCHER_PATH` | launcher path used by compile when `--launcher` is omitted |
| `SNAPFZZ_SEAL_LAUNCHER_SIZE` | optional launcher-size hint for embedded payload extraction |
| `RUST_LOG` | tracing verbosity (`error`, `warn`, `info`, `debug`, `trace`) |
| `DOCKER_BIN` | explicit Docker binary for server sandbox backend |

## Practical examples

```bash
seal compile --project ./agent --user-fingerprint "$USER_FP" --sandbox-fingerprint auto --output ./agent.sealed
seal sign --key ~/.snapfzz-seal/keys/builder_secret.key --binary ./agent.sealed
seal verify --binary ./agent.sealed --pubkey ~/.snapfzz-seal/keys/builder_public.key
SNAPFZZ_SEAL_MASTER_SECRET_HEX=<secret> seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

## Security considerations

- Prefer pinned key verification over TOFU in production automation.
- Avoid passing secrets via shell history in shared terminals.
- Restrict server command network exposure to authenticated local interfaces or protected tunnels.

## Limitations

- Exit code taxonomy is currently binary for CLI command success or failure.
- Structured machine-readable command output is limited to selected commands.
