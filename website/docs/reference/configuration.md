# Configuration

This section documents runtime and build-time configuration controls for Snapfzz Seal.

## Configuration model

Configuration is currently resolved from command arguments and environment variables. A dedicated declarative config file parser is not defined in the current CLI implementation.

## Environment variables

| Variable | Type | Default | Purpose |
|---|---|---|---|
| `SNAPFZZ_SEAL_MASTER_SECRET_HEX` | 64-hex string | none | master secret for launch key derivation fallback |
| `SNAPFZZ_SEAL_LAUNCHER_PATH` | path | none | launcher path for compile when `--launcher` omitted |
| `SNAPFZZ_SEAL_LAUNCHER_SIZE` | integer | none | launcher size hint used during embedded payload extraction |
| `RUST_LOG` | string | implementation default | tracing verbosity filter |
| `DOCKER_BIN` | path | auto-discovery | explicit docker binary for server sandbox backend |

## Command defaults

### `seal keygen`

- `--keys-dir`: `~/.snapfzz-seal/keys`

### `seal compile`

- `--sandbox-fingerprint`: `auto`
- `--backend`: `nuitka`
- `--mode`: `batch`

### `seal launch`

- `--fingerprint-mode`: `stable`
- `--grace-period`: `30`

### `seal server`

- `--bind`: `0.0.0.0:9090` in CLI wrapper context
- `--compile-dir`: `./.snapfzz-seal/compile`
- `--output-dir`: `./.snapfzz-seal/output`

## Configuration file format

No first-class configuration file format is currently enforced by the `seal` CLI. Teams that require declarative deployment control generally maintain external wrappers, for example in YAML or TOML, that materialize into CLI flags and environment variables.

Example wrapper file pattern (user-managed):

```yaml
seal:
  launcher_path: ./target/release/snapfzz-seal-launcher
  log_level: info
  keys_dir: ~/.snapfzz-seal/keys
```

The above is an operational convention, not a native CLI contract.

## Practical invocation examples

```bash
# compile with launcher path from env
export SNAPFZZ_SEAL_LAUNCHER_PATH=./target/release/snapfzz-seal-launcher
seal compile --project ./agent --user-fingerprint "$USER_FP" --output ./agent.sealed

# launch with master secret from env
export SNAPFZZ_SEAL_MASTER_SECRET_HEX=$(openssl rand -hex 32)
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"

# server with explicit docker binary
export DOCKER_BIN=/usr/bin/docker
seal server --bind 127.0.0.1:9090
```

## Security considerations

- Environment variables carrying secret material should be protected from shell history leakage.
- Secret values should not be emitted in logs.
- Wrapper scripts should apply strict permission and audit policies.

## Limitations

- Native hierarchical config file support is not currently implemented.
- No built-in validation schema is provided beyond CLI argument parsing and runtime checks.
