---
sidebar_position: 3
---

# Configuration

This document describes all runtime and build-time configuration controls for Snapfzz Seal. Configuration is resolved from CLI flags and environment variables; there is no native configuration file parser.

---

## Runtime environment variables

These variables are read at process startup by the launcher or the `seal` CLI.

| Variable | Format | Default | Read by | Description |
|----------|--------|---------|---------|-------------|
| `SNAPFZZ_SEAL_MASTER_SECRET_HEX` | 64 hex characters (32 bytes) | — | Launcher | Fallback master secret used when the launcher cannot reconstruct the secret from embedded Shamir shares. Required when the embedded secret is unavailable. |
| `SNAPFZZ_SEAL_LAUNCHER_PATH` | file path | — | `seal compile` | Path to the launcher binary. Used when `--launcher` is not supplied. |
| `SNAPFZZ_SEAL_LAUNCHER_SIZE` | positive integer | — | Launcher | Explicit byte-offset hint marking the boundary between the launcher binary and the appended payload. Used when the launcher cannot auto-detect the payload offset. |
| `RUST_LOG` | filter string | implementation default | All binaries | Tracing verbosity filter. Accepts level names such as `error`, `warn`, `info`, `debug`, `trace` and module-scoped filters. |
| `DOCKER_BIN` | file path | auto-discovery | Server | Explicit path to the Docker binary used by the sandbox backend. |

---

## Build-time environment variable

### BUILD_ID

`BUILD_ID` is consumed by the Cargo build scripts of `snapfzz-seal-core` and `snapfzz-seal-launcher`. It determines the deterministic binary markers (Shamir share slots, decoy slots, tamper marker, payload sentinel) that are embedded in both crates at compile time.

**Critical constraint:** Both `snapfzz-seal-core` (used by the `seal` CLI) and `snapfzz-seal-launcher` must be compiled with the **same `BUILD_ID`** value. If they differ, the launcher will fail to locate the secret shares the compiler embedded at seal time.

| Value | Effect |
|-------|--------|
| Any non-empty string | Markers derived from that string |
| Not set | Falls back to the literal string `"dev"` |

Always build both crates in a single invocation:

```bash
export BUILD_ID="$(openssl rand -hex 16)"
BUILD_ID="$BUILD_ID" cargo build --release
```

For local development, omitting `BUILD_ID` is safe as long as both crates are built together in the same `cargo build` run (they both default to `"dev"`).

---

## CLI flag defaults

### `seal keygen`

| Flag | Default |
|------|---------|
| `--keys-dir` | `~/.snapfzz-seal/keys` |

### `seal compile`

| Flag | Default |
|------|---------|
| `--sandbox-fingerprint` | `auto` |
| `--backend` | `nuitka` |
| `--mode` | `batch` |

### `seal launch`

| Flag | Default |
|------|---------|
| `--fingerprint-mode` | `stable` |
| `--grace-period` | `30` |

Note: `--grace-period` (and `--mode`, `--max-lifetime`) are accepted by the CLI but are not forwarded to the launcher. They have no effect at runtime.

### `seal server`

| Flag | Default (CLI wrapper `seal server`) | Default (standalone `snapfzz-seal-server`) |
|------|-------------------------------------|--------------------------------------------|
| `--bind` | `0.0.0.0:9090` | `127.0.0.1:9090` |
| `--compile-dir` | `./.snapfzz-seal/compile` | `./.snapfzz-seal/compile` |
| `--output-dir` | `./.snapfzz-seal/output` | `./.snapfzz-seal/output` |

---

## Configuration file

No first-class configuration file format is implemented. Declarative deployment configurations are typically expressed as wrapper scripts or CI environment variable blocks that materialize into CLI flags and environment variables.

Example shell wrapper (user-managed, not a native CLI feature):

```bash
#!/usr/bin/env bash
export SNAPFZZ_SEAL_LAUNCHER_PATH=./target/release/snapfzz-seal-launcher
export RUST_LOG=info

seal compile \
  --project ./agent \
  --user-fingerprint "$USER_FP" \
  --output ./agent.sealed
```

---

## Practical examples

```bash
# Compile with launcher path from environment
export SNAPFZZ_SEAL_LAUNCHER_PATH=./target/release/snapfzz-seal-launcher
seal compile \
  --project ./agent \
  --user-fingerprint "$USER_FP" \
  --output ./agent.sealed

# Launch with master secret fallback from environment
export SNAPFZZ_SEAL_MASTER_SECRET_HEX=$(openssl rand -hex 32)
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"

# Start the server with an explicit Docker binary
export DOCKER_BIN=/usr/bin/docker
seal server --bind 127.0.0.1:9090

# Enable debug logging
export RUST_LOG=debug
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

---

## Security considerations

- `SNAPFZZ_SEAL_MASTER_SECRET_HEX` contains cryptographic key material. Do not pass it as an inline shell argument or expose it in shared terminal sessions.
- Secret values must not appear in application logs. The launcher emits an error referencing the variable name on failure but does not log the value.
- Wrapper scripts that set secret environment variables should apply strict file permission and audit policies.
- `BUILD_ID` is deterministic input to marker derivation. Treat it as a sensitive build artifact in production environments.

---

## Limitations

- No hierarchical or file-based configuration parser is implemented.
- No built-in validation schema beyond CLI argument parsing and runtime checks.
- `--grace-period`, `--mode`, and `--max-lifetime` on `seal launch` are reserved for a future implementation and currently have no effect.
