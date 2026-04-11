---
sidebar_position: 1
---

# CLI Reference

This reference documents every subcommand of the `seal` command-line interface. Flag names, types, and defaults are derived directly from the clap struct definitions in `crates/snapfzz-seal/src/`.

## Global behavior

- Binary name: `seal`
- On command failure the process prints the error to stderr and exits with code `1`.
- Log verbosity is controlled by `RUST_LOG` (see [Environment variables](#environment-variables)).

## Command summary

| Command | Purpose |
|---------|---------|
| `seal compile` | Compile a project, derive keys, assemble a sealed artifact |
| `seal keygen` | Generate a builder Ed25519 signing key pair |
| `seal launch` | Verify and launch a sealed artifact |
| `seal server` | Start the orchestration API service |
| `seal sign` | Append a signature block to a sealed binary |
| `seal verify` | Verify the signature embedded in a sealed binary |

---

## `seal keygen`

Generate an Ed25519 signing key pair for the builder identity.

```bash
seal keygen [--keys-dir <path>]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--keys-dir` | path | `~/.snapfzz-seal/keys` | Destination directory for key files |

### Output files

- `<keys-dir>/builder_secret.key` — hex-encoded 32-byte Ed25519 signing key
- `<keys-dir>/builder_public.key` — hex-encoded 32-byte Ed25519 verifying key

### Stdout

```text
secret: /home/<user>/.snapfzz-seal/keys/builder_secret.key
public: /home/<user>/.snapfzz-seal/keys/builder_public.key
builder id: <first 16 hex chars of public key>
```

---

## `seal compile`

Compile a project, derive binding keys, and assemble a sealed artifact.

```bash
seal compile \
  --project <path> \
  --user-fingerprint <64-hex> \
  --output <path> \
  [--sandbox-fingerprint <auto|64-hex>] \
  [--launcher <path>] \
  [--backend <nuitka|pyinstaller|go>] \
  [--mode <batch|interactive>]
```

### Flags

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--project` | path | — | Yes | Source project directory |
| `--user-fingerprint` | string | — | Yes | 64 hex characters (32-byte user binding value) |
| `--output` | path | — | Yes | Destination path for the assembled sealed binary |
| `--sandbox-fingerprint` | string | `auto` | No | `auto` collects the current environment's stable fingerprint; alternatively supply 64 hex characters to bind to a specific sandbox |
| `--launcher` | path | — | No | Explicit path to the launcher binary; falls back to `SNAPFZZ_SEAL_LAUNCHER_PATH` if omitted |
| `--backend` | enum | `nuitka` | No | Compile backend: `nuitka`, `pyinstaller`, or `go` |
| `--mode` | enum | `batch` | No | Agent mode byte written into the payload header: `batch` or `interactive` |

### Backend requirements

| Backend | Requirements |
|---------|-------------|
| `nuitka` | `pip install nuitka`, C compiler (gcc or clang) |
| `pyinstaller` | `pip install pyinstaller` |
| `go` | Go toolchain 1.21+, `go.mod` present in project root |

The launcher binary must exist before running compile. Build it with `cargo build --release` using the same `BUILD_ID` used to build `snapfzz-seal`. See [BUILD_ID](#build_id) for details.

### Stdout on success

```text
compiled and assembled binary: <output-path> (<N> bytes)
```

---

## `seal sign`

Append an Ed25519 signature block to a sealed binary.

```bash
seal sign --key <path> --binary <path>
```

### Flags

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--key` | path | Yes | Path to `builder_secret.key` (hex-encoded 32-byte signing key) |
| `--binary` | path | Yes | Sealed artifact to sign in place |

The public key is read automatically from `builder_public.key` in the same directory as `--key`. Both files must exist.

The signature block appended to the binary has the format:

```
<original binary bytes> || "ASL\x02" || <64-byte Ed25519 signature> || <32-byte public key>
```

No output is produced on success.

---

## `seal verify`

Verify the Ed25519 signature embedded in a sealed binary.

```bash
seal verify --binary <path> [--pubkey <path>]
```

### Flags

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--binary` | path | Yes | Sealed artifact to verify |
| `--pubkey` | path | No | Pinned builder public key file (hex-encoded 32 bytes); if omitted the embedded key is used (TOFU mode) |

### Output

| Message | Meaning |
|---------|---------|
| `VALID (pinned to explicit public key)` | Signature verified against the supplied `--pubkey` |
| `VALID (TOFU: using embedded key — use --pubkey for pinned builder identity)` | Signature valid but no `--pubkey` was supplied |
| `INVALID` | Signature verification failed |
| `WARNING: unsigned` | No `ASL\x02` signature block found |

:::note

`seal verify` exits with code `0` in all cases, including `INVALID` and `WARNING: unsigned`. Parse the printed message to determine the actual result.

:::

---

## `seal launch`

Verify fingerprint binding and launch a sealed artifact.

```bash
seal launch \
  [--payload <path>] \
  [--fingerprint-mode <stable|session>] \
  [--user-fingerprint <64-hex>] \
  [--verbose] \
  [--mode <batch|interactive>] \
  [--max-lifetime <seconds>] \
  [--grace-period <seconds>]
```

### Flags

| Flag | Type | Default | Forwarded to launcher | Description |
|------|------|---------|----------------------|-------------|
| `--payload` | string | — | Yes | Explicit path to the sealed artifact; if omitted the launcher searches for an embedded payload |
| `--fingerprint-mode` | enum | `stable` | Yes | `stable` uses only stable host signals; `session` adds ephemeral namespace signals for session-scoped binding |
| `--user-fingerprint` | string | — | Yes | 64 hex characters required for key derivation |
| `--verbose` | bool | `false` | Yes | Enable detailed launcher logging |
| `--mode` | enum | `batch` | No — parsed, not forwarded | Accepted but not passed to the launcher |
| `--max-lifetime` | integer | — | No — parsed, not forwarded | Accepted but not passed to the launcher |
| `--grace-period` | integer | `30` | No — parsed, not forwarded | Accepted but not passed to the launcher |

:::warning[Flags with no current effect]

`--mode`, `--max-lifetime`, and `--grace-period` are accepted by the CLI but are not forwarded to the launcher and have no effect at runtime. They are reserved for a future implementation.

:::

### Output on success

The launcher prints an `ExecutionResult` JSON object to stdout:

```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": ""
}
```

Subprocess exit codes are embedded in `exit_code`, not reflected in the `seal launch` process exit code.

### Environment variables for launch

| Variable | Description |
|----------|-------------|
| `SNAPFZZ_SEAL_MASTER_SECRET_HEX` | 64 hex characters (32 bytes). Used as fallback master secret when the embedded Shamir shares cannot be reconstructed. |
| `SNAPFZZ_SEAL_LAUNCHER_SIZE` | Integer. Explicit byte offset hint marking the boundary between the launcher binary and the appended payload. |

---

## `seal server`

Start the Snapfzz Seal orchestration API server.

```bash
seal server \
  [--bind <host:port>] \
  [--compile-dir <path>] \
  [--output-dir <path>]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--bind` | string | `0.0.0.0:9090` | TCP address to listen on |
| `--compile-dir` | path | `./.snapfzz-seal/compile` | Working directory for compile jobs |
| `--output-dir` | path | `./.snapfzz-seal/output` | Directory for compiled sealed artifacts |

The default bind address when running `seal server` (the `seal` wrapper) is `0.0.0.0:9090`. The standalone `snapfzz-seal-server` binary uses `127.0.0.1:9090` as its default.

The server shuts down gracefully on `SIGINT` (Ctrl-C) or `SIGTERM`.

:::warning[No authentication]

The server has no built-in authentication or authorization. Deploy it behind an authenticated reverse proxy or API gateway. Do not expose it to untrusted networks.

:::

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Command completed without error |
| `1` | Runtime error (printed to stderr) |
| `2` | CLI argument parse error (clap default) |

`seal verify` always exits with `0`. Inspect the printed message to determine verification status.

---

## Environment variables

| Variable | Purpose |
|----------|---------|
| `SNAPFZZ_SEAL_MASTER_SECRET_HEX` | 64 hex characters (32-byte master secret) used as fallback when the launcher cannot reconstruct the secret from embedded Shamir shares |
| `SNAPFZZ_SEAL_LAUNCHER_PATH` | Launcher binary path; used by `seal compile` when `--launcher` is omitted |
| `SNAPFZZ_SEAL_LAUNCHER_SIZE` | Integer byte-offset hint for embedded payload extraction |
| `RUST_LOG` | Tracing verbosity filter (`error`, `warn`, `info`, `debug`, `trace`) |
| `DOCKER_BIN` | Explicit Docker binary path for the server sandbox backend |
| `BUILD_ID` | Build-time variable (not a runtime env var) — see below |

### BUILD_ID

`BUILD_ID` is a **build-time** environment variable read by the `snapfzz-seal-core` and `snapfzz-seal-launcher` build scripts. It determines the deterministic binary markers embedded in both crates. Both crates **must** be compiled with the same `BUILD_ID` or the launcher will fail to locate its embedded secret shares at runtime.

```bash
export BUILD_ID="$(openssl rand -hex 16)"
BUILD_ID="$BUILD_ID" cargo build --release
```

If `BUILD_ID` is not set it defaults to `"dev"`, which is safe for local development as long as both crates are built together.

---

## Practical examples

### Complete workflow

```bash
# 1. Build launcher and seal CLI with a consistent BUILD_ID
export BUILD_ID="$(openssl rand -hex 16)"
BUILD_ID="$BUILD_ID" cargo build --release

# 2. Generate builder keys
seal keygen

# 3. Generate a user fingerprint
USER_FP=$(openssl rand -hex 32)

# 4. Compile and seal
seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/release/snapfzz-seal-launcher

# 5. Sign
seal sign \
  --key ~/.snapfzz-seal/keys/builder_secret.key \
  --binary ./agent.sealed

# 6. Verify
seal verify \
  --binary ./agent.sealed \
  --pubkey ~/.snapfzz-seal/keys/builder_public.key

# 7. Launch
seal launch \
  --payload ./agent.sealed \
  --user-fingerprint "$USER_FP"
```

### Using environment variables for compile

```bash
export SNAPFZZ_SEAL_LAUNCHER_PATH=./target/release/snapfzz-seal-launcher

seal compile \
  --project ./agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed
```

### Session-mode launch

```bash
seal launch \
  --payload ./agent.sealed \
  --fingerprint-mode session \
  --user-fingerprint "$USER_FP"
```

---

## Security considerations

- **Use pinned key verification in production.** Automation must pass `--pubkey` to `seal verify`. TOFU mode (no `--pubkey`) trusts the key embedded in the artifact.
- **Protect secret material from shell history.** Do not pass hex secrets as inline shell arguments in shared environments.
- **Restrict server network exposure.** Run the server on loopback or behind an authenticated gateway; it has no built-in access control.
- **Treat compile logs as potentially sensitive.** Logs may contain operational details about project structure and artifact paths.

---

## Limitations

- Exit codes are binary for CLI command success or failure. Structured per-command exit codes are not implemented.
- `--mode`, `--max-lifetime`, and `--grace-period` on `seal launch` are accepted but have no effect.
- `--backend-opts` for passing flags through to backend tools is not implemented.
- Backend tools (Nuitka, PyInstaller, Go) must be pre-installed; automatic installation is not implemented.

---

## References

- **Ed25519**: Bernstein, D. et al. (2012). "High-speed high-security signatures". Journal of Cryptographic Engineering 4(2).
- **HKDF**: Krawczyk, H. (2010). RFC 5869.
