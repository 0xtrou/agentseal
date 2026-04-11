---
sidebar_position: 2
---

# Quick Start

This section provides a complete end-to-end example with expected output and operational checks.

:::warning[Platform Requirement]

Sealed agents can **only be executed on Linux x86_64**. macOS and Windows are supported for building and signing only, not for execution.

:::

## Prerequisites

Before starting, ensure you have:

1. **Rust 1.85 or later** — For building the `seal` CLI and `seal-launcher`.
2. **Python 3.7+ and Nuitka or PyInstaller** — For the default Python agent backend. Install with `pip install nuitka` or `pip install pyinstaller`.
3. **Linux x86_64** — For execution. macOS and Windows can build and sign but cannot launch.

## Step 0: Build the release binaries

Both the `seal` CLI and the `seal-launcher` binary must be built together with the same `BUILD_ID`. This is critical — the `BUILD_ID` determines the cryptographic markers embedded in the launcher at compile time, and the launcher at runtime must carry matching markers to reconstruct the master secret.

```bash
BUILD_ID="quickstart-demo" cargo build --release
```

This produces:

- `./target/release/seal` — the CLI tool
- `./target/release/seal-launcher` — the launcher binary embedded into compiled artifacts

:::note

Both binaries must be rebuilt together whenever `BUILD_ID` changes. Mixing a `seal` and `seal-launcher` from different `BUILD_ID` values will produce artifacts that fail at launch.

:::

## Step 1: Generate builder keys

```bash
./target/release/seal keygen
```

Expected output:

```text
secret: /home/<user>/.snapfzz-seal/keys/builder_secret.key
public: /home/<user>/.snapfzz-seal/keys/builder_public.key
builder id: <16-hex-prefix>
```

To write keys to a specific directory instead of the default:

```bash
./target/release/seal keygen --keys-dir /tmp/my-keys
```

## Step 2: Compile and seal an agent

Generate a 64-hex-character user fingerprint and compile:

```bash
USER_FP=$(openssl rand -hex 32)

./target/release/seal compile \
  --project ./examples/chat_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/release/seal-launcher \
  --backend pyinstaller
```

Expected output:

```text
compiled and assembled binary: ./agent.sealed (<N> bytes)
```

### Compile flag reference

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--project` | Yes | — | Path to the agent source project directory |
| `--user-fingerprint` | Yes | — | 64-hex-character identifier binding the artifact to a user identity |
| `--sandbox-fingerprint` | No | `auto` | 64-hex-character sandbox identity, or `auto` to collect current host fingerprint |
| `--output` | Yes | — | Output path for the sealed artifact |
| `--launcher` | No* | — | Path to `seal-launcher` binary. Falls back to `SNAPFZZ_SEAL_LAUNCHER_PATH` env var |
| `--backend` | No | `nuitka` | Compile backend: `nuitka`, `pyinstaller`, or `go` |
| `--mode` | No | `batch` | Execution mode: `batch` or `interactive` |

*If `--launcher` is omitted and `SNAPFZZ_SEAL_LAUNCHER_PATH` is not set, the compile step will fail with:
```text
launcher path missing: use --launcher or SNAPFZZ_SEAL_LAUNCHER_PATH
```

### Alternative: use environment variable for launcher path

```bash
export SNAPFZZ_SEAL_LAUNCHER_PATH=./target/release/seal-launcher

./target/release/seal compile \
  --project ./examples/chat_agent \
  --user-fingerprint "$USER_FP" \
  --output ./agent.sealed
```

## Step 3: Sign the sealed artifact

```bash
./target/release/seal sign \
  --key ~/.snapfzz-seal/keys/builder_secret.key \
  --binary ./agent.sealed
```

On success, no output is printed. The command appends a 100-byte signature block (`ASL\x02` magic marker + 64-byte Ed25519 signature + 32-byte embedded public key) to the artifact in-place.

## Step 4: Verify the signature

### Pinned verification (recommended for production)

```bash
./target/release/seal verify \
  --binary ./agent.sealed \
  --pubkey ~/.snapfzz-seal/keys/builder_public.key
```

Expected output:

```text
VALID (pinned to explicit public key)
```

### TOFU verification (embedded key)

```bash
./target/release/seal verify --binary ./agent.sealed
```

Expected output:

```text
VALID (TOFU: using embedded key — use --pubkey for pinned builder identity)
```

TOFU detects corruption but does not verify builder identity. An attacker who replaces the payload and re-signs with a new key will pass TOFU verification. Always use `--pubkey` in production.

## Step 5: Launch (Linux only)

```bash
./target/release/seal launch \
  --payload ./agent.sealed \
  --user-fingerprint "$USER_FP"
```

The launcher verifies the signature, reconstructs the master secret from embedded Shamir shares, derives the decryption key, decrypts the payload into a `memfd` anonymous file, and executes it via `fexecve`. Output is collected and printed on completion.

### Launch flag reference

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--payload` | Yes | — | Path to the signed sealed artifact |
| `--user-fingerprint` | No | — | Must match the value used at compile time |
| `--fingerprint-mode` | No | `stable` | `stable` or `session` |
| `--mode` | No | `batch` | `batch` or `interactive` |
| `--verbose` | No | false | Enable verbose output |
| `--max-lifetime` | No | — | Maximum agent lifetime in seconds |
| `--grace-period` | No | `30` | Grace period in seconds before forced termination |

## Step-by-step summary

1. **`cargo build --release` (with BUILD_ID)** — Builds both the CLI and the launcher binary with matching cryptographic markers.
2. **`seal keygen`** — Generates an Ed25519 key pair for signing and verifying artifacts.
3. **`seal compile`** — Compiles the agent with the chosen backend, encrypts the payload, embeds the master secret as Shamir shares, and assembles `[launcher][sentinel][encrypted payload][footer]`.
4. **`seal sign`** — Appends an Ed25519 signature block to the assembled artifact.
5. **`seal verify`** — Checks the Ed25519 signature using either the embedded key (TOFU) or a pinned external public key.
6. **`seal launch`** — Verifies integrity, reconstructs the master secret, derives the decryption key, decrypts in memory, and executes via `fexecve` (Linux only).

## Troubleshooting

### `launcher path missing` during compile

**Cause**: Neither `--launcher` nor `SNAPFZZ_SEAL_LAUNCHER_PATH` was provided.

**Solution**:

```bash
# Option 1: Pass the flag explicitly
BUILD_ID="my-build" cargo build --release
./target/release/seal compile --launcher ./target/release/seal-launcher ...

# Option 2: Set the environment variable
export SNAPFZZ_SEAL_LAUNCHER_PATH=./target/release/seal-launcher
```

### `pyinstaller not found` or `nuitka not found`

**Cause**: The selected compile backend is not installed.

**Solution**:

```bash
pip install nuitka       # for --backend nuitka (default)
pip install pyinstaller  # for --backend pyinstaller
```

### `missing signature` or `WARNING: unsigned` during verify or launch

**Cause**: The artifact was not signed, or the signature block was truncated.

**Solution**:

```bash
./target/release/seal sign \
  --key ~/.snapfzz-seal/keys/builder_secret.key \
  --binary ./agent.sealed

./target/release/seal verify \
  --binary ./agent.sealed \
  --pubkey ~/.snapfzz-seal/keys/builder_public.key
```

### `fingerprint mismatch` during launch

**Cause**: The `--user-fingerprint` value at launch differs from the value used at compile time, or the sandbox fingerprint has drifted.

**Action**:

- Confirm `--user-fingerprint` exactly matches the compile-time value.
- If `--sandbox-fingerprint auto` was used at compile time, the launcher must run on the same host (or a host with the same stable fingerprint).

### `memfd unsupported` on macOS or Windows

**Cause**: Execution was attempted on a non-Linux platform.

**Solution**: Sealed agents can only execute on Linux x86_64. Build and sign on any platform, but run `seal launch` on Linux.

## Platform support summary

| Platform | Build / Sign | Execute |
|----------|-------------|---------|
| Linux x86_64 | Yes | Yes |
| macOS arm64 | Yes | No |
| macOS x86_64 | Yes | No |
| Windows x86_64 | Yes | No |

## Security considerations

- Use `--pubkey` for all production verification paths. TOFU verification does not verify builder identity.
- Treat compile logs as potentially sensitive operational data.
- Store sealed artifacts in access-controlled locations.
- Signatures verify artifact integrity, not signer identity. Implement external key pinning for production deployments.

## Limitations

- `auto` sandbox fingerprint mode is a convenience feature. It binds the artifact to the current host's stable signals, which may drift across kernel upgrades, hostname changes, or container image rebuilds.
- Runtime protections depend on host integrity. A fully compromised host can defeat all protections.
- Execution is Linux-only. There is no cross-platform fallback.

## References

- **Ed25519**: Bernstein, D. et al. (2012). "High-speed high-security signatures". Journal of Cryptographic Engineering 4(2).
- **AES-GCM**: Dworkin, M. (2007). NIST SP 800-38D.
