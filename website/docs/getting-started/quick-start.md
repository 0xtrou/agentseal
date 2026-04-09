# Quick Start

This section provides a complete end-to-end example with expected output and operational checks.

## Step 1: Generate builder keys

```bash
seal keygen
```

Expected output pattern:

```text
secret: /home/<user>/.snapfzz-seal/keys/builder_secret.key
public: /home/<user>/.snapfzz-seal/keys/builder_public.key
builder id: <16-hex-prefix>
```

## Step 2: Compile and seal an agent

```bash
USER_FP=$(openssl rand -hex 32)

seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/release/snapfzz-seal-launcher
```

Expected output pattern:

```text
compiled and assembled binary: ./agent.sealed (<N> bytes)
```

## Step 3: Sign the sealed artifact

```bash
seal sign \
  --key ~/.snapfzz-seal/keys/builder_secret.key \
  --binary ./agent.sealed
```

No output indicates successful completion.

## Step 4: Verify signature

```bash
seal verify --binary ./agent.sealed --pubkey ~/.snapfzz-seal/keys/builder_public.key
```

Expected output:

```text
VALID (pinned to explicit public key)
```

## Step 5: Launch

```bash
SNAPFZZ_SEAL_MASTER_SECRET_HEX=<64-hex-secret> \
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

Expected output shape:

```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": ""
}
```

## Step-by-step explanation

1. `keygen` creates Ed25519 key material for builder identity.
2. `compile` builds the project, encrypts payload bytes, and assembles launcher plus payload structure.
3. `sign` appends a detached verification block to the artifact.
4. `verify` checks authenticity with either embedded key or pinned public key.
5. `launch` performs verification, derives keys from runtime state, decrypts in memory, and executes.

## Troubleshooting

### `missing signature` during launch

Cause: artifact was not signed, or signature block was truncated.

Action:

```bash
seal sign --key ~/.snapfzz-seal/keys/builder_secret.key --binary ./agent.sealed
seal verify --binary ./agent.sealed --pubkey ~/.snapfzz-seal/keys/builder_public.key
```

### `fingerprint mismatch`

Cause: runtime context differs from compile-time binding input.

Action:

- Confirm `--user-fingerprint` exactly matches compile-time value.
- Rebuild with current environment parameters when intentional drift occurred.

### `SNAPFZZ_SEAL_MASTER_SECRET_HEX is required`

Cause: no embedded secret was usable and environment secret was absent.

Action:

```bash
export SNAPFZZ_SEAL_MASTER_SECRET_HEX=$(openssl rand -hex 32)
```

### `launcher path missing` during compile

Cause: `--launcher` and `SNAPFZZ_SEAL_LAUNCHER_PATH` were both absent.

Action:

```bash
export SNAPFZZ_SEAL_LAUNCHER_PATH=./target/release/snapfzz-seal-launcher
```

## Security considerations

- Use pinned public key verification in all production paths.
- Treat compile logs as potentially sensitive operational data.
- Store build artifacts in access-controlled locations.

## Limitations

- `auto` sandbox fingerprint mode is intended for convenience, not high-assurance remote identity.
- Runtime protection depends on host integrity and cannot resist full host compromise.
