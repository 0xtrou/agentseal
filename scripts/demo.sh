#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Snapfzz Seal v0.2 Demo ==="
echo ""

# --- Config ---
USER_FP=$(echo -n "demo-user-$(date +%s)" | sha256sum | cut -d' ' -f1)
SANDBOX_FP=$(echo -n "demo-sandbox-$(date +%s)" | sha256sum | cut -d' ' -f1)
KEYS_DIR="/tmp/snapfzz-seal-keys-$(date +%s)"
OUTPUT="/tmp/snapfzz-seal-demo-$(date +%s).sealed"

export SNAPFZZ_SEAL_MASTER_SECRET_HEX=$(echo -n "demo-secret" | sha256sum | cut -d' ' -f1)

echo "User fingerprint:   $USER_FP"
echo "Sandbox fingerprint: $SANDBOX_FP"
echo "Keys directory:     $KEYS_DIR"
echo "Output binary:      $OUTPUT"
echo ""

# --- Step 1: Build launcher (musl static) ---
echo "[1/5] Building launcher..."
cargo build --release -p snapfzz-seal-launcher --target x86_64-unknown-linux-musl 2>/dev/null || \
    cargo build --release -p snapfzz-seal-launcher 2>/dev/null || \
    echo "Warning: launcher build failed, using existing binary"

LAUNCHER="${PROJECT_ROOT}/target/release/snapfzz-seal-launcher"
[ ! -f "$LAUNCHER" ] && LAUNCHER="${PROJECT_ROOT}/target/debug/snapfzz-seal-launcher"
[ ! -f "$LAUNCHER" ] && echo "ERROR: launcher not found" && exit 1

echo "Launcher: $LAUNCHER"
echo ""

# --- Step 2: Generate signing keys ---
echo "[2/5] Generating builder signing keys..."
cargo run --release -p snapfzz-seal -- keygen --keys-dir "$KEYS_DIR"
echo ""

# --- Step 3: Compile and seal (batch mode) ---
echo "[3/5] Compiling demo agent (batch mode)..."
cargo run --release -p snapfzz-seal -- \
    compile \
    --project "${PROJECT_ROOT}/examples/demo_agent" \
    --user-fingerprint "$USER_FP" \
    --sandbox-fingerprint "$SANDBOX_FP" \
    --output "$OUTPUT" \
    --launcher "$LAUNCHER" \
    --mode batch

echo "Output: $OUTPUT ($(wc -c < "$OUTPUT") bytes)"
echo ""

# --- Step 4: Sign the sealed binary ---
echo "[4/5] Signing sealed binary..."
cargo run --release -p snapfzz-seal -- \
    sign \
    --key "${KEYS_DIR}/key" \
    --binary "$OUTPUT"

echo ""

# --- Step 5: Verify and run ---
echo "[5/5] Verifying signature and running..."
cargo run --release -p snapfzz-seal -- \
    verify \
    --binary "$OUTPUT" \
    --pubkey "${KEYS_DIR}/key.pub"

echo ""
echo "Signature verified. Running sealed binary..."
echo ""

chmod +x "$OUTPUT"
"$OUTPUT" --user-fingerprint "$USER_FP"

echo ""
echo "=== Demo Complete ==="
echo "Signed binary: $OUTPUT"
echo "Public key:    ${KEYS_DIR}/key.pub"
