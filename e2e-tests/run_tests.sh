#!/bin/bash
set -e

echo "=========================================="
echo "Snapfzz Seal E2E Tests"
echo "=========================================="
echo ""

BUILD_ID="${BUILD_ID:-e2e-default-build-id}"
export BUILD_ID
echo "BUILD_ID: $BUILD_ID"

FAILED_BACKENDS=""
PASSED_BACKENDS=""

run_backend_test() {
    local backend=$1
    local project_dir=$2
    local output_file="/tmp/agent-${backend}.sealed"
    local keys_dir="/tmp/keys-${backend}"
    
    echo ""
    echo "=== Testing $backend Backend ==="
    echo ""
    
    USER_FP=$(openssl rand -hex 32)
    SANDBOX_FP=$(openssl rand -hex 32)
    
    echo "User FP: $USER_FP"
    echo "Sandbox FP: $SANDBOX_FP"
    
    # Generate keys
    mkdir -p "$keys_dir"
    seal keygen --keys-dir "$keys_dir" 2>&1
    
    # Compile
    echo ""
    echo "Compiling with $backend..."
    if ! seal compile \
        --project "$project_dir" \
        --user-fingerprint "$USER_FP" \
        --sandbox-fingerprint "$SANDBOX_FP" \
        --output "$output_file" \
        --launcher /usr/local/bin/seal-launcher \
        --backend "$backend" 2>&1; then
        echo "ERROR: Compilation failed for $backend"
        FAILED_BACKENDS="$FAILED_BACKENDS $backend"
        return 1
    fi
    
    # Sign
    echo ""
    echo "Signing binary..."
    if ! seal sign \
        --key "$keys_dir/builder_secret.key" \
        --binary "$output_file" 2>&1; then
        echo "ERROR: Signing failed for $backend"
        FAILED_BACKENDS="$FAILED_BACKENDS $backend"
        return 1
    fi
    
    # Verify
    echo ""
    echo "Verifying signature..."
    if ! seal verify \
        --pubkey "$keys_dir/builder_public.key" \
        --binary "$output_file" 2>&1; then
        echo "ERROR: Verification failed for $backend"
        FAILED_BACKENDS="$FAILED_BACKENDS $backend"
        return 1
    fi
    
    # Get binary info
    local size=$(stat -c%s "$output_file" 2>/dev/null || stat -f%z "$output_file")
    echo ""
    echo "Binary size: $size bytes"
    
    # Launch test (requires SNAPFZZ_SEAL_MASTER_SECRET_HEX or embedded secret)
    # For E2E, we test that the binary can be read and parsed
    echo ""
    echo "Testing payload extraction..."
    if python3 -c "
import sys
with open('$output_file', 'rb') as f:
    data = f.read()
    
# Check for ASL\x01 magic in payload
magic = b'ASL\x01'
if magic in data:
    print('  Payload magic found: OK')
    sys.exit(0)
else:
    print('  ERROR: Payload magic not found')
    sys.exit(1)
"; then
        echo ""
        echo "✓ $backend E2E complete"
        PASSED_BACKENDS="$PASSED_BACKENDS $backend"
        return 0
    else
        FAILED_BACKENDS="$FAILED_BACKENDS $backend"
        return 1
    fi
}

# Test PyInstaller backend
if command -v pyinstaller &> /dev/null; then
    run_backend_test "pyinstaller" "/app/examples/chat_agent" || true
else
    echo "PyInstaller not installed, installing..."
    pip3 install pyinstaller
    run_backend_test "pyinstaller" "/app/examples/chat_agent" || true
fi

# Test Nuitka backend
if command -v nuitka &> /dev/null; then
    run_backend_test "nuitka" "/app/examples/chat_agent" || true
else
    echo "Nuitka not installed, installing..."
    pip3 install nuitka
    run_backend_test "nuitka" "/app/examples/chat_agent" || true
fi

# Test Go backend
if command -v go &> /dev/null; then
    run_backend_test "go" "/app/examples/go_agent" || true
else
    echo "Go not installed, skipping Go backend test"
fi

echo ""
echo "=========================================="
echo "E2E Test Summary"
echo "=========================================="
echo ""
echo "Passed backends: $PASSED_BACKENDS"
echo "Failed backends: $FAILED_BACKENDS"
echo ""

if [ -n "$FAILED_BACKENDS" ]; then
    echo "Some tests failed!"
    exit 1
else
    echo "All tests passed!"
    exit 0
fi