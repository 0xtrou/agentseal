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

    echo "User FP: $USER_FP"
    echo "Sandbox FP: auto"
    
    # Generate keys
    mkdir -p "$keys_dir"
    seal keygen --keys-dir "$keys_dir" 2>&1
    
    # Compile
    echo ""
    echo "Compiling with $backend..."
    if ! seal compile \
        --project "$project_dir" \
        --user-fingerprint "$USER_FP" \
        --sandbox-fingerprint auto \
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
    
    # Launch — execute the sealed agent and capture output
    echo ""
    echo "Launching sealed agent..."
    launch_output=$(
        AGENT_PROMPT="Say hello in exactly 5 words." \
        SNAPFZZ_SEAL_API_KEY="${SNAPFZZ_SEAL_API_KEY:-}" \
        SNAPFZZ_SEAL_API_BASE="${SNAPFZZ_SEAL_API_BASE:-https://llm.solo.engineer/v1}" \
        SNAPFZZ_SEAL_MODEL="${SNAPFZZ_SEAL_MODEL:-bcp/qwen3.6-plus}" \
        seal launch \
            --payload "$output_file" \
            --user-fingerprint "$USER_FP" 2>&1
    ) || true

    echo ""
    echo "--- Agent Response ---"
    echo "$launch_output"
    echo "--- End Response ---"
    echo ""

    if echo "$launch_output" | grep -qE "fingerprint mismatch|invalid signature|ERROR.*launch"; then
        echo "ERROR: Launch failed for $backend"
        FAILED_BACKENDS="$FAILED_BACKENDS $backend"
        return 1
    fi

    echo "✓ $backend E2E complete"
    PASSED_BACKENDS="$PASSED_BACKENDS $backend"
    return 0
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