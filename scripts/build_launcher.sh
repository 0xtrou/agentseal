#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Building launcher for musl target..."
cargo build --release -p snapfzz-seal-launcher --target x86_64-unknown-linux-musl 2>/dev/null || \
cargo build --release -p snapfzz-seal-launcher 2>/dev/null

echo "Launcher binary: ${PROJECT_ROOT}/target/release/snapfzz-seal-launcher"
