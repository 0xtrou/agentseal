# Installation

## Prerequisites

- **Rust toolchain** (stable, edition 2024)
- **clippy** and **rustfmt** components
- **Linux musl linker support** (`x86_64-linux-musl-gcc` / `musl-tools`)
- Optional for CI parity: `cargo-nextest`, `cargo-llvm-cov`

## Build from Source

```bash
# Clone the repository
git clone https://github.com/0xtrou/agent-seal.git
cd agent-seal

# Build the workspace
cargo build --workspace --release

# Install the seal binary
cargo install --path crates/agent-seal
```

## Verify Installation

```bash
seal --version
seal compile --help
```

## Platform Notes

| Platform | Status |
|----------|--------|
| Linux x86_64 | Full support (native) |
| macOS arm64 | Cross-compile via Docker |
| Windows x86_64 | Cross-compile via Docker |

For cross-compilation, use Docker with the appropriate toolchain target.