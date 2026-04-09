# Installation

## Prerequisites

- Rust toolchain (stable, edition 2024)
- clippy and rustfmt components
- Linux musl linker support

## Build from Source

```bash
git clone https://github.com/0xtrou/snapfzz-seal.git
cd snapfzz-seal
cargo build --release
cargo install --path crates/snapfzz-seal
```

## Verify

```bash
seal --version
```