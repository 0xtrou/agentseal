---
sidebar_position: 1
---

# Installation

This section describes how to build and verify Snapfzz Seal from source.

## System requirements

### Required toolchain

- **Rust 1.85 or later** — The workspace declares `edition = "2024"` and `rust-version = "1.85"`. Install via [rustup](https://rustup.rs/).
- **Cargo** — Installed automatically with the Rust toolchain.
- **Git** — Required for source checkout.
- **OpenSSL CLI** — Used in key-generation and fingerprint examples.

### Runtime requirements

- **Linux x86_64** — Execution of sealed payloads requires Linux. The launcher uses `memfd_create` and `fexecve`, which are Linux-only system calls. macOS and Windows can build and sign artifacts but cannot execute them.
- **Docker** — Required when using the server-side sandbox execution API (`seal server`). Not needed for CLI-only workflows.

### Compile backend requirements

At least one of the following backends must be available when compiling agent payloads:

- **Nuitka** (default): `pip install nuitka`
- **PyInstaller**: `pip install pyinstaller`
- **Go toolchain**: required when using `--backend go`

## Platform notes

### Linux

Linux is the only supported execution platform. All runtime hardening features — `memfd` execution, seccomp-bpf filtering, anti-debugging protections, and the full fingerprinting module — are Linux-specific.

### macOS and Windows

Building and signing artifacts (`seal compile`, `seal sign`, `seal verify`, `seal keygen`) works on macOS and Windows. The `seal launch` subcommand will fail on these platforms because the Linux-specific execution path is not implemented.

## Build from source

```bash
git clone https://github.com/0xtrou/snapfzz-seal.git
cd snapfzz-seal
BUILD_ID="my-build-$(git rev-parse --short HEAD)" cargo build --release
```

The `BUILD_ID` environment variable is used during the build to derive all internal cryptographic markers. The `seal` CLI and `seal-launcher` binary **must be built with the same `BUILD_ID`** to produce compatible artifacts. If `BUILD_ID` is not set, it defaults to the string `"dev"`.

### Build outputs

After `cargo build --release`, two binaries are relevant:

| Binary | Path | Purpose |
|--------|------|---------|
| `seal` | `./target/release/seal` | CLI for keygen, compile, sign, verify, launch, server |
| `seal-launcher` | `./target/release/seal-launcher` | Embedded launcher binary required by `seal compile` |

### Install the CLI

```bash
cargo install --path crates/snapfzz-seal
```

This places the `seal` binary on your `PATH` via Cargo's install directory (typically `~/.cargo/bin/`).

## Reproducible local build

For CI-style validation before committing:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
BUILD_ID="ci-build" cargo build --release --workspace
```

## Verify installation

### Binary resolution

```bash
which seal
seal --version
seal --help
```

Expected behavior:

- `which seal` prints the resolved binary path.
- `seal --version` returns the version string.
- `seal --help` lists the subcommands: `compile`, `keygen`, `launch`, `server`, `sign`, `verify`.

### Key generation smoke test

```bash
seal keygen
ls -l ~/.snapfzz-seal/keys/
```

Expected output from `seal keygen`:

```text
secret: /home/<user>/.snapfzz-seal/keys/builder_secret.key
public: /home/<user>/.snapfzz-seal/keys/builder_public.key
builder id: <16-hex-prefix>
```

Expected files:

- `~/.snapfzz-seal/keys/builder_secret.key` — hex-encoded 32-byte Ed25519 signing key
- `~/.snapfzz-seal/keys/builder_public.key` — hex-encoded 32-byte Ed25519 verifying key

Keys can be stored in a custom directory using `--keys-dir`:

```bash
seal keygen --keys-dir /path/to/keys
```

## Security considerations

- Build hosts should be treated as high-trust assets.
- Key generation should occur on controlled hosts only.
- Secret key files should have minimal file permissions (e.g., `chmod 600`) and must never be committed to source control.
- The `BUILD_ID` value is security-relevant. A fixed, reproducible `BUILD_ID` should be used for production builds and stored alongside release metadata.

## Limitations

- No package manager distribution channel is currently available. Installation requires building from source.
- Cross-platform parity for runtime hardening is incomplete. Linux is the only production execution target.
- Build reproducibility across heterogeneous toolchains is not guaranteed without pinned Rust compiler and dependency versions.
