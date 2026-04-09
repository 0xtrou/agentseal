# Multi-Platform Support

## Platform Matrix

| Platform | Launcher | Compilation | Protection |
|----------|----------|-------------|------------|
| Linux x86_64 | Full | Native | seccomp, memfd, anti-debug |
| macOS arm64 | Stub | Cross-compile | Decrypt only |
| Windows x86_64 | Stub | Cross-compile | No-op |

## Linux (Full Support)

All security features available:
- memfd + fexecve execution
- seccomp allowlist
- PR_SET_NO_NEW_PRIVS
- PR_SET_DUMPABLE(0)
- ptrace anti-debug
- Tamper hash verification

## macOS (Stub)

- ✅ Decrypt payload
- ✅ Execute agent
- ❌ No seccomp
- ❌ No memfd (uses temp file)
- ❌ No tamper verification
- ❌ No anti-debug

Compile via Docker:
```bash
docker run --rm -v $(pwd):/workspace -w /workspace \
  rust:latest cargo build --release --target x86_64-unknown-linux-musl
```

## Windows (Stub)

- ✅ Binary loads
- ❌ No decryption
- ❌ No execution
- ❌ No protection

Compile via Docker:
```bash
docker run --rm -v $(pwd):/workspace -w /workspace \
  rust:latest cargo build --release --target x86_64-pc-windows-gnu
```

## Cross-Compilation

### Linux Target from macOS

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Using Docker

```bash
# Build Linux binary on any platform
docker build -t agent-seal-builder -f Dockerfile .
docker run --rm -v $(pwd)/target:/app/target agent-seal-builder
```

## Recommendation

For production, **run only on Linux**. macOS and Windows support is for development/testing only.